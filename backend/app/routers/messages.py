"""
API endpoints for unified messages view
Combines Postfix and Rspamd logs into a single view
FIXED: All timestamps now sent with proper UTC timezone ('Z' suffix)
"""
import logging
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session, aliased
from sqlalchemy import or_, and_, desc, exists, func, select, tuple_, literal
from datetime import datetime, timedelta, timezone
import re
from typing import List, Optional

from ..database import get_db
from ..models import MessageCorrelation, PostfixLog, RspamdLog, NetfilterLog, RawServiceLog
from ..config import settings
from ..app_time import range_bound
from ..services import excluded_addresses
from ..services.dovecot_parser import dovecot_line_user, parse_dovecot_message
from ..utils import internal_error, format_datetime_for_api as format_datetime_utc, RangeStart, RangeEnd

logger = logging.getLogger(__name__)

router = APIRouter()

# How far past the first sighting Dovecot lines are still looked for. The
# delivery happens seconds after Postfix accepts the message; a few hours of
# headroom covers a short deferral without scanning a whole day of raw logs.
DOVECOT_LOOKUP_WINDOW = timedelta(hours=6)


def _get_dovecot_logs(
    db: Session,
    correlation: MessageCorrelation,
    single_leg: bool = True
) -> list:
    """
    Fetch the Dovecot LMTP lines belonging to one message (issue #65).

    These come from the raw logs the Live Logs worker collects, so they are only
    available while that data is retained (RAW_LOGS_RETENTION_DAYS). The verdict
    itself is stored on the correlation and outlives them.

    The lines are found by Message-ID, which a re-submitted message shares with
    its other delivery legs (issue #36). When there is more than one leg, only
    the lines addressed to this leg's recipient are kept.
    """
    if not correlation.message_id or not correlation.first_seen:
        return []

    # LIKE wildcards inside a Message-ID would silently widen the match
    escaped = (
        correlation.message_id
        .replace('\\', '\\\\')
        .replace('%', '\\%')
        .replace('_', '\\_')
    )

    window_start = correlation.first_seen - timedelta(minutes=5)
    rows = db.query(RawServiceLog).filter(
        RawServiceLog.service == 'dovecot',
        RawServiceLog.time >= window_start,
        RawServiceLog.time <= correlation.first_seen + DOVECOT_LOOKUP_WINDOW,
        RawServiceLog.raw_data['message'].astext.like(f'%msgid=<{escaped}>%', escape='\\')
    ).order_by(RawServiceLog.time).limit(100).all()

    leg_recipient = (correlation.recipient or '').strip().lower()

    entries = []
    for row in rows:
        message = (row.raw_data or {}).get('message')
        # The raw logs keep every line; Messages does not show an excluded mailbox's
        if excluded_addresses.is_listed(dovecot_line_user(message)):
            continue
        parsed = parse_dovecot_message(message)
        line_recipient = (parsed.get('recipient') or '').strip().lower() if parsed else ''
        if not single_leg and leg_recipient and line_recipient and line_recipient != leg_recipient:
            continue
        verdict = parsed.get('verdict') if parsed else None
        # 'discard_pending' only exists to let a later store in the same session
        # win (see dovecot_parser); on its own line it reads as the discard it
        # is, and it is not a verdict the UI knows how to label.
        if verdict == 'discard_pending':
            verdict = 'discarded'
        entries.append({
            "time": format_datetime_utc(row.time),
            "priority": (row.raw_data or {}).get('priority'),
            "message": message,
            "verdict": verdict,
            "recipient": parsed.get('recipient') if parsed else None,
            "mailbox": parsed.get('mailbox') if parsed else None,
        })
    return entries


def _group_postfix_by_recipient(postfix_logs) -> dict:
    """
    Group Postfix logs by recipient for better display
    Includes ALL logs - those with recipient grouped by recipient,
    and logs without recipient in a 'system' category
    
    Args:
        postfix_logs: List of PostfixLog objects
    
    Returns:
        Dictionary mapping recipient -> list of log entries
        Special key '_system' for logs without recipient
    """
    grouped = {}
    seen_messages = set()  # Track seen messages to avoid duplicates
    
    for log in postfix_logs:
        # Create a unique key for deduplication
        msg_key = f"{log.time}:{log.message[:100] if log.message else ''}"
        if msg_key in seen_messages:
            continue
        seen_messages.add(msg_key)
        
        # Determine the group key
        if log.recipient:
            group_key = log.recipient
        else:
            group_key = '_system'  # System/general logs without recipient
        
        if group_key not in grouped:
            grouped[group_key] = []
        
        grouped[group_key].append({
            "time": format_datetime_utc(log.time),
            "program": log.program,
            "priority": log.priority,
            "message": log.message,
            "status": log.status,
            "relay": log.relay,
            "delay": log.delay,
            "dsn": log.dsn
        })
    
    return grouped


def message_group_key():
    """What makes deliveries one message: the Message-ID, else (none, or empty)
    the delivery's own key, so it is never merged with another"""
    return func.coalesce(func.nullif(MessageCorrelation.message_id, ""), MessageCorrelation.correlation_key)


def message_sort_time():
    """The time the Messages list sorts by: first seen, else when stored (a
    delivery may lack it), else the epoch. The list, its cursor, the leg that
    stands for a message and the CSV export all use it."""
    return func.coalesce(MessageCorrelation.first_seen, MessageCorrelation.created_at, literal(datetime(1970, 1, 1)))


def _filtered_messages_query(db, search=None, sender=None, recipient=None, direction=None, status=None,
                             user=None, ip=None, start_date=None, end_date=None):
    """The message legs matching the Messages filters. Shared by the list and
    its facet counts, so a count always equals what the list shows for it."""
    # Excluded addresses, here in the query, so pages, totals and facet
    # counts leave them out alike (no page comes out empty)
    query = db.query(MessageCorrelation).filter(excluded_addresses.correlation_visible())

    # Apply filters
    if search:
        search_term = f"%{search}%"
        # Search in correlation fields
        correlation_filters = or_(
            MessageCorrelation.sender.ilike(search_term),
            MessageCorrelation.recipient.ilike(search_term),
            MessageCorrelation.subject.ilike(search_term),
            MessageCorrelation.message_id.ilike(search_term),
            MessageCorrelation.queue_id.ilike(search_term)
        )
        
        # Also search in Rspamd fields (IP and user) via subquery
        rspamd_subquery = select(RspamdLog.id).where(
            or_(
                RspamdLog.ip.ilike(search_term),
                RspamdLog.user.ilike(search_term)
            )
        )
        
        query = query.filter(
            or_(
                correlation_filters,
                MessageCorrelation.rspamd_log_id.in_(rspamd_subquery)
            )
        )
    
    if sender:
        query = query.filter(MessageCorrelation.sender.ilike(f"%{sender}%"))
    
    if recipient:
        query = query.filter(MessageCorrelation.recipient.ilike(f"%{recipient}%"))
    
    if direction:
        query = query.filter(MessageCorrelation.direction == direction)
    
    if status:
        # For spam status, check both final_status and is_spam from Rspamd
        if status == 'spam':
            # Use outerjoin to include correlations without Rspamd logs
            # Check if final_status is 'spam' OR if Rspamd marked it as spam
            query = query.outerjoin(
                RspamdLog,
                MessageCorrelation.rspamd_log_id == RspamdLog.id
            ).filter(
                or_(
                    MessageCorrelation.final_status == 'spam',
                    RspamdLog.is_spam == True
                )
            )
        else:
            query = query.filter(MessageCorrelation.final_status == status)
    
    if start_date:
        query = query.filter(MessageCorrelation.first_seen >= start_date)
    
    if end_date:
        query = query.filter(MessageCorrelation.first_seen <= end_date)
    
    # Filter by user (need to join with Rspamd)
    # Check if we already have a join from spam filter (outerjoin)
    has_rspamd_join = status == 'spam'
    if user:
        if not has_rspamd_join:
            query = query.join(
                RspamdLog,
                MessageCorrelation.rspamd_log_id == RspamdLog.id
            )
            has_rspamd_join = True
        # outerjoin works fine for filtering, no need to change it
        query = query.filter(RspamdLog.user.ilike(f"%{user}%"))
    
    # Filter by IP (need to join with Rspamd if not already joined)
    if ip:
        if not has_rspamd_join:
            query = query.join(
                RspamdLog,
                MessageCorrelation.rspamd_log_id == RspamdLog.id
            )
        query = query.filter(RspamdLog.ip.ilike(f"%{ip}%"))
    return query


def _count_messages(query):
    """Messages, not legs, in a filtered leg query (the rule of the list)."""
    # As the list groups them: an empty Message-ID is none
    group_key = func.coalesce(func.nullif(MessageCorrelation.message_id, ""), MessageCorrelation.correlation_key)
    legs = query.with_entities(
        func.row_number().over(
            partition_by=group_key,
            order_by=(MessageCorrelation.first_seen.asc(), MessageCorrelation.id.asc())
        ).label("leg_rank")
    ).subquery()
    return query.session.query(func.count()).select_from(legs).filter(legs.c.leg_rank == 1).scalar() or 0


FACET_STATUSES = ("delivered", "deferred", "bounced", "rejected", "spam", "discarded")
FACET_DIRECTIONS = ("inbound", "outbound", "internal")


@router.get("/messages/facets")
def get_message_facets(
    search: Optional[str] = Query(None),
    sender: Optional[str] = Query(None),
    recipient: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    user: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    start_date: Optional[RangeStart] = Query(None),
    end_date: Optional[RangeEnd] = Query(None),
    since: List[str] = Query([], description="Time ranges to count, as name:start, an ISO instant or a YYYY-MM-DD day (e.g. today:2026-09-27T00:00:00Z)"),
    db: Session = Depends(get_db)
):
    """
    Message counts per outcome and per direction for the Messages facets.
    With since=name:start pairs it also counts each time range (every other
    filter applies, the chosen date range does not).

    Each outcome count applies every filter except the outcome itself, and each
    direction count every filter except the direction, so the numbers say what
    choosing that facet would show.
    """
    try:
        common = dict(search=search, sender=sender, recipient=recipient, user=user, ip=ip,
                      start_date=start_date, end_date=end_date)
        by_status = {
            value: _count_messages(_filtered_messages_query(db, direction=direction, status=value, **common))
            for value in FACET_STATUSES
        }
        by_direction = {
            value: _count_messages(_filtered_messages_query(db, direction=value, status=status, **common))
            for value in FACET_DIRECTIONS
        }
        result = {
            "status": {"all": _count_messages(_filtered_messages_query(db, direction=direction, **common)), **by_status},
            "direction": {"all": _count_messages(_filtered_messages_query(db, status=status, **common)), **by_direction},
        }
        if since:
            undated = dict(search=search, sender=sender, recipient=recipient, user=user, ip=ip)
            by_time = {"all": _count_messages(_filtered_messages_query(db, direction=direction, status=status, **undated))}
            for item in since[:8]:
                name, _, iso = item.partition(':')
                if not re.fullmatch(r'[a-z0-9]{1,16}', name):
                    continue
                try:
                    # An instant, or a date: the start of that day in the app's time zone
                    start = range_bound(iso, end=False)
                except ValueError:
                    continue
                by_time[name] = _count_messages(_filtered_messages_query(db, direction=direction, status=status, start_date=start, **undated))
            result["time"] = by_time
        return result
    except Exception as e:
        logger.error(f"Error counting message facets: {e}")
        raise internal_error(e)


def messages_watermark(db) -> int:
    """The newest delivery stored: a list read now holds nothing stored after it."""
    return db.query(func.max(MessageCorrelation.id)).scalar() or 0


@router.get("/messages/new")
def count_new_messages(
    after_id: int = Query(..., ge=0, description="The watermark of the list shown"),
    search: Optional[str] = Query(None),
    sender: Optional[str] = Query(None),
    recipient: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    user: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    start_date: Optional[RangeStart] = Query(None),
    end_date: Optional[RangeEnd] = Query(None),
    db: Session = Depends(get_db)
):
    """
    How many messages matching the filters came after a list was read: those
    with a matching delivery stored after its watermark and no delivery stored
    before it. A message that was there already, whose status changed or which
    got another delivery, is not new. Returns the count and the watermark now.
    """
    try:
        query = _filtered_messages_query(db, search, sender, recipient, direction, status, user, ip, start_date, end_date)
        fresh = query.filter(MessageCorrelation.id > after_id).with_entities(
            MessageCorrelation.message_id.label("message_id"),
            message_group_key().label("group_key"),
        ).subquery()
        # A delivery of the same message (by Message-ID) stored by the watermark
        earlier = aliased(MessageCorrelation)
        was_there = exists().where(
            earlier.id <= after_id,
            func.nullif(fresh.c.message_id, "").isnot(None),
            earlier.message_id == fresh.c.message_id,
        )
        count = db.query(func.count(func.distinct(fresh.c.group_key))).select_from(fresh).filter(~was_there).scalar() or 0
        return {"count": count, "watermark": messages_watermark(db)}
    except Exception as e:
        logger.error(f"Error counting new messages: {e}")
        raise internal_error(e)


@router.get("/messages")
def get_unified_messages(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=500, description="Items per page"),
    search: Optional[str] = Query(None, description="Search query"),
    sender: Optional[str] = Query(None, description="Filter by sender"),
    recipient: Optional[str] = Query(None, description="Filter by recipient"),
    direction: Optional[str] = Query(None, description="Filter by direction"),
    status: Optional[str] = Query(None, description="Filter by status"),
    user: Optional[str] = Query(None, description="Filter by authenticated user"),
    ip: Optional[str] = Query(None, description="Filter by source IP"),
    start_date: Optional[RangeStart] = Query(None, description="Start date"),
    end_date: Optional[RangeEnd] = Query(None, description="End date"),
    order: str = Query("desc", pattern="^(asc|desc)$", description="By time first seen: desc newest first, asc oldest first"),
    cursor: Optional[str] = Query(None, max_length=80, description="The next_cursor of the page before: the messages after it, instead of a page number"),
    upto_id: Optional[int] = Query(None, ge=0, description="The watermark of the list's first page: the next pages hold only what it held"),
    db: Session = Depends(get_db)
):
    """
    Get unified messages view (combines Postfix + Rspamd)
    """
    # A cursor is the last message shown (its time first seen and its leg's id):
    # the next page starts right after it, so a message removed or added in
    # between (retention, new mail) neither skips nor repeats one
    after = None
    if isinstance(cursor, str) and cursor:   # a direct call (tests) leaves the Query default
        try:
            at, leg = cursor.rsplit("|", 1)
            after = (datetime.fromisoformat(at), int(leg))
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid cursor")
    try:
        # The list holds what was stored up to its watermark, and nothing after it: what
        # comes later is new mail (GET /api/messages/new), never shown and counted twice.
        # Its next pages pass the first page's watermark, so paging adds no new mail either
        # A direct call (tests) leaves the Query default, which is no watermark
        watermark = upto_id if isinstance(upto_id, int) else messages_watermark(db)
        query = _filtered_messages_query(db, search, sender, recipient, direction, status, user, ip, start_date, end_date)
        query = query.filter(MessageCorrelation.id <= watermark)

        # One row per message, not one per delivery leg (issue #36). The filters
        # above select legs; the legs are then grouped by Message-ID and the
        # earliest matching leg represents its message in the list, so a search
        # always shows the leg that matched it. A correlation without a
        # Message-ID falls back to its own key and is never merged with another.
        group_key = message_group_key()
        legs = query.with_entities(
            MessageCorrelation.id.label("leg_id"),
            MessageCorrelation.first_seen.label("first_seen"),
            # The time the list sorts by: first seen, else stored (a leg may lack it)
            message_sort_time().label("sort_time"),
            func.row_number().over(
                partition_by=group_key,
                order_by=(
                    message_sort_time().asc(),
                    MessageCorrelation.id.asc()
                )
            ).label("leg_rank")
        ).subquery()

        # Count messages, not legs: exactly one leg per message has rank 1
        total_before_filter = db.query(func.count()).select_from(legs).filter(
            legs.c.leg_rank == 1
        ).scalar() or 0

        # A page: after the cursor when there is one, else by its number. One
        # row more than the page says whether another page follows
        rows = db.query(MessageCorrelation, legs.c.sort_time).join(
            legs, MessageCorrelation.id == legs.c.leg_id
        ).filter(
            legs.c.leg_rank == 1
        )
        if after:
            mark = tuple_(legs.c.sort_time, legs.c.leg_id)
            rows = rows.filter(mark > tuple_(*after) if order == "asc" else mark < tuple_(*after))
        found = rows.order_by(
            # The leg's id settles messages first seen at the same moment, so pages never overlap or skip
            *((legs.c.sort_time.asc(), legs.c.leg_id.asc()) if order == "asc" else (desc(legs.c.sort_time), desc(legs.c.leg_id)))
        ).offset(0 if after else (page - 1) * limit).limit(limit + 1).all()
        more = len(found) > limit
        found = found[:limit]
        messages = [msg for msg, _ in found]

        # How many deliveries the message has in total, which is what the row
        # reports - not only the legs the current filters matched
        message_ids = {msg.message_id for msg in messages if msg.message_id}
        leg_counts = {}
        if message_ids:
            leg_counts = dict(
                db.query(
                    MessageCorrelation.message_id,
                    func.count(MessageCorrelation.id)
                ).filter(
                    MessageCorrelation.message_id.in_(message_ids)
                ).group_by(MessageCorrelation.message_id).all()
            )

        # Build the response (hidden addresses are already left out by the query)
        result_messages = []
        for msg in messages:
            # Get Rspamd log for additional info
            rspamd_log = None
            if msg.rspamd_log_id:
                rspamd_log = db.query(RspamdLog).filter(
                    RspamdLog.id == msg.rspamd_log_id
                ).first()
            
            result_messages.append({
                "correlation_key": msg.correlation_key,
                "message_id": msg.message_id,
                "queue_id": msg.queue_id,
                "sender": msg.sender,
                "recipient": msg.recipient,
                "subject": msg.subject,
                "direction": msg.direction,
                "final_status": msg.final_status,
                "is_complete": msg.is_complete,
                "first_seen": format_datetime_utc(msg.first_seen),
                "last_seen": format_datetime_utc(msg.last_seen),
                "dovecot_status": msg.dovecot_status,
                "dovecot_mailbox": msg.dovecot_mailbox,
                "deliveries": leg_counts.get(msg.message_id, 1),
                "spam_score": rspamd_log.score if rspamd_log else None,
                "is_spam": rspamd_log.is_spam if rspamd_log else None,
                "user": rspamd_log.user if rspamd_log else None,
                "ip": rspamd_log.ip if rspamd_log else None
            })

        return {
            "total": total_before_filter,
            "page": page,
            "limit": limit,
            "pages": (total_before_filter + limit - 1) // limit if total_before_filter > 0 else 0,
            "data": result_messages,
            # Where the next page starts, or null at the end
            "next_cursor": f"{found[-1][1].isoformat()}|{found[-1][0].id}" if more and found else None,
            # What GET /api/messages/new counts from
            "watermark": watermark,
        }
    except Exception as e:
        logger.error(f"Error fetching unified messages: {e}")
        raise internal_error(e)


@router.get("/message/{correlation_key}/details")
def get_message_full_details(
    correlation_key: str,
    db: Session = Depends(get_db)
):
    """
    Get complete message details with all related logs
    Including Postfix, Rspamd, and Netfilter logs
    """
    try:
        # Get correlation
        correlation = db.query(MessageCorrelation).filter(
            MessageCorrelation.correlation_key == correlation_key
        ).first()
        
        # A delivery to or from an excluded address is not shown in Messages
        if not correlation or excluded_addresses.any_listed(correlation.sender, correlation.recipient):
            raise HTTPException(status_code=404, detail="Message not found")

        # Get Rspamd log
        rspamd_log = None
        if correlation.rspamd_log_id:
            rspamd_log = db.query(RspamdLog).filter(
                RspamdLog.id == correlation.rspamd_log_id
            ).first()

        # Get Postfix logs - Use queue_id instead of postfix_log_ids
        # This ensures we always get ALL logs, even if they arrive after correlation is marked complete
        postfix_logs = []
        if correlation.queue_id:
            # Query ALL postfix logs with this queue_id
            # This is the source of truth, not postfix_log_ids
            postfix_logs = db.query(PostfixLog).filter(
                PostfixLog.queue_id == correlation.queue_id
            ).order_by(PostfixLog.time).all()
        elif correlation.postfix_log_ids:
            # Fallback: if no queue_id yet, use postfix_log_ids (for incomplete correlations)
            unique_ids = list(set(correlation.postfix_log_ids))
            postfix_logs = db.query(PostfixLog).filter(
                PostfixLog.id.in_(unique_ids)
            ).order_by(PostfixLog.time).all()

        # Deduplicate postfix_logs by message content (same time + same message = duplicate)
        seen_messages = set()
        deduplicated_postfix_logs = []
        for log in postfix_logs:
            # Create unique key: time + first 100 chars of message
            msg_key = f"{log.time}:{log.message[:100] if log.message else ''}"
            if msg_key not in seen_messages:
                seen_messages.add(msg_key)
                deduplicated_postfix_logs.append(log)
        postfix_logs = excluded_addresses.visible_postfix_lines(deduplicated_postfix_logs)
        
        # Get Netfilter logs by IP from Rspamd, limited to ±1 hour around the
        # message (issue #68) - the Security tab explicitly promises "events
        # within 1 hour of this message"; unrelated events from days earlier
        # were confusing
        netfilter_logs = []
        if rspamd_log and rspamd_log.ip and rspamd_log.time:
            window = timedelta(hours=1)
            netfilter_logs = db.query(NetfilterLog).filter(
                NetfilterLog.ip == rspamd_log.ip,
                NetfilterLog.time >= rspamd_log.time - window,
                NetfilterLog.time <= rspamd_log.time + window,
            ).order_by(NetfilterLog.time.desc()).limit(100).all()

        # The other delivery legs of the same message (issue #36). A forward or
        # any other re-submission is a delivery of its own, with its own
        # sender, recipient and verdict, so neither leg tells the whole story
        # on its own and the detail view links them.
        related_deliveries = []
        other_legs = []
        if correlation.message_id:
            other_legs = db.query(MessageCorrelation).filter(
                MessageCorrelation.message_id == correlation.message_id,
                MessageCorrelation.correlation_key != correlation.correlation_key
            ).order_by(MessageCorrelation.first_seen).all()
            other_legs = [leg for leg in other_legs if not excluded_addresses.any_listed(leg.sender, leg.recipient)]
            related_deliveries = [
                {
                    "correlation_key": leg.correlation_key,
                    "sender": leg.sender,
                    "recipient": leg.recipient,
                    "direction": leg.direction,
                    "final_status": leg.final_status,
                    "first_seen": format_datetime_utc(leg.first_seen),
                    "queue_id": leg.queue_id,
                    "dovecot_status": leg.dovecot_status,
                    "dovecot_mailbox": leg.dovecot_mailbox,
                }
                for leg in other_legs
            ]

        # A delivery Rspamd did not scan, such as a release from quarantine,
        # has no subject of its own; it is the same message, so it takes the
        # subject another delivery of the same Message-ID recorded
        subject = correlation.subject
        if not subject and correlation.message_id:
            subject = next((leg.subject for leg in other_legs if leg.subject), None)

        # Get the Dovecot delivery lines for the last hop (issue #65)
        dovecot_logs = _get_dovecot_logs(
            db, correlation, single_leg=not related_deliveries
        )

        # Get all recipients - from Rspamd (primary source) or from Postfix logs
        recipients = []
        if rspamd_log and rspamd_log.recipients_smtp:
            recipients = excluded_addresses.visible_recipients(rspamd_log.recipients_smtp)
        
        # If no recipients from Rspamd, collect unique recipients from Postfix logs
        if not recipients:
            seen_recipients = set()
            for log in postfix_logs:
                if log.recipient and log.recipient not in seen_recipients:
                    recipients.append(log.recipient)
                    seen_recipients.add(log.recipient)
        
        # Build response
        return {
            "correlation_key": correlation.correlation_key,
            "message_id": correlation.message_id,
            "queue_id": correlation.queue_id,
            "sender": correlation.sender,
            "recipient": correlation.recipient,  # Primary recipient (for backwards compatibility)
            "recipients": recipients,  # ALL recipients
            "recipient_count": len(recipients),
            "subject": subject,
            "direction": correlation.direction,
            "final_status": correlation.final_status,
            "is_complete": correlation.is_complete,
            "first_seen": format_datetime_utc(correlation.first_seen),
            "last_seen": format_datetime_utc(correlation.last_seen),
            # Other deliveries of the same Message-ID, empty for most messages
            "related_deliveries": related_deliveries,
            "rspamd": {
                "time": format_datetime_utc(rspamd_log.time),
                "score": rspamd_log.score,
                "required_score": rspamd_log.required_score,
                "action": rspamd_log.action,
                "symbols": rspamd_log.symbols,
                "is_spam": rspamd_log.is_spam,
                "direction": rspamd_log.direction,
                "ip": rspamd_log.ip,
                "user": rspamd_log.user,
                "has_auth": rspamd_log.has_auth,
                "size": rspamd_log.size,
                "country_code": rspamd_log.country_code,
                "country_name": rspamd_log.country_name,
                "city": rspamd_log.city,
                "asn": rspamd_log.asn,
                "asn_org": rspamd_log.asn_org
            } if rspamd_log else None,
            "dovecot": {
                "status": correlation.dovecot_status,
                "mailbox": correlation.dovecot_mailbox,
                "detail": correlation.dovecot_detail,
                "logs": dovecot_logs,
            } if (correlation.dovecot_status or dovecot_logs) else None,
            "postfix_by_recipient": _group_postfix_by_recipient(postfix_logs),
            "postfix": [
                {
                    "time": format_datetime_utc(log.time),
                    "program": log.program,
                    "priority": log.priority,
                    "message": log.message,
                    "status": log.status,
                    "relay": log.relay,
                    "delay": log.delay,
                    "dsn": log.dsn,
                    "recipient": log.recipient  # Add recipient to each log entry
                }
                for log in postfix_logs
            ],
            "netfilter": [
                {
                    "time": format_datetime_utc(log.time),
                    "ip": log.ip,
                    "username": log.username,
                    "auth_method": log.auth_method,
                    "action": log.action,
                    "attempts_left": log.attempts_left,
                    "message": log.message
                }
                for log in netfilter_logs
            ]
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching message details: {e}")
        raise internal_error(e)