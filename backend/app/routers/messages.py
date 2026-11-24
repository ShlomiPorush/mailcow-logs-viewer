import logging
from fastapi import APIRouter, Depends, Query, HTTPException, Request
from sqlalchemy.orm import Session, aliased
from sqlalchemy import or_, and_, desc, exists, func, select, tuple_, literal
from datetime import datetime, timedelta, timezone
import re
from typing import List, Optional

from ..database import get_db
from ..models import MessageCorrelation, PostfixLog, RspamdLog, NetfilterLog, RawServiceLog
from ..correlation import shown_postfix_lines
from ..config import settings
from ..app_time import range_bound
from ..services import entity_values, excluded_addresses, written_recipients
from ..services.message_recipients import (legs_recipients, listed_recipients, resolve_recipients,
                                           union_recipients, written_address)
from ..services.dovecot_parser import dovecot_line_user, parse_dovecot_message
from ..utils import internal_error, format_datetime_for_api as format_datetime_utc, RangeStart, RangeEnd
from ..api_models import Invalid, documented
from ..api_models.messages import (MessageDetailsResponse, MessageFacetsResponse, MessageListResponse,
                                   NewMessagesResponse, NoMessageIdListResponse)
from ..services import no_message_id
from ..agent_access.scopes import READ
from ..user_access import caller_may

logger = logging.getLogger(__name__)

router = APIRouter()

DOVECOT_LOOKUP_WINDOW = timedelta(hours=6)


def _get_dovecot_logs(
    db: Session,
    correlation: MessageCorrelation,
    single_leg: bool = True
) -> list:
    if not correlation.message_id or not correlation.first_seen:
        return []

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
        if excluded_addresses.is_listed(dovecot_line_user(message)):
            continue
        parsed = parse_dovecot_message(message)
        line_recipient = (parsed.get('recipient') or '').strip().lower() if parsed else ''
        if not single_leg and leg_recipient and line_recipient and line_recipient != leg_recipient:
            continue
        verdict = parsed.get('verdict') if parsed else None
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


def _postfix_line_identity(log) -> tuple:
    return (log.time, log.program, log.queue_id, log.message)


def _group_postfix_by_recipient(postfix_logs) -> dict:
    grouped = {}
    seen_messages = set()
    
    for log in postfix_logs:
        msg_key = _postfix_line_identity(log)
        if msg_key in seen_messages:
            continue
        seen_messages.add(msg_key)
        
        if log.recipient:
            group_key = log.recipient
        else:
            group_key = '_system'
        
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
    return func.coalesce(func.nullif(MessageCorrelation.message_id, ""), MessageCorrelation.correlation_key)


def message_sort_time():
    return func.coalesce(MessageCorrelation.first_seen, MessageCorrelation.created_at, literal(datetime(1970, 1, 1)))


EXACT_DESCRIPTION = ("Match sender, recipient, user and ip exactly (an address in any case, the IP as written "
                     "canonically) instead of as a part. Off by default")
ADDRESS_DESCRIPTION = "Messages from or to this email address, matched whole in any case (the entity card's count)"
EXACT_IP_DESCRIPTION = ("Match ip whole (in any spelling of the address) while the other filters still match a part, "
                        "as the entity card opens Messages. Off by default")
DOMAIN_DESCRIPTION = ("Messages from or to an address on this domain: the part after the last @ is the domain, "
                      "so a subdomain is not included")


def address_equals(column, value: str):
    try:
        forms = entity_values.address_forms(entity_values.normalize_address(value)[0])
    except entity_values.InvalidValue:
        forms = [value.strip().lower()]
    return func.lower(column).in_(forms)


def on_domain(column, value: str):
    from ..services.entity_summary import domain_match
    try:
        domain = entity_values.normalize_domain(value)
    except entity_values.InvalidValue:
        return literal(False)
    return domain_match(column, domain)


def _address_match(column, value: str, exact: bool):
    if not exact:
        return column.ilike(f"%{value}%")
    return address_equals(column, value)


def _ip_match(column, value: str, exact: bool):
    if not exact:
        return column.ilike(f"%{value}%")
    return column.in_(entity_values.spellings_of_typed_ip(value))


def _filtered_messages_query(db, search=None, sender=None, recipient=None, direction=None, status=None,
                             user=None, ip=None, start_date=None, end_date=None, exact=False, base=None,
                             address=None, domain=None, exact_ip=False):
    exact = exact is True
    exact_ip = exact_ip is True
    query = (base if base is not None else db.query(MessageCorrelation)).filter(excluded_addresses.correlation_visible())

    if search:
        search_term = f"%{search}%"
        correlation_filters = or_(
            MessageCorrelation.sender.ilike(search_term),
            MessageCorrelation.recipient.ilike(search_term),
            written_recipients.any_value(MessageCorrelation.written_recipients, lambda v: v.ilike(search_term)),
            MessageCorrelation.subject.ilike(search_term),
            MessageCorrelation.message_id.ilike(search_term),
            MessageCorrelation.queue_id.ilike(search_term)
        )
        
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
        query = query.filter(_address_match(MessageCorrelation.sender, sender, exact))
    
    if recipient:
        query = query.filter(or_(
            _address_match(MessageCorrelation.recipient, recipient, exact),
            written_recipients.any_value(MessageCorrelation.written_recipients, lambda v: _address_match(v, recipient, exact))))

    if isinstance(address, str) and address.strip():
        query = query.filter(or_(address_equals(MessageCorrelation.sender, address),
                                 address_equals(MessageCorrelation.recipient, address),
                                 written_recipients.any_value(MessageCorrelation.written_recipients,
                                                              lambda v: address_equals(v, address))))

    if isinstance(domain, str) and domain.strip():
        query = query.filter(or_(on_domain(MessageCorrelation.sender, domain),
                                 on_domain(MessageCorrelation.recipient, domain)))

    if direction:
        query = query.filter(MessageCorrelation.direction == direction)
    
    if status:
        if status == 'spam':
            # An inner join would drop spam messages that have no Rspamd log
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
    
    has_rspamd_join = status == 'spam'
    if user:
        if not has_rspamd_join:
            query = query.join(
                RspamdLog,
                MessageCorrelation.rspamd_log_id == RspamdLog.id
            )
            has_rspamd_join = True
        query = query.filter(_address_match(RspamdLog.user, user, exact))
    
    if ip:
        if not has_rspamd_join:
            query = query.join(
                RspamdLog,
                MessageCorrelation.rspamd_log_id == RspamdLog.id
            )
        query = query.filter(_ip_match(RspamdLog.ip, ip, exact or exact_ip))
    return query


def _count_messages(query):
    group_key = func.coalesce(func.nullif(MessageCorrelation.message_id, ""), MessageCorrelation.correlation_key)
    legs = query.with_entities(
        func.row_number().over(
            partition_by=group_key,
            order_by=(MessageCorrelation.first_seen.asc(), MessageCorrelation.id.asc())
        ).label("leg_rank")
    ).subquery()
    return query.session.query(func.count()).select_from(legs).filter(legs.c.leg_rank == 1).scalar() or 0


def since_ranges(since) -> list:
    ranges = []
    for item in since[:8]:
        name, _, iso = item.partition(':')
        if name == 'all' or not re.fullmatch(r'[a-z0-9]{1,16}', name):
            continue
        try:
            ranges.append((name, range_bound(iso, end=False)))
        except (ValueError, OverflowError):
            continue
    return ranges


FACET_STATUSES = ("delivered", "deferred", "bounced", "rejected", "spam", "discarded")
FACET_DIRECTIONS = ("inbound", "outbound", "internal")


@router.get("/messages/facets", responses=documented(MessageFacetsResponse, errors={422: Invalid, 500: None}))
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
    exact: bool = Query(False, description=EXACT_DESCRIPTION),
    address: Optional[str] = Query(None, max_length=320, description=ADDRESS_DESCRIPTION),
    domain: Optional[str] = Query(None, max_length=260, description=DOMAIN_DESCRIPTION),
    exact_ip: bool = Query(False, description=EXACT_IP_DESCRIPTION),
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
                      start_date=start_date, end_date=end_date, exact=exact, address=address, domain=domain,
                      exact_ip=exact_ip)
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
            undated = dict(search=search, sender=sender, recipient=recipient, user=user, ip=ip, exact=exact,
                           address=address, domain=domain, exact_ip=exact_ip)
            by_time = {"all": _count_messages(_filtered_messages_query(db, direction=direction, status=status, **undated))}
            for name, start in since_ranges(since):
                by_time[name] = _count_messages(_filtered_messages_query(db, direction=direction, status=status, start_date=start, **undated))
            result["time"] = by_time
        return result
    except Exception as e:
        logger.error(f"Error counting message facets: {e}")
        raise internal_error(e)


def messages_watermark(db) -> int:
    return db.query(func.max(MessageCorrelation.id)).scalar() or 0


@router.get("/messages/new", responses=documented(NewMessagesResponse, errors={422: Invalid, 500: None}))
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
    exact: bool = Query(False, description=EXACT_DESCRIPTION),
    address: Optional[str] = Query(None, max_length=320, description=ADDRESS_DESCRIPTION),
    domain: Optional[str] = Query(None, max_length=260, description=DOMAIN_DESCRIPTION),
    exact_ip: bool = Query(False, description=EXACT_IP_DESCRIPTION),
    db: Session = Depends(get_db)
):
    """
    How many messages matching the filters came after a list was read: those
    with a matching delivery stored after its watermark and no delivery stored
    before it. A message that was there already, whose status changed or which
    got another delivery, is not new. Returns the count and the watermark now.
    """
    try:
        query = _filtered_messages_query(db, search, sender, recipient, direction, status, user, ip, start_date, end_date,
                                         exact=exact, address=address, domain=domain, exact_ip=exact_ip)
        fresh = query.filter(MessageCorrelation.id > after_id).with_entities(
            MessageCorrelation.message_id.label("message_id"),
            message_group_key().label("group_key"),
        ).subquery()
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


@router.get("/messages", responses=documented(MessageListResponse, errors={422: Invalid, 500: None}))
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
    exact: bool = Query(False, description=EXACT_DESCRIPTION),
    address: Optional[str] = Query(None, max_length=320, description=ADDRESS_DESCRIPTION),
    domain: Optional[str] = Query(None, max_length=260, description=DOMAIN_DESCRIPTION),
    exact_ip: bool = Query(False, description=EXACT_IP_DESCRIPTION),
    db: Session = Depends(get_db)
):
    """
    Get unified messages view (combines Postfix + Rspamd)
    """
    after = None
    if isinstance(cursor, str) and cursor:
        try:
            at, leg = cursor.rsplit("|", 1)
            after = (datetime.fromisoformat(at), int(leg))
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid cursor")
    try:
        watermark = upto_id if isinstance(upto_id, int) else messages_watermark(db)
        query = _filtered_messages_query(db, search, sender, recipient, direction, status, user, ip, start_date, end_date,
                                         exact=exact, address=address, domain=domain, exact_ip=exact_ip)
        query = query.filter(MessageCorrelation.id <= watermark)

        group_key = message_group_key()
        legs = query.with_entities(
            MessageCorrelation.id.label("leg_id"),
            MessageCorrelation.first_seen.label("first_seen"),
            message_sort_time().label("sort_time"),
            func.row_number().over(
                partition_by=group_key,
                order_by=(
                    message_sort_time().asc(),
                    MessageCorrelation.id.asc()
                )
            ).label("leg_rank")
        ).subquery()

        total_before_filter = db.query(func.count()).select_from(legs).filter(
            legs.c.leg_rank == 1
        ).scalar() or 0

        rows = db.query(MessageCorrelation, legs.c.sort_time).join(
            legs, MessageCorrelation.id == legs.c.leg_id
        ).filter(
            legs.c.leg_rank == 1
        )
        if after:
            mark = tuple_(legs.c.sort_time, legs.c.leg_id)
            rows = rows.filter(mark > tuple_(*after) if order == "asc" else mark < tuple_(*after))
        found = rows.order_by(
            *((legs.c.sort_time.asc(), legs.c.leg_id.asc()) if order == "asc" else (desc(legs.c.sort_time), desc(legs.c.leg_id)))
        ).offset(0 if after else (page - 1) * limit).limit(limit + 1).all()
        more = len(found) > limit
        found = found[:limit]
        messages = [msg for msg, _ in found]

        message_ids = {msg.message_id for msg in messages if msg.message_id}
        legs_of = {}
        if message_ids:
            for leg in db.query(MessageCorrelation).filter(
                MessageCorrelation.message_id.in_(message_ids), excluded_addresses.correlation_visible()
            ).all():
                legs_of.setdefault(leg.message_id, []).append(leg)

        page_legs = {leg.correlation_key: leg for leg in messages}
        page_legs.update({leg.correlation_key: leg for legs in legs_of.values() for leg in legs})
        hidden = excluded_addresses.hidden_deliveries(db, list(page_legs.values()))
        if any(msg.correlation_key in hidden for msg in messages):
            stale = {msg.message_id for msg in messages if msg.correlation_key in hidden and msg.message_id}
            visible = {}
            if stale:
                for leg in query.filter(MessageCorrelation.message_id.in_(stale)).order_by(
                        message_sort_time().asc(), MessageCorrelation.id.asc()).all():
                    if leg.correlation_key not in hidden:
                        visible.setdefault(leg.message_id, leg)
            messages = [msg if msg.correlation_key not in hidden else visible.get(msg.message_id)
                        for msg in messages]
            messages = [msg for msg in messages if msg is not None]
        row_legs = {msg.correlation_key: [msg] + [leg for leg in legs_of.get(msg.message_id, [])
                                                  if leg.correlation_key != msg.correlation_key
                                                  and leg.correlation_key not in hidden]
                    for msg in messages}
        all_legs = list({leg.correlation_key: leg for legs in row_legs.values() for leg in legs}.values())
        rspamd_ids = {leg.rspamd_log_id for leg in all_legs if leg.rspamd_log_id}
        rspamd_logs = {row.id: row for row in db.query(RspamdLog).filter(
            RspamdLog.id.in_(list(rspamd_ids))).all()} if rspamd_ids else {}
        recipients = legs_recipients(db, all_legs, rspamd_logs)

        result_messages = []
        for msg in messages:
            rspamd_log = rspamd_logs.get(msg.rspamd_log_id)
            recipient_count = len(union_recipients(recipients[leg.correlation_key]
                                                   for leg in row_legs[msg.correlation_key]))
            result_messages.append({
                "correlation_key": msg.correlation_key,
                "message_id": msg.message_id,
                "queue_id": msg.queue_id,
                "sender": msg.sender,
                "recipient": written_recipients.shown(msg.recipient, msg.written_recipients),
                "recipient_count": recipient_count,
                "subject": msg.subject,
                "direction": msg.direction,
                "final_status": msg.final_status,
                "is_complete": msg.is_complete,
                "first_seen": format_datetime_utc(msg.first_seen),
                "last_seen": format_datetime_utc(msg.last_seen),
                "dovecot_status": msg.dovecot_status,
                "dovecot_mailbox": msg.dovecot_mailbox,
                "deliveries": len(row_legs[msg.correlation_key]),
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
            "next_cursor": f"{found[-1][1].isoformat()}|{found[-1][0].id}" if more and found else None,
            "watermark": watermark,
        }
    except Exception as e:
        logger.error(f"Error fetching unified messages: {e}")
        raise internal_error(e)


@router.get("/messages/without-message-id",
            responses=documented(NoMessageIdListResponse, errors={422: Invalid, 500: None}))
def get_messages_without_message_id(
    limit: int = Query(50, ge=1, le=500, description="Items per page"),
    search: Optional[str] = Query(None, max_length=320, description="Part of an address, the queue id, or the "
                                                                    "client's name, IP or user"),
    start_date: Optional[RangeStart] = Query(None, description="Received at or after"),
    end_date: Optional[RangeEnd] = Query(None, description="Received at or before"),
    order: str = Query("desc", pattern="^(asc|desc)$", description="By time received: desc newest first, asc oldest first"),
    cursor: Optional[str] = Query(None, max_length=80, description="The next_cursor of the page before"),
    since: List[str] = Query([], description="Time ranges to count as well, as in GET /api/messages/facets "
                                             "(name:start); the search applies, start_date and end_date do not"),
    db: Session = Depends(get_db)
):
    """
    Messages whose header held no usable Message-ID (an empty one, or none), described from their
    Postfix lines. The Messages list joins Postfix and Rspamd by Message-ID, so these are not in it:
    they have no subject and no spam score. Open one with GET /api/message/{correlation_key}/details.
    A message to or from an excluded address is left out. The total of a first page with limit=1 is
    how many there are.
    """
    after = None
    if isinstance(cursor, str) and cursor:
        try:
            at, anchor = cursor.rsplit("|", 1)
            after = (datetime.fromisoformat(at), int(anchor))
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid cursor")
    filters = dict(start=start_date if isinstance(start_date, datetime) else None,
                   end=end_date if isinstance(end_date, datetime) else None,
                   search=search if isinstance(search, str) else None)
    try:
        total = no_message_id.count(db, **filters)
        found, more = no_message_id.page(db, limit=limit, order=order, cursor=after, **filters)
        instances = no_message_id.instance_lines(db, found)
        rows = [no_message_id.summary(anchor, instances[anchor.id][1], instances[anchor.id][0], format_datetime_utc)
                for anchor, _ in found]
        last = found[-1][0] if found else None
        result = {
            "total": total,
            "data": rows,
            "next_cursor": f"{last.time.isoformat()}|{last.id}" if more and last else None,
        }
        if since:
            by_time = {"all": no_message_id.count(db, search=filters["search"])}
            for name, start in since_ranges(since):
                by_time[name] = no_message_id.count(db, start=start, search=filters["search"])
            result["time"] = by_time
        return result
    except Exception as e:
        logger.error(f"Error fetching messages without a Message-ID: {e}")
        raise internal_error(e)


def _no_message_id_details(db: Session, key: str, with_security: bool = True) -> dict:
    found = no_message_id.find(db, key)
    if not found:
        raise HTTPException(status_code=404, detail="Message not found")
    anchor, reused = found
    lines, reused = no_message_id.instance_lines(db, [(anchor, reused)])[anchor.id]
    row = no_message_id.summary(anchor, reused, lines, format_datetime_utc)
    seen, postfix_logs = set(), []
    for log in lines:
        if _postfix_line_identity(log) not in seen:
            seen.add(_postfix_line_identity(log))
            postfix_logs.append(log)
    who = None if reused else no_message_id.located(no_message_id.client(postfix_logs))
    recipients = no_message_id.recipients(postfix_logs)
    return {
        "correlation_key": row["correlation_key"],
        "message_id": None,
        "queue_id": anchor.queue_id,
        "sender": row["sender"],
        "recipient": row["recipient"],
        "recipients": recipients,
        "recipient_count": len(recipients),
        "subject": None,
        "direction": None,
        "final_status": row["final_status"],
        "is_complete": row["is_complete"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "related_deliveries": [],
        "rspamd": None,
        "dovecot": None,
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
                "recipient": log.recipient,
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
                "message": log.message,
            }
            for log in (no_message_id.netfilter_events(db, anchor, who) if with_security else [])
        ],
        "client": who,
        "queue_id_reused": bool(reused),
    }


@router.get("/message/{correlation_key}/details", responses=documented(MessageDetailsResponse, errors={404: None, 500: None}))
def get_message_full_details(
    correlation_key: str,
    request: Request = None,
    db: Session = Depends(get_db)
):
    """
    Get complete message details with all related logs
    Including Postfix, Rspamd, and Netfilter logs. A noid- key (GET /api/messages/without-message-id)
    opens a message without a Message-ID: its Postfix lines only, rspamd and dovecot null.
    The Netfilter events belong to Security: empty for a caller without View for Security.
    """
    with_security = caller_may(request, "security", READ)
    try:
        if no_message_id.is_key(correlation_key):
            return _no_message_id_details(db, correlation_key, with_security)
        correlation = db.query(MessageCorrelation).filter(
            MessageCorrelation.correlation_key == correlation_key
        ).first()
        
        if not correlation or excluded_addresses.correlation_listed(correlation):
            raise HTTPException(status_code=404, detail="Message not found")

        rspamd_log = None
        if correlation.rspamd_log_id:
            rspamd_log = db.query(RspamdLog).filter(
                RspamdLog.id == correlation.rspamd_log_id
            ).first()

        postfix_logs = shown_postfix_lines(db, correlation)

        seen_messages = set()
        deduplicated_postfix_logs = []
        for log in postfix_logs:
            msg_key = _postfix_line_identity(log)
            if msg_key not in seen_messages:
                seen_messages.add(msg_key)
                deduplicated_postfix_logs.append(log)
        queue_lines = excluded_addresses.queue_lines(db, correlation.queue_id)
        if excluded_addresses.delivery_hidden(
                correlation, deduplicated_postfix_logs if queue_lines is None else queue_lines):
            raise HTTPException(status_code=404, detail="Message not found")
        postfix_logs = excluded_addresses.visible_postfix_lines(deduplicated_postfix_logs, queue_lines)
        if not correlation.queue_id and postfix_logs and excluded_addresses.listed():
            visible = {line_id for (line_id,) in db.query(PostfixLog.id).filter(
                PostfixLog.id.in_([log.id for log in postfix_logs]),
                excluded_addresses.postfix_line_visible_among(
                    list({log.queue_id for log in postfix_logs if log.queue_id}))).all()}
            postfix_logs = [log for log in postfix_logs if log.id in visible]
        
        netfilter_logs = []
        if with_security and rspamd_log and rspamd_log.ip and rspamd_log.time:
            window = timedelta(hours=1)
            netfilter_logs = db.query(NetfilterLog).filter(
                NetfilterLog.ip == rspamd_log.ip,
                NetfilterLog.time >= rspamd_log.time - window,
                NetfilterLog.time <= rspamd_log.time + window,
            ).order_by(NetfilterLog.time.desc()).limit(100).all()

        related_deliveries = []
        other_legs = []
        other_recipients = {}
        if correlation.message_id:
            other_legs = db.query(MessageCorrelation).filter(
                MessageCorrelation.message_id == correlation.message_id,
                MessageCorrelation.correlation_key != correlation.correlation_key
            ).order_by(MessageCorrelation.first_seen).all()
            hidden = excluded_addresses.hidden_deliveries(db, other_legs)
            other_legs = [leg for leg in other_legs if leg.correlation_key not in hidden]
            if other_legs:
                other_recipients = legs_recipients(db, other_legs)
            related_deliveries = [
                {
                    "correlation_key": leg.correlation_key,
                    "sender": leg.sender,
                    "recipient": written_recipients.shown(leg.recipient, leg.written_recipients),
                    "direction": leg.direction,
                    "final_status": leg.final_status,
                    "first_seen": format_datetime_utc(leg.first_seen),
                    "queue_id": leg.queue_id,
                    "dovecot_status": leg.dovecot_status,
                    "dovecot_mailbox": leg.dovecot_mailbox,
                    "recipients": other_recipients[leg.correlation_key],
                }
                for leg in other_legs
            ]

        subject = correlation.subject
        if not subject and correlation.message_id:
            subject = next((leg.subject for leg in other_legs if leg.subject), None)

        dovecot_logs = _get_dovecot_logs(
            db, correlation, single_leg=not related_deliveries
        )

        recipients = written_recipients.shown_list(
            listed_recipients(rspamd_log, (log.recipient for log in postfix_logs)), correlation.written_recipients)
        own = resolve_recipients(
            recipients, [(log.recipient, written_address(log.recipient, log.message)) for log in postfix_logs],
            correlation.recipient)
        recipient_count = len(union_recipients([own] + [other_recipients[leg.correlation_key] for leg in other_legs]))

        return {
            "correlation_key": correlation.correlation_key,
            "message_id": correlation.message_id,
            "queue_id": correlation.queue_id,
            "sender": correlation.sender,
            "recipient": written_recipients.shown(correlation.recipient, correlation.written_recipients),
            "recipients": recipients,
            "recipient_count": recipient_count,
            "subject": subject,
            "direction": correlation.direction,
            "final_status": correlation.final_status,
            "is_complete": correlation.is_complete,
            "first_seen": format_datetime_utc(correlation.first_seen),
            "last_seen": format_datetime_utc(correlation.last_seen),
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
                    "recipient": log.recipient
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