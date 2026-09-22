"""
API endpoints for mailbox statistics with message counts
Shows per-mailbox/per-alias message statistics from MessageCorrelation table
"""
import logging
import hashlib
import json
from threading import Lock
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, case, and_, or_
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from ..database import get_db
from ..models import MailboxStatistics, AliasStatistics, MessageCorrelation

from ..utils import format_datetime_for_api as format_datetime_utc

logger = logging.getLogger(__name__)

from app.services.alias_domains import get_alias_domain_map, expand_address

router = APIRouter()

# =============================================================================
# CACHING SYSTEM
# =============================================================================

# In-memory cache for mailbox stats
_stats_cache = {}
_stats_cache_lock = Lock()
_cache_ttl_seconds = 300  # 5 minutes cache TTL


def _get_cache_key(prefix: str, **params) -> str:
    """Generate a cache key from parameters"""
    param_str = json.dumps(params, sort_keys=True, default=str)
    hash_val = hashlib.md5(param_str.encode()).hexdigest()[:16]
    return f"{prefix}:{hash_val}"


def _get_cached(key: str):
    """Get cached value if not expired"""
    with _stats_cache_lock:
        if key in _stats_cache:
            cached_data, cached_time = _stats_cache[key]
            if datetime.now(timezone.utc) - cached_time < timedelta(seconds=_cache_ttl_seconds):
                logger.debug(f"Cache hit for key: {key}")
                return cached_data
            else:
                # Cache expired, remove it
                del _stats_cache[key]
    return None


def _set_cache(key: str, data):
    """Set cached value with current timestamp"""
    with _stats_cache_lock:
        _stats_cache[key] = (data, datetime.now(timezone.utc))
    logger.debug(f"Cache set for key: {key}")


def clear_stats_cache():
    """Clear all stats cache - call after data changes"""
    with _stats_cache_lock:
        _stats_cache.clear()
    logger.info("Stats cache cleared")


def format_bytes(bytes_value) -> str:
    """Format bytes into human-readable format"""
    if bytes_value is None:
        return "0 B"
    
    bytes_value = float(bytes_value)
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(bytes_value) < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def format_unix_timestamp(timestamp: Optional[int]) -> Optional[str]:
    """Convert Unix timestamp to ISO format string"""
    if timestamp is None or timestamp == 0:
        return None
    try:
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    except (ValueError, OSError):
        return None


def parse_date_range(date_range: str, start_date: Optional[str] = None, end_date: Optional[str] = None) -> tuple[datetime, datetime]:
    """Parse date range string into start and end datetimes
    
    For custom date ranges, start_date and end_date should be ISO format strings (YYYY-MM-DD)
    """
    now = datetime.now(timezone.utc)
    
    if date_range == "custom" and start_date and end_date:
        # Parse custom date range
        try:
            start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            if start.tzinfo is None:
                start = start.replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc)
            
            end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            if end.tzinfo is None:
                # Set end time to end of day
                end = end.replace(hour=23, minute=59, second=59, microsecond=999999, tzinfo=timezone.utc)
            
            return start, end
        except ValueError:
            # If parsing fails, fall back to 30 days
            logger.warning(f"Failed to parse custom date range: {start_date} - {end_date}, falling back to 30 days")
            start = now - timedelta(days=30)
            end = now
    elif date_range == "today":
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = now
    elif date_range == "7days":
        start = now - timedelta(days=7)
        end = now
    elif date_range == "30days":
        start = now - timedelta(days=30)
        end = now
    elif date_range == "90days":
        start = now - timedelta(days=90)
        end = now
    else:
        # Default to 30 days
        start = now - timedelta(days=30)
        end = now
    
    return start, end


def _empty_counts() -> dict:
    """Return a zeroed-out counts dict"""
    return {
        "sent_total": 0, "sent_delivered": 0, "sent_bounced": 0,
        "sent_rejected": 0, "sent_deferred": 0, "sent_expired": 0,
        "sent_failed": 0, "received_total": 0, "total_messages": 0,
        "failure_rate": 0.0,
        "direction_inbound": 0, "direction_outbound": 0, "direction_internal": 0
    }


def _counts_from_raw(sent_by_status: dict, received_total: int, direction_counts: dict) -> dict:
    """Build a counts dict from pre-aggregated data"""
    sent_total = sum(sent_by_status.values())
    sent_failed = sent_by_status.get('bounced', 0) + sent_by_status.get('rejected', 0)
    total = sent_total + received_total
    failure_rate = round((sent_failed / sent_total * 100) if sent_total > 0 else 0, 1)
    return {
        "sent_total": sent_total,
        "sent_delivered": sent_by_status.get('delivered', 0) + sent_by_status.get('sent', 0),
        "sent_bounced": sent_by_status.get('bounced', 0),
        "sent_rejected": sent_by_status.get('rejected', 0),
        "sent_deferred": sent_by_status.get('deferred', 0),
        "sent_expired": sent_by_status.get('expired', 0),
        "sent_failed": sent_failed,
        "received_total": received_total,
        "total_messages": total,
        "failure_rate": failure_rate,
        "direction_inbound": direction_counts.get('inbound', 0),
        "direction_outbound": direction_counts.get('outbound', 0),
        "direction_internal": direction_counts.get('internal', 0)
    }


# Best outcome first. One message can reach a mailbox through several delivery
# legs - a forward, a redirect that was refused, a release from quarantine -
# and the most successful leg is the one that describes what happened to it,
# so a failed attempt never counts against a mailbox that was delivered later.
_STATUS_PREFERENCE = ['delivered', 'sent', 'deferred', 'spam',
                      'discarded', 'bounced', 'rejected', 'expired']


def _representative_legs(db: Session, address_column, emails_lower: list,
                         start_date: datetime, end_date: datetime):
    """
    Sub-select of one leg per (mailbox address, message), the most successful one.

    Statistics count messages, not delivery legs (issue #36). Legs of one
    message are grouped by Message-ID; a correlation without a Message-ID falls
    back to its own key and is never merged with another. The chosen leg is
    marked leg_rank = 1 and lends the message its status and direction.
    """
    email = func.lower(address_column)
    message_key = func.coalesce(
        MessageCorrelation.message_id, MessageCorrelation.correlation_key
    )
    status_rank = case(
        *[(MessageCorrelation.final_status == status, rank)
          for rank, status in enumerate(_STATUS_PREFERENCE)],
        else_=99
    )
    return db.query(
        email.label('email'),
        MessageCorrelation.final_status.label('final_status'),
        MessageCorrelation.direction.label('direction'),
        func.row_number().over(
            partition_by=(email, message_key),
            order_by=(status_rank, MessageCorrelation.id.asc())
        ).label('leg_rank')
    ).filter(
        email.in_(emails_lower),
        MessageCorrelation.first_seen >= start_date,
        MessageCorrelation.first_seen <= end_date
    ).subquery()


def get_bulk_message_counts(db: Session, emails: list, start_date: datetime, end_date: datetime) -> dict:
    """
    Get message counts for ALL emails in a single pass using 2 bulk aggregate queries.
    Returns a dict mapping lowercase-email -> counts dict.

    PERFORMANCE: This replaces the old per-email approach (3 queries × N emails = 3N queries)
    with exactly 2 aggregate queries regardless of how many emails exist.
    """
    if not emails:
        return {}

    emails_lower = list({e.lower() for e in emails})

    # --- Query 1: Sent stats (group by sender + status + direction) ---
    sent_legs = _representative_legs(
        db, MessageCorrelation.sender, emails_lower, start_date, end_date)
    sent_rows = db.query(
        sent_legs.c.email,
        sent_legs.c.final_status,
        sent_legs.c.direction,
        func.count().label('cnt')
    ).filter(
        sent_legs.c.leg_rank == 1
    ).group_by(
        sent_legs.c.email,
        sent_legs.c.final_status,
        sent_legs.c.direction
    ).all()

    # --- Query 2: Received stats (group by recipient + direction) ---
    recv_legs = _representative_legs(
        db, MessageCorrelation.recipient, emails_lower, start_date, end_date)
    recv_rows = db.query(
        recv_legs.c.email,
        recv_legs.c.direction,
        func.count().label('cnt')
    ).filter(
        recv_legs.c.leg_rank == 1
    ).group_by(
        recv_legs.c.email,
        recv_legs.c.direction
    ).all()

    # --- Build per-email lookup ---
    # sent_data[email] = {status: count}
    sent_data = {}
    # direction_data[email] = {direction: count}  (from sent side)
    dir_data_sent = {}
    for row in sent_rows:
        em = row.email
        status = row.final_status or 'unknown'
        direction = row.direction or 'unknown'
        sent_data.setdefault(em, {})
        sent_data[em][status] = sent_data[em].get(status, 0) + row.cnt
        dir_data_sent.setdefault(em, {})
        dir_data_sent[em][direction] = dir_data_sent[em].get(direction, 0) + row.cnt

    # recv_data[email] = total_received
    recv_data = {}
    # direction_data from recv side
    dir_data_recv = {}
    for row in recv_rows:
        em = row.email
        direction = row.direction or 'unknown'
        recv_data[em] = recv_data.get(em, 0) + row.cnt
        dir_data_recv.setdefault(em, {})
        dir_data_recv[em][direction] = dir_data_recv[em].get(direction, 0) + row.cnt

    # --- Assemble per-email counts ---
    result = {}
    for em in emails_lower:
        sent_by_status = sent_data.get(em, {})
        received_total = recv_data.get(em, 0)
        # Merge direction counts from sent + received
        dir_counts = {}
        for d, c in dir_data_sent.get(em, {}).items():
            dir_counts[d] = dir_counts.get(d, 0) + c
        for d, c in dir_data_recv.get(em, {}).items():
            dir_counts[d] = dir_counts.get(d, 0) + c
        result[em] = _counts_from_raw(sent_by_status, received_total, dir_counts)

    return result


def get_message_counts_for_email(db: Session, email: str, start_date: datetime, end_date: datetime) -> dict:
    """
    Get message counts for a single email. Thin wrapper around bulk version.
    Kept for backward compatibility with summary endpoint.
    """
    bulk = get_bulk_message_counts(db, [email], start_date, end_date)
    return bulk.get(email.lower(), _empty_counts())


@router.get("/mailbox-stats/summary")
def get_mailbox_stats_summary(
    date_range: str = Query("30days", description="Date range: today, 7days, 30days, 90days, custom"),
    start_date: Optional[str] = Query(None, description="Custom start date (YYYY-MM-DD) - required when date_range is 'custom'"),
    end_date: Optional[str] = Query(None, description="Custom end date (YYYY-MM-DD) - required when date_range is 'custom'"),
    db: Session = Depends(get_db)
):
    """
    Get summary statistics for all mailboxes
    """
    try:
        parsed_start, parsed_end = parse_date_range(date_range, start_date, end_date)
        
        # Total mailboxes
        total_mailboxes = db.query(func.count(MailboxStatistics.id)).scalar() or 0
        active_mailboxes = db.query(func.count(MailboxStatistics.id)).filter(
            MailboxStatistics.active == True
        ).scalar() or 0
        
        # Total aliases
        total_aliases = db.query(func.count(AliasStatistics.id)).scalar() or 0
        active_aliases = db.query(func.count(AliasStatistics.id)).filter(
            AliasStatistics.active == True
        ).scalar() or 0
        
        # Unique domains
        unique_domains = db.query(func.count(func.distinct(MailboxStatistics.domain))).scalar() or 0
        
        # Get total storage used
        total_quota_used = db.query(func.sum(MailboxStatistics.quota_used)).scalar() or 0
        
        # Get last update time
        last_update = db.query(func.max(MailboxStatistics.updated_at)).scalar()
        
        # Get all local mailbox emails and alias emails (lowercased for case-insensitive matching)
        mailbox_emails = [m.username.lower() for m in db.query(MailboxStatistics.username).all()]
        alias_emails = [a.alias_address.lower() for a in db.query(AliasStatistics.alias_address).all()]
        all_local_emails = set(mailbox_emails + alias_emails)
        # A mailcow alias domain mirrors every address of its target domain, so
        # user@alias.tld is the same mailbox as user@target.tld (issue #92)
        alias_domain_map = get_alias_domain_map(db)
        if alias_domain_map:
            for email in list(all_local_emails):
                all_local_emails.update(expand_address(email, alias_domain_map))
        
        # Count total messages for all local emails (case-insensitive)
        total_sent = 0
        total_received = 0
        total_sent_failed = 0
        
        if all_local_emails:
            # Count each message once per mailbox instead of once per delivery
            # leg (issue #36). The per-mailbox counter already does exactly
            # that, and reusing it keeps these cards and the mailbox rows
            # below them telling the same story. Failures are outbound only,
            # and a message that was delivered on a later leg is not a failure.
            per_email_counts = get_bulk_message_counts(
                db, list(all_local_emails), parsed_start, parsed_end)
            for counts in per_email_counts.values():
                total_sent += counts['sent_total']
                total_received += counts['received_total']
                total_sent_failed += counts['sent_failed']

        total_messages = total_sent + total_received
        failure_rate = round((total_sent_failed / total_sent * 100) if total_sent > 0 else 0, 1)
        
        return {
            "total_sent": total_sent,
            "total_received": total_received,
            "total_messages": total_messages,
            "sent_failed": total_sent_failed,
            "failure_rate": failure_rate,
            "date_range": date_range,
            "start_date": format_datetime_utc(parsed_start),
            "end_date": format_datetime_utc(parsed_end),
            "last_update": format_datetime_utc(last_update)
        }
    except Exception as e:
        logger.error(f"Error fetching mailbox stats summary: {e}")
        return {"error": str(e), "total_mailboxes": 0}


@router.get("/mailbox-stats/all")
def get_all_mailbox_stats(
    domain: Optional[str] = None,
    active_only: bool = True,  # Changed default to True
    hide_zero: bool = False,  # Filter out mailboxes with zero activity
    search: Optional[str] = None,
    date_range: str = Query("30days", description="Date range: today, 7days, 30days, 90days, custom"),
    start_date: Optional[str] = Query(None, description="Custom start date (YYYY-MM-DD) - required when date_range is 'custom'"),
    end_date: Optional[str] = Query(None, description="Custom end date (YYYY-MM-DD) - required when date_range is 'custom'"),
    sort_by: str = "sent_total",
    sort_order: str = "desc",
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=10, le=100, description="Items per page"),
    db: Session = Depends(get_db)
):
    """
    Get all mailbox statistics with message counts and aliases (paginated)
    """
    try:
        # Check cache first
        cache_key = _get_cache_key(
            "mailbox_stats_all",
            domain=domain,
            active_only=active_only,
            hide_zero=hide_zero,
            search=search,
            date_range=date_range,
            start_date=start_date,
            end_date=end_date,
            sort_by=sort_by,
            sort_order=sort_order,
            page=page,
            page_size=page_size
        )
        
        cached_result = _get_cached(cache_key)
        if cached_result is not None:
            return cached_result
        
        parsed_start, parsed_end = parse_date_range(date_range, start_date, end_date)
        
        query = db.query(MailboxStatistics)
        
        # Apply domain filter. Selecting an alias domain shows the mailboxes of
        # its target domain, since those are the mailboxes it delivers to
        if domain:
            target = get_alias_domain_map(db).get(domain.lower(), domain)
            query = query.filter(MailboxStatistics.domain == target)
        
        # Apply active filter
        if active_only:
            query = query.filter(MailboxStatistics.active == True)
        
        # Apply search filter on mailbox username/name OR mailboxes that have matching aliases
        if search:
            mailbox_search_term = f"%{search}%"
            
            # Find mailboxes that have matching aliases
            alias_matched_usernames = db.query(AliasStatistics.primary_mailbox).filter(
                AliasStatistics.alias_address.ilike(mailbox_search_term)
            ).distinct().scalar_subquery()
            
            query = query.filter(
                or_(
                    MailboxStatistics.username.ilike(mailbox_search_term),
                    MailboxStatistics.name.ilike(mailbox_search_term),
                    MailboxStatistics.username.in_(alias_matched_usernames)
                )
            )
        
        # Get total count before pagination
        total_count = query.count()
        
        # Get all for sorting (we need to calculate counts before pagination)
        mailboxes = query.all()
        
        # Pre-load ALL aliases in one query (avoids N+1 alias queries)
        all_aliases = db.query(AliasStatistics).all()
        aliases_by_mailbox = {}
        for alias in all_aliases:
            aliases_by_mailbox.setdefault(alias.primary_mailbox, []).append(alias)
        
        # Collect ALL emails (mailboxes + aliases) for bulk counting.
        # Alias-domain variants (user@alias.tld for user@target.tld) are
        # counted too and shown as their own alias rows (issue #92)
        alias_domain_map = get_alias_domain_map(db)
        domain_alias_addresses = {}   # mailbox username -> [variant addresses]
        all_emails = [mb.username for mb in mailboxes]
        for mb in mailboxes:
            variants = list(expand_address(mb.username, alias_domain_map))
            for alias in aliases_by_mailbox.get(mb.username, []):
                all_emails.append(alias.alias_address)
                variants.extend(expand_address(alias.alias_address, alias_domain_map))
            domain_alias_addresses[mb.username] = variants
            all_emails.extend(variants)
        
        # Run bulk message counts (2 SQL queries total instead of 3×N)
        bulk_counts = get_bulk_message_counts(db, all_emails, parsed_start, parsed_end)
        
        # Build result using pre-computed counts
        result = []
        for mb in mailboxes:
            counts = bulk_counts.get(mb.username.lower(), _empty_counts())
            
            aliases = aliases_by_mailbox.get(mb.username, [])
            
            alias_list = []
            alias_sent_total = 0
            alias_received_total = 0
            alias_failed_total = 0
            alias_internal_total = 0
            alias_delivered_total = 0
            
            for alias in aliases:
                alias_counts = bulk_counts.get(alias.alias_address.lower(), _empty_counts())
                alias_sent_total += alias_counts['sent_total']
                alias_received_total += alias_counts['received_total']
                alias_failed_total += alias_counts['sent_failed']
                alias_internal_total += alias_counts['direction_internal']
                alias_delivered_total += alias_counts['sent_delivered']
                
                alias_list.append({
                    "alias_address": alias.alias_address,
                    "active": alias.active,
                    "is_catch_all": alias.is_catch_all,
                    **alias_counts
                })
            
            # Addresses on an alias domain belong to this mailbox too. They are
            # listed as alias rows (not folded into the mailbox count), so the
            # combined totals below count each message exactly once
            for variant in domain_alias_addresses.get(mb.username, []):
                variant_counts = bulk_counts.get(variant, _empty_counts())
                if variant_counts['sent_total'] == 0 and variant_counts['received_total'] == 0:
                    continue
                alias_sent_total += variant_counts['sent_total']
                alias_received_total += variant_counts['received_total']
                alias_failed_total += variant_counts['sent_failed']
                alias_internal_total += variant_counts['direction_internal']
                alias_delivered_total += variant_counts['sent_delivered']
                alias_list.append({
                    "alias_address": variant,
                    "active": True,
                    "is_catch_all": False,
                    "is_domain_alias": True,
                    **variant_counts
                })

            # Calculate combined totals (mailbox + all aliases)
            combined_sent = counts['sent_total'] + alias_sent_total
            combined_received = counts['received_total'] + alias_received_total
            combined_total = combined_sent + combined_received
            combined_failed = counts['sent_failed'] + alias_failed_total
            combined_failure_rate = round((combined_failed / combined_sent * 100) if combined_sent > 0 else 0, 1)
            combined_internal = counts['direction_internal'] + alias_internal_total
            combined_delivered = counts['sent_delivered'] + alias_delivered_total
            combined_inbound = counts['direction_inbound']
            combined_outbound = counts['direction_outbound']
            
            result.append({
                "id": mb.id,
                "username": mb.username,
                "domain": mb.domain,
                "name": mb.name,
                "active": mb.active,
                # Quota info
                "quota": float(mb.quota or 0),
                "quota_formatted": format_bytes(mb.quota),
                "quota_used": float(mb.quota_used or 0),
                "quota_used_formatted": format_bytes(mb.quota_used),
                "percent_in_use": round(float(mb.percent_in_use or 0), 1),
                "messages_in_mailbox": mb.messages or 0,
                # Last login times
                "last_imap_login": format_unix_timestamp(mb.last_imap_login),
                "last_pop3_login": format_unix_timestamp(mb.last_pop3_login),
                "last_smtp_login": format_unix_timestamp(mb.last_smtp_login),
                # Rate limiting
                "rl_value": mb.rl_value,
                "rl_frame": mb.rl_frame,
                # Attributes (access permissions)
                "attributes": mb.attributes or {},
                # Message counts for mailbox only
                "mailbox_counts": counts,
                # Aliases
                "aliases": alias_list,
                "alias_count": len(alias_list),
                # Combined totals (mailbox + aliases)
                "combined_sent": combined_sent,
                "combined_received": combined_received,
                "combined_total": combined_total,
                "combined_failed": combined_failed,
                "combined_failure_rate": combined_failure_rate,
                # Direction and status combined counts
                "combined_internal": combined_internal,
                "combined_delivered": combined_delivered,
                "combined_inbound": combined_inbound,
                "combined_outbound": combined_outbound,
                # Metadata
                "created": format_datetime_utc(mb.created_at),
                "modified": format_datetime_utc(mb.updated_at)
            })
        
        # Sort results
        reverse = sort_order.lower() == "desc"
        if sort_by == "sent_total":
            result.sort(key=lambda x: x['combined_sent'], reverse=reverse)
        elif sort_by == "received_total":
            result.sort(key=lambda x: x['combined_received'], reverse=reverse)
        elif sort_by == "failure_rate":
            result.sort(key=lambda x: x['combined_failure_rate'], reverse=reverse)
        elif sort_by == "username":
            result.sort(key=lambda x: x['username'].lower(), reverse=reverse)
        elif sort_by == "quota_used":
            result.sort(key=lambda x: x['quota_used'], reverse=reverse)
        else:
            result.sort(key=lambda x: x['combined_total'], reverse=reverse)
        
        # Apply hide_zero filter - remove mailboxes with no activity
        if hide_zero:
            result = [r for r in result if r['combined_total'] > 0]
        
        # Apply pagination
        total_pages = (len(result) + page_size - 1) // page_size
        start_index = (page - 1) * page_size
        end_index = start_index + page_size
        paginated_result = result[start_index:end_index]
        
        response = {
            "total": len(result),
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "date_range": date_range,
            "start_date": format_datetime_utc(parsed_start),
            "end_date": format_datetime_utc(parsed_end),
            "mailboxes": paginated_result
        }
        
        # Cache the result
        _set_cache(cache_key, response)
        
        return response
    except Exception as e:
        logger.error(f"Error fetching all mailbox stats: {e}")
        return {"error": str(e), "total": 0, "mailboxes": []}


@router.get("/mailbox-stats/domains")
def get_mailbox_domains(db: Session = Depends(get_db)):
    """
    Get list of all domains for filtering
    """
    try:
        domains = db.query(
            MailboxStatistics.domain,
            func.count(MailboxStatistics.id).label('count')
        ).group_by(
            MailboxStatistics.domain
        ).order_by(
            MailboxStatistics.domain
        ).all()
        
        entries = [
            {"domain": d.domain, "mailbox_count": d.count}
            for d in domains
        ]
        # Alias domains appear as their own entries so they can be selected;
        # they carry their target's mailbox count
        alias_domain_map = get_alias_domain_map(db)
        counts_by_domain = {d.domain: d.count for d in domains}
        for alias in sorted(alias_domain_map):
            target = alias_domain_map[alias]
            if target in counts_by_domain and alias not in counts_by_domain:
                entries.append({"domain": alias, "mailbox_count": counts_by_domain[target],
                                "alias_of": target})
        entries.sort(key=lambda x: x["domain"])
        return {"domains": entries}
    except Exception as e:
        logger.error(f"Error fetching mailbox domains: {e}")
        return {"error": str(e), "domains": []}


@router.get("/mailbox-stats/refresh")
def refresh_mailbox_stats(db: Session = Depends(get_db)):
    """
    Get last update time for mailbox statistics
    """
    try:
        last_mailbox_update = db.query(func.max(MailboxStatistics.updated_at)).scalar()
        last_alias_update = db.query(func.max(AliasStatistics.updated_at)).scalar()
        
        return {
            "last_mailbox_update": format_datetime_utc(last_mailbox_update),
            "last_alias_update": format_datetime_utc(last_alias_update)
        }
    except Exception as e:
        logger.error(f"Error getting refresh info: {e}")
        return {"error": str(e)}
