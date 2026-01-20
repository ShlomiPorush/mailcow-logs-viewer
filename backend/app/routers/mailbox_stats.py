"""
API endpoints for mailbox statistics with message counts
Shows per-mailbox/per-alias message statistics from MessageCorrelation table
"""
import logging
import hashlib
import json
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, case, and_, or_
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from ..database import get_db
from ..models import MailboxStatistics, AliasStatistics, MessageCorrelation

logger = logging.getLogger(__name__)

router = APIRouter()

# =============================================================================
# CACHING SYSTEM
# =============================================================================

# In-memory cache for mailbox stats
_stats_cache = {}
_cache_ttl_seconds = 300  # 5 minutes cache TTL


def _get_cache_key(prefix: str, **params) -> str:
    """Generate a cache key from parameters"""
    param_str = json.dumps(params, sort_keys=True, default=str)
    hash_val = hashlib.md5(param_str.encode()).hexdigest()[:16]
    return f"{prefix}:{hash_val}"


def _get_cached(key: str):
    """Get cached value if not expired"""
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
    _stats_cache[key] = (data, datetime.now(timezone.utc))
    logger.debug(f"Cache set for key: {key}")


def clear_stats_cache():
    """Clear all stats cache - call after data changes"""
    global _stats_cache
    _stats_cache = {}
    logger.info("Stats cache cleared")


def format_datetime_utc(dt: Optional[datetime]) -> Optional[str]:
    """Format datetime for API response with proper UTC timezone"""
    if dt is None:
        return None
    
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc.replace(microsecond=0).isoformat().replace('+00:00', 'Z')


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


def get_message_counts_for_email(db: Session, email: str, start_date: datetime, end_date: datetime) -> dict:
    """
    Get message counts for a specific email address (mailbox or alias)
    Counts sent (as sender) and received (as recipient) with status breakdown
    Also counts by direction (inbound, outbound, internal)
    """
    # Count sent messages (this email as sender) by status
    sent_query = db.query(
        MessageCorrelation.final_status,
        func.count(MessageCorrelation.id).label('count')
    ).filter(
        MessageCorrelation.sender == email,
        MessageCorrelation.first_seen >= start_date,
        MessageCorrelation.first_seen <= end_date
    ).group_by(MessageCorrelation.final_status).all()
    
    # Count received messages (this email as recipient) by status
    received_query = db.query(
        MessageCorrelation.final_status,
        func.count(MessageCorrelation.id).label('count')
    ).filter(
        MessageCorrelation.recipient == email,
        MessageCorrelation.first_seen >= start_date,
        MessageCorrelation.first_seen <= end_date
    ).group_by(MessageCorrelation.final_status).all()
    
    # Count by direction (inbound, outbound, internal)
    direction_query = db.query(
        MessageCorrelation.direction,
        func.count(MessageCorrelation.id).label('count')
    ).filter(
        or_(
            MessageCorrelation.sender == email,
            MessageCorrelation.recipient == email
        ),
        MessageCorrelation.first_seen >= start_date,
        MessageCorrelation.first_seen <= end_date
    ).group_by(MessageCorrelation.direction).all()
    
    # Process results
    sent_by_status = {row.final_status or 'unknown': row.count for row in sent_query}
    received_by_status = {row.final_status or 'unknown': row.count for row in received_query}
    direction_counts = {row.direction or 'unknown': row.count for row in direction_query}
    
    sent_total = sum(sent_by_status.values())
    received_total = sum(received_by_status.values())
    
    # Calculate failures (only for sent messages - bounces and rejections are outbound failures)
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
        # Direction counts
        "direction_inbound": direction_counts.get('inbound', 0),
        "direction_outbound": direction_counts.get('outbound', 0),
        "direction_internal": direction_counts.get('internal', 0)
    }


@router.get("/mailbox-stats/summary")
async def get_mailbox_stats_summary(
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
        
        # Get all local mailbox emails and alias emails
        mailbox_emails = [m.username for m in db.query(MailboxStatistics.username).all()]
        alias_emails = [a.alias_address for a in db.query(AliasStatistics.alias_address).all()]
        all_local_emails = set(mailbox_emails + alias_emails)
        
        # Count total messages for all local emails
        total_sent = 0
        total_received = 0
        total_failed = 0
        
        if all_local_emails:
            # Sent messages
            sent_result = db.query(func.count(MessageCorrelation.id)).filter(
                MessageCorrelation.sender.in_(all_local_emails),
                MessageCorrelation.first_seen >= parsed_start,
                MessageCorrelation.first_seen <= parsed_end
            ).scalar() or 0
            total_sent = sent_result
            
            # Received messages
            received_result = db.query(func.count(MessageCorrelation.id)).filter(
                MessageCorrelation.recipient.in_(all_local_emails),
                MessageCorrelation.first_seen >= parsed_start,
                MessageCorrelation.first_seen <= parsed_end
            ).scalar() or 0
            total_received = received_result
            
            # Failed messages (only sent that bounced/rejected - failures are outbound)
            failed_result = db.query(func.count(MessageCorrelation.id)).filter(
                MessageCorrelation.sender.in_(all_local_emails),
                MessageCorrelation.first_seen >= parsed_start,
                MessageCorrelation.first_seen <= parsed_end,
                MessageCorrelation.final_status.in_(['bounced', 'rejected'])
            ).scalar() or 0
            total_sent_failed = failed_result
        
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
async def get_all_mailbox_stats(
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
        
        # Apply domain filter
        if domain:
            query = query.filter(MailboxStatistics.domain == domain)
        
        # Apply active filter
        if active_only:
            query = query.filter(MailboxStatistics.active == True)
        
        # Apply search filter on mailbox username/name OR mailboxes that have matching aliases
        if search:
            mailbox_search_term = f"%{search}%"
            
            # Find mailboxes that have matching aliases
            alias_matched_usernames = db.query(AliasStatistics.primary_mailbox).filter(
                AliasStatistics.alias_address.ilike(mailbox_search_term)
            ).distinct().subquery()
            
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
        
        # Build result with message counts for each mailbox
        result = []
        for mb in mailboxes:
            # Get message counts for this mailbox
            counts = get_message_counts_for_email(db, mb.username, parsed_start, parsed_end)
            
            # Get aliases for this mailbox
            aliases = db.query(AliasStatistics).filter(
                AliasStatistics.primary_mailbox == mb.username
            ).all()
            
            # Get message counts for each alias
            alias_list = []
            alias_sent_total = 0
            alias_received_total = 0
            alias_failed_total = 0
            alias_internal_total = 0
            alias_delivered_total = 0
            
            for alias in aliases:
                alias_counts = get_message_counts_for_email(db, alias.alias_address, parsed_start, parsed_end)
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
async def get_mailbox_domains(db: Session = Depends(get_db)):
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
        
        return {
            "domains": [
                {"domain": d.domain, "mailbox_count": d.count}
                for d in domains
            ]
        }
    except Exception as e:
        logger.error(f"Error fetching mailbox domains: {e}")
        return {"error": str(e), "domains": []}


@router.get("/mailbox-stats/refresh")
async def refresh_mailbox_stats(db: Session = Depends(get_db)):
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
