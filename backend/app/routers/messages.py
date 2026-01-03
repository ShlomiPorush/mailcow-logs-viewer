"""
API endpoints for unified messages view
Combines Postfix and Rspamd logs into a single view
FIXED: All timestamps now sent with proper UTC timezone ('Z' suffix)
"""
import logging
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc, select
from datetime import datetime, timedelta, timezone
from typing import Optional

from ..database import get_db
from ..models import MessageCorrelation, PostfixLog, RspamdLog, NetfilterLog
from ..config import settings

logger = logging.getLogger(__name__)

router = APIRouter()


def format_datetime_utc(dt: Optional[datetime]) -> Optional[str]:
    """
    Format datetime for API response with proper UTC timezone
    Always returns ISO format with 'Z' suffix so browser knows it's UTC
    """
    if dt is None:
        return None
    
    # If naive (no timezone), assume UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    # Convert to UTC if not already
    dt_utc = dt.astimezone(timezone.utc)
    
    # Format as ISO string with 'Z' suffix for UTC
    return dt_utc.replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def is_blacklisted(email: str) -> bool:
    """
    Check if email is in blacklist
    
    Args:
        email: Email address to check
    
    Returns:
        True if blacklisted, False otherwise
    """
    if not email:
        return False
    
    email_lower = email.lower().strip()
    blacklist = settings.blacklist_emails_list
    
    return email_lower in blacklist


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


@router.get("/messages")
async def get_unified_messages(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=500, description="Items per page"),
    search: Optional[str] = Query(None, description="Search query"),
    sender: Optional[str] = Query(None, description="Filter by sender"),
    recipient: Optional[str] = Query(None, description="Filter by recipient"),
    direction: Optional[str] = Query(None, description="Filter by direction"),
    status: Optional[str] = Query(None, description="Filter by status"),
    user: Optional[str] = Query(None, description="Filter by authenticated user"),
    ip: Optional[str] = Query(None, description="Filter by source IP"),
    start_date: Optional[datetime] = Query(None, description="Start date"),
    end_date: Optional[datetime] = Query(None, description="End date"),
    db: Session = Depends(get_db)
):
    """
    Get unified messages view (combines Postfix + Rspamd)
    """
    try:
        query = db.query(MessageCorrelation)
        
        # Exclude blacklisted correlations
        query = query.filter(MessageCorrelation.correlation_key != "BLACKLISTED")
        
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
        
        # Get total count (before blacklist filter)
        total_before_filter = query.count()
        
        # Apply pagination
        offset = (page - 1) * limit
        messages = query.order_by(desc(MessageCorrelation.last_seen)).offset(offset).limit(limit * 2).all()
        
        # Filter out blacklisted emails and build response
        result_messages = []
        for msg in messages:
            # Check blacklist
            if is_blacklisted(msg.sender) or is_blacklisted(msg.recipient):
                continue
            
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
                "spam_score": rspamd_log.score if rspamd_log else None,
                "is_spam": rspamd_log.is_spam if rspamd_log else None,
                "user": rspamd_log.user if rspamd_log else None,
                "ip": rspamd_log.ip if rspamd_log else None
            })
            
            # Stop when we have enough messages
            if len(result_messages) >= limit:
                break
        
        return {
            "total": total_before_filter,
            "page": page,
            "limit": limit,
            "pages": (total_before_filter + limit - 1) // limit if total_before_filter > 0 else 0,
            "data": result_messages
        }
    except Exception as e:
        logger.error(f"Error fetching unified messages: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/message/{correlation_key}/details")
async def get_message_full_details(
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
        
        if not correlation:
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
        postfix_logs = deduplicated_postfix_logs
        
        # Get Netfilter logs by IP from Rspamd
        # Simply filter by IP without time restrictions to show all security events
        netfilter_logs = []
        if rspamd_log and rspamd_log.ip:
            # Get all Netfilter logs for this IP (no time window restriction)
            netfilter_logs = db.query(NetfilterLog).filter(
                NetfilterLog.ip == rspamd_log.ip
            ).order_by(NetfilterLog.time.desc()).limit(100).all()  # Limit to 100 most recent to avoid too many results
        
        # Get all recipients - from Rspamd (primary source) or from Postfix logs
        recipients = []
        if rspamd_log and rspamd_log.recipients_smtp:
            recipients = rspamd_log.recipients_smtp if isinstance(rspamd_log.recipients_smtp, list) else []
        
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
            "subject": correlation.subject,
            "direction": correlation.direction,
            "final_status": correlation.final_status,
            "is_complete": correlation.is_complete,
            "first_seen": format_datetime_utc(correlation.first_seen),
            "last_seen": format_datetime_utc(correlation.last_seen),
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
                "size": rspamd_log.size
            } if rspamd_log else None,
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
        raise HTTPException(status_code=500, detail=str(e))