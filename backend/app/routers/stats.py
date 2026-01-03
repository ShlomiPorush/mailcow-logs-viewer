"""
API endpoints for statistics and dashboard data
"""
import logging
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, and_
from datetime import datetime, timedelta, timezone
from typing import Optional

from ..database import get_db
from ..models import PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation

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


@router.get("/stats/dashboard")
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """
    Get main dashboard statistics
    """
    try:
        now = datetime.utcnow()
        day_ago = now - timedelta(days=1)
        week_ago = now - timedelta(days=7)
        month_ago = now - timedelta(days=30)
        
        # Messages processed
        messages_24h = db.query(MessageCorrelation).filter(
            MessageCorrelation.first_seen >= day_ago
        ).count()
        
        messages_7d = db.query(MessageCorrelation).filter(
            MessageCorrelation.first_seen >= week_ago
        ).count()
        
        messages_30d = db.query(MessageCorrelation).filter(
            MessageCorrelation.first_seen >= month_ago
        ).count()
        
        # Blocked messages (bounced, rejected, spam) - from MessageCorrelation
        blocked_24h = db.query(MessageCorrelation).filter(
            and_(
                MessageCorrelation.first_seen >= day_ago,
                MessageCorrelation.final_status.in_(['bounced', 'rejected', 'spam'])
            )
        ).count()
        
        blocked_7d = db.query(MessageCorrelation).filter(
            and_(
                MessageCorrelation.first_seen >= week_ago,
                MessageCorrelation.final_status.in_(['bounced', 'rejected', 'spam'])
            )
        ).count()
        
        # Deferred messages - from MessageCorrelation
        deferred_24h = db.query(MessageCorrelation).filter(
            and_(
                MessageCorrelation.first_seen >= day_ago,
                MessageCorrelation.final_status == 'deferred'
            )
        ).count()
        
        deferred_7d = db.query(MessageCorrelation).filter(
            and_(
                MessageCorrelation.first_seen >= week_ago,
                MessageCorrelation.final_status == 'deferred'
            )
        ).count()
        
        # Auth failures - only rule_id=3 (SASL authentication failures)
        auth_failures_24h = db.query(NetfilterLog).filter(
            and_(
                NetfilterLog.time >= day_ago,
                NetfilterLog.rule_id == 3
            )
        ).count()
        
        auth_failures_7d = db.query(NetfilterLog).filter(
            and_(
                NetfilterLog.time >= week_ago,
                NetfilterLog.rule_id == 3
            )
        ).count()
        
        # Direction statistics (last 24h)
        inbound_24h = db.query(RspamdLog).filter(
            and_(
                RspamdLog.time >= day_ago,
                RspamdLog.direction == 'inbound'
            )
        ).count()
        
        outbound_24h = db.query(RspamdLog).filter(
            and_(
                RspamdLog.time >= day_ago,
                RspamdLog.direction == 'outbound'
            )
        ).count()
        
        internal_24h = db.query(RspamdLog).filter(
            and_(
                RspamdLog.time >= day_ago,
                RspamdLog.direction == 'internal'
            )
        ).count()
        
        return {
            "messages": {
                "24h": messages_24h,
                "7d": messages_7d,
                "30d": messages_30d
            },
            "blocked": {
                "24h": blocked_24h,
                "7d": blocked_7d,
                "percentage_24h": round((blocked_24h / messages_24h * 100) if messages_24h > 0 else 0, 2)
            },
            "deferred": {
                "24h": deferred_24h,
                "7d": deferred_7d
            },
            "auth_failures": {
                "24h": auth_failures_24h,
                "7d": auth_failures_7d
            },
            "direction": {
                "inbound_24h": inbound_24h,
                "outbound_24h": outbound_24h,
                "internal_24h": internal_24h
            }
        }
    except Exception as e:
        logger.error(f"Error fetching dashboard stats: {e}")
        return {
            "error": str(e),
            "messages": {"24h": 0, "7d": 0, "30d": 0},
            "blocked": {"24h": 0, "7d": 0, "percentage_24h": 0},
            "deferred": {"24h": 0, "7d": 0},
            "auth_failures": {"24h": 0, "7d": 0},
            "direction": {"inbound_24h": 0, "outbound_24h": 0, "internal_24h": 0}
        }


@router.get("/stats/timeline")
async def get_timeline_stats(
    hours: int = 24,
    db: Session = Depends(get_db)
):
    """
    Get message timeline for charts
    Returns hourly message counts
    """
    try:
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Query for hourly counts
        timeline = db.query(
            func.date_trunc('hour', RspamdLog.time).label('hour'),
            func.count(RspamdLog.id).label('count'),
            func.sum(func.cast(RspamdLog.is_spam, func.Integer)).label('spam_count')
        ).filter(
            RspamdLog.time >= cutoff
        ).group_by(
            'hour'
        ).order_by(
            'hour'
        ).all()
        
        return {
            "timeline": [
                {
                    "hour": format_datetime_utc(row.hour),
                    "total": row.count,
                    "spam": row.spam_count or 0,
                    "clean": row.count - (row.spam_count or 0)
                }
                for row in timeline
            ]
        }
    except Exception as e:
        logger.error(f"Error fetching timeline stats: {e}")
        return {"timeline": [], "error": str(e)}


@router.get("/stats/top-spam-triggers")
async def get_top_spam_triggers(
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """
    Get top spam detection symbols
    """
    try:
        cutoff = datetime.utcnow() - timedelta(days=7)
        
        # Get all spam logs
        spam_logs = db.query(RspamdLog.symbols).filter(
            and_(
                RspamdLog.time >= cutoff,
                RspamdLog.is_spam == True
            )
        ).all()
        
        # Count symbols
        symbol_counts = {}
        for log in spam_logs:
            if log.symbols:
                for symbol_name in log.symbols.keys():
                    symbol_counts[symbol_name] = symbol_counts.get(symbol_name, 0) + 1
        
        # Sort and limit
        top_symbols = sorted(
            symbol_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]
        
        return {
            "triggers": [
                {"symbol": symbol, "count": count}
                for symbol, count in top_symbols
            ]
        }
    except Exception as e:
        logger.error(f"Error fetching spam triggers: {e}")
        return {"triggers": [], "error": str(e)}


@router.get("/stats/top-blocked-ips")
async def get_top_blocked_ips(
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """
    Get top blocked/warned IP addresses
    """
    try:
        cutoff = datetime.utcnow() - timedelta(days=7)
        
        top_ips = db.query(
            NetfilterLog.ip,
            func.count(NetfilterLog.id).label('count'),
            func.max(NetfilterLog.time).label('last_seen')
        ).filter(
            NetfilterLog.time >= cutoff
        ).group_by(
            NetfilterLog.ip
        ).order_by(
            func.count(NetfilterLog.id).desc()
        ).limit(limit).all()
        
        return {
            "blocked_ips": [
                {
                    "ip": row.ip,
                    "count": row.count,
                    "last_seen": format_datetime_utc(row.last_seen)
                }
                for row in top_ips
            ]
        }
    except Exception as e:
        logger.error(f"Error fetching blocked IPs: {e}")
        return {"blocked_ips": [], "error": str(e)}


@router.get("/stats/recent-activity")
async def get_recent_activity(
    limit: int = 20,
    db: Session = Depends(get_db)
):
    """
    Get recent message activity stream
    """
    try:
        recent = db.query(MessageCorrelation).order_by(
            MessageCorrelation.last_seen.desc()
        ).limit(limit).all()
        
        return {
            "activity": [
                {
                    "time": format_datetime_utc(msg.last_seen),
                    "sender": msg.sender,
                    "recipient": msg.recipient,
                    "subject": msg.subject,
                    "direction": msg.direction,
                    "status": msg.final_status,
                    "correlation_key": msg.correlation_key
                }
                for msg in recent
            ]
        }
    except Exception as e:
        logger.error(f"Error fetching recent activity: {e}")
        return {"activity": [], "error": str(e)}