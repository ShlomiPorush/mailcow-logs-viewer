import logging
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, cast, Integer
from datetime import datetime, timedelta, timezone
from typing import Optional

from ..database import get_db
from ..models import PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation
from ..services import excluded_addresses, written_recipients
from ..agent_access.scopes import READ
from ..user_access import caller_may

from ..utils import format_datetime_for_api as format_datetime_utc
from ..api_models import Invalid, documented
from ..api_models import stats as m

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/stats/dashboard", responses=documented(m.DashboardResponse))
def get_dashboard_stats(db: Session = Depends(get_db)):
    """
    Get main dashboard statistics
    """
    try:
        now = datetime.utcnow()
        day_ago = now - timedelta(days=1)
        week_ago = now - timedelta(days=7)
        month_ago = now - timedelta(days=30)
        
        messages_24h = db.query(MessageCorrelation).filter(
            MessageCorrelation.first_seen >= day_ago
        ).count()
        
        messages_7d = db.query(MessageCorrelation).filter(
            MessageCorrelation.first_seen >= week_ago
        ).count()
        
        messages_30d = db.query(MessageCorrelation).filter(
            MessageCorrelation.first_seen >= month_ago
        ).count()

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
            "error": "Unable to load statistics. Check the application logs.",
            "messages": {"24h": 0, "7d": 0, "30d": 0},
            "blocked": {"24h": 0, "7d": 0, "percentage_24h": 0},
            "deferred": {"24h": 0, "7d": 0},
            "auth_failures": {"24h": 0, "7d": 0},
            "direction": {"inbound_24h": 0, "outbound_24h": 0, "internal_24h": 0}
        }


@router.get("/stats/timeline", responses=documented(m.TimelineResponse, errors={422: Invalid}))
def get_timeline_stats(
    hours: int = 24,
    db: Session = Depends(get_db)
):
    """
    Get message timeline for charts
    Returns hourly message counts
    """
    try:
        cutoff = datetime.utcnow() - timedelta(hours=hours)

        timeline = db.query(
            func.date_trunc('hour', RspamdLog.time).label('hour'),
            func.count(RspamdLog.id).label('count'),
            func.sum(cast(RspamdLog.is_spam, Integer)).label('spam_count')
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
        return {"timeline": [], "error": "Unable to load statistics. Check the application logs."}


@router.get("/stats/top-spam-triggers", responses=documented(m.SpamTriggersResponse, errors={422: Invalid}))
def get_top_spam_triggers(
    limit: int = Query(10, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """
    Get top spam detection symbols
    """
    try:
        cutoff = datetime.utcnow() - timedelta(days=7)
        
        spam_logs = db.query(RspamdLog.symbols).filter(
            and_(
                RspamdLog.time >= cutoff,
                RspamdLog.is_spam == True
            )
        ).all()
        
        symbol_counts = {}
        for log in spam_logs:
            if log.symbols:
                for symbol_name in log.symbols.keys():
                    symbol_counts[symbol_name] = symbol_counts.get(symbol_name, 0) + 1
        
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
        return {"triggers": [], "error": "Unable to load statistics. Check the application logs."}


@router.get("/stats/top-blocked-ips", responses=documented(m.BlockedIpsResponse, errors={422: Invalid}))
def get_top_blocked_ips(
    limit: int = Query(10, ge=1, le=500),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """
    Get top blocked/warned IP addresses. They come from Security's Netfilter
    events: empty for a caller without View for Security.
    """
    if not caller_may(request, "security", READ):
        return {"blocked_ips": []}
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
        return {"blocked_ips": [], "error": "Unable to load statistics. Check the application logs."}


@router.get("/stats/recent-activity", responses=documented(m.RecentActivityResponse, errors={422: Invalid}))
def get_recent_activity(
    limit: int = Query(20, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """
    Get recent message activity stream
    """
    try:
        recent = db.query(MessageCorrelation).filter(excluded_addresses.correlation_visible()).order_by(
            MessageCorrelation.last_seen.desc()
        ).limit(limit).all()
        
        return {
            "activity": [
                {
                    "time": format_datetime_utc(msg.last_seen),
                    "sender": msg.sender,
                    "recipient": written_recipients.shown(msg.recipient, msg.written_recipients),
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
        return {"activity": [], "error": "Unable to load statistics. Check the application logs."}