"""
API endpoints for settings and system information
Shows configuration, last import times, and background job status
"""
import logging
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, text, or_
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

from ..database import get_db
from ..models import PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation
from ..config import settings
from ..scheduler import last_fetch_run_time

logger = logging.getLogger(__name__)

router = APIRouter()


def format_datetime_utc(dt: Optional[datetime]) -> Optional[str]:
    """Format datetime with UTC timezone indicator"""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc.replace(microsecond=0).isoformat().replace('+00:00', 'Z')


@router.get("/settings/info")
async def get_settings_info(db: Session = Depends(get_db)):
    """
    Get system configuration and status information
    
    Returns:
    - Configuration (without sensitive data)
    - Last import times for each log type
    - Background job statistics
    - Database statistics
    """
    try:
        # Get last import times
        last_postfix = db.query(func.max(PostfixLog.created_at)).scalar()
        last_rspamd = db.query(func.max(RspamdLog.created_at)).scalar()
        last_netfilter = db.query(func.max(NetfilterLog.created_at)).scalar()
        last_correlation = db.query(func.max(MessageCorrelation.updated_at)).scalar()
        
        # Get completion statistics
        total_correlations = db.query(func.count(MessageCorrelation.id)).scalar()
        complete_correlations = db.query(func.count(MessageCorrelation.id)).filter(
            MessageCorrelation.is_complete == True,
            MessageCorrelation.final_status != 'expired'
        ).scalar()
        incomplete_correlations = db.query(func.count(MessageCorrelation.id)).filter(
            MessageCorrelation.is_complete == False
        ).scalar()
        expired_correlations = db.query(func.count(MessageCorrelation.id)).filter(
            MessageCorrelation.final_status == 'expired'
        ).scalar()
        
        # Count correlations without definitive final_status (for update_final_status job)
        # Only count correlations within Max Correlation Age (older ones should be expired)
        status_cutoff_time = datetime.utcnow() - timedelta(
            minutes=settings.max_correlation_age_minutes
        )
        correlations_needing_status = db.query(func.count(MessageCorrelation.id)).filter(
            MessageCorrelation.created_at >= status_cutoff_time,
            MessageCorrelation.queue_id.isnot(None),
            or_(
                MessageCorrelation.final_status.is_(None),
                MessageCorrelation.final_status.notin_(['delivered', 'bounced', 'rejected', 'expired'])
            )
        ).scalar()
        
        # Get total counts
        total_postfix = db.query(func.count(PostfixLog.id)).scalar()
        total_rspamd = db.query(func.count(RspamdLog.id)).scalar()
        total_netfilter = db.query(func.count(NetfilterLog.id)).scalar()
        
        # Get oldest entries
        oldest_postfix = db.query(func.min(PostfixLog.time)).scalar()
        oldest_rspamd = db.query(func.min(RspamdLog.time)).scalar()
        oldest_netfilter = db.query(func.min(NetfilterLog.time)).scalar()
        
        # Get recent incomplete correlations (for monitoring)
        recent_incomplete = db.query(MessageCorrelation).filter(
            MessageCorrelation.is_complete == False
        ).order_by(desc(MessageCorrelation.created_at)).limit(5).all()
        
        return {
            "configuration": {
                "mailcow_url": settings.mailcow_url,
                "local_domains": settings.local_domains_list,
                "fetch_interval": settings.fetch_interval,
                "fetch_count_postfix": settings.fetch_count_postfix,
                "fetch_count_rspamd": settings.fetch_count_rspamd,
                "fetch_count_netfilter": settings.fetch_count_netfilter,
                "retention_days": settings.retention_days,
                "max_correlation_age_minutes": settings.max_correlation_age_minutes,
                "correlation_check_interval": settings.correlation_check_interval,
                "timezone": settings.tz,
                "app_title": settings.app_title,
                "log_level": settings.log_level,
                "blacklist_enabled": len(settings.blacklist_emails_list) > 0,
                "blacklist_count": len(settings.blacklist_emails_list),
                "max_search_results": settings.max_search_results,
                "csv_export_limit": settings.csv_export_limit,
                "scheduler_workers": settings.scheduler_workers,
                "auth_enabled": settings.auth_enabled,
                "auth_username": settings.auth_username if settings.auth_enabled else None
            },
            "import_status": {
                "postfix": {
                    "last_import": format_datetime_utc(last_postfix),
                    "last_fetch_run": format_datetime_utc(last_fetch_run_time.get('postfix')),
                    "total_entries": total_postfix or 0,
                    "oldest_entry": format_datetime_utc(oldest_postfix)
                },
                "rspamd": {
                    "last_import": format_datetime_utc(last_rspamd),
                    "last_fetch_run": format_datetime_utc(last_fetch_run_time.get('rspamd')),
                    "total_entries": total_rspamd or 0,
                    "oldest_entry": format_datetime_utc(oldest_rspamd)
                },
                "netfilter": {
                    "last_import": format_datetime_utc(last_netfilter),
                    "last_fetch_run": format_datetime_utc(last_fetch_run_time.get('netfilter')),
                    "total_entries": total_netfilter or 0,
                    "oldest_entry": format_datetime_utc(oldest_netfilter)
                }
            },
            "correlation_status": {
                "last_update": format_datetime_utc(last_correlation),
                "total": total_correlations or 0,
                "complete": complete_correlations or 0,
                "incomplete": incomplete_correlations or 0,
                "expired": expired_correlations or 0,
                "completion_rate": round((complete_correlations / total_correlations * 100) if total_correlations > 0 else 0, 2)
            },
            "background_jobs": {
                "fetch_logs": {
                    "interval": f"{settings.fetch_interval} seconds",
                    "status": "running"
                },
                "complete_correlations": {
                    "interval": f"{settings.correlation_check_interval} seconds ({settings.correlation_check_interval // 60} minutes)",
                    "status": "running",
                    "pending_items": incomplete_correlations or 0
                },
                "update_final_status": {
                    "interval": f"{settings.correlation_check_interval} seconds ({settings.correlation_check_interval // 60} minutes)",
                    "max_age": f"{settings.max_correlation_age_minutes} minutes",
                    "status": "running",
                    "pending_items": correlations_needing_status or 0
                },
                "expire_correlations": {
                    "interval": "60 seconds (1 minute)",
                    "expire_after": f"{settings.max_correlation_age_minutes} minutes",
                    "status": "running"
                },
                "cleanup_logs": {
                    "schedule": "Daily at 2 AM",
                    "retention": f"{settings.retention_days} days",
                    "status": "scheduled"
                }
            },
            "recent_incomplete_correlations": [
                {
                    "message_id": corr.message_id[:50] + "..." if corr.message_id and len(corr.message_id) > 50 else corr.message_id,
                    "queue_id": corr.queue_id,
                    "sender": corr.sender,
                    "recipient": corr.recipient,
                    "created_at": format_datetime_utc(corr.created_at),
                    "age_minutes": round((datetime.now(timezone.utc) - corr.created_at.replace(tzinfo=timezone.utc)).total_seconds() / 60) if corr.created_at else None
                }
                for corr in recent_incomplete
            ]
        }
        
    except Exception as e:
        logger.error(f"Error fetching settings info: {e}")
        return {
            "error": str(e),
            "configuration": {},
            "import_status": {},
            "correlation_status": {},
            "background_jobs": {}
        }


@router.get("/settings/health")
async def get_health_detailed(db: Session = Depends(get_db)):
    """
    Detailed health check with timing information
    """
    from datetime import timedelta
    try:
        # Check database response time
        start_time = datetime.now(timezone.utc)
        db.execute(text("SELECT 1"))
        db_response_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
        
        # Get recent activity (last 5 minutes)
        five_mins_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
        
        recent_postfix = db.query(func.count(PostfixLog.id)).filter(
            PostfixLog.created_at >= five_mins_ago
        ).scalar()
        
        recent_rspamd = db.query(func.count(RspamdLog.id)).filter(
            RspamdLog.created_at >= five_mins_ago
        ).scalar()
        
        recent_correlations = db.query(func.count(MessageCorrelation.id)).filter(
            MessageCorrelation.created_at >= five_mins_ago
        ).scalar()
        
        return {
            "status": "healthy",
            "timestamp": format_datetime_utc(datetime.now(timezone.utc)),
            "database": {
                "status": "connected",
                "response_time_ms": round(db_response_time, 2)
            },
            "recent_activity": {
                "last_5_minutes": {
                    "postfix_imported": recent_postfix or 0,
                    "rspamd_imported": recent_rspamd or 0,
                    "correlations_created": recent_correlations or 0
                }
            }
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": format_datetime_utc(datetime.now(timezone.utc)),
            "error": str(e)
        }