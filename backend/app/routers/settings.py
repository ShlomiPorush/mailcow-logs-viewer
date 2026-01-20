"""
API endpoints for settings and system information
Shows configuration, last import times, and background job status
"""
import logging
import httpx
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, text, or_
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

from ..database import get_db
from ..models import PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation
from ..config import settings
from ..scheduler import last_fetch_run_time, get_job_status
from ..services.connection_test import test_smtp_connection, test_imap_connection
from ..services.geoip_downloader import is_license_configured, get_geoip_status
from .domains import get_cached_server_ip

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
        
        jobs_status = get_job_status()

        return {
            "configuration": {
                "mailcow_url": settings.mailcow_url,
                "server_ip": get_cached_server_ip(),
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
                "auth_username": settings.auth_username if settings.auth_enabled else None,
                "maxmind_status": await validate_maxmind_license()
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
                    "description": "Imports logs from Mailcow API",
                    "status": jobs_status.get('fetch_logs', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('fetch_logs', {}).get('last_run')),
                    "error": jobs_status.get('fetch_logs', {}).get('error')
                },
                "complete_correlations": {
                    "interval": f"{settings.correlation_check_interval} seconds ({settings.correlation_check_interval // 60} minutes)",
                    "description": "Links Postfix logs to messages",
                    "status": jobs_status.get('complete_correlations', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('complete_correlations', {}).get('last_run')),
                    "error": jobs_status.get('complete_correlations', {}).get('error'),
                    "pending_items": incomplete_correlations or 0
                },
                "update_final_status": {
                    "interval": f"{settings.correlation_check_interval} seconds ({settings.correlation_check_interval // 60} minutes)",
                    "description": "Updates final status for correlations with late-arriving Postfix logs",
                    "max_age": f"{settings.max_correlation_age_minutes} minutes",
                    "status": jobs_status.get('update_final_status', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('update_final_status', {}).get('last_run')),
                    "error": jobs_status.get('update_final_status', {}).get('error'),
                    "pending_items": correlations_needing_status or 0
                },
                "expire_correlations": {
                    "interval": "60 seconds (1 minute)",
                    "description": "Marks old incomplete correlations as expired",
                    "expire_after": f"{settings.max_correlation_age_minutes} minutes",
                    "status": jobs_status.get('expire_correlations', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('expire_correlations', {}).get('last_run')),
                    "error": jobs_status.get('expire_correlations', {}).get('error')
                },
                "cleanup_logs": {
                    "schedule": "Daily at 2 AM",
                    "description": "Removes old logs based on retention period",
                    "retention": f"{settings.retention_days} days",
                    "status": jobs_status.get('cleanup_logs', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('cleanup_logs', {}).get('last_run')),
                    "error": jobs_status.get('cleanup_logs', {}).get('error')
                },
                "check_app_version": {
                    "interval": "6 hours",
                    "description": "Checks for application updates from GitHub",
                    "status": jobs_status.get('check_app_version', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('check_app_version', {}).get('last_run')),
                    "error": jobs_status.get('check_app_version', {}).get('error')
                },
                "dns_check": {
                    "interval": "6 hours",
                    "description": "Validates DNS records (SPF, DKIM, DMARC) for all active domains",
                    "status": jobs_status.get('dns_check', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('dns_check', {}).get('last_run')),
                    "error": jobs_status.get('dns_check', {}).get('error')
                },
                "sync_local_domains": {
                    "interval": "6 hours",
                    "description": "Syncs active domains list from Mailcow API",
                    "status": jobs_status.get('sync_local_domains', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('sync_local_domains', {}).get('last_run')),
                    "error": jobs_status.get('sync_local_domains', {}).get('error')
                },
                "dmarc_imap_sync": {
                    "interval": f"{settings.dmarc_imap_interval} seconds ({settings.dmarc_imap_interval // 60} minutes)" if settings.dmarc_imap_enabled else "Disabled",
                    "description": "Imports DMARC reports from IMAP mailbox",
                    "enabled": settings.dmarc_imap_enabled,
                    "status": jobs_status.get('dmarc_imap_sync', {}).get('status', 'idle') if settings.dmarc_imap_enabled else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('dmarc_imap_sync', {}).get('last_run')) if settings.dmarc_imap_enabled else None,
                    "error": jobs_status.get('dmarc_imap_sync', {}).get('error') if settings.dmarc_imap_enabled else None
                },
                "update_geoip": {
                    "schedule": "Weekly (Sunday 3 AM)" if is_license_configured() else "Disabled",
                    "description": "Updates MaxMind GeoIP databases (City & ASN)",
                    "enabled": is_license_configured(),
                    "status": jobs_status.get('update_geoip', {}).get('status', 'idle') if is_license_configured() else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('update_geoip', {}).get('last_run')) if is_license_configured() else None,
                    "error": jobs_status.get('update_geoip', {}).get('error') if is_license_configured() else None
                },
                "mailbox_stats": {
                    "interval": "5 minutes",
                    "description": "Fetches mailbox statistics from Mailcow API",
                    "status": jobs_status.get('mailbox_stats', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('mailbox_stats', {}).get('last_run')),
                    "error": jobs_status.get('mailbox_stats', {}).get('error')
                },
                "alias_stats": {
                    "interval": "5 minutes",
                    "description": "Syncs alias data from Mailcow API",
                    "status": jobs_status.get('alias_stats', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('alias_stats', {}).get('last_run')),
                    "error": jobs_status.get('alias_stats', {}).get('error')
                }
            },
            "smtp_configuration": {
                "enabled": settings.smtp_enabled,
                "host": settings.smtp_host if settings.smtp_enabled else None,
                "port": settings.smtp_port if settings.smtp_enabled else None,
                "user": settings.smtp_user if settings.smtp_enabled else None,
                "from_address": settings.smtp_from if settings.smtp_enabled else None,
                "use_tls": settings.smtp_use_tls if settings.smtp_enabled else None,
                "admin_email": settings.admin_email if settings.smtp_enabled else None,
                "configured": settings.notification_smtp_configured
            },
            "dmarc_configuration": {
                "manual_upload_enabled": settings.dmarc_manual_upload_enabled,
                "imap_sync_enabled": settings.dmarc_imap_enabled,
                "imap_host": settings.dmarc_imap_host if settings.dmarc_imap_enabled else None,
                "imap_user": settings.dmarc_imap_user if settings.dmarc_imap_enabled else None,
                "imap_folder": settings.dmarc_imap_folder if settings.dmarc_imap_enabled else None,
                "imap_delete_after": settings.dmarc_imap_delete_after if settings.dmarc_imap_enabled else None,
                "imap_interval_minutes": round(settings.dmarc_imap_interval / 60, 1) if settings.dmarc_imap_enabled else None,
                "smtp_configured": settings.notification_smtp_configured
            },
            "geoip_configuration": {
                "enabled": is_license_configured(),
                "databases": get_geoip_status() if is_license_configured() else {
                    "City": {"installed": False, "version": None, "last_updated": None},
                    "ASN": {"installed": False, "version": None, "last_updated": None}
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

@router.post("/settings/test/smtp")
async def test_smtp():
    """Test SMTP connection with detailed logging"""
    result = test_smtp_connection()
    return result

@router.post("/settings/test/imap")
async def test_imap():
    """Test IMAP connection with detailed logging"""
    result = test_imap_connection()
    return result

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

async def validate_maxmind_license() -> Dict[str, Any]:
    """Validate MaxMind license key"""
    import os
    
    license_key = os.getenv('MAXMIND_LICENSE_KEY')
    
    if not license_key:
        return {"configured": False, "valid": False, "error": None}
    
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                "https://secret-scanning.maxmind.com/secrets/validate-license-key",
                data={"license_key": license_key},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code == 204:
                return {"configured": True, "valid": True, "error": None}
            elif response.status_code == 401:
                return {"configured": True, "valid": False, "error": "Invalid"}
            else:
                return {"configured": True, "valid": False, "error": f"Status {response.status_code}"}
    except Exception:
        return {"configured": True, "valid": False, "error": "Connection error"}