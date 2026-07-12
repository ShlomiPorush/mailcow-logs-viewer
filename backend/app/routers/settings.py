"""
API endpoints for settings and system information
Shows configuration, last import times, and background job status
"""
import logging
import os
import httpx
from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, text, or_
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

from ..database import get_db
from ..models import PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation
from ..config import settings, EDITABLE_SETTING_KEYS, reload_settings, Settings
from ..config import _get_field_annotations, get_env_locked_keys
from ..scheduler import last_fetch_run_time, get_job_status, update_job_status, reschedule_interval_jobs
from ..services.settings_store import get_config_overrides_from_db, save_config_overrides_to_db, has_config_overrides_in_db, get_maxmind_validation_status, save_maxmind_validation_status, clear_maxmind_validation_status
from ..services.connection_test import test_smtp_connection, test_imap_connection
from ..services.geoip_downloader import is_license_configured, get_geoip_status
from .domains import get_cached_server_ip
from ..mailcow_api import mailcow_api
from ..services.oauth2_client import oauth2_client

from ..utils import format_datetime_for_api as format_datetime_utc

logger = logging.getLogger(__name__)

router = APIRouter()


def _get_raw_logs_job_status(job_key: str, field: str, enabled: bool):
    """Get raw logs job status from the separate worker module."""
    if not enabled:
        if field == 'status':
            return 'disabled'
        return None
    try:
        from ..raw_logs_worker import get_raw_logs_job_status
        status = get_raw_logs_job_status()
        job = status.get(job_key, {})
        val = job.get(field)
        if field == 'last_run' and val:
            return format_datetime_utc(val)
        if field == 'status':
            return val or 'idle'
        return val
    except Exception:
        if field == 'status':
            return 'unknown'
        return None

# Keys whose values are masked in GET /api/settings (never returned in plain text)
_SENSITIVE_SETTING_KEYS = frozenset({
    "mailcow_api_key", "mailcow_api_key_rw", "auth_password", "oauth2_client_secret", "smtp_password",
    "dmarc_imap_password", "session_secret_key", "maxmind_license_key", "rspamd_password"
})
MASK_PLACEHOLDER = "********"




def _effective_config_for_editable(settings_obj: Settings) -> Dict[str, Any]:
    """Build dict of editable keys -> value (secrets masked) for API response."""
    out = {}
    for key in EDITABLE_SETTING_KEYS:
        if not hasattr(settings_obj, key):
            continue
        val = getattr(settings_obj, key)
        if key in _SENSITIVE_SETTING_KEYS:
            out[key] = MASK_PLACEHOLDER if (val is not None and str(val).strip() != "") else ""
        else:
            out[key] = val
    return out


def _get_field_defaults() -> Dict[str, Any]:
    """Extract default values from the Settings model for editable keys.
    Returns None for required fields (no default)."""
    from pydantic_core import PydanticUndefined
    defaults = {}
    for key in EDITABLE_SETTING_KEYS:
        field_info = Settings.model_fields.get(key)
        if field_info is None:
            continue
        if field_info.default is PydanticUndefined:
            defaults[key] = None  # Required field, no default
        elif key in _SENSITIVE_SETTING_KEYS:
            defaults[key] = ""  # Don't expose actual default for sensitive keys
        else:
            defaults[key] = field_info.default
    return defaults


@router.get("/settings/info")
def get_settings_info(db: Session = Depends(get_db)):
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

        result = {
            "settings_edit_via_ui_enabled": settings.edit_settings_via_ui_enabled,
            "configuration": {
                "mailcow_url": settings.mailcow_url,
                "server_ip": get_cached_server_ip(),
                "local_domains": settings.local_domains_list,
                "fetch_interval": settings.fetch_interval,
                "fetch_count_postfix": settings.fetch_count_postfix,
                "fetch_count_rspamd": settings.fetch_count_rspamd,
                "fetch_count_netfilter": settings.fetch_count_netfilter,
                "fetch_max_pages": settings.fetch_max_pages,
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
                "auth_enabled": settings.is_authentication_enabled,
                "basic_auth_enabled": settings.is_basic_auth_enabled,
                "oauth2_enabled": settings.is_oauth2_enabled,
                "auth_username": settings.auth_username if settings.is_basic_auth_enabled else None,
                "oauth2_provider_name": settings.oauth2_provider_name if settings.is_oauth2_enabled else None,
                "maxmind_status": get_maxmind_validation_status(db)  # Last validated result from DB, or None if never checked
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
                    "description": "Imports logs from mailcow API",
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
                "cleanup_dmarc_reports": {
                    "schedule": "Daily at 2:15 AM" if settings.is_feature_enabled('dmarc') else "Disabled (feature off)",
                    "description": "Removes old DMARC and TLS reports based on DMARC retention period",
                    "retention": f"{settings.dmarc_retention_days} days",
                    "feature_disabled": not settings.is_feature_enabled('dmarc'),
                    "status": jobs_status.get('cleanup_dmarc_reports', {}).get('status', 'unknown') if settings.is_feature_enabled('dmarc') else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('cleanup_dmarc_reports', {}).get('last_run')) if settings.is_feature_enabled('dmarc') else None,
                    "error": jobs_status.get('cleanup_dmarc_reports', {}).get('error') if settings.is_feature_enabled('dmarc') else None
                },
                "check_app_version": {
                    "interval": "6 hours",
                    "description": "Checks for application updates from GitHub",
                    "status": jobs_status.get('check_app_version', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('check_app_version', {}).get('last_run')),
                    "error": jobs_status.get('check_app_version', {}).get('error')
                },
                "dns_check": {
                    "interval": "6 hours" if settings.is_feature_enabled('domains') else "Disabled (feature off)",
                    "description": "Validates DNS records (SPF, DKIM, DMARC) for all active domains",
                    "feature_disabled": not settings.is_feature_enabled('domains'),
                    "status": jobs_status.get('dns_check', {}).get('status', 'unknown') if settings.is_feature_enabled('domains') else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('dns_check', {}).get('last_run')) if settings.is_feature_enabled('domains') else None,
                    "error": jobs_status.get('dns_check', {}).get('error') if settings.is_feature_enabled('domains') else None
                },
                "sync_local_domains": {
                    "interval": "6 hours",
                    "description": "Syncs active domains list from mailcow API",
                    "status": jobs_status.get('sync_local_domains', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('sync_local_domains', {}).get('last_run')),
                    "error": jobs_status.get('sync_local_domains', {}).get('error')
                },
                "dmarc_imap_sync": {
                    "interval": f"{settings.dmarc_imap_interval} seconds ({settings.dmarc_imap_interval // 60} minutes)" if (settings.is_feature_enabled('dmarc') and settings.dmarc_imap_enabled) else ("Disabled (feature off)" if not settings.is_feature_enabled('dmarc') else "Disabled"),
                    "description": "Imports DMARC reports from IMAP mailbox",
                    "enabled": settings.is_feature_enabled('dmarc') and settings.dmarc_imap_enabled,
                    "feature_disabled": not settings.is_feature_enabled('dmarc'),
                    "status": jobs_status.get('dmarc_imap_sync', {}).get('status', 'idle') if (settings.is_feature_enabled('dmarc') and settings.dmarc_imap_enabled) else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('dmarc_imap_sync', {}).get('last_run')) if (settings.is_feature_enabled('dmarc') and settings.dmarc_imap_enabled) else None,
                    "error": jobs_status.get('dmarc_imap_sync', {}).get('error') if (settings.is_feature_enabled('dmarc') and settings.dmarc_imap_enabled) else None
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
                    "interval": "5 minutes" if settings.is_feature_enabled('mailbox-stats') else "Disabled (feature off)",
                    "description": "Fetches mailbox statistics from mailcow API",
                    "feature_disabled": not settings.is_feature_enabled('mailbox-stats'),
                    "status": jobs_status.get('mailbox_stats', {}).get('status', 'unknown') if settings.is_feature_enabled('mailbox-stats') else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('mailbox_stats', {}).get('last_run')) if settings.is_feature_enabled('mailbox-stats') else None,
                    "error": jobs_status.get('mailbox_stats', {}).get('error') if settings.is_feature_enabled('mailbox-stats') else None
                },
                "alias_stats": {
                    "interval": "5 minutes" if settings.is_feature_enabled('mailbox-stats') else "Disabled (feature off)",
                    "description": "Syncs alias data from mailcow API",
                    "feature_disabled": not settings.is_feature_enabled('mailbox-stats'),
                    "status": jobs_status.get('alias_stats', {}).get('status', 'unknown') if settings.is_feature_enabled('mailbox-stats') else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('alias_stats', {}).get('last_run')) if settings.is_feature_enabled('mailbox-stats') else None,
                    "error": jobs_status.get('alias_stats', {}).get('error') if settings.is_feature_enabled('mailbox-stats') else None
                },
                "blacklist_check": {
                    "schedule": "Daily at 5 AM" if settings.is_feature_enabled('blacklist') else "Disabled (feature off)",
                    "description": "Checks monitored hosts against DNS blacklists",
                    "feature_disabled": not settings.is_feature_enabled('blacklist'),
                    "status": jobs_status.get('blacklist_check', {}).get('status', 'unknown') if settings.is_feature_enabled('blacklist') else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('blacklist_check', {}).get('last_run')) if settings.is_feature_enabled('blacklist') else None,
                    "error": jobs_status.get('blacklist_check', {}).get('error') if settings.is_feature_enabled('blacklist') else None
                },
                "sync_transports": {
                    "interval": "6 hours" if settings.is_feature_enabled('domains') else "Disabled (feature off)",
                    "description": "Sync Transports & Relayhosts from mailcow",
                    "feature_disabled": not settings.is_feature_enabled('domains'),
                    "status": jobs_status.get('sync_transports', {}).get('status', 'unknown') if settings.is_feature_enabled('domains') else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('sync_transports', {}).get('last_run')) if settings.is_feature_enabled('domains') else None,
                    "error": jobs_status.get('sync_transports', {}).get('error') if settings.is_feature_enabled('domains') else None
                },
                "send_weekly_summary": {
                    "schedule": "Monday at 9:00 AM" if settings.enable_weekly_summary else "Disabled",
                    "description": "Sends a weekly summary report via email",
                    "enabled": settings.enable_weekly_summary,
                    "status": jobs_status.get('send_weekly_summary', {}).get('status', 'idle') if settings.enable_weekly_summary else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('send_weekly_summary', {}).get('last_run')) if settings.enable_weekly_summary else None,
                    "error": jobs_status.get('send_weekly_summary', {}).get('error') if settings.enable_weekly_summary else None
                },
                "fetch_raw_logs": {
                    "interval": f"{settings.raw_logs_fetch_interval} seconds" if (settings.is_feature_enabled('logs') and settings.raw_logs_enabled) else ("Disabled (feature off)" if not settings.is_feature_enabled('logs') else "Disabled"),
                    "description": "Fetches raw logs from mailcow services for the Logs page",
                    "enabled": settings.is_feature_enabled('logs') and settings.raw_logs_enabled,
                    "feature_disabled": not settings.is_feature_enabled('logs'),
                    "status": _get_raw_logs_job_status('fetch_raw_logs', 'status', settings.is_feature_enabled('logs') and settings.raw_logs_enabled),
                    "last_run": _get_raw_logs_job_status('fetch_raw_logs', 'last_run', settings.is_feature_enabled('logs') and settings.raw_logs_enabled),
                    "error": _get_raw_logs_job_status('fetch_raw_logs', 'error', settings.is_feature_enabled('logs') and settings.raw_logs_enabled)
                },
                "cleanup_raw_logs": {
                    "schedule": "Daily at 3:00 AM" if (settings.is_feature_enabled('logs') and settings.raw_logs_enabled) else ("Disabled (feature off)" if not settings.is_feature_enabled('logs') else "Disabled"),
                    "description": "Removes raw logs older than retention period",
                    "retention": f"{settings.raw_logs_retention_days} days" if (settings.is_feature_enabled('logs') and settings.raw_logs_enabled) else None,
                    "enabled": settings.is_feature_enabled('logs') and settings.raw_logs_enabled,
                    "feature_disabled": not settings.is_feature_enabled('logs'),
                    "status": _get_raw_logs_job_status('cleanup_raw_logs', 'status', settings.is_feature_enabled('logs') and settings.raw_logs_enabled),
                    "last_run": _get_raw_logs_job_status('cleanup_raw_logs', 'last_run', settings.is_feature_enabled('logs') and settings.raw_logs_enabled),
                    "error": _get_raw_logs_job_status('cleanup_raw_logs', 'error', settings.is_feature_enabled('logs') and settings.raw_logs_enabled)
                },
                "detect_suppressions": {
                    "interval": "5 minutes" if (settings.is_feature_enabled('spam-filter') and settings.suppression_enabled) else ("Disabled (feature off)" if not settings.is_feature_enabled('spam-filter') else "Disabled (suppression off)"),
                    "description": "Scans Postfix logs for bounces to auto-suppress recipients",
                    "enabled": settings.is_feature_enabled('spam-filter') and settings.suppression_enabled and settings.suppression_auto_detect,
                    "feature_disabled": not settings.is_feature_enabled('spam-filter'),
                    "status": jobs_status.get('detect_suppressions', {}).get('status', 'idle') if (settings.is_feature_enabled('spam-filter') and settings.suppression_enabled) else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('detect_suppressions', {}).get('last_run')) if (settings.is_feature_enabled('spam-filter') and settings.suppression_enabled) else None,
                    "error": jobs_status.get('detect_suppressions', {}).get('error') if (settings.is_feature_enabled('spam-filter') and settings.suppression_enabled) else None
                },
                "sync_suppressions": {
                    "interval": "10 minutes" if (settings.is_feature_enabled('spam-filter') and settings.suppression_enabled and settings.suppression_rspamd_sync) else ("Disabled (feature off)" if not settings.is_feature_enabled('spam-filter') else ("Disabled (suppression off)" if not settings.suppression_enabled else "Disabled (Rspamd sync off)")),
                    "description": "Syncs active suppressions to Rspamd recipient denylist",
                    "enabled": settings.is_feature_enabled('spam-filter') and settings.suppression_enabled and settings.suppression_rspamd_sync and settings.is_rspamd_configured,
                    "feature_disabled": not settings.is_feature_enabled('spam-filter'),
                    "status": jobs_status.get('sync_suppressions', {}).get('status', 'idle') if (settings.is_feature_enabled('spam-filter') and settings.suppression_enabled and settings.suppression_rspamd_sync) else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('sync_suppressions', {}).get('last_run')) if (settings.is_feature_enabled('spam-filter') and settings.suppression_enabled and settings.suppression_rspamd_sync) else None,
                    "error": jobs_status.get('sync_suppressions', {}).get('error') if (settings.is_feature_enabled('spam-filter') and settings.suppression_enabled and settings.suppression_rspamd_sync) else None
                },
                "expire_suppressions": {
                    "interval": "1 hour" if (settings.is_feature_enabled('spam-filter') and settings.suppression_enabled) else ("Disabled (feature off)" if not settings.is_feature_enabled('spam-filter') else "Disabled (suppression off)"),
                    "description": "Deactivates expired suppression entries",
                    "enabled": settings.is_feature_enabled('spam-filter') and settings.suppression_enabled,
                    "feature_disabled": not settings.is_feature_enabled('spam-filter'),
                    "status": jobs_status.get('expire_suppressions', {}).get('status', 'idle') if (settings.is_feature_enabled('spam-filter') and settings.suppression_enabled) else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('expire_suppressions', {}).get('last_run')) if (settings.is_feature_enabled('spam-filter') and settings.suppression_enabled) else None,
                    "error": jobs_status.get('expire_suppressions', {}).get('error') if (settings.is_feature_enabled('spam-filter') and settings.suppression_enabled) else None
                },
                "process_quarantine_rules": {
                    "interval": f"{settings.quarantine_rules_interval} minutes" if (settings.is_feature_enabled('quarantine') and mailcow_api.has_rw_key) else ("Disabled (feature off)" if not settings.is_feature_enabled('quarantine') else "Disabled (no RW API key)"),
                    "description": "Processes quarantine auto-rules (release/delete matching emails)",
                    "enabled": settings.is_feature_enabled('quarantine') and mailcow_api.has_rw_key,
                    "feature_disabled": not settings.is_feature_enabled('quarantine'),
                    "status": jobs_status.get('process_quarantine_rules', {}).get('status', 'idle') if (settings.is_feature_enabled('quarantine') and mailcow_api.has_rw_key) else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('process_quarantine_rules', {}).get('last_run')) if (settings.is_feature_enabled('quarantine') and mailcow_api.has_rw_key) else None,
                    "error": jobs_status.get('process_quarantine_rules', {}).get('error') if (settings.is_feature_enabled('quarantine') and mailcow_api.has_rw_key) else None
                },
                "cleanup_deferred_queue": {
                    "interval": "5 minutes" if (settings.is_feature_enabled('spam-filter') and settings.suppression_enabled and settings.queue_cleanup_enabled and mailcow_api.has_rw_key) else ("Disabled (feature off)" if not settings.is_feature_enabled('spam-filter') else ("Disabled (suppression off)" if not settings.suppression_enabled else ("Disabled (queue cleanup off)" if not settings.queue_cleanup_enabled else "Disabled (no RW API key)"))),
                    "description": f"Deletes deferred emails stuck > {settings.queue_cleanup_threshold_minutes}m and suppresses recipients",
                    "enabled": settings.is_feature_enabled('spam-filter') and settings.suppression_enabled and settings.queue_cleanup_enabled and mailcow_api.has_rw_key,
                    "feature_disabled": not settings.is_feature_enabled('spam-filter'),
                    "status": jobs_status.get('cleanup_deferred_queue', {}).get('status', 'idle') if (settings.is_feature_enabled('spam-filter') and settings.suppression_enabled and settings.queue_cleanup_enabled) else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('cleanup_deferred_queue', {}).get('last_run')) if (settings.is_feature_enabled('spam-filter') and settings.suppression_enabled and settings.queue_cleanup_enabled) else None,
                    "error": jobs_status.get('cleanup_deferred_queue', {}).get('error') if (settings.is_feature_enabled('spam-filter') and settings.suppression_enabled and settings.queue_cleanup_enabled) else None
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
                "db_valid": get_geoip_status().get('db_valid') if is_license_configured() else None,
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
        # When UI editing is enabled, include full editable config and migration status
        if settings.edit_settings_via_ui_enabled:
            result["editable_config"] = _effective_config_for_editable(settings)
            result["default_config"] = _get_field_defaults()
            result["settings_migrated"] = has_config_overrides_in_db(db)
        return result
        
    except Exception as e:
        logger.error(f"Error fetching settings info: {e}")
        return {
            "error": str(e),
            "settings_edit_via_ui_enabled": getattr(settings, "edit_settings_via_ui_enabled", False),
            "configuration": {},
            "import_status": {},
            "correlation_status": {},
            "background_jobs": {}
        }


@router.get("/settings")
def get_editable_settings(db: Session = Depends(get_db)):
    """
    Get effective configuration for editing (editable keys only; secrets masked).
    Includes settings_edit_via_ui_enabled so frontend can show/hide edit form.
    When UI editing is enabled, reloads settings from DB so response is up to date.
    Returns env_locked_keys: keys where ENV is set (ENV always overrides DB).
    """
    if settings.edit_settings_via_ui_enabled:
        reload_settings(db)
    # Keys where ENV is explicitly set — these are locked (ENV wins over DB).
    env_locked = sorted(get_env_locked_keys()) if settings.edit_settings_via_ui_enabled else []
    return {
        "settings_edit_via_ui_enabled": settings.edit_settings_via_ui_enabled,
        "settings_migrated": has_config_overrides_in_db(db),
        "configuration": _effective_config_for_editable(settings),
        "default_config": _get_field_defaults(),
        "env_locked_keys": env_locked,
    }


@router.put("/settings")
def update_settings(body: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Update app settings from UI. Only allowed when SETTINGS_EDIT_VIA_UI_ENABLED is true.
    Accepts only keys in EDITABLE_SETTING_KEYS. Secrets: send empty string to leave unchanged.
    When enabling basic_auth_enabled, verify_username and verify_password must be provided
    and must match the credentials being saved, to prevent lockout.
    """
    import secrets as _secrets
    if not settings.edit_settings_via_ui_enabled:
        raise HTTPException(status_code=403, detail="Editing settings from UI is disabled. Set SETTINGS_EDIT_VIA_UI_ENABLED=true to enable.")
    allowed = {k: v for k, v in body.items() if k in EDITABLE_SETTING_KEYS}
    # For sensitive keys, mask placeholder means "do not change" - omit from payload
    # Empty string means "clear this value" and should be kept
    for sk in _SENSITIVE_SETTING_KEYS:
        if sk in allowed and isinstance(allowed[sk], str) and allowed[sk] == MASK_PLACEHOLDER:
            del allowed[sk]
    if not allowed:
        reload_settings(db)
        return {"settings_edit_via_ui_enabled": True, "settings_migrated": True, "configuration": _effective_config_for_editable(settings)}

    # ── Basic Auth lockout prevention ──────────────────────────────────
    # When basic_auth_enabled is being turned ON, validate credentials
    # to ensure the user won't be locked out.
    _enabling_basic_auth = (
        allowed.get("basic_auth_enabled") is True
        and not settings.is_basic_auth_enabled
    )
    if _enabling_basic_auth:
        # Determine effective password: explicit value in payload, or current setting
        _eff_password = allowed.get("auth_password", settings.auth_password or "")
        _eff_username = allowed.get("auth_username", settings.auth_username or "admin")
        if not _eff_password or not str(_eff_password).strip():
            raise HTTPException(
                status_code=400,
                detail="Cannot enable Basic Auth without a password. Please set a password first."
            )
        # Require verification credentials from the user
        _verify_user = body.get("verify_username", "")
        _verify_pass = body.get("verify_password", "")
        if not _verify_user or not _verify_pass:
            raise HTTPException(
                status_code=400,
                detail="Credential verification required. Please confirm your username and password to enable Basic Auth."
            )
        _user_ok = _secrets.compare_digest(
            str(_verify_user).encode("utf-8"),
            str(_eff_username).encode("utf-8"),
        )
        _pass_ok = _secrets.compare_digest(
            str(_verify_pass).encode("utf-8"),
            str(_eff_password).encode("utf-8"),
        )
        if not (_user_ok and _pass_ok):
            raise HTTPException(
                status_code=400,
                detail="Credential verification failed. The username and password you entered do not match the configured credentials."
            )
        logger.info("Basic Auth credential verification passed — enabling authentication")

    # Prevent clearing the password while Basic Auth is (or will be) enabled
    _basic_auth_active = (
        allowed.get("basic_auth_enabled", settings.is_basic_auth_enabled) is True
    )
    _clearing_password = (
        "auth_password" in allowed
        and (not allowed["auth_password"] or not str(allowed["auth_password"]).strip())
    )
    if _basic_auth_active and _clearing_password:
        raise HTTPException(
            status_code=400,
            detail="Cannot clear the password while Basic Auth is enabled. Disable Basic Auth first, or set a new password."
        )
    # ──────────────────────────────────────────────────────────────────

    try:
        # Validate by building a Settings copy with current + updates
        current = settings.model_dump()
        for k, v in allowed.items():
            current[k] = v
        # Coerce None to valid types (UI sends null for empty; Settings expects str/int/bool)
        annotations = _get_field_annotations()
        for k, v in list(current.items()):
            if v is not None or k not in annotations:
                continue
            ann = annotations[k]
            if getattr(ann, "__args__", None) and type(None) in getattr(ann, "__args__", ()):
                continue  # Optional: None is valid
            effective = getattr(ann, "__args__", None)
            if effective:
                effective = [a for a in ann.__args__ if a is not type(None)]
                effective = effective[0] if effective else ann
            else:
                effective = ann
            if effective == str or effective is str:
                current[k] = ""
            elif effective == int or effective is int:
                current[k] = 0
            elif effective == bool or effective is bool:
                current[k] = False
        Settings.model_validate(current)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Validation error: {e}")
    save_config_overrides_to_db(db, allowed)
    reload_settings(db)
    mailcow_api.reload_config()
    oauth2_client.reload_config()
    reschedule_interval_jobs()

    # Invalidate MaxMind license cache when credentials change
    if 'maxmind_license_key' in allowed or 'maxmind_account_id' in allowed:
        clear_maxmind_validation_status(db)
    
    return {"settings_edit_via_ui_enabled": True, "settings_migrated": True, "configuration": _effective_config_for_editable(settings)}


# Feature → tables mapping for data purge
_FEATURE_TABLES = {
    'netfilter': ['netfilter_logs'],
    'domains': ['domain_dns_checks'],
    'dmarc': ['dmarc_records', 'tls_report_policies', 'dmarc_reports', 'dmarc_syncs', 'tls_reports'],
    'mailbox-stats': ['alias_statistics', 'mailbox_statistics'],
    'logs': ['raw_service_logs'],
    'blacklist': ['blacklist_checks', 'monitored_hosts'],
    'spam-filter': ['spam_suppressions'],
    'quarantine': ['quarantine_rule_logs', 'quarantine_rules'],
}


@router.post("/settings/purge-feature-data")
def purge_feature_data(body: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Delete all database data associated with a disabled feature.
    Body: { "feature": "<feature-id>" }
    Only allowed when SETTINGS_EDIT_VIA_UI_ENABLED is true and the feature is currently disabled.
    """
    if not settings.edit_settings_via_ui_enabled:
        raise HTTPException(status_code=403, detail="Editing settings from UI is disabled.")

    feature = body.get("feature", "").strip().lower()
    if feature not in _FEATURE_TABLES:
        raise HTTPException(status_code=400, detail=f"Unknown feature: {feature}")

    if settings.is_feature_enabled(feature):
        raise HTTPException(status_code=400, detail=f"Feature '{feature}' is currently enabled. Disable it first.")

    tables = _FEATURE_TABLES[feature]
    deleted_counts = {}
    # Allowed table name pattern (alphanumeric + underscores only) to satisfy static analysis
    import re
    _TABLE_NAME_RE = re.compile(r'^[a-z_][a-z0-9_]*$')
    try:
        for table_name in tables:
            if not _TABLE_NAME_RE.match(table_name):
                raise ValueError(f"Invalid table name: {table_name}")
            # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
            count = db.execute(text(f"SELECT COUNT(*) FROM {table_name}")).scalar() or 0
            if count > 0:
                # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                db.execute(text(f"TRUNCATE TABLE {table_name} CASCADE"))
            deleted_counts[table_name] = count
        db.commit()
        total = sum(deleted_counts.values())
        logger.info(f"Purged data for feature '{feature}': {deleted_counts} (total {total} rows)")
        return {
            "feature": feature,
            "tables_purged": deleted_counts,
            "total_rows_deleted": total,
        }
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to purge data for feature '{feature}': {e}")
        raise HTTPException(status_code=500, detail=f"Purge failed: {e}")


@router.post("/settings/import-from-env")
def import_settings_from_env(db: Session = Depends(get_db)):
    """
    Import current effective configuration (defaults + ENV + existing DB) into DB.
    Only allowed when SETTINGS_EDIT_VIA_UI_ENABLED is true.
    Use this to migrate from ENV to DB so you can later remove ENV vars.
    Returns env_locked_keys: keys where ENV is set and overrides DB.
    """
    if not settings.edit_settings_via_ui_enabled:
        raise HTTPException(status_code=403, detail="Editing settings from UI is disabled. Set SETTINGS_EDIT_VIA_UI_ENABLED=true to enable.")
    # Current effective config is in `settings` (includes DB overrides if any); export only editable keys
    overrides = {}
    for key in EDITABLE_SETTING_KEYS:
        if hasattr(settings, key):
            val = getattr(settings, key)
            overrides[key] = val
    save_config_overrides_to_db(db, overrides)
    reload_settings(db)
    mailcow_api.reload_config()
    oauth2_client.reload_config()
    reschedule_interval_jobs()
    return {
        "message": "Configuration imported from current environment into DB.",
        "settings_edit_via_ui_enabled": True,
        "settings_migrated": True,
        "configuration": _effective_config_for_editable(settings),
        "env_locked_keys": sorted(get_env_locked_keys()),
    }


# NOTE: these are plain `def` on purpose — FastAPI runs sync endpoints in a
# threadpool, so the blocking smtplib/imaplib connection tests (10-30s timeouts)
# don't freeze the shared event loop.
@router.post("/settings/test/smtp")
def test_smtp():
    """Test SMTP connection with detailed logging"""
    result = test_smtp_connection()
    return result

@router.post("/settings/test/imap")
def test_imap():
    """Test IMAP connection with detailed logging"""
    result = test_imap_connection()
    return result

@router.get("/settings/health")
def get_health_detailed(db: Session = Depends(get_db)):
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

async def validate_maxmind_license(db=None) -> Dict[str, Any]:
    """Validate MaxMind license key against MaxMind's API.
    Called on-demand only (user clicks 'Validate License' or before GeoIP download).
    Stores the result in DB so it persists across restarts.
    """
    license_key = settings.maxmind_license_key
    
    if not license_key:
        result = {"configured": False, "valid": False, "error": None}
        if db:
            save_maxmind_validation_status(db, result)
        return result
    
    try:
        timeout = httpx.Timeout(5.0, connect=3.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                "https://secret-scanning.maxmind.com/secrets/validate-license-key",
                data={"license_key": license_key},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code == 204:
                result = {"configured": True, "valid": True, "error": None}
            elif response.status_code == 401:
                result = {"configured": True, "valid": False, "error": "Invalid"}
            else:
                result = {"configured": True, "valid": False, "error": f"Status {response.status_code}"}
    except Exception:
        result = {"configured": True, "valid": False, "error": "Connection error"}
    
    if db:
        save_maxmind_validation_status(db, result)
    return result



def _run_async_in_background(coro_func):
    """Helper to run an async function from BackgroundTasks (which expects sync callables)."""
    import asyncio
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(coro_func())
    finally:
        loop.close()


@router.get("/settings/geoip/status")
def get_geoip_detailed_status():
    """
    Get detailed GeoIP status for frontend polling.
    Returns license validity, DB file info, and DB health validation status.
    """
    from ..services.geoip_service import get_geoip_db_valid
    
    geoip_status = get_geoip_status() if is_license_configured() else {
        'configured': False, 'db_valid': None,
        'City': {'available': False, 'age_days': -1, 'size_mb': 0, 'last_modified': None},
        'ASN': {'available': False, 'age_days': -1, 'size_mb': 0, 'last_modified': None}
    }
    
    # Get the update_geoip job status
    jobs_status = get_job_status()
    geoip_job = jobs_status.get('update_geoip', {})
    
    return {
        "configured": is_license_configured(),
        "db_valid": get_geoip_db_valid(),
        "databases": geoip_status,
        "job_status": geoip_job.get('status', 'idle'),
        "job_error": geoip_job.get('error'),
        "job_last_run": format_datetime_utc(geoip_job.get('last_run')) if geoip_job.get('last_run') else None,
    }


@router.post("/settings/geoip/download")
def trigger_geoip_download(background_tasks: BackgroundTasks):
    """
    Trigger GeoIP database download in background.
    Called by the setup modal when credentials are valid but DB files are missing.
    Returns immediately; use GET /settings/geoip/status to poll progress.
    """
    if not is_license_configured():
        raise HTTPException(status_code=400, detail="MaxMind license key not configured")
    
    logger.info("Manual GeoIP download triggered from setup modal")
    from ..scheduler import update_geoip_database
    background_tasks.add_task(_run_async_in_background, update_geoip_database)
    return {"status": "started", "message": "GeoIP download started in background"}


@router.post("/settings/maxmind/validate")
async def validate_maxmind_license_endpoint(db: Session = Depends(get_db)):
    """
    Validate MaxMind license key on-demand.
    Called when the user clicks 'Validate License' in settings.
    Persists the result to DB.
    """
    result = await validate_maxmind_license(db=db)
    return result


@router.post("/settings/geoip/validate")
def validate_geoip_db():
    """
    Validate GeoIP database integrity by running test IP lookups.
    Called by the setup modal after download completes.
    """
    from ..services.geoip_service import validate_geoip_database, reload_geoip_readers, get_geoip_db_valid
    
    # Ensure readers are loaded
    geoip_status = get_geoip_status()
    if not geoip_status.get('City', {}).get('available'):
        return {
            "valid": False,
            "city_ok": False,
            "asn_ok": False,
            "error": "City database file not found"
        }
    
    # Reload readers to pick up any new files
    reload_geoip_readers()
    
    return {
        "valid": get_geoip_db_valid() is True,
        "city_ok": get_geoip_db_valid() is True,
        "asn_ok": get_geoip_db_valid() is True,
        "db_valid": get_geoip_db_valid(),
    }


# =============================================================================
# MANUAL JOB TRIGGER
# =============================================================================

@router.post("/settings/jobs/{job_name}/run")
def trigger_job(job_name: str, background_tasks: BackgroundTasks):
    """
    Manually trigger a background job.
    
    Supported jobs:
    - fetch_logs: Fetch logs from mailcow API
    - complete_correlations: Link Postfix logs to messages
    - update_final_status: Update final status for correlations
    - expire_correlations: Mark old incomplete correlations as expired
    - cleanup_logs: Remove old logs
    - cleanup_dmarc_reports: Remove old DMARC/TLS reports
    - check_app_version: Check for app updates
    - dns_check: Validate DNS records for all domains
    - sync_local_domains: Sync domains from mailcow API
    - update_geoip: Update GeoIP databases
    - mailbox_stats: Fetch mailbox statistics
    - alias_stats: Sync alias data
    - blacklist_check: Check server IP against blacklists
    - fetch_raw_logs: Fetch raw logs from mailcow services
    - cleanup_raw_logs: Remove raw logs older than retention period
    """
    # Import job functions here to avoid circular imports
    from ..scheduler import (
        fetch_all_logs,
        complete_incomplete_correlations,
        update_final_status_for_correlations,
        expire_old_correlations,
        cleanup_old_logs,
        cleanup_old_dmarc_reports,
        check_app_version_update,
        check_all_domains_dns_background,
        sync_local_domains,
        update_geoip_database,
        update_mailbox_statistics,
        update_alias_statistics,
        check_monitored_hosts_job,
        sync_transports_job,
        send_weekly_summary_email_job,
        detect_suppressions_job,
        sync_suppressions_to_rspamd_job,
        expire_suppressions_job,
        process_quarantine_rules_job,
        cleanup_deferred_queue_job
    )
    from ..raw_logs_worker import fetch_raw_service_logs, cleanup_raw_service_logs
    
    # Map job names to (status_key, function, self_managing_status)
    # self_managing_status=True means the function updates its own status tracking
    # (raw log jobs use their own raw_logs_job_status dict)
    job_mapping = {
        'fetch_logs': ('fetch_logs', fetch_all_logs, False),
        'complete_correlations': ('complete_correlations', complete_incomplete_correlations, False),
        'update_final_status': ('update_final_status', update_final_status_for_correlations, False),
        'expire_correlations': ('expire_correlations', expire_old_correlations, False),
        'cleanup_logs': ('cleanup_logs', cleanup_old_logs, False),
        'cleanup_dmarc_reports': ('cleanup_dmarc_reports', cleanup_old_dmarc_reports, False),
        'check_app_version': ('check_app_version', check_app_version_update, False),
        'dns_check': ('dns_check', check_all_domains_dns_background, False),
        'sync_local_domains': ('sync_local_domains', sync_local_domains, False),
        'update_geoip': ('update_geoip', update_geoip_database, False),
        'mailbox_stats': ('mailbox_stats', update_mailbox_statistics, False),
        'alias_stats': ('alias_stats', update_alias_statistics, False),
        'blacklist_check': ('blacklist_check', check_monitored_hosts_job, False),
        'sync_transports': ('sync_transports', sync_transports_job, False),
        'send_weekly_summary': ('send_weekly_summary', send_weekly_summary_email_job, False),
        'detect_suppressions': ('detect_suppressions', detect_suppressions_job, False),
        'sync_suppressions': ('sync_suppressions', sync_suppressions_to_rspamd_job, False),
        'expire_suppressions': ('expire_suppressions', expire_suppressions_job, False),
        'process_quarantine_rules': ('process_quarantine_rules', process_quarantine_rules_job, False),
        'cleanup_deferred_queue': ('cleanup_deferred_queue', cleanup_deferred_queue_job, False),
        'fetch_raw_logs': ('fetch_raw_logs', fetch_raw_service_logs, True),
        'cleanup_raw_logs': ('cleanup_raw_logs', cleanup_raw_service_logs, True),
    }
    
    if job_name not in job_mapping:
        raise HTTPException(status_code=404, detail=f"Unknown job: {job_name}")
    
    status_key, job_func, self_managing = job_mapping[job_name]
    
    # Check if job is already running — check both main and raw logs status
    if self_managing:
        from ..raw_logs_worker import get_raw_logs_job_status
        current_status = get_raw_logs_job_status().get(status_key, {})
    else:
        current_status = get_job_status().get(status_key, {})
    if current_status.get('status') == 'running':
        raise HTTPException(status_code=409, detail=f"Job {job_name} is already running")
    
    # Mark job as running immediately (only for non-self-managing jobs)
    if not self_managing:
        update_job_status(status_key, 'running')
    
    # Run job in background
    def run_job_wrapper():
        try:
            import asyncio
            # Handle both sync and async functions
            if asyncio.iscoroutinefunction(job_func):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(job_func())
                finally:
                    loop.close()
            else:
                job_func()
            # Self-managing jobs update their own status internally
            if not self_managing:
                update_job_status(status_key, 'success')
        except Exception as e:
            logger.error(f"Manual job {job_name} failed: {e}")
            if not self_managing:
                update_job_status(status_key, 'failed', str(e))
    
    background_tasks.add_task(run_job_wrapper)
    
    return {
        'status': 'started',
        'job': job_name,
        'message': f'Job {job_name} started in background'
    }