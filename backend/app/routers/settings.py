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
from ..services.settings_store import get_config_overrides_from_db, save_config_overrides_to_db, has_config_overrides_in_db
from ..services.connection_test import test_smtp_connection, test_imap_connection
from ..services.geoip_downloader import is_license_configured, get_geoip_status
from .domains import get_cached_server_ip
from ..mailcow_api import mailcow_api
from ..services.oauth2_client import oauth2_client

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
    "dmarc_imap_password", "session_secret_key", "maxmind_license_key"
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
                    "schedule": "Daily at 2:15 AM",
                    "description": "Removes old DMARC and TLS reports based on DMARC retention period",
                    "retention": f"{settings.dmarc_retention_days} days",
                    "status": jobs_status.get('cleanup_dmarc_reports', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('cleanup_dmarc_reports', {}).get('last_run')),
                    "error": jobs_status.get('cleanup_dmarc_reports', {}).get('error')
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
                    "description": "Syncs active domains list from mailcow API",
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
                    "description": "Fetches mailbox statistics from mailcow API",
                    "status": jobs_status.get('mailbox_stats', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('mailbox_stats', {}).get('last_run')),
                    "error": jobs_status.get('mailbox_stats', {}).get('error')
                },
                "alias_stats": {
                    "interval": "5 minutes",
                    "description": "Syncs alias data from mailcow API",
                    "status": jobs_status.get('alias_stats', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('alias_stats', {}).get('last_run')),
                    "error": jobs_status.get('alias_stats', {}).get('error')
                },
                "blacklist_check": {
                    "schedule": "Daily at 5 AM",
                    "description": "Checks monitored hosts against DNS blacklists",
                    "status": jobs_status.get('blacklist_check', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('blacklist_check', {}).get('last_run')),
                    "error": jobs_status.get('blacklist_check', {}).get('error')
                },
                "sync_transports": {
                    "interval": "6 hours",
                    "description": "Sync Transports & Relayhosts from mailcow",
                    "status": jobs_status.get('sync_transports', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('sync_transports', {}).get('last_run')),
                    "error": jobs_status.get('sync_transports', {}).get('error')
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
                    "interval": f"{settings.raw_logs_fetch_interval} seconds" if settings.raw_logs_enabled else "Disabled",
                    "description": "Fetches raw logs from mailcow services for the Logs page",
                    "enabled": settings.raw_logs_enabled,
                    "status": _get_raw_logs_job_status('fetch_raw_logs', 'status', settings.raw_logs_enabled),
                    "last_run": _get_raw_logs_job_status('fetch_raw_logs', 'last_run', settings.raw_logs_enabled),
                    "error": _get_raw_logs_job_status('fetch_raw_logs', 'error', settings.raw_logs_enabled)
                },
                "cleanup_raw_logs": {
                    "schedule": "Daily at 3:00 AM" if settings.raw_logs_enabled else "Disabled",
                    "description": "Removes raw logs older than retention period",
                    "retention": f"{settings.raw_logs_retention_days} days" if settings.raw_logs_enabled else None,
                    "enabled": settings.raw_logs_enabled,
                    "status": _get_raw_logs_job_status('cleanup_raw_logs', 'status', settings.raw_logs_enabled),
                    "last_run": _get_raw_logs_job_status('cleanup_raw_logs', 'last_run', settings.raw_logs_enabled),
                    "error": _get_raw_logs_job_status('cleanup_raw_logs', 'error', settings.raw_logs_enabled)
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
async def get_editable_settings(db: Session = Depends(get_db)):
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
async def update_settings(body: Dict[str, Any], db: Session = Depends(get_db)):
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
    return {"settings_edit_via_ui_enabled": True, "settings_migrated": True, "configuration": _effective_config_for_editable(settings)}


@router.post("/settings/import-from-env")
async def import_settings_from_env(db: Session = Depends(get_db)):
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
    license_key = settings.maxmind_license_key
    
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


# =============================================================================
# MANUAL JOB TRIGGER
# =============================================================================

@router.post("/settings/jobs/{job_name}/run")
async def trigger_job(job_name: str, background_tasks: BackgroundTasks):
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
        send_weekly_summary_email_job
    )
    
    # Map job names to functions and their status keys
    job_mapping = {
        'fetch_logs': ('fetch_logs', fetch_all_logs),
        'complete_correlations': ('complete_correlations', complete_incomplete_correlations),
        'update_final_status': ('update_final_status', update_final_status_for_correlations),
        'expire_correlations': ('expire_correlations', expire_old_correlations),
        'cleanup_logs': ('cleanup_logs', cleanup_old_logs),
        'cleanup_dmarc_reports': ('cleanup_dmarc_reports', cleanup_old_dmarc_reports),
        'check_app_version': ('check_app_version', check_app_version_update),
        'dns_check': ('dns_check', check_all_domains_dns_background),
        'sync_local_domains': ('sync_local_domains', sync_local_domains),
        'update_geoip': ('update_geoip', update_geoip_database),
        'mailbox_stats': ('mailbox_stats', update_mailbox_statistics),
        'alias_stats': ('alias_stats', update_alias_statistics),
        'blacklist_check': ('blacklist_check', check_monitored_hosts_job),
        'sync_transports': ('sync_transports', sync_transports_job),
        'send_weekly_summary': ('send_weekly_summary', send_weekly_summary_email_job)
    }
    
    if job_name not in job_mapping:
        raise HTTPException(status_code=404, detail=f"Unknown job: {job_name}")
    
    status_key, job_func = job_mapping[job_name]
    
    # Check if job is already running
    current_status = get_job_status().get(status_key, {})
    if current_status.get('status') == 'running':
        raise HTTPException(status_code=409, detail=f"Job {job_name} is already running")
    
    # Mark job as running immediately
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
            update_job_status(status_key, 'success')
        except Exception as e:
            logger.error(f"Manual job {job_name} failed: {e}")
            update_job_status(status_key, 'failed', str(e))
    
    background_tasks.add_task(run_job_wrapper)
    
    return {
        'status': 'started',
        'job': job_name,
        'message': f'Job {job_name} started in background'
    }