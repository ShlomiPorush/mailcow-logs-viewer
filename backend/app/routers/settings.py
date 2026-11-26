import asyncio
import logging
import os
import threading
import httpx
from pydantic import ValidationError
from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException, Request, Response
from .. import leader
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, text, or_
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

from ..database import get_db, get_db_context
from ..models import PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation
from ..services.bounce_policy import cleanup_blocks
from ..services import excluded_addresses, written_recipients
from ..agent_access.scopes import READ
from ..agent_access.store import SIGN_IN_KEYS as _SESSION_BOUND_SETTING_KEYS
from ..user_access import DEFAULT_ACCESS_KEY, DEFAULT_VERSION_KEY, caller_may, job_error
from ..services import users_store
from ..config import settings, EDITABLE_SETTING_KEYS, FEATURE_IDS, reload_settings, Settings
from ..config import normalize_disabled_features, sign_in_problem
from ..config import _get_field_annotations, build_settings, get_env_locked_keys, settings_reload_lock
from ..app_time import app_tz, configured_zone_name, is_valid_zone, DATE_FORMATS, TIME_FORMATS
from ..scheduler import last_fetch_run_time, get_job_status, update_job_status, JOB_SKIPPED, JOB_STATUS_SET, reschedule_interval_jobs, clock_schedule, clock_parts, CLOCK_JOBS, dovecot_correlation_available, cleanup_disabled_feature_data, run_feature_data_sweep_soon, _mailbox_sync_needed
from ..services.settings_store import get_config_overrides_from_db, save_config_overrides_to_db, has_config_overrides_in_db, get_maxmind_validation_status, save_maxmind_validation_status, clear_maxmind_validation_status
from ..services.settings_store import credential_fingerprint, get_credential_check_status, save_credential_check_status
from ..services.settings_store import parse_bool
from ..services.connection_test import test_smtp_connection, test_imap_connection, list_imap_folders
from ..services.imap_folders import describe_setting
from ..services.geoip_downloader import is_license_configured, get_geoip_status
from .domains import get_cached_server_ip
from ..mailcow_api import mailcow_api, MailcowAPIError
from ..services.oauth2_client import oauth2_client
from ..session import get_session, get_session_from_request, set_session_cookie, revoke_all_sessions_keeping

from ..utils import format_datetime_for_api as format_datetime_utc
from ..api_models import Invalid, documented
from ..api_models import settings as m

logger = logging.getLogger(__name__)

router = APIRouter()


def _job_off_reason(key: str):
    rw = mailcow_api.has_rw_key
    checks = {
        'dmarc_imap_sync': [(not settings.dmarc_imap_enabled, 'IMAP import of DMARC and TLS reports is not set up', 'dmarc_imap')],
        'update_geoip': [(not is_license_configured(), 'Needs a MaxMind Account ID and License Key', 'maxmind')],
        'check_credentials': [(not rw and not settings.is_rspamd_configured,
                               'Needs the Read-Write API key or the Rspamd password', 'mailcow')],
        'send_weekly_summary': [(not settings.enable_weekly_summary, 'The weekly summary is turned off', 'notifications')],
        'detect_suppressions': [(not settings.suppression_enabled, '"Handle failed mail automatically" is off', 'outbound'),
                                (not settings.suppression_auto_detect, 'No choice under Outbound needs the mail logs', 'outbound')],
        'sync_suppressions': [(not settings.suppression_rspamd_sync, '"Sync with Rspamd" is off', 'outbound'),
                              (not settings.is_rspamd_configured, 'Needs the Rspamd password', 'mailcow')],
        'expire_suppressions': [(not settings.suppression_enabled, '"Handle failed mail automatically" is off', 'outbound')],
        'process_quarantine_rules': [(not rw, 'Needs the Read-Write API key (MAILCOW_API_KEY_RW)', 'mailcow')],
        'cleanup_deferred_queue': [(not settings.suppression_enabled, '"Handle failed mail automatically" is off', 'outbound'),
                                   (not settings.queue_cleanup_enabled, 'Temporary delivery failure is set to keep retrying', 'outbound'),
                                   (not rw, 'Needs the Read-Write API key (MAILCOW_API_KEY_RW)', 'mailcow')],
        'anomaly_detection': [(not settings.anomaly_detection_enabled, 'Anomaly detection is turned off', 'anomaly')],
        'smtp_abuse': [(not settings.smtp_abuse_enabled, 'Outgoing spam protection is turned off', 'smtp_abuse'),
                       (not rw, 'Needs the Read-Write API key (MAILCOW_API_KEY_RW)', 'mailcow')],
    }
    for off, reason, section in checks.get(key, []):
        if off:
            return reason, section
    return None


_JOB_FEATURES = {
    'cleanup_dmarc_reports': 'dmarc', 'dmarc_imap_sync': 'dmarc',
    'dns_check': 'domains',
    'alias_stats': 'mailbox-stats',
    'eas_devices': 'devices', 'cleanup_eas_devices': 'devices',
    'blacklist_check': 'blacklist', 'sync_transports': 'blacklist',
    'detect_suppressions': 'suppressions', 'sync_suppressions': 'suppressions',
    'expire_suppressions': 'suppressions', 'cleanup_deferred_queue': 'suppressions',
    'process_quarantine_rules': 'quarantine',
    'protection_rules': 'netfilter',
}


def _job_cannot_run(key: str):
    if key == 'mailbox_stats':
        return None if _mailbox_sync_needed() else 'Mailbox Stats and Rate Limits are both turned off'
    feature = _JOB_FEATURES.get(key)
    if feature and not settings.is_feature_enabled(feature):
        return 'The feature this job belongs to is turned off'
    off = _job_off_reason(key)
    return off[0] if off else None


def _get_raw_logs_job_status(job_key: str, field: str, enabled: bool):
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

_SENSITIVE_SETTING_KEYS = frozenset({
    "mailcow_api_key", "mailcow_api_key_rw", "auth_password", "oauth2_client_secret", "smtp_password",
    "dmarc_imap_password", "session_secret_key", "maxmind_license_key", "rspamd_password",
    "webhook_url",
})
MASK_PLACEHOLDER = "********"

_SECRET_BINDINGS = {
    "smtp_password": ("smtp_host", "smtp_port", "smtp_use_tls", "smtp_use_ssl", "smtp_user"),
    "rspamd_password": ("rspamd_url", "mailcow_url"),
    "dmarc_imap_password": ("dmarc_imap_host", "dmarc_imap_port", "dmarc_imap_use_ssl", "dmarc_imap_user"),
    "oauth2_client_secret": ("oauth2_issuer_url", "oauth2_authorization_url", "oauth2_token_url",
                             "oauth2_userinfo_url", "oauth2_use_oidc_discovery"),
    "mailcow_api_key": ("mailcow_url",),
    "mailcow_api_key_rw": ("mailcow_url",),
}
_SECRET_LABELS = {
    "smtp_password": "SMTP password",
    "rspamd_password": "Rspamd password",
    "dmarc_imap_password": "IMAP password",
    "oauth2_client_secret": "OAuth2 client secret",
    "mailcow_api_key": "mailcow API key",
    "mailcow_api_key_rw": "mailcow Read-Write API key",
}


def _comparable_setting(key: str, value: Any) -> Any:
    from ..services.settings_store import _get_effective_type
    if _get_effective_type(_get_field_annotations().get(key, str)) is bool:
        return parse_bool(value) is True
    if value is None:
        return ""
    return str(value).strip().rstrip("/")


def _normalize_booleans(allowed: Dict[str, Any]) -> None:
    from ..services.settings_store import _get_effective_type
    annotations = _get_field_annotations()
    for key, value in list(allowed.items()):
        if key not in annotations or _get_effective_type(annotations[key]) is not bool:
            continue
        parsed = False if value is None else parse_bool(value)
        if parsed is None:
            raise HTTPException(status_code=400, detail=f"Enter a valid value for {key}.")
        allowed[key] = parsed


def _reject_moved_secrets(allowed: Dict[str, Any]) -> None:
    env_locked = get_env_locked_keys()
    reenter, from_env = [], []
    for secret, endpoints in _SECRET_BINDINGS.items():
        if not str(getattr(settings, secret, None) or "").strip():
            continue
        posted = allowed.get(secret, MASK_PLACEHOLDER)
        if posted != MASK_PLACEHOLDER and secret not in env_locked:
            continue
        moved = [k for k in endpoints
                 if k in allowed and k not in env_locked
                 and _comparable_setting(k, allowed[k]) != _comparable_setting(k, getattr(settings, k, None))]
        if moved:
            (from_env if secret in env_locked else reenter).append((secret, moved))
    if from_env:
        secret, moved = from_env[0]
        raise HTTPException(status_code=400, detail=(
            f"The {_SECRET_LABELS[secret]} is set by the {secret.upper()} environment variable, so it can only "
            f"be sent to a different server from there. Change {', '.join(k.upper() for k in moved)} in the "
            f"environment as well, or undo the change here."))
    if reenter:
        labels = [_SECRET_LABELS[secret] for secret, _ in reenter]
        names = labels[0] if len(labels) == 1 else ", ".join(labels[:-1]) + " and " + labels[-1]
        raise HTTPException(status_code=400, detail=(
            f"You changed the server the {names} {'is' if len(labels) == 1 else 'are'} sent to. "
            f"Enter the {names} again: a stored secret is only sent to the server it was entered for."))


_ADDRESS_LIST_LABELS = {
    "admin_email": "Admin email",
    "blacklist_alert_email": "Blocklist alert email",
    "dmarc_error_email": "Report import error email",
}


def _normalize_address_lists(allowed: Dict[str, Any]) -> None:
    from ..services.smtp_service import invalid_addresses, split_addresses
    for key, label in _ADDRESS_LIST_LABELS.items():
        if key not in allowed or not str(allowed[key] or "").strip():
            continue
        bad = invalid_addresses(str(allowed[key]))
        if bad:
            raise HTTPException(status_code=400, detail=(
                f"{label}: \"{bad[0]}\" is not an email address. "
                f"Separate several addresses with commas."))
        allowed[key] = ", ".join(split_addresses(str(allowed[key])))


def _validate_bounce_actions(allowed: Dict[str, Any]) -> None:
    from ..services.bounce_policy import HARD_ACTIONS, SOFT_ACTIONS
    for key, known in (('suppression_hard_bounce_action', HARD_ACTIONS), ('suppression_soft_bounce_action', SOFT_ACTIONS)):
        if key not in allowed:
            continue
        value = str(allowed[key] or '')
        if value in known:
            allowed[key] = value
        elif value == str(getattr(settings, key) or ''):
            allowed.pop(key)
        else:
            raise HTTPException(status_code=400, detail=f"{key} accepts only: {', '.join(known)}.")


def _normalize_bounce_codes(allowed: Dict[str, Any]) -> None:
    from ..services.bounce_policy import EXCLUDED_CODES_KEYS, normalize_codes
    labels = {'5': 'Permanent delivery failure', '4': 'Temporary delivery failure'}
    for kind, key in EXCLUDED_CODES_KEYS.items():
        if key not in allowed:
            continue
        try:
            allowed[key] = normalize_codes(allowed[key], kind)
        except ValueError as bad:
            if str(allowed[key] or '') == str(getattr(settings, key) or ''):
                allowed.pop(key)
                continue
            raise HTTPException(status_code=400, detail=(
                f"{labels[kind]}: \"{bad}\" is not a {kind}.x.x code, such as {kind}.2.2."))


def _validate_agent_access(allowed: Dict[str, Any], current: Optional[Settings] = None) -> None:
    current = settings if current is None else current
    locked = get_env_locked_keys()
    _normalize_booleans(allowed)

    def on(key: str, after: bool) -> bool:
        value = allowed[key] if after and key in allowed and key not in locked else getattr(current, key)
        return value is True

    def agents_without_sign_in(after: bool) -> bool:
        sign_in = on("auth_enabled", after) or on("basic_auth_enabled", after) or on("oauth2_enabled", after)
        return on("agent_access_enabled", after) and not sign_in

    if agents_without_sign_in(True) and not agents_without_sign_in(False):
        raise HTTPException(status_code=400, detail=(
            "Agent access needs Basic Auth or OAuth2 sign-in. Turn on sign-in, or turn off agent access."))


def _whole_number(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("Not a number")
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return int(str(value).strip())


def _validate_session_limits(allowed: Dict[str, Any]) -> None:
    for key, low, high in (("session_expiry_hours", 1, None), ("session_idle_timeout_minutes", 5, 1440)):
        if key not in allowed:
            continue
        try:
            value = _whole_number(allowed[key])
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail=f"Enter a valid value for {key}.")
        allowed[key] = value
        if value == getattr(settings, key, None):
            continue
        if value < low or (high is not None and value > high):
            raise HTTPException(status_code=400, detail=f"Enter a valid value for {key}.")


def _validate_display_formats(allowed: Dict[str, Any]) -> None:
    for key, known in (('date_format', DATE_FORMATS), ('time_format', TIME_FORMATS)):
        if key not in allowed:
            continue
        value = str(allowed[key] or '').strip()
        match = next((k for k in known if k.lower() == value.lower()), None)
        if match:
            allowed[key] = match
        elif value == str(getattr(settings, key) or ''):
            allowed.pop(key)
        else:
            raise HTTPException(status_code=400, detail=f"{key} accepts only: {', '.join(known)}.")


def _validate_time_zone(allowed: Dict[str, Any], db: Session) -> None:
    if "tz" not in allowed:
        return
    zone = allowed["tz"] = str(allowed["tz"] or "").strip()
    if is_valid_zone(zone):
        return
    stored = get_config_overrides_from_db(db, _get_field_annotations()).get("tz")
    if zone == str(stored or "").strip():
        return
    if zone == configured_zone_name():
        if "tz" in get_env_locked_keys():
            del allowed["tz"]
        return
    raise HTTPException(status_code=400, detail=f"Unknown time zone: {zone}. Select a time zone from the list.")


_ADMIN_SIGN_IN_KEYS = ("basic_auth_enabled", "auth_username", "auth_password", "oauth2_enabled")


def _changes_admin_sign_in(allowed: Dict[str, Any], before: Settings) -> bool:
    return any(key in allowed and (allowed[key] or "") != (getattr(before, key, None) or "")
               for key in _ADMIN_SIGN_IN_KEYS)


def _session_bound_values(source: Settings) -> tuple:
    if source is None:
        raise ValueError("The sign-in values need the settings they come from")
    return tuple(getattr(source, key, None) for key in _SESSION_BOUND_SETTING_KEYS)


def _effective_config_for_editable(settings_obj: Settings) -> Dict[str, Any]:
    out = {}
    for key in EDITABLE_SETTING_KEYS:
        if not hasattr(settings_obj, key):
            continue
        val = getattr(settings_obj, key)
        if key in _SENSITIVE_SETTING_KEYS:
            out[key] = MASK_PLACEHOLDER if (val is not None and str(val).strip() != "") else ""
        elif key == "disabled_features":
            out[key] = ",".join(normalize_disabled_features(val))
        else:
            out[key] = val
    return out


def _get_field_defaults() -> Dict[str, Any]:
    from pydantic_core import PydanticUndefined
    defaults = {}
    for key in EDITABLE_SETTING_KEYS:
        field_info = Settings.model_fields.get(key)
        if field_info is None:
            continue
        if field_info.default is PydanticUndefined:
            defaults[key] = None
        elif key in _SENSITIVE_SETTING_KEYS:
            defaults[key] = ""
        else:
            defaults[key] = field_info.default
    return defaults


@router.get("/settings/info", responses=documented(m.SettingsInfoResponse, description="The information; when it could not be read, error and empty parts"))
def get_settings_info(request: Request = None, db: Session = Depends(get_db)):
    """
    Get system configuration and status information
    
    Returns:
    - Configuration (without sensitive data)
    - Last import times for each log type
    - Background job statistics
    - Database statistics
    The sign-in username, the alert mail and IMAP accounts and the editable
    settings are Settings: only for a caller who may read Settings (an admin).
    """
    with_settings = caller_may(request, "settings", READ)
    try:
        last_postfix = db.query(func.max(PostfixLog.created_at)).scalar()
        last_rspamd = db.query(func.max(RspamdLog.created_at)).scalar()
        last_netfilter = db.query(func.max(NetfilterLog.created_at)).scalar()
        last_correlation = db.query(func.max(MessageCorrelation.updated_at)).scalar()
        
        from ..services.figures import linking_figure
        linking = linking_figure(db)
        total_correlations = linking['total']
        complete_correlations = linking['complete']
        incomplete_correlations = linking['incomplete']
        expired_correlations = linking['expired']
        
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
        
        total_postfix = db.query(func.count(PostfixLog.id)).scalar()
        total_rspamd = db.query(func.count(RspamdLog.id)).scalar()
        total_netfilter = db.query(func.count(NetfilterLog.id)).scalar()
        
        oldest_postfix = db.query(func.min(PostfixLog.time)).scalar()
        oldest_rspamd = db.query(func.min(RspamdLog.time)).scalar()
        oldest_netfilter = db.query(func.min(NetfilterLog.time)).scalar()
        
        recent_incomplete = []
        if caller_may(request, "messages", READ):
            recent_incomplete = db.query(MessageCorrelation).filter(
                MessageCorrelation.is_complete == False,
                excluded_addresses.correlation_visible(),
            ).order_by(desc(MessageCorrelation.created_at)).limit(5).all()
        
        jobs_status = get_job_status()

        server_version = db.execute(text("SHOW server_version")).scalar() or ''
        database_version = server_version.split()[0] if server_version else None

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
                "timezone": app_tz().key,
                "date_format": settings.date_format,
                "time_format": settings.time_format,
                "app_title": settings.app_title,
                "log_level": settings.log_level,
                "blacklist_enabled": len(settings.blacklist_emails_list) > 0,
                "blacklist_count": len(settings.blacklist_emails_list),
                "max_search_results": settings.max_search_results,
                "csv_export_limit": settings.csv_export_limit,
                "scheduler_workers": settings.scheduler_workers,
                "rspamd_configured": settings.is_rspamd_configured,
                "database_version": database_version,
                "auth_enabled": settings.is_authentication_enabled,
                "basic_auth_enabled": settings.is_basic_auth_enabled,
                "oauth2_enabled": settings.is_oauth2_enabled,
                "auth_username": settings.auth_username if settings.is_basic_auth_enabled and with_settings else None,
                "oauth2_provider_name": settings.oauth2_provider_name if settings.is_oauth2_enabled else None,
                "maxmind_status": get_maxmind_validation_status(db),
                "mailcow_rw_key_status": _credential_status(db, "mailcow_rw_key"),
                "rspamd_password_status": _credential_status(db, "rspamd_password"),
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
                "completion_rate": linking['value'] if linking['valid'] else 0,
                "known": linking['valid']
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
                "trend_samples": {
                    "interval": "1 hour",
                    "description": "Samples the dashboard figures that show a trend (storage, linking, blocklists, Security), kept 90 days",
                    "status": jobs_status.get('trend_samples', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('trend_samples', {}).get('last_run')),
                    "error": jobs_status.get('trend_samples', {}).get('error')
                },
                "feature_data_sweep": {
                    "interval": "10 minutes",
                    "description": "Deletes the data of turned-off features (and the suppression list while Sync with Rspamd is off), and loads this app's Rspamd blocks back when they are turned on again",
                    "status": jobs_status.get('feature_data_sweep', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('feature_data_sweep', {}).get('last_run')),
                    "error": jobs_status.get('feature_data_sweep', {}).get('error')
                },
                "expire_correlations": {
                    "interval": "60 seconds (1 minute)",
                    "description": "Marks old incomplete correlations as expired",
                    "expire_after": f"{settings.max_correlation_age_minutes} minutes",
                    "status": jobs_status.get('expire_correlations', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('expire_correlations', {}).get('last_run')),
                    "error": jobs_status.get('expire_correlations', {}).get('error')
                },
                "correlate_dovecot": {
                    "interval": "60 seconds (1 minute)" if dovecot_correlation_available()
                               else "Disabled (needs raw log collection with the 'dovecot' service)",
                    "description": "Adds the Dovecot delivery outcome (Sieve discard, target folder, quota errors) to messages",
                    "feature_disabled": not dovecot_correlation_available(),
                    "status": jobs_status.get('correlate_dovecot', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('correlate_dovecot', {}).get('last_run')),
                    "error": jobs_status.get('correlate_dovecot', {}).get('error')
                },
                "cleanup_logs": {
                    "schedule": clock_schedule('cleanup_logs'),
                    "description": "Removes old logs based on retention period",
                    "retention": f"{settings.retention_days} days",
                    "status": jobs_status.get('cleanup_logs', {}).get('status', 'unknown'),
                    "last_run": format_datetime_utc(jobs_status.get('cleanup_logs', {}).get('last_run')),
                    "error": jobs_status.get('cleanup_logs', {}).get('error')
                },
                "cleanup_dmarc_reports": {
                    "schedule": clock_schedule('cleanup_dmarc_reports') if settings.is_feature_enabled('dmarc') else "Disabled (feature off)",
                    "description": "Removes DMARC and TLS reports older than the retention period",
                    "retention": f"{settings.dmarc_retention_days} days",
                    "feature_disabled": not settings.is_feature_enabled('dmarc'),
                    "status": jobs_status.get('cleanup_dmarc_reports', {}).get('status', 'unknown') if settings.is_feature_enabled('dmarc') else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('cleanup_dmarc_reports', {}).get('last_run')) if settings.is_feature_enabled('dmarc') else None,
                    "error": jobs_status.get('cleanup_dmarc_reports', {}).get('error') if settings.is_feature_enabled('dmarc') else None
                },
                "check_credentials": {
                    "interval": "6 hours, and after a start",
                    "description": "Checks that mailcow accepts the Read-Write API key and Rspamd the password, as Validate does; changes nothing",
                    "status": jobs_status.get('check_credentials', {}).get('status', 'idle') if (mailcow_api.has_rw_key or settings.is_rspamd_configured) else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('check_credentials', {}).get('last_run')),
                    "error": jobs_status.get('check_credentials', {}).get('error')
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
                    "description": "Imports DMARC and TLS reports from an IMAP mailbox",
                    "enabled": settings.is_feature_enabled('dmarc') and settings.dmarc_imap_enabled,
                    "feature_disabled": not settings.is_feature_enabled('dmarc'),
                    "status": jobs_status.get('dmarc_imap_sync', {}).get('status', 'idle') if (settings.is_feature_enabled('dmarc') and settings.dmarc_imap_enabled) else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('dmarc_imap_sync', {}).get('last_run')) if (settings.is_feature_enabled('dmarc') and settings.dmarc_imap_enabled) else None,
                    "error": jobs_status.get('dmarc_imap_sync', {}).get('error') if (settings.is_feature_enabled('dmarc') and settings.dmarc_imap_enabled) else None
                },
                "update_geoip": {
                    "schedule": clock_schedule('update_geoip') if is_license_configured() else "Disabled",
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
                "eas_devices": {
                    "interval": "1 minute" if settings.is_feature_enabled('devices') else "Disabled (feature off)",
                    "description": "Records ActiveSync devices from the SOGo log",
                    "feature_disabled": not settings.is_feature_enabled('devices'),
                    "status": jobs_status.get('eas_devices', {}).get('status', 'unknown') if settings.is_feature_enabled('devices') else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('eas_devices', {}).get('last_run')) if settings.is_feature_enabled('devices') else None,
                    "error": jobs_status.get('eas_devices', {}).get('error') if settings.is_feature_enabled('devices') else None
                },
                "cleanup_eas_devices": {
                    "schedule": clock_schedule('cleanup_eas_devices') if settings.is_feature_enabled('devices') else "Disabled (feature off)",
                    "description": "Removes ActiveSync devices not seen within the retention period",
                    "retention": (f"{settings.eas_devices_retention_days} days" if settings.eas_devices_retention_days > 0 else "Forever") if settings.is_feature_enabled('devices') else None,
                    "feature_disabled": not settings.is_feature_enabled('devices'),
                    "status": jobs_status.get('cleanup_eas_devices', {}).get('status', 'unknown') if settings.is_feature_enabled('devices') else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('cleanup_eas_devices', {}).get('last_run')) if settings.is_feature_enabled('devices') else None,
                    "error": jobs_status.get('cleanup_eas_devices', {}).get('error') if settings.is_feature_enabled('devices') else None
                },
                "blacklist_check": {
                    "schedule": clock_schedule('blacklist_check') if settings.is_feature_enabled('blacklist') else "Disabled (feature off)",
                    "description": "Checks monitored hosts against DNS blacklists",
                    "feature_disabled": not settings.is_feature_enabled('blacklist'),
                    "status": jobs_status.get('blacklist_check', {}).get('status', 'unknown') if settings.is_feature_enabled('blacklist') else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('blacklist_check', {}).get('last_run')) if settings.is_feature_enabled('blacklist') else None,
                    "error": jobs_status.get('blacklist_check', {}).get('error') if settings.is_feature_enabled('blacklist') else None
                },
                "sync_transports": {
                    "interval": "6 hours" if settings.is_feature_enabled('blacklist') else "Disabled (feature off)",
                    "description": "Syncs transports and relayhosts from mailcow",
                    "feature_disabled": not settings.is_feature_enabled('blacklist'),
                    "status": jobs_status.get('sync_transports', {}).get('status', 'unknown') if settings.is_feature_enabled('blacklist') else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('sync_transports', {}).get('last_run')) if settings.is_feature_enabled('blacklist') else None,
                    "error": jobs_status.get('sync_transports', {}).get('error') if settings.is_feature_enabled('blacklist') else None
                },
                "send_weekly_summary": {
                    "schedule": clock_schedule('send_weekly_summary') if settings.enable_weekly_summary else "Disabled",
                    "description": "Sends a weekly summary report via email",
                    "enabled": settings.enable_weekly_summary,
                    "status": jobs_status.get('send_weekly_summary', {}).get('status', 'idle') if settings.enable_weekly_summary else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('send_weekly_summary', {}).get('last_run')) if settings.enable_weekly_summary else None,
                    "error": jobs_status.get('send_weekly_summary', {}).get('error') if settings.enable_weekly_summary else None
                },
                "fetch_raw_logs": {
                    "interval": f"{settings.raw_logs_fetch_interval} seconds",
                    "description": "Fetches raw logs from mailcow services for the Logs page and the pages that read them",
                    "services": ", ".join(settings.raw_logs_collected_list),
                    "enabled": True,
                    "status": _get_raw_logs_job_status('fetch_raw_logs', 'status', True),
                    "last_run": _get_raw_logs_job_status('fetch_raw_logs', 'last_run', True),
                    "error": _get_raw_logs_job_status('fetch_raw_logs', 'error', True)
                },
                "cleanup_raw_logs": {
                    "schedule": clock_schedule('cleanup_raw_logs'),
                    "description": "Removes raw logs older than retention period",
                    "retention": f"{settings.raw_logs_retention_days} days, rate limit log {settings.rate_limits_retention_effective} days",
                    "enabled": True,
                    "status": _get_raw_logs_job_status('cleanup_raw_logs', 'status', True),
                    "last_run": _get_raw_logs_job_status('cleanup_raw_logs', 'last_run', True),
                    "error": _get_raw_logs_job_status('cleanup_raw_logs', 'error', True)
                },
                "detect_suppressions": {
                    "interval": "5 minutes" if (settings.is_feature_enabled('suppressions') and settings.suppression_enabled) else ("Disabled (feature off)" if not settings.is_feature_enabled('suppressions') else "Disabled (suppression off)"),
                    "description": "Reads delivery failures and handles queued mail using the Outbound settings",
                    "enabled": settings.is_feature_enabled('suppressions') and settings.suppression_enabled and settings.suppression_auto_detect,
                    "feature_disabled": not settings.is_feature_enabled('suppressions'),
                    "status": jobs_status.get('detect_suppressions', {}).get('status', 'idle') if (settings.is_feature_enabled('suppressions') and settings.suppression_enabled) else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('detect_suppressions', {}).get('last_run')) if (settings.is_feature_enabled('suppressions') and settings.suppression_enabled) else None,
                    "error": jobs_status.get('detect_suppressions', {}).get('error') if (settings.is_feature_enabled('suppressions') and settings.suppression_enabled) else None
                },
                "sync_suppressions": {
                    "interval": "10 minutes" if (settings.is_feature_enabled('suppressions') and settings.suppression_rspamd_sync and settings.is_rspamd_configured) else ("Disabled (feature off)" if not settings.is_feature_enabled('suppressions') else ("Disabled (Rspamd sync off)" if not settings.suppression_rspamd_sync else "Disabled (no Rspamd password)")),
                    "description": "Keeps the suppression list and this app's Rspamd blocks in step, both ways",
                    "enabled": settings.is_feature_enabled('suppressions') and settings.suppression_rspamd_sync and settings.is_rspamd_configured,
                    "feature_disabled": not settings.is_feature_enabled('suppressions'),
                    "status": jobs_status.get('sync_suppressions', {}).get('status', 'idle') if (settings.is_feature_enabled('suppressions') and settings.suppression_rspamd_sync and settings.is_rspamd_configured) else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('sync_suppressions', {}).get('last_run')) if (settings.is_feature_enabled('suppressions') and settings.suppression_rspamd_sync and settings.is_rspamd_configured) else None,
                    "error": jobs_status.get('sync_suppressions', {}).get('error') if (settings.is_feature_enabled('suppressions') and settings.suppression_rspamd_sync and settings.is_rspamd_configured) else None
                },
                "expire_suppressions": {
                    "interval": "1 hour" if (settings.is_feature_enabled('suppressions') and settings.suppression_enabled) else ("Disabled (feature off)" if not settings.is_feature_enabled('suppressions') else "Disabled (suppression off)"),
                    "description": "Deactivates expired suppression entries",
                    "enabled": settings.is_feature_enabled('suppressions') and settings.suppression_enabled,
                    "feature_disabled": not settings.is_feature_enabled('suppressions'),
                    "status": jobs_status.get('expire_suppressions', {}).get('status', 'idle') if (settings.is_feature_enabled('suppressions') and settings.suppression_enabled) else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('expire_suppressions', {}).get('last_run')) if (settings.is_feature_enabled('suppressions') and settings.suppression_enabled) else None,
                    "error": jobs_status.get('expire_suppressions', {}).get('error') if (settings.is_feature_enabled('suppressions') and settings.suppression_enabled) else None
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
                    "interval": "5 minutes" if (settings.is_feature_enabled('suppressions') and settings.suppression_enabled and settings.queue_cleanup_enabled and mailcow_api.has_rw_key) else ("Disabled (feature off)" if not settings.is_feature_enabled('suppressions') else ("Disabled (suppression off)" if not settings.suppression_enabled else ("Disabled (queue cleanup off)" if not settings.queue_cleanup_enabled else "Disabled (no RW API key)"))),
                    "description": (f"Deletes deferred mail after {settings.queue_cleanup_threshold_minutes} minutes in the queue"
                                    + (" and blocks its recipients" if cleanup_blocks() else "")),
                    "enabled": settings.is_feature_enabled('suppressions') and settings.suppression_enabled and settings.queue_cleanup_enabled and mailcow_api.has_rw_key,
                    "feature_disabled": not settings.is_feature_enabled('suppressions'),
                    "status": jobs_status.get('cleanup_deferred_queue', {}).get('status', 'idle') if (settings.is_feature_enabled('suppressions') and settings.suppression_enabled and settings.queue_cleanup_enabled) else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('cleanup_deferred_queue', {}).get('last_run')) if (settings.is_feature_enabled('suppressions') and settings.suppression_enabled and settings.queue_cleanup_enabled) else None,
                    "error": jobs_status.get('cleanup_deferred_queue', {}).get('error') if (settings.is_feature_enabled('suppressions') and settings.suppression_enabled and settings.queue_cleanup_enabled) else None
                },
                "anomaly_detection": {
                    "interval": f"{settings.anomaly_check_interval} minutes" if settings.anomaly_detection_enabled else "Disabled (anomaly detection off)",
                    "description": "Detects outbound volume spikes and auth-failure bursts, and raises security alerts",
                    "enabled": settings.anomaly_detection_enabled,
                    "status": jobs_status.get('anomaly_detection', {}).get('status', 'idle') if settings.anomaly_detection_enabled else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('anomaly_detection', {}).get('last_run')) if settings.anomaly_detection_enabled else None,
                    "error": jobs_status.get('anomaly_detection', {}).get('error') if settings.anomaly_detection_enabled else None
                },
                "smtp_abuse": {
                    "interval": "1 minute" if (settings.smtp_abuse_enabled and mailcow_api.has_rw_key) else ("Disabled (abuse protection off)" if not settings.smtp_abuse_enabled else "Disabled (no RW API key)"),
                    "description": f"Disables SMTP for mailboxes sending > {settings.smtp_abuse_threshold} messages / {settings.smtp_abuse_window_minutes}m",
                    "enabled": settings.smtp_abuse_enabled and mailcow_api.has_rw_key,
                    "status": jobs_status.get('smtp_abuse', {}).get('status', 'idle') if (settings.smtp_abuse_enabled and mailcow_api.has_rw_key) else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('smtp_abuse', {}).get('last_run')) if (settings.smtp_abuse_enabled and mailcow_api.has_rw_key) else None,
                    "error": jobs_status.get('smtp_abuse', {}).get('error') if (settings.smtp_abuse_enabled and mailcow_api.has_rw_key) else None
                },
                "protection_rules": {
                    "interval": "After each log fetch" if settings.is_feature_enabled('netfilter') else "Disabled (Security feature off)",
                    "description": "Notes the addresses the protection rules would ban (watch mode)",
                    "enabled": settings.is_feature_enabled('netfilter'),
                    "feature_disabled": not settings.is_feature_enabled('netfilter'),
                    "status": jobs_status.get('protection_rules', {}).get('status', 'idle') if settings.is_feature_enabled('netfilter') else 'disabled',
                    "last_run": format_datetime_utc(jobs_status.get('protection_rules', {}).get('last_run')) if settings.is_feature_enabled('netfilter') else None,
                    "error": jobs_status.get('protection_rules', {}).get('error') if settings.is_feature_enabled('netfilter') else None
                }
            },
            "smtp_configuration": {
                "enabled": settings.smtp_enabled,
                "host": settings.smtp_host if settings.smtp_enabled and with_settings else None,
                "port": settings.smtp_port if settings.smtp_enabled and with_settings else None,
                "user": settings.smtp_user if settings.smtp_enabled and with_settings else None,
                "from_address": settings.smtp_from if settings.smtp_enabled and with_settings else None,
                "use_tls": settings.smtp_use_tls if settings.smtp_enabled else None,
                "admin_email": settings.admin_email if settings.smtp_enabled and with_settings else None,
                "configured": settings.notification_smtp_configured
            },
            "dmarc_configuration": {
                "manual_upload_enabled": settings.dmarc_manual_upload_enabled,
                "imap_sync_enabled": settings.dmarc_imap_enabled,
                "imap_host": settings.dmarc_imap_host if settings.dmarc_imap_enabled and with_settings else None,
                "imap_user": settings.dmarc_imap_user if settings.dmarc_imap_enabled and with_settings else None,
                "imap_folder": describe_setting(settings.dmarc_imap_folder) if settings.dmarc_imap_enabled and with_settings else None,
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
                    "recipient": written_recipients.shown(corr.recipient, corr.written_recipients),
                    "created_at": format_datetime_utc(corr.created_at),
                    "age_minutes": round((datetime.now(timezone.utc) - corr.created_at.replace(tzinfo=timezone.utc)).total_seconds() / 60) if corr.created_at else None
                }
                for corr in recent_incomplete
            ]
        }
        for key, job in result.get("background_jobs", {}).items():
            if "error" in job:
                job["error"] = job_error(request, job["error"])
            off = None if job.get("feature_disabled") else _job_off_reason(key)
            if off:
                job["disabled_reason"], job["settings_section"] = off
            if key in CLOCK_JOBS and job.get("schedule") == clock_schedule(key):
                job["clock"] = clock_parts(key)
        result["raw_logs_required"] = settings.raw_logs_required
        if settings.edit_settings_via_ui_enabled and with_settings:
            result["editable_config"] = _effective_config_for_editable(settings)
            result["default_config"] = _get_field_defaults()
            result["settings_migrated"] = has_config_overrides_in_db(db)
            result["legacy_auth_enabled"] = bool(settings.auth_enabled)
        return result
        
    except Exception as e:
        logger.error(f"Error fetching settings info: {e}")
        return {
            "error": "Unable to load settings status. Check the application logs.",
            "settings_edit_via_ui_enabled": getattr(settings, "edit_settings_via_ui_enabled", False),
            "configuration": {},
            "import_status": {},
            "correlation_status": {},
            "background_jobs": {}
        }


@router.get("/settings", responses=documented(m.EditableSettings, errors={500: None}))
def get_editable_settings(db: Session = Depends(get_db)):
    """
    Get effective configuration for editing (editable keys only; secrets masked).
    Includes settings_edit_via_ui_enabled so frontend can show/hide edit form.
    When UI editing is enabled, reloads settings from DB so response is up to date.
    Returns env_locked_keys: keys where ENV is set (ENV always overrides DB).
    """
    if settings.edit_settings_via_ui_enabled:
        reload_settings(db)
    env_locked = sorted(get_env_locked_keys()) if settings.edit_settings_via_ui_enabled else []
    return {
        "settings_edit_via_ui_enabled": settings.edit_settings_via_ui_enabled,
        "settings_migrated": has_config_overrides_in_db(db),
        "configuration": _effective_config_for_editable(settings),
        "default_config": _get_field_defaults(),
        "env_locked_keys": env_locked,
        "legacy_auth_enabled": bool(settings.auth_enabled),
    }


@router.put("/settings", responses=documented(m.SettingsSaveResponse, description="Saved; a body without an editable change saves nothing", errors={400: None, 403: None, 409: None, 422: Invalid, 500: None}))
def update_settings(body: Dict[str, Any], request: Request = None, response: Response = None,
                    db: Session = Depends(get_db)):
    """
    Update app settings from UI. Only allowed when SETTINGS_EDIT_VIA_UI_ENABLED is true.
    Accepts only keys in EDITABLE_SETTING_KEYS. Secrets: send empty string to leave unchanged.
    When enabling basic_auth_enabled, verify_username and verify_password must be provided
    and must match the credentials being saved, to prevent lockout.
    """
    import secrets as _secrets
    if not settings.edit_settings_via_ui_enabled:
        raise HTTPException(status_code=403, detail="Settings editing is off. Set SETTINGS_EDIT_VIA_UI_ENABLED=true in the environment to enable it.")
    if any(key in body for key in ("oauth2_default_access", DEFAULT_ACCESS_KEY, DEFAULT_VERSION_KEY)):
        raise HTTPException(status_code=400, detail="The OAuth2 default access is changed under Users, not in Settings.")
    allowed = {k: v for k, v in body.items() if k in EDITABLE_SETTING_KEYS}
    if "disabled_features" in allowed:
        features = normalize_disabled_features(str(allowed["disabled_features"] or ""))
        if any(f not in FEATURE_IDS for f in features):
            raise HTTPException(status_code=400, detail="disabled_features accepts only known feature names.")
        allowed["disabled_features"] = ",".join(features)
    _normalize_booleans(allowed)
    _reject_moved_secrets(allowed)
    _normalize_address_lists(allowed)
    _validate_time_zone(allowed, db)
    _validate_display_formats(allowed)
    _validate_bounce_actions(allowed)
    _normalize_bounce_codes(allowed)
    _validate_agent_access(allowed)
    _validate_session_limits(allowed)
    for sk in _SENSITIVE_SETTING_KEYS:
        if sk in allowed and isinstance(allowed[sk], str) and allowed[sk] == MASK_PLACEHOLDER:
            del allowed[sk]
    if not allowed:
        reload_settings(db)
        return {"settings_edit_via_ui_enabled": True, "settings_migrated": True, "configuration": _effective_config_for_editable(settings)}

    _enabling_basic_auth = (
        allowed.get("basic_auth_enabled") is True
        and not settings.is_basic_auth_enabled
    )
    if _enabling_basic_auth:
        _eff_password = allowed.get("auth_password", settings.auth_password or "")
        _eff_username = allowed.get("auth_username", settings.auth_username or "admin")
        if not _eff_password or not str(_eff_password).strip():
            raise HTTPException(
                status_code=400,
                detail="Set a password before enabling Basic Auth."
            )
        _verify_user = body.get("verify_username", "")
        _verify_pass = body.get("verify_password", "")
        if not _verify_user or not _verify_pass:
            raise HTTPException(
                status_code=400,
                detail="Enter your configured username and password to enable Basic Auth."
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
                detail="The username or password does not match the configured credentials. Check both and try again."
            )
        logger.info("Basic Auth credential verification passed - enabling authentication")

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

    try:
        current = settings.model_dump()
        for k, v in allowed.items():
            current[k] = v
        annotations = _get_field_annotations()
        for k, v in list(current.items()):
            if v is not None or k not in annotations:
                continue
            ann = annotations[k]
            if getattr(ann, "__args__", None) and type(None) in getattr(ann, "__args__", ()):
                continue
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
    except ValidationError as e:
        fields = sorted({
            str(error["loc"][0]) for error in e.errors(include_input=False, include_context=False)
            if error["loc"] and error["loc"][0] in Settings.model_fields
        })
        detail = "Invalid settings. Check the submitted values."
        if fields:
            detail = "Invalid settings for: " + ", ".join(fields)
        raise HTTPException(status_code=400, detail=detail) from e
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid settings. Check the submitted values.") from e
    prev_sync_sources =(settings.blacklist_source_transports, settings.blacklist_source_relayhosts)
    prev_credentials = {name: check["fingerprint"]() for name, check in _CREDENTIAL_CHECKS.items()}
    operator_session = get_session_from_request(request) if request is not None else None
    from ..services.feature_data import spam_list_kept
    with _LIST_TRANSITION_LOCK, settings_reload_lock:
        before = build_settings(db)
        _validate_agent_access(allowed, before)
        locked = get_env_locked_keys()
        problem = sign_in_problem(before.model_copy(
            update={k: v for k, v in allowed.items() if k not in locked}))
        if problem:
            raise HTTPException(status_code=400, detail=problem)
        if _changes_admin_sign_in(allowed, before):
            try:
                users_store.check_sign_in_settings(db, before, allowed)
            except users_store.UserError as e:
                raise HTTPException(status_code=e.status, detail=e.detail)
        prev_sign_in = _session_bound_values(before)
        list_was_kept, switches_before = spam_list_kept(), _spam_list_switches()
        save_config_overrides_to_db(db, allowed)
        saved = reload_settings(db)
        rspamd_off_transition = _record_list_transition(
            db, list_was_kept, spam_list_kept(), switched=_spam_list_switches() != switches_before)
    oauth2_client.reload_config()
    if _session_bound_values(saved) != prev_sign_in:
        admitted = getattr(getattr(request, "state", None), "auth_generation", None)
        keep = operator_session if (operator_session and saved.is_authentication_enabled
                                    and response is not None and isinstance(admitted, int)) else None
        kept = revoke_all_sessions_keeping(keep, admitted)[1]
        try:
            from ..agent_access.store import check_sign_in_unchanged
            check_sign_in_unchanged(db)
        except Exception as e:
            logger.error(f"Could not disconnect agents after the sign-in change: {e}")
        if kept and get_session(kept) is not None:
            set_session_cookie(response, kept, request)
        elif keep is not None:
            logger.info("The operator who saved signs in again")
    feature_data_errors = cleanup_disabled_feature_data(db)
    run_feature_data_sweep_soon()
    mailcow_api.reload_config()
    reschedule_interval_jobs()

    new_sync_sources = (settings.blacklist_source_transports, settings.blacklist_source_relayhosts)
    from ..scheduler import scheduler as _scheduler
    if (settings.is_feature_enabled('blacklist') and _scheduler.running
            and any(new and not old for old, new in zip(prev_sync_sources, new_sync_sources))):
        try:
            from datetime import datetime, timedelta, timezone
            from ..scheduler import sync_transports_job
            _scheduler.add_job(
                sync_transports_job, 'date',
                run_date=datetime.now(timezone.utc) + timedelta(seconds=1),
                id='sync_transports_on_enable', replace_existing=True
            )
            logger.info("Transports/relayhosts source enabled - triggering immediate sync")
        except Exception as e:
            logger.warning(f"Could not trigger immediate transports sync: {e}")

    if 'maxmind_license_key' in allowed or 'maxmind_account_id' in allowed:
        clear_maxmind_validation_status(db)
    
    changed = {f"{name}_changed": check["configured"]() and prev_credentials[name] != check["fingerprint"]()
               for name, check in _CREDENTIAL_CHECKS.items()}
    errors = {"feature_data_errors": feature_data_errors} if feature_data_errors else {}
    return {"settings_edit_via_ui_enabled": True, "settings_migrated": True, "configuration": _effective_config_for_editable(settings),
            "rspamd_off_transition": rspamd_off_transition, **errors, **changed}


_LIST_TRANSITION_LOCK = threading.Lock()


def _spam_list_switches():
    return settings.is_feature_enabled('suppressions'), bool(settings.suppression_rspamd_sync)


def _record_list_transition(db: Session, was_kept: bool, now_kept: bool, switched: bool = False) -> Optional[str]:
    import secrets
    from ..models import SystemSetting
    from ..services.feature_data import _set_key
    from .suppressions import OFF_TRANSITION_KEY
    token = None
    if not now_kept and (was_kept or switched):
        token = secrets.token_hex(12)
        _set_key(db, OFF_TRANSITION_KEY, token)
    elif now_kept and not was_kept:
        db.query(SystemSetting).filter(SystemSetting.key == OFF_TRANSITION_KEY).delete(synchronize_session=False)
    else:
        return None
    db.commit()
    return token


from ..services.feature_data import FEATURE_TABLES as _FEATURE_TABLES  # noqa: E402


@router.post("/settings/purge-feature-data", responses=documented(m.FeatureDataPurged, errors={400: None, 403: None, 409: m.PurgeMapError, 422: Invalid, 500: None, 502: m.PurgeMapError}))
def purge_feature_data(body: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Delete all database data associated with a disabled feature.
    Body: { "feature": "<feature-id>" }, and for suppressions (or its old name spam-filter) "rspamd": "remove" or
    "keep": what happens to the blocks the app wrote to Rspamd. The list is
    never deleted without that choice, so no block stays in Rspamd unseen.
    Only allowed when SETTINGS_EDIT_VIA_UI_ENABLED is true and the feature is currently disabled.
    """
    if not settings.edit_settings_via_ui_enabled:
        raise HTTPException(status_code=403, detail="Settings editing is off. Enable SETTINGS_EDIT_VIA_UI_ENABLED in the environment.")

    feature = body.get("feature", "").strip().lower()
    if feature == 'spam-filter':
        feature = 'suppressions'
    if feature not in _FEATURE_TABLES:
        raise HTTPException(status_code=400, detail=f"Unknown feature: {feature}")

    if settings.is_feature_enabled(feature):
        raise HTTPException(status_code=400, detail=f"Feature '{feature}' is currently enabled. Disable it first.")

    if feature != 'suppressions':
        return _purge_tables(feature, db)

    rspamd = str(body.get("rspamd", "")).strip().lower()
    if rspamd not in ("remove", "keep"):
        raise HTTPException(status_code=400, detail='Say what happens to the Rspamd blocks: "rspamd": "remove" or "keep".')
    from .suppressions import _run_on_worker_loop, _clear_managed_section, MapUnavailable, _map_error
    from ..services.rspamd_map_lock import MapBusyError, map_write_lock
    transition = body.get("transition") or None

    def still_off():
        return not settings.is_feature_enabled(feature)

    try:
        with map_write_lock():
            if not still_off():
                raise HTTPException(status_code=400, detail=f"Feature '{feature}' is currently enabled. Disable it first.")
            if rspamd == "remove":
                _run_on_worker_loop(lambda worker_db: _clear_managed_section(
                    worker_db, 'remove', str(transition) if transition else None))
            return _purge_tables(feature, db, still_off)
    except (MapUnavailable, MapBusyError, MailcowAPIError) as e:
        raise _map_error(e)


def _purge_tables(feature: str, db: Session, still_off=None):
    from ..services.feature_data import purge_feature
    try:
        deleted = purge_feature(db, feature, still_off=still_off)
    except Exception as e:
        logger.error(f"Failed to purge data for feature '{feature}': {e}")
        raise HTTPException(status_code=500, detail="Could not delete the feature data. Check the application logs before trying again.")
    tables = {k: v for k, v in deleted.items() if not k.startswith('system_settings:')}
    total = sum(tables.values())
    logger.info(f"Purged data for feature '{feature}': {deleted} (total {total} rows)")
    return {"feature": feature, "tables_purged": tables, "total_rows_deleted": total}


@router.post("/settings/import-from-env", responses=documented(m.SettingsImported, errors={403: None, 500: None}))
def import_settings_from_env(db: Session = Depends(get_db)):
    """
    Import current effective configuration (defaults + ENV + existing DB) into DB.
    Only allowed when SETTINGS_EDIT_VIA_UI_ENABLED is true.
    Use this to migrate from ENV to DB so you can later remove ENV vars.
    Returns env_locked_keys: keys where ENV is set and overrides DB.
    """
    if not settings.edit_settings_via_ui_enabled:
        raise HTTPException(status_code=403, detail="Settings editing is off. Set SETTINGS_EDIT_VIA_UI_ENABLED=true in the environment to enable it.")
    with _LIST_TRANSITION_LOCK, settings_reload_lock:
        current = build_settings(db)
        overrides = {key: getattr(current, key) for key in EDITABLE_SETTING_KEYS if hasattr(current, key)}
        save_config_overrides_to_db(db, overrides)
        reload_settings(db)
    mailcow_api.reload_config()
    oauth2_client.reload_config()
    reschedule_interval_jobs()
    return {
        "message": "Settings copied from the environment to the database.",
        "settings_edit_via_ui_enabled": True,
        "settings_migrated": True,
        "configuration": _effective_config_for_editable(settings),
        "env_locked_keys": sorted(get_env_locked_keys()),
    }


# async def here would block the event loop for the whole 10-30 s connection test.
@router.post("/settings/test/smtp", responses=documented(m.ConnectionTest, description="The test's outcome and its steps; a failed test is still 200"))
def test_smtp():
    """Test SMTP connection with detailed logging"""
    result = test_smtp_connection()
    return result

@router.post("/settings/test/imap", responses=documented(m.ConnectionTest, description="The test's outcome and its steps; a failed test is still 200"))
def test_imap():
    """Test IMAP connection with detailed logging"""
    result = test_imap_connection()
    return result

@router.post("/settings/imap/folders", responses=documented(m.ImapFolderList, description="The stored IMAP account's folders; a failure is still 200, with error and message"))
def list_imap_folders_endpoint():
    """List the folders of the stored IMAP account, to choose which ones the report import reads"""
    return list_imap_folders()

@router.get("/settings/health", responses=documented(m.DetailedHealthResponse, description="healthy, or unhealthy when the database could not be read"))
def get_health_detailed(db: Session = Depends(get_db)):
    """
    Detailed health check with timing information
    """
    from datetime import timedelta
    try:
        start_time = datetime.now(timezone.utc)
        db.execute(text("SELECT 1"))
        db_response_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
        
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
            "error": "Unable to load settings status. Check the application logs."
        }

async def validate_maxmind_license() -> Dict[str, Any]:
    license_key = settings.maxmind_license_key
    
    if not license_key:
        result = {"configured": False, "valid": False, "error": None}
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
    
    return result


def _persist_maxmind_validation_worker(result: Dict[str, Any]) -> None:
    with get_db_context() as db:
        save_maxmind_validation_status(db, result)



def _precise_utc(value):
    if not value:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@router.get("/settings/geoip/status", responses=documented(m.GeoipStatus, errors={500: None}))
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
    
    jobs_status = get_job_status()
    geoip_job = jobs_status.get('update_geoip', {})
    
    return {
        "configured": is_license_configured(),
        "db_valid": get_geoip_db_valid(),
        "databases": geoip_status,
        "job_status": geoip_job.get('status', 'idle'),
        "job_error": geoip_job.get('error'),
        "job_last_run": _precise_utc(geoip_job.get('last_run')),
    }


@router.post("/settings/geoip/download", dependencies=[Depends(leader.require_leader)], responses=documented(m.Started, description="The download started in the background; poll GET /api/settings/geoip/status", errors={400: None, 503: None}))
def trigger_geoip_download(background_tasks: BackgroundTasks):
    """
    Trigger GeoIP database download in background.
    Called by the setup modal when credentials are valid but DB files are missing.
    Returns immediately; use GET /settings/geoip/status to poll progress.
    """
    if not is_license_configured():
        raise HTTPException(status_code=400, detail="Add a MaxMind account ID and license key in Settings > MaxMind before downloading.")
    
    logger.info("Manual GeoIP download triggered from setup modal")
    from ..scheduler import update_geoip_database
    background_tasks.add_task(update_geoip_database)
    return {"status": "started", "message": "GeoIP download started in background"}


@router.post("/settings/maxmind/validate", responses=documented(m.LicenseCheck, errors={500: None}))
async def validate_maxmind_license_endpoint():
    """
    Validate MaxMind license key on-demand.
    Called when the user clicks 'Validate License' in settings.
    Persists the result to DB.
    """
    result = await validate_maxmind_license()
    await asyncio.to_thread(_persist_maxmind_validation_worker, result)
    return result


_CREDENTIAL_CHECKS = {
    "mailcow_rw_key": {
        "configured": lambda: mailcow_api.has_rw_key,
        "fingerprint": lambda: credential_fingerprint(settings.mailcow_url, settings.mailcow_api_key_rw),
        "check": lambda: mailcow_api.check_rw_key(),
    },
    "rspamd_password": {
        "configured": lambda: settings.is_rspamd_configured,
        "fingerprint": lambda: credential_fingerprint(settings.mailcow_url, settings.rspamd_url, settings.rspamd_password),
        "check": lambda: mailcow_api.check_rspamd_password(),
    },
}


def _credential_status(db: Session, name: str) -> Optional[Dict[str, Any]]:
    check = _CREDENTIAL_CHECKS[name]
    if not check["configured"]():
        return {"configured": False, "valid": False, "error": None}
    return get_credential_check_status(db, name, check["fingerprint"]())


def _persist_credential_status_worker(name: str, result: Dict[str, Any], fingerprint: str) -> None:
    with get_db_context() as db:
        save_credential_check_status(db, name, result, fingerprint)


async def _validate_credential(name: str) -> Dict[str, Any]:
    check = _CREDENTIAL_CHECKS[name]
    fingerprint = check["fingerprint"]()
    result = await check["check"]()
    current = await asyncio.to_thread(_persist_if_current, name, result, fingerprint)
    if not current:
        return {**result, "stale": True}
    return result


_CREDENTIAL_SAVE_LOCK = threading.Lock()


def _persist_if_current(name: str, result: Dict[str, Any], fingerprint: str) -> bool:
    with _CREDENTIAL_SAVE_LOCK:
        if _CREDENTIAL_CHECKS[name]["fingerprint"]() != fingerprint:
            return False
        if result["configured"]:
            _persist_credential_status_worker(name, result, fingerprint)
        return True


@router.post("/settings/mailcow/rw-key/validate", responses=documented(m.CredentialCheck, errors={500: None}))
async def validate_mailcow_rw_key_endpoint():
    """
    Check that mailcow accepts the Read-Write API key for writes, changing nothing.
    Called after the key or URL is saved, and when the user clicks 'Validate'.
    Persists the result to DB.
    """
    return await _validate_credential("mailcow_rw_key")


@router.post("/settings/rspamd/password/validate", responses=documented(m.CredentialCheck, errors={500: None}))
async def validate_rspamd_password_endpoint():
    """
    Check that Rspamd accepts the password, the way its web UI logs in.
    Called after the password or the Rspamd or mailcow URL is saved, and when
    the user clicks 'Validate'. Persists the result to DB.
    """
    return await _validate_credential("rspamd_password")


@router.post("/settings/geoip/validate", responses=documented(m.GeoipValidationResponse, description="The result; valid false with error when the City file is missing", errors={500: None}))
def validate_geoip_db():
    """
    Validate GeoIP database integrity by running test IP lookups.
    Called by the setup modal after download completes.
    """
    from ..services.geoip_service import validate_geoip_database, reload_geoip_readers, get_geoip_db_valid
    
    geoip_status = get_geoip_status()
    if not geoip_status.get('City', {}).get('available'):
        return {
            "valid": False,
            "city_ok": False,
            "asn_ok": False,
            "error": "The City database is missing. Download the GeoIP databases again."
        }
    
    reload_geoip_readers()
    checked = validate_geoip_database()

    return {
        "valid": get_geoip_db_valid() is True,
        "city_ok": checked['city_ok'],
        "asn_ok": checked['asn_ok'],
        "db_valid": get_geoip_db_valid(),
    }


def _restore_job_status(status_key: str, previous: dict, mark: dict) -> None:
    statuses = get_job_status()
    if statuses.get(status_key) is not mark:
        return
    if previous:
        statuses[status_key] = dict(previous)
    else:
        statuses[status_key] = {'last_run': None, 'status': 'idle', 'error': None}


@router.post("/settings/jobs/{job_name}/run", dependencies=[Depends(leader.require_leader)], responses=documented(m.JobStarted, description="The job started in the background", errors={404: None, 409: None, 503: None}))
async def trigger_job(job_name: str, background_tasks: BackgroundTasks):
    """
    Manually trigger a background job.
    
    Supported jobs:
    - fetch_logs: Fetch logs from mailcow API
    - complete_correlations: Link Postfix logs to messages
    - update_final_status: Update final status for correlations
    - expire_correlations: Mark old incomplete correlations as expired
    - correlate_dovecot: Attach the Dovecot delivery outcome to messages
    - cleanup_logs: Remove old logs
    - cleanup_dmarc_reports: Remove old DMARC/TLS reports
    - check_app_version: Check for app updates
    - check_credentials: Check the Read-Write API key and the Rspamd password
    - dns_check: Validate DNS records for all domains
    - sync_local_domains: Sync domains from mailcow API
    - dmarc_imap_sync: Import DMARC reports from the IMAP mailbox
    - update_geoip: Update GeoIP databases
    - mailbox_stats: Fetch mailbox statistics
    - alias_stats: Sync alias data
    - blacklist_check: Check server IP against blacklists
    - fetch_raw_logs: Fetch raw logs from mailcow services
    - cleanup_raw_logs: Remove raw logs older than retention period
    """
    from ..scheduler import (
        fetch_all_logs,
        complete_incomplete_correlations,
        update_final_status_for_correlations,
        expire_old_correlations,
        feature_data_sweep_job,
        trend_samples_job,
        correlate_dovecot_logs,
        cleanup_old_logs,
        cleanup_old_dmarc_reports,
        check_app_version_update,
        check_credentials_job,
        check_all_domains_dns_background,
        sync_local_domains,
        dmarc_imap_sync_job,
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
        cleanup_deferred_queue_job,
        anomaly_detection_job,
        smtp_abuse_job,
        run_protection_rules,
        update_eas_devices,
        cleanup_eas_devices
    )
    from ..raw_logs_worker import fetch_raw_service_logs, cleanup_raw_service_logs
    
    job_mapping = {
        'fetch_logs': ('fetch_logs', fetch_all_logs, False),
        'complete_correlations': ('complete_correlations', complete_incomplete_correlations, False),
        'update_final_status': ('update_final_status', update_final_status_for_correlations, False),
        'expire_correlations': ('expire_correlations', expire_old_correlations, False),
        'feature_data_sweep': ('feature_data_sweep', feature_data_sweep_job, False),
        'trend_samples': ('trend_samples', trend_samples_job, False),
        'correlate_dovecot': ('correlate_dovecot', correlate_dovecot_logs, False),
        'cleanup_logs': ('cleanup_logs', cleanup_old_logs, False),
        'cleanup_dmarc_reports': ('cleanup_dmarc_reports', cleanup_old_dmarc_reports, False),
        'check_app_version': ('check_app_version', check_app_version_update, False),
        'check_credentials': ('check_credentials', check_credentials_job, False),
        'dns_check': ('dns_check', check_all_domains_dns_background, False),
        'sync_local_domains': ('sync_local_domains', sync_local_domains, False),
        'dmarc_imap_sync': ('dmarc_imap_sync', dmarc_imap_sync_job, False),
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
        'anomaly_detection': ('anomaly_detection', anomaly_detection_job, False),
        'smtp_abuse': ('smtp_abuse', smtp_abuse_job, False),
        'protection_rules': ('protection_rules', run_protection_rules, False),
        'eas_devices': ('eas_devices', update_eas_devices, False),
        'cleanup_eas_devices': ('cleanup_eas_devices', cleanup_eas_devices, False),
        'fetch_raw_logs': ('fetch_raw_logs', fetch_raw_service_logs, True),
        'cleanup_raw_logs': ('cleanup_raw_logs', cleanup_raw_service_logs, True),
    }
    
    if job_name not in job_mapping:
        raise HTTPException(status_code=404, detail=f"Unknown job: {job_name}")

    reason = _job_cannot_run(job_name)
    if reason:
        raise HTTPException(status_code=409, detail=f"The job cannot run. {reason}.")

    status_key, job_func, self_managing = job_mapping[job_name]
    
    if self_managing:
        from ..raw_logs_worker import get_raw_logs_job_status
        current_status = get_raw_logs_job_status().get(status_key, {})
    else:
        current_status = get_job_status().get(status_key, {})
    if current_status.get('status') == 'running':
        raise HTTPException(status_code=409, detail=f"Job {job_name} is already running")
    if job_name == 'blacklist_check':
        from ..scheduler import blacklist_check_admits
        if not blacklist_check_admits():
            raise HTTPException(status_code=409, detail="A blocklist check is already running. Try again when it is done.")
    previous = dict(current_status)

    mark = None
    if not self_managing:
        mark = update_job_status(status_key, 'running')

    async def run_job_wrapper():
        try:
            if asyncio.iscoroutinefunction(job_func):
                result = await job_func()
            else:
                result = await run_in_threadpool(job_func)
            if (not self_managing and result not in (JOB_SKIPPED, JOB_STATUS_SET)
                    and get_job_status().get(status_key) is mark):
                update_job_status(status_key, 'success')
            elif not self_managing and result == JOB_SKIPPED and job_name == 'blacklist_check':
                _restore_job_status(status_key, previous, mark)
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
