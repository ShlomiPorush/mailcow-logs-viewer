"""
Configuration management using Pydantic Settings
"""
import os
from pydantic_settings import BaseSettings
from pydantic import Field, validator, field_validator, model_validator
from typing import List, Optional, Any, Dict
import logging

logger = logging.getLogger(__name__)

_cached_active_domains: Optional[List[str]] = None

# Database-only keys: not editable from UI (must stay in ENV).
_DB_ONLY_KEYS = frozenset({"postgres_host", "postgres_port", "postgres_user", "postgres_password", "postgres_db"})
# Flag that controls UI editing; only read from ENV, not stored in DB.
# Name avoids "settings_" prefix to prevent Pydantic protected namespace warning.
_EDIT_VIA_UI_FLAG_KEY = "edit_settings_via_ui_enabled"

ALL_RAW_LOG_SERVICES = [
    'acme', 'api', 'autodiscover', 'dovecot', 'netfilter',
    'postfix', 'ratelimited', 'rspamd-history', 'sogo', 'watchdog'
]

class Settings(BaseSettings):
    """Application settings"""
    
    mailcow_url: str = Field(..., description="mailcow instance URL")
    mailcow_api_key: str = Field(..., description="mailcow API key (Read-Only)")
    mailcow_api_key_rw: Optional[str] = Field(
        default=None,
        description="mailcow API key (Read-Write) for edit operations"
    )
    mailcow_api_timeout: int = Field(default=30, description="API request timeout in seconds")
    mailcow_api_verify_ssl: bool = Field(
        default=True,
        description="Verify SSL certificates when connecting to mailcow API (set to false for development with self-signed certificates)"
    )
    
    # Blacklist Configuration
    blacklist_emails: str = Field(
        default="",
        description="Comma-separated list of email addresses to hide from logs"
    )
    
    # Fetch Configuration
    fetch_interval: int = Field(default=60, description="Seconds between log fetches")
    fetch_count_postfix: int = Field(
        default=2000, 
        description="Postfix logs to fetch per request"
    )
    fetch_count_rspamd: int = Field(
        default=500, 
        description="Rspamd logs to fetch per request"
    )
    fetch_count_netfilter: int = Field(
        default=500, 
        description="Netfilter logs to fetch per request"
    )
    retention_days: int = Field(default=7, description="Days to keep logs")
    
    # Correlation Configuration
    max_correlation_age_minutes: int = Field(
        default=10,
        description="Stop searching for correlations older than this (minutes)"
    )
    correlation_check_interval: int = Field(
        default=120,
        description="Seconds between correlation completion checks"
    )
    
    # Database Configuration
    postgres_host: str = Field(default="db", description="PostgreSQL host")
    postgres_port: int = Field(default=5432, description="PostgreSQL port")
    postgres_user: str = Field(..., description="PostgreSQL username")
    postgres_password: str = Field(..., description="PostgreSQL password")
    postgres_db: str = Field(..., description="PostgreSQL database name")
    
    # Application Configuration
    app_port: int = Field(default=8080, description="Application port")
    log_level: str = Field(
        default="WARNING",
        description="Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL"
    )
    tz: str = Field(
        default="UTC",
        description="Timezone"
    )
    app_title: str = Field(default="mailcow Logs Viewer", description="Application title")
    app_logo_url: str = Field(default="", description="Application logo URL (optional)")
    
    # Settings UI: allow editing config from web UI (overrides stored in DB). ENV only; default False.
    # Field name avoids "settings_" prefix (Pydantic protected namespace).
    edit_settings_via_ui_enabled: bool = Field(
        default=False,
        env="SETTINGS_EDIT_VIA_UI_ENABLED",
        description="Allow editing app settings from the web UI; overrides stored in DB"
    )

    @model_validator(mode="after")
    def _apply_edit_via_ui_from_env(self) -> "Settings":
        """Force-read SETTINGS_EDIT_VIA_UI_ENABLED from os.environ (Docker/env_file sometimes not picked by Pydantic)."""
        v = os.environ.get("SETTINGS_EDIT_VIA_UI_ENABLED", "").strip().lower()
        if v in ("true", "1", "yes"):
            object.__setattr__(self, "edit_settings_via_ui_enabled", True)
        return self
    
    # Advanced Configuration
    debug: bool = Field(default=False, description="Debug mode")
    max_search_results: int = Field(default=1000, description="Max search results")
    csv_export_limit: int = Field(default=10000, description="CSV export row limit")
    scheduler_workers: int = Field(default=4, description="Background job workers")
    
    @field_validator('scheduler_workers', mode='after')
    @classmethod
    def clamp_scheduler_workers(cls, v: int) -> int:
        """Clamp scheduler_workers to 1-64 for thread pool size."""
        if v < 1:
            return 1
        if v > 64:
            return 64
        return v
    
    # Authentication Configuration
    auth_enabled: bool = Field(
        default=False,
        description="Enable authentication (deprecated, use BASIC_AUTH_ENABLED and/or OAUTH2_ENABLED)"
    )
    basic_auth_enabled: bool = Field(
        default=False,
        description="Enable basic HTTP authentication"
    )
    auth_username: str = Field(
        default="admin",
        description="Basic auth username"
    )
    auth_password: str = Field(
        default="",
        description="Basic auth password (required if basic_auth_enabled=True)"
    )
    
    # OAuth2/OIDC Authentication Configuration
    oauth2_enabled: bool = Field(
        default=False,
        description="Enable OAuth2/OIDC authentication"
    )
    oauth2_provider_name: str = Field(
        default="OAuth2 Provider",
        description="Display name for the OAuth2 provider (e.g., 'Mailcow', 'Keycloak')"
    )
    oauth2_issuer_url: Optional[str] = Field(
        default=None,
        description="OAuth2/OIDC issuer URL for discovery (e.g., https://mail.example.com or https://keycloak.example.com/realms/myrealm)"
    )
    oauth2_authorization_url: Optional[str] = Field(
        default=None,
        description="OAuth2 authorization endpoint (auto-discovered if issuer_url provided)"
    )
    oauth2_token_url: Optional[str] = Field(
        default=None,
        description="OAuth2 token endpoint (auto-discovered if issuer_url provided)"
    )
    oauth2_userinfo_url: Optional[str] = Field(
        default=None,
        description="OAuth2 UserInfo endpoint (auto-discovered if issuer_url provided)"
    )
    oauth2_client_id: Optional[str] = Field(
        default=None,
        description="OAuth2 client ID from provider"
    )
    oauth2_client_secret: Optional[str] = Field(
        default=None,
        description="OAuth2 client secret from provider"
    )
    oauth2_redirect_uri: Optional[str] = Field(
        default=None,
        description="OAuth2 redirect URI callback (e.g., https://your-app.example.com/api/auth/callback)"
    )
    oauth2_scopes: str = Field(
        default="openid profile email",
        description="OAuth2 scopes to request"
    )
    oauth2_use_oidc_discovery: bool = Field(
        default=True,
        description="Enable OIDC discovery (uses .well-known/openid-configuration)"
    )
    session_secret_key: str = Field(
        default="",
        description="Secret key for signing session cookies (required if oauth2_enabled=True)"
    )
    session_expiry_hours: int = Field(
        default=24,
        description="Session expiration time in hours"
    )

    # DMARC configuration
    dmarc_retention_days: int = Field(
        default=60,
        env="DMARC_RETENTION_DAYS"
    )
    
    dmarc_manual_upload_enabled: bool = Field(
        default=True,
        env='DMARC_MANUAL_UPLOAD_ENABLED',
        description='Allow manual upload of DMARC reports via UI'
    )

    dmarc_allow_report_delete: bool = Field(
        default=False,
        env='DMARC_ALLOW_REPORT_DELETE',
        description='Allow deleting DMARC/TLS reports from the UI'
    )

    # DMARC IMAP Configuration
    dmarc_imap_enabled: bool = Field(
        default=False,
        env='DMARC_IMAP_ENABLED',
        description='Enable automatic DMARC report import from IMAP'
    )

    dmarc_imap_host: Optional[str] = Field(
        default=None,
        env='DMARC_IMAP_HOST',
        description='IMAP server hostname (e.g., imap.gmail.com)'
    )

    dmarc_imap_port: Optional[int] = Field(
        default=993,
        env='DMARC_IMAP_PORT',
        description='IMAP server port (993 for SSL, 143 for non-SSL)'
    )

    dmarc_imap_use_ssl: bool = Field(
        default=True,
        env='DMARC_IMAP_USE_SSL',
        description='Use SSL/TLS for IMAP connection'
    )

    dmarc_imap_user: Optional[str] = Field(
        default=None,
        env='DMARC_IMAP_USER',
        description='IMAP username (email address)'
    )

    dmarc_imap_password: Optional[str] = Field(
        default=None,
        env='DMARC_IMAP_PASSWORD',
        description='IMAP password'
    )

    dmarc_imap_folder: str = Field(
        default='INBOX',
        env='DMARC_IMAP_FOLDER',
        description='IMAP folder to scan for DMARC reports'
    )

    dmarc_imap_delete_after: bool = Field(
        default=True,
        env='DMARC_IMAP_DELETE_AFTER',
        description='Delete emails after successful processing'
    )

    dmarc_imap_interval: Optional[int] = Field(
        default=3600,
        env='DMARC_IMAP_INTERVAL',
        description='Interval between IMAP syncs in seconds (default: 3600 = 1 hour)'
    )

    dmarc_imap_run_on_startup: bool = Field(
        default=True,
        env='DMARC_IMAP_RUN_ON_STARTUP',
        description='Run IMAP sync once on application startup'
    )

    dmarc_imap_batch_size: int = Field(
        default=10,
        env='DMARC_IMAP_BATCH_SIZE',
        description='Number of emails to process per batch (prevents memory issues with large mailboxes)'
    )

    dmarc_error_email: Optional[str] = Field(
        default=None,
        env='DMARC_ERROR_EMAIL',
        description='Email address for DMARC error notifications (defaults to ADMIN_EMAIL if not set)'
    )

    # MaxMind Configuration
    maxmind_account_id: Optional[str] = Field(
        default=None,
        env='MAXMIND_ACCOUNT_ID',
        description='MaxMind Account ID for GeoIP database downloads'
    )

    maxmind_license_key: Optional[str] = Field(
        default=None,
        env='MAXMIND_LICENSE_KEY',
        description='MaxMind License Key for GeoIP database downloads'
    )

    # SMTP Configuration
    smtp_enabled: bool = Field(
        default=False,
        env='SMTP_ENABLED',
        description='Enable SMTP for sending notifications'
    )

    smtp_host: Optional[str] = Field(
        default=None,
        env='SMTP_HOST',
        description='SMTP server hostname'
    )

    smtp_port: Optional[int] = Field(
        default=587,
        env='SMTP_PORT',
        description='SMTP server port (587 for TLS, 465 for SSL, 25 for plain)'
    )

    smtp_use_tls: bool = Field(
        default=False,
        env='SMTP_USE_TLS',
        description='Use STARTTLS for SMTP connection'
    )

    smtp_use_ssl: bool = Field(
        default=False,
        env='SMTP_USE_SSL',
        description='Use Implicit SSL/TLS for SMTP connection (usually port 465)'
    )

    smtp_user: Optional[str] = Field(
        default=None,
        env='SMTP_USER',
        description='SMTP username (usually email address)'
    )

    smtp_password: Optional[str] = Field(
        default=None,
        env='SMTP_PASSWORD',
        description='SMTP password'
    )

    smtp_from: Optional[str] = Field(
        default=None,
        env='SMTP_FROM',
        description='From address for emails (defaults to SMTP user if not set)'
    )

    smtp_relay_mode: bool = Field(
        default=False,
        env='SMTP_RELAY_MODE',
        description='Relay mode - send emails without authentication (for local relay servers)'
    )

    # Global Admin Email
    admin_email: Optional[str] = Field(
        default=None,
        env='ADMIN_EMAIL',
        description='Administrator email for system notifications'
    )

    # Blacklist Alert Email
    blacklist_alert_email: Optional[str] = Field(
        default=None,
        env='BLACKLIST_ALERT_EMAIL',
        description='Email address for blacklist alerts (defaults to ADMIN_EMAIL if not set)'
    )

    # Weekly Summary Report
    enable_weekly_summary: bool = Field(
        default=True,
        env='ENABLE_WEEKLY_SUMMARY',
        description='Enable weekly summary email report'
    )

    # Raw Logs Viewer Configuration
    raw_logs_enabled: bool = Field(
        default=True,
        env='RAW_LOGS_ENABLED',
        description='Enable background raw log collection for the Logs page'
    )
    raw_logs_fetch_interval: int = Field(
        default=20,
        env='RAW_LOGS_FETCH_INTERVAL',
        description='Seconds between raw log fetch cycles'
    )
    raw_logs_fetch_count: int = Field(
        default=1000,
        env='RAW_LOGS_FETCH_COUNT',
        description='Number of logs to fetch per service per cycle'
    )
    raw_logs_retention_days: int = Field(
        default=2,
        env='RAW_LOGS_RETENTION_DAYS',
        description='Days to keep raw logs before cleanup'
    )
    raw_logs_services: str = Field(
        default='acme,api,autodiscover,dovecot,netfilter,postfix,ratelimited,rspamd-history,sogo,watchdog',
        env='RAW_LOGS_SERVICES',
        description='Comma-separated list of mailcow services to collect raw logs from'
    )

    @field_validator('smtp_port', 'dmarc_imap_port', 'dmarc_imap_interval', mode='before')
    @classmethod
    def empty_str_to_none(cls, v):
        """Convert empty string to None so default value is used"""
        if v == '':
            return None
        return v

    @validator('mailcow_url')
    def validate_mailcow_url(cls, v):
        """Ensure URL doesn't end with slash"""
        return v.rstrip('/')
    
    @validator('log_level')
    def validate_log_level(cls, v):
        """Ensure valid log level"""
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        v = v.upper()
        if v not in valid_levels:
            logger.warning(f"Invalid log level '{v}', using WARNING")
            return 'WARNING'
        return v
    
    @property
    def is_basic_auth_enabled(self) -> bool:
        """Check if Basic Auth is enabled (with backward compatibility)"""
        # For backward compatibility: if AUTH_ENABLED is set, use it
        if self.auth_enabled:
            return True
        return self.basic_auth_enabled
    
    @property
    def is_oauth2_enabled(self) -> bool:
        """Check if OAuth2 is enabled"""
        return self.oauth2_enabled
    
    @property
    def is_authentication_enabled(self) -> bool:
        """Check if any authentication is enabled"""
        return self.is_basic_auth_enabled or self.is_oauth2_enabled
    
    @property
    def local_domains_list(self) -> List[str]:
        """Get active domains from mailcow API cache"""
        global _cached_active_domains
        if _cached_active_domains is None:
            logger.warning("Local domains cache not yet populated")
            return []
        return _cached_active_domains
    
    @property
    def blacklist_emails_list(self) -> List[str]:
        """Parse blacklisted emails into a list"""
        if not self.blacklist_emails:
            return []
        return [e.strip().lower() for e in self.blacklist_emails.split(',') if e.strip()]
    
    @property
    def raw_logs_services_list(self) -> List[str]:
        """Parse raw_logs_services into a list of enabled service names.
        Supports 'all' as a shortcut for all services."""
        if not self.raw_logs_services:
            return []
        val = self.raw_logs_services.strip()
        if val.lower() == 'all':
            return list(ALL_RAW_LOG_SERVICES)
        return [s.strip().lower() for s in val.split(',') if s.strip()]
    
    @property
    def notification_smtp_configured(self) -> bool:
        """Check if SMTP is properly configured for notifications"""
        if self.smtp_relay_mode:
            # Relay mode - only need host and from address
            return (
                self.smtp_enabled and 
                self.smtp_host is not None and
                self.smtp_from is not None
            )
        else:
            # Standard mode - need authentication
            return (
                self.smtp_enabled and 
                self.smtp_host is not None and 
                self.smtp_user is not None and 
                self.smtp_password is not None
            )

    @property
    def database_url(self) -> str:
        """Construct PostgreSQL connection URL"""
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )
    
    @property
    def async_database_url(self) -> str:
        """Construct async PostgreSQL connection URL"""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )
    
    class Config:
        env_file = ".env"
        case_sensitive = False


def _get_editable_setting_keys() -> frozenset:
    """All Settings field names that are editable from UI (excludes DB keys, UI-edit flag, and deprecated/legacy fields)."""
    excluded = _DB_ONLY_KEYS | {_EDIT_VIA_UI_FLAG_KEY, "auth_enabled", "tz", "app_port"}  # auth_enabled deprecated, tz legacy, app_port is Docker-level
    keys = set(Settings.model_fields.keys()) - excluded
    return frozenset(keys)


def _get_field_annotations() -> Dict[str, Any]:
    """Field name -> annotation for type coercion when loading from DB."""
    return {k: v.annotation for k, v in Settings.model_fields.items()}


EDITABLE_SETTING_KEYS = _get_editable_setting_keys()


def _is_env_key_set(key: str) -> bool:
    """Check if a settings key has a corresponding ENV variable actually set in os.environ.

    Checks both the default name (field name uppercased, pydantic-settings default)
    and any explicit ``env=`` name from Field().

    Covers every field in Settings:
    - Fields without explicit env= (e.g. ``mailcow_url``) → checks ``MAILCOW_URL``
    - Fields with explicit env= (e.g. ``smtp_host``, env='SMTP_HOST') → checks ``SMTP_HOST``
    - Fields where field name uppercased == explicit env (most cases) → deduped via set
    """
    # Always check the uppercased field name (pydantic-settings default behaviour)
    env_names = {key.upper()}
    # Also check explicit env= parameter from Field() if present
    # In pydantic-settings 2.x the env= kwarg is stored in json_schema_extra
    field_info = Settings.model_fields.get(key)
    if field_info:
        jse = getattr(field_info, 'json_schema_extra', None)
        if isinstance(jse, dict):
            explicit_env = jse.get('env')
            if explicit_env:
                env_names.add(explicit_env.upper() if isinstance(explicit_env, str) else str(explicit_env).upper())
    return any(name in os.environ for name in env_names)


def get_env_locked_keys() -> frozenset:
    """Return the set of editable keys where an ENV variable is explicitly set.

    These keys are "locked" — their effective value comes from ENV, not DB.
    """
    return frozenset(k for k in EDITABLE_SETTING_KEYS if _is_env_key_set(k))


def build_settings(db: Optional[Any] = None) -> Settings:
    """
    Build effective Settings: defaults -> DB -> ENV overrides.

    Priority order (later wins):
      1. Application defaults
      2. DB overrides  (when SETTINGS_EDIT_VIA_UI_ENABLED and db given)
      3. ENV variables (always win when explicitly set)

    This prevents lockout: if a user makes a mistake in the UI (e.g. wrong
    OIDC URL or bad auth password), they can fix it by setting the correct
    value in ENV / docker-compose.yml and restarting.
    """
    base = Settings()  # loads defaults + ENV
    if not base.edit_settings_via_ui_enabled or db is None:
        return base
    try:
        from .services.settings_store import get_config_overrides_from_db
        overrides = get_config_overrides_from_db(db, _get_field_annotations())
        if not overrides:
            return base
        # Only apply DB overrides for editable keys where ENV is NOT explicitly set.
        # When an ENV variable is set, it takes precedence over the DB value.
        env_locked = get_env_locked_keys()
        allowed = {k: v for k, v in overrides.items()
                   if k in EDITABLE_SETTING_KEYS and k not in env_locked}
        if not allowed:
            return base
        merged = base.model_copy(update=allowed)
        # model_copy skips validators. Apply them manually on affected fields.
        # (We can't use Settings.model_validate() because BaseSettings re-reads ENV on init)
        try:
            if 'mailcow_url' in allowed:
                object.__setattr__(merged, 'mailcow_url', merged.mailcow_url.rstrip('/'))
            if 'log_level' in allowed:
                v = merged.log_level.upper()
                if v not in ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'):
                    v = 'WARNING'
                object.__setattr__(merged, 'log_level', v)
            if 'scheduler_workers' in allowed:
                object.__setattr__(merged, 'scheduler_workers', max(1, min(64, merged.scheduler_workers)))
        except Exception as e:
            logger.warning("Post-validation of DB overrides failed: %s", e)
        return merged
    except Exception as e:
        logger.warning("Could not load config overrides from DB: %s", e)
        return base


class SettingsWrapper:
    """Wrapper so that settings can be reloaded (e.g. after PUT) without changing import references."""
    _inner: Settings

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


_settings_wrapper = SettingsWrapper()
_settings_wrapper._inner = Settings()
settings = _settings_wrapper


def reload_settings(db: Optional[Any] = None) -> None:
    """Reload effective settings (e.g. after saving from UI). Updates the global settings wrapper."""
    global _settings_wrapper
    _settings_wrapper._inner = build_settings(db)
    # Re-apply log level to root logger (setup_logging ran at import time with the old level)
    root = logging.getLogger()
    root.setLevel(getattr(logging, _settings_wrapper.log_level, logging.WARNING))


def setup_logging():
    """Configure application logging"""
    root = logging.getLogger()
    
    # Remove ALL existing handlers
    for handler in root.handlers[:]:
        root.removeHandler(handler)
    
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    
    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))
    root.addHandler(console_handler)
    
    # File Handler (logs to /app/data/container.log)
    try:
        from logging.handlers import RotatingFileHandler
        import os
        
        # Ensure directory exists
        log_dir = "/app/data"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            
        log_file = os.path.join(log_dir, "container.log")
        
        # Rotate logs: 5MB max size, keep 3 backup files
        file_handler = RotatingFileHandler(
            log_file, 
            maxBytes=5*1024*1024, 
            backupCount=3,
            encoding='utf-8'
        )
        file_handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))
        root.addHandler(file_handler)
        
    except Exception as e:
        print(f"Failed to setup file logging: {e}")
    
    root.setLevel(getattr(logging, settings.log_level))
    
    # Set levels for third-party libraries
    logging.getLogger('httpx').setLevel(logging.ERROR)
    logging.getLogger('httpcore').setLevel(logging.ERROR)
    logging.getLogger('urllib3').setLevel(logging.ERROR)
    logging.getLogger('asyncio').setLevel(logging.ERROR)
    logging.getLogger('apscheduler').setLevel(logging.WARNING)
    logging.getLogger('watchfiles').setLevel(logging.WARNING)
    
    if settings.debug:
        root.warning("Debug mode is enabled")
        
    root.info("Logging initialized (Console + File)")


# Initialize logging
setup_logging()


def set_cached_active_domains(domains: List[str]) -> None:
    """Set the cached active domains list"""
    global _cached_active_domains
    _cached_active_domains = domains
    logger.info(f"Cached {len(domains)} active domains from mailcow API")


def get_cached_active_domains() -> Optional[List[str]]:
    """Get the cached active domains list"""
    global _cached_active_domains
    return _cached_active_domains if _cached_active_domains else []