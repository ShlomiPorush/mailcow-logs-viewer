"""
Configuration management using Pydantic Settings
"""
from pydantic_settings import BaseSettings
from pydantic import Field, validator, field_validator
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)

_cached_active_domains: Optional[List[str]] = None

class Settings(BaseSettings):
    """Application settings"""
    
    mailcow_url: str = Field(..., description="Mailcow instance URL")
    mailcow_api_key: str = Field(..., description="Mailcow API key")
    mailcow_api_timeout: int = Field(default=30, description="API request timeout in seconds")
    
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
    app_title: str = Field(default="Mailcow Logs Viewer", description="Application title")
    app_logo_url: str = Field(default="", description="Application logo URL (optional)")
    
    # Advanced Configuration
    debug: bool = Field(default=False, description="Debug mode")
    max_search_results: int = Field(default=1000, description="Max search results")
    csv_export_limit: int = Field(default=10000, description="CSV export row limit")
    scheduler_workers: int = Field(default=4, description="Background job workers")
    
    # Authentication Configuration
    auth_enabled: bool = Field(
        default=False,
        description="Enable basic authentication"
    )
    auth_username: str = Field(
        default="admin",
        description="Basic auth username"
    )
    auth_password: str = Field(
        default="",
        description="Basic auth password (required if auth_enabled=True)"
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
    def local_domains_list(self) -> List[str]:
        """Get active domains from Mailcow API cache"""
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


settings = Settings()


def setup_logging():
    """Configure application logging"""
    root = logging.getLogger()
    
    # Remove ALL existing handlers
    for handler in root.handlers[:]:
        root.removeHandler(handler)
    
    log_format = '%(levelname)s - %(message)s'
    
    logging.basicConfig(
        level=getattr(logging, settings.log_level),
        format=log_format,
        force=True
    )
    
    logging.getLogger('httpx').setLevel(logging.ERROR)
    logging.getLogger('httpcore').setLevel(logging.ERROR)
    logging.getLogger('urllib3').setLevel(logging.ERROR)
    logging.getLogger('asyncio').setLevel(logging.ERROR)
    logging.getLogger('apscheduler').setLevel(logging.WARNING)
    
    if settings.debug:
        logger.warning("Debug mode is enabled")


# Initialize logging
setup_logging()


def set_cached_active_domains(domains: List[str]) -> None:
    """Set the cached active domains list"""
    global _cached_active_domains
    _cached_active_domains = domains
    logger.info(f"Cached {len(domains)} active domains from Mailcow API")


def get_cached_active_domains() -> Optional[List[str]]:
    """Get the cached active domains list"""
    global _cached_active_domains
    return _cached_active_domains if _cached_active_domains else []