"""What the Settings calls return (routers/settings.py): the settings, the Status
page's information, the checks of credentials and connections, GeoIP, and the
manual job runs.

GET /api/settings/info and GET /api/settings/health answer 200 when the
database read fails: then `error` says so, as the Failed models show.
"""
from typing import Any, Dict, List, Optional, Union

from pydantic import Field

from . import Fixed
from .suppressions import RspamdMapError

TIME = "UTC, ISO 8601 with Z"
SETTINGS = ("One key per editable setting, named like its environment variable in lower case. "
            "A secret is ******** when set and empty when not")

# 403: UI editing is off ({detail}). An AI agent refused a route only people may use gets the agent
# gateway's {error, message} instead, which the API description covers for every call


# ---------------------------------------------------------------- shared parts

class CheckResult(Fixed):
    """The last check of a credential: MaxMind's license key, mailcow's Read-Write key or the Rspamd password."""
    configured: bool = Field(description="The credential is set")
    valid: bool
    error: Optional[str] = Field(description="Why it is not valid, such as rejected, read_only, redirected, "
                                             "connection or unexpected (Invalid, Connection error or Status "
                                             "<code> for MaxMind)")
    http_status: int = Field(None, description="Only when the server answered with an error")
    checked_at: Optional[str] = Field(None, description="When it was checked, " + TIME + "; missing until it "
                                                        "was stored")


class GeoipFile(Fixed):
    available: bool
    age_days: int = Field(description="-1 when the file is missing")
    size_mb: float
    last_modified: Optional[str] = Field(description=TIME)


class GeoipFiles(Fixed):
    """The GeoIP database files."""
    configured: bool = Field(description="The MaxMind Account ID and License Key are set")
    db_valid: Optional[bool] = Field(description="The files passed the test lookups; null when not checked yet")
    City: GeoipFile
    ASN: GeoipFile


class GeoipFileNotSet(Fixed):
    installed: bool = Field(description="false")
    version: Optional[str] = Field(description="null")
    last_updated: Optional[str] = Field(description="null")


class GeoipNotSet(Fixed):
    """Without MaxMind credentials."""
    City: GeoipFileNotSet
    ASN: GeoipFileNotSet


# ---------------------------------------------------------------- GET /settings/info

class InfoConfiguration(Fixed):
    """The settings in force, without secrets."""
    mailcow_url: str
    server_ip: Optional[str] = Field(description="The mail server's address, once read from mailcow")
    local_domains: List[str] = Field(description="The domains mailcow hosts")
    fetch_interval: int = Field(description="Seconds")
    fetch_count_postfix: int
    fetch_count_rspamd: int
    fetch_count_netfilter: int
    fetch_max_pages: int
    retention_days: int
    max_correlation_age_minutes: int
    correlation_check_interval: int = Field(description="Seconds")
    timezone: str = Field(description="The zone in use")
    date_format: str
    time_format: str
    app_title: str
    log_level: str
    blacklist_enabled: bool = Field(description="BLACKLIST_EMAILS has addresses")
    blacklist_count: int
    max_search_results: int
    csv_export_limit: int
    scheduler_workers: int
    rspamd_configured: bool = Field(description="The Rspamd password is set")
    database_version: Optional[str] = Field(description="PostgreSQL's version, such as 16.4")
    auth_enabled: bool
    basic_auth_enabled: bool
    oauth2_enabled: bool
    auth_username: Optional[str] = Field(description="null unless Basic Auth is on and the caller may read Settings")
    oauth2_provider_name: Optional[str] = Field(description="null unless OAuth2 is on")
    maxmind_status: Optional[CheckResult] = Field(description="The last license check; null when never checked")
    mailcow_rw_key_status: Optional[CheckResult] = Field(description="null when not checked since the key or "
                                                                     "the mailcow URL last changed")
    rspamd_password_status: Optional[CheckResult] = Field(description="null when not checked since the "
                                                                      "password or its address last changed")


class ImportState(Fixed):
    last_import: Optional[str] = Field(description="The newest line stored, " + TIME)
    last_fetch_run: Optional[str] = Field(description="The last fetch since the app started, " + TIME)
    total_entries: int
    oldest_entry: Optional[str] = Field(description=TIME)


class ImportStatus(Fixed):
    postfix: ImportState
    rspamd: ImportState
    netfilter: ImportState


class CorrelationStatus(Fixed):
    last_update: Optional[str] = Field(description=TIME)
    total: int
    complete: int
    incomplete: int
    expired: int
    completion_rate: float = Field(description="Percent complete; 0 when unknown")
    known: bool = Field(description="false when the figures could not be read")


class ClockParts(Fixed):
    """When a clock-time job runs, for the page to write in its own format."""
    hour: int
    minute: int
    weekday: Optional[str] = Field(description="Such as Monday; null for a daily job")
    zone: str = Field(description="The app time zone")


class BackgroundJob(Fixed):
    """One background job. The fields after `error` are sent only for the jobs they apply to."""
    description: str
    status: str = Field(description="idle, running, success, failed, disabled or unknown")
    last_run: Optional[str] = Field(description="Since the app started, " + TIME)
    error: Optional[str] = Field(description="The error of the last failed run")
    interval: str = Field(None, description="How often it runs, or why not, such as Disabled (feature off)")
    schedule: str = Field(None, description="When a clock-time job runs, or why not")
    clock: ClockParts = Field(None, description="A clock-time job that runs")
    enabled: bool = Field(None)
    feature_disabled: bool = Field(None, description="The feature it belongs to is off")
    disabled_reason: str = Field(None, description="Why it cannot run, unless its feature is off")
    settings_section: str = Field(None, description="The Settings section that changes that")
    pending_items: int = Field(None, description="The correlation jobs: items waiting")
    max_age: str = Field(None)
    expire_after: str = Field(None)
    retention: Optional[str] = Field(None, description="The job's retention setting; null while Devices is off")
    services: str = Field(None, description="fetch_raw_logs: the services collected, comma separated")


class BackgroundJobs(Fixed):
    """Every background job, by its ID (the job_name of POST /api/settings/jobs/{job_name}/run)."""
    fetch_logs: BackgroundJob
    complete_correlations: BackgroundJob
    update_final_status: BackgroundJob
    trend_samples: BackgroundJob
    feature_data_sweep: BackgroundJob
    expire_correlations: BackgroundJob
    correlate_dovecot: BackgroundJob
    cleanup_logs: BackgroundJob
    cleanup_dmarc_reports: BackgroundJob
    check_credentials: BackgroundJob
    check_app_version: BackgroundJob
    dns_check: BackgroundJob
    sync_local_domains: BackgroundJob
    dmarc_imap_sync: BackgroundJob
    update_geoip: BackgroundJob
    mailbox_stats: BackgroundJob
    alias_stats: BackgroundJob
    eas_devices: BackgroundJob
    cleanup_eas_devices: BackgroundJob
    blacklist_check: BackgroundJob
    sync_transports: BackgroundJob
    send_weekly_summary: BackgroundJob
    fetch_raw_logs: BackgroundJob
    cleanup_raw_logs: BackgroundJob
    detect_suppressions: BackgroundJob
    sync_suppressions: BackgroundJob
    expire_suppressions: BackgroundJob
    process_quarantine_rules: BackgroundJob
    cleanup_deferred_queue: BackgroundJob
    anomaly_detection: BackgroundJob
    smtp_abuse: BackgroundJob
    protection_rules: BackgroundJob


class SmtpConfiguration(Fixed):
    """The values after `enabled` are null while SMTP is off, except `configured`; host, port, user,
    from_address and admin_email are null for a caller who may not read Settings."""
    enabled: bool
    host: Optional[str]
    port: Optional[int]
    user: Optional[str]
    from_address: Optional[str]
    use_tls: Optional[bool]
    admin_email: Optional[str]
    configured: bool = Field(description="Notifications can be sent")


class DmarcConfiguration(Fixed):
    """The imap_* values are null while the IMAP import is off; host, user and folder are null for a
    caller who may not read Settings."""
    manual_upload_enabled: bool
    imap_sync_enabled: bool
    imap_host: Optional[str]
    imap_user: Optional[str]
    imap_folder: Optional[str]
    imap_delete_after: Optional[bool]
    imap_interval_minutes: Optional[float]
    smtp_configured: bool


class GeoipConfiguration(Fixed):
    enabled: bool = Field(description="The MaxMind Account ID and License Key are set")
    db_valid: Optional[bool] = Field(description="null while not enabled or not checked yet")
    databases: Union[GeoipFiles, GeoipNotSet]


class IncompleteCorrelation(Fixed):
    message_id: Optional[str] = Field(description="Cut to 50 characters and ...")
    queue_id: Optional[str]
    sender: Optional[str]
    recipient: Optional[str]
    created_at: Optional[str] = Field(description=TIME)
    age_minutes: Optional[int]


class SettingsInfo(Fixed):
    """Configuration, import, linking and background job state, for the Status and Settings pages."""
    settings_edit_via_ui_enabled: bool
    configuration: InfoConfiguration
    import_status: ImportStatus
    correlation_status: CorrelationStatus
    background_jobs: BackgroundJobs
    smtp_configuration: SmtpConfiguration
    dmarc_configuration: DmarcConfiguration
    geoip_configuration: GeoipConfiguration
    recent_incomplete_correlations: List[IncompleteCorrelation] = Field(
        description="The 5 newest, without excluded addresses; empty for an AI agent without View for Messages")
    raw_logs_required: Dict[str, List[str]] = Field(description="Raw log services other pages read, with those "
                                                                "pages; they are always collected")
    editable_config: Dict[str, Any] = Field(None, description="While UI editing is on, for a caller who may read Settings. " + SETTINGS)
    default_config: Dict[str, Any] = Field(None, description="While UI editing is on: the defaults, by the same "
                                                             "keys; null for a required setting, empty for a "
                                                             "secret")
    settings_migrated: bool = Field(None, description="While UI editing is on: settings are stored in the "
                                                      "database")


class SettingsInfoFailed(Fixed):
    """The information could not be read."""
    error: str = Field(description="What to do")
    settings_edit_via_ui_enabled: bool
    configuration: Dict[str, Any] = Field(description="Empty")
    import_status: Dict[str, Any] = Field(description="Empty")
    correlation_status: Dict[str, Any] = Field(description="Empty")
    background_jobs: Dict[str, Any] = Field(description="Empty")


SettingsInfoResponse = Union[SettingsInfo, SettingsInfoFailed]


# ---------------------------------------------------------------- editing the settings

class EditableSettings(Fixed):
    """The editable settings, for the Settings page."""
    settings_edit_via_ui_enabled: bool
    settings_migrated: bool = Field(description="Settings are stored in the database")
    configuration: Dict[str, Any] = Field(description=SETTINGS)
    default_config: Dict[str, Any] = Field(description="The defaults, by the same keys; null for a required "
                                                       "setting, empty for a secret")
    env_locked_keys: List[str] = Field(description="Settings an environment variable sets; it wins over the "
                                                   "stored value. Empty while UI editing is off")
    legacy_auth_enabled: bool = Field(description="The old AUTH_ENABLED turns Basic Auth on")


class SettingsUnchanged(Fixed):
    """The body held no editable change: nothing was saved."""
    settings_edit_via_ui_enabled: bool = Field(description="true")
    settings_migrated: bool = Field(description="true")
    configuration: Dict[str, Any] = Field(description=SETTINGS)


class SettingsSaved(Fixed):
    """The settings were saved and are in force."""
    settings_edit_via_ui_enabled: bool = Field(description="true")
    settings_migrated: bool = Field(description="true")
    configuration: Dict[str, Any] = Field(description=SETTINGS)
    rspamd_off_transition: Optional[str] = Field(description="A token when this save turned Suppressions or "
                                                             "Sync with Rspamd off, for removing the app's "
                                                             "Rspamd blocks; else null")
    feature_data_errors: Dict[str, str] = Field(None, description="Only when deleting a turned-off feature's data "
                                                                  "failed: the part and its error. The sweep "
                                                                  "tries again")
    mailcow_rw_key_changed: bool = Field(description="The Read-Write key is set and it, or the mailcow URL, "
                                                     "changed: check it")
    rspamd_password_changed: bool = Field(description="The Rspamd password is set and it, or its address, "
                                                      "changed: check it")


SettingsSaveResponse = Union[SettingsSaved, SettingsUnchanged]


class SettingsImported(Fixed):
    """Every setting in force was stored in the database."""
    message: str
    settings_edit_via_ui_enabled: bool = Field(description="true")
    settings_migrated: bool = Field(description="true")
    configuration: Dict[str, Any] = Field(description=SETTINGS)
    env_locked_keys: List[str] = Field(description="Settings an environment variable sets; it wins over the "
                                                   "stored value")


class FeatureDataPurged(Fixed):
    feature: str
    tables_purged: Dict[str, int] = Field(description="Rows deleted, by table")
    total_rows_deleted: int


# The same map error as the suppression calls give
PurgeMapError = RspamdMapError


# ---------------------------------------------------------------- checks

class ConnectionTest(Fixed):
    success: bool
    logs: List[str] = Field(description="The steps, in order")


class HealthDatabase(Fixed):
    status: str = Field(description="connected")
    response_time_ms: float


class HealthLastMinutes(Fixed):
    postfix_imported: int
    rspamd_imported: int
    correlations_created: int


class HealthActivity(Fixed):
    last_5_minutes: HealthLastMinutes


class DetailedHealth(Fixed):
    status: str = Field(description="healthy")
    timestamp: str = Field(description=TIME)
    database: HealthDatabase
    recent_activity: HealthActivity


class DetailedHealthFailed(Fixed):
    """The database could not be read."""
    status: str = Field(description="unhealthy")
    timestamp: str = Field(description=TIME)
    error: str


DetailedHealthResponse = Union[DetailedHealth, DetailedHealthFailed]


class LicenseCheck(Fixed):
    """MaxMind's answer about the license key; stored for maxmind_status."""
    configured: bool = Field(description="The license key is set")
    valid: bool
    error: Optional[str] = Field(description="Invalid, Connection error or Status <code>")


class CredentialCheck(Fixed):
    """Whether mailcow or Rspamd accepts the credential, changing nothing; stored unless it is not set."""
    configured: bool = Field(description="The credential is set")
    valid: bool
    error: Optional[str] = Field(description="rejected, read_only (the key), redirected (Rspamd), connection or "
                                             "unexpected")
    http_status: int = Field(None, description="Only when the server answered with an error")
    stale: bool = Field(None, description="true: the credential changed while it was checked, so this result "
                                          "was not stored")


# ---------------------------------------------------------------- GeoIP and jobs

class GeoipStatus(Fixed):
    configured: bool = Field(description="The MaxMind Account ID and License Key are set")
    db_valid: Optional[bool] = Field(description="The files passed the test lookups; null when not checked yet")
    databases: GeoipFiles
    job_status: str = Field(description="The last Update GeoIP run: idle, running, success or failed")
    job_error: Optional[str]
    job_last_run: Optional[str] = Field(description=TIME)


class Started(Fixed):
    """The work started in the background."""
    status: str = Field(description="started")
    message: str


class GeoipValidation(Fixed):
    valid: bool = Field(description="The City lookup worked")
    city_ok: bool
    asn_ok: bool
    db_valid: Optional[bool] = Field(description="The stored state after reloading the files")


class GeoipValidationMissing(Fixed):
    """The City file is missing: nothing was checked."""
    valid: bool = Field(description="false")
    city_ok: bool = Field(description="false")
    asn_ok: bool = Field(description="false")
    error: str


GeoipValidationResponse = Union[GeoipValidation, GeoipValidationMissing]


class JobStarted(Fixed):
    status: str = Field(description="started")
    job: str
    message: str
