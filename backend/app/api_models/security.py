"""What the Security alerts, Protection rules, SMTP abuse, Rate limits and Blacklist
calls return (routers/security_alerts.py, protection.py, smtp_abuse.py,
rate_limits.py, blacklist.py)."""
from typing import Any, Dict, List, Optional, Union

from pydantic import ConfigDict, Field

from . import Fixed
from .logs import ProtectionCatch

TIME = "UTC, ISO 8601 with Z"


# ---------------------------------------------------------------- security alerts

class SecurityAlert(Fixed):
    id: int
    alert_type: str = Field(description="Such as volume_spike, auth_failure_burst or smtp_abuse_block")
    severity: Optional[str] = Field(description="info, warning or critical")
    subject: Optional[str] = Field(description="The mailbox or user name the alert is about")
    title: str
    detail: Optional[str]
    metric_value: Optional[float] = Field(description="What was seen")
    baseline_value: Optional[float] = Field(description="What was expected")
    acknowledged: Optional[bool]
    created_at: Optional[str] = Field(description=TIME)


class SecurityAlertsResponse(Fixed):
    """Security alerts, newest first, and the open ones."""
    enabled: bool = Field(description="Anomaly detection is on")
    alerts: List[SecurityAlert]
    unacknowledged_count: int
    unacknowledged_critical: int
    unacknowledged_ids: List[int] = Field(description="Every open alert, newest first (at most 10000): send them "
                                                      "to acknowledge-all to dismiss exactly what this list showed")


class AcknowledgeResponse(Fixed):
    status: str = Field(description="success")
    acknowledged: int = Field(description="Alerts this call acknowledged; one acknowledged already is left as it is")
    ids: List[int]
    receipt: Optional[str] = Field(description="Undoes exactly this change; null when nothing changed")


class UndoAcknowledgeResponse(Fixed):
    status: str = Field(description="success")
    restored: int
    ids: List[int]


class ActivityBucket(Fixed):
    start: Optional[str] = Field(description=TIME)
    count: int
    partial: bool = Field(description="The last bucket, which ends now")


class NameCount(Fixed):
    name: str
    count: int


class AroundSentMail(Fixed):
    """Around a volume spike or an SMTP block: the mailbox's sent mail."""
    from_: str = Field(alias="from")
    to: str
    total: int
    recipient_domains: List[NameCount]
    results: List[NameCount]
    subjects: List[NameCount]

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class AroundLogins(Fixed):
    """Around an authentication failure burst: the failed logins."""
    from_: str = Field(alias="from")
    to: str
    total: int
    addresses: List[NameCount]
    address_count: int
    countries: List[NameCount]
    networks: List[NameCount]

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class AlertActivityResponse(Fixed):
    """The history behind an alert, per 15 minutes, and what happened around it."""
    alert: SecurityAlert
    bucket_minutes: int
    window_minutes: Optional[int] = Field(description="The window the alert counted in; null when not known")
    baseline_days: int
    buckets: List[ActivityBucket]
    data_end: str = Field(description="The end of the data: now, for a recent alert")
    around: Union[AroundSentMail, AroundLogins] = Field(description="From the check window before the alert to "
                                                                    "an hour after; from and to to the microsecond")


# ---------------------------------------------------------------- protection rules

class _Rule(Fixed):
    enabled: bool
    notify: bool


class _BanRule(_Rule):
    mode: str = Field(description="watch, or enforce (ban)")
    ban_hours: int = Field(description="0 is a permanent ban")


class TrapRule(_BanRule):
    names: List[str] = Field(description="Account names that do not exist; one try is caught")


class UnknownAccountsRule(_BanRule):
    threshold: int
    window_minutes: int


class RepeatOffenderRule(_BanRule):
    threshold: int
    window_days: int


class SubnetRule(_BanRule):
    threshold: int
    window_hours: int


class CountryRule(_BanRule):
    countries: List[str] = Field(description="Country codes")


class BreachRule(_Rule):
    failures: int
    window_minutes: int
    new_country: bool


class ProtectionRules(Fixed):
    """The rules as saving writes them: PUT checks and normalises every value."""
    trap: TrapRule
    unknown_accounts: UnknownAccountsRule
    repeat_offender: RepeatOffenderRule
    subnet: SubnetRule
    country: CountryRule
    breach: BreachRule = Field(description="Alerts only; it never bans")


class TrapSuggestion(Fixed):
    name: str = Field(description="An account name tried in the last week that does not exist")
    tries: int
    addresses: int


class CountrySuggestion(Fixed):
    code: str
    name: str
    tries: int = Field(description="Failed logins in the last week")


class ProtectionCapabilities(Fixed):
    can_ban: bool = Field(description="A Read-Write mailcow API key is set")
    geoip: bool
    raw_logs: bool = Field(description="Dovecot's raw logs are collected")


_STORED = ("The same keys as the rule in PUT's answer; each value as it is stored, so normally of that type, "
           "but a value written into the setting by hand is read back as it is")


class StoredRules(Fixed):
    """The rules as they are stored: the defaults, with what was saved over them."""
    trap: Dict[str, Any] = Field(description=_STORED)
    unknown_accounts: Dict[str, Any] = Field(description=_STORED)
    repeat_offender: Dict[str, Any] = Field(description=_STORED)
    subnet: Dict[str, Any] = Field(description=_STORED)
    country: Dict[str, Any] = Field(description=_STORED)
    breach: Dict[str, Any] = Field(description=_STORED)


class ProtectionRulesResponse(Fixed):
    rules: StoredRules
    trap_suggestions: List[TrapSuggestion]
    country_suggestions: List[CountrySuggestion]
    capabilities: ProtectionCapabilities


class SavedRulesResponse(Fixed):
    rules: ProtectionRules


class ProtectionHitsResponse(Fixed):
    hits: List[ProtectionCatch]
    counts: Dict[str, int] = Field(description="Catches by status, every one kept")


# ---------------------------------------------------------------- SMTP abuse

class AbuseMailbox(Fixed):
    email: str
    message_count: int = Field(description="Sent in the window")
    outbound_count: int = Field(description="The same as message_count")
    over_threshold: bool
    whitelisted: bool
    smtp_access: bool = Field(description="mailcow lets it send (true when mailcow could not be asked)")
    blocked_by_protection: bool


class AbuseStatusResponse(Fixed):
    enabled: bool
    rw_key_configured: bool
    threshold: int
    window_minutes: int
    unblock_grace_minutes: int
    revoke_app_passwords: bool
    mailboxes: List[AbuseMailbox] = Field(description="Most mail first")
    whitelist: List[str]


class WhitelistEntry(Fixed):
    email: str
    notes: Optional[str]
    active: bool


class WhitelistChange(Fixed):
    email: str
    active: bool


class WhitelistReplaced(Fixed):
    active: List[str]
    count: int


class BlockResult(Fixed):
    email: str
    smtp_access: bool
    app_passwords_revoked: int = Field(None, description="Block only")
    message_count: int = Field(None, description="Block only: sent in the window")


class AbuseAction(Fixed):
    email: str
    action: str = Field(description="blocked or unblocked")
    message_count: Optional[int]
    threshold: Optional[int]
    window_minutes: Optional[int]
    automatic: Optional[bool]
    operator: Optional[str]
    app_passwords_revoked: Optional[int]
    created_at: Optional[str] = Field(description=TIME)


# ---------------------------------------------------------------- rate limits

class RateLimitHit(Fixed):
    time: Optional[str] = Field(description=TIME)
    rcpt: str
    subject: str
    qid: str
    rl_hash: str = Field(description="The counter's hash, for a reset")


class RateLimitHitWithUser(RateLimitHit):
    user: str


class CurrentLimit(Fixed):
    value: int
    frame: Optional[str]


class RateLimitSender(Fixed):
    user: str
    events: int
    last_seen: Optional[str] = Field(description=TIME)
    last_rl_hash: Optional[str]
    current_limit: Optional[CurrentLimit] = Field(description="From the synced mailbox; null for no limit")
    recent: List[RateLimitHit] = Field(description="The newest few")
    last_reset: str = Field(None, description="When its counter was last reset from here, " + TIME)


class RateLimitBucket(Fixed):
    bucket: str = Field(description="An hour as UTC with Z, or a day of the app time zone as YYYY-MM-DD")
    count: int


class RateLimitEventsResponse(Fixed):
    """Every sender in the kept history that hit a rate limit, and the chart for the window."""
    hours: int = Field(description="The chart's window, narrowed to the kept history")
    windows: List[int] = Field(description="The windows offered, in hours")
    retention_days: int
    total_events: int = Field(description="In the window")
    window_senders: int
    by_sender: List[RateLimitSender] = Field(description="Every sender kept, most hits first")
    events: List[RateLimitHitWithUser] = Field(description="The newest hits")
    bucket: str = Field(description="hour or day")
    by_bucket: List[RateLimitBucket]


class SenderEventsResponse(Fixed):
    user: str
    total: int
    events: List[RateLimitHit] = Field(description="Newest first, capped")


class MailboxLimit(Fixed):
    username: str
    domain: Optional[str]
    rl_value: Optional[int]
    rl_frame: Optional[str]
    active: bool


class DomainLimit(Fixed):
    domain: str
    rl_value: Optional[int] = Field(description="null for no limit")
    rl_frame: Optional[str]


class RateLimitsResponse(Fixed):
    rw_key_configured: bool
    mailboxes: List[MailboxLimit]
    domains: List[DomainLimit] = Field(description="From mailcow")
    domains_error: Optional[str] = Field(description="Some domain limits could not be read from mailcow")


class MailboxLimitSet(Fixed):
    mailbox: str
    rl_value: Optional[int] = Field(description="null: no limit")
    rl_frame: Optional[str]
    mailcow_response: Any = Field(description="mailcow's answer")


class DomainLimitSet(Fixed):
    domain: str
    rl_value: Optional[int] = Field(description="null: no limit")
    rl_frame: Optional[str]
    mailcow_response: Any = Field(description="mailcow's answer")


class BulkLimitSet(Fixed):
    mailboxes_updated: int
    domains_updated: int
    skipped: List[str] = Field(description="Names this server does not know")
    value: int
    frame: str


class CounterReset(Fixed):
    rl_hash: str
    reset: bool
    mailcow_response: Any = Field(description="mailcow's answer, usually empty")


# ---------------------------------------------------------------- blacklist

class BlocklistResult(Fixed):
    """One blocklist's answer for an address, as the check stored it."""
    model_config = ConfigDict(extra="allow")
    name: str
    zone: str
    listed: bool
    status: str = Field(description="listed, clean, error or timeout")
    ignored: bool = Field(None, description="The admin ignores this list: it does not count")


class _CheckCounts(Fixed):
    total_blacklists: Optional[int]
    listed_count: Optional[int]
    status: Optional[str] = Field(description="listed, clean, error or unknown")
    results: List[BlocklistResult]
    ignored_listed_count: int = Field(None, description="Listings on ignored lists")


class MonitoredHost(_CheckCounts):
    hostname: str
    source: Optional[str]
    last_seen: Optional[str] = Field(description=TIME)
    has_data: bool
    total_blacklists: int = Field(None)
    listed_count: int = Field(None)
    results: List[BlocklistResult] = Field(None)
    checked_at: Optional[str] = Field(None, description=TIME)
    cache_valid: bool = Field(None, description="The check is recent enough to trust")


class MonitoredHostsResponse(Fixed):
    """Every monitored address with its latest check; empty when they cannot be read."""
    hosts: List[MonitoredHost]


class BlocklistCheck(_CheckCounts):
    server_ip: Optional[str]
    checked_at: Optional[str] = Field(description=TIME)
    clean_count: int
    error_count: int
    timeout_count: int
    error: str = Field(None, description="Only when the check could not run")


class CheckStarted(Fixed):
    status: str = Field(description="started")
    message: str


class CheckBusy(Fixed):
    status: str = Field(description="busy: a check is already running, nothing was started")
    message: str


class CheckProgress(Fixed):
    in_progress: bool
    current: int
    total: int
    current_blacklist: Optional[str]
    percent: int


class BlocklistConfig(Fixed):
    total_blacklists: int
    cache_ttl_hours: int
    cache_valid: bool
    last_check: Optional[str] = Field(description=TIME)
    server_ip: Optional[str]
    listed_count: Optional[int]
    status: Optional[str]


class SummaryHost(Fixed):
    hostname: Optional[str]
    source: Optional[str]
    status: str
    listed_count: int
    total_blacklists: Optional[int]
    checked_at: Optional[str] = Field(description=TIME)


class SummaryFigure(Fixed):
    value: Optional[float] = Field(description="Listed addresses; null when no check is fresh")
    of: float = Field(description="Monitored addresses")
    valid: bool


class BlocklistSummary(Fixed):
    """The dashboard's blocklist card: every monitored address's latest fresh check."""
    has_data: bool
    server_ip: Optional[str]
    status: str = Field(description="listed, error, clean or unknown")
    listed_count: int
    total_blacklists: int
    checked_at: Optional[str] = Field(description=TIME)
    hosts: List[SummaryHost]
    hosts_total: int
    hosts_listed: int
    figure: SummaryFigure


class IgnoredList(Fixed):
    name: str
    zone: str


class IgnoredListsResponse(Fixed):
    lists: List[IgnoredList]


class IgnoreChange(Fixed):
    zone: str
    name: str
    ignored: bool
