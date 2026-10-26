"""What the Mailbox stats, Devices and weekly summary calls return
(routers/mailbox_stats.py, devices.py, reporting.py).

The mailbox statistics answer 200 when the database read fails: then only
`error` and empty or zero figures are sent, as the Failed models say.
"""
from typing import Any, Dict, List, Optional, Union

from pydantic import Field

from . import Fixed
from .security import MonitoredHost

TIME = "UTC, ISO 8601 with Z"
FAILED = "The figures could not be read: what to do"


# ---------------------------------------------------------------- mailbox statistics

class MessageCounts(Fixed):
    """Messages of one address in the range, one per message (its most successful delivery)."""
    sent_total: int
    sent_delivered: int
    sent_bounced: int
    sent_rejected: int
    sent_deferred: int
    sent_expired: int
    sent_failed: int = Field(description="Bounced or rejected")
    received_total: int
    total_messages: int
    failure_rate: float = Field(description="Percent of sent that failed")
    direction_inbound: int
    direction_outbound: int
    direction_internal: int


class AliasStats(MessageCounts):
    alias_address: str
    active: Optional[bool]
    is_catch_all: Optional[bool]
    is_domain_alias: bool = Field(None, description="The mailbox's address on an alias domain")


class Activity(Fixed):
    sent: List[int] = Field(description="Per slot of activity_buckets")
    received: List[int]


class MailboxStats(Fixed):
    id: int
    username: str
    domain: str
    name: Optional[str]
    active: Optional[bool]
    quota: float = Field(description="Bytes; 0 for no quota")
    quota_formatted: str
    quota_used: float = Field(description="Bytes")
    quota_used_formatted: str
    percent_in_use: float
    messages_in_mailbox: int
    last_imap_login: Optional[str] = Field(description=TIME)
    last_pop3_login: Optional[str] = Field(description=TIME)
    last_smtp_login: Optional[str] = Field(description=TIME)
    rl_value: Optional[int] = Field(description="Its rate limit, messages per frame; null for none")
    rl_frame: Optional[str]
    attributes: Dict[str, Any] = Field(description="mailcow's mailbox attributes, as mailcow reports them")
    mailbox_counts: MessageCounts = Field(description="The mailbox's own address")
    aliases: List[AliasStats]
    alias_count: int
    combined_sent: int = Field(description="The mailbox and its aliases")
    combined_received: int
    combined_total: int
    combined_failed: int
    combined_failure_rate: float
    combined_internal: int
    combined_delivered: int
    combined_inbound: int
    combined_outbound: int
    created: Optional[str] = Field(description=TIME)
    modified: Optional[str] = Field(description=TIME)
    activity: Activity = Field(None, description="Messages per slot over the range; on the page's rows")


class MailboxStatsPage(Fixed):
    """Mailboxes with their messages in the range, sorted and paged."""
    total: int
    page: int
    page_size: int
    total_pages: int
    date_range: str
    start_date: Optional[str] = Field(description=TIME)
    end_date: Optional[str] = Field(description=TIME)
    mailboxes: List[MailboxStats]
    activity_unit: str = Field(description="hour or day")
    activity_buckets: List[str] = Field(description="An hour as UTC with Z, a day of the app time zone as "
                                                    "YYYY-MM-DD")


class MailboxStatsPageFailed(Fixed):
    error: str = Field(description=FAILED)
    total: int
    mailboxes: List[Any] = Field(description="Empty")


class MailboxSummary(Fixed):
    """Every mailbox and alias together over the range."""
    total_sent: int
    total_received: int
    total_messages: int
    sent_failed: int
    failure_rate: float
    date_range: str
    start_date: Optional[str] = Field(description=TIME)
    end_date: Optional[str] = Field(description=TIME)
    last_update: Optional[str] = Field(description="The newest mailbox sync, " + TIME)


class MailboxSummaryFailed(Fixed):
    error: str = Field(description=FAILED)
    total_mailboxes: int = Field(description="0")


class MailboxDomain(Fixed):
    domain: str
    mailbox_count: int
    alias_of: str = Field(None, description="An alias domain: the domain whose mailboxes it shows")


class MailboxDomainsResponse(Fixed):
    domains: List[MailboxDomain]
    error: str = Field(None, description=FAILED)


class MailboxRefreshResponse(Fixed):
    """When the mailboxes and aliases were last synced from mailcow."""
    last_mailbox_update: Optional[str] = Field(None, description=TIME)
    last_alias_update: Optional[str] = Field(None, description=TIME)
    error: str = Field(None, description=FAILED + "; then the times are not sent")


MailboxStatsResponse = Union[MailboxStatsPage, MailboxStatsPageFailed]
MailboxSummaryResponse = Union[MailboxSummary, MailboxSummaryFailed]


# ---------------------------------------------------------------- devices

class Device(Fixed):
    """A phone, tablet or Outlook client that syncs over ActiveSync."""
    country_code: Optional[str] = Field(description="Of the last IP, when GeoIP is on")
    country_name: Optional[str]
    city: Optional[str]
    asn: Optional[str]
    asn_org: Optional[str]
    client: Optional[str] = Field(description="The client, read from the device id and type")
    model: Optional[str]
    id: int
    username: str
    device_id: str
    device_type: Optional[str]
    last_ip: Optional[str]
    last_command: Optional[str]
    last_status: Optional[int] = Field(description="The HTTP status of its last request")
    first_seen: Optional[str] = Field(description=TIME)
    last_seen: Optional[str] = Field(description=TIME)


class DeviceSummary(Fixed):
    devices: int
    users: int
    recent: int = Field(description="Seen in the last recent_hours")
    new: int = Field(description="First seen in the last new_days")
    stale: int = Field(description="Not seen for stale_days")


class DeviceThresholds(Fixed):
    recent_hours: int
    new_days: int
    stale_days: int


class DevicesResponse(Fixed):
    """The recorded devices, filtered, sorted and paged, with the page's figures."""
    items: List[Device]
    geoip: bool
    total: int
    page: int
    per_page: int
    total_pages: int
    summary: DeviceSummary = Field(description="Every device, whatever the filters")
    device_types: List[str]
    thresholds: DeviceThresholds
    retention_days: int = Field(description="Devices not seen for this long are removed; 0 keeps them")
    last_run: Optional[str] = Field(description="The recording job's last run, " + TIME)
    last_status: Optional[str] = Field(description="Its outcome")


# ---------------------------------------------------------------- mailcow's counts and storage
# Also the answers of GET /api/status/mailcow-info and /api/status/storage

class TotalActive(Fixed):
    total: int
    active: int


class MailcowInfo(Fixed):
    """How many domains, mailboxes and aliases mailcow has, and how many are active."""
    domains: TotalActive
    mailboxes: TotalActive
    aliases: TotalActive


class StorageStatus(Fixed):
    """The mail storage, as mailcow reports it; unknown and 0 when it reports nothing."""
    disk: Any = Field(description="The volume")
    used: Any = Field(description="Such as 1.2G")
    total: Any
    used_percent: Any = Field(description="Such as 12%")


# ---------------------------------------------------------------- weekly summary

class SummaryBlocklists(Fixed):
    status: str = Field(description="listed or clean")
    listed_count: int = Field(description="Monitored addresses that are listed")
    total_hosts: int
    hosts: List[MonitoredHost]


class DnsIssue(Fixed):
    domain: Optional[str]
    issues: List[str] = Field(description="Such as 'SPF: ...', 'DKIM: ...', 'DMARC: ...'")


class Count(Fixed):
    count: int


class SystemSummaryResponse(Fixed):
    """The weekly summary's data: the last 7 days."""
    timestamp: str = Field(description=TIME)
    traffic: MailboxSummaryResponse
    system: MailcowInfo
    storage: StorageStatus
    blacklist: SummaryBlocklists
    top_failures: List[MailboxStats] = Field(description="Up to 5 mailboxes with the most failed mail")
    dns_issues: List[DnsIssue] = Field(description="Active domains with an SPF, DKIM or DMARC problem")
    queue: Count = Field(description="Messages in mailcow's queue; 0 when mailcow did not answer")
    quarantine: Count


class SummaryEmailSkipped(Fixed):
    status: str = Field(description="skipped")
    reason: str


class SummaryEmailQueued(Fixed):
    status: str = Field(description="queued: it is built and sent in the background")
    message: str


SummaryEmailResponse = Union[SummaryEmailQueued, SummaryEmailSkipped]
