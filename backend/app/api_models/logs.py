"""What the log, Security, Fail2ban, queue and quarantine calls return (routers/logs.py)."""
from typing import Any, Dict, List, Optional, Union

from pydantic import ConfigDict, Field

from . import Fixed

TIME = "UTC, ISO 8601 with Z"
MAILCOW = "As mailcow reports it; the keys depend on the mailcow version"


class Page(Fixed):
    total: int
    page: int
    limit: int
    pages: int


# ---------------------------------------------------------------- Postfix

class PostfixQueueRow(Fixed):
    """One queue: its lines combined, the latest status and time."""
    id: int = Field(description="The first line's id")
    time: Optional[str] = Field(description="The latest line, " + TIME)
    program: Optional[str]
    priority: Optional[str]
    message: Optional[str] = Field(description="The latest line")
    queue_id: str
    message_id: Optional[str]
    sender: Optional[str]
    recipient: Optional[str] = Field(description="The first recipient seen")
    status: Optional[str] = Field(description="The latest status, such as sent, deferred, bounced or rejected")
    relay: Optional[str]
    delay: Optional[float]
    dsn: Optional[str]
    correlation_key: Optional[str]


class PostfixLogsResponse(Page):
    """Postfix lines grouped by queue, newest activity first."""
    data: List[PostfixQueueRow]


class PostfixLine(Fixed):
    id: int
    time: Optional[str] = Field(description=TIME)
    program: Optional[str]
    priority: Optional[str]
    message: Optional[str]
    queue_id: Optional[str]
    message_id: Optional[str]
    sender: Optional[str]
    recipient: Optional[str]
    status: Optional[str]
    relay: Optional[str]
    delay: Optional[float]
    dsn: Optional[str]


class QueueRspamd(Fixed):
    score: Optional[float]
    required_score: Optional[float]
    action: Optional[str]
    symbols: Optional[Dict[str, Any]] = Field(description="The symbols as Rspamd reported them, by name")
    is_spam: Optional[bool]
    direction: Optional[str]
    subject: Optional[str]


class PostfixByQueueResponse(Fixed):
    """Every Postfix line of one queue, with Rspamd's scan when the message has one."""
    queue_id: str
    correlation_key: Optional[str]
    rspamd: Optional[QueueRspamd]
    logs: List[PostfixLine]


# ---------------------------------------------------------------- Rspamd

class RspamdRow(Fixed):
    id: int
    time: Optional[str] = Field(description=TIME)
    message_id: Optional[str]
    subject: Optional[str]
    size: Optional[int]
    sender_smtp: Optional[str]
    recipients_smtp: Any = Field(description="Normally a list of addresses; stored as Rspamd sent it")
    score: Optional[float]
    required_score: Optional[float]
    action: Optional[str]
    direction: Optional[str]
    ip: Optional[str]
    is_spam: Optional[bool]
    has_auth: Optional[bool]
    user: Optional[str]
    symbols: Optional[Dict[str, Any]] = Field(description="The symbols as Rspamd reported them, by name")
    correlation_key: Optional[str]


class RspamdLogsResponse(Page):
    """Rspamd scans, newest first."""
    data: List[RspamdRow]


# ---------------------------------------------------------------- Netfilter

class NetfilterCountry(Fixed):
    code: str
    name: Optional[str]


class NetfilterRow(Fixed):
    id: int
    time: Optional[str] = Field(description=TIME)
    priority: Optional[str]
    message: Optional[str]
    ip: Optional[str]
    rule_id: Optional[int] = Field(description="The netfilter rule matched; null on ban, unban and info lines")
    attempts_left: Optional[int]
    username: Optional[str]
    auth_method: Optional[str]
    action: Optional[str] = Field(description="Such as warning, ban, unban or info")
    country_code: Optional[str]
    country_name: Optional[str]
    city: Optional[str]
    asn: Optional[str]
    asn_org: Optional[str]


class NetfilterLogsResponse(Page):
    """Netfilter lines, newest first."""
    data: List[NetfilterRow]


class CountryStat(Fixed):
    country_code: str
    country_name: str
    ban: int
    unban: int
    warning: int = Field(description="Attempts: lines where netfilter matched a rule")
    total: int
    addresses: int = Field(description="Addresses that tried")


class ByCountryResponse(Fixed):
    """The 10 countries with the most attempts."""
    days: int
    since: Optional[str] = Field(description="The oldest line kept, when the logs are shorter than the period")
    data: List[CountryStat]


class NetworkStat(Fixed):
    asn: str
    asn_org: str
    attempts: int
    addresses: int


class ByNetworkResponse(Fixed):
    """The 8 networks (by ASN) with the most attempts."""
    days: int
    since: Optional[str] = Field(description="The oldest line kept, when the logs are shorter than the period")
    data: List[NetworkStat]


class OverviewSource(Fixed):
    ip: str
    attempts: int
    failed_logins: int
    last_seen: Optional[str] = Field(description=TIME)
    services: List[str]
    usernames: List[str] = Field(description="Up to 5")
    country_code: Optional[str]
    country_name: Optional[str]
    city: Optional[str]
    asn_org: Optional[str]
    last_action: Optional[str] = Field(description="The last Fail2ban action: ban or unban")


class OverviewLogin(Fixed):
    time: Optional[str] = Field(description=TIME)
    ip: Optional[str]
    username: Optional[str]
    service: Optional[str]
    country_code: Optional[str]
    country_name: Optional[str]


class NetfilterOverviewResponse(Fixed):
    """Attempts over the last hours by source address."""
    hours: int
    attempts: int
    failed_logins: int
    source_count: int
    sources: List[OverviewSource] = Field(description="Up to 50, most attempts first")
    latest: List[OverviewLogin] = Field(description="The 20 latest failed logins")


# ---------------------------------------------------------------- Security page lists

class ProtectionCatch(Fixed):
    """A protection rule's catch."""
    id: int
    ip: str
    rule: str
    mode: str = Field(description="watch or enforce")
    status: str = Field(description="Such as watching, pending, alert, banned, dismissed or ended")
    reason: Optional[str]
    usernames: List[str]
    attempts: int
    country_code: Optional[str]
    country_name: Optional[str]
    first_seen: Optional[str] = Field(description=TIME)
    last_seen: Optional[str] = Field(description=TIME)
    ended_at: Optional[str] = Field(description=TIME)
    ban_hours: Optional[int]
    banned_at: Optional[str] = Field(description=TIME)
    expires_at: Optional[str] = Field(description=TIME)
    owned: bool = Field(description="The app placed the ban")
    error: Optional[str]


class SecurityAddress(Fixed):
    ip: str = Field(description="An address, or a network banned as a whole by Fail2ban")
    state: str = Field(description="allow, banned, deny, review or quiet")
    tries: int = Field(description="Failed logins")
    attempts: int
    users: List[str]
    services: List[str]
    hits: List[ProtectionCatch] = Field(description="Open protection rule catches")
    country: str
    country_code: str
    city: str
    org: str
    last_seen: Optional[str] = Field(description=TIME)
    f2b: Optional[Dict[str, Any]] = Field(description="Fail2ban's ban, " + MAILCOW)
    listed_as: Optional[str] = Field(description="The allowlist or denylist entry that holds it")
    network_size: Optional[int] = Field(description="A network row: how many addresses the ban covers")
    network_range: Optional[List[str]] = Field(description="A network row: its first and last address")
    banned_through: Optional[str] = Field(description="An address banned through its network's ban")


class ListCounts(Fixed):
    review: int
    banned: int


class CountryPanel(Fixed):
    country_name: str
    country_code: str
    addresses: int
    attempts: int
    review: int
    banned: int


class NetworkPanel(Fixed):
    asn_org: str
    addresses: int
    attempts: int
    review: int
    banned: int


class SecurityAddressesResponse(Fixed):
    """One page of the Security page's To review or Banned list."""
    list: str = Field(description="review or banned")
    country: Optional[str]
    network: Optional[str]
    total: int = Field(description="Addresses on this list for the country, network and search given")
    counts: ListCounts = Field(description="Both lists, for the country, network and search given")
    all_counts: ListCounts = Field(description="Both lists, everything")
    items: List[SecurityAddress]
    next: Optional[str] = Field(description="Pass as `after` for the next page; null on the last")
    days: int
    countries: List[CountryPanel] = Field(description="Up to 10, most attempts first")
    networks: List[NetworkPanel] = Field(description="Up to 8, most attempts first")
    since: Optional[str] = Field(description="The oldest line kept, when the logs are shorter than the period")
    fail2ban_known: bool = Field(description="mailcow answered: the allowlist and denylist are known")


# ---------------------------------------------------------------- Fail2ban

class LegacyEntry(Fixed):
    list: str = Field(description="whitelist or blacklist")
    entry: str = Field(description="The entry as written, such as 2001:db8::1/32")
    address: str = Field(description="The single address it was meant to be")
    network: str = Field(description="The network mailcow reads it as")


class Fail2banResponse(Fixed):
    """mailcow's Fail2ban settings and bans, as mailcow reports them, and the entries to repair."""
    model_config = ConfigDict(extra="allow")
    legacy_entries: List[LegacyEntry] = Field(description="Allowlist and denylist entries an earlier version wrote "
                                                           "as a /32 network")


class ActionResult(Fixed):
    """The outcome of a change sent to mailcow. A refusal by mailcow is status error, not an HTTP error."""
    status: str = Field(description="success or error")
    msg: Union[str, List[Any]] = Field(description="A sentence, or mailcow's message as a list: a code and its values")
    already: bool = Field(None, description="The address was on the list already")
    networks: List[str] = Field(None, description="Unban: the bans lifted")
    raw: Any = Field(None, description="mailcow's answer, when it was not the usual list")


class ListsChangedDetail(Fixed):
    code: str = Field(description="lists_changed")
    message: str = Field(description="What to do instead")


class ListsChanged(Fixed):
    """The allowlist or denylist sent is not the current one."""
    detail: ListsChangedDetail


class RwStatusResponse(Fixed):
    rw_configured: bool = Field(description="A Read-Write mailcow API key is set")


class GeoIpResponse(Fixed):
    """What the GeoIP databases know about an address."""
    available: bool = Field(description="false when no GeoIP database is installed; then nothing else is sent")
    ip: str = Field(None)
    country_code: Optional[str] = Field(None)
    country_name: Optional[str] = Field(None)
    city: Optional[str] = Field(None)
    asn: Optional[str] = Field(None)
    asn_org: Optional[str] = Field(None)


# ---------------------------------------------------------------- queue and quarantine

class QueueResponse(Fixed):
    """mailcow's mail queue, newest first."""
    total: int
    data: List[Dict[str, Any]] = Field(description="Queue items " + MAILCOW.lower() + ", such as queue_id, "
                                                   "queue_name, arrival_time, message_size, sender and recipients")


class QuarantineResponse(Fixed):
    """mailcow's quarantine, newest first."""
    total: int
    data: List[Dict[str, Any]] = Field(description="Quarantined messages " + MAILCOW.lower() + "; created is "
                                                   "rewritten as " + TIME)


class QuarantineDetails(Fixed):
    """One quarantined message as mailcow's quarantine view shows it."""
    model_config = ConfigDict(extra="allow")


# mailcow's view may also answer an empty list or null, passed on as they are
QuarantineDetailsResponse = Optional[Union[QuarantineDetails, List[Any]]]


# ---------------------------------------------------------------- the compact message form

class CompactRspamd(Fixed):
    score: Optional[float]
    required_score: Optional[float]
    action: Optional[str]
    symbols: Optional[Dict[str, Any]]
    is_spam: Optional[bool]
    direction: Optional[str]
    ip: Optional[str]


class CompactPostfixLine(Fixed):
    time: Optional[str] = Field(description=TIME)
    program: Optional[str]
    message: Optional[str]
    status: Optional[str]
    relay: Optional[str]
    delay: Optional[float]


class TimelineEvent(Fixed):
    time: Optional[str] = Field(description=TIME)
    event: str


class CompactMessageResponse(Fixed):
    """The older, compact detail form of a delivery. GET /api/message/{correlation_key}/details has more."""
    correlation_key: str
    message_id: Optional[str]
    queue_id: Optional[str]
    sender: Optional[str]
    recipient: Optional[str]
    subject: Optional[str]
    direction: Optional[str]
    final_status: Optional[str]
    first_seen: Optional[str] = Field(description=TIME)
    last_seen: Optional[str] = Field(description=TIME)
    rspamd: Optional[CompactRspamd]
    postfix: List[CompactPostfixLine]
    timeline: List[Optional[TimelineEvent]] = Field(description="By time; null where the message has no Rspamd scan")
