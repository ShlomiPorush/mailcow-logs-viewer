"""What the entity card calls return (routers/entities.py, services/entity_summary.py).

Every source has a state. Only an "ok" source carries its figures; a
"disabled" or "error" one carries only the reason, so a missing figure is
never read as zero.
"""
from typing import Any, Dict, List, Optional

from pydantic import Field

from . import Fixed
from .security import ProtectionCatch

TIME = "UTC, ISO 8601 with Z"
_STATE = ("ok; disabled when its feature is off or the value is not shown (an excluded address in Messages); "
          "error when it could not be read. Only an ok source has figures")


class Source(Fixed):
    state: str = Field(description=_STATE)
    reason: Optional[str] = Field(description="Why it is disabled or failed, in words; null when ok")


class Range(Fixed):
    """The range the activity is counted in: the last 7 days unless asked, 90 days at most."""
    start: str = Field(description=TIME)
    end: str = Field(description=TIME)


# ---------------------------------------------------------------- messages

class MessageItem(Fixed):
    """One message (its earliest matching delivery), as the Messages list shows it."""
    correlation_key: str = Field(description="Opens the message: GET /api/message/{correlation_key}/details")
    first_seen: Optional[str] = Field(description=TIME)
    sender: Optional[str]
    recipient: Optional[str]
    subject: Optional[str]
    direction: Optional[str]
    final_status: Optional[str]


class MessagesSource(Source):
    count: int = Field(None, description="Messages in the range, not deliveries (excluded addresses left out)")
    sent: int = Field(None, description="Of them, sent by the address or domain (address and domain cards)")
    received: int = Field(None, description="Of them, sent to the address or domain (address and domain cards)")
    items: List[MessageItem] = Field(None, description="The newest, at most 50")


# ---------------------------------------------------------------- security

class SecurityItem(Fixed):
    """One Netfilter line."""
    time: Optional[str] = Field(description=TIME)
    ip: Optional[str]
    action: Optional[str] = Field(description="ban, unban or another Netfilter action; null on a rule match")
    rule_id: Optional[int] = Field(description="Set on a rule match (a failed attempt)")
    username: Optional[str] = Field(description="The account the client tried, when the line names one")
    service: Optional[str] = Field(description="What the line was about, such as SMTP auth or IMAP")
    attempts_left: Optional[int]
    message: Optional[str] = Field(description="The line as Netfilter wrote it")


class SecuritySource(Source):
    events: int = Field(None, description="Netfilter lines in the range")
    rule_matches: int = Field(None, description="Of them, rule matches (failed attempts)")
    bans: int = Field(None, description="Of them, bans")
    unbans: int = Field(None, description="Of them, unbans")
    ips: int = Field(None, description="Addresses the lines came from (address and domain cards)")
    last_seen: Optional[str] = Field(None, description=TIME)
    items: List[SecurityItem] = Field(None, description="The newest, at most 50")


class Fail2banBan(Fixed):
    network: str = Field(description="The network Fail2ban banned, such as 203.0.113.4/32 or 198.51.100.0/24")
    banned_until: Any = Field(description="As mailcow sends it")
    queued_for_unban: bool


class ListsSource(Source):
    """mailcow's Fail2ban allowlist, denylist and bans, read when the card opens."""
    allowlisted_as: Optional[str] = Field(None, description="The allowlist entry that holds the address")
    denylisted_as: Optional[str] = Field(None, description="The denylist entry that holds the address")
    ban: Optional[Fail2banBan] = Field(None, description="Fail2ban's current ban that holds the address")


class ProtectionSource(Source):
    count: int = Field(None, description="Catches open now or overlapping the range")
    open: int = Field(None, description="Of them, open")
    items: List[ProtectionCatch] = Field(None, description="The newest, at most 50")


# ---------------------------------------------------------------- devices

class DeviceItem(Fixed):
    id: int
    username: str
    device_id: str
    device_type: Optional[str]
    last_ip: Optional[str]
    last_command: Optional[str]
    first_seen: Optional[str] = Field(description=TIME)
    last_seen: Optional[str] = Field(description=TIME)


class DevicesSource(Source):
    count: int = Field(None, description="ActiveSync devices seen in the range (an IP card: last seen from it)")
    items: List[DeviceItem] = Field(None, description="The most recently seen, at most 50")


# ---------------------------------------------------------------- DMARC

class DmarcDomainFigures(Fixed):
    domain: str
    messages: int
    dmarc_pass: int = Field(description="Messages where SPF or DKIM passed")
    spf_pass: int
    dkim_pass: int
    reports: int
    last_period_end: Optional[str] = Field(description="End of the newest report period, " + TIME)
    last_received: Optional[str] = Field(description="When the newest report was stored, " + TIME)


class DmarcRecordItem(Fixed):
    domain: str
    org_name: str = Field(description="Who sent the report")
    report_id: str
    period_begin: Optional[str] = Field(description=TIME)
    period_end: Optional[str] = Field(description=TIME)
    received: Optional[str] = Field(description="When the report was stored, " + TIME)
    count: int
    disposition: Optional[str]
    spf_result: Optional[str]
    dkim_result: Optional[str]
    header_from: Optional[str]


class DmarcIpSource(Source):
    """Aggregate DMARC records naming the IP as a source, for every domain, by report period."""
    messages: int = Field(None)
    reports: int = Field(None)
    domains: int = Field(None)
    by_domain: List[DmarcDomainFigures] = Field(None, description="Most messages first, at most 20")
    records: List[DmarcRecordItem] = Field(None, description="Newest report period first, at most 50")


class DmarcDomainSource(Source):
    """The domain's own DMARC reports whose period overlaps the range."""
    reports: int = Field(None)
    messages: int = Field(None)
    dmarc_pass: int = Field(None, description="Messages where SPF or DKIM passed")
    spf_pass: int = Field(None)
    dkim_pass: int = Field(None)
    sources: int = Field(None, description="Sending addresses")
    last_period_end: Optional[str] = Field(None, description=TIME)
    last_received: Optional[str] = Field(None, description=TIME)


# ---------------------------------------------------------------- blocklists and place

class RblSource(Source):
    """The last stored blocklist check, never a new lookup (Check now is POST /api/blacklist/check)."""
    checked: bool = Field(None, description="false: not checked yet")
    monitored: bool = Field(None, description="The address is one of the monitored hosts")
    checked_at: Optional[str] = Field(None, description=TIME)
    status: Optional[str] = Field(None, description="clean, listed or error, with ignored lists applied")
    listed_count: Optional[int] = Field(None)
    total_blacklists: Optional[int] = Field(None)
    listed: List[str] = Field(None, description="The lists it is on, ignored lists left out")


class GeoSource(Source):
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    asn_org: Optional[str] = None


# ---------------------------------------------------------------- address and domain facts

class SuppressionEntry(Fixed):
    email: str = Field(description="The address or domain on the list")
    type: Optional[str] = Field(description="email or domain")
    reason: Optional[str]
    source: Optional[str]
    active: bool
    created_at: Optional[str] = Field(description=TIME)
    expires_at: Optional[str] = Field(description=TIME)
    bounce_count: Optional[int]


class SuppressionSource(Source):
    entry: Optional[SuppressionEntry] = Field(None, description="The value's own entry, or null")
    domain_entry: Optional[SuppressionEntry] = Field(None, description="The entry of the address's domain (address card)")


class MailboxFacts(Fixed):
    username: str
    name: Optional[str]
    domain: str
    active: Optional[bool]


class AliasFacts(Fixed):
    address: str
    goto: Optional[str] = Field(description="Where it delivers, comma separated")
    primary_mailbox: Optional[str]
    active: Optional[bool]


class MailboxSource(Source):
    local: bool = Field(None, description="A mailbox on this mailcow")
    mailbox: Optional[MailboxFacts] = None
    alias: Optional[AliasFacts] = None


class MailboxesSource(Source):
    mailboxes: int = Field(None)
    active_mailboxes: int = Field(None)
    aliases: int = Field(None)


class DnsSource(Source):
    checked: bool = Field(None, description="false: no DNS check stored")
    checked_at: Optional[str] = Field(None, description=TIME)
    checks: Dict[str, Optional[str]] = Field(None, description="Status of each stored check (spf, dkim, dmarc, "
                                                                 "dnssec, tlsa, mta_sts, tls_rpt)")


# ---------------------------------------------------------------- timeline

class TimelineItem(Fixed):
    """One stored event. Each kind sets the keys that belong to it."""
    time: str = Field(description=TIME)
    kind: str = Field(description="message, security (a rule match), ban, unban, protection, device_first_seen "
                                  "or device_last_seen")
    label: str = Field(description="The kind in words")
    correlation_key: Optional[str] = None
    sender: Optional[str] = None
    recipient: Optional[str] = None
    subject: Optional[str] = None
    direction: Optional[str] = None
    status: Optional[str] = Field(None, description="A message's outcome, or a catch's status")
    ip: Optional[str] = None
    username: Optional[str] = None
    service: Optional[str] = None
    hit_id: Optional[int] = None
    rule: Optional[str] = None
    device_id: Optional[str] = None
    device_type: Optional[str] = None


class Timeline(Fixed):
    items: List[TimelineItem] = Field(description="Newest first, at most 100")
    truncated: bool = Field(description="More happened in the range than the list holds")
    left_out: List[str] = Field(description="Sources that are off or failed, so they are not in it")


# ---------------------------------------------------------------- the cards

class IpSources(Fixed):
    messages: MessagesSource
    security: SecuritySource
    lists: ListsSource
    protection: ProtectionSource
    devices: DevicesSource
    dmarc: DmarcIpSource
    rbl: RblSource
    geo: GeoSource


class IpCard(Fixed):
    kind: str = Field(description="ip")
    value: str = Field(description="The address as the app reads it (IPv6 compressed)")
    display: str
    range: Range
    sources: IpSources
    timeline: Timeline


class AddressSources(Fixed):
    messages: MessagesSource
    security: SecuritySource
    protection: ProtectionSource
    devices: DevicesSource
    suppression: SuppressionSource
    mailbox: MailboxSource


class AddressCard(Fixed):
    kind: str = Field(description="address")
    value: str = Field(description="The address in lower case, its domain in ASCII")
    display: str = Field(description="The address as it was asked for")
    domain: str
    hosted_domain: Optional[bool] = Field(description="Its domain is on this mailcow; null while that is not known")
    excluded: bool = Field(description="One of the excluded addresses")
    range: Range
    sources: AddressSources
    timeline: Timeline


class DomainSources(Fixed):
    messages: MessagesSource
    security: SecuritySource
    protection: ProtectionSource
    devices: DevicesSource
    dmarc: DmarcDomainSource
    suppression: SuppressionSource
    mailboxes: MailboxesSource
    dns: DnsSource


class DomainCard(Fixed):
    kind: str = Field(description="domain")
    value: str = Field(description="The domain in ASCII (IDNA), lower case, without a trailing dot")
    display: str = Field(description="The domain in Unicode when it is an IDN")
    hosted: Optional[bool] = Field(description="On this mailcow; null while that is not known")
    range: Range
    sources: DomainSources
