"""What the dashboard statistics return (routers/stats.py, stats_flow.py, stats_trends.py).

Most of these calls answer 200 even when the database read fails: the
figures are then zero (or the list empty) and `error` says so.
"""
from typing import Dict, List, Optional

from pydantic import ConfigDict, Field

from . import Fixed

TIME = "UTC, ISO 8601 with Z"
FAILED = "Only when the figures could not be read: what to do"


class _Keyed(Fixed):
    """Keys such as 24h are not Python names; they are given as aliases."""
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class DashboardMessages(_Keyed):
    h24: int = Field(alias="24h", description="Deliveries first seen in the last 24 hours")
    d7: int = Field(alias="7d")
    d30: int = Field(alias="30d")
    unique_24h: int = Field(None, description="Messages, as the Messages page counts them (one per message). "
                                              "Missing when the figures could not be read")
    unique_7d: int = Field(None, description="As unique_24h, over 7 days")


class DashboardBlocked(_Keyed):
    h24: int = Field(alias="24h", description="Bounced, rejected or spam")
    d7: int = Field(alias="7d")
    percentage_24h: float = Field(description="Of the deliveries in the last 24 hours")


class DashboardPair(_Keyed):
    h24: int = Field(alias="24h")
    d7: int = Field(alias="7d")


class DashboardDirection(Fixed):
    inbound_24h: int
    outbound_24h: int
    internal_24h: int


class DashboardResponse(Fixed):
    """The dashboard's figures."""
    messages: DashboardMessages
    blocked: DashboardBlocked
    deferred: DashboardPair
    auth_failures: DashboardPair = Field(description="Failed SASL logins (Netfilter rule 3)")
    direction: DashboardDirection = Field(description="Rspamd scans in the last 24 hours, by direction")
    error: str = Field(None, description=FAILED)


class TimelineHour(Fixed):
    hour: Optional[str] = Field(description=TIME)
    total: int = Field(description="Rspamd scans")
    spam: int
    clean: int
    messages: int = Field(description="Deliveries first seen")
    unique_messages: int = Field(description="Messages, one per message")
    blocked: int
    deferred: int
    auth_failures: int


class TimelineResponse(Fixed):
    """Hourly counts for the chart, oldest first."""
    timeline: List[TimelineHour]
    error: str = Field(None, description=FAILED)


class SpamTrigger(Fixed):
    symbol: str
    count: int = Field(description="Spam scans with this symbol in the last 7 days")


class SpamTriggersResponse(Fixed):
    triggers: List[SpamTrigger]
    error: str = Field(None, description=FAILED)


class BlockedIp(Fixed):
    ip: Optional[str]
    count: int = Field(description="Netfilter lines in the last 7 days")
    last_seen: Optional[str] = Field(description=TIME)


class BlockedIpsResponse(Fixed):
    blocked_ips: List[BlockedIp]
    error: str = Field(None, description=FAILED)


class Activity(Fixed):
    time: Optional[str] = Field(description="The delivery's last activity, " + TIME)
    sender: Optional[str]
    recipient: Optional[str]
    subject: Optional[str]
    direction: Optional[str]
    status: Optional[str]
    correlation_key: str


class RecentActivityResponse(Fixed):
    activity: List[Activity]
    error: str = Field(None, description=FAILED)


class FlowCounts(Fixed):
    clean: int = Field(description="Rspamd scans that were not spam")
    spam: int
    messages: int = Field(description="Messages, one per message, by its earliest delivery in the range")
    deliveries: int
    blocked: int = Field(description="Bounced, rejected or spam")
    deferred: int
    auth_failures: int = Field(description="Failed SASL logins (Netfilter rule 3)")


class FlowBar(FlowCounts):
    start: str = Field(description="UTC, ISO 8601 with microseconds and Z")
    end: str
    end_inclusive: str = Field(description="The last moment in the bar, for an inclusive end")
    partial: bool = Field(description="The bar is still going on")


class FlowResponse(Fixed):
    """Mail flow in bars cut at the app time zone's own hours, quarters of the day or days."""
    from_: str = Field(alias="from")
    to: str
    to_inclusive: str
    as_of: str
    bucket: str = Field(description="hour, 6h or day")
    zone: str = Field(description="The app time zone")
    older_may_be_gone: bool = Field(description="The range starts before the retention days: older logs may be deleted")
    kept_from: str
    buckets: List[FlowBar]
    totals: FlowCounts

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class TrendSample(Fixed):
    slot: str = Field(description="The hour the sample stands for, UTC with Z")
    value: Optional[float]
    of: Optional[float] = Field(description="The denominator, when the figure has one")
    as_of: str = Field(description="When it was read")


class TrendsResponse(Fixed):
    """Hourly samples of the named trends, oldest first; a missing hour is a gap."""
    days: int
    trends: Dict[str, List[TrendSample]] = Field(description="By trend name. A trend of a feature that is off is "
                                                             "left out")
