"""What the Live Logs calls return (routers/raw_logs.py; the WebSocket is not an API call)."""
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from . import Fixed

TIME = "UTC, ISO 8601 with Z"


class WsToken(Fixed):
    """A one-time token for the live log stream (/ws/raw-logs?token=...)."""
    token: str
    ttl: int = Field(description="Seconds the token can be used in")


class RawLogService(Fixed):
    id: str = Field(description="Such as postfix, dovecot or rspamd-history")
    name: str
    icon: str
    description: str
    has_smart_filters: bool = Field(description="Only Postfix has them")
    log_count: int = Field(description="Stored lines; 0 when they cannot be counted")


class RawLogServices(Fixed):
    """The services shown on the Logs page."""
    services: List[RawLogService]
    ws_connections: Dict[str, int] = Field(description="Open live streams per service")
    raw_logs_enabled: bool


class FetchJob(Fixed):
    last_run: Optional[str] = Field(description=TIME + "; null before the first run")
    status: str = Field(description="idle, running, success or failed")
    error: Optional[str]
    stats: Dict[str, int] = Field(description="Lines fetched per service in the last run; -1 when it failed")


class CleanupJob(Fixed):
    last_run: Optional[str] = Field(description=TIME + "; null before the first run")
    status: str = Field(description="idle, running, success or failed")
    error: Optional[str]


class RawLogJobs(Fixed):
    fetch_raw_logs: FetchJob
    cleanup_raw_logs: CleanupJob


class RawLogsWorkerStatus(Fixed):
    """How the raw log collection is set up and how its jobs ran."""
    enabled: bool
    fetch_interval: int = Field(description="Seconds")
    fetch_count: int = Field(description="Lines asked from mailcow per service and run")
    retention_days: int
    services: List[str] = Field(description="The services shown on the Logs page")
    jobs: RawLogJobs
    ws_connections: Dict[str, int] = Field(description="Open live streams per service")


class RawLogLine(BaseModel):
    """A stored line: the entry as mailcow gave it, plus the three keys below. Its other keys
    depend on the service, such as time, priority, program and message (Rspamd history has
    its own, such as subject, sender_smtp, ip and action)."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)
    id_: int = Field(alias="_id", description="The stored line's id")
    service_: str = Field(alias="_service")
    stored_at_: Optional[str] = Field(alias="_stored_at", description="When it was stored, " + TIME)


class RawLogsPage(Fixed):
    """Stored lines of one service, one page."""
    data: List[RawLogLine]
    page: int
    limit: int
    total: int = Field(description="Lines that match, on every page")
    pages: int = Field(description="At least 1")
    service: str


class SmartFilter(Fixed):
    id: str = Field(description="Send it in smart_filter")
    label: str
    pattern: str = Field(description="Text the field contains")
    field: str = Field(description="program or message")
    color: str
    description: str


class SmartFilters(Fixed):
    """The quick filters of a service; only Postfix has any."""
    service: str
    filters: List[SmartFilter]
