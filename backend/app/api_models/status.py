"""What the Status calls return (routers/status.py): mailcow's containers,
version and counts, this app's version and its own log.

The mailcow counts and storage (MailcowInfo, StorageStatus) are in
mailboxes.py, because the weekly summary carries them too.
"""
from typing import Dict, List, Optional

from pydantic import Field

from . import Fixed

TIME = "UTC, ISO 8601 with Z"


class Container(Fixed):
    name: str = Field(description="Without -mailcow")
    state: str = Field(description="As mailcow reports it, such as running or exited; stopped for a container "
                                   "mailcow no longer reports")
    started_at: Optional[str] = Field(description=TIME + "; a value that cannot be read is passed on as mailcow "
                                                         "sent it")
    ignored: bool = Field(description="Listed but not counted")


class ContainerCounts(Fixed):
    """Counts without the ignored containers."""
    running: int
    stopped: int
    total: int
    ignored: int


class ContainersResponse(Fixed):
    """The mailcow containers. Containers mailcow stopped reporting stay listed from the app's records."""
    containers: Dict[str, Container] = Field(description="By the container's full name, such as postfix-mailcow")
    summary: ContainerCounts


class ContainerIgnored(Fixed):
    container: str
    ignored: bool


class MailcowVersion(Fixed):
    """The running mailcow version against mailcow's latest release on GitHub, checked at most once a day."""
    current_version: Optional[str] = Field(description="As mailcow reports it")
    latest_version: str = Field(description="The latest release's tag; unknown when GitHub did not answer")
    name: Optional[str] = Field(description="The latest release's name")
    update_available: bool
    changelog: Optional[str] = Field(description="The latest release's notes, Markdown")
    last_checked: str = Field(description=TIME)


class AppVersion(Fixed):
    """This app's version against its latest release on GitHub."""
    current_version: Optional[str] = Field(description="The running version; null before the first check")
    latest_version: Optional[str] = Field(description="Without the v; unknown when GitHub did not answer, null "
                                                      "before the first check")
    update_available: bool
    changelog: Optional[str] = Field(description="The latest release's notes, Markdown")
    last_checked: Optional[str] = Field(description=TIME)
    error: str = Field(None, description="Only when the version could not be read; then latest_version is "
                                         "unknown")


class Changelog(Fixed):
    version: str = Field(description="As asked")
    changelog: Optional[str] = Field(description="The release's notes, Markdown; a sentence when the release "
                                                 "was not found or GitHub did not answer")


class MailcowConnection(Fixed):
    connected: bool = Field(description="mailcow's API answered")
    timestamp: str = Field(description="Now, " + TIME)
    error: str = Field(None, description="Only when the check itself failed")


class SummaryContainers(Fixed):
    running: int
    stopped: int
    total: int
    ignored: int = Field(None, description="Missing when mailcow did not answer")


class SummaryStorage(Fixed):
    used_percent: str = Field(description="As mailcow reports it, such as 45%")
    used: str
    total: str
    known: bool = Field(description="false when mailcow did not tell it: the zeros are not a reading")


class SummarySystem(Fixed):
    domains: int
    mailboxes: int
    aliases: int


class StatusSummary(Fixed):
    """Containers, storage and mailcow counts, for the dashboard. A part that cannot be read is zeros."""
    containers: SummaryContainers = Field(description="The summary of GET /api/status/containers")
    containers_known: bool = Field(description="false when mailcow did not answer or nothing runs: the counts "
                                               "are not a reading")
    storage: SummaryStorage
    system: SummarySystem = Field(description="Totals")


class ContainerLogs(Fixed):
    logs: List[str] = Field(description="The newest lines of this app's own log, oldest first; a sentence when "
                                        "the file is missing or cannot be read")
