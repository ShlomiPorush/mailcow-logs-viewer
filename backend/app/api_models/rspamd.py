"""What the Rspamd map calls return (routers/rspamd_maps.py)."""
from typing import Any, List, Optional

from pydantic import Field

from . import Fixed


class RspamdConfig(Fixed):
    rspamd_configured: bool = Field(description="The Rspamd password is set, so the maps can be read")
    rw_key_configured: bool = Field(description="A Read-Write mailcow API key is set, so the maps can be saved")
    suppression_enabled: bool
    suppression_configured: bool


class RspamdMapInfo(Fixed):
    """One of the mailcow Rspamd maps the editor knows."""
    filename: str
    name: str
    category: str = Field(description="sender, recipient, content or system")
    description: str
    supports_regex: bool
    managed_by_suppression: bool = Field(None, description="Only on the maps Suppressions also writes")


class RspamdLiveMap(RspamdMapInfo):
    """A known map with what Rspamd says about it."""
    map_id: Optional[int] = Field(description="Rspamd's id of the map; null when Rspamd has not loaded it")
    loaded: bool
    editable: bool = Field(None, description="Only when Rspamd lists the map")
    rspamd_description: str = Field(None, description="Rspamd's own description; only when Rspamd lists the map")


class RspamdMapsNotConfigured(Fixed):
    """The Rspamd password is not set: the known maps only."""
    configured: bool = Field(description="false")
    message: str
    maps: List[RspamdMapInfo]


class RspamdMapsLive(Fixed):
    """The known maps with their state in Rspamd."""
    configured: bool = Field(description="true")
    rw_key_configured: bool
    maps: List[RspamdLiveMap]


class RspamdMapsUnreadable(Fixed):
    """Rspamd could not be read: the known maps only."""
    configured: bool = Field(description="true")
    error: str
    maps: List[RspamdMapInfo]


class RspamdMapNotLoaded(Fixed):
    """Rspamd does not list the map (yet): it is empty."""
    filename: str
    content: str = Field(description="Empty")
    content_hash: str = Field(description="SHA-256 of the content, hex; send it back as base_hash when saving")
    entry_count: int = Field(description="0")
    message: str


class RspamdMapContent(Fixed):
    """The map as Rspamd has it now."""
    filename: str
    content: str
    content_hash: str = Field(description="SHA-256 of the content, hex; send it back as base_hash when saving")
    entry_count: int = Field(description="Lines that are not empty and not comments")
    metadata: RspamdMapInfo


class MapFinding(Fixed):
    """A problem with one line of a map."""
    line: int = Field(description="Line number, from 1")
    content: str = Field(description="The line, trimmed")
    severity: str = Field(description="error (blocks a save) or warning")
    error: str = Field(description="What is wrong")


class RspamdMapSaved(Fixed):
    """The map was saved."""
    success: bool = Field(description="true")
    filename: str
    entry_count: int = Field(description="Lines that are not empty and not comments, in the saved map")
    normalized_entries: int = Field(description="Bare addresses that were anchored before saving")
    content: str = Field(description="The map as saved, read back from Rspamd; what was sent when it cannot be read")
    content_hash: Optional[str] = Field(description="SHA-256 of the saved map, for the next save; null when it "
                                                    "could not be read back, so open the map again first")
    warnings: List[MapFinding]
    api_response: Any = Field(description="mailcow's reply to the save, as mailcow sent it")


class MapInvalidDetail(Fixed):
    message: str
    validation_errors: List[MapFinding]


class MapInvalid(Fixed):
    """The map has lines that cannot be saved; nothing was saved."""
    detail: MapInvalidDetail


class MapChangedDetail(Fixed):
    code: str = Field(description="map_changed")
    message: str


class MapChanged(Fixed):
    """The map changed since it was read (base_hash); nothing was saved."""
    detail: MapChangedDetail


class MapValidation(Fixed):
    """The check of a map's content; nothing is saved."""
    valid: bool = Field(description="No line has an error")
    entry_count: int = Field(description="Lines that are not empty and not comments")
    errors: List[MapFinding]
    warnings: List[MapFinding]
