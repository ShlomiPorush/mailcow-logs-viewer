"""What the Suppressions calls return (routers/suppressions.py): the list, its
block details, import, and keeping it in step with the app's section of
Rspamd's global_rcpt_blacklist.map."""
from typing import Any, List, Optional

from pydantic import Field

from . import Fixed

TIME = "UTC, ISO 8601 with Z"


# ---------------------------------------------------------------- the list

class SuppressionExpiresIn(Fixed):
    """The time left until the entry expires."""
    days: int
    hours: int = Field(description="Hours past the whole days")
    total_seconds: int
    human: str = Field(description="Such as 11 days or 3 hours")


class Suppression(Fixed):
    """One entry of the list."""
    id: int
    email: str = Field(description="An address, or a /pattern/ (a domain is stored as /.+@example\\.com/i)")
    type: Optional[str] = Field(description="email or domain")
    reason: str = Field(description="hard_bounce, soft_bounce, deferred_stuck, rejected or manual")
    source: Optional[str] = Field(description="auto, manual, import or rspamd (added in mailcow); null for "
                                              "entries made before it was kept")
    notes: Optional[str]
    bounce_count: Optional[int] = Field(description="The escalation count: each bounce lengthens the next expiry")
    hard_bounce_count: Optional[int]
    soft_bounce_count: Optional[int]
    last_bounce_dsn: Optional[str] = Field(description="Such as 5.1.1")
    last_bounce_message: Optional[str]
    correlation_key: Optional[str] = Field(description="The message that caused it, on the Messages page")
    active: Optional[bool]
    synced_to_rspamd: Optional[bool] = Field(description="Rspamd has what this entry says: its block when "
                                                         "active, none when inactive")
    expires_at: Optional[str] = Field(description=TIME + "; null is a permanent block")
    is_expired: bool = Field(description="expires_at is set and past")
    expires_in: Optional[SuppressionExpiresIn] = Field(description="Only while expires_at is set and in the future")
    created_at: Optional[str] = Field(description=TIME)
    updated_at: Optional[str] = Field(description=TIME)


class SuppressionList(Fixed):
    """One page of the list."""
    items: List[Suppression]
    total: int = Field(description="Entries that match the filters")
    page: int
    per_page: int
    total_pages: int


class SuppressionStats(Fixed):
    """Counts over the whole list. The reason counts are of active entries."""
    total: int
    active: int
    expired: int = Field(description="Inactive with a past expiry")
    hard_bounce: int
    soft_bounce: int
    rejected: int
    manual: int
    pending_sync: int = Field(description="Changes waiting to be written to Rspamd: entries to add, and "
                                          "disabled, expired or deleted entries to remove")
    auto_detected: int = Field(description="Entries the app made from bounces or the mail queue")


class SuppressionConfig(Fixed):
    """The suppression settings and what is set up."""
    suppression_enabled: bool = Field(description="Handle undeliverable mail automatically")
    suppression_auto_detect: bool
    suppression_rspamd_sync: bool = Field(description="Sync with Rspamd")
    list_kept: bool = Field(description="The app keeps a list now: Suppressions and Sync with Rspamd are on")
    suppression_whitelist_domains: str = Field(description="Comma-separated domains never suppressed")
    suppression_hard_bounce_action: str = Field(description="suppress, delete or ignore")
    suppression_soft_bounce_action: str
    suppression_soft_bounce_threshold: int
    queue_cleanup_enabled: bool
    queue_cleanup_block: bool
    queue_cleanup_threshold_minutes: int
    suppression_base_expiry_days: int
    suppression_max_expiry_days: int
    rspamd_configured: bool = Field(description="An Rspamd password is set; it is not tested")
    rw_key_configured: bool = Field(description="A Read-Write mailcow API key is set; it is not tested")
    is_fully_configured: bool = Field(description="Suppression is on and a Read-Write key is set")


class SuppressionDeleted(Fixed):
    deleted: bool = Field(description="true")
    email: str
    was_active: Optional[bool]
    needs_rspamd_sync: Optional[bool] = Field(description="Its block may still be in Rspamd: the next write "
                                                          "removes it")


class SuppressionImport(Fixed):
    imported: int
    skipped: int = Field(description="Entries already on the list, or repeated in the file")
    errors: List[str] = Field(description="One sentence per row that was not imported, such as "
                                          "Row 5: empty email")


# ---------------------------------------------------------------- block details

class SuppressionEventLine(Fixed):
    """A Postfix line of the message, copied when the event was recorded."""
    time: str = Field(description=TIME)
    program: Optional[str] = Field(description="Such as postfix/smtp")
    message: Optional[str] = Field(description="Cut to 1000 characters")


class SuppressionEventOwner(Fixed):
    id: int
    email: str
    type: Optional[str] = Field(description="email or domain")
    active: Optional[bool]


class SuppressionEventItem(Fixed):
    """What happened to the block once. Fields the logs did not prove are null; evidence about an
    address excluded since is left out (sender, subject, ids and lines)."""
    id: int
    kind: str = Field(description="hard_bounce, soft_bounce, rejected, deferred_stuck, added, imported, enabled, "
                                  "disabled, expiry_changed, notes_changed, before_upgrade, loaded_from_rspamd "
                                  "or added_in_rspamd")
    outcome: Optional[str] = Field(description="created, activated, extended, counted or changed")
    recorded_at: Optional[str] = Field(description=TIME)
    message_time: Optional[str] = Field(description=TIME)
    reason: Optional[str]
    server_reply: Optional[str] = Field(description="The receiving server's answer")
    dsn: Optional[str]
    sender: Optional[str]
    recipient: Optional[str]
    subject: Optional[str]
    queue_id: Optional[str]
    message_id: Optional[str]
    notes: Optional[str] = Field(description="The notes as they were then")
    expires_at: Optional[str] = Field(description=TIME + ", as it was then")
    log_lines: List[SuppressionEventLine] = Field(description="At most about 50, always with the deciding line")
    logs_shortened: bool = Field(description="Lines or text were left out")
    correlation_key: Optional[str]
    message_available: bool = Field(description="The message is still on the Messages page")


class SuppressionEvents(Fixed):
    """Block details, newest first, 20 per page."""
    suppression: SuppressionEventOwner
    total: int
    page: int
    page_size: int
    events: List[SuppressionEventItem]


# ---------------------------------------------------------------- errors

class SuppressionErrorDetail(Fixed):
    code: str = Field(description="What went wrong, for a program")
    message: str = Field(description="What went wrong, in words")


class SuppressionListNotKept(Fixed):
    """The list is not kept: Sync with Rspamd or Suppressions is off."""
    detail: SuppressionErrorDetail = Field(description="code sync_off")


class SuppressionListChanged(Fixed):
    """What the read before the failure changed in the list."""
    list_added: int
    list_removed: int


class RspamdMapErrorDetail(SuppressionErrorDetail):
    list_changed: SuppressionListChanged = Field(None, description="Only when the list was brought in step with Rspamd "
                                                        "before the failure")


class RspamdMapError(Fixed):
    """The app's section of the Rspamd map could not be read or changed. 409 codes: no_rw_key, no_password,
    no_rw_key_and_password, read_failed, map_not_found, feature_off, import_failed, section_missing,
    section_unclear, map_changed, connection_changed, sync_off, sync_on, transition_changed, and busy (another
    map write still running). 502 codes: rejected_rw_key (mailcow refused the Read-Write key) and not_confirmed
    (mailcow did not confirm the save; check Rspamd before trying again)."""
    detail: RspamdMapErrorDetail


# ---------------------------------------------------------------- Rspamd sync

class SuppressionSyncDone(Fixed):
    """The list and the app's section are in step: read in, then the list's changes written."""
    success: bool = Field(description="true")
    written: bool = Field(description="false when the section already held what would be written")
    synced: int = Field(description="Active entries")
    added: int = Field(description="Map lines the write added")
    removed: int = Field(description="Map lines the write removed")
    manual_entries_preserved: int = Field(description="Lines outside the app's section, kept as they are")
    sync_time: Optional[str] = Field(description="UTC, ISO 8601 with Z, to the second; null when nothing was "
                                                 "written")
    skipped: bool = Field(None, description="Only when nothing was written: true")
    api_response: Any = Field(None, description="Only when written: mailcow's reply to the save, as mailcow "
                                                "sent it")
    list_added: int = Field(description="Entries the read added: lines added in mailcow")
    list_removed: int = Field(description="Entries the read removed: lines deleted in mailcow")
    pending_count: int = Field(description="Changes still waiting to be written")


class SuppressionSyncReadOnly(Fixed):
    """after_change without the Read-Write key: the section was read into the list, nothing was written."""
    success: bool = Field(description="true")
    written: bool = Field(description="false")
    skipped_off: bool = Field(description="true")
    list_added: int
    list_removed: int
    pending_count: int


class SuppressionSyncOff(Fixed):
    """after_change while Sync with Rspamd is off: nothing was read or written."""
    success: bool = Field(description="true")
    written: bool = Field(description="false")
    skipped_off: bool = Field(description="true")


class SuppressionSyncTurnedOff(Fixed):
    """after_change, when the sync went off or the password was removed during the call: nothing was read or
    written."""
    success: bool = Field(description="true")
    synced: int = Field(description="0")
    skipped_off: bool = Field(description="true")


class SuppressionRspamdState(Fixed):
    """What the app has in Rspamd, read from the map, and whether it can change it."""
    sync_on: bool = Field(description="The list is kept: Suppressions and Sync with Rspamd are on")
    active_count: int = Field(description="Active entries")
    list_count: int = Field(description="All entries")
    pending_count: int = Field(description="Changes waiting to be written: entries to add, disabled or expired "
                                           "entries to remove, deleted entries whose lines are still there")
    writable: bool = Field(description="The Read-Write key and the Rspamd password are set")
    readable: bool = Field(description="The map was read now")
    managed_count: Optional[int] = Field(description="Lines in the app's section; null when the map was not "
                                                     "read")
    reason: Optional[str] = Field(description="no_rw_key, no_password, no_rw_key_and_password, read_failed, "
                                              "map_not_found or section_unclear")
    reason_text: Optional[str] = Field(description="reason in words")


class SuppressionRspamdImport(Fixed):
    """Loading the app's blocks back into the list after it was deleted."""
    imported: int = Field(description="Entries this call loaded")
    pending: bool = Field(description="The load still waits")
    loaded: bool = Field(description="This call did the load")
    feature_off: bool = Field(None, description="Only when Suppressions is off: true")
    sync_off: bool = Field(None, description="Only when Sync with Rspamd is off: true; the first read once it is "
                                             "on loads them")
    reason: str = Field(None, description="Only when the load waits for the Rspamd password: no_password")


class SuppressionRspamdCleared(Fixed):
    removed_blocks: int = Field(description="Lines removed from the app's section")


class SuppressionsStartedFresh(Fixed):
    removed_blocks: int = Field(description="Lines removed from the app's section")
    deleted_entries: int = Field(description="Entries deleted from the list")
