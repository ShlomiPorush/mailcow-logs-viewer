"""What the Outbound settings do with mail that could not be delivered, as it
really happens.

The stored choices say what the user picked; a block reaches Rspamd only
through "Sync with Rspamd", so with the sync off a choice that blocks acts as
its twin that does not: a permanent failure still deletes the address's
queued mail, the queue cleanup still deletes stuck mail, and counting
temporary failures stops. Every job reads the choices here, never the raw
settings, and an unknown stored value (set by hand in the database, say)
blocks and deletes nothing.
"""
import logging
from typing import Optional

from ..config import settings

logger = logging.getLogger(__name__)

HARD_ACTIONS = ('suppress', 'delete', 'ignore')
SOFT_ACTIONS = ('suppress', 'count', 'ignore')
_warned = set()


def rspamd_sync_on() -> bool:
    """Whether the list is kept in step with the app's section of the Rspamd
    map ("Sync with Rspamd"), both ways and by itself."""
    return settings.is_feature_enabled('suppressions') and bool(settings.suppression_rspamd_sync)


def _known(name: str, value, allowed) -> str:
    value = str(value or '')
    if value in allowed:
        return value
    if (name, value) not in _warned:
        _warned.add((name, value))
        logger.warning(f"[QUEUE] Unknown {name} {value!r}: nothing is blocked or deleted for it")
    return 'ignore'


def hard_action(sync_on: Optional[bool] = None) -> str:
    """suppress (block and delete the address's queued mail), delete (only the
    queued mail) or ignore, for a permanent failure (5.x.x). sync_on: the
    sync as the caller read it under the row lock."""
    action = _known('SUPPRESSION_HARD_BOUNCE_ACTION', settings.suppression_hard_bounce_action, HARD_ACTIONS)
    on = rspamd_sync_on() if sync_on is None else sync_on
    return 'delete' if action == 'suppress' and not on else action


def soft_action(sync_on: Optional[bool] = None) -> str:
    """suppress, count or ignore, for a temporary failure (4.x.x) read from the
    logs. Both that block do nothing while the sync is off."""
    action = _known('SUPPRESSION_SOFT_BOUNCE_ACTION', settings.suppression_soft_bounce_action, SOFT_ACTIONS)
    on = rspamd_sync_on() if sync_on is None else sync_on
    return 'ignore' if action != 'ignore' and not on else action


def cleanup_blocks() -> bool:
    """Whether the queue cleanup blocks the recipients of the stuck mail it
    deletes (otherwise it only deletes)."""
    return bool(settings.queue_cleanup_enabled and settings.queue_cleanup_block and rspamd_sync_on())


def handling_on() -> bool:
    """Suppressions on and "Handle undeliverable mail automatically" on."""
    return settings.is_feature_enabled('suppressions') and bool(settings.suppression_enabled)
