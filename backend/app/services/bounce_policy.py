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
import re
from typing import FrozenSet, List, Optional

from ..config import settings

logger = logging.getLogger(__name__)

HARD_ACTIONS = ('suppress', 'delete', 'ignore')
SOFT_ACTIONS = ('suppress', 'count', 'ignore')
_warned = set()

# An enhanced status code (RFC 3463): class.subject.detail
_CODE = re.compile(r'^[45]\.\d{1,3}\.\d{1,3}$')
# The code in a deferral reason, such as "host mx said: 452 4.2.2 Mailbox full"
_CODE_IN_TEXT = re.compile(r'(?<![\d.])([45]\.\d{1,3}\.\d{1,3})(?![\d.])')
EXCLUDED_CODES_KEYS = {'5': 'suppression_hard_bounce_excluded_codes', '4': 'suppression_soft_bounce_excluded_codes'}


def split_codes(value) -> List[str]:
    """The codes in a stored list, as typed: separated by commas or spaces."""
    return [part for part in re.split(r'[\s,]+', str(value or '')) if part]


def bad_code(code: str, kind: str) -> bool:
    """Whether code is not an enhanced status code of class kind ('5' or '4')."""
    return not _CODE.match(code) or code[0] != kind


def _canonical(code: str) -> str:
    """A well-formed code without leading zeros: 5.02.2 is 5.2.2."""
    return '.'.join(str(int(part)) for part in code.split('.'))


def normalize_codes(value, kind: str) -> str:
    """The stored form of a list of codes: each once, in code order, joined by
    commas. Raises ValueError naming the first code that does not belong."""
    codes = []
    for code in split_codes(value):
        if bad_code(code, kind):
            raise ValueError(code)
        code = _canonical(code)
        if code not in codes:
            codes.append(code)
    codes.sort(key=lambda c: tuple(int(part) for part in c.split('.')))
    return ','.join(codes)


def excluded_codes(kind: str) -> FrozenSet[str]:
    """The codes of class kind ('5' permanent, '4' temporary) the jobs leave
    alone. A stored list with a code that does not belong (set by hand in the
    database, say) is read without it, with one warning."""
    key = EXCLUDED_CODES_KEYS[kind]
    value = getattr(settings, key, '') or ''
    good = set()
    for code in split_codes(value):
        if bad_code(code, kind):
            if (key, code) not in _warned:
                _warned.add((key, code))
                logger.warning(f"[QUEUE] {key.upper()} has {code!r}, which is not a {kind}.x.x code: it is not read")
            continue
        good.add(_canonical(code))
    return frozenset(good)


def code_excluded(dsn: str) -> bool:
    """Whether a failure with this status code is left alone: not blocked,
    counted or deleted. Only a permanent (5.x.x) or temporary (4.x.x) code
    can be."""
    dsn = str(dsn or '').strip()
    if not dsn or dsn[0] not in EXCLUDED_CODES_KEYS or bad_code(dsn, dsn[0]):
        return False
    return _canonical(dsn) in excluded_codes(dsn[0])


def codes_in_text(text: str) -> List[str]:
    """The 4.x.x and 5.x.x codes written in a server reply or a deferral reason."""
    return _CODE_IN_TEXT.findall(str(text or ''))


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
