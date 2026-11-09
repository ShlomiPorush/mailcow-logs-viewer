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
# A code in a server reply comes right after a reply code of its class:
# "said: 452 4.2.2 Mailbox full", "452-4.2.2", "refused to start TLS: 454
# 4.7.0", or the last line of a reply joined by Postfix. The remote server
# picks its reply anyway; what must not pass for a code is a number in a host
# name (452-4.2.2-mx.example.org) or an address (<452-4.2.2@example.org>).
_CODE_IN_TEXT = re.compile(r'(?<![\w.<@-])([45])\d\d[ -]\s*(\1\.\d{1,3}\.\d{1,3})(?![\w.@>-])')
# Addresses are taken out first, whole: <sender+452-4.2.2+tag@example.org>
_ADDRESS = re.compile(r'<[^<>]*>|\S*@\S*')
EXCLUDED_CODES_KEYS = {'5': 'suppression_hard_bounce_excluded_codes', '4': 'suppression_soft_bounce_excluded_codes'}
STANDARD_CODES_KEYS = {'5': 'suppression_hard_bounce_standard_codes', '4': 'suppression_soft_bounce_standard_codes'}

# The standard codes: failures about the sender, the message, the network or
# policy, which say nothing about the recipient's address (RFC 3463 and the
# IANA registry, plus provider codes such as Microsoft's 5.2.121). "x" stands
# for every detail of a subject, codes no registry lists included: providers
# number their own policy codes (Microsoft's 5.7.509, 5.7.606). Kept equal to
# SETTINGS_STANDARD_CODES in frontend/settings.js (a test compares them).
STANDARD_CODES = {
    '5': ('5.1.7', '5.1.8', '5.1.9',
          '5.2.2', '5.2.3', '5.2.4', '5.2.121', '5.2.122',
          '5.3.1', '5.3.2', '5.3.3', '5.3.4', '5.3.5',
          '5.4.0', '5.4.2', '5.4.3', '5.4.5', '5.4.6', '5.4.7', '5.4.8', '5.4.300',
          '5.5.1', '5.5.2', '5.5.3', '5.5.4', '5.5.5', '5.5.6',
          '5.6.x', '5.7.x'),
    '4': ('4.0.0', '4.1.7', '4.1.8', '4.1.9',
          '4.2.1', '4.2.2', '4.2.3', '4.2.4',
          '4.3.1', '4.3.2', '4.3.3', '4.3.4', '4.3.5',
          '4.4.x', '4.5.x', '4.6.x', '4.7.x'),
}


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


def standard_code(code: str) -> bool:
    """Whether a well-formed code is one of the standard codes of its class."""
    code = _canonical(code)
    subject = code.rsplit('.', 1)[0] + '.x'
    return any(entry in (code, subject) for entry in STANDARD_CODES.get(code[0], ()))


def standard_codes_on(kind: str) -> bool:
    """Whether the standard codes of class kind are left alone (the default)."""
    return bool(getattr(settings, STANDARD_CODES_KEYS[kind], True))


def code_excluded(dsn: str) -> bool:
    """Whether a failure with this status code is left alone: not blocked,
    counted or deleted. Only a permanent (5.x.x) or temporary (4.x.x) code
    can be: a standard code while its switch is on, or one on the list."""
    dsn = str(dsn or '').strip()
    if not dsn or dsn[0] not in EXCLUDED_CODES_KEYS or bad_code(dsn, dsn[0]):
        return False
    kind = dsn[0]
    return (standard_codes_on(kind) and standard_code(dsn)) or _canonical(dsn) in excluded_codes(kind)


def codes_in_text(text: str) -> List[str]:
    """The 4.x.x and 5.x.x codes written in a server reply or a deferral reason."""
    text = _ADDRESS.sub(' ', str(text or ''))
    return [match.group(2) for match in _CODE_IN_TEXT.finditer(text)]


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
    """Suppressions on and "Handle failed mail automatically" on."""
    return settings.is_feature_enabled('suppressions') and bool(settings.suppression_enabled)
