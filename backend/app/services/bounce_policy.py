import logging
import re
from typing import FrozenSet, List, Optional

from ..config import settings

logger = logging.getLogger(__name__)

HARD_ACTIONS = ('suppress', 'delete', 'ignore')
SOFT_ACTIONS = ('suppress', 'count', 'ignore')
_warned = set()

_CODE = re.compile(r'^[45]\.\d{1,3}\.\d{1,3}$')
_CODE_IN_TEXT = re.compile(r'(?<![\w.<@-])([45])\d\d[ -]\s*(\1\.\d{1,3}\.\d{1,3})(?![\w.@>-])')
_ADDRESS = re.compile(r'<[^<>]*>|\S*@\S*')
EXCLUDED_CODES_KEYS = {'5': 'suppression_hard_bounce_excluded_codes', '4': 'suppression_soft_bounce_excluded_codes'}
STANDARD_CODES_KEYS = {'5': 'suppression_hard_bounce_standard_codes', '4': 'suppression_soft_bounce_standard_codes'}

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
    return [part for part in re.split(r'[\s,]+', str(value or '')) if part]


def bad_code(code: str, kind: str) -> bool:
    return not _CODE.match(code) or code[0] != kind


def _canonical(code: str) -> str:
    return '.'.join(str(int(part)) for part in code.split('.'))


def normalize_codes(value, kind: str) -> str:
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
    code = _canonical(code)
    subject = code.rsplit('.', 1)[0] + '.x'
    return any(entry in (code, subject) for entry in STANDARD_CODES.get(code[0], ()))


def standard_codes_on(kind: str) -> bool:
    return bool(getattr(settings, STANDARD_CODES_KEYS[kind], True))


def code_excluded(dsn: str) -> bool:
    dsn = str(dsn or '').strip()
    if not dsn or dsn[0] not in EXCLUDED_CODES_KEYS or bad_code(dsn, dsn[0]):
        return False
    kind = dsn[0]
    return (standard_codes_on(kind) and standard_code(dsn)) or _canonical(dsn) in excluded_codes(kind)


def codes_in_text(text: str) -> List[str]:
    text = _ADDRESS.sub(' ', str(text or ''))
    return [match.group(2) for match in _CODE_IN_TEXT.finditer(text)]


def rspamd_sync_on() -> bool:
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
    action = _known('SUPPRESSION_HARD_BOUNCE_ACTION', settings.suppression_hard_bounce_action, HARD_ACTIONS)
    on = rspamd_sync_on() if sync_on is None else sync_on
    return 'delete' if action == 'suppress' and not on else action


def soft_action(sync_on: Optional[bool] = None) -> str:
    action = _known('SUPPRESSION_SOFT_BOUNCE_ACTION', settings.suppression_soft_bounce_action, SOFT_ACTIONS)
    on = rspamd_sync_on() if sync_on is None else sync_on
    return 'ignore' if action != 'ignore' and not on else action


def cleanup_blocks() -> bool:
    return bool(settings.queue_cleanup_enabled and settings.queue_cleanup_block and rspamd_sync_on())


def handling_on() -> bool:
    return settings.is_feature_enabled('suppressions') and bool(settings.suppression_enabled)
