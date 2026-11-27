import re
from typing import Any, Dict, List, Optional, Tuple

_PREFIX_RE = re.compile(
    r'^(?:dovecot:\s*)?(?:lmtp|lda)\((?P<user>[^)]*)\)(?P<ids>(?:<[^>]*>)*)\s*:\s*(?P<rest>.*)$',
    re.IGNORECASE
)
_SESSION_RE = re.compile(r'<([^>]*)>')

_ACTION_START_RE = re.compile(
    r"(?:[a-z]+ action:\s*)?"
    r"(?:stored mail into mailbox|saved mail to|discarded message|marked message to be discarded"
    r"|rejected message|forwarded to|save failed to|failed to store into mailbox)",
    re.IGNORECASE
)
_ACTION_PREFIX_RE = re.compile(r'[a-z]+ action:\s*', re.IGNORECASE)

_STORED_MAILBOX_RE = re.compile(r"stored mail into mailbox '([^']*)'", re.IGNORECASE)
_SAVED_TO_RE = re.compile(r'saved mail to (\S+)', re.IGNORECASE)
_REJECT_REASON_RE = re.compile(r'rejected message.*?\((.+)\)\s*$', re.IGNORECASE)
_FORWARD_TARGET_RE = re.compile(r'forwarded to <?([^>\s]+)>?', re.IGNORECASE)
_SAVE_FAILED_RE = re.compile(r'save failed to (\S+?):\s*(.+)$', re.IGNORECASE)
_STORE_FAILED_RE = re.compile(r"failed to store into mailbox '([^']*)':\s*(.+)$", re.IGNORECASE)

VERDICT_SEVERITY = {
    'stored': 0,
    'forwarded': 1,
    'failed': 2,
    'discarded': 3,
    'rejected': 4,
}

NON_DELIVERY_VERDICTS = frozenset({'discarded', 'rejected', 'failed'})


def _extract_user(raw_user: str) -> Optional[str]:
    candidate = raw_user.strip()
    if ',' in candidate:
        candidate = candidate.rsplit(',', 1)[-1].strip()
    return candidate if '@' in candidate else None


def dovecot_line_user(message: Optional[str]) -> Optional[str]:
    match = _PREFIX_RE.match((message or '').strip())
    return _extract_user(match.group('user') or '') if match else None


def parse_dovecot_message(message: Optional[str]) -> Optional[Dict[str, Any]]:
    if not message:
        return None

    if 'msgid=' not in message:
        return None

    prefix_match = _PREFIX_RE.match(message.strip())
    if not prefix_match:
        return None

    split = _split_msgid_and_action(prefix_match.group('rest'))
    if not split:
        return None
    message_id, action = split
    if not message_id:
        return None

    sessions = _SESSION_RE.findall(prefix_match.group('ids') or '')

    result: Dict[str, Any] = {
        'message_id': message_id,
        'recipient': _extract_user(prefix_match.group('user') or ''),
        'session': sessions[-1] if sessions else None,
        'verdict': None,
        'mailbox': None,
        'detail': None,
    }

    prefix = _ACTION_PREFIX_RE.match(action)
    if prefix:
        action = action[prefix.end():]
    lowered = action.lower()

    store_failed = _STORE_FAILED_RE.match(action)
    if store_failed:
        result['verdict'] = 'failed'
        result['mailbox'] = store_failed.group(1)
        result['detail'] = store_failed.group(2).strip()
        return result

    save_failed = _SAVE_FAILED_RE.match(action)
    if save_failed:
        result['verdict'] = 'failed'
        result['mailbox'] = save_failed.group(1)
        result['detail'] = save_failed.group(2).strip()
        return result

    if lowered.startswith('rejected message'):
        result['verdict'] = 'rejected'
        reason = _REJECT_REASON_RE.match(action)
        if reason:
            result['detail'] = reason.group(1).strip()
        return result

    if lowered.startswith('forwarded to'):
        result['verdict'] = 'forwarded'
        target = _FORWARD_TARGET_RE.match(action)
        if target:
            result['detail'] = target.group(1).strip()
        return result

    if lowered.startswith('marked message to be discarded'):
        result['verdict'] = 'discard_pending'
        return result

    if lowered.startswith('discarded message'):
        result['verdict'] = 'discarded'
        return result

    stored = _STORED_MAILBOX_RE.match(action)
    if stored:
        result['verdict'] = 'stored'
        result['mailbox'] = stored.group(1)
        return result

    saved = _SAVED_TO_RE.match(action)
    if saved:
        result['verdict'] = 'stored'
        result['mailbox'] = saved.group(1).rstrip(':')
        return result

    return None


def _split_msgid_and_action(rest: str) -> Optional[Tuple[str, str]]:
    start = rest.lower().find('msgid=<')
    if start < 0:
        return None
    body = rest[start + len('msgid=<'):]
    boundary = None
    pos = body.find('>: ')
    while pos != -1:
        if _ACTION_START_RE.match(body, pos + 3):
            boundary = pos
        pos = body.find('>: ', pos + 1)
    if boundary is None:
        return None
    return body[:boundary].strip(), body[boundary + 3:]


def resolve_session_verdicts(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups: Dict[Any, List[Dict[str, Any]]] = {}
    for event in events:
        key = (event.get('session'), event.get('recipient'))
        groups.setdefault(key, []).append(event)

    resolved: List[Dict[str, Any]] = []
    for group in groups.values():
        definite = [e for e in group if e['verdict'] != 'discard_pending']
        if definite:
            # Without the newest-first sort, an older event's mailbox and detail describe the delivery
            winner = max(
                sorted(definite, key=lambda e: e['time'], reverse=True),
                key=lambda e: VERDICT_SEVERITY.get(e['verdict'], -1)
            )
            resolved.append(dict(winner))
        else:
            out = dict(sorted(group, key=lambda e: e['time'])[-1])
            out['verdict'] = 'discarded'
            resolved.append(out)

    return sorted(resolved, key=lambda e: e['time'])


def pick_worst_verdict(verdicts: List[str]) -> Optional[str]:
    ranked = [v for v in verdicts if v in VERDICT_SEVERITY]
    if not ranked:
        return None
    return max(ranked, key=lambda v: VERDICT_SEVERITY[v])
