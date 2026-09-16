"""
Parser for Dovecot LMTP/LDA delivery log lines (issue #65).

Postfix hands a message to Dovecot over LMTP and then logs ``status=sent``,
which is where the existing correlation stops - so a message dropped by a
Sieve ``discard`` rule was reported as *delivered*. Dovecot logs the actual
outcome of that last hop, and every relevant line carries the ``msgid=`` of
the message, which is exactly the key the correlation is already built on.

Recognised line shapes (the mailcow API returns them in ``raw_data.message``,
already stripped of the syslog timestamp/host prefix)::

    lmtp(user@example.com)<123><SessID>: sieve: msgid=<x@y>: discarded message
    lmtp(user@example.com)<123><SessID>: sieve: msgid=<x@y>: marked message to be
        discarded if not explicitly delivered (discard action)
    lmtp(user@example.com)<123><SessID>: sieve: msgid=<x@y>: stored mail into mailbox 'Junk'
    lmtp(user@example.com)<123><SessID>: sieve: msgid=<x@y>: rejected message from <s@d> (reason)
    lmtp(user@example.com)<123><SessID>: sieve: msgid=<x@y>: forwarded to <other@d>
    lmtp(user@example.com)<123><SessID>: msgid=<x@y>: saved mail to INBOX
    lmtp(user@example.com)<123><SessID>: msgid=<x@y>: save failed to INBOX: Quota exceeded ...

Verdicts returned in ``verdict``:

``stored``            message was written to a mailbox (``mailbox`` names it)
``discarded``         Dovecot reported the message as dropped
``discard_pending``   Sieve ran ``discard``; only a final delivery still saves it
``rejected``          Sieve rejected the message back to the sender
``forwarded``         Sieve redirected the message elsewhere
``failed``            the message could not be stored (quota, missing folder, ...)

``discard_pending`` is deliberately kept apart from ``discarded``: the line says
"if not explicitly delivered", so a script combining ``fileinto`` with
``discard`` does deliver the message. Callers resolve it per delivery - see
``resolve_session_verdicts``.
"""
import re
from typing import Any, Dict, List, Optional

# lmtp(user@example.com)<pid><session>: rest   /   lda(user@example.com): rest
# Older Dovecot writes lmtp(12345, user@example.com); the user is then the part
# after the comma.
_PREFIX_RE = re.compile(
    r'^(?:dovecot:\s*)?(?:lmtp|lda)\((?P<user>[^)]*)\)(?P<ids>(?:<[^>]*>)*)\s*:\s*(?P<rest>.*)$',
    re.IGNORECASE
)
_SESSION_RE = re.compile(r'<([^>]*)>')
_MSGID_RE = re.compile(r'msgid=<([^>]+)>', re.IGNORECASE)

_STORED_MAILBOX_RE = re.compile(r"stored mail into mailbox '([^']*)'", re.IGNORECASE)
_SAVED_TO_RE = re.compile(r'saved mail to (\S+)', re.IGNORECASE)
_REJECT_REASON_RE = re.compile(r'rejected message.*?\((.+)\)\s*$', re.IGNORECASE)
_FORWARD_TARGET_RE = re.compile(r'forwarded to <?([^>\s]+)>?', re.IGNORECASE)
_SAVE_FAILED_RE = re.compile(r'save failed to (\S+?):\s*(.+)$', re.IGNORECASE)
_STORE_FAILED_RE = re.compile(r"failed to store into mailbox '([^']*)':\s*(.+)$", re.IGNORECASE)

# Severity order used when one message produced several verdicts (multiple
# recipients, or a Sieve script running several actions). Higher wins.
VERDICT_SEVERITY = {
    'stored': 0,
    'forwarded': 1,
    'failed': 2,
    'discarded': 3,
    'rejected': 4,
}

# Verdicts that mean the message never reached the mailbox it was addressed to.
NON_DELIVERY_VERDICTS = frozenset({'discarded', 'rejected', 'failed'})


def _extract_user(raw_user: str) -> Optional[str]:
    """Pull the mailbox address out of the lmtp(...) prefix."""
    candidate = raw_user.strip()
    if ',' in candidate:
        candidate = candidate.rsplit(',', 1)[-1].strip()
    return candidate if '@' in candidate else None


def parse_dovecot_message(message: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Parse a single Dovecot log message into a delivery verdict.

    Returns None for every line that is not an LMTP/LDA delivery event with a
    usable Message-ID - which is the vast majority of Dovecot output (IMAP
    sessions, auth, connection noise) and must stay cheap to skip.
    """
    if not message:
        return None

    # Cheap pre-filter before the regex work: every line we care about names a
    # Message-ID, and Dovecot logs "msgid=unspecified" when there was none.
    if 'msgid=' not in message:
        return None

    prefix_match = _PREFIX_RE.match(message.strip())
    if not prefix_match:
        return None

    msgid_match = _MSGID_RE.search(prefix_match.group('rest'))
    if not msgid_match:
        return None

    message_id = msgid_match.group(1).strip()
    if not message_id:
        return None

    rest = prefix_match.group('rest')
    sessions = _SESSION_RE.findall(prefix_match.group('ids') or '')

    result: Dict[str, Any] = {
        'message_id': message_id,
        'recipient': _extract_user(prefix_match.group('user') or ''),
        # The last <...> token is the LMTP session id; the first one is the pid.
        'session': sessions[-1] if sessions else None,
        'verdict': None,
        'mailbox': None,
        'detail': None,
    }

    lowered = rest.lower()

    # Order matters: the specific failure shapes have to be tested before the
    # generic "stored"/"discarded" wording they can contain.
    store_failed = _STORE_FAILED_RE.search(rest)
    if store_failed:
        result['verdict'] = 'failed'
        result['mailbox'] = store_failed.group(1)
        result['detail'] = store_failed.group(2).strip()
        return result

    save_failed = _SAVE_FAILED_RE.search(rest)
    if save_failed:
        result['verdict'] = 'failed'
        result['mailbox'] = save_failed.group(1)
        result['detail'] = save_failed.group(2).strip()
        return result

    if 'rejected message' in lowered:
        result['verdict'] = 'rejected'
        reason = _REJECT_REASON_RE.search(rest)
        if reason:
            result['detail'] = reason.group(1).strip()
        return result

    if 'forwarded to' in lowered:
        result['verdict'] = 'forwarded'
        target = _FORWARD_TARGET_RE.search(rest)
        if target:
            result['detail'] = target.group(1).strip()
        return result

    if 'marked message to be discarded' in lowered:
        result['verdict'] = 'discard_pending'
        return result

    if 'discarded message' in lowered:
        result['verdict'] = 'discarded'
        return result

    stored = _STORED_MAILBOX_RE.search(rest)
    if stored:
        result['verdict'] = 'stored'
        result['mailbox'] = stored.group(1)
        return result

    saved = _SAVED_TO_RE.search(rest)
    if saved:
        result['verdict'] = 'stored'
        result['mailbox'] = saved.group(1).rstrip(':')
        return result

    return None


def resolve_session_verdicts(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Collapse the parsed lines of one message into one verdict per delivery.

    Dovecot writes several lines per delivery. Postfix delivers multiple
    recipients over a single LMTP session, and every recipient logs with that
    same session id - so the lines are grouped by (session, recipient) and each
    recipient gets its own verdict.

    Within a delivery a completed store cancels a pending ``discard``
    regardless of the order the lines appear in - "discarded if not explicitly
    delivered" is exactly what a script running ``fileinto`` plus ``discard``
    means, and the raw logs worker inserts pages newest-first, so line order
    within the same second is not reliable. An explicit ``discarded message``
    line still wins over a store. When several definite verdicts remain, the
    most severe one (see ``VERDICT_SEVERITY``) describes the delivery.

    Args:
        events: parsed events for a single Message-ID, each with an extra
            ``time`` key, in any order.

    Returns:
        One resolved event per delivery, ordered by time.
    """
    groups: Dict[Any, List[Dict[str, Any]]] = {}
    for event in events:
        key = (event.get('session'), event.get('recipient'))
        groups.setdefault(key, []).append(event)

    resolved: List[Dict[str, Any]] = []
    for group in groups.values():
        # discard_pending is only a marker: it loses to any definite verdict
        # and only counts when nothing else happened in this delivery.
        definite = [e for e in group if e['verdict'] != 'discard_pending']
        if definite:
            # Iterate newest-first so that among equally severe events the
            # latest one supplies the mailbox/detail shown for this delivery.
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
    """Return the most severe verdict of a message's deliveries."""
    ranked = [v for v in verdicts if v in VERDICT_SEVERITY]
    if not ranked:
        return None
    return max(ranked, key=lambda v: VERDICT_SEVERITY[v])
