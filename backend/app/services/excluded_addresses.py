"""Excluded addresses (BLACKLIST_EMAILS): mail to or from them is not stored
or shown in Messages.

One definition for every writer, reader and cleanup of the message tables
(MessageCorrelation, PostfixLog, RspamdLog), so they all leave out the same
rows. The raw service logs (the Logs page) keep every line on purpose.

An address matches when it equals a listed one after trimming and lowering.
A Postfix line is listed when its sender, recipient or orig_to is listed, and
every line of the same queue id within QUEUE_WINDOW of a listed line belongs
to the same message and is left out with it. The window keeps a queue id that
Postfix reused days later, for another message, out of it.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy import and_, case, cast, exists, func, literal, not_, or_, select, true
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import aliased

from ..config import settings
from ..models import MessageCorrelation, PostfixLog, RspamdLog

logger = logging.getLogger(__name__)

# Every character Python's str.strip() removes around an address (str.isspace),
# so the SQL match hides exactly what is_listed hides
BLANKS = "".join(chr(c) for c in range(0x110000) if chr(c).isspace())

QUEUE_WINDOW = timedelta(days=1)

# Rows deleted per statement by the cleanup
CHUNK = 1000


def listed() -> List[str]:
    """The listed addresses, trimmed and lowered. An address that was not listed
    the last time asks for a full cleanup pass, whatever changed the settings."""
    global _last_listed
    hidden = settings.blacklist_emails_list
    current = frozenset(hidden)
    if not current <= _last_listed:
        request_full_pass()
    _last_listed = current
    return hidden


def is_listed(address: Optional[str]) -> bool:
    if not address or not isinstance(address, str):
        return False
    hidden = listed()
    return bool(hidden) and address.strip().lower() in hidden


def any_listed(*addresses) -> bool:
    return any(is_listed(a) for a in addresses)


def postfix_line_listed(sender, recipient, message, orig_to=None) -> bool:
    """A Postfix line (as stored or as parsed) that names a listed address."""
    if any_listed(sender, recipient, orig_to):
        return True
    text = (message or '').lower()
    return any(f'orig_to=<{a}>' in text for a in listed())


# ── SQL ────────────────────────────────────────────────────────────────────

def _norm(column):
    return func.lower(func.btrim(column, BLANKS))


def _column_listed(column, hidden):
    return and_(column.isnot(None), _norm(column).in_(hidden))


def correlation_visible(model=MessageCorrelation):
    """Deliveries whose own sender and recipient are not listed."""
    hidden = listed()
    if not hidden:
        return true()
    return not_(or_(_column_listed(model.sender, hidden), _column_listed(model.recipient, hidden)))


def _postfix_listed(model, hidden):
    message = func.lower(func.coalesce(model.message, ''))
    return or_(_column_listed(model.sender, hidden), _column_listed(model.recipient, hidden),
               *[message.contains(f'orig_to=<{a}>', autoescape=True) for a in hidden])


def postfix_line_visible(model=PostfixLog):
    """Postfix lines that are not listed and not in a listed line's queue occurrence."""
    hidden = listed()
    if not hidden:
        return true()
    other = aliased(PostfixLog)
    same_message = exists().where(
        other.queue_id == model.queue_id,
        other.time >= model.time - QUEUE_WINDOW,
        other.time <= model.time + QUEUE_WINDOW,
        _postfix_listed(other, hidden),
    )
    return not_(or_(_postfix_listed(model, hidden), and_(model.queue_id.isnot(None), same_message)))


def _recipients_listed(column, hidden):
    # Only a JSON array holds recipients; any other value (or NULL) names none
    array = case((func.jsonb_typeof(column) == 'array', column), else_=cast(literal('[]'), JSONB))
    elements = func.jsonb_array_elements_text(array).table_valued('value').alias('rcpt')
    return exists(select(literal(1)).select_from(elements).where(_norm(elements.c.value).in_(hidden)))


def rspamd_visible(model=RspamdLog):
    """Rspamd entries with no listed sender and no listed recipient."""
    hidden = listed()
    if not hidden:
        return true()
    return not_(or_(_column_listed(model.sender_smtp, hidden), _recipients_listed(model.recipients_smtp, hidden)))


# ── In Python, for rows already loaded ────────────────────────────────────

def visible_postfix_lines(lines: list) -> list:
    """The lines of loaded PostfixLog rows, without listed ones and their queue occurrences."""
    if not listed():
        return lines
    marks = [(l.queue_id, l.time) for l in lines if postfix_line_listed(l.sender, l.recipient, l.message)]
    if not marks:
        return lines

    def hidden(line) -> bool:
        if postfix_line_listed(line.sender, line.recipient, line.message):
            return True
        return bool(line.queue_id) and any(
            q == line.queue_id and t is not None and line.time is not None and abs(line.time - t) <= QUEUE_WINDOW
            for q, t in marks)
    return [l for l in lines if not hidden(l)]


def visible_recipients(recipients) -> list:
    return [r for r in (recipients or []) if not is_listed(r)] if isinstance(recipients, list) else []


# ── Ingest: queue ids seen with a listed address ───────────────────────────
# A queue's lines can come in different pages: the line naming the address
# may be dropped in one page while "message-id=" or "removed" come in another.
# The queue ids are remembered for QUEUE_WINDOW (in this process).

_listed_queues: Dict[str, datetime] = {}


def remember_listed_queue(queue_id: str, when: datetime) -> None:
    seen = _listed_queues.get(queue_id)
    if seen is None or when > seen:
        _listed_queues[queue_id] = when


def queue_was_listed(queue_id: Optional[str], when: datetime) -> bool:
    seen = _listed_queues.get(queue_id) if queue_id else None
    return seen is not None and abs(when - seen) <= QUEUE_WINDOW


def forget_old_queues(now: datetime) -> None:
    for queue_id in [q for q, t in _listed_queues.items() if now - t > QUEUE_WINDOW]:
        _listed_queues.pop(queue_id, None)


def delete_queue_occurrences(db, occurrences: Iterable[Tuple[str, datetime]]) -> Tuple[int, int]:
    """Delete the Postfix lines and deliveries of these queue occurrences.

    occurrence: (queue_id, time of a listed line). A line or delivery of the
    queue id within QUEUE_WINDOW of that time is part of the message.
    Returns (Postfix lines, deliveries) deleted.
    """
    occurrences = sorted({(q, t) for q, t in occurrences if q and t is not None})
    lines = deliveries = 0
    for i in range(0, len(occurrences), 200):
        part = occurrences[i:i + 200]
        seen_at = func.coalesce(MessageCorrelation.first_seen, MessageCorrelation.created_at)
        deliveries += db.query(MessageCorrelation).filter(or_(*[
            and_(MessageCorrelation.queue_id == q, seen_at >= t - QUEUE_WINDOW, seen_at <= t + QUEUE_WINDOW)
            for q, t in part])).delete(synchronize_session=False)
        lines += db.query(PostfixLog).filter(or_(*[
            and_(PostfixLog.queue_id == q, PostfixLog.time >= t - QUEUE_WINDOW, PostfixLog.time <= t + QUEUE_WINDOW)
            for q, t in part])).delete(synchronize_session=False)
    return lines, deliveries


# ── Cleanup ────────────────────────────────────────────────────────────────

def cleanup(db, since: Optional[datetime] = None) -> Optional[Dict[str, int]]:
    """Delete what the message tables still hold for listed addresses.

    since: only rows whose log time is from then on (the light pass of every
    correlation run, which catches a page stored with the list before a change);
    None for all of them. Each step commits in chunks. A list that changes
    while it runs stops it (the next pass starts over with the new list).
    Returns the counts, or None when stopped.
    """
    hidden = listed()
    if not hidden:
        return {}
    current = set(hidden)

    def still_current() -> bool:
        return set(listed()) == current

    counts = {'deliveries': 0, 'postfix': 0, 'rspamd': 0, 'detached': 0}

    # 1. Deliveries whose own sender or recipient is listed
    query = db.query(MessageCorrelation.id).filter(not_(correlation_visible()))
    if since is not None:
        query = query.filter(MessageCorrelation.first_seen >= since)
    ids = [r[0] for r in query.all()]
    for i in range(0, len(ids), CHUNK):
        if not still_current():
            return None
        counts['deliveries'] += db.query(MessageCorrelation).filter(
            MessageCorrelation.id.in_(ids[i:i + CHUNK])).delete(synchronize_session=False)
        db.commit()

    # 2. Listed Postfix lines, the rest of their queue occurrence, and its deliveries
    query = db.query(PostfixLog.id, PostfixLog.queue_id, PostfixLog.time).filter(_postfix_listed(PostfixLog, hidden))
    if since is not None:
        query = query.filter(PostfixLog.time >= since)
    rows = query.all()
    occurrences = [(q, t) for _, q, t in rows if q]
    for i in range(0, len(occurrences), CHUNK):
        if not still_current():
            return None
        lines, deliveries = delete_queue_occurrences(db, occurrences[i:i + CHUNK])
        counts['postfix'] += lines
        counts['deliveries'] += deliveries
        db.commit()
    queueless = [r[0] for r in rows if not r[1]]
    for i in range(0, len(queueless), CHUNK):
        if not still_current():
            return None
        counts['postfix'] += db.query(PostfixLog).filter(
            PostfixLog.id.in_(queueless[i:i + CHUNK])).delete(synchronize_session=False)
        db.commit()

    # 3. Rspamd entries with a listed sender or recipient. A delivery to
    # someone else keeps its row, without the link to the deleted entry
    query = db.query(RspamdLog.id).filter(not_(rspamd_visible()))
    if since is not None:
        query = query.filter(RspamdLog.time >= since)
    ids = [r[0] for r in query.all()]
    for i in range(0, len(ids), CHUNK):
        if not still_current():
            return None
        part = ids[i:i + CHUNK]
        counts['detached'] += db.query(MessageCorrelation).filter(
            MessageCorrelation.rspamd_log_id.in_(part)).update(
            {MessageCorrelation.rspamd_log_id: None}, synchronize_session=False)
        counts['rspamd'] += db.query(RspamdLog).filter(RspamdLog.id.in_(part)).delete(synchronize_session=False)
        db.commit()
    return counts


# A full pass is due at startup and after a settings change adds an address
# (listed() notices it). The correlation job runs it (one at a time). A
# request that comes while a pass runs is not answered by that pass: it
# started with the older list
_requested = 1
_done = 0
_last_listed: frozenset = frozenset()


def full_pass_due() -> Optional[int]:
    """The request a full pass now answers, or None when none is due."""
    return _requested if _requested != _done else None


def request_full_pass() -> None:
    global _requested
    _requested += 1


def full_pass_done(request: int) -> None:
    global _done
    _done = request
