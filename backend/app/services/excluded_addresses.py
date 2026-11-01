"""Excluded addresses (BLACKLIST_EMAILS): mail to or from them is not stored
or shown in Messages.

One definition for every writer, reader and cleanup of the message tables
(MessageCorrelation, PostfixLog, RspamdLog), so they all leave out the same
rows. The raw service logs (the Logs page) keep every line on purpose.

An address matches when it equals a listed one after trimming and lowering.
A Postfix line is listed when its sender, recipient or orig_to is listed, and
every line of the same queue id that is the same message (same_message: within
QUEUE_WINDOW of a listed line, and no "removed" between them) is left out
with it.

Postfix reuses a queue id once the message that had it left the queue, which
qmgr logs as "removed". So a "removed" between two lines of a queue id proves
two messages, and the next message is never deleted, dropped or hidden for
the one before it. Without a "removed", the window keeps a queue id that
Postfix reused days later out of the message.
"""
import logging
import threading
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy import and_, case, cast, exists, func, literal, not_, or_, select, true
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import aliased

from ..config import settings
from ..correlation import END, naive_utc, postfix_line_kind
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


def correlation_listed(correlation) -> bool:
    """A delivery whose own sender or recipient is listed, in either form of
    the recipient (written_recipients: the address the sender wrote)."""
    written = correlation.written_recipients if isinstance(correlation.written_recipients, dict) else {}
    return any_listed(correlation.sender, correlation.recipient, *written.values())


# A delivery line's own fields come before "status="; what follows is the
# receiving server's reply, which can say anything
_STATUS = ' status='


def postfix_line_listed(sender, recipient, message, orig_to=None) -> bool:
    """A Postfix line (as stored or as parsed) that names a listed address.

    orig_to has no column of its own: in a stored line it is read from the
    line's fields, never from the reply."""
    if any_listed(sender, recipient, orig_to):
        return True
    fields = (message or '').lower().split(_STATUS, 1)[0]
    return any(f'orig_to=<{a}>' in fields for a in listed())


def postfix_text_listed(message) -> bool:
    """A copied Postfix line whose own fields (from=, to=, orig_to=) name a listed address."""
    fields = str(message or '').lower().split(_STATUS, 1)[0]
    return any(f'from=<{a}>' in fields or f'to=<{a}>' in fields for a in listed())


# ── One message of a queue id ──────────────────────────────────────────────

def is_removed(program, message, queue_id) -> bool:
    """qmgr's "removed" line: the message left the queue (correlation's END kind)."""
    return bool(queue_id) and postfix_line_kind(
        SimpleNamespace(program=program, message=message, queue_id=queue_id)) == END


def _second(value: datetime) -> datetime:
    return naive_utc(value).replace(microsecond=0)


def separated(t, w, removed: Iterable[datetime]) -> bool:
    """Two times of one queue id are two messages: qmgr logged "removed" for
    the queue id in a second from the earlier one's up to before the later
    one's. Postfix logs whole seconds, and the order of lines inside one is
    unknown, so a "removed" in the later time's own second proves nothing (the
    next message may have started in it)."""
    if t is None or w is None:
        return False
    a, b = sorted((_second(t), _second(w)))
    return a < b and any(a <= _second(r) < b for r in removed if r is not None)


def same_message(t, w, removed: Iterable[datetime]) -> bool:
    """Two times of one queue id are one message: within QUEUE_WINDOW, and not separated()."""
    if t is None or w is None:
        return False
    return abs(naive_utc(t) - naive_utc(w)) <= QUEUE_WINDOW and not separated(t, w, removed)


# ── SQL ────────────────────────────────────────────────────────────────────

def _norm(column):
    return func.lower(func.btrim(column, BLANKS))


def _column_listed(column, hidden):
    return and_(column.isnot(None), _norm(column).in_(hidden))


def _written_listed(column, hidden):
    # Only a JSON object holds written addresses; any other value (or NULL) names none
    obj = case((func.jsonb_typeof(column) == 'object', column), else_=cast(literal('{}'), JSONB))
    rows = func.jsonb_each_text(obj).table_valued('key', 'value').alias('written')
    return exists(select(literal(1)).select_from(rows).where(_norm(rows.c.value).in_(hidden)))


def correlation_visible(model=MessageCorrelation):
    """Deliveries whose own sender and recipient (in either form) are not listed."""
    hidden = listed()
    if not hidden:
        return true()
    return not_(or_(_column_listed(model.sender, hidden), _column_listed(model.recipient, hidden),
                    _written_listed(model.written_recipients, hidden)))


def _postfix_listed(model, hidden):
    fields = func.split_part(func.lower(func.coalesce(model.message, '')), _STATUS, 1)
    return or_(_column_listed(model.sender, hidden), _column_listed(model.recipient, hidden),
               *[fields.contains(f'orig_to=<{a}>', autoescape=True) for a in hidden])


def postfix_listed(model, hidden):
    """The Postfix line names one of these listed addresses (sender, recipient or orig_to)."""
    return _postfix_listed(model, hidden)


def removed_line(model):
    """SQL for is_removed()."""
    return and_(model.queue_id.isnot(None),
                or_(model.program == 'qmgr', model.program.like('%/qmgr')),
                or_(model.message.startswith(model.queue_id + ': removed'), model.message.startswith('removed')))


def _removed_between(r_queue_id, r_time, queue_id, t, w):
    """SQL conditions of separated() on one removed line (r_queue_id, r_time).
    Stored times are whole seconds (the ingest stores the log's epoch second),
    so they are compared as they are."""
    return and_(r_queue_id == queue_id, r_time >= func.least(t, w), r_time < func.greatest(t, w))


def separated_sql(queue_id, t, w):
    """SQL for separated(): a stored "removed" line of queue_id between t and w."""
    r = aliased(PostfixLog)
    # Nested two levels deep: the line and the listed line come from the
    # enclosing queries, never from a FROM of its own
    return exists().where(removed_line(r), _removed_between(r.queue_id, r.time, queue_id, t, w)).correlate_except(r)


def postfix_line_visible(model=PostfixLog):
    """Postfix lines that are not listed and not the same message as a listed line."""
    hidden = listed()
    if not hidden:
        return true()
    other = aliased(PostfixLog)
    same_message = exists().where(
        other.queue_id == model.queue_id,
        other.time >= model.time - QUEUE_WINDOW,
        other.time <= model.time + QUEUE_WINDOW,
        _postfix_listed(other, hidden),
        not_(separated_sql(model.queue_id, other.time, model.time)),
    )
    return not_(or_(_postfix_listed(model, hidden), and_(model.queue_id.isnot(None), same_message)))


def postfix_line_visible_among(queue_ids, model=PostfixLog):
    """postfix_line_visible() for lines of a few queues only (a page's): the
    listed lines of those queues are found first, by the queue id index, and
    each line is checked against them. postfix_line_visible() checks each line
    against the whole table, which the planner may scan by time.

    queue_ids: a list, or a select of queue ids."""
    hidden = listed()
    if not hidden:
        return true()
    # MATERIALIZED: found once; inlined, PostgreSQL checks each line against the
    # table again (by the time index), which is what this avoids
    marks = select(PostfixLog.queue_id, PostfixLog.time).where(
        PostfixLog.queue_id.in_(queue_ids), _postfix_listed(PostfixLog, hidden)).cte('listed_marks').prefix_with('MATERIALIZED')
    # The "removed" lines of the queues that have a listed line (usually none)
    ends = select(PostfixLog.queue_id, PostfixLog.time).where(
        PostfixLog.queue_id.in_(select(marks.c.queue_id)), removed_line(PostfixLog)
    ).cte('listed_ends').prefix_with('MATERIALIZED')
    near = exists().where(marks.c.queue_id == model.queue_id,
                          marks.c.time >= model.time - QUEUE_WINDOW,
                          marks.c.time <= model.time + QUEUE_WINDOW,
                          not_(exists().where(_removed_between(ends.c.queue_id, ends.c.time, model.queue_id,
                                                               marks.c.time, model.time)).correlate_except(ends)))
    return not_(or_(_postfix_listed(model, hidden), and_(model.queue_id.isnot(None), near)))


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

def _marks_and_ends(lines) -> Tuple[Dict[str, list], Dict[str, list]]:
    """The times of the listed lines and of the "removed" lines, per queue id."""
    marks: Dict[str, list] = {}
    ends: Dict[str, list] = {}
    for l in lines:
        if not l.queue_id or l.time is None:
            continue
        if postfix_line_listed(l.sender, l.recipient, l.message):
            marks.setdefault(l.queue_id, []).append(l.time)
        elif is_removed(l.program, l.message, l.queue_id):
            ends.setdefault(l.queue_id, []).append(l.time)
    return marks, ends


def queue_lines(db, queue_id) -> Optional[list]:
    """Every stored line of a queue id, for the checks below when an address is
    listed: a detail view shows one message's lines, but whether a listed line
    is the same message is decided on all of them, as the lists decide it."""
    if not queue_id or not listed():
        return None
    return db.query(PostfixLog).filter(PostfixLog.queue_id == queue_id).all()


def visible_postfix_lines(lines: list, context: Optional[list] = None) -> list:
    """The lines of loaded PostfixLog rows, without listed ones and the lines
    that are the same message as a listed one. context: the lines to find the
    listed and "removed" lines in, when `lines` are not all of their queue."""
    if not listed():
        return lines
    marks, ends = _marks_and_ends(lines if context is None else context)

    def hidden(line) -> bool:
        if postfix_line_listed(line.sender, line.recipient, line.message):
            return True
        return bool(line.queue_id) and any(
            same_message(t, line.time, ends.get(line.queue_id, ())) for t in marks.get(line.queue_id, ()))
    return [l for l in lines if not hidden(l)]


def delivery_hidden(correlation, lines: list) -> bool:
    """A delivery of a listed address: by its own sender or recipient, or by a
    listed line (such as orig_to) among `lines` that is the same message."""
    if correlation_listed(correlation):
        return True
    at = correlation.first_seen or correlation.created_at
    if not correlation.queue_id or at is None:
        return False
    marks, ends = _marks_and_ends(l for l in lines if l.queue_id == correlation.queue_id)
    return any(same_message(t, at, ends.get(correlation.queue_id, ())) for t in marks.get(correlation.queue_id, ()))


def hidden_deliveries(db, legs) -> set:
    """The correlation keys of the legs delivery_hidden() hides, for many legs
    at once: by their own sender or recipient, or by a listed Postfix line (such
    as orig_to) that is the same message. One query whatever the number of
    legs, and one more only when a leg's queue id has a listed line."""
    hidden = listed()
    if not hidden:
        return set()
    found = {leg.correlation_key for leg in legs if correlation_listed(leg)}
    queued = [leg for leg in legs if leg.correlation_key not in found and leg.queue_id
              and (leg.first_seen or leg.created_at) is not None]
    if queued:
        marks: Dict[str, list] = {}
        for queue_id, time in db.query(PostfixLog.queue_id, PostfixLog.time).filter(
                PostfixLog.queue_id.in_(list({leg.queue_id for leg in queued})), PostfixLog.time.isnot(None),
                _postfix_listed(PostfixLog, hidden)).all():
            marks.setdefault(queue_id, []).append(time)
        ends = stored_ends(db, marks)
        for leg in queued:
            at = leg.first_seen or leg.created_at
            if any(same_message(time, at, ends.get(leg.queue_id, ())) for time in marks.get(leg.queue_id, [])):
                found.add(leg.correlation_key)
    return found


def stored_ends(db, times: Dict[str, list]) -> Dict[str, list]:
    """The times of the stored "removed" lines of these queue ids, within
    QUEUE_WINDOW of the given times of each (a "removed" further away cannot
    lie between two times of one message). One query."""
    times = {q: [t for t in ts if t is not None] for q, ts in times.items() if q}
    times = {q: ts for q, ts in times.items() if ts}
    if not times:
        return {}
    ends: Dict[str, list] = {}
    queue_ids = sorted(times)
    for i in range(0, len(queue_ids), 200):
        part = queue_ids[i:i + 200]
        rows = db.query(PostfixLog.queue_id, PostfixLog.time).filter(
            PostfixLog.queue_id.in_(part), removed_line(PostfixLog),
            PostfixLog.time >= min(min(times[q]) for q in part) - QUEUE_WINDOW,
            PostfixLog.time <= max(max(times[q]) for q in part) + QUEUE_WINDOW).all()
        for queue_id, time in rows:
            ends.setdefault(queue_id, []).append(time)
    return ends


def visible_recipients(recipients) -> list:
    return [r for r in (recipients or []) if not is_listed(r)] if isinstance(recipients, list) else []


# ── Ingest: queue ids seen with a listed address ───────────────────────────
# A queue's lines can come in different pages: the line naming the address
# may be dropped in one page while "message-id=" or "removed" come in another.
# Each occurrence (queue id, time of its listed line) is remembered, in this
# process, for QUEUE_WINDOW from when it was seen, whatever its log time: a
# catch-up of old lines needs it as much as the newest page. The ingest and
# the cleanup both add to it, from different threads.
#
# A listed message's own "removed" line is never stored (the ingest drops it,
# or the cleanup deletes it), so the time of each one is remembered too: it is
# what tells the next message on the queue id apart from the listed one.

_listed_queues: Dict[str, List[Tuple[datetime, datetime]]] = {}
_removed_queues: Dict[str, List[Tuple[datetime, datetime]]] = {}
_listed_queues_lock = threading.Lock()


def _remember(store, queue_id: str, when: datetime) -> None:
    now = datetime.utcnow()
    with _listed_queues_lock:
        seen = [(t, at) for t, at in store.get(queue_id, []) if t != when]
        store[queue_id] = seen + [(when, now)]


def remember_listed_queue(queue_id: str, when: datetime) -> None:
    _remember(_listed_queues, queue_id, when)


def remember_removed(queue_id: str, when: datetime) -> None:
    """A listed message's "removed" line that is not stored."""
    _remember(_removed_queues, queue_id, when)


def remembered_removed(queue_id: Optional[str]) -> List[datetime]:
    with _listed_queues_lock:
        return [t for t, _ in _removed_queues.get(queue_id, [])]


def remembered_listed(queue_ids: Iterable[Optional[str]]) -> Dict[str, List[datetime]]:
    """The remembered listed times of these queue ids, for those that have one."""
    with _listed_queues_lock:
        return {q: [t for t, _ in _listed_queues[q]] for q in set(queue_ids) if q in _listed_queues}


def queue_was_listed(queue_id: Optional[str], when: datetime, removed: Iterable[datetime] = ()) -> bool:
    """Whether a line of this queue id at this log time is the same message as
    a remembered listed line. removed: the "removed" times known besides the
    remembered ones (stored lines, the page being read)."""
    if not queue_id:
        return False
    with _listed_queues_lock:
        marks = [t for t, _ in _listed_queues.get(queue_id, [])]
        ends = [t for t, _ in _removed_queues.get(queue_id, [])]
    ends += list(removed)
    return any(same_message(t, when, ends) for t in marks)


_last_forget: Optional[datetime] = None


def forget_old_queues(now: datetime) -> None:
    """Drop what was remembered more than QUEUE_WINDOW ago (at most once a minute)."""
    global _last_forget
    with _listed_queues_lock:
        if _last_forget is not None and now - _last_forget < timedelta(minutes=1):
            return
        _last_forget = now
        for store in (_listed_queues, _removed_queues):
            for queue_id in list(store):
                kept = [(t, at) for t, at in store[queue_id] if now - at <= QUEUE_WINDOW]
                if kept:
                    store[queue_id] = kept
                else:
                    del store[queue_id]


def delete_queue_occurrences(db, occurrences: Iterable[Tuple[str, datetime]],
                             removed: Optional[Dict[str, List[datetime]]] = None) -> Tuple[int, int]:
    """Delete the Postfix lines and deliveries of these queue occurrences.

    occurrence: (queue_id, time of a listed line). A line or delivery of the
    queue id that is the same message as that time (same_message) is part of
    the message. The "removed" lines that decide it are the stored ones, the
    remembered ones and `removed` (queue id: times, from a page not stored
    yet). All occurrences of a queue id are decided before any of its rows is
    deleted, so deleting a listed message's own "removed" never joins the next
    message to it. Returns (Postfix lines, deliveries) deleted.
    """
    by_queue: Dict[str, list] = {}
    for q, t in occurrences:
        if q and t is not None:
            by_queue.setdefault(q, set()).add(naive_utc(t))
    # The evidence goes with them: a later line of the same message is
    # recognised by the ingest from this
    for q, times in by_queue.items():
        for t in times:
            remember_listed_queue(q, t)
    seen_at = func.coalesce(MessageCorrelation.first_seen, MessageCorrelation.created_at)
    lines = deliveries = 0
    queue_ids = sorted(by_queue)
    for i in range(0, len(queue_ids), 200):
        part = queue_ids[i:i + 200]
        spans = {q: (min(by_queue[q]) - QUEUE_WINDOW, max(by_queue[q]) + QUEUE_WINDOW) for q in part}
        rows = db.query(PostfixLog.id, PostfixLog.queue_id, PostfixLog.time, PostfixLog.program,
                        PostfixLog.message).filter(or_(*[
            and_(PostfixLog.queue_id == q, PostfixLog.time >= lo, PostfixLog.time <= hi)
            for q, (lo, hi) in spans.items()])).all()
        known = {q: remembered_removed(q) + list((removed or {}).get(q, ())) for q in part}
        for row in rows:
            if is_removed(row.program, row.message, row.queue_id):
                known[row.queue_id].append(row.time)
        doomed = [row for row in rows
                  if any(same_message(t, row.time, known[row.queue_id]) for t in by_queue[row.queue_id])]
        doomed_deliveries = [
            row.id for row in db.query(MessageCorrelation.id, MessageCorrelation.queue_id, seen_at.label('at')).filter(
                or_(*[and_(MessageCorrelation.queue_id == q, seen_at >= lo, seen_at <= hi)
                      for q, (lo, hi) in spans.items()])).all()
            if any(same_message(t, row.at, known[row.queue_id]) for t in by_queue[row.queue_id])]
        for row in doomed:
            if is_removed(row.program, row.message, row.queue_id):
                remember_removed(row.queue_id, row.time)
        ids = [row.id for row in doomed]
        for j in range(0, len(doomed_deliveries), CHUNK):
            deliveries += db.query(MessageCorrelation).filter(
                MessageCorrelation.id.in_(doomed_deliveries[j:j + CHUNK])).delete(synchronize_session=False)
        for j in range(0, len(ids), CHUNK):
            lines += db.query(PostfixLog).filter(PostfixLog.id.in_(ids[j:j + CHUNK])).delete(synchronize_session=False)
    return lines, deliveries


# ── Cleanup ────────────────────────────────────────────────────────────────

def _deliveries_to_delete(db, rows) -> List[int]:
    """Of the deliveries correlation_visible() hides, those step 1 deletes.

    One whose own sender or recipient is listed goes. One hidden only by an
    address in written_recipients goes only when none of its own Postfix lines
    is stored: that address was read from a Postfix line of its queue id, which
    could be another message's (a reused queue id). When its own lines are
    stored, step 2 deletes it if one of them names a listed address; if none
    does, it stays, hidden as before."""
    ids = []
    written_only = []
    for row in rows:
        at = row.first_seen or row.created_at
        if any_listed(row.sender, row.recipient) or not row.queue_id or at is None:
            ids.append(row.id)
        else:
            written_only.append((row, at))
    if not written_only:
        return ids
    times: Dict[str, list] = {}
    for row, at in written_only:
        times.setdefault(row.queue_id, []).append(at)
    queue_ids = sorted(times)
    lines: Dict[str, list] = {}
    for i in range(0, len(queue_ids), 200):
        for line in db.query(PostfixLog.queue_id, PostfixLog.time, PostfixLog.program, PostfixLog.message).filter(or_(*[
                and_(PostfixLog.queue_id == q, PostfixLog.time >= min(times[q]) - QUEUE_WINDOW,
                     PostfixLog.time <= max(times[q]) + QUEUE_WINDOW) for q in queue_ids[i:i + 200]])).all():
            lines.setdefault(line.queue_id, []).append(line)
    for row, at in written_only:
        own = lines.get(row.queue_id, [])
        ends = remembered_removed(row.queue_id) + [
            l.time for l in own if is_removed(l.program, l.message, l.queue_id)]
        if not any(same_message(at, l.time, ends) for l in own):
            ids.append(row.id)
    return ids

def cleanup(db) -> Optional[Dict[str, int]]:
    """Delete what the message tables still hold for listed addresses.

    The caller holds the ingest (scheduler). Each step commits in chunks. A
    list that changes while it runs stops it (the next pass starts over with
    the new list). Returns the counts, or None when stopped.
    """
    hidden = listed()
    if not hidden:
        return {}
    current = set(hidden)

    def still_current() -> bool:
        return set(listed()) == current

    counts = {'deliveries': 0, 'postfix': 0, 'rspamd': 0, 'detached': 0}

    # 1. Deliveries whose own sender or recipient (in either form) is listed
    query = db.query(MessageCorrelation.id, MessageCorrelation.queue_id, MessageCorrelation.sender,
                     MessageCorrelation.recipient, MessageCorrelation.first_seen,
                     MessageCorrelation.created_at).filter(not_(correlation_visible()))
    rows = query.all()
    ids = _deliveries_to_delete(db, rows)
    for i in range(0, len(ids), CHUNK):
        if not still_current():
            return None
        counts['deliveries'] += db.query(MessageCorrelation).filter(
            MessageCorrelation.id.in_(ids[i:i + CHUNK])).delete(synchronize_session=False)
        db.commit()

    # 2. Listed Postfix lines, the rest of their message, and its deliveries.
    # Whole queue ids per commit: a pass stopped half way never leaves a
    # queue id with a listed message's "removed" deleted and the rest not
    query = db.query(PostfixLog.id, PostfixLog.queue_id, PostfixLog.time).filter(_postfix_listed(PostfixLog, hidden))
    rows = query.all()
    marks: Dict[str, list] = {}
    for _, q, t in rows:
        if q:
            marks.setdefault(q, []).append((q, t))
    queue_ids = sorted(marks)
    for i in range(0, len(queue_ids), 200):
        if not still_current():
            return None
        lines, deliveries = delete_queue_occurrences(db, [m for q in queue_ids[i:i + 200] for m in marks[q]])
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


# A pass is due at startup and after a settings change adds an address
# (listed() notices it). The correlation job runs it (one at a time). A
# request that comes while a pass runs is not answered by that pass: it
# started with the older list
_requested = 1
_done = 0
_last_listed: frozenset = frozenset()


def full_pass_due() -> Optional[int]:
    """The request a pass now answers, or None when none is due."""
    return _requested if _requested != _done else None


def request_full_pass() -> None:
    global _requested
    _requested += 1


def full_pass_done(request: int) -> None:
    global _done
    _done = request
