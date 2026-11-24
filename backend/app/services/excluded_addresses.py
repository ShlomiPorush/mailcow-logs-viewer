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

BLANKS = "".join(chr(c) for c in range(0x110000) if chr(c).isspace())

QUEUE_WINDOW = timedelta(days=1)

CHUNK = 1000


def listed() -> List[str]:
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
    written = correlation.written_recipients if isinstance(correlation.written_recipients, dict) else {}
    return any_listed(correlation.sender, correlation.recipient, *written.values())


_STATUS = ' status='


def postfix_line_listed(sender, recipient, message, orig_to=None) -> bool:
    if any_listed(sender, recipient, orig_to):
        return True
    fields = (message or '').lower().split(_STATUS, 1)[0]
    return any(f'orig_to=<{a}>' in fields for a in listed())


def postfix_text_listed(message) -> bool:
    fields = str(message or '').lower().split(_STATUS, 1)[0]
    return any(f'from=<{a}>' in fields or f'to=<{a}>' in fields for a in listed())


def is_removed(program, message, queue_id) -> bool:
    return bool(queue_id) and postfix_line_kind(
        SimpleNamespace(program=program, message=message, queue_id=queue_id)) == END


def _second(value: datetime) -> datetime:
    return naive_utc(value).replace(microsecond=0)


def separated(t, w, removed: Iterable[datetime]) -> bool:
    if t is None or w is None:
        return False
    a, b = sorted((_second(t), _second(w)))
    return a < b and any(a <= _second(r) < b for r in removed if r is not None)


def same_message(t, w, removed: Iterable[datetime]) -> bool:
    if t is None or w is None:
        return False
    return abs(naive_utc(t) - naive_utc(w)) <= QUEUE_WINDOW and not separated(t, w, removed)


def _norm(column):
    return func.lower(func.btrim(column, BLANKS))


def _column_listed(column, hidden):
    return and_(column.isnot(None), _norm(column).in_(hidden))


def _written_listed(column, hidden):
    obj = case((func.jsonb_typeof(column) == 'object', column), else_=cast(literal('{}'), JSONB))
    rows = func.jsonb_each_text(obj).table_valued('key', 'value').alias('written')
    return exists(select(literal(1)).select_from(rows).where(_norm(rows.c.value).in_(hidden)))


def correlation_visible(model=MessageCorrelation):
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
    return _postfix_listed(model, hidden)


def removed_line(model):
    return and_(model.queue_id.isnot(None),
                or_(model.program == 'qmgr', model.program.like('%/qmgr')),
                or_(model.message.startswith(model.queue_id + ': removed'), model.message.startswith('removed')))


def _removed_between(r_queue_id, r_time, queue_id, t, w):
    return and_(r_queue_id == queue_id, r_time >= func.least(t, w), r_time < func.greatest(t, w))


def separated_sql(queue_id, t, w):
    r = aliased(PostfixLog)
    return exists().where(removed_line(r), _removed_between(r.queue_id, r.time, queue_id, t, w)).correlate_except(r)


def postfix_line_visible(model=PostfixLog):
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
    hidden = listed()
    if not hidden:
        return true()
    marks = select(PostfixLog.queue_id, PostfixLog.time).where(
        PostfixLog.queue_id.in_(queue_ids), _postfix_listed(PostfixLog, hidden)).cte('listed_marks').prefix_with('MATERIALIZED')
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
    array = case((func.jsonb_typeof(column) == 'array', column), else_=cast(literal('[]'), JSONB))
    elements = func.jsonb_array_elements_text(array).table_valued('value').alias('rcpt')
    return exists(select(literal(1)).select_from(elements).where(_norm(elements.c.value).in_(hidden)))


def rspamd_visible(model=RspamdLog):
    hidden = listed()
    if not hidden:
        return true()
    return not_(or_(_column_listed(model.sender_smtp, hidden), _recipients_listed(model.recipients_smtp, hidden)))


def _marks_and_ends(lines) -> Tuple[Dict[str, list], Dict[str, list]]:
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
    if not queue_id or not listed():
        return None
    return db.query(PostfixLog).filter(PostfixLog.queue_id == queue_id).all()


def visible_postfix_lines(lines: list, context: Optional[list] = None) -> list:
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
    if correlation_listed(correlation):
        return True
    at = correlation.first_seen or correlation.created_at
    if not correlation.queue_id or at is None:
        return False
    marks, ends = _marks_and_ends(l for l in lines if l.queue_id == correlation.queue_id)
    return any(same_message(t, at, ends.get(correlation.queue_id, ())) for t in marks.get(correlation.queue_id, ()))


def hidden_deliveries(db, legs) -> set:
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
    _remember(_removed_queues, queue_id, when)


def remembered_removed(queue_id: Optional[str]) -> List[datetime]:
    with _listed_queues_lock:
        return [t for t, _ in _removed_queues.get(queue_id, [])]


def remembered_listed(queue_ids: Iterable[Optional[str]]) -> Dict[str, List[datetime]]:
    with _listed_queues_lock:
        return {q: [t for t, _ in _listed_queues[q]] for q in set(queue_ids) if q in _listed_queues}


def queue_was_listed(queue_id: Optional[str], when: datetime, removed: Iterable[datetime] = ()) -> bool:
    if not queue_id:
        return False
    with _listed_queues_lock:
        marks = [t for t, _ in _listed_queues.get(queue_id, [])]
        ends = [t for t, _ in _removed_queues.get(queue_id, [])]
    ends += list(removed)
    return any(same_message(t, when, ends) for t in marks)


_last_forget: Optional[datetime] = None


def forget_old_queues(now: datetime) -> None:
    global _last_forget
    with _listed_queues_lock:
        if _last_forget is not None and now - _last_forget < timedelta(minutes=1):
            return
        _last_forget = now
        for queue_id in list(_listed_queues):
            kept = [(t, at) for t, at in _listed_queues[queue_id] if now - at <= QUEUE_WINDOW]
            if kept:
                _listed_queues[queue_id] = kept
            else:
                del _listed_queues[queue_id]
        for queue_id in list(_removed_queues):
            marks = [t for t, _ in _listed_queues.get(queue_id, [])]
            kept = [(r, at) for r, at in _removed_queues[queue_id]
                    if any(abs(naive_utc(r) - naive_utc(t)) <= QUEUE_WINDOW for t in marks)]
            if kept:
                _removed_queues[queue_id] = kept
            else:
                del _removed_queues[queue_id]


_SECOND = timedelta(seconds=1)


def message_span(t: datetime, removed: Iterable[datetime]) -> Tuple[datetime, datetime, Optional[datetime]]:
    t = naive_utc(t)
    s = _second(t)
    seconds = sorted({_second(r) for r in removed if r is not None})
    earlier = [r for r in seconds if r < s]
    later = [r for r in seconds if r >= s]
    lo = t - QUEUE_WINDOW
    if earlier:
        lo = max(lo, earlier[-1] + _SECOND)
    return lo, t + QUEUE_WINDOW, (later[0] + _SECOND) if later else None


def _in_span(column, span):
    lo, hi, before = span
    return and_(column >= lo, column <= hi, *([column < before] if before is not None else []))


def delete_queue_occurrences(db, occurrences: Iterable[Tuple[str, datetime]],
                             removed: Optional[Dict[str, List[datetime]]] = None) -> Tuple[int, int]:
    by_queue: Dict[str, set] = {}
    for q, t in occurrences:
        if q and t is not None:
            by_queue.setdefault(q, set()).add(naive_utc(t))
    for q, times in by_queue.items():
        for t in times:
            remember_listed_queue(q, t)
    seen_at = func.coalesce(MessageCorrelation.first_seen, MessageCorrelation.created_at)
    lines = deliveries = 0
    queue_ids = sorted(by_queue)
    for i in range(0, len(queue_ids), 200):
        part = queue_ids[i:i + 200]
        stored = stored_ends(db, {q: list(by_queue[q]) for q in part})
        spans = []
        for q in part:
            known = stored.get(q, []) + remembered_removed(q) + list((removed or {}).get(q, ()))
            for t in by_queue[q]:
                span = message_span(t, known)
                spans.append((q, span))
                for r in known:
                    if same_message(t, r, known):
                        remember_removed(q, r)
        deliveries += db.query(MessageCorrelation).filter(or_(*[
            and_(MessageCorrelation.queue_id == q, _in_span(seen_at, span)) for q, span in spans
        ])).delete(synchronize_session=False)
        lines += db.query(PostfixLog).filter(or_(*[
            and_(PostfixLog.queue_id == q, _in_span(PostfixLog.time, span)) for q, span in spans
        ])).delete(synchronize_session=False)
    return lines, deliveries


def _deliveries_to_delete(db, rows) -> List[int]:
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
    hidden = listed()
    if not hidden:
        return {}
    current = set(hidden)

    def still_current() -> bool:
        return set(listed()) == current

    counts = {'deliveries': 0, 'postfix': 0, 'rspamd': 0, 'detached': 0}

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


_requested = 1
_done = 0
_last_listed: frozenset = frozenset()


def full_pass_due() -> Optional[int]:
    return _requested if _requested != _done else None


def request_full_pass() -> None:
    global _requested
    _requested += 1


def full_pass_done(request: int) -> None:
    global _done
    _done = request
