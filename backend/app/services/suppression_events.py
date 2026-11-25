import re
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..models import MessageCorrelation, PostfixLog, SuppressionEvent
from . import excluded_addresses

MAX_LINES = 50
LINES_PER_QUEUE = 500
MAX_LINE_CHARS = 1000
MAX_TEXT_CHARS = 2000
NEARBY = timedelta(days=1)

_REPLY_RE = re.compile(r'status=\w+\s*\((.*)\)\s*$', re.S)


def clip(value, limit: int = MAX_TEXT_CHARS) -> Tuple[Optional[str], bool]:
    if value is None:
        return None, False
    text = str(value)
    if len(text) <= limit:
        return text, False
    return text[:limit - 1] + '…', True


def server_reply(message: Optional[str]) -> Optional[str]:
    if not message:
        return None
    match = _REPLY_RE.search(message)
    return clip(match.group(1).strip())[0] if match else None


def _line(row) -> Tuple[dict, bool]:
    message, cut = clip(row.message, MAX_LINE_CHARS)
    return {'time': row.time.strftime('%Y-%m-%dT%H:%M:%SZ'), 'program': row.program, 'message': message}, cut


def postfix_lines(db: Session, wanted: List[tuple]) -> List[Tuple[list, bool]]:
    asked = [w for w in wanted if w[0]]
    by_queue: Dict[str, list] = {}
    ends: Dict[str, list] = {}
    if asked:
        lo = min(w[2] for w in asked) - NEARBY
        hi = max(w[3] for w in asked) + NEARBY
        queue_ids = {w[0] for w in asked}
        ranked = db.query(PostfixLog.id.label('id'), func.row_number().over(
            partition_by=PostfixLog.queue_id, order_by=(PostfixLog.time.desc(), PostfixLog.id.desc())).label('n')
        ).filter(PostfixLog.queue_id.in_(queue_ids), PostfixLog.time >= lo, PostfixLog.time <= hi).subquery()
        rows = db.query(PostfixLog.id, PostfixLog.queue_id, PostfixLog.time, PostfixLog.program,
                        PostfixLog.message, PostfixLog.recipient) \
            .join(ranked, ranked.c.id == PostfixLog.id).filter(ranked.c.n <= LINES_PER_QUEUE) \
            .order_by(PostfixLog.time, PostfixLog.id).all()
        for row in rows:
            by_queue.setdefault(row.queue_id, []).append(row)
        for queue_id, time in db.query(PostfixLog.queue_id, PostfixLog.time).filter(
                PostfixLog.queue_id.in_(queue_ids), PostfixLog.time >= lo, PostfixLog.time <= hi,
                excluded_addresses.removed_line(PostfixLog)).all():
            ends.setdefault(queue_id, []).append(time)
    capped = {q for q, lines in by_queue.items() if len(lines) >= LINES_PER_QUEUE}

    picked_cache: Dict[tuple, list] = {}
    found = []
    for queue_id, recipient, start, end, deciding in wanted:
        if not queue_id:
            found.append(([], False))
            continue
        rcpt = (recipient or '').lower()
        key = (queue_id, rcpt, start, end)
        if key not in picked_cache:
            picked_cache[key] = [r for r in by_queue.get(queue_id, [])
                                 if start - NEARBY <= r.time <= end + NEARBY and (not r.recipient or r.recipient.lower() == rcpt)
                                 and not excluded_addresses.separated(r.time, start, ends.get(queue_id, ()))]
        lines = list(picked_cache[key])
        shortened = queue_id in capped
        if deciding is not None and all(r.id != deciding.id for r in lines):
            lines.append(deciding)
            lines.sort(key=lambda r: (r.time, r.id))
        if len(lines) > MAX_LINES:
            keep = lines[:20] + lines[-(MAX_LINES - 21):]
            if deciding is not None and all(r.id != deciding.id for r in keep):
                keep.append(deciding)
            lines = sorted({r.id: r for r in keep}.values(), key=lambda r: (r.time, r.id))
            shortened = True
        out = []
        for r in lines:
            line, cut = _line(r)
            shortened = shortened or cut
            out.append(line)
        found.append((out, shortened))
    return found


def disabled_by_hand(db: Session, ids: Iterable[int]) -> set:
    ids = list(ids)
    if not ids:
        return set()
    last = {}
    for sid, kind in db.query(SuppressionEvent.suppression_id, SuppressionEvent.kind).filter(
            SuppressionEvent.suppression_id.in_(ids),
            SuppressionEvent.kind.in_(['enabled', 'disabled'])).order_by(
            SuppressionEvent.recorded_at, SuppressionEvent.id):
        last[sid] = kind
    return {sid for sid, kind in last.items() if kind == 'disabled'}


def add_event(db: Session, suppression, **fields) -> SuppressionEvent:
    shortened = bool(fields.pop('logs_shortened', False))
    for key, limit in (('reason', MAX_TEXT_CHARS), ('server_reply', MAX_TEXT_CHARS), ('subject', 998),
                       ('notes', MAX_TEXT_CHARS), ('sender', 255), ('recipient', 255),
                       ('message_id', 255), ('queue_id', 50), ('dsn', 20)):
        if fields.get(key) is not None:
            fields[key], cut = clip(fields[key], limit)
            shortened = shortened or (cut and key in ('reason', 'server_reply'))
    event = SuppressionEvent(suppression_id=suppression.id, recorded_at=datetime.utcnow(),
                             logs_shortened=shortened, **fields)
    db.add(event)
    return event


def _excluded(sender, recipient) -> bool:
    return excluded_addresses.any_listed(sender, recipient)


def bounce_kind(dsn: str) -> str:
    return 'hard_bounce' if dsn.startswith('5.') else 'soft_bounce' if dsn.startswith('4.') else 'rejected'


def record_bounces(db: Session, captured: List[tuple]) -> None:
    if not captured:
        return
    db.flush()
    keys = {log.correlation_key for _, log, _, _ in captured if log.correlation_key}
    messages = {m.correlation_key: m for m in db.query(
        MessageCorrelation.correlation_key, MessageCorrelation.sender, MessageCorrelation.subject,
        MessageCorrelation.message_id).filter(MessageCorrelation.correlation_key.in_(keys)).all()} if keys else {}
    lines = postfix_lines(db, [(log.queue_id, log.recipient, log.time, log.time, log) for _, log, _, _ in captured])
    for (suppression, log, outcome, expires_at), (found, shortened) in zip(captured, lines):
        message = messages.get(log.correlation_key)
        if _excluded(log.sender or (message.sender if message else None), suppression.email):
            add_event(db, suppression, kind=bounce_kind(log.dsn or ''), outcome=outcome, message_time=log.time,
                      server_reply=server_reply(log.message), dsn=log.dsn, recipient=suppression.email,
                      expires_at=expires_at)
            continue
        add_event(db, suppression,
                  kind=bounce_kind(log.dsn or ''), outcome=outcome, message_time=log.time,
                  server_reply=server_reply(log.message), dsn=log.dsn,
                  sender=log.sender or (message.sender if message else None),
                  recipient=suppression.email, subject=message.subject if message else None,
                  queue_id=log.queue_id, message_id=log.message_id or (message.message_id if message else None),
                  correlation_key=log.correlation_key if message else None,
                  expires_at=expires_at, log_lines=found, logs_shortened=shortened)


def record_stuck(db: Session, captured: List[tuple]) -> None:
    if not captured:
        return
    db.flush()
    now = datetime.utcnow()
    lines = postfix_lines(db, [(item.get('queue_id'), suppression.email, item.get('arrived') or now, now, None)
                               for suppression, item, _, _ in captured])
    for (suppression, item, outcome, expires_at), (found, shortened) in zip(captured, lines):
        if _excluded(item.get('sender'), suppression.email):
            add_event(db, suppression, kind='deferred_stuck', outcome=outcome, message_time=item.get('arrived'),
                      reason=item.get('note'), server_reply=item.get('reason'), recipient=suppression.email,
                      expires_at=expires_at)
            continue
        add_event(db, suppression,
                  kind='deferred_stuck', outcome=outcome, message_time=item.get('arrived'),
                  reason=item.get('note'), server_reply=item.get('reason'),
                  sender=item.get('sender'), recipient=suppression.email, queue_id=item.get('queue_id'),
                  expires_at=expires_at, log_lines=found, logs_shortened=shortened)
