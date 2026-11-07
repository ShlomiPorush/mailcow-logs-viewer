"""Give each message of a reused Postfix queue id back its own lines.

Postfix names a queued message by a short queue id that comes back once the
message has left the queue, minutes or days later, for an unrelated message.
Earlier versions read every line of a queue id as one message, so a message
that got a used id could take the earlier message's lines: its first-seen
time (days early in the Messages list), its status, and its correlation key
stamped on all of them.

This finds the queue ids whose lines show more than one message, or that more
than one correlation has, and cuts their lines into messages. A correlation
that holds another message's lines, or whose own lines carry another
correlation's key, is re-derived from its own lines alone: its linked lines,
first-seen time, final status, its Rspamd spam mark, and its sender and
recipient where they are evidently the other message's. Then the lines of
each message are stamped with their own correlation's key. A correlation
whose lines cannot be told apart from another one's is left as it is.

It runs at startup before the scheduler. When run by hand (alembic upgrade
head), stop the app first, or the ingest may write the same rows meanwhile.

The logic is a frozen copy of the queue occurrence section of
app/correlation.py (split_queue_occurrences, occurrence_for, settle_queue and
what they use).

Revision ID: 0029
Revises: 0028
Create Date: 2026-11-01
"""
import json
import logging
from datetime import datetime, timedelta, timezone

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None

logger = logging.getLogger("app.migrations")

BATCH = 500


# ── Frozen copy of app/correlation.py (queue occurrences) ─────────────────

OPENER = 'opener'
RECEIPT = 'receipt'
END = 'end'
DELIVERY = 'delivery'

_RECEIPT_PROGRAMS = ('smtpd', 'qmqpd', 'pickup', 'cleanup')


class Row:
    """A database row whose fields can be changed."""

    def __init__(self, mapping):
        self.__dict__.update(mapping)


def postfix_line_kind(line) -> str:
    program = (line.program or '').rsplit('/', 1)[-1]
    message = line.message or ''
    queue_id = line.queue_id or ''
    prefix = f'{queue_id}: '
    text_ = message[len(prefix):] if queue_id and message.startswith(prefix) else message
    if program in ('smtpd', 'qmqpd') and text_.startswith('client='):
        return OPENER
    if program == 'pickup' and text_.startswith('uid='):
        return OPENER
    if program in _RECEIPT_PROGRAMS:
        return RECEIPT
    if program == 'qmgr' and text_.startswith('removed'):
        return END
    return DELIVERY


def naive_utc(value):
    if value is not None and value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _line_order(line):
    return (naive_utc(line.time) or datetime.min, line.id or 0)


class QueueOccurrence:
    def __init__(self, opened_at):
        self.opened_at = opened_at
        self.lines = []
        self.boundary = []
        self.ended = False
        self.delivered = False

    def add(self, line):
        self.lines.append(line)
        kind = postfix_line_kind(line)
        if kind == END:
            self.ended = True
        if kind in (END, DELIVERY):
            self.delivered = True

    @property
    def message_ids(self):
        return {line.message_id for line in self.lines if line.message_id}

    @property
    def ids(self):
        return {line.id for line in self.lines if line.id}

    def span(self):
        times = [naive_utc(line.time) for line in self.lines + self.boundary if line.time]
        return (min(times), max(times)) if times else (self.opened_at, self.opened_at)


def split_queue_occurrences(lines):
    by_second = {}
    for line in lines:
        if line.time is None:
            continue
        by_second.setdefault(naive_utc(line.time).replace(microsecond=0), []).append(line)

    occurrences = []
    current = None
    for second in sorted(by_second):
        group = sorted(by_second[second], key=_line_order)
        kinds = [postfix_line_kind(line) for line in group]
        opens = current is not None and (
            OPENER in kinds
            or (RECEIPT in kinds and current.delivered)
            or current.ended
        )
        if not opens:
            if current is None:
                current = QueueOccurrence(second)
                occurrences.append(current)
            for line in group:
                current.add(line)
            continue

        previous, current = current, QueueOccurrence(second)
        occurrences.append(current)
        for line, kind in zip(group, kinds):
            if not previous.ended and kind in (DELIVERY, END):
                previous.boundary.append(line)
                current.boundary.append(line)
            else:
                current.add(line)
    return occurrences


def _distance(occurrence, near):
    start, end = occurrence.span()
    near = naive_utc(near)
    if near is None or start <= near <= end:
        return timedelta(0)
    return min(abs(start - near), abs(end - near))


def occurrence_for(occurrences, message_id, near=None, strict=True):
    if not occurrences:
        return None
    if message_id:
        holding = [o for o in occurrences if message_id in o.message_ids]
        if len(holding) == 1:
            return holding[0]
        if holding:
            return None if strict else min(holding, key=lambda o: _distance(o, near))
        candidates = [o for o in occurrences if not o.message_ids]
    else:
        candidates = list(occurrences)
    if len(occurrences) == 1 and candidates:
        return occurrences[0]
    if strict:
        return None
    return min(candidates or occurrences, key=lambda o: _distance(o, near))


def identified_by_message_id(occurrence, message_id):
    return bool(occurrence and message_id and message_id in occurrence.message_ids)


def rspamd_marks_spam(rspamd_log):
    symbols = rspamd_log.symbols if isinstance(rspamd_log.symbols, dict) else {}
    return rspamd_log.action in ('reject', 'add header', 'rewrite subject') or 'SPAM_TRAP' in symbols


def derive_final_status(lines, rspamd_log, dovecot_status, stored_status):
    statuses = {line.status for line in lines if line.status}
    status = next((outcome for found, outcome in (
        ('bounced', 'bounced'), ('rejected', 'rejected'), ('spam', 'spam'), ('sent', 'delivered'),
        ('expired', 'expired'), ('deferred', 'deferred')) if found in statuses), None)
    if status is None and rspamd_log is not None:
        if rspamd_log.action == 'reject':
            status = 'rejected'
        elif rspamd_log.is_spam:
            status = 'spam'
    if status is None and stored_status == 'expired':
        status = 'expired'
    if dovecot_status == 'discarded' and status not in ('bounced', 'rejected', 'deferred'):
        status = 'discarded'
    return status


def _own_value(stored, own_values, rspamd_values, other_values):
    if not stored:
        return stored
    own = [v for v in own_values if v]
    rspamd = [v for v in rspamd_values if v]
    known = {v.lower() for v in own + rspamd}
    if stored.lower() in known or stored.lower() not in {v.lower() for v in other_values if v}:
        return stored
    return (own or rspamd or [None])[0]


def ownership_differs(correlation, occurrences, occurrence, queue_keys):
    own = occurrence.ids
    others = {line.id for o in occurrences for line in o.lines + o.boundary if line.id} - own
    stored = {i for i in (correlation.postfix_log_ids or []) if isinstance(i, int)}
    if stored & others:
        return True
    return any(line.correlation_key and line.correlation_key != correlation.correlation_key
               and line.correlation_key in queue_keys for line in occurrence.lines)


def repair_from_occurrence(rspamd_log, correlation, occurrence, occurrences, now):
    own = sorted(occurrence.lines, key=_line_order)
    other = [line for o in occurrences if o is not occurrence for line in o.lines]

    correlation.postfix_log_ids = [line.id for line in own if line.id]
    times = [naive_utc(line.time) for line in own if line.time]
    if rspamd_log is not None and rspamd_log.time:
        times.append(naive_utc(rspamd_log.time))
    if times:
        correlation.first_seen = min(times)

    if rspamd_log is not None:
        rspamd_log.is_spam = rspamd_marks_spam(rspamd_log) or any(line.status == 'spam' for line in own)

    rspamd_recipients = rspamd_log.recipients_smtp if rspamd_log is not None and isinstance(
        rspamd_log.recipients_smtp, list) else []
    correlation.sender = _own_value(
        correlation.sender, [line.sender for line in own],
        [rspamd_log.sender_smtp if rspamd_log is not None else None], [line.sender for line in other])
    correlation.recipient = _own_value(
        correlation.recipient, [line.recipient for line in own], rspamd_recipients,
        [line.recipient for line in other])

    correlation.final_status = derive_final_status(
        own, rspamd_log, correlation.dovecot_status, correlation.final_status)
    correlation.last_seen = now


def owners_of_queue(correlations, occurrences):
    owned = {}
    for correlation in correlations:
        occurrence = occurrence_for(occurrences, correlation.message_id, near=correlation.first_seen)
        if occurrence is None:
            continue
        if len(correlations) > 1 and not identified_by_message_id(occurrence, correlation.message_id):
            continue
        owned[correlation.id] = occurrence
    claimed = [id(o) for o in owned.values()]
    return {cid: o for cid, o in owned.items() if claimed.count(id(o)) == 1}


def settle_queue(load_rspamd, correlations, occurrences, now):
    """As app/correlation.py settle_queue; returns the correlations repaired.
    load_rspamd(id) gives a correlation's Rspamd row or None."""
    owned = owners_of_queue(correlations, occurrences)
    keys = {c.correlation_key for c in correlations}
    repaired = [c for c in correlations if c.id in owned
                and ownership_differs(c, occurrences, owned[c.id], keys)]
    if not repaired:
        return []
    for correlation in repaired:
        rspamd_log = load_rspamd(correlation.rspamd_log_id) if correlation.rspamd_log_id else None
        repair_from_occurrence(rspamd_log, correlation, owned[correlation.id], occurrences, now)
    by_occurrence = {id(owned[c.id]): c.correlation_key for c in correlations if c.id in owned}
    for occurrence in occurrences:
        for line in occurrence.lines:
            key = by_occurrence.get(id(occurrence))
            if key:
                line.correlation_key = key
            elif line.correlation_key in keys:
                line.correlation_key = None
        for line in occurrence.boundary:
            if line.correlation_key in keys:
                line.correlation_key = None
    return repaired


# ── The repair ────────────────────────────────────────────────────────────

# Queue ids whose lines show more than one message: more than one opener,
# more than one Message-ID, a receipt line in a later second than a delivery
# or qmgr "removed" line, or any line in a later second than qmgr's "removed".
# Plus the queue ids more than one correlation has.
_PROGRAM = "regexp_replace(COALESCE(program, ''), '^.*/', '')"
CANDIDATES = f"""
SELECT queue_id FROM (
    SELECT queue_id,
           count(*) FILTER (WHERE opener) AS openers,
           count(DISTINCT message_id) AS message_ids,
           max(second) FILTER (WHERE receipt) AS last_receipt,
           min(second) FILTER (WHERE NOT receipt) AS first_delivery,
           min(second) FILTER (WHERE ended) AS first_end,
           max(second) AS last_line
    FROM (
        SELECT queue_id, message_id, date_trunc('second', time) AS second,
               {_PROGRAM} IN ('smtpd', 'qmqpd', 'pickup', 'cleanup') AS receipt,
               ({_PROGRAM} IN ('smtpd', 'qmqpd') AND starts_with(COALESCE(message, ''), queue_id || ': client='))
               OR ({_PROGRAM} = 'pickup' AND starts_with(COALESCE(message, ''), queue_id || ': uid='))
               AS opener,
               {_PROGRAM} = 'qmgr' AND starts_with(COALESCE(message, ''), queue_id || ': removed')
               AS ended
        FROM postfix_logs
        WHERE queue_id IS NOT NULL AND queue_id <> '' AND time IS NOT NULL
    ) lines
    GROUP BY queue_id
) queues
WHERE openers > 1 OR message_ids > 1 OR last_receipt > first_delivery OR last_line > first_end
UNION
SELECT queue_id FROM message_correlations
WHERE queue_id IS NOT NULL AND queue_id <> ''
GROUP BY queue_id HAVING count(*) > 1
"""

LINES = ("SELECT id, time, program, message, queue_id, message_id, status, sender, recipient, correlation_key "
         "FROM postfix_logs WHERE queue_id = ANY(:queues)")
CORRELATIONS = ("SELECT id, correlation_key, message_id, queue_id, first_seen, final_status, dovecot_status, "
                "sender, recipient, rspamd_log_id, postfix_log_ids FROM message_correlations "
                "WHERE queue_id = ANY(:queues) ORDER BY id")
RSPAMD = ("SELECT id, time, action, symbols, is_spam, sender_smtp, recipients_smtp "
          "FROM rspamd_logs WHERE id = :id")


def _snapshot(row, fields):
    return tuple(json.dumps(v, sort_keys=True) if isinstance(v, (list, dict)) else v
                 for v in (getattr(row, f) for f in fields))


CORRELATION_FIELDS = ("postfix_log_ids", "first_seen", "final_status", "sender", "recipient")


def _repair_batch(bind, queues, now):
    lines_by_queue = {}
    for mapping in bind.execute(text(LINES), {"queues": queues}).mappings():
        line = Row(mapping)
        lines_by_queue.setdefault(line.queue_id, []).append(line)
    correlations_by_queue = {}
    for mapping in bind.execute(text(CORRELATIONS), {"queues": queues}).mappings():
        correlation = Row(mapping)
        correlations_by_queue.setdefault(correlation.queue_id, []).append(correlation)

    rspamd_rows = {}

    def load_rspamd(rspamd_id):
        if rspamd_id not in rspamd_rows:
            mapping = bind.execute(text(RSPAMD), {"id": rspamd_id}).mappings().first()
            rspamd_rows[rspamd_id] = Row(mapping) if mapping else None
            if rspamd_rows[rspamd_id] is not None:
                rspamd_rows[rspamd_id].original_is_spam = rspamd_rows[rspamd_id].is_spam
        return rspamd_rows[rspamd_id]

    repaired_count = 0
    for queue_id, correlations in correlations_by_queue.items():
        lines = lines_by_queue.get(queue_id, [])
        occurrences = split_queue_occurrences(lines)
        if not occurrences:
            continue
        before = {c.id: _snapshot(c, CORRELATION_FIELDS) for c in correlations}
        stamps = {line.id: line.correlation_key for line in lines}
        repaired = settle_queue(load_rspamd, correlations, occurrences, now)
        if not repaired:
            continue
        repaired_count += len(repaired)
        for correlation in repaired:
            if _snapshot(correlation, CORRELATION_FIELDS) == before[correlation.id]:
                continue
            bind.execute(text(
                "UPDATE message_correlations SET postfix_log_ids = CAST(:ids AS jsonb), first_seen = :first_seen, "
                "final_status = :final_status, sender = :sender, recipient = :recipient, last_seen = :now "
                "WHERE id = :id"
            ), {"ids": json.dumps(correlation.postfix_log_ids), "first_seen": correlation.first_seen,
                "final_status": correlation.final_status, "sender": correlation.sender,
                "recipient": correlation.recipient, "now": now, "id": correlation.id})
        by_key = {}
        for line in lines:
            if line.correlation_key != stamps[line.id]:
                by_key.setdefault(line.correlation_key, []).append(line.id)
        for key, ids in by_key.items():
            bind.execute(text("UPDATE postfix_logs SET correlation_key = :key WHERE id = ANY(:ids)"),
                         {"key": key, "ids": ids})

    for rspamd_log in rspamd_rows.values():
        if rspamd_log is not None and rspamd_log.is_spam != rspamd_log.original_is_spam:
            bind.execute(text("UPDATE rspamd_logs SET is_spam = :is_spam WHERE id = :id"),
                         {"is_spam": rspamd_log.is_spam, "id": rspamd_log.id})
    return repaired_count


def repair(bind, now=None):
    tables = set(sa.inspect(bind).get_table_names())
    if not {"postfix_logs", "message_correlations", "rspamd_logs"} <= tables:
        return 0
    now = now or datetime.utcnow()
    queues = sorted({row[0] for row in bind.execute(text(CANDIDATES))})
    repaired = 0
    for start in range(0, len(queues), BATCH):
        repaired += _repair_batch(bind, queues[start:start + BATCH], now)
    if repaired:
        logger.warning(f"[CORRELATION] Upgrade: {repaired} message(s) on reused Postfix queue ids "
                       f"were re-read from their own lines ({len(queues)} queue id(s) checked)")
    return repaired


def upgrade() -> None:
    repair(op.get_bind())


def downgrade() -> None:
    # The repaired correlations are not put back
    pass
