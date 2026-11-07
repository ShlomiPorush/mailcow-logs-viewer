"""Show the recipient address the sender wrote when Rspamd recorded it normalized.

Rspamd's alias resolution (symbol ALIAS_RESOLVED) records a Gmail recipient
without the dots of its local part, and any recipient without its +tag. The
Messages list, details, search and export showed that form, which no log line
contains. Adds message_correlations.written_recipients (Rspamd address ->
the address the sender wrote) and fills it for the messages already stored,
from their own Postfix delivery lines. message_correlations.recipient is not
changed.

The rule is a frozen copy of app/services/written_recipients.py. A delivery's
lines are its queue id's lines from when it was first seen to a day later,
when no other delivery has that queue id then (Postfix reuses queue ids),
else the lines linked to it by id. Nothing is guessed: no lines, no value.

The fresh-install start creates the column from the models first, so it is
only added when missing.

Revision ID: 0027
Revises: 0026
Create Date: 2026-10-29
"""
import json
import logging
import re
from datetime import timedelta

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None

logger = logging.getLogger("app.migrations")

BATCH = 500
WINDOW = timedelta(days=1)
_GMAIL = 'gmail.com'
_GMAIL_ALIASES = ('gmail.com', 'googlemail.com')
_PF_ADDR = r'(?:"(?:[^"\\]|\\.)*"|[^>"])*'
# A Postfix delivery line's fixed fields (app/correlation.py _PF_DELIVERY_RE)
_PF_DELIVERY_RE = re.compile(
    r'^[0-9A-F]+: to=<(?P<to>' + _PF_ADDR + r')>, '
    r'(?:orig_to=<(?P<orig_to>' + _PF_ADDR + r')>, )?'
    r'(?P<fields>(?:[a-z_]+=[^,\s<>]*, )*?)'
    r'dsn=(?P<dsn>\d\.\d{1,3}\.\d{1,3}), status=(?P<status>\w+)(?P<reply>.*)$'
)
_PLAIN_RE = re.compile(r'^[!-~]+$')


def key(address):
    return str(address or '').strip().lower()


def _plain(address):
    value = key(address)
    if not value or len(value) > 255 or '"' in value or not _PLAIN_RE.match(value) or value.count('@') != 1:
        return None
    local, domain = value.split('@')
    return value if local and domain else None


def loose(address):
    value = _plain(address)
    if not value:
        return None
    local, domain = value.split('@')
    local = local.split('+', 1)[0]
    if domain in _GMAIL_ALIASES:
        domain = _GMAIL
        local = local.replace('.', '')
    return f'{local}@{domain}' if local else None


def written_address(message):
    match = _PF_DELIVERY_RE.match(message or '')
    if not match:
        return None
    return (match.group('orig_to') or match.group('to') or '').strip() or None


def resolve(listed, lines):
    listed_keys = sorted({key(a) for a in listed or [] if key(a)})
    lines = sorted(lines, key=lambda l: (l.time is None, l.time or 0, l.id or 0))
    written = [w for w in (written_address(l.message) for l in lines) if w]
    own = {key(w) for w in written}
    found = {}
    for rspamd_address in listed_keys:
        target = loose(rspamd_address)
        if rspamd_address in own or not target:
            continue
        match = next((w for w in written if key(w) not in listed_keys and _plain(w) and loose(w) == target), None)
        if match:
            found[rspamd_address] = match
    return found


def _near(at, when):
    return at is not None and when is not None and abs(when - at) <= WINDOW


def _batch_lines(bind, rows):
    """The delivery lines of each candidate, by correlation id."""
    queues = sorted({r.queue_id for r in rows if r.queue_id})
    owners, by_queue = {}, {}
    if queues:
        for owner in bind.execute(sa.text(
                "SELECT queue_id, COALESCE(first_seen, created_at) AS at FROM message_correlations "
                "WHERE queue_id = ANY(:queues)"), {"queues": queues}):
            owners.setdefault(owner.queue_id, []).append(owner.at)
        for line in bind.execute(sa.text(
                "SELECT id, queue_id, time, recipient, message FROM postfix_logs "
                "WHERE queue_id = ANY(:queues) AND recipient IS NOT NULL AND recipient <> ''"),
                {"queues": queues}):
            by_queue.setdefault(line.queue_id, []).append(line)
    linked = sorted({i for r in rows if not r.queue_id and isinstance(r.postfix_log_ids, list)
                     for i in r.postfix_log_ids if isinstance(i, int)})
    by_id = {}
    if linked:
        for line in bind.execute(sa.text(
                "SELECT id, queue_id, time, recipient, message FROM postfix_logs "
                "WHERE id = ANY(:ids) AND recipient IS NOT NULL AND recipient <> ''"), {"ids": linked}):
            by_id[line.id] = line
    found = {}
    for r in rows:
        if r.queue_id:
            if sum(1 for at in owners.get(r.queue_id, []) if _near(r.at, at)) != 1:
                continue
            lines = by_queue.get(r.queue_id, [])
        else:
            ids = r.postfix_log_ids if isinstance(r.postfix_log_ids, list) else []
            lines = [by_id[i] for i in ids if isinstance(i, int) and i in by_id]
        # From the whole second the message was first seen: an earlier line is
        # another message's (Postfix logs whole seconds)
        found[r.id] = [l for l in lines if r.at is not None and l.time is not None
                       and r.at.replace(microsecond=0) <= l.time <= r.at + WINDOW]
    return found


def backfill(bind):
    tables = set(sa.inspect(bind).get_table_names())
    if not {"message_correlations", "rspamd_logs", "postfix_logs"} <= tables:
        return
    last, filled = 0, 0
    while True:
        rows = bind.execute(sa.text(
            "SELECT c.id, c.queue_id, c.postfix_log_ids, COALESCE(c.first_seen, c.created_at) AS at, "
            "c.written_recipients, r.recipients_smtp FROM message_correlations c "
            "JOIN rspamd_logs r ON r.id = c.rspamd_log_id "
            "WHERE c.id > :last AND jsonb_typeof(r.symbols) = 'object' AND r.symbols ? 'ALIAS_RESOLVED' "
            "ORDER BY c.id LIMIT :batch"), {"last": last, "batch": BATCH}).all()
        if not rows:
            break
        last = rows[-1].id
        lines = _batch_lines(bind, rows)
        updates = []
        for r in rows:
            if not isinstance(r.recipients_smtp, list) or r.id not in lines:
                continue
            stored = r.written_recipients if isinstance(r.written_recipients, dict) else {}
            found = {k: v for k, v in resolve(r.recipients_smtp, lines[r.id]).items() if k not in stored}
            if found:
                updates.append({"id": r.id, "found": json.dumps(found)})
        if updates:
            bind.execute(sa.text(
                "UPDATE message_correlations SET written_recipients = "
                "CAST(:found AS jsonb) || CASE WHEN jsonb_typeof(written_recipients) = 'object' "
                "THEN written_recipients ELSE CAST('{}' AS jsonb) END WHERE id = :id"), updates)
            filled += len(updates)
    if filled:
        logger.info(f"[CORRELATION] Upgrade: stored the written recipient address of {filled} message(s)")


def upgrade() -> None:
    bind = op.get_bind()
    if "message_correlations" not in set(sa.inspect(bind).get_table_names()):
        return
    if "written_recipients" not in {c["name"] for c in sa.inspect(bind).get_columns("message_correlations")}:
        op.add_column("message_correlations", sa.Column("written_recipients", JSONB))
    backfill(bind)


def downgrade() -> None:
    op.drop_column("message_correlations", "written_recipients")
