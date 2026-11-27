import json
import logging
import re
from typing import Dict, Iterable, List, Optional

from sqlalchemy import and_, case, cast, exists, func, literal, not_, select, update
from sqlalchemy.dialects.postgresql import JSONB

from ..correlation import _PF_DELIVERY_RE
from ..models import MessageCorrelation, PostfixLog, RspamdLog
from .excluded_addresses import QUEUE_WINDOW, separated_sql

logger = logging.getLogger(__name__)

MARK = 'ALIAS_RESOLVED'
_GMAIL = 'gmail.com'
_GMAIL_ALIASES = ('gmail.com', 'googlemail.com')

_PLAIN_RE = re.compile(r'^[!-~]+$')


def key(address) -> str:
    return str(address or '').strip().lower()


def _plain(address) -> Optional[str]:
    value = key(address)
    if not value or len(value) > 255 or '"' in value or not _PLAIN_RE.match(value) or value.count('@') != 1:
        return None
    local, domain = value.split('@')
    return value if local and domain else None


def loose(address) -> Optional[str]:
    value = _plain(address)
    if not value:
        return None
    local, domain = value.split('@')
    local = local.split('+', 1)[0]
    if domain in _GMAIL_ALIASES:
        domain = _GMAIL
        local = local.replace('.', '')
    return f'{local}@{domain}' if local else None


def written_address(message) -> Optional[str]:
    match = _PF_DELIVERY_RE.match(message or '')
    if not match:
        return None
    return (match.group('orig_to') or match.group('to') or '').strip() or None


def marked(rspamd_log) -> bool:
    symbols = getattr(rspamd_log, 'symbols', None)
    return isinstance(symbols, dict) and MARK in symbols


def resolve(listed: Iterable, lines: Iterable) -> Dict[str, str]:
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


def delivery_lines(db, correlation) -> List:
    at = correlation.first_seen or correlation.created_at
    if at is None:
        return []
    at = at.replace(microsecond=0)
    columns = (PostfixLog.id, PostfixLog.time, PostfixLog.message)
    near = and_(PostfixLog.time >= at, PostfixLog.time <= at + QUEUE_WINDOW,
                PostfixLog.recipient.isnot(None), PostfixLog.recipient != '')
    if correlation.queue_id:
        seen_at = func.coalesce(MessageCorrelation.first_seen, MessageCorrelation.created_at)
        owners = db.query(func.count(MessageCorrelation.id)).filter(
            MessageCorrelation.queue_id == correlation.queue_id,
            seen_at >= at - QUEUE_WINDOW, seen_at <= at + QUEUE_WINDOW).scalar()
        if owners != 1:
            return []
        return db.query(*columns).filter(
            PostfixLog.queue_id == correlation.queue_id, near,
            not_(separated_sql(correlation.queue_id, literal(at), PostfixLog.time))).all()
    ids = sorted({i for i in (correlation.postfix_log_ids or []) if isinstance(i, int)})
    if not ids:
        return []
    return db.query(*columns).filter(PostfixLog.id.in_(ids), near).all()


def record(db, correlation, rspamd_log=None) -> bool:
    if rspamd_log is None and not getattr(correlation, 'rspamd_log_id', None):
        return False
    try:
        with db.begin_nested():
            return _record(db, correlation, rspamd_log)
    except Exception as e:
        logger.warning(f"[CORRELATION] Written recipient not stored for correlation "
                       f"{getattr(correlation, 'id', None)}: {e}")
        return False


def _record(db, correlation, rspamd_log) -> bool:
    if rspamd_log is None:
        rspamd_log = db.get(RspamdLog, correlation.rspamd_log_id)
    if not marked(rspamd_log) or not isinstance(rspamd_log.recipients_smtp, list):
        return False
    # The session does not autoflush: without this the lookup below misses the link just made
    db.flush()
    stored = correlation.written_recipients if isinstance(correlation.written_recipients, dict) else {}
    if all(key(a) in stored for a in rspamd_log.recipients_smtp if key(a)):
        return False
    found = {k: v for k, v in resolve(rspamd_log.recipients_smtp, delivery_lines(db, correlation)).items()
             if k not in stored}
    if not found:
        return False
    column = MessageCorrelation.written_recipients
    current = case((func.jsonb_typeof(column) == 'object', column), else_=cast(literal('{}'), JSONB))
    db.execute(update(MessageCorrelation).where(MessageCorrelation.id == correlation.id).values(
        written_recipients=cast(literal(json.dumps(found)), JSONB).op('||')(current)
    ).execution_options(synchronize_session=False))
    db.expire(correlation, ['written_recipients'])
    return True


def record_for_queues(db, queue_ids) -> int:
    queue_ids = sorted({q for q in queue_ids or [] if q})
    done = 0
    try:
        for start in range(0, len(queue_ids), 500):
            rows = db.query(MessageCorrelation).join(
                RspamdLog, RspamdLog.id == MessageCorrelation.rspamd_log_id
            ).filter(
                MessageCorrelation.queue_id.in_(queue_ids[start:start + 500]),
                func.jsonb_typeof(RspamdLog.symbols) == 'object',
                RspamdLog.symbols.has_key(MARK),
            ).all()
            for row in rows:
                done += record(db, row)
    except Exception as e:
        db.rollback()
        logger.warning(f"[CORRELATION] Written recipients not stored for this page: {e}")
    return done


def shown(recipient, written) -> Optional[str]:
    if recipient and isinstance(written, dict):
        return written.get(key(recipient)) or recipient
    return recipient


def shown_list(recipients, written) -> list:
    if not isinstance(written, dict) or not isinstance(recipients, list):
        return recipients
    return [shown(r, written) for r in recipients]


def _value_rows(column):
    obj = case((func.jsonb_typeof(column) == 'object', column), else_=cast(literal('{}'), JSONB))
    return func.jsonb_each_text(obj).table_valued('key', 'value').alias('written')


def any_value(column, condition) -> 'exists':
    rows = _value_rows(column)
    return exists(select(literal(1)).select_from(rows).where(condition(rows.c.value)))
