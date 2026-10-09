"""One over-long value must not drop a whole page of mail logs.

Sender, recipient, Message-ID, From header and SASL user name are chosen by
whoever sends the mail or tries to log in, and they were written into
VARCHAR(255) columns as-is. PostgreSQL rejected the one long row, the single
page commit rolled back every entry of the page, and because the entries had
already been added to the in-memory duplicate cache the page was never
retried. Values are now cut to their column length, and the cache only
learns entries after the commit succeeded.
"""
import uuid
from contextlib import contextmanager
from datetime import datetime
from unittest.mock import Mock

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app import scheduler

MARK = uuid.uuid4().hex[:8]
LONG_ADDRESS = 'a' * 300 + '@example.com'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import NetfilterLog, PostfixLog, RspamdLog
    with get_db_context() as db:
        db.query(PostfixLog).filter(PostfixLog.message.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.message_id.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.query(NetfilterLog).filter(NetfilterLog.message.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def env(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db
    init_db()
    _cleanup()
    monkeypatch.setattr(scheduler, 'seen_postfix', set())
    monkeypatch.setattr(scheduler, 'seen_rspamd', set())
    monkeypatch.setattr(scheduler, 'seen_netfilter', set())
    monkeypatch.setattr(scheduler, 'is_blacklisted', lambda email: False)
    yield
    _cleanup()


def _count(model, column):
    from app.database import get_db_context
    with get_db_context() as db:
        return db.query(model).filter(column.like(f'%{MARK}%')).count()


def test_postfix_page_with_one_300_char_value_stores_every_entry(env):
    from app.models import PostfixLog
    base = int(datetime.utcnow().timestamp())
    logs = [{'time': str(base + i), 'program': 'postfix/cleanup', 'priority': 'info',
             'message': f'ABC{i}{MARK[:4].upper()}: message-id=<{i}-{MARK}@example.com>'} for i in range(4)]
    logs.append({'time': str(base + 9), 'program': 'postfix/qmgr', 'priority': 'info',
                 'message': f'ABC9{MARK[:4].upper()}: from=<{LONG_ADDRESS}>, size=1, nrcpt=1 (queue active) {MARK}'})
    logs.append({'time': str(base + 10), 'program': 'postfix/smtpd', 'priority': 'info',
                 'message': f'NOQUEUE: reject: RCPT from unknown[192.0.2.10]: 554 5.7.1 Relay access denied; '
                            f'from=<{LONG_ADDRESS}> to=<{LONG_ADDRESS}> proto=ESMTP helo=<x> {MARK}'})

    new, skipped, _ = scheduler._store_postfix_page(logs)

    assert new == 6 and skipped == 0
    assert _count(PostfixLog, PostfixLog.message) == 6


def test_rspamd_page_with_one_300_char_value_stores_every_entry(env):
    from app.models import RspamdLog
    base = int(datetime.utcnow().timestamp())
    logs = [{'unix_time': base + i, 'message-id': f'{i}-{MARK}@example.com', 'sender_smtp': 's@example.com',
             'rcpt_smtp': ['r@example.com'], 'action': 'no action', 'score': 0.0, 'required_score': 15.0,
             'symbols': {}} for i in range(3)]
    logs[1]['sender_mime'] = LONG_ADDRESS
    logs[2]['message-id'] = f'{MARK}-' + 'm' * 300 + '@example.com'
    logs[2]['rcpt_smtp'] = [LONG_ADDRESS]

    new, skipped, _ = scheduler._store_rspamd_page(logs)

    assert new == 3
    assert _count(RspamdLog, RspamdLog.message_id) == 3
    # A second pass over the same page (cache cleared, as after a restart)
    # must recognise every entry as already stored, the long Message-ID too.
    scheduler.seen_rspamd.clear()
    new, skipped, _ = scheduler._store_rspamd_page(logs)
    assert (new, skipped) == (0, 3)


def test_netfilter_batch_with_one_300_char_value_stores_every_entry(env):
    from app.models import NetfilterLog
    base = int(datetime.utcnow().timestamp())
    logs = [{'time': base + i, 'priority': 'warn',
             'message': f'192.0.2.{i + 1} SASL LOGIN authentication failed sasl_username=u{i}@example.com {MARK}'}
            for i in range(3)]
    logs[1]['message'] = f'192.0.2.9 SASL LOGIN authentication failed sasl_username={LONG_ADDRESS} {MARK}'

    scheduler._store_netfilter_logs(logs)

    assert _count(NetfilterLog, NetfilterLog.message) == 3


# ---- the duplicate cache only learns committed entries ----

def _failing_session():
    db = Mock()
    db.query.return_value.filter.return_value.all.return_value = []
    db.query.return_value.filter.return_value.first.return_value = None
    db.commit.side_effect = RuntimeError('commit failed')

    @contextmanager
    def session():
        yield db
    return session


def test_failed_postfix_commit_leaves_the_page_retryable(monkeypatch):
    monkeypatch.setattr(scheduler, 'seen_postfix', set())
    monkeypatch.setattr(scheduler, 'get_db_context', _failing_session())
    with pytest.raises(RuntimeError):
        scheduler._store_postfix_page([{'time': '1', 'program': 'postfix/cleanup', 'priority': 'info',
                                        'message': 'ABC1: message-id=<a@example.com>'}])
    assert scheduler.seen_postfix == set()


def test_failed_rspamd_commit_leaves_the_page_retryable(monkeypatch):
    monkeypatch.setattr(scheduler, 'seen_rspamd', set())
    monkeypatch.setattr(scheduler, 'is_blacklisted', lambda email: False)
    monkeypatch.setattr(scheduler, 'get_db_context', _failing_session())
    with pytest.raises(RuntimeError):
        scheduler._store_rspamd_page([{'unix_time': 1, 'message-id': 'a@example.com', 'symbols': {}}])
    assert scheduler.seen_rspamd == set()


def test_failed_netfilter_commit_leaves_the_batch_retryable(monkeypatch):
    monkeypatch.setattr(scheduler, 'seen_netfilter', set())
    monkeypatch.setattr(scheduler, 'get_db_context', _failing_session())
    with pytest.raises(RuntimeError):
        scheduler._store_netfilter_logs([{'time': 1, 'priority': 'warn', 'message': '192.0.2.1 banned'}])
    assert scheduler.seen_netfilter == set()


def test_identical_postfix_lines_on_one_page_are_stored_once(env):
    from app.models import PostfixLog
    line = {'time': str(int(datetime.utcnow().timestamp())), 'program': 'postfix/cleanup', 'priority': 'info',
            'message': f'ABCD{MARK[:4].upper()}: message-id=<dup-{MARK}@example.com>'}
    new, skipped, _ = scheduler._store_postfix_page([line, dict(line)])
    assert (new, skipped) == (1, 1)
    assert _count(PostfixLog, PostfixLog.message) == 1


def test_rspamd_recipient_list_items_fit_the_correlation_column(env):
    from app.database import get_db_context
    from app.models import MessageCorrelation, RspamdLog
    scheduler._store_rspamd_page([{
        'unix_time': int(datetime.utcnow().timestamp()), 'message-id': f'rcpt-{MARK}@example.com',
        'sender_smtp': 's@example.com', 'rcpt_smtp': [LONG_ADDRESS], 'symbols': {}}])
    limit = MessageCorrelation.__table__.columns['recipient'].type.length
    with get_db_context() as db:
        row = db.query(RspamdLog).filter(RspamdLog.message_id == f'rcpt-{MARK}@example.com').one()
        assert len(row.recipients_smtp[0]) == limit
        assert row.raw_data['rcpt_smtp'] == [LONG_ADDRESS], 'the raw entry stays complete'
