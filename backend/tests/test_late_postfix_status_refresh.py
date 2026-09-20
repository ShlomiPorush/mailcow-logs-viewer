"""A delivery that succeeds after the correlation age window must still be recorded.

Greylisting defers a message; Postfix retries minutes or hours later and the
delivery succeeds. `update_final_status_for_correlations` only looks at
correlations younger than MAX_CORRELATION_AGE_MINUTES, so once that window
passes the message is stuck on "deferred" forever even though it was delivered.

The fix refreshes a correlation when a status-bearing Postfix line for its queue
actually arrives, so these tests drive the real ingestion job rather than the
helper, and also pin the guards that keep that push path from doing harm.
"""
import asyncio
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.config import settings

# Postfix queue ids are parsed with ^([A-F0-9]+): - a placeholder like "TESTQ1"
# parses to no queue id at all and the test would pass for the wrong reason.
QUEUE = '4F2C1A01'
OTHER_QUEUE = '4F2C1A02'
RECIPIENT = 'rcpt@example.invalid'
MARKER = 'late-status-refresh.invalid'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _deferred_line(queue=QUEUE):
    return (f'{queue}: to=<{RECIPIENT}>, relay=mx.example.invalid[192.0.2.10]:25, '
            f'delay=1, dsn=4.7.1, status=deferred (450 4.7.1 Greylisted)')


def _sent_line(queue=QUEUE):
    return (f'{queue}: to=<{RECIPIENT}>, relay=mx.example.invalid[192.0.2.10]:25, '
            f'delay=2700, dsn=2.0.0, status=sent (250 2.0.0 OK)')


def _seed(db, queue, status, final_status, age_minutes, message_id=None):
    """One aged correlation plus the Postfix line it was built from."""
    from app.models import PostfixLog, MessageCorrelation
    when = datetime.utcnow() - timedelta(minutes=age_minutes)
    plog = PostfixLog(
        time=when, program='postfix/smtp', priority='info',
        message=_deferred_line(queue), queue_id=queue,
        recipient=RECIPIENT, status=status,
        raw_data={'marker': MARKER})
    db.add(plog)
    db.flush()
    corr = MessageCorrelation(
        correlation_key=uuid.uuid4().hex,
        message_id=message_id or f'<{uuid.uuid4().hex}@{MARKER}>',
        queue_id=queue, recipient=RECIPIENT, direction='outbound',
        final_status=final_status, is_complete=True,
        postfix_log_ids=[plog.id],
        first_seen=when, last_seen=when, created_at=when)
    db.add(corr)
    db.commit()
    return corr.correlation_key


def _cleanup():
    from app.database import get_db_context
    from app.models import PostfixLog, MessageCorrelation
    with get_db_context() as db:
        db.query(PostfixLog).filter(
            PostfixLog.queue_id.in_([QUEUE, OTHER_QUEUE])).delete(synchronize_session=False)
        db.query(MessageCorrelation).filter(
            MessageCorrelation.message_id.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def env(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db
    init_db()
    monkeypatch.setattr(settings._inner, 'max_correlation_age_minutes', 10)
    _cleanup()
    yield
    _cleanup()


def _ingest(monkeypatch, lines):
    """Run the real Postfix ingestion job over a single fabricated page."""
    from app import scheduler

    async def _total(*a, **k):
        return len(lines)

    pages = [list(lines)]

    async def _page(*a, **k):
        return pages.pop(0) if pages else []

    monkeypatch.setattr(scheduler, '_discover_total_logs', _total)
    monkeypatch.setattr(scheduler.mailcow_api, 'get_postfix_logs_page', _page)
    scheduler.seen_postfix.clear()
    scheduler._resume_offset['postfix'] = 0
    asyncio.run(scheduler.fetch_and_store_postfix())


def _entry(message):
    epoch = int((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds())
    return {'time': str(epoch), 'program': 'postfix/smtp', 'priority': 'info',
            'message': message}


def _reload(correlation_key):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    with get_db_context() as db:
        return db.query(MessageCorrelation).filter(
            MessageCorrelation.correlation_key == correlation_key).first().final_status


def test_late_delivery_updates_an_aged_correlation(env, monkeypatch):
    """The bug: delivered 45 minutes later, the correlation still says deferred."""
    from app.database import get_db_context
    from app.models import PostfixLog, MessageCorrelation

    with get_db_context() as db:
        key = _seed(db, QUEUE, 'deferred', 'deferred', age_minutes=45)

    _ingest(monkeypatch, [_entry(_sent_line())])
    asyncio.run(__import__('app.scheduler', fromlist=['x']).update_final_status_for_correlations())

    assert _reload(key) == 'delivered'

    with get_db_context() as db:
        corr = db.query(MessageCorrelation).filter(
            MessageCorrelation.correlation_key == key).first()
        sent = db.query(PostfixLog).filter(
            PostfixLog.queue_id == QUEUE, PostfixLog.status == 'sent').first()
        assert sent is not None, 'the sent line was not ingested'
        assert sent.correlation_key == key
        assert sent.id in (corr.postfix_log_ids or [])


def test_late_deferral_does_not_downgrade_a_delivered_correlation(env, monkeypatch):
    from app.database import get_db_context
    with get_db_context() as db:
        key = _seed(db, QUEUE, 'sent', 'delivered', age_minutes=45)

    _ingest(monkeypatch, [_entry(_deferred_line())])

    assert _reload(key) == 'delivered'


def test_a_spam_verdict_is_not_overwritten_by_a_late_delivery(env, monkeypatch):
    """routers/stats.py counts final_status 'spam' as blocked mail. A late
    delivery line must not quietly deflate that number."""
    from app.database import get_db_context
    with get_db_context() as db:
        key = _seed(db, QUEUE, 'deferred', 'spam', age_minutes=45)

    _ingest(monkeypatch, [_entry(_sent_line())])

    assert _reload(key) == 'spam'


def test_an_ambiguous_queue_id_is_not_attributed(env, monkeypatch):
    """Postfix reuses short queue ids. Two correlations on one queue means we
    cannot tell which the new line belongs to, so neither may be touched."""
    from app.database import get_db_context
    with get_db_context() as db:
        first = _seed(db, QUEUE, 'deferred', 'deferred', age_minutes=45,
                      message_id=f'<a-{uuid.uuid4().hex}@{MARKER}>')
        second = _seed(db, QUEUE, 'deferred', None, age_minutes=45,
                       message_id=f'<b-{uuid.uuid4().hex}@{MARKER}>')

    _ingest(monkeypatch, [_entry(_sent_line())])

    assert _reload(first) == 'deferred'
    assert _reload(second) is None


def test_a_correlation_older_than_the_retry_horizon_is_not_touched(env, monkeypatch):
    """Beyond Postfix's maximal_queue_lifetime a matching queue id is far more
    likely to be a reused id than a real retry."""
    from app.database import get_db_context
    with get_db_context() as db:
        key = _seed(db, QUEUE, 'deferred', 'deferred', age_minutes=60 * 24 * 10)

    _ingest(monkeypatch, [_entry(_sent_line())])

    assert _reload(key) == 'deferred'


def test_refresh_is_driven_by_arrivals_not_by_scanning(env, monkeypatch):
    """The whole point of the design: work follows arriving log lines. A page
    with no new status lines must not trigger any correlation refresh."""
    from app import scheduler
    from app.database import get_db_context

    with get_db_context() as db:
        _seed(db, QUEUE, 'deferred', 'deferred', age_minutes=45)

    calls = []
    original = scheduler.refresh_correlations_for_queue_ids

    def spy(db, queue_ids):
        calls.append(set(queue_ids))
        return original(db, queue_ids)

    monkeypatch.setattr(scheduler, 'refresh_correlations_for_queue_ids', spy)

    page = [_entry(_sent_line())]
    _ingest(monkeypatch, page)
    assert [c for c in calls if c] == [{QUEUE}], 'first ingest must refresh exactly this queue'

    # Same page again: every line is already in the database, so nothing new
    # arrives and no correlation may be re-examined.
    calls.clear()
    _ingest(monkeypatch, page)
    assert [c for c in calls if c] == [], 'a page of duplicates must refresh nothing'
