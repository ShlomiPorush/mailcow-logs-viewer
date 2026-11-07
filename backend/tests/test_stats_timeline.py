"""The /stats/timeline endpoint built its spam_count with
func.cast(RspamdLog.is_spam, func.Integer), which SQLAlchemy rejects at query
construction time - the endpoint's catch-all then returned an empty timeline
with an error, so the dashboard chart was silently broken."""
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

MARKER = f'timeline-test-{uuid.uuid4().hex[:8]}'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import RspamdLog
    with get_db_context() as db:
        db.query(RspamdLog).filter(RspamdLog.message_id.like(f'{MARKER}%')).delete(
            synchronize_session=False)
        db.commit()


@pytest.fixture()
def seeded():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import RspamdLog
    init_db()
    _cleanup()
    now = datetime.utcnow()
    with get_db_context() as db:
        db.add(RspamdLog(time=now - timedelta(minutes=10), message_id=f'{MARKER}-spam',
                         is_spam=True, action='reject'))
        db.add(RspamdLog(time=now - timedelta(minutes=5), message_id=f'{MARKER}-ham',
                         is_spam=False, action='no action'))
        db.commit()
    yield
    _cleanup()


def test_timeline_counts_spam_instead_of_erroring(seeded):
    from app.database import get_db_context
    from app.routers.stats import get_timeline_stats
    with get_db_context() as db:
        result = get_timeline_stats(hours=1, db=db)
    assert 'error' not in result, f"timeline query failed: {result.get('error')}"
    assert result['timeline'], 'the seeded hour must appear in the timeline'
    total = sum(row['total'] for row in result['timeline'])
    spam = sum(row['spam'] for row in result['timeline'])
    assert total >= 2
    assert spam >= 1


@pytest.fixture()
def seeded_hours():
    """Linked messages and failed logins, for the per-hour dashboard figures."""
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import MessageCorrelation, NetfilterLog
    init_db()
    now = datetime.utcnow()
    with get_db_context() as db:
        for status in ('delivered', 'rejected', 'spam', 'deferred'):
            db.add(MessageCorrelation(
                correlation_key=f'{MARKER}-{status}', message_id=f'<{MARKER}-{status}@example.test>',
                sender='a@example.test', recipient='b@example.test', direction='inbound',
                final_status=status, first_seen=now - timedelta(minutes=3), last_seen=now, created_at=now))
        db.add(NetfilterLog(time=now - timedelta(minutes=3), priority=MARKER[-12:], ip='198.51.100.9', rule_id=3,
                            message='SASL LOGIN authentication failed'))
        db.commit()
    yield
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(MessageCorrelation.correlation_key.like(f'{MARKER}%')).delete(synchronize_session=False)
        db.query(NetfilterLog).filter(NetfilterLog.priority == MARKER[-12:]).delete(synchronize_session=False)
        db.commit()


def test_each_hour_carries_the_dashboard_figures_and_they_add_up(seeded_hours):
    """A picked hour on the dashboard chart shows its own numbers: the hours of the
    timeline must add up to the dashboard's 24-hour figures."""
    from app.database import get_db_context
    from app.routers.stats import get_dashboard_stats, get_timeline_stats
    with get_db_context() as db:
        timeline = get_timeline_stats(hours=24, db=db)['timeline']
        dashboard = get_dashboard_stats(db=db)
    total = lambda key: sum(row[key] for row in timeline)
    assert total('messages') == dashboard['messages']['24h'] >= 4
    assert total('blocked') == dashboard['blocked']['24h'] >= 2
    assert total('deferred') == dashboard['deferred']['24h'] >= 1
    assert total('auth_failures') == dashboard['auth_failures']['24h'] >= 1
    assert all({'total', 'spam', 'clean'} <= set(row) for row in timeline)


def test_the_message_count_matches_the_messages_page(seeded_hours):
    """The dashboard shows messages as the Messages page counts them (one per
    message), so opening an hour on Messages lists the number the chart named."""
    from fastapi.testclient import TestClient
    from app.database import get_db_context
    from app.main import app
    from app.routers.stats import get_dashboard_stats, get_timeline_stats
    with get_db_context() as db:
        dashboard = get_dashboard_stats(db=db)
        timeline = get_timeline_stats(hours=24, db=db)['timeline']
    since = (datetime.utcnow() - timedelta(days=1)).isoformat()
    listed = TestClient(app).get('/api/messages', params={'start_date': since, 'limit': 1}).json()
    assert dashboard['messages']['unique_24h'] == listed['total']
    assert dashboard['messages']['unique_24h'] <= dashboard['messages']['24h']
    assert all(row['unique_messages'] <= row['messages'] for row in timeline)
    assert sum(row['unique_messages'] for row in timeline) >= 4
