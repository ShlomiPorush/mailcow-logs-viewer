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
