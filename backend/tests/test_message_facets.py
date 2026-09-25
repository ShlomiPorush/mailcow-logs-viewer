"""Message facets: the counts next to Outcome and Direction on the Messages
page must equal what the list shows when that facet is chosen."""
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

MARKER = f'facets-{uuid.uuid4().hex[:8]}.invalid'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import MessageCorrelation
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(
            MessageCorrelation.sender.like(f'%{MARKER}')).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def client():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from fastapi.testclient import TestClient
    from app.database import init_db
    from app.main import app
    init_db()
    _cleanup()
    yield TestClient(app)
    _cleanup()


def _add(status, direction, message_id=None, minutes_ago=5):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    when = datetime.utcnow() - timedelta(minutes=minutes_ago)
    key = uuid.uuid4().hex
    with get_db_context() as db:
        db.add(MessageCorrelation(
            correlation_key=key, message_id=message_id or f'<{key}@{MARKER}>',
            sender=f'sender@{MARKER}', recipient='rcpt@example.com', subject='facet test',
            direction=direction, final_status=status, is_complete=True,
            first_seen=when, last_seen=when))
        db.commit()


def test_facet_counts_match_the_list(client):
    _add('delivered', 'inbound')
    _add('delivered', 'outbound')
    _add('deferred', 'outbound')
    _add('rejected', 'inbound')
    shared = f'<shared@{MARKER}>'
    # Two delivery legs of one message count once, as in the list
    _add('delivered', 'internal', message_id=shared, minutes_ago=6)
    _add('delivered', 'internal', message_id=shared, minutes_ago=4)

    params = {'sender': MARKER}
    facets = client.get('/api/messages/facets', params=params).json()
    assert facets['status']['all'] == 5
    assert facets['status']['delivered'] == 3
    assert facets['status']['deferred'] == 1
    assert facets['status']['rejected'] == 1
    assert facets['direction'] == {'all': 5, 'inbound': 2, 'outbound': 2, 'internal': 1}

    for status, count in facets['status'].items():
        extra = {} if status == 'all' else {'status': status}
        total = client.get('/api/messages', params={**params, **extra, 'limit': 1}).json()['total']
        assert total == count, status
    for direction, count in facets['direction'].items():
        extra = {} if direction == 'all' else {'direction': direction}
        total = client.get('/api/messages', params={**params, **extra, 'limit': 1}).json()['total']
        assert total == count, direction


def test_each_facet_ignores_its_own_filter(client):
    _add('delivered', 'inbound')
    _add('deferred', 'outbound')
    facets = client.get('/api/messages/facets', params={'sender': MARKER, 'status': 'deferred', 'direction': 'inbound'}).json()
    # Outcome counts keep the direction filter, direction counts keep the outcome filter
    assert facets['status']['all'] == 1 and facets['status']['delivered'] == 1
    assert facets['direction']['all'] == 1 and facets['direction']['outbound'] == 1
