"""The Messages list comes newest first, and oldest first when asked (order=asc),
on every page; any other order is refused."""
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.config import settings

MARK = uuid.uuid4().hex[:8]
SENDER = f'order-{MARK}@example.com'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def client(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    from app.database import init_db, get_db_context
    from app.models import MessageCorrelation
    init_db()

    def cleanup():
        with get_db_context() as db:
            db.query(MessageCorrelation).filter(MessageCorrelation.sender == SENDER).delete(synchronize_session=False)
            db.commit()
    cleanup()
    now = datetime.utcnow().replace(microsecond=0)
    with get_db_context() as db:
        for minutes in (30, 10, 50, 20, 40):
            db.add(MessageCorrelation(correlation_key=uuid.uuid4().hex, sender=SENDER, recipient='rcpt@example.net',
                                      direction='outbound', subject=f'm{minutes} {MARK}', final_status='delivered',
                                      first_seen=now - timedelta(minutes=minutes), last_seen=now, created_at=now))
        db.commit()
    from fastapi.testclient import TestClient
    from app.main import app
    yield TestClient(app)
    cleanup()


def _subjects(client, query):
    response = client.get(f'/api/messages?search={SENDER}&{query}')
    assert response.status_code == 200, response.text
    return [m['subject'].split()[0] for m in response.json()['data']]


def test_newest_first_by_default(client):
    assert _subjects(client, 'limit=50') == ['m10', 'm20', 'm30', 'm40', 'm50']


def test_oldest_first_on_every_page(client):
    assert _subjects(client, 'order=asc&limit=50') == ['m50', 'm40', 'm30', 'm20', 'm10']
    assert _subjects(client, 'order=asc&limit=2&page=1') == ['m50', 'm40']
    assert _subjects(client, 'order=asc&limit=2&page=2') == ['m30', 'm20']


def test_another_order_is_refused(client):
    assert client.get('/api/messages?order=sideways').status_code == 422
