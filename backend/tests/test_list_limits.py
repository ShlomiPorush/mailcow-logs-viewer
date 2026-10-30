"""List routes take a bounded page size, so one call cannot load a whole table.

The bound is 500, like GET /api/messages, and the largest size the app's
own pages ask for (DMARC sources) still works. A page below 1 is refused
instead of reaching the database as a negative offset.
"""
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

ROUTES = (
    '/api/stats/recent-activity',
    '/api/stats/top-spam-triggers',
    '/api/stats/top-blocked-ips',
    '/api/dmarc/domains/example.test/reports',
    '/api/dmarc/domains/example.test/sources',
    '/api/dmarc/domains/example.test/tls-reports',
    '/api/dmarc/domains/example.test/tls-reports/daily',
    '/api/dmarc/imap/history',
)
PAGED = [r for r in ROUTES if r.startswith('/api/dmarc/')]


@pytest.fixture
def client(monkeypatch):
    from fastapi.testclient import TestClient
    from app.config import settings
    from app.main import app
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    return TestClient(app)


@pytest.mark.parametrize('path', ROUTES)
@pytest.mark.parametrize('limit', [0, 501, 1000000000])
def test_a_page_size_outside_1_to_500_is_refused(client, path, limit):
    assert client.get(path, params={'limit': limit}).status_code == 422


@pytest.mark.parametrize('path', PAGED)
@pytest.mark.parametrize('page', [0, -1])
def test_a_page_below_1_is_refused(client, path, page):
    assert client.get(path, params={'page': page}).status_code == 422


def test_the_largest_size_the_dmarc_page_asks_for_works(client):
    try:
        from app.database import engine
        with engine.connect():
            pass
    except Exception:
        pytest.skip('PostgreSQL not available')
    from app.database import init_db
    init_db()
    r = client.get('/api/dmarc/domains/example.test/sources', params={'days': 30, 'limit': 500})
    assert r.status_code == 200, r.text
