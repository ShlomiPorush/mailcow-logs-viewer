"""Every answer the Live Logs calls can give, so the contract check (conftest.py,
contract.py) holds each one to /openapi.json: the stream token, the services (also
when they cannot be counted), the worker's state before and after a run, stored
lines of a service, a database that fails (500), and the requests the calls refuse
(404, 422). The lines this test stores are removed after it."""
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app import database, raw_logs_worker  # noqa: E402
from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402
from app.routers import raw_logs  # noqa: E402

MARK = uuid.uuid4().hex


class _Broken:
    def __getattr__(self, name):
        raise RuntimeError('database gone')


@contextmanager
def _broken_context():
    yield _Broken()


def _postgres_available() -> bool:
    try:
        with database.engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture
def client(monkeypatch):
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def lines():
    """Two Postfix lines and an Rspamd history entry of this test, removed after it."""
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.models import RawServiceLog
    database.init_db()
    now = datetime.utcnow()
    rows = [
        RawServiceLog(service='postfix', time=now - timedelta(minutes=2), message_hash=f'{MARK}-1',
                      raw_data={'time': '1700000000', 'priority': 'info', 'program': 'postfix/postscreen',
                                'message': f'CONNECT from [203.0.113.5]:4711 {MARK}'}),
        RawServiceLog(service='postfix', time=now - timedelta(minutes=1), message_hash=f'{MARK}-2',
                      raw_data={'time': '1700000060', 'priority': 'info', 'program': 'postfix/smtpd',
                                'message': f'NOQUEUE: reject: RCPT from x {MARK}'}),
        RawServiceLog(service='rspamd-history', time=now, message_hash=f'{MARK}-3',
                      raw_data={'subject': f'Hello {MARK}', 'sender_smtp': 'a@example.com', 'ip': '203.0.113.5',
                                'action': 'no action', 'score': 1.5, 'symbols': {'X': {'score': 1.5}}}),
    ]
    with database.get_db_context() as db:
        db.add_all(rows)
    yield
    with database.get_db_context() as db:
        db.query(RawServiceLog).filter(RawServiceLog.message_hash.like(f'{MARK}-%')).delete(synchronize_session=False)


def test_ws_token(client):
    r = client.get('/api/raw-logs/ws-token')
    assert r.status_code == 200
    assert raw_logs._ws_tokens.pop(r.json()['token'], None) is not None


def test_services(client, lines):
    r = client.get('/api/raw-logs/services')
    assert r.status_code == 200
    assert {s['id'] for s in r.json()['services']} == set(settings.raw_logs_services_list)


def test_services_when_they_cannot_be_counted(client, monkeypatch):
    monkeypatch.setattr(raw_logs, 'get_db_context', _broken_context)
    monkeypatch.setattr(settings._inner, 'raw_logs_services', 'postfix,dovecot')
    r = client.get('/api/raw-logs/services')
    assert r.status_code == 200
    assert [s['log_count'] for s in r.json()['services']] == [0, 0]
    assert r.json()['services'][0]['has_smart_filters'] is True


def test_worker_status_before_the_first_run(client, monkeypatch):
    for job in ('fetch_raw_logs', 'cleanup_raw_logs'):
        monkeypatch.setitem(raw_logs_worker.raw_logs_job_status[job], 'last_run', None)
    r = client.get('/api/raw-logs/worker-status')
    assert r.status_code == 200
    assert r.json()['jobs']['fetch_raw_logs']['last_run'] is None


def test_worker_status_after_a_run(client, monkeypatch):
    ran = datetime(2026, 10, 26, 9, 30, tzinfo=timezone.utc)
    fetch, cleanup = (raw_logs_worker.raw_logs_job_status[job] for job in ('fetch_raw_logs', 'cleanup_raw_logs'))
    for key, value in {'last_run': ran, 'status': 'success', 'error': None, 'stats': {'postfix': 12, 'sogo': -1}}.items():
        monkeypatch.setitem(fetch, key, value)
    for key, value in {'last_run': ran, 'status': 'failed', 'error': 'database gone'}.items():
        monkeypatch.setitem(cleanup, key, value)
    r = client.get('/api/raw-logs/worker-status')
    assert r.status_code == 200
    assert r.json()['jobs']['fetch_raw_logs']['last_run'] == '2026-10-26T09:30:00Z'


def test_stored_lines(client, lines):
    r = client.get('/api/raw-logs/postfix', params={'search': MARK, 'order': 'asc', 'limit': 1, 'page': 2})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body['total'] == 2 and body['pages'] == 2
    assert body['data'][0]['program'] == 'postfix/smtpd' and body['data'][0]['_service'] == 'postfix'
    assert body['data'][0]['_stored_at'].endswith('Z')

    filtered = client.get('/api/raw-logs/postfix', params={'search': MARK, 'smart_filter': 'postscreen,nope'})
    assert filtered.status_code == 200 and filtered.json()['total'] == 1

    history = client.get('/api/raw-logs/rspamd-history', params={'search': MARK})
    assert history.status_code == 200 and history.json()['data'][0]['symbols'] == {'X': {'score': 1.5}}

    empty = client.get('/api/raw-logs/dovecot', params={'search': MARK, 'start_date': '2026-01-01',
                                                       'end_date': 'not a date'})
    assert empty.status_code == 200 and empty.json() == {'data': [], 'page': 1, 'limit': 200, 'total': 0,
                                                         'pages': 1, 'service': 'dovecot'}


def test_stored_lines_errors(client, monkeypatch):
    assert client.get('/api/raw-logs/nope').status_code == 404
    assert client.get('/api/raw-logs/postfix', params={'page': 0}).status_code == 422
    monkeypatch.setattr(raw_logs, 'get_db_context', _broken_context)
    assert client.get('/api/raw-logs/postfix').status_code == 500


def test_smart_filters(client):
    postfix = client.get('/api/raw-logs/postfix/smart-filters')
    assert postfix.status_code == 200 and len(postfix.json()['filters']) == 8
    other = client.get('/api/raw-logs/dovecot/smart-filters')
    assert other.status_code == 200 and other.json() == {'filters': [], 'service': 'dovecot'}
