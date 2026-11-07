"""Every answer the Status calls can give, so the contract check (conftest.py,
contract.py) holds each one to /openapi.json: mailcow answering, not answering
(502) or answering with something the call cannot read (500), the database
failing (500), the answers that stay 200 when GitHub or mailcow fail, and the
requests they refuse (404, 422). mailcow and GitHub are faked; nothing leaves
the test. The containers recorded and the ignored list are put back."""
import types
import uuid
from contextlib import contextmanager

import httpx
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app import database, scheduler  # noqa: E402
from app.config import settings  # noqa: E402
from app.mailcow_api import MailcowAPIError, mailcow_api  # noqa: E402
from app.main import app  # noqa: E402
from app.routers import status  # noqa: E402
from app.services.ignore_lists import IGNORED_CONTAINERS_KEY  # noqa: E402

MARK = uuid.uuid4().hex[:8]
RUNNING, EXITED = f'a{MARK}-mailcow', f'b{MARK}-mailcow'
DOWN = MailcowAPIError('down')
MAILCOW = {
    '/api/v1/get/status/containers': [{
        RUNNING: {'state': 'running', 'started_at': '2026-10-26T08:00:00.123456Z'},
        EXITED: {'state': 'exited', 'started_at': None}}],
    '/api/v1/get/status/vmail': [{'type': 'info', 'disk': '/dev/sda1', 'used': '45G', 'total': '100G',
                                  'used_percent': '45%'}],
    '/api/v1/get/status/version': [{'version': '2026-09'}],
    '/api/v1/get/domain/all': [{'domain_name': f'{MARK}.example', 'active': 1}],
    '/api/v1/get/mailbox/all': [{'username': f'u@{MARK}.example', 'active': 1}, {'active': 0}],
    '/api/v1/get/alias/all': [],
    '/api/v1/get/logs/postfix/1': [],
}


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


class _GitHub:
    """GitHub's releases API, answering with a fixed status and release."""
    status = 200
    release = {'tag_name': 'v9.9.9', 'name': 'Release 9.9.9', 'body': '## Notes'}

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url, **kwargs):
        if self.status is None:
            raise httpx.ConnectError('no network in tests')
        return httpx.Response(self.status, json=self.release, request=httpx.Request('GET', url))


@pytest.fixture
def client(monkeypatch):
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    answers = dict(MAILCOW)

    async def mailcow(endpoint, method='GET', **kwargs):
        answer = answers[endpoint]
        if isinstance(answer, Exception):
            raise answer
        return answer
    monkeypatch.setattr(mailcow_api, '_make_request', mailcow)
    github = type('GitHub', (_GitHub,), {})
    fake_httpx = types.SimpleNamespace(AsyncClient=github)
    monkeypatch.setattr(status, 'httpx', fake_httpx)
    monkeypatch.setattr(scheduler, 'httpx', fake_httpx)
    # The version checks keep their results in the process
    version_before, app_before = dict(status.version_cache), dict(scheduler.app_version_cache)
    job_before = dict(scheduler.job_status['check_app_version'])
    yield TestClient(app, raise_server_exceptions=False), answers, github
    for cache, before in ((status.version_cache, version_before), (scheduler.app_version_cache, app_before)):
        cache.clear()
        cache.update(before)
    scheduler.job_status['check_app_version'] = job_before


@pytest.fixture
def rows(client):
    """The containers this test records and the ignored list, put back after it."""
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.models import KnownContainer, SystemSetting
    database.init_db()
    with database.get_db_context() as db:
        row = db.query(SystemSetting).filter(SystemSetting.key == IGNORED_CONTAINERS_KEY).first()
        before = (row.value, row.updated_at) if row else None
    yield
    with database.get_db_context() as db:
        db.query(KnownContainer).filter(KnownContainer.container_name.in_([RUNNING, EXITED])).delete(
            synchronize_session=False)
        row = db.query(SystemSetting).filter(SystemSetting.key == IGNORED_CONTAINERS_KEY).first()
        if before is None:
            if row is not None:
                db.delete(row)
        elif row is None:
            db.add(SystemSetting(key=IGNORED_CONTAINERS_KEY, value=before[0], updated_at=before[1]))
        else:
            row.value, row.updated_at = before
        db.commit()


# ---------------------------------------------------------------- containers

def test_containers(client, rows):
    c, answers, _ = client
    assert c.get('/api/status/containers').json()['containers'][RUNNING]['name'] == f'a{MARK}'
    assert c.put(f'/api/status/containers/{EXITED}/ignore', json={'ignored': True}).json()['ignored'] is True
    # Gone from mailcow's answer: still listed, as stopped
    answers['/api/v1/get/status/containers'] = [{RUNNING: {'state': 'running'}}]
    body = c.get('/api/status/containers').json()
    assert body['containers'][EXITED]['state'] == 'stopped' and body['summary']['ignored'] >= 1
    assert c.put(f'/api/status/containers/{EXITED}/ignore', json={'ignored': False}).status_code == 200
    assert c.put(f'/api/status/containers/nope{MARK}/ignore', json={'ignored': True}).status_code == 404
    assert c.put(f'/api/status/containers/{EXITED}/ignore', json={}).status_code == 422
    answers['/api/v1/get/status/containers'] = DOWN
    assert c.get('/api/status/containers').status_code == 502


def test_containers_when_the_database_fails(client, monkeypatch):
    c, _, _ = client
    monkeypatch.setattr(status, 'SessionLocal', _broken_context)
    assert c.get('/api/status/containers').status_code == 500
    assert c.put(f'/api/status/containers/{EXITED}/ignore', json={'ignored': True}).status_code == 500


# ---------------------------------------------------------------- storage and counts

def test_storage(client):
    c, answers, _ = client
    assert c.get('/api/status/storage').json()['used_percent'] == '45%'
    answers['/api/v1/get/status/vmail'] = []
    assert c.get('/api/status/storage').json()['disk'] == 'unknown'
    # An answer that is not an object cannot be read
    answers['/api/v1/get/status/vmail'] = ['45%']
    assert c.get('/api/status/storage').status_code == 500
    answers['/api/v1/get/status/vmail'] = DOWN
    assert c.get('/api/status/storage').status_code == 502


def test_mailcow_info(client):
    c, answers, _ = client
    assert c.get('/api/status/mailcow-info').json()['mailboxes'] == {'total': 2, 'active': 1}
    answers['/api/v1/get/domain/all'] = ['not a domain']
    assert c.get('/api/status/mailcow-info').status_code == 500
    answers['/api/v1/get/domain/all'] = DOWN
    assert c.get('/api/status/mailcow-info').status_code == 502


def test_summary(client, rows):
    c, answers, _ = client
    assert c.get('/api/status/summary').json()['system']['domains'] == 1
    for endpoint in MAILCOW:
        answers[endpoint] = DOWN
    body = c.get('/api/status/summary').json()
    assert body['storage']['known'] is False and body['system']['mailboxes'] == 0


def test_mailcow_connection(client):
    c, answers, _ = client
    assert c.get('/api/status/mailcow-connection').json()['connected'] is True
    answers['/api/v1/get/logs/postfix/1'] = DOWN
    assert c.get('/api/status/mailcow-connection').json()['connected'] is False


# ---------------------------------------------------------------- versions

def test_mailcow_version(client):
    c, answers, github = client
    body = c.get('/api/status/version?force=true').json()
    assert body['latest_version'] == 'v9.9.9' and body['update_available'] is True
    github.status = None
    assert c.get('/api/status/version?force=true').json()['latest_version'] == 'unknown'
    assert c.get('/api/status/version?force=maybe').status_code == 422
    answers['/api/v1/get/status/version'] = DOWN
    assert c.get('/api/status/version?force=true').status_code == 502


def test_app_version(client):
    c, _, github = client
    assert c.get('/api/status/app-version?force=true').json()['latest_version'] == '9.9.9'
    github.status = 503
    assert c.get('/api/status/app-version?force=true').json()['latest_version'] == 'unknown'
    assert c.get('/api/status/app-version?force=maybe').status_code == 422


def test_changelog(client):
    c, _, github = client
    assert c.get('/api/status/app-version/changelog/9.9.9').json()['changelog'] == '## Notes'
    github.status = 404
    assert 'not found' in c.get('/api/status/app-version/changelog/v0.0.1').json()['changelog']
    github.status = None
    assert 'Failed' in c.get('/api/status/app-version/changelog/0.0.1').json()['changelog']


# ---------------------------------------------------------------- the app's log

def test_container_logs(client):
    c, _, _ = client
    assert isinstance(c.get('/api/status/container-logs?lines=10').json()['logs'], list)
    assert c.get('/api/status/container-logs?lines=5').status_code == 422
