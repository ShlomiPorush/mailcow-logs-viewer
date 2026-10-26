"""Every answer the notification destination calls can give, so the contract check
(conftest.py, contract.py) holds each one to /openapi.json: the types, destinations
saved, changed and removed, test notifications that are delivered and that fail, a
database that fails (500), and the requests the calls refuse (404, 422). The send
itself is faked (notification_channels._post); nothing leaves the test."""
import uuid
from contextlib import contextmanager

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app import database  # noqa: E402
from app.config import settings  # noqa: E402
from app.database import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.services import notification_channels as nc  # noqa: E402

MARK = uuid.uuid4().hex[:8]
TELEGRAM = {'name': f'{MARK} Ops Telegram', 'channel_type': 'telegram',
            'config': {'bot_token': '123:ABC', 'chat_id': '456'}, 'alert_types': ['security', 'blacklist']}
# A webhook URL urlparse cannot read; its path is the channel's secret
BAD_HOOK = 'http://[hooks.example/T000/B000/SECRET'


class _Broken:
    """A database session whose every query fails."""

    def rollback(self):
        pass

    def close(self):
        pass

    def __getattr__(self, name):
        raise RuntimeError('database gone')


def _broken_session():
    yield _Broken()


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
    sent = {'status': 200, 'calls': []}

    async def post(url, kwargs):
        # Where the request would go; no request is made
        sent['calls'].append(url)
        return sent['status'], 'the service is down'

    monkeypatch.setattr(nc, '_post', post)
    yield TestClient(app, raise_server_exceptions=False), sent
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def channels(client):
    """The destinations this test saves, removed after it."""
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.models import NotificationChannel
    database.init_db()
    yield
    with database.get_db_context() as db:
        db.query(NotificationChannel).filter(NotificationChannel.name.like(f'{MARK}%')).delete(synchronize_session=False)
        db.commit()


def test_types(client):
    c, _ = client
    answer = c.get('/api/notifications/types').json()
    assert {t['id'] for t in answer['types']} == set(nc.CHANNEL_TYPES)


def test_destinations(client, channels):
    c, sent = client
    created = c.post('/api/notifications/channels', json=TELEGRAM)
    assert created.status_code == 200 and created.json()['config']['bot_token'] == nc.MASK
    channel_id = created.json()['id']
    # Every alert type is the same as none: stored as every alert
    everything = c.post('/api/notifications/channels', json={**TELEGRAM, 'name': f'{MARK} all',
                                                             'alert_types': sorted(nc.ALERT_TYPE_IDS)})
    assert everything.json()['alert_types'] == []
    assert c.get('/api/notifications/channels').status_code == 200

    # The masked secret keeps the stored one
    changed = c.put(f'/api/notifications/channels/{channel_id}',
                    json={**TELEGRAM, 'config': {'bot_token': nc.MASK, 'chat_id': '789'}, 'enabled': False})
    assert changed.status_code == 200 and changed.json()['enabled'] is False

    # Refused: an unknown type or alert type, a missing field, a masked secret sent to a new server
    for body in ({**TELEGRAM, 'channel_type': 'pager'}, {**TELEGRAM, 'alert_types': ['nope']},
                 {**TELEGRAM, 'config': {'chat_id': '456'}}, {**TELEGRAM, 'name': ''}):
        assert c.post('/api/notifications/channels', json=body).status_code == 422
    ntfy = c.post('/api/notifications/channels', json={'name': f'{MARK} ntfy', 'channel_type': 'ntfy',
                                                       'config': {'topic': 'alerts', 'token': 'secret'}}).json()
    moved = c.put(f"/api/notifications/channels/{ntfy['id']}",
                  json={'name': f'{MARK} ntfy', 'channel_type': 'ntfy',
                        'config': {'topic': 'alerts', 'token': nc.MASK, 'server_url': 'https://ntfy.example.net'}})
    assert moved.status_code == 422
    assert c.put(f'/api/notifications/channels/{channel_id}', json={**TELEGRAM, 'channel_type': 'pager'}).status_code == 422
    assert c.put(f'/api/notifications/channels/{channel_id}', json={**TELEGRAM, 'config': {}}).status_code == 422
    assert c.put('/api/notifications/channels/0', json=TELEGRAM).status_code == 404
    assert c.put('/api/notifications/channels/x', json=TELEGRAM).status_code == 422

    # A test to a saved destination: delivered, then refused by the service
    delivered = c.post(f'/api/notifications/channels/{channel_id}/test')
    assert delivered.status_code == 200 and delivered.json()['success'] is True
    sent['status'] = 500
    failed = c.post(f'/api/notifications/channels/{channel_id}/test')
    assert failed.status_code == 200 and failed.json()['success'] is False
    assert c.get('/api/notifications/channels').status_code == 200, 'with its last error'
    assert c.post('/api/notifications/channels/0/test').status_code == 404
    assert c.post('/api/notifications/channels/x/test').status_code == 422

    assert c.delete(f'/api/notifications/channels/{channel_id}').json() == {'status': 'success'}
    assert c.delete(f'/api/notifications/channels/{channel_id}').status_code == 404
    assert c.delete('/api/notifications/channels/x').status_code == 422
    assert all(url.startswith('https://api.telegram.org/') for url in sent['calls'])


def test_unsaved_destination(client):
    c, sent = client
    tried = c.post('/api/notifications/test', json={'channel_type': 'telegram', 'config': TELEGRAM['config']})
    assert tried.status_code == 200 and tried.json()['success'] is True
    # A missing field is not sent at all
    missing = c.post('/api/notifications/test', json={'channel_type': 'telegram', 'config': {}})
    assert missing.status_code == 200 and missing.json()['success'] is False
    assert len(sent['calls']) == 1
    assert c.post('/api/notifications/test', json={'channel_type': 'pager'}).status_code == 422
    assert c.post('/api/notifications/test', json={}).status_code == 422
    # A URL urlparse cannot read is not sent to, and the answer does not quote it
    broken = c.post('/api/notifications/test', json={'channel_type': 'slack', 'config': {'webhook_url': BAD_HOOK}})
    assert broken.status_code == 200 and broken.json()['success'] is False
    assert 'SECRET' not in broken.text
    assert len(sent['calls']) == 1


def test_a_destination_with_a_url_that_cannot_be_read(client, channels):
    c, sent = client
    slack = {'name': f'{MARK} slack', 'channel_type': 'slack', 'config': {'webhook_url': BAD_HOOK}}
    refused = c.post('/api/notifications/channels', json=slack)
    assert refused.status_code == 422 and 'SECRET' not in refused.text
    good = c.post('/api/notifications/channels', json={**slack, 'config': {'webhook_url': 'https://hooks.example/x'}})
    channel_id = good.json()['id']
    changed = c.put(f'/api/notifications/channels/{channel_id}', json=slack)
    assert changed.status_code == 422 and 'SECRET' not in changed.text

    # One saved before the check existed fails its test without quoting it, here or in its last error
    from app.models import NotificationChannel
    with database.get_db_context() as db:
        db.query(NotificationChannel).filter(NotificationChannel.id == channel_id).update(
            {'config': {'webhook_url': BAD_HOOK}}, synchronize_session=False)
        db.commit()
    tested = c.post(f'/api/notifications/channels/{channel_id}/test')
    assert tested.status_code == 200 and tested.json()['success'] is False
    assert 'SECRET' not in tested.text
    listed = c.get('/api/notifications/channels').json()['channels']
    saved = next(row for row in listed if row['id'] == channel_id)
    assert saved['last_status'] == 'failed' and 'SECRET' not in saved['last_error']
    assert sent['calls'] == []


def test_destinations_when_the_database_fails(client, monkeypatch):
    c, _ = client
    app.dependency_overrides[get_db] = _broken_session
    assert c.get('/api/notifications/channels').status_code == 500
    assert c.post('/api/notifications/channels', json=TELEGRAM).status_code == 500
    assert c.put('/api/notifications/channels/1', json=TELEGRAM).status_code == 500
    assert c.delete('/api/notifications/channels/1').status_code == 500
    # The saved-destination test opens its own session
    monkeypatch.setattr(database, 'get_db_context', _broken_context)
    assert c.post('/api/notifications/channels/1/test').status_code == 500
