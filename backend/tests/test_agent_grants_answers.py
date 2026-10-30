"""Every answer the consent page and Settings > Agents calls can give, so the contract
check (conftest.py, contract.py) holds each one to /openapi.json: an open request and
its answers (a redirect back to the agent, or done for an agent that connects with a
code), the agents with their activity, changing and disconnecting them, a database
that fails (500), and the requests the calls refuse (400, 404, 409, 422).

The routes use the database only through get_db. Here it is a session inside a
transaction that is rolled back after each test, so disconnecting every agent or
saving a code changes nothing anyone else sees. The browser sessions and open
requests of this test live in stores of their own."""
import secrets
import uuid
from datetime import timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app import database  # noqa: E402
from app import session as session_module  # noqa: E402
from app.agent_access import pending, store  # noqa: E402
from app.config import settings  # noqa: E402
from app.database import get_db  # noqa: E402
from app.main import app  # noqa: E402

MARK = uuid.uuid4().hex[:12]
APP_URL = 'https://logs.example.com'
REDIRECT = 'http://127.0.0.1:53682/callback'


class _Broken:
    def __getattr__(self, name):
        raise RuntimeError('database gone')


def _broken_session():
    yield _Broken()


def _postgres_available() -> bool:
    try:
        with database.engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture
def db(monkeypatch):
    """Agent access live with Basic Auth, and get_db as a session whose work is rolled back."""
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.models import SystemSetting
    database.init_db()
    inner = settings._inner
    monkeypatch.setattr(inner, 'basic_auth_enabled', True)
    monkeypatch.setattr(inner, 'auth_enabled', False)
    monkeypatch.setattr(inner, 'oauth2_enabled', False)
    monkeypatch.setattr(inner, 'auth_username', 'admin')
    monkeypatch.setattr(inner, 'auth_password', 'correct horse battery staple')
    monkeypatch.setattr(inner, 'agent_access_enabled', True)
    monkeypatch.setattr(inner, 'agent_access_url', APP_URL)
    monkeypatch.setattr(inner, 'agent_access_max_days', 90)
    monkeypatch.setattr(session_module, '_session_store', {})
    monkeypatch.setattr(pending, '_pending', {})

    connection = database.engine.connect()
    outer = connection.begin()
    db = Session(bind=connection, join_transaction_mode='create_savepoint')
    # The sign-in settings as stored: nothing is disconnected for a change of them
    fingerprint = store.sign_in_fingerprint()
    monkeypatch.setattr(store, '_known_fingerprint', fingerprint)
    row = db.query(SystemSetting).filter(SystemSetting.key == store._FINGERPRINT_KEY).first()
    if row is None:
        db.add(SystemSetting(key=store._FINGERPRINT_KEY, value=fingerprint, updated_at=store.now()))
    else:
        row.value = fingerprint
    db.commit()

    def rolled_back():
        yield db

    app.dependency_overrides[get_db] = rolled_back
    try:
        yield db
    finally:
        app.dependency_overrides.pop(get_db, None)
        db.close()
        outer.rollback()
        connection.close()


@pytest.fixture
def browser(db):
    """A signed-in browser: its session cookie, and its session's key."""
    signed = session_module.create_session({'username': 'admin', 'auth_method': 'basic'},
                                           generation=session_module.auth_generation())
    client = TestClient(app, raise_server_exceptions=False)
    client.cookies.set(session_module.SESSION_COOKIE_NAME, signed)
    key = session_module.get_serializer().loads(signed)
    return client, key


def _grant(db, *, active=True, scopes='security:read status:read status:write'):
    from app.models import AgentAudit, AgentGrant
    t = store.now()
    grant = AgentGrant(client_id=f'client-{MARK}', client_kind='dcr', display_name=f'Agent {MARK}',
                       declared_name='Test Agent', publisher=None, redirect_uri=REDIRECT, scopes=scopes,
                       resource=APP_URL + '/mcp', approved_by='admin', created_at=t - timedelta(days=2),
                       expires_at=t + timedelta(days=5) if active else t - timedelta(days=1),
                       last_used_at=t - timedelta(hours=1) if active else None)
    db.add(grant)
    db.commit()
    db.add(AgentAudit(grant_id=grant.id, agent_name=grant.display_name, at=t, event='call', tool='read_api',
                      method='GET', path='/api/stats/dashboard', http_status=200, outcome='ok'))
    db.add(AgentAudit(grant_id=grant.id, agent_name=grant.display_name, at=t - timedelta(days=2),
                      event='grant_created', outcome='ok'))
    db.commit()
    return grant


def _request(key, *, device_id=None, user_code=None):
    return pending.add(session_key=key, client_id=f'client-{MARK}', client_kind='device' if device_id else 'dcr',
                       declared_name='Test Agent', publisher=None, redirect_uri='' if device_id else REDIRECT,
                       state='s-123', code_challenge='c' * 43, resource=APP_URL + '/mcp',
                       requested=frozenset({'security:read'}), sign_in=store.sign_in_fingerprint(),
                       device_id=device_id, user_code=user_code)


def _device_request(db, user_code):
    from app.models import AgentDeviceRequest
    t = store.now()
    row = AgentDeviceRequest(device_code_hash=store.token_hash(secrets.token_urlsafe(16)), user_code=user_code,
                             client_id=f'client-{MARK}', label='Test Agent', requested='security:read',
                             resource=APP_URL + '/api', state='pending', created_at=t,
                             expires_at=t + timedelta(minutes=10), interval=5)
    db.add(row)
    db.commit()
    return row


# ---------------------------------------------------------------- consent

def test_open_request(browser):
    client, key = browser
    entry = _request(key)
    r = client.get(f'/api/agents/consent/{entry.id}')
    assert r.status_code == 200, r.text
    assert r.json()['client']['user_code'] is None and r.json()['signed_in_as'] == 'admin'
    assert client.get('/api/agents/consent/nope').status_code == 404


def test_open_request_while_agents_are_off(browser, monkeypatch):
    client, key = browser
    entry = _request(key)
    monkeypatch.setattr(settings._inner, 'agent_access_url', '')
    assert client.get(f'/api/agents/consent/{entry.id}').status_code == 404


def test_allow_and_deny(browser):
    client, key = browser
    allowed = client.post(f'/api/agents/consent/{_request(key).id}',
                          json={'allow': True, 'name': 'My agent', 'views': ['security'], 'acts': ['status']})
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()['redirect'].startswith(REDIRECT + '?') and 'code=' in allowed.json()['redirect']

    denied = client.post(f'/api/agents/consent/{_request(key).id}', json={'allow': False})
    assert denied.status_code == 200 and 'error=access_denied' in denied.json()['redirect']


def test_answer_an_agent_that_connects_with_a_code(browser, db):
    client, key = browser
    entry = _request(key, device_id=_device_request(db, 'ABCD2345').id, user_code='ABCD-2345')
    shown = client.get(f'/api/agents/consent/{entry.id}')
    assert shown.status_code == 200 and shown.json()['client']['user_code'] == 'ABCD-2345'
    assert shown.json()['client']['redirect_uri'] is None
    r = client.post(f'/api/agents/consent/{entry.id}', json={'allow': True, 'views': ['security'], 'days': 1})
    assert r.status_code == 200 and r.json() == {'done': True}

    denied = _request(key, device_id=_device_request(db, 'WXYZ6789').id, user_code='WXYZ-6789')
    assert client.post(f'/api/agents/consent/{denied.id}', json={'allow': False}).json() == {'done': True}


def test_consent_errors(browser):
    client, key = browser
    entry = _request(key)
    assert client.post(f'/api/agents/consent/{entry.id}', json={'allow': True}).status_code == 400
    assert client.post(f'/api/agents/consent/{entry.id}', json={'allow': 'maybe'}).status_code == 422
    assert client.post('/api/agents/consent/nope', json={'allow': False}).status_code == 404
    app.dependency_overrides[get_db] = _broken_session
    assert client.post(f'/api/agents/consent/{entry.id}', json={'allow': True, 'views': ['security']}).status_code == 500


# ---------------------------------------------------------------- Settings > Agents

def test_agents(browser, db):
    client, _key = browser
    connected, ended = _grant(db), _grant(db, active=False)
    r = client.get('/api/agents')
    assert r.status_code == 200, r.text
    body = r.json()
    assert body['live'] is True and body['problem'] is None and body['mcp_url'] == APP_URL + '/mcp'
    rows = {row['id']: row for row in body['agents']}
    assert rows[connected.id]['state'] == 'connected' and rows[connected.id]['areas'] == {'status': 'act',
                                                                                         'security': 'view'}
    assert rows[ended.id]['state'] == 'expired' and rows[ended.id]['end_reason'] == 'expired'


def test_agents_while_sign_in_is_off(db, monkeypatch):
    monkeypatch.setattr(settings._inner, 'basic_auth_enabled', False)
    r = TestClient(app).get('/api/agents')
    assert r.status_code == 200
    assert r.json()['problem'] == 'no_sign_in' and r.json()['skill_sentence'] is None


def test_change_an_agent(browser, db):
    client, _key = browser
    grant = _grant(db)
    version = store.grant_version(grant)
    r = client.put(f'/api/agents/{grant.id}', json={'views': ['messages'], 'days': 30, 'version': version})
    assert r.status_code == 200 and r.json() == {'changed': 1}

    assert client.put(f'/api/agents/{grant.id}', json={'views': ['messages'], 'version': version}).status_code == 409
    assert client.put(f'/api/agents/{grant.id}', json={'views': []}).status_code == 400
    assert client.put(f'/api/agents/{grant.id}', json={'views': ['messages'], 'days': 2}).status_code == 400
    assert client.put('/api/agents/0', json={'views': ['messages']}).status_code == 404
    assert client.put('/api/agents/x', json={'views': ['messages']}).status_code == 422
    app.dependency_overrides[get_db] = _broken_session
    assert client.put(f'/api/agents/{grant.id}', json={'views': ['messages']}).status_code == 500


def test_disconnect_one(browser, db):
    client, _key = browser
    grant = _grant(db)
    r = client.delete(f'/api/agents/{grant.id}')
    assert r.status_code == 200 and r.json() == {'disconnected': 1}
    assert client.delete(f'/api/agents/{grant.id}').status_code == 404
    assert client.delete('/api/agents/x').status_code == 422
    app.dependency_overrides[get_db] = _broken_session
    assert client.delete(f'/api/agents/{grant.id}').status_code == 500


def test_disconnect_all(browser, db):
    client, _key = browser
    _grant(db)
    r = client.delete('/api/agents')
    assert r.status_code == 200 and r.json()['disconnected'] >= 1
    app.dependency_overrides[get_db] = _broken_session
    assert client.delete('/api/agents').status_code == 500


def test_activity(browser, db):
    client, _key = browser
    grant = _grant(db)
    r = client.get(f'/api/agents/{grant.id}/activity')
    assert r.status_code == 200
    assert [row['event'] for row in r.json()['activity']] == ['call', 'grant_created']
    assert client.get('/api/agents/x/activity').status_code == 422
    app.dependency_overrides[get_db] = _broken_session
    assert client.get(f'/api/agents/{grant.id}/activity').status_code == 500


def test_agents_when_the_database_fails(browser):
    client, _key = browser
    app.dependency_overrides[get_db] = _broken_session
    assert client.get('/api/agents').status_code == 500
