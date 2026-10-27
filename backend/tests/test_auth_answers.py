"""Every answer the sign-in calls can give, so the contract check (conftest.py,
contract.py) holds each one to /openapi.json: the sign-in state and methods, a Basic
Auth session (also refused while Basic Auth is off, after a sign-in change during the
login, and at capacity), the OAuth2 login and callback redirects, their refusals
while OAuth2 is off or not set up, and signing out. The OAuth2 provider is faked;
the sessions and used login states of this test are kept apart from everyone else's."""
import base64
from collections import OrderedDict
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app import session as session_module  # noqa: E402
from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402
from app.routers import auth  # noqa: E402
from app.services import oauth2_client as oauth2_module  # noqa: E402

USERNAME = 'admin'
PASSWORD = 'correct horse battery staple'
BASIC = 'Basic ' + base64.b64encode(f'{USERNAME}:{PASSWORD}'.encode()).decode()
AUTHORIZE = 'https://id.example.com/authorize'
TOKEN = 'https://id.example.com/token'
USERINFO = 'https://id.example.com/userinfo'


@pytest.fixture(autouse=True)
def own_sessions(monkeypatch):
    """This test's sessions and used OAuth2 states, in stores of their own."""
    monkeypatch.setattr(session_module, '_session_store', {})
    monkeypatch.setattr(auth, '_consumed_states', OrderedDict())


@pytest.fixture
def signed_out(monkeypatch):
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)


@pytest.fixture
def basic(monkeypatch):
    inner = settings._inner
    monkeypatch.setattr(inner, 'basic_auth_enabled', True)
    monkeypatch.setattr(inner, 'auth_enabled', False)
    monkeypatch.setattr(inner, 'oauth2_enabled', False)
    monkeypatch.setattr(inner, 'auth_username', USERNAME)
    monkeypatch.setattr(inner, 'auth_password', PASSWORD)


@pytest.fixture
def provider(monkeypatch):
    """OAuth2 on, the real client against a fake provider (as in test_oauth_pkce.py)."""
    client = auth.oauth2_client
    monkeypatch.setattr(settings._inner, 'oauth2_enabled', True)
    monkeypatch.setattr(settings._inner, 'basic_auth_enabled', False)
    monkeypatch.setattr(settings._inner, 'oauth2_provider_name', 'Example ID')
    monkeypatch.setattr(client, 'issuer_url', None)
    monkeypatch.setattr(client, 'client_id', 'viewer-test')
    monkeypatch.setattr(client, 'client_secret', 'viewer-test-secret')
    monkeypatch.setattr(client, 'redirect_uri', 'https://viewer.example.com/api/auth/callback')
    monkeypatch.setattr(client, 'scopes', ['openid', 'profile', 'email'])
    monkeypatch.setattr(client, 'authorization_url', AUTHORIZE)
    monkeypatch.setattr(client, 'token_url', TOKEN)
    monkeypatch.setattr(client, 'userinfo_url', USERINFO)

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == TOKEN:
            return httpx.Response(200, json={'access_token': 'test-token', 'token_type': 'Bearer'})
        if str(request.url) == USERINFO:
            return httpx.Response(200, json={'sub': '42', 'email': 'user@example.com', 'groups': ['admins']})
        return httpx.Response(404)

    real_async_client = httpx.AsyncClient
    monkeypatch.setattr(oauth2_module.httpx, 'AsyncClient',
                        lambda *a, **kw: real_async_client(*a, **{**kw, 'transport': httpx.MockTransport(handler)}))
    return client


def _client():
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------- state and methods

def test_verify_and_provider_info(signed_out):
    client = _client()
    assert client.get('/api/auth/verify').json() == {'verified': True}
    info = client.get('/api/auth/provider-info')
    assert info.status_code == 200 and info.json()['provider_name'] is None


def test_provider_info_with_oauth2(provider):
    info = _client().get('/api/auth/provider-info')
    assert info.status_code == 200 and info.json()['provider_name'] == 'Example ID'


def test_status_signed_out(signed_out):
    r = _client().get('/api/auth/status')
    assert r.status_code == 200 and r.json() == {'authenticated': False, 'auth_type': None, 'user': None, 'session': None}


def test_status_with_basic_auth_and_with_a_session(basic):
    client = _client()
    header_only = client.get('/api/auth/status', headers={'Authorization': BASIC})
    assert header_only.status_code == 200 and header_only.json()['user'] is None

    session = client.post('/api/auth/session', headers={'Authorization': BASIC})
    assert session.status_code == 200 and session.json() == {'authenticated': True, 'auth_type': 'basic'}
    status = client.get('/api/auth/status')
    assert status.status_code == 200
    assert status.json()['user'] == {'username': USERNAME, 'auth_method': 'basic'}


# ---------------------------------------------------------------- Basic Auth session

def test_session_while_basic_auth_is_off(signed_out):
    assert _client().post('/api/auth/session').status_code == 400


def test_session_after_a_sign_in_change_during_the_login(basic, monkeypatch):
    """Sign-in settings change between the check of the password and the session."""
    real = session_module.create_session

    def changed_meanwhile(user_info, *, generation):
        monkeypatch.setattr(session_module, '_auth_generation', session_module.auth_generation() + 1)
        return real(user_info, generation=generation)

    monkeypatch.setattr(auth, 'create_session', changed_meanwhile)
    r = _client().post('/api/auth/session', headers={'Authorization': BASIC})
    assert r.status_code == 409
    assert session_module._session_store == {}


def test_session_at_capacity(basic, monkeypatch):
    monkeypatch.setattr(settings._inner, 'session_max_entries', 0)
    r = _client().post('/api/auth/session', headers={'Authorization': BASIC})
    assert r.status_code == 503 and r.headers['retry-after'] == '60'


# ---------------------------------------------------------------- OAuth2

def test_login_and_callback_while_oauth2_is_off(signed_out):
    client = _client()
    assert client.get('/api/auth/login', follow_redirects=False).status_code == 400
    assert client.get('/api/auth/callback', params={'state': 'x', 'code': 'y'}, follow_redirects=False).status_code == 400


def test_login_when_oauth2_is_not_set_up(provider, monkeypatch):
    monkeypatch.setattr(provider, 'client_secret', None)
    assert _client().get('/api/auth/login', follow_redirects=False).status_code == 500


def test_login_when_discovery_fails(provider, monkeypatch):
    """Discovery at the provider fails and no endpoints are set by hand."""
    monkeypatch.setattr(provider, 'issuer_url', 'https://id.example.com')
    monkeypatch.setattr(provider, 'authorization_url', None)
    monkeypatch.setattr(provider, '_discovery_cache', None, raising=False)
    monkeypatch.setattr(settings._inner, 'oauth2_use_oidc_discovery', True)
    r = _client().get('/api/auth/login', follow_redirects=False)
    assert r.status_code == 500


def test_login_and_callback(provider):
    client = _client()
    login = client.get('/api/auth/login', params={'next': '/messages'}, follow_redirects=False)
    assert login.status_code == 307 and login.content == b''
    location = login.headers['location']
    assert location.startswith(AUTHORIZE + '?')
    state = parse_qs(urlsplit(location).query)['state'][0]

    callback = client.get('/api/auth/callback', params={'state': state, 'code': 'test-code'},
                          follow_redirects=False)
    assert callback.status_code == 302 and callback.headers['location'] == '/messages'
    assert 'session_id' in client.cookies

    status = client.get('/api/auth/status')
    assert status.json()['auth_type'] == 'oauth2' and status.json()['user']['groups'] == ['admins']

    again = client.get('/api/auth/callback', params={'state': state, 'code': 'test-code'}, follow_redirects=False)
    assert again.status_code == 302 and again.headers['location'] == '/login?error=invalid_state'


def test_callback_when_the_provider_declines(provider):
    client = _client()
    location = client.get('/api/auth/login', follow_redirects=False).headers['location']
    state = parse_qs(urlsplit(location).query)['state'][0]
    r = client.get('/api/auth/callback', params={'state': state, 'error': 'access_denied'}, follow_redirects=False)
    assert r.status_code == 302 and r.headers['location'] == '/login?error=oauth2_error'


# ---------------------------------------------------------------- signing out

def test_logout(basic):
    client = _client()
    assert client.post('/api/auth/session', headers={'Authorization': BASIC}).status_code == 200
    r = client.post('/api/auth/logout', follow_redirects=False)
    assert r.status_code == 302 and r.headers['location'] == '/login' and r.content == b''
    assert session_module._session_store == {}
