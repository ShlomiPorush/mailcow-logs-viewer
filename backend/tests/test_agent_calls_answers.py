"""GET /api/agent/access and /api/agent/endpoints: every answer the auth middleware
gives them (agent_access/rest.py), so the contract check (conftest.py) holds each
one to /openapi.json: the answers, an unknown area (400), no valid token (401)
and too many bad tokens (429). The token check is faked; no database is needed."""
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app.agent_access import live, rest, scopes  # noqa: E402
from app.main import app  # noqa: E402

BEARER = {'Authorization': 'Bearer a-token'}


@pytest.fixture
def agent(monkeypatch):
    grant = SimpleNamespace(name='Test agent', expires_at=datetime.utcnow() + timedelta(days=1),
                            scopes=frozenset(scopes.read_scopes()))
    state = {'grant': grant}

    async def check_token(function, *args):
        return state['grant']

    monkeypatch.setattr(live, 'is_live', lambda: True)
    monkeypatch.setattr(live, 'issuer', lambda: 'https://logs.example.com')
    monkeypatch.setattr(live, 'api_resource', lambda: 'https://logs.example.com/api')
    monkeypatch.setattr(rest, 'db_call', check_token)
    # A bad token here counts against no other test
    monkeypatch.setattr(rest.failed_tokens, '_events', type(rest.failed_tokens._events)())
    return state


def test_what_the_connection_may_do(agent):
    client = TestClient(app)
    assert client.get('/api/agent/access', headers=BEARER).json()['connection'] == 'Test agent'
    listed = client.get('/api/agent/endpoints', headers=BEARER).json()
    assert listed['count'] == len(listed['endpoints']) > 0
    assert client.get('/api/agent/endpoints?area=nope', headers=BEARER).status_code == 400


def test_no_valid_token(agent, monkeypatch):
    agent['grant'] = None
    assert TestClient(app).get('/api/agent/access', headers=BEARER).status_code == 401
    monkeypatch.setattr(live, 'is_live', lambda: False)
    assert TestClient(app).get('/api/agent/endpoints', headers=BEARER).status_code == 401


def test_too_many_bad_tokens(agent, monkeypatch):
    monkeypatch.setattr(rest.failed_tokens, 'full', lambda ip: True)
    assert TestClient(app).get('/api/agent/access', headers=BEARER).status_code == 429
    assert TestClient(app).get('/api/agent/endpoints', headers=BEARER).status_code == 429
