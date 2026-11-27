import asyncio
import base64
import secrets
import json

import pytest
from fastapi.testclient import TestClient
import starlette.staticfiles as sf
from starlette.websockets import WebSocketDisconnect

_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, "check_dir": False})

from app import session, user_access
from app.config import settings
from app.main import app
from app.routers import raw_logs
from sign_in_helpers import revoke_all_sessions

USERNAME = "admin"
PASSWORD = secrets.token_hex(16)
APP = "http://testserver"


class Client:
    def __init__(self):
        self.messages = []
        self.close_code = None

    async def accept(self):
        pass

    async def send_text(self, text):
        self.messages.append(json.loads(text))

    async def close(self, code=1000, reason=""):
        self.close_code = code


@pytest.fixture(autouse=True)
def clean_sessions():
    session._session_store.clear()
    raw_logs._ws_tokens.clear()
    yield
    session._session_store.clear()
    raw_logs._ws_tokens.clear()


def _open_session():
    user_info = {"email": "operator@example.test"}
    signed = session.create_session(user_info, generation=session.auth_generation(),
                                    principal=user_access.oauth2_ref(user_info))
    return signed, session.get_serializer().loads(signed)


def _stream(authority, between):
    async def run():
        manager = raw_logs.LogStreamManager()
        client = Client()
        await manager.connect(client, "postfix", authority)
        await manager.broadcast("postfix", [{"message": "before"}])
        between()
        await manager.broadcast("postfix", [{"message": "after"}])
        return manager, client
    return asyncio.run(run())


def _entries(client):
    return [m["entries"][0]["message"] for m in client.messages]


def test_sign_out_ends_the_stream():
    signed, key = _open_session()
    manager, client = _stream((key, session.auth_generation()), lambda: session.delete_session(signed))
    assert client.close_code == raw_logs.WS_SESSION_ENDED
    assert _entries(client) == ["before"]
    assert manager.get_connection_count() == {}


def test_revoking_all_sessions_ends_the_stream():
    _signed, key = _open_session()
    _manager, client = _stream((key, session.auth_generation()), revoke_all_sessions)
    assert client.close_code == raw_logs.WS_SESSION_ENDED
    assert _entries(client) == ["before"]


def test_a_stream_opened_without_authentication_ends_when_sessions_are_revoked():
    _manager, client = _stream((None, session.auth_generation()), revoke_all_sessions)
    assert client.close_code == raw_logs.WS_SESSION_ENDED
    assert _entries(client) == ["before"]


def test_a_current_session_keeps_its_stream():
    _signed, key = _open_session()
    _manager, client = _stream((key, session.auth_generation()), lambda: None)
    assert client.close_code is None
    assert _entries(client) == ["before", "after"]


@pytest.fixture
def basic_auth(monkeypatch):
    inner = settings._inner
    monkeypatch.setattr(inner, "basic_auth_enabled", True)
    monkeypatch.setattr(inner, "auth_enabled", False)
    monkeypatch.setattr(inner, "oauth2_enabled", False)
    monkeypatch.setattr(inner, "auth_username", USERNAME)
    monkeypatch.setattr(inner, "auth_password", PASSWORD)
    monkeypatch.setattr(inner, "raw_logs_services", "postfix")
    monkeypatch.setattr(raw_logs, "log_stream_manager", raw_logs.LogStreamManager())


def _signed_in_client():
    client = TestClient(app)
    raw = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
    assert client.post("/api/auth/session", headers={"Authorization": f"Basic {raw}"}).status_code == 200
    return client


def test_a_token_whose_session_ended_opens_no_stream(basic_auth):
    client = _signed_in_client()
    token = client.get("/api/raw-logs/ws-token").json()["token"]
    assert client.post("/api/auth/logout", follow_redirects=False).status_code == 302

    with client.websocket_connect(f"/ws/raw-logs?token={token}", headers={"Origin": APP}) as ws:
        assert ws.receive_json()["type"] == "error"
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
    assert closed.value.code == 4401


def test_a_token_from_a_current_session_opens_a_stream(basic_auth):
    client = _signed_in_client()
    token = client.get("/api/raw-logs/ws-token").json()["token"]
    with client.websocket_connect(f"/ws/raw-logs?token={token}", headers={"Origin": APP}) as ws:
        assert ws.receive_json()["type"] == "connected"


def test_signing_out_closes_an_open_stream(basic_auth):
    client = _signed_in_client()
    token = client.get("/api/raw-logs/ws-token").json()["token"]
    with client.websocket_connect(f"/ws/raw-logs?token={token}", headers={"Origin": APP}) as ws:
        assert ws.receive_json()["type"] == "connected"
        assert client.post("/api/auth/logout", follow_redirects=False).status_code == 302
        ws.portal.call(raw_logs.log_stream_manager.broadcast, "postfix", [{"message": "after"}])
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
    assert closed.value.code == raw_logs.WS_SESSION_ENDED
