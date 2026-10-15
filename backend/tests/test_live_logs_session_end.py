"""A Live Logs stream ends when the session that opened it ends.

The stream's one-time token only proved that a session existed when it was
issued. After sign-out, session expiry or a change of the sign-in settings,
the HTTP API refused that session, but an open stream kept delivering mail
logs until the page was closed. A stream now carries the session and session
generation it came from and is closed (code 4001) before the next message
once either is no longer current.
"""
import asyncio
import base64
import json

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app import session
from app.config import settings
from app.main import app
from app.routers import raw_logs

USERNAME = "admin"
PASSWORD = "correct horse battery staple"
# The test client always opens WebSockets to ws://testserver
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
    signed = session.create_session({"email": "operator@example.test"})
    return signed, session.get_serializer().loads(signed)


def _stream(authority, between):
    """Open a stream, deliver one message, run `between`, deliver another."""
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
    _manager, client = _stream((key, session.auth_generation()), session.revoke_all_sessions)
    assert client.close_code == raw_logs.WS_SESSION_ENDED
    assert _entries(client) == ["before"]


def test_a_stream_opened_without_authentication_ends_when_sessions_are_revoked():
    """Turning authentication on is a sign-in settings change, which revokes
    every session; a stream opened while it was off must not outlive that."""
    _manager, client = _stream((None, session.auth_generation()), session.revoke_all_sessions)
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
    assert client.post("/api/auth/logout").status_code == 200

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
        assert client.post("/api/auth/logout").status_code == 200
        # A new log line arrives, broadcast on the app's own event loop
        ws.portal.call(raw_logs.log_stream_manager.broadcast, "postfix", [{"message": "after"}])
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
    assert closed.value.code == raw_logs.WS_SESSION_ENDED
