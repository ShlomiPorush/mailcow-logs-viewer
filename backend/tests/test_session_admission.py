"""Only a real sign-in starts a session's clocks, and access derived from a
request is tied to how that request was let in.

- A signed-in browser could post to /api/auth/session without the password
  and get a new session with a fresh length, again and again: the session
  never ended. A new session now needs the password every time.
- The Live Logs token was issued for whatever the session state was when the
  handler ran, not when the request was let in. A session that ended in
  between, or a sign-in change in between, still got a token, and the stream
  it opened outlived the session.
- Re-issuing the operator's session after a sign-in settings change gave it a
  fresh full length, so saving the settings extended the session.
"""
import base64

import pytest
from fastapi.testclient import TestClient

from app import auth as auth_module
from app import session
from app.config import settings
from app.main import app
from app.routers import raw_logs
from test_session_revocation import basic, signed_in, store  # noqa: F401 (store: autouse fixture)

HOUR = 3600.0


@pytest.fixture(autouse=True)
def clean():
    auth_module._auth_failures.clear()
    raw_logs._ws_tokens.clear()
    yield
    auth_module._auth_failures.clear()
    raw_logs._ws_tokens.clear()


@pytest.fixture
def clock(monkeypatch):
    now = {"t": 1_000_000.0}
    monkeypatch.setattr(session, "_now", lambda: now["t"], raising=False)
    return now


# ── A new session needs the password ───────────────────────────────────────

def test_a_session_cookie_alone_gets_no_new_session():
    client = signed_in()
    response = client.post("/api/auth/session")
    assert response.status_code == 401
    assert "session_id=" not in response.headers.get("set-cookie", "")
    assert len(session._session_store) == 1


def test_a_session_cookie_with_a_wrong_password_gets_no_new_session_and_counts():
    client = signed_in()
    response = client.post("/api/auth/session", headers=basic("wrong-test-password"))
    assert response.status_code == 401
    assert len(session._session_store) == 1
    assert sum(len(failures) for failures in auth_module._auth_failures.values()) == 1


def test_the_password_gets_a_new_session():
    client = signed_in()
    response = client.post("/api/auth/session", headers=basic())
    assert response.status_code == 200
    assert "session_id=" in response.headers.get("set-cookie", "")
    assert len(session._session_store) == 2


# ── The Live Logs token follows the request's admission ───────────────────

def _token_with(monkeypatch, between, client, headers=None):
    """Ask for a Live Logs token; `between` runs after the request was let in
    and before the token is issued."""
    real = raw_logs._cleanup_expired_tokens

    def cleanup_then_change():
        between()
        real()

    monkeypatch.setattr(raw_logs, "_cleanup_expired_tokens", cleanup_then_change)
    return client.get("/api/raw-logs/ws-token", headers=headers or {})


def test_a_session_that_ends_before_the_token_gets_none(monkeypatch):
    client = signed_in()
    cookie = client.cookies.get(session.SESSION_COOKIE_NAME)
    response = _token_with(monkeypatch, lambda: session.delete_session(cookie), client)
    assert response.status_code == 401
    assert not raw_logs._ws_tokens


def test_basic_credentials_let_in_before_a_sign_in_change_get_no_token(monkeypatch):
    response = _token_with(monkeypatch, session.revoke_all_sessions, TestClient(app), basic())
    assert response.status_code == 401
    assert not raw_logs._ws_tokens


def test_a_request_let_in_while_sign_in_was_off_gets_no_token_once_it_is_on(monkeypatch):
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    monkeypatch.setattr(settings._inner, "auth_enabled", False)

    def sign_in_turned_on():
        settings._inner.basic_auth_enabled = True
        session.revoke_all_sessions()

    response = _token_with(monkeypatch, sign_in_turned_on, TestClient(app))
    assert response.status_code == 401
    assert not raw_logs._ws_tokens


def test_a_current_session_and_current_credentials_get_a_token():
    assert signed_in().get("/api/raw-logs/ws-token").status_code == 200
    assert TestClient(app).get("/api/raw-logs/ws-token", headers=basic()).status_code == 200


# ── Re-issuing the operator's session keeps its clocks ────────────────────

def _max_age(response) -> int:
    cookie = response.headers["set-cookie"]
    return int(cookie.split("Max-Age=", 1)[1].split(";", 1)[0])


def test_saving_sign_in_settings_near_the_end_does_not_extend_the_session(clock):
    operator = signed_in()
    clock["t"] += 23 * HOUR
    response = operator.put("/api/settings", json={"auth_password": "new-test-password"})
    assert response.status_code == 200
    assert _max_age(response) == int(HOUR)
    clock["t"] += HOUR
    assert operator.get("/api/auth/verify").status_code == 401
