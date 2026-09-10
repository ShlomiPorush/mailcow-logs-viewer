"""Basic Auth logins are exchanged for an HttpOnly session cookie.

The password used to be kept in sessionStorage in clear text, readable by any
script running in the page. The browser now sends it exactly once, to
POST /api/auth/session, and authenticates every later request with a cookie
the page cannot read.
"""
import base64

import pytest
from fastapi.testclient import TestClient

from app import session as session_module
from app.config import settings
from app.main import app

USERNAME = "admin"
PASSWORD = "correct horse battery staple"


def _basic(username: str, password: str) -> str:
    raw = f"{username}:{password}".encode()
    return "Basic " + base64.b64encode(raw).decode()


@pytest.fixture
def basic_auth_enabled(monkeypatch):
    # `settings` is a wrapper that forwards to ._inner, so patch the inner model.
    inner = settings._inner
    monkeypatch.setattr(inner, "basic_auth_enabled", True)
    monkeypatch.setattr(inner, "auth_enabled", False)
    monkeypatch.setattr(inner, "oauth2_enabled", False)
    monkeypatch.setattr(inner, "auth_username", USERNAME)
    monkeypatch.setattr(inner, "auth_password", PASSWORD)
    yield
    session_module._session_store.clear()


@pytest.fixture
def client():
    # No context manager: the app lifespan needs a database, and none of these
    # requests reach it.
    return TestClient(app)


def test_session_endpoint_issues_an_httponly_cookie(basic_auth_enabled, client):
    response = client.post(
        "/api/auth/session", headers={"Authorization": _basic(USERNAME, PASSWORD)}
    )
    assert response.status_code == 200
    assert response.json()["auth_type"] == "basic"

    cookie = response.headers["set-cookie"]
    assert "session_id=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie
    # Plain HTTP in this test: a Secure cookie would be dropped by the browser
    # and would lock out every http:// deployment.
    assert "Secure" not in cookie


def test_session_cookie_authenticates_later_requests(basic_auth_enabled, client):
    client.post(
        "/api/auth/session", headers={"Authorization": _basic(USERNAME, PASSWORD)}
    )
    # The client keeps the cookie; no Authorization header from here on.
    status = client.get("/api/auth/status")
    assert status.status_code == 200
    body = status.json()
    assert body["authenticated"] is True
    assert body["auth_type"] == "basic"
    assert body["user"]["username"] == USERNAME


def test_wrong_password_gets_no_session(basic_auth_enabled, client):
    response = client.post(
        "/api/auth/session", headers={"Authorization": _basic(USERNAME, "wrong")}
    )
    assert response.status_code == 401
    assert "set-cookie" not in response.headers


def test_no_credentials_gets_no_session(basic_auth_enabled, client):
    response = client.post("/api/auth/session")
    assert response.status_code == 401


def test_cookie_is_secure_behind_an_https_proxy(basic_auth_enabled, client):
    response = client.post(
        "/api/auth/session",
        headers={
            "Authorization": _basic(USERNAME, PASSWORD),
            "X-Forwarded-Proto": "https",
        },
    )
    assert response.status_code == 200
    assert "Secure" in response.headers["set-cookie"]


def test_protected_endpoint_rejects_a_forged_cookie(basic_auth_enabled, client):
    client.cookies.set(session_module.SESSION_COOKIE_NAME, "not-a-signed-session")
    response = client.get("/api/auth/status")
    # /auth/status is behind the middleware, so a forged cookie is a 401.
    assert response.status_code == 401
