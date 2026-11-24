import base64
import secrets

import pytest
from fastapi.testclient import TestClient

from app import session as session_module
from app.config import settings
from app.main import app

USERNAME = "admin"
PASSWORD = secrets.token_hex(16)


def _basic(username: str, password: str) -> str:
    raw = f"{username}:{password}".encode()
    return "Basic " + base64.b64encode(raw).decode()


@pytest.fixture
def basic_auth_enabled(monkeypatch):
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
    assert "Secure" not in cookie


def test_session_cookie_authenticates_later_requests(basic_auth_enabled, client):
    client.post(
        "/api/auth/session", headers={"Authorization": _basic(USERNAME, PASSWORD)}
    )
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
    assert response.status_code == 401
