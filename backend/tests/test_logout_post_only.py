"""Logging out changes state, so it only answers POST.

GET /api/auth/logout used to end the session, which let any page (an <img>
or a link on another site) sign the operator out. POST is covered by the
same-origin guard, which rejects a cross-site request before it runs.
"""
import base64

import pytest
from fastapi.testclient import TestClient

from app import session as session_module
from app.config import settings
from app.main import app

USERNAME = "admin"
PASSWORD = "logout-test-password"


@pytest.fixture
def signed_in(monkeypatch):
    inner = settings._inner
    monkeypatch.setattr(inner, "basic_auth_enabled", True)
    monkeypatch.setattr(inner, "auth_enabled", False)
    monkeypatch.setattr(inner, "oauth2_enabled", False)
    monkeypatch.setattr(inner, "auth_username", USERNAME)
    monkeypatch.setattr(inner, "auth_password", PASSWORD)
    client = TestClient(app, base_url="http://viewer.example.com")
    raw = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
    response = client.post("/api/auth/session", headers={"Authorization": "Basic " + raw})
    assert response.status_code == 200
    assert client.get("/api/auth/status").json()["authenticated"] is True
    yield client
    session_module._session_store.clear()


def test_get_does_not_log_out(signed_in):
    response = signed_in.get("/api/auth/logout", follow_redirects=False)
    assert response.status_code == 405
    assert response.headers["allow"] == "POST"
    assert session_module.SESSION_COOKIE_NAME in signed_in.cookies
    assert signed_in.get("/api/auth/status").json()["authenticated"] is True


def test_post_logs_out_and_redirects_to_login(signed_in):
    response = signed_in.post("/api/auth/logout", headers={"Origin": "http://viewer.example.com"},
                              follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/login"
    assert session_module.SESSION_COOKIE_NAME not in signed_in.cookies
    assert not session_module._session_store
    assert signed_in.get("/api/auth/status").status_code == 401


def test_cross_site_post_does_not_log_out(signed_in):
    response = signed_in.post("/api/auth/logout", headers={"Origin": "https://evil.example.com"},
                              follow_redirects=False)
    assert response.status_code == 403
    assert signed_in.get("/api/auth/status").json()["authenticated"] is True
