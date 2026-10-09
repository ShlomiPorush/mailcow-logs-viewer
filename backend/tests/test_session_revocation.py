"""Changing how people sign in revokes the sessions issued before the change.

Rotating the Basic Auth password from the Settings page used to reject the old
password at once but leave every session cookie issued with it valid until it
expired, so rotating a password did not evict whoever held a stolen cookie.
"""
import base64

import pytest
from fastapi.testclient import TestClient

from app import session
from app.config import settings
from app.database import get_db
from app.main import app
from app.routers import settings as settings_router


def basic(password="old-test-password"):
    return {"Authorization": "Basic " + base64.b64encode(f"admin:{password}".encode()).decode()}


@pytest.fixture(autouse=True)
def stored_settings(monkeypatch):
    inner = settings._inner
    monkeypatch.setattr(inner, "edit_settings_via_ui_enabled", True)
    monkeypatch.setattr(inner, "auth_enabled", False)
    monkeypatch.setattr(inner, "basic_auth_enabled", True)
    monkeypatch.setattr(inner, "oauth2_enabled", False)
    monkeypatch.setattr(inner, "auth_username", "admin")
    monkeypatch.setattr(inner, "auth_password", "old-test-password")

    def save(db, values):
        # Stand-in for the database: the saved values become the effective settings
        for key, value in values.items():
            monkeypatch.setattr(settings._inner, key, value)

    monkeypatch.setattr(settings_router, "save_config_overrides_to_db", save)
    monkeypatch.setattr(settings_router, "reload_settings", lambda db: None)
    monkeypatch.setattr(settings_router, "cleanup_disabled_feature_data", lambda db: None)
    monkeypatch.setattr(settings_router, "reschedule_interval_jobs", lambda: None)
    monkeypatch.setattr(settings_router.mailcow_api, "reload_config", lambda: None)
    monkeypatch.setattr(settings_router.oauth2_client, "reload_config", lambda: None)
    app.dependency_overrides[get_db] = lambda: object()
    session._session_store.clear()
    yield
    app.dependency_overrides.pop(get_db, None)
    session._session_store.clear()


def signed_in():
    client = TestClient(app)
    assert client.post("/api/auth/session", headers=basic()).status_code == 200
    return client


@pytest.mark.parametrize("change", [
    {"auth_password": "new-test-password"},
    {"auth_username": "operator"},
    {"oauth2_client_secret": "new-test-secret"},
    {"oauth2_issuer_url": "https://id.example.com"},
])
def test_auth_change_revokes_other_sessions_and_keeps_the_operator_signed_in(change):
    stolen, operator = signed_in(), signed_in()
    response = operator.put("/api/settings", json=change)
    assert response.status_code == 200
    assert stolen.get("/api/auth/verify").status_code == 401
    assert stolen.put("/api/settings", json={"auth_password": "attacker-test-password"}).status_code == 401
    # The operator who saved got a fresh session and is not signed out mid-save
    assert "session_id=" in response.headers.get("set-cookie", "")
    assert operator.get("/api/auth/verify").status_code == 200
    assert len(session._session_store) == 1


def test_disabling_authentication_clears_sessions():
    operator = signed_in()
    assert operator.put("/api/settings", json={"basic_auth_enabled": False}).status_code == 200
    assert not session._session_store


def test_unrelated_change_keeps_sessions():
    other, operator = signed_in(), signed_in()
    response = operator.put("/api/settings", json={"app_title": "Test viewer"})
    assert response.status_code == 200
    assert "set-cookie" not in response.headers
    assert other.get("/api/auth/verify").status_code == 200
    assert len(session._session_store) == 2


def test_resaving_the_same_credentials_keeps_sessions():
    other, operator = signed_in(), signed_in()
    assert operator.put("/api/settings", json={"auth_username": "admin"}).status_code == 200
    assert other.get("/api/auth/verify").status_code == 200
