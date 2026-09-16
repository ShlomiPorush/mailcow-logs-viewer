"""Compatibility contracts for framework and validation dependency upgrades."""
import base64
from unittest.mock import Mock

from fastapi.testclient import TestClient

from app import auth, session
from app.config import Settings, build_settings, settings
from app.main import app
from app.routers import raw_logs
from app.services import settings_store


def test_environment_still_overrides_database_settings(monkeypatch):
    monkeypatch.setenv("SETTINGS_EDIT_VIA_UI_ENABLED", "true")
    monkeypatch.setenv("AUTH_PASSWORD", "env-test-password")
    monkeypatch.setenv("BASIC_AUTH_ENABLED", "true")
    monkeypatch.delenv("APP_TITLE", raising=False)
    monkeypatch.setattr(settings_store, "get_config_overrides_from_db", lambda *args: {
        "auth_password": "db-test-password", "basic_auth_enabled": False,
        "app_title": "Test viewer",
    })
    effective = build_settings(Mock())
    assert effective.auth_password == "env-test-password"
    assert effective.is_basic_auth_enabled is True
    assert effective.app_title == "Test viewer"
    # Revalidation is also used by the settings editing API.
    assert Settings.model_validate(effective.model_dump()).auth_password == "env-test-password"


def test_authenticated_websocket_token_and_subscription_survive_upgrade(monkeypatch):
    monkeypatch.setattr(settings._inner, "auth_enabled", False)
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", True)
    monkeypatch.setattr(settings._inner, "oauth2_enabled", False)
    monkeypatch.setattr(settings._inner, "auth_username", "admin")
    monkeypatch.setattr(settings._inner, "auth_password", "test-password")
    monkeypatch.setattr(settings._inner, "raw_logs_services", "postfix,dovecot")
    client = TestClient(app)
    auth._auth_failures.clear()
    try:
        assert client.get("/api/raw-logs/ws-token").status_code == 401
        header = base64.b64encode(b"admin:test-password").decode()
        assert client.post("/api/auth/session", headers={"Authorization": f"Basic {header}"}).status_code == 200
        token = client.get("/api/raw-logs/ws-token").json()["token"]
        with client.websocket_connect(f"/ws/raw-logs?token={token}") as ws:
            assert ws.receive_json()["type"] == "connected"
            ws.send_json({"action": "subscribe", "service": "dovecot"})
            response = ws.receive_json()
            assert response["type"] == "subscribed"
            assert response["service"] == "dovecot"
        with client.websocket_connect(f"/ws/raw-logs?token={token}") as ws:
            assert ws.receive_json()["message"] == "Authentication required"
        assert not raw_logs.log_stream_manager.get_connection_count()
    finally:
        auth._auth_failures.clear()
        session._session_store.clear()
        raw_logs._ws_tokens.clear()
