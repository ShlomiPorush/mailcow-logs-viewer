"""The app does not start with a missing required secret or a published example value.

The examples in this project's documentation, old env.example, CI and demo are
public, so a setting that holds one guards nothing. Settings refuses them from
ENV (at start), from the database (when the stored settings load) and from a
Settings save.
"""
import secrets

import pytest
from pydantic import ValidationError

from app import config, main
from app.config import Settings, SettingsLoadError, build_settings, settings
from app.services import settings_store


def _settings(monkeypatch, **env):
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return Settings()


@pytest.mark.parametrize("value", [
    "changeme", " changeme ", "ChangeMe", "a7f3c8e2-4b1d-4f9a-8c3e-7d2f1a9b5e4c",
    "replace-with-a-random-hex-password", "ci", "demo", "test", "", "   ",
])
def test_the_database_password_cannot_be_empty_or_an_example(monkeypatch, value):
    with pytest.raises(ValidationError, match="POSTGRES_PASSWORD"):
        _settings(monkeypatch, POSTGRES_PASSWORD=value)


@pytest.mark.parametrize("value", ["", " ", "your-api-key-here", "ci-placeholder", "test-key"])
def test_the_mailcow_api_key_cannot_be_empty_or_an_example(monkeypatch, value):
    with pytest.raises(ValidationError, match="MAILCOW_API_KEY"):
        _settings(monkeypatch, MAILCOW_API_KEY=value)


@pytest.mark.parametrize("name", ["AUTH_PASSWORD", "MAILCOW_API_KEY_RW", "RSPAMD_PASSWORD", "SMTP_PASSWORD",
                                  "SESSION_SECRET_KEY", "OAUTH2_CLIENT_SECRET", "DMARC_IMAP_PASSWORD",
                                  "MAXMIND_LICENSE_KEY"])
@pytest.mark.parametrize("value", ["changeme", "pass", "replace-with-client-secret", "your_password", "  "])
def test_an_optional_secret_cannot_be_an_example_or_blank(monkeypatch, name, value):
    with pytest.raises(ValidationError, match=name):
        _settings(monkeypatch, **{name: value})


def test_an_optional_secret_left_empty_is_simply_not_set(monkeypatch):
    loaded = _settings(monkeypatch, AUTH_PASSWORD="", SESSION_SECRET_KEY="")
    assert loaded.auth_password == "" and loaded.session_secret_key == ""


def test_values_of_your_own_start(monkeypatch):
    own = secrets.token_hex(16)
    loaded = _settings(monkeypatch, POSTGRES_PASSWORD=own, AUTH_PASSWORD=f" {own} ")
    assert loaded.postgres_password == own
    # The value itself is kept as given; only the check ignores the spaces
    assert loaded.auth_password == f" {own} "


@pytest.fixture
def stored(monkeypatch):
    """Settings stored in the database, as the Settings page saves them."""
    monkeypatch.setenv("SETTINGS_EDIT_VIA_UI_ENABLED", "true")
    for name in ("AUTH_PASSWORD", "SMTP_PASSWORD"):
        monkeypatch.delenv(name, raising=False)

    def store(overrides):
        monkeypatch.setattr(settings_store, "get_config_overrides_from_db", lambda *args: dict(overrides))
    return store


@pytest.mark.parametrize("value", ["changeme", " replace-with-a-long-random-password ", "   "])
def test_a_stored_example_value_refuses_the_load(stored, value):
    stored({"auth_password": value})
    with pytest.raises(SettingsLoadError, match="AUTH_PASSWORD, stored in Settings"):
        build_settings(object())


def test_env_still_wins_over_a_stored_example_value(stored, monkeypatch):
    own = secrets.token_hex(16)
    monkeypatch.setenv("AUTH_PASSWORD", own)
    stored({"auth_password": "changeme"})
    assert build_settings(object()).auth_password == own


def test_a_stored_value_of_your_own_loads(stored):
    own = secrets.token_hex(16)
    stored({"smtp_password": own})
    assert build_settings(object()).smtp_password == own


def test_settings_does_not_save_an_example_value(monkeypatch):
    from fastapi.testclient import TestClient
    from app.database import get_db

    monkeypatch.setattr(settings._inner, "edit_settings_via_ui_enabled", True)
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    monkeypatch.setattr(settings._inner, "auth_enabled", False)
    monkeypatch.setattr(settings._inner, "oauth2_enabled", False)
    saved = []
    monkeypatch.setattr(settings_store, "save_config_overrides_to_db", lambda *args: saved.append(args))
    main.app.dependency_overrides[get_db] = lambda: object()
    try:
        client = TestClient(main.app, raise_server_exceptions=False)
        answer = client.put("/api/settings", json={"smtp_password": "changeme"})
    finally:
        main.app.dependency_overrides.pop(get_db, None)
    assert answer.status_code == 400, answer.text
    assert "smtp_password" in answer.json()["detail"]
    assert saved == []
