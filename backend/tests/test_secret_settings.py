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


@pytest.mark.parametrize("env, name", [
    ({"BASIC_AUTH_ENABLED": "true", "AUTH_PASSWORD": ""}, "AUTH_PASSWORD"),
    ({"AUTH_ENABLED": "true", "AUTH_PASSWORD": ""}, "AUTH_PASSWORD"),
    ({"OAUTH2_ENABLED": "true", "OAUTH2_CLIENT_SECRET": ""}, "OAUTH2_CLIENT_SECRET"),
])
def test_a_sign_in_method_without_its_secret_is_a_problem(monkeypatch, env, name):
    assert name in config.sign_in_problem(_settings(monkeypatch, **env))


def test_sign_in_methods_with_their_secrets_are_fine(monkeypatch):
    loaded = _settings(monkeypatch, BASIC_AUTH_ENABLED="true", AUTH_PASSWORD=secrets.token_hex(16),
                       OAUTH2_ENABLED="true", OAUTH2_CLIENT_SECRET=secrets.token_hex(16))
    assert config.sign_in_problem(loaded) is None
    assert config.sign_in_problem(_settings(monkeypatch, BASIC_AUTH_ENABLED="false", AUTH_PASSWORD="",
                                            OAUTH2_ENABLED="false")) is None


def test_a_stored_password_completes_basic_auth_set_in_env(stored, monkeypatch):
    monkeypatch.setenv("BASIC_AUTH_ENABLED", "true")
    stored({"auth_password": secrets.token_hex(16)})
    assert config.sign_in_problem(build_settings(object())) is None


_SIGN_IN_ENV = ("SETTINGS_EDIT_VIA_UI_ENABLED", "AUTH_ENABLED", "BASIC_AUTH_ENABLED", "AUTH_PASSWORD",
                "OAUTH2_ENABLED", "OAUTH2_CLIENT_SECRET")


def _start(monkeypatch):
    """Run the app start up to the sign-in check, with no database or mailcow."""
    import asyncio
    from contextlib import contextmanager
    from unittest.mock import AsyncMock
    from app import database, migrations

    monkeypatch.setattr(main, "init_db", lambda: None)
    monkeypatch.setattr(main, "check_db_connection", lambda: True)
    monkeypatch.setattr(main, "run_migrations", lambda: None)
    monkeypatch.setattr(migrations, "run_alembic_upgrade", lambda: None)

    @contextmanager
    def fake_db():
        yield object()
    monkeypatch.setattr(database, "get_db_context", fake_db)
    # Nothing past the check may run for real if startup wrongly continues
    monkeypatch.setattr(main, "is_license_configured", lambda: False)
    monkeypatch.setattr(main.mailcow_api, "test_connection", AsyncMock(return_value=False))
    monkeypatch.setattr(main, "start_scheduler", lambda: None)
    monkeypatch.setattr(main, "stop_scheduler", lambda: None)
    monkeypatch.setattr(main, "start_raw_logs_scheduler", lambda: None)
    monkeypatch.setattr(main, "stop_raw_logs_scheduler", lambda: None)
    monkeypatch.setattr(main.mailcow_api, "aclose", AsyncMock())

    async def start():
        async with main.lifespan(main.app):
            pass
    previous = config._settings_wrapper._inner
    try:
        asyncio.run(start())
    finally:
        config._settings_wrapper._inner = previous


def test_the_app_does_not_start_with_basic_auth_and_no_password(monkeypatch):
    monkeypatch.setattr(settings._inner, "edit_settings_via_ui_enabled", False)
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", True)
    monkeypatch.setattr(settings._inner, "auth_password", "")
    with pytest.raises(SettingsLoadError, match="AUTH_PASSWORD is not set"):
        _start(monkeypatch)


def test_the_app_does_not_start_with_oauth2_stored_without_a_client_secret(stored, monkeypatch):
    for name in _SIGN_IN_ENV[1:]:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(settings._inner, "edit_settings_via_ui_enabled", True)
    stored({"oauth2_enabled": True})
    with pytest.raises(SettingsLoadError, match="OAUTH2_CLIENT_SECRET is not set"):
        _start(monkeypatch)


def _save(monkeypatch, stored_values, body):
    """PUT /api/settings against stored settings, with sign-in off for the request itself."""
    from fastapi.testclient import TestClient
    from app.database import get_db
    from app.routers import settings as settings_router

    monkeypatch.setenv("SETTINGS_EDIT_VIA_UI_ENABLED", "true")
    monkeypatch.setattr(settings._inner, "edit_settings_via_ui_enabled", True)
    for flag in ("basic_auth_enabled", "auth_enabled", "oauth2_enabled"):
        monkeypatch.setattr(settings._inner, flag, False)
    monkeypatch.setattr(settings_store, "get_config_overrides_from_db", lambda *args: dict(stored_values))
    saved = []
    monkeypatch.setattr(settings_router, "save_config_overrides_to_db", lambda *args: saved.append(args))
    main.app.dependency_overrides[get_db] = lambda: object()
    try:
        answer = TestClient(main.app, raise_server_exceptions=False).put("/api/settings", json=body)
    finally:
        main.app.dependency_overrides.pop(get_db, None)
    return answer, saved


@pytest.fixture
def no_sign_in_env(monkeypatch):
    for name in _SIGN_IN_ENV[1:]:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(settings._inner, "oauth2_client_secret", None)


def test_settings_does_not_save_oauth2_without_a_client_secret(no_sign_in_env, monkeypatch):
    answer, saved = _save(monkeypatch, {}, {"oauth2_enabled": True})
    assert answer.status_code == 400, answer.text
    assert "OAUTH2_CLIENT_SECRET" in answer.json()["detail"]
    assert saved == []


def test_turning_off_a_flag_that_env_sets_does_not_let_the_secret_go(no_sign_in_env, monkeypatch):
    # OAUTH2_ENABLED from .env stays in force, whatever the save sends for it
    monkeypatch.setenv("OAUTH2_ENABLED", "true")
    answer, saved = _save(monkeypatch, {"oauth2_client_secret": secrets.token_hex(16)},
                          {"oauth2_enabled": False, "oauth2_client_secret": ""})
    assert answer.status_code == 400, answer.text
    assert "OAUTH2_CLIENT_SECRET" in answer.json()["detail"]
    assert saved == []


def test_the_save_checks_the_settings_as_stored_now(no_sign_in_env, monkeypatch):
    # Another save turned OAuth2 on after this app last loaded its settings
    answer, saved = _save(monkeypatch, {"oauth2_enabled": True, "oauth2_client_secret": secrets.token_hex(16)},
                          {"oauth2_client_secret": ""})
    assert answer.status_code == 400, answer.text
    assert "OAUTH2_CLIENT_SECRET" in answer.json()["detail"]
    assert saved == []
