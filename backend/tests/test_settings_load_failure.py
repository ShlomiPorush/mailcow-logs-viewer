"""A failed read of the settings stored in the database must never turn authentication off.

With SETTINGS_EDIT_VIA_UI_ENABLED=true, authentication can live only in the
database. Reading it used to fall back to the ENV-only defaults when the
database did not answer, and those defaults have authentication off: a short
PostgreSQL outage during a reload opened every API route to anyone.
"""
from contextlib import contextmanager

import pytest
from sqlalchemy.exc import OperationalError

from app import config, main
from app.config import reload_settings, settings
from app.services import settings_store

DB_AUTH = {
    "basic_auth_enabled": True,
    "auth_username": "admin",
    "auth_password": "db-test-password",
}


def _database_down(*args, **kwargs):
    raise OperationalError("SELECT 1", {}, Exception("connection refused"))


@pytest.fixture
def db_only_auth(monkeypatch):
    """Authentication configured only as database overrides, as the Settings UI stores it."""
    monkeypatch.setenv("SETTINGS_EDIT_VIA_UI_ENABLED", "true")
    for key in ("BASIC_AUTH_ENABLED", "AUTH_ENABLED", "AUTH_USERNAME", "AUTH_PASSWORD", "OAUTH2_ENABLED"):
        monkeypatch.delenv(key, raising=False)
    previous = config._settings_wrapper._inner
    monkeypatch.setattr(settings_store, "get_config_overrides_from_db", lambda *args: dict(DB_AUTH))
    reload_settings(object())
    assert settings.is_authentication_enabled
    yield
    config._settings_wrapper._inner = previous


def test_runtime_reload_keeps_authentication_when_the_database_fails(db_only_auth, monkeypatch):
    monkeypatch.setattr(settings_store, "get_config_overrides_from_db", _database_down)
    with pytest.raises(Exception):
        reload_settings(object())
    assert settings.is_authentication_enabled is True
    assert settings.auth_password == "db-test-password"


def test_settings_api_reports_the_failure_instead_of_opening_the_api(db_only_auth, monkeypatch):
    from fastapi.testclient import TestClient
    from app.database import get_db
    from app.session import SESSION_COOKIE_NAME, create_session, _session_store

    monkeypatch.setattr(settings_store, "get_config_overrides_from_db", _database_down)
    main.app.dependency_overrides[get_db] = lambda: object()
    try:
        client = TestClient(main.app, raise_server_exceptions=False)
        client.cookies.set(SESSION_COOKIE_NAME, create_session({"username": "admin"}))
        assert client.get("/api/settings").status_code == 500
        client.cookies.clear()
        # Still enforced for everyone else after the failed reload
        assert client.get("/api/settings/info").status_code == 401
    finally:
        main.app.dependency_overrides.pop(get_db, None)
        _session_store.clear()
    assert settings.is_authentication_enabled is True


def test_startup_aborts_when_stored_settings_cannot_be_read(monkeypatch):
    """The database check passed, but the override read failed: refuse to start."""
    import asyncio
    from app import database, migrations

    monkeypatch.setenv("SETTINGS_EDIT_VIA_UI_ENABLED", "true")
    monkeypatch.setattr(settings._inner, "edit_settings_via_ui_enabled", True)
    monkeypatch.setattr(main, "init_db", lambda: None)
    monkeypatch.setattr(main, "check_db_connection", lambda: True)
    monkeypatch.setattr(main, "run_migrations", lambda: None)
    monkeypatch.setattr(migrations, "run_alembic_upgrade", lambda: None)
    # Nothing past the settings load may run for real if startup wrongly continues
    from unittest.mock import AsyncMock
    monkeypatch.setattr(main, "is_license_configured", lambda: False)
    monkeypatch.setattr(main.mailcow_api, "test_connection", AsyncMock(return_value=False))
    monkeypatch.setattr(main, "start_scheduler", lambda: None)
    monkeypatch.setattr(main, "stop_scheduler", lambda: None)
    monkeypatch.setattr(main, "start_raw_logs_scheduler", lambda: None)
    monkeypatch.setattr(main, "stop_raw_logs_scheduler", lambda: None)
    monkeypatch.setattr(main.mailcow_api, "aclose", AsyncMock())

    @contextmanager
    def fake_db():
        yield object()

    monkeypatch.setattr(database, "get_db_context", fake_db)
    monkeypatch.setattr(settings_store, "get_config_overrides_from_db", _database_down)
    previous = config._settings_wrapper._inner

    async def start():
        async with main.lifespan(main.app):
            pass

    try:
        with pytest.raises(Exception):
            asyncio.run(start())
    finally:
        config._settings_wrapper._inner = previous
