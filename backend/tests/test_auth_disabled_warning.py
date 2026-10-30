"""Running without any authentication is logged as a warning at startup, not as info."""
import logging

from app import main
from app.config import settings


def test_no_authentication_is_a_startup_warning(monkeypatch, caplog):
    monkeypatch.setattr(settings._inner, "auth_enabled", False)
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    monkeypatch.setattr(settings._inner, "oauth2_enabled", False)
    with caplog.at_level(logging.INFO, logger="app.main"):
        main.log_authentication_state()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("Authentication is DISABLED" in r.getMessage() for r in warnings)


def test_enabled_authentication_is_info(monkeypatch, caplog):
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", True)
    monkeypatch.setattr(settings._inner, "auth_password", "test-password")
    with caplog.at_level(logging.INFO, logger="app.main"):
        main.log_authentication_state()
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("Authentication is ENABLED" in r.getMessage() for r in caplog.records)
