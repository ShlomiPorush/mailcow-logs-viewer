"""
/api/info tells a signed-in browser whether settings can be edited from the
UI. The search in the top bar leaves out its Settings results while editing
is off: they open fields that only the edit form has.
"""
import pytest
from fastapi.testclient import TestClient

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.config import settings
from app.main import app


@pytest.fixture(autouse=True)
def no_sign_in(monkeypatch):
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    monkeypatch.setattr(settings._inner, "auth_enabled", False)
    monkeypatch.setattr(settings._inner, "oauth2_enabled", False)


@pytest.mark.parametrize("editable", [True, False])
def test_info_says_whether_settings_can_be_edited(monkeypatch, editable):
    monkeypatch.setattr(settings._inner, "edit_settings_via_ui_enabled", editable)

    info = TestClient(app).get("/api/info").json()

    assert info["settings_edit_via_ui_enabled"] is editable


def test_info_keeps_it_from_a_visitor_who_is_not_signed_in(monkeypatch):
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", True)
    monkeypatch.setattr(settings._inner, "auth_username", "admin")
    monkeypatch.setattr(settings._inner, "auth_password", "correct-test-password")

    info = TestClient(app).get("/api/info").json()

    assert "settings_edit_via_ui_enabled" not in info
