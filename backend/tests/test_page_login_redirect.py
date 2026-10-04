"""A signed-out page request goes straight to the login page.

The pages used to be served to anyone, and the page's own script sent the
browser to /login only after it had drawn the app. The server now answers a
page request without a session with a redirect, so nothing of the app shows.
"""
import base64

import pytest
import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app import session as session_module  # noqa: E402
from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402

USERNAME = "admin"
PASSWORD = "correct horse battery staple"


def _basic(username: str, password: str) -> str:
    raw = f"{username}:{password}".encode()
    return "Basic " + base64.b64encode(raw).decode()


@pytest.fixture
def auth_mode(monkeypatch):
    inner = settings._inner

    def set_mode(basic: bool, oauth2: bool):
        monkeypatch.setattr(inner, "basic_auth_enabled", basic)
        monkeypatch.setattr(inner, "auth_enabled", False)
        monkeypatch.setattr(inner, "oauth2_enabled", oauth2)
        monkeypatch.setattr(inner, "auth_username", USERNAME)
        monkeypatch.setattr(inner, "auth_password", PASSWORD)

    yield set_mode
    session_module._session_store.clear()


@pytest.fixture
def client():
    # No context manager: the app lifespan needs a database, and none of these
    # requests reach it. CI has no /app/frontend, so a page that gets through
    # answers with an error; these tests only care whether it was redirected.
    return TestClient(app, follow_redirects=False, raise_server_exceptions=False)


def _is_login_redirect(response) -> bool:
    return response.status_code == 302 and response.headers["location"] == "/login"


@pytest.mark.parametrize("path", ["/", "/dashboard", "/messages", "/security/settings"])
def test_signed_out_page_redirects_to_login(auth_mode, client, path):
    auth_mode(basic=True, oauth2=False)
    response = client.get(path)
    assert _is_login_redirect(response)
    assert response.headers["cache-control"] == "no-store"


def test_signed_out_page_redirects_with_oauth2_only(auth_mode, client):
    auth_mode(basic=False, oauth2=True)
    assert _is_login_redirect(client.get("/messages"))


def test_signed_in_page_is_served(auth_mode, client):
    auth_mode(basic=True, oauth2=False)
    client.post("/api/auth/session", headers={"Authorization": _basic(USERNAME, PASSWORD)})
    assert client.get("/messages").status_code != 302


def test_login_page_and_assets_stay_public(auth_mode, client):
    auth_mode(basic=True, oauth2=False)
    assert client.get("/login").status_code != 302
    assert client.get("/static/app.js").status_code != 302


def test_signed_out_api_still_gets_401(auth_mode, client):
    auth_mode(basic=True, oauth2=False)
    assert client.get("/api/auth/status").status_code == 401


def test_pages_are_open_without_authentication(auth_mode, client):
    auth_mode(basic=False, oauth2=False)
    assert client.get("/messages").status_code != 302
