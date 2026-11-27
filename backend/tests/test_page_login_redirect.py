import base64
import builtins
import re
import secrets
from pathlib import Path

import pytest
import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app import main as main_module  # noqa: E402
from app import session as session_module  # noqa: E402
from app.auth import safe_return_path  # noqa: E402
from app.config import settings  # noqa: E402
from app.frontend_assets import stamp_asset_versions  # noqa: E402
from app.main import app  # noqa: E402

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
USERNAME = "admin"
PASSWORD = secrets.token_hex(16)


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
    return TestClient(app, follow_redirects=False, raise_server_exceptions=False)


def _sign_in(client):
    client.post("/api/auth/session", headers={"Authorization": _basic(USERNAME, PASSWORD)})


@pytest.mark.parametrize("path,location", [
    ("/", "/login"),
    ("/dashboard", "/login?next=%2Fdashboard"),
    ("/messages?status=bounced", "/login?next=%2Fmessages%3Fstatus%3Dbounced"),
    ("/security/settings", "/login?next=%2Fsecurity%2Fsettings"),
])
def test_signed_out_page_redirects_to_login(auth_mode, client, path, location):
    auth_mode(basic=True, oauth2=False)
    response = client.get(path)
    assert response.status_code == 302
    assert response.headers["location"] == location
    assert response.headers["cache-control"] == "no-store"


def test_signed_out_page_redirects_with_oauth2_only(auth_mode, client):
    auth_mode(basic=False, oauth2=True)
    response = client.get("/messages")
    assert response.status_code == 302
    assert response.headers["location"] == "/login?next=%2Fmessages"


def test_signed_in_page_is_served(auth_mode, client):
    auth_mode(basic=True, oauth2=False)
    _sign_in(client)
    assert client.get("/messages").status_code != 302


def test_login_page_is_served_when_signed_out(auth_mode, client):
    auth_mode(basic=True, oauth2=False)
    assert client.get("/login?next=%2Fmessages").status_code != 302
    assert client.get("/static/app.js").status_code != 302


def test_login_page_links_its_files_by_content_hash(auth_mode, client, monkeypatch):
    def frontend_open(path, *args, **kwargs):
        if str(path).startswith("/app/frontend/"):
            path = FRONTEND / str(path)[len("/app/frontend/"):]
        return builtins.open(path, *args, **kwargs)

    monkeypatch.setattr(main_module, "open", frontend_open, raising=False)
    monkeypatch.setattr(main_module, "stamp_asset_versions", lambda html, _: stamp_asset_versions(html, str(FRONTEND)))
    auth_mode(basic=True, oauth2=False)
    response = client.get("/login")
    assert response.status_code == 200
    refs = re.findall(r'/static/[^"]+\.(?:css|js)\?v=([^"]*)"', response.text)
    assert len(refs) == 2
    assert all(re.fullmatch(r"[0-9a-f]{12}", ref) for ref in refs), refs


@pytest.mark.parametrize("query,location", [
    ("", "/"),
    ("?next=%2Fmessages", "/messages"),
    ("?next=%2F%2Fevil.example.com", "/"),
    ("?next=https%3A%2F%2Fevil.example.com", "/"),
])
def test_login_page_is_skipped_when_signed_in(auth_mode, client, query, location):
    auth_mode(basic=True, oauth2=False)
    _sign_in(client)
    response = client.get("/login" + query)
    assert response.status_code == 302
    assert response.headers["location"] == location


def test_login_page_is_skipped_without_authentication(auth_mode, client):
    auth_mode(basic=False, oauth2=False)
    response = client.get("/login?next=%2Fqueue")
    assert response.status_code == 302
    assert response.headers["location"] == "/queue"


def test_signed_out_api_still_gets_401(auth_mode, client):
    auth_mode(basic=True, oauth2=False)
    assert client.get("/api/auth/status").status_code == 401


def test_pages_are_open_without_authentication(auth_mode, client):
    auth_mode(basic=False, oauth2=False)
    assert client.get("/messages").status_code != 302


@pytest.mark.parametrize("value,expected", [
    ("/messages", "/messages"),
    ("/messages?status=bounced", "/messages?status=bounced"),
    ("/security/settings", "/security/settings"),
    (None, "/"),
    ("", "/"),
    ("messages", "/"),
    ("//evil.example.com", "/"),
    ("/\\evil.example.com", "/"),
    ("https://evil.example.com", "/"),
    ("/a\tb", "/"),
    ("/login", "/"),
    ("/login?next=/messages", "/"),
    ("/api/auth/logout", "/"),
    ("/static/app.js", "/"),
    ("/" + "a" * 2048, "/"),
])
def test_only_local_pages_are_return_paths(value, expected):
    assert safe_return_path(value) == expected


@pytest.mark.parametrize("path", ["/loginx", "/login-help", "/api/infox", "/api/health-x", "/api/auth/login2"])
def test_public_paths_match_exactly(auth_mode, client, path):
    auth_mode(basic=True, oauth2=False)
    response = client.get(path)
    if path.startswith("/api/"):
        assert response.status_code == 401
    else:
        assert response.status_code == 302
        assert response.headers["location"].startswith("/login")
