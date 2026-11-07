"""The Content-Security-Policy every page and API response carries.

script-src kept 'unsafe-eval' for a Tailwind runtime in the browser long
after that runtime was removed. Nothing the app serves needs eval, so the
policy must not allow it on any response.
"""
import base64
import builtins
from pathlib import Path

import pytest
import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app import main as main_module  # noqa: E402
from app import session as session_module  # noqa: E402
from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
USERNAME = "admin"
PASSWORD = "correct horse battery staple"


@pytest.fixture
def client(monkeypatch):
    inner = settings._inner
    monkeypatch.setattr(inner, "basic_auth_enabled", True)
    monkeypatch.setattr(inner, "auth_enabled", False)
    monkeypatch.setattr(inner, "oauth2_enabled", False)
    monkeypatch.setattr(inner, "auth_username", USERNAME)
    monkeypatch.setattr(inner, "auth_password", PASSWORD)

    # The pages read /app/frontend, which exists only in the image
    def frontend_open(path, *args, **kwargs):
        if str(path).startswith("/app/frontend/"):
            path = FRONTEND / str(path)[len("/app/frontend/"):]
        return builtins.open(path, *args, **kwargs)

    monkeypatch.setattr(main_module, "open", frontend_open, raising=False)
    yield TestClient(app, follow_redirects=False, raise_server_exceptions=False)
    session_module._session_store.clear()


def _directives(response):
    policy = response.headers["content-security-policy"]
    return {part.split()[0]: part.split()[1:] for part in policy.split(";") if part.strip()}


def _sign_in(client):
    raw = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
    assert client.post("/api/auth/session", headers={"Authorization": "Basic " + raw}).status_code == 200


def _assert_policy(response):
    directives = _directives(response)
    assert directives["script-src"] == ["'self'", "'unsafe-inline'"]
    assert directives["object-src"] == ["'none'"]
    assert directives["frame-ancestors"] == ["'none'"]


def test_signed_out_pages_carry_the_policy(client):
    login = client.get("/login")
    assert login.status_code == 200
    assert "<form" in login.text
    _assert_policy(login)

    redirect = client.get("/")
    assert redirect.status_code == 302
    _assert_policy(redirect)

    api = client.get("/api/auth/status")
    _assert_policy(api)


@pytest.mark.parametrize("path", ["/", "/dashboard", "/docs"])
def test_signed_in_pages_carry_the_policy(client, path):
    _sign_in(client)
    page = client.get(path)
    assert page.status_code == 200
    assert "<script" in page.text
    _assert_policy(page)


def test_no_response_allows_eval(client):
    _sign_in(client)
    for path in ["/login", "/", "/docs", "/api/auth/status", "/api/info"]:
        policy = client.get(path).headers["content-security-policy"]
        assert "unsafe-eval" not in policy, path
