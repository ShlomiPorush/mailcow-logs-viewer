"""The API reference at /docs, its old address /redoc, and the document it reads.

FastAPI's own /docs and /redoc pages loaded Swagger UI and ReDoc from a CDN,
which the CSP blocks, so both stayed blank. /docs now serves
frontend/api-docs.html with the local Scalar bundle, /redoc sends old
bookmarks there, and all three need a session like every other page.
"""
import base64
import builtins
import re
from pathlib import Path

import pytest
import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app import main as main_module  # noqa: E402
from app import session as session_module  # noqa: E402
from app.config import settings  # noqa: E402
from app.frontend_assets import stamp_asset_versions  # noqa: E402
from app.main import app  # noqa: E402

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
USERNAME = "admin"
PASSWORD = "correct horse battery staple"


@pytest.fixture
def auth_mode(monkeypatch):
    inner = settings._inner

    def set_mode(basic: bool):
        monkeypatch.setattr(inner, "basic_auth_enabled", basic)
        monkeypatch.setattr(inner, "auth_enabled", False)
        monkeypatch.setattr(inner, "oauth2_enabled", False)
        monkeypatch.setattr(inner, "auth_username", USERNAME)
        monkeypatch.setattr(inner, "auth_password", PASSWORD)

    yield set_mode
    session_module._session_store.clear()


@pytest.fixture
def client(monkeypatch):
    # The routes read /app/frontend, which exists only in the image
    def frontend_open(path, *args, **kwargs):
        if str(path).startswith("/app/frontend/"):
            path = FRONTEND / str(path)[len("/app/frontend/"):]
        return builtins.open(path, *args, **kwargs)

    monkeypatch.setattr(main_module, "open", frontend_open, raising=False)
    return TestClient(app, follow_redirects=False, raise_server_exceptions=False)


def _sign_in(client):
    raw = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
    client.post("/api/auth/session", headers={"Authorization": "Basic " + raw})


@pytest.mark.parametrize("path,location", [
    ("/docs", "/login?next=%2Fdocs"),
    ("/redoc", "/login?next=%2Fredoc"),
    ("/openapi.json", "/login?next=%2Fopenapi.json"),
])
def test_signed_out_the_reference_and_its_document_go_to_login(auth_mode, client, path, location):
    auth_mode(basic=True)
    response = client.get(path)
    assert response.status_code == 302
    assert response.headers["location"] == location


def test_a_session_that_is_gone_goes_to_login(auth_mode, client):
    auth_mode(basic=True)
    _sign_in(client)
    session_module._session_store.clear()
    assert client.get("/docs").status_code == 302
    assert client.get("/openapi.json").status_code == 302


@pytest.mark.parametrize("basic", [True, False])
def test_the_reference_is_the_scalar_page(auth_mode, client, basic):
    auth_mode(basic=basic)
    if basic:
        _sign_in(client)
    response = client.get("/docs")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-cache"
    assert "/static/assets/libs/scalar-api-reference.min.js" in response.text
    assert "/static/api-docs.js" in response.text
    # The CSP that blocked the old pages still applies, unchanged
    assert "script-src 'self' 'unsafe-inline' 'unsafe-eval';" in response.headers["content-security-policy"]


@pytest.mark.parametrize("basic", [True, False])
def test_redoc_moved_to_the_reference(auth_mode, client, basic):
    auth_mode(basic=basic)
    if basic:
        _sign_in(client)
    response = client.get("/redoc")
    assert response.status_code == 301
    assert response.headers["location"] == "/docs"


@pytest.mark.parametrize("basic", [True, False])
def test_the_document_is_still_served(auth_mode, client, basic):
    auth_mode(basic=basic)
    if basic:
        _sign_in(client)
    response = client.get("/openapi.json")
    assert response.status_code == 200
    paths = response.json()["paths"]
    assert "/api/health" in paths
    # The pages are not API routes, so the reference does not list them
    assert not {"/", "/login", "/docs", "/redoc", "/{full_path}"} & set(paths)


def test_fastapi_no_longer_serves_its_cdn_pages():
    assert app.docs_url is None and app.redoc_url is None
    assert "/docs/oauth2-redirect" not in {getattr(r, "path", None) for r in app.routes}


def test_every_file_of_the_page_gets_a_content_stamp():
    html = (FRONTEND / "api-docs.html").read_text()
    stamped = stamp_asset_versions(html, str(FRONTEND))
    refs = re.findall(r'/static/[^"]+\.(?:css|js)\?v=([^"]+)"', stamped)
    assert len(refs) == 3
    assert all(re.fullmatch(r"[0-9a-f]{12}", ref) for ref in refs), refs
