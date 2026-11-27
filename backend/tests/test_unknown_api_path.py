import base64
import secrets

import pytest
from fastapi.testclient import TestClient

from app import main
from app import session as session_module

PAGE = "<html><body>Test page</body></html>"
USERNAME = "admin"
PASSWORD = secrets.token_hex(16)


class _Page:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self):
        return PAGE


@pytest.fixture
def client(monkeypatch):
    inner = main.settings._inner
    monkeypatch.setattr(inner, "auth_enabled", False)
    monkeypatch.setattr(inner, "basic_auth_enabled", False)
    monkeypatch.setattr(inner, "oauth2_enabled", False)
    monkeypatch.setattr(main, "check_db_connection", lambda: True)
    monkeypatch.setattr(main, "open", lambda name, mode="r": _Page(), raising=False)
    return TestClient(main.app, follow_redirects=False, raise_server_exceptions=False)


@pytest.mark.parametrize("path", [
    "/api",
    "/api/",
    "/api/does-not-exist",
    "/api/auth/logoutx",
    "/api/dmarc/nothing/here",
    "/ws/raw-logs",
    "/ws/unknown",
])
def test_unknown_api_get_is_json_404(client, path):
    response = client.get(path)
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {"detail": "Not Found"}


@pytest.mark.parametrize("method", ["HEAD", "POST", "PUT", "PATCH", "DELETE"])
def test_unknown_api_path_is_404_for_every_method(client, method):
    response = client.request(method, "/api/does-not-exist")
    assert response.status_code == 404
    if method != "HEAD":
        assert response.json() == {"detail": "Not Found"}


@pytest.mark.parametrize("path", [
    "/dashboard",
    "/messages",
    "/settings/general",
    "/dmarc/example.com",
    "/dmarc/tls/example.com/2026-01-01",
    "/apiary",
    "/wsx",
])
def test_page_routes_still_serve_the_spa(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.text == PAGE
    assert client.head(path).status_code == 405


def test_health_and_root_unchanged(client):
    assert client.get("/api/health").status_code == 200
    assert client.head("/api/health").status_code == 405
    assert client.get("/").text == PAGE


def test_known_api_path_with_wrong_method_stays_405(client):
    response = client.post("/api/health")
    assert response.status_code == 405
    assert response.json() == {"detail": "Method Not Allowed"}


def test_unknown_api_path_without_session_is_401_when_auth_is_on(client, monkeypatch):
    inner = main.settings._inner
    monkeypatch.setattr(inner, "basic_auth_enabled", True)
    monkeypatch.setattr(inner, "auth_username", USERNAME)
    monkeypatch.setattr(inner, "auth_password", PASSWORD)
    try:
        assert client.get("/api/does-not-exist").status_code == 401
        assert client.get("/api/settings").status_code == 401

        raw = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
        signed_in = client.get("/api/does-not-exist", headers={"Authorization": f"Basic {raw}"})
        assert signed_in.status_code == 404
        assert signed_in.json() == {"detail": "Not Found"}
    finally:
        session_module._session_store.clear()
