"""Exercise credential throttling through real routes and Uvicorn proxy handling."""
import base64

import pytest
from fastapi.testclient import TestClient
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from app import auth, session
from app.config import settings
from app.main import app


def credentials(password="correct-test-password"):
    value = base64.b64encode(f"admin:{password}".encode()).decode()
    return {"Authorization": f"Basic {value}"}


@pytest.fixture(autouse=True)
def basic_auth(monkeypatch):
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", True)
    monkeypatch.setattr(settings._inner, "auth_enabled", False)
    monkeypatch.setattr(settings._inner, "oauth2_enabled", False)
    monkeypatch.setattr(settings._inner, "auth_username", "admin")
    monkeypatch.setattr(settings._inner, "auth_password", "correct-test-password")
    auth._auth_failures.clear()
    session._session_store.clear()
    yield
    auth._auth_failures.clear()
    session._session_store.clear()


def client_at(peer="192.0.2.50", trusted="127.0.0.1"):
    # Set the transport peer BEFORE Uvicorn processes forwarding headers.
    # This exercises the installed server implementation, including proxy chains.
    proxied = ProxyHeadersMiddleware(app, trusted_hosts=trusted)

    async def transport(scope, receive, send):
        scope = dict(scope, client=(peer, 12345))
        await proxied(scope, receive, send)

    return TestClient(transport)


@pytest.mark.parametrize("path", ["/api/info", "/api/auth/verify", "/api/auth/session"])
@pytest.mark.parametrize("header", [credentials("wrong"), {"Authorization": "Basic !!!"}])
def test_every_password_check_consumes_the_same_failure_budget(path, header):
    client = client_at()
    method = "POST" if path.endswith("/session") else "GET"
    for _ in range(auth._AUTH_MAX_FAILURES):
        response = client.request(method, path, headers=header)
        assert response.status_code == (200 if path == "/api/info" else 401)
        if path == "/api/info":
            assert "version" not in response.json()
    # Switching to another endpoint cannot escape the exhausted budget.
    for blocked_path in ["/api/info", "/api/auth/verify"]:
        response = client.get(blocked_path, headers=credentials())
        assert response.status_code == 429
        assert int(response.headers["Retry-After"]) > 0
        assert "version" not in response.text


@pytest.mark.parametrize(
    "peer,trusted,chain",
    [
        ("192.0.2.50", "127.0.0.1", "{spoof}"),  # Direct access.
        ("192.0.2.10", "127.0.0.1", "{spoof}, 192.0.2.50"),  # Untrusted proxy.
        ("192.0.2.10", "192.0.2.10", "{spoof}, 192.0.2.50"),
        ("192.0.2.10", "192.0.2.10,192.0.2.11", "{spoof}, 192.0.2.50, 192.0.2.11"),
        ("192.0.2.10", "192.0.2.10", "{spoof}, 192.0.2.50, 192.0.2.11"),
        ("2001:db8::10", "2001:db8::10", "{spoof}, 2001:db8::50"),
    ],
)
def test_spoofed_forwarding_prefix_cannot_reset_limit(peer, trusted, chain):
    client = client_at(peer, trusted)
    for attempt in range(auth._AUTH_MAX_FAILURES + 1):
        forwarded = chain.format(spoof=f"198.51.100.{attempt + 1}")
        response = client.get("/api/auth/verify", headers={
            **credentials("wrong"), "X-Forwarded-For": forwarded,
        })
        assert response.status_code == (401 if attempt < auth._AUTH_MAX_FAILURES else 429)


def test_trusted_proxy_keeps_clients_independent():
    client = client_at("192.0.2.10", "192.0.2.10")
    for _ in range(auth._AUTH_MAX_FAILURES):
        client.get("/api/auth/verify", headers={
            **credentials("wrong"), "X-Forwarded-For": "192.0.2.50",
        })
    response = client.post("/api/auth/session", headers={
        **credentials(), "X-Forwarded-For": "192.0.2.51",
    })
    assert response.status_code == 200
    assert "session_id=" in response.headers["set-cookie"]


@pytest.mark.parametrize("peer,trusted", [
    ("192.0.2.50", "127.0.0.1"),
    ("192.0.2.10", "192.0.2.10"),
])
def test_no_forwarding_header_needs_no_configuration(peer, trusted):
    client = client_at(peer, trusted)
    response = client.post("/api/auth/session", headers=credentials())
    assert response.status_code == 200
    assert client.get("/api/auth/status").json()["authenticated"] is True


@pytest.mark.parametrize("oauth_only", [False, True])
def test_existing_sessions_and_public_login_info_survive_lockout(monkeypatch, oauth_only):
    client = client_at()
    for _ in range(auth._AUTH_MAX_FAILURES):
        client.get("/api/auth/verify", headers=credentials("wrong"))
    assert client.get("/api/info").status_code == 200
    assert "version" not in client.get("/api/info").json()
    assert client.get("/api/auth/provider-info").status_code == 200
    assert client.get("/login").status_code == 200
    if oauth_only:
        monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
        monkeypatch.setattr(settings._inner, "oauth2_enabled", True)
    cookie = session.create_session({"username": "admin"})
    client.cookies.set(session.SESSION_COOKIE_NAME, cookie)
    assert client.get("/api/auth/status").json()["authenticated"] is True
    assert "version" in client.get("/api/info").json()


def test_auth_disabled_remains_compatible_with_external_auth(monkeypatch):
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    client = client_at()
    for _ in range(auth._AUTH_MAX_FAILURES + 1):
        assert client.get("/api/info", headers=credentials("wrong")).status_code == 200
    assert "version" in client.get("/api/info").json()
    assert not auth._auth_failures


def test_successful_info_auth_resets_failures():
    client = client_at()
    for _ in range(auth._AUTH_MAX_FAILURES - 1):
        client.get("/api/auth/verify", headers=credentials("wrong"))
    assert "version" in client.get("/api/info", headers=credentials()).json()
    for _ in range(auth._AUTH_MAX_FAILURES):
        assert client.get("/api/auth/verify", headers=credentials("wrong")).status_code == 401


def test_lockout_expires(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(auth.time, "time", lambda: now[0])
    client = client_at()
    for _ in range(auth._AUTH_MAX_FAILURES):
        client.get("/api/auth/verify", headers=credentials("wrong"))
    assert client.get("/api/info", headers=credentials()).status_code == 429
    now[0] += auth._AUTH_WINDOW_SECONDS + 1
    assert "version" in client.get("/api/info", headers=credentials()).json()
