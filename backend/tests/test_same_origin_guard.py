"""State-changing requests and the live log WebSocket must come from the app's own pages.

Authentication is off by default, so the only thing that kept a web page on
another site from driving the API through the operator's browser (a text/plain
form POST to a mailcow write route, or a WebSocket to the live log stream) was
nothing. The API also answered every origin with a credentialed CORS policy.

The guard compares host[:port] only: behind the documented TLS reverse proxy
the app sees plain HTTP while the browser sends an https Origin.
"""
import base64

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app import auth, session
from app.config import Settings, settings
from app.main import app

APP = "http://logs.example.test"
# POST /api/auth/session answers 400 with Basic Auth off: reaching the route
# (400) and being stopped in front of it (403) are easy to tell apart.
WRITE = "/api/auth/session"


@pytest.fixture(autouse=True)
def no_auth(monkeypatch):
    monkeypatch.setattr(settings._inner, "auth_enabled", False)
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    monkeypatch.setattr(settings._inner, "oauth2_enabled", False)
    monkeypatch.setattr(settings._inner, "raw_logs_services", "postfix")
    yield
    session._session_store.clear()
    auth._auth_failures.clear()


def client(base_url=APP, **headers):
    return TestClient(app, base_url=base_url, headers=headers)


@pytest.mark.parametrize("headers", [
    {"Origin": "https://evil.invalid"},
    {"Origin": "http://logs.example.test.evil.invalid"},
    {"Origin": "http://logs.example.test:8081"},
    {"Origin": "null"},
    {"Referer": "https://evil.invalid/page"},
])
def test_cross_site_write_is_rejected(headers):
    response = client().post(WRITE, headers=headers)
    assert response.status_code == 403


def test_cross_site_text_plain_form_cannot_reach_a_mailcow_write(monkeypatch):
    from app.routers import logs
    from unittest.mock import AsyncMock
    unban = AsyncMock(return_value={"type": "success"})
    monkeypatch.setattr(logs.mailcow_api, "unban_fail2ban", unban, raising=False)
    response = client().post(
        "/api/fail2ban/unban", content='{"ip":"192.0.2.12","x":"="}',
        headers={"Origin": "https://evil.invalid", "Content-Type": "text/plain"},
    )
    assert response.status_code == 403
    unban.assert_not_awaited()


@pytest.mark.parametrize("headers", [
    {"Origin": APP},
    {"Origin": "HTTP://Logs.Example.Test"},
    {"Referer": APP + "/settings"},
    {},  # curl and other API clients send neither header
])
def test_same_origin_and_headerless_writes_pass(headers):
    assert client().post(WRITE, headers=headers).status_code == 400


@pytest.mark.parametrize("method", ["put", "patch", "delete"])
def test_every_unsafe_method_is_checked(method):
    response = client().request(method.upper(), "/api/settings", headers={"Origin": "https://evil.invalid"})
    assert response.status_code == 403


def test_reads_are_not_affected():
    assert client().get("/api/info", headers={"Origin": "https://evil.invalid"}).status_code == 200


def test_https_origin_behind_tls_proxy_passes():
    """The proxy terminates TLS: the app sees http, the browser sends https."""
    response = client(**{"X-Forwarded-Proto": "https"}).post(WRITE, headers={"Origin": "https://logs.example.test"})
    assert response.status_code == 400


@pytest.mark.parametrize("base_url,origin", [
    ("http://logs.example.test:8080", "http://logs.example.test:8080"),
    ("http://logs.example.test:443", "https://logs.example.test"),
    ("http://192.0.2.10:8080", "http://192.0.2.10:8080"),
])
def test_ports_and_address_literals(base_url, origin):
    assert client(base_url).post(WRITE, headers={"Origin": origin}).status_code == 400


def test_ipv6_address_literal():
    # The test client cannot take an IPv6 base URL; send the Host header a browser would
    response = client().post(WRITE, headers={"Host": "[2001:db8::10]:8080", "Origin": "http://[2001:db8::10]:8080"})
    assert response.status_code == 400
    response = client().post(WRITE, headers={"Host": "[2001:db8::10]:8080", "Origin": "http://[2001:db8::11]:8080"})
    assert response.status_code == 403


def test_proxy_that_rewrites_host_but_sends_forwarded_host():
    proxied = client("http://mailcow-logs-app:8080", **{"X-Forwarded-Host": "logs.example.test"})
    assert proxied.post(WRITE, headers={"Origin": "https://logs.example.test"}).status_code == 400
    assert proxied.post(WRITE, headers={"Origin": "https://evil.invalid"}).status_code == 403


def test_guard_applies_with_authentication_on(monkeypatch):
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", True)
    monkeypatch.setattr(settings._inner, "auth_username", "admin")
    monkeypatch.setattr(settings._inner, "auth_password", "test-password")
    signed_in = client()
    header = {"Authorization": "Basic " + base64.b64encode(b"admin:test-password").decode()}
    assert signed_in.post(WRITE, headers={**header, "Origin": APP}).status_code == 200
    # Valid credentials and a valid session cookie do not make a cross-site write acceptable
    assert signed_in.post(WRITE, headers={**header, "Origin": "https://evil.invalid"}).status_code == 403
    assert signed_in.post(WRITE, headers={"Origin": "https://evil.invalid"}).status_code == 403


def test_websocket_from_another_site_is_rejected():
    with pytest.raises(WebSocketDisconnect):
        with client().websocket_connect("/ws/raw-logs", headers={"Origin": "https://evil.invalid"}) as ws:
            ws.receive_json()


# The test client always opens WebSockets to ws://testserver
@pytest.mark.parametrize("headers", [{"Origin": "https://testserver"}, {"Origin": "http://testserver"}, {}])
def test_websocket_from_the_app_connects(headers):
    with client().websocket_connect("/ws/raw-logs", headers=headers) as ws:
        assert ws.receive_json()["type"] == "connected"


# CORS: the SPA is same-origin, so no cross-origin policy by default

def test_no_cors_headers_by_default():
    response = client().get("/api/info", headers={"Origin": "http://web.example.test"})
    assert "access-control-allow-origin" not in response.headers
    preflight = client().options("/api/fail2ban/unban", headers={
        "Origin": "http://web.example.test",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
    })
    assert "access-control-allow-origin" not in preflight.headers
    assert "access-control-allow-credentials" not in preflight.headers


def test_cors_allowed_origins_are_exact_and_never_wildcard(monkeypatch):
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", " https://Dash.Example.test/ , *, not-a-url, http://web.example.test:8081 ")
    assert Settings().cors_allowed_origins_list == ["https://dash.example.test", "http://web.example.test:8081"]
    monkeypatch.delenv("CORS_ALLOWED_ORIGINS")
    assert Settings().cors_allowed_origins_list == []


def test_configured_cors_origin_is_allowed_and_others_are_not(monkeypatch):
    from app.main import configure_cors
    monkeypatch.setattr(settings._inner, "cors_allowed_origins", "https://dash.example.test")
    probe = FastAPI()
    probe.get("/api/ping")(lambda: {"ok": True})
    configure_cors(probe)
    allowed = TestClient(probe).get("/api/ping", headers={"Origin": "https://dash.example.test"})
    assert allowed.headers["access-control-allow-origin"] == "https://dash.example.test"
    other = TestClient(probe).get("/api/ping", headers={"Origin": "https://evil.invalid"})
    assert "access-control-allow-origin" not in other.headers


def test_configured_cors_origin_passes_the_write_guard(monkeypatch):
    monkeypatch.setattr(settings._inner, "cors_allowed_origins", "https://dash.example.test")
    assert client().post(WRITE, headers={"Origin": "https://dash.example.test"}).status_code == 400
    assert client().post(WRITE, headers={"Origin": "https://evil.invalid"}).status_code == 403
