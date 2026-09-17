"""OAuth callbacks must belong to the browser that initiated authorization."""
from urllib.parse import parse_qs, urlencode, urlsplit
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.routers import auth
from app import session


@pytest.fixture(autouse=True)
def oauth(monkeypatch):
    monkeypatch.setattr(settings._inner, "oauth2_enabled", True)
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    monkeypatch.setattr(auth.oauth2_client, "is_configured", lambda: True)
    monkeypatch.setattr(auth.oauth2_client, "initialize", AsyncMock())
    monkeypatch.setattr(auth.oauth2_client, "get_authorization_url",
                        lambda state: "https://id.example.com/authorize?" + urlencode({"state": state}))
    monkeypatch.setattr(auth.oauth2_client, "exchange_code_for_token",
                        AsyncMock(return_value={"access_token": "test-token"}))
    monkeypatch.setattr(auth.oauth2_client, "get_user_info",
                        AsyncMock(return_value={"email": "user@example.com"}))
    auth._state_store.clear()
    session._session_store.clear()
    yield
    auth._state_store.clear()
    session._session_store.clear()


def start(client):
    response = client.get("/api/auth/login", follow_redirects=False)
    assert response.status_code in (302, 307)
    return parse_qs(urlsplit(response.headers["location"]).query)["state"][0]


def finish(client, state, **params):
    return client.get("/api/auth/callback", params={"state": state, "code": "test-code", **params},
                      follow_redirects=False)


def test_callback_from_another_browser_is_rejected_without_consuming_flow():
    owner = TestClient(app)
    other = TestClient(app)
    state = start(owner)
    response = finish(other, state)
    assert response.headers["location"] == "/login?error=invalid_state"
    assert session.SESSION_COOKIE_NAME not in other.cookies
    auth.oauth2_client.exchange_code_for_token.assert_not_awaited()
    assert finish(owner, state).headers["location"] == "/"
    assert owner.get("/api/auth/status").json()["authenticated"] is True


def test_state_alone_cannot_be_used_as_the_browser_secret():
    owner = TestClient(app)
    state = start(owner)
    other = TestClient(app)
    other.cookies.set("oauth_state_" + state, state)
    assert finish(other, state).headers["location"] == "/login?error=invalid_state"
    auth.oauth2_client.exchange_code_for_token.assert_not_awaited()

@pytest.mark.parametrize("base_url,headers,secure", [
    ("http://viewer.example.com", {}, False),
    ("https://viewer.example.com", {}, True),
    ("https://viewer.example.com", {"X-Forwarded-Proto": "https"}, True),
    ("http://viewer.example.com", {"X-Forwarded-Proto": "http"}, False),
])
def test_cookie_attributes_and_successful_cleanup(base_url, headers, secure):
    client = TestClient(app, base_url=base_url, headers=headers)
    state = start(client)
    cookie = next(c for c in client.cookies.jar if c.name == auth.OAUTH_COOKIE_PREFIX + state)
    assert cookie.secure is secure
    assert not cookie.domain_specified
    assert cookie.path == "/"
    assert cookie.has_nonstandard_attr("HttpOnly")
    assert cookie.get_nonstandard_attr("SameSite") == "lax"
    response = finish(client, state)
    assert response.headers["location"] == "/"
    assert cookie.name not in client.cookies
    assert state not in auth._state_store
    assert session.SESSION_COOKIE_NAME in client.cookies
    assert finish(client, state).headers["location"] == "/login?error=invalid_state"
    assert auth.oauth2_client.exchange_code_for_token.await_count == 1


def test_parallel_flows_in_one_browser_remain_independent():
    client = TestClient(app)
    first, second = start(client), start(client)
    assert finish(client, first).headers["location"] == "/"
    assert auth.OAUTH_COOKIE_PREFIX + second in client.cookies
    assert finish(client, second).headers["location"] == "/"


def test_expired_state_is_rejected_and_pending_records_are_pruned(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(auth.time, "monotonic", lambda: now[0])
    client = TestClient(app)
    expired = start(client)
    now[0] += auth.OAUTH_STATE_TTL
    assert finish(client, expired).headers["location"] == "/login?error=invalid_state"
    auth.oauth2_client.exchange_code_for_token.assert_not_awaited()
    assert not auth._state_store
    abandoned = start(client)
    now[0] += auth.OAUTH_STATE_TTL
    active = start(client)
    assert abandoned not in auth._state_store
    assert list(auth._state_store) == [active]


def test_capacity_rejects_new_logins_without_evicting_active_flow(monkeypatch):
    monkeypatch.setattr(auth, "MAX_PENDING_OAUTH_STATES", 1)
    client = TestClient(app)
    state = start(client)
    response = client.get("/api/auth/login", follow_redirects=False)
    assert response.status_code == 503
    assert len(auth._state_store) == 1
    assert finish(client, state).headers["location"] == "/"
    start(client)


@pytest.mark.parametrize("params,expected", [
    ({"error": "access_denied"}, "oauth2_error"),
    ({"code": ""}, "missing_code"),
])
def test_provider_error_and_missing_code_consume_only_bound_flow(params, expected):
    client = TestClient(app)
    state = start(client)
    assert finish(TestClient(app), state, **params).headers["location"] == "/login?error=invalid_state"
    assert finish(client, state, **params).headers["location"] == "/login?error=" + expected
    assert state not in auth._state_store
    assert auth.OAUTH_COOKIE_PREFIX + state not in client.cookies
    auth.oauth2_client.exchange_code_for_token.assert_not_awaited()


@pytest.mark.parametrize("failure", ["no_token", "oauth2_error", "server_error"])
def test_failed_exchange_cleans_cookie_and_cannot_be_replayed(monkeypatch, failure):
    client = TestClient(app)
    state = start(client)
    exchange = auth.oauth2_client.exchange_code_for_token
    if failure == "no_token":
        exchange.return_value = {}
    else:
        exchange.side_effect = auth.OAuth2ClientError("test") if failure == "oauth2_error" else RuntimeError("test")
    assert finish(client, state).headers["location"] == "/login?error=" + failure
    assert state not in auth._state_store
    assert auth.OAUTH_COOKIE_PREFIX + state not in client.cookies
    assert finish(client, state).headers["location"] == "/login?error=invalid_state"
    assert exchange.await_count == 1


def test_start_failure_does_not_leave_pending_state(monkeypatch):
    def fail(state):
        raise auth.OAuth2ClientError("test")
    monkeypatch.setattr(auth.oauth2_client, "get_authorization_url", fail)
    assert TestClient(app).get("/api/auth/login").status_code == 500
    assert not auth._state_store

@pytest.mark.parametrize("forwarded", ["https", "https, http"])
def test_https_browser_behind_tls_terminating_proxy(forwarded):
    async def http_backend(scope, receive, send):
        # The browser uses HTTPS, while the proxy talks HTTP to the application.
        scope = dict(scope, scheme="http")
        await app(scope, receive, send)

    client = TestClient(http_backend, base_url="https://viewer.example.com",
                        headers={"X-Forwarded-Proto": forwarded})
    state = start(client)
    cookie = next(c for c in client.cookies.jar if c.name == auth.OAUTH_COOKIE_PREFIX + state)
    assert cookie.secure
    assert finish(client, state).headers["location"] == "/"
    assert cookie.name not in client.cookies
