"""The OAuth2 login uses PKCE (RFC 7636, S256), bound to the browser that started it.

The code_verifier is derived on the server from the session secret and the
random nonce in the starting browser's cookie, so the login stays stateless
and the verifier never appears in the URL the provider or the browser sees.
An authorization code intercepted on its way back is useless without it.
"""
import base64
import hashlib
from urllib.parse import parse_qs, urlsplit
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi.testclient import TestClient

from app import session
from app.config import settings
from app.main import app
from app.routers import auth
from app.services import oauth2_client as oauth2_module

AUTHORIZE = "https://id.example.com/authorize"
TOKEN = "https://id.example.com/token"
USERINFO = "https://id.example.com/userinfo"


def s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


@pytest.fixture
def provider(monkeypatch):
    """The real OAuth2 client against a fake provider; records every token request."""
    client = auth.oauth2_client
    monkeypatch.setattr(settings._inner, "oauth2_enabled", True)
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    monkeypatch.setattr(client, "initialize", AsyncMock())
    monkeypatch.setattr(client, "issuer_url", None)
    monkeypatch.setattr(client, "client_id", "viewer-test")
    monkeypatch.setattr(client, "client_secret", "viewer-test-secret")
    monkeypatch.setattr(client, "redirect_uri", "https://viewer.example.com/api/auth/callback")
    monkeypatch.setattr(client, "scopes", ["openid", "profile", "email"])
    monkeypatch.setattr(client, "authorization_url", AUTHORIZE)
    monkeypatch.setattr(client, "token_url", TOKEN)
    monkeypatch.setattr(client, "userinfo_url", USERINFO)

    token_requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == TOKEN:
            form = {k: v[0] for k, v in parse_qs(request.content.decode("ascii")).items()}
            token_requests.append(form)
            return httpx.Response(200, json={"access_token": "test-token", "token_type": "Bearer"})
        if str(request.url) == USERINFO:
            return httpx.Response(200, json={"email": "user@example.com"})
        return httpx.Response(404)

    real_async_client = httpx.AsyncClient

    def fake_async_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(oauth2_module.httpx, "AsyncClient", fake_async_client)
    auth._consumed_states.clear()
    session._session_store.clear()
    yield token_requests
    auth._consumed_states.clear()
    session._session_store.clear()


def start(client):
    response = client.get("/api/auth/login", follow_redirects=False)
    assert response.status_code in (302, 307)
    location = response.headers["location"]
    assert location.startswith(AUTHORIZE + "?")
    return {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}


def finish(client, state):
    return client.get("/api/auth/callback", params={"state": state, "code": "test-code"},
                      follow_redirects=False)


def test_authorization_url_carries_an_s256_code_challenge(provider):
    query = start(TestClient(app))
    assert query["code_challenge_method"] == "S256"
    challenge = query["code_challenge"]
    # 32 bytes of SHA-256, base64url without padding
    assert len(challenge) == 43
    assert set(challenge) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def test_each_login_gets_its_own_challenge(provider):
    client = TestClient(app)
    assert start(client)["code_challenge"] != start(client)["code_challenge"]


def test_token_exchange_sends_the_matching_code_verifier(provider):
    client = TestClient(app)
    query = start(client)
    response = finish(client, query["state"])
    assert response.headers["location"] == "/"
    assert len(provider) == 1
    verifier = provider[0]["code_verifier"]
    # RFC 7636 section 4.1: 43 to 128 unreserved characters
    assert 43 <= len(verifier) <= 128
    assert s256(verifier) == query["code_challenge"]


def test_verifier_is_not_visible_to_the_browser_or_the_provider(provider):
    client = TestClient(app)
    query = start(client)
    finish(client, query["state"])
    verifier = provider[0]["code_verifier"]
    assert verifier not in query.values()
    assert all(verifier not in (cookie.value or "") for cookie in client.cookies.jar)


def test_parallel_flows_each_send_their_own_verifier(provider):
    client = TestClient(app)
    first, second = start(client), start(client)
    assert finish(client, second["state"]).headers["location"] == "/"
    assert finish(client, first["state"]).headers["location"] == "/"
    assert [s256(r["code_verifier"]) for r in provider] == [second["code_challenge"], first["code_challenge"]]


def test_callback_with_the_cookie_of_another_flow_is_rejected(provider):
    client = TestClient(app)
    first, second = start(client), start(client)
    first_cookie = client.cookies.get(auth.OAUTH_COOKIE_PREFIX + first["state"])
    client.cookies.delete(auth.OAUTH_COOKIE_PREFIX + second["state"])
    client.cookies.set(auth.OAUTH_COOKIE_PREFIX + second["state"], first_cookie)
    assert finish(client, second["state"]).headers["location"] == "/login?error=invalid_state"
    assert provider == []
