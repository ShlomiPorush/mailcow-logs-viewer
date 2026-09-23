"""Authentication capacity limits preserve live sessions and failure budgets."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from threading import Barrier
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app import auth, session
from app.config import Settings, build_settings, settings
from app.routers import auth as auth_router
from test_auth_request_limits import client_at, credentials


@pytest.fixture(autouse=True)
def limited_stores(monkeypatch):
    monkeypatch.setattr(settings, "session_max_entries", 2, raising=False)
    monkeypatch.setattr(settings, "auth_max_failure_clients", 2, raising=False)
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", True)
    monkeypatch.setattr(settings._inner, "auth_enabled", False)
    monkeypatch.setattr(settings._inner, "oauth2_enabled", False)
    monkeypatch.setattr(settings._inner, "auth_username", "admin")
    monkeypatch.setattr(settings._inner, "auth_password", "correct-test-password")
    monkeypatch.setattr(session, "_next_capacity_cleanup", 0.0, raising=False)
    monkeypatch.setattr(auth, "_next_capacity_cleanup", 0.0, raising=False)
    session._session_store.clear()
    auth._auth_failures.clear()
    auth_router._state_store.clear()
    yield
    session._session_store.clear()
    auth._auth_failures.clear()
    auth_router._state_store.clear()


def test_full_sessions_reject_new_login_and_preserve_cookies():
    first = client_at()
    assert first.post("/api/auth/session", headers=credentials()).status_code == 200
    session.create_session({"username": "admin"})
    response = client_at("192.0.2.51").post("/api/auth/session", headers=credentials())
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "60"
    assert "set-cookie" not in response.headers
    assert len(session._session_store) == 2
    assert first.get("/api/auth/status").json()["authenticated"] is True
    assert "version" in first.get("/api/info").json()


@pytest.mark.parametrize("peer,trusted", [
    ("192.0.2.50", "127.0.0.1"), ("192.0.2.10", "192.0.2.10"),
])
def test_failure_capacity_rejects_unknown_clients_before_password_check(monkeypatch, peer, trusted):
    for ip in ["198.51.100.1", "198.51.100.2"]:
        for _ in range(auth._AUTH_MAX_FAILURES):
            auth._record_auth_failure(ip)
    monkeypatch.setattr(auth, "verify_credentials", lambda *args: pytest.fail("Checked password at capacity"))
    client = client_at(peer, trusted)
    for path in ["/api/info", "/api/auth/verify", "/api/auth/session"]:
        method = "POST" if path.endswith("/session") else "GET"
        response = client.request(method, path, headers={**credentials(), "X-Forwarded-For": "192.0.2.51"})
        assert response.status_code == 429
    assert len(auth._auth_failures) == 2
    assert auth._is_rate_limited("198.51.100.1")
    assert client.get("/api/info").status_code == 200
    assert client.get("/api/auth/provider-info").status_code == 200
    cookie = session.create_session({"username": "admin"})
    client.cookies.set(session.SESSION_COOKIE_NAME, cookie)
    assert client.get("/api/auth/status").json()["authenticated"] is True


def test_expired_sessions_are_reclaimed_on_admission():
    active = session.create_session({"username": "admin"})
    expired = session.create_session({"username": "admin"})
    key = session.get_serializer().loads(expired)
    session._session_store[key]["expires_at"] = (datetime.utcnow() - timedelta(seconds=1)).isoformat()
    new = session.create_session({"username": "admin"})
    assert len(session._session_store) == 2
    assert session.get_session(active)
    assert session.get_session(new)
    assert session.delete_session(active)
    assert session.create_session({"username": "admin"})


def test_parallel_session_admission_is_atomic():
    barrier = Barrier(12)

    def create():
        barrier.wait()
        try:
            return session.create_session({"username": "admin"})
        except session.SessionCapacityError:
            return None

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda _: create(), range(12)))
    assert sum(result is not None for result in results) == 2
    assert len(session._session_store) == 2


def test_live_capacity_changes_do_not_evict_sessions_or_counters(monkeypatch):
    cookies = [session.create_session({"username": "admin"}) for _ in range(2)]
    for ip in ["192.0.2.50", "192.0.2.51"]:
        auth._record_auth_failure(ip)
    monkeypatch.setattr(settings, "session_max_entries", 1)
    monkeypatch.setattr(settings, "auth_max_failure_clients", 1)
    assert client_at("192.0.2.52").get("/api/auth/verify", headers=credentials()).status_code == 429
    with pytest.raises(session.SessionCapacityError):
        session.create_session({"username": "admin"})
    assert all(session.get_session(cookie) for cookie in cookies)
    assert len(auth._auth_failures) == 2
    # A tracked client below its lockout threshold may still authenticate.
    assert client_at().get("/api/auth/verify", headers=credentials()).status_code == 200
    monkeypatch.setattr(settings, "session_max_entries", 3)
    monkeypatch.setattr(settings, "auth_max_failure_clients", 3)
    assert session.create_session({"username": "admin"})
    assert client_at("192.0.2.52").get("/api/auth/verify", headers=credentials()).status_code == 200


def test_failure_capacity_recovers_after_expiry(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(auth.time, "time", lambda: now[0])
    monkeypatch.setattr(auth.time, "monotonic", lambda: now[0])
    for ip in ["198.51.100.1", "198.51.100.2"]:
        auth._record_auth_failure(ip)
    client = client_at()
    assert client.get("/api/auth/verify", headers=credentials()).status_code == 429
    now[0] += auth._AUTH_WINDOW_SECONDS + 1
    assert client.get("/api/auth/verify", headers=credentials()).status_code == 200
    assert not auth._auth_failures


def test_parallel_unknown_clients_do_not_overrun_failure_capacity():
    barrier = Barrier(12)

    def attempt(index):
        barrier.wait()
        return client_at(f"192.0.2.{index + 1}").get("/api/auth/verify", headers=credentials("wrong")).status_code

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(attempt, range(12)))
    assert results.count(401) == 2
    assert results.count(429) == 10
    assert len(auth._auth_failures) == 2


def test_saturated_cleanup_scans_are_throttled(monkeypatch):
    for ip in ["198.51.100.1", "198.51.100.2"]:
        auth._record_auth_failure(ip)
    calls = []
    cleanup = auth.cleanup_expired_auth_failures
    monkeypatch.setattr(auth.time, "monotonic", lambda: 1000.0)
    monkeypatch.setattr(auth, "cleanup_expired_auth_failures", lambda: (calls.append(True), cleanup()))
    for index in range(10):
        assert client_at(f"192.0.2.{index + 1}").get("/api/auth/verify", headers=credentials()).status_code == 429
    assert len(calls) == 1


@pytest.mark.parametrize("key", ["session_max_entries", "auth_max_failure_clients"])
@pytest.mark.parametrize("value", [0, -1, 1.5])
def test_settings_reject_invalid_capacity(key, value):
    with pytest.raises(ValidationError):
        Settings(**{key: value})


@pytest.mark.parametrize("key", ["session_max_entries", "auth_max_failure_clients"])
def test_invalid_capacity_is_rejected_by_env_and_settings_api(monkeypatch, key):
    from app.routers.settings import update_settings

    monkeypatch.setenv(key.upper(), "0")
    with pytest.raises(ValidationError):
        Settings()
    monkeypatch.delenv(key.upper())
    monkeypatch.setattr(settings._inner, "edit_settings_via_ui_enabled", True)
    with pytest.raises(HTTPException) as exc:
        update_settings({key: 0}, db=object())
    assert exc.value.status_code == 400
    assert key in exc.value.detail


@pytest.mark.parametrize("key", ["session_max_entries", "auth_max_failure_clients"])
def test_db_reload_rejects_invalid_capacity(monkeypatch, key):
    monkeypatch.setenv("SETTINGS_EDIT_VIA_UI_ENABLED", "true")
    monkeypatch.delenv(key.upper(), raising=False)
    monkeypatch.setattr("app.services.settings_store.get_config_overrides_from_db", lambda *args: {key: -1})
    assert getattr(build_settings(object()), key) == 10000


def test_oauth_capacity_consumes_state_and_returns_specific_error(monkeypatch):
    monkeypatch.setattr(settings._inner, "oauth2_enabled", True)
    monkeypatch.setattr(auth_router.oauth2_client, "exchange_code_for_token", AsyncMock(return_value={"access_token": "test-token"}))
    monkeypatch.setattr(auth_router.oauth2_client, "get_user_info", AsyncMock(return_value={"email": "user@example.com"}))
    for _ in range(2):
        session.create_session({"username": "admin"})
    state, nonce = "test-state", "a" * 43
    auth_router._state_store[state] = (nonce, auth_router.time.monotonic() + 600)
    client = client_at()
    client.cookies.set(auth_router.OAUTH_COOKIE_PREFIX + state, nonce, domain="testserver.local", path="/")
    response = client.get("/api/auth/callback", params={"state": state, "code": "test-code"}, follow_redirects=False)
    assert response.headers["location"] == "/login?error=session_capacity"
    assert state not in auth_router._state_store
    assert session.SESSION_COOKIE_NAME not in client.cookies
    assert auth_router.OAUTH_COOKIE_PREFIX + state not in client.cookies
    assert len(session._session_store) == 2
