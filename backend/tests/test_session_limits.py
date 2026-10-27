"""The two limits of a browser session: the longest session, counted from
sign-in, and sign-out after inactivity, counted from the last interaction the
page reported. Both apply to Basic Auth and OAuth2 sessions alike; the server
record alone decides, and a session that ended stays ended.

The real settings save and reload run here (test_session_revocation.py's
store fixture); the clock is session._now.
"""
import threading
from collections import OrderedDict

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import app.config as cfg
from app import session
from app.agent_access import scopes
from app.config import Settings, build_settings, settings
from app.main import app
from app.routers import auth as auth_router
from app.routers import settings as settings_router
from app.services import settings_store
from test_session_revocation import basic, signed_in, store  # noqa: F401 (store: autouse fixture)

HOUR = 3600.0
MINUTE = 60.0


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    now = {"t": 1_000_000.0}
    monkeypatch.setattr(session, "_now", lambda: now["t"])
    monkeypatch.setattr(session, "_tombstones", OrderedDict())
    return now


def _key(client):
    return session.get_serializer().loads(client.cookies.get(session.SESSION_COOKIE_NAME))


def _idle(minutes=60):
    return {"session_idle_enabled": True, "session_idle_timeout_minutes": minutes}


def _save(client, values):
    response = client.put("/api/settings", json=values)
    assert response.status_code == 200, response.text
    return response


def _max_age(response) -> int:
    cookie = response.headers["set-cookie"]
    return int(cookie.split("Max-Age=", 1)[1].split(";", 1)[0])


def _ended(response, reason):
    assert response.status_code == 401
    assert response.json() == {"detail": "Your session ended. Sign in again.", "reason": reason}
    assert response.headers["X-Session-End"] == reason


def _signed_out_plainly(response):
    assert response.status_code == 401
    assert "x-session-end" not in response.headers


# ── The longest session ────────────────────────────────────────────────────

def test_the_longest_session_ends_at_its_length_whatever_the_activity(clock):
    client = signed_in()
    clock["t"] += 24 * HOUR - 1
    assert client.post("/api/auth/activity").status_code == 200
    assert client.get("/api/auth/verify").status_code == 200
    clock["t"] += 1
    _ended(client.get("/api/auth/verify"), "session_expired")
    assert not session._session_store


def test_the_sign_in_sets_the_cookie_for_the_session_length():
    response = TestClient(app).post("/api/auth/session", headers=basic())
    assert _max_age(response) == 24 * 3600


def test_a_shorter_setting_applies_to_open_sessions(clock):
    other, operator = signed_in(), signed_in()
    _save(operator, {"session_expiry_hours": 2})
    clock["t"] += 2 * HOUR - 1
    assert other.get("/api/auth/verify").status_code == 200
    clock["t"] += 1
    _ended(other.get("/api/auth/verify"), "session_expired")


def test_a_longer_setting_never_goes_past_the_length_a_session_was_issued_with(clock):
    operator = signed_in()
    _save(operator, {"session_expiry_hours": 2})
    other = signed_in()
    _save(operator, {"session_expiry_hours": 48})
    clock["t"] += 2 * HOUR
    _ended(other.get("/api/auth/verify"), "session_expired")
    assert TestClient(app).post("/api/auth/session", headers=basic()).status_code == 200


def test_a_session_ended_under_a_shorter_setting_stays_ended_when_it_is_lengthened(clock, store):
    other, operator = signed_in(), signed_in()
    _save(operator, {"session_expiry_hours": 2})
    clock["t"] += 3 * HOUR
    # No request came from either session meanwhile; the next settings reload
    # must not bring them back with the longer setting
    store.update({"session_expiry_hours": 24})
    cfg.reload_settings(object())
    _ended(other.get("/api/auth/verify"), "session_expired")


def test_an_existing_long_session_setting_is_kept():
    """No upper bound: an install with a long session keeps starting and keeps it."""
    assert Settings(session_expiry_hours=1000).session_expiry_hours == 1000


# ── Sign-out after inactivity ──────────────────────────────────────────────

def test_inactivity_ends_the_session_at_its_timeout(clock, monkeypatch):
    monkeypatch.setattr(settings._inner, "session_idle_enabled", True)
    monkeypatch.setattr(settings._inner, "session_idle_timeout_minutes", 30)
    client = signed_in()
    clock["t"] += 30 * MINUTE - 1
    assert client.get("/api/auth/verify").status_code == 200
    clock["t"] += 1
    _ended(client.get("/api/auth/verify"), "session_idle")


def test_activity_restarts_the_idle_time_and_status_and_polling_do_not(clock, monkeypatch):
    monkeypatch.setattr(settings._inner, "session_idle_enabled", True)
    monkeypatch.setattr(settings._inner, "session_idle_timeout_minutes", 60)
    client = signed_in()
    clock["t"] += 50 * MINUTE
    activity = client.post("/api/auth/activity")
    assert activity.status_code == 200
    assert activity.json() == {"session": {"longest_seconds_left": int(24 * HOUR - 50 * MINUTE), "idle_enabled": True,
                                           "idle_timeout_seconds": 3600, "idle_seconds_left": 3600}}
    clock["t"] += 30 * MINUTE
    status = client.get("/api/auth/status").json()["session"]
    assert status["idle_seconds_left"] == int(30 * MINUTE)
    assert client.get("/api/auth/verify").status_code == 200
    clock["t"] += 30 * MINUTE
    _ended(client.get("/api/auth/status"), "session_idle")


def test_inactivity_is_off_by_default(clock):
    client = signed_in()
    clock["t"] += 23 * HOUR
    status = client.get("/api/auth/status").json()
    assert status["session"] == {"longest_seconds_left": int(HOUR), "idle_enabled": False,
                                 "idle_timeout_seconds": None, "idle_seconds_left": None}


def test_turning_inactivity_on_starts_the_idle_time_of_open_sessions_now(clock):
    other, operator = signed_in(), signed_in()
    clock["t"] += 2 * HOUR
    _save(operator, _idle(60))
    clock["t"] += 59 * MINUTE
    assert other.get("/api/auth/verify").status_code == 200
    clock["t"] += MINUTE
    _ended(other.get("/api/auth/verify"), "session_idle")


def test_turning_inactivity_on_waits_for_the_reset_before_any_check(clock, monkeypatch):
    """A check running while the new settings are put in force must see them
    together with the reset, never the new policy against the old idle time."""
    client = signed_in()
    key = _key(client)
    clock["t"] += 2 * HOUR
    monkeypatch.setattr(cfg._settings_wrapper, "_inner", cfg._settings_wrapper._inner)
    new = settings._inner.model_copy(update=_idle(60))
    started, result = threading.Event(), {}

    def check():
        started.set()
        result["active"] = session.is_session_active(key)

    def assign_then_check_elsewhere():
        cfg._settings_wrapper._inner = new
        thread = threading.Thread(target=check, daemon=True)
        thread.start()
        assert started.wait(timeout=5)
        thread.join(timeout=0.3)
        result["blocked"] = thread.is_alive()
        result["thread"] = thread

    session._publish_settings(new, assign_then_check_elsewhere)
    result["thread"].join(timeout=5)
    assert result["blocked"] is True
    assert result["active"] is True
    assert session._session_store[key]["active_at"] == clock["t"]


def test_the_session_limits_do_not_end_sessions_when_changed(clock):
    other, operator = signed_in(), signed_in()
    generation = session.auth_generation()
    response = _save(operator, {**_idle(30), "session_expiry_hours": 12})
    assert "set-cookie" not in response.headers
    assert session.auth_generation() == generation
    assert other.get("/api/auth/verify").status_code == 200
    for key in ("session_idle_enabled", "session_idle_timeout_minutes", "session_expiry_hours"):
        assert key not in settings_router._SESSION_BOUND_SETTING_KEYS


# ── Why a session ended ────────────────────────────────────────────────────

def test_a_page_request_goes_to_the_login_page_with_the_reason(clock, monkeypatch):
    monkeypatch.setattr(settings._inner, "session_idle_enabled", True)
    client = signed_in()
    clock["t"] += HOUR
    page = client.get("/messages?filter=x", follow_redirects=False)
    assert page.status_code == 302
    assert page.headers["location"] == "/login?reason=session_idle&next=%2Fmessages%3Ffilter%3Dx"
    # Every open tab hears the same reason for a while
    _ended(client.get("/api/auth/status"), "session_idle")


def test_the_reason_is_forgotten_after_ten_minutes(clock):
    client = signed_in()
    clock["t"] += 24 * HOUR
    _ended(client.get("/api/auth/status"), "session_expired")
    clock["t"] += 10 * MINUTE
    _signed_out_plainly(client.get("/api/auth/status"))
    assert client.get("/messages", follow_redirects=False).headers["location"] == "/login?next=%2Fmessages"


def test_reasons_are_kept_for_at_most_session_max_entries(clock, monkeypatch):
    # On the wrapper: an earlier test may have left a value there that hides the inner one
    monkeypatch.setattr(settings, "session_max_entries", 2, raising=False)
    first, second = signed_in(), signed_in()
    clock["t"] += 24 * HOUR
    _ended(first.get("/api/auth/status"), "session_expired")
    _ended(second.get("/api/auth/status"), "session_expired")
    clock["t"] -= 24 * HOUR
    third = signed_in()
    clock["t"] += 24 * HOUR
    _ended(third.get("/api/auth/status"), "session_expired")
    # The oldest reason made room: a plain sign-in answer, nothing revived
    _signed_out_plainly(first.get("/api/auth/status"))
    assert len(session._tombstones) == 2
    assert not session._session_store


def test_signing_out_and_revocation_leave_no_reason(clock):
    one, two = signed_in(), signed_in()
    assert one.post("/api/auth/logout", follow_redirects=False).status_code == 302
    session.revoke_all_sessions()
    assert not session._tombstones
    _signed_out_plainly(two.get("/api/auth/status"))


def test_basic_credentials_still_work_beside_an_ended_session_cookie(clock):
    client = signed_in()
    clock["t"] += 24 * HOUR
    assert client.get("/api/auth/verify", headers=basic()).status_code == 200
    # And the login form gets a new session with new clocks
    response = client.post("/api/auth/session", headers=basic())
    assert response.status_code == 200
    record = session._session_store[_key(client)]
    assert record["login_at"] == record["active_at"] == clock["t"]
    assert record["issued_hours"] == 24


def test_a_signed_cookie_without_a_live_record_is_refused():
    client = TestClient(app)
    client.cookies.set(session.SESSION_COOKIE_NAME, session.get_serializer().dumps("no-such-session"))
    _signed_out_plainly(client.get("/api/auth/status"))
    assert client.post("/api/auth/activity").status_code == 401


# ── The activity and status calls ──────────────────────────────────────────

def test_activity_never_brings_an_ended_session_back(clock, monkeypatch):
    monkeypatch.setattr(settings._inner, "session_idle_enabled", True)
    client = signed_in()
    clock["t"] += HOUR
    _ended(client.post("/api/auth/activity"), "session_idle")
    _ended(client.post("/api/auth/activity"), "session_idle")
    assert not session._session_store


def test_activity_needs_a_session_cookie():
    response = TestClient(app).post("/api/auth/activity", headers=basic())
    assert response.status_code == 401
    assert response.json() == {"detail": "No session to keep active"}


def test_status_reports_no_limits_without_a_session_cookie(monkeypatch):
    assert TestClient(app).get("/api/auth/status", headers=basic()).json()["session"] is None
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    assert TestClient(app).get("/api/auth/status").json()["session"] is None


def test_an_agent_token_never_counts_as_activity(clock, monkeypatch):
    """A bearer token is an agent's call, decided before the cookie: the
    activity route is for people only and never runs for it."""
    assert scopes.excluded_reason("POST", "/api/auth/activity")
    monkeypatch.setattr(settings._inner, "session_idle_enabled", True)
    client = signed_in()
    key = _key(client)
    calls = []
    monkeypatch.setattr(auth_router, "record_activity", lambda request: calls.append(request) or (None, None))
    clock["t"] += 10 * MINUTE
    response = client.post("/api/auth/activity", headers={"Authorization": "Bearer mlv_at_not-a-real-token"})
    assert response.status_code in (401, 403, 404)
    assert calls == []
    assert session._session_store[key]["active_at"] == clock["t"] - 10 * MINUTE


# ── Re-issuing the operator's session ──────────────────────────────────────

def test_re_issuing_keeps_the_clocks_and_the_cookie_follows_the_issued_length(clock):
    operator = signed_in()
    login_at = clock["t"]
    _save(operator, {"session_expiry_hours": 2})
    clock["t"] += HOUR
    rotated = _save(operator, {"auth_password": "new-test-password"})
    assert _max_age(rotated) == int(23 * HOUR)
    record = session._session_store[_key(operator)]
    assert (record["login_at"], record["issued_hours"]) == (login_at, 24)
    # Two hours apply while the setting says so ...
    assert operator.get("/api/auth/status").json()["session"]["longest_seconds_left"] == int(HOUR)
    # ... and back at 24 the server agrees with the cookie
    _save(operator, {"session_expiry_hours": 24})
    assert operator.get("/api/auth/status").json()["session"]["longest_seconds_left"] == int(23 * HOUR)


def test_re_issuing_keeps_the_last_activity(clock):
    operator = signed_in()
    _save(operator, _idle(60))
    clock["t"] += 50 * MINUTE
    _save(operator, {"auth_password": "new-test-password"})
    assert operator.get("/api/auth/status").json()["session"]["idle_seconds_left"] == int(10 * MINUTE)


# ── Stored and saved values ────────────────────────────────────────────────

@pytest.mark.parametrize("stored, expected", [
    ({"session_idle_enabled": "false"}, ("session_idle_enabled", False)),
    ({"session_idle_enabled": "true"}, ("session_idle_enabled", True)),
    ({"session_idle_enabled": "maybe"}, ("session_idle_enabled", False)),
    ({"session_idle_timeout_minutes": "30"}, ("session_idle_timeout_minutes", 30)),
    ({"session_idle_timeout_minutes": 4}, ("session_idle_timeout_minutes", 60)),
    ({"session_idle_timeout_minutes": 1441}, ("session_idle_timeout_minutes", 60)),
    ({"session_idle_timeout_minutes": "soon"}, ("session_idle_timeout_minutes", 60)),
    ({"session_expiry_hours": 1000}, ("session_expiry_hours", 1000)),
    ({"session_expiry_hours": 0}, ("session_expiry_hours", 24)),
    ({"session_expiry_hours": True}, ("session_expiry_hours", 24)),
])
def test_stored_session_limits_are_checked_on_load(monkeypatch, stored, expected):
    monkeypatch.setattr(settings_store, "get_config_overrides_from_db", lambda *args: stored)
    key, value = expected
    assert getattr(build_settings(object()), key) == value


@pytest.mark.parametrize("values", [
    {"session_idle_timeout_minutes": 4}, {"session_idle_timeout_minutes": 1441},
    {"session_expiry_hours": 0}, {"session_idle_enabled": "maybe"},
])
def test_invalid_session_limits_are_refused_on_save(values):
    with pytest.raises(HTTPException) as refused:
        settings_router.update_settings(values, db=object())
    assert refused.value.status_code == 400
    assert next(iter(values)) in refused.value.detail


def test_a_long_session_saves(store):
    _save(signed_in(), {"session_expiry_hours": 1000})
    assert settings.session_expiry_hours == 1000 and store["session_expiry_hours"] == 1000


def test_the_new_settings_change_nothing_by_default(monkeypatch):
    for key in ("SESSION_IDLE_ENABLED", "SESSION_IDLE_TIMEOUT_MINUTES", "SESSION_EXPIRY_HOURS"):
        monkeypatch.delenv(key, raising=False)
    fresh = Settings()
    assert (fresh.session_idle_enabled, fresh.session_idle_timeout_minutes, fresh.session_expiry_hours) == (False, 60, 24)
