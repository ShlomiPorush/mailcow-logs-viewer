"""Several people with their own access (issue #544).

Local users sign in on the login form; OAuth2 entries give an email its own
access instead of the OAuth2 default. Every request is checked against the
person's access as the database says now, so a change applies to the next
request. Without any user and without a stored default, everyone who signs
in is an admin, as before.
"""
import asyncio
import base64
import logging
import threading
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, "check_dir": False})

from fastapi.testclient import TestClient  # noqa: E402
from starlette.websockets import WebSocketDisconnect  # noqa: E402

from app import auth as auth_module  # noqa: E402
from app import session as session_module  # noqa: E402
from app import user_access  # noqa: E402
from app.agent_access.scopes import all_scopes  # noqa: E402
from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402
from app.routers import auth as auth_router  # noqa: E402
from app.routers import raw_logs  # noqa: E402
from app.routers import reporting  # noqa: E402
from app.services import oauth2_client as oauth2_module  # noqa: E402
from app.services import users_store  # noqa: E402

ADMIN_NAME = "admin"
ADMIN_PASSWORD = "correct horse battery staple"
PASSWORD = "a long enough password"
APP = "http://testserver"


def _basic(username, password):
    return {"Authorization": "Basic " + base64.b64encode(f"{username}:{password}".encode("utf-8")).decode()}


def _wipe():
    from app.database import get_db_context
    from app.models import SystemSetting, User
    with get_db_context() as db:
        db.query(User).delete(synchronize_session=False)
        db.query(SystemSetting).filter(SystemSetting.key.in_(
            (user_access.DEFAULT_ACCESS_KEY, user_access.DEFAULT_VERSION_KEY))).delete(synchronize_session=False)


@pytest.fixture
def people(app_schema, monkeypatch):
    inner = settings._inner
    monkeypatch.setattr(inner, "basic_auth_enabled", True)
    monkeypatch.setattr(inner, "auth_enabled", False)
    monkeypatch.setattr(inner, "oauth2_enabled", False)
    monkeypatch.setattr(inner, "auth_username", ADMIN_NAME)
    monkeypatch.setattr(inner, "auth_password", ADMIN_PASSWORD)
    monkeypatch.setattr(inner, "raw_logs_services", "postfix")
    monkeypatch.setattr(raw_logs, "log_stream_manager", raw_logs.LogStreamManager())
    # The guards read the sign-in settings as saved; here they are the test's settings
    monkeypatch.setattr(users_store, "build_settings", lambda db: settings._inner)
    _wipe()
    session_module._session_store.clear()
    auth_module._auth_failures.clear()
    raw_logs._ws_tokens.clear()
    yield
    _wipe()
    session_module._session_store.clear()
    auth_module._auth_failures.clear()
    raw_logs._ws_tokens.clear()


def _client():
    return TestClient(app, raise_server_exceptions=False)


def _admin():
    client = _client()
    assert client.post("/api/auth/session", headers=_basic(ADMIN_NAME, ADMIN_PASSWORD)).status_code == 200
    return client


def _add(admin, name="alice", access="viewer", views=(), acts=(), kind="local", disabled=False, password=PASSWORD):
    body = {"kind": kind, "access": access, "views": list(views), "acts": list(acts), "disabled": disabled}
    if kind == "local":
        body.update(username=name, password=password)
    else:
        body.update(email=name)
    r = admin.post("/api/users", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def _sign_in(name="alice", password=PASSWORD, expect=200):
    client = _client()
    r = client.post("/api/auth/session", headers=_basic(name, password))
    assert r.status_code == expect, r.text
    return client


def _oauth2_client(email, verified=None):
    """A browser with an OAuth2 session, as the callback makes it."""
    user_info = {"email": email, "sub": "42"}
    if verified is not None:
        user_info["email_verified"] = verified
    client = _client()
    signed = session_module.create_session(user_info, generation=session_module.auth_generation(),
                                           principal=user_access.oauth2_ref(user_info))
    client.cookies.set(session_module.SESSION_COOKIE_NAME, signed)
    return client


def _user(admin, user_id):
    return next(u for u in admin.get("/api/users").json()["users"] if u["id"] == user_id)


def _change(admin, row, **change):
    body = {"access": row["access"], "views": [a for a, k in row["areas"].items()],
            "acts": [a for a, k in row["areas"].items() if k == "act"], "disabled": row["disabled"],
            "row_version": row["row_version"], **change}
    return admin.put(f"/api/users/{row['id']}", json=body)


# ── Upgrade safety ─────────────────────────────────────────────────────────

def test_without_users_or_a_stored_default_everyone_signed_in_is_an_admin(people, monkeypatch):
    monkeypatch.setattr(settings._inner, "oauth2_enabled", True)
    for client in (_admin(), _oauth2_client("someone@example.com"), _oauth2_client("other@example.com", False)):
        status = client.get("/api/auth/status").json()
        assert status["is_admin"] is True and status["scopes"] == list(all_scopes())
        assert client.get("/api/users").status_code == 200
        assert client.get("/api/status/container-logs").status_code == 200


def test_sign_in_off_is_the_built_in_admin(people, monkeypatch):
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    client = _client()
    assert client.get("/api/users").status_code == 200
    assert client.get("/api/auth/status").json()["is_admin"] is True


# ── Local users sign in ────────────────────────────────────────────────────

def test_a_local_user_signs_in_on_the_login_form(people):
    admin = _admin()
    row = _add(admin, "Alice.Ops", "viewer")
    assert row["username"] == "Alice.Ops" and row["last_login_at"] is None
    client = _sign_in("alice.ops")
    status = client.get("/api/auth/status").json()
    assert status["user_name"] == "Alice.Ops" and status["is_admin"] is False
    assert status["auth_type"] == "basic"
    assert "settings:read" not in status["scopes"] and "messages:read" in status["scopes"]
    assert _user(admin, row["id"])["last_login_at"] is not None


def test_a_wrong_password_or_unknown_name_is_refused_and_counted(people):
    admin = _admin()
    _add(admin)
    _sign_in("alice", "not the password at all", expect=401)
    _sign_in("nobody", PASSWORD, expect=401)
    assert sum(len(v) for v in auth_module._auth_failures.values()) == 2


def test_the_failure_budget_applies_to_local_users_too(people, monkeypatch):
    admin = _admin()
    _add(admin)
    monkeypatch.setattr(auth_module, "_AUTH_MAX_FAILURES", 2)
    _sign_in("alice", "wrong password one", expect=401)
    _sign_in("alice", "wrong password two", expect=401)
    _sign_in("alice", PASSWORD, expect=429)


def test_an_unknown_name_costs_one_hash_like_a_known_one(people, monkeypatch):
    admin = _admin()
    _add(admin)
    from app.services import passwords
    passwords.burn("warm up")
    calls = []
    real = passwords._derive
    monkeypatch.setattr(passwords, "_derive", lambda *a: calls.append(1) or real(*a))
    for name in ("alice", "nobody", "admin", "not a valid name!"):
        calls.clear()
        _sign_in(name, "a wrong password here", expect=401)
        assert calls == [1], name


def test_at_most_two_password_checks_run_at_once(people):
    admin = _admin()
    _add(admin)
    assert users_store.SIGN_IN_HASHES.acquire(blocking=False)
    assert users_store.SIGN_IN_HASHES.acquire(blocking=False)
    try:
        r = _client().post("/api/auth/session", headers=_basic("alice", PASSWORD))
        assert r.status_code == 429
        assert r.json()["detail"] == "Too many sign-in attempts at once. Try again in a moment."
        # The built-in admin needs no hash
        assert _client().post("/api/auth/session", headers=_basic(ADMIN_NAME, ADMIN_PASSWORD)).status_code == 200
    finally:
        users_store.SIGN_IN_HASHES.release()
        users_store.SIGN_IN_HASHES.release()
    _sign_in("alice")


def test_a_non_ascii_password_signs_in(people):
    admin = _admin()
    _add(admin, password="pässwört 日本 été ok")
    _sign_in("alice", "pässwört 日本 été ok")


def test_a_local_user_cannot_use_a_basic_header_on_the_api(people):
    admin = _admin()
    _add(admin, access="admin")
    assert _client().get("/api/messages", headers=_basic("alice", PASSWORD)).status_code == 401
    assert _client().get("/api/messages", headers=_basic(ADMIN_NAME, ADMIN_PASSWORD)).status_code == 200


def test_a_disabled_user_cannot_sign_in(people):
    admin = _admin()
    _add(admin, disabled=True)
    _sign_in("alice", expect=401)


def test_local_users_cannot_sign_in_while_basic_auth_is_off(people, monkeypatch):
    admin = _admin()
    _add(admin)
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    monkeypatch.setattr(settings._inner, "oauth2_enabled", True)
    _sign_in("alice", expect=400)


def test_a_change_while_the_password_is_checked_gets_no_session(people, monkeypatch):
    admin = _admin()
    row = _add(admin)
    real = users_store.verify_sign_in

    def changed_meanwhile(username, password):
        found = real(username, password)
        assert _change(admin, row, access="operator").status_code == 200
        return found

    monkeypatch.setattr(users_store, "verify_sign_in", changed_meanwhile)
    client = _sign_in("alice", expect=409)
    assert "session_id" not in client.cookies


# ── Usernames ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", ["", "a" * 65, "with space", "colon:name", "tab\tname", "émile"])
def test_a_username_outside_the_allowed_characters_is_refused(people, name):
    r = _admin().post("/api/users", json={"kind": "local", "username": name, "password": PASSWORD, "access": "viewer"})
    assert r.status_code == 422


def test_usernames_are_unique_ignoring_case_and_width(people):
    admin = _admin()
    _add(admin, "alice")
    r = admin.post("/api/users", json={"kind": "local", "username": "ＡLICE", "password": PASSWORD, "access": "viewer"})
    assert r.status_code == 409


def test_a_short_password_is_refused(people):
    r = _admin().post("/api/users", json={"kind": "local", "username": "alice", "password": "short", "access": "viewer"})
    assert r.status_code == 422 and "12 to 256" in r.json()["detail"]


def test_a_local_user_cannot_take_the_built_in_admins_name(people):
    r = _admin().post("/api/users", json={"kind": "local", "username": "ADMIN", "password": PASSWORD, "access": "viewer"})
    assert r.status_code == 409


@pytest.fixture
def refused_saves_only(monkeypatch):
    """Settings saves through the real route, for saves that must be refused: one that got
    through would reload the settings every other test relies on, so it fails instead."""
    from app.routers import settings as settings_router

    def must_not_save(*args):
        raise AssertionError("this save should have been refused")

    monkeypatch.setattr(settings._inner, "edit_settings_via_ui_enabled", True)
    monkeypatch.setattr(settings_router, "save_config_overrides_to_db", must_not_save)


def test_the_built_in_admin_cannot_be_renamed_to_a_local_users_name(people, refused_saves_only):
    admin = _admin()
    _add(admin, "alice")
    r = admin.put("/api/settings", json={"auth_username": "Alice"})
    assert r.status_code == 400 and "local user" in r.json()["detail"]
    assert settings.auth_username == ADMIN_NAME


def test_after_the_environment_renamed_the_admin_the_built_in_admin_wins(people, monkeypatch, caplog):
    admin = _admin()
    row = _add(admin, "alice", access="admin")
    signed_in = _sign_in("alice")
    monkeypatch.setattr(settings._inner, "auth_username", "alice")
    from app import main
    with caplog.at_level(logging.WARNING):
        main.log_user_name_conflicts()
    assert "'alice' has the built-in admin's username" in caplog.text
    assert _user(_admin_as("alice"), row["id"])["name_conflict"] is True
    # The local user's session ends and it cannot sign in; the password is the built-in admin's
    assert signed_in.get("/api/messages").status_code == 401
    _sign_in("alice", PASSWORD, expect=401)
    _sign_in("alice", ADMIN_PASSWORD)


def _admin_as(name):
    client = _client()
    assert client.post("/api/auth/session", headers=_basic(name, ADMIN_PASSWORD)).status_code == 200
    return client


# ── What each person may do ────────────────────────────────────────────────

READS = {
    "status": ("GET", "/api/settings/health", {}),
    "messages": ("GET", "/api/messages", {}),
    "outbound": ("GET", "/api/suppressions/stats", {}),
    "quarantine": ("GET", "/api/quarantine/rules", {}),
    "security": ("GET", "/api/security-alerts", {}),
    "dmarc": ("GET", "/api/dmarc/imap/history", {}),
    "mailboxes": ("GET", "/api/devices", {}),
    "logs": ("GET", "/api/raw-logs/services", {}),
}
# Sent so that a request let through stops at validation (422) before doing anything
WRITES = {
    "outbound": ("POST", "/api/suppressions", {"json": {}}),
    "outbound-import": ("POST", "/api/suppressions/import", {}),
    "quarantine": ("POST", "/api/quarantine/rules", {"json": {}}),
    "security": ("POST", "/api/protection/hits/not-a-number/dismiss", {}),
    "rspamd": ("PUT", "/api/rspamd/maps/x.map", {"json": {}}),
    "dmarc-upload": ("POST", "/api/dmarc/upload", {}),
    "mailboxes": ("POST", "/api/rate-limits/mailbox", {"json": {}}),
}
ADMIN_ONLY = [
    ("GET", "/api/users", {}),
    ("GET", "/api/settings", {}),
    ("GET", "/api/agents", {}),
    ("GET", "/api/status/container-logs", {}),
    ("POST", "/api/settings/jobs/no-such-job/run", {}),
    ("PUT", "/api/notifications/channels/not-a-number", {"json": {}}),
    ("DELETE", "/api/notifications/channels/not-a-number", {}),
    ("GET", "/api/notifications/channels", {}),
    ("PUT", "/api/users/not-a-number", {"json": {}}),
]
ANYONE = [("GET", "/api/rw-status", {}), ("GET", "/api/auth/status", {}), ("GET", "/api/auth/verify", {})]


def _call(client, method, path, kwargs):
    return client.request(method, path, **kwargs)


def _allowed(response):
    """Whether the access check let the request through; a route may still refuse on its own (a feature off)."""
    assert response.status_code not in (401, 503), response.text
    return not (response.status_code == 403 and response.json() == {"detail": user_access.NOT_PERMITTED})


@pytest.mark.parametrize("access, views, acts, reads, writes, admin", [
    ("admin", (), (), set(READS), set(WRITES), True),
    ("operator", (), (), set(READS), set(WRITES) - {"rspamd"}, False),
    ("viewer", (), (), set(READS), set(), False),
    ("custom", ("messages", "logs"), ("dmarc",), {"messages", "logs", "dmarc"}, {"dmarc-upload"}, False),
    ("custom", (), ("outbound", "security"), {"outbound", "security"}, {"outbound", "outbound-import", "security"},
     False),
])
def test_each_access_level_reaches_what_it_should(people, access, views, acts, reads, writes, admin):
    _add(_admin(), access=access, views=views, acts=acts)
    client = _sign_in()
    for area, (method, path, kwargs) in READS.items():
        assert _allowed(_call(client, method, path, kwargs)) is (area in reads), (access, method, path)
    for area, (method, path, kwargs) in WRITES.items():
        assert _allowed(_call(client, method, path, kwargs)) is (area in writes), (access, method, path)
    for method, path, kwargs in ADMIN_ONLY:
        assert _allowed(_call(client, method, path, kwargs)) is admin, (access, method, path)
    for method, path, kwargs in ANYONE:
        assert _allowed(_call(client, method, path, kwargs)), (access, method, path)


def test_a_refusal_says_so_in_plain_words(people):
    _add(_admin())
    r = _sign_in().get("/api/users")
    assert r.status_code == 403 and r.json() == {"detail": "You do not have permission for this."}


def test_the_built_in_admin_reaches_everything(people):
    client = _admin()
    for method, path, kwargs in [*READS.values(), *WRITES.values(), *ADMIN_ONLY]:
        assert _allowed(_call(client, method, path, kwargs)), (method, path)


def test_settings_is_never_part_of_a_custom_access(people):
    admin = _admin()
    row = _add(admin, access="custom", views=("settings", "messages"), acts=("settings",))
    assert row["areas"] == {"messages": "view"}
    assert _sign_in().get("/api/settings").status_code == 403


def test_a_custom_access_without_any_view_is_refused(people):
    r = _admin().post("/api/users", json={"kind": "local", "username": "alice", "password": PASSWORD,
                                          "access": "custom", "views": ["settings"]})
    assert r.status_code == 422 and r.json()["detail"] == "Select View for at least one area."


def test_routes_that_combine_areas_need_view_on_each(people, monkeypatch):
    from fastapi import HTTPException

    async def no_mailcow():
        raise HTTPException(status_code=502, detail="mailcow is not part of this test")

    monkeypatch.setattr(reporting, "get_system_summary_data", no_mailcow)
    summary = ("status", "mailboxes", "domains", "outbound", "quarantine")
    admin = _admin()
    _add(admin, "most", access="custom", views=summary[:-1])
    _add(admin, "all", access="custom", views=summary)
    _add(admin, "acts", access="custom", views=summary, acts=("status",))
    most, every, acts = _sign_in("most"), _sign_in("all"), _sign_in("acts")
    assert most.get("/api/system/summary").status_code == 403
    assert every.get("/api/system/summary").status_code == 502
    assert every.post("/api/system/summary/email").status_code == 403
    assert acts.post("/api/system/summary/email").status_code == 200


@pytest.mark.parametrize("card, areas", [
    ("ip", ("messages", "security", "mailboxes", "dmarc", "status")),
    ("address", ("messages", "security", "mailboxes", "outbound")),
    ("domain", ("messages", "security", "mailboxes", "dmarc", "outbound", "domains")),
])
def test_an_entity_card_needs_view_on_every_area_it_reads(people, card, areas):
    admin = _admin()
    _add(admin, "every", access="custom", views=areas)
    every = _sign_in("every")
    # An unreadable value: let through, the card itself answers 422 without reading anything
    assert every.get(f"/api/entities/{card}", params={"value": "?"}).status_code == 422
    for missing in areas:
        name = "no-" + missing
        _add(admin, name, access="custom", views=[a for a in areas if a != missing])
        assert _sign_in(name).get(f"/api/entities/{card}", params={"value": "?"}).status_code == 403, missing


def test_settings_info_shows_recent_messages_only_with_view_for_messages(people, monkeypatch):
    from app.routers import settings as settings_router
    seen = []

    def recorded(request, area, kind):
        answer = user_access.caller_may(request, area, kind)
        if area == "messages":
            seen.append((request.state.principal.name, area, answer))
        return answer

    monkeypatch.setattr(settings_router, "caller_may", recorded)
    admin = _admin()
    _add(admin, "status-only", access="custom", views=("status",))
    _add(admin, "with-messages", access="custom", views=("status", "messages"))
    assert _sign_in("status-only").get("/api/settings/info").status_code == 200
    assert _sign_in("with-messages").get("/api/settings/info").status_code == 200
    assert seen == [("status-only", "messages", False), ("with-messages", "messages", True)]


def test_caller_may_answers_for_people_and_agents(monkeypatch):
    from types import SimpleNamespace
    from app.agent_access.context import SCOPE_KEY, AgentCall
    viewer = user_access.Principal("local", False, user_access.preset_scopes("viewer"), "v")
    person = SimpleNamespace(scope={}, state=SimpleNamespace(principal=viewer))
    assert user_access.caller_may(person, "messages", "read")
    assert not user_access.caller_may(person, "messages", "write")
    assert not user_access.caller_may(person, "settings", "read")
    grant = SimpleNamespace(scopes=frozenset({"status:read"}))
    agent = SimpleNamespace(scope={SCOPE_KEY: AgentCall(grant=grant, mode=None)}, state=SimpleNamespace())
    assert user_access.caller_may(agent, "status", "read")
    assert not user_access.caller_may(agent, "messages", "read")
    nobody = SimpleNamespace(scope={}, state=SimpleNamespace())
    for key in ("auth_enabled", "basic_auth_enabled", "oauth2_enabled"):
        monkeypatch.setattr(settings._inner, key, False)
    # Sign-in off: the built-in admin; on, a request nobody was resolved for gets nothing
    assert user_access.caller_may(nobody, "messages", "read")
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", True)
    assert not user_access.caller_may(nobody, "messages", "read")


def test_approving_an_agent_is_for_admins(people, monkeypatch):
    monkeypatch.setattr(settings._inner, "agent_access_enabled", True)
    monkeypatch.setattr(settings._inner, "agent_access_url", "https://logs.example.com")
    _add(_admin(), access="operator")
    client = _sign_in()
    for path in ("/oauth/authorize", "/oauth/consent", "/oauth/device"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 403, path
        assert "text/html" in r.headers["content-type"]
    assert client.post("/api/agents/consent/x", json={"allow": True}).status_code == 403


def test_operators_view_but_do_not_edit_rspamd_maps():
    operator = user_access.preset_scopes("operator")
    assert "rspamd:read" in operator and "rspamd:write" not in operator
    assert "outbound:write" in operator and "settings:read" not in operator
    viewer = user_access.preset_scopes("viewer")
    assert all(s.endswith(":read") for s in viewer) and "settings:read" not in viewer


@pytest.mark.no_contract(reason="stubs user_access._resolve_now with a database failure; the 503 is app-wide")
def test_a_database_error_while_checking_access_refuses_with_503(people, monkeypatch):
    client = _sign_in_as_viewer()

    def broken(*args):
        raise RuntimeError("database down")

    monkeypatch.setattr(user_access, "_resolve_now", broken)
    r = client.get("/api/messages")
    assert r.status_code == 503 and "could not be checked" in r.json()["detail"]
    assert not user_access.still_permits({"kind": "local", "user_id": 1, "auth_version": 1}, "logs", "read")


def _sign_in_as_viewer():
    _add(_admin())
    return _sign_in()


# ── A change applies to the next request ───────────────────────────────────

def _ended(response):
    assert response.status_code == 401
    assert response.json()["reason"] == "access_changed" and response.headers["x-session-end"] == "access_changed"


@pytest.mark.parametrize("change", [{"access": "operator"}, {"disabled": True}, {"password": "another long password"}])
def test_a_change_ends_the_users_sessions(people, change):
    admin = _admin()
    row = _add(admin)
    client = _sign_in()
    assert client.get("/api/messages").status_code == 200
    assert _change(admin, row, **change).status_code == 200
    _ended(client.get("/api/messages"))
    _ended(client.get("/api/messages"))


def test_a_change_applies_even_to_a_session_the_store_still_holds(people, monkeypatch):
    """Ending sessions actively is a convenience; the per-request check alone refuses them."""
    admin = _admin()
    row = _add(admin)
    client = _sign_in()
    monkeypatch.setattr(users_store, "_end_local_sessions", lambda user_id, below=None: None)
    assert _change(admin, row, access="custom", views=["logs"]).status_code == 200
    _ended(client.get("/api/messages"))


def test_deleting_a_user_ends_their_sessions(people):
    admin = _admin()
    row = _add(admin)
    client = _sign_in()
    assert admin.delete(f"/api/users/{row['id']}").json() == {"deleted": 1}
    _ended(client.get("/api/messages"))
    assert admin.delete(f"/api/users/{row['id']}").status_code == 404


def test_signing_out_works_after_the_access_ended(people, monkeypatch):
    admin = _admin()
    row = _add(admin)
    client = _sign_in()
    # The session is still in the store, but no longer gives access
    monkeypatch.setattr(users_store, "_end_local_sessions", lambda user_id, below=None: None)
    assert _change(admin, row, disabled=True).status_code == 200
    r = client.post("/api/auth/logout", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/login"
    assert len(session_module._session_store) == 1


def test_a_new_password_replaces_the_old_one(people):
    admin = _admin()
    row = _add(admin)
    assert _change(admin, row, password="another long password").status_code == 200
    _sign_in("alice", PASSWORD, expect=401)
    _sign_in("alice", "another long password")


def test_kind_name_and_email_cannot_be_changed(people):
    admin = _admin()
    row = _add(admin)
    assert _change(admin, row, username="mallory").status_code == 422
    assert _change(admin, row, kind="oauth2").status_code == 422


# ── OAuth2 ─────────────────────────────────────────────────────────────────

@pytest.fixture
def oauth2(people, monkeypatch):
    monkeypatch.setattr(settings._inner, "oauth2_enabled", True)


def _set_default(admin, value):
    version = admin.get("/api/users").json()["oauth2"]["version"]
    r = admin.put("/api/users/oauth2-default", json={"value": value, "version": version})
    assert r.status_code == 200, r.text
    return r.json()


def test_an_entry_gives_its_email_its_own_access(oauth2):
    admin = _admin()
    _set_default(admin, "viewer")
    _add(admin, "Carol@Example.COM", "custom", views=("logs",), kind="oauth2")
    carol = _oauth2_client(" carol@example.com ")
    assert carol.get("/api/auth/status").json()["scopes"] == ["logs:read"]
    assert carol.get("/api/messages").status_code == 403
    other = _oauth2_client("dave@example.com")
    assert other.get("/api/messages").status_code == 200
    assert other.get("/api/users").status_code == 403


def test_an_email_the_provider_says_is_not_verified_gets_the_default(oauth2):
    admin = _admin()
    _set_default(admin, "viewer")
    _add(admin, "carol@example.com", "admin", kind="oauth2")
    assert _oauth2_client("carol@example.com", verified=False).get("/api/users").status_code == 403
    assert _oauth2_client("carol@example.com", verified=True).get("/api/users").status_code == 200


def test_a_disabled_entry_refuses_and_ends_the_session(oauth2):
    admin = _admin()
    row = _add(admin, "carol@example.com", "admin", kind="oauth2")
    carol = _oauth2_client("carol@example.com")
    assert carol.get("/api/users").status_code == 200
    assert _change(admin, row, disabled=True).status_code == 200
    _ended(carol.get("/api/messages"))


def test_a_default_of_no_access_refuses_people_without_an_entry(oauth2):
    admin = _admin()
    _add(admin, "carol@example.com", "viewer", kind="oauth2")
    dave = _oauth2_client("dave@example.com")
    assert dave.get("/api/messages").status_code == 200
    _set_default(admin, "none")
    # Applies to the sessions already open
    _ended(dave.get("/api/messages"))
    assert _oauth2_client("carol@example.com").get("/api/messages").status_code == 200


def test_changing_the_default_applies_to_open_sessions(oauth2):
    admin = _admin()
    dave = _oauth2_client("dave@example.com")
    assert dave.get("/api/users").status_code == 200
    _set_default(admin, "operator")
    assert dave.get("/api/users").status_code == 403
    assert dave.get("/api/auth/status").json()["is_admin"] is False


def test_a_provider_cannot_claim_a_basic_sign_in(oauth2):
    """The session's person comes from the callback, never from what the provider sent."""
    admin = _admin()
    _set_default(admin, "viewer")
    user_info = {"email": "eve@example.com", "auth_method": "basic"}
    client = _client()
    client.cookies.set(session_module.SESSION_COOKIE_NAME, session_module.create_session(
        user_info, generation=session_module.auth_generation(), principal=user_access.oauth2_ref(user_info)))
    assert client.get("/api/users").status_code == 403


AUTHORIZE = "https://id.example.com/authorize"
TOKEN = "https://id.example.com/token"
USERINFO = "https://id.example.com/userinfo"


@pytest.fixture
def provider(oauth2, monkeypatch):
    client = auth_router.oauth2_client
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    for key, value in (("issuer_url", None), ("client_id", "viewer-test"), ("client_secret", "viewer-test-secret"),
                       ("redirect_uri", "https://viewer.example.com/api/auth/callback"),
                       ("scopes", ["openid", "email"]), ("authorization_url", AUTHORIZE), ("token_url", TOKEN),
                       ("userinfo_url", USERINFO)):
        monkeypatch.setattr(client, key, value)
    who = {"email": "dave@example.com"}

    def handler(request):
        if str(request.url) == TOKEN:
            return httpx.Response(200, json={"access_token": "test-token", "token_type": "Bearer"})
        if str(request.url) == USERINFO:
            return httpx.Response(200, json=who)
        return httpx.Response(404)

    real = httpx.AsyncClient
    monkeypatch.setattr(oauth2_module.httpx, "AsyncClient",
                        lambda *a, **kw: real(*a, **{**kw, "transport": httpx.MockTransport(handler)}))
    return who


def _callback(client):
    location = client.get("/api/auth/login", follow_redirects=False).headers["location"]
    state = parse_qs(urlsplit(location).query)["state"][0]
    return client.get("/api/auth/callback", params={"state": state, "code": "c"}, follow_redirects=False)


def _store_default(value):
    from app.database import get_db_context
    with get_db_context() as db:
        users_store._write_key(db, user_access.DEFAULT_ACCESS_KEY, value)


def test_a_refused_oauth2_login_gets_no_session_and_takes_no_slot(provider, monkeypatch):
    monkeypatch.setattr(settings._inner, "session_max_entries", 1)
    _store_default("none")
    refused = _client()
    r = _callback(refused)
    assert r.status_code == 302 and r.headers["location"] == "/login?error=no_access"
    assert "session_id" not in refused.cookies and not session_module._session_store
    # The one slot is still free for someone with access
    provider["email"] = "carol@example.com"
    from app.database import get_db_context
    with get_db_context() as db:
        users_store.create_user(db, kind="oauth2", username=None, email="carol@example.com", password=None,
                                access_level="viewer", views=(), acts=(), disabled=False)
    allowed = _client()
    assert _callback(allowed).headers["location"] == "/"
    assert allowed.get("/api/messages").status_code == 200


def test_a_disabled_oauth2_entry_cannot_sign_in(provider):
    from app.database import get_db_context
    with get_db_context() as db:
        users_store.create_user(db, kind="oauth2", username=None, email="dave@example.com", password=None,
                                access_level="admin", views=(), acts=(), disabled=True)
    assert _callback(_client()).headers["location"] == "/login?error=no_access"


def test_an_oauth2_login_stores_the_normalized_email(provider):
    provider.update(email=" Dave@Example.com", email_verified=False)
    client = _client()
    assert _callback(client).headers["location"] == "/"
    record = next(iter(session_module._session_store.values()))
    assert record["principal"] == {"kind": "oauth2", "email": "dave@example.com", "unverified": True}


# ── Versions and the last admin ────────────────────────────────────────────

def test_an_edit_on_an_older_copy_is_refused(people):
    admin = _admin()
    row = _add(admin)
    assert _change(admin, row, access="operator").status_code == 200
    r = _change(admin, row, access="admin")
    assert r.status_code == 409 and r.json()["detail"] == "Someone else changed this user. Reload and try again."
    assert _user(admin, row["id"])["access"] == "operator"


def test_a_default_change_on_an_older_version_is_refused(oauth2):
    admin = _admin()
    assert admin.put("/api/users/oauth2-default", json={"value": "viewer", "version": 0}).json() == {
        "default_access": "viewer", "version": 1}
    r = admin.put("/api/users/oauth2-default", json={"value": "admin", "version": 0})
    assert r.status_code == 409
    assert admin.get("/api/users").json()["oauth2"] == {"enabled": True, "default_access": "viewer", "version": 1}


def test_a_settings_form_cannot_change_the_oauth2_default(oauth2, refused_saves_only):
    admin = _admin()
    _set_default(admin, "viewer")
    for key in ("oauth2_default_access", user_access.DEFAULT_ACCESS_KEY, user_access.DEFAULT_VERSION_KEY):
        r = admin.put("/api/settings", json={key: "admin"})
        assert r.status_code == 400, key
    assert admin.get("/api/users").json()["oauth2"]["default_access"] == "viewer"


def test_the_last_admin_cannot_be_demoted_in_oauth2_only_mode(oauth2, monkeypatch):
    admin = _admin()
    row = _add(admin, "carol@example.com", "admin", kind="oauth2")
    _set_default(admin, "viewer")
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    carol = _oauth2_client("carol@example.com")
    r = _change(carol, row, access="operator")
    assert r.status_code == 409 and r.json()["detail"] == "This change would leave no admin who can sign in."
    assert carol.delete(f"/api/users/{row['id']}").status_code == 409
    assert _change(carol, row, disabled=True).status_code == 409
    version = carol.get("/api/users").json()["oauth2"]["version"]
    # A default of Admin is an admin who can sign in
    assert carol.put("/api/users/oauth2-default", json={"value": "admin", "version": version}).status_code == 200
    assert _change(carol, row, access="operator").status_code == 200
    dave = _oauth2_client("dave@example.com")
    version = dave.get("/api/users").json()["oauth2"]["version"]
    assert dave.put("/api/users/oauth2-default", json={"value": "none", "version": version}).status_code == 409


def test_two_demotions_at_once_leave_one_admin(oauth2, monkeypatch):
    admin = _admin()
    first = _add(admin, "carol@example.com", "admin", kind="oauth2")
    second = _add(admin, "dave@example.com", "admin", kind="oauth2")
    _set_default(admin, "viewer")
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    real = users_store.usable_admins

    def slow(db, sign_in, default):
        # Without the lock both would count two admins before either commits
        count = real(db, sign_in, default)
        time.sleep(0.3)
        return count

    monkeypatch.setattr(users_store, "usable_admins", slow)
    from app.database import SessionLocal
    results = []
    start = threading.Barrier(2)

    def demote(row):
        db = SessionLocal()
        try:
            start.wait()
            users_store.update_user(db, row["id"], access_level="viewer", views=(), acts=(), disabled=False,
                                    password=None, row_version=row["row_version"])
            results.append("ok")
        except users_store.UserError as e:
            results.append(e.status)
        finally:
            db.close()

    threads = [threading.Thread(target=demote, args=(row,)) for row in (first, second)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert sorted(results, key=str) == [409, "ok"]


def test_a_settings_save_that_would_leave_no_admin_is_refused(oauth2):
    _set_default(_admin(), "viewer")
    from app.database import get_db_context
    with get_db_context() as db:
        with pytest.raises(users_store.UserError) as refused:
            users_store.check_sign_in_settings(db, settings, {"basic_auth_enabled": False})
    assert refused.value.status == 409 and refused.value.detail == users_store.NO_ADMIN_LEFT
    with get_db_context() as db:
        # A new password keeps the built-in admin
        users_store.check_sign_in_settings(db, settings, {"auth_password": "a new admin password"})
        with pytest.raises(users_store.UserError):
            users_store.check_sign_in_settings(db, settings, {"auth_password": ""})


def test_the_settings_save_runs_the_sign_in_check_under_the_lock(people, refused_saves_only, monkeypatch):
    from app.routers import settings as settings_router
    seen = []

    def refuse(db, before, allowed):
        seen.append(dict(allowed))
        raise users_store.UserError(409, users_store.NO_ADMIN_LEFT)

    monkeypatch.setattr(settings_router.users_store, "check_sign_in_settings", refuse)
    admin = _admin()
    r = admin.put("/api/settings", json={"oauth2_enabled": True, "app_title": "Mail"})
    assert r.status_code == 409 and seen == [{"oauth2_enabled": True, "app_title": "Mail"}]


def test_only_a_save_that_changes_who_can_sign_in_needs_the_check():
    from types import SimpleNamespace
    from app.routers.settings import _changes_admin_sign_in
    before = SimpleNamespace(basic_auth_enabled=True, auth_username="admin", auth_password="secret password",
                             oauth2_enabled=False)
    # The form sends every key on each save
    assert not _changes_admin_sign_in({"basic_auth_enabled": True, "auth_username": "admin", "app_title": "x",
                                       "oauth2_client_id": "changed"}, before)
    assert _changes_admin_sign_in({"basic_auth_enabled": False}, before)
    assert _changes_admin_sign_in({"auth_username": "root"}, before)
    assert _changes_admin_sign_in({"auth_password": ""}, before)
    assert _changes_admin_sign_in({"oauth2_enabled": True}, before)


def test_turning_basic_auth_off_with_an_oauth2_admin_is_allowed_by_the_guard(oauth2):
    from app.database import get_db_context
    with get_db_context() as db:
        users_store._write_key(db, user_access.DEFAULT_ACCESS_KEY, "viewer")
        users_store.create_user(db, kind="oauth2", username=None, email="carol@example.com", password=None,
                                access_level="admin", views=(), acts=(), disabled=False)
    with get_db_context() as db:
        users_store.check_sign_in_settings(db, settings, {"basic_auth_enabled": False})


def test_a_local_admin_counts_only_while_basic_auth_is_on(people):
    from app.database import get_db_context
    with get_db_context() as db:
        users_store.create_user(db, kind="local", username="alice", email=None, password=PASSWORD,
                                access_level="admin", views=(), acts=(), disabled=False)
    with get_db_context() as db:
        on = users_store.SignIn(basic=True, password=False, env_name="admin", oauth2=False)
        assert users_store.usable_admins(db, on, "admin") == 1
        off = users_store.SignIn(basic=False, password=False, env_name="admin", oauth2=True)
        assert users_store.usable_admins(db, off, "viewer") == 0


# ── The users list ─────────────────────────────────────────────────────────

def test_the_list_says_what_each_preset_and_user_gets(people):
    admin = _admin()
    _add(admin, "alice", "operator")
    data = admin.get("/api/users").json()
    assert [a["id"] for a in data["areas"]] == [a.id for a in user_access.people_areas()]
    assert "settings" not in [a["id"] for a in data["areas"]]
    presets = {p["id"]: p["areas"] for p in data["presets"]}
    assert presets["operator"]["rspamd"] == "view" and presets["operator"]["outbound"] == "act"
    assert presets["viewer"]["outbound"] == "view" and presets["custom"] == {}
    assert data["builtin"] == {"username": ADMIN_NAME, "basic_auth_enabled": True}
    assert data["oauth2"] == {"enabled": False, "default_access": "admin", "version": 0}
    (row,) = data["users"]
    assert row["areas"] == presets["operator"] and row["email"] is None and row["name_conflict"] is False


def test_agents_never_reach_the_users_api():
    from app.agent_access import scopes
    for method in ("GET", "POST", "PUT", "DELETE"):
        for path in ("/api/users", "/api/users/{user_id}", "/api/users/oauth2-default"):
            assert scopes.excluded_reason(method, path)


# ── Live Logs ──────────────────────────────────────────────────────────────

def test_a_token_whose_person_lost_view_for_logs_opens_no_stream(people):
    admin = _admin()
    row = _add(admin, access="custom", views=("logs", "messages"))
    client = _sign_in()
    token = client.get("/api/raw-logs/ws-token").json()["token"]
    # An OAuth2 default or an entry can take Logs away without ending the session
    from sqlalchemy import text
    from app.database import get_db_context
    with get_db_context() as db:
        db.execute(text("UPDATE users SET scopes = 'messages:read' WHERE id = :id"), {"id": row["id"]})
    with client.websocket_connect(f"/ws/raw-logs?token={token}", headers={"Origin": APP}) as ws:
        assert ws.receive_json() == {"type": "error", "message": "You do not have permission for this."}
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
    assert closed.value.code == raw_logs.WS_NOT_PERMITTED


def test_a_person_without_view_for_logs_gets_no_token(people):
    _add(_admin(), access="custom", views=("messages",))
    assert _sign_in().get("/api/raw-logs/ws-token").status_code == 403


def test_an_open_stream_closes_when_its_person_loses_view_for_logs(oauth2, monkeypatch):
    monkeypatch.setattr(raw_logs, "WS_ACCESS_CHECK_SECONDS", 0)
    admin = _admin()
    row = _add(admin, "carol@example.com", access="custom", views=("logs",), kind="oauth2")
    carol = _oauth2_client("carol@example.com")
    token = carol.get("/api/raw-logs/ws-token").json()["token"]
    with carol.websocket_connect(f"/ws/raw-logs?token={token}", headers={"Origin": APP}) as ws:
        assert ws.receive_json()["type"] == "connected"
        ws.portal.call(raw_logs.log_stream_manager.broadcast, "postfix", [{"message": "before"}])
        assert ws.receive_json()["entries"] == [{"message": "before"}]
        # An entry's change keeps the session; only the stream's access goes
        assert _change(admin, _user(admin, row["id"]), views=["messages"], acts=[]).status_code == 200
        ws.portal.call(raw_logs.log_stream_manager.broadcast, "postfix", [{"message": "after"}])
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
    assert closed.value.code == raw_logs.WS_SESSION_ENDED


def test_a_stream_checks_access_at_most_every_few_seconds():
    calls = []

    async def run():
        manager = raw_logs.LogStreamManager()

        class Socket:
            async def accept(self):
                pass

            async def send_text(self, text):
                pass

            async def close(self, code=1000, reason=""):
                pass

        ws = Socket()
        await manager.connect(ws, "postfix", (None, session_module.auth_generation(), {"kind": "local"}))
        original = raw_logs._may_read_logs

        async def counted(authority):
            calls.append(1)
            return True

        raw_logs._may_read_logs = counted
        try:
            manager._access_checked[ws] = 0.0
            for _ in range(5):
                await manager.broadcast("postfix", [{"message": "x"}])
        finally:
            raw_logs._may_read_logs = original

    asyncio.run(run())
    assert calls == [1]


# ── The action log ─────────────────────────────────────────────────────────

class _Lines(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


def test_each_change_a_person_asks_for_is_logged_whatever_the_log_level(people):
    lines = _Lines()
    actions = logging.getLogger("mlv.actions")
    actions.addHandler(lines)
    root = logging.getLogger()
    level = root.level
    root.setLevel(logging.ERROR)
    try:
        admin = _admin()
        _add(admin)
        viewer = _sign_in()
        viewer.get("/api/messages")
        viewer.post("/api/quarantine/rules", json={})
    finally:
        root.setLevel(level)
        actions.removeHandler(lines)
    assert actions.level == logging.INFO and actions.propagate is False
    assert "Action by admin: POST /api/users answered 201" in lines.lines
    assert "Action by alice: POST /api/quarantine/rules answered 403" in lines.lines
    assert not any("/api/messages" in line for line in lines.lines)


# ── Turning sign-in on, and the saved sign-in under the lock ───────────────

def _sign_in_off():
    return settings._inner.model_copy(update={"basic_auth_enabled": False, "oauth2_enabled": False,
                                              "auth_enabled": False})


@pytest.mark.parametrize("default", ["none", "viewer"])
def test_turning_oauth2_on_from_sign_in_off_needs_an_admin(people, default):
    """With sign-in off everyone is an admin, so turning it on must leave one who can sign in."""
    from app.database import get_db_context
    _store_default(default)
    with get_db_context() as db:
        with pytest.raises(users_store.UserError) as refused:
            users_store.check_sign_in_settings(db, _sign_in_off(), {"oauth2_enabled": True})
    assert refused.value.status == 409
    with get_db_context() as db:
        users_store.create_user(db, kind="oauth2", username=None, email="carol@example.com", password=None,
                                access_level="admin", views=(), acts=(), disabled=False)
    with get_db_context() as db:
        users_store.check_sign_in_settings(db, _sign_in_off(), {"oauth2_enabled": True})


def test_turning_basic_auth_on_with_a_password_from_sign_in_off_passes(people):
    from app.database import get_db_context
    _store_default("none")
    with get_db_context() as db:
        users_store.check_sign_in_settings(db, _sign_in_off(), {"basic_auth_enabled": True,
                                                                "auth_password": "a long admin password"})
    with get_db_context() as db:
        with pytest.raises(users_store.UserError):
            users_store.check_sign_in_settings(db, _sign_in_off(), {"basic_auth_enabled": True, "auth_password": ""})


def test_a_user_write_counts_the_saved_sign_in_not_the_one_in_memory(oauth2, monkeypatch):
    """A Settings save turned Basic Auth off and committed; the shared settings are not reloaded yet."""
    admin = _admin()
    row = _add(admin, "carol@example.com", "admin", kind="oauth2")
    _set_default(admin, "viewer")
    saved = settings._inner.model_copy(update={"basic_auth_enabled": False})
    monkeypatch.setattr(users_store, "build_settings", lambda db: saved)
    assert settings.is_basic_auth_enabled
    r = _change(admin, row, access="operator")
    assert r.status_code == 409 and r.json()["detail"] == users_store.NO_ADMIN_LEFT


def test_a_local_user_cannot_take_the_saved_admin_name(people, monkeypatch):
    saved = settings._inner.model_copy(update={"auth_username": "root"})
    monkeypatch.setattr(users_store, "build_settings", lambda db: saved)
    r = _admin().post("/api/users", json={"kind": "local", "username": "Root", "password": PASSWORD,
                                          "access": "viewer"})
    assert r.status_code == 409


# ── A sign-in that read the new version keeps its session ──────────────────

def test_a_sign_in_after_a_password_reset_keeps_its_session(people, monkeypatch):
    admin = _admin()
    row = _add(admin)
    old = _sign_in()
    real = users_store._end_local_sessions
    late = {}

    def sign_in_meanwhile(user_id, below=None):
        # Between the commit and ending the old sessions, the user signs in with the new password
        late["client"] = _sign_in("alice", "another long password")
        real(user_id, below)

    monkeypatch.setattr(users_store, "_end_local_sessions", sign_in_meanwhile)
    assert _change(admin, row, password="another long password").status_code == 200
    _ended(old.get("/api/messages"))
    assert late["client"].get("/api/messages").status_code == 200


def test_ending_sessions_below_a_version_keeps_newer_ones(people):
    def session_with(version):
        return session_module.create_session({"username": "alice", "auth_method": "basic"},
                                             generation=session_module.auth_generation(),
                                             principal={"kind": "local", "user_id": 7, "auth_version": version})
    older, newer = session_with(1), session_with(2)
    users_store._end_local_sessions(7, below=2)
    assert session_module.get_session(older) is None and session_module.get_session(newer) is not None
    users_store._end_local_sessions(7)
    assert session_module.get_session(newer) is None


# ── Sign-in during a database outage ───────────────────────────────────────

def test_a_database_failure_while_checking_a_local_user_is_503_and_not_counted(people, monkeypatch):
    def broken(username, password):
        raise RuntimeError("database down")

    monkeypatch.setattr(users_store, "verify_sign_in", broken)
    for _ in range(auth_module._AUTH_MAX_FAILURES + 1):
        r = _client().post("/api/auth/session", headers=_basic("alice", PASSWORD))
        assert r.status_code == 503
        assert r.json()["detail"] == "Sign-in is not available right now. Try again in a moment."
    assert not auth_module._auth_failures
    _admin()


# ── Public routes count a session only while it gives access ───────────────

def test_info_details_end_with_the_persons_access(oauth2):
    admin = _admin()
    dave = _oauth2_client("dave@example.com")
    assert "version" in dave.get("/api/info").json()
    _set_default(admin, "none")
    info = dave.get("/api/info").json()
    assert "version" not in info and info["app_title"] and info["oauth2_enabled"] is True
    _ended(dave.get("/api/messages"))


def test_activity_ends_with_the_persons_access(oauth2):
    admin = _admin()
    dave = _oauth2_client("dave@example.com")
    assert dave.post("/api/auth/activity").status_code == 200
    _set_default(admin, "none")
    _ended(dave.post("/api/auth/activity"))


# ── Answers that hold another area's data ──────────────────────────────────

@pytest.fixture
def stored():
    """Rows a test adds, deleted afterwards (children first)."""
    from app.database import get_db_context
    added = []

    def add(row):
        with get_db_context() as db:
            db.add(row)
            db.flush()
            db.expunge(row)
        added.append(row)
        return row

    yield add
    with get_db_context() as db:
        for row in reversed(added):
            db.query(type(row)).filter(type(row).id == row.id).delete(synchronize_session=False)


def _person(admin, name, views=(), acts=()):
    _add(admin, name, access="custom", views=views, acts=acts)
    return _sign_in(name)


def test_message_details_show_netfilter_events_only_with_view_for_security(people, stored):
    from datetime import datetime
    from app.models import MessageCorrelation, NetfilterLog, RspamdLog
    now = datetime.utcnow()
    rspamd = stored(RspamdLog(time=now, ip="192.0.2.10", score=1.0, required_score=15.0, action="no action",
                              symbols={}, is_spam=False, direction="inbound", sender_smtp="alice@example.com",
                              recipients_smtp=["bob@example.com"], subject="Hello"))
    stored(MessageCorrelation(correlation_key="users-test-details", rspamd_log_id=rspamd.id,
                              sender="alice@example.com", recipient="bob@example.com", subject="Hello",
                              direction="inbound", first_seen=now, last_seen=now))
    stored(NetfilterLog(time=now, ip="192.0.2.10", username="bob@example.com", message="authentication failed"))
    admin = _admin()
    messages_only = _person(admin, "messages-only", views=("messages",))
    both = _person(admin, "both", views=("messages", "security"))
    details = messages_only.get("/api/message/users-test-details/details")
    assert details.status_code == 200 and details.json()["netfilter"] == []
    assert details.json()["subject"] == "Hello"
    assert [e["ip"] for e in both.get("/api/message/users-test-details/details").json()["netfilter"]] == ["192.0.2.10"]


@pytest.mark.no_contract(reason="stubs messages._no_message_id_details, which builds the answer")
def test_a_message_without_a_message_id_shows_netfilter_events_only_with_view_for_security(people, monkeypatch):
    from app.routers import messages as messages_router
    asked = []

    def details(db, key, with_security=True):
        asked.append(with_security)
        raise messages_router.HTTPException(status_code=404, detail="Message not found")

    monkeypatch.setattr(messages_router, "_no_message_id_details", details)
    monkeypatch.setattr(messages_router.no_message_id, "is_key", lambda key: True)
    admin = _admin()
    _person(admin, "messages-only", views=("messages",)).get("/api/message/noid-x/details")
    _person(admin, "both", views=("messages", "security")).get("/api/message/noid-x/details")
    assert asked == [False, True]


def test_alert_activity_shows_the_mail_around_it_only_with_view_for_messages(people, stored, monkeypatch):
    from datetime import datetime
    from app.models import SecurityAlert
    from app.routers import security_alerts
    now = datetime.utcnow()
    alert = stored(SecurityAlert(alert_type="volume_spike", severity="warning", title="Sending spike",
                                 subject="alice@example.com", detail="120 messages", created_at=now))
    monkeypatch.setattr(security_alerts, "_events",
                        lambda db, a, start, end: [(now, "bob@example.com", "delivered", "Hello")])
    admin = _admin()
    path = f"/api/security-alerts/{alert.id}/activity"
    security_only = _person(admin, "security-only", views=("security",)).get(path)
    assert security_only.status_code == 200
    around = security_only.json()["around"]
    assert (around["subjects"], around["recipient_domains"], around["results"], around["total"]) == ([], [], [], 1)
    both = _person(admin, "both", views=("security", "messages")).get(path)
    assert both.json()["around"]["subjects"] == [{"name": "Hello", "count": 1}]


def test_top_blocked_addresses_need_view_for_security(people, stored):
    from datetime import datetime
    from app.models import NetfilterLog
    stored(NetfilterLog(time=datetime.utcnow(), ip="192.0.2.20", message="banned"))
    admin = _admin()
    assert _person(admin, "status-only", views=("status",)).get("/api/stats/top-blocked-ips").json() == {
        "blocked_ips": []}
    ips = _person(admin, "both", views=("status", "security")).get("/api/stats/top-blocked-ips").json()["blocked_ips"]
    assert "192.0.2.20" in [row["ip"] for row in ips]


def test_rate_limit_events_show_the_refused_mail_only_with_view_for_messages(people, stored):
    from datetime import datetime
    from app.models import RawServiceLog
    stored(RawServiceLog(service="ratelimited", time=datetime.utcnow(), message_hash="users-test-rl",
                         raw_data={"user": "alice@example.com", "rcpt": "bob@example.com",
                                   "header_subject": "Hello", "qid": "Q1"}))
    admin = _admin()
    for client, shown in ((_person(admin, "mailboxes-only", views=("mailboxes",)), False),
                          (_person(admin, "both", views=("mailboxes", "messages")), True)):
        event = client.get("/api/rate-limits/events").json()["events"][0]
        assert (event["subject"], event["rcpt"]) == (("Hello", "bob@example.com") if shown else ("", ""))
        history = client.get("/api/rate-limits/sender-events", params={"user": "alice@example.com"}).json()
        assert history["events"][0]["subject"] == ("Hello" if shown else "")


def test_suppression_evidence_shows_the_message_only_with_view_for_messages(people, stored):
    from app.models import SpamSuppression, SuppressionEvent
    suppression = stored(SpamSuppression(email="bob@example.com", reason="hard_bounce", type="email", active=True))
    stored(SuppressionEvent(suppression_id=suppression.id, kind="blocked", outcome="blocked", reason="550 no such user",
                            sender="alice@example.com", recipient="bob@example.com", subject="Hello",
                            log_lines=[{"time": "2026-10-29T10:00:00Z", "program": "postfix/smtp",
                                       "message": "status=bounced"}]))
    admin = _admin()
    outbound_only = _person(admin, "outbound-only", views=("outbound",))
    event = outbound_only.get(f"/api/suppressions/{suppression.id}/events").json()["events"][0]
    assert (event["sender"], event["subject"], event["log_lines"]) == (None, None, [])
    assert event["recipient"] == "bob@example.com" and event["reason"] == "550 no such user"
    both = _person(admin, "both", views=("outbound", "messages"))
    assert both.get(f"/api/suppressions/{suppression.id}/events").json()["events"][0]["subject"] == "Hello"


def test_settings_info_keeps_settings_and_accounts_for_admins(people, monkeypatch):
    inner = settings._inner
    for key, value in (("smtp_enabled", True), ("smtp_host", "smtp.example.com"), ("smtp_user", "alerts@example.com"),
                       ("smtp_from", "alerts@example.com"), ("admin_email", "admin@example.com"),
                       ("dmarc_imap_enabled", True), ("dmarc_imap_host", "imap.example.com"),
                       ("dmarc_imap_user", "reports@example.com"), ("edit_settings_via_ui_enabled", True)):
        monkeypatch.setattr(inner, key, value)
    admin = _admin()
    viewer = _person(admin, "status-only", views=("status",)).get("/api/settings/info").json()
    assert "editable_config" not in viewer and "default_config" not in viewer
    assert viewer["configuration"]["auth_username"] is None
    hidden = ("host", "port", "user", "from_address", "admin_email")
    assert {k: viewer["smtp_configuration"][k] for k in hidden} == dict.fromkeys(hidden)
    assert viewer["smtp_configuration"]["enabled"] is True
    assert (viewer["dmarc_configuration"]["imap_host"], viewer["dmarc_configuration"]["imap_user"]) == (None, None)
    assert "import_status" in viewer and "background_jobs" in viewer
    full = admin.get("/api/settings/info").json()
    assert full["smtp_configuration"]["host"] == "smtp.example.com" and "editable_config" in full
    assert full["dmarc_configuration"]["imap_user"] == "reports@example.com"
    assert full["configuration"]["auth_username"] == ADMIN_NAME


# ── Round 2: saved and in-force sign-in, IMAP account, job errors, OAuth2 streams ──

def test_an_admin_counts_only_when_usable_both_as_saved_and_in_force(oauth2, monkeypatch):
    """A save turned Basic Auth on with a password and committed, but its reload failed: Basic is
    still off in force, so the built-in admin cannot sign in and does not count."""
    from app.database import get_db_context
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    _store_default("none")
    with get_db_context() as db:
        row = users_store.create_user(db, kind="oauth2", username=None, email="carol@example.com", password=None,
                                      access_level="admin", views=(), acts=(), disabled=False)
    saved = settings._inner.model_copy(update={"basic_auth_enabled": True})
    monkeypatch.setattr(users_store, "build_settings", lambda db: saved)
    with get_db_context() as db:
        with pytest.raises(users_store.UserError) as refused:
            users_store.update_user(db, row["id"], access_level="viewer", views=(), acts=(), disabled=False,
                                    password=None, row_version=row["row_version"])
    assert refused.value.status == 409 and refused.value.detail == users_store.NO_ADMIN_LEFT


def test_a_local_user_cannot_take_the_in_force_admin_name_either(people, monkeypatch):
    saved = settings._inner.model_copy(update={"auth_username": "root"})
    monkeypatch.setattr(users_store, "build_settings", lambda db: saved)
    admin = _admin()
    for name in ("root", ADMIN_NAME):
        r = admin.post("/api/users", json={"kind": "local", "username": name, "password": PASSWORD,
                                           "access": "viewer"})
        assert r.status_code == 409, name


def test_imap_status_shows_the_account_only_to_who_may_read_settings(people, monkeypatch):
    for key, value in (("dmarc_imap_enabled", True), ("dmarc_imap_host", "imap.example.com"),
                       ("dmarc_imap_user", "reports@example.com"), ("dmarc_imap_folder", "DMARC")):
        monkeypatch.setattr(settings._inner, key, value)
    admin = _admin()
    viewer = _person(admin, "dmarc-only", views=("dmarc",)).get("/api/dmarc/imap/status").json()
    assert viewer["enabled"] is True
    assert {k: viewer["configuration"][k] for k in ("host", "port", "user", "folder")} == dict.fromkeys(
        ("host", "port", "user", "folder"))
    assert viewer["configuration"]["interval_minutes"] is not None
    full = admin.get("/api/dmarc/imap/status").json()["configuration"]
    assert (full["host"], full["user"], full["folder"]) == ("imap.example.com", "reports@example.com", "DMARC")


LEAKY_ERROR = "IMAP connection refused by imap.example.com:993 for reports@example.com"


def test_job_errors_name_no_settings_for_who_may_not_read_them(people, stored, monkeypatch):
    from datetime import datetime
    from app import raw_logs_worker, scheduler
    from app.models import DMARCSync
    monkeypatch.setattr(settings._inner, "dmarc_imap_enabled", True)
    monkeypatch.setitem(scheduler.job_status, "dmarc_imap_sync",
                        {"status": "failed", "last_run": datetime.utcnow(), "error": LEAKY_ERROR})
    raw_job = next(iter(raw_logs_worker.raw_logs_job_status))
    monkeypatch.setitem(raw_logs_worker.raw_logs_job_status, raw_job,
                        {**raw_logs_worker.raw_logs_job_status[raw_job], "error": LEAKY_ERROR})
    stored(DMARCSync(sync_type="auto", status="failed", started_at=datetime.utcnow(), error_message=LEAKY_ERROR,
                     failed_emails=[{"email_id": "1", "message_id": "<r1@example.com>", "subject": "Report",
                                     "error": LEAKY_ERROR}]))
    admin = _admin()
    person = _person(admin, "no-settings", views=("status", "dmarc", "logs"))
    answers = {
        "info": lambda c: c.get("/api/settings/info").json()["background_jobs"]["dmarc_imap_sync"]["error"],
        "imap status": lambda c: c.get("/api/dmarc/imap/status").json()["latest_sync"]["error_message"],
        "imap history": lambda c: c.get("/api/dmarc/imap/history").json()["data"][0]["error_message"],
        "imap failed email": lambda c: c.get("/api/dmarc/imap/history").json()["data"][0]["failed_emails"][0]["error"],
        "raw logs": lambda c: c.get("/api/raw-logs/worker-status").json()["jobs"][raw_job]["error"],
    }
    for name, read in answers.items():
        assert read(person) == "The last run failed.", name
        assert read(admin) == LEAKY_ERROR, name


def test_a_disabled_oauth2_entry_is_refused_on_its_next_request_and_its_stream_closes(oauth2, monkeypatch):
    monkeypatch.setattr(raw_logs, "WS_ACCESS_CHECK_SECONDS", 0)
    admin = _admin()
    row = _add(admin, "carol@example.com", access="custom", views=("logs", "messages"), kind="oauth2")
    carol = _oauth2_client("carol@example.com")
    stream = _oauth2_client("carol@example.com")
    token = stream.get("/api/raw-logs/ws-token").json()["token"]
    with stream.websocket_connect(f"/ws/raw-logs?token={token}", headers={"Origin": APP}) as ws:
        assert ws.receive_json()["type"] == "connected"
        assert _change(admin, row, disabled=True).status_code == 200
        # Nothing ends the sessions at once; each is refused when it is next used
        assert len(session_module._session_store) == 3
        ws.portal.call(raw_logs.log_stream_manager.broadcast, "postfix", [{"message": "after"}])
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
    assert closed.value.code == raw_logs.WS_SESSION_ENDED
    _ended(carol.get("/api/messages"))


# ── Round 3: each sign-in reading checked on its own ───────────────────────

def test_a_demotion_needs_an_admin_under_the_reading_in_force(oauth2, monkeypatch):
    """A save switched to Basic with a password and OAuth2 off, but its reload failed: OAuth2 is
    still the only sign-in in force, so its last admin cannot be demoted."""
    from app.database import get_db_context
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    _store_default("none")
    with get_db_context() as db:
        row = users_store.create_user(db, kind="oauth2", username=None, email="carol@example.com", password=None,
                                      access_level="admin", views=(), acts=(), disabled=False)
    saved = settings._inner.model_copy(update={"basic_auth_enabled": True, "oauth2_enabled": False})
    monkeypatch.setattr(users_store, "build_settings", lambda db: saved)
    with get_db_context() as db:
        with pytest.raises(users_store.UserError) as refused:
            users_store.update_user(db, row["id"], access_level="viewer", views=(), acts=(), disabled=False,
                                    password=None, row_version=row["row_version"])
    assert refused.value.status == 409
    with get_db_context() as db:
        with pytest.raises(users_store.UserError):
            users_store.delete_user(db, row["id"])


def test_a_demotion_with_another_admin_under_both_readings_passes(oauth2, monkeypatch):
    from app.database import get_db_context
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    _store_default("none")
    with get_db_context() as db:
        first = users_store.create_user(db, kind="oauth2", username=None, email="carol@example.com", password=None,
                                        access_level="admin", views=(), acts=(), disabled=False)
    with get_db_context() as db:
        users_store.create_user(db, kind="oauth2", username=None, email="dave@example.com", password=None,
                                access_level="admin", views=(), acts=(), disabled=False)
    saved = settings._inner.model_copy(update={"basic_auth_enabled": True})
    monkeypatch.setattr(users_store, "build_settings", lambda db: saved)
    with get_db_context() as db:
        changed = users_store.update_user(db, first["id"], access_level="viewer", views=(), acts=(), disabled=False,
                                          password=None, row_version=first["row_version"])
    assert changed["access"] == "viewer"


def test_a_settings_save_counts_the_reading_in_force_before_it(oauth2, monkeypatch):
    """In force: OAuth2 only with an admin entry; as saved: Basic without a password, so no admin there.
    A save that keeps that leaves nobody who can sign in, whatever the saved reading had before."""
    from app.database import get_db_context
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    _store_default("none")
    with get_db_context() as db:
        users_store.create_user(db, kind="oauth2", username=None, email="carol@example.com", password=None,
                                access_level="admin", views=(), acts=(), disabled=False)
    before = settings._inner.model_copy(update={"basic_auth_enabled": True, "auth_password": "",
                                                "oauth2_enabled": False})
    with get_db_context() as db:
        with pytest.raises(users_store.UserError):
            users_store.check_sign_in_settings(db, before, {"auth_username": "root"})
