"""Agent access: an AI agent connects after a signed-in person approves it.

Covers the whole path an agent takes (registration, the authorize request,
the consent API, the token exchange and refresh, the MCP endpoint and the
calls it makes into the app) and the rules around it: what is never offered,
which route the policy is checked against, when everything answers 404,
single use of codes and refresh tokens, and disconnecting every agent when
sign-in settings change.
"""
import asyncio
import base64
import hashlib
import secrets
import threading
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app import session as session_module  # noqa: E402
from app.agent_access import cimd, dispatch, live, mcp, oauth, pending, scopes, store  # noqa: E402
from app.agent_access.context import AgentCall  # noqa: E402
from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402

USERNAME = "admin"
PASSWORD = "correct horse battery staple"
APP_URL = "https://logs.example.com"
REDIRECT = "http://127.0.0.1:53682/callback"
BASIC = "Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _wipe():
    from app.database import get_db_context
    from app.models import AgentAudit, AgentClient, AgentCode, AgentGrant, AgentToken, SystemSetting
    with get_db_context() as db:
        for model in (AgentAudit, AgentToken, AgentCode, AgentGrant, AgentClient):
            db.query(model).delete(synchronize_session=False)
        db.query(SystemSetting).filter(SystemSetting.key == store._FINGERPRINT_KEY).delete(synchronize_session=False)


@pytest.fixture
def live_agents(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db
    init_db()
    inner = settings._inner
    monkeypatch.setattr(inner, "basic_auth_enabled", True)
    monkeypatch.setattr(inner, "auth_enabled", False)
    monkeypatch.setattr(inner, "oauth2_enabled", False)
    monkeypatch.setattr(inner, "auth_username", USERNAME)
    monkeypatch.setattr(inner, "auth_password", PASSWORD)
    monkeypatch.setattr(inner, "agent_access_enabled", True)
    monkeypatch.setattr(inner, "agent_access_url", APP_URL)
    monkeypatch.setattr(inner, "agent_access_max_days", 90)
    monkeypatch.setattr(store, "_known_fingerprint", None)
    for window in (oauth.registrations, oauth.token_requests, mcp.failed_tokens):
        monkeypatch.setattr(window, "_events", type(window._events)())
    pending.clear()
    _wipe()
    yield
    pending.clear()
    session_module._session_store.clear()
    _wipe()


def _client() -> TestClient:
    return TestClient(app)


def _signed_in() -> TestClient:
    client = _client()
    assert client.post("/api/auth/session", headers={"Authorization": BASIC}).status_code == 200
    return client


def _pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _register(client, uris=(REDIRECT,), name="Test Agent"):
    r = client.post("/oauth/register", json={"client_name": name, "redirect_uris": list(uris),
                                             "grant_types": ["authorization_code", "refresh_token"],
                                             "token_endpoint_auth_method": "none"})
    assert r.status_code == 201, r.text
    return r.json()["client_id"]


def _authorize(client, client_id, challenge, redirect=REDIRECT, state="s-123", scope=None, **extra):
    params = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect,
              "code_challenge": challenge, "code_challenge_method": "S256", "state": state,
              "resource": APP_URL + "/mcp", **extra}
    if scope:
        params["scope"] = scope
    return client.get("/oauth/authorize", params=params, follow_redirects=False)


def _request_id(response) -> str:
    assert response.status_code == 302, response.text
    location = response.headers["location"]
    assert location.startswith("/oauth/consent?request=")
    return location.split("=", 1)[1]


def _connect(views=("security",), acts=(), days=7, client=None):
    """The full flow; returns (browser client, client_id, tokens)."""
    client = client or _signed_in()
    client_id = _register(client)
    verifier, challenge = _pkce()
    request_id = _request_id(_authorize(client, client_id, challenge))
    answer = client.post(f"/api/agents/consent/{request_id}", json={
        "allow": True, "name": "My agent", "views": list(views), "acts": list(acts), "days": days})
    assert answer.status_code == 200, answer.text
    query = parse_qs(urlsplit(answer.json()["redirect"]).query)
    tokens = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": query["code"][0], "client_id": client_id,
        "redirect_uri": REDIRECT, "code_verifier": verifier, "resource": APP_URL + "/mcp"})
    assert tokens.status_code == 200, tokens.text
    return client, client_id, tokens.json()


def _mcp(client, token, method, params=None, id_=1, modern=False, headers=None):
    body = {"jsonrpc": "2.0", "method": method, "params": dict(params or {})}
    if id_ is not None:
        body["id"] = id_
    h = {"Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream"}
    if modern:
        body["params"]["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                   "io.modelcontextprotocol/clientInfo": {"name": "t", "version": "1"},
                                   "io.modelcontextprotocol/clientCapabilities": {}}
        h.update({"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method})
        if method == "tools/call":
            h["Mcp-Name"] = body["params"]["name"]
    h.update(headers or {})
    return client.post("/mcp", json=body, headers=h)


def _tool(client, token, name, arguments=None):
    r = _mcp(client, token, "tools/call", {"name": name, "arguments": arguments or {}})
    assert r.status_code == 200, r.text
    return r.json()["result"]


# ── The policy ─────────────────────────────────────────────────────────────

def _api_routes():
    from conftest import registered_routes
    out = set()
    for route in registered_routes(app):
        path, methods = getattr(route, "path", ""), getattr(route, "methods", None)
        if path.startswith("/api/") and methods:
            out.update((m, path) for m in methods if m != "HEAD")
    return out


def test_every_api_route_is_decided_once():
    routes = _api_routes()
    undecided = sorted(r for r in routes if r not in scopes.POLICY and not scopes.excluded_reason(*r))
    assert not undecided, f"add these to agent_access/scopes.py POLICY or EXCLUDED: {undecided}"
    both = sorted(r for r in scopes.POLICY if scopes.excluded_reason(*r))
    assert not both
    stale = sorted(r for r in list(scopes.POLICY) + list(scopes.EXCLUDED) if r not in routes)
    assert not stale, f"no such routes: {stale}"


def test_people_only_routes_are_never_offered():
    for key in [("PUT", "/api/settings"), ("POST", "/api/settings/jobs/{job_name}/run"),
                ("GET", "/api/raw-logs/ws-token"), ("POST", "/api/auth/session"),
                ("POST", "/api/notifications/channels"), ("POST", "/api/dmarc/upload")]:
        assert scopes.excluded_reason(*key), key
    for method, path in _api_routes():
        if path.startswith("/api/agents"):
            assert scopes.excluded_reason(method, path)


def test_sign_in_keys_match_the_session_bound_settings():
    from app.routers.settings import _SESSION_BOUND_SETTING_KEYS
    assert tuple(store.SIGN_IN_KEYS) == tuple(_SESSION_BOUND_SETTING_KEYS)


def _sign_in_state(monkeypatch, *, agents=False, basic=False, oauth=False, legacy=False, locked=()):
    from app.routers import settings as settings_router
    for key, value in (("agent_access_enabled", agents), ("basic_auth_enabled", basic),
                       ("oauth2_enabled", oauth), ("auth_enabled", legacy)):
        monkeypatch.setattr(settings._inner, key, value)
    monkeypatch.setattr(settings_router, "get_env_locked_keys", lambda: set(locked))
    return settings_router._validate_agent_access


@pytest.mark.parametrize("state, payload", [
    ({}, {"agent_access_enabled": True}),
    ({}, {"agent_access_enabled": "true", "basic_auth_enabled": False}),
    ({"agents": True, "basic": True}, {"basic_auth_enabled": False}),
    ({"agents": True, "oauth": True}, {"oauth2_enabled": False, "agent_access_enabled": True}),
])
def test_agent_access_cannot_be_on_without_sign_in(monkeypatch, state, payload):
    from fastapi import HTTPException
    validate = _sign_in_state(monkeypatch, **state)
    with pytest.raises(HTTPException) as refused:
        validate(dict(payload))
    assert refused.value.status_code == 400
    assert "Basic Auth or OAuth2" in refused.value.detail


@pytest.mark.parametrize("state, payload", [
    ({}, {"agent_access_enabled": True, "basic_auth_enabled": True}),
    ({}, {"agent_access_enabled": True, "oauth2_enabled": True}),
    ({"legacy": True}, {"agent_access_enabled": True}),
    ({"agents": True, "basic": True}, {"basic_auth_enabled": False, "agent_access_enabled": False}),
    ({"agents": True, "basic": True}, {"basic_auth_enabled": False, "oauth2_enabled": True}),
    # Already like this (from .env): saving the other settings still works
    ({"agents": True}, {"agent_access_enabled": True, "app_title": "Logs"}),
    # A key set in .env is not changed by the form
    ({"locked": ("agent_access_enabled",)}, {"agent_access_enabled": True}),
])
def test_agent_access_saves_that_keep_sign_in(monkeypatch, state, payload):
    _sign_in_state(monkeypatch, **state)(dict(payload))


def test_act_never_starts_ticked_and_act_includes_view():
    asked = scopes.parse_scopes("security:write messages:read bogus")
    assert asked == frozenset({"security:write", "messages:read"})
    assert set(scopes.requested_views(asked)) == {"security", "messages"}
    assert scopes.requested_views(frozenset()) == tuple(a.id for a in scopes.AREAS)
    assert scopes.grant_scopes([], ["security", "messages"]) == "security:read security:write"


# ── Live or 404 ────────────────────────────────────────────────────────────

AGENT_PATHS = ["/mcp", "/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-authorization-server",
               "/oauth/authorize", "/oauth/consent"]


@pytest.mark.parametrize("change", [
    ("agent_access_enabled", False), ("basic_auth_enabled", False), ("agent_access_url", ""),
    ("agent_access_url", "http://logs.example.com"), ("agent_access_url", "https://logs.example.com/app"),
])
def test_everything_answers_404_unless_live(live_agents, monkeypatch, change):
    monkeypatch.setattr(settings._inner, *change)
    client = _signed_in() if settings.is_authentication_enabled else _client()
    for path in AGENT_PATHS:
        assert client.get(path, follow_redirects=False).status_code == 404, path
    assert client.post("/oauth/token", data={}).status_code == 404


def test_loopback_http_address_is_accepted_for_local_tests():
    assert live.normalize_base_url("http://127.0.0.1:8099/") == "http://127.0.0.1:8099"
    assert live.normalize_base_url("HTTPS://Logs.Example.com:443") == "https://logs.example.com"
    assert live.normalize_base_url("http://192.0.2.10") is None
    assert live.normalize_base_url("https://user@logs.example.com") is None


def test_discovery_documents_name_the_configured_address(live_agents):
    client = _client()
    prm = client.get("/.well-known/oauth-protected-resource/mcp", headers={"Host": "evil.example"}).json()
    assert prm["resource"] == APP_URL + "/mcp" and prm["authorization_servers"] == [APP_URL]
    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["issuer"] == APP_URL
    assert meta["code_challenge_methods_supported"] == ["S256"]
    assert meta["authorization_response_iss_parameter_supported"] is True
    assert meta["client_id_metadata_document_supported"] is True


# ── Authorize and consent ──────────────────────────────────────────────────

def test_signed_out_authorize_goes_to_the_login_page(live_agents):
    r = _client().get("/oauth/authorize?client_id=x", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith("/login?next=")


def test_bad_client_or_redirect_is_shown_never_redirected(live_agents):
    client = _signed_in()
    client_id = _register(client)
    _, challenge = _pkce()
    r = _authorize(client, "mlvc_unknown", challenge)
    assert r.status_code == 400 and "location" not in r.headers
    r = _authorize(client, client_id, challenge, redirect="https://attacker.example/cb")
    assert r.status_code == 400 and "location" not in r.headers
    r = _authorize(client, client_id, challenge, redirect="http://127.0.0.1:9/other")
    assert r.status_code == 400


def test_errors_after_the_redirect_check_go_back_with_state_and_iss(live_agents):
    client = _signed_in()
    client_id = _register(client)
    r = _authorize(client, client_id, "short", state="keep-me")
    q = parse_qs(urlsplit(r.headers["location"]).query)
    assert q["error"] == ["invalid_request"] and q["state"] == ["keep-me"] and q["iss"] == [APP_URL]
    _, challenge = _pkce()
    r = _authorize(client, client_id, challenge, resource="https://other.example/mcp")
    assert parse_qs(urlsplit(r.headers["location"]).query)["error"] == ["invalid_target"]


def test_loopback_redirect_may_change_only_the_port(live_agents):
    assert oauth.redirect_matches([REDIRECT], "http://127.0.0.1:1234/callback")
    assert not oauth.redirect_matches([REDIRECT], "http://localhost:1234/callback")
    assert not oauth.redirect_matches([REDIRECT], "http://127.0.0.1:1234/callback?x=1")
    assert not oauth.redirect_matches(["https://app.example/cb"], "https://app.example:8443/cb")
    assert oauth.valid_redirect_uri("com.example.agent:/cb")
    assert not oauth.valid_redirect_uri("javascript:alert(1)")
    assert not oauth.valid_redirect_uri("http://192.0.2.1/cb")
    assert oauth.with_params("https://a.example/cb?x=1", {"code": "c", "state": None}) == "https://a.example/cb?x=1&code=c"


def test_consent_belongs_to_the_session_that_opened_it(live_agents):
    owner = _signed_in()
    client_id = _register(owner)
    _, challenge = _pkce()
    request_id = _request_id(_authorize(owner, client_id, challenge, scope="security:write"))
    details = owner.get(f"/api/agents/consent/{request_id}").json()
    assert details["preselected_views"] == ["security"]
    assert details["client"]["kind"] == "dcr" and details["client"]["publisher"] is None
    other = _signed_in()
    assert other.get(f"/api/agents/consent/{request_id}").status_code == 404
    assert other.post(f"/api/agents/consent/{request_id}", json={"allow": True, "views": ["security"]}).status_code == 404


def test_deny_returns_access_denied_with_state(live_agents):
    client = _signed_in()
    client_id = _register(client)
    _, challenge = _pkce()
    request_id = _request_id(_authorize(client, client_id, challenge, state="st"))
    r = client.post(f"/api/agents/consent/{request_id}", json={"allow": False})
    q = parse_qs(urlsplit(r.json()["redirect"]).query)
    assert q["error"] == ["access_denied"] and q["state"] == ["st"] and q["iss"] == [APP_URL]
    assert client.post(f"/api/agents/consent/{request_id}", json={"allow": False}).status_code == 404


def test_allowing_nothing_keeps_the_request_open(live_agents):
    client = _signed_in()
    client_id = _register(client)
    _, challenge = _pkce()
    request_id = _request_id(_authorize(client, client_id, challenge))
    assert client.post(f"/api/agents/consent/{request_id}", json={"allow": True}).status_code == 400
    assert client.get(f"/api/agents/consent/{request_id}").status_code == 200


def test_period_is_capped_by_the_maximum(live_agents, monkeypatch):
    monkeypatch.setattr(settings._inner, "agent_access_max_days", 3)
    client, _, tokens = _connect(days=365)
    from app.database import get_db_context
    from app.models import AgentGrant
    with get_db_context() as db:
        grant = db.query(AgentGrant).one()
        assert grant.expires_at - grant.created_at <= timedelta(days=3, minutes=1)
        assert grant.approved_by == USERNAME and grant.display_name == "My agent"


# ── Tokens ─────────────────────────────────────────────────────────────────

def test_token_answer_carries_the_granted_scopes(live_agents):
    _, _, tokens = _connect(views=("messages",), acts=("security",))
    assert tokens["scope"] == "messages:read security:read security:write"
    assert tokens["token_type"] == "Bearer" and tokens["refresh_token"].startswith("mlvr_")


def test_wrong_verifier_does_not_spend_the_code(live_agents):
    client = _signed_in()
    client_id = _register(client)
    verifier, challenge = _pkce()
    request_id = _request_id(_authorize(client, client_id, challenge))
    code = parse_qs(urlsplit(client.post(f"/api/agents/consent/{request_id}", json={
        "allow": True, "views": ["security"]}).json()["redirect"]).query)["code"][0]
    form = {"grant_type": "authorization_code", "code": code, "client_id": client_id, "redirect_uri": REDIRECT}
    assert client.post("/oauth/token", data={**form, "code_verifier": "x" * 43}).json()["error"] == "invalid_grant"
    assert client.post("/oauth/token", data={**form, "code_verifier": verifier}).status_code == 200
    # The same code again, with every binding right: it leaked, so the grant ends
    again = client.post("/oauth/token", data={**form, "code_verifier": verifier})
    assert again.json()["error"] == "invalid_grant"
    assert client.get("/api/agents").json()["agents"][0]["state"] == "disconnected"


def test_two_exchanges_at_once_make_one_grant(live_agents):
    client = _signed_in()
    client_id = _register(client)
    verifier, challenge = _pkce()
    request_id = _request_id(_authorize(client, client_id, challenge))
    code = parse_qs(urlsplit(client.post(f"/api/agents/consent/{request_id}", json={
        "allow": True, "views": ["security"]}).json()["redirect"]).query)["code"][0]
    from app.database import SessionLocal
    results, barrier = [], threading.Barrier(2)

    def exchange():
        db = SessionLocal()
        try:
            barrier.wait()
            results.append(store.exchange_code(db, code=code, client_id=client_id, redirect_uri=REDIRECT,
                                               verifier=verifier, resource=None))
        except store.TokenError as e:
            results.append(e)
        finally:
            db.close()
    threads = [threading.Thread(target=exchange) for _ in range(2)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sum(isinstance(r, dict) for r in results) == 1


def test_refresh_rotates_and_a_reused_refresh_disconnects(live_agents):
    client, client_id, tokens = _connect()
    form = {"grant_type": "refresh_token", "client_id": client_id, "refresh_token": tokens["refresh_token"]}
    fresh = client.post("/oauth/token", data=form)
    assert fresh.status_code == 200 and fresh.json()["refresh_token"] != tokens["refresh_token"]
    assert _mcp(client, tokens["access_token"], "ping").status_code == 401
    assert _mcp(client, fresh.json()["access_token"], "ping").status_code == 200
    assert client.post("/oauth/token", data=form).json()["error"] == "invalid_grant"
    assert _mcp(client, fresh.json()["access_token"], "ping").status_code == 401


def test_refresh_never_changes_the_granted_scopes(live_agents):
    # Clients repeat the scope they first asked for; the answer is what the person granted
    client, client_id, tokens = _connect(views=("security",))
    r = client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": client_id,
                                          "refresh_token": tokens["refresh_token"],
                                          "scope": "security:write messages:read"})
    assert r.status_code == 200 and r.json()["scope"] == "security:read"


def test_one_hour_lasts_an_hour(live_agents):
    _connect(days=1 / 24)
    from app.database import get_db_context
    from app.models import AgentGrant
    with get_db_context() as db:
        grant = db.query(AgentGrant).one()
        assert timedelta(minutes=59) < grant.expires_at - grant.created_at <= timedelta(hours=1, minutes=1)


def test_a_sign_in_change_after_consent_voids_the_code(live_agents, monkeypatch):
    client = _signed_in()
    client_id = _register(client)
    verifier, challenge = _pkce()
    request_id = _request_id(_authorize(client, client_id, challenge))
    code = parse_qs(urlsplit(client.post(f"/api/agents/consent/{request_id}", json={
        "allow": True, "views": ["security"]}).json()["redirect"]).query)["code"][0]
    monkeypatch.setattr(settings._inner, "auth_username", "someone-else")
    r = client.post("/oauth/token", data={"grant_type": "authorization_code", "code": code, "client_id": client_id,
                                          "redirect_uri": REDIRECT, "code_verifier": verifier})
    assert r.json()["error"] == "invalid_grant"


def test_a_consent_opened_before_a_sign_in_change_cannot_finish(live_agents, monkeypatch):
    client = _signed_in()
    client_id = _register(client)
    verifier, challenge = _pkce()
    request_id = _request_id(_authorize(client, client_id, challenge))
    monkeypatch.setattr(settings._inner, "auth_username", "someone-else")
    answer = client.post(f"/api/agents/consent/{request_id}", json={"allow": True, "views": ["security"]})
    if answer.status_code == 200:
        code = parse_qs(urlsplit(answer.json()["redirect"]).query)["code"][0]
        r = client.post("/oauth/token", data={"grant_type": "authorization_code", "code": code,
                                              "client_id": client_id, "redirect_uri": REDIRECT,
                                              "code_verifier": verifier})
        assert r.json()["error"] == "invalid_grant"
    from app.database import get_db_context
    from app.models import AgentGrant
    with get_db_context() as db:
        assert db.query(AgentGrant).filter(AgentGrant.revoked_at.is_(None)).count() == 0


def test_a_call_waiting_past_its_token_does_not_run(live_agents):
    client, client_id, tokens = _connect(acts=("security",))
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        grant = store.validate_access_token(db, tokens["access_token"])
    finally:
        db.close()
    # The agent refreshes meanwhile: the token the waiting call came with is gone
    assert client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": client_id,
                                             "refresh_token": tokens["refresh_token"]}).status_code == 200

    async def run():
        dispatch._slots = None
        return await dispatch.call_api(app, grant, "write", "POST", "/api/security-alerts/acknowledge-all",
                                       None, None, None)
    result = asyncio.run(run())
    assert result.outcome == "denied" and "ended" in result.text


def test_refresh_and_disconnect_at_once_never_deadlock(live_agents):
    from app.database import SessionLocal
    for _ in range(8):
        pending.clear()
        client, client_id, tokens = _connect()
        grant_id = client.get("/api/agents").json()["agents"][0]["id"]
        errors, barrier = [], threading.Barrier(2)

        def refresh():
            db = SessionLocal()
            try:
                barrier.wait()
                store.refresh_tokens(db, refresh_token=tokens["refresh_token"], client_id=client_id,
                                     scope=None, resource=None)
            except store.TokenError:
                pass
            except Exception as e:
                errors.append(e)
            finally:
                db.close()

        def disconnect():
            db = SessionLocal()
            try:
                barrier.wait()
                store.revoke_grant(db, grant_id)
            except Exception as e:
                errors.append(e)
            finally:
                db.close()
        threads = [threading.Thread(target=refresh), threading.Thread(target=disconnect)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert not errors, errors
        assert client.get("/api/agents").json()["agents"][0]["state"] == "disconnected"


def test_a_change_while_access_is_off_still_disconnects(live_agents, monkeypatch):
    client, _, tokens = _connect()
    monkeypatch.setattr(settings._inner, "agent_access_enabled", False)
    monkeypatch.setattr(settings._inner, "auth_password", "changed while off")
    monkeypatch.setattr(store, "_known_fingerprint", None)
    from app.main import log_agent_access_state
    log_agent_access_state()  # what startup runs
    monkeypatch.setattr(settings._inner, "auth_password", PASSWORD)
    monkeypatch.setattr(settings._inner, "agent_access_enabled", True)
    assert _mcp(_client(), tokens["access_token"], "ping").status_code == 401


def test_a_call_waiting_while_the_agent_is_disconnected_does_not_run(live_agents):
    client, _, tokens = _connect(acts=("security",))
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        grant = store.validate_access_token(db, tokens["access_token"])
    finally:
        db.close()
    agent_id = client.get("/api/agents").json()["agents"][0]["id"]
    assert client.delete(f"/api/agents/{agent_id}").status_code == 200

    async def run():
        dispatch._slots = None
        return await dispatch.call_api(app, grant, "write", "POST", "/api/security-alerts/acknowledge-all",
                                       None, None, None)
    result = asyncio.run(run())
    assert result.outcome == "denied" and "ended" in result.text


def test_revocation_disconnects_the_agent(live_agents):
    client, client_id, tokens = _connect()
    assert client.post("/oauth/revoke", data={"token": tokens["refresh_token"], "client_id": client_id}).status_code == 200
    assert _mcp(client, tokens["access_token"], "ping").status_code == 401


def test_a_sign_in_change_disconnects_for_good(live_agents, monkeypatch):
    client, _, tokens = _connect()
    assert _mcp(client, tokens["access_token"], "ping").status_code == 200
    monkeypatch.setattr(settings._inner, "auth_password", "a new password")
    assert _mcp(client, tokens["access_token"], "ping").status_code == 401
    monkeypatch.setattr(settings._inner, "auth_password", PASSWORD)
    assert _mcp(client, tokens["access_token"], "ping").status_code == 401


def test_a_new_address_ends_old_tokens(live_agents, monkeypatch):
    client, _, tokens = _connect()
    monkeypatch.setattr(settings._inner, "agent_access_url", "https://other.example.com")
    assert _mcp(client, tokens["access_token"], "ping").status_code == 401


def test_registration_limits(live_agents):
    client = _client()
    bad = client.post("/oauth/register", json={"redirect_uris": ["http://192.0.2.1/cb"]})
    assert bad.status_code == 400
    too_many = client.post("/oauth/register", json={"redirect_uris": [f"https://a.example/{i}" for i in range(11)]})
    assert too_many.status_code == 400
    huge = client.post("/oauth/register", content=b"{" + b" " * 20000 + b"}", headers={"Content-Type": "application/json"})
    assert huge.status_code == 413
    for _ in range(10):
        client.post("/oauth/register", json={"redirect_uris": [REDIRECT]})
    assert client.post("/oauth/register", json={"redirect_uris": [REDIRECT]}).status_code == 429


# ── MCP ────────────────────────────────────────────────────────────────────

def test_mcp_without_a_token_points_to_the_metadata(live_agents):
    r = _client().post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert r.status_code == 401
    assert r.headers["www-authenticate"].startswith(
        f'Bearer resource_metadata="{APP_URL}/.well-known/oauth-protected-resource/mcp"')


def test_mcp_ignores_session_cookies(live_agents):
    client = _signed_in()
    assert client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}).status_code == 401


def test_legacy_handshake_and_tools(live_agents):
    client, _, tokens = _connect(views=("security",))
    token = tokens["access_token"]
    init = _mcp(client, token, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                              "clientInfo": {"name": "t", "version": "1"}})
    assert init.json()["result"]["protocolVersion"] == "2025-06-18"
    assert "Mcp-Session-Id" not in init.headers
    old = _mcp(client, token, "initialize", {"protocolVersion": "2025-03-26"})
    assert old.json()["result"]["protocolVersion"] == "2025-11-25"
    assert _mcp(client, token, "notifications/initialized", id_=None).status_code == 202
    names = [t["name"] for t in _mcp(client, token, "tools/list").json()["result"]["tools"]]
    assert names == ["get_access", "list_endpoints", "read_api"]
    assert _mcp(client, token, "nope").json()["error"]["code"] == -32601


def test_modern_requests_and_header_checks(live_agents):
    client, _, tokens = _connect(acts=("security",))
    token = tokens["access_token"]
    discover = _mcp(client, token, "server/discover", modern=True)
    assert discover.status_code == 200
    result = discover.json()["result"]
    assert result["resultType"] == "complete" and "2026-07-28" in result["supportedVersions"]
    listed = _mcp(client, token, "tools/list", modern=True).json()["result"]
    assert [t["name"] for t in listed["tools"]][-1] == "perform_action"
    wrong = _mcp(client, token, "tools/list", modern=True, headers={"Mcp-Method": "tools/call"})
    assert wrong.status_code == 400 and wrong.json()["error"]["code"] == -32020
    name = _mcp(client, token, "tools/call", {"name": "get_access"}, modern=True,
                headers={"Mcp-Name": "=?base64?" + base64.b64encode(b"list_endpoints").decode() + "?="})
    assert name.json()["error"]["code"] == -32020
    version = _mcp(client, token, "tools/list", modern=True,
                   headers={"MCP-Protocol-Version": "1900-01-01"})
    assert version.status_code == 400
    unknown = _mcp(client, token, "resources/list", modern=True)
    assert unknown.status_code == 404 and unknown.json()["error"]["code"] == -32601


def test_batches_and_other_methods(live_agents):
    client, _, tokens = _connect()
    h = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert client.post("/mcp", json=[{"jsonrpc": "2.0", "id": 1, "method": "ping"}], headers=h).status_code == 400
    assert client.get("/mcp", headers=h).status_code == 405
    assert client.delete("/mcp", headers=h).status_code == 405


def test_get_access_and_list_endpoints_follow_the_grant(live_agents):
    client, _, tokens = _connect(views=("dmarc",), acts=("security",))
    token = tokens["access_token"]
    access = _tool(client, token, "get_access")
    assert '"security"' in access["content"][0]["text"] and '"messages"' in access["content"][0]["text"]
    listed = _tool(client, token, "list_endpoints", {"area": "security"})["content"][0]["text"]
    assert "/api/fail2ban/ban" in listed and '"ip"' in listed
    assert "/api/messages" not in _tool(client, token, "list_endpoints")["content"][0]["text"]


def test_read_api_runs_inside_the_app_and_is_logged(live_agents):
    client, _, tokens = _connect(views=("security",))
    result = _tool(client, tokens["access_token"], "read_api", {"path": "/api/security-alerts"})
    assert not result["isError"] and result["content"][0]["text"].startswith("HTTP 200")
    activity = client.get("/api/agents").json()["agents"][0]
    rows = client.get(f"/api/agents/{activity['id']}/activity").json()["activity"]
    assert any(r["event"] == "call" and r["path"] == "/api/security-alerts" for r in rows)


def test_permissions_are_checked_on_the_route_the_app_picks(live_agents):
    client, _, tokens = _connect(views=("security", "logs"))
    token = tokens["access_token"]
    # /api/raw-logs/{service} would match, but the app runs the ws-token route
    ws = _tool(client, token, "read_api", {"path": "/api/raw-logs/ws-token"})
    assert ws["isError"] and "Not available to agents" in ws["content"][0]["text"]
    other = _tool(client, token, "read_api", {"path": "/api/messages"})
    assert other["isError"] and "messages:read" in other["content"][0]["text"]
    act = _tool(client, token, "read_api", {"method": "POST", "path": "/api/security-alerts/acknowledge-all"})
    assert act["isError"] and "perform_action" in act["content"][0]["text"]
    assert _tool(client, token, "perform_action", {"method": "POST", "path": "/api/fail2ban/ban"})["isError"]
    for path in ("/api/../login", "/api/messages?x=1", "/mcp", "/api/%2e%2e/x"):
        assert _tool(client, token, "read_api", {"path": path})["isError"], path
    rows = client.get(f"/api/agents/{client.get('/api/agents').json()['agents'][0]['id']}/activity").json()["activity"]
    assert any(r["event"] == "denied" for r in rows)


def test_perform_action_with_act(live_agents):
    client, _, tokens = _connect(acts=("security",))
    result = _tool(client, tokens["access_token"], "perform_action",
                   {"method": "POST", "path": "/api/security-alerts/acknowledge-all"})
    assert not result["isError"], result


def test_dns_check_only_for_own_domains(live_agents):
    client, _, tokens = _connect(acts=("domains",))
    result = _tool(client, tokens["access_token"], "perform_action",
                   {"method": "GET", "path": "/api/domains/attacker.example/dns-check"})
    assert result["isError"] and "not one of this mail server's domains" in result["content"][0]["text"]


def test_an_agent_cannot_reach_the_agents_api(live_agents):
    client, _, tokens = _connect(views=("settings",))
    result = _tool(client, tokens["access_token"], "read_api", {"path": "/api/agents"})
    assert result["isError"]


def test_a_forged_marker_is_not_honoured_over_http(live_agents):
    # Headers cannot set ASGI scope keys: without a session this is just unauthenticated
    r = _client().get("/api/security-alerts", headers={"mlv.agent": "1", "X-Mlv-Agent": "1"})
    assert r.status_code == 401


def test_management_lists_and_disconnects(live_agents):
    client, _, tokens = _connect()
    listing = client.get("/api/agents").json()
    assert listing["live"] and listing["mcp_url"] == APP_URL + "/mcp"
    agent = listing["agents"][0]
    assert agent["state"] == "connected" and agent["areas"] == {"security": "view"}
    assert client.delete(f"/api/agents/{agent['id']}").json() == {"disconnected": 1}
    assert _mcp(client, tokens["access_token"], "ping").status_code == 401
    assert _client().get("/api/agents").status_code == 401


# ── Dispatch limits ────────────────────────────────────────────────────────

def test_a_slot_is_held_until_background_work_ends():
    grant = store.GrantInfo(id=987654, name="t", client_id="c", scopes=frozenset(), expires_at=datetime.utcnow(),
                            publisher=None)
    release = None

    async def fake_app(scope, receive, send):
        scope[dispatch.SCOPE_KEY].checked = True
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b'{"status":"queued"}', "more_body": False})
        await release.wait()  # BackgroundTasks run after the answer

    async def run():
        nonlocal release
        release = asyncio.Event()
        dispatch._slots = None
        for _ in range(dispatch.SLOTS_PER_GRANT):
            result = await dispatch.call_api(fake_app, grant, "read", "GET", "/api/x", None, None, None)
            assert result.status == 200
        dispatch.SLOT_WAIT_SECONDS, saved = 0.05, dispatch.SLOT_WAIT_SECONDS
        try:
            with pytest.raises(dispatch.Busy):
                await dispatch.call_api(fake_app, grant, "read", "GET", "/api/x", None, None, None)
            release.set()
            await asyncio.sleep(0.01)
            assert (await dispatch.call_api(fake_app, grant, "read", "GET", "/api/x", None, None, None)).status == 200
        finally:
            dispatch.SLOT_WAIT_SECONDS = saved
    asyncio.run(run())


def test_a_route_that_skipped_the_check_is_refused():
    grant = store.GrantInfo(id=1, name="t", client_id="c", scopes=frozenset(), expires_at=datetime.utcnow(), publisher=None)

    async def unchecked_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"secret", "more_body": False})

    async def run():
        dispatch._slots = None
        return await dispatch.call_api(unchecked_app, grant, "read", "GET", "/api/x", None, None, None)
    result = asyncio.run(run())
    assert result.status == 403 and "secret" not in result.text


def test_a_long_answer_is_cut_while_streaming():
    grant = store.GrantInfo(id=2, name="t", client_id="c", scopes=frozenset(), expires_at=datetime.utcnow(), publisher=None)
    sent = 0

    async def streaming_app(scope, receive, send):
        nonlocal sent
        scope[dispatch.SCOPE_KEY].checked = True
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/csv")]})
        for _ in range(100):
            sent += 1
            await send({"type": "http.response.body", "body": b"x" * 65536, "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    async def run():
        dispatch._slots = None
        return await dispatch.call_api(streaming_app, grant, "read", "GET", "/api/x", None, None, None)
    result = asyncio.run(run())
    assert result.truncated and len(result.text) <= dispatch.MAX_RESULT_CHARS


# ── CIMD ───────────────────────────────────────────────────────────────────

DOC_URL = "https://agent.example/oauth/client.json"
GOOD_DOC = (b'{"client_id": "https://agent.example/oauth/client.json", "client_name": "Example Agent",'
            b' "redirect_uris": ["http://127.0.0.1/callback"], "token_endpoint_auth_method": "none"}')


@pytest.fixture
def fake_web(monkeypatch):
    seen = {}

    async def resolve(host):
        return "203.0.113.10"
    monkeypatch.setattr(cimd, "_resolve", resolve)
    monkeypatch.setattr(cimd, "_cache", {})
    monkeypatch.setattr(cimd, "_semaphore", None)
    answers = {}
    import httpx
    real_client = httpx.AsyncClient

    def handler(request):
        seen["url"], seen["host"] = str(request.url), request.headers.get("host")
        seen["sni"] = request.extensions.get("sni_hostname")
        return answers["response"]

    monkeypatch.setattr(cimd.httpx, "AsyncClient",
                        lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    return answers, seen


def test_cimd_document_is_fetched_from_the_vetted_address(fake_web):
    import httpx
    answers, seen = fake_web
    answers["response"] = httpx.Response(200, stream=httpx.ByteStream(GOOD_DOC), headers={"Content-Type": "application/json"})
    doc = asyncio.run(cimd.fetch(DOC_URL))
    assert doc.client_name == "Example Agent" and doc.publisher == "agent.example"
    assert seen["url"].startswith("https://203.0.113.10/") and seen["host"] == "agent.example"
    assert seen["sni"] == "agent.example"


@pytest.mark.parametrize("response_kwargs", [
    {"status_code": 302, "headers": {"Location": "https://169.254.169.254/"}},
    {"status_code": 200, "body": GOOD_DOC, "headers": {"Content-Encoding": "gzip"}},
    {"status_code": 200, "body": b" " * (cimd.MAX_BYTES + 1)},
    {"status_code": 200, "body": GOOD_DOC.replace(b"agent.example/oauth", b"other.example/oauth", 1)},
])
def test_cimd_refuses_bad_answers(fake_web, response_kwargs):
    import httpx
    answers, _ = fake_web
    kwargs = dict(response_kwargs)
    body = kwargs.pop("body", b"")
    answers["response"] = httpx.Response(stream=httpx.ByteStream(body), **kwargs)
    with pytest.raises(cimd.ClientDocumentError):
        asyncio.run(cimd.fetch(DOC_URL))


@pytest.mark.parametrize("url", ["http://agent.example/c.json", "https://agent.example/", "https://192.0.2.1/c.json",
                                 "https://agent.example:8443/c.json", "https://u@agent.example/c.json"])
def test_cimd_refuses_unsafe_addresses(url):
    with pytest.raises(cimd.ClientDocumentError):
        cimd._check_url(url)


@pytest.mark.parametrize("address", ["10.0.0.5", "127.0.0.1", "169.254.169.254", "100.64.0.1", "fec0::1",
                                     "fd00::1", "::1", "fe80::1", "::ffff:10.0.0.1", "2002:a00:1::1",
                                     "64:ff9b::a00:1", "ff02::1", "0.0.0.0"])
def test_cimd_treats_inside_addresses_as_inside(address):
    assert not cimd._public(address)


def test_cimd_gives_up_on_a_slow_server(fake_web, monkeypatch):
    import httpx
    answers, _ = fake_web

    class Drip(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(50):
                await asyncio.sleep(0.1)
                yield b" "

    answers["response"] = httpx.Response(200, stream=Drip())
    monkeypatch.setattr(cimd, "TIMEOUT_SECONDS", 0.5)
    with pytest.raises(cimd.ClientDocumentError, match="too long"):
        asyncio.run(cimd.fetch(DOC_URL))


def test_cimd_refuses_hosts_that_resolve_inside(monkeypatch):
    async def private(host, port, type=0):
        return [(2, 1, 6, "", ("10.0.0.5", 443))]
    loop = asyncio.new_event_loop()
    monkeypatch.setattr(loop, "getaddrinfo", private)
    try:
        with pytest.raises(cimd.ClientDocumentError):
            loop.run_until_complete(cimd._resolve("agent.example"))
    finally:
        loop.close()
