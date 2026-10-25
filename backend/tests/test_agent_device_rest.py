"""Agents that run commands (the skill): connect with a code, then call /api with a bearer token.

The agent asks for a code (RFC 8628) without a session; a signed-in person
opens the link on any device, compares the code and approves; the agent
collects its tokens once and calls /api under the same policy as MCP calls.
A bearer on /api is always an agent's request: a bad one never falls back to
a cookie or to sign-in being off. Tokens work only where they were issued
(the REST API or the MCP server).
"""
from datetime import datetime, timedelta

import pytest

from app.agent_access import oauth, scopes, store
from app.config import settings

from test_agent_access import (  # noqa: F401  (live_agents is a fixture)
    APP_URL, BASIC, PASSWORD, _client, _connect, _mcp, _request_id, _signed_in, live_agents,
)

DEVICE = "urn:ietf:params:oauth:grant-type:device_code"
CLIENT = "mailcow-logs-cli"
ALL_SCOPES = " ".join(scopes.all_scopes())


def _ask(client=None, label="Claude Code on DESK", **extra):
    client = client or _client()
    data = {"client_id": CLIENT, "client_label": label, "scope": ALL_SCOPES, "resource": APP_URL + "/api", **extra}
    return client.post("/oauth/device", data=data)


def _device(client=None, **extra):
    r = _ask(client, **extra)
    assert r.status_code == 200, r.text
    return r.json()


def _poll(client, device_code, client_id=CLIENT):
    return client.post("/oauth/token", data={"grant_type": DEVICE, "device_code": device_code, "client_id": client_id})


def _answer(user_code, views=("security",), acts=(), days=7, allow=True, browser=None):
    browser = browser or _signed_in()
    request_id = _request_id(browser.get("/oauth/device", params={"user_code": user_code}, follow_redirects=False))
    answer = browser.post(f"/api/agents/consent/{request_id}", json={
        "allow": allow, "name": "Approved on the phone", "views": list(views), "acts": list(acts), "days": days})
    assert answer.status_code == 200, answer.text
    assert answer.json() == {"done": True}
    return browser


def _connect_with_code(views=("security",), acts=(), days=7):
    agent = _client()
    d = _device(agent)
    browser = _answer(d["user_code"], views, acts, days)
    r = _poll(agent, d["device_code"])
    assert r.status_code == 200, r.text
    return agent, browser, r.json()


def _api(client, token, method, path, **kwargs):
    headers = {"Authorization": f"Bearer {token}", **kwargs.pop("headers", {})}
    return client.request(method, path, headers=headers, **kwargs)


def _rewind(field, **values):
    from app.database import get_db_context
    from app.models import AgentDeviceRequest
    with get_db_context() as db:
        db.query(AgentDeviceRequest).update(values, synchronize_session=False)


# ── Asking for a code ──────────────────────────────────────────────────────

def test_asking_for_a_code_needs_no_session_and_gives_a_short_code(live_agents):
    d = _device()
    assert d["verification_uri"] == APP_URL + "/oauth/device"
    assert d["verification_uri_complete"] == f"{APP_URL}/oauth/device?user_code={d['user_code']}"
    assert d["expires_in"] == 600 and d["interval"] == 5
    code = d["user_code"]
    assert len(code) == 9 and code[4] == "-" and all(c in store.USER_CODE_ALPHABET for c in code.replace("-", ""))
    assert d["device_code"].startswith("mlvd_")
    # The script's own name, shown as its word; anything but plain text is dropped
    from app.database import get_db_context
    from app.models import AgentDeviceRequest
    _device(label="<b>Claude</b>")
    with get_db_context() as db:
        assert sorted(r.label for r in db.query(AgentDeviceRequest)) == ["Claude Code on DESK", "Script"]


@pytest.mark.parametrize("change, error", [
    ({"client_id": "someone-else"}, "invalid_client"),
    ({"resource": APP_URL + "/mcp"}, "invalid_target"),
])
def test_asking_for_a_code_checks_the_client_and_resource(live_agents, change, error):
    r = _ask(**change)
    assert r.status_code in (400, 401) and r.json()["error"] == error


def test_asking_for_codes_is_limited_per_address(live_agents):
    for _ in range(oauth.device_requests.limit):
        assert _ask().status_code == 200
    assert _ask().status_code == 429


# ── The approval link ──────────────────────────────────────────────────────

def test_the_link_sends_a_signed_out_browser_to_sign_in_and_back(live_agents):
    d = _device()
    r = _client().get("/oauth/device", params={"user_code": d["user_code"]}, follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"].startswith("/login?next=%2Foauth%2Fdevice%3Fuser_code%3D")


def test_the_approval_page_shows_the_code_and_the_agents_own_name(live_agents):
    d = _device()
    browser = _signed_in()
    request_id = _request_id(browser.get("/oauth/device", params={"user_code": d["user_code"].lower().replace("-", "")},
                                         follow_redirects=False))
    page = browser.get(f"/api/agents/consent/{request_id}").json()
    assert page["client"]["user_code"] == d["user_code"]
    assert page["client"]["kind"] == "device" and page["client"]["declared_name"] == "Claude Code on DESK"
    assert page["client"]["redirect_uri"] is None
    # The request belongs to the session that opened it
    assert _signed_in().get(f"/api/agents/consent/{request_id}").status_code == 404


def test_a_wrong_code_is_refused_and_guesses_are_limited(live_agents):
    browser = _signed_in()
    r = browser.get("/oauth/device", params={"user_code": "BBBB-BBBB"}, follow_redirects=False)
    assert r.status_code == 404 and "not valid or has expired" in r.text
    assert browser.get("/oauth/device").status_code == 200   # the field to type it
    for _ in range(oauth.code_lookups.limit - 1):
        browser.get("/oauth/device", params={"user_code": "CCCC-CCCC"}, follow_redirects=False)
    d = _device()
    r = browser.get("/oauth/device", params={"user_code": d["user_code"]}, follow_redirects=False)
    assert r.status_code == 429


# ── Collecting the tokens ──────────────────────────────────────────────────

def test_the_agent_waits_then_collects_its_tokens_once(live_agents):
    agent = _client()
    d = _device(agent)
    r = _poll(agent, d["device_code"])
    assert r.status_code == 400 and r.json()["error"] == "authorization_pending"
    r = _poll(agent, d["device_code"])
    assert r.json()["error"] == "slow_down"
    _answer(d["user_code"], views=("security", "messages"), acts=("security",), days=30)
    r = _poll(agent, d["device_code"])
    assert r.status_code == 200, r.text
    tokens = r.json()
    assert set(tokens["scope"].split()) == {"security:read", "security:write", "messages:read"}
    assert _poll(agent, d["device_code"]).json()["error"] == "invalid_grant"
    from app.database import get_db_context
    from app.models import AgentGrant
    with get_db_context() as db:
        grant = db.query(AgentGrant).one()
        assert grant.client_kind == "device" and grant.resource == APP_URL + "/api"
        assert grant.declared_name == "Claude Code on DESK" and grant.display_name == "Approved on the phone"
        assert timedelta(days=29, hours=23) < grant.expires_at - datetime.utcnow() <= timedelta(days=30)


def test_a_denied_request_tells_the_agent_and_a_second_answer_changes_nothing(live_agents):
    agent = _client()
    d = _device(agent)
    browser = _answer(d["user_code"], allow=False)
    assert _poll(agent, d["device_code"]).json()["error"] == "access_denied"
    # The code no longer opens anything
    r = browser.get("/oauth/device", params={"user_code": d["user_code"]}, follow_redirects=False)
    assert r.status_code == 404


def test_an_expired_code_cannot_be_approved_or_collected(live_agents):
    agent = _client()
    d = _device(agent)
    _rewind("expires_at", expires_at=datetime.utcnow() - timedelta(seconds=1))
    r = _signed_in().get("/oauth/device", params={"user_code": d["user_code"]}, follow_redirects=False)
    assert r.status_code == 404
    assert _poll(agent, d["device_code"]).json()["error"] == "expired_token"


def test_a_sign_in_change_ends_an_approved_code_before_it_is_collected(live_agents, monkeypatch):
    agent = _client()
    d = _device(agent)
    _answer(d["user_code"])
    monkeypatch.setattr(settings._inner, "auth_password", "a new password")
    assert _poll(agent, d["device_code"]).json()["error"] == "expired_token"


def test_disconnect_all_ends_codes_waiting_for_a_person(live_agents):
    agent = _client()
    d = _device(agent)
    assert _signed_in().delete("/api/agents").status_code == 200
    assert _poll(agent, d["device_code"]).json()["error"] == "expired_token"


def test_unknown_device_codes_are_limited_but_known_polls_are_not(live_agents):
    agent = _client()
    for _ in range(oauth.unknown_device_codes.limit):
        assert _poll(agent, "mlvd_" + "x" * 43).json()["error"] == "invalid_grant"
    assert _poll(agent, "mlvd_" + "y" * 43).status_code == 429


def test_polling_does_not_use_the_token_budget(live_agents):
    agent = _client()
    d = _device(agent)
    for _ in range(oauth.token_requests.limit + 5):
        assert _poll(agent, d["device_code"]).status_code == 400
    # Refresh and code exchanges of other agents behind this address still work
    assert oauth.token_requests.full("testclient") is False


# ── Calling the API ────────────────────────────────────────────────────────

def test_a_read_in_an_allowed_area_runs_and_is_logged(live_agents):
    agent, browser, tokens = _connect_with_code(views=("security",))
    r = _api(agent, tokens["access_token"], "GET", "/api/security-alerts")
    assert r.status_code == 200, r.text
    activity = browser.get(f"/api/agents/{browser.get('/api/agents').json()['agents'][0]['id']}/activity").json()
    assert activity["activity"][0]["tool"] == "rest" and activity["activity"][0]["path"] == "/api/security-alerts"


def test_a_view_grant_does_not_allow_actions(live_agents):
    agent, _, tokens = _connect_with_code(views=("security", "domains"))
    token = tokens["access_token"]
    # A write without Take action
    r = _api(agent, token, "POST", "/api/security-alerts/acknowledge-all")
    assert r.status_code == 403 and r.json()["error"] == "forbidden"
    # A DNS check starts probes, so it is an action, not part of View
    r = _api(agent, token, "POST", "/api/domains/example.com/check-dns")
    assert r.status_code == 403 and "Take action" in r.json()["message"]
    # An area that was not allowed at all
    r = _api(agent, token, "GET", "/api/messages")
    assert r.status_code == 403


def test_an_allowed_action_runs(live_agents):
    agent, browser, tokens = _connect_with_code(views=("security",), acts=("security",))
    r = _api(agent, tokens["access_token"], "POST", "/api/security-alerts/acknowledge-all", json={"ids": [999999]})
    assert r.status_code == 200, r.text
    agent_id = browser.get("/api/agents").json()["agents"][0]["id"]
    row = browser.get(f"/api/agents/{agent_id}/activity").json()["activity"][0]
    assert (row["method"], row["path"], row["outcome"]) == ("POST", "/api/security-alerts/acknowledge-all", "ok")


def test_people_only_routes_are_refused(live_agents):
    agent, _, tokens = _connect_with_code(views=tuple(a.id for a in scopes.AREAS),
                                          acts=tuple(a.id for a in scopes.AREAS if a.act))
    token = tokens["access_token"]
    assert _api(agent, token, "PUT", "/api/settings", json={"app_title": "x"}).status_code == 403
    assert _api(agent, token, "GET", "/api/agents").status_code == 403
    assert _api(agent, token, "GET", "/api/raw-logs/ws-token").status_code == 403


def test_a_guessed_path_points_the_agent_to_the_list(live_agents):
    agent, _, tokens = _connect_with_code()
    r = _api(agent, tokens["access_token"], "GET", "/api/status")
    assert r.status_code == 404 and r.json()["error"] == "not_found"
    assert "mailcow-logs endpoints" in r.json()["message"]


def test_the_skill_lists_only_paths_that_exist(live_agents):
    import re
    text = (store.__file__.rsplit("store.py", 1)[0] + "skill_files/SKILL.md")
    with open(text, encoding="utf-8") as f:
        paths = re.findall(r"^\s*\| `([a-z][^`?]*)(?:\?[^`]*)?` \|", f.read(), re.M)
    assert len(paths) >= 10
    templates = {path for (method, path) in scopes.POLICY if method == "GET"}
    for p in paths:
        full = "/api/" + p
        assert any(re.fullmatch(re.sub(r"\{[^}]+\}", "[^/]+", t), full) for t in templates), p


def test_access_and_endpoints_describe_this_connection(live_agents):
    agent, _, tokens = _connect_with_code(views=("security", "messages"), acts=("security",))
    access = _api(agent, tokens["access_token"], "GET", "/api/agent/access").json()
    assert {a["area"]: a["may"] for a in access["areas"]} == {"security": "view and act", "messages": "view"}
    listed = _api(agent, tokens["access_token"], "GET", "/api/agent/endpoints", params={"area": "messages"}).json()
    assert listed["count"] > 0 and all(e["area"] == "messages" and e["kind"] == "read" for e in listed["endpoints"])
    assert _api(agent, tokens["access_token"], "POST", "/api/agent/access").status_code == 405


def test_a_bad_bearer_never_falls_back_to_the_owners_cookie(live_agents):
    browser = _signed_in()
    assert browser.get("/api/security-alerts").status_code == 200
    r = browser.get("/api/security-alerts", headers={"Authorization": "Bearer mlva_not-a-token"})
    assert r.status_code == 401 and r.json()["error"] == "invalid_token"
    assert "invalid_token" in r.headers["www-authenticate"]


@pytest.mark.parametrize("value", ["Basic dW51c2Vk, Bearer mlva_invalid", "Bearer", "bearer  ", "Basic x,Bearer y"])
def test_an_authorization_that_mixes_in_bearer_never_falls_back_to_the_cookie(live_agents, value):
    browser = _signed_in()
    r = browser.get("/api/security-alerts", headers={"Authorization": value})
    assert r.status_code == 401 and r.json()["error"] == "invalid_token"


def test_codes_that_can_never_succeed_count_against_the_address(live_agents):
    agent, _, _ = _connect_with_code()
    from app.database import get_db_context
    from app.models import AgentDeviceRequest
    d = _device(agent)
    _answer(d["user_code"], allow=False)
    for _ in range(oauth.unknown_device_codes.limit):
        assert _poll(agent, d["device_code"]).json()["error"] == "access_denied"
    assert _poll(agent, d["device_code"]).status_code == 429


def test_disconnect_all_and_collecting_a_code_at_once_leave_nothing_connected(live_agents):
    import threading
    from app.database import SessionLocal, get_db_context
    from app.models import AgentGrant
    for _ in range(6):
        agent = _client()
        d = _device(agent)
        _answer(d["user_code"])
        errors, barrier = [], threading.Barrier(2)

        def collect():
            db = SessionLocal()
            try:
                barrier.wait()
                store.redeem_device_code(db, device_code=d["device_code"], client_id=CLIENT)
            except store.TokenError:
                pass
            except Exception as e:
                errors.append(e)
            finally:
                db.close()

        def disconnect_all():
            db = SessionLocal()
            try:
                barrier.wait()
                store.revoke_all(db)
            except Exception as e:
                errors.append(e)
            finally:
                db.close()
        threads = [threading.Thread(target=collect), threading.Thread(target=disconnect_all)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert not errors, errors
        # Either the code was collected first and then disconnected, or it found its request ended
        with get_db_context() as db:
            assert db.query(AgentGrant).filter(AgentGrant.revoked_at.is_(None)).count() == 0


def test_disconnect_all_ends_an_mcp_code_not_exchanged_yet(live_agents):
    from urllib.parse import parse_qs, urlsplit
    from test_agent_access import REDIRECT, _authorize, _pkce, _register
    browser = _signed_in()
    client_id = _register(browser)
    verifier, challenge = _pkce()
    request_id = _request_id(_authorize(browser, client_id, challenge))
    answer = browser.post(f"/api/agents/consent/{request_id}", json={
        "allow": True, "name": "MCP app", "views": ["security"], "acts": [], "days": 7})
    code = parse_qs(urlsplit(answer.json()["redirect"]).query)["code"][0]
    assert browser.delete("/api/agents").status_code == 200
    r = browser.post("/oauth/token", data={"grant_type": "authorization_code", "code": code, "client_id": client_id,
                                           "redirect_uri": REDIRECT, "code_verifier": verifier,
                                           "resource": APP_URL + "/mcp"})
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_two_authorization_headers_are_refused(live_agents):
    agent, _, tokens = _connect_with_code()
    r = agent.get("/api/security-alerts", headers=[("Authorization", f"Bearer {tokens['access_token']}"),
                                                    ("Authorization", BASIC)])
    assert r.status_code == 401


def test_a_bearer_is_refused_while_agent_access_is_not_live(live_agents, monkeypatch):
    agent, _, tokens = _connect_with_code()
    monkeypatch.setattr(settings._inner, "agent_access_enabled", False)
    assert _api(agent, tokens["access_token"], "GET", "/api/security-alerts").status_code == 401
    # Sign-in off makes the app open to everyone, but never to a bearer
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    assert _api(agent, tokens["access_token"], "GET", "/api/security-alerts").status_code == 401


def test_tokens_work_only_where_they_were_issued(live_agents):
    agent, _, rest_tokens = _connect_with_code()
    _, mcp_client_id, mcp_tokens = _connect()
    assert _mcp(_client(), rest_tokens["access_token"], "ping").status_code == 401
    assert _api(agent, mcp_tokens["access_token"], "GET", "/api/security-alerts").status_code == 401
    # Also after a refresh, which never moves a grant to the other place
    r = agent.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": CLIENT,
                                         "refresh_token": rest_tokens["refresh_token"], "resource": APP_URL + "/mcp"})
    assert r.json()["error"] == "invalid_target"
    r = agent.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": CLIENT,
                                         "refresh_token": rest_tokens["refresh_token"]})
    assert r.status_code == 200
    fresh = r.json()["access_token"]
    assert _mcp(_client(), fresh, "ping").status_code == 401
    assert _api(agent, fresh, "GET", "/api/security-alerts").status_code == 200


def test_a_body_over_the_limit_is_refused_before_it_runs(live_agents):
    agent, _, tokens = _connect_with_code(views=("security",), acts=("security",))
    r = _api(agent, tokens["access_token"], "POST", "/api/security-alerts/acknowledge-all",
             content=b"x" * (300 * 1024), headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and r.json()["error"] == "too_large"


def test_the_live_log_stream_never_takes_an_agent_token(live_agents):
    agent, _, tokens = _connect_with_code(views=("logs",))
    from starlette.websockets import WebSocketDisconnect
    with agent.websocket_connect("/ws/raw-logs?service=postfix",
                                 headers={"Authorization": f"Bearer {tokens['access_token']}"}) as ws:
        assert ws.receive_json() == {"type": "error", "message": "Authentication required"}
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_text()
        assert closed.value.code == 4401


def test_a_person_changes_what_a_connected_agent_may_do(live_agents):
    agent, browser, tokens = _connect_with_code(views=("security",), acts=("security",))
    token = tokens["access_token"]
    agent_id = browser.get("/api/agents").json()["agents"][0]["id"]
    assert _api(agent, token, "GET", "/api/messages").status_code == 403
    # Take action away from Security, add View of Messages: applies to the next request
    r = browser.put(f"/api/agents/{agent_id}", json={"views": ["security", "messages"], "acts": []})
    assert r.status_code == 200, r.text
    assert _api(agent, token, "GET", "/api/messages").status_code == 200
    assert _api(agent, token, "POST", "/api/security-alerts/acknowledge-all", json={"ids": [1]}).status_code == 403
    row = browser.get("/api/agents").json()["agents"][0]
    assert row["areas"] == {"security": "view", "messages": "view"}
    activity = browser.get(f"/api/agents/{agent_id}/activity").json()["activity"]
    assert any(a["event"] == "grant_changed" and a["detail"].startswith("by admin:") for a in activity)


def test_a_new_end_moves_the_refresh_token_with_it(live_agents):
    agent, browser, tokens = _connect_with_code(days=1)
    agent_id = browser.get("/api/agents").json()["agents"][0]["id"]
    assert browser.put(f"/api/agents/{agent_id}", json={"views": ["security"], "days": 30}).status_code == 200
    from app.database import get_db_context
    from app.models import AgentGrant, AgentToken
    with get_db_context() as db:
        grant = db.query(AgentGrant).filter(AgentGrant.id == agent_id).one()
        refresh = db.query(AgentToken).filter(AgentToken.grant_id == agent_id, AgentToken.kind == "refresh").one()
        assert timedelta(days=29) < grant.expires_at - datetime.utcnow() and refresh.expires_at == grant.expires_at
    r = agent.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": CLIENT,
                                         "refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200


def test_a_call_waiting_while_its_access_is_narrowed_runs_under_the_new_access(live_agents):
    import asyncio
    from app.agent_access import dispatch
    from app.database import SessionLocal
    from app.main import app
    agent, browser, tokens = _connect_with_code(views=("security",), acts=("security",))
    db = SessionLocal()
    try:
        grant = store.validate_access_token(db, tokens["access_token"], APP_URL + "/api")
    finally:
        db.close()
    agent_id = browser.get("/api/agents").json()["agents"][0]["id"]
    # Take action is taken away while the call waits for its body or a slot
    assert browser.put(f"/api/agents/{agent_id}", json={"views": ["security"], "acts": []}).status_code == 200

    async def run():
        dispatch._slots = None
        return await dispatch.call_api(app, grant, None, "POST", "/api/security-alerts/acknowledge-all",
                                       None, {"ids": [1]}, None)
    result = asyncio.run(run())
    assert result.outcome == "denied" and "Take action" in result.text


def test_an_edit_made_on_an_older_copy_is_refused(live_agents):
    _, browser, _ = _connect_with_code(views=("security",), acts=("security",))
    row = browser.get("/api/agents").json()["agents"][0]
    old = row["version"]
    # Another window takes Take action away
    assert browser.put(f"/api/agents/{row['id']}", json={"views": ["security"], "version": old}).status_code == 200
    # This window still shows the old access and changes something else
    r = browser.put(f"/api/agents/{row['id']}", json={"views": ["security", "messages"], "acts": ["security"],
                                                      "version": old})
    assert r.status_code == 409 and "while you were editing" in r.json()["detail"]
    assert browser.get("/api/agents").json()["agents"][0]["areas"] == {"security": "view"}


def test_a_longer_end_keeps_catching_a_reused_refresh_token(live_agents):
    agent, browser, tokens = _connect_with_code(days=1)
    first = tokens["refresh_token"]
    r = agent.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": CLIENT, "refresh_token": first})
    assert r.status_code == 200
    agent_id = browser.get("/api/agents").json()["agents"][0]["id"]
    assert browser.put(f"/api/agents/{agent_id}", json={"views": ["security"], "days": 30}).status_code == 200
    from app.database import get_db_context
    from app.models import AgentGrant, AgentToken
    with get_db_context() as db:
        end = db.query(AgentGrant).filter(AgentGrant.id == agent_id).one().expires_at
        assert {t.expires_at for t in db.query(AgentToken).filter(AgentToken.grant_id == agent_id,
                                                                  AgentToken.kind == "refresh")} == {end}
    # The spent token, presented again, still ends the connection
    r = agent.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": CLIENT, "refresh_token": first})
    assert r.json()["error"] == "invalid_grant"
    assert browser.get("/api/agents").json()["agents"][0]["end_reason"] == "refresh_reused"


@pytest.mark.parametrize("body, status", [
    ({"views": [], "acts": []}, 400),
    ({"views": ["security"], "days": 3}, 400),
])
def test_a_change_must_leave_some_access_and_a_known_period(live_agents, body, status):
    _, browser, _ = _connect_with_code()
    agent_id = browser.get("/api/agents").json()["agents"][0]["id"]
    assert browser.put(f"/api/agents/{agent_id}", json=body).status_code == status


def test_only_a_connected_agent_can_be_changed_and_never_by_an_agent(live_agents):
    agent, browser, tokens = _connect_with_code()
    agent_id = browser.get("/api/agents").json()["agents"][0]["id"]
    assert _api(agent, tokens["access_token"], "PUT", f"/api/agents/{agent_id}",
                json={"views": ["security"], "acts": ["security"]}).status_code == 403
    assert browser.delete(f"/api/agents/{agent_id}").status_code == 200
    assert browser.put(f"/api/agents/{agent_id}", json={"views": ["security"]}).status_code == 404


def test_revoking_ends_the_connection_and_settings_say_how_it_connected(live_agents):
    agent, browser, tokens = _connect_with_code()
    row = browser.get("/api/agents").json()["agents"][0]
    assert row["kind"] == "device" and row["state"] == "connected"
    assert agent.post("/oauth/revoke", data={"token": tokens["refresh_token"], "client_id": CLIENT}).status_code == 200
    assert _api(agent, tokens["access_token"], "GET", "/api/security-alerts").status_code == 401
    assert browser.get("/api/agents").json()["agents"][0]["end_reason"] == "revoked_by_agent"


# ── The skill ──────────────────────────────────────────────────────────────

def test_the_skill_is_served_with_this_apps_address(live_agents):
    client = _client()
    note = client.get("/agents/skill/")
    assert note.status_code == 200 and note.headers["content-type"].startswith("text/markdown")
    assert f"{APP_URL}/agents/skill/SKILL.md" in note.text and "read `mailcow-logs/SKILL.md` now" in note.text
    skill = client.get("/agents/skill/SKILL.md")
    assert skill.status_code == 200 and "__MAILCOW_LOGS_URL__" not in skill.text and APP_URL in skill.text
    for name in ("scripts/mailcow-logs", "scripts/mailcow-logs.mjs", "scripts/mailcow-logs.ps1", "scripts/mailcow-logs.sh"):
        r = client.get(f"/agents/skill/{name}")
        assert r.status_code == 200 and "__MAILCOW_LOGS_URL__" not in r.text, name
    assert client.get("/agents/skill/scripts/mailcow-logs.mjs").headers["content-type"].startswith("text/javascript")
    assert client.get("/agents/skill/..%2F..%2Fmain.py").status_code == 404
    assert client.get("/agents/skill/scripts/other.sh").status_code == 404
    assert client.get("/agents/skill", follow_redirects=False).headers["location"] == "/agents/skill/"


def test_an_older_skill_is_told_to_install_again(live_agents):
    from app.agent_access.skill import skill_version
    agent, _, tokens = _connect_with_code()
    script = agent.get("/agents/skill/scripts/mailcow-logs.mjs").text
    assert "__MAILCOW_LOGS_SKILL_VERSION__" not in script and f'"{skill_version()}"' in script
    token = tokens["access_token"]
    current = _api(agent, token, "GET", "/api/agent/access", headers={"X-Mailcow-Logs-Skill": skill_version()}).json()
    assert "update_skill" not in current
    for headers in ({"X-Mailcow-Logs-Skill": "000000000000"}, {}):
        older = _api(agent, token, "GET", "/api/agent/access", headers=headers).json()
        assert f"{APP_URL}/agents/skill/" in older["update_skill"]
    assert "keep the folder's `.install-id`" in agent.get("/agents/skill/").text


def test_the_mcp_instructions_carry_this_apps_address(live_agents):
    client = _client()
    for path in ("/agents/mcp", "/agents/mcp/"):
        r = client.get(path)
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/markdown")
        assert f"MCP server URL: `{APP_URL}/mcp`" in r.text
        assert f"claude mcp add --transport http mailcow {APP_URL}/mcp" in r.text
        assert f"{APP_URL}/agents/skill/" in r.text
    listed = _signed_in().get("/api/agents").json()
    assert listed["mcp_sentence"] == ("Connect yourself to mailcow Logs Viewer over MCP as described at "
                                      f"{APP_URL}/agents/mcp/, then tell me what to approve.")


def test_the_skill_is_not_served_while_agent_access_is_not_live(live_agents, monkeypatch):
    monkeypatch.setattr(settings._inner, "agent_access_enabled", False)
    assert _client().get("/agents/skill/").status_code == 404
    assert _client().get("/agents/mcp/").status_code == 404
    assert _client().post("/oauth/device", data={"client_id": CLIENT}).status_code == 404


def test_settings_show_the_sentence_for_the_agent(live_agents):
    listed = _signed_in().get("/api/agents").json()
    assert listed["skill_sentence"] == ("Install the mailcow-logs skill into your personal skills folder as described at "
                                        f"{APP_URL}/agents/skill/, then connect to mailcow Logs Viewer.")
