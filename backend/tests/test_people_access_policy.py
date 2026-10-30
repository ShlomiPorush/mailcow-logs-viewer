"""Every route a person can reach has a rule (user_access.py).

A route without one is refused at run time; this test names it first, so a
new route cannot open up, or close, without a decision. It also fails on a
rule for a route that is gone and on a rule given twice.
"""
import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, "check_dir": False})

from app import user_access  # noqa: E402
from app.agent_access import scopes  # noqa: E402
from app.main import app  # noqa: E402
from conftest import registered_routes  # noqa: E402


def _routes(application=app):
    out = set()
    for route in registered_routes(application):
        methods = getattr(route, "methods", None)
        if methods:
            out.update((m, route.path) for m in methods)
        elif "WebSocket" in type(route).__name__:
            out.add(("WEBSOCKET", route.path))
    return out


def _missing(application=app):
    return sorted(r for r in _routes(application) if user_access.need_for(*r) is None)


def test_every_route_has_a_rule_for_people():
    missing = _missing()
    assert not missing, f"add these to user_access.HUMAN_ENTRIES or agent_access/scopes.py POLICY: {missing}"


def test_the_check_names_a_route_without_a_rule_whatever_its_kind():
    from fastapi import FastAPI

    probe = FastAPI()

    def endpoint():
        return {}

    async def socket(websocket):
        pass

    probe.add_api_route("/api/probe-get", endpoint, methods=["GET"])
    probe.add_api_route("/api/probe-head", endpoint, methods=["HEAD"])
    probe.add_api_websocket_route("/ws/probe", socket)
    # A HEAD route of a GET route that has a rule is covered by that rule
    probe.add_api_route("/api/messages", endpoint, methods=["HEAD"])
    found = _missing(probe)
    assert ("GET", "/api/probe-get") in found and ("HEAD", "/api/probe-head") in found
    assert ("WEBSOCKET", "/ws/probe") in found
    assert ("HEAD", "/api/messages") not in found


def test_no_rule_is_for_a_route_that_is_gone():
    routes = _routes()
    stale = sorted(key for key in user_access.HUMAN if key not in routes)
    assert not stale, f"remove these from user_access.HUMAN_ENTRIES: {stale}"


def test_no_rule_is_given_twice():
    keys = [entry for entry, _need in user_access.HUMAN_ENTRIES]
    assert len(keys) == len(set(keys)), sorted(k for k in keys if keys.count(k) > 1)


def test_the_websocket_and_the_api_are_both_covered():
    routes = _routes()
    assert ("WEBSOCKET", "/ws/raw-logs") in routes
    assert any(path.startswith("/api/users") for _m, path in routes)


def test_approving_an_agent_is_for_admins():
    for path in ("/oauth/authorize", "/oauth/consent", "/oauth/device"):
        assert user_access.need_for("GET", path).kind == user_access.ADMIN_ONLY, path
    for method, path in (("GET", "/api/agents/consent/{request_id}"), ("POST", "/api/agents/consent/{request_id}"),
                         ("PUT", "/api/agents/{grant_id}"), ("DELETE", "/api/agents")):
        assert user_access.need_for(method, path).kind == user_access.ADMIN_ONLY
    # An agent asking for a code is not a person approving it
    assert user_access.need_for("POST", "/oauth/device").kind == user_access.PUBLIC


def test_settings_and_what_agents_may_not_do_are_for_admins():
    for (method, path), rule in scopes.POLICY.items():
        if rule.area == "settings":
            assert user_access.need_for(method, path).kind == user_access.ADMIN_ONLY, path
    for method, path in (("PUT", "/api/settings"), ("POST", "/api/settings/jobs/{job_name}/run"),
                         ("POST", "/api/settings/test/smtp"), ("POST", "/api/notifications/test"),
                         ("POST", "/api/settings/mailcow/rw-key/validate"), ("GET", "/api/status/container-logs"),
                         ("GET", "/api/users"), ("PUT", "/api/users/oauth2-default"),
                         ("POST", "/api/users/password-check")):
        assert user_access.need_for(method, path).kind == user_access.ADMIN_ONLY, path


def test_people_follow_the_agent_policys_areas_elsewhere():
    differs = {("GET", "/api/system/summary"), ("POST", "/api/system/summary/email"),
               ("GET", "/api/status/container-logs"), ("GET", "/api/rw-status")}
    for (method, path), rule in scopes.POLICY.items():
        if rule.area in (scopes.ANY, "settings") or (method, path) in differs:
            continue
        need = user_access.need_for(method, path)
        assert need.kind == user_access.AREAS and need.areas == ((rule.area, rule.kind),), (method, path)


def test_uploads_and_the_live_log_token_belong_to_their_area():
    assert user_access.need_for("POST", "/api/dmarc/upload").areas == (("dmarc", "write"),)
    assert user_access.need_for("POST", "/api/suppressions/import").areas == (("outbound", "write"),)
    assert user_access.need_for("GET", "/api/raw-logs/ws-token").areas == (("logs", "read"),)


def test_a_route_without_a_rule_is_refused_even_for_an_admin(monkeypatch):
    import pytest
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient
    from app.config import settings

    for key in ("auth_enabled", "basic_auth_enabled", "oauth2_enabled"):
        monkeypatch.setattr(settings._inner, key, False)
    probe = FastAPI(dependencies=[Depends(user_access.enforce_people_policy)])
    probe.add_api_route("/api/probe", lambda: {"ran": True}, methods=["GET", "POST"])
    client = TestClient(probe)
    for method in ("GET", "POST"):
        with pytest.raises(user_access.NotPermitted):
            client.request(method, "/api/probe")
