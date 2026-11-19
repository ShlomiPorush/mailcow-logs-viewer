"""
The demo's example agents: Settings > Agents shows them with their activity
and lets visitors edit and disconnect them, while no agent can connect,
since the demo has no sign-in.
"""
from pathlib import Path

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app.agent_access import scopes, store  # noqa: E402
from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402
from demo import seed  # noqa: E402
from demo.banner import STYLE  # noqa: E402

SETTINGS_JS = Path(__file__).resolve().parents[2] / "frontend" / "settings.js"


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _wipe():
    from app.database import get_db_context
    from app.models import AgentAudit, AgentClient, AgentCode, AgentDeviceRequest, AgentGrant, AgentToken, SystemSetting
    with get_db_context() as db:
        db.query(AgentDeviceRequest).delete(synchronize_session=False)
        for model in (AgentAudit, AgentToken, AgentCode, AgentGrant, AgentClient):
            db.query(model).delete(synchronize_session=False)
        db.query(SystemSetting).filter(SystemSetting.key == store._FINGERPRINT_KEY).delete(synchronize_session=False)


@pytest.fixture
def demo_agents(monkeypatch):
    """Sign-in and agent access off, as in the demo image, with the example agents seeded."""
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db
    init_db()
    inner = settings._inner
    for key in ("basic_auth_enabled", "auth_enabled", "oauth2_enabled", "agent_access_enabled"):
        monkeypatch.setattr(inner, key, False)
    monkeypatch.setattr(inner, "agent_access_url", "")
    monkeypatch.setattr(store, "_known_fingerprint", None)
    _wipe()
    seed.seed_agents()
    yield TestClient(app)
    _wipe()


def test_the_examples_show_in_settings_but_cannot_be_used(demo_agents):
    from app.database import get_db_context
    from app.models import AgentToken
    body = demo_agents.get("/api/agents").json()
    assert body["live"] is False and body["problem"] == "no_sign_in"
    agents = {a["name"]: a for a in body["agents"]}
    assert set(agents) == {"Claude Code", "Codex", "Cursor"}
    assert agents["Claude Code"]["kind"] == "device" and agents["Codex"]["kind"] == "dcr"
    assert agents["Claude Code"]["areas"] == {"messages": "view", "outbound": "view", "security": "act"}
    assert [agents[n]["state"] for n in ("Claude Code", "Codex", "Cursor")] == ["connected", "connected", "disconnected"]
    with get_db_context() as db:
        assert db.query(AgentToken).count() == 0
    # No agent can ask to connect: everything agents use answers 404 while agent access is off
    assert demo_agents.post("/oauth/device", data={"client_id": "mailcow-logs-cli"}).status_code == 404
    assert demo_agents.get("/api/messages", headers={"Authorization": "Bearer x"}).status_code == 401


def test_the_activity_reads_like_a_real_one(demo_agents):
    agents = {a["name"]: a for a in demo_agents.get("/api/agents").json()["agents"]}
    rows = demo_agents.get(f"/api/agents/{agents['Codex']['id']}/activity").json()["activity"]
    events = [r["event"] for r in reversed(rows)]
    assert events[0] == "grant_created" and "grant_changed" in events
    assert any(r["tool"] == "perform_action" for r in rows)
    claude = demo_agents.get(f"/api/agents/{agents['Claude Code']['id']}/activity").json()["activity"]
    assert sum(r["event"] == "denied" for r in claude) == 2
    cursor = demo_agents.get(f"/api/agents/{agents['Cursor']['id']}/activity").json()["activity"]
    assert cursor[0]["event"] == "grant_revoked"


def test_visitors_can_edit_and_disconnect_the_examples(demo_agents):
    agents = {a["name"]: a for a in demo_agents.get("/api/agents").json()["agents"]}
    codex = agents["Codex"]
    changed = demo_agents.put(f"/api/agents/{codex['id']}", json={
        "views": ["status"], "acts": [], "days": None, "version": codex["version"]})
    assert changed.status_code == 200
    assert demo_agents.delete(f"/api/agents/{agents['Claude Code']['id']}").status_code == 200
    states = {a["name"]: a["state"] for a in demo_agents.get("/api/agents").json()["agents"]}
    assert states["Claude Code"] == "disconnected"
    assert demo_agents.delete("/api/agents").status_code == 200


def test_every_example_call_is_a_real_route_of_its_area():
    for spec in seed.DEMO_AGENTS:
        for _when, event, tool, method, path, _status, detail in spec["calls"]:
            if event == "changed":
                continue
            rule = scopes.POLICY.get((method, path))
            if event == "denied" and rule is None:
                assert scopes.excluded_reason(method, path) in detail
                continue
            assert rule is not None, (method, path)
            allowed = scopes.allows(scopes.parse_scopes(scopes.grant_scopes(spec["views"], spec["acts"])), rule)
            assert allowed == (event == "call"), (spec["name"], method, path)
            if tool in ("read_api", "perform_action"):
                assert (tool == "perform_action") == (rule.kind == scopes.WRITE)


def test_the_demo_rewrites_the_sign_in_note_next_to_the_switch():
    assert "[data-agent-lock]" in STYLE
    assert "dataset.agentLock" in SETTINGS_JS.read_text(encoding="utf-8")
