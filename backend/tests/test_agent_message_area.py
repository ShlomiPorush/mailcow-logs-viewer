"""A grant without View for Messages gets no message's sender, recipient or subject.

GET /api/stats/recent-activity lists messages and belongs to the Messages
area, and the pending deliveries in GET /api/settings/info (a Dashboard &
Status route) are left out for an agent without messages:read. Both ways
an agent calls the app are covered: MCP read_api and REST with a bearer.
"""
import json
import uuid
from datetime import datetime

import pytest

from test_agent_access import _connect, _signed_in, _tool, live_agents  # noqa: F401  (live_agents is a fixture)
from test_agent_device_rest import _api, _connect_with_code

MARK = uuid.uuid4().hex[:8]
SENDER = f"zed-{MARK}@example.test"
RECIPIENT = f"yan-{MARK}@example.test"
SUBJECT = f"subject-{MARK}"


@pytest.fixture
def pending_message(live_agents):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    now = datetime.utcnow()
    with get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=f"key-{MARK}", message_id=f"<{MARK}@example.test>",
                                  sender=SENDER, recipient=RECIPIENT, subject=SUBJECT, is_complete=False,
                                  first_seen=now, last_seen=now, created_at=now))
        db.commit()
    yield
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(MessageCorrelation.correlation_key == f"key-{MARK}").delete()
        db.commit()


def _mcp_read(views, path, query=None):
    client, _, tokens = _connect(views=views)
    return _tool(client, tokens["access_token"], "read_api", {"path": path, "query": query or {}})


def _pending_rows(text: str) -> list:
    body = json.loads(text.split("\n", 1)[1]) if text.startswith("HTTP") else json.loads(text)
    return body["recent_incomplete_correlations"]


def test_status_view_cannot_read_recent_activity_over_mcp(pending_message):
    result = _mcp_read(("status",), "/api/stats/recent-activity", {"limit": "3"})
    text = result["content"][0]["text"]
    assert result["isError"] and "messages:read" in text
    assert SENDER not in text and SUBJECT not in text


def test_status_view_cannot_read_recent_activity_over_rest(pending_message):
    agent, _, tokens = _connect_with_code(views=("status",))
    r = _api(agent, tokens["access_token"], "GET", "/api/stats/recent-activity", params={"limit": 3})
    assert r.status_code == 403 and "messages:read" in r.text
    assert SENDER not in r.text


def test_messages_view_reads_recent_activity(pending_message):
    result = _mcp_read(("messages",), "/api/stats/recent-activity", {"limit": "500"})
    assert not result["isError"] and SUBJECT in result["content"][0]["text"]


def test_status_view_gets_no_pending_messages_in_settings_info(pending_message):
    result = _mcp_read(("status",), "/api/settings/info")
    text = result["content"][0]["text"]
    assert not result["isError"], text
    assert _pending_rows(text) == []
    assert SENDER not in text and RECIPIENT not in text

    agent, _, tokens = _connect_with_code(views=("status",))
    r = _api(agent, tokens["access_token"], "GET", "/api/settings/info")
    assert r.status_code == 200 and r.json()["recent_incomplete_correlations"] == []
    assert SENDER not in r.text


def test_status_and_messages_view_and_people_get_pending_messages(pending_message):
    result = _mcp_read(("status", "messages"), "/api/settings/info")
    assert any(row["sender"] == SENDER for row in _pending_rows(result["content"][0]["text"]))

    browser = _signed_in()
    rows = browser.get("/api/settings/info").json()["recent_incomplete_correlations"]
    assert any(row["sender"] == SENDER for row in rows)
