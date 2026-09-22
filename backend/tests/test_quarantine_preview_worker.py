"""The quarantine dry run loads detached rules outside the request loop."""
import asyncio
import threading
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
from fastapi import FastAPI
from app.routers import quarantine_rules as rules


def test_preview_http_keeps_loop_responsive_and_closes_session(monkeypatch):
    started, release, closed = threading.Event(), threading.Event(), threading.Event()
    threads = []
    db = Mock()
    db.query.return_value.all.return_value = [
        SimpleNamespace(id=1, name="Allow", match_type="sender_domain", match_value="example.com",
                        is_regex=False, action="release", enabled=True),
        SimpleNamespace(id=2, name="Deny", match_type="subject", match_value="blocked",
                        is_regex=False, action="delete", enabled=False),
    ]

    @contextmanager
    def session():
        threads.append(threading.get_ident())
        started.set()
        release.wait(2)
        try:
            yield db
        finally:
            threads.append(threading.get_ident())
            closed.set()

    async def quarantine():
        assert closed.is_set()
        return [{"id": "ITEM", "sender": "user@example.com", "rcpt": "recipient@example.com", "subject": "blocked"}]

    monkeypatch.setattr(rules, "get_db_context", session)
    monkeypatch.setattr(rules.mailcow_api, "headers_rw", {"X-API-Key": "test-key"})
    monkeypatch.setattr(rules.mailcow_api, "get_quarantine", quarantine)
    monkeypatch.setattr(rules.mailcow_api, "release_quarantine", AsyncMock())
    monkeypatch.setattr(rules.mailcow_api, "delete_quarantine", AsyncMock())
    app = FastAPI()
    app.include_router(rules.router)

    async def run():
        loop_thread = threading.get_ident()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
            task = asyncio.create_task(api.post("/api/quarantine/rules/test"))
            try:
                assert await asyncio.to_thread(started.wait, 3)
                assert not closed.is_set(), "Rule preview blocked the request loop"
            finally:
                release.set()
                response = await task
        assert response.status_code == 200
        result = response.json()
        assert result["total_quarantine"] == result["total_matches"] == 1
        assert result["matches"][0]["rule_id"] == 2
        assert result["matches"][0]["rule_enabled"] is False
        assert threads[0] == threads[1] and threads[0] != loop_thread

    asyncio.run(run())
    rules.mailcow_api.release_quarantine.assert_not_awaited()
    rules.mailcow_api.delete_quarantine.assert_not_awaited()
