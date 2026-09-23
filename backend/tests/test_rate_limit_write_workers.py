"""Rate limit writes keep database waits off the request loop."""
import asyncio
import threading
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from fastapi import FastAPI
from app.database import get_db
from app.routers import rate_limits


@pytest.mark.parametrize("path,stage", [
    ("mailbox", "query"), ("mailbox", "commit"),
    ("bulk", "query"), ("bulk", "commit"),
    ("domain", "query"), ("reset", "query"), ("reset", "commit"),
])
def test_write_http_is_responsive(monkeypatch, path, stage):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads, sessions = [], []
    row = SimpleNamespace(username="User@example.test", rl_value=5, rl_frame="m")
    db = Mock()
    query = db.query.return_value
    query.filter.return_value.first.return_value = row if path != "reset" else None
    query.filter.return_value.all.return_value = [row]
    query.distinct.return_value.all.return_value = [("example.test",)]

    def block():
        threads.append(threading.get_ident())
        started.set()
        release.wait(2)
        finished.set()

    def read(*args):
        if stage == "query":
            block()
        return query

    db.query.side_effect = read
    db.commit.side_effect = block if stage == "commit" else lambda: None

    @contextmanager
    def session():
        sessions.append("open")
        try:
            yield db
        finally:
            sessions.append("closed")

    fake = SimpleNamespace(has_rw_key=True, **{name: AsyncMock(return_value=[]) for name in [
        "edit_rl_mbox", "edit_rl_mboxes", "edit_rl_domain", "edit_rl_domains", "delete_rl_hash"]})
    monkeypatch.setattr(rate_limits, "mailcow_api", fake)
    monkeypatch.setattr(rate_limits, "SessionLocal", session, raising=False)
    monkeypatch.setattr(rate_limits, "get_cached_active_domains", lambda: [])
    monkeypatch.setattr(rate_limits, "_domain_limit_cache", {"at": 0.0, "limits": None})
    app = FastAPI()
    app.include_router(rate_limits.router, prefix="/api")
    app.dependency_overrides[get_db] = lambda: db
    payload = {
        "mailbox": {"mailbox": "user@example.test", "value": 20, "frame": "h"},
        "bulk": {"mailboxes": ["user@example.test"], "domains": ["example.test"], "value": 20, "frame": "h"},
        "domain": {"domain": "example.test", "value": 20, "frame": "h"},
        "reset": {"rl_hash": "RLtest123", "user": "user@example.test"},
    }[path]

    async def run():
        loop_thread = threading.get_ident()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
            task = asyncio.create_task(api.post(f"/api/rate-limits/{path}", json=payload))
            try:
                assert await asyncio.to_thread(started.wait, 3)
                assert not finished.is_set(), "Database work blocked the request loop"
            finally:
                release.set()
                response = await task
        assert response.status_code == 200, response.text
        assert threads and all(t != loop_thread for t in threads)
        if path == "bulk":
            assert response.json()["mailboxes_updated"] == response.json()["domains_updated"] == 1
        if path == "mailbox":
            assert response.json()["mailbox"] == "User@example.test"
        assert sessions and sessions.count("open") == sessions.count("closed")

    asyncio.run(run())


@pytest.mark.parametrize("path", ["mailbox", "bulk", "reset"])
@pytest.mark.parametrize("failure", ["upstream", "commit"])
def test_write_failure_preserves_upstream_result_and_closes_sessions(monkeypatch, path, failure):
    db = Mock()
    row = SimpleNamespace(username="User@example.test", rl_value=5, rl_frame="m")
    db.query.return_value.filter.return_value.first.return_value = row if path != "reset" else None
    db.query.return_value.filter.return_value.all.return_value = [row]
    db.query.return_value.distinct.return_value.all.return_value = [("example.test",)]
    if failure == "commit":
        db.commit.side_effect = RuntimeError("Local write failed")
    active = []
    closed = []

    @contextmanager
    def session():
        active.append(True)
        try:
            yield db
        finally:
            active.pop()
            closed.append(True)

    calls = []
    async def write(*args):
        assert not active, "Database session held across upstream write"
        calls.append(args)
        if failure == "upstream":
            raise rate_limits.MailcowAPIError("Upstream write failed")
        return []

    fake = SimpleNamespace(has_rw_key=True, **{name: AsyncMock(side_effect=write) for name in [
        "edit_rl_mbox", "edit_rl_mboxes", "edit_rl_domains", "delete_rl_hash"]})
    monkeypatch.setattr(rate_limits, "mailcow_api", fake)
    monkeypatch.setattr(rate_limits, "SessionLocal", session)
    monkeypatch.setattr(rate_limits, "get_cached_active_domains", lambda: [])
    monkeypatch.setattr(rate_limits, "_domain_limit_cache", {"at": 0.0, "limits": None})
    app = FastAPI()
    app.include_router(rate_limits.router, prefix="/api")
    payload = {
        "mailbox": {"mailbox": "user@example.test", "value": 20, "frame": "h"},
        "bulk": {"mailboxes": ["user@example.test"], "domains": ["example.test"], "value": 20, "frame": "h"},
        "reset": {"rl_hash": "RLtest123", "user": "user@example.test"},
    }[path]

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
            response = await api.post(f"/api/rate-limits/{path}", json=payload)
        assert response.status_code == (502 if failure == "upstream" else 200), response.text
        if path == "bulk" and failure == "commit":
            assert response.json()["domains_updated"] == 1
            assert calls == [(["User@example.test"], 20, "h"), (["example.test"], 20, "h")]

    asyncio.run(run())
    assert not active
    if failure == "upstream":
        db.commit.assert_not_called()
        assert len(calls) == 1
    else:
        db.commit.assert_called_once()
        assert closed
        if path != "reset":
            db.rollback.assert_called_once()
