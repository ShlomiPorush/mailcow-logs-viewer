"""Rate limit list database reads must leave the request loop responsive."""
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


@pytest.mark.parametrize("stage", ["mailboxes", "domains"])
def test_list_http_is_responsive_and_closes_sessions(monkeypatch, stage):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads, sessions = [], []
    db = Mock()
    mailbox = SimpleNamespace(username="user@example.test", domain="example.test", rl_value=20, rl_frame="h", active=True)

    def query(column):
        kind = "mailboxes" if column is rate_limits.MailboxStatistics else "domains"
        if kind == stage:
            threads.append(threading.get_ident())
            started.set()
            release.wait(2)
            finished.set()
        result = Mock()
        result.filter.return_value.order_by.return_value.all.return_value = [mailbox]
        result.distinct.return_value.all.return_value = [("example.test",)]
        return result

    db.query.side_effect = query

    @contextmanager
    def session():
        sessions.append("open")
        try:
            yield db
        finally:
            sessions.append("closed")

    async def domain_limit(domain):
        assert sessions and sessions[-1] == "closed"
        return {"value": "30", "frame": "m"}

    monkeypatch.setattr(rate_limits, "SessionLocal", session, raising=False)
    monkeypatch.setattr(rate_limits, "get_cached_active_domains", lambda: [])
    monkeypatch.setattr(rate_limits, "_domain_limit_cache", {"at": 0.0, "limits": None})
    monkeypatch.setattr(rate_limits.mailcow_api, "get_rl_domain", AsyncMock(side_effect=domain_limit))
    app = FastAPI()
    app.include_router(rate_limits.router, prefix="/api")
    app.dependency_overrides[get_db] = lambda: db

    async def run():
        loop_thread = threading.get_ident()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
            task = asyncio.create_task(api.get("/api/rate-limits/limits"))
            try:
                assert await asyncio.to_thread(started.wait, 3)
                assert not finished.is_set(), "Rate limit reads blocked the request loop"
            finally:
                release.set()
                response = await task
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["mailboxes"] == [vars(mailbox)]
        assert data["domains"] == [{"domain": "example.test", "rl_value": 30, "rl_frame": "m"}]
        assert data["domains_error"] is None
        assert all(t != loop_thread for t in threads)

    asyncio.run(run())
    assert sessions == ["open", "closed", "open", "closed"]


def test_partial_domain_response_is_retried_then_cached(monkeypatch):
    reads = Mock(return_value={"a.test", "b.test"})
    monkeypatch.setattr(rate_limits, "_load_known_domains_worker", reads)
    monkeypatch.setattr(rate_limits, "_domain_limit_cache", {"at": 0.0, "limits": None})
    fetch = AsyncMock(side_effect=[
        {"value": "20", "frame": "h"}, rate_limits.MailcowAPIError("Unavailable"),
        {"value": "20", "frame": "h"}, {"value": "0", "frame": ""},
    ])
    monkeypatch.setattr(rate_limits.mailcow_api, "get_rl_domain", fetch)

    async def run():
        partial, error = await rate_limits._fetch_domain_limits()
        assert len(partial) == 1 and error == "Could not read domain rate limits. Check the application logs."
        assert rate_limits._domain_limit_cache["limits"] is None
        complete, error = await rate_limits._fetch_domain_limits()
        assert error is None and len(complete) == 2
        assert complete[1] == {"domain": "b.test", "rl_value": None, "rl_frame": None}
        assert await rate_limits._fetch_domain_limits() == (complete, None)

    asyncio.run(run())
    assert reads.call_count == 2
    assert fetch.await_count == 4


def test_mailbox_query_failure_closes_session(monkeypatch):
    db = Mock()
    db.query.side_effect = RuntimeError("Database unavailable")
    closed = []

    @contextmanager
    def session():
        try:
            yield db
        finally:
            closed.append(True)

    monkeypatch.setattr(rate_limits, "SessionLocal", session)
    with pytest.raises(rate_limits.HTTPException) as exc:
        asyncio.run(rate_limits.get_configured_limits())
    assert exc.value.status_code == 500
    assert closed == [True]
