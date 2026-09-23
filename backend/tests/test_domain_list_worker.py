"""Domain-list database work must leave the request loop responsive."""
import asyncio
import threading
from contextlib import contextmanager
from unittest.mock import AsyncMock, Mock

import httpx
from fastapi import FastAPI
from app.routers import domains


def test_domain_list_http_uses_worker_session(monkeypatch):
    started, release, closed = threading.Event(), threading.Event(), threading.Event()
    threads = []
    db = Mock()
    db.query.return_value.filter.return_value.order_by.return_value.first.return_value = None

    @contextmanager
    def session():
        domains.mailcow_api.get_domains.assert_awaited_once()
        threads.append(threading.get_ident())
        started.set()
        release.wait(2)
        try:
            yield db
        finally:
            threads.append(threading.get_ident())
            closed.set()

    def queried(*args):
        if not started.is_set():
            started.set()
            release.wait(2)
            closed.set()
        return db.query.return_value

    db.query.side_effect = queried
    monkeypatch.setattr(domains, "get_db_context", session)
    monkeypatch.setattr(domains.mailcow_api, "get_domains", AsyncMock(return_value=[
        {"domain_name": "example.com", "active": 1, "mboxes_in_domain": 2}]))
    monkeypatch.setattr(domains, "get_alias_domain_map", lambda db: {"alias.test": "example.com"})
    monkeypatch.setattr(domains, "get_cached_dns_check", lambda db, domain: {"domain": domain})
    app = FastAPI()
    app.include_router(domains.router, prefix="/api")
    app.dependency_overrides[domains.get_db] = lambda: db

    async def run():
        loop_thread = threading.get_ident()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
            task = asyncio.create_task(api.get("/api/domains/all"))
            try:
                assert await asyncio.to_thread(started.wait, 3)
                assert not closed.is_set(), "Domain list blocked the request loop"
            finally:
                release.set()
                response = await task
        assert response.status_code == 200
        result = response.json()
        assert result["total"] == result["active"] == 1
        row = result["domains"][0]
        assert row["mboxes_in_domain"] == 2
        assert row["alias_domains"] == [{"domain_name": "alias.test", "dns_checks": {"domain": "alias.test"}}]
        assert len(threads) == 2 and threads[0] == threads[1] and threads[0] != loop_thread
        assert closed.is_set()

    asyncio.run(run())
