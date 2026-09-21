"""Manual DNS endpoints keep database waits off the request event loop."""
import asyncio
import threading
from contextlib import contextmanager
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from fastapi import FastAPI

from app.routers import domains
from app.config import settings


@pytest.mark.parametrize("path,full,block_alias", [
    ("/domains/example.com/check-dns", False, False),
    ("/domains/check-all-dns", True, False),
    ("/domains/check-all-dns", True, True),
])
def test_manual_dns_save_keeps_loop_responsive(monkeypatch, path, full, block_alias):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads = []
    db = Mock()
    query = Mock()
    query.filter.return_value.first.return_value = None

    def slow_query(*args):
        threads.append(threading.get_ident())
        started.set()
        release.wait(2)
        finished.set()
        return query

    db.query.side_effect = slow_query
    db.commit.side_effect = lambda: threads.append(threading.get_ident())
    monkeypatch.setattr(settings._inner, "dns_change_alerts_enabled", False)
    monkeypatch.setattr(domains, "check_domain_dns", AsyncMock(return_value={"spf":{"record":"v=spf1 -all"}}))
    monkeypatch.setattr(domains, "get_spf_source_ips", AsyncMock(return_value=[]))
    monkeypatch.setattr(domains.mailcow_api, "get_domains", AsyncMock(return_value=[{"domain_name":"example.com","active":1}]))
    def alias_map(session):
        if block_alias:
            slow_query()
        return {}
    monkeypatch.setattr(domains, "get_alias_domain_map", alias_map)

    @contextmanager
    def session():
        yield db

    # The old endpoints use dependency injection; the worker owns a context.
    from app import database
    monkeypatch.setattr(database, "get_db_context", session)
    if hasattr(domains, "get_db_context"):
        monkeypatch.setattr(domains, "get_db_context", session)
    app = FastAPI()
    app.include_router(domains.router)
    app.dependency_overrides[domains.get_db] = lambda: db

    async def run():
        loop_thread = threading.get_ident()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            task = asyncio.create_task(client.post(path))
            try:
                assert await asyncio.to_thread(started.wait, 3)
                assert not finished.is_set(), "Manual DNS save blocked the request loop"
            finally:
                release.set()
                response = await task
            assert response.status_code == 200
            assert response.json()["status"] == "success"
            if full:
                assert response.json()["domains_checked"] == 1
                assert response.json()["errors"] == []
            else:
                assert response.json()["data"] == {"spf":{"record":"v=spf1 -all"}}
        assert len(threads) == (3 if block_alias else 2)
        assert all(thread != loop_thread for thread in threads)
        assert threads[-1] == threads[-2]
        assert db.add.call_args.args[0].is_full_check is full

    asyncio.run(run())
