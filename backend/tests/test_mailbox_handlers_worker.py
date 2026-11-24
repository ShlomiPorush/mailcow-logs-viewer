import asyncio
import threading
from unittest.mock import Mock

import httpx
import pytest
from fastapi import FastAPI
from app.routers import mailbox_stats as stats


@pytest.mark.parametrize("path", ["summary", "all"])
def test_mailbox_http_database_work_is_responsive(monkeypatch, path):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads = []
    query = Mock()
    query.scalar.return_value = None
    query.all.return_value = []
    query.filter.return_value = query
    db = Mock()

    def queried(*args):
        threads.append(threading.get_ident())
        if not started.is_set():
            started.set()
            release.wait(2)
            finished.set()
        return query

    db.query.side_effect = queried
    monkeypatch.setattr(stats, "get_alias_domain_map", lambda db: {})
    app = FastAPI()
    app.include_router(stats.router, prefix="/api")
    app.dependency_overrides[stats.get_db] = lambda: db

    async def run():
        loop_thread = threading.get_ident()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
            task = asyncio.create_task(api.get(f"/api/mailbox-stats/{path}"))
            try:
                assert await asyncio.to_thread(started.wait, 3)
                assert not finished.is_set(), "Mailbox query blocked the request loop"
            finally:
                release.set()
                response = await task
        assert response.status_code == 200
        assert "error" not in response.json(), response.text
        assert threads and all(t != loop_thread for t in threads)
        assert len(set(threads)) == 1

    asyncio.run(run())
