"""Mailbox HTTP handlers must not run blocking queries on the request loop."""
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
    monkeypatch.setattr(stats, "_stats_cache", {})
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


def test_expired_cache_read_does_not_remove_concurrent_refresh(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor, TimeoutError
    from datetime import datetime, timedelta, timezone

    reading, release, writing = threading.Event(), threading.Event(), threading.Event()
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(stats, "_stats_cache", {"key": ("old", now - timedelta(hours=1))})

    class Clock:
        @staticmethod
        def now(tz):
            if not reading.is_set():
                reading.set()
                assert release.wait(3)
            return now

    monkeypatch.setattr(stats, "datetime", Clock)

    def refresh():
        writing.set()
        stats._set_cache("key", "fresh")

    with ThreadPoolExecutor(max_workers=2) as pool:
        reader = pool.submit(stats._get_cached, "key")
        assert reading.wait(3)
        writer = pool.submit(refresh)
        try:
            assert writing.wait(3)
            try:
                writer.result(timeout=0.1)
            except TimeoutError:
                pass
        finally:
            release.set()
        assert reader.result(timeout=3) is None
        writer.result(timeout=3)
    assert stats._get_cached("key") == "fresh"
