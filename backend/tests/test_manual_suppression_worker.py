"""Manual suppression persistence must not block other requests."""
import asyncio
import threading
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from fastapi import FastAPI
from app.database import get_db
from app.routers import suppressions


@pytest.mark.parametrize("reactivate", [False, True])
@pytest.mark.parametrize("stage", ["query", "commit", "refresh"])
def test_create_http_is_responsive_and_closes_before_cleanup(monkeypatch, reactivate, stage):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads, active, closed = [], [], []
    db = Mock()
    row = SimpleNamespace(active=False, bounce_count=2)
    db.query.return_value.filter.return_value.first.return_value = row if reactivate else None
    def block():
        threads.append(threading.get_ident())
        started.set()
        release.wait(2)
        finished.set()
    def query(*args):
        if stage == "query":
            block()
        return db.query.return_value
    db.query.side_effect = query
    db.commit.side_effect = block if stage == "commit" else lambda: None
    db.refresh.side_effect = (lambda obj: block()) if stage == "refresh" else lambda obj: None

    @contextmanager
    def session():
        active.append(True)
        try:
            yield db
        finally:
            active.pop()
            closed.append(True)

    async def cleanup(email):
        assert not active
        db.commit.assert_called_once()
        db.refresh.assert_called_once()
    cleanup_mock = AsyncMock(side_effect=cleanup)
    monkeypatch.setattr(suppressions, "SessionLocal", session)
    monkeypatch.setattr(suppressions, "_cleanup_queue_for_email", cleanup_mock)
    monkeypatch.setattr(suppressions, "_serialize_suppression", lambda row, now: {"email": "user@example.test", "active": True})
    app = FastAPI()
    app.include_router(suppressions.router, prefix="/api")
    app.dependency_overrides[get_db] = lambda: db

    async def run():
        loop_thread = threading.get_ident()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
            task = asyncio.create_task(api.post("/api/suppressions", json={"email": "user@example.test"}))
            try:
                assert await asyncio.to_thread(started.wait, 3)
                assert not finished.is_set(), "Suppression save blocked the request loop"
            finally:
                release.set()
                response = await task
        assert response.status_code == 200, response.text
        assert response.json() == {"email": "user@example.test", "active": True}
        assert threads and all(t != loop_thread for t in threads)
    asyncio.run(run())
    assert closed == [True]
    cleanup_mock.assert_awaited_once_with("user@example.test")
    if reactivate:
        assert row.bounce_count == 3
        assert row.active and not row.synced_to_rspamd and row.expires_at is None


@pytest.mark.parametrize("stage", ["query", "commit", "refresh"])
def test_failed_save_never_cleans_queue(monkeypatch, stage):
    db = Mock()
    db.query.return_value.filter.return_value.first.return_value = None
    getattr(db, stage).side_effect = RuntimeError("Database operation failed")
    closed = []
    @contextmanager
    def session():
        try:
            yield db
        finally:
            closed.append(True)
    cleanup = AsyncMock()
    monkeypatch.setattr(suppressions, "SessionLocal", session)
    monkeypatch.setattr(suppressions, "_cleanup_queue_for_email", cleanup)
    app = FastAPI()
    app.include_router(suppressions.router, prefix="/api")
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as api:
            response = await api.post("/api/suppressions", json={"email": "user@example.test"})
        assert response.status_code == 500
    asyncio.run(run())
    assert closed == [True]
    cleanup.assert_not_awaited()
