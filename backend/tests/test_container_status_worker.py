"""Container status database work must not block either HTTP entry point."""
import asyncio
import threading
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from fastapi import FastAPI
from app.routers import status
from app.database import get_db


@pytest.mark.parametrize("path", ["containers", "summary"])
@pytest.mark.parametrize("stage", ["query", "commit"])
def test_container_http_is_responsive(monkeypatch, path, stage):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads = []
    db = Mock()
    db.query.return_value.all.return_value = [SimpleNamespace(container_name="missing-mailcow", display_name="missing")]

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

    @contextmanager
    def session():
        status.mailcow_api.get_status_containers.assert_awaited_once()
        yield db

    monkeypatch.setattr(status, "SessionLocal", session, raising=False)
    monkeypatch.setattr(status.mailcow_api, "get_status_containers", AsyncMock(return_value=[{
        "running-mailcow": {"state": " RUNNING "}, "unknown-mailcow": {"state": None}}]))
    monkeypatch.setattr(status, "get_storage_status", AsyncMock(return_value={"used_percent": "10%"}))
    monkeypatch.setattr(status, "get_mailcow_info", AsyncMock(return_value={"domains": {"total": 2}}))
    app = FastAPI()
    app.include_router(status.router, prefix="/api")
    app.dependency_overrides[get_db] = lambda: db

    async def run():
        loop_thread = threading.get_ident()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
            task = asyncio.create_task(api.get(f"/api/status/{path}"))
            try:
                assert await asyncio.to_thread(started.wait, 3)
                assert not finished.is_set(), "Container status blocked the request loop"
            finally:
                release.set()
                response = await task
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["summary" if path == "containers" else "containers"] == {"running": 1, "stopped": 2, "total": 3, "ignored": 0}
        assert threads and all(t != loop_thread for t in threads)
        if path == "containers":
            assert data["containers"]["missing-mailcow"]["state"] == "stopped"
            assert data["containers"]["unknown-mailcow"]["state"] == "unknown"

    asyncio.run(run())
    db.commit.assert_called_once()


def test_failed_cache_commit_returns_status_after_rollback(monkeypatch):
    db = Mock()
    db.query.return_value.all.return_value = []
    db.commit.side_effect = RuntimeError("Cache unavailable")
    closed = []

    @contextmanager
    def session():
        try:
            yield db
        finally:
            closed.append(True)

    monkeypatch.setattr(status, "SessionLocal", session, raising=False)
    monkeypatch.setattr(status.mailcow_api, "get_status_containers", AsyncMock(return_value={"test-mailcow": {"state": "running"}}))
    app = FastAPI()
    app.include_router(status.router, prefix="/api")
    app.dependency_overrides[get_db] = lambda: db

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
            response = await api.get("/api/status/containers")
            assert response.status_code == 200
            assert response.json()["summary"]["running"] == 1

    asyncio.run(run())
    db.rollback.assert_called_once()
    assert closed == [True]
