"""Suppression CSV processing must leave the request loop responsive."""
import asyncio
import threading
from contextlib import contextmanager
from unittest.mock import Mock

import httpx
import pytest
from fastapi import FastAPI
from app.database import get_db
from app.routers import suppressions


@pytest.mark.parametrize("stage", ["parse", "query", "commit"])
def test_import_http_is_responsive(monkeypatch, stage):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads, closed = [], []
    db = Mock()
    db.query.return_value.filter.return_value.first.return_value = None

    def block():
        threads.append(threading.get_ident())
        started.set()
        release.wait(2)
        finished.set()

    original_reader = suppressions.csv.reader
    def reader(*args, **kwargs):
        if stage == "parse":
            block()
        return original_reader(*args, **kwargs)
    def query(*args):
        if stage == "query":
            block()
        return db.query.return_value
    db.query.side_effect = query
    db.commit.side_effect = block if stage == "commit" else lambda: None

    @contextmanager
    def session():
        try:
            yield db
        finally:
            closed.append(True)

    monkeypatch.setattr(suppressions, "SessionLocal", session, raising=False)
    monkeypatch.setattr(suppressions.csv, "reader", reader)
    app = FastAPI()
    app.include_router(suppressions.router, prefix="/api")
    app.dependency_overrides[get_db] = lambda: db

    async def run():
        loop_thread = threading.get_ident()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
            task = asyncio.create_task(api.post("/api/suppressions/import", files={"file": ("test.csv", "email,notes\nuser@example.test,note\n")}))
            try:
                assert await asyncio.to_thread(started.wait, 3)
                assert not finished.is_set(), "CSV import blocked the request loop"
            finally:
                release.set()
                response = await task
        assert response.status_code == 200, response.text
        assert response.json() == {"imported": 1, "skipped": 0, "errors": []}
        assert threads and all(t != loop_thread for t in threads)

    asyncio.run(run())
    assert closed == [True]
    db.commit.assert_called_once()


def test_failed_commit_closes_session_without_success_response(monkeypatch):
    closed = []
    db = Mock()
    db.query.return_value.filter.return_value.first.return_value = None
    db.commit.side_effect = RuntimeError("Commit failed")

    @contextmanager
    def session():
        try:
            yield db
        finally:
            closed.append(True)

    monkeypatch.setattr(suppressions, "SessionLocal", session)
    app = FastAPI()
    app.include_router(suppressions.router, prefix="/api")

    async def run():
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as api:
            response = await api.post("/api/suppressions/import", files={"file": ("test.csv", "user@example.test\n")})
        assert response.status_code == 500

    asyncio.run(run())
    assert closed == [True]
