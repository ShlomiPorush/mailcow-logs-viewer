"""Postfix network I/O stays async while database work runs in a worker."""
import asyncio
import threading
from contextlib import contextmanager
from unittest.mock import AsyncMock, Mock

import pytest
from app import scheduler
from app.config import settings


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch):
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: True)
    monkeypatch.setattr(scheduler, "seen_postfix", set())
    monkeypatch.setattr(scheduler, "last_fetch_run_time", {})
    monkeypatch.setattr(scheduler, "_resume_offset", {"postfix": 0})
    monkeypatch.setattr(scheduler, "is_blacklisted", lambda email: False)
    monkeypatch.setattr(scheduler, "_discover_total_logs", AsyncMock(return_value=1))


def test_ingestion_keeps_loop_responsive(monkeypatch):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads, api_threads = [], []
    db = Mock()
    db.query.return_value.filter.return_value.all.return_value = []
    db.commit.side_effect = lambda: threads.append(threading.get_ident())
    async def fetch(**kwargs):
        api_threads.append(threading.get_ident())
        return [{"time": 1, "message": "ABC123: message-id=<message@example.com>", "priority": "crit"}]
    @contextmanager
    def session():
        threads.append(threading.get_ident())
        started.set()
        release.wait(2)
        try:
            yield db
        finally:
            threads.append(threading.get_ident())
            finished.set()
    monkeypatch.setattr(scheduler.mailcow_api, "get_postfix_logs_page", fetch)
    monkeypatch.setattr(scheduler, "get_db_context", session)
    async def run():
        loop_thread = threading.get_ident()
        task = asyncio.create_task(scheduler.fetch_and_store_postfix())
        try:
            assert await asyncio.to_thread(started.wait, 3)
            await asyncio.sleep(0)
            assert not finished.is_set(), "Postfix ingestion blocked the event loop"
        finally:
            release.set()
            await task
        assert api_threads == [loop_thread]
        assert len(threads) == 3 and len(set(threads)) == 1 and threads[0] != loop_thread
        db.add.assert_called_once()
        row = db.add.call_args.args[0]
        assert row.queue_id == "ABC123" and row.message_id == "message@example.com"
    asyncio.run(run())


def test_pages_resume_and_stop_on_persisted_duplicates(monkeypatch):
    import uuid
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session
    from app.database import Base, engine
    from app.models import PostfixLog, MessageCorrelation
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    schema = "postfix_worker_" + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    isolated = create_engine(engine.url, connect_args={"options": f"-csearch_path={schema}"})
    @contextmanager
    def session():
        with Session(isolated) as db:
            yield db
    logs = [{"time": 1700000000 + i, "program": "postfix/cleanup", "priority": "info",
             "message": f"ABC{i}: message-id=<message-{i}@example.com>"} for i in range(5)]
    calls = []
    async def page(page_size, offset):
        calls.append((page_size, offset))
        return logs[offset:offset + page_size]
    monkeypatch.setattr(scheduler, "get_db_context", session)
    monkeypatch.setattr(scheduler, "_discover_total_logs", AsyncMock(return_value=5))
    monkeypatch.setattr(scheduler.mailcow_api, "get_postfix_logs_page", page)
    monkeypatch.setattr(settings._inner, "fetch_count_postfix", 2)
    monkeypatch.setattr(settings._inner, "fetch_max_pages", 1)
    try:
        Base.metadata.create_all(isolated, tables=[PostfixLog.__table__, MessageCorrelation.__table__])
        for expected_count, expected_offset in [(2, 2), (4, 4), (5, 0)]:
            asyncio.run(scheduler.fetch_and_store_postfix())
            assert scheduler._resume_offset["postfix"] == expected_offset
            with session() as db:
                assert db.query(PostfixLog).count() == expected_count
        assert calls == [(2, 0), (2, 2), (2, 4)]
        scheduler.seen_postfix.clear()
        monkeypatch.setattr(settings._inner, "fetch_max_pages", 3)
        asyncio.run(scheduler.fetch_and_store_postfix())
        assert calls == [(2, 0), (2, 2), (2, 4), (2, 0)]
        assert scheduler._resume_offset["postfix"] == 0
        with session() as db:
            rows = db.query(PostfixLog).order_by(PostfixLog.time).all()
            assert [row.raw_data for row in rows] == logs
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
            assert conn.execute(text("SELECT count(*) FROM information_schema.schemata WHERE schema_name=:name"),
                                {"name": schema}).scalar() == 0
