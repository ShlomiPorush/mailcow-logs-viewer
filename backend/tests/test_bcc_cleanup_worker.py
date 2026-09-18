"""BCC cleanup keeps database work off the event loop and preserves queue scope."""
import asyncio
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime
from unittest.mock import Mock

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app import scheduler
from app.config import settings
from app.database import Base, engine
from app.models import PostfixLog


def test_bcc_cleanup_leaves_loop_responsive(monkeypatch):
    monkeypatch.setattr(settings._inner, "blacklist_emails", "bcc@example.com")
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads = []
    db = Mock()
    db.query.return_value.filter.return_value.all.return_value = [Mock(queue_id="BCC1")]
    db.query.return_value.filter.return_value.delete.return_value = 1
    db.commit.side_effect = lambda: threads.append(threading.get_ident())

    @contextmanager
    def slow_session():
        threads.append(threading.get_ident())
        started.set()
        release.wait(2)
        try:
            yield db
        finally:
            threads.append(threading.get_ident())
            finished.set()

    monkeypatch.setattr(scheduler, "get_db_context", slow_session)

    async def run():
        loop_thread = threading.get_ident()
        task = asyncio.create_task(scheduler.cleanup_blacklisted_queues())
        try:
            assert await asyncio.to_thread(started.wait, 3)
            await asyncio.sleep(0)
            assert not finished.is_set(), "BCC cleanup blocked the event loop"
        finally:
            release.set()
            await task
        assert len(threads) == 3
        assert len(set(threads)) == 1
        assert threads[0] != loop_thread
        db.commit.assert_called_once()

    asyncio.run(run())


def test_empty_blacklist_does_not_open_database(monkeypatch):
    monkeypatch.setattr(settings._inner, "blacklist_emails", "")
    session = Mock(side_effect=AssertionError("empty blacklist accessed database"))
    monkeypatch.setattr(scheduler, "get_db_context", session)
    asyncio.run(scheduler.cleanup_blacklisted_queues())
    session.assert_not_called()


def test_correlation_waits_for_cleanup(monkeypatch):
    events = []
    async def cleanup():
        events.append("cleanup started")
        await asyncio.sleep(0)
        events.append("cleanup finished")
    db = Mock()
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
    @contextmanager
    def session():
        events.append("correlation session")
        yield db
    monkeypatch.setattr(scheduler, "cleanup_blacklisted_queues", cleanup)
    monkeypatch.setattr(scheduler, "get_db_context", session)
    asyncio.run(scheduler.run_correlation())
    assert events == ["cleanup started", "cleanup finished", "correlation session"]


def test_cleanup_preserves_other_queue_chains(monkeypatch):
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    schema = "bcc_worker_test_" + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    isolated = create_engine(engine.url, connect_args={"options": f"-csearch_path={schema}"})
    @contextmanager
    def session():
        with Session(isolated) as db:
            yield db
    try:
        Base.metadata.create_all(isolated, tables=[PostfixLog.__table__])
        monkeypatch.setattr(settings._inner, "blacklist_emails", "bcc@example.com,archive@example.com")
        monkeypatch.setattr(scheduler, "get_db_context", session)
        with session() as db:
            rows = [PostfixLog(time=datetime.utcnow(), message_id="shared@example.com", queue_id=q, recipient=r)
                    for q, r in [("BCC1", "bcc@example.com"), ("BCC1", "other@example.com"),
                                 ("BCC2", "archive@example.com"), ("KEEP1", "recipient@example.com"),
                                 (None, "bcc@example.com"), ("KEEP2", "BCC@example.com")]]
            db.add_all(rows)
            db.flush()
            expected = {row.id for row in rows[3:]}
            db.commit()
        asyncio.run(scheduler.cleanup_blacklisted_queues())
        with session() as db:
            assert {row.id for row in db.query(PostfixLog).all()} == expected
        # Running again is harmless when all matched queue chains are gone.
        asyncio.run(scheduler.cleanup_blacklisted_queues())
        with session() as db:
            assert {row.id for row in db.query(PostfixLog).all()} == expected
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
            assert conn.execute(text("SELECT count(*) FROM information_schema.schemata WHERE schema_name=:name"),
                                {"name": schema}).scalar() == 0
