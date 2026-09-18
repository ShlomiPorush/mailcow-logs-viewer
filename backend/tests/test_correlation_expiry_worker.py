"""Expiry uses a worker and a bulk update without changing status semantics."""
import asyncio
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from itertools import product
from unittest.mock import Mock

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session

from app import scheduler
from app.config import settings
from app.database import Base, engine
from app.models import MessageCorrelation


def test_expiry_leaves_event_loop_responsive(monkeypatch):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads = []
    db = Mock()
    query = db.query.return_value.filter.return_value
    query.all.return_value = []
    query.update.return_value = 0
    db.commit.side_effect = lambda: threads.append(threading.get_ident())
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
    monkeypatch.setattr(scheduler, "get_db_context", session)
    monkeypatch.setattr(scheduler, "job_status", {})
    async def run():
        loop_thread = threading.get_ident()
        task = asyncio.create_task(scheduler.expire_old_correlations())
        try:
            assert await asyncio.to_thread(started.wait, 3)
            await asyncio.sleep(0)
            assert not finished.is_set(), "expiry blocked the event loop"
        finally:
            release.set()
            await task
        assert len(set(threads)) == 1 and threads[0] != loop_thread
        assert scheduler.job_status["expire_correlations"]["status"] == "success"
    asyncio.run(run())


def test_expiry_reports_database_failure(monkeypatch):
    @contextmanager
    def session():
        raise RuntimeError("fixture database failure")
        yield
    monkeypatch.setattr(scheduler, "get_db_context", session)
    monkeypatch.setattr(scheduler, "job_status", {})
    asyncio.run(scheduler.expire_old_correlations())
    assert scheduler.job_status["expire_correlations"]["status"] == "failed"
    assert scheduler.job_status["expire_correlations"]["error"] == "fixture database failure"


@pytest.mark.parametrize("extra_rows", [0, 1000])
def test_expiry_boundaries_and_bulk_query(monkeypatch, extra_rows):
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    schema = "expiry_test_" + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    isolated = create_engine(engine.url, connect_args={"options": f"-csearch_path={schema}"})
    now = datetime(2026, 1, 15)
    class Clock(datetime):
        @classmethod
        def utcnow(cls):
            return now
    @contextmanager
    def session():
        with Session(isolated) as db:
            yield db
    monkeypatch.setattr(scheduler, "datetime", Clock)
    monkeypatch.setattr(scheduler, "get_db_context", session)
    monkeypatch.setattr(scheduler, "job_status", {})
    monkeypatch.setattr(settings._inner, "max_correlation_age_minutes", 10)
    statements = []
    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    try:
        Base.metadata.create_all(isolated, tables=[MessageCorrelation.__table__])
        expected = {}
        cases = list(product((-1, 0, 1), (False, True),
                             (None, "deferred", "discarded", "delivered"), (None, "discarded", "stored")))
        cases += [(-1, False, None, None)] * extra_rows
        with session() as db:
            for index, (offset, complete, final, dovecot) in enumerate(cases):
                key = f"expiry-{index}"
                stamp = now - timedelta(minutes=10) + timedelta(seconds=offset)
                db.add(MessageCorrelation(correlation_key=key, created_at=stamp,
                    is_complete=complete, final_status=final, dovecot_status=dovecot,
                    subject="Preserve this text", first_seen=stamp, last_seen=stamp))
                expires = offset < 0 and not complete
                expected[key] = (complete or expires,
                    "expired" if expires and final != "discarded" and dovecot != "discarded" else final,
                    dovecot, stamp)
            db.commit()
        event.listen(isolated, "before_cursor_execute", capture)
        try:
            asyncio.run(scheduler.expire_old_correlations())
        finally:
            event.remove(isolated, "before_cursor_execute", capture)
        assert scheduler.job_status["expire_correlations"]["status"] == "success"
        with session() as db:
            rows = db.query(MessageCorrelation).all()
            assert len(rows) == len(expected)
            for row in rows:
                complete, final, dovecot, stamp = expected[row.correlation_key]
                assert (row.is_complete, row.final_status, row.dovecot_status) == (complete, final, dovecot)
                assert row.first_seen == row.last_seen == stamp
                assert row.subject == "Preserve this text"
        assert len(statements) == 1
        assert statements[0].lstrip().upper().startswith("UPDATE ")
        # Repeated expiry is harmless and still succeeds.
        asyncio.run(scheduler.expire_old_correlations())
        assert scheduler.job_status["expire_correlations"]["status"] == "success"
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
            assert conn.execute(text("SELECT count(*) FROM information_schema.schemata WHERE schema_name=:name"),
                                {"name": schema}).scalar() == 0
