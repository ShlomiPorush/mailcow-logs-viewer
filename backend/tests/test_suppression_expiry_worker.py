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
from app.models import SpamSuppression


@pytest.fixture(autouse=True)
def enable_suppressions(monkeypatch):
    monkeypatch.setattr(settings._inner, "suppression_enabled", True)
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: True)


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
        task = asyncio.create_task(scheduler.expire_suppressions_job())
        try:
            assert await asyncio.to_thread(started.wait, 3)
            await asyncio.sleep(0)
            assert not finished.is_set(), "expiry blocked the event loop"
        finally:
            release.set()
            await task
        assert len(set(threads)) == 1 and threads[0] != loop_thread
        assert scheduler.job_status["expire_suppressions"]["status"] == "success"
    asyncio.run(run())


def test_expiry_reports_database_failure(monkeypatch):
    @contextmanager
    def session():
        raise RuntimeError("fixture database failure")
        yield
    monkeypatch.setattr(scheduler, "get_db_context", session)
    monkeypatch.setattr(scheduler, "job_status", {})
    asyncio.run(scheduler.expire_suppressions_job())
    assert scheduler.job_status["expire_suppressions"]["status"] == "failed"
    assert scheduler.job_status["expire_suppressions"]["error"] == "fixture database failure"


@pytest.mark.parametrize("extra_rows", [0, 1000])
def test_expiry_boundaries_and_bulk_query(monkeypatch, extra_rows):
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    schema = "suppression_expiry_test_" + uuid.uuid4().hex
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
    statements = []
    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    try:
        Base.metadata.create_all(isolated, tables=[SpamSuppression.__table__])
        expected = {}
        cases = list(product((None, -1, 0, 1), (False, True), (False, True)))
        cases += [(-1, True, True)] * extra_rows
        with session() as db:
            for index, (offset, active, synced) in enumerate(cases):
                key = f"expiry-{index}@example.com"
                stamp = None if offset is None else now + timedelta(seconds=offset)
                db.add(SpamSuppression(email=key, active=active, synced_to_rspamd=synced,
                    expires_at=stamp, reason="manual", notes="Preserve this text"))
                expires = active and offset is not None and offset <= 0
                expected[key] = (False if expires else active, False if expires else synced, stamp)
            db.commit()
        event.listen(isolated, "before_cursor_execute", capture)
        try:
            asyncio.run(scheduler.expire_suppressions_job())
        finally:
            event.remove(isolated, "before_cursor_execute", capture)
        assert scheduler.job_status["expire_suppressions"]["status"] == "success"
        with session() as db:
            rows = db.query(SpamSuppression).all()
            assert len(rows) == len(expected)
            for row in rows:
                active, synced, stamp = expected[row.email]
                assert (row.active, row.synced_to_rspamd, row.expires_at) == (active, synced, stamp)
                assert row.notes == "Preserve this text"
        assert len(statements) == 1
        assert statements[0].lstrip().upper().startswith("UPDATE ")
        # Repeated expiry is harmless and still succeeds.
        asyncio.run(scheduler.expire_suppressions_job())
        assert scheduler.job_status["expire_suppressions"]["status"] == "success"
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
            assert conn.execute(text("SELECT count(*) FROM information_schema.schemata WHERE schema_name=:name"),
                                {"name": schema}).scalar() == 0


@pytest.mark.parametrize("feature,enabled", [(False, True), (True, False)])
def test_disabled_expiry_does_not_access_database(monkeypatch, feature, enabled):
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: feature)
    monkeypatch.setattr(settings._inner, "suppression_enabled", enabled)
    session = Mock(side_effect=AssertionError("disabled job accessed database"))
    monkeypatch.setattr(scheduler, "get_db_context", session)
    monkeypatch.setattr(scheduler, "job_status", {})
    asyncio.run(scheduler.expire_suppressions_job())
    session.assert_not_called()
    assert scheduler.job_status == {}
