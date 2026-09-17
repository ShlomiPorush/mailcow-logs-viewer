"""Retention work must keep its session inside a worker and leave the loop free."""
import asyncio
import threading
from contextlib import contextmanager
from unittest.mock import Mock
import pytest
from app import scheduler
from app.config import settings


JOBS = [("cleanup_old_logs", "cleanup_logs"),
        ("cleanup_old_dmarc_reports", "cleanup_dmarc_reports")]


@pytest.mark.parametrize("name,status_key", JOBS)
def test_retention_does_not_block_event_loop(monkeypatch, name, status_key):
    monkeypatch.setattr(settings._inner, "disabled_features", "")
    monkeypatch.setattr(scheduler, "job_status", {})
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads = []
    db = Mock()
    query = db.query.return_value.filter.return_value
    query.delete.return_value = 0
    query.all.return_value = []
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
        task = asyncio.create_task(getattr(scheduler, name)())
        try:
            assert await asyncio.to_thread(started.wait, 3)
            await asyncio.sleep(0)
            assert not finished.is_set(), "retention blocked the event loop"
        finally:
            release.set()
            await task
        assert len(set(threads)) == 1
        assert threads[0] != loop_thread
        assert scheduler.job_status[status_key]["status"] == "success"
    asyncio.run(run())


@pytest.mark.parametrize("name,status_key", JOBS)
def test_worker_database_failure_is_reported(monkeypatch, name, status_key):
    monkeypatch.setattr(settings._inner, "disabled_features", "")
    monkeypatch.setattr(scheduler, "job_status", {})
    @contextmanager
    def broken_session():
        raise RuntimeError("fixture database failure")
        yield
    monkeypatch.setattr(scheduler, "get_db_context", broken_session)
    asyncio.run(getattr(scheduler, name)())
    assert scheduler.job_status[status_key]["status"] == "failed"
    assert scheduler.job_status[status_key]["error"] == "fixture database failure"


def test_disabled_dmarc_cleanup_does_not_open_database(monkeypatch):
    monkeypatch.setattr(settings._inner, "disabled_features", "dmarc")
    db = Mock(side_effect=AssertionError("disabled cleanup accessed database"))
    monkeypatch.setattr(scheduler, "get_db_context", db)
    asyncio.run(scheduler.cleanup_old_dmarc_reports())
    db.assert_not_called()


def test_retention_boundaries_on_isolated_postgres_schema(monkeypatch):
    import uuid
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker
    from app.database import engine, Base
    from app.models import (PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation,
                            DMARCReport, DMARCRecord, TLSReport, TLSReportPolicy)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    schema = "retention_test_" + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    test_engine = create_engine(engine.url, connect_args={"options": f"-csearch_path={schema}"})
    session_factory = sessionmaker(bind=test_engine)
    @contextmanager
    def session_context():
        with session_factory() as db:
            yield db
    try:
        Base.metadata.create_all(test_engine)
        now = datetime(2026, 1, 15, tzinfo=timezone.utc)
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return now if tz else now.replace(tzinfo=None)
        monkeypatch.setattr(scheduler, "datetime", Clock)
        monkeypatch.setattr(scheduler, "get_db_context", session_context)
        monkeypatch.setattr(scheduler, "job_status", {})
        monkeypatch.setattr(settings._inner, "disabled_features", "")
        monkeypatch.setattr(settings._inner, "retention_days", 7)
        monkeypatch.setattr(settings._inner, "dmarc_retention_days", 7)
        expected = {}
        with session_context() as db:
            for offset in (-1, 0, 1):
                stamp = (now - timedelta(days=7) + timedelta(seconds=offset)).replace(tzinfo=None)
                rows = [PostfixLog(time=stamp), RspamdLog(time=stamp), NetfilterLog(time=stamp),
                        MessageCorrelation(correlation_key=f"retention-{offset}", first_seen=stamp)]
                dmarc = DMARCReport(report_id=f"dmarc-{offset}", domain="example.com", org_name="Test",
                                    begin_date=1, end_date=2, created_at=stamp)
                tls = TLSReport(report_id=f"tls-{offset}", policy_domain="example.com",
                                start_datetime=stamp, end_datetime=stamp, created_at=stamp)
                db.add_all(rows + [dmarc, tls])
                db.flush()
                children = [DMARCRecord(dmarc_report_id=dmarc.id, source_ip="192.0.2.1", count=1),
                            TLSReportPolicy(tls_report_id=tls.id, policy_domain="example.com")]
                db.add_all(children)
                db.flush()
                for row in rows + [dmarc, tls] + children:
                    expected.setdefault(type(row), set())
                    if offset >= 0:
                        expected[type(row)].add(row.id)
            db.commit()
        asyncio.run(scheduler.cleanup_old_logs())
        asyncio.run(scheduler.cleanup_old_dmarc_reports())
        assert scheduler.job_status["cleanup_logs"]["status"] == "success"
        assert scheduler.job_status["cleanup_dmarc_reports"]["status"] == "success"
        with session_context() as db:
            for model, ids in expected.items():
                assert {row.id for row in db.query(model).all()} == ids
    finally:
        test_engine.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
            assert conn.execute(text("SELECT count(*) FROM information_schema.schemata WHERE schema_name=:name"),
                                {"name": schema}).scalar() == 0


def test_dmarc_cache_lookup_tolerates_invalidation(monkeypatch):
    from app.services import dmarc_cache
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    class InvalidatedCache(dict):
        def __contains__(self, key):
            present = super().__contains__(key)
            self.clear()
            return present
        def get(self, key, default=None):
            value = super().get(key, default)
            self.clear()
            return value
    monkeypatch.setattr(dmarc_cache, "_last_db_check", now)
    monkeypatch.setattr(dmarc_cache, "_dmarc_cache", InvalidatedCache({"test": ({"count": 1}, now)}))
    assert dmarc_cache.get_dmarc_cached("test", Mock()) == {"count": 1}
