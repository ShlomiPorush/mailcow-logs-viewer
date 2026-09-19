"""Netfilter network I/O stays async while database work runs in a worker."""
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
    monkeypatch.setattr(scheduler, "seen_netfilter", set())
    monkeypatch.setattr(scheduler, "last_fetch_run_time", {})
    monkeypatch.setattr(scheduler.geoip_service, "is_geoip_available", lambda: False)


def test_ingestion_keeps_loop_responsive(monkeypatch):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads, api_threads = [], []
    db = Mock()
    db.query.return_value.filter.return_value.first.return_value = None
    db.commit.side_effect = lambda: threads.append(threading.get_ident())
    async def fetch(**kwargs):
        api_threads.append(threading.get_ident())
        return [{"time": 1, "message": "Banning 192.0.2.10", "priority": "crit"}]
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
    monkeypatch.setattr(scheduler.mailcow_api, "get_netfilter_logs", fetch)
    monkeypatch.setattr(scheduler, "get_db_context", session)
    async def run():
        loop_thread = threading.get_ident()
        task = asyncio.create_task(scheduler.fetch_and_store_netfilter())
        try:
            assert await asyncio.to_thread(started.wait, 3)
            await asyncio.sleep(0)
            assert not finished.is_set(), "Netfilter ingestion blocked the event loop"
        finally:
            release.set()
            await task
        assert api_threads == [loop_thread]
        assert len(threads) == 3 and len(set(threads)) == 1 and threads[0] != loop_thread
        db.add.assert_called_once()
        row = db.add.call_args.args[0]
        assert (row.ip, row.action, row.priority) == ("192.0.2.10", "ban", "crit")
    asyncio.run(run())


@pytest.mark.parametrize("enabled,logs", [(False, [{"time": 1}]), (True, [])])
def test_disabled_or_empty_does_not_open_database(monkeypatch, enabled, logs):
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: enabled)
    fetch = AsyncMock(return_value=logs)
    session = Mock(side_effect=AssertionError("database should not open"))
    monkeypatch.setattr(scheduler.mailcow_api, "get_netfilter_logs", fetch)
    monkeypatch.setattr(scheduler, "get_db_context", session)
    asyncio.run(scheduler.fetch_and_store_netfilter())
    session.assert_not_called()
    assert fetch.await_count == int(enabled)


def test_overlapping_batches_preserve_data_and_deduplication(monkeypatch):
    import uuid
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session
    from app.database import Base, engine
    from app.models import NetfilterLog
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    schema = "netfilter_worker_" + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    isolated = create_engine(engine.url, connect_args={"options": f"-csearch_path={schema}"})
    @contextmanager
    def session():
        with Session(isolated) as db:
            yield db
    logs = [{"time": 1700000000, "priority": "crit", "message": "Banning 192.0.2.10", "extra": "preserve"},
            {"time": 1700000001, "priority": "info", "message": "Unbanning 192.0.2.10"},
            {"time": "invalid", "message": "Malformed fixture"}]
    monkeypatch.setattr(scheduler.mailcow_api, "get_netfilter_logs", AsyncMock(return_value=logs))
    monkeypatch.setattr(scheduler, "get_db_context", session)
    monkeypatch.setattr(scheduler.geoip_service, "is_geoip_available", lambda: True)
    monkeypatch.setattr(scheduler.geoip_service, "lookup_ip", lambda ip: {
        "country_code": "US", "country_name": "United States", "city": "Example City",
        "asn": 64500, "asn_org": "Example network"})
    async def run():
        await asyncio.gather(scheduler.fetch_and_store_netfilter(), scheduler.fetch_and_store_netfilter())
    try:
        Base.metadata.create_all(isolated, tables=[NetfilterLog.__table__])
        asyncio.run(run())
        # Also prove deduplication from persisted rows after an empty memory cache.
        scheduler.seen_netfilter.clear()
        asyncio.run(scheduler.fetch_and_store_netfilter())
        with session() as db:
            rows = db.query(NetfilterLog).order_by(NetfilterLog.time).all()
            assert len(rows) == 2
            assert [row.action for row in rows] == ["ban", "unban"]
            assert rows[0].raw_data == logs[0]
            assert all(row.ip == "192.0.2.10" and row.country_code == "US" and row.asn == "64500" for row in rows)
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
            assert conn.execute(text("SELECT count(*) FROM information_schema.schemata WHERE schema_name=:name"),
                                {"name": schema}).scalar() == 0
