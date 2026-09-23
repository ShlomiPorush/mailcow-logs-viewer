"""Background database and filesystem waits leave the application loop runnable."""
import asyncio
import threading
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from app import raw_logs_worker as raw, scheduler
from app.config import settings
from app.services import geoip_downloader


async def assert_responsive(operation, started, release, finished):
    task = asyncio.create_task(operation())
    try:
        assert await asyncio.to_thread(started.wait, 3)
        assert not finished.is_set(), "Background I/O blocked the application loop"
        await asyncio.sleep(0)
        assert not finished.is_set()
    finally:
        release.set()
        await task


@pytest.mark.parametrize("job", ["collect", "counts", "retention"])
@pytest.mark.parametrize("stage", ["query", "commit"])
def test_raw_database_lifetime_is_owned_by_worker(monkeypatch, job, stage):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads, lifetimes = [], []
    db = Mock()
    query = db.query.return_value
    query.filter.return_value.all.return_value = []
    query.filter.return_value.first.return_value = None
    query.filter.return_value.delete.return_value = 1
    query.group_by.return_value.all.return_value = [("dovecot", 1)]

    def block(*args):
        threads.append(threading.get_ident())
        started.set()
        release.wait(2)
        finished.set()
        return query
    getattr(db, stage).side_effect = block

    @contextmanager
    def session():
        owner = threading.get_ident()
        lifetimes.append(("open", owner))
        try:
            yield db
            db.commit()
        finally:
            lifetimes.append(("close", threading.get_ident()))

    monkeypatch.setattr(raw, "get_db_context", session)
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: True)
    monkeypatch.setattr(settings._inner, "raw_logs_enabled", True)
    monkeypatch.setattr(settings._inner, "raw_logs_services", "dovecot")
    monkeypatch.setattr(raw, "_catchup_state", {})
    monkeypatch.setattr(raw, "_unavailable_services", set())
    api = SimpleNamespace(get_raw_logs=AsyncMock(return_value=[{
        "time": 1700000000, "message": "Example log"}]), aclose=AsyncMock())
    monkeypatch.setattr(raw, "mailcow_api", api)

    async def run():
        loop_thread = threading.get_ident()
        async def fetch(*args, **kwargs):
            assert threading.get_ident() == loop_thread
            return [{"time": 1700000000, "message": "Example log"}]
        api.get_raw_logs.side_effect = fetch
        async def broadcast(*args):
            assert threading.get_ident() == loop_thread
            assert lifetimes[-1][0] == "close"
        monkeypatch.setattr(raw, "_ws_broadcast_fn", AsyncMock(side_effect=broadcast))
        monkeypatch.setattr(raw, "_ws_broadcast_all_fn", AsyncMock(side_effect=broadcast) if job == "counts" else None)
        operation = {"collect": raw.fetch_raw_service_logs,
                     "counts": raw._broadcast_service_counts,
                     "retention": raw.cleanup_raw_service_logs}[job]
        await assert_responsive(operation, started, release, finished)
        assert threads and all(t != loop_thread for t in threads)
        assert lifetimes[0][1] == lifetimes[-1][1] == threads[0]
        if job == "collect":
            api.aclose.assert_not_awaited()
            raw._ws_broadcast_fn.assert_awaited_once()
            assert raw.raw_logs_job_status['fetch_raw_logs']['stats'] == {"dovecot": 1}
        elif job == "counts":
            raw._ws_broadcast_all_fn.assert_awaited_once_with({"type": "service_counts", "counts": {"dovecot": 1}})
        else:
            assert raw.raw_logs_job_status['cleanup_raw_logs']['status'] == 'success'
    asyncio.run(run())


@pytest.mark.parametrize("fail", [False, True])
def test_dmarc_stale_cleanup_is_off_loop_and_best_effort(monkeypatch, fail):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads = []
    db = Mock()
    def commit():
        threads.append(threading.get_ident())
        started.set()
        release.wait(2)
        finished.set()
        if fail:
            raise RuntimeError("Database unavailable")
    db.commit.side_effect = commit
    @contextmanager
    def session():
        yield db
    monkeypatch.setattr(scheduler, "SessionLocal", session)
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: True)
    monkeypatch.setattr(settings._inner, "dmarc_imap_enabled", True)
    sync = Mock(return_value={"status": "success", "reports_created": 0})
    monkeypatch.setattr(scheduler, "sync_dmarc_reports_from_imap", sync)
    monkeypatch.setattr(scheduler, "update_job_status", Mock())
    async def run():
        loop_thread = threading.get_ident()
        await assert_responsive(scheduler.dmarc_imap_sync_job, started, release, finished)
        assert threads[0] != loop_thread
        sync.assert_called_once_with('auto')
        scheduler.update_job_status.assert_called_with('dmarc_imap_sync', 'success')
    asyncio.run(run())


@pytest.mark.parametrize("updated", [False, True])
def test_geoip_reload_is_off_loop(monkeypatch, updated):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads = []
    def reload():
        threads.append(threading.get_ident())
        started.set()
        release.wait(2)
        finished.set()
    monkeypatch.setattr(geoip_downloader, "is_license_configured", lambda: True)
    monkeypatch.setattr(geoip_downloader, "update_geoip_database_if_needed", lambda: {
        "City": {"updated": updated, "available": False}, "ASN": {"updated": False, "available": False}})
    monkeypatch.setattr(scheduler.geoip_service, "get_geoip_db_valid", lambda: None)
    monkeypatch.setattr(scheduler.geoip_service, "reload_geoip_readers", reload)
    monkeypatch.setattr(scheduler, "update_job_status", Mock())
    async def run():
        loop_thread = threading.get_ident()
        await assert_responsive(scheduler.update_geoip_database, started, release, finished)
        assert threads[0] != loop_thread
        scheduler.update_job_status.assert_called_with('update_geoip', 'success')
    asyncio.run(run())
