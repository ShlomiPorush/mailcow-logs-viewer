"""Blacklist scan database stages must leave the request loop responsive."""
import asyncio
import threading
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from app import scheduler
from app.services import blacklist_service as service


@pytest.mark.parametrize("stage", ["hosts", "job_cache", "service_cache", "save"])
def test_database_stage_runs_outside_event_loop(monkeypatch, stage):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    worker_threads = []
    session_threads = []
    clean = {"server_ip": "192.0.2.10", "listed_count": 0, "status": "clean", "results": []}

    def block():
        worker_threads.append(threading.get_ident())
        started.set()
        release.wait(2)
        finished.set()

    db = Mock()
    db.query.return_value.filter.return_value.all.return_value = [
        SimpleNamespace(hostname="192.0.2.10", source="config")]

    @contextmanager
    def session():
        session_threads.append(threading.get_ident())
        if stage == "hosts":
            block()
        try:
            yield db
        finally:
            session_threads.append(threading.get_ident())

    def cached(ip):
        if stage in {"job_cache", "service_cache"}:
            block()
        assert ip == "192.0.2.10"
        return clean

    def save(data):
        assert data["server_ip"] == "192.0.2.10" and data["clean_count"] == 1
        block()

    monkeypatch.setattr(scheduler, "get_db_context", session)
    monkeypatch.setattr(scheduler, "update_job_status", Mock())
    monkeypatch.setattr(scheduler, "_blacklist_last_listed_actionable_count", 0)
    monkeypatch.setattr(service, "reconcile_monitored_hosts", Mock())
    monkeypatch.setattr(service, "get_cached_blacklist_check", cached)
    monkeypatch.setattr(service, "save_blacklist_check", save)
    monkeypatch.setattr(service, "applicable_blacklists", lambda ip: [{"name": "test", "zone": "rbl.test"}])
    monkeypatch.setattr(service, "check_ip_in_blacklist", AsyncMock(return_value={
        "name": "test", "zone": "rbl.test", "listed": False, "status": "clean"}))
    monkeypatch.setattr(service, "_batch_state", {"active": False})
    monkeypatch.setattr(service, "_check_progress", {})
    for name in ["start_batch_scan", "end_batch_scan", "mark_host_as_processed_batch"]:
        monkeypatch.setattr(service, name, Mock())

    async def run():
        loop_thread = threading.get_ident()
        if stage in {"hosts", "job_cache"}:
            call = scheduler._run_check_monitored_hosts(False, False)
        else:
            call = service.get_blacklist_check_results(force=stage == "save", ip="192.0.2.10")
        task = asyncio.create_task(call)
        try:
            assert await asyncio.to_thread(started.wait, 3)
            assert not finished.is_set(), f"{stage} blocked the event loop"
        finally:
            release.set()
            result = await task
        assert len(worker_threads) == 1 and worker_threads[0] != loop_thread
        if stage == "hosts":
            assert session_threads == worker_threads * 2
        if stage in {"hosts", "job_cache"}:
            service.check_ip_in_blacklist.assert_not_awaited()
            scheduler.update_job_status.assert_called_with("blacklist_check", "success")
            service.end_batch_scan.assert_called_once()
        elif stage == "service_cache":
            assert result is clean
            service.check_ip_in_blacklist.assert_not_awaited()
        else:
            assert result["status"] == "clean" and result["total_blacklists"] == 1
            service.check_ip_in_blacklist.assert_awaited_once()

    asyncio.run(run())
