"""GeoIP license persistence must not block the event loop."""
import asyncio
import threading
from contextlib import contextmanager
from unittest.mock import Mock

import pytest

from app import scheduler
from app.services import geoip_downloader


@pytest.fixture
def state(monkeypatch):
    monkeypatch.setattr(geoip_downloader, "is_license_configured", lambda: True)
    monkeypatch.setattr(geoip_downloader, "update_geoip_database_if_needed",
                        lambda: {"City": {"updated": True, "available": True},
                                 "ASN": {"updated": False, "available": False}})
    monkeypatch.setattr(scheduler.geoip_service, "reload_geoip_readers", Mock())
    monkeypatch.setattr(scheduler, "update_job_status", Mock())


def test_database_work_keeps_loop_responsive(monkeypatch, state):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads = []
    db = Mock()
    db.query.return_value.filter.return_value.first.return_value = None
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

    async def run():
        loop_thread = threading.get_ident()
        task = asyncio.create_task(scheduler.update_geoip_database())
        try:
            assert await asyncio.to_thread(started.wait, 3)
            assert not finished.is_set(), "GeoIP persistence blocked the event loop"
        finally:
            release.set()
            await task
        assert len(threads) == 3 and len(set(threads)) == 1 and threads[0] != loop_thread
        assert db.add.call_count == 4
        scheduler.geoip_service.reload_geoip_readers.assert_called_once()
        scheduler.update_job_status.assert_called_with("update_geoip", "success")

    asyncio.run(run())


def test_persistence_failure_remains_best_effort(monkeypatch, state):
    monkeypatch.setattr(scheduler, "get_db_context", Mock(side_effect=RuntimeError("Database unavailable")))
    asyncio.run(scheduler.update_geoip_database())
    scheduler.geoip_service.reload_geoip_readers.assert_called_once()
    scheduler.update_job_status.assert_called_with("update_geoip", "success")


def test_no_available_database_does_not_persist_license(monkeypatch, state):
    monkeypatch.setattr(geoip_downloader, "update_geoip_database_if_needed",
                        lambda: {"City": {"updated": False, "available": False},
                                 "ASN": {"updated": False, "available": False}})
    monkeypatch.setattr(scheduler.geoip_service, "get_geoip_db_valid", lambda: True)
    session = Mock()
    monkeypatch.setattr(scheduler, "get_db_context", session)
    asyncio.run(scheduler.update_geoip_database())
    session.assert_not_called()
    scheduler.geoip_service.reload_geoip_readers.assert_not_called()
