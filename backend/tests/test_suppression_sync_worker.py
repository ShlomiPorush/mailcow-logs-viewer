"""Both suppression sync entry points keep blocking work off the request loop."""
import asyncio
import threading
from contextlib import contextmanager
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import HTTPException

from app import scheduler
from app.config import settings
from app.routers import suppressions


@pytest.fixture
def state(monkeypatch):
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: True)
    monkeypatch.setattr(type(settings._inner), "is_rspamd_configured", property(lambda self: True))
    for key, value in {"suppression_enabled": True, "suppression_rspamd_sync": True,
                       "mailcow_api_key_rw": "test-key"}.items():
        monkeypatch.setattr(settings._inner, key, value)
    monkeypatch.setattr(suppressions.mailcow_api, "headers_rw", {"X-API-Key": "test-key"})
    monkeypatch.setattr(suppressions.mailcow_api, "aclose", AsyncMock())
    monkeypatch.setattr(scheduler, "update_job_status", Mock())


@pytest.mark.parametrize("manual", [False, True])
def test_sync_entry_point_uses_worker_and_closes_client(monkeypatch, state, manual):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    session_threads, sync_threads, close_threads = [], [], []
    db = Mock()
    result = {"success": True, "synced": 1, "skipped": True}

    @contextmanager
    def session():
        session_threads.append(threading.get_ident())
        try:
            yield db
        finally:
            session_threads.append(threading.get_ident())

    async def sync(session_db):
        sync_threads.append(threading.get_ident())
        started.set()
        release.wait(2)
        finished.set()
        return result

    async def close():
        close_threads.append(threading.get_ident())

    monkeypatch.setattr(scheduler, "get_db_context", session)
    monkeypatch.setattr(suppressions, "get_db_context", session, raising=False)
    monkeypatch.setattr(suppressions, "sync_suppressions_to_rspamd", sync)
    suppressions.mailcow_api.aclose.side_effect = close

    async def run():
        loop_thread = threading.get_ident()
        call = suppressions.manual_sync_to_rspamd() if manual else scheduler.sync_suppressions_to_rspamd_job()
        task = asyncio.create_task(call)
        try:
            assert await asyncio.to_thread(started.wait, 3)
            assert not finished.is_set(), "Suppression synchronization blocked the event loop"
        finally:
            release.set()
            value = await task
        assert sync_threads == close_threads
        assert session_threads == sync_threads * 2
        assert sync_threads[0] != loop_thread
        if manual:
            assert value == result
        else:
            scheduler.update_job_status.assert_called_with("sync_suppressions", "success")

    asyncio.run(run())
    suppressions.mailcow_api.aclose.assert_awaited_once()


@pytest.mark.parametrize("manual", [False, True])
def test_failed_sync_closes_session_and_client(monkeypatch, state, manual):
    closed = []

    @contextmanager
    def session():
        try:
            yield Mock()
        finally:
            closed.append(True)

    monkeypatch.setattr(suppressions, "get_db_context", session, raising=False)
    monkeypatch.setattr(scheduler, "get_db_context", session)
    monkeypatch.setattr(suppressions, "sync_suppressions_to_rspamd",
                        AsyncMock(side_effect=suppressions.MailcowAPIError("Map write failed")))
    if manual:
        with pytest.raises(HTTPException) as error:
            asyncio.run(suppressions.manual_sync_to_rspamd())
        assert error.value.status_code == 502
    else:
        asyncio.run(scheduler.sync_suppressions_to_rspamd_job())
        scheduler.update_job_status.assert_called_with("sync_suppressions", "failed", "Map write failed")
    assert closed == [True]
    suppressions.mailcow_api.aclose.assert_awaited_once()
