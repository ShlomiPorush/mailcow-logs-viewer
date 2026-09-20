"""Monitored-host persistence must not block asynchronous source discovery."""
import asyncio
import threading
from contextlib import contextmanager
from unittest.mock import AsyncMock, Mock

import pytest

from app import scheduler
from app.config import settings


@pytest.fixture
def state(monkeypatch):
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: True)
    monkeypatch.setattr(settings._inner, "mailcow_url", "https://mail.example.test")
    monkeypatch.setattr(settings._inner, "mailcow_api_key", "test-key")
    monkeypatch.setattr(settings._inner, "blacklist_source_transports", True)
    monkeypatch.setattr(settings._inner, "blacklist_source_relayhosts", False)
    monkeypatch.setattr(settings._inner, "blacklist_source_server_ip", False)
    monkeypatch.setattr(settings._inner, "blacklist_source_manual_hosts", "192.0.2.10")
    monkeypatch.setattr(scheduler.mailcow_api, "get_transports", AsyncMock(return_value=[]))
    monkeypatch.setattr(scheduler, "update_job_status", Mock())
    check = AsyncMock()
    monkeypatch.setattr(scheduler, "check_monitored_hosts_job", check)
    return check


def test_database_work_keeps_loop_responsive(monkeypatch, state):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads, api_threads = [], []
    db = Mock()
    db.query.return_value.all.return_value = []
    db.commit.side_effect = lambda: threads.append(threading.get_ident())

    async def transports():
        api_threads.append(threading.get_ident())
        return []

    async def check(**kwargs):
        assert finished.is_set(), "Blacklist check started before the session closed"

    state.side_effect = check

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

    monkeypatch.setattr(scheduler.mailcow_api, "get_transports", transports)
    monkeypatch.setattr(scheduler, "get_db_context", session)

    async def run():
        loop_thread = threading.get_ident()
        task = asyncio.create_task(scheduler.sync_transports_job())
        try:
            assert await asyncio.to_thread(started.wait, 3)
            assert not finished.is_set(), "Transport persistence blocked the event loop"
        finally:
            release.set()
            await task
        assert api_threads == [loop_thread]
        assert len(threads) == 3 and len(set(threads)) == 1 and threads[0] != loop_thread
        db.add.assert_called_once()
        row = db.add.call_args.args[0]
        assert row.hostname == "192.0.2.10" and row.source == "config" and row.active
        state.assert_awaited_once_with(force=False, send_notification=False)
        scheduler.update_job_status.assert_called_with("sync_transports", "success")

    asyncio.run(run())


def test_failed_commit_does_not_trigger_blacklist_check(monkeypatch, state):
    db = Mock()
    db.query.return_value.all.return_value = []
    db.commit.side_effect = RuntimeError("Database unavailable")

    @contextmanager
    def session():
        yield db

    monkeypatch.setattr(scheduler, "get_db_context", session)
    asyncio.run(scheduler.sync_transports_job())
    state.assert_not_awaited()
    scheduler.update_job_status.assert_called_with("sync_transports", "failed", "Database unavailable")
