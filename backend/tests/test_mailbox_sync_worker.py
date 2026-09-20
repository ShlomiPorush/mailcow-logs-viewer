"""Mailbox synchronization must not block the event loop on persistence."""
import asyncio
import threading
from contextlib import contextmanager
from unittest.mock import AsyncMock, Mock

import pytest

from app import scheduler


@pytest.fixture
def state(monkeypatch):
    monkeypatch.setattr(scheduler, "_mailbox_sync_needed", lambda: True)
    monkeypatch.setattr(scheduler, "update_job_status", Mock())


def test_database_work_keeps_loop_responsive(monkeypatch, state):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads, api_threads = [], []
    db = Mock()
    db.query.return_value.filter.return_value.first.return_value = None
    db.query.return_value.all.return_value = []
    db.commit.side_effect = lambda: threads.append(threading.get_ident())

    async def mailboxes():
        api_threads.append(threading.get_ident())
        return [{"username": "user@example.com", "quota": "100", "rl": {"value": "20", "frame": "h"}}]

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

    monkeypatch.setattr(scheduler.mailcow_api, "get_mailboxes", mailboxes)
    monkeypatch.setattr(scheduler, "get_db_context", session)

    async def run():
        loop_thread = threading.get_ident()
        task = asyncio.create_task(scheduler.update_mailbox_statistics())
        try:
            assert await asyncio.to_thread(started.wait, 3)
            assert not finished.is_set(), "Mailbox persistence blocked the event loop"
        finally:
            release.set()
            await task
        assert api_threads == [loop_thread]
        assert len(threads) == 3 and len(set(threads)) == 1 and threads[0] != loop_thread
        db.add.assert_called_once()
        row = db.add.call_args.args[0]
        assert row.username == "user@example.com"
        assert row.quota == 100 and row.rl_value == 20 and row.rl_frame == "h"
        scheduler.update_job_status.assert_called_with("mailbox_stats", "success")

    asyncio.run(run())




def test_empty_response_preserves_existing_mailboxes(monkeypatch, state):
    monkeypatch.setattr(scheduler.mailcow_api, "get_mailboxes", AsyncMock(return_value=[]))
    session = Mock()
    monkeypatch.setattr(scheduler, "get_db_context", session)
    asyncio.run(scheduler.update_mailbox_statistics())
    session.assert_not_called()
    scheduler.update_job_status.assert_called_with("mailbox_stats", "success")


def test_database_failure_sets_failed_status(monkeypatch, state):
    monkeypatch.setattr(scheduler.mailcow_api, "get_mailboxes", AsyncMock(return_value=[{"username": "user@example.com"}]))
    monkeypatch.setattr(scheduler, "get_db_context", Mock(side_effect=RuntimeError("Database unavailable")))
    asyncio.run(scheduler.update_mailbox_statistics())
    scheduler.update_job_status.assert_called_with("mailbox_stats", "failed", "Database unavailable")
