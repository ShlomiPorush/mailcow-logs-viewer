"""Deferred cleanup keeps database work off the request loop."""
import asyncio
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock

import pytest

from app import scheduler
from app.config import settings


@pytest.fixture
def state(monkeypatch):
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: True)
    for key, value in {
        "suppression_enabled": True,
        "queue_cleanup_enabled": True,
        "queue_cleanup_threshold_minutes": 30,
        "suppression_rspamd_sync": True,
        "suppression_whitelist_domains": "safe.test",
    }.items():
        monkeypatch.setattr(settings._inner, key, value)
    monkeypatch.setattr(type(settings._inner), "is_rspamd_configured", property(lambda self: True))
    monkeypatch.setattr(scheduler.mailcow_api, "headers_rw", {"X-API-Key": "test-key"})
    monkeypatch.setattr(scheduler, "update_job_status", Mock())
    monkeypatch.setattr(scheduler, "sync_suppressions_to_rspamd_job", AsyncMock())
    old = datetime.now(timezone.utc).timestamp() - 7200
    queue = [
        {"queue_id": "OLD", "queue_name": "deferred", "arrival_time": old,
         "recipients": ["<user@example.com>", "user@example.com", "skip@safe.test"]},
        {"queue_id": "NEW", "queue_name": "deferred", "arrival_time": old + 7200,
         "recipients": ["new@example.com"]},
        {"queue_id": "ACTIVE", "queue_name": "active", "arrival_time": old,
         "recipients": ["active@example.com"]},
    ]
    monkeypatch.setattr(scheduler.mailcow_api, "get_queue", AsyncMock(return_value=queue))
    monkeypatch.setattr(scheduler.mailcow_api, "delete_queue", AsyncMock())
    db = Mock()
    db.query.return_value.filter.return_value.first.return_value = None
    return db


def test_cleanup_is_responsive_and_closes_before_sync(monkeypatch, state):
    started, release, closed = threading.Event(), threading.Event(), threading.Event()
    threads = []
    state.commit.side_effect = lambda: threads.append(threading.get_ident())

    @contextmanager
    def session():
        scheduler.mailcow_api.delete_queue.assert_awaited_once_with(["OLD"])
        threads.append(threading.get_ident())
        started.set()
        release.wait(2)
        try:
            yield state
        finally:
            threads.append(threading.get_ident())
            closed.set()

    async def sync():
        assert closed.is_set()

    monkeypatch.setattr(scheduler, "get_db_context", session)
    scheduler.sync_suppressions_to_rspamd_job.side_effect = sync

    async def run():
        loop_thread = threading.get_ident()
        task = asyncio.create_task(scheduler.cleanup_deferred_queue_job())
        try:
            assert await asyncio.to_thread(started.wait, 3)
            assert not closed.is_set(), "Deferred cleanup blocked the event loop"
        finally:
            release.set()
            await task
        assert len(threads) == 3 and len(set(threads)) == 1
        assert threads[0] != loop_thread

    asyncio.run(run())
    state.add.assert_called_once()
    row = state.add.call_args.args[0]
    assert row.email == "user@example.com" and row.soft_bounce_count == 1
    assert row.active and row.reason == "deferred_stuck"
    scheduler.sync_suppressions_to_rspamd_job.assert_awaited_once()
    scheduler.update_job_status.assert_called_with("cleanup_deferred_queue", "success")


def test_delete_failure_prevents_database_work(monkeypatch, state):
    session = Mock()
    monkeypatch.setattr(scheduler, "get_db_context", session)
    scheduler.mailcow_api.delete_queue.side_effect = RuntimeError("Delete failed")
    asyncio.run(scheduler.cleanup_deferred_queue_job())
    session.assert_not_called()
    scheduler.sync_suppressions_to_rspamd_job.assert_not_awaited()
    scheduler.update_job_status.assert_called_with(
        "cleanup_deferred_queue", "failed", "Queue delete failed: Delete failed")


def test_commit_failure_prevents_sync(monkeypatch, state):
    @contextmanager
    def session():
        yield state

    state.commit.side_effect = RuntimeError("Commit failed")
    monkeypatch.setattr(scheduler, "get_db_context", session)
    asyncio.run(scheduler.cleanup_deferred_queue_job())
    scheduler.mailcow_api.delete_queue.assert_awaited_once_with(["OLD"])
    scheduler.sync_suppressions_to_rspamd_job.assert_not_awaited()
    scheduler.update_job_status.assert_called_with("cleanup_deferred_queue", "failed", "Commit failed")
