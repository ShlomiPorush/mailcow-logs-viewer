"""Suppression detection owns its database work outside the event loop."""
import asyncio
import threading
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from app import scheduler
from app.config import settings


@pytest.fixture
def state(monkeypatch):
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: True)
    for key,value in {
        "suppression_enabled":True,"suppression_auto_detect":True,
        "suppression_rspamd_sync":False,"suppression_hard_bounce_action":"suppress",
        "suppression_whitelist_domains":"","mailcow_api_key_rw":"test-key"
    }.items():
        monkeypatch.setattr(settings._inner,key,value)
    monkeypatch.setattr(scheduler.mailcow_api, "headers_rw", {"X-API-Key":"test-key"})
    monkeypatch.setattr(scheduler, "update_job_status", Mock())
    monkeypatch.setattr(scheduler.mailcow_api, "get_queue", AsyncMock(return_value=[]))
    monkeypatch.setattr(scheduler.mailcow_api, "delete_queue", AsyncMock())


def test_detection_keeps_loop_responsive_and_closes_before_queue(monkeypatch, state):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads,api_threads = [],[]
    db=Mock()
    db.query.return_value.filter.return_value.all.return_value=[
        SimpleNamespace(sender=None,recipient="user@example.com",dsn="5.1.1",message="No mailbox")]
    db.query.return_value.filter.return_value.first.return_value=None
    db.commit.side_effect=lambda:threads.append(threading.get_ident())

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

    async def queue():
        api_threads.append(threading.get_ident())
        assert finished.is_set(), "Queue fetched before the database session closed"
        return [{"queue_id":"ABC1","recipients":["user@example.com"]}]

    monkeypatch.setattr(scheduler,"get_db_context",session)
    monkeypatch.setattr(scheduler.mailcow_api,"get_queue",queue)

    async def run():
        loop_thread=threading.get_ident()
        task=asyncio.create_task(scheduler.detect_suppressions_job())
        try:
            assert await asyncio.to_thread(started.wait,3)
            assert not finished.is_set(), "Suppression detection blocked the event loop"
        finally:
            release.set()
            await task
        assert len(threads)==3 and len(set(threads))==1 and threads[0]!=loop_thread
        assert api_threads==[loop_thread]
        scheduler.mailcow_api.delete_queue.assert_awaited_once_with(["ABC1"])
        row=db.add.call_args.args[0]
        assert row.email=="user@example.com" and row.hard_bounce_count==1 and row.active
        scheduler.update_job_status.assert_called_with("detect_suppressions","success")

    asyncio.run(run())


def test_failed_commit_prevents_queue_cleanup(monkeypatch,state):
    db=Mock()
    db.query.return_value.filter.return_value.all.return_value=[
        SimpleNamespace(sender=None,recipient="user@example.com",dsn="5.1.1",message="No mailbox")]
    db.query.return_value.filter.return_value.first.return_value=None
    db.commit.side_effect=RuntimeError("Database unavailable")

    @contextmanager
    def session():
        yield db

    monkeypatch.setattr(scheduler,"get_db_context",session)
    asyncio.run(scheduler.detect_suppressions_job())
    scheduler.mailcow_api.get_queue.assert_not_awaited()
    scheduler.mailcow_api.delete_queue.assert_not_awaited()
    scheduler.update_job_status.assert_called_with("detect_suppressions","failed","Database unavailable")
