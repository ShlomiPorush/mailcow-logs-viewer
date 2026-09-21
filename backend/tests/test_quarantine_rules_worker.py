"""Quarantine rules own blocking work and network clients in a worker."""
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
    monkeypatch.setattr(settings._inner, "quarantine_rules_max_actions", 2)
    monkeypatch.setattr(settings._inner, "quarantine_rules_log_retention_days", 7)
    monkeypatch.setattr(scheduler.mailcow_api, "headers_rw", {"X-API-Key": "test-key"})
    monkeypatch.setattr(scheduler.mailcow_api, "aclose", AsyncMock())
    monkeypatch.setattr(scheduler, "update_job_status", Mock())
    rules = [
        SimpleNamespace(id=1, name="Allow", match_type="sender_domain", match_value="example.com",
                        is_regex=False, action="release", hit_count=0),
        SimpleNamespace(id=2, name="Deny", match_type="subject", match_value="blocked",
                        is_regex=False, action="delete", hit_count=0),
    ]
    db = Mock()
    db.query.return_value.filter.return_value.all.return_value = rules
    db.query.return_value.filter.return_value.first.side_effect = rules
    items = [
        {"id": "DELETE", "sender": "user@example.com", "rcpt": "recipient@example.com", "subject": "blocked"},
        {"id": "RELEASE", "sender": "user@example.com", "rcpt": "recipient@example.com", "subject": "allowed"},
        {"id": "LIMIT", "sender": "user@example.com", "subject": "allowed"},
    ]
    monkeypatch.setattr(scheduler.mailcow_api, "get_quarantine", AsyncMock(return_value=items))
    monkeypatch.setattr(scheduler.mailcow_api, "release_quarantine", AsyncMock())
    monkeypatch.setattr(scheduler.mailcow_api, "delete_quarantine", AsyncMock())
    return db


@pytest.mark.parametrize("stage", ["query", "commit"])
def test_quarantine_job_remains_responsive(monkeypatch, state, stage):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads, actions = [], []

    def block():
        started.set()
        release.wait(2)
        finished.set()

    @contextmanager
    def session():
        threads.append(threading.get_ident())
        if stage == "query":
            block()
        try:
            yield state
        finally:
            threads.append(threading.get_ident())

    def commit():
        threads.append(threading.get_ident())
        if stage == "commit":
            block()

    async def released(ids):
        actions.append(("release", ids, threading.get_ident()))

    async def deleted(ids):
        actions.append(("delete", ids, threading.get_ident()))

    state.commit.side_effect = commit
    scheduler.mailcow_api.release_quarantine.side_effect = released
    scheduler.mailcow_api.delete_quarantine.side_effect = deleted
    monkeypatch.setattr(scheduler, "get_db_context", session)

    async def run():
        loop_thread = threading.get_ident()
        task = asyncio.create_task(scheduler.process_quarantine_rules_job())
        try:
            assert await asyncio.to_thread(started.wait, 3)
            assert not finished.is_set(), f"Quarantine {stage} blocked the event loop"
        finally:
            release.set()
            await task
        assert len(threads) == 3 and len(set(threads)) == 1 and threads[0] != loop_thread
        assert actions == [("release", ["RELEASE"], threads[0]), ("delete", ["DELETE"], threads[0])]

    asyncio.run(run())
    assert state.add.call_count == 2
    logs = [call.args[0] for call in state.add.call_args_list]
    assert [(log.quarantine_id, log.action) for log in logs] == [("DELETE", "delete"), ("RELEASE", "release")]
    state.query.return_value.filter.return_value.delete.assert_called_once_with(synchronize_session=False)
    scheduler.mailcow_api.aclose.assert_awaited_once()
    scheduler.update_job_status.assert_called_with("process_quarantine_rules", "success")


def test_commit_failure_closes_resources(monkeypatch, state):
    closed = []

    @contextmanager
    def session():
        try:
            yield state
        finally:
            closed.append(True)

    state.commit.side_effect = RuntimeError("Commit failed")
    monkeypatch.setattr(scheduler, "get_db_context", session)
    asyncio.run(scheduler.process_quarantine_rules_job())
    assert closed == [True]
    scheduler.mailcow_api.aclose.assert_awaited_once()
    scheduler.update_job_status.assert_called_with("process_quarantine_rules", "failed", "Commit failed")
