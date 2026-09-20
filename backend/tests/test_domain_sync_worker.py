"""Local-domain synchronization must not block the event loop on persistence."""
import asyncio
import threading
from contextlib import contextmanager
from unittest.mock import AsyncMock, Mock

import pytest

from app import scheduler
from app.services import alias_domains


@pytest.fixture
def state(monkeypatch):
    monkeypatch.setattr(scheduler.mailcow_api, "get_active_domains", AsyncMock(return_value=["primary.test"]))
    monkeypatch.setattr(scheduler.mailcow_api, "get_alias_domain_map", AsyncMock(return_value={"alias.test": "primary.test"}))
    active, cached = Mock(), Mock()
    monkeypatch.setattr(scheduler, "set_cached_active_domains", active)
    monkeypatch.setattr(alias_domains, "set_cached_alias_domain_map", cached)
    monkeypatch.setattr(scheduler, "update_job_status", Mock())
    return active, cached


def test_database_work_keeps_loop_responsive(monkeypatch, state):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads, api_threads = [], []
    db = Mock()
    db.query.return_value.filter.return_value.first.return_value = None
    db.commit.side_effect = lambda: threads.append(threading.get_ident())

    async def domains():
        api_threads.append(threading.get_ident())
        return ["primary.test"]

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

    monkeypatch.setattr(scheduler.mailcow_api, "get_active_domains", domains)
    monkeypatch.setattr(scheduler, "get_db_context", session)

    async def run():
        loop_thread = threading.get_ident()
        task = asyncio.create_task(scheduler.sync_local_domains())
        try:
            assert await asyncio.to_thread(started.wait, 3)
            assert not finished.is_set(), "Domain persistence blocked the event loop"
            state[1].assert_not_called()
        finally:
            release.set()
            result = await task
        assert result is True
        assert api_threads == [loop_thread]
        assert len(threads) == 3 and len(set(threads)) == 1 and threads[0] != loop_thread
        state[0].assert_called_once_with(["primary.test", "alias.test"])
        state[1].assert_called_once_with({"alias.test": "primary.test"})
        db.add.assert_called_once()
        assert db.add.call_args.args[0].value == '{"alias.test": "primary.test"}'

    asyncio.run(run())


def test_failed_commit_keeps_previous_alias_cache(monkeypatch, state):
    db = Mock()
    db.query.return_value.filter.return_value.first.return_value = None
    db.commit.side_effect = RuntimeError("Database unavailable")

    @contextmanager
    def session():
        yield db

    monkeypatch.setattr(scheduler, "get_db_context", session)
    assert asyncio.run(scheduler.sync_local_domains()) is True
    state[0].assert_called_once_with(["primary.test", "alias.test"])
    state[1].assert_not_called()


def test_no_domains_does_not_replace_persisted_mapping(monkeypatch, state):
    monkeypatch.setattr(scheduler.mailcow_api, "get_active_domains", AsyncMock(return_value=[]))
    monkeypatch.setattr(scheduler.mailcow_api, "get_alias_domain_map", AsyncMock(return_value={}))
    session = Mock()
    monkeypatch.setattr(scheduler, "get_db_context", session)
    assert asyncio.run(scheduler.sync_local_domains()) is False
    session.assert_not_called()
    state[0].assert_not_called()
    state[1].assert_not_called()
