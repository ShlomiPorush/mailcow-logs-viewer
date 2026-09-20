"""Background DNS persistence runs outside the event loop."""
import asyncio
import threading
from contextlib import contextmanager
from unittest.mock import AsyncMock, Mock

import pytest

from app import scheduler
from app.config import settings
from app.routers import domains


@pytest.fixture
def state(monkeypatch):
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: True)
    monkeypatch.setattr(settings._inner, "dns_change_alerts_enabled", False)
    monkeypatch.setattr(scheduler.mailcow_api, "get_domains", AsyncMock(return_value=[{"domain_name":"example.com","active":1}]))
    monkeypatch.setattr(scheduler.mailcow_api, "get_alias_domain_map", AsyncMock(return_value={}))
    monkeypatch.setattr(domains, "get_spf_source_ips", AsyncMock(return_value=[]))
    monkeypatch.setattr(scheduler, "check_domain_dns", AsyncMock(return_value={"spf":{"valid":True}}))
    monkeypatch.setattr(scheduler, "update_job_status", Mock())


def test_persistence_keeps_loop_responsive(monkeypatch, state):
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
        task = asyncio.create_task(scheduler.check_all_domains_dns_background())
        try:
            assert await asyncio.to_thread(started.wait, 3)
            assert not finished.is_set(), "DNS persistence blocked the event loop"
        finally:
            release.set()
            await task
        assert len(threads) == 3 and len(set(threads)) == 1 and threads[0] != loop_thread
        row = db.add.call_args.args[0]
        assert row.domain_name == "example.com" and row.is_full_check
        assert row.spf_check == {"valid":True}

    asyncio.run(run())


def test_notification_follows_commit(monkeypatch, state):
    monkeypatch.setattr(settings._inner, "dns_change_alerts_enabled", True)
    db = Mock()
    db.query.return_value.filter.return_value.first.return_value = None
    events = []
    db.commit.side_effect = lambda: events.append("commit")
    monkeypatch.setattr(domains, "detect_dns_changes", lambda previous, data: [{"type":"spf"}])
    monkeypatch.setattr(domains, "notify_dns_changes", lambda *args: events.append("notify"))

    @contextmanager
    def session():
        try:
            yield db
        finally:
            events.append("close")

    monkeypatch.setattr(scheduler, "get_db_context", session)
    asyncio.run(scheduler.check_all_domains_dns_background())
    assert events == ["commit", "notify", "close"]


def test_failed_save_rolls_back_and_continues_to_alias(monkeypatch, state):
    monkeypatch.setattr(scheduler.mailcow_api, "get_alias_domain_map", AsyncMock(return_value={"alias.test":"example.com"}))
    db = Mock()
    db.query.return_value.filter.return_value.first.return_value = None
    db.commit.side_effect = [RuntimeError("Database unavailable"), None]

    @contextmanager
    def session():
        yield db

    monkeypatch.setattr(scheduler, "get_db_context", session)
    asyncio.run(scheduler.check_all_domains_dns_background())
    assert db.commit.call_count == 2
    db.rollback.assert_called_once()
    assert [c.args[0].domain_name for c in db.add.call_args_list] == ["example.com","alias.test"]
    scheduler.update_job_status.assert_called_with("dns_check","success")
