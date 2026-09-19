"""Correlation work stays off the event loop and owns its session."""
import asyncio
import threading
from contextlib import contextmanager
from unittest.mock import Mock, AsyncMock

from app import scheduler


def test_correlation_keeps_loop_responsive(monkeypatch):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads = []
    db = Mock()
    row = Mock(id=1, sender_smtp="sender@example.com", recipients_smtp=[])
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [row]
    def correlate(session, record):
        assert session is db and record is row
        threads.append(threading.get_ident())
        session.commit()
        return True
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
    monkeypatch.setattr(scheduler, "cleanup_blacklisted_queues", AsyncMock())
    monkeypatch.setattr(scheduler, "is_blacklisted", lambda email: False)
    monkeypatch.setattr(scheduler, "correlate_single_message", correlate)
    async def run():
        loop_thread = threading.get_ident()
        task = asyncio.create_task(scheduler.run_correlation())
        try:
            assert await asyncio.to_thread(started.wait, 3)
            await asyncio.sleep(0)
            assert not finished.is_set(), "correlation blocked the event loop"
        finally:
            release.set()
            await task
        assert len(threads) == 4
        assert len(set(threads)) == 1 and threads[0] != loop_thread
        db.commit.assert_called_once()
    asyncio.run(run())


def test_failed_record_rolls_back_before_next_record(monkeypatch):
    db = Mock()
    rows = [Mock(id=1, sender_smtp="sender@example.com", recipients_smtp=[]),
            Mock(id=2, sender_smtp="sender@example.com", recipients_smtp=[])]
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = rows
    events = []
    def correlate(session, row):
        events.append(row.id)
        if row.id == 1:
            raise RuntimeError("fixture failure")
        return True
    db.rollback.side_effect = lambda: events.append("rollback")
    @contextmanager
    def session():
        yield db
        events.append("closed")
    monkeypatch.setattr(scheduler, "get_db_context", session)
    monkeypatch.setattr(scheduler, "cleanup_blacklisted_queues", AsyncMock())
    monkeypatch.setattr(scheduler, "is_blacklisted", lambda email: False)
    monkeypatch.setattr(scheduler, "correlate_single_message", correlate)
    asyncio.run(scheduler.run_correlation())
    assert events == [1, "rollback", 2, "closed"]
