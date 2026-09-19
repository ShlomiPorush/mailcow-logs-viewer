"""Dovecot correlation owns its database session in a worker."""
import asyncio
import threading
from contextlib import contextmanager
from unittest.mock import Mock


from app import scheduler


def test_dovecot_leaves_event_loop_responsive(monkeypatch):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads = []
    db = Mock()
    query = db.query.return_value.filter.return_value
    query.first.return_value = None
    query.order_by.return_value.limit.return_value.all.return_value = []
    monkeypatch.setattr(scheduler, "dovecot_correlation_available", lambda: True)
    monkeypatch.setattr(scheduler, "_dovecot_pending", {})
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
    monkeypatch.setattr(scheduler, "job_status", {})
    async def run():
        loop_thread = threading.get_ident()
        task = asyncio.create_task(scheduler.correlate_dovecot_logs())
        try:
            assert await asyncio.to_thread(started.wait, 3)
            await asyncio.sleep(0)
            assert not finished.is_set(), "dovecot blocked the event loop"
        finally:
            release.set()
            await task
        assert len(set(threads)) == 1 and threads[0] != loop_thread
        assert scheduler.job_status["correlate_dovecot"]["status"] == "success"
    asyncio.run(run())


def test_dovecot_reports_database_failure(monkeypatch):
    monkeypatch.setattr(scheduler, "dovecot_correlation_available", lambda: True)
    @contextmanager
    def session():
        raise RuntimeError("fixture database failure")
        yield
    monkeypatch.setattr(scheduler, "get_db_context", session)
    monkeypatch.setattr(scheduler, "job_status", {})
    asyncio.run(scheduler.correlate_dovecot_logs())
    assert scheduler.job_status["correlate_dovecot"]["status"] == "failed"
    assert scheduler.job_status["correlate_dovecot"]["error"] == "fixture database failure"


def test_overlapping_runs_serialize_and_release_after_error(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import pytest
    first_started, release_first, second_attempted = threading.Event(), threading.Event(), threading.Event()
    calls = []
    def process():
        calls.append(threading.get_ident())
        if len(calls) == 1:
            first_started.set()
            assert release_first.wait(3)
            raise RuntimeError("fixture failure")
    monkeypatch.setattr(scheduler, "_correlate_dovecot_logs_sync", process)
    class ObservedLock:
        def __init__(self):
            self.lock = threading.Lock()
            self.attempts = 0
        def __enter__(self):
            self.attempts += 1
            if self.attempts == 2:
                second_attempted.set()
            return self.lock.__enter__()
        def __exit__(self, *args):
            return self.lock.__exit__(*args)
    monkeypatch.setattr(scheduler, "_dovecot_correlation_lock", ObservedLock())
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(scheduler._run_dovecot_correlation_worker)
        try:
            assert first_started.wait(3)
            next_run = pool.submit(scheduler._run_dovecot_correlation_worker)
            assert second_attempted.wait(3)
            assert len(calls) == 1
        finally:
            release_first.set()
        with pytest.raises(RuntimeError, match="fixture failure"):
            first.result(timeout=3)
        next_run.result(timeout=3)
    assert len(calls) == 2


def test_disabled_dovecot_does_not_access_database(monkeypatch):
    monkeypatch.setattr(scheduler, "dovecot_correlation_available", lambda: False)
    session = Mock(side_effect=AssertionError("disabled job accessed database"))
    monkeypatch.setattr(scheduler, "get_db_context", session)
    monkeypatch.setattr(scheduler, "job_status", {})
    asyncio.run(scheduler.correlate_dovecot_logs())
    session.assert_not_called()
    assert scheduler.job_status["correlate_dovecot"]["status"] == "success"
