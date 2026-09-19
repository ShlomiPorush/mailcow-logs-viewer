"""Status refresh owns its database session in a worker."""
import asyncio
import threading
from contextlib import contextmanager
from unittest.mock import Mock


from app import scheduler


def test_status_refresh_leaves_event_loop_responsive(monkeypatch):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads = []
    db = Mock()
    query = db.query.return_value.filter.return_value.limit.return_value
    query.all.return_value = [Mock(id=1)]
    monkeypatch.setattr(scheduler, "_recompute_correlation_from_postfix", lambda db, row: True)
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
        task = asyncio.create_task(scheduler.update_final_status_for_correlations())
        try:
            assert await asyncio.to_thread(started.wait, 3)
            await asyncio.sleep(0)
            assert not finished.is_set(), "status refresh blocked the event loop"
        finally:
            release.set()
            await task
        assert len(set(threads)) == 1 and threads[0] != loop_thread
        assert scheduler.job_status["update_final_status"]["status"] == "success"
    asyncio.run(run())


def test_status_refresh_reports_database_failure(monkeypatch):
    @contextmanager
    def session():
        raise RuntimeError("fixture database failure")
        yield
    monkeypatch.setattr(scheduler, "get_db_context", session)
    monkeypatch.setattr(scheduler, "job_status", {})
    asyncio.run(scheduler.update_final_status_for_correlations())
    assert scheduler.job_status["update_final_status"]["status"] == "failed"
    assert scheduler.job_status["update_final_status"]["error"] == "fixture database failure"


