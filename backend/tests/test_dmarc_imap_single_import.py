"""One IMAP import of DMARC and TLS reports at a time.

Fetch reports, the scheduled run and Status > Run now all start the same
import. A second start while one runs must not mark the running one as
failed, nor read the mailbox a second time.
"""
import asyncio
import threading
from unittest.mock import MagicMock, Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import scheduler
from app.config import settings
from app.routers import dmarc
from app.services import dmarc_imap_service


@pytest.fixture
def imap(monkeypatch):
    monkeypatch.setattr(settings._inner, "dmarc_imap_enabled", True)
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: True)
    started, release = threading.Event(), threading.Event()
    calls = []

    def slow_sync(self, sync_type='auto'):
        calls.append(sync_type)
        started.set()
        release.wait(2)
        return {'status': 'success', 'reports_created': 0}

    monkeypatch.setattr(dmarc_imap_service.DMARCImapService, "__init__", lambda self: None)
    monkeypatch.setattr(dmarc_imap_service.DMARCImapService, "sync_reports", slow_sync)
    service_db = MagicMock()
    monkeypatch.setattr(dmarc_imap_service, "SessionLocal", lambda: service_db)
    monkeypatch.setattr(dmarc, "update_job_status", Mock())
    route_db = MagicMock()
    app = FastAPI()
    app.include_router(dmarc.router)
    app.dependency_overrides[dmarc.get_db] = lambda: route_db
    return app, started, release, calls, route_db, service_db


def _running_import(started):
    running = threading.Thread(target=dmarc_imap_service.sync_dmarc_reports_from_imap, args=('auto',))
    running.start()
    assert started.wait(3)
    return running


def test_fetch_reports_while_an_import_runs_answers_already_running(imap):
    app, started, release, calls, route_db, service_db = imap
    running = _running_import(started)
    try:
        response = TestClient(app).post("/dmarc/imap/sync")
    finally:
        release.set()
        running.join(5)
    assert response.status_code == 200
    assert response.json()["status"] == "already_running"
    # The running import is neither marked failed nor joined by a second one
    route_db.query.assert_not_called()
    assert calls == ['auto']
    dmarc.update_job_status.assert_not_called()


def test_fetch_reports_starts_an_import_when_none_runs(imap):
    app, started, release, calls, route_db, service_db = imap
    release.set()
    response = TestClient(app).post("/dmarc/imap/sync")
    assert response.json()["status"] == "started"
    assert calls == ['manual']
    dmarc.update_job_status.assert_called_with('dmarc_imap_sync', 'success')


def test_an_import_left_running_by_a_restart_is_marked_failed_on_the_next_start(imap):
    app, started, release, calls, route_db, service_db = imap
    release.set()
    assert dmarc_imap_service.sync_dmarc_reports_from_imap('auto')['status'] == 'success'
    update = service_db.__enter__.return_value.query.return_value.filter.return_value.update
    update.assert_called_once()
    assert update.call_args.args[0]["status"] == "failed"


def test_a_failed_cleanup_does_not_stop_the_import(imap):
    app, started, release, calls, route_db, service_db = imap
    release.set()
    service_db.__enter__.return_value.commit.side_effect = RuntimeError("Database unavailable")
    assert dmarc_imap_service.sync_dmarc_reports_from_imap('auto')['status'] == 'success'
    assert calls == ['auto']


def test_scheduled_run_during_an_import_leaves_it_alone(imap, monkeypatch):
    app, started, release, calls, route_db, service_db = imap
    monkeypatch.setattr(scheduler, "update_job_status", Mock())
    monkeypatch.setattr(scheduler, "SessionLocal", lambda: MagicMock())
    running = _running_import(started)
    try:
        asyncio.run(scheduler.dmarc_imap_sync_job())
    finally:
        release.set()
        running.join(5)
    assert calls == ['auto']
    # The running import reports its own outcome; this run does not call it a success
    assert ('dmarc_imap_sync', 'success') not in [c.args[:2] for c in scheduler.update_job_status.call_args_list]
