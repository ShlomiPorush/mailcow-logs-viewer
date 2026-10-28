"""Status > Run of a job that another run already holds leaves its status alone.

A manual run is accepted while the job is idle, and its background task starts
a moment later. When another run takes the job's lock in between (Fetch
reports or the schedule for the DMARC import, the Blacklist page or the
schedule for the blacklist check), the manual run skips. The job is still
running then, and the run that holds it sets the outcome when it ends; the
manual run used to mark it a success at once.
"""
import asyncio
import threading
from unittest.mock import MagicMock

import pytest
from starlette.background import BackgroundTasks

from app import scheduler
from app.config import settings
from app.routers import settings as settings_router
from app.services import dmarc_imap_service


@pytest.fixture(autouse=True)
def _restore_job_status():
    saved = {k: dict(v) for k, v in scheduler.job_status.items()}
    yield
    scheduler.job_status.clear()
    scheduler.job_status.update(saved)


@pytest.fixture
def features_on(monkeypatch):
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: True)


def test_a_manual_import_that_meets_another_import_leaves_the_status_to_it(features_on, monkeypatch):
    monkeypatch.setattr(settings._inner, "dmarc_imap_enabled", True)
    started, release = threading.Event(), threading.Event()
    calls = []

    def slow_failing_sync(self, sync_type='auto'):
        calls.append(sync_type)
        started.set()
        release.wait(5)
        return {'status': 'error', 'error_message': 'IMAP login failed'}

    monkeypatch.setattr(dmarc_imap_service.DMARCImapService, "__init__", lambda self: None)
    monkeypatch.setattr(dmarc_imap_service.DMARCImapService, "sync_reports", slow_failing_sync)
    monkeypatch.setattr(dmarc_imap_service, "SessionLocal", lambda: MagicMock())
    scheduler.update_job_status('dmarc_imap_sync', 'idle')

    # Status accepts the Run while no import runs
    tasks = BackgroundTasks()
    assert settings_router.trigger_job('dmarc_imap_sync', tasks)['status'] == 'started'

    # The scheduled import takes the lock before the manual run's task starts
    owner = threading.Thread(target=lambda: asyncio.run(scheduler.dmarc_imap_sync_job()))
    owner.start()
    try:
        assert started.wait(5)
        asyncio.run(tasks())
        # The scheduled import still runs, so the job is not done yet
        assert scheduler.job_status['dmarc_imap_sync']['status'] == 'running'
    finally:
        release.set()
        owner.join(5)
    # The import that ran sets the outcome, and only one import read the mailbox
    assert scheduler.job_status['dmarc_imap_sync']['status'] == 'failed'
    assert scheduler.job_status['dmarc_imap_sync']['error'] == 'IMAP login failed'
    assert calls == ['auto']


def test_a_manual_blacklist_check_that_meets_another_check_leaves_the_status_to_it(features_on, monkeypatch):
    monkeypatch.setattr(scheduler, "_blacklist_check_lock", asyncio.Lock())
    checks = []

    async def fake_check(force, send_notification):
        checks.append(force)

    monkeypatch.setattr(scheduler, "_run_check_monitored_hosts", fake_check)
    scheduler.update_job_status('blacklist_check', 'idle')

    async def main():
        tasks = BackgroundTasks()
        assert settings_router.trigger_job('blacklist_check', tasks)['status'] == 'started'
        # A full check (the Blacklist page's or the schedule's) holds the lock; it sets the status
        async with scheduler.blacklist_check_hold('full'):
            scheduler.update_job_status('blacklist_check', 'running')   # as the full check does
            await tasks()
            return scheduler.job_status['blacklist_check']['status']

    assert asyncio.run(main()) == 'running'
    assert checks == []


def test_a_manual_blacklist_check_that_runs_is_marked_a_success(features_on, monkeypatch):
    monkeypatch.setattr(scheduler, "_blacklist_check_lock", asyncio.Lock())
    checks = []

    async def fake_check(force, send_notification):
        checks.append(force)

    monkeypatch.setattr(scheduler, "_run_check_monitored_hosts", fake_check)
    scheduler.update_job_status('blacklist_check', 'idle')
    tasks = BackgroundTasks()
    assert settings_router.trigger_job('blacklist_check', tasks)['status'] == 'started'
    asyncio.run(tasks())
    assert checks == [False]
    assert scheduler.job_status['blacklist_check']['status'] == 'success'
