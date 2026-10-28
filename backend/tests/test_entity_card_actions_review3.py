"""Third review of the entity card actions:

- A full blocklist check waiting for a single address check waits in the
  lock's queue, registered: no new single address check starts while it
  waits (POST /api/blacklist/check answers busy), so a stream of them cannot
  keep the scan out until it gives up.
- A manual Run that skipped puts the job's status back only while the status
  is still its own mark: a full check that ran and wrote its result
  meanwhile keeps it.
"""
import asyncio
from datetime import datetime

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from starlette.background import BackgroundTasks

from app import scheduler
from app.config import settings
from app.routers import settings as settings_router

BUSY = {"status": "busy", "message": "A blocklist check is already running. Try again when it is done."}


@pytest.fixture()
def scan(monkeypatch):
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    monkeypatch.setattr(scheduler, '_blacklist_check_lock', asyncio.Lock())
    monkeypatch.setattr(scheduler, '_blacklist_full_waiting', 0, raising=False)
    ran = []

    async def run(force, send_notification):
        ran.append(scheduler.blacklist_check_holder())

    monkeypatch.setattr(scheduler, '_run_check_monitored_hosts', run)
    return ran


def test_a_waiting_scan_goes_before_a_new_single_address_check(scan):
    async def main():
        async with scheduler.blacklist_check_hold('host'):
            job = asyncio.create_task(scheduler.check_monitored_hosts_job())
            await asyncio.sleep(0.05)
            assert scheduler.blacklist_full_scan_waiting(), "registered as waiting"
            assert not scheduler.blacklist_check_admits()
        # The first address check ended; a new one arrives before the scan runs
        assert not scheduler.blacklist_check_admits(), "a new address check would answer busy"
        result = await asyncio.wait_for(job, 2)
        assert result != scheduler.JOB_SKIPPED
        assert scan == ['full']
        assert scheduler.blacklist_check_admits(), "free again after the scan"
    asyncio.run(main())


def test_the_scan_waits_in_the_queue_without_polling(scan):
    """It is woken when the address check ends, not half a second later."""
    async def main():
        hold = scheduler.blacklist_check_hold('host')
        await hold.__aenter__()
        job = asyncio.create_task(scheduler.check_monitored_hosts_job())
        await asyncio.sleep(0.05)
        await hold.__aexit__(None, None, None)
        await asyncio.wait_for(job, 0.2)
        assert scan == ['full']
    asyncio.run(main())


def test_a_second_scan_skips_while_one_waits(scan):
    async def main():
        async with scheduler.blacklist_check_hold('host'):
            first = asyncio.create_task(scheduler.check_monitored_hosts_job())
            await asyncio.sleep(0.05)
            assert await asyncio.wait_for(scheduler.check_monitored_hosts_job(), 1) == scheduler.JOB_SKIPPED
        await asyncio.wait_for(first, 2)
        assert scan == ['full']
    asyncio.run(main())


def test_a_new_address_check_answers_busy_while_a_scan_waits(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.routers import blacklist
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    monkeypatch.setattr(scheduler, '_blacklist_full_waiting', 1, raising=False)   # the lock itself is free
    started = []

    async def results(**kwargs):
        started.append(kwargs)
        return {}

    monkeypatch.setattr(blacklist, 'get_blacklist_check_results', results)
    res = TestClient(app).post("/api/blacklist/check", params={"host": "203.0.113.45", "force": "true"})
    assert res.status_code == 200 and res.json() == BUSY
    assert started == []
    # and a manual Run of the job is refused too
    assert TestClient(app).post("/api/settings/jobs/blacklist_check/run").status_code == 409


@pytest.fixture()
def statuses():
    saved = {k: dict(v) for k, v in scheduler.job_status.items()}
    yield scheduler.job_status
    scheduler.job_status.clear()
    scheduler.job_status.update(saved)


def test_a_skipped_manual_run_keeps_the_result_a_full_check_wrote_meanwhile(statuses, monkeypatch):
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    statuses['blacklist_check'] = {'last_run': datetime(2026, 10, 27, 6, 0), 'status': 'success', 'error': None, 'retryable': False}

    async def job(**kwargs):
        # While the manual run waited, a full check started and ended with its own result
        scheduler.update_job_status('blacklist_check', 'running')
        scheduler.update_job_status('blacklist_check', 'failed', 'mailcow did not answer', retryable=True)
        return scheduler.JOB_SKIPPED

    monkeypatch.setattr(scheduler, 'check_monitored_hosts_job', job)
    tasks = BackgroundTasks()
    assert settings_router.trigger_job('blacklist_check', tasks)['status'] == 'started'
    asyncio.run(tasks())
    status = statuses['blacklist_check']
    assert status['status'] == 'failed'
    assert status['error'] == 'mailcow did not answer'
    assert status['retryable'] is True


def test_the_manual_mark_is_the_entry_it_wrote_not_one_read_back(statuses, monkeypatch):
    """The Run is accepted in the threadpool; a full check on the event loop can
    write its own 'running' right after the Run's. The Run's task then skips,
    and must not undo the running check's status."""
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    statuses['blacklist_check'] = {'last_run': datetime(2026, 10, 27, 6, 0), 'status': 'success', 'error': None, 'retryable': False}
    real = scheduler.update_job_status
    scan = {}

    def write_then_scan(name, status, *args, **kwargs):
        entry = real(name, status, *args, **kwargs)
        if name == 'blacklist_check' and status == 'running' and not scan:
            # The full check starts between the Run's write and anything after it
            scan['entry'] = real('blacklist_check', 'running')
        return entry

    monkeypatch.setattr(settings_router, 'update_job_status', write_then_scan)

    async def job(**kwargs):
        return scheduler.JOB_SKIPPED   # the running full check holds the job

    monkeypatch.setattr(scheduler, 'check_monitored_hosts_job', job)
    tasks = BackgroundTasks()
    assert settings_router.trigger_job('blacklist_check', tasks)['status'] == 'started'
    asyncio.run(tasks())
    assert statuses['blacklist_check'] is scan['entry'], "the running check's status stays"
    assert statuses['blacklist_check']['status'] == 'running'


def test_update_job_status_returns_the_entry_it_wrote(statuses):
    entry = scheduler.update_job_status('blacklist_check', 'failed', 'example error', retryable=True)
    assert entry is statuses['blacklist_check']
    assert entry['status'] == 'failed' and entry['error'] == 'example error' and entry['retryable'] is True
