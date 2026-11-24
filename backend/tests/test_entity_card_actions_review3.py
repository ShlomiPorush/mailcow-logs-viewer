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
    monkeypatch.setattr(scheduler, '_blacklist_full_scan_pending', False)
    ran = []

    async def run(force, send_notification):
        held = scheduler.blacklist_check_lock().locked() and scheduler._blacklist_full_scan_pending
        ran.append('full' if held else None)

    monkeypatch.setattr(scheduler, '_run_check_monitored_hosts', run)
    return ran


def test_a_waiting_scan_goes_before_a_new_single_address_check(scan):
    async def main():
        async with scheduler.blacklist_check_lock():
            job = asyncio.create_task(scheduler.check_monitored_hosts_job())
            await asyncio.sleep(0.05)
            assert scheduler._blacklist_full_scan_pending, "registered as waiting"
            assert not scheduler.blacklist_check_admits()
        assert not scheduler.blacklist_check_admits(), "a new address check would answer busy"
        result = await asyncio.wait_for(job, 2)
        assert result != scheduler.JOB_SKIPPED
        assert scan == ['full']
        assert scheduler.blacklist_check_admits(), "free again after the scan"
    asyncio.run(main())


def test_the_scan_waits_in_the_queue_without_polling(scan):
    async def main():
        lock = scheduler.blacklist_check_lock()
        await lock.acquire()
        job = asyncio.create_task(scheduler.check_monitored_hosts_job())
        await asyncio.sleep(0.05)
        lock.release()
        await asyncio.wait_for(job, 0.2)
        assert scan == ['full']
    asyncio.run(main())


@pytest.mark.parametrize("end", ["failure", "cancellation"])
def test_a_scan_that_ends_early_admits_checks_again(scan, monkeypatch, end):
    async def main():
        async def broken(force, send_notification):
            if end == "failure":
                raise RuntimeError("example failure")
            await asyncio.sleep(10)

        monkeypatch.setattr(scheduler, '_run_check_monitored_hosts', broken)
        job = asyncio.create_task(scheduler.check_monitored_hosts_job())
        await asyncio.sleep(0.05)
        if end == "cancellation":
            assert not scheduler.blacklist_check_admits()
            job.cancel()
        with pytest.raises((RuntimeError, asyncio.CancelledError)):
            await job
        assert scheduler.blacklist_check_admits()
    asyncio.run(main())


def test_a_scan_cancelled_while_it_waits_admits_checks_again(scan):
    async def main():
        async with scheduler.blacklist_check_lock():
            job = asyncio.create_task(scheduler.check_monitored_hosts_job())
            await asyncio.sleep(0.05)
            job.cancel()
            with pytest.raises(asyncio.CancelledError):
                await job
            assert not scheduler._blacklist_full_scan_pending
        assert scheduler.blacklist_check_admits()
        assert scan == []
    asyncio.run(main())


def test_a_second_scan_skips_while_one_waits(scan):
    async def main():
        async with scheduler.blacklist_check_lock():
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
    monkeypatch.setattr(scheduler, '_blacklist_full_scan_pending', True)
    started = []

    async def results(**kwargs):
        started.append(kwargs)
        return {}

    monkeypatch.setattr(blacklist, 'get_blacklist_check_results', results)
    res = TestClient(app).post("/api/blacklist/check", params={"host": "203.0.113.45", "force": "true"})
    assert res.status_code == 200 and res.json() == BUSY
    assert started == []
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
        scheduler.update_job_status('blacklist_check', 'running')
        scheduler.update_job_status('blacklist_check', 'failed', 'mailcow did not answer', retryable=True)
        return scheduler.JOB_SKIPPED

    monkeypatch.setattr(scheduler, 'check_monitored_hosts_job', job)
    tasks = BackgroundTasks()
    assert asyncio.run(settings_router.trigger_job('blacklist_check', tasks))['status'] == 'started'
    asyncio.run(tasks())
    status = statuses['blacklist_check']
    assert status['status'] == 'failed'
    assert status['error'] == 'mailcow did not answer'
    assert status['retryable'] is True


def test_the_manual_mark_is_the_entry_it_wrote_not_one_read_back(statuses, monkeypatch):
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    statuses['blacklist_check'] = {'last_run': datetime(2026, 10, 27, 6, 0), 'status': 'success', 'error': None, 'retryable': False}
    real = scheduler.update_job_status
    scan = {}

    def write_then_scan(name, status, *args, **kwargs):
        entry = real(name, status, *args, **kwargs)
        if name == 'blacklist_check' and status == 'running' and not scan:
            scan['entry'] = real('blacklist_check', 'running')
        return entry

    monkeypatch.setattr(settings_router, 'update_job_status', write_then_scan)

    async def job(**kwargs):
        return scheduler.JOB_SKIPPED

    monkeypatch.setattr(scheduler, 'check_monitored_hosts_job', job)
    tasks = BackgroundTasks()
    assert asyncio.run(settings_router.trigger_job('blacklist_check', tasks))['status'] == 'started'
    asyncio.run(tasks())
    assert statuses['blacklist_check'] is scan['entry'], "the running check's status stays"
    assert statuses['blacklist_check']['status'] == 'running'


def test_update_job_status_returns_the_entry_it_wrote(statuses):
    entry = scheduler.update_job_status('blacklist_check', 'failed', 'example error', retryable=True)
    assert entry is statuses['blacklist_check']
    assert entry['status'] == 'failed' and entry['error'] == 'example error' and entry['retryable'] is True


def test_trigger_job_runs_on_the_event_loop():
    assert asyncio.iscoroutinefunction(settings_router.trigger_job)


@pytest.mark.parametrize("scan_first", [True, False])
def test_a_scan_started_beside_a_manual_run_keeps_its_status(statuses, monkeypatch, scan_first):
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    monkeypatch.setattr(scheduler, '_blacklist_check_lock', asyncio.Lock())
    monkeypatch.setattr(scheduler, '_blacklist_full_scan_pending', False)
    statuses['blacklist_check'] = {'last_run': datetime(2026, 10, 27, 6, 0), 'status': 'success', 'error': None, 'retryable': False}
    seen = {}

    async def scan_body(force, send_notification):
        seen['entry'] = scheduler.update_job_status('blacklist_check', 'running')
        await asyncio.sleep(0.2)
        seen['during'] = scheduler.job_status['blacklist_check']

    monkeypatch.setattr(scheduler, '_run_check_monitored_hosts', scan_body)

    async def main():
        tasks = BackgroundTasks()
        if scan_first:
            scan = asyncio.create_task(scheduler.check_monitored_hosts_job())
            await asyncio.sleep(0)
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as refused:
                await settings_router.trigger_job('blacklist_check', tasks)
            assert refused.value.status_code == 409
        else:
            assert (await settings_router.trigger_job('blacklist_check', tasks))['status'] == 'started'
            scan = asyncio.create_task(scheduler.check_monitored_hosts_job())
            await tasks()
        await scan
        return tasks

    asyncio.run(main())
    if scan_first:
        assert seen['during'] is seen['entry']
    else:
        assert 'entry' in seen and seen['during'] is seen['entry']
