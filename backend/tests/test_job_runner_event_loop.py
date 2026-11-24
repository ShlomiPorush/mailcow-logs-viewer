import asyncio

import httpx
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.main import app  # noqa: E402
from app import scheduler  # noqa: E402


@pytest.fixture(autouse=True)
def _restore_job_status():
    saved = {k: dict(v) for k, v in scheduler.job_status.items()}
    yield
    scheduler.job_status.clear()
    scheduler.job_status.update(saved)


async def _post(path):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        return await client.post(path)


def test_manual_async_job_runs_on_the_application_loop(monkeypatch):
    seen = []

    async def fake_fetch_all_logs():
        seen.append(asyncio.get_running_loop())

    monkeypatch.setattr(scheduler, "fetch_all_logs", fake_fetch_all_logs)

    async def main():
        resp = await _post("/api/settings/jobs/fetch_logs/run")
        assert resp.status_code == 200, resp.text
        return asyncio.get_running_loop()

    app_loop = asyncio.run(main())
    assert seen == [app_loop]
    assert scheduler.job_status['fetch_logs']['status'] == 'success'


def test_manual_run_waits_for_a_scheduled_run_holding_the_lock(monkeypatch):
    monkeypatch.setattr(scheduler, "_protection_lock", asyncio.Lock())
    ran = []

    async def fake_locked():
        ran.append(scheduler._protection_lock.locked())

    monkeypatch.setattr(scheduler, "_run_protection_rules_locked", fake_locked)

    async def main():
        lock = scheduler._protection_lock
        await lock.acquire()
        waiter = asyncio.create_task(lock.acquire())
        await asyncio.sleep(0)
        lock.release()
        await waiter
        asyncio.get_running_loop().call_later(0.05, lock.release)
        resp = await _post("/api/settings/jobs/protection_rules/run")
        assert resp.status_code == 200, resp.text

    asyncio.run(main())
    status = scheduler.job_status['protection_rules']
    assert status['status'] == 'success', status
    assert ran == [True]
