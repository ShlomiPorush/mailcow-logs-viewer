import asyncio
import secrets
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app import scheduler
from app.config import settings


class _Scheduler:
    running = True

    def __init__(self):
        self.jobs = {}

    def add_job(self, func, trigger=None, id=None, **kwargs):
        self.jobs[id] = SimpleNamespace(id=id, func=func, trigger=trigger)

    def get_job(self, job_id):
        return self.jobs.get(job_id)

    def get_jobs(self):
        return list(self.jobs.values())

    def reschedule_job(self, job_id, trigger=None):
        self.jobs[job_id].trigger = trigger


@pytest.fixture
def fake_scheduler(monkeypatch):
    fake = _Scheduler()
    monkeypatch.setattr(scheduler, "scheduler", fake)
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: True)
    return fake


def _quarantine_job(fake):
    return fake.get_job("process_quarantine_rules")


def test_new_interval_takes_effect_without_restart(monkeypatch, fake_scheduler):
    monkeypatch.setattr(scheduler.mailcow_api, "headers_rw", {"X-API-Key": secrets.token_hex(16)})
    fake_scheduler.add_job(scheduler.process_quarantine_rules_job, trigger=scheduler.every(minutes=5),
                           id="process_quarantine_rules")
    monkeypatch.setattr(settings._inner, "quarantine_rules_interval", 15)
    scheduler.reschedule_interval_jobs()
    job = _quarantine_job(fake_scheduler)
    assert job is not None, "the quarantine rules job was not rescheduled"
    assert job.trigger.interval == timedelta(minutes=15)


def test_read_write_key_added_later_starts_the_job(monkeypatch, fake_scheduler):
    monkeypatch.setattr(scheduler.mailcow_api, "headers_rw", None)
    scheduler.reschedule_interval_jobs()
    assert _quarantine_job(fake_scheduler) is None

    monkeypatch.setattr(scheduler.mailcow_api, "headers_rw", {"X-API-Key": secrets.token_hex(16)})
    scheduler.reschedule_interval_jobs()
    assert _quarantine_job(fake_scheduler) is not None


def test_feature_switched_off_leaves_the_job_doing_nothing(monkeypatch, fake_scheduler):
    monkeypatch.setattr(scheduler.mailcow_api, "headers_rw", {"X-API-Key": secrets.token_hex(16)})
    scheduler.reschedule_interval_jobs()
    assert _quarantine_job(fake_scheduler) is not None

    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: name != "quarantine")
    scheduler.reschedule_interval_jobs()
    assert _quarantine_job(fake_scheduler) is not None
    get_quarantine = AsyncMock(return_value=[])
    monkeypatch.setattr(scheduler.mailcow_api, "get_quarantine", get_quarantine)
    asyncio.run(scheduler._process_quarantine_rules_in_worker())
    get_quarantine.assert_not_awaited()
