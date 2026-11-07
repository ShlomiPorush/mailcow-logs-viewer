"""Saving settings reschedules the quarantine rules job, like the other interval jobs."""
from datetime import timedelta
from unittest.mock import Mock

import pytest

from app import scheduler
from app.config import settings


@pytest.fixture
def fake_scheduler(monkeypatch):
    fake = Mock(running=True)
    monkeypatch.setattr(scheduler, "scheduler", fake)
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: True)
    return fake


def _quarantine_job(fake):
    calls = [c for c in fake.add_job.call_args_list if c.kwargs.get("id") == "process_quarantine_rules"]
    return calls[-1] if calls else None


def test_new_interval_takes_effect_without_restart(monkeypatch, fake_scheduler):
    monkeypatch.setattr(scheduler.mailcow_api, "headers_rw", {"X-API-Key": "test-key"})
    monkeypatch.setattr(settings._inner, "quarantine_rules_interval", 15)
    scheduler.reschedule_interval_jobs()
    call = _quarantine_job(fake_scheduler)
    assert call is not None, "the quarantine rules job was not rescheduled"
    assert call.kwargs["trigger"].interval == timedelta(minutes=15)
    assert call.kwargs["replace_existing"] is True


def test_read_write_key_added_later_starts_the_job(monkeypatch, fake_scheduler):
    monkeypatch.setattr(scheduler.mailcow_api, "headers_rw", None)
    scheduler.reschedule_interval_jobs()
    assert _quarantine_job(fake_scheduler) is None
    fake_scheduler.remove_job.assert_any_call("process_quarantine_rules")

    monkeypatch.setattr(scheduler.mailcow_api, "headers_rw", {"X-API-Key": "test-key"})
    scheduler.reschedule_interval_jobs()
    assert _quarantine_job(fake_scheduler) is not None


def test_feature_switched_off_stops_the_job(monkeypatch, fake_scheduler):
    monkeypatch.setattr(scheduler.mailcow_api, "headers_rw", {"X-API-Key": "test-key"})
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: name != "quarantine")
    scheduler.reschedule_interval_jobs()
    assert _quarantine_job(fake_scheduler) is None
    fake_scheduler.remove_job.assert_any_call("process_quarantine_rules")
