from types import SimpleNamespace

import pytest

from app import scheduler
from app.config import settings


class _Scheduler:
    running = True

    def __init__(self):
        self.jobs = {}
        self.rescheduled = []

    def add_job(self, func, trigger=None, id=None, **kwargs):
        self.jobs[id] = SimpleNamespace(id=id, func=func, trigger=trigger)

    def get_job(self, job_id):
        return self.jobs.get(job_id)

    def get_jobs(self):
        return list(self.jobs.values())

    def reschedule_job(self, job_id, trigger=None):
        self.rescheduled.append(job_id)
        self.jobs[job_id].trigger = trigger

    def start(self):
        pass


@pytest.fixture
def features(monkeypatch):
    off = set()
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: name not in off)
    monkeypatch.setattr(scheduler, "cleanup_disabled_feature_data", lambda *a, **k: None)
    fake = _Scheduler()
    monkeypatch.setattr(scheduler, "scheduler", fake)
    return off, fake


@pytest.mark.parametrize("feature, job_ids", [
    ("domains", {"dns_check_background"}),
    ("blacklist", {"blacklist_check", "sync_transports"}),
    ("dmarc", {"cleanup_dmarc_reports"}),
    ("mailbox-stats", {"alias_stats"}),
])
def test_a_feature_turned_on_later_starts_its_jobs(features, feature, job_ids):
    off, fake = features
    off.add(feature)
    scheduler.start_scheduler()
    assert not job_ids & set(fake.jobs)

    off.discard(feature)
    scheduler.reschedule_interval_jobs()
    assert job_ids <= set(fake.jobs)


def test_start_and_a_save_register_the_same_jobs(features):
    _, fake = features
    scheduler.start_scheduler()
    periodic = {job_id for job_id in fake.jobs if not job_id.endswith('_startup')}
    fake.jobs = {}
    scheduler.reschedule_interval_jobs()
    assert set(fake.jobs) == periodic


def test_a_save_leaves_an_unchanged_interval_alone(features, monkeypatch):
    _, fake = features
    scheduler.start_scheduler()
    scheduler.reschedule_interval_jobs()
    assert fake.rescheduled == []

    monkeypatch.setattr(settings._inner, "fetch_interval", settings.fetch_interval + 30)
    scheduler.reschedule_interval_jobs()
    assert fake.rescheduled == ["fetch_logs"]
