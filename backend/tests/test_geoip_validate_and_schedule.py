import asyncio

import pytest
import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app import scheduler  # noqa: E402
from app.routers import settings as settings_router  # noqa: E402
from app.services import geoip_service  # noqa: E402


def test_validate_reports_a_missing_asn_database(monkeypatch):
    monkeypatch.setattr(geoip_service, '_geoip_db_valid', None)
    monkeypatch.setattr(settings_router, 'get_geoip_status', lambda: {'City': {'available': True}})
    state = {}

    def reload():
        state['result'] = geoip_service.validate_geoip_database()
        return True
    monkeypatch.setattr(geoip_service, 'reload_geoip_readers', reload)
    monkeypatch.setattr(geoip_service, 'get_city_reader', lambda: _CityReader())
    monkeypatch.setattr(geoip_service, 'get_asn_reader', lambda: None)

    body = TestClient(app).post("/api/settings/geoip/validate").json()

    assert body['valid'] is True
    assert body['city_ok'] is True
    assert body['asn_ok'] is False


class _CityReader:
    def city(self, ip):
        class _Country:
            iso_code = 'US'

        class _Response:
            country = _Country()
        return _Response()


class _FakeScheduler:
    running = True

    def __init__(self):
        self.jobs = {}

    def add_job(self, func, trigger=None, id=None, **kwargs):
        self.jobs[id] = (func, trigger)

    def get_job(self, job_id):
        return self.jobs.get(job_id)


def test_saving_a_license_schedules_the_weekly_update(monkeypatch):
    fake = _FakeScheduler()
    monkeypatch.setattr(scheduler, 'scheduler', fake)
    monkeypatch.setattr(scheduler, 'is_license_configured', lambda: True)

    scheduler.reschedule_interval_jobs()

    func, trigger = fake.jobs['update_geoip']
    assert func is scheduler.update_geoip_database
    assert 'sun' in str(trigger) and "hour='3'" in str(trigger)


def test_removing_the_license_leaves_the_weekly_update_doing_nothing(monkeypatch):
    from app.services import geoip_downloader
    fake = _FakeScheduler()
    fake.jobs['update_geoip'] = (scheduler.update_geoip_database, None)
    monkeypatch.setattr(scheduler, 'scheduler', fake)
    monkeypatch.setattr(scheduler, 'is_license_configured', lambda: False)

    scheduler.reschedule_interval_jobs()

    assert 'update_geoip' in fake.jobs
    monkeypatch.setattr(geoip_downloader, 'is_license_configured', lambda: False)
    monkeypatch.setattr(geoip_downloader, 'update_geoip_database_if_needed',
                        lambda: pytest.fail("downloaded without a license"))
    saved = dict(scheduler.job_status['update_geoip'])
    try:
        assert asyncio.run(scheduler.update_geoip_database()) == scheduler.JOB_STATUS_SET
        assert scheduler.job_status['update_geoip'] == saved
    finally:
        scheduler.job_status['update_geoip'] = saved
