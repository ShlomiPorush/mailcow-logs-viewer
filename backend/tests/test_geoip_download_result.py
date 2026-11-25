import asyncio

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

import pytest  # noqa: E402

from app import scheduler  # noqa: E402
from app.services import geoip_downloader, geoip_service  # noqa: E402


def _db(available, updated, failed):
    return {'available': available, 'updated': updated, 'failed': failed}


def _run(monkeypatch, result):
    marked = []
    monkeypatch.setattr(geoip_downloader, 'is_license_configured', lambda: True)
    monkeypatch.setattr(geoip_downloader, 'update_geoip_database_if_needed', lambda: result)
    monkeypatch.setattr(geoip_service, 'reload_geoip_readers', lambda: True)
    monkeypatch.setattr(geoip_service, 'get_geoip_db_valid', lambda: True)
    monkeypatch.setattr(scheduler, '_persist_geoip_license_status', lambda: marked.append(True))
    monkeypatch.setitem(scheduler.job_status, 'update_geoip', {})
    asyncio.run(scheduler.update_geoip_database())
    return scheduler.job_status['update_geoip'], bool(marked)


def test_a_failed_download_with_an_older_file_fails_the_run(monkeypatch):
    entry, marked = _run(monkeypatch, {'City': _db(True, False, True), 'ASN': _db(True, False, False)})
    assert entry['status'] == 'failed'
    assert 'location database' in entry['error'] and 'network' not in entry['error']
    assert 'Settings > MaxMind' in entry['error']
    assert marked is False


def test_both_downloads_failing_without_files_fail_the_run(monkeypatch):
    entry, marked = _run(monkeypatch, {'City': _db(False, False, True), 'ASN': _db(False, False, True)})
    assert entry['status'] == 'failed'
    assert 'location and network information databases' in entry['error']
    assert marked is False


@pytest.mark.parametrize('result', [
    {'City': _db(True, True, False), 'ASN': _db(True, True, False)},
    {'City': _db(True, False, False), 'ASN': _db(True, False, False)},
])
def test_a_run_without_a_failed_download_succeeds(monkeypatch, result):
    entry, marked = _run(monkeypatch, result)
    assert entry['status'] == 'success'
    assert not entry.get('error')
    assert marked is True


def test_the_downloader_says_which_needed_download_failed(monkeypatch, tmp_path):
    old = tmp_path / 'old.mmdb'
    old.write_bytes(b'x')
    monkeypatch.setattr(geoip_downloader, 'is_license_configured', lambda: True)
    monkeypatch.setitem(geoip_downloader.DATABASES, 'City', {**geoip_downloader.DATABASES['City'], 'path': str(old)})
    monkeypatch.setitem(geoip_downloader.DATABASES, 'ASN', {**geoip_downloader.DATABASES['ASN'], 'path': str(tmp_path / 'none.mmdb')})
    monkeypatch.setattr(geoip_downloader, 'should_update_database', lambda name: True)
    monkeypatch.setattr(geoip_downloader, 'download_single_database', lambda name: False)
    status = geoip_downloader.update_geoip_database_if_needed()
    assert status['City'] == {'available': True, 'updated': False, 'failed': True}
    assert status['ASN'] == {'available': False, 'updated': False, 'failed': True}


def test_run_on_the_status_page_keeps_a_failed_download_failed(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.routers import settings as settings_router

    monkeypatch.setattr(settings_router, 'is_license_configured', lambda: True, raising=False)
    monkeypatch.setattr(geoip_downloader, 'is_license_configured', lambda: True)
    monkeypatch.setattr(geoip_downloader, 'update_geoip_database_if_needed',
                        lambda: {'City': _db(True, False, True), 'ASN': _db(True, False, False)})
    monkeypatch.setattr(geoip_service, 'reload_geoip_readers', lambda: True)
    monkeypatch.setattr(geoip_service, 'get_geoip_db_valid', lambda: True)
    monkeypatch.setattr(scheduler, '_persist_geoip_license_status', lambda: None)
    monkeypatch.setitem(scheduler.job_status, 'update_geoip', {})

    res = TestClient(app).post("/api/settings/jobs/update_geoip/run")
    assert res.status_code == 200, res.text
    entry = scheduler.job_status['update_geoip']
    assert entry['status'] == 'failed'
    assert 'location database' in entry['error']


def test_the_status_tells_two_runs_in_one_second_apart(monkeypatch):
    from datetime import datetime, timezone
    from app.routers import settings as settings_router

    first = datetime(2026, 11, 22, 8, 0, 0, 100000, tzinfo=timezone.utc)
    second = datetime(2026, 11, 22, 8, 0, 0, 900000, tzinfo=timezone.utc)
    assert settings_router._precise_utc(first) != settings_router._precise_utc(second)
    assert settings_router._precise_utc(first) == '2026-11-22T08:00:00.100000Z'
    assert settings_router._precise_utc(None) is None


def test_a_cancelled_run_is_not_reported_as_finished(monkeypatch):
    def cancelled():
        raise asyncio.CancelledError()
    monkeypatch.setattr(geoip_downloader, 'is_license_configured', lambda: True)
    monkeypatch.setattr(geoip_downloader, 'update_geoip_database_if_needed', cancelled)
    monkeypatch.setitem(scheduler.job_status, 'update_geoip', {})
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(scheduler.update_geoip_database())
    assert scheduler.job_status['update_geoip']['status'] == 'running'
