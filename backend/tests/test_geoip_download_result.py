"""GeoIP update job: a download that was needed and did not succeed fails the
run, also when an older file stays in use, and does not mark the MaxMind
license valid. Setup, Repair and Status read this job's result.
"""
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
    """Run the job with the downloader answering result; returns the job entry
    and whether the license was marked valid."""
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
    assert 'City' in entry['error'] and 'ASN' not in entry['error']
    assert 'Settings > MaxMind' in entry['error']
    # A refused download proves nothing about the license
    assert marked is False


def test_both_downloads_failing_without_files_fail_the_run(monkeypatch):
    entry, marked = _run(monkeypatch, {'City': _db(False, False, True), 'ASN': _db(False, False, True)})
    assert entry['status'] == 'failed'
    assert 'City and ASN databases' in entry['error']
    assert marked is False


@pytest.mark.parametrize('result', [
    {'City': _db(True, True, False), 'ASN': _db(True, True, False)},     # downloaded
    {'City': _db(True, False, False), 'ASN': _db(True, False, False)},   # up to date, nothing needed
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
