"""Status, Jobs: a job of a feature that is switched off says so.

Protection Rules belongs to the Security feature. With Security off it was
the only job without the feature_disabled flag, so the Status page showed a
plain "off" tag with a generic hint instead of "feature off" like the others.
The suppression sync now also reports the Read-Write key it needs.
"""
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.config import settings  # noqa: E402
from app.routers import settings as settings_router  # noqa: E402


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def jobs(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db
    init_db()

    def read():
        body = TestClient(app).get("/api/settings/info").json()
        assert body.get("background_jobs"), body
        return body["background_jobs"]
    return read


def test_protection_rules_is_a_job_of_the_security_feature(jobs, monkeypatch):
    monkeypatch.setattr(settings._inner, 'disabled_features', 'netfilter')
    job = jobs()['protection_rules']
    assert job['feature_disabled'] is True
    assert job['status'] == 'disabled'


def test_protection_rules_runs_with_security_on(jobs, monkeypatch):
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    job = jobs()['protection_rules']
    assert job['feature_disabled'] is False
    assert job['enabled'] is True


def test_suppression_sync_without_the_rw_key_still_reads(jobs, monkeypatch):
    # It reads the app's Rspamd blocks into the list; it writes only with the key
    monkeypatch.setattr(type(settings_router.mailcow_api), 'has_rw_key', property(lambda self: False))
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    monkeypatch.setattr(settings._inner, 'suppression_enabled', False)
    monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', True)
    monkeypatch.setattr(settings._inner, 'rspamd_password', 'example-password')
    job = jobs()['sync_suppressions']
    assert job['enabled'] is True and not job.get('disabled_reason'), 'the automatic handling is not needed'


def test_suppression_sync_off_says_why(jobs, monkeypatch):
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', False)
    monkeypatch.setattr(settings._inner, 'rspamd_password', 'example-password')
    job = jobs()['sync_suppressions']
    assert job['enabled'] is False
    assert 'Sync with Rspamd' in job['disabled_reason'] and job['settings_section'] == 'spam_filter'


def test_suppression_sync_without_the_rspamd_password_is_off_and_says_why(jobs, monkeypatch):
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', True)
    monkeypatch.setattr(settings._inner, 'rspamd_password', '')
    job = jobs()['sync_suppressions']
    assert job['enabled'] is False
    assert 'Rspamd password' in job['disabled_reason'] and job['settings_section'] == 'mailcow'
