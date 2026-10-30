"""A manual run of a job that cannot run is refused instead of reported as started.

The Status page hides Run for such a job, but the API accepted it: the job
returned at once and was marked success (or, for Protection Rules with the
Security feature off, ran anyway).
"""
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402
from starlette.background import BackgroundTasks  # noqa: E402

from app.main import app  # noqa: E402
from app import scheduler  # noqa: E402
from app.config import settings  # noqa: E402
from app.routers import settings as settings_router  # noqa: E402


@pytest.fixture()
def started(monkeypatch):
    """The jobs the runner started; nothing is executed."""
    tasks = []
    monkeypatch.setattr(BackgroundTasks, "add_task", lambda self, *a, **k: tasks.append(a))
    saved = {k: dict(v) for k, v in scheduler.job_status.items()}
    yield tasks
    scheduler.job_status.clear()
    scheduler.job_status.update(saved)


def _rw(monkeypatch, value):
    monkeypatch.setattr(type(settings_router.mailcow_api), 'has_rw_key', property(lambda self: value))


@pytest.mark.parametrize("job, disabled", [
    ("cleanup_dmarc_reports", "dmarc"),
    ("dns_check", "domains"),
    ("blacklist_check", "blacklist"),
    ("eas_devices", "devices"),
    ("expire_suppressions", "suppressions"),
    ("protection_rules", "netfilter"),
])
def test_a_job_of_a_feature_that_is_off_is_refused(started, monkeypatch, job, disabled):
    monkeypatch.setattr(settings._inner, 'disabled_features', disabled)
    resp = TestClient(app).post(f"/api/settings/jobs/{job}/run")
    assert resp.status_code == 409, resp.text
    assert 'turned off' in resp.json()['detail']
    assert started == []
    assert scheduler.job_status[job]['status'] != 'running'


def test_a_job_whose_setting_is_off_says_why(started, monkeypatch):
    monkeypatch.setattr(settings._inner, 'anomaly_detection_enabled', False)
    resp = TestClient(app).post("/api/settings/jobs/anomaly_detection/run")
    assert resp.status_code == 409
    assert 'Anomaly detection is turned off' in resp.json()['detail']
    assert started == []


def test_suppression_sync_without_the_rw_key_still_reads(started, monkeypatch):
    # It reads the app's Rspamd blocks into the list; it writes only with the key
    _rw(monkeypatch, False)
    monkeypatch.setattr(settings._inner, 'suppression_enabled', True)
    monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', True)
    monkeypatch.setattr(settings._inner, 'rspamd_password', 'example-password')
    resp = TestClient(app).post("/api/settings/jobs/sync_suppressions/run")
    assert resp.status_code == 200, resp.text
    assert len(started) == 1


def test_suppression_sync_without_the_rspamd_password_is_refused(started, monkeypatch):
    monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', True)
    monkeypatch.setattr(settings._inner, 'rspamd_password', '')
    resp = TestClient(app).post("/api/settings/jobs/sync_suppressions/run")
    assert resp.status_code == 409
    assert 'Rspamd password' in resp.json()['detail']


def test_mailbox_sync_still_runs_for_rate_limits(started, monkeypatch):
    # Mailbox Stats off, Rate Limits on: the sync still feeds Rate Limits
    monkeypatch.setattr(settings._inner, 'disabled_features', 'mailbox-stats')
    resp = TestClient(app).post("/api/settings/jobs/mailbox_stats/run")
    assert resp.status_code == 200, resp.text
    assert len(started) == 1


def test_a_job_that_can_run_is_started(started, monkeypatch):
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    resp = TestClient(app).post("/api/settings/jobs/cleanup_dmarc_reports/run")
    assert resp.status_code == 200
    assert len(started) == 1
