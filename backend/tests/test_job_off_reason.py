"""A background job that cannot run says why, and which Settings section changes it,
so the Status page shows the reason instead of a Run button that is simply missing."""
import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.routers import settings as settings_router


def _rw(monkeypatch, value):
    monkeypatch.setattr(type(settings_router.mailcow_api), 'has_rw_key', property(lambda self: value))


def test_a_job_that_needs_the_rw_key_says_so(monkeypatch):
    _rw(monkeypatch, False)
    reason, section = settings_router._job_off_reason('process_quarantine_rules')
    assert 'Read-Write' in reason and section == 'mailcow'


def test_imap_and_maxmind_point_to_their_own_sections(monkeypatch):
    monkeypatch.setattr(settings_router.settings, 'dmarc_imap_enabled', False)
    monkeypatch.setattr(settings_router, 'is_license_configured', lambda: False)
    assert settings_router._job_off_reason('dmarc_imap_sync')[1] == 'dmarc_imap'
    assert settings_router._job_off_reason('update_geoip') == ('Needs a MaxMind Account ID and License Key', 'maxmind')


def test_the_first_missing_condition_is_the_reason(monkeypatch):
    _rw(monkeypatch, False)
    monkeypatch.setattr(settings_router.settings, 'smtp_abuse_enabled', False)
    assert settings_router._job_off_reason('smtp_abuse')[0] == 'SMTP abuse protection is turned off'
    monkeypatch.setattr(settings_router.settings, 'smtp_abuse_enabled', True)
    assert 'Read-Write' in settings_router._job_off_reason('smtp_abuse')[0]


def test_a_job_that_can_run_has_no_reason(monkeypatch):
    _rw(monkeypatch, True)
    monkeypatch.setattr(settings_router.settings, 'smtp_abuse_enabled', True)
    assert settings_router._job_off_reason('smtp_abuse') is None
    assert settings_router._job_off_reason('complete_correlations') is None
