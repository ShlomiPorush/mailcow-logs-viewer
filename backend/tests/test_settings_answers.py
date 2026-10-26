"""Every answer the Settings calls can give, so the contract check (conftest.py,
contract.py) holds each one to /openapi.json: the information and settings, the
saves and the requests they refuse (400, 403, 422), a busy save (503), the
database failing (the 200 answers that say so, and 500), the purge of a feature's
data with Rspamd refusing (409, 502), the checks of credentials and connections,
GeoIP and the manual job runs (404, 409). mailcow, Rspamd, MaxMind, SMTP and IMAP
are faked or left unconfigured; nothing leaves the test. Every setting and stored
row a call changes is put back."""
import types
import uuid
from contextlib import contextmanager
from datetime import datetime

import httpx
import pytest
from sqlalchemy import text

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app import config, database, scheduler  # noqa: E402
from app.config import settings  # noqa: E402
from app.database import get_db  # noqa: E402
from app.mailcow_api import MailcowAPIError, mailcow_api  # noqa: E402
from app.main import app  # noqa: E402
from app.routers import settings as settings_router  # noqa: E402
from app.routers.suppressions import MANAGED_MARKER_END, MANAGED_MARKER_START, OFF_TRANSITION_KEY  # noqa: E402
from app.services import figures  # noqa: E402

MARK = uuid.uuid4().hex[:8]
# Stored rows these calls write: settings, check results, the Suppressions switch token
SHARED_PREFIXES = ('config.', 'maxmind.', 'credential_check.')
SHARED_KEYS = (OFF_TRANSITION_KEY,)


class _Broken:
    def __getattr__(self, name):
        raise RuntimeError('database gone')


def _broken_session():
    yield _Broken()


@contextmanager
def _broken_context():
    yield _Broken()


def _set(monkeypatch, key, value):
    """A setting for this test. A value an earlier test left on the settings wrapper itself
    would hide it, so that one is taken off for the test and put back after."""
    if key in vars(settings):
        monkeypatch.delattr(settings, key)
    monkeypatch.setattr(settings._inner, key, value)


def _postgres_available() -> bool:
    try:
        with database.engine.connect():
            return True
    except Exception:
        return False


def _shared(db):
    from app.models import SystemSetting
    return [row for row in db.query(SystemSetting).all()
            if row.key.startswith(SHARED_PREFIXES) or row.key in SHARED_KEYS]


@pytest.fixture
def client(monkeypatch):
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        _set(monkeypatch, key, False)
    _set(monkeypatch, 'edit_settings_via_ui_enabled', False)
    # Nothing is sent: no SMTP, IMAP, MaxMind, mailcow key or Rspamd password
    for key in ('smtp_host', 'smtp_user', 'smtp_password', 'smtp_from', 'dmarc_imap_host', 'dmarc_imap_user',
                'dmarc_imap_password', 'maxmind_license_key', 'maxmind_account_id', 'rspamd_password'):
        _set(monkeypatch, key, None)
    _set(monkeypatch, 'smtp_relay_mode', False)
    monkeypatch.setattr(mailcow_api, 'headers_rw', None)
    jobs_before = {key: dict(value) for key, value in scheduler.job_status.items()}
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.pop(get_db, None)
    scheduler.job_status.clear()
    scheduler.job_status.update(jobs_before)


@pytest.fixture
def rows(client):
    """The stored settings and check results as they were, put back after the test."""
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.models import SpamSuppression, SystemSetting
    database.init_db()
    with database.get_db_context() as db:
        before = {row.key: (row.value, row.updated_at) for row in _shared(db)}
        synced = [row.id for row in db.query(SpamSuppression).filter(SpamSuppression.active == True,  # noqa: E712
                                                                     SpamSuppression.synced_to_rspamd == True)]  # noqa: E712
    yield
    with database.get_db_context() as db:
        for row in _shared(db):
            if row.key not in before:
                db.delete(row)
            else:
                row.value, row.updated_at = before.pop(row.key)
        for key, (value, updated_at) in before.items():
            db.add(SystemSetting(key=key, value=value, updated_at=updated_at))
        if synced:
            db.query(SpamSuppression).filter(SpamSuppression.id.in_(synced)).update(
                {SpamSuppression.synced_to_rspamd: True}, synchronize_session=False)
        db.commit()


@pytest.fixture
def editing(client, rows, monkeypatch):
    """UI editing on, also for the settings a save reloads from the environment; the
    settings, the mailcow client and the jobs as they were after the test."""
    monkeypatch.setenv('SETTINGS_EDIT_VIA_UI_ENABLED', 'true')
    _set(monkeypatch, 'edit_settings_via_ui_enabled', True)
    # A save's side effects that build no part of its answer
    monkeypatch.setattr(settings_router, 'cleanup_disabled_feature_data', lambda db: {})
    monkeypatch.setattr(settings_router, 'run_feature_data_sweep_soon', lambda: None)
    monkeypatch.setattr(settings_router, 'reschedule_interval_jobs', lambda: None)
    yield client
    monkeypatch.undo()
    config.reload_settings()
    mailcow_api.reload_config()


# ---------------------------------------------------------------- information and health

def test_settings_info(client, rows, monkeypatch):
    from app.models import MessageCorrelation
    with database.get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=f'k{MARK}', message_id=f'<{MARK}{"x" * 60}@example.com>',
                                  queue_id=f'Q{MARK}', sender=f's@{MARK}.example', recipient=f'r@{MARK}.example',
                                  is_complete=False, created_at=datetime.utcnow()))
        db.commit()
    try:
        body = client.get('/api/settings/info').json()
        assert 'editable_config' not in body
        assert any(c['queue_id'] == f'Q{MARK}' for c in body['recent_incomplete_correlations'])
        # Editing on, MaxMind set, a stored license check and a job at its clock time
        _set(monkeypatch, 'edit_settings_via_ui_enabled', True)
        _set(monkeypatch, 'maxmind_license_key', 'placeholder')
        _set(monkeypatch, 'maxmind_account_id', '1')
        _set(monkeypatch, 'dmarc_imap_enabled', True)
        _set(monkeypatch, 'smtp_enabled', True)
        with database.get_db_context() as db:
            from app.services.settings_store import save_maxmind_validation_status
            save_maxmind_validation_status(db, {'configured': True, 'valid': False, 'error': 'Invalid'})
        body = client.get('/api/settings/info').json()
        assert body['configuration']['maxmind_status']['error'] == 'Invalid'
        assert 'editable_config' in body and body['geoip_configuration']['enabled'] is True
    finally:
        with database.get_db_context() as db:
            db.query(MessageCorrelation).filter(MessageCorrelation.correlation_key == f'k{MARK}').delete()
            db.commit()


def test_settings_info_when_the_database_fails(client):
    app.dependency_overrides[get_db] = _broken_session
    body = client.get('/api/settings/info').json()
    assert body['error'] and body['configuration'] == {}


def test_health(client, rows):
    assert client.get('/api/settings/health').json()['status'] == 'healthy'
    app.dependency_overrides[get_db] = _broken_session
    assert client.get('/api/settings/health').json()['status'] == 'unhealthy'


# ---------------------------------------------------------------- the settings

def test_editable_settings(client, rows, editing):
    assert client.get('/api/settings').status_code == 200
    app.dependency_overrides[get_db] = _broken_session
    assert client.get('/api/settings').status_code == 500


def test_editable_settings_while_editing_is_off(client, rows):
    body = client.get('/api/settings').json()
    assert body['settings_edit_via_ui_enabled'] is False and body['env_locked_keys'] == []


def test_saving_settings(editing):
    c = editing
    assert 'rspamd_off_transition' not in c.put('/api/settings', json={}).json()
    saved = c.put('/api/settings', json={'app_title': f'Logs {MARK}'}).json()
    assert saved['configuration']['app_title'] == f'Logs {MARK}'
    assert saved['mailcow_rw_key_changed'] is False
    assert c.put('/api/settings', json={'disabled_features': 'nope'}).status_code == 400
    assert c.put('/api/settings', json={'admin_email': 'not an address'}).status_code == 400
    assert c.put('/api/settings', json=['app_title']).status_code == 422


def test_saving_settings_while_editing_is_off(client):
    assert client.put('/api/settings', json={'app_title': 'x'}).status_code == 403
    assert client.post('/api/settings/import-from-env').status_code == 403
    assert client.post('/api/settings/purge-feature-data', json={'feature': 'dmarc'}).status_code == 403


def test_saving_settings_while_the_feature_list_is_busy(editing, monkeypatch):
    # Another save holds the samples' lock: this one waits, then changes nothing
    monkeypatch.setattr(figures, 'SWITCH_WAIT', '200ms')
    with database.engine.connect() as other:
        other.execute(text('SELECT pg_advisory_lock(:key)'), {'key': figures._LOCK_KEY})
        other.commit()
        try:
            assert editing.put('/api/settings', json={'disabled_features': ''}).status_code == 503
        finally:
            other.execute(text('SELECT pg_advisory_unlock(:key)'), {'key': figures._LOCK_KEY})
            other.commit()


def test_saving_settings_when_the_database_fails(editing):
    app.dependency_overrides[get_db] = _broken_session
    assert editing.put('/api/settings', json={'app_title': 'x'}).status_code == 500
    assert editing.post('/api/settings/import-from-env').status_code == 500


def test_import_from_env(editing):
    body = editing.post('/api/settings/import-from-env').json()
    assert body['settings_migrated'] is True and 'mailcow_url' in body['configuration']


# ---------------------------------------------------------------- purging a feature's data

class _Result:
    def scalar(self):
        return 2


class _RecordingDb:
    """Takes the statements of a purge, so no table of the shared database is emptied."""

    def execute(self, statement, *args, **kwargs):
        return _Result()

    def commit(self):
        pass

    def rollback(self):
        pass


def test_purge_feature_data(editing, monkeypatch):
    c = editing
    assert c.post('/api/settings/purge-feature-data', json={'feature': 'nope'}).status_code == 400
    assert c.post('/api/settings/purge-feature-data', json={'feature': 'dmarc'}).status_code == 400
    assert c.post('/api/settings/purge-feature-data', json=['dmarc']).status_code == 422
    # A feature name that is not text fails in the handler (main.py's handler)
    assert c.post('/api/settings/purge-feature-data', json={'feature': 5}).status_code == 500
    _set(monkeypatch, 'disabled_features', 'mailbox-stats,devices,suppressions')
    assert c.post('/api/settings/purge-feature-data', json={'feature': 'suppressions'}).status_code == 400
    # Without the Read-Write key and the Rspamd password the blocks cannot be removed
    assert c.post('/api/settings/purge-feature-data',
                  json={'feature': 'suppressions', 'rspamd': 'remove'}).json()['detail']['code'] == \
        'no_rw_key_and_password'
    app.dependency_overrides[get_db] = lambda: _RecordingDb()
    body = c.post('/api/settings/purge-feature-data', json={'feature': 'mailbox-stats'}).json()
    assert body['feature'] == 'mailbox-stats'
    app.dependency_overrides[get_db] = _broken_session
    assert c.post('/api/settings/purge-feature-data', json={'feature': 'devices'}).status_code == 500


def test_purge_when_mailcow_does_not_confirm_the_removal(editing, monkeypatch):
    _set(monkeypatch, 'disabled_features', 'suppressions')
    _set(monkeypatch, 'rspamd_password', 'placeholder')
    monkeypatch.setattr(mailcow_api, 'headers_rw', {'X-API-Key': 'placeholder'})
    content = '\n'.join(['# kept', MANAGED_MARKER_START, f'blocked@{MARK}.example', MANAGED_MARKER_END])

    async def map_id(name):
        return 1

    async def map_content(map_id):
        return content

    async def not_saved(name, data):
        raise MailcowAPIError('down')
    monkeypatch.setattr(mailcow_api, 'find_rspamd_map_id', map_id)
    monkeypatch.setattr(mailcow_api, 'get_rspamd_map_content', map_content)
    monkeypatch.setattr(mailcow_api, 'edit_rspamd_map', not_saved)
    answer = editing.post('/api/settings/purge-feature-data', json={'feature': 'suppressions', 'rspamd': 'remove'})
    assert answer.status_code == 502 and answer.json()['detail']['code'] == 'not_confirmed'


# ---------------------------------------------------------------- checks

def test_connection_tests_without_a_server(client):
    # Not configured: the tests stop before connecting
    for path in ('/api/settings/test/smtp', '/api/settings/test/imap'):
        assert client.post(path).json()['success'] is False


class _MaxMind:
    """MaxMind's license check, answering with a fixed status."""
    status = 401

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def post(self, url, **kwargs):
        return httpx.Response(self.status, request=httpx.Request('POST', url))


def test_maxmind_license(client, rows, monkeypatch):
    assert client.post('/api/settings/maxmind/validate').json()['configured'] is False
    _set(monkeypatch, 'maxmind_license_key', 'placeholder')
    monkeypatch.setattr(settings_router, 'httpx', types.SimpleNamespace(AsyncClient=_MaxMind, Timeout=httpx.Timeout))
    assert client.post('/api/settings/maxmind/validate').json()['error'] == 'Invalid'
    monkeypatch.setattr(settings_router, 'get_db_context', _broken_context)
    assert client.post('/api/settings/maxmind/validate').status_code == 500


def _answering(monkeypatch, status):
    """mailcow and Rspamd answer every request with this status."""
    transport = httpx.MockTransport(lambda request: httpx.Response(status, json={}))
    monkeypatch.setattr(mailcow_api, '_get_client', lambda: httpx.AsyncClient(transport=transport))


def test_credential_checks(client, rows, monkeypatch):
    for path in ('/api/settings/mailcow/rw-key/validate', '/api/settings/rspamd/password/validate'):
        assert client.post(path).json() == {'configured': False, 'valid': False, 'error': None}
    monkeypatch.setattr(mailcow_api, 'headers_rw', {'X-API-Key': 'placeholder'})
    _set(monkeypatch, 'rspamd_password', 'placeholder')
    _answering(monkeypatch, 401)
    assert client.post('/api/settings/mailcow/rw-key/validate').json()['error'] == 'rejected'
    _answering(monkeypatch, 302)
    assert client.post('/api/settings/rspamd/password/validate').json()['error'] == 'redirected'
    # The stored results, as the Status page reads them
    configuration = client.get('/api/settings/info').json()['configuration']
    assert configuration['mailcow_rw_key_status']['http_status'] == 401
    assert configuration['rspamd_password_status']['checked_at']
    monkeypatch.setattr(settings_router, 'get_db_context', _broken_context)
    assert client.post('/api/settings/mailcow/rw-key/validate').status_code == 500
    assert client.post('/api/settings/rspamd/password/validate').status_code == 500


# ---------------------------------------------------------------- GeoIP

def test_geoip(client, monkeypatch):
    assert client.get('/api/settings/geoip/status').json()['configured'] is False
    assert client.post('/api/settings/geoip/download').status_code == 400
    _set(monkeypatch, 'maxmind_license_key', 'placeholder')
    _set(monkeypatch, 'maxmind_account_id', '1')
    assert client.get('/api/settings/geoip/status').json()['configured'] is True

    async def not_downloaded():
        return None
    monkeypatch.setattr(scheduler, 'update_geoip_database', not_downloaded)
    assert client.post('/api/settings/geoip/download').json()['status'] == 'started'


def test_geoip_validation(client, monkeypatch):
    from app.services.geoip_downloader import get_geoip_status
    files = get_geoip_status()
    missing = {**files, 'City': {**files['City'], 'available': False}}
    monkeypatch.setattr(settings_router, 'get_geoip_status', lambda: missing)
    assert client.post('/api/settings/geoip/validate').json()['error'] == 'City database file not found'
    # The file is there: the readers are reloaded and the lookups tried
    there = {**files, 'City': {**files['City'], 'available': True}}
    monkeypatch.setattr(settings_router, 'get_geoip_status', lambda: there)
    assert 'db_valid' in client.post('/api/settings/geoip/validate').json()


# ---------------------------------------------------------------- manual job runs

def test_job_runs(client, monkeypatch):
    assert client.post('/api/settings/jobs/nope/run').status_code == 404
    # Without MaxMind credentials Update GeoIP would do nothing
    assert 'MaxMind' in client.post('/api/settings/jobs/update_geoip/run').json()['detail']

    async def checked():
        return scheduler.JOB_STATUS_SET
    monkeypatch.setattr(scheduler, 'check_app_version_update', checked)
    assert client.post('/api/settings/jobs/check_app_version/run').json()['job'] == 'check_app_version'
    scheduler.update_job_status('check_app_version', 'running')
    assert client.post('/api/settings/jobs/check_app_version/run').status_code == 409
