"""Every answer the Mailbox stats, Devices, weekly summary and CSV export calls can give,
so the contract check (conftest.py, contract.py) holds each one to /openapi.json: the
answers with data, the failures that still answer 200 (mailbox statistics), a database
that fails (500), mailcow failing (502), nothing to export (404) and bad parameters (422).
mailcow, DNS and email are faked; nothing leaves the test."""
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app import database  # noqa: E402
from app.config import settings  # noqa: E402
from app.database import get_db  # noqa: E402
from app.mailcow_api import MailcowAPIError, mailcow_api  # noqa: E402
from app.main import app  # noqa: E402
from app.routers import mailbox_stats, reporting  # noqa: E402
from app.services.csv_export import get_csv_db  # noqa: E402


MARK = uuid.uuid4().hex[:8]
DOMAIN = f'{MARK}.example'
MAILBOX = f'u@{DOMAIN}'
EXPORTS = ['postfix', 'rspamd', 'netfilter', 'messages']


class _Broken:
    def __getattr__(self, name):
        raise RuntimeError('database gone')


def _broken_session():
    yield _Broken()


def _postgres_available() -> bool:
    try:
        with database.engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture
def client(monkeypatch):
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    mailbox_stats.clear_stats_cache()
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.pop(get_db, None)
    app.dependency_overrides.pop(get_csv_db, None)
    mailbox_stats.clear_stats_cache()


@pytest.fixture
def rows(client):
    """A mailbox with an alias, a device, and one log line and message of each kind, removed after."""
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.models import (AliasStatistics, EasDevice, MailboxStatistics, MessageCorrelation, NetfilterLog,
                            PostfixLog, RspamdLog)
    database.init_db()
    now = datetime.utcnow()
    with database.get_db_context() as db:
        db.add(MailboxStatistics(username=MAILBOX, domain=DOMAIN, name='U', quota=1024, quota_used=10,
                                 active=True, last_imap_login=1700000000, attributes={'imap_access': '1'}))
        db.add(AliasStatistics(alias_address=f'a@{DOMAIN}', goto=MAILBOX, domain=DOMAIN, active=True,
                               primary_mailbox=MAILBOX))
        db.add(EasDevice(username=MAILBOX, device_id=f'androidc{MARK}', device_type='Android', last_ip='192.0.2.5',
                         last_command='Sync', last_status=200, first_seen=now - timedelta(days=1), last_seen=now))
        db.add(PostfixLog(time=now, program='postfix/smtp', queue_id=f'Q{MARK}', sender=MAILBOX,
                          recipient='r@x.example', status='sent', message=f'{MARK} sent'))
        db.add(RspamdLog(time=now, message_id=f'<{MARK}@x>', sender_smtp=MAILBOX, subject=MARK, score=1.0,
                         required_score=15.0, action='no action', is_spam=False, direction='outbound'))
        db.add(NetfilterLog(time=now, ip='192.0.2.99', username=MAILBOX, action='warning', message=f'{MARK} login'))
        db.add(MessageCorrelation(correlation_key=uuid.uuid4().hex, message_id=f'<{MARK}@x>', sender=MAILBOX,
                                  recipient=f'a@{DOMAIN}', subject=MARK, direction='internal',
                                  final_status='delivered', first_seen=now, last_seen=now, created_at=now))
        db.commit()
    yield
    with database.get_db_context() as db:
        db.query(MailboxStatistics).filter(MailboxStatistics.domain == DOMAIN).delete(synchronize_session=False)
        db.query(AliasStatistics).filter(AliasStatistics.domain == DOMAIN).delete(synchronize_session=False)
        db.query(EasDevice).filter(EasDevice.username == MAILBOX).delete(synchronize_session=False)
        db.query(PostfixLog).filter(PostfixLog.queue_id == f'Q{MARK}').delete(synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.subject == MARK).delete(synchronize_session=False)
        db.query(NetfilterLog).filter(NetfilterLog.message == f'{MARK} login').delete(synchronize_session=False)
        db.query(MessageCorrelation).filter(MessageCorrelation.subject == MARK).delete(synchronize_session=False)
        db.commit()


# ---------------------------------------------------------------- mailbox statistics

def test_mailbox_statistics(client, rows):
    page = client.get(f'/api/mailbox-stats/all?search={MARK}&active_only=false&date_range=7days').json()
    assert page['mailboxes'][0]['aliases'][0]['alias_address'] == f'a@{DOMAIN}'
    assert 'activity' in page['mailboxes'][0]
    assert client.get('/api/mailbox-stats/summary?date_range=today').json()['date_range'] == 'today'
    assert any(d['domain'] == DOMAIN for d in client.get('/api/mailbox-stats/domains').json()['domains'])
    assert 'last_mailbox_update' in client.get('/api/mailbox-stats/refresh').json()
    assert client.get('/api/mailbox-stats/all?page=0').status_code == 422


def test_mailbox_statistics_that_cannot_be_read_still_answer(client):
    app.dependency_overrides[get_db] = _broken_session
    for path in ('/api/mailbox-stats/all', '/api/mailbox-stats/summary', '/api/mailbox-stats/domains',
                 '/api/mailbox-stats/refresh'):
        response = client.get(path)
        assert response.status_code == 200 and 'error' in response.json()


# ---------------------------------------------------------------- devices

def test_devices(client, rows):
    listed = client.get(f'/api/devices?search={MARK}').json()
    assert listed['items'][0]['device_id'] == f'androidc{MARK}'
    assert client.get('/api/devices?seen=sometime').status_code == 422


def test_devices_when_the_database_fails(client):
    app.dependency_overrides[get_db] = _broken_session
    assert client.get('/api/devices').status_code == 500


# ---------------------------------------------------------------- weekly summary

@pytest.fixture
def summary_sources(monkeypatch, rows):
    """mailcow as the summary reads it (domains, mailboxes, aliases, storage, queue,
    quarantine), and a stored DNS check with an SPF problem; the summary's own code runs."""
    from app.models import DomainDNSCheck
    state = {'domains': [{'domain_name': DOMAIN, 'active': 1}], 'vmail': {'disk': '/dev/sda1', 'used': '1.2G',
                                                                          'total': '20G', 'used_percent': '6%'}}

    def answer(key):
        async def call(*args, **kwargs):
            if isinstance(state[key], Exception):
                raise state[key]
            return state[key]
        return call

    async def empty(*args, **kwargs):
        return []

    monkeypatch.setattr(mailcow_api, 'get_domains', answer('domains'))
    monkeypatch.setattr(mailcow_api, 'get_status_vmail', answer('vmail'))
    # Reading the monitored hosts would also align them with the settings
    from app.services import blacklist_service
    monkeypatch.setattr(blacklist_service, 'reconcile_monitored_hosts', lambda db: False)
    for name in ('get_mailboxes', 'get_aliases', 'get_queue', 'get_quarantine'):
        monkeypatch.setattr(mailcow_api, name, empty)
    with database.get_db_context() as db:
        db.add(DomainDNSCheck(domain_name=DOMAIN, checked_at=datetime.utcnow(),
                              spf_check={'status': 'error', 'message': 'No SPF record', 'record': None,
                                         'has_strict_all': False, 'includes_mx': False, 'includes': []}))
        db.commit()
    yield state
    with database.get_db_context() as db:
        db.query(DomainDNSCheck).filter(DomainDNSCheck.domain_name == DOMAIN).delete(synchronize_session=False)
        db.commit()


def test_the_weekly_summary(client, summary_sources):
    summary = client.get('/api/system/summary').json()
    assert summary['dns_issues'] == [{'domain': DOMAIN, 'issues': ['SPF: No SPF record']}]
    assert summary['system']['domains'] == {'total': 1, 'active': 1}
    # mailcow failing while the summary is read (502)
    summary_sources['domains'] = MailcowAPIError('down')
    assert client.get('/api/system/summary').status_code == 502
    # mailcow answering storage in a shape the summary cannot read (500)
    summary_sources['domains'] = [{'domain_name': DOMAIN, 'active': 1}]
    summary_sources['vmail'] = ['not', 'an', 'object']
    assert client.get('/api/system/summary').status_code == 500


def test_the_weekly_summary_email(client, monkeypatch):
    async def not_sent():
        return None
    monkeypatch.setattr(reporting, 'generate_and_send_email', not_sent)
    monkeypatch.setattr(settings._inner, 'enable_weekly_summary', False)
    assert client.post('/api/system/summary/email').json()['status'] == 'skipped'
    assert client.post('/api/system/summary/email?force=true').json()['status'] == 'queued'
    assert client.post('/api/system/summary/email?force=maybe').status_code == 422


# ---------------------------------------------------------------- CSV exports

@pytest.mark.parametrize('kind', EXPORTS)
def test_csv_exports(client, rows, kind):
    response = client.get(f'/api/export/{kind}/csv?search={MARK}')
    assert response.status_code == 200 and response.headers['content-type'].startswith('text/csv')
    assert client.get(f'/api/export/{kind}/csv?search=nothing-{MARK}-matches').status_code == 404
    assert client.get(f'/api/export/{kind}/csv?start_date=not-a-date').status_code == 422


@pytest.mark.parametrize('kind', EXPORTS)
def test_csv_exports_when_the_database_fails(client, kind):
    app.dependency_overrides[get_csv_db] = _broken_session
    assert client.get(f'/api/export/{kind}/csv').status_code == 500
