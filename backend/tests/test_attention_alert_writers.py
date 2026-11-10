"""Alerts that used to go only by email or a channel are kept for Needs attention.

DNS changes, DMARC & TLS report import errors, and the protection rules'
possible stolen passwords and failed bans are stored as alerts with a short
line, each in its own session. Storing is best effort: a failure is logged and
the notification and the job go on. The email keeps the details.
"""
import asyncio
import contextlib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.services import stored_alerts

DOMAIN = 'alerts-writers.example.com'


@pytest.fixture
def recorded(monkeypatch):
    """The alerts stored, as record() was called; nothing reaches a database."""
    calls = []

    def record(alert_type, severity, title, detail, subject=None, metric_value=None):
        calls.append(SimpleNamespace(alert_type=alert_type, severity=severity, title=title, detail=detail,
                                     subject=subject, metric_value=metric_value))
        return True
    monkeypatch.setattr(stored_alerts, 'record', record)
    return calls


@contextlib.contextmanager
def _commit_fails():
    """A session whose commit fails, as get_db_context does it: the error comes out."""
    session = Mock()
    yield session
    raise RuntimeError('database is gone')


# ---------- the short lines ----------

@pytest.mark.parametrize('types, line', [
    (['SPF'], 'SPF changed.'),
    (['SPF', 'DKIM'], 'SPF and DKIM changed.'),
    (['SPF', 'DKIM', 'DMARC'], 'SPF, DKIM and 1 more changed.'),
    (['SPF', 'DKIM', 'DMARC', 'TLSA (DANE)', 'MTA-STS', 'TLS-RPT'], 'SPF, DKIM and 4 more changed.'),
    # Each kind once, in the order found; TLSA (DANE) and DANE are different changes
    (['DKIM', 'DKIM', 'SPF'], 'DKIM and SPF changed.'),
    (['TLSA (DANE)', 'DANE'], 'TLSA (DANE) and DANE changed.'),
    (['DNSSEC'], 'DNSSEC changed.'),
])
def test_a_dns_change_says_which_kinds_changed_in_a_short_line(types, line):
    changes = [{'type': t, 'old': 'v=spf1 -all', 'new': 'v=spf1 include:example.org -all'} for t in types]
    assert stored_alerts.dns_types_line(changes) == line


def test_a_dns_change_alert_names_the_domain_and_never_a_record_value(recorded):
    changes = [{'type': 'SPF', 'old': 'v=spf1 -all', 'new': 'v=spf1 include:example.org -all'},
               {'type': 'DKIM', 'old': 'k=rsa; p=OLD', 'new': 'k=rsa; p=NEW'}]
    assert stored_alerts.record_dns_change(DOMAIN, changes)
    [alert] = recorded
    assert (alert.alert_type, alert.severity, alert.subject, alert.metric_value) == ('dns_change', 'warning', DOMAIN, 2)
    assert alert.title == f'DNS changes detected for {DOMAIN}'
    assert alert.detail == 'SPF and DKIM changed.'
    assert 'p=NEW' not in alert.detail and 'example.org' not in alert.detail


def test_no_dns_change_alert_without_a_change(recorded):
    assert not stored_alerts.record_dns_change(DOMAIN, [])
    assert recorded == []


@pytest.mark.parametrize('n, line', [(1, 'Could not fully import 1 report email.'),
                                     (3, 'Could not fully import 3 report emails.')])
def test_a_dmarc_import_alert_counts_the_emails(recorded, n, line):
    stored_alerts.record_dmarc_import_failed([{'email_id': str(i)} for i in range(n)])
    [alert] = recorded
    assert (alert.alert_type, alert.title, alert.detail, alert.metric_value, alert.subject) == (
        'dmarc_import_failed', 'DMARC & TLS report import errors', line, n, None)


@pytest.mark.parametrize('usernames, subject', [
    (['info@example.com'], 'info@example.com'),
    ([], '198.51.100.7'),
    (None, '198.51.100.7'),
    (['', '  '], '198.51.100.7'),
    # A hit can collect several accounts: the first in order, always the same one
    (['zed@example.com', 'ann@example.com'], 'ann@example.com'),
])
def test_a_possible_stolen_password_names_its_account_else_its_address(recorded, usernames, subject):
    stored_alerts.record_protection_breach('198.51.100.7', usernames)
    [alert] = recorded
    assert (alert.alert_type, alert.severity, alert.subject) == ('protection_breach', 'critical', subject)
    assert alert.title == f'Possible stolen password: {subject}'
    assert alert.detail == 'An unusual sign-in may mean someone else has access.'


@pytest.mark.parametrize('targets, line', [
    (['198.51.100.7'], 'Could not ban 1 address or network.'),
    # Two rules caught one address: it counts once; a network is a target too
    (['198.51.100.7', '198.51.100.7', '198.51.100.0/24'], 'Could not ban 2 addresses or networks.'),
])
def test_failed_bans_count_each_address_or_network_once(recorded, targets, line):
    stored_alerts.record_protection_ban_failed(targets)
    [alert] = recorded
    assert (alert.alert_type, alert.title, alert.detail, alert.metric_value) == (
        'protection_ban_failed', 'Protection rules could not ban addresses', line, len(set(targets)))


def test_every_line_ends_with_a_period_and_no_title_does():
    texts = [stored_alerts.dns_types_line([{'type': 'SPF'}]), stored_alerts.BREACH_DETAIL]
    assert all(t.endswith('.') for t in texts)
    for title in ('DNS changes detected for example.com', 'DMARC & TLS report import errors',
                  'Protection rules could not ban addresses'):
        assert not title.endswith('.')


def test_a_long_subject_keeps_the_title_in_its_column_and_is_never_cut(monkeypatch):
    added = []

    @contextlib.contextmanager
    def session():
        yield SimpleNamespace(add=added.append)
    monkeypatch.setattr(stored_alerts, 'get_db_context', session)
    long_domain = ('a' * 62 + '.') * 4 + 'example.com'
    assert len(long_domain) > 255
    assert stored_alerts.record_dns_change(long_domain, [{'type': 'SPF'}])
    [row] = added
    assert len(row.title) == 255 and row.title.endswith('...')
    # A cut domain would name another one: it is left out instead
    assert row.subject is None
    short = 'b' * 240 + '.example.com'
    stored_alerts.record_dns_change(short, [{'type': 'SPF'}])
    assert added[1].subject == short and len(added[1].title) == 255


def test_an_alert_that_cannot_be_stored_is_logged_and_does_not_raise(monkeypatch, caplog):
    monkeypatch.setattr(stored_alerts, 'get_db_context', _commit_fails)
    assert stored_alerts.record_dmarc_import_failed([{'email_id': '1'}]) is False
    assert 'Could not store the dmarc_import_failed alert' in caplog.text


def test_every_type_has_one_area():
    assert set(stored_alerts.ALERT_AREAS.values()) == {'security', 'domains', 'dmarc'}
    assert set(stored_alerts.ACTIVITY_TYPES) <= set(stored_alerts.ALERT_AREAS)
    assert stored_alerts.types_in(['domains']) == ['dns_change']
    assert stored_alerts.types_in(['dmarc']) == ['dmarc_import_failed']
    for name in stored_alerts.ALERT_AREAS:
        assert len(name) <= 40   # models.SecurityAlert.alert_type


# ---------- DNS changes ----------

def test_a_dns_change_is_stored_and_still_mailed_when_storing_fails(monkeypatch):
    from app.routers import domains
    from app.services import notification_service
    sent = []
    monkeypatch.setattr(notification_service, 'notify', lambda subject, text, **kw: sent.append(subject))
    monkeypatch.setattr(stored_alerts, 'get_db_context', _commit_fails)
    domains.notify_dns_changes(DOMAIN, [{'type': 'SPF', 'old': 'v=spf1 -all', 'new': 'v=spf1 ~all'}])
    assert sent == [f'DNS records changed for {DOMAIN}: SPF']


def test_a_dns_change_is_stored_once_with_its_email(monkeypatch, recorded):
    from app.routers import domains
    from app.services import notification_service
    monkeypatch.setattr(notification_service, 'notify', lambda subject, text, **kw: None)
    domains.notify_dns_changes(DOMAIN, [{'type': 'DKIM', 'old': 'p=A', 'new': 'p=B'}])
    domains.notify_dns_changes(DOMAIN, [])
    assert [(a.alert_type, a.detail) for a in recorded] == [('dns_change', 'DKIM changed.')]


def test_a_dns_check_that_could_not_be_saved_stores_no_alert(monkeypatch, recorded):
    from app.routers import domains
    monkeypatch.setattr(domains.settings._inner, 'dns_change_alerts_enabled', True)
    monkeypatch.setattr(domains, 'detect_dns_changes', lambda previous, data: [{'type': 'SPF', 'old': 'a', 'new': 'b'}])
    db = Mock()
    db.query.return_value.filter.return_value.first.return_value = None
    db.commit.side_effect = RuntimeError('database is gone')
    with pytest.raises(RuntimeError):
        asyncio.run(domains.save_dns_check_to_db(db, DOMAIN, {'spf': {'status': 'success', 'record': 'b'}}))
    assert recorded == []


# ---------- DMARC & TLS import errors ----------

FAILED = [{'email_id': '7', 'message_id': '<m@example.com>', 'subject': 'Report', 'error': 'Not a report'}]


def test_an_import_error_is_stored_even_with_no_email_or_channel_set_up(monkeypatch, recorded):
    from app.services import dmarc_notifications
    monkeypatch.setattr(dmarc_notifications, 'get_notification_email', lambda configured: None)
    monkeypatch.setattr(dmarc_notifications, 'any_channel_configured', lambda: False)
    sent = []
    monkeypatch.setattr(dmarc_notifications, 'notify', lambda *a, **kw: sent.append(a))
    # Nothing was sent: the answer still says so
    assert dmarc_notifications.send_dmarc_error_notification(FAILED, 5) is False
    assert sent == [] and [a.alert_type for a in recorded] == ['dmarc_import_failed']
    assert dmarc_notifications.send_dmarc_error_notification([], 6) is True
    assert len(recorded) == 1


def test_an_import_error_is_still_sent_when_storing_fails(monkeypatch):
    from app.services import dmarc_notifications
    monkeypatch.setattr(stored_alerts, 'get_db_context', _commit_fails)
    monkeypatch.setattr(dmarc_notifications, 'get_notification_email', lambda configured: 'admin@example.com')
    sent = []
    monkeypatch.setattr(dmarc_notifications, 'notify', lambda subject, text, html, email_recipient, alert_type:
                        sent.append(email_recipient) or {'email': True, 'channels_sent': 0})
    assert dmarc_notifications.send_dmarc_error_notification(FAILED, 5) is True
    assert sent == ['admin@example.com']


def test_an_import_that_fails_stores_one_alert_and_the_job_adds_none(monkeypatch, recorded):
    import app.services.dmarc_imap_service as imap_module
    from app import scheduler
    from app.services import dmarc_notifications
    from tests.test_dmarc_imap_bounces import FakeImap, _SyncRecord
    delivered = []
    monkeypatch.setattr(dmarc_notifications, 'get_notification_email', lambda configured: 'admin@example.com')
    # The email does not arrive: the import still counts the failures as reported
    monkeypatch.setattr(dmarc_notifications, 'notify', lambda *a, **kw: delivered.append(1) or {'email': False, 'channels_sent': 0})
    service = imap_module.DMARCImapService()
    service.connection = FakeImap({})
    monkeypatch.setattr(service, 'connect', lambda: True)
    monkeypatch.setattr(service, 'select_folder', lambda *folder: True)
    monkeypatch.setattr(service, 'disconnect', lambda: None)
    monkeypatch.setattr(imap_module, 'SessionLocal', Mock)
    monkeypatch.setattr(imap_module, 'DMARCSync', _SyncRecord)
    monkeypatch.setattr(imap_module, 'folder_targets', lambda connection, folder: ([SimpleNamespace(select='INBOX', label='INBOX')], [], [], 0))

    def sync_folder(db, record, folder, batch_size, counts, failed_emails):
        failed_emails.append(dict(FAILED[0]))
        raise RuntimeError('IMAP connection lost')
    monkeypatch.setattr(service, '_sync_folder', sync_folder)

    result = service.sync_reports()
    assert result['status'] == 'error' and result['notified'] is True and len(delivered) == 1
    assert [a.alert_type for a in recorded] == ['dmarc_import_failed']

    monkeypatch.setattr(scheduler.settings._inner, 'dmarc_imap_enabled', True)
    monkeypatch.setattr(type(scheduler.settings._inner), 'is_feature_enabled', lambda self, name: True)
    monkeypatch.setattr(scheduler, 'sync_dmarc_reports_from_imap', lambda trigger: result)
    saved = dict(scheduler.job_status['dmarc_imap_sync'])
    try:
        asyncio.run(scheduler.dmarc_imap_sync_job())
    finally:
        scheduler.job_status['dmarc_imap_sync'] = saved
    assert len(recorded) == 1 and len(delivered) == 1


# ---------- the protection rules ----------

def _breach(ip='198.51.100.7', usernames=('info@example.com',)):
    from app.scheduler import BreachFound
    return BreachFound(41, ip, 'breach', f'{usernames[0] if usernames else ip} logged in after 3 failed tries', tuple(usernames))


@pytest.fixture
def protection_run(monkeypatch):
    """The protection job with its parts replaced: what it stores, sends and says, in order."""
    from app import scheduler
    from app.services import protection_rules
    events, statuses, sent = [], [], []
    monkeypatch.setattr(protection_rules, 'load_rules', lambda db: {name: {'enabled': False} for name in protection_rules.RULE_NAMES})
    monkeypatch.setattr(scheduler, 'get_db_context', lambda: contextlib.nullcontext(Mock()))
    monkeypatch.setattr(scheduler, 'update_job_status', lambda job, status, error=None: statuses.append(status))
    monkeypatch.setattr(scheduler, 'mailcow_api', SimpleNamespace(has_rw_key=True))
    monkeypatch.setattr(scheduler.geoip_service, 'is_geoip_available', lambda: False)
    monkeypatch.setattr(scheduler, '_notify_protection', lambda banned, failed, alerts: sent.append((banned, failed, alerts)))
    real_record = stored_alerts.record

    def record(alert_type, *args, **kwargs):
        events.append(('store', alert_type))
        return real_record(alert_type, *args, **kwargs)
    monkeypatch.setattr(stored_alerts, 'record', record)
    stored = []

    @contextlib.contextmanager
    def session():
        yield SimpleNamespace(add=stored.append)
    monkeypatch.setattr(stored_alerts, 'get_db_context', session)

    def run(breaches=(), enforce=None):
        monkeypatch.setattr(scheduler, '_run_protection_rules_sync', lambda context: list(breaches))

        async def enforced(api):
            events.append(('enforce',))
            if isinstance(enforce, Exception):
                raise enforce
            return enforce or {'banned': [], 'lifted': [], 'failed': []}
        monkeypatch.setattr(protection_rules, 'enforce', enforced)
        asyncio.run(scheduler._run_protection_rules_locked())
    return SimpleNamespace(run=run, events=events, statuses=statuses, sent=sent, stored=stored)


def test_a_possible_stolen_password_is_stored_before_the_bans_and_kept_when_they_fail(protection_run):
    protection_run.run([_breach()], enforce=RuntimeError('mailcow did not answer'))
    assert protection_run.events == [('store', 'protection_breach'), ('enforce',)]
    [row] = protection_run.stored
    assert (row.alert_type, row.subject, row.severity) == ('protection_breach', 'info@example.com', 'critical')
    # The notification still goes, and the run is marked failed
    [(banned, failed, alerts)] = protection_run.sent
    assert alerts == [('198.51.100.7', 'breach', 'info@example.com logged in after 3 failed tries')]
    assert protection_run.statuses[-1] == 'failed'


def test_failed_bans_are_stored_once_per_target_and_only_for_rules_that_notify(protection_run):
    failed = [('198.51.100.7', 'trap', 'Tried the trap account admin', True),
              ('198.51.100.7', 'unknown_accounts', 'Tried 5 unknown accounts', True),
              ('198.51.100.0/24', 'subnet', 'Attacks from the network', True),
              ('203.0.113.9', 'country', 'From a blocked country', False)]
    protection_run.run(enforce={'banned': [], 'lifted': [], 'failed': failed})
    [row] = protection_run.stored
    assert (row.alert_type, row.detail, row.metric_value) == (
        'protection_ban_failed', 'Could not ban 2 addresses or networks.', 2)
    assert protection_run.statuses[-1] == 'success'
    [(banned, sent_failed, alerts)] = protection_run.sent
    assert '203.0.113.9' not in [f[0] for f in sent_failed]


def test_no_failed_ban_alert_when_every_failing_rule_does_not_notify(protection_run):
    protection_run.run(enforce={'banned': [], 'lifted': [], 'failed': [('203.0.113.9', 'country', 'x', False)]})
    assert protection_run.stored == [] and protection_run.sent == []


def test_without_a_read_write_key_nothing_is_banned_and_nothing_failed(protection_run, monkeypatch):
    from app import scheduler
    monkeypatch.setattr(scheduler, 'mailcow_api', SimpleNamespace(has_rw_key=False))
    protection_run.run(enforce=RuntimeError('must not be called'))
    assert ('enforce',) not in protection_run.events and protection_run.stored == []
    assert protection_run.statuses[-1] == 'success'


def test_a_breach_alert_that_cannot_be_stored_is_still_sent(protection_run, monkeypatch):
    monkeypatch.setattr(stored_alerts, 'get_db_context', _commit_fails)
    protection_run.run([_breach()])
    assert len(protection_run.sent) == 1 and protection_run.statuses[-1] == 'success'


# ---------- with the database ----------

def test_a_read_failure_names_each_pending_ban_with_its_notify_setting(db):
    from test_protection_enforce import _enforce, _trap_hit
    from test_protection_rules import TRAP_IP

    class Unreadable:
        has_rw_key = True

        async def get_fail2ban(self):
            return None
    _trap_hit(db, notify=False)
    result = _enforce(Unreadable())
    assert [(f[0], f[1], f[3]) for f in result['failed']] == [(TRAP_IP, 'trap', False)]
    db.expire_all()
    from test_protection_rules import _hits
    assert _hits(db)[0].error == 'Could not read the Fail2ban settings from mailcow'


def test_the_evaluation_hands_out_the_breachs_account_as_plain_values(db):
    from app import scheduler
    from app.services import protection_rules
    from test_protection_enforce import _login
    from test_protection_rules import DOMAIN as RULES_DOMAIN, SPRAY_IP, _context, _fail, _rules
    _rules(db, breach={'enabled': True, 'failures': 3, 'window_minutes': 60, 'notify': True})
    protection_rules.evaluate(db, _context())
    for _ in range(3):
        _fail(db, SPRAY_IP, f'info@{RULES_DOMAIN}', minutes_ago=10)
    _login(db, SPRAY_IP, f'info@{RULES_DOMAIN}')
    [found] = scheduler._run_protection_rules_sync(_context())
    assert (found.ip, found.rule, found.usernames) == (SPRAY_IP, 'breach', (f'info@{RULES_DOMAIN}',))
    assert isinstance(found.hit_id, int)
    assert stored_alerts.breach_subject(found.ip, found.usernames) == f'info@{RULES_DOMAIN}'


from test_protection_rules import db  # noqa: E402,F401  (a fixture)
