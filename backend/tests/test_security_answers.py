"""Every answer the Security alerts, Protection rules, SMTP abuse, Rate limits and
Blacklist calls can give, so the contract check (conftest.py, contract.py) holds each
one to /openapi.json: the answers with data, a database that fails (500), mailcow
refusing or not answering (502, 500 where the call turns a refusal into one), the
Read-Write key or the feature missing (403, 503) and the requests the calls refuse
(400, 404, 409, 422). mailcow and DNS are faked; nothing leaves the test."""
import uuid
from contextlib import contextmanager
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
from app.routers import blacklist, rate_limits  # noqa: E402
from app.services import blacklist_service, protection_rules, smtp_abuse_service  # noqa: E402

MARK = uuid.uuid4().hex[:8]
DOMAIN = f'{MARK}.example'
MAILBOX = f'u@{DOMAIN}'
OK = [{'type': 'success', 'msg': ['object_modified', 'x']}]
# The protection rules, the rate limit reset audit and the ignored blocklists
SHARED_KEYS = (protection_rules.RULES_KEY, 'rate_limit_resets', 'ignore.blocklists')


class _Broken:
    def __getattr__(self, name):
        raise RuntimeError('database gone')


def _broken_session():
    yield _Broken()


@contextmanager
def _broken_context():
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
    monkeypatch.setattr(settings._inner, 'smtp_abuse_enabled', True)
    monkeypatch.setattr(settings._inner, 'smtp_abuse_revoke_app_passwords', False)
    state = {'rw': True, 'mailcow': OK}
    monkeypatch.setattr(type(mailcow_api), 'has_rw_key', property(lambda self: state['rw']))

    async def answer(*args, **kwargs):
        if isinstance(state['mailcow'], Exception):
            raise state['mailcow']
        return state['mailcow']

    async def domain_limit(domain):
        return {'value': '50', 'frame': 'h'}

    async def no_mailboxes():
        return []

    for name in ('edit_mailbox', 'edit_rl_mbox', 'edit_rl_mboxes', 'edit_rl_domain', 'edit_rl_domains',
                 'delete_rl_hash'):
        monkeypatch.setattr(mailcow_api, name, answer)
    monkeypatch.setattr(mailcow_api, 'get_rl_domain', domain_limit)
    monkeypatch.setattr(mailcow_api, 'get_mailboxes', no_mailboxes)

    async def not_sent(*args, **kwargs):
        return None
    # A block notifies the operator and the user; nothing is sent from a test
    monkeypatch.setattr(smtp_abuse_service, '_notify_operator_blocked', not_sent)
    monkeypatch.setattr(smtp_abuse_service, '_notify_user_blocked', not_sent)
    # Reading the monitored hosts would also align them with the settings
    monkeypatch.setattr(blacklist_service, 'reconcile_monitored_hosts', lambda db: False)
    rate_limits._bust_domain_limit_cache()
    yield TestClient(app, raise_server_exceptions=False), state
    app.dependency_overrides.pop(get_db, None)
    rate_limits._bust_domain_limit_cache()


@pytest.fixture
def rows(client):
    """A mailbox, an alert and three catches of this test, removed after it."""
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.models import (MailboxStatistics, ProtectionHit, SecurityAlert, SMTPAbuseAction, SMTPAbuseWhitelist,
                            SystemSetting)
    database.init_db()
    now = datetime.utcnow()
    with database.get_db_context() as db:
        # What these calls change that other tests and the app share, put back after
        settings_before = {row.key: (row.value, row.updated_at)
                           for row in db.query(SystemSetting).filter(SystemSetting.key.in_(SHARED_KEYS))}
        whitelist_before = {row.email: (row.notes, row.active, row.updated_at) for row in db.query(SMTPAbuseWhitelist)}
        # Saving the rules can move other catches back to watching
        catches_before = {row.id: (row.status, row.mode) for row in db.query(ProtectionHit)}
        db.add(MailboxStatistics(username=MAILBOX, domain=DOMAIN, active=True))
        alert = SecurityAlert(alert_type='auth_failure_burst', severity='warning', subject=MAILBOX,
                              title='Failed logins', detail='12 failures in the last 15 minutes', created_at=now)
        hits = {status: ProtectionHit(ip=f'198.51.100.{n}', rule=rule, mode='watch', status=status, attempts=3,
                                      usernames=[MARK], first_seen=now, last_seen=now, owned=owned)
                for n, (status, rule, owned) in enumerate([('watching', 'trap', False), ('banned', 'trap', True),
                                                          ('alert', 'breach', False)], start=1)}
        db.add(alert)
        db.add_all(hits.values())
        db.commit()
        # The catch with status alert keeps its key; the security alert has its own
        ids = {**{status: hit.id for status, hit in hits.items()}, 'security_alert': alert.id}
    yield ids
    with database.get_db_context() as db:
        db.query(MailboxStatistics).filter(MailboxStatistics.domain == DOMAIN).delete(synchronize_session=False)
        db.query(SecurityAlert).filter(SecurityAlert.subject == MAILBOX).delete(synchronize_session=False)
        db.query(ProtectionHit).filter(ProtectionHit.usernames.contains([MARK])).delete(synchronize_session=False)
        db.query(SMTPAbuseAction).filter(SMTPAbuseAction.email == MAILBOX).delete(synchronize_session=False)
        for row in db.query(SMTPAbuseWhitelist).all():
            if row.email not in whitelist_before:
                db.delete(row)
            else:
                row.notes, row.active, row.updated_at = whitelist_before[row.email]
        for key in SHARED_KEYS:
            row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
            if key not in settings_before:
                if row is not None:
                    db.delete(row)
            elif row is None:
                db.add(SystemSetting(key=key, value=settings_before[key][0], updated_at=settings_before[key][1]))
            else:
                row.value, row.updated_at = settings_before[key]
        for row in db.query(ProtectionHit).filter(ProtectionHit.id.in_(list(catches_before))):
            row.status, row.mode = catches_before[row.id]
        db.commit()


# ---------------------------------------------------------------- security alerts

def test_security_alerts(client, rows):
    c, _ = client
    assert c.get('/api/security-alerts?limit=500').status_code == 200
    assert c.get(f"/api/security-alerts/{rows['security_alert']}/activity").status_code == 200
    receipt = c.post(f"/api/security-alerts/{rows['security_alert']}/acknowledge").json()['receipt']
    assert c.post(f'/api/security-alerts/acknowledgements/{receipt}/undo').json()['restored'] == 1
    assert c.post('/api/security-alerts/acknowledge-all', json={'ids': [rows['security_alert']]}).status_code == 200
    for path in ('/api/security-alerts?limit=0', '/api/security-alerts/x/activity'):
        assert c.get(path).status_code == 422
    for path in ('/api/security-alerts/x/acknowledge', '/api/security-alerts/acknowledgements/x/undo'):
        assert c.post(path).status_code == 422


def test_security_alerts_when_the_database_fails(client):
    c, _ = client
    app.dependency_overrides[get_db] = _broken_session
    assert c.get('/api/security-alerts').status_code == 500
    assert c.get('/api/security-alerts/1/activity').status_code == 500
    for path in ('/api/security-alerts/1/acknowledge', '/api/security-alerts/acknowledge-all',
                 f'/api/security-alerts/acknowledgements/{uuid.uuid4()}/undo'):
        assert c.post(path).status_code == 500


# ---------------------------------------------------------------- protection rules

def test_protection_rules_and_catches(client, rows, monkeypatch):
    c, state = client
    rules = c.get('/api/protection/rules').json()['rules']
    assert c.put('/api/protection/rules', json={'rules': rules}).status_code == 200
    assert c.put('/api/protection/rules', json={'rules': {'trap': {'mode': 'nope'}}}).status_code == 400
    assert c.put('/api/protection/rules').status_code == 422
    assert c.get('/api/protection/hits?status=all&limit=1000').status_code == 200
    assert c.get('/api/protection/hits?limit=0').status_code == 422
    assert c.post(f"/api/protection/hits/{rows['alert']}/dismiss").json()['status'] == 'dismissed'
    for action in ('dismiss', 'ban', 'undo'):
        assert c.post(f'/api/protection/hits/0/{action}').status_code == 404
        assert c.post(f'/api/protection/hits/x/{action}').status_code == 422
    # Ban: only a watched catch of a banning rule, with the Read-Write key
    assert c.post(f"/api/protection/hits/{rows['banned']}/ban").status_code == 409
    state['rw'] = False
    assert c.post(f"/api/protection/hits/{rows['watching']}/ban").status_code == 400
    assert c.post(f"/api/protection/hits/{rows['banned']}/undo").status_code == 400
    state['rw'] = True

    # A ban and its undo that succeed run for real against a fake mailcow in the
    # protection rules' own API tests; here, the ones mailcow does not take
    async def nothing_written(api, now=None):
        return {}
    monkeypatch.setattr(protection_rules, 'enforce', nothing_written)
    assert c.post(f"/api/protection/hits/{rows['watching']}/ban").status_code == 502

    async def refused(api, hit_id):
        raise RuntimeError('mailcow refused the change')
    monkeypatch.setattr(protection_rules, 'undo', refused)
    assert c.post(f"/api/protection/hits/{rows['banned']}/undo").status_code == 502


def test_protection_when_the_database_fails(client):
    c, _ = client
    app.dependency_overrides[get_db] = _broken_session
    assert c.get('/api/protection/rules').status_code == 500
    assert c.put('/api/protection/rules', json={'rules': {}}).status_code == 500
    assert c.get('/api/protection/hits').status_code == 500
    for action in ('dismiss', 'ban', 'undo'):
        assert c.post(f'/api/protection/hits/1/{action}').status_code == 500


# ---------------------------------------------------------------- SMTP abuse

def test_smtp_abuse(client, rows, monkeypatch):
    c, state = client
    monkeypatch.setattr(smtp_abuse_service, 'fetch_outbound_counts', lambda window, limit=None: {MAILBOX: 7})
    assert c.get('/api/smtp-abuse/status').json()['mailboxes'][0]['message_count'] == 7
    assert c.get('/api/smtp-abuse/status?limit=0').status_code == 422
    assert c.post('/api/smtp-abuse/whitelist', json={'email': f'w@{DOMAIN}'}).json()['active'] is True
    assert c.post('/api/smtp-abuse/whitelist', json={'email': 'not an address'}).status_code == 422
    assert any(e['email'] == f'w@{DOMAIN}' for e in c.get('/api/smtp-abuse/whitelist').json())
    assert c.put('/api/smtp-abuse/whitelist', json={'emails': [f'w@{DOMAIN}']}).json()['count'] >= 1
    assert c.put('/api/smtp-abuse/whitelist', json={'emails': ['nope']}).status_code == 422
    assert c.put('/api/smtp-abuse/whitelist', json={'emails': 'nope'}).status_code == 422
    assert c.delete(f'/api/smtp-abuse/whitelist/w@{DOMAIN}').json()['active'] is False
    assert c.delete(f'/api/smtp-abuse/whitelist/never@{DOMAIN}').status_code == 404
    assert c.post(f'/api/smtp-abuse/mailboxes/{MAILBOX}/block').json()['smtp_access'] is False
    assert c.post(f'/api/smtp-abuse/mailboxes/{MAILBOX}/unblock').json()['smtp_access'] is True
    assert c.get('/api/smtp-abuse/history?limit=500').status_code == 200
    assert c.get('/api/smtp-abuse/history?limit=0').status_code == 422
    # mailcow not answering (502), or refusing the change, which the call turns into a 500
    for answer, status in ((MailcowAPIError('down'), 502), ([{'type': 'danger', 'msg': 'alias'}], 500)):
        state['mailcow'] = answer
        assert c.post(f'/api/smtp-abuse/mailboxes/{MAILBOX}/block').status_code == status
        assert c.post(f'/api/smtp-abuse/mailboxes/{MAILBOX}/unblock').status_code == status


WRITES = [('post', '/api/smtp-abuse/whitelist', {'email': f'w@{DOMAIN}'}),
          ('put', '/api/smtp-abuse/whitelist', {'emails': []}),
          ('delete', f'/api/smtp-abuse/whitelist/w@{DOMAIN}', None),
          ('post', f'/api/smtp-abuse/mailboxes/{MAILBOX}/block', None),
          ('post', f'/api/smtp-abuse/mailboxes/{MAILBOX}/unblock', None)]


@pytest.mark.parametrize('method, path, body', WRITES)
def test_smtp_abuse_writes_need_the_feature_and_the_key(client, monkeypatch, method, path, body):
    c, state = client
    send = getattr(c, method)
    kwargs = {'json': body} if body is not None else {}
    state['rw'] = False
    assert send(path, **kwargs).status_code == 503
    monkeypatch.setattr(settings._inner, 'smtp_abuse_enabled', False)
    assert send(path, **kwargs).status_code == 403


def test_smtp_abuse_when_the_database_fails(client, monkeypatch):
    c, _ = client

    def broken(*args, **kwargs):
        raise RuntimeError('database gone')
    for name in ('fetch_outbound_counts', 'fetch_whitelist', 'upsert_whitelist_entry', 'set_whitelist',
                 'deactivate_whitelist_entry'):
        monkeypatch.setattr(smtp_abuse_service, name, broken)
    monkeypatch.setattr(database, 'get_db_context', _broken_context)
    assert c.get('/api/smtp-abuse/status').status_code == 500
    assert c.get('/api/smtp-abuse/whitelist').status_code == 500
    assert c.get('/api/smtp-abuse/history').status_code == 500
    # Unblock reads nothing first; its 500 is mailcow refusing (test_smtp_abuse)
    for method, path, body in WRITES[:4]:
        kwargs = {'json': body} if body is not None else {}
        assert getattr(c, method)(path, **kwargs).status_code == 500


# ---------------------------------------------------------------- rate limits

def test_rate_limit_reads(client, rows):
    c, _ = client
    assert c.get('/api/rate-limits/events').status_code == 200
    assert c.get('/api/rate-limits/events?hours=0').status_code == 422
    assert c.get(f'/api/rate-limits/sender-events?user={MAILBOX}').json()['user'] == MAILBOX
    assert c.get('/api/rate-limits/sender-events').status_code == 400
    limits = c.get('/api/rate-limits/limits').json()
    assert any(mb['username'] == MAILBOX for mb in limits['mailboxes'])


def test_rate_limit_changes(client, rows, monkeypatch):
    c, state = client
    monkeypatch.setattr(rate_limits, '_load_known_domains_worker', lambda: {DOMAIN})
    calls = [('/api/rate-limits/mailbox', {'mailbox': MAILBOX, 'value': 50, 'frame': 'h'}),
             ('/api/rate-limits/domain', {'domain': DOMAIN, 'value': 50, 'frame': 'h'}),
             ('/api/rate-limits/bulk', {'mailboxes': [MAILBOX], 'domains': [DOMAIN, 'gone.example'],
                                        'value': 0, 'frame': 'h'}),
             ('/api/rate-limits/reset', {'rl_hash': 'RLabc123', 'user': MAILBOX})]
    for path, body in calls:
        assert c.post(path, json=body).status_code == 200
        assert c.post(path, json={}).status_code == 422
        state['mailcow'] = MailcowAPIError('down')
        assert c.post(path, json=body).status_code == 502
        state['mailcow'] = OK
        state['rw'] = False
        assert c.post(path, json=body).status_code == 503
        state['rw'] = True
    bad = [('/api/rate-limits/mailbox', {'mailbox': 'nobody@x.example', 'value': 5, 'frame': 'h'}),
           ('/api/rate-limits/domain', {'domain': DOMAIN, 'value': -1, 'frame': 'h'}),
           ('/api/rate-limits/bulk', {'mailboxes': [], 'domains': [], 'value': 5, 'frame': 'h'}),
           ('/api/rate-limits/reset', {'rl_hash': 'not-a-hash'})]
    for path, body in bad:
        assert c.post(path, json=body).status_code == 400


def test_rate_limits_when_the_database_fails(client, monkeypatch):
    c, _ = client
    app.dependency_overrides[get_db] = _broken_session
    monkeypatch.setattr(rate_limits, 'SessionLocal', _broken_context)
    assert c.get('/api/rate-limits/events').status_code == 500
    assert c.get('/api/rate-limits/sender-events?user=a@b.example').status_code == 500
    assert c.get('/api/rate-limits/limits').status_code == 500
    for path, body in (('/api/rate-limits/mailbox', {'mailbox': 'a@b.example', 'value': 5, 'frame': 'h'}),
                       ('/api/rate-limits/domain', {'domain': 'b.example', 'value': 5, 'frame': 'h'}),
                       ('/api/rate-limits/bulk', {'mailboxes': ['a@b.example'], 'value': 5, 'frame': 'h'})):
        assert c.post(path, json=body).status_code == 500

    async def broken(rl_hash):
        raise RuntimeError('broken')
    monkeypatch.setattr(mailcow_api, 'delete_rl_hash', broken)
    assert c.post('/api/rate-limits/reset', json={'rl_hash': 'RLabc123'}).status_code == 500


# ---------------------------------------------------------------- blacklist

def test_blacklist(client, rows, monkeypatch):
    c, _ = client
    for path in ('/api/blacklist/monitored', '/api/blacklist/progress', '/api/blacklist/config',
                 '/api/blacklist/summary', '/api/blacklist/ignored'):
        assert c.get(path).status_code == 200
    zone = blacklist_service.BLACKLISTS[0]['zone']
    assert c.put(f'/api/blacklist/lists/{zone}/ignore', json={'ignored': False}).json()['zone'] == zone
    assert c.put('/api/blacklist/lists/nope.example/ignore', json={'ignored': True}).status_code == 404
    assert c.put(f'/api/blacklist/lists/{zone}/ignore', json={}).status_code == 422
    assert c.post('/api/blacklist/check?force=maybe').status_code == 422

    async def nothing(force=False):
        return None
    import app.scheduler as scheduler
    monkeypatch.setattr(scheduler, 'check_monitored_hosts_job', nothing)
    assert c.post('/api/blacklist/check').json()['status'] == 'started'

    async def checked(force=False, ip=None):
        return {'server_ip': ip, 'checked_at': '2026-10-26T00:00:00Z', 'total_blacklists': 1, 'listed_count': 0,
                'clean_count': 1, 'error_count': 0, 'timeout_count': 0, 'status': 'clean',
                'results': [{'name': 'A list', 'zone': zone, 'status': 'clean', 'listed': False, 'ignored': False}],
                'ignored_listed_count': 0}
    monkeypatch.setattr(blacklist, 'get_blacklist_check_results', checked)
    assert c.post('/api/blacklist/check?host=192.0.2.10').json()['status'] == 'clean'

    async def failed(force=False, ip=None):
        raise RuntimeError('no resolver')
    monkeypatch.setattr(blacklist, 'get_blacklist_check_results', failed)
    assert c.post('/api/blacklist/check?host=192.0.2.10').json()['status'] == 'error'


def test_ignored_blocklists_when_the_database_fails(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(blacklist, 'get_db_context', _broken_context)
    zone = blacklist_service.BLACKLISTS[0]['zone']
    assert c.get('/api/blacklist/ignored').status_code == 500
    assert c.put(f'/api/blacklist/lists/{zone}/ignore', json={'ignored': True}).status_code == 500
