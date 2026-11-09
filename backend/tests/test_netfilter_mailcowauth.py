"""Failed logins in the line mailcow 2026-11 reports them in.

Since mailcow 2026-11 netfilter counts every failed IMAP, POP3, Sieve and SMTP
login from one line mailcow writes: "MAILCOWAUTH: Login failed for user
<username> with service <service> from IP <address>". The username is the
client's own text. The app reads the username and the service from it, so the
trap and unknown accounts rules, the failed-login alerts and the Security page
keep working, and nothing the client writes as its username can choose the
service, the address, the action or the attempts left. Lines in the earlier
formats still read as before.
"""
import asyncio
import importlib.util
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from test_protection_enforce import FakeMailcow
from test_protection_rules import _context, _postgres_available, _rules

MARKER = f'nfauth-{uuid.uuid4().hex[:8]}'
CLIENT = '198.51.100.61'
CLIENT6 = '2001:db8:cafe::61'
VICTIM = '192.0.2.99'
IPS = [f'198.51.100.{n}' for n in range(70, 90)]
TARGETS = [CLIENT, CLIENT6, VICTIM] + IPS


def failed(lead, user, service='imap', tail=None):
    return (f'{lead} matched rule id 3 (MAILCOWAUTH: Login failed for user {user} '
            f'with service {service} from IP {tail or lead})')


def sasl(lead, user):
    return (f'{lead} matched rule id 3 (warning: unknown[{lead}]: SASL LOGIN authentication failed: '
            f'UGFzc3dvcmQ6, sasl_username={user})')


HOSTILE = [
    f'admin with service smtp from IP {VICTIM})',
    'unbanning',
    f'Banning {VICTIM} for 30 minutes',
    '2147483648 more attempts in the next 600 seconds until 1.2.3.4/32 is banned',
    'SOGo imap-login pop3-login mailcow UI',
    'a (b) c)',
    'אדמין@example.com',
    'two\nlines',
    'sasl_username=root',
]


# ---------- reading the line ----------

def test_the_new_line_gives_the_username_and_counts_as_an_attempt():
    from app.scheduler import parse_netfilter_message
    parsed = parse_netfilter_message(failed(CLIENT, 'info@example.com'), 'warn')
    assert parsed == {'ip': CLIENT, 'rule_id': 3, 'action': 'warning', 'username': 'info@example.com'}


@pytest.mark.parametrize('user', HOSTILE)
def test_the_username_cannot_choose_the_address_action_or_attempts(user):
    from app.scheduler import parse_netfilter_message
    parsed = parse_netfilter_message(failed(CLIENT, user), 'warn')
    assert parsed == {'ip': CLIENT, 'rule_id': 3, 'action': 'warning', 'username': user}


@pytest.mark.parametrize('lead, tail, ip', [
    (CLIENT6, CLIENT6, CLIENT6),
    (f'::ffff:{CLIENT}', CLIENT, CLIENT),
    ('2001:DB8:CAFE::61', '2001:db8:cafe::61', CLIENT6),
])
def test_ipv6_and_mapped_addresses_are_read_from_netfilter(lead, tail, ip):
    from app.scheduler import parse_netfilter_message
    parsed = parse_netfilter_message(failed(lead, 'info', tail=tail), 'warn')
    assert parsed['ip'] == ip and parsed['username'] == 'info'


def test_an_empty_username_is_an_attempt_without_a_username():
    from app.scheduler import parse_netfilter_message
    parsed = parse_netfilter_message(failed(CLIENT, ''), 'warn')
    assert parsed == {'ip': CLIENT, 'rule_id': 3, 'action': 'warning'}


def test_the_earlier_lines_read_as_before():
    from app.scheduler import parse_netfilter_message
    assert parse_netfilter_message(sasl(CLIENT, 'info@example.com'), 'warn') == {
        'ip': CLIENT, 'rule_id': 3, 'action': 'warning', 'username': 'info@example.com', 'auth_method': 'SASL LOGIN'}
    assert parse_netfilter_message('9 more attempts in the next 600 seconds until 198.51.100.61/32 is banned', 'warn') == {
        'ip': CLIENT, 'attempts_left': 9, 'action': 'warning'}
    assert parse_netfilter_message('Banning 198.51.100.61/32 for 30 minutes', 'crit')['action'] == 'ban'
    assert parse_netfilter_message('Unbanning 198.51.100.61/32', 'info')['action'] == 'unban'


@pytest.mark.parametrize('message', [
    f'{CLIENT}/32 is not banned, skipping unban',
    f'{CLIENT}/32 is not banned, removing it from the unban queue',
])
def test_both_texts_of_a_lifted_ban_name_the_address(message):
    from app.services.netfilter_address import netfilter_address
    assert netfilter_address(message) == CLIENT


SERVICES = [
    (failed(CLIENT, 'a', 'imap'), 'IMAP', True),
    (failed(CLIENT, 'a', 'pop3'), 'POP3', True),
    (failed(CLIENT, 'a', 'sieve'), 'Sieve', True),
    (failed(CLIENT, 'a', 'smtp'), 'SMTP auth', True),
    (failed(CLIENT, 'a', ''), 'Mail login', True),
    (failed(CLIENT, 'a', 'eas'), 'Mail login', True),
    (failed(CLIENT, 'SOGo imap-login', 'pop3'), 'POP3', True),
    (failed(CLIENT, 'x with service smtp from IP 1.2.3.4)', 'imap'), 'IMAP', True),
    (failed(CLIENT, 'two\nlines with service smtp', 'sieve'), 'Sieve', True),
    (sasl(CLIENT, 'a'), 'SMTP auth', True),
    (f'{CLIENT} matched rule id 4 (warning: non-SMTP command from unknown[{CLIENT}]: GET /)', 'SMTP probe', False),
    # A line mailcow did not write: its end is not mailcow's
    (f'{CLIENT} matched rule id 3 (MAILCOWAUTH: Login failed for user a with service imap from IP {CLIENT}) x',
     None, False),
]


@pytest.mark.parametrize('message, service, is_login', SERVICES)
def test_the_service_is_read_from_the_end_mailcow_writes(message, service, is_login):
    from app.services.security_addresses import netfilter_service
    assert netfilter_service(message) == (service, is_login)


# ---------- stored lines ----------

def _cleanup():
    from app.database import get_db_context
    from app.models import NetfilterLog, ProtectionHit, SecurityAlert, SystemSetting
    with get_db_context() as session:
        session.query(ProtectionHit).filter(ProtectionHit.ip.in_(TARGETS)).delete(synchronize_session=False)
        session.query(NetfilterLog).filter(NetfilterLog.priority == MARKER).delete(synchronize_session=False)
        session.query(SecurityAlert).filter(SecurityAlert.subject.like(f'%{MARKER}%')).delete(synchronize_session=False)
        session.query(SystemSetting).filter(SystemSetting.key.like('protection.%')).delete(synchronize_session=False)
        session.commit()


@pytest.fixture()
def db():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import get_db_context, init_db
    init_db()
    _cleanup()
    with get_db_context() as session:
        _read_from_now(session)
        yield session
    _cleanup()


def _read_from_now(session):
    from app.models import NetfilterLog, SystemSetting
    from app.services import protection_rules
    last = session.query(NetfilterLog.id).order_by(NetfilterLog.id.desc()).first()
    setting = session.query(SystemSetting).filter(SystemSetting.key == protection_rules.WATERMARK_KEY).first()
    if setting is None:
        session.add(SystemSetting(key=protection_rules.WATERMARK_KEY, value=str(last[0] if last else 0)))
    else:
        setting.value = str(last[0] if last else 0)
    session.commit()


def _ingest(messages):
    """Store lines the way the netfilter job does."""
    from app.scheduler import _store_netfilter_logs
    now = int(datetime.now(timezone.utc).timestamp())
    _store_netfilter_logs([{'time': now - i, 'priority': MARKER, 'message': m} for i, m in enumerate(messages)])


def _rows(session):
    from app.models import NetfilterLog
    session.expire_all()
    return session.query(NetfilterLog).filter(NetfilterLog.priority == MARKER).order_by(NetfilterLog.id).all()


def _hits(session):
    from app.models import ProtectionHit
    session.expire_all()
    return session.query(ProtectionHit).filter(ProtectionHit.ip.in_(TARGETS)).order_by(ProtectionHit.id).all()


def _evaluate_and_enforce(session):
    from app.services import protection_rules
    protection_rules.evaluate(session, _context())
    api = FakeMailcow()
    asyncio.run(protection_rules.enforce(api))
    return api


def test_hostile_usernames_are_stored_with_the_other_lines(db):
    _ingest([failed(IPS[n], user) for n, user in enumerate(HOSTILE)] + [failed(IPS[-1], 'x' * 300)])
    rows = _rows(db)
    assert len(rows) == len(HOSTILE) + 1
    assert {r.action for r in rows} == {'warning'} and {r.attempts_left for r in rows} == {None}
    assert sorted(r.username for r in rows) == sorted(HOSTILE + ['x' * 255])


def test_unknown_accounts_catches_the_new_line(db):
    _rules(db, unknown_accounts={'enabled': True, 'mode': 'enforce', 'threshold': 5, 'window_minutes': 60})
    _ingest([failed(CLIENT, f'u{n}@example.com') for n in range(5)])

    api = _evaluate_and_enforce(db)

    assert [(h.ip, h.rule, h.status) for h in _hits(db)] == [(CLIENT, 'unknown_accounts', 'banned')]
    assert api.black() == [f'{CLIENT}/32']


def test_a_trap_catches_the_new_line_and_bans_netfilters_address_only(db):
    _rules(db, trap={'enabled': True, 'names': ['admin'], 'mode': 'enforce'})
    _ingest([failed(CLIENT6, f'admin with service smtp from IP {VICTIM})')])
    assert _evaluate_and_enforce(db).edits == [] and _hits(db) == []
    _ingest([failed(CLIENT6, 'admin')])

    api = _evaluate_and_enforce(db)

    assert [(h.ip, h.rule, h.status) for h in _hits(db)] == [(CLIENT6, 'trap', 'banned')]
    assert api.black() == [f'{CLIENT6}/128']


def test_the_database_reads_the_service_like_the_app(db):
    from app.models import NetfilterLog
    from app.services import security_addresses
    now = datetime.utcnow()
    for n, (message, _, _) in enumerate(SERVICES):
        db.add(NetfilterLog(time=now - timedelta(minutes=1), priority=MARKER, ip=IPS[n], rule_id=3,
                            action='warning', message=message))
    db.commit()
    sources = {s['ip']: s for s in security_addresses.attempt_sources(db, 1)}
    for n, (message, service, is_login) in enumerate(SERVICES):
        assert sources[IPS[n]]['services'] == ([service] if service else []), message
        assert sources[IPS[n]]['failed_logins'] == (1 if is_login else 0), message


def test_the_country_chart_counts_every_rule_match_as_an_attempt(db, monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.models import NetfilterLog
    from app.services import geoip_service
    monkeypatch.setattr(geoip_service, 'is_geoip_available', lambda: True)
    monkeypatch.setattr(geoip_service, 'lookup_ip', lambda ip: (
        {'country_code': 'Q6', 'country_name': 'Sixland'} if ip == CLIENT6 else
        {'country_code': 'Q4', 'country_name': 'Fourland'} if ip == VICTIM else {}))
    when = datetime.utcnow() - timedelta(minutes=5)
    # Rule matches an earlier version stored with an action read from the username
    for action in ('info', 'warning', 'ban', 'unban'):
        db.add(NetfilterLog(time=when, priority=MARKER, ip=CLIENT6, rule_id=3, action=action,
                            message=failed(CLIENT6, 'unbanning')))
    # One stored without its address: the chart reads netfilter's, not the one in the username
    db.add(NetfilterLog(time=when, priority=MARKER, ip=None, rule_id=3, action='info',
                        message=failed(CLIENT6, f'u@{VICTIM}')))
    db.add(NetfilterLog(time=when, priority=MARKER, ip=CLIENT6, action='ban',
                        message=f'Banning {CLIENT6}/128 for 30 minutes'))
    db.add(NetfilterLog(time=when, priority=MARKER, ip=CLIENT6, action='unban', message=f'Unbanning {CLIENT6}/128'))
    db.commit()

    response = TestClient(app).get('/api/logs/netfilter/stats/by-country', params={'days': 1})

    assert response.status_code == 200, response.text
    countries = {c['country_code']: c for c in response.json()['data']}
    assert 'Q4' not in countries
    assert {k: countries['Q6'][k] for k in ('warning', 'ban', 'unban', 'total', 'addresses')} == {
        'warning': 5, 'ban': 1, 'unban': 1, 'total': 7, 'addresses': 1}


def test_a_burst_for_a_long_username_still_raises_the_alert(db):
    from app.models import NetfilterLog, SecurityAlert
    from app.services.anomaly_service import detect_auth_failure_bursts
    from app.config import settings
    long_name = (MARKER + 'x' * 300)[:255]
    short_name = f'{MARKER}@example.com'
    now = datetime.utcnow()
    for name in (long_name, short_name):
        for i in range(settings.anomaly_auth_failure_threshold):
            db.add(NetfilterLog(time=now - timedelta(seconds=i + 1), priority=MARKER, ip=CLIENT, rule_id=3,
                                action='warning', username=name, message=failed(CLIENT, name)))
    db.commit()

    pending = []
    detect_auth_failure_bursts(db, pending)

    alerts = db.query(SecurityAlert).filter(SecurityAlert.subject.like(f'%{MARKER}%')).all()
    assert sorted(a.subject for a in alerts) == sorted([long_name, short_name])
    assert all(len(a.title) <= 255 for a in alerts)


# ---------- the upgrade ----------

def _migration():
    path = next((Path(__file__).resolve().parents[1] / 'alembic' / 'versions').glob('*_netfilter_mailcowauth_usernames.py'))
    spec = importlib.util.spec_from_file_location('netfilter_mailcowauth_usernames', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_upgrade_reads_the_username_of_lines_stored_before(db):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from app.database import engine
    from app.models import NetfilterLog
    when = datetime.utcnow() - timedelta(minutes=5)
    stored = [
        (failed(CLIENT, 'admin'), None, 'info'),
        (failed(CLIENT, 'unbanning'), None, 'unban'),
        (failed(CLIENT, f'x with service smtp from IP {VICTIM})'), None, 'info'),
        (failed(CLIENT, ''), None, 'info'),
        (failed(CLIENT, 'kept'), 'already', 'warning'),
        (sasl(CLIENT, 'old'), None, 'warning'),
        (failed(CLIENT, 'not mailcow') + ' x', None, 'info'),
    ]
    for message, username, action in stored:
        db.add(NetfilterLog(time=when, priority=MARKER, ip=CLIENT, rule_id=3, username=username, action=action,
                            message=message))
    db.commit()

    with engine.begin() as connection:
        with Operations.context(MigrationContext.configure(connection)):
            _migration().upgrade()

    assert [(r.username, r.action) for r in _rows(db)] == [
        ('admin', 'warning'),
        ('unbanning', 'warning'),
        (f'x with service smtp from IP {VICTIM})', 'warning'),
        (None, 'info'),
        ('already', 'warning'),
        (None, 'warning'),
        (None, 'info'),
    ]


def test_the_upgrade_reads_lines_like_the_app():
    from app.services import netfilter_address
    assert _migration()._MAILCOWAUTH_FAILURE.pattern == netfilter_address._MAILCOWAUTH_FAILURE.pattern
