"""The address a netfilter line is attributed to comes only from mailcow's own fields.

mailcow netfilter writes '<addr> matched rule id N (<original log line>)'. The
original line holds text the remote client chose: a non-SMTP command, a
sasl_username, a Dovecot user=<...>. An IPv4 written there must never become the
offender of a line that netfilter attributed to an IPv6 client, or the
protection rules would ban an address the client picked. Lines stored that way
by an earlier version must not ban either, and the upgrade closes the catches
and clears the addresses they left behind.
"""
import asyncio
import importlib.util
import logging
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from test_protection_enforce import FakeMailcow
from test_protection_rules import _context, _postgres_available, _rules

MARKER = f'nfattr-{uuid.uuid4().hex[:8]}'
CLIENT6 = '2001:db8:beef::7'
VICTIM = '198.51.100.88'
GENUINE = '198.51.100.40'
NET = '203.0.113.0/24'
NET_IPS = [f'203.0.113.{n}' for n in range(21, 26)]
TARGETS = [CLIENT6, VICTIM, GENUINE, NET] + NET_IPS


def sasl(lead, user):
    return (f'{lead} matched rule id 3 (warning: unknown[{lead}]: SASL LOGIN authentication failed: '
            f'UGFzc3dvcmQ6, sasl_username={user})')


def dovecot(lead, user):
    return (f'{lead} matched rule id 6 (imap-login: Disconnected (auth failed, 1 attempts in 2 secs): '
            f'user=<{user}>, method=PLAIN, rip={lead}, lip=2001:db8:1::25, TLS)')


def non_smtp(lead, command):
    return f'{lead} matched rule id 4 (warning: non-SMTP command from unknown[{lead}]: {command})'


# ---------- parsing ----------

@pytest.mark.parametrize('message', [
    sasl(CLIENT6, f'u0@{VICTIM}'),
    sasl(CLIENT6, VICTIM),
    dovecot(CLIENT6, f'a@{VICTIM}'),
    non_smtp(CLIENT6, f'GET /{VICTIM} HTTP/1.1'),
    non_smtp(CLIENT6, f'HELO [{VICTIM}]'),
    non_smtp(CLIENT6, f'Banning {VICTIM} until {VICTIM} is banned'),
])
def test_an_ipv6_line_is_attributed_to_the_ipv6_client_not_to_an_ipv4_in_its_text(message):
    from app.scheduler import parse_netfilter_message
    assert parse_netfilter_message(message, 'warn').get('ip') == CLIENT6


@pytest.mark.parametrize('message, ip', [
    (non_smtp('192.0.2.200', f'GET /{VICTIM} HTTP/1.1'), '192.0.2.200'),
    (sasl('192.0.2.200', f'u0@{VICTIM}'), '192.0.2.200'),
    ('2001:DB8:BEEF::7 matched rule id 3 (x)', CLIENT6),
    ('Banning 192.0.2.10/32 for 30 minutes', '192.0.2.10'),
    ('Banning 192.0.2.10', '192.0.2.10'),
    ('Banning 192.0.2.0/24 for 60 minutes', '192.0.2.0'),
    ('Banning 2001:db8:beef::/64 for 30 minutes', '2001:db8:beef::'),
    ('Unbanning 192.0.2.10/32', '192.0.2.10'),
    ('Unbanning 2001:db8:beef::/64', '2001:db8:beef::'),
    ('9 more attempts in the next 600 seconds until 192.0.2.10/32 is banned', '192.0.2.10'),
    (f'9 more attempts in the next 600 seconds until {CLIENT6}/128 is banned', CLIENT6),
    ('Added host/network 198.51.100.7/32 to denylist', '198.51.100.7'),
    ('Removed host/network 198.51.100.7/32 from denylist', '198.51.100.7'),
    ('Add host/network 198.51.100.7/32 to blacklist', '198.51.100.7'),
    ('Remove host/network 2001:db8::1/128 from blacklist', '2001:db8::1'),
    ('::ffff:192.0.2.9 matched rule id 3 (x)', '192.0.2.9'),
    ('Address 198.51.100.7/32 is allowlisted by rule 198.51.100.0/24', '198.51.100.7'),
    ('Address 2001:db8::1/128 is allowlisted by rule 2001:db8::/32', '2001:db8::1'),
    ('Address 198.51.100.7/32 is whitelisted by rule 198.51.100.7/32', '198.51.100.7'),
    ('198.51.100.7/32 is not banned, skipping unban and deleting from queue (if any)', '198.51.100.7'),
])
def test_mailcow_own_fields_still_give_the_address(message, ip):
    from app.scheduler import parse_netfilter_message
    assert parse_netfilter_message(message, 'warn').get('ip') == ip


@pytest.mark.parametrize('message', [
    f'Something about {VICTIM} happened',
    f'warning: unknown[{VICTIM}]: SASL LOGIN authentication failed',
    f'999.1.1.1 matched rule id 3 (warning: unknown[{VICTIM}]: x)',
    f'not-an-address matched rule id 3 (sasl_username=u@{VICTIM})',
    '',
])
def test_a_line_without_an_address_in_mailcow_fields_has_no_ip(message):
    from app.scheduler import parse_netfilter_message
    assert parse_netfilter_message(message, 'warn').get('ip') is None


# ---------- the rules ----------

def _cleanup():
    from app.database import get_db_context
    from app.models import NetfilterLog, PostfixLog, ProtectionHit, SystemSetting
    with get_db_context() as session:
        session.query(ProtectionHit).filter(ProtectionHit.ip.in_(TARGETS)).delete(synchronize_session=False)
        session.query(NetfilterLog).filter(NetfilterLog.priority == MARKER).delete(synchronize_session=False)
        session.query(PostfixLog).filter(PostfixLog.queue_id == MARKER[:20]).delete(synchronize_session=False)
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
    """Move the rules' reading past every line stored so far."""
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


def _stored_before_the_fix(session, ip, message, username=None, minutes_ago=5):
    """A line an earlier version stored with an address taken from the client's text."""
    from app.models import NetfilterLog
    row = NetfilterLog(time=datetime.utcnow() - timedelta(minutes=minutes_ago), priority=MARKER, ip=ip,
                       username=username, action='warning', message=message,
                       country_code='XX', country_name='Testland', asn_org='Test Network')
    session.add(row)
    session.commit()
    return row


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


def test_an_ipv6_client_cannot_get_the_ipv4_in_its_usernames_banned(db):
    _rules(db, unknown_accounts={'enabled': True, 'mode': 'enforce', 'threshold': 5, 'window_minutes': 60})
    _ingest([sasl(CLIENT6, f'u{n}@{VICTIM}') for n in range(5)])

    api = _evaluate_and_enforce(db)

    assert [(h.ip, h.rule, h.status) for h in _hits(db)] == [(CLIENT6, 'unknown_accounts', 'banned')]
    assert api.black() == [f'{CLIENT6}/128']


def test_an_ipv6_client_cannot_get_a_network_banned_through_dovecot_usernames(db):
    _rules(db, subnet={'enabled': True, 'mode': 'enforce', 'threshold': 5, 'window_hours': 24})
    _ingest([dovecot(CLIENT6, f'a@{ip}') for ip in NET_IPS])

    api = _evaluate_and_enforce(db)

    assert _hits(db) == []
    assert api.edits == []


def test_a_line_stored_before_the_fix_is_not_caught(db):
    _rules(db, trap={'enabled': True, 'names': ['admin'], 'mode': 'enforce'})
    _stored_before_the_fix(db, VICTIM, sasl(CLIENT6, f'admin@{VICTIM}'), username=f'admin@{VICTIM}')

    api = _evaluate_and_enforce(db)

    assert _hits(db) == []
    assert api.edits == []


def test_lines_stored_before_the_fix_do_not_count_toward_unknown_accounts(db):
    _rules(db, unknown_accounts={'enabled': True, 'mode': 'enforce', 'threshold': 5, 'window_minutes': 60})
    for n in range(4):
        _stored_before_the_fix(db, GENUINE, sasl(CLIENT6, f'u{n}@{GENUINE}'), username=f'u{n}@{GENUINE}')
    _read_from_now(db)
    _ingest([sasl(GENUINE, 'u4@example.com')])

    api = _evaluate_and_enforce(db)

    assert _hits(db) == []
    assert api.edits == []


def test_lines_stored_before_the_fix_do_not_count_toward_a_network(db):
    _rules(db, subnet={'enabled': True, 'mode': 'enforce', 'threshold': 5, 'window_hours': 24})
    for ip in NET_IPS[:4]:
        _stored_before_the_fix(db, ip, dovecot(CLIENT6, f'a@{ip}'))
    _read_from_now(db)
    _ingest([sasl(NET_IPS[4], 'root')])

    api = _evaluate_and_enforce(db)

    assert _hits(db) == []
    assert api.edits == []


def test_lines_stored_before_the_fix_are_not_failed_tries_for_the_breach_alert(db):
    from app.models import PostfixLog
    from app.services import protection_rules
    _rules(db, breach={'enabled': True, 'failures': 3, 'window_minutes': 60})
    protection_rules.evaluate(db, _context())  # starts reading the logins from now
    for n in range(3):
        _stored_before_the_fix(db, GENUINE, sasl(CLIENT6, f'u{n}@{GENUINE}'), username=f'u{n}@{GENUINE}')
    db.add(PostfixLog(time=datetime.utcnow(), queue_id=MARKER[:20], program='postfix/submission/smtpd',
                      message=f'4Fq2Lk7Xz: client=unknown[{GENUINE}], sasl_method=LOGIN, sasl_username=info@example.com'))
    db.commit()

    protection_rules.evaluate(db, _context())

    assert _hits(db) == []


def test_ipv4_lines_and_mailcow_bans_still_count(db):
    _rules(db, unknown_accounts={'enabled': True, 'mode': 'enforce', 'threshold': 5, 'window_minutes': 60},
           repeat_offender={'enabled': True, 'mode': 'watch', 'threshold': 2, 'window_days': 7})
    _ingest([sasl(GENUINE, f'u{n}@example.com') for n in range(5)]
            + [f'Banning {NET_IPS[0]}/32 for 30 minutes', f'Banning {NET_IPS[0]}/32 for 60 minutes'])

    api = _evaluate_and_enforce(db)

    assert sorted((h.ip, h.rule, h.status) for h in _hits(db)) == [
        (GENUINE, 'unknown_accounts', 'banned'), (NET_IPS[0], 'repeat_offender', 'watching')]
    assert api.black() == [f'{GENUINE}/32']


# ---------- the upgrade ----------

def _migration():
    path = next((Path(__file__).resolve().parents[1] / 'alembic' / 'versions').glob('*_netfilter_attribution_repair.py'))
    spec = importlib.util.spec_from_file_location('netfilter_attribution_repair', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _repair(module=None):
    from app.database import engine
    with engine.begin() as connection:
        (module or _migration()).repair(connection)


def _hit(session, ip, rule, status, rows, mode='watch'):
    from app.models import ProtectionHit
    now = datetime.utcnow()
    hit = ProtectionHit(ip=ip, rule=rule, mode=mode, status=status, reason='Tried 5 accounts that do not exist',
                        usernames=[], log_ids=[r.id for r in rows], attempts=len(rows), first_seen=now, last_seen=now)
    session.add(hit)
    session.commit()
    return hit.id


def test_the_upgrade_closes_open_catches_a_stored_line_contradicts(db, caplog):
    from app.models import NetfilterLog, ProtectionHit
    forged = [_stored_before_the_fix(db, VICTIM, sasl(CLIENT6, f'u{n}@{VICTIM}'), username=f'u{n}@{VICTIM}')
              for n in range(4)]
    genuine = _stored_before_the_fix(db, VICTIM, sasl(VICTIM, 'u4@example.com'), username='u4@example.com')
    net_forged = _stored_before_the_fix(db, NET_IPS[0], dovecot(CLIENT6, f'a@{NET_IPS[0]}'))
    net_genuine = [_stored_before_the_fix(db, ip, sasl(ip, 'root')) for ip in NET_IPS[1:]]
    # Inside the network, but stored under another address than the one netfilter named
    net_shifted = _stored_before_the_fix(db, NET_IPS[1], sasl(NET_IPS[2], 'root'))
    other = _stored_before_the_fix(db, GENUINE, sasl(GENUINE, 'admin'), username='admin')
    deleted = _stored_before_the_fix(db, VICTIM, sasl(VICTIM, 'admin'), username='admin')
    many = [_stored_before_the_fix(db, VICTIM, sasl(VICTIM, f'u{n}@example.com')) for n in range(199)]

    closed = {
        'pending': _hit(db, VICTIM, 'unknown_accounts', 'pending', forged, mode='enforce'),
        'mixed': _hit(db, VICTIM, 'trap', 'watching', forged[:1] + [genuine]),
        'mixed network': _hit(db, NET, 'subnet', 'watching', [net_forged] + net_genuine),
        'shifted in network': _hit(db, NET, 'subnet', 'watching', net_genuine + [net_shifted]),
        'another address': _hit(db, VICTIM, 'trap', 'watching', [other]),
        'deleted and forged': _hit(db, VICTIM, 'unknown_accounts', 'watching', [deleted, forged[1]]),
        'forged after 199': _hit(db, VICTIM, 'unknown_accounts', 'watching', many + [forged[2]]),
    }
    clean_net = _hit(db, NET, 'subnet', 'pending', net_genuine, mode='enforce')
    banned = _hit(db, VICTIM, 'country', 'banned', forged[:1], mode='enforce')
    db.query(NetfilterLog).filter(NetfilterLog.id == deleted.id).delete()
    db.commit()

    with caplog.at_level(logging.WARNING, logger='app.migrations'):
        _repair()

    db.expire_all()
    hits = {h.id: h for h in db.query(ProtectionHit).filter(ProtectionHit.ip.in_(TARGETS))}
    for name, hit_id in closed.items():
        assert (hits[hit_id].status, hits[hit_id].mode) == ('expired', 'watch'), name
        assert hits[hit_id].ended_at and 'another address' in hits[hit_id].reason, name
    assert (hits[clean_net].status, hits[banned].status) == ('pending', 'banned')
    assert f'{VICTIM} stays banned by the country rule' in caplog.text

    api = FakeMailcow()
    from app.services import protection_rules
    asyncio.run(protection_rules.enforce(api))
    assert api.black() == [NET]


def test_the_upgrade_keeps_catches_whose_lines_aged_out_or_confirm(db, caplog):
    from app.models import NetfilterLog, ProtectionHit
    confirming = _stored_before_the_fix(db, VICTIM, sasl(VICTIM, 'admin'), username='admin')
    allowlisted = _stored_before_the_fix(db, VICTIM, f'Address {VICTIM}/32 is allowlisted by rule 198.51.100.0/24')
    neutral = _stored_before_the_fix(db, VICTIM, 'Allowlist was changed, it has 3 entries')
    contradicting = _stored_before_the_fix(db, VICTIM, sasl(CLIENT6, f'x@{VICTIM}'))
    deleted = [_stored_before_the_fix(db, VICTIM, sasl(CLIENT6, f'u{n}@{VICTIM}')) for n in range(3)]
    many = [_stored_before_the_fix(db, GENUINE, sasl(GENUINE, f'u{n}@example.com')) for n in range(200)]

    kept = {
        'partly aged out': _hit(db, VICTIM, 'trap', 'watching', deleted[:1] + [confirming]),
        'all aged out': _hit(db, VICTIM, 'unknown_accounts', 'watching', deleted[1:2]),
        'empty': _hit(db, GENUINE, 'country', 'watching', []),
        'capped': _hit(db, GENUINE, 'unknown_accounts', 'watching', many),
        'allowlisted and neutral': _hit(db, VICTIM, 'country', 'watching', [allowlisted, neutral]),
        # A breach alert never bans, so even a contradicted one is left alone
        'alert': _hit(db, VICTIM, 'breach', 'alert', [contradicting]),
    }
    banned = _hit(db, VICTIM, 'repeat_offender', 'banned', deleted[2:], mode='enforce')
    # Its forged lines aged out before the upgrade, so nothing is left to contradict it
    pending = _hit(db, VICTIM, 'country', 'pending', deleted, mode='enforce')
    db.query(NetfilterLog).filter(NetfilterLog.id.in_([r.id for r in deleted])).delete(synchronize_session=False)
    db.commit()
    before = {h.id: (h.status, h.mode) for h in db.query(ProtectionHit).filter(ProtectionHit.ip.in_(TARGETS))}

    with caplog.at_level(logging.WARNING, logger='app.migrations'):
        _repair()

    db.expire_all()
    after = {h.id: (h.status, h.mode) for h in db.query(ProtectionHit).filter(ProtectionHit.ip.in_(TARGETS))}
    for name, hit_id in kept.items():
        assert after[hit_id] == before[hit_id], name
    assert after[banned] == ('banned', 'enforce') and after[pending] == ('pending', 'enforce')
    assert '[PROTECTION]' not in caplog.text
    assert db.query(NetfilterLog).filter(NetfilterLog.id == allowlisted.id).one().ip == VICTIM

    api = FakeMailcow()
    from app.services import protection_rules
    asyncio.run(protection_rules.enforce(api))
    assert api.black() == [f'{VICTIM}/32']


def test_the_upgrade_clears_addresses_taken_from_client_text(db):
    from app.models import NetfilterLog
    from app.services import security_addresses
    forged = _stored_before_the_fix(db, VICTIM, sasl(CLIENT6, f'u0@{VICTIM}'), username=f'u0@{VICTIM}')
    forged.rule_id = 3
    genuine = _stored_before_the_fix(db, GENUINE, sasl(GENUINE, 'root'), username='root')
    genuine.rule_id = 3
    ban = _stored_before_the_fix(db, GENUINE, f'Banning {GENUINE}/32 for 30 minutes')
    later = _stored_before_the_fix(db, VICTIM, dovecot(CLIENT6, f'a@{VICTIM}'))
    allowlisted = _stored_before_the_fix(db, GENUINE, f'Address {GENUINE}/32 is allowlisted by rule {GENUINE}/32')
    db.commit()
    before = {s['ip'] for s in security_addresses.attempt_sources(db, 24)}
    assert VICTIM in before

    migration = _migration()
    migration.BATCH = 1  # every line in its own batch
    _repair(migration)

    db.expire_all()
    rows = {r.id: r for r in db.query(NetfilterLog).filter(NetfilterLog.priority == MARKER)}
    assert rows[forged.id].ip is None and rows[forged.id].country_code is None and rows[forged.id].asn_org is None
    assert rows[forged.id].message == sasl(CLIENT6, f'u0@{VICTIM}')
    assert (rows[genuine.id].ip, rows[genuine.id].country_code) == (GENUINE, 'XX')
    assert rows[ban.id].ip == GENUINE
    assert rows[later.id].ip is None
    assert (rows[allowlisted.id].ip, rows[allowlisted.id].country_code) == (GENUINE, 'XX')
    after = {s['ip'] for s in security_addresses.attempt_sources(db, 24)}
    assert VICTIM not in after and GENUINE in after


def test_the_upgrade_reads_addresses_like_the_app():
    from app.services.netfilter_address import netfilter_address
    frozen = _migration().netfilter_address
    for message in [sasl(CLIENT6, f'u0@{VICTIM}'), non_smtp('192.0.2.200', f'GET /{VICTIM}'),
                    'Banning 2001:db8:beef::/64 for 30 minutes', 'Unbanning 192.0.2.10/32',
                    '9 more attempts in the next 600 seconds until 192.0.2.10/32 is banned',
                    'Added host/network 198.51.100.7/32 to denylist', f'Something about {VICTIM}',
                    '::ffff:192.0.2.9 matched rule id 3 (x)', '',
                    'Address 2001:db8::1/128 is allowlisted by rule 2001:db8::/32',
                    'Address 198.51.100.7/32 is whitelisted by rule 198.51.100.7/32',
                    '198.51.100.7/32 is not banned, skipping unban and deleting from queue (if any)']:
        assert frozen(message) == netfilter_address(message), message
