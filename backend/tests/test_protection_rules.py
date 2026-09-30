"""Protection rules, layer 1: the Trap and unknown-account rules in watch mode.

A rule reads the failed logins netfilter records and notes which addresses it
would ban and why. In watch mode nothing is written to Fail2ban; the hits are
what the admin reviews before switching a rule to enforce.
"""
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

MARKER = f'protect-{uuid.uuid4().hex[:8]}'
DOMAIN = 'protect-test.example'
TRAP_IP = '198.51.100.10'
SPRAY_IP = '198.51.100.20'
TYPO_IP = '198.51.100.30'
ALLOWED_IP = '203.0.113.5'
PRIVATE_IP = '10.1.2.3'
ALL_IPS = [TRAP_IP, SPRAY_IP, TYPO_IP, ALLOWED_IP, PRIVATE_IP]


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import AliasStatistics, MailboxStatistics, NetfilterLog, PostfixLog, ProtectionHit, SystemSetting
    with get_db_context() as db:
        db.query(ProtectionHit).filter(ProtectionHit.ip.in_(ALL_IPS)).delete(synchronize_session=False)
        db.query(NetfilterLog).filter(NetfilterLog.priority == MARKER).delete(synchronize_session=False)
        db.query(PostfixLog).filter(PostfixLog.queue_id == MARKER[:20]).delete(synchronize_session=False)
        db.query(MailboxStatistics).filter(MailboxStatistics.domain == DOMAIN).delete(synchronize_session=False)
        db.query(AliasStatistics).filter(AliasStatistics.domain == DOMAIN).delete(synchronize_session=False)
        db.query(SystemSetting).filter(SystemSetting.key.like('protection.%')).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def db():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import get_db_context, init_db
    from app.models import MailboxStatistics, NetfilterLog, SystemSetting
    from app.services import protection_rules
    init_db()
    _cleanup()
    with get_db_context() as session:
        session.add(MailboxStatistics(username=f'info@{DOMAIN}', domain=DOMAIN))
        # Start reading after whatever the database already holds
        last = session.query(NetfilterLog.id).order_by(NetfilterLog.id.desc()).first()
        session.add(SystemSetting(key=protection_rules.WATERMARK_KEY, value=str(last[0] if last else 0)))
        session.commit()
        yield session
    _cleanup()


def _fail(session, ip, username, minutes_ago=2):
    from app.models import NetfilterLog
    session.add(NetfilterLog(time=datetime.utcnow() - timedelta(minutes=minutes_ago), priority=MARKER, ip=ip,
                             username=username, action='warning',
                             message=f'{ip} matched rule id 3 (warning: unknown[{ip}]: SASL LOGIN authentication failed)'))
    session.commit()


def _rules(session, **overrides):
    from app.services import protection_rules
    rules = protection_rules.load_rules(session)
    for name, values in overrides.items():
        rules[name].update(values)
    return protection_rules.save_rules(session, rules)


def _context(allowlist=()):
    from app.services.protection_rules import ProtectionContext
    return ProtectionContext(allowlist=list(allowlist), protected_ips=set())


def _hits(session):
    from app.models import ProtectionHit
    return session.query(ProtectionHit).filter(ProtectionHit.ip.in_(ALL_IPS)).order_by(ProtectionHit.id).all()


# ---------- Trap ----------

def test_a_login_to_a_trap_name_is_noted_in_watch_mode(db):
    from app.services import protection_rules
    _rules(db, trap={'enabled': True, 'names': ['admin']})
    _fail(db, TRAP_IP, f'admin@{DOMAIN}')

    protection_rules.evaluate(db, _context())

    hits = _hits(db)
    assert [(h.ip, h.rule, h.status) for h in hits] == [(TRAP_IP, 'trap', 'watching')]
    assert f'admin@{DOMAIN}' in hits[0].usernames
    assert 'admin' in hits[0].reason


def test_a_trap_name_matches_the_bare_name_and_any_case(db):
    from app.services import protection_rules
    _rules(db, trap={'enabled': True, 'names': ['Postgres']})
    _fail(db, TRAP_IP, 'postgres')
    protection_rules.evaluate(db, _context())
    assert [h.rule for h in _hits(db)] == ['trap']


def test_an_existing_mailbox_cannot_be_a_trap(db):
    from app.services import protection_rules
    with pytest.raises(ValueError, match='info'):
        _rules(db, trap={'enabled': True, 'names': ['info']})
    with pytest.raises(ValueError, match='info'):
        _rules(db, trap={'enabled': True, 'names': [f'info@{DOMAIN}']})
    assert protection_rules.load_rules(db)['trap']['names'] == []


def test_a_disabled_rule_notes_nothing_but_the_reading_moves_on(db):
    from app.services import protection_rules
    _rules(db, trap={'enabled': False, 'names': ['admin']})
    _fail(db, TRAP_IP, 'admin')
    protection_rules.evaluate(db, _context())
    assert _hits(db) == []
    # Turning it on later does not reach back into lines already read
    _rules(db, trap={'enabled': True})
    protection_rules.evaluate(db, _context())
    assert _hits(db) == []


# ---------- never ban ----------

def test_allowlisted_and_private_addresses_are_never_noted(db):
    from app.services import protection_rules
    _rules(db, trap={'enabled': True, 'names': ['admin']})
    _fail(db, ALLOWED_IP, 'admin')
    _fail(db, PRIVATE_IP, 'admin')
    # The allowlist is matched as a network, not only as a single address
    protection_rules.evaluate(db, _context(allowlist=['203.0.113.0/24']))
    assert _hits(db) == []


# ---------- unknown accounts ----------

def test_several_unknown_accounts_from_one_address_are_noted(db):
    from app.services import protection_rules
    _rules(db, unknown_accounts={'enabled': True, 'threshold': 3, 'window_minutes': 60})
    for name in ('ftpuser', 'scanner', f'nobody@{DOMAIN}'):
        _fail(db, SPRAY_IP, name)
    protection_rules.evaluate(db, _context())
    hits = _hits(db)
    assert [(h.ip, h.rule, h.status) for h in hits] == [(SPRAY_IP, 'unknown_accounts', 'watching')]
    assert sorted(hits[0].usernames) == sorted(['ftpuser', 'scanner', f'nobody@{DOMAIN}'])


def test_existing_accounts_and_too_few_tries_are_not_noted(db):
    from app.services import protection_rules
    _rules(db, unknown_accounts={'enabled': True, 'threshold': 3, 'window_minutes': 60})
    # A real mailbox with a wrong password is not an unknown account
    _fail(db, SPRAY_IP, f'info@{DOMAIN}')
    _fail(db, SPRAY_IP, 'ftpuser')
    _fail(db, SPRAY_IP, 'scanner')
    protection_rules.evaluate(db, _context())
    assert _hits(db) == []


def test_an_address_that_logged_in_successfully_is_not_noted(db):
    """A real user who typed a wrong address a few times is not an attacker."""
    from app.models import PostfixLog
    from app.services import protection_rules
    db.add(PostfixLog(time=datetime.utcnow() - timedelta(hours=2), queue_id=MARKER[:20], program='postfix/submission/smtpd',
                      message=f'{MARKER[:10]}: client=unknown[{TYPO_IP}], sasl_method=PLAIN, sasl_username=info@{DOMAIN}'))
    db.commit()
    _rules(db, unknown_accounts={'enabled': True, 'threshold': 3, 'window_minutes': 60})
    for name in ('inof', 'ifno', f'inf@{DOMAIN}'):
        _fail(db, TYPO_IP, name)
    protection_rules.evaluate(db, _context())
    assert _hits(db) == []


# ---------- repeat reading ----------

def test_a_second_run_adds_to_the_open_hit_instead_of_a_new_one(db):
    from app.services import protection_rules
    _rules(db, trap={'enabled': True, 'names': ['admin', 'root']})
    _fail(db, TRAP_IP, 'admin')
    protection_rules.evaluate(db, _context())
    protection_rules.evaluate(db, _context())
    _fail(db, TRAP_IP, 'root')
    protection_rules.evaluate(db, _context())
    hits = _hits(db)
    assert len(hits) == 1
    assert sorted(hits[0].usernames) == ['admin', 'root']


# ---------- API ----------

def test_the_api_saves_rules_suggests_traps_and_lists_hits(db):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.services import protection_rules
    client = TestClient(app)

    # A real mailbox is refused with a message the admin can act on
    bad = client.put('/api/protection/rules', json={'rules': {'trap': {'enabled': True, 'names': ['info']}}})
    assert bad.status_code == 400 and 'info' in bad.json()['detail']

    saved = client.put('/api/protection/rules', json={'rules': {'trap': {'enabled': True, 'names': ['Admin', 'admin']}}})
    assert saved.status_code == 200
    assert saved.json()['rules']['trap']['names'] == ['admin']
    assert saved.json()['rules']['trap']['mode'] == 'watch'

    _fail(db, TRAP_IP, 'admin')
    _fail(db, SPRAY_IP, 'ghostuser')
    protection_rules.evaluate(db, _context())

    rules = client.get('/api/protection/rules').json()
    suggested = [s['name'] for s in rules['trap_suggestions']]
    assert 'ghostuser' in suggested and 'info' not in suggested

    listed = client.get('/api/protection/hits').json()
    mine = [h for h in listed['hits'] if h['ip'] in ALL_IPS]
    assert [(h['ip'], h['rule'], h['status']) for h in mine] == [(TRAP_IP, 'trap', 'watching')]

    dismissed = client.post(f"/api/protection/hits/{mine[0]['id']}/dismiss").json()
    assert dismissed['status'] == 'dismissed' and dismissed['ended_at']
    assert [h for h in client.get('/api/protection/hits').json()['hits'] if h['ip'] in ALL_IPS] == []


# ---------- alias domains ----------

def test_an_address_on_an_alias_domain_is_a_real_account(db):
    """mailcow maps user@alias-domain to user@target-domain: it exists, so it is no trap and not unknown."""
    from app.services import protection_rules
    from app.services.alias_domains import persist_alias_domain_map, set_cached_alias_domain_map
    alias_domain = f'alias-{DOMAIN}'
    persist_alias_domain_map(db, {alias_domain: DOMAIN})
    set_cached_alias_domain_map({alias_domain: DOMAIN})
    try:
        with pytest.raises(ValueError, match='existing'):
            _rules(db, trap={'enabled': True, 'names': [f'info@{alias_domain}']})
        _rules(db, unknown_accounts={'enabled': True, 'threshold': 3, 'window_minutes': 60})
        for name in (f'info@{alias_domain}', 'ftpuser', 'scanner'):
            _fail(db, SPRAY_IP, name)
        protection_rules.evaluate(db, _context())
        assert _hits(db) == []
    finally:
        persist_alias_domain_map(db, {})
        set_cached_alias_domain_map({})
