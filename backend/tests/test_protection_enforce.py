"""Protection rules that ban, and the rules added after Trap and unknown accounts.

In ban mode a hit waits as pending until enforce() writes it to the Fail2ban
blacklist. The app lifts only the entries it added. Every write here goes to a
fake mailcow, never to a real one.
"""
import asyncio
from datetime import datetime, timedelta

import pytest

from test_protection_rules import (  # noqa: F401  (db is a fixture)
    ALL_IPS, DOMAIN, MARKER, SPRAY_IP, SUBNET, SUBNET_IPS, TRAP_IP, TYPO_IP,
    _context, _fail, _hits, _rules, db,
)


class FakeMailcow:
    """Stands in for the mailcow Fail2ban API: keeps the lists and records every edit."""
    has_rw_key = True

    def __init__(self, blacklist='', whitelist='', fail=None):
        self.settings = {'ban_time': 3600, 'ban_time_increment': 1, 'max_attempts': 7, 'max_ban_time': 604800,
                         'netban_ipv4': 32, 'netban_ipv6': 128, 'retry_window': 900,
                         'blacklist': blacklist, 'whitelist': whitelist}
        self.edits = []
        self.fail = fail

    async def get_fail2ban(self):
        return dict(self.settings)

    async def edit_fail2ban(self, attrs):
        self.edits.append(attrs)
        if self.fail:
            return [{'type': 'danger', 'msg': self.fail}]
        self.settings.update(blacklist=attrs['blacklist'], whitelist=attrs['whitelist'])
        return [{'type': 'success', 'msg': 'saved'}]

    def black(self):
        return [e for e in self.settings['blacklist'].split(',') if e]


def _enforce(api, now=None):
    from app.services import protection_rules
    return asyncio.run(protection_rules.enforce(api, now=now))


def _fresh(session):
    session.expire_all()
    return _hits(session)


def _trap_hit(session, **rule):
    from app.services import protection_rules
    _rules(session, trap={'enabled': True, 'names': ['admin'], 'mode': 'enforce', **rule})
    _fail(session, TRAP_IP, 'admin')
    protection_rules.evaluate(session, _context())


# ---------- writing bans ----------

def test_a_banning_rule_writes_the_address_and_keeps_every_other_setting(db):
    _trap_hit(db, ban_hours=720)
    assert [h.status for h in _hits(db)] == ['pending']

    api = FakeMailcow(blacklist='203.0.113.99/32', whitelist='203.0.113.0/24')
    result = _enforce(api)

    assert api.black() == ['203.0.113.99/32', f'{TRAP_IP}/32']
    edit = api.edits[0]
    assert edit['whitelist'] == '203.0.113.0/24' and edit['max_attempts'] == '7' and edit['retry_window'] == '900'
    hit = _fresh(db)[0]
    assert hit.status == 'banned' and hit.owned and hit.banned_at
    assert hit.expires_at - hit.banned_at == timedelta(hours=720)
    assert [b[0] for b in result['banned']] == [TRAP_IP]


def test_saving_a_banning_rule_needs_the_rw_key(db):
    from app.services import protection_rules
    rules = protection_rules.load_rules(db)
    rules['trap'].update(enabled=True, mode='enforce')
    with pytest.raises(ValueError, match='Read-Write'):
        protection_rules.save_rules(db, rules, can_ban=False)


def test_an_address_already_on_the_blacklist_is_not_owned_and_never_lifted(db):
    _trap_hit(db, ban_hours=1)
    api = FakeMailcow(blacklist=f'{TRAP_IP}/32')
    _enforce(api)
    assert api.edits == []
    hit = _fresh(db)[0]
    assert hit.status == 'banned' and not hit.owned

    _enforce(api, now=datetime.utcnow() + timedelta(hours=2))
    assert _fresh(db)[0].status == 'expired'
    assert api.black() == [f'{TRAP_IP}/32']


def test_an_ended_ban_lifts_only_the_entry_the_app_added(db):
    _trap_hit(db, ban_hours=1)
    api = FakeMailcow(blacklist='203.0.113.99')
    _enforce(api)
    assert api.black() == ['203.0.113.99', f'{TRAP_IP}/32']

    result = _enforce(api, now=datetime.utcnow() + timedelta(hours=2))
    assert api.black() == ['203.0.113.99']
    assert _fresh(db)[0].status == 'expired'
    assert [l[0] for l in result['lifted']] == [TRAP_IP]


def test_an_entry_removed_by_hand_in_mailcow_ends_quietly(db):
    _trap_hit(db, ban_hours=1)
    api = FakeMailcow()
    _enforce(api)
    api.settings['blacklist'] = ''
    edits = len(api.edits)
    _enforce(api, now=datetime.utcnow() + timedelta(hours=2))
    assert len(api.edits) == edits
    assert _fresh(db)[0].status == 'expired'


def test_an_address_put_on_the_allowlist_before_the_write_is_not_banned(db):
    _trap_hit(db)
    api = FakeMailcow(whitelist='198.51.100.0/24')
    _enforce(api)
    assert api.edits == []
    hit = _fresh(db)[0]
    assert hit.status == 'dismissed' and 'allowlist' in hit.error


def test_a_refused_write_keeps_the_ban_pending_with_the_reason(db):
    _trap_hit(db)
    result = _enforce(FakeMailcow(fail='access denied'))
    hit = _fresh(db)[0]
    assert hit.status == 'pending' and 'access denied' in hit.error
    assert [f[0] for f in result['failed']] == [TRAP_IP]


def test_switching_a_rule_back_to_watching_bans_nothing_pending(db):
    _trap_hit(db)
    _rules(db, trap={'mode': 'watch'})
    api = FakeMailcow()
    _enforce(api)
    assert api.edits == []
    assert _fresh(db)[0].status == 'watching'


def test_a_permanent_ban_has_no_end(db):
    _trap_hit(db, ban_hours=0)
    api = FakeMailcow()
    _enforce(api)
    _enforce(api, now=datetime.utcnow() + timedelta(days=3650))
    hit = _fresh(db)[0]
    assert hit.status == 'banned' and hit.expires_at is None
    assert api.black() == [f'{TRAP_IP}/32']


def test_when_two_rules_ban_one_address_the_entry_stays_until_both_end(db):
    from app.services import protection_rules
    _rules(db, trap={'enabled': True, 'names': ['admin'], 'mode': 'enforce', 'ban_hours': 1},
           unknown_accounts={'enabled': True, 'threshold': 3, 'mode': 'enforce', 'ban_hours': 48})
    for name in ('admin', 'ftpuser', 'scanner'):
        _fail(db, TRAP_IP, name)
    protection_rules.evaluate(db, _context())
    api = FakeMailcow()
    _enforce(api)
    assert api.black() == [f'{TRAP_IP}/32']

    _enforce(api, now=datetime.utcnow() + timedelta(hours=2))
    assert api.black() == [f'{TRAP_IP}/32']
    _enforce(api, now=datetime.utcnow() + timedelta(hours=49))
    assert api.black() == []
    assert sorted(h.status for h in _fresh(db)) == ['expired', 'expired']


def test_undo_lifts_the_ban_and_the_rule_leaves_the_address_alone_for_a_week(db):
    from app.services import protection_rules
    _trap_hit(db)
    api = FakeMailcow(blacklist='203.0.113.99')
    _enforce(api)
    hit = _fresh(db)[0]

    done = asyncio.run(protection_rules.undo(api, hit.id))
    assert done.status == 'undone'
    assert api.black() == ['203.0.113.99']

    _fail(db, TRAP_IP, 'admin')
    protection_rules.evaluate(db, _context())
    assert [h.status for h in _fresh(db)] == ['undone']


# ---------- repeat offender, subnet, country ----------

def _ban_line(session, ip, days_ago):
    from app.models import NetfilterLog
    session.add(NetfilterLog(time=datetime.utcnow() - timedelta(days=days_ago), priority=MARKER, ip=ip,
                             action='ban', message=f'Banning {ip}/32 for 60 minutes'))
    session.commit()


def test_an_address_fail2ban_banned_again_and_again_is_caught(db):
    from app.services import protection_rules
    _rules(db, repeat_offender={'enabled': True, 'threshold': 3, 'window_days': 30})
    _ban_line(db, SPRAY_IP, 40)  # outside the window
    _ban_line(db, SPRAY_IP, 10)
    _ban_line(db, SPRAY_IP, 5)
    protection_rules.evaluate(db, _context())
    assert _hits(db) == []
    _ban_line(db, SPRAY_IP, 0)
    protection_rules.evaluate(db, _context())
    hits = _hits(db)
    assert [(h.ip, h.rule) for h in hits] == [(SPRAY_IP, 'repeat_offender')]
    assert '3 times' in hits[0].reason


def test_many_addresses_of_one_network_catch_the_network(db):
    from app.services import protection_rules
    _rules(db, subnet={'enabled': True, 'threshold': 5, 'window_hours': 24})
    for ip in SUBNET_IPS[:4]:
        _fail(db, ip, 'root')
    protection_rules.evaluate(db, _context())
    assert _hits(db) == []
    _fail(db, SUBNET_IPS[4], 'root')
    protection_rules.evaluate(db, _context())
    assert [(h.ip, h.rule) for h in _hits(db)] == [(SUBNET, 'subnet')]


def test_a_network_holding_an_allowlisted_address_is_never_caught(db):
    from app.services import protection_rules
    _rules(db, subnet={'enabled': True, 'threshold': 5, 'window_hours': 24})
    for ip in SUBNET_IPS[:5]:
        _fail(db, ip, 'root')
    protection_rules.evaluate(db, _context(allowlist=[SUBNET_IPS[5]]))
    assert _hits(db) == []


def test_a_banned_network_is_written_as_a_network(db):
    from app.services import protection_rules
    _rules(db, subnet={'enabled': True, 'threshold': 5, 'mode': 'enforce'})
    for ip in SUBNET_IPS[:5]:
        _fail(db, ip, 'root')
    protection_rules.evaluate(db, _context())
    api = FakeMailcow()
    _enforce(api)
    assert api.black() == [SUBNET]


def _country_fail(session, ip, code, name):
    from app.models import NetfilterLog
    session.add(NetfilterLog(time=datetime.utcnow(), priority=MARKER, ip=ip, username='root', action='warning',
                             country_code=code, country_name=name, message='failed'))
    session.commit()


def test_the_country_rule_needs_geoip_and_catches_the_chosen_countries(db):
    from app.services import protection_rules
    from app.services.protection_rules import ProtectionContext
    _rules(db, country={'enabled': True, 'countries': ['xx']})
    _country_fail(db, SPRAY_IP, 'XX', 'Testland')
    protection_rules.evaluate(db, ProtectionContext(geoip=False))
    assert _hits(db) == []

    _country_fail(db, SPRAY_IP, 'XX', 'Testland')
    _country_fail(db, TRAP_IP, 'YY', 'Otherland')
    protection_rules.evaluate(db, ProtectionContext(geoip=True))
    assert [(h.ip, h.rule, h.country_code) for h in _hits(db)] == [(SPRAY_IP, 'country', 'XX')]
    with pytest.raises(ValueError, match='country code'):
        _rules(db, country={'countries': ['Testland']})


# ---------- breach alert ----------

def _login(session, ip, username, minutes_ago=0):
    from app.models import PostfixLog
    session.add(PostfixLog(time=datetime.utcnow() - timedelta(minutes=minutes_ago), queue_id=MARKER[:20],
                           program='postfix/submission/smtpd',
                           message=f'{MARKER[:10]}: client=unknown[{ip}], sasl_method=LOGIN, sasl_username={username}'))
    session.commit()


def test_a_login_after_failed_tries_raises_an_alert_and_never_bans(db):
    from app.services import protection_rules
    _rules(db, breach={'enabled': True, 'failures': 3, 'window_minutes': 60})
    protection_rules.evaluate(db, _context())  # starts reading the logins from now
    for _ in range(3):
        _fail(db, SPRAY_IP, f'info@{DOMAIN}', minutes_ago=10)
    _login(db, SPRAY_IP, f'info@{DOMAIN}')
    _login(db, TYPO_IP, f'info@{DOMAIN}')  # no failures from here: nothing to say
    protection_rules.evaluate(db, _context())
    hits = _hits(db)
    assert [(h.ip, h.rule, h.status) for h in hits] == [(SPRAY_IP, 'breach', 'alert')]
    assert f'info@{DOMAIN}' in hits[0].reason

    api = FakeMailcow()
    _enforce(api)
    assert api.edits == []


def test_logins_from_before_the_alert_was_on_are_not_read(db):
    from app.services import protection_rules
    protection_rules.evaluate(db, _context())
    for _ in range(3):
        _fail(db, SPRAY_IP, f'info@{DOMAIN}', minutes_ago=10)
    _login(db, SPRAY_IP, f'info@{DOMAIN}')
    protection_rules.evaluate(db, _context())
    _rules(db, breach={'enabled': True, 'failures': 3})
    protection_rules.evaluate(db, _context())
    assert _hits(db) == []


# ---------- API: ban now and undo ----------

def test_the_api_bans_a_watched_hit_now_and_undoes_it(db, monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.routers import protection as router
    from app.services import protection_rules
    api = FakeMailcow(blacklist='203.0.113.99')
    monkeypatch.setattr(router, 'mailcow_api', api)
    client = TestClient(app)

    _rules(db, trap={'enabled': True, 'names': ['admin']})
    _fail(db, TRAP_IP, 'admin')
    protection_rules.evaluate(db, _context())
    hit_id = _hits(db)[0].id

    assert client.get('/api/protection/rules').json()['capabilities']['can_ban'] is True

    banned = client.post(f'/api/protection/hits/{hit_id}/ban')
    assert banned.status_code == 200, banned.text
    assert banned.json()['status'] == 'banned' and banned.json()['owned'] is True
    assert api.black() == ['203.0.113.99', f'{TRAP_IP}/32']
    active = [h for h in client.get('/api/protection/hits?status=active').json()['hits'] if h['ip'] in ALL_IPS]
    assert [h['status'] for h in active] == ['banned']

    undone = client.post(f'/api/protection/hits/{hit_id}/undo')
    assert undone.status_code == 200 and undone.json()['status'] == 'undone'
    assert api.black() == ['203.0.113.99']
    history = [h for h in client.get('/api/protection/hits?status=history').json()['hits'] if h['ip'] in ALL_IPS]
    assert [h['status'] for h in history] == ['undone']
    assert client.post(f'/api/protection/hits/{hit_id}/undo').status_code == 409


def test_the_api_refuses_to_ban_without_the_rw_key(db, monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.routers import protection as router
    from app.services import protection_rules
    api = FakeMailcow()
    api.has_rw_key = False
    monkeypatch.setattr(router, 'mailcow_api', api)
    client = TestClient(app)
    _rules(db, trap={'enabled': True, 'names': ['admin']})
    _fail(db, TRAP_IP, 'admin')
    protection_rules.evaluate(db, _context())
    hit_id = _hits(db)[0].id
    assert client.post(f'/api/protection/hits/{hit_id}/ban').status_code == 400
    saved = client.put('/api/protection/rules', json={'rules': {'trap': {'mode': 'enforce'}}})
    assert saved.status_code == 400 and 'Read-Write' in saved.json()['detail']
    assert api.edits == []


# ---------- review follow-ups ----------

def test_a_watched_address_that_attacks_again_after_the_switch_to_ban_is_banned(db):
    from app.services import protection_rules
    _rules(db, trap={'enabled': True, 'names': ['admin']})
    _fail(db, TRAP_IP, 'admin')
    protection_rules.evaluate(db, _context())
    assert [h.status for h in _hits(db)] == ['watching']

    _rules(db, trap={'mode': 'enforce', 'ban_hours': 24})
    protection_rules.evaluate(db, _context())
    assert [h.status for h in _fresh(db)] == ['watching']  # switching alone bans nothing

    _fail(db, TRAP_IP, 'admin')
    protection_rules.evaluate(db, _context())
    hit = _fresh(db)[0]
    assert (hit.status, hit.ban_hours) == ('pending', 24)


def test_blacklist_entries_do_not_count_as_fail2ban_bans(db):
    from app.models import NetfilterLog
    from app.services import protection_rules
    _rules(db, repeat_offender={'enabled': True, 'threshold': 3, 'window_days': 30})
    for _ in range(4):
        db.add(NetfilterLog(time=datetime.utcnow(), priority=MARKER, ip=SPRAY_IP, action='ban',
                            message=f'Added host/network {SPRAY_IP}/32 to denylist'))
    db.commit()
    protection_rules.evaluate(db, _context())
    assert _hits(db) == []


def test_the_notification_names_the_bans_and_the_alerts(monkeypatch):
    from app import scheduler
    from app.services import notification_service
    sent = []
    monkeypatch.setattr(notification_service, 'notify', lambda subject, text, **kw: sent.append((subject, text, kw)))
    scheduler._notify_protection(
        banned=[(TRAP_IP, 'trap', 'Tried the trap account admin', True)], failed=[],
        alerts=[(SPRAY_IP, 'breach', f'info@{DOMAIN} logged in after 3 failed tries from the same address')])
    subject, text, kw = sent[0]
    assert subject == 'Possible stolen password' and kw == {'alert_type': 'security'}
    assert TRAP_IP in text and SPRAY_IP in text and 'Banned 1 address:' in text


# ---------- how a ban is written, and watched catches that go quiet ----------

@pytest.mark.parametrize('target,entry', [
    ('198.51.100.10', '198.51.100.10/32'),
    ('2001:db8::1', '2001:db8::1/128'),
    ('198.51.100.0/24', '198.51.100.0/24'),
])
def test_a_ban_is_written_like_the_ban_button_writes_it(target, entry):
    from app.services import protection_rules
    assert protection_rules._blacklist_entry(target) == entry


def test_a_watched_catch_with_no_new_activity_for_a_week_moves_to_the_history(db):
    from app.services import protection_rules
    _rules(db, trap={'enabled': True, 'names': ['admin']})
    _fail(db, TRAP_IP, 'admin')
    protection_rules.evaluate(db, _context())
    assert [h.status for h in _fresh(db)] == ['watching']

    protection_rules.evaluate(db, _context(), now=datetime.utcnow() + timedelta(days=6))
    assert [h.status for h in _fresh(db)] == ['watching']

    later = datetime.utcnow() + timedelta(days=8)
    protection_rules.evaluate(db, _context(), now=later)
    hit = _fresh(db)[0]
    assert hit.status == 'expired' and hit.mode == 'watch' and hit.ended_at == later

    # It comes back: the rule catches it again, as a new catch
    _fail(db, TRAP_IP, 'admin', minutes_ago=-8 * 24 * 60)
    protection_rules.evaluate(db, _context(), now=later + timedelta(minutes=1))
    assert [h.status for h in _fresh(db)] == ['expired', 'watching']


def test_a_ban_waiting_to_be_written_does_not_go_quiet(db):
    from app.services import protection_rules
    _trap_hit(db)
    protection_rules.evaluate(db, _context(), now=datetime.utcnow() + timedelta(days=8))
    assert [h.status for h in _fresh(db)] == ['pending']
