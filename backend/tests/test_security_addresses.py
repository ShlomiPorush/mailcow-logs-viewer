"""The Security page's lists come from the server, with real counts.

An address is banned or it is not: To review holds what a rule caught and what
only failed to log in, Banned what a rule or Fail2ban banned. The counts cover
every address (for the country, when one is chosen), not only a loaded page, and
the pages follow a cursor so none repeats or skips an address.
"""
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

MARKER = f'secaddr-{uuid.uuid4().hex[:8]}'
COUNTRY = f'Testland {uuid.uuid4().hex[:6]}'
OTHER = f'Otherland {uuid.uuid4().hex[:6]}'
IPS = [f'192.0.2.{n}' for n in range(10, 40)]


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import NetfilterLog, ProtectionHit
    with get_db_context() as db:
        db.query(NetfilterLog).filter(NetfilterLog.priority == MARKER).delete(synchronize_session=False)
        db.query(ProtectionHit).filter(ProtectionHit.ip.in_(IPS)).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def fail2ban(monkeypatch):
    from app.mailcow_api import mailcow_api
    state = {'answer': {'active_bans': [], 'perm_bans': [], 'blacklist': '', 'whitelist': ''}}

    async def get_fail2ban():
        return state['answer']
    monkeypatch.setattr(mailcow_api, 'get_fail2ban', get_fail2ban)
    return state


@pytest.fixture()
def client(fail2ban):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from fastapi.testclient import TestClient
    from app.database import init_db
    from app.main import app
    from app.services import security_addresses
    init_db()
    _cleanup()
    security_addresses.forget()
    yield TestClient(app)
    security_addresses.forget()
    _cleanup()


def _failed(ip, minutes_ago=5, country=COUNTRY, times=1):
    from app.database import get_db_context
    from app.models import NetfilterLog
    with get_db_context() as db:
        for i in range(times):
            db.add(NetfilterLog(time=datetime.utcnow() - timedelta(minutes=minutes_ago, seconds=i), priority=MARKER,
                                ip=ip, rule_id=3, username='info', action='warning', country_name=country, country_code='TL',
                                message=f'{ip} matched rule id 3 (warning: unknown[{ip}]: SASL LOGIN authentication failed)'))
        db.commit()


def _hit(ip, status, rule='trap', minutes_ago=5, country=COUNTRY):
    from app.database import get_db_context
    from app.models import ProtectionHit
    when = datetime.utcnow() - timedelta(minutes=minutes_ago)
    with get_db_context() as db:
        db.add(ProtectionHit(ip=ip, rule=rule, mode='enforce' if status == 'banned' else 'watch', status=status,
                             reason='Tried the trap account admin', usernames=['admin'], log_ids=[], attempts=1,
                             first_seen=when, last_seen=when, country_name=country, country_code='TL',
                             banned_at=when if status == 'banned' else None, owned=status == 'banned'))
        db.commit()


def _get(client, **params):
    from app.services import security_addresses
    security_addresses.forget()
    response = client.get('/api/security/addresses', params={'country': COUNTRY, **params})
    assert response.status_code == 200, response.text
    return response.json()


def _ips(page):
    return [a['ip'] for a in page['items']]


def test_an_address_is_banned_or_to_review(client, fail2ban):
    ip_failed, ip_watched, ip_rule_ban, ip_f2b, ip_queued = IPS[:5]
    _failed(ip_failed)
    _hit(ip_watched, 'watching')
    _hit(ip_rule_ban, 'banned')
    _failed(ip_f2b)
    _failed(ip_queued)
    fail2ban['answer']['active_bans'] = [
        {'ip': ip_f2b, 'network': f'{ip_f2b}/32', 'banned_until': '20m', 'queued_for_unban': 0},
        {'ip': ip_queued, 'network': f'{ip_queued}/32', 'banned_until': '5m', 'queued_for_unban': 1},
    ]

    review = _get(client, list='review')
    banned = _get(client, list='banned')
    assert set(_ips(review)) == {ip_failed, ip_watched, ip_queued}
    assert set(_ips(banned)) == {ip_rule_ban, ip_f2b}
    assert review['counts'] == banned['counts'] == {'review': 3, 'banned': 2}
    by_ip = {a['ip']: a for a in review['items'] + banned['items']}
    assert by_ip[ip_failed]['hits'] == [] and by_ip[ip_failed]['tries'] == 1
    assert [h['rule'] for h in by_ip[ip_watched]['hits']] == ['trap']
    assert by_ip[ip_f2b]['f2b']['banned_until'] == '20m'
    assert review['fail2ban_known'] is True


def test_the_allowlist_and_the_denylist_are_not_in_either_list(client, fail2ban):
    allowed, denied = IPS[:2]
    _failed(allowed)
    _hit(denied, 'watching')
    fail2ban['answer'].update(whitelist=f'{allowed}/32', blacklist=denied)
    page = _get(client, list='review')
    assert page['counts'] == {'review': 0, 'banned': 0}


def test_a_permanent_ban_is_a_list_entry_not_a_ban(client, fail2ban):
    ip = IPS[0]
    _failed(ip)
    fail2ban['answer'].update(active_bans=[{'ip': ip, 'network': f'{ip}/32', 'banned_until': ''}],
                              perm_bans=[{'network': f'{ip}/32'}], blacklist=f'{ip}/32')
    assert _get(client, list='banned')['counts'] == {'review': 0, 'banned': 0}


def test_the_counts_are_for_the_country_and_cover_every_address(client):
    for ip in IPS[:7]:
        _failed(ip, country=COUNTRY)
    for ip in IPS[7:10]:
        _failed(ip, country=OTHER)
    page = _get(client, list='review', limit=2)
    assert page['total'] == page['counts']['review'] == 7
    assert len(page['items']) == 2 and page['next']
    assert all(a['country'] == COUNTRY for a in page['items'])
    other = _get(client, list='review', country=OTHER)
    assert other['total'] == 3
    assert page['all_counts']['review'] >= 10


def test_a_search_keeps_the_addresses_that_contain_it_and_counts_only_those(client, fail2ban):
    for ip in IPS[:5]:
        _failed(ip)
    _hit(IPS[5], 'banned')
    everything = _get(client, list='review')
    assert everything['counts'] == {'review': 5, 'banned': 1}
    # 192.0.2.1 is in 192.0.2.10 to 192.0.2.14 and in 192.0.2.15
    page = _get(client, list='review', q='192.0.2.1')
    assert page['counts'] == {'review': 5, 'banned': 1}
    page = _get(client, list='review', q='2.12')
    assert _ips(page) == [IPS[2]] and page['counts'] == {'review': 1, 'banned': 0}
    banned = _get(client, list='banned', q=' 2.15 ')
    assert _ips(banned) == [IPS[5]] and banned['total'] == 1
    assert _get(client, list='review', q='198.51.100')['counts'] == {'review': 0, 'banned': 0}


def test_the_pages_neither_repeat_nor_skip_an_address(client):
    for n, ip in enumerate(IPS[:9]):
        _failed(ip, minutes_ago=n + 1)
    seen, after = [], None
    for _ in range(10):
        page = _get(client, list='review', limit=4, **({'after': after} if after else {}))
        seen += _ips(page)
        after = page['next']
        if not after:
            break
    assert seen == IPS[:9]  # newest first: IPS[0] was seen a minute ago


def test_an_address_that_leaves_the_list_does_not_shift_the_next_page(client, fail2ban):
    for n, ip in enumerate(IPS[:6]):
        _failed(ip, minutes_ago=n + 1)
    first = _get(client, list='review', limit=3)
    assert _ips(first) == IPS[:3]
    # The first address is banned meanwhile: the next page still starts after the third
    fail2ban['answer']['active_bans'] = [{'ip': IPS[0], 'network': f'{IPS[0]}/32', 'banned_until': '1h'}]
    second = _get(client, list='review', limit=3, after=first['next'])
    assert _ips(second) == IPS[3:6]


def test_without_mailcow_only_the_rules_bans_count(client, fail2ban):
    _hit(IPS[0], 'banned')
    _failed(IPS[1])
    fail2ban['answer'] = None
    page = _get(client, list='banned')
    assert page['fail2ban_known'] is False
    assert _ips(page) == [IPS[0]]
    assert page['counts'] == {'review': 1, 'banned': 1}


def test_an_address_without_a_line_today_takes_its_country_from_older_lines(client, fail2ban):
    ip = IPS[0]
    _failed(ip, minutes_ago=3 * 24 * 60)
    fail2ban['answer']['active_bans'] = [{'ip': ip, 'network': f'{ip}/32', 'banned_until': '2d'}]
    page = _get(client, list='banned')
    assert _ips(page) == [ip] and page['items'][0]['country'] == COUNTRY


def test_a_network_keeps_its_addresses_and_counts_only_those(client, fail2ban):
    from app.database import get_db_context
    from app.models import NetfilterLog
    for ip in IPS[:4]:
        _failed(ip)
    with get_db_context() as db:
        db.query(NetfilterLog).filter(NetfilterLog.priority == MARKER, NetfilterLog.ip.in_(IPS[:3])).update({NetfilterLog.asn_org: 'Test Network'}, synchronize_session=False)
        db.commit()
    page = _get(client, list='review', network='Test Network')
    assert sorted(_ips(page)) == sorted(IPS[:3])
    assert page['counts'] == {'review': 3, 'banned': 0} and page['network'] == 'Test Network'
    assert _get(client, list='review')['counts']['review'] == 4


def test_a_network_with_the_panels_period_lists_every_address_that_tried_in_it(client, fail2ban):
    from app.database import get_db_context
    from app.services import security_addresses
    from app.models import NetfilterLog
    _failed(IPS[0])
    _failed(IPS[1], minutes_ago=3 * 24 * 60)
    with get_db_context() as db:
        # A probe is an attempt the panels count, though not a failed login
        db.add(NetfilterLog(time=datetime.utcnow() - timedelta(days=2), priority=MARKER, ip=IPS[2], rule_id=1,
                            action='warning', country_name=COUNTRY, country_code='TL', asn_org='Test Network',
                            message=f'{IPS[2]} matched rule id 1 (warning: non-SMTP command from unknown[{IPS[2]}])'))
        db.commit()
        db.query(NetfilterLog).filter(NetfilterLog.priority == MARKER).update({NetfilterLog.asn_org: 'Test Network'}, synchronize_session=False)
        db.commit()
    assert _ips(_get(client, list='review', network='Test Network')) == [IPS[0]]
    page = _get(client, list='review', network='Test Network', days=7)
    assert _ips(page) == [IPS[0], IPS[2], IPS[1]] and page['counts'] == {'review': 3, 'banned': 0}
    # The Overview tab still counts the last day
    assert page['all_counts']['review'] == _get(client, list='review', network='Test Network')['all_counts']['review']
    # A country with the period does the same
    assert _ips(_get(client, list='review', days=7)) == [IPS[0], IPS[2], IPS[1]]
    # Without either, the list stays the last day
    security_addresses.forget()
    unfiltered = client.get('/api/security/addresses', params={'list': 'review', 'days': 7, 'limit': 200}).json()
    assert IPS[0] in _ips(unfiltered) and not {IPS[1], IPS[2]} & set(_ips(unfiltered))


def test_the_country_panel_counts_an_attempt_once(client):
    from app.database import get_db_context
    from app.models import NetfilterLog
    ip = IPS[0]
    _failed(ip, times=2)
    with get_db_context() as db:
        db.add(NetfilterLog(time=datetime.utcnow() - timedelta(minutes=5), priority=MARKER, ip=ip, action='warning',
                            country_name=COUNTRY, country_code='TL',
                            message=f'7 more attempts in the next 600 seconds until {ip}/32 is banned'))
        db.commit()
    response = client.get('/api/logs/netfilter/stats/by-country', params={'days': 7})
    assert response.status_code == 200, response.text
    country = next(c for c in response.json()['data'] if c['country_code'] == 'TL')
    assert country['warning'] == 2 and country['total'] == 2 and country['addresses'] == 1
