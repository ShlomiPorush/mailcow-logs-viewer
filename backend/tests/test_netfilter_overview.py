"""Security page: attempts grouped by source address, and Fail2ban Allow.

An attempt is a line where netfilter matched a rule; the "N more attempts"
line that follows it must not count again."""
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.routers.logs import netfilter_service

MARKER = f'overview-{uuid.uuid4().hex[:8]}'
IP_A = '198.51.100.23'
IP_B = '203.0.113.77'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import NetfilterLog
    with get_db_context() as db:
        db.query(NetfilterLog).filter(NetfilterLog.priority == MARKER).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def client():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from fastapi.testclient import TestClient
    from app.database import init_db
    from app.main import app
    init_db()
    _cleanup()
    yield TestClient(app)
    _cleanup()


def _add(ip, message, action='warning', rule_id=None, username=None, minutes_ago=5, **extra):
    from app.database import get_db_context
    from app.models import NetfilterLog
    with get_db_context() as db:
        db.add(NetfilterLog(time=datetime.utcnow() - timedelta(minutes=minutes_ago), priority=MARKER,
                            message=message, ip=ip, rule_id=rule_id, username=username, action=action, **extra))
        db.commit()


def test_service_comes_from_the_log_text():
    assert netfilter_service('1.2.3.4 matched rule id 3 (warning: unknown[1.2.3.4]: SASL LOGIN authentication failed: x)') == ('SMTP auth', True)
    assert netfilter_service('1.2.3.4 matched rule id 4 (warning: non-SMTP command from unknown[1.2.3.4]: GET / HTTP/1.1)') == ('SMTP probe', False)
    assert netfilter_service('imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<a>, method=PLAIN, rip=1.2.3.4,') == ('IMAP', True)
    assert netfilter_service('9 more attempts in the next 600 seconds until 1.2.3.4/32 is banned') == (None, False)
    assert netfilter_service(None) == (None, False)


def test_attempts_are_grouped_by_address(client):
    sasl = f'{IP_A} matched rule id 3 (warning: unknown[{IP_A}]: SASL LOGIN authentication failed: (reason unavailable), sasl_username=admin@example.com)'
    for minutes in (5, 10, 15):
        _add(IP_A, sasl, rule_id=3, username='admin@example.com', minutes_ago=minutes)
        _add(IP_A, f'9 more attempts in the next 600 seconds until {IP_A}/32 is banned', minutes_ago=minutes)
    _add(IP_B, f'{IP_B} matched rule id 4 (warning: non-SMTP command from unknown[{IP_B}]: GET / HTTP/1.1)', rule_id=4, minutes_ago=20)
    _add(IP_B, f'Banning {IP_B}/32 for 30 minutes', action='ban', minutes_ago=19)
    _add(IP_B, f'{IP_B} matched rule id 4 (warning: non-SMTP command from unknown[{IP_B}]: x)', rule_id=4, minutes_ago=60 * 30)

    data = client.get('/api/logs/netfilter/overview').json()
    by_ip = {s['ip']: s for s in data['sources']}

    assert by_ip[IP_A]['attempts'] == 3
    assert by_ip[IP_A]['failed_logins'] == 3
    assert by_ip[IP_A]['services'] == ['SMTP auth']
    assert by_ip[IP_A]['usernames'] == ['admin@example.com']
    assert by_ip[IP_A]['last_action'] is None

    # Older than 24 hours does not count; the ban is the last action
    assert by_ip[IP_B]['attempts'] == 1
    assert by_ip[IP_B]['failed_logins'] == 0
    assert by_ip[IP_B]['services'] == ['SMTP probe']
    assert by_ip[IP_B]['last_action'] == 'ban'

    assert data['failed_logins'] >= 3
    assert data['attempts'] >= 4
    assert sum(1 for row in data['latest'] if row['ip'] == IP_A) == 3
    assert all(row['ip'] != IP_B for row in data['latest'])


def test_allow_adds_to_the_whitelist_and_keeps_the_rest(client, monkeypatch):
    from app.mailcow_api import mailcow_api
    saved = {}

    async def fake_get():
        return {'ban_time': 1800, 'ban_time_increment': True, 'max_attempts': 10, 'max_ban_time': 86400,
                'netban_ipv4': 32, 'netban_ipv6': 128, 'retry_window': 600,
                'whitelist': '192.0.2.0/24\n192.0.2.1', 'blacklist': '203.0.113.9/32'}

    async def fake_edit(attrs):
        saved.update(attrs)
        return [{'type': 'success', 'msg': ['fail2ban_edit_ok']}]

    monkeypatch.setattr(mailcow_api, 'get_fail2ban', fake_get)
    monkeypatch.setattr(mailcow_api, 'edit_fail2ban', fake_edit)

    res = client.post('/api/fail2ban/allow', json={'ip': f'{IP_A}/32'})
    assert res.json()['status'] == 'success'
    assert saved['whitelist'] == f'192.0.2.0/24,192.0.2.1,{IP_A}/32'
    assert saved['blacklist'] == '203.0.113.9/32'
    assert saved['ban_time'] == '1800' and saved['ban_time_increment'] == '1'

    saved.clear()
    res = client.post('/api/fail2ban/ban', json={'ip': '192.0.2.50/32'})
    assert res.json()['status'] == 'success'
    assert saved['blacklist'] == '203.0.113.9/32,192.0.2.50/32'
    assert saved['whitelist'] == '192.0.2.0/24,192.0.2.1'

    saved.clear()
    res = client.post('/api/fail2ban/allow', json={'ip': '192.0.2.1'})
    assert 'already' in res.json()['msg']
    assert saved == {}

    assert client.post('/api/fail2ban/allow', json={}).status_code == 400


def test_attempts_are_counted_by_network(client):
    """The networks attempts come from: only matched-rule lines count, as on the overview."""
    asn, org = f'AS{uuid.uuid4().int % 10**9}', 'Example Hosting'
    line = lambda ip: f'{ip} matched rule id 3 (warning: unknown[{ip}]: SASL LOGIN authentication failed: x)'
    for ip in (IP_A, IP_A, IP_B):
        _add(ip, line(ip), rule_id=3, asn=asn, asn_org=org, city='Exampleton', country_name='Example')
    _add(IP_A, f'9 more attempts in the next 600 seconds until {IP_A}/32 is banned', asn=asn, asn_org=org)

    rows = {r['asn']: r for r in client.get('/api/logs/netfilter/stats/by-network?days=7').json()['data']}
    assert rows[asn] == {'asn': asn, 'asn_org': org, 'attempts': 3, 'addresses': 2}

    # The overview carries where each address is
    source = {s['ip']: s for s in client.get('/api/logs/netfilter/overview').json()['sources']}[IP_A]
    assert source['city'] == 'Exampleton' and source['asn_org'] == org


def test_an_exact_ip_does_not_match_a_longer_one(client):
    longer = IP_A + '0'  # 198.51.100.230 contains 198.51.100.23
    _add(IP_A, f'{IP_A} matched rule id 3 (x)', rule_id=3)
    _add(longer, f'{longer} matched rule id 3 (x)', rule_id=3)
    loose = {r['ip'] for r in client.get('/api/logs/netfilter', params={'ip': IP_A}).json()['data']}
    exact = {r['ip'] for r in client.get('/api/logs/netfilter', params={'ip': IP_A, 'exact_ip': True}).json()['data']}
    assert {IP_A, longer} <= loose
    assert exact == {IP_A}


def test_remove_takes_an_address_off_a_list_and_keeps_the_rest(client, monkeypatch):
    from app.mailcow_api import mailcow_api
    saved = {}

    async def fake_get():
        return {'ban_time': 1800, 'ban_time_increment': 1, 'max_attempts': 10, 'max_ban_time': 86400,
                'netban_ipv4': 32, 'netban_ipv6': 128, 'retry_window': 600,
                'whitelist': '192.0.2.0/24\n192.0.2.1', 'blacklist': '203.0.113.9/32,203.0.113.10'}

    async def fake_edit(attrs):
        saved.update(attrs)
        return [{'type': 'success', 'msg': ['fail2ban_edit_ok']}]

    monkeypatch.setattr(mailcow_api, 'get_fail2ban', fake_get)
    monkeypatch.setattr(mailcow_api, 'edit_fail2ban', fake_edit)

    # 203.0.113.9 and 203.0.113.9/32 are the same entry
    res = client.post('/api/fail2ban/remove', json={'ip': '203.0.113.9', 'list': 'blacklist'})
    assert res.json()['status'] == 'success'
    assert saved['blacklist'] == '203.0.113.10'
    assert saved['whitelist'] == '192.0.2.0/24,192.0.2.1'
    assert saved['ban_time'] == '1800' and saved['max_attempts'] == '10'

    saved.clear()
    res = client.post('/api/fail2ban/remove', json={'ip': '192.0.2.0/24', 'list': 'whitelist'})
    assert saved['whitelist'] == '192.0.2.1' and saved['blacklist'] == '203.0.113.9/32,203.0.113.10'

    # Not on the list: nothing is written
    saved.clear()
    res = client.post('/api/fail2ban/remove', json={'ip': '198.51.100.99', 'list': 'blacklist'})
    assert 'not in' in res.json()['msg'] and saved == {}

    assert client.post('/api/fail2ban/remove', json={'ip': '192.0.2.1', 'list': 'other'}).status_code == 400
    assert client.post('/api/fail2ban/remove', json={'list': 'whitelist'}).status_code == 400


def test_the_policy_keeps_the_lists_read_right_before_writing(client, monkeypatch):
    from app.mailcow_api import mailcow_api
    saved = {}
    lists = {'whitelist': '192.0.2.0/24', 'blacklist': '203.0.113.9/32'}

    async def fake_get():
        return {'ban_time': 1800, 'ban_time_increment': 1, 'max_attempts': 10, 'max_ban_time': 86400,
                'netban_ipv4': 32, 'netban_ipv6': 128, 'retry_window': 600, **lists}

    async def fake_edit(attrs):
        saved.update(attrs)
        return [{'type': 'success', 'msg': ['fail2ban_edit_ok']}]

    monkeypatch.setattr(mailcow_api, 'get_fail2ban', fake_get)
    monkeypatch.setattr(mailcow_api, 'edit_fail2ban', fake_edit)
    policy = {'ban_time': 3600, 'max_ban_time': 604800, 'ban_time_increment': False, 'max_attempts': 5,
              'retry_window': 900, 'netban_ipv4': 24, 'netban_ipv6': 64}

    # A rule added an address after the page loaded: it is still there after the save
    lists['blacklist'] = '203.0.113.9/32\n198.51.100.7/32'
    res = client.post('/api/fail2ban/policy', json=policy)
    assert res.json()['status'] == 'success'
    assert saved == {'ban_time': '3600', 'max_ban_time': '604800', 'ban_time_increment': '0', 'max_attempts': '5',
                     'retry_window': '900', 'netban_ipv4': '24', 'netban_ipv6': '64', 'manage_external': '0',
                     'blacklist': '203.0.113.9/32,198.51.100.7/32', 'whitelist': '192.0.2.0/24'}

    saved.clear()
    assert client.post('/api/fail2ban/policy', json={**policy, 'netban_ipv4': 33}).status_code == 400
    assert client.post('/api/fail2ban/policy', json={**policy, 'max_attempts': 'x'}).status_code == 400
    assert client.post('/api/fail2ban/policy', json={**policy, 'max_ban_time': 60}).status_code == 400
    assert saved == {}


def test_unban_is_the_edit_mailcow_takes(client, monkeypatch):
    """mailcow has no delete/fail2ban; an unban is edit/fail2ban with action unban
    and the networks as items, which mailcow handles before touching any setting."""
    from app.mailcow_api import mailcow_api
    calls = []

    async def fake_rw(endpoint, method='POST', **kwargs):
        calls.append((endpoint, kwargs.get('json')))
        return [{'type': 'success', 'msg': ['object_modified', '198.51.100.7/32']}]

    monkeypatch.setattr(mailcow_api, '_make_rw_request', fake_rw)
    assert client.post('/api/fail2ban/unban', json={'ip': '198.51.100.7'}).json()['status'] == 'success'
    assert calls == [('/api/v1/edit/fail2ban', {'items': ['198.51.100.7/32'], 'attr': {'action': 'unban'}})]


def test_an_unban_mailcow_refuses_says_so(client, monkeypatch):
    from app.mailcow_api import mailcow_api, MailcowAPIError

    async def refused(ip):
        raise MailcowAPIError('RW API request failed with status 404')

    monkeypatch.setattr(mailcow_api, 'unban_fail2ban', refused)
    res = client.post('/api/fail2ban/unban', json={'ip': '198.51.100.7'})
    assert res.status_code == 502 and 'unban' in res.json()['detail']


def test_every_full_edit_keeps_the_external_firewall_switch(client, monkeypatch):
    """mailcow turns manage_external off on an edit that leaves it out."""
    from app.mailcow_api import mailcow_api
    from app.services.protection_rules import fail2ban_attrs
    saved = []
    current = {'ban_time': 1800, 'ban_time_increment': 1, 'max_attempts': 10, 'max_ban_time': 86400,
               'netban_ipv4': 32, 'netban_ipv6': 128, 'retry_window': 600, 'manage_external': 1,
               'whitelist': '192.0.2.1', 'blacklist': '203.0.113.9/32'}

    async def fake_get():
        return dict(current)

    async def fake_edit(attrs):
        saved.append(attrs)
        return [{'type': 'success', 'msg': ['fail2ban_edit_ok']}]

    monkeypatch.setattr(mailcow_api, 'get_fail2ban', fake_get)
    monkeypatch.setattr(mailcow_api, 'edit_fail2ban', fake_edit)
    client.post('/api/fail2ban/allow', json={'ip': '192.0.2.50'})
    client.post('/api/fail2ban/ban', json={'ip': '192.0.2.51'})
    client.post('/api/fail2ban/remove', json={'ip': '203.0.113.9', 'list': 'blacklist'})
    client.post('/api/fail2ban/policy', json={'ban_time': 1800, 'max_ban_time': 86400, 'ban_time_increment': True,
                                              'max_attempts': 8, 'retry_window': 600, 'netban_ipv4': 32, 'netban_ipv6': 128})
    assert len(saved) == 4 and all(attrs['manage_external'] == '1' for attrs in saved)
    # The protection rules' writes too
    assert fail2ban_attrs(current, [], [])['manage_external'] == '1'
    assert fail2ban_attrs({**current, 'manage_external': 0}, [], [])['manage_external'] == '0'