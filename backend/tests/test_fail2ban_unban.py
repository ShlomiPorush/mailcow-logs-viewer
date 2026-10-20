"""Fail2ban Unban, and the external firewall switch, the way mailcow takes them.

mailcow has no delete/fail2ban endpoint: an unban is edit/fail2ban with the
networks as items and action "unban". mailcow's netfilter keys a ban by the
network it banned (the address with netban_ipv4 or netban_ipv6) and skips an
unban of any other key, while the API answers success either way. And mailcow
turns "manage external" off on any full edit that leaves it out. A list entry is
a network: 198.51.100.7 and 198.51.100.7/32 are the same entry."""
import asyncio

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient

from app.mailcow_api import MailcowAPIError, mailcow_api


def _client():
    from app.main import app
    return TestClient(app)


def _ban(network):
    return {'network': network, 'ip': network.split('/')[0], 'banned_until': '00h 20m 00s', 'queued_for_unban': 0}


@pytest.fixture()
def mailcow(monkeypatch):
    """A mailcow with the given Fail2ban answer; records every Read-Write call."""
    state = {'f2b': {'netban_ipv4': 32, 'netban_ipv6': 128, 'blacklist': '', 'whitelist': '', 'active_bans': []},
             'calls': []}

    async def fake_get():
        return state['f2b']

    async def fake_rw(endpoint, method='POST', **kwargs):
        state['calls'].append((endpoint, kwargs.get('json')))
        return [{'type': 'success', 'msg': ['object_modified', 'x']}]

    monkeypatch.setattr(mailcow_api, 'get_fail2ban', fake_get)
    monkeypatch.setattr(mailcow_api, '_make_rw_request', fake_rw)
    return state


def test_unban_is_the_edit_mailcow_takes(mailcow):
    mailcow['f2b']['active_bans'] = [_ban('198.51.100.7/32'), _ban('2001:db8::7/128')]
    assert _client().post('/api/fail2ban/unban', json={'ip': '198.51.100.7'}).json()['status'] == 'success'
    assert _client().post('/api/fail2ban/unban', json={'ip': '2001:db8::7'}).json()['status'] == 'success'
    assert mailcow['calls'] == [
        ('/api/v1/edit/fail2ban', {'items': ['198.51.100.7/32'], 'attr': {'action': 'unban'}}),
        ('/api/v1/edit/fail2ban', {'items': ['2001:db8::7/128'], 'attr': {'action': 'unban'}}),
    ]


def test_unban_lifts_the_network_fail2ban_banned(mailcow):
    # netban_ipv4 24 and netban_ipv6 64: Fail2ban banned the networks around the addresses
    mailcow['f2b'].update(netban_ipv4=24, netban_ipv6=64,
                          active_bans=[_ban('198.51.100.0/24'), _ban('2001:db8:0:7::/64')])
    client = _client()
    # The Events list sends the address that tried, the Security page the ban's own address
    for ip in ('198.51.100.7/32', '198.51.100.0/32', '2001:db8:0:7::9/128'):
        res = client.post('/api/fail2ban/unban', json={'ip': ip}).json()
        assert res['status'] == 'success', res
    assert [body['items'] for _, body in mailcow['calls']] == [
        ['198.51.100.0/24'], ['198.51.100.0/24'], ['2001:db8:0:7::/64']]
    assert res['networks'] == ['2001:db8:0:7::/64']


def test_an_address_that_is_not_banned_is_not_reported_unbanned(mailcow):
    mailcow['f2b'].update(netban_ipv4=24, active_bans=[_ban('198.51.100.0/24')], blacklist='203.0.113.99/32')
    client = _client()
    free = client.post('/api/fail2ban/unban', json={'ip': '203.0.113.7/32'}).json()
    denied = client.post('/api/fail2ban/unban', json={'ip': '203.0.113.99/32'}).json()
    assert free['status'] == 'error' and 'not banned' in free['msg']
    assert denied['status'] == 'error' and 'denylist' in denied['msg']
    assert mailcow['calls'] == []


def test_an_unban_mailcow_refuses_says_so(mailcow, monkeypatch):
    mailcow['f2b']['active_bans'] = [_ban('198.51.100.7/32')]

    async def refused(ip):
        raise MailcowAPIError('RW API request failed with status 404')

    monkeypatch.setattr(mailcow_api, 'unban_fail2ban', refused)
    monkeypatch.setattr(mailcow_api, 'unban_fail2ban', refused)
    res = _client().post('/api/fail2ban/unban', json={'ip': '198.51.100.7'})
    assert res.status_code == 502 and 'unban' in res.json()['detail']


def test_an_edit_keeps_the_external_firewall_switch(monkeypatch):
    sent = []

    async def fake_get():
        return {'ban_time': 1800, 'manage_external': 1}

    async def fake_rw(endpoint, method='POST', **kwargs):
        sent.append(kwargs.get('json'))
        return [{'type': 'success', 'msg': ['f2b_modified']}]

    monkeypatch.setattr(mailcow_api, 'get_fail2ban', fake_get)
    monkeypatch.setattr(mailcow_api, '_make_rw_request', fake_rw)
    asyncio.run(mailcow_api.edit_fail2ban({'ban_time': '3600'}))
    # A caller that sets it keeps its own value
    asyncio.run(mailcow_api.edit_fail2ban({'ban_time': '3600', 'manage_external': '0'}))
    assert sent[0]['attr'] == {'ban_time': '3600', 'manage_external': '1'}
    assert sent[1]['attr'] == {'ban_time': '3600', 'manage_external': '0'}


@pytest.mark.parametrize('listed, added', [
    ('198.51.100.7', '198.51.100.7/32'),
    ('198.51.100.7/32', '198.51.100.7'),
    ('2001:DB8:0::1', '2001:db8::1/128'),
])
def test_an_address_already_on_a_list_is_not_added_again(mailcow, listed, added):
    mailcow['f2b'].update(blacklist=f'203.0.113.99\n{listed}', whitelist=listed)
    client = _client()
    for path, label in (('/api/fail2ban/ban', 'blacklist'), ('/api/fail2ban/allow', 'allowlist')):
        res = client.post(path, json={'ip': added}).json()
        assert res['status'] == 'success' and res['already'] and f'already in the {label}' in res['msg'], res
    assert mailcow['calls'] == []


def test_a_single_ipv6_address_is_not_the_slash_32_network_on_the_list(mailcow):
    mailcow['f2b']['blacklist'] = '2001:db8::1/32'
    res = _client().post('/api/fail2ban/ban', json={'ip': '2001:db8::1/128'}).json()
    assert res['status'] == 'success' and 'added' in res['msg']
    assert mailcow['calls'][0][1]['attr']['blacklist'] == '2001:db8::1/32,2001:db8::1/128'
