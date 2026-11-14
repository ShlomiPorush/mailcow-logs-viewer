"""Ban and Allow take exactly one address or one network.

mailcow keeps the Fail2ban allowlist and denylist as one comma (or newline)
separated text, and the app writes the list back joined with commas. A value
with a comma or a line break in it would add several entries at once, so
"203.0.113.4/32,0.0.0.0/0" sent to Ban would deny every IPv4 address. The
server refuses anything that is not a single IP address or a single network
before it reads or writes the list.
"""
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient

from app.mailcow_api import mailcow_api


def _client():
    from app.main import app
    return TestClient(app)


@pytest.fixture()
def mailcow(monkeypatch):
    """A mailcow with empty lists; records every write."""
    state = {'f2b': {'netban_ipv4': 32, 'netban_ipv6': 128, 'blacklist': '', 'whitelist': '', 'active_bans': []},
             'writes': [], 'reads': 0}

    async def fake_get():
        state['reads'] += 1
        return state['f2b']

    async def fake_edit(attrs):
        state['writes'].append(attrs)
        return [{'type': 'success', 'msg': 'ok'}]

    monkeypatch.setattr(mailcow_api, 'get_fail2ban', fake_get)
    monkeypatch.setattr(mailcow_api, 'edit_fail2ban', fake_edit)
    return state


BAD_VALUES = [
    '203.0.113.4/32,0.0.0.0/0',     # two entries in one
    '203.0.113.4,203.0.113.5',
    '203.0.113.4\n0.0.0.0/0',       # mailcow splits on line breaks too
    '203.0.113.4/32\r\n',
    '203.0.113.4 203.0.113.5',
    ' 203.0.113.4',
    '203.0.113.4\t',
    'mail.example.com',             # a name, not an address
    'fe80::1%eth0',                 # an interface scope is not part of a list entry
    '203.0.113.4/33',
    '203.0.113.300',
    '',
]


@pytest.mark.parametrize('route', ['/api/fail2ban/ban', '/api/fail2ban/allow'])
@pytest.mark.parametrize('value', BAD_VALUES)
def test_a_value_that_is_not_one_address_or_network_is_refused(mailcow, route, value):
    res = _client().post(route, json={'ip': value})
    assert res.status_code == 400, (value, res.status_code, res.text)
    assert 'one IP address or one network' in res.json()['detail'] or 'Missing' in res.json()['detail']
    assert mailcow['writes'] == []


@pytest.mark.parametrize('route', ['/api/fail2ban/ban', '/api/fail2ban/allow'])
@pytest.mark.parametrize('value', [12345, ['203.0.113.4'], {'ip': '203.0.113.4'}, True])
def test_a_value_that_is_not_text_is_refused(mailcow, route, value):
    res = _client().post(route, json={'ip': value})
    assert res.status_code == 400, (value, res.status_code, res.text)
    assert mailcow['writes'] == []


@pytest.mark.parametrize('route,list_name', [('/api/fail2ban/ban', 'blacklist'), ('/api/fail2ban/allow', 'whitelist')])
@pytest.mark.parametrize('value', ['203.0.113.4/32', '203.0.113.4', '198.51.100.0/24', '198.51.100.7/24',
                                   '2001:db8::7/128', '2001:db8::7', '2001:db8::/48'])
def test_one_address_or_one_network_is_written_as_sent(mailcow, route, list_name, value):
    res = _client().post(route, json={'ip': value})
    assert res.status_code == 200, res.text
    assert res.json()['status'] == 'success'
    assert [w[list_name] for w in mailcow['writes']] == [value]
