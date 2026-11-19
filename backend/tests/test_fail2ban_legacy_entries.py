"""Fail2ban list entries an earlier version wrote as a /32 network.

The app used to write a single IPv6 address as 2001:db8::1/32. mailcow stores the
entry as sent and its netfilter reads it as all of 2001:db8::/32, so a Ban blocked
a whole provider and an Allow exempted one. Such an entry has host bits set under
its /32 prefix; a network written on purpose (2001:db8::/32) does not. The page
shows these entries, and Repair replaces one with the address as /128.
"""
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient

from app.mailcow_api import mailcow_api
from app.services.security_addresses import legacy_entries, legacy_ipv6_entry


def _client():
    from app.main import app
    return TestClient(app)


@pytest.mark.parametrize('entry, address', [
    ('2001:db8::1/32', '2001:db8::1'),
    (' 2001:db8:0:1::7/32 ', '2001:db8:0:1::7'),
    ('2001:db8::/32', None),          # a network written on purpose
    ('2001:db8::1/128', None),        # a single address, as written now
    ('2001:db8::1/64', None),         # another prefix the old code never wrote
    ('2001:db8::1', None),
    ('198.51.100.7/32', None),        # IPv4 /32 is a single address
    ('198.51.100.0/24', None),
    ('mail.example.com', None),
    ('', None),
])
def test_a_legacy_entry_is_an_ipv6_slash_32_with_host_bits_set(entry, address):
    assert legacy_ipv6_entry(entry) == address


def test_legacy_entries_are_found_on_both_lists():
    f2b = {'whitelist': '192.0.2.10\n2001:db8::2/32', 'blacklist': '2001:db8::/32,2001:db8::1/32,203.0.113.99/32'}
    assert legacy_entries(f2b) == [
        {'list': 'whitelist', 'entry': '2001:db8::2/32', 'address': '2001:db8::2', 'network': '2001:db8::/32'},
        {'list': 'blacklist', 'entry': '2001:db8::1/32', 'address': '2001:db8::1', 'network': '2001:db8::/32'},
    ]
    assert legacy_entries(None) == []


@pytest.fixture()
def mailcow(monkeypatch):
    """A mailcow that keeps its lists like the real one: entries stored as sent."""
    state = {
        'answer': {'whitelist': '', 'blacklist': '', 'ban_time': 600, 'manage_external': 1},
        'calls': [], 'reply': [{'type': 'success', 'msg': 'f2b_modified'}], 'keep': False,
    }

    async def get_fail2ban():
        state['calls'].append('get')
        return dict(state['answer'])

    async def edit_fail2ban(attrs):
        state['calls'].append(('edit', attrs))
        if not state['keep']:
            state['answer'] = {**state['answer'], 'blacklist': attrs['blacklist'].replace(',', '\n'),
                               'whitelist': attrs['whitelist'].replace(',', '\n')}
        return state['reply']

    monkeypatch.setattr(mailcow_api, 'get_fail2ban', get_fail2ban)
    monkeypatch.setattr(mailcow_api, 'edit_fail2ban', edit_fail2ban)
    return state


def test_the_fail2ban_answer_names_its_legacy_entries(mailcow):
    mailcow['answer']['blacklist'] = '2001:db8::1/32\n2001:db8::/32'
    data = _client().get('/api/fail2ban').json()
    assert data['blacklist'] == '2001:db8::1/32\n2001:db8::/32'
    assert data['legacy_entries'] == [
        {'list': 'blacklist', 'entry': '2001:db8::1/32', 'address': '2001:db8::1', 'network': '2001:db8::/32'}]


def test_repair_replaces_the_entry_with_the_address_in_one_edit_and_checks_it(mailcow):
    mailcow['answer']['blacklist'] = '198.51.100.7/32\n2001:db8::1/32\n2001:db8::/32'
    mailcow['answer']['whitelist'] = '192.0.2.10\n2001:db8::2/32'
    res = _client().post('/api/fail2ban/repair', json={'entry': '2001:db8::1/32', 'list': 'blacklist'}).json()
    assert res['status'] == 'success', res
    edits = [c[1] for c in mailcow['calls'] if c != 'get']
    assert mailcow['calls'][0] == 'get' and mailcow['calls'][-1] == 'get'
    assert len(edits) == 1
    assert edits[0]['blacklist'] == '198.51.100.7/32,2001:db8::1/128,2001:db8::/32'
    # The other list, the deliberate network and the other settings stay as they were
    assert edits[0]['whitelist'] == '192.0.2.10,2001:db8::2/32'
    assert edits[0]['manage_external'] == '1' and edits[0]['ban_time'] == '600'


def test_repair_on_the_allowlist_keeps_one_entry_when_the_address_is_there_already(mailcow):
    mailcow['answer']['whitelist'] = '2001:db8::2/32\n2001:db8::2/128'
    res = _client().post('/api/fail2ban/repair', json={'entry': '2001:db8::2/32', 'list': 'whitelist'}).json()
    assert res['status'] == 'success', res
    assert [c[1]['whitelist'] for c in mailcow['calls'] if c != 'get'] == ['2001:db8::2/128']


@pytest.mark.parametrize('entry', ['2001:db8::/32', '198.51.100.7/32', '2001:db8::1/128'])
def test_repair_refuses_an_entry_the_bug_did_not_write(mailcow, entry):
    mailcow['answer']['blacklist'] = entry
    res = _client().post('/api/fail2ban/repair', json={'entry': entry, 'list': 'blacklist'})
    assert res.status_code == 400
    assert mailcow['calls'] == []


def test_repair_of_an_entry_no_longer_on_the_list_writes_nothing(mailcow):
    res = _client().post('/api/fail2ban/repair', json={'entry': '2001:db8::1/32', 'list': 'blacklist'}).json()
    assert res['status'] == 'error'
    assert mailcow['calls'] == ['get']


def test_repair_reports_a_refusal_from_mailcow(mailcow):
    mailcow['answer']['blacklist'] = '2001:db8::1/32'
    mailcow['reply'] = [{'type': 'success', 'msg': 'f2b_modified'}, {'type': 'danger', 'msg': ['network_host_invalid', 'x']}]
    res = _client().post('/api/fail2ban/repair', json={'entry': '2001:db8::1/32', 'list': 'blacklist'}).json()
    assert res['status'] == 'error'


def test_repair_reports_a_list_that_did_not_change(mailcow):
    mailcow['answer']['blacklist'] = '2001:db8::1/32'
    mailcow['keep'] = True
    res = _client().post('/api/fail2ban/repair', json={'entry': '2001:db8::1/32', 'list': 'blacklist'}).json()
    assert res['status'] == 'error'
    assert 'did not show it' in res['msg']
