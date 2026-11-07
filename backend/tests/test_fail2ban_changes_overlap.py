"""Two changes to mailcow's Fail2ban settings at the same time both stay.

mailcow's edit replaces both lists and every setting, so each change here reads
them, changes them and writes them all back. Two changes that overlapped (two
Repairs, a Repair and a Ban, a protection rule ban and a Remove) both read the
same lists, and the second write put back what the first one had changed, while
both answered success. Every write path now waits for the one before it.

The fake mailcow below hands out a copy of its lists and yields to the event
loop before answering, so two calls that are not serialized both read before
either writes.
"""
import asyncio
import json

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from starlette.requests import Request  # noqa: E402

from app.mailcow_api import mailcow_api  # noqa: E402
from app.routers import logs  # noqa: E402
from app.services import protection_rules  # noqa: E402

from test_protection_enforce import _fresh, _trap_hit  # noqa: E402
from test_protection_rules import TRAP_IP, db  # noqa: E402,F401  (db is a fixture)


@pytest.fixture(autouse=True)
def fresh_lock(monkeypatch):
    # An asyncio lock binds to the first loop that waits on it; each test runs its own loop
    monkeypatch.setattr(protection_rules, 'fail2ban_lock', asyncio.Lock(), raising=False)


@pytest.fixture()
def mailcow(monkeypatch):
    """One shared mailcow: a read answers what was written last, a moment later."""
    state = {'blacklist': '', 'whitelist': '', 'ban_time': 600, 'manage_external': 1}

    async def get_fail2ban():
        answer = dict(state)
        for _ in range(3):
            await asyncio.sleep(0)
        return answer

    async def edit_fail2ban(attrs):
        await asyncio.sleep(0)
        state.update(blacklist=attrs['blacklist'], whitelist=attrs['whitelist'])
        return [{'type': 'success', 'msg': 'f2b_modified'}]

    monkeypatch.setattr(mailcow_api, 'get_fail2ban', get_fail2ban)
    monkeypatch.setattr(mailcow_api, 'edit_fail2ban', edit_fail2ban)
    return state


def _request(path, body):
    async def receive():
        return {'type': 'http.request', 'body': json.dumps(body).encode()}
    return Request({'type': 'http', 'method': 'POST', 'path': path, 'headers': []}, receive)


def _repair(entry, list_name='blacklist'):
    return logs.repair_fail2ban_entry(_request('/api/fail2ban/repair', {'entry': entry, 'list': list_name}))


def _together(*calls):
    async def run():
        # A change that waits for itself would hang: fail instead
        return await asyncio.wait_for(asyncio.gather(*calls), 5)
    return asyncio.run(run())


def _entries(value):
    return [e for e in value.replace('\n', ',').split(',') if e]


def test_two_repairs_at_once_keep_both_repairs(mailcow):
    mailcow['blacklist'] = '2001:db8::1/32,2001:db9::2/32'

    results = _together(_repair('2001:db8::1/32'), _repair('2001:db9::2/32'))

    assert _entries(mailcow['blacklist']) == ['2001:db8::1/128', '2001:db9::2/128']
    assert [r['status'] for r in results] == ['success', 'success']


def test_a_repair_and_a_ban_at_once_keep_both_changes(mailcow):
    mailcow['blacklist'] = '2001:db8::1/32'
    ban = logs.ban_fail2ban(_request('/api/fail2ban/ban', {'ip': '203.0.113.9'}))

    results = _together(_repair('2001:db8::1/32'), ban)

    assert sorted(_entries(mailcow['blacklist'])) == ['2001:db8::1/128', '203.0.113.9']
    assert [r['status'] for r in results] == ['success', 'success']


def test_a_protection_ban_and_a_list_remove_at_once_keep_both_changes(db, mailcow):
    _trap_hit(db)
    mailcow['blacklist'] = '203.0.113.50'
    remove = logs.remove_from_fail2ban_list(
        _request('/api/fail2ban/remove', {'ip': '203.0.113.50', 'list': 'blacklist'}))

    result, removed = _together(protection_rules.enforce(mailcow_api), remove)

    assert _entries(mailcow['blacklist']) == [f'{TRAP_IP}/32']
    assert [b[0] for b in result['banned']] == [TRAP_IP] and _fresh(db)[0].status == 'banned'
    assert removed['status'] == 'success'
