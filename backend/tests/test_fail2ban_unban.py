"""Fail2ban Unban, and the external firewall switch, the way mailcow takes them.

mailcow has no delete/fail2ban endpoint: an unban is edit/fail2ban with the
networks as items and action "unban". And mailcow turns "manage external" off on
any full edit that leaves it out."""
import asyncio

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient

from app.mailcow_api import MailcowAPIError, mailcow_api


def _client():
    from app.main import app
    return TestClient(app)


def test_unban_is_the_edit_mailcow_takes(monkeypatch):
    calls = []

    async def fake_rw(endpoint, method='POST', **kwargs):
        calls.append((endpoint, kwargs.get('json')))
        return [{'type': 'success', 'msg': ['object_modified', '198.51.100.7/32']}]

    monkeypatch.setattr(mailcow_api, '_make_rw_request', fake_rw)
    assert _client().post('/api/fail2ban/unban', json={'ip': '198.51.100.7'}).json()['status'] == 'success'
    assert _client().post('/api/fail2ban/unban', json={'ip': '2001:db8::7'}).json()['status'] == 'success'
    assert calls == [
        ('/api/v1/edit/fail2ban', {'items': ['198.51.100.7/32'], 'attr': {'action': 'unban'}}),
        ('/api/v1/edit/fail2ban', {'items': ['2001:db8::7/128'], 'attr': {'action': 'unban'}}),
    ]


def test_an_unban_mailcow_refuses_says_so(monkeypatch):
    async def refused(ip):
        raise MailcowAPIError('RW API request failed with status 404')

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
