"""Every answer the log, Security, Fail2ban, queue, quarantine and statistics calls can
give, so the contract check (conftest.py, contract.py) holds each one to /openapi.json:
the answers with data, the failures that still answer 200 (statistics), a database
that fails (500), mailcow refusing or not answering (502, 503), and the requests the
calls refuse (400, 422). mailcow is faked; nothing leaves the test."""
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app.config import settings  # noqa: E402
from app.database import get_db  # noqa: E402
from app.mailcow_api import MailcowAPIError, mailcow_api  # noqa: E402
from app.main import app  # noqa: E402
from app.services import geoip_service, security_addresses  # noqa: E402

DB_GETS = ['/api/logs/postfix', '/api/logs/rspamd', '/api/logs/netfilter', '/api/logs/netfilter/overview',
           '/api/logs/netfilter/stats/by-country', '/api/logs/netfilter/stats/by-network',
           '/api/logs/postfix/by-queue/Q1', '/api/message/x', '/api/stats/trends?names=storage_used']
STATS = ['/api/stats/dashboard', '/api/stats/timeline', '/api/stats/top-spam-triggers',
         '/api/stats/top-blocked-ips', '/api/stats/recent-activity']
BAD_PARAMS = ['/api/logs/postfix?page=0', '/api/logs/rspamd?limit=0', '/api/logs/netfilter?limit=0',
              '/api/logs/netfilter/overview?hours=0', '/api/logs/netfilter/stats/by-country?days=0',
              '/api/logs/netfilter/stats/by-network?days=0', '/api/security/addresses?limit=0',
              '/api/stats/timeline?hours=x', '/api/stats/top-spam-triggers?limit=0',
              '/api/stats/top-blocked-ips?limit=0', '/api/stats/recent-activity?limit=0',
              '/api/stats/trends?names=nope', '/api/stats/flow', '/api/stats/flow?period=1y']
ITEM_ACTIONS = ['/api/queue/action', '/api/queue/delete', '/api/quarantine/release', '/api/quarantine/delete',
                '/api/quarantine/learnham', '/api/quarantine/learnspam']
LIST_CHANGES = [('/api/fail2ban/ban', {'ip': '198.51.100.9'}), ('/api/fail2ban/allow', {'ip': '198.51.100.9'}),
                ('/api/fail2ban/remove', {'ip': '198.51.100.9', 'list': 'blacklist'}),
                ('/api/fail2ban/repair', {'entry': '2001:db8::9/32', 'list': 'whitelist'}),
                ('/api/fail2ban/unban', {'ip': '198.51.100.9'}),
                ('/api/fail2ban/policy', {'ban_time': 600, 'max_ban_time': 3600, 'max_attempts': 5,
                                          'retry_window': 600, 'netban_ipv4': 32, 'netban_ipv6': 128}),
                ('/api/fail2ban', {'ban_time': '600'})]
F2B = {'ban_time': 600, 'max_ban_time': 3600, 'max_attempts': 5, 'retry_window': 600, 'netban_ipv4': 32,
       'netban_ipv6': 128, 'ban_time_increment': 1, 'manage_external': 0, 'active_bans': [], 'perm_bans': [],
       'blacklist': '198.51.100.9', 'whitelist': '2001:db8::9/32'}


@pytest.fixture
def client(monkeypatch):
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    security_addresses.forget()
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.pop(get_db, None)
    security_addresses.forget()


@pytest.fixture
def mailcow(monkeypatch):
    """A mailcow that answers each call with what state holds, or raises it."""
    state = {'answer': [{'type': 'success', 'msg': ['object_modified', 'x']}], 'f2b': dict(F2B)}

    def give(value):
        if isinstance(value, Exception):
            raise value
        return value

    async def rw(*args, **kwargs):
        return give(state['answer'])

    async def fail2ban():
        return give(state['f2b'])

    async def queue():
        return give([{'queue_id': 'ABC', 'queue_name': 'deferred', 'arrival_time': 1700000000,
                      'message_size': 1234, 'sender': 'a@example.com', 'recipients': ['b@example.org (x)']}])

    async def quarantine():
        return give([{'id': 7, 'qid': 'Q7', 'subject': 's', 'score': 12.5, 'sender': 'a@example.com',
                      'rcpt': 'b@example.org', 'created': 1700000000, 'notified': 0, 'virus_flag': 0},
                     {'id': 8, 'created': '2023-11-14T22:13:20'}])

    async def details(item_id):
        return give({'subject': 's', 'score': 12.5, 'symbols': [], 'recipients': ['b@example.org']})

    monkeypatch.setattr(mailcow_api, '_make_rw_request', rw)
    monkeypatch.setattr(mailcow_api, 'get_fail2ban', fail2ban)
    monkeypatch.setattr(mailcow_api, 'get_queue', queue)
    monkeypatch.setattr(mailcow_api, 'get_quarantine', quarantine)
    monkeypatch.setattr(mailcow_api, 'get_quarantine_details', details)
    return state


def _broken_database():
    class Broken:
        def __getattr__(self, name):
            raise RuntimeError('database gone')
    yield Broken()


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.mark.parametrize('path', STATS + ['/api/stats/flow?period=24h', '/api/stats/trends?names=storage_used',
                                          '/api/logs/netfilter/countries', '/api/logs/netfilter/overview',
                                          '/api/logs/netfilter/stats/by-country',
                                          '/api/logs/netfilter/stats/by-network', '/api/logs/netfilter'])
def test_reads_with_the_database(client, path):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    assert client.get(path).status_code == 200


@pytest.mark.parametrize('path', STATS)
def test_statistics_that_cannot_be_read_still_answer(client, path):
    app.dependency_overrides[get_db] = _broken_database
    response = client.get(path)
    assert response.status_code == 200 and 'error' in response.json()


def test_the_country_list_is_empty_when_it_cannot_be_read(client):
    app.dependency_overrides[get_db] = _broken_database
    assert client.get('/api/logs/netfilter/countries').json() == []


@pytest.mark.parametrize('path', DB_GETS)
def test_a_database_that_fails(client, path):
    app.dependency_overrides[get_db] = _broken_database
    assert client.get(path).status_code == 500


@pytest.mark.parametrize('path', BAD_PARAMS)
def test_bad_parameters(client, path):
    assert client.get(path).status_code == 422


def test_security_addresses_when_mailcow_fails(client, mailcow):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    mailcow['f2b'] = MailcowAPIError('down')
    assert client.get('/api/security/addresses').status_code == 502
    security_addresses.forget()
    app.dependency_overrides[get_db] = _broken_database
    mailcow['f2b'] = dict(F2B)
    assert client.get('/api/security/addresses').status_code == 500


def test_simple_reads(client, mailcow, monkeypatch):
    assert client.get('/api/rw-status').json().keys() == {'rw_configured'}
    monkeypatch.setattr(geoip_service, 'is_geoip_available', lambda: False)
    assert client.get('/api/geoip/192.0.2.1').json() == {'available': False}
    monkeypatch.setattr(geoip_service, 'is_geoip_available', lambda: True)
    monkeypatch.setattr(geoip_service, 'lookup_ip', lambda ip: {'country_code': 'DE', 'country_name': 'Germany',
                                                                'city': None, 'asn': 'AS3320', 'asn_org': 'DTAG'})
    assert client.get('/api/geoip/192.0.2.1').json()['country_code'] == 'DE'
    assert client.get('/api/fail2ban').json()['legacy_entries'][0]['address'] == '2001:db8::9'
    assert client.get('/api/queue').json()['total'] == 1
    assert client.get('/api/quarantine').json()['data'][0]['created'].endswith('Z')
    assert client.get('/api/quarantine/7/details').json()['score'] == 12.5


@pytest.mark.parametrize('error, status', [(MailcowAPIError('down'), 502), (RuntimeError('broken'), 500)])
def test_mailcow_reads_that_fail(client, mailcow, error, status):
    mailcow['f2b'] = error
    assert client.get('/api/fail2ban').status_code == status


@pytest.mark.parametrize('path', ['/api/queue', '/api/quarantine', '/api/quarantine/7/details'])
@pytest.mark.parametrize('error, status', [(MailcowAPIError('down'), 502), (RuntimeError('broken'), 500)])
def test_mailcow_lists_that_fail(client, monkeypatch, path, error, status):
    async def fail(*args, **kwargs):
        raise error
    for name in ('get_queue', 'get_quarantine', 'get_quarantine_details'):
        monkeypatch.setattr(mailcow_api, name, fail)
    assert client.get(path).status_code == status


@pytest.mark.parametrize('path', ITEM_ACTIONS)
def test_item_actions(client, mailcow, path):
    body = {'items': ['ABC'], 'action': 'hold'}
    assert client.post(path, json=body).json()['status'] == 'success'
    mailcow['answer'] = [{'type': 'danger', 'msg': ['access_denied']}]
    assert client.post(path, json=body).json()['status'] == 'error'
    mailcow['answer'] = {'unexpected': True}
    assert 'raw' in client.post(path, json=body).json()
    assert client.post(path, json={}).status_code == 400
    mailcow['answer'] = MailcowAPIError('down')
    assert client.post(path, json=body).status_code == 502
    mailcow['answer'] = RuntimeError('broken')
    assert client.post(path, json=body).status_code == 500


@pytest.mark.parametrize('path, body', LIST_CHANGES)
def test_fail2ban_changes(client, mailcow, path, body):
    assert client.post(path, json=body).status_code == 200
    # A body the call cannot use: no address, or for the settings not an object
    assert client.post(path, json=['x'] if path == '/api/fail2ban' else {'list': 'nope'}).status_code == 400
    mailcow['f2b'] = None
    assert client.post(path, json=body).status_code == 503
    mailcow['f2b'] = MailcowAPIError('down')
    assert client.post(path, json=body).status_code == 502
    mailcow['f2b'] = RuntimeError('broken')
    # Unban answers every other failure 502, the rest 500
    assert client.post(path, json=body).status_code == (502 if path.endswith('unban') else 500)


def test_fail2ban_settings_with_other_lists(client, mailcow):
    response = client.post('/api/fail2ban', json={'blacklist': '203.0.113.1'})
    assert response.status_code == 409 and response.json()['detail']['code'] == 'lists_changed'


def test_fail2ban_settings_mailcow_does_not_give(client, mailcow):
    mailcow['f2b'] = None
    assert client.get('/api/fail2ban').status_code == 503
