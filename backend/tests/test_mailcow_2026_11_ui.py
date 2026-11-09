"""What mailcow 2026-11 added that the app shows: a mailbox whose login is
disabled (active 2, its mail still delivered), a shared mailbox, and Unban all
for Fail2ban's bans. Older mailcow versions send active 0 or 1 and no shared
attribute, and know only the "unban" action, which Unban all uses."""
import importlib.util
import uuid
from pathlib import Path

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient

from app.mailcow_api import MailcowAPIError, MailcowRwKeyError, mailbox_shared, mailbox_state, mailcow_api

DOMAIN = f'mc2611-{uuid.uuid4().hex[:8]}.example'


def _client():
    from app.main import app
    return TestClient(app)


# ---------- the mailbox state mailcow reports ----------

@pytest.mark.parametrize('value, state', [
    (1, (True, False)), ('1', (True, False)),
    (2, (True, True)), ('2', (True, True)), (' 2 ', (True, True)),
    (0, (False, False)), ('0', (False, False)), (None, (False, False)), ('x', (False, False)),
])
def test_a_mailbox_with_its_login_disabled_is_active(value, state):
    assert mailbox_state({'active': value}) == state


def test_a_mailbox_without_the_field_is_active():
    assert mailbox_state({}) == (True, False)


@pytest.mark.parametrize('attributes, shared', [
    ({'shared': '1'}, True), ({'shared': 1}, True), ({'shared': '0'}, False),
    ({}, False), (None, False), ('shared', False), ({'shared': None}, False),
])
def test_a_shared_mailbox_is_the_attribute_mailcow_sets(attributes, shared):
    assert mailbox_shared(attributes) is shared


# ---------- the mailbox sync ----------

def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import MailboxStatistics
    with get_db_context() as session:
        session.query(MailboxStatistics).filter(MailboxStatistics.domain == DOMAIN).delete(synchronize_session=False)
        session.commit()


@pytest.fixture()
def db():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import get_db_context, init_db
    import app.models  # noqa: F401  (the tables init_db creates)
    init_db()
    _cleanup()
    with get_db_context() as session:
        yield session
    _cleanup()


def _mailbox(name, active, **attributes):
    return {'username': f'{name}@{DOMAIN}', 'domain': DOMAIN, 'active': active,
            'attributes': {'imap_access': '1', **attributes}}


def _stored(session):
    from app.models import MailboxStatistics
    session.expire_all()
    rows = session.query(MailboxStatistics).filter(MailboxStatistics.domain == DOMAIN).all()
    return {r.username.split('@')[0]: (r.active, r.login_disabled) for r in rows}


def test_the_sync_keeps_the_login_disabled_state(db):
    from app.scheduler import _store_mailbox_statistics
    _store_mailbox_statistics([_mailbox('on', 1), _mailbox('off', 0), _mailbox('nologin', 2),
                               _mailbox('nologin-text', '2'), _mailbox('shared', 1, shared='1')])
    assert _stored(db) == {'on': (True, False), 'off': (False, False), 'nologin': (True, True),
                           'nologin-text': (True, True), 'shared': (True, False)}

    # mailcow turns the login back on, or turns the mailbox off
    _store_mailbox_statistics([_mailbox('on', 2), _mailbox('off', 0), _mailbox('nologin', 1),
                               _mailbox('nologin-text', 0), _mailbox('shared', 1, shared='1')])
    assert _stored(db) == {'on': (True, True), 'off': (False, False), 'nologin': (True, False),
                           'nologin-text': (False, False), 'shared': (True, False)}


def test_the_lists_and_the_card_tell_login_disabled_and_shared(db):
    from app.scheduler import _store_mailbox_statistics
    from app.services.entity_summary import _mailbox as card_mailbox
    _store_mailbox_statistics([_mailbox('nologin', 2), _mailbox('shared', 1, shared='1')])

    res = _client().get('/api/mailbox-stats/all', params={'search': DOMAIN, 'active_only': 'true'})
    assert res.status_code == 200, res.text
    shown = {m['username'].split('@')[0]: (m['login_disabled'], m['attributes'].get('shared'))
             for m in res.json()['mailboxes']}
    assert shown == {'nologin': (True, None), 'shared': (False, '1')}

    assert card_mailbox(db, f'nologin@{DOMAIN}')['mailbox'] == {
        'username': f'nologin@{DOMAIN}', 'name': '', 'domain': DOMAIN, 'active': True,
        'login_disabled': True, 'shared': False}
    assert card_mailbox(db, f'shared@{DOMAIN}')['mailbox']['shared'] is True


def test_status_counts_a_mailbox_with_its_login_disabled_as_active(monkeypatch):
    async def domains():
        return []

    async def mailboxes():
        return [{'active': 1}, {'active': 2}, {'active': '2'}, {'active': 0}]

    async def aliases():
        return []

    monkeypatch.setattr(mailcow_api, 'get_domains', domains)
    monkeypatch.setattr(mailcow_api, 'get_mailboxes', mailboxes)
    monkeypatch.setattr(mailcow_api, 'get_aliases', aliases)
    res = _client().get('/api/status/mailcow-info')
    assert res.status_code == 200, res.text
    assert res.json()['mailboxes'] == {'total': 4, 'active': 3}


# ---------- the upgrade ----------

def _migration():
    path = next((Path(__file__).resolve().parents[1] / 'alembic' / 'versions').glob('*_mailbox_login_disabled.py'))
    spec = importlib.util.spec_from_file_location('mailbox_login_disabled', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_upgrade_adds_the_column_false_for_stored_mailboxes(db):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy import inspect, text
    from app.database import engine
    from app.scheduler import _store_mailbox_statistics
    _store_mailbox_statistics([_mailbox('before', 2)])
    db.commit()
    db.close()

    def run(step):
        with engine.begin() as connection:
            with Operations.context(MigrationContext.configure(connection)):
                step()

    try:
        run(_migration().downgrade)
        assert 'login_disabled' not in {c['name'] for c in inspect(engine).get_columns('mailbox_statistics')}
    finally:
        run(_migration().upgrade)
        # A second run (the fresh-install start made the column already) changes nothing
        run(_migration().upgrade)
    with engine.connect() as connection:
        assert connection.execute(text('SELECT login_disabled FROM mailbox_statistics WHERE username = :u'),
                                  {'u': f'before@{DOMAIN}'}).scalar() is False


# ---------- Unban all ----------

def _ban(network, queued=0):
    return {'network': network, 'ip': network.split('/')[0], 'banned_until': '00h 20m 00s', 'queued_for_unban': queued}


def _done(network):
    return {'type': 'success', 'msg': ['object_modified', network]}


@pytest.fixture()
def mailcow(monkeypatch):
    """A mailcow with the given Fail2ban answer and unban reply; records every Read-Write call."""
    state = {'f2b': {'netban_ipv4': 32, 'netban_ipv6': 128, 'blacklist': '', 'whitelist': '',
                     'active_bans': [], 'perm_bans': []},
             'reply': None, 'calls': []}

    async def fake_get():
        return state['f2b']

    async def fake_rw(endpoint, method='POST', **kwargs):
        body = kwargs.get('json')
        state['calls'].append((endpoint, body))
        return state['reply'] if state['reply'] is not None else [_done(n) for n in body['items']]

    monkeypatch.setattr(mailcow_api, 'get_fail2ban', fake_get)
    monkeypatch.setattr(mailcow_api, '_make_rw_request', fake_rw)
    return state


def test_unban_all_lifts_fail2bans_bans_in_one_unban(mailcow):
    mailcow['f2b'].update(
        active_bans=[_ban('198.51.100.7/32'), _ban('2001:db8::/64'), _ban('198.51.100.7/32'),
                     _ban('203.0.113.9/32', queued=1), _ban('203.0.113.10/32', queued='1'),
                     _ban('192.0.2.66/32'), _ban('not a network'), 'junk', {'ip': '192.0.2.1'}],
        # A permanent ban is the denylist's: it stays
        perm_bans=[{'network': '192.0.2.66/32', 'ip': '192.0.2.66'}])
    res = _client().post('/api/fail2ban/unban-all')
    assert res.status_code == 200
    assert res.json() == {'status': 'success', 'msg': 'Fail2ban is lifting 2 bans',
                          'networks': ['198.51.100.7/32', '2001:db8::/64']}
    assert mailcow['calls'] == [('/api/v1/edit/fail2ban',
                                 {'items': ['198.51.100.7/32', '2001:db8::/64'], 'attr': {'action': 'unban'}})]


def test_unban_all_with_nothing_banned_sends_nothing(mailcow):
    mailcow['f2b'].update(active_bans=[_ban('203.0.113.9/32', queued=1)])
    assert _client().post('/api/fail2ban/unban-all').json() == {'status': 'error', 'msg': 'Nothing is banned by Fail2ban now'}
    assert mailcow['calls'] == []


@pytest.mark.parametrize('answer', [None, {'type': 'danger', 'msg': 'redis_error'}, [], 'x'])
def test_unban_all_without_the_bans_known_says_so(mailcow, answer):
    mailcow['f2b'] = answer
    res = _client().post('/api/fail2ban/unban-all')
    assert res.status_code == 503
    assert mailcow['calls'] == []


def test_unban_all_reports_the_bans_mailcow_did_not_take(mailcow):
    mailcow['f2b']['active_bans'] = [_ban('198.51.100.1/32'), _ban('198.51.100.2/32'), _ban('198.51.100.3/32')]
    mailcow['reply'] = [_done('198.51.100.1/32'), {'type': 'danger', 'msg': ['redis_error', 'gone']},
                        _done('198.51.100.3/32')]
    res = _client().post('/api/fail2ban/unban-all').json()
    assert res['status'] == 'error'
    assert res['networks'] == ['198.51.100.1/32', '198.51.100.3/32']
    assert '2 of 3' in res['msg']


@pytest.mark.parametrize('reply', [[{'type': 'danger', 'msg': ['redis_error', 'gone']}], [], {'unexpected': True}])
def test_unban_all_that_mailcow_refuses_is_not_success(mailcow, reply):
    mailcow['f2b']['active_bans'] = [_ban('198.51.100.1/32')]
    mailcow['reply'] = reply
    res = _client().post('/api/fail2ban/unban-all').json()
    assert res['status'] == 'error' and 'networks' not in res


def test_unban_all_without_the_read_write_key_says_what_to_fix(mailcow, monkeypatch):
    mailcow['f2b']['active_bans'] = [_ban('198.51.100.1/32')]

    async def read_only(networks):
        raise MailcowRwKeyError('read_only')

    monkeypatch.setattr(mailcow_api, 'unban_fail2ban', read_only)
    res = _client().post('/api/fail2ban/unban-all')
    assert res.status_code >= 400 and 'Read-Write Access' in res.text


def test_unban_all_mailcow_does_not_answer_is_an_error(mailcow, monkeypatch):
    mailcow['f2b']['active_bans'] = [_ban('198.51.100.1/32')]

    async def failed(networks):
        raise MailcowAPIError('RW API request failed with status 500')

    monkeypatch.setattr(mailcow_api, 'unban_fail2ban', failed)
    res = _client().post('/api/fail2ban/unban-all')
    assert res.status_code == 502 and 'unban' in res.json()['detail']


def test_a_single_unban_without_the_bans_known_says_so(mailcow):
    mailcow['f2b'] = {'type': 'danger', 'msg': 'redis_error'}
    res = _client().post('/api/fail2ban/unban', json={'ip': '198.51.100.7'})
    assert res.status_code == 503
    assert mailcow['calls'] == []


def test_unban_all_is_a_security_write():
    from app.agent_access.scopes import POLICY, WRITE
    rule = POLICY[('POST', '/api/fail2ban/unban-all')]
    assert (rule.area, rule.kind) == ('security', WRITE)
