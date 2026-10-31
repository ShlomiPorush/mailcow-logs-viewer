"""Every answer the Suppressions calls can give, so the contract check (conftest.py,
contract.py) holds each one to /openapi.json: the list, its counts and settings,
entries made, changed and deleted with their block details, import and export, and
keeping the list in step with the app's section of the Rspamd map (sync, state,
load back, clear, start fresh). Also the list not kept (409), the map refused or
busy (409), mailcow not confirming a save or refusing the key (502), a database
that fails (500), and the requests the calls refuse (400, 403, 404, 422).

mailcow, its queue and the Rspamd map are faked; nothing leaves the test. The map
calls work on the whole list, so the list, its events and its spam_filter.*
settings are put back exactly as they were."""
import threading
import types
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy import null

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app import database  # noqa: E402
from app.config import settings  # noqa: E402
from app.database import get_db  # noqa: E402
from app.mailcow_api import MailcowAPIError, MailcowRwKeyError, mailcow_api  # noqa: E402
from app.main import app  # noqa: E402
from app.routers import suppressions  # noqa: E402
from app.services import rspamd_map_lock  # noqa: E402

MARK = uuid.uuid4().hex[:8]
RCPT = f'gone-{MARK}@example.net'
QUEUE_ID = f'Q{MARK.upper()}'
START, END = suppressions.MANAGED_MARKER_START, suppressions.MANAGED_MARKER_END


class _Broken:
    """A database session whose every query fails."""
    info = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def rollback(self):
        pass

    def close(self):
        pass

    def __getattr__(self, name):
        raise RuntimeError('database gone')


def _broken_session():
    yield _Broken()


@contextmanager
def _broken_context():
    yield _Broken()


def _postgres_available() -> bool:
    try:
        with database.engine.connect():
            return True
    except Exception:
        return False


def _section(*lines):
    return '\n'.join(['/^kept-by-hand@example\\.org$/i', '', START, '# Last sync: x', *lines, END])


@pytest.fixture
def env(monkeypatch):
    """Suppressions and Sync with Rspamd on, the Rspamd password and Read-Write key
    set; a fake mail queue and Rspamd map."""
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    state = {'feature': True, 'map': '', 'writes': 0, 'write_error': None, 'deleted': [],
             'queue': [{'queue_id': QUEUE_ID, 'sender': f'sales@{MARK}.example', 'arrival_time': 1700000000,
                        'recipients': [f'{RCPT} (host mx.example.net said: 550 5.1.1 no such user)']}]}
    real = type(settings._inner).is_feature_enabled
    monkeypatch.setattr(type(settings._inner), 'is_feature_enabled',
                        lambda self, name: state['feature'] if name == 'suppressions' else real(self, name))
    monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', True)
    monkeypatch.setattr(settings._inner, 'rspamd_password', 'test-password')
    monkeypatch.setattr(mailcow_api, 'headers_rw', {'X-API-Key': 'test-key'})

    async def queue():
        return state['queue']

    async def delete_queue(ids):
        state['deleted'].extend(ids)
        return [{'type': 'success', 'msg': ['item_deleted']}]

    async def find(filename):
        return 1

    async def read(map_id):
        return state['map']

    async def write(filename, content):
        if state['write_error']:
            raise state['write_error']
        state['map'] = content
        state['writes'] += 1
        return [{'type': 'success', 'msg': ['map_saved']}]

    monkeypatch.setattr(mailcow_api, 'get_queue', queue)
    monkeypatch.setattr(mailcow_api, 'delete_queue', delete_queue)
    monkeypatch.setattr(mailcow_api, 'find_rspamd_map_id', find)
    monkeypatch.setattr(mailcow_api, 'get_rspamd_map_content', read)
    monkeypatch.setattr(mailcow_api, 'edit_rspamd_map', write)
    monkeypatch.setattr(mailcow_api, 'aclose', AsyncMock())
    yield TestClient(app, raise_server_exceptions=False), state
    app.dependency_overrides.pop(get_db, None)


def _tables():
    from app.models import SpamSuppression, SuppressionEvent, SystemSetting
    settings_rows = SystemSetting.__table__
    return [(SpamSuppression.__table__, None), (SuppressionEvent.__table__, None),
            (settings_rows, settings_rows.c.key.like('spam_filter.%'))]


def _wipe(db):
    for table, where in reversed(_tables()):
        db.execute(table.delete() if where is None else table.delete().where(where))


@pytest.fixture
def whole_list(env):
    """The list starts empty and is put back as it was after the test: every entry,
    its events and the spam_filter.* settings (tombstones, aliases, the Rspamd
    target, the pending load), with their own ids. Postfix lines this test adds go."""
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.models import PostfixLog
    database.init_db()
    with database.get_db_context() as db:
        saved = [[dict(row._mapping) for row in db.execute(table.select() if where is None else table.select().where(where))]
                 for table, where in _tables()]
        _wipe(db)
        db.commit()
    yield
    with database.get_db_context() as db:
        _wipe(db)
        for (table, _), rows in zip(_tables(), saved):
            for row in rows:
                # SQL NULL, not JSON null, where a JSON column was empty
                db.execute(table.insert().values(**{key: null() if value is None else value
                                                    for key, value in row.items()}))
        db.query(PostfixLog).filter(PostfixLog.queue_id == QUEUE_ID).delete(synchronize_session=False)
        db.commit()


def _pending_load(value='1'):
    """Mark the app's Rspamd blocks as waiting to be loaded into the list."""
    from app.services.feature_data import SPAM_IMPORT_PENDING_KEY, _set_key
    with database.get_db_context() as db:
        _set_key(db, SPAM_IMPORT_PENDING_KEY, value)
        db.commit()


# ---------------------------------------------------------------- the list

def test_list_counts_and_settings(env, whole_list):
    c, _ = env
    assert c.post('/api/suppressions', json={'email': f'a-{MARK}@example.net'}).status_code == 200
    # Not permanent: expires after the base expiry, with the time left
    temporary = c.post('/api/suppressions', json={'email': f'b-{MARK}@example.net', 'permanent': False}).json()
    assert temporary['expires_in']['days'] >= 0
    page = c.get(f'/api/suppressions?search={MARK}&active_filter=true&sort_by=email&sort_dir=asc&per_page=1')
    assert page.json()['total'] == 2 and page.json()['total_pages'] == 2
    for bad in ('page=0', 'per_page=201', 'sort_by=nope', 'sort_dir=up'):
        assert c.get(f'/api/suppressions?{bad}').status_code == 422
    assert c.get('/api/suppressions/stats').json()['active'] == 2
    assert c.get('/api/suppressions/config').json()['list_kept'] is True


def test_entries_and_block_details(env, whole_list):
    from app.models import PostfixLog
    c, state = env
    now = datetime.utcnow()
    with database.get_db_context() as db:
        db.add(PostfixLog(time=now - timedelta(minutes=1), program='postfix/smtp', priority='info',
                          queue_id=QUEUE_ID, recipient=RCPT, status='deferred', dsn='4.4.1', created_at=now,
                          message=f'to=<{RCPT}>, status=deferred (connect to mx.example.net: timed out)'))
        db.commit()
    # Made from a queued message: its details stay with the block, and the message leaves the queue
    made = c.post('/api/suppressions', json={'email': RCPT, 'reason': 'hard_bounce', 'notes': 'From the queue',
                                             'queue_id': QUEUE_ID})
    assert made.status_code == 200 and state['deleted'] == [QUEUE_ID]
    entry_id = made.json()['id']
    details = c.get(f'/api/suppressions/{entry_id}/events').json()
    assert details['events'][0]['queue_id'] == QUEUE_ID and details['events'][0]['log_lines']

    duplicate = c.post('/api/suppressions', json={'email': RCPT})
    assert duplicate.status_code == 409 and isinstance(duplicate.json()['detail'], str)
    assert c.post('/api/suppressions', json={'email': f'c-{MARK}@example.net', 'permanent': False,
                                             'expires_at': 'soon'}).status_code == 400
    for body in ({'email': 'not an address@'}, {'email': RCPT, 'type': 'person'}, {'email': RCPT, 'reason': 'nope'}, {}):
        assert c.post('/api/suppressions', json=body).status_code == 422

    off = c.put(f'/api/suppressions/{entry_id}', json={'active': False, 'notes': 'Moved away',
                                                       'expires_at': '2099-01-01T00:00:00Z'})
    assert off.status_code == 200 and off.json()['active'] is False
    assert c.put(f'/api/suppressions/{entry_id}', json={'expires_at': 'soon'}).status_code == 400
    assert c.put('/api/suppressions/0', json={'active': True}).status_code == 404
    assert c.put('/api/suppressions/x', json={}).status_code == 422
    # Made again: the inactive entry comes back
    assert c.post('/api/suppressions', json={'email': RCPT}).json()['id'] == entry_id

    assert c.get(f'/api/suppressions/{entry_id}/events?page=2').json()['events'] == []
    assert c.get('/api/suppressions/0/events').status_code == 404
    assert c.get(f'/api/suppressions/{entry_id}/events?page=0').status_code == 422

    assert c.delete(f'/api/suppressions/{entry_id}').json()['needs_rspamd_sync'] is True
    assert c.delete(f'/api/suppressions/{entry_id}').status_code == 404
    assert c.delete('/api/suppressions/x').status_code == 422


def test_changes_are_refused_while_the_list_is_not_kept(env, whole_list, monkeypatch):
    c, state = env
    monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', False)
    refused = [c.post('/api/suppressions', json={'email': RCPT}),
               c.put('/api/suppressions/1', json={'active': False}),
               c.delete('/api/suppressions/1'),
               c.post('/api/suppressions/import', files={'file': ('list.csv', b'email\nx@example.net\n')})]
    assert [(r.status_code, r.json()['detail']['code']) for r in refused] == [(409, 'sync_off')] * 4
    # After a change on the page nothing is done; asked for, the sync is refused
    assert c.post('/api/suppressions/sync?after_change=true').json() == {
        'success': True, 'written': False, 'skipped_off': True}
    asked = c.post('/api/suppressions/sync')
    assert asked.status_code == 409 and asked.json()['detail']['code'] == 'sync_off'
    assert state['writes'] == 0


def test_import_and_export(env, whole_list, monkeypatch):
    c, _ = env
    csv = f'email,type,reason,notes\nd-{MARK}@example.net,email,manual,Imported\n,email,manual,x\n' \
          f'd-{MARK}@example.net,email,manual,Twice\n'.encode()
    answer = c.post('/api/suppressions/import', files={'file': ('list.csv', csv)}).json()
    assert (answer['imported'], answer['skipped'], len(answer['errors'])) == (1, 1, 1)
    assert c.post('/api/suppressions/import', files={'file': ('list.txt', csv)}).status_code == 400
    assert c.post('/api/suppressions/import').status_code == 422
    # A file that is not UTF-8 is refused before the list is locked
    def no_lock(db):
        raise AssertionError('the list is locked for a file that cannot be read')
    with monkeypatch.context() as patched:
        patched.setattr(suppressions, 'lock_suppression_rows', no_lock)
        not_utf8 = c.post('/api/suppressions/import', files={'file': ('list.csv', b'email\nj\xf6rg@example.net\n')})
    assert not_utf8.status_code == 400 and 'UTF-8' in not_utf8.json()['detail']
    export = c.get('/api/suppressions/export')
    assert export.status_code == 200 and export.headers['content-type'].startswith('text/csv')
    assert f'd-{MARK}@example.net' in export.text


# ---------------------------------------------------------------- Rspamd

def test_sync_and_state(env, whole_list, monkeypatch):
    c, state = env
    c.post('/api/suppressions', json={'email': RCPT})
    written = c.post('/api/suppressions/sync').json()
    assert written['written'] is True and written['added'] == 1 and state['writes'] == 1
    again = c.post('/api/suppressions/sync').json()
    assert again['written'] is False and again['skipped'] is True
    readable = c.get('/api/suppressions/rspamd/state?check_map=true').json()
    assert (readable['readable'], readable['managed_count'], readable['pending_count']) == (True, 1, 0)
    assert c.get('/api/suppressions/rspamd/state?check_map=x').status_code == 422
    assert c.post('/api/suppressions/sync?after_change=x').status_code == 422

    # Without the Read-Write key: after a change the map is only read; asked for, refused
    monkeypatch.setattr(mailcow_api, 'headers_rw', None)
    read_only = c.post('/api/suppressions/sync?after_change=true').json()
    assert read_only['skipped_off'] is True and 'pending_count' in read_only
    assert c.post('/api/suppressions/sync').status_code == 403
    assert c.get('/api/suppressions/rspamd/state').json()['reason'] == 'no_rw_key'
    monkeypatch.setattr(mailcow_api, 'headers_rw', {'X-API-Key': 'test-key'})

    # mailcow does not confirm the save, or refuses the key: the read already changed nothing
    c.post('/api/suppressions', json={'email': f'e-{MARK}@example.net'})
    state['write_error'] = MailcowAPIError('mailcow did not save the map')
    lost = c.post('/api/suppressions/sync')
    assert lost.status_code == 502 and lost.json()['detail']['code'] == 'not_confirmed'
    state['write_error'] = MailcowRwKeyError('rejected')
    assert c.post('/api/suppressions/sync').json()['detail']['code'] == 'rejected_rw_key'
    state['write_error'] = None

    # Markers that do not make one section: nothing is read in or written
    kept = state['map']
    state['map'] = f'{START}\n/^x@example\\.net$/i\n'
    unclear = c.post('/api/suppressions/sync')
    assert unclear.status_code == 409 and unclear.json()['detail']['code'] == 'section_unclear'
    assert c.get('/api/suppressions/rspamd/state').json()['reason'] == 'section_unclear'
    state['map'] = kept

    monkeypatch.setattr(settings._inner, 'rspamd_password', None)
    assert c.post('/api/suppressions/sync').status_code == 400
    monkeypatch.setattr(settings._inner, 'rspamd_password', 'test-password')


def test_clear_and_start_fresh(env, whole_list, monkeypatch):
    c, state = env
    # Only while the list is not kept
    for path in ('/api/suppressions/rspamd/clear', '/api/suppressions/start-fresh'):
        refused = c.post(path)
        assert refused.status_code == 409 and refused.json()['detail']['code'] == 'sync_on'
    monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', False)
    state['map'] = _section(f'/^old-{MARK}@example\\.net$/i')
    assert c.post('/api/suppressions/rspamd/clear', json={'transition': 'another-save'}).json()['detail']['code'] \
        == 'transition_changed'
    assert c.post('/api/suppressions/rspamd/clear', json={'transition': 5}).status_code == 422
    state['write_error'] = MailcowAPIError('no answer')
    assert c.post('/api/suppressions/rspamd/clear').status_code == 502
    assert c.post('/api/suppressions/start-fresh').status_code == 502
    state['write_error'] = None
    assert c.post('/api/suppressions/rspamd/clear').json() == {'removed_blocks': 1}
    assert 'kept-by-hand' in state['map'], 'lines outside the section stay'

    state['map'] = _section(f'/^old-{MARK}@example\\.net$/i')
    with database.get_db_context() as db:
        from app.models import SpamSuppression
        db.add(SpamSuppression(email=f'f-{MARK}@example.net', type='email', reason='manual', source='manual',
                               active=True, synced_to_rspamd=True, bounce_count=0, hard_bounce_count=0,
                               soft_bounce_count=0))
        db.commit()
    assert c.post('/api/suppressions/start-fresh').json() == {'removed_blocks': 1, 'deleted_entries': 1}


def test_load_back_from_rspamd(env, whole_list, monkeypatch):
    c, state = env
    assert c.post('/api/suppressions/rspamd/import').json() == {'imported': 0, 'pending': False, 'loaded': False}
    _pending_load()
    state['map'] = _section(f'/^back-{MARK}@example\\.net$/i')
    assert c.post('/api/suppressions/rspamd/import').json() == {'imported': 1, 'pending': False, 'loaded': True}

    state['feature'] = False
    assert c.post('/api/suppressions/rspamd/import').json()['feature_off'] is True
    state['feature'] = True
    monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', False)
    assert c.post('/api/suppressions/rspamd/import').json()['sync_off'] is True
    monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', True)
    _pending_load()
    monkeypatch.setattr(settings._inner, 'rspamd_password', None)
    assert c.post('/api/suppressions/rspamd/import').json()['reason'] == 'no_password'
    monkeypatch.setattr(settings._inner, 'rspamd_password', 'test-password')

    state['map'] = f'{START}\n'
    unclear = c.post('/api/suppressions/rspamd/import')
    assert unclear.status_code == 409 and unclear.json()['detail']['code'] == 'section_unclear'

    # Another map write still running
    monkeypatch.setattr(rspamd_map_lock, 'WAIT_SECONDS', 0.05)
    holder_has_it, done = threading.Event(), threading.Event()

    def hold():
        with rspamd_map_lock.map_write_lock():
            holder_has_it.set()
            done.wait(10)

    holder = threading.Thread(target=hold)
    holder.start()
    try:
        assert holder_has_it.wait(10)
        busy = c.post('/api/suppressions/rspamd/import')
        assert busy.status_code == 409 and busy.json()['detail']['code'] == 'busy'
    finally:
        done.set()
        holder.join(10)


def test_rspamd_answers_a_page_in_place_of_its_map_list(env, whole_list, monkeypatch):
    """Through mailcow's own lookup of the map: the page is a map that cannot be
    read (409 read_failed), and nothing is written."""
    c, state = env
    monkeypatch.setattr(mailcow_api, 'find_rspamd_map_id',
                        types.MethodType(type(mailcow_api).find_rspamd_map_id, mailcow_api))

    async def page(endpoint, *args, **kwargs):
        return httpx.Response(200, text='<html>Sign in</html>', headers={'content-type': 'text/html'})

    monkeypatch.setattr(mailcow_api, '_make_rspamd_request', page)
    seen = c.get('/api/suppressions/rspamd/state?check_map=true').json()
    assert (seen['readable'], seen['reason']) == (False, 'read_failed')
    _pending_load()
    for path in ('/api/suppressions/sync', '/api/suppressions/rspamd/import'):
        refused = c.post(path)
        assert refused.status_code == 409 and refused.json()['detail']['code'] == 'read_failed', path
    monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', False)
    for path in ('/api/suppressions/rspamd/clear', '/api/suppressions/start-fresh'):
        refused = c.post(path)
        assert refused.status_code == 409 and refused.json()['detail']['code'] == 'read_failed', path
    assert state['writes'] == 0


# ---------------------------------------------------------------- a database that fails

def test_suppressions_when_the_database_fails(env, monkeypatch):
    c, _ = env
    app.dependency_overrides[get_db] = _broken_session
    for path in ('/api/suppressions', '/api/suppressions/stats', '/api/suppressions/1/events',
                 '/api/suppressions/export'):
        assert c.get(path).status_code == 500, path
    assert c.put('/api/suppressions/1', json={'active': False}).status_code == 500
    assert c.delete('/api/suppressions/1').status_code == 500
    # Making and importing open sessions of their own
    monkeypatch.setattr(suppressions, 'SessionLocal', _Broken)
    assert c.post('/api/suppressions', json={'email': RCPT}).status_code == 500
    assert c.post('/api/suppressions/import', files={'file': ('list.csv', b'email\nx@example.net\n')}).status_code == 500
    # The map calls too
    monkeypatch.setattr(suppressions, 'get_db_context', _broken_context)
    assert c.get('/api/suppressions/rspamd/state').status_code == 500
    assert c.post('/api/suppressions/sync').status_code == 500
    assert c.post('/api/suppressions/rspamd/import').status_code == 500
    monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', False)
    assert c.post('/api/suppressions/rspamd/clear').status_code == 500
    assert c.post('/api/suppressions/start-fresh').status_code == 500


@pytest.mark.parametrize('arrived', [1e20, -1e20, float('inf'), 'yesterday'])
@pytest.mark.asyncio
async def test_a_queued_message_with_a_time_mailcow_cannot_mean_keeps_its_details(monkeypatch, arrived):
    async def queue():
        return [{'queue_id': QUEUE_ID, 'sender': f'sales@{MARK}.example', 'arrival_time': arrived,
                 'recipients': [f'{RCPT} (host mx.example.net said: 550 5.1.1 no such user)']}]

    monkeypatch.setattr(mailcow_api, 'get_queue', queue)
    found = await suppressions._queued_message(QUEUE_ID, RCPT)
    assert found['queue_id'] == QUEUE_ID and found['reason'] and found['arrived'] is None
