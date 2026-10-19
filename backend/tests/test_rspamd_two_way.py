"""The list and the app's section of the Rspamd map, kept in step both ways.

mailcow is the source: a block deleted in the app's section leaves the list,
one added there joins it as From Rspamd. The list's own changes wait for Sync
to Rspamd while automatic updates are off, and a write applies only them to
what mailcow has now. Fictional addresses only.
"""
import asyncio
import threading
import time
import uuid
from datetime import datetime, timedelta
from unittest.mock import AsyncMock

import pytest

import app.models  # noqa: F401  init_db creates the tables of the models imported so far
from app.config import settings

MARK = uuid.uuid4().hex[:6]


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _automatic(monkeypatch, on: bool):
    monkeypatch.setattr(settings._inner, 'suppression_enabled', True)
    monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', on)


@pytest.fixture
def db(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import SpamSuppression, SystemSetting
    init_db()
    monkeypatch.setattr(type(settings._inner), 'is_feature_enabled', lambda self, name: True)
    monkeypatch.setattr(type(settings._inner), 'is_rspamd_configured', property(lambda self: True))
    _automatic(monkeypatch, False)

    def wipe():
        with get_db_context() as s:
            s.query(SpamSuppression).delete(synchronize_session=False)
            s.query(SystemSetting).filter(SystemSetting.key.like('spam_filter.%')).delete(synchronize_session=False)
            s.commit()

    wipe()
    yield get_db_context
    wipe()


@pytest.fixture
def rspamd(monkeypatch):
    """A fake map. read_hook(n) may change what the n-th read returns;
    write_hook(content) runs before a save lands; fail_write makes the save
    raise (after landing when land_then_fail)."""
    from app.routers import suppressions as sup
    state = {'content': '', 'writes': 0, 'reads': 0, 'read_hook': None, 'write_hook': None,
             'fail_write': False, 'land_then_fail': False}

    async def find(filename):
        return 1

    async def read(map_id):
        state['reads'] += 1
        if state['read_hook']:
            return state['read_hook'](state['reads'])
        return state['content']

    async def write(filename, content):
        if state['write_hook']:
            state['write_hook'](content)
        if state['fail_write'] and not state['land_then_fail']:
            raise sup.MailcowAPIError('mailcow did not save the map')
        state['content'] = content
        state['writes'] += 1
        if state['fail_write']:
            raise sup.MailcowAPIError('no answer')
        return [{'type': 'success'}]

    monkeypatch.setattr(sup.mailcow_api, 'find_rspamd_map_id', find)
    monkeypatch.setattr(sup.mailcow_api, 'get_rspamd_map_content', read)
    monkeypatch.setattr(sup.mailcow_api, 'edit_rspamd_map', write)
    monkeypatch.setattr(sup.mailcow_api, 'aclose', AsyncMock())
    monkeypatch.setattr(sup.mailcow_api, 'headers_rw', {'X-API-Key': 'test-key'})
    return state


def _section(*lines, above=('/^mine@example\\.test$/i',)):
    from app.routers.suppressions import MANAGED_MARKER_START, MANAGED_MARKER_END
    return '\n'.join(list(above) + ['', MANAGED_MARKER_START, '# Last sync: x'] + list(lines) + [MANAGED_MARKER_END])


def _line(value, source='manual'):
    from app.routers.suppressions import format_suppression_map_entry, suppression_allows_regex
    return format_suppression_map_entry(value, allow_regex=suppression_allows_regex(source))


def _add(db, email, active=True, synced=True, source='manual', expires_at=None):
    from app.models import SpamSuppression
    with db() as s:
        s.add(SpamSuppression(email=email, type='email', reason='manual', source=source, active=active,
                              synced_to_rspamd=synced, expires_at=expires_at, bounce_count=0,
                              hard_bounce_count=0, soft_bounce_count=0))
        s.commit()


def _rows(db):
    from app.models import SpamSuppression
    with db() as s:
        return {r.email: (r.active, r.synced_to_rspamd, r.source, r.expires_at) for r in s.query(SpamSuppression).all()}


def _managed(state):
    from app.routers.suppressions import split_managed_section
    return split_managed_section(state['content'])[1]


def _sync(automatic):
    from app.routers.suppressions import sync_suppressions_worker
    return sync_suppressions_worker(automatic)


def _key(db, key):
    from app.models import SystemSetting
    with db() as s:
        row = s.query(SystemSetting).filter(SystemSetting.key == key).first()
        return row.value if row else None


# ---- What comes in from mailcow ----

def test_a_block_deleted_in_mailcow_leaves_the_list_and_one_added_there_joins_it(db, rspamd):
    """The case on DEV: one address deleted in mailcow, one added there."""
    kept, gone, new = f'kept-{MARK}@example.test', f'"gone"-{MARK}@example.test', f's.new-{MARK}@example.test'
    _add(db, kept)
    _add(db, gone)
    rspamd['content'] = _section(_line(kept), _line(new))
    result = _sync(automatic=True)
    rows = _rows(db)
    assert gone not in rows
    assert rows[new][:3] == (True, True, 'rspamd') and rows[new][3] is None, 'permanent, From Rspamd'
    assert rows[kept][:2] == (True, True)
    assert (result['list_added'], result['list_removed']) == (1, 1)
    assert rspamd['writes'] == 0, 'automatic updates are off: nothing is written'
    from app.models import SpamSuppression, SuppressionEvent
    with db() as s:
        row = s.query(SpamSuppression).filter(SpamSuppression.email == new).one()
        assert [e.kind for e in s.query(SuppressionEvent).filter(SuppressionEvent.suppression_id == row.id)] == ['added_in_rspamd']


def test_a_block_waiting_to_be_added_is_not_taken_for_deleted(db, rspamd):
    waiting = f'waiting-{MARK}@example.test'
    _add(db, waiting, synced=False)
    rspamd['content'] = _section()
    _sync(automatic=True)
    assert _rows(db)[waiting][:2] == (True, False)


def test_a_disabled_block_still_in_rspamd_waits_to_be_removed(db, rspamd):
    off = f'off-{MARK}@example.test'
    _add(db, off, active=False, synced=False)
    rspamd['content'] = _section(_line(off))
    _sync(automatic=True)
    assert _rows(db)[off][:2] == (False, False), 'not taken for added in mailcow'


def test_a_block_the_list_holds_as_gone_that_is_back_in_mailcow_is_added_there(db, rspamd):
    expired = f'expired-{MARK}@example.test'
    _add(db, expired, active=False, synced=True, source='auto', expires_at=datetime.utcnow() - timedelta(days=1))
    rspamd['content'] = _section(_line(expired, 'auto'))
    _sync(automatic=True)
    active, synced, source, expires_at = _rows(db)[expired]
    assert (active, synced, source, expires_at) == (True, True, 'rspamd', None)


def test_a_removal_that_landed_is_taken_as_done(db, rspamd):
    off = f'off-{MARK}@example.test'
    _add(db, off, active=False, synced=False)
    rspamd['content'] = _section()
    _sync(automatic=True)
    assert _rows(db)[off][:2] == (False, True)


# ---- What the list writes ----

def test_a_write_applies_only_the_lists_changes_to_what_mailcow_has(db, rspamd):
    keep, add, off = (f'{n}-{MARK}@example.test' for n in ('keep', 'add', 'off'))
    typed = f'typed-{MARK}@example.test'
    _add(db, keep)
    _add(db, add, synced=False)
    _add(db, off, active=False, synced=False)
    rspamd['content'] = _section(_line(keep), _line(off), _line(typed))
    result = _sync(automatic=False)
    managed = _managed(rspamd)
    assert set(managed) == {_line(keep), _line(add), _line(typed)}
    assert rspamd['content'].startswith('/^mine@example\\.test$/i'), 'lines above the section stay'
    rows = _rows(db)
    assert all(rows[e][1] for e in (keep, add, off, typed))
    assert (result['added'], result['removed'], result['list_added']) == (1, 1, 1)


def test_page_changes_wait_while_automatic_updates_are_off(db, rspamd, monkeypatch):
    from app.routers.suppressions import manual_sync_to_rspamd
    add = f'add-{MARK}@example.test'
    _add(db, add, synced=False)
    rspamd['content'] = _section()
    monkeypatch.setattr(__import__('app.routers.suppressions', fromlist=['x']).mailcow_api, 'headers_rw', None)
    result = asyncio.run(manual_sync_to_rspamd(after_change=True))
    assert result['written'] is False and result['pending_count'] == 1 and rspamd['writes'] == 0
    _automatic(monkeypatch, True)
    monkeypatch.setattr(__import__('app.routers.suppressions', fromlist=['x']).mailcow_api, 'headers_rw', {'X-API-Key': 'k'})
    result = asyncio.run(manual_sync_to_rspamd(after_change=True))
    assert result['written'] is True and _managed(rspamd) == [_line(add)]


def test_a_deleted_block_is_removed_from_rspamd_and_not_read_back(db, rspamd):
    from app.routers.suppressions import TOMBSTONES_KEY, delete_suppression
    from app.models import SpamSuppression
    gone = f'gone-{MARK}@example.test'
    _add(db, gone)
    rspamd['content'] = _section(_line(gone))
    with db() as s:
        delete_suppression(s.query(SpamSuppression).filter(SpamSuppression.email == gone).one().id, s)
    assert _line(gone) in __import__('json').loads(_key(db, TOMBSTONES_KEY))
    _sync(automatic=True)
    assert gone not in _rows(db), 'its line waits to be removed; it is not read back as added'
    _sync(automatic=False)
    assert _managed(rspamd) == [] and _key(db, TOMBSTONES_KEY) is None


def test_a_tombstone_goes_when_mailcow_no_longer_has_the_line(db, rspamd):
    from app.routers.suppressions import TOMBSTONES_KEY, delete_suppression
    from app.models import SpamSuppression
    gone = f'gone-{MARK}@example.test'
    _add(db, gone)
    rspamd['content'] = _section(_line(gone))
    with db() as s:
        delete_suppression(s.query(SpamSuppression).filter(SpamSuppression.email == gone).one().id, s)
    rspamd['content'] = _section()
    _sync(automatic=True)
    assert _key(db, TOMBSTONES_KEY) is None


# ---- A write whose answer was lost ----

@pytest.mark.parametrize('landed', [True, False])
def test_a_write_without_an_answer_is_put_right_by_the_next_read(db, rspamd, landed):
    from app.routers.suppressions import MailcowAPIError
    add, off = f'add-{MARK}@example.test', f'off-{MARK}@example.test'
    _add(db, add, synced=False)
    _add(db, off, active=False, synced=False)
    rspamd['content'] = _section(_line(off))
    rspamd.update(fail_write=True, land_then_fail=landed)
    with pytest.raises(MailcowAPIError):
        _sync(automatic=False)
    assert _rows(db)[add][:2] == (True, False), 'nothing is marked without an answer'
    rspamd['fail_write'] = False
    _sync(automatic=True)
    rows = _rows(db)
    assert add in rows and off in rows, 'nothing is taken for deleted'
    if landed:
        assert rows[add][:2] == (True, True) and rows[off][:2] == (False, True)
    else:
        assert rows[add][:2] == (True, False) and rows[off][:2] == (False, False)


def test_clearing_whose_answer_was_lost_never_empties_the_list(db, rspamd):
    from app.routers.suppressions import MailcowAPIError, clear_managed_worker
    kept = f'kept-{MARK}@example.test'
    _add(db, kept)
    rspamd['content'] = _section(_line(kept))
    rspamd.update(fail_write=True, land_then_fail=True)
    with pytest.raises(MailcowAPIError):
        clear_managed_worker()
    rspamd['fail_write'] = False
    _sync(automatic=True)
    assert _rows(db)[kept][:2] == (True, False), 'waits to be added again, not deleted'


def test_a_row_changed_during_the_write_keeps_waiting(db, rspamd):
    from app.models import SpamSuppression
    changed = f'changed-{MARK}@example.test'
    _add(db, changed, synced=False)
    rspamd['content'] = _section()

    def disable_meanwhile(content):
        with db() as s:
            s.query(SpamSuppression).filter(SpamSuppression.email == changed).update(
                {SpamSuppression.active: False, SpamSuppression.synced_to_rspamd: False}, synchronize_session=False)
            s.commit()

    rspamd['write_hook'] = disable_meanwhile
    _sync(automatic=False)
    assert _rows(db)[changed][:2] == (False, False), 'written while active, disabled since: its removal waits'


# ---- Lines as earlier versions wrote them, and lines typed in mailcow ----

def test_a_domain_line_as_version_2_9_wrote_it_is_the_same_block(db, rspamd):
    domain = f'/.+@{MARK}\\.example\\.test/i'
    _add(db, domain)
    rspamd['content'] = _section(f'/^.+@{MARK}\\.example\\.test$/i')
    _sync(automatic=True)
    assert list(_rows(db)) == [domain], 'not deleted, not read in twice'
    _sync(automatic=False)
    assert _managed(rspamd) == [_line(domain)], 'written again in the current form'


def test_a_literal_shaped_like_a_pattern_never_becomes_one(db, rspamd):
    from app.routers.suppressions import MapUnavailable
    auto = '/.*|' + MARK + '@example.test/i'
    _add(db, auto, source='auto')
    rspamd['content'] = _section(_line(auto, 'auto'))
    _sync(automatic=False)
    assert _managed(rspamd) == [_line(auto, 'auto')] and _line(auto, 'auto').startswith('/^/'), 'kept as written'
    # The same line added in mailcow for a value no row has cannot be held as written
    stray = _line('/.*|other-' + MARK + '@example.test/i', 'auto')
    rspamd['content'] = _section(_line(auto, 'auto'), stray)
    before = _rows(db)
    with pytest.raises(MapUnavailable) as error:
        _sync(automatic=True)
    assert error.value.code == 'import_failed' and _rows(db) == before


def test_an_address_typed_in_the_section_becomes_an_exact_block_and_stays(db, rspamd):
    from app.routers.suppressions import ALIASES_KEY
    rspamd['content'] = _section(f'Typed-{MARK}@Example.test')
    _sync(automatic=True)
    _sync(automatic=True)
    rows = _rows(db)
    assert rows == {f'typed-{MARK}@example.test': (True, True, 'rspamd', None)}, 'read in once, not taken for deleted'
    assert _key(db, ALIASES_KEY)
    _sync(automatic=False)
    assert _managed(rspamd) == [_line(f'typed-{MARK}@example.test')] and _key(db, ALIASES_KEY) is None
    _sync(automatic=True)
    assert list(_rows(db)) == [f'typed-{MARK}@example.test']


# ---- A map that cannot be trusted changes nothing ----

@pytest.mark.parametrize('content', [
    'START\n/^a@example\\.test$/i\nSTART\nEND',
    '/^a@example\\.test$/i\nEND',
    'START\n/^a@example\\.test$/i',
    'END\nSTART',
])
def test_unclear_markers_change_nothing(db, rspamd, content):
    from app.routers.suppressions import MANAGED_MARKER_END, MANAGED_MARKER_START, MapUnavailable
    kept = f'kept-{MARK}@example.test'
    _add(db, kept)
    rspamd['content'] = content.replace('START', MANAGED_MARKER_START).replace('END', MANAGED_MARKER_END)
    with pytest.raises(MapUnavailable) as error:
        _sync(automatic=False)
    assert error.value.code == 'section_unclear'
    assert kept in _rows(db) and rspamd['writes'] == 0


def test_a_map_without_the_section_deletes_nothing(db, rspamd):
    from app.routers.suppressions import MapUnavailable
    kept = f'kept-{MARK}@example.test'
    _add(db, kept)
    rspamd['content'] = '/^mine@example\\.test$/i'
    with pytest.raises(MapUnavailable) as error:
        _sync(automatic=False)
    assert error.value.code == 'section_missing' and kept in _rows(db) and rspamd['writes'] == 0


def test_a_map_that_reads_differently_twice_deletes_nothing(db, rspamd):
    from app.routers.suppressions import MapUnavailable
    kept = f'kept-{MARK}@example.test'
    _add(db, kept)
    first = _section()
    rspamd['read_hook'] = lambda n: first if n == 1 else _section(_line(kept))
    with pytest.raises(MapUnavailable) as error:
        _sync(automatic=True)
    assert error.value.code == 'map_changed' and kept in _rows(db)


def test_a_map_changed_before_the_save_is_not_written_over(db, rspamd):
    from app.routers.suppressions import MapUnavailable
    add = f'add-{MARK}@example.test'
    _add(db, add, synced=False)
    first, typed = _section(), _section(_line(f'typed-{MARK}@example.test'))
    rspamd['read_hook'] = lambda n: first if n == 1 else typed
    with pytest.raises(MapUnavailable) as error:
        _sync(automatic=False)
    assert error.value.code == 'map_changed' and rspamd['writes'] == 0


def test_an_automatic_write_stops_when_updates_go_off_before_the_save(db, rspamd, monkeypatch):
    from app.routers import suppressions as sup
    add = f'add-{MARK}@example.test'
    _add(db, add, synced=False)
    rspamd['content'] = _section()
    _automatic(monkeypatch, True)
    plan = sup._section_after

    def plan_then_turn_off(*args):
        # Turned off after the write was planned, before it is saved
        monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', False)
        return plan(*args)

    monkeypatch.setattr(sup, '_section_after', plan_then_turn_off)
    with pytest.raises(sup.MapUnavailable) as error:
        _sync(automatic=True)
    assert error.value.code == 'updates_off' and rspamd['writes'] == 0


# ---- Another mailcow ----

def test_a_new_connection_never_takes_blocks_for_deleted(db, rspamd, monkeypatch):
    from app.routers import suppressions as sup
    from app.services.feature_data import _set_key
    import json
    kept, off, theirs = f'kept-{MARK}@example.test', f'off-{MARK}@example.test', f'theirs-{MARK}@example.test'
    _add(db, kept)
    _add(db, off, active=False, synced=False)
    with db() as s:
        _set_key(s, sup.TARGET_KEY, json.dumps('https://old.example.test|'))
        s.commit()
    rspamd['content'] = _section(_line(theirs))
    _sync(automatic=True)
    rows = _rows(db)
    assert rows[kept][:2] == (True, False), 'waits to be added to the new one'
    assert rows[off][:2] == (False, True)
    assert rows[theirs][:3] == (True, True, 'rspamd')
    assert json.loads(_key(db, sup.TARGET_KEY)) == sup._connection_target()


# ---- Counts the page shows ----

def test_the_pending_count_has_adds_removals_and_deletions(db, rspamd):
    from app.routers.suppressions import pending_count, delete_suppression
    from app.models import SpamSuppression
    _add(db, f'add-{MARK}@example.test', synced=False)
    _add(db, f'off-{MARK}@example.test', active=False, synced=False)
    _add(db, f'gone-{MARK}@example.test')
    _add(db, f'kept-{MARK}@example.test')
    with db() as s:
        delete_suppression(s.query(SpamSuppression).filter(SpamSuppression.email == f'gone-{MARK}@example.test').one().id, s)
    with db() as s:
        # One to add, one to remove, one deleted address (however many line forms it may stand as)
        assert pending_count(s) == 3


# ---- One writer of the rows at a time ----

@pytest.mark.parametrize('writer', ['expiry', 'create', 'store'])
def test_writers_of_the_rows_wait_for_the_row_lock(db, monkeypatch, writer):
    from app import scheduler
    from app.services.suppression_rows_lock import lock_suppression_rows
    from app.routers import suppressions as sup
    monkeypatch.setattr(scheduler, 'update_job_status', lambda *a, **k: None)
    monkeypatch.setattr(scheduler, 'record_stuck', lambda s, captured: None)
    run = {
        'expiry': lambda: scheduler._expire_suppressions_sync(),
        'create': lambda: sup._create_suppression_worker(sup.SuppressionCreateRequest(email=f'new-{MARK}@example.test')),
        'store': lambda: scheduler._store_deferred_suppressions_worker([f'stuck-{MARK}@example.test']),
    }[writer]
    done = threading.Event()
    with db() as holder:
        lock_suppression_rows(holder)
        worker = threading.Thread(target=lambda: (run(), done.set()), daemon=True)
        worker.start()
        time.sleep(0.6)
        assert not done.is_set(), f'{writer} went on while the rows were locked'
        holder.commit()
    worker.join(10)
    assert done.is_set()


def test_queued_mail_of_a_block_deleted_meanwhile_stays(db):
    from app import scheduler
    _add(db, f'on-{MARK}@example.test')
    _add(db, f'off-{MARK}@example.test', active=False)
    assert scheduler._blocked_now({f'on-{MARK}@example.test', f'off-{MARK}@example.test',
                                   f'none-{MARK}@example.test'}) == {f'on-{MARK}@example.test'}


def test_an_address_written_as_a_pattern_without_escaping_is_the_exact_address(db, rspamd):
    typed = f'/^add-ed-{MARK}@example\.test$/i'   # the hyphens left unescaped, as people type
    rspamd['content'] = _section(typed)
    _sync(automatic=True)
    assert list(_rows(db)) == [f'add-ed-{MARK}@example.test']
    _sync(automatic=False)
    assert _managed(rspamd) == [_line(f'add-ed-{MARK}@example.test')]
    _sync(automatic=True)
    assert list(_rows(db)) == [f'add-ed-{MARK}@example.test']


@pytest.mark.parametrize('line', ['/^a\S+@example\.test$/i', '/^a.b@example\.test$/i', '/^(a|b)@example\.test$/i'])
def test_a_line_with_pattern_characters_stays_a_pattern(line):
    from app.routers.suppressions import managed_line_entry
    assert managed_line_entry(line)[2] is False


# ---- Result review round 1 ----

def test_both_markers_on_one_line_are_not_an_empty_section(db, rspamd):
    from app.routers.suppressions import MANAGED_MARKER_END, MANAGED_MARKER_START, MapUnavailable
    kept = f'kept-{MARK}@example.test'
    _add(db, kept)
    rspamd['content'] = f'{MANAGED_MARKER_START} {MANAGED_MARKER_END}'
    with pytest.raises(MapUnavailable) as error:
        _sync(automatic=True)
    assert error.value.code == 'section_unclear' and kept in _rows(db)


def test_a_connection_changed_during_the_read_deletes_nothing(db, rspamd, monkeypatch):
    from app.routers import suppressions as sup
    kept = f'kept-{MARK}@example.test'
    _add(db, kept)
    rspamd['content'] = _section(_line(kept))
    _sync(automatic=True)  # the connection is known
    rspamd['content'] = _section()  # the other mailcow has none of it
    targets = iter(['https://a.example.test|'] + ['https://b.example.test|'] * 10)
    monkeypatch.setattr(sup, '_connection_target', lambda: next(targets))
    with pytest.raises(sup.MapUnavailable) as error:
        _sync(automatic=True)
    assert error.value.code == 'connection_changed' and _rows(db)[kept][:2] == (True, True)


def test_two_forms_of_one_new_address_make_one_block(db, rspamd):
    typed = f'two-{MARK}@example.test'
    rspamd['content'] = _section(typed, _line(typed))
    _sync(automatic=True)
    assert list(_rows(db)) == [typed]
    _sync(automatic=True)
    assert list(_rows(db)) == [typed], 'neither form is taken for deleted'
    _sync(automatic=False)
    assert _managed(rspamd) == [_line(typed)]


def test_a_disabled_row_sharing_its_line_with_an_active_one_stays_disabled(db, rspamd):
    from app.routers.suppressions import pending_count
    on, off = f'/^same-{MARK}@example\.test$/i', f'/same-{MARK}@example\.test/i'
    _add(db, on)
    _add(db, off, active=False, synced=False)
    assert _line(on) == _line(off)
    rspamd['content'] = _section(_line(on))
    _sync(automatic=False)
    _sync(automatic=True)
    rows = _rows(db)
    assert rows[off][:2] == (False, True), 'not taken for added in mailcow'
    assert rows[on][:2] == (True, True) and _managed(rspamd) == [_line(on)]
    with db() as s:
        assert pending_count(s) == 0


def test_deleted_and_added_again_leaves_nothing_waiting(db, rspamd):
    from app.routers import suppressions as sup
    from app.models import SpamSuppression
    again = f'again-{MARK}@example.test'
    _add(db, again)
    rspamd['content'] = _section(_line(again))
    with db() as s:
        sup.delete_suppression(s.query(SpamSuppression).filter(SpamSuppression.email == again).one().id, s)
    sup._create_suppression_worker(sup.SuppressionCreateRequest(email=again))
    _sync(automatic=False)
    assert _managed(rspamd) == [_line(again)] and _rows(db)[again][:2] == (True, True)
    with db() as s:
        assert sup.pending_count(s) == 0
    assert _key(db, sup.TOMBSTONES_KEY) is None


# ---- Result review round 2 ----

@pytest.mark.parametrize('change', ['connection', 'updates_off'])
def test_settings_changed_during_the_last_read_stop_the_write(db, rspamd, monkeypatch, change):
    from app.routers import suppressions as sup
    add = f'add-{MARK}@example.test'
    _add(db, add, synced=False)
    first = _section()
    _automatic(monkeypatch, True)
    monkeypatch.setattr(settings._inner, 'rspamd_url', '')

    def read(n):
        if n >= 2:  # the read right before the save
            if change == 'connection':
                settings._inner.rspamd_url = 'http://rspamd.other.example.test:11334'
            else:
                settings._inner.suppression_rspamd_sync = False
        return first

    rspamd['read_hook'] = read
    with pytest.raises(sup.MapUnavailable) as error:
        _sync(automatic=True)
    assert error.value.code == ('connection_changed' if change == 'connection' else 'updates_off')
    assert rspamd['writes'] == 0


def test_a_new_deletion_during_a_write_is_kept(db, rspamd, monkeypatch):
    from app.routers import suppressions as sup
    from app.models import SpamSuppression
    again = f'again-{MARK}@example.test'
    _add(db, again)
    rspamd['content'] = _section(_line(again))
    with db() as s:
        sup.delete_suppression(s.query(SpamSuppression).filter(SpamSuppression.email == again).one().id, s)
    pull = sup._pull_from_rspamd

    async def pull_then_add(s, snapshot):
        # Added again after the read, before the write is planned
        result = await pull(s, snapshot)
        sup._create_suppression_worker(sup.SuppressionCreateRequest(email=again))
        return result

    mark = sup._mark_written

    def delete_again_then_mark(s, *args):
        # And deleted again after the write was planned, before it is settled
        with db() as other:
            sup.delete_suppression(other.query(SpamSuppression).filter(SpamSuppression.email == again).one().id, other)
        return mark(s, *args)

    monkeypatch.setattr(sup, '_pull_from_rspamd', pull_then_add)
    monkeypatch.setattr(sup, '_mark_written', delete_again_then_mark)
    _sync(automatic=False)
    monkeypatch.setattr(sup, '_pull_from_rspamd', pull)
    monkeypatch.setattr(sup, '_mark_written', mark)
    with db() as s:
        assert sup.pending_count(s) == 1, 'the new deletion still waits'
    _sync(automatic=True)
    assert again not in _rows(db), 'its line is not read back as added in mailcow'
    _sync(automatic=False)
    assert _managed(rspamd) == []


def test_tombstones_of_an_earlier_build_count_per_line(db, rspamd):
    from app.routers import suppressions as sup
    from app.services.feature_data import _set_key
    import json
    with db() as s:
        _set_key(s, sup.TOMBSTONES_KEY, json.dumps(['/^a@example\.test$/i', '/^b@example\.test$/i']))
        s.commit()
    with db() as s:
        assert sup.pending_count(s) == 2
