"""Sync with Rspamd off keeps no suppression list, like a feature that is off.

Turned off, the list is deleted from the app (Rspamd is asked about apart);
while off, no change to it is accepted and no job adds to it; turned on, it
loads back from the app's section of the map, a read only. The races here
are real: a purge, a job or a late request against a switch that changed
meanwhile. Fictional addresses only.
"""
import asyncio
import threading
import time
import uuid
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import HTTPException
from sqlalchemy import text

from app.config import settings
from test_rspamd_two_way import (  # noqa: F401  db and rspamd are fixtures
    MARK, _add, _key, _line, _managed, _rows, _rw, _section, _sync_setting, db, rspamd)

PENDING = 'spam_filter.import_pending'


def _purge():
    from app.services.feature_data import purge_disabled_features
    return purge_disabled_features()


def _marker(db, value):
    from app.services.feature_data import _set_key
    with db() as s:
        _set_key(s, PENDING, value)
        s.commit()


def _transition(db, was_kept, now_kept):
    from app.routers.settings import _record_list_transition
    with db() as s:
        return _record_list_transition(s, was_kept, now_kept)


def _code(error):
    detail = error.value.detail
    return detail.get('code') if isinstance(detail, dict) else getattr(error.value, 'code', None)


# ---- Off deletes the list ----

def test_the_list_goes_while_the_sync_is_off_and_stays_while_it_is_on(db, monkeypatch):
    blocked = f'blocked-{MARK}@example.test'
    _add(db, blocked)
    assert _purge().get('suppressions') is None and blocked in _rows(db), 'on: nothing is deleted'
    assert _key(db, PENDING) is None
    _sync_setting(monkeypatch, False)  # as SUPPRESSION_RSPAMD_SYNC=false would set it
    assert _purge()['suppressions'] is None
    assert _rows(db) == {}
    assert _key(db, PENDING) == '1', 'a block was in Rspamd: it loads back'


def test_a_list_that_never_reached_rspamd_is_not_owed_a_load(db, monkeypatch):
    _add(db, f'waiting-{MARK}@example.test', synced=False)
    _sync_setting(monkeypatch, False)
    _purge()
    assert _rows(db) == {} and _key(db, PENDING) == 'bootstrap'


@pytest.mark.parametrize('evidence', ['target', 'removal', 'tombstone'])
def test_any_sign_of_blocks_in_rspamd_makes_the_load_owed(db, monkeypatch, evidence):
    from app.services.feature_data import _set_key
    if evidence == 'removal':
        _add(db, f'off-{MARK}@example.test', active=False, synced=False)
    else:
        with db() as s:
            _set_key(s, {'target': 'spam_filter.rspamd_target', 'tombstone': 'spam_filter.rspamd_tombstones'}[evidence],
                     '"x|y"' if evidence == 'target' else '{"/^a@b\\\\.c$/i": "a@b.c#1"}')
            s.commit()
    _sync_setting(monkeypatch, False)
    _purge()
    assert _key(db, PENDING) == '1'


def test_a_purge_that_waited_while_the_sync_came_back_on_deletes_nothing(db, monkeypatch):
    """The purge checked Off and waits for the row lock; the sync is turned on
    and a row is added by hand meanwhile. Once it has the lock it checks
    again: the list stays, and no load is owed."""
    from app.models import SpamSuppression
    from app.services.suppression_rows_lock import lock_suppression_rows
    kept, new = f'kept-{MARK}@example.test', f'new-{MARK}@example.test'
    _add(db, kept)
    _sync_setting(monkeypatch, False)
    done = threading.Event()
    with db() as holder:
        lock_suppression_rows(holder)
        worker = threading.Thread(target=lambda: (_purge(), done.set()), daemon=True)
        worker.start()
        time.sleep(0.6)
        assert not done.is_set(), 'the purge waits for the row lock'
        monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', True)
        holder.add(SpamSuppression(email=new, type='email', reason='manual', source='manual', active=True,
                                   synced_to_rspamd=False, bounce_count=0, hard_bounce_count=0, soft_bounce_count=0))
        holder.commit()
    worker.join(10)
    assert done.is_set()
    assert set(_rows(db)) == {kept, new}
    assert _key(db, PENDING) is None


# ---- While off, nothing changes the list ----

def test_every_list_change_is_refused_while_the_sync_is_off(db, monkeypatch):
    from app.routers import suppressions as sup
    from app.models import SpamSuppression
    row = f'row-{MARK}@example.test'
    _add(db, row)
    with db() as s:
        row_id = s.query(SpamSuppression.id).filter(SpamSuppression.email == row).scalar()
    _sync_setting(monkeypatch, False)
    attempts = {
        'create': lambda s: asyncio.run(sup.create_suppression(sup.SuppressionCreateRequest(email=f'new-{MARK}@example.test'))),
        'update': lambda s: sup.update_suppression(row_id, sup.SuppressionUpdateRequest(active=False), s),
        'delete': lambda s: sup.delete_suppression(row_id, s),
        'import': lambda s: sup._import_suppressions_worker(f'email\ncsv-{MARK}@example.test\n'.encode()),
    }
    for name, attempt in attempts.items():
        with db() as s:
            with pytest.raises(HTTPException) as error:
                attempt(s)
            s.rollback()
        assert error.value.status_code == 409 and _code(error) == 'sync_off', name
    assert set(_rows(db)) == {row} and _rows(db)[row][0] is True


def test_a_block_made_while_the_sync_goes_off_is_refused_under_the_lock(db, monkeypatch):
    """The sync goes off while the block waits for the queue: the check under
    the row lock refuses it, and no row is made."""
    from app.routers import suppressions as sup

    async def queued(queue_id, email):
        monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', False)
        return None

    monkeypatch.setattr(sup, '_queued_message', queued)
    with pytest.raises(HTTPException) as error:
        asyncio.run(sup.create_suppression(sup.SuppressionCreateRequest(email=f'late-{MARK}@example.test', queue_id='Q1')))
    assert _code(error) == 'sync_off' and _rows(db) == {}


def test_the_stuck_mail_store_adds_nothing_while_off_or_before_the_load(db, monkeypatch):
    from app import scheduler
    stuck = f'stuck-{MARK}@example.test'
    _sync_setting(monkeypatch, False)
    assert scheduler._store_deferred_suppressions_worker([stuck]) == 0 and _rows(db) == {}
    _sync_setting(monkeypatch, True)
    _marker(db, '1')
    assert scheduler._store_deferred_suppressions_worker([stuck]) == 0 and _rows(db) == {}
    with db() as s:
        s.execute(text("DELETE FROM system_settings WHERE key = :k"), {'k': PENDING})
        s.commit()
    monkeypatch.setattr(scheduler, 'record_stuck', lambda s, captured: None)
    assert scheduler._store_deferred_suppressions_worker([stuck]) == 1 and stuck in _rows(db)


def test_detection_waits_for_an_owed_load_without_using_up_the_bounce(db, monkeypatch):
    """On, with this app's blocks still to load: the run reads nothing, so a
    choice that blocks never turns into delete-only, and the bounce is
    counted once the blocks are loaded."""
    from app import scheduler
    from app.models import PostfixLog
    bad = f'gone-{MARK}@example.test'
    monkeypatch.setattr(settings._inner, 'suppression_hard_bounce_action', 'suppress')
    monkeypatch.setattr(settings._inner, 'suppression_whitelist_domains', '')
    monkeypatch.setattr(scheduler, 'record_bounces', lambda s, captured: None)
    now = datetime.utcnow()
    with db() as s:
        s.add(PostfixLog(time=now, created_at=now, program='postfix/smtp', priority='info', message=f'bounce {MARK}',
                         queue_id=f'Q{uuid.uuid4().hex[:8].upper()}', recipient=bad, status='bounced', dsn='5.1.1'))
        s.commit()
    _marker(db, '1')
    assert scheduler._detect_suppressions_worker() == (0, 0, [], [])
    assert bad not in _rows(db)
    with db() as s:
        s.execute(text("DELETE FROM system_settings WHERE key = :k"), {'k': PENDING})
        s.commit()
    new, updated, to_block, to_delete = scheduler._detect_suppressions_worker()
    assert bad in to_block and bad not in to_delete and _rows(db)[bad][0] is True, 'blocked, not delete-only'


# ---- On loads the list back, a read only ----

def test_turning_on_loads_the_blocks_without_writing_anything(db, rspamd, monkeypatch):
    from app.routers.suppressions import import_managed_worker
    legacy, exact = '/^.+@legacy\\.test$/i', f'kept-{MARK}@example.test'
    rspamd['content'] = _section(legacy, _line(exact, 'auto'), above=('bare@example.test', '/^mine@example\\.test$/i'))
    before = rspamd['content']
    _rw(monkeypatch)
    _marker(db, '1')
    result = import_managed_worker()
    assert result == {'imported': 2, 'pending': False, 'loaded': True}
    assert rspamd['writes'] == 0 and rspamd['content'] == before, 'not normalized, not migrated'
    rows = _rows(db)
    assert rows[exact] == (True, True, 'rspamd', None)
    assert import_managed_worker() == {'imported': 0, 'pending': False, 'loaded': False}, 'the count belongs to the first'


def test_without_the_password_an_owed_load_waits_and_so_do_the_jobs(db, rspamd, monkeypatch):
    from app import scheduler
    from app.routers.suppressions import import_managed_worker
    kept = f'kept-{MARK}@example.test'
    rspamd['content'] = _section(_line(kept, 'auto'))
    _marker(db, '1')
    monkeypatch.setattr(type(settings._inner), 'is_rspamd_configured', property(lambda self: False))
    assert import_managed_worker() == {'imported': 0, 'pending': True, 'loaded': False, 'reason': 'no_password'}
    assert _key(db, PENDING) == '1' and rspamd['reads'] == 0
    status = Mock()
    monkeypatch.setattr(scheduler, 'update_job_status', status)
    assert asyncio.run(scheduler._spam_blocks_loaded('detect_suppressions')) is False
    assert 'Rspamd password is not set' in status.call_args.args[2]
    # The password is back: the block loads as it was kept, permanent
    monkeypatch.setattr(type(settings._inner), 'is_rspamd_configured', property(lambda self: True))
    assert asyncio.run(scheduler._spam_blocks_loaded('detect_suppressions')) is True
    assert _rows(db)[kept] == (True, True, 'rspamd', None) and _key(db, PENDING) is None


def test_without_the_password_a_load_nothing_points_to_is_dropped(db, rspamd, monkeypatch):
    from app.routers.suppressions import import_managed_worker
    _marker(db, 'bootstrap')
    monkeypatch.setattr(type(settings._inner), 'is_rspamd_configured', property(lambda self: False))
    assert import_managed_worker() == {'imported': 0, 'pending': False, 'loaded': False}
    assert _key(db, PENDING) is None


# ---- Remove and Start fresh belong to their moment ----

def test_a_late_remove_is_refused_once_the_sync_is_on_or_switched_again(db, rspamd, monkeypatch):
    from app.routers.suppressions import MapUnavailable, clear_managed_worker
    block = f'block-{MARK}@example.test'
    rspamd['content'] = _section(_line(block))
    _rw(monkeypatch)
    _sync_setting(monkeypatch, False)
    first = _transition(db, True, False)
    _sync_setting(monkeypatch, True)
    assert _transition(db, False, True) is None
    with pytest.raises(MapUnavailable) as error:
        clear_managed_worker(first)
    assert error.value.code == 'sync_on' and rspamd['writes'] == 0
    _sync_setting(monkeypatch, False)
    second = _transition(db, True, False)  # off again, with Keep
    with pytest.raises(MapUnavailable) as error:
        clear_managed_worker(first)
    assert error.value.code == 'transition_changed' and rspamd['writes'] == 0
    assert clear_managed_worker(second) == 1 and _managed(rspamd) == []


def test_a_remove_whose_sync_comes_on_during_its_read_writes_nothing(db, rspamd, monkeypatch):
    from app.routers.suppressions import MapUnavailable, clear_managed_worker
    content = _section(_line(f'block-{MARK}@example.test'))
    rspamd['content'] = content
    _rw(monkeypatch)
    _sync_setting(monkeypatch, False)

    def read(n):
        if n == 2:  # the read right before the save
            settings._inner.suppression_rspamd_sync = True
        return content

    rspamd['read_hook'] = read
    with pytest.raises(MapUnavailable) as error:
        clear_managed_worker(None)
    assert error.value.code == 'sync_on' and rspamd['writes'] == 0


def test_a_late_start_fresh_never_empties_a_list_kept_again(db, rspamd, monkeypatch):
    from app.routers.suppressions import MapUnavailable, start_fresh_worker
    kept = f'kept-{MARK}@example.test'
    _add(db, kept)
    rspamd['content'] = _section(_line(kept))
    _rw(monkeypatch)
    with pytest.raises(MapUnavailable) as error:
        start_fresh_worker()
    assert error.value.code == 'sync_on' and rspamd['writes'] == 0 and kept in _rows(db)


def test_a_manual_sync_whose_sync_goes_off_before_the_save_writes_nothing(db, rspamd, monkeypatch):
    from app.routers.suppressions import MapUnavailable, sync_suppressions_worker
    waiting = f'waiting-{MARK}@example.test'
    _add(db, waiting, synced=False)
    content = _section()
    rspamd['content'] = content
    _rw(monkeypatch)

    def read(n):
        if n == 2:
            settings._inner.suppression_rspamd_sync = False
        return content

    rspamd['read_hook'] = read
    with pytest.raises(MapUnavailable) as error:
        sync_suppressions_worker(False)
    assert error.value.code == 'sync_off' and rspamd['writes'] == 0


# ---- The settings save ----

def test_the_save_names_the_transition_and_reports_a_purge_that_failed(monkeypatch):
    import app.services.settings_store as ss
    from app.routers import settings as rs
    from app import config as cfg
    data = {}
    monkeypatch.setenv('SETTINGS_EDIT_VIA_UI_ENABLED', 'true')

    def overrides(db, types_):
        return {k: ss._deserialize_value(ss._serialize_value(v), k, types_[k]) for k, v in data.items()}
    monkeypatch.setattr(ss, 'get_config_overrides_from_db', overrides)
    monkeypatch.setattr(rs, 'get_config_overrides_from_db', overrides)
    monkeypatch.setattr(rs, 'save_config_overrides_to_db', lambda db, ov: data.update(ov))
    monkeypatch.setattr(rs, 'has_config_overrides_in_db', lambda db: bool(data))
    monkeypatch.setattr(rs, 'cleanup_disabled_feature_data', lambda db: {'suppressions': 'the database is busy'})
    monkeypatch.setattr(rs, 'run_feature_data_sweep_soon', lambda: None)
    monkeypatch.setattr(rs, 'reschedule_interval_jobs', lambda: None)
    monkeypatch.setattr(rs, 'mailcow_api', SimpleNamespace(reload_config=lambda: None, has_rw_key=False))
    monkeypatch.setattr(rs, 'oauth2_client', SimpleNamespace(reload_config=lambda: None))
    seen = []
    monkeypatch.setattr(rs, '_record_list_transition',
                        lambda db, was, now, switched=False: seen.append((was, now)) or ('T' if was and not now else None))
    monkeypatch.setattr(rs, 'clear_maxmind_validation_status', lambda db: None)
    cfg.reload_settings(object())
    try:
        result = rs.update_settings({'suppression_rspamd_sync': False}, db=object())
    finally:
        monkeypatch.undo()
        cfg.reload_settings()
    assert result['feature_data_errors'] == {'suppressions': 'the database is busy'}
    assert result['rspamd_off_transition'] == 'T'
    assert seen and seen[0][1] is False


def test_two_saves_at_once_take_turns_from_the_state_to_the_token(monkeypatch):
    """A save that stops between storing Off and naming its transition must
    not let another save start from a state it has not finished: otherwise
    an Off, On, Off (Keep) in three windows could leave the first window's
    token in place, and its late Remove would take away blocks kept since."""
    import app.services.settings_store as ss
    from app.routers import settings as rs
    from app import config as cfg
    data = {}
    monkeypatch.setenv('SETTINGS_EDIT_VIA_UI_ENABLED', 'true')

    def overrides(db, types_):
        return {k: ss._deserialize_value(ss._serialize_value(v), k, types_[k]) for k, v in data.items()}
    monkeypatch.setattr(ss, 'get_config_overrides_from_db', overrides)
    monkeypatch.setattr(rs, 'get_config_overrides_from_db', overrides)
    monkeypatch.setattr(rs, 'has_config_overrides_in_db', lambda db: bool(data))
    monkeypatch.setattr(rs, 'cleanup_disabled_feature_data', lambda db: {})
    monkeypatch.setattr(rs, 'run_feature_data_sweep_soon', lambda: None)
    monkeypatch.setattr(rs, 'reschedule_interval_jobs', lambda: None)
    monkeypatch.setattr(rs, 'mailcow_api', SimpleNamespace(reload_config=lambda: None, has_rw_key=False))
    monkeypatch.setattr(rs, 'oauth2_client', SimpleNamespace(reload_config=lambda: None))
    monkeypatch.setattr(rs, 'clear_maxmind_validation_status', lambda db: None)
    first_stored, go_on = threading.Event(), threading.Event()
    order = []

    def save(db, ov):
        data.update(ov)
        order.append(('stored', ov['suppression_rspamd_sync']))
        if not first_stored.is_set():
            first_stored.set()
            go_on.wait(5)  # the first save stops here, before its token

    def record(db, was, now, switched=False):
        order.append(('token', was, now))
        return 'T' if was and not now else None

    monkeypatch.setattr(rs, 'save_config_overrides_to_db', save)
    monkeypatch.setattr(rs, '_record_list_transition', record)
    cfg.reload_settings(object())
    try:
        first = threading.Thread(target=lambda: rs.update_settings({'suppression_rspamd_sync': False}, db=object()), daemon=True)
        first.start()
        assert first_stored.wait(5)
        second = threading.Thread(target=lambda: rs.update_settings({'suppression_rspamd_sync': True}, db=object()), daemon=True)
        second.start()
        time.sleep(0.5)
        assert order == [('stored', False)], 'the second save waits for the first to name its transition'
        go_on.set()
        first.join(5)
        second.join(5)
    finally:
        go_on.set()
        monkeypatch.undo()
        cfg.reload_settings()
    assert order == [('stored', False), ('token', True, False), ('stored', True), ('token', False, True)]


def test_only_a_save_that_turned_a_switch_off_names_a_transition(db):
    """Off saved again while it already is (another window was first) names
    none, so that window's Remove is not run; Spam Filter turned off while
    the sync already was off names one, so its Remove is."""
    assert _transition(db, True, False) is not None, 'the list stopped being kept'
    first = _key(db, 'spam_filter.off_transition')
    assert _transition(db, False, False) is None and _key(db, 'spam_filter.off_transition') == first
    from app.routers.settings import _record_list_transition
    with db() as s:
        assert _record_list_transition(s, False, False, switched=True) not in (None, first)
    assert _transition(db, False, True) is None and _key(db, 'spam_filter.off_transition') is None


# ---- The Rspamd page has its own switch since the list moved to Outbound ----

def test_turning_only_the_maps_off_keeps_the_list_and_its_state(db, monkeypatch):
    from app.services.feature_data import _set_key
    blocked = f'blocked-{MARK}@example.test'
    _add(db, blocked)
    with db() as s:
        _set_key(s, 'spam_filter.off_transition', 'T-kept')
        _set_key(s, 'spam_filter.rspamd_target', 'mail.example.test')
        s.commit()
    monkeypatch.setattr(type(settings._inner), 'is_feature_enabled', lambda self, name: name != 'rspamd')
    assert 'suppressions' not in _purge()
    assert blocked in _rows(db)
    assert _key(db, 'spam_filter.off_transition') == 'T-kept'
    assert _key(db, 'spam_filter.rspamd_target') == 'mail.example.test'
