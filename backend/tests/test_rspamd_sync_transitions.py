"""The app's blocks in Rspamd never stay behind unseen: they can be removed on
their own (lines above the app's section stay exactly as they are), the list
is deleted only after mailcow confirmed the blocks are gone, a write mailcow
did not confirm is a failure, and an automatic sync that waited for the map
lock does not write after automatic updates were turned off."""
import asyncio
import uuid
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from app.config import settings
from app.mailcow_api import MailcowAPIError
from app.routers import suppressions
from app.routers.suppressions import MANAGED_MARKER_END, MANAGED_MARKER_START, split_managed_section

MARK = uuid.uuid4().hex[:8]
BEFORE = ['# my own entries', 'Bare@Example.org', '/^ceo@example\\.net$/i', '', '']
AFTER = ['# kept after the section']
MANAGED = ['/^a@example\\.com$/i', '/^b@example\\.com$/i']
MAP = '\n'.join(BEFORE + [MANAGED_MARKER_START, '# Last sync: x | Active: 2'] + MANAGED + [MANAGED_MARKER_END] + AFTER)


def test_the_map_splits_into_before_the_apps_part_and_after():
    before, entries, after = split_managed_section(MAP)
    assert before == BEFORE and entries == MANAGED and after == AFTER
    assert split_managed_section('one\ntwo') == (['one', 'two'], [], []), 'a map the app never wrote is all before'


@pytest.fixture
def creds(monkeypatch):
    monkeypatch.setattr(type(settings._inner), "is_rspamd_configured", property(lambda self: True))
    monkeypatch.setattr(suppressions.mailcow_api, "headers_rw", {"X-API-Key": "test-key"})
    monkeypatch.setattr(suppressions.mailcow_api, "aclose", AsyncMock())
    monkeypatch.setattr(suppressions.mailcow_api, "find_rspamd_map_id", AsyncMock(return_value=7))
    monkeypatch.setattr(suppressions.mailcow_api, "get_rspamd_map_content", AsyncMock(return_value=MAP))
    written = []

    async def edit(name, content):
        written.append(content)
        return [{"type": "success", "msg": ["map_content_saved", name]}]
    monkeypatch.setattr(suppressions.mailcow_api, "edit_rspamd_map", edit)
    return written


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture
def rows():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import SpamSuppression
    init_db()

    def cleanup():
        with get_db_context() as db:
            db.query(SpamSuppression).filter(SpamSuppression.email.like(f'%{MARK}%')).delete(synchronize_session=False)
            db.commit()
    cleanup()
    with get_db_context() as db:
        for name in ('a', 'b'):
            db.add(SpamSuppression(email=f'{name}-{MARK}@example.com', reason='manual', source='manual',
                                   active=True, synced_to_rspamd=True))
        db.commit()
    yield
    cleanup()


def _off(monkeypatch):
    """Remove and Start fresh run while the list is not kept (Sync with Rspamd off)."""
    monkeypatch.setattr(settings._inner, "suppression_rspamd_sync", False)


def _mine():
    from app.database import get_db_context
    from app.models import SpamSuppression
    with get_db_context() as db:
        return [(r.email.split('-')[0], r.synced_to_rspamd) for r in
                db.query(SpamSuppression).filter(SpamSuppression.email.like(f'%{MARK}%')).order_by(SpamSuppression.email)]


def test_clearing_removes_only_the_apps_part(creds, rows, monkeypatch):
    _off(monkeypatch)
    assert suppressions.clear_managed_worker() == 2
    before, entries, after = split_managed_section(creds[0])
    assert before == BEFORE, 'lines above the section stay exactly as they were, bare address and blank lines too'
    assert entries == [] and after == AFTER
    assert _mine() == [('a', False), ('b', False)], 'the list stays, now marked as not in Rspamd'


def test_clearing_needs_the_read_write_key_and_writes_nothing_without_it(creds, monkeypatch):
    _off(monkeypatch)
    monkeypatch.setattr(suppressions.mailcow_api, "headers_rw", None)
    with pytest.raises(suppressions.MapUnavailable) as exc:
        suppressions.clear_managed_worker()
    assert exc.value.code == 'no_rw_key' and creds == []


def test_a_map_that_cannot_be_read_is_never_written(creds, monkeypatch):
    _off(monkeypatch)
    monkeypatch.setattr(suppressions.mailcow_api, "get_rspamd_map_content", AsyncMock(side_effect=MailcowAPIError('down')))
    with pytest.raises(suppressions.MapUnavailable) as exc:
        suppressions.clear_managed_worker()
    assert exc.value.code == 'read_failed' and creds == []


def test_start_fresh_keeps_the_list_when_mailcow_did_not_confirm(creds, rows, monkeypatch):
    _off(monkeypatch)
    monkeypatch.setattr(suppressions.mailcow_api, "edit_rspamd_map", AsyncMock(side_effect=MailcowAPIError('not saved')))
    with pytest.raises(MailcowAPIError):
        suppressions.start_fresh_worker()
    assert len(_mine()) == 2


def test_start_fresh_empties_both_sides(creds, rows, monkeypatch):
    _off(monkeypatch)
    result = suppressions.start_fresh_worker()
    assert result['removed_blocks'] == 2 and result['deleted_entries'] >= 2
    assert _mine() == [] and split_managed_section(creds[0])[1] == []


@pytest.mark.parametrize('reply', [[{"type": "danger", "msg": "map not writable"}], None, [], "<html>"])
def test_a_map_write_mailcow_did_not_confirm_is_a_failure(monkeypatch, reply):
    from app.mailcow_api import mailcow_api
    monkeypatch.setattr(mailcow_api, "_make_rw_request", AsyncMock(return_value=reply))
    with pytest.raises(MailcowAPIError):
        asyncio.run(mailcow_api.edit_rspamd_map('global_rcpt_blacklist.map', 'x'))


def test_a_confirmed_map_write_passes(monkeypatch):
    from app.mailcow_api import mailcow_api
    ok = [{"type": "success", "msg": ["map_content_saved", "global_rcpt_blacklist.map"]}]
    monkeypatch.setattr(mailcow_api, "_make_rw_request", AsyncMock(return_value=ok))
    assert asyncio.run(mailcow_api.edit_rspamd_map('global_rcpt_blacklist.map', 'x')) == ok


def test_the_sync_runs_only_while_it_is_on(monkeypatch):
    # Sync with Rspamd off: nothing is read or written. It does not need the
    # automatic handling (test_rspamd_two_way.py covers what it does)
    called = []
    monkeypatch.setattr(suppressions, "_run_on_worker_loop", lambda work: called.append(work) or {"synced": 1})
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: True)
    monkeypatch.setattr(type(settings._inner), "is_rspamd_configured", property(lambda self: True))
    monkeypatch.setattr(settings._inner, "suppression_enabled", False)
    monkeypatch.setattr(settings._inner, "suppression_rspamd_sync", False)
    assert suppressions.sync_suppressions_worker(True).get('skipped_off') and called == []
    monkeypatch.setattr(settings._inner, "suppression_rspamd_sync", True)
    assert suppressions.sync_suppressions_worker(True) == {"synced": 1} and len(called) == 1
    monkeypatch.setattr(type(settings._inner), "is_rspamd_configured", property(lambda self: False))
    assert suppressions.sync_suppressions_worker(True).get('skipped_off') and len(called) == 1, 'nothing to read without the password'


def test_the_state_counts_the_apps_blocks_in_the_map(creds, rows):
    state = asyncio.run(suppressions.rspamd_state())
    assert state['readable'] and state['writable'] and state['managed_count'] == 2
    assert state['active_count'] >= 2, 'counted in the database, on a worker thread'


def test_without_the_rspamd_password_the_state_says_so(rows, monkeypatch):
    monkeypatch.setattr(type(settings._inner), "is_rspamd_configured", property(lambda self: False))
    monkeypatch.setattr(suppressions.mailcow_api, "headers_rw", {"X-API-Key": "k"})
    state = asyncio.run(suppressions.rspamd_state())
    assert not state['readable'] and state['managed_count'] is None and state['reason'] == 'no_password'


def test_an_empty_section_is_not_written_again(creds, rows, monkeypatch):
    _off(monkeypatch)
    empty = '\n'.join(BEFORE + [MANAGED_MARKER_START, '# Cleared: x', MANAGED_MARKER_END])
    monkeypatch.setattr(suppressions.mailcow_api, "get_rspamd_map_content", AsyncMock(return_value=empty))
    assert suppressions.clear_managed_worker() == 0 and creds == []


def test_a_request_that_stops_waiting_never_leaves_the_lock_taken():
    from app.services import rspamd_map_lock as lock

    async def run():
        lock._LOCK.acquire()
        async def wait():
            async with lock.map_write_lock_async():
                pass
        task = asyncio.create_task(wait())
        await asyncio.sleep(0.2)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        lock._LOCK.release()   # the other writer finishes; the abandoned waiter takes it and gives it back
        await asyncio.sleep(0.3)
        return lock._LOCK.locked()

    assert asyncio.run(run()) is False


# ---- turning the feature off with its data purge ----

@pytest.fixture
def purge_client(monkeypatch, rows):
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    monkeypatch.setattr(settings._inner, 'edit_settings_via_ui_enabled', True)
    real = type(settings._inner).is_feature_enabled
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: False if name == 'suppressions' else real(self, name))
    import starlette.staticfiles as sf
    orig = sf.StaticFiles.__init__
    monkeypatch.setattr(sf.StaticFiles, '__init__', lambda s, *a, **k: orig(s, *a, **{**k, 'check_dir': False}))
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


def test_the_list_is_not_deleted_without_a_choice_for_its_rspamd_blocks(purge_client):
    resp = purge_client.post('/api/settings/purge-feature-data', json={'feature': 'suppressions'})
    assert resp.status_code == 400 and len(_mine()) == 2


def test_remove_that_fails_keeps_the_list(purge_client, creds, monkeypatch):
    monkeypatch.setattr(suppressions.mailcow_api, "edit_rspamd_map", AsyncMock(side_effect=MailcowAPIError('not saved')))
    resp = purge_client.post('/api/settings/purge-feature-data', json={'feature': 'suppressions', 'rspamd': 'remove'})
    assert resp.status_code == 502 and resp.json()['detail']['code'] == 'not_confirmed'
    assert len(_mine()) == 2


def test_remove_then_delete(purge_client, creds, monkeypatch):
    from app.services import rspamd_map_lock as lock
    held = []
    real = suppressions._clear_managed_section

    async def clear(db, *args):
        held.append(lock._LOCK.locked())
        return await real(db, *args)
    monkeypatch.setattr(suppressions, "_clear_managed_section", clear)
    resp = purge_client.post('/api/settings/purge-feature-data', json={'feature': 'suppressions', 'rspamd': 'remove'})
    assert held == [True] and not lock._LOCK.locked(), 'the map lock is held from the removal until the list is gone'
    assert resp.status_code == 200 and _mine() == []
    assert split_managed_section(creds[0])[1] == [] and split_managed_section(creds[0])[0] == BEFORE


def test_keep_deletes_the_list_and_leaves_rspamd_alone(purge_client, creds):
    resp = purge_client.post('/api/settings/purge-feature-data', json={'feature': 'suppressions', 'rspamd': 'keep'})
    assert resp.status_code == 200 and _mine() == [] and creds == []


def test_the_old_name_of_the_switch_still_deletes_the_list(purge_client, creds):
    """spam-filter was the switch's name before the list moved to Outbound."""
    resp = purge_client.post('/api/settings/purge-feature-data', json={'feature': 'spam-filter', 'rspamd': 'keep'})
    assert resp.status_code == 200 and resp.json()['feature'] == 'suppressions'
    assert _mine() == [] and creds == []


def test_the_old_name_refuses_a_remove_whose_save_was_switched_again(purge_client, creds):
    """A Remove carries the token of the save that turned the list off; once
    another save turned it off again, that token is stale, also under the old name."""
    from app.database import get_db_context
    from app.services.feature_data import _set_key
    from app.models import SystemSetting
    with get_db_context() as db:
        _set_key(db, 'spam_filter.off_transition', 'the-newer-save')
        db.commit()
    try:
        resp = purge_client.post('/api/settings/purge-feature-data',
                                 json={'feature': 'spam-filter', 'rspamd': 'remove', 'transition': 'an-older-save'})
        assert resp.status_code == 409 and resp.json()['detail']['code'] == 'transition_changed'
        assert len(_mine()) == 2 and creds == [], 'nothing removed from Rspamd, nothing deleted'
    finally:
        with get_db_context() as db:
            db.query(SystemSetting).filter(SystemSetting.key == 'spam_filter.off_transition').delete()
            db.commit()
