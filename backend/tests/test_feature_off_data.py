"""A feature that is off keeps no data; turned on, it reads back what the
server still has (decision 57).

Fictional addresses only."""
import asyncio
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import app.models  # noqa: F401  init_db creates the tables of the models imported so far
from app.config import settings

MARK = uuid.uuid4().hex[:8]


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _off(monkeypatch, *features):
    monkeypatch.setattr(type(settings._inner), 'is_feature_enabled', lambda self, name: name not in features)


@pytest.fixture
def db_ready(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import ProtectionHit, QuarantineRule, SpamSuppression, SystemSetting
    init_db()
    _off(monkeypatch)
    monkeypatch.setattr(type(settings._inner), 'is_rspamd_configured', property(lambda self: True))

    def wipe():
        with get_db_context() as db:
            db.query(SpamSuppression).delete(synchronize_session=False)
            db.query(QuarantineRule).filter(QuarantineRule.name.like(f'%{MARK}%')).delete(synchronize_session=False)
            db.query(ProtectionHit).filter(ProtectionHit.reason.like(f'%{MARK}%')).delete(synchronize_session=False)
            db.query(SystemSetting).filter(SystemSetting.key.in_(
                ['spam_filter.import_pending', 'spam_filter.import_bootstrapped'])).delete(synchronize_session=False)
            db.commit()

    wipe()
    yield get_db_context
    wipe()


def _fake_map(monkeypatch, initial=''):
    from app.routers import suppressions as sup
    state = {'content': initial, 'writes': 0, 'fail_read': False}

    async def fake_find(filename):
        return 1

    async def fake_read(map_id):
        if state['fail_read']:
            raise sup.MailcowAPIError('read failed')
        return state['content']

    async def fake_write(filename, content):
        state['content'] = content
        state['writes'] += 1
        return [{'type': 'success'}]

    monkeypatch.setattr(sup.mailcow_api, 'find_rspamd_map_id', fake_find)
    monkeypatch.setattr(sup.mailcow_api, 'get_rspamd_map_content', fake_read)
    monkeypatch.setattr(sup.mailcow_api, 'edit_rspamd_map', fake_write)
    monkeypatch.setattr(sup.mailcow_api, 'aclose', AsyncMock())
    monkeypatch.setattr(sup.mailcow_api, 'headers_rw', {'X-API-Key': 'test-key'})
    return state


def _map(manual_above, managed, manual_below=()):
    from app.routers.suppressions import MANAGED_MARKER_START, MANAGED_MARKER_END
    return '\n'.join(list(manual_above) + ['', MANAGED_MARKER_START, '# Last sync: x'] + list(managed)
                     + [MANAGED_MARKER_END] + ([''] + list(manual_below) if manual_below else []))


# ---- Reading the app's map lines back ----

@pytest.mark.parametrize('stored, kind, source', [
    ('user+tag@example.test', 'email', 'auto'),
    ('o.brien@sub.example.test', 'email', 'manual'),
    ('/^.+@example\\.test$/i', 'domain', 'manual'),
    ('/^(sales|info)@example\\.test$/i', 'email', 'manual'),
    ('/^Case\\S+@example\\.test$/', 'email', 'manual'),
])
def test_a_line_the_app_wrote_reads_back_to_its_row(stored, kind, source):
    from app.routers.suppressions import format_suppression_map_entry, parse_managed_line, suppression_map_line, \
        suppression_allows_regex
    line = format_suppression_map_entry(stored, allow_regex=suppression_allows_regex(source))
    value, got_kind = parse_managed_line(line)
    assert got_kind == kind
    row = SimpleNamespace(email=value, source='rspamd')
    assert suppression_map_line(row) == line, 'written back unchanged'


@pytest.mark.parametrize('line', ['/^weird\\d+@example\\.test$/i', '/sales@example\\.test/i', '/^UPPER@example\\.test$/i'])
def test_a_line_the_app_did_not_write_is_kept_as_a_pattern_that_stays_the_same(line):
    from app.routers.suppressions import parse_managed_line, suppression_map_line
    value, kind = parse_managed_line(line)
    assert (value, kind) == (line, 'email')
    written = suppression_map_line(SimpleNamespace(email=value, source='rspamd'))
    assert written.startswith('/^(?:') and written.endswith(')$/i'), 'anchored like every pattern the app writes'
    # Loaded back and written again: the same line, it does not grow
    again = parse_managed_line(written)[0]
    assert suppression_map_line(SimpleNamespace(email=again, source='rspamd')) == written


def test_a_line_no_row_can_hold_stops_the_import():
    from app.routers.suppressions import parse_managed_line
    with pytest.raises(ValueError):
        parse_managed_line('/^(?:' + 'a' * 300 + ')$/x')


# ---- Lines typed into the map by hand ----

def test_the_sync_keeps_lines_typed_below_the_section(db_ready, monkeypatch):
    from app.routers.suppressions import sync_suppressions_worker
    below = ['/^kept-below@example\\.test$/i', '# a comment below']
    state = _fake_map(monkeypatch, _map(['/^kept-above@example\\.test$/i'], [], below))
    with db_ready() as db:
        from app.models import SpamSuppression
        db.add(SpamSuppression(email=f'new-{MARK}@example.test', type='email', reason='manual', source='manual', active=True))
        db.commit()
    sync_suppressions_worker()
    lines = state['content'].split('\n')
    assert '/^kept-above@example\\.test$/i' in lines
    assert all(line in lines for line in below), 'lines below the section stay'
    assert any(f'new\\-{MARK}' in line for line in lines)


def test_a_bare_address_below_the_section_is_anchored_like_one_above(db_ready, monkeypatch):
    from app.routers.suppressions import sync_suppressions_worker
    state = _fake_map(monkeypatch, _map([], [], ['bare@example.test']))
    sync_suppressions_worker()
    assert '/^bare@example\\.test$/i' in state['content'].split('\n')


def test_an_end_marker_without_its_start_keeps_the_lines_after_it(db_ready, monkeypatch):
    from app.routers.suppressions import sync_suppressions_worker, MANAGED_MARKER_END
    state = _fake_map(monkeypatch, '\n'.join(['/^a@example\\.test$/i', MANAGED_MARKER_END, '/^b@example\\.test$/i']))
    sync_suppressions_worker()
    lines = state['content'].split('\n')
    assert '/^a@example\\.test$/i' in lines and '/^b@example\\.test$/i' in lines
    assert lines.count(MANAGED_MARKER_END) == 1


# ---- Turned off: everything goes ----

def test_a_feature_that_is_off_keeps_nothing(db_ready, monkeypatch):
    from app.models import QuarantineRule, SpamSuppression, SystemSetting
    from app.services.feature_data import purge_disabled_features
    with db_ready() as db:
        db.add(QuarantineRule(name=f'rule-{MARK}', match_type='sender', match_value='x@example.test', action='delete'))
        db.add(SpamSuppression(email=f'kept-{MARK}@example.test', type='email', reason='manual', source='manual', active=True))
        db.add(SystemSetting(key='protection.rules', value='{}', updated_at=datetime.utcnow()))
        db.commit()
    _off(monkeypatch, 'quarantine', 'netfilter')
    results = purge_disabled_features()
    assert results == {'quarantine': None, 'netfilter': None}
    with db_ready() as db:
        assert db.query(QuarantineRule).filter(QuarantineRule.name == f'rule-{MARK}').count() == 0
        assert db.query(SystemSetting).filter(SystemSetting.key.like('protection.%')).count() == 0
        # Spam Filter is on: its list stays
        assert db.query(SpamSuppression).filter(SpamSuppression.email == f'kept-{MARK}@example.test').count() == 1


def test_spam_filter_off_deletes_its_list_and_marks_it_to_come_back(db_ready, monkeypatch):
    from app.models import SpamSuppression
    from app.routers.suppressions import import_pending
    from app.services.feature_data import purge_disabled_features
    with db_ready() as db:
        db.add(SpamSuppression(email=f'gone-{MARK}@example.test', type='email', reason='manual', source='manual', active=True))
        db.commit()
    _off(monkeypatch, 'spam-filter')
    purge_disabled_features()
    with db_ready() as db:
        assert db.query(SpamSuppression).count() == 0
        assert import_pending(db)


def test_one_feature_that_fails_does_not_keep_the_others(db_ready, monkeypatch):
    from app.models import QuarantineRule
    from app.services import feature_data
    real = feature_data.purge_feature

    def purge(db, feature):
        if feature == 'dmarc':
            raise RuntimeError('fixture failure')
        return real(db, feature)

    with db_ready() as db:
        db.add(QuarantineRule(name=f'rule-{MARK}', match_type='sender', match_value='x@example.test', action='delete'))
        db.commit()
    monkeypatch.setattr(feature_data, 'purge_feature', purge)
    _off(monkeypatch, 'dmarc', 'quarantine')
    results = feature_data.purge_disabled_features()
    assert results['dmarc'] == 'fixture failure' and results['quarantine'] is None
    with db_ready() as db:
        assert db.query(QuarantineRule).filter(QuarantineRule.name == f'rule-{MARK}').count() == 0


# ---- Turned on: Spam Filter loads its blocks back ----

def _pending(db_ready):
    from app.services.feature_data import _set_key, SPAM_IMPORT_PENDING_KEY
    with db_ready() as db:
        _set_key(db, SPAM_IMPORT_PENDING_KEY, '1')
        db.commit()


def test_the_blocks_the_app_wrote_come_back_as_permanent_rows(db_ready, monkeypatch):
    from app.models import SpamSuppression, SuppressionEvent
    from app.routers.suppressions import import_managed_worker, import_pending, format_suppression_map_entry
    managed = [format_suppression_map_entry('back@example.test'),
               format_suppression_map_entry('/^.+@blocked\\.test$/i', allow_regex=True),
               '/^weird\\d+@example\\.test$/i',
               format_suppression_map_entry('back@example.test')]  # twice in the map, once in the list
    state = _fake_map(monkeypatch, _map(['/^typed-by-hand@example\\.test$/i'], managed))
    _pending(db_ready)
    assert import_managed_worker() == {'imported': 3, 'pending': False}
    with db_ready() as db:
        rows = {r.email: r for r in db.query(SpamSuppression).all()}
        assert set(rows) == {'back@example.test', '/^.+@blocked\\.test$/i', '/^weird\\d+@example\\.test$/i'}
        assert all(r.source == 'rspamd' and r.active and r.expires_at is None for r in rows.values())
        assert rows['/^.+@blocked\\.test$/i'].type == 'domain'
        assert db.query(SuppressionEvent).filter(SuppressionEvent.kind == 'loaded_from_rspamd').count() == 3
        assert not import_pending(db)
    assert state['writes'] == 0, 'loading reads only'


def test_an_address_added_meanwhile_is_not_loaded_twice(db_ready, monkeypatch):
    from app.models import SpamSuppression
    from app.routers.suppressions import import_managed_worker, format_suppression_map_entry
    _fake_map(monkeypatch, _map([], [format_suppression_map_entry('both@example.test')]))
    with db_ready() as db:
        db.add(SpamSuppression(email='both@example.test', type='email', reason='manual', source='manual', active=True))
        db.commit()
    _pending(db_ready)
    assert import_managed_worker()['imported'] == 0
    with db_ready() as db:
        assert [r.source for r in db.query(SpamSuppression).all()] == ['manual']


def test_until_the_blocks_load_no_sync_writes_the_section(db_ready, monkeypatch):
    from app.routers.suppressions import MapUnavailable, sync_suppressions_worker, import_pending, \
        format_suppression_map_entry
    content = _map([], [format_suppression_map_entry('waiting@example.test')])
    state = _fake_map(monkeypatch, content)
    state['fail_read'] = True
    _pending(db_ready)
    with pytest.raises(MapUnavailable):
        sync_suppressions_worker()
    assert state['writes'] == 0 and state['content'] == content
    with db_ready() as db:
        assert import_pending(db)
    # Readable again: the block comes back and the section is left as it is
    state['fail_read'] = False
    result = sync_suppressions_worker()
    assert result.get('skipped') and state['writes'] == 0


def test_no_sync_while_spam_filter_is_off(db_ready, monkeypatch):
    from app.routers.suppressions import MapUnavailable, sync_suppressions_worker
    state = _fake_map(monkeypatch, _map([], ['/^x@example\\.test$/i']))
    _off(monkeypatch, 'spam-filter')
    with pytest.raises(MapUnavailable) as e:
        sync_suppressions_worker()
    assert e.value.code == 'feature_off'
    assert sync_suppressions_worker(automatic=True).get('skipped_off')
    assert state['writes'] == 0


def test_no_automatic_path_changes_a_row_loaded_from_rspamd(db_ready):
    from app import scheduler
    from app.models import SpamSuppression
    with db_ready() as db:
        db.add(SpamSuppression(email=f'kept-{MARK}@example.test', type='email', reason='manual', source='rspamd',
                               active=True, bounce_count=0, soft_bounce_count=0))
        db.commit()
    counted = scheduler._store_deferred_suppressions_worker([{
        'email': f'kept-{MARK}@example.test', 'queue_id': f'Q{MARK.upper()}', 'sender': 's@example.test',
        'arrived': datetime.utcnow() - timedelta(hours=2), 'reason': None}])
    assert counted == 0
    with db_ready() as db:
        row = db.query(SpamSuppression).filter(SpamSuppression.email == f'kept-{MARK}@example.test').one()
        assert (row.bounce_count, row.expires_at, row.reason) == (0, None, 'manual')


def test_an_upgrade_with_an_empty_list_loads_the_blocks_once(db_ready):
    from app.routers.suppressions import import_pending
    from app.services.feature_data import bootstrap_spam_import
    with db_ready() as db:
        bootstrap_spam_import(db)
        assert import_pending(db)
        db.query(app.models.SystemSetting).filter(
            app.models.SystemSetting.key == 'spam_filter.import_pending').delete()
        db.commit()
        bootstrap_spam_import(db)
        assert not import_pending(db), 'only on the first start'


def test_a_job_that_adds_to_the_list_waits_for_the_blocks(db_ready, monkeypatch):
    from app import scheduler
    from unittest.mock import Mock
    _fake_map(monkeypatch).update(fail_read=True)
    _pending(db_ready)
    monkeypatch.setattr(scheduler, 'update_job_status', Mock())
    assert asyncio.run(scheduler._spam_blocks_loaded('detect_suppressions')) is False
    status = scheduler.update_job_status.call_args.args
    assert status[:2] == ('detect_suppressions', 'failed')


# ---- Security turned off: the app's temporary bans leave Fail2ban ----

def _hit(ip, owned, hours, rule='trap'):
    now = datetime.utcnow()
    return app.models.ProtectionHit(ip=ip, rule=rule, mode='enforce', status='banned', reason=f'fixture {MARK}',
                                    first_seen=now, last_seen=now, banned_at=now, owned=owned, ban_hours=hours,
                                    expires_at=now + timedelta(hours=hours) if hours else None)


def _fake_fail2ban(monkeypatch, blacklist, reply=None):
    from app.services import protection_rules
    api = SimpleNamespace(writes=[])

    async def get_fail2ban():
        return {'blacklist': '\n'.join(blacklist), 'whitelist': '192.0.2.250', 'ban_time': 600}

    async def edit_fail2ban(attrs):
        api.writes.append(attrs)
        return reply if reply is not None else [{'type': 'success'}]

    api.get_fail2ban, api.edit_fail2ban = get_fail2ban, edit_fail2ban
    return api


def test_security_off_takes_out_only_the_apps_temporary_bans(db_ready, monkeypatch):
    from app.models import ProtectionHit
    from app.services import protection_rules
    from app.services.feature_data import purge_disabled_features
    with db_ready() as db:
        db.add(_hit('198.51.100.1', owned=True, hours=24))      # temporary, ours: goes
        db.add(_hit('198.51.100.2', owned=True, hours=24))      # temporary, ours, but also
        db.add(_hit('198.51.100.2', owned=False, hours=0, rule='subnet'))  # banned for good: stays
        db.add(_hit('198.51.100.3', owned=True, hours=0))       # permanent: stays
        db.commit()
    api = _fake_fail2ban(monkeypatch, ['198.51.100.1', '198.51.100.2', '198.51.100.3', '203.0.113.9'])
    _off(monkeypatch, 'netfilter')
    with db_ready() as db:
        purge_disabled_features()
        assert db.query(ProtectionHit).filter(ProtectionHit.reason == f'fixture {MARK}').count() == 4, \
            'the history waits until the temporary bans are out'
    assert asyncio.run(protection_rules.release_temporary_bans(api)) == 1
    written = api.writes[-1]
    assert written['blacklist'].split(',') == ['198.51.100.2', '198.51.100.3', '203.0.113.9']
    assert (written['whitelist'], written['ban_time']) == ('192.0.2.250', '600'), 'the other settings stay'
    purge_disabled_features()
    with db_ready() as db:
        assert db.query(ProtectionHit).filter(ProtectionHit.reason == f'fixture {MARK}').count() == 0


def test_a_change_mailcow_did_not_confirm_keeps_the_bans(db_ready, monkeypatch):
    from app.models import ProtectionHit
    from app.services import protection_rules
    with db_ready() as db:
        db.add(_hit('198.51.100.7', owned=True, hours=24))
        db.commit()
    api = _fake_fail2ban(monkeypatch, ['198.51.100.7'], reply=[{'type': 'danger', 'msg': 'denied'}])
    _off(monkeypatch, 'netfilter')
    with pytest.raises(RuntimeError):
        asyncio.run(protection_rules.release_temporary_bans(api))
    with db_ready() as db:
        assert db.query(ProtectionHit).filter(ProtectionHit.reason == f'fixture {MARK}').one().status == 'banned'


def test_nothing_is_taken_out_or_written_while_security_is_on_or_after_it_went_off(db_ready, monkeypatch):
    from app.services import protection_rules
    api = _fake_fail2ban(monkeypatch, ['198.51.100.8'])
    assert asyncio.run(protection_rules.release_temporary_bans(api)) is None
    _off(monkeypatch, 'netfilter')
    assert asyncio.run(protection_rules.enforce(api)) == {'banned': [], 'lifted': [], 'failed': []}
    assert api.writes == []


def test_a_ban_still_pending_when_security_went_off_is_closed_not_written(db_ready, monkeypatch):
    """An enforce run may be writing a pending ban: the history waits for the
    sweep, which closes it holding the Fail2ban lock."""
    from app.models import ProtectionHit
    from app.services import protection_rules
    from app.services.feature_data import purge_disabled_features
    with db_ready() as db:
        hit = _hit('198.51.100.9', owned=None, hours=24)
        hit.status, hit.banned_at, hit.expires_at = 'pending', None, None
        db.add(hit)
        db.commit()
    api = _fake_fail2ban(monkeypatch, [])
    _off(monkeypatch, 'netfilter')
    purge_disabled_features()
    with db_ready() as db:
        assert db.query(ProtectionHit).filter(ProtectionHit.reason == f'fixture {MARK}').count() == 1
    assert asyncio.run(protection_rules.release_temporary_bans(api)) == 0
    assert api.writes == []
    purge_disabled_features()
    with db_ready() as db:
        assert db.query(ProtectionHit).filter(ProtectionHit.reason == f'fixture {MARK}').count() == 0


@pytest.mark.parametrize('line, value, written', [
    # a bare pattern stays a pattern
    ('.*@blocked\\.test', '/.*@blocked\\.test/', '/^(?:.*@blocked\\.test)$/'),
    # a bare address is blocked exactly
    ('bare@example.test', 'bare@example.test', '/^bare@example\\.test$/i'),
])
def test_a_bare_line_in_the_section_keeps_its_meaning(line, value, written):
    from app.routers.suppressions import parse_managed_line, suppression_map_line
    got, _ = parse_managed_line(line)
    assert got == value
    assert suppression_map_line(SimpleNamespace(email=got, source='rspamd')) == written


def test_a_pattern_typed_above_the_section_is_not_taken_for_an_address():
    from app.routers.suppressions import migrate_manual_map_line
    assert migrate_manual_map_line('.*@blocked\\.test') == '.*@blocked\\.test'
    assert migrate_manual_map_line('user+tag@example.test') == '/^user\\+tag@example\\.test$/i'


def test_a_pattern_with_flags_the_app_cannot_keep_stops_the_import():
    from app.routers.suppressions import parse_managed_line
    with pytest.raises(ValueError):
        parse_managed_line('/^(?:x@example\\.test)$/u')


def test_a_long_pattern_that_fits_is_loaded_without_extra_anchors():
    from app.routers.suppressions import format_suppression_map_entry, parse_managed_line, suppression_map_line
    stored = '/' + 'a' * 253 + '/'                  # 255 characters, as a row can hold
    line = format_suppression_map_entry(stored, allow_regex=True)
    value, _ = parse_managed_line(line)
    assert len(value) <= 255
    assert suppression_map_line(SimpleNamespace(email=value, source='rspamd')) == line


def test_patterns_that_differ_only_in_case_are_both_loaded(db_ready, monkeypatch):
    from app.models import SpamSuppression
    from app.routers.suppressions import import_managed_worker, format_suppression_map_entry
    managed = [format_suppression_map_entry('/^User@x\\.test$/', allow_regex=True),
               format_suppression_map_entry('/^user@x\\.test$/', allow_regex=True)]
    _fake_map(monkeypatch, _map([], managed))
    _pending(db_ready)
    assert import_managed_worker()['imported'] == 2
    with db_ready() as db:
        assert db.query(SpamSuppression).count() == 2


def test_a_job_stops_when_spam_filter_went_off_while_it_waited(db_ready, monkeypatch):
    from app import scheduler
    from app.routers import suppressions
    _pending(db_ready)
    monkeypatch.setattr(suppressions, 'import_managed_worker',
                        lambda: {'imported': 0, 'pending': False, 'feature_off': True})
    assert asyncio.run(scheduler._spam_blocks_loaded('detect_suppressions')) is False


def test_a_disabled_block_from_rspamd_keeps_its_queued_mail(db_ready):
    from app import scheduler
    from app.models import SpamSuppression
    with db_ready() as db:
        db.add(SpamSuppression(email=f'off-{MARK}@example.test', type='email', reason='manual', source='rspamd',
                               active=False, bounce_count=0, soft_bounce_count=0))
        db.add(SpamSuppression(email=f'on-{MARK}@example.test', type='email', reason='manual', source='rspamd',
                               active=True, bounce_count=0, soft_bounce_count=0))
        db.commit()
    uncovered = set()
    item = {'queue_id': f'U{MARK.upper()}', 'sender': 's@example.test', 'arrived': datetime.utcnow(), 'reason': None}
    assert scheduler._store_deferred_suppressions_worker(
        [{**item, 'email': f'off-{MARK}@example.test'}, {**item, 'email': f'on-{MARK}@example.test'}], uncovered) == 0
    assert uncovered == {f'off-{MARK}@example.test'}


def test_the_queue_cleanup_keeps_messages_no_block_covers(monkeypatch):
    from unittest.mock import Mock
    from app import scheduler
    monkeypatch.setattr(type(settings._inner), 'is_feature_enabled', lambda self, name: True)
    for key, value in {'suppression_enabled': True, 'queue_cleanup_enabled': True, 'queue_cleanup_threshold_minutes': 30,
                       'suppression_rspamd_sync': False, 'suppression_whitelist_domains': ''}.items():
        monkeypatch.setattr(settings._inner, key, value)
    monkeypatch.setattr(scheduler.mailcow_api, 'headers_rw', {'X-API-Key': 'test-key'})
    monkeypatch.setattr(scheduler, 'update_job_status', Mock())
    monkeypatch.setattr(scheduler, '_spam_blocks_loaded', AsyncMock(return_value=True))
    old = datetime.utcnow().timestamp() - 7200
    monkeypatch.setattr(scheduler.mailcow_api, 'get_queue', AsyncMock(return_value=[
        {'queue_id': 'KEEP', 'queue_name': 'deferred', 'arrival_time': old, 'recipients': ['off@example.test']},
        {'queue_id': 'GO', 'queue_name': 'deferred', 'arrival_time': old, 'recipients': ['new@example.test']}]))
    monkeypatch.setattr(scheduler.mailcow_api, 'delete_queue', AsyncMock(return_value=[{'type': 'success'}]))

    def store(recipients, uncovered=None):
        uncovered.add('off@example.test')
        return 1

    monkeypatch.setattr(scheduler, '_store_deferred_suppressions_worker', store)
    asyncio.run(scheduler.cleanup_deferred_queue_job())
    scheduler.mailcow_api.delete_queue.assert_awaited_once_with(['GO'])


def test_detection_leaves_a_block_from_rspamd_alone(db_ready, monkeypatch):
    from app import scheduler
    from app.models import PostfixLog, SpamSuppression
    for key, value in {'suppression_hard_bounce_action': 'suppress', 'suppression_whitelist_domains': '',
                       'queue_cleanup_enabled': True}.items():
        monkeypatch.setattr(settings._inner, key, value)
    now = datetime.utcnow()
    with db_ready() as db:
        db.add(SpamSuppression(email=f'off-{MARK}@example.test', type='email', reason='manual', source='rspamd',
                               active=False, bounce_count=0, hard_bounce_count=0, soft_bounce_count=0))
        db.add(PostfixLog(time=now, created_at=now, program='postfix/smtp', priority='info', message=f'bounce {MARK}',
                          queue_id=f'D{MARK.upper()}', recipient=f'off-{MARK}@example.test', status='bounced', dsn='5.1.1'))
        db.commit()
    try:
        _, _, cleanup = scheduler._detect_suppressions_worker()
        assert f'off-{MARK}@example.test' not in cleanup, 'no block covers it: its queued mail stays'
        with db_ready() as db:
            row = db.query(SpamSuppression).filter(SpamSuppression.email == f'off-{MARK}@example.test').one()
            assert (row.bounce_count, row.active, row.reason) == (0, False, 'manual')
    finally:
        with db_ready() as db:
            db.query(PostfixLog).filter(PostfixLog.message == f'bounce {MARK}').delete()
            db.commit()


def test_the_sweep_reports_a_feature_it_could_not_clean(monkeypatch):
    from unittest.mock import Mock
    from app import scheduler
    monkeypatch.setattr(type(settings._inner), 'is_feature_enabled', lambda self, name: name != 'dmarc')
    monkeypatch.setattr(scheduler, 'update_job_status', Mock())
    monkeypatch.setattr(scheduler, 'cleanup_disabled_feature_data', lambda: {'dmarc': 'disk full'})
    asyncio.run(scheduler.feature_data_sweep_job(load_spam_blocks=False))
    status = scheduler.update_job_status.call_args.args
    assert status[:2] == ('feature_data_sweep', 'failed') and 'disk full' in status[2]


def test_without_the_rspamd_password_there_is_nothing_to_load(db_ready, monkeypatch):
    """A new install (no Rspamd password) never wrote to Rspamd: the marker of
    the first start must not hold the jobs back."""
    from app.routers.suppressions import import_managed_worker, import_pending
    monkeypatch.setattr(type(settings._inner), 'is_rspamd_configured', property(lambda self: False))
    _pending(db_ready)
    assert import_managed_worker() == {'imported': 0, 'pending': False}
    with db_ready() as db:
        assert not import_pending(db)


def test_run_now_keeps_a_failure_the_sweep_reported(monkeypatch):
    from fastapi import BackgroundTasks
    from app import scheduler
    from app.routers.settings import trigger_job
    monkeypatch.setattr(type(settings._inner), 'is_feature_enabled', lambda self, name: name != 'dmarc')
    monkeypatch.setattr(scheduler, 'cleanup_disabled_feature_data', lambda: {'dmarc': 'disk full'})
    monkeypatch.setitem(scheduler.job_status, 'feature_data_sweep', {'last_run': None, 'status': 'idle', 'error': None})
    tasks = BackgroundTasks()
    trigger_job('feature_data_sweep', tasks)
    asyncio.run(tasks())
    assert scheduler.job_status['feature_data_sweep']['status'] == 'failed'
    assert 'disk full' in scheduler.job_status['feature_data_sweep']['error']


def test_the_sweep_says_it_set_its_own_status(monkeypatch):
    from unittest.mock import Mock
    from app import scheduler
    monkeypatch.setattr(type(settings._inner), 'is_feature_enabled', lambda self, name: True)
    monkeypatch.setattr(scheduler, 'update_job_status', Mock())
    monkeypatch.setattr(scheduler, 'cleanup_disabled_feature_data', lambda: {})
    assert asyncio.run(scheduler.feature_data_sweep_job(load_spam_blocks=False)) == scheduler.JOB_STATUS_SET


def test_a_purge_that_waited_for_spam_filter_to_come_back_on_deletes_nothing(db_ready, monkeypatch):
    from app.models import SpamSuppression
    from app.services.feature_data import purge_disabled_features
    with db_ready() as db:
        db.add(SpamSuppression(email=f'new-{MARK}@example.test', type='email', reason='manual', source='manual', active=True))
        db.commit()
    asked = {'spam-filter': 0}

    def enabled(self, name):
        if name != 'spam-filter':
            return True
        asked['spam-filter'] += 1
        return asked['spam-filter'] > 2    # off at the first start check and the sweep, on again once it holds the lock

    monkeypatch.setattr(type(settings._inner), 'is_feature_enabled', enabled)
    purge_disabled_features()
    with db_ready() as db:
        assert db.query(SpamSuppression).filter(SpamSuppression.email == f'new-{MARK}@example.test').count() == 1
