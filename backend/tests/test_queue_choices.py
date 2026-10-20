"""Queue Management choices that delete queued mail without blocking, and
choices that block acting as their twin while Sync with Rspamd is off.

Deleting queued mail cannot be undone: these tests also pin the checks that
keep mail in the queue. Fictional addresses only.
"""
import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock

import pytest

import app.models  # noqa: F401  init_db creates the tables of the models imported so far
from app import scheduler
from app.config import settings

MARK = uuid.uuid4().hex[:6]
OLD = datetime.now(timezone.utc).timestamp() - 7200
_REAL_PROTECTED = scheduler._protected_now


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture
def base(monkeypatch):
    monkeypatch.setattr(type(settings._inner), 'is_feature_enabled', lambda self, name: True)
    for key, value in {'suppression_enabled': True, 'suppression_auto_detect': True, 'suppression_rspamd_sync': True,
                       'suppression_hard_bounce_action': 'suppress', 'suppression_soft_bounce_action': 'count',
                       'queue_cleanup_enabled': True, 'queue_cleanup_block': True, 'queue_cleanup_threshold_minutes': 30,
                       'suppression_whitelist_domains': 'safe.test', 'rspamd_password': ''}.items():
        monkeypatch.setattr(settings._inner, key, value)
    monkeypatch.setattr(scheduler.mailcow_api, 'headers_rw', {'X-API-Key': 'test-key'})
    monkeypatch.setattr(scheduler, 'update_job_status', Mock())
    monkeypatch.setattr(scheduler, '_spam_blocks_loaded', AsyncMock(return_value=True))
    monkeypatch.setattr(scheduler, '_protected_now', lambda emails: set())
    monkeypatch.setattr(scheduler, '_blocked_now', lambda emails: set(emails))
    monkeypatch.setattr(scheduler.mailcow_api, 'delete_queue', AsyncMock(return_value=[{'type': 'success'}]))
    return monkeypatch


def _set(monkeypatch, **values):
    for key, value in values.items():
        monkeypatch.setattr(settings._inner, key, value)


# ---- What really happens ----

@pytest.mark.parametrize('sync, hard, soft, block, expected', [
    (True, 'suppress', 'count', True, ('suppress', 'count', True)),
    (False, 'suppress', 'count', True, ('delete', 'ignore', False)),
    (False, 'suppress', 'suppress', True, ('delete', 'ignore', False)),
    (True, 'delete', 'ignore', False, ('delete', 'ignore', False)),
    (True, 'bogus', 'weird', True, ('ignore', 'ignore', True)),
])
def test_the_choices_as_they_really_happen(base, sync, hard, soft, block, expected):
    from app.services import bounce_policy
    _set(base, suppression_rspamd_sync=sync, suppression_hard_bounce_action=hard, suppression_soft_bounce_action=soft,
         queue_cleanup_block=block)
    assert (bounce_policy.hard_action(), bounce_policy.soft_action(), bounce_policy.cleanup_blocks()) == expected


# ---- The queue cleanup without blocking ----

def _queue(monkeypatch, items):
    monkeypatch.setattr(scheduler.mailcow_api, 'get_queue', AsyncMock(return_value=items))


def _stuck(queue_id, *recipients):
    return {'queue_id': queue_id, 'queue_name': 'deferred', 'arrival_time': OLD, 'recipients': list(recipients)}


@pytest.mark.parametrize('why', ['choice', 'sync_off'])
def test_the_cleanup_deletes_without_blocking(base, why):
    _set(base, **({'queue_cleanup_block': False} if why == 'choice' else {'suppression_rspamd_sync': False}))
    stored = []
    base.setattr(scheduler, '_store_deferred_suppressions_worker', lambda r, uncovered=None: stored.extend(r) or 0)
    _queue(base, [_stuck('GO', 'user@example.org (timed out)'), _stuck('SAFE', 'user@safe.test')])
    asyncio.run(scheduler.cleanup_deferred_queue_job())
    assert stored == [], 'nothing is blocked'
    scheduler.mailcow_api.delete_queue.assert_awaited_once_with(['GO'])
    scheduler.update_job_status.assert_called_with('cleanup_deferred_queue', 'success')


def test_the_cleanup_keeps_mail_of_a_block_disabled_by_hand(base):
    _set(base, queue_cleanup_block=False)
    base.setattr(scheduler, '_protected_now', lambda emails: set(emails) & {'kept@example.org'})
    _queue(base, [_stuck('KEEP', 'kept@example.org', 'other@example.org'), _stuck('GO', 'other@example.org')])
    asyncio.run(scheduler.cleanup_deferred_queue_job())
    scheduler.mailcow_api.delete_queue.assert_awaited_once_with(['GO'])


def test_a_recipient_that_cannot_be_read_keeps_the_message(base):
    _set(base, queue_cleanup_block=False)
    _queue(base, [_stuck('KEEP', 'user@example.org', 'broken@exa/mple.org'), _stuck('KEEP2', '')])
    asyncio.run(scheduler.cleanup_deferred_queue_job())
    scheduler.mailcow_api.delete_queue.assert_not_awaited()


@pytest.mark.parametrize('reply', [None, [], [{'type': 'danger', 'msg': 'no'}], [{'type': 'success'}, {'type': 'danger'}], 'ok'])
def test_the_cleanup_counts_only_a_confirmed_delete(base, reply):
    _set(base, queue_cleanup_block=False)
    base.setattr(scheduler.mailcow_api, 'delete_queue', AsyncMock(return_value=reply))
    _queue(base, [_stuck('GO', 'user@example.org')])
    asyncio.run(scheduler.cleanup_deferred_queue_job())
    assert scheduler.update_job_status.call_args.args[:2] == ('cleanup_deferred_queue', 'failed')


@pytest.mark.parametrize('change', [{'suppression_enabled': False}, {'queue_cleanup_enabled': False},
                                    {'suppression_whitelist_domains': 'example.org'}])
def test_settings_changed_before_the_deletion_keep_the_mail(base, change):
    """Read again right before the deletion, under the map lock."""
    _set(base, queue_cleanup_block=False)
    real = scheduler._cleanup_deletable

    def changed_then_check(items, blocking):
        _set(base, **change)
        return real(items, blocking)

    base.setattr(scheduler, '_cleanup_deletable', changed_then_check)
    _queue(base, [_stuck('GO', 'user@example.org')])
    asyncio.run(scheduler.cleanup_deferred_queue_job())
    scheduler.mailcow_api.delete_queue.assert_not_awaited()


# ---- A permanent failure: delete its queued mail, without a block ----

@pytest.fixture
def db(base):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import get_db_context, init_db
    from app.models import PostfixLog, SpamSuppression, SystemSetting
    init_db()
    base.setattr(scheduler, 'record_bounces', lambda s, captured: None)

    def wipe():
        with get_db_context() as s:
            s.query(SpamSuppression).filter(SpamSuppression.email.like(f'%{MARK}%')).delete(synchronize_session=False)
            s.query(PostfixLog).filter(PostfixLog.message.like(f'%{MARK}%')).delete(synchronize_session=False)
            s.commit()

    wipe()
    with get_db_context() as s:
        # Only this test's lines are new to the detection
        top = s.query(PostfixLog.id).order_by(PostfixLog.id.desc()).first()
        s.query(SystemSetting).filter(SystemSetting.key == scheduler.BOUNCE_WATERMARK_KEY).delete()
        s.add(SystemSetting(key=scheduler.BOUNCE_WATERMARK_KEY, value=str(top[0] if top else 0), updated_at=datetime.utcnow()))
        s.commit()
    yield get_db_context
    wipe()


def _bounce(db, recipient, dsn):
    from app.models import PostfixLog
    now = datetime.utcnow()
    with db() as s:
        s.add(PostfixLog(time=now, created_at=now, program='postfix/smtp', priority='info', message=f'bounce {MARK}',
                         queue_id=f'Q{uuid.uuid4().hex[:8].upper()}', recipient=recipient, status='bounced', dsn=dsn))
        s.commit()


def _rows(db):
    from app.models import SpamSuppression
    with db() as s:
        return {r.email: r.active for r in s.query(SpamSuppression).filter(SpamSuppression.email.like(f'%{MARK}%'))}


@pytest.mark.parametrize('why', ['choice', 'sync_off'])
def test_a_permanent_failure_deletes_its_queued_mail_without_a_block(db, base, why):
    _set(base, **({'suppression_hard_bounce_action': 'delete'} if why == 'choice' else {'suppression_rspamd_sync': False}))
    bad = f'gone-{MARK}@example.org'
    _bounce(db, bad, '5.1.1')
    _queue(base, [{'queue_id': 'ONLY', 'recipients': [bad]},
                  {'queue_id': 'MIXED', 'recipients': [bad, f'fine-{MARK}@example.org']},
                  {'queue_id': 'SAFE', 'recipients': [f'x-{MARK}@safe.test']}])
    asyncio.run(scheduler.detect_suppressions_job())
    assert _rows(db) == {}, 'no block'
    scheduler.mailcow_api.delete_queue.assert_awaited_once_with(['ONLY'])


def test_with_the_sync_off_temporary_failures_count_nothing(db, base):
    _set(base, suppression_rspamd_sync=False, queue_cleanup_enabled=False)
    _bounce(db, f'slow-{MARK}@example.org', '4.4.1')
    _bounce(db, f'odd-{MARK}@example.org', '2.0.0')
    asyncio.run(scheduler.detect_suppressions_job())
    assert _rows(db) == {}


def test_a_status_line_that_is_not_a_failure_blocks_nothing(db, base):
    _bounce(db, f'odd-{MARK}@example.org', '2.0.0')
    new, updated, to_block, to_delete = scheduler._detect_suppressions_worker()
    assert (new, updated, to_block, to_delete) == (0, 0, [], [])


def test_the_detection_counts_only_a_confirmed_delete(db, base):
    _set(base, suppression_hard_bounce_action='delete')
    bad = f'gone-{MARK}@example.org'
    _bounce(db, bad, '5.1.1')
    base.setattr(scheduler.mailcow_api, 'delete_queue', AsyncMock(return_value=[{'type': 'danger', 'msg': 'refused'}]))
    _queue(base, [{'queue_id': 'ONLY', 'recipients': [bad]}])
    asyncio.run(scheduler.detect_suppressions_job())
    assert scheduler.update_job_status.call_args.args[:2] == ('detect_suppressions', 'failed')


def test_a_block_disabled_by_hand_keeps_its_mail_without_a_block_too(base):
    base.setattr(scheduler, '_protected_now', lambda emails: set(emails) & {'kept@example.org'})
    assert scheduler._hard_deletable({'Q': ['kept@example.org']}, set(), {'kept@example.org'}) == []
    assert scheduler._hard_deletable({'Q': ['go@example.org']}, set(), {'go@example.org'}) == ['Q']


# ---- Saving the choices ----

def test_an_unknown_action_is_refused_on_save(base):
    from fastapi import HTTPException
    from app.routers.settings import _validate_bounce_actions
    allowed = {'suppression_hard_bounce_action': 'delete', 'suppression_soft_bounce_action': 'count'}
    _validate_bounce_actions(allowed)
    assert allowed == {'suppression_hard_bounce_action': 'delete', 'suppression_soft_bounce_action': 'count'}
    with pytest.raises(HTTPException) as error:
        _validate_bounce_actions({'suppression_hard_bounce_action': 'explode'})
    assert error.value.status_code == 400
    # The value in effect sent back as it is never blocks saving the rest
    _set(base, suppression_soft_bounce_action='legacy')
    echoed = {'suppression_soft_bounce_action': 'legacy'}
    _validate_bounce_actions(echoed)
    assert echoed == {}


# ---- Result review round 1 ----

def test_a_domain_block_disabled_by_hand_keeps_its_mail(db, base):
    from app.models import SpamSuppression
    base.setattr(scheduler, '_protected_now', _REAL_PROTECTED)  # the fixture stubs it
    domain = '/.+@' + MARK + r'\.example\.test/i'
    with db() as s:
        s.add(SpamSuppression(email=domain, type='domain', reason='manual', source='rspamd', active=False,
                              bounce_count=0, hard_bounce_count=0, soft_bounce_count=0))
        s.commit()
    inside, outside = f'user@{MARK}.example.test', f'user@other-{MARK}.example.test'
    assert scheduler._protected_now({inside, outside}) == {inside}


def test_no_deletion_once_reading_the_logs_is_off(base):
    _set(base, suppression_hard_bounce_action='delete', suppression_auto_detect=False)
    assert scheduler._hard_deletable({'Q': ['go@example.org']}, set(), {'go@example.org'}) == []


def test_a_deletion_that_failed_is_not_tried_again(db, base):
    """Reported on Status; the mail stays in the queue."""
    _set(base, suppression_hard_bounce_action='delete', queue_cleanup_enabled=False)
    bad = f'gone-{MARK}@example.org'
    _bounce(db, bad, '5.1.1')
    _queue(base, [{'queue_id': 'ONLY', 'recipients': [bad]}])
    base.setattr(scheduler.mailcow_api, 'delete_queue', AsyncMock(side_effect=RuntimeError('mailcow down')))
    asyncio.run(scheduler.detect_suppressions_job())
    assert scheduler.update_job_status.call_args.args[:2] == ('detect_suppressions', 'failed')
    base.setattr(scheduler.mailcow_api, 'delete_queue', AsyncMock(return_value=[{'type': 'success'}]))
    asyncio.run(scheduler.detect_suppressions_job())
    scheduler.mailcow_api.delete_queue.assert_not_awaited()


def _disabled_pattern(db, pattern):
    from app.models import SpamSuppression
    with db() as s:
        s.add(SpamSuppression(email=f'/{pattern}/i', type='email', reason='manual', source='rspamd', active=False,
                              bounce_count=0, hard_bounce_count=0, soft_bounce_count=0, notes=MARK))
        s.commit()


def _drop_patterns(db):
    from app.models import SpamSuppression
    with db() as s:
        s.query(SpamSuppression).filter(SpamSuppression.notes == MARK).delete(synchronize_session=False)
        s.commit()


def test_a_disabled_pcre_pattern_is_read_as_rspamd_reads_it(db, base):
    base.setattr(scheduler, '_protected_now', _REAL_PROTECTED)
    _disabled_pattern(db, '(?|user|admin)@x' + MARK + r'\.test')   # branch reset: PCRE, not Python re
    try:
        assert scheduler._protected_now({f'admin@x{MARK}.test', f'other@x{MARK}.test'}) == {f'admin@x{MARK}.test'}
    finally:
        _drop_patterns(db)


def test_a_disabled_pattern_that_cannot_be_read_keeps_the_mail(db, base):
    base.setattr(scheduler, '_protected_now', _REAL_PROTECTED)
    _disabled_pattern(db, '([unclosed@x' + MARK)
    try:
        assert scheduler._protected_now({f'anyone-{MARK}@other.test'}) == {f'anyone-{MARK}@other.test'}
    finally:
        _drop_patterns(db)


def test_a_runaway_pattern_does_not_stall_the_check(db, base):
    import time
    base.setattr(scheduler, '_protected_now', _REAL_PROTECTED)
    _disabled_pattern(db, '(a+)+(b+)+(c+)+@x' + MARK)
    try:
        started = time.monotonic()
        scheduler._protected_now({'a' * 30 + 'b' * 30 + 'c' * 30 + f'-{MARK}@other.test'})
        assert time.monotonic() - started < 3, 'the match is time limited'
    finally:
        _drop_patterns(db)
