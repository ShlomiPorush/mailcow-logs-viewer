"""Codes left alone (Settings > Outbound): a delivery failure with a status
code the admin listed for its kind is not blocked, counted or deleted, in the
log detection and in the queue cleanup alike.

Deleting queued mail cannot be undone, so the queue paths are pinned for both
kinds and for every choice that deletes. Fictional addresses only.
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock

import pytest

import app.models  # noqa: F401  init_db creates the tables of the models imported so far
from app import scheduler
from app.config import settings
from app.services import bounce_policy

MARK = uuid.uuid4().hex[:6]
OLD = datetime.now(timezone.utc).timestamp() - 7200


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _set(monkeypatch, **values):
    for key, value in values.items():
        monkeypatch.setattr(settings._inner, key, value)


@pytest.fixture
def base(monkeypatch):
    monkeypatch.setattr(type(settings._inner), 'is_feature_enabled', lambda self, name: True)
    _set(monkeypatch, suppression_enabled=True, suppression_auto_detect=True, suppression_rspamd_sync=True,
         suppression_hard_bounce_action='suppress', suppression_soft_bounce_action='count',
         suppression_soft_bounce_threshold=1,
         suppression_hard_bounce_excluded_codes='5.2.2', suppression_soft_bounce_excluded_codes='4.2.2',
         queue_cleanup_enabled=True, queue_cleanup_block=True, queue_cleanup_threshold_minutes=30,
         suppression_whitelist_domains='', rspamd_password='')
    monkeypatch.setattr(scheduler.mailcow_api, 'headers_rw', {'X-API-Key': 'test-key'})
    monkeypatch.setattr(scheduler, 'update_job_status', Mock())
    monkeypatch.setattr(scheduler, '_spam_blocks_loaded', AsyncMock(return_value=True))
    monkeypatch.setattr(scheduler, '_protected_now', lambda emails: set())
    monkeypatch.setattr(scheduler, '_blocked_now', lambda emails: set(emails))
    monkeypatch.setattr(scheduler.mailcow_api, 'delete_queue', AsyncMock(return_value=[{'type': 'success'}]))
    return monkeypatch


# ---- Reading the lists ----

def test_a_list_is_stored_in_one_form():
    assert bounce_policy.normalize_codes(' 5.2.2, 5.1.1 5.02.2,,5.10.1 ', '5') == '5.1.1,5.2.2,5.10.1'
    assert bounce_policy.normalize_codes('', '4') == ''


@pytest.mark.parametrize('kind, value', [('5', '4.2.2'), ('4', '5.2.2'), ('5', 'mailbox full'), ('5', '5.2'),
                                         ('5', '5.2.2.1'), ('5', '5.2.2000'), ('4', '2.0.0')])
def test_a_code_of_another_kind_or_no_code_is_refused(kind, value):
    with pytest.raises(ValueError):
        bounce_policy.normalize_codes(value, kind)


def test_only_a_code_of_its_own_kind_is_left_alone(base):
    _set(base, suppression_hard_bounce_excluded_codes='5.2.2,4.4.1,bogus', suppression_soft_bounce_excluded_codes='4.7.0')
    assert bounce_policy.code_excluded('5.2.2')
    assert bounce_policy.code_excluded('5.02.2'), 'the same code without its leading zero'
    assert not bounce_policy.code_excluded('5.1.1')
    assert not bounce_policy.code_excluded('4.4.1'), 'a temporary code in the permanent list is not read'
    assert bounce_policy.code_excluded('4.7.0')
    assert not bounce_policy.code_excluded('2.0.0')
    assert not bounce_policy.code_excluded('')


def test_the_code_is_read_from_a_reply_and_never_from_an_address():
    gmail = ("host gmail-smtp-in.l.google.com[192.0.2.27] said: 452-4.2.2 The recipient's inbox is out of storage "
             "space. 452 4.2.2 Please direct the recipient to (in reply to RCPT TO command)")
    assert set(bounce_policy.codes_in_text(gmail)) == {'4.2.2'}
    assert bounce_policy.codes_in_text('connect to mx.example.org[5.4.3.2]:25: Connection timed out') == []
    assert bounce_policy.codes_in_text('connect to mx.example.org[45.4.3.2]:25: timed out') == []
    assert bounce_policy.codes_in_text(None) == []
    # Review R4: a number in a host name or an address is not a code, only one after its reply code
    assert bounce_policy.codes_in_text('connect to 4.2.2-mx.example.test[192.0.2.1]:25: Connection timed out') == []
    assert bounce_policy.codes_in_text('host 452-4.2.2-mx.example.test[192.0.2.1] refused to talk to me') == []
    assert bounce_policy.codes_in_text('host mx said: 550 4.2.2 odd') == [], 'a code of another class than its reply'
    assert bounce_policy.codes_in_text('host mx[192.0.2.1] said: 451 4.7.1 Greylisted, try again') == ['4.7.1']
    # Round 3: only the code that opens the reply, however many spaces follow its reply code
    assert bounce_policy.codes_in_text('host mx said: 451 4.7.1 <452-4.2.2@example.test>: Recipient address rejected') == ['4.7.1']
    assert bounce_policy.codes_in_text('host mx.example.test said: 452  4.2.2 Mailbox full') == ['4.2.2']
    assert bounce_policy.codes_in_text('host mx[192.0.2.1] refused to talk to me: 421 4.7.0 Try again later') == ['4.7.0']
    # Round 4: other Postfix wordings, and a code only on the last line of a joined reply
    assert bounce_policy.codes_in_text('TLS is required, but host mx.example.test[192.0.2.1] refused to start TLS: '
                                       '454 4.7.0 TLS not available due to temporary reason') == ['4.7.0']
    assert bounce_policy.codes_in_text('host mx.example.test[192.0.2.1] said: 452-Temporary delivery failure '
                                       '452 4.2.2 Mailbox full (in reply to RCPT TO command)') == ['4.2.2']
    # Round 5: an address is taken out whole, whatever characters it holds
    assert bounce_policy.codes_in_text('host mx.example.test[192.0.2.1] said: 450 4.1.8 <sender+452-4.2.2+tag@example.invalid>: '
                                       'Sender address rejected: Domain not found (in reply to RCPT TO command)') == ['4.1.8']
    assert bounce_policy.codes_in_text('host mx said: 550 5.1.1 user 552 5.2.2+x@example.invalid unknown') == ['5.1.1']


# ---- The queue cleanup ----

def _queue(monkeypatch, items):
    monkeypatch.setattr(scheduler.mailcow_api, 'get_queue', AsyncMock(return_value=items))


def _stuck(queue_id, *recipients):
    return {'queue_id': queue_id, 'queue_name': 'deferred', 'arrival_time': OLD, 'recipients': list(recipients)}


@pytest.mark.parametrize('block', [True, False])
def test_the_cleanup_keeps_mail_deferred_with_a_code_left_alone(base, block):
    _set(base, queue_cleanup_block=block)
    stored = []
    base.setattr(scheduler, '_store_deferred_suppressions_worker',
                 lambda r, uncovered=None: stored.extend(r) or len({i['email'] for i in r}))
    _queue(base, [
        _stuck('FULL', 'full@example.org (host mx.example.org[192.0.2.1] said: 452 4.2.2 Mailbox full (in reply to RCPT TO command))'),
        _stuck('MIXED', 'slow@example.org (connect to mx.example.net[192.0.2.2]:25: Connection timed out)',
               'full2@example.org (host mx.example.org[192.0.2.1] said: 452 4.2.2 Mailbox full)'),
        _stuck('GO', 'slow@example.org (connect to mx.example.net[192.0.2.2]:25: Connection timed out)'),
    ])
    asyncio.run(scheduler.cleanup_deferred_queue_job())
    scheduler.mailcow_api.delete_queue.assert_awaited_once_with(['GO'])
    assert {i['email'] for i in stored} == ({'slow@example.org'} if block else set()), 'only the deleted mail is blocked'


def test_without_a_list_the_cleanup_deletes_as_before(base):
    _set(base, suppression_soft_bounce_excluded_codes='', queue_cleanup_block=False)
    _queue(base, [_stuck('FULL', 'full@example.org (host mx.example.org[192.0.2.1] said: 452 4.2.2 Mailbox full)')])
    asyncio.run(scheduler.cleanup_deferred_queue_job())
    scheduler.mailcow_api.delete_queue.assert_awaited_once_with(['FULL'])


# ---- The log detection ----

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


def _line(db, recipient, dsn, status='bounced', program='postfix/smtp', age=timedelta(0)):
    from app.models import PostfixLog
    when = datetime.utcnow() - age
    with db() as s:
        s.add(PostfixLog(time=when, created_at=datetime.utcnow(), program=program, priority='info', message=f'failure {MARK}',
                         queue_id=f'Q{uuid.uuid4().hex[:8].upper()}', recipient=recipient, status=status, dsn=dsn))
        s.commit()


def _rows(db):
    from app.models import SpamSuppression
    with db() as s:
        return {r.email: r.active for r in s.query(SpamSuppression).filter(SpamSuppression.email.like(f'%{MARK}%'))}


@pytest.mark.parametrize('action', ['suppress', 'delete'])
def test_a_permanent_failure_with_a_code_left_alone_is_not_blocked_or_deleted(db, base, action):
    _set(base, suppression_hard_bounce_action=action)
    full, gone = f'full-{MARK}@example.org', f'gone-{MARK}@example.org'
    _line(db, full, '5.2.2')
    _line(db, gone, '5.1.1')
    _queue(base, [{'queue_id': 'FULL', 'recipients': [full]}, {'queue_id': 'GONE', 'recipients': [gone]}])
    asyncio.run(scheduler.detect_suppressions_job())
    assert _rows(db) == ({gone: True} if action == 'suppress' else {}), 'only the other code is blocked'
    scheduler.mailcow_api.delete_queue.assert_awaited_once_with(['GONE'])


def test_mail_waiting_with_a_code_left_alone_stays_when_its_address_also_failed_permanently(db, base):
    """Review R1: another, permanent failure of the same address deletes its
    queued mail, but not a message deferred with a code left alone."""
    gone = f'gone-{MARK}@example.org'
    _line(db, gone, '5.1.1')
    _queue(base, [{'queue_id': 'WAITING', 'recipients': [f'{gone} (host mx.example.org[192.0.2.1] said: 452 4.2.2 Mailbox full)']},
                  {'queue_id': 'OTHER', 'recipients': [gone]}])
    asyncio.run(scheduler.detect_suppressions_job())
    scheduler.mailcow_api.delete_queue.assert_awaited_once_with(['OTHER'])


@pytest.mark.parametrize('block', [True, False])
def test_a_list_saved_while_the_cleanup_runs_keeps_the_mail(base, block):
    """Review R2: the codes are asked again right before the deletion, under the map lock."""
    _set(base, suppression_soft_bounce_excluded_codes='', queue_cleanup_block=block)
    base.setattr(scheduler, '_store_deferred_suppressions_worker', lambda r, uncovered=None: len(r))
    real = scheduler._cleanup_deletable

    def saved_then_check(items, blocking):
        _set(base, suppression_soft_bounce_excluded_codes='4.2.2')
        return real(items, blocking)

    base.setattr(scheduler, '_cleanup_deletable', saved_then_check)
    _queue(base, [_stuck('FULL', 'full@example.org (host mx.example.org[192.0.2.1] said: 452 4.2.2 Mailbox full)')])
    asyncio.run(scheduler.cleanup_deferred_queue_job())
    scheduler.mailcow_api.delete_queue.assert_not_awaited()


def test_a_list_saved_before_the_block_is_stored_blocks_nobody(db, base):
    """Review R2: the block is stored under the row lock, with the codes asked again there."""
    arrived = datetime.utcnow() - timedelta(hours=2)
    full, slow = f'full-{MARK}@example.org', f'slow-{MARK}@example.org'
    counted = scheduler._store_deferred_suppressions_worker([
        {'email': full, 'queue_id': 'FULL', 'sender': None, 'arrived': arrived,
         'reason': 'host mx.example.org[192.0.2.1] said: 452 4.2.2 Mailbox full'},
        {'email': slow, 'queue_id': 'FULL', 'sender': None, 'arrived': arrived, 'reason': 'connect to mx: timed out'},
        {'email': slow, 'queue_id': 'SLOW', 'sender': None, 'arrived': arrived, 'reason': 'connect to mx: timed out'},
    ], set())
    assert counted == 1
    assert _rows(db) == {slow: True}, 'no recipient of the message that stays is blocked for it'


def test_a_temporary_failure_with_a_code_left_alone_is_not_counted(db, base):
    _set(base, queue_cleanup_enabled=False)
    full, slow = f'full-{MARK}@example.org', f'slow-{MARK}@example.org'
    _line(db, full, '4.2.2', status='deferred')
    _line(db, slow, '4.4.1', status='deferred')
    asyncio.run(scheduler.detect_suppressions_job())
    assert _rows(db) == {slow: True}


# ---- Saving the lists ----

def test_saving_a_list_stores_it_in_one_form_and_refuses_a_wrong_code(base):
    from fastapi import HTTPException
    from app.routers.settings import _normalize_bounce_codes
    allowed = {'suppression_hard_bounce_excluded_codes': '5.2.2 5.1.1,5.2.2', 'suppression_soft_bounce_excluded_codes': ''}
    _normalize_bounce_codes(allowed)
    assert allowed == {'suppression_hard_bounce_excluded_codes': '5.1.1,5.2.2', 'suppression_soft_bounce_excluded_codes': ''}
    with pytest.raises(HTTPException) as error:
        _normalize_bounce_codes({'suppression_hard_bounce_excluded_codes': '4.2.2'})
    assert error.value.status_code == 400
    assert '"4.2.2" is not a 5.x.x code' in error.value.detail
    # The value in effect sent back as it is never blocks saving the rest
    _set(base, suppression_soft_bounce_excluded_codes='4.2.2,typo')
    echoed = {'suppression_soft_bounce_excluded_codes': '4.2.2,typo'}
    _normalize_bounce_codes(echoed)
    assert echoed == {}


# ---- The codes Settings offers ----

def test_the_codes_offered_are_the_failures_the_detection_reads(db, base):
    from app.routers.suppressions import get_bounce_codes
    # Codes no other test writes, so lines left by others do not count here
    perm, temp = '5.9.871', '4.9.872'
    for _ in range(2):
        _line(db, f'a-{MARK}@example.org', perm)
    _line(db, f'b-{MARK}@example.org', temp, status='deferred')
    _line(db, f'c-{MARK}@example.org', perm, program='postfix/smtpd')     # a client's line, not a delivery
    _line(db, f'd-{MARK}@example.org', perm, program='postfix/lmtp')      # inbound delivery to a mailbox here
    _line(db, f'e-{MARK}@example.org', perm, age=timedelta(days=8))       # older than the window
    _line(db, f'f-{MARK}@example.org', temp, status='sent')
    with db() as s:
        answer = get_bounce_codes(db=s)
    assert answer['days'] == 7
    assert [c for c in answer['permanent'] if c['code'] == perm] == [{'code': perm, 'count': 2}]
    assert [c for c in answer['temporary'] if c['code'] == temp] == [{'code': temp, 'count': 1}]
    assert all(c['code'].startswith('5.') for c in answer['permanent'])
    assert all(c['code'].startswith('4.') for c in answer['temporary'])
