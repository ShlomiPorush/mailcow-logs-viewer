import asyncio
import hashlib
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

MARKER = 'legs-corr.invalid'
REMOTE = f'ext@remote-{MARKER}'
LOCAL_USER = f'user@{MARKER}'
OTHER_USER = f'other@{MARKER}'
UNKNOWN_USER = f'nobody@{MARKER}'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _msgid():
    return f'{uuid.uuid4().hex}@{MARKER}'


def _queue():
    return uuid.uuid4().hex[:10].upper()


def _legacy_key(message_id):
    return hashlib.sha256(f'msgid:{message_id}'.encode()).hexdigest()


def _leg_key(message_id, queue_id):
    return hashlib.sha256(f'msgid:{message_id}:queue:{queue_id}'.encode()).hexdigest()


def _cleanup():
    from app.database import get_db_context
    from app.models import (MessageCorrelation, PostfixLog, RawServiceLog,
                            RspamdLog, SystemSetting)
    from app.scheduler import DOVECOT_WATERMARK_KEY
    with get_db_context() as db:
        db.query(RawServiceLog).filter(
            RawServiceLog.raw_data['message'].astext.like(f'%{MARKER}%')
        ).delete(synchronize_session=False)
        db.query(PostfixLog).filter(
            PostfixLog.message.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.query(RspamdLog).filter(
            RspamdLog.message_id.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.query(MessageCorrelation).filter(
            MessageCorrelation.message_id.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.query(MessageCorrelation).filter(
            MessageCorrelation.correlation_key.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.query(SystemSetting).filter(
            SystemSetting.key == DOVECOT_WATERMARK_KEY).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def env():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db
    init_db()
    _cleanup()
    yield
    _cleanup()


def _add_postfix(queue_id, when, program='postfix/smtp', msgid=None, sender=None,
                 recipient=None, status=None, relay=None):
    from app.database import get_db_context
    from app.models import PostfixLog
    with get_db_context() as db:
        row = PostfixLog(
            time=when, program=program, priority='info',
            message=f'{queue_id}: {MARKER} {uuid.uuid4().hex}',
            queue_id=queue_id, message_id=msgid, sender=sender,
            recipient=recipient, status=status, relay=relay)
        db.add(row)
        db.commit()
        return row.id


def _add_rspamd(msgid, when, sender, recipients, action='no action', is_spam=False):
    from app.database import get_db_context
    from app.models import RspamdLog
    with get_db_context() as db:
        row = RspamdLog(
            time=when, message_id=msgid, sender_smtp=sender,
            recipients_smtp=recipients, score=0.5, required_score=15.0,
            action=action, is_spam=is_spam, direction='inbound', user='unknown')
        db.add(row)
        db.commit()
        return row.id


def _correlate(rspamd_id):
    from app.services import correlation_jobs
    from app.database import get_db_context
    from app.models import RspamdLog
    with get_db_context() as db:
        rspamd_log = db.query(RspamdLog).filter(RspamdLog.id == rspamd_id).first()
        correlation = correlation_jobs.correlate_single_message(db, rspamd_log)
        return correlation.correlation_key if correlation else None


def _legs(msgid):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    with get_db_context() as db:
        rows = db.query(MessageCorrelation).filter(
            MessageCorrelation.message_id == msgid
        ).order_by(MessageCorrelation.id).all()
        for row in rows:
            db.expunge(row)
        return rows


def _seed_forward_scenario():
    msgid = _msgid()
    queue_a, queue_b = _queue(), _queue()
    t0 = datetime.utcnow() - timedelta(minutes=5)

    _add_postfix(queue_a, t0, program='postfix/cleanup', msgid=msgid)
    _add_postfix(queue_a, t0, program='postfix/qmgr', sender=REMOTE)
    _add_postfix(queue_a, t0 + timedelta(seconds=1), program='postfix/lmtp',
                 recipient=LOCAL_USER, status='sent', relay='dovecot')
    rspamd_a = _add_rspamd(msgid, t0, REMOTE, [LOCAL_USER], action='no action')

    t1 = t0 + timedelta(seconds=20)
    _add_postfix(queue_b, t1, program='postfix/cleanup', msgid=msgid)
    _add_postfix(queue_b, t1, program='postfix/qmgr', sender=LOCAL_USER)
    _add_postfix(queue_b, t1 + timedelta(seconds=1), program='postfix/smtp',
                 recipient=OTHER_USER)
    rspamd_b = _add_rspamd(msgid, t1, LOCAL_USER, [OTHER_USER], action='reject')

    return msgid, queue_a, queue_b, rspamd_a, rspamd_b


def _seed_single_delivery(recipient=None, when=None):
    msgid = _msgid()
    queue = _queue()
    t0 = when or (datetime.utcnow() - timedelta(minutes=2))
    _add_postfix(queue, t0, program='postfix/cleanup', msgid=msgid, sender=REMOTE)
    _add_postfix(queue, t0 + timedelta(seconds=1), program='postfix/lmtp',
                 recipient=recipient or LOCAL_USER, status='sent', relay='dovecot')
    key = _correlate(_add_rspamd(msgid, t0, REMOTE, [recipient or LOCAL_USER]))
    return msgid, key


def _list_messages(**overrides):
    from app.database import get_db_context
    from app.routers.messages import get_unified_messages
    params = dict(page=1, limit=50, search=MARKER, sender=None, recipient=None,
                  direction=None, status=None, user=None, ip=None,
                  start_date=None, end_date=None)
    params.update(overrides)
    with get_db_context() as db:
        return get_unified_messages(db=db, **params)


def test_forward_keeps_both_delivery_legs(env):
    msgid, queue_a, queue_b, rspamd_a, rspamd_b = _seed_forward_scenario()

    _correlate(rspamd_a)
    _correlate(rspamd_b)

    legs = {leg.queue_id: leg for leg in _legs(msgid)}
    assert set(legs) == {queue_a, queue_b}, 'both deliveries must be kept'

    leg_a, leg_b = legs[queue_a], legs[queue_b]

    assert (leg_a.sender, leg_a.recipient) == (REMOTE, LOCAL_USER)
    assert leg_a.final_status == 'delivered'
    assert leg_a.rspamd_log_id == rspamd_a

    assert (leg_b.sender, leg_b.recipient) == (LOCAL_USER, OTHER_USER)
    assert leg_b.final_status == 'rejected'
    assert leg_b.rspamd_log_id == rspamd_b

    assert leg_a.correlation_key == _legacy_key(msgid)
    assert leg_b.correlation_key == _leg_key(msgid, queue_b)
    assert leg_a.correlation_key != leg_b.correlation_key


def test_late_postfix_line_updates_only_its_own_leg(env):
    from app.database import get_db_context
    from app.models import RspamdLog
    from app.services import correlation_jobs

    msgid, queue_a, queue_b, rspamd_a, rspamd_b = _seed_forward_scenario()
    _correlate(rspamd_a)
    _correlate(rspamd_b)

    _add_postfix(queue_a, datetime.utcnow(), program='postfix/lmtp',
                 recipient=LOCAL_USER, status='bounced')
    with get_db_context() as db:
        scan = db.query(RspamdLog).filter(RspamdLog.id == rspamd_a).first()
        correlation = correlation_jobs.correlate_single_message(db, scan)
        assert correlation is not None
        assert correlation.queue_id == queue_a

    legs = {leg.queue_id: leg for leg in _legs(msgid)}
    assert legs[queue_a].final_status == 'bounced'
    assert legs[queue_b].final_status == 'rejected'


def test_rspamd_stub_adopts_the_first_chain_then_a_second_leg_follows(env):
    msgid = _msgid()
    queue_a, queue_b = _queue(), _queue()
    t0 = datetime.utcnow() - timedelta(minutes=5)

    rspamd_a = _add_rspamd(msgid, t0, REMOTE, [LOCAL_USER])
    key = _correlate(rspamd_a)

    stub = _legs(msgid)
    assert len(stub) == 1
    assert stub[0].queue_id is None
    assert key == _legacy_key(msgid)

    _add_postfix(queue_a, t0, program='postfix/cleanup', msgid=msgid, sender=REMOTE)
    _add_postfix(queue_a, t0 + timedelta(seconds=1), program='postfix/lmtp',
                 recipient=LOCAL_USER, status='sent', relay='dovecot')
    _correlate(rspamd_a)

    adopted = _legs(msgid)
    assert len(adopted) == 1
    assert adopted[0].queue_id == queue_a
    assert adopted[0].correlation_key == _legacy_key(msgid)

    t1 = t0 + timedelta(seconds=20)
    _add_postfix(queue_b, t1, program='postfix/cleanup', msgid=msgid, sender=LOCAL_USER)
    _add_postfix(queue_b, t1 + timedelta(seconds=1), program='postfix/smtp',
                 recipient=OTHER_USER, status='sent')
    rspamd_b = _add_rspamd(msgid, t1, LOCAL_USER, [OTHER_USER])
    _correlate(rspamd_b)

    legs = {leg.queue_id: leg for leg in _legs(msgid)}
    assert set(legs) == {queue_a, queue_b}
    assert legs[queue_a].correlation_key == _legacy_key(msgid)
    assert legs[queue_b].correlation_key == _leg_key(msgid, queue_b)


def _lmtp(recipient, rest, session=None):
    return (f'lmtp({recipient})<1234><{session or uuid.uuid4().hex[:12]}>: '
            f'{rest} {MARKER}')


def _add_raw_dovecot(message, when=None):
    from app.database import get_db_context
    from app.models import RawServiceLog
    with get_db_context() as db:
        row = RawServiceLog(
            service='dovecot', time=when or datetime.utcnow(),
            message_hash=uuid.uuid4().hex,
            raw_data={'message': message, 'priority': 'info', 'program': 'dovecot'})
        db.add(row)
        db.commit()
        return row.id


def _pin_dovecot_watermark():
    from sqlalchemy import func
    from app.database import get_db_context
    from app.models import RawServiceLog, SystemSetting
    from app.scheduler import DOVECOT_WATERMARK_KEY
    with get_db_context() as db:
        max_id = db.query(func.max(RawServiceLog.id)).scalar() or 0
        db.add(SystemSetting(key=DOVECOT_WATERMARK_KEY, value=str(max_id)))
        db.commit()


def test_dovecot_verdict_goes_to_the_leg_that_was_delivered(env, monkeypatch):
    from app import scheduler as sched

    msgid, queue_a, queue_b, rspamd_a, rspamd_b = _seed_forward_scenario()
    _correlate(rspamd_a)
    _correlate(rspamd_b)

    sched._dovecot_pending.clear()
    monkeypatch.setattr(sched, 'dovecot_correlation_available', lambda: True)
    _pin_dovecot_watermark()

    _add_raw_dovecot(_lmtp(LOCAL_USER, f"sieve: msgid=<{msgid}>: stored mail into mailbox 'INBOX'"))
    _add_raw_dovecot(_lmtp(OTHER_USER, f'sieve: msgid=<{msgid}>: discarded message'))
    _add_raw_dovecot(_lmtp(UNKNOWN_USER,
                           f'sieve: msgid=<{msgid}>: rejected message from <s@d> (spam content)'))

    asyncio.run(sched.correlate_dovecot_logs())
    assert sched.job_status['correlate_dovecot']['status'] == 'success'
    sched._dovecot_pending.clear()

    legs = {leg.queue_id: leg for leg in _legs(msgid)}
    assert legs[queue_a].dovecot_status == 'stored'
    assert legs[queue_a].dovecot_mailbox == 'INBOX'
    assert legs[queue_b].dovecot_status == 'discarded'


def test_details_endpoint_lists_the_other_delivery(env):
    from fastapi.testclient import TestClient
    from app.main import app

    msgid, queue_a, queue_b, rspamd_a, rspamd_b = _seed_forward_scenario()
    _correlate(rspamd_a)
    _correlate(rspamd_b)

    legs = {leg.queue_id: leg for leg in _legs(msgid)}
    client = TestClient(app)

    payload = client.get(f'/api/message/{legs[queue_a].correlation_key}/details').json()
    related = payload['related_deliveries']
    assert [d['correlation_key'] for d in related] == [legs[queue_b].correlation_key]
    assert (related[0]['sender'], related[0]['recipient']) == (LOCAL_USER, OTHER_USER)
    assert related[0]['final_status'] == 'rejected'

    other = client.get(f'/api/message/{legs[queue_b].correlation_key}/details').json()
    assert [d['correlation_key'] for d in other['related_deliveries']] == [
        legs[queue_a].correlation_key]


def test_details_endpoint_takes_the_subject_from_another_delivery(env):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.database import get_db_context
    from app.models import MessageCorrelation

    msgid, queue_a, queue_b, rspamd_a, rspamd_b = _seed_forward_scenario()
    _correlate(rspamd_a)
    _correlate(rspamd_b)
    legs = {leg.queue_id: leg for leg in _legs(msgid)}
    with get_db_context() as db:
        db.query(MessageCorrelation).filter_by(correlation_key=legs[queue_a].correlation_key).update({'subject': 'Quarterly report'})
        db.query(MessageCorrelation).filter_by(correlation_key=legs[queue_b].correlation_key).update({'subject': None})
        db.commit()

    client = TestClient(app)
    assert client.get(f'/api/message/{legs[queue_b].correlation_key}/details').json()['subject'] == 'Quarterly report'
    assert client.get(f'/api/message/{legs[queue_a].correlation_key}/details').json()['subject'] == 'Quarterly report'


def test_details_endpoint_has_no_related_deliveries_for_a_single_delivery(env):
    from fastapi.testclient import TestClient
    from app.main import app

    msgid = _msgid()
    queue = _queue()
    t0 = datetime.utcnow() - timedelta(minutes=5)
    _add_postfix(queue, t0, program='postfix/cleanup', msgid=msgid, sender=REMOTE)
    _add_postfix(queue, t0 + timedelta(seconds=1), program='postfix/lmtp',
                 recipient=LOCAL_USER, status='sent', relay='dovecot')
    key = _correlate(_add_rspamd(msgid, t0, REMOTE, [LOCAL_USER]))

    payload = TestClient(app).get(f'/api/message/{key}/details').json()
    assert payload['related_deliveries'] == []


def test_list_shows_one_row_per_message(env):
    msgid, queue_a, queue_b, rspamd_a, rspamd_b = _seed_forward_scenario()
    _correlate(rspamd_a)
    _correlate(rspamd_b)
    single_msgid, single_key = _seed_single_delivery()

    payload = _list_messages()
    rows = {row['correlation_key']: row for row in payload['data']}

    assert payload['total'] == 2
    assert len(payload['data']) == 2

    legs = {leg.queue_id: leg for leg in _legs(msgid)}
    forwarded = rows[legs[queue_a].correlation_key]
    assert forwarded['message_id'] == msgid
    assert forwarded['queue_id'] == queue_a, 'the earliest leg represents the message'
    assert (forwarded['sender'], forwarded['recipient']) == (REMOTE, LOCAL_USER)
    assert forwarded['deliveries'] == 2
    assert legs[queue_b].correlation_key not in rows

    assert rows[single_key]['message_id'] == single_msgid
    assert rows[single_key]['deliveries'] == 1


def test_list_row_is_the_leg_the_search_matched(env):
    msgid, queue_a, queue_b, rspamd_a, rspamd_b = _seed_forward_scenario()
    _correlate(rspamd_a)
    _correlate(rspamd_b)

    payload = _list_messages(search=OTHER_USER)
    legs = {leg.queue_id: leg for leg in _legs(msgid)}

    assert payload['total'] == 1
    assert len(payload['data']) == 1
    row = payload['data'][0]
    assert row['correlation_key'] == legs[queue_b].correlation_key
    assert (row['sender'], row['recipient']) == (LOCAL_USER, OTHER_USER)
    assert row['deliveries'] == 2


def test_list_does_not_group_correlations_without_a_message_id(env):
    from app.database import get_db_context
    from app.models import MessageCorrelation

    t0 = datetime.utcnow() - timedelta(minutes=3)
    keys = [f'nomsgid-{uuid.uuid4().hex}-{MARKER}' for _ in range(2)]
    with get_db_context() as db:
        for index, key in enumerate(keys):
            db.add(MessageCorrelation(
                correlation_key=key, message_id=None, queue_id=_queue(),
                sender=REMOTE, recipient=LOCAL_USER,
                subject=f'no message id {MARKER}', direction='inbound',
                final_status='delivered', is_complete=True,
                first_seen=t0 + timedelta(seconds=index),
                last_seen=t0 + timedelta(seconds=index)))
        db.commit()

    payload = _list_messages()

    assert payload['total'] == 2
    assert sorted(row['correlation_key'] for row in payload['data']) == sorted(keys)
    assert [row['deliveries'] for row in payload['data']] == [1, 1]


def test_cleanup_duplicate_correlations_keeps_both_legs(env):
    from app.database import get_db_context
    from app.migrations import cleanup_duplicate_correlations

    msgid, queue_a, queue_b, rspamd_a, rspamd_b = _seed_forward_scenario()
    _correlate(rspamd_a)
    _correlate(rspamd_b)

    with get_db_context() as db:
        cleanup_duplicate_correlations(db)

    legs = {leg.queue_id: leg for leg in _legs(msgid)}
    assert set(legs) == {queue_a, queue_b}
    assert legs[queue_a].final_status == 'delivered'
    assert legs[queue_b].final_status == 'rejected'


def test_recorrelating_the_same_logs_creates_no_extra_leg(env):
    msgid, queue_a, queue_b, rspamd_a, rspamd_b = _seed_forward_scenario()

    _correlate(rspamd_a)
    _correlate(rspamd_b)
    first = {leg.queue_id: leg.correlation_key for leg in _legs(msgid)}

    _correlate(rspamd_a)
    _correlate(rspamd_b)
    second = {leg.queue_id: leg.correlation_key for leg in _legs(msgid)}

    assert first == second
    assert len(second) == 2
