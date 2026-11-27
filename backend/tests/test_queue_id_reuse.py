import asyncio
import importlib.util
import itertools
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})


def split_queue_occurrences(lines):
    from app.correlation import split_queue_occurrences as split
    return split(lines)


def occurrence_for(*args, **kwargs):
    from app.correlation import occurrence_for as pick
    return pick(*args, **kwargs)


MARKER = 'queue-reuse.invalid'
SENDER_A = f'alice@{MARKER}'
SENDER_B = f'bob@{MARKER}'
RCPT_A = 'one@example.test'
RCPT_B = 'two@example.test'
T0 = datetime(2026, 10, 20, 9, 13, 0)


def _text(queue, kind, msgid=None, sender=None, rcpt=None):
    return {
        'client': ('postfix/smtpd', f'{queue}: client=mail.example.test[192.0.2.10]'),
        'uid': ('postfix/pickup', f'{queue}: uid=0 from=<{sender}>'),
        'msgid': ('postfix/cleanup', f'{queue}: message-id=<{msgid}>'),
        'from': ('postfix/qmgr', f'{queue}: from=<{sender}>, size=1200, nrcpt=1 (queue active)'),
        'sent': ('postfix/lmtp', f'{queue}: to=<{rcpt}>, relay=dovecot[192.0.2.20]:24, delay=1, '
                                 f'delays=0.1/0/0/0.9, dsn=2.0.0, status=sent (250 2.0.0 Saved)'),
        'deferred': ('postfix/smtp', f'{queue}: to=<{rcpt}>, relay=mx.example.test[192.0.2.30]:25, delay=1, '
                                     f'delays=0.1/0/0/0.9, dsn=4.7.1, status=deferred (450 4.7.1 Greylisted)'),
        'bounced': ('postfix/smtp', f'{queue}: to=<{rcpt}>, relay=mx.example.test[192.0.2.30]:25, delay=1, '
                                    f'delays=0.1/0/0/0.9, dsn=5.1.1, status=bounced (550 5.1.1 No such user)'),
        'spam': ('postfix/pipe', f'{queue}: to=<spam@localhost>, orig_to=<{rcpt}>, relay=rspamd-pipe-spam, '
                                 f'delay=1, delays=0.1/0/0/0.9, dsn=2.0.0, '
                                 f'status=sent (delivered via rspamd-pipe-spam service)'),
        'removed': ('postfix/qmgr', f'{queue}: removed'),
        'postsuper': ('postfix/postsuper', f'{queue}: removed'),
        'bounce_notice': ('postfix/bounce', f'{queue}: sender non-delivery notification: 0000AAAA'),
    }[kind]


_ids = itertools.count(1)


def _line(queue, when, kind, **fields):
    from app.correlation import parse_postfix_message
    program, message = _text(queue, kind, **fields)
    parsed = parse_postfix_message(message)
    return SimpleNamespace(
        id=next(_ids), time=when, program=program, message=message, queue_id=queue,
        message_id=parsed.get('message_id'), status=parsed.get('status'),
        sender=parsed.get('sender'), recipient=parsed.get('recipient'), correlation_key=None)


def _message(queue, start, msgid, sender, rcpt, outcome='sent', removed=True, opener='client'):
    lines = [_line(queue, start, opener, sender=sender),
             _line(queue, start, 'msgid', msgid=msgid),
             _line(queue, start + timedelta(seconds=1), 'from', sender=sender),
             _line(queue, start + timedelta(seconds=2), outcome, rcpt=rcpt)]
    if removed:
        lines.append(_line(queue, start + timedelta(seconds=2), 'removed'))
    return lines


def _ids_of(lines):
    return {line.id for line in lines}


def test_two_messages_days_apart_are_two_occurrences():
    a = _message('AAA1', T0, 'a@example.test', SENDER_A, RCPT_A)
    b = _message('AAA1', T0 + timedelta(days=2), 'b@example.test', SENDER_B, RCPT_B)
    occurrences = split_queue_occurrences(b + a)
    assert [_ids_of(o.lines) for o in occurrences] == [_ids_of(a), _ids_of(b)]
    assert all(not o.boundary for o in occurrences)


def test_a_message_without_removed_still_ends_at_the_next_opener():
    a = _message('AAA2', T0, 'a@example.test', SENDER_A, RCPT_A, removed=False)
    b = _message('AAA2', T0 + timedelta(minutes=1), 'b@example.test', SENDER_B, RCPT_B)
    occurrences = split_queue_occurrences(a + b)
    assert [_ids_of(o.lines) for o in occurrences] == [_ids_of(a), _ids_of(b)]


def test_line_order_inside_a_second_is_not_used():
    a = _message('AAA3', T0, 'a@example.test', SENDER_A, RCPT_A)
    b = _message('AAA3', T0 + timedelta(seconds=10), 'b@example.test', SENDER_B, RCPT_B)
    for line, new_id in zip(b + a, range(1000, 2000)):
        line.id = new_id
    occurrences = split_queue_occurrences(a + b)
    assert [_ids_of(o.lines) for o in occurrences] == [_ids_of(a), _ids_of(b)]


def test_the_previous_message_removed_in_the_next_ones_first_second_is_a_boundary_line():
    a = _message('AAA4', T0, 'a@example.test', SENDER_A, RCPT_A, removed=False)
    s = T0 + timedelta(seconds=3)
    a_removed = _line('AAA4', s, 'removed')
    b = [_line('AAA4', s, 'client'), _line('AAA4', s, 'msgid', msgid='b@example.test'),
         _line('AAA4', s + timedelta(seconds=1), 'sent', rcpt=RCPT_B)]
    first, second = split_queue_occurrences(a + [a_removed] + b)
    assert _ids_of(first.lines) == _ids_of(a)
    assert _ids_of(second.lines) == _ids_of(b)
    assert first.boundary == [a_removed] and second.boundary == [a_removed]


def test_a_bounce_in_the_opening_second_without_a_previous_removed_is_a_boundary_line():
    a = [_line('AAA5', T0, 'client'), _line('AAA5', T0, 'msgid', msgid='a@example.test'),
         _line('AAA5', T0 + timedelta(seconds=1), 'sent', rcpt=RCPT_A)]
    s = T0 + timedelta(seconds=2)
    bounce = _line('AAA5', s, 'bounced', rcpt='three@example.test')
    b = [_line('AAA5', s, 'client'), _line('AAA5', s, 'msgid', msgid='b@example.test')]
    first, second = split_queue_occurrences(a + [bounce] + b)
    assert bounce in first.boundary and bounce in second.boundary
    assert bounce not in first.lines + second.lines


def test_a_fast_message_after_a_removed_predecessor_keeps_all_its_lines():
    a = _message('AAA6', T0, 'a@example.test', SENDER_A, RCPT_A)
    s = T0 + timedelta(days=3)
    b = [_line('AAA6', s, 'client'), _line('AAA6', s, 'msgid', msgid='b@example.test'),
         _line('AAA6', s, 'sent', rcpt=RCPT_B), _line('AAA6', s, 'removed')]
    first, second = split_queue_occurrences(a + b)
    assert _ids_of(second.lines) == _ids_of(b) and not second.boundary


def test_a_line_after_qmgr_removed_is_another_messages():
    a = [_line('AAA7', T0, 'client'), _line('AAA7', T0, 'msgid', msgid='a@example.test'),
         _line('AAA7', T0 + timedelta(seconds=1), 'deferred', rcpt=RCPT_A),
         _line('AAA7', T0 + timedelta(hours=1), 'removed')]
    late = _line('AAA7', T0 + timedelta(days=1), 'bounced', rcpt=RCPT_B)
    first, second = split_queue_occurrences(a + [late])
    assert _ids_of(first.lines) == _ids_of(a)
    assert second.lines == [late] and not second.message_ids


def test_a_delivery_after_postsuper_removed_is_still_the_messages():
    a = [_line('AAA0', T0, 'client'), _line('AAA0', T0, 'msgid', msgid='a@example.test'),
         _line('AAA0', T0 + timedelta(seconds=1), 'deferred', rcpt=RCPT_A),
         _line('AAA0', T0 + timedelta(seconds=60), 'postsuper'),
         _line('AAA0', T0 + timedelta(seconds=61), 'sent', rcpt=RCPT_A)]
    assert [_ids_of(o.lines) for o in split_queue_occurrences(a)] == [_ids_of(a)]


def test_what_one_message_logs_never_cuts_it():
    q = 'AAA8'
    lines = [_line(q, T0, 'client'),
             _line(q, T0 + timedelta(seconds=30), 'msgid', msgid='a@example.test'),
             _line(q, T0 + timedelta(seconds=33), 'msgid', msgid='a@example.test'),
             _line(q, T0 + timedelta(seconds=34), 'from', sender=SENDER_A)]
    lines += [_line(q, T0 + timedelta(hours=h), 'deferred', rcpt=RCPT_A) for h in (1, 6, 30, 70, 119)]
    lines += [_line(q, T0 + timedelta(hours=120), 'sent', rcpt=RCPT_A),
              _line(q, T0 + timedelta(hours=120), 'removed')]
    assert len(split_queue_occurrences(lines)) == 1


def test_a_server_bounce_without_an_opener_is_its_own_message():
    a = _message('AAA9', T0, 'a@example.test', SENDER_A, RCPT_A, outcome='bounced', removed=False)
    later = T0 + timedelta(minutes=5)
    notice = [_line('AAA9', later, 'msgid', msgid='notice@example.test'),
              _line('AAA9', later + timedelta(seconds=1), 'sent', rcpt=SENDER_A)]
    first, second = split_queue_occurrences(a + notice)
    assert _ids_of(second.lines) == _ids_of(notice)


def test_a_local_submission_opens_with_pickup():
    a = _message('AAB1', T0, 'a@example.test', SENDER_A, RCPT_A, removed=False)
    b = _message('AAB1', T0 + timedelta(minutes=2), 'b@example.test', SENDER_B, RCPT_B, opener='uid')
    assert [_ids_of(o.lines) for o in split_queue_occurrences(a + b)] == [_ids_of(a), _ids_of(b)]


def test_the_message_id_says_which_occurrence_is_whose():
    a = _message('AAB2', T0, 'a@example.test', SENDER_A, RCPT_A)
    b = _message('AAB2', T0 + timedelta(days=1), 'b@example.test', SENDER_B, RCPT_B)
    occurrences = split_queue_occurrences(a + b)
    assert occurrence_for(occurrences, 'b@example.test') is occurrences[1]
    assert occurrence_for(occurrences, 'a@example.test', near=T0 + timedelta(days=1)) is occurrences[0]
    assert occurrence_for(occurrences, 'c@example.test') is None
    assert occurrence_for([occurrences[1]], 'c@example.test') is None
    assert occurrence_for([occurrences[1]], 'c@example.test', strict=False) is occurrences[1]


def test_the_same_message_id_twice_on_one_queue_id_is_not_decided_for_a_write():
    a = _message('AAB3', T0, 'same@example.test', SENDER_A, RCPT_A)
    b = _message('AAB3', T0 + timedelta(days=1), 'same@example.test', SENDER_B, RCPT_B)
    occurrences = split_queue_occurrences(a + b)
    assert occurrence_for(occurrences, 'same@example.test') is None
    assert occurrence_for(occurrences, 'same@example.test', near=T0 + timedelta(days=1),
                          strict=False) is occurrences[1]


def test_one_occurrence_without_a_message_id_line_is_the_messages():
    lines = [_line('AAB4', T0, 'deferred', rcpt=RCPT_A)]
    occurrences = split_queue_occurrences(lines)
    assert occurrence_for(occurrences, 'a@example.test') is occurrences[0]
    two = split_queue_occurrences(lines + [_line('AAB4', T0 + timedelta(days=1), 'client'),
                                           _line('AAB4', T0 + timedelta(days=1), 'sent', rcpt=RCPT_B)])
    assert occurrence_for(two, 'a@example.test') is None


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


QUEUES = set()


def _queue():
    queue = uuid.uuid4().hex[:11].upper()
    QUEUES.add(queue)
    return queue


def _cleanup():
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog, RspamdLog
    with get_db_context() as db:
        if QUEUES:
            db.query(PostfixLog).filter(PostfixLog.queue_id.in_(list(QUEUES))).delete(synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.message_id.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.query(MessageCorrelation).filter(
            MessageCorrelation.message_id.like(f'%{MARKER}%')).delete(synchronize_session=False)
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


def _msgid(tag):
    return f'{tag}-{uuid.uuid4().hex}@{MARKER}'


def _store(lines):
    from app.database import get_db_context
    from app.models import PostfixLog
    with get_db_context() as db:
        rows = [PostfixLog(time=l.time, program=l.program, priority='info', message=l.message,
                           queue_id=l.queue_id, message_id=l.message_id, status=l.status,
                           sender=l.sender, recipient=l.recipient) for l in lines]
        db.add_all(rows)
        db.commit()
        return [row.id for row in rows]


def _rspamd(msgid, when, sender, rcpt, action='no action', is_spam=False):
    from app.database import get_db_context
    from app.models import RspamdLog
    with get_db_context() as db:
        row = RspamdLog(time=when, message_id=msgid, sender_smtp=sender, recipients_smtp=[rcpt],
                        score=1.0, required_score=15.0, action=action, is_spam=is_spam,
                        direction='inbound', user='unknown', symbols={})
        db.add(row)
        db.commit()
        return row.id


def _correlate(rspamd_id):
    from app.services import correlation_jobs
    from app.database import get_db_context
    from app.models import RspamdLog
    with get_db_context() as db:
        correlation = correlation_jobs.correlate_single_message(db, db.get(RspamdLog, rspamd_id))
        return correlation.correlation_key if correlation else None


def _correlation(key):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    with get_db_context() as db:
        row = db.query(MessageCorrelation).filter(MessageCorrelation.correlation_key == key).first()
        db.expunge(row)
        return row


def _stamps(ids):
    from app.database import get_db_context
    from app.models import PostfixLog
    with get_db_context() as db:
        return {row.id: row.correlation_key for row in db.query(PostfixLog).filter(PostfixLog.id.in_(ids))}


def _two_messages(queue, gap=timedelta(days=2), b_outcome='sent', a_outcome='sent', b_removed=True):
    msgid_a, msgid_b = _msgid('a'), _msgid('b')
    t1 = T0 + gap
    a = _store(_message(queue, T0, msgid_a, SENDER_A, RCPT_A, outcome=a_outcome))
    b = _store(_message(queue, t1, msgid_b, SENDER_B, RCPT_B, outcome=b_outcome, removed=b_removed))
    return SimpleNamespace(msgid_a=msgid_a, msgid_b=msgid_b, t1=t1, a=a, b=b)


def test_the_second_message_on_a_queue_id_gets_its_own_time_and_lines(env):
    queue = _queue()
    m = _two_messages(queue)
    key_a = _correlate(_rspamd(m.msgid_a, T0, SENDER_A, RCPT_A))
    key_b = _correlate(_rspamd(m.msgid_b, m.t1, SENDER_B, RCPT_B))

    a, b = _correlation(key_a), _correlation(key_b)
    assert b.first_seen == m.t1
    assert set(b.postfix_log_ids) == set(m.b)
    assert set(a.postfix_log_ids) == set(m.a)
    stamps = _stamps(m.a + m.b)
    assert {stamps[i] for i in m.a} == {key_a}
    assert {stamps[i] for i in m.b} == {key_b}


def test_the_details_show_only_the_messages_own_lines(env):
    from fastapi.testclient import TestClient
    from app.main import app

    queue = _queue()
    m = _two_messages(queue, gap=timedelta(minutes=5))
    key_a = _correlate(_rspamd(m.msgid_a, T0, SENDER_A, RCPT_A))
    key_b = _correlate(_rspamd(m.msgid_b, m.t1, SENDER_B, RCPT_B))

    client = TestClient(app)
    shown_b = [line['message'] for line in client.get(f'/api/message/{key_b}/details').json()['postfix']]
    shown_a = [line['message'] for line in client.get(f'/api/message/{key_a}/details').json()['postfix']]
    assert any(m.msgid_b in text for text in shown_b) and not any(m.msgid_a in text for text in shown_b)
    assert not any(RCPT_A in text for text in shown_b)
    assert any(m.msgid_a in text for text in shown_a) and not any(RCPT_B in text for text in shown_a)
    compact = client.get(f'/api/message/{key_b}').json()['postfix']
    assert not any(RCPT_A in line['message'] for line in compact)


def test_a_status_is_never_taken_from_another_message(env):
    from app.services import correlation_jobs
    from app.database import get_db_context
    from app.models import MessageCorrelation

    queue = _queue()
    m = _two_messages(queue, a_outcome='deferred', b_outcome='bounced')
    with get_db_context() as db:
        a = MessageCorrelation(correlation_key=uuid.uuid4().hex, message_id=m.msgid_a, queue_id=queue,
                               final_status='deferred', is_complete=True, postfix_log_ids=m.a + m.b,
                               first_seen=T0, last_seen=T0, created_at=datetime.utcnow())
        db.add(a)
        db.commit()
        correlation_jobs.recompute_correlation_from_postfix(db, a)
        db.commit()
        db.refresh(a)
        assert a.final_status == 'deferred'
        assert set(a.postfix_log_ids) == set(m.a)


def _page(lines):
    from app import scheduler as sched
    sched.seen_postfix.clear()
    entries = [{'time': str(int(l.time.replace(tzinfo=timezone.utc).timestamp())), 'program': l.program,
                'priority': 'info', 'message': l.message} for l in lines]
    sched._store_postfix_page(entries)


def test_a_late_delivery_of_the_second_message_reaches_it(env):
    queue = _queue()
    m = _two_messages(queue, gap=timedelta(hours=3), b_outcome='deferred', b_removed=False)
    key_a = _correlate(_rspamd(m.msgid_a, T0, SENDER_A, RCPT_A))
    key_b = _correlate(_rspamd(m.msgid_b, m.t1, SENDER_B, RCPT_B))
    assert _correlation(key_b).final_status == 'deferred'

    _page([_line(queue, m.t1 + timedelta(minutes=30), 'sent', rcpt=RCPT_B),
           _line(queue, m.t1 + timedelta(minutes=30), 'removed')])

    assert _correlation(key_b).final_status == 'delivered'
    assert _correlation(key_a).final_status == 'delivered'


def test_a_line_after_a_removed_message_is_not_that_messages(env):
    from app.database import get_db_context
    from app.models import MessageCorrelation

    queue = _queue()
    msgid = _msgid('a')
    ids = _store([_line(queue, T0, 'client'), _line(queue, T0, 'msgid', msgid=msgid),
                  _line(queue, T0 + timedelta(seconds=1), 'deferred', rcpt=RCPT_A),
                  _line(queue, T0 + timedelta(hours=1), 'removed')])
    key = uuid.uuid4().hex
    with get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=key, message_id=msgid, queue_id=queue,
                                  final_status='deferred', is_complete=True, postfix_log_ids=ids,
                                  first_seen=T0, last_seen=T0, created_at=datetime.utcnow()))
        db.commit()

    _page([_line(queue, T0 + timedelta(hours=2), 'bounced', rcpt=RCPT_B)])

    assert _correlation(key).final_status == 'deferred'
    assert set(_correlation(key).postfix_log_ids) == set(ids)


def test_a_message_given_another_ones_bounce_gets_its_own_status_back(env):
    from app.database import get_db_context
    from app.models import MessageCorrelation

    queue = _queue()
    msgid_a, msgid_b = _msgid('a'), _msgid('b')
    a_ids = _store([_line(queue, T0, 'msgid', msgid=msgid_a)])
    key = uuid.uuid4().hex
    with get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=key, message_id=msgid_a, queue_id=queue,
                                  is_complete=True, postfix_log_ids=a_ids,
                                  first_seen=T0, last_seen=T0, created_at=datetime.utcnow()))
        db.commit()

    _page([_line(queue, T0 + timedelta(seconds=10), 'msgid', msgid=msgid_b),
           _line(queue, T0 + timedelta(seconds=11), 'bounced', rcpt=RCPT_B)])
    assert _correlation(key).final_status == 'bounced'

    _page([_line(queue, T0 + timedelta(seconds=5), 'deferred', rcpt=RCPT_A)])

    a = _correlation(key)
    assert a.final_status == 'deferred'
    assert len(a.postfix_log_ids) == 2
    stamps = _stamps(a.postfix_log_ids)
    assert set(stamps.values()) == {key}


def test_the_messages_list_counts_each_messages_own_recipients(env):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    from app.services.message_recipients import page_deliveries

    queue = _queue()
    m = _two_messages(queue)
    key_a = _correlate(_rspamd(m.msgid_a, T0, SENDER_A, RCPT_A))
    key_b = _correlate(_rspamd(m.msgid_b, m.t1, SENDER_B, RCPT_B))
    with get_db_context() as db:
        legs = db.query(MessageCorrelation).filter(MessageCorrelation.correlation_key.in_([key_a, key_b])).all()
        found = page_deliveries(db, legs)
    assert {to for to, _ in found[key_a]} == {RCPT_A}
    assert {to for to, _ in found[key_b]} == {RCPT_B}


def _migration():
    path = next((Path(__file__).resolve().parents[1] / 'alembic' / 'versions').glob('*_queue_id_reuse_repair.py'))
    spec = importlib.util.spec_from_file_location('queue_id_reuse_repair', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _repair():
    from app.database import engine
    with engine.begin() as connection:
        return _migration().repair(connection)


def _as_stored_before(queue, m, *, b_status, b_sender, b_is_spam=False, dovecot=None):
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog
    rspamd_a = _rspamd(m.msgid_a, T0, SENDER_A, RCPT_A)
    rspamd_b = _rspamd(m.msgid_b, m.t1, SENDER_B, RCPT_B, is_spam=b_is_spam)
    key_a, key_b = uuid.uuid4().hex, uuid.uuid4().hex
    with get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=key_a, message_id=m.msgid_a, queue_id=queue,
                                  sender=SENDER_A, recipient=RCPT_A, rspamd_log_id=rspamd_a,
                                  final_status='delivered', is_complete=True, postfix_log_ids=m.a,
                                  first_seen=T0, last_seen=T0))
        db.add(MessageCorrelation(correlation_key=key_b, message_id=m.msgid_b, queue_id=queue,
                                  sender=b_sender, recipient=RCPT_B, rspamd_log_id=rspamd_b,
                                  final_status=b_status, dovecot_status=dovecot, is_complete=True,
                                  postfix_log_ids=m.a + m.b, first_seen=T0, last_seen=T0))
        db.query(PostfixLog).filter(PostfixLog.id.in_(m.a + m.b)).update(
            {PostfixLog.correlation_key: key_b}, synchronize_session=False)
        db.commit()
    return key_a, key_b, rspamd_b


def test_the_upgrade_gives_each_message_back_its_own_lines_time_and_status(env):
    from app.database import get_db_context
    from app.models import RspamdLog

    queue = _queue()
    m = _two_messages(queue, a_outcome='spam')
    key_a, key_b, rspamd_b = _as_stored_before(queue, m, b_status='spam', b_sender=SENDER_A, b_is_spam=True)

    assert _repair() >= 2

    b = _correlation(key_b)
    assert b.first_seen == m.t1
    assert set(b.postfix_log_ids) == set(m.b)
    assert b.final_status == 'delivered'
    assert b.sender == SENDER_B
    with get_db_context() as db:
        assert db.get(RspamdLog, rspamd_b).is_spam is False
    stamps = _stamps(m.a + m.b)
    assert {stamps[i] for i in m.a} == {key_a}
    assert {stamps[i] for i in m.b} == {key_b}
    a = _correlation(key_a)
    assert (a.first_seen, a.final_status, set(a.postfix_log_ids)) == (T0, 'spam', set(m.a))

    _repair()
    assert _correlation(key_b).last_seen == b.last_seen
    assert _stamps(m.a + m.b) == stamps


def test_the_upgrade_keeps_a_dovecot_discard(env):
    queue = _queue()
    m = _two_messages(queue, a_outcome='bounced')
    _, key_b, _ = _as_stored_before(queue, m, b_status='bounced', b_sender=SENDER_B, dovecot='discarded')

    _repair()

    b = _correlation(key_b)
    assert b.final_status == 'discarded'
    assert b.first_seen == m.t1


def test_the_upgrade_leaves_one_message_queue_ids_alone(env):
    from app.database import get_db_context
    from app.models import MessageCorrelation

    queue = _queue()
    msgid = _msgid('a')
    lines = [_line(queue, T0, 'client'), _line(queue, T0, 'msgid', msgid=msgid),
             _line(queue, T0 + timedelta(seconds=1), 'deferred', rcpt=RCPT_A),
             _line(queue, T0 + timedelta(days=2), 'sent', rcpt=RCPT_A),
             _line(queue, T0 + timedelta(days=2), 'removed')]
    ids = _store(lines)
    key = uuid.uuid4().hex
    with get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=key, message_id=msgid, queue_id=queue,
                                  final_status='delivered', is_complete=True, postfix_log_ids=ids,
                                  first_seen=T0 - timedelta(seconds=1), last_seen=T0))
        db.commit()

    _repair()

    row = _correlation(key)
    assert (row.first_seen, row.final_status, row.postfix_log_ids) == (T0 - timedelta(seconds=1), 'delivered', ids)


def test_a_delivery_after_deferrals_is_delivered_whatever_order_the_lines_are_stored_in(env):
    queue = _queue()
    msgid = _msgid('a')
    _store([_line(queue, T0 + timedelta(hours=1), 'sent', rcpt=RCPT_A),
            _line(queue, T0 + timedelta(hours=1), 'removed')])
    _store([_line(queue, T0, 'client'), _line(queue, T0, 'msgid', msgid=msgid),
            _line(queue, T0 + timedelta(seconds=1), 'deferred', rcpt=RCPT_A)][::-1])
    key = _correlate(_rspamd(msgid, T0, SENDER_A, RCPT_A))
    assert _correlation(key).final_status == 'delivered'


def test_lines_that_do_not_yet_tell_two_messages_apart_are_given_to_neither(env):
    from app.database import get_db_context
    from app.models import MessageCorrelation

    queue = _queue()
    msgid_a, msgid_b = _msgid('a'), _msgid('b')
    a_ids = _store([_line(queue, T0, 'msgid', msgid=msgid_a)])
    b_ids = _store([_line(queue, T0 + timedelta(seconds=10), 'msgid', msgid=msgid_b)])
    keys = uuid.uuid4().hex, uuid.uuid4().hex
    with get_db_context() as db:
        for key, msgid, ids, when in ((keys[0], msgid_a, a_ids, T0), (keys[1], msgid_b, b_ids, T0 + timedelta(seconds=10))):
            db.add(MessageCorrelation(correlation_key=key, message_id=msgid, queue_id=queue, is_complete=True,
                                      postfix_log_ids=ids, first_seen=when, last_seen=when,
                                      created_at=datetime.utcnow()))
        db.commit()

    _page([_line(queue, T0 + timedelta(seconds=11), 'bounced', rcpt=RCPT_B)])

    a, b = _correlation(keys[0]), _correlation(keys[1])
    assert (a.final_status, a.postfix_log_ids) == (None, a_ids)
    assert (b.final_status, b.postfix_log_ids) == (None, b_ids)


def test_the_recipient_count_reads_the_messages_own_current_lines(env):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    from app.services.message_recipients import page_deliveries

    queue = _queue()
    msgid = _msgid('a')
    _store([_line(queue, T0, 'client'), _line(queue, T0, 'msgid', msgid=msgid),
            _line(queue, T0 + timedelta(seconds=1), 'sent', rcpt=RCPT_A)])
    key = _correlate(_rspamd(msgid, T0, SENDER_A, RCPT_A))
    _store([_line(queue, T0 + timedelta(seconds=2), 'sent', rcpt='three@example.test'),
            _line(queue, T0 + timedelta(seconds=2), 'removed'),
            _line(queue, T0 + timedelta(hours=2), 'msgid', msgid='notice@example.test'),
            _line(queue, T0 + timedelta(hours=2, seconds=1), 'sent', rcpt=RCPT_B)])
    with get_db_context() as db:
        leg = db.query(MessageCorrelation).filter(MessageCorrelation.correlation_key == key).one()
        found = page_deliveries(db, [leg])
    assert {to for to, _ in found[key]} == {RCPT_A, 'three@example.test'}


def test_the_upgrade_finds_a_line_stored_after_a_removed_message(env):
    from app.database import get_db_context
    from app.models import MessageCorrelation

    queue = _queue()
    msgid = _msgid('a')
    own = _store([_line(queue, T0, 'client'), _line(queue, T0, 'msgid', msgid=msgid),
                  _line(queue, T0 + timedelta(seconds=1), 'deferred', rcpt=RCPT_A),
                  _line(queue, T0 + timedelta(hours=1), 'removed')])
    late = _store([_line(queue, T0 + timedelta(days=1), 'bounced', rcpt=RCPT_B)])
    key = uuid.uuid4().hex
    with get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=key, message_id=msgid, queue_id=queue,
                                  final_status='bounced', is_complete=True, postfix_log_ids=own + late,
                                  first_seen=T0, last_seen=T0))
        db.commit()

    _repair()

    row = _correlation(key)
    assert (row.final_status, set(row.postfix_log_ids)) == ('deferred', set(own))


def test_the_upgrade_keeps_a_delivery_logged_after_postsuper_removed(env):
    from app.database import get_db_context
    from app.models import MessageCorrelation

    queue = _queue()
    msgid = _msgid('a')
    ids = _store([_line(queue, T0, 'client'), _line(queue, T0, 'msgid', msgid=msgid),
                  _line(queue, T0 + timedelta(seconds=1), 'deferred', rcpt=RCPT_A),
                  _line(queue, T0 + timedelta(seconds=60), 'postsuper'),
                  _line(queue, T0 + timedelta(seconds=61), 'sent', rcpt=RCPT_A)])
    key = uuid.uuid4().hex
    with get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=key, message_id=msgid, queue_id=queue,
                                  final_status='delivered', is_complete=True, postfix_log_ids=ids,
                                  first_seen=T0, last_seen=T0))
        db.commit()

    _repair()

    row = _correlation(key)
    assert (row.final_status, row.postfix_log_ids) == ('delivered', ids)


def test_two_waiting_messages_do_not_both_take_lines_they_share(env, monkeypatch):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    from app.services import correlation_jobs

    queue = _queue()
    msgid_a, msgid_b = _msgid('a'), _msgid('b')
    _store([_line(queue, T0, 'msgid', msgid=msgid_a),
            _line(queue, T0 + timedelta(seconds=10), 'msgid', msgid=msgid_b),
            _line(queue, T0 + timedelta(seconds=11), 'bounced', rcpt=RCPT_B)])
    keys = uuid.uuid4().hex, uuid.uuid4().hex
    with get_db_context() as db:
        for key, msgid in zip(keys, (msgid_a, msgid_b)):
            db.add(MessageCorrelation(correlation_key=key, message_id=msgid, is_complete=False,
                                      first_seen=T0, last_seen=T0, created_at=datetime.utcnow()))
        db.commit()

    monkeypatch.setattr(correlation_jobs, "update_job_status", lambda *a: None)
    monkeypatch.setattr(correlation_jobs.settings._inner, "max_correlation_age_minutes", 60)
    correlation_jobs.complete_incomplete_correlations()

    assert sum(_correlation(key).queue_id == queue for key in keys) == 1


def test_the_postfix_list_describes_the_message_the_filter_found(env):
    from fastapi.testclient import TestClient
    from app.main import app

    queue = _queue()
    _two_messages(queue)
    client = TestClient(app)
    by_sender = client.get('/api/logs/postfix', params={'queue_id': queue, 'sender': SENDER_A}).json()['data']
    assert [row['sender'] for row in by_sender] == [SENDER_A]
    latest = client.get('/api/logs/postfix', params={'queue_id': queue}).json()['data']
    assert [row['sender'] for row in latest] == [SENDER_B]


def test_creation_and_completion_never_link_lines_at_the_same_time(monkeypatch):
    from app import scheduler
    from app.services import correlation_jobs

    held = []
    monkeypatch.setattr(correlation_jobs, 'run_correlation',
                        lambda **kwargs: held.append(scheduler._correlation_link_lock.locked()))
    monkeypatch.setattr(correlation_jobs, 'complete_incomplete_correlations',
                        lambda **kwargs: held.append(scheduler._correlation_link_lock.locked()))
    scheduler._run_correlation_sync()
    scheduler._complete_incomplete_correlations_sync()
    assert held == [True, True]
    assert not scheduler._correlation_link_lock.locked()
