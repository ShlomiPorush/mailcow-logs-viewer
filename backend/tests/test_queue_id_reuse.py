"""Postfix reuses short queue ids; two messages on one id stay two messages.

A short queue id is the queue file's inode and the microsecond it was made,
so the id comes back once the message has left the queue, minutes or days
later, for an unrelated message. The app used to read every line of a queue
id as one message: the later message took the earlier one's first-seen time
(days early in the Messages list), its lines in the details, and its status,
and its key was stamped on all of them.

The pure tests pin how the lines of one queue id are cut into messages
(app/correlation.py split_queue_occurrences). The database tests drive the
real correlation, refresh, details and upgrade paths.
"""
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


# ---------- line builders (Postfix's own wording) ----------

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
    """A PostfixLog-like line for the pure tests, parsed as the ingest parses it."""
    from app.correlation import parse_postfix_message
    program, message = _text(queue, kind, **fields)
    parsed = parse_postfix_message(message)
    return SimpleNamespace(
        id=next(_ids), time=when, program=program, message=message, queue_id=queue,
        message_id=parsed.get('message_id'), status=parsed.get('status'),
        sender=parsed.get('sender'), recipient=parsed.get('recipient'), correlation_key=None)


def _message(queue, start, msgid, sender, rcpt, outcome='sent', removed=True, opener='client'):
    """One whole message: received, delivered, removed, a second per step."""
    lines = [_line(queue, start, opener, sender=sender),
             _line(queue, start, 'msgid', msgid=msgid),
             _line(queue, start + timedelta(seconds=1), 'from', sender=sender),
             _line(queue, start + timedelta(seconds=2), outcome, rcpt=rcpt)]
    if removed:
        lines.append(_line(queue, start + timedelta(seconds=2), 'removed'))
    return lines


def _ids_of(lines):
    return {line.id for line in lines}


# ---------- cutting lines into messages ----------

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
    """mailcow returns the log newest first; ids inside a second say nothing."""
    a = _message('AAA3', T0, 'a@example.test', SENDER_A, RCPT_A)
    b = _message('AAA3', T0 + timedelta(seconds=10), 'b@example.test', SENDER_B, RCPT_B)
    for line, new_id in zip(b + a, range(1000, 2000)):
        line.id = new_id
    occurrences = split_queue_occurrences(a + b)
    assert [_ids_of(o.lines) for o in occurrences] == [_ids_of(a), _ids_of(b)]


def test_the_previous_message_removed_in_the_next_ones_first_second_is_a_boundary_line():
    """A delivered in S-1, A's "removed" and B's client= both in S: the
    "removed" may be A's (qmgr logs it after the file is gone), so it is
    neither message's own."""
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
    """Opened, delivered and removed within one second, days after the
    previous message logged "removed": every line is its own."""
    a = _message('AAA6', T0, 'a@example.test', SENDER_A, RCPT_A)
    s = T0 + timedelta(days=3)
    b = [_line('AAA6', s, 'client'), _line('AAA6', s, 'msgid', msgid='b@example.test'),
         _line('AAA6', s, 'sent', rcpt=RCPT_B), _line('AAA6', s, 'removed')]
    first, second = split_queue_occurrences(a + b)
    assert _ids_of(second.lines) == _ids_of(b) and not second.boundary


def test_postsuper_removed_ends_a_message():
    """A line after an admin's postsuper -d is someone else's, even a status
    line that arrived before the next message's receipt lines."""
    a = [_line('AAA7', T0, 'client'), _line('AAA7', T0, 'msgid', msgid='a@example.test'),
         _line('AAA7', T0 + timedelta(seconds=1), 'deferred', rcpt=RCPT_A),
         _line('AAA7', T0 + timedelta(hours=1), 'postsuper')]
    late = _line('AAA7', T0 + timedelta(days=1), 'bounced', rcpt=RCPT_B)
    first, second = split_queue_occurrences(a + [late])
    assert _ids_of(first.lines) == _ids_of(a)
    assert second.lines == [late] and not second.message_ids


def test_what_one_message_logs_never_cuts_it():
    """Two Message-ID headers (cleanup logs both), a slow upload, deferred
    retries over five days and a hold and release are one message."""
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
    """Postfix's own bounce notice gets a queue file through cleanup alone."""
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


# ---------- which occurrence is a message's ----------

def test_the_message_id_says_which_occurrence_is_whose():
    a = _message('AAB2', T0, 'a@example.test', SENDER_A, RCPT_A)
    b = _message('AAB2', T0 + timedelta(days=1), 'b@example.test', SENDER_B, RCPT_B)
    occurrences = split_queue_occurrences(a + b)
    assert occurrence_for(occurrences, 'b@example.test') is occurrences[1]
    assert occurrence_for(occurrences, 'a@example.test', near=T0 + timedelta(days=1)) is occurrences[0]
    # Another message's occurrence is never a guess, for a write or a view
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


# ---------- database ----------

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
    """Store pure-test lines as PostfixLog rows; returns their new ids in order."""
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
    from app import scheduler as sched
    from app.database import get_db_context
    from app.models import RspamdLog
    with get_db_context() as db:
        correlation = sched.correlate_single_message(db, db.get(RspamdLog, rspamd_id))
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
    """The bug as seen on a live server: the second message's first-seen time
    was the first message's, days early, and it held both messages' lines."""
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
    """A deferred message whose stored lines include a later message's bounce
    (stored by an earlier version) keeps its own status and drops the line."""
    from app import scheduler as sched
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
        sched._recompute_correlation_from_postfix(db, a)
        db.commit()
        db.refresh(a)
        assert a.final_status == 'deferred'
        assert set(a.postfix_log_ids) == set(m.a)


def _page(lines):
    """Ingest Postfix lines as one page from mailcow, as the scheduler does."""
    from app import scheduler as sched
    sched.seen_postfix.clear()
    entries = [{'time': str(int(l.time.replace(tzinfo=timezone.utc).timestamp())), 'program': l.program,
                'priority': 'info', 'message': l.message} for l in lines]
    sched._store_postfix_page(entries)


def test_a_late_delivery_of_the_second_message_reaches_it(env):
    """Two correlations on one queue id used to block every late status."""
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
    """An admin deleted A from the queue (postsuper -d). The id's next
    message's bounce arrives before its receipt lines: it is not A's."""
    from app.database import get_db_context
    from app.models import MessageCorrelation

    queue = _queue()
    msgid = _msgid('a')
    ids = _store([_line(queue, T0, 'client'), _line(queue, T0, 'msgid', msgid=msgid),
                  _line(queue, T0 + timedelta(seconds=1), 'deferred', rcpt=RCPT_A),
                  _line(queue, T0 + timedelta(hours=1), 'postsuper')])
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
    """B's lines arrive before A's delivery attempt: nothing yet shows two
    messages, and A takes B's bounce. When A's deferral arrives, the lines
    show two messages, and A is re-derived from its own lines."""
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
    assert _correlation(key).final_status == 'bounced'  # nothing tells the messages apart yet

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


# ---------- the upgrade repairs what earlier versions stored ----------

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
    """Both correlations as earlier versions stored them: the second message
    holds every line of the queue id, its key on all of them, and the first
    message's first-seen time."""
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
    # B took A's spam-pipe delivery: its status, its Rspamd spam mark, and A's sender
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

    # Nothing is left to repair: a second run writes nothing
    _repair()
    assert _correlation(key_b).last_seen == b.last_seen
    assert _stamps(m.a + m.b) == stamps


def test_the_upgrade_keeps_a_dovecot_discard(env):
    """Issue #65: Dovecot dropped the message by Sieve after Postfix logged
    sent. The repair re-derives the status from the message's own lines and
    keeps the discard, as the ingest does."""
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
