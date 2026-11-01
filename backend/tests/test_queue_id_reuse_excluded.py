"""A message of an excluded address never takes the next message on its queue id with it.

Postfix reuses a queue id once the message that had it left the queue, which
qmgr logs as "removed". The excluded-address rules (BLACKLIST_EMAILS), the
block evidence and the written recipient read every line of a queue id
within a day as one message: the next message on the id, an hour later, was
deleted, never stored, hidden, or copied into another message's evidence.
Now a "removed" between two lines makes them two messages; without one,
the rules stay as they were.

Postfix logs whole seconds and the order of lines inside one is unknown, so
a "removed" in the later line's own second proves nothing. Times here are
whole seconds, as stored ones always are. Dummy data only, against the test
PostgreSQL.
"""
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

MARKER = 'reuse-excluded.invalid'
LISTED = f'secret@{MARKER}'
NORMAL = f'normal@{MARKER}'
SENDER = f'sender@{MARKER}'
BASE = datetime.utcnow().replace(microsecond=0) - timedelta(hours=3)
A_START = BASE
B_START = BASE + timedelta(hours=1)
SECOND = timedelta(seconds=1)


# ---------- the rule ----------

def test_a_removed_tells_two_times_apart_by_whole_seconds():
    from app.services.excluded_addresses import same_message, separated
    t = datetime(2026, 10, 20, 9, 0, 0)
    removed = [t + 2 * SECOND]
    assert separated(t, t + 3 * SECOND, removed)
    assert separated(t + 3 * SECOND, t, removed)
    # Delivered and removed in one second, the next message later
    assert separated(t + 2 * SECOND, t + 3 * SECOND, removed)
    # In the later time's own second the next message may already have started
    assert not separated(t, t + 2 * SECOND, removed)
    assert not separated(t + 2 * SECOND, t + 2 * SECOND, removed)
    assert not same_message(t, t + 3 * SECOND, removed)
    assert same_message(t, t + 3 * SECOND, [])
    assert not same_message(t, t + timedelta(days=2), [])


def test_the_span_deleted_is_exactly_the_times_of_the_same_message():
    """Deletion goes by a time span per listed line (message_span); it must
    hold exactly what same_message() says, also for times between seconds."""
    from app.services.excluded_addresses import message_span, same_message
    t = datetime(2026, 10, 20, 9, 0, 5, 300000)
    for removed in ([], [t - 3 * SECOND], [t], [t + 2 * SECOND], [t - 3 * SECOND, t + 2 * SECOND],
                    [t.replace(microsecond=0) + timedelta(milliseconds=10)]):
        lo, hi, before = message_span(t, removed)
        for ms in range(-6000, 6000, 100):
            w = t + timedelta(milliseconds=ms)
            inside = lo <= w <= hi and (before is None or w < before)
            assert inside == same_message(t, w, removed), (removed, w)


def test_forgetting_keeps_where_a_listed_message_ended_while_it_is_remembered():
    """A listed line seen again keeps its message remembered; where that
    message ended must stay known as long, or its neighbour would be taken."""
    from app.services import excluded_addresses as ex
    queue, t = f'MEM{uuid.uuid4().hex[:8].upper()}', datetime(2026, 10, 20, 9, 0, 0)
    ex.remember_listed_queue(queue, t)
    ex.remember_removed(queue, t + SECOND)
    with ex._listed_queues_lock:
        ex._removed_queues[queue] = [(r, at - timedelta(days=2)) for r, at in ex._removed_queues[queue]]
    ex._last_forget = None
    ex.forget_old_queues(datetime.utcnow())
    assert ex.remembered_removed(queue) == [t + SECOND]
    assert not ex.queue_was_listed(queue, t + timedelta(hours=1))
    with ex._listed_queues_lock:
        ex._listed_queues.pop(queue, None)
        ex._removed_queues.pop(queue, None)


# ---------- data ----------

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
    from app.models import MessageCorrelation, PostfixLog, RspamdLog, SpamSuppression
    with get_db_context() as db:
        if QUEUES:
            db.query(PostfixLog).filter(PostfixLog.queue_id.in_(list(QUEUES))).delete(synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.message_id.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.query(MessageCorrelation).filter(
            MessageCorrelation.correlation_key.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.query(SpamSuppression).filter(SpamSuppression.email.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def env(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app import scheduler
    from app.config import settings
    from app.database import init_db
    init_db()
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    monkeypatch.setattr(settings._inner, 'blacklist_emails', '')
    monkeypatch.setattr(scheduler, 'seen_postfix', set())
    _cleanup()
    yield SimpleNamespace(listed=lambda: monkeypatch.setattr(settings._inner, 'blacklist_emails', LISTED))
    _cleanup()


def _message(queue, start, rcpt, removed=True, one_second=False, status='sent'):
    """One message as Postfix logs it: (time, program, text)."""
    step = timedelta(0) if one_second else SECOND
    lines = [
        (start, 'postfix/smtpd', f'{queue}: client=mail.example.test[192.0.2.10]'),
        (start, 'postfix/cleanup', f'{queue}: message-id=<{queue}.{start:%H%M%S}@{MARKER}>'),
        (start + step, 'postfix/qmgr', f'{queue}: from=<{SENDER}>, size=1200, nrcpt=1 (queue active)'),
        (start + 2 * step, 'postfix/lmtp', f'{queue}: to=<{rcpt}>, relay=dovecot[192.0.2.20]:24, delay=1, '
                                           f'delays=0.1/0/0/0.9, dsn={"2.0.0" if status == "sent" else "5.1.1"}, '
                                           f'status={status} (250 2.0.0 Saved)'),
    ]
    if removed:
        lines.append((start + 2 * step, 'postfix/qmgr', f'{queue}: removed'))
    return lines


def _ingest(*pages):
    from app import scheduler
    for page in pages:
        scheduler._store_postfix_page([
            {'time': str(int(when.replace(tzinfo=timezone.utc).timestamp())), 'program': program,
             'priority': 'info', 'message': text} for when, program, text in page])


def _store(lines):
    from app.correlation import parse_postfix_message
    from app.database import get_db_context
    from app.models import PostfixLog
    with get_db_context() as db:
        for when, program, text in lines:
            parsed = parse_postfix_message(text)
            db.add(PostfixLog(time=when, program=program, priority='info', message=text,
                              queue_id=parsed.get('queue_id'), message_id=parsed.get('message_id'),
                              sender=parsed.get('sender'), recipient=parsed.get('recipient'),
                              status=parsed.get('status')))
        db.commit()


def _correlation(queue, start, rcpt, written=None):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    key = f'{uuid.uuid4().hex[:12]}@{MARKER}'
    with get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=key, message_id=f'{queue}.{start:%H%M%S}@{MARKER}',
                                  queue_id=queue, sender=SENDER, recipient=rcpt, subject=f'subject {MARKER}',
                                  written_recipients=written, is_complete=True, direction='inbound',
                                  final_status='delivered', first_seen=start, last_seen=start, created_at=start))
        db.commit()
    return key


def _texts(lines):
    return sorted(text for _, _, text in lines)


def _stored(queue):
    from app.database import get_db_context
    from app.models import PostfixLog
    with get_db_context() as db:
        return sorted(l.message for l in db.query(PostfixLog).filter(PostfixLog.queue_id == queue))


def _keys():
    from app.database import get_db_context
    from app.models import MessageCorrelation
    with get_db_context() as db:
        return {c.correlation_key for c in db.query(MessageCorrelation).filter(
            MessageCorrelation.correlation_key.like(f'%{MARKER}%'))}


def _client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


# ---------- the Postfix ingest ----------

def _orders(queue):
    a, b = _message(queue, A_START, LISTED), _message(queue, B_START, NORMAL)
    a_lines, a_removed = a[:-1], a[-1:]
    return {
        'one page, the next message first': [b + a],
        'the listed message, then the next one': [a, b],
        'the next message first': [b, a],
        'its "removed" in a page of its own': [a_lines, a_removed, b],
        'its "removed" stored before the line naming the address': [a[:3] + a_removed, a[3:4], b],
    }


@pytest.mark.parametrize('order', list(_orders('Q')))
def test_the_ingest_stores_the_next_message_on_a_listed_messages_queue_id(env, order):
    env.listed()
    queue = _queue()
    _ingest(*_orders(queue)[order])
    assert _stored(queue) == _texts(_message(queue, B_START, NORMAL))


def test_a_listed_message_without_removed_still_takes_the_queue_id_for_a_day(env):
    """Nothing proves two messages: as before, nothing of the queue id is stored."""
    env.listed()
    queue = _queue()
    _ingest(_message(queue, A_START, LISTED, removed=False), _message(queue, B_START, NORMAL))
    assert _stored(queue) == []


def test_a_message_logged_in_one_second_is_one_message(env):
    """Received, delivered and removed in one second, as a fast local delivery
    is: every line of it is the listed message's, the next one is not."""
    env.listed()
    queue = _queue()
    _ingest(_message(queue, A_START, LISTED, one_second=True),
            _message(queue, A_START + timedelta(minutes=1), NORMAL))
    assert _stored(queue) == _texts(_message(queue, A_START + timedelta(minutes=1), NORMAL))


def test_the_next_messages_lines_in_the_removed_second_are_treated_as_before(env):
    """The next message started in the second the listed one was removed: its
    lines of that second cannot be told from the listed message's and are not
    stored, as before; its later lines are."""
    env.listed()
    queue = _queue()
    a = _message(queue, A_START, LISTED)
    removed_at = a[-1][0]
    b = _message(queue, removed_at, NORMAL)
    _ingest(a, b)
    assert _stored(queue) == _texts([line for line in b if line[0] > removed_at])


def test_a_queue_id_listed_while_a_page_is_read_still_tells_its_messages_apart(env, monkeypatch):
    """The Rspamd ingest lists a message (B) while the Postfix ingest reads a
    page of the message before it (A), whose "removed" is stored: A's late
    line is checked against B with A's "removed", and stored."""
    from app.services import excluded_addresses
    queue = _queue()
    a = _message(queue, A_START, NORMAL)
    _store(a[:2] + a[3:])
    env.listed()
    real = excluded_addresses.remembered_listed
    calls = []

    def listed_after_the_page_was_read(queue_ids):
        calls.append(1)
        if len(calls) == 1:
            excluded_addresses.remember_listed_queue(queue, B_START + 2 * SECOND)
            return {}
        return real(queue_ids)
    monkeypatch.setattr(excluded_addresses, 'remembered_listed', listed_after_the_page_was_read)
    _ingest([a[2]])
    assert _stored(queue) == _texts(a)


def test_a_line_committed_while_a_listed_message_is_deleted_goes_with_it(env, monkeypatch):
    """The Postfix ingest commits a line of the listed message after the
    deletion read what it needs: it is deleted too, as the time is what counts."""
    from app.database import get_db_context
    from app.services import excluded_addresses
    queue = _queue()
    a = _message(queue, A_START, LISTED)
    _store(a[:1] + a[3:])
    real = excluded_addresses.remembered_removed
    committed = []

    def a_commit_meanwhile(queue_id):
        if not committed:
            committed.append(1)
            _store(a[1:3])
        return real(queue_id)
    monkeypatch.setattr(excluded_addresses, 'remembered_removed', a_commit_meanwhile)
    env.listed()
    with get_db_context() as db:
        excluded_addresses.delete_queue_occurrences(db, [(queue, a[3][0])])
        db.commit()
    assert _stored(queue) == []


# ---------- the cleanup and the Rspamd ingest ----------

def test_the_cleanup_keeps_the_next_message_on_a_listed_messages_queue_id(env):
    from app.services import excluded_addresses
    from app.database import get_db_context
    queue = _queue()
    _store(_message(queue, A_START, LISTED) + _message(queue, B_START, NORMAL))
    key_a = _correlation(queue, A_START, NORMAL)  # an alias: only its Postfix line names the address
    key_b = _correlation(queue, B_START, NORMAL)
    env.listed()
    with get_db_context() as db:
        excluded_addresses.cleanup(db)
    assert _stored(queue) == _texts(_message(queue, B_START, NORMAL))
    assert _keys() == {key_b}
    assert key_a not in _keys()


def test_the_rspamd_ingest_keeps_the_next_message_on_a_listed_messages_queue_id(env):
    from app import scheduler
    queue = _queue()
    _store(_message(queue, A_START, LISTED) + _message(queue, B_START, NORMAL))
    _correlation(queue, A_START, LISTED)
    key_b = _correlation(queue, B_START, NORMAL)
    env.listed()
    scheduler._store_rspamd_page([{
        'unix_time': int(A_START.replace(tzinfo=timezone.utc).timestamp()),
        'message-id': f'{queue}.{A_START:%H%M%S}@{MARKER}', 'sender_smtp': SENDER, 'rcpt_smtp': [LISTED],
        'action': 'no action', 'score': 0.0, 'required_score': 15.0, 'symbols': {}}])
    assert _keys() == {key_b}
    assert _stored(queue) == _texts(_message(queue, B_START, NORMAL))


def test_the_cleanup_keeps_a_delivery_whose_excluded_written_address_its_own_lines_do_not_name(env):
    """The written address can have come from another message's line (the old
    one-day window). With its own lines stored and none naming the address,
    the delivery stays (still hidden); without stored lines it goes, as before."""
    from app.services import excluded_addresses
    from app.database import get_db_context
    queue, gone = _queue(), _queue()
    _store(_message(queue, A_START, NORMAL))
    kept = _correlation(queue, A_START, NORMAL, written={NORMAL: LISTED})
    _correlation(gone, A_START, NORMAL, written={NORMAL: LISTED})
    env.listed()
    with get_db_context() as db:
        excluded_addresses.cleanup(db)
    assert _keys() == {kept}
    assert _client().get(f'/api/message/{kept}/details').status_code == 404


# ---------- readers, before the cleanup ----------

def test_every_reader_shows_the_next_message_and_hides_the_listed_one(env):
    queue = _queue()
    _store(_message(queue, A_START, LISTED) + _message(queue, B_START, NORMAL))
    key_a = _correlation(queue, A_START, NORMAL)
    key_b = _correlation(queue, B_START, NORMAL)
    env.listed()
    client = _client()
    b_texts = _texts(_message(queue, B_START, NORMAL))

    listing = client.get('/api/logs/postfix', params={'queue_id': queue}).json()
    assert listing['total'] == 1 and listing['data'][0]['recipient'] == NORMAL

    by_queue = client.get(f'/api/logs/postfix/by-queue/{queue}').json()['logs']
    assert sorted(l['message'] for l in by_queue) == b_texts

    export = client.get('/api/export/postfix/csv', params={'search': queue}).text
    assert NORMAL in export and LISTED not in export
    assert f'{queue}.{A_START:%H%M%S}' not in export  # the listed message's own Message-ID line

    # Both SQL filters, line by line: the listed message's lines that name no
    # address are hidden with it, the next message's are not
    from app.database import get_db_context
    from app.models import PostfixLog
    from app.services import excluded_addresses
    with get_db_context() as db:
        for visible in (excluded_addresses.postfix_line_visible(),
                        excluded_addresses.postfix_line_visible_among([queue])):
            shown = sorted(l.message for l in db.query(PostfixLog).filter(PostfixLog.queue_id == queue, visible))
            assert shown == b_texts

    details = client.get(f'/api/message/{key_b}/details')
    assert details.status_code == 200, details.text
    assert sorted(l['message'] for l in details.json()['postfix']) == b_texts
    compact = client.get(f'/api/message/{key_b}')
    assert compact.status_code == 200, compact.text
    assert client.get(f'/api/message/{key_a}/details').status_code == 404
    assert client.get(f'/api/message/{key_a}').status_code == 404

    rows = client.get('/api/messages', params={'search': queue, 'limit': 50}).json()['data']
    assert {r['correlation_key'] for r in rows} == {key_b}


def test_without_removed_the_details_hide_both_as_the_list_does(env):
    """Nothing proves two messages, so the list hides the queue id's lines
    within a day of the listed one; the details decide on the same lines
    (not on the lines they show), so they agree."""
    queue = _queue()
    _store(_message(queue, A_START, LISTED, removed=False) + _message(queue, B_START, NORMAL))
    key_b = _correlation(queue, B_START, NORMAL)
    env.listed()
    client = _client()
    assert client.get('/api/logs/postfix', params={'queue_id': queue}).json()['total'] == 0
    assert client.get(f'/api/message/{key_b}/details').status_code == 404


# ---------- block evidence and the written recipient ----------

def test_block_evidence_holds_no_line_of_the_message_before(env):
    from app.database import get_db_context
    from app.models import PostfixLog
    from app.services.suppression_events import postfix_lines
    queue = _queue()
    a = _message(queue, A_START, NORMAL)
    b = _message(queue, B_START, LISTED.replace('secret', 'bounced'), status='bounced')
    _store(a + b)
    with get_db_context() as db:
        bounce = db.query(PostfixLog).filter(PostfixLog.queue_id == queue, PostfixLog.status == 'bounced').one()
        rcpt = bounce.recipient
        [(bounced, _), (stuck, _)] = postfix_lines(db, [
            (queue, rcpt, bounce.time, bounce.time, bounce),
            (queue, rcpt, B_START, datetime.utcnow(), None)])
    assert sorted(l['message'] for l in bounced) == _texts(b)
    assert sorted(l['message'] for l in stuck) == _texts(b)


def test_the_written_address_is_not_read_after_the_messages_removed(env):
    from app.database import get_db_context
    from app.services.written_recipients import delivery_lines
    queue = _queue()
    a = _message(queue, A_START, NORMAL)
    _store(a + [(B_START, 'postfix/smtp', f'{queue}: to=<Dana.Lee@gmail.test>, relay=mx.example.test[192.0.2.30]:25, '
                                          f'delay=1, delays=0.1/0/0/0.9, dsn=2.0.0, status=sent (250 ok)')])
    # The next message's delivery has no correlation yet: the one stored is the only owner
    _correlation(queue, A_START, NORMAL)
    with get_db_context() as db:
        lines = delivery_lines(db, SimpleNamespace(first_seen=A_START, created_at=A_START, queue_id=queue,
                                                   postfix_log_ids=None))
    assert [l.message for l in lines] == [a[3][2]]
