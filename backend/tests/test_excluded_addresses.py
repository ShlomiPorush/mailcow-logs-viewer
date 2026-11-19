"""Excluded addresses (BLACKLIST_EMAILS): mail to or from them is not stored or shown in Messages.

The data here was stored before the address was listed. Every reader of the
message tables leaves it out at once, the cleanup then deletes it (and only
it), and the Postfix ingest does not store a listed message's lines, even
when they come in another page. The raw service logs keep every line.
Dummy data only, against the test PostgreSQL.
"""
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

MARK = uuid.uuid4().hex[:8]
# "_" is a LIKE wildcard: the neighbour must never be taken for the listed address
LISTED = f'arch_{MARK}@example.test'
NEIGHBOUR = f'archx{MARK}@example.test'
NORMAL = f'user-{MARK}@example.test'
SENDER = f'boss-{MARK}@example.test'
MSGID = f'{MARK}@example.test'
Q_LISTED = f'A{MARK.upper()}1'     # the BCC copy's queue, also used 10 days earlier for another message
Q_ORIG = f'A{MARK.upper()}2'       # delivered to NORMAL as an alias of LISTED
Q_NORMAL = f'A{MARK.upper()}3'
Q_NEIGHBOUR = f'A{MARK.upper()}4'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _wipe():
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog, RawServiceLog, RspamdLog
    with get_db_context() as db:
        db.query(PostfixLog).filter(PostfixLog.message.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.subject.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.query(MessageCorrelation).filter(
            MessageCorrelation.correlation_key.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.query(RawServiceLog).filter(RawServiceLog.message_hash.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.commit()


def _line(db, when, queue_id, message, sender=None, recipient=None):
    from app.models import PostfixLog
    db.add(PostfixLog(time=when, program='postfix/smtp', priority='info', queue_id=queue_id,
                      message=f'{message} [{MARK}]', sender=sender, recipient=recipient))


def _seed():
    from app.database import get_db_context
    from app.models import MessageCorrelation, RawServiceLog, RspamdLog
    now = datetime.utcnow().replace(microsecond=0) - timedelta(minutes=5)
    old = now - timedelta(days=10)
    keys = {}
    with get_db_context() as db:
        scan = RspamdLog(time=now, message_id=MSGID, sender_smtp=SENDER, recipients_smtp=[NORMAL, f'  {LISTED.upper()} '],
                         subject=f'two recipients {MARK}', action='no action', score=0.0, required_score=15.0, symbols={})
        object_value = RspamdLog(time=now, message_id=f'obj-{MSGID}', sender_smtp=SENDER, recipients_smtp={'unexpected': 'shape'},
                                 subject=f'object value {MARK}', action='no action', score=0.0, required_score=15.0,
                                 symbols={})
        no_value = RspamdLog(time=now, message_id=f'none-{MSGID}', sender_smtp=SENDER, recipients_smtp=None,
                             subject=f'no value {MARK}', action='no action', score=0.0, required_score=15.0, symbols={})
        db.add_all([scan, object_value, no_value])
        db.flush()
        keys['scan'] = scan.id
        for name, recipient, queue, rspamd_id in (('listed', f' {LISTED.upper()}', Q_LISTED, None),
                                                   ('normal', NORMAL, Q_NORMAL, scan.id),
                                                   ('neighbour', NEIGHBOUR, Q_NEIGHBOUR, None)):
            db.add(MessageCorrelation(correlation_key=f'{name}-{MARK}', message_id=MSGID, queue_id=queue,
                                      sender=SENDER, recipient=recipient, subject=f'{name} {MARK}',
                                      rspamd_log_id=rspamd_id, is_complete=False, direction='outbound',
                                      final_status='delivered', first_seen=now, last_seen=now, created_at=now))
        # The BCC copy's queue: only one of its lines names the address
        _line(db, now, Q_LISTED, f'{Q_LISTED}: from=<{SENDER}>, size=100, nrcpt=1', sender=SENDER)
        _line(db, now + timedelta(seconds=1), Q_LISTED, f'{Q_LISTED}: to=<{LISTED}>, relay=local, status=sent',
              recipient=LISTED)
        _line(db, now + timedelta(seconds=2), Q_LISTED, f'{Q_LISTED}: removed')
        # The same queue id, ten days earlier, for someone else's message
        _line(db, old, Q_LISTED, f'{Q_LISTED}: to=<{NORMAL}>, relay=local, status=sent old-message', recipient=NORMAL)
        # Mail to LISTED, an alias, delivered to NORMAL
        _line(db, now, Q_ORIG, f'{Q_ORIG}: to=<{NORMAL}>, orig_to=<{LISTED}>, relay=local, status=sent',
              recipient=NORMAL)
        _line(db, now, Q_NORMAL, f'{Q_NORMAL}: to=<{NORMAL}>, relay=local, status=sent', recipient=NORMAL)
        _line(db, now, Q_NEIGHBOUR, f'{Q_NEIGHBOUR}: to=<{NEIGHBOUR}>, relay=local, status=sent', recipient=NEIGHBOUR)
        # Rejected before it had a queue
        _line(db, now, None, f'NOQUEUE: reject: RCPT from x[192.0.2.1]: 554 5.7.1 denied; from=<{SENDER}> to=<{LISTED}>',
              sender=SENDER, recipient=LISTED)
        for i, text in enumerate((f'lmtp({LISTED})<1><s{MARK}>: msgid=<{MSGID}>: unknown action',
                                  f'lmtp({NORMAL})<2><t{MARK}>: msgid=<{MSGID}>: saved mail to INBOX')):
            db.add(RawServiceLog(service='dovecot', time=now + timedelta(seconds=i), message_hash=f'{MARK}{i}',
                                 raw_data={'message': text, 'priority': 'info'}))
        db.commit()
    return keys


@pytest.fixture
def stored(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.config import settings
    from app.database import init_db
    init_db()
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    _wipe()
    monkeypatch.setattr(settings._inner, 'blacklist_emails', '')
    keys = _seed()
    # The operator lists the address after the mail was stored
    monkeypatch.setattr(settings._inner, 'blacklist_emails', f'other@example.test, {LISTED.upper()}')
    yield keys
    _wipe()


@pytest.fixture
def client(stored):
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


def _no_listed(response):
    assert response.status_code == 200, response.text
    assert LISTED not in response.text.lower(), response.text
    return response


# ── Readers, before any cleanup ────────────────────────────────────────────

def test_message_readers_leave_out_listed_mail(client):
    listing = _no_listed(client.get('/api/messages', params={'search': MARK, 'limit': 50})).json()
    # One row per message (Message-ID): a visible leg stands for it
    assert {m['recipient'] for m in listing['data']} & {NORMAL, NEIGHBOUR}

    activity = _no_listed(client.get('/api/stats/recent-activity', params={'limit': 500})).json()['activity']
    assert any(a['recipient'] == NEIGHBOUR for a in activity)

    pending = _no_listed(client.get('/api/settings/info')).json()['recent_incomplete_correlations']
    assert all(LISTED not in (row['recipient'] or '').lower() for row in pending)

    assert client.get(f'/api/message/listed-{MARK}/details').status_code == 404
    assert client.get(f'/api/message/listed-{MARK}').status_code == 404

    details = _no_listed(client.get(f'/api/message/normal-{MARK}/details')).json()
    assert {d['recipient'] for d in details['related_deliveries']} == {NEIGHBOUR}
    assert details['recipients'] == [NORMAL]
    assert [d['recipient'] for d in details['dovecot']['logs']] == [NORMAL]
    _no_listed(client.get(f'/api/message/normal-{MARK}'))

    for path in ('/api/export/messages/csv', '/api/export/postfix/csv', '/api/export/rspamd/csv'):
        _no_listed(client.get(path, params={'search': MARK}))


def test_postfix_and_rspamd_readers_leave_out_listed_queues(client):
    rows = _no_listed(client.get('/api/logs/postfix', params={'search': MARK, 'limit': 500})).json()['data']
    by_queue = {r['queue_id']: r for r in rows}
    assert Q_ORIG not in by_queue
    assert {Q_NORMAL, Q_NEIGHBOUR} <= set(by_queue)
    # Only the earlier message under the reused queue id is shown for it
    assert by_queue[Q_LISTED]['recipient'] == NORMAL and 'old-message' in by_queue[Q_LISTED]['message']

    assert client.get(f'/api/logs/postfix/by-queue/{Q_ORIG}').status_code == 404
    lines = _no_listed(client.get(f'/api/logs/postfix/by-queue/{Q_LISTED}')).json()['logs']
    assert [l['recipient'] for l in lines] == [NORMAL]

    scans = _no_listed(client.get('/api/logs/rspamd', params={'search': MARK, 'limit': 500})).json()['data']
    assert {s['subject'] for s in scans} == {f'object value {MARK}', f'no value {MARK}'}


def test_raw_service_logs_keep_every_line(client):
    body = client.get('/api/raw-logs/dovecot', params={'search': MARK}).json()
    assert body['total'] == 2


# ── Cleanup ────────────────────────────────────────────────────────────────

def _state():
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog, RawServiceLog, RspamdLog
    with get_db_context() as db:
        return {
            'deliveries': {c.correlation_key.split('-')[0]: c.rspamd_log_id for c in db.query(MessageCorrelation).filter(
                MessageCorrelation.correlation_key.like(f'%{MARK}%'))},
            'postfix': sorted(l.message.split(' [')[0] for l in db.query(PostfixLog).filter(
                PostfixLog.message.like(f'%{MARK}%'))),
            'rspamd': sorted(r.subject for r in db.query(RspamdLog).filter(RspamdLog.subject.like(f'%{MARK}%'))),
            'raw': db.query(RawServiceLog).filter(RawServiceLog.message_hash.like(f'%{MARK}%')).count(),
        }


def test_cleanup_deletes_only_listed_mail(stored):
    from app import scheduler
    scheduler.cleanup_blacklisted_data()
    state = _state()
    # The other recipient's delivery stays, without the deleted scan
    assert state['deliveries'] == {'normal': None, 'neighbour': None}
    assert state['postfix'] == sorted([
        f'{Q_LISTED}: to=<{NORMAL}>, relay=local, status=sent old-message',
        f'{Q_NORMAL}: to=<{NORMAL}>, relay=local, status=sent',
        f'{Q_NEIGHBOUR}: to=<{NEIGHBOUR}>, relay=local, status=sent',
    ])
    assert state['rspamd'] == sorted([f'object value {MARK}', f'no value {MARK}'])
    assert state['raw'] == 2
    # A second run finds nothing more
    scheduler.cleanup_blacklisted_data()
    assert _state() == state


def test_adding_an_address_starts_a_pass(stored, monkeypatch):
    """The correlation job cleans up only when a pass is due: adding an
    address, as a settings save does, makes the next run one."""
    from app import scheduler
    from app.config import settings
    from app.services import excluded_addresses
    monkeypatch.setattr(settings._inner, 'blacklist_emails', 'other@example.test')
    scheduler._cleanup_blacklisted_queues_sync()
    assert excluded_addresses.full_pass_due() is None
    assert 'listed' in _state()['deliveries']

    monkeypatch.setattr(settings._inner, 'blacklist_emails', f'other@example.test,{LISTED}')
    scheduler._cleanup_blacklisted_queues_sync()
    assert 'listed' not in _state()['deliveries']
    assert excluded_addresses.full_pass_due() is None


# ── Ingest ─────────────────────────────────────────────────────────────────

def test_postfix_ingest_stores_no_line_of_a_listed_message(stored, monkeypatch):
    from app import scheduler
    monkeypatch.setattr(scheduler, 'seen_postfix', set())
    now = int(datetime.utcnow().timestamp())
    queue, alias = f'B{MARK.upper()}1', f'B{MARK.upper()}2'

    def entry(offset, message):
        return {'time': str(now + offset), 'program': 'postfix/smtp', 'priority': 'info', 'message': f'{message} [{MARK}]'}

    scheduler._store_postfix_page([
        entry(0, f'{queue}: message-id=<{MARK}-in@example.test>'),
        entry(1, f'{queue}: to=<{LISTED}>, relay=local, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 ok)'),
        entry(2, f'NOQUEUE: reject: RCPT from x[192.0.2.1]: 554 5.7.1 <{LISTED}>: denied; '
                 f'from=<{SENDER}> to=<{LISTED}> proto=ESMTP helo=<x>'),
        entry(3, f'{alias}: to=<{NORMAL}>, orig_to=<{LISTED}>, relay=local, delay=1, delays=0/0/0/1, dsn=2.0.0, '
                 f'status=sent (250 ok)'),
    ])
    # The rest of the queue comes in a later page
    scheduler._store_postfix_page([entry(4, f'{queue}: removed')])

    from app.database import get_db_context
    from app.models import PostfixLog
    with get_db_context() as db:
        stored_lines = [l.message for l in db.query(PostfixLog).filter(
            PostfixLog.message.like(f'%{MARK}%'), PostfixLog.time >= datetime.utcfromtimestamp(now))]
    assert stored_lines == []


# ── Edges of the queue rule ────────────────────────────────────────────────

def _ingest(scheduler, monkeypatch, *pages):
    monkeypatch.setattr(scheduler, 'seen_postfix', set())
    for page in pages:
        scheduler._store_postfix_page([
            {'time': str(int(when.replace(tzinfo=__import__('datetime').timezone.utc).timestamp())),
             'program': 'postfix/smtp', 'priority': 'info', 'message': f'{message} [{MARK}]'}
            for when, message in page])


def _stored_lines(queue_id):
    from app.database import get_db_context
    from app.models import PostfixLog
    with get_db_context() as db:
        return sorted(l.message.split(' [')[0] for l in db.query(PostfixLog).filter(PostfixLog.queue_id == queue_id))


def test_a_reply_that_quotes_orig_to_does_not_make_a_message_listed(stored, monkeypatch):
    from app import scheduler
    queue = f'C{MARK.upper()}1'
    line = (f'{queue}: to=<{NORMAL}>, relay=mx.example.test[192.0.2.9]:25, delay=1, delays=0/0/0/1, dsn=2.0.0, '
            f'status=sent (250 ok orig_to=<{LISTED}>)')
    _ingest(scheduler, monkeypatch, [(datetime.utcnow(), line)])
    assert _stored_lines(queue) == [line]
    scheduler.cleanup_blacklisted_data()
    assert _stored_lines(queue) == [line]


def test_the_rspamd_path_deletes_around_the_listed_line_only(stored):
    """A delivery at t, the line naming the address at t+23h, and another
    message under the same queue id at t-12h: 35 hours from the evidence."""
    from app import scheduler
    from app.database import get_db_context
    from app.models import MessageCorrelation
    queue = f'D{MARK.upper()}1'
    t = datetime.utcnow().replace(microsecond=0) - timedelta(days=2)
    with get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=f'late-{MARK}', message_id=f'late-{MSGID}', queue_id=queue,
                                  sender=SENDER, recipient=NORMAL, first_seen=t, last_seen=t, created_at=t))
        _line(db, t + timedelta(hours=23), queue, f'{queue}: to=<{LISTED}>, relay=local, status=sent',
              recipient=LISTED)
        _line(db, t - timedelta(hours=12), queue, f'{queue}: to=<{NORMAL}>, relay=local, status=sent earlier',
              recipient=NORMAL)
        db.commit()
    scheduler._store_rspamd_page([{
        'unix_time': int(datetime.utcnow().timestamp()), 'message-id': f'late-{MSGID}', 'sender_smtp': LISTED,
        'rcpt_smtp': [NORMAL], 'action': 'no action', 'score': 0.0, 'required_score': 15.0, 'symbols': {}}])
    assert 'late' not in _state()['deliveries']
    assert _stored_lines(queue) == [f'{queue}: to=<{NORMAL}>, relay=local, status=sent earlier']


def test_lines_of_an_old_listed_message_in_a_later_page_are_dropped(stored, monkeypatch):
    """A catch-up of lines two days old: the queue is remembered from when it
    was seen, not from the log time."""
    from app import scheduler
    queue = f'E{MARK.upper()}1'
    old = datetime.utcnow().replace(microsecond=0) - timedelta(days=2)
    _ingest(scheduler, monkeypatch,
            [(old, f'{queue}: to=<{LISTED}>, relay=local, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 ok)')],
            [(old + timedelta(seconds=1), f'{queue}: removed')])
    assert _stored_lines(queue) == []


def test_lines_after_the_cleanup_removed_the_evidence_are_dropped(stored, monkeypatch):
    from app import scheduler
    scheduler.cleanup_blacklisted_data()
    assert _stored_lines(Q_LISTED) == [f'{Q_LISTED}: to=<{NORMAL}>, relay=local, status=sent old-message']
    seeded = datetime.utcnow().replace(microsecond=0) - timedelta(minutes=5)
    _ingest(scheduler, monkeypatch, [(seeded + timedelta(seconds=30), f'{Q_LISTED}: removed again')])
    assert _stored_lines(Q_LISTED) == [f'{Q_LISTED}: to=<{NORMAL}>, relay=local, status=sent old-message']


def test_the_cleanup_waits_for_a_page_being_stored(stored):
    """A page checked against the list from before a change, and committed
    while the cleanup is due, is in the database before the cleanup reads."""
    import threading
    from app import scheduler
    from app.database import get_db_context
    from app.services import excluded_addresses
    queue = f'F{MARK.upper()}1'
    excluded_addresses.request_full_pass()
    scheduler._postfix_ingest_lock.acquire()
    try:
        worker = threading.Thread(target=scheduler._cleanup_blacklisted_queues_sync)
        worker.start()
        worker.join(0.5)
        assert worker.is_alive(), 'the cleanup did not wait for the page'
        when = datetime.utcnow() - timedelta(hours=6)
        with get_db_context() as db:
            _line(db, when, queue, f'{queue}: message-id=<late-{MSGID}>')
            _line(db, when + timedelta(seconds=1), queue, f'{queue}: to=<{LISTED}>, relay=local, status=sent',
                  recipient=LISTED)
            db.commit()
    finally:
        scheduler._postfix_ingest_lock.release()
    worker.join(60)
    assert _stored_lines(queue) == []
    assert excluded_addresses.full_pass_due() is None


def test_an_alias_delivery_of_a_listed_address_has_no_details(client):
    """Mail to the listed address delivered to NORMAL as an alias (orig_to)."""
    from app.database import get_db_context
    from app.models import MessageCorrelation
    now = datetime.utcnow().replace(microsecond=0) - timedelta(minutes=5)
    with get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=f'alias-{MARK}', message_id=f'alias-{MSGID}', queue_id=Q_ORIG,
                                  sender=SENDER, recipient=NORMAL, subject=f'alias {MARK}',
                                  first_seen=now, last_seen=now, created_at=now))
        db.commit()
    assert client.get(f'/api/message/alias-{MARK}/details').status_code == 404
    assert client.get(f'/api/message/alias-{MARK}').status_code == 404
    from app import scheduler
    scheduler.cleanup_blacklisted_data()
    assert 'alias' not in _state()['deliveries']


def test_block_details_do_not_show_an_excluded_address_message(client):
    from app.database import get_db_context
    from app.models import SpamSuppression, SuppressionEvent
    with get_db_context() as db:
        block = SpamSuppression(email=f'bounced-{MARK}@example.test', reason='hard_bounce', source='auto')
        db.add(block)
        db.flush()
        # Sent by the listed address, and (an alias bounce) sent to it as orig_to
        db.add(SuppressionEvent(suppression_id=block.id, kind='hard_bounce', outcome='blocked', dsn='5.1.1',
                                sender=LISTED, recipient=block.email, subject=f'secret {MARK}', queue_id=Q_LISTED,
                                message_id=MSGID, correlation_key=f'normal-{MARK}',
                                log_lines=[{'message': f'to=<{block.email}> from {LISTED}'}]))
        db.add(SuppressionEvent(suppression_id=block.id, kind='hard_bounce', outcome='extended', dsn='5.1.1',
                                sender=SENDER, recipient=block.email, subject=f'secret alias {MARK}',
                                queue_id=Q_ORIG, message_id=MSGID,
                                log_lines=[{'message': f'{Q_ORIG}: to=<{block.email}>, orig_to=<{LISTED}>, '
                                                       f'status=bounced (550 unknown)'}]))
        db.commit()
        block_id = block.id
    try:
        r = client.get(f'/api/suppressions/{block_id}/events')
        events = _no_listed(r).json()['events']
        assert len(events) == 2
        for event in events:
            assert event['dsn'] == '5.1.1' and event['recipient'] == f'bounced-{MARK}@example.test'
            assert event['log_lines'] == [] and event['subject'] is None and event['message_available'] is False
    finally:
        with get_db_context() as db:
            db.query(SpamSuppression).filter(SpamSuppression.id == block_id).delete(synchronize_session=False)
            db.commit()


def test_an_alias_delivery_is_gone_from_every_message_reader_after_the_cleanup(client):
    """A message whose only delivery reached NORMAL as an alias of the listed
    address (orig_to), stored before the address was listed. The readers that
    count or list the whole table check only a delivery's own addresses (reading
    every delivery's Postfix lines would slow every count); listing the address
    asks for a cleanup pass, which deletes the delivery, and then the timeline's
    message count, the recent activity, the Status page's pending list and a
    block's link to the message leave it out."""
    from app.database import get_db_context
    from app.models import MessageCorrelation, SpamSuppression, SuppressionEvent

    def unique_messages():
        hours = client.get('/api/stats/timeline', params={'hours': 24}).json()['timeline']
        return sum(hour['unique_messages'] for hour in hours)
    before = unique_messages()
    now = datetime.utcnow().replace(microsecond=0) - timedelta(minutes=5)
    with get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=f'alias-only-{MARK}', message_id=f'alias-only-{MSGID}', queue_id=Q_ORIG,
                                  sender=SENDER, recipient=NORMAL, subject=f'alias only {MARK}', is_complete=False,
                                  first_seen=now, last_seen=now + timedelta(minutes=4), created_at=now + timedelta(minutes=4)))
        block = SpamSuppression(email=f'bounced-alias-{MARK}@example.test', reason='hard_bounce', source='auto')
        db.add(block)
        db.flush()
        db.add(SuppressionEvent(suppression_id=block.id, kind='hard_bounce', outcome='blocked', dsn='5.1.1',
                                sender=SENDER, recipient=block.email, queue_id=Q_ORIG,
                                correlation_key=f'alias-only-{MARK}'))
        db.commit()
        block_id = block.id
    try:
        from app import scheduler
        scheduler.cleanup_blacklisted_data()
        assert unique_messages() == before
        activity = client.get('/api/stats/recent-activity', params={'limit': 500}).json()['activity']
        assert f'alias-only-{MARK}' not in {a['correlation_key'] for a in activity}
        pending = client.get('/api/settings/info').json()['recent_incomplete_correlations']
        assert Q_ORIG not in {row['queue_id'] for row in pending}
        [event] = client.get(f'/api/suppressions/{block_id}/events').json()['events']
        assert event['message_available'] is False
    finally:
        with get_db_context() as db:
            db.query(SpamSuppression).filter(SpamSuppression.id == block_id).delete(synchronize_session=False)
            db.commit()
