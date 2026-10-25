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


def test_adding_an_address_starts_a_full_pass(stored, monkeypatch):
    """The light pass of every correlation run looks one hour back; the data
    here is older, so only a full pass removes it. Adding an address, as a
    settings save does, makes the next run a full one."""
    from app import scheduler
    from app.config import settings
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog
    from app.services import excluded_addresses
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(MessageCorrelation.correlation_key.like(f'%{MARK}%')).update(
            {MessageCorrelation.first_seen: datetime.utcnow() - timedelta(hours=5)}, synchronize_session=False)
        db.query(PostfixLog).filter(PostfixLog.message.like(f'%{MARK}%')).update(
            {PostfixLog.time: PostfixLog.time - timedelta(hours=5)}, synchronize_session=False)
        db.commit()
    monkeypatch.setattr(settings._inner, 'blacklist_emails', 'other@example.test')
    scheduler._cleanup_blacklisted_queues_sync()
    scheduler._cleanup_blacklisted_queues_sync()  # the startup pass is done; this one is light
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
