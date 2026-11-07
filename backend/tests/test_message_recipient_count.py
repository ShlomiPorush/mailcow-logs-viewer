"""The Messages list says how many recipients a message has.

A row used to show only the delivery's primary recipient, so a message sent
to three people looked like a message sent to one. Each list item now carries
recipient_count, counted exactly as the message dialog counts its recipients:
Rspamd's SMTP recipients without excluded addresses, else the distinct
recipients of the visible Postfix lines. The list counts a whole page with one
grouped Postfix query, never one per row.
"""
import hashlib
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

MARKER = 'rcpt-count.example.test'
SENDER = f'sender@{MARKER}'
ALICE = f'alice@{MARKER}'
BOB = f'bob@{MARKER}'
CAROL = f'carol@{MARKER}'
LISTED = f'listed@{MARKER}'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog, RspamdLog
    with get_db_context() as db:
        db.query(PostfixLog).filter(PostfixLog.message.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.message_id.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.query(MessageCorrelation).filter(
            MessageCorrelation.message_id.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def env(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.config import settings
    from app.database import init_db
    import app.models  # noqa: F401 - the tables init_db creates on an empty database
    init_db()
    monkeypatch.setattr(settings._inner, 'blacklist_emails', '')
    _cleanup()
    yield monkeypatch
    _cleanup()


def _seed(recipient, rspamd=None, postfix=(), queue=True, minutes=5):
    """One delivery leg. rspamd: Rspamd's recipients (None: no Rspamd log).
    postfix: the recipients of its Postfix delivery lines, in order.
    queue=False links the lines by id only, as a leg without a queue id does.
    Returns the correlation key."""
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog, RspamdLog
    msgid = f'{uuid.uuid4().hex}@{MARKER}'
    queue_id = uuid.uuid4().hex[:10].upper()
    t0 = datetime.utcnow() - timedelta(minutes=minutes)
    with get_db_context() as db:
        rspamd_id = None
        if rspamd is not None:
            row = RspamdLog(time=t0, message_id=msgid, sender_smtp=SENDER, recipients_smtp=list(rspamd),
                            score=0.5, required_score=15.0, action='no action', is_spam=False,
                            direction='inbound', user='unknown')
            db.add(row)
            db.flush()
            rspamd_id = row.id
        line_ids = []
        for i, address in enumerate(postfix):
            line = PostfixLog(time=t0 + timedelta(seconds=i + 1), program='postfix/lmtp', priority='info',
                              message=f'{queue_id}: to=<{address}>, relay=dovecot, {MARKER} status=sent',
                              queue_id=queue_id, recipient=address, status='sent', relay='dovecot')
            db.add(line)
            db.flush()
            line_ids.append(line.id)
        key = hashlib.sha256(f'{msgid}:{queue_id}'.encode()).hexdigest()
        db.add(MessageCorrelation(
            correlation_key=key, message_id=msgid, queue_id=queue_id if queue else None,
            postfix_log_ids=line_ids, rspamd_log_id=rspamd_id, sender=SENDER, recipient=recipient,
            subject='Weekly notes', direction='inbound', final_status='delivered', is_complete=True,
            first_seen=t0, last_seen=t0))
        db.commit()
    return key


def _rows(client):
    payload = client.get('/api/messages', params={'search': MARKER, 'limit': 50}).json()
    return {row['correlation_key']: row for row in payload['data']}


def _details(client, key):
    return client.get(f'/api/message/{key}/details').json()


@pytest.fixture()
def client(env):
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


def test_one_recipient_counts_one(client):
    key = _seed(ALICE, rspamd=[ALICE], postfix=[ALICE])
    assert _rows(client)[key]['recipient_count'] == 1


def test_recipients_from_rspamd_are_counted(client):
    key = _seed(ALICE, rspamd=[ALICE, BOB], postfix=[ALICE])
    row = _rows(client)[key]
    assert row['recipient'] == ALICE
    assert row['recipient_count'] == 2


def test_without_rspamd_the_postfix_recipients_are_counted(client):
    # No Rspamd log at all; a retried delivery to Bob logs him twice
    key = _seed(ALICE, rspamd=None, postfix=[ALICE, BOB, BOB, CAROL])
    # An Rspamd log that names no recipient falls back the same way
    empty = _seed(ALICE, rspamd=[], postfix=[ALICE, BOB], minutes=6)
    # A leg without a queue id counts the lines it is linked to
    loose = _seed(ALICE, rspamd=None, postfix=[ALICE, CAROL], queue=False, minutes=7)
    rows = _rows(client)
    assert rows[key]['recipient_count'] == 3
    assert rows[empty]['recipient_count'] == 2
    assert rows[loose]['recipient_count'] == 2


def test_an_excluded_recipient_is_not_counted(client, env):
    from app.config import settings
    key = _seed(ALICE, rspamd=[ALICE, LISTED, BOB], postfix=[ALICE])
    # The operator lists the address after the mail was stored
    env.setattr(settings._inner, 'blacklist_emails', LISTED.upper())
    assert _rows(client)[key]['recipient_count'] == 2
    assert LISTED not in _details(client, key)['recipients']


def test_a_leg_with_no_recipient_left_still_counts_its_own(client):
    """Retention removed its Postfix lines and Rspamd never scanned it: the
    row still names a recipient, so it counts at least that one."""
    key = _seed(ALICE, rspamd=None, postfix=[])
    assert _rows(client)[key]['recipient_count'] == 1
    assert _details(client, key)['recipient_count'] == 1


def test_list_and_details_agree(client):
    keys = [
        _seed(ALICE, rspamd=[ALICE], postfix=[ALICE]),
        _seed(ALICE, rspamd=[ALICE, BOB, CAROL], postfix=[ALICE], minutes=6),
        _seed(BOB, rspamd=None, postfix=[BOB, CAROL], minutes=7),
        _seed(CAROL, rspamd=None, postfix=[CAROL, ALICE], queue=False, minutes=8),
    ]
    rows = _rows(client)
    for key in keys:
        details = _details(client, key)
        assert rows[key]['recipient_count'] == details['recipient_count'] == len(details['recipients']), key


def test_lines_linked_by_id_are_shown_and_counted_alike(client, env):
    """A leg without a queue id reads the lines linked to it. A line whose queue
    occurrence names an excluded address in another, unlinked line is left out
    of the rows the details show, as it is left out of the list's count."""
    from app.config import settings
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog
    msgid = f'{uuid.uuid4().hex}@{MARKER}'
    hidden_queue, kept_queue = uuid.uuid4().hex[:10].upper(), uuid.uuid4().hex[:10].upper()
    t0 = datetime.utcnow() - timedelta(minutes=5)

    def line(queue_id, address, seconds):
        return PostfixLog(time=t0 + timedelta(seconds=seconds), program='postfix/lmtp', priority='info',
                          message=f'{queue_id}: to=<{address}>, relay=dovecot, {MARKER} status=sent',
                          queue_id=queue_id, recipient=address, status='sent', relay='dovecot')
    with get_db_context() as db:
        kept, hidden = line(kept_queue, ALICE, 1), line(hidden_queue, BOB, 2)
        db.add_all([kept, hidden, line(hidden_queue, LISTED, 3)])
        db.flush()
        key = hashlib.sha256(f'{msgid}:by-id'.encode()).hexdigest()
        db.add(MessageCorrelation(
            correlation_key=key, message_id=msgid, queue_id=None, postfix_log_ids=[kept.id, hidden.id],
            sender=SENDER, recipient=ALICE, subject='Weekly notes', direction='inbound', final_status='delivered',
            is_complete=False, first_seen=t0, last_seen=t0))
        db.commit()
    env.setattr(settings._inner, 'blacklist_emails', LISTED)

    details = _details(client, key)
    assert [log['recipient'] for log in details['postfix']] == [ALICE]
    assert details['recipient_count'] == _rows(client)[key]['recipient_count'] == 1


def test_two_lines_that_differ_after_their_first_100_characters_are_two(client):
    """Two long aliases delivered to one mailbox in the same second: the lines
    match for well over 100 characters and differ only in orig_to. They are two
    recipients in the details and in the list alike."""
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog
    msgid = f'{uuid.uuid4().hex}@{MARKER}'
    queue_id = uuid.uuid4().hex[:10].upper()
    box = f'box@{MARKER}'
    alias = 'a' * 60
    t0 = datetime.utcnow() - timedelta(minutes=5)
    messages = [f'{queue_id}: to=<{box}>, orig_to=<{alias}{n}@{MARKER}>, relay=dovecot, delay=0.1, '
                f'delays=0/0/0/0.1, dsn=2.0.0, status=sent (250 2.0.0 Ok)' for n in (1, 2)]
    assert messages[0][:100] == messages[1][:100]
    with get_db_context() as db:
        for message in messages:
            db.add(PostfixLog(time=t0 + timedelta(seconds=1), program='postfix/lmtp', priority='info', message=message,
                              queue_id=queue_id, recipient=box, status='sent', relay='dovecot'))
        key = hashlib.sha256(f'{msgid}:{queue_id}'.encode()).hexdigest()
        db.add(MessageCorrelation(
            correlation_key=key, message_id=msgid, queue_id=queue_id, sender=SENDER, recipient=box,
            subject='Weekly notes', direction='inbound', final_status='delivered', is_complete=True,
            first_seen=t0, last_seen=t0))
        db.commit()

    details = _details(client, key)
    assert len(details['postfix']) == 2
    assert len(details['postfix_by_recipient'][box]) == 2
    assert details['recipient_count'] == _rows(client)[key]['recipient_count'] == 2


def test_the_details_count_from_the_lines_they_loaded(client):
    """The details read the message's Postfix lines once, and count from them."""
    from sqlalchemy import event
    from app.database import engine
    key = _seed(ALICE, rspamd=None, postfix=[ALICE, BOB])
    seen = []

    def count(conn, cursor, statement, *args):
        if 'FROM postfix_logs' in statement:
            seen.append(statement)
    event.listen(engine, 'before_cursor_execute', count)
    try:
        assert _details(client, key)['recipient_count'] == 2
    finally:
        event.remove(engine, 'before_cursor_execute', count)
    assert len(seen) == 1


def test_a_page_of_messages_delivered_twice_takes_the_same_queries_as_a_short_one(client):
    """Every message passed through the server twice (two legs, one recipient
    each): each row counts both legs' recipients, and the page reads the legs,
    their Rspamd logs and their Postfix lines in grouped queries, so 8 rows
    take as many statements as 2."""
    from sqlalchemy import event
    from app.database import engine, get_db_context
    from app.models import MessageCorrelation, PostfixLog, RspamdLog

    def seed(rows):
        for i in range(rows):
            msgid = f'{uuid.uuid4().hex}@{MARKER}'
            t0 = datetime.utcnow() - timedelta(minutes=10 + i)
            with get_db_context() as db:
                for n, address in enumerate((ALICE, f'friend{i}@outside.{MARKER}')):
                    queue_id = uuid.uuid4().hex[:10].upper()
                    rspamd = RspamdLog(time=t0, message_id=msgid, sender_smtp=SENDER, recipients_smtp=[address],
                                       score=0.5, required_score=15.0, action='no action', is_spam=False,
                                       direction='inbound', user='unknown')
                    db.add(rspamd)
                    db.flush()
                    db.add(PostfixLog(time=t0 + timedelta(seconds=n * 30 + 1), program='postfix/lmtp', priority='info',
                                      message=f'{queue_id}: to=<{address}>, relay=dovecot, {MARKER} status=sent',
                                      queue_id=queue_id, recipient=address, status='sent', relay='dovecot'))
                    db.add(MessageCorrelation(
                        correlation_key=hashlib.sha256(f'{msgid}:{queue_id}'.encode()).hexdigest(), message_id=msgid,
                        queue_id=queue_id, rspamd_log_id=rspamd.id, sender=SENDER, recipient=address,
                        subject='Weekly notes', direction='inbound', final_status='delivered', is_complete=True,
                        first_seen=t0 + timedelta(seconds=n * 30), last_seen=t0 + timedelta(seconds=n * 30)))
                db.commit()

    def statements(rows):
        seed(rows)
        seen = []

        def count(conn, cursor, statement, *args):
            seen.append(statement)
        event.listen(engine, 'before_cursor_execute', count)
        try:
            found = _rows(client)
        finally:
            event.remove(engine, 'before_cursor_execute', count)
        assert len(found) == rows and all(r['recipient_count'] == 2 for r in found.values())
        return len(seen)

    few = statements(2)
    _cleanup()
    assert statements(8) == few


def test_the_postfix_fallback_is_one_query_per_page(client):
    """No query per row: a page of messages Rspamd has no recipients for reads
    the Postfix recipients of all of them at once."""
    from sqlalchemy import event
    from app.database import engine

    def postfix_queries(rows):
        for i in range(rows):
            _seed(ALICE, rspamd=None, postfix=[ALICE, BOB], minutes=10 + i)
        seen = []

        def count(conn, cursor, statement, *args):
            if 'FROM postfix_logs' in statement:
                seen.append(statement)
        event.listen(engine, 'before_cursor_execute', count)
        try:
            found = _rows(client)
        finally:
            event.remove(engine, 'before_cursor_execute', count)
        assert len(found) >= rows and all(r['recipient_count'] == 2 for r in found.values())
        return len(seen)

    few = postfix_queries(2)
    _cleanup()
    many = postfix_queries(8)
    assert few == many == 1
