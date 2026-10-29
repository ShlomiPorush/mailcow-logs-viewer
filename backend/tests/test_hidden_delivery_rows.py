"""A Messages row never stands for a delivery its details would hide.

A delivery whose own sender and recipient are allowed can still belong to an
excluded address through a line of its Postfix queue, such as an alias in
orig_to; opening it answers 404 (delivery_hidden). Such a delivery only lives
until the cleanup deletes it (listing an address asks for a pass). The list
checks the deliveries of the page it shows: the row stands for a visible
delivery of the message the filters match, or is left off the page. Totals,
facet counts, the count of new mail and the export check a delivery's own
addresses only, so they never read the Postfix lines; after the cleanup they
leave it out too. A guard keeps the Postfix lines out of those queries.
"""
import hashlib
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

MARKER = 'hidden-rows.example.test'
SENDER = f'sender@{MARKER}'
BOX = f'box@{MARKER}'
CAROL = f'carol@{MARKER}'
DAVE = f'dave@{MARKER}'
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
    from app.models import MessageCorrelation, PostfixLog
    with get_db_context() as db:
        db.query(PostfixLog).filter(PostfixLog.message.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.query(MessageCorrelation).filter(MessageCorrelation.sender.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def client(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from fastapi.testclient import TestClient
    from app.config import settings
    from app.database import init_db
    from app.main import app
    import app.models as _tables  # noqa: F401 - the tables init_db creates on an empty database
    init_db()
    monkeypatch.setattr(settings._inner, 'blacklist_emails', '')
    _cleanup()
    yield TestClient(app)
    _cleanup()


def _leg(msgid, recipient, t0, orig_to=None):
    """One delivery with one Postfix line; orig_to names the alias it came through."""
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog
    queue_id = uuid.uuid4().hex[:10].upper()
    orig = f'orig_to=<{orig_to}>, ' if orig_to else ''
    key = hashlib.sha256(f'{msgid}:{queue_id}'.encode()).hexdigest()
    with get_db_context() as db:
        db.add(PostfixLog(time=t0 + timedelta(seconds=1), program='postfix/lmtp', priority='info',
                          message=f'{queue_id}: to=<{recipient}>, {orig}relay=dovecot, delay=0.1, dsn=2.0.0, '
                                  f'status=sent ({MARKER})',
                          queue_id=queue_id, recipient=recipient, status='sent', relay='dovecot'))
        db.add(MessageCorrelation(correlation_key=key, message_id=msgid, queue_id=queue_id, sender=SENDER,
                                  recipient=recipient, subject='Weekly notes', direction='inbound',
                                  final_status='delivered', is_complete=True, first_seen=t0, last_seen=t0))
        db.commit()
    return key


def _exclude(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings._inner, 'blacklist_emails', LISTED)


def _list(client):
    return client.get('/api/messages', params={'search': MARKER, 'limit': 50}).json()


def test_a_row_stands_for_the_visible_delivery(client, monkeypatch):
    """The earlier delivery came through an excluded alias; the later one did not."""
    msgid = f'{uuid.uuid4().hex}@{MARKER}'
    t0 = datetime.utcnow() - timedelta(minutes=10)
    hidden = _leg(msgid, BOX, t0, orig_to=LISTED)
    visible = _leg(msgid, CAROL, t0 + timedelta(seconds=30))
    _exclude(monkeypatch)

    payload = _list(client)
    assert payload['total'] == 1
    [row] = payload['data']
    assert row['correlation_key'] == visible
    assert (row['recipient'], row['recipient_count'], row['deliveries']) == (CAROL, 1, 1)
    assert client.get(f'/api/message/{visible}/details').status_code == 200
    assert client.get(f'/api/message/{hidden}/details').status_code == 404


def test_a_row_is_never_replaced_by_a_delivery_the_filters_do_not_match(client, monkeypatch):
    """Filtered to the hidden delivery's recipient, the message has no visible
    delivery that matches: the row is left off, not given the other delivery."""
    msgid = f'{uuid.uuid4().hex}@{MARKER}'
    t0 = datetime.utcnow() - timedelta(minutes=10)
    _leg(msgid, BOX, t0, orig_to=LISTED)
    _leg(msgid, CAROL, t0 + timedelta(seconds=30))
    _exclude(monkeypatch)
    payload = client.get('/api/messages', params={'search': MARKER, 'recipient': BOX, 'limit': 50}).json()
    assert payload['data'] == []


def _cleanup_pass():
    from app.database import get_db_context
    from app.services import excluded_addresses
    with get_db_context() as db:
        excluded_addresses.cleanup(db)


def test_a_message_whose_only_delivery_is_hidden_is_left_off_and_then_cleaned(client, monkeypatch):
    t0 = datetime.utcnow() - timedelta(minutes=10)
    _leg(f'{uuid.uuid4().hex}@{MARKER}', BOX, t0, orig_to=LISTED)
    shown = _leg(f'{uuid.uuid4().hex}@{MARKER}', DAVE, t0 + timedelta(minutes=1))
    _exclude(monkeypatch)

    # Left off the page at once; the total counts it until the cleanup runs
    assert [row['correlation_key'] for row in _list(client)['data']] == [shown]
    _cleanup_pass()
    payload = _list(client)
    assert [row['correlation_key'] for row in payload['data']] == [shown]
    assert payload['total'] == 1
    facets = client.get('/api/messages/facets', params={'search': MARKER}).json()
    assert facets['status']['all'] == facets['direction']['all'] == 1
    assert client.get('/api/messages/new', params={'after_id': 0, 'search': MARKER}).json()['count'] == 1
    csv = client.get('/api/export/messages/csv', params={'search': MARKER}).text
    assert DAVE in csv and BOX not in csv


def test_a_delivery_without_a_message_id_hidden_this_way_is_not_listed(client, monkeypatch):
    t0 = datetime.utcnow() - timedelta(minutes=10)
    _leg(None, BOX, t0, orig_to=LISTED)
    _exclude(monkeypatch)
    assert _list(client)['data'] == []
    _cleanup_pass()
    assert _list(client)['total'] == 0


def test_nothing_is_hidden_before_the_alias_is_excluded(client):
    """The rule only leaves out what an excluded address names."""
    msgid = f'{uuid.uuid4().hex}@{MARKER}'
    t0 = datetime.utcnow() - timedelta(minutes=10)
    first = _leg(msgid, BOX, t0, orig_to=LISTED)
    _leg(msgid, CAROL, t0 + timedelta(seconds=30))
    [row] = _list(client)['data']
    assert row['correlation_key'] == first
    assert row['deliveries'] == 2


def test_an_empty_queue_id_joins_no_lines(client, monkeypatch):
    """A delivery with an empty queue id is not hidden by another empty-queue line
    that names an excluded address: delivery_hidden() reads an empty queue id as none."""
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog
    t0 = datetime.utcnow() - timedelta(minutes=10)
    msgid = f'{uuid.uuid4().hex}@{MARKER}'
    key = hashlib.sha256(f'{msgid}:empty'.encode()).hexdigest()
    with get_db_context() as db:
        db.add(PostfixLog(time=t0 + timedelta(seconds=1), program='postfix/smtpd', priority='info',
                          message=f'NOQUEUE: reject: RCPT to=<{LISTED}> ({MARKER})', queue_id='',
                          recipient=LISTED, status='reject'))
        db.add(MessageCorrelation(correlation_key=key, message_id=msgid, queue_id='', sender=SENDER, recipient=DAVE,
                                  subject='Weekly notes', direction='inbound', final_status='delivered',
                                  is_complete=True, first_seen=t0, last_seen=t0))
        db.commit()
    _exclude(monkeypatch)
    assert [row['correlation_key'] for row in _list(client)['data']] == [key]
    assert client.get(f'/api/message/{key}/details').status_code == 200


def test_counts_and_pages_never_read_the_postfix_lines(client, monkeypatch):
    """Guard: with addresses excluded, the facet counts, the count of new mail
    and the export run no query on the Postfix lines, and the list reads them
    only for the deliveries of its page (by queue id or line id), never the
    whole table: a check per delivery there made every count pay for it."""
    from sqlalchemy import event
    from app.database import engine
    msgid = f'{uuid.uuid4().hex}@{MARKER}'
    t0 = datetime.utcnow() - timedelta(minutes=10)
    _leg(msgid, BOX, t0, orig_to=LISTED)
    _leg(msgid, CAROL, t0 + timedelta(seconds=30))
    _leg(f'{uuid.uuid4().hex}@{MARKER}', DAVE, t0 + timedelta(minutes=1))
    _exclude(monkeypatch)

    def statements(*requests):
        seen = []
        listener = lambda conn, cursor, statement, *args: seen.append(statement)  # noqa: E731
        event.listen(engine, 'before_cursor_execute', listener)
        try:
            for path, params in requests:
                assert client.get(path, params=params).status_code == 200
        finally:
            event.remove(engine, 'before_cursor_execute', listener)
        return [s for s in seen if 'postfix_logs' in s]

    since = (datetime.utcnow() - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    assert statements(('/api/messages/facets', {'search': MARKER, 'since': [f'day:{since}', f'week:{since}']}),
                      ('/api/messages/new', {'after_id': 0, 'search': MARKER}),
                      ('/api/export/messages/csv', {'search': MARKER})) == []
    page = statements(('/api/messages', {'search': MARKER, 'limit': 50}))
    assert page, 'the list checks its own page'
    assert all('postfix_logs.queue_id IN' in s or 'postfix_logs.id IN' in s for s in page), page
