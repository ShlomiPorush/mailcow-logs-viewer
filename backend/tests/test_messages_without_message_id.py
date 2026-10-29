"""Messages without a usable Message-ID are listed from their Postfix lines.

A scanner that sends "Message-ID:" with nothing in it, or a message without
the header when Postfix is not told to add one, is never joined with its
Rspamd scan, so it has no row in Messages. GET /api/messages/without-message-id
lists such messages from their stored Postfix lines, and the details endpoint
opens them by their noid- key. A Postfix queue id comes back once its file is
gone; a message never takes another message's lines. Dummy data only, against
the test PostgreSQL; the lines go through the real Postfix import.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

MARK = uuid.uuid4().hex[:8]
HEX = MARK.upper()
SCANNER = f'scanner-{MARK}@example.test'
OFFICE = f'office-{MARK}@example.test'
LISTED = f'archive-{MARK}@example.test'


def _q(n: int) -> str:
    """A queue id of this run (hex, as Postfix writes it)."""
    return f'D{HEX}{n:X}'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _wipe():
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog, RspamdLog
    with get_db_context() as db:
        db.query(PostfixLog).filter(PostfixLog.message.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.subject.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.query(MessageCorrelation).filter(
            MessageCorrelation.sender.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.commit()


@pytest.fixture
def api(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from fastapi.testclient import TestClient
    from app import scheduler
    from app.config import settings
    from app.database import init_db
    from app.main import app
    init_db()
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    monkeypatch.setattr(settings._inner, 'blacklist_emails', '')
    monkeypatch.setattr(scheduler, 'seen_postfix', set())
    _wipe()
    yield TestClient(app)
    _wipe()


NOW = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=1)


def _ingest(*lines):
    """Store lines through the Postfix import: (when, program, message)."""
    from app import scheduler
    scheduler._store_postfix_page([
        {'time': str(int(when.timestamp())), 'program': program, 'priority': 'info', 'message': f'{message} [{MARK}]'}
        for when, program, message in lines])


def _message(queue, at, message_id='', sender=SCANNER, to=OFFICE, client=None, status='sent', removed=True):
    """The lines of one message as Postfix logs them, client line first."""
    client = client or f'unknown[192.0.2.40], sasl_method=LOGIN, sasl_username={sender}'
    lines = [(at, 'postfix/submission/smtpd', f'{queue}: client={client}'),
             (at, 'postfix/cleanup', f'{queue}: message-id={message_id}'),
             (at + timedelta(seconds=1), 'postfix/qmgr', f'{queue}: from=<{sender}>, size=5328, nrcpt=1 (queue active)')]
    if status:
        lines.append((at + timedelta(seconds=2), 'postfix/lmtp',
                      f'{queue}: to=<{to}>, relay=dovecot, delay=2.1, delays=0.1/0/0/2, dsn=2.0.0, '
                      f'status={status} (250 2.0.0 Saved)'))
    if removed:
        lines.append((at + timedelta(seconds=2), 'postfix/qmgr', f'{queue}: removed'))
    return lines


def _list(api, **params):
    response = api.get('/api/messages/without-message-id', params={'search': MARK, **params})
    assert response.status_code == 200, response.text
    return response.json()


def _by_queue(body):
    return {row['queue_id']: row for row in body['data']}


def test_an_empty_message_id_is_listed_from_its_postfix_lines(api):
    _ingest(*_message(_q(1), NOW))
    body = _list(api)
    assert body['total'] == 1
    row = body['data'][0]
    assert row['correlation_key'].startswith('noid-')
    assert (row['queue_id'], row['sender'], row['recipient'], row['recipient_count']) == (_q(1), SCANNER, OFFICE, 1)
    assert (row['final_status'], row['is_complete'], row['queue_id_reused']) == ('delivered', True, False)
    assert (row['ip'], row['user']) == ('192.0.2.40', SCANNER)
    assert row['subject'] is None and row['message_id'] is None and row['spam_score'] is None

    details = api.get(f"/api/message/{row['correlation_key']}/details")
    assert details.status_code == 200, details.text
    data = details.json()
    assert data['rspamd'] is None and data['dovecot'] is None and data['related_deliveries'] == []
    assert data['client'] == {'ip': '192.0.2.40', 'host': 'unknown', 'user': SCANNER}
    assert data['recipients'] == [OFFICE] and data['final_status'] == 'delivered'
    assert len(data['postfix']) == 5


def test_brackets_alone_and_a_broken_field_are_listed_a_real_id_is_not(api):
    _ingest(*_message(_q(2), NOW, message_id='<>'),
            *_message(_q(3), NOW, message_id=f'broken: message-id=<x-{MARK}@example.test>'),
            *_message(_q(4), NOW, message_id=f'<real-{MARK}@example.test>'),
            (NOW, 'postfix/cleanup', f'{_q(5)}: resent-message-id='))
    assert set(_by_queue(_list(api))) == {_q(2), _q(3)}


def test_inbound_without_login_keeps_the_client_address(api):
    _ingest(*_message(_q(6), NOW, client='mx.example.org[192.0.2.7]:41234'))
    row = _by_queue(_list(api))[_q(6)]
    assert (row['ip'], row['user']) == ('192.0.2.7', None)
    details = api.get(f"/api/message/{row['correlation_key']}/details").json()
    assert details['client'] == {'ip': '192.0.2.7', 'host': 'mx.example.org', 'user': None}


def test_a_queue_id_used_again_close_by_shows_the_cleanup_line_only(api):
    """A message delivered and removed 30 seconds before its queue id names a
    message without a Message-ID: the second shows nothing of the first."""
    earlier = NOW - timedelta(seconds=78)
    _ingest(*_message(_q(7), earlier, message_id=f'<first-{MARK}@example.test>', to=LISTED.replace('archive', 'first')),
            *_message(_q(7), NOW))
    row = _by_queue(_list(api))[_q(7)]
    assert row['queue_id_reused'] is True
    assert (row['sender'], row['recipient'], row['recipient_count']) == (None, None, 0)
    assert (row['final_status'], row['is_complete'], row['ip']) == (None, None, None)
    details = api.get(f"/api/message/{row['correlation_key']}/details").json()
    assert [line['message'].split(' [')[0] for line in details['postfix']] == [f'{_q(7)}: message-id=']
    assert details['client'] is None and details['queue_id_reused'] is True
    # A search does not find it by the other message's addresses
    assert _q(7) not in _by_queue(_list(api, search=f'first-{MARK}'))
    assert _q(7) in _by_queue(_list(api, search=_q(7)))


def test_an_older_message_of_the_same_queue_id_stays_out(api):
    """The other message's cleanup line is more than 6 days old (it was on hold),
    its delivery 30 seconds before this one: only this message's lines count."""
    old = NOW - timedelta(days=8)
    other = f'other-{MARK}@example.test'
    _ingest((old, 'postfix/cleanup', f'{_q(8)}: message-id=<held-{MARK}@example.test>'),
            (NOW - timedelta(seconds=30), 'postfix/lmtp',
             f'{_q(8)}: to=<{other}>, relay=dovecot, delay=9, delays=0/0/0/9, dsn=2.0.0, status=sent (250 ok)'),
            (NOW - timedelta(seconds=30), 'postfix/qmgr', f'{_q(8)}: removed'),
            *_message(_q(8), NOW, status='deferred', removed=False))
    row = _by_queue(_list(api))[_q(8)]
    assert row['queue_id_reused'] is False
    assert (row['recipient'], row['final_status'], row['is_complete']) == (OFFICE, 'deferred', False)
    details = api.get(f"/api/message/{row['correlation_key']}/details").json()
    assert other not in str(details['postfix'])


def test_a_queue_id_used_again_after_six_days_is_two_messages(api):
    week = NOW - timedelta(days=7)
    first = f'first-{MARK}@example.test'
    _ingest(*_message(_q(9), week, to=first), *_message(_q(9), NOW))
    rows = [row for row in _list(api, start_date=(NOW - timedelta(days=8)).isoformat())['data']
            if row['queue_id'] == _q(9)]
    assert sorted(row['recipient'] for row in rows) == sorted([first, OFFICE])
    assert all(row['queue_id_reused'] is False for row in rows)


def test_two_aliases_count_as_the_details_count_them(api):
    queue = _q(10)
    lines = _message(queue, NOW, status=None)
    for mailbox in ('a', 'b'):
        lines.append((NOW + timedelta(seconds=2), 'postfix/lmtp',
                      f'{queue}: to=<{mailbox}-{MARK}@example.test>, orig_to=<team-{MARK}@example.test>, relay=dovecot, '
                      f'delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 ok)'))
    _ingest(*lines)
    row = _by_queue(_list(api))[queue]
    details = api.get(f"/api/message/{row['correlation_key']}/details").json()
    assert row['recipient_count'] == details['recipient_count'] == 1


def test_an_excluded_address_anywhere_in_the_message_hides_it(api, monkeypatch):
    from app.config import settings
    queue = _q(11)
    _ingest(*_message(queue, NOW, status='deferred', removed=False),
            (NOW + timedelta(days=2), 'postfix/lmtp',
             f'{queue}: to=<{LISTED}>, relay=dovecot, delay=9, delays=0/0/0/9, dsn=2.0.0, status=sent (250 ok)'))
    key = _by_queue(_list(api))[queue]['correlation_key']
    # The address is listed after the lines were stored
    monkeypatch.setattr(settings._inner, 'blacklist_emails', LISTED)
    assert queue not in _by_queue(_list(api))
    assert api.get(f'/api/message/{key}/details').status_code == 404


def test_pages_follow_the_cursor_and_the_total_counts_them_all(api):
    _ingest(*_message(_q(12), NOW - timedelta(minutes=2)), *_message(_q(13), NOW - timedelta(minutes=1)),
            *_message(_q(14), NOW))
    first = _list(api, limit=2)
    assert first['total'] == 3 and [r['queue_id'] for r in first['data']] == [_q(14), _q(13)]
    second = _list(api, limit=2, cursor=first['next_cursor'])
    assert [r['queue_id'] for r in second['data']] == [_q(12)] and second['next_cursor'] is None
    oldest = _list(api, limit=3, order='asc')
    assert [r['queue_id'] for r in oldest['data']] == [_q(12), _q(13), _q(14)]
    assert api.get('/api/messages/without-message-id', params={'cursor': 'nonsense'}).status_code == 422


def test_search_finds_the_client_and_the_queue_id(api):
    _ingest(*_message(_q(15), NOW, client=f'printer-{MARK}.example.test[192.0.2.99]'))
    assert _q(15) in _by_queue(_list(api, search=f'printer-{MARK}'))
    assert _q(15) in _by_queue(_list(api, search=_q(15).lower()))
    body = api.get('/api/messages/without-message-id', params={'search': f'nothing-{MARK}'}).json()
    assert body['total'] == 0 and body['data'] == []


def test_keys_that_are_not_such_a_message_are_not_found(api):
    _ingest(*_message(_q(16), NOW))
    from app.database import get_db_context
    from app.models import PostfixLog
    with get_db_context() as db:
        delivery = db.query(PostfixLog).filter(PostfixLog.queue_id == _q(16), PostfixLog.status == 'sent').one()
        delivery_id = delivery.id
    for key in ('noid-', 'noid-abc', 'noid-0', 'noid-' + '9' * 25, 'noid-' + '9' * 18, f'noid-{delivery_id}', 'noid--1', 'noid-1 '):
        assert api.get(f'/api/message/{key}/details').status_code == 404, key


def test_a_message_without_a_message_id_never_gets_a_correlation(api):
    """The paths that create correlations skip an empty Message-ID, so a listed
    message is never also a Messages row (the list does not check for one)."""
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog, RspamdLog
    from app.services import correlation_jobs
    from app.correlation import correlate_postfix_log
    _ingest(*_message(_q(17), NOW))
    picked = []
    with get_db_context() as db:
        for message_id in ('', 'undef'):
            db.add(RspamdLog(time=NOW.replace(tzinfo=None), message_id=message_id, sender_smtp=SCANNER,
                             subject=f'scan {MARK}', action='no action', score=0.0, required_score=15.0, symbols={}))
        db.commit()
        for line in db.query(PostfixLog).filter(PostfixLog.queue_id == _q(17)).all():
            assert correlate_postfix_log(db, line) is None
    correlation_jobs.run_correlation(get_db_context=get_db_context, is_blacklisted=lambda _: False,
                                     correlate=lambda db, scan: picked.append(scan.subject))
    assert not any(MARK in subject for subject in picked)
    with get_db_context() as db:
        assert db.query(MessageCorrelation).filter(MessageCorrelation.sender == SCANNER).count() == 0


# -- migration 0026 -------------------------------------------------------------

def _revision():
    import importlib.util
    import pathlib
    path = next((pathlib.Path(__file__).resolve().parent.parent / 'alembic' / 'versions').glob('0026_*.py'))
    spec = importlib.util.spec_from_file_location('postfix_no_message_id_index', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def isolated_engine():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from sqlalchemy import create_engine, text
    from app.database import engine
    schema = 'no_message_id_' + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA {schema}'))
    isolated = create_engine(engine.url, connect_args={'options': f'-csearch_path={schema}'})
    try:
        yield isolated
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f'DROP SCHEMA {schema} CASCADE'))


def _run(engine, step):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            step()


def _indexes(engine):
    from sqlalchemy import inspect
    return {index['name'] for index in inspect(engine).get_indexes('postfix_logs')}


def test_a_new_install_has_the_index_and_the_migration_passes(isolated_engine):
    """create_all builds it from the model before the migrations run."""
    from app.database import Base
    from app.models import PostfixLog
    Base.metadata.create_all(isolated_engine, tables=[PostfixLog.__table__])
    revision = _revision()
    assert revision.INDEX in _indexes(isolated_engine)
    _run(isolated_engine, revision.upgrade)
    _run(isolated_engine, revision.upgrade)
    assert revision.INDEX in _indexes(isolated_engine)


def test_an_existing_install_gets_the_index_and_keeps_its_lines(isolated_engine):
    from sqlalchemy import text
    from app.database import Base
    from app.models import PostfixLog
    revision = _revision()
    Base.metadata.create_all(isolated_engine, tables=[PostfixLog.__table__])
    with isolated_engine.begin() as conn:
        conn.execute(text(f'DROP INDEX {revision.INDEX}'))
        conn.execute(text("INSERT INTO postfix_logs (time, program, message, queue_id) VALUES "
                          "(now(), 'postfix/cleanup', 'D1: message-id=', 'D1'), "
                          "(now(), 'postfix/qmgr', 'D1: removed', 'D1')"))
    assert revision.INDEX not in _indexes(isolated_engine)
    _run(isolated_engine, revision.upgrade)
    assert revision.INDEX in _indexes(isolated_engine)
    with isolated_engine.connect() as conn:
        assert conn.execute(text('SELECT count(*) FROM postfix_logs')).scalar() == 2
    _run(isolated_engine, revision.downgrade)
    assert revision.INDEX not in _indexes(isolated_engine)
    _run(isolated_engine, revision.downgrade)
