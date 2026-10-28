"""Two Postfix lines are the same line only when the whole line matches.

The duplicate cache of the Postfix import keyed a line on its time and the
first 100 characters of its message. Lines of one queue in the same second
often share a long start: a message delivered to one mailbox through two
long aliases logs two lines that differ only in orig_to, after character 100.
The second line was taken for a duplicate before the database check saw it,
so it was never stored and a recipient was missing. The message details now
compare stored lines by the same fields. Exact duplicates are still stored once.
"""
import asyncio
import uuid
from contextlib import contextmanager
from datetime import datetime
from unittest.mock import AsyncMock

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app import scheduler  # noqa: E402
from app.config import settings  # noqa: E402

MARK = uuid.uuid4().hex[:8]
QUEUE = f'4B{MARK.upper()}'
TIME = 1700000000


def _delivery(alias: str, queue: str = QUEUE) -> str:
    """A delivery line whose orig_to only differs at the very end."""
    return (f'{queue}: to=<mailbox@example.com>, orig_to=<'
            f'{"team-distribution-list-" * 4}{alias}@example.com>, relay=dovecot, delay=0.4, '
            f'delays=0.1/0/0/0.3, dsn=2.0.0, status=sent (delivered via dovecot service)')


SALES = _delivery('sales')
SUPPORT = _delivery('support')


def _line(message: str, time: int = TIME) -> dict:
    return {'time': str(time), 'program': 'postfix/lmtp', 'priority': 'info', 'message': message}


def test_the_two_lines_share_their_first_100_characters():
    assert SALES[:100] == SUPPORT[:100] and SALES != SUPPORT


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def ingest(monkeypatch):
    """A schema of its own and a mailcow that serves whatever page is set."""
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session
    from app.database import Base, engine
    from app.models import MessageCorrelation, PostfixLog

    schema = 'postfix_dedup_' + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA {schema}'))
    isolated = create_engine(engine.url, connect_args={'options': f'-csearch_path={schema}'})
    Base.metadata.create_all(isolated, tables=[PostfixLog.__table__, MessageCorrelation.__table__])

    @contextmanager
    def session():
        with Session(isolated) as db:
            yield db

    served = {'logs': []}

    async def page(page_size, offset):
        return served['logs'][offset:offset + page_size]

    async def total(log_type):
        return len(served['logs'])

    monkeypatch.setattr(scheduler, 'get_db_context', session)
    monkeypatch.setattr(scheduler, 'seen_postfix', set())
    monkeypatch.setattr(scheduler, '_resume_offset', {'postfix': 0})
    monkeypatch.setattr(scheduler, 'last_fetch_run_time', {})
    monkeypatch.setattr(scheduler, '_discover_total_logs', AsyncMock(side_effect=total))
    monkeypatch.setattr(scheduler.mailcow_api, 'get_postfix_logs_page', page)
    monkeypatch.setattr(settings._inner, 'fetch_count_postfix', 100)
    monkeypatch.setattr(settings._inner, 'fetch_max_pages', 1)

    def fetch(logs):
        served['logs'] = logs
        asyncio.run(scheduler.fetch_and_store_postfix())

    def stored():
        with session() as db:
            return sorted(row.message for row in db.query(PostfixLog).all())

    try:
        yield fetch, stored, session
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f'DROP SCHEMA {schema} CASCADE'))


def test_lines_in_one_second_sharing_a_long_start_are_both_stored(ingest):
    fetch, stored, _ = ingest
    fetch([_line(SALES), _line(SUPPORT)])
    assert stored() == sorted([SALES, SUPPORT])


def test_a_line_sharing_a_long_start_with_an_earlier_fetch_is_stored(ingest):
    fetch, stored, _ = ingest
    fetch([_line(SALES)])
    # The first line is in the duplicate cache now; the second must not match it
    fetch([_line(SUPPORT), _line(SALES)])
    assert stored() == sorted([SALES, SUPPORT])


def test_an_exact_duplicate_is_stored_once(ingest):
    fetch, stored, _ = ingest
    fetch([_line(SALES), _line(SALES)])
    assert stored() == [SALES]


def test_an_exact_duplicate_in_a_later_fetch_is_skipped_by_the_cache(ingest):
    fetch, stored, session = ingest
    fetch([_line(SALES)])
    assert stored() == [SALES]
    # With the stored row gone, only the cache can tell that the line was seen
    from app.models import PostfixLog
    with session() as db:
        db.query(PostfixLog).delete()
        db.commit()
    fetch([_line(SALES)])
    assert stored() == []


def test_an_exact_duplicate_of_a_stored_row_is_skipped_by_the_database_check(ingest):
    fetch, stored, _ = ingest
    fetch([_line(SALES)])
    scheduler.seen_postfix.clear()
    new, skipped, _ = scheduler._store_postfix_page([_line(SALES), _line(SUPPORT)])
    assert (new, skipped) == (1, 1)
    assert stored() == sorted([SALES, SUPPORT])


def test_the_cache_keeps_a_short_key_per_line(ingest):
    fetch, _, _ = ingest
    long_line = _delivery('x' * 2000)
    fetch([_line(long_line)])
    assert len(scheduler.seen_postfix) == 1
    assert all(len(key) < 200 for key in scheduler.seen_postfix)


def test_an_over_long_program_or_queue_id_matches_its_stored_row(ingest):
    """Program and queue id are cut to their columns when stored, so the key
    is built from the cut values: with the cache cleared, the stored row
    still tells the line was seen."""
    fetch, stored, _ = ingest
    lines = [
        {'time': str(TIME), 'program': 'postfix/' + 'p' * 150, 'priority': 'info', 'message': SALES},
        {'time': str(TIME), 'program': 'postfix/lmtp', 'priority': 'info',
         'message': _delivery('sales', queue='A' * 60)},
    ]
    fetch(lines)
    assert len(stored()) == 2
    scheduler.seen_postfix.clear()
    new, skipped, _ = scheduler._store_postfix_page(lines)
    assert (new, skipped) == (0, 2)
    assert len(stored()) == 2


def _row(message: str, time: datetime, program: str = 'postfix/lmtp', queue_id: str = QUEUE):
    from types import SimpleNamespace
    return SimpleNamespace(time=time, program=program, priority='info', queue_id=queue_id, message=message,
                           recipient='mailbox@example.com', status='sent', relay='dovecot', delay=0.4,
                           dsn='2.0.0')


def test_grouping_by_recipient_keeps_lines_sharing_a_long_start():
    from app.routers.messages import _group_postfix_by_recipient
    now = datetime(2026, 1, 1, 12, 0, 0)
    grouped = _group_postfix_by_recipient([_row(SALES, now), _row(SUPPORT, now), _row(SALES, now)])
    assert [line['message'] for line in grouped['mailbox@example.com']] == [SALES, SUPPORT]


def test_grouping_by_recipient_keeps_lines_of_another_program_or_queue():
    """Same time and message, but another program or another queue id: the
    database stores them as two lines, and the details show both."""
    from app.routers.messages import _group_postfix_by_recipient
    now = datetime(2026, 1, 1, 12, 0, 0)
    rows = [_row(SALES, now), _row(SALES, now, program='postfix/pipe'), _row(SALES, now, queue_id='5C0FFEE0'),
            _row(SALES, now)]
    grouped = _group_postfix_by_recipient(rows)
    assert [(line['program'], line['message']) for line in grouped['mailbox@example.com']] \
        == [('postfix/lmtp', SALES), ('postfix/pipe', SALES), ('postfix/lmtp', SALES)]


@pytest.fixture()
def details(monkeypatch):
    """Two messages whose Postfix lines share time and message: one by queue id
    with another program, one linked by line ids with another queue id."""
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    from app.database import get_db_context, init_db
    from app.models import MessageCorrelation, PostfixLog
    init_db()
    now = datetime.utcnow().replace(microsecond=0)
    by_queue, by_ids = f'5C{MARK.upper()}', f'6D{MARK.upper()}'
    queues = (by_queue, by_ids, f'7E{MARK.upper()}')
    message = f'{by_queue}: to=<mailbox@example.com>, relay=dovecot, dsn=2.0.0, status=sent (delivered)'
    keys = (uuid.uuid4().hex, uuid.uuid4().hex)

    def line(queue_id, program):
        return PostfixLog(time=now, program=program, priority='info', queue_id=queue_id, message=message,
                          recipient='mailbox@example.com', status='sent')

    with get_db_context() as db:
        db.add_all([line(by_queue, 'postfix/lmtp'), line(by_queue, 'postfix/pipe')])
        linked = [line(by_ids, 'postfix/lmtp'), line(queues[2], 'postfix/lmtp')]
        db.add_all(linked)
        db.flush()
        for key, queue_id, ids in ((keys[0], by_queue, None), (keys[1], None, [row.id for row in linked])):
            db.add(MessageCorrelation(correlation_key=key, message_id=f'{key}@example.com', queue_id=queue_id,
                                      postfix_log_ids=ids, sender='sender@example.com',
                                      recipient='mailbox@example.com', direction='inbound',
                                      final_status='delivered', is_complete=True, first_seen=now, last_seen=now,
                                      created_at=now))
        db.commit()
    from fastapi.testclient import TestClient
    from app.main import app
    yield TestClient(app), keys
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(MessageCorrelation.correlation_key.in_(keys)).delete(
            synchronize_session=False)
        db.query(PostfixLog).filter(PostfixLog.queue_id.in_(queues)).delete(synchronize_session=False)
        db.commit()


def test_the_details_keep_a_line_of_another_program(details):
    client, (key, _) = details
    payload = client.get(f'/api/message/{key}/details').json()
    assert sorted(line['program'] for line in payload['postfix']) == ['postfix/lmtp', 'postfix/pipe']
    assert len(payload['postfix_by_recipient']['mailbox@example.com']) == 2


def test_the_details_keep_a_linked_line_of_another_queue(details):
    client, (_, key) = details
    payload = client.get(f'/api/message/{key}/details').json()
    assert len(payload['postfix']) == 2
    assert len(payload['postfix_by_recipient']['mailbox@example.com']) == 2
