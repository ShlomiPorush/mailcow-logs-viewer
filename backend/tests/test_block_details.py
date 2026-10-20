"""Block details: every block keeps why it happened, with its own copy of the
evidence, for as long as the address is on the list.

Fictional addresses and messages only."""
import importlib.util
import io
import pathlib
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from app.config import settings
# init_db creates the tables of the models imported so far
import app.models  # noqa: F401

MARK = uuid.uuid4().hex[:8]
RCPT = f'gone-{MARK}@example.net'
OTHER = f'fine-{MARK}@example.net'
SENDER = f'sales-{MARK}@example.com'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture
def db_ready(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db
    init_db()
    for key, value in {'suppression_whitelist_domains': '', 'suppression_hard_bounce_action': 'suppress',
                       'queue_cleanup_enabled': True, 'auth_enabled': False, 'basic_auth_enabled': False,
                       'oauth2_enabled': False}.items():
        monkeypatch.setattr(settings._inner, key, value)
    yield
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog, SpamSuppression
    with get_db_context() as db:
        db.query(SpamSuppression).filter(SpamSuppression.email.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.query(PostfixLog).filter(PostfixLog.queue_id.like(f'%{MARK.upper()}%')).delete(synchronize_session=False)
        db.query(MessageCorrelation).filter(MessageCorrelation.correlation_key.like(f'{MARK}%')).delete(synchronize_session=False)
        db.commit()


def _line(queue_id, when, program, message, recipient=None, status=None, dsn=None, key=None):
    from app.models import PostfixLog
    return PostfixLog(time=when, program=program, priority='info', message=message, queue_id=queue_id,
                      recipient=recipient, status=status, dsn=dsn, correlation_key=key, created_at=datetime.utcnow())


def _events(email):
    from app.database import get_db_context
    from app.models import SpamSuppression, SuppressionEvent
    with get_db_context() as db:
        row = db.query(SpamSuppression).filter(SpamSuppression.email == email).one()
        events = db.query(SuppressionEvent).filter(SuppressionEvent.suppression_id == row.id) \
            .order_by(SuppressionEvent.id).all()
        # Plain copies: the session closes on return
        return row.id, [SimpleNamespace(**{c.name: getattr(e, c.name) for c in SuppressionEvent.__table__.columns})
                        for e in events]


def test_a_bounce_keeps_its_answer_message_and_only_its_own_lines(db_ready):
    from app import scheduler
    from app.database import get_db_context
    from app.models import MessageCorrelation
    queue_id, key, now = f'Q{MARK.upper()}', f'{MARK}-key', datetime.utcnow()
    with get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=key, sender=SENDER, recipient=RCPT, subject='Quarterly report',
                                  message_id=f'<{MARK}@example.com>', direction='outbound', final_status='bounced',
                                  first_seen=now, last_seen=now, created_at=now))
        db.add_all([
            _line(queue_id, now - timedelta(days=3), 'postfix/qmgr', 'an older message with the same queue id'),
            _line(queue_id, now - timedelta(seconds=5), 'postfix/qmgr', f'from=<{SENDER}>, size=1200, nrcpt=2 (queue active)'),
            _line(queue_id, now - timedelta(seconds=3), 'postfix/smtp', f'to=<{OTHER}>, status=sent (250 ok)', OTHER, 'sent', '2.0.0'),
            _line(queue_id, now, 'postfix/smtp',
                  f'to=<{RCPT}>, relay=mx.example.net, status=bounced (host mx.example.net said: 550 5.1.1 <{RCPT}>: no such user)',
                  RCPT, 'bounced', '5.1.1', key),
        ])
        db.commit()
    scheduler._detect_suppressions_worker()
    _, events = _events(RCPT)
    assert len(events) == 1
    e = events[0]
    assert (e.kind, e.outcome, e.dsn) == ('hard_bounce', 'created', '5.1.1')
    assert e.server_reply == f'host mx.example.net said: 550 5.1.1 <{RCPT}>: no such user'
    assert (e.sender, e.subject, e.message_id, e.queue_id) == (SENDER, 'Quarterly report', f'<{MARK}@example.com>', queue_id)
    messages = [line['message'] for line in e.log_lines]
    assert any('nrcpt=2' in m for m in messages) and any('no such user' in m for m in messages)
    assert not any(OTHER in m for m in messages), "another recipient's lines stay out"
    assert not any('older message' in m for m in messages), 'a reused queue id from days earlier stays out'


def test_a_long_message_keeps_the_deciding_line(db_ready):
    from app import scheduler
    from app.database import get_db_context
    queue_id, now = f'L{MARK.upper()}', datetime.utcnow()
    with get_db_context() as db:
        db.add_all([_line(queue_id, now - timedelta(seconds=200 - i), 'postfix/smtp',
                          f'to=<{RCPT}>, status=deferred (try {i})', RCPT, 'deferred', '4.4.1') for i in range(80)])
        db.add(_line(queue_id, now, 'postfix/smtp', f'to=<{RCPT}>, status=bounced (550 gone)', RCPT, 'bounced', '5.1.1'))
        db.commit()
    scheduler._detect_suppressions_worker()
    _, events = _events(RCPT)
    lines = events[-1].log_lines
    assert events[-1].logs_shortened and len(lines) <= 51
    assert lines[-1]['message'].endswith('(550 gone)')


def test_a_stuck_message_keeps_the_queue_details(db_ready):
    from app import scheduler
    arrived = datetime.utcnow() - timedelta(hours=2)
    scheduler._store_deferred_suppressions_worker([{'email': RCPT, 'queue_id': f'D{MARK.upper()}', 'sender': SENDER,
                                                    'arrived': arrived, 'reason': 'connect to mx.example.net: Connection timed out'}])
    _, events = _events(RCPT)
    e = events[-1]
    assert (e.kind, e.outcome, e.sender, e.queue_id) == ('deferred_stuck', 'created', SENDER, f'D{MARK.upper()}')
    assert e.server_reply == 'connect to mx.example.net: Connection timed out'
    assert abs((e.message_time - arrived).total_seconds()) < 1


@pytest.fixture
def client(db_ready, monkeypatch):
    import starlette.staticfiles as sf
    orig = sf.StaticFiles.__init__
    monkeypatch.setattr(sf.StaticFiles, '__init__', lambda s, *a, **k: orig(s, *a, **{**k, 'check_dir': False}))
    from app.routers import suppressions
    from unittest.mock import AsyncMock
    monkeypatch.setattr(suppressions, '_cleanup_queue_for_email', AsyncMock())
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


def test_changes_by_hand_are_kept_with_the_notes_of_the_time(client):
    created = client.post('/api/suppressions', json={'email': RCPT, 'reason': 'manual', 'notes': 'asked by support'})
    assert created.status_code == 200, created.text
    sid = created.json()['id']
    client.put(f'/api/suppressions/{sid}', json={'active': False})
    client.put(f'/api/suppressions/{sid}', json={'notes': 'customer left'})
    client.post('/api/suppressions', json={'email': RCPT, 'reason': 'manual', 'notes': 'back again'})
    _, events = _events(RCPT)
    assert [(e.kind, e.notes) for e in events] == [('added', 'asked by support'), ('disabled', 'asked by support'),
                                                   ('notes_changed', 'customer left'), ('enabled', 'back again')]


def test_an_import_keeps_new_rows_only(client):
    client.post('/api/suppressions', json={'email': OTHER, 'reason': 'manual'})
    body = f'email,type,reason,notes\n{RCPT},email,manual,from the old system\n{OTHER},email,manual,again\n'
    result = client.post('/api/suppressions/import', files={'file': ('list.csv', io.BytesIO(body.encode()))})
    assert result.json()['imported'] == 1
    assert [(e.kind, e.notes) for e in _events(RCPT)[1]] == [('imported', 'from the old system')]
    assert [e.kind for e in _events(OTHER)[1]] == ['added'], 'a skipped row adds nothing'


def test_details_read_newest_first_and_go_with_the_address(client):
    from app.database import get_db_context
    from app.models import SuppressionEvent
    sid = client.post('/api/suppressions', json={'email': RCPT, 'reason': 'manual', 'notes': 'one'}).json()['id']
    client.put(f'/api/suppressions/{sid}', json={'notes': 'two'})
    data = client.get(f'/api/suppressions/{sid}/events').json()
    assert [e['kind'] for e in data['events']] == ['notes_changed', 'added'] and data['total'] == 2
    assert data['events'][0]['message_available'] is False
    client.delete(f'/api/suppressions/{sid}')
    with get_db_context() as db:
        assert db.query(SuppressionEvent).filter(SuppressionEvent.suppression_id == sid).count() == 0


def test_the_upgrade_keeps_what_an_existing_block_knows(db_ready):
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session
    from app.database import engine
    from app.models import Base, SpamSuppression, SuppressionEvent
    path = sorted((pathlib.Path(__file__).resolve().parent.parent / 'alembic' / 'versions').glob('*_suppression_events.py'))[0]
    spec = importlib.util.spec_from_file_location('rev0019', path)
    revision = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(revision)
    schema = 'block_details_' + MARK
    with engine.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA {schema}'))
    isolated = create_engine(engine.url, connect_args={'options': f'-csearch_path={schema}'})
    try:
        Base.metadata.create_all(isolated, tables=[SpamSuppression.__table__, SuppressionEvent.__table__])
        with Session(isolated) as db:
            db.add(SpamSuppression(email=RCPT, reason='hard_bounce', source='auto', last_bounce_dsn='5.1.1',
                                   last_bounce_message='550 no such user', notes='kept', active=True))
            db.commit()
        from alembic.migration import MigrationContext
        from alembic.operations import Operations
        for _ in range(2):
            with isolated.begin() as conn:
                with Operations.context(MigrationContext.configure(conn)):
                    revision.upgrade()
        with Session(isolated) as db:
            events = db.query(SuppressionEvent).all()
            assert [(e.kind, e.reason, e.dsn, e.server_reply, e.notes) for e in events] == \
                [('before_upgrade', 'hard_bounce', '5.1.1', '550 no such user', 'kept')], 'once, with only what the row knew'
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f'DROP SCHEMA {schema} CASCADE'))


def test_each_event_keeps_the_expiry_it_set_and_its_own_message(db_ready):
    """Two bounces of one address in one run: a queue id Postfix reused four
    days later is another message, and each event keeps the expiry it set."""
    from app import scheduler
    from app.database import get_db_context
    queue_id, now = f'R{MARK.upper()}', datetime.utcnow()
    with get_db_context() as db:
        db.add_all([
            _line(queue_id, now - timedelta(days=4), 'postfix/smtp',
                  f'to=<{RCPT}>, status=bounced (550 first message)', RCPT, 'bounced', '5.1.1'),
            _line(queue_id, now, 'postfix/smtp', f'to=<{RCPT}>, status=bounced (550 second message)', RCPT, 'bounced', '5.1.1'),
        ])
        db.commit()
    scheduler._detect_suppressions_worker()
    _, events = _events(RCPT)
    assert [e.outcome for e in events] == ['created', 'extended']
    assert events[0].expires_at < events[1].expires_at, 'the first event keeps the expiry it set'
    first, second = ([line['message'] for line in e.log_lines] for e in events)
    assert any('first message' in m for m in first) and not any('second message' in m for m in first)
    assert any('second message' in m for m in second) and not any('first message' in m for m in second)
    assert all(line['time'].endswith('Z') for line in events[1].log_lines), 'log times are UTC, marked so'


def test_saving_the_same_expiry_again_records_nothing(client):
    sid = client.post('/api/suppressions', json={'email': RCPT, 'reason': 'manual', 'permanent': False,
                                                 'expires_at': '2030-01-02T03:04:05Z'}).json()['id']
    client.put(f'/api/suppressions/{sid}', json={'expires_at': '2030-01-02T03:04:05Z'})
    assert [e.kind for e in _events(RCPT)[1]] == ['added']
