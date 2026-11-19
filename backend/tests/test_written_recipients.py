"""The recipient address the sender wrote, when Rspamd recorded it normalized.

Rspamd's alias resolution (ALIAS_RESOLVED) records a Gmail recipient without
the dots of its local part and any recipient without its +tag; only Postfix
logs the written address. The Messages list, details, search and export
showed the normalized form, and the v3 details listed one recipient twice.
`written_recipients` maps the Rspamd form to the written one, stored when a
delivery is linked to its Postfix lines (and by revision 0027 for stored mail).
"""
import calendar
import json
import importlib.util
import uuid
from collections import namedtuple
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

MARKER = 'written-rcpt.invalid'
SENDER = f'sender@{MARKER}'
Line = namedtuple('Line', 'id time recipient message')
T0 = datetime(2026, 1, 1, 12, 0, 0)


def _line(i, to, orig_to=None, seconds=0):
    orig = f'orig_to=<{orig_to}>, ' if orig_to else ''
    return Line(i, T0 + timedelta(seconds=seconds), to,
                f'ABC123: to=<{to}>, {orig}relay=mx.example.com[192.0.2.1]:25, delay=1, dsn=2.0.0, status=sent (250 ok)')


# Gmail's domains stand in as .test ones, so no test names a real mailbox
FAKE_GMAIL = 'gmail.test'
FAKE_GMAIL_ALIASES = ('gmail.test', 'googlemail.test')


def _fake_gmail(module):
    module._GMAIL, module._GMAIL_ALIASES = FAKE_GMAIL, FAKE_GMAIL_ALIASES
    return module


def _migration():
    path = next((Path(__file__).resolve().parents[1] / 'alembic' / 'versions').glob('*_written_recipients.py'))
    spec = importlib.util.spec_from_file_location('written_recipients_migration', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return _fake_gmail(module)


@pytest.fixture(autouse=True)
def fake_gmail(monkeypatch):
    from app.services import written_recipients
    monkeypatch.setattr(written_recipients, '_GMAIL', FAKE_GMAIL)
    monkeypatch.setattr(written_recipients, '_GMAIL_ALIASES', FAKE_GMAIL_ALIASES)


def _rules():
    from app.services import written_recipients
    return [written_recipients, _migration()]


def test_the_dots_rule_is_for_gmail_and_googlemail_only():
    backend = Path(__file__).resolve().parents[1]
    for path in (backend / 'app' / 'services' / 'written_recipients.py',
                 next((backend / 'alembic' / 'versions').glob('*_written_recipients.py'))):
        source = path.read_text()
        assert "\n_GMAIL = 'gmail.com'\n" in source, path.name
        assert "\n_GMAIL_ALIASES = ('gmail.com', 'googlemail.com')\n" in source, path.name


RULE_CASES = [
    # (Rspamd recipients, Postfix lines, expected map)
    (['danalee@gmail.test'], [_line(1, 'Dana.Lee@gmail.test')], {'danalee@gmail.test': 'Dana.Lee@gmail.test'}),
    (['danalee@gmail.test'], [_line(1, 'dana.lee@googlemail.test')], {'danalee@gmail.test': 'dana.lee@googlemail.test'}),
    (['dana@example.com'], [_line(1, 'dana+news@example.com')], {'dana@example.com': 'dana+news@example.com'}),
    (['danalee@gmail.test'], [_line(1, 'dana.lee+x@gmail.test')], {'danalee@gmail.test': 'dana.lee+x@gmail.test'}),
    # Dots only count on Gmail: another domain's dotted address is another person
    (['danalee@example.com'], [_line(1, 'dana.lee@example.com')], {}),
    # An address with a delivery line of its own is already right
    (['dana@example.com'], [_line(1, 'dana@example.com'), _line(2, 'dana+x@example.com')], {}),
    # Postfix delivered to the address without the tag and kept the written one in orig_to
    (['dana@example.com'], [_line(1, 'dana@example.com', orig_to='dana+news@example.com')],
     {'dana@example.com': 'dana+news@example.com'}),
    # Only a delivery line's fixed fields count, never an address in another line's text
    (['dana@example.com'], [Line(1, T0, 'dana+forged@example.com',
                                 'ABC123: from=<"to=<dana+forged@example.com>"@sender.invalid>, size=100, nrcpt=1')], {}),
    # Among many: each its own
    (['danalee@gmail.test', 'b@example.net'], [_line(1, 'b@example.net'), _line(2, 'dana.lee@gmail.test')],
     {'danalee@gmail.test': 'dana.lee@gmail.test'}),
    # Two written forms of one mailbox: the earliest delivery line
    (['danalee@gmail.test'], [_line(2, 'd.analee@gmail.test', seconds=5), _line(1, 'dana.lee@gmail.test', seconds=1)],
     {'danalee@gmail.test': 'dana.lee@gmail.test'}),
    # The same Rspamd address twice, in two cases
    (['danalee@gmail.test', 'DanaLee@gmail.test'], [_line(1, 'Dana.Lee@gmail.test')], {'danalee@gmail.test': 'Dana.Lee@gmail.test'}),
    # An alias Postfix expanded: the address written is orig_to
    (['teamlead@gmail.test'], [_line(1, 'mailbox@example.com', orig_to='team.lead@gmail.test')],
     {'teamlead@gmail.test': 'team.lead@gmail.test'}),
    # Odd input is left alone
    (['ab@gmail.test'], [_line(1, '"a.b"@gmail.test')], {}),
    (['ab@gmail.test'], [_line(1, 'a.b@x@gmail.test')], {}),
    (['ab@gmail.test'], [_line(1, 'a.' + 'b' * 300 + '@gmail.test')], {}),
    (['@gmail.test'], [_line(1, '.@gmail.test')], {}),
    ([], [_line(1, 'dana.lee@gmail.test')], {}),
]


@pytest.mark.parametrize('listed,lines,expected', RULE_CASES)
def test_the_rule_and_its_frozen_copy_in_the_upgrade(listed, lines, expected):
    for rule in _rules():
        assert rule.resolve(listed, lines) == expected, rule.__name__


def test_shown_prefers_the_written_address():
    from app.services.written_recipients import shown, shown_list
    written = {'danalee@gmail.test': 'Dana.Lee@gmail.test'}
    assert shown('DanaLee@gmail.test', written) == 'Dana.Lee@gmail.test'
    assert shown('other@example.com', written) == 'other@example.com'
    assert shown('danalee@gmail.test', None) == 'danalee@gmail.test'
    assert shown_list(['danalee@gmail.test', 'b@example.net'], written) == ['Dana.Lee@gmail.test', 'b@example.net']


# ---------- with PostgreSQL ----------

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
    monkeypatch.setattr(settings._inner, 'blacklist_emails', '')
    init_db()
    _cleanup()
    yield
    _cleanup()


def _msgid():
    return f'{uuid.uuid4().hex}@{MARKER}'


def _queue():
    return uuid.uuid4().hex[:10].upper()


def _postfix(queue_id, when, to=None, status='sent', msgid=None, orig_to=None):
    from app.database import get_db_context
    from app.models import PostfixLog
    if to:
        orig = f'orig_to=<{orig_to}>, ' if orig_to else ''
        message = (f'{queue_id or "ABCDEF0123"}: to=<{to}>, {orig}relay=mx.example.com[192.0.2.1]:25, delay=1, '
                   f'dsn=2.0.0, status={status} (250 ok {MARKER})')
    else:
        message = f'{queue_id}: message-id=<{msgid}> {MARKER}'
    with get_db_context() as db:
        row = PostfixLog(time=when, program='postfix/smtp' if to else 'postfix/cleanup', priority='info',
                         message=message, queue_id=queue_id, message_id=msgid, sender=SENDER,
                         recipient=to, status=status if to else None)
        db.add(row)
        db.commit()
        return row.id


def _rspamd(msgid, when, recipients, resolved=True):
    from app.database import get_db_context
    from app.models import RspamdLog
    symbols = {'MAILCOW_AUTH': {'score': -20}}
    if resolved:
        symbols['ALIAS_RESOLVED'] = {'score': 0}
    with get_db_context() as db:
        row = RspamdLog(time=when, message_id=msgid, sender_smtp=SENDER, recipients_smtp=recipients,
                        score=-18.5, required_score=15.0, action='no action', is_spam=False,
                        direction='outbound', user=SENDER, symbols=symbols)
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


def _row(key):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    with get_db_context() as db:
        row = db.query(MessageCorrelation).filter(MessageCorrelation.correlation_key == key).one()
        db.expunge(row)
        return row


def _list(**params):
    from app.database import get_db_context
    from app.routers.messages import get_unified_messages
    base = dict(page=1, limit=50, search=None, sender=None, recipient=None, direction=None, status=None,
                user=None, ip=None, start_date=None, end_date=None, order='desc', cursor=None, upto_id=None)
    base.update(params)
    with get_db_context() as db:
        return get_unified_messages(db=db, **base)['data']


def _delivered(rcpt_rspamd='danalee@gmail.test', rcpt_written='Dana.Lee@gmail.test', resolved=True):
    """Postfix lines first, then the Rspamd verdict: the correlation job links them."""
    msgid, queue = _msgid(), _queue()
    t0 = datetime.utcnow() - timedelta(minutes=2)
    _postfix(queue, t0, msgid=msgid)
    _postfix(queue, t0 + timedelta(seconds=1), to=rcpt_written)
    key = _correlate(_rspamd(msgid, t0, [rcpt_rspamd], resolved=resolved))
    return msgid, queue, key


def test_linking_stores_the_written_address_and_every_reader_shows_it(env):
    from fastapi.testclient import TestClient
    from app.main import app

    msgid, queue, key = _delivered()
    row = _row(key)
    assert row.recipient == 'danalee@gmail.test'  # matching keeps Rspamd's form
    assert row.written_recipients == {'danalee@gmail.test': 'Dana.Lee@gmail.test'}

    [listed] = _list(search=msgid)
    assert listed['recipient'] == 'Dana.Lee@gmail.test'

    details = TestClient(app).get(f'/api/message/{key}/details').json()
    assert details['recipient'] == 'Dana.Lee@gmail.test'
    assert details['recipients'] == ['Dana.Lee@gmail.test']

    # Either form finds it, in the search and in the recipient filter
    for term in ('Dana.Lee@gmail.test', 'danalee@gmail.test'):
        assert [m['correlation_key'] for m in _list(search=term) if m['message_id'] == msgid] == [key]
        assert [m['correlation_key'] for m in _list(recipient=term) if m['message_id'] == msgid] == [key]


def test_the_export_writes_the_written_address(env):
    from fastapi.testclient import TestClient
    from app.main import app

    msgid, _, _ = _delivered()
    body = TestClient(app).get('/api/export/messages/csv', params={'search': msgid}).text
    assert 'Dana.Lee@gmail.test' in body
    assert 'danalee@gmail.test' not in body


def test_without_the_symbol_nothing_is_stored(env):
    _, _, key = _delivered(rcpt_rspamd='danalee@gmail.test', resolved=False)
    assert _row(key).written_recipients is None


def test_a_queue_less_correlation_gets_it_when_it_adopts_its_lines(env):
    """Rspamd first (no Postfix line yet), then the lines, then the completion job."""
    from app import scheduler as sched
    msgid, queue = _msgid(), _queue()
    t0 = datetime.utcnow() - timedelta(minutes=2)
    key = _correlate(_rspamd(msgid, t0, ['dana@example.com']))
    assert _row(key).queue_id is None
    _postfix(queue, t0 + timedelta(seconds=1), msgid=msgid)
    _postfix(queue, t0 + timedelta(seconds=2), to='dana+news@example.com')
    sched._complete_incomplete_correlations_sync()
    row = _row(key)
    assert row.queue_id == queue
    assert row.written_recipients == {'dana@example.com': 'dana+news@example.com'}


def _ingest(monkeypatch, *lines):
    """Store Postfix lines the way the ingest does: lines are (time, message)."""
    from app import scheduler as sched
    monkeypatch.setattr(sched, 'seen_postfix', set())
    sched._store_postfix_page([{'time': str(calendar.timegm(when.timetuple())), 'program': 'postfix/smtp',
                                'priority': 'info', 'message': message} for when, message in lines])


def _delivery(queue, to, status='sent', relay='mx.example.com[192.0.2.1]:25'):
    return (f'{queue}: to=<{to}>, relay={relay}, delay=1, delays=0/0/0/1, dsn=2.0.0, '
            f'status={status} (250 ok {MARKER})')


def test_a_delivery_line_after_the_outcome_is_final_still_counts(env, monkeypatch):
    """Delivered to one recipient already; the other recipient's line comes later."""
    msgid, queue = _msgid(), _queue()
    t0 = datetime.utcnow().replace(microsecond=0) - timedelta(minutes=2)
    _postfix(queue, t0, msgid=msgid)
    _postfix(queue, t0 + timedelta(seconds=1), to='b@example.net')
    key = _correlate(_rspamd(msgid, t0, ['danalee@gmail.test', 'b@example.net']))
    row = _row(key)
    assert row.final_status == 'delivered' and not row.written_recipients

    _ingest(monkeypatch, (t0 + timedelta(seconds=30), _delivery(queue, 'dana.lee@gmail.test')))
    assert _row(key).written_recipients == {'danalee@gmail.test': 'dana.lee@gmail.test'}


def test_a_delivery_to_the_spam_folder_counts(env, monkeypatch):
    """Postfix reports it as status=sent through rspamd-pipe-spam; the app stores 'spam'."""
    msgid, queue = _msgid(), _queue()
    t0 = datetime.utcnow().replace(microsecond=0) - timedelta(minutes=2)
    _postfix(queue, t0, msgid=msgid)
    key = _correlate(_rspamd(msgid, t0, ['dana@example.com']))
    _ingest(monkeypatch, (t0 + timedelta(seconds=5), _delivery(queue, 'dana+x@example.com', relay='rspamd-pipe-spam')))
    assert _row(key).written_recipients == {'dana@example.com': 'dana+x@example.com'}


def test_a_queue_id_used_days_before_still_serves_this_delivery(env, monkeypatch):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    msgid, queue = _msgid(), _queue()
    t0 = datetime.utcnow().replace(microsecond=0) - timedelta(minutes=2)
    with get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=uuid.uuid4().hex, message_id=_msgid(), queue_id=queue,
                                  recipient='x@example.com', first_seen=t0 - timedelta(days=3), is_complete=True))
        db.commit()
    _postfix(queue, t0, msgid=msgid)
    key = _correlate(_rspamd(msgid, t0, ['danalee@gmail.test']))
    _ingest(monkeypatch, (t0 + timedelta(seconds=5), _delivery(queue, 'dana.lee@gmail.test')))
    assert _row(key).written_recipients == {'danalee@gmail.test': 'dana.lee@gmail.test'}


def test_a_failure_here_never_stops_the_ingest_or_the_status(env, monkeypatch):
    from app.services import written_recipients
    msgid, queue = _msgid(), _queue()
    t0 = datetime.utcnow().replace(microsecond=0) - timedelta(minutes=2)
    _postfix(queue, t0, msgid=msgid)
    _postfix(queue, t0 + timedelta(seconds=1), to='b@example.net', status='deferred')
    key = _correlate(_rspamd(msgid, t0, ['b@example.net']))
    assert _row(key).final_status == 'deferred'

    def broken(db, correlation, rspamd_log):
        db.execute(text('SELECT no_such_column FROM message_correlations'))
    monkeypatch.setattr(written_recipients, '_record', broken)
    monkeypatch.setattr(written_recipients, 'marked', lambda rspamd_log: True)
    _ingest(monkeypatch, (t0 + timedelta(seconds=60), _delivery(queue, 'b@example.net')))
    assert _row(key).final_status == 'delivered'


def test_a_stored_value_never_changes_and_writers_only_add(env):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    from app.services import written_recipients
    msgid, queue = _msgid(), _queue()
    t0 = datetime.utcnow() - timedelta(minutes=2)
    _postfix(queue, t0, msgid=msgid)
    key = _correlate(_rspamd(msgid, t0, ['danalee@gmail.test', 'otto@example.com']))
    assert _row(key).written_recipients is None

    def store(value):
        with get_db_context() as db:
            db.query(MessageCorrelation).filter(MessageCorrelation.correlation_key == key).update(
                {MessageCorrelation.written_recipients: value}, synchronize_session=False)
            db.commit()

    with get_db_context() as stale:
        # This writer read the row before another one stored a value
        row = stale.query(MessageCorrelation).filter(MessageCorrelation.correlation_key == key).one()
        store({'danalee@gmail.test': 'kept@gmail.test'})
        _postfix(queue, t0 + timedelta(seconds=1), to='dana.lee@gmail.test')
        _postfix(queue, t0 + timedelta(seconds=2), to='otto+x@example.com')
        assert written_recipients.record(stale, row)
        stale.commit()
    assert _row(key).written_recipients == {'danalee@gmail.test': 'kept@gmail.test', 'otto@example.com': 'otto+x@example.com'}

    # A JSON null left in the column counts as nothing stored
    with get_db_context() as db:
        db.execute(MessageCorrelation.__table__.update().where(MessageCorrelation.correlation_key == key)
                   .values(written_recipients=None))
        db.commit()
    with get_db_context() as db:
        row = db.query(MessageCorrelation).filter(MessageCorrelation.correlation_key == key).one()
        assert written_recipients.record(db, row)
        db.commit()
    assert _row(key).written_recipients == {'danalee@gmail.test': 'dana.lee@gmail.test', 'otto@example.com': 'otto+x@example.com'}


def test_a_queue_id_two_deliveries_share_then_is_not_used(env):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    msgid, queue = _msgid(), _queue()
    t0 = datetime.utcnow() - timedelta(minutes=2)
    with get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=uuid.uuid4().hex, message_id=_msgid(), queue_id=queue,
                                  recipient='x@example.com', first_seen=t0, is_complete=True))
        db.commit()
    _postfix(queue, t0, msgid=msgid)
    _postfix(queue, t0 + timedelta(seconds=1), to='dana.lee@gmail.test')
    key = _correlate(_rspamd(msgid, t0, ['danalee@gmail.test']))
    assert _row(key).written_recipients is None


def test_an_excluded_written_address_hides_the_message_and_the_cleanup_removes_it(env, monkeypatch):
    from fastapi.testclient import TestClient
    from app.config import settings
    from app.database import get_db_context
    from app.main import app
    from app.models import MessageCorrelation
    from app.services import excluded_addresses

    msgid, _, key = _delivered(rcpt_written='Secret.Person@gmail.test', rcpt_rspamd='secretperson@gmail.test')
    monkeypatch.setattr(settings._inner, 'blacklist_emails', 'secret.person@gmail.test')
    assert _list(search=msgid) == []
    assert TestClient(app).get(f'/api/message/{key}/details').status_code == 404
    with get_db_context() as db:
        excluded_addresses.cleanup(db)
        assert db.query(MessageCorrelation).filter(MessageCorrelation.correlation_key == key).count() == 0


# ---------- the upgrade ----------

def _store_old_row(recipients, lines, queue=None, linked=False):
    """A delivery stored before the upgrade: no written_recipients."""
    from app.database import get_db_context
    from app.models import MessageCorrelation
    msgid, queue = _msgid(), queue or _queue()
    t0 = datetime.utcnow() - timedelta(days=3)
    ids = [_postfix(queue if not linked else None, t0 + timedelta(seconds=i + 1), to=to) for i, to in enumerate(lines)]
    rspamd_id = _rspamd(msgid, t0, recipients)
    with get_db_context() as db:
        row = MessageCorrelation(correlation_key=uuid.uuid4().hex, message_id=msgid,
                                 queue_id=None if linked else queue, postfix_log_ids=ids, rspamd_log_id=rspamd_id,
                                 recipient=recipients[0], first_seen=t0, final_status='delivered', is_complete=True)
        db.add(row)
        db.commit()
        return row.correlation_key


def _upgrade(module=None):
    from app.database import engine
    with engine.begin() as connection:
        (module or _migration()).backfill(connection)


def test_the_upgrade_fills_stored_deliveries(env, monkeypatch):
    module = _migration()
    monkeypatch.setattr(module, 'BATCH', 1)
    by_queue = _store_old_row(['danalee@gmail.test'], ['Dana.Lee@gmail.test'])
    by_id = _store_old_row(['otto@example.com'], ['otto+x@example.com'], linked=True)
    untouched = _store_old_row(['dana.lee@example.com'], ['dana.lee@example.com'])
    _upgrade(module)
    assert _row(by_queue).written_recipients == {'danalee@gmail.test': 'Dana.Lee@gmail.test'}
    assert _row(by_id).written_recipients == {'otto@example.com': 'otto+x@example.com'}
    assert _row(untouched).written_recipients is None
    _upgrade(module)  # again: nothing changes
    assert _row(by_queue).written_recipients == {'danalee@gmail.test': 'Dana.Lee@gmail.test'}


def test_the_upgrade_skips_a_reused_queue_id_and_lines_of_another_day(env):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    queue = _queue()
    key = _store_old_row(['danalee@gmail.test'], [], queue=queue)
    # Postfix used the queue id again days later, for another message
    _postfix(queue, datetime.utcnow(), to='dana.lee@gmail.test')
    _upgrade()
    assert _row(key).written_recipients is None

    shared = _queue()
    first = _store_old_row(['danalee@gmail.test'], ['dana.lee@gmail.test'], queue=shared)
    with get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=uuid.uuid4().hex, message_id=_msgid(), queue_id=shared,
                                  recipient='x@example.com', first_seen=_row(first).first_seen, is_complete=True))
        db.commit()
    _upgrade()
    assert _row(first).written_recipients is None


def test_the_startup_cleanup_runs_before_the_column_exists(env):
    """The pre-Alembic duplicate cleanup must not read a column a later revision adds."""
    from sqlalchemy import text
    from app.database import engine, get_db_context
    from app.migrations import cleanup_duplicate_correlations
    from app.models import MessageCorrelation
    msgid = _msgid()
    with engine.begin() as connection:
        connection.execute(text('ALTER TABLE message_correlations DROP COLUMN written_recipients'))
    try:
        with engine.begin() as connection:
            for i in range(2):
                connection.execute(text(
                    "INSERT INTO message_correlations (correlation_key, message_id, queue_id, recipient, "
                    "first_seen, last_seen, is_complete) VALUES (:k, :m, 'QREUSED1', 'a@example.com', :t, :t, true)"),
                    {'k': uuid.uuid4().hex, 'm': msgid, 't': datetime.utcnow() + timedelta(seconds=i)})
        with get_db_context() as db:
            assert cleanup_duplicate_correlations(db) >= 1
        with engine.begin() as connection:
            count = connection.execute(text('SELECT COUNT(*) FROM message_correlations WHERE message_id = :m'),
                                       {'m': msgid}).scalar()
        assert count == 1
    finally:
        with engine.begin() as connection:
            connection.execute(text('ALTER TABLE message_correlations ADD COLUMN IF NOT EXISTS written_recipients JSONB'))
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(MessageCorrelation.message_id == msgid).delete(synchronize_session=False)
        db.commit()


def test_the_startup_cleanup_keeps_the_written_addresses_of_the_rows_it_merges(env):
    from app.database import engine, get_db_context
    from app.migrations import cleanup_duplicate_correlations
    from app.models import MessageCorrelation
    msgid, at = _msgid(), datetime.utcnow()
    with engine.begin() as connection:
        for written in ({'a@example.com': 'a+kept@example.com'}, {'a@example.com': 'a+other@example.com',
                                                                  'b@example.com': 'b+x@example.com'}):
            connection.execute(text(
                "INSERT INTO message_correlations (correlation_key, message_id, queue_id, recipient, first_seen, "
                "last_seen, is_complete, written_recipients) VALUES (:k, :m, 'QDUPLIC8', 'a@example.com', :t, :t, "
                "true, CAST(:w AS jsonb))"), {'k': uuid.uuid4().hex, 'm': msgid, 't': at, 'w': json.dumps(written)})
    with get_db_context() as db:
        assert cleanup_duplicate_correlations(db) >= 1
        [row] = db.query(MessageCorrelation).filter(MessageCorrelation.message_id == msgid).all()
        # Same first_seen: the older row (lower id) is kept, and its own value wins
        assert row.written_recipients == {'a@example.com': 'a+kept@example.com', 'b@example.com': 'b+x@example.com'}


def test_the_upgrade_reads_delivery_lines_as_the_app_does():
    from app.correlation import _PF_DELIVERY_RE
    assert _migration()._PF_DELIVERY_RE.pattern == _PF_DELIVERY_RE.pattern


def test_a_delivery_line_of_the_message_before_on_a_reused_queue_id_is_not_taken(env, monkeypatch):
    """The earlier message used the queue id 36 hours before and was delivered
    30 seconds before this one was first seen: its line is not this message's."""
    from app import scheduler as sched
    from app.database import get_db_context
    from app.models import MessageCorrelation
    msgid, queue = _msgid(), _queue()
    t0 = datetime.utcnow().replace(microsecond=0) - timedelta(minutes=2)
    with get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=uuid.uuid4().hex, message_id=_msgid(), queue_id=queue,
                                  recipient='dana@example.com', first_seen=t0 - timedelta(hours=36), is_complete=True))
        db.commit()
    _postfix(queue, t0 - timedelta(seconds=30), to='dana+old@example.com')
    key = _correlate(_rspamd(msgid, t0, ['dana@example.com']))
    _postfix(queue, t0 + timedelta(seconds=1), msgid=msgid)
    _postfix(queue, t0 + timedelta(seconds=2), to='dana+new@example.com')
    sched._complete_incomplete_correlations_sync()
    assert _row(key).written_recipients == {'dana@example.com': 'dana+new@example.com'}

    # The upgrade reads the same lines
    _cleanup_written(key)
    _upgrade()
    assert _row(key).written_recipients == {'dana@example.com': 'dana+new@example.com'}


def _cleanup_written(key):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    with get_db_context() as db:
        db.execute(MessageCorrelation.__table__.update().where(MessageCorrelation.correlation_key == key)
                   .values(written_recipients=None))
        db.commit()


def test_a_delivery_line_stored_while_the_link_is_made_is_not_lost(env, monkeypatch):
    """The ingest stores the delivery line after the completion job read the
    queue's lines and before it committed the link: neither may miss it."""
    from contextlib import contextmanager
    from app.database import get_db_context
    from app.services import correlation_jobs
    msgid, queue = _msgid(), _queue()
    t0 = datetime.utcnow().replace(microsecond=0) - timedelta(minutes=2)
    key = _correlate(_rspamd(msgid, t0, ['danalee@gmail.test']))
    _postfix(queue, t0 + timedelta(seconds=1), msgid=msgid)

    @contextmanager
    def racing_session():
        with get_db_context() as db:
            commit, raced = db.commit, []

            def commit_after_the_ingest():
                if not raced:
                    raced.append(1)
                    _ingest(monkeypatch, (t0 + timedelta(seconds=2), _delivery(queue, 'dana.lee@gmail.test')))
                commit()
            db.commit = commit_after_the_ingest
            yield db

    correlation_jobs.complete_incomplete_correlations(
        get_db_context=racing_session, update_job_status=lambda *a: None, max_age_minutes=60, clock=datetime)
    row = _row(key)
    assert row.queue_id == queue
    assert row.written_recipients == {'danalee@gmail.test': 'dana.lee@gmail.test'}


def test_a_delivery_in_the_same_second_as_the_scan_is_taken(env):
    """Rspamd's time has a fraction; Postfix logs the whole second."""
    from app import scheduler as sched
    msgid, queue = _msgid(), _queue()
    t0 = datetime.utcnow().replace(microsecond=0) - timedelta(minutes=2)
    key = _correlate(_rspamd(msgid, t0 + timedelta(milliseconds=700), ['danalee@gmail.test']))
    _postfix(queue, t0, msgid=msgid)
    _postfix(queue, t0, to='dana.lee@gmail.test')
    sched._complete_incomplete_correlations_sync()
    assert _row(key).written_recipients == {'danalee@gmail.test': 'dana.lee@gmail.test'}
