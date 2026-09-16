"""Dovecot delivery correlation (issue #65).

Postfix logs status=sent the moment it hands a message to Dovecot over LMTP,
so a message dropped by a Sieve ``discard`` rule was shown as delivered. The
dovecot_parser turns the LMTP/LDA lines the raw logs worker already collects
into per-delivery verdicts, and correlate_dovecot_logs attaches them to the
existing MessageCorrelation rows - flipping the final status to 'discarded'
where Dovecot dropped the message, and pinning that verdict against every
Postfix-driven job that would otherwise flip it back to 'delivered'.
"""
import asyncio
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.config import settings
from app.services.dovecot_parser import (
    parse_dovecot_message,
    pick_worst_verdict,
    resolve_session_verdicts,
)

MARKER = 'dovecot-corr.invalid'
USER = f'rcpt@{MARKER}'


def _msgid():
    return f'{uuid.uuid4().hex}@{MARKER}'


def _lmtp(rest, user=USER, session='SessAbc123', pid='1234'):
    return f'lmtp({user})<{pid}><{session}>: {rest}'


# ---------- parser: recognised line shapes ----------

@pytest.mark.parametrize('rest,verdict,mailbox,detail', [
    ("sieve: msgid=<m@d>: stored mail into mailbox 'INBOX'", 'stored', 'INBOX', None),
    ("sieve: msgid=<m@d>: stored mail into mailbox 'Junk'", 'stored', 'Junk', None),
    ('msgid=<m@d>: saved mail to INBOX', 'stored', 'INBOX', None),
    ('sieve: msgid=<m@d>: discarded message', 'discarded', None, None),
    ('sieve: msgid=<m@d>: marked message to be discarded if not explicitly '
     'delivered (discard action)', 'discard_pending', None, None),
    ('sieve: msgid=<m@d>: rejected message from <sender@remote.invalid> '
     '(spam content)', 'rejected', None, 'spam content'),
    ('sieve: msgid=<m@d>: forwarded to <other@remote.invalid>', 'forwarded',
     None, 'other@remote.invalid'),
    ('msgid=<m@d>: save failed to INBOX: Quota exceeded (mailbox for user is full)',
     'failed', 'INBOX', 'Quota exceeded (mailbox for user is full)'),
    ("sieve: msgid=<m@d>: failed to store into mailbox 'Archive': "
     'Mailbox does not exist', 'failed', 'Archive', 'Mailbox does not exist'),
])
def test_parser_recognised_shapes(rest, verdict, mailbox, detail):
    parsed = parse_dovecot_message(_lmtp(rest))
    assert parsed is not None
    assert parsed['message_id'] == 'm@d'
    assert parsed['verdict'] == verdict
    assert parsed['mailbox'] == mailbox
    assert parsed['detail'] == detail
    assert parsed['recipient'] == USER
    assert parsed['session'] == 'SessAbc123'


def test_parser_real_server_lines():
    """Ground truth captured from a live mailcow server."""
    stored = parse_dovecot_message(
        'lmtp(13163@sendmail.co.il)<3698783><QFzrJ1zXpmpfcDgAiLK9ww>: sieve: '
        'msgid=<20260913170323.CE9116E38E2@web.sendmail.co.il>: '
        "stored mail into mailbox 'INBOX'")
    assert stored['verdict'] == 'stored'
    assert stored['mailbox'] == 'INBOX'
    assert stored['recipient'] == '13163@sendmail.co.il'
    assert stored['session'] == 'QFzrJ1zXpmpfcDgAiLK9ww'
    assert stored['message_id'] == '20260913170323.CE9116E38E2@web.sendmail.co.il'

    # Connection noise has no msgid and must be skipped cheaply
    assert parse_dovecot_message('lmtp(1015): Connect from 172.22.1.253') is None
    assert parse_dovecot_message(
        'lmtp(1015): Disconnect from 172.22.1.253: Logged out (state=READY)') is None


def test_parser_ignores_imap_lines_with_msgid():
    """IMAP expunge/delete lines carry msgid= but are not deliveries."""
    assert parse_dovecot_message(
        'imap(dmarc@sendmail.co.il)<3700941><UBeVKGBbNuPAqBgB>: expunge: '
        'box=INBOX, uid=1789, msgid=<f8768de4877d4210bf4c287cb04ad4cd@microsoft.com>, '
        'size=15600') is None


def test_parser_lda_prefix():
    parsed = parse_dovecot_message(
        f"lda({USER}): sieve: msgid=<m@d>: stored mail into mailbox 'INBOX'")
    assert parsed['verdict'] == 'stored'
    assert parsed['recipient'] == USER
    assert parsed['session'] is None


def test_parser_old_pid_comma_user_prefix():
    parsed = parse_dovecot_message(
        f"lmtp(12345, {USER}): sieve: msgid=<m@d>: discarded message")
    assert parsed['verdict'] == 'discarded'
    assert parsed['recipient'] == USER


def test_parser_msgid_unspecified_is_skipped():
    assert parse_dovecot_message(
        _lmtp("sieve: msgid=unspecified: stored mail into mailbox 'INBOX'")) is None
    assert parse_dovecot_message(None) is None
    assert parse_dovecot_message('') is None


def test_parser_folder_names_with_spaces():
    parsed = parse_dovecot_message(
        _lmtp("sieve: msgid=<m@d>: stored mail into mailbox 'Archive/Old Mail'"))
    assert parsed['verdict'] == 'stored'
    assert parsed['mailbox'] == 'Archive/Old Mail'


def test_parser_hostile_content_passes_through_unmodified():
    """The parser is not an escaping layer - it must hand hostile strings
    through untouched; the API/frontend own the escaping."""
    folder = '<img src=x onerror=alert(1)>'
    parsed = parse_dovecot_message(
        _lmtp(f"sieve: msgid=<m@d>: stored mail into mailbox '{folder}'"))
    assert parsed['mailbox'] == folder

    reason = '"><script>alert(2)</script>'
    parsed = parse_dovecot_message(
        _lmtp(f'sieve: msgid=<m@d>: rejected message from <s@d> ({reason})'))
    assert parsed['detail'] == reason


# ---------- resolving per-delivery verdicts ----------

def _ev(verdict, minute=0, session='S1', recipient=USER, mailbox=None):
    return {
        'message_id': 'm@d', 'recipient': recipient, 'session': session,
        'verdict': verdict, 'mailbox': mailbox, 'detail': None,
        'time': datetime(2026, 9, 13, 12, minute),
    }


def test_resolve_discard_only_session_is_discarded():
    resolved = resolve_session_verdicts([_ev('discard_pending', 0)])
    assert [e['verdict'] for e in resolved] == ['discarded']


def test_resolve_store_cancels_pending_discard_in_both_orders():
    """Regression: Sieve's "discarded if not explicitly delivered" is cancelled
    by a fileinto no matter which line the log shows first - the raw logs
    worker inserts pages newest-first, so order is not reliable."""
    pending_then_store = [
        _ev('discard_pending', 0),
        _ev('stored', 1, mailbox='Archive'),
    ]
    store_then_pending = [
        _ev('stored', 0, mailbox='Archive'),
        _ev('discard_pending', 1),
    ]
    for events in (pending_then_store, store_then_pending):
        resolved = resolve_session_verdicts(events)
        assert [e['verdict'] for e in resolved] == ['stored']
        assert resolved[0]['mailbox'] == 'Archive'


def test_resolve_explicit_discard_still_wins_over_store():
    resolved = resolve_session_verdicts([
        _ev('stored', 0, mailbox='INBOX'),
        _ev('discarded', 1),
    ])
    assert [e['verdict'] for e in resolved] == ['discarded']


def test_resolve_two_recipients_sharing_one_lmtp_session():
    """Regression: Postfix delivers multiple recipients over one LMTP session;
    every recipient logs with the same session id and needs its own verdict."""
    events = [
        _ev('stored', 0, session='Shared', recipient=f'a@{MARKER}', mailbox='INBOX'),
        _ev('discard_pending', 1, session='Shared', recipient=f'b@{MARKER}'),
    ]
    resolved = resolve_session_verdicts(events)
    verdicts = {e['recipient']: e['verdict'] for e in resolved}
    assert verdicts == {f'a@{MARKER}': 'stored', f'b@{MARKER}': 'discarded'}


def test_pick_worst_verdict_across_sessions():
    assert pick_worst_verdict(['stored', 'discarded']) == 'discarded'
    assert pick_worst_verdict(['stored', 'forwarded']) == 'forwarded'
    assert pick_worst_verdict(['rejected', 'discarded']) == 'rejected'
    assert pick_worst_verdict(['unknown']) is None
    assert pick_worst_verdict([]) is None


# ---------- database-backed job and precedence tests ----------

def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import (MessageCorrelation, PostfixLog, RawServiceLog,
                            SystemSetting)
    from app.scheduler import DOVECOT_WATERMARK_KEY
    with get_db_context() as db:
        db.query(RawServiceLog).filter(
            RawServiceLog.raw_data['message'].astext.like(f'%{MARKER}%')
        ).delete(synchronize_session=False)
        db.query(PostfixLog).filter(
            PostfixLog.message.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.query(MessageCorrelation).filter(
            MessageCorrelation.message_id.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.query(SystemSetting).filter(
            SystemSetting.key == DOVECOT_WATERMARK_KEY).delete(synchronize_session=False)
        db.commit()


def _set_watermark_to_current_max():
    """Pin the watermark so the job only walks the rows this test inserts."""
    from sqlalchemy import func
    from app.database import get_db_context
    from app.models import RawServiceLog, SystemSetting
    from app.scheduler import DOVECOT_WATERMARK_KEY
    with get_db_context() as db:
        max_id = db.query(func.max(RawServiceLog.id)).scalar() or 0
        db.add(SystemSetting(key=DOVECOT_WATERMARK_KEY, value=str(max_id)))
        db.commit()
        return max_id


def _get_watermark():
    from app.database import get_db_context
    from app.models import SystemSetting
    from app.scheduler import DOVECOT_WATERMARK_KEY
    with get_db_context() as db:
        row = db.query(SystemSetting).filter(
            SystemSetting.key == DOVECOT_WATERMARK_KEY).first()
        return int(row.value) if row and row.value else 0


@pytest.fixture()
def env(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db
    from app import scheduler as sched
    init_db()
    _cleanup()
    sched._dovecot_pending.clear()
    monkeypatch.setattr(sched, 'dovecot_correlation_available', lambda: True)
    _set_watermark_to_current_max()
    yield
    _cleanup()
    sched._dovecot_pending.clear()


def _add_raw_line(message, when=None):
    from app.database import get_db_context
    from app.models import RawServiceLog
    with get_db_context() as db:
        row = RawServiceLog(
            service='dovecot', time=when or datetime.utcnow(),
            message_hash=uuid.uuid4().hex,
            raw_data={'message': message, 'priority': 'info', 'program': 'dovecot'})
        db.add(row)
        db.commit()
        return row.id


def _add_correlation(msgid, queue_id=None, final_status='delivered',
                     dovecot_status=None, is_complete=True, age_minutes=1):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    when = datetime.utcnow() - timedelta(minutes=age_minutes)
    with get_db_context() as db:
        corr = MessageCorrelation(
            correlation_key=uuid.uuid4().hex, message_id=msgid,
            queue_id=queue_id, sender=f'sender@{MARKER}', recipient=USER,
            direction='inbound', final_status=final_status,
            dovecot_status=dovecot_status, is_complete=is_complete,
            first_seen=when, last_seen=when, created_at=when)
        db.add(corr)
        db.commit()
        return corr.correlation_key


def _add_postfix_log(queue_id, status, msgid=None, age_minutes=1):
    from app.database import get_db_context
    from app.models import PostfixLog
    with get_db_context() as db:
        db.add(PostfixLog(
            time=datetime.utcnow() - timedelta(minutes=age_minutes),
            program='postfix/lmtp', priority='info',
            message=(f'{queue_id}: to=<{USER}>, relay=dovecot, delay=0.5, '
                     f'dsn=2.0.0, status={status} ({MARKER} {uuid.uuid4().hex})'),
            queue_id=queue_id, message_id=msgid, recipient=USER, status=status))
        db.commit()


def _get_correlation(key):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    with get_db_context() as db:
        corr = db.query(MessageCorrelation).filter(
            MessageCorrelation.correlation_key == key).first()
        db.expunge(corr)
        return corr


def _run_dovecot_job():
    from app import scheduler as sched
    asyncio.run(sched.correlate_dovecot_logs())
    status = sched.job_status['correlate_dovecot']
    assert status['status'] == 'success', status['error']


def test_job_flips_delivered_to_discarded_and_advances_watermark(env):
    """The heart of the issue: Sieve discarded the message, Postfix said sent."""
    msgid = _msgid()
    key = _add_correlation(msgid, final_status='delivered')
    row_id = _add_raw_line(_lmtp(f'sieve: msgid=<{msgid}>: discarded message'))

    _run_dovecot_job()

    corr = _get_correlation(key)
    assert corr.dovecot_status == 'discarded'
    assert corr.final_status == 'discarded'
    assert _get_watermark() >= row_id


def test_job_records_the_target_folder_without_touching_final_status(env):
    msgid = _msgid()
    key = _add_correlation(msgid, final_status='delivered')
    _add_raw_line(_lmtp(f"sieve: msgid=<{msgid}>: stored mail into mailbox 'Junk'"))

    _run_dovecot_job()

    corr = _get_correlation(key)
    assert corr.dovecot_status == 'stored'
    assert corr.dovecot_mailbox == 'Junk'
    assert corr.final_status == 'delivered'


def test_job_applies_line_that_arrived_before_its_correlation(env):
    """The dovecot line lands first, the correlation only exists on a later
    cycle - the parked events must still be applied even though the watermark
    has moved past the raw row."""
    msgid = _msgid()
    row_id = _add_raw_line(_lmtp(f'sieve: msgid=<{msgid}>: discarded message'))

    _run_dovecot_job()
    assert _get_watermark() >= row_id  # watermark advances even when unmatched

    key = _add_correlation(msgid, final_status='delivered')
    _run_dovecot_job()

    corr = _get_correlation(key)
    assert corr.dovecot_status == 'discarded'
    assert corr.final_status == 'discarded'


def test_job_is_idempotent(env):
    msgid = _msgid()
    key = _add_correlation(msgid, final_status='delivered')
    _add_raw_line(_lmtp(f'sieve: msgid=<{msgid}>: discarded message'))

    _run_dovecot_job()
    first = _get_correlation(key)
    _run_dovecot_job()
    second = _get_correlation(key)

    assert (first.dovecot_status, first.final_status) == ('discarded', 'discarded')
    assert (second.dovecot_status, second.final_status) == ('discarded', 'discarded')
    assert second.updated_at == first.updated_at  # second run wrote nothing


# ---------- precedence: 'discarded' survives the Postfix-driven jobs ----------

def test_recompute_keeps_discarded_over_a_late_sent_line(env):
    """Regression for the freeze-fix seam (PR #115): the queue-driven recompute
    derives 'delivered' from status=sent and must not resurrect the message."""
    from app.database import get_db_context
    from app.models import MessageCorrelation
    from app import scheduler as sched

    msgid = _msgid()
    queue = uuid.uuid4().hex[:10].upper()
    key = _add_correlation(msgid, queue_id=queue, final_status='discarded',
                           dovecot_status='discarded')
    _add_postfix_log(queue, 'sent', msgid=msgid)

    with get_db_context() as db:
        corr = db.query(MessageCorrelation).filter(
            MessageCorrelation.correlation_key == key).first()
        sched._recompute_correlation_from_postfix(db, corr)
        db.commit()

    assert _get_correlation(key).final_status == 'discarded'


def test_recompute_lets_a_real_bounce_win_over_discarded(env):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    from app import scheduler as sched

    msgid = _msgid()
    queue = uuid.uuid4().hex[:10].upper()
    key = _add_correlation(msgid, queue_id=queue, final_status='discarded',
                           dovecot_status='discarded')
    _add_postfix_log(queue, 'bounced', msgid=msgid)

    with get_db_context() as db:
        corr = db.query(MessageCorrelation).filter(
            MessageCorrelation.correlation_key == key).first()
        sched._recompute_correlation_from_postfix(db, corr)
        db.commit()

    assert _get_correlation(key).final_status == 'bounced'


def test_update_final_status_job_skips_discarded(env):
    from app import scheduler as sched

    msgid = _msgid()
    queue = uuid.uuid4().hex[:10].upper()
    key = _add_correlation(msgid, queue_id=queue, final_status='discarded',
                           dovecot_status='discarded')
    _add_postfix_log(queue, 'sent', msgid=msgid)

    asyncio.run(sched.update_final_status_for_correlations())
    assert sched.job_status['update_final_status']['status'] == 'success'

    assert _get_correlation(key).final_status == 'discarded'


def test_arrival_driven_push_path_skips_discarded(env):
    """PR #115 refreshes correlations when a status-bearing Postfix line
    arrives; PUSH_SKIP_FINAL_STATUSES must keep it away from a discard."""
    from app.database import get_db_context
    from app import scheduler as sched

    msgid = _msgid()
    queue = uuid.uuid4().hex[:10].upper()
    key = _add_correlation(msgid, queue_id=queue, final_status='discarded',
                           dovecot_status='discarded')
    _add_postfix_log(queue, 'sent', msgid=msgid)

    with get_db_context() as db:
        updated, skipped = sched.refresh_correlations_for_queue_ids(db, [queue])
        db.commit()

    assert updated == 0
    assert _get_correlation(key).final_status == 'discarded'


def test_complete_correlations_job_leaves_discarded_alone(env):
    from app import scheduler as sched

    msgid = _msgid()
    queue = uuid.uuid4().hex[:10].upper()
    key = _add_correlation(msgid, queue_id=None, final_status='discarded',
                           dovecot_status='discarded', is_complete=False)
    _add_postfix_log(queue, 'sent', msgid=msgid)

    asyncio.run(sched.complete_incomplete_correlations())
    assert sched.job_status['complete_correlations']['status'] == 'success'

    corr = _get_correlation(key)
    assert corr.is_complete is True          # the linking work still happens
    assert corr.queue_id == queue
    assert corr.final_status == 'discarded'  # but the verdict is kept


def test_expire_job_leaves_discarded_alone(env, monkeypatch):
    from app import scheduler as sched

    monkeypatch.setattr(settings._inner, 'max_correlation_age_minutes', 10)
    msgid = _msgid()
    key = _add_correlation(msgid, final_status='discarded',
                           dovecot_status='discarded', is_complete=False,
                           age_minutes=30)

    asyncio.run(sched.expire_old_correlations())
    assert sched.job_status['expire_correlations']['status'] == 'success'

    corr = _get_correlation(key)
    assert corr.final_status == 'discarded'
    assert corr.is_complete is True  # marked done so it is not re-fetched forever
