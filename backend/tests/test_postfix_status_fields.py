"""The delivery outcome of a Postfix line comes only from its result fields.

parse_postfix_message used to search the whole line for ``status=`` and
``dsn=``. An smtpd NOQUEUE reject line has neither field, but it carries the
client-chosen envelope sender and HELO name, so an unauthenticated SMTP client
sending ``MAIL FROM:<status=bounced.dsn=5.1.1@...>`` produced a stored
"hard bounce" for any recipient - and, with suppression enabled, an automatic
block of that recipient in Rspamd.

It also took the Message-ID from the reply text inside ``status=(...)``. On
mailcow every Dovecot LMTP reply quotes the recipient
(``250 2.0.0 <rcpt> <session> Saved``), so each local delivery was stored
with the mailbox address as its Message-ID, and an inbound message with
``Message-ID: <mailbox>`` was stitched to every earlier delivery to it.
"""
import asyncio
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.correlation import parse_postfix_message

MARKER = 'status-fields.invalid'


# ---- parser: forged status/dsn in client-controlled fields ----

FORGED_FROM = ('NOQUEUE: reject: RCPT from unknown[192.0.2.10]: 554 5.7.1 <ceo@partner.test>: '
               'Relay access denied; from=<status=bounced.dsn=5.1.1@sender.invalid> '
               'to=<ceo@partner.test> proto=ESMTP helo=<client.invalid>')
FORGED_HELO = ('NOQUEUE: reject: RCPT from unknown[192.0.2.11]: 554 5.7.1 <cfo@partner.test>: '
               'Relay access denied; from=<a@sender.invalid> to=<cfo@partner.test> '
               'proto=ESMTP helo=<status=bounced.dsn=5.1.1>')


@pytest.mark.parametrize('line', [FORGED_FROM, FORGED_HELO])
def test_noqueue_reject_never_yields_a_status_or_dsn(line):
    parsed = parse_postfix_message(line)
    assert parsed.get('status') is None
    assert parsed.get('dsn') is None
    assert parsed.get('queue_id') is None


def test_status_inside_the_recipient_address_is_ignored_on_a_queued_line():
    line = ('A1B2C3D4E5: milter-reject: END-OF-MESSAGE from mx.sender.invalid[192.0.2.9]: '
            '5.7.1 Spam message rejected; from=<status=bounced.dsn=5.1.1@sender.invalid> '
            'to=<user@example.com> proto=ESMTP helo=<mx.sender.invalid>')
    parsed = parse_postfix_message(line)
    assert parsed.get('queue_id') == 'A1B2C3D4E5'
    assert parsed.get('status') is None
    assert parsed.get('dsn') is None


def test_status_words_in_the_remote_reply_do_not_override_the_real_result():
    line = ('A1B2C3D4E5: to=<user@example.net>, relay=mx.example.net[192.0.2.20]:25, delay=1.2, '
            'delays=0.1/0/0.5/0.6, dsn=2.0.0, status=sent '
            '(250 2.0.0 Ok dsn=5.1.1, status=bounced queued as 99)')
    parsed = parse_postfix_message(line)
    assert parsed['status'] == 'sent'
    assert parsed['dsn'] == '2.0.0'


# ---- parser: genuine delivery-agent lines keep working ----

@pytest.mark.parametrize('line, status, dsn, recipient, relay, delay', [
    ('A1B2C3D4E5: to=<user@example.net>, relay=mx.example.net[192.0.2.20]:25, delay=1.4, '
     'delays=0.1/0/0.6/0.7, dsn=5.1.1, status=bounced (host mx.example.net[192.0.2.20] said: '
     '550 5.1.1 <user@example.net>: Recipient address rejected: User unknown '
     '(in reply to RCPT TO command))',
     'bounced', '5.1.1', 'user@example.net', 'mx.example.net[192.0.2.20]:25', 1.4),
    ('A1B2C3D4E5: to=<user@example.net>, relay=mx.example.net[192.0.2.20]:25, delay=2.1, '
     'delays=0.1/0/0.9/1.1, dsn=4.7.1, status=deferred (host mx.example.net[192.0.2.20] said: '
     '450 4.7.1 Greylisted, please try again later (in reply to RCPT TO command))',
     'deferred', '4.7.1', 'user@example.net', 'mx.example.net[192.0.2.20]:25', 2.1),
    ('A1B2C3D4E5: to=<user@example.com>, relay=dovecot[192.0.2.250]:24, delay=0.3, '
     'delays=0.1/0/0/0.2, dsn=2.0.0, status=sent (250 2.0.0 <user@example.com> AbCdEf Saved)',
     'sent', '2.0.0', 'user@example.com', 'dovecot[192.0.2.250]:24', 0.3),
    ('A1B2C3D4E5: to=<user@example.net>, relay=none, delay=0.02, delays=0.01/0/0/0.01, '
     'dsn=5.4.4, status=bounced (Host or domain name not found. Name service error for '
     'name=example.net type=AAAA: Host not found)',
     'bounced', '5.4.4', 'user@example.net', 'none', 0.02),
    ('A1B2C3D4E5: to=<user@example.net>, relay=mx.example.net[192.0.2.20]:25, conn_use=2, '
     'delay=0.5, delays=0.1/0/0.1/0.3, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 1A2B3C)',
     'sent', '2.0.0', 'user@example.net', 'mx.example.net[192.0.2.20]:25', 0.5),
])
def test_genuine_delivery_lines_keep_their_outcome(line, status, dsn, recipient, relay, delay):
    parsed = parse_postfix_message(line)
    assert parsed['queue_id'] == 'A1B2C3D4E5'
    assert parsed['status'] == status
    assert parsed['dsn'] == dsn
    assert parsed['recipient'] == recipient
    assert parsed['relay'] == relay
    assert parsed['delay'] == delay


def test_rspamd_pipe_spam_delivery_is_still_reported_as_spam():
    line = ('A1B2C3D4E5: to=<spam@localhost>, orig_to=<user@example.com>, relay=rspamd-pipe-spam, '
            'delay=0.1, delays=0.05/0/0/0.05, dsn=2.0.0, status=sent '
            '(delivered via rspamd-pipe-spam service)')
    parsed = parse_postfix_message(line)
    assert parsed['status'] == 'spam'
    assert parsed['recipient'] == 'user@example.com'


def test_a_remote_reply_mentioning_rspamd_pipe_spam_is_not_spam():
    line = ('A1B2C3D4E5: to=<user@example.net>, relay=mx.example.net[192.0.2.20]:25, delay=0.5, '
            'delays=0.1/0/0.1/0.3, dsn=2.0.0, status=sent (250 2.0.0 rspamd-pipe-spam)')
    assert parse_postfix_message(line)['status'] == 'sent'


def test_qmgr_expired_line_keeps_its_status():
    line = 'A1B2C3D4E5: from=<user@example.com>, status=expired, returned to sender'
    parsed = parse_postfix_message(line)
    assert parsed['status'] == 'expired'
    assert parsed['sender'] == 'user@example.com'


# ---- parser: Message-ID only from the cleanup line ----

def test_lmtp_reply_address_is_not_taken_as_the_message_id():
    line = ('A1B2C3D4E5: to=<alice@example.com>, relay=dovecot[192.0.2.250]:24, delay=0.1, '
            'delays=0.05/0/0/0.05, dsn=2.0.0, status=sent '
            '(250 2.0.0 <alice@example.com> qZQnLx3YbmZ5AQAAhRwMlg Saved)')
    assert parse_postfix_message(line).get('message_id') is None


def test_remote_reply_angle_address_is_not_taken_as_the_message_id():
    line = ('A1B2C3D4E5: to=<user@example.net>, relay=mx.example.net[192.0.2.20]:25, delay=0.5, '
            'delays=0.1/0/0.1/0.3, dsn=2.6.0, status=sent (250 2.6.0 <victim@example.org> Queued)')
    assert parse_postfix_message(line).get('message_id') is None


def test_cleanup_line_still_sets_the_message_id():
    assert parse_postfix_message('A1B2C3D4E5: message-id=<abc.123@example.com>')['message_id'] \
        == 'abc.123@example.com'


# ---- database: the bounce scan ignores smtpd NOQUEUE rejects ----

def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def db_env():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db
    init_db()
    _cleanup()
    yield
    _cleanup()


def _cleanup():
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog, RspamdLog, SpamSuppression
    with get_db_context() as db:
        db.query(PostfixLog).filter(PostfixLog.message.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.message_id.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.query(MessageCorrelation).filter(
            MessageCorrelation.recipient.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.query(MessageCorrelation).filter(
            MessageCorrelation.message_id.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.query(SpamSuppression).filter(SpamSuppression.email.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.commit()


def test_forged_noqueue_bounce_creates_no_suppression(db_env, monkeypatch):
    """The reproduced attack: the line goes through the real ingest and the
    real detection job. Only the genuine bounce may become a suppression."""
    from app import scheduler
    from app.config import settings
    from app.database import get_db_context
    from app.models import SpamSuppression

    victim = f'ceo@{MARKER}'
    genuine = f'gone@{MARKER}'
    queue_id = uuid.uuid4().hex[:10].upper()
    now = int(datetime.utcnow().timestamp())
    logs = [
        {'time': str(now), 'program': 'postfix/smtpd', 'priority': 'info', 'message':
         f'NOQUEUE: reject: RCPT from unknown[192.0.2.10]: 554 5.7.1 <{victim}>: Relay access denied; '
         f'from=<status=bounced.dsn=5.1.1@sender.invalid> to=<{victim}> proto=ESMTP helo=<client.invalid>'},
        {'time': str(now), 'program': 'postfix/smtpd', 'priority': 'info', 'message':
         f'NOQUEUE: reject: RCPT from unknown[192.0.2.11]: 554 5.7.1 <{victim}>: Relay access denied; '
         f'from=<a@sender.invalid> to=<{victim}> proto=ESMTP helo=<status=bounced.dsn=5.1.1>'},
        {'time': str(now), 'program': 'postfix/smtp', 'priority': 'info', 'message':
         f'{queue_id}: to=<{genuine}>, relay=mx.example.net[192.0.2.20]:25, delay=1.4, '
         f'delays=0.1/0/0.6/0.7, dsn=5.1.1, status=bounced (host mx.example.net[192.0.2.20] said: '
         f'550 5.1.1 User unknown (in reply to RCPT TO command))'},
    ]
    monkeypatch.setattr(scheduler, 'seen_postfix', set())
    monkeypatch.setattr(scheduler, 'is_blacklisted', lambda email: False)
    scheduler._store_postfix_page(logs)

    monkeypatch.setattr(type(settings._inner), 'is_feature_enabled', lambda self, name: True)
    monkeypatch.setattr(settings._inner, 'suppression_enabled', True)
    monkeypatch.setattr(settings._inner, 'suppression_auto_detect', True)
    monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', False)
    monkeypatch.setattr(settings._inner, 'suppression_whitelist_domains', '')
    asyncio.run(scheduler.detect_suppressions_job())

    with get_db_context() as db:
        emails = {s.email for s in db.query(SpamSuppression).filter(
            SpamSuppression.email.like(f'%{MARKER}%')).all()}
    assert victim not in emails, 'a forged NOQUEUE line must never suppress its recipient'
    assert genuine in emails, 'a genuine delivery-agent bounce must still be detected'


def test_bounce_scan_skips_rows_without_queue_id_or_delivery_program(db_env, monkeypatch):
    """Rows stored by an older parser with a forged status must not be acted on either."""
    from app import scheduler
    from app.config import settings
    from app.database import get_db_context
    from app.models import PostfixLog, SpamSuppression

    rows = [
        ('postfix/smtpd', None, f'noqueue@{MARKER}'),
        ('postfix/smtpd', 'ABCDEF0001', f'smtpd@{MARKER}'),
        ('postfix/smtp', 'ABCDEF0002', f'smtp@{MARKER}'),
    ]
    with get_db_context() as db:
        for program, queue_id, rcpt in rows:
            db.add(PostfixLog(time=datetime.utcnow(), created_at=datetime.utcnow(), program=program,
                              priority='info', message=f'{rcpt} {MARKER}', queue_id=queue_id,
                              recipient=rcpt, status='bounced', dsn='5.1.1'))
        db.commit()

    monkeypatch.setattr(settings._inner, 'suppression_whitelist_domains', '')
    monkeypatch.setattr(settings._inner, 'queue_cleanup_enabled', True)
    scheduler._detect_suppressions_worker()

    with get_db_context() as db:
        emails = {s.email for s in db.query(SpamSuppression).filter(
            SpamSuppression.email.like(f'%{MARKER}%')).all()}
    assert emails == {f'smtp@{MARKER}'}


# ---- database: a Message-ID equal to a mailbox is not stitched to its deliveries ----

def test_message_id_equal_to_a_mailbox_does_not_hijack_its_deliveries(db_env, monkeypatch):
    from app import scheduler
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog, RspamdLog

    victim = f'alice@{MARKER}'
    monkeypatch.setattr(scheduler, 'seen_postfix', set())
    monkeypatch.setattr(scheduler, 'is_blacklisted', lambda email: False)
    base = int((datetime.utcnow() - timedelta(minutes=10)).timestamp())

    def chain(queue_id, msgid, sender, t):
        return [
            {'time': str(t), 'program': 'postfix/cleanup', 'priority': 'info',
             'message': f'{queue_id}: message-id=<{msgid}>'},
            {'time': str(t + 1), 'program': 'postfix/qmgr', 'priority': 'info',
             'message': f'{queue_id}: from=<{sender}>, size=2048, nrcpt=1 (queue active)'},
            {'time': str(t + 2), 'program': 'postfix/lmtp', 'priority': 'info',
             'message': f'{queue_id}: to=<{victim}>, relay=dovecot[192.0.2.250]:24, delay=0.1, '
                        f'delays=0.05/0/0/0.05, dsn=2.0.0, status=sent '
                        f'(250 2.0.0 <{victim}> S{queue_id} Saved)'},
        ]

    legit_queues = [uuid.uuid4().hex[:10].upper() for _ in range(2)]
    attacker_queue = uuid.uuid4().hex[:10].upper()
    logs = []
    for i, q in enumerate(legit_queues):
        logs += chain(q, f'legit{i}-{q}@{MARKER}', f'friend{i}@{MARKER}', base + i * 60)
    logs += chain(attacker_queue, victim, f'x@{MARKER}', base + 300)
    scheduler._store_postfix_page(logs)

    with get_db_context() as db:
        lmtp_ids = {p.message_id for p in db.query(PostfixLog).filter(
            PostfixLog.queue_id.in_(legit_queues), PostfixLog.program == 'postfix/lmtp').all()}
        assert lmtp_ids == {None}, 'the LMTP reply must not set a Message-ID'

        rspamd = RspamdLog(time=datetime.utcnow(), message_id=victim, sender_smtp='x@sender.invalid',
                           recipients_smtp=[victim], score=0.5, required_score=15.0,
                           action='no action', is_spam=False, direction='inbound', user='unknown')
        db.add(rspamd)
        db.commit()
        scheduler.correlate_single_message(db, rspamd)
        db.commit()

        legs = db.query(MessageCorrelation).filter(MessageCorrelation.message_id == victim).all()
        assert {leg.queue_id for leg in legs} <= {attacker_queue}, \
            'legitimate deliveries must not become legs of the attacker message'
        db.query(MessageCorrelation).filter(MessageCorrelation.message_id == victim).delete(
            synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.id == rspamd.id).delete(synchronize_session=False)
        db.commit()
