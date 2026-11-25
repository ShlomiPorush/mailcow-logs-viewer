import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

import app.models
from app.config import settings

MARKER = 'final-status-rule.invalid'
RCPT = f'rcpt@{MARKER}'
SENDER = f'sender@{MARKER}'


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
        db.query(MessageCorrelation).filter(
            MessageCorrelation.message_id.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.message_id.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def env(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db
    init_db()
    monkeypatch.setattr(settings._inner, 'max_correlation_age_minutes', 10)
    _cleanup()
    yield
    _cleanup()


LINES = {
    'queued': ('postfix/cleanup', 'message-id=<{mid}>'),
    'deferred': ('postfix/smtp', f'to=<{RCPT}>, relay=mx.example.com[192.0.2.1]:25, delay=1, dsn=4.7.1, '
                                 'status=deferred (450 4.7.1 Greylisted)'),
    'sent': ('postfix/smtp', f'to=<other@{MARKER}>, relay=mx.example.com[192.0.2.1]:25, delay=2, dsn=2.0.0, '
                             'status=sent (250 2.0.0 OK)'),
    'spam': ('postfix/pipe', f'to=<{RCPT}>, relay=rspamd-pipe-spam, delay=1, dsn=2.0.0, '
                             'status=sent (delivered via rspamd-pipe-spam service)'),
    'expired': ('postfix/qmgr', f'from=<{SENDER}>, status=expired, returned to sender'),
}


class Message:
    def __init__(self, *kinds, final_status=None, complete=True, dovecot=None, action=None, is_spam=False):
        from app.correlation import parse_postfix_message
        from app.database import get_db_context
        from app.models import MessageCorrelation, PostfixLog, RspamdLog
        self.mid = f'{uuid.uuid4().hex}@{MARKER}'
        self.queue = uuid.uuid4().hex[:10].upper()
        self.when = datetime.utcnow() - timedelta(minutes=5)
        self._parse, self._db, self._line = parse_postfix_message, get_db_context, PostfixLog
        self._second = 0
        with self._db() as db:
            rspamd_id = None
            if action:
                scan = RspamdLog(time=self.when, message_id=self.mid, action=action, is_spam=is_spam,
                                 sender_smtp=SENDER, recipients_smtp=[RCPT], raw_data={})
                db.add(scan)
                db.flush()
                rspamd_id = scan.id
            for kind in ('queued',) + kinds:
                self._add(db, kind)
            correlation = MessageCorrelation(
                correlation_key=uuid.uuid4().hex, message_id=self.mid, queue_id=self.queue, sender=SENDER,
                recipient=RCPT, direction='outbound', final_status=final_status, is_complete=complete,
                dovecot_status=dovecot, rspamd_log_id=rspamd_id, postfix_log_ids=[],
                first_seen=self.when, last_seen=self.when, created_at=datetime.utcnow())
            db.add(correlation)
            db.commit()

    def _add(self, db, kind):
        program, text = LINES[kind]
        message = f'{self.queue}: ' + text.replace('{mid}', self.mid)
        parsed = self._parse(message)
        self._second += 1
        db.add(self._line(
            time=self.when + timedelta(seconds=self._second), program=program, priority='info', message=message,
            queue_id=self.queue, message_id=parsed.get('message_id'), sender=parsed.get('sender'),
            recipient=parsed.get('recipient'), status=parsed.get('status'), relay=parsed.get('relay'),
            raw_data={}))
        db.flush()

    def later(self, kind):
        with self._db() as db:
            self._add(db, kind)
            db.commit()

    def status(self):
        from app.models import MessageCorrelation
        with self._db() as db:
            return db.query(MessageCorrelation.final_status).filter(
                MessageCorrelation.message_id == self.mid).scalar()

    def scan_is_spam(self):
        from app.models import RspamdLog
        with self._db() as db:
            return db.query(RspamdLog.is_spam).filter(RspamdLog.message_id == self.mid).scalar()


def _timer():
    from app.services import correlation_jobs
    correlation_jobs.update_final_status_for_correlations()


def _arrived(message):
    from app.database import get_db_context
    from app.services import correlation_jobs
    with get_db_context() as db:
        correlation_jobs.refresh_correlations_for_queue_ids(db, [message.queue])
        db.commit()


def _relink(message, with_scan=False):
    from app.correlation import ensure_leg, own_occurrence
    from app.database import get_db_context
    from app.models import RspamdLog
    with get_db_context() as db:
        lines = own_occurrence(db, message.queue, message.mid).lines
        scan = db.query(RspamdLog).filter(RspamdLog.message_id == message.mid).first() if with_scan else None
        ensure_leg(db, message.mid, message.queue, lines, rspamd_log=scan)
        db.commit()


def test_the_timer_keeps_spam_when_another_recipient_got_the_message(env):
    message = Message('spam', 'sent', final_status='spam')
    _timer()
    assert message.status() == 'spam'


def test_a_message_that_expired_in_the_queue_is_expired(env):
    message = Message('deferred', 'expired', final_status='deferred')
    _timer()
    assert message.status() == 'expired'


def test_an_expired_line_that_arrives_later_counts(env):
    message = Message('deferred', final_status='deferred')
    message.later('expired')
    _arrived(message)
    assert message.status() == 'expired'


def test_linking_a_message_again_keeps_what_dovecot_discarded(env):
    message = Message('sent', final_status='discarded', dovecot='discarded')
    _relink(message)
    assert message.status() == 'discarded'


@pytest.mark.parametrize('kinds', [('sent', 'deferred'), ('deferred', 'sent')])
def test_completing_a_message_does_not_put_deferred_over_a_delivery(env, kinds):
    from app.services import correlation_jobs
    message = Message(*kinds, complete=False)
    correlation_jobs.complete_incomplete_correlations()
    assert message.status() == 'delivered'


def test_a_message_the_scan_called_spam_is_delivered_when_its_delivery_comes_later(env):
    from app.services import correlation_jobs
    message = Message('sent', final_status='spam', action='add header', is_spam=True, complete=False)
    correlation_jobs.complete_incomplete_correlations()
    assert message.status() == 'delivered'
    assert message.scan_is_spam() is True


def test_the_timer_and_a_late_line_also_put_the_delivery_over_the_scan(env):
    for settle in (lambda message: _timer(), _arrived):
        message = Message('sent', final_status='spam', action='add header', is_spam=True)
        settle(message)
        assert message.status() == 'delivered'


def test_a_spam_line_stays_spam_whatever_arrives_later(env):
    message = Message('spam', final_status='spam')
    message.later('sent')
    _arrived(message)
    assert message.status() == 'spam'


def test_a_discard_stays_when_another_recipient_is_deferred(env):
    from app.services import correlation_jobs
    message = Message('deferred', final_status='discarded', dovecot='discarded', complete=False)
    correlation_jobs.complete_incomplete_correlations()
    assert message.status() == 'discarded'


def test_a_spam_line_that_arrives_later_counts_and_leaves_the_scan_alone(env):
    message = Message(final_status=None, action='no action')
    message.later('spam')
    _arrived(message)
    assert message.status() == 'spam'
    assert message.scan_is_spam() is False


@pytest.mark.parametrize('action,is_spam,expected', [('reject', True, 'rejected'), ('add header', True, 'spam')])
def test_without_a_delivery_line_the_scan_decides(env, action, is_spam, expected):
    message = Message(final_status=None, action=action, is_spam=is_spam)
    _relink(message, with_scan=True)
    assert message.status() == expected


def test_the_delivery_decides_over_the_scan(env):
    message = Message('sent', final_status='spam', action='add header', is_spam=True)
    _relink(message, with_scan=True)
    assert message.status() == 'delivered'


def test_an_older_spam_scan_does_not_replace_a_rejection(env):
    message = Message(final_status='rejected', action='add header', is_spam=True)
    _relink(message, with_scan=True)
    assert message.status() == 'rejected'


def test_a_status_stays_when_no_line_says_otherwise(env):
    message = Message(final_status='deferred')
    _relink(message)
    _timer()
    assert message.status() == 'deferred'


def test_a_spam_line_marks_the_scan_when_the_message_is_linked(env):
    message = Message('spam', final_status=None, action='no action')
    _relink(message)
    assert message.status() == 'spam'
    assert message.scan_is_spam() is True
