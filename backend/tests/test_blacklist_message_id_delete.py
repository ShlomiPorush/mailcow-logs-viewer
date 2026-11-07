"""BLACKLIST_EMAILS only removes records that involve a listed address.

The Rspamd ingest used the Message-ID of any entry with a blacklisted sender
or recipient as a deletion key and removed every correlation with that
Message-ID, plus all Postfix logs of their queues. Message-IDs are chosen by
the sender, so one message reusing the Message-ID of an earlier message (and
naming one listed address) erased that earlier message from the viewer.
"""
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

MARK = uuid.uuid4().hex[:8]
DOMAIN = f'bl-{MARK}.invalid'
LISTED = f'noise@{DOMAIN}'


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
        db.query(PostfixLog).filter(PostfixLog.message.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.message_id.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.query(MessageCorrelation).filter(
            MessageCorrelation.message_id.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def env(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app import scheduler
    from app.config import settings
    from app.database import init_db
    init_db()
    _cleanup()
    monkeypatch.setattr(settings._inner, 'blacklist_emails', LISTED)
    monkeypatch.setattr(scheduler, 'seen_rspamd', set())
    yield
    _cleanup()


def _seed(msgid, sender, recipient):
    """A correlated message: its correlation plus two Postfix lines of its queue."""
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog
    queue = uuid.uuid4().hex[:10].upper()
    now = datetime.utcnow() - timedelta(minutes=5)
    with get_db_context() as db:
        for i in range(2):
            db.add(PostfixLog(time=now + timedelta(seconds=i), program='postfix/smtp', priority='info',
                              message=f'{queue}: {MARK} line {i}', queue_id=queue, message_id=msgid,
                              sender=sender, recipient=recipient))
        db.add(MessageCorrelation(correlation_key=uuid.uuid4().hex + uuid.uuid4().hex, message_id=msgid,
                                  queue_id=queue, sender=sender, recipient=recipient,
                                  first_seen=now, last_seen=now))
        db.commit()
    return queue


def _state(queue):
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog
    with get_db_context() as db:
        return (db.query(MessageCorrelation).filter(MessageCorrelation.queue_id == queue).count(),
                db.query(PostfixLog).filter(PostfixLog.queue_id == queue).count())


def _entry(msgid, sender, rcpts):
    return {'unix_time': int(datetime.utcnow().timestamp()), 'message-id': msgid,
            'sender_smtp': sender, 'rcpt_smtp': rcpts, 'action': 'no action', 'score': 0.0,
            'required_score': 15.0, 'symbols': {}}


@pytest.mark.parametrize('sender, rcpts', [
    (LISTED, [f'user@{DOMAIN}']),           # forged listed envelope sender
    (f'x@attacker-{DOMAIN}', [LISTED]),     # listed address used as a recipient
])
def test_reused_message_id_does_not_erase_an_unrelated_message(env, sender, rcpts):
    from app import scheduler
    target = f'keep-{MARK}@partner.test'
    queue = _seed(target, f'friend@partner-{DOMAIN}', f'user@{DOMAIN}')
    assert _state(queue) == (1, 2)

    scheduler._store_rspamd_page([_entry(target, sender, rcpts)])

    assert _state(queue) == (1, 2), 'a message without any listed address must be kept'


def test_records_of_a_message_with_a_listed_address_are_still_removed(env):
    from app import scheduler
    msgid = f'drop-{MARK}@partner.test'
    queue = _seed(msgid, LISTED, f'user@{DOMAIN}')

    scheduler._store_rspamd_page([_entry(msgid, LISTED, [f'user@{DOMAIN}'])])

    assert _state(queue) == (0, 0)
