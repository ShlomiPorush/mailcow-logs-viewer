"""Mailbox statistics count messages, not delivery legs (issue #36).

Since a correlation describes one delivery leg, a single message can hold
several of them: a Sieve forward, a redirect that was refused, a release from
quarantine. Counting the rows made a mailbox look like it had sent mail it
never wrote, and a refused attempt raised its failure rate even when the same
message was delivered a moment later. Each message now counts once per
mailbox, represented by its most successful leg.
"""
import asyncio
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

MARK = 'legs-stats.invalid'
DOMAIN = MARK
LOCAL_USER = f'user@{DOMAIN}'
OTHER_USER = f'other@{DOMAIN}'
REMOTE = f'ext@remote-{MARK}'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import MailboxStatistics, MessageCorrelation
    from app.routers.mailbox_stats import clear_stats_cache
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(
            MessageCorrelation.correlation_key.like(f'%{MARK}')
        ).delete(synchronize_session=False)
        db.query(MailboxStatistics).filter(
            MailboxStatistics.domain == DOMAIN).delete(synchronize_session=False)
        db.commit()
    clear_stats_cache()


@pytest.fixture()
def env():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import MailboxStatistics
    init_db()
    _cleanup()
    with get_db_context() as db:
        for username in (LOCAL_USER, OTHER_USER):
            db.add(MailboxStatistics(username=username, domain=DOMAIN, active=True))
        db.commit()
    yield
    _cleanup()


# ---------- seeding helpers ----------

def _msgid():
    return f'<{uuid.uuid4().hex}@{MARK}>'


def _leg(sender, recipient, status, message_id, direction='internal', age_minutes=1):
    """One delivery leg of a message, as the correlation jobs would store it."""
    from app.database import get_db_context
    from app.models import MessageCorrelation
    when = datetime.utcnow() - timedelta(minutes=age_minutes)
    with get_db_context() as db:
        db.add(MessageCorrelation(
            correlation_key=f'{uuid.uuid4().hex}-{MARK}',
            message_id=message_id,
            queue_id=uuid.uuid4().hex[:10].upper(),
            sender=sender, recipient=recipient, subject=f'leg {MARK}',
            direction=direction, final_status=status, is_complete=True,
            first_seen=when, last_seen=when, created_at=when))
        db.commit()


def _seed_forward_scenario():
    """One message, three legs, exactly as it happens on a live server.

    An inbound delivery, the Sieve redirect it triggered and that Rspamd
    refused, and the same redirect again after the message was released.
    """
    msgid = _msgid()
    _leg(REMOTE, LOCAL_USER, 'delivered', msgid, direction='inbound', age_minutes=5)
    _leg(LOCAL_USER, OTHER_USER, 'rejected', msgid, age_minutes=4)
    _leg(LOCAL_USER, OTHER_USER, 'delivered', msgid, age_minutes=3)
    return msgid


# ---------- endpoint helpers ----------

def _mailboxes():
    """Call the Mailbox Statistics list the way FastAPI calls it."""
    from app.database import get_db_context
    from app.routers.mailbox_stats import clear_stats_cache, get_all_mailbox_stats
    clear_stats_cache()
    with get_db_context() as db:
        payload = get_all_mailbox_stats(
            domain=DOMAIN, active_only=False, hide_zero=False, search=None,
            date_range='7days', start_date=None, end_date=None,
            sort_by='sent_total', sort_order='desc', page=1, page_size=100, db=db)
    assert 'error' not in payload, payload.get('error')
    return {mb['username']: mb for mb in payload['mailboxes']}


def _summary():
    from app.database import get_db_context
    from app.routers.mailbox_stats import get_mailbox_stats_summary
    with get_db_context() as db:
        payload = get_mailbox_stats_summary(
            date_range='7days', start_date=None, end_date=None, db=db)
    assert 'error' not in payload, payload.get('error')
    return payload


# ---------- the regression ----------

def test_a_forwarded_message_counts_once_and_is_not_a_failure(env):
    """THE issue: the forward legs were counted as mail of their own, and the
    refused attempt raised the failure rate of a message that was delivered."""
    _seed_forward_scenario()

    rows = _mailboxes()
    user = rows[LOCAL_USER]['mailbox_counts']
    other = rows[OTHER_USER]['mailbox_counts']

    assert user['sent_total'] == 1, 'the two forward legs are one message'
    assert user['sent_delivered'] == 1, 'the delivered leg represents the message'
    assert user['sent_failed'] == 0, 'a later delivery clears the refused attempt'
    assert user['sent_rejected'] == 0
    assert user['failure_rate'] == 0.0
    assert user['received_total'] == 1

    assert other['received_total'] == 1, 'two legs delivered one message here'
    assert other['sent_total'] == 0


def test_correlations_without_a_message_id_are_never_merged(env):
    """Nothing says two messages without a Message-ID are the same message."""
    _leg(LOCAL_USER, REMOTE, 'delivered', None, direction='outbound')
    _leg(LOCAL_USER, REMOTE, 'delivered', None, direction='outbound', age_minutes=2)

    assert _mailboxes()[LOCAL_USER]['mailbox_counts']['sent_total'] == 2


def test_two_messages_from_one_mailbox_count_twice(env):
    _leg(LOCAL_USER, REMOTE, 'delivered', _msgid(), direction='outbound')
    _leg(LOCAL_USER, REMOTE, 'bounced', _msgid(), direction='outbound', age_minutes=2)

    counts = _mailboxes()[LOCAL_USER]['mailbox_counts']
    assert counts['sent_total'] == 2
    assert counts['sent_delivered'] == 1
    assert counts['sent_bounced'] == 1
    assert counts['sent_failed'] == 1


def test_the_best_of_two_unsuccessful_legs_represents_the_message(env):
    """Nothing was delivered here, so the least bad outcome is the one shown."""
    msgid = _msgid()
    _leg(LOCAL_USER, REMOTE, 'deferred', msgid, direction='outbound', age_minutes=4)
    _leg(LOCAL_USER, REMOTE, 'bounced', msgid, direction='outbound', age_minutes=3)

    counts = _mailboxes()[LOCAL_USER]['mailbox_counts']
    assert counts['sent_total'] == 1
    assert counts['sent_deferred'] == 1, 'deferred outranks bounced'
    assert counts['sent_delivered'] == 0


def test_summary_totals_count_the_message_once(env):
    """The summary cards and the mailbox rows must tell the same story."""
    before = _summary()
    _seed_forward_scenario()
    after = _summary()

    assert after['total_sent'] - before['total_sent'] == 1
    assert after['total_received'] - before['total_received'] == 2
    assert after['sent_failed'] - before['sent_failed'] == 0

    rows = _mailboxes()
    assert after['total_sent'] - before['total_sent'] == \
        rows[LOCAL_USER]['combined_sent'] + rows[OTHER_USER]['combined_sent']
