"""Each mailbox on the Mailbox Stats page carries its activity over the range.

The small chart beside a mailbox and the window it opens draw the messages it
sent and received per day (per hour for Today), its aliases included, and
must add up to the totals shown beside them.
"""
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

MARK = 'activity-stats.invalid'
DOMAIN = MARK
USER = f'user@{DOMAIN}'
ALIAS = f'sales@{DOMAIN}'
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
    from app.models import AliasStatistics, MailboxStatistics, MessageCorrelation
    from app.routers.mailbox_stats import clear_stats_cache
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(
            MessageCorrelation.correlation_key.like(f'%{MARK}')
        ).delete(synchronize_session=False)
        db.query(AliasStatistics).filter(
            AliasStatistics.primary_mailbox == USER).delete(synchronize_session=False)
        db.query(MailboxStatistics).filter(
            MailboxStatistics.domain == DOMAIN).delete(synchronize_session=False)
        db.commit()
    clear_stats_cache()


@pytest.fixture()
def env():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import AliasStatistics, MailboxStatistics
    init_db()
    _cleanup()
    with get_db_context() as db:
        db.add(MailboxStatistics(username=USER, domain=DOMAIN, active=True))
        db.add(AliasStatistics(alias_address=ALIAS, goto=USER, domain=DOMAIN, primary_mailbox=USER, active=True))
        db.commit()
    yield
    _cleanup()


def _leg(sender, recipient, when, direction):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    with get_db_context() as db:
        db.add(MessageCorrelation(
            correlation_key=f'{uuid.uuid4().hex}-{MARK}',
            message_id=f'<{uuid.uuid4().hex}@{MARK}>',
            queue_id=uuid.uuid4().hex[:10].upper(),
            sender=sender, recipient=recipient, subject=f'activity {MARK}',
            direction=direction, final_status='delivered', is_complete=True,
            first_seen=when, last_seen=when, created_at=when))
        db.commit()


def _page(date_range):
    from app.database import get_db_context
    from app.routers.mailbox_stats import clear_stats_cache, get_all_mailbox_stats
    clear_stats_cache()
    with get_db_context() as db:
        payload = get_all_mailbox_stats(
            domain=DOMAIN, active_only=False, hide_zero=False, search=None,
            date_range=date_range, start_date=None, end_date=None,
            sort_by='sent_total', sort_order='desc', page=1, page_size=100, db=db)
    assert 'error' not in payload, payload.get('error')
    return payload


def _local_day(utc_naive):
    from app.config import settings
    return utc_naive.replace(tzinfo=timezone.utc).astimezone(ZoneInfo(settings.tz or 'UTC')).date().isoformat()


def test_the_activity_adds_up_to_the_totals_and_lands_on_its_day(env):
    now = datetime.utcnow()
    two_days_ago = now - timedelta(days=2)
    _leg(REMOTE, USER, two_days_ago, 'inbound')
    _leg(REMOTE, ALIAS, two_days_ago, 'inbound')
    just_now = now - timedelta(seconds=5)
    _leg(USER, REMOTE, just_now, 'outbound')

    payload = _page('7days')
    mb = payload['mailboxes'][0]
    assert payload['activity_unit'] == 'day'
    assert len(payload['activity_buckets']) in (7, 8)
    assert sum(mb['activity']['sent']) == mb['combined_sent'] == 1
    assert sum(mb['activity']['received']) == mb['combined_received'] == 2

    days = [b[:10] for b in payload['activity_buckets']]
    assert mb['activity']['received'][days.index(_local_day(two_days_ago))] == 2
    assert mb['activity']['sent'][days.index(_local_day(just_now))] == 1


def test_today_is_drawn_by_the_hour(env):
    _leg(USER, REMOTE, datetime.utcnow() - timedelta(seconds=5), 'outbound')
    payload = _page('today')
    assert payload['activity_unit'] == 'hour'
    assert payload['activity_buckets'][-1][14:] == '00:00'
    mb = payload['mailboxes'][0]
    assert len(mb['activity']['sent']) == len(payload['activity_buckets'])
    assert sum(mb['activity']['sent']) == mb['combined_sent'] == 1
