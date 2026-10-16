"""Bounce detection counts every bounce once, and Count then suppress waits for
the Suppression Soft Bounce Threshold.

Detection runs every 5 minutes over the logs imported in the last 10, so each
log line is in two runs in a row."""
import asyncio
from datetime import datetime, timedelta

import pytest


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture
def env(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import PostfixLog, SpamSuppression
    from app.config import settings
    import app.scheduler as sch

    init_db()
    monkeypatch.setattr(type(settings._inner), 'is_feature_enabled', lambda self, name: True)
    for key, value in {
        'suppression_enabled': True, 'suppression_auto_detect': True, 'suppression_rspamd_sync': False,
        'suppression_whitelist_domains': '', 'suppression_hard_bounce_action': 'suppress',
        'suppression_soft_bounce_action': 'count', 'suppression_soft_bounce_threshold': 3,
        'suppression_base_expiry_days': 7, 'suppression_max_expiry_days': 90,
        # Soft bounces are read from the logs only while Queue Cleanup is off
        'queue_cleanup_enabled': False,
    }.items():
        monkeypatch.setattr(settings._inner, key, value)
    monkeypatch.setattr(sch.mailcow_api, 'headers_rw', None)   # no queue calls
    if hasattr(sch, '_counted_bounce_log_ids'):
        monkeypatch.setattr(sch, '_counted_bounce_log_ids', {})

    emails = []

    def wipe():
        with get_db_context() as db:
            for email in emails:
                db.query(SpamSuppression).filter(SpamSuppression.email == email).delete()
                db.query(PostfixLog).filter(PostfixLog.recipient == email).delete()
            db.commit()

    class Env:
        def bounce(self, email, dsn, n):
            emails.append(email)
            with get_db_context() as db:
                now = datetime.utcnow()
                db.add(PostfixLog(time=now, created_at=now, program='postfix/smtp', priority='info',
                                  message=f'bounce {n}', queue_id=f'Q{n}COUNT', recipient=email,
                                  status='bounced' if dsn.startswith('5.') else 'deferred', dsn=dsn))
                db.commit()

        def age_logs(self, email):
            # Time passes: these lines leave the 10-minute detection window
            with get_db_context() as db:
                db.query(PostfixLog).filter(PostfixLog.recipient == email).update(
                    {PostfixLog.created_at: datetime.utcnow() - timedelta(minutes=30)})
                db.commit()

        def detect(self):
            asyncio.run(sch.detect_suppressions_job())

        def row(self, email):
            with get_db_context() as db:
                s = db.query(SpamSuppression).filter(SpamSuppression.email == email).one()
                db.expunge(s)
                return s

    wipe()
    yield Env()
    wipe()


def test_hard_bounce_seen_by_two_runs_counts_once(env):
    email = 'hard-once@example.com'
    env.bounce(email, '5.1.1', 1)
    env.detect()
    env.detect()   # 5 minutes later the same line is still inside the window
    row = env.row(email)
    assert row.bounce_count == 1 and row.hard_bounce_count == 1
    assert row.expires_at < datetime.utcnow() + timedelta(days=8)


def test_soft_bounce_seen_by_two_runs_counts_once(env):
    email = 'soft-once@example.com'
    env.bounce(email, '4.4.1', 1)
    env.detect()
    env.detect()
    row = env.row(email)
    assert row.soft_bounce_count == 1
    assert row.active is False


def test_count_then_suppress_waits_for_the_threshold(env):
    email = 'soft-threshold@example.com'
    for n in (1, 2):
        env.bounce(email, '4.4.1', n)
        env.detect()
        env.age_logs(email)
        row = env.row(email)
        assert row.soft_bounce_count == n
        assert row.active is False, f"suppressed after {n} soft bounce(s), threshold is 3"
    env.bounce(email, '4.4.1', 3)
    env.detect()
    row = env.row(email)
    assert row.soft_bounce_count == 3 and row.active is True


def test_threshold_of_one_suppresses_at_once(env, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings._inner, 'suppression_soft_bounce_threshold', 1)
    email = 'soft-one@example.com'
    env.bounce(email, '4.4.1', 1)
    env.detect()
    assert env.row(email).active is True
