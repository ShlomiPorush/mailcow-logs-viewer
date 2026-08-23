"""A mailbox that bursts at the same hour every day (scheduled reports) must
not trigger volume-spike alerts - but the same mailbox bursting at an unusual
hour, or far above its usual batch size, still must."""
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.config import settings

SENDER = 'daily-report@pattern.example'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _seed_burst(db, count, when):
    from app.models import MessageCorrelation
    for i in range(count):
        db.add(MessageCorrelation(
            correlation_key=uuid.uuid4().hex,
            message_id=f"<{uuid.uuid4().hex}@pattern.example>",
            sender=SENDER, direction='outbound',
            first_seen=when + timedelta(seconds=i), last_seen=when,
            created_at=when))


@pytest.fixture()
def anomaly_env(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import MessageCorrelation, MailboxStatistics, SecurityAlert
    init_db()
    monkeypatch.setattr(settings._inner, 'anomaly_check_interval', 15)
    monkeypatch.setattr(settings._inner, 'anomaly_volume_multiplier', 10.0)
    monkeypatch.setattr(settings._inner, 'anomaly_volume_min_messages', 20)
    monkeypatch.setattr(settings._inner, 'anomaly_baseline_days', 7)
    monkeypatch.setattr(settings._inner, 'anomaly_alert_cooldown_hours', 24)

    def cleanup():
        with get_db_context() as db:
            db.query(MessageCorrelation).filter(MessageCorrelation.sender == SENDER).delete(
                synchronize_session=False)
            db.query(SecurityAlert).filter(SecurityAlert.subject == SENDER).delete(
                synchronize_session=False)
            db.query(MailboxStatistics).filter(MailboxStatistics.username == SENDER).delete(
                synchronize_session=False)
            db.commit()

    cleanup()
    with get_db_context() as db:
        db.add(MailboxStatistics(username=SENDER, domain='pattern.example'))
        db.commit()
    yield
    cleanup()


def _run_detector():
    from app.services.anomaly_service import detect_volume_spikes
    from app.database import get_db_context
    pending = []
    with get_db_context() as db:
        alerts = detect_volume_spikes(db, pending)
    return alerts


def test_daily_batch_at_usual_hour_does_not_alert(anomaly_env):
    from app.database import get_db_context
    now = datetime.utcnow()
    with get_db_context() as db:
        _seed_burst(db, 30, now - timedelta(minutes=5))          # current burst
        _seed_burst(db, 28, now - timedelta(days=1, minutes=5))  # same hour yesterday
        _seed_burst(db, 32, now - timedelta(days=2, minutes=5))  # and the day before
        db.commit()
    assert _run_detector() == 0, "recurring same-hour batch must be treated as scheduled"


def test_burst_with_no_history_still_alerts(anomaly_env):
    from app.database import get_db_context
    now = datetime.utcnow()
    with get_db_context() as db:
        _seed_burst(db, 30, now - timedelta(minutes=5))
        db.commit()
    assert _run_detector() == 1


def test_burst_at_unusual_hour_still_alerts(anomaly_env):
    from app.database import get_db_context
    now = datetime.utcnow()
    with get_db_context() as db:
        _seed_burst(db, 30, now - timedelta(minutes=5))
        # history exists, but 12 hours away from the current slot
        _seed_burst(db, 30, now - timedelta(days=1, hours=12))
        _seed_burst(db, 30, now - timedelta(days=2, hours=12))
        db.commit()
    assert _run_detector() == 1, "off-schedule burst must alert even with daily history"


def test_burst_far_above_usual_batch_still_alerts(anomaly_env):
    from app.database import get_db_context
    now = datetime.utcnow()
    with get_db_context() as db:
        _seed_burst(db, 90, now - timedelta(minutes=5))          # 3x the usual batch
        _seed_burst(db, 30, now - timedelta(days=1, minutes=5))
        _seed_burst(db, 30, now - timedelta(days=2, minutes=5))
        db.commit()
    assert _run_detector() == 1, "a burst well above the usual batch must alert"
