"""A volume-spike or failed-sign-in alert email shows the counts per hour
over the last 24 hours up to the alert, so the reader sees a burst against
an ordinary day. The chart counts what the detector counted."""
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.config import settings

SENDER = f'chart-{uuid.uuid4().hex[:6]}@chart.example'
OTHER = f'other-{uuid.uuid4().hex[:6]}@chart.example'
USER = f'signin-{uuid.uuid4().hex[:6]}@chart.example'
MARKER = f'chart-{uuid.uuid4().hex[:8]}'
END = datetime(2026, 10, 26, 12, 0)


def test_hourly_counts_puts_each_time_in_its_hour():
    from app.services.anomaly_service import hourly_counts
    times = [
        END - timedelta(hours=24),                # the first moment counts, in the first hour
        END - timedelta(hours=23, seconds=1),     # still the first hour
        END - timedelta(hours=23),                # the second hour starts here
        END - timedelta(hours=5, minutes=10),     # 18h50m after the start
        END - timedelta(minutes=59),
        END,                                      # now itself: the last hour, as the detectors count it
        END - timedelta(hours=24, seconds=1),     # before the 24 hours
        END + timedelta(seconds=1),               # after now: a log clock ahead, in the last hour
        None,
    ]
    counts = hourly_counts(times, END)
    assert len(counts) == 24
    assert counts[0] == 2 and counts[1] == 1 and counts[18] == 1 and counts[23] == 3
    assert sum(counts) == 7
    assert hourly_counts([], END) == [0] * 24


def test_the_alert_window_is_the_last_hour_or_more():
    from app.services.anomaly_service import window_hours
    assert window_hours(15) == [23]
    assert window_hours(60) == [23]
    assert window_hours(61) == [22, 23]
    assert window_hours(120) == [22, 23]
    assert window_hours(121) == [21, 22, 23]
    assert window_hours(0) == [23]
    assert window_hours(3000) == list(range(24))


def test_the_detection_run_sends_the_chart_with_the_email(monkeypatch):
    """The counts are read in the detector's session and travel to the email,
    which is built after the session is closed."""
    from app.services import anomaly_service, notification_service
    chart = anomaly_service.AlertChart([0] * 23 + [39], [23], END, usual_rate=0.6)

    def detector(db, pending):
        pending.append(('Outbound volume spike: a@example.com', 'Mailbox a@example.com sent 39 messages.\n\nReview it.',
                        'critical', 'volume_spike', 'a@example.com', chart))
        return 1

    @contextmanager
    def no_db():
        yield None

    sent = []
    monkeypatch.setattr(settings._inner, 'anomaly_detection_enabled', True)
    monkeypatch.setattr(anomaly_service, 'get_db_context', no_db)
    monkeypatch.setattr(anomaly_service, 'detect_volume_spikes', detector)
    monkeypatch.setattr(anomaly_service, 'detect_auth_failure_bursts', lambda db, pending: 0)
    monkeypatch.setattr(notification_service, 'notify', lambda **kw: sent.append(kw))
    assert anomaly_service.run_anomaly_detection()['volume_spikes'] == 1
    assert len(sent) == 1
    assert 'Messages sent per hour. 39 in the last hour, usually 0.6 an hour.' in sent[0]['html_content']
    # The plain text, which the webhooks get, stays the detail
    assert sent[0]['text_content'] == 'Mailbox a@example.com sent 39 messages.\n\nReview it.'


def test_an_alert_whose_hours_cannot_be_read_goes_out_without_its_chart():
    from app.services.anomaly_service import _alert_chart

    class BrokenSession:
        rolled_back = False

        def query(self, *args):
            raise RuntimeError('connection lost')

        def rollback(self):
            self.rolled_back = True

    db = BrokenSession()
    assert _alert_chart(db, 'auth_failure_burst', 'a@example.com', END, 15) is None
    # The session is usable again for recording the alert
    assert db.rolled_back


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def env(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import MailboxStatistics, MessageCorrelation, NetfilterLog, RspamdLog, SecurityAlert
    from app.services import anomaly_service
    init_db()
    monkeypatch.setattr(settings._inner, 'anomaly_check_interval', 15)
    monkeypatch.setattr(settings._inner, 'anomaly_volume_multiplier', 10.0)
    monkeypatch.setattr(settings._inner, 'anomaly_volume_min_messages', 20)
    monkeypatch.setattr(settings._inner, 'anomaly_baseline_days', 7)
    monkeypatch.setattr(settings._inner, 'anomaly_auth_failure_threshold', 10)
    monkeypatch.setattr(settings._inner, 'anomaly_alert_cooldown_hours', 24)
    monkeypatch.setattr(anomaly_service, '_is_recurring_daily_pattern', lambda *a, **k: False)

    def cleanup():
        with get_db_context() as db:
            db.query(MessageCorrelation).filter(MessageCorrelation.sender.in_([SENDER, OTHER])).delete(
                synchronize_session=False)
            db.query(RspamdLog).filter(RspamdLog.sender_smtp.in_([SENDER, OTHER])).delete(synchronize_session=False)
            db.query(NetfilterLog).filter(NetfilterLog.priority == MARKER).delete(synchronize_session=False)
            db.query(SecurityAlert).filter(SecurityAlert.subject.in_([SENDER, OTHER, USER])).delete(
                synchronize_session=False)
            db.query(MailboxStatistics).filter(MailboxStatistics.username.in_([SENDER, OTHER])).delete(
                synchronize_session=False)
            db.commit()

    cleanup()
    with get_db_context() as db:
        db.add(MailboxStatistics(username=SENDER, domain='chart.example'))
        db.commit()
    yield get_db_context
    cleanup()


def _messages(db, sender, count, when, authenticated=True):
    from app.models import MessageCorrelation, RspamdLog
    scan = RspamdLog(time=when, sender_smtp=sender, has_auth=authenticated, user=sender if authenticated else 'unknown',
                     ip=None if authenticated else '203.0.113.9', direction='outbound')
    db.add(scan)
    db.flush()
    for i in range(count):
        at = when + timedelta(seconds=i)
        db.add(MessageCorrelation(correlation_key=uuid.uuid4().hex, message_id=f'<{uuid.uuid4().hex}@chart.example>',
                                  sender=sender, direction='outbound', rspamd_log_id=scan.id,
                                  first_seen=at, last_seen=at, created_at=at))


def test_a_spike_alert_carries_the_mailboxs_sent_mail_per_hour(env):
    from app.services.anomaly_service import detect_volume_spikes
    now = datetime.utcnow()
    with env() as db:
        _messages(db, SENDER, 30, now - timedelta(minutes=5))           # the burst
        _messages(db, SENDER, 3, now - timedelta(hours=5, minutes=10))  # earlier today
        _messages(db, SENDER, 4, now - timedelta(hours=3, minutes=10), authenticated=False)  # not sent by it
        _messages(db, OTHER, 6, now - timedelta(hours=2, minutes=10))   # another mailbox
        _messages(db, SENDER, 5, now - timedelta(days=2))               # before the 24 hours
        db.commit()
    pending = []
    with env() as db:
        assert detect_volume_spikes(db, pending) == 1
    chart = pending[0][5]
    assert chart.counts[23] == 30 and chart.counts[18] == 3
    assert sum(chart.counts) == 33
    assert chart.highlight == [23]
    # The baseline the detector measured: 8 messages over 7 days before the window
    assert chart.usual_rate == pytest.approx(8 / (7 * 24 - 0.25))


def test_a_sign_in_burst_alert_carries_the_usernames_failures_per_hour(env):
    from app.models import NetfilterLog
    from app.services.anomaly_service import detect_auth_failure_bursts
    now = datetime.utcnow()
    with env() as db:
        for i in range(12):
            db.add(NetfilterLog(time=now - timedelta(minutes=5, seconds=i), priority=MARKER, ip='192.0.2.1',
                                username=USER, message='failed'))
        for i in range(4):
            db.add(NetfilterLog(time=now - timedelta(hours=3, minutes=10, seconds=i), priority=MARKER, ip='192.0.2.2',
                                username=USER, message='failed'))
        for i in range(3):
            db.add(NetfilterLog(time=now - timedelta(hours=1, minutes=30), priority=MARKER, ip='192.0.2.3',
                                username=f'x{USER}', message='failed'))
        # A log clock ahead of ours: the alert counts it, so the chart does too
        db.add(NetfilterLog(time=now + timedelta(minutes=10), priority=MARKER, ip='192.0.2.1',
                            username=USER, message='failed'))
        db.commit()
    pending = []
    with env() as db:
        detect_auth_failure_bursts(db, pending)
    chart = next(item[5] for item in pending if item[4] == USER)
    assert chart.counts[23] == 13 and chart.counts[20] == 4
    assert sum(chart.counts) == 17
    assert chart.highlight == [23]
    assert chart.usual_rate is None


def test_an_alert_is_recorded_and_sent_when_its_chart_fails_in_the_database(env, monkeypatch):
    from sqlalchemy import text
    from app.models import NetfilterLog, SecurityAlert
    from app.services import anomaly_service
    real_chart = anomaly_service._alert_chart

    class FailingQuery:
        """The session, but the chart's query breaks the transaction as a real database error does."""
        def __init__(self, db):
            self._db = db

        def __getattr__(self, name):
            return getattr(self._db, name)

        def query(self, *args):
            self._db.execute(text('SELECT 1 / 0'))

    monkeypatch.setattr(anomaly_service, '_alert_chart',
                        lambda db, *args, **kwargs: real_chart(FailingQuery(db), *args, **kwargs))
    now = datetime.utcnow()
    with env() as db:
        for i in range(12):
            db.add(NetfilterLog(time=now - timedelta(minutes=5, seconds=i), priority=MARKER, ip='192.0.2.1',
                                username=USER, message='failed'))
        db.commit()
    pending = []
    with env() as db:
        assert anomaly_service.detect_auth_failure_bursts(db, pending) >= 1
    assert next(item for item in pending if item[4] == USER)[5] is None
    with env() as db:
        assert db.query(SecurityAlert).filter(SecurityAlert.subject == USER).count() == 1
