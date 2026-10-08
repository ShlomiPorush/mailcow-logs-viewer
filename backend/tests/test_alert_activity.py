"""An alert opens on its history: the mailbox's sent mail per 15 minutes
around a volume spike (or the username's failed logins around a burst), and
what happened around it."""
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.config import settings

SENDER = f'spike-{uuid.uuid4().hex[:6]}@activity.example'
USER = f'burst-{uuid.uuid4().hex[:6]}@activity.example'
MARKER = f'activity-{uuid.uuid4().hex[:8]}'


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
    from app.models import MessageCorrelation, NetfilterLog, RspamdLog, SecurityAlert
    init_db()
    monkeypatch.setattr(settings._inner, 'anomaly_check_interval', 15)
    monkeypatch.setattr(settings._inner, 'anomaly_baseline_days', 7)
    now = datetime.utcnow().replace(second=0, microsecond=0)

    def cleanup():
        with get_db_context() as db:
            db.query(MessageCorrelation).filter(MessageCorrelation.sender == SENDER).delete(synchronize_session=False)
            db.query(RspamdLog).filter(RspamdLog.sender_smtp == SENDER).delete(synchronize_session=False)
            db.query(NetfilterLog).filter(NetfilterLog.priority == MARKER).delete(synchronize_session=False)
            db.query(SecurityAlert).filter(SecurityAlert.subject.in_([SENDER, USER])).delete(synchronize_session=False)
            db.commit()
    cleanup()
    with get_db_context() as db:
        # Sent after logging in (counted), and mail from outside that only
        # claims the mailbox as its sender (not counted, as in the alert)
        own = RspamdLog(time=now, sender_smtp=SENDER, has_auth=True, user=SENDER, direction='outbound')
        forged = RspamdLog(time=now, sender_smtp=SENDER, has_auth=False, user='unknown', ip='203.0.113.9',
                           direction='outbound')
        db.add_all([own, forged])
        db.flush()
        # Two messages three days before, then 30 in the alert's 15 minutes to two domains
        for i in range(2):
            when = now - timedelta(days=3, minutes=i)
            db.add(MessageCorrelation(correlation_key=uuid.uuid4().hex, sender=SENDER, recipient='friend@known.example', direction='outbound',
                                      subject='Hello', final_status='delivered', first_seen=when, last_seen=when, created_at=when,
                                      rspamd_log_id=own.id))
        for i in range(30):
            when = now - timedelta(minutes=10, seconds=i)
            db.add(MessageCorrelation(correlation_key=uuid.uuid4().hex, sender=SENDER, recipient=f'x{i}@{"a.example" if i < 20 else "b.example"}',
                                      direction='outbound', subject='Win a prize', final_status='bounced' if i % 3 == 0 else 'delivered',
                                      first_seen=when, last_seen=when, created_at=when, rspamd_log_id=own.id))
        for i in range(5):
            when = now - timedelta(minutes=8, seconds=i)
            db.add(MessageCorrelation(correlation_key=uuid.uuid4().hex, sender=SENDER, recipient='dest@forged.invalid',
                                      direction='outbound', subject='Forged', final_status='delivered',
                                      first_seen=when, last_seen=when, created_at=when, rspamd_log_id=forged.id))
        for i in range(12):
            db.add(NetfilterLog(time=now - timedelta(minutes=5, seconds=i), priority=MARKER, ip=f'192.0.2.{i % 3 + 1}', username=USER,
                                rule_id=3, country_name='Testland', asn_org='Test Net', message='failed'))
        spike = SecurityAlert(alert_type='volume_spike', severity='critical', subject=SENDER, title='spike', metric_value=30, baseline_value=0.01, created_at=now)
        burst = SecurityAlert(alert_type='auth_failure_burst', severity='warning', subject=USER, title='burst', metric_value=12, baseline_value=10, created_at=now)
        db.add_all([spike, burst])
        db.commit()
        ids = (spike.id, burst.id)
    yield ids
    cleanup()


def _client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


def test_a_spike_opens_on_the_mailboxs_sent_mail(env):
    data = _client().get(f'/api/security-alerts/{env[0]}/activity').json()
    assert data['bucket_minutes'] == 15 and data['baseline_days'] == 7
    counts = [b['count'] for b in data['buckets']]
    assert sum(counts) == 32
    # Seven days before, two hours after, in quarters of an hour
    assert 7 * 24 * 4 <= len(counts) <= 7 * 24 * 4 + 2 * 4 + 4
    around = data['around']
    assert around['total'] == 30
    assert around['recipient_domains'][0] == {'name': 'a.example', 'count': 20}
    assert {r['name']: r['count'] for r in around['results']} == {'delivered': 20, 'bounced': 10}
    assert around['subjects'] == [{'name': 'Win a prize', 'count': 30}]


def test_a_burst_opens_on_the_usernames_failed_logins(env):
    data = _client().get(f'/api/security-alerts/{env[1]}/activity').json()
    assert sum(b['count'] for b in data['buckets']) == 12
    around = data['around']
    assert around['total'] == 12
    assert len(around['addresses']) == 3 and around['countries'] == [{'name': 'Testland', 'count': 12}]
    assert around['networks'] == [{'name': 'Test Net', 'count': 12}]


def test_an_unknown_alert_is_not_found(env):
    assert _client().get('/api/security-alerts/999999999/activity').status_code == 404
