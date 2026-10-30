"""SMTP abuse protection and the outbound volume-spike alert count messages,
not recipients.

One submission to many recipients is one Postfix queue chain with one
Rspamd scan, so it becomes one message correlation and counts once. The rows
are the ones a real submission to 30 recipients produces: the Postfix lines
are parsed by the real parser and correlated by the scheduler's own jobs, in
both orders the logs can arrive in.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app import config as cfg
from app.config import settings

MARK = uuid.uuid4().hex[:10]
DOMAIN = f"hosted-{MARK}.test"
SENDER = f"newsletter@{DOMAIN}"
RECIPIENTS = [f"reader{i}@example.net" for i in range(30)]
QUEUE_IDS = []


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import MailboxStatistics, MessageCorrelation, PostfixLog, RspamdLog, SecurityAlert
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(MessageCorrelation.message_id.like(f"%{MARK}%")).delete(
            synchronize_session=False)
        db.query(PostfixLog).filter(PostfixLog.queue_id.in_(QUEUE_IDS)).delete(synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.message_id.like(f"%{MARK}%")).delete(synchronize_session=False)
        db.query(SecurityAlert).filter(SecurityAlert.subject == SENDER).delete(synchronize_session=False)
        db.query(MailboxStatistics).filter(MailboxStatistics.domain == DOMAIN).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def env(monkeypatch):
    if not _postgres_available():
        pytest.skip("PostgreSQL not available")
    from app.database import init_db, get_db_context
    from app.models import MailboxStatistics
    init_db()
    previous_domains = cfg.get_cached_active_domains()
    cfg.set_cached_active_domains([DOMAIN])
    monkeypatch.setattr(settings._inner, "smtp_abuse_threshold", 5)
    monkeypatch.setattr(settings._inner, "smtp_abuse_window_minutes", 60)
    monkeypatch.setattr(settings._inner, "anomaly_check_interval", 15)
    monkeypatch.setattr(settings._inner, "anomaly_volume_multiplier", 10.0)
    monkeypatch.setattr(settings._inner, "anomaly_volume_min_messages", 20)
    monkeypatch.setattr(settings._inner, "anomaly_baseline_days", 7)
    monkeypatch.setattr(settings._inner, "anomaly_alert_cooldown_hours", 24)
    _cleanup()
    with get_db_context() as db:
        db.add(MailboxStatistics(username=SENDER, domain=DOMAIN))
        db.commit()
    try:
        yield
    finally:
        _cleanup()
        cfg.set_cached_active_domains(previous_domains)


def _postfix_lines(queue_id, message_id):
    """What Postfix logs for one authenticated submission to every recipient."""
    lines = [
        ("postfix/submission/smtpd",
         f"{queue_id}: client=unknown[198.51.100.20], sasl_method=LOGIN, sasl_username={SENDER}"),
        ("postfix/cleanup", f"{queue_id}: message-id=<{message_id}>"),
        ("postfix/qmgr", f"{queue_id}: from=<{SENDER}>, size=4096, nrcpt={len(RECIPIENTS)} (queue active)"),
    ]
    for rcpt in RECIPIENTS:
        lines.append(("postfix/smtp",
                      f"{queue_id}: to=<{rcpt}>, relay=mx.example.net[203.0.113.25]:25, delay=1.4, "
                      f"delays=0.2/0.01/0.6/0.6, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as {MARK})"))
    lines.append(("postfix/qmgr", f"{queue_id}: removed"))
    return lines


def _ingest_postfix(queue_id, message_id):
    """Same field mapping as the Postfix import in scheduler.py."""
    from app.correlation import parse_postfix_message
    from app.database import get_db_context
    from app.models import PostfixLog
    now = datetime.utcnow()
    with get_db_context() as db:
        for program, message in _postfix_lines(queue_id, message_id):
            parsed = parse_postfix_message(message)
            db.add(PostfixLog(
                time=now, program=program, priority="info", message=message,
                queue_id=parsed.get("queue_id"), message_id=parsed.get("message_id"),
                sender=parsed.get("sender"), recipient=parsed.get("recipient"),
                status=parsed.get("status"), relay=parsed.get("relay"),
                delay=parsed.get("delay"), dsn=parsed.get("dsn"), raw_data={"message": message}))
        db.commit()


def _ingest_rspamd_and_correlate(queue_id, message_id):
    """Same field mapping as the Rspamd history import in scheduler.py, then
    the scheduler's correlation job for that log."""
    from app.correlation import detect_direction
    from app.database import get_db_context
    from app.models import RspamdLog
    from app.scheduler import correlate_single_message
    entry = {
        "unix_time": int(datetime.utcnow().replace(tzinfo=timezone.utc).timestamp()),
        "message-id": message_id, "sender_smtp": SENDER, "rcpt_smtp": RECIPIENTS,
        "ip": "198.51.100.20", "user": SENDER, "qid": queue_id,
        "symbols": {"MAILCOW_AUTH": {"score": 0.0}},
    }
    with get_db_context() as db:
        row = RspamdLog(
            time=datetime.fromtimestamp(entry["unix_time"], tz=timezone.utc).replace(tzinfo=None),
            message_id=message_id, queue_id=queue_id, sender_smtp=SENDER, sender_mime=SENDER,
            recipients_smtp=RECIPIENTS, recipients_mime=RECIPIENTS, subject="Monthly news",
            score=0.0, required_score=15.0, action="no action", symbols=entry["symbols"],
            is_spam=False, has_auth=True, direction=detect_direction(entry),
            ip=entry["ip"], user=SENDER, raw_data=entry)
        db.add(row)
        db.commit()
        correlate_single_message(db, row)


def _correlations():
    from app.database import get_db_context
    from app.models import MessageCorrelation
    with get_db_context() as db:
        return db.query(MessageCorrelation.queue_id, MessageCorrelation.direction).filter(
            MessageCorrelation.message_id.like(f"%{MARK}%")).all()


def _volume_alerts():
    from app.database import get_db_context
    from app.models import SecurityAlert
    from app.services.anomaly_service import detect_volume_spikes
    with get_db_context() as db:
        detect_volume_spikes(db, [])
        return db.query(SecurityAlert).filter(
            SecurityAlert.alert_type == "volume_spike", SecurityAlert.subject == SENDER).count()


@pytest.mark.parametrize("postfix_first", [True, False], ids=["postfix-first", "rspamd-first"])
def test_one_message_to_many_recipients_counts_once(env, postfix_first):
    from app.scheduler import _complete_incomplete_correlations_sync
    from app.services import smtp_abuse_service as svc
    queue_id = uuid.uuid4().hex[:10].upper()
    QUEUE_IDS.append(queue_id)
    message_id = f"news-{MARK}@{DOMAIN}"

    if postfix_first:
        _ingest_postfix(queue_id, message_id)
        _ingest_rspamd_and_correlate(queue_id, message_id)
    else:
        _ingest_rspamd_and_correlate(queue_id, message_id)
        _ingest_postfix(queue_id, message_id)
        _complete_incomplete_correlations_sync()

    assert _correlations() == [(queue_id, "outbound")]
    # 30 recipients, threshold 5: one message, so no block
    assert svc.fetch_outbound_counts(60).get(SENDER) == 1
    assert SENDER not in {c["email"] for c in svc.find_candidates()}
    # The spike alert counts the same rows: 1 is below its minimum of 20
    assert _volume_alerts() == 0
