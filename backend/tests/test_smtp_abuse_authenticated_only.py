"""SMTP abuse protection and the outbound volume-spike alert count only mail
the mailbox actually submitted with authentication.

The 'outbound' direction also covers unauthenticated mail whose envelope
sender is a hosted address and whose recipient looks external. Anyone on the
internet controls those envelope fields, so counting such rows let a remote
sender push a hosted mailbox over the abuse threshold and get its SMTP access
disabled and its app passwords revoked. Rows are ingested the same way the
Rspamd history import does it, then correlated by the real code.
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
FORGED_A = f"victim-a@{DOMAIN}"
FORGED_B = f"victim-b@{DOMAIN}"
SENDER = f"sender@{DOMAIN}"
ADDRESSES = (FORGED_A, FORGED_B, SENDER)


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import MessageCorrelation, RspamdLog, SecurityAlert, MailboxStatistics
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(MessageCorrelation.message_id.like(f"%{MARK}%")).delete(
            synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.message_id.like(f"%{MARK}%")).delete(synchronize_session=False)
        db.query(SecurityAlert).filter(SecurityAlert.subject.in_(ADDRESSES)).delete(synchronize_session=False)
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
        for address in ADDRESSES:
            db.add(MailboxStatistics(username=address, domain=DOMAIN))
        db.commit()
    try:
        yield
    finally:
        _cleanup()
        cfg.set_cached_active_domains(previous_domains)


def _ingest(entry):
    """Same field mapping as the Rspamd history import in scheduler.py."""
    from app.correlation import correlate_rspamd_log, detect_direction
    from app.database import get_db_context
    from app.models import RspamdLog
    with get_db_context() as db:
        row = RspamdLog(
            time=datetime.fromtimestamp(entry["unix_time"], tz=timezone.utc).replace(tzinfo=None),
            message_id=entry["message-id"], sender_smtp=entry["sender_smtp"],
            sender_mime=entry["sender_smtp"], recipients_smtp=entry["rcpt_smtp"],
            recipients_mime=entry["rcpt_smtp"], subject="x", score=0.0, required_score=15.0,
            action="no action", symbols=entry["symbols"], is_spam=False,
            has_auth=("MAILCOW_AUTH" in entry["symbols"]), direction=detect_direction(entry),
            ip=entry["ip"], user=entry["user"], raw_data=entry)
        db.add(row)
        db.commit()
        correlate_rspamd_log(db, row)


def _send(label, sender, rcpt, ip, count, authenticated=False):
    now = int(datetime.utcnow().replace(tzinfo=timezone.utc).timestamp())
    for i in range(count):
        _ingest({
            "unix_time": now - i, "message-id": f"{label}-{i}-{MARK}@sender.invalid",
            "sender_smtp": sender, "rcpt_smtp": [rcpt], "ip": ip,
            "user": sender if authenticated else "unknown",
            "symbols": {"MAILCOW_AUTH": {"score": 0.0}} if authenticated else {},
        })


def _directions():
    from app.database import get_db_context
    from app.models import MessageCorrelation
    with get_db_context() as db:
        rows = db.query(MessageCorrelation.sender, MessageCorrelation.direction).filter(
            MessageCorrelation.message_id.like(f"%{MARK}%")).all()
    return {(sender, direction) for sender, direction in rows}


def test_unauthenticated_forged_sender_is_not_a_block_candidate(env):
    from app.services import smtp_abuse_service as svc
    # Public-IP client, hosted recipient written with a trailing dot
    _send("a", FORGED_A, f"mbox@{DOMAIN}.", "203.0.113.10", 6)
    # Shape of a redirected copy: container IP, no login, external recipient
    _send("b", FORGED_B, "dest@external.invalid", "172.22.1.250", 6)
    # The rows are still shown as outbound; only the attribution changes
    assert {(FORGED_A, "outbound"), (FORGED_B, "outbound")} <= _directions()

    counts = svc.fetch_outbound_counts(60)
    assert FORGED_A not in counts and FORGED_B not in counts
    candidates = {c["email"] for c in svc.find_candidates()}
    assert FORGED_A not in candidates and FORGED_B not in candidates


def test_authenticated_sending_above_threshold_is_still_a_candidate(env):
    from app.services import smtp_abuse_service as svc
    _send("auth", SENDER, "dest@external.invalid", "198.51.100.20", 6, authenticated=True)
    assert svc.fetch_outbound_counts(60).get(SENDER) == 6
    assert {"email": SENDER, "count": 6} in svc.find_candidates()


def _volume_alerts():
    from app.database import get_db_context
    from app.models import SecurityAlert
    from app.services.anomaly_service import detect_volume_spikes
    with get_db_context() as db:
        detect_volume_spikes(db, [])
        rows = db.query(SecurityAlert.subject).filter(
            SecurityAlert.alert_type == "volume_spike", SecurityAlert.subject.in_(ADDRESSES)).all()
    return {subject for (subject,) in rows}


def test_volume_spike_ignores_unauthenticated_forged_sender(env):
    _send("spike-forged", FORGED_B, "dest@external.invalid", "172.22.1.250", 30)
    assert _volume_alerts() == set()


def test_volume_spike_still_alerts_on_authenticated_burst(env):
    _send("spike-auth", SENDER, "dest@external.invalid", "198.51.100.20", 30, authenticated=True)
    assert _volume_alerts() == {SENDER}
