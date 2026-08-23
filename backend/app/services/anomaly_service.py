"""
Anomaly detection - compromised-mailbox and auth-attack alerts.

Two independent detectors, run periodically by the scheduler:

1. Outbound volume spike: a local mailbox sending far above its own recent
   baseline (the classic account-takeover / outbound-spam signature).
2. Auth-failure burst: a username accumulating many authentication failures
   within the check window (credential stuffing / brute force).

Findings are written to the security_alerts table and dispatched through the
unified notification service (email + webhook). A per-(type, subject) cooldown
prevents alert storms. Synchronous - call from a worker thread / executor.
"""
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func

from ..config import settings
from ..database import get_db_context
from ..models import (
    MessageCorrelation,
    NetfilterLog,
    MailboxStatistics,
    AliasStatistics,
    SecurityAlert,
)

logger = logging.getLogger(__name__)


def _local_addresses(db) -> set:
    """Lowercased set of all local mailbox + alias addresses."""
    mailboxes = [m[0].lower() for m in db.query(MailboxStatistics.username).all() if m[0]]
    aliases = [a[0].lower() for a in db.query(AliasStatistics.alias_address).all() if a[0]]
    return set(mailboxes) | set(aliases)


def _recently_alerted(db, alert_type: str, subject: str, cooldown_hours: int) -> bool:
    """True if an alert of this type/subject fired within the cooldown window."""
    cutoff = datetime.utcnow() - timedelta(hours=cooldown_hours)
    existing = db.query(SecurityAlert.id).filter(
        SecurityAlert.alert_type == alert_type,
        SecurityAlert.subject == subject,
        SecurityAlert.created_at >= cutoff,
    ).first()
    return existing is not None


def _record_and_notify(db, pending, alert_type, severity, subject, title, detail,
                       metric_value=None, baseline_value=None) -> None:
    alert = SecurityAlert(
        alert_type=alert_type,
        severity=severity,
        subject=subject,
        title=title,
        detail=detail,
        metric_value=metric_value,
        baseline_value=baseline_value,
        created_at=datetime.utcnow(),
    )
    db.add(alert)
    db.commit()

    # Notification delivery is slow (HTTP + SMTP with timeouts); queue it and
    # dispatch after the DB session is closed so a pooled connection is never
    # pinned while we wait on external services.
    pending.append((title, detail))


def _is_recurring_daily_pattern(db, sender: str, recent_count: int,
                                now: datetime, window_minutes: int) -> bool:
    """Did this sender produce similar volume in the same time-of-day slot
    on at least two past days?

    The slot is the current check window shifted back N whole days, padded
    by an hour on each side so cron drift and processing time do not break
    the match. "Similar" = at least half of today's burst - so if the usual
    daily batch suddenly doubles or more, past slots fall below the bar and
    the alert still fires.
    """
    tolerance = timedelta(minutes=60)
    window = timedelta(minutes=window_minutes)
    recurring_days = 0
    for day_back in range(1, settings.anomaly_baseline_days + 1):
        slot_end = now - timedelta(days=day_back) + tolerance
        slot_start = now - timedelta(days=day_back) - window - tolerance
        slot_count = db.query(func.count(MessageCorrelation.id)).filter(
            MessageCorrelation.direction == "outbound",
            MessageCorrelation.first_seen >= slot_start,
            MessageCorrelation.first_seen <= slot_end,
            func.lower(MessageCorrelation.sender) == sender,
        ).scalar() or 0
        if slot_count >= recent_count * 0.5:
            recurring_days += 1
            if recurring_days >= 2:
                return True
    return False


def detect_volume_spikes(db, pending) -> int:
    """Alert on mailboxes sending far above their own baseline. Returns count."""
    window_minutes = settings.anomaly_check_interval
    now = datetime.utcnow()
    window_start = now - timedelta(minutes=window_minutes)
    baseline_start = now - timedelta(days=settings.anomaly_baseline_days)

    locals_ = _local_addresses(db)
    if not locals_:
        return 0

    # Messages sent per local sender in the recent window
    recent = db.query(
        func.lower(MessageCorrelation.sender).label("sender"),
        func.count(MessageCorrelation.id).label("cnt"),
    ).filter(
        MessageCorrelation.direction == "outbound",
        MessageCorrelation.first_seen >= window_start,
        MessageCorrelation.first_seen <= now,
        func.lower(MessageCorrelation.sender).in_(locals_),
    ).group_by(func.lower(MessageCorrelation.sender)).all()

    alerts = 0
    window_hours = max(window_minutes / 60.0, 1e-6)
    for sender, recent_count in recent:
        if recent_count < settings.anomaly_volume_min_messages:
            continue

        # Baseline: this sender's average per-window rate over the history period
        baseline_total = db.query(func.count(MessageCorrelation.id)).filter(
            MessageCorrelation.direction == "outbound",
            MessageCorrelation.first_seen >= baseline_start,
            MessageCorrelation.first_seen < window_start,
            func.lower(MessageCorrelation.sender) == sender,
        ).scalar() or 0

        baseline_hours = max((window_start - baseline_start).total_seconds() / 3600.0, 1e-6)
        baseline_rate = baseline_total / baseline_hours          # msgs/hour, historical
        recent_rate = recent_count / window_hours                # msgs/hour, now

        # A brand-new sender with no history but a large burst is also suspicious;
        # treat a zero baseline as "1 msg/hour" so the ratio stays meaningful.
        effective_baseline = max(baseline_rate, 1.0)
        if recent_rate < effective_baseline * settings.anomaly_volume_multiplier:
            continue

        if _recently_alerted(db, "volume_spike", sender, settings.anomaly_alert_cooldown_hours):
            continue

        # A mailbox that bursts at the same time every day (scheduled
        # reports, digests) is following its own routine, not compromised.
        # A whitelist would blind us to off-schedule bursts - instead the
        # detector compares against the same time-of-day slot on past days:
        # recurring similar volume there means "scheduled", while a burst at
        # an unusual hour finds near-empty slots and still alerts.
        if _is_recurring_daily_pattern(db, sender, recent_count, now, window_minutes):
            logger.info(f"[ANOMALY] {sender}: burst matches its daily send pattern - not alerting")
            continue

        ratio = round(recent_rate / effective_baseline, 1)
        title = f"Outbound volume spike: {sender}"
        detail = (
            f"Mailbox {sender} sent {recent_count} messages in the last "
            f"{window_minutes} minutes ({round(recent_rate)}/hour), about {ratio}x its "
            f"baseline of {round(baseline_rate, 1)}/hour over the past "
            f"{settings.anomaly_baseline_days} days.\n\n"
            "This can indicate a compromised mailbox sending spam. Review the "
            "mailbox's recent activity and consider resetting its password."
        )
        severity = "critical" if ratio >= settings.anomaly_volume_multiplier * 2 else "warning"
        _record_and_notify(db, pending, "volume_spike", severity, sender, title, detail,
                           metric_value=float(recent_count), baseline_value=round(baseline_rate, 2))
        alerts += 1
        logger.warning(f"[ANOMALY] {title} ({ratio}x baseline)")

    return alerts


def detect_auth_failure_bursts(db, pending) -> int:
    """Alert on usernames with many auth failures in the window. Returns count."""
    window_start = datetime.utcnow() - timedelta(minutes=settings.anomaly_check_interval)

    rows = db.query(
        NetfilterLog.username.label("username"),
        func.count(NetfilterLog.id).label("cnt"),
    ).filter(
        NetfilterLog.time >= window_start,
        NetfilterLog.username.isnot(None),
        NetfilterLog.username != "",
    ).group_by(NetfilterLog.username).having(
        func.count(NetfilterLog.id) >= settings.anomaly_auth_failure_threshold
    ).all()

    alerts = 0
    for username, count in rows:
        if _recently_alerted(db, "auth_failure_burst", username, settings.anomaly_alert_cooldown_hours):
            continue

        # How many distinct source IPs? (distributed attack vs single host)
        distinct_ips = db.query(func.count(func.distinct(NetfilterLog.ip))).filter(
            NetfilterLog.time >= window_start,
            NetfilterLog.username == username,
        ).scalar() or 0

        title = f"Authentication failure burst: {username}"
        detail = (
            f"{count} authentication failures for '{username}' from {distinct_ips} "
            f"source IP(s) in the last {settings.anomaly_check_interval} minutes.\n\n"
            "This can indicate a brute-force or credential-stuffing attack. "
            "Verify the account is secured and consider blocking the source IPs."
        )
        severity = "critical" if count >= settings.anomaly_auth_failure_threshold * 3 else "warning"
        _record_and_notify(db, pending, "auth_failure_burst", severity, username, title, detail,
                           metric_value=float(count), baseline_value=float(settings.anomaly_auth_failure_threshold))
        alerts += 1
        logger.warning(f"[ANOMALY] {title} ({count} failures, {distinct_ips} IPs)")

    return alerts


def run_anomaly_detection() -> dict:
    """Run all detectors. Returns a summary dict."""
    if not settings.anomaly_detection_enabled:
        return {"status": "disabled"}

    pending = []
    spikes = bursts = 0
    try:
        with get_db_context() as db:
            spikes = detect_volume_spikes(db, pending)
            bursts = detect_auth_failure_bursts(db, pending)
    finally:
        # Deliver after the session is closed (notification HTTP/SMTP timeouts
        # must not pin a pooled DB connection). In finally: alerts are already
        # committed one by one, so a detector crash must not swallow the
        # notifications of alerts recorded before it - the cooldown would then
        # suppress any retry.
        for title, detail in pending:
            try:
                from .notification_service import notify
                notify(subject=f"[Security] {title}", text_content=detail, alert_type="security")
            except Exception as e:
                logger.error(f"Failed to dispatch security alert notification: {e}")

    total = spikes + bursts
    if total:
        logger.info(f"[ANOMALY] Detection run: {spikes} volume spike(s), {bursts} auth-failure burst(s)")
    return {"status": "ok", "volume_spikes": spikes, "auth_failure_bursts": bursts}
