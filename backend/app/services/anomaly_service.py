import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, NamedTuple, Optional

from sqlalchemy import func

from ..config import settings
from ..correlation import authenticated_submissions, submitting_mailbox
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
    from .alias_domains import get_alias_domain_map, expand_address
    mailboxes = [m[0].lower() for m in db.query(MailboxStatistics.username).all() if m[0]]
    aliases = [a[0].lower() for a in db.query(AliasStatistics.alias_address).all() if a[0]]
    addresses = set(mailboxes) | set(aliases)
    mapping = get_alias_domain_map(db)
    if mapping:
        for address in list(addresses):
            addresses.update(expand_address(address, mapping))
    return addresses


def _recently_alerted(db, alert_type: str, subject: str, cooldown_hours: int) -> bool:
    cutoff = datetime.utcnow() - timedelta(hours=cooldown_hours)
    existing = db.query(SecurityAlert.id).filter(
        SecurityAlert.alert_type == alert_type,
        SecurityAlert.subject == subject,
        SecurityAlert.created_at >= cutoff,
    ).first()
    return existing is not None


def _record_and_notify(db, pending, alert_type, severity, subject, title, detail,
                       metric_value=None, baseline_value=None, chart=None) -> None:
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

    pending.append((title, detail, severity, alert_type, subject, chart))


CHART_HOURS = 24


class AlertChart(NamedTuple):
    counts: List[int]
    highlight: List[int]
    end: datetime
    usual_rate: Optional[float] = None


def hourly_counts(times: Iterable[datetime], end: datetime, hours: int = CHART_HOURS) -> List[int]:
    start = end - timedelta(hours=hours)
    counts = [0] * hours
    for when in times:
        if when is None or when < start:
            continue
        counts[min((when - start) // timedelta(hours=1), hours - 1)] += 1
    return counts


def window_hours(window_minutes: int, hours: int = CHART_HOURS) -> List[int]:
    first = (hours * 60 - max(int(window_minutes), 1)) // 60
    return list(range(max(first, 0), hours))


def _alert_chart(db, alert_type: str, subject: str, now: datetime, window_minutes: int,
                 usual_rate: Optional[float] = None) -> Optional[AlertChart]:
    start = now - timedelta(hours=CHART_HOURS)
    try:
        if alert_type == "volume_spike":
            rows = authenticated_submissions(db.query(MessageCorrelation.first_seen)).filter(
                MessageCorrelation.direction == "outbound",
                MessageCorrelation.first_seen >= start,
                MessageCorrelation.first_seen <= now,
                submitting_mailbox() == subject,
            ).all()
        else:
            rows = db.query(NetfilterLog.time).filter(
                NetfilterLog.time >= start,
                NetfilterLog.username == subject,
            ).all()
    except Exception as e:
        logger.warning(f"[ANOMALY] Could not count the hours behind the alert for {subject}: {e}")
        db.rollback()
        return None
    return AlertChart(hourly_counts((row[0] for row in rows), now), window_hours(window_minutes), now, usual_rate)


def _is_recurring_daily_pattern(db, sender: str, recent_count: int,
                                now: datetime, window_minutes: int) -> bool:
    tolerance = timedelta(minutes=60)
    window = timedelta(minutes=window_minutes)
    recurring_days = 0
    for day_back in range(1, settings.anomaly_baseline_days + 1):
        slot_end = now - timedelta(days=day_back) + tolerance
        slot_start = now - timedelta(days=day_back) - window - tolerance
        slot_count = authenticated_submissions(db.query(func.count(MessageCorrelation.id))).filter(
            MessageCorrelation.direction == "outbound",
            MessageCorrelation.first_seen >= slot_start,
            MessageCorrelation.first_seen <= slot_end,
            submitting_mailbox() == sender,
        ).scalar() or 0
        if slot_count >= recent_count * 0.5:
            recurring_days += 1
            if recurring_days >= 2:
                return True
    return False


def detect_volume_spikes(db, pending) -> int:
    window_minutes = settings.anomaly_check_interval
    now = datetime.utcnow()
    window_start = now - timedelta(minutes=window_minutes)
    baseline_start = now - timedelta(days=settings.anomaly_baseline_days)

    locals_ = _local_addresses(db)
    if not locals_:
        return 0

    mailbox = submitting_mailbox()
    recent = authenticated_submissions(db.query(
        mailbox.label("sender"),
        func.count(MessageCorrelation.id).label("cnt"),
    )).filter(
        MessageCorrelation.direction == "outbound",
        MessageCorrelation.first_seen >= window_start,
        MessageCorrelation.first_seen <= now,
        mailbox.in_(locals_),
    ).group_by(mailbox).all()

    alerts = 0
    window_hours = max(window_minutes / 60.0, 1e-6)
    for sender, recent_count in recent:
        if recent_count < settings.anomaly_volume_min_messages:
            continue

        baseline_total = authenticated_submissions(db.query(func.count(MessageCorrelation.id))).filter(
            MessageCorrelation.direction == "outbound",
            MessageCorrelation.first_seen >= baseline_start,
            MessageCorrelation.first_seen < window_start,
            submitting_mailbox() == sender,
        ).scalar() or 0

        baseline_hours = max((window_start - baseline_start).total_seconds() / 3600.0, 1e-6)
        baseline_rate = baseline_total / baseline_hours
        recent_rate = recent_count / window_hours

        effective_baseline = max(baseline_rate, 1.0)
        if recent_rate < effective_baseline * settings.anomaly_volume_multiplier:
            continue

        if _recently_alerted(db, "volume_spike", sender, settings.anomaly_alert_cooldown_hours):
            continue

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
        chart = _alert_chart(db, "volume_spike", sender, now, window_minutes, usual_rate=baseline_rate)
        _record_and_notify(db, pending, "volume_spike", severity, sender, title, detail,
                           metric_value=float(recent_count), baseline_value=round(baseline_rate, 2),
                           chart=chart)
        alerts += 1
        logger.warning(f"[ANOMALY] {title} ({ratio}x baseline)")

    return alerts


def detect_auth_failure_bursts(db, pending) -> int:
    now = datetime.utcnow()
    window_start = now - timedelta(minutes=settings.anomaly_check_interval)

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

        distinct_ips = db.query(func.count(func.distinct(NetfilterLog.ip))).filter(
            NetfilterLog.time >= window_start,
            NetfilterLog.username == username,
        ).scalar() or 0

        shown = re.sub(r'[\x00-\x1f\x7f]', ' ', username)
        title = f"Authentication failure burst: {shown}"[:255]
        detail = (
            f"{count} authentication failures for '{username}' from {distinct_ips} "
            f"source IP(s) in the last {settings.anomaly_check_interval} minutes.\n\n"
            "This can indicate a brute-force or credential-stuffing attack. "
            "Verify the account is secured and consider blocking the source IPs."
        )
        severity = "critical" if count >= settings.anomaly_auth_failure_threshold * 3 else "warning"
        chart = _alert_chart(db, "auth_failure_burst", username, now, settings.anomaly_check_interval)
        _record_and_notify(db, pending, "auth_failure_burst", severity, username, title, detail,
                           metric_value=float(count), baseline_value=float(settings.anomaly_auth_failure_threshold),
                           chart=chart)
        alerts += 1
        logger.warning(f"[ANOMALY] {title} ({count} failures, {distinct_ips} IPs)")

    return alerts


_ALERT_HEADINGS = {
    "volume_spike": ("Unusual sending from {}", "Mailbox"),
    "auth_failure_burst": ("Many failed sign-ins for {}", "Username"),
}


_CHART_UNITS = {
    "volume_spike": "Messages sent per hour",
    "auth_failure_burst": "Failed sign-ins per hour",
}


def _usual_rate(rate: float) -> str:
    if rate <= 0:
        return "none"
    if rate < 0.1:
        return "under 0.1 an hour"
    return f"{round(rate, 1):g} an hour" if rate < 10 else f"{round(rate)} an hour"


def _chart_panel(chart: AlertChart, alert_type: str):
    from . import email_layout as e
    from .. import app_time
    hours = len(chart.highlight)
    recent = sum(chart.counts[i] for i in chart.highlight)
    summary = f"{recent} in the last hour" if hours == 1 else f"{recent} in the last {hours} hours"
    if chart.usual_rate is not None:
        summary += f", usually {_usual_rate(chart.usual_rate)}"
    caption = f"{_CHART_UNITS.get(alert_type, 'Per hour')}. {summary}."
    start = chart.end - timedelta(hours=len(chart.counts))
    same_day = app_time.to_local(start).date() == app_time.to_local(chart.end).date()
    zone = app_time.zone_label(start) != app_time.zone_label(chart.end)
    start_label = e.format_time(start, zone=zone) if same_day else e.format_date(start, time=True, zone=zone)
    return e.panel(f"Last {len(chart.counts)} hours", e.bar_chart(
        chart.counts, chart.highlight, start=start_label, end=e.format_time(chart.end), caption=caption))


def _alert_email_html(title, detail, severity, alert_type, subject, chart: Optional[AlertChart] = None) -> str:
    from . import email_layout as e
    heading, label = _ALERT_HEADINGS.get(alert_type, ("{}", "Subject"))
    what, _, advice = detail.partition("\n\n")
    blocks = [e.panel('Details', e.kv([
        (label, subject),
        ('Severity', e.tag(severity.capitalize(), 'fail' if severity == 'critical' else 'warn')),
    ]))]
    if chart is not None and chart.counts:
        blocks.append(_chart_panel(chart, alert_type))
    if advice:
        blocks.append(e.banner('warn', 'What to do', advice))
    blocks.append(e.paragraph('The alert is also on the Dashboard.', muted=True))
    return e.render(
        title=heading.format(subject) if alert_type in _ALERT_HEADINGS else title,
        topic='Security', tone='fail' if severity == 'critical' else 'warn',
        intro=what, blocks=blocks,
        footer='Anomaly detection is on in Settings, Anomaly Detection.')


def run_anomaly_detection() -> dict:
    if not settings.anomaly_detection_enabled:
        return {"status": "disabled"}

    pending = []
    spikes = bursts = 0
    try:
        with get_db_context() as db:
            spikes = detect_volume_spikes(db, pending)
            bursts = detect_auth_failure_bursts(db, pending)
    finally:
        for title, detail, severity, alert_type, subject, chart in pending:
            try:
                from .notification_service import notify
                notify(subject=f"[Security] {title}", text_content=detail,
                       html_content=_alert_email_html(title, detail, severity, alert_type, subject, chart),
                       alert_type="security")
            except Exception as e:
                logger.error(f"Failed to dispatch security alert notification: {e}")

    total = spikes + bursts
    if total:
        logger.info(f"[ANOMALY] Detection run: {spikes} volume spike(s), {bursts} auth-failure burst(s)")
    return {"status": "ok", "volume_spikes": spikes, "auth_failure_bursts": bursts}
