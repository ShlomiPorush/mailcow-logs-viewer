"""
Security Alerts API - anomaly-detection findings (compromised mailbox /
auth attack) surfaced on the dashboard.
"""
import logging
from collections import Counter
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import SecurityAlert, MessageCorrelation, NetfilterLog
from ..config import settings
from ..correlation import submitted_with_auth
from ..utils import internal_error, format_datetime_for_api as format_datetime_utc

logger = logging.getLogger(__name__)

router = APIRouter()


def _serialize(a: SecurityAlert) -> dict:
    return {
        "id": a.id,
        "alert_type": a.alert_type,
        "severity": a.severity,
        "subject": a.subject,
        "title": a.title,
        "detail": a.detail,
        "metric_value": a.metric_value,
        "baseline_value": a.baseline_value,
        "acknowledged": a.acknowledged,
        "created_at": format_datetime_utc(a.created_at),
    }


@router.get("/security-alerts")
def list_security_alerts(
    acknowledged: Optional[bool] = Query(None, description="Filter by acknowledged state"),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """List security alerts (newest first), plus an unacknowledged count."""
    try:
        q = db.query(SecurityAlert)
        if acknowledged is not None:
            q = q.filter(SecurityAlert.acknowledged == acknowledged)
        alerts = q.order_by(SecurityAlert.created_at.desc()).limit(limit).all()

        unacked = db.query(SecurityAlert).filter(
            SecurityAlert.acknowledged == False  # noqa: E712
        ).count()

        return {
            "enabled": settings.anomaly_detection_enabled,
            "alerts": [_serialize(a) for a in alerts],
            "unacknowledged_count": unacked,
        }
    except Exception as e:
        logger.error(f"Error listing security alerts: {e}")
        raise internal_error(e)


@router.post("/security-alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int, db: Session = Depends(get_db)):
    """Mark a single alert as acknowledged."""
    try:
        alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        alert.acknowledged = True
        db.commit()
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error acknowledging alert: {e}")
        raise internal_error(e)


@router.post("/security-alerts/acknowledge-all")
def acknowledge_all_alerts(db: Session = Depends(get_db)):
    """Acknowledge every outstanding alert."""
    try:
        updated = db.query(SecurityAlert).filter(
            SecurityAlert.acknowledged == False  # noqa: E712
        ).update({"acknowledged": True}, synchronize_session=False)
        db.commit()
        return {"status": "success", "acknowledged": updated}
    except Exception as e:
        db.rollback()
        logger.error(f"Error acknowledging all alerts: {e}")
        raise internal_error(e)


# What an alert is about, over time: the mailbox's sent mail for a volume spike,
# the username's failed logins for an auth failure burst. Counted per 15 minutes
# from the baseline period before the alert to two hours after it.
BUCKET_MINUTES = 15
AFTER_HOURS = 2


def _events(db: Session, alert: SecurityAlert, start, end):
    subject = (alert.subject or '').lower()
    if alert.alert_type == 'volume_spike':
        return db.query(MessageCorrelation.first_seen, MessageCorrelation.recipient,
                        MessageCorrelation.final_status, MessageCorrelation.subject).filter(
            MessageCorrelation.direction == 'outbound',
            # The same messages the volume-spike alert counted
            submitted_with_auth(),
            func.lower(MessageCorrelation.sender) == subject,
            MessageCorrelation.first_seen >= start, MessageCorrelation.first_seen < end,
        ).all()
    return db.query(NetfilterLog.time, NetfilterLog.ip, NetfilterLog.country_name, NetfilterLog.asn_org).filter(
        func.lower(NetfilterLog.username) == subject,
        NetfilterLog.time >= start, NetfilterLog.time < end,
    ).all()


def _top(counter: Counter, limit: int = 6) -> list:
    return [{'name': name, 'count': count} for name, count in counter.most_common(limit)]


@router.get("/security-alerts/{alert_id}/activity")
def alert_activity(alert_id: int, db: Session = Depends(get_db)):
    """
    The history behind an alert: counts per 15 minutes from the baseline period
    before it to two hours after, and what happened around it (from the check
    window before the alert to an hour after): recipient domains, delivery
    results and subjects for a volume spike; source addresses, countries and
    networks for an auth failure burst.
    """
    try:
        alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        at = alert.created_at
        window = max(int(settings.anomaly_check_interval or 15), 1)
        start = (at - timedelta(days=max(int(settings.anomaly_baseline_days or 7), 1))).replace(minute=0, second=0, microsecond=0)
        end = at + timedelta(hours=AFTER_HOURS)
        rows = _events(db, alert, start, end)

        step = timedelta(minutes=BUCKET_MINUTES)
        counts = Counter(int((row[0] - start) / step) for row in rows if row[0])
        buckets = []
        t, i = start, 0
        while t < end:
            buckets.append({'start': format_datetime_utc(t), 'count': counts.get(i, 0)})
            t += step
            i += 1

        around_from, around_to = at - timedelta(minutes=window), at + timedelta(hours=1)
        near = [row for row in rows if row[0] and around_from <= row[0] <= around_to]
        if alert.alert_type == 'volume_spike':
            around = {
                'recipient_domains': _top(Counter((r[1] or '?').split('@')[-1].lower() for r in near)),
                'results': _top(Counter((r[2] or 'unknown') for r in near)),
                'subjects': _top(Counter((r[3] or '(no subject)') for r in near), 5),
            }
        else:
            around = {
                'addresses': _top(Counter(r[1] or '?' for r in near)),
                'countries': _top(Counter(r[2] or 'Unknown' for r in near)),
                'networks': _top(Counter(r[3] or 'Unknown' for r in near)),
            }
        return {
            'alert': _serialize(alert),
            'bucket_minutes': BUCKET_MINUTES,
            'window_minutes': window,
            'baseline_days': int(settings.anomaly_baseline_days or 7),
            'buckets': buckets,
            'around': {'from': format_datetime_utc(around_from), 'to': format_datetime_utc(around_to), 'total': len(near), **around},
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error building the activity of an alert: {e}")
        raise internal_error(e)
