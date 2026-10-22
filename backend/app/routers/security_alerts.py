"""
Security Alerts API - anomaly-detection findings (compromised mailbox /
auth attack) surfaced on the dashboard.
"""
import logging
import re
import uuid
from collections import Counter
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Body, Depends, Query, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, update
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import SecurityAlert, MessageCorrelation, NetfilterLog, SMTPAbuseAction
from ..config import settings
from ..correlation import authenticated_submissions, submitting_mailbox
from ..utils import internal_error, format_datetime_for_api as format_datetime_utc

logger = logging.getLogger(__name__)

router = APIRouter()

# Dismiss all takes at most this many ids (the list hands out as many)
MAX_ACK_IDS = 10000


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
        # One snapshot for the rows and the ids: an alert committed between the two
        # queries is in neither, so Dismiss all never takes one the list did not show
        db.connection(execution_options={"isolation_level": "REPEATABLE READ"})
        q = db.query(SecurityAlert)
        if acknowledged is not None:
            q = q.filter(SecurityAlert.acknowledged == acknowledged)
        alerts = q.order_by(SecurityAlert.created_at.desc()).limit(limit).all()

        # Every alert still open as this answer sees it (newest first): Dismiss all
        # sends these back, so one committed after this answer is not touched
        open_ids = [row[0] for row in db.query(SecurityAlert.id).filter(
            SecurityAlert.acknowledged == False  # noqa: E712
        ).order_by(SecurityAlert.created_at.desc(), SecurityAlert.id.desc()).limit(MAX_ACK_IDS + 1).all()]
        unacked = len(open_ids) if len(open_ids) <= MAX_ACK_IDS else db.query(SecurityAlert).filter(
            SecurityAlert.acknowledged == False  # noqa: E712
        ).count()
        # The open critical ones, also those past the rows asked for: Needs attention
        # is marked critical for one even when its list shows only the newest
        critical = db.query(SecurityAlert).filter(
            SecurityAlert.acknowledged == False,  # noqa: E712
            SecurityAlert.severity == 'critical',
        ).count()

        return {
            "enabled": settings.anomaly_detection_enabled,
            "alerts": [_serialize(a) for a in alerts],
            "unacknowledged_count": unacked,
            "unacknowledged_critical": critical,
            "unacknowledged_ids": open_ids[:MAX_ACK_IDS],
        }
    except Exception as e:
        logger.error(f"Error listing security alerts: {e}")
        raise internal_error(e)


def _acknowledge(db: Session, condition) -> dict:
    """Acknowledge the open alerts matching condition in one statement, all under
    one new receipt; an alert already acknowledged is left as it is (its own
    receipt stays), so the receipt names only what this call changed."""
    receipt = uuid.uuid4()
    ids = [row[0] for row in db.execute(
        update(SecurityAlert)
        .where(condition, SecurityAlert.acknowledged == False)  # noqa: E712
        .values(acknowledged=True, ack_batch=receipt)
        .returning(SecurityAlert.id)
    ).all()]
    db.commit()
    return {"status": "success", "acknowledged": len(ids), "ids": sorted(ids), "receipt": str(receipt) if ids else None}


class AcknowledgeIds(BaseModel):
    ids: List[int] = Field(..., min_length=1, max_length=MAX_ACK_IDS)


@router.post("/security-alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int, db: Session = Depends(get_db)):
    """Mark a single alert as acknowledged. The answer's receipt undoes it; an
    alert that was already acknowledged (by another tab) gives no receipt."""
    try:
        if not db.query(SecurityAlert.id).filter(SecurityAlert.id == alert_id).first():
            raise HTTPException(status_code=404, detail="Alert not found")
        return _acknowledge(db, SecurityAlert.id == alert_id)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error acknowledging alert: {e}")
        raise internal_error(e)


@router.post("/security-alerts/acknowledge-all")
def acknowledge_all_alerts(body: Optional[AcknowledgeIds] = Body(None), db: Session = Depends(get_db)):
    """Acknowledge the open alerts whose ids are given (the list's
    unacknowledged_ids), or, with no body, every open alert. The answer's
    receipt undoes exactly what changed."""
    try:
        condition = SecurityAlert.id.in_(set(body.ids)) if body else SecurityAlert.id.isnot(None)
        return _acknowledge(db, condition)
    except Exception as e:
        db.rollback()
        logger.error(f"Error acknowledging all alerts: {e}")
        raise internal_error(e)


@router.post("/security-alerts/acknowledgements/{receipt}/undo")
def undo_acknowledgement(receipt: uuid.UUID, db: Session = Depends(get_db)):
    """Re-open the alerts a dismissal acknowledged, by its receipt: only those
    still acknowledged under it (a second undo changes nothing)."""
    try:
        ids = [row[0] for row in db.execute(
            update(SecurityAlert)
            .where(SecurityAlert.ack_batch == receipt, SecurityAlert.acknowledged == True)  # noqa: E712
            .values(acknowledged=False, ack_batch=None)
            .returning(SecurityAlert.id)
        ).all()]
        db.commit()
        return {"status": "success", "restored": len(ids), "ids": sorted(ids)}
    except Exception as e:
        db.rollback()
        logger.error(f"Error undoing an acknowledgement: {e}")
        raise internal_error(e)


# What an alert is about, over time: the mailbox's sent mail for a volume spike
# or an SMTP block by abuse protection, the username's failed logins for an
# auth failure burst. Counted per 15 minutes from the baseline period before
# the alert to two hours after it.
BUCKET_MINUTES = 15
AFTER_HOURS = 2
SENT_MAIL_ALERTS = ('volume_spike', 'smtp_abuse_block')
# An SMTP block is recorded twice at once: its abuse action, then its alert
BLOCK_ACTION_MATCH = timedelta(minutes=5)
# How far before an alert "Around the alert" starts when its window is not known
UNKNOWN_WINDOW_MINUTES = 60
# An anomaly alert names the window it counted in, and a spike its baseline
# period, in its detail (anomaly_service): the settings may have changed since
DETAIL_WINDOW_RE = re.compile(r"in the last (\d+) minutes")
DETAIL_BASELINE_RE = re.compile(r"over the past (\d+) days")


def _events(db: Session, alert: SecurityAlert, start, end):
    subject = (alert.subject or '').lower()
    if alert.alert_type in SENT_MAIL_ALERTS:
        # The same messages the volume-spike alert counted
        return authenticated_submissions(
            db.query(MessageCorrelation.first_seen, MessageCorrelation.recipient,
                     MessageCorrelation.final_status, MessageCorrelation.subject)).filter(
            MessageCorrelation.direction == 'outbound',
            submitting_mailbox() == subject,
            MessageCorrelation.first_seen >= start, MessageCorrelation.first_seen < end,
        ).all()
    return db.query(NetfilterLog.time, NetfilterLog.ip, NetfilterLog.country_name, NetfilterLog.asn_org).filter(
        func.lower(NetfilterLog.username) == subject,
        NetfilterLog.time >= start, NetfilterLog.time < end,
    ).all()


def _block_window(db: Session, alert: SecurityAlert) -> Optional[int]:
    """The window an SMTP block counted in, from its own abuse action; None when that action is gone."""
    at = alert.created_at
    actions = db.query(SMTPAbuseAction.created_at, SMTPAbuseAction.window_minutes).filter(
        SMTPAbuseAction.email == (alert.subject or '').lower(),
        SMTPAbuseAction.action == 'blocked',
        SMTPAbuseAction.created_at >= at - BLOCK_ACTION_MATCH,
        SMTPAbuseAction.created_at <= at + BLOCK_ACTION_MATCH,
    ).all()
    if not actions:
        return None
    return max(min(actions, key=lambda r: abs(r[0] - at))[1], 1)


def _detail_number(alert: SecurityAlert, pattern) -> Optional[int]:
    match = pattern.search(alert.detail or "")
    return max(int(match.group(1)), 1) if match else None


def _top(counter: Counter, limit: int = 6) -> list:
    return [{'name': name, 'count': count} for name, count in counter.most_common(limit)]


@router.get("/security-alerts/{alert_id}/activity")
def alert_activity(alert_id: int, db: Session = Depends(get_db)):
    """
    The history behind an alert: counts per 15 minutes from the baseline period
    before it to two hours after, and what happened around it (from the check
    window before the alert to an hour after): recipient domains, delivery
    results and subjects for a volume spike or an SMTP block; source addresses, countries and
    networks for an auth failure burst.
    """
    try:
        alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        at = alert.created_at
        # The window the alert counted in, even after the setting changed:
        # an SMTP block keeps the one it was blocked with, an anomaly alert
        # the one its detail names; None when not known
        if alert.alert_type == 'smtp_abuse_block':
            window = _block_window(db, alert)
        else:
            window = _detail_number(alert, DETAIL_WINDOW_RE)
        baseline_days = _detail_number(alert, DETAIL_BASELINE_RE) or max(int(settings.anomaly_baseline_days or 7), 1)
        start = (at - timedelta(days=baseline_days)).replace(minute=0, second=0, microsecond=0)
        end = at + timedelta(hours=AFTER_HOURS)
        rows = _events(db, alert, start, end)

        step = timedelta(minutes=BUCKET_MINUTES)
        counts = Counter(int((row[0] - start) / step) for row in rows if row[0])
        # Data only up to now: for a recent alert the hours after it have not
        # happened yet, and are no quiet hours
        seen_to = min(end, datetime.utcnow())
        buckets = []
        t, i = start, 0
        while t < seen_to:
            buckets.append({'start': format_datetime_utc(t), 'count': counts.get(i, 0),
                            # The last one ends at now, part of its 15 minutes
                            'partial': t + step > seen_to})
            t += step
            i += 1

        around_from, around_to = at - timedelta(minutes=window or UNKNOWN_WINDOW_MINUTES), at + timedelta(hours=1)
        near = [row for row in rows if row[0] and around_from <= row[0] <= around_to]
        if alert.alert_type in SENT_MAIL_ALERTS:
            around = {
                'recipient_domains': _top(Counter((r[1] or '?').split('@')[-1].lower() for r in near)),
                'results': _top(Counter((r[2] or 'unknown') for r in near)),
                'subjects': _top(Counter((r[3] or '(no subject)') for r in near), 5),
            }
        else:
            around = {
                'addresses': _top(Counter(r[1] or '?' for r in near)),
                # Every address, not only the top ones listed
                'address_count': len({r[1] or '?' for r in near}),
                'countries': _top(Counter(r[2] or 'Unknown' for r in near)),
                'networks': _top(Counter(r[3] or 'Unknown' for r in near)),
            }
        return {
            'alert': _serialize(alert),
            'bucket_minutes': BUCKET_MINUTES,
            'window_minutes': window,
            'baseline_days': baseline_days,
            'buckets': buckets,
            # The exact end of the data (now, for a recent alert)
            'data_end': seen_to.isoformat(timespec='microseconds') + 'Z',
            # To the microsecond, as the database keeps them: Open in Messages asks for exactly this span
            'around': {'from': around_from.isoformat(timespec='microseconds') + 'Z', 'to': around_to.isoformat(timespec='microseconds') + 'Z',
                       'total': len(near), **around},
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error building the activity of an alert: {e}")
        raise internal_error(e)
