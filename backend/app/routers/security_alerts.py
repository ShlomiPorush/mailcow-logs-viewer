"""
Security Alerts API - anomaly-detection findings (compromised mailbox /
auth attack) surfaced on the dashboard.
"""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import SecurityAlert
from ..config import settings
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
