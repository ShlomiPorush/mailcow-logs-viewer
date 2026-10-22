"""The trends of the dashboard figures (services/figures.py): their hourly samples."""
import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import MetricSnapshot
from ..services.figures import METRICS, metric_on
from ..utils import internal_error

logger = logging.getLogger(__name__)

router = APIRouter()

MAX_NAMES = 10


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds") + "Z"


@router.get("/stats/trends")
def get_trends(
    names: str = Query(..., max_length=400, description="Comma-separated trend names"),
    days: int = Query(7, ge=1, le=90),
    db: Session = Depends(get_db),
):
    """The hourly samples of the named trends over the last days: { name: [{slot, value, of, as_of}] },
    oldest first, a missing hour left out (a gap). A trend of a feature that is off is not served."""
    wanted = list(dict.fromkeys(n.strip() for n in names.split(",") if n.strip()))
    if not wanted or len(wanted) > MAX_NAMES:
        raise HTTPException(status_code=422, detail=f"Give 1 to {MAX_NAMES} trend names")
    unknown = [n for n in wanted if n not in METRICS]
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown trend: {unknown[0][:40]}")
    served = [n for n in wanted if metric_on(n)]
    try:
        since = datetime.utcnow() - timedelta(days=days)
        rows = db.query(MetricSnapshot.name, MetricSnapshot.slot, MetricSnapshot.value, MetricSnapshot.of, MetricSnapshot.as_of).filter(
            MetricSnapshot.name.in_(served), MetricSnapshot.slot >= since,
        ).order_by(MetricSnapshot.slot).all() if served else []
        out = {n: [] for n in served}
        for name, slot, value, of, as_of in rows:
            out[name].append({"slot": _iso(slot), "value": value, "of": of, "as_of": _iso(as_of)})
        return {"days": days, "trends": out}
    except Exception as e:
        logger.error(f"Error reading trends: {e}")
        raise internal_error(e)
