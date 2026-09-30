"""
Protection rules API: the rules the admin manages on the Security page, and the
addresses they caught. Watch mode only: nothing here writes to Fail2ban.
"""
import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import NetfilterLog, ProtectionHit
from ..services import protection_rules as rules_service
from ..utils import format_datetime_for_api as format_datetime_utc

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/protection")


def _hit(hit: ProtectionHit) -> dict:
    return {
        "id": hit.id,
        "ip": hit.ip,
        "rule": hit.rule,
        "mode": hit.mode,
        "status": hit.status,
        "reason": hit.reason,
        "usernames": hit.usernames or [],
        "attempts": hit.attempts or 0,
        "country_code": hit.country_code,
        "country_name": hit.country_name,
        "first_seen": format_datetime_utc(hit.first_seen),
        "last_seen": format_datetime_utc(hit.last_seen),
        "ended_at": format_datetime_utc(hit.ended_at),
    }


def _trap_suggestions(db: Session) -> list:
    """Account names tried in the last week that do not exist: good trap candidates."""
    known, catch_all = rules_service._known_accounts(db)
    since = datetime.utcnow() - timedelta(days=7)
    rows = db.query(NetfilterLog.username, func.count(NetfilterLog.id), func.count(func.distinct(NetfilterLog.ip))).filter(
        NetfilterLog.time >= since, NetfilterLog.username.isnot(None)
    ).group_by(NetfilterLog.username).order_by(func.count(NetfilterLog.id).desc()).limit(200).all()
    local_parts = {address.split("@", 1)[0] for address in known}
    out = []
    for username, tries, addresses in rows:
        name = (username or "").strip().lower()
        if not name or not rules_service._is_unknown(name, known, catch_all):
            continue
        # A bare name that is a real local part would ban real users; never suggest it
        if "@" not in name and name in local_parts:
            continue
        out.append({"name": name, "tries": tries, "addresses": addresses})
        if len(out) >= 12:
            break
    return out


@router.get("/rules")
def get_rules(db: Session = Depends(get_db)):
    return {"rules": rules_service.load_rules(db), "trap_suggestions": _trap_suggestions(db)}


@router.put("/rules")
def put_rules(payload: dict = Body(...), db: Session = Depends(get_db)):
    try:
        return {"rules": rules_service.save_rules(db, payload.get("rules") or {})}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/hits")
def get_hits(status: str = Query("watching", pattern="^(watching|dismissed|all)$"),
             limit: int = Query(200, ge=1, le=1000), db: Session = Depends(get_db)):
    query = db.query(ProtectionHit)
    if status != "all":
        query = query.filter(ProtectionHit.status == status)
    hits = query.order_by(ProtectionHit.last_seen.desc()).limit(limit).all()
    counts = dict(db.query(ProtectionHit.status, func.count(ProtectionHit.id)).group_by(ProtectionHit.status).all())
    return {"hits": [_hit(h) for h in hits], "counts": counts}


@router.post("/hits/{hit_id}/dismiss")
def dismiss_hit(hit_id: int, db: Session = Depends(get_db)):
    hit = db.query(ProtectionHit).filter(ProtectionHit.id == hit_id).first()
    if not hit:
        raise HTTPException(status_code=404, detail="Not found")
    if hit.status == "watching":
        hit.status = "dismissed"
        hit.ended_at = datetime.utcnow()
        db.commit()
        logger.info("Protection hit dismissed: %s (%s)", hit.ip, hit.rule)
    return _hit(hit)
