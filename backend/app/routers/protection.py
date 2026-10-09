"""
Protection rules API: the rules the admin manages on the Security page, and the
addresses they caught. Ban now and Undo write to the Fail2ban blacklist; both
wait for a rules run in progress so the two never write at once.
"""
import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..mailcow_api import mailcow_api
from ..models import NetfilterLog, ProtectionHit
from ..services import geoip_service
from ..services import protection_rules as rules_service
from ..services import security_addresses

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/protection")


_hit = rules_service.hit_dict


def _capabilities() -> dict:
    """What the rules can do on this install; the page locks what is missing."""
    return {
        "can_ban": bool(mailcow_api.has_rw_key),
        "geoip": bool(geoip_service.is_geoip_available()),
        "raw_logs": "dovecot" in settings.raw_logs_collected_list,
    }


def _country_suggestions(db: Session) -> list:
    """The countries failed logins came from in the last week, most first."""
    since = datetime.utcnow() - timedelta(days=7)
    rows = db.query(NetfilterLog.country_code, func.max(NetfilterLog.country_name), func.count(NetfilterLog.id)).filter(
        NetfilterLog.time >= since, NetfilterLog.country_code.isnot(None)
    ).group_by(NetfilterLog.country_code).order_by(func.count(NetfilterLog.id).desc()).limit(12).all()
    return [{"code": code.upper(), "name": name or code.upper(), "tries": tries} for code, name, tries in rows if code]


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
    return {"rules": rules_service.load_rules(db), "trap_suggestions": _trap_suggestions(db),
            "country_suggestions": _country_suggestions(db), "capabilities": _capabilities()}


@router.put("/rules")
def put_rules(payload: dict = Body(...), db: Session = Depends(get_db)):
    try:
        return {"rules": rules_service.save_rules(db, payload.get("rules") or {}, can_ban=bool(mailcow_api.has_rw_key))}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


STATUS_GROUPS = {
    "active": rules_service.OPEN_STATUSES,
    "history": rules_service.CLOSED_STATUSES,
    "watching": ("watching",),
    "dismissed": ("dismissed",),
}


@router.get("/hits")
def get_hits(status: str = Query("active", pattern="^(active|history|watching|dismissed|all)$"),
             limit: int = Query(200, ge=1, le=1000), db: Session = Depends(get_db)):
    query = db.query(ProtectionHit)
    if status != "all":
        query = query.filter(ProtectionHit.status.in_(STATUS_GROUPS[status]))
    order = ProtectionHit.ended_at.desc() if status == "history" else ProtectionHit.last_seen.desc()
    hits = query.order_by(order).limit(limit).all()
    counts = dict(db.query(ProtectionHit.status, func.count(ProtectionHit.id)).group_by(ProtectionHit.status).all())
    return {"hits": [_hit(h) for h in hits], "counts": counts}


def _get_or_404(db: Session, hit_id: int) -> ProtectionHit:
    hit = db.query(ProtectionHit).filter(ProtectionHit.id == hit_id).first()
    if not hit:
        raise HTTPException(status_code=404, detail="Not found")
    return hit


@router.post("/hits/{hit_id}/dismiss")
def dismiss_hit(hit_id: int, db: Session = Depends(get_db)):
    hit = _get_or_404(db, hit_id)
    if hit.status in ("watching", "alert"):
        hit.status = "dismissed"
        hit.ended_at = datetime.utcnow()
        db.commit()
        security_addresses.forget()
        logger.info("Protection hit dismissed: %s (%s)", hit.ip, hit.rule)
    return _hit(hit)


@router.post("/hits/{hit_id}/ban")
async def ban_hit(hit_id: int, db: Session = Depends(get_db)):
    """Ban an address a watching rule caught, now."""
    from ..scheduler import _protection_lock
    hit = _get_or_404(db, hit_id)
    if hit.rule not in rules_service.BAN_RULES:
        raise HTTPException(status_code=400, detail="This rule only alerts; it does not ban")
    if not mailcow_api.has_rw_key:
        raise HTTPException(status_code=400, detail="Banning needs the Read-Write API key (MAILCOW_API_KEY_RW)")
    if hit.status != "watching":
        raise HTTPException(status_code=409, detail="Only a hit that is being watched can be banned")
    async with _protection_lock:
        rules_service.request_ban(db, hit_id)
        await rules_service.enforce(mailcow_api)
    db.expire_all()
    security_addresses.forget()
    hit = _get_or_404(db, hit_id)
    if hit.status != "banned":
        raise HTTPException(status_code=502, detail=hit.error or "The ban could not be written to mailcow; the next run tries again")
    logger.info("Protection hit banned by the admin: %s (%s)", hit.ip, hit.rule)
    return _hit(hit)


@router.post("/hits/{hit_id}/undo")
async def undo_hit(hit_id: int, db: Session = Depends(get_db)):
    """Lift a ban (or cancel a pending one); the rule leaves the address alone for a week."""
    from ..scheduler import _protection_lock
    hit = _get_or_404(db, hit_id)
    if hit.status not in ("banned", "pending"):
        raise HTTPException(status_code=409, detail="Only a ban can be undone")
    if hit.status == "banned" and hit.owned and not mailcow_api.has_rw_key:
        raise HTTPException(status_code=400, detail="Lifting a ban needs the Read-Write API key (MAILCOW_API_KEY_RW)")
    async with _protection_lock:
        try:
            done = await rules_service.undo(mailcow_api, hit_id)
        except RuntimeError as e:
            raise HTTPException(status_code=502, detail=str(e))
        finally:
            security_addresses.forget()
    return _hit(done)
