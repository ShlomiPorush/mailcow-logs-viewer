"""
SMTP Abuse Protection API - status, whitelist management, manual controls.

Endpoints that only touch the database are plain ``def`` (FastAPI runs them in
its threadpool); endpoints that call the mailcow API are ``async`` and keep
their database work in worker threads. See services/smtp_abuse_service.py for
the logic.
"""
import asyncio
import logging
import re
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from ..config import settings
from ..mailcow_api import mailcow_api
from ..services import smtp_abuse_service as svc
from ..utils import internal_error

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/smtp-abuse")

# Bounded quantifiers keep the match linear: the original
# ^[^@\s]+@[^@\s]+\.[^@\s]+$ let the two + classes overlap on the dot, so a
# long non-matching local part backtracked quadratically and stalled the event
# loop. The lengths follow RFC 5321 (64-octet local part, 63-octet labels).
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s.]{1,63}(?:\.[^@\s.]{1,63})+$")

# RFC 5321 caps a path at 256 octets; reject longer input before matching.
_MAX_EMAIL_LENGTH = 254

# Upper bound on a bulk whitelist replace, so one request cannot pin a worker.
_MAX_WHITELIST_ENTRIES = 5000


def is_valid_email(value: str) -> bool:
    """Length-capped email syntax check (single source of truth for the API)."""
    return len(value) <= _MAX_EMAIL_LENGTH and _EMAIL_RE.match(value) is not None


class WhitelistRequest(BaseModel):
    email: str
    notes: Optional[str] = None

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        value = (value or "").strip().lower()
        if not is_valid_email(value):
            raise ValueError("Invalid email format")
        return value


class WhitelistBulkRequest(BaseModel):
    emails: List[str] = Field(default_factory=list)


def require_control_access() -> None:
    """Write operations need the feature on and a Read-Write mailcow key."""
    if not settings.smtp_abuse_enabled:
        raise HTTPException(status_code=403, detail="SMTP abuse protection is disabled")
    if not mailcow_api.has_rw_key:
        raise HTTPException(status_code=503, detail="MAILCOW_API_KEY_RW is required")


@router.get("/status")
async def get_status(limit: int = Query(200, ge=1, le=1000)):
    """Current outbound activity, block states and whitelist."""
    try:
        # SMTP access state per mailbox (best effort - the panel still works
        # without it, just without the open/closed column)
        mailbox_access = {}
        try:
            for mailbox in await mailcow_api.get_mailboxes():
                address = mailbox.get("username")
                if not address:
                    continue
                # Some mailcow versions nest the flags under `attributes`
                attributes = mailbox.get("attributes") or {}
                access = mailbox.get("smtp_access", attributes.get("smtp_access", 1))
                mailbox_access[svc.normalize(address)] = not (
                    access is False or str(access).lower() in ("0", "false", "no")
                )
        except Exception as e:
            logger.warning("Could not load mailbox SMTP access states: %s", e)

        counts = await asyncio.to_thread(
            svc.fetch_outbound_counts, settings.smtp_abuse_window_minutes, limit
        )
        whitelist_entries = await asyncio.to_thread(svc.fetch_whitelist)
        latest_actions = await asyncio.to_thread(svc.fetch_latest_actions)

        whitelist = {e["email"] for e in whitelist_entries}
        # Only mailboxes THIS system blocked count as abuse cases - an
        # incoming-only mailbox (e.g. a DMARC report inbox) also has SMTP off.
        blocked_by_us = {
            email for email, a in latest_actions.items() if a.get("action") == "blocked"
        }

        emails = set(counts) | blocked_by_us
        mailboxes = []
        for email in emails:
            count = counts.get(email, 0)
            smtp_open = mailbox_access.get(email, True)
            # Hide mailboxes that simply have SMTP disabled by configuration
            if not smtp_open and email not in blocked_by_us:
                continue
            mailboxes.append({
                "email": email,
                "message_count": count,
                "outbound_count": count,
                "over_threshold": count > settings.smtp_abuse_threshold,
                "whitelisted": email in whitelist,
                "smtp_access": smtp_open,
                "blocked_by_protection": email in blocked_by_us,
            })
        mailboxes.sort(key=lambda m: m["message_count"], reverse=True)

        return {
            "enabled": settings.smtp_abuse_enabled,
            "rw_key_configured": mailcow_api.has_rw_key,
            "threshold": settings.smtp_abuse_threshold,
            "window_minutes": settings.smtp_abuse_window_minutes,
            "unblock_grace_minutes": settings.smtp_abuse_unblock_grace_minutes,
            "mailboxes": mailboxes,
            "whitelist": sorted(whitelist),
        }
    except Exception as e:
        logger.error(f"Error building SMTP abuse status: {e}")
        raise internal_error(e)


@router.get("/whitelist")
def get_whitelist():
    """Active whitelist entries."""
    try:
        return svc.fetch_whitelist()
    except Exception as e:
        logger.error(f"Error fetching SMTP abuse whitelist: {e}")
        raise internal_error(e)


@router.post("/whitelist")
def add_whitelist(request: WhitelistRequest):
    """Add (or re-activate) a single whitelist entry."""
    require_control_access()
    try:
        svc.upsert_whitelist_entry(request.email, request.notes)
        return {"email": request.email, "active": True}
    except Exception as e:
        logger.error(f"Error adding whitelist entry: {e}")
        raise internal_error(e)


@router.put("/whitelist")
def replace_whitelist(request: WhitelistBulkRequest):
    """Replace the whole whitelist (one address per line in the UI)."""
    require_control_access()
    if len(request.emails) > _MAX_WHITELIST_ENTRIES:
        raise HTTPException(
            status_code=422,
            detail=f"Too many entries: the whitelist holds at most {_MAX_WHITELIST_ENTRIES} addresses",
        )
    emails = []
    for value in request.emails:
        email = (value or "").strip().lower()
        if not email:
            continue
        if not is_valid_email(email):
            raise HTTPException(status_code=422, detail=f"Invalid email format: {value}")
        emails.append(email)
    try:
        active = svc.set_whitelist(emails)
        return {"active": active, "count": len(active)}
    except Exception as e:
        logger.error(f"Error saving whitelist: {e}")
        raise internal_error(e)


@router.delete("/whitelist/{email}")
def remove_whitelist(email: str):
    """Deactivate a whitelist entry."""
    require_control_access()
    try:
        if not svc.deactivate_whitelist_entry(email):
            raise HTTPException(status_code=404, detail="Email is not on the whitelist")
        return {"email": svc.normalize(email), "active": False}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing whitelist entry: {e}")
        raise internal_error(e)


@router.post("/mailboxes/{email}/block")
async def manual_block(email: str):
    """Disable SMTP for a mailbox now."""
    require_control_access()
    try:
        counts = await asyncio.to_thread(
            svc.fetch_outbound_counts, settings.smtp_abuse_window_minutes
        )
        count = counts.get(svc.normalize(email), 0)
        return await svc.block_mailbox(email, count, automatic=False, operator="manual")
    except Exception as e:
        logger.error(f"Error blocking mailbox {email}: {e}")
        raise internal_error(e)


@router.post("/mailboxes/{email}/unblock")
async def manual_unblock(email: str):
    """Re-enable SMTP for a mailbox (starts the auto-block grace period)."""
    require_control_access()
    try:
        return await svc.unblock_mailbox(email, operator="manual")
    except Exception as e:
        logger.error(f"Error unblocking mailbox {email}: {e}")
        raise internal_error(e)


@router.get("/history")
def get_history(limit: int = Query(50, ge=1, le=500)):
    """Recent block/unblock actions (audit trail)."""
    from ..database import get_db_context
    from ..models import SMTPAbuseAction
    from ..utils import format_datetime_for_api
    try:
        with get_db_context() as db:
            rows = db.query(SMTPAbuseAction).order_by(
                SMTPAbuseAction.created_at.desc()
            ).limit(limit).all()
            return [{
                "email": r.email,
                "action": r.action,
                "message_count": r.message_count,
                "threshold": r.threshold,
                "window_minutes": r.window_minutes,
                "automatic": r.automatic,
                "operator": r.operator,
                "app_passwords_revoked": r.app_passwords_revoked,
                "created_at": format_datetime_for_api(r.created_at),
            } for r in rows]
    except Exception as e:
        logger.error(f"Error fetching SMTP abuse history: {e}")
        raise internal_error(e)
