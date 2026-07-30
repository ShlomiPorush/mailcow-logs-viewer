"""
SMTP abuse protection - enforcement layer.

Where anomaly detection *alerts* on a mailbox sending far above its own
baseline, this module *acts*: when a mailbox crosses a hard outbound ceiling
it disables SMTP for that mailbox via the mailcow API (IMAP stays up, so the
user keeps their mail), optionally revokes its app passwords, records the
action, raises a SecurityAlert, and notifies both the operator and the user.

Detection alerts never act on their own; this module is the enforcement
path, sharing the alerting and notification layer with anomaly detection.

Async functions touch the mailcow API; every database access is a plain sync
helper executed through ``asyncio.to_thread`` so the event loop never blocks.
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import func

from ..config import settings
from ..database import get_db_context
from ..mailcow_api import mailcow_api
from ..models import (
    MessageCorrelation,
    SecurityAlert,
    SMTPAbuseAction,
    SMTPAbuseWhitelist,
)

logger = logging.getLogger(__name__)


def normalize(email: str) -> str:
    return (email or "").strip().lower()


# ── sync DB helpers (run via asyncio.to_thread from async callers) ──────────

def fetch_outbound_counts(window_minutes: int, limit: Optional[int] = None) -> Dict[str, int]:
    """Outbound message count per sender within the rolling window.

    Grouped on lower(sender) so 'User@x' and 'user@x' are one mailbox - the
    same normalisation used everywhere else for addresses.
    """
    cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
    with get_db_context() as db:
        q = db.query(
            func.lower(MessageCorrelation.sender).label("email"),
            func.count(MessageCorrelation.id).label("count"),
        ).filter(
            func.lower(MessageCorrelation.direction) == "outbound",
            MessageCorrelation.first_seen >= cutoff,
            MessageCorrelation.sender.isnot(None),
            MessageCorrelation.sender != "",
        ).group_by(func.lower(MessageCorrelation.sender)).order_by(
            func.count(MessageCorrelation.id).desc()
        )
        if limit:
            q = q.limit(limit)
        return {row.email: int(row.count) for row in q.all()}


def fetch_whitelist(active_only: bool = True) -> List[Dict]:
    with get_db_context() as db:
        q = db.query(SMTPAbuseWhitelist)
        if active_only:
            q = q.filter(SMTPAbuseWhitelist.active.is_(True))
        return [
            {"email": r.email, "notes": r.notes, "active": r.active}
            for r in q.order_by(SMTPAbuseWhitelist.email).all()
        ]


def fetch_latest_actions() -> Dict[str, Dict]:
    """Most recent action per mailbox - this is the current block state."""
    with get_db_context() as db:
        latest = db.query(
            SMTPAbuseAction.email.label("email"),
            func.max(SMTPAbuseAction.created_at).label("ts"),
        ).group_by(SMTPAbuseAction.email).subquery()

        rows = db.query(SMTPAbuseAction).join(
            latest,
            (SMTPAbuseAction.email == latest.c.email)
            & (SMTPAbuseAction.created_at == latest.c.ts),
        ).all()
        return {
            normalize(r.email): {
                "action": r.action,
                "created_at": r.created_at,
                "automatic": r.automatic,
                "operator": r.operator,
                "message_count": r.message_count,
            }
            for r in rows
        }


def record_action(email: str, count: int, action: str, automatic: bool,
                  operator: str, app_passwords_revoked: int = 0) -> None:
    with get_db_context() as db:
        db.add(SMTPAbuseAction(
            email=normalize(email),
            message_count=count,
            threshold=settings.smtp_abuse_threshold,
            window_minutes=settings.smtp_abuse_window_minutes,
            action=action,
            automatic=automatic,
            operator=operator,
            app_passwords_revoked=app_passwords_revoked,
            created_at=datetime.utcnow(),
        ))
        db.commit()


def record_security_alert(email: str, count: int, revoked: int, automatic: bool) -> None:
    """Surface the block in the same dashboard feed as anomaly detection."""
    detail = (
        f"SMTP sending was disabled for {email} after {count} outbound messages "
        f"in {settings.smtp_abuse_window_minutes} minutes "
        f"(limit: {settings.smtp_abuse_threshold}).\n\n"
        f"IMAP access is unchanged. App passwords revoked: {revoked}.\n"
        "Review the mailbox, reset its password, then re-enable SMTP from "
        "Security → Abuse Protection."
    )
    with get_db_context() as db:
        db.add(SecurityAlert(
            alert_type="smtp_abuse_block",
            severity="critical",
            subject=normalize(email),
            title=f"SMTP disabled (abuse protection): {email}",
            detail=detail,
            metric_value=float(count),
            baseline_value=float(settings.smtp_abuse_threshold),
            created_at=datetime.utcnow(),
        ))
        db.commit()


def set_whitelist(emails: List[str]) -> List[str]:
    """Replace the active whitelist with exactly this set (rows are kept and
    deactivated rather than deleted, so notes survive a round-trip)."""
    wanted = {normalize(e) for e in emails if normalize(e)}
    with get_db_context() as db:
        existing = {r.email: r for r in db.query(SMTPAbuseWhitelist).all()}
        for email, row in existing.items():
            row.active = email in wanted
        for email in wanted - set(existing):
            db.add(SMTPAbuseWhitelist(email=email, active=True))
        db.commit()
    return sorted(wanted)


def upsert_whitelist_entry(email: str, notes: Optional[str]) -> None:
    email = normalize(email)
    with get_db_context() as db:
        row = db.query(SMTPAbuseWhitelist).filter(SMTPAbuseWhitelist.email == email).first()
        if row:
            row.active = True
            row.notes = notes
        else:
            db.add(SMTPAbuseWhitelist(email=email, notes=notes, active=True))
        db.commit()


def deactivate_whitelist_entry(email: str) -> bool:
    email = normalize(email)
    with get_db_context() as db:
        row = db.query(SMTPAbuseWhitelist).filter(SMTPAbuseWhitelist.email == email).first()
        if not row:
            return False
        row.active = False
        db.commit()
        return True


# ── enforcement decisions ──────────────────────────────────────────────────

def in_unblock_grace(latest: Optional[Dict]) -> bool:
    """True if an operator re-enabled SMTP recently.

    Without this, re-enabling a mailbox while its rolling count is still above
    the threshold gets undone by the very next job run - the operator's action
    would appear to do nothing.
    """
    if not latest or latest.get("action") != "unblocked":
        return False
    grace = settings.smtp_abuse_unblock_grace_minutes
    if grace <= 0:
        return False
    unblocked_at = latest.get("created_at")
    if not unblocked_at:
        return False
    return datetime.utcnow() - unblocked_at < timedelta(minutes=grace)


def find_candidates() -> List[Dict]:
    """Mailboxes that should be auto-blocked right now (sync; DB only)."""
    counts = fetch_outbound_counts(settings.smtp_abuse_window_minutes)
    whitelist = {e["email"] for e in fetch_whitelist()}
    latest_actions = fetch_latest_actions()

    candidates = []
    for email, count in counts.items():
        if count <= settings.smtp_abuse_threshold:
            continue
        if email in whitelist:
            continue
        latest = latest_actions.get(email)
        if latest and latest.get("action") == "blocked":
            continue  # already blocked
        if in_unblock_grace(latest):
            logger.info("[SMTP ABUSE] %s is over the limit but was recently "
                        "re-enabled by an operator - skipping (grace period)", email)
            continue
        candidates.append({"email": email, "count": count})
    return candidates


# ── async actions (mailcow API) ────────────────────────────────────────────

async def _revoke_app_passwords(email: str) -> int:
    entries = await mailcow_api.get_app_passwords(email)
    ids = [str(e["id"]) for e in entries
           if isinstance(e, dict) and e.get("id") is not None]
    if ids:
        await mailcow_api.delete_app_passwords(ids)
    return len(ids)


async def _notify_user_blocked(email: str, count: int) -> None:
    """Tell the mailbox owner their SMTP was disabled (best effort)."""
    if not settings.notification_smtp_configured:
        logger.info("SMTP not configured - skipping user notification for %s", email)
        return
    from .smtp_service import send_notification_email

    subject = "Security alert: outgoing mail has been paused for your account"
    contact = settings.smtp_abuse_help_address or settings.admin_email or "your administrator"
    text = (
        f"Sending has been temporarily disabled for {email}.\n\n"
        f"We detected {count} outgoing messages in the last "
        f"{settings.smtp_abuse_window_minutes} minutes, above the limit of "
        f"{settings.smtp_abuse_threshold}. This usually means the account is "
        "compromised.\n\n"
        "You can still receive and read mail (IMAP is unaffected).\n\n"
        "Please change your password and revoke any app passwords you no "
        f"longer use, then contact {contact} to restore sending."
    )
    html = text.replace("\n", "<br>")
    await asyncio.to_thread(send_notification_email, email, subject, text, html)


def _ensure_mailcow_success(email: str, response, action: str) -> None:
    """mailcow answers HTTP 200 even for logical failures (items with
    type "danger", e.g. when the address is an alias, not a mailbox). The
    action must not be recorded as done when nothing actually changed -
    an unrecorded failure is retried on the next run."""
    items = response if isinstance(response, list) else [response] if isinstance(response, dict) else []
    for item in items:
        if isinstance(item, dict) and item.get("type") == "danger":
            raise RuntimeError(f"mailcow rejected {action} for {email}: {item.get('msg')}")


async def _notify_operator_blocked(email: str, count: int, revoked: int) -> None:
    """Alert the operator through every configured channel (email + webhook)."""
    from .notification_service import notify

    subject = f"[Security] SMTP disabled (abuse protection): {email}"
    text = (
        f"{email} sent {count} outbound messages in "
        f"{settings.smtp_abuse_window_minutes} minutes "
        f"(limit: {settings.smtp_abuse_threshold}).\n\n"
        f"SMTP has been disabled for this mailbox. App passwords revoked: {revoked}.\n"
        "IMAP access is unchanged. Re-enable from Security → Abuse Protection "
        "after securing the account."
    )
    await asyncio.to_thread(notify, subject, text, None, None, "security")


async def block_mailbox(email: str, count: int, automatic: bool = False,
                        operator: str = "system") -> Dict:
    """Disable SMTP for a mailbox, record it, alert, and notify."""
    email = normalize(email)

    # 1. The actual enforcement - everything else is best effort around it
    response = await mailcow_api.edit_mailbox(email, {"smtp_access": "0"})
    _ensure_mailcow_success(email, response, "disable SMTP")

    # 2. A compromised mailbox usually sends via an app password
    revoked = 0
    if settings.smtp_abuse_revoke_app_passwords:
        try:
            revoked = await _revoke_app_passwords(email)
        except Exception as e:
            logger.error("Could not revoke app passwords for %s: %s", email, e)

    # 3. Audit trail + dashboard alert
    await asyncio.to_thread(record_action, email, count, "blocked", automatic, operator, revoked)
    try:
        await asyncio.to_thread(record_security_alert, email, count, revoked, automatic)
    except Exception as e:
        logger.error("Could not record security alert for %s: %s", email, e)

    # 4. Notifications (operator + the affected user)
    try:
        await _notify_operator_blocked(email, count, revoked)
    except Exception as e:
        logger.error("Could not notify operator about %s: %s", email, e)
    try:
        await _notify_user_blocked(email, count)
    except Exception as e:
        logger.error("Could not notify %s: %s", email, e)

    logger.warning("[SMTP ABUSE] SMTP disabled for %s (%s messages, %s app passwords revoked)",
                   email, count, revoked)
    return {
        "email": email,
        "smtp_access": False,
        "app_passwords_revoked": revoked,
        "message_count": count,
    }


async def unblock_mailbox(email: str, operator: str = "manual") -> Dict:
    """Re-enable SMTP. Starts the grace period that prevents an immediate
    automatic re-block while the rolling window still holds old messages."""
    email = normalize(email)
    response = await mailcow_api.edit_mailbox(email, {"smtp_access": "1"})
    _ensure_mailcow_success(email, response, "re-enable SMTP")
    await asyncio.to_thread(record_action, email, 0, "unblocked", False, operator, 0)
    logger.info("[SMTP ABUSE] SMTP re-enabled for %s by %s (grace: %s min)",
                email, operator, settings.smtp_abuse_unblock_grace_minutes)
    return {"email": email, "smtp_access": True}


async def run_abuse_protection() -> Dict:
    """Scheduler entry point: block everything currently over the limit."""
    if not settings.smtp_abuse_enabled:
        return {"status": "disabled"}
    if not mailcow_api.has_rw_key:
        logger.warning("[SMTP ABUSE] Enabled but no Read-Write mailcow API key - skipping")
        return {"status": "no_rw_key"}

    candidates = await asyncio.to_thread(find_candidates)
    blocked = []
    for candidate in candidates:
        try:
            await block_mailbox(candidate["email"], candidate["count"],
                                automatic=True, operator="smtp-abuse")
            blocked.append(candidate["email"])
        except Exception as e:
            logger.error("[SMTP ABUSE] Failed to block %s: %s", candidate["email"], e)
    return {"status": "ok", "blocked": blocked, "checked": len(candidates)}
