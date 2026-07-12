"""
API endpoints for Spam Suppression management

Provides CRUD operations for the spam suppression list,
including auto-detection of bounced/rejected outbound emails
and syncing to Rspamd's global_rcpt_blacklist.map.
"""
import csv
import io
import re
import logging
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Depends, Query, UploadFile, File
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, desc

from ..database import get_db
from ..config import settings
from ..models import SpamSuppression
from ..mailcow_api import mailcow_api, MailcowAPIError
from ..utils import internal_error

logger = logging.getLogger(__name__)

router = APIRouter()

# Marker comment used to separate manual entries from managed ones in the Rspamd map
MANAGED_MARKER_START = "# === MANAGED BY MAILCOW LOGS VIEWER - DO NOT EDIT BELOW ==="
MANAGED_MARKER_END = "# === END MANAGED SECTION ==="


class SuppressionCreateRequest(BaseModel):
    email: str
    type: str = "email"  # 'email' or 'domain'
    reason: str = "manual"
    notes: Optional[str] = None
    permanent: bool = True  # True = never expires, False = use expires_at or auto-calculate
    expires_at: Optional[str] = None  # ISO format datetime string
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        v = v.strip().lower()
        if not v:
            raise ValueError("Email address cannot be empty")
        # Allow regex patterns (e.g., /.+@example\.com/i)
        if v.startswith('/'):
            return v
        # Basic email/domain validation
        if '@' in v:
            if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', v):
                raise ValueError("Invalid email format")
        else:
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$', v):
                raise ValueError("Invalid domain format")
        return v
    
    @field_validator('type')
    @classmethod
    def validate_type(cls, v):
        if v not in ('email', 'domain'):
            raise ValueError("Type must be 'email' or 'domain'")
        return v
    
    @field_validator('reason')
    @classmethod
    def validate_reason(cls, v):
        valid = ('hard_bounce', 'soft_bounce', 'rejected', 'manual')
        if v not in valid:
            raise ValueError(f"Reason must be one of: {', '.join(valid)}")
        return v


class SuppressionUpdateRequest(BaseModel):
    active: Optional[bool] = None
    notes: Optional[str] = None
    expires_at: Optional[str] = None  # ISO format or null


# =========================================================================
# Queue Cleanup Helper
# =========================================================================

async def _cleanup_queue_for_email(email: str):
    """
    Check the mail queue for stuck messages to the given recipient
    and delete them. Called after a suppression is created/activated.
    
    For domain suppressions (regex patterns like /.+@example\.com/i),
    matches all queue items with recipients in that domain.
    """
    if not mailcow_api.has_rw_key:
        return  # Can't delete without RW key
    
    try:
        queue = await mailcow_api.get_queue()
        if not queue:
            return
        
        # Determine matching strategy based on email type
        is_regex = email.startswith('/')
        if is_regex:
            # Extract domain from regex like /.+@example\.com/i
            import re as re_mod
            domain_match = re_mod.search(r'@([a-zA-Z0-9._\\-]+)', email)
            if domain_match:
                domain = domain_match.group(1).replace('\\', '')  # unescape dots
                match_domain = domain.lower()
            else:
                return  # Can't parse regex pattern
        else:
            match_domain = None
            match_email = email.lower()
        
        # Find queue items with matching recipients
        items_to_delete = []
        for item in queue:
            recipients = item.get('recipients', [])
            queue_id = item.get('queue_id')
            if not queue_id or not recipients:
                continue
            
            for rcpt in recipients:
                # Extract email from recipient string (strip error info)
                rcpt_email = rcpt.split(' ')[0].strip('<>').lower()
                
                if is_regex:
                    # Domain match
                    if rcpt_email.endswith('@' + match_domain):
                        items_to_delete.append(queue_id)
                        break
                else:
                    # Exact email match
                    if rcpt_email == match_email:
                        items_to_delete.append(queue_id)
                        break
        
        if items_to_delete:
            result = await mailcow_api.delete_queue(items_to_delete)
            logger.info(
                f"[SUPPRESSION] Cleaned up {len(items_to_delete)} queue item(s) "
                f"for suppressed address: {email}"
            )
    except Exception as e:
        # Queue cleanup is best-effort — don't fail the suppression
        logger.warning(f"[SUPPRESSION] Queue cleanup failed for {email}: {e}")


# =========================================================================
# CRUD Endpoints
# =========================================================================

@router.get("/suppressions")
def list_suppressions(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    search: Optional[str] = None,
    type_filter: Optional[str] = None,
    reason_filter: Optional[str] = None,
    active_filter: Optional[str] = None,
    sort_by: str = Query("created_at", regex="^(email|reason|bounce_count|created_at|expires_at)$"),
    sort_dir: str = Query("desc", regex="^(asc|desc)$"),
):
    """List all suppressions with pagination, search, and filtering."""
    query = db.query(SpamSuppression)
    
    # Filters
    if search:
        search_term = f"%{search.lower()}%"
        query = query.filter(
            or_(
                SpamSuppression.email.ilike(search_term),
                SpamSuppression.notes.ilike(search_term),
                SpamSuppression.last_bounce_message.ilike(search_term),
            )
        )
    
    if type_filter and type_filter in ('email', 'domain'):
        query = query.filter(SpamSuppression.type == type_filter)
    
    if reason_filter and reason_filter in ('hard_bounce', 'soft_bounce', 'deferred_stuck', 'rejected', 'manual'):
        query = query.filter(SpamSuppression.reason == reason_filter)
    
    if active_filter is not None:
        if active_filter == 'true':
            query = query.filter(SpamSuppression.active == True)
        elif active_filter == 'false':
            query = query.filter(SpamSuppression.active == False)
        elif active_filter == 'expired':
            query = query.filter(
                SpamSuppression.active == False,
                SpamSuppression.expires_at.isnot(None),
                SpamSuppression.expires_at < datetime.utcnow()
            )
    
    # Total count before pagination
    total = query.count()
    
    # Sort
    sort_col = getattr(SpamSuppression, sort_by, SpamSuppression.created_at)
    if sort_dir == "desc":
        query = query.order_by(desc(sort_col))
    else:
        query = query.order_by(sort_col)
    
    # Paginate
    offset = (page - 1) * per_page
    items = query.offset(offset).limit(per_page).all()
    
    now = datetime.utcnow()
    return {
        "items": [_serialize_suppression(s, now) for s in items],
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page,
    }


@router.get("/suppressions/stats")
def get_suppression_stats(db: Session = Depends(get_db)):
    """Get suppression statistics."""
    now = datetime.utcnow()
    
    total = db.query(func.count(SpamSuppression.id)).scalar() or 0
    active = db.query(func.count(SpamSuppression.id)).filter(SpamSuppression.active == True).scalar() or 0
    
    hard_bounce = db.query(func.count(SpamSuppression.id)).filter(
        SpamSuppression.reason == 'hard_bounce', SpamSuppression.active == True
    ).scalar() or 0
    
    soft_bounce = db.query(func.count(SpamSuppression.id)).filter(
        SpamSuppression.reason == 'soft_bounce', SpamSuppression.active == True
    ).scalar() or 0
    
    rejected = db.query(func.count(SpamSuppression.id)).filter(
        SpamSuppression.reason == 'rejected', SpamSuppression.active == True
    ).scalar() or 0
    
    manual = db.query(func.count(SpamSuppression.id)).filter(
        SpamSuppression.reason == 'manual', SpamSuppression.active == True
    ).scalar() or 0
    
    pending_sync = db.query(func.count(SpamSuppression.id)).filter(
        SpamSuppression.active == True,
        SpamSuppression.synced_to_rspamd == False
    ).scalar() or 0
    
    expired = db.query(func.count(SpamSuppression.id)).filter(
        SpamSuppression.active == False,
        SpamSuppression.expires_at.isnot(None),
        SpamSuppression.expires_at < now
    ).scalar() or 0
    
    auto_detected = db.query(func.count(SpamSuppression.id)).filter(
        SpamSuppression.source == 'auto'
    ).scalar() or 0
    
    return {
        "total": total,
        "active": active,
        "expired": expired,
        "hard_bounce": hard_bounce,
        "soft_bounce": soft_bounce,
        "rejected": rejected,
        "manual": manual,
        "pending_sync": pending_sync,
        "auto_detected": auto_detected,
    }


@router.get("/suppressions/config")
def get_suppression_config():
    """Get suppression feature configuration."""
    return {
        "suppression_enabled": settings.suppression_enabled,
        "suppression_auto_detect": settings.suppression_auto_detect,
        "suppression_rspamd_sync": settings.suppression_rspamd_sync,
        "suppression_whitelist_domains": settings.suppression_whitelist_domains,
        "suppression_hard_bounce_action": settings.suppression_hard_bounce_action,
        "suppression_soft_bounce_action": settings.suppression_soft_bounce_action,
        "suppression_soft_bounce_threshold": settings.suppression_soft_bounce_threshold,
        "suppression_base_expiry_days": settings.suppression_base_expiry_days,
        "suppression_max_expiry_days": settings.suppression_max_expiry_days,
        "rspamd_configured": settings.is_rspamd_configured,
        "rw_key_configured": mailcow_api.has_rw_key,
        "is_fully_configured": settings.is_suppression_configured,
    }


@router.post("/suppressions")
async def create_suppression(body: SuppressionCreateRequest, db: Session = Depends(get_db)):
    """Add a manual suppression entry."""
    # Check for duplicate
    existing = db.query(SpamSuppression).filter(
        SpamSuppression.email == body.email
    ).first()
    
    if existing:
        if existing.active:
            raise HTTPException(status_code=409, detail=f"Address '{body.email}' is already suppressed")
        else:
            # Reactivate expired entry
            existing.active = True
            existing.reason = body.reason
            existing.source = 'manual'
            existing.notes = body.notes
            existing.bounce_count += 1
            existing.synced_to_rspamd = False
            existing.expires_at = None  # Manual entries don't expire
            existing.updated_at = datetime.utcnow()
            db.commit()
            db.refresh(existing)
            
            # Clean up queue items for this address
            await _cleanup_queue_for_email(body.email)
            
            return _serialize_suppression(existing, datetime.utcnow())
    
    # Determine expiry
    expires_at_val = None
    if not body.permanent:
        if body.expires_at:
            try:
                expires_at_val = datetime.fromisoformat(body.expires_at.replace('Z', '+00:00'))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid date format for expires_at")
        else:
            # Default: base_expiry_days from settings
            expires_at_val = datetime.utcnow() + timedelta(days=settings.suppression_base_expiry_days)
    
    suppression = SpamSuppression(
        email=body.email,
        type=body.type,
        reason=body.reason,
        source='manual',
        notes=body.notes,
        bounce_count=1 if body.reason != 'manual' else 0,
        hard_bounce_count=0,
        soft_bounce_count=0,
        active=True,
        synced_to_rspamd=False,
        expires_at=expires_at_val,
    )
    db.add(suppression)
    db.commit()
    db.refresh(suppression)
    
    # Clean up queue items for this address
    await _cleanup_queue_for_email(body.email)
    
    return _serialize_suppression(suppression, datetime.utcnow())


@router.put("/suppressions/{suppression_id}")
def update_suppression(suppression_id: int, body: SuppressionUpdateRequest, db: Session = Depends(get_db)):
    """Update a suppression entry (toggle active, edit notes, change expiry)."""
    suppression = db.query(SpamSuppression).filter(SpamSuppression.id == suppression_id).first()
    if not suppression:
        raise HTTPException(status_code=404, detail="Suppression not found")
    
    if body.active is not None:
        suppression.active = body.active
        suppression.synced_to_rspamd = False  # needs re-sync
    
    if body.notes is not None:
        suppression.notes = body.notes
    
    if body.expires_at is not None:
        if body.expires_at == "" or body.expires_at == "null":
            suppression.expires_at = None
        else:
            try:
                suppression.expires_at = datetime.fromisoformat(body.expires_at.replace('Z', '+00:00'))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid date format for expires_at")
    
    suppression.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(suppression)
    
    return _serialize_suppression(suppression, datetime.utcnow())


@router.delete("/suppressions/{suppression_id}")
def delete_suppression(suppression_id: int, db: Session = Depends(get_db)):
    """Permanently remove a suppression entry."""
    suppression = db.query(SpamSuppression).filter(SpamSuppression.id == suppression_id).first()
    if not suppression:
        raise HTTPException(status_code=404, detail="Suppression not found")
    
    email = suppression.email
    was_active = suppression.active
    db.delete(suppression)
    db.commit()
    
    return {
        "deleted": True,
        "email": email,
        "was_active": was_active,
        "needs_rspamd_sync": was_active,  # If was active, need to sync to remove from map
    }


# =========================================================================
# Import / Export
# =========================================================================

@router.post("/suppressions/import")
async def import_suppressions(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Bulk import suppressions from CSV file.
    CSV format: email, type (optional), reason (optional), notes (optional)
    """
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="File must be a CSV")
    
    content = await file.read()
    text = content.decode('utf-8-sig')  # handle BOM
    reader = csv.reader(io.StringIO(text))
    
    imported = 0
    skipped = 0
    errors_list = []
    
    for row_num, row in enumerate(reader, 1):
        if not row or (row_num == 1 and row[0].lower().strip() in ('email', 'address')):
            continue  # Skip header row
        
        email = row[0].strip().lower() if len(row) > 0 else ""
        entry_type = row[1].strip() if len(row) > 1 and row[1].strip() in ('email', 'domain') else 'email'
        reason = row[2].strip() if len(row) > 2 and row[2].strip() in ('hard_bounce', 'soft_bounce', 'rejected', 'manual') else 'manual'
        notes = row[3].strip() if len(row) > 3 else f"Imported from CSV"
        
        if not email:
            errors_list.append(f"Row {row_num}: empty email")
            continue
        
        # Check for duplicate
        existing = db.query(SpamSuppression).filter(SpamSuppression.email == email).first()
        if existing:
            skipped += 1
            continue
        
        try:
            suppression = SpamSuppression(
                email=email,
                type=entry_type,
                reason=reason,
                source='import',
                notes=notes,
                bounce_count=0,
                hard_bounce_count=0,
                soft_bounce_count=0,
                active=True,
                synced_to_rspamd=False,
                expires_at=None,
            )
            db.add(suppression)
            imported += 1
        except Exception as e:
            errors_list.append(f"Row {row_num}: {str(e)}")
    
    db.commit()
    
    return {
        "imported": imported,
        "skipped": skipped,
        "errors": errors_list,
    }


@router.get("/suppressions/export")
def export_suppressions(db: Session = Depends(get_db)):
    """Export all suppressions as CSV."""
    suppressions = db.query(SpamSuppression).order_by(SpamSuppression.created_at).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['email', 'type', 'reason', 'source', 'notes', 'bounce_count', 
                     'hard_bounces', 'soft_bounces', 'active', 'expires_at', 'created_at'])
    
    for s in suppressions:
        writer.writerow([
            s.email, s.type, s.reason, s.source or '', s.notes or '',
            s.bounce_count, s.hard_bounce_count, s.soft_bounce_count,
            s.active, s.expires_at.isoformat() if s.expires_at else '',
            s.created_at.isoformat() if s.created_at else '',
        ])
    
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode('utf-8')),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=spam_suppressions.csv"}
    )


# =========================================================================
# Rspamd Sync
# =========================================================================

@router.post("/suppressions/sync")
async def manual_sync_to_rspamd(db: Session = Depends(get_db)):
    """
    Manually trigger sync of suppression list to Rspamd global_rcpt_blacklist.map.
    
    Strategy:
    1. Read current map via Rspamd API
    2. Preserve manual entries (above marker comment)
    3. Replace managed section with active suppressions
    4. Write via mailcow API
    """
    if not mailcow_api.has_rw_key:
        raise HTTPException(status_code=403, detail="Read-Write API key not configured")
    
    if not settings.is_rspamd_configured:
        raise HTTPException(status_code=400, detail="Rspamd password not configured")
    
    try:
        result = await sync_suppressions_to_rspamd(db)
        return result
    except MailcowAPIError as e:
        raise internal_error(e, status_code=502)
    except Exception as e:
        logger.error(f"Sync failed: {e}")
        raise internal_error(e)


async def sync_suppressions_to_rspamd(db: Session) -> dict:
    """
    Sync active suppressions to Rspamd global_rcpt_blacklist.map.
    
    Preserves manual entries above the managed marker,
    replaces the managed section with current active suppressions.
    
    Returns sync result details.
    """
    MAP_FILENAME = "global_rcpt_blacklist.map"
    
    # 1. Read current map content
    current_content = ""
    try:
        map_id = await mailcow_api.find_rspamd_map_id(MAP_FILENAME)
        if map_id is not None:
            current_content = await mailcow_api.get_rspamd_map_content(map_id)
    except MailcowAPIError as e:
        logger.warning(f"Could not read current map (proceeding with empty): {e}")
    
    # 2. Parse: extract manual entries (above any managed marker)
    # Recognizes both current and legacy marker formats to prevent
    # duplicate managed sections accumulating.
    manual_lines = []
    if current_content:
        for line in current_content.split('\n'):
            # Stop at current marker
            if MANAGED_MARKER_START in line:
                break
            # Stop at legacy marker (older format without "DO NOT EDIT BELOW")
            if '# === MANAGED BY MAILCOW LOGS VIEWER' in line:
                break
            # Stop at end marker (in case start marker was missing)
            if MANAGED_MARKER_END in line:
                break
            manual_lines.append(line)
    
    # Remove trailing blank lines from manual section
    while manual_lines and not manual_lines[-1].strip():
        manual_lines.pop()
    
    # 3. Get active suppressions from DB
    active_suppressions = db.query(SpamSuppression).filter(
        SpamSuppression.active == True
    ).order_by(SpamSuppression.email).all()
    
    # 4. Build new map content
    parts = []
    
    # Manual entries
    if manual_lines:
        parts.append('\n'.join(manual_lines))
        parts.append('')  # blank line before marker
    
    # Managed section
    now_str = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    parts.append(MANAGED_MARKER_START)
    parts.append(f"# Last sync: {now_str} | Active: {len(active_suppressions)}")
    
    for s in active_suppressions:
        parts.append(s.email)
    
    parts.append(MANAGED_MARKER_END)
    
    new_content = '\n'.join(parts)
    
    # 5. Write via mailcow API
    result = await mailcow_api.edit_rspamd_map(MAP_FILENAME, new_content)
    
    # 6. Mark all active as synced
    synced_count = 0
    for s in active_suppressions:
        if not s.synced_to_rspamd:
            s.synced_to_rspamd = True
            s.updated_at = datetime.utcnow()
            synced_count += 1
    db.commit()
    
    logger.info(f"[SUPPRESSION] Synced {len(active_suppressions)} suppressions to Rspamd ({synced_count} newly synced)")
    
    return {
        "success": True,
        "synced": len(active_suppressions),
        "newly_synced": synced_count,
        "manual_entries_preserved": len([l for l in manual_lines if l.strip() and not l.strip().startswith('#')]),
        "sync_time": now_str,
        "api_response": result,
    }


# =========================================================================
# Helpers
# =========================================================================

def _serialize_suppression(s: SpamSuppression, now: datetime) -> dict:
    """Serialize a SpamSuppression model for API response."""
    expires_in = None
    is_expired = False
    
    if s.expires_at:
        if s.expires_at <= now:
            is_expired = True
        else:
            delta = s.expires_at - now
            expires_in = {
                "days": delta.days,
                "hours": delta.seconds // 3600,
                "total_seconds": int(delta.total_seconds()),
                "human": _humanize_timedelta(delta),
            }
    
    return {
        "id": s.id,
        "email": s.email,
        "type": s.type,
        "reason": s.reason,
        "source": s.source,
        "notes": s.notes,
        "bounce_count": s.bounce_count,
        "hard_bounce_count": s.hard_bounce_count,
        "soft_bounce_count": s.soft_bounce_count,
        "last_bounce_dsn": s.last_bounce_dsn,
        "last_bounce_message": s.last_bounce_message,
        "correlation_key": s.correlation_key,
        "active": s.active,
        "synced_to_rspamd": s.synced_to_rspamd,
        "expires_at": s.expires_at.isoformat() + 'Z' if s.expires_at else None,
        "is_expired": is_expired,
        "expires_in": expires_in,
        "created_at": s.created_at.isoformat() + 'Z' if s.created_at else None,
        "updated_at": s.updated_at.isoformat() + 'Z' if s.updated_at else None,
    }


def _humanize_timedelta(delta: timedelta) -> str:
    """Convert timedelta to human-readable string."""
    days = delta.days
    if days >= 30:
        months = days // 30
        return f"{months} month{'s' if months > 1 else ''}"
    elif days >= 1:
        return f"{days} day{'s' if days > 1 else ''}"
    else:
        hours = delta.seconds // 3600
        if hours >= 1:
            return f"{hours} hour{'s' if hours > 1 else ''}"
        else:
            minutes = delta.seconds // 60
            return f"{minutes} minute{'s' if minutes > 1 else ''}"
