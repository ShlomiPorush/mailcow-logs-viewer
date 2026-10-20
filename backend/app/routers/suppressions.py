"""
API endpoints for Spam Suppression management

Provides CRUD operations for the spam suppression list,
including auto-detection of bounced/rejected outbound emails
and syncing to Rspamd's global_rcpt_blacklist.map.
"""
import asyncio
import csv
import io
import re
import logging
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, Depends, Query, UploadFile, File
from pydantic import BaseModel, field_validator
from typing import Optional, List
from sqlalchemy.orm import Session, load_only
from sqlalchemy import func, or_, desc

from ..services.csv_export import CSV_ESCAPE_COLUMN, csv_download, csv_query_rows, get_csv_db, restore_csv_text
from ..database import SessionLocal, get_db, get_db_context
from ..config import settings
from ..models import MessageCorrelation, SpamSuppression, SuppressionEvent
from ..mailcow_api import mailcow_api, MailcowAPIError, MailcowRwKeyError
from ..services.rspamd_map_lock import MapBusyError, map_write_lock
from ..services.suppression_events import add_event, postfix_lines
from ..utils import internal_error, format_datetime_for_api
from ..app_time import to_local, utc_naive

logger = logging.getLogger(__name__)

router = APIRouter()

# Marker comment used to separate manual entries from managed ones in the Rspamd map
MANAGED_MARKER_START = "# === MANAGED BY MAILCOW LOGS VIEWER - DO NOT EDIT BELOW ==="
MANAGED_MARKER_END = "# === END MANAGED SECTION ==="
DENYLIST_MAP = "global_rcpt_blacklist.map"


# Sources whose rows hold addresses read from Postfix logs or the mail queue.
# Everything else (manual, import, and rows from before the column was set)
# was entered by an administrator.
AUTOMATIC_SOURCES = frozenset({'auto'})


def suppression_allows_regex(source: Optional[str]) -> bool:
    """Only an administrator's entry may be a /regex/; automatic ones are literal."""
    return source not in AUTOMATIC_SOURCES


def auto_suppression_address(raw: Optional[str]) -> Optional[str]:
    """
    The recipient an automatic path may suppress, or None to skip it.

    Recipients come from Postfix logs and the mail queue, so they are
    whatever a sender typed. A '/' in the domain or any whitespace is never
    a deliverable address and is refused here; the map line is written as an
    escaped literal regardless (see format_suppression_map_entry).
    """
    email = (raw or '').strip().lower()
    local, sep, domain = email.rpartition('@')
    if not sep or not local or not domain:
        return None
    if '/' in domain or any(ch.isspace() for ch in email):
        return None
    return email


def format_suppression_map_entry(email: str, allow_regex: bool = False) -> str:
    """
    One line of the Rspamd map, matching the address exactly.

    global_rcpt_blacklist.map is a regexp map: a bare address like e@example.com
    is compiled as an unanchored pattern and blocks every recipient that
    merely CONTAINS it (alice@example.com, joe@example.com, ...). Every
    entry is therefore written as an anchored, escaped pattern.

    allow_regex is for entries an administrator added (domain suppressions
    are stored as /.+@example\\.com/i). Their body is anchored as one group,
    ^(?:body)$, so an alternation cannot escape the anchors. Automatic rows
    must pass allow_regex=False: their value came from a log or the mail
    queue, and a recipient shaped like /.*/i would otherwise block everyone.
    """
    email = (email or '').strip()
    pattern = re.match(r'^/(.*)/(i?)$', email) if allow_regex else None
    if pattern:
        body, flags = pattern.group(1), pattern.group(2)
        if body.startswith('^'):
            body = body[1:]
        if body.endswith('$') and not body.endswith('\\$'):
            body = body[:-1]
        return f'/^(?:{body})$/{flags}'
    return f'/^{re.escape(email)}$/i'


# A line that is just an address. Used to auto-migrate dangerous bare
# entries: in a regexp map they match as substrings. Domain labels exclude
# the dot so the pattern cannot backtrack polynomially on crafted input, and
# callers cap the line length - map content is operator-provided. A line with
# a regex character (\ * ( ) [ ] ^ $ | ? { }) is a pattern someone wrote, such
# as .*@example\.com, and is left as it is.
_BARE_ADDRESS_MAX_LEN = 320
_BARE_ADDRESS_RE = re.compile(r'^[^\s/@\\*()\[\]^$|?{}]+@[^\s/@.\\*()\[\]^$|?{}]+(?:\.[^\s/@.\\*()\[\]^$|?{}]+)+$')


def migrate_manual_map_line(line: str) -> str:
    """
    Anchor a manual map line when it is a bare address; leave everything
    else (comments, regex patterns, other entry shapes) untouched.

    Operators are not expected to fix their maps by hand - installations in
    the field carry bare entries added before anchoring existed, and each
    one silently blocks unrelated recipients until it is anchored.
    """
    stripped = line.strip()
    if len(stripped) <= _BARE_ADDRESS_MAX_LEN and _BARE_ADDRESS_RE.match(stripped):
        return format_suppression_map_entry(stripped)
    return line


# Rows loaded back from the app's section of the Rspamd map when Spam Filter
# was turned on again: permanent, and no automatic path changes them
RSPAMD_SOURCE = 'rspamd'
# Longest value a row holds (spam_suppressions.email)
_ROW_VALUE_MAX = 255
_LITERAL_LINE_RE = re.compile(r'^/\^(.*)\$/i$')
_PATTERN_LINE_RE = re.compile(r'^/\^\(\?:(.*)\)\$/(i?)$')
_DOMAIN_BODY_RE = re.compile(r'^\.\+@((?:[A-Za-z0-9-]|\\\.)+)$')
_ANY_PATTERN_RE = re.compile(r'^/(.*)/([A-Za-z]*)$', re.S)


def suppression_map_line(s) -> str:
    """The map line of a row."""
    return format_suppression_map_entry(s.email, allow_regex=suppression_allows_regex(s.source))


def parse_managed_line(line: str):
    """(value, type) of a row for one line of the app's section.

    The app writes an address as /^escaped$/i and a pattern or domain as
    /^(?:body)$/flags. Either form is read back to the value the row held,
    only when writing that value again gives the same line, so a block the
    app wrote goes back to Rspamd unchanged. Any other line in the app's
    section keeps its meaning as a pattern (the map is a regexp map; a bare
    address is blocked exactly, as above the section); it is written
    anchored, like every pattern the app writes, and reads back to the same
    row after that.
    Raises ValueError for a line no row can hold: longer than a row, or a
    pattern with flags other than i.
    """
    line = line.strip()
    pattern = _PATTERN_LINE_RE.match(line)
    if pattern:
        body, flags = pattern.group(1), pattern.group(2)
        # With the anchors as the app stores them, or without when they would not fit
        for value in (f'/^{body}$/{flags}', f'/{body}/{flags}'):
            if len(value) <= _ROW_VALUE_MAX and format_suppression_map_entry(value, allow_regex=True) == line:
                return value, ('domain' if _DOMAIN_BODY_RE.match(body) else 'email')
    literal = _LITERAL_LINE_RE.match(line)
    if literal and not pattern:
        # re.escape puts a backslash before single characters only
        value = re.sub(r'\\(.)', r'\1', literal.group(1), flags=re.S)
        if value == value.lower() and format_suppression_map_entry(value) == line and len(value) <= _ROW_VALUE_MAX:
            return value, 'email'
    other = _ANY_PATTERN_RE.match(line)
    if other:
        if other.group(2) not in ('', 'i'):
            raise ValueError(f'A line of the Rspamd map uses flags this app cannot keep ({other.group(2)}): {line[:60]}')
        value = line
    elif len(line) <= _BARE_ADDRESS_MAX_LEN and _BARE_ADDRESS_RE.match(line):
        value = line.lower()
    else:
        value = f'/{line}/'
    if len(value) > _ROW_VALUE_MAX:
        raise ValueError(f'A line of the Rspamd map is longer than {_ROW_VALUE_MAX} characters: {line[:60]}...')
    return value, 'email'


class SuppressionCreateRequest(BaseModel):
    email: str
    type: str = "email"  # 'email' or 'domain'
    reason: str = "manual"
    notes: Optional[str] = None
    permanent: bool = True  # True = never expires, False = use expires_at or auto-calculate
    expires_at: Optional[str] = None  # ISO format datetime string
    # Set when the block is made from a message on the Queue page: that message
    # is kept with the block as its details
    queue_id: Optional[str] = None
    
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
        valid = ('hard_bounce', 'soft_bounce', 'deferred_stuck', 'rejected', 'manual')
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
        # Queue cleanup is best-effort - don't fail the suppression
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
    # The id breaks ties, so the pages the list loads one after another
    # neither repeat nor miss a row among rows that sort equal
    if sort_dir == "desc":
        query = query.order_by(desc(sort_col), desc(SpamSuppression.id))
    else:
        query = query.order_by(sort_col, SpamSuppression.id)
    
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
async def create_suppression(body: SuppressionCreateRequest):
    """Save a manual suppression before cleaning up matching queue items."""
    # A block made from a queued message keeps that message: read it before
    # the cleanup below deletes it
    queued = await _queued_message(body.queue_id, body.email) if body.queue_id else None
    result = await asyncio.to_thread(_create_suppression_worker, body, queued)
    await _cleanup_queue_for_email(body.email)
    return result


async def _queued_message(queue_id: str, email: str) -> Optional[dict]:
    """The queue item a block is made from, for the block's details. A queue
    that cannot be read leaves the details out; the block is still made."""
    try:
        queue = await mailcow_api.get_queue()
    except MailcowAPIError:
        return None
    for item in queue or []:
        if item.get('queue_id') != queue_id:
            continue
        recipients = [raw.split(' ')[0].strip('<>').lower() for raw in (item.get('recipients') or [])]
        if email not in recipients:
            return None
        reason = next((raw.split(' ', 1)[1].strip().strip('()') for raw in (item.get('recipients') or [])
                       if ' ' in raw and raw.split(' ')[0].strip('<>').lower() == email), None)
        arrived = item.get('arrival_time')
        return {'queue_id': queue_id, 'sender': item.get('sender'), 'reason': reason,
                'arrived': datetime.fromtimestamp(arrived, tz=timezone.utc).replace(tzinfo=None) if arrived else None}
    return None


def _manual_event(db, suppression, kind: str, outcome: str, body, queued: Optional[dict]) -> None:
    fields = dict(kind=kind, outcome=outcome, reason=body.reason, notes=body.notes,
                  recipient=suppression.email, expires_at=suppression.expires_at)
    if queued:
        found, shortened = postfix_lines(db, [(queued['queue_id'], suppression.email,
                                               queued['arrived'] or datetime.utcnow(), datetime.utcnow(), None)])[0]
        fields.update(queue_id=queued['queue_id'], sender=queued['sender'], server_reply=queued['reason'],
                      message_time=queued['arrived'], log_lines=found, logs_shortened=shortened)
    add_event(db, suppression, **fields)


def _create_suppression_worker(body: SuppressionCreateRequest, queued: Optional[dict] = None) -> dict:
    with SessionLocal() as db:
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
                _manual_event(db, existing, 'enabled', 'activated', body, queued)
                db.commit()
                db.refresh(existing)

                return _serialize_suppression(existing, datetime.utcnow())

        # Determine expiry
        expires_at_val = None
        if not body.permanent:
            if body.expires_at:
                try:
                    expires_at_val = utc_naive(datetime.fromisoformat(body.expires_at.replace('Z', '+00:00')))
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
        db.flush()
        _manual_event(db, suppression, 'added', 'created', body, queued)
        db.commit()
        db.refresh(suppression)

        return _serialize_suppression(suppression, datetime.utcnow())


@router.put("/suppressions/{suppression_id}")
def update_suppression(suppression_id: int, body: SuppressionUpdateRequest, db: Session = Depends(get_db)):
    """Update a suppression entry (toggle active, edit notes, change expiry)."""
    suppression = db.query(SpamSuppression).filter(SpamSuppression.id == suppression_id).first()
    if not suppression:
        raise HTTPException(status_code=404, detail="Suppression not found")
    
    was = (suppression.active, suppression.notes, suppression.expires_at)
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
                # Stored as naive UTC, so an unchanged expiry compares equal
                suppression.expires_at = utc_naive(datetime.fromisoformat(body.expires_at.replace('Z', '+00:00')))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid date format for expires_at")
    
    # What changed by hand is kept with the block, with the notes as they were then
    if suppression.active != was[0]:
        add_event(db, suppression, kind='enabled' if suppression.active else 'disabled', outcome='changed',
                  notes=suppression.notes, expires_at=suppression.expires_at, recipient=suppression.email)
    if suppression.expires_at != was[2]:
        add_event(db, suppression, kind='expiry_changed', outcome='changed', notes=suppression.notes,
                  expires_at=suppression.expires_at, recipient=suppression.email)
    if (suppression.notes or '') != (was[1] or ''):
        add_event(db, suppression, kind='notes_changed', outcome='changed', notes=suppression.notes,
                  expires_at=suppression.expires_at, recipient=suppression.email)
    suppression.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(suppression)
    
    return _serialize_suppression(suppression, datetime.utcnow())


EVENTS_PAGE = 20


@router.get("/suppressions/{suppression_id}/events")
def get_suppression_events(suppression_id: int, page: int = Query(1, ge=1), db: Session = Depends(get_db)):
    """Block details: what happened to this address, newest first, with the
    evidence copied at the time. message_available says whether the linked
    message is still on the Messages page right now."""
    suppression = db.query(SpamSuppression).filter(SpamSuppression.id == suppression_id).first()
    if not suppression:
        raise HTTPException(status_code=404, detail="Suppression not found")
    query = db.query(SuppressionEvent).filter(SuppressionEvent.suppression_id == suppression_id)
    total = query.count()
    events = query.order_by(SuppressionEvent.recorded_at.desc(), SuppressionEvent.id.desc())         .offset((page - 1) * EVENTS_PAGE).limit(EVENTS_PAGE).all()
    keys = {e.correlation_key for e in events if e.correlation_key}
    present = {k for (k,) in db.query(MessageCorrelation.correlation_key)
               .filter(MessageCorrelation.correlation_key.in_(keys)).all()} if keys else set()
    when = lambda value: format_datetime_for_api(value) if value else None  # noqa: E731
    return {
        "suppression": {"id": suppression.id, "email": suppression.email, "type": suppression.type,
                        "active": suppression.active},
        "total": total, "page": page, "page_size": EVENTS_PAGE,
        "events": [{
            "id": e.id, "kind": e.kind, "outcome": e.outcome, "recorded_at": when(e.recorded_at),
            "message_time": when(e.message_time), "reason": e.reason, "server_reply": e.server_reply,
            "dsn": e.dsn, "sender": e.sender, "recipient": e.recipient, "subject": e.subject,
            "queue_id": e.queue_id, "message_id": e.message_id, "notes": e.notes,
            "expires_at": when(e.expires_at), "log_lines": e.log_lines or [], "logs_shortened": bool(e.logs_shortened),
            "correlation_key": e.correlation_key, "message_available": e.correlation_key in present,
        } for e in events],
    }


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
async def import_suppressions(file: UploadFile = File(...)):
    """
    Bulk import suppressions from CSV file.
    CSV format: email, type (optional), reason (optional), notes (optional)
    """
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="File must be a CSV")
    
    content = await file.read()
    return await asyncio.to_thread(_import_suppressions_worker, content)


def _import_suppressions_worker(content: bytes):
    with SessionLocal() as db:
        text = content.decode('utf-8-sig')  # handle BOM
        reader = csv.reader(io.StringIO(text))

        imported = 0
        skipped = 0
        errors_list = []

        accepted_emails = set()
        headers = None
        for row_num, row in enumerate(reader, 1):
            if not row:
                continue
            if row_num == 1 and row[0].lower().strip() in ('email', 'address'):
                headers = [name.lower().strip() for name in row]
                continue

            if headers:
                values = dict(zip(headers, row))
                email_value = values.get('email', values.get('address', ''))
                values['email'] = email_value
            else:
                values = dict(zip(('email', 'type', 'reason', 'notes'), row))
            encoded = headers is not None and CSV_ESCAPE_COLUMN in headers
            if encoded:
                try:
                    for field in filter(None, values.get(CSV_ESCAPE_COLUMN, '').split(',')):
                        if field not in headers or field == CSV_ESCAPE_COLUMN:
                            raise ValueError("Invalid CSV escape metadata")
                        values[field] = restore_csv_text(values.get(field, ''))
                except ValueError:
                    errors_list.append(f"Row {row_num}: invalid CSV escape metadata")
                    continue
            email = values.get('email', '').strip().lower()
            entry_type = values.get('type', '').strip()
            if entry_type not in ('email', 'domain'):
                entry_type = 'email'
            reason = values.get('reason', '').strip()
            if reason not in ('hard_bounce', 'soft_bounce', 'rejected', 'manual'):
                reason = 'manual'
            notes = values.get('notes', 'Imported from CSV')
            if not encoded:
                notes = notes.strip()

            if not email:
                errors_list.append(f"Row {row_num}: empty email")
                continue

            # Pending rows are invisible to queries because autoflush is disabled.
            if email in accepted_emails:
                skipped += 1
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
                db.flush()
                add_event(db, suppression, kind='imported', outcome='created', reason=reason, notes=notes,
                          recipient=email)
                accepted_emails.add(email)
                imported += 1
            except Exception as e:
                logger.error("Suppression import failed on row %s: %s", row_num, e)
                errors_list.append(f"Row {row_num}: Import failed. Check the application logs.")

        db.commit()

        return {
            "imported": imported,
            "skipped": skipped,
            "errors": errors_list,
        }


@router.get("/suppressions/export")
def export_suppressions(db: Session = Depends(get_csv_db)):
    """Export all suppressions as CSV."""
    suppressions = csv_query_rows(db.query(SpamSuppression).options(load_only(
        SpamSuppression.email, SpamSuppression.type, SpamSuppression.reason,
        SpamSuppression.source, SpamSuppression.notes, SpamSuppression.bounce_count,
        SpamSuppression.hard_bounce_count, SpamSuppression.soft_bounce_count,
        SpamSuppression.active, SpamSuppression.expires_at, SpamSuppression.created_at,
    )).order_by(SpamSuppression.created_at), allow_empty=True)
    
    columns = ['email', 'type', 'reason', 'source', 'notes', 'bounce_count',
               'hard_bounces', 'soft_bounces', 'active', 'expires_at', 'created_at']

    def csv_time(value):
        # The app's time zone with its offset, like the log exports
        return to_local(value).isoformat(sep=' ', timespec='seconds') if value else ''

    rows = (dict(zip(columns, [
        s.email, s.type, s.reason, s.source or '', s.notes or '',
        s.bounce_count, s.hard_bounce_count, s.soft_bounce_count,
        s.active, csv_time(s.expires_at), csv_time(s.created_at),
    ])) for s in suppressions)
    return csv_download(rows, "spam_suppressions.csv", columns, escape_metadata=True)



# =========================================================================
# Rspamd Sync
# =========================================================================

@router.post("/suppressions/sync")
async def manual_sync_to_rspamd():
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
        result = await asyncio.to_thread(sync_suppressions_worker)
        return result
    except MapUnavailable as e:
        raise _map_error(e)
    except MapBusyError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except MailcowAPIError as e:
        raise internal_error(e, status_code=502)
    except Exception as e:
        logger.error(f"Sync failed: {e}")
        raise internal_error(e)


def automatic_updates_on() -> bool:
    """Whether the app writes its blocks to Rspamd by itself: new blocks and
    expiries. Changes made on the Suppressions page are written either way."""
    return (settings.is_feature_enabled('spam-filter') and settings.suppression_enabled
            and settings.suppression_rspamd_sync)


def _run_on_worker_loop(work):
    """Run an async map operation on a short-lived loop of this worker
    thread, with its own database session and HTTP client."""
    async def run():
        try:
            with get_db_context() as db:
                return await work(db)
        finally:
            await mailcow_api.aclose()

    return asyncio.run(run())


def sync_suppressions_worker(automatic: bool = False) -> dict:
    """Write the active list to Rspamd, holding the map lock.

    An automatic sync (the scheduled job, after detection or queue cleanup)
    checks the switches again once it holds the lock: one that waited while
    automatic updates were turned off does not write after all.
    """
    with map_write_lock():
        if not settings.is_feature_enabled('spam-filter'):
            # Its list is deleted while it is off: writing it would wipe the
            # blocks that come back when it is turned on
            if automatic:
                return {"success": True, "synced": 0, "skipped_off": True}
            raise MapUnavailable("feature_off")
        if automatic and not automatic_updates_on():
            return {"success": True, "synced": 0, "skipped_off": True}

        async def work(db):
            # The blocks of before go back into the list first; until they
            # can, nothing is written
            await _import_managed_blocks(db)
            return await sync_suppressions_to_rspamd(db)

        return _run_on_worker_loop(work)


# ---- The app's part of the map: state, clear, start fresh ----

class MapUnavailable(Exception):
    """The app's part of the Rspamd map cannot be read or written now."""

    REASONS = {
        "no_rw_key": "The Read-Write API key is not set.",
        "no_password": "The Rspamd password is not set.",
        "no_rw_key_and_password": "The Read-Write API key and Rspamd password are not set.",
        "read_failed": "The Rspamd map could not be read. Check the connection and try again.",
        "map_not_found": "Rspamd has no recipient denylist map.",
        "feature_off": "Spam Filter is off.",
        "import_failed": "This app's Rspamd blocks could not be loaded into the list.",
    }

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        super().__init__(self.REASONS.get(code, detail) if not detail else detail)


def _missing_credentials() -> Optional[str]:
    rw, pw = mailcow_api.has_rw_key, settings.is_rspamd_configured
    if not rw and not pw:
        return "no_rw_key_and_password"
    if not rw:
        return "no_rw_key"
    if not pw:
        return "no_password"
    return None



def split_managed_section(content: str):
    """The map's lines before the app's section, the app's entries, and the
    lines after its end marker. A map the app never wrote has no section:
    every line is before it."""
    lines = content.split('\n') if content else []
    start = next((i for i, line in enumerate(lines)
                  if MANAGED_MARKER_START in line or '# === MANAGED BY MAILCOW LOGS VIEWER' in line), None)
    if start is None:
        # An end marker without its start (edited by hand): the lines around it
        # are kept, the marker itself is written again
        end = next((i for i, line in enumerate(lines) if MANAGED_MARKER_END in line), None)
        if end is not None:
            return lines[:end], [], lines[end + 1:]
        return lines, [], []
    end = next((i for i in range(start + 1, len(lines)) if MANAGED_MARKER_END in lines[i]), len(lines))
    entries = [line.strip() for line in lines[start + 1:end] if line.strip() and not line.strip().startswith('#')]
    return lines[:start], entries, lines[end + 1:]


async def _read_denylist_map():
    """(map id, content) of the recipient denylist, or MapUnavailable."""
    if not settings.is_rspamd_configured:
        raise MapUnavailable("no_password")
    try:
        map_id = await mailcow_api.find_rspamd_map_id(DENYLIST_MAP)
        if map_id is None:
            raise MapUnavailable("map_not_found")
        return map_id, await mailcow_api.get_rspamd_map_content(map_id)
    except MailcowAPIError as e:
        logger.warning(f"[SUPPRESSION] Could not read the Rspamd denylist map: {e}")
        raise MapUnavailable("read_failed")


async def _clear_managed_section(db: Session) -> int:
    """Empty the app's part of the map, leaving every other line exactly as it
    is, and mark every row as not in Rspamd. Returns how many blocks went.
    Raises when the map cannot be read or mailcow did not confirm the save."""
    missing = _missing_credentials()
    if missing:
        raise MapUnavailable(missing)
    _, content = await _read_denylist_map()
    before, entries, after = split_managed_section(content)
    # An empty section needs no write: every save makes Rspamd reload the map
    if entries:
        now_str = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        new_content = '\n'.join(before + [MANAGED_MARKER_START, f"# Cleared: {now_str}", MANAGED_MARKER_END] + after)
        await mailcow_api.edit_rspamd_map(DENYLIST_MAP, new_content)
    db.query(SpamSuppression).filter(SpamSuppression.synced_to_rspamd == True).update(  # noqa: E712
        {SpamSuppression.synced_to_rspamd: False}, synchronize_session=False)
    db.commit()
    logger.info(f"[SUPPRESSION] Removed the app's {len(entries)} block(s) from Rspamd")
    return len(entries)


def clear_managed_worker() -> int:
    with map_write_lock():
        return _run_on_worker_loop(_clear_managed_section)


def start_fresh_worker() -> dict:
    """Clear the app's part of the map, then delete the whole list. The list
    goes only after mailcow confirmed the map, so nothing stays blocked unseen."""
    async def work(db):
        from ..models import SystemSetting
        from ..services.feature_data import SPAM_IMPORT_PENDING_KEY
        removed = await _clear_managed_section(db)
        deleted = db.query(SpamSuppression).delete(synchronize_session=False)
        # A fresh list loads nothing back from Rspamd
        db.query(SystemSetting).filter(SystemSetting.key == SPAM_IMPORT_PENDING_KEY).delete(synchronize_session=False)
        db.commit()
        logger.info(f"[SUPPRESSION] Started fresh: {deleted} entr(ies) deleted, {removed} Rspamd block(s) removed")
        return {"removed_blocks": removed, "deleted_entries": deleted}

    with map_write_lock():
        return _run_on_worker_loop(work)


def import_pending(db: Session) -> bool:
    """Whether the blocks this app wrote to Rspamd still have to be loaded
    into the list (Spam Filter was off and its list deleted)."""
    from ..models import SystemSetting
    from ..services.feature_data import SPAM_IMPORT_PENDING_KEY
    return db.query(SystemSetting.key).filter(SystemSetting.key == SPAM_IMPORT_PENDING_KEY).first() is not None


async def _import_managed_blocks(db: Session) -> dict:
    """Load the blocks this app wrote to Rspamd back into the list, once,
    after Spam Filter was off. The caller holds the map lock.

    Every line of the app's section becomes a permanent row with source
    'rspamd' unless the list already has that line (an entry added by hand
    since wins). Lines outside the section are entries typed into Rspamd and
    are never read in. When the map cannot be read, or a line cannot be held,
    nothing is loaded and the import stays pending: until it is done no sync
    writes the section, so a list emptied by the purge can never wipe it.
    """
    from ..models import SystemSetting
    from ..services.feature_data import SPAM_IMPORT_PENDING_KEY
    if not import_pending(db):
        return {"imported": 0, "pending": False}
    if not settings.is_rspamd_configured:
        # Without the Rspamd password the app never wrote to Rspamd: nothing to load
        db.query(SystemSetting).filter(SystemSetting.key == SPAM_IMPORT_PENDING_KEY).delete(synchronize_session=False)
        db.commit()
        return {"imported": 0, "pending": False}
    _, content = await _read_denylist_map()
    _, entries, _ = split_managed_section(content)
    try:
        parsed = [parse_managed_line(line) for line in entries]
    except ValueError as e:
        raise MapUnavailable("import_failed", str(e))
    # The same block twice: the same map line, or the same address (addresses
    # match whatever their case; a pattern is compared as written)
    have_lines, have_addresses = set(), set()
    for row in db.query(SpamSuppression).all():
        have_lines.add(suppression_map_line(row))
        if not (row.email or '').startswith('/'):
            have_addresses.add(row.email.strip().lower())
    imported = 0
    for value, kind in parsed:
        row = SpamSuppression(email=value, type=kind, reason='manual', source=RSPAMD_SOURCE,
                              bounce_count=0, hard_bounce_count=0, soft_bounce_count=0,
                              active=True, synced_to_rspamd=True, expires_at=None)
        line = suppression_map_line(row)
        address = None if value.startswith('/') else value.lower()
        if line in have_lines or (address is not None and address in have_addresses):
            continue
        have_lines.add(line)
        if address is not None:
            have_addresses.add(address)
        db.add(row)
        db.flush()
        add_event(db, row, kind='loaded_from_rspamd', outcome='created', recipient=value, expires_at=None)
        imported += 1
    db.query(SystemSetting).filter(SystemSetting.key == SPAM_IMPORT_PENDING_KEY).delete(synchronize_session=False)
    db.commit()
    logger.info(f"[SUPPRESSION] Loaded {imported} block(s) of this app back from Rspamd")
    return {"imported": imported, "pending": False}


def import_managed_worker() -> dict:
    """Load the app's Rspamd blocks into the list if that is pending. Only
    while Spam Filter is on; the purge of a Spam Filter that is off holds the
    same lock."""
    with map_write_lock():
        if not settings.is_feature_enabled('spam-filter'):
            return {"imported": 0, "pending": False, "feature_off": True}
        return _run_on_worker_loop(_import_managed_blocks)


@router.post("/suppressions/rspamd/import")
async def import_rspamd_blocks():
    """Load the blocks this app wrote to Rspamd back into the list after Spam
    Filter was off. Nothing happens when that is not pending."""
    try:
        return await asyncio.to_thread(import_managed_worker)
    except (MapUnavailable, MapBusyError, MailcowAPIError) as e:
        raise _map_error(e)


def _map_error(e: Exception) -> HTTPException:
    """What a map operation tells the page when it could not finish."""
    if isinstance(e, MapUnavailable):
        return HTTPException(status_code=409, detail={"code": e.code, "message": str(e)})
    if isinstance(e, MapBusyError):
        return HTTPException(status_code=409, detail={"code": "busy", "message": str(e)})
    if isinstance(e, MailcowRwKeyError):
        return HTTPException(status_code=502, detail={"code": "rejected_rw_key", "message": str(e)})
    # mailcow did not confirm, or the request failed: the outcome is not known
    logger.error(f"[SUPPRESSION] Rspamd map change not confirmed: {e}")
    return HTTPException(status_code=502, detail={
        "code": "not_confirmed", "message": "mailcow did not confirm the change. Check the Rspamd map before trying again."})


@router.get("/suppressions/rspamd/state")
async def rspamd_state():
    """What the app has in Rspamd now, read from the map itself, and whether it
    can change it. Counts are blocks (map lines), not addresses: a line can be
    a domain or a pattern."""
    def count_active():
        with get_db_context() as db:
            return db.query(func.count(SpamSuppression.id)).filter(SpamSuppression.active == True).scalar() or 0  # noqa: E712

    active = await asyncio.to_thread(count_active)
    missing = _missing_credentials()
    state = {"automatic": automatic_updates_on(), "active_count": int(active), "writable": missing is None,
             "readable": False, "managed_count": None, "reason": missing, "reason_text": MapUnavailable.REASONS.get(missing)}
    if not settings.is_rspamd_configured:
        return state
    try:
        _, content = await _read_denylist_map()
        state["readable"] = True
        state["managed_count"] = len(split_managed_section(content)[1])
    except MapUnavailable as e:
        if not missing:
            state["reason"], state["reason_text"] = e.code, str(e)
    return state


@router.post("/suppressions/rspamd/clear")
async def clear_rspamd_blocks():
    """Remove the app's blocks from Rspamd. Lines above its section stay."""
    try:
        removed = await asyncio.to_thread(clear_managed_worker)
    except (MapUnavailable, MapBusyError, MailcowAPIError) as e:
        raise _map_error(e)
    return {"removed_blocks": removed}


@router.post("/suppressions/start-fresh")
async def start_fresh():
    """Remove the app's blocks from Rspamd, then delete the whole list."""
    try:
        return await asyncio.to_thread(start_fresh_worker)
    except (MapUnavailable, MapBusyError, MailcowAPIError) as e:
        raise _map_error(e)


async def sync_suppressions_to_rspamd(db: Session) -> dict:
    """
    Sync active suppressions to Rspamd global_rcpt_blacklist.map.
    
    Preserves manual entries above the managed marker,
    replaces the managed section with current active suppressions.
    
    Returns sync result details.
    """
    MAP_FILENAME = DENYLIST_MAP
    
    # 1. Read current map content. A failed read stops the sync: writing
    # without it would drop the manual entries above the managed section.
    current_content = ""
    try:
        map_id = await mailcow_api.find_rspamd_map_id(MAP_FILENAME)
        if map_id is not None:
            current_content = await mailcow_api.get_rspamd_map_content(map_id)
    except MailcowAPIError as e:
        logger.warning(f"Could not read the current map, not writing it: {e}")
        raise
    
    # 2. Parse: the entries typed into the map by hand, above and below the
    # app's section, stay. Recognizes both current and legacy marker formats
    # to prevent duplicate managed sections accumulating.
    manual_lines, current_managed, after_lines = split_managed_section(current_content)
    manual_lines, after_lines = list(manual_lines), list(after_lines)

    # Remove blank lines next to the section; one is written back on each side
    while manual_lines and not manual_lines[-1].strip():
        manual_lines.pop()
    while after_lines and not after_lines[0].strip():
        after_lines.pop(0)
    while after_lines and not after_lines[-1].strip():
        after_lines.pop()

    # Auto-migrate dangerous bare addresses among the manual entries - they
    # match as substrings in this regexp map. The operator never has to edit
    # the map by hand for this.
    migrated_manual = [migrate_manual_map_line(l) for l in manual_lines]
    migrated_after = [migrate_manual_map_line(l) for l in after_lines]
    manual_needs_migration = migrated_manual != manual_lines or migrated_after != after_lines
    manual_lines, after_lines = migrated_manual, migrated_after

    # 3. Get active suppressions from DB
    active_suppressions = db.query(SpamSuppression).filter(
        SpamSuppression.active == True
    ).order_by(SpamSuppression.email).all()

    # Skip the write when the managed entries are already exactly what we
    # would write. Every save makes Rspamd truncate + rewrite the file and
    # reload the map (its write is not atomic - see issue #80), so identical
    # content must not be pushed every sync just to refresh a timestamp.
    desired_lines = [suppression_map_line(s) for s in active_suppressions]
    if (current_content and not manual_needs_migration
            and sorted(current_managed) == sorted(desired_lines)):
        synced_count = 0
        for s in active_suppressions:
            if not s.synced_to_rspamd:
                s.synced_to_rspamd = True
                s.updated_at = datetime.utcnow()
                synced_count += 1
        db.commit()
        logger.debug("[SUPPRESSION] Rspamd map already up to date - skipping write")
        return {
            "success": True,
            "synced": len(active_suppressions),
            "newly_synced": synced_count,
            "manual_entries_preserved": len([l for l in manual_lines + after_lines if l.strip() and not l.strip().startswith('#')]),
            "sync_time": None,
            "skipped": True,
        }

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
    
    parts.extend(desired_lines)

    parts.append(MANAGED_MARKER_END)

    # Entries typed below the section
    if after_lines:
        parts.append('')
        parts.extend(after_lines)

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
        "manual_entries_preserved": len([l for l in manual_lines + after_lines if l.strip() and not l.strip().startswith('#')]),
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
        "expires_at": format_datetime_for_api(s.expires_at),
        "is_expired": is_expired,
        "expires_in": expires_in,
        "created_at": format_datetime_for_api(s.created_at),
        "updated_at": format_datetime_for_api(s.updated_at),
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
