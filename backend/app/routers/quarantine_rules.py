"""
Quarantine Auto-Rules API
CRUD endpoints for quarantine rules and action history.
Requires Read-Write API key (MAILCOW_API_KEY_RW) for all operations.
"""
import re
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from ..database import get_db_context
from ..models import QuarantineRule, QuarantineRuleLog
from ..mailcow_api import mailcow_api

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/quarantine/rules", tags=["quarantine-rules"])

VALID_MATCH_TYPES = {'sender', 'sender_domain', 'recipient', 'subject'}
VALID_ACTIONS = {'release', 'delete'}


# ---- Pydantic schemas ----

class RuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    match_type: str = Field(..., description="sender, sender_domain, recipient, or subject")
    match_value: str = Field(..., min_length=1, max_length=500)
    is_regex: bool = False
    action: str = Field(..., description="release or delete")
    notes: Optional[str] = None

class RuleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    match_type: Optional[str] = None
    match_value: Optional[str] = Field(None, min_length=1, max_length=500)
    is_regex: Optional[bool] = None
    action: Optional[str] = None
    enabled: Optional[bool] = None
    notes: Optional[str] = None


def _require_rw_key():
    """Raise 403 if no RW key is configured."""
    if not mailcow_api.has_rw_key:
        raise HTTPException(
            status_code=403,
            detail="Read-Write API key (MAILCOW_API_KEY_RW) is required for quarantine rules"
        )


def _validate_regex(pattern: str):
    """Validate a regex pattern."""
    try:
        re.compile(pattern)
    except re.error as e:
        raise HTTPException(status_code=400, detail=f"Invalid regex pattern: {e}")


def _rule_to_dict(rule: QuarantineRule) -> dict:
    return {
        "id": rule.id,
        "name": rule.name,
        "match_type": rule.match_type,
        "match_value": rule.match_value,
        "is_regex": rule.is_regex,
        "action": rule.action,
        "enabled": rule.enabled,
        "hit_count": rule.hit_count or 0,
        "last_hit_at": rule.last_hit_at.isoformat() + 'Z' if rule.last_hit_at else None,
        "notes": rule.notes,
        "created_at": rule.created_at.isoformat() + 'Z' if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() + 'Z' if rule.updated_at else None,
    }


def _find_matching_rule(rules, sender: str, sender_domain: str, rcpt: str, subject: str):
    """
    Find the first matching rule for a quarantine item.
    Delete rules are checked first (deny wins over allow).
    """
    # Sort: delete rules first, then release
    sorted_rules = sorted(rules, key=lambda r: (0 if r.action == 'delete' else 1))
    
    for rule in sorted_rules:
        value = rule.match_value
        
        if rule.match_type == 'sender':
            target = sender
        elif rule.match_type == 'sender_domain':
            target = sender_domain
        elif rule.match_type == 'recipient':
            target = rcpt
        elif rule.match_type == 'subject':
            target = subject
        else:
            continue
        
        if rule.is_regex:
            try:
                if re.search(value, target, re.IGNORECASE):
                    return rule
            except re.error:
                continue
        else:
            # Case-insensitive exact match
            if target == value.lower():
                return rule
    
    return None


# ---- CRUD Endpoints ----
# IMPORTANT: Static routes (/logs, /test) MUST be defined before
# parameterized routes (/{rule_id}) to avoid FastAPI matching "logs" as a rule_id.

@router.get("")
def list_rules():
    """List all quarantine rules."""
    _require_rw_key()
    
    with get_db_context() as db:
        rules = db.query(QuarantineRule).order_by(
            QuarantineRule.action.desc(),  # delete rules first
            QuarantineRule.created_at.desc()
        ).all()
        return {
            "total": len(rules),
            "data": [_rule_to_dict(r) for r in rules],
        }


@router.post("")
def create_rule(body: RuleCreate):
    """Create a new quarantine rule."""
    _require_rw_key()
    
    if body.match_type not in VALID_MATCH_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid match_type. Must be one of: {', '.join(VALID_MATCH_TYPES)}")
    if body.action not in VALID_ACTIONS:
        raise HTTPException(status_code=400, detail=f"Invalid action. Must be one of: {', '.join(VALID_ACTIONS)}")
    if body.is_regex:
        _validate_regex(body.match_value)
    
    with get_db_context() as db:
        rule = QuarantineRule(
            name=body.name,
            match_type=body.match_type,
            match_value=body.match_value,
            is_regex=body.is_regex,
            action=body.action,
            notes=body.notes,
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)
        
        logger.info(f"[QUARANTINE RULES] Created rule '{rule.name}': {rule.match_type}={rule.match_value} → {rule.action}")
        return _rule_to_dict(rule)


# ---- Action History (must be before /{rule_id}) ----

@router.get("/logs")
def get_rule_logs(
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    rule_id: Optional[int] = Query(default=None),
):
    """Get quarantine rule action history."""
    _require_rw_key()
    
    with get_db_context() as db:
        query = db.query(QuarantineRuleLog)
        
        if rule_id is not None:
            query = query.filter(QuarantineRuleLog.rule_id == rule_id)
        
        total = query.count()
        logs = query.order_by(
            QuarantineRuleLog.created_at.desc()
        ).offset(offset).limit(limit).all()
        
        return {
            "total": total,
            "data": [{
                "id": log.id,
                "rule_id": log.rule_id,
                "rule_name": log.rule_name,
                "action": log.action,
                "quarantine_id": log.quarantine_id,
                "sender": log.sender,
                "recipient": log.recipient,
                "subject": log.subject,
                "matched_field": log.matched_field,
                "matched_value": log.matched_value,
                "created_at": log.created_at.isoformat() + 'Z' if log.created_at else None,
            } for log in logs]
        }


# ---- Dry-Run Test (must be before /{rule_id}) ----

@router.post("/test")
async def test_rules():
    """
    Test all rules against current quarantine items (dry-run).
    No actions are taken — just returns what would match.
    Includes disabled rules in results, marked as rule_enabled=false.
    """
    _require_rw_key()
    
    # Load ALL rules (enabled + disabled) and convert to plain objects
    with get_db_context() as db:
        db_rules = db.query(QuarantineRule).all()
        rules = []
        for r in db_rules:
            rules.append(type('Rule', (), {
                'id': r.id, 'name': r.name, 'match_type': r.match_type,
                'match_value': r.match_value, 'is_regex': r.is_regex,
                'action': r.action, 'enabled': r.enabled
            })())
    
    if not rules:
        return {"matches": [], "total_matches": 0, "total_quarantine": 0, "message": "No rules to test"}
    
    try:
        quarantine = await mailcow_api.get_quarantine()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch quarantine: {e}")
    
    if not quarantine:
        return {"matches": [], "total_matches": 0, "total_quarantine": 0, "message": "Quarantine is empty"}
    
    matches = []
    for item in quarantine:
        item_id = str(item.get('id', ''))
        sender = (item.get('sender') or '').lower()
        rcpt = (item.get('rcpt') or '').lower()
        subject = item.get('subject') or ''
        sender_domain = sender.split('@')[-1] if '@' in sender else ''
        
        matched_rule = _find_matching_rule(rules, sender, sender_domain, rcpt, subject)
        if matched_rule:
            matches.append({
                "quarantine_id": item_id,
                "sender": item.get('sender'),
                "recipient": item.get('rcpt'),
                "subject": item.get('subject'),
                "rule_id": matched_rule.id,
                "rule_name": matched_rule.name,
                "action": matched_rule.action,
                "rule_enabled": matched_rule.enabled,
            })
    
    return {
        "total_quarantine": len(quarantine),
        "total_matches": len(matches),
        "matches": matches,
    }


# ---- Parameterized routes (/{rule_id}) ----

@router.put("/{rule_id}")
def update_rule(rule_id: int, body: RuleUpdate):
    """Update an existing quarantine rule."""
    _require_rw_key()
    
    with get_db_context() as db:
        rule = db.query(QuarantineRule).filter(QuarantineRule.id == rule_id).first()
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        
        if body.match_type is not None:
            if body.match_type not in VALID_MATCH_TYPES:
                raise HTTPException(status_code=400, detail=f"Invalid match_type. Must be one of: {', '.join(VALID_MATCH_TYPES)}")
            rule.match_type = body.match_type
        
        if body.action is not None:
            if body.action not in VALID_ACTIONS:
                raise HTTPException(status_code=400, detail=f"Invalid action. Must be one of: {', '.join(VALID_ACTIONS)}")
            rule.action = body.action
        
        if body.match_value is not None:
            is_regex = body.is_regex if body.is_regex is not None else rule.is_regex
            if is_regex:
                _validate_regex(body.match_value)
            rule.match_value = body.match_value
        
        if body.is_regex is not None:
            if body.is_regex:
                _validate_regex(body.match_value or rule.match_value)
            rule.is_regex = body.is_regex
        
        if body.name is not None:
            rule.name = body.name
        if body.enabled is not None:
            rule.enabled = body.enabled
        if body.notes is not None:
            rule.notes = body.notes
        
        rule.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(rule)
        
        logger.info(f"[QUARANTINE RULES] Updated rule '{rule.name}' (id={rule.id})")
        return _rule_to_dict(rule)


@router.delete("/{rule_id}")
def delete_rule(rule_id: int):
    """Delete a quarantine rule."""
    _require_rw_key()
    
    with get_db_context() as db:
        rule = db.query(QuarantineRule).filter(QuarantineRule.id == rule_id).first()
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        
        rule_name = rule.name
        db.delete(rule)
        db.commit()
        
        logger.info(f"[QUARANTINE RULES] Deleted rule '{rule_name}' (id={rule_id})")
        return {"success": True, "message": f"Rule '{rule_name}' deleted"}


@router.post("/{rule_id}/toggle")
def toggle_rule(rule_id: int):
    """Toggle a rule's enabled/disabled state."""
    _require_rw_key()
    
    with get_db_context() as db:
        rule = db.query(QuarantineRule).filter(QuarantineRule.id == rule_id).first()
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        
        rule.enabled = not rule.enabled
        rule.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(rule)
        
        state = "enabled" if rule.enabled else "disabled"
        logger.info(f"[QUARANTINE RULES] Rule '{rule.name}' {state}")
        return _rule_to_dict(rule)
