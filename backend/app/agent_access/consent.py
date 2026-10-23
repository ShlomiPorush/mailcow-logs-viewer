"""The consent page's API and the Settings > Agents management API (/api/agents).

For people only: an agent's own calls never reach these routes (they are
excluded in scopes.py, and operator() refuses an agent call as well). The
consent routes also need the browser session that opened the request.
"""
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..session import get_session_from_request, session_key_from_request
from ..utils import format_datetime_for_api
from . import live, pending, store
from .context import agent_call
from .oauth import client_redirect
from .scopes import AREAS, areas_of, grant_scopes, parse_scopes, requested_views

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agents", tags=["Agents"])

PERIOD_DAYS = (1 / 24, 1, 7, 30, 90, 365)
DEFAULT_PERIOD_DAYS = 7


def operator(request: Request) -> None:
    """A person using this app, never an agent.

    The middleware already required sign-in when it is on. With sign-in off
    nobody can approve an agent (the consent routes answer 404), but the list
    still loads, so Settings can say what is missing.
    """
    if agent_call(request.scope) is not None:
        raise HTTPException(status_code=403, detail="Agents cannot manage agents.")


def periods() -> List[dict]:
    """The periods a person can pick, up to the configured maximum."""
    out = []
    for days in PERIOD_DAYS:
        if days <= settings.agent_access_max_days:
            out.append({"days": days, "label": _period_label(days)})
    if not any(p["days"] == settings.agent_access_max_days for p in out):
        out.append({"days": settings.agent_access_max_days, "label": _period_label(settings.agent_access_max_days)})
    return out


def _period_label(days: float) -> str:
    if days < 1:
        return "1 hour"
    if days == 365:
        return "1 year"
    days = int(days)
    return "1 day" if days == 1 else f"{days} days"


def _who(request: Request) -> Optional[str]:
    session = get_session_from_request(request) or {}
    user = session.get("user_info") or {}
    for key in ("email", "preferred_username", "username", "name", "sub"):
        if user.get(key):
            return str(user[key])[:255]
    return None


# ── Consent ────────────────────────────────────────────────────────────────

@router.get("/consent/{request_id}", dependencies=[Depends(operator)])
def get_consent(request_id: str, request: Request):
    if not live.is_live():
        raise HTTPException(status_code=404, detail="Agent access is turned off.")
    entry = pending.get(request_id, session_key_from_request(request))
    if entry is None:
        raise HTTPException(status_code=404, detail="This request has expired or was already answered. Connect the agent again.")
    max_days = settings.agent_access_max_days
    return {
        "client": {
            "declared_name": entry.declared_name,
            "publisher": entry.publisher,
            "kind": entry.client_kind,
            "redirect_uri": entry.redirect_uri,
        },
        "areas": [{"id": a.id, "label": a.label, "view": a.view, "act": a.act} for a in AREAS],
        "preselected_views": list(requested_views(entry.requested)),
        "periods": periods(),
        "default_days": DEFAULT_PERIOD_DAYS if DEFAULT_PERIOD_DAYS <= max_days else max_days,
        "app_title": settings.app_title,
        "signed_in_as": _who(request),
    }


class ConsentAnswer(BaseModel):
    allow: bool
    name: str = Field(default="", max_length=100)
    views: List[str] = Field(default_factory=list, max_length=50)
    acts: List[str] = Field(default_factory=list, max_length=50)
    days: float = DEFAULT_PERIOD_DAYS


@router.post("/consent/{request_id}", dependencies=[Depends(operator)])
def answer_consent(request_id: str, answer: ConsentAnswer, request: Request, db: Session = Depends(get_db)):
    """Allow or deny; the answer is the address to send the browser back to the agent."""
    if not live.is_live():
        raise HTTPException(status_code=404, detail="Agent access is turned off.")
    session_key = session_key_from_request(request)
    scopes = grant_scopes(answer.views, answer.acts)
    if answer.allow and not scopes and pending.get(request_id, session_key) is not None:
        # Nothing to allow: the request stays open so the page can be fixed
        raise HTTPException(status_code=400, detail="Choose at least one area to allow.")
    entry = pending.take(request_id, session_key)
    if entry is None:
        raise HTTPException(status_code=404, detail="This request has expired or was already answered. Connect the agent again.")
    if not answer.allow:
        logger.info(f"Agent access: a person denied '{entry.declared_name}'")
        return {"redirect": client_redirect(entry.redirect_uri, entry.state, error="access_denied",
                                            error_description="The request was denied.").headers["location"]}
    if not scopes:
        raise HTTPException(status_code=400, detail="Choose at least one area to allow.")
    allowed_days = {p["days"] for p in periods()}
    days = answer.days if answer.days in allowed_days else min(DEFAULT_PERIOD_DAYS, settings.agent_access_max_days)
    name = " ".join(answer.name.split())[:100] or entry.declared_name
    code = store.create_code(db, client_id=entry.client_id, redirect_uri=entry.redirect_uri,
                             code_challenge=entry.code_challenge, resource=entry.resource, details={
                                 "client_kind": entry.client_kind,
                                 "display_name": name,
                                 "declared_name": entry.declared_name[:100],
                                 "publisher": entry.publisher,
                                 "scopes": scopes,
                                 "days": days,
                                 "approved_by": _who(request),
                                 # A sign-in change before the token request voids the code
                                 "sign_in": store.sign_in_stamp(db),
                             })
    return {"redirect": client_redirect(entry.redirect_uri, entry.state, code=code).headers["location"]}


# ── Management (Settings > Agents) ─────────────────────────────────────────

def _grant_row(grant) -> dict:
    scopes = parse_scopes(grant.scopes)
    if store.grant_is_active(grant):
        state = "connected"
    elif grant.revoked_at is not None:
        state = "disconnected"
    else:
        state = "expired"
    return {
        "id": grant.id,
        "name": grant.display_name,
        "declared_name": grant.declared_name,
        "publisher": grant.publisher,
        "kind": grant.client_kind,
        "areas": areas_of(scopes),
        "approved_by": grant.approved_by,
        "created_at": format_datetime_for_api(grant.created_at),
        "expires_at": format_datetime_for_api(grant.expires_at),
        "last_used_at": format_datetime_for_api(grant.last_used_at),
        "ended_at": format_datetime_for_api(grant.revoked_at or (grant.expires_at if state == "expired" else None)),
        "end_reason": grant.revoke_reason if grant.revoked_at else (state if state == "expired" else None),
        "state": state,
    }


@router.get("", dependencies=[Depends(operator)])
def list_agents(db: Session = Depends(get_db)):
    problem = live.problem()
    if problem is None:
        store.check_sign_in_unchanged(db)
    return {
        "live": problem is None,
        "problem": problem,
        "enabled": settings.agent_access_enabled,
        "url": settings.agent_access_url,
        "mcp_url": live.resource() if problem is None else None,
        "max_days": settings.agent_access_max_days,
        "areas": [{"id": a.id, "label": a.label} for a in AREAS],
        "agents": [_grant_row(g) for g in store.list_grants(db)],
    }


@router.delete("/{grant_id}", dependencies=[Depends(operator)])
def disconnect_agent(grant_id: int, db: Session = Depends(get_db)):
    if not store.revoke_grant(db, grant_id):
        raise HTTPException(status_code=404, detail="This agent is not connected.")
    return {"disconnected": 1}


@router.delete("", dependencies=[Depends(operator)])
def disconnect_all_agents(db: Session = Depends(get_db)):
    return {"disconnected": store.revoke_all(db)}


@router.get("/{grant_id}/activity", dependencies=[Depends(operator)])
def agent_activity(grant_id: int, db: Session = Depends(get_db)):
    return {"activity": [{
        "at": format_datetime_for_api(row.at),
        "event": row.event,
        "tool": row.tool,
        "method": row.method,
        "path": row.path,
        "http_status": row.http_status,
        "outcome": row.outcome,
        "detail": row.detail,
    } for row in store.activity(db, grant_id)]}
