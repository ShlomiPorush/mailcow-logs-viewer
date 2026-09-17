"""
Raw Logs Router - REST API endpoints and WebSocket for the Live Log Viewer.

Endpoints:
- GET  /api/raw-logs/services         - List available services
- GET  /api/raw-logs/worker-status    - Worker health info
- GET  /api/raw-logs/{service}        - Query stored logs (paginated)
- GET  /api/raw-logs/{service}/smart-filters - Postfix smart filter definitions
- WS   /ws/raw-logs                   - WebSocket for real-time log streaming
"""
import logging
import asyncio
import json
import secrets
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Query, Path, WebSocket, WebSocketDisconnect, HTTPException
from sqlalchemy import func, desc, asc, or_, cast, String
from sqlalchemy.dialects.postgresql import JSONB

from ..database import get_db_context
from ..config import settings
from ..models import RawServiceLog
from ..raw_logs_worker import (
    SERVICE_METADATA,
    ALL_SERVICES,
    get_raw_logs_job_status,
    set_ws_broadcast_fn,
    set_ws_broadcast_all_fn,
)
from ..utils import internal_error

logger = logging.getLogger(__name__)

router = APIRouter()

# The WebSocket route is mounted at the application root (no /api prefix), so it
# lives on its own router. Mounting the whole router twice would also publish
# every HTTP route here under /raw-logs/..., which the auth middleware lets
# through unauthenticated because it only guards paths under /api/.
ws_router = APIRouter()

# ── WebSocket Auth Tokens (in-memory, short-lived) ─────────────────────────
_ws_tokens: Dict[str, float] = {}  # token -> expiry timestamp
_WS_TOKEN_TTL = 30  # seconds

def _cleanup_expired_tokens():
    """Remove expired tokens. Iterate over a snapshot so a concurrent
    mutation of _ws_tokens can never raise 'dictionary changed size'."""
    now = time.time()
    expired = [t for t, exp in list(_ws_tokens.items()) if exp < now]
    for t in expired:
        _ws_tokens.pop(t, None)


# =============================================================================
# WEBSOCKET MANAGER
# =============================================================================

WS_SEND_TIMEOUT_SECONDS = 10
WS_CLOSE_TIMEOUT_SECONDS = 1


class LogStreamManager:
    """Broadcast independently to viewers while serializing each socket's writes."""

    def __init__(self):
        self.connections: Dict[str, List[WebSocket]] = {}
        self._send_locks: Dict[WebSocket, asyncio.Lock] = {}

    async def connect(self, websocket: WebSocket, service: str):
        await websocket.accept()
        self._send_locks[websocket] = asyncio.Lock()
        self.connections.setdefault(service, []).append(websocket)

    async def disconnect(self, websocket: WebSocket, service: str):
        clients = self.connections.get(service, [])
        if websocket in clients:
            clients.remove(websocket)
        self._send_locks.pop(websocket, None)

    async def switch_service(self, websocket: WebSocket, old_service: str, new_service: str):
        if websocket not in self._send_locks:
            return False
        clients = self.connections.get(old_service, [])
        if websocket in clients:
            clients.remove(websocket)
        self.connections.setdefault(new_service, []).append(websocket)
        return True

    async def _drop(self, websocket: WebSocket):
        # A client may have switched service while its write was pending.
        if self._send_locks.pop(websocket, None) is None:
            return
        for clients in self.connections.values():
            if websocket in clients:
                clients.remove(websocket)
        try:
            await asyncio.wait_for(websocket.close(code=1013), WS_CLOSE_TIMEOUT_SECONDS)
        except Exception:
            pass  # The peer may already be gone or unable to receive a close frame.

    async def _send_text(self, websocket: WebSocket, text: str):
        lock = self._send_locks.get(websocket)
        if lock is None:
            return False
        try:
            # Include waiting for an earlier write in this client's time budget.
            async with asyncio.timeout(WS_SEND_TIMEOUT_SECONDS):
                async with lock:
                    if self._send_locks.get(websocket) is not lock:
                        return False
                    await websocket.send_text(text)
            return True
        except Exception:
            await self._drop(websocket)
            return False

    async def send_json(self, websocket: WebSocket, message: dict):
        return await self._send_text(websocket, json.dumps(message))

    async def _broadcast_text(self, clients, text):
        await asyncio.gather(*(self._send_text(ws, text) for ws in clients))

    async def broadcast(self, service: str, entries: List[dict]):
        clients = list(self.connections.get(service, []))
        if not clients:
            return
        text = json.dumps({
            "type": "new_logs",
            "service": service,
            "entries": entries,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        await self._broadcast_text(clients, text)

    def get_connection_count(self) -> Dict[str, int]:
        return {s: len(conns) for s, conns in self.connections.items() if conns}

    async def broadcast_to_all(self, message: dict):
        clients = [ws for conns in self.connections.values() for ws in conns]
        await self._broadcast_text(clients, json.dumps(message))


# Module-level instance
log_stream_manager = LogStreamManager()

# Register the broadcast functions with the worker
set_ws_broadcast_fn(log_stream_manager.broadcast)
set_ws_broadcast_all_fn(log_stream_manager.broadcast_to_all)


@router.get("/raw-logs/ws-token")
async def get_ws_token():
    """
    Issue a one-time short-lived token for WebSocket authentication.
    This endpoint is protected by the existing HTTP auth middleware,
    so only authenticated users can obtain a token.

    MUST stay ``async`` (run on the event loop): it mutates the in-memory
    ``_ws_tokens`` store that the async WebSocket endpoint also reads/pops.
    Running it in a threadpool (plain ``def``) races that store against the
    event loop and intermittently drops WebSocket connections under load.
    """
    _cleanup_expired_tokens()
    token = secrets.token_urlsafe(32)
    _ws_tokens[token] = time.time() + _WS_TOKEN_TTL
    return {"token": token, "ttl": _WS_TOKEN_TTL}


# =============================================================================
# WEBSOCKET ENDPOINT
# =============================================================================

@ws_router.websocket("/ws/raw-logs")
async def websocket_raw_logs(
    websocket: WebSocket,
    service: str = Query(default="postfix"),
    token: str = Query(default=None),
):
    """
    WebSocket endpoint for real-time log streaming.
    
    1. Client calls GET /api/raw-logs/ws-token (authenticated) to get a one-time token
    2. Client connects: wss://host/ws/raw-logs?service=postfix&token=<one-time-token>  # nosemgrep: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket
    
    Client can send messages to switch service:
      {"action": "subscribe", "service": "dovecot"}
    """
    # ── WebSocket Authentication ────────────────────────────────────────
    if settings.is_authentication_enabled:
        authenticated = False
        
        # Validate one-time token
        if token and token in _ws_tokens:
            if _ws_tokens[token] >= time.time():
                authenticated = True
                logger.debug("[WS Auth] One-time token verified")
            # Always consume the token (one-time use)
            _ws_tokens.pop(token, None)
        
        if not authenticated:
            logger.warning("[WS Auth] Unauthenticated WebSocket connection attempt")
            await websocket.accept()
            await websocket.send_json({
                "type": "error",
                "message": "Authentication required"
            })
            await websocket.close(code=4401, reason="Authentication required")
            return
    # ────────────────────────────────────────────────────────────────────
    
    # Validate service
    enabled = settings.raw_logs_services_list
    if service not in enabled:
        service = enabled[0] if enabled else "postfix"
    
    current_service = service
    await log_stream_manager.connect(websocket, current_service)
    
    try:
        # Send initial connection confirmation
        await log_stream_manager.send_json(websocket, {
            "type": "connected",
            "service": current_service,
            "message": f"Connected to {current_service} log stream"
        })
        
        # Listen for client messages (service switches, etc.)
        while True:
            try:
                data = await websocket.receive_text()
                msg = json.loads(data)

                if msg.get("action") == "subscribe":
                    new_service = msg.get("service", "").lower()
                    if new_service in enabled and new_service != current_service:
                        if not await log_stream_manager.switch_service(websocket, current_service, new_service):
                            break
                        current_service = new_service
                        await log_stream_manager.send_json(websocket, {
                            "type": "subscribed",
                            "service": current_service,
                            "message": f"Switched to {current_service} log stream"
                        })
                    elif new_service not in enabled:
                        await log_stream_manager.send_json(websocket, {
                            "type": "error",
                            "message": f"Service '{new_service}' is not enabled"
                        })
                        
            except WebSocketDisconnect:
                break
            except json.JSONDecodeError:
                pass  # Ignore malformed messages
            except Exception:
                break
    finally:
        await log_stream_manager.disconnect(websocket, current_service)


# =============================================================================
# REST API ENDPOINTS
# =============================================================================

@router.get("/raw-logs/services")
def get_services():
    """
    List available log services with metadata.
    Only returns services that are enabled in settings.
    """
    enabled = settings.raw_logs_services_list
    
    # Get log counts per service
    service_counts = {}
    try:
        with get_db_context() as db:
            counts = db.query(
                RawServiceLog.service,
                func.count(RawServiceLog.id)
            ).group_by(RawServiceLog.service).all()
            service_counts = {s: c for s, c in counts}
    except Exception as e:
        logger.error(f"Error fetching service counts: {e}")
    
    services = []
    for service_id in enabled:
        meta = SERVICE_METADATA.get(service_id, {})
        services.append({
            "id": service_id,
            "name": meta.get("name", service_id.title()),
            "icon": meta.get("icon", "file"),
            "description": meta.get("description", ""),
            "has_smart_filters": meta.get("has_smart_filters", False),
            "log_count": service_counts.get(service_id, 0),
        })
    
    # WebSocket connection info
    ws_connections = log_stream_manager.get_connection_count()
    
    return {
        "services": services,
        "ws_connections": ws_connections,
        "raw_logs_enabled": settings.raw_logs_enabled,
    }


@router.get("/raw-logs/worker-status")
def get_worker_status():
    """Worker health check - last fetch time, stats, errors"""
    status = get_raw_logs_job_status()
    return {
        "enabled": settings.raw_logs_enabled,
        "fetch_interval": settings.raw_logs_fetch_interval,
        "fetch_count": settings.raw_logs_fetch_count,
        "retention_days": settings.raw_logs_retention_days,
        "services": settings.raw_logs_services_list,
        "jobs": status,
        "ws_connections": log_stream_manager.get_connection_count(),
    }


@router.get("/raw-logs/{service}")
def get_raw_logs(
    service: str = Path(..., description="Service name (e.g., postfix, dovecot)"),
    page: int = Query(default=1, ge=1, description="Page number"),
    limit: int = Query(default=200, ge=1, le=1000, description="Results per page"),
    search: Optional[str] = Query(default=None, description="Search in log message"),
    program: Optional[str] = Query(default=None, description="Filter by program name"),
    start_date: Optional[str] = Query(default=None, description="Start date (ISO format)"),
    end_date: Optional[str] = Query(default=None, description="End date (ISO format)"),
    order: str = Query(default="desc", description="Sort order: asc or desc"),
    smart_filter: Optional[str] = Query(default=None, description="Comma-separated smart filter IDs"),
):
    """
    Query stored raw logs for a specific service.
    Used for initial page load, search, and historical queries.
    """
    enabled = settings.raw_logs_services_list
    if service not in enabled and service not in ALL_SERVICES:
        raise HTTPException(status_code=404, detail=f"Service '{service}' not found")

    try:
        with get_db_context() as db:
            query = db.query(RawServiceLog).filter(RawServiceLog.service == service)

            # Date range filter
            if start_date:
                try:
                    start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                    query = query.filter(RawServiceLog.time >= start_dt)
                except ValueError:
                    pass
            
            if end_date:
                try:
                    end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                    query = query.filter(RawServiceLog.time <= end_dt)
                except ValueError:
                    pass
            
            # Text search in raw_data JSONB
            if search:
                search_term = f"%{search}%"
                if service == "rspamd-history":
                    # Rspamd history has subject, sender_smtp, sender_mime, ip - no 'message' field
                    query = query.filter(
                        or_(
                            cast(RawServiceLog.raw_data['subject'], String).ilike(search_term),
                            cast(RawServiceLog.raw_data['sender_smtp'], String).ilike(search_term),
                            cast(RawServiceLog.raw_data['sender_mime'], String).ilike(search_term),
                            cast(RawServiceLog.raw_data['ip'], String).ilike(search_term),
                            cast(RawServiceLog.raw_data['action'], String).ilike(search_term),
                        )
                    )
                else:
                    query = query.filter(
                        cast(RawServiceLog.raw_data['message'], String).ilike(search_term)
                    )
            
            # Program filter
            if program:
                query = query.filter(
                    cast(RawServiceLog.raw_data['program'], String).ilike(f"%{program}%")
                )
            
            # Smart filters (Postfix-specific patterns)
            if smart_filter and service == "postfix":
                filters = smart_filter.split(',')
                smart_conditions = _build_smart_filter_conditions(filters)
                if smart_conditions:
                    query = query.filter(or_(*smart_conditions))
            
            # Get total count
            total = query.count()
            
            # Sort
            if order == "asc":
                query = query.order_by(asc(RawServiceLog.time))
            else:
                query = query.order_by(desc(RawServiceLog.time))
            
            # Paginate
            offset = (page - 1) * limit
            logs = query.offset(offset).limit(limit).all()
            
            # Build response
            data = []
            for log in logs:
                entry = log.raw_data.copy() if log.raw_data else {}
                entry['_id'] = log.id
                entry['_service'] = log.service
                entry['_stored_at'] = log.created_at.isoformat() if log.created_at else None
                data.append(entry)
            
            return {
                "data": data,
                "page": page,
                "limit": limit,
                "total": total,
                "pages": max(1, (total + limit - 1) // limit),
                "service": service,
            }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error querying raw logs for {service}: {e}")
        raise internal_error(e)


@router.get("/raw-logs/{service}/smart-filters")
def get_smart_filters(
    service: str = Path(..., description="Service name"),
):
    """
    Get available smart filters for a service.
    Currently only Postfix has smart filters.
    """
    if service != "postfix":
        return {"filters": [], "service": service}
    
    return {
        "service": "postfix",
        "filters": [
            {
                "id": "postscreen",
                "label": "Postscreen",
                "pattern": "postfix/postscreen",
                "field": "program",
                "color": "red",
                "description": "Postscreen connection filtering"
            },
            {
                "id": "noqueue_reject",
                "label": "NOQUEUE Reject",
                "pattern": "NOQUEUE: reject",
                "field": "message",
                "color": "orange",
                "description": "Pre-queue rejections"
            },
            {
                "id": "dnsbl",
                "label": "DNSBL Block",
                "pattern": "blocked using",
                "field": "message",
                "color": "red",
                "description": "DNS blacklist blocks"
            },
            {
                "id": "pregreet",
                "label": "Pregreet",
                "pattern": "PREGREET",
                "field": "message",
                "color": "yellow",
                "description": "Pregreet protocol violations"
            },
            {
                "id": "sender_restrict",
                "label": "Sender Restriction",
                "pattern": "Sender address rejected",
                "field": "message",
                "color": "orange",
                "description": "Sender address restrictions"
            },
            {
                "id": "recipient_restrict",
                "label": "Recipient Restriction",
                "pattern": "Recipient address rejected",
                "field": "message",
                "color": "orange",
                "description": "Recipient address restrictions"
            },
            {
                "id": "relay_restrict",
                "label": "Relay Denied",
                "pattern": "Relay access denied",
                "field": "message",
                "color": "red",
                "description": "Relay access denied"
            },
            {
                "id": "connections",
                "label": "Connections",
                "pattern": "CONNECT",
                "field": "message",
                "color": "blue",
                "description": "Connection events"
            },
        ]
    }


def _build_smart_filter_conditions(filter_ids: List[str]):
    """Build SQLAlchemy filter conditions from smart filter IDs"""
    # Smart filter definitions
    filter_map = {
        "postscreen":        ("program", "postfix/postscreen"),
        "noqueue_reject":    ("message", "NOQUEUE: reject"),
        "dnsbl":             ("message", "blocked using"),
        "pregreet":          ("message", "PREGREET"),
        "sender_restrict":   ("message", "Sender address rejected"),
        "recipient_restrict":("message", "Recipient address rejected"),
        "relay_restrict":    ("message", "Relay access denied"),
        "connections":       ("message", "CONNECT"),
    }
    
    conditions = []
    for fid in filter_ids:
        fid = fid.strip()
        if fid in filter_map:
            field, pattern = filter_map[fid]
            conditions.append(
                cast(RawServiceLog.raw_data[field], String).ilike(f"%{pattern}%")
            )
    
    return conditions
