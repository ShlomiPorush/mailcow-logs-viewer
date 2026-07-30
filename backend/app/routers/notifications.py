"""
Notification channels API - manage where alerts are delivered.

Multiple channels can be configured (Slack, Telegram, ntfy, ...); every alert
goes to all enabled ones. Secrets are masked in responses and preserved when
the UI sends the mask back unchanged.
"""
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import NotificationChannel
from ..services import notification_channels as nc
from ..utils import internal_error, format_datetime_for_api

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/notifications")


class ChannelRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    channel_type: str
    config: Dict = Field(default_factory=dict)
    alert_types: Optional[List[str]] = None   # None/empty = every alert
    enabled: bool = True


class ChannelTestRequest(BaseModel):
    """Test an unsaved channel (the Test button in the editor)."""
    channel_type: str
    config: Dict = Field(default_factory=dict)


def _clean_alert_types(alert_types: Optional[List[str]]) -> Optional[List[str]]:
    """Keep only known topic ids. Empty means "every alert" (stored as NULL)."""
    if not alert_types:
        return None
    cleaned = [t for t in alert_types if t in nc.ALERT_TYPE_IDS]
    unknown = set(alert_types) - nc.ALERT_TYPE_IDS
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown alert type(s): {', '.join(sorted(unknown))}")
    # Subscribing to everything is the same as no filter
    return None if len(cleaned) == len(nc.ALERT_TYPE_IDS) else cleaned


def _serialize(c: NotificationChannel) -> Dict:
    return {
        "id": c.id,
        "name": c.name,
        "channel_type": c.channel_type,
        "config": nc.mask_config(c.channel_type, c.config),
        "alert_types": c.alert_types or [],
        "enabled": c.enabled,
        "last_status": c.last_status,
        "last_error": c.last_error,
        "last_sent_at": format_datetime_for_api(c.last_sent_at),
    }


@router.get("/types")
def get_channel_types():
    """Field specs per channel type - drives the settings UI."""
    return {
        "types": [
            {"id": ctype, "label": spec["label"], "help": spec["help"], "fields": spec["fields"]}
            for ctype, spec in nc.CHANNEL_TYPES.items()
        ],
        "alert_types": nc.ALERT_TYPES,
    }


@router.get("/channels")
def list_channels(db: Session = Depends(get_db)):
    """All configured channels (secrets masked)."""
    try:
        rows = db.query(NotificationChannel).order_by(NotificationChannel.id).all()
        return {"channels": [_serialize(c) for c in rows]}
    except Exception as e:
        logger.error(f"Error listing notification channels: {e}")
        raise internal_error(e)


@router.post("/channels")
def create_channel(request: ChannelRequest, db: Session = Depends(get_db)):
    """Add a channel."""
    if request.channel_type not in nc.CHANNEL_TYPES:
        raise HTTPException(status_code=422, detail=f"Unknown channel type: {request.channel_type}")
    # On create there is no stored secret behind the mask placeholder - treat
    # a literal mask as empty so validation rejects it instead of storing it
    config = {k: ("" if v == nc.MASK else v) for k, v in (request.config or {}).items()}
    ok, error = nc.validate_config(request.channel_type, config)
    if not ok:
        raise HTTPException(status_code=422, detail=error)
    alert_types = _clean_alert_types(request.alert_types)
    try:
        channel = NotificationChannel(
            name=request.name.strip(),
            channel_type=request.channel_type,
            config=config,
            alert_types=alert_types,
            enabled=request.enabled,
            created_at=datetime.utcnow(),
        )
        db.add(channel)
        db.commit()
        db.refresh(channel)
        return _serialize(channel)
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating notification channel: {e}")
        raise internal_error(e)


@router.put("/channels/{channel_id}")
def update_channel(channel_id: int, request: ChannelRequest, db: Session = Depends(get_db)):
    """Update a channel. Masked secrets left untouched keep their stored value."""
    if request.channel_type not in nc.CHANNEL_TYPES:
        raise HTTPException(status_code=422, detail=f"Unknown channel type: {request.channel_type}")
    try:
        channel = db.query(NotificationChannel).filter(NotificationChannel.id == channel_id).first()
        if not channel:
            raise HTTPException(status_code=404, detail="Channel not found")

        merged = nc.merge_config(request.channel_type, channel.config or {}, request.config)
        ok, error = nc.validate_config(request.channel_type, merged)
        if not ok:
            raise HTTPException(status_code=422, detail=error)

        channel.name = request.name.strip()
        channel.channel_type = request.channel_type
        channel.config = merged
        channel.alert_types = _clean_alert_types(request.alert_types)
        channel.enabled = request.enabled
        db.commit()
        db.refresh(channel)
        return _serialize(channel)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating notification channel: {e}")
        raise internal_error(e)


@router.delete("/channels/{channel_id}")
def delete_channel(channel_id: int, db: Session = Depends(get_db)):
    """Remove a channel."""
    try:
        channel = db.query(NotificationChannel).filter(NotificationChannel.id == channel_id).first()
        if not channel:
            raise HTTPException(status_code=404, detail="Channel not found")
        db.delete(channel)
        db.commit()
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting notification channel: {e}")
        raise internal_error(e)


@router.post("/channels/{channel_id}/test")
async def test_saved_channel(channel_id: int):
    """Send a test notification to a saved channel."""
    from ..database import get_db_context

    def _load():
        with get_db_context() as db:
            c = db.query(NotificationChannel).filter(NotificationChannel.id == channel_id).first()
            if not c:
                return None
            return {"id": c.id, "type": c.channel_type, "config": c.config or {}, "name": c.name}

    channel = await asyncio.to_thread(_load)
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")

    ok, error = await asyncio.to_thread(
        nc.send_to_config, channel["type"], channel["config"],
        "Test notification",
        "This is a test notification from mailcow Logs Viewer. "
        "If you can read this, the channel is working."
    )
    await asyncio.to_thread(nc._record_result, channel["id"], ok, error)
    return {
        "success": ok,
        "logs": [
            f"Channel: {channel['name']} ({channel['type']})",
            "Sending test notification...",
            "Delivered successfully" if ok else f"Failed: {error}",
        ],
    }


@router.post("/test")
async def test_unsaved_channel(request: ChannelTestRequest):
    """Test a channel configuration before saving it."""
    if request.channel_type not in nc.CHANNEL_TYPES:
        raise HTTPException(status_code=422, detail=f"Unknown channel type: {request.channel_type}")
    ok, error = await asyncio.to_thread(
        nc.send_to_config, request.channel_type, request.config,
        "Test notification",
        "This is a test notification from mailcow Logs Viewer. "
        "If you can read this, the channel is working."
    )
    return {
        "success": ok,
        "logs": [
            f"Channel type: {request.channel_type}",
            "Sending test notification...",
            "Delivered successfully" if ok else f"Failed: {error}",
        ],
    }
