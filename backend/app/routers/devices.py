"""
ActiveSync devices for the Devices page, recorded from SOGo's access log by
the eas_devices job (services/eas_devices.py).
"""
import logging
import math
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import EasDevice
from ..scheduler import get_job_status
from ..services import geoip_service
from ..utils import format_datetime_for_api as format_datetime_utc

logger = logging.getLogger(__name__)

router = APIRouter()

# A Ping can hold the connection for up to an hour before SOGo logs it, so
# "recent" has to be wider than that to mean "this phone is connected"
RECENT_HOURS = 24
NEW_DAYS = 7
STALE_DAYS = 30

_SORT_COLUMNS = {
    'username': EasDevice.username,
    'device_type': EasDevice.device_type,
    'last_ip': EasDevice.last_ip,
    'last_command': EasDevice.last_command,
    'first_seen': EasDevice.first_seen,
    'last_seen': EasDevice.last_seen,
}


def _like(term: str) -> str:
    escaped = term.lower().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
    return f"%{escaped}%"


def _location(ip: Optional[str], geoip: bool) -> dict:
    """Country, city and network of the last IP, looked up when the page is
    read so a newer GeoIP database applies to every device."""
    geo = geoip_service.lookup_ip(ip) if (geoip and ip) else {}
    return {key: geo.get(key) for key in ('country_code', 'country_name', 'city', 'asn', 'asn_org')}


def _device_json(d: EasDevice, geoip: bool) -> dict:
    return {
        **_location(d.last_ip, geoip),
        'id': d.id,
        'username': d.username,
        'device_id': d.device_id,
        'device_type': d.device_type,
        'last_ip': d.last_ip,
        'last_command': d.last_command,
        'last_status': d.last_status,
        'first_seen': format_datetime_utc(d.first_seen),
        'last_seen': format_datetime_utc(d.last_seen),
    }


@router.get("/devices")
def list_devices(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    search: Optional[str] = None,
    device_type: Optional[str] = None,
    seen: str = Query("all", pattern="^(all|recent|new|stale)$"),
    sort_by: str = Query("last_seen", pattern="^(username|device_type|last_ip|last_command|first_seen|last_seen)$"),
    sort_dir: str = Query("desc", pattern="^(asc|desc)$"),
):
    """The recorded ActiveSync devices, filtered, sorted and paged, with the
    page's summary figures and the state of the job that records them."""
    now = datetime.utcnow()
    recent_after = now - timedelta(hours=RECENT_HOURS)
    new_after = now - timedelta(days=NEW_DAYS)
    stale_before = now - timedelta(days=STALE_DAYS)

    summary_row = db.query(
        func.count(EasDevice.id),
        func.count(func.distinct(EasDevice.username)),
        func.count(EasDevice.id).filter(EasDevice.last_seen >= recent_after),
        func.count(EasDevice.id).filter(EasDevice.first_seen >= new_after),
        func.count(EasDevice.id).filter(EasDevice.last_seen < stale_before),
    ).one()
    types = [t for (t,) in db.query(EasDevice.device_type).filter(
        EasDevice.device_type.isnot(None)).distinct().order_by(EasDevice.device_type).all()]

    query = db.query(EasDevice)
    if search and search.strip():
        term = _like(search.strip())
        query = query.filter(or_(
            func.lower(EasDevice.username).like(term, escape='\\'),
            func.lower(EasDevice.device_id).like(term, escape='\\'),
            func.lower(EasDevice.device_type).like(term, escape='\\'),
            func.lower(EasDevice.last_ip).like(term, escape='\\'),
        ))
    if device_type:
        query = query.filter(EasDevice.device_type == device_type)
    if seen == 'recent':
        query = query.filter(EasDevice.last_seen >= recent_after)
    elif seen == 'new':
        query = query.filter(EasDevice.first_seen >= new_after)
    elif seen == 'stale':
        query = query.filter(EasDevice.last_seen < stale_before)

    total = query.count()
    column = _SORT_COLUMNS[sort_by]
    order = column.asc().nullslast() if sort_dir == 'asc' else column.desc().nullslast()
    rows = query.order_by(order, EasDevice.id).offset((page - 1) * per_page).limit(per_page).all()

    job = get_job_status().get('eas_devices', {})
    geoip = bool(geoip_service.is_geoip_available())
    return {
        'items': [_device_json(d, geoip) for d in rows],
        'geoip': geoip,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': max(1, math.ceil(total / per_page)),
        'summary': {
            'devices': summary_row[0],
            'users': summary_row[1],
            'recent': summary_row[2],
            'new': summary_row[3],
            'stale': summary_row[4],
        },
        'device_types': types,
        'thresholds': {'recent_hours': RECENT_HOURS, 'new_days': NEW_DAYS, 'stale_days': STALE_DAYS},
        'retention_days': settings.eas_devices_retention_days,
        'last_run': format_datetime_utc(job.get('last_run')),
        'last_status': job.get('status'),
    }
