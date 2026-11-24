import ipaddress
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qs

from sqlalchemy import case, func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from ..models import EasDevice
from .db_values import is_row_error as _is_row_error

logger = logging.getLogger(__name__)

EAS_PATH = '/microsoft-server-activesync'

_LINE_RE = re.compile(
    r'^(?:\[\d+\]:\s*)?(?P<remote>[^"]*?)\s+"(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+HTTP/[\d.]+"\s+(?P<status>\d{3})\b'
)

_CONTROL_RE = re.compile(r'[\x00-\x1f\x7f-\x9f]')


def _param(query: Dict[str, List[str]], name: str) -> Optional[str]:
    for key, values in query.items():
        if key.lower() == name and values:
            value = values[0].strip()
            return value or None
    return None


def _ip_or_none(remote: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(remote.split(',')[0].strip()))
    except ValueError:
        return None


def parse_eas_line(message: str) -> Optional[Dict[str, Any]]:
    if not isinstance(message, str) or 'activesync' not in message.lower():
        return None
    match = _LINE_RE.match(message.strip())
    if not match:
        return None
    path, _, query_string = match.group('target').partition('?')
    if not path.lower().endswith(EAS_PATH) or not query_string:
        return None
    query = parse_qs(query_string, keep_blank_values=False)
    user = _param(query, 'user')
    device_id = _param(query, 'deviceid')
    if not user or not device_id:
        return None
    device_type = _param(query, 'devicetype')
    command = _param(query, 'cmd')
    if any(_CONTROL_RE.search(value) for value in (user, device_id, device_type, command) if value):
        return None
    return {
        'username': user.lower()[:255],
        'device_id': device_id[:255],
        'device_type': device_type[:100] if device_type else None,
        'last_command': command[:64] if command else None,
        'last_ip': _ip_or_none(match.group('remote')),
        'last_status': int(match.group('status')),
    }


_CLIENTS = (
    (lambda i, t: t == 'outlook', 'Outlook'),
    (lambda i, t: t == 'windowsmail', 'Windows Mail'),
    (lambda i, t: i.startswith('appl'), 'Apple Mail'),
    (lambda i, t: i.startswith('sec') or t.startswith('samsung'), 'Samsung Email'),
    (lambda i, t: i.startswith('androidc') and t == 'android', 'Gmail'),
)

_SAMSUNG_MODEL = re.compile(r'^SAMSUNG(SM)([A-Z0-9]+)$', re.IGNORECASE)


def describe_device(device_id: Optional[str], device_type: Optional[str]) -> Dict[str, Optional[str]]:
    i, t = (device_id or '').lower(), (device_type or '').lower()
    client = next((name for match, name in _CLIENTS if match(i, t)), None)
    model = _SAMSUNG_MODEL.match(device_type or '')
    return {
        'client': client,
        'model': f"{model.group(1).upper()}-{model.group(2).upper()}" if model else None,
    }


def _entry_time(entry: Dict[str, Any]) -> Optional[datetime]:
    try:
        epoch = float(entry.get('time'))
    except (TypeError, ValueError):
        return None
    if epoch <= 0:
        return None
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).replace(tzinfo=None)
    except (OverflowError, OSError, ValueError):
        return None


def collect_devices(entries: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    devices: Dict[tuple, Dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        parsed = parse_eas_line(entry.get('message') or '')
        when = _entry_time(entry)
        if parsed is None or when is None:
            continue
        key = (parsed['username'], parsed['device_id'])
        known = devices.get(key)
        if known is None:
            devices[key] = {**parsed, 'first_seen': when, 'last_seen': when}
            continue
        if when < known['first_seen']:
            known['first_seen'] = when
        if when >= known['last_seen']:
            known.update(parsed, last_seen=when)
    return list(devices.values())


def store_devices(db: Session, devices: List[Dict[str, Any]]) -> int:
    if not devices:
        return 0
    try:
        with db.begin_nested():
            db.execute(_upsert(devices))
        written = len(devices)
    except Exception as error:
        if not _is_row_error(error):
            raise
        written = sum(_store_one(db, device) for device in devices)
    db.commit()
    return written


def _store_one(db: Session, device: Dict[str, Any]) -> int:
    try:
        with db.begin_nested():
            db.execute(_upsert([device]))
        return 1
    except Exception as error:
        if not _is_row_error(error):
            raise
        code = getattr(getattr(error, 'orig', None), 'pgcode', None)
        logger.warning(
            "[DEVICES] Skipped an ActiveSync device the database refused - user %r, device %r (%s%s)",
            str(device.get('username'))[:64], str(device.get('device_id'))[:64],
            type(error).__name__, f" {code}" if code else '',
        )
        return 0


def _upsert(devices: List[Dict[str, Any]]):
    table = EasDevice.__table__
    stmt = insert(table).values(devices)
    new = stmt.excluded
    newer = new.last_seen >= table.c.last_seen

    def follow_newest(column: str):
        if column in ('device_type', 'last_ip'):
            value = func.coalesce(new[column], table.c[column])
        else:
            value = new[column]
        return case((newer, value), else_=table.c[column])

    return stmt.on_conflict_do_update(
        constraint='uq_eas_device',
        set_={
            'first_seen': func.least(table.c.first_seen, new.first_seen),
            'last_seen': func.greatest(table.c.last_seen, new.last_seen),
            **{c: follow_newest(c) for c in ('device_type', 'last_ip', 'last_command', 'last_status')},
        },
    )


def delete_stale_devices(db: Session, retention_days: int) -> int:
    if retention_days <= 0:
        return 0
    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    deleted = db.query(EasDevice).filter(EasDevice.last_seen < cutoff).delete(synchronize_session=False)
    db.commit()
    return deleted
