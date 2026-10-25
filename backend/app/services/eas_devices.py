"""
ActiveSync devices, read from SOGo's access log.

mailcow proxies /Microsoft-Server-ActiveSync to SOGo, and SOGo writes one
access line per request, which the mailcow API returns under logs/sogo:

    [61]: 203.0.113.7 "POST /SOGo/Microsoft-Server-ActiveSync?User=jane%40example.com&DeviceId=ABC123&DeviceType=iPhone&Cmd=Ping HTTP/1.1" 200 13/0 600.012 - - 0 - 15

The query names the user, the device and the command, so the newest line per
(user, device id) is all a device inventory needs. The base64-encoded query
form of the protocol carries no user name and is skipped.

A Ping is a long poll (SOGo's maximum is 3540 seconds in mailcow) and the
line is written when it ends, so a connected phone can look up to an hour
old.
"""
import ipaddress
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qs

from sqlalchemy import case, func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import DataError
from sqlalchemy.orm import Session

from ..models import EasDevice

logger = logging.getLogger(__name__)

EAS_PATH = '/microsoft-server-activesync'

# "[pid]: " is optional: the prefix is not part of every SOGo line. Behind a
# second proxy the client can be an X-Forwarded-For list ("client, proxy").
_LINE_RE = re.compile(
    r'^(?:\[\d+\]:\s*)?(?P<remote>[^"]*?)\s+"(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+HTTP/[\d.]+"\s+(?P<status>\d{3})\b'
)

# The query is the client's choice and percent-decoding can put any character
# in a value. No real user, device id, type or command holds a control
# character, and PostgreSQL text cannot hold NUL at all
_CONTROL_RE = re.compile(r'[\x00-\x1f\x7f-\x9f]')


def _param(query: Dict[str, List[str]], name: str) -> Optional[str]:
    """First value of a query parameter, matched case-insensitively."""
    for key, values in query.items():
        if key.lower() == name and values:
            value = values[0].strip()
            return value or None
    return None


def _ip_or_none(remote: str) -> Optional[str]:
    """The client address; of a forwarded list, the first (the client's)."""
    try:
        return str(ipaddress.ip_address(remote.split(',')[0].strip()))
    except ValueError:
        return None


def parse_eas_line(message: str) -> Optional[Dict[str, Any]]:
    """The device fields of one SOGo access line, or None for any line that is
    not a plain-query ActiveSync request with a user and a device id."""
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


# The mail app behind a device, recognised by how it names itself. These are
# conventions of each app, not part of the protocol, so an app that matches
# none of them gets no name rather than a guess.
_CLIENTS = (
    (lambda i, t: t == 'outlook', 'Outlook'),
    (lambda i, t: t == 'windowsmail', 'Windows Mail'),
    (lambda i, t: i.startswith('appl'), 'Apple Mail'),
    (lambda i, t: i.startswith('sec') or t.startswith('samsung'), 'Samsung Email'),
    # Gmail names devices the way Android's own mail code does, which a few
    # phone makers' mail apps share; the page says so in a tooltip
    (lambda i, t: i.startswith('androidc') and t == 'android', 'Gmail'),
)

# Samsung Email reports the model code: SAMSUNGSMS918B is the SM-S918B
_SAMSUNG_MODEL = re.compile(r'^SAMSUNG(SM)([A-Z0-9]+)$', re.IGNORECASE)


def describe_device(device_id: Optional[str], device_type: Optional[str]) -> Dict[str, Optional[str]]:
    """The likely mail app and a readable model for a recorded device."""
    i, t = (device_id or '').lower(), (device_type or '').lower()
    client = next((name for match, name in _CLIENTS if match(i, t)), None)
    model = _SAMSUNG_MODEL.match(device_type or '')
    return {
        'client': client,
        'model': f"{model.group(1).upper()}-{model.group(2).upper()}" if model else None,
    }


def _entry_time(entry: Dict[str, Any]) -> Optional[datetime]:
    """The line's own time as naive UTC, like the other tables."""
    try:
        epoch = float(entry.get('time'))
    except (TypeError, ValueError):
        return None
    if epoch <= 0:
        return None
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).replace(tzinfo=None)
    except (OverflowError, OSError, ValueError):
        # nan, inf or a year no datetime can hold
        return None


def collect_devices(entries: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The newest request per (user, device id), with the oldest time seen in
    the same batch as its first_seen."""
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
    """Upsert the devices. The same line read again in a later cycle changes
    nothing: first_seen only moves back, last_seen only forward, and the
    request fields follow the newest line.

    A device the database refuses for its own values is logged and skipped,
    so one line cannot hold back the others behind it. Any other failure,
    such as a lost connection, is raised with nothing committed, and the job
    reads the same lines again. Commits; returns the rows written."""
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


# SQLSTATE class 22 is a value the column cannot hold, except 2200H, a spent
# id sequence, which fails every row alike
_SPENT_SEQUENCE = '2200H'


def _is_row_error(error: Exception) -> bool:
    """Whether the database refused a row for the row's own values. psycopg2
    refuses NUL with a bare ValueError before the statement is sent."""
    if isinstance(error, ValueError):
        return True
    if isinstance(error, DataError):
        code = getattr(error.orig, 'pgcode', None) or ''
        return code.startswith('22') and code != _SPENT_SEQUENCE
    return False


def _store_one(db: Session, device: Dict[str, Any]) -> int:
    try:
        with db.begin_nested():
            db.execute(_upsert([device]))
        return 1
    except Exception as error:
        if not _is_row_error(error):
            raise
        # Neither the statement nor its parameters: only the fields that name
        # the device, escaped and cut short, and why it was refused
        orig = getattr(error, 'orig', None)
        reason = getattr(getattr(orig, 'diag', None), 'message_primary', None) or str(error)
        logger.warning(
            "[DEVICES] Skipped an ActiveSync device the database refused - user %r, device %r: %s",
            str(device.get('username'))[:64], str(device.get('device_id'))[:64], reason[:200],
        )
        return 0


def _upsert(devices: List[Dict[str, Any]]):
    table = EasDevice.__table__
    stmt = insert(table).values(devices)
    new = stmt.excluded
    newer = new.last_seen >= table.c.last_seen

    def follow_newest(column: str):
        # A Ping without DeviceType must not erase the type a Sync reported
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
    """Forget devices not seen for retention_days; 0 keeps them forever."""
    if retention_days <= 0:
        return 0
    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    deleted = db.query(EasDevice).filter(EasDevice.last_seen < cutoff).delete(synchronize_session=False)
    db.commit()
    return deleted
