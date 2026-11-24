import functools
import hashlib
import json
import logging
from typing import Dict, Any, Optional

from sqlalchemy.orm import Session

from ..models import SystemSetting
from ..utils import format_datetime_for_api

logger = logging.getLogger(__name__)

CONFIG_PREFIX = "config."


def _serialize_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return str(value)


_TRUE = frozenset({"true", "1", "yes", "on", "t", "y"})
_FALSE = frozenset({"false", "0", "no", "off", "f", "n"})


def parse_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in _TRUE:
            return True
        if text in _FALSE:
            return False
    return None


def _get_effective_type(annotation: type) -> type:
    if getattr(annotation, "__args__", None):
        args = [a for a in annotation.__args__ if a is not type(None)]
        if args:
            return args[0]
    return annotation


def _deserialize_value(value_str: str, field_name: str, annotation: type) -> Any:
    effective = _get_effective_type(annotation)
    is_optional = getattr(annotation, "__args__", None) and type(None) in getattr(annotation, "__args__", ())
    if value_str is None or value_str == "":
        if is_optional:
            return None
        if effective == bool:
            return False
        if effective == int:
            return 0
        return ""
    if effective == bool:
        return parse_bool(value_str) is True
    if effective == int:
        try:
            return int(value_str)
        except ValueError:
            return 0
    if effective == float:
        try:
            return float(value_str)
        except ValueError:
            return 0.0
    return value_str


def has_config_overrides_in_db(db: Session) -> bool:
    return db.query(SystemSetting).filter(SystemSetting.key.startswith(CONFIG_PREFIX)).first() is not None


def get_config_overrides_from_db(db: Session, field_types: Dict[str, type]) -> Dict[str, Any]:
    rows = db.query(SystemSetting).filter(SystemSetting.key.startswith(CONFIG_PREFIX)).all()
    out = {}
    for row in rows:
        key = row.key
        if not key.startswith(CONFIG_PREFIX):
            continue
        field_name = key[len(CONFIG_PREFIX) :]
        if field_name not in field_types:
            continue
        annotation = field_types[field_name]
        try:
            out[field_name] = _deserialize_value(row.value or "", field_name, annotation)
        except Exception as e:
            logger.warning("Skip config key %s: %s", field_name, e)
    return out


def save_config_overrides_to_db(db: Session, overrides: Dict[str, Any]) -> None:
    for field_name, value in overrides.items():
        key = CONFIG_PREFIX + field_name
        value_str = _serialize_value(value)
        row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
        if row:
            row.value = value_str
        else:
            row = SystemSetting(key=key, value=value_str)
            db.add(row)
    db.commit()


def delete_all_config_overrides_from_db(db: Session) -> None:
    db.query(SystemSetting).filter(SystemSetting.key.startswith(CONFIG_PREFIX)).delete(synchronize_session=False)
    db.commit()


_MAXMIND_PREFIX = "maxmind."


def _utc_z(stored: str):
    if not stored:
        return None
    from datetime import datetime
    try:
        return format_datetime_for_api(datetime.fromisoformat(stored.replace("Z", "+00:00")))
    except ValueError:
        return None


def get_maxmind_validation_status(db: Session) -> dict:
    rows = db.query(SystemSetting).filter(SystemSetting.key.startswith(_MAXMIND_PREFIX)).all()
    if not rows:
        return None
    data = {row.key[len(_MAXMIND_PREFIX):]: row.value for row in rows}
    configured = data.get("license_configured", "false").lower() == "true"
    valid = data.get("license_valid", "false").lower() == "true"
    error = data.get("license_error", "") or None
    checked_at = data.get("license_checked_at", "")
    return {
        "configured": configured,
        "valid": valid,
        "error": error,
        "checked_at": _utc_z(checked_at)
    }


def save_maxmind_validation_status(db: Session, result: dict) -> None:
    from datetime import datetime, timezone
    pairs = {
        "license_configured": "true" if result.get("configured") else "false",
        "license_valid": "true" if result.get("valid") else "false",
        "license_error": result.get("error") or "",
        "license_checked_at": format_datetime_for_api(datetime.now(timezone.utc)),
    }
    for suffix, value in pairs.items():
        key = _MAXMIND_PREFIX + suffix
        row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
        if row:
            row.value = value
        else:
            row = SystemSetting(key=key, value=value)
            db.add(row)
    db.commit()


def clear_maxmind_validation_status(db: Session) -> None:
    db.query(SystemSetting).filter(SystemSetting.key.startswith(_MAXMIND_PREFIX)).delete(synchronize_session=False)
    db.commit()


_CREDENTIAL_CHECK_PREFIX = "credential_check."


@functools.lru_cache(maxsize=16)
def credential_fingerprint(*parts: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        "\n".join(p or "" for p in parts).encode("utf-8"),
        b"mailcow-logs-viewer credential check",
        100_000,
    ).hex()[:16]


def get_credential_check_status(db: Session, name: str, fingerprint: str) -> dict:
    row = db.query(SystemSetting).filter(SystemSetting.key == _CREDENTIAL_CHECK_PREFIX + name).first()
    if not row or not row.value:
        return None
    try:
        data = json.loads(row.value)
    except ValueError:
        return None
    if data.get("fingerprint") != fingerprint:
        return None
    data.pop("fingerprint", None)
    if "checked_at" in data:
        data["checked_at"] = _utc_z(data["checked_at"])
    return data


def save_credential_check_status(db: Session, name: str, result: dict, fingerprint: str) -> None:
    from datetime import datetime, timezone
    data = {**result, "fingerprint": fingerprint, "checked_at": format_datetime_for_api(datetime.now(timezone.utc))}
    key = _CREDENTIAL_CHECK_PREFIX + name
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    if row:
        row.value = json.dumps(data)
    else:
        db.add(SystemSetting(key=key, value=json.dumps(data)))
    db.commit()
