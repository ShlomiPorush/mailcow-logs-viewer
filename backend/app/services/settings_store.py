"""
Load/save app config overrides from DB (system_settings table, keys config.*).
Used when SETTINGS_EDIT_VIA_UI_ENABLED is True.
"""
import functools
import hashlib
import json
import logging
from typing import Dict, Any

from sqlalchemy.orm import Session

from ..models import SystemSetting

logger = logging.getLogger(__name__)

CONFIG_PREFIX = "config."


def _serialize_value(value: Any) -> str:
    """Serialize a Python value to string for DB storage."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return str(value)


def _get_effective_type(annotation: type) -> type:
    """Resolve Optional[X] / Union[X, None] to X for type-based coercion."""
    if getattr(annotation, "__args__", None):
        args = [a for a in annotation.__args__ if a is not type(None)]
        if args:
            return args[0]
    return annotation


def _deserialize_value(value_str: str, field_name: str, annotation: type) -> Any:
    """Deserialize DB string to Python value based on field type."""
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
        return value_str.lower() in ("true", "1", "yes")
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
    """Return True if any config.* override exists in system_settings (migration was done)."""
    return db.query(SystemSetting).filter(SystemSetting.key.startswith(CONFIG_PREFIX)).first() is not None


def get_config_overrides_from_db(db: Session, field_types: Dict[str, type]) -> Dict[str, Any]:
    """
    Load all config.* keys from system_settings and return as dict of field_name -> value.
    Values are coerced to types from field_types (e.g. from Settings model).
    """
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
    """
    Upsert config overrides into system_settings (keys config.<field_name>).
    Only keys present in overrides are updated; pass full set to replace all UI config.
    """
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
    """Remove all config.* keys from system_settings (e.g. to reset to ENV-only)."""
    db.query(SystemSetting).filter(SystemSetting.key.startswith(CONFIG_PREFIX)).delete(synchronize_session=False)
    db.commit()


# ── MaxMind license validation status persistence ─────────────────────────

_MAXMIND_PREFIX = "maxmind."

def get_maxmind_validation_status(db: Session) -> dict:
    """Read the last MaxMind license validation result from DB.
    Returns None if never checked, or a dict with configured/valid/error/checked_at."""
    rows = db.query(SystemSetting).filter(SystemSetting.key.startswith(_MAXMIND_PREFIX)).all()
    if not rows:
        return None
    data = {row.key[len(_MAXMIND_PREFIX):]: row.value for row in rows}
    # Parse boolean strings
    configured = data.get("license_configured", "false").lower() == "true"
    valid = data.get("license_valid", "false").lower() == "true"
    error = data.get("license_error", "") or None
    checked_at = data.get("license_checked_at", "")
    return {
        "configured": configured,
        "valid": valid,
        "error": error,
        "checked_at": checked_at or None
    }


def save_maxmind_validation_status(db: Session, result: dict) -> None:
    """Persist a MaxMind license validation result to DB."""
    from datetime import datetime, timezone
    pairs = {
        "license_configured": "true" if result.get("configured") else "false",
        "license_valid": "true" if result.get("valid") else "false",
        "license_error": result.get("error") or "",
        "license_checked_at": datetime.now(timezone.utc).isoformat(),
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
    """Delete all maxmind.* keys from system_settings (e.g. after credentials change)."""
    db.query(SystemSetting).filter(SystemSetting.key.startswith(_MAXMIND_PREFIX)).delete(synchronize_session=False)
    db.commit()


# ── Credential check status persistence (mailcow Read-Write key, Rspamd password) ──

_CREDENTIAL_CHECK_PREFIX = "credential_check."


@functools.lru_cache(maxsize=16)
def credential_fingerprint(*parts: str) -> str:
    """Short hash of the address and secret a check ran against; the secret itself is never stored here.

    PBKDF2, not a plain hash: the fingerprint is stored, and a fast hash of a
    password lets anyone holding the database try guesses cheaply. It is read
    on every settings load, so the result is kept in memory.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        "\n".join(p or "" for p in parts).encode("utf-8"),
        b"mailcow-logs-viewer credential check",
        100_000,
    ).hex()[:16]


def get_credential_check_status(db: Session, name: str, fingerprint: str) -> dict:
    """The last check of a credential, or None if never checked or its address or secret changed since."""
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
    return data


def save_credential_check_status(db: Session, name: str, result: dict, fingerprint: str) -> None:
    """Persist a credential check result with the address and secret it ran against."""
    from datetime import datetime, timezone
    data = {**result, "fingerprint": fingerprint, "checked_at": datetime.now(timezone.utc).isoformat()}
    key = _CREDENTIAL_CHECK_PREFIX + name
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    if row:
        row.value = json.dumps(data)
    else:
        db.add(SystemSetting(key=key, value=json.dumps(data)))
    db.commit()
