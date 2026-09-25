"""
What the admin chose to ignore: a mailcow container that is stopped on
purpose (for example ipv6nat on a server without IPv6) and blocklists that
do not matter for delivery (for example UCEPROTECT Level 3).

Stored in system_settings as JSON lists. This is operational state, not app
configuration, so it works even when editing settings from the UI is off.
"""
import json
import logging
from typing import Set

from sqlalchemy.orm import Session

from ..models import SystemSetting

logger = logging.getLogger(__name__)

IGNORED_CONTAINERS_KEY = "ignore.containers"
IGNORED_BLOCKLISTS_KEY = "ignore.blocklists"


def load_ignored(db: Session, key: str) -> Set[str]:
    """Return the ignored items stored under key (empty when none or unreadable)."""
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    if not row or not row.value:
        return set()
    try:
        values = json.loads(row.value)
    except (TypeError, ValueError):
        logger.warning("Ignore list %s is not valid JSON; treating it as empty", key)
        return set()
    if not isinstance(values, list):
        return set()
    return {str(v).strip() for v in values if str(v).strip()}


def set_ignored(db: Session, key: str, item: str, ignored: bool) -> Set[str]:
    """Add or remove one item and return the updated set."""
    items = load_ignored(db, key)
    if ignored:
        items.add(item)
    else:
        items.discard(item)
    value = json.dumps(sorted(items))
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(SystemSetting(key=key, value=value))
    db.commit()
    # Ignoring silences alerts, so keep a trail of who-changed-what in the log
    logger.info("Ignore list %s: %s %s", key, "added" if ignored else "removed", item)
    return items


def ignored_now(key: str) -> Set[str]:
    """Read the ignore list in its own session (never raises)."""
    from ..database import get_db_context
    try:
        with get_db_context() as db:
            return load_ignored(db, key)
    except Exception as e:
        logger.warning("Could not read ignore list %s: %s", key, e)
        return set()
