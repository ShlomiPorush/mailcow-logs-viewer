"""
Values from outside, made storable, and rows stored one bad row at a time.

Mail logs, quarantine items and report emails carry text that whoever sends
the mail chooses. PostgreSQL text and JSONB cannot hold NUL (U+0000), and a
batch that commits many rows at once used to lose all of them to the one row
the database refused.
"""
import logging
from typing import Any, Dict, List

from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def strip_nul(value: Any) -> Any:
    """The value without NUL characters, in every string of it: dict keys and
    values and list items too, as stored in a JSON column. Every other
    character fits a text or JSONB column and is kept."""
    if isinstance(value, str):
        return value.replace('\x00', '') if '\x00' in value else value
    if isinstance(value, dict):
        return {strip_nul(k): strip_nul(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [strip_nul(v) for v in value]
    return value


# SQLSTATE class 22 is a value the column cannot hold, except 2200H, a spent
# id sequence, which fails every row alike
_SPENT_SEQUENCE = '2200H'
_UNIQUE_VIOLATION = '23505'


def _pgcode(error: Exception) -> str:
    return getattr(getattr(error, 'orig', None), 'pgcode', None) or ''


def is_row_error(error: Exception) -> bool:
    """Whether the database refused a row for the row's own values. psycopg2
    refuses NUL with a bare ValueError before the statement is sent."""
    if isinstance(error, ValueError):
        return True
    if isinstance(error, DataError):
        code = _pgcode(error)
        return code.startswith('22') and code != _SPENT_SEQUENCE
    return False


def _is_refused_row(error: Exception) -> bool:
    # For a plain insert a duplicate key is the row's own problem too: it is
    # already stored
    return is_row_error(error) or (
        isinstance(error, IntegrityError) and _pgcode(error) == _UNIQUE_VIOLATION)


def add_rows(db: Session, model, rows: List[Dict[str, Any]], what: str) -> List[bool]:
    """Insert one model row per dict, and return for each whether it was stored.

    The rows go in together. When the database refuses one for its own
    values, each row is tried alone and only the refused one is skipped and
    logged, so one row cannot take the others down with it. Any other
    failure, such as a lost connection, is raised. Does not commit."""
    if not rows:
        return []
    try:
        with db.begin_nested():
            for row in rows:
                db.add(model(**row))
        return [True] * len(rows)
    except Exception as error:
        if not _is_refused_row(error):
            raise
    stored = []
    for row in rows:
        try:
            # A new object: the one in the rolled back savepoint is detached
            with db.begin_nested():
                db.add(model(**row))
            stored.append(True)
        except Exception as error:
            if not _is_refused_row(error):
                raise
            # The kind of error only: database messages quote the values
            code = _pgcode(error)
            logger.warning("Skipped a %s the database refused (%s%s)",
                           what, type(error).__name__, f" {code}" if code else '')
            stored.append(False)
    return stored
