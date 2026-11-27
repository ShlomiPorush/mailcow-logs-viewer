import logging
from typing import Any, Dict, List

from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def strip_nul(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace('\x00', '') if '\x00' in value else value
    if isinstance(value, dict):
        return {strip_nul(k): strip_nul(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [strip_nul(v) for v in value]
    return value


_SPENT_SEQUENCE = '2200H'
_UNIQUE_VIOLATION = '23505'
_INDEX_ROW_TOO_LARGE = '54000'


def _pgcode(error: Exception) -> str:
    return getattr(getattr(error, 'orig', None), 'pgcode', None) or ''


def is_row_error(error: Exception) -> bool:
    if isinstance(error, ValueError):
        return True
    if isinstance(error, DataError):
        code = _pgcode(error)
        return code.startswith('22') and code != _SPENT_SEQUENCE
    return False


def _is_index_row_too_large(error: Exception) -> bool:
    if _pgcode(error) != _INDEX_ROW_TOO_LARGE:
        return False
    diag = getattr(getattr(error, 'orig', None), 'diag', None)
    return 'index row' in (getattr(diag, 'message_primary', None) or '')


def _is_refused_row(error: Exception) -> bool:
    return is_row_error(error) or _is_index_row_too_large(error) or (
        isinstance(error, IntegrityError) and _pgcode(error) == _UNIQUE_VIOLATION)


def add_rows(db: Session, model, rows: List[Dict[str, Any]], what: str) -> List[bool]:
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
            with db.begin_nested():
                db.add(model(**row))
            stored.append(True)
        except Exception as error:
            if not _is_refused_row(error):
                raise
            code = _pgcode(error)
            logger.warning("Skipped a %s the database refused (%s%s)",
                           what, type(error).__name__, f" {code}" if code else '')
            stored.append(False)
    return stored
