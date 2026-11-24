from datetime import datetime, timezone
from typing import Annotated, Optional

from pydantic import BeforeValidator

from .app_time import is_date_only, range_bound


def format_datetime_for_api(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    dt_utc = dt.astimezone(timezone.utc)
    
    return dt_utc.replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _date_as_day(end: bool):
    def read(value):
        if isinstance(value, str) and is_date_only(value):
            try:
                return range_bound(value, end)
            except ValueError:
                pass
        return value
    return BeforeValidator(read)


RangeStart = Annotated[datetime, _date_as_day(end=False)]
RangeEnd = Annotated[datetime, _date_as_day(end=True)]


MAILCOW_NO_ANSWER ="mailcow did not answer. Try again in a moment."


def internal_error(e: Exception, status_code: int = 500):
    from fastapi import HTTPException
    from .config import settings
    from .mailcow_api import MailcowAPIError, MailcowShownError
    if isinstance(e, MailcowShownError):
        return HTTPException(status_code=502, detail=str(e))
    if isinstance(e, MailcowAPIError):
        return HTTPException(status_code=502, detail=str(e) if settings.debug else MAILCOW_NO_ANSWER)
    detail = str(e) if settings.debug else "Internal server error"
    return HTTPException(status_code=status_code, detail=detail)