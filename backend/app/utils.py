"""
Utility functions for proper timezone handling
Ensures all timestamps sent to frontend include timezone info
"""
from datetime import datetime, timezone
from typing import Optional


def format_datetime_for_api(dt: Optional[datetime]) -> Optional[str]:
    """
    Format datetime for API response with proper timezone
    
    Ensures frontend always receives UTC timestamps with 'Z' suffix
    so browser can correctly convert to local time
    
    Args:
        dt: datetime object (should be timezone-aware)
        
    Returns:
        ISO format string with 'Z' suffix (e.g. "2025-12-23T13:30:00Z")
        or None if input is None
    """
    if dt is None:
        return None
    
    # If naive (no timezone), assume UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    # Convert to UTC if not already
    dt_utc = dt.astimezone(timezone.utc)
    
    # Format as ISO string with 'Z' suffix for UTC
    # Remove microseconds for cleaner display
    return dt_utc.replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def ensure_timezone_aware(dt: datetime) -> datetime:
    """
    Ensure datetime is timezone-aware (has tzinfo)

    Args:
        dt: datetime object

    Returns:
        Timezone-aware datetime (assumes UTC if naive)
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def internal_error(e: Exception, status_code: int = 500):
    """
    Build an HTTPException that hides internal error details from clients
    unless DEBUG is enabled. Callers should log the full exception first.
    """
    from fastapi import HTTPException
    from .config import settings
    detail = str(e) if settings.debug else "Internal server error"
    return HTTPException(status_code=status_code, detail=detail)