"""
The application time zone.

Times are stored in UTC: naive values in `timestamp without time zone`
columns, with every database session pinned to UTC (database.py). Everything
a user reads, and everything that runs by the clock, follows one zone: the
`tz` setting (TZ in the environment, or Settings > Application), UTC when it
is empty. The browser's zone and the containers' zones play no part.

An unknown name never stops the app: the zone is then UTC, the log says so
once, and tz_status() reports it for the Settings page.

Everything else asks this module for the zone; nothing reads settings.tz.
"""
import logging
from datetime import date, datetime, timedelta, timezone
from typing import Optional, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

logger = logging.getLogger(__name__)

UTC = ZoneInfo("UTC")

_warned = set()


def zone_for(name: Optional[str]) -> Optional[ZoneInfo]:
    """The zone for an IANA name such as Europe/Berlin: UTC when empty, None when unknown."""
    name = (name or "").strip()
    if not name:
        return UTC
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return None


def is_valid_zone(name: Optional[str]) -> bool:
    return zone_for(name) is not None


def configured_zone_name() -> str:
    from .config import settings
    return (settings.tz or "").strip()


def app_tz() -> ZoneInfo:
    """The zone the app works in."""
    configured = configured_zone_name()
    zone = zone_for(configured)
    if zone is None:
        if configured not in _warned:
            _warned.add(configured)
            logger.warning(
                f"Unknown time zone {configured!r} in TZ: the app uses UTC. "
                "Set an IANA name such as Europe/Berlin."
            )
        return UTC
    return zone


def tz_status() -> dict:
    """What /api/info and Settings report about the zone."""
    configured = configured_zone_name()
    return {
        "timezone": app_tz().key,
        "timezone_valid": is_valid_zone(configured),
        "timezone_configured": configured,
    }


def local_now() -> datetime:
    """Now, as an aware time in the app's zone."""
    return datetime.now(app_tz())


def local_today() -> date:
    return local_now().date()


def as_utc(value: datetime) -> datetime:
    """An aware UTC time. A naive value is a stored one, so it is UTC already."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def to_local(value: datetime) -> datetime:
    """A stored (naive UTC) or aware time, as an aware time in the app's zone."""
    return as_utc(value).astimezone(app_tz())


def utc_naive(value: datetime) -> datetime:
    """A time as the database stores it: naive UTC."""
    return as_utc(value).replace(tzinfo=None)


def epoch(value: datetime) -> int:
    """Unix seconds of a stored (naive UTC) or aware time.

    datetime.timestamp() reads a naive value as the container's local time,
    so never call it on a stored value directly.
    """
    return int(as_utc(value).timestamp())


def local_wall_time_to_utc_naive(value: datetime) -> datetime:
    """A naive wall-clock time in the app's zone (as mailcow writes some of its
    own dates) to naive UTC."""
    return value.replace(tzinfo=app_tz()).astimezone(timezone.utc).replace(tzinfo=None)


def day_bounds(day: date) -> Tuple[datetime, datetime]:
    """Start of the day and start of the next one in the app's zone, as naive
    UTC for queries. A day around a daylight saving change is 23 or 25 hours."""
    zone = app_tz()
    start = datetime(day.year, day.month, day.day, tzinfo=zone)
    following = day + timedelta(days=1)
    end = datetime(following.year, following.month, following.day, tzinfo=zone)
    return utc_naive(start), utc_naive(end)


def day_key(value: datetime) -> str:
    """The app-zone day (YYYY-MM-DD) of a stored or aware time."""
    return to_local(value).strftime("%Y-%m-%d")


def epoch_day_key(seconds: float) -> str:
    """The app-zone day (YYYY-MM-DD) of a unix time."""
    return datetime.fromtimestamp(seconds, app_tz()).strftime("%Y-%m-%d")


def zone_label(value: Optional[datetime] = None) -> str:
    """The zone as people read it next to a time, for example CET, CEST or UTC."""
    moment = to_local(value) if value is not None else local_now()
    return moment.tzname() or app_tz().key
