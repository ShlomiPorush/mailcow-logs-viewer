import logging
from datetime import date, datetime, timedelta, timezone
from typing import Optional, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

logger = logging.getLogger(__name__)

UTC = ZoneInfo("UTC")

_warned = set()


def zone_for(name: Optional[str]) -> Optional[ZoneInfo]:
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
    configured = configured_zone_name()
    return {
        "timezone": app_tz().key,
        "timezone_valid": is_valid_zone(configured),
        "timezone_configured": configured,
    }


def local_now() -> datetime:
    return datetime.now(app_tz())


def local_today() -> date:
    return local_now().date()


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def to_local(value: datetime) -> datetime:
    return as_utc(value).astimezone(app_tz())


def utc_naive(value: datetime) -> datetime:
    return as_utc(value).replace(tzinfo=None)


def epoch(value: datetime) -> int:
    return int(as_utc(value).timestamp())


def local_wall_time_to_utc_naive(value: datetime) -> datetime:
    return value.replace(tzinfo=app_tz()).astimezone(timezone.utc).replace(tzinfo=None)


def day_bounds(day: date) -> Tuple[datetime, datetime]:
    zone = app_tz()
    start = datetime(day.year, day.month, day.day, tzinfo=zone)
    following = day + timedelta(days=1)
    end = datetime(following.year, following.month, following.day, tzinfo=zone)
    return utc_naive(start), utc_naive(end)


def is_date_only(value: Optional[str]) -> bool:
    return bool(value) and len(value) == 10 and value[4] == '-' and value[7] == '-'


def range_bound(value: str, end: bool) -> datetime:
    if is_date_only(value):
        start, next_day = day_bounds(datetime.strptime(value, '%Y-%m-%d').date())
        return next_day - timedelta(microseconds=1) if end else start
    return utc_naive(datetime.fromisoformat(value.replace('Z', '+00:00')))


def day_key(value: datetime) -> str:
    return to_local(value).strftime("%Y-%m-%d")


def epoch_day_key(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, app_tz()).strftime("%Y-%m-%d")


def zone_label(value: Optional[datetime] = None) -> str:
    moment = to_local(value) if value is not None else local_now()
    return moment.tzname() or app_tz().key


DATE_FORMATS = ("browser", "DD/MM/YYYY", "MM/DD/YYYY", "DD.MM.YYYY", "YYYY-MM-DD")
TIME_FORMATS = ("24h", "12h", "browser")
DEFAULT_DATE_FORMAT = "browser"
DEFAULT_TIME_FORMAT = "24h"
_SERVER_DATE_FORMAT = "DD/MM/YYYY"


def _normalize(value, known, default: str, name: str) -> str:
    text = str(value if value is not None else "").strip()
    match = next((k for k in known if k.lower() == text.lower()), None)
    if match:
        return match
    if text:
        logger.warning(f"Unknown {name} {text!r}: using {default}. Use one of: {', '.join(known)}.")
    return default


def normalize_date_format(value) -> str:
    return _normalize(value, DATE_FORMATS, DEFAULT_DATE_FORMAT, "date format")


def normalize_time_format(value) -> str:
    return _normalize(value, TIME_FORMATS, DEFAULT_TIME_FORMAT, "time format")


def display_formats() -> dict:
    from .config import settings
    return {
        "date_format": normalize_date_format(settings.date_format),
        "time_format": normalize_time_format(settings.time_format),
    }


def format_day(day: date) -> str:
    fmt = display_formats()["date_format"]
    if fmt == "browser":
        fmt = _SERVER_DATE_FORMAT
    d, m, y = f"{day.day:02d}", f"{day.month:02d}", f"{day.year:04d}"
    return {
        "DD/MM/YYYY": f"{d}/{m}/{y}",
        "MM/DD/YYYY": f"{m}/{d}/{y}",
        "DD.MM.YYYY": f"{d}.{m}.{y}",
        "YYYY-MM-DD": f"{y}-{m}-{d}",
    }[fmt]


def format_clock(hour: int, minute: int) -> str:
    if display_formats()["time_format"] == "12h":
        return f"{(hour % 12) or 12}:{minute:02d} {'AM' if hour < 12 else 'PM'}"
    return f"{hour:02d}:{minute:02d}"
