"""
Rate Limits API - who is hitting mailcow's sender rate limits, and control
over the limits themselves.

mailcow enforces sender rate limits in rspamd, which counts every send against
a Redis key and writes a line to the `ratelimited` log when a sender runs out.
This app already collects that log into raw_service_logs, so /events reads the
local table only: the page stays fast and still answers when mailcow is down.
/limits and all three write endpoints do talk to mailcow.

Two different things can be changed here, and they are easy to confuse:
  - the LIMIT is configuration (rl_value messages per rl_frame)
  - the COUNTER is the Redis hash a blocked sender is currently stuck behind;
    releasing it lets that sender through again without touching the limit
"""
import asyncio
import logging
import re
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import and_, func
from sqlalchemy.orm import Session

from ..config import get_cached_active_domains, settings
from ..database import SessionLocal, get_db
from ..mailcow_api import MailcowAPIError, MailcowShownError, mailcow_api
from ..models import MailboxStatistics, RawServiceLog
from ..agent_access.scopes import READ
from ..user_access import caller_may
from ..utils import format_datetime_for_api, internal_error
from ..api_models import Invalid, documented
from ..api_models import security as m
from ..app_time import app_tz, day_key, to_local

logger = logging.getLogger(__name__)


def _write_failed(e: MailcowAPIError, detail: str) -> HTTPException:
    """A refused Read-Write key or a write mailcow did not confirm says what to do; any other failure points to the logs."""
    return HTTPException(status_code=502, detail=str(e) if isinstance(e, MailcowShownError) else detail)

router = APIRouter(prefix="/rate-limits")

# A limit sent to mailcow: no Read-Write key (503), a bad value or name (400), mailcow refusing (502)
RL_WRITE = {400: None, 422: Invalid, 500: None, 502: None, 503: None}

# rspamd's time frames: second, minute, hour, day
VALID_FRAMES = ('s', 'm', 'h', 'd')

# Shape of the Redis key rspamd counts against, as it appears in the log
_RL_HASH_RE = re.compile(r'^RL[A-Za-z0-9]+$')

# Detail rows kept per sender, and the length of the flat feed
_RECENT_PER_SENDER = 5
_FLAT_EVENT_LIMIT = 50

# One sender's detail view reads its whole history separately. This is far
# above any realistic sender's collected hits and only guards against a single
# request rendering a runaway table; `total` still reports the real number.
_SENDER_EVENTS_MAX = 2000

# The windows the activity chart offers, in hours. Only those within the
# rate limit history the app keeps are offered (settings.rate_limits_retention_effective)
_WINDOW_HOURS = (24, 168, 720, 2160, 8760)

# Reading the domain limits is one mailcow round trip per domain and the page
# refreshes often, so the answers are reused in-process for a few minutes.
_DOMAIN_LIMIT_TTL = 300
_domain_limit_cache: Dict[str, Any] = {'at': 0.0, 'limits': None}

# One bulk apply is a single mailcow call per kind, so the only real cost is
# the size of the payload. This is far above the largest realistic selection
# (every mailbox of a big server) and keeps a runaway client out.
_BULK_MAX_ITEMS = 1000


# ---- helpers ----

def _bust_domain_limit_cache() -> None:
    """Drop the cached domain limits after a write."""
    _domain_limit_cache['at'] = 0.0
    _domain_limit_cache['limits'] = None


def _require_rw_key() -> None:
    """Every write here goes through mailcow and needs the Read-Write key."""
    if not mailcow_api.has_rw_key:
        raise HTTPException(
            status_code=503,
            detail="MAILCOW_API_KEY_RW is required to change rate limits"
        )


def _validate_value(value: Any) -> int:
    """Rate limit values are whole messages per frame; 0 means no limit."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Rate limit value must be a whole number")
    if parsed < 0:
        raise HTTPException(status_code=400, detail="Rate limit value cannot be negative")
    return parsed


def _validate_frame(frame: str) -> str:
    value = (frame or '').strip().lower()
    if value not in VALID_FRAMES:
        raise HTTPException(
            status_code=400,
            detail="Time frame must be s (second), m (minute), h (hour) or d (day)"
        )
    return value


def _normalised_names(raw: Optional[List[str]]) -> List[str]:
    """Lower-cased names in the order they were sent, without blanks or repeats.

    The browser sends whatever the filter currently shows, so the same name can
    arrive twice; sending it to mailcow twice would be pointless work.
    """
    names: List[str] = []
    seen = set()
    for name in raw or []:
        value = (name or '').strip().lower()
        if value and value not in seen:
            seen.add(value)
            names.append(value)
    return names


def _limit_value(raw: Any) -> Optional[int]:
    """mailcow returns the limit as a string; 0 and junk both mean no limit."""
    try:
        parsed = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _bucket_key(when: datetime, kind: str) -> str:
    """The key one event (a stored naive UTC time) is counted under. An hour
    is the UTC instant it starts at, with Z, which the frontend shows in the
    app time zone; a day is a day in the app time zone, shown as it is."""
    if kind == 'hour':
        return format_datetime_for_api(when.replace(minute=0, second=0, microsecond=0))
    return day_key(when)


def _bucket_series(since: datetime, until: datetime, kind: str,
                   counts: Dict[str, int]) -> List[Dict[str, Any]]:
    """Every bucket of the window, oldest first, zero-filled.

    A quiet stretch has to show as a gap in the chart, not disappear from it,
    so buckets with no events are returned with a count of 0.
    """
    if kind == 'hour':
        cursor = since.replace(minute=0, second=0, microsecond=0)
        keys = []
        while cursor <= until:
            keys.append(_bucket_key(cursor, kind))
            cursor += timedelta(hours=1)
    else:
        # Calendar days of the app time zone, so a 23 or 25 hour day is one bucket
        day, last = to_local(since).date(), to_local(until).date()
        keys = []
        while day <= last:
            keys.append(day.isoformat())
            day += timedelta(days=1)

    series: List[Dict[str, Any]] = []
    covered = set()
    for key in keys:
        covered.add(key)
        series.append({'bucket': key, 'count': counts.get(key, 0)})

    # A row can sit just outside the generated range (a log written while the
    # request was running). Keep its count rather than losing it.
    for key, count in counts.items():
        if key not in covered:
            series.append({'bucket': key, 'count': count})

    # Both key shapes sort correctly as plain strings
    series.sort(key=lambda entry: entry['bucket'])
    return series


def _known_domains(db: Session) -> set:
    """Local domain names: the mailcow domain cache, plus the domains we have
    mailboxes for (so the page keeps working before the cache is populated)."""
    names = {(d or '').strip().lower() for d in (get_cached_active_domains() or [])}
    for (domain,) in db.query(MailboxStatistics.domain).distinct().all():
        names.add((domain or '').strip().lower())
    names.discard('')
    return names


def _load_known_domains_worker() -> set:
    with SessionLocal() as db:
        return _known_domains(db)


async def _fetch_domain_limits() -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Per-domain limits from mailcow, cached in-process for _DOMAIN_LIMIT_TTL."""
    now = time.monotonic()
    cached = _domain_limit_cache.get('limits')
    if cached is not None and (now - _domain_limit_cache['at']) < _DOMAIN_LIMIT_TTL:
        return cached, None

    limits: List[Dict[str, Any]] = []
    error: Optional[str] = None
    for domain in sorted(await asyncio.to_thread(_load_known_domains_worker)):
        try:
            data = await mailcow_api.get_rl_domain(domain)
        except MailcowAPIError as e:
            logger.warning(f"Could not read the rate limit of {domain}: {e}")
            error = "Could not read domain rate limits. Check the application logs."
            continue
        limits.append({
            'domain': domain,
            'rl_value': _limit_value(data.get('value')),
            'rl_frame': data.get('frame') or None,
        })

    # Never cache a partial answer - the next refresh should retry mailcow
    if error is None:
        _domain_limit_cache['limits'] = limits
        _domain_limit_cache['at'] = now
    return limits, error


# ---- request models ----

class MailboxLimitRequest(BaseModel):
    mailbox: str
    value: int
    frame: str


class DomainLimitRequest(BaseModel):
    domain: str
    value: int
    frame: str


class BulkLimitRequest(BaseModel):
    mailboxes: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    value: int
    frame: str


class ReleaseRequest(BaseModel):
    rl_hash: str
    user: Optional[str] = None


# Audit of counter resets, kept in system_settings as JSON: user -> last reset.
# Feeds the "counter reset" marker on the events rows.
_RESETS_KEY = 'rate_limit_resets'
_RESETS_MAX = 100


def _load_resets(db: Session) -> Dict[str, Any]:
    from ..models import SystemSetting
    import json
    try:
        row = db.query(SystemSetting).filter(SystemSetting.key == _RESETS_KEY).first()
        return json.loads(row.value) if row and row.value else {}
    except Exception as e:
        logger.warning(f"Could not read the rate limit reset audit: {e}")
        return {}


def _record_reset(db: Session, user: str, rl_hash: str) -> None:
    from ..models import SystemSetting
    import json
    resets = _load_resets(db)
    resets[user.strip().lower()] = {
        'at': format_datetime_for_api(datetime.utcnow()),
        'rl_hash': rl_hash,
    }
    if len(resets) > _RESETS_MAX:
        oldest = sorted(resets.items(), key=lambda kv: kv[1].get('at', ''))
        resets = dict(oldest[len(resets) - _RESETS_MAX:])
    row = db.query(SystemSetting).filter(SystemSetting.key == _RESETS_KEY).first()
    value = json.dumps(resets)
    if row is None:
        db.add(SystemSetting(key=_RESETS_KEY, value=value))
    else:
        row.value = value
    db.commit()


# ---- endpoints ----

def _sender_column():
    """The sender of a rate limit row, as the page groups it: the logged-in
    user, or the envelope sender when there is none, trimmed and lowercased.
    Every query here uses this one expression, so the list, the counts and a
    sender's own history always agree."""
    user = func.nullif(func.trim(RawServiceLog.raw_data['user'].astext), '')
    return func.lower(func.trim(func.coalesce(user, RawServiceLog.raw_data['from'].astext, '')))


def _offered_windows() -> List[int]:
    """The chart windows within the kept history; a day is always offered."""
    kept = settings.rate_limits_retention_effective * 24
    return [hours for hours in _WINDOW_HOURS if hours <= kept] or [_WINDOW_HOURS[0]]


@router.get("/events", responses=documented(m.RateLimitEventsResponse, errors={422: Invalid, 500: None}))
def get_rate_limit_events(
    hours: int = Query(168, ge=1, le=8760),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """Every sender that hit a rate limit in the kept history (grouped), plus
    the hits per time bucket for the activity chart.

    The `hours` window scopes ONLY the chart, and is narrowed to the longest
    window the kept history covers. The sender list mirrors reality:
    everything the viewer has kept, however old - a filter must never hide a
    sender from it. Everything is counted in the database, so a busy server
    with a long history gives exact numbers.

    Reads only the collected `ratelimited` log, so this never waits on mailcow.
    A refused message's recipient and subject are mail from Messages: empty for
    a caller without View for Messages.
    """
    with_messages = caller_may(request, "messages", READ)
    offered = _offered_windows()
    if hours > offered[-1]:
        hours = offered[-1]
    now = datetime.utcnow()
    since = now - timedelta(hours=hours)
    # A day of hits reads per hour; anything longer reads per day
    bucket_kind = 'hour' if hours <= 24 else 'day'
    sender = _sender_column().label('sender')
    is_rl = and_(RawServiceLog.service == 'ratelimited', _sender_column() != '')
    if bucket_kind == 'hour':
        bucket = func.date_trunc('hour', RawServiceLog.time)
    else:
        # The day in the app time zone: the stored time is naive UTC
        zone = getattr(app_tz(), 'key', 'UTC')
        bucket = func.to_char(func.timezone(zone, func.timezone('UTC', RawServiceLog.time)), 'YYYY-MM-DD')
    try:
        totals = db.query(sender, func.count(RawServiceLog.id), func.max(RawServiceLog.time)) \
            .filter(is_rl).group_by(sender).all()
        # The newest few rows of each sender, for the detail view
        ranked = db.query(RawServiceLog.id.label('id'), func.row_number().over(
            partition_by=_sender_column(), order_by=(RawServiceLog.time.desc(), RawServiceLog.id.desc())).label('n')
        ).filter(is_rl).subquery()
        recent_rows = db.query(RawServiceLog).join(ranked, ranked.c.id == RawServiceLog.id) \
            .filter(ranked.c.n <= _RECENT_PER_SENDER).order_by(RawServiceLog.time.desc(), RawServiceLog.id.desc()).all()
        # The newest limit hash of each sender, however far back it is
        rl_hash = func.trim(RawServiceLog.raw_data['rl_hash'].astext)
        hashes = db.query(sender, rl_hash).filter(is_rl, rl_hash != '') \
            .distinct(_sender_column()).order_by(_sender_column(), RawServiceLog.time.desc(), RawServiceLog.id.desc()).all()
        in_window = and_(is_rl, RawServiceLog.time >= since)
        bucket_counts = {key: count for key, count in
                         db.query(bucket, func.count(RawServiceLog.id)).filter(in_window).group_by(bucket).all()}
        window_senders = db.query(func.count(func.distinct(_sender_column()))).filter(in_window).scalar() or 0
        newest = db.query(RawServiceLog).filter(is_rl) \
            .order_by(RawServiceLog.time.desc(), RawServiceLog.id.desc()).limit(_FLAT_EVENT_LIMIT).all()
    except Exception as e:
        logger.error(f"Error reading rate limit events: {e}")
        raise internal_error(e)

    if bucket_kind == 'hour':
        bucket_counts = {_bucket_key(key, 'hour'): count for key, count in bucket_counts.items()}

    def detail_of(row):
        data = row.raw_data if isinstance(row.raw_data, dict) else {}
        return data, {
            'time': format_datetime_for_api(row.time),
            'rcpt': (data.get('rcpt') or '') if with_messages else '',
            'subject': (data.get('header_subject') or '') if with_messages else '',
            'qid': data.get('qid') or '',
            'rl_hash': (data.get('rl_hash') or '').strip(),
        }

    def sender_of(data):
        user = (data.get('user') or '').strip()
        return (user or (data.get('from') or '')).strip().lower()

    last_hash = dict(hashes)
    groups: Dict[str, Dict[str, Any]] = {
        user: {
            'user': user,
            'events': int(count),
            'last_seen': format_datetime_for_api(last),
            'last_rl_hash': last_hash.get(user) or None,
            'current_limit': None,
            'recent': [],
        } for user, count, last in totals
    }
    for row in recent_rows:
        data, detail = detail_of(row)
        group = groups.get(sender_of(data))
        if group is not None:
            group['recent'].append(detail)
    events = []
    for row in newest:
        data, detail = detail_of(row)
        events.append({'user': sender_of(data), **detail})

    # The configured limit comes from the synced mailbox row, never from a
    # mailcow call - this endpoint has to stay fast and work offline.
    if groups:
        try:
            configured = db.query(
                MailboxStatistics.username,
                MailboxStatistics.rl_value,
                MailboxStatistics.rl_frame
            ).filter(func.lower(MailboxStatistics.username).in_(list(groups))).all()
        except Exception as e:
            logger.error(f"Error reading configured limits: {e}")
            raise internal_error(e)
        for username, rl_value, rl_frame in configured:
            group = groups.get((username or '').strip().lower())
            if group is not None and rl_value:
                group['current_limit'] = {'value': rl_value, 'frame': rl_frame}

    # Mark senders whose counter was reset from here (the audit in
    # system_settings), so the row can show it
    resets = _load_resets(db)
    for user_key, group in groups.items():
        reset = resets.get(user_key)
        if reset:
            group['last_reset'] = reset.get('at')

    by_sender = sorted(groups.values(), key=lambda g: (-g['events'], g['user']))
    return {
        'hours': hours,
        'windows': offered,
        'retention_days': settings.rate_limits_retention_effective,
        'total_events': sum(bucket_counts.values()),
        'window_senders': int(window_senders),
        'by_sender': by_sender,
        'events': events,
        'bucket': bucket_kind,
        'by_bucket': _bucket_series(since, now, bucket_kind, bucket_counts),
    }


@router.get("/sender-events", responses=documented(m.SenderEventsResponse, errors={400: None, 500: None}))
def get_sender_events(
    user: str = Query('', description="The sender address to read the history of"),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """One sender's full collected history of refused messages, newest first.
    Recipient and subject are empty for a caller without View for Messages.

    /events carries only the newest few rows per sender - enough to paint the
    detail view the moment it opens. This is the rest of it: the page mirrors
    reality, so an open sender shows everything that was collected about them,
    not a sample of it.
    """
    with_messages = caller_may(request, "messages", READ)
    address = (user or '').strip().lower()
    if not address:
        raise HTTPException(status_code=400, detail="A sender address is required")

    # The same sender as the events list: `user`, else `from`
    matches_sender = _sender_column() == address

    try:
        # The real number, counted in the database - the list below is capped
        total = db.query(func.count(RawServiceLog.id)).filter(
            RawServiceLog.service == 'ratelimited',
            matches_sender
        ).scalar() or 0
        rows = db.query(RawServiceLog).filter(
            RawServiceLog.service == 'ratelimited',
            matches_sender
        ).order_by(RawServiceLog.time.desc()).limit(_SENDER_EVENTS_MAX).all()
    except Exception as e:
        logger.error(f"Error reading the rate limit history of {address}: {e}")
        raise internal_error(e)

    events: List[Dict[str, Any]] = []
    for row in rows:
        data = row.raw_data if isinstance(row.raw_data, dict) else {}
        events.append({
            'time': format_datetime_for_api(row.time),
            'rcpt': (data.get('rcpt') or '') if with_messages else '',
            'subject': (data.get('header_subject') or '') if with_messages else '',
            'qid': data.get('qid') or '',
            'rl_hash': (data.get('rl_hash') or '').strip(),
        })

    return {'user': address, 'total': int(total), 'events': events}


def _load_configured_mailboxes_worker() -> List[Dict[str, Any]]:
    with SessionLocal() as db:
        try:
            rows = db.query(MailboxStatistics).filter(
                MailboxStatistics.active == True  # noqa: E712 - SQLAlchemy filter
            ).order_by(MailboxStatistics.username).all()
        except Exception as e:
            logger.error(f"Error reading mailbox rate limits: {e}")
            raise internal_error(e)

        return [{
            'username': row.username,
            'domain': row.domain,
            'rl_value': row.rl_value,
            'rl_frame': row.rl_frame,
            'active': bool(row.active),
        } for row in rows]


@router.get("/limits", responses=documented(m.RateLimitsResponse, errors={500: None}))
async def get_configured_limits():
    """List active mailboxes and domain limits without blocking other requests."""
    mailboxes = await asyncio.to_thread(_load_configured_mailboxes_worker)
    domains, domains_error = await _fetch_domain_limits()

    return {
        'rw_key_configured': mailcow_api.has_rw_key,
        'mailboxes': mailboxes,
        'domains': domains,
        'domains_error': domains_error,
    }


def _load_mailbox_name_worker(mailbox: str) -> Optional[str]:
    with SessionLocal() as db:
        row = db.query(MailboxStatistics).filter(
            func.lower(MailboxStatistics.username) == mailbox
        ).first()
        return row.username if row is not None else None


def _load_bulk_mailboxes_worker(wanted: List[str]) -> Dict[str, str]:
    with SessionLocal() as db:
        rows = db.query(MailboxStatistics).filter(
            func.lower(MailboxStatistics.username).in_(wanted)
        ).all()
        return {(row.username or '').strip().lower(): row.username for row in rows}


def _store_mailbox_limits_worker(usernames: List[str], value: Optional[int], frame: Optional[str]) -> None:
    with SessionLocal() as db:
        try:
            rows = db.query(MailboxStatistics).filter(
                MailboxStatistics.username.in_(usernames)
            ).all()
            for row in rows:
                row.rl_value = value
                row.rl_frame = frame
            db.commit()
        except Exception:
            db.rollback()
            raise


def _record_reset_worker(user: str, rl_hash: str) -> None:
    with SessionLocal() as db:
        _record_reset(db, user, rl_hash)


@router.post("/mailbox", responses=documented(m.MailboxLimitSet, errors=RL_WRITE))
async def set_mailbox_limit(request: MailboxLimitRequest):
    """Set the rate limit of one mailbox. A value of 0 removes the limit."""
    _require_rw_key()
    mailbox = (request.mailbox or '').strip().lower()
    value = _validate_value(request.value)
    frame = _validate_frame(request.frame)

    username = await asyncio.to_thread(_load_mailbox_name_worker, mailbox)
    if username is None:
        raise HTTPException(status_code=400, detail=f"Unknown mailbox: {request.mailbox}")

    try:
        response = await mailcow_api.edit_rl_mbox(username, value, frame)
    except MailcowAPIError as e:
        logger.error(f"Failed to set the rate limit of {mailbox}: {e}")
        raise _write_failed(e, "mailcow did not apply the change. Check the application logs.")

    # Mirror the change locally so the page shows it without waiting for the
    # next mailbox sync. A failure here is cosmetic, not a failed write.
    new_value = value or None
    try:
        await asyncio.to_thread(
            _store_mailbox_limits_worker, [username], new_value, frame if new_value else None
        )
    except Exception as e:
        logger.warning(f"Rate limit applied in mailcow but not stored locally for {mailbox}: {e}")

    return {
        'mailbox': username,
        'rl_value': new_value,
        'rl_frame': frame if new_value else None,
        'mailcow_response': response,
    }


@router.post("/domain", responses=documented(m.DomainLimitSet, errors=RL_WRITE))
async def set_domain_limit(request: DomainLimitRequest):
    """Set the rate limit of one domain. A value of 0 removes the limit."""
    _require_rw_key()
    domain = (request.domain or '').strip().lower()
    value = _validate_value(request.value)
    frame = _validate_frame(request.frame)

    if domain not in await asyncio.to_thread(_load_known_domains_worker):
        raise HTTPException(status_code=400, detail=f"Unknown domain: {request.domain}")

    try:
        response = await mailcow_api.edit_rl_domain(domain, value, frame)
    except MailcowAPIError as e:
        logger.error(f"Failed to set the rate limit of {domain}: {e}")
        raise _write_failed(e, "mailcow did not apply the change. Check the application logs.")

    _bust_domain_limit_cache()
    return {
        'domain': domain,
        'rl_value': value or None,
        'rl_frame': frame if value else None,
        'mailcow_response': response,
    }


@router.post("/bulk", responses=documented(m.BulkLimitSet, errors=RL_WRITE))
async def set_limits_in_bulk(request: BulkLimitRequest):
    """Set one rate limit on many mailboxes and domains at once. A value of 0
    removes the limit from all of them.

    This is what "Apply to filtered" on the page sends: everything the search
    and the type filter currently show, in one request. Each kind is a single
    mailcow call - a selection of 160 mailboxes must not become 160 round trips.

    A name the server does not know (a stale row in an open browser tab) is
    reported back in `skipped` rather than failing the whole batch.
    """
    _require_rw_key()
    value = _validate_value(request.value)
    frame = _validate_frame(request.frame)

    if len(request.mailboxes or []) + len(request.domains or []) > _BULK_MAX_ITEMS:
        raise HTTPException(
            status_code=400,
            detail=f"Too many items in one request - at most {_BULK_MAX_ITEMS}"
        )

    wanted_mailboxes = _normalised_names(request.mailboxes)
    wanted_domains = _normalised_names(request.domains)
    if not wanted_mailboxes and not wanted_domains:
        raise HTTPException(status_code=400, detail="Select at least one mailbox or domain")

    skipped: List[str] = []

    # Mailboxes are matched against the synced rows, exactly like the
    # single-mailbox endpoint, and written with their stored spelling
    names_by_key: Dict[str, str] = {}
    if wanted_mailboxes:
        try:
            names_by_key = await asyncio.to_thread(_load_bulk_mailboxes_worker, wanted_mailboxes)
        except Exception as e:
            logger.error(f"Error reading mailboxes for a bulk rate limit change: {e}")
            raise internal_error(e)

    targets = [names_by_key[name] for name in wanted_mailboxes if name in names_by_key]
    skipped.extend(name for name in wanted_mailboxes if name not in names_by_key)

    known = await asyncio.to_thread(_load_known_domains_worker) if wanted_domains else set()
    domains = [name for name in wanted_domains if name in known]
    skipped.extend(name for name in wanted_domains if name not in known)

    new_value = value or None
    new_frame = frame if new_value else None

    mailboxes_updated = 0
    if targets:
        try:
            await mailcow_api.edit_rl_mboxes(targets, value, frame)
        except MailcowAPIError as e:
            logger.error(f"Failed to set the rate limit of {len(targets)} mailboxes: {e}")
            raise _write_failed(e, "mailcow did not apply the change. Check the application logs.")
        mailboxes_updated = len(targets)

        # Mirror the change locally so the page shows it without waiting for
        # the next mailbox sync. A failure here is cosmetic, not a failed write.
        try:
            await asyncio.to_thread(_store_mailbox_limits_worker, targets, new_value, new_frame)
        except Exception as e:
            logger.warning(f"Bulk rate limit applied in mailcow but not stored locally: {e}")

    domains_updated = 0
    if domains:
        try:
            await mailcow_api.edit_rl_domains(domains, value, frame)
        except MailcowAPIError as e:
            logger.error(f"Failed to set the rate limit of {len(domains)} domains: {e}")
            raise _write_failed(e, "mailcow did not apply the change. Check the application logs.")
        domains_updated = len(domains)
        _bust_domain_limit_cache()

    return {
        'mailboxes_updated': mailboxes_updated,
        'domains_updated': domains_updated,
        'skipped': skipped,
        'value': value,
        'frame': frame,
    }


@router.post("/reset", responses=documented(m.CounterReset, errors=RL_WRITE))
async def reset_rate_limit_counter(request: ReleaseRequest):
    """Reset an active counter so a blocked sender can send again now."""
    _require_rw_key()
    rl_hash = (request.rl_hash or '').strip()
    if not _RL_HASH_RE.match(rl_hash):
        raise HTTPException(
            status_code=400,
            detail="That is not a rate limit hash - it must look like RLabc123"
        )

    try:
        response = await mailcow_api.delete_rl_hash(rl_hash)
    except MailcowAPIError as e:
        logger.error(f"Failed to reset the rate limit counter {rl_hash}: {e}")
        raise _write_failed(e, "mailcow did not reset the counter. Check the application logs.")

    # mailcow answers this delete with an empty 200 - reaching here means it
    # accepted the request. Record who was reset for the row marker.
    if request.user:
        try:
            await asyncio.to_thread(_record_reset_worker, request.user, rl_hash)
        except Exception as e:
            logger.warning(f"Counter reset done but not recorded: {e}")

    return {'rl_hash': rl_hash, 'reset': True, 'mailcow_response': response}
