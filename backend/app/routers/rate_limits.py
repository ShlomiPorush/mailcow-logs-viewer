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
import logging
import re
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..config import get_cached_active_domains
from ..database import get_db
from ..mailcow_api import MailcowAPIError, mailcow_api
from ..models import MailboxStatistics, RawServiceLog
from ..utils import format_datetime_for_api, internal_error

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/rate-limits")

# rspamd's time frames: second, minute, hour, day
VALID_FRAMES = ('s', 'm', 'h', 'd')

# Shape of the Redis key rspamd counts against, as it appears in the log
_RL_HASH_RE = re.compile(r'^RL[A-Za-z0-9]+$')

# Detail rows kept per sender, and the length of the flat feed
_RECENT_PER_SENDER = 5
_FLAT_EVENT_LIMIT = 50

# Upper bound on the rows one request will parse, so a long window on a busy
# server cannot pin a worker. The grouping is still correct for everything read.
_MAX_EVENT_ROWS = 5000

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
    """The key one event is counted under. Keys stay UTC, like every other
    timestamp this API returns - the frontend localises them."""
    if kind == 'hour':
        return when.strftime('%Y-%m-%dT%H:00')
    return when.strftime('%Y-%m-%d')


def _bucket_series(since: datetime, until: datetime, kind: str,
                   counts: Dict[str, int]) -> List[Dict[str, Any]]:
    """Every bucket of the window, oldest first, zero-filled.

    A quiet stretch has to show as a gap in the chart, not disappear from it,
    so buckets with no events are returned with a count of 0.
    """
    step = timedelta(hours=1) if kind == 'hour' else timedelta(days=1)
    if kind == 'hour':
        cursor = since.replace(minute=0, second=0, microsecond=0)
    else:
        cursor = since.replace(hour=0, minute=0, second=0, microsecond=0)

    series: List[Dict[str, Any]] = []
    covered = set()
    while cursor <= until:
        key = _bucket_key(cursor, kind)
        covered.add(key)
        series.append({'bucket': key, 'count': counts.get(key, 0)})
        cursor += step

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


async def _fetch_domain_limits(db: Session) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Per-domain limits from mailcow, cached in-process for _DOMAIN_LIMIT_TTL."""
    now = time.monotonic()
    cached = _domain_limit_cache.get('limits')
    if cached is not None and (now - _domain_limit_cache['at']) < _DOMAIN_LIMIT_TTL:
        return cached, None

    limits: List[Dict[str, Any]] = []
    error: Optional[str] = None
    for domain in sorted(_known_domains(db)):
        try:
            data = await mailcow_api.get_rl_domain(domain)
        except MailcowAPIError as e:
            logger.warning(f"Could not read the rate limit of {domain}: {e}")
            error = str(e)
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

@router.get("/events")
def get_rate_limit_events(
    hours: int = Query(168, ge=1, le=8760),
    db: Session = Depends(get_db)
):
    """Senders that hit a rate limit in the window, grouped by sender, plus the
    hits per time bucket for the activity chart.

    Reads only the collected `ratelimited` log, so this never waits on mailcow.
    """
    now = datetime.utcnow()
    since = now - timedelta(hours=hours)
    # A day of hits reads per hour; anything longer reads per day
    bucket_kind = 'hour' if hours <= 24 else 'day'
    try:
        rows = db.query(RawServiceLog).filter(
            RawServiceLog.service == 'ratelimited',
            RawServiceLog.time >= since
        ).order_by(RawServiceLog.time.desc()).limit(_MAX_EVENT_ROWS).all()
    except Exception as e:
        logger.error(f"Error reading rate limit events: {e}")
        raise internal_error(e)

    groups: Dict[str, Dict[str, Any]] = {}
    events: List[Dict[str, Any]] = []
    # Hits per bucket, for the activity chart. Counted from every row read,
    # not from the capped per-sender detail lists.
    bucket_counts: Dict[str, int] = {}
    total_events = 0

    # Rows arrive newest first, so the first row seen for a sender is the
    # latest one - that is where last_seen and last_rl_hash come from.
    for row in rows:
        data = row.raw_data if isinstance(row.raw_data, dict) else {}
        user = (data.get('user') or data.get('from') or '').strip().lower()
        if not user:
            continue

        total_events += 1
        bucket = _bucket_key(row.time, bucket_kind)
        bucket_counts[bucket] = bucket_counts.get(bucket, 0) + 1
        rl_hash = (data.get('rl_hash') or '').strip()
        detail = {
            'time': format_datetime_for_api(row.time),
            'rcpt': data.get('rcpt') or '',
            'subject': data.get('header_subject') or '',
            'qid': data.get('qid') or '',
            'rl_hash': rl_hash,
        }

        group = groups.get(user)
        if group is None:
            group = groups[user] = {
                'user': user,
                'events': 0,
                'last_seen': detail['time'],
                'last_rl_hash': rl_hash or None,
                'current_limit': None,
                'recent': [],
            }
        group['events'] += 1
        if not group['last_rl_hash'] and rl_hash:
            group['last_rl_hash'] = rl_hash
        if len(group['recent']) < _RECENT_PER_SENDER:
            group['recent'].append(detail)

        if len(events) < _FLAT_EVENT_LIMIT:
            events.append({'user': user, **detail})

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

    by_sender = sorted(groups.values(), key=lambda g: g['events'], reverse=True)
    return {
        'hours': hours,
        'total_events': total_events,
        'by_sender': by_sender,
        'events': events,
        'bucket': bucket_kind,
        'by_bucket': _bucket_series(since, now, bucket_kind, bucket_counts),
    }


@router.get("/limits")
async def get_configured_limits(db: Session = Depends(get_db)):
    """Every active mailbox with its limit (or none), and the limit of every
    local domain. Unlimited mailboxes are listed too - that is where a limit
    gets added in the first place."""
    try:
        rows = db.query(MailboxStatistics).filter(
            MailboxStatistics.active == True  # noqa: E712 - SQLAlchemy filter
        ).order_by(MailboxStatistics.username).all()
    except Exception as e:
        logger.error(f"Error reading mailbox rate limits: {e}")
        raise internal_error(e)

    mailboxes = [{
        'username': row.username,
        'domain': row.domain,
        'rl_value': row.rl_value,
        'rl_frame': row.rl_frame,
        'active': bool(row.active),
    } for row in rows]

    domains, domains_error = await _fetch_domain_limits(db)

    return {
        'rw_key_configured': mailcow_api.has_rw_key,
        'mailboxes': mailboxes,
        'domains': domains,
        'domains_error': domains_error,
    }


@router.post("/mailbox")
async def set_mailbox_limit(request: MailboxLimitRequest, db: Session = Depends(get_db)):
    """Set the rate limit of one mailbox. A value of 0 removes the limit."""
    _require_rw_key()
    mailbox = (request.mailbox or '').strip().lower()
    value = _validate_value(request.value)
    frame = _validate_frame(request.frame)

    row = db.query(MailboxStatistics).filter(
        func.lower(MailboxStatistics.username) == mailbox
    ).first()
    if row is None:
        raise HTTPException(status_code=400, detail=f"Unknown mailbox: {request.mailbox}")

    try:
        response = await mailcow_api.edit_rl_mbox(row.username, value, frame)
    except MailcowAPIError as e:
        logger.error(f"Failed to set the rate limit of {mailbox}: {e}")
        raise HTTPException(status_code=502, detail=f"mailcow did not apply the change: {e}")

    # Mirror the change locally so the page shows it without waiting for the
    # next mailbox sync. A failure here is cosmetic, not a failed write.
    new_value = value or None
    try:
        row.rl_value = new_value
        row.rl_frame = frame if new_value else None
        db.commit()
    except Exception as e:
        db.rollback()
        logger.warning(f"Rate limit applied in mailcow but not stored locally for {mailbox}: {e}")

    return {
        'mailbox': row.username,
        'rl_value': new_value,
        'rl_frame': frame if new_value else None,
        'mailcow_response': response,
    }


@router.post("/domain")
async def set_domain_limit(request: DomainLimitRequest, db: Session = Depends(get_db)):
    """Set the rate limit of one domain. A value of 0 removes the limit."""
    _require_rw_key()
    domain = (request.domain or '').strip().lower()
    value = _validate_value(request.value)
    frame = _validate_frame(request.frame)

    if domain not in _known_domains(db):
        raise HTTPException(status_code=400, detail=f"Unknown domain: {request.domain}")

    try:
        response = await mailcow_api.edit_rl_domain(domain, value, frame)
    except MailcowAPIError as e:
        logger.error(f"Failed to set the rate limit of {domain}: {e}")
        raise HTTPException(status_code=502, detail=f"mailcow did not apply the change: {e}")

    _bust_domain_limit_cache()
    return {
        'domain': domain,
        'rl_value': value or None,
        'rl_frame': frame if value else None,
        'mailcow_response': response,
    }


@router.post("/bulk")
async def set_limits_in_bulk(request: BulkLimitRequest, db: Session = Depends(get_db)):
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
    rows_by_name: Dict[str, Any] = {}
    if wanted_mailboxes:
        try:
            rows = db.query(MailboxStatistics).filter(
                func.lower(MailboxStatistics.username).in_(wanted_mailboxes)
            ).all()
        except Exception as e:
            logger.error(f"Error reading mailboxes for a bulk rate limit change: {e}")
            raise internal_error(e)
        rows_by_name = {(row.username or '').strip().lower(): row for row in rows}

    targets = [rows_by_name[name] for name in wanted_mailboxes if name in rows_by_name]
    skipped.extend(name for name in wanted_mailboxes if name not in rows_by_name)

    known = _known_domains(db) if wanted_domains else set()
    domains = [name for name in wanted_domains if name in known]
    skipped.extend(name for name in wanted_domains if name not in known)

    new_value = value or None
    new_frame = frame if new_value else None

    mailboxes_updated = 0
    if targets:
        try:
            await mailcow_api.edit_rl_mboxes([row.username for row in targets], value, frame)
        except MailcowAPIError as e:
            logger.error(f"Failed to set the rate limit of {len(targets)} mailboxes: {e}")
            raise HTTPException(status_code=502, detail=f"mailcow did not apply the change: {e}")
        mailboxes_updated = len(targets)

        # Mirror the change locally so the page shows it without waiting for
        # the next mailbox sync. A failure here is cosmetic, not a failed write.
        try:
            for row in targets:
                row.rl_value = new_value
                row.rl_frame = new_frame
            db.commit()
        except Exception as e:
            db.rollback()
            logger.warning(f"Bulk rate limit applied in mailcow but not stored locally: {e}")

    domains_updated = 0
    if domains:
        try:
            await mailcow_api.edit_rl_domains(domains, value, frame)
        except MailcowAPIError as e:
            logger.error(f"Failed to set the rate limit of {len(domains)} domains: {e}")
            raise HTTPException(status_code=502, detail=f"mailcow did not apply the change: {e}")
        domains_updated = len(domains)
        _bust_domain_limit_cache()

    return {
        'mailboxes_updated': mailboxes_updated,
        'domains_updated': domains_updated,
        'skipped': skipped,
        'value': value,
        'frame': frame,
    }


@router.post("/reset")
async def reset_rate_limit_counter(request: ReleaseRequest, db: Session = Depends(get_db)):
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
        raise HTTPException(status_code=502, detail=f"mailcow did not reset the counter: {e}")

    # mailcow answers this delete with an empty 200 - reaching here means it
    # accepted the request. Record who was reset for the row marker.
    if request.user:
        try:
            _record_reset(db, request.user, rl_hash)
        except Exception as e:
            logger.warning(f"Counter reset done but not recorded: {e}")

    return {'rl_hash': rl_hash, 'reset': True, 'mailcow_response': response}
