"""
Raw Logs Worker - Separate background scheduler for fetching raw logs from all mailcow services.

This module runs independently from the main scheduler to avoid impacting
the core log processing pipeline (Postfix/Rspamd/Netfilter correlation).

Architecture:
- Separate AsyncIOScheduler instance
- Sequential fetching: one service at a time to avoid overwhelming the mailcow API
- SHA-256 dedup: prevents duplicate entries via unique constraint
- Daily cleanup: removes entries older than RAW_LOGS_RETENTION_DAYS
- WebSocket broadcast: pushes new entries to connected clients
"""
import logging
import hashlib
import json
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger

from .config import settings
from .database import get_db_context
from .mailcow_api import mailcow_api, MailcowAPIError
from .models import RawServiceLog, SystemSetting

logger = logging.getLogger(__name__)

# Separate scheduler instance for raw logs (independent from main scheduler)
raw_logs_scheduler = AsyncIOScheduler(
    job_defaults={
        'misfire_grace_time': 30,
        'coalesce': True,
    }
)

# All supported mailcow log services
ALL_SERVICES = [
    "acme", "api", "autodiscover", "dovecot", "netfilter",
    "postfix", "ratelimited", "rspamd-history", "sogo", "watchdog"
]

# Services whose newest-N page is checked for a gap and, when one may exist,
# paged deeper with the range form until the walk meets rows already stored or
# the end of mailcow's list. These are the two services the message pipeline
# depends on; the other services keep the plain newest-N fetch.
CATCHUP_SERVICES = frozenset({"postfix", "rspamd-history"})

# Deeper pages a single cycle may fetch for one service. A walk that needs more
# resumes on the next cycle from where it stopped, like the message pipeline.
CATCHUP_MAX_PAGES_PER_CYCLE = 10

# A pending deep walk per service: where to resume ('offset', lines already
# taken from the head), when the walk began ('started_at'), and the offset at
# which an empty page was last seen ('empty_at', optional). The start time is
# what tells rows this walk stored in an earlier cycle apart from older history:
# positions in mailcow's list shift every time a line arrives, so a position on
# its own cannot. Mirrored in system_settings under _STATE_KEY_PREFIX in the
# same transaction as the rows, and loaded at startup, so a restart in the
# middle of a long catch-up resumes instead of abandoning the rest.
_catchup_state: Dict[str, Dict[str, Any]] = {}
_STATE_KEY_PREFIX = 'raw_logs_catchup:'


def _persist_state(db, service: str, state: Optional[Dict[str, Any]]) -> None:
    """Write (or clear) the pending walk for a service in the caller's session,
    so it commits or rolls back together with the rows of the same cycle."""
    key = _STATE_KEY_PREFIX + service
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    if state is None:
        if row is not None:
            db.delete(row)
        return
    payload = dict(state)
    payload['started_at'] = state['started_at'].isoformat()
    value = json.dumps(payload)
    if row is None:
        db.add(SystemSetting(key=key, value=value))
    else:
        row.value = value


def load_catchup_state() -> None:
    """Load pending walks left by a previous process. Called at startup."""
    _catchup_state.clear()
    try:
        with get_db_context() as db:
            rows = db.query(SystemSetting).filter(
                SystemSetting.key.like(_STATE_KEY_PREFIX + '%')).all()
            for row in rows:
                try:
                    data = json.loads(row.value)
                    data['started_at'] = datetime.fromisoformat(data['started_at'])
                    _catchup_state[row.key[len(_STATE_KEY_PREFIX):]] = data
                except (ValueError, KeyError, TypeError) as e:
                    logger.warning(f"[RAW LOGS] Ignoring unreadable catch-up state {row.key}: {e}")
        if _catchup_state:
            logger.info(f"[RAW LOGS] Resuming catch-up for: {', '.join(sorted(_catchup_state))}")
    except Exception as e:
        logger.warning(f"[RAW LOGS] Could not load catch-up state, starting fresh: {e}")

# Service metadata for the frontend
SERVICE_METADATA = {
    "acme":          {"name": "ACME",         "icon": "lock",     "description": "SSL certificate logs"},
    "api":           {"name": "API",          "icon": "code",     "description": "API access logs"},
    "autodiscover":  {"name": "Autodiscover", "icon": "search",   "description": "Auto-configuration logs"},
    "dovecot":       {"name": "Dovecot",      "icon": "inbox",    "description": "IMAP/POP3 server logs"},
    "netfilter":     {"name": "Netfilter",    "icon": "shield",   "description": "Firewall/Fail2Ban logs"},
    "postfix":       {"name": "Postfix",      "icon": "mail",     "description": "Mail transfer agent logs", "has_smart_filters": True},
    "ratelimited":   {"name": "Ratelimited",  "icon": "clock",    "description": "Rate limiting logs"},
    "rspamd-history":{"name": "Rspamd",       "icon": "filter",   "description": "Spam filter history"},
    "sogo":          {"name": "SOGo",         "icon": "calendar",  "description": "Groupware logs"},
    "watchdog":      {"name": "Watchdog",     "icon": "eye",      "description": "Container monitoring logs"},
}

# Track services that returned 404 (not available on this mailcow instance)
_unavailable_services: Set[str] = set()

# Job status for monitoring
raw_logs_job_status = {
    'fetch_raw_logs': {'last_run': None, 'status': 'idle', 'error': None, 'stats': {}},
    'cleanup_raw_logs': {'last_run': None, 'status': 'idle', 'error': None},
}

# Reference to the WebSocket broadcast functions (set by the router module)
_ws_broadcast_fn = None
_ws_broadcast_all_fn = None


def set_ws_broadcast_fn(fn):
    """Set the WebSocket broadcast function. Called by the router module on startup."""
    global _ws_broadcast_fn
    _ws_broadcast_fn = fn


def set_ws_broadcast_all_fn(fn):
    """Set the broadcast-to-all function. Called by the router module on startup."""
    global _ws_broadcast_all_fn
    _ws_broadcast_all_fn = fn


def compute_message_hash(service: str, time_val: Any, raw_data: dict) -> str:
    """
    Compute a SHA-256 hash for deduplication.
    Uses service + timestamp + message content (or full JSON if no message field).
    """
    time_str = str(time_val)
    # Use 'message' field if available, otherwise hash the full JSON
    message = raw_data.get('message', '') or json.dumps(raw_data, sort_keys=True)
    content = f"{service}:{time_str}:{message}"
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def _prepare_candidates(service: str, logs: List[Dict[str, Any]]) -> List[tuple]:
    """Turn raw API entries into (timestamp, message_hash, entry) tuples,
    skipping anything without a usable time."""
    candidates = []
    for log_entry in logs:
        try:
            time_val = log_entry.get('time') or log_entry.get('unix_time', 0)
            # mailcow API often returns time as a string - cast to number
            try:
                time_val = int(time_val)
            except (ValueError, TypeError):
                try:
                    time_val = float(time_val)
                except (ValueError, TypeError):
                    continue

            if time_val <= 0:
                continue

            timestamp = datetime.fromtimestamp(time_val, tz=timezone.utc)
            msg_hash = compute_message_hash(service, time_val, log_entry)
            candidates.append((timestamp, msg_hash, log_entry))
        except Exception as e:
            logger.error(f"[RAW LOGS] Error processing {service} entry: {e}")
            continue
    return candidates


def _load_stored(db, service: str, hashes: List[str]) -> Dict[str, datetime]:
    """Which of these hashes are already committed for the service, and when
    each was stored (created_at, naive UTC)."""
    stored: Dict[str, datetime] = {}
    # Query in chunks of 500 to avoid overly large IN clauses
    for i in range(0, len(hashes), 500):
        chunk = hashes[i:i + 500]
        rows = db.query(RawServiceLog.message_hash, RawServiceLog.created_at).filter(
            RawServiceLog.service == service,
            RawServiceLog.message_hash.in_(chunk)
        ).all()
        stored.update({r[0]: r[1] for r in rows})
    return stored


def _store_page(db, service: str, candidates: List[tuple], known: Set[str]) -> List[Dict[str, Any]]:
    """Add the candidates that are not yet stored. Returns their raw entries.
    Mutates `known` so a hash repeated within one cycle is stored once."""
    new_entries = []
    for timestamp, msg_hash, log_entry in candidates:
        if msg_hash in known:
            continue
        try:
            db.add(RawServiceLog(
                service=service,
                time=timestamp,
                message_hash=msg_hash,
                raw_data=log_entry,
            ))
            new_entries.append(log_entry)
            known.add(msg_hash)
        except Exception as e:
            logger.error(f"[RAW LOGS] Error inserting {service} entry: {e}")
            continue
    return new_entries


def _page_is_history(candidates: List[tuple], stored: Dict[str, datetime],
                     known: Set[str], before: datetime) -> bool:
    """True when every line on the page is already stored AND was stored before
    `before`. Rows stored by this walk in an earlier cycle (or by this cycle's
    head page) fail the time test: they mean the list shifted under the walk,
    not that older history was reached."""
    if not candidates:
        return False
    for _, h, _ in candidates:
        if h not in known:
            return False
        when = stored.get(h)
        if when is None or when >= before:
            return False
    return True


async def _walk(db, service: str, page_size: int, offset: int, known: Set[str],
                boundary_before: datetime, budget: int) -> tuple:
    """Page deeper from `offset` until a page is entirely rows stored before
    `boundary_before`, or the end of mailcow's list, or `budget` pages.

    Returns (new_entries, pages_fetched, next_offset_or_None, empty_at).
    next_offset None means the walk finished on a short page or on rows already
    stored; an int means it must resume there on a later cycle. empty_at is the
    offset at which mailcow answered with nothing - the caller decides whether
    that is the end of the list (it is only trusted when it repeats, because
    mailcow also answers {} when a backend such as rspamd is briefly down). A
    range request that fails ends the walk for this cycle without discarding
    what was already fetched; the caller resumes from the same offset next time.
    """
    new_entries: List[Dict[str, Any]] = []
    pages = 0
    while pages < budget:
        try:
            page = await mailcow_api.get_raw_logs_range(service, offset, page_size)
        except MailcowAPIError as e:
            logger.warning(f"[RAW LOGS] {service}: range fetch at {offset} failed, "
                           f"resuming there next cycle: {e}")
            return (new_entries, pages, offset, None)
        pages += 1
        if not page:
            return (new_entries, pages, offset, offset)   # empty: end, or a hiccup

        candidates = _prepare_candidates(service, page)
        stored = _load_stored(db, service, [c[1] for c in candidates])
        known |= set(stored)
        if _page_is_history(candidates, stored, known, boundary_before):
            return (new_entries, pages, None, None)     # reached what we already had
        new_entries.extend(_store_page(db, service, candidates, known))
        if len(page) < page_size:
            return (new_entries, pages, None, None)     # short page: end of the list
        offset += len(page)
    return (new_entries, pages, offset, None)


async def _collect_service(service: str, page_size: int) -> tuple:
    """Fetch and store one service for this cycle.

    Returns (head_entries, deeper_entries, pages, pending_state); head_entries
    is None when the service is unavailable. The head page (newest N) is always
    fetched, so the Live Logs page stays current, and only its new lines are
    broadcast live. For CATCHUP_SERVICES the head page is then read as
    evidence: a full page on which every row was new means lines may have been
    missed, and the walk goes deeper.

    `pending_state` is what _catchup_state[service] should become after the
    caller's commit (None to clear). It is returned rather than written here so
    a failed commit leaves the previous resume position in place.
    """
    logs = await mailcow_api.get_raw_logs(service, count=page_size)
    if logs is None:
        return (None, [], 0, _catchup_state.get(service))
    if not logs:
        return ([], [], 1, _catchup_state.get(service))

    candidates = _prepare_candidates(service, logs)
    if not candidates:
        return ([], [], 1, _catchup_state.get(service))

    cycle_started = datetime.utcnow()
    pending = _catchup_state.get(service)
    next_state = pending

    with get_db_context() as db:
        stored = _load_stored(db, service, [c[1] for c in candidates])
        known: Set[str] = set(stored)
        seam = bool(stored)
        head_entries = _store_page(db, service, candidates, known)
        deeper: List[Dict[str, Any]] = []
        pages = 1

        if service in CATCHUP_SERVICES:
            head_is_full = len(logs) >= page_size
            budget = CATCHUP_MAX_PAGES_PER_CYCLE

            if pending and head_is_full and not seam:
                # More than a page arrived since the last cycle while a deep walk
                # is pending. The lines between this head page and the previous
                # cycle's head were never requested: close that gap first, from
                # just below the head, stopping at rows stored before this cycle.
                gap, used, rest, _ = await _walk(db, service, page_size, page_size, known,
                                                 cycle_started, budget)
                deeper.extend(gap)
                pages += used
                budget -= used
                if rest is not None:
                    # The burst was larger than a whole cycle's budget. Make the
                    # gap the pending walk; the deeper region is re-walked later
                    # (its rows are recognised as this walk's own and passed).
                    next_state = {'offset': rest, 'started_at': pending['started_at']}
                    budget = 0

            if budget > 0 and (pending or (head_is_full and not seam)):
                if pending:
                    offset = pending['offset']
                    started_at = pending['started_at']
                else:
                    offset = page_size
                    started_at = cycle_started
                    logger.info(
                        f"[RAW LOGS] {service}: a full page of {len(logs)} new lines with no "
                        f"overlap - paging deeper to close the gap"
                    )
                found, used, rest, empty_at = await _walk(db, service, page_size, offset, known,
                                                          started_at, budget)
                deeper.extend(found)
                pages += used
                if rest is None:
                    next_state = None
                elif empty_at is not None and pending and pending.get('empty_at') == empty_at:
                    # Nothing at this offset two cycles in a row: the end is real.
                    next_state = None
                else:
                    next_state = {'offset': rest, 'started_at': started_at}
                    if empty_at is not None:
                        next_state['empty_at'] = empty_at
                if used:
                    tail = "" if rest is None else f", resuming at {rest} next cycle"
                    logger.info(
                        f"[RAW LOGS] {service}: caught up {len(found)} lines across "
                        f"{used} page(s){tail}"
                    )

        if head_entries or deeper or next_state != pending:
            _persist_state(db, service, next_state)
            db.commit()

    return (head_entries, deeper, pages, next_state)


async def fetch_raw_service_logs():
    """
    Main fetch job - runs every RAW_LOGS_FETCH_INTERVAL seconds.
    Sequentially fetches logs from each enabled service and stores in DB.
    After storing, broadcasts new entries via WebSocket.
    """
    raw_logs_job_status['fetch_raw_logs']['status'] = 'running'
    raw_logs_job_status['fetch_raw_logs']['last_run'] = datetime.now(timezone.utc)

    # Runtime feature check - skip if logs feature was disabled after startup
    if not settings.is_feature_enabled('logs') or not settings.raw_logs_enabled:
        raw_logs_job_status['fetch_raw_logs']['status'] = 'success'
        return

    try:
        enabled_services = settings.raw_logs_services_list
        if not enabled_services:
            logger.debug("[RAW LOGS] No services enabled, skipping fetch")
            raw_logs_job_status['fetch_raw_logs']['status'] = 'success'
            return

        fetch_count = settings.raw_logs_fetch_count
        fetch_count_rspamd = settings.fetch_count_rspamd
        stats: Dict[str, int] = {}

        for service in enabled_services:
            # Skip services that we know are unavailable on this mailcow instance
            if service in _unavailable_services:
                continue

            try:
                # Use fetch_count_rspamd for rspamd-history (each entry is a full email record, much heavier)
                count = fetch_count_rspamd if service == 'rspamd-history' else fetch_count
                head_entries, deeper, _pages, next_state = await _collect_service(service, count)

                if head_entries is None:
                    # Service returned an error - mark as unavailable
                    _unavailable_services.add(service)
                    logger.warning(f"[RAW LOGS] Service '{service}' is not available on this mailcow instance, skipping in future runs")
                    continue

                # The commit succeeded (or there was nothing to commit): only now
                # is it safe to move or clear the resume position.
                if next_state is None:
                    _catchup_state.pop(service, None)
                else:
                    _catchup_state[service] = next_state

                stats[service] = len(head_entries) + len(deeper)

                # Broadcast only what is genuinely new at the head. Caught-up
                # history is older than what the page already shows and would
                # appear at the newest end if streamed.
                if head_entries and _ws_broadcast_fn:
                    try:
                        await _ws_broadcast_fn(service, head_entries)
                    except Exception as e:
                        logger.debug(f"[RAW LOGS] WebSocket broadcast error for {service}: {e}")

            except Exception as e:
                logger.error(f"[RAW LOGS] Error fetching {service}: {e}")
                stats[service] = -1
                continue

        # Log summary (only if we got new data)
        total_new = sum(v for v in stats.values() if v > 0)
        if total_new > 0:
            parts = [f"{k}={v}" for k, v in stats.items() if v > 0]
            logger.info(f"[RAW LOGS] Ingested: {', '.join(parts)} (total: {total_new})")

        # Broadcast updated service counts to all connected WS clients
        if _ws_broadcast_all_fn:
            try:
                await _broadcast_service_counts()
            except Exception as e:
                logger.debug(f"[RAW LOGS] Service counts broadcast error: {e}")
        
        raw_logs_job_status['fetch_raw_logs']['status'] = 'success'
        raw_logs_job_status['fetch_raw_logs']['stats'] = stats
        raw_logs_job_status['fetch_raw_logs']['error'] = None
        
    except asyncio.CancelledError:
        logger.info("[RAW LOGS] Fetch cycle cancelled by shutdown")
        return
    except Exception as e:
        logger.error(f"[RAW LOGS] Fetch cycle error: {e}")
        raw_logs_job_status['fetch_raw_logs']['status'] = 'failed'
        raw_logs_job_status['fetch_raw_logs']['error'] = str(e)

async def _broadcast_service_counts():
    """Query DB for per-service log counts and broadcast to all WS clients."""
    from sqlalchemy import func
    
    with get_db_context() as db:
        rows = db.query(
            RawServiceLog.service,
            func.count(RawServiceLog.id)
        ).group_by(RawServiceLog.service).all()
    
    counts = {row[0]: row[1] for row in rows}
    
    await _ws_broadcast_all_fn({
        "type": "service_counts",
        "counts": counts,
    })


async def cleanup_raw_service_logs():
    """
    Daily cleanup job - removes raw logs older than RAW_LOGS_RETENTION_DAYS.
    Runs at 3:00 AM (offset from main cleanup at 2:00 AM).
    """
    raw_logs_job_status['cleanup_raw_logs']['status'] = 'running'
    raw_logs_job_status['cleanup_raw_logs']['last_run'] = datetime.now(timezone.utc)
    
    # Runtime feature check
    if not settings.is_feature_enabled('logs') or not settings.raw_logs_enabled:
        raw_logs_job_status['cleanup_raw_logs']['status'] = 'success'
        return
    
    try:
        retention_days = settings.raw_logs_retention_days
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        
        with get_db_context() as db:
            deleted = db.query(RawServiceLog).filter(
                RawServiceLog.time < cutoff_date
            ).delete()
            
            db.commit()
            
            if deleted > 0:
                logger.info(f"[RAW LOGS CLEANUP] Deleted {deleted} entries older than {retention_days} days")
        
        raw_logs_job_status['cleanup_raw_logs']['status'] = 'success'
        raw_logs_job_status['cleanup_raw_logs']['error'] = None
        
    except Exception as e:
        logger.error(f"[RAW LOGS CLEANUP] Error: {e}")
        raw_logs_job_status['cleanup_raw_logs']['status'] = 'failed'
        raw_logs_job_status['cleanup_raw_logs']['error'] = str(e)


def start_raw_logs_scheduler():
    """Start the raw logs background scheduler (called from main.py startup)"""
    if not settings.raw_logs_enabled or not settings.is_feature_enabled('logs'):
        reason = "RAW_LOGS_ENABLED=false" if not settings.raw_logs_enabled else "Logs feature disabled"
        logger.info(f"[RAW LOGS] Raw logs collection is disabled ({reason})")
        return
    
    load_catchup_state()

    try:
        # Fetch job - every RAW_LOGS_FETCH_INTERVAL seconds
        raw_logs_scheduler.add_job(
            fetch_raw_service_logs,
            trigger=IntervalTrigger(seconds=settings.raw_logs_fetch_interval),
            id='fetch_raw_logs',
            name='Fetch Raw Service Logs',
            replace_existing=True,
            max_instances=1
        )
        
        # Cleanup job - daily at 3:00 AM
        raw_logs_scheduler.add_job(
            cleanup_raw_service_logs,
            trigger=CronTrigger(hour=3, minute=0),
            id='cleanup_raw_logs',
            name='Cleanup Raw Service Logs',
            replace_existing=True
        )
        
        raw_logs_scheduler.start()
        
        services = settings.raw_logs_services_list
        logger.info(f"[RAW LOGS] Scheduler started")
        logger.info(f"   [FETCH] Every {settings.raw_logs_fetch_interval}s, {settings.raw_logs_fetch_count} logs/service")
        logger.info(f"   [SERVICES] {', '.join(services)} ({len(services)} enabled)")
        logger.info(f"   [RETENTION] {settings.raw_logs_retention_days} days")
        logger.info(f"   [CLEANUP] Daily at 3:00 AM")
        
    except Exception as e:
        logger.error(f"[RAW LOGS] Failed to start scheduler: {e}")
        raise


def stop_raw_logs_scheduler():
    """Stop the raw logs background scheduler (called from main.py shutdown)"""
    try:
        if raw_logs_scheduler.running:
            raw_logs_scheduler.shutdown(wait=False)
            logger.info("[RAW LOGS] Scheduler stopped")
    except Exception as e:
        logger.error(f"[RAW LOGS] Error stopping scheduler: {e}")


def reschedule_raw_logs_jobs():
    """
    Reschedule raw logs jobs when settings change.
    Called from reschedule_interval_jobs() in scheduler.py.
    """
    if not raw_logs_scheduler.running:
        if settings.raw_logs_enabled:
            # Scheduler wasn't running but now it should be
            start_raw_logs_scheduler()
        return
    
    if not settings.raw_logs_enabled:
        # Disable: stop the scheduler
        stop_raw_logs_scheduler()
        return
    
    try:
        # Update fetch interval
        raw_logs_scheduler.add_job(
            fetch_raw_service_logs,
            trigger=IntervalTrigger(seconds=settings.raw_logs_fetch_interval),
            id='fetch_raw_logs',
            name='Fetch Raw Service Logs',
            replace_existing=True,
            max_instances=1
        )
        
        # Clear unavailable services cache so they're retried
        _unavailable_services.clear()
        
        logger.info(f"[RAW LOGS] Rescheduled: fetch every {settings.raw_logs_fetch_interval}s, "
                     f"services: {', '.join(settings.raw_logs_services_list)}")
    except Exception as e:
        logger.warning(f"[RAW LOGS] Failed to reschedule: {e}")


def get_raw_logs_job_status() -> dict:
    """Get raw logs job status for monitoring"""
    return raw_logs_job_status
