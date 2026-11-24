import logging
import hashlib
import json
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from .app_time import UTC, app_tz
from .config import settings
from .database import get_db_context
from .mailcow_api import mailcow_api, MailcowAPIError
from .models import RawServiceLog, SystemSetting
from .services.db_values import add_rows, strip_nul

logger = logging.getLogger(__name__)

raw_logs_scheduler = AsyncIOScheduler(
    timezone=UTC,
    job_defaults={
        'misfire_grace_time': 30,
        'coalesce': True,
    }
)

ALL_SERVICES = [
    "acme", "api", "autodiscover", "dovecot", "netfilter",
    "postfix", "ratelimited", "rspamd-history", "sogo", "watchdog"
]

CATCHUP_SERVICES = frozenset({"postfix", "rspamd-history"})

CATCHUP_MAX_PAGES_PER_CYCLE = 10

_catchup_state: Dict[str, Dict[str, Any]] = {}
_STATE_KEY_PREFIX = 'raw_logs_catchup:'


def _persist_state(db, service: str, state: Optional[Dict[str, Any]]) -> None:
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

raw_logs_job_status = {
    'fetch_raw_logs': {'last_run': None, 'status': 'idle', 'error': None, 'stats': {}},
    'cleanup_raw_logs': {'last_run': None, 'status': 'idle', 'error': None},
}

_ws_broadcast_fn = None
_ws_broadcast_all_fn = None


def set_ws_broadcast_fn(fn):
    global _ws_broadcast_fn
    _ws_broadcast_fn = fn


def set_ws_broadcast_all_fn(fn):
    global _ws_broadcast_all_fn
    _ws_broadcast_all_fn = fn


def compute_message_hash(service: str, time_val: Any, raw_data: dict) -> str:
    time_str = str(time_val)
    message = raw_data.get('message', '') or json.dumps(raw_data, sort_keys=True)
    content = f"{service}:{time_str}:{message}"
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def _prepare_candidates(service: str, logs: List[Dict[str, Any]]) -> List[tuple]:
    candidates = []
    for log_entry in logs:
        try:
            log_entry = strip_nul(log_entry)
            time_val = log_entry.get('time') or log_entry.get('unix_time', 0)
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
    stored: Dict[str, datetime] = {}
    for i in range(0, len(hashes), 500):
        chunk = hashes[i:i + 500]
        rows = db.query(RawServiceLog.message_hash, RawServiceLog.created_at).filter(
            RawServiceLog.service == service,
            RawServiceLog.message_hash.in_(chunk)
        ).all()
        stored.update({r[0]: r[1] for r in rows})
    return stored


def _store_page(db, service: str, candidates: List[tuple], known: Set[str]) -> List[Dict[str, Any]]:
    rows = []
    entries = []
    for timestamp, msg_hash, log_entry in candidates:
        if msg_hash in known:
            continue
        known.add(msg_hash)
        rows.append(dict(service=service, time=timestamp, message_hash=msg_hash, raw_data=log_entry))
        entries.append(log_entry)
    stored = add_rows(db, RawServiceLog, rows, f'{service} log line')
    return [entry for entry, ok in zip(entries, stored) if ok]


def _page_is_history(candidates: List[tuple], stored: Dict[str, datetime],
                     known: Set[str], before: datetime) -> bool:
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
                boundary_before: datetime, budget: int, fetch) -> tuple:
    new_entries: List[Dict[str, Any]] = []
    pages = 0
    while pages < budget:
        try:
            page = await fetch('get_raw_logs_range', service, offset, page_size)
        except MailcowAPIError as e:
            logger.warning(f"[RAW LOGS] {service}: range fetch at {offset} failed, "
                           f"resuming there next cycle: {e}")
            return (new_entries, pages, offset, None)
        pages += 1
        if not page:
            return (new_entries, pages, offset, offset)

        candidates = _prepare_candidates(service, page)
        stored = _load_stored(db, service, [c[1] for c in candidates])
        known |= set(stored)
        if _page_is_history(candidates, stored, known, boundary_before):
            return (new_entries, pages, None, None)
        new_entries.extend(_store_page(db, service, candidates, known))
        if len(page) < page_size:
            return (new_entries, pages, None, None)
        offset += len(page)
    return (new_entries, pages, offset, None)


async def _collect_service(service: str, page_size: int) -> tuple:
    return await asyncio.to_thread(
        _collect_service_worker, service, page_size, asyncio.get_running_loop()
    )


def _collect_service_worker(service: str, page_size: int, request_loop) -> tuple:
    async def fetch(method, *args, **kwargs):
        future = asyncio.run_coroutine_threadsafe(
            getattr(mailcow_api, method)(*args, **kwargs), request_loop
        )
        try:
            return await asyncio.wrap_future(future)
        finally:
            if not future.done():
                future.cancel()
    return asyncio.run(_collect_service_in_worker(service, page_size, fetch))


async def _collect_service_in_worker(service: str, page_size: int, fetch) -> tuple:
    logs = await fetch('get_raw_logs', service, count=page_size)
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
                gap, used, rest, _ = await _walk(db, service, page_size, page_size, known,
                                                 cycle_started, budget, fetch)
                deeper.extend(gap)
                pages += used
                budget -= used
                if rest is not None:
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
                                                          started_at, budget, fetch)
                deeper.extend(found)
                pages += used
                if rest is None:
                    next_state = None
                elif empty_at is not None and pending and pending.get('empty_at') == empty_at:
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
    raw_logs_job_status['fetch_raw_logs']['status'] = 'running'
    raw_logs_job_status['fetch_raw_logs']['last_run'] = datetime.now(timezone.utc)

    try:
        enabled_services = settings.raw_logs_collected_list
        page_services = set(settings.raw_logs_services_list) if settings.raw_logs_page_on else set()
        if not enabled_services:
            logger.debug("[RAW LOGS] No services enabled, skipping fetch")
            raw_logs_job_status['fetch_raw_logs']['status'] = 'success'
            return

        fetch_count = settings.raw_logs_fetch_count
        fetch_count_rspamd = settings.fetch_count_rspamd
        stats: Dict[str, int] = {}

        for service in enabled_services:
            try:
                count = fetch_count_rspamd if service == 'rspamd-history' else fetch_count
                head_entries, deeper, _pages, next_state = await _collect_service(service, count)

                if next_state is None:
                    _catchup_state.pop(service, None)
                else:
                    _catchup_state[service] = next_state

                stats[service] = len(head_entries) + len(deeper)

                if head_entries and _ws_broadcast_fn and service in page_services:
                    try:
                        await _ws_broadcast_fn(service, head_entries)
                    except Exception as e:
                        logger.debug(f"[RAW LOGS] WebSocket broadcast error for {service}: {e}")

            except Exception as e:
                logger.error(f"[RAW LOGS] Error fetching {service}: {e}")
                stats[service] = -1
                continue

        total_new = sum(v for v in stats.values() if v > 0)
        if total_new > 0:
            parts = [f"{k}={v}" for k, v in stats.items() if v > 0]
            logger.info(f"[RAW LOGS] Ingested: {', '.join(parts)} (total: {total_new})")

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
    counts = await asyncio.to_thread(_load_service_counts)
    await _ws_broadcast_all_fn({"type": "service_counts", "counts": counts})


def _load_service_counts():
    from sqlalchemy import func
    
    with get_db_context() as db:
        rows = db.query(
            RawServiceLog.service,
            func.count(RawServiceLog.id)
        ).group_by(RawServiceLog.service).all()
    
    return {row[0]: row[1] for row in rows}


async def cleanup_raw_service_logs():
    await asyncio.to_thread(_cleanup_raw_service_logs_worker)


def _cleanup_raw_service_logs_worker():
    raw_logs_job_status['cleanup_raw_logs']['status'] = 'running'
    raw_logs_job_status['cleanup_raw_logs']['last_run'] = datetime.now(timezone.utc)
    
    try:
        retention_days = settings.raw_logs_retention_days
        now = datetime.now(timezone.utc)
        cutoff_date = now - timedelta(days=retention_days)
        rate_limit_cutoff = now - timedelta(days=settings.rate_limits_retention_effective)
        
        with get_db_context() as db:
            deleted = db.query(RawServiceLog).filter(
                RawServiceLog.service != 'ratelimited',
                RawServiceLog.time < cutoff_date
            ).delete()
            deleted += db.query(RawServiceLog).filter(
                RawServiceLog.service == 'ratelimited',
                RawServiceLog.time < rate_limit_cutoff
            ).delete()
            uncollected = delete_uncollected_raw_logs(db)
            
            db.commit()
            
            if deleted > 0:
                logger.info(f"[RAW LOGS CLEANUP] Deleted {deleted} entries older than {retention_days} days")
            if uncollected > 0:
                logger.info(f"[RAW LOGS CLEANUP] Deleted {uncollected} entries of services no longer collected")
        
        raw_logs_job_status['cleanup_raw_logs']['status'] = 'success'
        raw_logs_job_status['cleanup_raw_logs']['error'] = None
        
    except Exception as e:
        logger.error(f"[RAW LOGS CLEANUP] Error: {e}")
        raw_logs_job_status['cleanup_raw_logs']['status'] = 'failed'
        raw_logs_job_status['cleanup_raw_logs']['error'] = str(e)


def delete_uncollected_raw_logs(db) -> int:
    collected = settings.raw_logs_collected_list
    return db.query(RawServiceLog).filter(
        ~RawServiceLog.service.in_(collected)
    ).delete(synchronize_session=False)


def start_raw_logs_scheduler():
    if not settings.raw_logs_collected_list:
        logger.info("[RAW LOGS] No service to collect")
        return
    if not settings.raw_logs_page_on:
        logger.info("[RAW LOGS] Logs page is off; collecting only what other pages read")
    
    load_catchup_state()
    from .scheduler import every, clock_trigger, clock_schedule
    raw_logs_scheduler.timezone = app_tz()

    try:
        raw_logs_scheduler.add_job(
            fetch_raw_service_logs,
            trigger=every(seconds=settings.raw_logs_fetch_interval),
            id='fetch_raw_logs',
            name='Fetch Raw Service Logs',
            replace_existing=True,
            max_instances=1
        )
        
        raw_logs_scheduler.add_job(
            cleanup_raw_service_logs,
            trigger=clock_trigger('cleanup_raw_logs'),
            id='cleanup_raw_logs',
            name='Cleanup Raw Service Logs',
            replace_existing=True
        )
        
        raw_logs_scheduler.start()
        
        services = settings.raw_logs_collected_list
        logger.info(f"[RAW LOGS] Scheduler started")
        logger.info(f"   [FETCH] Every {settings.raw_logs_fetch_interval}s, {settings.raw_logs_fetch_count} logs/service")
        logger.info(f"   [SERVICES] {', '.join(services)} ({len(services)} enabled)")
        logger.info(f"   [RETENTION] {settings.raw_logs_retention_days} days, rate limit log {settings.rate_limits_retention_effective} days")
        logger.info(f"   [CLEANUP] {clock_schedule('cleanup_raw_logs')}")
        
    except Exception as e:
        logger.error(f"[RAW LOGS] Failed to start scheduler: {e}")
        raise


def stop_raw_logs_scheduler():
    try:
        if raw_logs_scheduler.running:
            raw_logs_scheduler.shutdown(wait=False)
            logger.info("[RAW LOGS] Scheduler stopped")
    except Exception as e:
        logger.error(f"[RAW LOGS] Error stopping scheduler: {e}")


def reschedule_raw_logs_jobs():
    if not raw_logs_scheduler.running:
        if settings.raw_logs_collected_list:
            start_raw_logs_scheduler()
        return
    
    if not settings.raw_logs_collected_list:
        stop_raw_logs_scheduler()
        return

    from .scheduler import every
    try:
        raw_logs_scheduler.add_job(
            fetch_raw_service_logs,
            trigger=every(seconds=settings.raw_logs_fetch_interval),
            id='fetch_raw_logs',
            name='Fetch Raw Service Logs',
            replace_existing=True,
            max_instances=1
        )

        logger.info(f"[RAW LOGS] Rescheduled: fetch every {settings.raw_logs_fetch_interval}s, "
                     f"services: {', '.join(settings.raw_logs_collected_list)}")
    except Exception as e:
        logger.warning(f"[RAW LOGS] Failed to reschedule: {e}")


def get_raw_logs_job_status() -> dict:
    return raw_logs_job_status
