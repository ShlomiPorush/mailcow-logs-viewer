"""
Raw Logs Worker — Separate background scheduler for fetching raw logs from all mailcow services.

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
from .mailcow_api import mailcow_api
from .models import RawServiceLog

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


async def fetch_raw_service_logs():
    """
    Main fetch job — runs every RAW_LOGS_FETCH_INTERVAL seconds.
    Sequentially fetches logs from each enabled service and stores in DB.
    After storing, broadcasts new entries via WebSocket.
    """
    raw_logs_job_status['fetch_raw_logs']['status'] = 'running'
    raw_logs_job_status['fetch_raw_logs']['last_run'] = datetime.now(timezone.utc)
    
    # Runtime feature check — skip if logs feature was disabled after startup
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
                logs = await mailcow_api.get_raw_logs(service, count=count)
                
                if logs is None:
                    # Service returned an error — mark as unavailable
                    _unavailable_services.add(service)
                    logger.warning(f"[RAW LOGS] Service '{service}' is not available on this mailcow instance, skipping in future runs")
                    continue
                
                if not logs:
                    stats[service] = 0
                    continue
                
                new_entries = []
                
                with get_db_context() as db:
                    # Pre-compute hashes and timestamps for all entries
                    candidates = []
                    for log_entry in logs:
                        try:
                            time_val = log_entry.get('time') or log_entry.get('unix_time', 0)
                            # mailcow API often returns time as a string — cast to number
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
                    
                    if not candidates:
                        stats[service] = 0
                        continue
                    
                    # Batch lookup: find which hashes already exist in DB
                    candidate_hashes = [c[1] for c in candidates]
                    existing_hashes = set()
                    
                    # Query in chunks of 500 to avoid overly large IN clauses
                    for i in range(0, len(candidate_hashes), 500):
                        chunk = candidate_hashes[i:i+500]
                        rows = db.query(RawServiceLog.message_hash).filter(
                            RawServiceLog.service == service,
                            RawServiceLog.message_hash.in_(chunk)
                        ).all()
                        existing_hashes.update(r[0] for r in rows)
                    
                    # Insert only new entries
                    new_count = 0
                    for timestamp, msg_hash, log_entry in candidates:
                        if msg_hash in existing_hashes:
                            continue
                        
                        try:
                            raw_log = RawServiceLog(
                                service=service,
                                time=timestamp,
                                message_hash=msg_hash,
                                raw_data=log_entry,
                            )
                            db.add(raw_log)
                            new_count += 1
                            new_entries.append(log_entry)
                            existing_hashes.add(msg_hash)  # Prevent duplicates within same batch
                        except Exception as e:
                            logger.error(f"[RAW LOGS] Error inserting {service} entry: {e}")
                            continue
                    
                    if new_count > 0:
                        db.commit()
                    
                    stats[service] = new_count
                
                # Broadcast new entries via WebSocket
                if new_entries and _ws_broadcast_fn:
                    try:
                        await _ws_broadcast_fn(service, new_entries)
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
    Daily cleanup job — removes raw logs older than RAW_LOGS_RETENTION_DAYS.
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
    
    try:
        # Fetch job — every RAW_LOGS_FETCH_INTERVAL seconds
        raw_logs_scheduler.add_job(
            fetch_raw_service_logs,
            trigger=IntervalTrigger(seconds=settings.raw_logs_fetch_interval),
            id='fetch_raw_logs',
            name='Fetch Raw Service Logs',
            replace_existing=True,
            max_instances=1
        )
        
        # Cleanup job — daily at 3:00 AM
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
