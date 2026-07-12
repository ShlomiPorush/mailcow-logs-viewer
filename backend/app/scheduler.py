"""
Background scheduler
"""
import logging
import asyncio
import hashlib
import re
import httpx
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Set, Optional, List, Dict, Any
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_
from sqlalchemy.exc import IntegrityError

from .config import settings, set_cached_active_domains
from .database import get_db_context, SessionLocal
from .mailcow_api import mailcow_api
from .models import PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation, DMARCSync, DomainDNSCheck, MailboxStatistics, AliasStatistics, MonitoredHost, BlacklistCheck, DMARCReport, DMARCRecord, TLSReport, TLSReportPolicy, SpamSuppression
from .correlation import detect_direction, parse_postfix_message
from .routers.domains import check_domain_dns, save_dns_check_to_db
from .services.dmarc_imap_service import sync_dmarc_reports_from_imap
from .services.dmarc_notifications import send_dmarc_error_notification
from .services import geoip_service

from .services.geoip_downloader import is_license_configured
from .services.dmarc_cache import clear_dmarc_cache

logger = logging.getLogger(__name__)

# Thread pool executor for blocking I/O operations (can be replaced when scheduler_workers changes)
_thread_pool_executor = ThreadPoolExecutor(max_workers=settings.scheduler_workers, thread_name_prefix="imap_sync")


def get_thread_pool_executor():
    """Return the current thread pool executor (used so it can be updated when settings change)."""
    return _thread_pool_executor


def reschedule_interval_jobs():
    """
    Reschedule jobs that use dynamic intervals (fetch_interval, correlation_check_interval, dmarc_imap_interval).
    Call after reload_settings() so interval changes take effect without restart.
    """
    global _thread_pool_executor
    if not scheduler.running:
        return
    try:
        # Reschedule fetch_logs
        scheduler.add_job(
            fetch_all_logs,
            trigger=IntervalTrigger(seconds=settings.fetch_interval),
            id='fetch_logs',
            name='Fetch mailcow Logs',
            replace_existing=True,
            max_instances=1
        )
        # Reschedule complete_correlations
        scheduler.add_job(
            complete_incomplete_correlations,
            trigger=IntervalTrigger(seconds=settings.correlation_check_interval),
            id='complete_correlations',
            name='Complete Correlations',
            replace_existing=True,
            max_instances=1
        )
        # Reschedule update_final_status
        scheduler.add_job(
            update_final_status_for_correlations,
            trigger=IntervalTrigger(seconds=settings.correlation_check_interval),
            id='update_final_status',
            name='Update Final Status',
            replace_existing=True,
            max_instances=1
        )
        # Reschedule DMARC IMAP sync if enabled
        if settings.dmarc_imap_enabled:
            scheduler.add_job(
                dmarc_imap_sync_job,
                IntervalTrigger(seconds=settings.dmarc_imap_interval),
                id='dmarc_imap_sync',
                name='DMARC IMAP Sync',
                replace_existing=True
            )
        # Update thread pool size if scheduler_workers changed
        new_workers = getattr(settings, 'scheduler_workers', 4)
        if _thread_pool_executor._max_workers != new_workers:
            old_executor = _thread_pool_executor
            _thread_pool_executor = ThreadPoolExecutor(max_workers=new_workers, thread_name_prefix="imap_sync")
            try:
                old_executor.shutdown(wait=False)
            except Exception:
                pass
            logger.info(f"Scheduler thread pool updated to {new_workers} workers")
        logger.info(f"Rescheduled interval jobs: fetch={settings.fetch_interval}s, correlation={settings.correlation_check_interval}s")
        # Also reschedule raw logs worker if active
        try:
            from .raw_logs_worker import reschedule_raw_logs_jobs
            reschedule_raw_logs_jobs()
        except Exception as e:
            logger.warning(f"Failed to reschedule raw logs jobs: {e}")

        # Reschedule suppression jobs based on current settings
        _reschedule_suppression_jobs()

    except Exception as e:
        logger.warning("Failed to reschedule interval jobs: %s", e)


def _reschedule_suppression_jobs():
    """Add or remove suppression-related jobs based on current settings."""
    if not scheduler.running:
        return

    spam_enabled = settings.is_feature_enabled('spam-filter') and settings.suppression_enabled

    # detect_suppressions
    if spam_enabled and settings.suppression_auto_detect:
        scheduler.add_job(
            detect_suppressions_job,
            trigger=IntervalTrigger(minutes=5),
            id='detect_suppressions',
            name='Detect Suppressions',
            replace_existing=True,
            max_instances=1
        )
        logger.info("   [SPAM] Suppression detection: scheduled (every 5 minutes)")
    else:
        try:
            scheduler.remove_job('detect_suppressions')
        except Exception:
            pass

    # sync_suppressions
    if spam_enabled and settings.suppression_rspamd_sync and settings.is_rspamd_configured:
        scheduler.add_job(
            sync_suppressions_to_rspamd_job,
            trigger=IntervalTrigger(minutes=10),
            id='sync_suppressions',
            name='Sync Suppressions to Rspamd',
            replace_existing=True,
            max_instances=1
        )
        logger.info("   [SPAM] Rspamd sync: scheduled (every 10 minutes)")
    else:
        try:
            scheduler.remove_job('sync_suppressions')
        except Exception:
            pass

    # expire_suppressions
    if spam_enabled:
        scheduler.add_job(
            expire_suppressions_job,
            trigger=IntervalTrigger(hours=1),
            id='expire_suppressions',
            name='Expire Suppressions',
            replace_existing=True,
            max_instances=1
        )
        logger.info("   [SPAM] Expiry check: scheduled (every hour)")
    else:
        try:
            scheduler.remove_job('expire_suppressions')
        except Exception:
            pass

    # cleanup_deferred_queue
    if spam_enabled and settings.queue_cleanup_enabled and mailcow_api.has_rw_key:
        scheduler.add_job(
            cleanup_deferred_queue_job,
            trigger=IntervalTrigger(minutes=5),
            id='cleanup_deferred_queue',
            name='Cleanup Deferred Queue',
            replace_existing=True,
            max_instances=1
        )
        logger.info("   [SPAM] Deferred queue cleanup: scheduled (every 5 minutes)")
    else:
        try:
            scheduler.remove_job('cleanup_deferred_queue')
        except Exception:
            pass

# Job execution tracking
job_status = {
    'fetch_logs': {'last_run': None, 'status': 'idle', 'error': None},
    'complete_correlations': {'last_run': None, 'status': 'idle', 'error': None},
    'update_final_status': {'last_run': None, 'status': 'idle', 'error': None},
    'expire_correlations': {'last_run': None, 'status': 'idle', 'error': None},
    'cleanup_logs': {'last_run': None, 'status': 'idle', 'error': None},
    'cleanup_dmarc_reports': {'last_run': None, 'status': 'idle', 'error': None},
    'check_app_version': {'last_run': None, 'status': 'idle', 'error': None},
    'dns_check': {'last_run': None, 'status': 'idle', 'error': None},
    'update_geoip': {'last_run': None, 'status': 'idle', 'error': None},
    'dmarc_imap_sync': {'last_run': None, 'status': 'idle', 'error': None},
    'mailbox_stats': {'last_run': None, 'status': 'idle', 'error': None},
    'alias_stats': {'last_run': None, 'status': 'idle', 'error': None},
    'blacklist_check': {'last_run': None, 'status': 'idle', 'error': None},
    'send_weekly_summary': {'last_run': None, 'status': 'idle', 'error': None},
    'sync_transports': {'last_run': None, 'status': 'idle', 'error': None},
    'fetch_raw_logs': {'last_run': None, 'status': 'idle', 'error': None},
    'cleanup_raw_logs': {'last_run': None, 'status': 'idle', 'error': None},
    'detect_suppressions': {'last_run': None, 'status': 'idle', 'error': None},
    'sync_suppressions': {'last_run': None, 'status': 'idle', 'error': None},
    'expire_suppressions': {'last_run': None, 'status': 'idle', 'error': None},
    'process_quarantine_rules': {'last_run': None, 'status': 'idle', 'error': None},
    'cleanup_deferred_queue': {'last_run': None, 'status': 'idle', 'error': None},
}

# Number of hosts that were listed on actionable blacklists in the previous blacklist check run (for "cleared" notification)
_blacklist_last_listed_actionable_count = 0

def update_job_status(job_name: str, status: str, error: str = None):
    """Update job execution status"""
    job_status[job_name] = {
        'last_run': datetime.now(timezone.utc),
        'status': status,
        'error': error
    }

def get_job_status():
    """Get all job statuses"""
    return job_status

# App version cache (shared with status router)
app_version_cache = {
    "checked_at": None,
    "current_version": None,  # Will be set on first check
    "latest_version": None,
    "update_available": False,
    "changelog": None
}

def is_version_newer(latest_version: str, current_version: str) -> bool:
    """
    Compare two semantic versions and return True if latest_version is newer than current_version.
    
    Uses packaging.version.Version for proper semantic version comparison if available,
    otherwise falls back to simple numeric comparison.
    
    Args:
        latest_version: The version to check if it's newer (e.g., "2.2.6")
        current_version: The current version to compare against (e.g., "2.2.5")
    
    Returns:
        True if latest_version > current_version, False otherwise
    """
    try:
        # Try using packaging.version.Version for robust semantic version comparison
        from packaging.version import Version
        return Version(latest_version) > Version(current_version)
    except ImportError:
        # Fallback: simple numeric comparison for major.minor.patch format
        logger.warning("packaging module not available, using fallback version comparison")
        try:
            def parse_version(version_str: str) -> tuple:
                """Parse version string into tuple of integers"""
                # Remove any non-numeric suffixes (e.g., "2.2.6-dev" -> "2.2.6")
                version_str = re.sub(r'[^0-9.].*$', '', version_str)
                parts = version_str.split('.')
                # Convert to integers, pad with zeros if needed
                return tuple(int(part) for part in parts[:3] + ['0'] * (3 - len(parts[:3])))
            
            latest_parts = parse_version(latest_version)
            current_parts = parse_version(current_version)
            return latest_parts > current_parts
        except (ValueError, AttributeError) as e:
            logger.error(f"Failed to compare versions '{latest_version}' and '{current_version}': {e}")
            # If comparison fails, default to False (no update available)
            return False

async def check_app_version_update():
    """
    Check for app version updates from GitHub and update the cache.
    This function is called by the scheduler and can also be called from the API endpoint.
    """
    update_job_status('check_app_version', 'running')
    
    global app_version_cache
    
    # Get current version from VERSION file
    try:
        from .version import __version__
        current_version = __version__
        app_version_cache["current_version"] = current_version
    except Exception as e:
        logger.error(f"Failed to read current version: {e}")
        update_job_status('check_app_version', 'failed', str(e))
        return
    
    logger.info("Checking app version and updates from GitHub...")
    
    # Check GitHub for latest version
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                "https://api.github.com/repos/ShlomiPorush/mailcow-logs-viewer/releases/latest"
            )
            
            if response.status_code == 200:
                release_data = response.json()
                latest_version = release_data.get('tag_name', 'unknown')
                # Remove 'v' prefix if present
                if latest_version.startswith('v'):
                    latest_version = latest_version[1:]
                changelog = release_data.get('body', '')
                
                app_version_cache["latest_version"] = latest_version
                app_version_cache["changelog"] = changelog
                
                # Compare versions (proper semantic version comparison)
                # Only show update available if latest_version is actually newer than current_version
                app_version_cache["update_available"] = is_version_newer(latest_version, current_version)
                
                logger.info(f"App version check: Current={current_version}, Latest={latest_version}, Update Available={app_version_cache['update_available']}")
                update_job_status('check_app_version', 'success')
            else:
                logger.warning(f"GitHub API returned status {response.status_code}")
                app_version_cache["latest_version"] = "unknown"
                app_version_cache["update_available"] = False
                update_job_status('check_app_version', 'failed', f"GitHub API returned {response.status_code}")
                
    except Exception as e:
        logger.error(f"Failed to check GitHub for app updates: {e}")
        app_version_cache["latest_version"] = "unknown"
        app_version_cache["update_available"] = False
        update_job_status('check_app_version', 'failed', str(e))
    
    app_version_cache["checked_at"] = datetime.now(timezone.utc)

def get_app_version_cache():
    """Get app version cache (for API endpoint)"""
    return app_version_cache

scheduler = AsyncIOScheduler(
    job_defaults={
        'misfire_grace_time': 30,
        'coalesce': True,
    }
)

seen_postfix: Set[str] = set()
seen_rspamd: Set[str] = set()
seen_netfilter: Set[str] = set()

# Resume offsets: when max pages is hit, next cycle continues from here
_resume_offset: Dict[str, int] = {
    'postfix': 0,
    'rspamd': 0,
}

last_fetch_run_time: Dict[str, Optional[datetime]] = {
    'postfix': None,
    'rspamd': None,
    'netfilter': None
}

def is_blacklisted(email: Optional[str]) -> bool:
    """
    Check if email is in blacklist.
    
    Args:
        email: Email address to check
    
    Returns:
        True if blacklisted, False otherwise
    """
    if not email:
        return False
    
    email_lower = email.lower().strip()
    blacklist = settings.blacklist_emails_list
    
    if not blacklist:
        return False
    
    is_blocked = email_lower in blacklist
    if is_blocked:
        logger.debug(f"Blacklist: blocking {email_lower}")
    
    return is_blocked


# Cache for log discovery results to avoid expensive binary search on every cycle
_log_count_cache: Dict[str, tuple] = {}  # log_type -> (count, cached_at)
_LOG_COUNT_CACHE_TTL = 300  # seconds (5 minutes)


async def _discover_total_logs(log_type: str) -> int:
    """
    Discover total number of available logs using progressive probing.
    
    Uses decreasing step sizes (100k -> 10k -> 1k) to narrow down the
    total log count with minimal API calls (~30 probes max).
    Results are cached for 5 minutes to avoid repeating the expensive
    binary search on every fetch cycle.
    
    Args:
        log_type: 'postfix' or 'rspamd-history'
    
    Returns:
        Approximate total log count (accurate within 1000)
    """
    # Check cache first
    cached = _log_count_cache.get(log_type)
    if cached:
        count, cached_at = cached
        age = (datetime.now(timezone.utc) - cached_at).total_seconds()
        if age < _LOG_COUNT_CACHE_TTL:
            logger.debug(f"[{log_type.upper()}] Using cached log count: {count} (age: {int(age)}s)")
            return count

    position = 0
    try:
        for step in [100000, 10000, 1000, 100, 10, 1]:
            while True:
                probe_pos = position + step
                exists = await mailcow_api.probe_log_position(log_type, probe_pos)
                if exists:
                    position = probe_pos
                else:
                    break
    except asyncio.CancelledError:
        logger.warning(f"[{log_type.upper()}] Log discovery cancelled (task timeout or shutdown)")
        return 0
    except Exception as e:
        logger.warning(f"[{log_type.upper()}] Log discovery failed: {e}")
        return 0

    # Cache the result
    _log_count_cache[log_type] = (position, datetime.now(timezone.utc))
    return position


async def fetch_and_store_postfix():
    """Fetch Postfix logs from API and store in DB (paginated — fetches all available logs)"""
    last_fetch_run_time['postfix'] = datetime.now(timezone.utc)
    
    page_size = settings.fetch_count_postfix
    max_pages = settings.fetch_max_pages
    offset = _resume_offset['postfix']
    total_new = 0
    total_skipped = 0
    total_blacklisted = 0
    page_num = 0
    
    try:
        # Discover total available logs in mailcow
        total_available = await _discover_total_logs('postfix')
        
        if total_available == 0:
            logger.debug("[POSTFIX] No logs available in mailcow")
            return
        
        # If resume offset is beyond total, reset
        if offset >= total_available:
            offset = 0
            _resume_offset['postfix'] = 0
        
        remaining = total_available - offset
        total_pages_needed = (remaining + page_size - 1) // page_size
        pages_to_fetch = min(total_pages_needed, max_pages)
        
        if offset > 0:
            logger.info(f"[POSTFIX] Resuming from offset {offset}")
        logger.info(f"[POSTFIX] Total available: ~{total_available}, pages to fetch: {pages_to_fetch}/{total_pages_needed}")
        
        while page_num < pages_to_fetch:
            page_num += 1
            logs = await mailcow_api.get_postfix_logs_page(page_size=page_size, offset=offset)
            
            if not logs:
                _resume_offset['postfix'] = 0
                break
            
            page_new = 0
            page_skipped = 0
            page_blacklisted = 0
            
            with get_db_context() as db:
                blacklisted_queue_ids: Set[str] = set()
                
                for log_entry in logs:
                    message = log_entry.get('message', '')
                    parsed = parse_postfix_message(message)
                    queue_id = parsed.get('queue_id')
                    
                    if not queue_id:
                        continue
                    
                    sender = parsed.get('sender')
                    recipient = parsed.get('recipient')
                    
                    if is_blacklisted(sender) or is_blacklisted(recipient):
                        blacklisted_queue_ids.add(queue_id)
                        logger.debug(f"Blacklist: Queue ID {queue_id} marked for deletion (sender={sender}, recipient={recipient})")
                
                if blacklisted_queue_ids:
                    deleted_count = db.query(PostfixLog).filter(
                        PostfixLog.queue_id.in_(blacklisted_queue_ids)
                    ).delete(synchronize_session=False)
                    
                    db.query(MessageCorrelation).filter(
                        MessageCorrelation.queue_id.in_(blacklisted_queue_ids)
                    ).delete(synchronize_session=False)
                    
                    if deleted_count > 0:
                        logger.info(f"[BLACKLIST] Deleted {deleted_count} Postfix logs for {len(blacklisted_queue_ids)} blacklisted queue IDs")
                    
                    db.commit()
                
                # Batch existence check
                existing_in_db: Set[str] = set()
                times_in_batch = set()
                for log_entry in logs:
                    times_in_batch.add(datetime.fromtimestamp(int(log_entry.get('time', 0)), tz=timezone.utc))
                
                if times_in_batch:
                    existing_rows = db.query(
                        PostfixLog.time, PostfixLog.program, PostfixLog.queue_id, PostfixLog.message
                    ).filter(
                        PostfixLog.time.in_(list(times_in_batch))
                    ).all()
                    for row in existing_rows:
                        dt = row.time.replace(tzinfo=timezone.utc) if row.time.tzinfo is None else row.time
                        time_val = int(dt.timestamp())
                        db_key = f"{time_val}|{row.program or ''}|{row.queue_id or ''}|{row.message or ''}"
                        existing_in_db.add(db_key)
                
                for log_entry in logs:
                    try:
                        time_str = str(log_entry.get('time', ''))
                        message = log_entry.get('message', '')
                        unique_id = f"{time_str}:{message[:100]}"
                        
                        if unique_id in seen_postfix:
                            page_skipped += 1
                            continue
                        
                        parsed = parse_postfix_message(message)
                        queue_id = parsed.get('queue_id')
                        
                        if queue_id and queue_id in blacklisted_queue_ids:
                            page_blacklisted += 1
                            seen_postfix.add(unique_id)
                            continue
                        
                        # Parse timestamp with timezone
                        timestamp = datetime.fromtimestamp(
                            int(log_entry.get('time', 0)),
                            tz=timezone.utc
                        )
                        
                        # Check if already exists in DB (pre-checked batch query)
                        time_val = int(log_entry.get('time', 0))
                        db_key = f"{time_val}|{log_entry.get('program', '')}|{queue_id or ''}|{message}"
                        if db_key in existing_in_db:
                            seen_postfix.add(unique_id)
                            page_skipped += 1
                            continue
                        
                        sender = parsed.get('sender')
                        recipient = parsed.get('recipient')
                        
                        postfix_log = PostfixLog(
                            time=timestamp,
                            program=log_entry.get('program'),
                            priority=log_entry.get('priority'),
                            message=message,
                            queue_id=queue_id,
                            message_id=parsed.get('message_id'),
                            sender=sender,
                            recipient=recipient,
                            status=parsed.get('status'),
                            relay=parsed.get('relay'),
                            delay=parsed.get('delay'),
                            dsn=parsed.get('dsn'),
                            raw_data=log_entry
                        )
                        
                        db.add(postfix_log)
                        seen_postfix.add(unique_id)
                        page_new += 1
                        
                    except Exception as e:
                        logger.error(f"Error processing Postfix log: {e}")
                        continue
                
                db.commit()
            
            total_new += page_new
            total_skipped += page_skipped
            total_blacklisted += page_blacklisted
            
            pct = round(page_num / pages_to_fetch * 100)
            if page_new > 0:
                logger.info(f"[POSTFIX] Page {page_num}/{pages_to_fetch} ({pct}%): imported {page_new} new, skipped {page_skipped} duplicates")
            
            # Early stop: no new imports means we've caught up (duplicates + blacklisted = processed)
            if page_new == 0:
                logger.info(f"[POSTFIX] Page {page_num}/{pages_to_fetch}: all duplicates/blacklisted, caught up — stopping early")
                _resume_offset['postfix'] = 0
                break
            
            offset += len(logs)
        
        else:
            # Loop completed without break. `offset` was already advanced by
            # len(logs) each page, so it points at the first unfetched log —
            # adding page_size here would silently skip a whole page.
            if pages_to_fetch < total_pages_needed:
                _resume_offset['postfix'] = offset
                logger.info(f"[POSTFIX] Completed {pages_to_fetch}/{total_pages_needed} pages, will resume from offset {_resume_offset['postfix']} next cycle")
            else:
                _resume_offset['postfix'] = 0
        
        if total_new > 0 or total_skipped > 0:
            msg = f"[OK] Imported {total_new} Postfix logs across {page_num} page(s)"
            if total_skipped > 0:
                msg += f" (skipped {total_skipped} duplicates)"
            if total_blacklisted > 0:
                msg += f" (skipped {total_blacklisted} blacklisted)"
            logger.info(msg)
        
        if len(seen_postfix) > 10000:
            seen_postfix.clear()
    
    except Exception as e:
        logger.error(f"[ERROR] Postfix fetch error: {e}")


async def fetch_and_store_rspamd():
    """Fetch Rspamd logs from API and store in DB (paginated — fetches all available logs)"""
    last_fetch_run_time['rspamd'] = datetime.now(timezone.utc)
    
    page_size = settings.fetch_count_rspamd
    max_pages = settings.fetch_max_pages
    offset = _resume_offset['rspamd']
    total_new = 0
    total_skipped = 0
    total_blacklisted = 0
    page_num = 0
    
    try:
        # Discover total available logs in mailcow
        total_available = await _discover_total_logs('rspamd-history')
        
        if total_available == 0:
            logger.debug("[RSPAMD] No logs available in mailcow")
            return
        
        # If resume offset is beyond total, reset
        if offset >= total_available:
            offset = 0
            _resume_offset['rspamd'] = 0
        
        remaining = total_available - offset
        total_pages_needed = (remaining + page_size - 1) // page_size
        pages_to_fetch = min(total_pages_needed, max_pages)
        
        if offset > 0:
            logger.info(f"[RSPAMD] Resuming from offset {offset}")
        logger.info(f"[RSPAMD] Total available: ~{total_available}, pages to fetch: {pages_to_fetch}/{total_pages_needed}")
        
        while page_num < pages_to_fetch:
            page_num += 1
            logs = await mailcow_api.get_rspamd_logs_page(page_size=page_size, offset=offset)
            
            if not logs:
                _resume_offset['rspamd'] = 0
                break
            
            page_new = 0
            page_skipped = 0
            page_blacklisted = 0
            
            with get_db_context() as db:
                blacklisted_message_ids: Set[str] = set()
                
                # Batch existence check
                existing_in_db: Set[str] = set()
                times_in_batch = set()
                for log_entry in logs:
                    times_in_batch.add(datetime.fromtimestamp(log_entry.get('unix_time', 0), tz=timezone.utc))
                
                if times_in_batch:
                    existing_rows = db.query(
                        RspamdLog.time, RspamdLog.message_id
                    ).filter(
                        RspamdLog.time.in_(list(times_in_batch))
                    ).all()
                    for row in existing_rows:
                        dt = row.time.replace(tzinfo=timezone.utc) if row.time.tzinfo is None else row.time
                        time_val = int(dt.timestamp())
                        db_key = f"{time_val}:{row.message_id if row.message_id else 'no-id'}"
                        existing_in_db.add(db_key)
                
                for log_entry in logs:
                    try:
                        unix_time = log_entry.get('unix_time', 0)
                        message_id = log_entry.get('message-id', '')
                        if message_id == 'undef' or not message_id:
                            message_id = None
                        sender = log_entry.get('sender_smtp')
                        recipients = log_entry.get('rcpt_smtp', [])
                        
                        unique_id = f"{unix_time}:{message_id if message_id else 'no-id'}"
                        
                        if unique_id in seen_rspamd or unique_id in existing_in_db:
                            seen_rspamd.add(unique_id)
                            page_skipped += 1
                            continue
                        
                        if is_blacklisted(sender):
                            page_blacklisted += 1
                            seen_rspamd.add(unique_id)
                            if message_id:
                                blacklisted_message_ids.add(message_id)
                            continue
                        
                        if recipients and any(is_blacklisted(r) for r in recipients):
                            page_blacklisted += 1
                            seen_rspamd.add(unique_id)
                            if message_id:
                                blacklisted_message_ids.add(message_id)
                            continue
                        
                        timestamp = datetime.fromtimestamp(unix_time, tz=timezone.utc)
                        direction = detect_direction(log_entry)
                        
                        rspamd_log = RspamdLog(
                            time=timestamp,
                            message_id=message_id,
                            sender_smtp=sender,
                            sender_mime=log_entry.get('sender_mime', sender),
                            recipients_smtp=recipients,
                            recipients_mime=log_entry.get('rcpt_mime', recipients),
                            subject=log_entry.get('subject'),
                            score=log_entry.get('score', 0.0),
                            required_score=log_entry.get('required_score', 15.0),
                            action=log_entry.get('action', 'unknown'),
                            symbols=log_entry.get('symbols', {}),
                            is_spam=(
                                log_entry.get('action') in ['reject', 'add header', 'rewrite subject'] or
                                'SPAM_TRAP' in log_entry.get('symbols', {})
                            ),
                            has_auth=('MAILCOW_AUTH' in log_entry.get('symbols', {})),
                            direction=direction,
                            ip=log_entry.get('ip'),
                            user=log_entry.get('user'),
                            size=log_entry.get('size'),
                            raw_data=log_entry
                        )

                        if geoip_service.is_geoip_available() and rspamd_log.ip:
                            geo_info = geoip_service.lookup_ip(rspamd_log.ip)
                            rspamd_log.country_code = geo_info.get('country_code')
                            rspamd_log.country_name = geo_info.get('country_name')
                            rspamd_log.city = geo_info.get('city')
                            rspamd_log.asn = geo_info.get('asn')
                            rspamd_log.asn_org = geo_info.get('asn_org')
                        
                        db.add(rspamd_log)
                        seen_rspamd.add(unique_id)
                        page_new += 1
                        
                    except Exception as e:
                        logger.error(f"Error processing Rspamd log: {e}")
                        continue
                
                if blacklisted_message_ids:
                    correlations_to_delete = db.query(MessageCorrelation).filter(
                        MessageCorrelation.message_id.in_(blacklisted_message_ids)
                    ).all()
                    
                    queue_ids_to_delete = set()
                    for corr in correlations_to_delete:
                        if corr.queue_id:
                            queue_ids_to_delete.add(corr.queue_id)
                    
                    deleted_corr = db.query(MessageCorrelation).filter(
                        MessageCorrelation.message_id.in_(blacklisted_message_ids)
                    ).delete(synchronize_session=False)
                    
                    if queue_ids_to_delete:
                        deleted_postfix = db.query(PostfixLog).filter(
                            PostfixLog.queue_id.in_(queue_ids_to_delete)
                        ).delete(synchronize_session=False)
                        
                        if deleted_postfix > 0:
                            logger.info(f"[BLACKLIST] Deleted {deleted_postfix} Postfix logs linked to blacklisted messages")
                    
                    if deleted_corr > 0:
                        logger.info(f"[BLACKLIST] Deleted {deleted_corr} correlations for blacklisted message IDs")
                
                db.commit()
            
            total_new += page_new
            total_skipped += page_skipped
            total_blacklisted += page_blacklisted
            
            pct = round(page_num / pages_to_fetch * 100)
            if page_new > 0:
                logger.info(f"[RSPAMD] Page {page_num}/{pages_to_fetch} ({pct}%): imported {page_new} new, skipped {page_skipped} duplicates")
            
            # Early stop: no new imports means we've caught up (duplicates + blacklisted = processed)
            if page_new == 0:
                logger.info(f"[RSPAMD] Page {page_num}/{pages_to_fetch}: all duplicates/blacklisted, caught up — stopping early")
                _resume_offset['rspamd'] = 0
                break
            
            offset += len(logs)
        
        else:
            # Loop completed without break. `offset` already points at the
            # first unfetched log — adding page_size would skip a whole page.
            if pages_to_fetch < total_pages_needed:
                _resume_offset['rspamd'] = offset
                logger.info(f"[RSPAMD] Completed {pages_to_fetch}/{total_pages_needed} pages, will resume from offset {_resume_offset['rspamd']} next cycle")
            else:
                _resume_offset['rspamd'] = 0
        
        if total_new > 0:
            msg = f"[OK] Imported {total_new} Rspamd logs across {page_num} page(s)"
            if total_skipped > 0:
                msg += f" (skipped {total_skipped} duplicates)"
            if total_blacklisted > 0:
                msg += f" (skipped {total_blacklisted} blacklisted)"
            logger.info(msg)
        
        if len(seen_rspamd) > 10000:
            seen_rspamd.clear()
    
    except Exception as e:
        logger.error(f"[ERROR] Rspamd fetch error: {e}")



def parse_netfilter_message(message: str, priority: Optional[str] = None) -> Dict[str, Any]:

    result = {}
    message_lower = message.lower()
    
    ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', message)
    if ip_match:
        result['ip'] = ip_match.group(1)
    
    if not result.get('ip'):
        ban_match = re.search(r'until\s+(\d+\.\d+\.\d+\.\d+)', message)
        if ban_match:
            result['ip'] = ban_match.group(1)
    
    if not result.get('ip'):
        bracket_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', message)
        if bracket_match:
            result['ip'] = bracket_match.group(1)
    
    if not result.get('ip'):
        banned_match = re.search(r'Ban(?:ned|ning)\s+(\d+\.\d+\.\d+\.\d+)', message, re.IGNORECASE)
        if banned_match:
            result['ip'] = banned_match.group(1)
    
    if not result.get('ip'):
        cidr_match = re.search(r'Ban(?:ned|ning)\s+(\d+\.\d+\.\d+\.\d+/\d+)', message, re.IGNORECASE)
        if cidr_match:
            ip_part = cidr_match.group(1).split('/')[0]
            result['ip'] = ip_part
    
    # Fallback: extract any IP address (with optional CIDR) from the message
    # Catches denylist messages like "Added host/network 175.157.10.170/32 to denylist"
    if not result.get('ip'):
        generic_ip = re.search(r'(\d+\.\d+\.\d+\.\d+)(?:/\d+)?', message)
        if generic_ip:
            result['ip'] = generic_ip.group(1)
    
    username_match = re.search(r'sasl_username=([^\s,\)]+)', message)
    if username_match:
        result['username'] = username_match.group(1)
    
    auth_match = re.search(r'SASL\s+(\w+)', message)
    if auth_match:
        result['auth_method'] = f"SASL {auth_match.group(1)}"
    
    rule_match = re.search(r'rule id\s+(\d+)', message)
    if rule_match:
        result['rule_id'] = int(rule_match.group(1))
    
    attempts_match = re.search(r'(\d+)\s+more\s+attempt', message)
    if attempts_match:
        result['attempts_left'] = int(attempts_match.group(1))
    
    # Check for unbanning first (before banning) - use word boundaries to avoid matching "banning" inside "unbanning"
    # Check for "unbanning" or "unban" as separate words
    if re.search(r'\bunban(?:ning)?\b', message_lower):
        result['action'] = 'unban'
    # "Removed host/network ... from denylist" = unban
    elif 'removed' in message_lower and 'denylist' in message_lower:
        result['action'] = 'unban'
    # "Added host/network ... to denylist" = ban
    elif 'added' in message_lower and 'denylist' in message_lower:
        result['action'] = 'ban'
    # Check for "banning" or "banned" as separate words (but not if it's part of "unbanning")
    elif re.search(r'\bban(?:ning|ned)\b', message_lower):
        if 'more attempts' in message_lower:
            result['action'] = 'warning'
        else:
            result['action'] = 'ban'
    elif priority and priority.lower() == 'crit':
        # For crit priority, default to ban if not already set
        result['action'] = 'ban'
    elif 'warning' in message_lower:
        result['action'] = 'warning'
    else:
        result['action'] = 'info'
    
    return result


async def fetch_and_store_netfilter():
    """Fetch Netfilter logs from API and store in DB"""
    if not settings.is_feature_enabled('netfilter'):
        return
    last_fetch_run_time['netfilter'] = datetime.now(timezone.utc)
    
    try:
        logger.debug(f"[NETFILTER] Starting fetch (count: {settings.fetch_count_netfilter})")
        logs = await mailcow_api.get_netfilter_logs(count=settings.fetch_count_netfilter)
        
        if not logs:
            logger.debug("[NETFILTER] No logs returned from API")
            return
        
        logger.debug(f"[NETFILTER] Received {len(logs)} logs from API")
        
        with get_db_context() as db:
            new_count = 0
            skipped_count = 0
            
            for log_entry in logs:
                try:
                    time_val = log_entry.get('time', 0)
                    message = log_entry.get('message', '')
                    priority = log_entry.get('priority', 'info')
                    unique_id = f"{time_val}:{priority}:{message}"
                    
                    if unique_id in seen_netfilter:
                        skipped_count += 1
                        continue
                    
                    timestamp = datetime.fromtimestamp(time_val, tz=timezone.utc)
                    existing = db.query(NetfilterLog).filter(
                        NetfilterLog.message == message,
                        NetfilterLog.time == timestamp,
                        NetfilterLog.priority == priority
                    ).first()
                    
                    if existing:
                        skipped_count += 1
                        seen_netfilter.add(unique_id)
                        continue
                    
                    parsed = parse_netfilter_message(message, priority=priority)
                    
                    netfilter_log = NetfilterLog(
                        time=timestamp,
                        priority=priority,
                        message=message,
                        ip=parsed.get('ip'),
                        username=parsed.get('username'),
                        auth_method=parsed.get('auth_method'),
                        action=parsed.get('action'),
                        rule_id=parsed.get('rule_id'),
                        attempts_left=parsed.get('attempts_left'),
                        raw_data=log_entry
                    )
                    
                    # Enrich with GeoIP data at import time
                    if geoip_service.is_geoip_available() and netfilter_log.ip:
                        geo_info = geoip_service.lookup_ip(netfilter_log.ip)
                        netfilter_log.country_code = geo_info.get('country_code')
                        netfilter_log.country_name = geo_info.get('country_name')
                        netfilter_log.city = geo_info.get('city')
                        netfilter_log.asn = geo_info.get('asn')
                        netfilter_log.asn_org = geo_info.get('asn_org')
                    
                    db.add(netfilter_log)
                    seen_netfilter.add(unique_id)
                    new_count += 1
                    
                except Exception as e:
                    logger.error(f"[NETFILTER] Error processing log entry: {e}")
                    continue
            
            db.commit()
            
            if new_count > 0:
                logger.info(f"[OK] Imported {new_count} Netfilter logs (skipped {skipped_count} duplicates)")
            elif skipped_count > 0:
                logger.debug(f"[NETFILTER] All {skipped_count} logs were duplicates, nothing new to import")
            
            if len(seen_netfilter) > 10000:
                logger.debug("[NETFILTER] Clearing seen_netfilter cache (size > 10000)")
                seen_netfilter.clear()
    
    except Exception as e:
        logger.error(f"[ERROR] Netfilter fetch error: {e}", exc_info=True)


async def fetch_all_logs():
    """Fetch all log types concurrently"""
    try:
        update_job_status('fetch_logs', 'running')
        logger.debug("[FETCH] Starting fetch_all_logs")
        
        tasks = [
            fetch_and_store_postfix(),
            fetch_and_store_rspamd(),
        ]
        if settings.is_feature_enabled('netfilter'):
            tasks.append(fetch_and_store_netfilter())
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        log_types = ["Postfix", "Rspamd"]
        if settings.is_feature_enabled('netfilter'):
            log_types.append("Netfilter")
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"[ERROR] {log_types[i]} fetch failed: {result}", exc_info=result)
        
        logger.debug("[FETCH] Completed fetch_all_logs")
        update_job_status('fetch_logs', 'success')
    
    except asyncio.CancelledError:
        logger.info("[FETCH] Log fetch cancelled (application shutting down)")
        return
    except Exception as e:
        update_job_status('fetch_logs', 'failed', str(e))
        logger.error(f"[ERROR] Fetch all logs error: {e}", exc_info=True)



async def cleanup_blacklisted_queues():
    """
    Clean up Postfix queues where the recipient is blacklisted.
    
    This handles the BCC scenario:
    - Same message-id appears with multiple queue-ids
    - One queue is for the real recipient
    - Another queue is for the BCC address (which is blacklisted)
    
    We need to delete ALL logs for queues where the recipient is blacklisted,
    so that correlation only finds the "real" queue.
    """
    blacklist = settings.blacklist_emails_list
    if not blacklist:
        return
    
    try:
        with get_db_context() as db:
            blacklisted_queue_ids = set()
            
            for email in blacklist:
                logs_with_blacklisted_recipient = db.query(PostfixLog).filter(
                    PostfixLog.recipient == email,
                    PostfixLog.queue_id.isnot(None)
                ).all()
                
                for log in logs_with_blacklisted_recipient:
                    if log.queue_id:
                        blacklisted_queue_ids.add(log.queue_id)
            
            if not blacklisted_queue_ids:
                return
            
            deleted_count = 0
            for queue_id in blacklisted_queue_ids:
                count = db.query(PostfixLog).filter(
                    PostfixLog.queue_id == queue_id
                ).delete(synchronize_session=False)
                deleted_count += count
            
            db.commit()
            
            if deleted_count > 0:
                logger.info(f"[CLEANUP] Cleaned up {deleted_count} Postfix logs from {len(blacklisted_queue_ids)} blacklisted BCC queues")
    
    except Exception as e:
        logger.error(f"[ERROR] Blacklisted queue cleanup error: {e}")


async def run_correlation():
    """
    Main correlation job - links Rspamd logs with Postfix logs.
    
    Strategy:
    1. Clean up blacklisted BCC queues first
    2. Find Rspamd logs without correlation_key
    3. For each, find Postfix logs with same message_id
    4. Get queue_id and find ALL related Postfix logs
    5. Create MessageCorrelation (if doesn't exist)
    
    Note: Also checks blacklist for legacy logs that were imported before blacklist was set.
    """
    # Step 1: Clean up blacklisted BCC queues before correlating
    await cleanup_blacklisted_queues()
    
    try:
        with get_db_context() as db:
            uncorrelated_rspamd = db.query(RspamdLog).filter(
                RspamdLog.correlation_key.is_(None),
                RspamdLog.message_id.isnot(None),
                RspamdLog.message_id != '',
                RspamdLog.message_id != 'undef'
            ).order_by(desc(RspamdLog.time)).limit(100).all()
            
            if not uncorrelated_rspamd:
                return
            
            correlated_count = 0
            skipped_blacklist = 0
            
            for rspamd_log in uncorrelated_rspamd:
                try:
                    if is_blacklisted(rspamd_log.sender_smtp):
                        rspamd_log.correlation_key = "BLACKLISTED"
                        db.commit()
                        skipped_blacklist += 1
                        continue
                    
                    if rspamd_log.recipients_smtp:
                        recipients = rspamd_log.recipients_smtp
                        if any(is_blacklisted(r) for r in recipients):
                            rspamd_log.correlation_key = "BLACKLISTED"
                            db.commit()
                            skipped_blacklist += 1
                            continue
                    
                    result = correlate_single_message(db, rspamd_log)
                    if result:
                        correlated_count += 1
                except Exception as e:
                    logger.warning(f"Correlation failed for rspamd {rspamd_log.id}: {e}")
                    db.rollback()
                    continue
            
            if correlated_count > 0:
                logger.info(f"[LINK] Correlated {correlated_count} messages")
            if skipped_blacklist > 0:
                logger.info(f"[INFO] Skipped {skipped_blacklist} blacklisted messages")
    
    except Exception as e:
        logger.error(f"[ERROR] Correlation job error: {e}")


def correlate_single_message(db: Session, rspamd_log: RspamdLog) -> Optional[MessageCorrelation]:
    """
    Correlate a single Rspamd log with Postfix logs.
    
    Steps:
    1. Check if correlation already exists for this message_id
    2. Find Postfix logs with same message_id => get queue_id
    3. Find ALL Postfix logs with that queue_id
    4. Create or update correlation
    """
    message_id = rspamd_log.message_id
    if not message_id:
        return None
    
    # Step 1: Check if correlation already exists
    existing = db.query(MessageCorrelation).filter(
        MessageCorrelation.message_id == message_id
    ).first()
    
    if existing:
        # Just update the rspamd log with correlation key
        rspamd_log.correlation_key = existing.correlation_key
        if not existing.rspamd_log_id:
            existing.rspamd_log_id = rspamd_log.id
            existing.last_seen = datetime.now(timezone.utc)
        db.commit()
        return existing
    
    # Step 2: Find Postfix logs with this message_id
    postfix_with_msgid = db.query(PostfixLog).filter(
        PostfixLog.message_id == message_id
    ).all()
    
    # Get queue_id from Postfix logs
    queue_id = None
    for plog in postfix_with_msgid:
        if plog.queue_id:
            queue_id = plog.queue_id
            break
    
    # Step 3: Find ALL Postfix logs with this queue_id
    all_postfix_logs: List[PostfixLog] = []
    if queue_id:
        all_postfix_logs = db.query(PostfixLog).filter(
            PostfixLog.queue_id == queue_id
        ).all()
    
    # Step 4: Double-check no correlation exists (race condition protection)
    existing_check = db.query(MessageCorrelation).filter(
        MessageCorrelation.message_id == message_id
    ).first()
    
    if existing_check:
        # Another process created it, just link and return
        rspamd_log.correlation_key = existing_check.correlation_key
        if not existing_check.rspamd_log_id:
            existing_check.rspamd_log_id = rspamd_log.id
        db.commit()
        return existing_check
    
    # Create correlation
    correlation_key = hashlib.sha256(f"msgid:{message_id}".encode()).hexdigest()
    
    # Get recipient
    recipients = rspamd_log.recipients_smtp or []
    first_recipient = recipients[0] if recipients else None
    
    # Determine final status from Postfix logs
    final_status = None
    for plog in all_postfix_logs:
        if plog.status:
            if plog.status in ['bounced', 'rejected']:
                final_status = plog.status
                break
            elif plog.status == 'deferred' and not final_status:
                final_status = plog.status
            elif plog.status == 'sent' and not final_status:
                final_status = 'delivered'
    
    # Use Rspamd action if no Postfix status
    if not final_status:
        if rspamd_log.action == 'reject':
            final_status = 'rejected'
        elif rspamd_log.is_spam:
            final_status = 'spam'
    
    # Check if email was delivered locally (relay=dovecot + both sender and recipient are local domains)
    # This is the definitive way to determine if email is internal
    direction = rspamd_log.direction
    
    # Check if sender and recipient are both local domains
    from .correlation import extract_domain, is_local_domain
    sender_domain = extract_domain(rspamd_log.sender_smtp)
    recipients = rspamd_log.recipients_smtp or []
    
    sender_is_local = sender_domain and is_local_domain(sender_domain)
    all_recipients_local = True
    if recipients:
        for recipient in recipients:
            recipient_domain = extract_domain(recipient)
            if not recipient_domain or not is_local_domain(recipient_domain):
                all_recipients_local = False
                break
    else:
        all_recipients_local = False
    
    # Only mark as internal if: relay=dovecot AND sender is local AND all recipients are local
    if sender_is_local and all_recipients_local:
        for plog in all_postfix_logs:
            if plog.relay and 'dovecot' in plog.relay.lower():
                direction = 'internal'
                rspamd_log.direction = 'internal'
                break
    
    # Get earliest timestamp (ensure timezone-aware)
    now = datetime.now(timezone.utc)
    first_seen = rspamd_log.time
    if first_seen and first_seen.tzinfo is None:
        first_seen = first_seen.replace(tzinfo=timezone.utc)
    if not first_seen:
        first_seen = now
    
    try:
        # Create correlation
        correlation = MessageCorrelation(
            correlation_key=correlation_key,
            message_id=message_id,
            queue_id=queue_id,
            sender=rspamd_log.sender_smtp,
            recipient=first_recipient,
            subject=rspamd_log.subject,
            direction=direction,
            final_status=final_status,
            rspamd_log_id=rspamd_log.id,
            postfix_log_ids=[plog.id for plog in all_postfix_logs] if all_postfix_logs else [],
            first_seen=first_seen,
            last_seen=now,
            is_complete=bool(queue_id and all_postfix_logs)
        )
        
        db.add(correlation)
        db.flush()  # Try to insert - will fail if duplicate
        
        # Update rspamd log with correlation key
        rspamd_log.correlation_key = correlation_key
        
        # Update all postfix logs with correlation key
        for plog in all_postfix_logs:
            plog.correlation_key = correlation_key
        
        db.commit()
        
        logger.debug(f"Created correlation for {message_id[:40]}... (queue: {queue_id}, {len(all_postfix_logs)} postfix logs)")
        return correlation
        
    except Exception as e:
        # Handle race condition - another process created the correlation
        db.rollback()
        
        # Try to find and return the existing one
        existing = db.query(MessageCorrelation).filter(
            MessageCorrelation.message_id == message_id
        ).first()
        
        if existing:
            rspamd_log.correlation_key = existing.correlation_key
            db.commit()
            return existing
        
        # Re-raise if it's a different error
        raise


async def complete_incomplete_correlations():
    """
    Complete correlations that are missing Postfix logs.
    
    This handles the case where rspamd was processed before postfix logs arrived.
    """
    update_job_status('complete_correlations', 'running')
    try:
        with get_db_context() as db:
            # Find incomplete correlations (have message_id but missing queue_id or postfix logs)
            # Use naive datetime for comparison since DB stores naive UTC
            cutoff_time = datetime.utcnow() - timedelta(
                minutes=settings.max_correlation_age_minutes
            )
            
            incomplete = db.query(MessageCorrelation).filter(
                MessageCorrelation.is_complete == False,
                MessageCorrelation.message_id.isnot(None),
                MessageCorrelation.created_at >= cutoff_time
            ).limit(100).all()
            
            if not incomplete:
                update_job_status('complete_correlations', 'success')
                return
            
            completed_count = 0
            
            for correlation in incomplete:
                try:
                    # Find Postfix logs with this message_id
                    postfix_with_msgid = db.query(PostfixLog).filter(
                        PostfixLog.message_id == correlation.message_id
                    ).all()
                    
                    if not postfix_with_msgid:
                        continue
                    
                    # Get queue_id
                    queue_id = None
                    for plog in postfix_with_msgid:
                        if plog.queue_id:
                            queue_id = plog.queue_id
                            break
                    
                    if not queue_id:
                        continue
                    
                    # Find ALL Postfix logs with this queue_id
                    all_postfix = db.query(PostfixLog).filter(
                        PostfixLog.queue_id == queue_id
                    ).all()
                    
                    # Update correlation
                    correlation.queue_id = queue_id
                    correlation.postfix_log_ids = [plog.id for plog in all_postfix]
                    correlation.is_complete = True
                    correlation.last_seen = datetime.now(timezone.utc)
                    
                    # Update final status
                    for plog in all_postfix:
                        if plog.status:
                            if plog.status in ['bounced', 'rejected']:
                                correlation.final_status = plog.status
                                break
                            elif plog.status == 'deferred' and correlation.final_status not in ['bounced', 'rejected']:
                                correlation.final_status = plog.status
                            elif plog.status == 'sent' and not correlation.final_status:
                                correlation.final_status = 'delivered'
                    
                    # Update correlation key in Postfix logs
                    for plog in all_postfix:
                        plog.correlation_key = correlation.correlation_key
                    
                    completed_count += 1
                    
                except Exception as e:
                    logger.warning(f"Failed to complete correlation {correlation.id}: {e}")
                    continue
            
            db.commit()
            
            if completed_count > 0:
                logger.info(f"[OK] Completed {completed_count} correlations")
            
            update_job_status('complete_correlations', 'success')
    
    except Exception as e:
        logger.error(f"[ERROR] Complete correlations error: {e}")
        update_job_status('complete_correlations', 'failed', str(e))


async def expire_old_correlations():
    """
    SEPARATE JOB: Mark old incomplete correlations as "expired".
    
    This runs independently to ensure old incomplete correlations get expired even if
    the complete_incomplete_correlations job has issues.
    
    Only marks incomplete correlations (is_complete == False) as expired.
    Complete correlations with non-final statuses (None, 'deferred', etc.) are left as-is,
    as they may have legitimate statuses that don't need to be changed.
    
    Uses datetime.utcnow() (naive) to match the naive datetime in created_at.
    """
    update_job_status('expire_correlations', 'running')
    try:
        with get_db_context() as db:
            # Use naive datetime for comparison (DB stores naive UTC)
            old_cutoff = datetime.utcnow() - timedelta(
                minutes=settings.max_correlation_age_minutes
            )
            
            # Find old incomplete correlations and mark them as expired
            expired_correlations = db.query(MessageCorrelation).filter(
                MessageCorrelation.is_complete == False,
                MessageCorrelation.created_at < old_cutoff
            ).all()
            
            if not expired_correlations:
                update_job_status('expire_correlations', 'success')
                return
            
            expired_count = 0
            for corr in expired_correlations:
                corr.is_complete = True  # Mark as complete so we stop trying
                corr.final_status = "expired"  # Set status to expired
                expired_count += 1
            
            db.commit()
            
            if expired_count > 0:
                logger.info(f"[EXPIRED] Marked {expired_count} correlations as expired (older than {settings.max_correlation_age_minutes}min)")
            
            update_job_status('expire_correlations', 'success')
    
    except Exception as e:
        logger.error(f"[ERROR] Expire correlations error: {e}")
        update_job_status('expire_correlations', 'failed', str(e))


async def update_final_status_for_correlations():
    """
    Background job to update final_status for correlations that don't have one yet.
    
    This handles the case where Postfix logs (especially status=sent) arrive after
    the initial correlation was created. The job:
    1. Finds correlations without a definitive final_status
    2. Only checks correlations within Max Correlation Age
    3. Looks for new Postfix logs that may have arrived
    4. Updates final_status, postfix_log_ids, and correlation_key
    
    This runs independently from correlation creation to ensure we catch
    late-arriving Postfix logs.
    """
    update_job_status('update_final_status', 'running')
    try:
        with get_db_context() as db:
            # Only check correlations within Max Correlation Age
            cutoff_time = datetime.utcnow() - timedelta(
                minutes=settings.max_correlation_age_minutes
            )
            
            # Find correlations that:
            # 1. Are within the correlation age limit
            # 2. Have a queue_id (so we can check Postfix logs)
            # 3. Don't have a definitive final_status yet
            #    We exclude 'delivered', 'bounced', 'rejected', 'expired' as these are final
            #    We check None, 'deferred', 'spam', and other non-final statuses
            correlations_to_check = db.query(MessageCorrelation).filter(
                MessageCorrelation.created_at >= cutoff_time,
                MessageCorrelation.queue_id.isnot(None),
                or_(
                    MessageCorrelation.final_status.is_(None),
                    MessageCorrelation.final_status.notin_(['delivered', 'bounced', 'rejected', 'expired'])
                )
            ).limit(500).all()  # Increased from 100 to 500
            
            if not correlations_to_check:
                update_job_status('update_final_status', 'success')
                return
            
            updated_count = 0
            
            for correlation in correlations_to_check:
                try:
                    # Get all Postfix logs for this queue_id
                    all_postfix = db.query(PostfixLog).filter(
                        PostfixLog.queue_id == correlation.queue_id
                    ).all()
                    
                    if not all_postfix:
                        continue
                    
                    # Determine best final status from all Postfix logs
                    # Priority: bounced > rejected > sent (delivered) > deferred
                    new_final_status = correlation.final_status
                    
                    for plog in all_postfix:
                        if plog.status:
                            if plog.status in ['bounced', 'rejected']:
                                new_final_status = plog.status
                                break  # Highest priority, stop here
                            elif plog.status == 'sent':
                                # 'sent' (delivered) is better than 'deferred' or None
                                if new_final_status not in ['bounced', 'rejected', 'delivered']:
                                    new_final_status = 'delivered'
                            elif plog.status == 'deferred' and new_final_status not in ['bounced', 'rejected', 'delivered']:
                                new_final_status = 'deferred'
                    
                    # FIX #1: Update postfix_log_ids - add any missing logs
                    current_ids = list(correlation.postfix_log_ids or [])
                    ids_added = 0
                    for plog in all_postfix:
                        if plog.id and plog.id not in current_ids:
                            current_ids.append(plog.id)
                            ids_added += 1
                    
                    if ids_added > 0:
                        correlation.postfix_log_ids = current_ids
                    
                    # FIX #2: Update correlation_key in ALL Postfix logs
                    for plog in all_postfix:
                        if not plog.correlation_key or plog.correlation_key != correlation.correlation_key:
                            plog.correlation_key = correlation.correlation_key
                    
                    # Update if we found a better status or added logs
                    if (new_final_status and new_final_status != correlation.final_status) or ids_added > 0:
                        old_status = correlation.final_status
                        correlation.final_status = new_final_status
                        correlation.last_seen = datetime.now(timezone.utc)
                        updated_count += 1
                        
                        if ids_added > 0:
                            logger.debug(f"Updated correlation {correlation.id}: added {ids_added} logs, status {old_status} -> {new_final_status}")
                        else:
                            logger.debug(f"Updated final_status for correlation {correlation.id} ({correlation.message_id[:40] if correlation.message_id else 'no-id'}...): {old_status} -> {new_final_status}")
                
                except Exception as e:
                    logger.warning(f"Failed to update final_status for correlation {correlation.id}: {e}")
                    continue
            
            db.commit()
            
            if updated_count > 0:
                logger.info(f"[STATUS] Updated final_status for {updated_count} correlations")
            
            update_job_status('update_final_status', 'success')
    
    except Exception as e:
        logger.error(f"[ERROR] Update final status error: {e}")
        update_job_status('update_final_status', 'failed', str(e))


async def update_geoip_database():
    """Background job: Update GeoIP databases"""
    from .services.geoip_downloader import (
        update_geoip_database_if_needed,
        is_license_configured
    )
    
    try:
        update_job_status('update_geoip', 'running')
        
        if not is_license_configured():
            update_job_status('update_geoip', 'idle', 'License key not configured')
            return
        
        # Run blocking download in thread pool to avoid blocking the event loop
        loop = asyncio.get_event_loop()
        status = await loop.run_in_executor(None, update_geoip_database_if_needed)
        
        if status['City']['updated'] or status['ASN']['updated']:
            # Reload the GeoIP readers so the cached _geoip_available flag
            # and reader objects are refreshed with the new database files
            geoip_service.reload_geoip_readers()
            logger.info("GeoIP readers reloaded after database update")
            update_job_status('update_geoip', 'success')
        else:
            # Ensure readers are loaded and validated even when no download was needed
            # (handles case where DB exists but validation hasn't run yet)
            if geoip_service.get_geoip_db_valid() is not True:
                geoip_service.reload_geoip_readers()
            update_job_status('update_geoip', 'success')
        
        # Successful download implies valid license — persist to DB
        # so the settings page shows "License Valid" without a manual check
        if status['City']['available'] or status['ASN']['available']:
            try:
                from .services.settings_store import save_maxmind_validation_status
                with get_db_context() as db:
                    save_maxmind_validation_status(db, {
                        "configured": True,
                        "valid": True,
                        "error": None
                    })
            except Exception as e:
                logger.debug(f"Failed to persist license status after GeoIP update: {e}")
        
    except asyncio.CancelledError:
        logger.info("GeoIP update cancelled by shutdown")
        return
    except Exception as e:
        logger.error(f"GeoIP update failed: {e}")
        update_job_status('update_geoip', 'failed', str(e))


async def check_monitored_hosts_job(force: bool = False, send_notification: bool = True):
    """
    Background job: Check all monitored hosts against DNS blacklists
    Sends aggregated email notification if any host is listed (and send_notification=True).
    Sends notification when all hosts are cleared from actionable blacklists (were listed, now clear).
    Args:
        force: If True, bypass cache and force fresh check
        send_notification: If True, send email on failure. Defaults to True.
    """
    if not settings.is_feature_enabled('blacklist'):
        logger.debug("[BLACKLIST] Feature disabled, skipping")
        return
    global _blacklist_last_listed_actionable_count
    update_job_status('blacklist_check', 'running')
    
    try:
        from .services.blacklist_service import (
            get_blacklist_check_results, 
            get_listed_blacklists, 
            get_cached_blacklist_check,
            start_batch_scan,
            end_batch_scan,
            update_batch_status,
            mark_host_as_processed_batch,
            IGNORED_NOTIFICATION_BLACKLISTS
        )
        from .services.smtp_service import send_notification_email, get_notification_email
        from .routers.domains import get_cached_server_ip
        
        logger.info(f"Starting blacklist check job (send_notification={send_notification})...")
        
        # Get all monitored hosts and detach fields to avoid DetachedInstanceError in async loop
        monitored_hosts = []
        with get_db_context() as db:
            db_hosts = db.query(MonitoredHost).filter(MonitoredHost.active == True).all()
            for h in db_hosts:
                monitored_hosts.append({
                    'hostname': h.hostname,
                    'source': h.source
                })
        
        # If no hosts, try to initialize with local IP
        if not monitored_hosts:
            server_ip = get_cached_server_ip()
            if server_ip:
                with get_db_context() as db:
                    new_host = MonitoredHost(hostname=server_ip, source="system", active=True, last_seen=datetime.utcnow())
                    db.add(new_host)
                    db.commit()
                    # Add to our local list
                    monitored_hosts.append({
                        'hostname': server_ip,
                        'source': "system"
                    })
        
        if not monitored_hosts:
            logger.warning("Cannot check blacklists: No monitored hosts available")
            update_job_status('blacklist_check', 'failed', 'No monitored hosts available')
            return

        listed_hosts = []
        total_checks = 0

        # Start Batch Session
        start_batch_scan(len(monitored_hosts))
        
        try:
            for i, host in enumerate(monitored_hosts):
                hostname = host['hostname']
                source = host['source']
                
                logger.info(f"Processing host {i+1}/{len(monitored_hosts)}: {hostname} (Source: {source})")
                target_ip = hostname
                # Simple IP validation and resolution if needed
                if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_ip):
                    try:
                        from app.services.dns_resolver import resolve as dns_resolve
                        answers = await dns_resolve(target_ip, 'A', timeout=5)
                        if answers:
                            resolved_ip = str(answers[0])
                            logger.info(f"Resolved {target_ip} to {resolved_ip}")
                            target_ip = resolved_ip
                    except Exception as e:
                        logger.warning(f"Could not resolve hostname {hostname}: {e}")
                        continue

                # Check if we have valid cached data (within 24h)
                cached = get_cached_blacklist_check(target_ip)
                if cached and not force:
                    logger.info(f"Blacklist check for {hostname}: Using cached data")
                    if cached.get('listed_count', 0) > 0:
                         listed_hosts.append({
                            'hostname': hostname,
                            'ip': target_ip,
                            'source': source,
                            'results': cached
                        })
                    total_checks += 1
                    mark_host_as_processed_batch()
                    continue
                
                # Run fresh blacklist check
                logger.info(f"Running fresh blacklist check for {target_ip}...")
                results = await get_blacklist_check_results(force=True, ip=target_ip)
                logger.info(f"Finished blacklist check for {target_ip}. Results: listed={results.get('listed_count')}")
                total_checks += 1
                
                listed_cnt = results.get('listed_count', 0)
                if listed_cnt > 0:
                    listed_hosts.append({
                        'hostname': hostname,
                        'ip': target_ip,
                        'source': source,
                        'results': results
                    })
                
                # Sleep between checks to avoid rate limits (if more to come)
                if i < len(monitored_hosts) - 1:
                    logger.info("Waiting 10s before next check...")
                    update_batch_status(f"Cooldown 10s before checking {monitored_hosts[i+1]['hostname']}...")
                    await asyncio.sleep(10)

            logger.info(f"Blacklist check complete for {total_checks} hosts. {len(listed_hosts)} listed.")
            
            # Count hosts that are listed on at least one actionable blacklist (for "listed", "cleared", "improved" notifications)
            actionable_listed_hosts = []
            for host_data in listed_hosts:
                results = host_data.get('results', {}).get('results', [])
                for res in results:
                    if res.get('listed') and res.get('name') not in IGNORED_NOTIFICATION_BLACKLISTS:
                        actionable_listed_hosts.append(host_data)
                        break
            actionable_count = len(actionable_listed_hosts)
            should_alert = actionable_count > 0
            prev_listed = _blacklist_last_listed_actionable_count
            if listed_hosts and send_notification and not should_alert:
                logger.info("Hosts are listed, but only on ignored blacklists (e.g. UCEPROTECT). Suppressing notification.")

            # Send notification if ANY server is listed AND notification is enabled AND should_alert is True
            if listed_hosts and send_notification and should_alert:
                # Get admin email for notification
                blacklist_alert_email = settings.blacklist_alert_email if hasattr(settings, 'blacklist_alert_email') else None
                notification_email = get_notification_email(blacklist_alert_email)
                
                logger.info(f"Found listed hosts. Attempting to send alert to: {notification_email} (Source: {blacklist_alert_email})")
                
                if notification_email:
                    # Build aggregated email content
                    subject = f"⚠️ ALERT: {len(listed_hosts)} Host(s) Listed on Blacklists"
                    
                    text_content = f"The following hosts have been detected on one or more blacklists:\n\n"
                    
                    html_rows = ""
                    
                    for host_data in listed_hosts:
                        hostname = host_data['hostname']
                        ip = host_data['ip']
                        source = host_data.get('source', '')
                        results = host_data['results']
                        listed_count = results.get('listed_count', 0)
                        total_bl = results.get('total_blacklists', 0)
                        
                        # Determine display name
                        display_name = hostname
                        extra_info = ""
                        
                        # If hostname matches IP, try to find a better name in source
                        if hostname == ip:
                            # Source format is often "type:fqdn"
                            if ':' in source:
                                _, fqdn = source.split(':', 1)
                                if fqdn and fqdn != ip:
                                    extra_info = f" ({fqdn})"
                            elif source and source != 'system' and source != ip:
                                extra_info = f" ({source})"
                        else:
                             if hostname != ip:
                                extra_info = f" ({ip})"

                        # Get specific blacklists
                        listed_bls = [r for r in results.get('results', []) if r.get('listed')]
                        bl_text_list = "\n".join([f"  - {bl['name']} ({bl['zone']})" for bl in listed_bls])
                        
                        text_content += f"Host: {display_name}{extra_info}\n"
                        text_content += f"Listed on: {listed_count}/{total_bl} blacklists\n"
                        text_content += f"Blacklists:\n{bl_text_list}\n\n"
                        
                        # HTML Row
                        bl_html_list = "".join([f'<li><strong>{bl["name"]}</strong> - {bl["zone"]} (<a href="{bl.get("info_url", "#")}">lookup</a>)</li>' for bl in listed_bls])
                        
                        html_rows += f"""
                        <div style="margin-bottom: 30px; border-bottom: 1px solid #eee; padding-bottom: 20px;">
                            <h3 style="margin: 0 0 10px 0;">{display_name} <span style="font-weight: normal; font-size: 14px; color: #666;">{extra_info}</span></h3>
                            <div style="background-color: #fef2f2; border: 1px solid #fee2e2; border-radius: 4px; padding: 10px; margin-bottom: 10px;">
                                <strong style="color: #dc2626;">Listed on {listed_count} blacklist(s)</strong>
                            </div>
                            <ul style="margin-top: 5px;">
                                {bl_html_list}
                            </ul>
                        </div>
                        """

                    text_content += "Action Required:\nPlease investigate and request removal from these blacklists to ensure email deliverability.\n\n"
                    text_content += "This is an automated notification from mailcow Logs Viewer."
                    
                    html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px; line-height: 1.5;">
    <h2 style="color: #dc2626;">⚠️ Blacklist Alert</h2>
    <p>The following hosts have been detected on blacklists:</p>

    {html_rows}

    <p style="color: #666; margin-top: 20px;">Please investigate and request removal from these blacklists to ensure email deliverability.</p>
    <hr style="margin-top: 30px;">
    <p style="color: #999; font-size: 12px;">This is an automated notification from mailcow Logs Viewer.</p>
    </body>
    </html>
    """
                    
                    # Send notification (in executor — smtplib blocks the event loop)
                    logger.info("Calling send_notification_email...")
                    sent = await asyncio.get_running_loop().run_in_executor(
                        _thread_pool_executor,
                        send_notification_email, notification_email, subject, text_content, html_content
                    )
                    if sent:
                        logger.info(f"Blacklist alert sent to {notification_email}")
                    else:
                        logger.error(f"Failed to send blacklist alert to {notification_email}. Check SMTP settings.")
                        # Try to debug more info if possible
                        from .services.smtp_service import SmtpService
                        svc = SmtpService()
                        logger.warning(f"SMTP Configured: {svc.is_configured()}")
                        logger.warning(f"SMTP Host: {svc.host}:{svc.port}, User: {svc.user}, From: {svc.from_address}")
                else:
                    logger.error("Blacklist alert: No notification email configured (both blacklist_alert_email and admin_email are missing)")
            elif listed_hosts and not send_notification:
                logger.info(f"Blacklist check completed with listed hosts ({len(listed_hosts)}), but notification is suppressed (by job param).")

            # Notify when count decreased: cleared (X→0) or improved (X→Y, Y>0)
            if prev_listed > actionable_count and send_notification:
                blacklist_alert_email = settings.blacklist_alert_email if hasattr(settings, 'blacklist_alert_email') else None
                notification_email = get_notification_email(blacklist_alert_email)
                if notification_email:
                    if actionable_count == 0:
                        subject = "✅ Blacklist Cleared – All Monitored Hosts Are Off Blacklists"
                        host_list = ", ".join(h["hostname"] for h in monitored_hosts)
                        text_content = (
                            "All monitored hosts are no longer listed on any (actionable) blacklists.\n\n"
                            f"Monitored hosts: {host_list}\n\n"
                            "This is an automated notification from mailcow Logs Viewer."
                        )
                        html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px; line-height: 1.5;">
    <h2 style="color: #16a34a;">✅ Blacklist Cleared</h2>
    <p>All monitored hosts are no longer listed on any (actionable) blacklists.</p>
    <p><strong>Monitored hosts:</strong> {host_list}</p>
    <hr style="margin-top: 30px;">
    <p style="color: #999; font-size: 12px;">This is an automated notification from mailcow Logs Viewer.</p>
    </body>
    </html>
    """
                    else:
                        subject = f"📉 Blacklist Improved – {prev_listed} → {actionable_count} Host(s) Listed"
                        still_listed = ", ".join(h["hostname"] for h in actionable_listed_hosts)
                        text_content = (
                            f"Fewer hosts are now listed on (actionable) blacklists.\n\n"
                            f"Previously: {prev_listed} host(s) listed.\n"
                            f"Now: {actionable_count} host(s) listed.\n\n"
                            f"Still listed: {still_listed}\n\n"
                            "This is an automated notification from mailcow Logs Viewer."
                        )
                        html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px; line-height: 1.5;">
    <h2 style="color: #2563eb;">📉 Blacklist Improved</h2>
    <p>Fewer hosts are now listed on (actionable) blacklists.</p>
    <p><strong>Previously:</strong> {prev_listed} host(s) listed.</p>
    <p><strong>Now:</strong> {actionable_count} host(s) listed.</p>
    <p><strong>Still listed:</strong> {still_listed}</p>
    <hr style="margin-top: 30px;">
    <p style="color: #999; font-size: 12px;">This is an automated notification from mailcow Logs Viewer.</p>
    </body>
    </html>
    """
                    sent = await asyncio.get_running_loop().run_in_executor(
                        _thread_pool_executor,
                        send_notification_email, notification_email, subject, text_content, html_content
                    )
                    if sent:
                        logger.info(f"Blacklist count change notification sent to {notification_email} (was {prev_listed}, now {actionable_count})")
                    else:
                        logger.error(f"Failed to send blacklist count change notification to {notification_email}")
                else:
                    logger.error("Blacklist count change: No notification email configured.")

            _blacklist_last_listed_actionable_count = actionable_count
            
            update_job_status('blacklist_check', 'success')

        finally:
            end_batch_scan()
        
    except asyncio.CancelledError:
        logger.info("Blacklist check cancelled by shutdown")
        try:
            end_batch_scan()
        except Exception:
            pass
        return
    except Exception as e:
        logger.error(f"Blacklist check failed: {e}")
        update_job_status('blacklist_check', 'failed', str(e))
        try:
            end_batch_scan()
        except Exception:
            pass


async def dmarc_imap_sync_job():
    """
    Scheduled job to sync DMARC reports from IMAP mailbox
    Runs every hour (configurable via DMARC_IMAP_INTERVAL)
    """
    if not settings.is_feature_enabled('dmarc'):
        logger.debug("[DMARC] Feature disabled, skipping IMAP sync")
        return
    if not settings.dmarc_imap_enabled:
        logger.debug("DMARC IMAP sync is disabled, skipping")
        return
    
    # Global cleanup to ensure no other job is stuck in 'running' state
    try:
        # Assuming you have a way to get a DB session here
        with SessionLocal() as db:
            db.query(DMARCSync).filter(DMARCSync.status == 'running').update({
                "status": "failed",
                "error_message": "Stale job cleaned by scheduler"
            })
            db.commit()
    except Exception as cleanup_err:
        logger.warning(f"Background cleanup failed: {cleanup_err}")

    # Start the current job
    update_job_status('dmarc_imap_sync', 'running')
    
    try:
        logger.info("Starting DMARC IMAP sync...")
        
        # Execute the actual IMAP sync logic in thread pool to avoid blocking event loop
        # This prevents the application from freezing during IMAP connection attempts
        result = await asyncio.get_event_loop().run_in_executor(
            _thread_pool_executor,
            sync_dmarc_reports_from_imap,
            'auto'
        )
        
        if result.get('status') == 'error':
            error_msg = result.get('error_message', 'Unknown error')
            logger.error(f"DMARC IMAP sync failed: {error_msg}")
            update_job_status('dmarc_imap_sync', 'failed', error_msg)
            
            # Send notification if needed
            failed_emails = result.get('failed_emails')
            if failed_emails and settings.notification_smtp_configured:
                try:
                    await asyncio.get_running_loop().run_in_executor(
                        _thread_pool_executor,
                        send_dmarc_error_notification, failed_emails, result.get('sync_id')
                    )
                except Exception as e:
                    logger.error(f"Failed to send error notification: {e}")
        elif result.get('status') == 'disabled':
            logger.debug("DMARC IMAP sync is disabled")
            update_job_status('dmarc_imap_sync', 'disabled')
        else:
            # Sync finished successfully
            logger.info(f"DMARC IMAP sync completed: {result.get('reports_created', 0)} created")
            update_job_status('dmarc_imap_sync', 'success')
            
    except Exception as e:
        # Catch-all for unexpected crashes
        logger.error(f"DMARC IMAP sync job error: {e}", exc_info=True)
        update_job_status('dmarc_imap_sync', 'failed', str(e))
    finally:
        # Ensure the state is never left as 'running' if the code reaches here
        logger.debug("DMARC IMAP sync job cycle finished")


# =============================================================================
# CLEANUP
# =============================================================================

async def cleanup_old_logs():
    """Delete logs older than retention period"""
    update_job_status('cleanup_logs', 'running')
    try:
        with get_db_context() as db:
            cutoff_date = datetime.now(timezone.utc) - timedelta(
                days=settings.retention_days
            )
            
            postfix_deleted = db.query(PostfixLog).filter(
                PostfixLog.time < cutoff_date
            ).delete()
            
            rspamd_deleted = db.query(RspamdLog).filter(
                RspamdLog.time < cutoff_date
            ).delete()
            
            netfilter_deleted = db.query(NetfilterLog).filter(
                NetfilterLog.time < cutoff_date
            ).delete()
            
            correlation_deleted = db.query(MessageCorrelation).filter(
                MessageCorrelation.first_seen < cutoff_date
            ).delete()
            
            db.commit()
            
            total = postfix_deleted + rspamd_deleted + netfilter_deleted + correlation_deleted
            
            if total > 0:
                logger.info(f"[CLEANUP] Cleaned up {total} old entries")
            
            update_job_status('cleanup_logs', 'success')
    
    except Exception as e:
        logger.error(f"[ERROR] Cleanup error: {e}")
        update_job_status('cleanup_logs', 'failed', str(e))


async def cleanup_old_dmarc_reports():
    """Delete DMARC and TLS reports older than DMARC_RETENTION_DAYS"""
    if not settings.is_feature_enabled('dmarc'):
        logger.debug("[DMARC] Feature disabled, skipping report cleanup")
        return
    update_job_status('cleanup_dmarc_reports', 'running')
    try:
        with get_db_context() as db:
            cutoff_date = datetime.now(timezone.utc) - timedelta(
                days=settings.dmarc_retention_days
            )

            # Old DMARC report IDs (by created_at)
            old_dmarc_ids = [
                row[0]
                for row in db.query(DMARCReport.id).filter(
                    DMARCReport.created_at < cutoff_date
                ).all()
            ]
            dmarc_records_deleted = 0
            if old_dmarc_ids:
                dmarc_records_deleted = db.query(DMARCRecord).filter(
                    DMARCRecord.dmarc_report_id.in_(old_dmarc_ids)
                ).delete(synchronize_session=False)
                dmarc_reports_deleted = db.query(DMARCReport).filter(
                    DMARCReport.created_at < cutoff_date
                ).delete()
            else:
                dmarc_reports_deleted = 0

            # Old TLS report IDs (by created_at)
            old_tls_ids = [
                row[0]
                for row in db.query(TLSReport.id).filter(
                    TLSReport.created_at < cutoff_date
                ).all()
            ]
            tls_policies_deleted = 0
            if old_tls_ids:
                tls_policies_deleted = db.query(TLSReportPolicy).filter(
                    TLSReportPolicy.tls_report_id.in_(old_tls_ids)
                ).delete(synchronize_session=False)
                tls_reports_deleted = db.query(TLSReport).filter(
                    TLSReport.created_at < cutoff_date
                ).delete()
            else:
                tls_reports_deleted = 0

            db.commit()

            total = dmarc_records_deleted + dmarc_reports_deleted + tls_policies_deleted + tls_reports_deleted
            if total > 0:
                logger.info(
                    f"[CLEANUP DMARC] Removed {dmarc_reports_deleted} DMARC reports (+ {dmarc_records_deleted} records), "
                    f"{tls_reports_deleted} TLS reports (+ {tls_policies_deleted} policies) older than {settings.dmarc_retention_days} days"
                )
                clear_dmarc_cache(db)

            update_job_status('cleanup_dmarc_reports', 'success')
    except Exception as e:
        logger.error(f"[ERROR] DMARC cleanup error: {e}")
        update_job_status('cleanup_dmarc_reports', 'failed', str(e))


def cleanup_blacklisted_data():
    """
    One-time cleanup of existing blacklisted data.
    Called on startup to purge any data that was imported before
    the blacklist was properly configured.
    """
    blacklist = settings.blacklist_emails_list
    if not blacklist:
        logger.info("[BLACKLIST] No blacklist configured, skipping cleanup")
        return
    
    logger.info(f"[BLACKLIST] Running startup cleanup for {len(blacklist)} blacklisted emails...")
    
    try:
        with get_db_context() as db:
            total_deleted = 0
            
            # 1. Find and delete correlations with blacklisted sender or recipient
            for email in blacklist:
                # Delete correlations where sender matches
                deleted = db.query(MessageCorrelation).filter(
                    MessageCorrelation.sender.ilike(email)
                ).delete(synchronize_session=False)
                total_deleted += deleted
                
                # Delete correlations where recipient matches
                deleted = db.query(MessageCorrelation).filter(
                    MessageCorrelation.recipient.ilike(email)
                ).delete(synchronize_session=False)
                total_deleted += deleted
            
            if total_deleted > 0:
                logger.info(f"[BLACKLIST] Deleted {total_deleted} correlations with blacklisted emails")
            
            # 2. Find Postfix logs with blacklisted emails and get their queue IDs
            blacklisted_queue_ids: Set[str] = set()
            
            for email in blacklist:
                # Find queue IDs from logs with blacklisted sender
                postfix_with_sender = db.query(PostfixLog.queue_id).filter(
                    PostfixLog.sender.ilike(email),
                    PostfixLog.queue_id.isnot(None)
                ).distinct().all()
                
                for row in postfix_with_sender:
                    if row[0]:
                        blacklisted_queue_ids.add(row[0])
                
                # Find queue IDs from logs with blacklisted recipient
                postfix_with_recipient = db.query(PostfixLog.queue_id).filter(
                    PostfixLog.recipient.ilike(email),
                    PostfixLog.queue_id.isnot(None)
                ).distinct().all()
                
                for row in postfix_with_recipient:
                    if row[0]:
                        blacklisted_queue_ids.add(row[0])
            
            # 3. Delete all Postfix logs with blacklisted queue IDs
            if blacklisted_queue_ids:
                deleted_postfix = db.query(PostfixLog).filter(
                    PostfixLog.queue_id.in_(blacklisted_queue_ids)
                ).delete(synchronize_session=False)
                
                if deleted_postfix > 0:
                    logger.info(f"[BLACKLIST] Deleted {deleted_postfix} Postfix logs from {len(blacklisted_queue_ids)} blacklisted queue IDs")
                
                # Also delete any remaining correlations for these queue IDs
                deleted_corr = db.query(MessageCorrelation).filter(
                    MessageCorrelation.queue_id.in_(blacklisted_queue_ids)
                ).delete(synchronize_session=False)
                
                if deleted_corr > 0:
                    logger.info(f"[BLACKLIST] Deleted {deleted_corr} additional correlations")
            
            # 4. Delete Rspamd logs with blacklisted emails
            deleted_rspamd = 0
            for email in blacklist:
                # Delete by sender
                deleted = db.query(RspamdLog).filter(
                    RspamdLog.sender_smtp.ilike(email)
                ).delete(synchronize_session=False)
                deleted_rspamd += deleted
            
            if deleted_rspamd > 0:
                logger.info(f"[BLACKLIST] Deleted {deleted_rspamd} Rspamd logs with blacklisted senders")
            
            db.commit()
            logger.info("[BLACKLIST] Startup cleanup completed")
            
    except Exception as e:
        logger.error(f"[BLACKLIST] Cleanup error: {e}")


async def check_all_domains_dns_background():
    """Background job to check DNS for all domains"""
    if not settings.is_feature_enabled('domains'):
        logger.debug("[DNS] Domains feature disabled, skipping DNS check")
        return
    logger.info("Starting background DNS check...")
    update_job_status('dns_check', 'running')
    try:
        domains = await mailcow_api.get_domains()
        
        if not domains:
            return
        
        checked_count = 0
        
        for domain_data in domains:
            domain_name = domain_data.get('domain_name')
            if not domain_name or domain_data.get('active', 0) != 1:
                continue
            
            try:
                dns_data = await check_domain_dns(domain_name)
                
                with get_db_context() as db:
                    await save_dns_check_to_db(db, domain_name, dns_data, is_full_check=True)
                
                checked_count += 1
                await asyncio.sleep(0.5)
                
            except asyncio.CancelledError:
                logger.info("DNS check interrupted by shutdown")
                return
            except Exception as e:
                logger.error(f"Failed DNS check for {domain_name}: {e}")
        
        logger.info(f"DNS check completed: {checked_count} domains")
        update_job_status('dns_check', 'success')
        
    except asyncio.CancelledError:
        logger.info("Background DNS check cancelled by shutdown")
        return
    except Exception as e:
        logger.error(f"Background DNS check failed: {e}")
        update_job_status('dns_check', 'failed', str(e))


async def sync_local_domains():
    """
    Sync local domains from mailcow API (primary domains + alias domains).
    Alias domains are included so
    mail from them is correctly classified as outbound/local.
    Runs every 6 hours.
    """
    logger.info("Starting background local domains sync...")
    update_job_status('sync_local_domains', 'running')
    
    try:
        active_domains = await mailcow_api.get_active_domains()
        alias_domains = await mailcow_api.get_alias_domains()
        # Merge: primary domains + alias domains (no duplicates)
        all_domains = list(dict.fromkeys((active_domains or []) + (alias_domains or [])))
        if all_domains:
            set_cached_active_domains(all_domains)
            logger.info(f"✓ Local domains synced: {len(active_domains or [])} primary, {len(alias_domains or [])} alias → {len(all_domains)} total")
            update_job_status('sync_local_domains', 'success')
            return True
        else:
            logger.warning("⚠ No active domains retrieved")
            update_job_status('sync_local_domains', 'failed', "No domains")
            return False
    except Exception as e:
        logger.error(f"✗ Failed to sync local domains: {e}")
        update_job_status('sync_local_domains', 'failed', str(e))
        return False

# =============================================================================
# MAILBOX STATISTICS
# =============================================================================

def safe_int(value, default=0):
    """Safely convert a value to int, handling '- ', None, and other invalid values"""
    if value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip()
        if value in ('', '-', '- '):
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default

def safe_float(value, default=0.0):
    """Safely convert a value to float, handling '- ', None, and other invalid values"""
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        value = value.strip()
        if value in ('', '-', '- '):
            return default
        try:
            return float(value)
        except (ValueError, TypeError):
            return default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default

async def update_mailbox_statistics():
    """
    Fetch mailbox statistics from mailcow API and update the database.
    Runs every 5 minutes.
    Also removes mailboxes that no longer exist in mailcow.
    """
    if not settings.is_feature_enabled('mailbox-stats'):
        logger.debug("[MAILBOX] Feature disabled, skipping mailbox statistics")
        return
    update_job_status('mailbox_stats', 'running')
    logger.info("Starting mailbox statistics update...")
    
    try:
        # Fetch mailboxes from mailcow API
        mailboxes = await mailcow_api.get_mailboxes()
        
        if not mailboxes:
            logger.warning("No mailboxes retrieved from mailcow API")
            update_job_status('mailbox_stats', 'success')
            return
        
        # Get set of current mailbox usernames from API
        api_mailbox_usernames = {mb.get('username') for mb in mailboxes if mb.get('username')}
        
        with get_db_context() as db:
            updated = 0
            created = 0
            deleted = 0
            
            # First, mark mailboxes that no longer exist in mailcow as inactive
            db_mailboxes = db.query(MailboxStatistics).all()
            for db_mb in db_mailboxes:
                if db_mb.username not in api_mailbox_usernames:
                    if db_mb.active:  # Only log and count if it was previously active
                        logger.info(f"Marking deleted mailbox as inactive: {db_mb.username}")
                        db_mb.active = False
                        db_mb.updated_at = datetime.now(timezone.utc)
                        deleted += 1
            
            for mb in mailboxes:
                try:
                    username = mb.get('username')
                    if not username:
                        continue
                    
                    # Extract domain from username
                    domain = username.split('@')[-1] if '@' in username else ''
                    
                    # Check if mailbox exists
                    existing = db.query(MailboxStatistics).filter(
                        MailboxStatistics.username == username
                    ).first()
                    
                    # Prepare data - safely convert values
                    attributes = mb.get('attributes', {})
                    # Handle Rate Limit (can be flat or nested unique to Mailcow version)
                    rl_data = mb.get('rl')
                    if isinstance(rl_data, dict):
                        rl_value_raw = rl_data.get('value')
                        rl_frame_raw = rl_data.get('frame')
                    else:
                        rl_value_raw = mb.get('rl_value')
                        rl_frame_raw = mb.get('rl_frame')

                    rl_value = safe_int(rl_value_raw) if rl_value_raw not in (None, '', '-', '- ') else None
                    rl_frame = rl_frame_raw if rl_frame_raw not in (None, '', '-', '- ') else None
                    
                    if existing:
                        # Update existing record
                        existing.domain = domain
                        existing.name = mb.get('name', '') or ''
                        existing.quota = safe_int(mb.get('quota'), 0)
                        existing.quota_used = safe_int(mb.get('quota_used'), 0)
                        existing.percent_in_use = safe_float(mb.get('percent_in_use'), 0.0)
                        existing.messages = safe_int(mb.get('messages'), 0)
                        existing.active = mb.get('active', 1) == 1
                        existing.last_imap_login = safe_int(mb.get('last_imap_login'), 0) or None
                        existing.last_pop3_login = safe_int(mb.get('last_pop3_login'), 0) or None
                        existing.last_smtp_login = safe_int(mb.get('last_smtp_login'), 0) or None
                        existing.spam_aliases = safe_int(mb.get('spam_aliases'), 0)
                        existing.rl_value = rl_value
                        existing.rl_frame = rl_frame
                        existing.attributes = attributes
                        existing.updated_at = datetime.now(timezone.utc)
                        updated += 1
                    else:
                        # Create new record
                        new_mailbox = MailboxStatistics(
                            username=username,
                            domain=domain,
                            name=mb.get('name', '') or '',
                            quota=safe_int(mb.get('quota'), 0),
                            quota_used=safe_int(mb.get('quota_used'), 0),
                            percent_in_use=safe_float(mb.get('percent_in_use'), 0.0),
                            messages=safe_int(mb.get('messages'), 0),
                            active=mb.get('active', 1) == 1,
                            last_imap_login=safe_int(mb.get('last_imap_login'), 0) or None,
                            last_pop3_login=safe_int(mb.get('last_pop3_login'), 0) or None,
                            last_smtp_login=safe_int(mb.get('last_smtp_login'), 0) or None,
                            spam_aliases=safe_int(mb.get('spam_aliases'), 0),
                            rl_value=rl_value,
                            rl_frame=rl_frame,
                            attributes=attributes
                        )
                        db.add(new_mailbox)
                        created += 1
                
                except Exception as e:
                    logger.error(f"Error processing mailbox {mb.get('username', 'unknown')}: {e}")
                    continue
            
            db.commit()
            logger.info(f"✓ Mailbox statistics updated: {updated} updated, {created} created, {deleted} deactivated")
            update_job_status('mailbox_stats', 'success')
    
    except Exception as e:
        logger.error(f"✗ Failed to update mailbox statistics: {e}")
        update_job_status('mailbox_stats', 'failed', str(e))


# =============================================================================
# ALIAS STATISTICS
# =============================================================================

async def update_alias_statistics():
    """
    Fetch aliases from mailcow API and update the database.
    Links aliases to their target mailboxes.
    Runs every 5 minutes.
    Also removes aliases that no longer exist in mailcow.
    """
    if not settings.is_feature_enabled('mailbox-stats'):
        logger.debug("[ALIAS] Feature disabled, skipping alias statistics")
        return
    update_job_status('alias_stats', 'running')
    logger.info("Starting alias statistics update...")
    
    try:
        # Fetch aliases from mailcow API
        aliases = await mailcow_api.get_aliases()
        
        if not aliases:
            logger.warning("No aliases retrieved from mailcow API")
            update_job_status('alias_stats', 'success')
            return
        
        # Get set of current alias addresses from API
        api_alias_addresses = {alias.get('address') for alias in aliases if alias.get('address')}
        
        with get_db_context() as db:
            updated = 0
            created = 0
            deleted = 0
            
            # First, mark aliases that no longer exist in mailcow as inactive
            db_aliases = db.query(AliasStatistics).all()
            for db_alias in db_aliases:
                if db_alias.alias_address not in api_alias_addresses:
                    if db_alias.active:  # Only log and count if it was previously active
                        logger.info(f"Marking deleted alias as inactive: {db_alias.alias_address}")
                        db_alias.active = False
                        db_alias.updated_at = datetime.now(timezone.utc)
                        deleted += 1
            
            for alias in aliases:
                try:
                    alias_address = alias.get('address')
                    if not alias_address:
                        continue
                    
                    # Skip if this is a mailbox address (not an alias)
                    if alias.get('is_catch_all') is None and not alias.get('goto'):
                        continue
                    
                    # Extract domain from alias address
                    domain = alias_address.split('@')[-1] if '@' in alias_address else ''
                    
                    # Get the target mailbox(es)
                    goto = alias.get('goto', '')
                    
                    # Determine primary mailbox (first in goto list)
                    primary_mailbox = None
                    if goto:
                        goto_list = [g.strip() for g in goto.split(',') if g.strip()]
                        if goto_list:
                            primary_mailbox = goto_list[0]
                    
                    # Check if alias exists
                    existing = db.query(AliasStatistics).filter(
                        AliasStatistics.alias_address == alias_address
                    ).first()
                    
                    is_catch_all = alias.get('is_catch_all', 0) == 1
                    is_active = alias.get('active', 1) == 1
                    
                    if existing:
                        # Update existing record
                        existing.goto = goto
                        existing.domain = domain
                        existing.active = is_active
                        existing.is_catch_all = is_catch_all
                        existing.primary_mailbox = primary_mailbox
                        existing.updated_at = datetime.now(timezone.utc)
                        updated += 1
                    else:
                        # Create new record
                        new_alias = AliasStatistics(
                            alias_address=alias_address,
                            goto=goto,
                            domain=domain,
                            active=is_active,
                            is_catch_all=is_catch_all,
                            primary_mailbox=primary_mailbox
                        )
                        db.add(new_alias)
                        created += 1
                
                except Exception as e:
                    logger.error(f"Error processing alias {alias.get('address', 'unknown')}: {e}")
                    continue
            
            db.commit()
            logger.info(f"✓ Alias statistics updated: {updated} updated, {created} created, {deleted} deactivated")
            update_job_status('alias_stats', 'success')
    
    except Exception as e:
        logger.error(f"✗ Failed to update alias statistics: {e}")
        update_job_status('alias_stats', 'failed', str(e))



# =============================================================================
# MONITORED HOSTS SYNC
# =============================================================================

async def sync_transports_job():
    """
    Sync transports and relayhosts from mailcow to MonitoredHost table.
    Resolves FQDNs to IPs and skips private/internal IPs.
    Stores Original FQDN in source field as 'transport:fqdn' or 'relayhost:fqdn'.
    Runs every 6 hours.
    """
    if not settings.is_feature_enabled('domains'):
        logger.debug("[TRANSPORTS] Domains feature disabled, skipping transport sync")
        return
    update_job_status('sync_transports', 'running')
    try:
        if not settings.mailcow_api_key or not settings.mailcow_url:
            logger.warning("mailcow API not configured, skipping transport sync")
            update_job_status('sync_transports', 'failed', 'API not configured')
            return

        # Fetch Transports and Relay Hosts using mailcow_api
        transports_data = await mailcow_api.get_transports()
        relayhosts_data = await mailcow_api.get_relayhosts()

        # Process and Deduplicate
        hosts_to_monitor = {}  # ip -> source_string

        async def resolve_and_validate(host_input: str, source_type: str) -> Optional[tuple]:
            """Resolve host to IP, validate public, return (ip, full_source_string)"""
            host_clean = host_input.strip().lower()
            # Remove brackets/ports
            host_clean = host_clean.strip('[]')
            if ':' in host_clean:
                host_clean = host_clean.split(':')[0]

            if not host_clean:
                return None

            try:
                # Is it already an IP?
                try:
                    ip_obj = ipaddress.ip_address(host_clean)
                    ip_str = str(ip_obj)
                    fqdn = None # IP was provided directly
                except ValueError:
                    # It's a domain, resolve it in a worker thread so a slow DNS
                    # lookup doesn't block the shared event loop
                    try:
                        loop = asyncio.get_running_loop()
                        ip_str = await loop.run_in_executor(None, socket.gethostbyname, host_clean)
                        ip_obj = ipaddress.ip_address(ip_str)
                        fqdn = host_clean
                    except Exception:
                        logger.warning(f"Could not resolve host: {host_clean}")
                        return None
                
                # Check for private IP
                if ip_obj.is_private or ip_obj.is_loopback:
                    logger.info(f"Skipping private/loopback IP: {ip_str} ({host_clean})")
                    return None
                
                # Construct source string
                # If we have an FQDN, store it: "transport:example.com"
                # If we just have IP, store: "transport"
                if fqdn:
                    final_source = f"{source_type}:{fqdn}"
                else:
                    final_source = source_type

                return (ip_str, final_source)
                
            except Exception as e:
                logger.error(f"Error validating host {host_clean}: {e}")
                return None

        # Process Transports
        for t in transports_data:
            if str(t.get('active', '0')) == '1':
                nexthop = t.get('nexthop', '').strip()
                result = await resolve_and_validate(nexthop, 'transport')
                if result:
                    hosts_to_monitor[result[0]] = result[1]

        # Process Relay Hosts
        for r in relayhosts_data:
            if str(r.get('active', '0')) == '1':
                hostname = r.get('hostname', '').strip()
                result = await resolve_and_validate(hostname, 'relayhost')
                if result:
                    hosts_to_monitor[result[0]] = result[1]
        
        # Also ensure local IP is monitored
        from .routers.domains import get_cached_server_ip
        local_ip = get_cached_server_ip()
        if local_ip:
            if local_ip not in hosts_to_monitor:
                hosts_to_monitor[local_ip] = 'system'
            # Update local IP source to 'system' regardless if it was found elsewhere, 
            # or maybe prefer 'system' label? User likes 'system' label.
            # But if system IP matches a transport IP, we might want to know it's also a transport?
            # Let's keep 'system' priority if it's the main server.
            hosts_to_monitor[local_ip] = 'system'

        # Update DB
        with get_db_context() as db:
            existing_hosts = {h.hostname: h for h in db.query(MonitoredHost).all()}
            
            added_count = 0
            updated_count = 0
            
            for ip_addr, source in hosts_to_monitor.items():
                if ip_addr in existing_hosts:
                    host = existing_hosts[ip_addr]
                    if not host.active or host.source != source:
                        host.active = True
                        host.source = source
                        updated_count += 1
                else:
                    new_host = MonitoredHost(
                        hostname=ip_addr, # Store IP here now!
                        source=source,
                        active=True,
                        last_seen=datetime.utcnow()
                    )
                    db.add(new_host)
                    added_count += 1
            
            deactivated_count = 0
            for hostname, host in existing_hosts.items():
                if hostname not in hosts_to_monitor and host.active:
                    host.active = False
                    deactivated_count += 1
            
            db.commit()
            
            summary = f"Synced monitored hosts: {added_count} added, {updated_count} updated, {deactivated_count} deactivated (filtered private IPs)"
            logger.info(summary)
            update_job_status('sync_transports', 'success')

            # Trigger immediate blacklist check (smart mode: checks cache headers/validity inside)
            # This ensures if we added new hosts, they get checked immediately
            logger.info("Triggering post-sync blacklist check...")
            await check_monitored_hosts_job(force=False, send_notification=False)
            
    except Exception as e:
        logger.error(f"Sync transports failed: {e}")
        update_job_status('sync_transports', 'failed', str(e))


async def send_weekly_summary_email_job():
    """
    Background job to send weekly summary email
    """
    from .routers.reporting import generate_and_send_email

    update_job_status('send_weekly_summary', 'running')
    try:
        if not settings.enable_weekly_summary:
            # logger.info("Weekly summary report is disabled, skipping.")
            update_job_status('send_weekly_summary', 'skipped')
            return

        # Execute
        await generate_and_send_email(db=None) 
        update_job_status('send_weekly_summary', 'success')
        
    except Exception as e:
        logger.error(f"Weekly summary job failed: {e}")
        update_job_status('send_weekly_summary', 'failed', str(e))

async def cleanup_deferred_queue_job():
    """
    Periodically scan the mail queue for deferred items stuck longer than
    QUEUE_CLEANUP_THRESHOLD_MINUTES.  For each stuck item:
      1. Delete from queue via mailcow API
      2. Suppress the recipient(s) using suppression_base_expiry_days
    Completely stateless — only looks at arrival_time vs now.
    """
    if not settings.is_feature_enabled('spam-filter'):
        return
    if not settings.suppression_enabled or not settings.queue_cleanup_enabled:
        return
    if not mailcow_api.has_rw_key:
        return

    update_job_status('cleanup_deferred_queue', 'running')

    try:
        queue = await mailcow_api.get_queue()
        if not queue:
            update_job_status('cleanup_deferred_queue', 'success')
            return

        now_ts = datetime.now(timezone.utc).timestamp()
        threshold_seconds = settings.queue_cleanup_threshold_minutes * 60
        whitelist = settings.suppression_whitelist_domains_list

        items_to_delete = []
        recipients_to_suppress = []  # (email, dsn_hint)

        for item in queue:
            queue_name = (item.get('queue_name') or '').lower()
            if queue_name != 'deferred':
                continue

            arrival_time = item.get('arrival_time')
            if not arrival_time:
                continue

            age_seconds = now_ts - arrival_time
            if age_seconds < threshold_seconds:
                continue

            queue_id = item.get('queue_id')
            if not queue_id:
                continue

            # This item has been deferred longer than threshold — collect for deletion
            items_to_delete.append(queue_id)

            # Collect recipients for suppression
            for rcpt in (item.get('recipients') or []):
                rcpt_email = rcpt.split(' ')[0].strip('<>').lower()
                if not rcpt_email or '@' not in rcpt_email:
                    continue
                domain = rcpt_email.split('@')[-1]
                if domain in whitelist:
                    continue
                recipients_to_suppress.append(rcpt_email)

            age_min = int(age_seconds / 60)
            logger.info(
                f"[QUEUE CLEANUP] Deferred item {queue_id} stuck for {age_min}m "
                f"(threshold: {settings.queue_cleanup_threshold_minutes}m) — "
                f"recipients: {', '.join(r.split(' ')[0].strip('<>') for r in (item.get('recipients') or []))}"
            )

        if not items_to_delete:
            update_job_status('cleanup_deferred_queue', 'success')
            return

        # Delete stuck items from queue
        try:
            await mailcow_api.delete_queue(items_to_delete)
            logger.info(f"[QUEUE CLEANUP] Deleted {len(items_to_delete)} stuck deferred item(s) from queue")
        except Exception as e:
            logger.error(f"[QUEUE CLEANUP] Failed to delete queue items: {e}")
            update_job_status('cleanup_deferred_queue', 'failed', f"Queue delete failed: {e}")
            return

        # Suppress recipients
        if recipients_to_suppress:
            unique_recipients = set(recipients_to_suppress)
            suppress_count = 0

            with get_db_context() as db:
                for email in unique_recipients:
                    existing = db.query(SpamSuppression).filter(
                        SpamSuppression.email == email
                    ).first()

                    if existing:
                        existing.bounce_count = (existing.bounce_count or 0) + 1
                        existing.soft_bounce_count = (existing.soft_bounce_count or 0) + 1
                        existing.reason = 'deferred_stuck'
                        existing.last_bounce_message = f'Deferred in queue > {settings.queue_cleanup_threshold_minutes}m — auto-cleaned'
                        existing.updated_at = datetime.utcnow()

                        if not existing.active or (existing.expires_at and existing.expires_at < datetime.utcnow()):
                            existing.active = True
                            existing.synced_to_rspamd = False

                        # Extend expiry
                        expiry_days = min(
                            settings.suppression_base_expiry_days * existing.bounce_count,
                            settings.suppression_max_expiry_days
                        )
                        existing.expires_at = datetime.utcnow() + timedelta(days=expiry_days)
                    else:
                        new_entry = SpamSuppression(
                            email=email,
                            type='email',
                            reason='deferred_stuck',
                            source='auto',
                            bounce_count=1,
                            hard_bounce_count=0,
                            soft_bounce_count=1,
                            last_bounce_dsn='4.x.x',
                            last_bounce_message=f'Deferred in queue > {settings.queue_cleanup_threshold_minutes}m — auto-cleaned',
                            active=True,
                            synced_to_rspamd=False,
                            expires_at=datetime.utcnow() + timedelta(days=settings.suppression_base_expiry_days),
                            correlation_key=None
                        )
                        db.add(new_entry)
                    suppress_count += 1

                db.commit()

            logger.info(
                f"[QUEUE CLEANUP] Suppressed {suppress_count} recipient(s) for "
                f"{settings.suppression_base_expiry_days} day(s)"
            )

            # Trigger immediate Rspamd sync so the block takes effect now
            if settings.suppression_rspamd_sync and settings.is_rspamd_configured:
                try:
                    await sync_suppressions_to_rspamd_job()
                    logger.info("[QUEUE CLEANUP] Triggered immediate Rspamd sync")
                except Exception as e:
                    logger.warning(f"[QUEUE CLEANUP] Rspamd sync failed (will retry on schedule): {e}")

        update_job_status('cleanup_deferred_queue', 'success')

    except asyncio.CancelledError:
        logger.info("[QUEUE CLEANUP] Job cancelled (shutdown)")
        update_job_status('cleanup_deferred_queue', 'success')
    except Exception as e:
        logger.error(f"[QUEUE CLEANUP] Error: {e}", exc_info=True)
        update_job_status('cleanup_deferred_queue', 'failed', str(e))


def start_scheduler():
    """Start the background scheduler"""
    try:
        # Run one-time blacklist cleanup on startup
        cleanup_blacklisted_data()
        
        # Job 1: Fetch logs from API (every fetch_interval seconds)
        scheduler.add_job(
            fetch_all_logs,
            trigger=IntervalTrigger(seconds=settings.fetch_interval),
            id='fetch_logs',
            name='Fetch mailcow Logs',
            replace_existing=True,
            max_instances=1
        )
        
        # Job 2: Run correlation (every 30 seconds, after logs are imported)
        scheduler.add_job(
            run_correlation,
            trigger=IntervalTrigger(seconds=30),
            id='run_correlation',
            name='Correlate Logs',
            replace_existing=True,
            max_instances=1
        )
        
        # Job 3: Complete incomplete correlations (every 2 minutes)
        scheduler.add_job(
            complete_incomplete_correlations,
            trigger=IntervalTrigger(seconds=settings.correlation_check_interval),
            id='complete_correlations',
            name='Complete Correlations',
            replace_existing=True,
            max_instances=1
        )
        
        # Job 4: Expire old incomplete correlations (every 1 minute)
        # This is separate to ensure old correlations get expired reliably
        scheduler.add_job(
            expire_old_correlations,
            trigger=IntervalTrigger(seconds=60),
            id='expire_correlations',
            name='Expire Old Correlations',
            replace_existing=True,
            max_instances=1
        )
        
        # Job 5: Update final status for correlations (every correlation_check_interval)
        # This handles late-arriving Postfix logs (e.g., status=sent) that arrive
        # after the initial correlation was created
        scheduler.add_job(
            update_final_status_for_correlations,
            trigger=IntervalTrigger(seconds=settings.correlation_check_interval),
            id='update_final_status',
            name='Update Final Status',
            replace_existing=True,
            max_instances=1
        )
        
        # Job 6: Cleanup old logs (daily at 2 AM)
        scheduler.add_job(
            cleanup_old_logs,
            trigger=CronTrigger(hour=2, minute=0),
            id='cleanup_logs',
            name='Cleanup Old Logs',
            replace_existing=True
        )

        # Job 6b: Cleanup old DMARC/TLS reports (daily at 2:15 AM)
        if settings.is_feature_enabled('dmarc'):
            scheduler.add_job(
                cleanup_old_dmarc_reports,
                trigger=CronTrigger(hour=2, minute=15),
                id='cleanup_dmarc_reports',
                name='Cleanup Old DMARC Reports',
                replace_existing=True
            )
        else:
            logger.info("   [FEATURE] DMARC feature disabled — skipping DMARC cleanup job")
        
        # Job 7: Check app version updates (every 6 hours, starting immediately)
        scheduler.add_job(
            check_app_version_update,
            trigger=IntervalTrigger(hours=6),
            id='check_app_version',
            name='Check App Version Updates',
            replace_existing=True,
            max_instances=1,
            next_run_time=datetime.now(timezone.utc)
        )
        
        # Job 8: DNS Check
        if settings.is_feature_enabled('domains'):
            scheduler.add_job(
                check_all_domains_dns_background,
                trigger=IntervalTrigger(hours=6),
                id='dns_check_background',
                name='DNS Check (All Domains)',
                replace_existing=True,
                max_instances=1
            )
            
            # Job 8b: Initial DNS check on startup
            scheduler.add_job(
                check_all_domains_dns_background,
                'date',
                run_date=datetime.now(timezone.utc) + timedelta(seconds=60),
                id='dns_check_startup',
                name='DNS Check (Startup)'
            )
        else:
            logger.info("   [FEATURE] Domains feature disabled — skipping DNS check jobs")

        # Job 9: Sync local domains (every 6 hours)
        scheduler.add_job(
            sync_local_domains,
            IntervalTrigger(hours=6),
            id='sync_local_domains',
            name='Sync Local Domains',
            replace_existing=True,
            max_instances=1,
            next_run_time=datetime.now(timezone.utc)
        )

        # Job 11: Update GeoIP database (weekly, Sunday at 3 AM)
        # Only runs if MaxMind license key is configured
        if is_license_configured():
            scheduler.add_job(
                update_geoip_database,
                trigger=CronTrigger(day_of_week='sun', hour=3, minute=0),
                id='update_geoip',
                name='Update GeoIP',
                replace_existing=True
            )
            
            # Run initial check on startup (after 60 seconds to let everything settle)
            scheduler.add_job(
                update_geoip_database,
                'date',
                run_date=datetime.now(timezone.utc) + timedelta(seconds=60),
                id='geoip_startup',
                name='GeoIP Check (Startup)'
            )
            logger.info("   [GEOIP] Initial GeoIP check scheduled (60 seconds after startup)")
        else:
            logger.info("   [GEOIP] MaxMind license key not configured, GeoIP features disabled")

        # Job 12: DMARC IMAP Sync - runs at configured interval (default: hourly)
        if settings.is_feature_enabled('dmarc') and settings.dmarc_imap_enabled:
            scheduler.add_job(
                dmarc_imap_sync_job,
                IntervalTrigger(seconds=settings.dmarc_imap_interval),
                id='dmarc_imap_sync',
                name='DMARC IMAP Sync',
                replace_existing=True
            )
            logger.info(f"Scheduled DMARC IMAP sync job (interval: {settings.dmarc_imap_interval}s)")
        
        # Run once on startup if configured
        if settings.is_feature_enabled('dmarc') and settings.dmarc_imap_run_on_startup:
            scheduler.add_job(
                dmarc_imap_sync_job,
                'date',
                run_date=datetime.now() + timedelta(seconds=30),
                id='dmarc_imap_sync_startup',
                name='DMARC IMAP Sync (Startup)'
            )
            logger.info("Scheduled initial DMARC IMAP sync on startup")

        # Job 13: Mailbox Statistics (every 5 minutes)
        if settings.is_feature_enabled('mailbox-stats'):
            scheduler.add_job(
                update_mailbox_statistics,
                IntervalTrigger(minutes=5),
                id='mailbox_stats',
                name='Update Mailbox Statistics',
                replace_existing=True,
                max_instances=1
            )
            
            # Run once on startup (after 45 seconds)
            scheduler.add_job(
                update_mailbox_statistics,
                'date',
                run_date=datetime.now(timezone.utc) + timedelta(seconds=45),
                id='mailbox_stats_startup',
                name='Mailbox Statistics (Startup)'
            )
            logger.info("Scheduled mailbox statistics job (interval: 5 minutes)")

            # Job 14: Alias Statistics (every 5 minutes)
            scheduler.add_job(
                update_alias_statistics,
                IntervalTrigger(minutes=5),
                id='alias_stats',
                name='Update Alias Statistics',
                replace_existing=True,
                max_instances=1
            )
            
            # Run once on startup (after 50 seconds)
            scheduler.add_job(
                update_alias_statistics,
                'date',
                run_date=datetime.now(timezone.utc) + timedelta(seconds=50),
                id='alias_stats_startup',
                name='Alias Statistics (Startup)'
            )
            logger.info("Scheduled alias statistics job (interval: 5 minutes)")
        else:
            logger.info("   [FEATURE] Mailbox Stats feature disabled — skipping mailbox/alias stats jobs")

        # Job 15: Blacklist Check (daily at 5 AM)
        if settings.is_feature_enabled('blacklist'):
            scheduler.add_job(
                check_monitored_hosts_job,
                trigger=CronTrigger(hour=5, minute=0),
                id='blacklist_check',
                name='IP Blacklist Check (Daily)',
                replace_existing=True,
                max_instances=1
            )
            
            # Run check on startup (after 15 seconds)
            scheduler.add_job(
                check_monitored_hosts_job,
                'date',
                run_date=datetime.now(timezone.utc) + timedelta(seconds=15),
                id='blacklist_check_startup',
                name='IP Blacklist Check (Startup)'
            )
        else:
            logger.info("   [FEATURE] IP Blacklist feature disabled — skipping blacklist check jobs")


        # Job 14: Sync Transports (every 6 hours)
        if settings.is_feature_enabled('domains'):
            scheduler.add_job(
                sync_transports_job,
                trigger=IntervalTrigger(hours=6),
                id='sync_transports',
                name='Sync Transports & Relayhosts',
                replace_existing=True
            )

            # Run sync on startup (after 30 seconds)
            scheduler.add_job(
                sync_transports_job,
                'date',
                run_date=datetime.now(timezone.utc) + timedelta(seconds=30),
                id='sync_transports_startup',
                name='Sync Transports & Relayhosts (Startup)'
            )

        # Job 15: Weekly Summary Email (Every Monday at 9:00 AM)
        scheduler.add_job(
            send_weekly_summary_email_job,
            trigger=CronTrigger(day_of_week='mon', hour=9, minute=0),
            id='send_weekly_summary',
            name='Send Weekly Summary',
            replace_existing=True
        )

        # Job 16: Spam Suppression (if enabled)
        if settings.is_feature_enabled('spam-filter') and settings.suppression_enabled:
            # Detect bounces from postfix logs every 5 minutes
            scheduler.add_job(
                detect_suppressions_job,
                trigger=IntervalTrigger(minutes=5),
                id='detect_suppressions',
                name='Detect Suppressions',
                replace_existing=True,
                max_instances=1
            )
            
            # Sync suppressions to Rspamd every 10 minutes
            if settings.suppression_rspamd_sync and settings.is_rspamd_configured:
                scheduler.add_job(
                    sync_suppressions_to_rspamd_job,
                    trigger=IntervalTrigger(minutes=10),
                    id='sync_suppressions',
                    name='Sync Suppressions to Rspamd',
                    replace_existing=True,
                    max_instances=1
                )
            
            # Expire old suppressions every hour
            scheduler.add_job(
                expire_suppressions_job,
                trigger=IntervalTrigger(hours=1),
                id='expire_suppressions',
                name='Expire Suppressions',
                replace_existing=True,
                max_instances=1
            )
            
            logger.info("   [SPAM] Suppression detection: every 5 minutes")
            if settings.suppression_rspamd_sync and settings.is_rspamd_configured:
                logger.info("   [SPAM] Rspamd sync: every 10 minutes")
            logger.info("   [SPAM] Expiry check: every hour")
            
            # Deferred queue cleanup (requires RW key)
            if settings.queue_cleanup_enabled and mailcow_api.has_rw_key:
                scheduler.add_job(
                    cleanup_deferred_queue_job,
                    trigger=IntervalTrigger(minutes=5),
                    id='cleanup_deferred_queue',
                    name='Cleanup Deferred Queue',
                    replace_existing=True,
                    max_instances=1
                )
                logger.info(f"   [SPAM] Deferred queue cleanup: every 5 minutes (threshold: {settings.queue_cleanup_threshold_minutes}m)")

        # Quarantine Auto-Rules
        if settings.is_feature_enabled('quarantine') and mailcow_api.has_rw_key:
            scheduler.add_job(
                process_quarantine_rules_job,
                trigger=IntervalTrigger(minutes=settings.quarantine_rules_interval),
                id='process_quarantine_rules',
                name='Process Quarantine Rules',
                replace_existing=True,
                max_instances=1
            )
            logger.info(f"   [QUARANTINE] Auto-rules: every {settings.quarantine_rules_interval} minutes")

        scheduler.start()

        logger.info("[OK] Scheduler started")
        logger.info(f"   [INFO] Import: every {settings.fetch_interval}s")
        logger.info(f"   [LINK] Correlation: every 30s")
        logger.info(f"   [COMPLETE] Incomplete correlations: every {settings.correlation_check_interval}s")
        logger.info(f"   [STATUS] Update final status: every {settings.correlation_check_interval}s (max age: {settings.max_correlation_age_minutes}min)")
        logger.info(f"   [EXPIRE] Old correlations: every 60s (expire after {settings.max_correlation_age_minutes}min)")
        logger.info(f"   [VERSION] Check app version updates: every 6 hours")
        logger.info(f"   [DNS] Check all domains DNS: every 6 hours")
        logger.info("   [GEOIP] Update GeoIP database: weekly (Sunday 3 AM)")
        logger.info("   [BLACKLIST] Check IP blacklists: daily at 5:00 AM")
        logger.info("   [REPORT] Weekly Summary: Monday at 9:00 AM")

        
        if settings.dmarc_imap_enabled:
            logger.info(f"   [DMARC] IMAP sync: every {settings.dmarc_imap_interval // 60} minutes")
        else:
            logger.info("   [DMARC] IMAP sync: disabled")
        
        # Log blacklist status
        blacklist = settings.blacklist_emails_list
        if blacklist:
            logger.info(f"   [INFO] Blacklist: {len(blacklist)} emails")
            for email in blacklist[:5]:  # Show first 5
                logger.info(f"      - {email}")
            if len(blacklist) > 5:
                logger.info(f"      ... and {len(blacklist) - 5} more")
        else:
            logger.info("   [INFO] Blacklist: disabled (no emails configured)")
        
    except Exception as e:
        logger.error(f"[ERROR] Failed to start scheduler: {e}")
        raise


# =============================================================================
# SPAM SUPPRESSION SCHEDULER JOBS
# =============================================================================

async def detect_suppressions_job():
    """
    Scan recent postfix logs for bounced/rejected outbound emails
    and add them to the suppression list.
    """
    if not settings.is_feature_enabled('spam-filter'):
        return
    if not settings.suppression_enabled or not settings.suppression_auto_detect:
        return
    
    update_job_status('detect_suppressions', 'running')
    
    try:
        with get_db_context() as db:
            # Look for recently imported bounced emails (last 10 minutes by import time)
            # Uses created_at (DB insert time) instead of time (original mailcow timestamp)
            # so that historical bounces imported via paginated fetch are still detected
            cutoff = datetime.utcnow() - timedelta(minutes=10)
            
            # When queue_cleanup_enabled, soft bounces are handled by
            # cleanup_deferred_queue_job (checks the live queue directly).
            # Only scan logs for hard bounces in that case.
            statuses_to_check = ['bounced']
            if not settings.queue_cleanup_enabled:
                statuses_to_check.append('deferred')
            
            bounce_logs = db.query(PostfixLog).filter(
                PostfixLog.created_at >= cutoff,
                PostfixLog.status.in_(statuses_to_check),
                PostfixLog.recipient.isnot(None),
                PostfixLog.dsn.isnot(None),
            ).all()
            
            if not bounce_logs:
                update_job_status('detect_suppressions', 'success')
                return
            
            whitelist = settings.suppression_whitelist_domains_list
            new_count = 0
            updated_count = 0
            emails_for_queue_cleanup = []  # Only hard bounces — deferred/soft should be retried by Postfix
            
            for log in bounce_logs:
                # Skip DSN bounce notifications:
                # - Regular bounce lines have NO from= field → sender is None → process normally
                # - DSN messages have from=<> (empty) or from=<MAILER-DAEMON> → skip
                if log.sender is not None:
                    sender_val = log.sender.lower().strip()
                    if not sender_val or sender_val.startswith('mailer-daemon'):
                        continue
                
                recipient = log.recipient.lower().strip()
                
                # Skip whitelisted domains
                domain = recipient.split('@')[-1] if '@' in recipient else ''
                if domain in whitelist:
                    continue
                
                dsn = log.dsn or ''
                is_hard = dsn.startswith('5.')
                is_soft = dsn.startswith('4.')
                
                if is_hard and settings.suppression_hard_bounce_action == 'ignore':
                    continue
                if is_soft and settings.suppression_soft_bounce_action == 'ignore':
                    continue
                
                # Only clean queue for hard bounces (permanent failures)
                # Deferred/soft bounces are temporary — Postfix should keep retrying
                if is_hard:
                    emails_for_queue_cleanup.append(recipient)
                
                # Check if already exists
                existing = db.query(SpamSuppression).filter(
                    SpamSuppression.email == recipient
                ).first()
                
                if existing:
                    # Update bounce counts
                    existing.bounce_count = (existing.bounce_count or 0) + 1
                    if is_hard:
                        existing.hard_bounce_count = (existing.hard_bounce_count or 0) + 1
                        existing.reason = 'hard_bounce'
                    elif is_soft:
                        existing.soft_bounce_count = (existing.soft_bounce_count or 0) + 1
                    
                    existing.last_bounce_dsn = dsn
                    existing.last_bounce_message = log.message[:500] if log.message else None
                    existing.updated_at = datetime.utcnow()
                    
                    # Re-activate if expired
                    if not existing.active or (existing.expires_at and existing.expires_at < datetime.utcnow()):
                        existing.active = True
                        existing.synced_to_rspamd = False
                    
                    # Progressive expiry: base_days × bounce_count, capped at max_days
                    expiry_days = min(
                        settings.suppression_base_expiry_days * existing.bounce_count,
                        settings.suppression_max_expiry_days
                    )
                    existing.expires_at = datetime.utcnow() + timedelta(days=expiry_days)
                    
                    updated_count += 1
                else:
                    # Determine if we should suppress
                    if is_soft and settings.suppression_soft_bounce_action == 'count':
                        # For soft bounces with count action, we still create the entry
                        # but only activate it when threshold is reached
                        pass
                    
                    reason = 'hard_bounce' if is_hard else ('soft_bounce' if is_soft else 'rejected')
                    
                    is_active = True
                    # For soft bounces with count action, only activate if threshold reached
                    if is_soft and settings.suppression_soft_bounce_action == 'count':
                        is_active = False
                    
                    new_entry = SpamSuppression(
                        email=recipient,
                        type='email',
                        reason=reason,
                        source='auto',
                        bounce_count=1,
                        hard_bounce_count=1 if is_hard else 0,
                        soft_bounce_count=1 if is_soft else 0,
                        last_bounce_dsn=dsn,
                        last_bounce_message=log.message[:500] if log.message else None,
                        active=is_active,
                        synced_to_rspamd=False,
                        expires_at=datetime.utcnow() + timedelta(days=settings.suppression_base_expiry_days),
                        correlation_key=None
                    )
                    
                    db.add(new_entry)
                    new_count += 1
            
            db.commit()
            
            if new_count > 0 or updated_count > 0:
                logger.info(f"[SUPPRESSION] Detected {new_count} new, {updated_count} updated suppressions")
                
                # Trigger immediate Rspamd sync so the block takes effect now
                if settings.suppression_rspamd_sync and settings.is_rspamd_configured:
                    try:
                        await sync_suppressions_to_rspamd_job()
                        logger.info("[SUPPRESSION] Triggered immediate Rspamd sync")
                    except Exception as e:
                        logger.warning(f"[SUPPRESSION] Rspamd sync failed (will retry on schedule): {e}")
            
            # Clean up queue items for ALL detected bounce recipients
            # If a message is bouncing/deferred, there's no point keeping it stuck in the queue
            if emails_for_queue_cleanup and mailcow_api.has_rw_key:
                try:
                    queue = await mailcow_api.get_queue()
                    if queue:
                        cleanup_set = set(emails_for_queue_cleanup)
                        items_to_delete = []
                        for item in queue:
                            recipients = item.get('recipients', [])
                            queue_id = item.get('queue_id')
                            if not queue_id or not recipients:
                                continue
                            for rcpt in recipients:
                                rcpt_email = rcpt.split(' ')[0].strip('<>').lower()
                                if rcpt_email in cleanup_set:
                                    items_to_delete.append(queue_id)
                                    break
                        
                        if items_to_delete:
                            await mailcow_api.delete_queue(items_to_delete)
                            logger.info(
                                f"[SUPPRESSION] Cleaned up {len(items_to_delete)} queue item(s) "
                                f"for {len(cleanup_set)} bounced address(es)"
                            )
                except Exception as e:
                    logger.warning(f"[SUPPRESSION] Queue cleanup failed: {e}")
            
            update_job_status('detect_suppressions', 'success')
            
    except Exception as e:
        logger.error(f"[SUPPRESSION] Detection error: {e}", exc_info=True)
        update_job_status('detect_suppressions', 'failed', str(e))


async def sync_suppressions_to_rspamd_job():
    """
    Sync active suppressions to Rspamd's global_rcpt_blacklist.map
    using the shared sync function from the suppressions router.
    """
    if not settings.is_feature_enabled('spam-filter'):
        return
    if not settings.suppression_enabled or not settings.suppression_rspamd_sync:
        return
    if not settings.is_rspamd_configured or not settings.mailcow_api_key_rw:
        return
    
    update_job_status('sync_suppressions', 'running')
    
    try:
        with get_db_context() as db:
            from app.routers.suppressions import sync_suppressions_to_rspamd
            result = await sync_suppressions_to_rspamd(db)
            
            logger.info(f"[SUPPRESSION] Rspamd sync complete: {result.get('synced', 0)} active entries")
            update_job_status('sync_suppressions', 'success')
    except Exception as e:
        logger.error(f"[SUPPRESSION] Sync error: {e}", exc_info=True)
        update_job_status('sync_suppressions', 'failed', str(e))


async def expire_suppressions_job():
    """
    Deactivate suppressions that have passed their expiry date.
    """
    if not settings.is_feature_enabled('spam-filter'):
        return
    if not settings.suppression_enabled:
        return
    
    update_job_status('expire_suppressions', 'running')
    
    try:
        with get_db_context() as db:
            now = datetime.utcnow()
            
            expired = db.query(SpamSuppression).filter(
                SpamSuppression.active == True,
                SpamSuppression.expires_at.isnot(None),
                SpamSuppression.expires_at <= now
            ).all()
            
            if expired:
                for entry in expired:
                    entry.active = False
                    entry.synced_to_rspamd = False  # Will be removed from Rspamd on next sync
                
                db.commit()
                logger.info(f"[SUPPRESSION] Expired {len(expired)} suppressions")
            
            update_job_status('expire_suppressions', 'success')
            
    except Exception as e:
        logger.error(f"[SUPPRESSION] Expiry error: {e}", exc_info=True)
        update_job_status('expire_suppressions', 'failed', str(e))


async def process_quarantine_rules_job():
    """
    Process quarantine auto-rules:
    1. Fetch quarantine items from mailcow
    2. Match against enabled rules (delete rules first)
    3. Execute actions (release/delete) up to max_actions limit
    4. Log each action to QuarantineRuleLog
    5. Clean up old logs based on retention setting
    """
    if not settings.is_feature_enabled('quarantine'):
        return
    from .models import QuarantineRule, QuarantineRuleLog
    from .routers.quarantine_rules import _find_matching_rule
    import re
    
    if not mailcow_api.has_rw_key:
        return
    
    update_job_status('process_quarantine_rules', 'running')
    
    try:
        # Fetch quarantine
        quarantine = await mailcow_api.get_quarantine()
        if not quarantine:
            update_job_status('process_quarantine_rules', 'success')
            return
        
        # Load enabled rules
        with get_db_context() as db:
            rules = db.query(QuarantineRule).filter(
                QuarantineRule.enabled == True
            ).all()
            
            if not rules:
                update_job_status('process_quarantine_rules', 'success')
                return
            
            # Match items against rules
            actions_to_take = []  # [(item, rule)]
            max_actions = settings.quarantine_rules_max_actions
            
            for item in quarantine:
                if len(actions_to_take) >= max_actions:
                    break
                
                sender = (item.get('sender') or '').lower()
                rcpt = (item.get('rcpt') or '').lower()
                subject = item.get('subject') or ''
                sender_domain = sender.split('@')[-1] if '@' in sender else ''
                
                matched_rule = _find_matching_rule(rules, sender, sender_domain, rcpt, subject)
                if matched_rule:
                    actions_to_take.append((item, matched_rule))
            
            if not actions_to_take:
                update_job_status('process_quarantine_rules', 'success')
                return
            
            # Group by action
            release_items = [(item, rule) for item, rule in actions_to_take if rule.action == 'release']
            delete_items = [(item, rule) for item, rule in actions_to_take if rule.action == 'delete']
            
            released_count = 0
            deleted_count = 0
            
            # Execute releases
            if release_items:
                release_ids = [str(item.get('id', '')) for item, _ in release_items]
                try:
                    await mailcow_api.release_quarantine(release_ids)
                    released_count = len(release_ids)
                except Exception as e:
                    logger.error(f"[QUARANTINE RULES] Release failed: {e}")
            
            # Execute deletes
            if delete_items:
                delete_ids = [str(item.get('id', '')) for item, _ in delete_items]
                try:
                    await mailcow_api.delete_quarantine(delete_ids)
                    deleted_count = len(delete_ids)
                except Exception as e:
                    logger.error(f"[QUARANTINE RULES] Delete failed: {e}")
            
            # Log actions and update hit counts
            rule_hit_counts = {}  # rule_id -> count
            for item, rule in actions_to_take:
                log_entry = QuarantineRuleLog(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    action=rule.action,
                    quarantine_id=str(item.get('id', '')),
                    sender=item.get('sender'),
                    recipient=item.get('rcpt'),
                    subject=(item.get('subject') or '')[:500],
                    matched_field=rule.match_type,
                    matched_value=rule.match_value,
                )
                db.add(log_entry)
                rule_hit_counts[rule.id] = rule_hit_counts.get(rule.id, 0) + 1
            
            # Update hit counts
            now = datetime.utcnow()
            for rule_id, count in rule_hit_counts.items():
                rule = db.query(QuarantineRule).filter(QuarantineRule.id == rule_id).first()
                if rule:
                    rule.hit_count = (rule.hit_count or 0) + count
                    rule.last_hit_at = now
            
            # Clean up old logs
            retention_days = settings.quarantine_rules_log_retention_days
            if retention_days > 0:
                cutoff = datetime.utcnow() - timedelta(days=retention_days)
                db.query(QuarantineRuleLog).filter(
                    QuarantineRuleLog.created_at < cutoff
                ).delete(synchronize_session=False)
            
            db.commit()
            
            if released_count > 0 or deleted_count > 0:
                logger.info(
                    f"[QUARANTINE RULES] Processed: {released_count} released, {deleted_count} deleted "
                    f"(from {len(quarantine)} quarantine items, {len(rules)} rules)"
                )
        
        update_job_status('process_quarantine_rules', 'success')
        
    except Exception as e:
        logger.error(f"[QUARANTINE RULES] Processing error: {e}", exc_info=True)
        update_job_status('process_quarantine_rules', 'failed', str(e))


def stop_scheduler():
    """Stop the background scheduler"""
    try:
        if scheduler.running:
            scheduler.shutdown(wait=False)
            logger.info("Scheduler stopped")
    except Exception as e:
        logger.error(f"Error stopping scheduler: {e}")
