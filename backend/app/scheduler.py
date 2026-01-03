"""
Background scheduler
"""
import logging
import asyncio
import hashlib
import re
from datetime import datetime, timedelta, timezone
from typing import Set, Optional, List, Dict, Any
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_

from .config import settings
from .database import get_db_context
from .mailcow_api import mailcow_api
from .models import PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation
from .correlation import detect_direction, parse_postfix_message

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()

seen_postfix: Set[str] = set()
seen_rspamd: Set[str] = set()
seen_netfilter: Set[str] = set()

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


async def fetch_and_store_postfix():
    """Fetch Postfix logs from API and store in DB"""
    last_fetch_run_time['postfix'] = datetime.now(timezone.utc)
    
    try:
        logs = await mailcow_api.get_postfix_logs(count=settings.fetch_count_postfix)
        
        if not logs:
            return
        
        with get_db_context() as db:
            new_count = 0
            skipped_blacklist = 0
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
            
            # Delete existing logs with blacklisted queue IDs
            if blacklisted_queue_ids:
                deleted_count = db.query(PostfixLog).filter(
                    PostfixLog.queue_id.in_(blacklisted_queue_ids)
                ).delete(synchronize_session=False)
                
                # Also delete correlations for these queue IDs
                db.query(MessageCorrelation).filter(
                    MessageCorrelation.queue_id.in_(blacklisted_queue_ids)
                ).delete(synchronize_session=False)
                
                if deleted_count > 0:
                    logger.info(f"[BLACKLIST] Deleted {deleted_count} Postfix logs for {len(blacklisted_queue_ids)} blacklisted queue IDs")
                
                db.commit()
            
            for log_entry in logs:
                try:
                    time_str = str(log_entry.get('time', ''))
                    message = log_entry.get('message', '')
                    unique_id = f"{time_str}:{message[:100]}"
                    
                    if unique_id in seen_postfix:
                        continue
                    
                    # Parse message for fields
                    parsed = parse_postfix_message(message)
                    queue_id = parsed.get('queue_id')
                    
                    # Skip if queue ID is blacklisted
                    if queue_id and queue_id in blacklisted_queue_ids:
                        skipped_blacklist += 1
                        seen_postfix.add(unique_id)
                        continue
                    
                    # Parse timestamp with timezone
                    timestamp = datetime.fromtimestamp(
                        int(log_entry.get('time', 0)),
                        tz=timezone.utc
                    )
                    
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
                    new_count += 1
                    
                except Exception as e:
                    logger.error(f"Error processing Postfix log: {e}")
                    continue
            
            db.commit()
            
            if new_count > 0:
                msg = f"[OK] Imported {new_count} Postfix logs"
                if skipped_blacklist > 0:
                    msg += f" (skipped {skipped_blacklist} blacklisted)"
                logger.info(msg)
            
            if len(seen_postfix) > 10000:
                seen_postfix.clear()
    
    except Exception as e:
        logger.error(f"[ERROR] Postfix fetch error: {e}")


async def fetch_and_store_rspamd():
    """Fetch Rspamd logs from API and store in DB"""
    last_fetch_run_time['rspamd'] = datetime.now(timezone.utc)
    
    try:
        logs = await mailcow_api.get_rspamd_logs(count=settings.fetch_count_rspamd)
        
        if not logs:
            return
        
        with get_db_context() as db:
            new_count = 0
            skipped_blacklist = 0
            blacklisted_message_ids: Set[str] = set()
            
            for log_entry in logs:
                try:
                    unix_time = log_entry.get('unix_time', 0)
                    message_id = log_entry.get('message-id', '')
                    if message_id == 'undef' or not message_id:
                        message_id = None
                    sender = log_entry.get('sender_smtp')
                    recipients = log_entry.get('rcpt_smtp', [])
                    
                    unique_id = f"{unix_time}:{message_id if message_id else 'no-id'}"
                    
                    if unique_id in seen_rspamd:
                        continue
                    
                    if is_blacklisted(sender):
                        skipped_blacklist += 1
                        seen_rspamd.add(unique_id)
                        if message_id:
                            blacklisted_message_ids.add(message_id)
                        continue
                    
                    if recipients and any(is_blacklisted(r) for r in recipients):
                        skipped_blacklist += 1
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
                        is_spam=(log_entry.get('action') in ['reject', 'add header', 'rewrite subject']),
                        has_auth=('MAILCOW_AUTH' in log_entry.get('symbols', {})),
                        direction=direction,
                        ip=log_entry.get('ip'),
                        user=log_entry.get('user'),
                        size=log_entry.get('size'),
                        raw_data=log_entry
                    )
                    
                    db.add(rspamd_log)
                    seen_rspamd.add(unique_id)
                    new_count += 1
                    
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
            
            if new_count > 0:
                msg = f"[OK] Imported {new_count} Rspamd logs"
                if skipped_blacklist > 0:
                    msg += f" (skipped {skipped_blacklist} blacklisted)"
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
        logger.debug("[FETCH] Starting fetch_all_logs")
        results = await asyncio.gather(
            fetch_and_store_postfix(),
            fetch_and_store_rspamd(),
            fetch_and_store_netfilter(),
            return_exceptions=True
        )
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                log_type = ["Postfix", "Rspamd", "Netfilter"][i]
                logger.error(f"[ERROR] {log_type} fetch failed: {result}", exc_info=result)
        
        logger.debug("[FETCH] Completed fetch_all_logs")
    except Exception as e:
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
    
    except Exception as e:
        logger.error(f"[ERROR] Complete correlations error: {e}")


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
                return
            
            expired_count = 0
            for corr in expired_correlations:
                corr.is_complete = True  # Mark as complete so we stop trying
                corr.final_status = "expired"  # Set status to expired
                expired_count += 1
            
            db.commit()
            
            if expired_count > 0:
                logger.info(f"[EXPIRED] Marked {expired_count} correlations as expired (older than {settings.max_correlation_age_minutes}min)")
    
    except Exception as e:
        logger.error(f"[ERROR] Expire correlations error: {e}")


async def update_final_status_for_correlations():
    """
    Background job to update final_status for correlations that don't have one yet.
    
    This handles the case where Postfix logs (especially status=sent) arrive after
    the initial correlation was created. The job:
    1. Finds correlations without a definitive final_status
    2. Only checks correlations within Max Correlation Age
    3. Looks for new Postfix logs that may have arrived
    4. Updates final_status if a better status is found
    
    This runs independently from correlation creation to ensure we catch
    late-arriving Postfix logs.
    """
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
            ).limit(100).all()
            
            if not correlations_to_check:
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
                    # We check all logs to find the best status
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
                    
                    # Update if we found a better status
                    if new_final_status and new_final_status != correlation.final_status:
                        old_status = correlation.final_status
                        correlation.final_status = new_final_status
                        correlation.last_seen = datetime.now(timezone.utc)
                        updated_count += 1
                        logger.debug(f"Updated final_status for correlation {correlation.id} ({correlation.message_id[:40] if correlation.message_id else 'no-id'}...): {old_status} -> {new_final_status}")
                
                except Exception as e:
                    logger.warning(f"Failed to update final_status for correlation {correlation.id}: {e}")
                    continue
            
            db.commit()
            
            if updated_count > 0:
                logger.info(f"[STATUS] Updated final_status for {updated_count} correlations")
    
    except Exception as e:
        logger.error(f"[ERROR] Update final status error: {e}")


# =============================================================================
# CLEANUP
# =============================================================================

async def cleanup_old_logs():
    """Delete logs older than retention period"""
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
    
    except Exception as e:
        logger.error(f"[ERROR] Cleanup error: {e}")


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


# =============================================================================
# SCHEDULER SETUP
# =============================================================================

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
            name='Fetch Mailcow Logs',
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
        
        scheduler.start()
        
        logger.info("[OK] Scheduler started")
        logger.info(f"   [INFO] Import: every {settings.fetch_interval}s")
        logger.info(f"   [LINK] Correlation: every 30s")
        logger.info(f"   [COMPLETE] Incomplete correlations: every {settings.correlation_check_interval}s")
        logger.info(f"   [STATUS] Update final status: every {settings.correlation_check_interval}s (max age: {settings.max_correlation_age_minutes}min)")
        logger.info(f"   [EXPIRE] Old correlations: every 60s (expire after {settings.max_correlation_age_minutes}min)")
        
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


def stop_scheduler():
    """Stop the background scheduler"""
    try:
        if scheduler.running:
            scheduler.shutdown(wait=False)
            logger.info("Scheduler stopped")
    except Exception as e:
        logger.error(f"Error stopping scheduler: {e}")