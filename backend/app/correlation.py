"""
Message correlation logic - Simplified to rely on Message-ID only

Now that every message has a Message-ID, we can simplify:
1. Rspamd log has Message-ID
2. Find Message-ID in Postfix logs => get Queue-ID
3. Find all Postfix logs with that Queue-ID
4. Create one MessageCorrelation linking everything

BLACKLIST filtering is done at import time (in scheduler.py)
"""
import logging
import re
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import and_

from .models import MessageCorrelation, PostfixLog, RspamdLog
from .config import settings

logger = logging.getLogger(__name__)


def extract_domain(email: str) -> Optional[str]:
    """
    Extract domain from email address
    
    Args:
        email: Email address (e.g., "user@example.com")
    
    Returns:
        Domain name or None if invalid
    """
    if not email or '@' not in email:
        return None
    return email.split('@', 1)[1].lower().strip()


def is_local_domain(domain: Optional[str]) -> bool:
    """
    Check if domain is in local domains list
    
    Args:
        domain: Domain name to check
    
    Returns:
        True if domain is local, False otherwise
    """
    if not domain:
        return False
    local_domains = settings.local_domains_list
    if not local_domains:
        return False
    return domain.lower() in [d.lower() for d in local_domains]


def detect_direction(rspamd_log: Dict[str, Any]) -> str:
    """
    Detect if email is inbound or outbound based on Rspamd log
    
    Note: Internal direction is determined later based on Postfix relay=dovecot
    
    Logic:
    1. Check for MAILCOW_AUTH symbol (definitive outbound indicator)
    2. Check user field (if authenticated = outbound, if unknown = inbound)
    
    Args:
        rspamd_log: Rspamd log entry dictionary
    
    Returns:
        'inbound', 'outbound', or 'unknown'
    """
    # Check for MAILCOW_AUTH symbol - most reliable indicator
    symbols = rspamd_log.get('symbols', {})
    if 'MAILCOW_AUTH' in symbols:
        return 'outbound'
    
    # Check user field - if authenticated, it's outbound
    user = rspamd_log.get('user', 'unknown')
    if user != 'unknown' and user:
        return 'outbound'
    
    # If user is unknown, it's inbound (external sender)
    if user == 'unknown':
        return 'inbound'
    
    return 'unknown'


def is_blacklisted(email: str) -> bool:
    """
    Check if an email address is in the blacklist
    
    Args:
        email: Email address to check
    
    Returns:
        True if blacklisted, False otherwise
    """
    if not email:
        return False
    
    email_lower = email.lower().strip()
    blacklist = settings.blacklist_emails_list
    
    return email_lower in blacklist


def parse_postfix_message(message: str) -> Dict[str, Any]:
    """
    Parse Postfix log message to extract structured data
    
    Args:
        message: Postfix log message string
    
    Returns:
        Dictionary with parsed fields
    """
    result = {}
    
    # Extract queue ID (at the start of message)
    queue_match = re.match(r'^([A-F0-9]+):', message)
    if queue_match:
        result['queue_id'] = queue_match.group(1)
    
    # Extract message-id - Method 1: Standalone line
    mid_match = re.search(r'message-id=<([^>]+)>', message, re.IGNORECASE)
    if mid_match:
        result['message_id'] = mid_match.group(1)
    
    # Extract message-id - Method 2: Inside status message (alternative location)
    # Example: status=sent (250 2.6.0 <message-id@domain.com> ...)
    if not result.get('message_id'):
        status_mid_match = re.search(r'status=\w+\s*\([^<]*<([^>@]+@[^>]+)>', message)
        if status_mid_match:
            # Verify it looks like a message-id (has @ symbol)
            potential_mid = status_mid_match.group(1)
            # Additional check: message-ids often have special chars, not just email format
            if '@' in potential_mid:
                result['message_id'] = potential_mid
    
    # Extract from= (sender)
    from_match = re.search(r'from=<([^>]*)>', message)
    if from_match:
        result['sender'] = from_match.group(1) if from_match.group(1) else None
    
    # Extract to= (recipient)
    to_match = re.search(r'to=<([^>]*)>', message)
    if to_match:
        result['recipient'] = to_match.group(1) if to_match.group(1) else None
    
    # Extract relay
    relay_match = re.search(r'relay=([^,\s]+)', message)
    if relay_match:
        result['relay'] = relay_match.group(1)
    
    # Extract delay
    delay_match = re.search(r'delay=([\d.]+)', message)
    if delay_match:
        result['delay'] = float(delay_match.group(1))
    
    # Extract DSN
    dsn_match = re.search(r'dsn=([\d.]+)', message)
    if dsn_match:
        result['dsn'] = dsn_match.group(1)
    
    # Extract status
    status_match = re.search(r'status=(\w+)', message)
    if status_match:
        result['status'] = status_match.group(1)
    
    return result


def correlate_rspamd_log(db: Session, rspamd_log: RspamdLog) -> Optional[MessageCorrelation]:
    """
    Correlate Rspamd log with Postfix logs using Message-ID
    
    NEW SIMPLIFIED LOGIC:
    1. Get Message-ID from Rspamd
    2. Find Postfix log(s) with same Message-ID
    3. Get Queue-ID from Postfix
    4. Find ALL Postfix logs with that Queue-ID
    5. Create/update correlation linking everything
    
    Args:
        db: Database session
        rspamd_log: RspamdLog object
    
    Returns:
        MessageCorrelation object or None
    """
    # Skip if no message_id
    if not rspamd_log.message_id or rspamd_log.message_id == 'undef':
        logger.debug("Rspamd log has no message_id, skipping correlation")
        return None
    
    message_id = rspamd_log.message_id.strip()
    
    # Step 1: Find Postfix log(s) with this Message-ID
    postfix_logs_with_msgid = db.query(PostfixLog).filter(
        PostfixLog.message_id == message_id
    ).all()
    
    if not postfix_logs_with_msgid:
        logger.debug(f"No Postfix logs found with Message-ID: {message_id[:50]}")
        # Create correlation without Postfix data (message not yet delivered)
        return create_correlation_from_rspamd(db, rspamd_log)
    
    # Step 2: Get Queue-ID from Postfix logs
    queue_id = None
    for plog in postfix_logs_with_msgid:
        if plog.queue_id:
            queue_id = plog.queue_id
            break
    
    if not queue_id:
        logger.warning(f"Postfix logs found but no Queue-ID for Message-ID: {message_id[:50]}")
        return create_correlation_from_rspamd(db, rspamd_log)
    
    logger.debug(f"Found Queue-ID {queue_id} for Message-ID {message_id[:50]}")
    
    # Step 3: Find ALL Postfix logs with this Queue-ID
    all_postfix_logs = db.query(PostfixLog).filter(
        PostfixLog.queue_id == queue_id
    ).all()
    
    logger.debug(f"Found {len(all_postfix_logs)} Postfix logs with Queue-ID {queue_id}")
    
    # Step 4: Check if correlation already exists
    existing_correlation = db.query(MessageCorrelation).filter(
        MessageCorrelation.message_id == message_id
    ).first()
    
    if existing_correlation:
        # Update existing correlation
        logger.debug(f"Updating existing correlation for Message-ID {message_id[:50]}")
        update_correlation_with_rspamd(db, existing_correlation, rspamd_log)
        update_correlation_with_postfix_logs(db, existing_correlation, all_postfix_logs)
        return existing_correlation
    
    # Step 5: Create new correlation
    logger.info(f"Creating new correlation for Message-ID {message_id[:50]} (Queue-ID: {queue_id})")
    correlation = create_correlation_with_all_data(
        db, 
        rspamd_log, 
        all_postfix_logs, 
        message_id, 
        queue_id
    )
    
    # Update all Postfix logs with correlation key
    for plog in all_postfix_logs:
        plog.correlation_key = correlation.correlation_key
    
    db.commit()
    return correlation


def correlate_postfix_log(db: Session, postfix_log: PostfixLog) -> Optional[MessageCorrelation]:
    """
    Correlate Postfix log with existing correlation (if exists)
    
    NEW SIMPLIFIED LOGIC:
    1. If Postfix has Message-ID => find correlation by Message-ID
    2. If Postfix has Queue-ID => find correlation by Queue-ID
    3. Update correlation with this Postfix log
    
    Args:
        db: Database session
        postfix_log: PostfixLog object
    
    Returns:
        MessageCorrelation object or None
    """
    correlation = None
    
    # Method 1: Find by Message-ID (most reliable)
    if postfix_log.message_id:
        correlation = db.query(MessageCorrelation).filter(
            MessageCorrelation.message_id == postfix_log.message_id
        ).first()
        
        if correlation:
            logger.debug(f"Found correlation by Message-ID: {postfix_log.message_id[:50]}")
    
    # Method 2: Find by Queue-ID (fallback)
    if not correlation and postfix_log.queue_id:
        correlation = db.query(MessageCorrelation).filter(
            MessageCorrelation.queue_id == postfix_log.queue_id
        ).first()
        
        if correlation:
            logger.debug(f"Found correlation by Queue-ID: {postfix_log.queue_id}")
    
    # Update correlation if found
    if correlation:
        update_correlation_with_postfix_log(db, correlation, postfix_log)
        postfix_log.correlation_key = correlation.correlation_key
        db.commit()
        return correlation
    
    # No correlation found yet (Rspamd may not have been processed)
    logger.debug(f"No correlation found for Postfix log (Queue-ID: {postfix_log.queue_id}, Message-ID: {postfix_log.message_id})")
    return None


def create_correlation_from_rspamd(
    db: Session, 
    rspamd_log: RspamdLog
) -> MessageCorrelation:
    """
    Create a new correlation from Rspamd log only
    (used when Postfix logs are not yet available)
    
    Args:
        db: Database session
        rspamd_log: RspamdLog object
    
    Returns:
        MessageCorrelation object (marked as incomplete)
    """
    # Generate correlation key from message_id
    correlation_key = hashlib.sha256(f"msgid:{rspamd_log.message_id}".encode()).hexdigest()
    
    # Get first recipient
    recipients = rspamd_log.recipients_smtp if rspamd_log.recipients_smtp else []
    first_recipient = recipients[0] if recipients else None
    
    correlation = MessageCorrelation(
        correlation_key=correlation_key,
        message_id=rspamd_log.message_id,
        queue_id=rspamd_log.queue_id,  # May be None
        sender=rspamd_log.sender_smtp,
        recipient=first_recipient,
        subject=rspamd_log.subject,
        direction=rspamd_log.direction,
        rspamd_log_id=rspamd_log.id,
        first_seen=rspamd_log.time,
        last_seen=datetime.utcnow(),
        is_complete=False  # Incomplete - waiting for Postfix logs
    )
    
    # Set initial status based on Rspamd action
    if rspamd_log.action == 'reject':
        correlation.final_status = 'rejected'
    elif rspamd_log.is_spam:
        correlation.final_status = 'spam'
    
    db.add(correlation)
    db.commit()
    
    logger.debug(f"Created incomplete correlation from Rspamd (waiting for Postfix): {correlation_key[:16]}")
    return correlation


def create_correlation_with_all_data(
    db: Session,
    rspamd_log: RspamdLog,
    postfix_logs: List[PostfixLog],
    message_id: str,
    queue_id: str
) -> MessageCorrelation:
    """
    Create a new correlation with all available data
    
    Args:
        db: Database session
        rspamd_log: RspamdLog object
        postfix_logs: List of PostfixLog objects
        message_id: Email Message-ID
        queue_id: Postfix Queue-ID
    
    Returns:
        MessageCorrelation object
    """
    # Generate correlation key from message_id
    correlation_key = hashlib.sha256(f"msgid:{message_id}".encode()).hexdigest()
    
    # Get first recipient from Rspamd
    recipients = rspamd_log.recipients_smtp if rspamd_log.recipients_smtp else []
    first_recipient = recipients[0] if recipients else None
    
    # Get postfix log IDs
    postfix_log_ids = [log.id for log in postfix_logs if log.id]
    
    # Determine final status from Postfix logs
    final_status = None
    for plog in postfix_logs:
        if plog.status:
            if plog.status in ['bounced', 'rejected']:
                final_status = plog.status
                break  # Priority status found
            elif plog.status == 'deferred' and not final_status:
                final_status = plog.status
            elif plog.status == 'sent' and not final_status:
                final_status = 'delivered'
    
    # If no status from Postfix, use Rspamd
    if not final_status:
        if rspamd_log.action == 'reject':
            final_status = 'rejected'
        elif rspamd_log.is_spam:
            final_status = 'spam'
    
    # Get earliest timestamp
    all_times = [rspamd_log.time] + [log.time for log in postfix_logs]
    first_seen = min(all_times)
    
    # Check if email was delivered locally (relay=dovecot + both sender and recipient are local domains)
    # This is the definitive way to determine if email is internal
    direction = rspamd_log.direction
    
    # Check if sender and recipient are both local domains
    sender_domain = extract_domain(rspamd_log.sender_smtp)
    recipients = rspamd_log.recipients_smtp if rspamd_log.recipients_smtp else []
    
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
        for plog in postfix_logs:
            if plog.relay and 'dovecot' in plog.relay.lower():
                direction = 'internal'
                # Also update Rspamd log
                rspamd_log.direction = 'internal'
                break
    
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
        postfix_log_ids=postfix_log_ids,
        first_seen=first_seen,
        last_seen=datetime.utcnow(),
        is_complete=True  # Has Queue-ID and Postfix logs
    )
    
    db.add(correlation)
    db.commit()
    
    logger.info(f"Created full correlation: {correlation_key[:16]} (Queue: {queue_id}, {len(postfix_logs)} Postfix logs)")
    return correlation


def update_correlation_with_rspamd(
    db: Session,
    correlation: MessageCorrelation,
    rspamd_log: RspamdLog
):
    """
    Update correlation with Rspamd log information
    
    Args:
        db: Database session
        correlation: MessageCorrelation object
        rspamd_log: RspamdLog object
    """
    correlation.rspamd_log_id = rspamd_log.id
    
    if not correlation.sender and rspamd_log.sender_smtp:
        correlation.sender = rspamd_log.sender_smtp
    
    if not correlation.recipient and rspamd_log.recipients_smtp:
        recipients = rspamd_log.recipients_smtp
        if recipients and isinstance(recipients, list):
            correlation.recipient = recipients[0]
    
    if not correlation.subject and rspamd_log.subject:
        correlation.subject = rspamd_log.subject
    
    if not correlation.direction:
        correlation.direction = rspamd_log.direction
    
    # Update status if Rspamd has stronger verdict
    if rspamd_log.action == 'reject':
        correlation.final_status = 'rejected'
    elif rspamd_log.is_spam and not correlation.final_status:
        correlation.final_status = 'spam'
    
    correlation.last_seen = datetime.utcnow()
    db.commit()


def update_correlation_with_postfix_log(
    db: Session,
    correlation: MessageCorrelation,
    postfix_log: PostfixLog
):
    """
    Update correlation with a single Postfix log
    
    IMPORTANT: When we get a queue_id for the first time, we must also
    find and link ALL existing PostfixLogs with that queue_id!
    This handles the case where logs arrive out of order.
    
    Args:
        db: Database session
        correlation: MessageCorrelation object
        postfix_log: PostfixLog object
    """
    # Check if this is the first time we're getting a queue_id
    first_queue_id = not correlation.queue_id and postfix_log.queue_id
    
    # Add to postfix log IDs list
    current_ids = list(correlation.postfix_log_ids or [])
    if postfix_log.id and postfix_log.id not in current_ids:
        current_ids.append(postfix_log.id)
        correlation.postfix_log_ids = current_ids
    
    # Update basic info if not set
    if not correlation.sender and postfix_log.sender:
        correlation.sender = postfix_log.sender
    
    if not correlation.recipient and postfix_log.recipient:
        correlation.recipient = postfix_log.recipient
    
    if not correlation.queue_id and postfix_log.queue_id:
        correlation.queue_id = postfix_log.queue_id
    
    if not correlation.message_id and postfix_log.message_id:
        correlation.message_id = postfix_log.message_id
    
    # CRITICAL FIX: If we just got a queue_id, find ALL existing postfix logs
    # with this queue_id and link them to this correlation
    if first_queue_id and postfix_log.queue_id:
        logger.info(f"First queue_id {postfix_log.queue_id} for correlation - searching for related logs")
        
        # Find all PostfixLogs with this queue_id that aren't already linked
        related_logs = db.query(PostfixLog).filter(
            PostfixLog.queue_id == postfix_log.queue_id,
            PostfixLog.id != postfix_log.id  # Exclude current log
        ).all()
        
        if related_logs:
            logger.info(f"Found {len(related_logs)} additional postfix logs with queue_id {postfix_log.queue_id}")
            
            for related_log in related_logs:
                # Add to IDs list
                if related_log.id and related_log.id not in current_ids:
                    current_ids.append(related_log.id)
                
                # Update correlation key in the related log
                related_log.correlation_key = correlation.correlation_key
                
                # Extract info from related logs
                if not correlation.sender and related_log.sender:
                    correlation.sender = related_log.sender
                if not correlation.recipient and related_log.recipient:
                    correlation.recipient = related_log.recipient
                
                # Update status from related logs
                if related_log.status:
                    if related_log.status in ['bounced', 'rejected']:
                        correlation.final_status = related_log.status
                    elif related_log.status == 'deferred' and correlation.final_status not in ['bounced', 'rejected']:
                        correlation.final_status = related_log.status
                    elif related_log.status == 'sent' and not correlation.final_status:
                        correlation.final_status = 'delivered'
            
            correlation.postfix_log_ids = current_ids
    
    # Check if email was delivered locally (relay=dovecot + both sender and recipient are local domains)
    # This is the definitive way to determine if email is internal
    if postfix_log.relay and 'dovecot' in postfix_log.relay.lower():
        # Check if sender and recipient are both local domains
        sender_domain = extract_domain(correlation.sender or postfix_log.sender)
        recipient_domain = extract_domain(correlation.recipient or postfix_log.recipient)
        
        sender_is_local = sender_domain and is_local_domain(sender_domain)
        recipient_is_local = recipient_domain and is_local_domain(recipient_domain)
        
        # Only mark as internal if both sender and recipient are local domains
        if sender_is_local and recipient_is_local:
            correlation.direction = 'internal'
            # Also update Rspamd log if it exists
            if correlation.rspamd_log_id:
                rspamd_log = db.query(RspamdLog).filter(
                    RspamdLog.id == correlation.rspamd_log_id
                ).first()
                if rspamd_log:
                    rspamd_log.direction = 'internal'
    
    # Update final status based on current Postfix log status
    # Priority: bounced > rejected > deferred > sent
    if postfix_log.status:
        if postfix_log.status in ['bounced', 'rejected']:
            correlation.final_status = postfix_log.status
        elif postfix_log.status == 'deferred' and correlation.final_status not in ['bounced', 'rejected']:
            correlation.final_status = postfix_log.status
        elif postfix_log.status == 'sent' and not correlation.final_status:
            correlation.final_status = 'delivered'
    
    # Mark as complete if we now have Queue-ID and Postfix logs
    if correlation.queue_id and correlation.postfix_log_ids:
        correlation.is_complete = True
    
    correlation.last_seen = datetime.utcnow()
    db.commit()


def update_correlation_with_postfix_logs(
    db: Session,
    correlation: MessageCorrelation,
    postfix_logs: List[PostfixLog]
):
    """
    Update correlation with multiple Postfix logs
    
    Args:
        db: Database session
        correlation: MessageCorrelation object
        postfix_logs: List of PostfixLog objects
    """
    # Collect all IDs (use list() to ensure mutable copy)
    current_ids = list(correlation.postfix_log_ids or [])
    for plog in postfix_logs:
        if plog.id and plog.id not in current_ids:
            current_ids.append(plog.id)
    
    correlation.postfix_log_ids = current_ids
    
    # Update fields from logs
    for plog in postfix_logs:
        if not correlation.sender and plog.sender:
            correlation.sender = plog.sender
        
        if not correlation.recipient and plog.recipient:
            correlation.recipient = plog.recipient
        
        if not correlation.queue_id and plog.queue_id:
            correlation.queue_id = plog.queue_id
        
        if not correlation.message_id and plog.message_id:
            correlation.message_id = plog.message_id
        
        # Update correlation key in Postfix log
        plog.correlation_key = correlation.correlation_key
    
    # Check if email was delivered locally (relay=dovecot + both sender and recipient are local domains)
    # This is the definitive way to determine if email is internal
    is_internal = False
    
    # Check if sender and recipient are both local domains
    sender_domain = extract_domain(correlation.sender)
    recipient_domain = extract_domain(correlation.recipient)
    
    sender_is_local = sender_domain and is_local_domain(sender_domain)
    recipient_is_local = recipient_domain and is_local_domain(recipient_domain)
    
    # Only mark as internal if: relay=dovecot AND sender is local AND recipient is local
    if sender_is_local and recipient_is_local:
        for plog in postfix_logs:
            if plog.relay and 'dovecot' in plog.relay.lower():
                is_internal = True
                break
    
    # Update direction to internal if all conditions met
    if is_internal:
        correlation.direction = 'internal'
        # Also update Rspamd log if it exists
        if correlation.rspamd_log_id:
            rspamd_log = db.query(RspamdLog).filter(
                RspamdLog.id == correlation.rspamd_log_id
            ).first()
            if rspamd_log:
                rspamd_log.direction = 'internal'
    
    # Determine final status from all logs
    final_status = None
    for plog in postfix_logs:
        if plog.status:
            if plog.status in ['bounced', 'rejected']:
                final_status = plog.status
                break
            elif plog.status == 'deferred' and not final_status:
                final_status = plog.status
            elif plog.status == 'sent' and not final_status:
                final_status = 'delivered'
    
    if final_status:
        correlation.final_status = final_status
    
    # Mark as complete if we have Queue-ID and Postfix logs
    if correlation.queue_id and correlation.postfix_log_ids:
        correlation.is_complete = True
    
    correlation.last_seen = datetime.utcnow()
    db.commit()


def complete_incomplete_correlations(db: Session) -> int:
    """
    Background job to complete correlations that don't have Postfix logs yet
    
    This handles the timing issue where Rspamd logs arrive before Postfix logs:
    1. Find correlations with Message-ID but no Queue-ID (incomplete)
    2. Search for Postfix logs with matching Message-ID
    3. If found, get Queue-ID and find all related Postfix logs
    4. Update correlation and mark as complete
    
    Returns:
        Number of correlations completed
    """
    logger.info("Starting background job to complete incomplete correlations...")
    
    try:
        # Find incomplete correlations (have Message-ID but missing Queue-ID or no Postfix logs)
        incomplete_correlations = db.query(MessageCorrelation).filter(
            MessageCorrelation.is_complete == False,
            MessageCorrelation.message_id.isnot(None),
            MessageCorrelation.message_id != ''
        ).limit(100).all()  # Process 100 at a time to avoid overload
        
        if not incomplete_correlations:
            logger.debug("No incomplete correlations found")
            return 0
        
        logger.info(f"Found {len(incomplete_correlations)} incomplete correlations to process")
        
        completed_count = 0
        
        for correlation in incomplete_correlations:
            try:
                message_id = correlation.message_id
                
                # Find Postfix logs with this Message-ID
                postfix_logs_with_msgid = db.query(PostfixLog).filter(
                    PostfixLog.message_id == message_id
                ).all()
                
                if not postfix_logs_with_msgid:
                    logger.debug(f"No Postfix logs yet for Message-ID: {message_id[:50]}")
                    continue
                
                # Get Queue-ID from Postfix logs
                queue_id = None
                for plog in postfix_logs_with_msgid:
                    if plog.queue_id:
                        queue_id = plog.queue_id
                        break
                
                if not queue_id:
                    logger.debug(f"Postfix logs found but no Queue-ID for Message-ID: {message_id[:50]}")
                    continue
                
                logger.info(f"Completing correlation: Message-ID {message_id[:50]} => Queue-ID {queue_id}")
                
                # Find ALL Postfix logs with this Queue-ID
                all_postfix_logs = db.query(PostfixLog).filter(
                    PostfixLog.queue_id == queue_id
                ).all()
                
                # Update correlation with all Postfix data
                update_correlation_with_postfix_logs(db, correlation, all_postfix_logs)
                
                # Update correlation fields
                if not correlation.queue_id:
                    correlation.queue_id = queue_id
                
                # Mark as complete
                correlation.is_complete = True
                correlation.last_seen = datetime.utcnow()
                
                db.commit()
                completed_count += 1
                
                logger.info(f"[OK] Completed correlation for Message-ID {message_id[:50]} "
                           f"(Queue: {queue_id}, {len(all_postfix_logs)} Postfix logs)")
                
            except Exception as e:
                logger.error(f"Error completing correlation {correlation.id}: {e}")
                db.rollback()
                continue
        
        logger.info(f"Background completion job finished: {completed_count} correlations completed")
        return completed_count
        
    except Exception as e:
        logger.error(f"Error in complete_incomplete_correlations: {e}")
        return 0