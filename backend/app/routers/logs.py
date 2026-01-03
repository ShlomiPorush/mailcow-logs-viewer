"""
API endpoints for log retrieval and search
"""
import logging
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc, func
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from ..database import get_db
from ..models import PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation
from ..mailcow_api import mailcow_api
from ..config import settings

logger = logging.getLogger(__name__)

router = APIRouter()


def format_datetime_utc(dt: Optional[datetime]) -> Optional[str]:
    """
    Format datetime for API response with proper UTC timezone
    Always returns ISO format with 'Z' suffix so browser knows it's UTC
    """
    if dt is None:
        return None
    
    # If naive (no timezone), assume UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    # Convert to UTC if not already
    dt_utc = dt.astimezone(timezone.utc)
    
    # Format as ISO string with 'Z' suffix for UTC
    return dt_utc.replace(microsecond=0).isoformat().replace('+00:00', 'Z')


@router.get("/logs/postfix/by-queue/{queue_id}")
async def get_postfix_logs_by_queue(
    queue_id: str,
    db: Session = Depends(get_db)
):
    """
    Get all Postfix logs for a specific Queue ID with linked Rspamd data
    """
    try:
        logs = db.query(PostfixLog).filter(
            PostfixLog.queue_id == queue_id
        ).order_by(PostfixLog.time).all()
        
        if not logs:
            raise HTTPException(status_code=404, detail="No logs found for this Queue ID")
        
        # Get correlation key from first log
        correlation_key = logs[0].correlation_key if logs else None
        
        # Try to find Rspamd data via correlation
        rspamd_data = None
        if correlation_key:
            correlation = db.query(MessageCorrelation).filter(
                MessageCorrelation.correlation_key == correlation_key
            ).first()
            
            if correlation and correlation.rspamd_log_id:
                rspamd_log = db.query(RspamdLog).filter(
                    RspamdLog.id == correlation.rspamd_log_id
                ).first()
                
                if rspamd_log:
                    rspamd_data = {
                        "score": rspamd_log.score,
                        "required_score": rspamd_log.required_score,
                        "action": rspamd_log.action,
                        "symbols": rspamd_log.symbols,
                        "is_spam": rspamd_log.is_spam,
                        "direction": rspamd_log.direction,
                        "subject": rspamd_log.subject
                    }
        
        return {
            "queue_id": queue_id,
            "correlation_key": correlation_key,
            "rspamd": rspamd_data,
            "logs": [
                {
                    "id": log.id,
                    "time": log.time.isoformat(),
                    "program": log.program,
                    "priority": log.priority,
                    "message": log.message,
                    "queue_id": log.queue_id,
                    "message_id": log.message_id,
                    "sender": log.sender,
                    "recipient": log.recipient,
                    "status": log.status,
                    "relay": log.relay,
                    "delay": log.delay,
                    "dsn": log.dsn
                }
                for log in logs
            ]
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching Postfix logs by queue: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/logs/postfix")
async def get_postfix_logs(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=500, description="Items per page"),
    search: Optional[str] = Query(None, description="Search query"),
    sender: Optional[str] = Query(None, description="Filter by sender"),
    recipient: Optional[str] = Query(None, description="Filter by recipient"),
    status: Optional[str] = Query(None, description="Filter by status"),
    queue_id: Optional[str] = Query(None, description="Filter by queue ID"),
    start_date: Optional[datetime] = Query(None, description="Start date"),
    end_date: Optional[datetime] = Query(None, description="End date"),
    db: Session = Depends(get_db)
):
    """
    Get Postfix logs with filtering and pagination - grouped by Queue ID
    Only shows logs that have a Queue ID (one row per queue with aggregated data)
    """
    try:
        from sqlalchemy.sql import case
        
        # First, filter out logs without queue_id
        base_query = db.query(PostfixLog).filter(
            and_(
                PostfixLog.queue_id.isnot(None),
                PostfixLog.queue_id != ''
            )
        )
        
        # Apply filters to base query
        if search:
            search_term = f"%{search}%"
            base_query = base_query.filter(
                or_(
                    PostfixLog.message.ilike(search_term),
                    PostfixLog.sender.ilike(search_term),
                    PostfixLog.recipient.ilike(search_term),
                    PostfixLog.queue_id.ilike(search_term)
                )
            )
        
        if sender:
            base_query = base_query.filter(PostfixLog.sender.ilike(f"%{sender}%"))
        
        if recipient:
            base_query = base_query.filter(PostfixLog.recipient.ilike(f"%{recipient}%"))
        
        if status:
            base_query = base_query.filter(PostfixLog.status == status)
        
        if queue_id:
            base_query = base_query.filter(PostfixLog.queue_id == queue_id)
        
        if start_date:
            base_query = base_query.filter(PostfixLog.time >= start_date)
        
        if end_date:
            base_query = base_query.filter(PostfixLog.time <= end_date)
        
        # Get all queue IDs that match filters
        queue_ids = [row[0] for row in base_query.with_entities(PostfixLog.queue_id).distinct().all()]
        
        # For each queue_id, get aggregated data
        results = []
        for qid in queue_ids:
            # Get all logs for this queue_id
            queue_logs = db.query(PostfixLog).filter(
                PostfixLog.queue_id == qid
            ).order_by(PostfixLog.time).all()
            
            if not queue_logs:
                continue
            
            # Aggregate data from all logs
            aggregated = {
                "id": queue_logs[0].id,
                "time": queue_logs[-1].time,  # Use latest time
                "program": queue_logs[0].program,
                "priority": queue_logs[0].priority,
                "message": queue_logs[-1].message,  # Latest message
                "queue_id": qid,
                "message_id": None,
                "sender": None,
                "recipient": None,
                "status": None,
                "relay": None,
                "delay": None,
                "dsn": None,
                "correlation_key": queue_logs[0].correlation_key
            }
            
            # Extract best values from all logs
            for log in queue_logs:
                if log.message_id and not aggregated["message_id"]:
                    aggregated["message_id"] = log.message_id
                if log.sender and not aggregated["sender"]:
                    aggregated["sender"] = log.sender
                if log.recipient and not aggregated["recipient"]:
                    aggregated["recipient"] = log.recipient
                if log.relay and not aggregated["relay"]:
                    aggregated["relay"] = log.relay
                if log.delay is not None:
                    aggregated["delay"] = log.delay
                if log.dsn:
                    aggregated["dsn"] = log.dsn
                # Always update status to get the latest one
                if log.status:
                    aggregated["status"] = log.status
            
            results.append(aggregated)
        
        # Sort by time descending
        results.sort(key=lambda x: x["time"], reverse=True)
        
        # Apply pagination
        total = len(results)
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        paginated_results = results[start_idx:end_idx]
        
        # Convert time to ISO format
        for result in paginated_results:
            result["time"] = result["time"].isoformat()
        
        return {
            "total": total,
            "page": page,
            "limit": limit,
            "pages": (total + limit - 1) // limit if total > 0 else 0,
            "data": paginated_results
        }
    except Exception as e:
        logger.error(f"Error fetching Postfix logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/logs/rspamd")
async def get_rspamd_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    search: Optional[str] = Query(None),
    sender: Optional[str] = Query(None),
    direction: Optional[str] = Query(None, regex="^(inbound|outbound|internal|unknown)$"),
    min_score: Optional[float] = Query(None),
    max_score: Optional[float] = Query(None),
    action: Optional[str] = Query(None),
    is_spam: Optional[bool] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Get Rspamd logs with filtering and pagination
    """
    try:
        query = db.query(RspamdLog)
        
        # Apply filters
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    RspamdLog.subject.ilike(search_term),
                    RspamdLog.sender_smtp.ilike(search_term),
                    RspamdLog.message_id.ilike(search_term)
                )
            )
        
        if sender:
            query = query.filter(RspamdLog.sender_smtp.ilike(f"%{sender}%"))
        
        if direction:
            query = query.filter(RspamdLog.direction == direction)
        
        if min_score is not None:
            query = query.filter(RspamdLog.score >= min_score)
        
        if max_score is not None:
            query = query.filter(RspamdLog.score <= max_score)
        
        if action:
            query = query.filter(RspamdLog.action == action)
        
        if is_spam is not None:
            query = query.filter(RspamdLog.is_spam == is_spam)
        
        if start_date:
            query = query.filter(RspamdLog.time >= start_date)
        
        if end_date:
            query = query.filter(RspamdLog.time <= end_date)
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * limit
        logs = query.order_by(desc(RspamdLog.time)).offset(offset).limit(limit).all()
        
        return {
            "total": total,
            "page": page,
            "limit": limit,
            "pages": (total + limit - 1) // limit,
            "data": [
                {
                    "id": log.id,
                    "time": log.time.isoformat(),
                    "message_id": log.message_id,
                    "subject": log.subject,
                    "size": log.size,
                    "sender_smtp": log.sender_smtp,
                    "recipients_smtp": log.recipients_smtp,
                    "score": log.score,
                    "required_score": log.required_score,
                    "action": log.action,
                    "direction": log.direction,
                    "ip": log.ip,
                    "is_spam": log.is_spam,
                    "has_auth": log.has_auth,
                    "user": log.user,
                    "symbols": log.symbols,
                    "correlation_key": log.correlation_key
                }
                for log in logs
            ]
        }
    except Exception as e:
        logger.error(f"Error fetching Rspamd logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/logs/netfilter")
async def get_netfilter_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    search: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Get Netfilter logs with filtering and pagination
    """
    try:
        query = db.query(NetfilterLog)
        
        # Apply filters
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    NetfilterLog.message.ilike(search_term),
                    NetfilterLog.ip.ilike(search_term),
                    NetfilterLog.username.ilike(search_term)
                )
            )
        
        if ip:
            query = query.filter(NetfilterLog.ip.ilike(f"%{ip}%"))
        
        if username:
            query = query.filter(NetfilterLog.username.ilike(f"%{username}%"))
        
        if action:
            # Backward compatibility: 'ban' filter should also include legacy 'banned' values
            # 'unban' filter should also include legacy 'info' values that are actually unbanning events
            if action == 'ban':
                query = query.filter(
                    or_(
                        NetfilterLog.action == 'ban',
                        NetfilterLog.action == 'banned'
                    )
                )
            elif action == 'unban':
                query = query.filter(
                    or_(
                        NetfilterLog.action == 'unban',
                        NetfilterLog.action == 'info'
                    )
                )
            else:
                query = query.filter(NetfilterLog.action == action)
        
        if start_date:
            query = query.filter(NetfilterLog.time >= start_date)
        
        if end_date:
            query = query.filter(NetfilterLog.time <= end_date)
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * limit
        logs = query.order_by(desc(NetfilterLog.time)).offset(offset).limit(limit).all()
        
        return {
            "total": total,
            "page": page,
            "limit": limit,
            "pages": (total + limit - 1) // limit,
            "data": [
                {
                    "id": log.id,
                    "time": format_datetime_utc(log.time),
                    "priority": log.priority,
                    "message": log.message,
                    "ip": log.ip,
                    "rule_id": log.rule_id,
                    "attempts_left": log.attempts_left,
                    "username": log.username,
                    "auth_method": log.auth_method,
                    "action": log.action
                }
                for log in logs
            ]
        }
    except Exception as e:
        logger.error(f"Error fetching Netfilter logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/queue")
async def get_queue():
    """
    Get current mail queue from Mailcow (real-time)
    """
    try:
        queue = await mailcow_api.get_queue()
        return {
            "total": len(queue),
            "data": queue
        }
    except Exception as e:
        logger.error(f"Error fetching queue: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/quarantine")
async def get_quarantine():
    """
    Get quarantined messages from Mailcow (real-time)
    """
    try:
        quarantine = await mailcow_api.get_quarantine()
        return {
            "total": len(quarantine),
            "data": quarantine
        }
    except Exception as e:
        logger.error(f"Error fetching quarantine: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/message/{correlation_key}")
async def get_message_details(
    correlation_key: str,
    db: Session = Depends(get_db)
):
    """
    Get complete message details with all related logs
    """
    try:
        # Get correlation
        correlation = db.query(MessageCorrelation).filter(
            MessageCorrelation.correlation_key == correlation_key
        ).first()
        
        if not correlation:
            raise HTTPException(status_code=404, detail="Message not found")
        
        # Get Rspamd log
        rspamd_log = None
        if correlation.rspamd_log_id:
            rspamd_log = db.query(RspamdLog).filter(
                RspamdLog.id == correlation.rspamd_log_id
            ).first()
        
        # Get Postfix logs - Use queue_id instead of postfix_log_ids
        # This ensures we always get ALL logs, even if they arrive after correlation is marked complete
        postfix_logs = []
        if correlation.queue_id:
            # Query ALL postfix logs with this queue_id
            # This is the source of truth, not postfix_log_ids
            postfix_logs = db.query(PostfixLog).filter(
                PostfixLog.queue_id == correlation.queue_id
            ).order_by(PostfixLog.time).all()
        elif correlation.postfix_log_ids:
            # Fallback: if no queue_id yet, use postfix_log_ids (for incomplete correlations)
            postfix_logs = db.query(PostfixLog).filter(
                PostfixLog.id.in_(correlation.postfix_log_ids)
            ).order_by(PostfixLog.time).all()
        
        # Build response
        return {
            "correlation_key": correlation.correlation_key,
            "message_id": correlation.message_id,
            "queue_id": correlation.queue_id,
            "sender": correlation.sender,
            "recipient": correlation.recipient,
            "subject": correlation.subject,
            "direction": correlation.direction,
            "final_status": correlation.final_status,
            "first_seen": correlation.first_seen.isoformat() if correlation.first_seen else None,
            "last_seen": correlation.last_seen.isoformat() if correlation.last_seen else None,
            "rspamd": {
                "score": rspamd_log.score,
                "required_score": rspamd_log.required_score,
                "action": rspamd_log.action,
                "symbols": rspamd_log.symbols,
                "is_spam": rspamd_log.is_spam,
                "direction": rspamd_log.direction,
                "ip": rspamd_log.ip
            } if rspamd_log else None,
            "postfix": [
                {
                    "time": log.time.isoformat(),
                    "program": log.program,
                    "message": log.message,
                    "status": log.status,
                    "relay": log.relay,
                    "delay": log.delay
                }
                for log in postfix_logs
            ],
            "timeline": sorted([
                {"time": correlation.first_seen, "event": "Message received"},
                *[{"time": log.time, "event": f"Postfix: {log.status}"} for log in postfix_logs if log.status],
                {"time": rspamd_log.time, "event": f"Rspamd: {rspamd_log.action}"} if rspamd_log else None
            ], key=lambda x: x["time"] if x else datetime.min) if correlation.first_seen else []
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching message details: {e}")
        raise HTTPException(status_code=500, detail=str(e))
