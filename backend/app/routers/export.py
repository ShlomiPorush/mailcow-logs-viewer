"""
API endpoints for exporting logs to CSV
"""
import logging
import io
from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc
from datetime import datetime
from typing import Optional
import pandas as pd

from ..database import get_db
from ..models import PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation
from ..config import settings
from ..utils import internal_error

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/export/postfix/csv")
def export_postfix_csv(
    search: Optional[str] = Query(None),
    sender: Optional[str] = Query(None),
    recipient: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Export Postfix logs to CSV
    """
    try:
        query = db.query(PostfixLog)
        
        # Apply same filters as the main API
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    PostfixLog.message.ilike(search_term),
                    PostfixLog.sender.ilike(search_term),
                    PostfixLog.recipient.ilike(search_term),
                    PostfixLog.queue_id.ilike(search_term)
                )
            )
        
        if sender:
            query = query.filter(PostfixLog.sender.ilike(f"%{sender}%"))
        
        if recipient:
            query = query.filter(PostfixLog.recipient.ilike(f"%{recipient}%"))
        
        if status:
            query = query.filter(PostfixLog.status == status)
        
        if start_date:
            query = query.filter(PostfixLog.time >= start_date)
        
        if end_date:
            query = query.filter(PostfixLog.time <= end_date)
        
        # Limit to prevent massive exports
        logs = query.order_by(desc(PostfixLog.time)).limit(settings.csv_export_limit).all()
        
        if not logs:
            raise HTTPException(status_code=404, detail="No data to export")
        
        # Convert to DataFrame
        data = [
            {
                "Time": log.time.isoformat(),
                "Program": log.program,
                "Priority": log.priority,
                "Queue ID": log.queue_id,
                "Message ID": log.message_id,
                "Sender": log.sender,
                "Recipient": log.recipient,
                "Status": log.status,
                "Relay": log.relay,
                "Delay": log.delay,
                "DSN": log.dsn,
                "Message": log.message
            }
            for log in logs
        ]
        
        df = pd.DataFrame(data)
        
        # Create CSV in memory
        output = io.StringIO()
        df.to_csv(output, index=False)
        output.seek(0)
        
        # Return as streaming response
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=postfix_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting Postfix logs: {e}")
        raise internal_error(e)


@router.get("/export/rspamd/csv")
def export_rspamd_csv(
    search: Optional[str] = Query(None),
    sender: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
    min_score: Optional[float] = Query(None),
    max_score: Optional[float] = Query(None),
    is_spam: Optional[bool] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Export Rspamd logs to CSV
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
        
        if is_spam is not None:
            query = query.filter(RspamdLog.is_spam == is_spam)
        
        if start_date:
            query = query.filter(RspamdLog.time >= start_date)
        
        if end_date:
            query = query.filter(RspamdLog.time <= end_date)
        
        logs = query.order_by(desc(RspamdLog.time)).limit(settings.csv_export_limit).all()
        
        if not logs:
            raise HTTPException(status_code=404, detail="No data to export")
        
        # Convert to DataFrame
        data = [
            {
                "Time": log.time.isoformat(),
                "Message ID": log.message_id,
                "Subject": log.subject,
                "Sender": log.sender_smtp,
                "Recipients": ", ".join(log.recipients_smtp) if log.recipients_smtp else "",
                "Score": log.score,
                "Required Score": log.required_score,
                "Action": log.action,
                "Direction": log.direction,
                "Is Spam": log.is_spam,
                "Has Auth": log.has_auth,
                "User": log.user,
                "IP": log.ip,
                "Size": log.size,
                "Top Symbols": ", ".join(list(log.symbols.keys())[:5]) if log.symbols else ""
            }
            for log in logs
        ]
        
        df = pd.DataFrame(data)
        
        # Create CSV
        output = io.StringIO()
        df.to_csv(output, index=False)
        output.seek(0)
        
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=rspamd_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting Rspamd logs: {e}")
        raise internal_error(e)


@router.get("/export/netfilter/csv")
def export_netfilter_csv(
    search: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Export Netfilter logs to CSV
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
        
        if start_date:
            query = query.filter(NetfilterLog.time >= start_date)
        
        if end_date:
            query = query.filter(NetfilterLog.time <= end_date)
        
        logs = query.order_by(desc(NetfilterLog.time)).limit(settings.csv_export_limit).all()
        
        if not logs:
            raise HTTPException(status_code=404, detail="No data to export")
        
        # Convert to DataFrame
        data = [
            {
                "Time": log.time.isoformat(),
                "IP": log.ip,
                "Username": log.username,
                "Auth Method": log.auth_method,
                "Action": log.action,
                "Attempts Left": log.attempts_left,
                "Rule ID": log.rule_id,
                "Priority": log.priority,
                "Message": log.message
            }
            for log in logs
        ]
        
        df = pd.DataFrame(data)
        
        # Create CSV
        output = io.StringIO()
        df.to_csv(output, index=False)
        output.seek(0)
        
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=netfilter_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting Netfilter logs: {e}")
        raise internal_error(e)


@router.get("/export/messages/csv")
def export_messages_csv(
    search: Optional[str] = Query(None),
    sender: Optional[str] = Query(None),
    recipient: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    user: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Export Messages (correlations) to CSV
    """
    try:
        query = db.query(MessageCorrelation)
        
        # Apply filters
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    MessageCorrelation.sender.ilike(search_term),
                    MessageCorrelation.recipient.ilike(search_term),
                    MessageCorrelation.subject.ilike(search_term),
                    MessageCorrelation.message_id.ilike(search_term),
                    MessageCorrelation.queue_id.ilike(search_term)
                )
            )
        
        if sender:
            query = query.filter(MessageCorrelation.sender.ilike(f"%{sender}%"))
        
        if recipient:
            query = query.filter(MessageCorrelation.recipient.ilike(f"%{recipient}%"))
        
        if direction:
            query = query.filter(MessageCorrelation.direction == direction)
        
        if status:
            query = query.filter(MessageCorrelation.final_status == status)
        
        if start_date:
            query = query.filter(MessageCorrelation.first_seen >= start_date)
        
        if end_date:
            query = query.filter(MessageCorrelation.first_seen <= end_date)
        
        # Join with Rspamd for user/ip filters
        if user or ip:
            query = query.join(
                RspamdLog,
                MessageCorrelation.rspamd_log_id == RspamdLog.id
            )
            if user:
                query = query.filter(RspamdLog.user.ilike(f"%{user}%"))
            if ip:
                query = query.filter(RspamdLog.ip.ilike(f"%{ip}%"))
        
        # Limit and order
        messages = query.order_by(desc(MessageCorrelation.last_seen)).limit(settings.csv_export_limit).all()
        
        if not messages:
            raise HTTPException(status_code=404, detail="No data to export")
        
        # Get Rspamd data for each message
        rspamd_data = {}
        rspamd_ids = [msg.rspamd_log_id for msg in messages if msg.rspamd_log_id]
        if rspamd_ids:
            rspamd_logs = db.query(RspamdLog).filter(RspamdLog.id.in_(rspamd_ids)).all()
            rspamd_data = {r.id: r for r in rspamd_logs}
        
        # Convert to DataFrame
        data = []
        for msg in messages:
            rspamd = rspamd_data.get(msg.rspamd_log_id)
            data.append({
                "Time": msg.first_seen.isoformat() if msg.first_seen else "",
                "Sender": msg.sender,
                "Recipient": msg.recipient,
                "Subject": msg.subject,
                "Direction": msg.direction,
                "Status": msg.final_status,
                "Queue ID": msg.queue_id,
                "Message ID": msg.message_id,
                "Spam Score": rspamd.score if rspamd else "",
                "Is Spam": rspamd.is_spam if rspamd else "",
                "User": rspamd.user if rspamd else "",
                "IP": rspamd.ip if rspamd else "",
                "Is Complete": msg.is_complete
            })
        
        df = pd.DataFrame(data)
        
        # Create CSV
        output = io.StringIO()
        df.to_csv(output, index=False)
        output.seek(0)
        
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=messages_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting Messages: {e}")
        raise internal_error(e)