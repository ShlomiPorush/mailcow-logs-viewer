"""
API endpoints for exporting logs to CSV
"""
import logging
from fastapi import APIRouter, Depends, Query, HTTPException, Request
from sqlalchemy.orm import Session, load_only
from sqlalchemy import or_, and_, desc, func
from datetime import datetime
from typing import Optional

from ..models import PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation
from ..app_time import local_now, to_local
from ..config import settings
from ..utils import internal_error, RangeStart, RangeEnd
from ..services.csv_export import csv_download, csv_query_rows, get_csv_db

logger = logging.getLogger(__name__)

router = APIRouter()


def _csv_time(value: Optional[datetime]) -> str:
    """A stored (naive UTC) time in the app's time zone with its offset, for
    example 2026-01-15 13:00:00+01:00, so a spreadsheet cannot misread it."""
    return to_local(value).isoformat(sep=' ', timespec='seconds') if value else ""


@router.head("/export/postfix/csv", include_in_schema=False)
@router.get("/export/postfix/csv")
def export_postfix_csv(
    request: Request,
    search: Optional[str] = Query(None),
    sender: Optional[str] = Query(None),
    recipient: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    start_date: Optional[RangeStart] = Query(None),
    end_date: Optional[RangeEnd] = Query(None),
    db: Session = Depends(get_csv_db)
):
    """
    Export Postfix logs to CSV
    """
    try:
        query = db.query(PostfixLog).options(load_only(
            PostfixLog.time, PostfixLog.program, PostfixLog.priority, PostfixLog.queue_id,
            PostfixLog.message_id, PostfixLog.sender, PostfixLog.recipient, PostfixLog.status,
            PostfixLog.relay, PostfixLog.delay, PostfixLog.dsn, PostfixLog.message,
        ))
        
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
        logs = csv_query_rows(query.order_by(desc(PostfixLog.time)).limit(settings.csv_export_limit))
        
        # Format one row at a time while the response is consumed.
        data = (
            {
                "Time": _csv_time(log.time),
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
        )
        
        return csv_download(
            data, f"postfix_logs_{local_now().strftime('%Y%m%d_%H%M%S')}.csv",
            head_only=request.method == "HEAD",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting Postfix logs: {e}")
        raise internal_error(e)


@router.head("/export/rspamd/csv", include_in_schema=False)
@router.get("/export/rspamd/csv")
def export_rspamd_csv(
    request: Request,
    search: Optional[str] = Query(None),
    sender: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
    min_score: Optional[float] = Query(None),
    max_score: Optional[float] = Query(None),
    is_spam: Optional[bool] = Query(None),
    start_date: Optional[RangeStart] = Query(None),
    end_date: Optional[RangeEnd] = Query(None),
    db: Session = Depends(get_csv_db)
):
    """
    Export Rspamd logs to CSV
    """
    try:
        query = db.query(RspamdLog).options(load_only(
            RspamdLog.time, RspamdLog.message_id, RspamdLog.subject, RspamdLog.sender_smtp,
            RspamdLog.recipients_smtp, RspamdLog.score, RspamdLog.required_score,
            RspamdLog.action, RspamdLog.direction, RspamdLog.is_spam, RspamdLog.has_auth,
            RspamdLog.user, RspamdLog.ip, RspamdLog.size, RspamdLog.symbols,
        ))
        
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
        
        logs = csv_query_rows(query.order_by(desc(RspamdLog.time)).limit(settings.csv_export_limit))
        
        # Format one row at a time while the response is consumed.
        data = (
            {
                "Time": _csv_time(log.time),
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
        )
        
        return csv_download(
            data, f"rspamd_logs_{local_now().strftime('%Y%m%d_%H%M%S')}.csv",
            head_only=request.method == "HEAD",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting Rspamd logs: {e}")
        raise internal_error(e)


@router.head("/export/netfilter/csv", include_in_schema=False)
@router.get("/export/netfilter/csv")
def export_netfilter_csv(
    request: Request,
    search: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    country_code: Optional[str] = Query(None),
    start_date: Optional[RangeStart] = Query(None),
    end_date: Optional[RangeEnd] = Query(None),
    db: Session = Depends(get_csv_db)
):
    """
    Export Netfilter logs to CSV, with the filters of the Events list
    """
    try:
        query = db.query(NetfilterLog).options(load_only(
            NetfilterLog.time, NetfilterLog.ip, NetfilterLog.username, NetfilterLog.auth_method,
            NetfilterLog.action, NetfilterLog.attempts_left, NetfilterLog.rule_id,
            NetfilterLog.priority, NetfilterLog.message,
        ))
        
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
            # As in the list: 'ban' also matches the older 'banned' lines
            if action == 'ban':
                query = query.filter(or_(NetfilterLog.action == 'ban', NetfilterLog.action == 'banned'))
            else:
                query = query.filter(NetfilterLog.action == action)

        if country_code:
            query = query.filter(NetfilterLog.country_code == country_code.upper())

        if start_date:
            query = query.filter(NetfilterLog.time >= start_date)
        
        if end_date:
            query = query.filter(NetfilterLog.time <= end_date)
        
        logs = csv_query_rows(query.order_by(desc(NetfilterLog.time)).limit(settings.csv_export_limit))
        
        # Format one row at a time while the response is consumed.
        data = (
            {
                "Time": _csv_time(log.time),
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
        )
        
        return csv_download(
            data, f"netfilter_logs_{local_now().strftime('%Y%m%d_%H%M%S')}.csv",
            head_only=request.method == "HEAD",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting Netfilter logs: {e}")
        raise internal_error(e)


@router.head("/export/messages/csv", include_in_schema=False)
@router.get("/export/messages/csv")
def export_messages_csv(
    request: Request,
    search: Optional[str] = Query(None),
    sender: Optional[str] = Query(None),
    recipient: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    user: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    start_date: Optional[RangeStart] = Query(None),
    end_date: Optional[RangeEnd] = Query(None),
    db: Session = Depends(get_csv_db)
):
    """
    Export Messages (correlations) to CSV
    """
    try:
        query = db.query(MessageCorrelation, RspamdLog).outerjoin(
            RspamdLog, MessageCorrelation.rspamd_log_id == RspamdLog.id,
        ).options(load_only(
            MessageCorrelation.first_seen, MessageCorrelation.sender, MessageCorrelation.recipient,
            MessageCorrelation.subject, MessageCorrelation.direction, MessageCorrelation.final_status,
            MessageCorrelation.queue_id, MessageCorrelation.message_id,
            MessageCorrelation.rspamd_log_id, MessageCorrelation.is_complete,
        ), load_only(RspamdLog.id, RspamdLog.score, RspamdLog.is_spam, RspamdLog.user, RspamdLog.ip))

        # The filters mean what they mean in the Messages list (messages.py)
        query = query.filter(MessageCorrelation.correlation_key != "BLACKLISTED")

        # Apply filters
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    MessageCorrelation.sender.ilike(search_term),
                    MessageCorrelation.recipient.ilike(search_term),
                    MessageCorrelation.subject.ilike(search_term),
                    MessageCorrelation.message_id.ilike(search_term),
                    MessageCorrelation.queue_id.ilike(search_term),
                    RspamdLog.ip.ilike(search_term),
                    RspamdLog.user.ilike(search_term)
                )
            )
        
        if sender:
            query = query.filter(MessageCorrelation.sender.ilike(f"%{sender}%"))
        
        if recipient:
            query = query.filter(MessageCorrelation.recipient.ilike(f"%{recipient}%"))
        
        if direction:
            query = query.filter(MessageCorrelation.direction == direction)
        
        if status == 'spam':
            # Spam is the final status or Rspamd's verdict
            query = query.filter(or_(MessageCorrelation.final_status == 'spam', RspamdLog.is_spam == True))  # noqa: E712
        elif status:
            query = query.filter(MessageCorrelation.final_status == status)

        if start_date:
            query = query.filter(MessageCorrelation.first_seen >= start_date)

        if end_date:
            query = query.filter(MessageCorrelation.first_seen <= end_date)

        # Filtering the joined columns excludes messages without a matching log.
        if user:
            query = query.filter(RspamdLog.user.ilike(f"%{user}%"))
        if ip:
            query = query.filter(RspamdLog.ip.ilike(f"%{ip}%"))

        # Addresses hidden with Blacklist Emails stay hidden here, as in the list.
        # Rows stored before an address was added are left out too
        hidden = settings.blacklist_emails_list
        if hidden:
            for column in (MessageCorrelation.sender, MessageCorrelation.recipient):
                query = query.filter(or_(column.is_(None), func.lower(column).notin_(hidden)))

        # Newest first, as the list orders them, so the row limit keeps the same messages
        messages = csv_query_rows(query.order_by(desc(MessageCorrelation.first_seen), desc(MessageCorrelation.id))
                                  .limit(settings.csv_export_limit))
        
        # Format one row at a time while the response is consumed.
        def rows():
            for msg, rspamd in messages:
                yield {
                    "Time": _csv_time(msg.first_seen),
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
                }

        return csv_download(
            rows(), f"messages_{local_now().strftime('%Y%m%d_%H%M%S')}.csv",
            head_only=request.method == "HEAD",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting Messages: {e}")
        raise internal_error(e)
