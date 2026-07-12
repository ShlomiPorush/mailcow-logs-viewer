"""
API endpoints for log retrieval and search
"""
import logging
from fastapi import APIRouter, Depends, Query, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc, func
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from ..database import get_db
from ..models import PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation
from ..mailcow_api import mailcow_api
from ..config import settings
from ..services import geoip_service
from ..utils import internal_error, format_datetime_for_api as format_datetime_utc

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/logs/postfix/by-queue/{queue_id}")
def get_postfix_logs_by_queue(
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
        raise internal_error(e)


@router.get("/logs/postfix")
def get_postfix_logs(
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
        
        # Paginate at the queue level in SQL (one row per queue, newest activity
        # first) instead of loading every matching queue and paginating in
        # Python — the old approach issued one query per queue_id (N+1).
        grouped = base_query.with_entities(
            PostfixLog.queue_id
        ).group_by(PostfixLog.queue_id)

        total = grouped.count()

        page_queue_ids = [
            row[0] for row in grouped
            .order_by(func.max(PostfixLog.time).desc())
            .offset((page - 1) * limit)
            .limit(limit)
            .all()
        ]

        # Fetch all logs for this page's queues in a single query
        logs_by_queue = {}
        if page_queue_ids:
            for log in db.query(PostfixLog).filter(
                PostfixLog.queue_id.in_(page_queue_ids)
            ).order_by(PostfixLog.time).all():
                logs_by_queue.setdefault(log.queue_id, []).append(log)

        results = []
        for qid in page_queue_ids:
            queue_logs = logs_by_queue.get(qid)
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

        # Sort the page by display time descending
        results.sort(key=lambda x: x["time"], reverse=True)

        # Convert time to ISO format
        for result in results:
            result["time"] = result["time"].isoformat()

        return {
            "total": total,
            "page": page,
            "limit": limit,
            "pages": (total + limit - 1) // limit if total > 0 else 0,
            "data": results
        }
    except Exception as e:
        logger.error(f"Error fetching Postfix logs: {e}")
        raise internal_error(e)


@router.get("/logs/rspamd")
def get_rspamd_logs(
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
        raise internal_error(e)


@router.get("/logs/netfilter/countries")
def get_netfilter_countries(db: Session = Depends(get_db)):
    """
    Get distinct country codes from netfilter logs for the filter dropdown
    """
    try:
        rows = db.query(
            NetfilterLog.country_code,
            NetfilterLog.country_name
        ).filter(
            NetfilterLog.country_code.isnot(None)
        ).distinct().order_by(NetfilterLog.country_name).all()
        
        return [{"code": r.country_code, "name": r.country_name} for r in rows if r.country_code]
    except Exception as e:
        logger.error(f"Error fetching netfilter countries: {e}")
        return []


@router.get("/logs/netfilter/stats/by-country")
def get_netfilter_stats_by_country(
    days: int = Query(30, ge=1, le=365, description="Number of days to look back"),
    db: Session = Depends(get_db)
):
    """
    Get netfilter event counts grouped by country and action type.
    Returns data suitable for a stacked bar chart.
    """
    try:
        import re
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Fetch ALL netfilter events in the time range (including those without country_code)
        rows = db.query(
            NetfilterLog.country_code,
            NetfilterLog.country_name,
            NetfilterLog.action,
            NetfilterLog.message,
            NetfilterLog.ip
        ).filter(
            NetfilterLog.time >= cutoff
        ).all()

        # Aggregate into per-country structure
        countries = {}
        for row in rows:
            code = row.country_code
            name = row.country_name
            
            # If no country_code, try to resolve from IP (or extract IP from message)
            if not code:
                ip = row.ip
                if not ip and row.message:
                    # Extract IP from message text
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', row.message)
                    if ip_match:
                        ip = ip_match.group(1)
                
                if ip and geoip_service.is_geoip_available():
                    geo = geoip_service.lookup_ip(ip)
                    code = geo.get('country_code')
                    name = geo.get('country_name')
            
            if not code:
                continue  # Skip events we can't geo-locate
            
            if code not in countries:
                countries[code] = {
                    "country_code": code,
                    "country_name": name or code,
                    "ban": 0,
                    "unban": 0,
                    "warning": 0,
                    "total": 0
                }
            
            action = (row.action or '').lower()
            msg_lower = (row.message or '').lower()
            
            # Re-classify 'info' events by examining the message text
            if action == 'info' and msg_lower:
                if 'removed' in msg_lower and 'denylist' in msg_lower:
                    action = 'unban'
                elif 'added' in msg_lower and 'denylist' in msg_lower:
                    action = 'ban'

            if action in ('ban', 'banned'):
                countries[code]["ban"] += 1
            elif action == 'unban':
                countries[code]["unban"] += 1
            elif action == 'warning':
                countries[code]["warning"] += 1
            # Skip 'info' and 'other' — not interesting for chart
            else:
                continue
            countries[code]["total"] += 1

        # Remove countries with 0 total after filtering
        countries = {k: v for k, v in countries.items() if v["total"] > 0}

        # Sort by total descending, take top 10
        sorted_countries = sorted(countries.values(), key=lambda x: x["total"], reverse=True)[:10]
        
        return {
            "days": days,
            "data": sorted_countries
        }
    except Exception as e:
        logger.error(f"Error fetching netfilter stats by country: {e}")
        raise internal_error(e)


@router.get("/logs/netfilter")
def get_netfilter_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    search: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    country_code: Optional[str] = Query(None, description="Filter by country code (e.g., US, IL)"),
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
            if action == 'ban':
                query = query.filter(
                    or_(
                        NetfilterLog.action == 'ban',
                        NetfilterLog.action == 'banned'
                    )
                )
            else:
                query = query.filter(NetfilterLog.action == action)
        
        if country_code:
            query = query.filter(NetfilterLog.country_code == country_code.upper())
        
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
                    "action": log.action,
                    "country_code": log.country_code,
                    "country_name": log.country_name,
                    "city": log.city,
                    "asn": log.asn,
                    "asn_org": log.asn_org
                }
                for log in logs
            ]
        }
    except Exception as e:
        logger.error(f"Error fetching Netfilter logs: {e}")
        raise internal_error(e)


@router.get("/fail2ban")
async def get_fail2ban():
    """
    Get Fail2Ban configuration from mailcow (real-time)
    """
    try:
        data = await mailcow_api.get_fail2ban()
        
        if data is None:
            raise HTTPException(status_code=503, detail="Could not fetch Fail2Ban configuration from mailcow")
        
        return data
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching Fail2Ban configuration: {e}")
        raise internal_error(e)


@router.get("/rw-status")
def get_rw_status():
    """
    Check if the Read-Write API key is configured.
    Used by all features that require write access (Fail2Ban, Quarantine, etc.)
    """
    return {"rw_configured": mailcow_api.has_rw_key}


@router.post("/fail2ban")
async def edit_fail2ban(request: Request):
    """
    Update Fail2Ban configuration on mailcow (requires Read-Write API key)
    """
    try:
        body = await request.json()
        attrs = body.get("attr", body)
        
        result = await mailcow_api.edit_fail2ban(attrs)
        
        # mailcow returns a list with status objects
        if isinstance(result, list) and len(result) > 0:
            first = result[0]
            if first.get("type") == "success":
                return {"status": "success", "msg": first.get("msg", "Settings updated")}
            else:
                return {"status": "error", "msg": first.get("msg", "Update failed")}
        
        return {"status": "success", "msg": "Settings updated", "raw": result}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating Fail2Ban configuration: {e}")
        raise internal_error(e)


@router.post("/fail2ban/unban")
async def unban_fail2ban(request: Request):
    """
    Unban an IP address from Fail2Ban on mailcow (requires Read-Write API key)
    """
    try:
        body = await request.json()
        ip = body.get("ip")
        if not ip:
            raise HTTPException(status_code=400, detail="Missing 'ip' field")
        
        result = await mailcow_api.unban_fail2ban(ip)
        
        # mailcow returns a list with status objects
        if isinstance(result, list) and len(result) > 0:
            first = result[0]
            if first.get("type") == "success":
                return {"status": "success", "msg": first.get("msg", f"IP {ip} unbanned")}
            else:
                return {"status": "error", "msg": first.get("msg", "Unban failed")}
        
        return {"status": "success", "msg": f"IP {ip} unbanned", "raw": result}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error unbanning IP from Fail2Ban: {e}")
        raise internal_error(e)


@router.post("/fail2ban/ban")
async def ban_fail2ban(request: Request):
    """
    Ban an IP address in Fail2Ban on mailcow by adding it to the blacklist.
    Fetches current settings, appends IP to blacklist, and saves back.
    Requires Read-Write API key.
    """
    try:
        body = await request.json()
        ip = body.get("ip")
        if not ip:
            raise HTTPException(status_code=400, detail="Missing 'ip' field")
        
        # Get current fail2ban settings to read the existing blacklist
        current = await mailcow_api.get_fail2ban()
        if current is None:
            raise HTTPException(status_code=503, detail="Could not fetch current Fail2Ban settings")
        
        # Parse current blacklist (may be comma or newline separated from GET API)
        current_blacklist = current.get("blacklist", "")
        # Normalize: split by both commas and newlines
        blacklist_entries = [e.strip() for e in current_blacklist.replace('\n', ',').split(",") if e.strip()] if current_blacklist else []
        
        # Check if IP is already in the blacklist
        if ip in blacklist_entries:
            return {"status": "success", "msg": f"IP {ip} is already in the blacklist"}
        
        # Add IP to blacklist
        blacklist_entries.append(ip)
        new_blacklist = ",".join(blacklist_entries)
        
        # Normalize whitelist the same way
        current_whitelist = current.get("whitelist", "")
        whitelist_normalized = ",".join([e.strip() for e in current_whitelist.replace('\n', ',').split(",") if e.strip()]) if current_whitelist else ""
        
        # Build full attribute set (required by mailcow API - ALL params must be sent)
        # ban_time_increment must be "1" or "0" as string
        bti = current.get("ban_time_increment", 1)
        bti_str = "1" if bti in (True, 1, "1") else "0"
        
        attrs = {
            "ban_time": str(current.get("ban_time", "86400")),
            "ban_time_increment": bti_str,
            "blacklist": new_blacklist,
            "max_attempts": str(current.get("max_attempts", "5")),
            "max_ban_time": str(current.get("max_ban_time", "86400")),
            "netban_ipv4": str(current.get("netban_ipv4", "24")),
            "netban_ipv6": str(current.get("netban_ipv6", "64")),
            "retry_window": str(current.get("retry_window", "600")),
            "whitelist": whitelist_normalized
        }
        
        logger.info(f"Banning IP {ip} - sending attrs: {attrs}")
        result = await mailcow_api.edit_fail2ban(attrs)
        
        if isinstance(result, list) and len(result) > 0:
            first = result[0]
            if first.get("type") == "success":
                return {"status": "success", "msg": f"IP {ip} added to blacklist"}
            else:
                return {"status": "error", "msg": first.get("msg", "Ban failed")}
        
        return {"status": "success", "msg": f"IP {ip} added to blacklist", "raw": result}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error banning IP in Fail2Ban: {e}")
        raise internal_error(e)


@router.get("/geoip/{ip}")
def lookup_geoip(ip: str):
    """
    Lookup GeoIP information for an IP address.
    Returns country, city, ASN info when MaxMind databases are available.
    """
    if not geoip_service.is_geoip_available():
        return {"available": False}
    
    geo = geoip_service.lookup_ip(ip)
    return {"available": True, "ip": ip, **geo}


@router.get("/queue")
async def get_queue():
    """
    Get current mail queue from mailcow (real-time)
    Returns messages sorted by newest first (by arrival_time)
    """
    try:
        queue = await mailcow_api.get_queue()
        
        # Sort by arrival_time - newest first (descending order)
        # arrival_time is a Unix timestamp (integer)
        queue_sorted = sorted(
            queue,
            key=lambda x: x.get('arrival_time', 0),
            reverse=True  # Newest first
        )
        
        return {
            "total": len(queue_sorted),
            "data": queue_sorted
        }
    except Exception as e:
        logger.error(f"Error fetching queue: {e}")
        raise internal_error(e)


@router.post("/queue/action")
async def queue_action(request: Request):
    """
    Perform an action on mail queue items (requires Read-Write API key).
    Actions: deliver, hold, unhold, flush (flush uses mailqitems-all).
    """
    try:
        body = await request.json()
        items = body.get("items", [])
        action = body.get("action", "")
        
        if not items:
            raise HTTPException(status_code=400, detail="Missing 'items' array")
        if action not in ("deliver", "hold", "unhold", "flush", "super_delete"):
            raise HTTPException(status_code=400, detail=f"Invalid action: {action}")
        
        # super_delete goes through edit endpoint with special item
        items = [str(item) for item in items]
        
        result = await mailcow_api.edit_queue(items, action)
        
        if isinstance(result, list) and len(result) > 0:
            first = result[0]
            if first.get("type") == "success":
                return {"status": "success", "msg": first.get("msg", f"Queue action '{action}' completed")}
            else:
                return {"status": "error", "msg": first.get("msg", f"Queue action '{action}' failed")}
        
        return {"status": "success", "msg": f"Queue action '{action}' completed", "raw": result}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error performing queue action: {e}")
        raise internal_error(e)


@router.post("/queue/delete")
async def delete_queue(request: Request):
    """
    Delete mail queue items (requires Read-Write API key).
    Sends POST to /api/v1/delete/mailq.
    """
    try:
        body = await request.json()
        items = body.get("items", [])
        if not items:
            raise HTTPException(status_code=400, detail="Missing 'items' array")
        
        items = [str(item) for item in items]
        
        result = await mailcow_api.delete_queue(items)
        
        if isinstance(result, list) and len(result) > 0:
            first = result[0]
            if first.get("type") == "success":
                return {"status": "success", "msg": first.get("msg", "Queue item(s) deleted")}
            else:
                return {"status": "error", "msg": first.get("msg", "Delete failed")}
        
        return {"status": "success", "msg": "Queue item(s) deleted", "raw": result}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting queue items: {e}")
        raise internal_error(e)


@router.get("/quarantine")
async def get_quarantine():
    """
    Get quarantined messages from mailcow (real-time)
    Returns messages sorted by newest first
    """
    try:
        quarantine = await mailcow_api.get_quarantine()
        
        # Format timestamps for each quarantine item to ensure consistency
        for item in quarantine:
            if 'created' in item and item['created']:
                # Handle Unix timestamp (number) or ISO string
                if isinstance(item['created'], (int, float)):
                    # Convert Unix timestamp to ISO format with 'Z' suffix
                    dt = datetime.fromtimestamp(item['created'], tz=timezone.utc)
                    item['created'] = dt.replace(microsecond=0).isoformat().replace('+00:00', 'Z')
                    # Store the numeric value for sorting
                    item['_created_timestamp'] = item['created']
                elif isinstance(item['created'], str):
                    # Parse ISO string and ensure it has 'Z' suffix for UTC
                    try:
                        dt = datetime.fromisoformat(item['created'].replace('Z', '+00:00'))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        else:
                            dt = dt.astimezone(timezone.utc)
                        item['created'] = dt.replace(microsecond=0).isoformat().replace('+00:00', 'Z')
                        # Store the datetime object for sorting
                        item['_created_timestamp'] = dt.timestamp()
                    except (ValueError, AttributeError):
                        pass
        
        # Sort by created timestamp - newest first (descending order)
        # Items without valid timestamp will be at the end
        quarantine_sorted = sorted(
            quarantine,
            key=lambda x: x.get('_created_timestamp', 0),
            reverse=True  # Newest first
        )
        
        # Remove the temporary sorting field before returning
        for item in quarantine_sorted:
            item.pop('_created_timestamp', None)
        
        return {
            "total": len(quarantine_sorted),
            "data": quarantine_sorted
        }
    except Exception as e:
        logger.error(f"Error fetching quarantine: {e}")
        raise internal_error(e)




@router.post("/quarantine/release")
async def release_quarantine(request: Request):
    """
    Release quarantined messages on mailcow (requires Read-Write API key).
    Sends POST to /api/v1/edit/qitem with action=release.
    """
    try:
        body = await request.json()
        items = body.get("items", [])
        if not items:
            raise HTTPException(status_code=400, detail="Missing 'items' array")
        
        # Ensure all items are strings
        items = [str(item) for item in items]
        
        result = await mailcow_api.release_quarantine(items)
        
        # mailcow returns a list with status objects
        if isinstance(result, list) and len(result) > 0:
            first = result[0]
            if first.get("type") == "success":
                return {"status": "success", "msg": first.get("msg", "Message(s) released")}
            else:
                return {"status": "error", "msg": first.get("msg", "Release failed")}
        
        return {"status": "success", "msg": "Message(s) released", "raw": result}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error releasing quarantine items: {e}")
        raise internal_error(e)


@router.post("/quarantine/delete")
async def delete_quarantine(request: Request):
    """
    Delete quarantined messages on mailcow (requires Read-Write API key).
    Sends POST to /api/v1/delete/qitem.
    """
    try:
        body = await request.json()
        items = body.get("items", [])
        if not items:
            raise HTTPException(status_code=400, detail="Missing 'items' array")
        
        # Ensure all items are strings
        items = [str(item) for item in items]
        
        result = await mailcow_api.delete_quarantine(items)
        
        # mailcow returns a list with status objects
        if isinstance(result, list) and len(result) > 0:
            first = result[0]
            if first.get("type") == "success":
                return {"status": "success", "msg": first.get("msg", "Message(s) deleted")}
            else:
                return {"status": "error", "msg": first.get("msg", "Delete failed")}
        
        return {"status": "success", "msg": "Message(s) deleted", "raw": result}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting quarantine items: {e}")
        raise internal_error(e)


@router.post("/quarantine/learnham")
async def learnham_quarantine(request: Request):
    """
    Release quarantined messages and train Rspamd that they are NOT spam.
    Sends POST to /api/v1/edit/qitem with action=learnham.
    """
    try:
        body = await request.json()
        items = body.get("items", [])
        if not items:
            raise HTTPException(status_code=400, detail="Missing 'items' array")
        
        items = [str(item) for item in items]
        
        result = await mailcow_api.learnham_quarantine(items)
        
        if isinstance(result, list) and len(result) > 0:
            first = result[0]
            if first.get("type") == "success":
                return {"status": "success", "msg": first.get("msg", "Message(s) released and learned as ham")}
            else:
                return {"status": "error", "msg": first.get("msg", "Learn ham failed")}
        
        return {"status": "success", "msg": "Message(s) released and learned as ham", "raw": result}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error learning ham for quarantine items: {e}")
        raise internal_error(e)


@router.post("/quarantine/learnspam")
async def learnspam_quarantine(request: Request):
    """
    Delete quarantined messages and train Rspamd that they ARE spam.
    Sends POST to /api/v1/edit/qitem with action=learnspam.
    """
    try:
        body = await request.json()
        items = body.get("items", [])
        if not items:
            raise HTTPException(status_code=400, detail="Missing 'items' array")
        
        items = [str(item) for item in items]
        
        result = await mailcow_api.learnspam_quarantine(items)
        
        if isinstance(result, list) and len(result) > 0:
            first = result[0]
            if first.get("type") == "success":
                return {"status": "success", "msg": first.get("msg", "Message(s) deleted and learned as spam")}
            else:
                return {"status": "error", "msg": first.get("msg", "Learn spam failed")}
        
        return {"status": "success", "msg": "Message(s) deleted and learned as spam", "raw": result}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error learning spam for quarantine items: {e}")
        raise internal_error(e)


@router.get("/quarantine/{item_id}/details")
async def get_quarantine_details(item_id: str):
    """
    Get detailed information for a quarantine item.
    Proxies to mailcow's qitem_details.php for full email details
    including Rspamd symbols, email content, and recipients.
    """
    try:
        result = await mailcow_api.get_quarantine_details(item_id)
        return result
    except Exception as e:
        logger.error(f"Error fetching quarantine details for item {item_id}: {e}")
        raise internal_error(e)


@router.get("/message/{correlation_key}")
def get_message_details(
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
        raise internal_error(e)
