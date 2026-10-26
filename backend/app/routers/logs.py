"""
API endpoints for log retrieval and search
"""
import ipaddress
import math
import logging
from fastapi import APIRouter, Depends, Query, HTTPException, Request
from starlette.concurrency import run_in_threadpool
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc, func
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from ..database import get_db
from ..models import PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation
from ..mailcow_api import MailcowShownError, mailcow_api
from ..config import settings
from ..services import excluded_addresses, geoip_service, protection_rules, security_addresses
from ..services.security_addresses import netfilter_service  # noqa: F401  (tests import it from here)
from ..app_time import as_utc
from ..utils import internal_error, format_datetime_for_api as format_datetime_utc, RangeStart, RangeEnd
from ..api_models import Invalid, documented
from ..api_models import logs as m

logger = logging.getLogger(__name__)

router = APIRouter()

# A change sent to mailcow: a bad request, mailcow refusing or not answering
MAILCOW_WRITE = {400: None, 500: None, 502: None, 503: None}
MAILCOW_ITEMS = {400: None, 500: None, 502: None}


@router.get("/logs/postfix/by-queue/{queue_id}", responses=documented(m.PostfixByQueueResponse, errors={404: None, 500: None}))
def get_postfix_logs_by_queue(
    queue_id: str,
    db: Session = Depends(get_db)
):
    """
    Get all Postfix logs for a specific Queue ID with linked Rspamd data
    """
    try:
        logs = excluded_addresses.visible_postfix_lines(db.query(PostfixLog).filter(
            PostfixLog.queue_id == queue_id
        ).order_by(PostfixLog.time).all())

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
                    "time": format_datetime_utc(log.time),
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


@router.get("/logs/postfix", responses=documented(m.PostfixLogsResponse, errors={422: Invalid, 500: None}))
def get_postfix_logs(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=500, description="Items per page"),
    search: Optional[str] = Query(None, description="Search query"),
    sender: Optional[str] = Query(None, description="Filter by sender"),
    recipient: Optional[str] = Query(None, description="Filter by recipient"),
    status: Optional[str] = Query(None, description="Filter by status"),
    queue_id: Optional[str] = Query(None, description="Filter by queue ID"),
    start_date: Optional[RangeStart] = Query(None, description="Start date"),
    end_date: Optional[RangeEnd] = Query(None, description="End date"),
    db: Session = Depends(get_db)
):
    """
    Get Postfix logs with filtering and pagination - grouped by Queue ID
    Only shows logs that have a Queue ID (one row per queue with aggregated data)
    """
    try:
        from sqlalchemy.sql import case
        
        # First, filter out logs without queue_id, and the lines of messages
        # of excluded addresses (here, and again below where a page's queues
        # are read in full)
        visible = excluded_addresses.postfix_line_visible()
        base_query = db.query(PostfixLog).filter(
            and_(
                PostfixLog.queue_id.isnot(None),
                PostfixLog.queue_id != ''
            ),
            visible,
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
        # Python - the old approach issued one query per queue_id (N+1).
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
                PostfixLog.queue_id.in_(page_queue_ids), visible
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
            result["time"] = format_datetime_utc(result["time"])

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


@router.get("/logs/rspamd", responses=documented(m.RspamdLogsResponse, errors={422: Invalid, 500: None}))
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
    start_date: Optional[RangeStart] = Query(None),
    end_date: Optional[RangeEnd] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Get Rspamd logs with filtering and pagination
    """
    try:
        # Not an excluded address's mail, as in Messages
        query = db.query(RspamdLog).filter(excluded_addresses.rspamd_visible())

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
                    "time": format_datetime_utc(log.time),
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


@router.get("/logs/netfilter/countries", responses=documented(List[m.NetfilterCountry], description="The countries in the Netfilter logs; empty when they cannot be read"))
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


def _netfilter_since(db: Session, cutoff: datetime) -> Optional[str]:
    """The oldest netfilter line kept, when it is newer than the period's start."""
    oldest = db.query(func.min(NetfilterLog.time)).scalar()
    if oldest is None:
        return None
    if oldest.tzinfo is None:
        oldest = oldest.replace(tzinfo=timezone.utc)
    return format_datetime_utc(oldest) if oldest > cutoff else None


@router.get("/logs/netfilter/stats/by-country", responses=documented(m.ByCountryResponse, errors={422: Invalid, 500: None}))
def get_netfilter_stats_by_country(
    days: int = Query(30, ge=1, le=365, description="Number of days to look back"),
    db: Session = Depends(get_db)
):
    """
    Netfilter counts by country: attempts (lines where netfilter matched a rule,
    as on the Security page; the "N more attempts" line after each is not
    counted again), bans and unbans, and the addresses that tried. `since` is
    the oldest line kept, when the logs are shorter than the period.
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
            NetfilterLog.ip,
            NetfilterLog.rule_id
        ).filter(
            NetfilterLog.time >= cutoff
        ).all()
        addresses = {}

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
            elif action == 'warning' and row.rule_id is not None:
                countries[code]["warning"] += 1
                if row.ip:
                    addresses.setdefault(code, set()).add(row.ip)
            # Skip 'info' and 'other' - not interesting for chart
            else:
                continue
            countries[code]["total"] += 1

        # Remove countries with 0 total after filtering
        countries = {k: v for k, v in countries.items() if v["total"] > 0}
        for code, country in countries.items():
            country["addresses"] = len(addresses.get(code, ()))

        # Sort by total descending, take top 10
        sorted_countries = sorted(countries.values(), key=lambda x: (x["warning"], x["total"]), reverse=True)[:10]
        
        return {
            "days": days,
            "since": _netfilter_since(db, cutoff),
            "data": sorted_countries
        }
    except Exception as e:
        logger.error(f"Error fetching netfilter stats by country: {e}")
        raise internal_error(e)


@router.get("/logs/netfilter/stats/by-network", responses=documented(m.ByNetworkResponse, errors={422: Invalid, 500: None}))
def get_netfilter_stats_by_network(
    days: int = Query(30, ge=1, le=365, description="Number of days to look back"),
    db: Session = Depends(get_db)
):
    """
    The networks (by ASN) that attempts came from, most attempts first.
    An attempt is a line where netfilter matched a rule, as on the overview.
    """
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        rows = db.query(
            NetfilterLog.asn,
            func.max(NetfilterLog.asn_org),
            func.count(NetfilterLog.id),
            func.count(func.distinct(NetfilterLog.ip)),
        ).filter(
            NetfilterLog.time >= cutoff,
            NetfilterLog.rule_id.isnot(None),
            NetfilterLog.asn.isnot(None),
        ).group_by(NetfilterLog.asn).order_by(desc(func.count(NetfilterLog.id))).limit(8).all()
        return {
            "days": days,
            "since": _netfilter_since(db, cutoff),
            "data": [
                {"asn": asn, "asn_org": org or asn, "attempts": attempts, "addresses": addresses}
                for asn, org, attempts, addresses in rows
            ]
        }
    except Exception as e:
        logger.error(f"Error fetching netfilter stats by network: {e}")
        raise internal_error(e)


@router.get("/logs/netfilter", responses=documented(m.NetfilterLogsResponse, errors={422: Invalid, 500: None}))
def get_netfilter_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    search: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    exact_ip: bool = Query(False, description="Match the IP exactly instead of as a part"),
    username: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    country_code: Optional[str] = Query(None, description="Filter by country code (e.g., US, IL)"),
    start_date: Optional[RangeStart] = Query(None),
    end_date: Optional[RangeEnd] = Query(None),
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
        
        if ip and exact_ip:
            query = query.filter(NetfilterLog.ip == ip)
        elif ip:
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


@router.get("/logs/netfilter/overview", responses=documented(m.NetfilterOverviewResponse, errors={422: Invalid, 500: None}))
def get_netfilter_overview(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db)
):
    """
    Attempts against the server over the last hours, grouped by source address.

    Only lines where netfilter matched a rule count as an attempt; the
    "N more attempts ... until banned" lines that follow each one are not
    counted again. Ban and unban lines give the last Fail2ban action per address.
    """
    try:
        sources, totals = security_addresses.netfilter_sources(db, hours)
        attempts_total, failed_logins = totals["attempts"], totals["failed_logins"]
        latest = [{
            "time": format_datetime_utc(row.time), "ip": row.ip, "username": row.username,
            "service": security_addresses.netfilter_service(row.message)[0],
            "country_code": row.country_code, "country_name": row.country_name,
        } for row in totals["latest"]]

        ordered = sorted(
            (e for e in sources.values() if e["attempts"] > 0),
            key=lambda e: (e["attempts"], e["last_seen"]), reverse=True
        )
        for entry in ordered:
            entry["last_seen"] = format_datetime_utc(entry["last_seen"])

        return {
            "hours": hours,
            "attempts": attempts_total,
            "failed_logins": failed_logins,
            "source_count": len(ordered),
            "sources": ordered[:50],
            "latest": latest,
        }
    except Exception as e:
        logger.error(f"Error building netfilter overview: {e}")
        raise internal_error(e)


def _security_item(a: dict) -> dict:
    return {
        "ip": a["ip"], "state": a["state"], "tries": a["tries"], "attempts": a["attempts"],
        "users": a["users"], "services": a["services"], "hits": a["hits"],
        "country": a["country"], "country_code": a["country_code"], "city": a["city"], "org": a["org"],
        "last_seen": format_datetime_utc(a["last"]), "f2b": a["f2b"], "listed_as": a["listed_as"],
        # A Fail2ban network ban: its size on the network's row, the network on an address's
        "network_size": a.get("network_size"), "network_range": a.get("network_range"),
        "banned_through": a.get("banned_through"),
    }


async def _security_addresses(db: Session, hours: int):
    found = security_addresses.cached(hours)
    if found is None:
        f2b = await mailcow_api.get_fail2ban()
        # An error answer is no answer: its missing lists are not empty ones
        if not security_addresses.fail2ban_answered(f2b):
            f2b = None
        addresses = await run_in_threadpool(security_addresses.collect, db, f2b, None, hours)
        security_addresses.remember(addresses, f2b is not None, hours)
        found = (addresses, f2b is not None)
    return found


@router.get("/security/addresses", responses=documented(m.SecurityAddressesResponse, errors={422: Invalid, 500: None}))
async def get_security_addresses(
    list_name: str = Query("review", alias="list", pattern="^(review|banned)$"),
    country: Optional[str] = Query(None, max_length=100),
    after: Optional[str] = Query(None, max_length=200),
    limit: int = Query(50, ge=1, le=200),
    q: Optional[str] = Query(None, max_length=100),
    network: Optional[str] = Query(None, max_length=200),
    days: int = Query(1, ge=1, le=365, description="The period: addresses that tried in the last days"),
    db: Session = Depends(get_db)
):
    """
    One page of the Security page's To review or Banned list, newest activity
    first, with the real count of both lists (for the country or network, when
    one is given). `after` is the `next` cursor of the page before. `q` keeps the
    addresses that contain it. `days` is the period. `countries` and `networks`
    are counted from the same addresses (every one of the period, whatever is
    picked), and `since` is the oldest log line kept when the logs are shorter.
    """
    try:
        hours = days * 24
        addresses, fail2ban_known = await _security_addresses(db, hours)
        result = security_addresses.page(addresses, list_name, country or None, after, limit, (q or '').strip() or None, network or None)
        result["days"] = days
        result["countries"], result["networks"] = security_addresses.panels(addresses)
        result["since"] = _netfilter_since(db, datetime.now(timezone.utc) - timedelta(hours=hours))
        result["items"] = [_security_item(a) for a in result["items"]]
        result["fail2ban_known"] = fail2ban_known
        return result
    except Exception as e:
        logger.error(f"Error building the security address list: {e}")
        raise internal_error(e)


@router.get("/fail2ban", responses=documented(m.Fail2banResponse, errors={500: None, 503: None}))
async def get_fail2ban():
    """
    Get Fail2Ban configuration from mailcow (real-time)
    """
    try:
        data = await mailcow_api.get_fail2ban()
        
        if data is None:
            raise HTTPException(status_code=503, detail="Could not fetch Fail2Ban configuration from mailcow")
        
        # Single IPv6 addresses an earlier version wrote as /32 networks
        return {**data, "legacy_entries": security_addresses.legacy_entries(data)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching Fail2Ban configuration: {e}")
        raise internal_error(e)


@router.get("/rw-status", responses=documented(m.RwStatusResponse))
def get_rw_status():
    """
    Check if the Read-Write API key is configured.
    Used by all features that require write access (Fail2Ban, Quarantine, etc.)
    """
    return {"rw_configured": mailcow_api.has_rw_key}


_FAIL2BAN_LISTS = ("blacklist", "whitelist")
_LISTS_CHANGED = ("The Fail2ban allowlist or denylist is not the one sent: it changed since it was read, or the "
                  "request tried to change it. Read the settings again, and change the lists with "
                  "/api/fail2ban/ban, /api/fail2ban/allow or /api/fail2ban/remove.")


def _list_entries(value) -> set:
    if isinstance(value, list):
        value = ",".join(str(v) for v in value)
    return set(_split_ip_list(value if isinstance(value, str) else str(value)))


@router.post("/fail2ban", responses=documented(m.ActionResult, errors={400: None, 409: m.ListsChanged, 500: None, 502: None, 503: None}))
async def edit_fail2ban(request: Request):
    """
    Update Fail2Ban configuration on mailcow (requires Read-Write API key).

    Takes the object GET /api/fail2ban returns, but never changes the
    allowlist or denylist: they are read fresh under the lock, so a ban a
    protection rule wrote meanwhile is kept. Lists sent with the settings
    must be the current ones, or the request is refused with 409.
    """
    try:
        body = await request.json()
        attrs = body.get("attr", body) if isinstance(body, dict) else None
        if not isinstance(attrs, dict):
            raise HTTPException(status_code=400, detail="Send the Fail2ban settings as an object")

        async with protection_rules.fail2ban_lock:
            current = await mailcow_api.get_fail2ban()
            if current is None:
                raise HTTPException(status_code=503, detail="Could not fetch current Fail2Ban settings")
            lists = {name: _split_ip_list(current.get(name, "")) for name in _FAIL2BAN_LISTS}
            if any(name in attrs and _list_entries(attrs[name]) != set(lists[name]) for name in _FAIL2BAN_LISTS):
                raise HTTPException(status_code=409, detail={"code": "lists_changed", "message": _LISTS_CHANGED})
            settings_only = {key: value for key, value in attrs.items() if key not in _FAIL2BAN_LISTS}
            result = await mailcow_api.edit_fail2ban(protection_rules.fail2ban_attrs(
                {**current, **settings_only}, lists["blacklist"], lists["whitelist"]))
        
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


# The Fail2ban policy fields and their allowed range, as mailcow's own form takes them
_FAIL2BAN_POLICY = {
    "ban_time": (60, None), "max_ban_time": (60, None), "max_attempts": (1, None),
    "retry_window": (1, None), "netban_ipv4": (8, 32), "netban_ipv6": (8, 128),
}


@router.post("/fail2ban/policy", responses=documented(m.ActionResult, errors=MAILCOW_WRITE))
async def edit_fail2ban_policy(request: Request):
    """
    Change how Fail2ban bans (times, attempts, network size) without touching the
    allowlist and denylist: they are read fresh right before writing, so an address
    added meanwhile in mailcow or by a protection rule is kept. Requires the
    Read-Write API key.
    """
    try:
        body = await request.json()
        policy = {}
        for key, (low, high) in _FAIL2BAN_POLICY.items():
            try:
                value = int(body[key])
            except (KeyError, TypeError, ValueError):
                raise HTTPException(status_code=400, detail=f"'{key}' must be a whole number")
            if value < low or (high is not None and value > high):
                raise HTTPException(status_code=400, detail=f"'{key}' must be between {low} and {high}" if high else f"'{key}' must be at least {low}")
            policy[key] = str(value)
        if int(policy["max_ban_time"]) < int(policy["ban_time"]):
            raise HTTPException(status_code=400, detail="The longest ban cannot be shorter than the first ban")
        policy["ban_time_increment"] = "1" if body.get("ban_time_increment") in (True, 1, "1") else "0"

        async with protection_rules.fail2ban_lock:
            current = await mailcow_api.get_fail2ban()
            if current is None:
                raise HTTPException(status_code=503, detail="Could not fetch current Fail2Ban settings")
            attrs = {**policy,
                     "blacklist": ",".join(_split_ip_list(current.get("blacklist", ""))),
                     "whitelist": ",".join(_split_ip_list(current.get("whitelist", ""))),
                     "manage_external": _manage_external(current)}
            result = await mailcow_api.edit_fail2ban(attrs)
        if isinstance(result, list) and result and result[0].get("type") != "success":
            return {"status": "error", "msg": result[0].get("msg", "Update failed")}
        logger.info("Fail2ban policy changed: %s", policy)
        return {"status": "success", "msg": "Fail2ban policy saved"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating the Fail2Ban policy: {e}")
        raise internal_error(e)

@router.post("/fail2ban/unban", responses=documented(m.ActionResult, errors={400: None, 502: None, 503: None}))
async def unban_fail2ban(request: Request):
    """
    Unban an IP address from Fail2Ban on mailcow (requires Read-Write API key)
    """
    try:
        body = await request.json()
        ip = body.get("ip")
        if not ip:
            raise HTTPException(status_code=400, detail="Missing 'ip' field")
        
        current = await mailcow_api.get_fail2ban()
        if current is None:
            raise HTTPException(status_code=503, detail="Could not fetch current Fail2Ban settings")
        # mailcow answers success to any unban and its netfilter skips one it has no
        # ban for, so only an address Fail2ban banned now is sent, as the ban it is
        networks = _bans_covering(ip, current.get("active_bans"))
        if not networks:
            if any(_same_entry(entry, ip) for entry in _split_ip_list(current.get("blacklist", ""))):
                return {"status": "error", "msg": f"{security_addresses._bare(ip)} is on the denylist. Remove it from the denylist to lift the ban."}
            return {"status": "error", "msg": f"{security_addresses._bare(ip)} is not banned by Fail2ban now"}

        result = await mailcow_api.unban_fail2ban(networks)
        
        # mailcow returns a list with status objects
        if isinstance(result, list) and len(result) > 0:
            first = result[0]
            if first.get("type") != "success":
                return {"status": "error", "msg": first.get("msg", "Unban failed")}
        
        return {"status": "success", "msg": f"{', '.join(networks)} unbanned", "networks": networks}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error unbanning IP from Fail2Ban: {e}")
        if isinstance(e, MailcowShownError):
            raise internal_error(e)
        raise HTTPException(status_code=502, detail="mailcow did not accept the unban. Check the Read-Write API key and try again.")


def _bans_covering(ip: str, active_bans) -> List[str]:
    """The Fail2ban bans that hold the address, by the network mailcow keys them
    with: with netban_ipv4 24, 198.51.100.7 is banned as 198.51.100.0/24."""
    try:
        target = ipaddress.ip_network(ip.strip(), strict=False)
    except ValueError:
        return []
    networks = []
    for ban in active_bans or []:
        key = ban.get("network") if isinstance(ban, dict) else None
        try:
            net = ipaddress.ip_network(key or "", strict=False)
        except ValueError:
            continue
        if net.version == target.version and target.subnet_of(net) and key not in networks:
            networks.append(key)
    # A network is lifted only by its own ban: a wider one around it holds
    # addresses outside it, also when the network's own ban has ended meanwhile
    if target.num_addresses > 1:
        return [key for key in networks if ipaddress.ip_network(key, strict=False) == target]
    return networks


def _split_ip_list(value) -> List[str]:
    """mailcow returns the Fail2ban lists comma or newline separated."""
    return [e.strip() for e in (value or '').replace('\n', ',').split(',') if e.strip()]


def _manage_external(current: dict) -> str:
    """mailcow's 'firewall managed outside mailcow' switch, as an edit must resend it."""
    return "1" if current.get("manage_external") in (True, 1, "1") else "0"


def _same_entry(a: str, b: str) -> bool:
    """1.2.3.4 and 1.2.3.4/32 (or 2001:db8::1 and 2001:db8::1/128) are the same list
    entry; an IPv6 address with /32 is a whole network. Entries are compared as the
    networks mailcow reads them; a hostname by its text."""
    try:
        return ipaddress.ip_network(a.strip(), strict=False) == ipaddress.ip_network(b.strip(), strict=False)
    except ValueError:
        return security_addresses._bare(a) == security_addresses._bare(b)


async def _add_to_fail2ban_list(ip: str, list_name: str, remove: bool = False) -> dict:
    """Add an address to the Fail2ban blacklist or whitelist, or remove it, keeping every
    other setting. The lists are read fresh right before writing, so a change made in
    mailcow meanwhile is not overwritten."""
    async with protection_rules.fail2ban_lock:
        return await _change_fail2ban_list(ip, list_name, remove)


async def _change_fail2ban_list(ip: str, list_name: str, remove: bool) -> dict:
    current = await mailcow_api.get_fail2ban()
    if current is None:
        raise HTTPException(status_code=503, detail="Could not fetch current Fail2Ban settings")

    lists = {name: _split_ip_list(current.get(name, "")) for name in ("blacklist", "whitelist")}
    label = "denylist" if list_name == "blacklist" else "allowlist"
    if remove:
        kept = [entry for entry in lists[list_name] if not _same_entry(entry, ip)]
        if len(kept) == len(lists[list_name]):
            return {"status": "success", "msg": f"IP {ip} is not in the {label}"}
        lists[list_name] = kept
    elif any(_same_entry(entry, ip) for entry in lists[list_name]):
        return {"status": "success", "msg": f"IP {ip} is already in the {label}", "already": True}
    else:
        lists[list_name].append(ip)

    # ban_time_increment must be "1" or "0" as string
    bti = current.get("ban_time_increment", 1)
    attrs = {
        "ban_time": str(current.get("ban_time", "86400")),
        "ban_time_increment": "1" if bti in (True, 1, "1") else "0",
        "blacklist": ",".join(lists["blacklist"]),
        "max_attempts": str(current.get("max_attempts", "5")),
        "max_ban_time": str(current.get("max_ban_time", "86400")),
        "netban_ipv4": str(current.get("netban_ipv4", "24")),
        "netban_ipv6": str(current.get("netban_ipv6", "64")),
        "retry_window": str(current.get("retry_window", "600")),
        "whitelist": ",".join(lists["whitelist"]),
        # mailcow turns this off on any edit that leaves it out
        "manage_external": _manage_external(current),
    }

    logger.info(f"{'Removing' if remove else 'Adding'} IP {ip} {'from' if remove else 'to'} the Fail2Ban {label}")
    result = await mailcow_api.edit_fail2ban(attrs)
    if isinstance(result, list) and len(result) > 0:
        first = result[0]
        if first.get("type") != "success":
            return {"status": "error", "msg": first.get("msg", "Update failed")}
    return {"status": "success", "msg": f"IP {ip} {'removed from' if remove else 'added to'} {label}"}


async def _ip_from_body(request: Request) -> str:
    body = await request.json()
    ip = body.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="Missing 'ip' field")
    return ip


@router.post("/fail2ban/ban", responses=documented(m.ActionResult, errors=MAILCOW_WRITE))
async def ban_fail2ban(request: Request):
    """
    Ban an IP address in Fail2Ban on mailcow by adding it to the blacklist.
    Requires Read-Write API key.
    """
    try:
        return await _add_to_fail2ban_list(await _ip_from_body(request), "blacklist")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error banning IP in Fail2Ban: {e}")
        raise internal_error(e)


@router.post("/fail2ban/allow", responses=documented(m.ActionResult, errors=MAILCOW_WRITE))
async def allow_fail2ban(request: Request):
    """
    Allow an IP address in Fail2Ban on mailcow by adding it to the whitelist,
    so its failed attempts never lead to a ban. Requires Read-Write API key.
    """
    try:
        return await _add_to_fail2ban_list(await _ip_from_body(request), "whitelist")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error allowing IP in Fail2Ban: {e}")
        raise internal_error(e)


@router.post("/fail2ban/remove", responses=documented(m.ActionResult, errors=MAILCOW_WRITE))
async def remove_from_fail2ban_list(request: Request):
    """
    Take an address off the Fail2ban blacklist or whitelist. Body: {"ip", "list":
    "blacklist" | "whitelist"}. Requires Read-Write API key.
    """
    try:
        body = await request.json()
        ip, list_name = body.get("ip"), body.get("list")
        if not ip:
            raise HTTPException(status_code=400, detail="Missing 'ip' field")
        if list_name not in ("blacklist", "whitelist"):
            raise HTTPException(status_code=400, detail="'list' must be blacklist or whitelist")
        return await _add_to_fail2ban_list(ip, list_name, remove=True)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing IP from the Fail2Ban list: {e}")
        raise internal_error(e)


@router.post("/fail2ban/repair", responses=documented(m.ActionResult, errors=MAILCOW_WRITE))
async def repair_fail2ban_entry(request: Request):
    """
    Replace an entry an earlier version wrote as a /32 network (2001:db8::1/32) with
    the single address it was meant to be (2001:db8::1/128), in one edit, then read
    the list back to confirm it. Body: {"entry", "list": "blacklist" | "whitelist"}.
    Requires Read-Write API key.
    """
    try:
        body = await request.json()
        entry, list_name = (body.get("entry") or "").strip(), body.get("list")
        if list_name not in ("blacklist", "whitelist"):
            raise HTTPException(status_code=400, detail="'list' must be blacklist or whitelist")
        address = security_addresses.legacy_ipv6_entry(entry)
        if not address:
            raise HTTPException(status_code=400, detail=f"{entry} is not a single address written as a /32 network")
        single = f"{address}/128"

        async with protection_rules.fail2ban_lock:
            current = await mailcow_api.get_fail2ban()
            if current is None:
                raise HTTPException(status_code=503, detail="Could not fetch current Fail2Ban settings")
            lists = {name: _split_ip_list(current.get(name, "")) for name in ("blacklist", "whitelist")}
            if entry not in lists[list_name]:
                return {"status": "error", "msg": f"{entry} is no longer on the list"}
            # The address takes the old entry's place, once if the list holds it already
            lists[list_name] = list(dict.fromkeys(single if e == entry else e for e in lists[list_name]))

            logger.info(f"Replacing {entry} with {single} on the Fail2Ban {list_name}")
            result = await mailcow_api.edit_fail2ban(
                protection_rules.fail2ban_attrs(current, lists["blacklist"], lists["whitelist"]))
            failed = [m for m in result if isinstance(m, dict) and m.get("type") != "success"] if isinstance(result, list) else []
            if failed:
                return {"status": "error", "msg": failed[0].get("msg", "Update failed")}

            after = await mailcow_api.get_fail2ban()
        written = _split_ip_list((after or {}).get(list_name, ""))
        if after is None or entry in written or single not in written:
            return {"status": "error", "msg": "mailcow took the change, but the list did not show it when checked. Refresh to see what it holds."}
        return {"status": "success", "msg": f"{entry} replaced with {single}"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error repairing a Fail2Ban list entry: {e}")
        raise internal_error(e)


@router.get("/geoip/{ip}", responses=documented(m.GeoIpResponse))
def lookup_geoip(ip: str):
    """
    Lookup GeoIP information for an IP address.
    Returns country, city, ASN info when MaxMind databases are available.
    """
    if not geoip_service.is_geoip_available():
        return {"available": False}
    
    geo = geoip_service.lookup_ip(ip)
    return {"available": True, "ip": ip, **geo}


def _queue_time_key(item: dict):
    """Sort key: (has a time, the time). A number or a numeric string is a time;
    anything else, such as text or a missing value, sorts after every time."""
    value = item.get('arrival_time')
    if isinstance(value, bool):
        return (False, 0.0)
    try:
        number = float(value)  # a number too large for a float raises OverflowError
    except (TypeError, ValueError, OverflowError):
        return (False, 0.0)
    return (True, number) if math.isfinite(number) else (False, 0.0)


@router.get("/queue", responses=documented(m.QueueResponse, errors={502: None}))
async def get_queue():
    """
    Get current mail queue from mailcow (real-time)
    Returns messages sorted by newest first (by arrival_time)
    """
    try:
        queue = await mailcow_api.get_queue()

        # Sort by arrival_time - newest first (descending order)
        # arrival_time is a Unix timestamp; an item without a readable one goes last
        for item in queue:
            if isinstance(item.get('arrival_time'), float) and not math.isfinite(item['arrival_time']):
                item['arrival_time'] = None  # NaN and infinity are not JSON
        queue_sorted = sorted(queue, key=_queue_time_key, reverse=True)  # Newest first
        
        return {
            "total": len(queue_sorted),
            "data": queue_sorted
        }
    except Exception as e:
        logger.error(f"Error fetching queue: {e}")
        raise internal_error(e)


@router.post("/queue/action", responses=documented(m.ActionResult, errors=MAILCOW_ITEMS))
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


@router.post("/queue/delete", responses=documented(m.ActionResult, errors=MAILCOW_ITEMS))
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


@router.get("/quarantine", responses=documented(m.QuarantineResponse, errors={502: None}))
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
                    try:
                        dt = datetime.fromtimestamp(item['created'], tz=timezone.utc)
                    except (OverflowError, OSError, ValueError):
                        # A time mailcow cannot have meant (or NaN, which the
                        # answer cannot carry): the item is shown without one
                        item['created'] = None
                        continue
                    item['created'] = format_datetime_utc(dt)
                    # Sort on the number, like the ISO branch (not on the string)
                    item['_created_timestamp'] = dt.timestamp()
                elif isinstance(item['created'], str):
                    # Parse ISO string and ensure it has 'Z' suffix for UTC
                    try:
                        dt = as_utc(datetime.fromisoformat(item['created'].replace('Z', '+00:00')))
                        item['created'] = format_datetime_utc(dt)
                        # Store the datetime object for sorting
                        item['_created_timestamp'] = dt.timestamp()
                    except (ValueError, AttributeError):
                        pass
        
        # Sort by created timestamp - newest first (descending order)
        # Items without valid timestamp will be at the end, after times before 1970 too
        quarantine_sorted = sorted(
            quarantine,
            key=lambda x: ('_created_timestamp' in x, x.get('_created_timestamp', 0)),
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




@router.post("/quarantine/release", responses=documented(m.ActionResult, errors=MAILCOW_ITEMS))
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


@router.post("/quarantine/delete", responses=documented(m.ActionResult, errors=MAILCOW_ITEMS))
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


@router.post("/quarantine/learnham", responses=documented(m.ActionResult, errors=MAILCOW_ITEMS))
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


@router.post("/quarantine/learnspam", responses=documented(m.ActionResult, errors=MAILCOW_ITEMS))
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


@router.get("/quarantine/{item_id}/details", responses=documented(m.QuarantineDetailsResponse, errors={502: None}))
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


@router.get("/message/{correlation_key}", responses=documented(m.CompactMessageResponse, errors={404: None, 500: None}))
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
        
        if not correlation or excluded_addresses.any_listed(correlation.sender, correlation.recipient):
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
        
        if excluded_addresses.delivery_hidden(correlation, postfix_logs):
            raise HTTPException(status_code=404, detail="Message not found")
        postfix_logs = excluded_addresses.visible_postfix_lines(postfix_logs)

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
            "first_seen": format_datetime_utc(correlation.first_seen),
            "last_seen": format_datetime_utc(correlation.last_seen),
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
                    "time": format_datetime_utc(log.time),
                    "program": log.program,
                    "message": log.message,
                    "status": log.status,
                    "relay": log.relay,
                    "delay": log.delay
                }
                for log in postfix_logs
            ],
            # Sorted on the stored times, then sent as UTC with Z like every other time
            "timeline": [
                dict(event, time=format_datetime_utc(event["time"])) if event else None
                for event in sorted([
                    {"time": correlation.first_seen, "event": "Message received"},
                    *[{"time": log.time, "event": f"Postfix: {log.status}"} for log in postfix_logs if log.status],
                    {"time": rspamd_log.time, "event": f"Rspamd: {rspamd_log.action}"} if rspamd_log else None
                ], key=lambda x: x["time"] if x else datetime.min)
            ] if correlation.first_seen else []
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching message details: {e}")
        raise internal_error(e)
