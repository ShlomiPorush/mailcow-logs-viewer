"""
API endpoints for IP blacklist checking
"""
import logging
from fastapi import APIRouter, Query
from datetime import datetime, timezone, timedelta
from typing import Dict, Any
from sqlalchemy import desc

from app.services.blacklist_service import (
    get_blacklist_check_results,
    get_cached_blacklist_check,
    get_check_progress,
    BLACKLISTS,
    CACHE_TTL_HOURS,
    check_all_blacklists
)
from app.routers.domains import get_cached_server_ip, init_server_ip
from app.database import get_db_context
from app.models import MonitoredHost, BlacklistCheck

logger = logging.getLogger(__name__)

router = APIRouter()

def format_datetime(dt: datetime) -> str:
    """Format datetime as UTC ISO string"""
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')

@router.get("/monitored")
def get_monitored_hosts() -> Dict[str, Any]:
    """
    Get list of all monitored hosts and their latest status.
    Sync def: the reconcile + per-host queries run in the threadpool,
    off the event loop.
    """
    try:
        with get_db_context() as db:
            # Align with current settings first, so a just-saved blacklist
            # source toggle or manual-hosts change is reflected immediately
            # instead of waiting for the next scheduled scan
            from app.services.blacklist_service import reconcile_monitored_hosts
            reconcile_monitored_hosts(db)
            hosts = db.query(MonitoredHost).filter(MonitoredHost.active == True).all()
            results = []
            for host in hosts:
                # Get latest check for this host
                check = db.query(BlacklistCheck).filter(
                    BlacklistCheck.server_ip == host.hostname
                ).order_by(desc(BlacklistCheck.checked_at)).first()
                
                status_data = {
                    "hostname": host.hostname,
                    "source": host.source,
                    "last_seen": format_datetime(host.last_seen),
                    "has_data": False,
                    "status": "unknown"
                }
                
                if check:
                    age = datetime.now(timezone.utc) - check.checked_at.replace(tzinfo=timezone.utc)
                    is_valid = age <= timedelta(hours=CACHE_TTL_HOURS)
                    
                    status_data.update({
                        "has_data": True,
                        "status": check.status,
                        "listed_count": check.listed_count,
                        "total_blacklists": check.total_blacklists,
                        "checked_at": format_datetime(check.checked_at),
                        "cache_valid": is_valid,
                        "results": check.results or []
                    })
                
                results.append(status_data)
                
            return {"hosts": results}
    except Exception as e:
        logger.error(f"Error getting monitored hosts: {e}")
        return {"hosts": []}

@router.get("/check")
async def check_blacklists(
    host: str = Query(None, description="Host/IP to check (default: system IP)"),
    force: bool = Query(False, description="Force new check ignoring cache")
) -> Dict[str, Any]:
    """
    Get IP blacklist check results for a specific host
    """
    target_ip = host
    
    # If no host specified, check ALL monitored hosts (background job)
    if not target_ip:
        from ..scheduler import check_monitored_hosts_job
        import asyncio
        # Trigger background job without awaiting it
        asyncio.create_task(check_monitored_hosts_job(force=force))
        return {"status": "started", "message": "Background check started for all hosts"}
        
    # If host specified, check single host.
    # IP literals (IPv4 or IPv6) are used as-is; hostnames are resolved.
    import ipaddress
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
         try:
            from app.services.dns_resolver import resolve
            answers = await resolve(target_ip, 'A', timeout=5)
            if answers:
                target_ip = str(answers[0])
         except Exception:
              pass # use hostname as is if resolution fails
             
    try:
        results = await get_blacklist_check_results(force=force, ip=target_ip)
        return results
    except Exception as e:
        logger.error(f"Error checking blacklists: {type(e).__name__} - {str(e)}")
        from app.services.blacklist_service import applicable_blacklists
        return {
            "server_ip": target_ip,
            "checked_at": datetime.now(timezone.utc).isoformat() + 'Z',
            "total_blacklists": len(applicable_blacklists(target_ip)) if target_ip else len(BLACKLISTS),
            "listed_count": 0,
            "clean_count": 0,
            "error_count": 1,
            "timeout_count": 0,
            "status": "error",
            "error": "Unable to check blacklists. Check the application logs.",
            "results": []
        }

@router.get("/progress")
def get_progress() -> Dict[str, Any]:
    """
    Get current blacklist check progress (for UI progress bar)
    """
    progress = get_check_progress()
    return {
        "in_progress": progress["in_progress"],
        "current": progress["current"],
        "total": progress["total"],
        "current_blacklist": progress["current_blacklist"],
        "percent": int((progress["current"] / progress["total"]) * 100) if progress["total"] > 0 else 0
    }

@router.get("/config")
def get_blacklist_config() -> Dict[str, Any]:
    """
    Get blacklist check configuration and status
    """
    ip = get_cached_server_ip()
    cached = get_cached_blacklist_check(ip) if ip else None
    
    return {
        "total_blacklists": len(BLACKLISTS),
        "cache_ttl_hours": CACHE_TTL_HOURS,
        "cache_valid": cached is not None,
        "last_check": cached.get("checked_at") if cached else None,
        "server_ip": ip,
        "listed_count": cached.get("listed_count", 0) if cached else None,
        "status": cached.get("status") if cached else None
    }

@router.get("/summary")
def get_blacklist_summary() -> Dict[str, Any]:
    """
    Get compact blacklist status summary for dashboard.

    Aggregates the latest check of every ACTIVE monitored host (WAN IP,
    manual hosts, transports/relayhosts) instead of only the auto-detected
    WAN IP, so the card still has data when the server IP source is
    disabled. Sync def on purpose: DB work runs in the threadpool,
    off the event loop.
    """
    from sqlalchemy import func
    from app.services.blacklist_service import aggregate_blacklist_summary

    host_rows = []
    try:
        with get_db_context() as db:
            hosts = db.query(MonitoredHost.hostname, MonitoredHost.source).filter(
                MonitoredHost.active == True
            ).order_by(MonitoredHost.id).all()

            latest_by_ip = {}
            hostnames = [h.hostname for h in hosts]
            if hostnames:
                # Latest check per host in ONE query (window function) and
                # only the summary columns - the full results JSONB is never
                # loaded here.
                rn = func.row_number().over(
                    partition_by=BlacklistCheck.server_ip,
                    order_by=desc(BlacklistCheck.checked_at)
                ).label("rn")
                subq = db.query(
                    BlacklistCheck.server_ip,
                    BlacklistCheck.status,
                    BlacklistCheck.listed_count,
                    BlacklistCheck.total_blacklists,
                    BlacklistCheck.checked_at,
                    rn
                ).filter(BlacklistCheck.server_ip.in_(hostnames)).subquery()
                for row in db.query(subq).filter(subq.c.rn == 1).all():
                    latest_by_ip[row.server_ip] = row

            for h in hosts:
                check = latest_by_ip.get(h.hostname)
                host_rows.append({
                    "hostname": h.hostname,
                    "source": h.source,
                    "status": check.status if check else None,
                    "listed_count": check.listed_count if check else None,
                    "total_blacklists": check.total_blacklists if check else None,
                    "checked_at": check.checked_at if check else None
                })
    except Exception as e:
        logger.error(f"Error building blacklist summary: {e}")
        host_rows = []

    return aggregate_blacklist_summary(host_rows, server_ip=get_cached_server_ip())
