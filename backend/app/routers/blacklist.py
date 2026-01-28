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
async def get_monitored_hosts() -> Dict[str, Any]:
    """
    Get list of all monitored hosts and their latest status
    """
    try:
        with get_db_context() as db:
            # Get all active hosts
            hosts = db.query(MonitoredHost).filter(MonitoredHost.active == True).all()
            # If no hosts, try to initialize with local IP
            if not hosts:
                ip = get_cached_server_ip()
                if ip:
                    db.add(MonitoredHost(hostname=ip, source="system", active=True, last_seen=datetime.utcnow()))
                    db.commit()
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
        
    # If host specified, check single host
    import re
    import dns.asyncresolver
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_ip):
         try:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            answers = await resolver.resolve(target_ip, 'A')
            if answers:
                target_ip = str(answers[0])
         except Exception:
             pass # use hostname as is if resolution fails
             
    try:
        results = await get_blacklist_check_results(force=force, ip=target_ip)
        return results
    except Exception as e:
        logger.error(f"Error checking blacklists: {type(e).__name__} - {str(e)}")
        return {
            "server_ip": target_ip,
            "checked_at": datetime.now(timezone.utc).isoformat() + 'Z',
            "total_blacklists": len(BLACKLISTS),
            "listed_count": 0,
            "clean_count": 0,
            "error_count": 1,
            "timeout_count": 0,
            "status": "error",
            "error": str(e),
            "results": []
        }

@router.get("/progress")
async def get_progress() -> Dict[str, Any]:
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
async def get_blacklist_config() -> Dict[str, Any]:
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
async def get_blacklist_summary() -> Dict[str, Any]:
    """
    Get compact blacklist status summary for dashboard
    """
    ip = get_cached_server_ip()
    cached = get_cached_blacklist_check(ip) if ip else None
    
    if not cached:
        return {
            "has_data": False,
            "server_ip": ip,
            "status": "unknown",
            "listed_count": 0,
            "total_blacklists": len(BLACKLISTS),
            "checked_at": None
        }
    
    return {
        "has_data": True,
        "server_ip": cached.get("server_ip"),
        "status": cached.get("status", "unknown"),
        "listed_count": cached.get("listed_count", 0),
        "total_blacklists": cached.get("total_blacklists", len(BLACKLISTS)),
        "checked_at": cached.get("checked_at")
    }
