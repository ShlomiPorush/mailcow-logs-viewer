"""
IP Blacklist Checking Service
Checks mail server IP against DNS-based blacklists (DNSBLs/RBLs)
Results are persisted in database for 24 hours.
"""
import logging
import asyncio
import dns.asyncresolver
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy import desc

logger = logging.getLogger(__name__)

# Blacklist zones to check
BLACKLISTS = [
    # Major blacklists
    {"name": "Spamhaus ZEN", "zone": "zen.spamhaus.org", "info_url": "https://www.spamhaus.org/lookup/"},
    {"name": "Spamhaus SBL", "zone": "sbl.spamhaus.org", "info_url": "https://www.spamhaus.org/lookup/"},
    {"name": "Spamhaus XBL", "zone": "xbl.spamhaus.org", "info_url": "https://www.spamhaus.org/lookup/"},
    {"name": "Spamhaus PBL", "zone": "pbl.spamhaus.org", "info_url": "https://www.spamhaus.org/lookup/"},
    {"name": "Barracuda", "zone": "b.barracudacentral.org", "info_url": "https://www.barracudacentral.org/lookups"},
    {"name": "SpamCop", "zone": "bl.spamcop.net", "info_url": "https://www.spamcop.net/bl.shtml"},
    {"name": "Composite Blocking List", "zone": "cbl.abuseat.org", "info_url": "https://www.abuseat.org/lookup.cgi"},
    
    # SORBS
    {"name": "SORBS DNSBL", "zone": "dnsbl.sorbs.net", "info_url": "http://www.sorbs.net/lookup.shtml"},
    {"name": "SORBS HTTP", "zone": "http.dnsbl.sorbs.net", "info_url": "http://www.sorbs.net/lookup.shtml"},
    {"name": "SORBS SOCKS", "zone": "socks.dnsbl.sorbs.net", "info_url": "http://www.sorbs.net/lookup.shtml"},
    {"name": "SORBS MISC", "zone": "misc.dnsbl.sorbs.net", "info_url": "http://www.sorbs.net/lookup.shtml"},
    {"name": "SORBS SMTP", "zone": "smtp.dnsbl.sorbs.net", "info_url": "http://www.sorbs.net/lookup.shtml"},
    {"name": "SORBS WEB", "zone": "web.dnsbl.sorbs.net", "info_url": "http://www.sorbs.net/lookup.shtml"},
    {"name": "SORBS SPAM", "zone": "spam.dnsbl.sorbs.net", "info_url": "http://www.sorbs.net/lookup.shtml"},
    {"name": "SORBS ZOMBIE", "zone": "zombie.dnsbl.sorbs.net", "info_url": "http://www.sorbs.net/lookup.shtml"},
    {"name": "SORBS DUL", "zone": "dul.dnsbl.sorbs.net", "info_url": "http://www.sorbs.net/lookup.shtml"},
    
    # UCEPROTECT
    {"name": "UCEPROTECT Level 1", "zone": "dnsbl-1.uceprotect.net", "info_url": "https://www.uceprotect.net/en/rblcheck.php"},
    {"name": "UCEPROTECT Level 2", "zone": "dnsbl-2.uceprotect.net", "info_url": "https://www.uceprotect.net/en/rblcheck.php"},
    {"name": "UCEPROTECT Level 3", "zone": "dnsbl-3.uceprotect.net", "info_url": "https://www.uceprotect.net/en/rblcheck.php"},
    
    # Other commonly used
    {"name": "PSBL", "zone": "psbl.surriel.com", "info_url": "https://psbl.org/"},
    {"name": "Truncate", "zone": "truncate.gbudb.net", "info_url": "https://www.gbudb.com/"},
    {"name": "invaluement", "zone": "ivmSIP.invaluement.com", "info_url": "https://www.invaluement.com/lookup/"},
    {"name": "invaluement SIP/24", "zone": "ivmSIP24.invaluement.com", "info_url": "https://www.invaluement.com/lookup/"},

    {"name": "Hostkarma Black", "zone": "hostkarma.junkemailfilter.com", "info_url": "http://wiki.junkemailfilter.com/index.php/Spam_DNS_Lists"},
    {"name": "JustSpam", "zone": "dnsbl.justspam.org", "info_url": "http://www.justspam.org/"},

    {"name": "Mailspike BL", "zone": "bl.mailspike.net", "info_url": "https://www.mailspike.org/"},
    {"name": "Mailspike Z", "zone": "z.mailspike.net", "info_url": "https://www.mailspike.org/"},

    {"name": "s5h.net", "zone": "all.s5h.net", "info_url": "http://www.s5h.net/"},
    {"name": "Blocklist.de", "zone": "bl.blocklist.de", "info_url": "https://www.blocklist.de/en/search.html"},
    {"name": "Spamhaus DBL", "zone": "dbl.spamhaus.org", "info_url": "https://www.spamhaus.org/lookup/"},
    {"name": "SURBL", "zone": "multi.surbl.org", "info_url": "https://www.surbl.org/"},
    {"name": "0spam", "zone": "bl.0spam.org", "info_url": "https://www.0spam.org/"},

    {"name": "DRONE BL", "zone": "dnsbl.dronebl.org", "info_url": "https://dronebl.org/lookup"},
    {"name": "EFnet RBL", "zone": "rbl.efnetrbl.org", "info_url": "http://rbl.efnetrbl.org/"},
    {"name": "KEMPT", "zone": "dnsbl.kempt.net", "info_url": "https://www.kempt.net/"},
    {"name": "Lashback", "zone": "ubl.lashback.com", "info_url": "https://www.lashback.com/"},
    {"name": "MegaRBL", "zone": "rbl.megarbl.net", "info_url": "https://www.megarbl.net/check"},
    {"name": "Nordspam", "zone": "bl.nordspam.com", "info_url": "https://www.nordspam.com/"},
    {"name": "Abuse.ro", "zone": "rbl.abuse.ro", "info_url": "https://abuse.ro/"},

    {"name": "SEM FRESH", "zone": "fresh.spameatingmonkey.net", "info_url": "https://spameatingmonkey.com/"},
    {"name": "SEM URIRED", "zone": "urired.spameatingmonkey.net", "info_url": "https://spameatingmonkey.com/"},
]

# Blacklists that should NOT trigger a notification if they are the ONLY ones listed
# (e.g. because they are paid removal / unremovable / broad policy)
IGNORED_NOTIFICATION_BLACKLISTS = [
    "UCEPROTECT Level 2",
    "UCEPROTECT Level 3",
]

# Cache TTL: 24 hours
CACHE_TTL_HOURS = 24

# Progress tracking for UI
_check_progress: Dict[str, Any] = {
    "in_progress": False,
    "current": 0,
    "total": len(BLACKLISTS),
    "current_blacklist": None,
    "percent": 0
}

_batch_state: Dict[str, Any] = {
    "active": False,
    "total_hosts": 0,
    "processed_hosts": 0
}


def get_check_progress() -> Dict[str, Any]:
    """Get current check progress for UI"""
    p = _check_progress.copy()
    if p["total"] > 0:
        p["percent"] = int((p["current"] / p["total"]) * 100)
    return p

def start_batch_scan(total_hosts: int):
    """Start a batch scan session"""
    global _batch_state, _check_progress
    _batch_state["active"] = True
    _batch_state["total_hosts"] = total_hosts
    _batch_state["processed_hosts"] = 0
    _check_progress["in_progress"] = True
    _check_progress["current"] = 0
    _check_progress["total"] = total_hosts * len(BLACKLISTS)
    _check_progress["current_blacklist"] = "Initializing batch scan..."

def end_batch_scan():
    """End a batch scan session"""
    global _batch_state, _check_progress
    _batch_state["active"] = False
    _check_progress["in_progress"] = False
    _check_progress["current"] = _check_progress["total"]
    _check_progress["current_blacklist"] = None

def update_batch_status(message: str):
    """Update status message during cooldown"""
    global _check_progress
    _check_progress["current_blacklist"] = message

def mark_host_as_processed_batch():
    """
    Manually mark a host as processed for batch progress tracking.
    Used when a host is skipped due to cache but we still need to advance the progress bar.
    """
    global _batch_state, _check_progress
    
    if _batch_state["active"]:
        _batch_state["processed_hosts"] += 1
        _check_progress["current"] = _batch_state["processed_hosts"] * len(BLACKLISTS)

def reverse_ip(ip: str) -> str:
    """Reverse IP address for DNSBL lookup (1.2.3.4 -> 4.3.2.1)"""
    parts = ip.split('.')
    return '.'.join(reversed(parts))

def get_cached_blacklist_check(ip: str) -> Optional[Dict[str, Any]]:
    """
    Get cached blacklist check from database if still valid (within 24h)
    """
    from app.database import get_db_context
    from app.models import BlacklistCheck
    
    try:
        with get_db_context() as db:
            # Find most recent check for this IP
            check = db.query(BlacklistCheck).filter(
                BlacklistCheck.server_ip == ip
            ).order_by(desc(BlacklistCheck.checked_at)).first()
            
            if not check:
                return None
            
            # Check if still valid (within 24 hours)
            age = datetime.now(timezone.utc) - check.checked_at.replace(tzinfo=timezone.utc)
            if age > timedelta(hours=CACHE_TTL_HOURS):
                return None
            
            # Check if configuration changed (number of blacklists)
            if check.total_blacklists != len(BLACKLISTS):
                logger.info(f"Blacklist configuration changed (stored: {check.total_blacklists}, current: {len(BLACKLISTS)}). Invalidating cache.")
                return None
            
            # Return cached data
            return {
                "server_ip": check.server_ip,
                "checked_at": check.checked_at.isoformat() + 'Z',
                "total_blacklists": check.total_blacklists,
                "listed_count": check.listed_count,
                "clean_count": check.clean_count,
                "error_count": check.error_count,
                "timeout_count": check.timeout_count,
                "status": check.status,
                "results": check.results or []
            }
    except Exception as e:
        logger.error(f"Error getting cached blacklist check: {e}")
        return None

def save_blacklist_check(data: Dict[str, Any]) -> None:
    """
    Save blacklist check results to database
    """
    from app.database import get_db_context
    from app.models import BlacklistCheck
    
    try:
        with get_db_context() as db:
            check = BlacklistCheck(
                server_ip=data["server_ip"],
                total_blacklists=data["total_blacklists"],
                listed_count=data["listed_count"],
                clean_count=data["clean_count"],
                error_count=data["error_count"],
                timeout_count=data["timeout_count"],
                status=data["status"],
                results=data["results"],
                checked_at=datetime.now(timezone.utc)
            )
            db.add(check)
            db.commit()
            logger.info(f"Saved blacklist check to DB: {data['status']} ({data['listed_count']} listed)")
    except Exception as e:
        logger.error(f"Error saving blacklist check: {e}")

def reverse_ip(ip: str) -> str:
    """Reverse IP address for DNSBL lookup (1.2.3.4 -> 4.3.2.1)"""
    parts = ip.split('.')
    return '.'.join(reversed(parts))

def get_cached_blacklist_check(ip: str) -> Optional[Dict[str, Any]]:
    """
    Get cached blacklist check from database if still valid (within 24h)
    """
    from app.database import get_db_context
    from app.models import BlacklistCheck
    
    try:
        with get_db_context() as db:
            # Find most recent check for this IP
            check = db.query(BlacklistCheck).filter(
                BlacklistCheck.server_ip == ip
            ).order_by(desc(BlacklistCheck.checked_at)).first()
            
            if not check:
                return None
            
            # Check if still valid (within 24 hours)
            age = datetime.now(timezone.utc) - check.checked_at.replace(tzinfo=timezone.utc)
            if age > timedelta(hours=CACHE_TTL_HOURS):
                return None
            
            # Check if configuration changed (number of blacklists)
            if check.total_blacklists != len(BLACKLISTS):
                logger.info(f"Blacklist configuration changed (stored: {check.total_blacklists}, current: {len(BLACKLISTS)}). Invalidating cache.")
                return None
            
            # Return cached data
            return {
                "server_ip": check.server_ip,
                "checked_at": check.checked_at.isoformat() + 'Z',
                "total_blacklists": check.total_blacklists,
                "listed_count": check.listed_count,
                "clean_count": check.clean_count,
                "error_count": check.error_count,
                "timeout_count": check.timeout_count,
                "status": check.status,
                "results": check.results or []
            }
    except Exception as e:
        logger.error(f"Error getting cached blacklist check: {e}")
        return None

def save_blacklist_check(data: Dict[str, Any]) -> None:
    """
    Save blacklist check results to database
    """
    from app.database import get_db_context
    from app.models import BlacklistCheck
    
    try:
        with get_db_context() as db:
            check = BlacklistCheck(
                server_ip=data["server_ip"],
                total_blacklists=data["total_blacklists"],
                listed_count=data["listed_count"],
                clean_count=data["clean_count"],
                error_count=data["error_count"],
                timeout_count=data["timeout_count"],
                status=data["status"],
                results=data["results"],
                checked_at=datetime.now(timezone.utc)
            )
            db.add(check)
            db.commit()
            logger.info(f"Saved blacklist check to DB: {data['status']} ({data['listed_count']} listed)")
    except Exception as e:
        logger.error(f"Error saving blacklist check: {e}")

async def check_ip_in_blacklist(ip: str, blacklist: Dict[str, str], index: int) -> Dict[str, Any]:
    """
    Check if IP is listed in a single blacklist using DNS query
    
    Args:
        ip: IP address to check
        blacklist: Dict with 'name', 'zone', 'info_url'
        index: Index for progress tracking
    
    Returns:
        Dict with check result
    """
    global _check_progress, _batch_state
    
    current_idx = index + 1
    if _batch_state.get("active", False):
        # Add offset from processed hosts
        current_idx += (_batch_state.get("processed_hosts", 0) * len(BLACKLISTS))
        
    _check_progress["current"] = current_idx
    _check_progress["current_blacklist"] = blacklist["name"]
    
    reversed_ip = reverse_ip(ip)
    query = f"{reversed_ip}.{blacklist['zone']}"
    
    try:
        resolver = dns.asyncresolver.Resolver()
        # Use external DNS servers to avoid Docker's internal DNS issues
        resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
        resolver.timeout = 10
        resolver.lifetime = 10
        
        answers = await resolver.resolve(query, 'A')
        
        # If we get a response, check if it's a real listing or a blocked-query response
        response_ips = [str(rdata) for rdata in answers]
        response = response_ips[0] if response_ips else None
        
        # Spamhaus returns 127.255.255.x codes to indicate blocked queries
        if response and response.startswith('127.255.'):
            logger.debug(f"{blacklist['name']}: Blocked query response {response} - treating as clean")
            return {
                "name": blacklist["name"],
                "zone": blacklist["zone"],
                "info_url": blacklist.get("info_url", ""),
                "status": "clean",
                "listed": False,
                "response": None
            }
        
        # Valid listing response (127.0.0.x for most blacklists)
        return {
            "name": blacklist["name"],
            "zone": blacklist["zone"],
            "info_url": blacklist.get("info_url", ""),
            "status": "listed",
            "listed": True,
            "response": response
        }
        
    except dns.resolver.NXDOMAIN:
        return {
            "name": blacklist["name"],
            "zone": blacklist["zone"],
            "info_url": blacklist.get("info_url", ""),
            "status": "clean",
            "listed": False,
            "response": None
        }
    except dns.resolver.NoAnswer:
        return {
            "name": blacklist["name"],
            "zone": blacklist["zone"],
            "info_url": blacklist.get("info_url", ""),
            "status": "clean",
            "listed": False,
            "response": None
        }
    except dns.resolver.NoNameservers as e:
        logger.debug(f"{blacklist['name']}: NoNameservers - {str(e)}")
        return {
            "name": blacklist["name"],
            "zone": blacklist["zone"],
            "info_url": blacklist.get("info_url", ""),
            "status": "error",
            "listed": False,
            "response": "DNS Error"
        }
    except dns.exception.Timeout:
        return {
            "name": blacklist["name"],
            "zone": blacklist["zone"],
            "info_url": blacklist.get("info_url", ""),
            "status": "timeout",
            "listed": False,
            "response": None
        }
    except Exception as e:
        logger.warning(f"Error checking {blacklist['name']}: {type(e).__name__} - {str(e)}")
        return {
            "name": blacklist["name"],
            "zone": blacklist["zone"],
            "info_url": blacklist.get("info_url", ""),
            "status": "error",
            "listed": False,
            "response": str(e)
        }


async def check_all_blacklists(ip: str) -> Dict[str, Any]:
    """
    Check IP against all blacklists concurrently
    
    Args:
        ip: IP address to check
    
    Returns:
        Dict with all results and summary
    """
    global _check_progress, _batch_state
    
    # Only reset progress if NOT in batch mode
    if not _batch_state.get("active", False):
        _check_progress["in_progress"] = True
        _check_progress["current"] = 0
        _check_progress["total"] = len(BLACKLISTS)
    
    logger.info(f"Starting blacklist check for IP: {ip}")
    
    try:
        # Run all checks concurrently with index for progress tracking
        tasks = [check_ip_in_blacklist(ip, bl, i) for i, bl in enumerate(BLACKLISTS)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        processed_results = []
        listed_count = 0
        clean_count = 0
        error_count = 0
        timeout_count = 0
        
        for result in results:
            if isinstance(result, Exception):
                processed_results.append({
                    "name": "Unknown",
                    "zone": "unknown",
                    "info_url": "",
                    "status": "error",
                    "listed": False,
                    "response": str(result)
                })
                error_count += 1
            else:
                processed_results.append(result)
                if result["listed"]:
                    listed_count += 1
                elif result["status"] == "clean":
                    clean_count += 1
                elif result["status"] == "timeout":
                    timeout_count += 1
                else:
                    error_count += 1
        
        # Sort results: listed first, then clean, then errors
        processed_results.sort(key=lambda x: (
            0 if x["listed"] else (1 if x["status"] == "clean" else 2),
            x["name"]
        ))
        
        # Determine overall status
        if listed_count > 0:
            status = "listed"
        elif error_count + timeout_count > len(BLACKLISTS) / 2:
            status = "error"
        else:
            status = "clean"
        
        data = {
            "server_ip": ip,
            "checked_at": datetime.now(timezone.utc).isoformat() + 'Z',
            "total_blacklists": len(BLACKLISTS),
            "listed_count": listed_count,
            "clean_count": clean_count,
            "error_count": error_count,
            "timeout_count": timeout_count,
            "status": status,
            "results": processed_results
        }
        
        # Save to database
        save_blacklist_check(data)
        
        logger.info(f"Blacklist check complete: {listed_count} listed, {clean_count} clean, {error_count} errors")
        
        return data
        
    finally:
        if not _batch_state.get("active", False):
            _check_progress["in_progress"] = False
            _check_progress["current"] = len(BLACKLISTS)
            _check_progress["current_blacklist"] = None
        else:
            # Batch mode: Mark this host as done
            _batch_state["processed_hosts"] += 1
            # Current becomes exact total for this host chunk
            # Actually, check_ip_in_blacklist increments it to exactly the end of this chunk?
            # Yes, index goes to 49. so (processed * 50) + 50.
            # But wait, processed_hosts incremented AFTER loop.
            # So inside loop, processed=0. index=49. current=50.
            # Next host. processed=1. index=0. current = 51. Correct.
            pass


async def get_blacklist_check_results(force: bool = False, ip: Optional[str] = None) -> Dict[str, Any]:
    """
    Get blacklist check results (from DB cache or perform new check)
    
    Args:
        force: Force new check ignoring cache
        ip: IP address to check (if None, will try to get from domains cache)
    
    Returns:
        Dict with blacklist check results
    """
    # Get IP if not provided
    if not ip:
        from app.routers.domains import get_cached_server_ip, init_server_ip
        ip = get_cached_server_ip()
        if not ip:
            ip = await init_server_ip()
    
    if not ip:
        return {
            "server_ip": None,
            "checked_at": datetime.now(timezone.utc).isoformat() + 'Z',
            "total_blacklists": len(BLACKLISTS),
            "listed_count": 0,
            "clean_count": 0,
            "error_count": 0,
            "timeout_count": 0,
            "status": "error",
            "error": "Could not determine server IP",
            "results": []
        }
    
    # Check DB cache first (unless force)
    if not force:
        cached = get_cached_blacklist_check(ip)
        if cached:
            logger.debug("Returning cached blacklist results from DB")
            return cached
    
    # Perform new check
    return await check_all_blacklists(ip)


def get_listed_blacklists() -> List[Dict[str, Any]]:
    """Get list of blacklists where server is currently listed (from DB cache)"""
    from app.routers.domains import get_cached_server_ip
    
    ip = get_cached_server_ip()
    if not ip:
        return []
    
    cached = get_cached_blacklist_check(ip)
    if not cached or not cached.get("results"):
        return []
    
    return [r for r in cached["results"] if r.get("listed")]
