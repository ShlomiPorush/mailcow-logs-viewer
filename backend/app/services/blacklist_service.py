import logging
import asyncio
import ipaddress
import dns.asyncresolver
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Set
from sqlalchemy import desc

from app.utils import format_datetime_for_api

logger = logging.getLogger(__name__)

BLACKLISTS = [
    {"name": "Spamhaus ZEN", "zone": "zen.spamhaus.org", "info_url": "https://www.spamhaus.org/lookup/", "ipv6": True},
    {"name": "Spamhaus SBL", "zone": "sbl.spamhaus.org", "info_url": "https://www.spamhaus.org/lookup/", "ipv6": True},
    {"name": "Spamhaus XBL", "zone": "xbl.spamhaus.org", "info_url": "https://www.spamhaus.org/lookup/", "ipv6": True},
    {"name": "Spamhaus PBL", "zone": "pbl.spamhaus.org", "info_url": "https://www.spamhaus.org/lookup/"},
    {"name": "Barracuda", "zone": "b.barracudacentral.org", "info_url": "https://www.barracudacentral.org/lookups"},
    {"name": "SpamCop", "zone": "bl.spamcop.net", "info_url": "https://www.spamcop.net/bl.shtml"},

    {"name": "UCEPROTECT Level 1", "zone": "dnsbl-1.uceprotect.net", "info_url": "https://www.uceprotect.net/en/rblcheck.php"},
    {"name": "UCEPROTECT Level 2", "zone": "dnsbl-2.uceprotect.net", "info_url": "https://www.uceprotect.net/en/rblcheck.php"},
    {"name": "UCEPROTECT Level 3", "zone": "dnsbl-3.uceprotect.net", "info_url": "https://www.uceprotect.net/en/rblcheck.php"},
    
    {"name": "PSBL", "zone": "psbl.surriel.com", "info_url": "https://psbl.org/"},
    {"name": "Truncate", "zone": "truncate.gbudb.net", "info_url": "https://www.gbudb.com/"},
    {"name": "invaluement", "zone": "ivmSIP.invaluement.com", "info_url": "https://www.invaluement.com/lookup/"},
    {"name": "invaluement SIP/24", "zone": "ivmSIP24.invaluement.com", "info_url": "https://www.invaluement.com/lookup/"},

    {"name": "Hostkarma Black", "zone": "hostkarma.junkemailfilter.com", "info_url": "http://wiki.junkemailfilter.com/index.php/Spam_DNS_Lists"},
    {"name": "JustSpam", "zone": "dnsbl.justspam.org", "info_url": "http://www.justspam.org/"},

    {"name": "Mailspike BL", "zone": "bl.mailspike.net", "info_url": "https://www.mailspike.org/"},
    {"name": "Mailspike Z", "zone": "z.mailspike.net", "info_url": "https://www.mailspike.org/"},

    {"name": "s5h.net", "zone": "all.s5h.net", "info_url": "http://www.s5h.net/", "ipv6": True},
    {"name": "Blocklist.de", "zone": "bl.blocklist.de", "info_url": "https://www.blocklist.de/en/search.html"},
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

_SPAMHAUS_DOMAIN = "spamhaus.org"


def _is_spamhaus_zone(zone: str) -> bool:
    zone = (zone or "").strip().rstrip(".").lower()
    return zone == _SPAMHAUS_DOMAIN or zone.endswith("." + _SPAMHAUS_DOMAIN)


def overall_status(results: List[Dict[str, Any]], total: int, ignored: Optional[Set[str]] = None) -> str:
    ignored = ignored or set()
    listed = errors = timeouts = 0
    spamhaus_failed = False
    for r in results:
        if r.get("zone") in ignored:
            continue
        if r.get("listed"):
            listed += 1
        elif r.get("status") == "timeout":
            timeouts += 1
        elif r.get("status") != "clean":
            errors += 1
        if _is_spamhaus_zone(r.get("zone", "")) and r.get("status") in ("error", "timeout"):
            spamhaus_failed = True
    if listed > 0:
        return "listed"
    if spamhaus_failed:
        return "error"
    if errors + timeouts > total / 2:
        return "error"
    return "clean"


def apply_ignored_lists(check: Optional[Dict[str, Any]], ignored: Set[str]) -> Optional[Dict[str, Any]]:
    if not check:
        return check
    results = [dict(r, ignored=r.get("zone") in ignored) for r in (check.get("results") or [])]
    out = dict(check, results=results)
    out["ignored_listed_count"] = sum(1 for r in results if r["ignored"] and r.get("listed"))
    if ignored and results:
        out["listed_count"] = sum(1 for r in results if r.get("listed") and not r["ignored"])
        if check.get("status") in ("listed", "clean", "error"):
            out["status"] = overall_status(results, check.get("total_blacklists") or len(results), ignored)
    return out

def applicable_blacklists(ip: str) -> List[Dict[str, str]]:
    try:
        import ipaddress
        if ipaddress.ip_address(ip).version == 6:
            return [bl for bl in BLACKLISTS if bl.get("ipv6")]
    except ValueError:
        pass
    return BLACKLISTS


IGNORED_NOTIFICATION_BLACKLISTS = [
    "UCEPROTECT Level 2",
    "UCEPROTECT Level 3",
]

CACHE_TTL_HOURS = 24

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
    p = _check_progress.copy()
    if p["total"] > 0:
        p["percent"] = int((p["current"] / p["total"]) * 100)
    return p

def start_batch_scan(total_hosts: int):
    global _batch_state, _check_progress
    _batch_state["active"] = True
    _batch_state["total_hosts"] = total_hosts
    _batch_state["processed_hosts"] = 0
    _check_progress["in_progress"] = True
    _check_progress["current"] = 0
    _check_progress["total"] = total_hosts * len(BLACKLISTS)
    _check_progress["current_blacklist"] = "Initializing batch scan..."

def end_batch_scan():
    global _batch_state, _check_progress
    _batch_state["active"] = False
    _check_progress["in_progress"] = False
    _check_progress["current"] = _check_progress["total"]
    _check_progress["current_blacklist"] = None

def update_batch_status(message: str):
    global _check_progress
    _check_progress["current_blacklist"] = message

def mark_host_as_processed_batch():
    global _batch_state, _check_progress
    
    if _batch_state["active"]:
        _batch_state["processed_hosts"] += 1
        _check_progress["current"] = _batch_state["processed_hosts"] * len(BLACKLISTS)

def reverse_ip(ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return '.'.join(reversed(ip.split('.')))
    if ip_obj.version == 6:
        nibbles = ip_obj.exploded.replace(':', '')
        return '.'.join(reversed(nibbles))
    return '.'.join(reversed(ip.split('.')))


def is_config_source(source) -> bool:
    return bool(source) and (source == 'config' or source.startswith('config:'))


def config_row_origin(row) -> str:
    if row.source and row.source.startswith('config:'):
        return row.source.split(':', 1)[1]
    return row.hostname


def get_auto_monitor_entries() -> List[tuple]:
    from app.config import settings
    from app.routers.domains import get_cached_server_ip

    entries = []
    for host in settings.blacklist_source_manual_hosts_list:
        entries.append((host, 'config'))
    if settings.blacklist_source_server_ip:
        wan_ip = get_cached_server_ip()
        if wan_ip and all(existing != wan_ip for existing, _ in entries):
            entries.append((wan_ip, 'system'))
    else:
        logger.debug("blacklist_source_server_ip disabled - auto-detected WAN IP is not monitored on blacklists")
    return entries

def _synced_source_disabled(row, prefix: str, enabled: bool) -> bool:
    return bool(row.source and row.source.startswith(prefix)
                and row.active and not enabled)


def reconcile_monitored_hosts(db) -> bool:
    from datetime import datetime
    from app.config import settings
    from app.models import MonitoredHost
    from app.routers.domains import get_cached_server_ip

    manual_hosts = settings.blacklist_source_manual_hosts_list
    wan_ip = get_cached_server_ip()
    changed = False
    rows = db.query(MonitoredHost).all()
    by_host = {row.hostname: row for row in rows}
    resolved_hostnames = {
        row.source.split(':', 1)[1] for row in rows
        if row.active and row.source and row.source.startswith('config:')
    }

    for row in rows:
        if row.source == 'system' and not settings.blacklist_source_server_ip and row.active:
            row.active = False
            changed = True
        elif (row.source == 'system' and settings.blacklist_source_server_ip
              and not row.active and wan_ip is None):
            row.active = True
            changed = True
        elif (is_config_source(row.source) and row.active
              and config_row_origin(row) not in manual_hosts):
            row.active = False
            changed = True
        elif _synced_source_disabled(row, 'transport', settings.blacklist_source_transports):
            row.active = False
            changed = True
        elif _synced_source_disabled(row, 'relayhost', settings.blacklist_source_relayhosts):
            row.active = False
            changed = True

    for host, source in get_auto_monitor_entries():
        if source == 'config' and host in resolved_hostnames:
            continue
        existing = by_host.get(host)
        if existing:
            if not existing.active or existing.source != source:
                existing.active = True
                existing.source = source
                changed = True
        else:
            db.add(MonitoredHost(hostname=host, source=source, active=True,
                                 last_seen=datetime.utcnow()))
            changed = True

    if changed:
        db.commit()
    return changed


def _format_checked_at(dt: Optional[datetime]) -> Optional[str]:
    return format_datetime_for_api(dt) if dt else None


def aggregate_blacklist_summary(host_rows: List[Dict[str, Any]],
                                server_ip: Optional[str] = None,
                                now: Optional[datetime] = None) -> Dict[str, Any]:
    if now is None:
        now = datetime.now(timezone.utc)
    ttl = timedelta(hours=CACHE_TTL_HOURS)

    hosts_out: List[Dict[str, Any]] = []
    fresh_statuses: List[str] = []
    listed_count = 0
    total_blacklists = 0
    hosts_listed = 0
    latest_checked_at: Optional[datetime] = None

    for row in host_rows:
        checked_at = row.get("checked_at")
        aware_checked_at = None
        if checked_at is not None:
            aware_checked_at = checked_at if checked_at.tzinfo else checked_at.replace(tzinfo=timezone.utc)
            if latest_checked_at is None or aware_checked_at > latest_checked_at:
                latest_checked_at = aware_checked_at

        is_fresh = aware_checked_at is not None and (now - aware_checked_at) <= ttl
        host_status = (row.get("status") or "unknown") if is_fresh else "unknown"
        host_listed = (row.get("listed_count") or 0) if is_fresh else 0

        if is_fresh:
            fresh_statuses.append(host_status)
            listed_count += host_listed
            total_blacklists += row.get("total_blacklists") or 0
            if host_status == "listed":
                hosts_listed += 1

        hosts_out.append({
            "hostname": row.get("hostname"),
            "source": row.get("source"),
            "status": host_status,
            "listed_count": host_listed,
            "total_blacklists": (row.get("total_blacklists") or 0) if is_fresh else None,
            "checked_at": _format_checked_at(checked_at)
        })

    has_data = len(fresh_statuses) > 0
    if "listed" in fresh_statuses:
        status = "listed"
    elif "error" in fresh_statuses:
        status = "error"
    elif fresh_statuses:
        status = "clean"
    else:
        status = "unknown"

    if not server_ip and len(hosts_out) == 1:
        server_ip = hosts_out[0]["hostname"]

    return {
        "has_data": has_data,
        "server_ip": server_ip,
        "status": status,
        "listed_count": listed_count,
        "total_blacklists": total_blacklists if has_data else len(BLACKLISTS),
        "checked_at": _format_checked_at(latest_checked_at),
        "hosts": hosts_out,
        "hosts_total": len(hosts_out),
        "hosts_listed": hosts_listed
    }


def get_cached_blacklist_check(ip: str) -> Optional[Dict[str, Any]]:
    from app.database import get_db_context
    from app.models import BlacklistCheck
    
    try:
        with get_db_context() as db:
            check = db.query(BlacklistCheck).filter(
                BlacklistCheck.server_ip == ip
            ).order_by(desc(BlacklistCheck.checked_at)).first()
            
            if not check:
                return None
            
            age = datetime.now(timezone.utc) - check.checked_at.replace(tzinfo=timezone.utc)
            if age > timedelta(hours=CACHE_TTL_HOURS):
                return None
            
            expected_total = len(applicable_blacklists(ip))
            if check.total_blacklists != expected_total:
                logger.info(f"Blacklist configuration changed (stored: {check.total_blacklists}, current: {expected_total}). Invalidating cache.")
                return None
            
            from .ignore_lists import load_ignored, IGNORED_BLOCKLISTS_KEY
            return apply_ignored_lists({
                "server_ip": check.server_ip,
                "checked_at": format_datetime_for_api(check.checked_at),
                "total_blacklists": check.total_blacklists,
                "listed_count": check.listed_count,
                "clean_count": check.clean_count,
                "error_count": check.error_count,
                "timeout_count": check.timeout_count,
                "status": check.status,
                "results": check.results or []
            }, load_ignored(db, IGNORED_BLOCKLISTS_KEY))
    except Exception as e:
        logger.error(f"Error getting cached blacklist check: {e}")
        return None

def save_blacklist_check(data: Dict[str, Any]) -> None:
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
    global _check_progress, _batch_state
    
    current_idx = index + 1
    if _batch_state.get("active", False):
        current_idx += (_batch_state.get("processed_hosts", 0) * len(BLACKLISTS))
        
    _check_progress["current"] = current_idx
    _check_progress["current_blacklist"] = blacklist["name"]
    
    reversed_ip = reverse_ip(ip)
    query = f"{reversed_ip}.{blacklist['zone']}"
    
    try:
        from app.services.dns_resolver import resolve_for_blacklist
        answers = await resolve_for_blacklist(query, 'A', timeout=10)
        
        response_ips = [str(rdata) for rdata in answers]
        response = response_ips[0] if response_ips else None
        
        if response and response.startswith('127.255.'):
            if response == "127.255.255.252":
                error_msg = "Query rejected (typing error in the zone name) - status unknown"
            elif response == "127.255.255.254":
                error_msg = ("Query rejected: sent via a public/open DNS resolver. "
                             "Set BLACKLIST_DNS_SERVERS to your own recursive resolver "
                             "(mailcow: 172.22.1.254) - status unknown")
            elif response == "127.255.255.255":
                error_msg = "Query rejected: too many queries from this resolver - status unknown"
            else:
                error_msg = f"Query rejected ({response}) - status unknown"
            
            logger.warning(f"{blacklist['name']}: {error_msg}")
            return {
                "name": blacklist["name"],
                "zone": blacklist["zone"],
                "info_url": blacklist.get("info_url", ""),
                "status": "error",
                "listed": False,
                "response": error_msg
            }
        
        if response == '127.0.0.1':
            logger.warning(f"{blacklist['name']}: got 127.0.0.1 - the resolver is "
                           "blocking/rewriting the RBL domain, status unknown")
            return {
                "name": blacklist["name"],
                "zone": blacklist["zone"],
                "info_url": blacklist.get("info_url", ""),
                "status": "error",
                "listed": False,
                "response": "Invalid answer (127.0.0.1): the DNS resolver appears to "
                            "block or rewrite this RBL domain - status unknown"
            }

        if (response and _is_spamhaus_zone(blacklist['zone'])
                and response.startswith('127.')):
            try:
                last_octet = int(response.rsplit('.', 1)[1])
                valid = response.startswith('127.0.0.') and 2 <= last_octet <= 11
            except (ValueError, IndexError):
                valid = False
            if not valid:
                logger.warning(f"{blacklist['name']}: unexpected Spamhaus answer "
                               f"{response} - status unknown")
                return {
                    "name": blacklist["name"],
                    "zone": blacklist["zone"],
                    "info_url": blacklist.get("info_url", ""),
                    "status": "error",
                    "listed": False,
                    "response": f"Unexpected Spamhaus answer ({response}) - not a "
                                "documented listing code - status unknown"
                }

        if response and not response.startswith('127.'):
            logger.warning(f"{blacklist['name']}: non-DNSBL answer {response} - "
                           "resolver is rewriting NXDOMAIN, status unknown")
            return {
                "name": blacklist["name"],
                "zone": blacklist["zone"],
                "info_url": blacklist.get("info_url", ""),
                "status": "error",
                "listed": False,
                "response": f"Invalid DNSBL answer ({response}) - the DNS resolver "
                            "appears to rewrite NXDOMAIN responses - status unknown"
            }

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
    except Exception as e:
        error_msg = f"All DNS resolvers failed - {str(e)}"
        logger.warning(f"{blacklist['name']}: {error_msg}")
        return {
            "name": blacklist["name"],
            "zone": blacklist["zone"],
            "info_url": blacklist.get("info_url", ""),
            "status": "error",
            "listed": False,
            "response": error_msg
        }


async def check_all_blacklists(ip: str) -> Dict[str, Any]:
    global _check_progress, _batch_state

    blacklists = applicable_blacklists(ip)

    if not _batch_state.get("active", False):
        _check_progress["in_progress"] = True
        _check_progress["current"] = 0
        _check_progress["total"] = len(blacklists)

    logger.info(f"Starting blacklist check for IP: {ip} ({len(blacklists)} zones)")

    try:
        tasks = [check_ip_in_blacklist(ip, bl, i) for i, bl in enumerate(blacklists)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
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
        
        processed_results.sort(key=lambda x: (
            0 if x["listed"] else (1 if x["status"] == "clean" else 2),
            x["name"]
        ))
        
        status = overall_status(processed_results, len(blacklists))
        if status == "error" and listed_count == 0 and any(
            _is_spamhaus_zone(r.get('zone', '')) and r.get('status') in ('error', 'timeout') for r in processed_results
        ):
            logger.warning(
                "Blacklist check for %s: Spamhaus zone(s) could not be checked - "
                "reporting status 'error' rather than 'clean'", ip
            )

        data = {
            "server_ip": ip,
            "checked_at": format_datetime_for_api(datetime.now(timezone.utc)),
            "total_blacklists": len(blacklists),
            "listed_count": listed_count,
            "clean_count": clean_count,
            "error_count": error_count,
            "timeout_count": timeout_count,
            "status": status,
            "results": processed_results
        }
        
        await asyncio.to_thread(save_blacklist_check, data)
        
        logger.info(f"Blacklist check complete: {listed_count} listed, {clean_count} clean, {error_count} errors")
        
        from .ignore_lists import ignored_now, IGNORED_BLOCKLISTS_KEY
        ignored = await asyncio.to_thread(ignored_now, IGNORED_BLOCKLISTS_KEY)
        return apply_ignored_lists(data, ignored)
        
    finally:
        if not _batch_state.get("active", False):
            _check_progress["in_progress"] = False
            _check_progress["current"] = len(blacklists)
            _check_progress["current_blacklist"] = None
        else:
            _batch_state["processed_hosts"] += 1
            pass


async def get_blacklist_check_results(force: bool = False, ip: Optional[str] = None) -> Dict[str, Any]:
    if not ip:
        from app.routers.domains import get_cached_server_ip, init_server_ip
        ip = get_cached_server_ip()
        if not ip:
            ip = await init_server_ip()
    
    if not ip:
        return {
            "server_ip": None,
            "checked_at": format_datetime_for_api(datetime.now(timezone.utc)),
            "total_blacklists": len(BLACKLISTS),
            "listed_count": 0,
            "clean_count": 0,
            "error_count": 0,
            "timeout_count": 0,
            "status": "error",
            "error": "Could not determine server IP",
            "results": []
        }
    
    if not force:
        cached = await asyncio.to_thread(get_cached_blacklist_check, ip)
        if cached:
            logger.debug("Returning cached blacklist results from DB")
            return cached
    
    return await check_all_blacklists(ip)


def get_listed_blacklists() -> List[Dict[str, Any]]:
    from app.routers.domains import get_cached_server_ip
    
    ip = get_cached_server_ip()
    if not ip:
        return []
    
    cached = get_cached_blacklist_check(ip)
    if not cached or not cached.get("results"):
        return []
    
    return [r for r in cached["results"] if r.get("listed") and not r.get("ignored")]
