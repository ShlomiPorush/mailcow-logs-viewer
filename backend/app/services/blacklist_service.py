"""
IP Blacklist Checking Service
Checks mail server IP against DNS-based blacklists (DNSBLs/RBLs)
Results are persisted in database for 24 hours.
"""
import logging
import asyncio
import ipaddress
import dns.asyncresolver
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy import desc

logger = logging.getLogger(__name__)

# Blacklist zones to check
BLACKLISTS = [
    # Major blacklists.
    # "ipv6": True marks zones known to answer IPv6 (nibble-reversed) queries;
    # every other zone is IPv4-only and is skipped for IPv6 addresses so an
    # NXDOMAIN from a zone that cannot even hold an IPv6 listing is never
    # reported as "clean".
    {"name": "Spamhaus ZEN", "zone": "zen.spamhaus.org", "info_url": "https://www.spamhaus.org/lookup/", "ipv6": True},
    {"name": "Spamhaus SBL", "zone": "sbl.spamhaus.org", "info_url": "https://www.spamhaus.org/lookup/", "ipv6": True},
    {"name": "Spamhaus XBL", "zone": "xbl.spamhaus.org", "info_url": "https://www.spamhaus.org/lookup/", "ipv6": True},
    {"name": "Spamhaus PBL", "zone": "pbl.spamhaus.org", "info_url": "https://www.spamhaus.org/lookup/"},
    {"name": "Barracuda", "zone": "b.barracudacentral.org", "info_url": "https://www.barracudacentral.org/lookups"},
    {"name": "SpamCop", "zone": "bl.spamcop.net", "info_url": "https://www.spamcop.net/bl.shtml"},
    # SORBS shut down in 2024 (zones removed); CBL was absorbed into Spamhaus XBL.

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

def applicable_blacklists(ip: str) -> List[Dict[str, str]]:
    """The zones that can actually hold a listing for this address.

    IPv6 addresses are only checked against zones known to serve IPv6; most
    DNSBLs are IPv4-only and would return NXDOMAIN for any IPv6 query, which
    would show up as a meaningless "clean".
    """
    try:
        import ipaddress
        if ipaddress.ip_address(ip).version == 6:
            return [bl for bl in BLACKLISTS if bl.get("ipv6")]
    except ValueError:
        pass  # hostname or invalid literal - use the full list
    return BLACKLISTS


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
    """
    Reverse an IP address for DNSBL lookup.

    IPv4: 1.2.3.4 -> 4.3.2.1
    IPv6 (RFC 5782 nibble format): 2001:db8::1 ->
         1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        # Not a literal IP - keep legacy dotted reversal behavior
        return '.'.join(reversed(ip.split('.')))
    if ip_obj.version == 6:
        nibbles = ip_obj.exploded.replace(':', '')
        return '.'.join(reversed(nibbles))
    return '.'.join(reversed(ip.split('.')))


def is_config_source(source) -> bool:
    """'config' rows come from blacklist_source_manual_hosts.

    A direct entry (IP literal or hostname) is stored with source 'config'
    and the entry itself as hostname; an IP resolved from a manual hostname
    by the transports sync is stored as 'config:<hostname>' (mirroring
    'transport:<fqdn>' / 'relayhost:<fqdn>').
    """
    return bool(source) and (source == 'config' or source.startswith('config:'))


def config_row_origin(row) -> str:
    """The manual-hosts entry a 'config' row belongs to."""
    if row.source and row.source.startswith('config:'):
        return row.source.split(':', 1)[1]
    return row.hostname


def get_auto_monitor_entries() -> List[tuple]:
    """
    (host, source) pairs that should be monitored based on settings, without
    any DNS resolution (safe to call from sync read paths).

    - Manual hosts (blacklist_source_manual_hosts) get source 'config'.
      Hostname entries stay hostname rows here; the transports sync resolves
      them to all public IPs (stored as 'config:<hostname>').
    - The auto-detected WAN IP gets source 'system' while
      blacklist_source_server_ip is enabled (relay users can turn it off).
    """
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
    """Active transport/relayhost row whose source toggle is now off.

    Only DISABLING is handled here (must hide on the next page load).
    Re-enabling is deliberately left to the sync job (triggered immediately
    on settings save): reconcile cannot tell a row deactivated by the toggle
    from one deactivated because the host was removed in mailcow - blindly
    reactivating resurrects deleted relayhosts. The sync reads the live
    mailcow state, so only hosts that still exist come back.
    """
    return bool(row.source and row.source.startswith(prefix)
                and row.active and not enabled)


def reconcile_monitored_hosts(db) -> bool:
    """Align monitored_hosts rows with the current settings.

    A just-saved source toggle or manual-hosts change must show up in the
    monitored list immediately, not only after the next scheduled scan - so
    this runs whenever the list is read. Rows are only activated/deactivated,
    never deleted. Returns True when anything changed.
    """
    from datetime import datetime
    from app.config import settings
    from app.models import MonitoredHost
    from app.routers.domains import get_cached_server_ip

    manual_hosts = settings.blacklist_source_manual_hosts_list
    wan_ip = get_cached_server_ip()
    changed = False
    rows = db.query(MonitoredHost).all()
    by_host = {row.hostname: row for row in rows}
    # Manual hostnames already represented by sync-resolved IP rows do not
    # need (or get) a bare hostname row of their own
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
            # WAN monitoring was re-enabled but detection has not succeeded
            # (yet) this run - the stored row is the best known WAN address.
            # A stale row is cleaned up by the transports sync once detection
            # works again.
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
    """Format a (possibly naive UTC) datetime as an ISO string with Z suffix"""
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace('+00:00', '') + 'Z'


def aggregate_blacklist_summary(host_rows: List[Dict[str, Any]],
                                server_ip: Optional[str] = None,
                                now: Optional[datetime] = None) -> Dict[str, Any]:
    """Build the dashboard /summary payload from the latest check per host.

    Aggregates across ALL active monitored hosts instead of only the
    auto-detected WAN IP, so the dashboard card keeps working when
    the server IP source is disabled and only relay/transport IPs are monitored.

    host_rows: one entry per active monitored host, with its LATEST check:
        {hostname, source, status, listed_count, total_blacklists, checked_at}
    The check fields are None for hosts that have never been checked.
    checked_at may be naive (stored as UTC) or timezone-aware.

    Rules:
    - A host's latest check only counts while fresh (CACHE_TTL_HOURS), which
      preserves the old single-host summary behavior of has_data dropping to
      False once the cache expires.
    - Overall status precedence: "listed" if any host is listed, else "error"
      if any host's latest fresh check errored, else "clean" if at least one
      host has fresh data, else "unknown".
    - listed_count / total_blacklists are SUMS across hosts with fresh data,
      so the legacy "Listed On X/Y" ratio stays meaningful for consumers of
      the old single-host schema.
    - checked_at is the most recent check across all hosts.
    """
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

    # server_ip kept for backward compatibility: the auto-detected WAN IP as
    # before; when unavailable (server IP source off) fall back to the single
    # monitored host so single-host UIs still show an address.
    if not server_ip and len(hosts_out) == 1:
        server_ip = hosts_out[0]["hostname"]

    return {
        "has_data": has_data,
        "server_ip": server_ip,
        "status": status,
        # Sum across hosts with fresh data (see docstring)
        "listed_count": listed_count,
        "total_blacklists": total_blacklists if has_data else len(BLACKLISTS),
        "checked_at": _format_checked_at(latest_checked_at),
        "hosts": hosts_out,
        "hosts_total": len(hosts_out),
        "hosts_listed": hosts_listed
    }


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
            
            # Check if configuration changed (number of blacklists applicable
            # to THIS address - IPv6 hosts are checked against fewer zones)
            expected_total = len(applicable_blacklists(ip))
            if check.total_blacklists != expected_total:
                logger.info(f"Blacklist configuration changed (stored: {check.total_blacklists}, current: {expected_total}). Invalidating cache.")
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
        from app.services.dns_resolver import resolve_for_blacklist
        answers = await resolve_for_blacklist(query, 'A', timeout=10)
        
        # If we get a response, check if it's a real listing or a blocked-query response
        response_ips = [str(rdata) for rdata in answers]
        response = response_ips[0] if response_ips else None
        
        # 127.255.255.x means the RBL REJECTED the query, not that the IP is
        # listed. Spamhaus returns these when the query arrives via a public
        # resolver (Google/Cloudflare/Quad9/DoH) - set BLACKLIST_DNS_SERVERS to
        # your own recursive resolver (mailcow: 172.22.1.254) to fix it.
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
        
        # RFC 5782: 127.0.0.1 must never be listed in any DNSBL - it is the
        # classic answer of a DNS blocker (Pi-hole, router adblock, ISP
        # filter) intercepting the RBL domain itself.
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

        # Spamhaus documents its listing codes as 127.0.0.2-11; anything else
        # from a spamhaus zone is not a listing
        if (response and blacklist['zone'].endswith('spamhaus.org')
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

        # RFC 5782: a genuine DNSBL listing answer is always inside
        # 127.0.0.0/8. Anything else is a broken/hijacking resolver
        # (NXDOMAIN redirection to an ad server, captive portal, ...) and
        # must never be reported as a listing.
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
        # NXDOMAIN means IP is not listed - this is a valid response
        return {
            "name": blacklist["name"],
            "zone": blacklist["zone"],
            "info_url": blacklist.get("info_url", ""),
            "status": "clean",
            "listed": False,
            "response": None
        }
    except dns.resolver.NoAnswer:
        # NoAnswer also means not listed
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
    """
    Check IP against all blacklists concurrently
    
    Args:
        ip: IP address to check
    
    Returns:
        Dict with all results and summary
    """
    global _check_progress, _batch_state

    # IPv6 addresses are checked only against zones that actually serve IPv6
    blacklists = applicable_blacklists(ip)

    # Only reset progress if NOT in batch mode
    if not _batch_state.get("active", False):
        _check_progress["in_progress"] = True
        _check_progress["current"] = 0
        _check_progress["total"] = len(blacklists)

    logger.info(f"Starting blacklist check for IP: {ip} ({len(blacklists)} zones)")

    try:
        # Run all checks concurrently with index for progress tracking
        tasks = [check_ip_in_blacklist(ip, bl, i) for i, bl in enumerate(blacklists)]
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
        
        # Determine overall status.
        # A failed Spamhaus lookup must never be reported as "clean": Spamhaus
        # is the RBL that actually matters for deliverability, so if its zones
        # could not be checked the honest answer is "unknown".
        spamhaus_failed = [
            r for r in processed_results
            if 'spamhaus' in r.get('zone', '').lower() and r.get('status') in ('error', 'timeout')
        ]
        if listed_count > 0:
            status = "listed"
        elif spamhaus_failed:
            status = "error"
            logger.warning(
                "Blacklist check for %s: %d Spamhaus zone(s) could not be checked - "
                "reporting status 'error' rather than 'clean'", ip, len(spamhaus_failed)
            )
        elif error_count + timeout_count > len(blacklists) / 2:
            status = "error"
        else:
            status = "clean"

        data = {
            "server_ip": ip,
            "checked_at": datetime.now(timezone.utc).isoformat() + 'Z',
            "total_blacklists": len(blacklists),
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
            _check_progress["current"] = len(blacklists)
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
