"""
Helpers for normalizing mailcow/Postfix transport & relayhost nexthops
and resolving their public IPv4 addresses.

Shared by the blacklist monitoring sync (scheduler.py) and the domain
SPF source-IP checks (routers/domains.py) so both features interpret
mailcow transport/relayhost data identically. Contains no mailcow API
calls - callers are responsible for fetching transport/relayhost data
and deciding which sources to use.
"""
import ipaddress
import logging
import re
from typing import Any, List, Optional

import dns.resolver

from app.services.dns_resolver import resolve

logger = logging.getLogger(__name__)

# Matches Postfix bracketed nexthop syntax: [host] or [host]:port
POSTFIX_NEXTHOP_RE = re.compile(r"^\[(?P<host>[^\]]+)\](?::(?P<port>\d+))?$")


def normalize_postfix_nexthop(value: Optional[str]) -> Optional[str]:
    """
    Normalize a Postfix/mailcow nexthop into a bare hostname or IP.

    Handles: 'host', 'host:port', '[host]', '[host]:port'.
    Returns None for empty/invalid input.
    """
    if not value:
        return None

    cleaned = value.strip().lower()
    if not cleaned:
        return None

    match = POSTFIX_NEXTHOP_RE.match(cleaned)
    if match:
        host = match.group('host').strip()
        return host or None

    # Not bracketed - only strip a trailing :port if it's purely numeric,
    # so hostnames without a port are left untouched.
    if ':' in cleaned:
        host, _, port = cleaned.rpartition(':')
        if host and port.isdigit():
            return host.strip()

    return cleaned or None


def is_public_ipv4(ip_obj: ipaddress.IPv4Address) -> bool:
    """
    True if the address is fine to monitor/check.

    Mirrors the pre-existing filter used by the blacklist sync
    (private/loopback), unchanged to avoid a behavior shift.
    """
    return not (ip_obj.is_private or ip_obj.is_loopback)


async def resolve_public_ipv4_addresses(value: str) -> List[str]:
    """
    Normalize a mailcow nexthop and resolve it to all public IPv4 addresses.

    - Already-an-IPv4 input is returned as-is (if public).
    - A hostname is resolved via the shared DNS resolver; every A record
      is returned (deduplicated, sorted).
    - DNS errors are logged and result in an empty list (never raises).
    - IPv6/AAAA records are never returned.
    """
    host = normalize_postfix_nexthop(value)
    if not host:
        return []

    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        ip_obj = None

    if ip_obj is not None:
        if isinstance(ip_obj, ipaddress.IPv4Address) and is_public_ipv4(ip_obj):
            return [str(ip_obj)]
        return []

    try:
        answers = await resolve(host, 'A', timeout=5)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        logger.debug(f"No A records found for {host}")
        return []
    except Exception as e:
        logger.warning(f"DNS resolution failed for {host}: {e}")
        return []

    ips = set()
    for rdata in answers:
        try:
            candidate = ipaddress.ip_address(str(rdata))
        except ValueError:
            continue
        if isinstance(candidate, ipaddress.IPv4Address) and is_public_ipv4(candidate):
            ips.add(str(candidate))

    if not ips:
        logger.debug(f"No public IPv4 A records found for {host}")

    return sorted(ips)


def is_mailcow_active(value: Any) -> bool:
    """Tolerant truthy check for mailcow 'active' flags: 1, '1', True, 'true'."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1
    if isinstance(value, str):
        return value.strip().lower() in ('1', 'true')
    return False
