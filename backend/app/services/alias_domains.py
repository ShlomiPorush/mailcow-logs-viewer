"""Alias-domain awareness (issue #92).

mailcow lets a domain act as an alias of another: mail for user@alias.tld is
the same mailbox as user@target.tld. mailcow's own API only reports the
mapping on /api/v1/get/alias-domain/all; nothing per-mailbox mentions it.

The mapping is fetched by the local-domains sync job and persisted as JSON in
system_settings (no schema change), with a short in-process cache so request
paths do not hit the database on every call. Consumers:

- Mailbox Statistics attributes user@alias.tld traffic to user@target.tld.
- The Domains page checks the alias domains' own DNS records.
- Anomaly detection treats alias-domain addresses as local.
"""
import json
import logging
import time
from typing import Dict, List, Optional

from ..models import SystemSetting

logger = logging.getLogger(__name__)

ALIAS_DOMAIN_MAP_KEY = 'alias_domain_map'
_CACHE_TTL_SECONDS = 300

_cache: Dict[str, str] = {}
_cache_loaded_at: float = 0.0


def set_cached_alias_domain_map(mapping: Dict[str, str]) -> None:
    """Refresh the in-process cache. Called by the sync job after it persisted
    the mapping, and by tests."""
    global _cache, _cache_loaded_at
    _cache = {k.lower(): v.lower() for k, v in (mapping or {}).items()}
    _cache_loaded_at = time.monotonic()


def persist_alias_domain_map(db, mapping: Dict[str, str]) -> None:
    """Write the mapping to system_settings in the caller's session."""
    row = db.query(SystemSetting).filter(SystemSetting.key == ALIAS_DOMAIN_MAP_KEY).first()
    value = json.dumps(mapping or {})
    if row is None:
        db.add(SystemSetting(key=ALIAS_DOMAIN_MAP_KEY, value=value))
    else:
        row.value = value


def get_alias_domain_map(db) -> Dict[str, str]:
    """alias_domain -> target_domain, lowercased. Empty when none configured.

    Served from the in-process cache when fresh, otherwise reloaded from
    system_settings (where the sync job persisted it), so it survives restarts
    and stays correct across workers.
    """
    global _cache, _cache_loaded_at
    if _cache_loaded_at and time.monotonic() - _cache_loaded_at < _CACHE_TTL_SECONDS:
        return dict(_cache)
    try:
        row = db.query(SystemSetting).filter(SystemSetting.key == ALIAS_DOMAIN_MAP_KEY).first()
        mapping = json.loads(row.value) if row and row.value else {}
        set_cached_alias_domain_map(mapping)
    except Exception as e:
        logger.warning(f"Could not load the alias domain map: {e}")
    return dict(_cache)


def aliases_of_domain(domain: str, mapping: Dict[str, str]) -> List[str]:
    """The alias domains pointing at this domain."""
    d = (domain or '').lower()
    return sorted(a for a, t in mapping.items() if t == d)


def expand_address(address: str, mapping: Dict[str, str]) -> List[str]:
    """user@target.tld -> [user@alias.tld for every alias of target.tld].
    Returns only the extra variants, not the address itself."""
    addr = (address or '').lower()
    if '@' not in addr or not mapping:
        return []
    local, _, domain = addr.rpartition('@')
    return [f'{local}@{alias}' for alias in aliases_of_domain(domain, mapping)]


def expand_addresses(addresses, mapping: Dict[str, str]) -> List[str]:
    """The alias-domain variants of every address, deduplicated, extras only."""
    out = []
    seen = set()
    for address in addresses:
        for variant in expand_address(address, mapping):
            if variant not in seen:
                seen.add(variant)
                out.append(variant)
    return out
