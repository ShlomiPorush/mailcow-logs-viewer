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
    global _cache, _cache_loaded_at
    _cache = {k.lower(): v.lower() for k, v in (mapping or {}).items()}
    _cache_loaded_at = time.monotonic()


def persist_alias_domain_map(db, mapping: Dict[str, str]) -> None:
    row = db.query(SystemSetting).filter(SystemSetting.key == ALIAS_DOMAIN_MAP_KEY).first()
    value = json.dumps(mapping or {})
    if row is None:
        db.add(SystemSetting(key=ALIAS_DOMAIN_MAP_KEY, value=value))
    else:
        row.value = value


def get_alias_domain_map(db) -> Dict[str, str]:
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
    d = (domain or '').lower()
    return sorted(a for a, t in mapping.items() if t == d)


def expand_address(address: str, mapping: Dict[str, str]) -> List[str]:
    addr = (address or '').lower()
    if '@' not in addr or not mapping:
        return []
    local, _, domain = addr.rpartition('@')
    return [f'{local}@{alias}' for alias in aliases_of_domain(domain, mapping)]


def expand_addresses(addresses, mapping: Dict[str, str]) -> List[str]:
    out = []
    seen = set()
    for address in addresses:
        for variant in expand_address(address, mapping):
            if variant not in seen:
                seen.add(variant)
                out.append(variant)
    return out
