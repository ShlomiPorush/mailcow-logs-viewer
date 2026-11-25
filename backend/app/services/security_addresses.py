import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import ipaddress

from sqlalchemy import case, desc, distinct, func
from sqlalchemy.orm import Session

from ..models import NetfilterLog, ProtectionHit
from . import protection_rules
from .netfilter_address import mailcowauth_failure

LISTS = ("review", "banned")
CACHE_SECONDS = 10

_NETFILTER_SERVICES = (
    ('SASL ', 'SMTP auth', True),
    ('non-SMTP command', 'SMTP probe', False),
    ('Protocol error', 'SMTP probe', False),
    ('imap-login', 'IMAP', True),
    ('pop3-login', 'POP3', True),
    ('managesieve-login', 'Sieve', True),
    ('SOGo', 'SOGo', True),
    ('mailcow UI', 'mailcow UI', True),
    ('Rspamd UI', 'Rspamd UI', True),
)


_MAILCOWAUTH_SERVICES = {'imap': 'IMAP', 'pop3': 'POP3', 'sieve': 'Sieve', 'smtp': 'SMTP auth'}
_MAILCOWAUTH_OTHER = 'Mail login'


def _mailcowauth_pattern(service: str) -> str:
    return (r'^\S+ matched rule id \d+ \(MAILCOWAUTH: Login failed for user .* '
            rf'with service {service} from IP [0-9a-f.:]+\)$')


def netfilter_service(message: Optional[str]):
    failure = mailcowauth_failure(message)
    if failure:
        return _MAILCOWAUTH_SERVICES.get(failure[1], _MAILCOWAUTH_OTHER), True
    text = message or ''
    for needle, service, is_login in _NETFILTER_SERVICES:
        if needle in text:
            return service, is_login
    return None, False


def netfilter_sources(db: Session, hours: int, now: Optional[datetime] = None) -> Tuple[Dict[str, dict], dict]:
    cutoff = (now or datetime.utcnow()) - timedelta(hours=hours)
    rows = db.query(
        NetfilterLog.time, NetfilterLog.ip, NetfilterLog.message, NetfilterLog.username,
        NetfilterLog.action, NetfilterLog.rule_id, NetfilterLog.country_code, NetfilterLog.country_name,
        NetfilterLog.city, NetfilterLog.asn_org
    ).filter(
        NetfilterLog.time >= cutoff,
        NetfilterLog.ip.isnot(None)
    ).order_by(desc(NetfilterLog.time)).limit(50000).all()

    sources: Dict[str, dict] = {}
    totals = {"attempts": 0, "failed_logins": 0, "latest": []}

    def entry_for(row):
        entry = sources.get(row.ip)
        if entry is None:
            entry = sources[row.ip] = {
                "ip": row.ip, "attempts": 0, "failed_logins": 0, "last_seen": row.time,
                "services": [], "usernames": [], "country_code": row.country_code,
                "country_name": row.country_name, "city": row.city, "asn_org": row.asn_org,
                "last_action": None,
            }
        return entry

    for row in rows:
        if row.rule_id is not None:
            service, is_login = netfilter_service(row.message)
            totals["attempts"] += 1
            if is_login:
                totals["failed_logins"] += 1
            entry = entry_for(row)
            entry["attempts"] += 1
            if is_login:
                entry["failed_logins"] += 1
            if service and service not in entry["services"]:
                entry["services"].append(service)
            if row.username and row.username not in entry["usernames"] and len(entry["usernames"]) < 5:
                entry["usernames"].append(row.username)
            if is_login and len(totals["latest"]) < 20:
                totals["latest"].append(row)
        elif row.action in ('ban', 'banned', 'unban'):
            entry = entry_for(row)
            if entry["last_action"] is None:
                entry["last_action"] = 'unban' if row.action == 'unban' else 'ban'
    return sources, totals


def attempt_sources(db: Session, hours: int, now: Optional[datetime] = None) -> List[dict]:
    cutoff = (now or datetime.utcnow()) - timedelta(hours=hours)
    text = NetfilterLog.message
    mailcowauth = [(text.op('~')(_mailcowauth_pattern(token)), name) for token, name in _MAILCOWAUTH_SERVICES.items()]
    mailcowauth.append((text.op('~')(_mailcowauth_pattern('[a-z0-9]*')), _MAILCOWAUTH_OTHER))
    service = case(*mailcowauth, *[(text.like(f'%{needle}%'), name) for needle, name, _ in _NETFILTER_SERVICES],
                   else_=None)
    login = case(*[(condition, 1) for condition, _ in mailcowauth],
                 *[(text.like(f'%{needle}%'), 1 if is_login else 0) for needle, _, is_login in _NETFILTER_SERVICES],
                 else_=0)
    rows = db.query(
        NetfilterLog.ip, func.count(NetfilterLog.id), func.sum(login), func.max(NetfilterLog.time),
        func.array_agg(distinct(service)), func.array_agg(distinct(NetfilterLog.username)),
        func.max(NetfilterLog.country_code), func.max(NetfilterLog.country_name),
        func.max(NetfilterLog.city), func.max(NetfilterLog.asn_org)
    ).filter(
        NetfilterLog.time >= cutoff, NetfilterLog.ip.isnot(None), NetfilterLog.rule_id.isnot(None)
    ).group_by(NetfilterLog.ip).all()
    return [{
        "ip": ip, "attempts": attempts, "failed_logins": int(logins or 0), "last_seen": last,
        "services": sorted(s for s in services or [] if s), "usernames": sorted(u for u in users or [] if u)[:5],
        "country_code": code, "country_name": name, "city": city, "asn_org": org,
    } for ip, attempts, logins, last, services, users, code, name, city, org in rows]


def _bare(entry: str) -> str:
    entry = (entry or "").strip()
    suffix = "/128" if ":" in entry else "/32"
    return entry[:-len(suffix)] if entry.endswith(suffix) else entry


def legacy_ipv6_entry(entry: str) -> Optional[str]:
    entry = (entry or "").strip()
    if ":" not in entry or not entry.endswith("/32"):
        return None
    try:
        ipaddress.ip_network(entry)
        return None
    except ValueError:
        pass
    try:
        ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None
    return entry[:-3]


def legacy_entries(f2b: Optional[dict]) -> List[dict]:
    found = []
    for list_name in ("whitelist", "blacklist"):
        for entry in protection_rules.split_ip_list((f2b or {}).get(list_name)):
            address = legacy_ipv6_entry(entry)
            if address:
                found.append({"list": list_name, "entry": entry, "address": address,
                              "network": str(ipaddress.ip_network(entry, strict=False))})
    return found


def _entry_for(entries: List[str], ip: str) -> Optional[str]:
    for entry in entries:
        if _bare(entry) == ip:
            return entry
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for entry in entries:
        try:
            net = ipaddress.ip_network(entry.strip(), strict=False)
        except ValueError:
            continue
        if address.version == net.version and address in net:
            return entry
    return None


def _truthy(value) -> bool:
    return value in (True, 1, "1")


def _ban_network(ban: dict):
    try:
        return ipaddress.ip_network((ban.get("network") or ban.get("ip") or "").strip(), strict=False)
    except ValueError:
        return None


def _state(a: dict, known: bool, whitelist: List[str], blacklist: List[str]) -> str:
    statuses = {h["status"] for h in a["hits"]}
    allowed = _entry_for(whitelist, a["ip"]) if known else None
    if allowed:
        a["listed_as"] = allowed
        return "allow"
    if "banned" in statuses or a["f2b"]:
        return "banned"
    denied = _entry_for(blacklist, a["ip"]) if known else None
    if denied:
        a["listed_as"] = denied
        return "deny"
    if statuses & {"watching", "pending", "alert"}:
        return "review"
    return "quiet"


def _list_of(a: dict) -> Optional[str]:
    if a["state"] in ("banned", "deny"):
        return "banned"
    if a["state"] in ("review", "allow") or (a["state"] == "quiet" and a["attempts"] > 0):
        return "review"
    return None


def attempts_of(a: dict) -> int:
    return a["attempts"] or sum(h.get("attempts") or 0 for h in a["hits"])


def panels(addresses: List[dict], countries: int = 10, networks: int = 8) -> Tuple[List[dict], List[dict]]:
    by_country: Dict[str, dict] = {}
    by_network: Dict[str, dict] = {}
    for a in addresses:
        if a["list"] is None:
            continue
        n = attempts_of(a)
        for key, groups, base in ((a["country"], by_country, {"country_name": a["country"], "country_code": a["country_code"]}),
                                  (a["org"], by_network, {"asn_org": a["org"]})):
            if not key:
                continue
            g = groups.setdefault(key, {**base, "addresses": 0, "attempts": 0, "review": 0, "banned": 0})
            g["addresses"] += 1
            g["attempts"] += n
            g[a["list"]] += n

    def top(groups, limit):
        return sorted(groups.values(), key=lambda g: (g["attempts"], g["addresses"]), reverse=True)[:limit]
    return top(by_country, countries), top(by_network, networks)


def fail2ban_answered(f2b) -> bool:
    if not isinstance(f2b, dict):
        return False
    if str(f2b.get('type', '')).lower() in ('danger', 'error'):
        return False
    return any(key in f2b for key in ('active_bans', 'perm_bans', 'ban_time', 'max_attempts'))


def collect(db: Session, f2b: Optional[dict], now: Optional[datetime] = None, hours: int = 24) -> List[dict]:
    now = now or datetime.utcnow()
    addresses: Dict[str, dict] = {}

    def get(ip: str) -> dict:
        if ip not in addresses:
            addresses[ip] = {"ip": ip, "tries": 0, "attempts": 0, "users": [], "services": [], "hits": [],
                             "country": "", "country_code": "", "city": "", "org": "", "last": None, "f2b": None,
                             "listed_as": None, "network_size": None, "network_range": None, "banned_through": None}
        return addresses[ip]

    def seen(a: dict, when: Optional[datetime]) -> None:
        if when and (a["last"] is None or when > a["last"]):
            a["last"] = when

    for s in attempt_sources(db, hours, now):
        if not s["attempts"]:
            continue
        a = get(s["ip"])
        a.update(tries=s["failed_logins"], attempts=s["attempts"], users=list(s["usernames"]),
                 services=list(s["services"]), country=s["country_name"] or "", country_code=s["country_code"] or "",
                 city=s["city"] or "", org=s["asn_org"] or "")
        seen(a, s["last_seen"])

    hits = db.query(ProtectionHit).filter(ProtectionHit.status.in_(protection_rules.OPEN_STATUSES)).all()
    for hit in hits:
        a = get(hit.ip)
        a["hits"].append(protection_rules.hit_dict(hit))
        a["country"] = a["country"] or hit.country_name or ""
        a["country_code"] = a["country_code"] or hit.country_code or ""
        for name in hit.usernames or []:
            if name not in a["users"]:
                a["users"].append(name)
        seen(a, hit.last_seen)

    known = f2b is not None
    whitelist = blacklist = []
    if known:
        whitelist = protection_rules.split_ip_list(f2b.get("whitelist"))
        blacklist = protection_rules.split_ip_list(f2b.get("blacklist"))
        permanent = {b.get("network") or b.get("ip") for b in f2b.get("perm_bans") or [] if isinstance(b, dict)}
        network_bans = []
        for ban in f2b.get("active_bans") or []:
            if not isinstance(ban, dict) or ban.get("network") in permanent or _truthy(ban.get("queued_for_unban")):
                continue
            network = _ban_network(ban)
            if network is not None and network.num_addresses > 1:
                row = get(str(network))
                row["f2b"], row["network_size"] = ban, network.num_addresses
                row["network_range"] = [str(network.network_address), str(network[-1])]
                network_bans.append((network, ban))
                continue
            ip = _bare(ban.get("ip") or ban.get("network") or "")
            if ip:
                get(ip)["f2b"] = ban
        for a in list(addresses.values()):
            if a["f2b"] or a["network_size"] or _entry_for(blacklist, a["ip"]):
                continue
            try:
                address = ipaddress.ip_address(a["ip"])
            except ValueError:
                continue
            for network, ban in network_bans:
                if address.version == network.version and address in network:
                    a["f2b"], a["banned_through"] = ban, str(network)
                    seen(get(str(network)), a["last"])
                    break

    missing = [ip for ip, a in addresses.items() if not a["country"]]
    if missing:
        rows = db.query(NetfilterLog.ip, func.max(NetfilterLog.country_name), func.max(NetfilterLog.country_code),
                        func.max(NetfilterLog.asn_org)).filter(
            NetfilterLog.ip.in_(missing), NetfilterLog.country_name.isnot(None)
        ).group_by(NetfilterLog.ip).all()
        for ip, name, code, org in rows:
            a = addresses[ip]
            a.update(country=name or "", country_code=code or "", org=a["org"] or org or "")

    out = []
    for a in addresses.values():
        a["state"] = _state(a, known, whitelist, blacklist)
        a["list"] = _list_of(a)
        if a["list"]:
            out.append(a)
    out.sort(key=_order, reverse=True)
    return out


def _order(a: dict) -> tuple:
    return (a["last"] or datetime.min, a["ip"])


def cursor_of(a: dict) -> str:
    return f"{(a['last'] or datetime.min).isoformat()}|{a['ip']}"


def _parse_cursor(value: str) -> Optional[tuple]:
    try:
        when, ip = value.split("|", 1)
        return (datetime.fromisoformat(when), ip)
    except (ValueError, AttributeError):
        return None


def page(addresses: List[dict], list_name: str, country: Optional[str], after: Optional[str], limit: int,
         query: Optional[str] = None, network: Optional[str] = None) -> dict:
    in_country = [a for a in addresses if (not country or a["country"] == country)
                  and (not network or a["org"] == network)
                  and (not query or query in a["ip"])]
    counts = {name: sum(1 for a in in_country if a["list"] == name) for name in LISTS}
    rows = [a for a in in_country if a["list"] == list_name]
    start = _parse_cursor(after) if after else None
    if start is not None:
        rows = [a for a in rows if _order(a) < start]
    items = rows[:limit]
    return {
        "list": list_name,
        "country": country,
        "network": network,
        "total": counts[list_name],
        "counts": counts,
        "all_counts": {name: sum(1 for a in addresses if a["list"] == name) for name in LISTS},
        "items": items,
        "next": cursor_of(items[-1]) if len(rows) > limit else None,
    }


_cache: Dict[int, Tuple[float, List[dict], bool]] = {}


def cached(hours: int = 24) -> Optional[Tuple[List[dict], bool]]:
    found = _cache.get(hours)
    if found and time.monotonic() - found[0] < CACHE_SECONDS:
        return found[1], found[2]
    return None


def remember(addresses: List[dict], fail2ban_known: bool, hours: int = 24) -> None:
    _cache[hours] = (time.monotonic(), addresses, fail2ban_known)


def forget() -> None:
    _cache.clear()
