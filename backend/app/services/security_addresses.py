"""
The Security page's address lists, built here so the counts are real and a
country filter covers every address, not only the ones a browser has loaded.

Every address that tried in the chosen period, or that a rule caught, is on
one of two lists. Banned: a rule's ban, one of Fail2ban's own (not one mailcow
is about to lift), or the denylist. To review: every other one, whether a rule
caught it or not, and the ones on the allowlist too, tagged so. The panels
beside the list (countries and networks) are counted from the same addresses,
so a number there is the rows a click on it shows. The newest activity comes first; pages follow a cursor, so an address
that changes list while someone scrolls does not shift the rest.
"""
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import ipaddress

from sqlalchemy import case, desc, distinct, func
from sqlalchemy.orm import Session

from ..models import NetfilterLog, ProtectionHit
from . import protection_rules

LISTS = ("review", "banned")
CACHE_SECONDS = 10

# What a netfilter "matched rule" line was about, from the log text itself
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


def netfilter_service(message: Optional[str]):
    """Return (service, is_login) for a netfilter line, or (None, False)."""
    text = message or ''
    for needle, service, is_login in _NETFILTER_SERVICES:
        if needle in text:
            return service, is_login
    return None, False


def netfilter_sources(db: Session, hours: int, now: Optional[datetime] = None) -> Tuple[Dict[str, dict], dict]:
    """Attempts over the last hours by source address, and the totals.

    Only lines where netfilter matched a rule count as an attempt; the
    "N more attempts ... until banned" lines that follow each one are not
    counted again. Ban and unban lines give the last Fail2ban action per address.
    """
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
    """Attempts over the last hours by source address, counted by the database.

    The same attempts netfilter_sources counts (lines where netfilter matched a
    rule), but grouped in SQL, so a long period is not cut at a number of lines.
    """
    cutoff = (now or datetime.utcnow()) - timedelta(hours=hours)
    text = NetfilterLog.message
    service = case(*[(text.like(f'%{needle}%'), name) for needle, name, _ in _NETFILTER_SERVICES], else_=None)
    login = case(*[(text.like(f'%{needle}%'), 1 if is_login else 0) for needle, _, is_login in _NETFILTER_SERVICES], else_=0)
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


# ---------------------------------------------------------------- the lists

def _bare(entry: str) -> str:
    entry = (entry or "").strip()
    return entry[:-3] if entry.endswith("/32") else entry[:-4] if entry.endswith("/128") else entry


def _entry_for(entries: List[str], ip: str) -> Optional[str]:
    """The list entry that holds the address: the address itself, or a network around it."""
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


def _state(a: dict, known: bool, whitelist: List[str], blacklist: List[str]) -> str:
    """Where an address stands; the same order the page used to apply. listed_as
    is the allowlist or denylist entry that holds it."""
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
    """An address's attempts as its row shows them: logged ones, or what the rules counted."""
    return a["attempts"] or sum(h.get("attempts") or 0 for h in a["hits"])


def panels(addresses: List[dict], countries: int = 10, networks: int = 8) -> Tuple[List[dict], List[dict]]:
    """The countries and networks the listed addresses come from, most attempts first.

    Counted from the lists themselves: addresses is how many rows a click shows
    (To review and Banned together), and the attempts are the ones on those rows.
    """
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


def collect(db: Session, f2b: Optional[dict], now: Optional[datetime] = None, hours: int = 24) -> List[dict]:
    """Every address on one of the lists, newest activity first.

    f2b is mailcow's Fail2ban answer, or None when mailcow did not answer: then
    only the rules' bans count as banned, and the allow and deny lists are unknown.
    hours is the period the attempts are counted over.
    """
    now = now or datetime.utcnow()
    addresses: Dict[str, dict] = {}

    def get(ip: str) -> dict:
        if ip not in addresses:
            addresses[ip] = {"ip": ip, "tries": 0, "attempts": 0, "users": [], "services": [], "hits": [],
                             "country": "", "country_code": "", "city": "", "org": "", "last": None, "f2b": None,
                             "listed_as": None}
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
        for ban in f2b.get("active_bans") or []:
            if not isinstance(ban, dict) or ban.get("network") in permanent or _truthy(ban.get("queued_for_unban")):
                continue
            ip = _bare(ban.get("ip") or ban.get("network") or "")
            if ip:
                get(ip)["f2b"] = ban

    # An address with no line in the last day (a long Fail2ban ban) has its place in its older lines
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
    """One page of a list, its real total, and both lists' counts (for the country, when one is chosen).

    `query` keeps the addresses that contain it, for the global search, and
    `network` the ones from that network (its ASN organization); the counts then
    count only those.
    """
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


# ---------------------------------------------------------------- a short cache
# Scrolling asks for one page after another; they come from one reading of the
# logs and of mailcow, so a page never disagrees with the one before it. Each
# period has its own reading. Any change to Fail2ban or to a catch forgets them.

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
