"""
The Security page's address lists, built here so the counts are real and a
country filter covers every address, not only the ones a browser has loaded.

An address is banned or it is not. Banned: a rule's ban, or one of Fail2ban's
own (not a permanent one, and not one mailcow is about to lift). To review:
every other address a rule caught, or that failed to log in in the last 24
hours. A country or network picked in the page's panels covers the panels'
period instead, and every address that tried in it, so the list holds the
addresses the panel counted. An address on the allowlist or the denylist is
shown on the Lists, not here. The newest activity comes first; pages follow a cursor, so an address
that changes list while someone scrolls does not shift the rest.
"""
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy import desc, func
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


# ---------------------------------------------------------------- the lists

def _bare(entry: str) -> str:
    entry = (entry or "").strip()
    return entry[:-3] if entry.endswith("/32") else entry[:-4] if entry.endswith("/128") else entry


def _on(entries: List[str], ip: str) -> bool:
    return any(_bare(e) == ip for e in entries)


def _truthy(value) -> bool:
    return value in (True, 1, "1")


def _state(a: dict, known: bool, whitelist: List[str], blacklist: List[str]) -> str:
    """Where an address stands; the same order the page used to apply."""
    statuses = {h["status"] for h in a["hits"]}
    if known and _on(whitelist, a["ip"]):
        return "allow"
    if "banned" in statuses or a["f2b"]:
        return "banned"
    if known and _on(blacklist, a["ip"]):
        return "deny"
    if statuses & {"watching", "pending", "alert"}:
        return "review"
    return "quiet"


def _list_of(a: dict, wide: bool) -> Optional[str]:
    if a["state"] == "banned":
        return "banned"
    if a["state"] == "review" or (a["state"] == "quiet" and (a["attempts"] if wide else a["tries"]) > 0):
        return "review"
    return None


def collect(db: Session, f2b: Optional[dict], now: Optional[datetime] = None, hours: int = 24) -> List[dict]:
    """Every address on one of the lists, newest activity first.

    f2b is mailcow's Fail2ban answer, or None when mailcow did not answer: then
    only the rules' bans count as banned, and the allow and deny lists are unknown.
    hours longer than a day is a panel's period: every address that tried in it
    is listed, as the panels count them, not only the ones that failed to log in.
    """
    now = now or datetime.utcnow()
    addresses: Dict[str, dict] = {}

    def get(ip: str) -> dict:
        if ip not in addresses:
            addresses[ip] = {"ip": ip, "tries": 0, "attempts": 0, "users": [], "services": [], "hits": [],
                             "country": "", "country_code": "", "city": "", "org": "", "last": None, "f2b": None}
        return addresses[ip]

    def seen(a: dict, when: Optional[datetime]) -> None:
        if when and (a["last"] is None or when > a["last"]):
            a["last"] = when

    sources, _ = netfilter_sources(db, hours, now)
    for s in sources.values():
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
        a["list"] = _list_of(a, hours > 24)
        # An address on the allowlist or denylist is in neither list, but a
        # filter says how many of its addresses are there
        if a["list"] or (a["state"] in ("allow", "deny") and a["attempts"]):
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
        "on_lists": sum(1 for a in in_country if a["list"] is None),
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
