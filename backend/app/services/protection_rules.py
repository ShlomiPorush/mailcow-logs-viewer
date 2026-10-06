"""
Protection rules: act on the failed logins netfilter records.

The rules read the new netfilter lines after every log fetch, decide which
addresses to catch and record why as a ProtectionHit.

Rules that ban (each starts in watch mode; banning is the admin's choice):
- trap: names the admin knows have no mailbox. An address that tries one is
  caught at once. A trap may not be a real mailbox or alias; a trap that later
  becomes one is skipped.
- unknown_accounts: an address that tries several accounts which do not exist
  within a time window. An address with a successful login in the last day is
  never caught, so a user who mistyped the address is safe.
- repeat_offender: an address Fail2ban itself banned several times.
- subnet: several addresses of one IPv4 /24 attacking within a window. The
  network is caught as a whole, unless it holds an address that may never be.
- country: failed logins from countries the admin chose (needs GeoIP).

A rule that only alerts:
- breach: a successful login right after failed tries from the same address,
  or from a country the account did not log in from in 30 days. It points at a
  stolen password; banning would lock out the real user, so it never bans.

In watch mode a hit only records what the rule would do. In ban mode the hit
waits as 'pending' until enforce() writes it to the Fail2ban blacklist in one
batch, with a fresh read just before the write so a change made in mailcow in
the meantime is kept. The app records which entries it added (owned) and only
ever removes those: when the ban ends, or when the admin undoes it. An address
the admin dismissed or undid is left alone by that rule for a week.

Never caught by any rule: the Fail2ban allowlist (matched as networks),
internal networks, and the mailcow host with its transports and relay hosts.

The rules are stored in system_settings as JSON like the ignore lists, so they
can be managed on the Security page even when editing settings from the UI is
off. Reading moves forward by log id, so a restart never reads a line twice
and a rule switched on later never reaches back into lines already read.
"""
import copy
import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Set, Tuple

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from .alias_domains import aliases_of_domain, expand_addresses, get_alias_domain_map
from ..models import AliasStatistics, MailboxStatistics, NetfilterLog, PostfixLog, ProtectionHit, RawServiceLog, SystemSetting
from ..utils import format_datetime_for_api

logger = logging.getLogger(__name__)

RULES_KEY = "protection.rules"
WATERMARK_KEY = "protection.watermark"
BREACH_POSTFIX_KEY = "protection.breach.postfix"
BREACH_DOVECOT_KEY = "protection.breach.dovecot"
BATCH_SIZE = 5000
MAX_EVIDENCE = 200

BAN_RULES = ("trap", "unknown_accounts", "repeat_offender", "subnet", "country")
RULE_NAMES = BAN_RULES + ("breach",)
OPEN_STATUSES = ("watching", "pending", "banned", "alert")
CLOSED_STATUSES = ("dismissed", "expired", "undone")
LEAVE_ALONE = timedelta(days=7)
# A watched address not seen for this long leaves To review for the history
QUIET_AFTER = timedelta(days=7)

DEFAULT_RULES: Dict[str, dict] = {
    "trap": {"enabled": False, "mode": "watch", "names": [], "ban_hours": 720, "notify": True},
    "unknown_accounts": {"enabled": False, "mode": "watch", "threshold": 5, "window_minutes": 60, "ban_hours": 168, "notify": True},
    "repeat_offender": {"enabled": False, "mode": "watch", "threshold": 3, "window_days": 30, "ban_hours": 0, "notify": True},
    "subnet": {"enabled": False, "mode": "watch", "threshold": 5, "window_hours": 24, "ban_hours": 24, "notify": True},
    "country": {"enabled": False, "mode": "watch", "countries": [], "ban_hours": 168, "notify": True},
    "breach": {"enabled": False, "failures": 3, "window_minutes": 60, "new_country": True, "notify": True},
}

# Internal networks, spelled out: ipaddress' is_private also covers the
# documentation ranges, which are public-facing test addresses here
_INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10",
)]
_NAME_RE = re.compile(r"^[a-z0-9._%+\-]+(@[a-z0-9.\-]+)?$")
_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
_SUCCESS_LOGIN_WINDOW = timedelta(hours=24)
_POSTFIX_LOGIN_RE = re.compile(r"client=[^\[]*\[(?:IPv6:)?([0-9a-fA-F:.]+)\].*?sasl_username=(\S+)")
_DOVECOT_LOGIN_RE = re.compile(r"Login: user=<([^>]+)>.*?rip=([0-9a-fA-F:.]+)")


@dataclass
class ProtectionContext:
    """What the rules need from outside the database, read once per run."""
    allowlist: List[str] = field(default_factory=list)   # Fail2ban allowlist entries (addresses or networks)
    protected_ips: Set[str] = field(default_factory=set)  # mailcow host, transports, relay hosts
    geoip: bool = False                                    # the country rule and new-country alert need it
    raw_logs: bool = False                                 # IMAP logins for the breach alert come from the raw logs


# ---------------------------------------------------------------- stored state

def _setting(db: Session, key: str) -> Optional[str]:
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    return row.value if row else None


def _store(db: Session, key: str, value: str) -> None:
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(SystemSetting(key=key, value=value))


def load_rules(db: Session) -> Dict[str, dict]:
    """The stored rules over the defaults; an unreadable value falls back to the defaults."""
    rules = copy.deepcopy(DEFAULT_RULES)
    raw = _setting(db, RULES_KEY)
    if raw:
        try:
            stored = json.loads(raw)
        except (TypeError, ValueError):
            logger.warning("Protection rules are not valid JSON; using the defaults")
            stored = {}
        for name in RULE_NAMES:
            if isinstance(stored.get(name), dict):
                rules[name].update({k: v for k, v in stored[name].items() if k in rules[name]})
    return rules


def _known_accounts(db: Session):
    """Every real mailbox and alias, lower case, with the domains that have a catch-all.

    mailcow alias domains make user@alias.tld the same account as
    user@target.tld, so every address also counts on each alias of its domain.
    """
    known = {u.lower() for (u,) in db.query(MailboxStatistics.username).all() if u}
    catch_all = set()
    for address, domain, is_catch_all in db.query(AliasStatistics.alias_address, AliasStatistics.domain, AliasStatistics.is_catch_all).all():
        if address:
            known.add(address.lower())
        if is_catch_all and domain:
            catch_all.add(domain.lower())
    mapping = get_alias_domain_map(db)
    if mapping:
        known |= set(expand_addresses(known, mapping))
        catch_all |= {alias for domain in list(catch_all) for alias in aliases_of_domain(domain, mapping)}
    return known, catch_all


def _int(value, low: int, high: int, name: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a whole number")
    if not low <= number <= high:
        raise ValueError(f"{name} must be between {low} and {high}")
    return number


def _is_existing(name: str, known: Set[str], local_parts: Set[str]) -> bool:
    return (name in known) if "@" in name else (name in local_parts)


def save_rules(db: Session, rules: dict, can_ban: bool = True) -> Dict[str, dict]:
    """Validate and store the rules. Raises ValueError with a message the admin can act on."""
    current = load_rules(db)
    for name in RULE_NAMES:
        if isinstance(rules.get(name), dict):
            current[name].update({k: v for k, v in rules[name].items() if k in current[name]})

    for name in RULE_NAMES:
        rule = current[name]
        rule["enabled"] = bool(rule["enabled"])
        rule["notify"] = bool(rule.get("notify", True))
        if name in BAN_RULES:
            if rule["mode"] not in ("watch", "enforce"):
                raise ValueError("A rule either watches or bans")
            if rule["mode"] == "enforce" and not can_ban:
                raise ValueError("Banning needs the Read-Write API key (MAILCOW_API_KEY_RW)")
            rule["ban_hours"] = _int(rule["ban_hours"], 0, 8760, "The ban length in hours")

    known, _ = _known_accounts(db)
    local_parts = {address.split("@", 1)[0] for address in known}
    names = []
    for raw in current["trap"]["names"] or []:
        name = str(raw).strip().lower()
        if not name:
            continue
        if len(name) > 255 or not _NAME_RE.match(name):
            raise ValueError(f"{name} is not an account name")
        # A real account as a trap would ban its own user for one wrong password
        if _is_existing(name, known, local_parts):
            raise ValueError(f"{name} is an existing mailbox or alias, so it cannot be a trap")
        if name not in names:
            names.append(name)
    current["trap"]["names"] = names[:500]

    ua = current["unknown_accounts"]
    ua["threshold"] = _int(ua["threshold"], 2, 100, "The number of accounts")
    ua["window_minutes"] = _int(ua["window_minutes"], 5, 1440, "The time window")
    ro = current["repeat_offender"]
    ro["threshold"] = _int(ro["threshold"], 2, 50, "The number of bans")
    ro["window_days"] = _int(ro["window_days"], 1, 365, "The number of days")
    sn = current["subnet"]
    sn["threshold"] = _int(sn["threshold"], 2, 256, "The number of addresses")
    sn["window_hours"] = _int(sn["window_hours"], 1, 168, "The time window")
    countries = []
    for raw in current["country"]["countries"] or []:
        code = str(raw).strip().upper()
        if not _COUNTRY_RE.match(code):
            raise ValueError(f"{code} is not a two-letter country code")
        if code not in countries:
            countries.append(code)
    current["country"]["countries"] = countries
    br = current["breach"]
    br["failures"] = _int(br["failures"], 1, 50, "The number of failed tries")
    br["window_minutes"] = _int(br["window_minutes"], 5, 1440, "The time window")
    br["new_country"] = bool(br["new_country"])

    _store(db, RULES_KEY, json.dumps(current))
    # A rule switched back to watching bans nothing it has not banned yet
    watching = [n for n in BAN_RULES if current[n]["mode"] == "watch" or not current[n]["enabled"]]
    db.query(ProtectionHit).filter(ProtectionHit.status == "pending", ProtectionHit.rule.in_(watching),
                                   ProtectionHit.mode == "enforce").update({"status": "watching", "mode": "watch"}, synchronize_session=False)
    db.commit()
    logger.info("Protection rules saved: %s", ", ".join(
        f"{n} {'off' if not current[n]['enabled'] else current[n].get('mode', 'alert')}" for n in RULE_NAMES))
    return current


# ---------------------------------------------------------------- never catch

def _networks(entries: Iterable[str]):
    nets = []
    for entry in entries:
        try:
            nets.append(ipaddress.ip_network(str(entry).strip(), strict=False))
        except ValueError:
            continue
    return nets


def never_ban(ip: str, allow_networks, protected_ips: Set[str]) -> bool:
    """True for addresses no rule may catch."""
    if not ip or ip in protected_ips:
        return True
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True  # not an address: nothing to ban
    return any(address.version == net.version and address in net for net in list(allow_networks) + _INTERNAL_NETWORKS)


def _network_is_protected(net, allow_networks, protected_ips: Set[str]) -> bool:
    """A network may not be banned when it overlaps anything that may never be."""
    for other in list(allow_networks) + _INTERNAL_NETWORKS:
        if other.version == net.version and net.overlaps(other):
            return True
    for ip in protected_ips:
        try:
            if ipaddress.ip_address(ip) in net:
                return True
        except ValueError:
            continue
    return False


def _logged_in_recently(db: Session, ip: str, now: datetime) -> bool:
    """A successful SMTP or IMAP login from this address in the last day."""
    since = now - _SUCCESS_LOGIN_WINDOW
    smtp = db.query(PostfixLog.id).filter(
        PostfixLog.time >= since,
        PostfixLog.message.like("%sasl_username=%"),
        # Postfix writes an IPv6 client as [IPv6:2001:db8::1]
        or_(PostfixLog.message.like(f"%[{ip}]%"), PostfixLog.message.like(f"%[IPv6:{ip}]%")),
    ).first()
    if smtp:
        return True
    imap = db.query(RawServiceLog.id).filter(
        RawServiceLog.service == "dovecot",
        RawServiceLog.time >= since,
        RawServiceLog.raw_data["message"].astext.like("%Login: user=<%"),
        RawServiceLog.raw_data["message"].astext.like(f"%rip={ip},%"),
    ).first()
    return imap is not None


# ---------------------------------------------------------------- recording

def _is_unknown(username: str, known: Set[str], catch_all: Set[str]) -> bool:
    """mailcow logins are full addresses: a bare name, or an address with no mailbox, does not exist."""
    name = username.lower()
    if "@" not in name:
        return True
    if name in known:
        return False
    return name.split("@", 1)[1] not in catch_all


def hit_dict(hit: ProtectionHit) -> dict:
    """A catch as the API and the Security page see it."""
    return {
        "id": hit.id,
        "ip": hit.ip,
        "rule": hit.rule,
        "mode": hit.mode,
        "status": hit.status,
        "reason": hit.reason,
        "usernames": hit.usernames or [],
        "attempts": hit.attempts or 0,
        "country_code": hit.country_code,
        "country_name": hit.country_name,
        "first_seen": format_datetime_for_api(hit.first_seen),
        "last_seen": format_datetime_for_api(hit.last_seen),
        "ended_at": format_datetime_for_api(hit.ended_at),
        "ban_hours": hit.ban_hours,
        "banned_at": format_datetime_for_api(hit.banned_at),
        "expires_at": format_datetime_for_api(hit.expires_at),
        "owned": bool(hit.owned),
        "error": hit.error,
    }


def _record(found: Dict[tuple, dict], target: str, rule: str, reason: str, lines: List[NetfilterLog],
            trap: Optional[str] = None) -> None:
    entry = found.setdefault((target, rule), {"reason": reason, "lines": [], "traps": set()})
    entry["reason"] = reason or entry["reason"]
    entry["lines"].extend(lines)
    if trap:
        entry["traps"].add(trap)


def _trap_reason(names: Iterable[str]) -> str:
    names = sorted(set(names))
    return f"Tried the trap account{'s' if len(names) > 1 else ''} {', '.join(names)}"


def _traps_in(reason: Optional[str]) -> Set[str]:
    """The trap names an earlier run already put in a trap hit's reason."""
    match = re.match(r"^Tried the trap accounts? (.+)$", reason or "")
    return {n.strip() for n in match.group(1).split(",")} if match else set()


def _left_alone(db: Session, target: str, rule: str, now: datetime) -> bool:
    """The admin dismissed or undid this target for this rule less than a week ago."""
    return db.query(ProtectionHit.id).filter(
        ProtectionHit.ip == target, ProtectionHit.rule == rule,
        ProtectionHit.status.in_(("dismissed", "undone")), ProtectionHit.ended_at >= now - LEAVE_ALONE,
    ).first() is not None


def _upsert(db: Session, target: str, rule: str, reason: str, lines: list, rules: dict,
            now: datetime, times: Optional[List[datetime]] = None) -> Tuple[Optional[ProtectionHit], bool]:
    """Add the lines to the open hit for this target and rule, or open one. Returns (hit, created)."""
    hit = db.query(ProtectionHit).filter(
        ProtectionHit.ip == target, ProtectionHit.rule == rule, ProtectionHit.status.in_(OPEN_STATUSES)
    ).first()
    names = sorted({l.username for l in lines if getattr(l, "username", None)})
    ids = [l.id for l in lines]
    stamps = times or [l.time for l in lines]
    first, last = min(stamps), max(stamps)
    geo = next((l for l in lines if getattr(l, "country_code", None)), None)
    if hit is None:
        if _left_alone(db, target, rule, now):
            return None, False
        config = rules.get(rule, {})
        banning = rule in BAN_RULES and config.get("mode") == "enforce"
        hit = ProtectionHit(ip=target, rule=rule, mode="enforce" if banning else "watch",
                            status="alert" if rule == "breach" else ("pending" if banning else "watching"),
                            reason=reason, usernames=names, log_ids=ids[:MAX_EVIDENCE], attempts=len(set(ids)),
                            first_seen=first, last_seen=last, ban_hours=config.get("ban_hours"),
                            country_code=geo.country_code if geo else None, country_name=geo.country_name if geo else None)
        db.add(hit)
        return hit, True
    seen = set(hit.log_ids or [])
    fresh = [i for i in ids if i not in seen]
    hit.usernames = sorted(set(hit.usernames or []) | set(names))
    hit.log_ids = (list(hit.log_ids or []) + fresh)[:MAX_EVIDENCE]
    hit.attempts = (hit.attempts or 0) + len(set(fresh))
    if reason:
        hit.reason = reason
    hit.first_seen = min(hit.first_seen, first)
    hit.last_seen = max(hit.last_seen, last)
    # Still attacking after its rule was switched to ban: ban it now
    config = rules.get(rule, {})
    if fresh and hit.status == "watching" and rule in BAN_RULES and config.get("mode") == "enforce":
        hit.status, hit.mode, hit.ban_hours = "pending", "enforce", config.get("ban_hours")
    return hit, False


# ---------------------------------------------------------------- evaluation

def _read_watermark(db: Session, key: str, model) -> Optional[int]:
    """The last id read, or None on the first run (which starts from now, never from the history)."""
    stored = _setting(db, key)
    if stored is None:
        last = db.query(model.id).order_by(model.id.desc()).first()
        _store(db, key, str(last[0] if last else 0))
        db.commit()
        return None
    try:
        return int(stored)
    except ValueError:
        return 0


def evaluate(db: Session, context: ProtectionContext, now: Optional[datetime] = None) -> List[ProtectionHit]:
    """Read what was logged since the last run and record what the rules catch. Returns the new hits."""
    now = now or datetime.utcnow()
    rules = load_rules(db)
    created: List[ProtectionHit] = []
    created += _evaluate_netfilter(db, context, rules, now)
    created += _evaluate_breach(db, context, rules, now)
    quiet = _close_quiet(db, now)
    db.commit()
    if created:
        logger.info("Protection rules caught %d new address(es)", len(created))
    if quiet:
        logger.info("Protection rules: %d watched address(es) quiet for %d days moved to the history", quiet, QUIET_AFTER.days)
    return created


def _close_quiet(db: Session, now: datetime) -> int:
    """Close the watched catches with no new activity for QUIET_AFTER. Only
    'watching' ones: a ban ends on its own clock, and an alert waits for the admin.
    If the address comes back, the rule catches it again as a new catch."""
    return db.query(ProtectionHit).filter(
        ProtectionHit.status == "watching", ProtectionHit.last_seen < now - QUIET_AFTER,
    ).update({"status": "expired", "ended_at": now}, synchronize_session=False)


def _evaluate_netfilter(db: Session, context: ProtectionContext, rules: dict, now: datetime) -> List[ProtectionHit]:
    watermark = _read_watermark(db, WATERMARK_KEY, NetfilterLog)
    if watermark is None:
        return []
    rows = db.query(NetfilterLog).filter(NetfilterLog.id > watermark).order_by(NetfilterLog.id).limit(BATCH_SIZE).all()
    if not rows:
        return []
    new_watermark = rows[-1].id
    found: Dict[tuple, dict] = {}

    if any(rules[n]["enabled"] for n in BAN_RULES):
        allow = _networks(context.allowlist)
        candidates = [r for r in rows if r.ip and not never_ban(r.ip, allow, context.protected_ips)]
        tried = [r for r in candidates if r.username]

        if rules["trap"]["enabled"] and rules["trap"]["names"]:
            # A trap saved before its mailbox existed must never ban the real user
            known, _ = _known_accounts(db)
            local_parts = {address.split("@", 1)[0] for address in known}
            traps = set()
            for name in rules["trap"]["names"]:
                if _is_existing(name, known, local_parts):
                    logger.warning("Protection rules: trap %s is now a real mailbox or alias and is skipped", name)
                else:
                    traps.add(name)
            for row in tried:
                # A full trap address matches exactly; a bare trap name matches the part before the @
                name = row.username.lower()
                local = name.split("@", 1)[0]
                matched = name if name in traps else local if local in traps else None
                if matched:
                    _record(found, row.ip, "trap", "", [row], matched)

        ua = rules["unknown_accounts"]
        if ua["enabled"]:
            known, catch_all = _known_accounts(db)
            since = now - timedelta(minutes=ua["window_minutes"])
            for ip in sorted({r.ip for r in tried}):
                window = db.query(NetfilterLog).filter(
                    NetfilterLog.ip == ip, NetfilterLog.time >= since, NetfilterLog.username.isnot(None)
                ).all()
                unknown = [l for l in window if _is_unknown(l.username, known, catch_all)]
                accounts = {l.username.lower() for l in unknown}
                if len(accounts) < ua["threshold"] or _logged_in_recently(db, ip, now):
                    continue
                _record(found, ip, "unknown_accounts",
                        f"Tried {len(accounts)} accounts that do not exist within {ua['window_minutes']} minutes", unknown)

        ro = rules["repeat_offender"]
        if ro["enabled"]:
            since = now - timedelta(days=ro["window_days"])
            # Only Fail2ban's own bans count: mailcow also logs a blacklist entry
            # ("Added host/network ... to denylist") as a ban, including the ones this app adds
            fail2ban_ban = lambda r: (r.action or "") == "ban" and (r.message or "").startswith("Banning ")
            for ip in sorted({r.ip for r in candidates if fail2ban_ban(r)}):
                bans = db.query(NetfilterLog).filter(
                    NetfilterLog.ip == ip, NetfilterLog.action == "ban", NetfilterLog.message.like("Banning %"),
                    NetfilterLog.time >= since,
                ).all()
                if len(bans) >= ro["threshold"]:
                    _record(found, ip, "repeat_offender",
                            f"Banned by Fail2ban {len(bans)} times in {ro['window_days']} days", bans)

        sn = rules["subnet"]
        if sn["enabled"]:
            since = now - timedelta(hours=sn["window_hours"])
            seen_nets = set()
            for row in candidates:
                try:
                    address = ipaddress.ip_address(row.ip)
                except ValueError:
                    continue
                if address.version != 4:
                    continue  # IPv6 networks are left to a later version
                net = ipaddress.ip_network(f"{row.ip}/24", strict=False)
                if net in seen_nets:
                    continue
                seen_nets.add(net)
                if _network_is_protected(net, allow, context.protected_ips):
                    continue
                prefix = str(net.network_address).rsplit(".", 1)[0] + "."
                lines = db.query(NetfilterLog).filter(NetfilterLog.ip.like(f"{prefix}%"), NetfilterLog.time >= since).all()
                addresses = {l.ip for l in lines}
                if len(addresses) >= sn["threshold"]:
                    _record(found, str(net), "subnet",
                            f"{len(addresses)} addresses in {net} attacked within {sn['window_hours']} hours", lines)

        co = rules["country"]
        if co["enabled"] and co["countries"] and context.geoip:
            wanted = set(co["countries"])
            for row in candidates:
                if (row.country_code or "").upper() in wanted:
                    _record(found, row.ip, "country", f"Failed to log in from {row.country_name or row.country_code}", [row])

    created = []
    for (target, rule), entry in found.items():
        hit, is_new = _upsert(db, target, rule, entry["reason"], entry["lines"], rules, now)
        if hit is None:
            continue
        if rule == "trap":
            # Every trap this address tried, including those from earlier runs
            hit.reason = _trap_reason(entry["traps"] | _traps_in(hit.reason))
        if is_new:
            created.append(hit)
    _store(db, WATERMARK_KEY, str(new_watermark))
    return created


# ---------------------------------------------------------------- breach alert

@dataclass
class _Login:
    id: int
    time: datetime
    username: str
    ip: str


def _successful_logins(db: Session, context: ProtectionContext) -> List[_Login]:
    """New successful SMTP logins, and IMAP logins when the raw logs are read."""
    logins: List[_Login] = []
    mark = _read_watermark(db, BREACH_POSTFIX_KEY, PostfixLog)
    if mark is not None:
        rows = db.query(PostfixLog).filter(PostfixLog.id > mark, PostfixLog.message.like("%sasl_username=%")).order_by(PostfixLog.id).limit(BATCH_SIZE).all()
        last = db.query(func.max(PostfixLog.id)).scalar() or mark
        for row in rows:
            match = _POSTFIX_LOGIN_RE.search(row.message or "")
            if match:
                logins.append(_Login(row.id, row.time, match.group(2).lower(), match.group(1)))
        _store(db, BREACH_POSTFIX_KEY, str(rows[-1].id if len(rows) == BATCH_SIZE else last))
    if context.raw_logs:
        mark = _read_watermark(db, BREACH_DOVECOT_KEY, RawServiceLog)
        if mark is not None:
            rows = db.query(RawServiceLog).filter(
                RawServiceLog.id > mark, RawServiceLog.service == "dovecot",
                RawServiceLog.raw_data["message"].astext.like("%Login: user=<%"),
            ).order_by(RawServiceLog.id).limit(BATCH_SIZE).all()
            last = db.query(func.max(RawServiceLog.id)).scalar() or mark
            for row in rows:
                match = _DOVECOT_LOGIN_RE.search((row.raw_data or {}).get("message") or "")
                if match:
                    logins.append(_Login(-row.id, row.time, match.group(1).lower(), match.group(2)))
            _store(db, BREACH_DOVECOT_KEY, str(rows[-1].id if len(rows) == BATCH_SIZE else last))
    return logins


def _countries_of(ips: Iterable[str]) -> Set[str]:
    from . import geoip_service
    out = set()
    for ip in ips:
        code = (geoip_service.lookup_ip(ip) or {}).get("country_code")
        if code:
            out.add(code)
    return out


def _evaluate_breach(db: Session, context: ProtectionContext, rules: dict, now: datetime) -> List[ProtectionHit]:
    br = rules["breach"]
    logins = _successful_logins(db, context)
    if not br["enabled"] or not logins:
        return []
    allow = _networks(context.allowlist)
    created = []
    for login in logins:
        if never_ban(login.ip, allow, context.protected_ips):
            continue
        reason = None
        failures = db.query(func.count(NetfilterLog.id)).filter(
            NetfilterLog.ip == login.ip, NetfilterLog.time >= login.time - timedelta(minutes=br["window_minutes"]),
            NetfilterLog.time <= login.time,
        ).scalar() or 0
        if failures >= br["failures"]:
            reason = f"{login.username} logged in after {failures} failed tries from the same address"
        elif br["new_country"] and context.geoip:
            current = _countries_of([login.ip])
            earlier_ips = set()
            for (message,) in db.query(PostfixLog.message).filter(
                PostfixLog.time >= login.time - timedelta(days=30), PostfixLog.time < login.time,
                PostfixLog.message.like(f"%sasl_username={login.username}%"),
            ).limit(500).all():
                match = _POSTFIX_LOGIN_RE.search(message or "")
                if match and match.group(1) != login.ip:
                    earlier_ips.add(match.group(1))
            earlier = _countries_of(sorted(earlier_ips)[:50])
            if current and earlier and not (current & earlier):
                reason = f"{login.username} logged in from {', '.join(sorted(current))}, a country it did not use in 30 days"
        if not reason:
            continue

        class _Line:  # the login as evidence, in the shape _upsert reads
            pass
        line = _Line()
        line.id, line.time, line.username, line.country_code, line.country_name = login.id, login.time, login.username, None, None
        hit, is_new = _upsert(db, login.ip, "breach", reason, [line], rules, now)
        if hit is not None and is_new:
            created.append(hit)
    return created


# ---------------------------------------------------------------- enforcement

def split_ip_list(value) -> List[str]:
    """mailcow returns the Fail2ban lists comma or newline separated."""
    return [e.strip() for e in (value or "").replace("\n", ",").split(",") if e.strip()]


def fail2ban_attrs(current: dict, blacklist: List[str], whitelist: List[str]) -> dict:
    """Every Fail2ban setting mailcow expects on an edit, with the given lists."""
    bti = current.get("ban_time_increment", 1)
    return {
        "ban_time": str(current.get("ban_time", "86400")),
        "ban_time_increment": "1" if bti in (True, 1, "1") else "0",
        "blacklist": ",".join(blacklist),
        "max_attempts": str(current.get("max_attempts", "5")),
        "max_ban_time": str(current.get("max_ban_time", "86400")),
        "netban_ipv4": str(current.get("netban_ipv4", "24")),
        "netban_ipv6": str(current.get("netban_ipv6", "64")),
        "retry_window": str(current.get("retry_window", "600")),
        "whitelist": ",".join(whitelist),
        # mailcow turns this off on any edit that leaves it out
        "manage_external": "1" if current.get("manage_external") in (True, 1, "1") else "0",
    }


def _blacklist_entry(target: str) -> str:
    """How a ban is written to the blacklist: a single address as /32 (/128), as
    the Ban button on the page writes it; a network keeps its own prefix."""
    if "/" in target:
        return target
    try:
        return f"{target}/{ipaddress.ip_address(target).max_prefixlen}"
    except ValueError:
        return target


def _in_list(target: str, entries: List[str]) -> bool:
    """mailcow keeps a single address either bare or as /32 (/128)."""
    if target in entries:
        return True
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    return any(_same(e, net) for e in entries)


def _same(entry: str, net) -> bool:
    try:
        return ipaddress.ip_network(entry, strict=False) == net
    except ValueError:
        return False


def _without(target: str, entries: List[str]) -> List[str]:
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return [e for e in entries if e != target]
    return [e for e in entries if e != target and not _same(e, net)]


def _hand_over(db: Session, hit: ProtectionHit) -> bool:
    """When a hit that added an entry ends while another rule still bans the same target,
    that hit takes the entry over. Returns True when one did."""
    other = db.query(ProtectionHit).filter(
        ProtectionHit.ip == hit.ip, ProtectionHit.status == "banned", ProtectionHit.id != hit.id
    ).order_by(ProtectionHit.expires_at.is_(None).desc(), ProtectionHit.expires_at.desc()).first()
    if other is None:
        return False
    other.owned = True
    return True


async def enforce(mailcow_api, now: Optional[datetime] = None) -> Dict[str, list]:
    """Write pending bans to the Fail2ban blacklist and lift the ones that ended, in one edit.

    Returns {'banned': [...], 'lifted': [...], 'failed': [...]} as (target, rule, reason, notify) tuples
    for the caller to notify about.
    """
    from ..database import get_db_context
    now = now or datetime.utcnow()
    with get_db_context() as db:
        pending = db.query(ProtectionHit).filter(ProtectionHit.status == "pending").all()
        ending = db.query(ProtectionHit).filter(
            ProtectionHit.status == "banned", ProtectionHit.expires_at.isnot(None), ProtectionHit.expires_at <= now
        ).all()
        if not pending and not ending:
            return {"banned": [], "lifted": [], "failed": []}
        pending_ids = [h.id for h in pending]
        ending_ids = [h.id for h in ending]

    current = await mailcow_api.get_fail2ban()
    if not current:
        with get_db_context() as db:
            for hit in db.query(ProtectionHit).filter(ProtectionHit.id.in_(pending_ids)).all():
                hit.error = "Could not read the Fail2ban settings from mailcow"
            db.commit()
        return {"banned": [], "lifted": [], "failed": pending_ids}

    blacklist = split_ip_list(current.get("blacklist"))
    whitelist = split_ip_list(current.get("whitelist"))
    allow = _networks(whitelist)
    rules = None
    result = {"banned": [], "lifted": [], "failed": []}
    with get_db_context() as db:
        rules = load_rules(db)
        pending = db.query(ProtectionHit).filter(ProtectionHit.id.in_(pending_ids)).all()
        ending = db.query(ProtectionHit).filter(ProtectionHit.id.in_(ending_ids)).all()
        new_black = list(blacklist)
        added: Set[str] = set()
        for hit in pending:
            # Put on the allowlist in the meantime: never ban it
            try:
                on_allowlist = ("/" in hit.ip and _network_is_protected(ipaddress.ip_network(hit.ip, strict=False), allow, set())) \
                    or ("/" not in hit.ip and never_ban(hit.ip, allow, set()))
            except ValueError:
                on_allowlist = True
            if on_allowlist:
                hit.status, hit.ended_at, hit.error = "dismissed", now, "On the allowlist now, so it was not banned"
                continue
            if not _in_list(hit.ip, new_black):
                new_black.append(_blacklist_entry(hit.ip))
                added.add(hit.ip)
        for hit in ending:
            hit.status, hit.ended_at = "expired", now
            if hit.owned and hit.ip not in added and not _hand_over(db, hit):
                new_black = _without(hit.ip, new_black)
        changed = new_black != blacklist
        error = None
        if changed:
            try:
                response = await mailcow_api.edit_fail2ban(fail2ban_attrs(current, new_black, whitelist))
                first = response[0] if isinstance(response, list) and response else {}
                if isinstance(first, dict) and first.get("type") not in (None, "success"):
                    error = first.get("msg") or "mailcow refused the change"
            except Exception as e:
                error = str(e) or "The change could not be written to mailcow"
        for hit in pending:
            if hit.status != "pending":
                continue
            if error:
                hit.error = f"Not banned yet: {error}"
                result["failed"].append((hit.ip, hit.rule, hit.reason, rules.get(hit.rule, {}).get("notify", True)))
                continue
            hit.status, hit.banned_at, hit.error = "banned", now, None
            hit.owned = hit.ip in added
            hours = hit.ban_hours if hit.ban_hours is not None else rules.get(hit.rule, {}).get("ban_hours", 0)
            hit.ban_hours = hours
            hit.expires_at = now + timedelta(hours=hours) if hours else None
            result["banned"].append((hit.ip, hit.rule, hit.reason, rules.get(hit.rule, {}).get("notify", True)))
        if error:
            # Nothing was written: the ended bans stay until the next run can lift them
            for hit in ending:
                hit.status, hit.ended_at = "banned", None
        else:
            result["lifted"] = [(h.ip, h.rule, h.reason, False) for h in ending]
        db.commit()
    if changed and not error:
        logger.info("Protection rules: banned %d, lifted %d", len(result["banned"]), len(result["lifted"]))
    return result


async def undo(mailcow_api, hit_id: int) -> Optional[ProtectionHit]:
    """Lift a ban (or cancel a pending one) and leave the address alone for a week."""
    from ..database import get_db_context
    now = datetime.utcnow()
    with get_db_context() as db:
        hit = db.query(ProtectionHit).filter(ProtectionHit.id == hit_id).first()
        if hit is None:
            return None
        target, owned, status = hit.ip, hit.owned, hit.status
        if status == "banned" and owned and _hand_over(db, hit):
            owned = False
            hit.owned = False
            db.commit()
    if status == "banned" and owned:
        current = await mailcow_api.get_fail2ban()
        if not current:
            raise RuntimeError("Could not read the Fail2ban settings from mailcow")
        blacklist = split_ip_list(current.get("blacklist"))
        new_black = _without(target, blacklist)
        if new_black != blacklist:
            response = await mailcow_api.edit_fail2ban(fail2ban_attrs(current, new_black, split_ip_list(current.get("whitelist"))))
            first = response[0] if isinstance(response, list) and response else {}
            if isinstance(first, dict) and first.get("type") not in (None, "success"):
                raise RuntimeError(first.get("msg") or "mailcow refused the change")
    with get_db_context() as db:
        hit = db.query(ProtectionHit).filter(ProtectionHit.id == hit_id).first()
        if hit.status in OPEN_STATUSES:
            hit.status = "undone" if status in ("banned", "pending") else "dismissed"
            hit.ended_at = now
            db.commit()
        db.refresh(hit)
        db.expunge(hit)
        logger.info("Protection hit %s by the admin: %s (%s)", hit.status, hit.ip, hit.rule)
        return hit


def request_ban(db: Session, hit_id: int) -> Optional[ProtectionHit]:
    """Ban a hit the admin reviewed in watch mode; enforce() writes it on its next run."""
    hit = db.query(ProtectionHit).filter(ProtectionHit.id == hit_id).first()
    if hit is None or hit.status != "watching":
        return hit
    rules = load_rules(db)
    # 'manual': the admin chose this one, so switching the rule back to watching keeps it
    hit.status, hit.mode = "pending", "manual"
    hit.ban_hours = rules.get(hit.rule, {}).get("ban_hours", 0)
    db.commit()
    return hit
