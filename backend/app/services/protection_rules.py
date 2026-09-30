"""
Protection rules: act on the failed logins netfilter records.

A rule reads the new netfilter lines, decides which addresses it would ban and
records why as a ProtectionHit. This layer is watch mode only: nothing is
written to Fail2ban. The admin reviews the hits before a rule is ever allowed
to ban.

Rules
- trap: names the admin knows have no mailbox. Any address that tries one is
  caught at once. A trap may not be a real mailbox or alias.
- unknown_accounts: an address that tried several accounts which do not exist
  within a time window. A real user who mistyped is protected: an address with
  a successful login in the last day is never caught by this rule.

Some addresses are never caught by any rule: the Fail2ban allowlist (matched as
networks), internal networks, and the mailcow host with its transports and
relay hosts (ProtectionContext.protected_ips).

The rules are operational state, stored in system_settings as JSON like the
ignore lists, so they can be managed on the Security page even when editing
settings from the UI is off. The netfilter reading moves forward with a stored
log id, so a restart never reads the same line twice and a rule switched on
later never reaches back into lines already read.
"""
import copy
import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Set

from sqlalchemy import or_
from sqlalchemy.orm import Session

from .alias_domains import aliases_of_domain, expand_addresses, get_alias_domain_map
from ..models import AliasStatistics, MailboxStatistics, NetfilterLog, PostfixLog, ProtectionHit, RawServiceLog, SystemSetting

logger = logging.getLogger(__name__)

RULES_KEY = "protection.rules"
WATERMARK_KEY = "protection.watermark"
BATCH_SIZE = 5000
MAX_EVIDENCE = 200
RULE_NAMES = ("trap", "unknown_accounts")

DEFAULT_RULES: Dict[str, dict] = {
    "trap": {"enabled": False, "mode": "watch", "names": []},
    "unknown_accounts": {"enabled": False, "mode": "watch", "threshold": 5, "window_minutes": 60},
}

# Internal networks, spelled out: ipaddress' is_private also covers the
# documentation ranges, which are public-facing test addresses here
_INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10",
)]
_NAME_RE = re.compile(r"^[a-z0-9._%+\-]+(@[a-z0-9.\-]+)?$")
_SUCCESS_LOGIN_WINDOW = timedelta(hours=24)


@dataclass
class ProtectionContext:
    """What the rules need from outside the database, read once per run."""
    allowlist: List[str] = field(default_factory=list)   # Fail2ban allowlist entries (addresses or networks)
    protected_ips: Set[str] = field(default_factory=set)  # mailcow host, transports, relay hosts


# ---------------------------------------------------------------- the rules

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


def save_rules(db: Session, rules: dict) -> Dict[str, dict]:
    """Validate and store the rules. Raises ValueError with a message the admin can act on."""
    current = load_rules(db)
    for name in RULE_NAMES:
        if isinstance(rules.get(name), dict):
            current[name].update({k: v for k, v in rules[name].items() if k in current[name]})

    for name in RULE_NAMES:
        current[name]["enabled"] = bool(current[name]["enabled"])
        # Watch mode only for now: nothing is written to Fail2ban
        current[name]["mode"] = "watch"

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
        if (name in known) if "@" in name else (name in local_parts):
            raise ValueError(f"{name} is an existing mailbox or alias, so it cannot be a trap")
        if name not in names:
            names.append(name)
    current["trap"]["names"] = names[:500]

    ua = current["unknown_accounts"]
    ua["threshold"] = _int(ua["threshold"], 2, 100, "The number of accounts")
    ua["window_minutes"] = _int(ua["window_minutes"], 5, 1440, "The time window")

    _store(db, RULES_KEY, json.dumps(current))
    db.commit()
    logger.info("Protection rules saved: trap %s (%d names), unknown accounts %s",
                "on" if current["trap"]["enabled"] else "off", len(names),
                "on" if ua["enabled"] else "off")
    return current


# ---------------------------------------------------------------- never ban

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


# ---------------------------------------------------------------- evaluation

def _is_unknown(username: str, known: Set[str], catch_all: Set[str]) -> bool:
    """mailcow logins are full addresses: a bare name, or an address with no mailbox, does not exist."""
    name = username.lower()
    if "@" not in name:
        return True
    if name in known:
        return False
    return name.split("@", 1)[1] not in catch_all


def _record(db: Session, found: Dict[tuple, dict], ip: str, rule: str, reason: str, lines: List[NetfilterLog],
            trap: Optional[str] = None) -> None:
    entry = found.setdefault((ip, rule), {"reason": reason, "lines": [], "traps": set()})
    entry["reason"] = reason or entry["reason"]
    entry["lines"].extend(lines)
    if trap:
        entry["traps"].add(trap)


def _trap_reason(names: Iterable[str]) -> str:
    names = sorted(set(names))
    return f"Tried the trap account{'s' if len(names) > 1 else ''} {', '.join(names)}"


def _upsert(db: Session, ip: str, rule: str, reason: str, lines: List[NetfilterLog]) -> ProtectionHit:
    hit = db.query(ProtectionHit).filter(
        ProtectionHit.ip == ip, ProtectionHit.rule == rule, ProtectionHit.status == "watching"
    ).first()
    names = sorted({l.username for l in lines if l.username})
    ids = [l.id for l in lines]
    first = min(l.time for l in lines)
    last = max(l.time for l in lines)
    geo = next((l for l in lines if l.country_code), None)
    if hit is None:
        hit = ProtectionHit(ip=ip, rule=rule, mode="watch", status="watching", reason=reason, usernames=names,
                            log_ids=ids[:MAX_EVIDENCE], attempts=len(set(ids)), first_seen=first, last_seen=last,
                            country_code=geo.country_code if geo else None, country_name=geo.country_name if geo else None)
        db.add(hit)
        return hit
    seen = set(hit.log_ids or [])
    fresh = [i for i in ids if i not in seen]
    hit.usernames = sorted(set(hit.usernames or []) | set(names))
    hit.log_ids = (list(hit.log_ids or []) + fresh)[:MAX_EVIDENCE]
    hit.attempts = (hit.attempts or 0) + len(set(fresh))
    if reason:
        hit.reason = reason
    hit.first_seen = min(hit.first_seen, first)
    hit.last_seen = max(hit.last_seen, last)
    return hit


def _traps_in(reason: Optional[str]) -> Set[str]:
    """The trap names an earlier run already put in a trap hit's reason."""
    match = re.match(r"^Tried the trap accounts? (.+)$", reason or "")
    return {n.strip() for n in match.group(1).split(",")} if match else set()


def evaluate(db: Session, context: ProtectionContext, now: Optional[datetime] = None) -> List[ProtectionHit]:
    """Read the netfilter lines since the last run and record what the rules catch."""
    now = now or datetime.utcnow()
    stored = _setting(db, WATERMARK_KEY)
    if stored is None:
        # First run: start from now, never from the whole history
        last = db.query(NetfilterLog.id).order_by(NetfilterLog.id.desc()).first()
        _store(db, WATERMARK_KEY, str(last[0] if last else 0))
        db.commit()
        return []
    try:
        watermark = int(stored)
    except ValueError:
        watermark = 0

    rows = db.query(NetfilterLog).filter(NetfilterLog.id > watermark).order_by(NetfilterLog.id).limit(BATCH_SIZE).all()
    if not rows:
        return []
    new_watermark = rows[-1].id

    rules = load_rules(db)
    found: Dict[tuple, dict] = {}
    if rules["trap"]["enabled"] or rules["unknown_accounts"]["enabled"]:
        allow = _networks(context.allowlist)
        candidates = [r for r in rows if r.username and not never_ban(r.ip, allow, context.protected_ips)]

        if rules["trap"]["enabled"] and rules["trap"]["names"]:
            # A trap saved before its mailbox existed must never ban the real user
            known, _ = _known_accounts(db)
            local_parts = {address.split("@", 1)[0] for address in known}
            traps = set()
            for name in rules["trap"]["names"]:
                if (name in known) if "@" in name else (name in local_parts):
                    logger.warning("Protection rules: trap %s is now a real mailbox or alias and is skipped", name)
                else:
                    traps.add(name)
            for row in candidates:
                # A full trap address matches exactly; a bare trap name matches the part before the @
                name = row.username.lower()
                local = name.split("@", 1)[0]
                matched = name if name in traps else local if local in traps else None
                if matched:
                    _record(db, found, row.ip, "trap", "", [row], matched)

        ua = rules["unknown_accounts"]
        if ua["enabled"]:
            known, catch_all = _known_accounts(db)
            since = now - timedelta(minutes=ua["window_minutes"])
            for ip in sorted({r.ip for r in candidates}):
                window = db.query(NetfilterLog).filter(
                    NetfilterLog.ip == ip, NetfilterLog.time >= since, NetfilterLog.username.isnot(None)
                ).all()
                unknown = [l for l in window if _is_unknown(l.username, known, catch_all)]
                accounts = {l.username.lower() for l in unknown}
                if len(accounts) < ua["threshold"] or _logged_in_recently(db, ip, now):
                    continue
                _record(db, found, ip, "unknown_accounts",
                        f"Tried {len(accounts)} accounts that do not exist within {ua['window_minutes']} minutes", unknown)

    hits = []
    for (ip, rule), entry in found.items():
        hit = _upsert(db, ip, rule, entry["reason"], entry["lines"])
        if rule == "trap":
            # Every trap this address tried, including those from earlier runs
            tried = entry["traps"] | _traps_in(hit.reason)
            hit.reason = _trap_reason(tried)
        hits.append(hit)
    _store(db, WATERMARK_KEY, str(new_watermark))
    db.commit()
    if hits:
        logger.info("Protection rules noted %d address(es) in watch mode", len(hits))
    return hits
