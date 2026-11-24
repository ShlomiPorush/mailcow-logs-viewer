import ipaddress
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Tuple

from sqlalchemy import and_, case, cast, desc, distinct, exists, func, literal, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from ..app_time import utc_naive
from ..config import cached_domains_known, is_hosted_domain, settings
from ..mailcow_api import mailbox_shared
from ..models import (AliasStatistics, BlacklistCheck, DMARCRecord, DMARCReport, DomainDNSCheck, EasDevice,
                      MailboxStatistics, MessageCorrelation, MonitoredHost, NetfilterLog, ProtectionHit,
                      RspamdLog, SpamSuppression)
from ..utils import format_datetime_for_api as iso
from . import entity_values, excluded_addresses, geoip_service, protection_rules, security_addresses, written_recipients

logger = logging.getLogger(__name__)

DEFAULT_DAYS = 7
MAX_DAYS = 90
ITEMS = 50
TIMELINE = 100
DMARC_DOMAINS = 20

_FEATURE_NAMES = {
    "netfilter": "Security", "devices": "Devices", "dmarc": "DMARC & TLS", "blacklist": "IP blocklists",
    "suppressions": "Suppressions", "mailbox-stats": "Mailboxes", "domains": "Domains",
}
_BAN_ACTIONS = ("ban", "banned")


class _Answer(Exception):

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class Unavailable(_Answer):
    pass


class Off(_Answer):
    pass


class TurnedOff(Off):
    pass


def resolve_range(start: Optional[datetime], end: Optional[datetime],
                  now: Optional[datetime] = None) -> Tuple[datetime, datetime]:
    now = now or datetime.utcnow()
    end = utc_naive(end) if end is not None else now
    start = utc_naive(start) if start is not None else end - timedelta(days=DEFAULT_DAYS)
    if start > end:
        raise entity_values.InvalidValue("The start of the range must be before its end.")
    if end - start > timedelta(days=MAX_DAYS):
        raise entity_values.InvalidValue(f"The range can be {MAX_DAYS} days at most.")
    return start, end


def _epoch(value: datetime) -> int:
    return int(value.replace(tzinfo=timezone.utc).timestamp())


def _from_epoch(value: Optional[int]) -> Optional[str]:
    if value is None:
        return None
    return iso(datetime.fromtimestamp(int(value), tz=timezone.utc))


def _run(db: Session, feature: Optional[str], what: str, read: Callable[[], dict], snapshot: bool = False) -> dict:
    if feature and not settings.is_feature_enabled(feature):
        return {"state": "disabled", "disabled": True, "reason": f"The {_FEATURE_NAMES[feature]} feature is turned off."}
    try:
        if snapshot:
            _rollback(db)
            db.connection(execution_options={"isolation_level": "REPEATABLE READ"})
        try:
            return {"state": "ok", "reason": None, **read()}
        finally:
            if snapshot:
                _rollback(db)
    except TurnedOff as e:
        return {"state": "disabled", "disabled": True, "reason": e.reason}
    except Off as e:
        return {"state": "disabled", "reason": e.reason}
    except Unavailable as e:
        _rollback(db)
        return {"state": "error", "reason": e.reason}
    except Exception:
        logger.exception("Could not read %s for the entity card", what)
        _rollback(db)
        return {"state": "error", "reason": f"Could not read {what}. The details are in the container log."}


def _rollback(db: Session) -> None:
    try:
        db.rollback()
    except Exception:  # pragma: no cover
        logger.debug("Rollback after a failed entity source failed too", exc_info=True)


def _like_suffix(column, domain: str):
    escaped = domain.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return func.lower(column).like(f"%@{escaped}", escape="\\")


def domain_match(column, domain: str):
    return or_(*[_like_suffix(column, form) for form in entity_values.domain_forms(domain)])


_domain_match = domain_match


IP_TEXTS_CHUNK = 5000
IP_TEXTS_CEILING = 200000


def _ip_spellings_match(column, ip: str):
    return column.in_(entity_values.ip_spellings(ip))


def _ip_value_match(texts_query, column, ip: str):
    spellings = entity_values.ip_spellings(ip)
    candidate = column.like("%:%") if ipaddress.ip_address(ip).version == 6 else column.ilike("%ffff%")
    found, read, last = set(spellings), 0, None
    while True:
        page = texts_query.with_entities(column).filter(candidate)
        if last is not None:
            page = page.filter(column > last)
        chunk = [t for (t,) in page.distinct().order_by(column).limit(IP_TEXTS_CHUNK).all()]
        read += len(chunk)
        if read > IP_TEXTS_CEILING:
            raise Unavailable("Too many different addresses are stored to compare them all. Try a shorter range.")
        found.update(t for t in chunk if entity_values.same_ip(t, ip))
        if len(chunk) < IP_TEXTS_CHUNK:
            break
        last = chunk[-1]
    return column.in_(sorted(found))


def _message_group_key():
    from ..routers.messages import message_group_key
    return message_group_key()


def _message_sort_time():
    from ..routers.messages import message_sort_time
    return message_sort_time()


def _count_messages(db: Session, condition, *parts) -> List[int]:
    key = _message_group_key()
    counts = [func.count(distinct(key))] + [func.count(distinct(key)).filter(part) for part in parts]
    return [int(n or 0) for n in db.query(*counts).select_from(MessageCorrelation).filter(condition).one()]


def _latest_messages(db: Session, condition, limit: int = ITEMS) -> List[dict]:
    legs = db.query(
        MessageCorrelation.id.label("leg_id"),
        _message_sort_time().label("sort_time"),
        func.row_number().over(
            partition_by=_message_group_key(),
            order_by=(_message_sort_time().asc(), MessageCorrelation.id.asc())).label("leg_rank"),
    ).select_from(MessageCorrelation).filter(condition).subquery()
    rows = db.query(MessageCorrelation).join(legs, MessageCorrelation.id == legs.c.leg_id).filter(
        legs.c.leg_rank == 1).order_by(desc(legs.c.sort_time), desc(legs.c.leg_id)).limit(limit).all()
    return [{
        "_at": m.first_seen, "correlation_key": m.correlation_key, "first_seen": iso(m.first_seen), "sender": m.sender,
        "recipient": written_recipients.shown(m.recipient, m.written_recipients), "subject": m.subject,
        "direction": m.direction, "final_status": m.final_status,
    } for m in rows]


def _in_range(start: datetime, end: datetime):
    return and_(MessageCorrelation.first_seen >= start, MessageCorrelation.first_seen <= end,
                excluded_addresses.correlation_visible())


def _messages_of_ip(db: Session, ip: str, start: datetime, end: datetime) -> dict:
    scanned_from = MessageCorrelation.rspamd_log_id.in_(
        select(RspamdLog.id).where(_ip_spellings_match(RspamdLog.ip, ip)))
    condition = and_(_in_range(start, end), scanned_from)
    count, = _count_messages(db, condition)
    return {"count": count, "items": _latest_messages(db, condition)}


def _messages_of(db: Session, sender, recipient, start: datetime, end: datetime) -> dict:
    condition = and_(_in_range(start, end), or_(sender, recipient))
    count, sent, received = _count_messages(db, condition, sender, recipient)
    return {"count": count, "sent": sent, "received": received, "items": _latest_messages(db, condition)}


def _address_columns(address: str):
    forms = entity_values.address_forms(address)
    return (func.lower(MessageCorrelation.sender).in_(forms),
            or_(func.lower(MessageCorrelation.recipient).in_(forms),
                written_recipients.any_value(MessageCorrelation.written_recipients, lambda v: func.lower(v).in_(forms))))


def _security(db: Session, condition, start: datetime, end: datetime, with_ips: bool) -> dict:
    window = and_(NetfilterLog.time >= start, NetfilterLog.time <= end, condition)
    figures = db.query(
        func.count(NetfilterLog.id),
        func.count(NetfilterLog.id).filter(NetfilterLog.rule_id.isnot(None)),
        func.count(NetfilterLog.id).filter(NetfilterLog.action.in_(_BAN_ACTIONS)),
        func.count(NetfilterLog.id).filter(NetfilterLog.action == "unban"),
        func.count(distinct(NetfilterLog.ip)),
        func.max(NetfilterLog.time),
    ).filter(window).one()
    rows = db.query(NetfilterLog).filter(window).order_by(desc(NetfilterLog.time), desc(NetfilterLog.id)).limit(ITEMS).all()
    result = {
        "events": figures[0], "rule_matches": figures[1], "bans": figures[2], "unbans": figures[3],
        "last_seen": iso(figures[5]),
        "items": [{
            "_at": r.time, "time": iso(r.time), "ip": r.ip, "action": r.action, "rule_id": r.rule_id, "username": r.username,
            "service": security_addresses.netfilter_service(r.message)[0], "attempts_left": r.attempts_left,
            "message": r.message,
        } for r in rows],
    }
    if with_ips:
        result["ips"] = figures[4]
    return result


def _netfilter_username(match):
    return and_(NetfilterLog.username.isnot(None), match)


def _lists(ip: str, read_fail2ban: Callable[[], Optional[dict]]) -> dict:
    f2b = read_fail2ban()
    if not security_addresses.fail2ban_answered(f2b):
        raise Unavailable("mailcow did not answer, so the allowlist, denylist and bans are not known.")
    whitelist = protection_rules.split_ip_list(f2b.get("whitelist"))
    blacklist = protection_rules.split_ip_list(f2b.get("blacklist"))
    address = ipaddress.ip_address(ip)
    ban = None
    for entry in f2b.get("active_bans") or []:
        if not isinstance(entry, dict):
            continue
        network = security_addresses._ban_network(entry)
        if network is not None and network.version == address.version and address in network:
            ban = {"network": str(network), "banned_until": entry.get("banned_until"),
                   "queued_for_unban": security_addresses._truthy(entry.get("queued_for_unban"))}
            break
    return {
        "allowlisted_as": security_addresses._entry_for(whitelist, ip),
        "denylisted_as": security_addresses._entry_for(blacklist, ip),
        "ban": ban,
    }


def _usernames_match(match_value):
    column = ProtectionHit.usernames
    array = case((func.jsonb_typeof(column) == "array", column), else_=cast(literal("[]"), JSONB))
    names = func.jsonb_array_elements_text(array).table_valued("value").alias("names")
    return exists(select(literal(1)).select_from(names).where(match_value(names.c.value)))


def _protection_window(start: datetime, end: datetime):
    return or_(ProtectionHit.status.in_(protection_rules.OPEN_STATUSES),
               and_(ProtectionHit.last_seen >= start, ProtectionHit.first_seen <= end))


def _protection_of_ip(db: Session, ip: str, start: datetime, end: datetime) -> dict:
    window = _protection_window(start, end)
    return _protection(db, _ip_value_match(db.query(ProtectionHit).filter(window), ProtectionHit.ip, ip), start, end)


def _protection(db: Session, condition, start: datetime, end: datetime) -> dict:
    relevant = and_(condition, _protection_window(start, end))
    total, open_count = db.query(
        func.count(ProtectionHit.id),
        func.count(ProtectionHit.id).filter(ProtectionHit.status.in_(protection_rules.OPEN_STATUSES)),
    ).filter(relevant).one()
    rows = db.query(ProtectionHit).filter(relevant).order_by(
        desc(ProtectionHit.last_seen), desc(ProtectionHit.id)).limit(ITEMS).all()
    return {"count": total, "open": open_count, "items": [{**protection_rules.hit_dict(h), "_at": h.first_seen} for h in rows]}


def _device_window(start: datetime, end: datetime):
    return and_(EasDevice.last_seen >= start, EasDevice.first_seen <= end)


def _devices_of_ip(db: Session, ip: str, start: datetime, end: datetime) -> dict:
    window = _device_window(start, end)
    return _devices(db, _ip_value_match(db.query(EasDevice).filter(window), EasDevice.last_ip, ip), start, end)


def _devices(db: Session, condition, start: datetime, end: datetime) -> dict:
    seen = and_(condition, _device_window(start, end))
    total = db.query(func.count(EasDevice.id)).filter(seen).scalar() or 0
    rows = db.query(EasDevice).filter(seen).order_by(desc(EasDevice.last_seen), desc(EasDevice.id)).limit(ITEMS).all()
    return {"count": total, "items": [{
        "id": d.id, "username": d.username, "device_id": d.device_id, "device_type": d.device_type,
        "last_ip": d.last_ip, "last_command": d.last_command,
        "first_seen": iso(d.first_seen), "last_seen": iso(d.last_seen), "_first": d.first_seen, "_last": d.last_seen,
    } for d in rows]}


def _passed(condition):
    return func.coalesce(func.sum(case((condition, DMARCRecord.count), else_=0)), 0)


def _report_overlaps(start: datetime, end: datetime):
    return and_(DMARCReport.end_date >= _epoch(start), DMARCReport.begin_date <= _epoch(end))


def _report_domain():
    return func.rtrim(func.lower(DMARCReport.domain), ".")


def _dmarc_of_ip(db: Session, ip: str, start: datetime, end: datetime) -> dict:
    in_range = db.query(DMARCRecord).join(DMARCReport, DMARCRecord.dmarc_report_id == DMARCReport.id).filter(
        _report_overlaps(start, end))
    where = and_(_ip_value_match(in_range, DMARCRecord.source_ip, ip), _report_overlaps(start, end))
    joined = lambda q: q.select_from(DMARCRecord).join(DMARCReport, DMARCRecord.dmarc_report_id == DMARCReport.id).filter(where)  # noqa: E731
    domain = _report_domain()
    messages, reports, domains = joined(db.query(
        func.coalesce(func.sum(DMARCRecord.count), 0), func.count(distinct(DMARCReport.id)),
        func.count(distinct(domain)))).one()
    dmarc_pass = or_(DMARCRecord.spf_result == "pass", DMARCRecord.dkim_result == "pass")
    by_domain = joined(db.query(
        domain, func.coalesce(func.sum(DMARCRecord.count), 0), _passed(dmarc_pass),
        _passed(DMARCRecord.spf_result == "pass"), _passed(DMARCRecord.dkim_result == "pass"),
        func.count(distinct(DMARCReport.id)), func.max(DMARCReport.end_date), func.max(DMARCReport.created_at),
    )).group_by(domain).order_by(desc(func.sum(DMARCRecord.count)), domain).limit(DMARC_DOMAINS).all()
    records = joined(db.query(DMARCRecord, DMARCReport)).order_by(
        desc(DMARCReport.end_date), desc(DMARCRecord.id)).limit(ITEMS).all()
    return {
        "messages": int(messages), "reports": reports, "domains": domains,
        "by_domain": [{
            "domain": d, "messages": int(total), "dmarc_pass": int(passed), "spf_pass": int(spf), "dkim_pass": int(dkim),
            "reports": count, "last_period_end": _from_epoch(last_end), "last_received": iso(last_received),
        } for d, total, passed, spf, dkim, count, last_end, last_received in by_domain],
        "records": [{
            "domain": report.domain.lower().rstrip("."), "org_name": report.org_name, "report_id": report.report_id,
            "period_begin": _from_epoch(report.begin_date), "period_end": _from_epoch(report.end_date),
            "received": iso(report.created_at), "count": record.count, "disposition": record.disposition,
            "spf_result": record.spf_result, "dkim_result": record.dkim_result, "header_from": record.header_from,
        } for record, report in records],
    }


def _dmarc_of_domain(db: Session, domain: str, start: datetime, end: datetime) -> dict:
    where = and_(_report_domain().in_(entity_values.domain_forms(domain)), _report_overlaps(start, end))
    reports, last_end, last_received = db.query(
        func.count(DMARCReport.id), func.max(DMARCReport.end_date), func.max(DMARCReport.created_at)).filter(where).one()
    dmarc_pass = or_(DMARCRecord.spf_result == "pass", DMARCRecord.dkim_result == "pass")
    messages, passed, spf, dkim, sources = db.query(
        func.coalesce(func.sum(DMARCRecord.count), 0), _passed(dmarc_pass), _passed(DMARCRecord.spf_result == "pass"),
        _passed(DMARCRecord.dkim_result == "pass"), func.count(distinct(DMARCRecord.source_ip)),
    ).select_from(DMARCRecord).join(DMARCReport, DMARCRecord.dmarc_report_id == DMARCReport.id).filter(where).one()
    return {
        "reports": reports, "messages": int(messages), "dmarc_pass": int(passed), "spf_pass": int(spf),
        "dkim_pass": int(dkim), "sources": sources, "last_period_end": _from_epoch(last_end),
        "last_received": iso(last_received),
    }


def _rbl(db: Session, ip: str) -> dict:
    from .blacklist_service import apply_ignored_lists
    from .ignore_lists import IGNORED_BLOCKLISTS_KEY, load_ignored
    hosts = db.query(MonitoredHost).filter(MonitoredHost.active == True)  # noqa: E712
    monitored = hosts.filter(_ip_value_match(hosts, MonitoredHost.hostname, ip)).first() is not None
    checks = db.query(BlacklistCheck)
    check = checks.filter(_ip_value_match(checks, BlacklistCheck.server_ip, ip)).order_by(
        desc(BlacklistCheck.checked_at), desc(BlacklistCheck.id)).first()
    if check is None:
        return {"checked": False, "monitored": monitored}
    shown = apply_ignored_lists({"status": check.status, "listed_count": check.listed_count,
                                 "total_blacklists": check.total_blacklists, "results": check.results or []},
                                load_ignored(db, IGNORED_BLOCKLISTS_KEY))
    listed = [r.get("name") or r.get("zone") for r in shown["results"]
              if isinstance(r, dict) and r.get("listed") and not r.get("ignored")]
    return {
        "checked": True, "monitored": monitored, "checked_at": iso(check.checked_at), "status": shown["status"],
        "listed_count": shown["listed_count"], "total_blacklists": shown["total_blacklists"],
        "listed": [name for name in listed if name],
    }


def _geo(ip: str) -> dict:
    if not geoip_service.is_geoip_available():
        raise Off("GeoIP is not set up, so the place of an address is not known.")
    found = geoip_service.lookup_ip(ip)
    return {key: found.get(key) for key in ("country_code", "country_name", "city", "asn", "asn_org")}


def _suppression_dict(row: Optional[SpamSuppression]) -> Optional[dict]:
    if row is None:
        return None
    return {"email": row.email, "type": row.type, "reason": row.reason, "source": row.source,
            "active": bool(row.active), "created_at": iso(row.created_at), "expires_at": iso(row.expires_at),
            "bounce_count": row.bounce_count}


def _js_escape(text: str) -> str:
    return re.sub(r"[.*+?^${}()|\[\]\\]", lambda m: "\\" + m.group(0), text)


def _escapes(text: str) -> List[str]:
    return list(dict.fromkeys((_js_escape(text), re.escape(text))))


def _address_entry_values(address: str) -> List[str]:
    values = []
    for form in entity_values.address_forms(address):
        values.append(form)
        values += [f"/^{escaped}$/{flags}" for escaped in _escapes(form) for flags in ("i", "")]
    return list(dict.fromkeys(v.lower() for v in values))


def _domain_entry_values(domain: str) -> List[str]:
    values = []
    for form in entity_values.domain_forms(domain):
        for escaped in _escapes(form):
            for flags in ("i", ""):
                values += [f"/^.+@{escaped}$/{flags}", f"/^.+@(.+\\.)?{escaped}$/{flags}", f"/.+@{escaped}/{flags}"]
    return list(dict.fromkeys(v.lower() for v in values))


def _first_entry(db: Session, condition) -> Optional[dict]:
    row = db.query(SpamSuppression).filter(condition).order_by(
        desc(SpamSuppression.active), SpamSuppression.id).first()
    return _suppression_dict(row)


def _address_entry(db: Session, address: str) -> Optional[dict]:
    return _first_entry(db, and_(func.lower(SpamSuppression.email).in_(_address_entry_values(address)),
                                 or_(SpamSuppression.type.is_(None), SpamSuppression.type != "domain")))


def _domain_entry(db: Session, domain: str) -> Optional[dict]:
    email = func.lower(SpamSuppression.email)
    return _first_entry(db, or_(email.in_(_domain_entry_values(domain)),
                                and_(email.in_(entity_values.domain_forms(domain)), SpamSuppression.type == "domain")))


def _suppressions(db: Session, read: Callable[[], dict]) -> dict:
    from ..routers.suppressions import import_pending
    from .bounce_policy import rspamd_sync_on
    if not rspamd_sync_on():
        raise TurnedOff("Sync with Rspamd is off, so the app keeps no suppression list.")
    if import_pending(db):
        raise Off("The suppression list is being loaded back from Rspamd. Try again in a few minutes.")
    return read()


def _mailbox(db: Session, address: str) -> dict:
    forms = entity_values.address_forms(address)
    box = db.query(MailboxStatistics).filter(func.lower(MailboxStatistics.username).in_(forms)).first()
    alias = db.query(AliasStatistics).filter(func.lower(AliasStatistics.alias_address).in_(forms)).first()
    target = None
    if alias is not None and alias.primary_mailbox:
        target = db.query(MailboxStatistics.username).filter(
            func.lower(MailboxStatistics.username) == alias.primary_mailbox.strip().lower()).limit(1).scalar()
    return {
        "local": box is not None,
        "mailbox": {"username": box.username, "name": box.name, "domain": box.domain, "active": box.active,
                    "login_disabled": bool(box.login_disabled), "shared": mailbox_shared(box.attributes)} if box else None,
        "alias": {"address": alias.alias_address, "goto": alias.goto, "primary_mailbox": alias.primary_mailbox,
                  "local_mailbox": target, "active": alias.active} if alias else None,
    }


def _mailboxes_of_domain(db: Session, domain: str) -> dict:
    forms = entity_values.domain_forms(domain)
    total, active = db.query(func.count(MailboxStatistics.id),
                             func.count(MailboxStatistics.id).filter(MailboxStatistics.active == True)  # noqa: E712
                             ).filter(func.lower(MailboxStatistics.domain).in_(forms)).one()
    aliases = db.query(func.count(AliasStatistics.id)).filter(func.lower(AliasStatistics.domain).in_(forms)).scalar() or 0
    return {"mailboxes": total, "active_mailboxes": active, "aliases": aliases}


_DNS_CHECKS = ("spf", "dkim", "dmarc", "dnssec", "tlsa", "mta_sts", "tls_rpt")


def _dns(db: Session, domain: str) -> dict:
    row = db.query(DomainDNSCheck).filter(func.lower(DomainDNSCheck.domain_name).in_(entity_values.domain_forms(domain))).first()
    if row is None:
        return {"checked": False}
    checks = {}
    for name in _DNS_CHECKS:
        value = getattr(row, f"{name}_check", None)
        checks[name] = value.get("status") if isinstance(value, dict) and isinstance(value.get("status"), str) else None
    return {"checked": True, "checked_at": iso(row.checked_at), "checks": checks}


def _hosted(domain: str) -> Optional[bool]:
    if not cached_domains_known():
        return None
    return any(is_hosted_domain(form) for form in entity_values.domain_forms(domain))


_KIND_ORDER = {"message": 0, "security": 1, "ban": 2, "unban": 3, "protection": 4,
               "device_first_seen": 5, "device_last_seen": 6}
_LABELS = {"message": "Message", "security": "Security event", "ban": "Banned", "unban": "Unbanned",
           "protection": "Protection catch", "device_first_seen": "Device first seen",
           "device_last_seen": "Device last seen"}

def _timeline(sources: Dict[str, dict], start: datetime, end: datetime, device_first_seen: bool) -> dict:
    items, truncated, left_out = [], False, []
    for name in ("messages", "security", "protection", "devices"):
        source = sources.get(name)
        if source is None:
            continue
        if source["state"] != "ok":
            left_out.append(name)
            continue
        count = source.get("count", source.get("events", 0))
        if count > len(source["items"]):
            truncated = True
        for row in source["items"]:
            if name == "messages":
                items.append({"_at": row["_at"], "time": row["first_seen"], "kind": "message", "correlation_key": row["correlation_key"],
                              "sender": row["sender"], "recipient": row["recipient"], "subject": row["subject"],
                              "direction": row["direction"], "status": row["final_status"]})
            elif name == "security":
                kind = ("security" if row["rule_id"] is not None else "ban" if row["action"] in _BAN_ACTIONS
                        else "unban" if row["action"] == "unban" else None)
                if kind:
                    items.append({"_at": row["_at"], "time": row["time"], "kind": kind, "ip": row["ip"], "username": row["username"],
                                  "service": row["service"]})
            elif name == "protection":
                items.append({"_at": row["_at"], "time": row["first_seen"], "kind": "protection", "hit_id": row["id"], "ip": row["ip"],
                              "rule": row["rule"], "status": row["status"]})
            else:
                for kind, at, raw in (("device_first_seen", row["first_seen"], row["_first"]),
                                     ("device_last_seen", row["last_seen"], row["_last"])):
                    if kind == "device_first_seen" and not device_first_seen:
                        continue
                    items.append({"_at": raw, "time": at, "kind": kind, "username": row["username"],
                                  "device_id": row["device_id"], "device_type": row["device_type"], "ip": row["last_ip"]})
    items = [i for i in items if i["_at"] is not None and start <= i["_at"] <= end]
    items.sort(key=lambda i: (i["_at"], -_KIND_ORDER[i["kind"]]), reverse=True)
    if len(items) > TIMELINE:
        items, truncated = items[:TIMELINE], True
    for item in items:
        del item["_at"]
        item["label"] = _LABELS[item["kind"]]
    return {"items": items, "truncated": truncated, "left_out": left_out}


def _without_private_keys(sources: Dict[str, dict]) -> Dict[str, dict]:
    for source in sources.values():
        for row in source.get("items") or []:
            for key in [k for k in row if k.startswith("_")]:
                del row[key]
    return sources


def _range_dict(start: datetime, end: datetime) -> dict:
    return {"start": iso(start), "end": iso(end)}


def ip_summary(db: Session, ip: str, start: datetime, end: datetime,
               read_fail2ban: Callable[[], Optional[dict]]) -> dict:
    sources = {
        "messages": _run(db, None, "the messages", lambda: _messages_of_ip(db, ip, start, end)),
        "security": _run(db, "netfilter", "the security events",
                         lambda: _security(db, _ip_spellings_match(NetfilterLog.ip, ip), start, end, with_ips=False)),
        "lists": _run(db, "netfilter", "the Fail2ban lists", lambda: _lists(ip, read_fail2ban)),
        "protection": _run(db, "netfilter", "the protection catches", lambda: _protection_of_ip(db, ip, start, end),
                           snapshot=True),
        "devices": _run(db, "devices", "the devices", lambda: _devices_of_ip(db, ip, start, end), snapshot=True),
        "dmarc": _run(db, "dmarc", "the DMARC reports", lambda: _dmarc_of_ip(db, ip, start, end), snapshot=True),
        "rbl": _run(db, "blacklist", "the blocklist check", lambda: _rbl(db, ip), snapshot=True),
        "geo": _run(db, None, "the place of the address", lambda: _geo(ip)),
    }
    timeline = _timeline(sources, start, end, device_first_seen=False)
    return {"kind": "ip", "value": ip, "display": ip, "range": _range_dict(start, end),
            "sources": _without_private_keys(sources), "timeline": timeline}


def address_summary(db: Session, address: str, display: str, start: datetime, end: datetime) -> dict:
    forms = entity_values.address_forms(address)
    domain = entity_values.address_domain(address)
    excluded = any(excluded_addresses.is_listed(form) for form in forms)
    if excluded:
        messages = {"state": "disabled",
                    "reason": "This address is excluded, so Messages does not keep or show its mail."}
    else:
        messages = _run(db, None, "the messages", lambda: _messages_of(db, *_address_columns(address), start, end))
    lowered = lambda column: func.lower(column).in_(forms)  # noqa: E731
    sources = {
        "messages": messages,
        "security": _run(db, "netfilter", "the security events",
                         lambda: _security(db, _netfilter_username(lowered(NetfilterLog.username)), start, end, with_ips=True)),
        "protection": _run(db, "netfilter", "the protection catches",
                           lambda: _protection(db, _usernames_match(lambda v: func.lower(v).in_(forms)), start, end)),
        "devices": _run(db, "devices", "the devices", lambda: _devices(db, lowered(EasDevice.username), start, end)),
        "suppression": _run(db, "suppressions", "the suppression list", lambda: _suppressions(db, lambda: {
            "entry": _address_entry(db, address), "domain_entry": _domain_entry(db, domain)})),
        "mailbox": _run(db, "mailbox-stats", "the mailboxes", lambda: _mailbox(db, address)),
    }
    timeline = _timeline(sources, start, end, device_first_seen=True)
    return {"kind": "address", "value": address, "display": display, "domain": domain,
            "hosted_domain": _hosted(domain), "excluded": excluded, "range": _range_dict(start, end),
            "sources": _without_private_keys(sources), "timeline": timeline}


def domain_summary(db: Session, domain: str, start: datetime, end: datetime) -> dict:
    forms = entity_values.domain_forms(domain)
    sources = {
        "messages": _run(db, None, "the messages", lambda: _messages_of(
            db, _domain_match(MessageCorrelation.sender, domain), _domain_match(MessageCorrelation.recipient, domain),
            start, end)),
        "security": _run(db, "netfilter", "the security events", lambda: _security(
            db, _netfilter_username(_domain_match(NetfilterLog.username, domain)), start, end, with_ips=True)),
        "protection": _run(db, "netfilter", "the protection catches", lambda: _protection(
            db, _usernames_match(lambda v: or_(*[_like_suffix(v, f) for f in forms])), start, end)),
        "devices": _run(db, "devices", "the devices",
                        lambda: _devices(db, _domain_match(EasDevice.username, domain), start, end)),
        "dmarc": _run(db, "dmarc", "the DMARC reports", lambda: _dmarc_of_domain(db, domain, start, end)),
        "suppression": _run(db, "suppressions", "the suppression list",
                            lambda: _suppressions(db, lambda: {"entry": _domain_entry(db, domain)})),
        "mailboxes": _run(db, "mailbox-stats", "the mailboxes", lambda: _mailboxes_of_domain(db, domain)),
        "dns": _run(db, "domains", "the DNS checks", lambda: _dns(db, domain)),
    }
    return {"kind": "domain", "value": domain, "display": forms[-1], "hosted": _hosted(domain),
            "range": _range_dict(start, end), "sources": _without_private_keys(sources)}
