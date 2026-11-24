import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from sqlalchemy import and_, exists, func, not_, or_, select, tuple_
from sqlalchemy.orm import Session, aliased

from ..models import NetfilterLog, PostfixLog
from . import excluded_addresses
from .message_recipients import listed_recipients, resolve_recipients, union_recipients, written_address

logger = logging.getLogger(__name__)

INSTANCE_SPAN = timedelta(days=6)
CLIENT_LEAD = timedelta(minutes=2)

KEY_PREFIX = "noid-"
_KEY_RE = re.compile(r"^noid-([1-9][0-9]{0,17})$")

_ANCHOR_RE = r"^[0-9A-F]+: message-id="
_CLIENT_LINE_RE = r"^[0-9A-F]+: client="
_CLIENT_RE = re.compile(
    r"^[0-9A-F]+: client=([^\s\[\],]*)\[(?:IPv6:)?([0-9a-fA-F:.]+)\](?::\d+)?"
    r"(?:, sasl_method=[^\s,]+, sasl_username=([^\s,]+))?")

TERMINAL = ("delivered", "bounced", "rejected", "expired", "spam")
NETFILTER_WINDOW = timedelta(hours=1)


def _is_anchor(model):
    return and_(model.program.like("%/cleanup"), model.queue_id.isnot(None), model.message_id.is_(None),
                model.message.op("~")(_ANCHOR_RE))


def _reused(anchor):
    other = aliased(PostfixLog)
    return exists().where(
        other.queue_id == anchor.queue_id, other.id != anchor.id,
        other.program.like("%/cleanup"), other.message.op("~")(_ANCHOR_RE),
        other.time >= anchor.time - INSTANCE_SPAN, other.time <= anchor.time + INSTANCE_SPAN).correlate_except(other)


def _in_window(line, anchor):
    return and_(line.queue_id == anchor.queue_id,
                line.time >= anchor.time - CLIENT_LEAD, line.time <= anchor.time + INSTANCE_SPAN)


def _in_instance(line, anchor, reused):
    own = and_(_in_window(line, anchor),
               or_(line.time >= anchor.time, line.message.op("~")(_CLIENT_LINE_RE)))
    return or_(line.id == anchor.id, and_(not_(reused), own))


def _visible(anchor):
    hidden = excluded_addresses.listed()
    if not hidden:
        return None
    line = aliased(PostfixLog)
    return not_(exists().where(_in_window(line, anchor), excluded_addresses.postfix_listed(line, hidden))
                .correlate_except(line))


def _search(anchor, reused, text: str):
    term = "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"

    def has(column):
        return column.ilike(term, escape="\\")
    line = aliased(PostfixLog)
    match = or_(has(line.sender), has(line.recipient),
                and_(line.message.op("~")(_CLIENT_LINE_RE), has(line.message)))
    return or_(has(anchor.queue_id), exists().where(_in_instance(line, anchor, reused), match).correlate_except(line))


def anchors_query(db: Session, *, start=None, end=None, search: Optional[str] = None):
    anchor = aliased(PostfixLog, name="anchor")
    reused = _reused(anchor)
    query = db.query(anchor, reused.label("reused")).filter(_is_anchor(anchor))
    if start:
        query = query.filter(anchor.time >= _naive(start))
    if end:
        query = query.filter(anchor.time <= _naive(end))
    visible = _visible(anchor)
    if visible is not None:
        query = query.filter(visible)
    if isinstance(search, str) and search.strip():
        query = query.filter(_search(anchor, reused, search.strip()))
    return query, anchor


def _naive(value: datetime) -> datetime:
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def count(db: Session, **filters) -> int:
    query, _ = anchors_query(db, **filters)
    return query.order_by(None).count()


def page(db: Session, *, limit: int, order: str = "desc", cursor=None, **filters):
    query, anchor = anchors_query(db, **filters)
    mark = tuple_(anchor.time, anchor.id)
    if cursor:
        query = query.filter(mark > tuple_(*cursor) if order == "asc" else mark < tuple_(*cursor))
    keys = (anchor.time.asc(), anchor.id.asc()) if order == "asc" else (anchor.time.desc(), anchor.id.desc())
    found = query.order_by(*keys).limit(limit + 1).all()
    return found[:limit], len(found) > limit


def instance_lines(db: Session, anchors) -> Dict[int, tuple]:
    result = {anchor.id: ([anchor], True) for anchor, reused in anchors if reused}
    open_ = [anchor for anchor, reused in anchors if not reused]
    if not open_:
        return result
    queues = {anchor.queue_id for anchor in open_}
    low = min(anchor.time for anchor in open_) - INSTANCE_SPAN
    high = max(anchor.time for anchor in open_) + INSTANCE_SPAN
    lines = db.query(PostfixLog).filter(PostfixLog.queue_id.in_(queues), PostfixLog.time >= low,
                                        PostfixLog.time <= high).all()
    client = re.compile(_CLIENT_LINE_RE)
    marker = re.compile(_ANCHOR_RE)
    for anchor in open_:
        same = [line for line in lines if line.id != anchor.id and line.queue_id == anchor.queue_id]
        if any((line.program or "").endswith("/cleanup") and marker.match(line.message or "")
               and abs(line.time - anchor.time) <= INSTANCE_SPAN for line in same):
            result[anchor.id] = ([anchor], True)
            continue
        own = [line for line in same
               if anchor.time - CLIENT_LEAD <= line.time <= anchor.time + INSTANCE_SPAN
               and (line.time >= anchor.time or client.match(line.message or ''))]
        result[anchor.id] = (sorted([anchor] + own, key=lambda line: (line.time, line.id)), False)
    return result


def final_status(lines) -> Optional[str]:
    statuses = {line.status for line in lines if line.status}
    for status, outcome in (("bounced", "bounced"), ("rejected", "rejected"), ("expired", "expired"),
                            ("sent", "delivered"), ("spam", "spam"), ("deferred", "deferred")):
        if status in statuses:
            return outcome
    return None


def client(lines) -> Optional[dict]:
    for line in lines:
        if (line.program or "").endswith("/smtpd"):
            match = _CLIENT_RE.match(line.message or "")
            if match:
                name, ip, user = match.groups()
                return {"ip": ip, "host": name or None, "user": user}
    return None


GEO_KEYS = ("country_code", "country_name", "city", "asn", "asn_org")


def located(who: Optional[dict]) -> Optional[dict]:
    if not who:
        return None
    from . import geoip_service
    try:
        geo = geoip_service.lookup_ip(who["ip"]) if who.get("ip") and geoip_service.is_geoip_available() else {}
    except Exception as error:
        logger.debug(f"GeoIP lookup failed for a message without a Message-ID: {error}")
        geo = {}
    return {**who, **{key: geo.get(key) for key in GEO_KEYS}}


def sender(lines) -> Optional[str]:
    for line in lines:
        if line.sender and (line.program or "").endswith("/qmgr"):
            return line.sender
    return next((line.sender for line in lines if line.sender), None)


def recipients(lines) -> List[str]:
    delivered = [line for line in lines if line.recipient]
    listed = listed_recipients(None, (line.recipient for line in delivered))
    own = resolve_recipients(listed, [(line.recipient, written_address(line.recipient, line.message))
                                      for line in delivered],
                             delivered[0].recipient if delivered else None)
    return union_recipients([own])


def key_of(anchor) -> str:
    return f"{KEY_PREFIX}{anchor.id}"


def anchor_id(key: str) -> Optional[int]:
    match = _KEY_RE.match(key or "")
    return int(match.group(1)) if match else None


def is_key(key: str) -> bool:
    return isinstance(key, str) and key.startswith(KEY_PREFIX)


def find(db: Session, key: str):
    wanted = anchor_id(key)
    if wanted is None:
        return None
    query, anchor = anchors_query(db)
    return query.filter(anchor.id == wanted).first()


def summary(anchor, reused: bool, lines, fmt) -> dict:
    if reused:
        lines = [anchor]
    rcpts = recipients(lines)
    status = final_status(lines)
    who = client(lines)
    return {
        "correlation_key": key_of(anchor),
        "message_id": None,
        "queue_id": anchor.queue_id,
        "sender": sender(lines),
        "recipient": rcpts[0] if rcpts else None,
        "recipient_count": len(rcpts),
        "subject": None,
        "direction": None,
        "final_status": status,
        "is_complete": None if reused else status in TERMINAL,
        "first_seen": fmt(min(line.time for line in lines)),
        "last_seen": fmt(max(line.time for line in lines)),
        "dovecot_status": None,
        "dovecot_mailbox": None,
        "deliveries": 1,
        "spam_score": None,
        "is_spam": None,
        "user": who["user"] if who else None,
        "ip": who["ip"] if who else None,
        "queue_id_reused": bool(reused),
    }


def netfilter_events(db: Session, anchor, who) -> list:
    if not who or not who.get("ip"):
        return []
    return db.query(NetfilterLog).filter(
        NetfilterLog.ip == who["ip"],
        NetfilterLog.time >= anchor.time - NETFILTER_WINDOW,
        NetfilterLog.time <= anchor.time + NETFILTER_WINDOW,
    ).order_by(NetfilterLog.time.desc()).limit(100).all()
