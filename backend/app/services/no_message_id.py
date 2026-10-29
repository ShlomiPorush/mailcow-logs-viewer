"""Messages without a usable Message-ID, shown from their Postfix lines.

The Messages list joins a message's Postfix lines and its Rspamd scan by the
Message-ID. A message whose header holds no usable one (an empty
"Message-ID:" from a scanner, or none at all when Postfix is not told to add
it) is never joined, so it has no row there. Its Postfix lines are stored all
the same; this module finds such messages and describes them from those lines
alone: no subject, no spam score, no direction.

Which lines are one message. Postfix names a queued message by a short queue
id, made of the queue file's inode and the microsecond it was created, so an
id comes back once the file is gone, sometimes within minutes. Lines are not
told apart by their order: mailcow returns the log newest first and lines of
one second are stored in no reliable order, and the "removed" line is missing
in some cases. So a message (an "instance") starts at its cleanup line, the
anchor, whose message-id field the parser found no ID in:
- When no other cleanup message-id line of that queue id lies within
  INSTANCE_SPAN on either side, the instance is every line of the queue id
  from the anchor's time to INSTANCE_SPAN after it, and the smtpd "client="
  line logged up to CLIENT_LEAD before it (a message that ended earlier logs
  no such line once its file is gone).
- Otherwise (the id was used again close by) it is the anchor line alone: the
  time and the queue id, and nothing that could be another message's.

A message is hidden when any stored line within the anchor's window names an
excluded address (excluded_addresses), as the Messages list hides one.
"""
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from sqlalchemy import and_, exists, func, not_, or_, select, tuple_
from sqlalchemy.orm import Session, aliased

from ..models import NetfilterLog, PostfixLog
from . import excluded_addresses
from .message_recipients import listed_recipients, resolve_recipients, union_recipients, written_address

# Postfix keeps a message at most maximal_queue_lifetime, 5 days by default
INSTANCE_SPAN = timedelta(days=6)
# The smtpd "client=" line comes a moment before the cleanup line
CLIENT_LEAD = timedelta(minutes=2)

KEY_PREFIX = "noid-"
_KEY_RE = re.compile(r"^noid-([1-9][0-9]{0,17})$")

# The cleanup line's message-id field, at the fixed start of the line, as the
# parser reads it (correlation._PF_MESSAGE_ID_RE). The parser leaves message_id
# empty on such a line when the field holds no <id>
_ANCHOR_RE = r"^[0-9A-F]+: message-id="
_CLIENT_LINE_RE = r"^[0-9A-F]+: client="
# The client of an smtpd line, for display: the name, the address and, after a
# login, the user. Not protection_rules' login rule, which needs the login
_CLIENT_RE = re.compile(
    r"^[0-9A-F]+: client=([^\s\[\],]*)\[(?:IPv6:)?([0-9a-fA-F:.]+)\](?::\d+)?"
    r"(?:, sasl_method=[^\s,]+, sasl_username=([^\s,]+))?")

TERMINAL = ("delivered", "bounced", "rejected", "expired", "spam")
NETFILTER_WINDOW = timedelta(hours=1)


def _is_anchor(model):
    return and_(model.program.like("%/cleanup"), model.queue_id.isnot(None), model.message_id.is_(None),
                model.message.op("~")(_ANCHOR_RE))


def _reused(anchor):
    """The anchor's queue id has another cleanup message-id line close by."""
    other = aliased(PostfixLog)
    return exists().where(
        other.queue_id == anchor.queue_id, other.id != anchor.id,
        other.program.like("%/cleanup"), other.message.op("~")(_ANCHOR_RE),
        other.time >= anchor.time - INSTANCE_SPAN, other.time <= anchor.time + INSTANCE_SPAN).correlate_except(other)


def _in_window(line, anchor):
    """Lines of the anchor's queue id that could be its message's at all."""
    return and_(line.queue_id == anchor.queue_id,
                line.time >= anchor.time - CLIENT_LEAD, line.time <= anchor.time + INSTANCE_SPAN)


def _in_instance(line, anchor, reused):
    """The lines that are the anchor's message (see the module docstring)."""
    own = and_(_in_window(line, anchor),
               or_(line.time >= anchor.time, line.message.op("~")(_CLIENT_LINE_RE)))
    return or_(line.id == anchor.id, and_(not_(reused), own))


def _visible(anchor):
    """No stored line within the anchor's window names an excluded address."""
    hidden = excluded_addresses.listed()
    if not hidden:
        return None
    line = aliased(PostfixLog)
    return not_(exists().where(_in_window(line, anchor), excluded_addresses.postfix_listed(line, hidden))
                .correlate_except(line))


def _search(anchor, reused, text: str):
    term = f"%{text}%"
    line = aliased(PostfixLog)
    # The address, the queue id, and the client's name, address and user (the client line's text)
    match = or_(line.sender.ilike(term), line.recipient.ilike(term),
                and_(line.message.op("~")(_CLIENT_LINE_RE), line.message.ilike(term)))
    return or_(anchor.queue_id.ilike(term), exists().where(_in_instance(line, anchor, reused), match).correlate_except(line))


def anchors_query(db: Session, *, start=None, end=None, search: Optional[str] = None):
    """The anchors of the messages without a Message-ID matching the filters,
    each with whether its queue id was used again close by."""
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
    """Postfix times are stored as naive UTC."""
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def count(db: Session, **filters) -> int:
    query, _ = anchors_query(db, **filters)
    return query.order_by(None).count()


def page(db: Session, *, limit: int, order: str = "desc", cursor=None, **filters):
    """A page of anchors after the cursor (time, id), and whether more follow."""
    query, anchor = anchors_query(db, **filters)
    mark = tuple_(anchor.time, anchor.id)
    if cursor:
        query = query.filter(mark > tuple_(*cursor) if order == "asc" else mark < tuple_(*cursor))
    keys = (anchor.time.asc(), anchor.id.asc()) if order == "asc" else (anchor.time.desc(), anchor.id.desc())
    found = query.order_by(*keys).limit(limit + 1).all()
    return found[:limit], len(found) > limit


def instance_lines(db: Session, anchors) -> Dict[int, List[PostfixLog]]:
    """The lines of each anchor's message, by anchor id, read in one query."""
    result = {anchor.id: [anchor] for anchor, _ in anchors}
    open_ = [(anchor, reused) for anchor, reused in anchors if not reused]
    if not open_:
        return result
    queues = {anchor.queue_id for anchor, _ in open_}
    low = min(anchor.time for anchor, _ in open_) - CLIENT_LEAD
    high = max(anchor.time for anchor, _ in open_) + INSTANCE_SPAN
    lines = db.query(PostfixLog).filter(PostfixLog.queue_id.in_(queues), PostfixLog.time >= low,
                                        PostfixLog.time <= high).all()
    client = re.compile(_CLIENT_LINE_RE)
    for anchor, _ in open_:
        own = [line for line in lines
               if line.id != anchor.id and line.queue_id == anchor.queue_id
               and anchor.time - CLIENT_LEAD <= line.time <= anchor.time + INSTANCE_SPAN
               and (line.time >= anchor.time or client.match(line.message or ''))]
        result[anchor.id] = sorted([anchor] + own, key=lambda line: (line.time, line.id))
    return result


def final_status(lines) -> Optional[str]:
    """The message's outcome from its own lines: a bounce or reject wins, then
    expiry, then a delivery (spam when it went to the spam pipe), then deferral."""
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


def sender(lines) -> Optional[str]:
    """The envelope sender, from the qmgr "from=" line."""
    for line in lines:
        if line.sender and (line.program or "").endswith("/qmgr"):
            return line.sender
    return next((line.sender for line in lines if line.sender), None)


def recipients(lines) -> List[str]:
    """The recipients as the message details count them (message_recipients)."""
    delivered = [line for line in lines if line.recipient]
    listed = listed_recipients(None, (line.recipient for line in delivered))
    own = resolve_recipients(listed, [(line.recipient, written_address(line.recipient, line.message))
                                      for line in delivered],
                             delivered[0].recipient if delivered else None)
    return union_recipients([own])


def key_of(anchor) -> str:
    return f"{KEY_PREFIX}{anchor.id}"


def anchor_id(key: str) -> Optional[int]:
    """The anchor id of a key made by key_of, else None."""
    match = _KEY_RE.match(key or "")
    return int(match.group(1)) if match else None


def is_key(key: str) -> bool:
    return isinstance(key, str) and key.startswith(KEY_PREFIX)


def find(db: Session, key: str):
    """The (anchor, reused) of a key, when it still stands for a message
    without a Message-ID (not excluded), else None."""
    wanted = anchor_id(key)
    if wanted is None:
        return None
    query, anchor = anchors_query(db)
    return query.filter(anchor.id == wanted).first()


def summary(anchor, reused: bool, lines, fmt) -> dict:
    """A Messages row for the message (MessageRow, plus queue_id_reused)."""
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
        # A reused queue id leaves no outcome to tell (queue_id_reused says why)
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
    """Fail2ban events of the client within an hour of the message."""
    if not who or not who.get("ip"):
        return []
    return db.query(NetfilterLog).filter(
        NetfilterLog.ip == who["ip"],
        NetfilterLog.time >= anchor.time - NETFILTER_WINDOW,
        NetfilterLog.time <= anchor.time + NETFILTER_WINDOW,
    ).order_by(NetfilterLog.time.desc()).limit(100).all()
