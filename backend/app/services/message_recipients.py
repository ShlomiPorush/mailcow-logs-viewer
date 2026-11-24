import re
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy import and_, select

from ..correlation import _PF_ADDR, occurrence_for, split_queue_occurrences
from ..models import PostfixLog
from . import excluded_addresses, written_recipients

_ORIG_TO_RE = re.compile(r'^[0-9A-F]+: to=<' + _PF_ADDR + r'>, orig_to=<(' + _PF_ADDR + r')>, ')


def address_key(address) -> str:
    return str(address or '').strip().lower()


def written_address(recipient: Optional[str], message: Optional[str]) -> str:
    match = _ORIG_TO_RE.match(message or '')
    return (match.group(1) if match else None) or recipient or ''


def listed_recipients(rspamd_log, postfix_recipients: Iterable[Optional[str]]) -> List[str]:
    recipients = excluded_addresses.visible_recipients(rspamd_log.recipients_smtp if rspamd_log else None)
    if recipients:
        return recipients
    delivered = []
    for recipient in postfix_recipients:
        if recipient and recipient not in delivered:
            delivered.append(recipient)
    return delivered


def resolve_recipients(listed: List[str], deliveries: Iterable[Tuple[Optional[str], str]],
                       primary: Optional[str]) -> List[str]:
    deliveries = [(to, written) for to, written in deliveries if to]
    owners: Dict[str, set] = {}
    for to, written in deliveries:
        owners.setdefault(address_key(to), set()).add(address_key(written))
    written_keys = set().union(*owners.values()) if owners else set()
    expanded = {to for to, written in owners.items() if to not in written}
    listed_keys = [address_key(address) for address in listed or []]
    from_postfix = bool(listed_keys) and set(listed_keys) == set(owners)
    found: Dict[str, str] = {}

    def add(address):
        key = address_key(address)
        if key and key not in found:
            found[key] = str(address).strip()
    for address in listed or []:
        key = address_key(address)
        if not from_postfix or key not in expanded or key in written_keys:
            add(address)
    for _, written in deliveries:
        add(written)
    if not found:
        add(primary)
    return list(found.values())


def count_recipients(listed: List[str], deliveries: Iterable[Tuple[Optional[str], str]], primary: Optional[str]) -> int:
    return len(resolve_recipients(listed, deliveries, primary))


def union_recipients(legs: Iterable[List[str]]) -> List[str]:
    found: Dict[str, str] = {}
    for addresses in legs:
        for address in addresses:
            key = address_key(address)
            if key and key not in found:
                found[key] = str(address).strip()
    return list(found.values())


def legs_recipients(db, legs, rspamd_logs: Optional[Dict[int, object]] = None) -> Dict[str, List[str]]:
    from ..models import RspamdLog
    rspamd_logs = dict(rspamd_logs or {})
    missing = {leg.rspamd_log_id for leg in legs if leg.rspamd_log_id and leg.rspamd_log_id not in rspamd_logs}
    if missing:
        rspamd_logs.update({row.id: row for row in db.query(RspamdLog).filter(RspamdLog.id.in_(list(missing))).all()})
    deliveries = page_deliveries(db, legs)
    found = {}
    for leg in legs:
        lines = deliveries[leg.correlation_key]
        listed = written_recipients.shown_list(
            listed_recipients(rspamd_logs.get(leg.rspamd_log_id), (to for to, _ in lines)), leg.written_recipients)
        found[leg.correlation_key] = resolve_recipients(listed, lines, leg.recipient)
    return found


def page_deliveries(db, legs) -> Dict[str, List[Tuple[str, str]]]:
    found = {leg.correlation_key: [] for leg in legs}
    by_queue, by_line = {}, {}
    for leg in legs:
        if leg.queue_id:
            by_queue.setdefault(leg.queue_id, []).append(leg)
        elif isinstance(leg.postfix_log_ids, list):
            for line_id in {i for i in leg.postfix_log_ids if isinstance(i, int)}:
                by_line.setdefault(line_id, []).append(leg.correlation_key)

    has_recipient = and_(PostfixLog.recipient.isnot(None), PostfixLog.recipient != '')
    if by_queue:
        lines = {}
        for line in db.query(PostfixLog.id, PostfixLog.time, PostfixLog.program, PostfixLog.message,
                             PostfixLog.queue_id, PostfixLog.message_id, PostfixLog.recipient).filter(
                PostfixLog.queue_id.in_(list(by_queue)),
                excluded_addresses.postfix_line_visible_among(list(by_queue))).all():
            lines.setdefault(line.queue_id, []).append(line)
        for queue_id, queue_legs in by_queue.items():
            occurrences = split_queue_occurrences(lines.get(queue_id, []))
            for leg in queue_legs:
                occurrence = occurrence_for(occurrences, leg.message_id, near=leg.first_seen, strict=False)
                for line in (occurrence.shown_lines() if occurrence else []):
                    if line.recipient:
                        found[leg.correlation_key].append(
                            (line.recipient, written_address(line.recipient, line.message)))
    if by_line:
        line_ids = list(by_line)
        rows = db.query(PostfixLog.id, PostfixLog.recipient, PostfixLog.message).filter(
            PostfixLog.id.in_(line_ids), has_recipient,
            excluded_addresses.postfix_line_visible_among(
                select(PostfixLog.queue_id).where(PostfixLog.id.in_(line_ids)).scalar_subquery())
        ).all()
        for line_id, recipient, message in rows:
            for key in by_line[line_id]:
                found[key].append((recipient, written_address(recipient, message)))
    return found
