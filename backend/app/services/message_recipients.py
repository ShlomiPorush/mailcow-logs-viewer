"""How many recipients a message has, as the message details count them.

The details dialog counts its recipients in the browser (messageRecipients()
in frontend/message-details.js); the Messages list shows the same number
beside its first recipient. count_recipients() is that count in Python, rule
for rule, so the two cannot disagree. tests/fixtures/recipient_count_cases.json
runs the same cases through both (test_recipient_count_parity.py and
.github/tests/recipient-count-parity.test.cjs): change both together.

The rules:
- An address is one recipient whatever its case or surrounding blanks.
- The recipients the API lists (Rspamd's, else the addresses Postfix delivered
  to) count, and so does every address only Postfix logged.
- A Postfix line counts for the address the sender wrote: orig_to when Postfix
  expanded an alias or a forward, else the address it delivered to. Two aliases
  that reach one mailbox are two recipients; one alias that reaches two
  mailboxes is one.
- A mailbox only an alias reached is not a recipient of its own. Only a list
  taken from Postfix can name one; what Rspamd named is always kept.
- With nothing else, the delivery's own recipient counts.
- A message that passed through the server more than once (a forward, a copy
  sent on) is one email: its recipients are those of all its delivery legs
  (every visible correlation of its Message-ID), each address once.
"""
import re
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy import and_, select

from ..correlation import _PF_ADDR, occurrence_for, split_queue_occurrences
from ..models import PostfixLog
from . import excluded_addresses, written_recipients

# The written address of a delivery line, read only from the fixed start of
# the line (an address or a reply cannot supply it), as correlation.py parses
# it and as mdLineAddress() in message-details.js reads it
_ORIG_TO_RE = re.compile(r'^[0-9A-F]+: to=<' + _PF_ADDR + r'>, orig_to=<(' + _PF_ADDR + r')>, ')


def address_key(address) -> str:
    return str(address or '').strip().lower()


def written_address(recipient: Optional[str], message: Optional[str]) -> str:
    """The address the sender wrote for one Postfix delivery line."""
    match = _ORIG_TO_RE.match(message or '')
    return (match.group(1) if match else None) or recipient or ''


def listed_recipients(rspamd_log, postfix_recipients: Iterable[Optional[str]]) -> List[str]:
    """The `recipients` of the message details: Rspamd's, without excluded
    addresses, else the distinct addresses Postfix delivered to, in order."""
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
    """The recipients of one delivery leg as the dialog lists them
    (messageRecipients()): one address per recipient, in the dialog's order.

    listed: the details' `recipients`. deliveries: (delivered to, written
    address) for each visible Postfix line. primary: the delivery's recipient."""
    deliveries = [(to, written) for to, written in deliveries if to]
    owners: Dict[str, set] = {}
    for to, written in deliveries:
        owners.setdefault(address_key(to), set()).add(address_key(written))
    written_keys = set().union(*owners.values()) if owners else set()
    expanded = {to for to, written in owners.items() if to not in written}
    listed_keys = [address_key(address) for address in listed or []]
    # Whether the list is the one taken from Postfix: the same addresses, in any order
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
    """How many recipients one delivery leg has, as the dialog counts them."""
    return len(resolve_recipients(listed, deliveries, primary))


def union_recipients(legs: Iterable[List[str]]) -> List[str]:
    """The recipients of a whole message: those of each of its delivery legs,
    one address per recipient (messageRecipientsAll() in message-details.js)."""
    found: Dict[str, str] = {}
    for addresses in legs:
        for address in addresses:
            key = address_key(address)
            if key and key not in found:
                found[key] = str(address).strip()
    return list(found.values())


def legs_recipients(db, legs, rspamd_logs: Optional[Dict[int, object]] = None) -> Dict[str, List[str]]:
    """The recipients of each leg, by correlation key, from two grouped queries
    (its Rspamd log, its visible Postfix lines) whatever the number of legs.
    rspamd_logs: the Rspamd logs already loaded, by id."""
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
    """(delivered to, written address) of the visible Postfix lines of each leg,
    by correlation key: the lines of its own message of its queue id, as the
    message details show them, else the lines linked to it.

    One query for every leg with a queue id: Postfix reuses queue ids, so
    the lines of each queue id are cut into messages
    (correlation.split_queue_occurrences) and each leg counts its own. A
    second query only for legs linked to their lines by id alone. Never one
    per leg."""
    found = {leg.correlation_key: [] for leg in legs}
    by_queue, by_line = {}, {}
    for leg in legs:
        if leg.queue_id:
            by_queue.setdefault(leg.queue_id, []).append(leg)
        elif isinstance(leg.postfix_log_ids, list):
            for line_id in {i for i in leg.postfix_log_ids if isinstance(i, int)}:
                by_line.setdefault(line_id, []).append(leg.correlation_key)

    # Which lines are visible is checked against the listed lines of these queues
    # only (postfix_line_visible_among), never against the whole table
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
