"""
Message correlation logic - Simplified to rely on Message-ID only

Now that every message has a Message-ID, we can simplify:
1. Rspamd log has Message-ID
2. Find Message-ID in Postfix logs => get Queue-ID
3. Find all Postfix logs with that Queue-ID
4. Create one MessageCorrelation linking everything

BLACKLIST filtering is done at import time (in scheduler.py)
"""
import ipaddress
import logging
import re
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import and_, exists, func, literal_column, or_

from .models import MessageCorrelation, PostfixLog, RspamdLog
from .config import settings

logger = logging.getLogger(__name__)


def origin_is_local(rspamd_log: Optional[RspamdLog]) -> bool:
    """
    Whether the message entered the server from the inside.

    A locally hosted sender domain is not enough to call a message internal:
    mail for a hosted domain can arrive from an outside relay (for example a
    message sent through Microsoft 365 carries a local sender address but
    enters from the internet). The origin counts as local when the submission
    was authenticated (SMTP auth / MAILCOW_AUTH) or came from a private or
    loopback address; a message that never passed Rspamd was generated on the
    host itself.
    """
    if rspamd_log is None:
        return True
    if getattr(rspamd_log, 'has_auth', False):
        return True
    user = getattr(rspamd_log, 'user', None)
    if user and user != 'unknown':
        return True
    ip = getattr(rspamd_log, 'ip', None)
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback


def submitted_with_auth():
    """
    Filter clause for message_correlations rows whose Rspamd scan shows an
    authenticated submission (MAILCOW_AUTH, or a logged-in SMTP user).

    Use this wherever a row is attributed to the mailbox in its sender field
    for enforcement or alerting. The 'outbound' direction alone is not enough:
    it also covers unauthenticated mail with a hosted envelope sender, and the
    envelope sender of such mail is whatever the remote client claimed.
    Rows without a linked Rspamd scan do not qualify.
    """
    return exists().where(RspamdLog.id == MessageCorrelation.rspamd_log_id, _authenticated_scan())


def _authenticated_scan():
    return or_(
        RspamdLog.has_auth.is_(True),
        and_(RspamdLog.user.isnot(None), RspamdLog.user != '', RspamdLog.user != 'unknown'),
    )


def authenticated_submissions(query):
    """
    Limit a message_correlations query to authenticated submissions, the same
    rows as submitted_with_auth(), with their Rspamd scan joined so that
    submitting_mailbox() can be used in it.
    """
    return query.select_from(MessageCorrelation).join(
        RspamdLog, RspamdLog.id == MessageCorrelation.rspamd_log_id
    ).filter(_authenticated_scan())


def submitting_mailbox():
    """
    The mailbox an authenticated submission is counted for, lowercased: the
    login Rspamd recorded, or the envelope sender when the scan has none.

    mailcow lets a mailbox send from every alias that points to it and from the
    addresses it may send as (sender ACL), so the envelope sender is not always
    the mailbox that sent. Counting by it let one mailbox spread its mail over
    several addresses, and pointed enforcement at an alias, which mailcow
    cannot disable. Use inside authenticated_submissions().
    """
    # Literal SQL, not bound parameters, so the same expression can be grouped by
    login = func.nullif(func.nullif(func.trim(RspamdLog.user), literal_column("''")),
                        literal_column("'unknown'"))
    return func.lower(func.coalesce(login, MessageCorrelation.sender))


def extract_domain(email: str) -> Optional[str]:
    """
    Extract domain from email address
    
    Args:
        email: Email address (e.g., "user@example.com")
    
    Returns:
        Domain name or None if invalid
    """
    if not email or '@' not in email:
        return None
    return email.split('@', 1)[1].lower().strip()


def is_local_domain(domain: Optional[str]) -> bool:
    """
    Check if domain is in local domains list
    
    Args:
        domain: Domain name to check
    
    Returns:
        True if domain is local, False otherwise
    """
    if not domain:
        return False
    local_domains = settings.local_domains_list
    if not local_domains:
        return False
    return domain.lower() in [d.lower() for d in local_domains]


def detect_direction(rspamd_log: Dict[str, Any]) -> str:
    """
    Detect if email is inbound or outbound based on Rspamd log
    
    Note: Internal direction is determined later based on Postfix relay=dovecot
    Local domains list includes primary + alias domains (from API alias-domain/all).
    
    Logic:
    1. Check for MAILCOW_AUTH symbol (definitive outbound indicator)
    2. Check user field (if authenticated = outbound, if unknown = inbound)
    3. Fallback: if inbound by above but sender is local (incl. alias domain) and
       any recipient is external → outbound
    
    Args:
        rspamd_log: Rspamd log entry dictionary
    
    Returns:
        'inbound', 'outbound', or 'unknown'
    """
    # Check for MAILCOW_AUTH symbol - most reliable indicator
    symbols = rspamd_log.get('symbols', {})
    if 'MAILCOW_AUTH' in symbols:
        return 'outbound'
    
    # Check user field - if authenticated, it's outbound
    user = rspamd_log.get('user', 'unknown')
    if user != 'unknown' and user:
        return 'outbound'
    
    # If user is unknown, default to inbound
    direction = 'inbound' if user == 'unknown' else 'unknown'
    
    # Fallback: sender from alias domain may not have MAILCOW_AUTH/user set
    if direction == 'inbound':
        sender = rspamd_log.get('sender_smtp')
        recipients = rspamd_log.get('rcpt_smtp', [])
        if isinstance(recipients, str):
            recipients = [recipients] if recipients else []
        sender_domain = extract_domain(sender) if sender else None
        if sender_domain and is_local_domain(sender_domain) and recipients:
            for r in recipients:
                recv_domain = extract_domain(r) if r else None
                if recv_domain and not is_local_domain(recv_domain):
                    return 'outbound'
    return direction


# Postfix programs that log a delivery result (the last part of the syslog
# program name, e.g. postfix/smtp, postfix/lmtp).
POSTFIX_DELIVERY_AGENTS = ('smtp', 'lmtp', 'local', 'virtual', 'error', 'retry', 'discard', 'pipe')

# An address as Postfix logs it between <>: a quoted local part may contain
# '>' and ', ', anything outside quotes ends at the first '>'. The two
# alternatives start with different characters, so matching stays linear.
_PF_ADDR = r'(?:"(?:[^"\\]|\\.)*"|[^>"])*'

# Delivery-agent result (smtp, lmtp, local, virtual, error, pipe, ...):
#   QID: to=<rcpt>, [orig_to=<o>, ]relay=R, [conn_use=N, ]delay=D,
#        delays=a/b/c/d, dsn=X.Y.Z, status=word (reply text)
# Only these fixed fields carry the outcome. The addresses are chosen by
# senders and the reply text by remote servers, so neither may supply a
# status, a DSN or a Message-ID.
_PF_DELIVERY_RE = re.compile(
    r'^[0-9A-F]+: to=<(?P<to>' + _PF_ADDR + r')>, '
    r'(?:orig_to=<(?P<orig_to>' + _PF_ADDR + r')>, )?'
    r'(?P<fields>(?:[a-z_]+=[^,\s<>]*, )*?)'
    r'dsn=(?P<dsn>\d\.\d{1,3}\.\d{1,3}), status=(?P<status>\w+)(?P<reply>.*)$'
)
_PF_FIELD_RE = re.compile(r'([a-z_]+)=([^,\s<>]*), ')
# qmgr: QID: from=<sender>, status=expired, returned to sender
_PF_EXPIRED_RE = re.compile(r'^[0-9A-F]+: from=<' + _PF_ADDR + r'>, status=(?P<status>expired)\b')
# cleanup: QID: message-id=<id>
_PF_MESSAGE_ID_RE = re.compile(r'^[0-9A-F]+: message-id=<([^>]+)>', re.IGNORECASE)


def parse_postfix_message(message: str) -> Dict[str, Any]:
    """
    Parse Postfix log message to extract structured data

    status, dsn, relay and delay are read only from a delivery-agent result
    line (or the qmgr "status=expired" line) of a queued message, and the
    Message-ID only from the cleanup "message-id=" line. Text inside from=<>,
    to=<>, helo=<> or a server reply never sets them, so an smtpd NOQUEUE
    reject line can never look like a bounce.

    Args:
        message: Postfix log message string

    Returns:
        Dictionary with parsed fields
    """
    result = {}

    # Extract queue ID (at the start of message)
    queue_match = re.match(r'^([A-F0-9]+):', message)
    if queue_match:
        result['queue_id'] = queue_match.group(1)

    # Message-ID: only the cleanup line names it. Reply text inside
    # status=(...) is not a Message-ID: Dovecot LMTP quotes the recipient
    # there ("250 2.0.0 <rcpt> <session> Saved") and a remote MX may quote
    # anything.
    mid_match = _PF_MESSAGE_ID_RE.match(message)
    if mid_match:
        result['message_id'] = mid_match.group(1)

    delivery = _PF_DELIVERY_RE.match(message)
    if delivery:
        result['recipient'] = delivery.group('to') or None
        if delivery.group('orig_to') is not None:
            result['orig_to'] = delivery.group('orig_to') or None
        fields = dict(_PF_FIELD_RE.findall(delivery.group('fields')))
        if fields.get('relay'):
            result['relay'] = fields['relay']
        try:
            if fields.get('delay'):
                result['delay'] = float(fields['delay'])
        except ValueError:
            pass
        result['dsn'] = delivery.group('dsn')
        result['status'] = delivery.group('status')

        # Check for rspamd-pipe-spam delivery. Only the relay or Postfix's
        # own pipe/local result text count, never a remote server's reply.
        # Example: relay=rspamd-pipe-spam, ... status=sent (delivered via rspamd-pipe-spam service)
        reply = delivery.group('reply').strip()
        if result['status'] == 'sent' and (
                'rspamd-pipe-spam' in (result.get('relay') or '')
                or (reply.startswith('(delivered ') and 'rspamd-pipe-spam' in reply)):
            result['status'] = 'spam'
            # If we have orig_to, use it as the recipient because the actual to= is the spam alias
            if result.get('orig_to'):
                result['recipient'] = result['orig_to']
        return result

    # Extract from= (sender)
    from_match = re.search(r'from=<([^>]*)>', message)
    if from_match:
        result['sender'] = from_match.group(1) if from_match.group(1) else None

    # Extract to= (recipient)
    to_match = re.search(r'to=<([^>]*)>', message)
    if to_match:
        result['recipient'] = to_match.group(1) if to_match.group(1) else None

    expired = _PF_EXPIRED_RE.match(message)
    if expired:
        result['status'] = expired.group('status')

    return result


# --- Delivery legs --------------------------------------------------------
#
# A correlation is one delivery leg: one (Message-ID, Postfix queue chain)
# pair, not one Message-ID (issue #36). A SOGo/Sieve forward or any other
# re-submission pushes the same Message-ID through a second queue chain, with
# its own sender, recipient, direction and status. Keying on the Message-ID
# alone let the second leg overwrite the first one, which hid the original
# delivery completely.


def legacy_correlation_key(message_id: str) -> str:
    """
    The historical Message-ID-only key.

    The first leg of a message keeps it, so every correlation key handed out
    before issue #36 (links, exports, stored references) stays valid.
    """
    return hashlib.sha256(f"msgid:{message_id}".encode()).hexdigest()


def leg_correlation_key(message_id: str, queue_id: str) -> str:
    """Key of an additional delivery leg of the same Message-ID."""
    return hashlib.sha256(f"msgid:{message_id}:queue:{queue_id}".encode()).hexdigest()


def build_correlation_key(db: Session, message_id: str, queue_id: Optional[str]) -> Optional[str]:
    """
    Pick the correlation key for a leg that is about to be created.

    Returns None when no key can be minted: the Message-ID-only key is already
    taken and there is no queue chain to scope a new one by. The caller must
    then reuse the existing correlation instead of opening a second one.
    """
    legacy = legacy_correlation_key(message_id)
    taken = {
        row[0] for row in db.query(MessageCorrelation.correlation_key).filter(
            MessageCorrelation.message_id == message_id
        ).all()
    }
    if legacy not in taken:
        return legacy
    if not queue_id:
        return None
    return leg_correlation_key(message_id, queue_id)


def find_legs(db: Session, message_id: str) -> List[MessageCorrelation]:
    """Every delivery leg recorded for a Message-ID, oldest first."""
    if not message_id:
        return []
    return db.query(MessageCorrelation).filter(
        MessageCorrelation.message_id == message_id
    ).order_by(MessageCorrelation.id).all()


def find_stub_leg(db: Session, message_id: str) -> Optional[MessageCorrelation]:
    """
    A correlation created from an Rspamd log before any Postfix line existed.

    It has no queue chain yet and adopts the first one that arrives.
    """
    if not message_id:
        return None
    return db.query(MessageCorrelation).filter(
        MessageCorrelation.message_id == message_id,
        MessageCorrelation.queue_id.is_(None)
    ).order_by(MessageCorrelation.id).first()


def find_leg_by_queue(
    db: Session,
    queue_id: str,
    message_id: Optional[str] = None
) -> Optional[MessageCorrelation]:
    """
    The leg that owns a Postfix queue chain.

    Postfix reuses short queue ids, so when the log line carries a Message-ID
    it is used to tell the legs apart; a queue whose legs all belong to other
    messages is treated as unknown rather than guessed at.
    """
    if not queue_id:
        return None
    rows = db.query(MessageCorrelation).filter(
        MessageCorrelation.queue_id == queue_id
    ).order_by(MessageCorrelation.id).all()
    if not rows:
        return None
    if message_id:
        matching = [r for r in rows if r.message_id == message_id]
        if matching:
            return matching[0]
        unclaimed = [r for r in rows if not r.message_id]
        if unclaimed:
            return unclaimed[0]
        logger.debug(
            f"Queue {queue_id} belongs to another Message-ID than {message_id[:50]}"
        )
        return None
    if len(rows) > 1:
        logger.warning(
            f"Queue {queue_id} maps to {len(rows)} correlations - using the oldest"
        )
    return rows[0]


def group_postfix_logs_by_queue(postfix_logs: List[PostfixLog]) -> Dict[str, List[PostfixLog]]:
    """
    Split Postfix logs into queue chains, earliest chain first.

    Each chain is one delivery leg. Logs without a queue id carry no chain and
    are dropped here.
    """
    chains: Dict[str, List[PostfixLog]] = {}
    for plog in postfix_logs:
        if plog.queue_id:
            chains.setdefault(plog.queue_id, []).append(plog)

    def chain_start(item):
        times = [p.time for p in item[1] if p.time]
        return (min(times) if times else datetime.max, item[0])

    return dict(sorted(chains.items(), key=chain_start))


def nearest_queue_chain(
    chains: Dict[str, List[PostfixLog]],
    reference_time: Optional[datetime]
) -> Optional[str]:
    """
    The queue chain closest in time to a reference point (an Rspamd log).

    Every re-submission passes Rspamd on its own, a second or two from the
    Postfix lines of its own chain, so proximity in time is what says which
    leg a verdict belongs to.
    """
    if not chains:
        return None
    queue_ids = list(chains.keys())
    if not reference_time:
        return queue_ids[0]

    def distance(queue_id):
        times = [p.time for p in chains[queue_id] if p.time]
        if not times:
            return timedelta.max
        return min(abs(t - reference_time) for t in times)

    return min(queue_ids, key=distance)


# --- Queue occurrences ----------------------------------------------------
#
# Postfix names a queued message by a short queue id made of the queue
# file's inode and the microsecond it was created, so an id comes back once
# the previous message has left the queue: minutes or days later, for an
# unrelated message. All lines of one queue id are therefore not one
# message. split_queue_occurrences() cuts them into occurrences, one per
# message, and occurrence_for() says which one a correlation owns.
#
# What the cut relies on:
# - Every line of the previous message is logged before the first line of
#   the next one (the id is free only once the file is gone).
# - Line order inside one second is not chronological: mailcow returns the
#   log newest first, and PostfixLog.id is the order of storage. So lines
#   are compared by whole second only.
# - "removed" is not always logged, and qmgr logs it after the file is gone,
#   possibly in the second the next message opens. Only qmgr's "removed"
#   ends a message: qmgr logs it once every delivery is done, while
#   postsuper -d can remove a message whose delivery is still running, and
#   that delivery's result is logged after it.
# - cleanup logs one message-id= line per Message-ID header, so a message
#   with that header twice logs two lines; those never split a message.

OPENER = 'opener'      # smtpd/qmqpd "client=", pickup "uid=": the queue file is created
RECEIPT = 'receipt'    # any other smtpd, qmqpd, pickup or cleanup line
END = 'end'            # qmgr "removed": every delivery is done and the queue file is gone
DELIVERY = 'delivery'  # everything else: qmgr, delivery agents, bounce, postsuper

_RECEIPT_PROGRAMS = ('smtpd', 'qmqpd', 'pickup', 'cleanup')


def postfix_line_kind(line) -> str:
    """Which part of a message's life a Postfix line with a queue id logs."""
    program = (getattr(line, 'program', None) or '').rsplit('/', 1)[-1]
    message = getattr(line, 'message', None) or ''
    queue_id = getattr(line, 'queue_id', None) or ''
    prefix = f'{queue_id}: '
    text = message[len(prefix):] if queue_id and message.startswith(prefix) else message
    if program in ('smtpd', 'qmqpd') and text.startswith('client='):
        return OPENER
    if program == 'pickup' and text.startswith('uid='):
        return OPENER
    if program in _RECEIPT_PROGRAMS:
        return RECEIPT
    if program == 'qmgr' and text.startswith('removed'):
        return END
    return DELIVERY


def naive_utc(value: Optional[datetime]) -> Optional[datetime]:
    """Times are stored as naive UTC; an aware value is converted to that."""
    if value is not None and value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _line_order(line):
    return (naive_utc(line.time) or datetime.min, line.id or 0)


class QueueOccurrence:
    """One message's lines of a queue id.

    lines: the lines that are this message's.
    boundary: delivery and "removed" lines of the second this message
    opened in that may be the previous message's, when that one logged no
    "removed" before. They belong to both messages for display and to
    neither for status, times or links.
    """

    def __init__(self, opened_at: datetime):
        self.opened_at = opened_at
        self.lines: List[PostfixLog] = []
        self.boundary: List[PostfixLog] = []
        self.ended = False      # an own "removed" line
        self.delivered = False  # an own delivery or "removed" line

    def add(self, line) -> None:
        self.lines.append(line)
        kind = postfix_line_kind(line)
        if kind == END:
            self.ended = True
        if kind in (END, DELIVERY):
            self.delivered = True

    @property
    def message_ids(self) -> set:
        return {line.message_id for line in self.lines if line.message_id}

    @property
    def ids(self) -> set:
        return {line.id for line in self.lines if line.id}

    def shown_lines(self) -> List[PostfixLog]:
        """Own and boundary lines, in time order: what a detail view shows."""
        return sorted(self.lines + self.boundary, key=_line_order)

    def span(self):
        times = [naive_utc(line.time) for line in self.lines + self.boundary if line.time]
        return (min(times), max(times)) if times else (self.opened_at, self.opened_at)


def split_queue_occurrences(lines) -> List[QueueOccurrence]:
    """Cut the lines of one queue id into messages, earliest first.

    A second opens a new message when the current one already has a line in
    an earlier second and either: the second holds an opener; or it holds a
    receipt line and the current message already logged a delivery or
    "removed"; or the current message already logged "removed" (anything
    after that is someone else's). Deferred retries, hold and release, and
    gaps of days never cut a message.

    When the previous message logged no "removed" before the second the new
    one opens in, the delivery and "removed" lines of that second cannot be
    placed: they are boundary lines of both.
    """
    by_second: Dict[datetime, list] = {}
    for line in lines:
        if line.time is None:
            continue
        by_second.setdefault(naive_utc(line.time).replace(microsecond=0), []).append(line)

    occurrences: List[QueueOccurrence] = []
    current: Optional[QueueOccurrence] = None
    for second in sorted(by_second):
        group = sorted(by_second[second], key=_line_order)
        kinds = [postfix_line_kind(line) for line in group]
        opens = current is not None and (
            OPENER in kinds
            or (RECEIPT in kinds and current.delivered)
            or current.ended
        )
        if not opens:
            if current is None:
                current = QueueOccurrence(second)
                occurrences.append(current)
            for line in group:
                current.add(line)
            continue

        previous, current = current, QueueOccurrence(second)
        occurrences.append(current)
        for line, kind in zip(group, kinds):
            if not previous.ended and kind in (DELIVERY, END):
                previous.boundary.append(line)
                current.boundary.append(line)
            else:
                current.add(line)
    return occurrences


def _distance(occurrence: QueueOccurrence, near: Optional[datetime]) -> timedelta:
    start, end = occurrence.span()
    near = naive_utc(near)
    if near is None or start <= near <= end:
        return timedelta(0)
    return min(abs(start - near), abs(end - near))


def occurrence_for(
    occurrences: List[QueueOccurrence],
    message_id: Optional[str],
    near: Optional[datetime] = None,
    strict: bool = True,
) -> Optional[QueueOccurrence]:
    """The occurrence that is the message with this Message-ID.

    An occurrence that logged another Message-ID (and not this one) is
    someone else's. When exactly one occurrence logged this Message-ID, it is
    that one. When none did, the only occurrence of the queue id is taken, as
    long as it logged no other Message-ID.

    Anything else cannot be decided from the lines: strict (every write)
    returns None; otherwise (a detail view) the occurrence nearest to `near`
    is returned.
    """
    if not occurrences:
        return None
    if message_id:
        holding = [o for o in occurrences if message_id in o.message_ids]
        if len(holding) == 1:
            return holding[0]
        if holding:
            return None if strict else min(holding, key=lambda o: _distance(o, near))
        candidates = [o for o in occurrences if not o.message_ids]
    else:
        candidates = list(occurrences)
    if len(occurrences) == 1 and candidates:
        return occurrences[0]
    if strict:
        return None
    return min(candidates or occurrences, key=lambda o: _distance(o, near))


def identified_by_message_id(occurrence: Optional[QueueOccurrence], message_id: Optional[str]) -> bool:
    return bool(occurrence and message_id and message_id in occurrence.message_ids)


def queue_occurrences(db: Session, queue_id: Optional[str]) -> List[QueueOccurrence]:
    """The occurrences of one queue id, from all its stored lines."""
    if not queue_id:
        return []
    return split_queue_occurrences(
        db.query(PostfixLog).filter(PostfixLog.queue_id == queue_id).all())


def own_occurrence(db: Session, queue_id: Optional[str], message_id: Optional[str],
                   near: Optional[datetime] = None, occurrences=None) -> Optional[QueueOccurrence]:
    """The occurrence a write may read for this message (occurrence_for,
    strict). None as well when it also holds the Message-ID of another
    correlation of the queue id: the lines that tell the two messages apart
    have not all arrived yet. occurrences: when the caller already split them."""
    if occurrences is None:
        occurrences = queue_occurrences(db, queue_id)
    occurrence = occurrence_for(occurrences, message_id, near=near)
    others = (occurrence.message_ids - {message_id}) if occurrence is not None else set()
    if others:
        # The session does not autoflush: a correlation given this queue id
        # earlier in the same run must be seen
        db.flush()
    if others and db.query(MessageCorrelation.id).filter(
            MessageCorrelation.queue_id == queue_id, MessageCorrelation.message_id.in_(others)).first():
        return None
    return occurrence


def shown_postfix_lines(db: Session, correlation) -> List[PostfixLog]:
    """The Postfix lines a detail view shows for a correlation: its own
    occurrence of its queue id with that occurrence's boundary lines, else
    the lines linked to it by id."""
    if correlation.queue_id:
        occurrence = occurrence_for(
            queue_occurrences(db, correlation.queue_id), correlation.message_id,
            near=correlation.first_seen, strict=False)
        return occurrence.shown_lines() if occurrence else []
    ids = sorted({i for i in (correlation.postfix_log_ids or []) if isinstance(i, int)})
    if not ids:
        return []
    return db.query(PostfixLog).filter(PostfixLog.id.in_(ids)).order_by(PostfixLog.time, PostfixLog.id).all()


def rspamd_marks_spam(rspamd_log) -> bool:
    """RspamdLog.is_spam as the import sets it (scheduler, Rspamd ingest)."""
    symbols = rspamd_log.symbols if isinstance(rspamd_log.symbols, dict) else {}
    return rspamd_log.action in ('reject', 'add header', 'rewrite subject') or 'SPAM_TRAP' in symbols


def derive_final_status(lines, rspamd_log, dovecot_status, stored_status) -> Optional[str]:
    """A delivery's final status from its own Postfix lines alone.

    Postfix outcome first (a bounce or reject wins, then a delivery to the
    spam pipe, a delivery, an expiry, a deferral), then the Rspamd verdict
    when Postfix logged none, then the Dovecot discard (issue #65) as
    scheduler._apply_dovecot_verdict applies it.
    """
    statuses = {line.status for line in lines if line.status}
    status = next((outcome for found, outcome in (
        ('bounced', 'bounced'), ('rejected', 'rejected'), ('spam', 'spam'), ('sent', 'delivered'),
        ('expired', 'expired'), ('deferred', 'deferred')) if found in statuses), None)
    if status is None and rspamd_log is not None:
        if rspamd_log.action == 'reject':
            status = 'rejected'
        elif rspamd_log.is_spam:
            status = 'spam'
    if status is None and stored_status == 'expired':
        status = 'expired'
    if dovecot_status == 'discarded' and status not in ('bounced', 'rejected', 'deferred'):
        status = 'discarded'
    return status


def _own_value(stored, own_values, rspamd_values, other_values):
    """stored, unless it is evidently another message's: found in another
    occurrence of the queue id and neither in this message's lines nor in its
    Rspamd scan. Then this message's own value replaces it."""
    if not stored:
        return stored
    own = [v for v in own_values if v]
    rspamd = [v for v in rspamd_values if v]
    known = {v.lower() for v in own + rspamd}
    if stored.lower() in known or stored.lower() not in {v.lower() for v in other_values if v}:
        return stored
    return (own or rspamd or [None])[0]


def ownership_differs(correlation, occurrences: List[QueueOccurrence], occurrence: QueueOccurrence,
                      queue_keys: set) -> bool:
    """Whether a correlation holds lines of its queue id that are not its own
    occurrence's (another message's, or boundary lines), or its own lines
    carry the key of another correlation of this queue id."""
    own = occurrence.ids
    others = {line.id for o in occurrences for line in o.lines + o.boundary if line.id} - own
    stored = {i for i in (correlation.postfix_log_ids or []) if isinstance(i, int)}
    if stored & others:
        return True
    return any(line.correlation_key and line.correlation_key != correlation.correlation_key
               and line.correlation_key in queue_keys for line in occurrence.lines)


def repair_from_occurrence(db: Session, correlation, occurrence: QueueOccurrence,
                           occurrences: List[QueueOccurrence], now: datetime) -> None:
    """Re-derive a correlation from its own occurrence alone, after it was
    found holding another message's lines. Does not commit; stamps are set by
    settle_queue()."""
    rspamd_log = db.get(RspamdLog, correlation.rspamd_log_id) if correlation.rspamd_log_id else None
    own = sorted(occurrence.lines, key=_line_order)
    other = [line for o in occurrences if o is not occurrence for line in o.lines]

    correlation.postfix_log_ids = [line.id for line in own if line.id]
    times = [naive_utc(line.time) for line in own if line.time]
    if rspamd_log is not None and rspamd_log.time:
        times.append(naive_utc(rspamd_log.time))
    if times:
        correlation.first_seen = min(times)

    if rspamd_log is not None:
        rspamd_log.is_spam = rspamd_marks_spam(rspamd_log) or any(line.status == 'spam' for line in own)

    rspamd_recipients = rspamd_log.recipients_smtp if rspamd_log is not None and isinstance(
        rspamd_log.recipients_smtp, list) else []
    correlation.sender = _own_value(
        correlation.sender, [line.sender for line in own],
        [rspamd_log.sender_smtp if rspamd_log is not None else None], [line.sender for line in other])
    correlation.recipient = _own_value(
        correlation.recipient, [line.recipient for line in own], rspamd_recipients,
        [line.recipient for line in other])

    correlation.final_status = derive_final_status(
        own, rspamd_log, correlation.dovecot_status, correlation.final_status)
    correlation.last_seen = now


def owners_of_queue(correlations, occurrences: List[QueueOccurrence]) -> Dict[int, QueueOccurrence]:
    """{correlation id: its own occurrence} for the correlations of one queue
    id whose occurrence can be told. With several correlations on the queue
    id, only a Message-ID tells; an occurrence two of them claim is no one's."""
    owned = {}
    for correlation in correlations:
        occurrence = occurrence_for(occurrences, correlation.message_id, near=correlation.first_seen)
        if occurrence is None:
            continue
        if len(correlations) > 1 and not identified_by_message_id(occurrence, correlation.message_id):
            continue
        owned[correlation.id] = occurrence
    claimed = [id(o) for o in owned.values()]
    return {cid: o for cid, o in owned.items() if claimed.count(id(o)) == 1}


def settle_queue(db: Session, correlations, occurrences: List[QueueOccurrence], now: datetime) -> list:
    """Give every message of one queue id back its own lines.

    A correlation found holding lines that are not its own occurrence's is
    re-derived from its occurrence alone (repair_from_occurrence). Then the
    queue id's lines are stamped: the lines of an owned occurrence with its
    owner's key; any other line that carries the key of one of these
    correlations loses it. Returns the correlations repaired. Does not
    commit."""
    owned = owners_of_queue(correlations, occurrences)
    keys = {c.correlation_key for c in correlations}
    repaired = [c for c in correlations if c.id in owned
                and ownership_differs(c, occurrences, owned[c.id], keys)]
    if not repaired:
        return []
    for correlation in repaired:
        repair_from_occurrence(db, correlation, owned[correlation.id], occurrences, now)
    by_occurrence = {id(owned[c.id]): c.correlation_key for c in correlations if c.id in owned}
    for occurrence in occurrences:
        for line in occurrence.lines:
            key = by_occurrence.get(id(occurrence))
            if key:
                line.correlation_key = key
            elif line.correlation_key in keys:
                line.correlation_key = None
        for line in occurrence.boundary:
            if line.correlation_key in keys:
                line.correlation_key = None
    logger.info(f"[CORRELATION] Queue id {repaired[0].queue_id} was used by more than one message: "
                f"{len(repaired)} correlation(s) re-derived from their own lines")
    return repaired


def ensure_leg(
    db: Session,
    message_id: str,
    queue_id: str,
    postfix_logs: List[PostfixLog],
    rspamd_log: Optional[RspamdLog] = None
) -> Optional[MessageCorrelation]:
    """
    Return the correlation for one (Message-ID, queue chain) pair.

    Creates it when this chain has not been seen before, unless a stub is
    waiting for a chain to adopt. The Rspamd log is only attached to the leg it
    actually belongs to, so the other legs keep their own verdict.
    """
    leg = find_leg_by_queue(db, queue_id, message_id)

    if not leg:
        leg = find_stub_leg(db, message_id)
        if leg:
            logger.debug(f"Stub for {message_id[:50]} adopts queue chain {queue_id}")
            leg.queue_id = queue_id

    # Linked to its Postfix lines: the addresses Rspamd recorded normalized
    # get the ones the sender wrote. Only after the link is committed: a
    # delivery line stored meanwhile by the ingest is seen here, or the
    # ingest sees the link (written_recipients.record_for_queues)
    from .services.written_recipients import record as record_written

    if leg:
        if rspamd_log:
            update_correlation_with_rspamd(db, leg, rspamd_log)
        update_correlation_with_postfix_logs(db, leg, postfix_logs)  # commits
        if record_written(db, leg, rspamd_log):
            db.commit()
        return leg

    if rspamd_log:
        leg = create_correlation_with_all_data(
            db, rspamd_log, postfix_logs, message_id, queue_id
        )
    else:
        leg = create_correlation_from_postfix_logs(
            db, message_id, queue_id, postfix_logs
        )

    if leg:
        for plog in postfix_logs:
            plog.correlation_key = leg.correlation_key
        db.commit()
        if record_written(db, leg, rspamd_log):
            db.commit()
    return leg


def correlate_rspamd_log(db: Session, rspamd_log: RspamdLog) -> Optional[MessageCorrelation]:
    """
    Correlate Rspamd log with Postfix logs using Message-ID

    LOGIC:
    1. Get Message-ID from Rspamd
    2. Find Postfix log(s) with same Message-ID
    3. Split them into queue chains - every chain is a delivery leg (issue #36)
    4. Make sure each leg has a correlation of its own
    5. Attach this Rspamd verdict to the leg it belongs to (nearest in time)

    Args:
        db: Database session
        rspamd_log: RspamdLog object

    Returns:
        MessageCorrelation object of the leg this Rspamd log belongs to, or None
    """
    # Skip if no message_id
    if not rspamd_log.message_id or rspamd_log.message_id == 'undef':
        logger.debug("Rspamd log has no message_id, skipping correlation")
        return None

    message_id = rspamd_log.message_id.strip()

    # Step 1: Find Postfix log(s) with this Message-ID
    postfix_logs_with_msgid = db.query(PostfixLog).filter(
        PostfixLog.message_id == message_id
    ).all()

    # Step 2: One delivery leg per Postfix queue chain
    chains = group_postfix_logs_by_queue(postfix_logs_with_msgid)

    if not chains:
        if postfix_logs_with_msgid:
            logger.warning(f"Postfix logs found but no Queue-ID for Message-ID: {message_id[:50]}")
        else:
            logger.debug(f"No Postfix logs found with Message-ID: {message_id[:50]}")
        # Reuse the waiting stub, otherwise open one - it adopts the first
        # queue chain that shows up.
        stub = find_stub_leg(db, message_id)
        if stub:
            update_correlation_with_rspamd(db, stub, rspamd_log)
            return stub
        return create_correlation_from_rspamd(db, rspamd_log)

    # Step 3: This verdict belongs to the chain nearest to it in time
    target_queue = nearest_queue_chain(chains, rspamd_log.time)
    logger.debug(
        f"Message-ID {message_id[:50]} has {len(chains)} delivery leg(s), "
        f"this Rspamd log belongs to queue {target_queue}"
    )

    correlation = None
    for queue_id in chains:
        # The whole chain, including lines that do not repeat the Message-ID,
        # of this message only: the queue id may have been used by others
        occurrence = own_occurrence(db, queue_id, message_id, near=rspamd_log.time)
        if occurrence is None:
            logger.warning(f"Queue {queue_id} holds Message-ID {message_id[:50]} more than once - not linked")
            continue

        leg = ensure_leg(
            db, message_id, queue_id, occurrence.lines,
            rspamd_log=rspamd_log if queue_id == target_queue else None
        )
        if queue_id == target_queue:
            correlation = leg

    return correlation


def correlate_postfix_log(db: Session, postfix_log: PostfixLog) -> Optional[MessageCorrelation]:
    """
    Correlate Postfix log with existing correlation (if exists)

    The queue chain is what identifies a delivery leg, so the lookup is queue
    first (issue #36):
    1. A correlation for this Queue-ID - that is this leg, update it
    2. A correlation for this Message-ID with no queue chain yet (a stub from
       Rspamd) - it adopts this chain
    3. Legs of this Message-ID that all sit on other chains - this line is a
       re-submission and opens a leg of its own

    Args:
        db: Database session
        postfix_log: PostfixLog object

    Returns:
        MessageCorrelation object or None
    """
    # Postfix logs the Message-ID once per queue chain, so a line without one
    # takes it from the rest of its own chain: its own occurrence of the queue
    # id, never another message that used the id before or after it
    message_id = postfix_log.message_id
    mine, occurrences = None, []
    if postfix_log.queue_id:
        lines = db.query(PostfixLog).filter(PostfixLog.queue_id == postfix_log.queue_id).all()
        if not any(line is postfix_log for line in lines):
            lines.append(postfix_log)
        occurrences = split_queue_occurrences(lines)
        mine = next((o for o in occurrences if any(line is postfix_log for line in o.lines)), None)
        if not message_id and mine and len(mine.message_ids) == 1:
            message_id = next(iter(mine.message_ids))

    def owns_this_line(leg_message_id, near=None):
        """The line's occurrence is this message's, for a write."""
        return mine is not None and own_occurrence(
            db, postfix_log.queue_id, leg_message_id, near=near, occurrences=occurrences) is mine

    # Method 1: the queue chain this line belongs to. A leg of the queue id
    # that is not the message this line is part of gets nothing, and no
    # other leg is made from the line either
    correlation = find_leg_by_queue(db, postfix_log.queue_id, message_id)
    if correlation and postfix_log.queue_id and not owns_this_line(correlation.message_id, correlation.first_seen):
        logger.debug(f"Queue-ID {postfix_log.queue_id}: the line is not {correlation.message_id}'s")
        return None

    if correlation:
        logger.debug(f"Found correlation by Queue-ID: {postfix_log.queue_id}")

    # Method 2: a stub waiting for its first queue chain
    if not correlation and message_id:
        correlation = find_stub_leg(db, message_id)
        if correlation:
            logger.debug(f"Stub adopts queue chain: {message_id[:50]}")

    # Method 3: another delivery of a Message-ID we already know - a new leg
    if not correlation and message_id and postfix_log.queue_id:
        if find_legs(db, message_id) and owns_this_line(message_id):
            all_postfix_logs = list(mine.lines)
            logger.info(
                f"New delivery leg for Message-ID {message_id[:50]} "
                f"(Queue-ID: {postfix_log.queue_id})"
            )
            correlation = create_correlation_from_postfix_logs(
                db, message_id, postfix_log.queue_id, all_postfix_logs
            )
            if correlation:
                postfix_log.correlation_key = correlation.correlation_key
                db.commit()
                return correlation

    # Update correlation if found
    if correlation:
        update_correlation_with_postfix_log(db, correlation, postfix_log)
        postfix_log.correlation_key = correlation.correlation_key
        db.commit()
        return correlation

    # No correlation found yet (Rspamd may not have been processed)
    logger.debug(f"No correlation found for Postfix log (Queue-ID: {postfix_log.queue_id}, Message-ID: {postfix_log.message_id})")
    return None


def create_correlation_from_rspamd(
    db: Session,
    rspamd_log: RspamdLog
) -> Optional[MessageCorrelation]:
    """
    Create a new correlation from Rspamd log only
    (used when Postfix logs are not yet available)

    Args:
        db: Database session
        rspamd_log: RspamdLog object

    Returns:
        MessageCorrelation object (marked as incomplete), or None when this
        message already has a leg that cannot be told apart from this one
    """
    correlation_key = build_correlation_key(db, rspamd_log.message_id, rspamd_log.queue_id)
    if not correlation_key:
        logger.debug(
            f"Not opening a second queue-less correlation for {rspamd_log.message_id[:50]}"
        )
        return None

    # Get first recipient
    recipients = rspamd_log.recipients_smtp if rspamd_log.recipients_smtp else []
    first_recipient = recipients[0] if recipients else None
    
    correlation = MessageCorrelation(
        correlation_key=correlation_key,
        message_id=rspamd_log.message_id,
        queue_id=rspamd_log.queue_id,  # May be None
        sender=rspamd_log.sender_smtp,
        recipient=first_recipient,
        subject=rspamd_log.subject,
        direction=rspamd_log.direction,
        rspamd_log_id=rspamd_log.id,
        first_seen=rspamd_log.time,
        last_seen=datetime.utcnow(),
        is_complete=False  # Incomplete - waiting for Postfix logs
    )
    
    # Set initial status based on Rspamd action
    if rspamd_log.action == 'reject':
        correlation.final_status = 'rejected'
    elif rspamd_log.is_spam:
        correlation.final_status = 'spam'
    
    db.add(correlation)
    db.commit()
    
    logger.debug(f"Created incomplete correlation from Rspamd (waiting for Postfix): {correlation_key[:16]}")
    return correlation


def create_correlation_with_all_data(
    db: Session,
    rspamd_log: RspamdLog,
    postfix_logs: List[PostfixLog],
    message_id: str,
    queue_id: str
) -> MessageCorrelation:
    """
    Create a new correlation with all available data
    
    Args:
        db: Database session
        rspamd_log: RspamdLog object
        postfix_logs: List of PostfixLog objects
        message_id: Email Message-ID
        queue_id: Postfix Queue-ID
    
    Returns:
        MessageCorrelation object
    """
    # The first leg keeps the historical Message-ID-only key; another leg of
    # the same message is keyed by its queue chain as well (issue #36)
    correlation_key = build_correlation_key(db, message_id, queue_id)

    # Get first recipient from Rspamd
    recipients = rspamd_log.recipients_smtp if rspamd_log.recipients_smtp else []
    first_recipient = recipients[0] if recipients else None
    
    # Get postfix log IDs
    postfix_log_ids = [log.id for log in postfix_logs if log.id]
    
    # Determine final status from Postfix logs
    final_status = None
    for plog in postfix_logs:
        if plog.status:
            if plog.status in ['bounced', 'rejected']:
                final_status = plog.status
                break  # Priority status found
            elif plog.status == 'deferred' and not final_status:
                final_status = plog.status
            elif plog.status == 'sent' and final_status in (None, 'deferred'):
                # A delivery after deferrals, whatever order the lines come in
                final_status = 'delivered'
            elif plog.status == 'spam':
                final_status = 'spam'
                # Mark Rspamd log as spam as well (so frontend shows SPAM badge)
                if rspamd_log:
                    rspamd_log.is_spam = True

    
    # If no status from Postfix, use Rspamd
    if not final_status:
        if rspamd_log.action == 'reject':
            final_status = 'rejected'
        elif rspamd_log.is_spam:
            final_status = 'spam'
    
    # Get earliest timestamp
    all_times = [rspamd_log.time] + [log.time for log in postfix_logs]
    first_seen = min(all_times)
    
    # Check if email was delivered locally (relay=dovecot + both sender and recipient are local domains)
    # This is the definitive way to determine if email is internal
    direction = rspamd_log.direction
    
    # Check if sender and recipient are both local domains
    sender_domain = extract_domain(rspamd_log.sender_smtp)
    recipients = rspamd_log.recipients_smtp if rspamd_log.recipients_smtp else []
    
    sender_is_local = sender_domain and is_local_domain(sender_domain)
    all_recipients_local = True
    if recipients:
        for recipient in recipients:
            recipient_domain = extract_domain(recipient)
            if not recipient_domain or not is_local_domain(recipient_domain):
                all_recipients_local = False
                break
    else:
        all_recipients_local = False
    
    # Internal needs relay=dovecot, local sender, local recipients AND a local
    # origin - a hosted sender domain arriving from an outside relay is inbound
    if sender_is_local and all_recipients_local and origin_is_local(rspamd_log):
        for plog in postfix_logs:
            if plog.relay and 'dovecot' in plog.relay.lower():
                direction = 'internal'
                # Also update Rspamd log
                rspamd_log.direction = 'internal'
                break
    elif direction == 'internal':
        # The stored direction came from the earlier, laxer classification
        # that ignored the origin - re-derive instead of inheriting it
        direction = 'outbound' if (rspamd_log.has_auth or (
            rspamd_log.user and rspamd_log.user != 'unknown')) else 'inbound'
        rspamd_log.direction = direction

    correlation = MessageCorrelation(
        correlation_key=correlation_key,
        message_id=message_id,
        queue_id=queue_id,
        sender=rspamd_log.sender_smtp,
        recipient=first_recipient,
        subject=rspamd_log.subject,
        direction=direction,
        final_status=final_status,
        rspamd_log_id=rspamd_log.id,
        postfix_log_ids=postfix_log_ids,
        first_seen=first_seen,
        last_seen=datetime.utcnow(),
        is_complete=True  # Has Queue-ID and Postfix logs
    )
    
    db.add(correlation)
    db.commit()
    
    logger.info(f"Created full correlation: {correlation_key[:16]} (Queue: {queue_id}, {len(postfix_logs)} Postfix logs)")
    return correlation


def create_correlation_from_postfix_logs(
    db: Session,
    message_id: str,
    queue_id: str,
    postfix_logs: List[PostfixLog]
) -> Optional[MessageCorrelation]:
    """
    Open a delivery leg from Postfix data alone (issue #36)

    Used for a re-submission whose Rspamd log has not been processed yet: the
    leg has to exist before anything can be attached to it, and the sender,
    recipient and status are all readable from the queue chain itself.

    Args:
        db: Database session
        message_id: Email Message-ID
        queue_id: Postfix Queue-ID of this leg
        postfix_logs: All Postfix logs of that queue chain

    Returns:
        MessageCorrelation object, or None when no key could be minted
    """
    correlation_key = build_correlation_key(db, message_id, queue_id)
    if not correlation_key:
        return None

    times = [plog.time for plog in postfix_logs if plog.time]

    correlation = MessageCorrelation(
        correlation_key=correlation_key,
        message_id=message_id,
        queue_id=queue_id,
        first_seen=min(times) if times else datetime.utcnow(),
        last_seen=datetime.utcnow(),
        is_complete=False
    )

    db.add(correlation)
    db.flush()

    # Fills sender, recipient, status and the log ids from the chain, and
    # commits
    update_correlation_with_postfix_logs(db, correlation, postfix_logs)

    logger.info(
        f"Created Postfix-only correlation: {correlation_key[:16]} "
        f"(Queue: {queue_id}, {len(postfix_logs)} Postfix logs)"
    )
    return correlation


def update_correlation_with_rspamd(
    db: Session,
    correlation: MessageCorrelation,
    rspamd_log: RspamdLog
):
    """
    Update correlation with Rspamd log information
    
    Args:
        db: Database session
        correlation: MessageCorrelation object
        rspamd_log: RspamdLog object
    """
    correlation.rspamd_log_id = rspamd_log.id
    
    if not correlation.sender and rspamd_log.sender_smtp:
        correlation.sender = rspamd_log.sender_smtp
    
    if not correlation.recipient and rspamd_log.recipients_smtp:
        recipients = rspamd_log.recipients_smtp
        if recipients and isinstance(recipients, list):
            correlation.recipient = recipients[0]
    
    if not correlation.subject and rspamd_log.subject:
        correlation.subject = rspamd_log.subject
    
    if not correlation.direction:
        direction = rspamd_log.direction
        if direction == 'internal' and not origin_is_local(rspamd_log):
            # A stored 'internal' from the earlier, laxer classification that
            # ignored the origin - re-derive instead of inheriting it
            direction = 'outbound' if (rspamd_log.has_auth or (
                rspamd_log.user and rspamd_log.user != 'unknown')) else 'inbound'
            rspamd_log.direction = direction
        correlation.direction = direction
    elif correlation.direction == 'internal' and not origin_is_local(rspamd_log):
        # The leg was classified before its Rspamd evidence existed (created
        # from Postfix lines alone, where a missing scan reads as host-local).
        # The scan that just arrived shows an outside origin - correct it.
        correlation.direction = 'outbound' if (rspamd_log.has_auth or (
            rspamd_log.user and rspamd_log.user != 'unknown')) else 'inbound'
        rspamd_log.direction = correlation.direction

    # Update status if Rspamd has stronger verdict
    if rspamd_log.action == 'reject':
        correlation.final_status = 'rejected'
    elif rspamd_log.is_spam and not correlation.final_status:
        correlation.final_status = 'spam'
    
    correlation.last_seen = datetime.utcnow()
    db.commit()


def update_correlation_with_postfix_log(
    db: Session,
    correlation: MessageCorrelation,
    postfix_log: PostfixLog
):
    """
    Update correlation with a single Postfix log
    
    IMPORTANT: When we get a queue_id for the first time, we must also
    find and link ALL existing PostfixLogs with that queue_id!
    This handles the case where logs arrive out of order.
    
    Args:
        db: Database session
        correlation: MessageCorrelation object
        postfix_log: PostfixLog object
    """
    # Check if this is the first time we're getting a queue_id
    first_queue_id = not correlation.queue_id and postfix_log.queue_id
    
    # Add to postfix log IDs list
    current_ids = list(correlation.postfix_log_ids or [])
    if postfix_log.id and postfix_log.id not in current_ids:
        current_ids.append(postfix_log.id)
        correlation.postfix_log_ids = current_ids
    
    # Update basic info if not set
    if not correlation.sender and postfix_log.sender:
        correlation.sender = postfix_log.sender
    
    if not correlation.recipient and postfix_log.recipient:
        correlation.recipient = postfix_log.recipient
    
    if not correlation.queue_id and postfix_log.queue_id:
        correlation.queue_id = postfix_log.queue_id
    
    if not correlation.message_id and postfix_log.message_id:
        correlation.message_id = postfix_log.message_id
    
    # CRITICAL FIX: If we just got a queue_id, find ALL existing postfix logs
    # with this queue_id and link them to this correlation
    if first_queue_id and postfix_log.queue_id:
        logger.info(f"First queue_id {postfix_log.queue_id} for correlation - searching for related logs")
        
        # The other lines of this message's occurrence of the queue id; none
        # when the lines cannot tell which occurrence is this message
        occurrence = own_occurrence(
            db, postfix_log.queue_id, correlation.message_id, near=correlation.first_seen)
        related_logs = [line for line in (occurrence.lines if occurrence else [])
                        if line.id != postfix_log.id]

        if related_logs:
            logger.info(f"Found {len(related_logs)} additional postfix logs with queue_id {postfix_log.queue_id}")
            
            for related_log in related_logs:
                # Add to IDs list
                if related_log.id and related_log.id not in current_ids:
                    current_ids.append(related_log.id)
                
                # Update correlation key in the related log
                related_log.correlation_key = correlation.correlation_key
                
                # Extract info from related logs
                if not correlation.sender and related_log.sender:
                    correlation.sender = related_log.sender
                if not correlation.recipient and related_log.recipient:
                    correlation.recipient = related_log.recipient
                
                # Update status from related logs
                if related_log.status:
                    if related_log.status in ['bounced', 'rejected']:
                        correlation.final_status = related_log.status
                    elif related_log.status == 'deferred' and correlation.final_status not in ['bounced', 'rejected']:
                        correlation.final_status = related_log.status
                    elif related_log.status == 'sent' and not correlation.final_status:
                        correlation.final_status = 'delivered'
                    elif related_log.status == 'spam':
                        # Priority: bounced > rejected > spam > delivered
                        if correlation.final_status not in ['bounced', 'rejected']:
                            correlation.final_status = 'spam'

            
            correlation.postfix_log_ids = current_ids
    
    # Check if email was delivered locally (relay=dovecot + both sender and recipient are local domains)
    # This is the definitive way to determine if email is internal
    if postfix_log.relay and 'dovecot' in postfix_log.relay.lower():
        # Check if sender and recipient are both local domains
        sender_domain = extract_domain(correlation.sender or postfix_log.sender)
        recipient_domain = extract_domain(correlation.recipient or postfix_log.recipient)
        
        sender_is_local = sender_domain and is_local_domain(sender_domain)
        recipient_is_local = recipient_domain and is_local_domain(recipient_domain)
        
        # Internal needs local sender, local recipient AND a local origin - a
        # hosted sender domain arriving from an outside relay is inbound
        if sender_is_local and recipient_is_local:
            rspamd_log = None
            if correlation.rspamd_log_id:
                rspamd_log = db.query(RspamdLog).filter(
                    RspamdLog.id == correlation.rspamd_log_id
                ).first()
            if origin_is_local(rspamd_log):
                correlation.direction = 'internal'
                if rspamd_log:
                    rspamd_log.direction = 'internal'
    
    # Update final status based on current Postfix log status
    # Priority: bounced > rejected > deferred > sent
    if postfix_log.status:
        if postfix_log.status in ['bounced', 'rejected']:
            correlation.final_status = postfix_log.status
        elif postfix_log.status == 'deferred' and correlation.final_status not in ['bounced', 'rejected']:
            correlation.final_status = postfix_log.status
        elif postfix_log.status == 'sent' and not correlation.final_status:
            correlation.final_status = 'delivered'
        elif postfix_log.status == 'spam':
            # Priority: bounced > rejected > spam > delivered
            if correlation.final_status not in ['bounced', 'rejected']:
                correlation.final_status = 'spam'
                # Mark Rspamd log as spam as well
                if correlation.rspamd_log_id:
                    rspamd_log = db.query(RspamdLog).filter(
                        RspamdLog.id == correlation.rspamd_log_id
                    ).first()
                    if rspamd_log:
                        rspamd_log.is_spam = True

    
    # Mark as complete if we now have Queue-ID and Postfix logs
    if correlation.queue_id and correlation.postfix_log_ids:
        correlation.is_complete = True
    
    correlation.last_seen = datetime.utcnow()
    db.commit()


def update_correlation_with_postfix_logs(
    db: Session,
    correlation: MessageCorrelation,
    postfix_logs: List[PostfixLog]
):
    """
    Update correlation with multiple Postfix logs

    Args:
        db: Database session
        correlation: MessageCorrelation object
        postfix_logs: The PostfixLog objects of this message alone (its own
            occurrence of the queue id, see occurrence_for)
    """
    # Collect all IDs (use list() to ensure mutable copy)
    current_ids = list(correlation.postfix_log_ids or [])
    for plog in postfix_logs:
        if plog.id and plog.id not in current_ids:
            current_ids.append(plog.id)

    correlation.postfix_log_ids = current_ids

    # The message was first seen at its earliest line: a line stored after the
    # correlation was made (an smtpd "client=" line read later) moves it back
    times = [naive_utc(plog.time) for plog in postfix_logs if plog.time]
    if times and (correlation.first_seen is None or min(times) < naive_utc(correlation.first_seen)):
        correlation.first_seen = min(times)
    
    # Update fields from logs
    for plog in postfix_logs:
        if not correlation.sender and plog.sender:
            correlation.sender = plog.sender
        
        if not correlation.recipient and plog.recipient:
            correlation.recipient = plog.recipient
        
        if not correlation.queue_id and plog.queue_id:
            correlation.queue_id = plog.queue_id
        
        if not correlation.message_id and plog.message_id:
            correlation.message_id = plog.message_id
        
        # Update correlation key in Postfix log
        plog.correlation_key = correlation.correlation_key
    
    # Check if email was delivered locally (relay=dovecot + both sender and recipient are local domains)
    # This is the definitive way to determine if email is internal
    is_internal = False
    
    # Check if sender and recipient are both local domains
    sender_domain = extract_domain(correlation.sender)
    recipient_domain = extract_domain(correlation.recipient)
    
    sender_is_local = sender_domain and is_local_domain(sender_domain)
    recipient_is_local = recipient_domain and is_local_domain(recipient_domain)
    
    # Only mark as internal if: relay=dovecot AND sender is local AND recipient is local
    if sender_is_local and recipient_is_local:
        for plog in postfix_logs:
            if plog.relay and 'dovecot' in plog.relay.lower():
                is_internal = True
                break
    
    # Update direction to internal if all conditions met, including a local
    # origin - a hosted sender domain arriving from an outside relay is inbound
    if is_internal:
        rspamd_log = None
        if correlation.rspamd_log_id:
            rspamd_log = db.query(RspamdLog).filter(
                RspamdLog.id == correlation.rspamd_log_id
            ).first()
        if origin_is_local(rspamd_log):
            correlation.direction = 'internal'
            if rspamd_log:
                rspamd_log.direction = 'internal'
    
    # Determine final status from all logs
    final_status = None
    for plog in postfix_logs:
        if plog.status:
            if plog.status in ['bounced', 'rejected']:
                final_status = plog.status
                break
            elif plog.status == 'deferred' and not final_status:
                final_status = plog.status
            elif plog.status == 'sent' and final_status in (None, 'deferred'):
                # A delivery after deferrals, whatever order the lines come in
                final_status = 'delivered'
            elif plog.status == 'spam':
                 if final_status not in ['bounced', 'rejected']:
                    final_status = 'spam'
                    # Mark Rspamd log as spam as well
                    if correlation.rspamd_log_id:
                        rspamd_log = db.query(RspamdLog).filter(
                            RspamdLog.id == correlation.rspamd_log_id
                        ).first()
                        if rspamd_log:
                            rspamd_log.is_spam = True

    
    if final_status:
        correlation.final_status = final_status
    
    # Mark as complete if we have Queue-ID and Postfix logs
    if correlation.queue_id and correlation.postfix_log_ids:
        correlation.is_complete = True
    
    correlation.last_seen = datetime.utcnow()
    db.commit()


def complete_incomplete_correlations(db: Session) -> int:
    """
    Background job to complete correlations that don't have Postfix logs yet
    
    This handles the timing issue where Rspamd logs arrive before Postfix logs:
    1. Find correlations with Message-ID but no Queue-ID (incomplete)
    2. Search for Postfix logs with matching Message-ID
    3. If found, get Queue-ID and find all related Postfix logs
    4. Update correlation and mark as complete
    
    Returns:
        Number of correlations completed
    """
    logger.info("Starting background job to complete incomplete correlations...")
    
    try:
        # Find incomplete correlations (have Message-ID but missing Queue-ID or no Postfix logs)
        incomplete_correlations = db.query(MessageCorrelation).filter(
            MessageCorrelation.is_complete == False,
            MessageCorrelation.message_id.isnot(None),
            MessageCorrelation.message_id != ''
        ).limit(100).all()  # Process 100 at a time to avoid overload
        
        if not incomplete_correlations:
            logger.debug("No incomplete correlations found")
            return 0
        
        logger.info(f"Found {len(incomplete_correlations)} incomplete correlations to process")
        
        completed_count = 0
        
        for correlation in incomplete_correlations:
            try:
                message_id = correlation.message_id

                # A leg that already owns a queue chain completes from that
                # chain and no other; only a stub is free to adopt one, and
                # then only a chain no other leg has claimed (issue #36).
                queue_id = correlation.queue_id

                if not queue_id:
                    postfix_logs_with_msgid = db.query(PostfixLog).filter(
                        PostfixLog.message_id == message_id
                    ).all()

                    if not postfix_logs_with_msgid:
                        logger.debug(f"No Postfix logs yet for Message-ID: {message_id[:50]}")
                        continue

                    chains = group_postfix_logs_by_queue(postfix_logs_with_msgid)
                    claimed = {
                        leg.queue_id for leg in find_legs(db, message_id)
                        if leg.queue_id
                    }
                    queue_id = next((q for q in chains if q not in claimed), None)

                if not queue_id:
                    logger.debug(f"No unclaimed Queue-ID for Message-ID: {message_id[:50]}")
                    continue
                
                logger.info(f"Completing correlation: Message-ID {message_id[:50]} => Queue-ID {queue_id}")
                
                # This message's lines of the queue id, not those of another
                # message that used the id before or after it
                occurrence = own_occurrence(
                    db, queue_id, message_id, near=correlation.first_seen)
                if occurrence is None:
                    logger.debug(f"Queue-ID {queue_id} cannot tell which lines are {message_id[:50]}")
                    continue
                all_postfix_logs = occurrence.lines

                # Update correlation with all Postfix data
                update_correlation_with_postfix_logs(db, correlation, all_postfix_logs)
                
                # Update correlation fields
                if not correlation.queue_id:
                    correlation.queue_id = queue_id
                
                # Mark as complete
                correlation.is_complete = True
                correlation.last_seen = datetime.utcnow()
                
                db.commit()
                completed_count += 1
                
                logger.info(f"[OK] Completed correlation for Message-ID {message_id[:50]} "
                           f"(Queue: {queue_id}, {len(all_postfix_logs)} Postfix logs)")
                
            except Exception as e:
                logger.error(f"Error completing correlation {correlation.id}: {e}")
                db.rollback()
                continue
        
        logger.info(f"Background completion job finished: {completed_count} correlations completed")
        return completed_count
        
    except Exception as e:
        logger.error(f"Error in complete_incomplete_correlations: {e}")
        return 0