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
    return exists().where(RspamdLog.id == MessageCorrelation.rspamd_log_id, _authenticated_scan())


def _authenticated_scan():
    return or_(
        RspamdLog.has_auth.is_(True),
        and_(RspamdLog.user.isnot(None), RspamdLog.user != '', RspamdLog.user != 'unknown'),
    )


def authenticated_submissions(query):
    return query.select_from(MessageCorrelation).join(
        RspamdLog, RspamdLog.id == MessageCorrelation.rspamd_log_id
    ).filter(_authenticated_scan())


def submitting_mailbox():
    login = func.nullif(func.nullif(func.trim(RspamdLog.user), literal_column("''")),
                        literal_column("'unknown'"))
    return func.lower(func.coalesce(login, MessageCorrelation.sender))


def extract_domain(email: str) -> Optional[str]:
    if not email or '@' not in email:
        return None
    return email.split('@', 1)[1].lower().strip()


def is_local_domain(domain: Optional[str]) -> bool:
    if not domain:
        return False
    local_domains = settings.local_domains_list
    if not local_domains:
        return False
    return domain.lower() in [d.lower() for d in local_domains]


def detect_direction(rspamd_log: Dict[str, Any]) -> str:
    symbols = rspamd_log.get('symbols', {})
    if 'MAILCOW_AUTH' in symbols:
        return 'outbound'
    
    user = rspamd_log.get('user', 'unknown')
    if user != 'unknown' and user:
        return 'outbound'
    
    direction = 'inbound' if user == 'unknown' else 'unknown'
    
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


POSTFIX_DELIVERY_AGENTS = ('smtp', 'lmtp', 'local', 'virtual', 'error', 'retry', 'discard', 'pipe')

_PF_ADDR = r'(?:"(?:[^"\\]|\\.)*"|[^>"])*'

_PF_DELIVERY_RE = re.compile(
    r'^[0-9A-F]+: to=<(?P<to>' + _PF_ADDR + r')>, '
    r'(?:orig_to=<(?P<orig_to>' + _PF_ADDR + r')>, )?'
    r'(?P<fields>(?:[a-z_]+=[^,\s<>]*, )*?)'
    r'dsn=(?P<dsn>\d\.\d{1,3}\.\d{1,3}), status=(?P<status>\w+)(?P<reply>.*)$'
)
_PF_FIELD_RE = re.compile(r'([a-z_]+)=([^,\s<>]*), ')
_PF_EXPIRED_RE = re.compile(r'^[0-9A-F]+: from=<' + _PF_ADDR + r'>, status=(?P<status>expired)\b')
_PF_MESSAGE_ID_RE = re.compile(r'^[0-9A-F]+: message-id=<([^>]+)>', re.IGNORECASE)


def parse_postfix_message(message: str) -> Dict[str, Any]:
    result = {}

    queue_match = re.match(r'^([A-F0-9]+):', message)
    if queue_match:
        result['queue_id'] = queue_match.group(1)

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

        reply = delivery.group('reply').strip()
        if result['status'] == 'sent' and (
                'rspamd-pipe-spam' in (result.get('relay') or '')
                or (reply.startswith('(delivered ') and 'rspamd-pipe-spam' in reply)):
            result['status'] = 'spam'
            if result.get('orig_to'):
                result['recipient'] = result['orig_to']
        return result

    from_match = re.search(r'from=<([^>]*)>', message)
    if from_match:
        result['sender'] = from_match.group(1) if from_match.group(1) else None

    to_match = re.search(r'to=<([^>]*)>', message)
    if to_match:
        result['recipient'] = to_match.group(1) if to_match.group(1) else None

    expired = _PF_EXPIRED_RE.match(message)
    if expired:
        result['status'] = expired.group('status')

    return result


def legacy_correlation_key(message_id: str) -> str:
    return hashlib.sha256(f"msgid:{message_id}".encode()).hexdigest()


def leg_correlation_key(message_id: str, queue_id: str) -> str:
    return hashlib.sha256(f"msgid:{message_id}:queue:{queue_id}".encode()).hexdigest()


def build_correlation_key(db: Session, message_id: str, queue_id: Optional[str]) -> Optional[str]:
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
    if not message_id:
        return []
    return db.query(MessageCorrelation).filter(
        MessageCorrelation.message_id == message_id
    ).order_by(MessageCorrelation.id).all()


def find_stub_leg(db: Session, message_id: str) -> Optional[MessageCorrelation]:
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


OPENER = 'opener'
RECEIPT = 'receipt'
END = 'end'
DELIVERY = 'delivery'

_RECEIPT_PROGRAMS = ('smtpd', 'qmqpd', 'pickup', 'cleanup')


def postfix_line_kind(line) -> str:
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
    if value is not None and value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _line_order(line):
    return (naive_utc(line.time) or datetime.min, line.id or 0)


class QueueOccurrence:
    def __init__(self, opened_at: datetime):
        self.opened_at = opened_at
        self.lines: List[PostfixLog] = []
        self.boundary: List[PostfixLog] = []
        self.ended = False
        self.delivered = False

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
        return sorted(self.lines + self.boundary, key=_line_order)

    def span(self):
        times = [naive_utc(line.time) for line in self.lines + self.boundary if line.time]
        return (min(times), max(times)) if times else (self.opened_at, self.opened_at)


def split_queue_occurrences(lines) -> List[QueueOccurrence]:
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
    if not queue_id:
        return []
    return split_queue_occurrences(
        db.query(PostfixLog).filter(PostfixLog.queue_id == queue_id).all())


def own_occurrence(db: Session, queue_id: Optional[str], message_id: Optional[str],
                   near: Optional[datetime] = None, occurrences=None) -> Optional[QueueOccurrence]:
    if occurrences is None:
        occurrences = queue_occurrences(db, queue_id)
    occurrence = occurrence_for(occurrences, message_id, near=near)
    others = (occurrence.message_ids - {message_id}) if occurrence is not None else set()
    if others:
        db.flush()
    if others and db.query(MessageCorrelation.id).filter(
            MessageCorrelation.queue_id == queue_id, MessageCorrelation.message_id.in_(others)).first():
        return None
    return occurrence


def shown_postfix_lines(db: Session, correlation) -> List[PostfixLog]:
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
    symbols = rspamd_log.symbols if isinstance(rspamd_log.symbols, dict) else {}
    return rspamd_log.action in ('reject', 'add header', 'rewrite subject') or 'SPAM_TRAP' in symbols


def derive_final_status(lines, rspamd_log, dovecot_status, stored_status) -> Optional[str]:
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
    own = occurrence.ids
    others = {line.id for o in occurrences for line in o.lines + o.boundary if line.id} - own
    stored = {i for i in (correlation.postfix_log_ids or []) if isinstance(i, int)}
    if stored & others:
        return True
    return any(line.correlation_key and line.correlation_key != correlation.correlation_key
               and line.correlation_key in queue_keys for line in occurrence.lines)


def repair_from_occurrence(db: Session, correlation, occurrence: QueueOccurrence,
                           occurrences: List[QueueOccurrence], now: datetime) -> None:
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
    leg = find_leg_by_queue(db, queue_id, message_id)

    if not leg:
        leg = find_stub_leg(db, message_id)
        if leg:
            logger.debug(f"Stub for {message_id[:50]} adopts queue chain {queue_id}")
            leg.queue_id = queue_id

    from .services.written_recipients import record as record_written

    if leg:
        if rspamd_log:
            update_correlation_with_rspamd(db, leg, rspamd_log)
        update_correlation_with_postfix_logs(db, leg, postfix_logs)
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


def create_correlation_with_all_data(
    db: Session,
    rspamd_log: RspamdLog,
    postfix_logs: List[PostfixLog],
    message_id: str,
    queue_id: str
) -> MessageCorrelation:
    correlation_key = build_correlation_key(db, message_id, queue_id)

    recipients = rspamd_log.recipients_smtp if rspamd_log.recipients_smtp else []
    first_recipient = recipients[0] if recipients else None
    
    postfix_log_ids = [log.id for log in postfix_logs if log.id]
    
    final_status = None
    for plog in postfix_logs:
        if plog.status:
            if plog.status in ['bounced', 'rejected']:
                final_status = plog.status
                break
            elif plog.status == 'deferred' and not final_status:
                final_status = plog.status
            elif plog.status == 'sent' and final_status in (None, 'deferred'):
                final_status = 'delivered'
            elif plog.status == 'spam':
                final_status = 'spam'
                if rspamd_log:
                    rspamd_log.is_spam = True

    
    if not final_status:
        if rspamd_log.action == 'reject':
            final_status = 'rejected'
        elif rspamd_log.is_spam:
            final_status = 'spam'
    
    all_times = [rspamd_log.time] + [log.time for log in postfix_logs]
    first_seen = min(all_times)
    
    direction = rspamd_log.direction
    
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
    
    if sender_is_local and all_recipients_local and origin_is_local(rspamd_log):
        for plog in postfix_logs:
            if plog.relay and 'dovecot' in plog.relay.lower():
                direction = 'internal'
                rspamd_log.direction = 'internal'
                break
    elif direction == 'internal':
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
        is_complete=True
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
            direction = 'outbound' if (rspamd_log.has_auth or (
                rspamd_log.user and rspamd_log.user != 'unknown')) else 'inbound'
            rspamd_log.direction = direction
        correlation.direction = direction
    elif correlation.direction == 'internal' and not origin_is_local(rspamd_log):
        correlation.direction = 'outbound' if (rspamd_log.has_auth or (
            rspamd_log.user and rspamd_log.user != 'unknown')) else 'inbound'
        rspamd_log.direction = correlation.direction

    if rspamd_log.action == 'reject':
        correlation.final_status = 'rejected'
    elif rspamd_log.is_spam and not correlation.final_status:
        correlation.final_status = 'spam'
    
    correlation.last_seen = datetime.utcnow()
    db.commit()


def update_correlation_with_postfix_logs(
    db: Session,
    correlation: MessageCorrelation,
    postfix_logs: List[PostfixLog]
):
    current_ids = list(correlation.postfix_log_ids or [])
    for plog in postfix_logs:
        if plog.id and plog.id not in current_ids:
            current_ids.append(plog.id)

    correlation.postfix_log_ids = current_ids

    times = [naive_utc(plog.time) for plog in postfix_logs if plog.time]
    if times and (correlation.first_seen is None or min(times) < naive_utc(correlation.first_seen)):
        correlation.first_seen = min(times)
    
    for plog in postfix_logs:
        if not correlation.sender and plog.sender:
            correlation.sender = plog.sender
        
        if not correlation.recipient and plog.recipient:
            correlation.recipient = plog.recipient
        
        if not correlation.queue_id and plog.queue_id:
            correlation.queue_id = plog.queue_id
        
        if not correlation.message_id and plog.message_id:
            correlation.message_id = plog.message_id
        
        plog.correlation_key = correlation.correlation_key
    
    is_internal = False
    
    sender_domain = extract_domain(correlation.sender)
    recipient_domain = extract_domain(correlation.recipient)
    
    sender_is_local = sender_domain and is_local_domain(sender_domain)
    recipient_is_local = recipient_domain and is_local_domain(recipient_domain)
    
    if sender_is_local and recipient_is_local:
        for plog in postfix_logs:
            if plog.relay and 'dovecot' in plog.relay.lower():
                is_internal = True
                break
    
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
    
    final_status = None
    for plog in postfix_logs:
        if plog.status:
            if plog.status in ['bounced', 'rejected']:
                final_status = plog.status
                break
            elif plog.status == 'deferred' and not final_status:
                final_status = plog.status
            elif plog.status == 'sent' and final_status in (None, 'deferred'):
                final_status = 'delivered'
            elif plog.status == 'spam':
                 if final_status not in ['bounced', 'rejected']:
                    final_status = 'spam'
                    if correlation.rspamd_log_id:
                        rspamd_log = db.query(RspamdLog).filter(
                            RspamdLog.id == correlation.rspamd_log_id
                        ).first()
                        if rspamd_log:
                            rspamd_log.is_spam = True

    
    if final_status:
        correlation.final_status = final_status
    
    if correlation.queue_id and correlation.postfix_log_ids:
        correlation.is_complete = True
    
    correlation.last_seen = datetime.utcnow()
    db.commit()
