import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import case, desc, or_
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db_context
from ..models import MessageCorrelation, PostfixLog, RspamdLog
from ..correlation import (
    build_correlation_key,
    derive_final_status,
    ensure_leg,
    find_legs,
    find_stub_leg,
    group_postfix_logs_by_queue,
    identified_by_message_id,
    naive_utc,
    nearest_queue_chain,
    owners_of_queue,
    own_occurrence,
    queue_occurrences,
    settle_queue,
    split_queue_occurrences,
)
from . import written_recipients
from .excluded_addresses import is_listed
from .job_status import update_job_status

logger = logging.getLogger(__name__)


TERMINAL_FINAL_STATUSES = ('delivered', 'bounced', 'rejected', 'discarded', 'expired')

LATE_STATUS_MAX_CORRELATION_AGE = timedelta(days=5)


def run_correlation():
    try:
        with get_db_context() as db:
            uncorrelated_rspamd = db.query(RspamdLog).filter(
                RspamdLog.correlation_key.is_(None),
                RspamdLog.message_id.isnot(None),
                RspamdLog.message_id != '',
                RspamdLog.message_id != 'undef'
            ).order_by(desc(RspamdLog.time)).limit(100).all()

            if not uncorrelated_rspamd:
                return

            correlated_count = 0
            skipped_blacklist = 0

            for rspamd_log in uncorrelated_rspamd:
                try:
                    if is_listed(rspamd_log.sender_smtp):
                        rspamd_log.correlation_key = "BLACKLISTED"
                        db.commit()
                        skipped_blacklist += 1
                        continue

                    if rspamd_log.recipients_smtp:
                        recipients = rspamd_log.recipients_smtp
                        if any(is_listed(r) for r in recipients):
                            rspamd_log.correlation_key = "BLACKLISTED"
                            db.commit()
                            skipped_blacklist += 1
                            continue

                    result = correlate_single_message(db, rspamd_log)
                    if result:
                        correlated_count += 1
                except Exception as e:
                    logger.warning(f"Correlation failed for rspamd {rspamd_log.id}: {e}")
                    db.rollback()
                    continue

            if correlated_count > 0:
                logger.info(f"[LINK] Correlated {correlated_count} messages")
            if skipped_blacklist > 0:
                logger.info(f"[INFO] Skipped {skipped_blacklist} blacklisted messages")

    except Exception as e:
        logger.error(f"[ERROR] Correlation job error: {e}")


def correlate_single_message(db: Session, rspamd_log: RspamdLog) -> Optional[MessageCorrelation]:
    message_id = rspamd_log.message_id
    if not message_id:
        return None

    postfix_with_msgid = db.query(PostfixLog).filter(
        PostfixLog.message_id == message_id
    ).all()
    chains = group_postfix_logs_by_queue(postfix_with_msgid)

    if chains:
        target_queue = nearest_queue_chain(chains, rspamd_log.time)
        correlation = None

        for queue_id in chains:
            occurrence = own_occurrence(db, queue_id, message_id, near=rspamd_log.time)
            if occurrence is None:
                logger.warning(f"Queue {queue_id} holds Message-ID {message_id[:40]}... more than once - not linked")
                continue

            leg = ensure_leg(
                db, message_id, queue_id, occurrence.lines,
                rspamd_log=rspamd_log if queue_id == target_queue else None
            )
            if queue_id == target_queue:
                correlation = leg

        if correlation:
            rspamd_log.correlation_key = correlation.correlation_key
            if not correlation.rspamd_log_id:
                correlation.rspamd_log_id = rspamd_log.id
            db.commit()
            logger.debug(
                f"Correlated {message_id[:40]}... to queue {target_queue} "
                f"({len(chains)} delivery leg(s))"
            )
        return correlation

    existing = find_stub_leg(db, message_id)
    if not existing:
        legs = find_legs(db, message_id)
        existing = legs[0] if legs else None

    if existing:
        rspamd_log.correlation_key = existing.correlation_key
        if not existing.rspamd_log_id:
            existing.rspamd_log_id = rspamd_log.id
            existing.last_seen = datetime.now(timezone.utc)
        db.commit()
        return existing

    correlation_key = build_correlation_key(db, message_id, None)
    if not correlation_key:
        return None

    recipients = rspamd_log.recipients_smtp or []
    first_recipient = recipients[0] if recipients else None

    final_status = None
    if rspamd_log.action == 'reject':
        final_status = 'rejected'
    elif rspamd_log.is_spam:
        final_status = 'spam'

    now = datetime.now(timezone.utc)
    first_seen = rspamd_log.time
    if first_seen and first_seen.tzinfo is None:
        first_seen = first_seen.replace(tzinfo=timezone.utc)
    if not first_seen:
        first_seen = now

    correlation = MessageCorrelation(
        correlation_key=correlation_key,
        message_id=message_id,
        queue_id=None,
        sender=rspamd_log.sender_smtp,
        recipient=first_recipient,
        subject=rspamd_log.subject,
        direction=rspamd_log.direction,
        final_status=final_status,
        rspamd_log_id=rspamd_log.id,
        postfix_log_ids=[],
        first_seen=first_seen,
        last_seen=now,
        is_complete=False
    )
    db.add(correlation)
    rspamd_log.correlation_key = correlation_key
    db.commit()

    logger.debug(f"Created correlation for {message_id[:40]}... (no Postfix logs yet)")
    return correlation


def _update_final_status(correlation: MessageCorrelation, lines) -> None:
    status = derive_final_status(lines, None, correlation.dovecot_status, correlation.final_status)
    kept_discard = (correlation.final_status == correlation.dovecot_status == 'discarded'
                    and status == 'deferred')
    if status and not kept_discard:
        correlation.final_status = status


def complete_incomplete_correlations():
    update_job_status('complete_correlations', 'running')
    try:
        with get_db_context() as db:
            cutoff_time = datetime.utcnow() - timedelta(
                minutes=settings.max_correlation_age_minutes
            )

            incomplete = db.query(MessageCorrelation).filter(
                MessageCorrelation.is_complete == False,
                MessageCorrelation.message_id.isnot(None),
                MessageCorrelation.created_at >= cutoff_time
            ).limit(100).all()

            if not incomplete:
                update_job_status('complete_correlations', 'success')
                return

            completed_count = 0
            completed = []

            for correlation in incomplete:
                try:
                    queue_id = correlation.queue_id

                    if not queue_id:
                        postfix_with_msgid = db.query(PostfixLog).filter(
                            PostfixLog.message_id == correlation.message_id
                        ).all()

                        if not postfix_with_msgid:
                            continue

                        chains = group_postfix_logs_by_queue(postfix_with_msgid)
                        claimed = {
                            leg.queue_id
                            for leg in find_legs(db, correlation.message_id)
                            if leg.queue_id
                        }
                        queue_id = next((q for q in chains if q not in claimed), None)

                    if not queue_id:
                        continue

                    occurrence = own_occurrence(
                        db, queue_id, correlation.message_id, near=correlation.first_seen)
                    if occurrence is None:
                        continue
                    all_postfix = occurrence.lines

                    correlation.queue_id = queue_id
                    correlation.postfix_log_ids = [plog.id for plog in all_postfix]
                    correlation.is_complete = True
                    correlation.last_seen = datetime.now(timezone.utc)
                    times = [naive_utc(plog.time) for plog in all_postfix if plog.time]
                    if times and (correlation.first_seen is None
                                  or min(times) < naive_utc(correlation.first_seen)):
                        correlation.first_seen = min(times)

                    _update_final_status(correlation, all_postfix)

                    for plog in all_postfix:
                        plog.correlation_key = correlation.correlation_key

                    completed.append(correlation)
                    completed_count += 1

                except Exception as e:
                    logger.warning(f"Failed to complete correlation {correlation.id}: {e}")
                    continue

            db.commit()

            if sum(written_recipients.record(db, correlation) for correlation in completed):
                db.commit()

            if completed_count > 0:
                logger.info(f"[OK] Completed {completed_count} correlations")

            update_job_status('complete_correlations', 'success')

    except Exception as e:
        logger.error(f"[ERROR] Complete correlations error: {e}")
        update_job_status('complete_correlations', 'failed', str(e))


def expire_old_correlations():
    update_job_status('expire_correlations', 'running')
    try:
        with get_db_context() as db:
            old_cutoff = datetime.utcnow() - timedelta(
                minutes=settings.max_correlation_age_minutes
            )

            completed_count = db.query(MessageCorrelation).filter(
                MessageCorrelation.is_complete == False,
                MessageCorrelation.created_at < old_cutoff
            ).update({
                MessageCorrelation.is_complete: True,
                MessageCorrelation.final_status: case(
                    (or_(MessageCorrelation.final_status == 'discarded',
                         MessageCorrelation.dovecot_status == 'discarded'),
                     MessageCorrelation.final_status),
                    else_='expired',
                ),
            }, synchronize_session=False)

            db.commit()

            if completed_count > 0:
                logger.info(f"[EXPIRED] Completed tracking for {completed_count} old correlations (older than {settings.max_correlation_age_minutes}min), preserving discard outcomes")

            update_job_status('expire_correlations', 'success')

    except Exception as e:
        logger.error(f"[ERROR] Expire correlations error: {e}")
        update_job_status('expire_correlations', 'failed', str(e))


def recompute_correlation_from_postfix(db: Session, correlation: MessageCorrelation,
                                       occurrences=None) -> bool:
    if not correlation.queue_id:
        return False

    if occurrences is None:
        occurrences = queue_occurrences(db, correlation.queue_id)
    own = own_occurrence(db, correlation.queue_id, correlation.message_id,
                         near=correlation.first_seen, occurrences=occurrences)
    if own is None:
        return False

    stored = {i for i in (correlation.postfix_log_ids or []) if isinstance(i, int)}
    foreign = {line.id for o in occurrences for line in o.lines + o.boundary if line.id} - own.ids
    if stored & foreign or any(line.correlation_key not in (None, correlation.correlation_key)
                               for line in own.lines):
        correlations = db.query(MessageCorrelation).filter(
            MessageCorrelation.queue_id == correlation.queue_id).all()
        if correlation in settle_queue(db, correlations, occurrences, datetime.now(timezone.utc)):
            return True

    all_postfix = own.lines

    old_status = correlation.final_status
    _update_final_status(correlation, all_postfix)

    current_ids = list(correlation.postfix_log_ids or [])
    ids_added = 0
    for plog in all_postfix:
        if plog.id and plog.id not in current_ids:
            current_ids.append(plog.id)
            ids_added += 1

    if ids_added > 0:
        correlation.postfix_log_ids = current_ids

    for plog in all_postfix:
        if not plog.correlation_key or plog.correlation_key != correlation.correlation_key:
            plog.correlation_key = correlation.correlation_key

    if correlation.final_status != old_status or ids_added > 0:
        correlation.last_seen = datetime.now(timezone.utc)
        logger.debug(
            f"Recomputed correlation {correlation.id} from queue {correlation.queue_id}: "
            f"{old_status} -> {correlation.final_status}, {ids_added} log ids added"
        )
        return True

    return False


def refresh_correlations_for_queue_ids(db: Session, queue_ids) -> tuple:
    queue_ids = [q for q in set(queue_ids or []) if q]
    if not queue_ids:
        return (0, 0)

    updated = 0
    skipped = 0
    horizon = datetime.utcnow() - LATE_STATUS_MAX_CORRELATION_AGE

    for start in range(0, len(queue_ids), 500):
        chunk = queue_ids[start:start + 500]
        rows = db.query(MessageCorrelation).filter(
            MessageCorrelation.queue_id.in_(chunk)
        ).all()

        by_queue = {}
        for row in rows:
            by_queue.setdefault(row.queue_id, []).append(row)
        if not by_queue:
            continue

        lines = {}
        for line in db.query(PostfixLog).filter(PostfixLog.queue_id.in_(list(by_queue))).all():
            lines.setdefault(line.queue_id, []).append(line)

        for queue_id, correlations in by_queue.items():
            occurrences = split_queue_occurrences(lines.get(queue_id, []))
            if not occurrences:
                continue

            repaired = settle_queue(db, correlations, occurrences, datetime.now(timezone.utc))
            updated += len(repaired)
            owned = owners_of_queue(correlations, occurrences)

            for correlation in correlations:
                if correlation in repaired:
                    continue
                occurrence = owned.get(correlation.id)
                identified = identified_by_message_id(occurrence, correlation.message_id)

                if occurrence is None:
                    skipped += 1
                    logger.warning(
                        f"[STATUS] Queue {queue_id} maps to {len(correlations)} correlation(s) and "
                        "its lines do not tell which is this one - not attributing them"
                    )
                    continue

                if correlation.final_status in TERMINAL_FINAL_STATUSES:
                    continue

                if not identified and correlation.created_at and correlation.created_at < horizon:
                    skipped += 1
                    continue

                if recompute_correlation_from_postfix(db, correlation, occurrences=occurrences):
                    updated += 1

    return (updated, skipped)


def update_final_status_for_correlations():
    update_job_status('update_final_status', 'running')
    try:
        with get_db_context() as db:
            cutoff_time = datetime.utcnow() - timedelta(
                minutes=settings.max_correlation_age_minutes
            )

            correlations_to_check = db.query(MessageCorrelation).filter(
                MessageCorrelation.created_at >= cutoff_time,
                MessageCorrelation.queue_id.isnot(None),
                or_(
                    MessageCorrelation.final_status.is_(None),
                    MessageCorrelation.final_status.notin_(TERMINAL_FINAL_STATUSES)
                )
            ).limit(500).all()

            if not correlations_to_check:
                update_job_status('update_final_status', 'success')
                return

            updated_count = 0

            for correlation in correlations_to_check:
                try:
                    if recompute_correlation_from_postfix(db, correlation):
                        updated_count += 1
                except Exception as e:
                    logger.warning(f"Failed to update final_status for correlation {correlation.id}: {e}")
                    continue

            db.commit()

            if updated_count > 0:
                logger.info(f"[STATUS] Updated final_status for {updated_count} correlations")

            update_job_status('update_final_status', 'success')

    except Exception as e:
        logger.error(f"[ERROR] Update final status error: {e}")
        update_job_status('update_final_status', 'failed', str(e))
