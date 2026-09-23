"""Message correlation lifecycle and late-delivery reconciliation.

The scheduler supplies session factories, clocks, current policy values and
status callbacks. This module owns synchronous correlation work only; it does
not initialize schedulers, create executors or import request handlers.
"""
import logging
from datetime import timedelta, timezone
from typing import Optional

from sqlalchemy import case, desc, or_
from sqlalchemy.orm import Session

from ..models import MessageCorrelation, PostfixLog, RspamdLog
from ..correlation import (
    build_correlation_key,
    ensure_leg,
    find_legs,
    find_stub_leg,
    group_postfix_logs_by_queue,
    nearest_queue_chain,
)

logger = logging.getLogger(__name__)


# The statuses a correlation never moves away from once it has them.
# 'discarded' is terminal in the same sense: Dovecot already dropped the
# message via Sieve, and a later Postfix 'sent' line must not resurrect it.
TERMINAL_FINAL_STATUSES = ('delivered', 'bounced', 'rejected', 'discarded', 'expired')

# The push path additionally refuses to touch a spam verdict. routers/stats.py
# counts final_status 'spam' as blocked mail, and a late delivery line would
# otherwise overwrite it and quietly deflate that number.
PUSH_SKIP_FINAL_STATUSES = TERMINAL_FINAL_STATUSES + ('spam',)

# Postfix gives up on a queue after maximal_queue_lifetime (5 days by default),
# so a genuine retry cannot arrive later than that. A queue id that matches an
# older correlation is far more likely to be a reused short id.
LATE_STATUS_MAX_CORRELATION_AGE = timedelta(days=5)

# Postfix statuses worth reacting to on arrival. Anything else carries no
# outcome, so pushing on it would be pure overhead.
PUSH_TRIGGER_STATUSES = ('sent', 'bounced', 'deferred')


def run_correlation(*, get_db_context, is_blacklisted, correlate):
    """Create message correlations with a session owned by the worker."""
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
                    if is_blacklisted(rspamd_log.sender_smtp):
                        rspamd_log.correlation_key = "BLACKLISTED"
                        db.commit()
                        skipped_blacklist += 1
                        continue

                    if rspamd_log.recipients_smtp:
                        recipients = rspamd_log.recipients_smtp
                        if any(is_blacklisted(r) for r in recipients):
                            rspamd_log.correlation_key = "BLACKLISTED"
                            db.commit()
                            skipped_blacklist += 1
                            continue

                    result = correlate(db, rspamd_log)
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


def correlate_single_message(db: Session, rspamd_log: RspamdLog, *, clock) -> Optional[MessageCorrelation]:
    """
    Correlate a single Rspamd log with Postfix logs.

    Steps:
    1. Find Postfix logs with the same message_id and split them into queue
       chains - each chain is a delivery leg of its own (issue #36)
    2. Give every leg a correlation, so a forward or any other re-submission
       never overwrites the delivery it came from
    3. Attach this Rspamd verdict to the leg nearest to it in time: every
       re-submission passes Rspamd separately, seconds from its own chain
    4. With no Postfix log yet, keep one queue-less correlation that adopts
       the first chain to arrive
    """
    message_id = rspamd_log.message_id
    if not message_id:
        return None

    # Steps 1-3: one correlation per queue chain
    postfix_with_msgid = db.query(PostfixLog).filter(
        PostfixLog.message_id == message_id
    ).all()
    chains = group_postfix_logs_by_queue(postfix_with_msgid)

    if chains:
        target_queue = nearest_queue_chain(chains, rspamd_log.time)
        correlation = None

        for queue_id in chains:
            # The whole chain, including the lines that do not repeat the
            # Message-ID (Postfix only logs it once per queue id)
            chain_logs = db.query(PostfixLog).filter(
                PostfixLog.queue_id == queue_id
            ).all() or chains[queue_id]

            leg = ensure_leg(
                db, message_id, queue_id, chain_logs,
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

    # Step 4: no queue chain known yet - reuse the waiting correlation
    existing = find_stub_leg(db, message_id)
    if not existing:
        legs = find_legs(db, message_id)
        existing = legs[0] if legs else None

    if existing:
        rspamd_log.correlation_key = existing.correlation_key
        if not existing.rspamd_log_id:
            existing.rspamd_log_id = rspamd_log.id
            existing.last_seen = clock.now(timezone.utc)
        db.commit()
        return existing

    correlation_key = build_correlation_key(db, message_id, None)
    if not correlation_key:
        return None

    # Get recipient
    recipients = rspamd_log.recipients_smtp or []
    first_recipient = recipients[0] if recipients else None

    # Without Postfix logs the Rspamd action is the only verdict there is
    final_status = None
    if rspamd_log.action == 'reject':
        final_status = 'rejected'
    elif rspamd_log.is_spam:
        final_status = 'spam'

    # Get earliest timestamp (ensure timezone-aware)
    now = clock.now(timezone.utc)
    first_seen = rspamd_log.time
    if first_seen and first_seen.tzinfo is None:
        first_seen = first_seen.replace(tzinfo=timezone.utc)
    if not first_seen:
        first_seen = now

    try:
        # Create correlation
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
        db.flush()  # Try to insert - will fail if the key was just taken

        # Update rspamd log with correlation key
        rspamd_log.correlation_key = correlation_key

        db.commit()

        logger.debug(f"Created correlation for {message_id[:40]}... (no Postfix logs yet)")
        return correlation

    except Exception as e:
        # Handle race condition - another process created the correlation
        db.rollback()

        # Try to find and return the existing one
        existing = find_stub_leg(db, message_id)
        if not existing:
            legs = find_legs(db, message_id)
            existing = legs[0] if legs else None

        if existing:
            rspamd_log.correlation_key = existing.correlation_key
            db.commit()
            return existing

        # Re-raise if it's a different error
        raise


def complete_incomplete_correlations(*, get_db_context, update_job_status, max_age_minutes: int, clock):
    """
    Complete correlations that are missing Postfix logs.

    This handles the case where rspamd was processed before postfix logs arrived.
    """
    update_job_status('complete_correlations', 'running')
    try:
        with get_db_context() as db:
            # Find incomplete correlations (have message_id but missing queue_id or postfix logs)
            # Use naive datetime for comparison since DB stores naive UTC
            cutoff_time = clock.utcnow() - timedelta(
                minutes=max_age_minutes
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

            for correlation in incomplete:
                try:
                    # A leg that already owns a queue chain completes from that
                    # chain and no other; only a queue-less correlation may
                    # adopt one, and then only a chain no other leg of the same
                    # message has claimed (issue #36).
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

                    # Find ALL Postfix logs with this queue_id
                    all_postfix = db.query(PostfixLog).filter(
                        PostfixLog.queue_id == queue_id
                    ).all()

                    # Update correlation
                    correlation.queue_id = queue_id
                    correlation.postfix_log_ids = [plog.id for plog in all_postfix]
                    correlation.is_complete = True
                    correlation.last_seen = clock.now(timezone.utc)

                    # Update final status. A 'discarded' verdict from Dovecot is kept:
                    # Postfix logs status=sent for a message Sieve then drops,
                    # so only a real bounce/reject may override it (issue #65).
                    for plog in all_postfix:
                        if plog.status:
                            if plog.status in ['bounced', 'rejected']:
                                correlation.final_status = plog.status
                                break
                            elif plog.status == 'deferred' and correlation.final_status not in ['bounced', 'rejected', 'discarded'] and correlation.dovecot_status != 'discarded':
                                correlation.final_status = plog.status
                            elif plog.status == 'sent' and not correlation.final_status and correlation.dovecot_status != 'discarded':
                                correlation.final_status = 'delivered'

                    # Update correlation key in Postfix logs
                    for plog in all_postfix:
                        plog.correlation_key = correlation.correlation_key

                    completed_count += 1

                except Exception as e:
                    logger.warning(f"Failed to complete correlation {correlation.id}: {e}")
                    continue

            db.commit()

            if completed_count > 0:
                logger.info(f"[OK] Completed {completed_count} correlations")

            update_job_status('complete_correlations', 'success')

    except Exception as e:
        logger.error(f"[ERROR] Complete correlations error: {e}")
        update_job_status('complete_correlations', 'failed', str(e))


def expire_old_correlations(*, get_db_context, update_job_status, max_age_minutes: int, clock):
    """
    SEPARATE JOB: Mark old incomplete correlations as "expired".

    This runs independently to ensure old incomplete correlations get expired even if
    the complete_incomplete_correlations job has issues.

    Only marks incomplete correlations (is_complete == False) as expired.
    Complete correlations with non-final statuses (None, 'deferred', etc.) are left as-is,
    as they may have legitimate statuses that don't need to be changed.

    Uses clock.utcnow() (naive) to match the naive datetime in created_at.
    """
    update_job_status('expire_correlations', 'running')
    try:
        with get_db_context() as db:
            # Use naive datetime for comparison (DB stores naive UTC)
            old_cutoff = clock.utcnow() - timedelta(
                minutes=max_age_minutes
            )

            # Update in the database without loading every matching correlation.
            # Preserve a Dovecot discard while completing its tracking work.
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
                logger.info(f"[EXPIRED] Completed tracking for {completed_count} old correlations (older than {max_age_minutes}min), preserving discard outcomes")

            update_job_status('expire_correlations', 'success')

    except Exception as e:
        logger.error(f"[ERROR] Expire correlations error: {e}")
        update_job_status('expire_correlations', 'failed', str(e))


def recompute_correlation_from_postfix(db: Session, correlation: MessageCorrelation, *, clock) -> bool:
    """Re-derive final_status and postfix_log_ids for one correlation from every
    Postfix log sharing its queue_id. Returns True when something was written.

    Does not commit; the caller owns the transaction.
    """
    # Without this guard a correlation with no queue_id turns the filter below into
    # "queue_id IS NULL", which matches the majority of postfix_logs (617,987 of
    # 1,122,822 rows on a real instance) and would stamp one correlation_key across
    # all of them. The poller avoids it with a filter; the helper must not rely on
    # every future caller remembering that.
    if not correlation.queue_id:
        return False

    all_postfix = db.query(PostfixLog).filter(
        PostfixLog.queue_id == correlation.queue_id
    ).all()

    if not all_postfix:
        return False

    # Determine best final status from all Postfix logs
    # Priority: bounced > rejected > sent (delivered) > deferred
    new_final_status = correlation.final_status

    for plog in all_postfix:
        if plog.status:
            if plog.status in ['bounced', 'rejected']:
                new_final_status = plog.status
                break  # Highest priority, stop here
            elif plog.status == 'sent':
                # 'sent' (delivered) is better than 'deferred' or None
                if new_final_status not in ['bounced', 'rejected', 'delivered']:
                    new_final_status = 'delivered'
            elif plog.status == 'deferred' and new_final_status not in ['bounced', 'rejected', 'delivered']:
                new_final_status = 'deferred'

    # A Sieve discard is invisible from Postfix's side: Dovecot answers 2xx and
    # then drops the message, so Postfix truthfully logs status=sent. Keep the
    # Dovecot verdict in that case (issue #65). A genuine bounce or reject means
    # the delivery itself failed and must still win.
    if correlation.dovecot_status == 'discarded' and new_final_status == 'delivered':
        new_final_status = 'discarded'

    # Add any Postfix logs this correlation does not know about yet
    current_ids = list(correlation.postfix_log_ids or [])
    ids_added = 0
    for plog in all_postfix:
        if plog.id and plog.id not in current_ids:
            current_ids.append(plog.id)
            ids_added += 1

    if ids_added > 0:
        correlation.postfix_log_ids = current_ids

    # Point every Postfix log of this queue at the correlation
    for plog in all_postfix:
        if not plog.correlation_key or plog.correlation_key != correlation.correlation_key:
            plog.correlation_key = correlation.correlation_key

    if (new_final_status and new_final_status != correlation.final_status) or ids_added > 0:
        old_status = correlation.final_status
        correlation.final_status = new_final_status
        correlation.last_seen = clock.now(timezone.utc)
        logger.debug(
            f"Recomputed correlation {correlation.id} from queue {correlation.queue_id}: "
            f"{old_status} -> {new_final_status}, {ids_added} log ids added"
        )
        return True

    return False


def refresh_correlations_for_queue_ids(db: Session, queue_ids, *, recompute, clock) -> tuple:
    """Re-derive the status of the correlations behind the given Postfix queue ids.

    Called right after a page of Postfix logs is stored, so the work follows the
    log lines that actually arrived instead of re-polling every open correlation
    on a timer. That is what lets a delivery which succeeds long after the
    correlation age window still be recorded.

    Returns (updated, skipped). Does not commit; the caller owns the transaction.
    """
    queue_ids = [q for q in set(queue_ids or []) if q]
    if not queue_ids:
        return (0, 0)

    updated = 0
    skipped = 0
    horizon = clock.utcnow() - LATE_STATUS_MAX_CORRELATION_AGE

    # Chunked so a large page cannot build an unbounded IN clause
    for start in range(0, len(queue_ids), 500):
        chunk = queue_ids[start:start + 500]
        rows = db.query(MessageCorrelation).filter(
            MessageCorrelation.queue_id.in_(chunk)
        ).all()

        by_queue = {}
        for row in rows:
            by_queue.setdefault(row.queue_id, []).append(row)

        for queue_id, correlations in by_queue.items():
            # A queue id shared by two correlations is ambiguous: Postfix reuses
            # short queue ids, so we cannot tell which message the new line
            # belongs to. Guessing would rewrite an unrelated message's status.
            if len(correlations) > 1:
                skipped += len(correlations)
                logger.warning(
                    f"[STATUS] Queue {queue_id} maps to {len(correlations)} correlations - "
                    "not attributing the new log line to either"
                )
                continue

            correlation = correlations[0]

            if correlation.final_status in PUSH_SKIP_FINAL_STATUSES:
                continue

            if correlation.created_at and correlation.created_at < horizon:
                skipped += 1
                continue

            if recompute(db, correlation):
                updated += 1

    return (updated, skipped)


def update_final_status_for_correlations(*, get_db_context, update_job_status, max_age_minutes: int, recompute, clock):
    """
    Background job to update final_status for correlations that don't have one yet.

    This handles the case where Postfix logs (especially status=sent) arrive after
    the initial correlation was created. The job:
    1. Finds correlations without a definitive final_status
    2. Only checks correlations within Max Correlation Age
    3. Looks for new Postfix logs that may have arrived
    4. Updates final_status, postfix_log_ids, and correlation_key

    This runs independently from correlation creation to ensure we catch
    late-arriving Postfix logs.
    """
    update_job_status('update_final_status', 'running')
    try:
        with get_db_context() as db:
            # Only check correlations within Max Correlation Age
            cutoff_time = clock.utcnow() - timedelta(
                minutes=max_age_minutes
            )

            # Find correlations that:
            # 1. Are within the correlation age limit
            # 2. Have a queue_id (so we can check Postfix logs)
            # 3. Don't have a definitive final_status yet
            #    We exclude 'delivered', 'bounced', 'rejected', 'expired' as these are final
            #    We check None, 'deferred', 'spam', and other non-final statuses
            correlations_to_check = db.query(MessageCorrelation).filter(
                MessageCorrelation.created_at >= cutoff_time,
                MessageCorrelation.queue_id.isnot(None),
                or_(
                    MessageCorrelation.final_status.is_(None),
                    MessageCorrelation.final_status.notin_(TERMINAL_FINAL_STATUSES)
                )
            ).limit(500).all()  # Increased from 100 to 500

            if not correlations_to_check:
                update_job_status('update_final_status', 'success')
                return

            updated_count = 0

            for correlation in correlations_to_check:
                try:
                    if recompute(db, correlation):
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
