"""Correlation workflows can run without scheduler-owned global dependencies."""
import subprocess
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

from app.services import correlation_jobs


def test_service_import_does_not_initialize_scheduling_or_request_handlers():
    result = subprocess.run(
        [sys.executable, "-c", (
            "import sys; from app.services import correlation_jobs; "
            "assert 'app.scheduler' not in sys.modules; "
            "assert 'app.main' not in sys.modules; "
            "assert not any(n.startswith('app.routers.') for n in sys.modules)"
        )], capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


def test_batch_uses_injected_blacklist_and_record_processor():
    db = Mock()
    rows = [
        SimpleNamespace(id=1, sender_smtp="blocked@example.test", recipients_smtp=[]),
        SimpleNamespace(id=2, sender_smtp="sender@example.test", recipients_smtp=[]),
        SimpleNamespace(id=3, sender_smtp="sender@example.test", recipients_smtp=[]),
    ]
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = rows
    events = []

    @contextmanager
    def database():
        events.append("open")
        try:
            yield db
        finally:
            events.append("close")

    def correlate(session, row):
        assert session is db
        events.append(row.id)
        if row.id == 2:
            raise RuntimeError("fixture record failure")
        return True

    db.rollback.side_effect = lambda: events.append("rollback")
    correlation_jobs.run_correlation(
        get_db_context=database,
        is_blacklisted=lambda address: address == "blocked@example.test",
        correlate=correlate,
    )
    assert rows[0].correlation_key == "BLACKLISTED"
    assert events == ["open", 2, "rollback", 3, "close"]
    db.commit.assert_called_once()


def test_arrival_reconciliation_uses_clock_and_leaves_commit_to_caller():
    from app.models import MessageCorrelation, PostfixLog
    now = datetime(2026, 1, 15)

    def row(number, queue_id, final_status, created_at):
        return SimpleNamespace(id=number, correlation_key=f"key-{number}", message_id=None, queue_id=queue_id,
                               final_status=final_status, created_at=created_at, first_seen=created_at,
                               postfix_log_ids=[number])

    def line(number, queue_id):
        return SimpleNamespace(id=number, queue_id=queue_id, time=now, program="postfix/smtp",
                               message=f"{queue_id}: to=<a@example.test>, status=deferred", message_id=None,
                               status="deferred", correlation_key=None)

    rows = [
        row(1, "RECENT", "deferred", now),
        row(2, "OLD", "deferred", now - timedelta(days=6)),
        row(3, "SPAM", "spam", now),
        row(4, "DUPLICATE", None, now),
        row(5, "DUPLICATE", None, now),
    ]
    lines = [line(1, "RECENT"), line(2, "OLD"), line(3, "SPAM"), line(4, "DUPLICATE"), line(5, "DUPLICATE")]
    db = Mock()
    db.query.side_effect = lambda model: Mock(**{"filter.return_value.all.return_value": {
        MessageCorrelation: rows, PostfixLog: lines}[model]})
    recompute = Mock(return_value=True)
    result = correlation_jobs.refresh_correlations_for_queue_ids(
        db, [row.queue_id for row in rows], recompute=recompute,
        clock=SimpleNamespace(utcnow=lambda: now, now=lambda tz: now),
    )
    assert result == (1, 3)
    recompute.assert_called_once()
    assert recompute.call_args.args == (db, rows[0])
    db.commit.assert_not_called()


def test_failed_expiry_reports_through_injected_status_callback():
    events = []

    @contextmanager
    def database():
        raise RuntimeError("fixture database failure")
        yield

    correlation_jobs.expire_old_correlations(
        get_db_context=database, update_job_status=lambda *event: events.append(event),
        max_age_minutes=7, clock=datetime,
    )
    assert events == [
        ("expire_correlations", "running"),
        ("expire_correlations", "failed", "fixture database failure"),
    ]
