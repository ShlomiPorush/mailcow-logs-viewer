"""
Fill the demo with a week of history and reset it every night.

Every start is a fresh demo: the database is emptied, the fake mailcow
server gets a week of fictional logs, and the application's own jobs ingest
them (fetch, correlation, Dovecot outcomes, mailbox and alias statistics,
suppressions, DNS and blocklist checks) before the scheduler starts. DMARC
and TLS reports go through the regular upload path.

The nightly reset is a restart: at 00:00 in the container's time zone the
process replaces itself (exec), which drops every visitor change, cache and
background state at once and runs this startup again.

The database is only emptied when it is empty or carries the demo's marker
table, so pointing the demo image at a real database cannot wipe it.
"""
import asyncio
import datetime
import logging
import os
import sys
import threading
import time

from sqlalchemy import text

logger = logging.getLogger(__name__)

MARKER_TABLE = "mailcow_logs_viewer_demo"
HISTORY_DAYS = 7
# The fake server keeps more than mailcow's default 9999 lines so the whole
# week fits while the live trickle keeps adding to it
LOG_CAP = 30000


# Features that are off by default but make the demo worth exploring. Stored
# as regular UI overrides, so visitors can still switch them off in Settings.
DEMO_SETTINGS = {
    "suppression_enabled": True,
    "smtp_abuse_enabled": True,
    "anomaly_detection_enabled": True,
    "admin_email": "admin@example.com",
    "blacklist_alert_email": "admin@example.com",
}


class NotADemoDatabase(RuntimeError):
    pass


def prepare_database(engine, schema="public"):
    """Empty the demo database, refusing any database the demo did not create."""
    with engine.begin() as conn:
        tables = set(conn.execute(text(
            "SELECT tablename FROM pg_tables WHERE schemaname = :schema"), {"schema": schema}).scalars())
        if tables and MARKER_TABLE not in tables:
            raise NotADemoDatabase(
                "The demo empties its database on every start, and this database holds tables "
                "the demo did not create. Give the demo an empty database of its own.")
        if tables:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            conn.execute(text(f'CREATE SCHEMA "{schema}"'))
        conn.execute(text(f'CREATE TABLE "{schema}".{MARKER_TABLE} (created_at TIMESTAMPTZ NOT NULL DEFAULT now())'))
        conn.execute(text(f'INSERT INTO "{schema}".{MARKER_TABLE} DEFAULT VALUES'))
    logger.warning("[DEMO] Database emptied for a fresh demo")


def fill_history(fake, now=None, days=HISTORY_DAYS):
    """Put a week of fictional logs in the fake mailcow server."""
    from .traffic import Traffic

    now = int(now or time.time())
    # Stay just inside log retention (7 days by default)
    start = now - days * 86400 + 3600
    traffic = Traffic(seed=now // 86400)
    fake.log_cap = max(fake.log_cap, LOG_CAP)
    for service, entries in traffic.generate(start, now).items():
        fake.push_logs(service, entries)
    counts = {svc: len(buf) for svc, buf in fake.logs.items() if buf}
    logger.warning(f"[DEMO] Generated {days} days of history: {counts}")
    return traffic


async def _step(name, coro_or_func, *args, **kwargs):
    started = time.monotonic()
    try:
        result = coro_or_func(*args, **kwargs)
        if asyncio.iscoroutine(result):
            result = await result
        logger.warning(f"[DEMO] Seed step {name} done in {time.monotonic() - started:.1f}s")
        return result
    except Exception as e:
        logger.error(f"[DEMO] Seed step {name} failed: {e}")
        return None


def _uncorrelated_count():
    from app.database import get_db_context
    from app.models import RspamdLog

    with get_db_context() as db:
        return db.query(RspamdLog).filter(
            RspamdLog.correlation_key.is_(None),
            RspamdLog.message_id.isnot(None),
            RspamdLog.message_id != "",
            RspamdLog.message_id != "undef",
        ).count()


def import_reports(now=None):
    from app.routers.dmarc import _upload_report_worker
    from . import reports

    created = 0
    for filename, content in reports.build(now or time.time(), seed=int(now or time.time()) // 86400):
        try:
            result = _upload_report_worker(content, filename)
            created += result.get("status") == "success"
        except Exception as e:
            logger.error(f"[DEMO] Report {filename} was not imported: {e}")
    return created


def apply_demo_settings():
    from app.config import reload_settings
    from app.database import get_db_context
    from app.services.settings_store import save_config_overrides_to_db

    with get_db_context() as db:
        save_config_overrides_to_db(db, DEMO_SETTINGS)
        reload_settings(db)


async def ingest():
    """Run the application's own jobs over the generated history."""
    from app import scheduler
    from app.raw_logs_worker import fetch_raw_service_logs

    await _step("demo_settings", apply_demo_settings)
    await _step("sync_local_domains", scheduler.sync_local_domains)
    await _step("mailbox_stats", scheduler.update_mailbox_statistics)
    await _step("alias_stats", scheduler.update_alias_statistics)
    await _step("fetch_logs", scheduler.fetch_all_logs)

    # The correlation job takes 100 messages per run
    remaining, rounds = _uncorrelated_count(), 0
    while remaining and rounds < 200:
        await scheduler.run_correlation()
        left = _uncorrelated_count()
        if left >= remaining:
            break
        remaining, rounds = left, rounds + 1
    logger.warning(f"[DEMO] Correlated history in {rounds} rounds, {remaining} left")

    await _step("complete_correlations", scheduler.complete_incomplete_correlations)
    await _step("update_final_status", scheduler.update_final_status_for_correlations)
    for _ in range(3):
        await _step("fetch_raw_logs", fetch_raw_service_logs)
    await _step("correlate_dovecot", scheduler.correlate_dovecot_logs)
    await _step("detect_suppressions", scheduler.detect_suppressions_job)
    await _step("dns_check", scheduler.check_all_domains_dns_background)
    await _step("blacklist_check", scheduler.check_monitored_hosts_job, force=True, send_notification=False)
    await _step("anomaly_detection", scheduler.anomaly_detection_job)
    created = await _step("dmarc_reports", asyncio.to_thread, import_reports)
    logger.warning(f"[DEMO] Imported {created} DMARC and TLS reports")


def run_ingest_blocking():
    """Seed from a worker thread with its own event loop, like a manual job."""
    started = time.monotonic()
    error = []

    def worker():
        try:
            asyncio.run(ingest())
        except Exception as e:  # pragma: no cover - logged, startup continues
            error.append(e)

    thread = threading.Thread(target=worker, name="demo-seed")
    thread.start()
    thread.join()
    if error:
        logger.error(f"[DEMO] Seeding failed: {error[0]}")
    logger.warning(f"[DEMO] Demo ready in {time.monotonic() - started:.0f}s")


LIVE_INTERVAL_SECONDS = 60
# About twelve messages an hour at any time of day, plus connection noise
LIVE_MIN_WEIGHT = 2.0
LIVE_NOISE_PER_MINUTE = 2.0


def start_live_traffic(fake, traffic, interval=LIVE_INTERVAL_SECONDS):
    """Keep mail flowing: every minute the fake server gets that minute's
    traffic, which the scheduler's regular jobs pick up like new logs."""
    def loop():
        last = time.time()
        while True:
            time.sleep(interval)
            now = time.time()
            try:
                batch = traffic.generate(last, now, min_weight=LIVE_MIN_WEIGHT,
                                         noise_per_minute=LIVE_NOISE_PER_MINUTE)
                for service, entries in batch.items():
                    if entries:
                        fake.push_logs(service, entries)
            except Exception as e:
                logger.error(f"[DEMO] Live traffic failed: {e}")
            last = now

    thread = threading.Thread(target=loop, name="demo-live-traffic", daemon=True)
    thread.start()
    return thread


def seconds_until_midnight(now=None):
    """Seconds until the next 00:00 in the process's local time zone (TZ)."""
    now = now if now is not None else time.time()
    local = datetime.datetime.fromtimestamp(now).astimezone()
    tomorrow = (local + datetime.timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    # Normalise across a DST change: rebuild midnight in the zone it falls in
    midnight = datetime.datetime(tomorrow.year, tomorrow.month, tomorrow.day).astimezone()
    return max(midnight.timestamp() - now, 1.0)


def restart_process():
    logger.warning("[DEMO] Nightly reset: restarting with a fresh demo")
    for handler in logging.getLogger().handlers:
        try:
            handler.flush()
        except Exception:
            pass
    os.execv(sys.executable, [sys.executable] + sys.argv)


def schedule_nightly_reset():
    # DEMO_RESET_AFTER_SECONDS exists for tests of the reset itself
    override = os.environ.get("DEMO_RESET_AFTER_SECONDS", "").strip()
    delay = float(override) if override else seconds_until_midnight()
    timer = threading.Timer(delay, restart_process)
    timer.daemon = True
    timer.name = "demo-nightly-reset"
    timer.start()
    at = datetime.datetime.fromtimestamp(time.time() + delay).astimezone()
    logger.warning(f"[DEMO] Next reset at {at:%Y-%m-%d %H:%M %Z}")
    return timer
