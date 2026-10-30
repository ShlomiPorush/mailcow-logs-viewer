"""
Fill the demo with a week of history and reset it every night.

Every start is a fresh demo: the database is emptied, the fake mailcow
server gets a week of fictional logs, and the application's own jobs ingest
them (fetch, correlation, Dovecot outcomes, mailbox and alias statistics,
suppressions, DNS and blocklist checks) before the scheduler starts. DMARC
and TLS reports go through the regular upload path.

The daily reset is a restart: at DEMO_RESET_TIME (00:00 by default) in the
container's time zone the process replaces itself (exec), which drops every
visitor change, cache and background state at once and runs this startup
again.

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
    await _step("eas_devices", scheduler.update_eas_devices)
    await _step("correlate_dovecot", scheduler.correlate_dovecot_logs)
    await _step("detect_suppressions", scheduler.detect_suppressions_job)
    await _step("dns_check", scheduler.check_all_domains_dns_background)
    await _step("blacklist_check", scheduler.check_monitored_hosts_job, force=True, send_notification=False)
    await _step("anomaly_detection", scheduler.anomaly_detection_job)
    created = await _step("dmarc_reports", asyncio.to_thread, import_reports)
    logger.warning(f"[DEMO] Imported {created} DMARC and TLS reports")
    # The figures as they are now, then a fictional week before them for the trends
    await _step("trend_samples", scheduler.trend_samples_job)
    await _step("trend_history", asyncio.to_thread, seed_trend_history)
    await _step("agents", asyncio.to_thread, seed_agents)


def seed_trend_history(days=7):
    """A fictional week of hourly samples ending at each figure as it is now (the
    demo starts with an empty database, and a trend needs a past to show)."""
    import random
    from datetime import timedelta
    from app.database import get_db_context
    from app.models import MetricSnapshot

    rnd = random.Random(int(time.time()) // 86400)
    with get_db_context() as db:
        latest = {}
        for row in db.query(MetricSnapshot).order_by(MetricSnapshot.slot).all():
            latest[row.name] = row
        written = 0
        for name, row in latest.items():
            value = row.value or 0.0
            # Walking back from now: storage a little lower each day, the counts drifting
            # now and then and staying a while
            walk = value
            for hours_back in range(1, days * 24):
                slot = row.slot - timedelta(hours=hours_back)
                if name == 'storage_used':
                    past = max(0.0, value - hours_back * 0.02)
                elif name in ('security_review', 'security_banned'):
                    if rnd.random() < 0.06:
                        walk = max(0.0, walk + rnd.choice((-1, 1)))
                    past = float(walk)
                else:
                    past = value
                db.add(MetricSnapshot(name=name, slot=slot, value=past, of=row.of, as_of=slot + timedelta(minutes=1)))
                written += 1
        db.commit()
    logger.warning(f"[DEMO] Seeded {written} trend samples")
    return written


# Connected agents to look at in Settings > Agents. The demo has no sign-in,
# so no agent can connect to it: these have no tokens and only show the list,
# its activity, Edit and Disconnect. Times are minutes before the start.
DEMO_AGENTS = (
    {"name": "Claude Code", "kind": "device", "ago": 2 * 1440, "days": 30, "used": 6,
     "views": ("messages", "outbound", "security"), "acts": ("security",),
     "calls": (
         (2 * 1440 - 1, "denied", "rest", "GET", "/api/status/summary", 403,
          "This connection does not have View for Dashboard & Status (status:read). "
          "The person who connected you can reconnect you with that permission."),
         (1440, "call", "rest", "GET", "/api/messages", 200, None),
         (40, "call", "rest", "GET", "/api/security-alerts", 200, None),
         (38, "call", "rest", "GET", "/api/logs/netfilter", 200, None),
         (35, "denied", "rest", "PUT", "/api/settings", 403,
          "Not available to agents: only people change settings, because a change could turn off "
          "sign-in or agent limits, or send alerts elsewhere."),
         (6, "call", "rest", "GET", "/api/messages", 200, None),
     )},
    {"name": "Codex", "kind": "dcr", "ago": 6 * 1440, "days": 7, "used": 180,
     "views": ("status", "quarantine", "dmarc", "domains"), "acts": ("quarantine",),
     "before": (("status", "dmarc", "domains"), ()),
     "calls": (
         (6 * 1440 - 2, "call", "read_api", "GET", "/api/dmarc/domains", 200, None),
         (2 * 1440, "changed", None, None, None, None, None),
         (2 * 1440 - 5, "call", "read_api", "GET", "/api/quarantine", 200, None),
         (2 * 1440 - 7, "call", "perform_action", "POST", "/api/quarantine/release", 200, None),
         (180, "call", "read_api", "GET", "/api/status/summary", 200, None),
     )},
    {"name": "Cursor", "kind": "dcr", "ago": 12 * 1440, "days": 30, "used": 3 * 1440, "ended": 1440,
     "views": ("domains",), "acts": (),
     "calls": ((3 * 1440, "call", "read_api", "GET", "/api/domains/all", 200, None),)},
)


def seed_agents(agents=DEMO_AGENTS):
    """Fictional connected agents with their activity, for Settings > Agents."""
    from datetime import datetime, timedelta
    from app.agent_access.scopes import grant_scopes
    from app.database import get_db_context
    from app.models import AgentAudit, AgentGrant

    start = datetime.utcnow()
    at = lambda minutes: start - timedelta(minutes=minutes)  # noqa: E731
    with get_db_context() as db:
        for spec in agents:
            created = at(spec["ago"])
            scopes = grant_scopes(spec["views"], spec["acts"])
            before = grant_scopes(*spec["before"]) if spec.get("before") else scopes
            device = spec["kind"] == "device"
            grant = AgentGrant(
                client_id="mailcow-logs-cli" if device else f"demo-{spec['name'].lower()}",
                client_kind=spec["kind"], display_name=spec["name"], declared_name=spec["name"],
                redirect_uri="" if device else "http://127.0.0.1/callback", scopes=scopes,
                resource="https://logs.example.com/" + ("api" if device else "mcp"),
                approved_by=DEMO_SETTINGS["admin_email"], created_at=created,
                expires_at=created + timedelta(days=spec["days"]), last_used_at=at(spec["used"]),
                revoked_at=at(spec["ended"]) if spec.get("ended") else None,
                revoke_reason="disconnected" if spec.get("ended") else None,
            )
            db.add(grant)
            db.flush()
            row = lambda when, event, **kw: db.add(AgentAudit(  # noqa: E731
                grant_id=grant.id, agent_name=grant.display_name, at=at(when), event=event, **kw))
            row(spec["ago"], "grant_created", outcome="ok",
                detail=f"{before} until {grant.expires_at.isoformat(timespec='minutes')}Z")
            for when, event, tool, method, path, status, detail in spec["calls"]:
                if event == "changed":
                    row(when, "grant_changed", outcome="ok",
                        detail=f"by {DEMO_SETTINGS['admin_email']}: {before} -> {scopes}")
                    continue
                row(when, event, tool=tool, method=method, path=path, http_status=status,
                    outcome="denied" if event == "denied" else "ok", detail=detail)
            if spec.get("ended"):
                row(spec["ended"], "grant_revoked", outcome="ok", detail="disconnected")
        db.commit()
    logger.warning(f"[DEMO] Seeded {len(agents)} connected agents")
    return len(agents)


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


def start_live_traffic(fake, traffic, interval=LIVE_INTERVAL_SECONDS, stop=None):
    """Keep mail flowing: every minute the fake server gets that minute's
    traffic, which the scheduler's regular jobs pick up like new logs.

    Setting the optional ``stop`` event ends the loop (used by tests)."""
    stop = stop or threading.Event()

    def loop():
        last = time.time()
        while not stop.wait(interval):
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


DEFAULT_RESET_TIME = (0, 0)


def parse_reset_time(value):
    """DEMO_RESET_TIME as (hour, minute). 'HH:MM' in 24-hour time; anything
    else falls back to 00:00 with a warning, so a typo never stops the demo."""
    text = (value or "").strip()
    if not text:
        return DEFAULT_RESET_TIME
    try:
        hour_text, minute_text = text.split(":")
        hour, minute = int(hour_text), int(minute_text)
        if 0 <= hour <= 23 and 0 <= minute <= 59 and len(minute_text) == 2:
            return hour, minute
    except ValueError:
        pass
    logger.warning(f"[DEMO] DEMO_RESET_TIME={text!r} is not a time like 03:30; resetting at 00:00")
    return DEFAULT_RESET_TIME


def seconds_until_reset(reset_time=DEFAULT_RESET_TIME, now=None):
    """Seconds until the next reset_time (hour, minute) in the app's time
    zone (app_time.py), whatever the container clock says. Always in the
    future: at exactly that minute the next one is a day away."""
    from app.app_time import app_tz
    zone = app_tz()
    now = now if now is not None else time.time()
    hour, minute = reset_time
    today = datetime.datetime.fromtimestamp(now, zone).date()
    for day in (today, today + datetime.timedelta(days=1)):
        # Built as a wall-clock time in the zone, so a DST change lands on the right instant
        at = datetime.datetime(day.year, day.month, day.day, hour, minute, tzinfo=zone)
        if at.timestamp() > now + 1:
            return at.timestamp() - now
    return 86400.0


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
    reset_time = parse_reset_time(os.environ.get("DEMO_RESET_TIME"))
    delay = float(override) if override else seconds_until_reset(reset_time)
    timer = threading.Timer(delay, restart_process)
    timer.daemon = True
    timer.name = "demo-nightly-reset"
    timer.start()
    from app.app_time import app_tz
    at = datetime.datetime.fromtimestamp(time.time() + delay, app_tz())
    logger.warning(f"[DEMO] Next reset at {at:%Y-%m-%d %H:%M %Z}")
    return timer
