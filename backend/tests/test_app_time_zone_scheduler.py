"""Scheduled jobs run by the app's time zone, never by the container's.

Both schedulers used to take the container's zone (APScheduler asks tzlocal),
so the 02:00 cleanup and the Monday 09:00 summary ran at 02:00 and 09:00 of
whatever TZ the container had. An unknown TZ such as Europe/Berlinn was worse:
tzlocal raised while APScheduler was being constructed, at import time, and the
app did not start at all.

Each case runs in its own Python process: the old failure happens at import
time, and tzlocal remembers the first zone it found for the whole process.
"""
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

BACKEND = Path(__file__).resolve().parents[1]

# Every job that runs at a clock time: (hour, minute, weekday or None)
CLOCK_JOBS = {
    "cleanup_logs": (2, 0, None),
    "cleanup_dmarc_reports": (2, 15, None),
    "update_geoip": (3, 0, 6),
    "cleanup_eas_devices": (3, 30, None),
    "blacklist_check": (5, 0, None),
    "send_weekly_summary": (9, 0, 0),
    "cleanup_raw_logs": (3, 0, None),
}
# Registered whatever the features and credentials are
ALWAYS_REGISTERED = {"cleanup_logs", "cleanup_eas_devices", "send_weekly_summary", "cleanup_raw_logs"}

SCRIPT = r'''
import asyncio, json, logging, sys, time
time.tzset()

warnings = []
class Grab(logging.Handler):
    def emit(self, record):
        warnings.append(record.getMessage())
logging.getLogger("app.app_time").addHandler(Grab())

import starlette.staticfiles as sf
_orig = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig(s, *a, **{**k, "check_dir": False})

from app.main import app
from app.config import settings
import app.scheduler as sch
import app.raw_logs_worker as rlw

stored, changed = sys.argv[1], sys.argv[2]
if stored:
    settings._inner.tz = stored  # what reload_settings(db) does with a value saved in Settings
for key in ("basic_auth_enabled", "auth_enabled", "oauth2_enabled"):
    setattr(settings._inner, key, False)
sch.cleanup_blacklisted_data = lambda: None
sch.cleanup_disabled_feature_data = lambda *a, **k: None
rlw.load_catchup_state = lambda: None

def clock_jobs():
    jobs = sch.scheduler.get_jobs() + rlw.raw_logs_scheduler.get_jobs()
    return {j.id: {"zone": str(j.trigger.timezone), "next": j.next_run_time.isoformat()}
            for j in jobs if type(j.trigger).__name__ == "CronTrigger"}

async def run():
    sch.start_scheduler()
    rlw.start_raw_logs_scheduler()
    out = {"scheduler_zone": str(sch.scheduler.timezone),
           "raw_zone": str(rlw.raw_logs_scheduler.timezone),
           "raw_running": rlw.raw_logs_scheduler.running,
           "started": clock_jobs()}
    if changed:
        settings._inner.tz = changed
        sch.reschedule_interval_jobs()
        out["changed"] = clock_jobs()
        out["scheduler_zone_changed"] = str(sch.scheduler.timezone)
    # Stop before the loop runs anything (the version check would go online)
    sch.scheduler.shutdown(wait=False)
    rlw.raw_logs_scheduler.shutdown(wait=False)
    return out

out = asyncio.run(run())
from fastapi.testclient import TestClient
info = TestClient(app).get("/api/info").json()
out["info"] = {k: info.get(k) for k in ("timezone", "timezone_valid", "timezone_configured")}
out["warnings"] = warnings
print("RESULT " + json.dumps(out))
'''


def run_app(container_tz, stored="", changed=""):
    env = dict(os.environ)
    env.pop("TZ", None)
    if container_tz is not None:
        env["TZ"] = container_tz
    proc = subprocess.run(
        [sys.executable, "-c", SCRIPT, stored, changed],
        cwd=BACKEND, env=env, capture_output=True, text=True, timeout=180,
    )
    lines = [line for line in proc.stdout.splitlines() if line.startswith("RESULT ")]
    assert proc.returncode == 0 and lines, (
        f"the app did not come up (exit {proc.returncode}):\n{proc.stderr[-3000:]}")
    return json.loads(lines[-1][len("RESULT "):])


def assert_clock_jobs_in(jobs, zone):
    assert ALWAYS_REGISTERED <= set(jobs), sorted(jobs)
    for job_id, job in jobs.items():
        assert job_id in CLOCK_JOBS, f"{job_id} runs at a clock time but is not in CLOCK_JOBS"
        assert job["zone"] == zone, (job_id, job["zone"])
        hour, minute, weekday = CLOCK_JOBS[job_id]
        at = datetime.fromisoformat(job["next"]).astimezone(ZoneInfo(zone))
        assert (at.hour, at.minute) == (hour, minute), (job_id, at.isoformat())
        if weekday is not None:
            assert at.weekday() == weekday, (job_id, at.isoformat())


@pytest.fixture(autouse=True)
def posix_only():
    if not hasattr(__import__("time"), "tzset"):
        pytest.skip("time.tzset is POSIX only")


def test_unknown_tz_in_the_environment_starts_the_app_on_utc():
    out = run_app("Europe/Berlinn")

    assert out["scheduler_zone"] == "UTC"
    assert out["raw_running"] is True
    assert out["raw_zone"] == "UTC"
    assert_clock_jobs_in(out["started"], "UTC")
    assert out["info"] == {"timezone": "UTC", "timezone_valid": False,
                           "timezone_configured": "Europe/Berlinn"}
    # The log names the bad value, once
    assert sum("Europe/Berlinn" in w for w in out["warnings"]) == 1, out["warnings"]


def test_unknown_tz_saved_in_settings_starts_the_app_on_utc():
    out = run_app(None, stored="Mars/Olympus")

    assert out["scheduler_zone"] == "UTC"
    assert_clock_jobs_in(out["started"], "UTC")
    assert out["info"] == {"timezone": "UTC", "timezone_valid": False,
                           "timezone_configured": "Mars/Olympus"}
    assert sum("Mars/Olympus" in w for w in out["warnings"]) == 1, out["warnings"]


def test_clock_jobs_run_in_the_app_zone_not_the_container_zone():
    # The container runs on New York time; the app zone is Berlin
    out = run_app("America/New_York", stored="Europe/Berlin")

    assert out["scheduler_zone"] == "Europe/Berlin"
    assert out["raw_zone"] == "Europe/Berlin"
    assert_clock_jobs_in(out["started"], "Europe/Berlin")


def test_a_new_zone_in_settings_moves_every_clock_job_at_once():
    out = run_app("America/New_York", stored="Europe/Berlin", changed="Asia/Tokyo")

    assert_clock_jobs_in(out["started"], "Europe/Berlin")
    assert set(out["changed"]) == set(out["started"])
    assert_clock_jobs_in(out["changed"], "Asia/Tokyo")
    assert out["scheduler_zone_changed"] == "Asia/Tokyo"
