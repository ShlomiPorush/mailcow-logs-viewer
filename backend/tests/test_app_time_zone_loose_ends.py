"""The app time zone, second round: the places the first round left on the
container clock or on UTC.

- caches whose content depends on the zone kept days of the old zone for
  minutes after the zone changed in Settings;
- a date (YYYY-MM-DD) in a range was read as midnight UTC, not as a day in the
  app zone;
- the app's own log lines carried the container's wall time, with no zone;
- demo traffic followed the container clock;
- a few times still left the API as +00:00 instead of Z.
"""
import asyncio
import csv
import io
import json
import logging
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

import app.config as cfg  # noqa: E402
from app.config import settings  # noqa: E402

UTC_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MARKER = f"tzle-{uuid.uuid4().hex[:8]}.invalid"


def assert_utc_z(value):
    assert isinstance(value, str) and UTC_Z.match(value), value


@pytest.fixture
def app_zone(monkeypatch):
    def set_zone(name):
        monkeypatch.setattr(settings._inner, "tz", name)
    return set_zone


# --- 1. Caches key on the zone -----------------------------------------------

def test_mailbox_stats_cache_keys_on_the_zone(app_zone):
    from app.routers import mailbox_stats

    params = dict(date_range="7days", page=1, page_size=50)
    app_zone("")
    in_utc = mailbox_stats._get_cache_key("mailbox_stats_all", **params)
    app_zone("Europe/Berlin")
    in_berlin = mailbox_stats._get_cache_key("mailbox_stats_all", **params)

    assert in_utc != in_berlin
    assert mailbox_stats._get_cache_key("mailbox_stats_all", **params) == in_berlin


def test_a_cached_mailbox_stats_page_is_not_served_in_a_new_zone(app_zone):
    from app.routers import mailbox_stats

    params = dict(date_range="today", page=1, page_size=50)
    app_zone("")
    mailbox_stats._set_cache(mailbox_stats._get_cache_key("mailbox_stats_all", **params), {"days": "UTC"})
    try:
        app_zone("Europe/Berlin")
        assert mailbox_stats._get_cached(mailbox_stats._get_cache_key("mailbox_stats_all", **params)) is None
    finally:
        mailbox_stats.clear_stats_cache()


def test_dmarc_cache_keys_on_the_zone(app_zone):
    from app.services.dmarc_cache import get_dmarc_cache_key

    app_zone("")
    in_utc = get_dmarc_cache_key("domains_list")
    app_zone("Europe/Berlin")
    in_berlin = get_dmarc_cache_key("domains_list")

    assert in_utc != in_berlin
    assert get_dmarc_cache_key("domains_list") == in_berlin


# --- 2. A date in a range is a day in the app zone ---------------------------

def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(
            MessageCorrelation.sender.like(f"%{MARKER}")).delete(synchronize_session=False)
        db.query(PostfixLog).filter(PostfixLog.sender.like(f"%{MARKER}")).delete(synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.sender_smtp.like(f"%{MARKER}")).delete(synchronize_session=False)
        db.query(NetfilterLog).filter(NetfilterLog.username.like(f"%{MARKER}")).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def client(monkeypatch):
    if not _postgres_available():
        pytest.skip("PostgreSQL not available")
    from fastapi.testclient import TestClient
    from app.database import init_db
    from app.main import app
    init_db()
    for key in ("basic_auth_enabled", "auth_enabled", "oauth2_enabled"):
        monkeypatch.setattr(settings._inner, key, False)
    monkeypatch.setattr(settings._inner, "tz", "Europe/Berlin")
    _cleanup()
    yield TestClient(app)
    _cleanup()


# Stored naive UTC. In Berlin (UTC+1 in January) the first and the last are
# outside 15 January, the middle two inside it.
TIMES = [
    datetime(2026, 1, 14, 22, 30),  # 23:30 on 14 January in Berlin
    datetime(2026, 1, 14, 23, 30),  # 00:30 on 15 January in Berlin
    datetime(2026, 1, 15, 22, 30),  # 23:30 on 15 January in Berlin
    datetime(2026, 1, 15, 23, 30),  # 00:30 on 16 January in Berlin
]
IN_DAY = TIMES[1:3]
DAY = {"start_date": "2026-01-15", "end_date": "2026-01-15"}


def _seed():
    from app.database import get_db_context
    from app.models import PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation
    with get_db_context() as db:
        for i, when in enumerate(TIMES):
            key = uuid.uuid4().hex
            db.add(PostfixLog(time=when, program="postfix/smtp", priority="info", message="sent",
                              queue_id=f"TZLE{i}{uuid.uuid4().hex[:6].upper()}", sender=f"s{i}@{MARKER}",
                              recipient="r@example.com", status="sent"))
            db.add(RspamdLog(time=when, message_id=f"<{key}@{MARKER}>", subject="tz",
                             sender_smtp=f"s{i}@{MARKER}", recipients_smtp=["r@example.com"], score=1.0,
                             required_score=15.0, action="no action", is_spam=False, direction="inbound"))
            db.add(NetfilterLog(time=when, priority="warn", message=f"login failed {MARKER}",
                                ip="192.0.2.7", username=f"u{i}@{MARKER}", action="warning"))
            db.add(MessageCorrelation(correlation_key=key, message_id=f"<{key}@{MARKER}>",
                                      sender=f"s{i}@{MARKER}", recipient="r@example.com", subject="tz",
                                      direction="inbound", final_status="delivered", is_complete=True,
                                      first_seen=when, last_seen=when))
        db.commit()


def _times(rows, field="time"):
    return sorted(datetime.fromisoformat(r[field].replace("Z", "+00:00")).replace(tzinfo=None) for r in rows)


def _csv_times(response):
    rows = list(csv.reader(io.StringIO(response.text)))
    return sorted(datetime.fromisoformat(row[0]).astimezone(timezone.utc).replace(tzinfo=None) for row in rows[1:])


@pytest.mark.parametrize("path, params, field", [
    ("/api/logs/postfix", {"sender": MARKER}, "time"),
    ("/api/logs/rspamd", {"search": MARKER}, "time"),
    ("/api/logs/netfilter", {"username": MARKER}, "time"),
    ("/api/messages", {"sender": MARKER}, "first_seen"),
])
def test_list_ranges_read_a_date_as_a_day_in_the_app_zone(client, path, params, field):
    _seed()

    response = client.get(path, params={**params, **DAY})

    assert response.status_code == 200, response.text
    assert _times(response.json()["data"], field) == IN_DAY


@pytest.mark.parametrize("path, params", [
    ("/api/export/postfix/csv", {"sender": MARKER}),
    ("/api/export/rspamd/csv", {"sender": MARKER}),
    ("/api/export/netfilter/csv", {"username": MARKER}),
    ("/api/export/messages/csv", {"sender": MARKER}),
])
def test_csv_exports_read_a_date_as_a_day_in_the_app_zone(client, path, params):
    _seed()

    response = client.get(path, params={**params, **DAY})

    assert response.status_code == 200, response.text
    assert _csv_times(response) == IN_DAY


def test_message_facets_read_a_date_as_a_day_in_the_app_zone(client):
    _seed()

    facets = client.get("/api/messages/facets", params={
        "sender": MARKER, **DAY, "since": "fromday:2026-01-15"}).json()

    assert facets["status"]["all"] == 2
    # Since the start of 15 January in Berlin: three of the four
    assert facets["time"]["fromday"] == 3


def test_full_instants_keep_their_meaning(client):
    _seed()

    rows = client.get("/api/logs/postfix", params={
        "sender": MARKER, "start_date": "2026-01-14T23:00:00Z", "end_date": "2026-01-15T22:30:00Z"}).json()["data"]
    assert _times(rows) == IN_DAY

    # An instant without a zone is UTC, as before
    rows = client.get("/api/logs/postfix", params={
        "sender": MARKER, "start_date": "2026-01-14T23:00:00", "end_date": "2026-01-15T22:30:00"}).json()["data"]
    assert _times(rows) == IN_DAY


def test_range_parameters_keep_their_api_shape():
    from app.main import app

    schema = app.openapi()
    for path in ("/api/logs/postfix", "/api/messages", "/api/export/messages/csv"):
        params = {p["name"]: p for p in schema["paths"][path]["get"]["parameters"]}
        for name in ("start_date", "end_date"):
            assert '"format": "date-time"' in json.dumps(params[name]["schema"]), (path, name)


def test_an_unreadable_range_is_still_refused(client):
    response = client.get("/api/logs/postfix", params={"start_date": "yesterday"})
    assert response.status_code == 422


# --- 3. The app's own log lines are in the app zone ---------------------------

def _record(created):
    record = logging.LogRecord("app.test", logging.INFO, __file__, 1, "hello", None, None)
    record.created = created
    record.msecs = 0
    return record


def test_app_log_lines_carry_the_app_zone_and_its_offset(app_zone):
    root = logging.getLogger()
    saved = root.handlers[:]
    try:
        cfg.setup_logging()
        formatter = root.handlers[0].formatter
        moment = datetime(2026, 1, 15, 12, 30, 5, tzinfo=timezone.utc).timestamp()

        app_zone("Europe/Berlin")
        assert formatter.format(_record(moment)).startswith("2026-01-15 13:30:05+01:00 - INFO - hello")

        # A new zone in Settings applies to the next line, with no restart
        app_zone("Asia/Tokyo")
        assert formatter.format(_record(moment)).startswith("2026-01-15 21:30:05+09:00 - INFO - hello")

        # Every handler writes the same time, the file the page shows included
        for handler in root.handlers:
            assert handler.formatter.format(_record(moment)).startswith("2026-01-15 21:30:05+09:00")
    finally:
        for handler in root.handlers[:]:
            root.removeHandler(handler)
            if handler not in saved:
                handler.close()
        for handler in saved:
            root.addHandler(handler)


def test_an_unknown_zone_writes_log_lines_in_utc(app_zone):
    root = logging.getLogger()
    saved = root.handlers[:]
    try:
        cfg.setup_logging()
        app_zone("Europe/Berlinn")
        moment = datetime(2026, 1, 15, 12, 30, 5, tzinfo=timezone.utc).timestamp()
        assert root.handlers[0].formatter.format(_record(moment)).startswith("2026-01-15 12:30:05+00:00")
    finally:
        for handler in root.handlers[:]:
            root.removeHandler(handler)
            if handler not in saved:
                handler.close()
        for handler in saved:
            root.addHandler(handler)


# --- 5. Demo traffic follows the app zone -------------------------------------

def test_demo_working_hours_follow_the_app_zone(app_zone):
    from demo.traffic import Traffic

    app_zone("Asia/Tokyo")
    # Thursday 15 January 2026, 10:00 in Tokyo (01:00 UTC): the busiest hours
    ten_in_tokyo = datetime(2026, 1, 15, 1, 0, tzinfo=timezone.utc).timestamp()
    assert Traffic._hour_weight(ten_in_tokyo) == 2.0
    # Saturday 17 January 2026, 10:00 in Tokyo: a weekend
    assert Traffic._hour_weight(ten_in_tokyo + 2 * 86400) == pytest.approx(2.0 * 0.45)


def test_demo_certificate_check_runs_at_three_in_the_app_zone(app_zone):
    from demo.traffic import Traffic
    from app.app_time import app_tz

    app_zone("Asia/Tokyo")
    start = datetime(2026, 1, 15, 0, 0, tzinfo=timezone.utc).timestamp()
    acme = Traffic(seed=5).generate(start, start + 86400)["acme"]

    hours = {datetime.fromtimestamp(int(entry["time"]), app_tz()).hour for entry in acme}
    assert hours == {3}


# --- 6. Every instant leaves the API with Z ------------------------------------

def test_live_log_broadcasts_carry_a_utc_z_timestamp():
    from app.routers.raw_logs import LogStreamManager

    manager = LogStreamManager()
    manager.connections["postfix"] = [object()]
    sent = []

    async def capture(clients, text):
        sent.append(json.loads(text))
    manager._broadcast_text = capture

    asyncio.run(manager.broadcast("postfix", [{"message": "x"}]))

    assert_utc_z(sent[0]["timestamp"])


def test_raw_log_worker_status_sends_utc_z(monkeypatch):
    from app.routers import raw_logs

    status = {
        "fetch_raw_logs": {"last_run": datetime(2026, 1, 15, 12, 0, 1, 500, tzinfo=timezone.utc),
                           "status": "success", "error": None, "stats": {}},
        "cleanup_raw_logs": {"last_run": None, "status": "idle", "error": None},
    }
    monkeypatch.setattr(raw_logs, "get_raw_logs_job_status", lambda: status)

    jobs = raw_logs.get_worker_status()["jobs"]

    assert jobs["fetch_raw_logs"]["last_run"] == "2026-01-15T12:00:01Z"
    assert jobs["cleanup_raw_logs"]["last_run"] is None
    # The worker's own record is left as it is
    assert isinstance(status["fetch_raw_logs"]["last_run"], datetime)


class _Rows:
    """system_settings as a dict, enough for settings_store's read and write paths."""

    def __init__(self):
        self.rows = {}

    def query(self, model):
        return self

    def filter(self, condition):
        self._key = condition.right.value
        return self

    def first(self):
        return self.rows.get(self._key)

    def add(self, row):
        self.rows[row.key] = row

    def commit(self):
        pass


def test_credential_check_time_is_utc_z():
    from app.models import SystemSetting
    from app.services import settings_store

    db = _Rows()
    settings_store.save_credential_check_status(db, "mailcow_rw_key", {"valid": True}, "fp")
    assert_utc_z(settings_store.get_credential_check_status(db, "mailcow_rw_key", "fp")["checked_at"])

    # A result saved by an earlier version, with +00:00
    db.rows["credential_check.rspamd_password"] = SystemSetting(
        key="credential_check.rspamd_password",
        value=json.dumps({"valid": True, "fingerprint": "fp", "checked_at": "2026-01-15T12:00:01.123456+00:00"}))
    assert settings_store.get_credential_check_status(db, "rspamd_password", "fp")["checked_at"] == "2026-01-15T12:00:01Z"


def test_maxmind_check_time_is_utc_z():
    from app.models import SystemSetting
    from app.services import settings_store

    class Settings(_Rows):
        def filter(self, condition):
            # get_maxmind_validation_status reads every maxmind.* row at once
            if hasattr(condition.right, "value"):
                self._key = condition.right.value
            return self

        def all(self):
            return list(self.rows.values())

    db = Settings()
    settings_store.save_maxmind_validation_status(db, {"configured": True, "valid": True})
    assert_utc_z(settings_store.get_maxmind_validation_status(db)["checked_at"])

    db.rows["maxmind.license_checked_at"] = SystemSetting(
        key="maxmind.license_checked_at", value="2026-01-15T12:00:01.123456+00:00")
    assert settings_store.get_maxmind_validation_status(db)["checked_at"] == "2026-01-15T12:00:01Z"


def test_quarantine_rule_and_suppression_times_are_utc_z():
    from app.routers import quarantine_rules, suppressions

    when = datetime(2026, 1, 15, 12, 0, 1, 123456)
    rule = SimpleNamespace(id=1, name="r", match_type="sender", match_value="x", is_regex=False,
                           action="delete", enabled=True, hit_count=0, last_hit_at=when, notes=None,
                           created_at=when, updated_at=when.replace(tzinfo=timezone.utc))
    out = quarantine_rules._rule_to_dict(rule)
    for key in ("last_hit_at", "created_at", "updated_at"):
        assert out[key] == "2026-01-15T12:00:01Z", key

    suppression = SimpleNamespace(
        id=1, email="a@example.com", type="sender", reason="bounce", source="auto", notes=None,
        bounce_count=1, hard_bounce_count=1, soft_bounce_count=0, last_bounce_dsn=None,
        last_bounce_message=None, correlation_key=None, active=True, synced_to_rspamd=False,
        expires_at=when + timedelta(days=1), created_at=when, updated_at=when)
    out = suppressions._serialize_suppression(suppression, when)
    assert out["expires_at"] == "2026-01-16T12:00:01Z"
    assert out["created_at"] == out["updated_at"] == "2026-01-15T12:00:01Z"
