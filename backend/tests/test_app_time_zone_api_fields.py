"""Every instant the API returns is ISO 8601 UTC with Z.

The browser reads an ISO string without a zone as its own local time, so a
naive value (log lines, message details, raw log storage time, connection
checks, GeoIP file dates) showed shifted by the viewer's offset, and
'+00:00Z' (blacklist checks) is not a date at all for some parsers. mailcow's
domain 'created' is a wall time in mailcow's own clock and must be read in the
app zone before it is sent.
"""
import asyncio
import os
import re
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.config import settings  # noqa: E402

UTC_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MARKER = f"tzapi-{uuid.uuid4().hex[:8]}.invalid"


def assert_utc_z(value, expected=None):
    assert isinstance(value, str) and UTC_Z.match(value), value
    if expected is not None:
        assert value == expected.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def jerusalem(monkeypatch):
    """The container runs on Jerusalem time (TZ in the process environment)."""
    if not hasattr(time, "tzset"):
        pytest.skip("time.tzset is POSIX only")
    monkeypatch.setenv("TZ", "Asia/Jerusalem")
    time.tzset()
    yield
    monkeypatch.delenv("TZ")
    time.tzset()


# --- Database-backed endpoints ----------------------------------------------

def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import PostfixLog, RspamdLog, MessageCorrelation, RawServiceLog
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(
            MessageCorrelation.sender.like(f"%{MARKER}")).delete(synchronize_session=False)
        db.query(PostfixLog).filter(PostfixLog.sender.like(f"%{MARKER}")).delete(synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.sender_smtp.like(f"%{MARKER}")).delete(synchronize_session=False)
        db.query(RawServiceLog).filter(
            RawServiceLog.message_hash.like(f"{MARKER}%")).delete(synchronize_session=False)
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
    _cleanup()
    yield TestClient(app)
    _cleanup()


WHEN = datetime(2026, 1, 15, 12, 30, 5)  # stored: naive UTC


def _seed_message():
    from app.database import get_db_context
    from app.models import PostfixLog, RspamdLog, MessageCorrelation
    queue_id = uuid.uuid4().hex[:10].upper()
    key = uuid.uuid4().hex
    with get_db_context() as db:
        rspamd = RspamdLog(time=WHEN, message_id=f"<{key}@{MARKER}>", queue_id=queue_id,
                           subject="tz", sender_smtp=f"s@{MARKER}", recipients_smtp=["r@example.com"],
                           score=1.0, required_score=15.0, action="no action", is_spam=False,
                           direction="inbound")
        db.add(rspamd)
        db.flush()
        db.add(PostfixLog(time=WHEN + timedelta(seconds=2), program="postfix/smtp", priority="info",
                          message="sent", queue_id=queue_id, sender=f"s@{MARKER}",
                          recipient="r@example.com", status="sent", correlation_key=key))
        db.add(MessageCorrelation(correlation_key=key, message_id=f"<{key}@{MARKER}>",
                                  queue_id=queue_id, sender=f"s@{MARKER}", recipient="r@example.com",
                                  subject="tz", direction="inbound", final_status="delivered",
                                  is_complete=True, rspamd_log_id=rspamd.id,
                                  first_seen=WHEN, last_seen=WHEN + timedelta(seconds=2)))
        db.commit()
    return queue_id, key


def test_log_lists_send_utc_with_z(client):
    queue_id, _ = _seed_message()

    postfix = client.get("/api/logs/postfix", params={"queue_id": queue_id}).json()["data"]
    assert_utc_z(postfix[0]["time"], WHEN + timedelta(seconds=2))

    rspamd = client.get("/api/logs/rspamd", params={"sender": MARKER}).json()["data"]
    assert_utc_z(rspamd[0]["time"], WHEN)

    by_queue = client.get(f"/api/logs/postfix/by-queue/{queue_id}").json()
    assert_utc_z(by_queue["logs"][0]["time"], WHEN + timedelta(seconds=2))


def test_message_details_send_utc_with_z(client):
    _, key = _seed_message()

    details = client.get(f"/api/message/{key}").json()

    assert_utc_z(details["first_seen"], WHEN)
    assert_utc_z(details["last_seen"], WHEN + timedelta(seconds=2))
    assert_utc_z(details["postfix"][0]["time"], WHEN + timedelta(seconds=2))
    timeline = [event for event in details["timeline"] if event]
    assert [e["event"] for e in timeline] == ["Message received", "Rspamd: no action", "Postfix: sent"]
    for event in timeline:
        assert_utc_z(event["time"])


def _seed_raw(when, stored_at):
    from app.database import get_db_context
    from app.models import RawServiceLog
    with get_db_context() as db:
        db.add(RawServiceLog(service="postfix", time=when, message_hash=f"{MARKER}{uuid.uuid4().hex}",
                             raw_data={"message": f"line {MARKER}", "time": int(when.replace(tzinfo=timezone.utc).timestamp())},
                             created_at=stored_at))
        db.commit()


def test_raw_logs_send_the_storage_time_in_utc_with_z(client):
    _seed_raw(WHEN, WHEN + timedelta(seconds=7))

    rows = client.get("/api/raw-logs/postfix", params={"search": MARKER}).json()["data"]

    assert_utc_z(rows[0]["_stored_at"], WHEN + timedelta(seconds=7))


def test_raw_logs_read_a_date_as_a_day_in_the_app_zone(client, monkeypatch):
    monkeypatch.setattr(settings._inner, "tz", "Europe/Berlin")
    _seed_raw(datetime(2026, 1, 14, 23, 30), None)   # 00:30 on 15 January in Berlin
    _seed_raw(datetime(2026, 1, 15, 22, 30), None)   # 23:30 on 15 January in Berlin
    _seed_raw(datetime(2026, 1, 15, 23, 30), None)   # 00:30 on 16 January in Berlin

    rows = client.get("/api/raw-logs/postfix", params={
        "search": MARKER, "start_date": "2026-01-15", "end_date": "2026-01-15", "order": "asc"}).json()["data"]

    times = [datetime.fromtimestamp(r["time"], timezone.utc).replace(tzinfo=None) for r in rows]
    assert times == [datetime(2026, 1, 14, 23, 30), datetime(2026, 1, 15, 22, 30)]


# --- Endpoints fed by mailcow or the file system ----------------------------

def test_quarantine_sorts_epoch_and_iso_items_together(monkeypatch):
    from app.routers import logs
    monkeypatch.setattr(logs.mailcow_api, "get_quarantine", AsyncMock(return_value=[
        {"id": 1, "created": 1_768_478_400},              # 2026-01-15T12:00:00Z
        {"id": 2, "created": "2026-01-15T13:00:00Z"},
        {"id": 3},
        {"id": 4, "created": "2026-01-15T11:00:00"},
    ]))

    result = asyncio.run(logs.get_quarantine())

    assert [item["id"] for item in result["data"]] == [2, 1, 4, 3]
    assert result["data"][1]["created"] == "2026-01-15T12:00:00Z"
    assert all("_created_timestamp" not in item for item in result["data"])


def test_container_start_times_are_utc_with_z(monkeypatch):
    from app.routers import status
    db = MagicMock()
    db.query.return_value.all.return_value = []
    session = MagicMock()
    session.__enter__.return_value = db
    monkeypatch.setattr(status, "SessionLocal", lambda: session)
    monkeypatch.setattr(status, "load_ignored", lambda db, key: set())

    result = status._store_container_status_worker([{
        "postfix-mailcow": {"state": "running", "started_at": "2026-01-15T12:00:00.123456789Z"},
        "dovecot-mailcow": {"state": "running", "started_at": "2026-01-15T14:00:00+02:00"},
        "odd-mailcow": {"state": "running", "started_at": "yesterday"},
    }])

    containers = result["containers"]
    assert containers["postfix-mailcow"]["started_at"] == "2026-01-15T12:00:00Z"
    assert containers["dovecot-mailcow"]["started_at"] == "2026-01-15T12:00:00Z"
    assert containers["odd-mailcow"]["started_at"] == "yesterday"


def test_connection_check_time_is_utc_with_z(monkeypatch):
    from app.routers import status
    monkeypatch.setattr(status.mailcow_api, "test_connection", AsyncMock(return_value=True))
    assert_utc_z(asyncio.run(status.get_mailcow_connection_status())["timestamp"])

    monkeypatch.setattr(status.mailcow_api, "test_connection", AsyncMock(side_effect=RuntimeError("down")))
    assert_utc_z(asyncio.run(status.get_mailcow_connection_status())["timestamp"])


def test_blacklist_check_times_are_utc_with_z(monkeypatch):
    from app.routers import blacklist as router
    from app.routers import domains
    from app.services import blacklist_service as service
    from app.services import ignore_lists

    # No server address known
    monkeypatch.setattr(domains, "get_cached_server_ip", lambda: None)
    monkeypatch.setattr(domains, "init_server_ip", AsyncMock(return_value=None))
    assert_utc_z(asyncio.run(service.get_blacklist_check_results())["checked_at"])

    # A fresh check
    monkeypatch.setattr(service, "save_blacklist_check", lambda data: None)
    monkeypatch.setattr(service, "applicable_blacklists", lambda ip: [{"name": "test", "zone": "rbl.test"}])
    monkeypatch.setattr(service, "check_ip_in_blacklist", AsyncMock(return_value={
        "name": "test", "zone": "rbl.test", "listed": False, "status": "clean"}))
    monkeypatch.setattr(service, "_batch_state", {"active": False})
    monkeypatch.setattr(service, "_check_progress", {})
    monkeypatch.setattr(ignore_lists, "ignored_now", lambda key: set())
    assert_utc_z(asyncio.run(service.check_all_blacklists("192.0.2.10"))["checked_at"])

    # A cached check (stored naive UTC, with microseconds)
    stored = SimpleNamespace(server_ip="192.0.2.10", checked_at=datetime.utcnow().replace(microsecond=123456),
                             total_blacklists=1, listed_count=0, clean_count=1, error_count=0,
                             timeout_count=0, status="clean", results=[])
    db = MagicMock()
    db.query.return_value.filter.return_value.order_by.return_value.first.return_value = stored

    @contextmanager
    def session():
        yield db
    monkeypatch.setattr("app.database.get_db_context", session)
    monkeypatch.setattr(ignore_lists, "load_ignored", lambda db, key: set())
    assert_utc_z(service.get_cached_blacklist_check("192.0.2.10")["checked_at"],
                 stored.checked_at.replace(microsecond=0))

    # The check failed
    monkeypatch.setattr(router, "get_blacklist_check_results", AsyncMock(side_effect=RuntimeError("dns")))
    assert_utc_z(asyncio.run(router.check_blacklists(host="192.0.2.10", force=False))["checked_at"])


def test_domain_created_is_read_in_the_app_zone(monkeypatch):
    from app.routers import domains
    monkeypatch.setattr(settings._inner, "tz", "Europe/Berlin")

    @contextmanager
    def session():
        yield MagicMock()
    monkeypatch.setattr(domains, "get_db_context", session)
    monkeypatch.setattr(domains, "_last_full_dns_check", lambda db: None)
    monkeypatch.setattr(domains, "get_alias_domain_map", lambda db: {})
    monkeypatch.setattr(domains, "get_cached_dns_check", lambda db, name: {})

    result = domains._build_domain_list_worker([
        {"domain_name": "winter.example", "active": 1, "created": "2026-01-15 13:00:00"},
        {"domain_name": "summer.example", "active": 1, "created": "2026-07-15 13:00:00"},
        {"domain_name": "none.example", "active": 1, "created": None},
    ])

    created = {d["domain_name"]: d["created"] for d in result["domains"]}
    assert created == {
        "winter.example": "2026-01-15T12:00:00Z",   # CET, UTC+1
        "summer.example": "2026-07-15T11:00:00Z",   # CEST, UTC+2
        "none.example": None,
    }


def test_geoip_file_dates_are_utc_with_z(jerusalem, tmp_path, monkeypatch):
    from app.services import geoip_downloader as geoip
    city, asn = tmp_path / "city.mmdb", tmp_path / "asn.mmdb"
    for path in (city, asn):
        path.write_bytes(b"x")
    modified = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    os.utime(city, (modified.timestamp(), modified.timestamp()))
    os.utime(asn, (modified.timestamp(), modified.timestamp()))
    monkeypatch.setattr(geoip, "DATABASES", {
        "City": {**geoip.DATABASES["City"], "path": str(city)},
        "ASN": {**geoip.DATABASES["ASN"], "path": str(asn)},
    })

    status = geoip.get_geoip_status()

    # Jerusalem is UTC+2 in January: the old value said 14:00 with no zone
    assert status["City"]["last_modified"] == "2026-01-15T12:00:00Z"
    assert status["ASN"]["last_modified"] == "2026-01-15T12:00:00Z"
