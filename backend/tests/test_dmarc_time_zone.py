"""DMARC & TLS times follow the app time zone, never the container's.

TLS report periods are stored as naive UTC; calling .timestamp() on them read
them as container local time, so with a non-UTC container every TLS epoch was
off by the offset. The 30-day TLS window and the IMAP "last 24 hours" compared
the container's local now with UTC columns. Days were container days for DMARC
and UTC days for TLS; they are now days in the app time zone. Import dates and
TLS periods are sent as UTC with Z.
"""
import os
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings
from app.database import Base, engine, get_db
from app.models import DMARCRecord, DMARCReport, DMARCSync, DomainDNSCheck, TLSReport, TLSReportPolicy
from app.routers import dmarc as dmarc_router

DOMAIN = "tz.example.com"
TLS_ONLY = "tls-only.example.com"


@pytest.fixture
def container_tz():
    """Run the test in a container whose own clock is in another zone."""
    saved = os.environ.get("TZ")

    def apply(name):
        os.environ["TZ"] = name
        time.tzset()

    try:
        yield apply
    finally:
        if saved is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = saved
        time.tzset()


@pytest.fixture
def app_zone(monkeypatch):
    return lambda name: monkeypatch.setattr(settings._inner, "tz", name)


@pytest.fixture
def db(monkeypatch):
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    schema = "dmarc_tz_test_" + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    isolated = create_engine(engine.url, connect_args={"options": f"-csearch_path={schema} -ctimezone=UTC"})
    try:
        Base.metadata.create_all(isolated, tables=[model.__table__ for model in
            (DMARCReport, DMARCRecord, DMARCSync, DomainDNSCheck, TLSReport, TLSReportPolicy)])
        monkeypatch.setattr(dmarc_router, "SessionLocal", sessionmaker(bind=isolated))
        app = FastAPI()
        app.include_router(dmarc_router.router)

        def session_override():
            with Session(isolated) as session:
                yield session
        app.dependency_overrides[get_db] = session_override
        with TestClient(app) as client:
            yield client, isolated
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))


def _utc_epoch(value: datetime) -> int:
    return int(value.replace(tzinfo=timezone.utc).timestamp())


def _add_tls(isolated, domain, start, end, created_at=None, index=None):
    with Session(isolated) as session:
        report = TLSReport(report_id=f"tls-{index or uuid.uuid4().hex}", policy_domain=domain,
                           organization_name="Reporter", start_datetime=start, end_datetime=end,
                           created_at=created_at or datetime(2026, 1, 13, 8, 30))
        session.add(report)
        session.flush()
        session.add(TLSReportPolicy(tls_report_id=report.id, policy_domain=domain, policy_type="sts",
                                    successful_session_count=5, failed_session_count=0))
        session.commit()


def _add_dmarc(isolated, domain, begin, created_at=None):
    with Session(isolated) as session:
        report = DMARCReport(report_id=f"dmarc-{uuid.uuid4().hex}", domain=domain, org_name="Reporter",
                             begin_date=begin, end_date=begin + 86399,
                             created_at=created_at or datetime(2026, 1, 13, 8, 30))
        session.add(report)
        session.flush()
        session.add(DMARCRecord(dmarc_report_id=report.id, source_ip="192.0.2.1", count=3,
                                spf_result="pass", dkim_result="pass"))
        session.commit()


def _recent_utc_day(days_ago=3) -> date:
    return datetime.now(timezone.utc).date() - timedelta(days=days_ago)


# ---- Finding 2: TLS epochs ----

def test_tls_periods_are_utc_epochs_whatever_the_container_zone(db, container_tz):
    client, isolated = db
    container_tz("Asia/Tokyo")
    start, end = datetime(2026, 1, 12), datetime(2026, 1, 12, 23, 59, 59)
    _add_tls(isolated, TLS_ONLY, start, end)

    reports = client.get("/dmarc/reports/all").json()["reports"]
    assert (reports[0]["begin_date"], reports[0]["end_date"]) == (_utc_epoch(start), _utc_epoch(end))

    rows = {row["domain"]: row for row in client.get("/dmarc/reports/domains").json()["domains"]}
    assert rows[TLS_ONLY]["last_report"] == _utc_epoch(end)

    domains, _ = dmarc_router._build_domains_list()
    entry = {d["domain"]: d for d in domains["domains"]}[TLS_ONLY]
    assert (entry["first_report"], entry["last_report"]) == (_utc_epoch(start), _utc_epoch(end))
    assert (entry["tls_first_report"], entry["tls_last_report"]) == (_utc_epoch(start), _utc_epoch(end))


# ---- Finding 3 and 15: instants carry Z ----

def test_import_dates_and_tls_periods_are_sent_as_utc_with_z(db, app_zone):
    client, isolated = db
    app_zone("Europe/Berlin")
    day = _recent_utc_day()
    start = datetime(day.year, day.month, day.day, 6)
    _add_tls(isolated, DOMAIN, start, start + timedelta(hours=12), created_at=datetime(2026, 1, 13, 8, 30, 15))
    _add_dmarc(isolated, DOMAIN, _utc_epoch(start), created_at=datetime(2026, 1, 13, 8, 30, 15))

    reports = client.get("/dmarc/reports/all").json()["reports"]
    assert {r["type"]: r["created_at"] for r in reports} == {
        "dmarc": "2026-01-13T08:30:15Z", "tls": "2026-01-13T08:30:15Z"}
    paged = client.get("/dmarc/reports/all", params={"page": 1}).json()["reports"]
    assert all(r["created_at"] == "2026-01-13T08:30:15Z" for r in paged)

    expected = (f"{day.isoformat()}T06:00:00Z", f"{day.isoformat()}T18:00:00Z")
    listed = client.get(f"/dmarc/domains/{DOMAIN}/tls-reports").json()["data"][0]
    assert (listed["start_datetime"], listed["end_datetime"]) == expected
    details = client.get(f"/dmarc/domains/{DOMAIN}/tls-reports/{day.isoformat()}/details").json()
    assert (details["providers"][0]["start_datetime"], details["providers"][0]["end_datetime"]) == expected


# ---- Finding 4: DMARC and TLS days are days in the app time zone ----

def test_dmarc_reports_are_grouped_by_app_zone_days(db, app_zone, container_tz):
    client, isolated = db
    container_tz("Asia/Tokyo")
    app_zone("America/New_York")
    day = _recent_utc_day()
    # 02:00 UTC is the evening before in New York, and 11:00 the same day in Tokyo
    begin = datetime(day.year, day.month, day.day, 2, tzinfo=timezone.utc)
    _add_dmarc(isolated, DOMAIN, int(begin.timestamp()))
    local_day = begin.astimezone(ZoneInfo("America/New_York")).date().isoformat()
    assert local_day == (day - timedelta(days=1)).isoformat()

    domains, _ = dmarc_router._build_domains_list()
    assert [d["date"] for d in domains["daily"]] == [local_day]

    overview = dmarc_router._load_domain_overview(DOMAIN, 30, None, None)
    assert [d["date"] for d in overview["daily_stats"]] == [local_day]

    daily = client.get(f"/dmarc/domains/{DOMAIN}/reports").json()["data"]
    assert [d["date"] for d in daily] == [local_day]

    details = client.get(f"/dmarc/domains/{DOMAIN}/reports/{local_day}/details")
    assert details.status_code == 200
    assert details.json()["totals"]["total_messages"] == 3
    assert client.get(f"/dmarc/domains/{DOMAIN}/reports/{day.isoformat()}/details").status_code == 404


def test_tls_reports_are_grouped_by_app_zone_days(db, app_zone):
    client, isolated = db
    app_zone("America/New_York")
    day = _recent_utc_day()
    start = datetime(day.year, day.month, day.day)  # midnight UTC: the evening before in New York
    _add_tls(isolated, DOMAIN, start, start + timedelta(hours=23, minutes=59, seconds=59))
    local_day = (day - timedelta(days=1)).isoformat()

    daily = client.get(f"/dmarc/domains/{DOMAIN}/tls-reports/daily").json()["data"]
    assert [d["date"] for d in daily] == [local_day]

    details = client.get(f"/dmarc/domains/{DOMAIN}/tls-reports/{local_day}/details")
    assert details.status_code == 200
    assert details.json()["stats"]["total_reports"] == 1
    assert client.get(f"/dmarc/domains/{DOMAIN}/tls-reports/{day.isoformat()}/details").status_code == 404


def test_a_day_with_a_daylight_saving_change_holds_all_its_hours(db, app_zone):
    """Europe/Berlin 2026-10-25 has 25 hours, from 22:00 UTC the day before to 23:00 UTC."""
    client, isolated = db
    app_zone("Europe/Berlin")
    for moment in (datetime(2026, 10, 24, 22, 30), datetime(2026, 10, 25, 22, 30)):
        _add_dmarc(isolated, DOMAIN, _utc_epoch(moment))
        _add_tls(isolated, DOMAIN, moment, moment + timedelta(minutes=10))

    dmarc_day = client.get(f"/dmarc/domains/{DOMAIN}/reports/2026-10-25/details").json()
    assert dmarc_day["totals"]["total_messages"] == 6
    tls_day = client.get(f"/dmarc/domains/{DOMAIN}/tls-reports/2026-10-25/details").json()
    assert tls_day["stats"]["total_reports"] == 2
    assert client.get(f"/dmarc/domains/{DOMAIN}/reports/2026-10-24/details").status_code == 404
    assert client.get(f"/dmarc/domains/{DOMAIN}/tls-reports/2026-10-26/details").status_code == 404


# ---- Finding 9: windows are counted in UTC ----

def test_the_tls_30_day_window_is_counted_in_utc(db, container_tz):
    _, isolated = db
    container_tz("Asia/Tokyo")
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    # Inside the last 30 days by four hours; the container's local clock is 9 hours ahead
    _add_tls(isolated, TLS_ONLY, now - timedelta(days=30) + timedelta(hours=4), now - timedelta(days=29))

    domains, _ = dmarc_router._build_domains_list()
    entry = {d["domain"]: d for d in domains["domains"]}[TLS_ONLY]
    assert entry["tls_report_count"] == 1
    assert entry["stats_30d"]["tls_sessions"] == 5


def test_the_imap_last_24_hours_are_counted_in_utc(db, container_tz):
    client, isolated = db
    container_tz("Asia/Tokyo")
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    with Session(isolated) as session:
        for hours, created in ((20, 4), (26, 50)):
            started = now - timedelta(hours=hours)
            session.add(DMARCSync(sync_type="auto", status="success", started_at=started,
                                  completed_at=started + timedelta(minutes=1), reports_created=created))
        session.commit()

    payload = client.get("/dmarc/imap/status").json()
    assert payload["stats_24h"]["total_syncs"] == 1
    assert payload["stats_24h"]["total_reports_created"] == 4
    assert payload["latest_sync"]["started_at"].endswith("Z")
