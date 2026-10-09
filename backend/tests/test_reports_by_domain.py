"""Manage Reports counts the reports of each domain and deletes all of one domain's reports.

A domain removed from mailcow keeps its stored DMARC and TLS reports, so it stays
on the DMARC & TLS page (#412). Deleting them one report at a time is not practical.
"""
import uuid
from datetime import datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.config import settings
from app.database import Base, engine, get_db
from app.models import DMARCRecord, DMARCReport, SystemSetting, TLSReport, TLSReportPolicy
from app.routers.dmarc import router

APP = "http://logs.example.test"


@pytest.fixture
def deletion(monkeypatch):
    def set_allowed(value):
        monkeypatch.setattr(settings._inner, "dmarc_allow_report_delete", value)
    set_allowed(False)
    return set_allowed


@pytest.fixture
def db_client():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    schema = "reports_by_domain_test_" + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    isolated = create_engine(engine.url, connect_args={"options": f"-csearch_path={schema}"})
    try:
        Base.metadata.create_all(isolated, tables=[model.__table__ for model in
            (DMARCReport, DMARCRecord, TLSReport, TLSReportPolicy, SystemSetting)])
        app = FastAPI()
        app.include_router(router)

        def session_override():
            with Session(isolated) as db:
                yield db
        app.dependency_overrides[get_db] = session_override
        with TestClient(app) as client:
            yield client, isolated
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))


def seed(isolated):
    """example.com: 2 DMARC (one stored with different case) + 1 TLS; example.net: 1 DMARC; example.org: 2 TLS."""
    with Session(isolated) as db:
        def dmarc(domain, index, end_date, records):
            report = DMARCReport(report_id=f"dmarc-{index}", domain=domain, org_name="Test",
                                 begin_date=end_date - 86400, end_date=end_date)
            db.add(report)
            db.flush()
            for _ in range(records):
                db.add(DMARCRecord(dmarc_report_id=report.id, source_ip="192.0.2.1", count=5))

        def tls(domain, index, end, policies):
            report = TLSReport(report_id=f"tls-{index}", policy_domain=domain, organization_name="Test",
                               start_datetime=end, end_datetime=end)
            db.add(report)
            db.flush()
            for _ in range(policies):
                db.add(TLSReportPolicy(tls_report_id=report.id, policy_domain=domain))

        dmarc("example.com", 1, 1_767_225_600, 2)
        dmarc("Example.COM", 2, 1_767_312_000, 1)
        dmarc("example.net", 3, 1_767_398_400, 3)
        tls("example.com", 1, datetime(2026, 1, 3), 2)
        tls("example.org", 2, datetime(2026, 1, 4), 1)
        tls("example.org", 3, datetime(2026, 1, 5), 1)
        db.commit()


def counts(isolated):
    with Session(isolated) as db:
        return {
            "dmarc": sorted(r.domain for r in db.query(DMARCReport)),
            "records": db.query(DMARCRecord).count(),
            "tls": sorted(r.policy_domain for r in db.query(TLSReport)),
            "policies": db.query(TLSReportPolicy).count(),
        }


def test_summary_counts_each_domain_once(db_client, deletion):
    client, isolated = db_client
    seed(isolated)
    payload = client.get("/dmarc/reports/domains").json()
    assert payload["allow_delete"] is False
    rows = {row["domain"]: row for row in payload["domains"]}
    assert list(rows) == ["example.com", "example.net", "example.org"]
    assert (rows["example.com"]["dmarc_reports"], rows["example.com"]["tls_reports"]) == (2, 1)
    assert (rows["example.net"]["dmarc_reports"], rows["example.net"]["tls_reports"]) == (1, 0)
    assert (rows["example.org"]["dmarc_reports"], rows["example.org"]["tls_reports"]) == (0, 2)
    # The latest report period end, whichever report type it came from
    assert rows["example.net"]["last_report"] == 1_767_398_400
    assert rows["example.org"]["last_report"] == int(datetime(2026, 1, 5).timestamp())
    assert rows["example.com"]["last_report"] == int(datetime(2026, 1, 3).timestamp())


def test_summary_of_no_reports(db_client):
    client, _ = db_client
    assert client.get("/dmarc/reports/domains").json()["domains"] == []


def test_delete_all_removes_only_that_domain(db_client, deletion, caplog):
    client, isolated = db_client
    seed(isolated)
    deletion(True)
    with caplog.at_level("INFO", logger="app.routers.dmarc"):
        response = client.delete("/dmarc/reports/domains/%20Example.com%20")
    assert response.status_code == 200
    assert response.json() == {"status": "success", "domain": "example.com", "dmarc_reports": 2,
                               "dmarc_records": 3, "tls_reports": 1, "tls_policies": 2}
    # The deletion is on record in the log
    assert any("example.com" in r.message and "2 DMARC reports" in r.message and "1 TLS reports" in r.message
               for r in caplog.records if r.name == "app.routers.dmarc")
    assert counts(isolated) == {"dmarc": ["example.net"], "records": 3,
                                "tls": ["example.org", "example.org"], "policies": 2}
    # Other processes are told their cached DMARC figures are stale
    with Session(isolated) as db:
        assert db.query(SystemSetting).filter(SystemSetting.key == "dmarc_last_update").count() == 1
    assert [row["domain"] for row in client.get("/dmarc/reports/domains").json()["domains"]] == [
        "example.net", "example.org"]
    # A TLS-only domain goes too
    assert client.delete("/dmarc/reports/domains/example.org").json()["tls_reports"] == 2
    assert counts(isolated)["tls"] == []


def test_delete_is_refused_while_deletion_is_off(db_client, deletion):
    client, isolated = db_client
    seed(isolated)
    before = counts(isolated)
    response = client.delete("/dmarc/reports/domains/example.com")
    assert response.status_code == 403
    assert counts(isolated) == before


def test_unknown_domain_is_not_found(db_client, deletion):
    client, isolated = db_client
    seed(isolated)
    deletion(True)
    before = counts(isolated)
    assert client.delete("/dmarc/reports/domains/unknown.invalid").status_code == 404
    assert counts(isolated) == before


# The checks below go through the full app and need no database: each is
# answered before the handler opens a query.

@pytest.fixture
def no_auth(monkeypatch):
    monkeypatch.setattr(settings._inner, "auth_enabled", False)
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    monkeypatch.setattr(settings._inner, "oauth2_enabled", False)


def test_route_is_not_taken_by_the_single_report_delete(deletion, no_auth):
    from app.main import app
    response = TestClient(app, base_url=APP).delete("/api/dmarc/reports/domains/example.com")
    # The single-report route would answer 422 (the domain is not a report id)
    assert response.status_code == 403
    assert "Report deletion is disabled" in response.json()["detail"]


def test_blank_domain_is_rejected(deletion, no_auth):
    from app.main import app
    deletion(True)
    response = TestClient(app, base_url=APP).delete("/api/dmarc/reports/domains/%20%20")
    assert response.status_code == 400


def test_cross_site_delete_is_rejected(deletion, no_auth):
    from app.main import app
    deletion(True)
    response = TestClient(app, base_url=APP).delete(
        "/api/dmarc/reports/domains/example.com", headers={"Origin": "https://evil.invalid"})
    assert response.status_code == 403
    assert "another site" in response.json()["detail"]
