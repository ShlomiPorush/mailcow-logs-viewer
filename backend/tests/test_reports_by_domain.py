"""Manage Reports counts the reports of each domain and deletes all of one domain's reports.

A domain removed from mailcow keeps its stored DMARC and TLS reports, so it stays
on the DMARC & TLS page (#412). Deleting them one report at a time is not practical.
"""
import uuid
from datetime import datetime, timedelta

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


# Search on the All reports list: the domain or the reporter, literally and in any case

def seed_search(isolated):
    with Session(isolated) as db:
        stamp = datetime(2026, 1, 1)
        rows = [
            DMARCReport(report_id="s-1", domain="example.com", org_name="Google", begin_date=1, end_date=2,
                        created_at=stamp.replace(hour=1)),
            DMARCReport(report_id="s-2", domain="example.net", org_name="Odd 50%_Off\Mail", begin_date=1,
                        end_date=2, created_at=stamp.replace(hour=2)),
            TLSReport(report_id="s-3", policy_domain="example.com", organization_name="Microsoft",
                      start_datetime=stamp, end_datetime=stamp, created_at=stamp.replace(hour=3)),
            TLSReport(report_id="s-4", policy_domain="example.org", organization_name="Google",
                      start_datetime=stamp, end_datetime=stamp, created_at=stamp.replace(hour=4)),
        ]
        db.add_all(rows)
        db.commit()


def found(client, search, **params):
    response = client.get("/dmarc/reports/all", params={"page": 1, "search": search, **params})
    assert response.status_code == 200
    payload = response.json()
    return payload, sorted((row["type"], row["domain"], row["org_name"]) for row in payload["reports"])


def test_search_matches_the_domain_in_any_case_across_both_types(db_client):
    client, isolated = db_client
    seed_search(isolated)
    payload, rows = found(client, "  EXAMPLE.com ")
    assert rows == [("dmarc", "example.com", "Google"), ("tls", "example.com", "Microsoft")]
    assert payload["total"] == 2


def test_search_matches_the_reporter(db_client):
    client, isolated = db_client
    seed_search(isolated)
    _, rows = found(client, "google")
    assert rows == [("dmarc", "example.com", "Google"), ("tls", "example.org", "Google")]


@pytest.mark.parametrize("term", ["%", "_", "\\", "50%_off"])
def test_like_wildcards_are_literal(db_client, term):
    client, isolated = db_client
    seed_search(isolated)
    payload, rows = found(client, term)
    assert rows == [("dmarc", "example.net", "Odd 50%_Off\Mail")]
    assert payload["total"] == 1


def test_total_and_pages_follow_the_search(db_client):
    client, isolated = db_client
    seed_search(isolated)
    payload, _ = found(client, "google", limit=1)
    assert (payload["total"], payload["total_pages"]) == (2, 2)
    last = client.get("/dmarc/reports/all", params={"page": 99, "limit": 1, "search": "google"}).json()
    assert (last["page"], len(last["reports"])) == (2, 1)
    payload, rows = found(client, "nothing-matches.invalid")
    assert (payload["total"], payload["total_pages"], rows) == (0, 1, [])


def test_an_empty_or_absent_search_lists_everything(db_client):
    client, isolated = db_client
    seed_search(isolated)
    assert found(client, "   ")[0]["total"] == 4
    assert client.get("/dmarc/reports/all?page=1").json()["total"] == 4
    # The legacy unpaginated response is unchanged without a search and filtered with one
    assert client.get("/dmarc/reports/all").json()["total"] == 4
    assert client.get("/dmarc/reports/all", params={"search": "microsoft"}).json()["total"] == 1


def test_a_very_long_search_is_capped_not_refused(db_client):
    client, isolated = db_client
    seed_search(isolated)
    payload, rows = found(client, "x" * 5000)
    assert (payload["total"], rows) == (0, [])


# Sorting All reports on the server: across both report types, before paging

def seed_sort(isolated):
    """Mixed DMARC and TLS rows with ties on every key, and a TLS report without a reporter."""
    t1, t2, t3 = datetime(2026, 1, 1, 1), datetime(2026, 1, 1, 2), datetime(2026, 1, 1, 3)
    dmarc = [  # domain, reporter, period start, imported, records
        ("b.example.com", "Zeta", 300, t1, 2),
        ("A.example.net", "alpha", 100, t2, 0),
        ("c.example.org", "Mid", 200, t1, 5),
    ]
    tls = [  # domain, reporter, period start, imported, policies
        ("a.example.com", "beta", 150, t3, 1),
        ("b.example.com", "Zeta", 300, t1, 2),
        ("d.example.com", None, 50, t2, 0),
    ]
    expected = []
    with Session(isolated) as db:
        for i, (domain, org, begin, created, n) in enumerate(dmarc):
            report = DMARCReport(report_id=f"sort-d{i}", domain=domain, org_name=org or "", begin_date=begin,
                                 end_date=begin + 10, created_at=created)
            db.add(report)
            db.flush()
            db.add_all([DMARCRecord(dmarc_report_id=report.id, source_ip="192.0.2.1", count=1) for _ in range(n)])
            expected.append({"type": "dmarc", "id": report.id, "domain": domain.lower(), "reporter": org.lower(),
                             "records": n, "period": begin, "created_at": created})
        for i, (domain, org, begin, created, n) in enumerate(tls):
            start = datetime(1970, 1, 1) + timedelta(seconds=begin)
            report = TLSReport(report_id=f"sort-t{i}", policy_domain=domain, organization_name=org,
                               start_datetime=start, end_datetime=start, created_at=created)
            db.add(report)
            db.flush()
            db.add_all([TLSReportPolicy(tls_report_id=report.id, policy_domain=domain) for _ in range(n)])
            expected.append({"type": "tls", "id": report.id, "domain": domain.lower(),
                             "reporter": org.lower() if org else None, "records": n, "period": begin,
                             "created_at": created})
        db.commit()
    return expected


def python_order(rows, sort_by, sort_dir):
    """The documented order: the key (empty values last), then newest import, type, highest id."""
    rows = sorted(rows, key=lambda r: -r["id"])
    rows = sorted(rows, key=lambda r: r["type"])
    rows = sorted(rows, key=lambda r: r["created_at"], reverse=True)
    if sort_by == "created_at" and sort_dir == "desc":
        return rows
    present = [r for r in rows if r[sort_by] is not None]
    empty = [r for r in rows if r[sort_by] is None]
    return sorted(present, key=lambda r: r[sort_by], reverse=sort_dir == "desc") + empty


def all_pages(client, limit=2, **params):
    first = client.get("/dmarc/reports/all", params={"page": 1, "limit": limit, **params}).json()
    rows = []
    for page in range(1, first["total_pages"] + 1):
        payload = client.get("/dmarc/reports/all", params={"page": page, "limit": limit, **params}).json()
        assert payload["page"] == page
        rows += [(row["type"], row["id"]) for row in payload["reports"]]
    return first, rows


@pytest.mark.parametrize("sort_dir", ["asc", "desc"])
@pytest.mark.parametrize("sort_by", ["created_at", "type", "domain", "reporter", "records", "period"])
def test_every_column_sorts_across_pages_and_types(db_client, sort_by, sort_dir):
    client, isolated = db_client
    expected = seed_sort(isolated)
    first, rows = all_pages(client, sort_by=sort_by, sort_dir=sort_dir)
    assert (first["sort_by"], first["sort_dir"], first["total"]) == (sort_by, sort_dir, 6)
    assert rows == [(r["type"], r["id"]) for r in python_order(expected, sort_by, sort_dir)]
    # The same order on every request, at any page size
    assert all_pages(client, limit=4, sort_by=sort_by, sort_dir=sort_dir)[1] == rows
    assert all_pages(client, limit=6, sort_by=sort_by, sort_dir=sort_dir)[1] == rows


def test_default_order_is_the_newest_import_first(db_client):
    client, isolated = db_client
    expected = seed_sort(isolated)
    assert all_pages(client)[1] == [(r["type"], r["id"]) for r in python_order(expected, "created_at", "desc")]


def test_sort_works_with_the_search(db_client):
    client, isolated = db_client
    expected = seed_sort(isolated)
    first, rows = all_pages(client, search="example.com", sort_by="records", sort_dir="asc")
    matching = [r for r in expected if r["domain"].endswith("example.com")]
    assert first["total"] == 4
    assert rows == [(r["type"], r["id"]) for r in python_order(matching, "records", "asc")]


@pytest.mark.parametrize("query", ["sort_by=raw_xml", "sort_by=id;drop", "sort_by=", "sort_dir=up", "sort_dir=DESC"])
def test_unknown_sort_values_are_refused(db_client, query):
    client, _ = db_client
    assert client.get(f"/dmarc/reports/all?page=1&{query}").status_code == 422
