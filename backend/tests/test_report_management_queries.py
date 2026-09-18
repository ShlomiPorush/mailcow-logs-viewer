"""Report management returns correct counts with a constant query budget."""
import uuid
from datetime import datetime, timedelta
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.database import engine, Base
from app.database import get_db
from app.models import DMARCReport, DMARCRecord, TLSReport, TLSReportPolicy
from app.routers.dmarc import get_all_reports, router


@pytest.mark.parametrize("size", [0, 1, 100])
def test_report_counts_and_query_budget(size):
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    schema = "report_counts_test_" + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    isolated = create_engine(engine.url, connect_args={"options": f"-csearch_path={schema}"})
    try:
        Base.metadata.create_all(isolated, tables=[model.__table__ for model in
            (DMARCReport, DMARCRecord, TLSReport, TLSReportPolicy)])
        expected = {}
        with Session(isolated) as db:
            for index in range(size):
                stamp = datetime(2026, 1, 1) + timedelta(seconds=index)
                dmarc = DMARCReport(report_id=f"dmarc-{index}", domain="example.com", org_name="Test",
                                    begin_date=1, end_date=2, created_at=stamp, raw_xml="x" * 10000)
                tls = TLSReport(report_id=f"tls-{index}", policy_domain="example.com", organization_name="Test",
                                start_datetime=stamp, end_datetime=stamp, created_at=stamp, raw_json="x" * 10000)
                db.add_all([dmarc, tls])
                db.flush()
                count = index % 3
                for _ in range(count):
                    db.add(DMARCRecord(dmarc_report_id=dmarc.id, source_ip="192.0.2.1", count=50))
                    db.add(TLSReportPolicy(tls_report_id=tls.id, policy_domain="example.com"))
                expected["dmarc", dmarc.id] = count
                expected["tls", tls.id] = count
            db.commit()
        statements = []
        def capture(conn, cursor, statement, parameters, context, executemany):
            statements.append(statement)
        event.listen(isolated, "before_cursor_execute", capture)
        try:
            with Session(isolated) as db:
                result = get_all_reports(db)
        finally:
            event.remove(isolated, "before_cursor_execute", capture)
        assert result["total"] == size * 2
        assert {(row["type"], row["id"]): row["record_count"] for row in result["reports"]} == expected
        dates = [row["created_at"] for row in result["reports"]]
        assert dates == sorted(dates, reverse=True)
        assert all(set(row) == {"id", "type", "domain", "org_name", "begin_date", "end_date",
                               "record_count", "created_at", "report_id"} for row in result["reports"])
        for statement in statements:
            assert "raw_xml" not in statement
            assert "raw_json" not in statement
            assert "policy_published" not in statement
        assert len(statements) == 2, f"Executed {len(statements)} queries for {size * 2} reports"

        app = FastAPI()
        app.include_router(router)
        def session_override():
            with Session(isolated) as db:
                yield db
        app.dependency_overrides[get_db] = session_override
        with TestClient(app) as client:
            pages = max(1, (size * 2 + 6) // 7)
            seen = {}
            for page in range(1, pages + 1):
                statements.clear()
                event.listen(isolated, "before_cursor_execute", capture)
                try:
                    response = client.get(f"/dmarc/reports/all?page={page}&limit=7")
                finally:
                    event.remove(isolated, "before_cursor_execute", capture)
                assert response.status_code == 200
                payload = response.json()
                assert len(payload["reports"]) <= 7
                assert payload["total"] == size * 2
                assert payload["page"] == page
                assert payload["total_pages"] == pages
                assert payload["limit"] == 7
                assert len(statements) <= 4
                for statement in statements:
                    assert "raw_xml" not in statement
                    assert "raw_json" not in statement
                for row in payload["reports"]:
                    key = row["type"], row["id"]
                    assert key not in seen
                    seen[key] = row["record_count"]
            assert seen == expected
            # Equal timestamps across report types must not shuffle between pages.
            first = client.get("/dmarc/reports/all?page=1&limit=7").json()
            assert [(r["type"], r["id"]) for r in first["reports"]] == list(seen)[:7]
            assert client.get("/dmarc/reports/all?page=999&limit=7").json()["page"] == pages
            for query in ("page=0", "page=-1", "page=one", "page=1&limit=0", "page=1&limit=201"):
                assert client.get(f"/dmarc/reports/all?{query}").status_code == 422
            if size:
                ordered = sorted(result["reports"], key=lambda row: (
                    -datetime.fromisoformat(row["created_at"]).timestamp(), row["type"], -row["id"]))
                assert list(seen) == [(row["type"], row["id"]) for row in ordered]
                # Removing a final page must land on the last remaining page.
                last_id = ordered[-1]["id"]
                with Session(isolated) as db:
                    db.query(DMARCRecord).delete()
                    db.query(TLSReportPolicy).delete()
                    db.query(DMARCReport).delete()
                    db.query(TLSReport).filter(TLSReport.id != last_id).delete()
                    db.query(TLSReport).update({TLSReport.created_at: None})
                    db.commit()
                remaining = client.get(f"/dmarc/reports/all?page={pages}&limit=7").json()
                assert remaining["page"] == remaining["total_pages"] == remaining["total"] == 1
                assert remaining["reports"][0]["created_at"] is None
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
            assert conn.execute(text("SELECT count(*) FROM information_schema.schemata WHERE schema_name=:name"),
                                {"name": schema}).scalar() == 0
