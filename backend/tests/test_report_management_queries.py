"""Report management returns correct counts with a constant query budget."""
import uuid
from datetime import datetime, timedelta
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session
from app.database import engine, Base
from app.models import DMARCReport, DMARCRecord, TLSReport, TLSReportPolicy
from app.routers.dmarc import get_all_reports


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
                                    begin_date=1, end_date=2, created_at=stamp)
                tls = TLSReport(report_id=f"tls-{index}", policy_domain="example.com", organization_name="Test",
                                start_datetime=stamp, end_datetime=stamp, created_at=stamp)
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
        assert len(statements) == 2, f"Executed {len(statements)} queries for {size * 2} reports"
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
            assert conn.execute(text("SELECT count(*) FROM information_schema.schemata WHERE schema_name=:name"),
                                {"name": schema}).scalar() == 0
