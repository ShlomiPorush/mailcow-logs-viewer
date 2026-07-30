"""DMARC pass = aligned SPF OR aligned DKIM passed (RFC 7489).

Regression for the domains table / overview / sources computing pass with
AND (both must pass), which wildly understated the rate for mail that
passes only one mechanism (e.g. forwarded mail breaks SPF, DKIM survives)
and contradicted the Insights panel.
"""
import time

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.database import init_db, SessionLocal
from app.models import DMARCReport, DMARCRecord


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def seeded_domain():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    init_db()
    db = SessionLocal()
    domain = "passrate-test.example"
    db.query(DMARCRecord).filter(DMARCRecord.dmarc_report_id.in_(
        db.query(DMARCReport.id).filter(DMARCReport.domain == domain)
    )).delete(synchronize_session=False)
    db.query(DMARCReport).filter(DMARCReport.domain == domain).delete()
    now = int(time.time())
    report = DMARCReport(domain=domain, org_name="test", report_id=f"rpt-{now}",
                         begin_date=now - 3600, end_date=now)
    db.add(report)
    db.flush()
    # 10 both-pass, 30 dkim-only, 40 spf-only, 20 both-fail -> 80% DMARC pass
    for spf, dkim, count in [("pass", "pass", 10), ("fail", "pass", 30),
                             ("pass", "fail", 40), ("fail", "fail", 20)]:
        db.add(DMARCRecord(dmarc_report_id=report.id, source_ip="192.0.2.1",
                           count=count, spf_result=spf, dkim_result=dkim,
                           disposition="none"))
    db.commit()
    yield domain
    db.query(DMARCRecord).filter(DMARCRecord.dmarc_report_id == report.id).delete()
    db.query(DMARCReport).filter(DMARCReport.id == report.id).delete()
    db.commit()
    db.close()


def test_domains_table_pass_rate_uses_or_semantics(seeded_domain):
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)
    payload = client.get("/api/dmarc/domains").json()
    row = next((d for d in payload.get("domains", []) if d["domain"] == seeded_domain), None)
    assert row is not None, payload
    assert row["stats_30d"]["dmarc_pass_pct"] == 80.0, row["stats_30d"]
