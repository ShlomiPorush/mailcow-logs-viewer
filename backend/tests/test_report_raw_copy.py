"""Parsed DMARC / TLS-RPT reports keep only the parsed data.

The original report text was stored next to the parsed rows but never read,
so it only multiplied memory and disk use for every report (and for a hostile
one up to the decompression cap). Parsing and both write paths (IMAP sync and
manual upload) must drop it, the migration must clear existing copies, and the
decompression cap must reject an oversized report while real ones still parse.
"""
import asyncio
import gzip
import importlib.util
import json
import pathlib
import uuid
from contextlib import contextmanager
from email.message import EmailMessage
from unittest.mock import Mock

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import create_engine, text

from app.config import settings
from app.models import DMARCReport, TLSReport
from app.routers import dmarc
from app.services.dmarc_imap_service import DMARCImapService
from app.services.dmarc_parser import parse_dmarc_file
from app.services.safe_decompress import (
    DecompressionLimitError,
    MAX_COMPRESSED_BYTES,
    MAX_DECOMPRESSED_BYTES,
    gzip_decompress_limited,
)
from app.services.tls_rpt_parser import parse_tls_rpt_file

MIB = 1024 * 1024

_RECORD = """  <record>
    <row>
      <source_ip>192.0.2.{n}</source_ip>
      <count>3</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
"""


def dmarc_xml(records: int = 1, report_id: str = "raw-copy-dmarc") -> str:
    body = "".join(_RECORD.format(n=(i % 250) + 1) for i in range(records))
    return f"""<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>reporter.example.com</org_name>
    <email>dmarc@reporter.example.com</email>
    <report_id>{report_id}</report_id>
    <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><p>none</p></policy_published>
{body}</feedback>"""


def tls_json(report_id: str = "raw-copy-tls") -> str:
    return json.dumps({
        "organization-name": "reporter.example.com",
        "date-range": {"start-datetime": "2026-01-12T00:00:00Z", "end-datetime": "2026-01-12T23:59:59Z"},
        "contact-info": "tls@reporter.example.com",
        "report-id": report_id,
        "policies": [{
            "policy": {"policy-type": "sts", "policy-domain": "example.com",
                       "policy-string": ["version: STSv1"], "mx-host": ["mail.example.com"]},
            "summary": {"total-successful-session-count": 5, "total-failure-session-count": 0},
        }],
    })


# -- parsing ----------------------------------------------------------------

def test_parsed_dmarc_report_carries_no_raw_copy():
    parsed = parse_dmarc_file(gzip.compress(dmarc_xml().encode()), "report.xml.gz")
    assert parsed is not None and parsed["report_id"] == "raw-copy-dmarc"
    assert "raw_xml" not in parsed


def test_parsed_tls_report_carries_no_raw_copy():
    parsed = parse_tls_rpt_file(gzip.compress(tls_json().encode()), "report.json.gz")
    assert parsed is not None and parsed["report_id"] == "raw-copy-tls"
    assert "raw_json" not in parsed


# -- decompression cap --------------------------------------------------------

def test_decompression_cap_is_ten_mib():
    assert MAX_DECOMPRESSED_BYTES == 10 * MIB
    # The compressed input may never be larger than what it may expand to
    assert MAX_COMPRESSED_BYTES <= MAX_DECOMPRESSED_BYTES


def test_gzip_expanding_beyond_ten_mib_is_rejected():
    bomb = gzip.compress(b" " * (11 * MIB))
    assert len(bomb) < 100 * 1024
    with pytest.raises(DecompressionLimitError):
        gzip_decompress_limited(bomb)
    assert parse_dmarc_file(bomb, "report.xml.gz") is None
    assert parse_tls_rpt_file(bomb, "report.json.gz") is None


def test_large_realistic_report_still_parses():
    # Several thousand rows is far above what real senders put in one report
    xml = dmarc_xml(records=8000)
    assert 2 * MIB < len(xml) < MAX_DECOMPRESSED_BYTES
    parsed = parse_dmarc_file(gzip.compress(xml.encode()), "report.xml.gz")
    assert parsed is not None and len(parsed["records"]) == 8000


# -- write paths --------------------------------------------------------------

def _recording_db():
    db = Mock()
    db.query.return_value.filter.return_value.first.return_value = None
    added = []

    def add(row):
        row.id = len(added) + 1
        added.append(row)

    db.add.side_effect = add
    return db, added


def _stored(added, model):
    rows = [row for row in added if isinstance(row, model)]
    assert len(rows) == 1
    return rows[0]


def test_upload_stores_no_raw_copy(monkeypatch):
    monkeypatch.setattr(settings._inner, "dmarc_manual_upload_enabled", True)
    db, added = _recording_db()

    @contextmanager
    def session():
        yield db

    monkeypatch.setattr(dmarc, "SessionLocal", session)
    monkeypatch.setattr(dmarc, "enrich_dmarc_record", lambda row: row)
    monkeypatch.setattr(dmarc, "clear_dmarc_cache", Mock())
    app = FastAPI()
    app.include_router(dmarc.router)

    async def upload(name, content):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
            response = await api.post("/dmarc/upload", files={"file": (name, content)})
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "success"

    asyncio.run(upload("report.xml.gz", gzip.compress(dmarc_xml().encode())))
    asyncio.run(upload("report.json", tls_json().encode()))
    assert _stored(added, DMARCReport).raw_xml is None
    assert _stored(added, TLSReport).raw_json is None


def _report_mail(filename: str, content: bytes, subtype: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = "Report"
    msg["From"] = "reports@reporter.example.com"
    msg["To"] = "dmarc@example.com"
    msg.set_content("Report attached")
    msg.add_attachment(content, maintype="application", subtype=subtype, filename=filename)
    return msg


def _result():
    return {"reports_created": 0, "reports_duplicate": 0, "error": None}


def test_imap_sync_stores_no_raw_copy(monkeypatch):
    import app.services.dmarc_imap_service as imap_module
    monkeypatch.setattr(imap_module, "enrich_dmarc_record", lambda row: row)
    service = DMARCImapService()

    db, added = _recording_db()
    msg = _report_mail("report.xml.gz", gzip.compress(dmarc_xml().encode()), "gzip")
    result = service._process_dmarc_email(msg, db, _result())
    assert result["reports_created"] == 1, result
    assert _stored(added, DMARCReport).raw_xml is None

    db, added = _recording_db()
    msg = _report_mail("report.json.gz", gzip.compress(tls_json().encode()), "tlsrpt+gzip")
    result = service._process_tls_rpt_email(msg, db, _result())
    assert result["reports_created"] == 1, result
    assert _stored(added, TLSReport).raw_json is None


# -- migration ------------------------------------------------------------------

def _load_revision():
    versions = pathlib.Path(__file__).resolve().parent.parent / "alembic" / "versions"
    matches = sorted(versions.glob("*_clear_raw_report_copies.py"))
    assert matches, "migration that clears the stored report copies is missing"
    spec = importlib.util.spec_from_file_location("clear_raw_report_copies", matches[0])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_clears_existing_raw_copies():
    from app.database import engine
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    revision = _load_revision()

    from datetime import datetime
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy.orm import Session
    from app.database import Base

    schema = "raw_copy_test_" + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    isolated = create_engine(engine.url, connect_args={"options": f"-csearch_path={schema}"})
    try:
        Base.metadata.create_all(isolated, tables=[DMARCReport.__table__, TLSReport.__table__])
        stamp = datetime(2026, 1, 1)
        with Session(isolated) as db:
            for i in range(3):
                db.add(DMARCReport(report_id=f"d-{i}", domain="example.com", org_name="reporter.example.com",
                                   begin_date=1, end_date=2, raw_xml="<feedback/>" * 100))
                db.add(TLSReport(report_id=f"t-{i}", policy_domain="example.com",
                                 organization_name="reporter.example.com", start_datetime=stamp,
                                 end_datetime=stamp, raw_json="{}" * 100))
            db.add(DMARCReport(report_id="d-empty", domain="example.com", org_name="reporter.example.com",
                               begin_date=1, end_date=2, raw_xml=None))
            db.commit()

        with isolated.begin() as conn:
            with Operations.context(MigrationContext.configure(conn)):
                revision.upgrade()

        with isolated.connect() as conn:
            assert conn.execute(text("SELECT count(*) FROM dmarc_reports")).scalar() == 4
            assert conn.execute(text("SELECT count(*) FROM tls_reports")).scalar() == 3
            assert conn.execute(text("SELECT count(*) FROM dmarc_reports WHERE raw_xml IS NOT NULL")).scalar() == 0
            assert conn.execute(text("SELECT count(*) FROM tls_reports WHERE raw_json IS NOT NULL")).scalar() == 0
            # The parsed data stays
            assert conn.execute(text(
                "SELECT count(*) FROM dmarc_reports WHERE domain = 'example.com' AND org_name = 'reporter.example.com'"
            )).scalar() == 4
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
