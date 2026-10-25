"""A report is a duplicate only when its whole content is stored already, and
one email can store only so much.

Anyone can mail the report address, and the report_id is a field the sender
writes. Deduplicating on report_id alone let a sender claim the report_id of
a real reporter's coming report: the real report was then dropped as a
duplicate and its email deleted. And with no limit on report files per email
or records per report, a few KB of mail stored tens of thousands of rows.

These tests run the real IMAP processing and upload paths against PostgreSQL.
"""
import gzip
import importlib.util
import io
import json
import pathlib
import uuid
import zipfile
from datetime import datetime
from email.message import EmailMessage
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import DMARCRecord, DMARCReport, DMARCSync, TLSReport, TLSReportPolicy
from app.routers import dmarc as dmarc_router
from app.services import dmarc_imap_service as imap_module
from app.services import report_store
from app.services.dmarc_imap_service import DMARCImapService
from app.services.dmarc_parser import parse_dmarc_file
from app.services.report_identity import (
    MAX_REPORT_ATTACHMENTS_PER_EMAIL,
    MAX_REPORT_ITEMS,
    ReportLimitError,
    ReportRejectedError,
)
from app.services.tls_rpt_parser import parse_tls_rpt_file
from tests.test_dmarc_imap_bounces import FakeImap

TABLES = [DMARCReport.__table__, DMARCRecord.__table__, TLSReport.__table__,
          TLSReportPolicy.__table__, DMARCSync.__table__]


# -- reports ------------------------------------------------------------------

def dmarc_xml(report_id="rid-1", org="reporter.example.com", domain="example.com",
              records=(("192.0.2.1", 5, "pass", "pass"),), begin=1700000000, end=1700086400):
    rows = "".join(
        f"<record><row><source_ip>{ip}</source_ip><count>{count}</count>"
        f"<policy_evaluated><disposition>none</disposition><dkim>{dkim}</dkim><spf>{spf}</spf>"
        f"</policy_evaluated></row><identifiers><header_from>{domain}</header_from></identifiers>"
        f"<auth_results><spf><domain>{domain}</domain><result>{spf}</result></spf></auth_results></record>"
        for ip, count, dkim, spf in records)
    return (f'<?xml version="1.0"?><feedback><report_metadata><org_name>{org}</org_name>'
            f"<email>dmarc@{org}</email><report_id>{report_id}</report_id>"
            f"<date_range><begin>{begin}</begin><end>{end}</end></date_range></report_metadata>"
            f"<policy_published><domain>{domain}</domain><p>none</p></policy_published>{rows}</feedback>")


def dmarc_gz(*args, **kwargs) -> bytes:
    return gzip.compress(dmarc_xml(*args, **kwargs).encode())


def distinct_records(n, start=0):
    return [(f"2001:db8::{start + i + 1:x}", 1, "pass", "pass") for i in range(n)]


def tls_json(report_id="2026-11-02T00:00:00Z_example.com", org="Reporter Inc.",
             contact="tls@reporter.example.com", policies=((3, 21, None),)) -> bytes:
    entries = []
    for success, failure, details in policies:
        entry = {"policy": {"policy-type": "sts", "policy-domain": "example.com",
                            "policy-string": ["version: STSv1", "mode: enforce"],
                            "mx-host": ["mail.example.com"]},
                 "summary": {"total-successful-session-count": success,
                             "total-failure-session-count": failure}}
        if details is not None:
            entry["failure-details"] = details
        entries.append(entry)
    return json.dumps({"organization-name": org, "contact-info": contact, "report-id": report_id,
                       "date-range": {"start-datetime": "2026-11-02T00:00:00Z",
                                      "end-datetime": "2026-11-02T23:59:59Z"},
                       "policies": entries}).encode()


def failures(n):
    return [{"result-type": "starttls-not-supported", "sending-mta-ip": "198.51.100.7",
             "receiving-mx-hostname": "mail.example.com", "failed-session-count": 1}] * n


def mail(*files, uid="1", sender="reports@reporter.example.com"):
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = "dmarc@example.com"
    msg["Subject"] = "Report Domain: example.com Submitter: reporter.example.com"
    msg["Message-ID"] = f"<{uid}@reporter.example.com>"
    msg.set_content("Report attached.")
    for filename, content in files:
        msg.add_attachment(content, maintype="application", subtype="octet-stream", filename=filename)
    return msg.as_bytes()


def zipped(*members) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in members:
            archive.writestr(name, content)
    return buffer.getvalue()


# -- database -----------------------------------------------------------------

def _postgres():
    from app.database import engine
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    return engine


@pytest.fixture
def isolated_engine():
    engine = _postgres()
    schema = "report_identity_" + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    isolated = create_engine(engine.url, connect_args={"options": f"-csearch_path={schema}"})
    try:
        yield isolated
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))


@pytest.fixture
def env(isolated_engine, monkeypatch):
    Base.metadata.create_all(isolated_engine, tables=TABLES)
    Session = sessionmaker(bind=isolated_engine, autoflush=False)
    notify, cache = Mock(return_value=True), Mock()
    monkeypatch.setattr(imap_module, "SessionLocal", Session)
    monkeypatch.setattr(imap_module, "send_dmarc_error_notification", notify)
    monkeypatch.setattr(imap_module, "clear_dmarc_cache", cache)
    monkeypatch.setattr(dmarc_router, "SessionLocal", Session)
    monkeypatch.setattr(dmarc_router, "clear_dmarc_cache", Mock())
    monkeypatch.setattr(report_store, "enrich_dmarc_record", lambda row: row)
    return SimpleNamespace(engine=isolated_engine, Session=Session, notify=notify, cache=cache)


def sync(mails, delete_after=True):
    service = DMARCImapService()
    service.delete_after = delete_after
    service.scan_all_unseen = False
    service.connection = FakeImap(mails)
    service.connect = lambda: True
    service.select_folder = lambda: True
    service.disconnect = lambda: None
    return service.sync_reports("manual"), service.connection


def count(env, model, **filters):
    with env.Session() as db:
        return db.query(model).filter_by(**filters).count()


def upload(filename, content):
    return dmarc_router._upload_report_worker(content, filename)


# -- C06: report_id is not the identity ------------------------------------

def test_a_report_id_claimed_by_another_sender_does_not_drop_the_real_report(env):
    forged_tls = tls_json(org="Reporter Inc.", contact="x@attacker.invalid", policies=((50, 0, None),))
    real_tls = tls_json(org="Reporter Inc.", contact="tls@reporter.example.com",
                        policies=((3, 21, failures(2)),))
    forged_dmarc = dmarc_gz(org="attacker.invalid", records=[("192.0.2.1", 7, "pass", "pass")])
    real_dmarc = dmarc_gz(org="reporter.example.com", records=[("198.51.100.7", 4, "fail", "fail")])

    result, imap = sync({1: mail(("f.json", forged_tls), sender="x@attacker.invalid"),
                         2: mail(("f.xml.gz", forged_dmarc), sender="x@attacker.invalid"),
                         3: mail(("r.json", real_tls), uid="3"),
                         4: mail(("r.xml.gz", real_dmarc), uid="4")})

    assert result["reports_created"] == 4 and result["reports_duplicate"] == 0, result
    assert count(env, TLSReport, report_id="2026-11-02T00:00:00Z_example.com") == 2
    assert count(env, DMARCReport, report_id="rid-1") == 2
    # The real reports' emails stay in the mailbox: they share an ID with another report
    assert b"3" not in imap.deleted and b"4" not in imap.deleted
    assert {b"3", b"4"} <= imap.seen
    assert result["failed_emails"] is None
    with env.Session() as db:
        failed = db.query(TLSReportPolicy.failed_session_count).join(
            TLSReport, TLSReport.id == TLSReportPolicy.tls_report_id).filter(
            TLSReport.contact_info == "tls@reporter.example.com").scalar()
    assert failed == 21


def test_a_forgery_with_the_real_metadata_but_other_records_is_kept_apart(env):
    # Same report_id, org, contact, domain and dates; only the counts differ
    forged = dmarc_gz(records=[("192.0.2.1", 99, "pass", "pass")])
    real = dmarc_gz(records=[("192.0.2.1", 5, "fail", "fail")])
    assert upload("forged.xml.gz", forged)["status"] == "success"
    response = upload("real.xml.gz", real)
    assert response["status"] == "success", response
    assert "same report ID" in response["message"]
    assert count(env, DMARCReport, report_id="rid-1") == 2

    forged_tls = tls_json(policies=((50, 0, None),))
    real_tls = tls_json(policies=((3, 21, None),))
    assert upload("forged.json", forged_tls)["status"] == "success"
    assert upload("real.json", real_tls)["status"] == "success"
    assert count(env, TLSReport) == 2


def test_the_same_report_again_is_a_duplicate_and_its_email_is_deleted(env):
    report = dmarc_gz(records=distinct_records(3))
    first, imap = sync({1: mail(("a.xml.gz", report))})
    assert first["reports_created"] == 1 and b"1" in imap.deleted
    again, imap = sync({2: mail(("a.xml.gz", report), uid="2")})
    assert again["reports_created"] == 0 and again["reports_duplicate"] == 1, again
    assert b"2" in imap.deleted
    assert upload("a.xml.gz", report)["status"] == "duplicate"
    assert upload("t.json", tls_json())["status"] == "success"
    assert upload("t.json", tls_json())["status"] == "duplicate"
    assert count(env, DMARCReport) == 1 and count(env, TLSReport) == 1


def test_the_reports_list_marks_reports_that_share_a_report_id(env):
    upload("a.xml.gz", dmarc_gz(records=[("192.0.2.1", 1, "pass", "pass")]))
    upload("b.xml.gz", dmarc_gz(records=[("192.0.2.2", 1, "pass", "pass")]))
    upload("c.xml.gz", dmarc_gz(report_id="rid-other"))
    upload("t.json", tls_json())
    with env.Session() as db:
        rows = dmarc_router.get_all_reports(db)["reports"]
    shared = {(row["type"], row["report_id"], row["shared_report_id"]) for row in rows}
    assert shared == {("dmarc", "rid-1", True), ("dmarc", "rid-other", False),
                      ("tls", "2026-11-02T00:00:00Z_example.com", False)}


# -- C05: limits per email ----------------------------------------------------

def test_identical_records_are_stored_once_with_their_counts_added(env):
    records = [("192.0.2.7", 1, "pass", "pass")] * 20_000
    content = dmarc_gz(records=records)
    assert len(content) < 50_000
    result, _ = sync({1: mail(("a.xml.gz", content))})
    assert result["reports_created"] == 1
    with env.Session() as db:
        rows = db.query(DMARCRecord.count).all()
    assert rows == [(20_000,)]


@pytest.mark.parametrize("files", [
    "too many files",
    "too many records in one report",
    "valid and over-limit TLS-RPT",
    "over the total of the email",
    "over the data size",
    "valid report and one that expands too far",
])
def test_an_email_over_a_limit_stores_nothing_and_is_kept_as_failed(env, files):
    if files == "too many files":
        attachments = [(f"{i}.xml.gz", dmarc_gz(report_id=f"rid-{i}"))
                       for i in range(MAX_REPORT_ATTACHMENTS_PER_EMAIL + 1)]
    elif files == "too many records in one report":
        attachments = [("a.xml.gz", dmarc_gz(records=distinct_records(MAX_REPORT_ITEMS + 1)))]
    elif files == "valid and over-limit TLS-RPT":
        attachments = [("ok.json", tls_json(report_id="ok")),
                       ("big.json.gz", gzip.compress(tls_json(policies=((1, 1, failures(MAX_REPORT_ITEMS)),))))]
    elif files == "over the total of the email":
        attachments = [("a.xml.gz", dmarc_gz(report_id="a", records=distinct_records(12_000))),
                       ("b.xml.gz", dmarc_gz(report_id="b", records=distinct_records(12_000, 12_000)))]
    elif files == "valid report and one that expands too far":
        attachments = [("ok.xml.gz", dmarc_gz()), ("bomb.json.gz", gzip.compress(b" " * (11 * 1024 * 1024)))]
    else:
        big = [{"result-type": "certificate-expired", "additional-information": "x" * 6_000_000}]
        attachments = [("a.json.gz", gzip.compress(tls_json(report_id="a", policies=((1, 1, big),)))),
                       ("b.json.gz", gzip.compress(tls_json(report_id="b", policies=((1, 1, big),))))]

    result, imap = sync({1: mail(*attachments)})

    assert count(env, DMARCReport) == 0 and count(env, DMARCRecord) == 0
    assert count(env, TLSReport) == 0 and count(env, TLSReportPolicy) == 0
    assert result["reports_created"] == 0 and result["reports_failed"] == 1, result
    assert b"1" not in imap.deleted and b"1" in imap.seen
    assert result["failed_emails"][0]["message_id"] == "<1@reporter.example.com>"
    assert "nothing" in result["failed_emails"][0]["error"].lower()
    env.notify.assert_called_once()


def test_an_email_exactly_at_the_limits_is_imported(env):
    half = MAX_REPORT_ITEMS // 2
    result, imap = sync({1: mail(("a.xml.gz", dmarc_gz(report_id="a", records=distinct_records(half))),
                                 ("b.xml.gz", dmarc_gz(report_id="b", records=distinct_records(half, half))))})
    assert result["reports_created"] == 2, result
    assert count(env, DMARCRecord) == MAX_REPORT_ITEMS
    assert b"1" in imap.deleted


def test_an_upload_over_a_limit_is_refused_with_400(env):
    with pytest.raises(HTTPException) as refused:
        upload("a.xml.gz", dmarc_gz(records=distinct_records(MAX_REPORT_ITEMS + 1)))
    assert refused.value.status_code == 400
    assert "20,000 records" in refused.value.detail
    assert count(env, DMARCReport) == 0


def test_real_size_reports_import(env):
    result, imap = sync({1: mail(("a.xml.gz", dmarc_gz(records=distinct_records(2_000)))),
                         2: mail(("t.json.gz", gzip.compress(tls_json(
                             policies=((10, 2, failures(40)), (500, 0, None), (7, 7, failures(300)))))), uid="2")})
    assert result["reports_created"] == 2 and result["failed_emails"] is None, result
    assert count(env, DMARCRecord) == 2_000 and count(env, TLSReportPolicy) == 3
    assert imap.deleted == {b"1", b"2"}


# -- every report of an email ---------------------------------------------------

@pytest.mark.parametrize("order", ["dmarc first", "tls first"])
def test_an_email_with_a_dmarc_and_a_tls_report_imports_both(env, order):
    files = [("a.xml.gz", dmarc_gz()), ("t.json", tls_json())]
    if order == "tls first":
        files.reverse()
    result, imap = sync({1: mail(*files)})
    assert result["reports_created"] == 2, result
    assert count(env, DMARCReport) == 1 and count(env, TLSReport) == 1
    assert b"1" in imap.deleted


def test_a_broken_report_keeps_the_email_and_counts_what_was_stored(env):
    result, imap = sync({1: mail(("a.xml.gz", dmarc_gz()), ("t.json", b"{not json"))})
    assert count(env, DMARCReport) == 1
    assert result["reports_created"] == 1 and result["reports_failed"] == 1, result
    assert b"1" not in imap.deleted and b"1" in imap.seen
    env.cache.assert_called_once()
    env.notify.assert_called_once()


def test_a_report_the_database_refuses_leaves_no_rows_and_keeps_the_email(env):
    # header_from is VARCHAR(255): the record insert fails inside its report
    long_domain = ("a" * 60 + ".") * 5 + "example.com"
    bad = gzip.compress(dmarc_xml(report_id="bad").replace(
        "<header_from>example.com</header_from>", f"<header_from>{long_domain}</header_from>").encode())
    result, imap = sync({1: mail(("good.xml.gz", dmarc_gz(report_id="good")), ("bad.xml.gz", bad))})
    assert count(env, DMARCReport, report_id="good") == 1
    assert count(env, DMARCReport, report_id="bad") == 0
    assert count(env, DMARCRecord) == 1
    assert result["reports_created"] == 1 and result["reports_failed"] == 1, result
    assert b"1" not in imap.deleted


def test_a_failed_commit_counts_nothing_and_keeps_the_email(env, monkeypatch):
    service = DMARCImapService()
    with env.Session() as db:
        monkeypatch.setattr(db, "commit", Mock(side_effect=RuntimeError("Database unavailable")))
        result = service._process_reports(EmailMessage_from(mail(("a.xml.gz", dmarc_gz()))), db, {
            "success": False, "reports_created": 0, "reports_duplicate": 0, "error": None,
            "report_type": None, "skipped": None, "keep": False})
        # Rolled back in this session too, not only invisible to others
        assert db.query(DMARCReport).count() == 0 and db.query(DMARCRecord).count() == 0
    assert result["success"] is False and result["reports_created"] == 0
    assert "could not be saved" in result["error"]
    assert count(env, DMARCReport) == 0 and count(env, DMARCRecord) == 0


def test_two_imports_of_one_report_id_at_once_see_each_other(env):
    import threading
    first = report_store.prepare_report("dmarc", parse_dmarc_file(dmarc_gz(records=distinct_records(1)), "a"))
    second = report_store.prepare_report("dmarc", parse_dmarc_file(dmarc_gz(records=distinct_records(2)), "b"))
    outcome = {}
    with env.Session() as db:
        assert report_store.store_report(db, first)[0] == "created"

        def other_import():
            with env.Session() as other:
                outcome["status"] = report_store.store_report(other, second)[0]
                other.commit()

        thread = threading.Thread(target=other_import)
        thread.start()
        thread.join(1)
        # It waits for the first import to finish
        assert thread.is_alive() and "status" not in outcome
        db.commit()
    thread.join(10)
    assert outcome["status"] == "conflict"


def EmailMessage_from(raw: bytes):
    import email
    return email.message_from_bytes(raw)


@pytest.mark.parametrize("members", [
    [("a.xml", dmarc_xml(report_id="a")), ("b.xml", dmarc_xml(report_id="b"))],
    [("a.json", tls_json(report_id="a")), ("b.json", tls_json(report_id="b"))],
    [("a.xml", dmarc_xml(report_id="a")), ("b.json", tls_json(report_id="b"))],
])
def test_a_zip_with_several_reports_is_refused(env, members):
    archive = zipped(*members)
    result, imap = sync({1: mail(("reports.zip", archive))})
    assert result["reports_failed"] == 1 and b"1" not in imap.deleted
    assert "more than one report" in result["failed_emails"][0]["error"]
    assert count(env, DMARCReport) == 0 and count(env, TLSReport) == 0
    with pytest.raises(HTTPException) as refused:
        upload("reports.zip", archive)
    assert refused.value.status_code == 400 and "more than one report" in refused.value.detail


# -- the content hash -----------------------------------------------------------

EDGE_DETAILS = [{"result-type": "validation-failure", "a": 1e23, "b": 1e20, "c": 1.0, "d": 0.1,
                 "e": -0.0, "f": None, "g": {"z": [1, 2.5, {"y": True}], "a": "text"}, "h": 1e300}]


def test_the_hash_of_a_stored_report_equals_its_hash_on_arrival(env):
    content = tls_json(policies=((1, 2, EDGE_DETAILS), (3, 4, None)))
    upload("t.json", content)
    upload("a.xml.gz", dmarc_gz(records=distinct_records(5)))
    with env.Session() as db:
        for kind, model in (("tls-rpt", TLSReport), ("dmarc", DMARCReport)):
            row = db.query(model).one()
            assert report_store.stored_content_hash(db, kind, row) == row.content_hash
    assert upload("t.json", content)["status"] == "duplicate"


def test_reports_stored_without_a_hash_are_matched_and_hashed(env):
    report = dmarc_gz(records=distinct_records(3))
    other = dmarc_gz(records=distinct_records(4))
    upload("a.xml.gz", report)
    upload("b.xml.gz", other)
    with env.engine.begin() as conn:
        # As an older version stores them: no hash, and the same report twice
        conn.execute(text("UPDATE dmarc_reports SET content_hash = NULL"))
        first = conn.execute(text("SELECT id FROM dmarc_reports ORDER BY id LIMIT 1")).scalar()
        copy = conn.execute(text(
            "INSERT INTO dmarc_reports (report_id, domain, org_name, email, begin_date, end_date, policy_published) "
            "SELECT report_id, domain, org_name, email, begin_date, end_date, policy_published "
            "FROM dmarc_reports WHERE id = :id RETURNING id"), {"id": first}).scalar()
        conn.execute(text(
            "INSERT INTO dmarc_records (dmarc_report_id, source_ip, count, disposition, dkim_result, spf_result, "
            "header_from, envelope_from, envelope_to, auth_results) SELECT :copy, source_ip, count, disposition, "
            "dkim_result, spf_result, header_from, envelope_from, envelope_to, auth_results FROM dmarc_records "
            "WHERE dmarc_report_id = :id"), {"copy": copy, "id": first})

    assert upload("a.xml.gz", report)["status"] == "duplicate"
    assert upload("b.xml.gz", other)["status"] == "duplicate"
    with env.Session() as db:
        hashes = [h for (h,) in db.query(DMARCReport.content_hash).order_by(DMARCReport.id)]
    # Each report got its hash; the second copy of the first one keeps none
    assert hashes[0] and hashes[1] and hashes[0] != hashes[1] and hashes[2] is None
    assert upload("c.xml.gz", dmarc_gz(records=distinct_records(9)))["status"] == "success"
    assert count(env, DMARCReport) == 4


def test_the_same_report_stored_at_the_same_moment_is_a_duplicate(env, monkeypatch):
    report = dmarc_gz()
    upload("a.xml.gz", report)
    # The other import stored it after this one looked for it
    original = report_store._same_report
    calls = []

    def missed_first(*args):
        calls.append(1)
        return None if len(calls) == 1 else original(*args)

    monkeypatch.setattr(report_store, "_same_report", missed_first)
    assert upload("a.xml.gz", report)["status"] == "duplicate"
    assert count(env, DMARCReport) == 1

    calls.clear()
    monkeypatch.setattr(report_store, "_constraint", lambda error: "some_other_constraint")
    with pytest.raises(IntegrityError):
        upload("a.xml.gz", report)


def test_a_record_count_that_merges_beyond_the_column_is_refused():
    big = [("192.0.2.1", 2**31 - 1, "pass", "pass"), ("192.0.2.1", 1, "pass", "pass")]
    assert parse_dmarc_file(dmarc_gz(records=big), "a.xml.gz") is None
    assert parse_dmarc_file(dmarc_gz(records=big[:1]), "a.xml.gz") is not None


@pytest.mark.parametrize("change", [
    {"report-id": 5}, {"organization-name": ["x"]}, {"contact-info": 1},
    {"summary": {"total-successful-session-count": "5"}},
    {"summary": {"total-successful-session-count": 1.5}},
    {"summary": {"total-successful-session-count": True}},
])
def test_tls_rpt_values_of_the_wrong_type_are_refused(change):
    data = json.loads(tls_json())
    if "summary" in change:
        data["policies"][0]["summary"].update(change["summary"])
    else:
        data.update(change)
    assert parse_tls_rpt_file(json.dumps(data).encode(), "t.json") is None


def test_limit_errors_reach_the_caller():
    with pytest.raises(ReportLimitError):
        parse_tls_rpt_file(tls_json(policies=((1, 1, failures(MAX_REPORT_ITEMS)),)), "t.json")
    with pytest.raises(ReportLimitError):
        parse_dmarc_file(dmarc_gz(records=distinct_records(MAX_REPORT_ITEMS + 1)), "a.xml.gz")
    with pytest.raises(ReportRejectedError):
        parse_dmarc_file(zipped(("a.xml", dmarc_xml()), ("b.json", "{}")), "a.zip")


# -- migration 0024 -------------------------------------------------------------

def _revision():
    path = next((pathlib.Path(__file__).resolve().parent.parent / "alembic" / "versions")
                .glob("0024_*.py"))
    spec = importlib.util.spec_from_file_location("report_content_hash", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


OLD_REPORT_TABLES = """
CREATE TABLE dmarc_reports (
    id SERIAL PRIMARY KEY, report_id VARCHAR(255) NOT NULL {legacy_unique}, domain VARCHAR(255) NOT NULL,
    org_name VARCHAR(255) NOT NULL, email VARCHAR(255), extra_contact_info TEXT, begin_date INTEGER NOT NULL,
    end_date INTEGER NOT NULL, policy_published JSONB, domain_id VARCHAR(255), raw_xml TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE tls_reports (
    id SERIAL PRIMARY KEY, report_id VARCHAR(255) NOT NULL, organization_name VARCHAR(255),
    contact_info VARCHAR(255), policy_domain VARCHAR(255) NOT NULL, start_datetime TIMESTAMP NOT NULL,
    end_datetime TIMESTAMP NOT NULL, raw_json TEXT, created_at TIMESTAMP, updated_at TIMESTAMP);
CREATE UNIQUE INDEX ix_tls_reports_report_id ON tls_reports (report_id);
"""


def _old_schema(engine, legacy):
    with engine.begin() as conn:
        for statement in OLD_REPORT_TABLES.format(legacy_unique="UNIQUE" if legacy else "").split(";"):
            if statement.strip():
                conn.execute(text(statement))
        if not legacy:
            conn.execute(text("CREATE UNIQUE INDEX ix_dmarc_reports_report_id ON dmarc_reports (report_id)"))
    Base.metadata.create_all(engine, tables=[DMARCRecord.__table__, TLSReportPolicy.__table__])


def _insert_old_dmarc(conn, parsed, split_first=False):
    report = conn.execute(text(
        "INSERT INTO dmarc_reports (report_id, domain, org_name, email, extra_contact_info, begin_date, "
        "end_date, policy_published) VALUES (:report_id, :domain, :org_name, :email, :extra_contact_info, "
        ":begin_date, :end_date, CAST(:policy_published AS JSONB)) RETURNING id"),
        {**{k: parsed[k] for k in ("report_id", "domain", "org_name", "email", "extra_contact_info",
                                     "begin_date", "end_date")},
         "policy_published": json.dumps(parsed["policy_published"])}).scalar()
    records = [dict(r) for r in parsed["records"]]
    if split_first:
        # An older version stored identical records as separate rows
        first = records[0]
        records[0:1] = [{**first, "count": 2}, {**first, "count": first["count"] - 2}]
    for record in records:
        conn.execute(text(
            "INSERT INTO dmarc_records (dmarc_report_id, source_ip, count, disposition, dkim_result, "
            "spf_result, header_from, envelope_from, envelope_to, auth_results) VALUES (:id, :source_ip, "
            ":count, :disposition, :dkim_result, :spf_result, :header_from, :envelope_from, :envelope_to, "
            "CAST(:auth_results AS JSONB))"),
            {**record, "id": report, "auth_results": json.dumps(record["auth_results"])})


def _insert_old_tls(conn, parsed):
    report = conn.execute(text(
        "INSERT INTO tls_reports (report_id, organization_name, contact_info, policy_domain, start_datetime, "
        "end_datetime) VALUES (:report_id, :organization_name, :contact_info, :policy_domain, "
        ":start_datetime, :end_datetime) RETURNING id"),
        {k: parsed[k] for k in ("report_id", "organization_name", "contact_info", "policy_domain",
                                "start_datetime", "end_datetime")}).scalar()
    for policy in parsed["policies"]:
        conn.execute(text(
            "INSERT INTO tls_report_policies (tls_report_id, policy_type, policy_domain, policy_string, mx_host, "
            "successful_session_count, failed_session_count, failure_details) VALUES (:id, :policy_type, "
            ":policy_domain, CAST(:policy_string AS JSONB), CAST(:mx_host AS JSONB), :successful_session_count, "
            ":failed_session_count, CAST(:failure_details AS JSONB))"),
            {**policy, "id": report, "policy_string": json.dumps(policy["policy_string"]),
             "mx_host": json.dumps(policy["mx_host"]), "failure_details": json.dumps(policy["failure_details"])})


def _upgrade(engine, revision):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            revision.upgrade()


@pytest.mark.parametrize("legacy", [True, False], ids=["legacy-constraint", "unique-index"])
def test_migration_hashes_old_reports_so_they_match_on_arrival(isolated_engine, legacy):
    revision = _revision()
    _old_schema(isolated_engine, legacy)
    dmarc_file = dmarc_gz(records=[("192.0.2.1", 5, "pass", "pass")] + distinct_records(3))
    tls_file = tls_json(policies=((1, 2, EDGE_DETAILS), (3, 4, None)))
    parsed_dmarc = parse_dmarc_file(dmarc_file, "a.xml.gz")
    parsed_tls = parse_tls_rpt_file(tls_file, "t.json")
    with isolated_engine.begin() as conn:
        _insert_old_dmarc(conn, parse_dmarc_file(dmarc_file, "a.xml.gz"), split_first=True)
        _insert_old_dmarc(conn, parse_dmarc_file(dmarc_gz(report_id="empty", records=[]), "e.xml.gz"))
        _insert_old_tls(conn, parsed_tls)

    _upgrade(isolated_engine, revision)

    inspector = inspect(isolated_engine)
    for table, constraint in (("dmarc_reports", "uq_dmarc_reports_report_id_hash"),
                              ("tls_reports", "uq_tls_reports_report_id_hash")):
        uniques = {u["name"]: u["column_names"] for u in inspector.get_unique_constraints(table)}
        assert uniques == {constraint: ["report_id", "content_hash"]}
        assert not [i for i in inspector.get_indexes(table) if i["column_names"] == ["report_id"]]
    with isolated_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM dmarc_reports WHERE content_hash IS NULL")).scalar() == 0
        dmarc_hash = conn.execute(text("SELECT content_hash FROM dmarc_reports WHERE report_id = 'rid-1'")).scalar()
        tls_hash = conn.execute(text("SELECT content_hash FROM tls_reports")).scalar()
    assert dmarc_hash == report_store.prepare_report("dmarc", parsed_dmarc).content_hash
    assert tls_hash == report_store.prepare_report("tls-rpt", parsed_tls).content_hash

    # A second run changes nothing; two reports can now share a report_id
    _upgrade(isolated_engine, revision)
    with isolated_engine.begin() as conn:
        conn.execute(text("INSERT INTO dmarc_reports (report_id, domain, org_name, begin_date, end_date, "
                          "content_hash) VALUES ('rid-1', 'example.com', 'other.example', 1, 2, 'x')"))


def test_migration_is_a_no_op_on_a_fresh_install(isolated_engine):
    revision = _revision()
    Base.metadata.create_all(isolated_engine, tables=TABLES)
    before = {t: inspect(isolated_engine).get_unique_constraints(t) for t in ("dmarc_reports", "tls_reports")}
    _upgrade(isolated_engine, revision)
    after = {t: inspect(isolated_engine).get_unique_constraints(t) for t in ("dmarc_reports", "tls_reports")}
    assert before == after


def test_a_migration_that_fails_midway_changes_nothing(isolated_engine, monkeypatch):
    revision = _revision()
    _old_schema(isolated_engine, legacy=True)
    with isolated_engine.begin() as conn:
        for i in range(3):
            _insert_old_dmarc(conn, parse_dmarc_file(dmarc_gz(report_id=f"r{i}"), "a.xml.gz"))
    calls = []
    original = revision.dmarc_content_hash

    def fail_on_second(*args):
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("stop")
        return original(*args)

    monkeypatch.setattr(revision, "TABLES", ((revision.TABLES[0][:6] + (fail_on_second,) + revision.TABLES[0][7:]),)
                        + revision.TABLES[1:])
    with pytest.raises(RuntimeError):
        _upgrade(isolated_engine, revision)
    inspector = inspect(isolated_engine)
    assert "content_hash" not in {c["name"] for c in inspector.get_columns("dmarc_reports")}
    assert [u["column_names"] for u in inspector.get_unique_constraints("dmarc_reports")] == [["report_id"]]


def test_migration_keeps_nulls_an_older_version_stored(isolated_engine):
    # An older version stored null fields of a TLS report as NULL; the report
    # sent again must still match the stored one
    revision = _revision()
    _old_schema(isolated_engine, legacy=False)
    data = json.loads(tls_json())
    data["organization-name"] = data["contact-info"] = None
    data["policies"][0]["policy"]["policy-type"] = None
    data["policies"][0]["summary"]["total-failure-session-count"] = None
    data["policies"][0]["failure-details"] = None
    content = json.dumps(data).encode()
    with isolated_engine.begin() as conn:
        _insert_old_tls(conn, {
            "report_id": data["report-id"], "organization_name": None, "contact_info": None,
            "policy_domain": "example.com", "start_datetime": datetime(2026, 11, 2),
            "end_datetime": datetime(2026, 11, 2, 23, 59, 59),
            "policies": [{"policy_type": None, "policy_domain": "example.com",
                          "policy_string": ["version: STSv1", "mode: enforce"], "mx_host": ["mail.example.com"],
                          "successful_session_count": 3, "failed_session_count": None,
                          "failure_details": None}]})
    _upgrade(isolated_engine, revision)
    with isolated_engine.connect() as conn:
        stored = conn.execute(text("SELECT content_hash FROM tls_reports")).scalar()
    assert stored == report_store.prepare_report("tls-rpt", parse_tls_rpt_file(content, "t.json")).content_hash


def test_migration_works_in_batches_and_downgrades(isolated_engine, monkeypatch):
    revision = _revision()
    monkeypatch.setattr(revision, "BATCH", 2)
    _old_schema(isolated_engine, legacy=True)
    files = [dmarc_gz(report_id=f"r{i}", records=distinct_records(i)) for i in range(5)]
    with isolated_engine.begin() as conn:
        for i, content in enumerate(files):
            _insert_old_dmarc(conn, parse_dmarc_file(content, "a.xml.gz"))
    _upgrade(isolated_engine, revision)
    with isolated_engine.connect() as conn:
        stored = dict(conn.execute(text("SELECT report_id, content_hash FROM dmarc_reports")).all())
    assert stored == {f"r{i}": report_store.prepare_report("dmarc", parse_dmarc_file(content, "a")).content_hash
                      for i, content in enumerate(files)}

    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    with isolated_engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            revision.downgrade()
    inspector = inspect(isolated_engine)
    for table in ("dmarc_reports", "tls_reports"):
        assert "content_hash" not in {c["name"] for c in inspector.get_columns(table)}
        assert inspector.get_unique_constraints(table) == []
        assert [(i["column_names"], i["unique"]) for i in inspector.get_indexes(table)
                if i["name"] == f"ix_{table}_report_id"] == [(["report_id"], False)]
