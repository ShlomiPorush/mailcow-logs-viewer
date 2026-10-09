"""
Some reporters send aggregate reports whose rows are empty placeholders: no
source IP, a count of 0 and no results. Storing such a row violated the NOT
NULL constraint on dmarc_records.source_ip and the whole report failed on
every sync (issue #324). Rows without a usable source IP are now skipped and
the report itself is kept.
"""
import gzip

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.services.dmarc_parser import is_valid_ip, parse_dmarc_xml

from test_dmarc_parser import VALID_REPORT

REPORT_ID = "324.empty-records.test"

EMPTY_ROW_REPORT = f"""<?xml version="1.0"?>
<feedback>
    <report_metadata>
        <date_range>
            <begin>1790546400</begin>
            <end>1790632800</end>
        </date_range>
        <org_name>reporter.example</org_name>
        <email>dmarc-support@reporter.example</email>
        <extra_contact_info>dmarc-reports@reporter.example</extra_contact_info>
        <report_id>{REPORT_ID}</report_id>
    </report_metadata>
    <policy_published>
        <domain>empty-rows.example</domain>
        <adkim>r</adkim>
        <aspf>r</aspf>
        <p>quarantine</p>
        <sp>quarantine</sp>
        <pct>100</pct>
    </policy_published>
    <record>
        <row>
            <source_ip/>
            <count>0</count>
            <policy_evaluated>
                <disposition/>
                <dkim/>
                <spf/>
            </policy_evaluated>
        </row>
        <identifiers>
            <header_from/>
        </identifiers>
        <auth_results>
            <spf>
                <domain/>
                <result/>
            </spf>
        </auth_results>
    </record>
</feedback>"""


@pytest.mark.parametrize("value", ["203.0.113.5", "2001:db8::1"])
def test_ip_addresses_are_accepted(value):
    assert is_valid_ip(value)


@pytest.mark.parametrize("value", [None, "", "not-an-ip", "203.0.113", "example.com"])
def test_anything_else_is_not_an_ip(value):
    assert not is_valid_ip(value)


def test_a_row_without_a_source_ip_is_skipped_and_the_report_is_kept():
    parsed = parse_dmarc_xml(EMPTY_ROW_REPORT)
    assert parsed["report_id"] == REPORT_ID
    assert parsed["domain"] == "empty-rows.example"
    assert parsed["records"] == []


def test_a_row_with_an_invalid_source_ip_is_skipped():
    report = VALID_REPORT.replace("<source_ip>203.0.113.5</source_ip>", "<source_ip>not-an-ip</source_ip>")
    assert report != VALID_REPORT
    assert parse_dmarc_xml(report)["records"] == []


@pytest.mark.parametrize("tag", ["report_id", "org_name"])
def test_a_report_without_a_required_metadata_field_is_not_parsed(tag):
    report = EMPTY_ROW_REPORT.replace(f"<{tag}>", f"<{tag}_gone>").replace(f"</{tag}>", f"</{tag}_gone>")
    with pytest.raises(ValueError):
        parse_dmarc_xml(report)


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def db():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, SessionLocal
    from app.models import DMARCReport
    init_db()
    session = SessionLocal()

    def cleanup():
        session.rollback()
        session.query(DMARCReport).filter(DMARCReport.report_id == REPORT_ID).delete()
        session.commit()

    cleanup()
    yield session
    cleanup()
    session.close()


def test_uploading_a_report_with_only_empty_rows_stores_the_report(db):
    from app.models import DMARCRecord, DMARCReport
    from app.routers.dmarc import _upload_dmarc_report

    content = gzip.compress(EMPTY_ROW_REPORT.encode("utf-8"))
    result = _upload_dmarc_report(content, "reporter.example!empty-rows.example.xml.gz", db)

    assert result["status"] == "success"
    assert result["records_count"] == 0
    report = db.query(DMARCReport).filter(DMARCReport.report_id == REPORT_ID).one()
    assert db.query(DMARCRecord).filter(DMARCRecord.dmarc_report_id == report.id).count() == 0
