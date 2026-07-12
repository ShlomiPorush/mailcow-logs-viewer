"""Tests for the DMARC aggregate report parser."""
import gzip
import io
import zipfile

import pytest

from app.services.dmarc_parser import parse_dmarc_file, parse_dmarc_xml

VALID_REPORT = """<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>1234567890</report_id>
    <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim><aspf>r</aspf><p>none</p><pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>203.0.113.5</source_ip>
      <count>2</count>
      <policy_evaluated>
        <disposition>none</disposition><dkim>pass</dkim><spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><selector>s1</selector><result>pass</result></dkim>
      <spf><domain>example.com</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>"""


def test_parse_valid_xml():
    parsed = parse_dmarc_xml(VALID_REPORT, VALID_REPORT)
    assert parsed["org_name"] == "google.com"
    assert parsed["domain"] == "example.com"
    assert parsed["report_id"] == "1234567890"
    assert parsed["begin_date"] == 1700000000
    record = parsed["records"][0]
    assert record["source_ip"] == "203.0.113.5"
    assert record["count"] == 2
    assert record["header_from"] == "example.com"
    assert record["auth_results"]["dkim"][0]["result"] == "pass"


def test_entity_expansion_blocked():
    """defusedxml must reject XML with internal entity definitions (billion laughs)."""
    evil = (
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;">]><feedback>&lol2;</feedback>'
    )
    with pytest.raises(Exception):
        parse_dmarc_xml(evil, evil)


def test_parse_gz_file_end_to_end():
    result = parse_dmarc_file(gzip.compress(VALID_REPORT.encode()), "report.xml.gz")
    assert result is not None
    assert result["org_name"] == "google.com"


def test_parse_zip_file_end_to_end():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("report.xml", VALID_REPORT)
    result = parse_dmarc_file(buf.getvalue(), "report.zip")
    assert result is not None
    assert result["domain"] == "example.com"


def test_gzip_bomb_returns_none():
    bomb = gzip.compress(b"\x00" * (60 * 1024 * 1024))
    assert parse_dmarc_file(bomb, "bomb.xml.gz") is None


def test_oversized_compressed_input_returns_none():
    big = b"\x00" * (11 * 1024 * 1024)  # over the 10 MB compressed cap
    assert parse_dmarc_file(big, "big.xml.gz") is None


def test_unsupported_extension_returns_none():
    assert parse_dmarc_file(b"whatever", "report.txt") is None


def test_missing_metadata_raises():
    with pytest.raises(Exception):
        parse_dmarc_xml("<feedback></feedback>", "<feedback></feedback>")
