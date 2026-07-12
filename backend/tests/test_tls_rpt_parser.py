"""Tests for the TLS-RPT (RFC 8460) report parser."""
import gzip
import json

from app.services.tls_rpt_parser import (
    is_tls_rpt_json,
    parse_iso_datetime,
    parse_tls_rpt_file,
    parse_tls_rpt_json,
)

VALID_REPORT = {
    "organization-name": "Google Inc.",
    "date-range": {
        "start-datetime": "2026-01-12T00:00:00Z",
        "end-datetime": "2026-01-12T23:59:59Z",
    },
    "contact-info": "smtp-tls-reporting@google.com",
    "report-id": "2026-01-12T00:00:00Z_example.com",
    "policies": [
        {
            "policy": {
                "policy-type": "sts",
                "policy-string": ["version: STSv1", "mode: enforce"],
                "policy-domain": "example.com",
                "mx-host": ["mail.example.com"],
            },
            "summary": {
                "total-successful-session-count": 5,
                "total-failure-session-count": 1,
            },
        }
    ],
}


def test_parse_valid_json():
    parsed = parse_tls_rpt_json(json.dumps(VALID_REPORT))
    assert parsed is not None
    assert parsed["policy_domain"] == "example.com"
    assert parsed["organization_name"] == "Google Inc."
    policy = parsed["policies"][0]
    assert policy["successful_session_count"] == 5
    assert policy["failed_session_count"] == 1


def test_parse_gz_end_to_end():
    payload = gzip.compress(json.dumps(VALID_REPORT).encode())
    parsed = parse_tls_rpt_file(payload, "report.json.gz")
    assert parsed is not None
    assert parsed["report_id"] == VALID_REPORT["report-id"]


def test_missing_report_id_returns_none():
    bad = dict(VALID_REPORT)
    del bad["report-id"]
    assert parse_tls_rpt_json(json.dumps(bad)) is None


def test_invalid_json_returns_none():
    assert parse_tls_rpt_json("not json {") is None


def test_gzip_bomb_returns_none():
    bomb = gzip.compress(b"\x00" * (60 * 1024 * 1024))
    assert parse_tls_rpt_file(bomb, "bomb.json.gz") is None


def test_parse_iso_datetime_z_suffix():
    dt = parse_iso_datetime("2026-01-12T10:30:00Z")
    assert dt is not None
    assert (dt.year, dt.hour, dt.tzinfo) == (2026, 10, None)  # stored UTC-naive


def test_parse_iso_datetime_offset():
    dt = parse_iso_datetime("2026-01-12T12:30:00+02:00")
    assert dt is not None
    assert dt.hour == 10  # converted to UTC


def test_parse_iso_datetime_invalid():
    assert parse_iso_datetime("") is None
    assert parse_iso_datetime("garbage") is None


def test_is_tls_rpt_json_detection():
    assert is_tls_rpt_json(json.dumps(VALID_REPORT)) is True
    assert is_tls_rpt_json('{"some": "other json"}') is False
    assert is_tls_rpt_json("not json") is False
