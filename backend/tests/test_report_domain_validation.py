"""
Reports arrive from outside, so their domain fields must be plain domain
names before they are stored; and the feature list saved from Settings
accepts only known features.
"""
import json

import pytest
from fastapi import HTTPException

from app.services.dmarc_parser import is_valid_domain_name, parse_dmarc_xml
from app.services.tls_rpt_parser import parse_tls_rpt_json

from test_dmarc_parser import VALID_REPORT


@pytest.mark.parametrize("name", ["example.com", "mail.example.co.uk", "xn--bcher-kva.example", "example.com."])
def test_plain_domain_names_are_accepted(name):
    assert is_valid_domain_name(name)


@pytest.mark.parametrize("name", ["", None, "exa mple.com", "example.com'", 'example.com"', "<b>example.com",
                                  "-example.com", "example..com", "a" * 64 + ".com"])
def test_anything_else_is_rejected(name):
    assert not is_valid_domain_name(name)


def test_a_dmarc_report_with_an_invalid_domain_is_not_parsed():
    report = VALID_REPORT.replace("<domain>example.com</domain>\n    <adkim>", "<domain>example.com'x</domain>\n    <adkim>")
    assert report != VALID_REPORT
    with pytest.raises(ValueError):
        parse_dmarc_xml(report, report)


def _tls_report(domain):
    return json.dumps({
        "organization-name": "Example Provider",
        "date-range": {"start-datetime": "2026-01-01T00:00:00Z", "end-datetime": "2026-01-01T23:59:59Z"},
        "contact-info": "tls@example.net",
        "report-id": "2026-01-01_example.com",
        "policies": [{"policy": {"policy-type": "sts", "policy-domain": domain},
                      "summary": {"total-successful-session-count": 1, "total-failure-session-count": 0}}],
    })


def test_a_tls_report_with_an_invalid_policy_domain_is_not_parsed():
    assert parse_tls_rpt_json(_tls_report("example.com"))["policy_domain"] == "example.com"
    assert parse_tls_rpt_json(_tls_report("example.com'x")) is None


def test_disabled_features_accepts_only_known_features(monkeypatch):
    from app.config import settings
    from app.routers import settings as settings_router

    monkeypatch.setattr(settings._inner, "edit_settings_via_ui_enabled", True)
    with pytest.raises(HTTPException) as exc:
        settings_router.update_settings({"disabled_features": "queue,not-a-feature"}, db=None)
    assert exc.value.status_code == 400
