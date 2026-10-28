"""The entity card, fourth round: an IPv4-compatible IPv6 address in the
dotted form glibc writes, and one snapshot for a source that pages through
address candidates. Builds on the rows of test_entity_cards (March 2020)."""
from datetime import datetime, timedelta

import pytest

from test_entity_cards import AT, IP, MARK, RANGE, _card, client  # noqa: F401

from app.services import entity_summary, entity_values

COMPAT = "::203.0.113.4"          # ::cb00:7104 as glibc's inet_ntop writes it
SNAP_DOMAIN = f"snap{MARK}.example"
V6 = "2001:db8::1"


def _epoch(value: datetime) -> int:
    return int((value - datetime(1970, 1, 1)).total_seconds())


@pytest.fixture()
def round3(client):  # noqa: F811
    from app.database import get_db_context
    from app.models import DMARCRecord, DMARCReport, MessageCorrelation, RspamdLog
    with get_db_context() as db:
        scan = RspamdLog(time=AT, ip=COMPAT, correlation_key=f"{MARK}-compat")
        db.add(scan)
        db.flush()
        db.add(MessageCorrelation(correlation_key=f"{MARK}-compat", message_id=f"<compat.{MARK}@example.com>",
                                  sender="c@example.net", recipient="c@example.org", subject=f"compat {MARK}",
                                  direction="inbound", final_status="delivered", first_seen=AT, last_seen=AT,
                                  created_at=AT, rspamd_log_id=scan.id))
        report = DMARCReport(report_id=f"{MARK}-snap", domain=SNAP_DOMAIN, org_name="Reporter Example",
                             begin_date=_epoch(AT - timedelta(days=1)), end_date=_epoch(AT), created_at=AT)
        db.add(report)
        db.flush()
        # Three other IPv6 texts and one spelling of 2001:db8::1 the closed set does not hold
        for n in (1, 2, 3):
            db.add(DMARCRecord(dmarc_report_id=report.id, source_ip=f"2001:0000::{n}", count=100, spf_result="pass"))
        db.add(DMARCRecord(dmarc_report_id=report.id, source_ip="2001:0db8::1", count=9, spf_result="pass"))
        db.commit()
        report_id = report.id
    client.report_id = report_id
    yield client


# ---------------------------------------------------------------- R9 IPv4-compatible

@pytest.mark.parametrize("typed", ["::cb00:7104", "::203.0.113.4", "0:0:0:0:0:0:cb00:7104"])
def test_ipv4_compatible_address_in_glibc_form_is_found(round3, typed):
    card = _card(round3, "ip", typed)
    assert card["value"] == "::cb00:7104"
    assert [m["subject"].split()[0] for m in card["sources"]["messages"]["items"]] == ["compat"]
    listed = round3.get("/api/messages", params={**RANGE, "ip": typed, "exact": "true"}).json()["data"]
    assert [m["subject"].split()[0] for m in listed if MARK in (m["subject"] or "")] == ["compat"]


def test_ipv4_compatible_address_is_not_the_ipv4_address(round3):
    card = _card(round3, "ip", IP)
    assert "compat" not in [m["subject"].split()[0] for m in card["sources"]["messages"]["items"]]
    listed = round3.get("/api/messages", params={**RANGE, "ip": IP, "exact": "true"}).json()["data"]
    assert "compat" not in [m["subject"].split()[0] for m in listed if m["subject"]]
    assert COMPAT not in entity_values.ip_spellings(IP)
    assert "::ffff:203.0.113.4" not in entity_values.ip_spellings("::cb00:7104")


# ---------------------------------------------------------------- R10 one snapshot

def test_a_commit_between_candidate_pages_does_not_change_the_count(round3, monkeypatch):
    """A report imported while the card pages through the address candidates
    is not half counted: the source reads one snapshot."""
    from app.database import get_db_context
    from app.models import DMARCRecord
    monkeypatch.setattr(entity_summary, "IP_TEXTS_CHUNK", 2, raising=False)
    real_same_ip = entity_values.same_ip
    state = {"inserted": False}

    def same_ip_then_import(stored, ip):
        if not state["inserted"] and str(stored).startswith("2001:0000::"):   # a page of this DMARC source
            state["inserted"] = True
            # Another session commits two records of the address while the first page is read
            with get_db_context() as other:
                other.add(DMARCRecord(dmarc_report_id=round3.report_id, source_ip=V6, count=5, spf_result="pass"))
                other.add(DMARCRecord(dmarc_report_id=round3.report_id, source_ip="2001:DB8:0::1", count=7,
                                      spf_result="pass"))
                other.commit()
        return real_same_ip(stored, ip)

    monkeypatch.setattr(entity_values, "same_ip", same_ip_then_import)
    dmarc = _card(round3, "ip", V6)["sources"]["dmarc"]
    assert state["inserted"]
    assert dmarc["state"] == "ok"
    # What the snapshot held when the source started: only the record of 9
    assert dmarc["messages"] == 9 and dmarc["reports"] == 1
    assert [r["count"] for r in dmarc["records"]] == [9]
    # The next card sees the new records
    assert _card(round3, "ip", V6)["sources"]["dmarc"]["messages"] == 21
