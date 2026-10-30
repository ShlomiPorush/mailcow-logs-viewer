"""The entity card, third round: an IPv4 address stored as an IPv4-mapped IPv6
text is found everywhere, the by-value comparison reads every candidate or
says it could not, and the timeline range keeps the fraction of a second.
Builds on the rows of test_entity_cards (the same March 2020 range)."""
import csv
import io
from datetime import datetime, timedelta

import pytest

from test_entity_cards import AT, DOMAIN, IP, MARK, RANGE, _card, client  # noqa: F401

from app.services import entity_summary

MAPPED = ("::ffff:cb00:7104", "::FFFF:203.0.113.4", "0:0:0:0:0:ffff:cb00:7104")
OTHER_MAPPED = "::ffff:cb00:7105"            # 203.0.113.5: the same prefix, another address
R2_DOMAIN = f"r2{MARK}.example"
V6 = "2001:db8::1"
V6_ODD = "2001:0db8::1"                       # not in the closed set of spellings: only the by-value pass finds it
PRECISE_USER = f"prec@{DOMAIN}"


def _epoch(value: datetime) -> int:
    return int((value - datetime(1970, 1, 1)).total_seconds())


@pytest.fixture()
def round2(client):  # noqa: F811
    from app.database import get_db_context
    from app.models import DMARCRecord, DMARCReport, EasDevice, MessageCorrelation, NetfilterLog, RspamdLog
    with get_db_context() as db:
        for i, ip in enumerate(MAPPED + (OTHER_MAPPED,)):
            scan = RspamdLog(time=AT, ip=ip, correlation_key=f"{MARK}-mapped{i}")
            db.add(scan)
            db.flush()
            db.add(MessageCorrelation(correlation_key=f"{MARK}-mapped{i}", message_id=f"<mapped{i}.{MARK}@example.com>",
                                      sender="m@example.net", recipient=f"mapped@{R2_DOMAIN}", subject=f"mapped{i} {MARK}",
                                      direction="inbound", final_status="delivered", first_seen=AT + timedelta(minutes=i),
                                      last_seen=AT, created_at=AT, rspamd_log_id=scan.id))
        report = DMARCReport(report_id=f"{MARK}-r2", domain=R2_DOMAIN, org_name="Reporter Example",
                             begin_date=_epoch(AT - timedelta(days=1)), end_date=_epoch(AT), created_at=AT)
        db.add(report)
        db.flush()
        for ip, n in zip(MAPPED + (OTHER_MAPPED,), (1, 2, 4, 8)):
            db.add(DMARCRecord(dmarc_report_id=report.id, source_ip=ip, count=n, spf_result="pass"))
        # Many other IPv6 texts in the range, and one more spelling of 2001:db8::1
        for n in range(1, 21):
            db.add(DMARCRecord(dmarc_report_id=report.id, source_ip=f"2001:0000::{n:x}", count=100, spf_result="pass"))
        db.add(DMARCRecord(dmarc_report_id=report.id, source_ip=V6_ODD, count=9, spf_result="pass"))
        db.add(NetfilterLog(time=AT, ip="::ffff:203.0.113.4", rule_id=3,
                            message=f"::ffff:203.0.113.4 matched rule id 3 (SASL) {MARK}"))
        db.add(EasDevice(username=PRECISE_USER, device_id=f"{MARK}precise", device_type="iPhone", last_ip=IP,
                         first_seen=datetime(2020, 3, 10, 12, 0, 0, 100000),
                         last_seen=datetime(2020, 3, 10, 12, 0, 0, 950000)))
        db.commit()
    yield client


# ---------------------------------------------------------------- R4 IPv4-mapped spellings

def test_ipv4_mapped_spellings_are_the_ipv4_address_in_the_card(round2):
    s = _card(round2, "ip", IP)["sources"]
    # One message of the base rows, and the three stored with a mapped spelling; not 203.0.113.5
    assert s["messages"]["count"] == 4
    assert sorted(m["subject"].split()[0] for m in s["messages"]["items"] if "mapped" in m["subject"]) == [
        "mapped0", "mapped1", "mapped2"]
    r2 = next(d for d in s["dmarc"]["by_domain"] if d["domain"] == R2_DOMAIN)
    assert r2["messages"] == 7
    assert any(i["ip"] == "::ffff:203.0.113.4" for i in s["security"]["items"])


def test_ipv4_mapped_spellings_in_the_messages_exact_mode(round2):
    res = round2.get("/api/messages", params={**RANGE, "ip": IP, "exact": "true"}).json()
    subjects = sorted(m["subject"].split()[0] for m in res["data"] if "mapped" in (m["subject"] or ""))
    assert subjects == ["mapped0", "mapped1", "mapped2"]


def test_ipv4_mapped_spelling_in_the_netfilter_exact_filters(round2):
    params = {**RANGE, "ip": IP, "exact_ip": "true"}
    listed = round2.get("/api/logs/netfilter", params=params).json()["data"]
    assert any(row["ip"] == "::ffff:203.0.113.4" for row in listed)
    rows = list(csv.DictReader(io.StringIO(
        round2.get("/api/export/netfilter/csv", params=params).content.decode("utf-8-sig"))))
    assert any(row["IP"] == "::ffff:203.0.113.4" for row in rows)


# ---------------------------------------------------------------- R8 every candidate, or an error

def test_by_value_pass_reads_every_candidate_page(round2, monkeypatch):
    monkeypatch.setattr(entity_summary, "IP_TEXTS_CHUNK", 2, raising=False)
    monkeypatch.setattr(entity_summary, "IP_TEXTS_READ", 2, raising=False)    # the single read of the older code
    dmarc = _card(round2, "ip", V6)["sources"]["dmarc"]
    assert dmarc["state"] == "ok" and dmarc["messages"] == 9


def test_too_many_candidates_is_an_error_not_a_partial_count(round2, monkeypatch):
    monkeypatch.setattr(entity_summary, "IP_TEXTS_CHUNK", 2, raising=False)
    monkeypatch.setattr(entity_summary, "IP_TEXTS_CEILING", 5, raising=False)
    monkeypatch.setattr(entity_summary, "IP_TEXTS_READ", 2, raising=False)
    dmarc = _card(round2, "ip", V6)["sources"]["dmarc"]
    assert dmarc["state"] == "error" and "Too many different addresses" in dmarc["reason"]
    assert "messages" not in dmarc


# ---------------------------------------------------------------- R5 the fraction of a second

def test_timeline_range_keeps_the_fraction_of_a_second(round2):
    res = round2.get("/api/entities/address", params={
        "value": PRECISE_USER, "start_date": "2020-03-10T12:00:00.900Z", "end_date": "2020-03-10T13:00:00Z"})
    card = res.json()
    assert card["sources"]["devices"]["count"] == 1
    # First seen at .100 is before the start at .900; last seen at .950 is after it
    assert [i["kind"] for i in card["timeline"]["items"]] == ["device_last_seen"]
