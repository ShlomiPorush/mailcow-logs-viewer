"""The entity card, second round: suppression entries in the forms the app
stores, DMARC domains in any case or with a trailing dot, IPv6 addresses
matched by value, a timeline that keeps to its range, the suppression list
while it is not kept, and the sources that are not filtered by excluded
addresses. Builds on the rows of test_entity_cards (the same March 2020 range).
"""
from datetime import datetime, timedelta

import pytest

from test_entity_cards import AT, DOMAIN, HIDDEN, IP, MARK, RANGE, _card, client  # noqa: F401

from app.config import settings

SUPP = f"s{MARK}.example"           # stored as the Add form writes a domain: /^.+@s<mark>\.example$/i
LEGACY = f"l-{MARK}.example"        # the older unanchored form: /.+@l-<mark>\.example/i
WIZARD = f"w{MARK}.example"         # the pattern wizard's domain form, with subdomains
NEAR = f"n{MARK}.example"           # only similar domains have entries
BARE = f"b{MARK}.example"           # a bare domain row (the API and CSV import take one)
BOB, CAROL = f"bob@{SUPP}", f"carol@{SUPP}"
DMARC_MIXED = f"dm{MARK}.example"
IP6 = "2001:db8::1"
OLD_DEVICE_USER = f"old@{DOMAIN}"


def _cleanup():
    from app.database import get_db_context
    from app.models import BlacklistCheck, MonitoredHost, SystemSetting
    from app.services.feature_data import SPAM_IMPORT_PENDING_KEY
    with get_db_context() as db:
        db.query(BlacklistCheck).filter(BlacklistCheck.status == f"clean-{MARK}"[:20]).delete(synchronize_session=False)
        db.query(MonitoredHost).filter(MonitoredHost.source == f"test {MARK}").delete(synchronize_session=False)
        db.query(SystemSetting).filter(SystemSetting.key == SPAM_IMPORT_PENDING_KEY).delete(synchronize_session=False)
        db.commit()


def _epoch(value: datetime) -> int:
    return int((value - datetime(1970, 1, 1)).total_seconds())


@pytest.fixture()
def review(client, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', True)
    from app.database import get_db_context
    from app.models import (BlacklistCheck, DMARCRecord, DMARCReport, EasDevice, MessageCorrelation, MonitoredHost,
                            NetfilterLog, ProtectionHit, RspamdLog, SpamSuppression)
    _cleanup()
    with get_db_context() as db:
        for email, kind, source in (
            (f"/^.+@s{MARK}\\.example$/i", "domain", "manual"),
            (f"/.+@l-{MARK}\\.example/i", "domain", "manual"),
            (f"/^.+@(.+\\.)?w{MARK}\\.example$/i", "email", "rspamd"),
            (f"/^.+@badn{MARK}\\.example$/i", "domain", "manual"),
            (f"/^.+@n{MARK}\\.example\\.test$/i", "domain", "manual"),
            (f"/.+@n{MARK}x\\.example/i", "domain", "manual"),
            (BARE, "domain", "import"),
            (BOB, "email", "auto"),
            (f"/^carol@s{MARK}\\.example$/i", "email", "manual"),
            (f"xbob@{SUPP}", "email", "auto"),
        ):
            db.add(SpamSuppression(email=email, type=kind, reason="manual", source=source, active=True, created_at=AT))

        # DMARC: one domain stored in two spellings
        for domain, n in ((f"DM{MARK}.Example.", 2), (DMARC_MIXED, 3)):
            report = DMARCReport(report_id=f"{MARK}-mixed-{n}", domain=domain, org_name="Reporter Example",
                                 begin_date=_epoch(AT - timedelta(days=1)), end_date=_epoch(AT), created_at=AT)
            db.add(report)
            db.flush()
            db.add(DMARCRecord(dmarc_report_id=report.id, source_ip=IP, count=n, spf_result="pass", dkim_result="fail"))

        # IPv6: the app's own writers store it canonically; the others as they got it
        scan = RspamdLog(time=AT, ip=IP6, correlation_key=f"{MARK}-v6")
        db.add(scan)
        db.flush()
        db.add(MessageCorrelation(correlation_key=f"{MARK}-v6", message_id=f"<v6.{MARK}@example.com>",
                                  sender="v6@example.net", recipient=f"to@{DOMAIN}", subject=f"v6 {MARK}",
                                  direction="inbound", final_status="delivered", first_seen=AT, last_seen=AT,
                                  created_at=AT, rspamd_log_id=scan.id))
        db.add(NetfilterLog(time=AT, ip=IP6, rule_id=3, message=f"{IP6} matched rule id 3 (SASL) {MARK}"))
        db.add(EasDevice(username=f"v6@{DOMAIN}", device_id=f"{MARK}v6", device_type="Android", last_ip=IP6,
                         first_seen=AT, last_seen=AT))
        db.add(ProtectionHit(ip="2001:db8:0:0::1", rule="breach", mode="watch", status="alert", reason=f"v6 {MARK}",
                             usernames=[], attempts=1, first_seen=AT, last_seen=AT))
        for n, spelling in ((4, "2001:DB8:0:0:0:0:0:1"), (6, "2001:db8:0:0::1")):
            report = DMARCReport(report_id=f"{MARK}-v6-{n}", domain=DMARC_MIXED, org_name="Reporter Example",
                                 begin_date=_epoch(AT - timedelta(days=1)), end_date=_epoch(AT), created_at=AT)
            db.add(report)
            db.flush()
            db.add(DMARCRecord(dmarc_report_id=report.id, source_ip=spelling, count=n, spf_result="pass"))
        db.add(BlacklistCheck(server_ip="2001:0db8::1", total_blacklists=1, listed_count=0, clean_count=1,
                              error_count=0, timeout_count=0, status=f"clean-{MARK}"[:20], checked_at=AT, results=[]))
        db.add(MonitoredHost(hostname="2001:DB8:0::1", source=f"test {MARK}", active=True))

        # A device first seen in January and last seen in October: neither is in March
        db.add(EasDevice(username=OLD_DEVICE_USER, device_id=f"{MARK}old", device_type="iPad", last_ip=IP,
                         first_seen=datetime(2020, 1, 5), last_seen=datetime(2020, 10, 5)))
        # The excluded address is still named by Security and Protection
        db.add(NetfilterLog(time=AT, ip="198.51.100.99", rule_id=3, username=HIDDEN,
                            message=f"198.51.100.99 matched rule id 3 (SASL) {MARK}"))
        db.commit()
    yield client
    _cleanup()
    with get_db_context() as db:
        db.query(MonitoredHost).filter(MonitoredHost.source == f"test {MARK}").delete(synchronize_session=False)
        db.commit()


# ---------------------------------------------------------------- R1 suppression entries

@pytest.mark.parametrize("domain,stored", [
    (SUPP, f"/^.+@s{MARK}\\.example$/i"),
    (LEGACY, f"/.+@l-{MARK}\\.example/i"),
    (WIZARD, f"/^.+@(.+\\.)?w{MARK}\\.example$/i"),
    (BARE, BARE),
])
def test_domain_card_finds_the_domain_entry_in_every_stored_form(review, domain, stored):
    entry = _card(review, "domain", domain)["sources"]["suppression"]["entry"]
    assert entry is not None and entry["email"] == stored


def test_similar_domains_are_not_the_domain_entry(review):
    assert _card(review, "domain", NEAR)["sources"]["suppression"]["entry"] is None


@pytest.mark.parametrize("address,stored", [(BOB, BOB), (CAROL, f"/^carol@s{MARK}\\.example$/i")])
def test_address_card_finds_its_own_entry_and_its_domain_entry(review, address, stored):
    suppression = _card(review, "address", address)["sources"]["suppression"]
    assert suppression["entry"]["email"] == stored
    assert suppression["domain_entry"]["email"] == f"/^.+@s{MARK}\\.example$/i"


def test_a_similar_address_is_not_the_entry(review):
    suppression = _card(review, "address", f"ob@{SUPP}")["sources"]["suppression"]
    assert suppression["entry"] is None


# ---------------------------------------------------------------- R2 what excluded addresses hide

def test_excluded_address_hides_messages_only(review):
    """The card follows the page each source comes from: Messages leaves an
    excluded address out, Security, Protection, Devices and Suppressions do not."""
    s = _card(review, "address", HIDDEN)["sources"]
    assert s["messages"]["state"] == "disabled" and "excluded" in s["messages"]["reason"]
    assert s["security"]["state"] == "ok" and s["security"]["rule_matches"] == 1
    assert s["security"]["items"][0]["username"] == HIDDEN


# ---------------------------------------------------------------- R3 DMARC domain spelling

def test_dmarc_domain_in_any_case_or_with_a_trailing_dot_is_one_domain(review):
    by_domain = _card(review, "ip", IP)["sources"]["dmarc"]["by_domain"]
    mixed = [d for d in by_domain if d["domain"].rstrip(".").lower() == DMARC_MIXED]
    assert len(mixed) == 1 and mixed[0]["domain"] == DMARC_MIXED
    assert mixed[0]["messages"] == 5 and mixed[0]["reports"] == 2
    dmarc = _card(review, "domain", DMARC_MIXED)["sources"]["dmarc"]
    assert dmarc["reports"] == 4 and dmarc["messages"] == 15


# ---------------------------------------------------------------- R4 IPv6 by value

def test_ip_card_reads_ipv6_in_any_form(review):
    card = _card(review, "ip", "2001:DB8:0:0::1")
    assert card["value"] == IP6
    s = card["sources"]
    assert s["messages"]["count"] == 1
    assert s["security"]["rule_matches"] == 1
    assert s["devices"]["count"] == 1
    assert s["protection"]["count"] == 1 and s["protection"]["items"][0]["ip"] == "2001:db8:0:0::1"
    assert s["dmarc"]["messages"] == 10 and s["dmarc"]["reports"] == 2
    assert s["rbl"]["checked"] is True and s["rbl"]["monitored"] is True


def test_netfilter_exact_ip_reads_any_spelling_of_the_address(review):
    """The Events list and its export compare the typed address in the canonical form Netfilter lines store."""
    params = {"ip": "2001:DB8:0:0::1", "exact_ip": "true", **RANGE}
    listed = review.get("/api/logs/netfilter", params=params).json()
    assert [row["message"] for row in listed["data"]] == [f"{IP6} matched rule id 3 (SASL) {MARK}"]
    exported = review.get("/api/export/netfilter/csv", params=params)
    assert exported.status_code == 200 and exported.text.count(MARK) == 1


# ---------------------------------------------------------------- R5 timeline range

def test_timeline_keeps_only_events_inside_the_range(review):
    card = _card(review, "address", OLD_DEVICE_USER)
    assert card["sources"]["devices"]["count"] == 1
    assert [i for i in card["timeline"]["items"] if i["kind"].startswith("device")] == []
    for item in _card(review, "ip", IP)["timeline"]["items"]:
        assert "2020-03-01T00:00:00Z" <= item["time"] <= "2020-03-20T23:59:59Z", item


# ---------------------------------------------------------------- R7 suppression list not kept

def test_suppressions_disabled_while_rspamd_sync_is_off(review, monkeypatch):
    monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', False)
    for kind, value in (("address", BOB), ("domain", SUPP)):
        source = _card(review, kind, value)["sources"]["suppression"]
        assert source["state"] == "disabled" and "Sync with Rspamd" in source["reason"], source
        assert set(source) == {"state", "reason"}


def test_suppressions_disabled_while_the_list_is_loaded_back(review):
    from app.database import get_db_context
    from app.models import SystemSetting
    from app.services.feature_data import SPAM_IMPORT_PENDING_KEY, SPAM_IMPORT_RESTORE
    with get_db_context() as db:
        db.add(SystemSetting(key=SPAM_IMPORT_PENDING_KEY, value=SPAM_IMPORT_RESTORE))
        db.commit()
    source = _card(review, "address", BOB)["sources"]["suppression"]
    assert source["state"] == "disabled" and "loaded" in source["reason"], source
