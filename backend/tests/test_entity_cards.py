"""The entity card (GET /api/entities/ip, /address, /domain) against a real
PostgreSQL: every source matches the value exactly, never a similar one, an
excluded address stays hidden, a source that is off or failed says so instead
of counting zero, and the timeline holds only what is stored.

The rows live in March 2020 and the calls ask for that range, so nothing else
in the database is counted with them.
"""
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app import config
from app.config import settings
from app.mailcow_api import mailcow_api

MARK = uuid.uuid4().hex[:8]
DOMAIN = f"c{MARK}.example"
UNDERSCORE_DOMAIN = f"u_{MARK}.example"       # '_' is a LIKE wildcard: uX<mark>.example must not match
LOOKALIKE_DOMAIN = f"ux{MARK}.example"
ANN = f"ann@{DOMAIN}"
JOANN = f"joann@{DOMAIN}"
WILD = f"ann_1%@{DOMAIN}"                      # '_' and '%' in an address are plain characters
WILD_LOOKALIKE = f"annx1zz@{DOMAIN}"
HIDDEN = f"hidden@{DOMAIN}"
IP, SIMILAR_IP = "203.0.113.4", "203.0.113.45"
CHECKED_IP, UNCHECKED_IP = "198.51.100.61", "198.51.100.62"
DMARC_A, DMARC_B = f"da{MARK}.example", f"db{MARK}.example"
AT = datetime(2020, 3, 10, 12, 0, 0)
RANGE = {"start_date": "2020-03-01", "end_date": "2020-03-20"}
IPS = (IP, SIMILAR_IP, CHECKED_IP, UNCHECKED_IP)


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import (BlacklistCheck, DMARCRecord, DMARCReport, EasDevice, MailboxStatistics,
                            MessageCorrelation, NetfilterLog, ProtectionHit, RspamdLog, SpamSuppression)
    window = (datetime(2020, 2, 1), datetime(2020, 4, 30))
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(MessageCorrelation.correlation_key.like(f"{MARK}-%")).delete(synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.correlation_key.like(f"{MARK}-%")).delete(synchronize_session=False)
        db.query(NetfilterLog).filter(NetfilterLog.ip.in_(IPS), NetfilterLog.time.between(*window)).delete(synchronize_session=False)
        db.query(NetfilterLog).filter(NetfilterLog.message.like(f"%{MARK}%")).delete(synchronize_session=False)
        db.query(ProtectionHit).filter(ProtectionHit.reason.like(f"%{MARK}%")).delete(synchronize_session=False)
        db.query(EasDevice).filter(EasDevice.device_id.like(f"{MARK}%")).delete(synchronize_session=False)
        reports = [r.id for r in db.query(DMARCReport.id).filter(DMARCReport.report_id.like(f"{MARK}-%"))]
        if reports:
            db.query(DMARCRecord).filter(DMARCRecord.dmarc_report_id.in_(reports)).delete(synchronize_session=False)
            db.query(DMARCReport).filter(DMARCReport.id.in_(reports)).delete(synchronize_session=False)
        db.query(BlacklistCheck).filter(BlacklistCheck.server_ip.in_(IPS)).delete(synchronize_session=False)
        db.query(SpamSuppression).filter(SpamSuppression.email.like(f"%{MARK}%")).delete(synchronize_session=False)
        db.query(MailboxStatistics).filter(MailboxStatistics.domain == DOMAIN).delete(synchronize_session=False)
        db.commit()


def _epoch(value: datetime) -> int:
    return int((value - datetime(1970, 1, 1)).total_seconds())


def _seed():
    from app.database import get_db_context
    from app.models import (BlacklistCheck, DMARCRecord, DMARCReport, EasDevice, MailboxStatistics,
                            MessageCorrelation, NetfilterLog, ProtectionHit, RspamdLog, SpamSuppression)
    with get_db_context() as db:
        def scan(name, ip, minutes):
            row = RspamdLog(time=AT + timedelta(minutes=minutes), ip=ip, correlation_key=f"{MARK}-{name}")
            db.add(row)
            db.flush()
            return row.id

        def message(name, sender, recipient, minutes, rspamd=None, message_id=None, direction="inbound"):
            db.add(MessageCorrelation(
                correlation_key=f"{MARK}-{name}", message_id=message_id or f"<{name}.{MARK}@example.com>",
                sender=sender, recipient=recipient, subject=f"{name} {MARK}", direction=direction,
                final_status="delivered", first_seen=AT + timedelta(minutes=minutes),
                last_seen=AT + timedelta(minutes=minutes), created_at=AT, rspamd_log_id=rspamd))

        # From IP: one message delivered twice (two legs), and one to an excluded address
        from_ip = scan("ip", IP, 0)
        message("ip-leg1", "Sender@Example.NET", ANN, 0, from_ip, message_id=f"<two-legs.{MARK}@example.com>")
        message("ip-leg2", "Sender@Example.NET", JOANN, 1, from_ip, message_id=f"<two-legs.{MARK}@example.com>")
        message("ip-hidden", "sender@example.net", HIDDEN, 2, scan("hidden", IP, 2))
        # From the similar IP
        message("similar", "sender@example.net", JOANN, 3, scan("similar", SIMILAR_IP, 3))
        # Mail of the address, in another case; and of addresses that only contain it
        message("ann-out", ANN.upper(), "friend@example.org", 10, direction="outbound")
        message("joann", JOANN, "friend@example.org", 11, direction="outbound")
        message("wild", WILD, "friend@example.org", 12, direction="outbound")
        message("wild-lookalike", WILD_LOOKALIKE, "friend@example.org", 13, direction="outbound")
        # Domain: an exact domain, a subdomain, a domain that merely ends the same, and '_' as a wildcard
        message("dom-sub", f"x@sub.{DOMAIN}", "friend@example.org", 14)
        message("dom-suffix", f"x@{DOMAIN}.evil.example", "friend@example.org", 15)
        message("under", f"x@{UNDERSCORE_DOMAIN}", "friend@example.org", 16)
        message("under-lookalike", f"x@{LOOKALIKE_DOMAIN}", "friend@example.org", 17)

        # Netfilter: two failed attempts, the warning after one, a ban, and a line of the similar IP
        for i, (ip, message_text, rule, action, user) in enumerate((
            (IP, f"{IP} matched rule id 3 (warning: unknown[{IP}]: SASL LOGIN authentication failed) {MARK}", 3, None, ANN),
            (IP, f"4 more attempts in the next 600 seconds until {IP}/32 is banned {MARK}", None, "warning", None),
            (IP, f"{IP} matched rule id 3 (imap-login: Disconnected) {MARK}", 3, None, JOANN),
            (IP, f"Banning {IP}/32 for 60 minutes {MARK}", None, "ban", None),
            (SIMILAR_IP, f"{SIMILAR_IP} matched rule id 3 (SASL) {MARK}", 3, None, ANN),
        )):
            db.add(NetfilterLog(time=AT + timedelta(minutes=20 + i), ip=ip, message=message_text, rule_id=rule,
                                action=action, username=user))

        db.add(ProtectionHit(ip=IP, rule="unknown_accounts", mode="watch", status="watching", reason=f"test {MARK}",
                             usernames=[ANN.upper()], attempts=4, first_seen=AT + timedelta(minutes=30),
                             last_seen=AT + timedelta(minutes=31)))
        db.add(ProtectionHit(ip=SIMILAR_IP, rule="unknown_accounts", mode="watch", status="dismissed",
                             reason=f"test {MARK}", usernames=[JOANN], attempts=2, first_seen=AT, last_seen=AT,
                             ended_at=AT))

        db.add(EasDevice(username=ANN, device_id=f"{MARK}phone", device_type="iPhone", last_ip=IP,
                         first_seen=AT + timedelta(minutes=40), last_seen=AT + timedelta(minutes=50)))
        db.add(EasDevice(username=JOANN, device_id=f"{MARK}tablet", device_type="iPad", last_ip=SIMILAR_IP,
                         first_seen=AT, last_seen=AT + timedelta(minutes=5)))

        # DMARC: the IP sends for two domains; the similar IP for one of them
        for domain, n, ip, spf in ((DMARC_A, 7, IP, "pass"), (DMARC_B, 3, IP, "fail"), (DMARC_A, 100, SIMILAR_IP, "pass")):
            report = DMARCReport(report_id=f"{MARK}-{domain}-{ip}", domain=domain, org_name="Reporter Example",
                                 begin_date=_epoch(AT - timedelta(days=1)), end_date=_epoch(AT),
                                 created_at=AT + timedelta(hours=6))
            db.add(report)
            db.flush()
            db.add(DMARCRecord(dmarc_report_id=report.id, source_ip=ip, count=n, disposition="none",
                               spf_result=spf, dkim_result="fail", header_from=domain))
        # Own domain DMARC
        report = DMARCReport(report_id=f"{MARK}-own", domain=DOMAIN, org_name="Reporter Example",
                             begin_date=_epoch(AT - timedelta(days=1)), end_date=_epoch(AT), created_at=AT)
        db.add(report)
        db.flush()
        db.add(DMARCRecord(dmarc_report_id=report.id, source_ip=IP, count=5, spf_result="pass", dkim_result="pass"))

        db.add(BlacklistCheck(server_ip=CHECKED_IP, total_blacklists=2, listed_count=1, clean_count=1, error_count=0,
                              timeout_count=0, status="listed", checked_at=AT,
                              results=[{"name": "Example RBL", "zone": "rbl.example", "listed": True},
                                       {"name": "Other RBL", "zone": "other.example", "listed": False}]))
        db.add(SpamSuppression(email=ANN, type="email", reason="hard_bounce", source="auto", active=True, created_at=AT))
        db.add(SpamSuppression(email=DOMAIN, type="domain", reason="manual", source="manual", active=True, created_at=AT))
        db.add(MailboxStatistics(username=ANN, domain=DOMAIN, name="Ann", active=True))
        db.commit()


@pytest.fixture()
def client(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    monkeypatch.setattr(settings._inner, 'blacklist_emails', HIDDEN)
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    monkeypatch.setattr(config, '_cached_active_domains', [DOMAIN])
    monkeypatch.setattr(config, '_cached_hosted_domains', {DOMAIN})

    async def fake_fail2ban():
        return {'ban_time': 600, 'max_attempts': 5, 'whitelist': '', 'blacklist': '203.0.113.0/24',
                'active_bans': [{'network': f'{IP}/32', 'ip': IP, 'banned_until': '00h 20m 00s', 'queued_for_unban': 0}]}
    monkeypatch.setattr(mailcow_api, 'get_fail2ban', fake_fail2ban)

    from app.database import init_db
    init_db()
    _cleanup()
    _seed()
    from fastapi.testclient import TestClient
    from app.main import app
    yield TestClient(app)
    _cleanup()


def _card(client, kind, value, **params):
    res = client.get(f"/api/entities/{kind}", params={"value": value, **RANGE, **params})
    assert res.status_code == 200, res.text
    return res.json()


def _subjects(source):
    return sorted(i["subject"].split()[0] for i in source["items"])


# ---------------------------------------------------------------- IP

def test_ip_card_matches_the_address_exactly(client):
    card = _card(client, "ip", IP)
    assert card["kind"] == "ip" and card["value"] == IP
    s = card["sources"]
    # Two deliveries of one message count once; the excluded recipient's message is left out; the
    # similar IP 203.0.113.45 is not 203.0.113.4
    assert s["messages"]["state"] == "ok" and s["messages"]["count"] == 1
    assert _subjects(s["messages"]) == ["ip-leg1"]
    sec = s["security"]
    assert (sec["events"], sec["rule_matches"], sec["bans"], sec["unbans"]) == (4, 2, 1, 0)
    assert {i["ip"] for i in sec["items"]} == {IP}
    assert s["protection"]["count"] == 1 and s["protection"]["open"] == 1
    assert [d["device_id"] for d in s["devices"]["items"]] == [f"{MARK}phone"]
    assert s["lists"] == {"state": "ok", "reason": None, "allowlisted_as": None, "denylisted_as": "203.0.113.0/24",
                          "ban": {"network": f"{IP}/32", "banned_until": "00h 20m 00s", "queued_for_unban": False}}


def test_ip_card_dmarc_covers_every_domain(client):
    dmarc = _card(client, "ip", IP)["sources"]["dmarc"]
    assert dmarc["state"] == "ok"
    assert (dmarc["messages"], dmarc["domains"], dmarc["reports"]) == (15, 3, 3)
    by_domain = {d["domain"]: d for d in dmarc["by_domain"]}
    assert by_domain[DMARC_A]["messages"] == 7 and by_domain[DMARC_A]["spf_pass"] == 7
    assert by_domain[DMARC_B]["messages"] == 3 and by_domain[DMARC_B]["dmarc_pass"] == 0
    assert by_domain[DOMAIN]["dkim_pass"] == 5
    # The report period and when it came in are separate
    record = next(r for r in dmarc["records"] if r["domain"] == DMARC_A)
    assert record["period_end"] == "2020-03-10T12:00:00Z" and record["received"] == "2020-03-10T18:00:00Z"
    assert record["period_begin"] == "2020-03-09T12:00:00Z"


def test_rbl_is_the_stored_check_or_not_checked(client):
    checked = _card(client, "ip", CHECKED_IP)["sources"]["rbl"]
    assert checked["state"] == "ok" and checked["checked"] is True
    assert checked["status"] == "listed" and checked["listed"] == ["Example RBL"]
    assert checked["checked_at"] == "2020-03-10T12:00:00Z"
    unchecked = _card(client, "ip", UNCHECKED_IP)["sources"]["rbl"]
    assert unchecked == {"state": "ok", "reason": None, "checked": False, "monitored": False}


def test_ip_card_reads_ipv6_in_any_form(client):
    card = _card(client, "ip", "2001:DB8:0:0::1")
    assert card["value"] == "2001:db8::1"
    assert card["sources"]["messages"]["count"] == 0


def test_lists_unknown_when_mailcow_does_not_answer(client, monkeypatch):
    async def no_answer():
        return None
    monkeypatch.setattr(mailcow_api, 'get_fail2ban', no_answer)
    lists = _card(client, "ip", IP)["sources"]["lists"]
    assert lists["state"] == "error" and "mailcow did not answer" in lists["reason"]
    assert "allowlisted_as" not in lists and "ban" not in lists


# ---------------------------------------------------------------- address

def test_address_card_matches_the_address_exactly(client):
    card = _card(client, "address", "Ann@" + DOMAIN.upper())
    assert card["value"] == ANN and card["display"] == "Ann@" + DOMAIN.upper()
    assert card["domain"] == DOMAIN and card["hosted_domain"] is True and card["excluded"] is False
    s = card["sources"]
    # ann@ never finds joann@; the stored address in upper case is the same address
    assert _subjects(s["messages"]) == ["ann-out", "ip-leg1"]
    assert (s["messages"]["count"], s["messages"]["sent"], s["messages"]["received"]) == (2, 1, 1)
    # The account was tried from both addresses
    assert s["security"]["rule_matches"] == 2 and s["security"]["ips"] == 2
    assert s["protection"]["count"] == 1
    assert [d["username"] for d in s["devices"]["items"]] == [ANN]
    assert s["suppression"]["entry"]["email"] == ANN and s["suppression"]["domain_entry"]["email"] == DOMAIN
    assert s["mailbox"]["local"] is True and s["mailbox"]["mailbox"]["username"] == ANN


def test_underscore_and_percent_in_an_address_are_plain_characters(client):
    card = _card(client, "address", WILD)
    assert _subjects(card["sources"]["messages"]) == ["wild"]
    assert card["sources"]["mailbox"]["local"] is False


def test_an_excluded_address_shows_no_messages(client):
    card = _card(client, "address", HIDDEN)
    assert card["excluded"] is True
    messages = card["sources"]["messages"]
    assert messages["state"] == "disabled" and "excluded" in messages["reason"] and "count" not in messages
    assert "messages" in card["timeline"]["left_out"]


# ---------------------------------------------------------------- domain

def test_domain_card_matches_the_part_after_the_last_at(client):
    card = _card(client, "domain", DOMAIN.upper() + ".")
    assert card["value"] == DOMAIN and card["hosted"] is True
    s = card["sources"]
    # Not sub.<domain>, not <domain>.evil.example; the excluded address stays out
    assert _subjects(s["messages"]) == ["ann-out", "ip-leg1", "joann", "similar", "wild", "wild-lookalike"]
    assert (s["messages"]["count"], s["messages"]["sent"], s["messages"]["received"]) == (6, 4, 2)
    assert s["dmarc"]["messages"] == 5 and s["dmarc"]["reports"] == 1 and s["dmarc"]["sources"] == 1
    assert s["suppression"]["entry"]["email"] == DOMAIN
    assert s["mailboxes"]["mailboxes"] == 1
    assert s["devices"]["count"] == 2
    assert s["dns"] == {"state": "ok", "reason": None, "checked": False}


def test_underscore_in_a_domain_is_a_plain_character(client):
    card = _card(client, "domain", UNDERSCORE_DOMAIN)
    assert _subjects(card["sources"]["messages"]) == ["under"]


# ---------------------------------------------------------------- states

def test_a_feature_that_is_off_is_disabled_never_zero(client, monkeypatch):
    monkeypatch.setattr(settings._inner, 'disabled_features', 'netfilter,devices,dmarc,blacklist')
    card = _card(client, "ip", IP)
    for name in ("security", "lists", "protection", "devices", "dmarc", "rbl"):
        source = card["sources"][name]
        assert source["state"] == "disabled" and "turned off" in source["reason"], name
        assert set(source) == {"state", "reason"}, name
    assert card["sources"]["messages"]["count"] == 1
    assert card["sources"]["geo"]["state"] == "disabled"
    assert set(card["timeline"]["left_out"]) == {"security", "protection", "devices"}
    assert {i["kind"] for i in card["timeline"]["items"]} == {"message"}


def test_a_source_that_fails_is_an_error_and_the_others_still_answer(client, monkeypatch):
    from app.services import entity_summary

    def broken(db, *args, **kwargs):
        from sqlalchemy import text
        db.execute(text("SELECT no_such_column FROM netfilter_logs"))
    monkeypatch.setattr(entity_summary, '_security', broken)
    card = _card(client, "ip", IP)
    assert card["sources"]["security"]["state"] == "error"
    assert "events" not in card["sources"]["security"]
    # The failed statement did not take the next sources with it
    assert card["sources"]["protection"]["state"] == "ok" and card["sources"]["devices"]["count"] == 1
    assert "security" in card["timeline"]["left_out"]


# ---------------------------------------------------------------- timeline

def test_ip_timeline_is_newest_first_with_its_labels(client):
    timeline = _card(client, "ip", IP)["timeline"]
    items = timeline["items"]
    times = [i["time"] for i in items]
    assert times == sorted(times, reverse=True)
    assert [(i["kind"], i["label"]) for i in items] == [
        ("device_last_seen", "Device last seen"),
        ("protection", "Protection catch"),
        ("ban", "Banned"),
        ("security", "Security event"),
        ("security", "Security event"),
        ("message", "Message"),
    ]
    assert timeline["truncated"] is False and timeline["left_out"] == []


def test_address_timeline_has_device_first_and_last_seen(client):
    kinds = [i["kind"] for i in _card(client, "address", ANN)["timeline"]["items"]]
    assert kinds == ["device_last_seen", "device_first_seen", "protection", "security", "security", "message", "message"]


def test_no_label_calls_anything_a_login(client):
    for kind, value in (("ip", IP), ("address", ANN)):
        for item in _card(client, kind, value)["timeline"]["items"]:
            assert "login" not in item["label"].lower()


# ---------------------------------------------------------------- the request

@pytest.mark.parametrize("kind,value,says", [
    ("ip", "203.0.113.0/24", "not a network"),
    ("ip", "fe80::1%eth0", "interface"),
    ("ip", "example.com", "one IP address"),
    ("address", "ann", "one email address"),
    ("address", "ann @example.com", "without spaces"),
    ("domain", "ann@example.com", "a domain"),
    ("domain", "x" * 300, "too long"),
])
def test_a_bad_value_is_422_with_what_to_change(client, kind, value, says):
    res = client.get(f"/api/entities/{kind}", params={"value": value})
    assert res.status_code == 422
    assert says in res.json()["detail"]


@pytest.mark.parametrize("params,says", [
    ({"start_date": "2020-03-20", "end_date": "2020-03-01"}, "before its end"),
    ({"start_date": "2020-01-01", "end_date": "2020-05-01"}, "90 days at most"),
    ({"start_date": "2020-01-01"}, "90 days at most"),
])
def test_range_is_checked(client, params, says):
    res = client.get("/api/entities/ip", params={"value": IP, **params})
    assert res.status_code == 422 and says in res.json()["detail"]


def test_default_range_is_the_last_seven_days(client):
    card = client.get("/api/entities/address", params={"value": ANN}).json()
    start = datetime.fromisoformat(card["range"]["start"].replace("Z", ""))
    end = datetime.fromisoformat(card["range"]["end"].replace("Z", ""))
    assert end - start == timedelta(days=7)
    # March 2020 is outside it
    assert card["sources"]["messages"]["count"] == 0


def test_missing_value_is_422(client):
    assert client.get("/api/entities/domain").status_code == 422
