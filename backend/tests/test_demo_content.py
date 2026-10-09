"""
The demo's generated history: its log lines must parse the way the
application's own parsers expect, stay inside what one fetch cycle ingests,
and use only fictional names and documentation addresses. Also the
database safety of the nightly reset and its timing.
"""
import ipaddress
import re
import time
import unicodedata
import uuid

import pytest

from app.correlation import detect_direction, parse_postfix_message
from app.scheduler import parse_netfilter_message
from app.services.dmarc_parser import parse_dmarc_file
from app.services.dovecot_parser import parse_dovecot_message
from app.services.tls_rpt_parser import parse_tls_rpt_file
from demo import reports, seed, world
from demo.traffic import Traffic

NOW = 1_790_000_000


@pytest.fixture(scope="module")
def week():
    return Traffic(seed=42).generate(NOW - 7 * 86400 + 3600, NOW)


def test_the_same_seed_rebuilds_the_same_week(week):
    again = Traffic(seed=42).generate(NOW - 7 * 86400 + 3600, NOW)
    assert again == week


def test_postfix_lines_parse(week):
    with_qid = [e for e in week["postfix"] if re.match(r"^[A-F0-9]+:", e["message"])]
    assert len(with_qid) > 0.6 * len(week["postfix"])
    statuses = {parse_postfix_message(e["message"]).get("status") for e in with_qid}
    assert {"sent", "deferred", "bounced"} <= statuses
    assert all(isinstance(e["time"], str) and e["time"].isdigit() for e in week["postfix"])


def test_every_rspamd_message_has_its_postfix_message_id(week):
    postfix_ids = {parse_postfix_message(e["message"]).get("message_id") for e in week["postfix"]
                   if "message-id=" in e["message"]}
    rspamd_ids = {e["message-id"] for e in week["rspamd-history"]}
    assert rspamd_ids <= postfix_ids
    assert all(isinstance(e["unix_time"], int) for e in week["rspamd-history"])


def test_directions_cover_inbound_and_outbound(week):
    directions = {detect_direction(e) for e in week["rspamd-history"]}
    assert {"inbound", "outbound"} <= directions
    # An empty user would make the direction "unknown"
    assert "" not in {e["user"] for e in week["rspamd-history"]}


def test_dovecot_lines_parse_and_match_messages(week):
    rspamd_ids = {e["message-id"] for e in week["rspamd-history"]}
    parsed = [parse_dovecot_message(e["message"]) for e in week["dovecot"]]
    assert parsed and all(p for p in parsed)
    assert {p["message_id"] for p in parsed} <= rspamd_ids


def test_netfilter_lines_parse_and_include_a_live_attack(week):
    parsed = [parse_netfilter_message(e["message"], e["priority"]) for e in week["netfilter"]]
    assert all(p.get("ip") for p in parsed)
    assert any(p.get("action") == "ban" for p in parsed)
    recent = [e for e in week["netfilter"] if e["time"] > NOW - 900 and "admin@example.com" in e["message"]]
    assert len(recent) >= 20  # the auth-failure burst alert threshold


def test_activesync_lines_parse_into_every_demo_device(week):
    from app.services.eas_devices import collect_devices
    devices = {(d["username"], d["device_id"]): d for d in collect_devices(week["sogo"])}
    assert set(devices) == {(user, device_id) for user, device_id, *_ in world.EAS_DEVICES}
    assert devices[("heidi@example.org", world.EAS_FAILING_DEVICE)]["last_status"] == 401
    assert any(":" in (d["last_ip"] or "") for d in devices.values())


def test_volumes_fit_one_ingest_cycle(week):
    # netfilter is fetched as the newest 500 only; services without raw-log
    # catch-up are read as the newest 1000
    assert len(week["netfilter"]) < 500
    for service in ("dovecot", "sogo", "watchdog", "api", "autodiscover", "acme", "ratelimited"):
        assert len(week[service]) < 1000, service
    assert len(week["postfix"]) + 5000 < seed.LOG_CAP


def test_only_fictional_names_and_documentation_addresses(week):
    documentation = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    private = ipaddress.ip_network("172.16.0.0/12")
    text = repr(week)
    for ip in set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)):
        addr = ipaddress.ip_address(ip)
        assert any(addr in n for n in documentation) or addr in private or addr.is_loopback, ip
    for domain in set(re.findall(r"@([a-z0-9.-]+\.[a-z]+)", text)):
        assert domain.endswith((".test", "example.com", "example.org", "example.net")), domain


def test_queue_recipients_cannot_be_suppressed_by_the_history():
    from demo.traffic import REMOTE_PEOPLE
    for item in world.build_queue(NOW):
        for rcpt in item["recipients"]:
            local = rcpt.split("@", 1)[0]
            assert local not in REMOTE_PEOPLE, rcpt


def test_rtl_subjects_are_present(week):
    # Bidi class R is Hebrew, AL is Arabic
    classes = {unicodedata.bidirectional(c) for e in week["rspamd-history"] for c in e["subject"]}
    assert {"R", "AL"} <= classes


def test_reports_parse_with_the_application_parsers():
    files = reports.build(NOW, seed=1)
    dmarc = [(n, c) for n, c in files if n.endswith(".xml.gz")]
    tls = [(n, c) for n, c in files if n.endswith(".json.gz")]
    assert dmarc and tls
    for name, content in dmarc:
        parsed = parse_dmarc_file(content, name)
        assert parsed and parsed["records"], name
        assert parsed["domain"] in ("example.com", "example.org")
    for name, content in tls:
        parsed = parse_tls_rpt_file(content, name)
        assert parsed and parsed["policies"], name


@pytest.fixture
def jerusalem(monkeypatch):
    if not hasattr(time, "tzset"):
        pytest.skip("time.tzset is POSIX only")
    monkeypatch.setenv("TZ", "Asia/Jerusalem")
    time.tzset()
    yield
    monkeypatch.delenv("TZ")
    time.tzset()


# 2026-09-27 21:30 in Jerusalem (UTC+3)
EVENING = 1_790_533_800


def test_the_reset_defaults_to_midnight_in_the_container_time_zone(jerusalem):
    assert seed.seconds_until_reset(seed.parse_reset_time(None), EVENING) == pytest.approx(2.5 * 3600)


def test_the_reset_time_can_be_chosen(jerusalem):
    # Later the same evening, and early the next morning
    assert seed.seconds_until_reset(seed.parse_reset_time("22:15"), EVENING) == pytest.approx(45 * 60)
    assert seed.seconds_until_reset(seed.parse_reset_time("04:30"), EVENING) == pytest.approx(7 * 3600)
    # A time that just passed is tomorrow, never now
    assert seed.seconds_until_reset(seed.parse_reset_time("21:30"), EVENING) == pytest.approx(24 * 3600)


def test_the_reset_time_crosses_a_dst_change(jerusalem):
    # Israel leaves summer time on 2026-10-25 at 02:00; from 20:00 the evening
    # before, 04:30 is 8.5 hours of wall clock but 9.5 real hours away
    evening_before = 1_792_861_200  # 2026-10-24 20:00 IDT
    assert seed.seconds_until_reset(seed.parse_reset_time("04:30"), evening_before) == pytest.approx(9.5 * 3600)


@pytest.mark.parametrize("value", ["", None, "  "])
def test_an_unset_reset_time_is_midnight(value):
    assert seed.parse_reset_time(value) == (0, 0)


@pytest.mark.parametrize("value", ["24:00", "7", "07:5", "7pm", "12:60", "ab:cd"])
def test_an_invalid_reset_time_falls_back_to_midnight(value, caplog):
    assert seed.parse_reset_time(value) == (0, 0)
    assert "DEMO_RESET_TIME" in caplog.text


@pytest.mark.parametrize("value,expected", [("00:00", (0, 0)), ("4:30", (4, 30)), ("23:59", (23, 59))])
def test_valid_reset_times(value, expected):
    assert seed.parse_reset_time(value) == expected


def _isolated_schema():
    from sqlalchemy import create_engine, text
    from app.database import engine
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    schema = "demo_seed_" + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    return engine, schema, text


def test_reset_empties_a_demo_database_and_refuses_any_other():
    engine, schema, text = _isolated_schema()
    try:
        # A database with someone else's tables is never touched
        with engine.begin() as conn:
            conn.execute(text(f"CREATE TABLE {schema}.real_data (id int)"))
            conn.execute(text(f"INSERT INTO {schema}.real_data VALUES (1)"))
        with pytest.raises(seed.NotADemoDatabase):
            seed.prepare_database(engine, schema=schema)
        with engine.connect() as conn:
            assert conn.execute(text(f"SELECT count(*) FROM {schema}.real_data")).scalar() == 1

        # An empty database becomes a demo database; a demo database is emptied
        with engine.begin() as conn:
            conn.execute(text(f"DROP TABLE {schema}.real_data"))
        seed.prepare_database(engine, schema=schema)
        with engine.begin() as conn:
            conn.execute(text(f"CREATE TABLE {schema}.visitor_changes (id int)"))
        seed.prepare_database(engine, schema=schema)
        with engine.connect() as conn:
            tables = set(conn.execute(text(
                "SELECT tablename FROM pg_tables WHERE schemaname = :s"), {"s": schema}).scalars())
        assert tables == {seed.MARKER_TABLE}
    finally:
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA IF EXISTS {schema} CASCADE"))
