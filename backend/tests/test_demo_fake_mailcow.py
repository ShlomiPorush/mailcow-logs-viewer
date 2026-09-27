"""
The demo's fake mailcow server, driven through the real MailcowAPI client so
the application's own request, retry and parsing code is what is tested.
"""
import asyncio
import logging

import pytest

from app.mailcow_api import MailcowAPI
from demo import fake_mailcow, world


@pytest.fixture
def api(monkeypatch):
    fake = fake_mailcow.FakeMailcow(now=1_790_000_000)
    original = MailcowAPI._get_client
    fake_mailcow.install(fake)
    client = MailcowAPI()
    client.headers_rw = {"X-API-Key": "demo", "Content-Type": "application/json"}
    from app.config import settings
    monkeypatch.setattr(settings._inner, "rspamd_password", "demo")
    try:
        yield client, fake
    finally:
        MailcowAPI._get_client = original


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def no_unhandled_routes(caplog):
    caplog.set_level(logging.WARNING, logger="demo.fake_mailcow")
    yield
    unhandled = [r.getMessage() for r in caplog.records if "has no answer" in r.getMessage()]
    assert not unhandled, unhandled


def test_every_read_the_app_makes_is_answered(api, no_unhandled_routes):
    client, _ = api

    async def reads():
        assert await client.test_connection() is True  # an empty log list is still an answer
        assert await client.get_active_domains() == ["example.com", "example.org", "shop.test"]
        assert await client.get_alias_domain_map() == {"example.net": "example.com"}
        assert len(await client.get_mailboxes()) == len(world.MAILBOXES)
        assert any(a["is_catch_all"] for a in await client.get_aliases())
        queue = await client.get_queue()
        assert {q["queue_name"] for q in queue} >= {"deferred", "hold"}
        assert all(isinstance(q["sender"], str) and isinstance(q["recipients"], list) for q in queue)
        quarantine = await client.get_quarantine()
        assert all(isinstance(q["score"], float) for q in quarantine)
        details = await client.get_quarantine_details(str(quarantine[0]["id"]))
        assert details["subject"] == quarantine[0]["subject"]
        containers = (await client.get_status_containers())[0]
        assert all(c["state"] == "running" for c in containers.values())
        assert (await client.get_status_vmail())["used_percent"].endswith("%")
        assert await client.get_status_version() == world.MAILCOW_VERSION
        assert await client.get_status_host_ip() == world.SERVER_IPV4
        assert (await client.get_dkim("example.com"))["dkim_selector"] == "dkim"
        assert await client.get_transports() == []
        assert await client.get_relayhosts() == []
        assert (await client.get_fail2ban())["active_bans"]
        assert await client.get_app_passwords("alice@example.com")
        assert await client.get_rl_domain("example.com") == {"value": "2000", "frame": "h"}
        maps = await client.get_rspamd_maps()
        assert len(maps) == len(world.RSPAMD_MAPS)
        map_id = await client.find_rspamd_map_id("bad_words.map")
        assert "prize" in await client.get_rspamd_map_content(map_id)
        for service in fake_mailcow.LOG_SERVICES:
            assert await client.get_raw_logs(service, 10) == []

    run(reads())


def test_active_flags_are_integers_and_access_attributes_strings(api):
    client, _ = api
    mailboxes = run(client.get_mailboxes())
    assert all(isinstance(m["active"], int) for m in mailboxes)
    assert all(isinstance(v, str) for m in mailboxes for v in m["attributes"].values())
    assert all(isinstance(d["active"], int) for d in run(client.get_domains()))


def test_logs_are_newest_first_with_mailcow_range_semantics(api):
    client, fake = api
    fake.push_logs("postfix", [{"time": str(1_790_000_000 + i), "program": "postfix/smtpd",
                                "priority": "info", "message": f"line {i}"} for i in range(5)])
    fake.push_logs("rspamd-history", [{"unix_time": 1_790_000_000 + i, "message-id": f"m{i}@example.com"}
                                      for i in range(5)])

    async def reads():
        head = await client.get_postfix_logs(2)
        assert [e["message"] for e in head] == ["line 4", "line 3"]
        # 1-based on the Redis lists: 2-3 is the second and third newest
        page = await client.get_postfix_logs_page(page_size=2, offset=1)
        assert [e["message"] for e in page] == ["line 3", "line 2"]
        # 0-based on rspamd-history
        page = await client.get_raw_logs_range("rspamd-history", offset=1, page_size=2)
        assert [e["message-id"] for e in page] == ["m3@example.com", "m2@example.com"]
        assert await client.probe_log_position("postfix", 5) is True
        assert await client.probe_log_position("postfix", 6) is False

    run(reads())


def test_log_buffers_are_capped_like_mailcow():
    fake = fake_mailcow.FakeMailcow(log_cap=3)
    fake.push_logs("netfilter", [{"time": i, "message": str(i)} for i in range(5)])
    assert [e["message"] for e in fake.logs["netfilter"]] == ["4", "3", "2"]


def test_queue_actions_change_what_the_queue_shows(api):
    client, _ = api

    async def flow():
        deferred = [q["queue_id"] for q in await client.get_queue() if q["queue_name"] == "deferred"]
        result = await client.edit_queue([deferred[0]], "hold")
        assert result[0]["type"] == "success"
        held = {q["queue_id"] for q in await client.get_queue() if q["queue_name"] == "hold"}
        assert deferred[0] in held
        await client.delete_queue([deferred[0]])
        assert deferred[0] not in {q["queue_id"] for q in await client.get_queue()}
        await client.edit_queue(["mailqitems-all"], "super_delete")
        assert await client.get_queue() == []

    run(flow())


def test_quarantine_release_and_delete_remove_the_item(api):
    client, _ = api

    async def flow():
        items = await client.get_quarantine()
        result = await client.release_quarantine([str(items[0]["id"])])
        assert result[0]["type"] == "success"
        await client.delete_quarantine([str(items[1]["id"])])
        remaining = {q["id"] for q in await client.get_quarantine()}
        assert items[0]["id"] not in remaining and items[1]["id"] not in remaining
        assert len(remaining) == len(items) - 2

    run(flow())


def test_fail2ban_ban_allow_and_unban(api):
    client, _ = api

    async def flow():
        f2b = await client.get_fail2ban()
        attrs = {k: str(f2b[k]) for k in ("ban_time", "max_ban_time", "ban_time_increment",
                                          "max_attempts", "retry_window", "netban_ipv4", "netban_ipv6")}
        attrs["whitelist"] = f2b["whitelist"].replace("\n", ",")
        attrs["blacklist"] = f2b["blacklist"].replace("\n", ",") + ",192.0.2.201"
        result = await client.edit_fail2ban(attrs)
        assert result[0]["type"] == "success"
        f2b = await client.get_fail2ban()
        assert {"network": "192.0.2.201/32", "ip": "192.0.2.201"} in f2b["perm_bans"]
        result = await client.unban_fail2ban("203.0.113.5")
        assert result[0]["type"] == "success"
        assert "203.0.113.5" not in {b["ip"] for b in (await client.get_fail2ban())["active_bans"]}
        result = await client.unban_fail2ban("203.0.113.5")
        assert result[0]["type"] == "danger"

    run(flow())


def test_mailbox_rate_limit_and_map_edits_persist(api):
    client, _ = api

    async def flow():
        await client.edit_mailbox("bob@example.com", {"smtp_access": "0"})
        bob = next(m for m in await client.get_mailboxes() if m["username"] == "bob@example.com")
        assert bob["attributes"]["smtp_access"] == "0" and bob["smtp_access"] == 0

        await client.edit_rl_mbox("bob@example.com", "50", "h")
        bob = next(m for m in await client.get_mailboxes() if m["username"] == "bob@example.com")
        assert bob["rl"] == {"value": "50", "frame": "h"}
        await client.edit_rl_domain("example.org", "300", "d")
        assert await client.get_rl_domain("example.org") == {"value": "300", "frame": "d"}
        assert await client.delete_rl_hash("RLabc123") is None

        ids = [str(p["id"]) for p in await client.get_app_passwords("alice@example.com")]
        await client.delete_app_passwords(ids)
        assert await client.get_app_passwords("alice@example.com") == []

        await client.edit_rspamd_map("global_rcpt_blacklist.map", "# denied\nvictim@example.com\n")
        map_id = await client.find_rspamd_map_id("global_rcpt_blacklist.map")
        assert "victim@example.com" in await client.get_rspamd_map_content(map_id)

    run(flow())


def test_reset_restores_the_world(api):
    client, fake = api
    run(client.edit_queue(["mailqitems-all"], "super_delete"))
    fake.push_logs("postfix", [{"time": "1", "message": "x"}])
    fake.reset(now=1_790_000_000)
    assert len(run(client.get_queue())) == len(world.build_queue())
    assert fake.logs["postfix"] == []


def test_unknown_routes_are_logged(caplog):
    import httpx

    fake = fake_mailcow.FakeMailcow()
    caplog.set_level(logging.WARNING, logger="demo.fake_mailcow")
    response = fake.handle(httpx.Request("GET", "https://mail.example.com/api/v1/get/nothing"))
    assert response.status_code == 404
    assert any("has no answer" in r.getMessage() for r in caplog.records)
