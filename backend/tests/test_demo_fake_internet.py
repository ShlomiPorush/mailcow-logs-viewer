"""
The demo's fake internet, exercised through the application's own checks:
the Domains page's DNS checks, the blocklist lookups, the HTTP calls to
GitHub and MaxMind, mail, webhooks and GeoIP.
"""
import asyncio

import httpx
import pytest

from app.mailcow_api import MailcowAPI
from app.routers import domains
from app.routers import settings as settings_router
from app.services import (blacklist_service, connection_test, dmarc_imap_service, dns_resolver,
                          geoip_downloader, geoip_service, notification_channels, smtp_service)
from demo import fake_internet, fake_mailcow, world

_PATCHED = [
    (dns_resolver, "resolve"), (dns_resolver, "resolve_for_blacklist"), (httpx, "AsyncClient"),
    (smtp_service.SmtpService, "send_email"), (connection_test, "test_smtp_connection"),
    (connection_test, "test_imap_connection"), (settings_router, "test_smtp_connection"),
    (settings_router, "test_imap_connection"), (dmarc_imap_service.DMARCImapService, "sync_reports"),
    (notification_channels, "send_to_config"), (geoip_downloader, "download_single_database"),
    (geoip_service, "lookup_ip"), (geoip_service, "is_geoip_available"),
    (MailcowAPI, "_get_client"),
]


@pytest.fixture
def internet(monkeypatch):
    saved = [(obj, name, getattr(obj, name)) for obj, name in _PATCHED]
    fake_mailcow.install(fake_mailcow.FakeMailcow())
    fake_internet.install()
    monkeypatch.setattr(domains, "_server_ip_cache", world.SERVER_IPV4)
    # check_dkim_record uses the module-level client; give it a fresh one
    monkeypatch.setattr(domains, "mailcow_api", MailcowAPI())
    try:
        yield
    finally:
        for obj, name, value in saved:
            setattr(obj, name, value)


def statuses(result):
    return {k: v["status"] for k, v in result.items() if isinstance(v, dict) and "status" in v}


def test_domains_show_good_warning_and_error_states(internet):
    async def checks():
        return [await domains.check_domain_dns(d) for d in ("example.com", "example.org", "shop.test", "example.net")]

    com, org, shop, net = asyncio.run(checks())
    assert statuses(com) == {"spf": "success", "dkim": "success", "dmarc": "success",
                             "tlsa": "success", "mta_sts": "success"}
    assert statuses(org)["dmarc"] == "warning"
    assert "~all" in org["spf"]["message"]
    assert statuses(shop)["dmarc"] == "error"
    # The alias domain has its own DKIM key in mailcow and in DNS
    assert statuses(net)["dkim"] == "success"


def test_answers_are_stable_so_no_dns_change_alert_fires(internet):
    first = asyncio.run(dns_resolver.resolve("example.com", "TXT"))
    second = asyncio.run(dns_resolver.resolve("example.com", "TXT"))
    assert [r.to_text() for r in first] == [r.to_text() for r in second]


def test_unknown_names_do_not_exist(internet):
    import dns.resolver
    with pytest.raises(dns.resolver.NXDOMAIN):
        asyncio.run(dns_resolver.resolve("nothing.example.com", "A"))
    with pytest.raises(dns.resolver.NoAnswer):
        asyncio.run(dns_resolver.resolve("example.com", "AAAA"))


def test_the_server_is_listed_on_exactly_one_blocklist(internet):
    async def check_all():
        return [await blacklist_service.check_ip_in_blacklist(world.SERVER_IPV4, bl, i)
                for i, bl in enumerate(blacklist_service.applicable_blacklists(world.SERVER_IPV4))]

    results = asyncio.run(check_all())
    listed = [r["zone"] for r in results if r["status"] == "listed"]
    assert listed == ["dnsbl-3.uceprotect.net"]
    assert all(r["status"] in ("clean", "listed") for r in results)


def test_http_calls_get_fictional_answers(internet):
    from app.version import __version__

    async def calls():
        async with httpx.AsyncClient() as client:
            app_release = (await client.get(
                "https://api.github.com/repos/ShlomiPorush/mailcow-logs-viewer/releases/latest")).json()
            mailcow_release = (await client.get(
                "https://api.github.com/repos/mailcow/mailcow-dockerized/releases/latest")).json()
            policy = (await client.get("https://mta-sts.example.com/.well-known/mta-sts.txt")).text
            doc = await client.get("https://raw.githubusercontent.com/ShlomiPorush/mailcow-logs-viewer/"
                                   "main/documentation/HelpDocs/Domains.md")
            with pytest.raises(httpx.ConnectError):
                await client.get("https://unknown.example.com/")
        return app_release, mailcow_release, policy, doc

    app_release, mailcow_release, policy, doc = asyncio.run(calls())
    assert app_release["tag_name"] == f"v{__version__}"
    assert mailcow_release["tag_name"] == world.MAILCOW_VERSION
    assert "mode: enforce" in policy
    assert doc.status_code == 200 and doc.text.strip()


def test_help_documents_cannot_escape_their_folder(internet):
    async def fetch():
        async with httpx.AsyncClient() as client:
            return await client.get("https://raw.githubusercontent.com/x/documentation/HelpDocs/..%2F..%2FDockerfile")

    assert asyncio.run(fetch()).status_code == 404


def test_the_mailcow_client_keeps_its_own_fake(internet):
    api = MailcowAPI()
    assert asyncio.run(api.get_status_host_ip()) == world.SERVER_IPV4


def test_mail_tests_and_webhooks_succeed_without_sending(internet):
    assert smtp_service.SmtpService().send_email("alice@example.com", "Hi", "text") is True
    assert settings_router.test_smtp_connection()["success"] is True
    assert settings_router.test_imap_connection()["success"] is True
    assert notification_channels.send_to_config("slack", {}, "s", "m") == (True, "")
    assert geoip_downloader.download_single_database() is False


def test_geoip_is_stable_and_uses_documentation_asns(internet):
    first = geoip_service.lookup_ip("203.0.113.66")
    assert first == geoip_service.lookup_ip("203.0.113.66")
    assert first["country_code"] and first["city"]
    assert 64496 <= int(first["asn"][2:]) <= 64511
    assert geoip_service.lookup_ip(world.SERVER_IPV4)["asn_org"] == "Demo Hosting GmbH"
    assert geoip_service.is_geoip_available() is True
