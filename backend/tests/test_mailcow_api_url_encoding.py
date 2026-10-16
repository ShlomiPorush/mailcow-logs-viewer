"""Values placed in a mailcow URL are encoded, so they cannot change the request.

get_dkim put the domain into the path as-is and get_quarantine_details put the
item ID into the query string as-is: a value with '/', '?' or '&' reached a
different mailcow endpoint or added query parameters. The DNS-check routes
also passed any path value on, so they now accept only a domain name.
"""
import asyncio

import pytest
from fastapi import HTTPException

from app import mailcow_api as mod
from app.routers import domains
from tests.test_mailcow_api_recovery import server  # noqa: F401  (the fake mailcow)


def _run(coro_factory):
    async def scenario():
        api = mod.MailcowAPI()
        try:
            return await coro_factory(api)
        finally:
            await api.aclose()
    return asyncio.run(scenario())


def test_dkim_domain_stays_one_path_segment(server):
    _run(lambda api: api.get_dkim("example.com/../../get/status/version?x=1"))
    request = server["requests"][-1]
    assert request.url.raw_path == (
        b"/api/v1/get/dkim/example.com%2F..%2F..%2Fget%2Fstatus%2Fversion%3Fx%3D1"
    )
    assert request.url.query == b""


def test_plain_dkim_domain_is_unchanged(server):
    _run(lambda api: api.get_dkim("mail.example.com"))
    assert server["requests"][-1].url.raw_path == b"/api/v1/get/dkim/mail.example.com"


def test_quarantine_item_id_is_one_query_value(server):
    _run(lambda api: api.get_quarantine_details("17&action=delete"))
    request = server["requests"][-1]
    assert request.url.path == "/inc/ajax/qitem_details.php"
    assert dict(request.url.params) == {"id": "17&action=delete"}


@pytest.fixture
def dns_checked(monkeypatch):
    checked = []

    async def fake_check(domain):
        checked.append(domain)
        return {"domain": domain}

    monkeypatch.setattr(domains, "check_domain_dns", fake_check)
    monkeypatch.setattr(domains, "store_dns_check_worker", lambda *a, **k: None)
    return checked


@pytest.mark.parametrize("route", ["check_single_domain_dns", "check_single_domain_dns_manual"])
@pytest.mark.parametrize("bad", ["example.com/../x", "exa mple.com", "example.com?x=1", "-bad.example.com", ""])
def test_dns_check_rejects_a_value_that_is_not_a_domain(dns_checked, route, bad):
    with pytest.raises(HTTPException) as err:
        asyncio.run(getattr(domains, route)(bad))
    assert err.value.status_code == 400
    assert dns_checked == []


@pytest.mark.parametrize("route", ["check_single_domain_dns", "check_single_domain_dns_manual"])
def test_dns_check_accepts_a_domain(dns_checked, route):
    asyncio.run(getattr(domains, route)("mail.example.com"))
    assert dns_checked == ["mail.example.com"]


def test_changelog_version_stays_one_path_segment(monkeypatch):
    """The version from the URL goes into a GitHub API path the same way."""
    from app.routers import status

    seen = []
    real_client = status.httpx.AsyncClient

    class FakeClient(real_client):
        def __init__(self, *args, **kwargs):
            def handler(request):
                seen.append(request)
                return status.httpx.Response(404)
            kwargs["transport"] = status.httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(status.httpx, "AsyncClient", FakeClient)
    asyncio.run(status.get_app_version_changelog("3.0.0/../../../users?x=1"))
    assert seen[0].url.raw_path == (
        b"/repos/ShlomiPorush/mailcow-logs-viewer/releases/tags/v3.0.0%2F..%2F..%2F..%2Fusers%3Fx%3D1"
    )
