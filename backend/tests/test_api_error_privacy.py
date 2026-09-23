"""API fallbacks must not serialize database exception details."""
import logging
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routers import mailbox_stats, stats


@pytest.mark.parametrize("module,path,fallback", [
    (mailbox_stats, "/mailbox-stats/summary", "total_mailboxes"),
    (mailbox_stats, "/mailbox-stats/all", "mailboxes"),
    (mailbox_stats, "/mailbox-stats/domains", "domains"),
    (mailbox_stats, "/mailbox-stats/refresh", None),
    (stats, "/stats/dashboard", "messages"),
    (stats, "/stats/timeline", "timeline"),
    (stats, "/stats/top-spam-triggers", "triggers"),
    (stats, "/stats/top-blocked-ips", "blocked_ips"),
    (stats, "/stats/recent-activity", "activity"),
])
def test_database_errors_remain_server_side(monkeypatch, caplog, module, path, fallback):
    private_detail = "SELECT private_column FROM private_table; token=synthetic-secret"
    db = Mock()
    db.query.side_effect = RuntimeError(private_detail)
    monkeypatch.setattr(mailbox_stats, "_stats_cache", {})
    app = FastAPI()
    app.include_router(module.router)
    app.dependency_overrides[module.get_db] = lambda: db
    with caplog.at_level(logging.ERROR), TestClient(app) as client:
        response = client.get(path)
    assert response.status_code == 200
    assert db.query.called
    assert private_detail not in response.text
    assert response.json()["error"]
    if fallback:
        assert fallback in response.json()
    assert private_detail in caplog.text


def test_settings_validation_hides_input_values(monkeypatch):
    from app.routers import settings as route

    monkeypatch.setattr(route.settings._inner, "edit_settings_via_ui_enabled", True)
    app = FastAPI()
    app.include_router(route.router)
    db = Mock()
    app.dependency_overrides[route.get_db] = lambda: db
    with TestClient(app) as client:
        response = client.put("/settings", json={"session_max_entries": "synthetic-private-input"})
    assert response.status_code == 400
    assert "session_max_entries" in response.json()["detail"]
    assert "synthetic-private-input" not in response.text
    db.commit.assert_not_called()


@pytest.mark.parametrize("path,target,code", [
    ("/status/storage", "get_status_vmail", 500),
    ("/status/mailcow-connection", "test_connection", 200),
])
def test_upstream_errors_are_not_returned(monkeypatch, path, target, code):
    from app.routers import status
    from app.mailcow_api import MailcowAPIError

    upstream = AsyncMock(side_effect=MailcowAPIError("synthetic-private-upstream-body"))
    monkeypatch.setattr(status.mailcow_api, target, upstream)
    app = FastAPI()
    app.include_router(status.router)
    with TestClient(app) as client:
        response = client.get(path)
    assert response.status_code == code
    assert "synthetic-private-upstream-body" not in response.text
    upstream.assert_awaited_once()


def test_domain_rate_limit_failure_keeps_partial_result_private(monkeypatch):
    import asyncio
    from app.routers import rate_limits
    from app.mailcow_api import MailcowAPIError

    monkeypatch.setattr(rate_limits, "_domain_limit_cache", {"at": 0, "limits": None})
    monkeypatch.setattr(rate_limits, "_load_known_domains_worker", lambda: {"example.test"})
    monkeypatch.setattr(rate_limits.mailcow_api, "get_rl_domain",
                        AsyncMock(side_effect=MailcowAPIError("synthetic-private-upstream-body")))
    limits, error = asyncio.run(rate_limits._fetch_domain_limits())
    assert limits == []
    assert error and "synthetic-private-upstream-body" not in error
    assert rate_limits._domain_limit_cache["limits"] is None


def test_cached_dns_failures_from_previous_versions_are_safe():
    from types import SimpleNamespace
    from app.routers.domains import get_cached_dns_check

    legacy = {"status": "error", "message": "Failed to check SPF: synthetic-private-detail", "record": None}
    valid = {"status": "warning", "message": "DMARC record not found", "record": None}
    db = Mock()
    db.query.return_value.filter.return_value.first.return_value = SimpleNamespace(
        spf_check=legacy, dkim_check=None, dmarc_check=valid,
        tlsa_check=None, mta_sts_check=None, checked_at=None,
    )
    result = get_cached_dns_check(db, "example.test")
    assert "synthetic-private-detail" not in result["spf"]["message"]
    assert result["spf"]["status"] == "error"
    assert result["dmarc"] == valid
    assert "synthetic-private-detail" in legacy["message"]
