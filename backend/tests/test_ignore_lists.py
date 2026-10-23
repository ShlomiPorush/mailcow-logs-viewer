"""Ignoring a stopped container or a blocklist silences it without hiding it."""
import asyncio
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from app.routers import status
from app.services.blacklist_service import apply_ignored_lists, overall_status

UCE3 = "dnsbl-3.uceprotect.net"
ZEN = "zen.spamhaus.org"


def result(zone, status_="clean", listed=False):
    return {"name": zone, "zone": zone, "status": status_, "listed": listed}


def check(results, status_="listed"):
    return {"status": status_, "listed_count": sum(1 for r in results if r["listed"]),
            "total_blacklists": len(results), "results": results}


def test_listing_only_on_an_ignored_list_reads_clean():
    stored = check([result(UCE3, "listed", True), result(ZEN), result("psbl.surriel.com")])
    out = apply_ignored_lists(stored, {UCE3})
    assert out["status"] == "clean"
    assert out["listed_count"] == 0
    assert out["ignored_listed_count"] == 1
    assert [r["ignored"] for r in out["results"]] == [True, False, False]
    # The stored check is untouched, so un-ignoring brings the listing back
    assert stored["listed_count"] == 1 and "ignored" not in stored["results"][0]


def test_other_listings_still_count():
    out = apply_ignored_lists(check([result(UCE3, "listed", True), result(ZEN, "listed", True)]), {UCE3})
    assert out["status"] == "listed"
    assert out["listed_count"] == 1


def test_nothing_ignored_keeps_the_stored_verdict():
    stored = check([result(UCE3, "listed", True), result(ZEN)])
    out = apply_ignored_lists(stored, set())
    assert (out["status"], out["listed_count"], out["ignored_listed_count"]) == ("listed", 1, 0)


def test_failed_spamhaus_lookup_is_still_an_error_after_ignoring():
    out = apply_ignored_lists(check([result(UCE3, "listed", True), result(ZEN, "timeout")]), {UCE3})
    assert out["status"] == "error"


def test_overall_status_rules():
    assert overall_status([result(ZEN), result("a", "listed", True)], 2) == "listed"
    assert overall_status([result(ZEN, "error"), result("a")], 2) == "error"
    assert overall_status([result("a", "error"), result("b", "timeout"), result("c")], 3) == "error"
    assert overall_status([result("a", "error"), result("b"), result("c")], 3) == "clean"


def _containers_response(monkeypatch, ignored):
    db = Mock()
    db.query.return_value.all.return_value = [SimpleNamespace(container_name="ipv6nat-mailcow", display_name="ipv6nat")]

    @contextmanager
    def session():
        yield db

    monkeypatch.setattr(status, "SessionLocal", session, raising=False)
    monkeypatch.setattr(status, "load_ignored", lambda _db, _key: set(ignored))
    monkeypatch.setattr(status.mailcow_api, "get_status_containers", AsyncMock(return_value=[{
        "postfix-mailcow": {"state": "running"}, "ipv6nat-mailcow": {"state": "exited"}}]))
    return asyncio.run(status._get_containers_status_internal())


def test_ignored_container_is_listed_but_not_counted(monkeypatch):
    data = _containers_response(monkeypatch, {"ipv6nat-mailcow"})
    assert data["summary"] == {"running": 1, "stopped": 0, "total": 1, "ignored": 1}
    assert data["containers"]["ipv6nat-mailcow"]["ignored"] is True
    assert data["containers"]["postfix-mailcow"]["ignored"] is False


def test_stopped_container_counts_until_ignored(monkeypatch):
    data = _containers_response(monkeypatch, set())
    assert data["summary"] == {"running": 1, "stopped": 1, "total": 2, "ignored": 0}


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def test_ignore_list_round_trip():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import SystemSetting
    from app.services.ignore_lists import load_ignored, set_ignored, IGNORED_BLOCKLISTS_KEY
    init_db()
    try:
        with get_db_context() as db:
            db.query(SystemSetting).filter(SystemSetting.key == IGNORED_BLOCKLISTS_KEY).delete()
        with get_db_context() as db:
            assert set_ignored(db, IGNORED_BLOCKLISTS_KEY, UCE3, True) == {UCE3}
            set_ignored(db, IGNORED_BLOCKLISTS_KEY, ZEN, True)
        with get_db_context() as db:
            assert load_ignored(db, IGNORED_BLOCKLISTS_KEY) == {UCE3, ZEN}
            set_ignored(db, IGNORED_BLOCKLISTS_KEY, ZEN, False)
        with get_db_context() as db:
            assert load_ignored(db, IGNORED_BLOCKLISTS_KEY) == {UCE3}
    finally:
        with get_db_context() as db:
            db.query(SystemSetting).filter(SystemSetting.key == IGNORED_BLOCKLISTS_KEY).delete()
