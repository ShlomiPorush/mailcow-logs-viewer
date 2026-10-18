"""Mail to whitelisted domains stays in the queue: neither queue cleanup nor a hard bounce deletes it."""
import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock

from app import scheduler
from app.config import settings


def test_whitelisted_domain_mail_stays_in_queue(monkeypatch):
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: True)
    for key, value in {
        "suppression_enabled": True, "queue_cleanup_enabled": True,
        "queue_cleanup_threshold_minutes": 30, "suppression_rspamd_sync": False,
        "suppression_whitelist_domains": "example.net",
    }.items():
        monkeypatch.setattr(settings._inner, key, value)
    monkeypatch.setattr(scheduler.mailcow_api, "headers_rw", {"X-API-Key": "test-key"})
    monkeypatch.setattr(scheduler, "update_job_status", Mock())
    old = datetime.now(timezone.utc).timestamp() - 7200
    queue = [
        {"queue_id": "WHITE", "queue_name": "deferred", "arrival_time": old,
         "recipients": ["user@example.net (connect to mx.example.net: Connection timed out)"]},
        {"queue_id": "MIXED", "queue_name": "deferred", "arrival_time": old,
         "recipients": ["a@example.org", "b@Example.NET"]},
        {"queue_id": "OTHER", "queue_name": "deferred", "arrival_time": old,
         "recipients": ["user@example.org"]},
    ]
    monkeypatch.setattr(scheduler.mailcow_api, "get_queue", AsyncMock(return_value=queue))
    monkeypatch.setattr(scheduler.mailcow_api, "delete_queue", AsyncMock())
    stored = []
    monkeypatch.setattr(scheduler, "_store_deferred_suppressions_worker", lambda r: stored.extend(r) or len(r))

    asyncio.run(scheduler.cleanup_deferred_queue_job())

    scheduler.mailcow_api.delete_queue.assert_awaited_once_with(["OTHER"])
    assert [r["email"] for r in stored] == ["user@example.org"]
    assert stored[0]["queue_id"] == "OTHER", 'the queued message is handed over for the block details'


def test_hard_bounce_keeps_messages_that_also_go_to_a_whitelisted_domain(monkeypatch):
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: True)
    for key, value in {
        "suppression_enabled": True, "suppression_auto_detect": True, "suppression_rspamd_sync": False,
        "suppression_whitelist_domains": "example.net",
    }.items():
        monkeypatch.setattr(settings._inner, key, value)
    monkeypatch.setattr(scheduler.mailcow_api, "headers_rw", {"X-API-Key": "test-key"})
    monkeypatch.setattr(scheduler, "update_job_status", Mock())
    monkeypatch.setattr(scheduler, "_detect_suppressions_worker", lambda: (1, 0, ["bad@example.org"]))
    queue = [
        {"queue_id": "ONLY", "recipients": ["bad@example.org"]},
        {"queue_id": "MIXED", "recipients": ["bad@example.org", "user@example.net"]},
        {"queue_id": "OTHER", "recipients": ["user@example.com"]},
    ]
    monkeypatch.setattr(scheduler.mailcow_api, "get_queue", AsyncMock(return_value=queue))
    monkeypatch.setattr(scheduler.mailcow_api, "delete_queue", AsyncMock())

    asyncio.run(scheduler.detect_suppressions_job())

    scheduler.mailcow_api.delete_queue.assert_awaited_once_with(["ONLY"])
