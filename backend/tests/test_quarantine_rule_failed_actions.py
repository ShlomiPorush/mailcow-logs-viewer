"""History and Hits only record what mailcow actually did."""
import asyncio
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from app import scheduler
from app.config import settings


@pytest.fixture
def state(monkeypatch):
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: True)
    monkeypatch.setattr(settings._inner, "quarantine_rules_max_actions", 10)
    monkeypatch.setattr(settings._inner, "quarantine_rules_log_retention_days", 7)
    monkeypatch.setattr(scheduler.mailcow_api, "headers_rw", {"X-API-Key": "test-key"})
    monkeypatch.setattr(scheduler.mailcow_api, "aclose", AsyncMock())
    monkeypatch.setattr(scheduler, "update_job_status", Mock())
    allow = SimpleNamespace(id=1, name="Allow", match_type="sender_domain", match_value="example.com",
                            is_regex=False, action="release", hit_count=0, last_hit_at=None)
    deny = SimpleNamespace(id=2, name="Deny", match_type="subject", match_value="blocked",
                           is_regex=False, action="delete", hit_count=0, last_hit_at=None)
    by_id = {1: allow, 2: deny}
    db = Mock()

    def where(*criteria):
        # QuarantineRule.id == rule_id: answer with that rule
        query = Mock()
        query.all.return_value = [allow, deny]
        value = getattr(getattr(criteria[0], 'right', None), 'value', None)
        query.first.return_value = by_id.get(value) if isinstance(value, int) and not isinstance(value, bool) else None
        return query
    db.query.return_value.filter.side_effect = where

    @contextmanager
    def session():
        yield db
    monkeypatch.setattr(scheduler, "get_db_context", session)
    items = [
        {"id": "DEL1", "sender": "user@example.org", "rcpt": "rcpt@example.net", "subject": "blocked"},
        {"id": "REL1", "sender": "user@example.com", "rcpt": "rcpt@example.net", "subject": "hello"},
    ]
    monkeypatch.setattr(scheduler.mailcow_api, "get_quarantine", AsyncMock(return_value=items))
    monkeypatch.setattr(scheduler.mailcow_api, "release_quarantine", AsyncMock())
    monkeypatch.setattr(scheduler.mailcow_api, "delete_quarantine", AsyncMock())
    return SimpleNamespace(db=db, allow=allow, deny=deny)


def _logged(db):
    return [(c.args[0].quarantine_id, c.args[0].action) for c in db.add.call_args_list]


def test_failed_release_is_not_recorded(state):
    scheduler.mailcow_api.release_quarantine.side_effect = RuntimeError("mailcow said no")
    asyncio.run(scheduler.process_quarantine_rules_job())
    assert _logged(state.db) == [("DEL1", "delete")]
    assert state.deny.hit_count == 1
    assert state.allow.hit_count == 0 and state.allow.last_hit_at is None


def test_failed_delete_is_not_recorded(state):
    scheduler.mailcow_api.delete_quarantine.side_effect = RuntimeError("mailcow said no")
    asyncio.run(scheduler.process_quarantine_rules_job())
    assert _logged(state.db) == [("REL1", "release")]
    assert state.allow.hit_count == 1
    assert state.deny.hit_count == 0 and state.deny.last_hit_at is None


def test_successful_actions_are_recorded(state):
    asyncio.run(scheduler.process_quarantine_rules_job())
    assert sorted(_logged(state.db)) == [("DEL1", "delete"), ("REL1", "release")]
    assert state.allow.hit_count == 1 and state.deny.hit_count == 1
