"""Issue #80: the Rspamd map must not be rewritten when nothing changed.
The old code refreshed a timestamp comment every sync, forcing Rspamd to
truncate + reload the map every 10 minutes and occasionally log
"regexp map is empty" mid-write."""
import asyncio
from datetime import datetime

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def two_suppressions():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import SpamSuppression
    init_db()
    emails = ['skip-a@test.example', 'skip-b@test.example']
    with get_db_context() as db:
        db.query(SpamSuppression).filter(SpamSuppression.email.like('skip-%@test.example')).delete(
            synchronize_session=False)
        for e in emails:
            db.add(SpamSuppression(email=e, type='email', reason='hard_bounce', source='auto',
                                   bounce_count=1, hard_bounce_count=1, soft_bounce_count=0,
                                   active=True, synced_to_rspamd=True,
                                   created_at=datetime.utcnow()))
        db.commit()
    yield emails
    with get_db_context() as db:
        db.query(SpamSuppression).filter(SpamSuppression.email.like('skip-%@test.example')).delete(
            synchronize_session=False)
        db.commit()


def _run_sync(monkeypatch, map_content):
    from app.routers import suppressions as sup
    from app.database import get_db_context

    calls = {"writes": 0}

    async def fake_find(name): return 7
    async def fake_get(map_id): return map_content
    async def fake_edit(name, content):
        calls["writes"] += 1
        calls["content"] = content
        return {"type": "success"}

    monkeypatch.setattr(sup.mailcow_api, 'find_rspamd_map_id', fake_find)
    monkeypatch.setattr(sup.mailcow_api, 'get_rspamd_map_content', fake_get)
    monkeypatch.setattr(sup.mailcow_api, 'edit_rspamd_map', fake_edit)

    with get_db_context() as db:
        # only our test rows: constrain the query scope by deactivating others
        result = asyncio.run(sup.sync_suppressions_to_rspamd(db))
    return calls, result


def test_unchanged_map_is_not_rewritten(monkeypatch, two_suppressions):
    from app.routers.suppressions import MANAGED_MARKER_START, MANAGED_MARKER_END
    from app.database import get_db_context
    from app.models import SpamSuppression

    with get_db_context() as db:
        others = [s.email for s in db.query(SpamSuppression).filter(
            SpamSuppression.active == True).all() if not s.email.startswith('skip-')]
    if others:
        pytest.skip('other active suppressions present in shared test DB')

    content = "\n".join([
        "manual@entry.example", "",
        MANAGED_MARKER_START,
        "# Last sync: 2026-07-01T00:00:00Z | Active: 2",
        "skip-a@test.example", "skip-b@test.example",
        MANAGED_MARKER_END,
    ])
    calls, result = _run_sync(monkeypatch, content)
    assert calls["writes"] == 0, "identical managed entries must not trigger a map write"
    assert result.get("skipped") is True


def test_changed_map_is_rewritten(monkeypatch, two_suppressions):
    from app.routers.suppressions import MANAGED_MARKER_START, MANAGED_MARKER_END

    content = "\n".join([
        MANAGED_MARKER_START,
        "# Last sync: 2026-07-01T00:00:00Z | Active: 1",
        "skip-a@test.example",          # skip-b missing -> real change
        MANAGED_MARKER_END,
    ])
    calls, result = _run_sync(monkeypatch, content)
    assert calls["writes"] == 1, "a real change must still be written"
    assert 'skip-b@test.example' in calls["content"]
    assert result.get("skipped") is None or result.get("skipped") is not True
