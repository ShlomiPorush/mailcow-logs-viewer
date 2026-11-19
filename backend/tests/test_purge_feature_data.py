"""Turning Mailbox Stats off keeps the mailbox rows while Rate Limits still reads them.

The Settings page deletes a switched-off feature's data through
/api/settings/purge-feature-data. For Mailbox Stats that emptied
mailbox_statistics too, where Rate Limits reads each mailbox's configured
limit, so the Rate Limits page lost its limits until the next mailbox sync.
"""
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.config import settings  # noqa: E402
from app.database import get_db  # noqa: E402


class _Result:
    def scalar(self):
        return 3


class _RecordingDb:
    def __init__(self):
        self.statements = []

    def execute(self, statement, *args, **kwargs):
        self.statements.append(str(statement))
        return _Result()

    def commit(self):
        pass

    def rollback(self):
        pass


@pytest.fixture()
def purge(monkeypatch):
    db = _RecordingDb()
    monkeypatch.setattr(settings._inner, 'edit_settings_via_ui_enabled', True)
    app.dependency_overrides[get_db] = lambda: db
    client = TestClient(app)

    def run(disabled):
        monkeypatch.setattr(settings._inner, 'disabled_features', disabled)
        db.statements.clear()
        resp = client.post("/api/settings/purge-feature-data", json={"feature": "mailbox-stats"})
        assert resp.status_code == 200, resp.text
        return [s for s in db.statements if s.startswith('TRUNCATE')], resp.json()
    yield run
    app.dependency_overrides.pop(get_db, None)


def test_mailbox_rows_stay_while_rate_limits_is_on(purge):
    truncated, body = purge('mailbox-stats')
    assert truncated == ['TRUNCATE TABLE alias_statistics CASCADE']
    assert 'mailbox_statistics' not in body['tables_purged']


def test_mailbox_rows_go_when_rate_limits_is_off_too(purge):
    truncated, _ = purge('mailbox-stats,rate-limits')
    assert truncated == ['TRUNCATE TABLE alias_statistics CASCADE',
                         'TRUNCATE TABLE mailbox_statistics CASCADE']
