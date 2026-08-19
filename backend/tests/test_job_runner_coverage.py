"""Issue #82: "Run" on the DMARC IMAP Sync job returned 404.

The Status page lists every job in scheduler.job_status, but the manual
runner (POST /api/settings/jobs/{name}/run) has its own name -> function
map. A job present in one and missing from the other shows a Run button
that does nothing. This test keeps the two in sync.
"""
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402
from starlette.background import BackgroundTasks  # noqa: E402

from app.main import app  # noqa: E402
from app import scheduler  # noqa: E402


@pytest.fixture()
def client(monkeypatch):
    # Accept the job without executing it: the functions need mailcow/DB.
    monkeypatch.setattr(BackgroundTasks, "add_task", lambda self, *a, **k: None)
    # Start from a clean status table and restore it afterwards.
    saved = {k: dict(v) for k, v in scheduler.job_status.items()}
    yield TestClient(app)
    scheduler.job_status.clear()
    scheduler.job_status.update(saved)


def test_every_status_page_job_is_runnable(client):
    missing = []
    for job_name in scheduler.job_status:
        resp = client.post(f"/api/settings/jobs/{job_name}/run")
        if resp.status_code != 200:
            missing.append(f"{job_name} -> {resp.status_code} {resp.text}")
    assert not missing, "jobs listed on the Status page that the runner rejects:\n" + "\n".join(missing)


def test_unknown_job_is_rejected(client):
    resp = client.post("/api/settings/jobs/no_such_job/run")
    assert resp.status_code == 404
