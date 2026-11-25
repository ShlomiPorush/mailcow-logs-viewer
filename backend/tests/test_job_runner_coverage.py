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
    monkeypatch.setattr(BackgroundTasks, "add_task", lambda self, *a, **k: None)
    saved = {k: dict(v) for k, v in scheduler.job_status.items()}
    yield TestClient(app)
    scheduler.job_status.clear()
    scheduler.job_status.update(saved)


def test_every_status_page_job_is_runnable(client):
    missing = []
    for job_name in scheduler.job_status:
        resp = client.post(f"/api/settings/jobs/{job_name}/run")
        if resp.status_code not in (200, 409):
            missing.append(f"{job_name} -> {resp.status_code} {resp.text}")
    assert not missing, "jobs listed on the Status page that the runner rejects:\n" + "\n".join(missing)


def test_unknown_job_is_rejected(client):
    resp = client.post("/api/settings/jobs/no_such_job/run")
    assert resp.status_code == 404
