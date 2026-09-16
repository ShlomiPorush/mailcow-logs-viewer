"""Reject oversized form fields before upload handlers process untrusted input."""
from unittest.mock import AsyncMock, Mock
import threading
import tempfile

import pytest
from fastapi.testclient import TestClient
from starlette import formparsers

from app.config import settings
from app.database import get_db
from app.main import app
from app.routers import dmarc


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(settings._inner, "auth_enabled", False)
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    monkeypatch.setattr(settings._inner, "oauth2_enabled", False)
    monkeypatch.setattr(settings._inner, "dmarc_manual_upload_enabled", True)
    db = Mock()
    app.dependency_overrides[get_db] = lambda: db
    monkeypatch.setattr(dmarc, "_upload_dmarc_report", AsyncMock(return_value={"status": "success"}))
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.mark.parametrize("path,filename", [
    ("/api/dmarc/upload", "report.xml"),
    ("/api/suppressions/import", "addresses.csv"),
])
def test_oversized_text_part_is_rejected_before_handler(client, path, filename):
    response = client.post(path, files={
        "file": (filename, b"email\n"),
        "extra": (None, "x" * (1024 * 1024 + 1)),
    })
    assert response.status_code == 400
    assert "maximum size" in response.json()["detail"].lower()
    dmarc._upload_dmarc_report.assert_not_awaited()
    app.dependency_overrides[get_db]().commit.assert_not_called()


@pytest.mark.parametrize("path,filename", [
    ("/api/dmarc/upload", "report.xml"),
    ("/api/suppressions/import", "addresses.csv"),
])
def test_text_part_limit_does_not_reject_normal_file_uploads(client, path, filename):
    # Files above the spool threshold remain supported; the field cap must not
    # accidentally impose a 1 MiB limit on uploaded files.
    response = client.post(path, files={
        "file": (filename, b"email\n" + b"\n" * (1024 * 1024 + 1)),
    })
    assert response.status_code == 200


@pytest.mark.parametrize("path", ["/api/dmarc/upload", "/api/suppressions/import"])
def test_oversized_urlencoded_field_is_rejected(client, path):
    response = client.post(path, content=b"extra=" + b"x" * (1024 * 1024 + 1),
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 400


def test_dmarc_file_limit_still_applies(client):
    from app.services.safe_decompress import MAX_COMPRESSED_BYTES
    response = client.post("/api/dmarc/upload", files={
        "file": ("report.xml", b"x" * (MAX_COMPRESSED_BYTES + 1)),
    })
    assert response.status_code == 413
    dmarc._upload_dmarc_report.assert_not_awaited()


def test_large_file_rollover_runs_off_the_event_loop(client, monkeypatch):
    loop_threads = []
    rollover_threads = []

    class RecordingFile(tempfile.SpooledTemporaryFile):
        def rollover(self):
            rollover_threads.append(threading.get_ident())
            return super().rollover()

    async def record_loop(scope, receive, send):
        loop_threads.append(threading.get_ident())
        await app(scope, receive, send)

    monkeypatch.setattr(formparsers, "SpooledTemporaryFile", RecordingFile)
    response = TestClient(record_loop).post("/api/dmarc/upload", files={
        "file": ("report.xml", b"x" * (2 * 1024 * 1024)),
    })
    assert response.status_code == 200
    assert rollover_threads
    assert all(thread not in loop_threads for thread in rollover_threads)
