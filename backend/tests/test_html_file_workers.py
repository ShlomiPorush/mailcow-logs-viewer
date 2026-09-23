"""Serving a frontend page must not block unrelated API requests."""
import asyncio
import threading

import httpx
import pytest
from fastapi.testclient import TestClient

from app import main


@pytest.mark.parametrize("path,filename", [("/login", "login.html"), ("/", "index.html"), ("/dashboard", "index.html")])
def test_slow_html_read_keeps_api_responsive(monkeypatch, path, filename):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    reads = []
    loop_thread = threading.get_ident()
    monkeypatch.setattr(main.settings._inner, "auth_enabled", False)
    monkeypatch.setattr(main.settings._inner, "basic_auth_enabled", False)

    class Page:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            reads.append(threading.get_ident())
            started.set()
            try:
                release.wait(0.5)
                return "<html><body>Test page</body></html>"
            finally:
                finished.set()

    def open_page(name, mode):
        assert name == "/app/frontend/" + filename
        assert mode == "r"
        return Page()

    monkeypatch.setattr(main, "open", open_page, raising=False)

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://testserver") as client:
            page = asyncio.create_task(client.get(path))
            try:
                assert await asyncio.to_thread(started.wait, 2)
                info = await asyncio.wait_for(client.get("/api/info"), 1)
                assert info.status_code == 200
                assert not finished.is_set(), "HTML file read blocked unrelated API requests"
            finally:
                release.set()
                response = await page
            assert response.status_code == 200
            assert response.text == "<html><body>Test page</body></html>"

    asyncio.run(run())
    assert reads and all(thread != loop_thread for thread in reads)


@pytest.mark.parametrize("path,message", [("/login", "Login page not found"), ("/", "Frontend not found"), ("/dashboard", "Frontend not found")])
def test_missing_html_keeps_error_response(monkeypatch, path, message):
    monkeypatch.setattr(main.settings._inner, "auth_enabled", False)
    monkeypatch.setattr(main.settings._inner, "basic_auth_enabled", False)

    def missing(*args):
        raise FileNotFoundError("test page unavailable")

    monkeypatch.setattr(main, "open", missing, raising=False)
    response = TestClient(main.app).get(path)
    assert response.status_code == 500
    assert message in response.text
