"""GET /api/docs/{doc_name}: the help page as Markdown, 404 for a page that does
not exist (here or on GitHub), 503 when GitHub cannot be reached. The contract
check (conftest.py) holds each answer to /openapi.json."""
import httpx
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402
from app.routers import documentation  # noqa: E402


@pytest.fixture
def client(monkeypatch):
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    return TestClient(app)


def _github(monkeypatch, answer):
    class Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            return answer(url)

    monkeypatch.setattr(documentation.httpx, 'AsyncClient', Client)


def test_a_help_page_is_markdown(client, monkeypatch):
    _github(monkeypatch, lambda url: httpx.Response(200, text='# Messages', request=httpx.Request('GET', url)))
    response = client.get('/api/docs/Messages')
    assert response.status_code == 200 and response.text == '# Messages'
    assert response.headers['content-type'].startswith('text/plain')


def test_an_unknown_page(client):
    assert client.get('/api/docs/Nothing').json() == {'detail': 'Documentation not found'}


def test_a_page_github_does_not_have(client, monkeypatch):
    _github(monkeypatch, lambda url: httpx.Response(404, request=httpx.Request('GET', url)))
    assert client.get('/api/docs/Messages').status_code == 404


def test_github_out_of_reach(client, monkeypatch):
    def fail(url):
        raise httpx.ConnectError('no route', request=httpx.Request('GET', url))
    _github(monkeypatch, fail)
    response = client.get('/api/docs/Messages')
    assert response.status_code == 503 and response.json() == {'detail': 'Failed to fetch documentation'}
