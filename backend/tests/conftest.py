"""
Test configuration.

Sets required environment variables BEFORE any app module import so that
app.config.Settings() can construct without a real deployment environment.
"""
import os
import pathlib
import sys
import time as _real_time

import pytest

os.environ.setdefault("MAILCOW_URL", "https://mail.example.com")
os.environ.setdefault("MAILCOW_API_KEY", "test-key")
os.environ.setdefault("POSTGRES_USER", "test")
os.environ.setdefault("POSTGRES_PASSWORD", "test")
os.environ.setdefault("POSTGRES_DB", "test")

# Make `app` importable when running pytest from the repo root or backend/
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))


def registered_routes(application):
    """Inspect resolved routes, including hidden HTTP and WebSocket routes.

    FastAPI 0.141 resolves included routers lazily. Keep this version-specific
    introspection in one place; OpenAPI alone omits security-relevant routes.
    """
    from fastapi.routing import _iter_routes_with_context

    for original, context in _iter_routes_with_context(application.routes):
        route = original if context is None else (context.starlette_route or context)
        assert getattr(route, "path", None) is not None, type(route)
        yield route


class _ModuleClock:
    """Stands in for the ``time`` module inside one module under test.

    Patching ``some_module.time.time`` would replace ``time.time`` for the
    whole process, including background threads started by other tests.
    """

    def __init__(self):
        self._overrides = {}

    def __getattr__(self, name):
        overrides = self.__dict__.get("_overrides", {})
        if name in overrides:
            return overrides[name]
        return getattr(_real_time, name)


@pytest.fixture
def module_clock(monkeypatch):
    """Override time functions as seen by one module only: module_clock(auth, time=lambda: 1000.0)."""
    clocks = {}

    def apply(module, **overrides):
        clock = clocks.get(module)
        if clock is None:
            clock = clocks[module] = _ModuleClock()
            monkeypatch.setattr(module, "time", clock)
        clock._overrides.update(overrides)

    return apply


@pytest.fixture(autouse=True)
def local_domains_loaded(monkeypatch):
    """The automatic suppression jobs wait until every domain of this mailcow is
    known; a test runs with that list loaded unless it says otherwise."""
    from app import config
    from app.mailcow_api import mailcow_api
    monkeypatch.setattr(config, "_cached_domains_complete", mailcow_api.base_url)


# One Contract per app, shared by the whole run: building it copies the document
_contracts = {}


@pytest.fixture(autouse=True)
def api_contract(monkeypatch):
    """Check every answer the real app gives a test against /openapi.json (contract.py).

    Only TestClient calls to app.main.app are checked; tests that build an app
    of their own are left alone. A mismatch fails the test that made the call.
    """
    from starlette.testclient import TestClient

    original = TestClient.request

    def request(self, *args, **kwargs):
        response = original(self, *args, **kwargs)
        main = sys.modules.get("app.main")
        if main is not None and self.app is main.app:
            from contract import Contract, check_response
            contract = _contracts.get(id(main.app))
            if contract is None or contract.app is not main.app:
                contract = _contracts[id(main.app)] = Contract(main.app)
            # A followed redirect is an answer too
            for answer in (*response.history, response):
                check_response(contract, answer)
        return response

    monkeypatch.setattr(TestClient, "request", request)
