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
