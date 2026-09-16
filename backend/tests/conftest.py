"""
Test configuration.

Sets required environment variables BEFORE any app module import so that
app.config.Settings() can construct without a real deployment environment.
"""
import os
import sys
import pathlib

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
