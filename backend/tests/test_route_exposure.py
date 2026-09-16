"""Every HTTP route must sit under /api so the auth middleware can guard it.

BasicAuthMiddleware only requires credentials for paths starting with /api/;
everything else is let through so the SPA can use clean URLs like /dashboard.
That makes an API router accidentally mounted at the root an unauthenticated
copy of itself. This happened with the raw-logs router, which was included a
second time without the /api prefix to expose its WebSocket route, publishing
/raw-logs/ws-token (and the stored log content) to anyone.
"""
from app.main import app
from conftest import registered_routes

# Root-level paths that are meant to be reachable without the /api prefix.
# The SPA page routes serve HTML only; the data behind them still comes from
# /api endpoints. Add to this list only after checking the route returns no
# data that authentication is supposed to protect.
ALLOWED_ROOT_PATHS = {
    "/",
    "/login",
    "/logout",
    "/openapi.json",
    "/docs",
    "/docs/oauth2-redirect",
    "/redoc",
    "/static",
    "/favicon.ico",
    "/robots.txt",
    "/manifest.json",
    "/ws/raw-logs",
    # SPA catch-all: serves index.html for clean URLs such as /dashboard.
    "/{full_path:path}",
}


def test_no_api_route_is_exposed_outside_the_api_prefix():
    allowed = ALLOWED_ROOT_PATHS
    exposed = []
    for route in registered_routes(app):
        path = getattr(route, "path", None)
        if not path or path.startswith("/api/") or path == "/api":
            continue
        if path in allowed:
            continue
        # Mounts (StaticFiles) expose everything below their prefix.
        if any(path.startswith(p.rstrip("/") + "/") for p in allowed if p != "/"):
            continue
        exposed.append(f"{sorted(getattr(route, 'methods', ['WS']))} {path}")
    assert not exposed, (
        "These routes are reachable without authentication because they are not "
        "under /api/: " + ", ".join(sorted(exposed))
    )


def test_ws_token_endpoint_is_only_under_api():
    paths = {getattr(r, "path", "") for r in registered_routes(app)}
    assert "/api/raw-logs/ws-token" in paths
    assert "/raw-logs/ws-token" not in paths


def test_route_inventory_includes_nested_hidden_and_websocket_routes():
    from fastapi import APIRouter, FastAPI

    nested = APIRouter()
    nested.add_api_route("/hidden", lambda: {}, include_in_schema=False)
    nested.add_api_websocket_route("/socket", lambda websocket: None)
    parent = APIRouter()
    parent.include_router(nested, prefix="/nested")
    isolated = FastAPI()
    isolated.include_router(parent, prefix="/api")
    # An accidentally duplicated root include must remain visible to the guard.
    isolated.include_router(parent)
    paths = {route.path for route in registered_routes(isolated)}
    assert {"/api/nested/hidden", "/api/nested/socket",
            "/nested/hidden", "/nested/socket"} <= paths
