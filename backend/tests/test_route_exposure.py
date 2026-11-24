from app.main import app
from conftest import registered_routes

ALLOWED_ROOT_PATHS = {
    "/",
    "/login",
    "/logout",
    "/openapi.json",
    "/docs",
    "/redoc",
    "/static",
    "/favicon.ico",
    "/robots.txt",
    "/manifest.json",
    "/ws/raw-logs",
    "/{full_path:spa_path}",
    "/mcp",
    "/oauth/authorize",
    "/oauth/consent",
    "/oauth/token",
    "/oauth/register",
    "/oauth/revoke",
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    "/.well-known/oauth-authorization-server",
    "/oauth/device",
    "/agents/skill",
    "/agents/skill/{name:path}",
    "/agents/mcp",
    "/agents/mcp/",
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
    isolated.include_router(parent)
    paths = {route.path for route in registered_routes(isolated)}
    assert {"/api/nested/hidden", "/api/nested/socket",
            "/nested/hidden", "/nested/socket"} <= paths
