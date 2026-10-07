"""
Main FastAPI application
Entry point for the Mailcow Logs Viewer backend
"""
import logging
root = logging.getLogger()
root.handlers = []

import asyncio
import mimetypes
import time

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from .frontend_assets import stamp_asset_versions
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.datastructures import MutableHeaders
from contextlib import asynccontextmanager, suppress
from typing import Optional

from .config import settings, set_cached_active_domains, reload_settings
from .database import init_db, check_db_connection
from .scheduler import start_scheduler, stop_scheduler
from .raw_logs_worker import start_raw_logs_scheduler, stop_raw_logs_scheduler
from .mailcow_api import mailcow_api, MailcowAPIError
from .utils import internal_error
from .routers import (
    logs,
    stats,
    export as export_router,
    domains as domains_router,
    dmarc as dmarc_router,
    mailbox_stats as mailbox_stats_router,
    devices as devices_router,
    documentation,
    blacklist as blacklist_router,
    reporting,
    auth as auth_router,
    raw_logs as raw_logs_router,
    rspamd_maps as rspamd_maps_router,
    suppressions as suppressions_router,
    quarantine_rules as quarantine_rules_router,
    security_alerts as security_alerts_router,
    smtp_abuse as smtp_abuse_router,
    protection as protection_router,
    notifications as notifications_router,
    rate_limits as rate_limits_router,
)
from .migrations import run_migrations
from .auth import BasicAuthMiddleware, safe_return_path
from .origin_guard import SameOriginGuardMiddleware
from .session import get_session_from_request
from .services.auth_cleanup import auth_store_maintenance
from .version import __version__

from .services.geoip_downloader import (
    is_license_configured,
    get_geoip_status
)

logger = logging.getLogger(__name__)

# These are first-party routers - an ImportError here is a bug that should
# crash startup, not silently ship a container missing its Settings/Status/
# Messages APIs (which is what the old try/except ImportError did).
from .routers import status as status_router
from .routers import messages as messages_router
from .routers import settings as settings_router


async def _loop_lag_watchdog():
    """Log when the event loop is blocked.

    Production runs a single uvicorn worker, so any blocking call in a
    background job stalls every request. A 1s sleep that takes noticeably
    longer than 1s is the cheapest proof that the stall is in-app rather
    than in the network/reverse-proxy layer.
    """
    while True:
        try:
            start = asyncio.get_running_loop().time()
            await asyncio.sleep(1)
            lag = asyncio.get_running_loop().time() - start - 1
            if lag > 1.0:
                logger.warning(f"[LOOP-LAG] Event loop was blocked for ~{lag:.1f}s - a background job is likely running blocking work")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug(f"Loop lag watchdog iteration failed: {e}")


def log_authentication_state() -> None:
    """Log which authentication is in force; running without any is a warning."""
    if settings.is_authentication_enabled:
        auth_methods = []
        if settings.is_basic_auth_enabled:
            auth_methods.append("Basic Auth")
            if not settings.auth_password:
                logger.warning("WARNING: Basic Auth enabled but password not set!")
        if settings.is_oauth2_enabled:
            auth_methods.append(f"OAuth2 ({settings.oauth2_provider_name})")
            if not settings.oauth2_client_id or not settings.oauth2_client_secret:
                logger.warning("WARNING: OAuth2 enabled but client credentials not configured!")

        logger.info(f"Authentication is ENABLED: {', '.join(auth_methods)}")
    else:
        logger.warning(
            "Authentication is DISABLED: anyone who can reach this app can read the logs, "
            "change settings and run mailcow actions. Set BASIC_AUTH_ENABLED=true with "
            "AUTH_PASSWORD, or configure OAuth2, unless access is restricted another way."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management"""
    # Startup
    logger.info("Starting mailcow Logs Viewer")
    
    # Initialize database
    try:
        init_db()
        if not check_db_connection():
            logger.error("Database connection failed!")
            raise Exception("Cannot connect to database")
        
        # Run migrations and cleanup
        logger.info("Running database migrations and cleanup...")
        run_migrations()

        # Apply Alembic revisions (the forward migration path from v2.6.4 on;
        # run_migrations above is the frozen pre-Alembic legacy path)
        from .migrations import run_alembic_upgrade
        run_alembic_upgrade()

        # Load settings overrides from DB (if UI editing is enabled and overrides exist).
        # A failed read aborts startup: authentication enabled from the UI is
        # stored only there, and starting without it would serve with auth off.
        if settings.edit_settings_via_ui_enabled:
            from .database import get_db_context
            with get_db_context() as db:
                reload_settings(db)
            logger.info("Settings loaded from database overrides")
            try:
                # Reload services that cache settings values
                mailcow_api.reload_config()
                from .services.oauth2_client import oauth2_client
                oauth2_client.reload_config()
            except Exception as e:
                logger.warning(f"Could not apply the stored settings to the mailcow and OAuth2 clients: {e}")
    except Exception as e:
        logger.error(f"Failed to initialize database or load the stored settings: {e}")
        raise

    # Log effective configuration (after DB overrides are loaded)
    logger.info(f"Configuration: {settings.fetch_interval}s interval, {settings.retention_days}d retention")

    if settings.blacklist_emails_list:
        logger.info(f"Blacklist enabled with {len(settings.blacklist_emails_list)} email(s)")

    log_authentication_state()

    # GeoIP initialization
    try:
        if is_license_configured():
            status = get_geoip_status()
            city_info = status['City']
            asn_info = status['ASN']
            if city_info['available']:
                logger.info(f"GeoIP databases found: City {city_info['size_mb']}MB ({city_info['age_days']}d), ASN {asn_info['size_mb']}MB ({asn_info['age_days']}d)")
                # Eagerly load and validate readers so GeoIP works from the first fetch cycle
                from .services import geoip_service
                geoip_service.reload_geoip_readers()
                if geoip_service.get_geoip_db_valid():
                    logger.info("GeoIP databases loaded and validated - ready for use")
                else:
                    logger.warning("GeoIP databases found but validation failed - will re-download in background")
                logger.info("GeoIP update check will run in background (60s after startup)")
            else:
                logger.info("GeoIP databases not yet downloaded - will download in background (60s after startup)")
        else:
            logger.info("MaxMind license key not configured, GeoIP features disabled")
            logger.info("To enable: Set MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY environment variables")
    except Exception as e:
        logger.error(f"Error initializing GeoIP: {e}")

    # Test mailcow API connection and fetch active domains
    try:
        api_ok = await mailcow_api.test_connection()
        if not api_ok:
            logger.warning("mailcow API connection test failed - check your configuration")
        else:
            try:
                active_domains = await mailcow_api.get_active_domains()
                if active_domains:
                    set_cached_active_domains(active_domains)
                    logger.info(f"Loaded {len(active_domains)} active domains from mailcow API")
                else:
                    logger.warning("No active domains found in mailcow - check your configuration")
            except Exception as e:
                logger.error(f"Failed to fetch active domains: {e}")
            # Initialize server IP cache for SPF checks
            try:
                from app.routers.domains import init_server_ip
                await init_server_ip()
            except Exception as e:
                logger.warning(f"Failed to initialize server IP cache: {e}")
    except Exception as e:
        logger.error(f"mailcow API test failed: {e}")
    
    # Start background scheduler
    try:
        start_scheduler()
    except Exception as e:
        logger.error(f"Failed to start scheduler: {e}")
        raise
    
    # Start raw logs worker (separate scheduler)
    try:
        start_raw_logs_scheduler()
    except Exception as e:
        logger.error(f"Failed to start raw logs scheduler: {e}")
        # Non-fatal: main app still works without raw logs
    
    # Event loop lag watchdog (diagnostics for occasional request stalls)
    lag_watchdog_task = asyncio.create_task(_loop_lag_watchdog())

    logger.info("Application startup complete")
    
    async with auth_store_maintenance():
        yield
    
    # Shutdown
    logger.info("Shutting down application")
    lag_watchdog_task.cancel()
    with suppress(asyncio.CancelledError):
        await lag_watchdog_task
    stop_raw_logs_scheduler()
    stop_scheduler()
    await mailcow_api.aclose()
    logger.info("Application shutdown complete")


# Create FastAPI app
app = FastAPI(
    title="mailcow Logs Viewer",
    description="Modern dashboard for viewing and analyzing mailcow mail server logs",
    version=__version__,
    lifespan=lifespan
)

# Add Basic Auth Middleware FIRST (innermost)
# This ensures ALL requests are authenticated when enabled
app.add_middleware(BasicAuthMiddleware)

# Writes and the live log WebSocket must come from the app's own pages,
# with or without authentication
app.add_middleware(SameOriginGuardMiddleware)


def configure_cors(application: FastAPI) -> None:
    """Allow cross-origin API access only for the exact origins in CORS_ALLOWED_ORIGINS.

    The web interface is served from the same origin as the API and needs no
    CORS at all, so by default no CORS policy is installed. Credentials are
    never combined with a wildcard or a reflected Origin.
    """
    origins = settings.cors_allowed_origins_list
    if not origins:
        return
    application.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "Authorization"],
    )
    logger.info(f"Cross-origin API access allowed for: {', '.join(origins)}")


configure_cors(app)

# Security headers on every response.
# CSP notes: the frontend relies on inline event handlers and inline <script>
# blocks, so script-src needs 'unsafe-inline' (and 'unsafe-eval' for the local
# Tailwind runtime). The CSP still blocks loading scripts from external hosts,
# which is the main escalation path for any injected HTML. ws:/wss: are needed
# for the live log viewer ('self' does not reliably cover WebSocket schemes).
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: https:; "
    "font-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)


class SecurityHeadersMiddleware:
    """Add security headers to HTTP responses.

    Deliberately a PURE ASGI middleware, not Starlette's BaseHTTPMiddleware
    (``@app.middleware("http")``): BaseHTTPMiddleware is known to interfere
    with WebSocket connections behind reverse/auth proxies (the /ws/raw-logs
    upgrade would hang). This implementation touches only ``http`` responses
    and passes ``websocket`` (and ``lifespan``) scopes through untouched.
    """

    def __init__(self, app, csp: str):
        self.app = app
        self.csp = csp

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("X-Frame-Options", "DENY")
                headers.setdefault("Referrer-Policy", "same-origin")
                headers.setdefault("Content-Security-Policy", self.csp)
            await send(message)

        await self.app(scope, receive, send_with_headers)


class SlowRequestLogMiddleware:
    """Log requests that spend more than 3s inside the app.

    Pure ASGI for the same reason as SecurityHeadersMiddleware above:
    BaseHTTPMiddleware breaks the /ws/raw-logs upgrade. Only ``http``
    scopes are timed; ``websocket``/``lifespan`` pass through untouched
    (a long-lived WebSocket would always look "slow").
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = time.monotonic()
        try:
            await self.app(scope, receive, send)
        finally:
            elapsed = time.monotonic() - started
            if elapsed > 3.0:
                logger.warning(f"[SLOW-REQUEST] {scope['method']} {scope['path']} took {elapsed:.1f}s")


app.add_middleware(SecurityHeadersMiddleware, csp=_CSP)

# Registered last so it is the outermost middleware: the measured time then
# covers auth/origin guard/security-headers as well, not just the route handler.
app.add_middleware(SlowRequestLogMiddleware)

# Include routers
app.include_router(auth_router.router, prefix="/api", tags=["Authentication"])
app.include_router(logs.router, prefix="/api", tags=["Logs"])
app.include_router(stats.router, prefix="/api", tags=["Statistics"])
app.include_router(reporting.router, prefix="/api", tags=["Reporting"])
app.include_router(export_router.router, prefix="/api", tags=["Export"])
if status_router:
    app.include_router(status_router.router, prefix="/api", tags=["Status"])
if messages_router:
    app.include_router(messages_router.router, prefix="/api", tags=["Messages"])
if settings_router:
    app.include_router(settings_router.router, prefix="/api", tags=["Settings"])
app.include_router(domains_router.router, prefix="/api", tags=["Domains"])
app.include_router(dmarc_router.router, prefix="/api", tags=["DMARC"])
app.include_router(mailbox_stats_router.router, prefix="/api", tags=["Mailbox Stats"])
app.include_router(devices_router.router, prefix="/api", tags=["Devices"])
app.include_router(documentation.router, prefix="/api", tags=["Documentation"])
app.include_router(blacklist_router.router, prefix="/api/blacklist", tags=["Blacklist"])
app.include_router(raw_logs_router.router, prefix="/api", tags=["Raw Logs"])
app.include_router(rspamd_maps_router.router, prefix="/api", tags=["Rspamd Maps"])
app.include_router(suppressions_router.router, prefix="/api", tags=["Suppressions"])
app.include_router(quarantine_rules_router.router, tags=["Quarantine Rules"])
app.include_router(security_alerts_router.router, prefix="/api", tags=["Security Alerts"])
app.include_router(smtp_abuse_router.router, prefix="/api", tags=["SMTP Abuse Protection"])
app.include_router(protection_router.router, prefix="/api", tags=["Protection Rules"])
app.include_router(notifications_router.router, prefix="/api", tags=["Notifications"])
app.include_router(rate_limits_router.router, prefix="/api", tags=["Rate Limits"])

# WebSocket endpoint needs root-level mount (not under /api prefix) so it is
# reachable at wss://host/ws/raw-logs  # nosemgrep: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket
# Only ws_router is mounted here: including the full raw-logs router would also
# publish its HTTP routes outside /api, where the auth middleware does not guard
# them (see backend/tests/test_route_exposure.py).
app.include_router(raw_logs_router.ws_router, tags=["Raw Logs WebSocket"])

# Mount static files (frontend). The slim Python image has no MIME entry for
# web fonts, so they would go out as application/octet-stream.
mimetypes.add_type("font/woff2", ".woff2")
app.mount("/static", StaticFiles(directory="/app/frontend"), name="static")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: Optional[str] = None):
    """Serve the login page, or skip it when there is nothing to sign in to"""
    if not settings.is_authentication_enabled or get_session_from_request(request):
        return RedirectResponse(url=safe_return_path(next), status_code=302, headers={"Cache-Control": "no-store"})
    try:
        with open("/app/frontend/login.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(
            content="<h1>mailcow Logs Viewer</h1><p>Login page not found. Please check installation.</p>",
            status_code=500
        )


@app.get("/", response_class=HTMLResponse)
def root():
    """Serve the main HTML page - requires authentication"""
    # Authentication is handled by middleware
    # If user reaches here, they are authenticated
    try:
        with open("/app/frontend/index.html", "r") as f:
            html = f.read()
        # Asset links carry a content hash, and the page itself is always revalidated
        return HTMLResponse(content=stamp_asset_versions(html, "/app/frontend"), headers={"Cache-Control": "no-cache"})
    except FileNotFoundError:
        return HTMLResponse(
            content="<h1>mailcow Logs Viewer</h1><p>Frontend not found. Please check installation.</p>",
            status_code=500
        )


@app.get("/api/health")
def health_check():
    """Health check endpoint for Docker monitoring.

    Publicly reachable - intentionally returns no configuration details.
    Keep this synchronous so FastAPI runs the blocking DB probe in its thread pool.
    """
    db_ok = check_db_connection()

    return JSONResponse(
        status_code=200 if db_ok else 503,
        content={
            "status": "healthy" if db_ok else "unhealthy",
            "database": "connected" if db_ok else "disconnected",
        },
    )


@app.get("/api/info")
async def app_info(request: Request):
    """Application information endpoint.

    This endpoint is reachable without authentication (the login page needs
    the title/auth flags), so infrastructure details (mailcow URL, hosted
    domains, version) are only included for authenticated requests.
    """
    from .auth import is_request_authenticated

    info = {
        "name": "mailcow Logs Viewer",
        "app_title": settings.app_title,
        "app_logo_url": settings.app_logo_url,
        "auth_enabled": settings.is_authentication_enabled,
        "basic_auth_enabled": settings.is_basic_auth_enabled,
        "oauth2_enabled": settings.is_oauth2_enabled,
    }

    if is_request_authenticated(request):
        info.update({
            "version": __version__,
            "mailcow_url": settings.mailcow_url,
            "local_domains": settings.local_domains_list,
            "fetch_interval": settings.fetch_interval,
            "retention_days": settings.retention_days,
            "timezone": settings.tz,
            "blacklist_count": len(settings.blacklist_emails_list),
            "disabled_features": sorted(settings.disabled_features_set),
        })

    return info


@app.exception_handler(MailcowAPIError)
async def mailcow_exception_handler(request: Request, exc: MailcowAPIError):
    """A mailcow failure no route turned into an answer: say it was mailcow"""
    logger.error(f"mailcow request failed: {exc}")
    error = internal_error(exc)
    return JSONResponse(status_code=error.status_code, content={"detail": error.detail})


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc) if settings.debug else "An error occurred"
        }
    )


# SPA catch-all route - must be AFTER all other routes and exception handlers
# Returns index.html for all frontend routes (e.g., /dashboard, /messages, /dmarc)
@app.get("/{full_path:path}", response_class=HTMLResponse)
def spa_catch_all(full_path: str):
    """Serve the SPA for all frontend routes - enables clean URLs"""
    # API and static routes are handled by their respective routers/mounts
    # This catch-all only receives unmatched routes
    try:
        with open("/app/frontend/index.html", "r") as f:
            html = f.read()
        # Asset links carry a content hash, and the page itself is always revalidated
        return HTMLResponse(content=stamp_asset_versions(html, "/app/frontend"), headers={"Cache-Control": "no-cache"})
    except FileNotFoundError:
        return HTMLResponse(
            content="<h1>mailcow Logs Viewer</h1><p>Frontend not found. Please check installation.</p>",
            status_code=500
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.app_port,
        reload=settings.debug
    )
