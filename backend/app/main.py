import logging
root = logging.getLogger()
root.handlers = []

import asyncio
import mimetypes
import time

from fastapi import Depends, FastAPI, Request
from fastapi.staticfiles import StaticFiles
from .frontend_assets import stamp_asset_versions
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.convertors import Convertor, register_url_convertor
from starlette.datastructures import MutableHeaders
from contextlib import asynccontextmanager, suppress
from typing import Optional

from .config import settings, reload_settings, sign_in_problem, SettingsLoadError
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
    entities as entities_router,
    users as users_router,
)
from .migrations import run_migrations
from .agent_access import consent as agent_consent, live as agent_live, mcp as agent_mcp, oauth as agent_oauth
from .agent_access import skill as agent_skill
from .agent_access.dispatch import enforce_agent_policy
from .auth import BasicAuthMiddleware, _login_redirect, safe_return_path, session_ended_response
from . import user_access
from .origin_guard import SameOriginGuardMiddleware
from .session import get_session_from_request
from .services.auth_cleanup import auth_store_maintenance
from .version import __version__
from .api_models import documented, errors_as_json
from .api_models.agents import agent_paths
from .api_models.system import HealthResponse, InfoResponse
from .app_time import app_tz, tz_status, display_formats

from .services.geoip_downloader import (
    is_license_configured,
    get_geoip_status
)

logger = logging.getLogger(__name__)

from .routers import status as status_router
from .routers import messages as messages_router
from .routers import stats_flow as stats_flow_router
from .routers import stats_trends as stats_trends_router
from .routers import settings as settings_router


async def _loop_lag_watchdog():
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
    if settings.is_authentication_enabled:
        auth_methods = []
        if settings.is_basic_auth_enabled:
            auth_methods.append("Basic Auth")
        if settings.is_oauth2_enabled:
            auth_methods.append(f"OAuth2 ({settings.oauth2_provider_name})")
            if not settings.oauth2_client_id:
                logger.warning("WARNING: OAuth2 enabled but no client ID configured!")

        logger.info(f"Authentication is ENABLED: {', '.join(auth_methods)}")
    else:
        logger.warning(
            "Authentication is DISABLED: anyone who can reach this app can read the logs, "
            "change settings and run mailcow actions. Set BASIC_AUTH_ENABLED=true with "
            "AUTH_PASSWORD, or configure OAuth2, unless access is restricted another way."
        )


def log_agent_access_state() -> None:
    problem = agent_live.problem()
    if problem == agent_live.OFF or not settings.agent_access_enabled:
        pass
    elif problem:
        logger.warning(f"Agent access is switched on but not available ({problem}): see Settings > Agents")
    else:
        logger.info(f"Agent access is ON: skill at {agent_live.issuer()}/agents/skill/, MCP at {agent_live.resource()}")
    try:
        from .agent_access import store as agent_store
        from .database import get_db_context
        with get_db_context() as db:
            agent_store.check_sign_in_unchanged(db)
    except Exception as e:
        logger.error(f"Could not compare the sign-in settings for agent access: {e}")


def log_user_name_conflicts() -> None:
    if not settings.is_basic_auth_enabled:
        return
    try:
        from .database import get_db_context
        from .services.users_store import name_conflicts
        with get_db_context() as db:
            for name in name_conflicts(db):
                logger.warning(f"The local user '{name}' has the built-in admin's username (AUTH_USERNAME) and "
                               "cannot sign in. Delete that user, or choose another AUTH_USERNAME.")
    except Exception as e:
        logger.error(f"Could not compare local users with AUTH_USERNAME: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting mailcow Logs Viewer")
    
    try:
        init_db()
        if not check_db_connection():
            logger.error("Database connection failed!")
            raise Exception("Cannot connect to database")
        
        logger.info("Running database migrations and cleanup...")
        run_migrations()

        from .migrations import run_alembic_upgrade
        run_alembic_upgrade()

        if settings.edit_settings_via_ui_enabled:
            from .database import get_db_context
            with get_db_context() as db:
                reload_settings(db)
            logger.info("Settings loaded from database overrides")
            try:
                mailcow_api.reload_config()
                from .services.oauth2_client import oauth2_client
                oauth2_client.reload_config()
            except Exception as e:
                logger.warning(f"Could not apply the stored settings to the mailcow and OAuth2 clients: {e}")
    except Exception as e:
        logger.error(f"Failed to initialize database or load the stored settings: {e}")
        raise

    problem = sign_in_problem(settings)
    if problem:
        logger.error(problem)
        raise SettingsLoadError(problem)

    logger.info(f"Configuration: {settings.fetch_interval}s interval, {settings.retention_days}d retention")
    
    if settings.blacklist_emails_list:
        logger.info(f"Blacklist enabled with {len(settings.blacklist_emails_list)} email(s)")
    
    log_authentication_state()
    log_agent_access_state()
    log_user_name_conflicts()

    logger.info(f"Time zone: {app_tz().key}")
    
    try:
        if is_license_configured():
            status = get_geoip_status()
            city_info = status['City']
            asn_info = status['ASN']
            if city_info['available']:
                logger.info(f"GeoIP databases found: City {city_info['size_mb']}MB ({city_info['age_days']}d), ASN {asn_info['size_mb']}MB ({asn_info['age_days']}d)")
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

    try:
        start_scheduler()
    except Exception as e:
        logger.error(f"Failed to start scheduler: {e}")
        raise
    
    try:
        start_raw_logs_scheduler()
    except Exception as e:
        logger.error(f"Failed to start raw logs scheduler: {e}")
    
    lag_watchdog_task = asyncio.create_task(_loop_lag_watchdog())

    logger.info("Application startup complete")
    
    async with auth_store_maintenance():
        yield
    
    logger.info("Shutting down application")
    lag_watchdog_task.cancel()
    with suppress(asyncio.CancelledError):
        await lag_watchdog_task
    stop_raw_logs_scheduler()
    stop_scheduler()
    await mailcow_api.aclose()
    logger.info("Application shutdown complete")


app = FastAPI(
    title="mailcow Logs Viewer",
    description=(
        "Modern dashboard for viewing and analyzing mailcow mail server logs\n\n"
        "With sign-in on, every call except /api/health, /api/info and the sign-in calls needs a session or Basic "
        "credentials, and answers 401 without them. A call with a session that a limit ended answers 401 with "
        "{detail, reason} and the reason in the X-Session-End header: session_expired (the longest session) or "
        "session_idle (inactivity) or access_changed (the person's account changed or no longer gives access). "
        "A write sent from another site's page answers 403, and so does a call the signed-in person's access does "
        "not cover, with {detail}. When the person's access cannot be checked, a call answers 503. "
        "With Basic auth on but no password set, those calls answer 500 with a sentence in plain text. "
        "An agent's call with a bearer token may also be refused or cut short by the agent gateway, which answers "
        "{error, message}."
    ),
    version=__version__,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    dependencies=[Depends(enforce_agent_policy), Depends(user_access.enforce_people_policy)],
)

_generate_openapi = app.openapi


def _openapi_with_agent_calls():
    if app.openapi_schema is None:
        document = _generate_openapi()
        errors_as_json(document)
        agent_paths(document)
    return app.openapi_schema


app.openapi = _openapi_with_agent_calls

app.add_middleware(user_access.ActionLogMiddleware)

app.add_middleware(BasicAuthMiddleware)

app.add_middleware(SameOriginGuardMiddleware)


def configure_cors(application: FastAPI) -> None:
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

# Without ws: wss: in connect-src, browsers where 'self' does not cover WebSocket schemes block the live log viewer
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: https:; "
    "font-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)


class SecurityHeadersMiddleware:
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

app.add_middleware(SlowRequestLogMiddleware)

app.include_router(auth_router.router, prefix="/api", tags=["Authentication"])
app.include_router(logs.router, prefix="/api", tags=["Logs"])
app.include_router(stats.router, prefix="/api", tags=["Statistics"])
app.include_router(stats_flow_router.router, prefix="/api", tags=["Statistics"])
app.include_router(stats_trends_router.router, prefix="/api", tags=["Statistics"])
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
app.include_router(entities_router.router, prefix="/api", tags=["Entities"])
app.include_router(users_router.router, prefix="/api")
app.include_router(agent_consent.router, prefix="/api")

app.include_router(agent_oauth.router)
app.include_router(agent_mcp.router)
app.include_router(agent_skill.router)

app.include_router(raw_logs_router.ws_router, tags=["Raw Logs WebSocket"])

mimetypes.add_type("font/woff2", ".woff2")
app.mount("/static", StaticFiles(directory="/app/frontend"), name="static")


@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_page(request: Request, next: Optional[str] = None):
    if not settings.is_authentication_enabled or get_session_from_request(request):
        return RedirectResponse(url=safe_return_path(next), status_code=302, headers={"Cache-Control": "no-store"})
    try:
        with open("/app/frontend/login.html", "r") as f:
            html = f.read()
        return HTMLResponse(content=stamp_asset_versions(html, "/app/frontend"))
    except FileNotFoundError:
        return HTMLResponse(
            content="<h1>mailcow Logs Viewer</h1><p>Login page not found. Please check installation.</p>",
            status_code=500
        )


@app.get(agent_oauth.CONSENT_PAGE, response_class=HTMLResponse, include_in_schema=False)
def agent_consent_page():
    if not agent_live.is_live():
        return HTMLResponse(content="Not Found", status_code=404)
    with open("/app/frontend/authorize.html", "r") as f:
        html = f.read()
    return HTMLResponse(content=stamp_asset_versions(html, "/app/frontend"), headers={"Cache-Control": "no-store"})


@app.get("/docs", response_class=HTMLResponse, include_in_schema=False)
def api_docs_page():
    with open("/app/frontend/api-docs.html", "r") as f:
        html = f.read()
    return HTMLResponse(content=stamp_asset_versions(html, "/app/frontend"), headers={"Cache-Control": "no-cache"})


@app.get("/redoc", include_in_schema=False)
def redoc_moved():
    return RedirectResponse(url="/docs", status_code=301)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def root():
    try:
        with open("/app/frontend/index.html", "r") as f:
            html = f.read()
        return HTMLResponse(content=stamp_asset_versions(html, "/app/frontend"), headers={"Cache-Control": "no-cache"})
    except FileNotFoundError:
        return HTMLResponse(
            content="<h1>mailcow Logs Viewer</h1><p>Frontend not found. Please check installation.</p>",
            status_code=500
        )


@app.get("/api/health", responses={**documented(HealthResponse), 503: {"model": HealthResponse, "description": "The database cannot be reached"}})
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


@app.get("/api/info", responses=documented(InfoResponse))
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

    from starlette.concurrency import run_in_threadpool
    cookie = "none" if not settings.is_authentication_enabled else await run_in_threadpool(user_access.cookie_access, request)
    if cookie == "ok" or (cookie == "none" and is_request_authenticated(request)):
        info.update({
            "version": __version__,
            "mailcow_url": settings.mailcow_url,
            "local_domains": settings.local_domains_list,
            "fetch_interval": settings.fetch_interval,
            "retention_days": settings.retention_days,
            **tz_status(),
            **display_formats(),
            "blacklist_count": len(settings.blacklist_emails_list),
            "disabled_features": sorted(settings.disabled_features_set),
            "settings_edit_via_ui_enabled": settings.edit_settings_via_ui_enabled,
        })

    return info


@app.exception_handler(user_access.SessionEnded)
async def session_ended_handler(request: Request, exc: user_access.SessionEnded):
    if request.url.path.startswith("/api/"):
        return session_ended_response(exc.reason)
    return _login_redirect(request, exc.reason)


@app.exception_handler(user_access.NotPermitted)
async def not_permitted_handler(request: Request, exc: user_access.NotPermitted):
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=403, content={"detail": user_access.NOT_PERMITTED})
    return agent_oauth.error_page("No permission", "Only an admin can connect agents to this app.", 403)


@app.exception_handler(MailcowAPIError)
async def mailcow_exception_handler(request: Request, exc: MailcowAPIError):
    logger.error(f"mailcow request failed: {exc}")
    error = internal_error(exc)
    return JSONResponse(status_code=error.status_code, content={"detail": error.detail})


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc) if settings.debug else "An error occurred"
        }
    )


class SpaPathConvertor(Convertor):
    regex = r"(?!(?:api|ws)(?:/|$)).*"

    def convert(self, value: str) -> str:
        return value

    def to_string(self, value: str) -> str:
        return value


register_url_convertor("spa_path", SpaPathConvertor())


@app.get("/{full_path:spa_path}", response_class=HTMLResponse, include_in_schema=False)
def spa_catch_all(full_path: str):
    try:
        with open("/app/frontend/index.html", "r") as f:
            html = f.read()
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
