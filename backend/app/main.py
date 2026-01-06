"""
Main FastAPI application
Entry point for the Mailcow Logs Viewer backend
"""
import logging
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from .config import settings, set_cached_active_domains
from .database import init_db, check_db_connection
from .scheduler import start_scheduler, stop_scheduler
from .mailcow_api import mailcow_api
from .routers import logs, stats
from .routers import export as export_router
from .routers import domains as domains_router
from .migrations import run_migrations
from .auth import BasicAuthMiddleware
from .version import __version__

logger = logging.getLogger(__name__)

try:
    from .routers import status as status_router
    from .routers import messages as messages_router
    from .routers import settings as settings_router
except ImportError as e:
    logger.warning(f"Optional routers not available: {e}")
    status_router = None
    messages_router = None
    settings_router = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management"""
    # Startup
    logger.info("Starting Mailcow Logs Viewer")
    logger.info(f"Configuration: {settings.fetch_interval}s interval, {settings.retention_days}d retention")
    
    if settings.blacklist_emails_list:
        logger.info(f"Blacklist enabled with {len(settings.blacklist_emails_list)} email(s)")
    
    if settings.auth_enabled:
        logger.info("Basic authentication is ENABLED")
        if not settings.auth_password:
            logger.warning("WARNING: Authentication enabled but password not set!")
    else:
        logger.info("Basic authentication is DISABLED")
    
    # Initialize database
    try:
        init_db()
        if not check_db_connection():
            logger.error("Database connection failed!")
            raise Exception("Cannot connect to database")
        
        # Run migrations and cleanup
        logger.info("Running database migrations and cleanup...")
        run_migrations()
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise
    
    # Test Mailcow API connection and fetch active domains
    try:
        api_ok = await mailcow_api.test_connection()
        if not api_ok:
            logger.warning("Mailcow API connection test failed - check your configuration")
        else:
            try:
                active_domains = await mailcow_api.get_active_domains()
                if active_domains:
                    set_cached_active_domains(active_domains)
                    logger.info(f"Loaded {len(active_domains)} active domains from Mailcow API")
                else:
                    logger.warning("No active domains found in Mailcow - check your configuration")
            except Exception as e:
                logger.error(f"Failed to fetch active domains: {e}")
    except Exception as e:
        logger.error(f"Mailcow API test failed: {e}")
    
    # Start background scheduler
    try:
        start_scheduler()
    except Exception as e:
        logger.error(f"Failed to start scheduler: {e}")
        raise
    
    logger.info("Application startup complete")
    
    yield
    
    # Shutdown
    logger.info("Shutting down application")
    stop_scheduler()
    logger.info("Application shutdown complete")


# Create FastAPI app
app = FastAPI(
    title="Mailcow Logs Viewer",
    description="Modern dashboard for viewing and analyzing Mailcow mail server logs",
    version=__version__,
    lifespan=lifespan
)

# Add Basic Auth Middleware FIRST (before CORS)
# This ensures ALL requests are authenticated when enabled
app.add_middleware(BasicAuthMiddleware)

# CORS middleware (allow all origins for now)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(logs.router, prefix="/api", tags=["Logs"])
app.include_router(stats.router, prefix="/api", tags=["Statistics"])
app.include_router(export_router.router, prefix="/api", tags=["Export"])
app.include_router(status_router.router, prefix="/api", tags=["Status"])
app.include_router(messages_router.router, prefix="/api", tags=["Messages"])
app.include_router(settings_router.router, prefix="/api", tags=["Settings"])
app.include_router(domains_router.router, prefix="/api", tags=["Domains"])

# Mount static files (frontend)
app.mount("/static", StaticFiles(directory="/app/frontend"), name="static")


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    """Serve the login page"""
    try:
        with open("/app/frontend/login.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(
            content="<h1>Mailcow Logs Viewer</h1><p>Login page not found. Please check installation.</p>",
            status_code=500
        )


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main HTML page - requires authentication"""
    # Authentication is handled by middleware
    # If user reaches here, they are authenticated
    try:
        with open("/app/frontend/index.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(
            content="<h1>Mailcow Logs Viewer</h1><p>Frontend not found. Please check installation.</p>",
            status_code=500
        )


@app.get("/api/health")
async def health_check():
    """Health check endpoint for monitoring"""
    db_ok = check_db_connection()
    
    return {
        "status": "healthy" if db_ok else "unhealthy",
        "database": "connected" if db_ok else "disconnected",
        "version": __version__,
        "config": {
            "fetch_interval": settings.fetch_interval,
            "retention_days": settings.retention_days,
            "mailcow_url": settings.mailcow_url,
            "blacklist_enabled": len(settings.blacklist_emails_list) > 0,
            "auth_enabled": settings.auth_enabled
        }
    }


@app.get("/api/info")
async def app_info():
    """Application information endpoint"""
    return {
        "name": "Mailcow Logs Viewer",
        "version": __version__,
        "mailcow_url": settings.mailcow_url,
        "local_domains": settings.local_domains_list,
        "fetch_interval": settings.fetch_interval,
        "retention_days": settings.retention_days,
        "timezone": settings.tz,
        "app_title": settings.app_title,
        "app_logo_url": settings.app_logo_url,
        "blacklist_count": len(settings.blacklist_emails_list),
        "auth_enabled": settings.auth_enabled
    }


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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.app_port,
        reload=settings.debug
    )