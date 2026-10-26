"""
API endpoints for system status and health monitoring
"""
import asyncio
import logging
import httpx
from urllib.parse import quote
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from typing import Dict, Any

from ..mailcow_api import mailcow_api
from ..version import __version__
from ..scheduler import check_app_version_update, get_app_version_cache
from ..database import SessionLocal
from ..models import KnownContainer
from ..services.ignore_lists import load_ignored, set_ignored, IGNORED_CONTAINERS_KEY
from ..utils import internal_error, format_datetime_for_api
from ..api_models import Invalid, documented
from ..api_models import status as m
from ..api_models.mailboxes import MailcowInfo, StorageStatus

logger = logging.getLogger(__name__)

router = APIRouter()

# Cache for version check (check once per day)
version_cache = {
    "checked_at": None,
    "current_version": None,
    "latest_version": None,
    "update_available": False,
    "changelog": None
}

def _started_at(value):
    """A container start time as UTC with Z. Docker gives RFC 3339 in UTC with
    nanoseconds; anything unreadable is passed on as it came."""
    if not value or not isinstance(value, str):
        return value
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return value
    return format_datetime_for_api(parsed)


async def _get_containers_status_internal():
    """Fetch mailcow asynchronously, then persist and build status in a worker."""
    containers_data = await mailcow_api.get_status_containers()
    return await asyncio.to_thread(_store_container_status_worker, containers_data)


def _store_container_status_worker(containers_data):
    """Keep cache queries, writes and rollback in one worker-owned session."""
    with SessionLocal() as db:
        try:
            # Extract the containers dict from the list
            containers_dict = {}
            if containers_data and len(containers_data) > 0:
                containers_dict = containers_data[0] if isinstance(containers_data, list) else containers_data

            # Load known containers from database
            known_containers = {kc.container_name: kc for kc in db.query(KnownContainer).all()}
            # Containers stopped on purpose (e.g. ipv6nat without IPv6) are
            # listed but never counted, so they raise no alert
            ignored = load_ignored(db, IGNORED_CONTAINERS_KEY)
            ignored_count = 0

            # Track which containers are active (appear in API response)
            active_container_names = set(containers_dict.keys())
            current_time = datetime.utcnow()

            # Build simplified response
            simplified_containers = {}
            running_count = 0
            stopped_count = 0

            # Process containers from API (active containers)
            for container_key, info in containers_dict.items():
                # Get state and normalize (handle None, empty string, etc.)
                state = info.get('state', 'unknown')
                if state is None or state == '':
                    state = 'unknown'
                else:
                    state = str(state).lower().strip()

                # Simplify container name (remove -mailcow suffix)
                display_name = container_key.replace('-mailcow', '')

                # Update or create known container
                if container_key in known_containers:
                    known_container = known_containers[container_key]
                    known_container.last_seen = current_time
                    known_container.updated_at = current_time
                    if known_container.display_name != display_name:
                        known_container.display_name = display_name
                else:
                    # New container - add to database
                    known_container = KnownContainer(
                        container_name=container_key,
                        display_name=display_name,
                        last_seen=current_time
                    )
                    db.add(known_container)
                    known_containers[container_key] = known_container

                # Count containers: only 'running' is considered running, everything else is stopped
                if container_key in ignored:
                    ignored_count += 1
                elif state == 'running':
                    running_count += 1
                else:
                    stopped_count += 1

                # Build simplified entry
                simplified_containers[container_key] = {
                    "name": display_name,
                    "state": state,
                    "started_at": _started_at(info.get('started_at')),
                    "ignored": container_key in ignored
                }

            # Process known containers that are not in API response (stopped containers)
            for container_key, known_container in known_containers.items():
                if container_key not in active_container_names:
                    # Container is known but not in API response - it's stopped
                    display_name = known_container.display_name

                    simplified_containers[container_key] = {
                        "name": display_name,
                        "state": "stopped",
                        "started_at": None,
                        "ignored": container_key in ignored
                    }
                    if container_key in ignored:
                        ignored_count += 1
                    else:
                        stopped_count += 1

            # Commit database changes
            try:
                db.commit()
            except Exception as db_error:
                logger.error(f"Error committing container cache changes: {db_error}")
                db.rollback()
                # Continue without cache update - still return the results

            return {
                "containers": simplified_containers,
                "summary": {
                    "running": running_count,
                    "stopped": stopped_count,
                    "total": len(simplified_containers) - ignored_count,
                    "ignored": ignored_count
                }
            }

        except Exception as e:
            logger.error(f"Error fetching container status: {e}", exc_info=True)
            # Try to rollback if there's a DB error
            try:
                db.rollback()
            except Exception:
                pass
            # Re-raise the exception - let the caller handle HTTPException
            raise


@router.get("/status/containers", responses=documented(m.ContainersResponse, errors={500: None, 502: None}))
async def get_containers_status():
    """
    Get status of all mailcow containers
    Returns simplified container info: name (without -mailcow), state, started_at
    Uses database cache to track stopped containers that don't appear in API response
    """
    try:
        return await _get_containers_status_internal()
    except Exception as e:
        logger.error("Failed to fetch container status: %s", e)
        raise internal_error(e)


class ContainerIgnoreRequest(BaseModel):
    ignored: bool


@router.put("/status/containers/{container}/ignore", responses=documented(m.ContainerIgnored, errors={404: None, 422: Invalid, 500: None}))
def ignore_container(container: str, body: ContainerIgnoreRequest):
    """Ignore or stop ignoring one mailcow container (by its full name, e.g. ipv6nat-mailcow)."""
    with SessionLocal() as db:
        if not db.query(KnownContainer).filter(KnownContainer.container_name == container).first():
            raise HTTPException(status_code=404, detail="Unknown container.")
        set_ignored(db, IGNORED_CONTAINERS_KEY, container, body.ignored)
    return {"container": container, "ignored": body.ignored}


@router.get("/status/storage", responses=documented(StorageStatus, description="mailcow's mail storage, as mailcow reports it; unknown and zeros when it reports nothing", errors={500: None, 502: None}))
async def get_storage_status():
    """
    Get storage/disk usage information
    """
    try:
        vmail_data = await mailcow_api.get_status_vmail()
        
        if not vmail_data:
            return {
                "disk": "unknown",
                "used": "0",
                "total": "0",
                "used_percent": "0%"
            }
        
        return {
            "disk": vmail_data.get('disk', 'unknown'),
            "used": vmail_data.get('used', '0'),
            "total": vmail_data.get('total', '0'),
            "used_percent": vmail_data.get('used_percent', '0%')
        }
        
    except Exception as e:
        logger.error(f"Error fetching storage status: {e}", exc_info=True)
        raise internal_error(e)

@router.get("/status/version", responses=documented(m.MailcowVersion, errors={422: Invalid, 502: None}))
async def get_version_status(force: bool = Query(False, description="Force a fresh version check")):
    """
    Get current mailcow version and check for updates
    Checks GitHub once per day and caches the result
    """
    try:
        global version_cache
        
        # Check if we need to refresh the cache (once per day or forced)
        now = datetime.now(timezone.utc)
        if (force or 
            version_cache["checked_at"] is None or 
            now - version_cache["checked_at"] > timedelta(days=1)):
            
            logger.info("Checking mailcow version and updates...")
            
            # Get current version
            current_version = await mailcow_api.get_status_version()
            version_cache["current_version"] = current_version
            
            # Check GitHub for latest version
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    response = await client.get(
                        "https://api.github.com/repos/mailcow/mailcow-dockerized/releases/latest"
                    )
                    
                    if response.status_code == 200:
                        release_data = response.json()
                        latest_version = release_data.get('tag_name', 'unknown')
                        name = release_data.get('name', '')
                        changelog = release_data.get('body', '')
                        
                        version_cache["latest_version"] = latest_version
                        version_cache["name"] = name
                        version_cache["changelog"] = changelog
                        
                        # Compare versions (normalize by removing 'v' prefix)
                        curr_norm = current_version.lower().lstrip('v')
                        latest_norm = latest_version.lower().lstrip('v')
                        
                        version_cache["update_available"] = curr_norm != latest_norm
                        
                        logger.info(f"Version check: Current='{current_version}' (norm='{curr_norm}'), Latest='{latest_version}' (norm='{latest_norm}'), Update Available={version_cache['update_available']}")
                    else:
                        logger.warning(f"GitHub API returned status {response.status_code}")
                        version_cache["latest_version"] = "unknown"
                        version_cache["update_available"] = False
                        
            except Exception as e:
                logger.error(f"Failed to check GitHub for updates: {e}")
                version_cache["latest_version"] = "unknown"
                version_cache["update_available"] = False
            
            version_cache["checked_at"] = now
        
        # Format last_checked with UTC timezone indicator ('Z' suffix)
        last_checked = format_datetime_for_api(version_cache["checked_at"])
        
        return {
            "current_version": version_cache["current_version"],
            "latest_version": version_cache["latest_version"],
            "name": version_cache.get("name", ""),
            "update_available": version_cache["update_available"],
            "changelog": version_cache["changelog"],
            "last_checked": last_checked
        }
    except Exception as e:
        logger.error(f"Error fetching version status: {e}")
        raise internal_error(e)


@router.get("/status/app-version", responses=documented(m.AppVersion, errors={422: Invalid}))
async def get_app_version_status(force: bool = Query(False, description="Force a fresh version check")):
    """
    Get current app version and check for updates from GitHub
    Returns cached result (updated periodically by scheduler)
    
    Args:
        force: If True, force a fresh check regardless of cache age
    """
    try:
        # Get cache from scheduler
        app_version_cache = get_app_version_cache()
        
        # Force check or check if cache is stale (more than 1 day old) and refresh if needed
        # This is a fallback in case the scheduler hasn't run yet
        now = datetime.now(timezone.utc)
        if (force or 
            app_version_cache["checked_at"] is None or 
            now - app_version_cache["checked_at"] > timedelta(days=1)):
            await check_app_version_update()
            app_version_cache = get_app_version_cache()  # Get updated cache
        
        # Format last_checked with UTC timezone indicator ('Z' suffix)
        last_checked = format_datetime_for_api(app_version_cache["checked_at"])
        
        return {
            "current_version": app_version_cache["current_version"],
            "latest_version": app_version_cache["latest_version"],
            "update_available": app_version_cache["update_available"],
            "changelog": app_version_cache["changelog"],
            "last_checked": last_checked
        }
    except Exception as e:
        logger.error(f"Error fetching app version status: {e}")
        return {
            "current_version": __version__,
            "latest_version": "unknown",
            "update_available": False,
            "changelog": None,
            "last_checked": None,
            "error": "Unable to load system status. Check the application logs."
        }


@router.get("/status/mailcow-info", responses=documented(MailcowInfo, errors={500: None, 502: None}))
async def get_mailcow_info():
    """
    Get mailcow system information (domains, mailboxes, aliases)
    """
    try:
        # Fetch all info in parallel
        import asyncio
        domains, mailboxes, aliases = await asyncio.gather(
            mailcow_api.get_domains(),
            mailcow_api.get_mailboxes(),
            mailcow_api.get_aliases()
        )
        
        # Count active items
        active_domains = sum(1 for d in domains if d.get('active', 0) == 1)
        active_mailboxes = sum(1 for m in mailboxes if m.get('active', 0) == 1)
        active_aliases = sum(1 for a in aliases if a.get('active', 0) == 1)
        
        return {
            "domains": {
                "total": len(domains),
                "active": active_domains
            },
            "mailboxes": {
                "total": len(mailboxes),
                "active": active_mailboxes
            },
            "aliases": {
                "total": len(aliases),
                "active": active_aliases
            }
        }
    except Exception as e:
        logger.error(f"Error fetching mailcow info: {e}")
        raise internal_error(e)


@router.get("/status/mailcow-connection", responses=documented(m.MailcowConnection))
async def get_mailcow_connection_status():
    """
    Check mailcow API connection status
    """
    try:
        is_connected = await mailcow_api.test_connection()
        return {
            "connected": is_connected,
            "timestamp": format_datetime_for_api(datetime.now(timezone.utc))
        }
    except Exception as e:
        logger.error(f"Error checking mailcow connection: {e}")
        return {
            "connected": False,
            "timestamp": format_datetime_for_api(datetime.now(timezone.utc)),
            "error": "Unable to load system status. Check the application logs."
        }


@router.get("/status/app-version/changelog/{version}", responses=documented(m.Changelog, description="The notes; a sentence in changelog when they could not be read"))
async def get_app_version_changelog(version: str):
    """
    Get changelog for a specific app version from GitHub
    """
    try:
        # Remove 'v' prefix if present for API call
        version_tag = version if version.startswith('v') else f'v{version}'
        
        async with httpx.AsyncClient(timeout=10) as client:
            # Try to get the specific release by tag
            response = await client.get(
                f"https://api.github.com/repos/ShlomiPorush/mailcow-logs-viewer/releases/tags/{quote(version_tag, safe='')}"
            )
            
            if response.status_code == 200:
                release_data = response.json()
                changelog = release_data.get('body', 'No changelog available')
                return {
                    "version": version,
                    "changelog": changelog
                }
            else:
                logger.warning(f"GitHub API returned status {response.status_code} for version {version_tag}")
                return {
                    "version": version,
                    "changelog": "Changelog not found for this version"
                }
                
    except Exception as e:
        logger.error(f"Failed to fetch changelog for version {version}: {e}")
        return {
            "version": version,
            "changelog": "Failed to fetch changelog. Check the application logs."
        }


@router.get("/status/summary", responses=documented(m.StatusSummary))
async def get_status_summary():
    """
    Get combined status summary for dashboard
    """
    try:
        import asyncio
        
        # Fetch all status info in parallel
        from ..services.figures import storage_figure
        containers_data, storage_data, mailcow_info = await asyncio.gather(
            _get_containers_status_internal(),
            storage_figure(),
            get_mailcow_info(),
            return_exceptions=True
        )
        
        # Handle exceptions. Without an answer from mailcow the counts are zeros, which
        # are not "nothing stopped": containers_known says whether they were read. Its
        # API runs in a container, so an answer has one running; none running means the
        # counts came from the containers known before, not from mailcow
        containers_known = not isinstance(containers_data, Exception)
        if not containers_known:
            containers_data = {"summary": {"running": 0, "stopped": 0, "total": 0}}
        containers_known = containers_known and containers_data.get("summary", {}).get("running", 0) > 0
        if isinstance(storage_data, Exception):
            storage_data = {"used_percent": "0%", "valid": False}
        if isinstance(mailcow_info, Exception):
            mailcow_info = {"domains": {"total": 0}, "mailboxes": {"total": 0}, "aliases": {"total": 0}}
        
        return {
            "containers": containers_data.get("summary", {}),
            "containers_known": containers_known,
            "storage": {
                "used_percent": storage_data.get("used_percent", "0%"),
                "used": storage_data.get("used", "0"),
                "total": storage_data.get("total", "0"),
                # False when mailcow did not tell it: the card says Unknown, not 0%
                "known": bool(storage_data.get("valid")),
            },
            "system": {
                "domains": mailcow_info.get("domains", {}).get("total", 0),
                "mailboxes": mailcow_info.get("mailboxes", {}).get("total", 0),
                "aliases": mailcow_info.get("aliases", {}).get("total", 0)
            }
        }
    except Exception as e:
        logger.error(f"Error fetching status summary: {e}")
        raise internal_error(e)


@router.get("/status/container-logs", responses=documented(m.ContainerLogs, errors={422: Invalid}))
def get_container_logs(lines: int = Query(100, ge=10, le=1000, description="Number of lines to fetch")):
    """
    Get the application container logs from the log file
    """
    try:
        import os
        log_file = "/app/data/container.log"
        
        if not os.path.exists(log_file):
            return {"logs": ["Log file not found or hasn't been created yet."]}
            
        # Read file efficiently using deque for last N lines
        from collections import deque
        
        with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
            last_lines = deque(f, maxlen=lines)
            
        return {"logs": list(last_lines)}
        
    except Exception as e:
        logger.error(f"Error reading container logs: {e}")
        return {"logs": ["Error reading logs. Check the container output."]}
