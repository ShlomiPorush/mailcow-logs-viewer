"""
API endpoints for system status and health monitoring
"""
import logging
import httpx
from fastapi import APIRouter, HTTPException, Query, Depends
from datetime import datetime, timedelta, timezone
from typing import Dict, Any
from sqlalchemy.orm import Session

from ..mailcow_api import mailcow_api
from ..version import __version__
from ..scheduler import check_app_version_update, get_app_version_cache
from ..database import get_db
from ..models import KnownContainer
from ..utils import internal_error

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

async def _get_containers_status_internal(db: Session):
    """
    Internal function to get container status with explicit db session
    """
    try:
        # Get containers from API
        containers_data = await mailcow_api.get_status_containers()
        
        # Extract the containers dict from the list
        containers_dict = {}
        if containers_data and len(containers_data) > 0:
            containers_dict = containers_data[0] if isinstance(containers_data, list) else containers_data
        
        # Load known containers from database
        known_containers = {kc.container_name: kc for kc in db.query(KnownContainer).all()}
        
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
            if state == 'running':
                running_count += 1
            else:
                stopped_count += 1
            
            # Build simplified entry
            simplified_containers[container_key] = {
                "name": display_name,
                "state": state,
                "started_at": info.get('started_at', None)
            }
        
        # Process known containers that are not in API response (stopped containers)
        for container_key, known_container in known_containers.items():
            if container_key not in active_container_names:
                # Container is known but not in API response - it's stopped
                display_name = known_container.display_name
                
                simplified_containers[container_key] = {
                    "name": display_name,
                    "state": "stopped",
                    "started_at": None
                }
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
                "total": len(simplified_containers)
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


@router.get("/status/containers")
async def get_containers_status(db: Session = Depends(get_db)):
    """
    Get status of all mailcow containers
    Returns simplified container info: name (without -mailcow), state, started_at
    Uses database cache to track stopped containers that don't appear in API response
    """
    try:
        return await _get_containers_status_internal(db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch container status: {str(e)}")


@router.get("/status/storage")
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
        raise HTTPException(status_code=500, detail=f"Failed to fetch storage status: {str(e)}")

@router.get("/status/version")
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
        last_checked = None
        if version_cache["checked_at"]:
            if version_cache["checked_at"].tzinfo is None:
                # If naive, assume UTC
                dt = version_cache["checked_at"].replace(tzinfo=timezone.utc)
            else:
                dt = version_cache["checked_at"]
            # Convert to UTC and format with 'Z' suffix
            dt_utc = dt.astimezone(timezone.utc)
            last_checked = dt_utc.replace(microsecond=0).isoformat().replace('+00:00', 'Z')
        
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


@router.get("/status/app-version")
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
        last_checked = None
        if app_version_cache["checked_at"]:
            if app_version_cache["checked_at"].tzinfo is None:
                # If naive, assume UTC
                dt = app_version_cache["checked_at"].replace(tzinfo=timezone.utc)
            else:
                dt = app_version_cache["checked_at"]
            # Convert to UTC and format with 'Z' suffix
            dt_utc = dt.astimezone(timezone.utc)
            last_checked = dt_utc.replace(microsecond=0).isoformat().replace('+00:00', 'Z')
        
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
            "error": str(e)
        }


@router.get("/status/mailcow-info")
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


@router.get("/status/mailcow-connection")
async def get_mailcow_connection_status():
    """
    Check mailcow API connection status
    """
    try:
        is_connected = await mailcow_api.test_connection()
        return {
            "connected": is_connected,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error checking mailcow connection: {e}")
        return {
            "connected": False,
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }


@router.get("/status/app-version/changelog/{version}")
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
                f"https://api.github.com/repos/ShlomiPorush/mailcow-logs-viewer/releases/tags/{version_tag}"
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
            "changelog": f"Failed to fetch changelog: {str(e)}"
        }


@router.get("/status/summary")
async def get_status_summary(db: Session = Depends(get_db)):
    """
    Get combined status summary for dashboard
    """
    try:
        import asyncio
        
        # Fetch all status info in parallel
        containers_data, storage_data, mailcow_info = await asyncio.gather(
            _get_containers_status_internal(db),
            get_storage_status(),
            get_mailcow_info(),
            return_exceptions=True
        )
        
        # Handle exceptions
        if isinstance(containers_data, Exception):
            containers_data = {"summary": {"running": 0, "stopped": 0, "total": 0}}
        if isinstance(storage_data, Exception):
            storage_data = {"used_percent": "0%"}
        if isinstance(mailcow_info, Exception):
            mailcow_info = {"domains": {"total": 0}, "mailboxes": {"total": 0}, "aliases": {"total": 0}}
        
        return {
            "containers": containers_data.get("summary", {}),
            "storage": {
                "used_percent": storage_data.get("used_percent", "0%"),
                "used": storage_data.get("used", "0"),
                "total": storage_data.get("total", "0")
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


@router.get("/status/container-logs")
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
        return {"logs": [f"Error reading logs: {str(e)}"]}