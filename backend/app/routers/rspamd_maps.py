"""
API endpoints for managing Rspamd map files

Provides read/write access to all 13 Rspamd maps in mailcow,
including regex validation before saving.

Read: Rspamd API (GET /rspamd/maps, GET /rspamd/getmap) via Password header
Write: mailcow API (POST /api/v1/edit/rspamd-map) via X-API-Key RW header
"""
import re
import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from ..config import settings
from ..mailcow_api import mailcow_api, MailcowAPIError
from ..utils import internal_error

logger = logging.getLogger(__name__)

router = APIRouter()

# All known mailcow Rspamd maps with metadata
RSPAMD_MAPS = [
    {
        "filename": "global_mime_from_blacklist.map",
        "name": "Header-From: Denylist",
        "category": "sender",
        "description": "Block emails by From header address",
        "supports_regex": True,
    },
    {
        "filename": "global_mime_from_whitelist.map",
        "name": "Header-From: Allowlist",
        "category": "sender",
        "description": "Allow emails by From header address",
        "supports_regex": True,
    },
    {
        "filename": "global_smtp_from_blacklist.map",
        "name": "Envelope Sender Denylist",
        "category": "sender",
        "description": "Block by envelope sender address",
        "supports_regex": True,
    },
    {
        "filename": "global_smtp_from_whitelist.map",
        "name": "Envelope Sender Allowlist",
        "category": "sender",
        "description": "Allow by envelope sender address",
        "supports_regex": True,
    },
    {
        "filename": "global_rcpt_blacklist.map",
        "name": "Recipient Denylist",
        "category": "recipient",
        "description": "Block sending to these recipient addresses",
        "supports_regex": True,
        "managed_by_suppression": True,
    },
    {
        "filename": "global_rcpt_whitelist.map",
        "name": "Recipient Allowlist",
        "category": "recipient",
        "description": "Allow sending to these recipient addresses",
        "supports_regex": True,
    },
    {
        "filename": "fishy_tlds.map",
        "name": "Fishy TLDs",
        "category": "content",
        "description": "Suspicious TLDs (only fired in combination with bad words)",
        "supports_regex": True,
    },
    {
        "filename": "bad_words.map",
        "name": "Bad Words",
        "category": "content",
        "description": "Bad words (only fired in combination with fishy TLDs)",
        "supports_regex": True,
    },
    {
        "filename": "bad_words_de.map",
        "name": "Bad Words DE",
        "category": "content",
        "description": "German bad words (only fired in combination with fishy TLDs)",
        "supports_regex": True,
    },
    {
        "filename": "bad_languages.map",
        "name": "Bad Languages",
        "category": "content",
        "description": "Blocked languages",
        "supports_regex": True,
    },
    {
        "filename": "bulk_header.map",
        "name": "Bulk Mail Headers",
        "category": "content",
        "description": "Bulk/mass mail header patterns",
        "supports_regex": True,
    },
    {
        "filename": "bad_header.map",
        "name": "Bad Mail Headers",
        "category": "content",
        "description": "Junk mail header patterns",
        "supports_regex": True,
    },
    {
        "filename": "monitoring_nolog.map",
        "name": "Monitoring Hosts",
        "category": "system",
        "description": "Hosts excluded from logging",
        "supports_regex": True,
    },
]

# Build a quick lookup by filename
_MAP_METADATA = {m["filename"]: m for m in RSPAMD_MAPS}


class MapContentRequest(BaseModel):
    content: str


class MapValidationRequest(BaseModel):
    content: str
    filename: Optional[str] = None


def validate_map_content(content: str) -> List[Dict[str, Any]]:
    """
    Validate map content line by line.
    Returns a list of errors (empty if all valid).
    
    Each line can be:
    - Empty / whitespace only -> valid
    - Comment (starts with #) -> valid
    - Regex (starts with / and ends with / or /i) -> validate regex syntax
    - Plain text (email, domain, header, word) -> accept
    """
    errors = []
    lines = content.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # Empty or comment lines are always valid
        if not stripped or stripped.startswith('#'):
            continue
        
        # Check if it looks like a regex: /pattern/ or /pattern/i
        regex_match = re.match(r'^/(.+)/([a-zA-Z]*)$', stripped)
        if regex_match:
            pattern = regex_match.group(1)
            flags_str = regex_match.group(2)
            try:
                flags = 0
                if 'i' in flags_str:
                    flags |= re.IGNORECASE
                re.compile(pattern, flags)
            except re.error as e:
                errors.append({
                    "line": i,
                    "content": stripped,
                    "severity": "error",
                    "error": f"Invalid regex: {str(e)}"
                })
            continue

        # A bare address in a regexp map is compiled unanchored and matches
        # every recipient that merely CONTAINS it - e@example.com also hits
        # alice@example.com. Accepted for compatibility, but flagged.
        if re.match(r'^[^\s/@]+@[^\s/@]+\.[^\s/@]+$', stripped):
            errors.append({
                "line": i,
                "content": stripped,
                "severity": "warning",
                "error": "A bare address matches as a substring: mail to every recipient containing it is affected. It is anchored automatically when saved (for example /^user@example\\.com$/i)"
            })
            continue

        # All other lines are accepted (emails, domains, headers, words, TLDs, etc.)
        # We don't strictly validate format since maps can contain various entry types

    return errors


@router.get("/rspamd/config")
def get_rspamd_config():
    """
    Check Rspamd integration configuration status.
    Returns whether Rspamd password and RW key are configured.
    """
    return {
        "rspamd_configured": settings.is_rspamd_configured,
        "rw_key_configured": mailcow_api.has_rw_key,
        "suppression_enabled": settings.suppression_enabled,
        "suppression_configured": settings.is_suppression_configured,
    }


@router.get("/rspamd/maps")
async def list_rspamd_maps():
    """
    List all 13 Rspamd map files with metadata.
    
    If Rspamd is configured, also fetches the map IDs and entry counts
    from the Rspamd API for live status.
    """
    if not settings.is_rspamd_configured:
        # Return metadata only, without live data
        return {
            "configured": False,
            "message": "Rspamd password not configured. Set RSPAMD_PASSWORD in Settings.",
            "maps": RSPAMD_MAPS,
        }
    
    try:
        # Fetch live map data from Rspamd
        live_maps = await mailcow_api.get_rspamd_maps()
        
        # Build lookup by filename from uri
        live_lookup = {}
        for lm in live_maps:
            uri = lm.get("uri", "")
            for known in RSPAMD_MAPS:
                if known["filename"] in uri:
                    live_lookup[known["filename"]] = {
                        "map_id": lm.get("map"),
                        "loaded": lm.get("loaded", False),
                        "editable": lm.get("editable", False),
                        "rspamd_description": lm.get("description", ""),  # renamed to avoid overwriting our metadata description
                    }
                    break
        
        # Merge live data with our metadata
        result_maps = []
        for m in RSPAMD_MAPS:
            entry = {**m}
            live = live_lookup.get(m["filename"])
            if live:
                entry.update(live)
            else:
                entry["map_id"] = None
                entry["loaded"] = False
            result_maps.append(entry)
        
        return {
            "configured": True,
            "rw_key_configured": mailcow_api.has_rw_key,
            "maps": result_maps,
        }
        
    except MailcowAPIError as e:
        logger.error(f"Failed to list Rspamd maps: {e}")
        return {
            "configured": True,
            "error": str(e),
            "maps": RSPAMD_MAPS,
        }


@router.get("/rspamd/maps/{filename}")
async def get_map_content(filename: str):
    """
    Get the content of a specific Rspamd map file.
    
    Reads via Rspamd API using the map ID.
    """
    if filename not in _MAP_METADATA:
        raise HTTPException(status_code=404, detail=f"Unknown map file: {filename}")
    
    if not settings.is_rspamd_configured:
        raise HTTPException(status_code=400, detail="Rspamd password not configured")
    
    try:
        map_id = await mailcow_api.find_rspamd_map_id(filename)
        if map_id is None:
            return {
                "filename": filename,
                "content": "",
                "entry_count": 0,
                "message": "Map file not found in Rspamd. It may not be loaded yet.",
            }
        
        content = await mailcow_api.get_rspamd_map_content(map_id)
        
        # Count non-empty, non-comment lines
        lines = [l.strip() for l in content.split('\n') if l.strip() and not l.strip().startswith('#')]
        
        return {
            "filename": filename,
            "content": content,
            "entry_count": len(lines),
            "metadata": _MAP_METADATA[filename],
        }
        
    except MailcowAPIError as e:
        logger.error(f"Failed to read map {filename}: {e}")
        raise internal_error(e, status_code=502)


@router.put("/rspamd/maps/{filename}")
async def update_map_content(filename: str, body: MapContentRequest):
    """
    Update the content of a specific Rspamd map file.
    
    Validates content (including regex syntax), then writes via mailcow API.
    Requires MAILCOW_API_KEY_RW.
    """
    if filename not in _MAP_METADATA:
        raise HTTPException(status_code=404, detail=f"Unknown map file: {filename}")
    
    if not mailcow_api.has_rw_key:
        raise HTTPException(
            status_code=403,
            detail="Read-Write API key (MAILCOW_API_KEY_RW) is not configured. Cannot save map changes."
        )
    
    # Bare addresses are anchored automatically - in a regexp map they match
    # as substrings, and operators are not expected to fix that by hand
    from .suppressions import migrate_manual_map_line
    raw_lines = body.content.split('\n')
    normalized_lines = [migrate_manual_map_line(l) for l in raw_lines]
    normalized_count = sum(1 for a, b in zip(raw_lines, normalized_lines) if a != b)
    content_to_save = '\n'.join(normalized_lines)

    # Validate the content that will actually be saved - only real errors
    # block the save
    findings = validate_map_content(content_to_save)
    errors = [f for f in findings if f.get('severity', 'error') == 'error']
    warnings = [f for f in findings if f.get('severity') == 'warning']
    if errors:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Map content contains invalid entries",
                "validation_errors": errors,
            }
        )

    try:
        result = await mailcow_api.edit_rspamd_map(filename, content_to_save)

        # Count entries for response
        lines = [l.strip() for l in content_to_save.split('\n') if l.strip() and not l.strip().startswith('#')]

        return {
            "success": True,
            "filename": filename,
            "entry_count": len(lines),
            "normalized_entries": normalized_count,
            "content": content_to_save,
            "warnings": warnings,
            "api_response": result,
        }
        
    except MailcowAPIError as e:
        logger.error(f"Failed to update map {filename}: {e}")
        raise internal_error(e, status_code=502)


@router.post("/rspamd/validate")
def validate_map(body: MapValidationRequest):
    """
    Validate map content without saving.
    Returns validation errors if any regex patterns are invalid.
    """
    findings = validate_map_content(body.content)
    errors = [f for f in findings if f.get('severity', 'error') == 'error']
    warnings = [f for f in findings if f.get('severity') == 'warning']

    # Count entries
    lines = [l.strip() for l in body.content.split('\n') if l.strip() and not l.strip().startswith('#')]

    return {
        "valid": len(errors) == 0,
        "entry_count": len(lines),
        "errors": errors,
        "warnings": warnings,
    }
