"""
Shared DMARC Caching Service
Used to share cache state between API router and background services
"""
import logging
import json
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Any
from sqlalchemy.orm import Session
from ..models import SystemSetting

logger = logging.getLogger(__name__)

# In-memory cache for DMARC stats
_dmarc_cache = {}
_dmarc_cache_ttl_seconds = 300  # 5 minutes cache TTL

# Global signal tracking
_cache_valid_since = datetime.now(timezone.utc)
_last_db_check = datetime.min.replace(tzinfo=timezone.utc)
_db_check_interval_seconds = 5


def get_dmarc_cache_key(prefix: str, **params) -> str:
    """Generate a cache key from parameters"""
    param_str = json.dumps(params, sort_keys=True, default=str)
    hash_val = hashlib.md5(param_str.encode()).hexdigest()[:16]
    return f"dmarc:{prefix}:{hash_val}"


def get_dmarc_cached(key: str, db: Session) -> Optional[Any]:
    """Get cached value if not expired and not invalidated globally"""
    global _dmarc_cache, _last_db_check, _cache_valid_since

    now = datetime.now(timezone.utc)
    
    # Periodically check DB for invalidation signal
    if (now - _last_db_check).total_seconds() > _db_check_interval_seconds:
        _last_db_check = now
        try:
            setting = db.query(SystemSetting).filter(SystemSetting.key == "dmarc_last_update").first()
            if setting and setting.updated_at:
                # Ensure timezone awareness
                db_updated_at = setting.updated_at
                if db_updated_at.tzinfo is None:
                    db_updated_at = db_updated_at.replace(tzinfo=timezone.utc)
                
                # If DB signal is newer than our local validity, clear cache
                if db_updated_at > _cache_valid_since:
                    logger.info("DMARC cache invalidated by another process")
                    _dmarc_cache = {}
                    _cache_valid_since = now
                    return None
        except Exception as e:
            logger.error(f"Error checking cache signal: {e}")

    if key in _dmarc_cache:
        cached_data, cached_time = _dmarc_cache[key]
        if now - cached_time < timedelta(seconds=_dmarc_cache_ttl_seconds):
            logger.debug(f"DMARC cache hit for key: {key}")
            return cached_data
        else:
            # Cache expired, remove it
            del _dmarc_cache[key]
    return None


def set_dmarc_cache(key: str, data: Any) -> None:
    """Set cached value with current timestamp"""
    _dmarc_cache[key] = (data, datetime.now(timezone.utc))
    logger.debug(f"DMARC cache set for key: {key}")


def clear_dmarc_cache(db: Session) -> None:
    """Clear all DMARC cache locally and signal other processes via DB"""
    global _dmarc_cache, _cache_valid_since
    
    # local clear
    _dmarc_cache = {}
    _cache_valid_since = datetime.now(timezone.utc)
    
    try:
        # DB signal
        setting = db.query(SystemSetting).filter(SystemSetting.key == "dmarc_last_update").first()
        if not setting:
            setting = SystemSetting(key="dmarc_last_update", value="signal")
            db.add(setting)
        
        setting.updated_at = datetime.utcnow()
        db.commit()
        logger.info("DMARC cache cleared and signaled to DB")
    except Exception as e:
        logger.error(f"Error clearing cache signal: {e}")
        db.rollback()
