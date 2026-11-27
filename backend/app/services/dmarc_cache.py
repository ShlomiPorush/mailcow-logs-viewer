import logging
import json
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Any
from sqlalchemy.orm import Session
from ..app_time import app_tz
from ..models import SystemSetting

logger = logging.getLogger(__name__)

_dmarc_cache = {}
_dmarc_cache_ttl_seconds = 300

_cache_valid_since = datetime.now(timezone.utc)
_last_db_check = datetime.min.replace(tzinfo=timezone.utc)
_db_check_interval_seconds = 5


def get_dmarc_cache_key(prefix: str, **params) -> str:
    param_str = json.dumps({**params, "_tz": app_tz().key}, sort_keys=True, default=str)
    hash_val = hashlib.md5(param_str.encode()).hexdigest()[:16]
    return f"dmarc:{prefix}:{hash_val}"


def get_dmarc_cached(key: str, db: Session) -> Optional[Any]:
    global _dmarc_cache, _last_db_check, _cache_valid_since

    now = datetime.now(timezone.utc)
    
    if (now - _last_db_check).total_seconds() > _db_check_interval_seconds:
        _last_db_check = now
        try:
            setting = db.query(SystemSetting).filter(SystemSetting.key == "dmarc_last_update").first()
            if setting and setting.updated_at:
                db_updated_at = setting.updated_at
                if db_updated_at.tzinfo is None:
                    db_updated_at = db_updated_at.replace(tzinfo=timezone.utc)
                
                if db_updated_at > _cache_valid_since:
                    logger.info("DMARC cache invalidated by another process")
                    _dmarc_cache = {}
                    _cache_valid_since = now
                    return None
        except Exception as e:
            logger.error(f"Error checking cache signal: {e}")

    cached = _dmarc_cache.get(key)
    if cached is not None:
        cached_data, cached_time = cached
        if now - cached_time < timedelta(seconds=_dmarc_cache_ttl_seconds):
            logger.debug(f"DMARC cache hit for key: {key}")
            return cached_data
        else:
            _dmarc_cache.pop(key, None)
    return None


def set_dmarc_cache(key: str, data: Any) -> None:
    _dmarc_cache[key] = (data, datetime.now(timezone.utc))
    logger.debug(f"DMARC cache set for key: {key}")


def clear_dmarc_cache(db: Session) -> None:
    global _dmarc_cache, _cache_valid_since
    
    _dmarc_cache = {}
    _cache_valid_since = datetime.now(timezone.utc)
    
    try:
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
