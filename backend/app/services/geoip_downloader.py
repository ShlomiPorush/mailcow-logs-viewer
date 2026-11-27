import logging
import os
import tarfile
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, quote_plus
import requests

logger = logging.getLogger(__name__)

from ..config import settings
from ..utils import format_datetime_for_api

def get_maxmind_license_key() -> str:
    return settings.maxmind_license_key or ''

def get_maxmind_account_id() -> str:
    return settings.maxmind_account_id or ''

GEOIP_DB_DIR = os.getenv('GEOIP_DB_DIR', '/app/data')

GEOIP_CITY_DB_PATH = os.path.join(GEOIP_DB_DIR, 'GeoLite2-City.mmdb')
GEOIP_ASN_DB_PATH = os.path.join(GEOIP_DB_DIR, 'GeoLite2-ASN.mmdb')

MAXMIND_DOWNLOAD_URL = "https://download.maxmind.com/geoip/databases/{edition_id}/download"
MAXMIND_LEGACY_DOWNLOAD_URL = "https://download.maxmind.com/app/geoip_download"

UPDATE_CHECK_DAYS = 7

DATABASES = {
    'City': {
        'edition_id': 'GeoLite2-City',
        'path': GEOIP_CITY_DB_PATH,
        'description': 'Country + City + Coordinates'
    },
    'ASN': {
        'edition_id': 'GeoLite2-ASN',
        'path': GEOIP_ASN_DB_PATH,
        'description': 'ASN + ISP information'
    }
}


def is_license_configured() -> bool:
    license_key = get_maxmind_license_key()
    account_id = get_maxmind_account_id()
    return bool(license_key and account_id)


def get_db_age_days(db_path: str) -> int:
    path = Path(db_path)
    
    if not path.exists():
        return -1
    
    mtime = path.stat().st_mtime
    modified_date = datetime.fromtimestamp(mtime, timezone.utc)
    age_days = (datetime.now(timezone.utc) - modified_date).days
    
    return age_days


def should_update_database(db_name: str) -> bool:
    db_path = DATABASES[db_name]['path']
    age_days = get_db_age_days(db_path)
    
    if age_days == -1:
        logger.info(f"{db_name} database not found, download required")
        return True
    
    if age_days >= UPDATE_CHECK_DAYS:
        logger.info(f"{db_name} database is {age_days} days old, update required")
        return True
    
    logger.info(f"{db_name} database is {age_days} days old, no update needed")
    return False


def _redact(text: str, secret: str) -> str:
    if not secret:
        return text
    for form in {secret, quote(secret, safe=''), quote_plus(secret)}:
        text = text.replace(form, '***')
    return text


def download_single_database(db_name: str) -> bool:
    db_info = DATABASES[db_name]
    license_key = ''
    
    try:
        logger.info(f"Downloading GeoLite2-{db_name} database from MaxMind...")
        logger.info(f"  ({db_info['description']})")
        
        license_key = get_maxmind_license_key()
        account_id = get_maxmind_account_id()
        
        if not license_key or not account_id:
            logger.error("MaxMind license key or account ID not configured")
            return False
        
        response = requests.get(
            MAXMIND_DOWNLOAD_URL.format(edition_id=db_info['edition_id']),
            params={'suffix': 'tar.gz'},
            auth=(account_id, license_key),
            stream=True,
            timeout=300,
        )
        
        if response.status_code == 401:
            response.close()
            response = requests.get(
                MAXMIND_LEGACY_DOWNLOAD_URL,
                params={'edition_id': db_info['edition_id'],
                        'license_key': license_key,
                        'suffix': 'tar.gz'},
                stream=True,
                timeout=300,
            )
            if response.status_code == 200:
                logger.warning("MaxMind rejected the account ID and license key pair; downloaded "
                               "with the license key alone. Check the MaxMind account ID.")
        
        if response.status_code == 401:
            logger.error("MaxMind license key is invalid or expired")
            return False
        
        if response.status_code != 200:
            logger.error(f"Failed to download {db_name} database: HTTP {response.status_code}")
            return False
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz') as tmp_file:
            tmp_path = tmp_file.name
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            for chunk in response.iter_content(chunk_size=8192):
                tmp_file.write(chunk)
                downloaded += len(chunk)
                
                if total_size > 0 and downloaded % (5 * 1024 * 1024) == 0:
                    progress = (downloaded / total_size) * 100
                    logger.info(f"  Download progress: {progress:.1f}%")
        
        size_mb = downloaded / (1024 * 1024)
        logger.info(f"  Downloaded {size_mb:.1f}MB")
        
        logger.info(f"  Extracting GeoLite2-{db_name} database...")
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            with tarfile.open(tmp_path, 'r:gz') as tar:
                tar.extractall(tmp_dir, filter='data')
            
            mmdb_files = list(Path(tmp_dir).rglob('*.mmdb'))
            
            if not mmdb_files:
                logger.error(f"No .mmdb file found in downloaded {db_name} archive")
                os.unlink(tmp_path)
                return False
            
            mmdb_file = mmdb_files[0]
            
            os.makedirs(GEOIP_DB_DIR, exist_ok=True)
            
            import shutil
            with tempfile.NamedTemporaryFile(dir=os.path.dirname(db_info['path']), suffix='.new', delete=False) as staged:
                staged_path = staged.name
            shutil.copy2(mmdb_file, staged_path)
            os.replace(staged_path, db_info['path'])
            
            logger.info(f"✓ GeoLite2-{db_name} database installed at {db_info['path']}")
        
        os.unlink(tmp_path)
        
        db_size = Path(db_info['path']).stat().st_size / (1024 * 1024)
        logger.info(f"  Database size: {db_size:.1f}MB")
        
        return True
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error downloading {db_name} database: {_redact(str(e), license_key)}")
        return False
    except Exception as e:
        logger.error(f"Error downloading {db_name} database: {_redact(str(e), license_key)}")
        return False


def download_geoip_databases() -> dict:
    if not is_license_configured():
        logger.warning("MaxMind license key not configured, skipping download")
        return {'City': False, 'ASN': False}
    
    results = {}
    
    for db_name in ['City', 'ASN']:
        if should_update_database(db_name):
            results[db_name] = download_single_database(db_name)
        else:
            logger.info(f"{db_name} database is up to date, skipping download")
            results[db_name] = True
    
    return results


def update_geoip_database_if_needed() -> dict:
    if not is_license_configured():
        logger.info("MaxMind license key not configured, GeoIP features will be disabled")
        return {
            'City': {'available': False, 'updated': False, 'failed': False},
            'ASN': {'available': False, 'updated': False, 'failed': False}
        }
    
    status = {}
    
    for db_name in ['City', 'ASN']:
        db_path = DATABASES[db_name]['path']
        needs_update = should_update_database(db_name)
        
        if not needs_update:
            status[db_name] = {
                'available': True,
                'updated': False,
                'failed': False
            }
            continue
        
        success = download_single_database(db_name)
        
        if success:
            status[db_name] = {
                'available': True,
                'updated': True,
                'failed': False
            }
        else:
            if Path(db_path).exists():
                logger.info(f"Using existing (outdated) {db_name} database")
                status[db_name] = {
                    'available': True,
                    'updated': False,
                    'failed': True
                }
            else:
                logger.error(f"No {db_name} database available")
                status[db_name] = {
                    'available': False,
                    'updated': False,
                    'failed': True
                }
    
    return status


def get_geoip_status() -> dict:
    from .geoip_service import get_geoip_db_valid
    
    status = {
        'configured': is_license_configured(),
        'db_valid': get_geoip_db_valid(),
        'City': {
            'available': False,
            'age_days': -1,
            'size_mb': 0,
            'last_modified': None
        },
        'ASN': {
            'available': False,
            'age_days': -1,
            'size_mb': 0,
            'last_modified': None
        }
    }
    
    for db_name in ['City', 'ASN']:
        db_path = Path(DATABASES[db_name]['path'])
        
        if db_path.exists():
            status[db_name]['available'] = True
            status[db_name]['age_days'] = get_db_age_days(str(db_path))
            status[db_name]['size_mb'] = round(db_path.stat().st_size / (1024 * 1024), 1)
            
            mtime = db_path.stat().st_mtime
            status[db_name]['last_modified'] = format_datetime_for_api(datetime.fromtimestamp(mtime, timezone.utc))
    
    return status