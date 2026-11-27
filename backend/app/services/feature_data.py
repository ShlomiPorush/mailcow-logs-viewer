import logging
import re
from typing import Dict, List, Optional

from sqlalchemy import and_, or_, text
from sqlalchemy.orm import Session

from ..config import settings

logger = logging.getLogger(__name__)

FEATURE_TABLES: Dict[str, List[str]] = {
    'netfilter': ['netfilter_logs'],
    'domains': ['domain_dns_checks'],
    'dmarc': ['dmarc_records', 'tls_report_policies', 'dmarc_reports', 'dmarc_syncs', 'tls_reports'],
    'mailbox-stats': ['alias_statistics', 'mailbox_statistics'],
    'logs': ['raw_service_logs'],
    'blacklist': ['blacklist_checks', 'monitored_hosts'],
    'suppressions': ['suppression_events', 'spam_suppressions'],
    'quarantine': ['quarantine_rule_logs', 'quarantine_rules'],
    'devices': ['eas_devices'],
}

FEATURE_KEYS: Dict[str, List[str]] = {
    'netfilter': ['protection.%'],
    'blacklist': ['ignore.blocklists'],
    'domains': ['dns_last_full_check'],
    'suppressions': ['spam_filter.rspamd_%'],
}

SPAM_IMPORT_PENDING_KEY = 'spam_filter.import_pending'
SPAM_IMPORT_RESTORE = '1'
SPAM_IMPORT_BOOTSTRAP = 'bootstrap'

_TABLE_NAME_RE = re.compile(r'^[a-z_][a-z0-9_]*$')


def _set_key(db: Session, key: str, value: str) -> None:
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from datetime import datetime
    from ..models import SystemSetting
    db.execute(pg_insert(SystemSetting).values(key=key, value=value, updated_at=datetime.utcnow())
               .on_conflict_do_update(index_elements=['key'], set_={'value': value, 'updated_at': datetime.utcnow()}))


def security_bans_to_release(db: Session) -> int:
    from ..models import ProtectionHit
    return db.query(ProtectionHit).filter(or_(
        ProtectionHit.status == 'pending',
        and_(ProtectionHit.status == 'banned', ProtectionHit.owned == True,  # noqa: E712
             ProtectionHit.expires_at.isnot(None)))).count()


def spam_list_kept() -> bool:
    from .bounce_policy import rspamd_sync_on
    return rspamd_sync_on()


def _spam_may_be_in_rspamd(db: Session) -> bool:
    from ..models import SpamSuppression, SystemSetting
    keys = dict(db.query(SystemSetting.key, SystemSetting.value).filter(SystemSetting.key.in_(
        ['spam_filter.rspamd_target', 'spam_filter.rspamd_tombstones', SPAM_IMPORT_PENDING_KEY])).all())
    if keys.get('spam_filter.rspamd_target') or keys.get('spam_filter.rspamd_tombstones', '') not in ('', '{}', '[]'):
        return True
    if keys.get(SPAM_IMPORT_PENDING_KEY) == SPAM_IMPORT_RESTORE:
        return True
    return db.query(SpamSuppression.id).filter(or_(
        and_(SpamSuppression.active == True, SpamSuppression.synced_to_rspamd == True),  # noqa: E712
        and_(SpamSuppression.active == False, SpamSuppression.synced_to_rspamd == False))).first() is not None  # noqa: E712


def purge_feature(db: Session, feature: str, still_off=None) -> dict:
    from ..models import ProtectionHit, SystemSetting
    deleted: Dict[str, int] = {}
    restore = False
    try:
        if feature == 'suppressions':
            from .suppression_rows_lock import lock_suppression_rows
            lock_suppression_rows(db)
            if still_off is not None and not still_off():
                db.rollback()
                return {}
            restore = _spam_may_be_in_rspamd(db)
        from .figures import purge_feature_metrics
        removed_metrics = purge_feature_metrics(db, feature)
        if removed_metrics:
            deleted['metric_snapshots'] = removed_metrics
        for table_name in FEATURE_TABLES[feature]:
            if not _TABLE_NAME_RE.match(table_name):
                raise ValueError(f"Invalid table name: {table_name}")
            if table_name == 'raw_service_logs':
                from ..raw_logs_worker import delete_uncollected_raw_logs
                deleted[table_name] = delete_uncollected_raw_logs(db)
                continue
            if table_name == 'mailbox_statistics' and settings.is_feature_enabled('rate-limits'):
                continue
            # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
            count = db.execute(text(f"SELECT COUNT(*) FROM {table_name}")).scalar() or 0
            if count > 0:
                # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                db.execute(text(f"TRUNCATE TABLE {table_name} CASCADE"))
            deleted[table_name] = count
        for key in FEATURE_KEYS.get(feature, []):
            query = db.query(SystemSetting).filter(
                SystemSetting.key.like(key) if key.endswith('%') else SystemSetting.key == key)
            removed = query.delete(synchronize_session=False)
            if removed:
                deleted[f'system_settings:{key}'] = removed
        if feature == 'netfilter' and not security_bans_to_release(db):
            removed = db.query(ProtectionHit).delete(synchronize_session=False)
            if removed:
                deleted['protection_hits'] = removed
        if feature == 'suppressions':
            _set_key(db, SPAM_IMPORT_PENDING_KEY, SPAM_IMPORT_RESTORE if restore else SPAM_IMPORT_BOOTSTRAP)
        db.commit()
    except Exception:
        db.rollback()
        raise
    if feature == 'dmarc' and any(deleted.values()):
        try:
            from .dmarc_cache import clear_dmarc_cache
            clear_dmarc_cache(db)
        except Exception as e:
            logger.warning(f"[FEATURES] Could not clear the DMARC cache: {e}")
    return deleted


SPAM_IMPORT_BOOTSTRAP_KEY = 'spam_filter.import_bootstrapped'


def bootstrap_spam_import(db: Session) -> None:
    from ..models import SpamSuppression, SystemSetting
    if db.query(SystemSetting.key).filter(SystemSetting.key == SPAM_IMPORT_BOOTSTRAP_KEY).first() is not None:
        return
    if settings.is_feature_enabled('suppressions') and db.query(SpamSuppression.id).first() is None \
            and db.query(SystemSetting.key).filter(SystemSetting.key == SPAM_IMPORT_PENDING_KEY).first() is None:
        _set_key(db, SPAM_IMPORT_PENDING_KEY, SPAM_IMPORT_BOOTSTRAP)
    _set_key(db, SPAM_IMPORT_BOOTSTRAP_KEY, '1')
    db.commit()


def purge_disabled_features() -> Dict[str, Optional[str]]:
    from ..database import get_db_context
    from .rspamd_map_lock import map_write_lock
    results: Dict[str, Optional[str]] = {}
    try:
        with get_db_context() as db:
            bootstrap_spam_import(db)
    except Exception as e:
        logger.warning(f"[FEATURES] Could not check whether the Suppressions feature's blocks need loading: {e}")
    def spam_off():
        return not spam_list_kept()

    for feature in FEATURE_TABLES:
        if not spam_off() if feature == 'suppressions' else settings.is_feature_enabled(feature):
            continue
        try:
            with get_db_context() as db:
                if feature == 'suppressions':
                    with map_write_lock():
                        if not spam_off():
                            continue
                        deleted = purge_feature(db, feature, still_off=spam_off)
                else:
                    deleted = purge_feature(db, feature)
            results[feature] = None
            if any(deleted.values()):
                logger.info(f"[FEATURES] Deleted the data of {feature}, which is off: "
                            + ", ".join(f"{t}={n}" for t, n in deleted.items() if n))
        except Exception as e:
            results[feature] = str(e) or type(e).__name__
            logger.warning(f"[FEATURES] Could not delete the data of {feature}, which is off: {e}")
    return results
