"""The data a feature keeps, and its deletion while the feature is off.

A feature that is off keeps nothing in the app, whichever way it was turned
off (the Settings switch or DISABLED_FEATURES). Turned on again, it reads
back what the server still has: Spam Filter loads the blocks this app wrote
to Rspamd (see routers/suppressions.import_managed_worker), the other
features fetch or check again on their own.

The deletion runs at startup, after every settings save and on a sweep every
few minutes, so a row written by a job or an API call that was already under
way when the feature went off goes on the next pass.
"""
import logging
import re
from typing import Dict, List, Optional

from sqlalchemy import and_, or_, text
from sqlalchemy.orm import Session

from ..config import settings

logger = logging.getLogger(__name__)

# Feature -> its tables. The order matters only for the counts reported.
FEATURE_TABLES: Dict[str, List[str]] = {
    'netfilter': ['netfilter_logs'],
    'domains': ['domain_dns_checks'],
    'dmarc': ['dmarc_records', 'tls_report_policies', 'dmarc_reports', 'dmarc_syncs', 'tls_reports'],
    'mailbox-stats': ['alias_statistics', 'mailbox_statistics'],
    'logs': ['raw_service_logs'],
    'blacklist': ['blacklist_checks', 'monitored_hosts'],
    # The block details go with their blocks (the foreign key cascades too); listed first to count them
    'spam-filter': ['suppression_events', 'spam_suppressions'],
    'quarantine': ['quarantine_rule_logs', 'quarantine_rules'],
    'devices': ['eas_devices'],
}

# Feature -> keys in system_settings that belong to it. A key ending in '%'
# is a prefix.
FEATURE_KEYS: Dict[str, List[str]] = {
    'netfilter': ['protection.%'],
    'blacklist': ['ignore.blocklists'],
    'domains': ['dns_last_full_check'],
}

# Spam Filter turned on again loads the blocks this app wrote to Rspamd while
# this key is set (routers/suppressions.import_managed_worker)
SPAM_IMPORT_PENDING_KEY = 'spam_filter.import_pending'

_TABLE_NAME_RE = re.compile(r'^[a-z_][a-z0-9_]*$')


def _set_key(db: Session, key: str, value: str) -> None:
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from datetime import datetime
    from ..models import SystemSetting
    db.execute(pg_insert(SystemSetting).values(key=key, value=value, updated_at=datetime.utcnow())
               .on_conflict_do_update(index_elements=['key'], set_={'value': value, 'updated_at': datetime.utcnow()}))


def security_bans_to_release(db: Session) -> int:
    """Hits protection_rules.release_temporary_bans still has to handle: bans
    this app wrote to Fail2ban that would have ended on their own (nothing
    lifts them once their hits are gone), and bans still pending (an enforce
    run may be writing one right now). Until there are none, the ban history
    stays."""
    from ..models import ProtectionHit
    return db.query(ProtectionHit).filter(or_(
        ProtectionHit.status == 'pending',
        and_(ProtectionHit.status == 'banned', ProtectionHit.owned == True,  # noqa: E712
             ProtectionHit.expires_at.isnot(None)))).count()


def purge_feature(db: Session, feature: str) -> dict:
    """Delete everything a feature that is off keeps, in one transaction.

    Raises on failure after rolling back; the caller decides whether that
    stops it. Returns the rows deleted per table.
    """
    from ..models import ProtectionHit, SystemSetting
    deleted: Dict[str, int] = {}
    try:
        for table_name in FEATURE_TABLES[feature]:
            if not _TABLE_NAME_RE.match(table_name):
                raise ValueError(f"Invalid table name: {table_name}")
            if table_name == 'raw_service_logs':
                # Other pages read some services from this table; only the rows
                # nothing collects any more go
                from ..raw_logs_worker import delete_uncollected_raw_logs
                deleted[table_name] = delete_uncollected_raw_logs(db)
                continue
            if table_name == 'mailbox_statistics' and settings.is_feature_enabled('rate-limits'):
                # Rate Limits reads each mailbox's configured limit from it
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
            # The ban history goes once no temporary ban of this app is left in Fail2ban
            removed = db.query(ProtectionHit).delete(synchronize_session=False)
            if removed:
                deleted['protection_hits'] = removed
        if feature == 'spam-filter':
            _set_key(db, SPAM_IMPORT_PENDING_KEY, '1')
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
    """Once, on the first start of a version that loads Spam Filter's blocks
    back: an empty list with Spam Filter on loads them too. An earlier
    version could leave the blocks in Rspamd with the list deleted (turned off
    with "Keep blocks"), and nothing marked them to come back."""
    from ..models import SpamSuppression, SystemSetting
    if db.query(SystemSetting.key).filter(SystemSetting.key == SPAM_IMPORT_BOOTSTRAP_KEY).first() is not None:
        return
    if settings.is_feature_enabled('spam-filter') and db.query(SpamSuppression.id).first() is None:
        _set_key(db, SPAM_IMPORT_PENDING_KEY, '1')
    _set_key(db, SPAM_IMPORT_BOOTSTRAP_KEY, '1')
    db.commit()


def purge_disabled_features() -> Dict[str, Optional[str]]:
    """Purge every feature that is off, each in its own session, so one that
    fails does not keep the others. Returns {feature: error or None}."""
    from ..database import get_db_context
    from .rspamd_map_lock import map_write_lock
    results: Dict[str, Optional[str]] = {}
    try:
        with get_db_context() as db:
            bootstrap_spam_import(db)
    except Exception as e:
        logger.warning(f"[FEATURES] Could not check whether Spam Filter's blocks need loading: {e}")
    for feature in FEATURE_TABLES:
        if settings.is_feature_enabled(feature):
            continue
        try:
            with get_db_context() as db:
                if feature == 'spam-filter':
                    # A sync or an import of the list waits, or is waited for
                    with map_write_lock():
                        # Turned on again while this waited for the lock: its list stays
                        if settings.is_feature_enabled(feature):
                            continue
                        deleted = purge_feature(db, feature)
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
