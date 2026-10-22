"""The dashboard figures that have a trend, and their hourly samples.

One function per figure, used by the card's own endpoint and by the hourly
collector, so a trend's last point is what the card showed at that moment.
Each returns {value, of, valid, as_of, ...}: valid is False when its source
did not answer (mailcow unreachable, Fail2ban unknown, no fresh blocklist
check, the database failing), and then no sample is written: the trend shows
a gap, never a made-up zero.

The samples (metric_snapshots, one per figure and hour, kept KEEP_DAYS days)
of a feature that is off are neither written nor served, and are deleted
when it is switched off (feature_data.purge_feature). A switch and a write
are serialized by one transaction-level advisory lock: the purge takes it,
bumps that feature's epoch and deletes; the collector notes the epochs when
its run starts and, under the lock, writes a feature's samples only if the
feature is on and its epoch is unchanged. So nothing lands after a delete,
and an off-and-on during a run drops that run's samples.
"""
import asyncio
import logging
import re
import threading
from datetime import datetime, timedelta
from typing import Dict, Optional

from sqlalchemy import func, text
from sqlalchemy.orm import Session

from ..config import settings

logger = logging.getLogger(__name__)

# The trends, by name, and the feature each belongs to (None: always on)
METRICS: Dict[str, Optional[str]] = {
    'storage_used': None,
    'linking_rate': None,
    'blocklists_listed': 'blacklist',
    'security_review': 'netfilter',
    'security_banned': 'netfilter',
}
KEEP_DAYS = 90
# One source may take this long before its sample of the hour is left out
SOURCE_TIMEOUT = 30
_LOCK_KEY = 0x4D4C5602

_epochs: Dict[str, int] = {}
_epochs_lock = threading.Lock()


def feature_epoch(feature: str) -> int:
    with _epochs_lock:
        return _epochs.get(feature, 0)


def bump_feature_epoch(feature: str) -> None:
    with _epochs_lock:
        _epochs[feature] = _epochs.get(feature, 0) + 1


def note_feature_switches(off_before, off_after) -> None:
    """A save that switches a feature with a trend (on or off) moves its epoch under
    the lock, so a sample read before the switch is not written after it, also
    when the feature goes off and on again before its data is deleted."""
    from ..database import get_db_context
    changed = {f for f in set(METRICS.values()) if f and ((f in off_before) != (f in off_after))}
    if not changed:
        return
    with get_db_context() as db:
        db.execute(text("SET LOCAL lock_timeout = '10s'"))
        lock_metric_rows(db)
        for feature in changed:
            bump_feature_epoch(feature)
        db.commit()


def features_off() -> set:
    return {f for f in set(METRICS.values()) if f and not settings.is_feature_enabled(f)}


def lock_metric_rows(db: Session) -> None:
    """Held to the end of the transaction: a purge and a collector's write never interleave."""
    db.execute(text('SELECT pg_advisory_xact_lock(:key)'), {'key': _LOCK_KEY})


def metric_on(name: str) -> bool:
    feature = METRICS.get(name)
    return feature is None or settings.is_feature_enabled(feature)


def _now() -> datetime:
    return datetime.utcnow()


_PERCENT = re.compile(r'^\s*(\d+(?:\.\d+)?)\s*%?\s*$')


def parse_percent(value) -> Optional[float]:
    match = _PERCENT.match(str(value)) if value is not None else None
    return float(match.group(1)) if match else None


async def storage_figure() -> dict:
    """Mail storage: mailcow's used percent of the vmail volume, with its words."""
    from ..mailcow_api import mailcow_api
    try:
        vmail = await mailcow_api.get_status_vmail()
    except Exception as e:
        logger.info(f"Storage figure: mailcow did not answer ({e})")
        vmail = None
    vmail = vmail or {}
    percent = parse_percent(vmail.get('used_percent'))
    return {
        'value': percent, 'of': 100.0, 'valid': percent is not None, 'as_of': _now(),
        'disk': vmail.get('disk', 'unknown'), 'used': vmail.get('used', '0'), 'total': vmail.get('total', '0'),
        'used_percent': vmail.get('used_percent', '0%'),
    }


def linking_figure(db: Session) -> dict:
    """Message linking: the share of linked messages that are complete (not expired)."""
    from ..models import MessageCorrelation
    try:
        total = db.query(func.count(MessageCorrelation.id)).scalar() or 0
        complete = db.query(func.count(MessageCorrelation.id)).filter(
            MessageCorrelation.is_complete == True,  # noqa: E712
            MessageCorrelation.final_status != 'expired',
        ).scalar() or 0
        incomplete = db.query(func.count(MessageCorrelation.id)).filter(
            MessageCorrelation.is_complete == False  # noqa: E712
        ).scalar() or 0
        expired = db.query(func.count(MessageCorrelation.id)).filter(
            MessageCorrelation.final_status == 'expired'
        ).scalar() or 0
    except Exception as e:
        logger.warning(f"Linking figure: {e}")
        return {'value': None, 'of': 100.0, 'valid': False, 'as_of': _now(), 'total': 0, 'complete': 0, 'incomplete': 0, 'expired': 0}
    rate = round(complete / total * 100, 2) if total > 0 else 0
    return {'value': rate, 'of': 100.0, 'valid': True, 'as_of': _now(),
            'total': total, 'complete': complete, 'incomplete': incomplete, 'expired': expired}


def blocklists_figure(summary: dict) -> dict:
    """Blocklists: the monitored addresses listed, of all of them (as the card counts),
    known only with a fresh check that is not an error."""
    hosts = summary.get('hosts') or []
    listed = sum(1 for h in hosts if h.get('status') == 'listed')
    valid = bool(summary.get('has_data')) and summary.get('status') in ('listed', 'clean')
    return {'value': float(listed) if valid else None, 'of': float(len(hosts)), 'valid': valid, 'as_of': _now()}


def security_figures(addresses, fail2ban_known: bool) -> dict:
    """To review and Banned now, as the dashboard counts them; known only when
    Fail2ban answered (without it bans and lists are unknown)."""
    review = sum(1 for a in addresses if a.get('list') == 'review')
    banned = sum(1 for a in addresses if a.get('list') == 'banned')
    now = _now()
    return {
        'security_review': {'value': float(review) if fail2ban_known else None, 'of': None, 'valid': fail2ban_known, 'as_of': now},
        'security_banned': {'value': float(banned) if fail2ban_known else None, 'of': None, 'valid': fail2ban_known, 'as_of': now},
    }


def _in_session(fn):
    """In a session of its own whose statements stop at the source's time budget
    (a wait_for on a thread does not stop the thread's query)."""
    from ..database import get_db_context
    with get_db_context() as db:
        db.execute(text(f"SET LOCAL statement_timeout = '{SOURCE_TIMEOUT - 5}s'"))
        return fn(db)


async def collect_figures() -> Dict[str, dict]:
    """Every figure that is on and whose source answered, each source in its own time budget."""
    points: Dict[str, dict] = {}

    async def bounded(work, label):
        try:
            return await asyncio.wait_for(work, SOURCE_TIMEOUT)
        except Exception as e:
            logger.info(f"Trend sample of {label} left out this hour: {e or type(e).__name__}")
            return None

    storage = await bounded(storage_figure(), 'mail storage')
    if storage and storage['valid']:
        points['storage_used'] = storage
    linking = await bounded(asyncio.to_thread(_in_session, linking_figure), 'message linking')
    if linking and linking['valid']:
        points['linking_rate'] = linking
    if metric_on('blocklists_listed'):
        from ..routers.blacklist import blacklist_summary_data
        summary = await bounded(asyncio.to_thread(blacklist_summary_data), 'blocklists')
        figure = blocklists_figure(summary) if summary else None
        if figure and figure['valid']:
            points['blocklists_listed'] = figure
    if metric_on('security_review'):
        from ..mailcow_api import mailcow_api
        from . import security_addresses
        f2b = await bounded(mailcow_api.get_fail2ban(), 'Fail2ban')
        if security_addresses.fail2ban_answered(f2b):
            addresses = await bounded(asyncio.to_thread(_in_session, lambda db: security_addresses.collect(db, f2b, None, 24)), 'security addresses')
            if addresses is not None:
                points.update(security_figures(addresses, True))
    return points


def slot_of(moment: datetime) -> datetime:
    return moment.replace(minute=0, second=0, microsecond=0)


def write_points(points: Dict[str, dict], epochs: Dict[str, int], slot: datetime) -> int:
    """Write the hour's samples under the lock (a feature switched off, or off and on,
    since the run began writes nothing), and drop samples older than KEEP_DAYS."""
    from sqlalchemy.dialects.postgresql import insert
    from ..database import get_db_context
    from ..models import MetricSnapshot
    written = 0
    with get_db_context() as db:
        try:
            # A purge holding the lock longer than this: the hour is a gap, the job is no failure
            db.execute(text("SET LOCAL lock_timeout = '10s'"))
            db.execute(text("SET LOCAL statement_timeout = '30s'"))
            lock_metric_rows(db)
        except Exception as e:
            db.rollback()
            logger.warning(f"Trend samples left out this hour: the samples are busy ({e})")
            return 0
        for name, figure in points.items():
            feature = METRICS.get(name)
            if feature and (not settings.is_feature_enabled(feature) or feature_epoch(feature) != epochs.get(feature, 0)):
                continue
            row = {'name': name, 'slot': slot, 'value': figure['value'], 'of': figure.get('of'), 'as_of': figure['as_of']}
            db.execute(insert(MetricSnapshot).values(**row).on_conflict_do_update(
                index_elements=['name', 'slot'], set_={'value': row['value'], 'of': row['of'], 'as_of': row['as_of']}))
            written += 1
        db.query(MetricSnapshot).filter(MetricSnapshot.slot < _now() - timedelta(days=KEEP_DAYS)).delete(synchronize_session=False)
        db.commit()
    return written


async def run_trend_samples() -> int:
    """One hourly run: the epochs as it starts, the figures, then the write."""
    epochs = {f: feature_epoch(f) for f in set(METRICS.values()) if f}
    slot = slot_of(_now())
    points = await collect_figures()
    return await asyncio.to_thread(write_points, points, epochs, slot)


def purge_feature_metrics(db: Session, feature: str) -> int:
    """For feature_data.purge_feature, inside its transaction: the feature's samples go."""
    from ..models import MetricSnapshot
    names = [name for name, f in METRICS.items() if f == feature]
    if not names:
        return 0
    lock_metric_rows(db)
    bump_feature_epoch(feature)
    return db.query(MetricSnapshot).filter(MetricSnapshot.name.in_(names)).delete(synchronize_session=False)
