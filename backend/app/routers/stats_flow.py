import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import Integer, DateTime, and_, column, func, values
from sqlalchemy.orm import Session

from ..app_time import app_tz
from ..config import settings
from ..database import get_db
from ..models import MessageCorrelation, NetfilterLog, RspamdLog
from .messages import _filtered_messages_query, message_group_key
from ..api_models import Invalid, documented
from ..api_models import stats as m

logger = logging.getLogger(__name__)

router = APIRouter()

BUCKETS = {"hour": timedelta(hours=1), "6h": timedelta(hours=6), "day": timedelta(days=1)}
PERIODS = {"24h": ("hour", 24), "7d": ("6h", 28), "30d": ("day", 30)}
MAX_SPAN = timedelta(days=62)
STEP = timedelta(minutes=15)
BLOCKED = ("bounced", "rejected", "spam")


def _slot(moment_utc: datetime, bucket: str, zone):
    local = moment_utc.astimezone(zone)
    if bucket == "hour":
        return (local.date(), local.hour, local.fold)
    if bucket == "6h":
        return (local.date(), local.hour // 6)
    return (local.date(),)


def bucket_edges(start: datetime, end: datetime, bucket: str, zone) -> List[datetime]:
    floor = start.replace(minute=start.minute - start.minute % 15, second=0, microsecond=0)
    t = floor
    key = _slot(t, bucket, zone)
    while _slot(t - STEP, bucket, zone) == key:
        t -= STEP
    edges = [t]
    t += STEP
    while t < end:
        k = _slot(t, bucket, zone)
        if k != key:
            edges.append(t)
            key = k
        t += STEP
    return edges


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).replace(tzinfo=None).isoformat(timespec="microseconds") + "Z"


def _naive(moment: datetime) -> datetime:
    return moment.astimezone(timezone.utc).replace(tzinfo=None)


def _parse(value: str) -> datetime:
    moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _last_bars(end: datetime, bucket: str, count: int, zone) -> List[datetime]:
    span = BUCKETS[bucket] * (count + 2) + timedelta(hours=26)
    edges = [e for e in bucket_edges(end - span, end, bucket, zone) if e < end]
    return edges[-count:]


def flow(db: Session, start: datetime, end: datetime, bucket: str, edges: List[datetime], now: datetime) -> dict:
    zone = app_tz()
    bars = [(i, _naive(s), _naive(edges[i + 1] if i + 1 < len(edges) else end)) for i, s in enumerate(edges)]
    bk = values(column("idx", Integer), column("s", DateTime), column("e", DateTime), name="bk").data(bars)
    lo, hi = _naive(start), _naive(end)
    out = {i: {"clean": 0, "spam": 0, "messages": 0, "deliveries": 0, "blocked": 0, "deferred": 0, "auth_failures": 0} for i, _, _ in bars}

    when = MessageCorrelation.first_seen
    legs = _filtered_messages_query(db).filter(when >= lo, when < hi).with_entities(
        MessageCorrelation.final_status.label("status"),
        when.label("t"),
        func.row_number().over(partition_by=message_group_key(), order_by=(when.asc(), MessageCorrelation.id.asc())).label("rk"),
    ).subquery()
    for idx, messages, deliveries, blocked, deferred in db.query(
        bk.c.idx,
        func.count().filter(legs.c.rk == 1),
        func.count(),
        func.count().filter(legs.c.status.in_(BLOCKED)),
        func.count().filter(legs.c.status == "deferred"),
    ).select_from(bk).join(legs, and_(legs.c.t >= bk.c.s, legs.c.t < bk.c.e)).group_by(bk.c.idx):
        out[idx].update(messages=messages, deliveries=deliveries, blocked=blocked, deferred=deferred)

    for idx, total, spam in db.query(
        bk.c.idx, func.count(RspamdLog.id), func.count().filter(RspamdLog.is_spam.is_(True)),
    ).select_from(bk).join(RspamdLog, and_(RspamdLog.time >= bk.c.s, RspamdLog.time < bk.c.e)).group_by(bk.c.idx):
        out[idx].update(clean=total - spam, spam=spam)
    for idx, failures in db.query(
        bk.c.idx, func.count(NetfilterLog.id),
    ).select_from(bk).join(NetfilterLog, and_(NetfilterLog.time >= bk.c.s, NetfilterLog.time < bk.c.e,
                                              NetfilterLog.rule_id == 3)).group_by(bk.c.idx):
        out[idx]["auth_failures"] = failures

    result = []
    for i, s, e in bars:
        e_aware = e.replace(tzinfo=timezone.utc)
        result.append({
            "start": _iso(s.replace(tzinfo=timezone.utc)),
            "end": _iso(e_aware),
            "end_inclusive": _iso(e_aware - timedelta(microseconds=1)),
            "partial": e_aware >= now,
            **out[i],
        })
    totals = {key: sum(b[key] for b in result) for key in ("clean", "spam", "messages", "deliveries", "blocked", "deferred", "auth_failures")}
    kept_from = now - timedelta(days=settings.retention_days)
    return {
        "from": _iso(start),
        "to": _iso(end),
        "to_inclusive": _iso(end - timedelta(microseconds=1)),
        "as_of": _iso(now),
        "bucket": bucket,
        "zone": getattr(zone, "key", "UTC"),
        "older_may_be_gone": start < kept_from,
        "kept_from": _iso(kept_from),
        "buckets": result,
        "totals": totals,
    }


@router.get("/stats/flow", responses=documented(m.FlowResponse, errors={422: Invalid, 500: None}))
def get_flow(
    period: Optional[str] = Query(None, pattern="^(24h|7d|30d)$", description="A dashboard period: its bars up to now"),
    previous: bool = Query(False, description="With period: the same number of bars right before it"),
    start: Optional[str] = Query(None, alias="from", max_length=40, description="A zoomed range: its start (an instant)"),
    end: Optional[str] = Query(None, alias="to", max_length=40, description="A zoomed range: its end (an instant)"),
    bucket: Optional[str] = Query(None, pattern="^(hour|6h|day)$", description="With from and to: the bar length"),
    db: Session = Depends(get_db),
):
    zone = app_tz()
    now = datetime.now(timezone.utc)
    if period:
        kind, count = PERIODS[period]
        bars = _last_bars(now, kind, count, zone)
        if previous:
            to = bars[0]
            bars = _last_bars(to, kind, count, zone)
            return flow(db, bars[0], to, kind, bars, now)
        return flow(db, bars[0], now, kind, bars, now)
    if not (start and end and bucket):
        raise HTTPException(status_code=422, detail="Give a period, or from, to and bucket")
    try:
        lo, hi = _parse(start), _parse(end)
    except ValueError:
        raise HTTPException(status_code=422, detail="from and to must be instants")
    hi = min(hi, now)
    if lo >= hi or hi - lo > MAX_SPAN:
        raise HTTPException(status_code=422, detail="The range must be after from and at most 62 days long")
    edges = bucket_edges(lo, hi + BUCKETS[bucket] + timedelta(hours=2), bucket, zone)
    nearest = lambda moment, among: min(among, key=lambda e: abs(e - moment))
    first = nearest(lo, [e for e in edges if e < now])
    to = now if hi >= now else min(nearest(hi, edges), now)
    if to <= first:
        middle = lo + (hi - lo) / 2
        first = max(e for e in edges if e <= middle and e < now)
        to = min(next(e for e in edges if e > first), now)
    bars = [e for e in edges if first <= e < to]
    return flow(db, first, to, bucket, bars, now)
