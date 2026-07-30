"""
DMARC insights - turn collected aggregate-report data into actionable advice:

- Policy recommendations: when a domain has a healthy, high-volume DMARC pass
  rate under a lax policy (p=none / p=quarantine), recommend tightening it.
- New-source detection: source IPs that only recently started sending under a
  domain AND are failing DMARC - a possible spoofing / abuse signal.

Read-only, synchronous. Safe to call from a threadpooled endpoint (the routers
that use it are plain `def`).
"""
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func

from ..config import settings
from ..models import DMARCReport, DMARCRecord

logger = logging.getLogger(__name__)

# A DMARC-aligned pass = the evaluated (aligned) DKIM OR SPF result passed.
_PASS = "pass"


def _window_epoch_bounds(days: int):
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    return int(start.timestamp()), int(now.timestamp()), now


def _current_policy(report: DMARCReport) -> str:
    pub = report.policy_published or {}
    return (pub.get("p") or "none").lower()


def compute_domain_insights(db, domain: str) -> dict:
    """Insights for a single domain over the configured window."""
    window_days = settings.dmarc_insights_window_days
    start_epoch, _end_epoch, _now = _window_epoch_bounds(window_days)

    reports = db.query(DMARCReport).filter(
        DMARCReport.domain == domain,
        DMARCReport.end_date >= start_epoch,
    ).all()
    if not reports:
        return {"domain": domain, "has_data": False, "recommendations": [], "new_sources": []}

    report_ids = [r.id for r in reports]
    latest = max(reports, key=lambda r: r.end_date)
    policy = _current_policy(latest)

    # Aggregate volume + aligned pass/fail across all records in the window
    records = db.query(
        DMARCRecord.count,
        DMARCRecord.dkim_result,
        DMARCRecord.spf_result,
    ).filter(DMARCRecord.dmarc_report_id.in_(report_ids)).all()

    total = 0
    passed = 0
    for count, dkim, spf in records:
        c = count or 0
        total += c
        if (dkim or "").lower() == _PASS or (spf or "").lower() == _PASS:
            passed += c

    pass_rate = round((passed / total * 100), 2) if total else 0.0

    recommendations = _policy_recommendations(domain, policy, pass_rate, total)
    new_sources = _detect_new_failing_sources(db, domain, report_ids, window_days)

    return {
        "domain": domain,
        "has_data": True,
        "window_days": window_days,
        "current_policy": policy,
        "total_messages": total,
        "pass_rate": pass_rate,
        "recommendations": recommendations,
        "new_sources": new_sources,
    }


def _policy_recommendations(domain, policy, pass_rate, total):
    recs = []
    threshold = settings.dmarc_insights_pass_threshold
    min_volume = settings.dmarc_insights_min_volume

    next_policy = {"none": "quarantine", "quarantine": "reject"}.get(policy)

    if pass_rate < 90 and total >= min_volume:
        recs.append({
            "type": "low_pass_rate",
            "severity": "warning",
            "message": (
                f"DMARC pass rate for {domain} is {pass_rate}% over {total} messages. "
                "Before tightening the policy, fix SPF/DKIM alignment for your "
                "legitimate senders - tightening now could drop real mail."
            ),
        })
        return recs

    if next_policy is None:
        recs.append({
            "type": "already_strict",
            "severity": "info",
            "message": f"{domain} is already at the strictest policy (p=reject). Nothing to do.",
        })
        return recs

    if total < min_volume:
        recs.append({
            "type": "insufficient_volume",
            "severity": "info",
            "message": (
                f"Only {total} messages reported for {domain} in the last "
                f"{settings.dmarc_insights_window_days} days - collect more data "
                "before changing policy."
            ),
        })
        return recs

    if pass_rate >= threshold:
        recs.append({
            "type": "tighten_policy",
            "severity": "success",
            "message": (
                f"{domain} has a {pass_rate}% DMARC pass rate over {total} messages "
                f"under p={policy}. It looks safe to move to p={next_policy}."
            ),
            "current_policy": policy,
            "recommended_policy": next_policy,
        })
    else:
        recs.append({
            "type": "monitor",
            "severity": "info",
            "message": (
                f"{domain} pass rate is {pass_rate}% (need ≥{threshold}% to recommend "
                f"p={next_policy}). Keep monitoring."
            ),
        })
    return recs


def _detect_new_failing_sources(db, domain, report_ids, window_days):
    """Source IPs seen only in the recent quarter of the window that are failing."""
    recent_days = max(window_days // 4, 3)
    recent_start = int((datetime.now(timezone.utc) - timedelta(days=recent_days)).timestamp())

    # Recent report ids (their coverage ends within the recent sub-window)
    recent_report_ids = [
        r.id for r in db.query(DMARCReport.id, DMARCReport.end_date).filter(
            DMARCReport.domain == domain,
            DMARCReport.end_date >= recent_start,
        ).all()
    ]
    if not recent_report_ids:
        return []
    older_report_ids = [rid for rid in report_ids if rid not in set(recent_report_ids)]

    # IPs that failed DMARC in the recent window
    recent_failing = db.query(
        DMARCRecord.source_ip,
        func.sum(DMARCRecord.count).label("cnt"),
    ).filter(
        DMARCRecord.dmarc_report_id.in_(recent_report_ids),
        func.lower(func.coalesce(DMARCRecord.dkim_result, "")) != _PASS,
        func.lower(func.coalesce(DMARCRecord.spf_result, "")) != _PASS,
    ).group_by(DMARCRecord.source_ip).all()
    if not recent_failing:
        return []

    # IPs known from before the recent window (any result)
    known_ips = set()
    if older_report_ids:
        known_ips = {
            row[0] for row in db.query(DMARCRecord.source_ip).filter(
                DMARCRecord.dmarc_report_id.in_(older_report_ids)
            ).distinct().all()
        }

    new_sources = []
    for source_ip, cnt in recent_failing:
        if source_ip in known_ips:
            continue
        new_sources.append({
            "source_ip": source_ip,
            "failing_messages": int(cnt or 0),
            "first_seen_window_days": recent_days,
        })
    # Most active first, cap to keep the response tidy
    new_sources.sort(key=lambda s: s["failing_messages"], reverse=True)
    return new_sources[:20]


def compute_all_insights(db) -> dict:
    """Insights across every domain that has DMARC data in the window."""
    start_epoch, _end, _now = _window_epoch_bounds(settings.dmarc_insights_window_days)
    domains = [
        row[0] for row in db.query(DMARCReport.domain).filter(
            DMARCReport.end_date >= start_epoch
        ).distinct().all()
    ]

    results = []
    for domain in domains:
        try:
            insight = compute_domain_insights(db, domain)
            if insight.get("has_data"):
                results.append(insight)
        except Exception as e:
            logger.error(f"Failed to compute DMARC insights for {domain}: {e}")

    # Surface actionable domains first (a tighten/low-rate/new-source signal)
    def _priority(i):
        if any(r["type"] == "low_pass_rate" for r in i["recommendations"]):
            return 0
        if i["new_sources"]:
            return 1
        if any(r["type"] == "tighten_policy" for r in i["recommendations"]):
            return 2
        return 3
    results.sort(key=_priority)

    return {
        "window_days": settings.dmarc_insights_window_days,
        "domain_count": len(results),
        "insights": results,
    }
