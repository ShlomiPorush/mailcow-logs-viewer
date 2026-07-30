"""
Tests for the aggregated dashboard blacklist summary:
aggregate_blacklist_summary combines the latest check of every active
monitored host into the /api/blacklist/summary payload.
"""
from datetime import datetime, timedelta, timezone

from app.services.blacklist_service import (
    aggregate_blacklist_summary,
    BLACKLISTS,
    CACHE_TTL_HOURS,
)

NOW = datetime(2026, 7, 30, 12, 0, 0, tzinfo=timezone.utc)
FRESH = NOW - timedelta(hours=1)
STALE = NOW - timedelta(hours=CACHE_TTL_HOURS + 1)


def host(hostname, status=None, listed=None, total=None, checked_at=None, source='config'):
    return {
        "hostname": hostname,
        "source": source,
        "status": status,
        "listed_count": listed,
        "total_blacklists": total,
        "checked_at": checked_at,
    }


def test_empty_hosts_is_unknown_no_data():
    result = aggregate_blacklist_summary([], server_ip=None, now=NOW)
    assert result["has_data"] is False
    assert result["status"] == "unknown"
    assert result["listed_count"] == 0
    assert result["total_blacklists"] == len(BLACKLISTS)
    assert result["checked_at"] is None
    assert result["hosts"] == []
    assert result["hosts_total"] == 0
    assert result["hosts_listed"] == 0


def test_hosts_without_any_checks_is_unknown():
    result = aggregate_blacklist_summary(
        [host("203.0.113.5"), host("198.51.100.7")], now=NOW)
    assert result["has_data"] is False
    assert result["status"] == "unknown"
    assert result["hosts_total"] == 2
    assert all(h["status"] == "unknown" for h in result["hosts"])


def test_listed_takes_precedence_over_error_and_clean():
    result = aggregate_blacklist_summary([
        host("a", "clean", 0, 30, FRESH),
        host("b", "error", 0, 30, FRESH),
        host("c", "listed", 3, 30, FRESH),
    ], now=NOW)
    assert result["status"] == "listed"
    assert result["has_data"] is True
    assert result["hosts_listed"] == 1
    assert result["hosts_total"] == 3


def test_error_takes_precedence_over_clean_when_none_listed():
    result = aggregate_blacklist_summary([
        host("a", "clean", 0, 30, FRESH),
        host("b", "error", 0, 30, FRESH),
    ], now=NOW)
    assert result["status"] == "error"
    assert result["hosts_listed"] == 0


def test_all_clean_is_clean():
    result = aggregate_blacklist_summary([
        host("a", "clean", 0, 30, FRESH),
        host("b", "clean", 0, 12, FRESH),
    ], now=NOW)
    assert result["status"] == "clean"
    assert result["has_data"] is True
    assert result["listed_count"] == 0
    assert result["total_blacklists"] == 42  # sum across hosts


def test_listed_count_is_sum_across_hosts():
    result = aggregate_blacklist_summary([
        host("a", "listed", 2, 30, FRESH),
        host("b", "listed", 3, 30, FRESH),
        host("c", "clean", 0, 30, FRESH),
    ], now=NOW)
    assert result["listed_count"] == 5
    assert result["total_blacklists"] == 90
    assert result["hosts_listed"] == 2


def test_stale_check_counts_as_no_data():
    # Preserves the old single-host behavior: has_data drops after the TTL
    result = aggregate_blacklist_summary(
        [host("a", "listed", 2, 30, STALE)], now=NOW)
    assert result["has_data"] is False
    assert result["status"] == "unknown"
    assert result["listed_count"] == 0
    assert result["hosts"][0]["status"] == "unknown"
    # checked_at still reports the last known check time
    assert result["checked_at"] is not None


def test_mixed_fresh_and_stale_only_fresh_counts():
    result = aggregate_blacklist_summary([
        host("a", "listed", 2, 30, STALE),
        host("b", "clean", 0, 30, FRESH),
    ], now=NOW)
    assert result["has_data"] is True
    assert result["status"] == "clean"
    assert result["listed_count"] == 0
    assert result["hosts_listed"] == 0


def test_checked_at_is_most_recent_check():
    older = NOW - timedelta(hours=5)
    result = aggregate_blacklist_summary([
        host("a", "clean", 0, 30, older),
        host("b", "clean", 0, 30, FRESH),
    ], now=NOW)
    assert result["checked_at"] == FRESH.isoformat().replace('+00:00', '') + 'Z'


def test_naive_datetimes_are_treated_as_utc():
    naive_fresh = FRESH.replace(tzinfo=None)
    result = aggregate_blacklist_summary(
        [host("a", "listed", 1, 30, naive_fresh)], now=NOW)
    assert result["has_data"] is True
    assert result["status"] == "listed"
    assert result["checked_at"].endswith('Z')


def test_server_ip_falls_back_to_single_host():
    result = aggregate_blacklist_summary(
        [host("198.51.100.7", "clean", 0, 30, FRESH)], server_ip=None, now=NOW)
    assert result["server_ip"] == "198.51.100.7"


def test_server_ip_prefers_wan_ip_when_given():
    result = aggregate_blacklist_summary(
        [host("198.51.100.7", "clean", 0, 30, FRESH)],
        server_ip="203.0.113.5", now=NOW)
    assert result["server_ip"] == "203.0.113.5"


def test_hosts_detail_shape():
    result = aggregate_blacklist_summary([
        host("a", "listed", 2, 30, FRESH, source='system'),
        host("b", None, None, None, None, source='transport'),
    ], now=NOW)
    assert result["hosts"][0] == {
        "hostname": "a",
        "source": "system",
        "status": "listed",
        "listed_count": 2,
        "checked_at": FRESH.isoformat().replace('+00:00', '') + 'Z',
    }
    assert result["hosts"][1]["status"] == "unknown"
    assert result["hosts"][1]["listed_count"] == 0
    assert result["hosts"][1]["checked_at"] is None
