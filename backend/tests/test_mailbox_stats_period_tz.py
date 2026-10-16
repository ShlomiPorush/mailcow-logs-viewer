"""Mailbox Stats counts a day in the app's time zone (TZ), like its activity chart.

"Today" and a custom range used to start at midnight UTC, while the activity
chart and every time on the page use TZ: with TZ=Asia/Jerusalem the counts
missed the first hours of the day and the chart gained an extra day.
"""
from datetime import datetime, timezone

from app.config import settings
from app.routers import mailbox_stats


def test_today_starts_at_local_midnight(monkeypatch):
    monkeypatch.setattr(settings._inner, 'tz', 'Asia/Jerusalem')
    start, end = mailbox_stats.parse_date_range('today')
    # Israel is UTC+2 or UTC+3, so its midnight is 21:00 or 22:00 UTC the day before
    assert start.utcoffset().total_seconds() == 0
    assert (start.hour, start.minute) in ((21, 0), (22, 0))
    assert start.astimezone(mailbox_stats.ZoneInfo('Asia/Jerusalem')).hour == 0
    assert start <= end


def test_custom_days_are_local_days(monkeypatch):
    monkeypatch.setattr(settings._inner, 'tz', 'Asia/Jerusalem')
    start, end = mailbox_stats.parse_date_range('custom', '2026-07-01', '2026-07-02')
    # Summer time, UTC+3
    assert start == datetime(2026, 6, 30, 21, 0, tzinfo=timezone.utc)
    assert end == datetime(2026, 7, 2, 20, 59, 59, 999999, tzinfo=timezone.utc)


def test_the_chart_has_exactly_the_days_of_the_range(monkeypatch):
    monkeypatch.setattr(settings._inner, 'tz', 'Asia/Jerusalem')
    start, end = mailbox_stats.parse_date_range('custom', '2026-07-01', '2026-07-03')
    unit, _, buckets = mailbox_stats._activity_buckets(start, end)
    assert unit == 'day'
    assert [b.day for b in buckets] == [1, 2, 3]


def test_utc_is_unchanged(monkeypatch):
    monkeypatch.setattr(settings._inner, 'tz', 'UTC')
    start, end = mailbox_stats.parse_date_range('custom', '2026-07-01', '2026-07-02')
    assert start == datetime(2026, 7, 1, tzinfo=timezone.utc)
    assert end == datetime(2026, 7, 2, 23, 59, 59, 999999, tzinfo=timezone.utc)
