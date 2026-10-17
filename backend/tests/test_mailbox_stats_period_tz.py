"""Mailbox Stats counts a day in the app time zone, like its activity chart.

"Today" and a custom range used to start at midnight UTC, while the activity
chart and every time on the page use the app zone: with Asia/Jerusalem the
counts missed the first hours of the day and the chart gained an extra day.

The chart's day slots are app-zone days (YYYY-MM-DD, shown as they are); its
hour slots are the UTC instants they start at, with Z, so the page formats
them in the app zone and the repeated hour at the end of daylight saving is
two slots, not one.
"""
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from app.config import settings
from app.routers import mailbox_stats


def test_today_starts_at_local_midnight(monkeypatch):
    monkeypatch.setattr(settings._inner, 'tz', 'Asia/Jerusalem')
    start, end = mailbox_stats.parse_date_range('today')
    # Israel is UTC+2 or UTC+3, so its midnight is 21:00 or 22:00 UTC the day before
    assert start.utcoffset().total_seconds() == 0
    assert (start.hour, start.minute) in ((21, 0), (22, 0))
    assert start.astimezone(ZoneInfo('Asia/Jerusalem')).hour == 0
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
    activity = mailbox_stats.get_bulk_activity(None, {}, start, end)
    assert activity['unit'] == 'day'
    assert activity['buckets'] == ['2026-07-01', '2026-07-02', '2026-07-03']


def test_hour_slots_are_utc_instants_and_the_repeated_hour_is_two_slots(monkeypatch):
    monkeypatch.setattr(settings._inner, 'tz', 'Europe/Berlin')
    # 2026-10-25 in Berlin has 25 hours: 22:00 UTC the day before to 23:00 UTC
    start, end = mailbox_stats.parse_date_range('custom', '2026-10-25', '2026-10-25')
    activity = mailbox_stats.get_bulk_activity(None, {}, start, end)
    assert activity['unit'] == 'hour'
    first = datetime(2026, 10, 24, 22, tzinfo=timezone.utc)
    assert activity['buckets'] == [
        (first + timedelta(hours=i)).strftime('%Y-%m-%dT%H:%M:%SZ') for i in range(25)]


def test_a_day_with_a_daylight_saving_change_is_one_day_slot(monkeypatch):
    monkeypatch.setattr(settings._inner, 'tz', 'Europe/Berlin')
    start, end = mailbox_stats.parse_date_range('custom', '2026-03-28', '2026-03-30')
    assert start == datetime(2026, 3, 27, 23, tzinfo=timezone.utc)
    assert end == datetime(2026, 3, 30, 21, 59, 59, 999999, tzinfo=timezone.utc)
    activity = mailbox_stats.get_bulk_activity(None, {}, start, end)
    assert activity['buckets'] == ['2026-03-28', '2026-03-29', '2026-03-30']


def test_utc_is_unchanged(monkeypatch):
    monkeypatch.setattr(settings._inner, 'tz', 'UTC')
    start, end = mailbox_stats.parse_date_range('custom', '2026-07-01', '2026-07-02')
    assert start == datetime(2026, 7, 1, tzinfo=timezone.utc)
    assert end == datetime(2026, 7, 2, 23, 59, 59, 999999, tzinfo=timezone.utc)


def test_an_unknown_zone_counts_utc_days(monkeypatch):
    monkeypatch.setattr(settings._inner, 'tz', 'Europe/Berlinn')
    start, end = mailbox_stats.parse_date_range('custom', '2026-07-01', '2026-07-01')
    assert start == datetime(2026, 7, 1, tzinfo=timezone.utc)
    assert end == datetime(2026, 7, 1, 23, 59, 59, 999999, tzinfo=timezone.utc)
