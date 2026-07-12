"""Tests for shared utility helpers."""
from datetime import datetime, timezone, timedelta

from fastapi import HTTPException

from app.utils import ensure_timezone_aware, format_datetime_for_api, internal_error


def test_format_datetime_naive_assumed_utc():
    dt = datetime(2026, 1, 12, 10, 30, 0)
    assert format_datetime_for_api(dt) == "2026-01-12T10:30:00Z"


def test_format_datetime_converts_to_utc():
    tz = timezone(timedelta(hours=2))
    dt = datetime(2026, 1, 12, 12, 30, 0, tzinfo=tz)
    assert format_datetime_for_api(dt) == "2026-01-12T10:30:00Z"


def test_format_datetime_none():
    assert format_datetime_for_api(None) is None


def test_format_datetime_strips_microseconds():
    dt = datetime(2026, 1, 12, 10, 30, 0, 123456, tzinfo=timezone.utc)
    assert format_datetime_for_api(dt) == "2026-01-12T10:30:00Z"


def test_ensure_timezone_aware():
    naive = datetime(2026, 1, 12, 10, 0, 0)
    aware = ensure_timezone_aware(naive)
    assert aware.tzinfo == timezone.utc
    already = datetime(2026, 1, 12, 10, 0, 0, tzinfo=timezone(timedelta(hours=3)))
    assert ensure_timezone_aware(already) is already


def test_internal_error_hides_details_by_default():
    exc = internal_error(ValueError("postgres://user:secret@db/prod exploded"))
    assert isinstance(exc, HTTPException)
    assert exc.status_code == 500
    assert "secret" not in exc.detail
    assert exc.detail == "Internal server error"


def test_internal_error_custom_status():
    exc = internal_error(RuntimeError("boom"), status_code=502)
    assert exc.status_code == 502
    assert exc.detail == "Internal server error"
