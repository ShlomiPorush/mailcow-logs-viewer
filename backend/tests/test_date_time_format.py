"""How dates and times are written: Settings > Application > Time.

The browser writes the dates on the screen (utils.js); the server writes the
ones it sends itself: the date in every email, the weekly summary's window and
the clock-time jobs. "browser" leaves the order to the browser; the server has
no browser, so it then writes DD/MM/YYYY as emails always did. Times default to
the 24-hour clock, as every time was written before the setting.

An unknown value never stops the app (it falls back to the default); a new
unknown value is refused on save.
"""
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

import app.config as cfg
from app.app_time import (DATE_FORMATS, TIME_FORMATS, display_formats, format_clock, format_day,
                          normalize_date_format, normalize_time_format)
from app.config import EDITABLE_SETTING_KEYS, Settings, get_env_locked_keys
from app.services import email_layout as e
from test_app_time_zone_settings import _put, jobs, store  # noqa: F401  (fixtures)

WINTER = datetime(2026, 1, 15, 12, 5, tzinfo=timezone.utc)


@pytest.fixture
def formats(monkeypatch):
    monkeypatch.setattr(cfg.settings._inner, "tz", "Europe/Berlin")

    def use(date_format, time_format="24h"):
        monkeypatch.setattr(cfg.settings._inner, "date_format", date_format)
        monkeypatch.setattr(cfg.settings._inner, "time_format", time_format)
    return use


def test_the_defaults_change_nothing():
    assert Settings.model_fields["date_format"].default == "browser"
    assert Settings.model_fields["time_format"].default == "24h"
    assert {"date_format", "time_format"} <= EDITABLE_SETTING_KEYS


@pytest.mark.parametrize("value, expected", [
    ("DD/MM/YYYY", "DD/MM/YYYY"), ("yyyy-mm-dd", "YYYY-MM-DD"), (" DD.MM.YYYY ", "DD.MM.YYYY"),
    ("", "browser"), (None, "browser"), ("DD-MM-YY", "browser"),
])
def test_a_date_format_is_known_or_the_default(value, expected):
    assert normalize_date_format(value) == expected


@pytest.mark.parametrize("value, expected", [
    ("12h", "12h"), ("12H", "12h"), ("Browser", "browser"), ("", "24h"), ("am/pm", "24h"),
])
def test_a_time_format_is_known_or_the_default(value, expected):
    assert normalize_time_format(value) == expected


@pytest.mark.parametrize("date_format, expected", [
    ("browser", "15/01/2026"), ("DD/MM/YYYY", "15/01/2026"), ("MM/DD/YYYY", "01/15/2026"),
    ("DD.MM.YYYY", "15.01.2026"), ("YYYY-MM-DD", "2026-01-15"),
])
def test_an_email_date_follows_the_setting(formats, date_format, expected):
    formats(date_format)
    assert format_day(WINTER.date()) == expected
    assert e.format_date(WINTER) == expected
    assert e.format_date(WINTER, time=True) == f"{expected} 13:05 CET"


@pytest.mark.parametrize("hour, minute, expected", [
    (0, 0, "12:00 AM"), (0, 30, "12:30 AM"), (9, 5, "9:05 AM"), (12, 0, "12:00 PM"), (13, 5, "1:05 PM"),
    (23, 59, "11:59 PM"),
])
def test_the_12_hour_clock(formats, hour, minute, expected):
    formats("browser", "12h")
    assert format_clock(hour, minute) == expected


@pytest.mark.parametrize("time_format", ["24h", "browser"])
def test_the_server_writes_24_hours_unless_12_is_chosen(formats, time_format):
    formats("browser", time_format)
    assert format_clock(0, 0) == "00:00"
    assert format_clock(13, 5) == "13:05"


def test_an_email_in_12_hour_time_keeps_its_zone(formats):
    formats("MM/DD/YYYY", "12h")
    assert e.format_date(WINTER, time=True) == "01/15/2026 1:05 PM CET"
    html = e.render(title="T", topic="Weekly", app_title="My Logs", when=WINTER)
    assert "01/15/2026 1:05 PM CET" in html


def test_the_weekly_summary_window_follows_the_setting(formats):
    from app.routers.reporting import build_summary_email
    from test_email_layout import _summary_data
    formats("YYYY-MM-DD", "12h")
    data = _summary_data()
    data["traffic"].update(start_date="2026-10-19T07:00:00Z", end_date="2026-10-26T08:00:00Z")
    subject, text, html = build_summary_email(data, now=datetime(2026, 10, 26, 8, 0, tzinfo=timezone.utc))
    # The window crosses the end of summer time: each end keeps its own zone
    assert subject == "Weekly summary: 2026-10-19 9:00 AM CEST to 2026-10-26 9:00 AM CET"
    assert "2026-10-19 9:00 AM CEST to 2026-10-26 9:00 AM CET." in text
    assert "2026-10-19 9:00 AM CEST to 2026-10-26 9:00 AM CET" in html


def test_the_dmarc_error_email_dates_follow_the_setting(formats, monkeypatch):
    from app.services import dmarc_notifications
    formats("DD.MM.YYYY", "12h")
    monkeypatch.setattr(e, "local_now", lambda: WINTER.astimezone(e.app_time.app_tz()))
    failed = [{"email_id": "1", "message_id": "<m@x>", "subject": "Report", "error": "bad"}]

    assert "Date: 15.01.2026 1:05 PM CET" in dmarc_notifications._create_text_content(failed, 5)
    assert "15.01.2026 1:05 PM CET" in dmarc_notifications._create_html_content(failed, 5)


def test_api_info_reports_the_formats(formats):
    formats("DD.MM.YYYY", "12h")
    assert display_formats() == {"date_format": "DD.MM.YYYY", "time_format": "12h"}


# Saving, and values from the environment or the database

def test_saving_known_formats_stores_them(store):
    result = _put({"date_format": "yyyy-mm-dd", "time_format": "12H"})

    assert store.data["date_format"] == "YYYY-MM-DD"
    assert store.data["time_format"] == "12h"
    assert cfg.settings.date_format == "YYYY-MM-DD"
    assert result["configuration"]["date_format"] == "YYYY-MM-DD"
    assert display_formats() == {"date_format": "YYYY-MM-DD", "time_format": "12h"}


@pytest.mark.parametrize("key, value", [("date_format", "DD-MM-YY"), ("time_format", "am/pm")])
def test_saving_an_unknown_format_is_refused(store, key, value):
    with pytest.raises(HTTPException) as refused:
        _put({key: value, "app_title": "Mail logs"})

    assert refused.value.status_code == 400
    assert key in refused.value.detail
    assert store.data == {}


def test_the_value_in_effect_sent_back_never_blocks_a_save(store):
    _put({"date_format": cfg.settings.date_format, "time_format": cfg.settings.time_format,
          "app_title": "Mail logs"})

    assert store.data["app_title"] == "Mail logs"


def test_an_unknown_stored_format_reads_as_the_default(store):
    store.data.update(date_format="DD-MM-YY", time_format="am/pm")
    cfg.reload_settings(object())

    assert display_formats() == {"date_format": "browser", "time_format": "24h"}


def test_env_wins_and_locks_the_fields(store, monkeypatch):
    store.data.update(date_format="MM/DD/YYYY", time_format="12h")
    monkeypatch.setenv("DATE_FORMAT", "DD.MM.YYYY")
    monkeypatch.setenv("TIME_FORMAT", "24h")
    cfg.reload_settings(object())

    assert {"date_format", "time_format"} <= get_env_locked_keys()
    assert display_formats() == {"date_format": "DD.MM.YYYY", "time_format": "24h"}

    # Without the environment the stored choice is back
    monkeypatch.delenv("DATE_FORMAT")
    monkeypatch.delenv("TIME_FORMAT")
    cfg.reload_settings(object())
    assert display_formats() == {"date_format": "MM/DD/YYYY", "time_format": "12h"}


def test_an_empty_env_value_locks_the_fields_at_the_defaults(store, monkeypatch):
    store.data.update(date_format="MM/DD/YYYY", time_format="12h")
    monkeypatch.setenv("DATE_FORMAT", "")
    monkeypatch.setenv("TIME_FORMAT", "")
    cfg.reload_settings(object())

    assert {"date_format", "time_format"} <= get_env_locked_keys()
    assert display_formats() == {"date_format": "browser", "time_format": "24h"}


def test_an_unknown_format_in_env_never_stops_the_app(monkeypatch):
    """Settings() is built at import and at every reload: an unknown value
    there must fall back, not raise, or the app would not start."""
    monkeypatch.setenv("DATE_FORMAT", "DD-MM-YY")
    monkeypatch.setenv("TIME_FORMAT", "am/pm")
    monkeypatch.setenv("SETTINGS_EDIT_VIA_UI_ENABLED", "false")

    built = Settings()

    assert (built.date_format, built.time_format) == ("browser", "24h")
    assert cfg.build_settings(None).date_format == "browser"


def test_the_formats_cover_what_the_page_offers():
    assert DATE_FORMATS == ("browser", "DD/MM/YYYY", "MM/DD/YYYY", "DD.MM.YYYY", "YYYY-MM-DD")
    assert TIME_FORMATS == ("24h", "12h", "browser")


# What the page reads

def test_api_info_sends_the_formats_to_the_page(jobs, monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    monkeypatch.setattr(cfg.settings._inner, "date_format", "DD.MM.YYYY")
    monkeypatch.setattr(cfg.settings._inner, "time_format", "12h")
    body = TestClient(app).get("/api/info").json()

    assert (body["date_format"], body["time_format"]) == ("DD.MM.YYYY", "12h")
    config = TestClient(app).get("/api/settings/info").json()["configuration"]
    assert (config["date_format"], config["time_format"]) == ("DD.MM.YYYY", "12h")


# The jobs list

def test_clock_time_jobs_follow_the_time_setting_and_give_their_parts(jobs, monkeypatch):
    monkeypatch.setattr(cfg.settings._inner, "time_format", "12h")
    from fastapi.testclient import TestClient
    from app.main import app
    monkeypatch.setattr(cfg.settings._inner, "tz", "Europe/Berlin")
    body = TestClient(app).get("/api/settings/info").json()["background_jobs"]

    assert body["send_weekly_summary"]["schedule"] == "Weekly, Monday at 9:00 AM (Europe/Berlin)"
    assert body["send_weekly_summary"]["clock"] == {
        "hour": 9, "minute": 0, "weekday": "Monday", "zone": "Europe/Berlin"}
    assert body["cleanup_dmarc_reports"]["clock"] == {
        "hour": 2, "minute": 15, "weekday": None, "zone": "Europe/Berlin"}
    # A job with no clock time has no parts
    assert "clock" not in body["fetch_logs"]
