"""The app time zone is a setting like the others: Settings > Application.

TZ used to be a legacy, ENV-only value nobody could see or change from the
page. It is now editable there; an ENV value wins and locks the field, an
unknown name is refused on save, and the jobs list says in which zone the
clock-time jobs run.
"""
import types

import pytest
from fastapi import HTTPException

import app.config as cfg
import app.routers.settings as rs
import app.services.settings_store as ss
from app.app_time import tz_status
from app.config import EDITABLE_SETTING_KEYS, Settings, get_env_locked_keys


@pytest.fixture
def store(monkeypatch):
    """Real update_settings and build_settings; only the system_settings table is a dict."""
    data = {}
    monkeypatch.delenv("TZ", raising=False)
    monkeypatch.setenv("SETTINGS_EDIT_VIA_UI_ENABLED", "true")
    monkeypatch.setattr(ss, "get_config_overrides_from_db", lambda db, types_: {
        k: ss._deserialize_value(ss._serialize_value(v), k, types_[k]) for k, v in data.items()})
    monkeypatch.setattr(rs, "save_config_overrides_to_db", lambda db, ov: data.update(ov))
    monkeypatch.setattr(rs, "has_config_overrides_in_db", lambda db: bool(data))
    monkeypatch.setattr(rs, "cleanup_disabled_feature_data", lambda db: None)
    rescheduled = []
    monkeypatch.setattr(rs, "reschedule_interval_jobs", lambda: rescheduled.append(cfg.settings.tz))
    monkeypatch.setattr(rs, "clear_maxmind_validation_status", lambda db: None)
    monkeypatch.setattr(rs, "mailcow_api", types.SimpleNamespace(
        reload_config=lambda: None, has_rw_key=False))
    monkeypatch.setattr(rs, "oauth2_client", types.SimpleNamespace(reload_config=lambda: None))
    cfg.reload_settings(object())
    yield types.SimpleNamespace(data=data, rescheduled=rescheduled)
    monkeypatch.undo()
    cfg.reload_settings()


def _put(body):
    return rs.update_settings(dict(body), db=object())


def test_tz_is_editable_and_unset_by_default():
    assert "tz" in EDITABLE_SETTING_KEYS
    assert Settings.model_fields["tz"].default == ""
    assert rs._get_field_defaults()["tz"] == ""


def test_nothing_configured_reads_as_unset_and_means_utc(store):
    assert cfg.settings.tz == ""
    assert tz_status() == {"timezone": "UTC", "timezone_valid": True, "timezone_configured": ""}
    assert rs.get_editable_settings(db=object())["configuration"]["tz"] == ""


def test_saving_a_zone_stores_it_and_moves_the_jobs(store):
    result = _put({"tz": " Europe/Berlin "})

    assert result["configuration"]["tz"] == "Europe/Berlin"
    assert store.data["tz"] == "Europe/Berlin"
    assert tz_status()["timezone"] == "Europe/Berlin"
    # Clock-time jobs are rescheduled after the new zone is in effect
    assert store.rescheduled == ["Europe/Berlin"]


def test_saving_an_unknown_zone_is_refused(store):
    with pytest.raises(HTTPException) as refused:
        _put({"tz": "Europe/Berlinn"})

    assert refused.value.status_code == 400
    assert refused.value.detail == "Unknown time zone: Europe/Berlinn"
    assert "tz" not in store.data


def test_saving_an_empty_zone_means_utc(store):
    store.data["tz"] = "Europe/Berlin"
    cfg.reload_settings(object())

    _put({"tz": ""})

    assert store.data["tz"] == ""
    assert tz_status()["timezone"] == "UTC"


def test_env_wins_and_locks_the_field(store, monkeypatch):
    store.data["tz"] = "Asia/Tokyo"
    monkeypatch.setenv("TZ", "Europe/Berlin")
    cfg.reload_settings(object())

    assert "tz" in get_env_locked_keys()
    assert tz_status()["timezone"] == "Europe/Berlin"


def test_an_unknown_zone_from_env_does_not_block_saving_other_settings(store, monkeypatch):
    # The page posts every key, the locked one included
    monkeypatch.setenv("TZ", "Europe/Berlinn")
    cfg.reload_settings(object())

    _put({"tz": "Europe/Berlinn", "app_title": "Mail logs"})

    assert store.data["app_title"] == "Mail logs"


def test_an_unknown_stored_zone_does_not_block_saving_other_settings(store):
    store.data["tz"] = "Mars/Olympus"
    cfg.reload_settings(object())

    _put({"tz": "Mars/Olympus", "app_title": "Mail logs"})

    assert store.data["app_title"] == "Mail logs"


# --- The jobs list names the zone -------------------------------------------

def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def jobs(monkeypatch):
    if not _postgres_available():
        pytest.skip("PostgreSQL not available")
    import starlette.staticfiles as sf
    orig = sf.StaticFiles.__init__
    monkeypatch.setattr(sf.StaticFiles, "__init__",
                        lambda s, *a, **k: orig(s, *a, **{**k, "check_dir": False}))
    from fastapi.testclient import TestClient
    from app.database import init_db
    from app.main import app
    init_db()
    for key in ("basic_auth_enabled", "auth_enabled", "oauth2_enabled"):
        monkeypatch.setattr(cfg.settings._inner, key, False)
    monkeypatch.setattr(cfg.settings._inner, "disabled_features", "")
    monkeypatch.setattr(cfg.settings._inner, "enable_weekly_summary", True)
    monkeypatch.setattr(rs, "is_license_configured", lambda: True)

    def read(zone):
        monkeypatch.setattr(cfg.settings._inner, "tz", zone)
        body = TestClient(app).get("/api/settings/info").json()
        return {name: job.get("schedule") for name, job in body["background_jobs"].items()}
    return read


def test_clock_time_jobs_name_the_zone(jobs):
    schedules = jobs("Europe/Berlin")

    assert schedules["cleanup_logs"] == "Daily at 02:00 (Europe/Berlin)"
    assert schedules["cleanup_dmarc_reports"] == "Daily at 02:15 (Europe/Berlin)"
    assert schedules["update_geoip"] == "Weekly, Sunday at 03:00 (Europe/Berlin)"
    assert schedules["cleanup_eas_devices"] == "Daily at 03:30 (Europe/Berlin)"
    assert schedules["blacklist_check"] == "Daily at 05:00 (Europe/Berlin)"
    assert schedules["send_weekly_summary"] == "Weekly, Monday at 09:00 (Europe/Berlin)"
    assert schedules["cleanup_raw_logs"] == "Daily at 03:00 (Europe/Berlin)"


def test_clock_time_jobs_say_utc_when_no_zone_is_set(jobs):
    assert jobs("")["cleanup_logs"] == "Daily at 02:00 (UTC)"
