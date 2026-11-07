"""The time of the last full DNS check (the 6-hourly job or Check all) stays
put when one domain is checked again on its own. Each test runs in a schema
of its own on the CI PostgreSQL."""
import asyncio
import uuid
from contextlib import contextmanager

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.models import Base, DomainDNSCheck, SystemSetting
from app.routers import domains

DNS = {"spf": {"status": "success"}, "dkim": {"status": "success"}, "dmarc": {"status": "success"}}


@contextmanager
def _session():
    from app.database import engine
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    schema = "dns_check_test_" + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    isolated = create_engine(engine.url, connect_args={"options": f"-csearch_path={schema}"})
    try:
        Base.metadata.create_all(isolated, tables=[DomainDNSCheck.__table__, SystemSetting.__table__])
        with Session(isolated) as db:
            yield db
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))


def _save(db, name, full):
    asyncio.run(domains.save_dns_check_to_db(db, name, DNS, is_full_check=full))


def test_checking_the_only_domain_again_keeps_the_last_full_check(monkeypatch):
    monkeypatch.setattr(domains.settings, "dns_change_alerts_enabled", False, raising=False)
    with _session() as db:
        _save(db, "example.com", full=True)
        full = domains._last_full_dns_check(db)
        assert full is not None

        _save(db, "example.com", full=False)
        assert domains._last_full_dns_check(db) == full


def test_checking_one_domain_does_not_move_the_last_full_check(monkeypatch):
    monkeypatch.setattr(domains.settings, "dns_change_alerts_enabled", False, raising=False)
    with _session() as db:
        _save(db, "example.org", full=True)
        _save(db, "example.com", full=True)
        full = domains._last_full_dns_check(db)

        _save(db, "example.com", full=False)
        assert domains._last_full_dns_check(db) == full


def test_a_new_full_check_moves_it_forward(monkeypatch):
    monkeypatch.setattr(domains.settings, "dns_change_alerts_enabled", False, raising=False)
    with _session() as db:
        _save(db, "example.com", full=True)
        first = domains._last_full_dns_check(db)
        _save(db, "example.com", full=True)
        assert domains._last_full_dns_check(db) > first


def test_deleting_the_domains_data_forgets_it(monkeypatch):
    import starlette.staticfiles as sf
    orig = sf.StaticFiles.__init__
    monkeypatch.setattr(sf.StaticFiles, "__init__", lambda s, *a, **k: orig(s, *a, **{**k, "check_dir": False}))
    from fastapi.testclient import TestClient
    from app.main import app
    from app.config import settings
    from app.database import get_db

    monkeypatch.setattr(domains.settings, "dns_change_alerts_enabled", False, raising=False)
    monkeypatch.setattr(settings._inner, "edit_settings_via_ui_enabled", True)
    monkeypatch.setattr(settings._inner, "disabled_features", "domains")
    with _session() as db:
        _save(db, "example.com", full=True)
        app.dependency_overrides[get_db] = lambda: db
        try:
            resp = TestClient(app).post("/api/settings/purge-feature-data", json={"feature": "domains"})
        finally:
            app.dependency_overrides.pop(get_db, None)
        assert resp.status_code == 200, resp.text
        assert domains._last_full_dns_check(db) is None
