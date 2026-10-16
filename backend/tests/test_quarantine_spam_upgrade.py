"""Upgrade steps that repair what earlier bounce counting and rule editing left
in the database. Each runs on seeded rows in a schema of its own."""
import importlib.util
import pathlib
import uuid
from contextlib import contextmanager
from datetime import datetime

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.models import Base, PostfixLog, SystemSetting


def _revision(suffix):
    versions = pathlib.Path(__file__).resolve().parent.parent / "alembic" / "versions"
    matches = sorted(versions.glob(f"*_{suffix}.py"))
    assert matches, f"upgrade step {suffix} is missing"
    spec = importlib.util.spec_from_file_location(suffix, matches[0])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextmanager
def _schema(*tables):
    from app.database import engine
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    schema = "upgrade_test_" + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    isolated = create_engine(engine.url, connect_args={"options": f"-csearch_path={schema}"})
    try:
        Base.metadata.create_all(isolated, tables=[t.__table__ for t in tables])
        yield isolated
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))


def _upgrade(isolated, revision):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    with isolated.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            revision.upgrade()


# -- 0016: bounce detection's mark starts at the lines already stored ---------

def _mark(isolated):
    with isolated.connect() as conn:
        return conn.execute(text(
            "SELECT value FROM system_settings WHERE key = 'suppression_bounce_log_watermark'")).scalar()


def test_bounce_mark_starts_at_the_newest_stored_line():
    import app.scheduler as sch
    revision = _revision("bounce_log_watermark")
    assert revision.KEY == sch.BOUNCE_WATERMARK_KEY
    with _schema(PostfixLog, SystemSetting) as isolated:
        _upgrade(isolated, revision)
        assert _mark(isolated) == "0"   # no lines yet

    with _schema(PostfixLog, SystemSetting) as isolated:
        now = datetime.utcnow()
        with Session(isolated) as db:
            for n in range(3):
                db.add(PostfixLog(time=now, created_at=now, program="postfix/smtp", message=f"line {n}",
                                  queue_id=f"Q{n}", recipient="user@example.com", status="deferred", dsn="4.4.1"))
            db.commit()
            newest = max(row.id for row in db.query(PostfixLog).all())
        _upgrade(isolated, revision)
        assert _mark(isolated) == str(newest)
        # Running it again keeps the mark detection has moved on since
        with isolated.begin() as conn:
            conn.execute(text("UPDATE system_settings SET value = '999999' "
                              "WHERE key = 'suppression_bounce_log_watermark'"))
        _upgrade(isolated, revision)
        assert _mark(isolated) == "999999"


# -- 0017: soft-bounce suppressions active below the threshold ----------------

# email -> (reason, source, soft_bounce_count, active); with a threshold of 5
# only the first two are wrong (with the default of 3, only the first)
SUPPRESSIONS = {
    "below@example.com": ("soft_bounce", "auto", 2, True),
    "four@example.com": ("soft_bounce", "auto", 4, True),
    "at@example.com": ("soft_bounce", "auto", 5, True),
    "above@example.com": ("soft_bounce", "auto", 7, True),
    "off@example.com": ("soft_bounce", "auto", 1, False),
    "manual@example.com": ("manual", "manual", 0, True),
    "manual-soft@example.com": ("soft_bounce", "manual", 1, True),
    "imported@example.com": ("soft_bounce", "import", 1, True),
    "hard@example.com": ("hard_bounce", "auto", 0, True),
    "stuck@example.com": ("deferred_stuck", "auto", 1, True),
}


def _seed_suppressions(isolated):
    from app.models import SpamSuppression
    expires = datetime(2030, 1, 1)
    with Session(isolated) as db:
        for email, (reason, source, soft, active) in SUPPRESSIONS.items():
            db.add(SpamSuppression(email=email, type="email", reason=reason, source=source,
                                   bounce_count=max(soft, 1), soft_bounce_count=soft,
                                   hard_bounce_count=1 if reason == "hard_bounce" else 0,
                                   active=active, synced_to_rspamd=True, expires_at=expires))
        db.commit()


def _suppressions(isolated):
    with isolated.connect() as conn:
        rows = conn.execute(text(
            "SELECT email, active, synced_to_rspamd, soft_bounce_count, bounce_count, expires_at "
            "FROM spam_suppressions")).all()
    return {r.email: r for r in rows}


@pytest.fixture
def suppression_settings(monkeypatch):
    for name in ("SUPPRESSION_SOFT_BOUNCE_THRESHOLD", "SUPPRESSION_SOFT_BOUNCE_ACTION", "SETTINGS_EDIT_VIA_UI_ENABLED"):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


TURNED_OFF = ("below@example.com", "four@example.com")


def _check_only_below_turned_off(isolated):
    rows = _suppressions(isolated)
    for email in TURNED_OFF:
        assert (rows[email].active, rows[email].synced_to_rspamd) == (False, False), email
    # Counts and expiry stay as they were
    assert rows["four@example.com"].soft_bounce_count == 4 and rows["four@example.com"].bounce_count == 4
    assert rows["four@example.com"].expires_at == datetime(2030, 1, 1)
    for email, (_, _, _, active) in SUPPRESSIONS.items():
        if email not in TURNED_OFF:
            assert (rows[email].active, rows[email].synced_to_rspamd) == (active, True), email


def test_suppressions_below_the_threshold_are_turned_off(suppression_settings, caplog):
    from app.models import SpamSuppression
    suppression_settings.setenv("SUPPRESSION_SOFT_BOUNCE_THRESHOLD", "5")
    revision = _revision("soft_bounce_threshold_repair")
    with _schema(SpamSuppression, SystemSetting) as isolated:
        _seed_suppressions(isolated)
        with caplog.at_level("WARNING", logger="app.migrations"):
            _upgrade(isolated, revision)
        _check_only_below_turned_off(isolated)
        assert "turned off 2 automatic soft-bounce suppression(s) below the Soft Bounce Threshold of 5" in caplog.text
        # Running it again changes nothing and says nothing
        caplog.clear()
        _upgrade(isolated, revision)
        _check_only_below_turned_off(isolated)
        assert "turned off" not in caplog.text


def test_the_threshold_saved_from_the_ui_is_used(suppression_settings):
    from app.models import SpamSuppression
    suppression_settings.setenv("SETTINGS_EDIT_VIA_UI_ENABLED", "true")
    revision = _revision("soft_bounce_threshold_repair")
    with _schema(SpamSuppression, SystemSetting) as isolated:
        _seed_suppressions(isolated)
        with Session(isolated) as db:
            db.add(SystemSetting(key="config.suppression_soft_bounce_threshold", value="5"))
            db.commit()
        _upgrade(isolated, revision)
        _check_only_below_turned_off(isolated)


def test_nothing_changes_when_soft_bounces_are_not_counted(suppression_settings):
    from app.models import SpamSuppression
    suppression_settings.setenv("SUPPRESSION_SOFT_BOUNCE_THRESHOLD", "5")
    revision = _revision("soft_bounce_threshold_repair")
    for action in ("suppress", "ignore"):
        suppression_settings.setenv("SUPPRESSION_SOFT_BOUNCE_ACTION", action)
        with _schema(SpamSuppression, SystemSetting) as isolated:
            _seed_suppressions(isolated)
            _upgrade(isolated, revision)
            rows = _suppressions(isolated)
            for email, (_, _, _, active) in SUPPRESSIONS.items():
                assert (rows[email].active, rows[email].synced_to_rspamd) == (active, True), (action, email)


# -- 0018: Contains rules an earlier edit escaped twice -----------------------

# The pattern the rule dialog saves for a Contains rule on example.com after
# an earlier version opened and saved it again (made by the real dialog code
# in .github/tests/queue-quarantine-actions.test.cjs)
TWICE_SAVED = r"example\\\.com"
REPAIRED = r"example\.com"

# name -> (match_type, match_value, is_regex, value after the upgrade)
RULES = {
    "domain twice": ("sender_domain", TWICE_SAVED, True, REPAIRED),
    "sender twice": ("sender", r"user@example\\\.com", True, r"user@example\.com"),
    "recipient three times": ("recipient", r"user@example\\\\\\\.com", True, r"user@example\.com"),
    "domain once": ("sender_domain", r"example\.org", True, r"example\.org"),
    "plain text": ("sender", "noreply", True, "noreply"),
    "subject twice": ("subject", r"Invoice\\\.pdf", True, r"Invoice\\\.pdf"),
    "regex": ("sender", r"^.*@(spam|junk)\.example$", True, r"^.*@(spam|junk)\.example$"),
    "regex with escapes": ("sender", r"a\\\.b|c", True, r"a\\\.b|c"),
    "regex digits": ("sender", r"invoice\\d+", True, r"invoice\\d+"),
    "exact": ("sender", TWICE_SAVED, False, TWICE_SAVED),
}


def _seed_rules(isolated):
    from app.models import QuarantineRule
    with Session(isolated) as db:
        for name, (match_type, value, is_regex, _) in RULES.items():
            db.add(QuarantineRule(name=name, match_type=match_type, match_value=value,
                                  is_regex=is_regex, action="release"))
        db.commit()


def _rules(isolated):
    from app.models import QuarantineRule
    with Session(isolated) as db:
        rules = db.query(QuarantineRule).all()
        for rule in rules:
            db.expunge(rule)
    return {rule.name: rule for rule in rules}


def _matches(rule, sender="user@example.com", rcpt="user@example.com", subject="Hello"):
    from app.routers.quarantine_rules import _find_matching_rule
    domain = sender.split("@")[-1]
    return _find_matching_rule([rule], sender, domain, rcpt, subject) is rule


def test_twice_escaped_contains_rules_are_repaired(caplog):
    from app.models import QuarantineRule
    revision = _revision("repair_twice_escaped_rules")
    with _schema(QuarantineRule) as isolated:
        _seed_rules(isolated)
        before = _rules(isolated)
        assert not _matches(before["domain twice"]), "the damaged rule should not match before the upgrade"
        with caplog.at_level("WARNING", logger="app.migrations"):
            _upgrade(isolated, revision)
        after = _rules(isolated)
        for name, (_, _, _, expected) in RULES.items():
            assert after[name].match_value == expected, name
        for name in ("domain twice", "sender twice", "recipient three times"):
            assert _matches(after[name]), name
        assert caplog.text.count("Upgrade: repaired rule") == 3
        assert f"sender_domain pattern {TWICE_SAVED} is now {REPAIRED}" in caplog.text
        # Running it again changes nothing
        caplog.clear()
        _upgrade(isolated, revision)
        assert {n: r.match_value for n, r in _rules(isolated).items()} == {n: v[3] for n, v in RULES.items()}
        assert "repaired" not in caplog.text
