"""Upgrade steps that repair what earlier bounce counting and rule editing left
in the database. Each runs on seeded rows in a schema of its own."""
import importlib.util
import pathlib
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta

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
        from app.models import SpamSuppression, SuppressionEvent
        extra = [SuppressionEvent] if SpamSuppression in tables else []
        Base.metadata.create_all(isolated, tables=[t.__table__ for t in (*tables, *extra)])
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


# -- 0017: automatic soft-bounce suppressions start counting again -------------

# email -> (reason, source, soft_bounce_count, active). Earlier versions could
# count a bounce twice, so with Count then suppress every automatic soft-bounce
# entry is lifted and its counts start again, at, above or below the threshold
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
LIFTED = ("below@example.com", "four@example.com", "at@example.com", "above@example.com", "off@example.com")
EXPIRES = datetime(2030, 1, 1)


def _seed_suppressions(isolated):
    from app.models import SpamSuppression
    with Session(isolated) as db:
        for email, (reason, source, soft, active) in SUPPRESSIONS.items():
            db.add(SpamSuppression(email=email, type="email", reason=reason, source=source,
                                   bounce_count=max(soft, 1), soft_bounce_count=soft,
                                   hard_bounce_count=1 if reason == "hard_bounce" else 0,
                                   active=active, synced_to_rspamd=True, expires_at=EXPIRES))
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


def _check_soft_bounces_lifted(isolated, upgraded_at):
    rows = _suppressions(isolated)
    for email in LIFTED:
        row = rows[email]
        assert (row.active, row.synced_to_rspamd) == (False, False), email
        assert (row.soft_bounce_count, row.bounce_count) == (0, 0), email
        # The escalated expiry is not kept: the entry reads as expired
        assert upgraded_at - timedelta(minutes=1) <= row.expires_at <= datetime.utcnow(), email
    for email, (reason, _, soft, active) in SUPPRESSIONS.items():
        if email not in LIFTED:
            row = rows[email]
            assert (row.active, row.synced_to_rspamd) == (active, True), email
            assert (row.soft_bounce_count, row.bounce_count, row.expires_at) == (soft, max(soft, 1), EXPIRES), email


def test_automatic_soft_bounce_suppressions_are_lifted_and_counted_again(suppression_settings, caplog):
    from app.models import SpamSuppression
    suppression_settings.setenv("SUPPRESSION_SOFT_BOUNCE_THRESHOLD", "5")
    revision = _revision("soft_bounce_threshold_repair")
    with _schema(SpamSuppression, SystemSetting) as isolated:
        _seed_suppressions(isolated)
        upgraded_at = datetime.utcnow()
        with caplog.at_level("WARNING", logger="app.migrations"):
            _upgrade(isolated, revision)
        _check_soft_bounces_lifted(isolated, upgraded_at)
        assert ("lifted 5 automatic soft-bounce suppression(s) (4 of them active) and reset their bounce counts; "
                "the Soft Bounce Threshold of 5 counts new bounces only") in caplog.text
        # Running it again changes nothing and says nothing
        caplog.clear()
        before = _suppressions(isolated)
        _upgrade(isolated, revision)
        assert _suppressions(isolated) == before
        assert "lifted" not in caplog.text


def test_the_threshold_saved_from_the_ui_is_reported(suppression_settings, caplog):
    from app.models import SpamSuppression
    suppression_settings.setenv("SETTINGS_EDIT_VIA_UI_ENABLED", "true")
    revision = _revision("soft_bounce_threshold_repair")
    with _schema(SpamSuppression, SystemSetting) as isolated:
        _seed_suppressions(isolated)
        with Session(isolated) as db:
            db.add(SystemSetting(key="config.suppression_soft_bounce_threshold", value="4"))
            db.commit()
        upgraded_at = datetime.utcnow()
        with caplog.at_level("WARNING", logger="app.migrations"):
            _upgrade(isolated, revision)
        _check_soft_bounces_lifted(isolated, upgraded_at)
        assert "the Soft Bounce Threshold of 4 counts new bounces only" in caplog.text


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
            for email, (_, _, soft, active) in SUPPRESSIONS.items():
                row = rows[email]
                assert (row.active, row.synced_to_rspamd) == (active, True), (action, email)
                assert (row.soft_bounce_count, row.expires_at) == (soft, EXPIRES), (action, email)


def test_after_the_upgrade_the_threshold_counts_new_bounces_only(suppression_settings, monkeypatch):
    """Threshold 3. An earlier version counted one real soft bounce twice
    (count 2, suppressed), and another recipient reached the threshold the
    same way. After the upgrade one new real soft bounce suppresses neither;
    the third new one does, with the expiry of three bounces."""
    from app.config import settings
    from app.models import SpamSuppression
    import app.scheduler as sch
    suppression_settings.setenv("SUPPRESSION_SOFT_BOUNCE_THRESHOLD", "3")
    for key, value in {
        "suppression_soft_bounce_action": "count", "suppression_soft_bounce_threshold": 3,
        "suppression_hard_bounce_action": "suppress", "suppression_whitelist_domains": "",
        "suppression_base_expiry_days": 7, "suppression_max_expiry_days": 90, "queue_cleanup_enabled": False,
    }.items():
        monkeypatch.setattr(settings._inner, key, value)
    revision = _revision("soft_bounce_threshold_repair")
    legacy = {"twice@example.com": 2, "at-threshold@example.com": 3}
    with _schema(SpamSuppression, SystemSetting, PostfixLog) as isolated:
        @contextmanager
        def isolated_db():
            db = Session(isolated, autoflush=False)
            try:
                yield db
                db.commit()
            finally:
                db.close()
        monkeypatch.setattr(sch, "get_db_context", isolated_db)
        now = datetime.utcnow()
        with Session(isolated) as db:
            for email, count in legacy.items():
                db.add(SpamSuppression(email=email, type="email", reason="soft_bounce", source="auto",
                                       bounce_count=count, soft_bounce_count=count, hard_bounce_count=0,
                                       active=True, synced_to_rspamd=True,
                                       expires_at=now + timedelta(days=7 * count)))
            db.commit()
        _upgrade(isolated, revision)

        def bounce(n):
            with Session(isolated) as db:
                stamp = datetime.utcnow()
                for i, email in enumerate(legacy):
                    db.add(PostfixLog(time=stamp, created_at=stamp, program="postfix/smtp", priority="info",
                                      message=f"deferred {n}", queue_id=f"Q{n}R{i}", recipient=email,
                                      status="deferred", dsn="4.4.1"))
                db.commit()
            sch._detect_suppressions_worker()
            return _suppressions(isolated)

        rows = bounce(1)
        for email in legacy:
            assert (rows[email].active, rows[email].soft_bounce_count, rows[email].bounce_count) == (False, 1, 1), email
        bounce(2)
        rows = bounce(3)
        for email in legacy:
            assert (rows[email].active, rows[email].soft_bounce_count) == (True, 3), email
            assert rows[email].expires_at < datetime.utcnow() + timedelta(days=21, minutes=1), email


# -- 0018: Sender Domain Contains rules an earlier edit escaped twice ----------

# The pattern the rule dialog saves for a Contains rule on example.com after
# an earlier version opened and saved it again (made by the real dialog code
# in .github/tests/queue-quarantine-actions.test.cjs)
TWICE_SAVED = r"example\\\.com"
REPAIRED = r"example\.com"
# A Sender Contains rule created once for the text a\.b: a quoted local part
# can hold that, so the same shape is not proof of damage there
SENDER_BACKSLASH = r"a\\\.b"
# A Subject Contains rule for Invoice.pdf an earlier edit escaped twice, and
# what its Repair button in the Auto-Rules list saves (queue-quarantine-actions.test.cjs)
SUBJECT_TWICE = r"Invoice\\\.pdf"
SUBJECT_REPAIRED = r"Invoice\.pdf"

# name -> (match_type, match_value, is_regex, value after the upgrade)
RULES = {
    "domain twice": ("sender_domain", TWICE_SAVED, True, REPAIRED),
    "domain three times": ("sender_domain", r"example\\\\\\\.com", True, REPAIRED),
    "domain once": ("sender_domain", r"example\.org", True, r"example\.org"),
    "sender twice": ("sender", r"user@example\\\.com", True, r"user@example\\\.com"),
    "sender backslash": ("sender", SENDER_BACKSLASH, True, SENDER_BACKSLASH),
    "recipient three times": ("recipient", r"user@example\\\\\\\.com", True, r"user@example\\\\\\\.com"),
    "plain text": ("sender", "noreply", True, "noreply"),
    "subject twice": ("subject", SUBJECT_TWICE, True, SUBJECT_TWICE),
    "regex": ("sender", r"^.*@(spam|junk)\.example$", True, r"^.*@(spam|junk)\.example$"),
    "regex with escapes": ("sender", r"a\\\.b|c", True, r"a\\\.b|c"),
    "regex digits": ("sender", r"invoice\\d+", True, r"invoice\\d+"),
    "exact": ("sender_domain", TWICE_SAVED, False, TWICE_SAVED),
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


def test_only_twice_escaped_sender_domain_rules_are_repaired(caplog):
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
        for name in ("domain twice", "domain three times"):
            assert _matches(after[name]), name
        assert caplog.text.count("Upgrade: repaired rule") == 2
        assert f"sender_domain pattern {TWICE_SAVED} is now {REPAIRED}" in caplog.text
        # Running it again changes nothing
        caplog.clear()
        _upgrade(isolated, revision)
        assert {n: r.match_value for n, r in _rules(isolated).items()} == {n: v[3] for n, v in RULES.items()}
        assert "repaired" not in caplog.text


def test_a_sender_rule_for_a_backslash_keeps_matching_it():
    from app.models import QuarantineRule
    revision = _revision("repair_twice_escaped_rules")
    quoted = r'"a\.b"@example.com'
    with _schema(QuarantineRule) as isolated:
        _seed_rules(isolated)
        assert _matches(_rules(isolated)["sender backslash"], sender=quoted)
        _upgrade(isolated, revision)
        rule = _rules(isolated)["sender backslash"]
        assert rule.match_value == SENDER_BACKSLASH
        assert _matches(rule, sender=quoted)
        assert not _matches(rule, sender="a.b@example.com")


def test_a_twice_escaped_subject_rule_is_left_for_its_repair_button():
    from app.models import QuarantineRule
    revision = _revision("repair_twice_escaped_rules")
    with _schema(QuarantineRule) as isolated:
        _seed_rules(isolated)
        _upgrade(isolated, revision)
        rule = _rules(isolated)["subject twice"]
        assert rule.match_value == SUBJECT_TWICE
        assert not _matches(rule, subject="Invoice.pdf")
        # What the Repair button saves matches the subject the rule was made for
        rule.match_value = SUBJECT_REPAIRED
        assert _matches(rule, subject="Invoice.pdf")
        assert not _matches(rule, subject="Invoice-pdf")
