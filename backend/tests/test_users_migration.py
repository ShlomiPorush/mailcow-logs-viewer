"""Migration 0028 (users): safe on a fresh database, after the start's create_all, and on a half-made table."""
import importlib.util
import pathlib
import uuid

import pytest
from sqlalchemy import create_engine, inspect, text

from app.models import User

CHECKS = {"ck_users_kind", "ck_users_access", "ck_users_local", "ck_users_oauth2"}
INDEXES = {"ux_users_local_username", "ux_users_oauth2_email"}


def _revision():
    path = next((pathlib.Path(__file__).resolve().parent.parent / "alembic" / "versions").glob("0028_*.py"))
    spec = importlib.util.spec_from_file_location("users_revision", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def isolated():
    from app.database import engine
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    schema = "users_migration_" + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    isolated = create_engine(engine.url, connect_args={"options": f"-csearch_path={schema}"})
    try:
        yield isolated
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))


def _upgrade(engine):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    revision = _revision()
    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            revision.upgrade()


def _shape(engine):
    inspector = inspect(engine)
    checks = {c["name"] for c in inspector.get_check_constraints("users")}
    indexes = {i["name"]: i for i in inspector.get_indexes("users")}
    return checks, indexes


def _assert_complete(engine):
    checks, indexes = _shape(engine)
    assert CHECKS <= checks
    assert INDEXES <= set(indexes)
    for name in INDEXES:
        assert indexes[name]["unique"]
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO users (kind, username, username_norm, password_hash, access, scopes, "
                          "created_at, updated_at) VALUES ('local', 'Alice', 'alice', 'h', 'viewer', '', now(), now())"))
        # The same name is unique among local users only
        conn.execute(text("INSERT INTO users (kind, email, email_norm, access, scopes, created_at, updated_at) "
                          "VALUES ('oauth2', 'alice', 'alice', 'viewer', '', now(), now())"))
        row = conn.execute(text("SELECT disabled, auth_version, row_version FROM users WHERE kind = 'local'")).one()
        assert tuple(row) == (False, 1, 1)
    for bad in (
        # A second local user with the same name
        "INSERT INTO users (kind, username, username_norm, password_hash, access, scopes, created_at, updated_at) "
        "VALUES ('local', 'ALICE', 'alice', 'h', 'viewer', '', now(), now())",
        # A local user without a password, or with an email
        "INSERT INTO users (kind, username_norm, access, scopes, created_at, updated_at) "
        "VALUES ('local', 'bob', 'viewer', '', now(), now())",
        "INSERT INTO users (kind, username_norm, password_hash, email, access, scopes, created_at, updated_at) "
        "VALUES ('local', 'bob', 'h', 'bob@example.com', 'viewer', '', now(), now())",
        # An OAuth2 entry with a password, or without an email
        "INSERT INTO users (kind, email_norm, password_hash, access, scopes, created_at, updated_at) "
        "VALUES ('oauth2', 'bob@example.com', 'h', 'viewer', '', now(), now())",
        "INSERT INTO users (kind, access, scopes, created_at, updated_at) VALUES ('oauth2', 'viewer', '', now(), now())",
        # Unknown kind or access
        "INSERT INTO users (kind, email_norm, access, scopes, created_at, updated_at) "
        "VALUES ('ldap', 'x@example.com', 'viewer', '', now(), now())",
        "INSERT INTO users (kind, email_norm, access, scopes, created_at, updated_at) "
        "VALUES ('oauth2', 'x@example.com', 'root', '', now(), now())",
    ):
        with pytest.raises(Exception):
            with engine.begin() as conn:
                conn.execute(text(bad))


def test_a_fresh_database_gets_the_whole_table(isolated):
    _upgrade(isolated)
    _assert_complete(isolated)


def test_after_the_start_created_the_table_from_the_model_it_changes_nothing(isolated):
    User.__table__.create(isolated)
    before = _shape(isolated)
    _upgrade(isolated)
    assert _shape(isolated) == before
    _assert_complete(isolated)


def test_a_table_without_its_checks_and_indexes_gets_them(isolated):
    with isolated.begin() as conn:
        conn.execute(text(
            "CREATE TABLE users (id SERIAL PRIMARY KEY, kind VARCHAR(10) NOT NULL, username VARCHAR(64), "
            "username_norm VARCHAR(64), email VARCHAR(320), email_norm VARCHAR(320), password_hash VARCHAR(255), "
            "access VARCHAR(10) NOT NULL, scopes TEXT NOT NULL, disabled BOOLEAN NOT NULL DEFAULT false, "
            "auth_version INTEGER NOT NULL DEFAULT 1, row_version INTEGER NOT NULL DEFAULT 1, "
            "created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, last_login_at TIMESTAMP)"))
    _upgrade(isolated)
    _assert_complete(isolated)


def test_running_it_twice_is_harmless(isolated):
    _upgrade(isolated)
    _upgrade(isolated)
    _assert_complete(isolated)
