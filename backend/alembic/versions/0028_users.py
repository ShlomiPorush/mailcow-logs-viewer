"""Users: people who sign in with their own access (issue #544).

Creates users: local users (a username and a password hash) and OAuth2
entries (an email that gets its own access instead of the OAuth2 default).
Nothing is added for an installation that does not create users: the
built-in admin keeps signing in as before, and so does everyone OAuth2 lets
in. The app's start creates the table from the models first, so the table,
each check and each index is only created when missing.

Revision ID: 0028
Revises: 0027
Create Date: 2026-10-29
"""
from alembic import op
import sqlalchemy as sa


revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None

CHECKS = {
    "ck_users_kind": "kind IN ('local', 'oauth2')",
    "ck_users_access": "access IN ('admin', 'operator', 'viewer', 'custom')",
    "ck_users_local": "kind <> 'local' OR (username_norm IS NOT NULL AND password_hash IS NOT NULL "
                      "AND email IS NULL AND email_norm IS NULL)",
    "ck_users_oauth2": "kind <> 'oauth2' OR (email_norm IS NOT NULL AND password_hash IS NULL)",
}
INDEXES = {
    "ux_users_local_username": ("username_norm", "kind = 'local'"),
    "ux_users_oauth2_email": ("email_norm", "kind = 'oauth2'"),
}


def upgrade() -> None:
    bind = op.get_bind()
    if "users" not in sa.inspect(bind).get_table_names():
        op.create_table(
            "users",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("kind", sa.String(10), nullable=False),
            sa.Column("username", sa.String(64)),
            sa.Column("username_norm", sa.String(64)),
            sa.Column("email", sa.String(320)),
            sa.Column("email_norm", sa.String(320)),
            sa.Column("password_hash", sa.String(255)),
            sa.Column("access", sa.String(10), nullable=False),
            sa.Column("scopes", sa.Text, nullable=False),
            sa.Column("disabled", sa.Boolean, nullable=False, server_default=sa.text("false")),
            sa.Column("auth_version", sa.Integer, nullable=False, server_default=sa.text("1")),
            sa.Column("row_version", sa.Integer, nullable=False, server_default=sa.text("1")),
            sa.Column("created_at", sa.DateTime, nullable=False),
            sa.Column("updated_at", sa.DateTime, nullable=False),
            sa.Column("last_login_at", sa.DateTime),
        )
    inspector = sa.inspect(bind)
    checks = {c["name"] for c in inspector.get_check_constraints("users")}
    for name, condition in CHECKS.items():
        if name not in checks:
            op.create_check_constraint(name, "users", condition)
    indexes = {i["name"] for i in inspector.get_indexes("users")}
    for name, (column, where) in INDEXES.items():
        if name not in indexes:
            op.create_index(name, "users", [column], unique=True, postgresql_where=sa.text(where))


def downgrade() -> None:
    op.drop_table("users")
