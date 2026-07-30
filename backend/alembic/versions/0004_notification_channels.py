"""Add notification_channels table (multiple alert destinations).

Also migrates a legacy single-webhook ENV/DB configuration into a channel row
so existing setups keep working without any manual step.

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-27
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_exists = "notification_channels" in set(inspector.get_table_names())

    # init_db() runs Base.metadata.create_all() before Alembic, so on both
    # fresh installs and upgrades the table usually already exists here. The
    # legacy-webhook migration below must therefore NOT hide behind the DDL
    # guard - it runs whenever the table is still empty.
    if not table_exists:
        _create_table()

    count = bind.execute(sa.text("SELECT COUNT(*) FROM notification_channels")).scalar()
    if count == 0:
        _migrate_legacy_webhook(bind)


def _create_table() -> None:
    op.create_table(
        "notification_channels",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("channel_type", sa.String(30), nullable=False),
        sa.Column("config", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("last_status", sa.String(20)),
        sa.Column("last_error", sa.Text),
        sa.Column("last_sent_at", sa.DateTime),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime),
    )
    op.create_index("ix_notification_channels_enabled", "notification_channels", ["enabled"])


def _read_db_webhook_overrides(bind) -> dict:
    """webhook_* values a 2.6.4-dev build may have saved through the UI.

    DB overrides are applied to the settings object only AFTER Alembic runs
    (main.py loads them post-migration), so they must be read straight from
    system_settings here. Values are stored as plain strings ("true"/"false"
    for booleans) under keys config.<field_name>."""
    try:
        rows = bind.execute(sa.text(
            "SELECT key, value FROM system_settings WHERE key LIKE 'config.webhook%'"
        )).fetchall()
        return {key[len("config."):]: (value or "") for key, value in rows}
    except Exception:
        return {}


def _migrate_legacy_webhook(bind) -> None:
    """Carry a previously configured single webhook over to a channel row."""
    try:
        from app.config import settings
    except Exception:
        return

    db_vals = _read_db_webhook_overrides(bind)

    url = (db_vals.get("webhook_url") or getattr(settings, "webhook_url", "") or "").strip()
    if not url:
        return

    wtype = ((db_vals.get("webhook_type") or getattr(settings, "webhook_type", "") or "generic")
             .strip().lower() or "generic")
    chat_id = (db_vals.get("webhook_telegram_chat_id")
               or getattr(settings, "webhook_telegram_chat_id", "") or "").strip()
    if "webhook_enabled" in db_vals:
        enabled = db_vals["webhook_enabled"].strip().lower() in ("true", "1", "yes")
    else:
        enabled = bool(getattr(settings, "webhook_enabled", False))

    # Map the old flat settings onto the per-type config shape
    if wtype == "telegram":
        token = ""
        if "/bot" in url:
            token = url.split("/bot", 1)[1].split("/", 1)[0]
        config = {"bot_token": token, "chat_id": chat_id}
        channel_type = "telegram"
    elif wtype in ("slack", "discord"):
        config = {"webhook_url": url}
        channel_type = wtype
    elif wtype == "ntfy":
        # https://server/topic -> server + topic
        trimmed = url.rstrip("/")
        parts = trimmed.rsplit("/", 1)
        config = {"server_url": parts[0] if len(parts) == 2 else "https://ntfy.sh",
                  "topic": parts[1] if len(parts) == 2 else ""}
        channel_type = "ntfy"
    elif wtype == "gotify":
        base, _, query = url.partition("?")
        token = ""
        if query.startswith("token="):
            token = query.split("token=", 1)[1]
        config = {"server_url": base.replace("/message", "").rstrip("/"), "app_token": token}
        channel_type = "gotify"
    else:
        config = {"url": url}
        channel_type = "webhook"

    import json
    from datetime import datetime
    bind.execute(
        sa.text(
            "INSERT INTO notification_channels "
            "(name, channel_type, config, enabled, created_at) "
            "VALUES (:name, :channel_type, CAST(:config AS JSONB), :enabled, :created_at)"
        ),
        {
            "name": f"{channel_type.capitalize()} (migrated)",
            "channel_type": channel_type,
            "config": json.dumps(config),
            "enabled": enabled,
            "created_at": datetime.utcnow(),
        },
    )


def downgrade() -> None:
    op.drop_table("notification_channels")
