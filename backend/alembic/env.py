"""Alembic environment - wired to the application's settings and models."""
import sys
from pathlib import Path

from alembic import context
from sqlalchemy import create_engine, pool

# Make `app` importable: backend/ locally, /app inside the container
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings   # noqa: E402
from app.models import Base       # noqa: E402

config = context.config

# Autogenerate compares this metadata against the live database.
# NOTE: installs migrated from the legacy migrations.py may carry extra
# indexes/constraints that models.py doesn't declare - review diffs carefully.
target_metadata = Base.metadata


def get_url() -> str:
    # Allow override via -x db_url=... or sqlalchemy.url, else app settings
    return (
        context.get_x_argument(as_dictionary=True).get("db_url")
        or config.get_main_option("sqlalchemy.url")
        or settings.database_url
    )


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of executing (alembic upgrade --sql)."""
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_engine(get_url(), poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
