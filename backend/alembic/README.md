# Schema migrations (Alembic)

As of v2.6.4, **all new schema changes are Alembic revisions in `versions/`**.
The legacy startup migrations in `app/migrations.py` are frozen at their
v2.6.3 state - do not add new ones there.

## How it runs

On startup (`app/main.py` lifespan) the app runs, in order:

1. `init_db()` - `create_all()` for brand-new tables (fresh installs)
2. `run_migrations()` - the frozen legacy migrations (idempotent)
3. `alembic upgrade head` - applies any pending revisions in `versions/`

The `0001` baseline revision is a no-op that marks the v2.6.3 schema state,
so existing installs adopt Alembic without any schema change.

## Adding a schema change

From `backend/` with the app's `POSTGRES_*`/`MAILCOW_*` env vars set
(easiest inside the container):

```bash
# empty revision you fill in yourself (preferred for small changes):
alembic revision -m "add foo column to bar"

# or autogenerate a diff against app/models.py - ALWAYS review the output:
# installs migrated from the legacy path carry indexes/constraints that
# models.py does not declare, and autogenerate will try to drop them.
alembic revision --autogenerate -m "add foo column to bar"
```

Then edit the new file in `versions/`, update `app/models.py` to match, and
restart the app (or run `alembic upgrade head`).

## Useful commands

```bash
alembic current            # revision the DB is at
alembic history            # list revisions
alembic upgrade head       # apply pending revisions
alembic downgrade -1       # revert the last revision
alembic upgrade head --sql # print SQL without executing
```
