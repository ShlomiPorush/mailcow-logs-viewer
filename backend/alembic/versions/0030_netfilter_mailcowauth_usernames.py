"""Read the username of the failed logins mailcow 2026-11 reports to netfilter.

Since mailcow 2026-11 every failed IMAP, POP3, Sieve and SMTP login reaches
netfilter as "MAILCOWAUTH: Login failed for user <username> with service
<service> from IP <address>". Earlier versions of this app read the username
only from Postfix's sasl_username=, so the lines stored before this version
have none, and the protection rules, the failed-login alerts and the Security
page could not tell who was tried. This sets the username and the 'warning'
action that a rule match is stored with now. Bans and alerts are not run again
for these lines.

The pattern is a frozen copy of app/services/netfilter_address.py
(_MAILCOWAUTH_FAILURE).

Revision ID: 0030
Revises: 0029
Create Date: 2026-11-09
"""
import logging
import re

from alembic import op
from sqlalchemy import text


revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None

logger = logging.getLogger("app.migrations")

BATCH = 500

_MAILCOWAUTH_FAILURE = re.compile(
    r'^\S+ matched rule id \d+ \(MAILCOWAUTH: Login failed for user (.*) '
    r'with service ([a-z0-9]*) from IP [0-9a-f.:]+\)\Z', re.S)


def upgrade():
    conn = op.get_bind()
    last_id = 0
    updated = 0
    while True:
        rows = conn.execute(text(
            "SELECT id, message FROM netfilter_logs "
            "WHERE id > :last AND username IS NULL "
            "AND message LIKE '% matched rule id % (MAILCOWAUTH: Login failed for user %' "
            "ORDER BY id LIMIT :batch"), {"last": last_id, "batch": BATCH}).fetchall()
        if not rows:
            break
        last_id = rows[-1].id
        for row in rows:
            match = _MAILCOWAUTH_FAILURE.match(row.message or '')
            if not match or not match.group(1):
                continue
            conn.execute(text(
                "UPDATE netfilter_logs SET username = :username, action = 'warning' WHERE id = :id"),
                {"username": match.group(1)[:255], "id": row.id})
            updated += 1
    if updated:
        logger.info(f"Read the username of {updated} failed logins in the Netfilter log")


def downgrade():
    pass
