"""Repair Sender Domain rules whose Contains text an earlier edit escaped twice.

A Contains rule is stored as a regex that only escapes its text
(example.com -> example\\.com). Earlier versions opened such a rule with the
stored pattern as its text and escaped it again on save
(example\\\\\\.com), so it stopped matching. A domain cannot contain a
backslash, so on a Sender Domain rule a pattern that only escapes a text
that itself only escapes a text was saved twice; one level is removed until
that is no longer the case. Sender, Recipient and Subject rules can be
meant to look for a backslash (a quoted local part can hold one), so they
are left as they are; the Auto-Rules list flags them with a Repair button.
Real regexes are left as they are.

Revision ID: 0018
Revises: 0017
Create Date: 2026-10-16
"""
import logging

from alembic import op
from sqlalchemy import text


revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None

logger = logging.getLogger("app.migrations")

# What the rule dialog escapes for a Contains rule (frontend/app.js)
SPECIAL = set(".*+?^${}()|[]\\")
FIELDS = ("sender_domain",)


def unescape(value):
    """The text a Contains rule escaped into value, or None if value is not that."""
    out, i = [], 0
    while i < len(value):
        if value[i] == "\\" and i + 1 < len(value) and value[i + 1] in SPECIAL:
            out.append(value[i + 1])
            i += 2
        elif value[i] in SPECIAL:
            return None
        else:
            out.append(value[i])
            i += 1
    return "".join(out)


def repaired(value):
    while True:
        once = unescape(value)
        if once is None or once == value or unescape(once) is None:
            return value
        value = once


def upgrade() -> None:
    bind = op.get_bind()
    rules = bind.execute(text(
        "SELECT id, name, match_type, match_value FROM quarantine_rules "
        "WHERE is_regex AND match_type = ANY(:fields) ORDER BY id"
    ), {"fields": list(FIELDS)}).all()
    for rule in rules:
        fixed = repaired(rule.match_value)
        if fixed == rule.match_value:
            continue
        bind.execute(text("UPDATE quarantine_rules SET match_value = :value WHERE id = :id"),
                     {"value": fixed, "id": rule.id})
        logger.warning(
            f"[QUARANTINE RULES] Upgrade: repaired rule '{rule.name}' (id {rule.id}), "
            f"{rule.match_type} pattern {rule.match_value} is now {fixed}"
        )


def downgrade() -> None:
    # The twice-escaped patterns are not restored
    pass
