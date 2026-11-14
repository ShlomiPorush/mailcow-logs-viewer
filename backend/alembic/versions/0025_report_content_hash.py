"""Identify DMARC and TLS-RPT reports by their content, not by report_id alone.

The report_id is written in the report by its sender, so anyone who can mail
the report address could store a report under the report_id a real reporter
uses later, and the real report was then dropped as a duplicate. Reports now
carry a SHA-256 of their whole content (content_hash), and only the same
report_id with the same content is the same report.

Adds content_hash to dmarc_reports and tls_reports and computes it for the
stored reports, so a report stored before the upgrade still counts as a
duplicate when it arrives again. The unique report_id (a constraint on
installs from the legacy migrations, a unique index on newer ones) becomes
UNIQUE (report_id, content_hash). content_hash stays nullable so an older
version can still store reports; the app computes missing ones when needed.

The fresh-install start creates these tables from the models first, so every
step only runs when it is still needed.

Revision ID: 0025
Revises: 0024
Create Date: 2026-10-25
"""
import hashlib
import itertools
import json
import math
from datetime import datetime
from decimal import Decimal
from typing import Mapping

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None

BATCH = 500

# -- Frozen copy of the content hash in app/services/report_identity.py ------
# It must produce the same hash as the app for the same report.

DMARC_REPORT_FIELDS = ('report_id', 'org_name', 'email', 'extra_contact_info', 'domain',
                       'begin_date', 'end_date', 'policy_published')
DMARC_RECORD_KEY_FIELDS = ('source_ip', 'disposition', 'dkim_result', 'spf_result',
                           'header_from', 'envelope_from', 'envelope_to', 'auth_results')
TLS_REPORT_FIELDS = ('report_id', 'organization_name', 'contact_info', 'policy_domain',
                     'start_datetime', 'end_datetime')
TLS_POLICY_FIELDS = ('policy_type', 'policy_domain', 'policy_string', 'mx_host',
                     'successful_session_count', 'failed_session_count', 'failure_details')


def _number(value) -> str:
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("not finite")
        number = Decimal(repr(value))
    else:
        number = Decimal(value)
    if number == 0:
        return "0"
    if number == number.to_integral_value():
        return str(int(number))
    return str(number.normalize())


def canonical(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, datetime):
        return json.dumps(value.isoformat())
    if isinstance(value, Mapping):
        return "{" + ",".join(f"{json.dumps(str(key))}:{canonical(item)}"
                              for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical(item) for item in value) + "]"
    raise ValueError("unsupported type")


def _fields(row, names) -> str:
    return canonical({name: row.get(name) for name in names})


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _content_hash(header, entries) -> str:
    return _digest(header + "\n" + "\n".join(sorted(entries)))


def dmarc_content_hash(report, records) -> str:
    counts = {}
    for record in records:
        key = _digest(_fields(record, DMARC_RECORD_KEY_FIELDS))
        counts[key] = counts.get(key, 0) + int(record.get('count') or 0)
    return _content_hash(_fields(report, DMARC_REPORT_FIELDS),
                         (f"{key}:{count}" for key, count in counts.items()))


def tls_content_hash(report, policies) -> str:
    return _content_hash(_fields(report, TLS_REPORT_FIELDS),
                         (_digest(_fields(policy, TLS_POLICY_FIELDS)) for policy in policies))

# -----------------------------------------------------------------------------

TABLES = (
    # table, child table, parent column, report fields, child fields, JSON columns, hash, constraint
    ("dmarc_reports", "dmarc_records", "dmarc_report_id", DMARC_REPORT_FIELDS,
     DMARC_RECORD_KEY_FIELDS + ('count',), ('policy_published', 'auth_results'), dmarc_content_hash,
     "uq_dmarc_reports_report_id_hash"),
    ("tls_reports", "tls_report_policies", "tls_report_id", TLS_REPORT_FIELDS,
     TLS_POLICY_FIELDS, ('policy_string', 'mx_host', 'failure_details'), tls_content_hash,
     "uq_tls_reports_report_id_hash"),
)


def _select(sql, names, json_columns):
    # JSONB read back as the app reads it (the same JSON decoding)
    return sa.text(sql).columns(**{name: JSONB for name in names if name in json_columns})


def backfill(bind, table, child, parent, report_fields, child_fields, json_columns, content_hash):
    """Hash the reports without a hash, BATCH reports at a time. Children are
    streamed in report order, so memory holds one report's digests at a time."""
    last = 0
    while True:
        reports = bind.execute(_select(
            f"SELECT id, {', '.join(report_fields)} FROM {table} "
            f"WHERE content_hash IS NULL AND id > :last ORDER BY id LIMIT :n",
            report_fields, json_columns), {"last": last, "n": BATCH}).mappings().all()
        if not reports:
            return
        ids = [row["id"] for row in reports]
        children = bind.execute(_select(
            f"SELECT {parent}, {', '.join(child_fields)} FROM {child} "
            f"WHERE {parent} = ANY(:ids) ORDER BY {parent}",
            child_fields, json_columns).execution_options(stream_results=True, yield_per=2000),
            {"ids": ids}).mappings()
        hashes = {}
        by_report = {row["id"]: row for row in reports}
        for report_id, rows in itertools.groupby(children, key=lambda row: row[parent]):
            hashes[report_id] = content_hash(by_report[report_id], rows)
        for report_id in ids:
            if report_id not in hashes:
                hashes[report_id] = content_hash(by_report[report_id], ())
        bind.execute(sa.text(f"UPDATE {table} SET content_hash = :hash WHERE id = :id"),
                     [{"id": report_id, "hash": value} for report_id, value in hashes.items()])
        last = ids[-1]


def upgrade() -> None:
    bind = op.get_bind()
    for table, child, parent, report_fields, child_fields, json_columns, content_hash, constraint in TABLES:
        inspector = sa.inspect(bind)
        if "content_hash" not in {c["name"] for c in inspector.get_columns(table)}:
            op.add_column(table, sa.Column("content_hash", sa.String(64)))

        backfill(bind, table, child, parent, report_fields, child_fields, json_columns, content_hash)

        # The unique report_id: a constraint (legacy installs) or a unique index
        for unique in sa.inspect(bind).get_unique_constraints(table):
            if unique["column_names"] == ["report_id"]:
                op.drop_constraint(unique["name"], table, type_="unique")
        for index in sa.inspect(bind).get_indexes(table):
            if index["column_names"] == ["report_id"]:
                op.drop_index(index["name"], table_name=table)

        if constraint not in {u["name"] for u in sa.inspect(bind).get_unique_constraints(table)}:
            op.create_unique_constraint(constraint, table, ["report_id", "content_hash"])


def downgrade() -> None:
    # Not the old unique report_id: two reports may share a report_id by now
    for table, *_, constraint in TABLES:
        op.drop_constraint(constraint, table, type_="unique")
        op.drop_column(table, "content_hash")
        op.create_index(f"ix_{table}_report_id", table, ["report_id"])
