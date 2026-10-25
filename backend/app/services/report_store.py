"""
Store parsed DMARC and TLS-RPT reports.

The IMAP import and the manual upload both store through here, so the same
report counts as a duplicate on both paths, and only when its whole content
is the same (services/report_identity.py). A report with a known report_id
but other content is stored next to the first one.
"""
import logging
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models import DMARCReport, DMARCRecord, TLSReport, TLSReportPolicy
from . import dmarc_parser, tls_rpt_parser
from .geoip_service import enrich_dmarc_record
from .report_identity import (
    DMARC_RECORD_KEY_FIELDS,
    DMARC_REPORT_FIELDS,
    TLS_POLICY_FIELDS,
    TLS_REPORT_FIELDS,
    dmarc_content_hash,
    report_data_size,
    tls_content_hash,
)

logger = logging.getLogger(__name__)

DMARC_RECORD_FIELDS = DMARC_RECORD_KEY_FIELDS + ('count',)

# Rows an older version wrote without a hash: at most this many are hashed
# when a report with their report_id arrives
UNHASHED_ROWS_PER_LOOKUP = 50


@dataclass(frozen=True)
class _Kind:
    report: type
    child: type
    parent_column: str
    constraint: str
    report_fields: tuple
    child_fields: tuple
    content_hash: object


KINDS = {
    'dmarc': _Kind(DMARCReport, DMARCRecord, 'dmarc_report_id', 'uq_dmarc_reports_report_id_hash',
                   DMARC_REPORT_FIELDS, DMARC_RECORD_FIELDS, dmarc_content_hash),
    'tls-rpt': _Kind(TLSReport, TLSReportPolicy, 'tls_report_id', 'uq_tls_reports_report_id_hash',
                     TLS_REPORT_FIELDS, TLS_POLICY_FIELDS, tls_content_hash),
}


@dataclass
class PreparedReport:
    """A parsed report with its identity, ready to store."""
    kind: str
    fields: Dict
    children: List[Dict]
    content_hash: str
    items: int
    size: int

    @property
    def report_id(self) -> str:
        return self.fields['report_id']


def prepare_report(kind: str, parsed: Dict) -> PreparedReport:
    spec = KINDS[kind]
    if kind == 'dmarc':
        fields = {name: parsed.get(name) for name in spec.report_fields}
        children = parsed.get('records', [])
        items = len(children)
    else:
        fields = {
            'report_id': parsed['report_id'],
            'organization_name': parsed.get('organization_name', 'Unknown'),
            'contact_info': parsed.get('contact_info', ''),
            'policy_domain': parsed['policy_domain'],
            'start_datetime': parsed['start_datetime'],
            'end_datetime': parsed['end_datetime'],
        }
        children = parsed.get('policies', [])
        items = len(children) + sum(len(p.get('failure_details') or []) for p in children)
    return PreparedReport(kind, fields, children, spec.content_hash(fields, children), items,
                          report_data_size(fields, spec.report_fields, children, spec.child_fields))


def prepare_report_file(kind: str, content: bytes, filename: str) -> Optional[PreparedReport]:
    """Parse a report file. None when it is not a report; ReportRejectedError
    (and its ReportLimitError) when it must not be imported, with the reason."""
    if kind == 'dmarc':
        parsed = dmarc_parser.parse_dmarc_file(content, filename)
    else:
        parsed = tls_rpt_parser.parse_tls_rpt_file(content, filename)
    return prepare_report(kind, parsed) if parsed else None


def _constraint(error: IntegrityError) -> Optional[str]:
    return getattr(getattr(error.orig, 'diag', None), 'constraint_name', None)


def _same_report(db: Session, spec: _Kind, report_id: str, content_hash: str):
    return db.query(spec.report).filter(
        spec.report.report_id == report_id, spec.report.content_hash == content_hash,
    ).first()


def stored_content_hash(db: Session, kind: str, row) -> str:
    """The content hash of a stored report, computed from its stored rows."""
    spec = KINDS[kind]
    report = {name: getattr(row, name) for name in spec.report_fields}
    children = db.query(*(getattr(spec.child, name) for name in spec.child_fields)).filter(
        getattr(spec.child, spec.parent_column) == row.id)
    return spec.content_hash(report, (child._asdict() for child in children))


def _hash_unhashed(db: Session, spec: _Kind, kind: str, prepared: PreparedReport):
    """Give rows with this report_id and no hash their hash; the one equal to the
    incoming report, if any. A row whose hash another row already has stays
    without one: it is the same report, stored twice by an older version."""
    rows = db.query(spec.report).filter(
        spec.report.report_id == prepared.report_id, spec.report.content_hash.is_(None),
    ).order_by(spec.report.id).limit(UNHASHED_ROWS_PER_LOOKUP).all()
    match = None
    for row in rows:
        content_hash = stored_content_hash(db, kind, row)
        if match is None and content_hash == prepared.content_hash:
            match = row
        try:
            with db.begin_nested():
                row.content_hash = content_hash
                db.flush()
        except IntegrityError as e:
            if _constraint(e) != spec.constraint:
                raise
    return match


def store_report(db: Session, prepared: PreparedReport) -> Tuple[str, object]:
    """('created', row), ('conflict', row) when it was stored next to another
    report with the same report_id, or ('duplicate', the stored row).
    Flushes, never commits."""
    spec = KINDS[prepared.kind]
    existing = _same_report(db, spec, prepared.report_id, prepared.content_hash)
    if existing is None:
        existing = _hash_unhashed(db, spec, prepared.kind, prepared)
    if existing is not None:
        logger.info(f"Duplicate {prepared.kind} report: {prepared.report_id}")
        return 'duplicate', existing

    try:
        with db.begin_nested():
            report = spec.report(**prepared.fields, content_hash=prepared.content_hash)
            db.add(report)
            db.flush()
            for child in prepared.children:
                row = {name: child.get(name) for name in spec.child_fields}
                row[spec.parent_column] = report.id
                if prepared.kind == 'dmarc':
                    row = enrich_dmarc_record(row)
                db.add(spec.child(**row))
            db.flush()
    except IntegrityError as e:
        # The same report stored at the same moment by another import
        if _constraint(e) != spec.constraint:
            raise
        existing = _same_report(db, spec, prepared.report_id, prepared.content_hash)
        if existing is None:
            raise
        return 'duplicate', existing

    if db.query(spec.report.id).filter(
            spec.report.report_id == prepared.report_id, spec.report.id != report.id).first():
        logger.warning(f"{prepared.kind} report {prepared.report_id} from {report_sender(report)} has the "
                       f"report ID of another stored report with different content; both are kept")
        return 'conflict', report
    logger.info(f"Created {prepared.kind} report: {prepared.report_id}")
    return 'created', report


def report_sender(report) -> str:
    return getattr(report, 'org_name', None) or getattr(report, 'organization_name', None) or 'unknown'


def conflicting_report_ids(db: Session, kind: str, report_ids: Iterable[str]) -> Set[str]:
    """The report IDs among these that more than one stored report of this kind has."""
    report_ids = {report_id for report_id in report_ids if report_id}
    if not report_ids:
        return set()
    model = KINDS[kind].report
    return {row[0] for row in db.query(model.report_id).filter(
        model.report_id.in_(report_ids)).group_by(model.report_id).having(func.count(model.id) > 1)}
