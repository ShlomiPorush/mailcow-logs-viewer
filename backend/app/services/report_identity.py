import hashlib
import json
import math
import zipfile
from datetime import datetime
from decimal import Decimal
from io import BytesIO
from typing import Iterable, Mapping, Optional

MAX_REPORT_ATTACHMENTS_PER_EMAIL = 10
MAX_REPORT_ITEMS = 20_000
MAX_REPORT_DATA_BYTES = 10 * 1024 * 1024

REPORT_TOO_LARGE = "The report is larger than 10 MB, or expands to more than 10 MB."

MAX_STORED_COUNT = 2**31 - 1

DMARC_REPORT_FIELDS = ('report_id', 'org_name', 'email', 'extra_contact_info', 'domain',
                       'begin_date', 'end_date', 'policy_published')
DMARC_RECORD_KEY_FIELDS = ('source_ip', 'disposition', 'dkim_result', 'spf_result',
                           'header_from', 'envelope_from', 'envelope_to', 'auth_results')
TLS_REPORT_FIELDS = ('report_id', 'organization_name', 'contact_info', 'policy_domain',
                     'start_datetime', 'end_datetime')
TLS_POLICY_FIELDS = ('policy_type', 'policy_domain', 'policy_string', 'mx_host',
                     'successful_session_count', 'failed_session_count', 'failure_details')


class ReportRejectedError(ValueError):
    pass


class ReportLimitError(ReportRejectedError):
    pass


def _number(value) -> str:
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ReportRejectedError("The report has a number that is not finite.")
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
    raise ReportRejectedError("The report has a value of an unsupported type.")


def _fields(row: Mapping, names) -> str:
    return canonical({name: row.get(name) for name in names})


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def dmarc_record_key(record: Mapping) -> str:
    return _fields(record, DMARC_RECORD_KEY_FIELDS)


def _content_hash(header: str, entries: Iterable[str]) -> str:
    return _digest(header + "\n" + "\n".join(sorted(entries)))


def dmarc_content_hash(report: Mapping, records: Iterable[Mapping]) -> str:
    counts = {}
    for record in records:
        key = _digest(dmarc_record_key(record))
        counts[key] = counts.get(key, 0) + int(record.get('count') or 0)
    return _content_hash(_fields(report, DMARC_REPORT_FIELDS),
                         (f"{key}:{count}" for key, count in counts.items()))


def tls_content_hash(report: Mapping, policies: Iterable[Mapping]) -> str:
    return _content_hash(_fields(report, TLS_REPORT_FIELDS),
                         (_digest(_fields(policy, TLS_POLICY_FIELDS)) for policy in policies))


def report_data_size(report: Mapping, report_fields, children: Iterable[Mapping], child_fields) -> int:
    return len(_fields(report, report_fields)) + sum(len(_fields(child, child_fields)) for child in children)


def zip_report_member(archive: zipfile.ZipFile, extension: str) -> Optional[str]:
    reports = [name for name in archive.namelist() if name.lower().endswith(('.xml', '.json'))]
    if len(reports) > 1:
        raise ReportRejectedError("The ZIP file holds more than one report. Send each report in its own file.")
    if reports and reports[0].lower().endswith(extension):
        return reports[0]
    return None


def report_kind(filename: str, content: bytes) -> str:
    if filename.lower().endswith(('.json', '.json.gz', '.json.zip')):
        return 'tls-rpt'
    if content[:4] != b'PK\x03\x04':
        return 'dmarc'
    try:
        with zipfile.ZipFile(BytesIO(content)) as archive:
            names = [name.lower() for name in archive.namelist()]
    except zipfile.BadZipFile:
        return 'dmarc'
    if any(n.endswith('.json') for n in names) and not any(n.endswith('.xml') for n in names):
        return 'tls-rpt'
    return 'dmarc'


class ReportBudget:

    def __init__(self):
        self.items = 0
        self.size = 0

    def add(self, items: int, size: int):
        self.items += items
        self.size += size
        if self.items > MAX_REPORT_ITEMS:
            raise ReportLimitError(f"The reports have more than {MAX_REPORT_ITEMS:,} records.")
        if self.size > MAX_REPORT_DATA_BYTES:
            raise ReportLimitError(
                f"The reports hold more than {MAX_REPORT_DATA_BYTES // (1024 * 1024)} MB of data.")
