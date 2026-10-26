"""What the DMARC & TLS calls return (routers/dmarc.py).

Unix timestamps are seconds. A day (`date`) is YYYY-MM-DD in the app's time
zone unless a field says otherwise. A pass is aligned SPF or aligned DKIM
passing (RFC 7489).
"""
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field

from . import Fixed

TIME = "UTC, ISO 8601 with Z"
GEO = "From the GeoIP database; null when it has no answer or is not installed"
PAGES = "0 without data"


class StatusMessage(Fixed):
    status: str = Field(description="success")
    message: str


# ---------------------------------------------------------------- insights

class Recommendation(Fixed):
    type: str = Field(description="low_pass_rate, already_strict, insufficient_volume, tighten_policy or monitor")
    severity: str = Field(description="warning, info or success")
    message: str
    current_policy: str = Field(None, description="Only for tighten_policy")
    recommended_policy: str = Field(None, description="Only for tighten_policy: the next stricter policy")


class NewSource(Fixed):
    source_ip: str
    failing_messages: int
    first_seen_window_days: int = Field(description="Seen only in this many recent days")


class DomainInsights(Fixed):
    """One domain's policy advice and new failing sources. Without reports in the window, only domain,
    has_data (false), recommendations and new_sources (both empty)."""
    domain: str
    has_data: bool
    window_days: int = Field(None, description="Only with data")
    current_policy: str = Field(None, description="p of the latest report: none, quarantine or reject. Only with data")
    total_messages: int = Field(None, description="Only with data")
    pass_rate: float = Field(None, description="Percent. Only with data")
    recommendations: List[Recommendation]
    new_sources: List[NewSource] = Field(description="Addresses failing DMARC that only started sending recently, "
                                                     "most messages first, at most 20")


class AllInsights(Fixed):
    """Every domain with reports in the window, those that need action first."""
    window_days: int
    domain_count: int
    insights: List[DomainInsights]


# ---------------------------------------------------------------- reports management

class ReportsConfig(Fixed):
    allow_delete: bool = Field(description="From DMARC_ALLOW_REPORT_DELETE")


class ReportSummary(Fixed):
    id: int = Field(description="The database ID")
    type: str = Field(description="dmarc or tls")
    domain: str
    org_name: Optional[str] = Field(description="The reporter")
    begin_date: Optional[int] = Field(description="Unix time")
    end_date: Optional[int] = Field(description="Unix time")
    record_count: int = Field(description="Records (DMARC) or policies (TLS)")
    created_at: Optional[str] = Field(description="Import time, " + TIME)
    report_id: str = Field(description="The report ID the sender gave")
    shared_report_id: bool = Field(description="Another report of the same type has this report_id and other content")


class AllReports(Fixed):
    """Without page: every matching report, newest import first."""
    reports: List[ReportSummary]
    total: int
    allow_delete: bool


class AllReportsPage(Fixed):
    """With page: one page, sorted across both types before paging."""
    reports: List[ReportSummary]
    total: int
    page: int = Field(description="Clamped to the last page")
    limit: int
    total_pages: int = Field(description="At least 1")
    sort_by: str
    sort_dir: str
    allow_delete: bool


class DomainReportCount(Fixed):
    domain: str = Field(description="Trimmed, in lower case")
    dmarc_reports: int
    tls_reports: int
    last_report: Optional[int] = Field(description="End of the latest report period (DMARC or TLS), Unix time")


class ReportsByDomain(Fixed):
    """Report counts per domain, sorted by name."""
    domains: List[DomainReportCount]
    allow_delete: bool


class DomainReportsDeleted(Fixed):
    status: str = Field(description="success")
    domain: str
    dmarc_reports: int
    dmarc_records: int
    tls_reports: int
    tls_policies: int


# ---------------------------------------------------------------- domains list

class RecordState(Fixed):
    checked: bool = Field(description="False when the record could not be read")
    found: bool
    status: Optional[str] = Field(description="The DNS check's status, such as success, warning or error")


class DmarcRecordState(RecordState):
    policy: Optional[str] = Field(description="The record's p, in lower case; null when no record was found")


class Stats30d(Fixed):
    total_messages: int
    unique_ips: int
    dmarc_pass_pct: float = Field(description="0 without messages")
    tls_success_pct: float = Field(description="100 without sessions")
    tls_sessions: int


class DmarcDomain(Fixed):
    domain: str
    report_count: int = Field(description="DMARC reports")
    tls_report_count: int = Field(description="TLS reports that started in the last 30 days, counted once per "
                                                "policy: a report with two policies counts twice")
    first_report: Optional[int] = Field(description="Start of the first DMARC report period (TLS for a domain with "
                                                    "only TLS reports), Unix time")
    last_report: Optional[int] = Field(description="End of the last report period, as first_report")
    has_dmarc: bool
    has_tls: bool
    tls_rpt_status: Optional[str] = Field(description="Of the last stored DNS check; null when not checked")
    tls_first_report: Optional[int] = Field(description="Unix time")
    tls_last_report: Optional[int] = Field(description="Unix time")
    stats_30d: Stats30d = Field(description="Reports that started in the last 30 days")
    failing_sources: int = Field(description="Source addresses that failed DMARC for most of their mail in the last "
                                             "30 days")
    dmarc_record: DmarcRecordState = Field(description="From the stored DNS check, or looked up live without one")
    tls_rpt_record: RecordState = Field(description="As dmarc_record")
    on_mailcow: Optional[bool] = Field(description="An active domain or alias domain on this mailcow server; null "
                                                   "while the server's domains are not known")


class DailyTotal(Fixed):
    date: str
    total: int
    dmarc_pass: int
    dmarc_fail: int


class DomainsList(Fixed):
    """Every domain with DMARC or TLS reports, newest last_report first. Cached for 5 minutes."""
    domains: List[DmarcDomain]
    total: int
    daily: List[DailyTotal] = Field(description="Messages per day across every domain in the last 30 days")


# ---------------------------------------------------------------- DNS records

class DmarcRecordCheck(BaseModel):
    """The DMARC DNS check as stored by the last DNS check, or a live one. A check stored by an older
    version may lack keys."""
    model_config = ConfigDict(extra="allow")
    status: str = Field(description="success, warning or error")
    message: str
    record: Optional[str] = Field(description="The TXT record; null when none is published")
    policy: Optional[str] = Field(None, description="none, quarantine, reject or unknown")
    is_strong: bool = Field(None, description="The policy is quarantine or reject")
    warnings: List[str] = Field(None)
    settings: Dict[str, Any] = Field(None, description="The record's tags by name, such as policy, "
                                                       "subdomain_policy, aggregate_report_uris, dkim_alignment, "
                                                       "spf_alignment, percentage; only the tags present")


class TlsRptRecordCheck(BaseModel):
    """The TLS-RPT DNS check as stored by the last DNS check, or a live one. A check stored by an older
    version may lack keys."""
    model_config = ConfigDict(extra="allow")
    status: str = Field(description="success; warning (no record published); error (more than one record, or no "
                                    "usable rua address); unknown (the lookup failed)")
    message: str
    record: Optional[str] = Field(description="null when nothing is published")
    report_uris: List[str] = Field(None, description="The mailto: and https: rua addresses")
    warnings: List[str] = Field(None)
    info: List[str] = Field(None, description="Only without a record: what to publish")


class TlsRptRecordResponse(Fixed):
    domain: str
    tls_rpt_record: TlsRptRecordCheck


# ---------------------------------------------------------------- domain overview and calendar

class PublishedPolicy(Fixed):
    """From the latest report in the period, as the reporter sent it; missing tags get their default."""
    p: str = Field(description="none by default")
    sp: Optional[str]
    pct: Union[int, str] = Field(description="100 by default; as the report sent it otherwise")
    adkim: str = Field(description="r by default")
    aspf: str = Field(description="r by default")


class OverviewDay(Fixed):
    date: str
    total: int
    dmarc_pass: int
    dmarc_fail: int
    spf_pass: int
    dkim_pass: int


class OverviewTotals(Fixed):
    total_messages: int
    dmarc_pass: int
    dmarc_pass_pct: float = Field(None, description="Only when the period has reports")
    dmarc_fail: int
    unique_ips: int
    unique_reporters: int


class DomainOverview(Fixed):
    """One domain's report summary and DNS record state over the period."""
    domain: str
    policy: Optional[PublishedPolicy] = Field(description="null without reports")
    daily_stats: List[OverviewDay] = Field(description="Oldest first")
    totals: OverviewTotals
    dmarc_record: DmarcRecordCheck
    tls_rpt_record: TlsRptRecordCheck
    on_mailcow: Optional[bool] = Field(description="An active domain or alias domain on this mailcow server; null "
                                                   "while the server's domains are not known")


class CalendarDay(Fixed):
    date: str
    total: int
    pass_: int = Field(alias="pass")
    fail: int

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class DomainCalendar(Fixed):
    """Messages and DMARC passes per day, for the days with reports."""
    domain: str
    from_: str = Field(alias="from", description="The first day")
    to: str = Field(description="Today")
    retention_days: int
    maybe_incomplete_before: str = Field(description="Reports are kept by import date, so a day before this may "
                                                     "miss some")
    days: List[CalendarDay]

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


# ---------------------------------------------------------------- DMARC reports and sources

class DayReport(Fixed):
    report_id: str
    org_name: str
    begin_date: int = Field(description="Unix time")
    end_date: int = Field(description="Unix time")
    volume: int = Field(description="Messages")
    dmarc_pass_pct: float


class ReportDay(Fixed):
    date: str
    total_messages: int
    dmarc_pass_pct: float
    spf_pass_pct: float
    dkim_pass_pct: float
    unique_ips: int
    reporters: List[str]
    reports: List[DayReport]


class DomainReports(Fixed):
    """DMARC data per day, newest first."""
    domain: str
    total: int = Field(description="Days")
    page: int
    limit: int
    pages: int = Field(description=PAGES)
    data: List[ReportDay]


class _Totals(Fixed):
    total_messages: int
    dmarc_pass: int
    dmarc_pass_pct: float
    spf_pass: int
    spf_pass_pct: float
    dkim_pass: int
    dkim_pass_pct: float
    reporters: List[str]


class ReportDetailsTotals(_Totals):
    unique_ips: int = Field(description="Rows in sources (one per address and reporter), not distinct addresses")


class _Geo(Fixed):
    country_code: Optional[str] = Field(description=GEO)
    country_name: Optional[str] = Field(description=GEO)
    city: Optional[str] = Field(description=GEO)
    asn: Optional[str] = Field(description="Such as AS15169. " + GEO)
    asn_org: Optional[str] = Field(description=GEO)


class ReportDetailsSource(_Geo):
    """One sending address and reporter."""
    source_ip: str
    source_name: Optional[str] = Field(description="asn_org")
    header_from: Optional[str]
    envelope_from: Optional[str]
    reporter: str
    volume: int
    dmarc_pass: int
    dmarc_fail: int
    spf_pass: int
    dkim_pass: int
    dmarc_pass_pct: float
    spf_pass_pct: float
    dkim_pass_pct: float


class ReportDetails(Fixed):
    """One domain's DMARC data for one day."""
    domain: str
    date: str
    totals: ReportDetailsTotals
    sources: List[ReportDetailsSource] = Field(description="Largest volume first")


class SourceReporter(Fixed):
    org_name: str
    count: int
    dmarc_pass: int


class Source(_Geo):
    source_ip: str
    country_emoji: str = Field(description="The country's flag; a globe without a country")
    total_count: int
    dmarc_pass: int
    dmarc_pass_pct: float
    spf_pass: int
    spf_pass_pct: float
    dkim_pass: int
    dkim_pass_pct: float
    reporters: List[SourceReporter] = Field(description="Who reported this address, most messages first")


class DomainSources(Fixed):
    """Sending addresses by message count."""
    domain: str
    total: int
    page: int
    limit: int
    pages: int = Field(description=PAGES)
    data: List[Source]


class EnvelopeGroup(Fixed):
    """One envelope-from and reporter."""
    envelope_from: Optional[str]
    header_from: Optional[str]
    reporter: str
    volume: int
    dmarc_pass: int
    dmarc_fail: int
    spf_aligned: int
    dkim_aligned: int
    spf_result: Optional[str] = Field(description="Of the group's first record")
    dkim_result: Optional[str] = Field(description="Of the group's first record")


class SourceDetailsTotals(_Totals):
    unique_envelopes: int


class SourceDetails(_Geo):
    """One sending address for one domain over the period."""
    domain: str
    source_ip: str
    source_name: Optional[str] = Field(description="asn_org")
    totals: SourceDetailsTotals
    envelope_from_groups: List[EnvelopeGroup] = Field(description="Largest volume first")


# ---------------------------------------------------------------- TLS reports

FAILURE_DETAILS = "As the report sent them (RFC 8460 failure-details); null or empty without failures"
MX_HOST = "As the report sent it, usually a list of host names"


class TlsPolicy(Fixed):
    policy_type: Optional[str] = Field(description="Such as sts, tlsa or no-policy-found")
    policy_domain: Optional[str]
    mx_host: Any = Field(description=MX_HOST)
    successful_sessions: int
    failed_sessions: int
    failure_details: Any = Field(description=FAILURE_DETAILS)


class TlsReport(Fixed):
    id: int = Field(description="The database ID")
    report_id: str
    organization_name: Optional[str]
    contact_info: Optional[str]
    start_datetime: str = Field(description=TIME)
    end_datetime: str = Field(description=TIME)
    successful_sessions: int
    failed_sessions: int
    total_sessions: int
    success_rate: float = Field(description="Percent; 100 without sessions")
    policies: List[TlsPolicy]


class TlsReportsTotals(Fixed):
    total_reports: int = Field(description="Every report in the period")
    total_successful_sessions: int = Field(description="This page only")
    total_failed_sessions: int = Field(description="This page only")
    overall_success_rate: float = Field(description="This page only; 100 without sessions")
    unique_organizations: int = Field(description="This page only")


class TlsReports(Fixed):
    """Single TLS reports, newest start first."""
    domain: str
    total: int
    page: int
    limit: int
    pages: int = Field(description=PAGES)
    totals: TlsReportsTotals
    data: List[TlsReport]


class TlsDayReport(Fixed):
    id: int
    organization_name: Optional[str]
    successful_sessions: int
    failed_sessions: int


class TlsDay(Fixed):
    date: str
    report_count: int
    organizations: List[Optional[str]]
    organization_count: int
    total_success: int
    total_fail: int
    total_sessions: int
    success_rate: float = Field(description="Percent; 100 without sessions")
    reports: List[TlsDayReport]


class TlsDailyTotals(Fixed):
    total_days: int
    total_reports: int
    total_successful_sessions: int
    total_failed_sessions: int
    overall_success_rate: float = Field(description="Percent; 100 without sessions")


class TlsDaily(Fixed):
    """TLS reports per day, newest first."""
    domain: str
    total: int = Field(description="Days")
    page: int
    limit: int
    pages: int = Field(description=PAGES)
    totals: TlsDailyTotals = Field(description="Every day in the period")
    data: List[TlsDay]


class TlsDetailsPolicy(TlsPolicy):
    total_sessions: int
    success_rate: float = Field(description="Percent; 100 without sessions")


class TlsProvider(Fixed):
    """One report; a provider with two reports that day appears twice."""
    report_id: str
    organization_name: Optional[str]
    contact_info: Optional[str]
    start_datetime: str = Field(description=TIME)
    end_datetime: str = Field(description=TIME)
    successful_sessions: int
    failed_sessions: int
    total_sessions: int
    success_rate: float = Field(description="Percent; 100 without sessions")
    policies: List[TlsDetailsPolicy]


class TlsDayStats(Fixed):
    total_reports: int
    total_providers: int
    total_success: int
    total_fail: int
    total_sessions: int
    success_rate: float = Field(description="Percent; 100 without sessions")


class TlsDetails(Fixed):
    """One day's TLS reports."""
    domain: str
    date: str
    stats: TlsDayStats
    providers: List[TlsProvider]


# ---------------------------------------------------------------- IMAP import

class ImapConfiguration(Fixed):
    """All null while the import is off. The password is never returned."""
    host: Optional[str]
    port: Optional[int]
    user: Optional[str]
    folder: Optional[str]
    delete_after: Optional[bool] = Field(description="Delete each email once its reports are stored")
    interval_seconds: Optional[int]
    interval_minutes: Optional[float]


class ImapRun(Fixed):
    id: int
    sync_type: str = Field(description="auto or manual")
    started_at: str = Field(description=TIME)
    completed_at: Optional[str] = Field(description="Null while running. " + TIME)
    status: str = Field(description="success, error, running or failed (interrupted, or cleaned up as stale)")
    emails_found: int
    emails_processed: int
    reports_created: int
    reports_duplicate: int
    reports_failed: int = Field(description="Emails that failed")
    error_message: Optional[str] = Field(description="Null when nothing failed")


class ImapStats24h(Fixed):
    total_syncs: int
    total_reports_created: int
    total_reports_failed: int


class ImapStatus(Fixed):
    """The IMAP import's settings and its last run, also while it is off."""
    enabled: bool
    configuration: ImapConfiguration
    latest_sync: Optional[ImapRun] = Field(description="null before the first run")
    stats_24h: ImapStats24h


class ImapSyncStarted(Fixed):
    status: str = Field(description="started; or already_running, when an import runs already and nothing starts")
    message: str


class FailedEmail(Fixed):
    email_id: Optional[str] = Field(description="The IMAP UID")
    message_id: Optional[str]
    subject: Optional[str]
    error: Optional[str]


class ImapHistoryRun(ImapRun):
    failed_emails: Optional[List[FailedEmail]] = Field(description="Null when nothing failed")


class ImapHistory(Fixed):
    """Import runs, newest first."""
    total: int
    page: int
    limit: int
    pages: int = Field(description=PAGES)
    data: List[ImapHistoryRun]


# ---------------------------------------------------------------- upload

class UploadStored(Fixed):
    status: str = Field(description="success")
    report_type: str = Field(description="dmarc or tls-rpt")
    message: str = Field(description="Says so when another report has the same report ID and other content")
    report_id: int = Field(description="The database ID")
    records_count: int = Field(None, description="Only for DMARC")
    policies_count: int = Field(None, description="Only for TLS-RPT")


class UploadDuplicate(Fixed):
    status: str = Field(description="duplicate: a report with this content is already stored")
    report_type: str = Field(description="dmarc or tls-rpt")
    message: str
