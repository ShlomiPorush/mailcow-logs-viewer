"""
SQLAlchemy database models for storing mailcow logs

SIMPLIFIED VERSION:
- Correlation now relies solely on Message-ID
- Removed old generate_correlation_key function
- Correlation key is now SHA256 of Message-ID
"""
from sqlalchemy import Column, Integer, BigInteger, String, Float, DateTime, Boolean, Text, Index, JSON, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime

from .database import Base


class PostfixLog(Base):
    """Postfix mail server logs"""
    __tablename__ = "postfix_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    time = Column(DateTime, index=True, nullable=False)
    program = Column(String(100), index=True)
    priority = Column(String(20))
    message = Column(Text)
    
    queue_id = Column(String(50), index=True)
    message_id = Column(String(255), index=True)
    sender = Column(String(255), index=True)
    recipient = Column(String(255), index=True)
    status = Column(String(50), index=True)
    relay = Column(String(255))
    delay = Column(Float)
    dsn = Column(String(20))
    
    correlation_key = Column(String(64), index=True)
    
    raw_data = Column(JSONB)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_postfix_time_queue', 'time', 'queue_id'),
        Index('idx_postfix_sender_recipient', 'sender', 'recipient'),
        Index('idx_postfix_correlation', 'correlation_key'),
        Index('idx_postfix_message_id', 'message_id'),
        UniqueConstraint('time', 'program', 'queue_id', 'message', name='uq_postfix_log'),
    )
    
    def __repr__(self):
        return f"<PostfixLog(queue_id={self.queue_id}, status={self.status})>"


class RspamdLog(Base):
    """Rspamd spam filtering logs"""
    __tablename__ = "rspamd_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    time = Column(DateTime, index=True, nullable=False)
    
    message_id = Column(String(255), index=True)
    queue_id = Column(String(50), index=True)
    subject = Column(Text)
    size = Column(Integer)
    
    sender_smtp = Column(String(255), index=True)
    sender_mime = Column(String(255))
    recipients_smtp = Column(JSONB)
    recipients_mime = Column(JSONB)
    
    score = Column(Float, index=True)
    required_score = Column(Float)
    action = Column(String(50), index=True)
    symbols = Column(JSONB)
    
    user = Column(String(255), index=True)
    direction = Column(String(20), index=True)
    ip = Column(String(50), index=True)

    country_code = Column(String(2), index=True)
    country_name = Column(String(100))
    city = Column(String(100))
    asn = Column(String(20))
    asn_org = Column(String(255))

    is_spam = Column(Boolean, index=True)
    is_skipped = Column(Boolean)
    has_auth = Column(Boolean, index=True)
    
    correlation_key = Column(String(64), index=True)
    
    raw_data = Column(JSONB)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_rspamd_time_direction', 'time', 'direction'),
        Index('idx_rspamd_sender', 'sender_smtp'),
        Index('idx_rspamd_recipients', 'recipients_smtp', postgresql_using='gin'),
        Index('idx_rspamd_score', 'score', 'action'),
        Index('idx_rspamd_correlation', 'correlation_key'),
        Index('idx_rspamd_message_id', 'message_id'),
    )
    
    def __repr__(self):
        return f"<RspamdLog(message_id={self.message_id}, score={self.score}, action={self.action})>"


class NetfilterLog(Base):
    """Netfilter/Authentication failure logs"""
    __tablename__ = "netfilter_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    time = Column(DateTime, index=True, nullable=False)
    priority = Column(String(20))
    message = Column(Text)
    
    ip = Column(String(50), index=True)
    rule_id = Column(Integer)
    attempts_left = Column(Integer)
    username = Column(String(255), index=True)
    auth_method = Column(String(50))
    action = Column(String(50), index=True)
    
    raw_data = Column(JSONB)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_netfilter_time_ip', 'time', 'ip'),
        Index('idx_netfilter_username', 'username'),
    )
    
    def __repr__(self):
        return f"<NetfilterLog(ip={self.ip}, username={self.username}, action={self.action})>"


class MessageCorrelation(Base):
    """
    Correlation table to link related logs from different sources
    
    SIMPLIFIED APPROACH:
    - Uses Message-ID as the primary correlation key (SHA256 hashed)
    - Links all Postfix logs via Queue-ID
    - Links Rspamd log via Message-ID match
    """
    __tablename__ = "message_correlations"
    
    id = Column(Integer, primary_key=True, index=True)
    correlation_key = Column(String(64), unique=True, index=True, nullable=False)
    
    message_id = Column(String(255), index=True, unique=True)
    queue_id = Column(String(50), index=True)
    
    postfix_log_ids = Column(JSONB)
    rspamd_log_id = Column(Integer, index=True)
    
    sender = Column(String(255), index=True)
    recipient = Column(String(255), index=True)
    subject = Column(Text)
    direction = Column(String(20))
    final_status = Column(String(50))
    
    is_complete = Column(Boolean, default=False, index=True)
    
    first_seen = Column(DateTime, index=True)
    last_seen = Column(DateTime)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_correlation_message_id', 'message_id'),
        Index('idx_correlation_queue_id', 'queue_id'),
        Index('idx_correlation_sender_recipient', 'sender', 'recipient'),
    )
    
    def __repr__(self):
        return f"<MessageCorrelation(message_id={self.message_id}, status={self.final_status})>"


class DomainDNSCheck(Base):
    """Cached DNS check results for domains"""
    __tablename__ = "domain_dns_checks"
    
    id = Column(Integer, primary_key=True, index=True)
    domain_name = Column(String(255), unique=True, index=True, nullable=False)
    
    spf_check = Column(JSONB)
    dkim_check = Column(JSONB)
    dmarc_check = Column(JSONB)
    
    checked_at = Column(DateTime, nullable=False)
    is_full_check = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class DMARCReport(Base):
    """DMARC aggregate reports received from email providers"""
    __tablename__ = "dmarc_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    
    report_id = Column(String(255), unique=True, index=True, nullable=False)
    
    domain = Column(String(255), index=True, nullable=False)
    
    org_name = Column(String(255), index=True, nullable=False)
    email = Column(String(255))
    extra_contact_info = Column(Text)
    
    begin_date = Column(Integer, nullable=False)
    end_date = Column(Integer, nullable=False)
    
    policy_published = Column(JSONB)
    
    domain_id = Column(String(255), index=True)
    
    raw_xml = Column(Text)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_dmarc_report_domain_date', 'domain', 'begin_date'),
        Index('idx_dmarc_report_org', 'org_name'),
    )
    
    def __repr__(self):
        return f"<DMARCReport(report_id={self.report_id}, domain={self.domain}, org={self.org_name})>"


class DMARCRecord(Base):
    """Individual records within a DMARC report (one per source IP)"""
    __tablename__ = "dmarc_records"
    
    id = Column(Integer, primary_key=True, index=True)
    dmarc_report_id = Column(Integer, index=True, nullable=False)
    source_ip = Column(String(50), index=True, nullable=False)
    count = Column(Integer, nullable=False)
    disposition = Column(String(20), index=True)
    dkim_result = Column(String(20), index=True)
    spf_result = Column(String(20), index=True)
    header_from = Column(String(255))
    envelope_from = Column(String(255))
    envelope_to = Column(String(255))
    auth_results = Column(JSONB)
    
    country_code = Column(String(2))
    country_name = Column(String(100))
    country_emoji = Column(String(10))
    city = Column(String(100))
    asn = Column(String(20))
    asn_org = Column(String(255))
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_dmarc_record_report', 'dmarc_report_id'),
        Index('idx_dmarc_record_ip', 'source_ip'),
        Index('idx_dmarc_record_results', 'dkim_result', 'spf_result'),
    )
    
    def __repr__(self):
        return f"<DMARCRecord(ip={self.source_ip}, count={self.count}, dkim={self.dkim_result}, spf={self.spf_result})>"


class DMARCSync(Base):
    """History of DMARC IMAP sync operations"""
    __tablename__ = "dmarc_syncs"
    
    id = Column(Integer, primary_key=True, index=True)
    sync_type = Column(String(20), nullable=False)
    started_at = Column(DateTime, nullable=False, index=True)
    completed_at = Column(DateTime)
    status = Column(String(20), nullable=False, index=True)
    
    emails_found = Column(Integer, default=0)
    emails_processed = Column(Integer, default=0)
    reports_created = Column(Integer, default=0)
    reports_duplicate = Column(Integer, default=0)
    reports_failed = Column(Integer, default=0)
    
    error_message = Column(Text)
    failed_emails = Column(JSONB)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_dmarc_sync_type_status', 'sync_type', 'status'),
        Index('idx_dmarc_sync_started', 'started_at'),
    )
    
    def __repr__(self):
        return f"<DMARCSync(type={self.sync_type}, status={self.status}, reports={self.reports_created})>"


class MailboxStatistics(Base):
    """
    Mailbox statistics fetched from Mailcow API
    Tracks quota usage, message counts, and last access times for each mailbox
    """
    __tablename__ = "mailbox_statistics"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Mailbox identification
    username = Column(String(255), unique=True, index=True, nullable=False)  # email address
    domain = Column(String(255), index=True, nullable=False)
    name = Column(String(255))  # Display name
    
    # Quota information (in bytes)
    quota = Column(BigInteger, default=0)  # Allocated quota
    quota_used = Column(BigInteger, default=0)  # Used quota
    percent_in_use = Column(Float, default=0.0)  # Percentage used
    
    # Message counts
    messages = Column(Integer, default=0)  # Total messages in mailbox
    
    # Status
    active = Column(Boolean, default=True, index=True)
    
    # Access times (Unix timestamps from API, stored as integers)
    last_imap_login = Column(BigInteger, nullable=True)
    last_pop3_login = Column(BigInteger, nullable=True)
    last_smtp_login = Column(BigInteger, nullable=True)
    
    # Spam filter settings
    spam_aliases = Column(Integer, default=0)
    
    # Rate limits
    rl_value = Column(Integer, nullable=True)  # Rate limit value
    rl_frame = Column(String(20), nullable=True)  # Rate limit time frame (e.g., "s", "m", "h")
    
    # Attributes from API
    attributes = Column(JSONB)  # Store full attributes for reference
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_mailbox_domain', 'domain'),
        Index('idx_mailbox_active', 'active'),
        Index('idx_mailbox_quota_used', 'quota_used'),
    )
    
    def __repr__(self):
        return f"<MailboxStatistics(username={self.username}, quota_used={self.quota_used}/{self.quota})>"


class AliasStatistics(Base):
    """
    Alias statistics for tracking message counts per alias
    Links aliases to their target mailboxes
    """
    __tablename__ = "alias_statistics"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Alias identification
    alias_address = Column(String(255), unique=True, index=True, nullable=False)  # The alias email
    goto = Column(Text)  # Target mailbox(es), comma-separated
    domain = Column(String(255), index=True, nullable=False)
    
    # Status
    active = Column(Boolean, default=True, index=True)
    is_catch_all = Column(Boolean, default=False)  # Is this a catch-all alias
    
    # Link to primary mailbox (if applicable)
    primary_mailbox = Column(String(255), index=True, nullable=True)  # Main target mailbox
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_alias_domain', 'domain'),
        Index('idx_alias_active', 'active'),
        Index('idx_alias_primary_mailbox', 'primary_mailbox'),
    )
    
    def __repr__(self):
        return f"<AliasStatistics(alias={self.alias_address}, goto={self.goto})>"


class TLSReport(Base):
    """TLS-RPT (SMTP TLS Reporting) reports received from email providers"""
    __tablename__ = "tls_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Report identification
    report_id = Column(String(255), unique=True, index=True, nullable=False)
    
    # Organization that sent the report
    organization_name = Column(String(255), index=True)
    contact_info = Column(String(255))
    
    # Domain being reported on
    policy_domain = Column(String(255), index=True, nullable=False)
    
    # Date range of the report
    start_datetime = Column(DateTime, nullable=False)
    end_datetime = Column(DateTime, nullable=False)
    
    # Raw JSON for reference
    raw_json = Column(Text)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_tls_report_domain_date', 'policy_domain', 'start_datetime'),
        Index('idx_tls_report_org', 'organization_name'),
    )
    
    def __repr__(self):
        return f"<TLSReport(report_id={self.report_id}, domain={self.policy_domain}, org={self.organization_name})>"


class TLSReportPolicy(Base):
    """Individual policy records within a TLS-RPT report"""
    __tablename__ = "tls_report_policies"
    
    id = Column(Integer, primary_key=True, index=True)
    tls_report_id = Column(Integer, index=True, nullable=False)
    
    # Policy information
    policy_type = Column(String(50))  # "sts", "no-policy-found", etc.
    policy_domain = Column(String(255))
    policy_string = Column(JSONB)  # The policy string array
    mx_host = Column(JSONB)  # List of MX hosts
    
    # Session counts
    successful_session_count = Column(Integer, default=0)
    failed_session_count = Column(Integer, default=0)
    
    # Failure details if any
    failure_details = Column(JSONB)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_tls_policy_report', 'tls_report_id'),
        Index('idx_tls_policy_type', 'policy_type'),
    )
    
    def __repr__(self):
        return f"<TLSReportPolicy(type={self.policy_type}, success={self.successful_session_count}, fail={self.failed_session_count})>"


class SystemSetting(Base):
    """
    Global system settings and state
    Used for inter-process signaling (e.g., cache invalidation)
    """
    __tablename__ = "system_settings"
    
    key = Column(String(255), primary_key=True, index=True)
    value = Column(Text)  # JSON string or simple text
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<SystemSetting(key={self.key}, updated={self.updated_at})>"
