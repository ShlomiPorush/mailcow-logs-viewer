from sqlalchemy import Column, Integer, BigInteger, String, Float, DateTime, Boolean, Text, Index, JSON, UniqueConstraint, ForeignKey, CheckConstraint, func, text, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime

from .database import Base


class PostfixLog(Base):
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
        Index('idx_postfix_cleanup_no_message_id', 'time',
              postgresql_where=text("message_id IS NULL AND program LIKE '%/cleanup'")),
        UniqueConstraint('time', 'program', 'queue_id', 'message', name='uq_postfix_log'),
    )
    
    def __repr__(self):
        return f"<PostfixLog(queue_id={self.queue_id}, status={self.status})>"


class RspamdLog(Base):
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
    
    country_code = Column(String(2), index=True)
    country_name = Column(String(100))
    city = Column(String(100))
    asn = Column(String(20))
    asn_org = Column(String(255))
    
    raw_data = Column(JSONB)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_netfilter_time_ip', 'time', 'ip'),
        Index('idx_netfilter_username', 'username'),
    )
    
    def __repr__(self):
        return f"<NetfilterLog(ip={self.ip}, username={self.username}, action={self.action})>"


class MessageCorrelation(Base):
    __tablename__ = "message_correlations"
    
    id = Column(Integer, primary_key=True, index=True)
    correlation_key = Column(String(64), unique=True, index=True, nullable=False)
    
    message_id = Column(String(255))
    queue_id = Column(String(50), index=True)
    
    postfix_log_ids = Column(JSONB)
    rspamd_log_id = Column(Integer, index=True)
    
    sender = Column(String(255), index=True)
    recipient = Column(String(255), index=True)
    written_recipients = Column(JSONB)
    subject = Column(Text)
    direction = Column(String(20))
    final_status = Column(String(50))

    dovecot_status = Column(String(30), index=True)
    dovecot_mailbox = Column(String(255))
    dovecot_detail = Column(Text)

    is_complete = Column(Boolean, default=False, index=True)
    
    first_seen = Column(DateTime, index=True)
    last_seen = Column(DateTime)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_correlation_message_id', 'message_id'),
        Index('idx_correlation_queue_id', 'queue_id'),
        Index('idx_correlation_sender_recipient', 'sender', 'recipient'),
        Index('idx_correlation_sender_lower', func.lower(sender)),
        Index('idx_correlation_recipient_lower', func.lower(recipient)),
    )
    
    def __repr__(self):
        return f"<MessageCorrelation(message_id={self.message_id}, status={self.final_status})>"


class DomainDNSCheck(Base):
    __tablename__ = "domain_dns_checks"
    
    id = Column(Integer, primary_key=True, index=True)
    domain_name = Column(String(255), unique=True, index=True, nullable=False)
    
    spf_check = Column(JSONB)
    dkim_check = Column(JSONB)
    dmarc_check = Column(JSONB)
    dnssec_check = Column(JSONB)
    tlsa_check = Column(JSONB)
    mta_sts_check = Column(JSONB)
    tls_rpt_check = Column(JSONB)
    
    checked_at = Column(DateTime, nullable=False)
    is_full_check = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class DMARCReport(Base):
    __tablename__ = "dmarc_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    
    report_id = Column(String(255), nullable=False)
    content_hash = Column(String(64))

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
        UniqueConstraint('report_id', 'content_hash', name='uq_dmarc_reports_report_id_hash'),
        Index('idx_dmarc_report_domain_date', 'domain', 'begin_date'),
        Index('idx_dmarc_report_org', 'org_name'),
    )
    
    def __repr__(self):
        return f"<DMARCReport(report_id={self.report_id}, domain={self.domain}, org={self.org_name})>"


class DMARCRecord(Base):
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
    __tablename__ = "mailbox_statistics"
    
    id = Column(Integer, primary_key=True, index=True)
    
    username = Column(String(255), unique=True, index=True, nullable=False)
    domain = Column(String(255), index=True, nullable=False)
    name = Column(String(255))
    
    quota = Column(BigInteger, default=0)
    quota_used = Column(BigInteger, default=0)
    percent_in_use = Column(Float, default=0.0)
    
    messages = Column(Integer, default=0)
    
    active = Column(Boolean, default=True, index=True)
    login_disabled = Column(Boolean, nullable=False, default=False, server_default=text('false'))

    last_imap_login = Column(BigInteger, nullable=True)
    last_pop3_login = Column(BigInteger, nullable=True)
    last_smtp_login = Column(BigInteger, nullable=True)
    last_sogo_login = Column(BigInteger, nullable=True)
    
    spam_aliases = Column(Integer, default=0)
    
    rl_value = Column(Integer, nullable=True)
    rl_frame = Column(String(20), nullable=True)
    
    attributes = Column(JSONB)
    
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
    __tablename__ = "alias_statistics"
    
    id = Column(Integer, primary_key=True, index=True)
    
    alias_address = Column(String(255), unique=True, index=True, nullable=False)
    goto = Column(Text)
    domain = Column(String(255), index=True, nullable=False)
    
    active = Column(Boolean, default=True, index=True)
    is_catch_all = Column(Boolean, default=False)
    
    primary_mailbox = Column(String(255), index=True, nullable=True)
    
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
    __tablename__ = "tls_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    
    report_id = Column(String(255), nullable=False)
    content_hash = Column(String(64))
    
    organization_name = Column(String(255), index=True)
    contact_info = Column(String(255))
    
    policy_domain = Column(String(255), index=True, nullable=False)
    
    start_datetime = Column(DateTime, nullable=False)
    end_datetime = Column(DateTime, nullable=False)
    
    raw_json = Column(Text)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        UniqueConstraint('report_id', 'content_hash', name='uq_tls_reports_report_id_hash'),
        Index('idx_tls_report_domain_date', 'policy_domain', 'start_datetime'),
        Index('idx_tls_report_org', 'organization_name'),
    )
    
    def __repr__(self):
        return f"<TLSReport(report_id={self.report_id}, domain={self.policy_domain}, org={self.organization_name})>"


class TLSReportPolicy(Base):
    __tablename__ = "tls_report_policies"
    
    id = Column(Integer, primary_key=True, index=True)
    tls_report_id = Column(Integer, index=True, nullable=False)
    
    policy_type = Column(String(50))
    policy_domain = Column(String(255))
    policy_string = Column(JSONB)
    mx_host = Column(JSONB)
    
    successful_session_count = Column(Integer, default=0)
    failed_session_count = Column(Integer, default=0)
    
    failure_details = Column(JSONB)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_tls_policy_report', 'tls_report_id'),
        Index('idx_tls_policy_type', 'policy_type'),
    )
    
    def __repr__(self):
        return f"<TLSReportPolicy(type={self.policy_type}, success={self.successful_session_count}, fail={self.failed_session_count})>"


class SystemSetting(Base):
    __tablename__ = "system_settings"
    
    key = Column(String(255), primary_key=True, index=True)
    value = Column(Text)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<SystemSetting(key={self.key}, updated={self.updated_at})>"


class BlacklistCheck(Base):
    __tablename__ = "blacklist_checks"
    
    id = Column(Integer, primary_key=True, index=True)
    server_ip = Column(String(50), index=True, nullable=False)
    
    total_blacklists = Column(Integer, default=0)
    listed_count = Column(Integer, default=0)
    clean_count = Column(Integer, default=0)
    error_count = Column(Integer, default=0)
    timeout_count = Column(Integer, default=0)
    
    status = Column(String(20), index=True)
    
    results = Column(JSONB)
    
    checked_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_blacklist_check_ip_time', 'server_ip', 'checked_at'),
    )
    
    def __repr__(self):
        return f"<BlacklistCheck(ip={self.server_ip}, status={self.status}, listed={self.listed_count})>"


class MonitoredHost(Base):
    __tablename__ = "monitored_hosts"
    
    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), unique=True, index=True, nullable=False)
    source = Column(Text)
    active = Column(Boolean, default=True, index=True)
    last_seen = Column(DateTime)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_monitored_host_active', 'active'),
    )
    
    def __repr__(self):
        return f"<MonitoredHost(hostname={self.hostname}, source={self.source})>"


class KnownContainer(Base):
    __tablename__ = "known_containers"
    
    container_name = Column(String(255), primary_key=True, index=True, nullable=False)
    display_name = Column(String(255), nullable=False)
    last_seen = Column(DateTime, index=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_known_containers_last_seen', 'last_seen'),
    )
    
    def __repr__(self):
        return f"<KnownContainer(container_name={self.container_name}, display_name={self.display_name}, last_seen={self.last_seen})>"


class RawServiceLog(Base):
    __tablename__ = "raw_service_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    service = Column(String(50), nullable=False, index=True)
    time = Column(DateTime, nullable=False, index=True)
    message_hash = Column(String(64), nullable=False)
    raw_data = Column(JSONB, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        UniqueConstraint('service', 'time', 'message_hash', name='uq_raw_service_log'),
        Index('idx_raw_log_service_time', 'service', time.desc()),
        Index('idx_raw_log_time', 'time'),
    )
    
    def __repr__(self):
        return f"<RawServiceLog(service={self.service}, time={self.time})>"


class EasDevice(Base):
    __tablename__ = "eas_devices"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), nullable=False)
    device_id = Column(String(255), nullable=False)
    device_type = Column(String(100))
    last_ip = Column(String(255))
    last_command = Column(String(64))
    last_status = Column(Integer)
    first_seen = Column(DateTime, nullable=False)
    last_seen = Column(DateTime, nullable=False)

    __table_args__ = (
        UniqueConstraint('username', 'device_id', name='uq_eas_device'),
        Index('idx_eas_device_last_seen', 'last_seen'),
    )

    def __repr__(self):
        return f"<EasDevice(username={self.username}, device_id={self.device_id})>"


class SpamSuppression(Base):
    __tablename__ = "spam_suppressions"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    type = Column(String(20), index=True, default='email')
    reason = Column(String(50), index=True, nullable=False)
    source = Column(String(100))
    notes = Column(Text)
    
    bounce_count = Column(Integer, default=1)
    hard_bounce_count = Column(Integer, default=0)
    soft_bounce_count = Column(Integer, default=0)
    last_bounce_dsn = Column(String(20))
    last_bounce_message = Column(Text)
    
    correlation_key = Column(String(64), nullable=True)
    
    active = Column(Boolean, default=True, index=True)
    synced_to_rspamd = Column(Boolean, default=False, index=True)
    
    expires_at = Column(DateTime, nullable=True, index=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_suppression_email', 'email'),
        Index('idx_suppression_active_sync', 'active', 'synced_to_rspamd'),
        Index('idx_suppression_expires', 'active', 'expires_at'),
    )
    
    def __repr__(self):
        return f"<SpamSuppression(email={self.email}, reason={self.reason}, active={self.active}, bounces={self.bounce_count})>"


class SuppressionEvent(Base):
    __tablename__ = "suppression_events"

    id = Column(Integer, primary_key=True)
    suppression_id = Column(Integer, ForeignKey('spam_suppressions.id', ondelete='CASCADE'), nullable=False)
    kind = Column(String(30), nullable=False)
    outcome = Column(String(20))
    recorded_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    message_time = Column(DateTime)
    reason = Column(Text)
    server_reply = Column(Text)
    dsn = Column(String(20))
    sender = Column(String(255))
    recipient = Column(String(255))
    subject = Column(Text)
    queue_id = Column(String(50))
    message_id = Column(String(255))
    correlation_key = Column(String(64))
    notes = Column(Text)
    expires_at = Column(DateTime)
    log_lines = Column(JSONB)
    logs_shortened = Column(Boolean, default=False)

    __table_args__ = (
        Index('idx_suppression_event_owner', 'suppression_id', 'recorded_at'),
    )


class QuarantineRule(Base):
    __tablename__ = "quarantine_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    match_type = Column(String(20), nullable=False)
    match_value = Column(String(500), nullable=False)
    is_regex = Column(Boolean, default=False)
    action = Column(String(20), nullable=False)
    enabled = Column(Boolean, default=True, index=True)
    hit_count = Column(Integer, default=0)
    last_hit_at = Column(DateTime, nullable=True)
    notes = Column(Text)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_qrule_enabled', 'enabled'),
        Index('idx_qrule_action', 'action'),
    )
    
    def __repr__(self):
        return f"<QuarantineRule(name={self.name}, match={self.match_type}:{self.match_value}, action={self.action})>"


class QuarantineRuleLog(Base):
    __tablename__ = "quarantine_rule_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(Integer, index=True, nullable=False)
    rule_name = Column(String(255))
    action = Column(String(20), nullable=False)
    quarantine_id = Column(String(100))
    sender = Column(String(255))
    recipient = Column(String(255))
    subject = Column(Text)
    matched_field = Column(String(20))
    matched_value = Column(String(500))
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index('idx_qrule_log_rule', 'rule_id'),
        Index('idx_qrule_log_created', 'created_at'),
    )

class MetricSnapshot(Base):
    __tablename__ = "metric_snapshots"

    id = Column(Integer, primary_key=True)
    name = Column(String(40), nullable=False)
    slot = Column(DateTime, nullable=False)
    value = Column(Float)
    of = Column(Float)
    as_of = Column(DateTime, nullable=False)

    __table_args__ = (
        UniqueConstraint('name', 'slot', name='uq_metric_snapshot_name_slot'),
        Index('idx_metric_snapshot_slot', 'slot'),
    )


class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(40), nullable=False, index=True)
    severity = Column(String(20), default='warning', index=True)
    subject = Column(String(255))
    title = Column(String(255), nullable=False)
    detail = Column(Text)
    metric_value = Column(Float)
    baseline_value = Column(Float)
    acknowledged = Column(Boolean, default=False, index=True)
    ack_batch = Column(Uuid, nullable=True, index=True)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        Index('idx_security_alert_type_subject', 'alert_type', 'subject'),
        Index('idx_security_alert_created', 'created_at'),
    )

    def __repr__(self):
        return f"<SecurityAlert(type={self.alert_type}, subject={self.subject}, severity={self.severity})>"


class SMTPAbuseWhitelist(Base):
    __tablename__ = "smtp_abuse_whitelist"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    notes = Column(Text)
    active = Column(Boolean, default=True, nullable=False, index=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<SMTPAbuseWhitelist(email={self.email}, active={self.active})>"


class SMTPAbuseAction(Base):
    __tablename__ = "smtp_abuse_actions"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), nullable=False, index=True)
    message_count = Column(Integer, nullable=False)
    threshold = Column(Integer, nullable=False)
    window_minutes = Column(Integer, nullable=False)
    action = Column(String(30), nullable=False, default="blocked")
    automatic = Column(Boolean, nullable=False, default=True)
    operator = Column(String(255))
    app_passwords_revoked = Column(Integer, default=0)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    __table_args__ = (
        Index('idx_smtp_abuse_email_created', 'email', 'created_at'),
    )

    def __repr__(self):
        return f"<SMTPAbuseAction(email={self.email}, action={self.action}, count={self.message_count})>"


class ProtectionHit(Base):
    __tablename__ = "protection_hits"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(50), nullable=False, index=True)
    rule = Column(String(40), nullable=False, index=True)
    mode = Column(String(20), nullable=False, default="watch")
    status = Column(String(20), nullable=False, default="watching", index=True)
    reason = Column(Text)
    usernames = Column(JSONB, default=list)
    log_ids = Column(JSONB, default=list)
    attempts = Column(Integer, nullable=False, default=0)
    country_code = Column(String(2))
    country_name = Column(String(100))

    first_seen = Column(DateTime, nullable=False)
    last_seen = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    ended_at = Column(DateTime)

    ban_hours = Column(Integer)
    banned_at = Column(DateTime)
    expires_at = Column(DateTime, index=True)
    owned = Column(Boolean)
    error = Column(Text)

    __table_args__ = (
        Index('idx_protection_hits_ip_rule_status', 'ip', 'rule', 'status'),
    )

    def __repr__(self):
        return f"<ProtectionHit(ip={self.ip}, rule={self.rule}, status={self.status})>"


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    channel_type = Column(String(30), nullable=False)
    config = Column(JSONB, nullable=False, default=dict)
    alert_types = Column(JSONB)
    enabled = Column(Boolean, default=True, nullable=False, index=True)

    last_status = Column(String(20))
    last_error = Column(Text)
    last_sent_at = Column(DateTime)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<NotificationChannel(name={self.name}, type={self.channel_type}, enabled={self.enabled})>"



class AgentClient(Base):
    __tablename__ = "agent_clients"

    id = Column(Integer, primary_key=True)
    client_id = Column(String(64), nullable=False, unique=True)
    client_name = Column(String(100), nullable=False)
    redirect_uris = Column(JSONB, nullable=False, default=list)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    created_ip = Column(String(64))
    last_used_at = Column(DateTime)


class AgentGrant(Base):
    __tablename__ = "agent_grants"

    id = Column(Integer, primary_key=True)
    client_id = Column(String(512), nullable=False, index=True)
    client_kind = Column(String(10), nullable=False)
    display_name = Column(String(100), nullable=False)
    declared_name = Column(String(100), nullable=False)
    publisher = Column(String(255))
    redirect_uri = Column(String(512), nullable=False)
    scopes = Column(Text, nullable=False)
    resource = Column(String(512), nullable=False)
    approved_by = Column(String(255))
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    last_used_at = Column(DateTime)
    revoked_at = Column(DateTime, index=True)
    revoke_reason = Column(String(40))


class AgentCode(Base):
    __tablename__ = "agent_codes"

    id = Column(Integer, primary_key=True)
    code_hash = Column(String(64), nullable=False, unique=True)
    client_id = Column(String(512), nullable=False)
    redirect_uri = Column(String(512), nullable=False)
    code_challenge = Column(String(128), nullable=False)
    resource = Column(String(512), nullable=False)
    details = Column(JSONB, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    used_at = Column(DateTime)
    grant_id = Column(Integer, ForeignKey("agent_grants.id", ondelete="CASCADE"))


class AgentDeviceRequest(Base):
    __tablename__ = "agent_device_requests"

    id = Column(Integer, primary_key=True)
    device_code_hash = Column(String(64), nullable=False, unique=True)
    user_code = Column(String(8), nullable=False, index=True)
    client_id = Column(String(64), nullable=False)
    label = Column(String(100), nullable=False)
    requested = Column(Text, nullable=False)
    resource = Column(String(512), nullable=False)
    state = Column(String(10), nullable=False, default="pending")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    interval = Column(Integer, nullable=False, default=5)
    last_poll_at = Column(DateTime)
    details = Column(JSONB)
    answered_at = Column(DateTime)
    grant_id = Column(Integer, ForeignKey("agent_grants.id", ondelete="SET NULL"))


class AgentToken(Base):
    __tablename__ = "agent_tokens"

    id = Column(Integer, primary_key=True)
    grant_id = Column(Integer, ForeignKey("agent_grants.id", ondelete="CASCADE"), nullable=False, index=True)
    kind = Column(String(10), nullable=False)
    token_hash = Column(String(64), nullable=False, unique=True)
    client_id = Column(String(512), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    rotated_at = Column(DateTime)


class AgentAudit(Base):
    __tablename__ = "agent_audit"

    id = Column(Integer, primary_key=True)
    grant_id = Column(Integer, ForeignKey("agent_grants.id", ondelete="SET NULL"), index=True)
    agent_name = Column(String(100))
    at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    event = Column(String(20), nullable=False)
    tool = Column(String(40))
    method = Column(String(10))
    path = Column(String(512))
    http_status = Column(Integer)
    outcome = Column(String(10))
    detail = Column(String(300))


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    kind = Column(String(10), nullable=False)
    username = Column(String(64))
    username_norm = Column(String(64))
    email = Column(String(320))
    email_norm = Column(String(320))
    password_hash = Column(String(255))
    access = Column(String(10), nullable=False)
    scopes = Column(Text, nullable=False, default="")
    disabled = Column(Boolean, nullable=False, default=False, server_default=text("false"))
    auth_version = Column(Integer, nullable=False, default=1, server_default=text("1"))
    row_version = Column(Integer, nullable=False, default=1, server_default=text("1"))
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_login_at = Column(DateTime)

    __table_args__ = (
        CheckConstraint("kind IN ('local', 'oauth2')", name="ck_users_kind"),
        CheckConstraint("access IN ('admin', 'operator', 'viewer', 'custom')", name="ck_users_access"),
        CheckConstraint("kind <> 'local' OR (username_norm IS NOT NULL AND password_hash IS NOT NULL "
                        "AND email IS NULL AND email_norm IS NULL)", name="ck_users_local"),
        CheckConstraint("kind <> 'oauth2' OR (email_norm IS NOT NULL AND password_hash IS NULL)",
                        name="ck_users_oauth2"),
        Index("ux_users_local_username", "username_norm", unique=True, postgresql_where=text("kind = 'local'")),
        Index("ux_users_oauth2_email", "email_norm", unique=True, postgresql_where=text("kind = 'oauth2'")),
    )
