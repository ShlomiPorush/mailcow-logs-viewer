"""API operations whose answers are not documented yet, by the layer that will document them.

test_openapi_coverage.py fails when an operation is neither documented nor
listed here, and when an entry here is stale (documented already, or gone).
Each layer of the work removes its entries; the list ends empty.
"""

PENDING = {
    ("DELETE", "/api/dmarc/reports/domains/{domain}"): "L4",  # dmarc
    ("DELETE", "/api/dmarc/reports/{report_type}/{report_id}"): "L4",  # dmarc
    ("GET", "/api/devices"): "L4",  # devices
    ("GET", "/api/dmarc/domains"): "L4",  # dmarc
    ("GET", "/api/dmarc/domains/{domain}/calendar"): "L4",  # dmarc
    ("GET", "/api/dmarc/domains/{domain}/overview"): "L4",  # dmarc
    ("GET", "/api/dmarc/domains/{domain}/reports"): "L4",  # dmarc
    ("GET", "/api/dmarc/domains/{domain}/reports/{report_date}/details"): "L4",  # dmarc
    ("GET", "/api/dmarc/domains/{domain}/sources"): "L4",  # dmarc
    ("GET", "/api/dmarc/domains/{domain}/sources/{source_ip}/details"): "L4",  # dmarc
    ("GET", "/api/dmarc/domains/{domain}/tls-reports"): "L4",  # dmarc
    ("GET", "/api/dmarc/domains/{domain}/tls-reports/daily"): "L4",  # dmarc
    ("GET", "/api/dmarc/domains/{domain}/tls-reports/{report_date}/details"): "L4",  # dmarc
    ("GET", "/api/dmarc/domains/{domain}/tls-rpt-record"): "L4",  # dmarc
    ("GET", "/api/dmarc/imap/history"): "L4",  # dmarc
    ("GET", "/api/dmarc/imap/status"): "L4",  # dmarc
    ("GET", "/api/dmarc/insights"): "L4",  # dmarc
    ("GET", "/api/dmarc/reports/all"): "L4",  # dmarc
    ("GET", "/api/dmarc/reports/config"): "L4",  # dmarc
    ("GET", "/api/dmarc/reports/domains"): "L4",  # dmarc
    ("GET", "/api/domains/all"): "L4",  # domains
    ("GET", "/api/export/messages/csv"): "L4",  # export
    ("GET", "/api/export/netfilter/csv"): "L4",  # export
    ("GET", "/api/export/postfix/csv"): "L4",  # export
    ("GET", "/api/export/rspamd/csv"): "L4",  # export
    ("GET", "/api/mailbox-stats/all"): "L4",  # mailbox_stats
    ("GET", "/api/mailbox-stats/domains"): "L4",  # mailbox_stats
    ("GET", "/api/mailbox-stats/refresh"): "L4",  # mailbox_stats
    ("GET", "/api/mailbox-stats/summary"): "L4",  # mailbox_stats
    ("GET", "/api/system/summary"): "L4",  # reporting
    ("POST", "/api/dmarc/cache/clear"): "L4",  # dmarc
    ("POST", "/api/dmarc/imap/sync"): "L4",  # dmarc
    ("POST", "/api/dmarc/upload"): "L4",  # dmarc
    ("POST", "/api/domains/check-all-dns"): "L4",  # domains
    ("POST", "/api/domains/{domain}/check-dns"): "L4",  # domains
    ("POST", "/api/system/summary/email"): "L4",  # reporting
    ("DELETE", "/api/agents"): "L5",  # consent
    ("DELETE", "/api/agents/{grant_id}"): "L5",  # consent
    ("DELETE", "/api/notifications/channels/{channel_id}"): "L5",  # notifications
    ("DELETE", "/api/quarantine/rules/{rule_id}"): "L5",  # quarantine_rules
    ("DELETE", "/api/suppressions/{suppression_id}"): "L5",  # suppressions
    ("GET", "/api/agents"): "L5",  # consent
    ("GET", "/api/agents/consent/{request_id}"): "L5",  # consent
    ("GET", "/api/agents/{grant_id}/activity"): "L5",  # consent
    ("GET", "/api/auth/callback"): "L5",  # auth
    ("GET", "/api/auth/login"): "L5",  # auth
    ("GET", "/api/auth/provider-info"): "L5",  # auth
    ("GET", "/api/auth/status"): "L5",  # auth
    ("GET", "/api/auth/verify"): "L5",  # auth
    ("GET", "/api/notifications/channels"): "L5",  # notifications
    ("GET", "/api/notifications/types"): "L5",  # notifications
    ("GET", "/api/quarantine/rules"): "L5",  # quarantine_rules
    ("GET", "/api/quarantine/rules/logs"): "L5",  # quarantine_rules
    ("GET", "/api/raw-logs/services"): "L5",  # raw_logs
    ("GET", "/api/raw-logs/worker-status"): "L5",  # raw_logs
    ("GET", "/api/raw-logs/ws-token"): "L5",  # raw_logs
    ("GET", "/api/raw-logs/{service}"): "L5",  # raw_logs
    ("GET", "/api/raw-logs/{service}/smart-filters"): "L5",  # raw_logs
    ("GET", "/api/rspamd/config"): "L5",  # rspamd_maps
    ("GET", "/api/rspamd/maps"): "L5",  # rspamd_maps
    ("GET", "/api/rspamd/maps/{filename}"): "L5",  # rspamd_maps
    ("GET", "/api/settings"): "L5",  # settings
    ("GET", "/api/settings/geoip/status"): "L5",  # settings
    ("GET", "/api/settings/health"): "L5",  # settings
    ("GET", "/api/settings/info"): "L5",  # settings
    ("GET", "/api/status/app-version"): "L5",  # status
    ("GET", "/api/status/app-version/changelog/{version}"): "L5",  # status
    ("GET", "/api/status/container-logs"): "L5",  # status
    ("GET", "/api/status/containers"): "L5",  # status
    ("GET", "/api/status/mailcow-connection"): "L5",  # status
    ("GET", "/api/status/mailcow-info"): "L5",  # status
    ("GET", "/api/status/storage"): "L5",  # status
    ("GET", "/api/status/summary"): "L5",  # status
    ("GET", "/api/status/version"): "L5",  # status
    ("GET", "/api/suppressions"): "L5",  # suppressions
    ("GET", "/api/suppressions/config"): "L5",  # suppressions
    ("GET", "/api/suppressions/export"): "L5",  # suppressions
    ("GET", "/api/suppressions/rspamd/state"): "L5",  # suppressions
    ("GET", "/api/suppressions/stats"): "L5",  # suppressions
    ("GET", "/api/suppressions/{suppression_id}/events"): "L5",  # suppressions
    ("POST", "/api/agents/consent/{request_id}"): "L5",  # consent
    ("POST", "/api/auth/logout"): "L5",  # auth
    ("POST", "/api/auth/session"): "L5",  # auth
    ("POST", "/api/notifications/channels"): "L5",  # notifications
    ("POST", "/api/notifications/channels/{channel_id}/test"): "L5",  # notifications
    ("POST", "/api/notifications/test"): "L5",  # notifications
    ("POST", "/api/quarantine/rules"): "L5",  # quarantine_rules
    ("POST", "/api/quarantine/rules/test"): "L5",  # quarantine_rules
    ("POST", "/api/quarantine/rules/{rule_id}/toggle"): "L5",  # quarantine_rules
    ("POST", "/api/rspamd/validate"): "L5",  # rspamd_maps
    ("POST", "/api/settings/geoip/download"): "L5",  # settings
    ("POST", "/api/settings/geoip/validate"): "L5",  # settings
    ("POST", "/api/settings/import-from-env"): "L5",  # settings
    ("POST", "/api/settings/jobs/{job_name}/run"): "L5",  # settings
    ("POST", "/api/settings/mailcow/rw-key/validate"): "L5",  # settings
    ("POST", "/api/settings/maxmind/validate"): "L5",  # settings
    ("POST", "/api/settings/purge-feature-data"): "L5",  # settings
    ("POST", "/api/settings/rspamd/password/validate"): "L5",  # settings
    ("POST", "/api/settings/test/imap"): "L5",  # settings
    ("POST", "/api/settings/test/smtp"): "L5",  # settings
    ("POST", "/api/suppressions"): "L5",  # suppressions
    ("POST", "/api/suppressions/import"): "L5",  # suppressions
    ("POST", "/api/suppressions/rspamd/clear"): "L5",  # suppressions
    ("POST", "/api/suppressions/rspamd/import"): "L5",  # suppressions
    ("POST", "/api/suppressions/start-fresh"): "L5",  # suppressions
    ("POST", "/api/suppressions/sync"): "L5",  # suppressions
    ("PUT", "/api/agents/{grant_id}"): "L5",  # consent
    ("PUT", "/api/notifications/channels/{channel_id}"): "L5",  # notifications
    ("PUT", "/api/quarantine/rules/{rule_id}"): "L5",  # quarantine_rules
    ("PUT", "/api/rspamd/maps/{filename}"): "L5",  # rspamd_maps
    ("PUT", "/api/settings"): "L5",  # settings
    ("PUT", "/api/status/containers/{container}/ignore"): "L5",  # status
    ("PUT", "/api/suppressions/{suppression_id}"): "L5",  # suppressions
}

# Operations left out of /openapi.json on purpose, with the reason
HIDDEN = {
    ("GET", "/api/auth/logout"): "Always answers 405: signing out is POST /api/auth/logout",
}
