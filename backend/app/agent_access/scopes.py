"""What an agent may call, by area of the app.

Every /api route is either in POLICY (an area, and whether it only reads or
changes something) or in EXCLUDED with the reason no agent may call it. A test
fails when a route is in neither, so a new route cannot become reachable, or
silently unreachable, without a decision.

The areas follow the app's menu, and the consent page offers View and Act for
each. A route's kind follows its effect, not its HTTP method: a POST that only
checks a value is View, a GET that starts probes is Act.
"""
from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, Optional, Tuple

READ = "read"
WRITE = "write"


@dataclass(frozen=True)
class Area:
    id: str
    label: str
    view: str
    act: str  # empty: the area has no actions


AREAS: Tuple[Area, ...] = (
    Area("status", "Dashboard & Status",
         "Dashboard figures, server and container status, versions, background job state, IP blocklist results",
         "Ignore a container or a blocklist, run a blocklist check, email the summary"),
    Area("messages", "Messages",
         "Messages, their delivery details, Postfix and Rspamd logs, CSV exports",
         ""),
    Area("outbound", "Outbound",
         "Mail queue and suppression list",
         "Deliver, hold or delete queued mail; add, change, delete and sync suppressions"),
    Area("quarantine", "Quarantine",
         "Quarantined messages, quarantine rules and their log",
         "Release, delete or learn quarantined mail; create, change and delete rules"),
    Area("security", "Security",
         "Netfilter events, Fail2ban state, security alerts, protection rules and hits, SMTP abuse protection",
         "Ban, unban and allow addresses, change Fail2ban, dismiss alerts, act on protection hits, block or unblock sending"),
    Area("rspamd", "Rspamd",
         "Rspamd maps and their content",
         "Save an Rspamd map"),
    Area("dmarc", "DMARC & TLS",
         "DMARC and TLS reports, sources and the import state",
         "Delete reports, start an IMAP import, clear the report cache"),
    Area("domains", "Domains",
         "Your domains and their stored DNS check results",
         "Run DNS checks for your domains"),
    Area("mailboxes", "Mailboxes",
         "Mailbox statistics, devices and rate limits",
         "Set and reset rate limits"),
    Area("logs", "Logs",
         "Raw logs of the mailcow services",
         ""),
    Area("settings", "Settings",
         "The settings, with every secret hidden, and the notification destinations",
         ""),
)

AREA_IDS: FrozenSet[str] = frozenset(a.id for a in AREAS)

# Calls every grant may make, whatever its areas: help text and public facts
ANY = "any"


@dataclass(frozen=True)
class Rule:
    area: str
    kind: str
    # Checked against the path parameters before the call; returns an error
    # text the agent sees, or None to allow
    guard: Optional[str] = None
    # The body for routes that read the JSON themselves (no OpenAPI schema)
    body: Optional[str] = None


def _r(*paths, area, kind, guard=None, body=None) -> Dict[Tuple[str, str], Rule]:
    rule = Rule(area, kind, guard, body)
    out = {}
    for p in paths:
        method, path = p.split(" ", 1)
        out[(method, path)] = rule
    return out


_ITEMS = '{"items": ["<id>", ...]}'

POLICY: Dict[Tuple[str, str], Rule] = {
    **_r("GET /api/docs/{doc_name}", "GET /api/info", "GET /api/health", area=ANY, kind=READ),

    # Dashboard & Status
    **_r("GET /api/stats/dashboard", "GET /api/stats/timeline", "GET /api/stats/top-spam-triggers",
         "GET /api/stats/top-blocked-ips", "GET /api/stats/recent-activity", "GET /api/stats/flow",
         "GET /api/stats/trends", "GET /api/system/summary",
         "GET /api/status/containers", "GET /api/status/storage", "GET /api/status/version",
         "GET /api/status/app-version", "GET /api/status/mailcow-info", "GET /api/status/mailcow-connection",
         "GET /api/status/app-version/changelog/{version}", "GET /api/status/summary",
         "GET /api/status/container-logs", "GET /api/settings/info", "GET /api/settings/health",
         "GET /api/blacklist/monitored", "GET /api/blacklist/progress", "GET /api/blacklist/config",
         "GET /api/blacklist/summary", "GET /api/blacklist/ignored",
         area="status", kind=READ),
    **_r("PUT /api/status/containers/{container}/ignore", "PUT /api/blacklist/lists/{zone}/ignore",
         "POST /api/blacklist/check", "POST /api/system/summary/email",
         area="status", kind=WRITE),

    # Messages
    **_r("GET /api/messages", "GET /api/messages/facets", "GET /api/message/{correlation_key}/details",
         "GET /api/message/{correlation_key}", "GET /api/logs/postfix", "GET /api/logs/postfix/by-queue/{queue_id}",
         "GET /api/logs/rspamd", "GET /api/export/postfix/csv", "GET /api/export/rspamd/csv",
         "GET /api/export/messages/csv",
         area="messages", kind=READ),

    # Outbound
    **_r("GET /api/queue", "GET /api/suppressions", "GET /api/suppressions/stats", "GET /api/suppressions/config",
         "GET /api/suppressions/{suppression_id}/events", "GET /api/suppressions/export",
         "GET /api/suppressions/rspamd/state",
         area="outbound", kind=READ),
    **_r("POST /api/queue/action", area="outbound", kind=WRITE,
         body='{"items": ["<queue id>", ...], "action": "deliver" | "hold" | "unhold" | "flush" | "super_delete"}'),
    **_r("POST /api/queue/delete", area="outbound", kind=WRITE, body='{"items": ["<queue id>", ...]}'),
    **_r("POST /api/suppressions", "PUT /api/suppressions/{suppression_id}", "DELETE /api/suppressions/{suppression_id}",
         "POST /api/suppressions/sync", "POST /api/suppressions/rspamd/import", "POST /api/suppressions/rspamd/clear",
         "POST /api/suppressions/start-fresh",
         area="outbound", kind=WRITE),

    # Quarantine
    **_r("GET /api/quarantine", "GET /api/quarantine/{item_id}/details", "GET /api/quarantine/rules",
         "GET /api/quarantine/rules/logs", "POST /api/quarantine/rules/test",
         area="quarantine", kind=READ),
    **_r("POST /api/quarantine/release", "POST /api/quarantine/delete", "POST /api/quarantine/learnham",
         "POST /api/quarantine/learnspam",
         area="quarantine", kind=WRITE, body='{"items": ["<quarantine item id>", ...]}'),
    **_r("POST /api/quarantine/rules", "PUT /api/quarantine/rules/{rule_id}", "DELETE /api/quarantine/rules/{rule_id}",
         "POST /api/quarantine/rules/{rule_id}/toggle",
         area="quarantine", kind=WRITE),

    # Security
    **_r("GET /api/logs/netfilter", "GET /api/logs/netfilter/countries", "GET /api/logs/netfilter/stats/by-country",
         "GET /api/logs/netfilter/stats/by-network", "GET /api/logs/netfilter/overview",
         "GET /api/export/netfilter/csv", "GET /api/security/addresses", "GET /api/fail2ban", "GET /api/rw-status",
         "GET /api/geoip/{ip}", "GET /api/security-alerts", "GET /api/security-alerts/{alert_id}/activity",
         "GET /api/protection/rules", "GET /api/protection/hits", "GET /api/smtp-abuse/status",
         "GET /api/smtp-abuse/whitelist", "GET /api/smtp-abuse/history",
         area="security", kind=READ),
    **_r("POST /api/fail2ban", area="security", kind=WRITE,
         body='{"attr": {<mailcow Fail2ban attributes>}} - the same object GET /api/fail2ban returns'),
    **_r("POST /api/fail2ban/policy", area="security", kind=WRITE,
         body='{"ban_time", "max_ban_time", "max_attempts", "retry_window", "netban_ipv4", "netban_ipv6": <int>, '
              '"ban_time_increment": <bool>}'),
    **_r("POST /api/fail2ban/unban", "POST /api/fail2ban/ban", "POST /api/fail2ban/allow",
         area="security", kind=WRITE, body='{"ip": "<address or network>"}'),
    **_r("POST /api/fail2ban/remove", area="security", kind=WRITE,
         body='{"ip": "<address or network>", "list": "blacklist" | "whitelist"}'),
    **_r("POST /api/fail2ban/repair", area="security", kind=WRITE,
         body='{"entry": "<entry as listed>", "list": "blacklist" | "whitelist"}'),
    **_r("POST /api/security-alerts/{alert_id}/acknowledge", "POST /api/security-alerts/acknowledge-all",
         "POST /api/security-alerts/acknowledgements/{receipt}/undo", "PUT /api/protection/rules",
         "POST /api/protection/hits/{hit_id}/dismiss", "POST /api/protection/hits/{hit_id}/ban",
         "POST /api/protection/hits/{hit_id}/undo", "POST /api/smtp-abuse/whitelist", "PUT /api/smtp-abuse/whitelist",
         "DELETE /api/smtp-abuse/whitelist/{email}", "POST /api/smtp-abuse/mailboxes/{email}/block",
         "POST /api/smtp-abuse/mailboxes/{email}/unblock",
         area="security", kind=WRITE),

    # Rspamd
    **_r("GET /api/rspamd/config", "GET /api/rspamd/maps", "GET /api/rspamd/maps/{filename}",
         "POST /api/rspamd/validate",
         area="rspamd", kind=READ),
    **_r("PUT /api/rspamd/maps/{filename}", area="rspamd", kind=WRITE),

    # DMARC & TLS
    **_r("GET /api/dmarc/insights", "GET /api/dmarc/reports/config", "GET /api/dmarc/reports/all",
         "GET /api/dmarc/reports/domains", "GET /api/dmarc/domains", "GET /api/dmarc/domains/{domain}/overview",
         "GET /api/dmarc/domains/{domain}/tls-rpt-record", "GET /api/dmarc/domains/{domain}/calendar",
         "GET /api/dmarc/domains/{domain}/reports", "GET /api/dmarc/domains/{domain}/reports/{report_date}/details",
         "GET /api/dmarc/domains/{domain}/sources", "GET /api/dmarc/domains/{domain}/sources/{source_ip}/details",
         "GET /api/dmarc/domains/{domain}/tls-reports", "GET /api/dmarc/domains/{domain}/tls-reports/daily",
         "GET /api/dmarc/domains/{domain}/tls-reports/{report_date}/details", "GET /api/dmarc/imap/status",
         "GET /api/dmarc/imap/history",
         area="dmarc", kind=READ),
    **_r("POST /api/dmarc/cache/clear", "DELETE /api/dmarc/reports/domains/{domain}",
         "DELETE /api/dmarc/reports/{report_type}/{report_id}", "POST /api/dmarc/imap/sync",
         area="dmarc", kind=WRITE),

    # Domains: a check runs DNS, HTTPS (MTA-STS) and SMTP (DANE) probes, so it
    # is an action, and only for the app's own domains
    **_r("GET /api/domains/all", area="domains", kind=READ),
    **_r("GET /api/domains/{domain}/dns-check", "POST /api/domains/{domain}/check-dns",
         area="domains", kind=WRITE, guard="own_domain"),
    **_r("POST /api/domains/check-all-dns", area="domains", kind=WRITE),

    # Mailboxes
    **_r("GET /api/mailbox-stats/summary", "GET /api/mailbox-stats/all", "GET /api/mailbox-stats/domains",
         "GET /api/mailbox-stats/refresh", "GET /api/devices", "GET /api/rate-limits/events",
         "GET /api/rate-limits/sender-events", "GET /api/rate-limits/limits",
         area="mailboxes", kind=READ),
    **_r("POST /api/rate-limits/mailbox", "POST /api/rate-limits/domain", "POST /api/rate-limits/bulk",
         "POST /api/rate-limits/reset",
         area="mailboxes", kind=WRITE),

    # Logs
    **_r("GET /api/raw-logs/services", "GET /api/raw-logs/worker-status", "GET /api/raw-logs/{service}",
         "GET /api/raw-logs/{service}/smart-filters",
         area="logs", kind=READ),

    # Settings: secrets are masked by these routes
    **_r("GET /api/settings", "GET /api/settings/geoip/status", "GET /api/notifications/types",
         "GET /api/notifications/channels",
         area="settings", kind=READ),
}

_SIGN_IN = "sign-in and sessions are for people only"
_SETTINGS = "only people change settings, because a change could turn off sign-in or agent limits, or send alerts elsewhere"

EXCLUDED: Dict[Tuple[str, str], str] = {
    **{(m, p): _SIGN_IN for m, p in (
        ("GET", "/api/auth/verify"), ("POST", "/api/auth/session"), ("GET", "/api/auth/provider-info"),
        ("GET", "/api/auth/login"), ("GET", "/api/auth/callback"), ("POST", "/api/auth/logout"),
        ("GET", "/api/auth/logout"), ("GET", "/api/auth/status"))},
    ("GET", "/api/raw-logs/ws-token"): "issues a credential for the live log stream",
    ("PUT", "/api/settings"): _SETTINGS,
    ("POST", "/api/settings/purge-feature-data"): _SETTINGS,
    ("POST", "/api/settings/import-from-env"): _SETTINGS,
    ("POST", "/api/settings/test/smtp"): "sends mail on the operator's behalf",
    ("POST", "/api/settings/test/imap"): "signs in to the IMAP mailbox",
    ("POST", "/api/settings/geoip/download"): _SETTINGS,
    ("POST", "/api/settings/maxmind/validate"): "checks a credential",
    ("POST", "/api/settings/mailcow/rw-key/validate"): "checks a credential",
    ("POST", "/api/settings/rspamd/password/validate"): "checks a credential",
    ("POST", "/api/settings/geoip/validate"): _SETTINGS,
    ("POST", "/api/settings/jobs/{job_name}/run"): "a job can sync, delete and ban without the permission of its area",
    ("POST", "/api/notifications/channels"): _SETTINGS,
    ("PUT", "/api/notifications/channels/{channel_id}"): _SETTINGS,
    ("DELETE", "/api/notifications/channels/{channel_id}"): _SETTINGS,
    ("POST", "/api/notifications/channels/{channel_id}/test"): "sends a message to an outside service",
    ("POST", "/api/notifications/test"): "sends a message to an outside service",
    ("POST", "/api/dmarc/upload"): "file uploads are not offered to agents",
    ("POST", "/api/suppressions/import"): "file uploads are not offered to agents",
}

# Managing agents is for people, whatever the method (consent.py registers these)
AGENTS_API_PREFIX = "/api/agents"
_MANAGE = "managing agents is for people"


def excluded_reason(method: str, path: str) -> Optional[str]:
    if path == AGENTS_API_PREFIX or path.startswith(AGENTS_API_PREFIX + "/"):
        return _MANAGE
    return EXCLUDED.get((method, path))


def read_scope(area: str) -> str:
    return f"{area}:{READ}"


def write_scope(area: str) -> str:
    return f"{area}:{WRITE}"


def all_scopes() -> Tuple[str, ...]:
    """Every scope, in menu order: View, then Act where the area has actions."""
    out = []
    for a in AREAS:
        out.append(read_scope(a.id))
        if a.act:
            out.append(write_scope(a.id))
    return tuple(out)


def read_scopes() -> Tuple[str, ...]:
    return tuple(read_scope(a.id) for a in AREAS)


def parse_scopes(value: Optional[str]) -> FrozenSet[str]:
    """The known scopes in a space separated string; anything else is ignored."""
    known = set(all_scopes())
    return frozenset(s for s in (value or "").split() if s in known)


def grant_scopes(views: Iterable[str], acts: Iterable[str]) -> str:
    """The scope string for the areas a person ticked. Act includes View."""
    areas = {a.id: a for a in AREAS}
    chosen = set()
    for area in views:
        if area in areas:
            chosen.add(read_scope(area))
    for area in acts:
        if area in areas and areas[area].act:
            chosen.add(read_scope(area))
            chosen.add(write_scope(area))
    return " ".join(s for s in all_scopes() if s in chosen)


def requested_views(requested: FrozenSet[str]) -> Tuple[str, ...]:
    """The areas whose View box starts ticked on the consent page.

    Act never starts ticked, whatever the client asked for. Without a known
    scope in the request, every area starts with View.
    """
    areas = tuple(a.id for a in AREAS if read_scope(a.id) in requested or write_scope(a.id) in requested)
    return areas or tuple(a.id for a in AREAS)


def allows(scopes: FrozenSet[str], rule: Rule) -> bool:
    if rule.area == ANY:
        return rule.kind == READ
    return f"{rule.area}:{rule.kind}" in scopes


def areas_of(scopes: FrozenSet[str]) -> Dict[str, str]:
    """area id -> 'act' or 'view' for the areas a grant covers, in menu order."""
    out = {}
    for a in AREAS:
        if write_scope(a.id) in scopes:
            out[a.id] = "act"
        elif read_scope(a.id) in scopes:
            out[a.id] = "view"
    return out
