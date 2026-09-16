# Environment Variables Reference

Complete reference guide for all environment variables available in mailcow Logs Viewer.

> **Note:** When `SETTINGS_EDIT_VIA_UI_ENABLED=true`, most settings can be managed from the web UI. Only database connection settings (`POSTGRES_*`) and the UI editing flag itself must remain in the `.env` file.

---

## Required Settings

These settings **must** be configured in your `.env` file:

| Variable | Type | Description | Example |
|----------|------|-------------|---------|
| `MAILCOW_URL` | string | Your mailcow instance URL (without trailing slash) | `https://mail.example.com` |
| `MAILCOW_API_KEY` | string | mailcow API key — **Read-Only** (generate from System → API in mailcow admin). Required permissions: Read access to logs | `abc123-def456-ghi789` |
| `POSTGRES_USER` | string | PostgreSQL username | `mailcowlogs` |
| `POSTGRES_PASSWORD` | string | PostgreSQL password. ⚠️ Avoid special chars (`@:/?#`) - breaks connection strings. 💡 Use UUID: `uuidgen` or https://it-tools.tech/uuid-generator | `a7f3c8e2-4b1d-4f9a-8c3e-7d2f1a9b5e4c` |
| `POSTGRES_DB` | string | PostgreSQL database name | `mailcowlogs` |
| `POSTGRES_HOST` | string | PostgreSQL host (use `db` for docker-compose setup) | `db` |
| `POSTGRES_PORT` | integer | PostgreSQL port | `5432` |

---

## Settings UI Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SETTINGS_EDIT_VIA_UI_ENABLED` | boolean | `false` | Allow editing app settings from the web UI (Settings tab). When enabled, values are stored in the database (priority: Default → DB → ENV; ENV always wins). **Must be in .env** and app must be restarted after change. |

---

## mailcow API Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MAILCOW_API_KEY_RW` | string | (empty) | mailcow API key — **Read-Write** (optional). Generate a separate key from System → API with write permissions. Used only for edit operations (e.g. Fail2Ban settings). When not set, edit features are disabled |
| `MAILCOW_API_VERIFY_SSL` | boolean | `true` | Verify SSL certificates when connecting to mailcow API. Set to `false` for development environments with self-signed certificates |
| `MAILCOW_API_TIMEOUT` | integer | `30` | API request timeout in seconds |

---

## Fetch Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `FETCH_INTERVAL` | integer | `60` | Seconds between log fetches from mailcow. Lower = more frequent updates, higher load on mailcow |
| `FETCH_COUNT_POSTFIX` | integer | `2000` | Number of Postfix records to fetch per request. Recommended: 500-2000 for most servers, increase if you have high email volume |
| `FETCH_COUNT_RSPAMD` | integer | `500` | Number of Rspamd records to fetch per request |
| `FETCH_COUNT_NETFILTER` | integer | `500` | Number of Netfilter records to fetch per request |
| `FETCH_MAX_PAGES` | integer | `50` | Maximum number of pages to fetch per cycle for Postfix/Rspamd (safety limit to prevent infinite loops) |
| `RETENTION_DAYS` | integer | `7` | Number of days to keep logs in database. Logs older than this will be automatically deleted. Recommended: 7 for most cases, 30 for compliance/audit requirements |

---

## Correlation Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MAX_CORRELATION_AGE_MINUTES` | integer | `10` | Stop searching for correlations older than this (minutes) |
| `CORRELATION_CHECK_INTERVAL` | integer | `120` | Seconds between correlation completion checks |

---

## Application Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `APP_TITLE` | string | `mailcow Logs Viewer` | Application title (shown in browser tab) |
| `APP_LOGO_URL` | string | (empty) | Logo URL (optional, leave empty to use the default project icon) |
| `LOG_LEVEL` | string | `WARNING` | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `DEBUG` | boolean | `false` | Enable debug mode (shows detailed errors, use only for development). ⚠️ **WARNING: Never enable in production!** |
| `MAX_SEARCH_RESULTS` | integer | `1000` | Maximum records to return in search results |
| `CSV_EXPORT_LIMIT` | integer | `10000` | CSV export row limit |
| `SCHEDULER_WORKERS` | integer | `4` | Thread pool size for blocking scheduler jobs (e.g. DMARC IMAP sync). Valid range: 1-64. Higher values allow more blocking jobs to run in parallel |
| `DISABLED_FEATURES` | string | (empty) | Comma-separated list of features to disable (hides navigation, stops background jobs). Valid values: `netfilter`, `queue`, `quarantine`, `spam-filter`, `domains`, `dmarc`, `mailbox-stats`, `rate-limits`, `logs`, `blacklist`. Can also be managed from the Settings UI when `SETTINGS_EDIT_VIA_UI_ENABLED=true` |

---

## SMTP Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SMTP_ENABLED` | boolean | `false` | Enable SMTP for sending notifications |
| `SMTP_HOST` | string | (empty) | SMTP server hostname |
| `SMTP_PORT` | integer | `587` | SMTP server port (587 for TLS, 465 for SSL, 25 for plain) |
| `SMTP_USE_TLS` | boolean | `false` | Use STARTTLS for SMTP connection (recommended) |
| `SMTP_USE_SSL` | boolean | `false` | Use Implicit SSL/TLS for SMTP connection (usually port 465) |
| `SMTP_USER` | string | (empty) | SMTP username (usually email address) |
| `SMTP_PASSWORD` | string | (empty) | SMTP password |
| `SMTP_FROM` | string | (empty) | From address for emails (defaults to SMTP user if not set) |
| `SMTP_RELAY_MODE` | boolean | `false` | Relay mode - send emails without authentication (for local relay servers). When enabled, username and password are not required |

---

## Admin & Notification Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ADMIN_EMAIL` | string | (empty) | Administrator email for system notifications |
| `BLACKLIST_ALERT_EMAIL` | string | (empty) | Email address for blacklist alerts (defaults to `ADMIN_EMAIL` if not set) |
| `ENABLE_WEEKLY_SUMMARY` | boolean | `true` | Enable weekly summary email report (sent to `ADMIN_EMAIL`) |

---

## Notification Destinations

Alerts (blacklist listings, DMARC processing errors, security alerts) are delivered by email and to any number of **notification destinations** - Slack, Discord, Telegram, ntfy, Gotify, or a custom JSON endpoint.

Destinations are **configured in the web UI**, not through environment variables: go to **Settings -> Notifications -> Add destination**, pick the service, and fill in only the fields that service needs (Telegram asks for a bot token and chat ID, ntfy for a server and topic, Slack for its incoming-webhook URL). The endpoint URL is assembled for you. Each destination has a **Send test** button, can be enabled/disabled individually, and shows whether the last delivery succeeded.

You can add as many destinations as you like, and choose **which alerts each one receives**:

| Alert type | Sent when |
|------------|-----------|
| **Security** | A mailbox looks compromised (outbound spike), an authentication attack is detected, or SMTP is disabled by abuse protection |
| **IP blacklist** | Your server IP appears on a spam blacklist, or is no longer listed |
| **DNS record changes** | A domain's SPF, DKIM, DMARC or TLSA record changed |
| **DMARC processing errors** | A DMARC report could not be imported or parsed |

A destination with all types ticked receives everything. Destinations created before this existed keep receiving all alerts.

| Setting | Where | Description |
|---------|-------|-------------|
| Destinations | Settings -> Notifications | Add/edit/remove Slack, Discord, Telegram, ntfy, Gotify or custom webhook targets |
| `ADMIN_EMAIL` | ENV or Settings | Email address for general alerts (see Admin & Notification Configuration above) |

> **Upgrading from the old single-webhook settings?** Nothing to do. `WEBHOOK_ENABLED`, `WEBHOOK_TYPE`, `WEBHOOK_URL` and `WEBHOOK_TELEGRAM_CHAT_ID` are migrated automatically into a destination on first start, and are not used afterwards.

---

## Security Monitoring & Abuse Protection

Two complementary layers for detecting and stopping a compromised mailbox:

- **Anomaly detection** - *alerts only*. Compares each mailbox against **its own** recent sending baseline, so it catches an account takeover even at low volumes. Never takes action on its own.
- **SMTP abuse protection** - *acts*. Applies a **hard** outbound limit and disables SMTP for a mailbox that crosses it.

Both write to the same security alert feed (dashboard banner) and notify through email + webhook.

### Anomaly Detection

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ANOMALY_DETECTION_ENABLED` | boolean | `false` | Enable anomaly detection (outbound volume spikes and authentication-failure bursts) |
| `ANOMALY_CHECK_INTERVAL` | integer | `15` | Minutes between detection runs. Also the length of the window each run examines |
| `ANOMALY_VOLUME_MULTIPLIER` | float | `5.0` | Alert when a mailbox's current sending rate exceeds this multiple of its own baseline (e.g. `5.0` = five times its normal rate) |
| `ANOMALY_VOLUME_MIN_MESSAGES` | integer | `30` | Noise floor: a mailbox must send at least this many messages in the window before a spike can alert |
| `ANOMALY_BASELINE_DAYS` | integer | `7` | Days of history used to compute each mailbox's normal sending rate |
| `ANOMALY_AUTH_FAILURE_THRESHOLD` | integer | `20` | Alert when a username accumulates this many authentication failures within the window (brute-force / credential stuffing) |
| `ANOMALY_ALERT_COOLDOWN_HOURS` | integer | `6` | Suppress repeat alerts for the same mailbox and alert type within this many hours |

> Alerts appear as a banner on the Dashboard and can be dismissed there. No mailbox is ever blocked by this feature.

### SMTP Abuse Protection

Automatically disables **sending** for a mailbox that exceeds a hard outbound limit - the usual signature of a compromised account. **Receiving (IMAP) is never affected**, so the user keeps access to their mail. Manage blocked mailboxes and the whitelist under **Security → Abuse Protection**.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SMTP_ABUSE_ENABLED` | boolean | `false` | Enable automatic SMTP blocking |
| `SMTP_ABUSE_THRESHOLD` | integer | `100` | Outbound messages a mailbox may send within the rolling window before SMTP is disabled |
| `SMTP_ABUSE_WINDOW_MINUTES` | integer | `60` | Length of the rolling window in minutes |
| `SMTP_ABUSE_REVOKE_APP_PASSWORDS` | boolean | `true` | Also revoke the mailbox's app passwords when blocking (a compromised mailbox usually sends via an app password) |
| `SMTP_ABUSE_UNBLOCK_GRACE_MINUTES` | integer | `60` | After an operator re-enables SMTP, do not auto-block that mailbox again for this many minutes. Prevents the mailbox from being re-blocked immediately while old messages are still inside the rolling window |
| `SMTP_ABUSE_HELP_ADDRESS` | string | (empty) | Support address included in the notification sent to the blocked mailbox (falls back to `ADMIN_EMAIL`) |

> **Prerequisites:**
> - `MAILCOW_API_KEY_RW` - **required**; blocking uses the mailcow edit API. Without it the feature stays inactive
> - Whitelist mailboxes that legitimately send in bursts (newsletters, ticketing, monitoring) under Security → Abuse Protection
> - Set `SMTP_ENABLED` / `ADMIN_EMAIL` (or a webhook) to be notified when a mailbox is blocked
>
> **Tip:** start with a threshold well above your busiest legitimate mailbox's hourly volume, watch the Security page for a few days, then tighten it.

---

## Blacklist Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DNS_CHANGE_ALERTS_ENABLED` | boolean | `true` | Alert when a domain's SPF, DKIM, DMARC or TLSA (DANE) record changes. The alert names the domain and shows the old and new value, so you can update the records at your registrar. A failed DNS lookup is never treated as a change, so a temporary resolver problem cannot cause a false alarm |
| `BLACKLIST_DNS_SERVERS` | string | (empty) | DNS resolvers used for IP blacklist (RBL) lookups, comma-separated. **Spamhaus rejects queries that arrive through public resolvers** (Google, Cloudflare, Quad9 and all DoH endpoints) and answers with a `127.255.255.x` rejection code instead of a real result. Point this at your own recursive resolver - in a mailcow deployment: `172.22.1.254` (unbound-mailcow). Leave empty to use the container's own resolver, which is correct in most setups |
| `BLACKLIST_SOURCE_SERVER_IP` | boolean | `true` | Monitor the auto-detected WAN IP (reported by the mailcow status API) on spam blacklists (RBLs). Set to `false` when outbound mail goes through a relay host: the auto-detected WAN entry is deactivated (not deleted) and only the other enabled sources are monitored |
| `BLACKLIST_SOURCE_TRANSPORTS` | boolean | `true` | Monitor the public IPs of active mailcow transports on spam blacklists. Each transport nexthop is resolved to **all** of its public IPs, so relay pools with several addresses are fully covered |
| `BLACKLIST_SOURCE_RELAYHOSTS` | boolean | `true` | Monitor the public IPs of active mailcow relayhosts (sender-dependent transports) on spam blacklists |
| `BLACKLIST_SOURCE_MANUAL_HOSTS` | string | (empty) | Additional hosts to monitor on spam blacklists, comma-separated, e.g. `203.0.113.10,2001:db8::10,relay.example.com`. Accepts IPv4/IPv6 addresses and hostnames (a hostname is resolved to all of its public IPs, source `config`). Monitored **in addition** to the sources above - these may also be hosts unrelated to this mailcow server. Invalid entries are rejected on save |
| `BLACKLIST_EMAILS` | string | (empty) | Comma-separated list of email addresses to hide from logs (no spaces). These emails will NOT be stored in the database. Use cases: BCC addresses that receive all outbound mail, monitoring/health check addresses, internal system addresses. Example: `bcc-archive@example.com,monitor@example.com` |

---

## Domain SPF Check Configuration

Which sending IPs must pass each domain's SPF record on the Domains page. With a relay setup the relay IPs matter, not the auto-detected WAN IP.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DOMAIN_SPF_SOURCE_SERVER_IP` | boolean | `true` | Validate the auto-detected WAN IP against each domain's SPF record. Set to `false` when outbound mail leaves through a relay host and the WAN IP is not supposed to be in your SPF records |
| `DOMAIN_SPF_SOURCE_TRANSPORTS` | boolean | `false` | Also validate the public IPs resolved from active mailcow transport nexthops against each domain's SPF record |
| `DOMAIN_SPF_SOURCE_RELAYHOSTS` | boolean | `false` | Also validate the public IPs resolved from active mailcow relayhosts against each domain's SPF record |
| `DOMAIN_SPF_SOURCE_MANUAL_HOSTS` | string | (empty) | Additional hosts that must pass each domain's SPF check, comma-separated. Accepts IPv4/IPv6 addresses and hostnames. **Outbound sending addresses only** - every entry must pass the SPF check, so do not add addresses that never send mail (such as an inbound-only MX). Invalid entries are rejected on save |
| `DOMAIN_SPF_SOURCE_DMARC_HISTORY` | boolean | `false` | Also validate source IPs observed with a passing SPF result in the last 30 days of imported DMARC aggregate reports for each domain (up to 20 IPs per domain). Caution: with relaxed SPF alignment, an IP sending from an ESP subdomain can appear as an aligned pass without being listed in the domain's own SPF record, which then shows up as a false warning |

---

## DMARC Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DMARC_RETENTION_DAYS` | integer | `60` | DMARC reports retention in days |
| `DMARC_MANUAL_UPLOAD_ENABLED` | boolean | `true` | Allow manual upload of DMARC reports via UI |
| `DMARC_ALLOW_REPORT_DELETE` | boolean | `false` | Allow deleting DMARC/TLS reports from the UI |
| `DMARC_ERROR_EMAIL` | string | (empty) | Email address for DMARC error notifications (defaults to `ADMIN_EMAIL` if not set) |

### DMARC Insights (Policy Recommendations)

Turns collected DMARC report data into advice: when a domain's pass rate and volume are healthy under a lax policy, the DMARC page suggests tightening it (`p=none` → `p=quarantine` → `p=reject`), and it flags source IPs that only recently started sending for a domain **and** are failing DMARC (possible spoofing).

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DMARC_INSIGHTS_WINDOW_DAYS` | integer | `28` | Days of DMARC report data used for recommendations |
| `DMARC_INSIGHTS_PASS_THRESHOLD` | float | `99.5` | Minimum DMARC pass rate (%) before a stricter policy is recommended |
| `DMARC_INSIGHTS_MIN_VOLUME` | integer | `100` | Minimum reported messages in the window before any recommendation is made (avoids advice based on a handful of messages) |

> Read-only: this feature never changes DNS records - it only shows recommendations on the DMARC page.

### DMARC IMAP Auto-Import Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DMARC_IMAP_ENABLED` | boolean | `false` | Enable automatic DMARC report import from IMAP |
| `DMARC_IMAP_HOST` | string | (empty) | IMAP server hostname (e.g., `imap.gmail.com`) |
| `DMARC_IMAP_PORT` | integer | `993` | IMAP server port (993 for SSL, 143 for non-SSL) |
| `DMARC_IMAP_USE_SSL` | boolean | `true` | Use SSL/TLS for IMAP connection |
| `DMARC_IMAP_USER` | string | (empty) | IMAP username (email address) |
| `DMARC_IMAP_PASSWORD` | string | (empty) | IMAP password |
| `DMARC_IMAP_FOLDER` | string | `INBOX` | IMAP folder to scan for DMARC reports |
| `DMARC_IMAP_DELETE_AFTER` | boolean | `true` | Delete emails after successful processing |
| `DMARC_IMAP_INTERVAL` | integer | `3600` | Interval between IMAP syncs in seconds (default: 3600 = 1 hour) |
| `DMARC_IMAP_RUN_ON_STARTUP` | boolean | `true` | Run IMAP sync once on application startup |
| `DMARC_IMAP_BATCH_SIZE` | integer | `10` | Number of emails to process per batch (prevents memory issues with large mailboxes) |
| `DMARC_IMAP_SCAN_ALL_UNSEEN` | boolean | `false` | Scan all unread emails for DMARC/TLS-RPT attachments, not just those matching known subject patterns. Enable if you receive reports from providers that use non-English subjects. Only recommended for dedicated DMARC mailboxes |

---

## MaxMind GeoIP Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MAXMIND_ACCOUNT_ID` | string | (empty) | MaxMind Account ID for GeoIP database downloads |
| `MAXMIND_LICENSE_KEY` | string | (empty) | MaxMind License Key for GeoIP database downloads |

> **Note:** To use MaxMind GeoIP features, you need to add a data volume in `docker-compose.yml`:
> ```yaml
> services:
>   app:
>     volumes:
>       - ./data:/app/data
> ```

---

## Raw Logs Configuration (Live Log Viewer)

Settings for the background raw log collector that powers the Logs page. Logs are fetched from mailcow services and stored in a dedicated database table, then streamed to the UI via WebSocket.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RAW_LOGS_ENABLED` | boolean | `true` | Enable background raw log collection for the Logs page. When disabled, no logs are fetched and the Logs page shows historical data only |
| `RAW_LOGS_FETCH_INTERVAL` | integer | `20` | Seconds between raw log fetch cycles. Lower = more real-time, higher = less API load |
| `RAW_LOGS_FETCH_COUNT` | integer | `1000` | Number of log entries to fetch per service per cycle. Higher values catch more logs but increase API load |
| `RAW_LOGS_RETENTION_DAYS` | integer | `2` | Days to keep raw logs in the database. Older logs are automatically deleted daily at 3:00 AM |
| `RAW_LOGS_SERVICES` | string | `all` | Which mailcow services to collect logs from. Use `all` for all 10 services, or comma-separated list: `postfix,dovecot,sogo,api`. Available: `acme`, `api`, `autodiscover`, `dovecot`, `netfilter`, `postfix`, `ratelimited`, `rspamd-history`, `sogo`, `watchdog` |

---

## Rspamd Integration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RSPAMD_URL` | string | (empty) | Address of the Rspamd controller. **Leave empty** to reach Rspamd through mailcow itself (`MAILCOW_URL/rspamd`) - this is correct for most setups, including when this app runs on a different server, because mailcow's own web server proxies the request. Only set it when this app has **direct network access** to the Rspamd controller *and* the path through mailcow fails - for example a reverse proxy in front of mailcow that redirects (302) `/rspamd` before the `Password` header is evaluated. Value depends on where the app runs: on the same Docker network as mailcow use `http://rspamd-mailcow:11334`; from another host you would first have to expose that port, which mailcow does not do by default |
| `RSPAMD_PASSWORD` | string | (empty) | Rspamd UI/API password for reading and writing Rspamd map data. Found in mailcow's `mailcow.conf` as `RSPAMD_PASSWORD` or via the mailcow admin UI. Required for the Spam Filter maps editor |

---

## Spam Suppression Configuration

Settings for the automatic email suppression feature. When enabled, the system monitors Postfix logs for hard bounces and the live mail queue for stuck deferred emails, automatically blocking future delivery attempts via Rspamd.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SUPPRESSION_ENABLED` | boolean | `false` | Master switch for the suppression system. When enabled, bounced/rejected recipients are automatically blocked from receiving future emails |
| `SUPPRESSION_AUTO_DETECT` | boolean | `true` | Automatically scan Postfix logs to detect hard bounce (5.x.x) errors and add recipients to the suppression list |
| `SUPPRESSION_RSPAMD_SYNC` | boolean | `true` | Sync the suppression list to Rspamd's `global_rcpt_blacklist.map` so blocked emails are rejected at SMTP level. Requires `RSPAMD_PASSWORD` and `MAILCOW_API_KEY_RW` |
| `SUPPRESSION_WHITELIST_DOMAINS` | string | (empty) | Domains that should never be suppressed, even if they bounce. Comma-separated (e.g., `gmail.com,outlook.com`) |
| `SUPPRESSION_HARD_BOUNCE_ACTION` | string | `suppress` | What to do when a permanent delivery failure (5.x.x) is detected: `suppress` (block the recipient immediately) or `ignore` (do nothing) |
| `SUPPRESSION_SOFT_BOUNCE_ACTION` | string | `count` | What to do when a temporary delivery failure (4.x.x) is detected in Postfix logs: `suppress` (block immediately), `count` (block after reaching threshold), or `ignore` (do nothing). Note: deferred emails stuck in the queue are handled separately by Queue Cleanup below |
| `SUPPRESSION_SOFT_BOUNCE_THRESHOLD` | integer | `3` | How many soft bounces from Postfix logs before the recipient is suppressed (only used when `SUPPRESSION_SOFT_BOUNCE_ACTION=count`) |
| `SUPPRESSION_BASE_EXPIRY_DAYS` | integer | `7` | How long to block a recipient in days. Multiplied by bounce count for repeat offenders (e.g., 7 × 3 bounces = 21 days). Used by all suppression types (hard bounces, soft bounces, and queue cleanup) |
| `SUPPRESSION_MAX_EXPIRY_DAYS` | integer | `90` | Maximum block duration cap in days, regardless of bounce count |

### Deferred Queue Cleanup

Automatically monitors the live mail queue for deferred emails that have been stuck longer than a configurable threshold. When a stuck email is found, it is deleted from the queue and the recipient is suppressed. This catches soft bounces that may be missed by log-based detection on busy servers.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `QUEUE_CLEANUP_ENABLED` | boolean | `true` | Automatically monitor the mail queue for stuck deferred emails. If an email has been deferred longer than the threshold, it is deleted and the recipient is suppressed |
| `QUEUE_CLEANUP_THRESHOLD_MINUTES` | integer | `60` | How long (in minutes) a deferred email must be stuck in the queue before it is automatically deleted and the recipient suppressed |

> **Prerequisites:**
> - `SUPPRESSION_ENABLED=true` — Queue cleanup is part of the suppression system
> - `MAILCOW_API_KEY_RW` — Required for deleting queue items and syncing to Rspamd maps
> - `RSPAMD_PASSWORD` — Required for reading/writing Rspamd map files
> - Block duration uses `SUPPRESSION_BASE_EXPIRY_DAYS` with progressive expiry

---

## Quarantine Auto-Rules Configuration

Settings for the automatic quarantine rule processing feature. When rules are defined and a Read-Write API key is configured, the system periodically checks quarantine items against user-defined rules and automatically releases or deletes matching emails.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `QUARANTINE_RULES_MAX_ACTIONS` | integer | `50` | Safety limit: maximum emails to release/delete per scheduler run. Prevents accidental mass-processing from overly broad rules. Set lower for cautious environments |
| `QUARANTINE_RULES_INTERVAL` | integer | `5` | Minutes between quarantine rule processing runs. Lower = faster response to new quarantine items, higher = less API load on mailcow |
| `QUARANTINE_RULES_LOG_RETENTION_DAYS` | integer | `30` | Days to keep quarantine auto-rule action history. Older logs are automatically cleaned up |

> **Prerequisites:**
> - `MAILCOW_API_KEY_RW` — Required for releasing and deleting quarantine items
> - Rules are managed from the Quarantine page in the web UI (not via environment variables)
> - If no rules are defined or no RW key is configured, the background job simply does nothing

---

## Authentication Configuration

### Basic HTTP Authentication

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `BASIC_AUTH_ENABLED` | boolean | `false` | Enable Basic HTTP authentication. When enabled, ALL pages and API endpoints require Basic Auth. If both `BASIC_AUTH_ENABLED` and `OAUTH2_ENABLED` are true, both methods are available |
| `AUTH_USERNAME` | string | `admin` | Basic auth username |
| `AUTH_PASSWORD` | string | (empty) | Basic auth password (required if `BASIC_AUTH_ENABLED=true` or `AUTH_ENABLED=true`). ⚠️ **WARNING: Use a strong password in production!** |

### OAuth2/OIDC Authentication

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `OAUTH2_ENABLED` | boolean | `false` | Enable OAuth2/OIDC authentication. Works with any standard OAuth2/OIDC provider (Mailcow, Keycloak, Auth0, Google, etc.) |
| `OAUTH2_PROVIDER_NAME` | string | `OAuth2 Provider` | Display name for the OAuth2 provider (shown on login button). Examples: `Mailcow`, `Keycloak`, `Google`, `Microsoft` |
| `OAUTH2_ISSUER_URL` | string | (empty) | OAuth2/OIDC issuer URL for discovery (recommended - auto-discovers endpoints). Examples: `https://mail.example.com` (Mailcow), `https://keycloak.example.com/realms/myrealm` (Keycloak) |
| `OAUTH2_AUTHORIZATION_URL` | string | (empty) | OAuth2 authorization endpoint (auto-discovered if `OAUTH2_ISSUER_URL` provided). Only needed if OIDC discovery is not available |
| `OAUTH2_TOKEN_URL` | string | (empty) | OAuth2 token endpoint (auto-discovered if `OAUTH2_ISSUER_URL` provided). Only needed if OIDC discovery is not available |
| `OAUTH2_USERINFO_URL` | string | (empty) | OAuth2 UserInfo endpoint (auto-discovered if `OAUTH2_ISSUER_URL` provided). Only needed if OIDC discovery is not available |
| `OAUTH2_CLIENT_ID` | string | (empty) | OAuth2 Client ID from your provider |
| `OAUTH2_CLIENT_SECRET` | string | (empty) | OAuth2 Client Secret from your provider |
| `OAUTH2_REDIRECT_URI` | string | (empty) | OAuth2 Redirect URI (callback URL). Must match the redirect URI configured in your OAuth2 provider. Example: `https://your-logs-viewer.example.com/api/auth/callback` |
| `OAUTH2_SCOPES` | string | `openid profile email` | OAuth2 scopes to request |
| `OAUTH2_USE_OIDC_DISCOVERY` | boolean | `true` | Enable OIDC discovery (uses `.well-known/openid-configuration`). Default: `true` (if `OAUTH2_ISSUER_URL` is set) |
| `SESSION_SECRET_KEY` | string | (empty) | Secret key for signing session cookies. **REQUIRED if `OAUTH2_ENABLED=true`**. Also used for Basic Auth logins since 2.7.1: without it a new key is generated on every start, so restarting the container signs everyone out and they log in again. Generate a random secret: `openssl rand -hex 32`. ⚠️ **WARNING: Use a strong random secret in production!** |
| `SESSION_EXPIRY_HOURS` | integer | `24` | Session expiration time in hours |

---

## Configuration Priority

When `SETTINGS_EDIT_VIA_UI_ENABLED=true`, configuration is resolved in this order (later overrides earlier):

1. **Defaults** (from the application)
2. **DB** (values stored via the web UI)
3. **ENV** (environment variables — **always win** when set)

So: ENV overrides DB, and DB overrides defaults. If an environment variable is explicitly set, it always takes precedence over the value stored in the database. This prevents lockout: if you make a configuration mistake in the UI (e.g., wrong OIDC URL or password typo), you can fix it by setting the correct value in your `.env` / `docker-compose.yml` and restarting.

---

## Settings That Cannot Be Changed via UI

The following settings **must** remain in the `.env` file and cannot be changed via the web UI:

- `POSTGRES_HOST`
- `POSTGRES_PORT`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `POSTGRES_DB`
- `SETTINGS_EDIT_VIA_UI_ENABLED`

All other settings can be managed from the Settings tab in the web interface when `SETTINGS_EDIT_VIA_UI_ENABLED=true`.

---

## Related Documentation

- [Getting Started Guide](./GETTING_STARTED.md) - Quick start installation
- [Settings UI Guide](Settings_UI.md) - How to use the web UI for configuration
- [OAuth2 Configuration](./OAuth2_Configuration.md) - Detailed OAuth2/OIDC setup guide
