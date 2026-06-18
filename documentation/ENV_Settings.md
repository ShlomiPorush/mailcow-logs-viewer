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
| `APP_LOGO_URL` | string | (empty) | Logo URL (optional, leave empty for no logo) |
| `LOG_LEVEL` | string | `WARNING` | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `DEBUG` | boolean | `false` | Enable debug mode (shows detailed errors, use only for development). ⚠️ **WARNING: Never enable in production!** |
| `MAX_SEARCH_RESULTS` | integer | `1000` | Maximum records to return in search results |
| `CSV_EXPORT_LIMIT` | integer | `10000` | CSV export row limit |
| `SCHEDULER_WORKERS` | integer | `4` | Thread pool size for blocking scheduler jobs (e.g. DMARC IMAP sync). Valid range: 1-64. Higher values allow more blocking jobs to run in parallel |
| `DISABLED_FEATURES` | string | (empty) | Comma-separated list of features to disable (hides navigation, stops background jobs). Valid values: `netfilter`, `queue`, `quarantine`, `spam-filter`, `domains`, `dmarc`, `mailbox-stats`, `logs`, `blacklist`. Can also be managed from the Settings UI when `SETTINGS_EDIT_VIA_UI_ENABLED=true` |

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

## Blacklist Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `BLACKLIST_EMAILS` | string | (empty) | Comma-separated list of email addresses to hide from logs (no spaces). These emails will NOT be stored in the database. Use cases: BCC addresses that receive all outbound mail, monitoring/health check addresses, internal system addresses. Example: `bcc-archive@example.com,monitor@example.com` |

---

## DMARC Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DMARC_RETENTION_DAYS` | integer | `60` | DMARC reports retention in days |
| `DMARC_MANUAL_UPLOAD_ENABLED` | boolean | `true` | Allow manual upload of DMARC reports via UI |
| `DMARC_ALLOW_REPORT_DELETE` | boolean | `false` | Allow deleting DMARC/TLS reports from the UI |
| `DMARC_ERROR_EMAIL` | string | (empty) | Email address for DMARC error notifications (defaults to `ADMIN_EMAIL` if not set) |

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
| `SESSION_SECRET_KEY` | string | (empty) | Secret key for signing session cookies. **REQUIRED if `OAUTH2_ENABLED=true`**. Generate a random secret: `openssl rand -hex 32`. ⚠️ **WARNING: Use a strong random secret in production!** |
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
