# API reference

Use these endpoints to read viewer data, manage saved configuration and request mailcow actions. Paths without an `/api` prefix below are relative to the API base URL; `/login` and `/ws/raw-logs` are application-root paths.

**Base URL:** `https://logs.example.com/api`

**Authentication:** When Basic authentication or OAuth2/OIDC is enabled, every endpoint except the public ones listed under [Authentication](#authentication) needs a session cookie or Basic Auth credentials.

---

## Contents

- [Authentication](#authentication)

- [Health & Info](#health--info)

- [OAuth2 Authentication Endpoints](#oauth2-authentication-endpoints)

- [Job Status Tracking](#job-status-tracking)

- [Domains](#domains)

- [Mailbox Statistics](#mailbox-statistics)

- [Devices](#devices)

- [Rate Limits](#rate-limits)

- [Messages (Unified View)](#messages-unified-view)

- [Logs](#logs)

- [Queue & Quarantine](#queue--quarantine)

- [Statistics](#statistics)

- [Status](#status)

- [Settings](#settings)

- [GeoIP Management](#geoip-management)

- [SMTP & IMAP Test](#smtp--imap-test)

- [Export](#export)

- [DMARC](#dmarc)

- [DMARC IMAP Auto-Import](#dmarc-imap-auto-import)

- [TLS-RPT (TLS Reporting)](#tls-rpt-tls-reporting)

- [Blacklist Monitoring](#blacklist-monitoring)

- [Reporting](#reporting)

- [Error Responses](#error-responses)

- [System Status](#system-status)

- [Raw Logs (Live Log Viewer)](#raw-logs-live-log-viewer)

- [Spam Filter](#spam-filter)

- [Quarantine Auto-Rules](#quarantine-auto-rules)

- [Security Alerts (Anomaly Detection)](#security-alerts-anomaly-detection)

- [SMTP Abuse Protection](#smtp-abuse-protection)

- [DMARC Insights](#dmarc-insights)

- [Protection rules](#protection-rules)

- [Notification Destinations](#notification-destinations)

- [In-app documentation](#in-app-documentation)

---

## Authentication

### Sign-in methods

You can enable either method, or both:

1. **Basic Authentication**: HTTP Basic Auth with one username and password
2. **OAuth2/OIDC**: sign-in through an OAuth2/OpenID Connect identity provider (Authentik, mailcow, Keycloak, Google, Microsoft and others)

With both off (the default), no endpoint needs credentials.

**Public Endpoints (No Authentication Required):**

- `GET /api/health` - Health check (for Docker monitoring)

- `GET /api/info` - Application information

- `GET /api/auth/provider-info` - Authentication provider information

- `GET /login` - Login page (HTML)

- `GET /api/auth/login` - OAuth2 login initiation

- `GET /api/auth/callback` - OAuth2 callback handler

**Protected Endpoints (Authentication Required):**

- `GET /api/auth/verify` - Verify Basic Auth credentials (returns 401 if invalid)

- `POST /api/auth/session` - Exchange Basic Auth credentials for a session cookie (used by the login form)

- All other `/api/*` endpoints

### Authentication Methods

#### Basic Authentication

When `BASIC_AUTH_ENABLED=true` (or legacy `AUTH_ENABLED=true`), use HTTP Basic Authentication:

- Username: `AUTH_USERNAME` (default: `admin`)

- Password: `AUTH_PASSWORD` (if it is empty, protected requests return 500)

A request without credentials gets 401 with a plain-text body and no `WWW-Authenticate` header, so browsers do not show their own password prompt. Wrong credentials also get 401. Page paths outside `/api` redirect to `/login?next=<page>` instead.

After 10 failed Basic Auth attempts within 15 minutes from one client address (IPv6 clients are counted per /64), every request from that client that carries Basic credentials gets 429 with `Retry-After: 900`, including the public `GET /api/info`. A correct password resets the count.

**Example Request:**
```bash
curl -u username:password https://logs.example.com/api/info
```

Or with explicit header:
```bash
curl -H "Authorization: Basic $(echo -n 'username:password' | base64)" \
  https://logs.example.com/api/info
```

**Session cookie (what the web UI uses):**

The browser sends the password once, to `POST /api/auth/session`, and gets back an `HttpOnly` session cookie named `session_id` that authenticates every later request. The browser does not keep the password, and page scripts cannot read the cookie. The cookie is marked `Secure` when the request arrives over HTTPS (directly, or through a reverse proxy that sets `X-Forwarded-Proto`), and `SameSite=lax` in all cases.

```bash
# Log in once and keep the cookie

curl -u username:password -c cookies.txt -X POST https://logs.example.com/api/auth/session

# Every later call needs only the cookie

curl -b cookies.txt https://logs.example.com/api/info
```

Sessions live in the application's memory, so restarting the container signs everyone out. One process holds at most `SESSION_MAX_ENTRIES` live sessions (default 50); when it is full, a new sign-in gets 503 with `Retry-After: 60`. `POST /api/auth/logout` ends the session and clears the cookie (`curl -b cookies.txt -X POST https://logs.example.com/api/auth/logout`). API clients can also send `Authorization: Basic` on every request instead of using a session.

#### OAuth2/OIDC Authentication

When `OAUTH2_ENABLED=true`, users sign in through the identity provider. The app finds the provider's endpoints through `.well-known/openid-configuration` (OIDC discovery), or uses endpoints you set yourself for providers without discovery.

**Configuration:** See [OAuth2 Configuration Guide](OAuth2_Configuration.md) for setup.

**Authentication Flow:**
1. User initiates login via `GET /api/auth/login`
2. User is redirected to OAuth2 provider
3. After authentication, provider redirects to `GET /api/auth/callback`
4. Application exchanges authorization code for tokens, proving the login with PKCE (S256)
5. Session is created and HTTP-only cookie is set
6. User is redirected to main application

**Session Management:**

- Sessions are stored server-side with signed session IDs

- HttpOnly prevents scripts from reading the session cookie; it does not prevent script injection

- Session expiration configurable via `SESSION_EXPIRY_HOURS` (default: 24 hours)

### Login Endpoint

#### GET /login

Serves the login page (HTML). This endpoint is always public. The page shows the Basic Auth form when `BASIC_AUTH_ENABLED=true`, the OAuth2 button when `OAUTH2_ENABLED=true`, and an "OR" separator when both are on.

**Query parameter:** `next`, the local page to open after sign-in. The app accepts only a path on this site; anything else, and any path under `/login`, `/api/` or `/static/`, becomes `/`.

When authentication is disabled, or the request already has a valid session, the endpoint redirects (302) to `next` instead of serving the page.

---

## Health & Info

### GET /health

Health check endpoint for monitoring and load balancers.

**Authentication:** Not required (public endpoint for Docker health checks)

**Response:** HTTP 200 when connected; HTTP 503 when the database check fails.

```json
{
  "status": "healthy",
  "database": "connected"
}
```

On HTTP 503, the values are `"unhealthy"` and `"disconnected"`. This public endpoint does not expose configuration details.

---

### GET /info

Read app branding and sign-in flags without authentication. When authentication is enabled, unauthenticated callers receive only `name`, `app_title`, `app_logo_url`, `auth_enabled`, `basic_auth_enabled` and `oauth2_enabled`.

Authenticated callers, or callers when authentication is disabled, also receive `version`, `mailcow_url`, `local_domains`, `fetch_interval`, `retention_days`, `timezone`, `blacklist_count` and `disabled_features`. The version comes from the running image.

`disabled_features` contains the configured feature IDs. This is configuration metadata, not a per-endpoint authorization policy.

---

### GET /rw-status

Check whether a read-write mailcow API key (`MAILCOW_API_KEY_RW`, from ENV or **Settings**) is configured. Every feature that writes to mailcow (Fail2ban, quarantine actions and others) depends on it.

**Response:**
```json
{
  "rw_configured": true
}
```

- `rw_configured`: Boolean. `true` if a read-write key is set, `false` otherwise. The key is not tested; use [`POST /api/settings/mailcow/rw-key/validate`](#post-apisettingsmailcowrw-keyvalidate) for that.

The web interface reads this once at startup to show or hide write controls.

---

## OAuth2 Authentication Endpoints

### GET /api/auth/provider-info

Get authentication provider information for frontend.

**Authentication:** Not required (public endpoint)

**Response:**
```json
{
  "oauth2_enabled": true,
  "basic_auth_enabled": true,
  "provider_name": "Authentik"
}
```

**Response Fields:**

- `oauth2_enabled`: Boolean - Whether OAuth2 is enabled

- `basic_auth_enabled`: Boolean - Whether Basic Auth is enabled

- `provider_name`: String - OAuth2 provider name (null if OAuth2 disabled)

---

### GET /api/auth/login

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `next` | string or null | Unset | Local page to open after sign-in. Same rules as `next` on [`GET /login`](#get-login); anything else becomes `/`. |

Start the OAuth2 sign-in. The endpoint redirects the browser to the provider.

**Authentication:** Not required (public endpoint)

**Response:** HTTP 307 redirect to the provider's authorization URL. The response also sets a short-lived `oauth_state_<state>` cookie (HttpOnly, 10 minutes) that ties the callback to this browser.

**Error Responses:**

- `400 Bad Request`: OAuth2 is not enabled

- `500 Internal Server Error`: OAuth2 is not configured correctly (missing client settings, or discovery failed)

**Notes:**

- The signed `state` value protects against CSRF and expires after 10 minutes

- Sends a PKCE code challenge (RFC 7636, `code_challenge_method=S256`); the callback sends the matching `code_verifier` with the token request

- The provider sends the user back to `/api/auth/callback`

---

### GET /api/auth/callback

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `code` | string | Unset | Authorization code from the provider |
| `state` | string | Unset | Signed state from `GET /api/auth/login` |
| `error` | string | Unset | Set by the provider when it declined the sign-in |

The provider sends the browser here after sign-in. The endpoint exchanges the code for tokens, reads the user information and creates a server-side session that expires after `SESSION_EXPIRY_HOURS`.

**Authentication:** Not required (public endpoint)

**Response:** HTTP 302 redirect to the local `next` page chosen at login, or `/`, with the HttpOnly session cookie set.

**Errors:** OAuth2 disabled returns 400. Every other failure redirects to `/login?error=<code>`:

| Code | Meaning |
| --- | --- |
| `invalid_state` | The state is missing, invalid, expired, already used, or does not match this browser's cookie. Checked first, so a provider error with a bad state also gives this code. |
| `oauth2_error` | The provider declined (`error` was set), or the token or user information request failed |
| `missing_code` | No `code` in the callback |
| `no_token` | The token response had no access token |
| `session_capacity` | The session store is full (see `SESSION_MAX_ENTRIES` above) |
| `server_error` | Any other error |

---

### POST /api/auth/logout

Sign out: deletes the server-side session (OAuth2 or Basic Auth) and clears the session cookie.

**Authentication:** Required while authentication is enabled (a valid session or Basic Auth credentials).

**Response:** HTTP 302 redirect to `/login` with the session cookie cleared.

The endpoint takes POST only, so another site cannot sign you out with a link or an image. `GET /api/auth/logout` returns `405 Method Not Allowed` with `Allow: POST`. A cross-site POST gets 403 from the [same-origin check](#403-forbidden).

---

### GET /api/auth/status

Read the current session or validated Basic Auth identity. This route is protected when authentication is enabled, so a request without valid credentials receives 401 rather than a public signed-out status.

The response has `authenticated`, `auth_type` and `user`. Browser sessions from either method return their stored user object. A Basic Auth session includes `username` and `auth_method: "basic"`; direct Basic Auth headers return `user: null`. With authentication disabled and no session, the response is:

`{ "authenticated": false, "auth_type": null, "user": null }`

---

### GET /api/auth/verify

Return `{ "verified": true }` after the authentication middleware accepts the request. With authentication enabled, use a valid session or Basic Auth credentials. The current login form creates a session through `POST /api/auth/session` instead of using this endpoint.

---

### POST /api/auth/session

Exchange valid Basic Auth credentials in the Authorization header for an HttpOnly `session_id` cookie. No JSON body is required. The response is `{ "authenticated": true, "auth_type": "basic" }`.

With authentication off, the endpoint returns 400; with only OAuth2 enabled, it returns 401. Invalid credentials return 401. A client locked out after failed attempts gets 429 (see [Basic Authentication](#basic-authentication)). A full session store returns 503 with `Retry-After: 60`.

---

## Job Status Tracking

### Job state

`GET /api/settings/info` includes job state, last-run timestamps and errors. State is process-local and resets at app restart. Disabled features and missing prerequisites are returned with the job metadata.

### Job Status Data Structure

The scheduler keeps one entry per job ID, each starting as `{"last_run": null, "status": "idle", "error": null}`. The IDs are `fetch_logs`, `complete_correlations`, `update_final_status`, `expire_correlations`, `correlate_dovecot`, `cleanup_logs`, `cleanup_dmarc_reports`, `check_app_version`, `dns_check`, `update_geoip`, `dmarc_imap_sync`, `mailbox_stats`, `alias_stats`, `blacklist_check`, `send_weekly_summary`, `sync_transports`, `fetch_raw_logs`, `cleanup_raw_logs`, `detect_suppressions`, `sync_suppressions`, `expire_suppressions`, `process_quarantine_rules`, `cleanup_deferred_queue`, `anomaly_detection`, `smtp_abuse`, `protection_rules`, `eas_devices` and `cleanup_eas_devices`. `sync_local_domains` is added on its first run. The raw log jobs keep their status in the raw log worker, which is what `GET /api/settings/info` reads for `fetch_raw_logs` and `cleanup_raw_logs`.

### Status Values

| Status | Meaning |
| --- | --- |
| `idle` | The job has not run yet |
| `running` | The job is running |
| `success` | The last run finished |
| `failed` | The last run hit an error |
| `disabled` | The job is off because its feature or a prerequisite is off |
| `skipped` | The job ran but had nothing to do because its setting is off (weekly summary) |
| `unknown` | No status is recorded, or the raw log worker status could not be read |

### Accessing Job Status

Read job status through `GET /api/settings/info` (the `background_jobs` field). The web interface shows it in **Status** > **Jobs**.

### Background Jobs List

Times of day follow the container's clock.

| Job Name | Interval | Description |
|----------|----------|-------------|
| **Fetch Logs** | Every `FETCH_INTERVAL` seconds (default 60) | Imports Postfix and Rspamd logs from the mailcow API, plus Netfilter logs while the Security feature is on. Runs the protection rules after each fetch. |
| **Run Correlation** | Every 30 seconds | Correlates new Postfix and Rspamd logs into messages. Has no status entry. |
| **Complete Correlations** | Every `CORRELATION_CHECK_INTERVAL` seconds (default 120) | Links Postfix logs to message correlations |
| **Update Final Status** | Every `CORRELATION_CHECK_INTERVAL` seconds (default 120) | Updates message delivery status for late-arriving logs |
| **Expire Correlations** | Every 60 seconds | Marks incomplete correlations as expired after `MAX_CORRELATION_AGE_MINUTES` (default 10) |
| **Correlate Dovecot** | Every 60 seconds | Adds the Dovecot delivery outcome to messages. Runs only while the `dovecot` raw log service is collected. |
| **Cleanup Logs** | Daily at 2 AM | Removes logs older than the retention period |
| **Cleanup DMARC Reports** | Daily at 2:15 AM | Removes DMARC and TLS reports older than `DMARC_RETENTION_DAYS`. DMARC feature only. |
| **Check App Version** | Every 6 hours, first run at startup | Checks GitHub for application updates |
| **DNS Check** | Every 6 hours, and 60 seconds after startup | Checks SPF, DKIM, DMARC, DNSSEC, TLSA, MTA-STS and TLS-RPT for all active domains. Domains feature only. |
| **Sync Local Domains** | Every 6 hours, first run at startup | Refreshes the active domain list from mailcow |
| **Update GeoIP** | Weekly (Sunday 3 AM), and 60 seconds after startup | Downloads the MaxMind GeoLite2 City and ASN databases when a file is missing or 7 or more days old. Runs only when the MaxMind Account ID and License Key are set. |
| **DMARC IMAP Sync** | Every `DMARC_IMAP_INTERVAL` seconds (default 3600), and 30 seconds after startup when `DMARC_IMAP_RUN_ON_STARTUP` is on | Imports DMARC and TLS reports from IMAP. Needs the DMARC feature and IMAP import on. |
| **Mailbox Stats** | Every 5 minutes, and 45 seconds after startup | Fetches mailbox statistics. Runs while Mailbox Stats or Rate Limits is on. |
| **Alias Stats** | Every 5 minutes, and 50 seconds after startup | Syncs alias data. Mailbox Stats feature only. |
| **ActiveSync Devices** | Every minute | Records ActiveSync devices from the SOGo log. Does nothing while Devices is off. |
| **Cleanup ActiveSync Devices** | Daily at 3:30 AM | Removes devices not seen within `EAS_DEVICES_RETENTION_DAYS` (default 90; 0 keeps them) |
| **Blacklist Check** | Daily at 5 AM, and 15 seconds after startup | Checks monitored hosts against DNS blacklists. Blacklist feature only. |
| **Sync Transports** | Every 6 hours, and 30 seconds after startup | Syncs transports and relayhosts from mailcow for blacklist monitoring. Blacklist feature only. |
| **Weekly Summary** | Monday at 9 AM | Sends the weekly summary email when it is turned on |
| **Anomaly Detection** | Every `ANOMALY_CHECK_INTERVAL` minutes (default 15) | Detects outbound volume spikes and sign-in failure bursts. Runs while anomaly detection is on. |
| **SMTP Abuse** | Every minute | Disables SMTP for mailboxes over the sending threshold. Needs SMTP abuse protection on and a read-write API key. |
| **Protection Rules** | After each log fetch | Evaluates the protection rules on new Netfilter lines and writes bans when a read-write API key is set. Security feature only. |
| **Fetch Raw Logs** | Every `RAW_LOGS_FETCH_INTERVAL` seconds (default 30) | Collects raw service logs for the Logs page and the pages that read them |
| **Cleanup Raw Logs** | Daily at 3 AM | Removes raw logs older than `RAW_LOGS_RETENTION_DAYS` (default 2) |
| **Detect Suppressions** | Every 5 minutes | Suppresses recipients of bounced messages found in Postfix logs, and of deferred messages too while deferred queue cleanup is off. Runs while the Spam Filter feature, suppressions and automatic detection are on. |
| **Cleanup Deferred Queue** | Every 5 minutes | Deletes deferred messages stuck longer than `QUEUE_CLEANUP_THRESHOLD_MINUTES` (default 60) and suppresses their recipients. Needs suppressions, queue cleanup and a read-write API key. |
| **Sync Suppressions** | Every 10 minutes | Syncs active suppressions to the Rspamd recipient denylist. Needs the Rspamd password and Rspamd sync turned on. |
| **Expire Suppressions** | Every hour | Deactivates expired suppression entries |
| **Process Quarantine Rules** | Every `QUARANTINE_RULES_INTERVAL` minutes (default 5) | Applies the quarantine auto-rules (release or delete matching messages). Needs the Quarantine feature and a read-write API key. |

## Domains

### GET /api/domains/all

Get list of all domains with statistics and cached DNS validation results.

**Response:**
```json
{
  "total": 10,
  "active": 8,
  "last_dns_check": "2026-01-08T01:34:08Z",
  "domains": [
    {
      "domain_name": "example.com",
      "active": true,
      "mboxes_in_domain": 5,
      "mboxes_left": 995,
      "max_num_mboxes_for_domain": 1000,
      "aliases_in_domain": 3,
      "aliases_left": 397,
      "max_num_aliases_for_domain": 400,
      "created": "2025-01-01T00:00:00Z",
      "bytes_total": 1572864,
      "msgs_total": 1234,
      "quota_used_in_domain": "1572864",
      "max_quota_for_domain": 10240000,
      "backupmx": false,
      "relay_all_recipients": false,
      "relay_unknown_only": false,
      "dns_checks": {
        "spf": {
          "status": "success",
          "message": "SPF configured correctly with strict -all policy. Server IP authorized via ip4:192.0.2.10",
          "record": "v=spf1 mx include:_spf.example.net -all",
          "has_strict_all": true,
          "includes_mx": true,
          "includes": ["_spf.example.net"],
          "warnings": [],
          "dns_lookups": 3,
          "checked_ips": [
            {"ip": "192.0.2.10", "source": "auto-detected", "authorized": true}
          ]
        },
        "dkim": {
          "status": "success",
          "message": "DKIM configured correctly",
          "selector": "dkim",
          "dkim_domain": "dkim._domainkey.example.com",
          "expected_record": "v=DKIM1;k=rsa;p=MIIBIjANBg...",
          "actual_record": "v=DKIM1;k=rsa;p=MIIBIjANBg...",
          "match": true,
          "warnings": [],
          "info": [],
          "parameters": {
            "v": "DKIM1",
            "k": "rsa",
            "p": "MIIBIjANBg..."
          }
        },
        "dmarc": {
          "status": "success",
          "message": "DMARC configured with strict policy",
          "record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
          "policy": "reject",
          "subdomain_policy": null,
          "pct": "100",
          "is_strong": true,
          "warnings": []
        },
        "checked_at": "2026-01-08T01:34:08Z"
      },
      "alias_domains": [
        {
          "domain_name": "alias.example.com",
          "dns_checks": {
            "spf": {"status": "success", "message": "..."},
            "dkim": {"status": "success", "message": "..."},
            "dmarc": {"status": "warning", "message": "..."},
            "checked_at": "2026-01-08T01:34:08Z"
          }
        }
      ]
    }
  ]
}
```

**Response Fields:**

- `total`: Total number of domains

- `active`: Number of active domains

- `last_dns_check`: Timestamp of last global DNS check (only updated by scheduled or manual full checks)

- `domains`: Array of domain objects

**Domain Object Fields:**

- `domain_name`: Domain name

- `active`: Boolean indicating if domain is active

- `mboxes_in_domain`: Number of mailboxes

- `mboxes_left`: Available mailbox slots

- `max_num_mboxes_for_domain`: Maximum mailboxes allowed

- `aliases_in_domain`: Number of aliases

- `aliases_left`: Available alias slots

- `max_num_aliases_for_domain`: Maximum aliases allowed

- `created`: Domain creation timestamp (UTC)

- `bytes_total`: Total storage used (bytes)

- `msgs_total`: Total messages

- `quota_used_in_domain`: Storage quota used (string format)

- `max_quota_for_domain`: Maximum storage quota

- `backupmx`: Boolean - true if domain is backup MX

- `relay_all_recipients`: Boolean - true if relaying all recipients

- `relay_unknown_only`: Boolean - true if relaying only unknown recipients

- `dns_checks`: DNS validation results (cached from database)

- `alias_domains`: Array of the domain's mailcow alias domains, each with its own `domain_name` and cached `dns_checks`. Empty array when the domain has no alias domains

**DNS Check Status Values:**

- `success`: Check passed with no issues

- `warning`: Check passed but with recommendations for improvement

- `error`: Check failed or record not found

- `unknown`: Check not yet performed

**SPF Status Indicators:**
- **DNS Lookup Limit**: Error if >10 lookups (RFC 7208)
- **Source IP Authorization**: Error if any validated source IP is not authorized by the SPF record (see `checked_ips`)
- **Multiple Records**: Error (only one SPF record allowed per domain)
- **Invalid Syntax**: Error (must start with `v=spf1 ` with space)
- **Invalid Mechanisms**: Error (only valid mechanisms allowed)

- `-all`: Strict policy (status: success)

- `~all`: Soft fail (status: success, informational)

- `?all`: Neutral (status: warning); gives minimal protection

- `+all`: Pass all (status: error); gives no protection

- Missing `all`: No policy defined (status: error)

**New SPF Fields:**

- `dns_lookups`: Integer count of DNS lookups (0-999)

- `warnings`: Array of warning messages

- `checked_ips`: Array of every source IP validated against the record. Each entry has:
  - `ip`: The IP address that was checked
  - `source`: Where the IP came from: one of `auto-detected` (WAN IP), `transport`, `relayhost`, `configured` (manual entry), `dmarc-history`
  - `authorized`: Boolean per-IP verdict
  - The set of validated sources is controlled by the `DOMAIN_SPF_SOURCE_*` settings; the overall check fails if any IP is not authorized. Cached results written before this field existed lack the key

**DKIM Validation:**

- Fetches expected DKIM record from mailcow API

- Queries DNS for actual DKIM record

- Compares expected vs actual records

- `match`: Boolean indicating if records match
- **Parameter Validation**: Checks for security issues
  - `t=y` (Testing mode): Critical error
  - `t=s` (Strict subdomain): Informational only
  - `h=sha1` (Weak hash): Warning
  - `p=` (Empty key): Error (key revoked)
  - Unknown key types: Warning

**New DKIM Fields:**

- `warnings`: Array of security warnings

- `info`: Array of informational messages (plain text)

- `parameters`: Dictionary of parsed DKIM tags (v, k, t, h, p, etc.)

**DMARC Policy Types:**

- `reject`: Strict policy (status: success)

- `quarantine`: Moderate policy (status: warning); consider moving to reject

- `none`: Requests monitoring without DMARC policy enforcement (status: warning)

**Notes:**

- DNS checks are cached in database for performance

- `last_dns_check` only updates from global/scheduled checks, not individual domain checks

- `checked_at` (per domain) updates whenever that specific domain is checked

- All timestamps include UTC timezone indicator ('Z' suffix)

---

### POST /api/domains/check-all-dns

Manually trigger DNS validation for all active domains.

**Description:** Performs DNS checks (SPF, DKIM, DMARC) for all active domains and updates the global `last_dns_check` timestamp. Results are cached in database.

**Authentication:** Required when sign-in is enabled.

**Response:**
```json
{
  "status": "success",
  "message": "Checked 8 domains",
  "domains_checked": 8,
  "errors": []
}
```

**Response Fields:**

- `status`: `success` (all domains checked) or `partial` (some domains failed)

- `message`: Summary message

- `domains_checked`: Number of domains successfully checked

- `errors`: Array of error messages for failed domains (empty if all successful)

**Error Response (partial success):**
```json
{
  "status": "partial",
  "message": "Checked 7 domains",
  "domains_checked": 7,
  "errors": [
    "example.com: DNS timeout"
  ]
}
```

**Notes:**

- Checks active domains and their mailcow alias domains

- Updates `is_full_check=true` flag in database

- Updates global `last_dns_check` timestamp

- Frontend shows progress with toast notifications

- Waits for the domain checks to finish, then returns their counts and errors.

---

### POST /api/domains/{domain}/check-dns

Manually trigger DNS validation for a specific domain.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | Domain name to check |

**Authentication:** Required when sign-in is enabled.

**Example Request:**
```
POST /api/domains/example.com/check-dns
```

**Response:**
```json
{
  "status": "success",
  "message": "DNS checked for example.com",
  "data": {
    "domain": "example.com",
    "spf": {
      "status": "success",
      "message": "SPF configured correctly with strict -all policy. Server IP authorized via ip4:192.0.2.10",
      "record": "v=spf1 mx include:_spf.example.net -all",
      "has_strict_all": true,
      "includes_mx": true,
      "includes": ["_spf.example.net"],
      "warnings": [],
      "dns_lookups": 3,
      "checked_ips": [
        {"ip": "192.0.2.10", "source": "auto-detected", "authorized": true}
      ]
    },
    "dkim": {
      "status": "success",
      "message": "DKIM configured correctly",
      "selector": "dkim",
      "dkim_domain": "dkim._domainkey.example.com",
      "expected_record": "v=DKIM1;k=rsa;p=MIIBIjANBg...",
      "actual_record": "v=DKIM1;k=rsa;p=MIIBIjANBg...",
      "match": true,
      "warnings": [],
      "info": [],
      "parameters": {
        "v": "DKIM1",
        "k": "rsa",
        "p": "MIIBIjANBg..."
      }
    },
    "dmarc": {
      "status": "success",
      "message": "DMARC configured with strict policy",
      "record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
      "policy": "reject",
      "is_strong": true,
      "warnings": []
    },
    "checked_at": "2026-01-08T01:45:23Z"
  }
}
```

**Notes:**

- Only checks the specified domain

- Updates `is_full_check=false` flag in database

- Does NOT update global `last_dns_check` timestamp


---

DNS record checks are described in [Domains](HelpDocs/Domains.md).

### GET /api/domains/{domain}/dns-check

Run DNS checks for one valid domain and return the result object directly. This route calls the DNS checker on every request; it does not use the stored-check cache or save a new check. Invalid domain names return 400.

The result includes `domain`, `checked_at`, `spf`, `dkim`, `dmarc`, `dnssec`, `tlsa`, `mta_sts`, `tls_rpt`. The POST force-check endpoint also saves the result and wraps it in `data`.

---

## Mailbox Statistics

### GET /api/mailbox-stats/summary

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `date_range` | string | `30days` | `today`, `7days`, `30days`, `90days` or `custom` |
| `start_date` | string or null | Unset | Start date (`YYYY-MM-DD`); required when `date_range` is `custom` |
| `end_date` | string or null | Unset | End date (`YYYY-MM-DD`); required when `date_range` is `custom` |

Read server-wide traffic for the selected period. Mailbox search and domain filters on the UI list do not change this endpoint's totals.

The successful response contains `total_sent`, `total_received`, `total_messages`, `sent_failed`, `failure_rate`, `date_range`, `start_date`, `end_date` and `last_update`. It does not return mailbox inventory counts on success.

`sent_failed` counts bounced and rejected outgoing messages. Deferred messages are counted separately, and a later successful delivery leg takes precedence for message counting. Values come from collected correlations, so retention limits the history.

---

### GET /api/mailbox-stats/all

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `domain` | string or null | Unset | Only mailboxes of this domain. An alias domain shows the mailboxes of its target domain. |
| `active_only` | boolean | `true` | Only active mailboxes |
| `hide_zero` | boolean | `false` | Leave out mailboxes with no activity in the period |
| `search` | string or null | Unset | Substring match on the address, the name, or any of the mailbox's aliases |
| `date_range` | string | `30days` | `today`, `7days`, `30days`, `90days` or `custom` |
| `start_date` | string or null | Unset | Start date (`YYYY-MM-DD`); required when `date_range` is `custom` |
| `end_date` | string or null | Unset | End date (`YYYY-MM-DD`); required when `date_range` is `custom` |
| `sort_by` | string | `sent_total` | `sent_total`, `received_total`, `failure_rate`, `username` or `quota_used`; any other value sorts by total messages. Sent and received include aliases. |
| `sort_order` | string | `desc` | `desc`; any other value sorts ascending |
| `page` | integer | `1` | Page number, at least 1 |
| `page_size` | integer | `50` | Items per page, 10 to 100 |

Get all mailbox statistics with message counts and aliases (paginated).

**Example Request:**
```
GET /api/mailbox-stats/all?date_range=30days&active_only=true&hide_zero=true&sort_by=sent_total&sort_order=desc&page=1
```

**Response:**
```json
{
  "total": 25,
  "page": 1,
  "page_size": 50,
  "total_pages": 1,
  "date_range": "30days",
  "start_date": "2026-01-16T00:00:00Z",
  "end_date": "2026-02-16T00:00:00Z",
  "mailboxes": [
    {
      "id": 1,
      "username": "user@example.com",
      "domain": "example.com",
      "name": "John Doe",
      "active": true,
      "quota": 1073741824,
      "quota_formatted": "1.0 GB",
      "quota_used": 536870912,
      "quota_used_formatted": "512 MB",
      "percent_in_use": 50.0,
      "messages_in_mailbox": 1234,
      "last_imap_login": "2026-01-15T10:30:00Z",
      "last_pop3_login": null,
      "last_smtp_login": "2026-01-16T08:45:00Z",
      "rl_value": 100,
      "rl_frame": "m",
      "attributes": {
        "imap_access": "1",
        "pop3_access": "0",
        "smtp_access": "1",
        "sieve_access": "1",
        "sogo_access": "1",
        "tls_enforce_in": "0",
        "tls_enforce_out": "0"
      },
      "mailbox_counts": {
        "sent_total": 150,
        "sent_delivered": 145,
        "sent_bounced": 3,
        "sent_deferred": 2,
        "sent_rejected": 0,
        "sent_failed": 3,
        "received_total": 320,
        "failure_rate": 2.0
      },
      "aliases": [
        {
          "alias_address": "info@example.com",
          "active": true,
          "is_catch_all": false,
          "sent_total": 50,
          "sent_delivered": 48,
          "sent_bounced": 2,
          "sent_deferred": 0,
          "sent_rejected": 0,
          "sent_failed": 2,
          "received_total": 100,
          "failure_rate": 4.0
        },
        {
          "alias_address": "user@alias.example.com",
          "active": true,
          "is_catch_all": false,
          "is_domain_alias": true,
          "sent_total": 12,
          "sent_delivered": 12,
          "sent_bounced": 0,
          "sent_deferred": 0,
          "sent_rejected": 0,
          "sent_failed": 0,
          "received_total": 4,
          "failure_rate": 0.0
        }
      ],
      "alias_count": 2,
      "combined_sent": 212,
      "combined_received": 424,
      "combined_total": 636,
      "combined_failed": 5,
      "combined_failure_rate": 2.4,
      "created": "2025-01-01T00:00:00Z",
      "modified": "2026-01-15T12:00:00Z"
    }
  ]
}
```

**Response Fields:**

| Field | Description |
|-------|-------------|
| `username` | Email address of the mailbox |
| `name` | Display name |
| `active` | Whether mailbox is active in mailcow |
| `quota` / `quota_used` | Quota in bytes |
| `percent_in_use` | Quota usage percentage |
| `messages_in_mailbox` | Number of messages stored |
| `last_*_login` | Last login timestamps (null if never) |
| `rl_value` / `rl_frame` | Rate limiting (e.g., 100/m = 100 per minute) |
| `attributes` | Access permissions from mailcow |
| `mailbox_counts` | Message statistics for mailbox only |
| `aliases` | Array of alias statistics. Addresses on a mailcow alias domain (user@alias.example.com for user@example.com) appear here as rows with `is_domain_alias: true`; they are listed only when they have traffic in the selected range |
| `combined_*` | Combined totals (mailbox + all aliases, including alias-domain addresses) |
| `created` / `modified` | Mailbox creation and last update timestamps |

---

The response also includes `activity_unit` and `activity_buckets`; each mailbox has its corresponding `activity` series and combined delivery/status counts. Rows count a mailbox together with its aliases, while `mailbox_counts` covers its own address. Failed means bounced plus rejected, excluding deferred.

### GET /api/mailbox-stats/domains

Get list of domains with mailbox counts for filter dropdown.

**Response:**
```json
{
  "domains": [
    {
      "domain": "example.com",
      "mailbox_count": 15
    },
    {
      "domain": "example.org",
      "mailbox_count": 10
    },
    {
      "domain": "alias.example.com",
      "mailbox_count": 15,
      "alias_of": "example.com"
    }
  ]
}
```

**Notes:**

- mailcow alias domains are listed too, marked with `alias_of` (their target domain) and showing the target's mailbox count. Selecting one filters to the target domain's mailboxes

### Caching

The Mailbox Statistics API uses in-memory caching to improve performance:

| Setting | Value |
|---------|-------|
| **Cache TTL** | 5 minutes (300 seconds) |
| **Cache Scope** | Per unique query parameter combination |
| **Cached Parameters** | domain, active_only, hide_zero, search, date_range, start_date, end_date, sort_by, sort_order, page, page_size |

**Cache Behavior:**

- First request with specific parameters fetches from database and caches result

- Subsequent requests with identical parameters return cached data

- Cache automatically expires after 5 minutes

- Changing any parameter results in a cache miss (new database query)

## Devices

ActiveSync devices recorded from SOGo's access log. The `eas_devices` job reads the newest SOGo lines through the mailcow API every minute and keeps one row per user and device ID: the newest request, and when the device was first and last seen. Devices not seen for `EAS_DEVICES_RETENTION_DAYS` (default 90, `0` = forever) are removed daily.

### GET /api/devices

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `page` | integer | `1` | Page number, at least 1 |
| `per_page` | integer | `50` | 1 to 200 |
| `search` | string or null | Unset | Case-insensitive substring of the user, device ID, device type or last IP |
| `device_type` | string or null | Unset | Exact device type (one of `device_types` in the response) |
| `seen` | string | `all` | `all`, `recent` (seen in the last 24 hours), `new` (first seen in the last 7 days) or `stale` (not seen for 30 days) |
| `sort_by` | string | `last_seen` | `username`, `device_type`, `last_ip`, `last_command`, `first_seen` or `last_seen` |
| `sort_dir` | string | `desc` | `asc` or `desc` |

List the recorded devices, filtered, sorted and paged.

**Response:**
```json
{
  "items": [
    {
      "id": 12,
      "username": "jane@example.com",
      "device_id": "ApplF2C8A1D94B7E",
      "device_type": "iPhone",
      "last_ip": "203.0.113.7",
      "country_code": "DE",
      "country_name": "Germany",
      "city": "Berlin",
      "asn": "AS64500",
      "asn_org": "Example Mobile",
      "client": "Apple Mail",
      "model": null,
      "last_command": "Ping",
      "last_status": 200,
      "first_seen": "2026-09-02T08:14:03Z",
      "last_seen": "2026-10-05T14:02:51Z"
    }
  ],
  "total": 1,
  "page": 1,
  "per_page": 50,
  "total_pages": 1,
  "summary": {"devices": 16, "users": 11, "recent": 14, "new": 2, "stale": 1},
  "device_types": ["iPad", "iPhone", "Outlook"],
  "thresholds": {"recent_hours": 24, "new_days": 7, "stale_days": 30},
  "retention_days": 90,
  "geoip": true,
  "last_run": "2026-10-05T14:03:00Z",
  "last_status": "success"
}
```

**Notes:**

- `summary` counts every device, not only the filtered page

- `last_ip` is `null` when SOGo logged something other than an IP address

- The location fields come from the MaxMind GeoIP databases, looked up when the list is read; they are `null` when `geoip` is `false` or the address is not in the database

- `client` is the mail app recognized from the device ID and type (`Apple Mail`, `Samsung Email`, `Outlook`, `Windows Mail`, `Gmail`), `null` when not recognized; `model` is a Samsung model code such as `SM-S918B`, else `null`

- `last_status` is the HTTP status SOGo answered; `401` means the device's password was refused

- A connected phone's `last_seen` can be up to an hour old: SOGo logs a `Ping` when it ends, and mailcow allows a Ping of up to 59 minutes

---

### GET /api/mailbox-stats/refresh

Read the last metadata synchronization timestamps. This GET does not request a refresh.

`{ "last_mailbox_update": "2026-10-16T09:00:00Z", "last_alias_update": "2026-10-16T09:00:00Z" }`

Either timestamp can be null. A database failure returns an `error` field.

---

## Rate Limits

mailcow rate-limits senders through rspamd, which counts every send against a Redis key and writes a line to the `ratelimited` log when a sender runs out. These endpoints show who is hitting a limit, reset a stuck counter, and change the limits themselves. The write endpoints need a read-write API key (`MAILCOW_API_KEY_RW`) and return 503 without one. Limit values are whole messages per time frame; `0` removes the limit. Time frames are `s` (second), `m` (minute), `h` (hour) and `d` (day).

These endpoints back **Mailbox Stats** > **Rate Limits**. Turning off `rate-limits` hides the view and stops collecting its required raw service unless another enabled surface needs it. Feature switches are not an API authorization boundary.

### GET /api/rate-limits/events

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `hours` | integer | `168` | Chart window in hours, 1 to 8760 |

Read grouped sender history and a windowed activity chart from collected `ratelimited` logs. The endpoint reads the newest 5,000 log rows and does not call mailcow.

The response contains `hours`, `total_events`, `window_senders`, `by_sender`, `events`, `bucket` and `by_bucket`. The window applies to chart totals and buckets only. `by_sender` covers all sender history in the scanned rows, sorted by hit count.

Each sender has `user`, `events`, `last_seen`, `last_rl_hash`, `current_limit`, `recent` and optional `last_reset`. `recent` contains up to 5 events; the flat `events` feed contains up to 50. Event fields are `time`, `rcpt`, `subject`, `qid` and `rl_hash`; the flat feed also includes `user`.

`current_limit` is `{value, frame}` from the locally synced mailbox, or null. Buckets use `{bucket, count}`, hourly for windows of 24 hours or less and daily for longer windows.

---

### GET /api/rate-limits/limits

Get the configured rate limits for every locally synced mailbox and every active local domain.

**Response:**
```json
{
  "rw_key_configured": true,
  "mailboxes": [
    {
      "username": "sales@example.com",
      "domain": "example.com",
      "rl_value": 100,
      "rl_frame": "m",
      "active": true
    }
  ],
  "domains": [
    {
      "domain": "example.com",
      "rl_value": 500,
      "rl_frame": "h"
    }
  ],
  "domains_error": null
}
```

**Response Fields:**

- `rw_key_configured`: Whether a read-write API key is set; the write endpoints need it

- `mailboxes`: Every synced mailbox, read from the local sync; `rl_value` and `rl_frame` are null when no limit is set.

- `domains`: Every local domain with the limit fetched from mailcow; `rl_value` is `null` when the domain has no limit. Cached in-process for 300 seconds

- `domains_error`: The mailcow error text when the domain limits could not be read, `null` otherwise

---

### POST /api/rate-limits/mailbox

**JSON fields:**

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `mailbox` | string | Required | Mailbox address; must be a synced mailbox |
| `value` | integer | Required | Messages per frame, 0 or more; `0` removes the limit |
| `frame` | string | Required | `s`, `m`, `h` or `d` |

Set the rate limit of one mailbox.

**Request Body:**
```json
{
  "mailbox": "sales@example.com",
  "value": 100,
  "frame": "m"
}
```

**Response:**
```json
{
  "mailbox": "sales@example.com",
  "rl_value": 100,
  "rl_frame": "m",
  "mailcow_response": [
    {
      "type": "success",
      "msg": "Rate limit has been modified"
    }
  ]
}
```

**Notes:**

- The local mailbox row is updated on success, so the page shows the new limit immediately instead of waiting for the next mailbox sync

**Error Responses:**

- `400 Bad Request`: Unknown mailbox, negative value, or invalid frame

- `502 Bad Gateway`: mailcow did not apply the change

- `503 Service Unavailable`: No read-write API key configured

---

### POST /api/rate-limits/domain

**JSON fields:**

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `domain` | string | Required | A local domain |
| `value` | integer | Required | Messages per frame, 0 or more; `0` removes the limit |
| `frame` | string | Required | `s`, `m`, `h` or `d` |

Set the rate limit of one domain.

**Request Body:**
```json
{
  "domain": "example.com",
  "value": 500,
  "frame": "h"
}
```

**Response:**
```json
{
  "domain": "example.com",
  "rl_value": 500,
  "rl_frame": "h",
  "mailcow_response": [
    {
      "type": "success",
      "msg": "Rate limit has been modified"
    }
  ]
}
```

**Notes:**

- The domain is validated against the local domain list

- A successful change busts the cached domain limits, so the next `GET /api/rate-limits/limits` reads mailcow again

**Error Responses:**

- `400 Bad Request`: Unknown domain, negative value, or invalid frame

- `502 Bad Gateway`: mailcow did not apply the change

- `503 Service Unavailable`: No read-write API key configured

---

### POST /api/rate-limits/reset

**JSON fields:**

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `rl_hash` | string | Required | The counter's hash from the `ratelimited` log: `RL` followed by letters and digits |
| `user` | string or null | Unset | Sender to record the reset against (shown as `last_reset` in the events) |

Reset an active counter so a blocked sender can send again immediately. The configured limit is not changed.

**Request Body:**
```json
{
  "rl_hash": "RLwhscgno1zwitb6nif6i83msr"
}
```

**Response:**
```json
{
  "rl_hash": "RLwhscgno1zwitb6nif6i83msr",
  "reset": true,
  "mailcow_response": null
}
```

mailcow usually answers this call with an empty body, so `mailcow_response` is often `null`.

**Error Responses:**

- `400 Bad Request`: The value is not a rate limit hash (it must match `^RL[A-Za-z0-9]+$`)

- `502 Bad Gateway`: mailcow did not reset the counter

- `503 Service Unavailable`: No read-write API key configured

---

### GET /api/rate-limits/sender-events

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `user` | string | `` | The sender address to read the history of |

Read one sender's full collected refused-message history. A non-empty `user` is required by the handler; otherwise it returns 400.

The response contains normalized `user`, true database `total` and newest-first `events`, capped at 2,000 rows. Event fields are `time`, `rcpt`, `subject`, `qid` and `rl_hash`. The response is independent of the activity-chart window.

---

### POST /api/rate-limits/bulk

**JSON fields:**

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `mailboxes` | array of strings | `[]` | Mailbox addresses |
| `domains` | array of strings | `[]` | Local domains |
| `value` | integer | Required | Messages per frame, 0 or more; `0` removes the limits |
| `frame` | string | Required | `s`, `m`, `h` or `d` |

Set one limit on many mailboxes and domains at once (**Apply to filtered** on the page). Needs a read-write API key. More than 1,000 items in total, or none, returns 400.

Example body: `{ "mailboxes": ["alice@example.com"], "domains": ["example.com"], "value": 100, "frame": "h" }`.

Names the server does not know are skipped, not rejected. All mailboxes go to mailcow in one call, then all domains in a second. Response fields are `mailboxes_updated`, `domains_updated`, `skipped`, `value` and `frame`. If the domain call fails after the mailbox call succeeded, the mailbox change stays in place.

---

## Messages (Unified View)

### GET /messages

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `page` | integer | `1` | Page number, at least 1 |
| `limit` | integer | `50` | Items per page, 1 to 500 |
| `search` | string or null | Unset | Case-insensitive substring of sender, recipient, subject, Message-ID, queue ID, or the Rspamd client IP or user |
| `sender` | string or null | Unset | Substring of the sender |
| `recipient` | string or null | Unset | Substring of the recipient |
| `direction` | string or null | Unset | Exact direction: `inbound`, `outbound` or `internal` |
| `status` | string or null | Unset | Exact final status, such as `delivered`, `deferred`, `bounced`, `rejected` or `discarded`. `spam` also matches messages Rspamd marked as spam. |
| `user` | string or null | Unset | Substring of the authenticated sender (Rspamd user) |
| `ip` | string or null | Unset | Substring of the source IP (Rspamd) |
| `start_date` | datetime or null | Unset | Earliest `first_seen` (ISO 8601) |
| `end_date` | datetime or null | Unset | Latest `first_seen` (ISO 8601) |

Get unified messages view combining Postfix and Rspamd data.

**Example Request:**
```
GET /api/messages?page=1&limit=50&direction=outbound&sender=user@example.com
```

**Response:**
```json
{
  "total": 1234,
  "page": 1,
  "limit": 50,
  "pages": 25,
  "data": [
    {
      "correlation_key": "abc123def456...",
      "message_id": "<unique-id@example.com>",
      "queue_id": "ABC123DEF",
      "sender": "user@example.com",
      "recipient": "recipient@example.net",
      "subject": "Hello World",
      "direction": "outbound",
      "final_status": "delivered",
      "is_complete": true,
      "first_seen": "2025-12-25T10:30:00Z",
      "last_seen": "2025-12-25T10:30:05Z",
      "dovecot_status": "stored",
      "dovecot_mailbox": "INBOX",
      "deliveries": 1,
      "spam_score": 0.5,
      "is_spam": false,
      "user": "user@example.com",
      "ip": "192.0.2.100"
    }
  ]
}
```

**One row per message:** a message that was delivered more than once (a forward, a BCC copy, a quarantine release) has one correlation per delivery leg, but the list returns a single row for it. Rows are grouped by Message-ID; a correlation without a Message-ID is grouped by its own `correlation_key` and is therefore never merged with another one. The filters apply to the legs first, and the earliest matching leg represents the message, so a search always answers with the leg that matched it. `deliveries` is the total number of legs that message has in the database, including legs the filters did not match, and is `1` for an ordinary message. `total` and `pages` count messages, not legs. The full list of legs, in order, is available as `related_deliveries` in `GET /message/{correlation_key}/details`.

**Dovecot delivery fields:** `dovecot_status` is the outcome of the final LMTP hop as reported by Dovecot: one of `stored`, `discarded`, `rejected`, `forwarded`, `failed`, or `null` when no matching Dovecot information is available, such as mail delivered outside this server. `dovecot_mailbox` names the folder the message was filed into (e.g. `INBOX`, `Junk`). A message dropped by a Sieve `discard` rule gets `final_status` `discarded` instead of a false `delivered`.

---

### GET /message/{correlation_key}/details

Get complete message details with all related logs.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `correlation_key` | string | The correlation key (SHA256 hash) |

**Response:**
```json
{
  "correlation_key": "abc123def456...",
  "message_id": "<unique-id@example.com>",
  "queue_id": "ABC123DEF",
  "sender": "user@example.com",
  "recipient": "recipient@example.net",
  "recipients": [
    "recipient@example.net",
    "cc@example.net"
  ],
  "recipient_count": 2,
  "subject": "Hello World",
  "direction": "outbound",
  "final_status": "delivered",
  "is_complete": true,
  "first_seen": "2025-12-25T10:30:00Z",
  "last_seen": "2025-12-25T10:30:05Z",
  "related_deliveries": [
    {
      "correlation_key": "789abc012def...",
      "sender": "recipient@example.net",
      "recipient": "forward-target@example.org",
      "direction": "outbound",
      "final_status": "rejected",
      "first_seen": "2025-12-25T10:30:07Z",
      "queue_id": "5D9C86E1234",
      "dovecot_status": null,
      "dovecot_mailbox": null
    }
  ],
  "rspamd": {
    "time": "2025-12-25T10:30:00Z",
    "score": 0.5,
    "required_score": 15,
    "action": "no action",
    "symbols": {
      "MAILCOW_AUTH": {
        "score": -20,
        "description": "mailcow authenticated"
      },
      "RCVD_COUNT_ZERO": {
        "score": 0,
        "options": [
          "0"
        ]
      }
    },
    "is_spam": false,
    "direction": "outbound",
    "ip": "192.0.2.100",
    "user": "user@example.com",
    "has_auth": true,
    "size": 1024
  },
  "dovecot": {
    "status": "stored",
    "mailbox": "Junk",
    "detail": null,
    "logs": [
      {
        "time": "2025-12-25T10:30:06Z",
        "priority": "info",
        "message": "lmtp(recipient@example.net)<123><AbCdEf>: sieve: msgid=<unique-id@example.com>: stored mail into mailbox 'Junk'",
        "verdict": "stored",
        "recipient": "recipient@example.net",
        "mailbox": "Junk"
      }
    ]
  },
  "postfix": [
    {
      "time": "2025-12-25T10:30:00Z",
      "program": "postfix/smtpd",
      "priority": "info",
      "message": "ABC123DEF: client=...",
      "status": null,
      "relay": null,
      "delay": null,
      "dsn": null
    },
    {
      "time": "2025-12-25T10:30:05Z",
      "program": "postfix/smtp",
      "priority": "info",
      "message": "ABC123DEF: to=<recipient@example.net>, relay=mx.example.org...",
      "status": "sent",
      "relay": "mx.example.org[192.0.2.26]:25",
      "delay": 1.5,
      "dsn": "2.0.0"
    }
  ],
  "postfix_by_recipient": {
    "recipient@example.net": [
      {
        "time": "2025-12-25T10:30:05Z",
        "program": "postfix/smtp",
        "priority": "info",
        "message": "ABC123DEF: to=<recipient@example.net>, relay=mx.example.org...",
        "status": "sent",
        "relay": "mx.example.org[192.0.2.26]:25",
        "delay": 1.5,
        "dsn": "2.0.0"
      }
    ],
    "_system": [
      {
        "time": "2025-12-25T10:30:00Z",
        "program": "postfix/smtpd",
        "priority": "info",
        "message": "ABC123DEF: client=...",
        "status": null,
        "relay": null,
        "delay": null,
        "dsn": null
      }
    ]
  },
  "netfilter": []
}
```

**`related_deliveries`:** a Message-ID can map to several correlations, one per delivery leg. A forward, a Sieve redirect or any other re-submission delivers the same message a second time through its own Postfix queue chain, with its own sender, recipient, direction and status, and its own `correlation_key`. `GET /messages` shows all of them as one row, so this list is where the individual legs are read. It holds the other legs of the same Message-ID, ordered by `first_seen`, and is empty for the vast majority of messages. The first leg of a message keeps the historical `correlation_key` (SHA256 of `msgid:<message-id>`), so links created before this change keep resolving; an additional leg is keyed by SHA256 of `msgid:<message-id>:queue:<queue-id>`.

**`dovecot` object:** the mailbox-delivery outcome reported by Dovecot for the final LMTP hop. `status` is one of `stored`, `discarded`, `rejected`, `forwarded`, `failed`; `mailbox` is the target folder; `detail` carries the reject reason, forward target or storage error; `logs` lists the matching raw Dovecot lines (available while raw log retention keeps them). The whole object is `null` when no Dovecot information exists for the message.

---

### GET /api/messages/facets

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `search`, `sender`, `recipient`, `direction`, `status`, `user`, `ip`, `start_date`, `end_date` | as in `GET /api/messages` | Unset | Same filters as the message list |
| `since` | array of strings | `[]` | Time ranges to count, as `name:ISO-start` (for example `today:2026-09-27T00:00:00Z`). Repeat the parameter for more ranges; up to 8 are read. `name` is 1 to 16 lower-case letters or digits; invalid entries are skipped. |

Read filter counts for the message search.

Returns `status` counts (`delivered`, `deferred`, `bounced`, `rejected`, `spam`, `discarded`) and `direction` counts (`inbound`, `outbound`, `internal`), each with an `all` count. Each status or direction count applies the other filters but not its own. When `since` is given, `time` contains an `all` count and one count per valid named range; these time counts ignore `start_date` and `end_date`. Counts are messages, not delivery legs.

---

### GET /api/message/{correlation_key}

Read the older compact message-detail representation. Returns identity and addressing fields, `direction`, `final_status`, `first_seen`, `last_seen`, `rspamd`, `postfix` and `timeline`. An unknown key returns 404.

Use `GET /api/message/{correlation_key}/details` for the current UI detail representation, including Dovecot data and related deliveries.

---

## Logs

### Postfix Logs

#### GET /logs/postfix

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `page` | integer | `1` | Page number, at least 1 |
| `limit` | integer | `50` | Items per page, 1 to 500 |
| `search` | string or null | Unset | Case-insensitive substring of the log message, sender, recipient or queue ID |
| `sender` | string or null | Unset | Substring of the sender |
| `recipient` | string or null | Unset | Substring of the recipient |
| `status` | string or null | Unset | Exact Postfix status, such as `sent`, `deferred`, `bounced` or `rejected` |
| `queue_id` | string or null | Unset | Exact queue ID |
| `start_date` | datetime or null | Unset | Earliest log time (ISO 8601) |
| `end_date` | datetime or null | Unset | Latest log time (ISO 8601) |

Get Postfix logs grouped by queue ID (one row per queue; lines without a queue ID are left out).

**Response:**
```json
{
  "total": 500,
  "page": 1,
  "limit": 50,
  "pages": 10,
  "data": [
    {
      "id": 12345,
      "time": "2025-12-25T10:30:00Z",
      "program": "postfix/smtp",
      "priority": "info",
      "message": "ABC123DEF: to=<user@example.com>...",
      "queue_id": "ABC123DEF",
      "message_id": "<unique-id@example.com>",
      "sender": "sender@example.com",
      "recipient": "user@example.com",
      "status": "sent",
      "relay": "mail.example.com[192.0.2.10]:25",
      "delay": 1.5,
      "dsn": "2.0.0",
      "correlation_key": "abc123..."
    }
  ]
}
```

---

#### GET /logs/postfix/by-queue/{queue_id}

Get all Postfix logs for one queue ID, oldest first, with linked Rspamd data. A queue ID with no logs returns 404.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `queue_id` | string | The Postfix queue ID |

**Response:**
```json
{
  "queue_id": "ABC123DEF",
  "correlation_key": "abc123...",
  "rspamd": {
    "score": 0.5,
    "required_score": 15,
    "action": "no action",
    "symbols": {},
    "is_spam": false,
    "direction": "outbound",
    "subject": "Hello World"
  },
  "logs": [
    {
      "id": 12345,
      "time": "2025-12-25T10:30:00Z",
      "program": "postfix/smtpd",
      "priority": "info",
      "message": "ABC123DEF: client=...",
      "queue_id": "ABC123DEF",
      "message_id": "<unique-id@example.com>",
      "sender": "sender@example.com",
      "recipient": "user@example.com",
      "status": null,
      "relay": null,
      "delay": null,
      "dsn": null
    }
  ]
}
```

---

### Rspamd Logs

#### GET /logs/rspamd

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `page` | integer | `1` | Page number, at least 1 |
| `limit` | integer | `50` | Items per page, 1 to 500 |
| `search` | string or null | Unset | Case-insensitive substring of the subject, SMTP sender or Message-ID |
| `sender` | string or null | Unset | Substring of the SMTP sender |
| `direction` | string or null | Unset | `inbound`, `outbound`, `internal` or `unknown` |
| `min_score` | float or null | Unset | Lowest Rspamd score |
| `max_score` | float or null | Unset | Highest Rspamd score |
| `action` | string or null | Unset | Exact Rspamd action, such as `no action`, `add header`, `rewrite subject`, `greylist` or `reject` |
| `is_spam` | boolean or null | Unset | Only spam (`true`) or only non-spam (`false`) |
| `start_date` | datetime or null | Unset | Earliest log time (ISO 8601) |
| `end_date` | datetime or null | Unset | Latest log time (ISO 8601) |

Get Rspamd spam analysis logs.

**Response:**
```json
{
  "total": 1000,
  "page": 1,
  "limit": 50,
  "pages": 20,
  "data": [
    {
      "id": 5678,
      "time": "2025-12-25T10:30:00Z",
      "message_id": "<unique-id@example.com>",
      "subject": "Hello World",
      "size": 1024,
      "sender_smtp": "sender@example.com",
      "recipients_smtp": ["user@example.com"],
      "score": 0.5,
      "required_score": 15,
      "action": "no action",
      "direction": "outbound",
      "ip": "192.0.2.100",
      "is_spam": false,
      "has_auth": true,
      "user": "sender@example.com",
      "symbols": {
        "MAILCOW_AUTH": {"score": -20, "description": "mailcow authenticated"},
        "RCVD_COUNT_ZERO": {"score": 0, "options": ["0"]}
      },
      "correlation_key": "abc123..."
    }
  ]
}
```

---

### Netfilter Logs

#### GET /logs/netfilter

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `page` | integer | `1` | Page number, at least 1 |
| `limit` | integer | `50` | Rows per page, 1 to 500 |
| `search` | string or null | Unset | Case-insensitive substring of the message, IP or username |
| `ip` | string or null | Unset | Substring of the IP, or the exact IP when `exact_ip` is true |
| `exact_ip` | boolean | `false` | Match the IP exactly instead of as a part |
| `username` | string or null | Unset | Case-insensitive substring of the username |
| `action` | string or null | Unset | `warning`, `ban`, `unban` or `info`; `ban` also matches older `banned` lines |
| `country_code` | string or null | Unset | Two-letter country code, in any case |
| `start_date` | datetime or null | Unset | Earliest log time (ISO 8601) |
| `end_date` | datetime or null | Unset | Latest log time (ISO 8601) |

Get stored Netfilter log lines (failed logins, Fail2ban bans and unbans, and other messages), newest first.

**Response:**
```json
{
  "total": 100,
  "page": 1,
  "limit": 50,
  "pages": 2,
  "data": [
    {
      "id": 999,
      "time": "2025-12-25T10:30:00Z",
      "priority": "warn",
      "message": "198.51.100.53 matched rule id 3...",
      "ip": "198.51.100.53",
      "rule_id": 3,
      "attempts_left": 9,
      "username": "user@example.com",
      "auth_method": "SASL LOGIN",
      "action": "warning",
      "country_code": "NL",
      "country_name": "Netherlands",
      "city": "Amsterdam",
      "asn": "AS64496",
      "asn_org": "Example Hosting"
    }
  ]
}
```

#### GET /logs/netfilter/overview

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `hours` | integer | `24` | Period in hours, 1 to 168 |

Attempts against the server over the last hours, grouped by source address. Used by the Security page.

Only lines where netfilter matched a rule count as an attempt; the "N more attempts ... until banned" line that follows each one is not counted again. The service comes from the log text (SMTP auth, SMTP probe, IMAP, POP3, Sieve, SOGo, mailcow UI, Rspamd UI); failed logins are the attempts that are not SMTP probes.

**Response:**
```json
{
  "hours": 24,
  "attempts": 61,
  "failed_logins": 53,
  "source_count": 4,
  "sources": [
    {
      "ip": "198.51.100.23",
      "attempts": 38,
      "failed_logins": 38,
      "last_seen": "2025-12-25T10:30:00Z",
      "services": ["SMTP auth"],
      "usernames": ["admin@example.com"],
      "country_code": "NL",
      "country_name": "Netherlands",
      "city": "Amsterdam",
      "asn_org": "Example Hosting",
      "last_action": null
    }
  ],
  "latest": [
    {
      "time": "2025-12-25T10:30:00Z",
      "ip": "198.51.100.23",
      "username": "admin@example.com",
      "service": "SMTP auth",
      "country_code": "NL",
      "country_name": "Netherlands"
    }
  ]
}
```

`sources` holds the 50 addresses with the most attempts; `last_action` is the last Fail2ban `ban` or `unban` seen for the address in the window, or `null`. `usernames` holds up to 5 names. `latest` holds the 20 most recent failed logins. The overview reads at most the 50,000 newest lines in the period.

---

#### GET /api/logs/netfilter/countries

Read the recorded country choices as an array of `{code, name}` objects. Only entries with a country code are included. A read failure returns an empty array.

---

#### GET /api/logs/netfilter/stats/by-country

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `days` | integer | `30` | Days to look back, 1 to 365 |

Read countries grouped over the selected number of days. The response contains `days`, `since` and `data`. `since` reports retained history when it is shorter than the requested period.

Returns up to 10 countries, sorted by `warning` and then `total`. Rows contain `country_code`, `country_name`, `ban`, `unban`, `warning`, `total` and `addresses`. `warning` counts attempts (lines where netfilter matched a rule); `ban` and `unban` count Fail2ban ban and unban lines; `total` is their sum; `addresses` is the number of distinct addresses with attempts. Lines without a stored country are located with GeoIP when it is available.

---

#### GET /api/logs/netfilter/stats/by-network

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `days` | integer | `30` | Days to look back, 1 to 365 |

Read attempted logins grouped by ASN/network. The response contains `days`, `since` and `data`; each row has `asn`, `asn_org`, `attempts` and `addresses`. Returns up to 8 networks with the most attempts. Only attempt lines with a known ASN count; `asn_org` falls back to the ASN when the organization is unknown.

---

#### GET /api/security/addresses

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `list` | string | `review` | `review` or `banned` |
| `country` | string or null | Unset | Only addresses from this country, matched by name as in `countries[].country_name`; up to 100 characters |
| `after` | string or null | Unset | The `next` value from the previous page; up to 200 characters |
| `limit` | integer | `50` | Addresses per page, 1 to 200 |
| `q` | string or null | Unset | Only addresses whose IP contains this text; up to 100 characters |
| `network` | string or null | Unset | Only addresses from this network, matched by ASN organization as in `networks[].asn_org`; up to 200 characters |
| `days` | integer | `1` | Period in days (addresses that tried in the last N days), 1 to 365 |

Read the Security page's cursor-paginated `review` or `banned` addresses. Use the previous response's `next` as `after`. Results are cached for 10 seconds per period.

The response contains `list`, `country`, `network`, `total`, `counts`, `all_counts`, `items`, `next`, `days`, `countries`, `networks`, `since` and `fail2ban_known`. `total` counts the requested list after `country`, `network` and `q`; `counts` gives both lists with those filters; `all_counts` gives both lists without them. `countries` (top 10) and `networks` (top 8) count every address on either list in the period, ignoring `country`, `network` and `q`. Country rows have `country_name`, `country_code`, `addresses`, `attempts`, `review` and `banned`; network rows have `asn_org` and the same counts. `review` and `banned` there are attempt totals per list, not address counts.

Items contain `ip`, `state`, `tries`, `attempts`, `users`, `services`, `hits`, `country`, `country_code`, `city`, `org`, `last_seen`, `f2b` and `listed_as`:

- `state`: `review` (open rule catch), `allow` (on the allowlist, shown under review), `quiet` (attempts only, shown under review), `banned` (rule ban or active Fail2ban ban) or `deny` (on the denylist, shown under banned)
- `tries` counts failed logins; `attempts` counts every attempt line
- `hits`: the address's open protection hits
- `f2b`: mailcow's active-ban entry, or `null`
- `listed_as`: the allowlist or denylist entry that holds the address, or `null`

A false `fail2ban_known` means current mailcow ban state was unavailable.

---

### Fail2Ban Configuration

#### GET /fail2ban

Get the current Fail2ban configuration from mailcow (passed through from `/api/v1/get/fail2ban`). The fields are mailcow's.

**Response:**
```json
{
  "ban_time": 1800,
  "ban_time_increment": false,
  "max_ban_time": 86400,
  "netban_ipv4": 32,
  "netban_ipv6": 128,
  "max_attempts": 10,
  "retry_window": 600,
  "manage_external": 0,
  "whitelist": "192.0.2.0/24\n198.51.100.0/24",
  "blacklist": "",
  "perm_bans": [],
  "active_bans": []
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `ban_time` | int | Ban duration in seconds |
| `ban_time_increment` | bool | Whether ban time increases with each offense |
| `max_ban_time` | int | Maximum ban duration in seconds (when increment enabled) |
| `netban_ipv4` | int | IPv4 subnet size for banning (e.g., 32 = single IP) |
| `netban_ipv6` | int | IPv6 subnet size for banning |
| `max_attempts` | int | Number of failed attempts before ban |
| `retry_window` | int | Time window in seconds for counting attempts |
| `manage_external` | int | Whether Fail2Ban is managed externally (0/1) |
| `whitelist` | string | Newline-separated list of allowlisted IPs/networks |
| `blacklist` | string | Newline-separated list of denylisted IPs/networks |
| `perm_bans` | array | Permanent ban entries from mailcow |
| `active_bans` | array | Active ban entries from mailcow (each with `network`, `ip` and `queued_for_unban`) |

**Error Responses:**

- `503 Service Unavailable`: mailcow returned no Fail2ban configuration

- `502 Bad Gateway`: The mailcow request failed

#### POST /fail2ban

Update the Fail2ban configuration on mailcow. Needs a read-write API key (`MAILCOW_API_KEY_RW`).

**Request Body:**
```json
{
  "attr": {
    "ban_time": "86400",
    "ban_time_increment": "1",
    "max_ban_time": "86400",
    "max_attempts": "5",
    "retry_window": "600",
    "netban_ipv4": "24",
    "netban_ipv6": "64",
    "whitelist": "192.0.2.0/24",
    "blacklist": "192.0.2.5/32"
  }
}
```

Send the complete configuration, including unchanged values, either inside an `attr` object or as the top-level object. When `manage_external` is left out, the current mailcow value is kept.

**Response:**
```json
{ "status": "success", "msg": ["fail2ban_edit_ok"] }
```

The app turns mailcow's first result into `status` and `msg`. A mailcow rejection returns HTTP 200 with `status: "error"`. When mailcow does not answer with a list, the success object adds `raw`. A missing or refused read-write API key (including a read-only key), or a failed mailcow request, returns 502. A body that is not valid JSON returns 500.

#### POST /fail2ban/ban

Add an address to the Fail2ban denylist (`blacklist`). Every other Fail2ban setting is kept, and the lists are read fresh right before writing. Needs a read-write API key.

**Request Body:**
```json
{ "ip": "198.51.100.23/32" }
```

**Response:**
```json
{ "status": "success", "msg": "IP 198.51.100.23/32 added to blacklist" }
```

A missing `ip` returns 400. If the current settings cannot be read, 503. A missing or refused read-write API key returns 502. An address already on the list returns `success` with `IP ... is already in the blacklist`. A mailcow rejection returns HTTP 200 with `status: "error"`.

#### POST /fail2ban/allow

Add an address to the mailcow allowlist. Send `{ "ip": "192.0.2.10/32" }`. Same rules, errors and response shape as `ban`; success answers `IP ... added to allowlist` (or `is already in the allowlist`).

#### POST /fail2ban/unban

Lift an active ban with mailcow's unban action. The denylist and other settings are not changed. Send `{ "ip": "198.51.100.23" }`; a bare address is sent as /32 (IPv4) or /128 (IPv6). The response has `status` and `msg` from mailcow's first result, plus `raw` when mailcow does not answer with a list. A missing `ip` returns 400. Any mailcow failure, including a missing or refused read-write API key, returns 502.

#### RW Status Check

See [GET /rw-status](#get-rw-status) to check whether a read-write API key is configured.

---

#### POST /api/fail2ban/policy

Change the Fail2ban policy while keeping the allowlist, denylist and external-management flag, which are read fresh right before writing. Needs a read-write API key.

Send `ban_time` and `max_ban_time` as seconds, each at least 60, with the longest ban no shorter than the first ban. Also send `max_attempts` (at least 1), `retry_window` (at least 1 second), `netban_ipv4` (8 to 32) and `netban_ipv6` (8 to 128). `ban_time_increment` is optional: `true`, `1` or `"1"` turns it on, and any other value or leaving it out turns it off.

A field that is not a whole number, or is out of range, returns 400; unavailable current settings return 503; a missing or refused read-write API key returns 502. Success answers `{ "status": "success", "msg": "Fail2ban policy saved" }`. Check `status` even after HTTP 200, because mailcow can report a rejected update in the body.

---

#### POST /api/fail2ban/remove

Remove an address from the mailcow denylist or allowlist without replacing the other settings. Needs a read-write API key.

Body: `{ "ip": "192.0.2.10", "list": "blacklist" }`, with `list` equal to `blacklist` or `whitelist`. `192.0.2.10` and `192.0.2.10/32` (or `/128`) match the same entry. A missing IP or an invalid list returns 400; unavailable current settings return 503; a missing or refused read-write API key returns 502. The response contains `status` and `msg`; an absent entry answers `success` with `IP ... is not in the blacklist` (or `allowlist`).

---

#### GET /api/geoip/{ip}

Read the MaxMind location for an address. Returns `{ "available": false }` if the City database is not installed. Otherwise returns `available: true`, `ip`, `country_code`, `country_name`, `city`, `asn` and `asn_org`. Each location field is `null` when the address is not found; `asn` and `asn_org` are also `null` without the ASN database.

---

## Queue & Quarantine

### GET /queue

Read the current mail queue live from mailcow.

**Response:**
```json
{
  "total": 5,
  "data": [
    {
      "queue_name": "deferred",
      "queue_id": "ABC123DEF",
      "arrival_time": 1735123456,
      "message_size": 515749,
      "forced_expire": false,
      "sender": "sender@example.com",
      "recipients": [
        "user@example.com (connect to example.com[192.0.2.10]:25: Connection timed out)"
      ]
    }
  ]
}
```
---

### POST /queue/action

Perform an action on mail queue items. Needs a read-write API key (`MAILCOW_API_KEY_RW`).

**Request Body:**
```json
{
  "items": ["ABC123DEF"],
  "action": "deliver"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `items` | string[] | Yes | Array of queue IDs, or `["mailqitems-all"]` for bulk actions |
| `action` | string | Yes | Action to perform (see table below) |

**Supported Actions:**

| Action | Description |
|--------|-------------|
| `deliver` | Retry delivery of the message |
| `hold` | Put message on hold (pause delivery attempts) |
| `unhold` | Release a held message |
| `flush` | Flush (retry) all queued messages. Use with `items: ["mailqitems-all"]` |
| `super_delete` | Delete all messages from queue. Use with `items: ["mailqitems-all"]` |

**Response (Success):**
```json
{
  "status": "success",
  "msg": "Queue action 'deliver' completed"
}
```

**Error Responses:**

- `400 Bad Request`: Missing `items` array or invalid action

- `502 Bad Gateway`: Read-write API key not configured or refused, or mailcow did not answer

**Notes:**

- Proxies to mailcow `POST /api/v1/edit/mailq` with `{"items": [...], "attr": {"action": "..."}}`

- For bulk actions (`flush`, `super_delete`), use `["mailqitems-all"]` as items

---

### POST /queue/delete

Delete specific mail queue items. Needs a read-write API key (`MAILCOW_API_KEY_RW`).

**Request Body:**
```json
{
  "items": ["ABC123DEF"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `items` | string[] | Yes | Array of queue IDs to delete |

**Response (Success):**
```json
{
  "status": "success",
  "msg": "Queue item(s) deleted"
}
```

**Error Responses:**

- `400 Bad Request`: Missing `items` array

- `502 Bad Gateway`: Read-write API key not configured or refused, or mailcow did not answer

**Notes:**

- Proxies to mailcow `POST /api/v1/delete/mailq` with queue IDs array

- To delete all items, use `POST /queue/action` with `action: "super_delete"` instead

---

### GET /quarantine

Read the quarantined messages live from mailcow.

**Response:**
```json
{
  "total": 3,
  "data": [
    {
      "id": 123,
      "subject": "Suspicious Email",
      "sender": "spammer@example.org",
      "rcpt": "user@example.com",
      "created": "2025-12-25T10:30:00Z",
      "action": "reject",
      "score": 15.2,
      "virus_flag": false,
      "qid": "ABC123DEF"
    }
  ]
}
```

---

### RW Status Check

Quarantine actions need a read-write API key. See [GET /rw-status](#get-rw-status) for checking availability.

---

### POST /quarantine/release

Release (approve) quarantined messages on mailcow. Needs a read-write API key (`MAILCOW_API_KEY_RW`).

**Request Body:**
```json
{
  "items": ["123", "456"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `items` | string[] | Yes | Array of quarantine item ID strings to release |

**Response (Success):**
```json
{
  "status": "success",
  "msg": "Message(s) released"
}
```

**Response (Error):**
```json
{
  "status": "error",
  "msg": "Release failed"
}
```

**Error Responses:**

- `400 Bad Request`: Missing `items` array

- `502 Bad Gateway`: Read-write API key not configured or refused, or mailcow did not answer

**Notes:**

- Proxies to mailcow `POST /api/v1/edit/qitem` with `{"items": [...], "attr": {"action": "release"}}`

- Released messages are delivered to the original recipient's mailbox

---

### POST /quarantine/delete

Permanently delete quarantined messages on mailcow. Needs a read-write API key (`MAILCOW_API_KEY_RW`).

**Request Body:**
```json
{
  "items": ["123"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `items` | string[] | Yes | Array of quarantine item ID strings to delete |

**Response (Success):**
```json
{
  "status": "success",
  "msg": "Message(s) deleted"
}
```

**Response (Error):**
```json
{
  "status": "error",
  "msg": "Delete failed"
}
```

**Error Responses:**

- `400 Bad Request`: Missing `items` array

- `502 Bad Gateway`: Read-write API key not configured or refused, or mailcow did not answer

**Notes:**

- Proxies to mailcow `POST /api/v1/delete/qitem` with `["id1", "id2"]`

- Deleted messages are permanently removed and cannot be recovered

---

### POST /quarantine/learnham

Release quarantined messages and train Rspamd that they are **not spam** (ham). Needs a read-write API key (`MAILCOW_API_KEY_RW`).

**Request Body:**
```json
{
  "items": ["123"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `items` | string[] | Yes | Array of quarantine item ID strings |

**Response (Success):**
```json
{
  "status": "success",
  "msg": "Message(s) released & marked as not spam"
}
```

**Error Responses:**

- `400 Bad Request`: Missing `items` array

- `502 Bad Gateway`: Read-write API key not configured or refused, or mailcow did not answer

**Notes:**

- Proxies to mailcow `POST /api/v1/edit/qitem` with `{"items": [...], "attr": {"action": "learnham"}}`

- mailcow performs its `learnham` action on the selected messages

---

### POST /quarantine/learnspam

Delete quarantined messages and train Rspamd that they are **spam**. Needs a read-write API key (`MAILCOW_API_KEY_RW`).

**Request Body:**
```json
{
  "items": ["123"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `items` | string[] | Yes | Array of quarantine item ID strings |

**Response (Success):**
```json
{
  "status": "success",
  "msg": "Message(s) deleted & marked as spam"
}
```

**Error Responses:**

- `400 Bad Request`: Missing `items` array

- `502 Bad Gateway`: Read-write API key not configured or refused, or mailcow did not answer

**Notes:**

- Proxies to mailcow `POST /api/v1/edit/qitem` with `{"items": [...], "attr": {"action": "learnspam"}}`

- mailcow performs its `learnspam` action on the selected messages

---

### GET /quarantine/{item_id}/details

Get detailed information about a specific quarantine item, including full email headers, Rspamd symbols with scores, email body content, and fuzzy hashes. Proxies mailcow's `qitem_details.php`.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `item_id` | string | Quarantine item ID |

**Response:**
```json
{
  "recipients": [
    {"address": "user@example.com", "type": "to"},
    {"address": "user@example.com", "type": "smtp"}
  ],
  "header_from": "Sender Name <sender@example.com>",
  "env_from": "sender@example.com",
  "score": 9.72,
  "action": "add header",
  "symbols": [
    {
      "group": "hfilter",
      "name": "HFILTER_URL_ONLY",
      "groups": ["hfilter"],
      "weight": 8.2,
      "score": 8.2,
      "options": ["1"]
    },
    {
      "group": "headers",
      "name": "FROM_HAS_DN",
      "groups": ["headers"],
      "weight": 0,
      "score": 0,
      "options": []
    }
  ],
  "subject": "Test email",
  "text_plain": "Email body content...",
  "text_html": null,
  "fuzzy_hashes": [
    {"type": "text", "hash": "abc123..."}
  ]
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `recipients` | array | List of recipients with `address` and `type` (to/smtp) |
| `header_from` | string | Display name and address from email header |
| `env_from` | string | Envelope sender address |
| `score` | float | Rspamd spam score |
| `action` | string | Action taken (e.g., "add header", "reject") |
| `symbols` | array | Rspamd symbols with group, name, score, and options |
| `subject` | string | Email subject line |
| `text_plain` | string/null | Plain text email body |
| `text_html` | string/null | HTML email body |
| `fuzzy_hashes` | array | Fuzzy hash data for the email |

**Error Responses:**

- `502 Bad Gateway`: Failed to fetch details from mailcow

**Notes:**

- Proxies to mailcow's `/inc/ajax/qitem_details.php?id={item_id}` using the API key for authentication

- The response is the first element of the array returned by mailcow

---

## Statistics

### GET /stats/dashboard

Read current aggregate counts. The response has:

- `messages`: `24h`, `7d`, `30d` delivery-leg counts, plus deduplicated `unique_24h` and `unique_7d` message counts.

- `blocked`: `24h`, `7d`, `percentage_24h` for bounced, rejected and spam statuses.

- `deferred` and `auth_failures`: `24h` and `7d` counts.

- `direction`: `inbound_24h`, `outbound_24h`, `internal_24h`.

There is no top-level spam or failed_deliveries object. A data-read failure can return an error and zero-valued fallback fields with HTTP 200, so inspect `error` as well as the HTTP status.

---

### GET /stats/timeline

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `hours` | integer | `24` | How many hours back to chart, one bucket per hour |

Get message timeline for charts.

**Response:**
```json
{
  "timeline": [
    {
      "hour": "2025-12-25T08:00:00Z",
      "total": 45,
      "spam": 2,
      "clean": 43
    },
    {
      "hour": "2025-12-25T09:00:00Z",
      "total": 67,
      "spam": 5,
      "clean": 62
    }
  ]
}
```

---

### GET /stats/top-spam-triggers

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `limit` | integer | `10` | Number of symbols to return |

Get the Rspamd symbols seen most often on spam in the last 7 days. On a read error, the response is `{ "triggers": [], "error": "..." }` with HTTP 200.

**Response:**
```json
{
  "triggers": [
    {"symbol": "RCVD_IN_DNSWL_NONE", "count": 456},
    {"symbol": "DKIM_SIGNED", "count": 234},
    {"symbol": "SPF_PASS", "count": 200}
  ]
}
```

---

### GET /stats/top-blocked-ips

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `limit` | integer | `10` | Number of addresses to return |

Get the addresses with the most Netfilter (Fail2ban) log entries in the last 7 days. On a read error, the response is `{ "blocked_ips": [], "error": "..." }` with HTTP 200.

**Response:**
```json
{
  "blocked_ips": [
    {
      "ip": "198.51.100.53",
      "count": 45,
      "last_seen": "2025-12-25T10:30:00Z"
    }
  ]
}
```

---

### GET /stats/recent-activity

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `limit` | integer | `20` | Number of messages to return |

Get the most recently updated messages, newest first.

**Response:**
```json
{
  "activity": [
    {
      "time": "2025-12-25T10:30:00Z",
      "sender": "user@example.com",
      "recipient": "other@example.net",
      "subject": "Hello World",
      "direction": "outbound",
      "status": "delivered",
      "correlation_key": "abc123..."
    }
  ]
}
```

---

## Status

### GET /status/containers

Get status of all mailcow containers.

**Response:**
```json
{
  "containers": {
    "postfix-mailcow": {
      "name": "postfix",
      "state": "running",
      "started_at": "2025-12-20T08:00:00Z",
      "ignored": false
    },
    "ipv6nat-mailcow": {
      "name": "ipv6nat",
      "state": "exited",
      "started_at": null,
      "ignored": true
    }
  },
  "summary": {
    "running": 18,
    "stopped": 0,
    "total": 18,
    "ignored": 1
  }
}
```

An ignored container is still listed but never counted: `running`, `stopped` and `total` leave it out, and `ignored` counts them. The dashboard alert and the problem counters follow the summary.

---

### PUT /status/containers/{container}/ignore

**JSON fields:**

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `ignored` | boolean | Required | `true` to ignore the container, `false` to count it again |

Ignore or stop ignoring one container, for example `ipv6nat-mailcow` on a server without IPv6. The choice is stored on the server for every user.

**Request:**
```json
{ "ignored": true }
```

**Response:**
```json
{ "container": "ipv6nat-mailcow", "ignored": true }
```

Returns `404` for a container name the app has never seen.

---

### GET /status/storage

Get storage/disk usage information.

**Response:**
```json
{
  "disk": "/dev/sda1",
  "used": "45G",
  "total": "100G",
  "used_percent": "45%"
}
```

---

### GET /status/version

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `force` | boolean | `false` | Force a fresh version check |

Get mailcow version and update status.

**Response:**
```json
{
  "current_version": "2025-01",
  "latest_version": "2025-01a",
  "update_available": true,
  "changelog": "Bug fixes and improvements...",
  "last_checked": "2025-12-25T10:30:00Z"
}
```

---

### GET /status/app-version

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `force` | boolean | `false` | Force a fresh version check |

Get application version and check for updates from GitHub.

**Response:**
```json
{
  "current_version": "1.4.9",
  "latest_version": "1.4.9",
  "update_available": false,
  "changelog": "### Added\n\n#### Background jobs list\n- Compact layout...",
  "last_checked": "2026-01-08T15:52:46Z"
}
```

**Implementation Notes:**

- Version checks are performed by the scheduler every 6 hours

- Results are cached in `app_version_cache` (managed by `scheduler.py`)

- Status endpoint retrieves cached data via `get_app_version_cache()`

- Use `force=true` parameter to bypass cache and trigger immediate check

- All timestamps include UTC timezone indicator ('Z' suffix)

- Changelog is retrieved from GitHub releases in Markdown format

**Version Check Process:**
1. Scheduler job `check_app_version_update` runs every 6 hours
2. Fetches latest release from `https://api.github.com/repos/ShlomiPorush/mailcow-logs-viewer/releases/latest`
3. Compares current version (from `/app/VERSION` file) with latest GitHub release
4. Updates cache with result and changelog
5. Job status tracked with `update_job_status()` (visible in Settings > Background Jobs)

---

### GET /status/app-version/changelog/{version}

Get changelog for a specific app version from GitHub.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `version` | string | Version number (with or without 'v' prefix, e.g., "1.4.6" or "v1.4.6") |

**Response:**
```json
{
  "version": "1.4.6",
  "changelog": "Full changelog in Markdown format for the specified version..."
}
```

**Note:** Returns the changelog from the GitHub release for the specified version tag.

---

### GET /status/mailcow-connection

Check mailcow API connection status.

**Response:**
```json
{
  "connected": true,
  "timestamp": "2026-01-05T15:52:46Z"
}
```

**Note:** Returns connection status and current timestamp in UTC format.

---

### GET /status/mailcow-info

Get mailcow system information.

**Response:**
```json
{
  "domains": {
    "total": 5,
    "active": 5
  },
  "mailboxes": {
    "total": 25,
    "active": 23
  },
  "aliases": {
    "total": 50,
    "active": 48
  }
}
```

---

### GET /status/summary

Get combined status summary for dashboard.

**Response:**
```json
{
  "containers": {
    "running": 18,
    "stopped": 0,
    "total": 18
  },
  "storage": {
    "used_percent": "45%",
    "used": "45G",
    "total": "100G"
  },
  "system": {
    "domains": 5,
    "mailboxes": 25,
    "aliases": 50
  }
}
```

---

## Settings

### GET /api/settings/info

Get system configuration and status information.

**Description:** Returns system configuration, import status, correlation status, and background job status. When `SETTINGS_EDIT_VIA_UI_ENABLED=true`, also includes editable configuration and migration status.

**Authentication:** Required when sign-in is enabled.

**Response:**
```json
{
  "settings_edit_via_ui_enabled": true,
  "settings_migrated": true,
  "editable_config": {
    "mailcow_url": "https://mail.example.com",
    "mailcow_api_key": "********",
    "fetch_interval": 60,
    "retention_days": 7
  },
  "configuration": {
    "mailcow_url": "https://mail.example.com",
    "server_ip": "192.0.2.10",
    "local_domains": ["example.com"],
    "fetch_interval": 60,
    "fetch_count_postfix": 2000,
    "fetch_count_rspamd": 500,
    "fetch_count_netfilter": 500,
    "fetch_max_pages": 50,
    "retention_days": 7,
    "max_correlation_age_minutes": 10,
    "correlation_check_interval": 120,
    "timezone": "UTC",
    "app_title": "mailcow Logs Viewer",
    "log_level": "WARNING",
    "blacklist_enabled": true,
    "blacklist_count": 3,
    "max_search_results": 1000,
    "csv_export_limit": 10000,
    "scheduler_workers": 4,
    "rspamd_configured": true,
    "database_version": "16.4",
    "auth_enabled": true,
    "basic_auth_enabled": true,
    "oauth2_enabled": false,
    "auth_username": "admin",
    "oauth2_provider_name": null,
    "maxmind_status": {
      "configured": true,
      "valid": true,
      "error": null,
      "checked_at": "2026-05-15T14:30:00Z"
    },
    "mailcow_rw_key_status": {
      "configured": true,
      "valid": true,
      "error": null,
      "checked_at": "2026-10-07T09:12:00Z"
    },
    "rspamd_password_status": {
      "configured": true,
      "valid": true,
      "error": null,
      "checked_at": "2026-10-07T09:12:01Z"
    }
  },
  "import_status": {
    "postfix": {
      "last_import": "2025-12-25T10:30:00Z",
      "last_fetch_run": "2025-12-25T10:35:00Z",
      "total_entries": 50000,
      "oldest_entry": "2025-12-18T00:00:00Z"
    },
    "rspamd": {
      "last_import": "2025-12-25T10:30:00Z",
      "last_fetch_run": "2025-12-25T10:35:00Z",
      "total_entries": 45000,
      "oldest_entry": "2025-12-18T00:00:00Z"
    },
    "netfilter": {
      "last_import": "2025-12-25T10:30:00Z",
      "last_fetch_run": "2025-12-25T10:35:00Z",
      "total_entries": 1000,
      "oldest_entry": "2025-12-18T00:00:00Z"
    }
  },
  "correlation_status": {
    "last_update": "2025-12-25T10:30:00Z",
    "total": 40000,
    "complete": 39500,
    "incomplete": 500,
    "expired": 100,
    "completion_rate": 98.75
  },
  "background_jobs": {
    "fetch_logs": {
      "interval": "60 seconds",
      "description": "Imports logs from mailcow API",
      "status": "success",
      "last_run": "2026-01-08T12:14:56Z",
      "error": null
    },
    "complete_correlations": {
      "interval": "120 seconds (2 minutes)",
      "description": "Links Postfix logs to messages",
      "status": "running",
      "last_run": "2026-01-08T12:13:56Z",
      "error": null,
      "pending_items": 93
    },
    "update_final_status": {
      "interval": "120 seconds (2 minutes)",
      "description": "Updates final status for correlations with late-arriving Postfix logs",
      "max_age": "10 minutes",
      "status": "success",
      "last_run": "2026-01-08T12:13:56Z",
      "error": null,
      "pending_items": 25
    },
    "expire_correlations": {
      "interval": "60 seconds (1 minute)",
      "description": "Marks old incomplete correlations as expired",
      "expire_after": "10 minutes",
      "status": "success",
      "last_run": "2026-01-08T12:14:45Z",
      "error": null
    },
    "cleanup_logs": {
      "schedule": "Daily at 2 AM",
      "description": "Removes old logs based on retention period",
      "retention": "7 days",
      "status": "success",
      "last_run": "2026-01-08T02:00:00Z",
      "error": null
    },
    "check_app_version": {
      "interval": "6 hours",
      "description": "Checks for application updates from GitHub",
      "status": "success",
      "last_run": "2026-01-08T10:00:00Z",
      "error": null
    },
    "dns_check": {
      "interval": "6 hours",
      "description": "Validates DNS records (SPF, DKIM, DMARC) for all active domains",
      "status": "success",
      "last_run": "2026-01-08T08:00:00Z",
      "error": null
    },
    "update_geoip": {
      "schedule": "Weekly (Sunday 3 AM)",
      "description": "Updates MaxMind GeoIP databases (City & ASN)",
      "enabled": true,
      "status": "success",
      "last_run": "2026-01-05T03:00:00Z",
      "error": null
    }
  },
  "recent_incomplete_correlations": [
    {
      "message_id": "<unique-id@example.com>",
      "queue_id": "ABC123",
      "sender": "user@example.com",
      "recipient": "other@example.net",
      "created_at": "2025-12-25T10:28:00Z",
      "age_minutes": 2
    }
  ]
}
```

**Response Fields (when `SETTINGS_EDIT_VIA_UI_ENABLED=true`):**

- `settings_edit_via_ui_enabled`: Boolean indicating if UI editing is enabled

- `settings_migrated`: Boolean indicating if settings have been migrated from ENV to DB

- `editable_config`: Dictionary of editable settings (sensitive fields masked); only present when UI editing is enabled

**Configuration notes:**

- `auth_username` is `null` unless Basic Auth is on; `oauth2_provider_name` is `null` unless OAuth2 is on.

- `mailcow_rw_key_status` and `rspamd_password_status`: without a read-write API key or Rspamd password, the field is `{"configured": false, "valid": false, "error": null}`. With one that has not been checked since the last change, it is `null`.

- If the data cannot be read, the endpoint still answers 200 with `error` set and empty `configuration`, `import_status`, `correlation_status` and `background_jobs`.

**Background Jobs Status Tracking:**

The real response has one entry per job (29 in total; the example shows 8). Each entry reports its current state:

| Field | Type | Description |
|-------|------|-------------|
| `interval` / `schedule` | string | How often the job runs |
| `description` | string | Human-readable job description |
| `status` | string | Current status: `idle`, `running`, `success`, `failed`, `disabled`, `skipped` or `unknown` (see [Status Values](#status-values)) |
| `last_run` | datetime | UTC timestamp of last execution (with 'Z' suffix) |
| `error` | string / null | Error message if job failed, otherwise null |
| `pending_items` | int | Number of items waiting (for correlation jobs only) |
| `max_age` / `expire_after` / `retention` | string | Job-specific configuration |
| `services` | string | Comma-separated raw log services collected (`fetch_raw_logs` only) |

A job that is off reports `status: "disabled"` and an interval such as `Disabled (feature off)`. What each job does is in the [Background Jobs List](#background-jobs-list).

---

The full result also includes `smtp_configuration`, `dmarc_configuration`, `geoip_configuration` and `raw_logs_required`. Editable mode adds `default_config` as well as `editable_config` and `settings_migrated`. Job metadata can include `enabled`, `feature_disabled`, `disabled_reason` and `settings_section`. The Status and Settings pages read these keys. Without MaxMind credentials, `geoip_configuration.databases` has the shape `{"City": {"installed": false, "version": null, "last_updated": null}, "ASN": {...}}`.

### GET /api/settings

Get editable settings configuration for UI editing.

**Description:** Returns all settings that can be edited via the web UI, along with feature flags and migration status. It remains readable when UI editing is off; database overrides reload only when editing is enabled.

**Authentication:** Required when sign-in is enabled.

**Response:**
```json
{
  "settings_edit_via_ui_enabled": true,
  "settings_migrated": true,
  "configuration": {
    "mailcow_url": "https://mail.example.com",
    "mailcow_api_key": "********",
    "mailcow_api_timeout": 30,
    "mailcow_api_verify_ssl": true,
    "fetch_interval": 60,
    "fetch_count_postfix": 2000,
    "fetch_count_rspamd": 500,
    "fetch_count_netfilter": 500,
    "retention_days": 7,
    "max_correlation_age_minutes": 10,
    "correlation_check_interval": 120,
    "log_level": "WARNING",
    "app_title": "mailcow Logs Viewer",
    "app_logo_url": "",
    "debug": false,
    "max_search_results": 1000,
    "csv_export_limit": 10000,
    "scheduler_workers": 4,
    "blacklist_emails": "archive@example.com,monitor@example.com",
    "basic_auth_enabled": true,
    "auth_username": "admin",
    "auth_password": "********",
    "oauth2_enabled": false,
    "admin_email": "admin@example.com",
    "blacklist_alert_email": "alerts@example.com",
    "dmarc_error_email": "dmarc@example.com",
    "smtp_enabled": true,
    "smtp_host": "smtp.example.com",
    "smtp_port": 587,
    "smtp_use_tls": true,
    "smtp_use_ssl": false,
    "smtp_user": "noreply@example.com",
    "smtp_password": "********",
    "smtp_from": "noreply@example.com",
    "smtp_relay_mode": false,
    "maxmind_account_id": "123456",
    "maxmind_license_key": "********",
    "dmarc_retention_days": 60,
    "dmarc_manual_upload_enabled": true,
    "dmarc_allow_report_delete": false,
    "enable_weekly_summary": true,
    "dmarc_imap_enabled": true,
    "dmarc_imap_host": "imap.example.net",
    "dmarc_imap_port": 993,
    "dmarc_imap_use_ssl": true,
    "dmarc_imap_user": "dmarc@example.com",
    "dmarc_imap_password": "********",
    "dmarc_imap_folder": "INBOX",
    "dmarc_imap_delete_after": true,
    "dmarc_imap_interval": 3600,
    "dmarc_imap_run_on_startup": true,
    "dmarc_imap_batch_size": 10
  },
  "env_locked_keys": ["mailcow_url", "mailcow_api_key"]
}
```

**Response Fields:**

- `default_config`: Application defaults for editable fields.

- `settings_edit_via_ui_enabled`: Boolean indicating if UI editing is enabled

- `settings_migrated`: Boolean indicating if settings have been migrated from ENV to DB

- `configuration`: Dictionary of all editable settings (sensitive fields are masked with `********`)

- `env_locked_keys`: Setting keys set by an environment variable. The environment value always wins over the database. Empty when UI editing is off.

**Sensitive Fields (Masked):**

- `mailcow_api_key`

- `mailcow_api_key_rw`

- `rspamd_password`

- `auth_password`

- `oauth2_client_secret`

- `smtp_password`

- `dmarc_imap_password`

- `session_secret_key`

- `maxmind_license_key`

**Notes:**

- Automatically reloads settings from database if UI editing is enabled

- Sensitive fields are masked with `********` in responses

- Empty sensitive fields are returned as empty string `""`

- `env_locked_keys` shows which fields are controlled by ENV and cannot be overridden from the UI

- Only editable settings are included. The PostgreSQL settings, `SETTINGS_EDIT_VIA_UI_ENABLED`, `AUTH_ENABLED`, `TZ`, `APP_PORT`, `CORS_ALLOWED_ORIGINS` and the legacy `WEBHOOK_*` settings are excluded.

---

### PUT /api/settings

Send a JSON object in the request body. The object itself contains the setting keys shown below; there is no `body` wrapper.

Update settings from the web UI.

**Description:** Updates application settings stored in the database. Only available when `SETTINGS_EDIT_VIA_UI_ENABLED=true`. Settings are validated before saving. After saving, the app reloads the settings, the mailcow API client and the OAuth2 client, reschedules the interval jobs, and deletes some data of features that are now off (see [purge-feature-data](#post-apisettingspurge-feature-data)).

**Authentication:** Required when sign-in is enabled.

**Request Body:**
```json
{
  "mailcow_url": "https://mail.example.com",
  "mailcow_api_key": "new-api-key-here",
  "fetch_interval": 120,
  "retention_days": 14,
  "smtp_enabled": true,
  "smtp_host": "smtp.example.com",
  "smtp_port": 587,
  "smtp_user": "noreply@example.com",
  "smtp_password": "new-password",
  "admin_email": "admin@example.com"
}
```

**Request Fields:**

- Any editable setting key (see `GET /api/settings` for full list)

- Sensitive fields: Send `********` to keep current value unchanged, send empty string `""` to clear the value

- Omit a field to leave it unchanged. `null` is kept for optional fields, coerced to an empty string for non-optional strings, and to zero/false for non-optional numbers/booleans; it is not a reset-to-default instruction.

Changing sign-in settings revokes existing sessions; the operator who saved gets a replacement session cookie. The response always includes `mailcow_rw_key_changed` and `rspamd_password_changed`: each is `true` when that credential is set after the save and it, or the address it is sent to, changed. Changed server or account values cannot reuse a masked stored secret; send the secret again for the new destination.

A key set by an environment variable can be saved, but the saved value has no effect while the variable is set; no error is returned. Keys that are not editable settings are ignored. A body with no editable change saves nothing and returns the current configuration without the `*_changed` keys.

#### Basic Auth Lockout Prevention

When the request sends `basic_auth_enabled` as JSON `true` while Basic Auth is off, it must include two more fields (a string such as `"true"` skips this check):

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `verify_username` | string | Yes (when enabling auth) | Must match `auth_username` in the request, or the stored username (default `admin`) when the request does not change it |
| `verify_password` | string | Yes (when enabling auth) | Must match `auth_password` in the request, or the stored password when the request omits it or sends `********` |

This prevents users from accidentally locking themselves out of the application by enabling authentication without knowing the credentials.

**Example request (enabling Basic Auth):**
```json
{
  "basic_auth_enabled": true,
  "auth_username": "admin",
  "auth_password": "my-secure-password",
  "verify_username": "admin",
  "verify_password": "my-secure-password"
}
```

`verify_username` and `verify_password` are only required when enabling Basic Auth (switching from `false` to `true`). They are not needed when disabling Basic Auth or when Basic Auth is already enabled.

**Response:**
```json
{
  "settings_edit_via_ui_enabled": true,
  "settings_migrated": true,
  "configuration": {
    "mailcow_url": "https://mail.example.com",
    "mailcow_api_key": "********",
    "fetch_interval": 120,
    "retention_days": 14,
    "smtp_enabled": true,
    "smtp_host": "smtp.example.com",
    "smtp_port": 587,
    "smtp_user": "noreply@example.com",
    "smtp_password": "********",
    "admin_email": "admin@example.com"
  },
  "mailcow_rw_key_changed": false,
  "rspamd_password_changed": false
}
```

**Error Responses:**

**403 Forbidden** (UI editing disabled):
```json
{
  "detail": "Editing settings from UI is disabled. Set SETTINGS_EDIT_VIA_UI_ENABLED=true to enable."
}
```

**400 Bad Request** (Validation error):
```json
{
  "detail": "Invalid settings for: smtp_port"
}
```

When no field can be named, `detail` is `Invalid settings. Check the submitted values.`

**400 Bad Request** (other checks), with these `detail` texts:

- An unknown feature in `disabled_features`: `disabled_features accepts only known feature names.`
- A server address changed but its stored secret was not sent again: `You changed the server the {names} is sent to. Enter the {names} again: ...`
- A server address changed for a secret set by an environment variable: `The {label} is set by the {SECRET} environment variable, so it can only be sent to a different server from there. ...`
- An invalid address in `admin_email`, `blacklist_alert_email` or `dmarc_error_email`: `{label}: "{bad}" is not an email address. Separate several addresses with commas.`
- Clearing the password while Basic Auth is on: `Cannot clear the password while Basic Auth is enabled. Disable Basic Auth first, or set a new password.`

**400 Bad Request** (No password when enabling Basic Auth):
```json
{
  "detail": "Cannot enable Basic Auth without a password. Please set a password first."
}
```

**400 Bad Request** (Missing verification credentials):
```json
{
  "detail": "Credential verification required. Please confirm your username and password to enable Basic Auth."
}
```

**400 Bad Request** (Verification credentials mismatch):
```json
{
  "detail": "Credential verification failed. The username and password you entered do not match the configured credentials."
}
```

**Notes:**

- `********` for sensitive fields means "keep current value"

- Returns the updated configuration with masked sensitive fields

- When enabling Basic Auth, credential verification uses timing-safe comparison (`secrets.compare_digest`)

---

### POST /api/settings/import-from-env

Import current configuration from environment variables to database.

**Description:** Migrates all current effective settings (from defaults + ENV + existing DB) into database. This allows users to transition from ENV-only management to UI management. After migration, remove only optional variables you intend to manage in the UI. Keep `MAILCOW_URL`, `MAILCOW_API_KEY`, the database connection values and `SETTINGS_EDIT_VIA_UI_ENABLED`; required mailcow values are read before database overrides load.

**Authentication:** Required when sign-in is enabled.

**Response:**
```json
{
  "message": "Configuration imported from current environment into DB.",
  "settings_edit_via_ui_enabled": true,
  "settings_migrated": true,
  "configuration": {
    "mailcow_url": "https://mail.example.com",
    "mailcow_api_key": "********",
    "fetch_interval": 60,
    "retention_days": 7
  },
  "env_locked_keys": ["mailcow_url", "mailcow_api_key"]
}
```

**Response Fields:**

- `message`: Success message

- `settings_edit_via_ui_enabled`: Always `true` (only available when enabled)

- `settings_migrated`: Always `true` after import

- `configuration`: Updated configuration with masked sensitive fields

- `env_locked_keys`: Array of setting keys where ENV is set and overrides DB values

**Error Responses:**

**403 Forbidden** (UI editing disabled):
```json
{
  "detail": "Editing settings from UI is disabled. Set SETTINGS_EDIT_VIA_UI_ENABLED=true to enable."
}
```

**Notes:**

- Imports all editable settings from current effective configuration

- Settings are automatically reloaded after import

- MailcowAPI configuration is automatically updated

- `env_locked_keys` shows which fields are controlled by ENV and cannot be overridden from the UI

- After migration, settings are managed via UI and stored in database

- `SETTINGS_EDIT_VIA_UI_ENABLED` must remain in ENV (not stored in DB)

---

### POST /api/settings/purge-feature-data

Send a JSON object in the request body with the feature ID shown below; there is no `body` wrapper.

Delete all database data associated with a disabled feature.

**Description:** When a feature is disabled, this endpoint permanently deletes all stored data from that feature's database tables. The feature must already be disabled (in `disabled_features`). Only available when `SETTINGS_EDIT_VIA_UI_ENABLED=true`.

**Authentication:** Required when sign-in is enabled.

**Request Body:**
```json
{
  "feature": "dmarc"
}
```

**Request Fields:**

- `feature` (string, required): Feature ID to purge. Valid values: `netfilter`, `domains`, `dmarc`, `mailbox-stats`, `logs`, `blacklist`, `spam-filter`, `quarantine`, `devices`

**Feature to Tables Mapping:**

| Feature | Tables Truncated |
|---------|-----------------|
| `netfilter` | `netfilter_logs` |
| `domains` | `domain_dns_checks` |
| `dmarc` | `dmarc_reports`, `dmarc_records`, `dmarc_syncs`, `tls_reports`, `tls_report_policies` |
| `mailbox-stats` | `mailbox_statistics`, `alias_statistics` |
| `logs` | `raw_service_logs` (only services nothing collects any more; `dovecot` always stays because message details read it, `ratelimited` stays while Rate Limits is on, `sogo` stays while Devices is on) |
| `blacklist` | `blacklist_checks`, `monitored_hosts` |
| `spam-filter` | `spam_suppressions` |
| `quarantine` | `quarantine_rules`, `quarantine_rule_logs` |
| `devices` | `eas_devices` |

**Response:**
```json
{
  "feature": "dmarc",
  "tables_purged": {
    "dmarc_records": 1523,
    "tls_report_policies": 42,
    "dmarc_reports": 87,
    "dmarc_syncs": 12,
    "tls_reports": 15
  },
  "total_rows_deleted": 1679
}
```

**Error Responses:**

**400 Bad Request** (unknown feature):
```json
{
  "detail": "Unknown feature: invalid-feature"
}
```

**400 Bad Request** (feature is still enabled):
```json
{
  "detail": "Feature 'dmarc' is currently enabled. Disable it first."
}
```

**403 Forbidden** (UI editing disabled):
```json
{
  "detail": "Editing settings from UI is disabled."
}
```

**500 Internal Server Error**: `Purge failed. Check the application logs.` Nothing is deleted.

**Notes:**

- Tables are truncated with `CASCADE` to handle foreign key relationships. For `raw_service_logs`, only the rows of services no longer collected are deleted.

- `PUT /api/settings` already deletes some data of features that are off: alias statistics, mailbox statistics (when Mailbox Stats and Rate Limits are both off), ActiveSync devices, raw log rows nothing collects and the Rate Limits reset history. The Settings page then calls this endpoint for each newly disabled feature, after a confirmation that data will be deleted.

- Features without database tables (for example `queue`, `rate-limits`) cannot be purged; the endpoint returns 400 for them.

---

### GET /settings/health

Detailed health check with timing information. Unlike `GET /api/health`, it needs authentication when sign-in is enabled. On a database failure it answers 200 with `"status": "unhealthy"`, `timestamp` and `error`.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-12-25T10:30:00Z",
  "database": {
    "status": "connected",
    "response_time_ms": 1.25
  },
  "recent_activity": {
    "last_5_minutes": {
      "postfix_imported": 45,
      "rspamd_imported": 42,
      "correlations_created": 40
    }
  }
}
```

---

### POST /api/settings/jobs/{job_name}/run

Manually trigger a background job.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `job_name` | string | Name of the job to run |

**Supported Job Names:**

- `correlate_dovecot`: Link Dovecot delivery outcomes

- `cleanup_dmarc_reports`: Remove old DMARC and TLS reports

- `dmarc_imap_sync`: Import reports from IMAP

- `anomaly_detection`: Run anomaly detection

- `smtp_abuse`: Run SMTP abuse enforcement

- `protection_rules`: Process protection rules

- `fetch_raw_logs`: Collect raw service logs

- `cleanup_raw_logs`: Remove old raw logs

- `fetch_logs`: Import logs from mailcow

- `complete_correlations`: Link logs to messages

- `update_final_status`: Update delivery status

- `expire_correlations`: Expire old correlations

- `cleanup_logs`: Clean up old logs

- `check_app_version`: Check for updates

- `dns_check`: Validate DNS records

- `sync_local_domains`: Sync domains

- `update_geoip`: Update MaxMind databases

- `mailbox_stats`: Update mailbox statistics

- `alias_stats`: Update alias statistics

- `blacklist_check`: Check blacklists

- `sync_transports`: Sync transports

- `send_weekly_summary`: Send weekly summary email

- `detect_suppressions`: Detect bounces and suppress recipients

- `sync_suppressions`: Sync suppressions to Rspamd

- `expire_suppressions`: Expire old suppressions

- `process_quarantine_rules`: Process quarantine auto-rules

- `cleanup_deferred_queue`: Clean up stuck deferred queue items

- `eas_devices`: Record ActiveSync devices from the SOGo log

- `cleanup_eas_devices`: Remove ActiveSync devices not seen within the retention period

**Response:**
```json
{
  "status": "started",
  "job": "fetch_logs",
  "message": "Job fetch_logs started in background"
}
```

**Error Responses:**

- `404`: Unknown job name

- `409`: Job is already running

The job runs in the background after the response. This endpoint does not check whether the job's feature or prerequisites are on: a job that is switched off returns at once, and its status then shows `success`.

---

## GeoIP Management

### GET /api/settings/geoip/status

Get detailed GeoIP status for frontend polling during setup/download.

**Authentication:** Required when sign-in is enabled.

**Response:**
```json
{
  "configured": true,
  "db_valid": true,
  "databases": {
    "configured": true,
    "db_valid": true,
    "City": {
      "available": true,
      "age_days": 1,
      "size_mb": 62.3,
      "last_modified": "2026-04-22T10:00:00"
    },
    "ASN": {
      "available": true,
      "age_days": 0,
      "size_mb": 11.3,
      "last_modified": "2026-04-22T18:00:00"
    }
  },
  "job_status": "success",
  "job_error": null,
  "job_last_run": "2026-04-22T18:00:05Z"
}
```

**Response Fields:**

- `configured`: Boolean - whether MaxMind Account ID and License Key are set

- `db_valid`: Boolean or null - `true` if DB validated, `false` if corrupt, `null` if not yet checked

- `databases`: Object - file-level info for City and ASN databases (size, age, availability)

- `job_status`: String - last GeoIP update job status: `idle`, `running`, `success`, `failed`

- `job_error`: String or null - error message if last job failed

- `job_last_run`: String or null - ISO timestamp of last job execution

**Notes:**

- Used by the GeoIP Setup Modal to poll download progress

- Returns `configured: false` when credentials are not set

---

### POST /api/settings/geoip/download

Trigger GeoIP database download in background.

**Authentication:** Required when sign-in is enabled.

**Response:**
```json
{
  "status": "started",
  "message": "GeoIP download started in background"
}
```

**Error Responses:**

- `400`: The MaxMind Account ID or License Key is not set (`detail`: `MaxMind license key not configured`)

**Notes:**

- Returns immediately; download runs in background

- Use `GET /api/settings/geoip/status` to poll progress (`job_status` field). `job_status` changes to `running` only when the background task starts, so the first poll can still show the previous result.

- Downloads the GeoLite2 City and ASN databases that are missing or 7 or more days old. Fresh files are kept.

- After download completes, readers are reloaded and validated automatically

---

### POST /api/settings/maxmind/validate

Validate MaxMind license key on-demand. Result is persisted to database.

**Authentication:** Required when sign-in is enabled.

**Response (valid):**
```json
{
  "configured": true,
  "valid": true,
  "error": null
}
```

**Response (invalid):**
```json
{
  "configured": true,
  "valid": false,
  "error": "Invalid"
}
```

**Response (not configured):**
```json
{
  "configured": false,
  "valid": false,
  "error": null
}
```

**Response Fields:**

- `configured`: Boolean - whether a MaxMind license key is present

- `valid`: Boolean - whether the license key passed MaxMind's validation API

- `error`: String or null - error description if validation failed (`"Invalid"`, `"Connection error"`, `"Status {code}"`)

**Notes:**

- Validates against MaxMind's `secret-scanning.maxmind.com` API with a 5-second timeout

- Result is **persisted in the database** (`system_settings` table) so it survives page refreshes and container restarts

- The `maxmind_status` field in `GET /api/settings/info` returns the last persisted result (or `null` if never checked)

- A `PUT /api/settings` that includes `maxmind_account_id`, or a `maxmind_license_key` other than `********`, clears the persisted validation result

- After any Update GeoIP run that ends with a City or ASN database file on disk, the license is stored as valid

---

### POST /api/settings/mailcow/rw-key/validate

Check that mailcow accepts the read-write API key (`MAILCOW_API_KEY_RW`) for writes, without changing anything. The Settings page calls it right after a new or changed key or mailcow URL is saved, and from the Validate button. The result is stored in the database.

**Authentication:** Required when sign-in is enabled.

**Response (accepted):**
```json
{
  "configured": true,
  "valid": true,
  "error": null
}
```

**Response (rejected):**
```json
{
  "configured": true,
  "valid": false,
  "error": "rejected",
  "http_status": 401
}
```

**Response (not configured):** `{"configured": false, "valid": false, "error": null}`. This result is not stored.

**Response Fields:**

- `configured`: Boolean - whether a read-write API key is set

- `valid`: Boolean - whether mailcow accepted the key for writes

- `error`: String or null - `"rejected"` (401: wrong or inactive key, or this server's IP is not allowed for the key), `"read_only"` (403: a read-only key), `"connection"` (mailcow not reachable), `"unexpected"` (any other answer)

- `http_status`: Integer - mailcow's status code, present when mailcow answered with an error

**Notes:**

- Sends one `POST /api/v1/edit/mlv-key-check` to mailcow. mailcow checks the key and its allowed IPs before routing, so an accepted key gets `404 route not found` and nothing is changed

- No retry: every rejected key is also a failed login for mailcow's Fail2ban

- The `mailcow_rw_key_status` field in `GET /api/settings/info` returns the last result for the current mailcow URL and key; `null` if not checked since either changed

- `PUT /api/settings` returns `mailcow_rw_key_changed: true` when the saved mailcow URL or read-write API key differs from before

- When mailcow refuses the read-write API key during an action (quarantine, queue, Fail2Ban, rate limits and other writes), the endpoint answers `502` at once, without retries, and `detail` says whether the key was rejected or is read-only and what to fix

---

### POST /api/settings/rspamd/password/validate

Check that Rspamd accepts the Rspamd password (`RSPAMD_PASSWORD`), the way the Rspamd web UI logs in, without changing anything. The Settings page calls it right after a new or changed password, Rspamd URL or mailcow URL is saved, and from the Validate button. Result is persisted to database.

**Authentication:** Required when sign-in is enabled.

**Response (rejected):**
```json
{
  "configured": true,
  "valid": false,
  "error": "rejected",
  "http_status": 403
}
```

**Response (not configured):** `{"configured": false, "valid": false, "error": null}`. This result is not stored.

**Response Fields:**

- `configured`: Boolean - whether an Rspamd password is set

- `valid`: Boolean - whether Rspamd accepted the password

- `error`: String or null - `"rejected"` (401 or 403: wrong password), `"redirected"` (a proxy answered with a redirect before Rspamd saw the password; set `RSPAMD_URL`), `"connection"` (Rspamd not reachable), `"unexpected"` (any other answer)

- `http_status`: Integer - the status code, present when the answer was an error

**Notes:**

- Sends one `GET /rspamd/auth` with the `Password` header, through the mailcow proxy or straight to `RSPAMD_URL` when it is set. An accepted password gets `200` with `"auth": "ok"`

- No retry: a wrong password is also a failed login for mailcow's Fail2ban

- The `rspamd_password_status` field in `GET /api/settings/info` returns the last result for the current address and password; `null` if not checked since either changed

- `PUT /api/settings` returns `rspamd_password_changed: true` when the saved password, Rspamd URL or mailcow URL differs from before

---

### POST /api/settings/geoip/validate

Validate GeoIP database integrity by running test IP lookups.

**Authentication:** Required when sign-in is enabled.

**Response:**
```json
{
  "valid": true,
  "city_ok": true,
  "asn_ok": true,
  "db_valid": true
}
```

**Response Fields:**

- `valid`: Boolean. `true` when the City database answered a test lookup. The ASN database does not affect it.

- `city_ok`: Boolean. The same value as `valid`.

- `asn_ok`: Boolean. The same value as `valid`; the ASN result is not reported separately.

- `db_valid`: Boolean or null. The stored validation state after the reload.

**Error Response (DB not found):**
```json
{
  "valid": false,
  "city_ok": false,
  "asn_ok": false,
  "error": "City database file not found"
}
```

**Notes:**

- Reloads readers before validation to pick up newly downloaded files

- Looks up 8.8.8.8 and 1.1.1.1; only the City lookup decides the result

- Called by the GeoIP Setup Modal as Step 3 (integrity check)

---

## SMTP & IMAP Test

### POST /api/settings/test/smtp

Test SMTP connection with detailed logging for diagnostics.

**Request:** No body required

**Response:**
```json
{
  "success": true,
  "logs": [
    "Starting SMTP connection test...",
    "Host: mail.example.com",
    "Port: 587",
    "Use TLS: True",
    "Use SSL: False",
    "Verify SSL: Automatic",
    "Relay Mode: False",
    "User: noreply@example.com",
    "Connecting to SMTP server...",
    "Connected",
    "Starting TLS...",
    "TLS established",
    "Logging in...",
    "Login successful",
    "Sending test email to admin@example.com...",
    "Test email sent successfully",
    "Connection closed",
    "SMTP test completed successfully"
  ]
}
```

**Error Response:**
```json
{
  "success": false,
  "logs": [
    "Starting SMTP connection test...",
    "Host: mail.example.com",
    "Port: 587",
    "Use TLS: True",
    "Use SSL: False",
    "Verify SSL: Automatic",
    "Relay Mode: False",
    "User: noreply@example.com",
    "Connecting to SMTP server...",
    "Connected",
    "Starting TLS...",
    "TLS established",
    "Logging in...",
    "Authentication failed: (535, b'5.7.8 Error: authentication failed')"
  ]
}
```

In the real output, the final success line starts with a check mark and each failure line with a cross mark; the examples leave the marks out.

**Response Fields:**

- `success`: Boolean indicating if test passed

- `logs`: Array of log messages showing connection attempt details

**Notes:**

- Sends a test email to the valid addresses in `ADMIN_EMAIL`, or to `SMTP_USER` when `ADMIN_EMAIL` is empty. If no valid address is left, the test fails. This test can send while normal SMTP delivery is turned off.

- Runs the full flow: connect (SSL when `SMTP_USE_SSL` is on or the port is 465, otherwise STARTTLS when `SMTP_USE_TLS` is on), log in (skipped in relay mode), send.

---

### POST /api/settings/test/imap

Test IMAP connection with detailed logging for diagnostics.

**Request:** No body required

**Response:**
```json
{
  "success": true,
  "logs": [
    "Starting IMAP connection test...",
    "Host: mail.example.com",
    "Port: 993",
    "Use SSL: True",
    "Verify SSL: Automatic",
    "User: dmarc@example.com",
    "Folder: INBOX",
    "Connecting to IMAP server...",
    "Connected using SSL",
    "Logging in...",
    "Login successful",
    "Listing mailboxes...",
    "Found 7 mailboxes:",
    "  - (\\HasNoChildren) \"/\" \"INBOX\"",
    "  - (\\HasNoChildren \\Sent) \"/\" \"Sent\"",
    "  - (\\HasNoChildren \\Drafts) \"/\" \"Drafts\"",
    "  - (\\HasNoChildren \\Junk) \"/\" \"Junk\"",
    "  - (\\HasNoChildren \\Trash) \"/\" \"Trash\"",
    "  ... and 2 more",
    "Selecting folder: INBOX",
    "Folder selected: 42 messages",
    "Searching for emails...",
    "Found 42 emails in folder",
    "Connection closed",
    "IMAP test completed successfully"
  ]
}
```

**Error Response:**
```json
{
  "success": false,
  "logs": [
    "Starting IMAP connection test...",
    "Host: mail.example.com",
    "Port: 993",
    "Use SSL: True",
    "Verify SSL: Automatic",
    "User: dmarc@example.com",
    "Folder: INBOX",
    "Connecting to IMAP server...",
    "Connected using SSL",
    "Logging in...",
    "IMAP error: [AUTHENTICATIONFAILED] Authentication failed."
  ]
}
```

As with the SMTP test, the real success and failure lines start with a check or cross mark.

**Response Fields:**

- `success`: Boolean indicating if test passed

- `logs`: Array of log messages showing connection attempt details

**Notes:**

- Runs the full flow: connect, log in, list folders (up to 5 shown), open the folder read-only, count its messages.

- Does not modify or process any emails.

---

## Export

CSV downloads use UTF-8 with a byte order mark (BOM) so spreadsheet applications can detect multilingual text when opening the file directly. Programmatic readers should decode with `utf-8-sig` to remove the BOM before parsing headers.

CSV serialization is streamed in chunks. Source rows are fetched in batches of 500 through a database cursor. The cursor and database session close when the download finishes or disconnects. The frontend still buffers the complete download before saving it.

Each export holds the newest rows first and stops at `CSV_EXPORT_LIMIT` rows (default 10,000). Each export route also answers `HEAD` with the same headers and no body.

CSV downloads are intended for spreadsheet viewing. Text with a formula-like prefix is prefixed with an apostrophe; fields are quoted and embedded quotes are escaped. Numeric values, including negative scores, retain their values. This changes only the downloaded representation, not stored messages or settings. Spreadsheet import settings vary; saving and reopening a CSV can remove text escaping. Treat exported content as untrusted when importing into other tools.

### GET /export/postfix/csv

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `search` | string or null | Unset | Substring of the log message, sender, recipient or queue ID |
| `sender` | string or null | Unset | Substring of the sender |
| `recipient` | string or null | Unset | Substring of the recipient |
| `status` | string or null | Unset | Exact Postfix status |
| `start_date` | datetime or null | Unset | Earliest log time (ISO 8601) |
| `end_date` | datetime or null | Unset | Latest log time (ISO 8601) |

Export Postfix logs to a CSV file, one row per log line.

**Response:** CSV file download

**Columns:** Time, Program, Priority, Queue ID, Message ID, Sender, Recipient, Status, Relay, Delay, DSN, Message

---

### GET /export/rspamd/csv

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `search` | string or null | Unset | Substring of the subject, SMTP sender or Message-ID |
| `sender` | string or null | Unset | Substring of the SMTP sender |
| `direction` | string or null | Unset | Exact direction |
| `min_score` | float or null | Unset | Lowest score |
| `max_score` | float or null | Unset | Highest score |
| `is_spam` | boolean or null | Unset | Only spam or only non-spam |
| `start_date` | datetime or null | Unset | Earliest log time (ISO 8601) |
| `end_date` | datetime or null | Unset | Latest log time (ISO 8601) |

Export Rspamd logs to a CSV file.

**Response:** CSV file download

**Columns:** Time, Message ID, Subject, Sender, Recipients, Score, Required Score, Action, Direction, Is Spam, Has Auth, User, IP, Size, Top Symbols

---

### GET /export/netfilter/csv

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `search` | string or null | Unset | Substring of the log message, IP or username |
| `ip` | string or null | Unset | Substring of the IP |
| `username` | string or null | Unset | Substring of the username |
| `start_date` | datetime or null | Unset | Earliest log time (ISO 8601) |
| `end_date` | datetime or null | Unset | Latest log time (ISO 8601) |

Export Netfilter logs to a CSV file.

**Response:** CSV file download

**Columns:** Time, IP, Username, Auth Method, Action, Attempts Left, Rule ID, Priority, Message

---

### GET /export/messages/csv

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `search` | string or null | Unset | Substring of sender, recipient, subject, Message-ID or queue ID |
| `sender` | string or null | Unset | Substring of the sender |
| `recipient` | string or null | Unset | Substring of the recipient |
| `direction` | string or null | Unset | Exact direction |
| `status` | string or null | Unset | Exact final status |
| `user` | string or null | Unset | Substring of the Rspamd user |
| `ip` | string or null | Unset | Substring of the Rspamd client IP |
| `start_date` | datetime or null | Unset | Earliest `first_seen` (ISO 8601) |
| `end_date` | datetime or null | Unset | Latest `first_seen` (ISO 8601) |

Export messages to a CSV file, one row per delivery leg. The filters are close to those of `GET /api/messages`, with two differences: `search` does not match the Rspamd IP or user, and `status=spam` matches only the final status `spam`.

**Response:** CSV file download

**Columns:** Time, Sender, Recipient, Subject, Direction, Status, Queue ID, Message ID, Spam Score, Is Spam, User, IP, Is Complete

---

## DMARC

`DISABLED_FEATURES=dmarc` hides the **DMARC & TLS** page and stops the IMAP import, retention cleanup and related jobs, but the `/api/dmarc/*` endpoints still answer.

### GET /api/dmarc/reports/config

Read `{ "allow_delete": false }`, reflecting `DMARC_ALLOW_REPORT_DELETE`. Report deletion is off by default.

---

### POST /api/dmarc/cache/clear

Clear the in-memory DMARC cache (it holds the domain list from `GET /api/dmarc/domains` for 5 minutes) and signal other app processes to clear theirs. No body is required. Returns `{ "status": "success", "message": "Cache cleared" }`.

---

### GET /api/dmarc/reports/all

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `page` | integer or null | Unset | Page number, at least 1. Omit it for the older unpaginated response. |
| `limit` | integer | `50` | Reports per page, 1 to 200. Used only with `page`. |
| `search` | string or null | Unset | Keeps the reports whose domain or reporter (`org_name`) contains this text, in any case. `%`, `_` and `\` match literally. Leading and trailing spaces are ignored, only the first 255 characters are used, and an empty value lists every report. |
| `sort_by` | string | `created_at` | Orders a paged request by `created_at` (import date), `type`, `domain`, `reporter`, `records` (record or policy count) or `period` (start of the report period). Domain and reporter compare in lower case. Any other value returns `422`. |
| `sort_dir` | string | `desc` | `asc` or `desc`; any other value returns `422`. |

`GET /api/dmarc/reports/all?page=1&limit=50` returns a combined page of DMARC and TLS report summaries, newest first. In paged responses, equal import timestamps are ordered by report type and then descending ID.

Paged responses contain `reports`, `total`, `allow_delete`, `page`, `limit`, `total_pages`, `sort_by`, and `sort_dir`. The order covers DMARC and TLS reports together and is applied before paging, so the next page continues it; empty values sort last, and ties fall back to the newest import, then type, then the highest ID. Without `page`, the response keeps its newest-first order and ignores `sort_by` and `sort_dir`. In both forms, `total` counts the reports of both types that match `search` (all reports when `search` is empty). Empty results return page 1 of 1. A page beyond the end is clamped to the last available page, including after deletions. Concurrent imports or deletions may shift reports between requests; reload from page 1 to refresh the history.

Each report contains `id`, `type` (`dmarc` or `tls`), `domain`, `org_name`, `begin_date`, `end_date`, `record_count`, `created_at`, and `report_id`. Unpaginated responses retain only the original top-level fields: `reports`, `total`, and `allow_delete`.

### GET /api/dmarc/reports/domains

This endpoint returns how many reports each domain has, sorted by domain name. Domain names are compared trimmed and in lower case, so `Example.com` and `example.com` count as one domain.

```json
{
  "domains": [
    {"domain": "example.com", "dmarc_reports": 42, "tls_reports": 7, "last_report": 1767312000}
  ],
  "allow_delete": false
}
```

- `dmarc_reports`, `tls_reports`: Number of stored DMARC and TLS reports for the domain

- `last_report`: Unix timestamp of the end of the domain's latest report period (DMARC or TLS), or `null`

### DELETE /api/dmarc/reports/domains/{domain}

This endpoint deletes every DMARC and TLS report of one domain, with their records and policies, in one transaction. The domain is matched the same way (trimmed, lower case). It is refused with `403` unless report deletion is turned on (`DMARC_ALLOW_REPORT_DELETE=true`, off by default), answers `400` for an empty domain or one longer than 255 characters, and `404` when the domain has no reports. Each deletion is written to the application log with the domain and the counts.

```json
{
  "status": "success",
  "domain": "example.com",
  "dmarc_reports": 42,
  "dmarc_records": 310,
  "tls_reports": 7,
  "tls_policies": 7
}
```

Reports that arrive later for the domain (from IMAP or an upload) are imported as usual.

### DELETE /api/dmarc/reports/{report_type}/{report_id}

Delete one imported report and its records/policies. `report_type` accepts `dmarc` or `tls`; `report_id` is its integer database ID.

Deletion disabled returns 403. Unknown type returns 400; a non-integer `report_id` returns 422; a missing report returns 404. Success returns `{ "status": "success", "message": "DMARC report deleted" }` (or `"TLS report deleted"`).

---

Read imported report data through the endpoints below. For protocol background and user actions, see [DMARC & TLS](HelpDocs/DMARC.md).

### GET /api/dmarc/domains

List every domain with DMARC or TLS reports, with 30-day statistics.

**Response:**
```json
{
  "domains": [
    {
      "domain": "example.com",
      "report_count": 42,
      "tls_report_count": 7,
      "first_report": 1764547200,
      "last_report": 1767312000,
      "has_dmarc": true,
      "has_tls": true,
      "tls_rpt_status": "success",
      "tls_first_report": 1764547200,
      "tls_last_report": 1767225599,
      "stats_30d": {
        "total_messages": 8234,
        "unique_ips": 89,
        "dmarc_pass_pct": 98.5,
        "tls_success_pct": 100.0,
        "tls_sessions": 1520
      },
      "failing_sources": 2,
      "dmarc_record": {"checked": true, "found": true, "status": "success", "policy": "reject"},
      "tls_rpt_record": {"checked": true, "found": true, "status": "success"},
      "on_mailcow": true
    }
  ],
  "total": 1,
  "daily": [
    {"date": "2026-01-01", "total": 310, "dmarc_pass": 305, "dmarc_fail": 5}
  ]
}
```

**Response Fields:**

- `domains`: The domains, newest `last_report` first. `total`: number of domains.

**Domain Object Fields:**

- `report_count`, `tls_report_count`: Stored DMARC and TLS reports for the domain

- `first_report`, `last_report`: Unix timestamps of the start of the first and the end of the last DMARC report period (TLS report period for a domain with only TLS reports)

- `has_dmarc`, `has_tls`: Whether the domain has DMARC or TLS reports

- `stats_30d`: `total_messages`, `unique_ips`, `dmarc_pass_pct` (aligned SPF or aligned DKIM passed, per RFC 7489), `tls_success_pct` and `tls_sessions` for reports that started in the last 30 days. The published DMARC policy is in `dmarc_record.policy`.

- `tls_first_report`, `tls_last_report`: Unix timestamps of the domain's first and last TLS report, or `null` without TLS reports

- `tls_rpt_status`: Result of the last DNS check of the domain's TLS-RPT record (`success`, `warning`, `error`, `unknown`), or `null` when the domain has not been checked. The daily DNS check covers the mailcow domains only

- `dmarc_record`: `{checked, found, status, policy}`. The domain's DMARC record from the stored DNS check, or looked up live when the domain has none (a domain that is not in mailcow). `checked` is false when it could not be read; `policy` is `none`, `quarantine` or `reject` when a record was found

- `tls_rpt_record`: `{checked, found, status}`, the same for the TLS-RPT record

- `failing_sources`: How many source IPs failed DMARC for most of their mail in the last 30 days

- `on_mailcow`: `true` when the domain is an active domain or alias domain on this mailcow server, `false` when it is not, `null` while the server's domains are not known yet. Read on every request, not cached with the list

- `stats_30d.dmarc_pass_pct` is `0` and `stats_30d.tls_success_pct` is `100` when there were no messages or TLS sessions in the last 30 days; check `stats_30d.total_messages` and `stats_30d.tls_sessions` before reading them as a rate

**Top-level field:** `daily`, messages per day across every domain in the last 30 days: `[{date, total, dmarc_pass, dmarc_fail}]`.

The list is cached for 5 minutes. Uploads, IMAP imports, deletions, retention cleanup and `POST /api/dmarc/cache/clear` clear the cache sooner.

---

### GET /api/dmarc/domains/{domain}/overview

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `days` | integer | `30` | How many days back to read, by report start date |

Read the report summary and DNS-record state for one domain. The response contains `domain`, `policy`, `daily_stats`, `totals`, `dmarc_record`, `tls_rpt_record` and `on_mailcow`.

`policy` contains `p`, `sp`, `pct`, `adkim` and `aspf` from the latest report in the period; missing tags default to `p: "none"`, `pct: 100`, `adkim: "r"`, `aspf: "r"`. It is null when there are no reports in the period. `dmarc_record` and `tls_rpt_record` are full DNS check results (`status`, `message`, `record` and more), not the short form of the domain list; `dmarc_record` also has `settings`, the parsed record tags. Daily rows use an ISO date and contain `date`, `total`, `dmarc_pass`, `dmarc_fail`, `spf_pass` and `dkim_pass`.

`totals` contains `total_messages`, `dmarc_pass`, `dmarc_fail`, `unique_ips` and `unique_reporters`, plus `dmarc_pass_pct` when reports exist. The record objects come from cached DNS checks or live checks when missing. The response does not place totals or pass percentages at the top level.

---

### GET /api/dmarc/domains/{domain}/reports

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `days` | integer | `30` | How many days back to read, by report start date |
| `page` | integer | `1` | Page of days, starting at 1 |
| `limit` | integer | `50` | Days per page |

Read DMARC report data aggregated by day, newest first. The response contains `domain`, `total`, `page`, `limit`, `pages` and `data`; `pages` is 0 when there is no data.

Each data row contains `date` (ISO date), `total_messages`, `dmarc_pass_pct`, `spf_pass_pct`, `dkim_pass_pct`, `unique_ips`, `reporters` and `reports`. Each entry in `reports` has `report_id`, `org_name`, `begin_date`, `end_date`, `volume` and `dmarc_pass_pct`. Use the daily details endpoint for its source breakdown.

---

### GET /api/dmarc/domains/{domain}/sources

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `days` | integer | `30` | How many days back to read, by report start date |
| `page` | integer | `1` | Page of source addresses, starting at 1 |
| `limit` | integer | `50` | Source addresses per page |

Read source addresses, sorted by message count, with report and GeoIP data. The response contains `domain`, `total`, `page`, `limit`, `pages` and `data`.

Each data row has `source_ip`, `country_code`, `country_name`, `country_emoji` (a display string), `city`, `asn`, `asn_org`, `total_count`, `dmarc_pass`, `dmarc_pass_pct`, `spf_pass`, `spf_pass_pct`, `dkim_pass`, `dkim_pass_pct` and `reporters`. Location values can be null. Reporter entries contain `org_name`, `count` and `dmarc_pass`.

Use source details for the envelope-from groups reported for one address.

---

### POST /api/dmarc/upload

Upload a report as multipart form field `file`; a request without it returns 422. The filename chooses the parser: a name ending in `.json`, `.json.gz` or `.json.zip` (any case) is read as TLS-RPT, anything else as DMARC.

<!-- VERIFY: plain .xml DMARC uploads are refused by services/dmarc_parser.py:78 although the upload docstring (routers/dmarc.py:1786) and the file picker (frontend/index.html accept=".xml,...") offer them. Fix the code or keep this text. -->
DMARC accepts gzip-compressed XML (filename ending in `.gz`) and ZIP files (`.zip`; the first `.xml` member is read). A plain `.xml` file is refused with 400. The DMARC extension check is case-sensitive, so `.GZ` or `.ZIP` is also refused.

An upload larger than 10 MB returns 413. A report that decompresses to more than 10 MB returns 400. Manual upload is on by default (`DMARC_MANUAL_UPLOAD_ENABLED=true`); turned off, the endpoint returns 403. Invalid reports return 400.

Success returns HTTP 200 with `status: "success"`, `report_type` (`dmarc` or `tls-rpt`), `message`, numeric database `report_id`, and `records_count` for DMARC or `policies_count` for TLS. Duplicate report IDs return HTTP 200 with `status: "duplicate"`, `report_type` and `message`.

`curl -b cookies.txt -F "file=@report.xml.gz" https://logs.example.com/api/dmarc/upload`

---

### GET /api/dmarc/domains/{domain}/reports/{report_date}/details

Read one domain's DMARC day breakdown. `report_date` is `YYYY-MM-DD`. Response fields are `domain`, `date`, `totals` and `sources`.

`totals` contains `total_messages`, `dmarc_pass`, `dmarc_pass_pct`, `spf_pass`, `spf_pass_pct`, `dkim_pass`, `dkim_pass_pct`, `unique_ips` and `reporters`. `sources` has one row per sending address and reporter, largest volume first, so `unique_ips` counts these rows, not distinct addresses. Each row has `source_ip`, `source_name`, `country_code`, `country_name`, `city`, `asn`, `asn_org`, `header_from`, `envelope_from`, `reporter`, `volume`, `dmarc_pass`, `dmarc_fail`, `spf_pass`, `dkim_pass`, `dmarc_pass_pct`, `spf_pass_pct` and `dkim_pass_pct`.

A malformed date returns 400. A day without reports currently returns 500 instead of the intended 404.

---

### GET /api/dmarc/domains/{domain}/sources/{source_ip}/details

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `days` | integer | `30` | How many days back to read, by report start date |

Read a source address for one domain across the selected days. Response fields are `domain`, `source_ip`, `source_name`, country/city/ASN fields, `totals` and `envelope_from_groups`.

Totals include message and pass counts, percentages, `unique_envelopes` and `reporters`. `envelope_from_groups` has one row per envelope-from and reporter, largest volume first, with `envelope_from`, `header_from`, `reporter`, `volume`, `dmarc_pass`, `dmarc_fail`, `spf_aligned`, `dkim_aligned`, `spf_result` and `dkim_result`. It has no daily breakdown. An address with no records in the period currently returns 500 instead of the intended 404.

---

## DMARC IMAP Auto-Import

The IMAP importer reads both DMARC and TLS report attachments. Configure it through **Settings** > **DMARC & TLS IMAP**; see [Settings](HelpDocs/Settings.md#dmarc--tls-imap). Report history is stored in the database.

### GET /api/dmarc/imap/status

Read import state even when IMAP import is disabled. Passwords are omitted.

The response has `enabled`, `configuration`, `latest_sync` and `stats_24h`. Configuration contains `host`, `port`, `user`, `folder`, `delete_after`, `interval_seconds` and `interval_minutes`, with null values while disabled.

`latest_sync` is null before a run; otherwise it contains `id`, `sync_type`, `started_at`, `completed_at`, `status`, `emails_found`, `emails_processed`, `reports_created`, `reports_duplicate`, `reports_failed` and `error_message`.

`stats_24h` contains `total_syncs`, `total_reports_created` and `total_reports_failed`. History is stored in PostgreSQL and survives app restarts.

---

### POST /api/dmarc/imap/sync

Queue a manual report import and return immediately. No body is required. IMAP import must be enabled, or the endpoint returns 400.

`{ "status": "started", "message": "IMAP import of DMARC and TLS reports started" }`

Read `GET /api/dmarc/imap/status` or `GET /api/dmarc/imap/history` for the result. The request first sets every sync run still marked `running` to `failed`, with the message "Interrupted by manual restart". If the import cannot be queued, the endpoint returns 500.

Manual and scheduled imports send the same failed-report email when some emails fail and notification SMTP is configured. Bounces and emails without reports are skipped rather than treated as report failures.

---

### GET /api/dmarc/imap/history

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `limit` | integer | `20` | Sync runs per page |
| `page` | integer | `1` | Page to return, starting at 1 |

Get history of IMAP sync operations.

**Response:**
```json
{
  "total": 43,
  "page": 1,
  "limit": 20,
  "pages": 3,
  "data": [
    {
      "id": 43,
      "sync_type": "manual",
      "status": "success",
      "started_at": "2026-01-12T10:30:00Z",
      "completed_at": "2026-01-12T10:30:05Z",
      "emails_found": 3,
      "emails_processed": 3,
      "reports_created": 2,
      "reports_duplicate": 1,
      "reports_failed": 0,
      "error_message": null,
      "failed_emails": null
    },
    {
      "id": 42,
      "sync_type": "auto",
      "status": "success",
      "started_at": "2026-01-12T08:45:20Z",
      "completed_at": "2026-01-12T08:45:21Z",
      "emails_found": 5,
      "emails_processed": 5,
      "reports_created": 4,
      "reports_duplicate": 0,
      "reports_failed": 1,
      "error_message": "1 emails failed to process",
      "failed_emails": [
        {
          "email_id": "21",
          "message_id": "",
          "subject": "FW: Report",
          "error": "No DMARC attachments found"
        }
      ]
    }
  ]
}
```

**Response Fields:**

- `total`: Number of stored sync runs. `page`, `limit`: the page returned. `pages`: number of pages, 0 when there is no history.

- `data`: Sync runs on this page, newest first

**Sync Record Fields:**

- `id`: Unique sync ID

- `sync_type`: `auto` or `manual`

- `status`: `success`, `error`, `running`, or `failed` (a run interrupted by a manual import or cleaned up as stale)

- `started_at`: ISO 8601 timestamp

- `completed_at`: ISO 8601 timestamp (null if still running)

- `emails_found`: Number of emails found

- `emails_processed`: Number of emails processed

- `reports_created`: Number of new reports created

- `reports_duplicate`: Number of duplicates skipped

- `reports_failed`: Number of failed emails

- `error_message`: Error description (null if no errors)

- `failed_emails`: Array of failed email details (null if none)

**Notes:**

- Running syncs have a null `completed_at`.

- Each entry in `failed_emails` has `email_id` (the IMAP UID), `message_id`, `subject` and `error`.

- History persists across application restarts.

---

## TLS-RPT (TLS Reporting)

### Data returned

TLS-RPT reports (RFC 8460) tell you when other mail servers failed to set up TLS while delivering to your domain, which points to MTA-STS policy or certificate problems.

---

### GET /api/dmarc/domains/{domain}/tls-rpt-record

The domain's TLS-RPT record. Comes from the cached DNS check, or a live lookup when the domain has not been checked. The DMARC & TLS page reads it from the domain overview.

**Response:**
```json
{
  "domain": "example.com",
  "tls_rpt_record": {
    "status": "success",
    "message": "TLS-RPT configured",
    "record": "v=TLSRPTv1; rua=mailto:tls-reports@example.com",
    "report_uris": ["mailto:tls-reports@example.com"],
    "warnings": []
  }
}
```

`status` is `success`, `warning` (no record published; the result then also has an `info` list with the record to publish), `error` (more than one record, or no usable `rua` address) or `unknown` (the lookup failed). `record` is null when nothing is published.

---

### GET /api/dmarc/domains/{domain}/tls-reports

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `days` | integer | `30` | How many days back to read, by report start date |
| `page` | integer | `1` | Page of reports, starting at 1 |
| `limit` | integer | `50` | Reports per page |

Read individual TLS reports, newest first by start time. The response contains `domain`, `total`, `page`, `limit`, `pages`, `totals` and `data`.

`totals.total_reports` counts every report in the period. `total_successful_sessions`, `total_failed_sessions`, `overall_success_rate` and `unique_organizations` cover only the reports on the current page; `overall_success_rate` is 100 when there are no sessions. Each data row contains `id`, `report_id`, `organization_name`, `contact_info`, `start_datetime`, `end_datetime`, `successful_sessions`, `failed_sessions`, `total_sessions`, `success_rate` and `policies`. Each policy has `policy_type`, `policy_domain`, `mx_host`, `successful_sessions`, `failed_sessions` and `failure_details`.

---

### GET /api/dmarc/domains/{domain}/tls-reports/daily

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `days` | integer | `30` | How many days back to read, by report start date |
| `page` | integer | `1` | Page of days, starting at 1 |
| `limit` | integer | `30` | Days per page |

Read TLS reports aggregated by UTC date. The response contains `domain`, `total`, `page`, `limit`, `pages`, `totals` and `data`.

Totals contain `total_days`, `total_reports`, `total_successful_sessions`, `total_failed_sessions` and `overall_success_rate`. Data rows contain `date`, `report_count`, `total_success`, `total_fail`, `total_sessions`, `success_rate`, `organizations`, `organization_count` and `reports`.

---

### GET /api/dmarc/domains/{domain}/tls-reports/{report_date}/details

Read a day's TLS report providers and policy details. `report_date` is a date in `YYYY-MM-DD` form. A day without reports returns 404. A malformed date currently returns 500 (the DMARC day endpoint returns 400 for the same input).

The response contains `domain`, `date`, `stats` and `providers`. Stats contain `total_reports`, `total_providers`, `total_success`, `total_fail`, `total_sessions` and `success_rate`. `providers` has one entry per report (a provider that sent two reports that day appears twice): `report_id`, `organization_name`, `contact_info`, `start_datetime`, `end_datetime`, `successful_sessions`, `failed_sessions`, `total_sessions`, `success_rate` and `policies`. Each policy adds `total_sessions`, `success_rate` and `failure_details`.

---

### POST /api/dmarc/upload (TLS-RPT Support)

The DMARC upload endpoint also accepts TLS-RPT reports (RFC 8460 JSON).

**Supported TLS-RPT Formats:**

- `.json.gz`: gzip-compressed JSON (the usual format)

- `.json`: plain JSON

- `.json.zip`: ZIP file; the first `.json` member is read

**Detection:** The filename decides: a name ending in `.json`, `.json.gz` or `.json.zip` (any case) is parsed as TLS-RPT; anything else is parsed as DMARC. A TLS-RPT report needs `report-id`, a valid `date-range` and at least one policy with a valid `policy-domain`, or it is refused with 400.

---

## Blacklist Monitoring

### GET /api/blacklist/summary

Get the blacklist summary for the dashboard, combined across all active monitored hosts (WAN IP, transports, relayhosts, manual hosts), not only the auto-detected server IP.

**Response:**
```json
{
  "has_data": true,
  "server_ip": "192.0.2.10",
  "status": "listed",
  "listed_count": 1,
  "total_blacklists": 60,
  "checked_at": "2026-01-25T14:00:00Z",
  "hosts": [
    {
      "hostname": "192.0.2.10",
      "source": "system",
      "status": "listed",
      "listed_count": 1,
      "checked_at": "2026-01-25T14:00:00Z"
    },
    {
      "hostname": "198.51.100.20",
      "source": "relayhost:smtp.example.com",
      "status": "clean",
      "listed_count": 0,
      "checked_at": "2026-01-25T14:00:00Z"
    }
  ],
  "hosts_total": 2,
  "hosts_listed": 1
}
```

**Response Fields:**

- `has_data`: `true` when at least one host has a check fresher than 24 hours

- `server_ip`: The auto-detected WAN IP (kept for backward compatibility); falls back to the single monitored host when unavailable

- `status`: `listed` if any host is listed, else `error` if any fresh check errored, else `clean` if at least one host has fresh data, else `unknown`

- `listed_count` / `total_blacklists`: Sums across hosts with fresh (under 24h) data

- `checked_at`: Most recent check across all hosts

- `hosts`: One entry per active monitored host. A host's `status` is `unknown` and its `listed_count` is `0` when its latest check is older than 24 hours

- `hosts_total`: Number of active monitored hosts

- `hosts_listed`: Number of hosts currently listed (fresh data only)

---

### Ignored blocklists

A blocklist can be ignored for every monitored address (for example UCEPROTECT Level 3, which lists whole ranges). It is still checked and shown, but a listing on it is not counted and sends no alert. Every response that carries per-list `results` marks each entry with `"ignored": true|false`, and `listed_count` and `status` leave ignored listings out. `ignored_listed_count` says how many listings were left out. The stored check is never changed, so un-ignoring takes effect at once.

### GET /api/blacklist/ignored

```json
{ "lists": [{ "name": "UCEPROTECT Level 3", "zone": "dnsbl-3.uceprotect.net" }] }
```

### PUT /api/blacklist/lists/{zone}/ignore

**JSON fields:**

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `ignored` | boolean | Required | `true` to ignore the blocklist, `false` to count it again |

**Request:**
```json
{ "ignored": true }
```

**Response:**
```json
{ "zone": "dnsbl-3.uceprotect.net", "name": "UCEPROTECT Level 3", "ignored": true }
```

Returns `404` for a zone that is not one of the checked blocklists.

---

### GET /api/blacklist/config

Read the server-IP check cache metadata. It returns `total_blacklists`, `cache_ttl_hours` (24), `cache_valid`, `last_check`, `server_ip`, `listed_count` and `status`.

The check fields can be null before a saved result exists. Monitoring-source settings and recipient addresses are not part of this response.

---

### GET /api/blacklist/monitored

Read every active monitored host, reconciling the saved list with the enabled server, transport, relayhost and manual sources first. The response contains a `hosts` array.

Each host has `hostname`, `source`, `last_seen`, `has_data` and `status`. When a saved check exists, it also has `listed_count`, `total_blacklists`, `checked_at`, `cache_valid` and per-list `results`. Ignored-list handling adjusts the displayed totals and adds ignore metadata.

`has_data` means a saved check exists; inspect `cache_valid` to determine whether it is within the 24-hour cache lifetime. A host with no check has `status: "unknown"`. This route does not include an `active` field in each result.

---

### POST /api/blacklist/check

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `host` | string | Unset | Host name or IP to check; omit it to check all monitored hosts in the background |
| `force` | boolean | `false` | Check again even when a result from the last 24 hours exists |

Start a manual blacklist check.

**Response (batch mode, no `host`):**
```json
{
  "status": "started",
  "message": "Background check started for all hosts"
}
```

**Response (Single Host):** Returns the check result with `server_ip`, `checked_at`, `status`, the per-list `results` and the `total_blacklists`, `listed_count`, `clean_count`, `error_count` and `timeout_count` totals. Cached responses can include cache metadata. Hostname input first tries an IPv4 lookup; a lookup failure leaves the hostname for the checker. Checker exceptions produce HTTP 200 with `status: "error"` and an `error` message, so inspect the body.

---

### GET /api/blacklist/progress

Get the progress of the current blacklist check batch.

**Response:**
```json
{
  "in_progress": true,
  "current": 4,
  "total": 150,
  "current_blacklist": "Spamhaus ZEN",
  "percent": 2
}
```

- `current`: Global progress counter across all hosts.

- `total`: Total items to check (Number of Hosts * Number of Blacklists).

- `percent`: Integer percentage (0-100).

---

## Reporting

### GET /api/system/summary

Read the data used by the weekly summary email. The response contains:

| Field | Content |
| --- | --- |
| `timestamp` | Time the summary was generated, in UTC ISO format. |
| `traffic` | Mailbox traffic totals for the last seven days, with the same fields as `GET /api/mailbox-stats/summary`. |
| `system` | Total and active counts for domains, mailboxes and aliases, from `GET /api/status/mailcow-info`. |
| `storage` | `disk`, `used`, `total` and `used_percent`, from mailcow's mail-storage status. |
| `blacklist` | `status`, `listed_count`, `total_hosts` and the monitored `hosts` list. |
| `top_failures` | Up to five active mailboxes with failed outgoing messages, selected from the first 20 results ordered by failure rate. |
| `dns_issues` | Active domains with SPF, DKIM or DMARC issues. Each entry has `domain` and an `issues` array. |
| `queue` | An object with the current queue `count`. |
| `quarantine` | An object with the current quarantine `count`. |

Queue and quarantine counts fall back to zero if their mailcow read fails.

---

### POST /api/system/summary/email

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `force` | boolean | `false` | Send even when the weekly summary is turned off |

Send the weekly summary email now. The email is built and sent in the background after the response.

**Response:**
```json
{
  "status": "queued",
  "message": "Weekly summary email generation started"
}
```

With the weekly summary turned off and no `force`, the response is `{ "status": "skipped", "reason": "Weekly summary disabled" }`.

---

## Error Responses

Most errors are JSON with a `detail` field. Each endpoint section lists its own codes.

### 400 Bad Request

```json
{
  "detail": "Invalid parameter value"
}
```

### 404 Not Found

```json
{
  "detail": "Resource not found"
}
```

### 401 Unauthorized

Returned by the authentication middleware when authentication is enabled and the request has no valid session or Basic Auth credentials. The body is plain text, not JSON: `Authentication required`, or `Incorrect username or password` for wrong Basic Auth credentials. There is no `WWW-Authenticate` header, so browsers do not show their own password prompt.

### 403 Forbidden

A POST, PUT, PATCH or DELETE whose `Origin` (or, without it, `Referer`) names another host is rejected before it reaches the endpoint, whether or not authentication is enabled:

```json
{
  "detail": "This request came from another site and was rejected."
}
```

Requests with neither header (curl, scripts) pass. Origins listed exactly in `CORS_ALLOWED_ORIGINS` also pass. Some endpoints use 403 for their own reasons too, such as a disabled feature or a setting locked by ENV; their sections say so.

### 422, 429 and 503

422 reports request validation errors (wrong type, out-of-range value). 429 means the client is locked out after failed Basic Auth attempts (`Retry-After: 900`). 503 can mean the session store is full, upstream data is unavailable, or no read-write API key is configured, depending on the endpoint. Some endpoints return an `error` field with HTTP 200; check it.

### 500 Internal Server Error

```json
{
  "detail": "Internal server error"
}
```

An unexpected exception that no endpoint handled returns `{ "error": "Internal server error", "detail": "An error occurred" }` instead. With `DEBUG=true`, `detail` contains the exception text.

### 502 Bad Gateway

```json
{
  "detail": "mailcow did not answer. Try again in a moment."
}
```

Most failed mailcow API calls return 502. When mailcow rejects the read-write API key, the 502 `detail` says so, and the app does not retry. Some status reads return 503 or fallback data instead.

---

## System Status

### GET /api/status/container-logs

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `lines` | integer | `100` | Number of lines, 10 to 1000 |

Read the last application log lines from `/app/data/container.log`. The response contains a `logs` array. These are the viewer's own application logs, rather than mailcow service logs.

A missing file or read failure returns an explanatory line in that array. The route does not access the Docker daemon or stream arbitrary container stdout.

---

## Raw Logs (Live Log Viewer)

Endpoints behind the **Logs** page. A background worker collects raw logs from the mailcow services, stores them in the `raw_service_logs` table and streams new lines over a WebSocket.

**Supported Services:** `acme`, `api`, `autodiscover`, `dovecot`, `netfilter`, `postfix`, `ratelimited`, `rspamd-history`, `sogo`, `watchdog`

### GET /api/raw-logs/services

List the services selected for the Logs page, with metadata and the number of stored lines for each.

**Response:**
```json
{
  "services": [
    {
      "id": "postfix",
      "name": "Postfix",
      "icon": "mail",
      "description": "Mail transfer agent logs",
      "has_smart_filters": true,
      "log_count": 1523
    },
    {
      "id": "dovecot",
      "name": "Dovecot",
      "icon": "inbox",
      "description": "IMAP/POP3 server logs",
      "has_smart_filters": false,
      "log_count": 980
    }
  ],
  "ws_connections": 1,
  "raw_logs_enabled": true
}
```

`ws_connections` is the number of open live streams. `raw_logs_enabled` mirrors the raw-log collection setting.

---

### GET /api/raw-logs/{service}

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `page` | integer | `1` | Page number, at least 1 |
| `limit` | integer | `200` | Results per page, 1 to 1000 |
| `search` | string or null | Unset | Case-insensitive substring of the message. For `rspamd-history`, of the subject, SMTP or MIME sender, IP or action. |
| `program` | string or null | Unset | Substring of the program name |
| `start_date` | string or null | Unset | Earliest time (ISO 8601); an unparsable value is ignored |
| `end_date` | string or null | Unset | Latest time (ISO 8601); an unparsable value is ignored |
| `order` | string | `desc` | `asc` for oldest first; anything else is newest first |
| `smart_filter` | string or null | Unset | Comma-separated smart filter IDs (Postfix only); a line matching any of them is returned |

Read stored log lines for one service. An unknown service returns 404. The response contains `data`, `page`, `limit`, `total`, `pages` and `service`.

Each data row contains the original mailcow log object, plus `_id`, `_service` and `_stored_at`.

`GET /api/raw-logs/postfix?page=1&limit=200&search=reject&order=desc`

---

### GET /api/raw-logs/{service}/smart-filters

Read smart-filter definitions. Services other than `postfix` return an empty filters list.

The response contains `service` and `filters`. Each filter has `id`, `label`, `pattern`, `field`, `color` and `description`. `field` is `message` or `program`; `pattern` is a single string.

Postfix filter IDs are `postscreen`, `noqueue_reject`, `dnsbl`, `pregreet`, `sender_restrict`, `recipient_restrict`, `relay_restrict` and `connections`.

---

### GET /api/raw-logs/worker-status

Read raw-log settings and worker state. The response contains `enabled`, `fetch_interval`, `fetch_count`, `retention_days`, `services`, `jobs` and `ws_connections`.

`jobs` contains the raw fetch and cleanup job status. `ws_connections` maps service names to active stream counts. `services` is the Logs page's configured selection; required services from other pages may also be collected.

---

### GET /api/raw-logs/ws-token

Issue a one-time token for the live log WebSocket. Only an authenticated caller can get one. The token expires after 30 seconds and works once.

**Response:**
```json
{
  "token": "a1b2c3d4e5f6...",
  "ttl": 30
}
```

Tokens are bound to the requesting session. A token issued before sign-out, session expiry or a change to the sign-in settings can no longer open a stream.

---

### WebSocket: /ws/raw-logs

Live log streaming. The server pushes new lines as the background worker stores them.

**Authentication Flow:**
1. Call `GET /api/raw-logs/ws-token` to get a one-time token
2. Connect to the WebSocket with the token as a query parameter
3. The server checks and consumes the token
4. With authentication disabled, no token is needed

**Connection URL:**
```
wss://your-server/ws/raw-logs?service=postfix&token=<one-time-token>
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `service` | string | Initial service to stream (default `postfix`). A service not selected for the Logs page falls back to the first selected one. |
| `token` | string | One-time token from `/api/raw-logs/ws-token` |

**Client to Server Messages:**

Switch to a different service:
```json
{"action": "subscribe", "service": "dovecot"}
```

**Server to Client Messages:**

Connection confirmed:
```json
{
  "type": "connected",
  "service": "postfix",
  "message": "Connected to postfix log stream"
}
```

New log entries (pushed automatically when worker ingests new data):
```json
{
  "type": "new_logs",
  "service": "postfix",
  "entries": [
    {
      "time": "1776189085",
      "program": "postfix/smtpd",
      "priority": "info",
      "message": "connect from unknown[192.0.2.10]"
    }
  ],
  "timestamp": "2026-04-15T01:21:25Z"
}
```

Authentication error (connection will be closed with code 4401):
```json
{
  "type": "error",
  "message": "Authentication required"
}
```

**Close Codes:**

| Code | Meaning |
|------|---------|
| `4401` | Authentication required - invalid or missing token |
| `1000` | Normal closure |
| `4001` | The session ended or authentication settings revoked it. |
| `1013` | A client could not receive within the send time budget. |

**Notes:**

- Only entries for the current service are streamed. Use the `subscribe` action to change services without reconnecting. The server answers with `type: "subscribed"`, or with `type: "error"` for a service that is not selected.

- The server also broadcasts `service_counts` messages with updated per-service counts.

- The web interface reconnects after a drop (3-second delay), except after 4401.

- A cross-site `Origin` or `Referer` is refused before the upgrade with HTTP 403. A stream tied to a session closes when that session ends or is revoked.

---

## Spam Filter

The Spam Filter feature has two parts:
1. **Rspamd Maps**: an editor for Rspamd map files
2. **Suppressions**: a recipient suppression list with automatic bounce detection

### Rspamd Maps

#### GET /api/rspamd/config

Read connection and feature prerequisites:

`{ "rspamd_configured": true, "rw_key_configured": true, "suppression_enabled": false, "suppression_configured": false }`

`rspamd_configured` means a password is set. `rw_key_configured` means a read-write API key is set. `suppression_configured` requires suppression enabled and a read-write API key; these flags do not validate the credentials.

---

#### GET /api/rspamd/maps

List known Rspamd maps and available metadata. The response is an object with `configured` and `maps`, plus `rw_key_configured` when connected.

With no Rspamd password, `configured` is false and `message` explains what to add. A connection failure can return `configured: true`, an `error`, and the known map metadata with HTTP 200. Inspect that error before treating the list as live data.

Each entry includes `filename`, `name`, `category`, `description` and `supports_regex`; suppression-managed maps also have `managed_by_suppression`. Connected entries add `map_id`, `loaded`, `editable` and `rspamd_description`. Use only filenames returned by this endpoint; unknown map filenames return 404.

---

#### GET /api/rspamd/maps/{filename}

Read the content of a specific Rspamd map file.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `filename` | string | Map filename (e.g., `global_smtp_from_whitelist.map`) |

**Response:** `{ "filename": "global_smtp_from_whitelist.map", "content": "/^alice@example\\.com$/i", "entry_count": 1 }`

The response can also include map `metadata`. A known map not yet loaded returns empty content, zero entries and a message. An unknown filename returns 404, a missing Rspamd password 400, and an Rspamd failure 502.

---

#### PUT /api/rspamd/maps/{filename}

**JSON fields:**

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `content` | string | Required | The whole new map, one entry per line; lines starting with `#` are comments |

Replace the content of an Rspamd map through the mailcow API. Needs a read-write API key: without one, the endpoint returns 403. An unknown filename returns 404; a mailcow failure returns 502.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `filename` | string | Map filename to update |

**Request Body:**
```json
{
  "content": "user@example.com\nadmin@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "filename": "global_smtp_from_whitelist.map",
  "entry_count": 2,
  "normalized_entries": 2,
  "content": "/^user@example\\.com$/i\n/^admin@example\\.com$/i",
  "warnings": [],
  "api_response": []
}
```

Before saving, bare addresses are converted into anchored, escaped regexp entries; `normalized_entries` counts the converted lines and `content` is what was saved. Warnings do not block the save. Invalid entries return 400 with a `detail` object containing `message` and `validation_errors`.

---

#### POST /api/rspamd/validate

**JSON fields:**

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `content` | string | Required | Map content to check |
| `filename` | string or null | Unset | Accepted but not used |

Check map entries (including regexp syntax) without saving. Unlike the save, this check does not convert bare addresses first.

**Request Body:**
```json
{
  "content": "/^alice@example\\.com$/i\n/invalid[/",
  "filename": "global_smtp_from_whitelist.map"
}
```

**Response:**
```json
{
  "valid": false,
  "entry_count": 2,
  "errors": [
    {
      "line": 2,
      "content": "/invalid[/",
      "severity": "error",
      "error": "Invalid regex: unterminated character set at position 7"
    }
  ],
  "warnings": []
}
```

---

### Suppressions

#### GET /api/suppressions

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `page` | integer | `1` | Page number, at least 1 |
| `per_page` | integer | `50` | 1 to 200 |
| `search` | string or null | Unset | Case-insensitive substring of the address, the notes or the last bounce message |
| `type_filter` | string or null | Unset | `email` or `domain`; other values are ignored |
| `reason_filter` | string or null | Unset | `hard_bounce`, `soft_bounce`, `deferred_stuck`, `rejected` or `manual`; other values are ignored |
| `active_filter` | string or null | Unset | `true` (active), `false` (inactive) or `expired` (inactive with a past expiry) |
| `sort_by` | string | `created_at` | `email`, `reason`, `bounce_count`, `created_at` or `expires_at` |
| `sort_dir` | string | `desc` | `asc` or `desc` |

List suppression entries with pagination, search, and filters.

**Response:**
```json
{
  "items": [
    {
      "id": 1,
      "email": "bounce@example.com",
      "type": "email",
      "reason": "hard_bounce",
      "source": "auto",
      "notes": null,
      "bounce_count": 3,
      "hard_bounce_count": 2,
      "soft_bounce_count": 1,
      "last_bounce_dsn": "5.1.1",
      "last_bounce_message": "User unknown",
      "active": true,
      "synced_to_rspamd": true,
      "expires_at": "2026-05-01T00:00:00Z",
      "is_expired": false,
      "expires_in": {
        "days": 11,
        "hours": 5,
        "total_seconds": 968400,
        "human": "11 days"
      },
      "created_at": "2026-04-20T10:00:00Z",
      "updated_at": "2026-04-20T10:00:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "per_page": 50,
  "total_pages": 1
}
```

**Notes:**

- `expires_at`: `null` means permanent block (never expires)

- `expires_in`: Only present when `expires_at` is set and not expired

- `is_expired`: `true` when `expires_at` is in the past

---

#### GET /api/suppressions/stats

Read suppression totals. Response keys are `total`, `active`, `expired`, `hard_bounce`, `soft_bounce`, `rejected`, `manual`, `pending_sync` and `auto_detected`. The reason counts are top-level fields, not a by_reason object.

---

#### GET /api/suppressions/config

Read the suppression settings and connection prerequisites. The response contains:

- `suppression_enabled`, `suppression_auto_detect`, `suppression_rspamd_sync`.

- `suppression_whitelist_domains` (the configured comma-separated string).

- `suppression_hard_bounce_action`, `suppression_soft_bounce_action`, `suppression_soft_bounce_threshold`.

- `suppression_base_expiry_days`, `suppression_max_expiry_days`.

- `rspamd_configured`, `rw_key_configured`, `is_fully_configured`.

`is_fully_configured` checks suppression enabled plus the read-write API key; check `rspamd_configured` separately for map sync.

---

#### POST /api/suppressions

**JSON fields:**

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `email` | string | Required | An address, a domain, or a `/regex/` pattern; stored in lower case |
| `type` | string | `email` | `email` or `domain` |
| `reason` | string | `manual` | `hard_bounce`, `soft_bounce`, `rejected` or `manual` |
| `notes` | string or null | Unset | Free text |
| `permanent` | boolean | `true` | `true` never expires; `false` uses `expires_at` |
| `expires_at` | string or null | Unset | Expiry (ISO 8601), used only when `permanent` is `false` |

Create a new suppression entry.

**Request Body:**
```json
{
  "email": "user@example.com",
  "type": "email",
  "reason": "manual",
  "notes": "Repeated bounces",
  "permanent": true,
  "expires_at": null
}
```

**Response:** `200 OK` with the created suppression object (same format as a list item)

**Error Responses:**

- `409 Conflict`: Email already exists in suppression list

- `422 Unprocessable Entity`: Validation error (invalid email/type/reason)

**Notes:**

- Domain type entries are stored as regex patterns (e.g., `/.+@example\.com/i`)

- Regex patterns (starting with `/`) bypass email format validation

- When written to Rspamd, a regex pattern is anchored as a whole (`/^(?:pattern)$/i`). Entries created automatically (`source: auto`, from bounces and the deferred queue cleanup) are always written as the exact address, even when they look like a pattern

- If `permanent=false` and no `expires_at` is provided, the entry expires after `SUPPRESSION_BASE_EXPIRY_DAYS`. An unparsable `expires_at` returns 400.

- After saving, the app also tries to remove matching messages from the mail queue.

- Re-adding an inactive entry reactivates it as a permanent manual entry. An existing active entry returns 409.

---

#### PUT /api/suppressions/{suppression_id}

**JSON fields:**

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `active` | boolean or null | Unset | Turn the entry on or off |
| `notes` | string or null | Unset | Free text |
| `expires_at` | string or null | Unset | New expiry (ISO 8601); `"null"` or `""` makes the entry permanent |

Update an existing suppression entry.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `suppression_id` | integer | Suppression entry ID |

**Request Body:**
```json
{
  "active": true,
  "notes": "Updated notes",
  "expires_at": "null"
}
```

**Notes:**

- All fields are optional; only the fields you send are updated

- Setting `expires_at` to `"null"` or `""` clears the expiry (permanent block)

- Sending `active` sets `synced_to_rspamd = false` to trigger a re-sync

- An unknown ID returns 404; an unparsable `expires_at` returns 400. The response is the updated entry.

---

#### DELETE /api/suppressions/{suppression_id}

Permanently delete a suppression entry. An unknown ID returns 404.

**Response:**
```json
{
  "deleted": true,
  "email": "user@example.com",
  "was_active": true
}
```

---

#### POST /api/suppressions/import

Bulk import suppressions from CSV data.

**Request Body:** Multipart form with the file in the `file` field. A filename that does not end in `.csv` returns 400.

**CSV Format:**
```csv
email,type,reason,notes
user@example.com,email,manual,Imported entry
/.+@spam\.com/i,domain,manual,Domain block
```

**Response:**
```json
{
  "imported": 10,
  "skipped": 2,
  "errors": ["Row 5: Invalid email format"]
}
```

---

#### GET /api/suppressions/export

Export all suppressions as CSV download. The final `_csv_escape_v1` column lists which cells received a text prefix. Keep this column when importing the file back into the application: the importer restores those values automatically. Files without this column are still accepted and are never unescaped. Files with a header row map columns by name; files without one use the four columns `email,type,reason,notes`. Imports create active, unsynced entries with source `import`; this is a list transfer, not a backup of counts or sync state.

**Response:** CSV file download with headers `email,type,reason,source,notes,bounce_count,hard_bounces,soft_bounces,active,expires_at,created_at,_csv_escape_v1`

---

#### POST /api/suppressions/sync

Manually trigger sync of active suppressions to Rspamd's `global_rcpt_blacklist.map`.

**Response:**
```json
{
  "success": true,
  "synced": 120,
  "message": "Synced 120 entries to Rspamd"
}
```

**Notes:**

- Only active, non-expired entries are synced

- Managed entries are placed between markers in the map file

- Manual entries above the markers are preserved

- Needs a read-write API key (403 without one) and `RSPAMD_PASSWORD` (400 without it). A mailcow failure returns 502.

---

## Quarantine Auto-Rules

Manage rules that release or delete quarantined messages automatically. Every endpoint in this section, including the rule list and the action history, needs a read-write API key (`MAILCOW_API_KEY_RW`) and returns 403 without one.

### GET /api/quarantine/rules

List all quarantine rules, delete rules first, then newest first.

**Response:**
```json
{
  "total": 2,
  "data": [
    {
      "id": 1,
      "name": "Allow billing emails",
      "match_type": "sender",
      "match_value": "billing@example.com",
      "is_regex": false,
      "action": "release",
      "enabled": true,
      "hit_count": 42,
      "last_hit_at": "2026-04-21T10:30:00Z",
      "notes": "Trusted billing sender",
      "created_at": "2026-04-20T08:00:00Z",
      "updated_at": "2026-04-21T10:30:00Z"
    }
  ]
}
```

**Response Fields:**

- `match_type`: One of `sender`, `sender_domain`, `recipient`, `subject`

- `is_regex`: Whether `match_value` is a regex pattern

- `action`: `release` (deliver to inbox) or `delete` (permanently remove)

- `hit_count`: Number of quarantine items matched by this rule

- `last_hit_at`: Timestamp of the last match

---

### POST /api/quarantine/rules

**JSON fields:**

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `name` | string | Required | 1 to 255 characters |
| `match_type` | string | Required | `sender`, `sender_domain`, `recipient` or `subject` |
| `match_value` | string | Required | 1 to 500 characters |
| `is_regex` | boolean | `false` | Treat `match_value` as a regular expression |
| `action` | string | Required | `release` or `delete` |
| `notes` | string or null | Unset | Free text |

Create a new quarantine rule.

**Request Body:**
```json
{
  "name": "Block spam domain",
  "match_type": "sender_domain",
  "match_value": "example.net",
  "is_regex": false,
  "action": "delete",
  "notes": "Known spam source"
}
```

**Response:** The created rule object (same format as GET response)

**Error Responses:**

- `400 Bad Request`: Invalid `match_type` or `action`, an invalid regex, or a regex with nested repetition such as `(a+)+` (refused because it can take very long on some messages)

- `403 Forbidden`: No read-write API key configured

---

### PUT /api/quarantine/rules/{id}

**JSON fields:**

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `name` | string or null | Unset | 1 to 255 characters |
| `match_type` | string or null | Unset | `sender`, `sender_domain`, `recipient` or `subject` |
| `match_value` | string or null | Unset | 1 to 500 characters |
| `is_regex` | boolean or null | Unset | Treat `match_value` as a regular expression |
| `action` | string or null | Unset | `release` or `delete` |
| `enabled` | boolean or null | Unset | Turn the rule on or off |
| `notes` | string or null | Unset | Free text |

Update an existing quarantine rule. Only provided fields are updated.

**Request Body (partial update):**
```json
{
  "name": "Updated name",
  "enabled": false
}
```

**Response:** The updated rule object

**Error Responses:**

- `404 Not Found`: Rule not found

- `400 Bad Request`: Invalid field values

---

### DELETE /api/quarantine/rules/{id}

Delete a quarantine rule permanently.

**Response:**
```json
{
  "success": true,
  "message": "Rule 'Block spam domain' deleted"
}
```

---

### POST /api/quarantine/rules/{id}/toggle

Turn a rule on or off.

**Response:** The updated rule object with `enabled` switched. An unknown ID returns 404 (also for `DELETE`).

---

### POST /api/quarantine/rules/test

Dry-run all rules (enabled and disabled) against the current quarantine. Nothing is changed. With no rules or an empty quarantine, the response has zero counts and a `message`.

**Response:**
```json
{
  "total_quarantine": 15,
  "total_matches": 3,
  "matches": [
    {
      "quarantine_id": "12345",
      "sender": "spam@example.org",
      "recipient": "user@example.com",
      "subject": "You won a prize!",
      "rule_id": 1,
      "rule_name": "Block example.org",
      "action": "delete",
      "rule_enabled": true
    }
  ]
}
```

**Response Fields:**

- `rule_enabled`: `true` if the rule is active, `false` if disabled (match shown but won't execute)

- Results include matches from disabled rules so users can test before enabling

**Notes:**

- Delete rules are checked before release rules (delete always wins)

- Each quarantine item is matched against the first matching rule only

- No quarantine items are modified

---

### GET /api/quarantine/rules/logs

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `limit` | integer | `50` | Entries to return, at most 200 |
| `offset` | integer | `0` | Entries to skip, 0 or more |
| `rule_id` | integer or null | Unset | Only actions of this rule |

Get quarantine rule action history (paginated).

**Response:**
```json
{
  "total": 100,
  "data": [
    {
      "id": 1,
      "rule_id": 2,
      "rule_name": "Block spam domain",
      "action": "delete",
      "quarantine_id": "12345",
      "sender": "spam@example.org",
      "recipient": "user@example.com",
      "subject": "Buy now!",
      "matched_field": "sender_domain",
      "matched_value": "example.org",
      "created_at": "2026-04-21T10:30:00Z"
    }
  ]
}
```

**Notes:**

- Logs are automatically pruned based on `QUARANTINE_RULES_LOG_RETENTION_DAYS` (default: 30)

- Each entry is one action the scheduled job took

---

## Security Alerts (Anomaly Detection)

Alerts raised by anomaly detection (outbound volume spikes, authentication-failure bursts) and by SMTP abuse protection. Unacknowledged alerts appear in the Dashboard's **Needs attention** panel.

### GET /api/security-alerts

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `acknowledged` | boolean or null | Unset | `true` for acknowledged alerts only, `false` for unacknowledged only; omit for all |
| `limit` | integer | `50` | Most alerts to return, 1 to 500 |

List security alerts, newest first. `enabled` reflects `ANOMALY_DETECTION_ENABLED` only; alerts are still listed and can be acknowledged when it is off. `unacknowledged_count` counts every unacknowledged alert, whatever the filter and limit. `severity` is `warning` or `critical`.

**Response:**
```json
{
  "enabled": true,
  "unacknowledged_count": 2,
  "alerts": [
    {
      "id": 12,
      "alert_type": "volume_spike",
      "severity": "critical",
      "subject": "user@example.com",
      "title": "Outbound volume spike: user@example.com",
      "detail": "Mailbox user@example.com sent 240 messages in the last 15 minutes...",
      "metric_value": 240.0,
      "baseline_value": 4.2,
      "acknowledged": false,
      "created_at": "2026-07-14T09:12:00Z"
    }
  ]
}
```

**Alert types:** `volume_spike`, `auth_failure_burst`, `smtp_abuse_block`

### GET /api/security-alerts/{alert_id}/activity

The history behind an alert, for its **Show activity** window. For a `volume_spike` it counts the mailbox's outbound messages; for any other type, including `auth_failure_burst` and `smtp_abuse_block`, the failed logins of the alert's subject.

- `buckets`: `[{start, count}]` per `bucket_minutes` (15) from `baseline_days` before the alert to two hours after it; the first bucket starts on the hour

- `window_minutes`, `baseline_days`: the check window and baseline period the alert was raised with, not today's settings. For a `volume_spike` or an `auth_failure_burst` they are read from the alert's detail; for an `smtp_abuse_block`, the window comes from its abuse action. `window_minutes` is `null` when it is not known. `baseline_days` is today's setting when the alert does not name it
- `around`: from the check window (an hour when it is `null`) before the alert to an hour after it (`from`, `to`): `total`, and for a volume spike `recipient_domains`, `results` and `subjects`, for a burst `addresses`, `countries` and `networks`, each `[{name, count}]`, most first. Each list holds up to 6 entries (`subjects` up to 5)

- `alert`: the alert itself

Returns 404 for an unknown alert.

### POST /api/security-alerts/{alert_id}/acknowledge

Mark a single alert as acknowledged, which removes it from the Dashboard's **Needs attention** panel. Returns `{ "status": "success" }`; an unknown ID returns 404.

### POST /api/security-alerts/acknowledge-all

Acknowledge every outstanding alert.

**Response:**
```json
{ "status": "success", "acknowledged": 3 }
```

---

## SMTP Abuse Protection

Automatic and manual control of outbound (SMTP) access per mailbox. Receiving over IMAP is never affected.

The read endpoints (`GET status`, `GET whitelist`, `GET history`) work without a read-write API key and with the feature off. The write endpoints return `403` when `SMTP_ABUSE_ENABLED=false` and `503` when `MAILCOW_API_KEY_RW` is not configured.

### GET /api/smtp-abuse/status

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `limit` | integer | `200` | Most mailboxes to count by outbound volume, 1 to 1000; mailboxes this system blocked are always included |

Current outbound activity per mailbox, block state and whitelist. Mailboxes are sorted by `message_count`, highest first. `over_threshold` means strictly above `threshold`. `smtp_access` is `true` when mailcow's state could not be read.

**Response:**
```json
{
  "enabled": true,
  "rw_key_configured": true,
  "threshold": 100,
  "window_minutes": 60,
  "unblock_grace_minutes": 60,
  "mailboxes": [
    {
      "email": "user@example.com",
      "message_count": 152,
      "outbound_count": 152,
      "over_threshold": true,
      "whitelisted": false,
      "smtp_access": false,
      "blocked_by_protection": true
    }
  ],
  "whitelist": ["newsletter@example.com"]
}
```

**Notes:**

- `blocked_by_protection` marks mailboxes this system blocked. Mailboxes with SMTP turned off in mailcow for another reason (for example an incoming-only DMARC report mailbox) are left out.

### GET /api/smtp-abuse/whitelist

Active whitelist entries. Whitelisted mailboxes are never blocked automatically.

**Response:**
```json
[ { "email": "newsletter@example.com", "notes": "Marketing sender", "active": true } ]
```

### POST /api/smtp-abuse/whitelist

**JSON fields:**

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `email` | string | Required | Address to whitelist; trimmed and lowercased; up to 254 characters |
| `notes` | string or null | Unset | Note stored with the entry; replaces any earlier note |

Add (or re-activate) a single whitelist entry.

**Request Body:**
```json
{ "email": "newsletter@example.com", "notes": "Marketing sender" }
```

Returns `{ "email": "newsletter@example.com", "active": true }`. An invalid address returns 422.

### PUT /api/smtp-abuse/whitelist

**JSON fields:**

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `emails` | array of strings | `[]` | Complete list of addresses to keep active, at most 5000 |

Replace the whole whitelist (used by the one-address-per-line editor in the UI). Addresses are lowercased and blank entries are skipped. An invalid address, or more than 5000 entries, returns `422`. Entries that stay on the list keep their notes.

**Request Body:**
```json
{ "emails": ["newsletter@example.com", "monitoring@example.com"] }
```

**Response:**
```json
{ "active": ["monitoring@example.com", "newsletter@example.com"], "count": 2 }
```

### DELETE /api/smtp-abuse/whitelist/{email}

Deactivate a whitelist entry. Returns `{ "email": "...", "active": false }`, or `404` if the address is not on the list.

### POST /api/smtp-abuse/mailboxes/{email}/block

Disable SMTP for a mailbox immediately. Also revokes its app passwords (when `SMTP_ABUSE_REVOKE_APP_PASSWORDS=true`), records a security alert, and notifies the operator and the mailbox owner (the owner only when notification SMTP is configured). A manual block does not check the whitelist. If mailcow refuses the change (for example, the address is an alias), the endpoint returns 500; if the mailcow request fails, 502. The same errors apply to unblock.

**Response:**
```json
{
  "email": "user@example.com",
  "smtp_access": false,
  "app_passwords_revoked": 2,
  "message_count": 152
}
```

### POST /api/smtp-abuse/mailboxes/{email}/unblock

Re-enable SMTP for a mailbox. Starts the grace period (`SMTP_ABUSE_UNBLOCK_GRACE_MINUTES`) during which automatic blocking is paused for that mailbox, so it is not re-blocked while old messages are still inside the rolling window.

**Response:**
```json
{ "email": "user@example.com", "smtp_access": true }
```

### GET /api/smtp-abuse/history

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `limit` | integer | `50` | Most recent actions to return, 1 to 500 |

Audit trail of block and unblock actions. `action` is `blocked` or `unblocked`; `operator` is `smtp-abuse` for automatic blocks and `manual` for API actions.

**Response:**
```json
[
  {
    "email": "user@example.com",
    "action": "blocked",
    "message_count": 152,
    "threshold": 100,
    "window_minutes": 60,
    "automatic": true,
    "operator": "smtp-abuse",
    "app_passwords_revoked": 2,
    "created_at": "2026-07-14T09:15:00Z"
  }
]
```

---

## DMARC Insights

### GET /api/dmarc/insights

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `domain` | string or null | Unset | Return only this domain's insight (exact match); omit for every domain with report data in the window |

Policy recommendations and new-source (possible spoofing) detection, computed from collected DMARC reports over the last `DMARC_INSIGHTS_WINDOW_DAYS` (default 28). It is read-only and never changes DNS.

Without `domain`, only domains with data are listed, most actionable first (low pass rate, then new sources, then tighten recommendations). With `domain`, the response is that domain's insight object on its own (`domain`, `has_data`, `window_days`, `current_policy`, `total_messages`, `pass_rate`, `recommendations`, `new_sources`). A domain without reports in the window returns `{"domain": "...", "has_data": false, "recommendations": [], "new_sources": []}`.

**Response (all domains):**
```json
{
  "window_days": 28,
  "domain_count": 1,
  "insights": [
    {
      "domain": "example.com",
      "has_data": true,
      "window_days": 28,
      "current_policy": "none",
      "total_messages": 5400,
      "pass_rate": 99.8,
      "recommendations": [
        {
          "type": "tighten_policy",
          "severity": "success",
          "message": "example.com has a 99.8% DMARC pass rate over 5400 messages under p=none. It looks safe to move to p=quarantine.",
          "current_policy": "none",
          "recommended_policy": "quarantine"
        }
      ],
      "new_sources": [
        { "source_ip": "198.51.100.88", "failing_messages": 80, "first_seen_window_days": 7 }
      ]
    }
  ]
}
```

**Recommendation types:** `low_pass_rate` (severity `warning`: pass rate under 90% with enough volume), `already_strict` (`info`: the policy is `reject`), `insufficient_volume` (`info`: fewer than `DMARC_INSIGHTS_MIN_VOLUME` messages, default 100), `tighten_policy` (`success`: pass rate at or above `DMARC_INSIGHTS_PASS_THRESHOLD`, default 99.5), `monitor` (`info`). Only `tighten_policy` adds `current_policy` and `recommended_policy`.

`new_sources` lists up to 20 addresses, most failing messages first, that fail DMARC and first appeared in the last quarter of the window (at least 3 days, so 7 days with the default 28-day window).

---

## Protection rules

These routes back **Security** > **Settings**. Rule configuration and watch mode work with UI settings editing off. Enforcing bans needs a read-write API key.

### GET /api/protection/rules

Return `rules`, `trap_suggestions`, `country_suggestions` and `capabilities`. Capabilities contain `can_ban` (a read-write API key is set), `geoip` and `raw_logs` (Dovecot raw logs are collected; the breach rule needs them for IMAP logins). `trap_suggestions` rows are `{name, tries, addresses}` for up to 12 unknown account names tried in the last 7 days. `country_suggestions` rows are `{code, name, tries}` for up to 12 countries with failed logins in the last 7 days.

### PUT /api/protection/rules

Send `{ "rules": { ... } }` to update rule fields. Omitted rules and fields keep their current values. Unknown rule keys and fields are ignored. The response is `{ "rules": { ... } }` with the effective rules. Invalid settings return 400.

Setting any ban rule to `enforce` without a read-write API key returns 400; this also blocks every save while a stored rule is still in `enforce`. Country codes are uppercased and deduplicated. Switching a rule to `watch`, or disabling it, moves its pending automatic bans back to `watching`.

All rules have `enabled` (default false) and `notify` (default true). Ban rules also have `mode` (`watch` by default or `enforce`) and `ban_hours` (0 through 8760; zero is indefinite).

| Rule ID | Other fields and defaults | Validation |
| --- | --- | --- |
| `trap` | `names: []`, `ban_hours: 720` | Names are trimmed, lowercased and deduplicated. Each must be an address or bare name of up to 255 characters using letters, digits and `. _ % + -`. A real mailbox or alias, or a bare name equal to a real mailbox's local part, returns 400. Names after the first 500 are dropped without an error. |
| `unknown_accounts` | `threshold: 5`, `window_minutes: 60`, `ban_hours: 168` | Threshold 2 through 100; window 5 through 1440 minutes. |
| `repeat_offender` | `threshold: 3`, `window_days: 30`, `ban_hours: 0` | Threshold 2 through 50; window 1 through 365 days. |
| `subnet` | `threshold: 5`, `window_hours: 24`, `ban_hours: 24` | Threshold 2 through 256 addresses; window 1 through 168 hours. |
| `country` | `countries: []`, `ban_hours: 168` | Two-letter country codes; country matching needs GeoIP. |
| `breach` | `failures: 3`, `window_minutes: 60`, `new_country: true` | Failures 1 through 50; window 5 through 1440 minutes. Alerts only; has no ban mode. |

### GET /api/protection/hits

**Query Parameters:**

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `status` | string | `active` | `active`, `history`, `watching`, `dismissed` or `all` |
| `limit` | integer | `200` | Most hits to return, 1 to 1000 |

Return `hits` and per-status `counts`. Status groups are active (watching, pending, banned, alert), history (dismissed, expired, undone), watching, dismissed or all. History sorts by end time; other views sort by last seen. `counts` covers all hits, whatever the filter, and leaves out statuses with no hits.

Each hit has `id`, `ip`, `rule`, `mode` (`watch`, `enforce` or `manual`), `status`, `reason`, `usernames`, `attempts`, `country_code`, `country_name`, `first_seen`, `last_seen`, `ended_at`, `ban_hours`, `banned_at`, `expires_at` (null means no end), `owned` and `error`. A `watching` hit with no activity for 7 days becomes `expired`.

### POST /api/protection/hits/{hit_id}/dismiss

Dismiss a watching or alert hit and return the updated hit. This does not change mailcow. Other states are returned unchanged. Missing ID returns 404.

### POST /api/protection/hits/{hit_id}/ban

Ban a watching hit from a ban-capable rule and return the updated hit, whose `mode` becomes `manual`. Missing ID returns 404. A non-ban rule or a missing read-write API key returns 400; a non-watching state returns 409. If the address is on the allowlist by then, the hit becomes `dismissed` and the endpoint returns 502 with that reason. On any other failure the hit stays `pending`, keeps the error, and the next rules run tries again (502).

### POST /api/protection/hits/{hit_id}/undo

Undo a banned or pending hit and return it. Missing ID returns 404; other states return 409. Lifting a ban the app added without a read-write API key returns 400; a mailcow failure returns 502. Undoing a pending hit changes nothing in mailcow. Entries the app did not add are left in mailcow. If another rule still bans the same address, that hit takes over the entry and it stays in mailcow. Dismissed and undone addresses are left alone by that rule for a week.

---

## Notification Destinations

Manage where alerts are delivered. Multiple destinations can be configured; each alert goes to enabled destinations subscribed to its topic. See [Notifications](Notifications.md) for email routing and delivery exceptions.

### GET /api/notifications/types

The fields each service type needs (the settings form shows only these) and the alert types a destination can subscribe to. A field can also carry `placeholder` and, for the ntfy server URL, `default` (`https://ntfy.sh`). Fields with `secret: true` are masked once saved.

```json
{
  "types": [
    {
      "id": "telegram",
      "label": "Telegram",
      "help": "Create a bot with @BotFather to get the token...",
      "fields": [
        {"key": "bot_token", "label": "Bot token", "type": "text", "required": true, "secret": true},
        {"key": "chat_id", "label": "Chat ID", "type": "text", "required": true}
      ]
    }
  ],
  "alert_types": [
    {"id": "security", "label": "Security", "description": "Compromised mailbox detected, authentication attacks, SMTP disabled by abuse protection"},
    {"id": "blacklist", "label": "IP blacklist", "description": "Your server IP was listed on a spam blacklist, or is listed no more"},
    {"id": "dns_changes", "label": "DNS record changes", "description": "A domain SPF, DKIM, DMARC, TLSA, MTA-STS or TLS-RPT record changed, DNSSEC stopped validating, or DANE broke"},
    {"id": "dmarc_errors", "label": "DMARC processing errors", "description": "A DMARC report could not be imported or parsed"}
  ]
}
```

**Types:** `slack`, `discord`, `telegram`, `ntfy`, `gotify`, `webhook`

**Alert types:** `security`, `blacklist`, `dns_changes`, `dmarc_errors`

### GET /api/notifications/channels

List configured destinations. Secret fields are returned masked as `********`.

```json
{
  "channels": [
    {
      "id": 1,
      "name": "Ops Slack",
      "channel_type": "slack",
      "config": {"webhook_url": "********"},
      "alert_types": [],
      "enabled": true,
      "last_status": "success",
      "last_error": null,
      "last_sent_at": "2026-07-27T09:00:00Z"
    }
  ]
}
```

- `alert_types`: The alert types this destination is subscribed to. An empty array means the destination receives every alert.
- `last_status`: `success`, `failed`, or `null` before the first delivery. `last_error` holds the failure text (secrets removed, up to 500 characters).

### POST /api/notifications/channels

**JSON fields:**

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `name` | string | Required | 1 to 100 characters; leading and trailing spaces are removed |
| `channel_type` | string | Required | `slack`, `discord`, `telegram`, `ntfy`, `gotify` or `webhook` |
| `config` | object | `{}` | The type's fields from `GET /api/notifications/types`, by `key` |
| `alert_types` | array of strings or null | Unset | Alert type IDs to subscribe to. Empty, unset or all four means every alert. |
| `enabled` | boolean | `true` | Disabled destinations receive no alerts |

Create a destination. Returns `422` for an unknown `channel_type`, a missing required field for that type, or an unknown ID in `alert_types`. A literal `********` counts as empty here, because there is no stored secret yet.

```json
{
  "name": "Ops Telegram",
  "channel_type": "telegram",
  "config": {"bot_token": "123:ABC", "chat_id": "456"},
  "alert_types": ["security", "blacklist"],
  "enabled": true
}
```

- `alert_types` is optional: omit it (or subscribe to all types) to receive every alert.

Returns the created destination object with its integer `id`, `name`, `channel_type`, masked `config`, `alert_types`, `enabled`, `last_status`, `last_error` and `last_sent_at`.

### PUT /api/notifications/channels/{id}

**JSON fields:**

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `name` | string | Required | 1 to 100 characters |
| `channel_type` | string | Required | Same values as for create |
| `config` | object | `{}` | The type's fields; send a secret as `********` to keep the stored value |
| `alert_types` | array of strings or null | Unset | As for create |
| `enabled` | boolean | `true` | As for create |

Update a destination. The body replaces the whole destination: an omitted `alert_types` resets the destination to every alert, and an omitted `enabled` turns it back on. Send a secret field back as `********` to keep the stored value.

Changing `server_url` or `url` while keeping a masked secret returns 422 and asks for the secret again, so a stored secret is never sent to a new server. A different service type does not inherit secrets from the old type. An unknown ID returns 404. The response is the saved destination object with secrets masked.

### DELETE /api/notifications/channels/{id}

Remove a destination.

Success returns `{ "status": "success" }`; an unknown ID returns 404.

### POST /api/notifications/channels/{id}/test

Send a test notification ("Test notification") to a saved destination. An unknown ID returns 404.

```json
{ "success": true, "logs": ["Channel: Ops Slack (slack)", "Sending test notification...", "Delivered successfully"] }
```

The test sends even when the destination is disabled and bypasses topic selection. It updates the stored last-delivery result.

### POST /api/notifications/test

**JSON fields:**

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `channel_type` | string | Required | One of the six service types |
| `config` | object | `{}` | The type's fields, with real secret values |

Test a configuration before saving it (the test button in the destination editor). An unknown `channel_type` returns 422; a missing required field returns `success: false` with the reason in `logs`.

```json
{ "channel_type": "ntfy", "config": {"server_url": "https://ntfy.sh", "topic": "mailcow-alerts"} }
```

Draft tests use the submitted values directly. They do not resolve `********` against an existing destination. Use the saved-channel test for stored secrets. Both test routes return `success` and `logs`.

## In-app documentation

### GET /api/docs/{doc_name}

Return a help page as plain-text Markdown, fetched from `documentation/HelpDocs` on the `main` branch of the GitHub repository (10-second timeout). Only names on a fixed list are accepted: `Domains`, `DMARC`, `Mailbox_Stats`, `IP_Blacklist_Monitor`, `Spam_Filter`, `Quarantine`, `Abuse_Protection`, `Rate_Limits` and `Devices`.

Other names return 404. An HTTP error from GitHub (including a missing file) also returns 404; a network failure returns 503.
