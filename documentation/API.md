# API reference

**Base URL:** `https://logs.example.com/api`. A heading path without `/api`, such as `GET /health`, is relative to the base URL; `/login` and `/ws/raw-logs` are at the application root.

What applies to every endpoint:

- **Authentication:** with Basic authentication or OAuth2/OIDC on, every endpoint except the [public ones](#sign-in-methods) needs a session cookie or Basic credentials.
- **Read-write key:** endpoints that change mailcow need `MAILCOW_API_KEY_RW`. The status code when it is missing depends on the endpoint and is given in its entry. When mailcow refuses the key during an action, the endpoint answers 502 at once, without retries, and `detail` says whether the key was rejected or is read-only. [`GET /rw-status`](#get-rw-status) says whether a key is set.
- **Feature switches:** `DISABLED_FEATURES` hides pages and stops jobs used only by those features; collection shared with enabled pages continues. It does not block their API routes.
- **Times:** a time is ISO 8601 in UTC with `Z`, or unix seconds where the entry says so. A date without a time (`YYYY-MM-DD`), in a request or a response, is a day in the app's time zone (`TZ`, UTC when unset).
- **Errors:** see [Error Responses](#error-responses).

## Contents

- [Authentication](#authentication)
- [Error Responses](#error-responses)
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
- [System Status](#system-status)
- [Raw Logs (Live Log Viewer)](#raw-logs-live-log-viewer)
- [Suppressions and Rspamd maps](#suppressions-and-rspamd-maps)
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

Basic authentication (`BASIC_AUTH_ENABLED`), OAuth2/OIDC (`OAUTH2_ENABLED`), or both. With both off (the default), no endpoint needs credentials.

Public endpoints: `GET /api/health`, `GET /api/info`, `GET /api/auth/provider-info`, `GET /login`, `GET /api/auth/login` and `GET /api/auth/callback`. Every other `/api/*` endpoint is protected, including `GET /api/auth/verify` and `POST /api/auth/session`.

### Authentication Methods

#### Basic Authentication

On when `BASIC_AUTH_ENABLED=true` (or the legacy `AUTH_ENABLED=true`). The username is `AUTH_USERNAME` (default `admin`), the password `AUTH_PASSWORD`; with an empty password, protected requests return 500.

A request without credentials, or with wrong ones, gets 401 with a plain-text body and no `WWW-Authenticate` header, so browsers do not show their own password prompt. Page paths outside `/api` redirect to `/login?next=<page>` instead.

After 10 failed attempts within 15 minutes from one client address (IPv6 clients are counted per /64), every request from that client that carries Basic credentials gets 429 with `Retry-After: 900`, including the public `GET /api/info`. A correct password resets the count.

```bash
curl -u username:password https://logs.example.com/api/info
```

**Session cookie (what the web UI uses):** send the password once to `POST /api/auth/session` and get an `HttpOnly` cookie named `session_id` that authenticates later requests. The cookie is `Secure` when the request arrives over HTTPS (directly, or through a reverse proxy that sets `X-Forwarded-Proto`), and `SameSite=lax` in all cases.

```bash
curl -u username:password -c cookies.txt -X POST https://logs.example.com/api/auth/session
curl -b cookies.txt https://logs.example.com/api/info
```

Sessions live in the application's memory, so restarting the container signs everyone out. One process holds at most `SESSION_MAX_ENTRIES` sessions (default 50); when it is full, a new sign-in gets 503 with `Retry-After: 60`. API clients can also send `Authorization: Basic` on every request instead of using a session.

#### OAuth2/OIDC Authentication

On when `OAUTH2_ENABLED=true`; see the [OAuth2 Configuration Guide](OAuth2_Configuration.md). `GET /api/auth/login` sends the browser to the provider, which returns it to `GET /api/auth/callback`; the app exchanges the code for tokens with PKCE (S256), creates a server-side session that lasts `SESSION_EXPIRY_HOURS` (default 24) and sets the HttpOnly cookie.

### Login Endpoint

#### GET /login

Always public. Serves the login page with the Basic form, the OAuth2 button, or both.

**Query parameter:** `next`, the local page to open after sign-in. Only a path on this site is accepted; anything else, and any path under `/login`, `/api/` or `/static/`, becomes `/`.

With authentication off, or a valid session already present, it redirects (302) to `next`.

---

## Error Responses

Most errors, including 400 and 404, are JSON with a `detail` field, such as `{ "detail": "Invalid parameter value" }`. Each entry lists the codes that matter for it.

### 401 Unauthorized

Authentication is on and the request has no valid session or Basic credentials. The body is plain text, not JSON: `Authentication required`, or `Incorrect username or password` for wrong Basic credentials. There is no `WWW-Authenticate` header.

### 403 Forbidden

A POST, PUT, PATCH or DELETE whose `Origin` (or, without it, `Referer`) names another host is rejected before it reaches the endpoint, whether or not authentication is on:

```json
{ "detail": "This request came from another site and was rejected." }
```

Requests with neither header (curl, scripts) pass, and so do origins listed exactly in `CORS_ALLOWED_ORIGINS`. Some endpoints use 403 for their own reasons too, such as UI editing being off or a missing read-write key; their entries say so.

### 422, 429 and 503

422 reports request validation errors (wrong type, out-of-range value). 429 means the client is locked out after failed Basic attempts (`Retry-After: 900`). 503 can mean the session store is full, upstream data is unavailable, or no read-write key is set, depending on the endpoint. Some endpoints return an `error` field with HTTP 200; check it.

### 500 Internal Server Error

`{ "detail": "Internal server error" }`. An exception no endpoint handled returns `{ "error": "Internal server error", "detail": "An error occurred" }` instead. With `DEBUG=true`, `detail` holds the exception text.

### 502 Bad Gateway

A failed mailcow API call, usually `{ "detail": "mailcow did not answer. Try again in a moment." }`. When mailcow refuses the read-write key, `detail` says so. Some status reads return 503 or fallback data instead.

---

## Health & Info

### GET /health

Public. Returns 200 with `{ "status": "healthy", "database": "connected" }`, or 503 with `"unhealthy"` and `"disconnected"` when the database check fails.

---

### GET /info

Public. Without valid credentials while authentication is on, the response has only `name`, `app_title`, `app_logo_url`, `auth_enabled`, `basic_auth_enabled` and `oauth2_enabled`.

Signed-in callers, or any caller while authentication is off, also get `version` (from the running image), `mailcow_url`, `local_domains`, `fetch_interval`, `retention_days`, `timezone` (the zone in use, `UTC` when unset or unknown), `timezone_valid` (false when the configured name is unknown), `timezone_configured` (the configured name, empty when unset), `blacklist_count`, `disabled_features` and `settings_edit_via_ui_enabled`. The top-bar search leaves out settings while `settings_edit_via_ui_enabled` is `false`.

---

### GET /rw-status

`{ "rw_configured": true }` when a read-write key (`MAILCOW_API_KEY_RW`, from ENV or **Settings**) is set. The key is not tested; use [`POST /api/settings/mailcow/rw-key/validate`](#post-apisettingsmailcowrw-keyvalidate) for that. The web interface reads this once at startup to show or hide write controls.

---

## OAuth2 Authentication Endpoints

### GET /api/auth/provider-info

Public. `{ "oauth2_enabled": true, "basic_auth_enabled": true, "provider_name": "Authentik" }`; `provider_name` is null while OAuth2 is off.

---

### GET /api/auth/login

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `next` | string or null | Unset | Local page to open after sign-in. Same rules as `next` on [`GET /login`](#get-login). |

Public. Starts the OAuth2 sign-in: 307 redirect to the provider with a signed `state` (expires after 10 minutes) and a PKCE challenge (`code_challenge_method=S256`). It also sets an HttpOnly `oauth_state_<state>` cookie for 10 minutes that ties the callback to this browser.

OAuth2 off returns 400; missing client settings or failed discovery return 500.

---

### GET /api/auth/callback

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `code` | string | Unset | Authorization code from the provider |
| `state` | string | Unset | Signed state from `GET /api/auth/login` |
| `error` | string | Unset | Set by the provider when it declined the sign-in |

Public. Exchanges the code for tokens, reads the user information, creates the session and redirects (302) to the `next` page chosen at login, or `/`.

OAuth2 off returns 400. Every other failure redirects to `/login?error=<code>`:

| Code | Meaning |
| --- | --- |
| `invalid_state` | The state is missing, invalid, expired, already used, or does not match this browser's cookie. Checked first, so a provider error with a bad state also gives this code. |
| `oauth2_error` | The provider declined (`error` was set), or the token or user information request failed |
| `missing_code` | No `code` in the callback |
| `no_token` | The token response had no access token |
| `session_capacity` | The session store is full (`SESSION_MAX_ENTRIES`) |
| `server_error` | Any other error |

---

### POST /api/auth/logout

Deletes the server-side session (OAuth2 or Basic) and redirects (302) to `/login` with the cookie cleared. POST only, so another site cannot sign you out with a link or an image: `GET /api/auth/logout` returns 405 with `Allow: POST`, and a cross-site POST gets the [same-origin 403](#403-forbidden).

---

### GET /api/auth/status

Returns `authenticated`, `auth_type` and `user`. Protected, so a request without valid credentials gets 401, not a signed-out status. A session from either method returns its stored user object (a Basic session has `username` and `auth_method: "basic"`); direct Basic headers return `user: null`. With authentication off and no session: `{ "authenticated": false, "auth_type": null, "user": null }`.

---

### GET /api/auth/verify

Returns `{ "verified": true }` once the authentication middleware accepts the request. The login form uses `POST /api/auth/session` instead.

---

### POST /api/auth/session

Exchanges valid Basic credentials in the `Authorization` header for the `session_id` cookie. No body. Returns `{ "authenticated": true, "auth_type": "basic" }`.

With Basic authentication off, the handler returns 400; when only OAuth2 is on, a request without a valid session is rejected first with 401. Invalid Basic credentials return 401; a locked-out client gets 429; a full session store 503 with `Retry-After: 60`.

---

## Job Status Tracking

### Job state

`GET /api/settings/info` returns job state in its `background_jobs` field; the web interface shows it in **Status** > **Jobs**. State is held in the process and resets when the app restarts.

### Job Status Data Structure

Each job starts as `{"last_run": null, "status": "idle", "error": null}`. The IDs are `fetch_logs`, `complete_correlations`, `update_final_status`, `expire_correlations`, `correlate_dovecot`, `cleanup_logs`, `cleanup_dmarc_reports`, `check_app_version`, `check_credentials`, `dns_check`, `update_geoip`, `dmarc_imap_sync`, `mailbox_stats`, `alias_stats`, `blacklist_check`, `send_weekly_summary`, `sync_transports`, `fetch_raw_logs`, `cleanup_raw_logs`, `detect_suppressions`, `sync_suppressions`, `expire_suppressions`, `process_quarantine_rules`, `cleanup_deferred_queue`, `anomaly_detection`, `smtp_abuse`, `protection_rules`, `eas_devices` and `cleanup_eas_devices`. `sync_local_domains` is added on its first run. `fetch_raw_logs` and `cleanup_raw_logs` keep their status in the raw log worker.

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
| **Credential Checks** | Every 6 hours, and 30 seconds after startup | Checks that mailcow accepts the Read-Write API key and Rspamd the password, as **Validate** does; changes nothing. Off when neither is set. A rejected or unreachable one fails the job. |
| **DNS Check** | Every 6 hours, and 60 seconds after startup | Checks SPF, DKIM, DMARC, DNSSEC, TLSA, MTA-STS and TLS-RPT for all active domains. Domains feature only. |
| **Sync Local Domains** | Every 6 hours, first run at startup | Refreshes the active domain list from mailcow |
| **Update GeoIP** | Weekly (Sunday 3 AM), and 60 seconds after startup | Downloads the MaxMind GeoLite2 City and ASN databases when a file is missing or 7 or more days old. Runs only when the MaxMind Account ID and License Key are set; saving or removing the license in Settings adds or removes the weekly run. |
| **DMARC IMAP Sync** | Every `DMARC_IMAP_INTERVAL` seconds (default 3600), and 30 seconds after startup when `DMARC_IMAP_RUN_ON_STARTUP` is on | Imports DMARC and TLS reports from IMAP. Needs the DMARC feature and IMAP import on. |
| **Mailbox Stats** | Every 5 minutes, and 45 seconds after startup | Fetches mailbox statistics. Runs while Mailbox Stats or Rate Limits is on. |
| **Alias Stats** | Every 5 minutes, and 50 seconds after startup | Syncs alias data. Mailbox Stats feature only. |
| **ActiveSync Devices** | Every minute | Records ActiveSync devices from the SOGo log. Does nothing while Devices is off. |
| **Cleanup ActiveSync Devices** | Daily at 3:30 AM | Removes devices not seen within `EAS_DEVICES_RETENTION_DAYS` (default 90; 0 keeps them) |
| **Blacklist Check** | Daily at 5 AM, and 15 seconds after startup | Checks monitored hosts against DNS blacklists. Blacklist feature only. |
| **Sync Transports** | Every 6 hours, and 30 seconds after startup | Syncs transports and relayhosts from mailcow for blacklist monitoring. Blacklist feature only. |
| **Weekly Summary** | Monday at 9 AM | Sends the weekly summary email when it is turned on |
| **Anomaly Detection** | Every `ANOMALY_CHECK_INTERVAL` minutes (default 15) | Detects outbound volume spikes and sign-in failure bursts. Runs while anomaly detection is on. |
| **SMTP Abuse** | Every minute | Disables SMTP for mailboxes over the sending threshold. Needs SMTP abuse protection on and a read-write key. Shown on **Status** > **Jobs** as **Outgoing Spam**. |
| **Protection Rules** | After each log fetch | Evaluates the protection rules on new Netfilter lines and writes bans when a read-write key is set. Security feature only. |
| **Fetch Raw Logs** | Every `RAW_LOGS_FETCH_INTERVAL` seconds (default 30) | Collects raw service logs for the Logs page and the pages that read them |
| **Cleanup Raw Logs** | Daily at 3 AM | Removes raw logs older than `RAW_LOGS_RETENTION_DAYS` (default 2), and the rate limit log older than `RATE_LIMITS_RETENTION_DAYS` (default 90, never less than the first) |
| **Detect Suppressions** | Every 5 minutes | Suppresses recipients of bounced messages found in Postfix logs, and of deferred messages too while deferred queue cleanup is off. Runs while the Suppressions feature, suppressions and automatic detection are on. |
| **Cleanup Deferred Queue** | Every 5 minutes | Deletes deferred messages stuck longer than `QUEUE_CLEANUP_THRESHOLD_MINUTES` (default 60) and suppresses their recipients. Needs suppressions, queue cleanup and a read-write key. |
| **Sync Suppressions** | Every 10 minutes | Syncs active suppressions to the Rspamd recipient denylist. Needs the Rspamd password, Rspamd sync turned on and a read-write key. |
| **Expire Suppressions** | Every hour | Deactivates expired suppression entries |
| **Process Quarantine Rules** | Every `QUARANTINE_RULES_INTERVAL` minutes (default 5) | Applies the quarantine auto-rules (release or delete matching messages). Needs the Quarantine feature and a read-write key. Saving settings applies a new interval and starts or stops the job when either of these changes. |

## Domains

What each DNS check means is in [Domains](HelpDocs/Domains.md).

### GET /api/domains/all

All mailcow domains with their counts and the stored DNS check results.

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
      "max_num_mboxes_for_domain": 1000,
      "quota_used_in_domain": "1572864",
      "backupmx": false,
      "dns_checks": {
        "spf": {
          "status": "success",
          "message": "SPF configured correctly with strict -all policy. Server IP authorized via ip4:192.0.2.10",
          "record": "v=spf1 mx include:_spf.example.net -all",
          "dns_lookups": 3,
          "warnings": [],
          "checked_ips": [{"ip": "192.0.2.10", "source": "auto-detected", "authorized": true}]
        },
        "dkim": {"status": "success", "selector": "dkim", "match": true, "warnings": [], "info": [], "parameters": {"v": "DKIM1", "k": "rsa", "p": "MIIBIjANBg..."}},
        "dmarc": {"status": "success", "policy": "reject", "is_strong": true, "warnings": []},
        "checked_at": "2026-01-08T01:34:08Z"
      },
      "alias_domains": [
        {"domain_name": "alias.example.com", "dns_checks": {"spf": {"status": "success", "message": "..."}}}
      ]
    }
  ]
}
```

Each domain also has mailcow's other limits and counters (`mboxes_left`, `aliases_in_domain`, `aliases_left`, `max_num_aliases_for_domain`, `created`, `bytes_total`, `msgs_total`, `max_quota_for_domain`, `relay_all_recipients`, `relay_unknown_only`). `quota_used_in_domain` is a string. `dns_checks` holds `spf`, `dkim`, `dmarc`, `dnssec`, `tlsa`, `mta_sts`, `tls_rpt` and `checked_at`, read from the database. `alias_domains` lists the domain's mailcow alias domains with their own `dns_checks`, or is empty.

`checked_at` changes whenever that domain is checked. `last_dns_check` is when every domain was last checked together (the scheduled check or `check-all-dns`); checking one domain does not change it.

**Check status:** `success` (passed), `warning` (passed, with a recommendation), `error` (failed or no record), `unknown` (not checked yet).

**SPF:**

- More than 10 DNS lookups (RFC 7208): error. `dns_lookups` holds the count.
- A checked source IP that the record does not authorize: error. `checked_ips` lists each one with `ip`, `authorized` and `source`: `auto-detected` (WAN IP), `transport`, `relayhost`, `configured` (manual entry) or `dmarc-history`. The `DOMAIN_SPF_SOURCE_*` settings choose the sources. Results stored before this field existed lack it.
- More than one SPF record: error.
- Invalid syntax after `v=spf1`, or an unknown mechanism: error. Unknown `name=value` modifiers are ignored; using a mechanism name as a modifier, such as `ip4=192.0.2.10`, adds a warning.
- `ptr`: warning (discouraged by RFC 7208); counted as a DNS lookup, not evaluated.
- `-all` and `~all`: success. `?all`: warning. `+all` or bare `all`: error. Without `all`, a `redirect=` is accepted: success when it authorizes every checked source, warning when no sources were checked, error when a checked source is unauthorized; without a redirect, no `all` is an error.

**DKIM:** `match` compares the key, version, key type and permitted signing hashes with mailcow's record; tag order and compatible policy differences do not make it false. A mismatch or `t=y` (testing mode) gives `status: "error"`; `h=sha1` alone cannot verify mailcow's SHA256 signatures and therefore mismatches. Other warnings give `status: "warning"`. `t=s` is information only: the domain in a signature's `i=` must equal its `d=`. `parameters` holds the parsed tags, `warnings` the problems and policy differences, and `info` informational messages.

**DMARC:** `reject` and `quarantine` are success (`is_strong: true`); `none` is a warning.

SPF also returns `record`, `has_strict_all`, `includes_mx` and `includes`; DKIM returns `selector`, `dkim_domain`, `expected_record` and `actual_record`; DMARC returns `record`, `policy`, `is_strong`, `warnings` and parsed tags in `settings` (including `subdomain_policy` and `percentage` when published).

---

### POST /api/domains/check-all-dns

Checks SPF, DKIM, DMARC, DNSSEC, TLSA, MTA-STS and TLS-RPT for every active domain and its alias domains now, stores the results, sets `last_dns_check` and waits for the checks to finish.

```json
{ "status": "partial", "message": "Checked 7 domains", "domains_checked": 7, "errors": ["example.com: DNS check failed. Check the application logs."] }
```

`status` is `success` when every domain was checked, else `partial`.

---

### POST /api/domains/{domain}/check-dns

Checks one domain now and stores the result as an individual check. Returns `{ "status": "success", "message": "DNS checked for example.com", "data": { ... } }`, where `data` is the same result object as `GET /api/domains/{domain}/dns-check`. An invalid domain name returns 400.

---

### GET /api/domains/{domain}/dns-check

Runs the DNS checks for one domain on every request and returns the result directly, without reading or saving the stored checks. The result has `domain`, `checked_at`, `spf`, `dkim`, `dmarc`, `dnssec`, `tlsa`, `mta_sts` and `tls_rpt`. An invalid domain name returns 400.

---

## Mailbox Statistics

### GET /api/mailbox-stats/summary

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `date_range` | string | `30days` | `today`, `7days`, `30days`, `90days` or `custom` |
| `start_date` | string or null | Unset | Start date (`YYYY-MM-DD`), used when `date_range` is `custom` |
| `end_date` | string or null | Unset | End date (`YYYY-MM-DD`), used when `date_range` is `custom` |

Server-wide traffic for the period: `total_sent`, `total_received`, `total_messages`, `sent_failed`, `failure_rate`, `date_range`, `start_date`, `end_date` and `last_update`. The search and domain filters of the list do not change these totals.

`sent_failed` counts bounced and rejected outgoing messages; deferred messages are counted separately, and a later successful delivery leg wins. Values come from collected correlations, so retention limits the history.

For both traffic endpoints, `today` and custom date-only boundaries are days in the app's time zone; the returned boundaries are UTC. An unknown `date_range`, or `custom` without both valid dates, falls back to the last 30 days.

---

### GET /api/mailbox-stats/all

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `domain` | string or null | Unset | Only mailboxes of this domain. An alias domain shows the mailboxes of its target domain. |
| `active_only` | boolean | `true` | Only active mailboxes |
| `hide_zero` | boolean | `false` | Leave out mailboxes with no activity in the period |
| `search` | string or null | Unset | Substring match on the address, the name, or any of the mailbox's aliases |
| `date_range` | string | `30days` | `today`, `7days`, `30days`, `90days` or `custom` |
| `start_date` | string or null | Unset | Start date (`YYYY-MM-DD`), used when `date_range` is `custom` |
| `end_date` | string or null | Unset | End date (`YYYY-MM-DD`), used when `date_range` is `custom` |
| `sort_by` | string | `sent_total` | `sent_total`, `received_total`, `failure_rate`, `username` or `quota_used`; any other value sorts by total messages. Sent and received include aliases. |
| `sort_order` | string | `desc` | `desc` in any case; any other value sorts ascending |
| `page` | integer | `1` | Page number, at least 1 |
| `page_size` | integer | `50` | Items per page, 10 to 100 |

Mailboxes with their message counts and aliases, paged. Results are cached in memory for 5 minutes per combination of query parameters.

```json
{
  "total": 25, "page": 1, "page_size": 50, "total_pages": 1,
  "date_range": "30days", "start_date": "2026-01-16T00:00:00Z", "end_date": "2026-02-16T00:00:00Z",
  "mailboxes": [
    {
      "username": "user@example.com",
      "name": "John Doe",
      "active": true,
      "quota": 1073741824,
      "quota_used": 536870912,
      "percent_in_use": 50.0,
      "last_smtp_login": "2026-01-16T08:45:00Z",
      "rl_value": 100,
      "rl_frame": "m",
      "attributes": {"imap_access": "1", "smtp_access": "1"},
      "mailbox_counts": {"sent_total": 150, "sent_delivered": 145, "sent_bounced": 3, "sent_deferred": 2, "sent_rejected": 0, "sent_failed": 3, "received_total": 320, "failure_rate": 2.0},
      "aliases": [
        {"alias_address": "user@alias.example.com", "active": true, "is_catch_all": false, "is_domain_alias": true, "sent_total": 12, "received_total": 4, "failure_rate": 0.0}
      ],
      "alias_count": 1,
      "combined_sent": 162,
      "combined_failure_rate": 1.9
    }
  ]
}
```

`mailbox_counts` covers the mailbox's own address; aliases use the same count fields. `combined_sent`, `combined_received`, `combined_total`, `combined_failed`, `combined_failure_rate`, `combined_internal` and `combined_delivered` add aliases, including alias-domain addresses; `combined_inbound` and `combined_outbound` count only the mailbox's own address. An alias-domain address (`user@alias.example.com`) appears in `aliases` with `is_domain_alias: true` only when it has traffic in the period. Failed means bounced plus rejected, not deferred. `rl_value`/`rl_frame` is the mailbox's rate limit (100 per minute above).

Rows also have `id`, `domain`, `created`, `modified`, `last_imap_login`, `last_pop3_login`, `quota_formatted`, `quota_used_formatted` and `messages_in_mailbox`. Quotas are bytes, formatted quotas are display strings, login times are null if never, and `messages_in_mailbox` is the synced stored-message count, not traffic in the period. Count objects also include `sent_expired`, `total_messages`, `direction_inbound`, `direction_outbound` and `direction_internal`.

The response also has `activity_unit` and `activity_buckets`, and each mailbox an `activity` series.

A read failure returns HTTP 200 with `error`, `total: 0` and `mailboxes: []`, rather than a normal page.

---

### GET /api/mailbox-stats/domains

Domains with their mailbox counts, for the domain filter. An alias domain is listed with `alias_of` (its target domain) and the target's count; filtering by it shows the target's mailboxes.

```json
{ "domains": [ {"domain": "example.com", "mailbox_count": 15}, {"domain": "alias.example.com", "mailbox_count": 15, "alias_of": "example.com"} ] }
```

---

### GET /api/mailbox-stats/refresh

Returns the last sync times: `{ "last_mailbox_update": "2026-10-16T09:00:00Z", "last_alias_update": "2026-10-16T09:00:00Z" }`. It does not start a refresh. Either time can be null; a database failure returns an `error` field.

---

## Devices

ActiveSync devices recorded from SOGo's access log. The `eas_devices` job reads the newest SOGo lines every minute and keeps one row per user and device ID: the newest request, and when the device was first and last seen. Devices not seen for `EAS_DEVICES_RETENTION_DAYS` (default 90, `0` = forever) are removed daily.

### GET /api/devices

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `page` | integer | `1` | Page number, at least 1 |
| `per_page` | integer | `50` | 1 to 200 |
| `search` | string or null | Unset | Case-insensitive substring of the user, device ID, device type or last IP |
| `device_type` | string or null | Unset | Exact device type (one of `device_types` in the response) |
| `seen` | string | `all` | `all`, `recent` (seen in the last 24 hours), `new` (first seen in the last 7 days) or `stale` (not seen for 30 days) |
| `sort_by` | string | `last_seen` | `username`, `device_type`, `last_ip`, `last_command`, `first_seen` or `last_seen` |
| `sort_dir` | string | `desc` | `asc` or `desc` |

```json
{
  "items": [
    {
      "id": 12, "username": "jane@example.com", "device_id": "ApplF2C8A1D94B7E", "device_type": "iPhone",
      "last_ip": "203.0.113.7", "country_code": "DE", "country_name": "Germany", "city": "Berlin", "asn": "AS64500", "asn_org": "Example Mobile",
      "client": "Apple Mail", "model": null, "last_command": "Ping", "last_status": 200,
      "first_seen": "2026-09-02T08:14:03Z", "last_seen": "2026-10-05T14:02:51Z"
    }
  ],
  "total": 1, "page": 1, "per_page": 50, "total_pages": 1,
  "summary": {"devices": 16, "users": 11, "recent": 14, "new": 2, "stale": 1},
  "device_types": ["iPad", "iPhone", "Outlook"],
  "thresholds": {"recent_hours": 24, "new_days": 7, "stale_days": 30},
  "retention_days": 90, "geoip": true, "last_run": "2026-10-05T14:03:00Z", "last_status": "success"
}
```

- `summary` counts every device, not only the filtered page.
- `last_ip` is null when SOGo logged something other than an IP address.
- The location fields are looked up in the MaxMind databases when the list is read; they are null when `geoip` is false or the address is not in the database.
- `client` is the mail app recognized from the device ID and type (`Apple Mail`, `Samsung Email`, `Outlook`, `Windows Mail`, `Gmail`), else null; `model` is a Samsung model code such as `SM-S918B`, else null.
- `last_status` is the HTTP status SOGo answered; `401` means the device's password was refused.
- A connected phone's `last_seen` can be up to an hour old: SOGo logs a `Ping` when it ends, and mailcow allows a Ping of up to 59 minutes.

---

## Rate Limits

mailcow rate-limits senders through Rspamd, which counts every send against a Redis key and writes a line to the `ratelimited` log when a sender runs out. These endpoints back **Mailbox Stats** > **Rate Limits**. The write endpoints need a read-write key and return 503 without one. Limit values are whole messages per time frame, `0` removes the limit, and frames are `s`, `m`, `h` and `d`. A mailcow refusal returns 502.

### GET /api/rate-limits/events

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `hours` | integer | `168` | Chart window in hours, 1 to 8760; narrowed to the longest window in `windows` |

Sender history and an activity chart from the collected `ratelimited` log, counted in the database; does not call mailcow.

The response has `hours` (the window used), `windows` (the windows the kept history covers, from 24, 168, 720, 2160 and 8760), `retention_days`, `total_events`, `window_senders`, `by_sender`, `events`, `bucket` and `by_bucket`. The window applies to the chart totals and buckets only; `by_sender` covers every sender in the kept history, by hit count. Each sender has `user`, `events`, `last_seen`, `last_rl_hash`, `current_limit` (`{value, frame}` from the synced mailbox, or null), `recent` (up to 5 events) and optional `last_reset`. The flat `events` feed holds up to 50. Event fields are `time`, `rcpt`, `subject`, `qid` and `rl_hash` (plus `user` in the flat feed). Buckets are `{bucket, count}`, hourly for windows up to 24 hours, else daily.

---

### GET /api/rate-limits/limits

The limits of every synced mailbox and every active local domain.

```json
{
  "rw_key_configured": true,
  "mailboxes": [{"username": "sales@example.com", "domain": "example.com", "rl_value": 100, "rl_frame": "m", "active": true}],
  "domains": [{"domain": "example.com", "rl_value": 500, "rl_frame": "h"}],
  "domains_error": null
}
```

Mailbox limits come from the local sync; domain limits are read from mailcow and cached for 300 seconds. `rl_value` is null when no limit is set. `domains_error` holds mailcow's error text when the domain limits could not be read.

---

### POST /api/rate-limits/mailbox

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `mailbox` | string | Required | Mailbox address; must be a synced mailbox |
| `value` | integer | Required | Messages per frame, 0 or more; `0` removes the limit |
| `frame` | string | Required | `s`, `m`, `h` or `d` |

Sets one mailbox's limit. Returns `mailbox`, `rl_value`, `rl_frame` and `mailcow_response`. The local mailbox row is updated at once, so the page shows the new limit before the next sync. An unknown mailbox, negative value or invalid frame returns 400.

---

### POST /api/rate-limits/domain

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `domain` | string | Required | A local domain |
| `value` | integer | Required | Messages per frame, 0 or more; `0` removes the limit |
| `frame` | string | Required | `s`, `m`, `h` or `d` |

Sets one domain's limit. Returns `domain`, `rl_value`, `rl_frame` and `mailcow_response`, and clears the cached domain limits. An unknown domain, negative value or invalid frame returns 400.

---

### POST /api/rate-limits/reset

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `rl_hash` | string | Required | The counter's hash from the `ratelimited` log: `RL` followed by letters and digits |
| `user` | string or null | Unset | Sender to record the reset against (shown as `last_reset` in the events) |

Resets an active counter so a blocked sender can send again at once; the limit itself is not changed. Returns `{ "rl_hash": "RLwhscgno1zwitb6nif6i83msr", "reset": true, "mailcow_response": null }` (mailcow usually answers with an empty body). A value that does not match `^RL[A-Za-z0-9]+$` returns 400.

---

### GET /api/rate-limits/sender-events

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `user` | string | `` | The sender address to read the history of |

One sender's whole collected history of refused messages, newest first, up to 2,000 rows, whatever the chart window. Returns `user`, `total` (the full count in the database) and `events` with the fields above. An empty `user` returns 400.

---

### POST /api/rate-limits/bulk

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `mailboxes` | array of strings | `[]` | Mailbox addresses |
| `domains` | array of strings | `[]` | Local domains |
| `value` | integer | Required | Messages per frame, 0 or more; `0` removes the limits |
| `frame` | string | Required | `s`, `m`, `h` or `d` |

Sets one limit on many mailboxes and domains (**Apply to filtered** on the page). None, or more than 1,000 in total, returns 400. Unknown names are skipped, not rejected. All mailboxes go to mailcow in one call, then all domains in a second; if the domain call fails, the mailbox change stays. Returns `mailboxes_updated`, `domains_updated`, `skipped`, `value` and `frame`.

---

## Messages (Unified View)

### GET /messages

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

Messages with their Postfix and Rspamd data combined.

```json
{
  "total": 1234, "page": 1, "limit": 50, "pages": 25,
  "data": [
    {
      "correlation_key": "abc123def456...", "message_id": "<unique-id@example.com>", "queue_id": "ABC123DEF",
      "sender": "user@example.com", "recipient": "recipient@example.net", "subject": "Hello World",
      "direction": "outbound", "final_status": "delivered", "is_complete": true,
      "first_seen": "2025-12-25T10:30:00Z", "last_seen": "2025-12-25T10:30:05Z",
      "dovecot_status": "stored", "dovecot_mailbox": "INBOX", "deliveries": 1,
      "spam_score": 0.5, "is_spam": false, "user": "user@example.com", "ip": "192.0.2.100"
    }
  ]
}
```

**One row per message:** a message delivered more than once (a forward, a BCC copy, a quarantine release) has one correlation per delivery leg, but the list returns one row for it. Rows are grouped by Message-ID; a correlation without one is grouped by its own `correlation_key` and never merged. The filters apply to the legs first, and the earliest matching leg represents the message, so a search answers with the leg that matched. `deliveries` is the number of legs the message has in the database, including legs the filters did not match. `total` and `pages` count messages, not legs. The legs are listed in `related_deliveries` of the details endpoint.

**Dovecot fields:** `dovecot_status` is the outcome of the final LMTP hop: `stored`, `discarded`, `rejected`, `forwarded`, `failed`, or null without matching Dovecot information (such as mail delivered outside this server). `dovecot_mailbox` is the folder it was filed into. A message dropped by a Sieve `discard` rule gets `final_status` `discarded`, not `delivered`.

---

### GET /message/{correlation_key}/details

The message with its related logs. An unknown key returns 404; `rspamd` is null when the message was not scanned. `netfilter` contains at most 100 events for the Rspamd client IP within one hour before or after the scan.

```json
{
  "correlation_key": "abc123def456...",
  "message_id": "<unique-id@example.com>",
  "recipients": ["recipient@example.net", "cc@example.net"],
  "recipient_count": 2,
  "final_status": "delivered",
  "related_deliveries": [
    {"correlation_key": "789abc012def...", "sender": "recipient@example.net", "recipient": "forward-target@example.org", "direction": "outbound", "final_status": "rejected", "first_seen": "2025-12-25T10:30:07Z", "queue_id": "5D9C86E1234", "dovecot_status": null, "dovecot_mailbox": null}
  ],
  "rspamd": {"score": 0.5, "required_score": 15, "action": "no action", "symbols": {"MAILCOW_AUTH": {"score": -20, "description": "mailcow authenticated"}}, "is_spam": false, "ip": "192.0.2.100", "user": "user@example.com", "has_auth": true, "size": 1024},
  "dovecot": {"status": "stored", "mailbox": "Junk", "detail": null, "logs": [{"time": "2025-12-25T10:30:06Z", "message": "lmtp(recipient@example.net)...: stored mail into mailbox 'Junk'", "verdict": "stored", "recipient": "recipient@example.net", "mailbox": "Junk"}]},
  "postfix": [{"time": "2025-12-25T10:30:05Z", "program": "postfix/smtp", "message": "ABC123DEF: to=<recipient@example.net>, relay=...", "status": "sent", "relay": "mx.example.org[192.0.2.26]:25", "delay": 1.5, "dsn": "2.0.0"}],
  "postfix_by_recipient": {"recipient@example.net": [ ... ], "_system": [ ... ]},
  "netfilter": []
}
```

The top level also has the list fields (`queue_id`, `sender`, `recipient`, `subject`, `direction`, `is_complete`, `first_seen`, `last_seen`). `postfix_by_recipient` groups the Postfix lines by recipient; lines that belong to no recipient go under `_system`.

**`related_deliveries`:** the other legs of the same Message-ID, ordered by `first_seen`; empty for most messages. A forward, a Sieve redirect or another re-submission delivers the message again through its own Postfix queue chain, with its own sender, recipient, direction, status and `correlation_key`. The first leg keeps the key SHA256 of `msgid:<message-id>`, so older links still resolve; another leg is keyed by SHA256 of `msgid:<message-id>:queue:<queue-id>`.

**`dovecot`:** the outcome of the final LMTP hop. `status` is `stored`, `discarded`, `rejected`, `forwarded` or `failed`; `mailbox` is the folder; `detail` holds the reject reason, forward target or storage error; `logs` lists the matching raw Dovecot lines while raw log retention keeps them. Null without Dovecot information.

---

### GET /api/messages/facets

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `search`, `sender`, `recipient`, `direction`, `status`, `user`, `ip`, `start_date`, `end_date` | as in `GET /api/messages` | Unset | Same filters as the message list |
| `since` | array of strings | `[]` | Time ranges to count, as `name:ISO-start` (for example `today:2026-09-27T00:00:00Z`). Repeat the parameter for more ranges; up to 8 are read. `name` is 1 to 16 lower-case letters or digits; invalid entries are skipped. |

Filter counts for the message search: `status` (`delivered`, `deferred`, `bounced`, `rejected`, `spam`, `discarded`) and `direction` (`inbound`, `outbound`, `internal`), each with an `all` count. Each count applies the other filters but not its own. With `since`, `time` holds an `all` count and one count per valid range; these ignore `start_date` and `end_date`. Counts are messages, not legs.

---

### GET /api/message/{correlation_key}

The older compact detail form: identity and address fields, `direction`, `final_status`, `first_seen`, `last_seen`, `rspamd`, `postfix` and `timeline`, without Dovecot data or related deliveries. An unknown key returns 404.

---

## Logs

### Postfix Logs

#### GET /logs/postfix

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

Postfix logs grouped by queue ID, one row per queue; lines without a queue ID are left out. Paged like `GET /messages` (`total`, `page`, `limit`, `pages`, `data`). Each row has `id`, `time`, `program`, `priority`, `message`, `queue_id`, `message_id`, `sender`, `recipient`, `status`, `relay`, `delay`, `dsn` and `correlation_key`.

---

#### GET /logs/postfix/by-queue/{queue_id}

All Postfix lines of one queue ID, oldest first, with the linked Rspamd data. Returns `queue_id`, `correlation_key`, `rspamd` (`score`, `required_score`, `action`, `symbols`, `is_spam`, `direction`, `subject`) and `logs` (rows as in `GET /logs/postfix`). A queue ID without logs returns 404.

---

### Rspamd Logs

#### GET /logs/rspamd

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

Rspamd scan results, paged. Each row has `id`, `time`, `message_id`, `subject`, `size`, `sender_smtp`, `recipients_smtp` (array), `score`, `required_score`, `action`, `direction`, `ip`, `is_spam`, `has_auth`, `user`, `symbols` and `correlation_key`. `symbols` maps each symbol name to `{score, description}` or `{score, options}`.

---

### Netfilter Logs

#### GET /logs/netfilter

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

Stored Netfilter lines (failed logins, Fail2ban bans and unbans, other messages), newest first, paged. Each row has `id`, `time`, `priority`, `message`, `ip`, `rule_id`, `attempts_left`, `username`, `auth_method`, `action`, `country_code`, `country_name`, `city`, `asn` and `asn_org`.

#### GET /logs/netfilter/overview

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `hours` | integer | `24` | Period in hours, 1 to 168 |

Attempts against the server in the period, grouped by source address, for the Security page. Reads at most the 50,000 newest lines in the period.

```json
{
  "hours": 24, "attempts": 61, "failed_logins": 53, "source_count": 4,
  "sources": [
    {"ip": "198.51.100.23", "attempts": 38, "failed_logins": 38, "last_seen": "2025-12-25T10:30:00Z", "services": ["SMTP auth"], "usernames": ["admin@example.com"], "country_code": "NL", "country_name": "Netherlands", "city": "Amsterdam", "asn_org": "Example Hosting", "last_action": null}
  ],
  "latest": [
    {"time": "2025-12-25T10:30:00Z", "ip": "198.51.100.23", "username": "admin@example.com", "service": "SMTP auth", "country_code": "NL", "country_name": "Netherlands"}
  ]
}
```

Only lines where Netfilter matched a rule count as an attempt; the "N more attempts ... until banned" line that follows each one is not counted again. The service comes from the log text (SMTP auth, SMTP probe, IMAP, POP3, Sieve, SOGo, mailcow UI, Rspamd UI); failed logins are the attempts that are not SMTP probes. `sources` holds the 50 addresses with the most attempts, each with up to 5 `usernames`; `last_action` is the last Fail2ban `ban` or `unban` for the address in the period, or null. `latest` holds the 20 newest failed logins.

---

#### GET /api/logs/netfilter/countries

The recorded countries as an array of `{code, name}`, only entries with a country code. A read failure returns an empty array.

---

#### GET /api/logs/netfilter/stats/by-country

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `days` | integer | `30` | Days to look back, 1 to 365 |

Up to 10 countries, sorted by `warning`, then `total`. Returns `days`, `since` (the start of the retained history when it is shorter than the period) and `data`. Each row has `country_code`, `country_name`, `ban`, `unban`, `warning`, `total` and `addresses`. `warning` counts attempts (lines where Netfilter matched a rule), `ban` and `unban` count Fail2ban lines, `total` is their sum, and `addresses` counts distinct addresses with attempts. Lines without a stored country are located with GeoIP when it is available.

---

#### GET /api/logs/netfilter/stats/by-network

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `days` | integer | `30` | Days to look back, 1 to 365 |

Up to 8 networks (ASN) with the most attempts. Returns `days`, `since` and `data`; rows have `asn`, `asn_org`, `attempts` and `addresses`. Only attempt lines with a known ASN count; `asn_org` falls back to the ASN.

---

#### GET /api/security/addresses

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `list` | string | `review` | `review` or `banned` |
| `country` | string or null | Unset | Only addresses from this country, matched by name as in `countries[].country_name`; up to 100 characters |
| `after` | string or null | Unset | The `next` value from the previous page; up to 200 characters |
| `limit` | integer | `50` | Addresses per page, 1 to 200 |
| `q` | string or null | Unset | Only addresses whose IP contains this text; up to 100 characters |
| `network` | string or null | Unset | Only addresses from this network, matched by ASN organization as in `networks[].asn_org`; up to 200 characters |
| `days` | integer | `1` | Period in days (addresses that tried in the last N days), 1 to 365 |

The Security page's `review` or `banned` list, paged by cursor: pass the previous response's `next` as `after`. Cached for 10 seconds per period.

The response has `list`, `country`, `network`, `total`, `counts`, `all_counts`, `items`, `next`, `days`, `countries`, `networks`, `since` and `fail2ban_known`. `total` counts the requested list after `country`, `network` and `q`; `counts` gives both lists with those filters, `all_counts` without them. `countries` (top 10) and `networks` (top 8) count every address on either list in the period, ignoring the filters; their `review` and `banned` are attempt totals, not address counts. A false `fail2ban_known` means mailcow's current ban state was unavailable.

Each item has `ip`, `state`, `tries`, `attempts`, `users`, `services`, `hits`, `country`, `country_code`, `city`, `org`, `last_seen`, `f2b` and `listed_as`:

- `state`: `review` (open rule catch), `allow` (on the allowlist, shown under review), `quiet` (attempts only, shown under review), `banned` (rule ban or active Fail2ban ban) or `deny` (on the denylist, shown under banned)
- `tries` counts failed logins; `attempts` counts every attempt line
- `hits`: the address's open protection hits
- `f2b`: mailcow's active-ban entry, or null
- `listed_as`: the allowlist or denylist entry that holds the address, or null

---

### Fail2Ban Configuration

The write endpoints here need a read-write key. A missing or refused key returns 502. mailcow can refuse a change with HTTP 200 and `status: "error"` in the body, so check `status`.

#### GET /fail2ban

mailcow's Fail2ban configuration, passed through from `/api/v1/get/fail2ban`:

```json
{
  "ban_time": 1800, "ban_time_increment": false, "max_ban_time": 86400,
  "netban_ipv4": 32, "netban_ipv6": 128, "max_attempts": 10, "retry_window": 600,
  "manage_external": 0, "whitelist": "192.0.2.0/24\n198.51.100.0/24", "blacklist": "",
  "perm_bans": [], "active_bans": []
}
```

Times are seconds: `max_attempts` failures within `retry_window` trigger a `ban_time` ban; `ban_time_increment` lengthens repeat bans up to `max_ban_time`. `netban_ipv4` and `netban_ipv6` are the prefix sizes banned (32 = one IPv4 address). `manage_external` is the external-management flag (0 or 1), `perm_bans` the permanent bans, and `whitelist` and `blacklist` comma- or newline-separated address lists. Each entry of `active_bans` has `network`, `ip` and `queued_for_unban`.

No configuration from mailcow returns 503; a failed mailcow request 502.

#### POST /fail2ban

Replaces the Fail2ban configuration on mailcow. Send the complete configuration, unchanged values included, inside an `attr` object or as the top-level object:

```json
{ "attr": { "ban_time": "86400", "ban_time_increment": "1", "max_ban_time": "86400", "max_attempts": "5", "retry_window": "600", "netban_ipv4": "24", "netban_ipv6": "64", "whitelist": "192.0.2.0/24", "blacklist": "192.0.2.5/32" } }
```

Without `manage_external`, mailcow's current value is kept. Returns `{ "status": "success", "msg": ["fail2ban_edit_ok"] }` from mailcow's first result, plus `raw` when mailcow does not answer with a list. A body that is not valid JSON returns 500.

#### POST /fail2ban/ban

Adds an address to the denylist (`blacklist`). The lists are read fresh right before writing and every other setting is kept. Body: `{ "ip": "198.51.100.23/32" }`. Returns `{ "status": "success", "msg": "IP 198.51.100.23/32 added to blacklist" }`, or `IP ... is already in the blacklist`.

Send a single address with its prefix: `/32` for IPv4, `/128` for IPv6. mailcow reads a prefix as a network, so `2001:db8::1/32` would be all of `2001:db8::/32`; the web interface adds the right prefix. A missing `ip` returns 400; unreadable current settings 503.

#### POST /fail2ban/allow

Adds an address to the allowlist. Body `{ "ip": "192.0.2.10/32" }`. Same rules, errors and response as `ban`; success says `IP ... added to allowlist` (or `is already in the allowlist`).

#### POST /fail2ban/unban

Lifts an active ban with mailcow's unban action; the denylist and other settings do not change. Body `{ "ip": "198.51.100.23" }`; a bare address is sent as /32 (IPv4) or /128 (IPv6). Returns `status` and `msg` from mailcow's first result, plus `raw` when mailcow does not answer with a list. A missing `ip` returns 400; any mailcow failure 502.

---

#### POST /api/fail2ban/policy

Changes the ban policy and keeps the allowlist, denylist and external-management flag, which are read fresh right before writing.

Send `ban_time` and `max_ban_time` in seconds, each at least 60, with `max_ban_time` not shorter than `ban_time`; `max_attempts` (at least 1); `retry_window` (at least 1 second); `netban_ipv4` (8 to 32) and `netban_ipv6` (8 to 128). `ban_time_increment` is optional: `true`, `1` or `"1"` turns it on, anything else or leaving it out turns it off.

A value that is not a whole number, or out of range, returns 400; unreadable current settings 503. Success: `{ "status": "success", "msg": "Fail2ban policy saved" }`.

---

#### POST /api/fail2ban/remove

Removes an address from the denylist or allowlist and keeps the other settings. Body: `{ "ip": "192.0.2.10", "list": "blacklist" }`, with `list` `blacklist` or `whitelist`. `192.0.2.10` and `192.0.2.10/32` match the same entry, as do `2001:db8::1` and `2001:db8::1/128`; `2001:db8::1/32` is a network entry.

A missing IP or an invalid list returns 400; unreadable current settings 503. Returns `status` and `msg`; an absent entry answers `success` with `IP ... is not in the blacklist` (or `allowlist`).

---

#### POST /api/fail2ban/repair

Replaces an entry that an earlier version wrote as a /32 network for a single IPv6 address (`2001:db8::5/32`) with the address itself (`2001:db8::5/128`), in one edit, and reads the list back to confirm. Body: `{ "entry": "2001:db8::5/32", "list": "blacklist" }`, with `list` `blacklist` or `whitelist`.

An invalid list, or an entry that is not such a /32 entry, returns 400; unreadable current settings 503. Returns `status` and `msg`: `error` when the entry is no longer on the list, when mailcow refuses the change, or when the list read back does not show it.

---

#### GET /api/geoip/{ip}

The MaxMind location of an address: `{ "available": false }` without the City database, else `available: true`, `ip`, `country_code`, `country_name`, `city`, `asn` and `asn_org`. A field is null when the address is not found; `asn` and `asn_org` are also null without the ASN database.

---

## Queue & Quarantine

The reads come live from mailcow. The write endpoints take `{ "items": [...] }` and need a read-write key. They answer HTTP 200 with `status` (`success` or `error`) and `msg` from mailcow's first result, plus `raw` when mailcow does not answer with a list, so check `status`. Missing `items` returns 400; a missing or refused key, or no answer from mailcow, returns 502.

### GET /queue

The mail queue: `{ "total": 5, "data": [ ... ] }`.

```json
{"queue_name": "deferred", "queue_id": "ABC123DEF", "arrival_time": 1735123456, "message_size": 515749, "forced_expire": false, "sender": "sender@example.com", "recipients": ["user@example.com (connect to example.com[192.0.2.10]:25: Connection timed out)"]}
```

`arrival_time` is a Unix timestamp; each recipient carries the last delivery error.

---

### POST /queue/action

Body: `{ "items": ["ABC123DEF"], "action": "deliver" }`. Sent to mailcow's `POST /api/v1/edit/mailq`.

| Action | Effect |
|--------|--------|
| `deliver` | Retry delivery of the message |
| `hold` | Put the message on hold (no delivery attempts) |
| `unhold` | Release a held message |
| `flush` | Retry every queued message. Use `items: ["mailqitems-all"]`. |
| `super_delete` | Delete every message in the queue. Use `items: ["mailqitems-all"]`. |

An invalid action returns 400.

---

### POST /queue/delete

Deletes the queue IDs in `items` through mailcow's `POST /api/v1/delete/mailq`. To delete everything, use `POST /queue/action` with `super_delete`.

---

### GET /quarantine

The quarantined messages: `{ "total": 3, "data": [ ... ] }`, each with `id`, `subject`, `sender`, `rcpt`, `created`, `action`, `score`, `virus_flag` and `qid`. The write endpoints below take these `id` values in `items`.

---

### POST /quarantine/release

Delivers the messages to their original recipients (mailcow `edit/qitem`, action `release`).

---

### POST /quarantine/delete

Deletes the messages for good; they cannot be recovered (mailcow `delete/qitem`).

---

### POST /quarantine/learnham

Releases the messages and teaches Rspamd they are not spam (mailcow `edit/qitem`, action `learnham`).

---

### POST /quarantine/learnspam

Deletes the messages and teaches Rspamd they are spam (mailcow `edit/qitem`, action `learnspam`).

---

### GET /quarantine/{item_id}/details

One quarantined message with its headers, Rspamd symbols, body and fuzzy hashes, from mailcow's `/inc/ajax/qitem_details.php?id={item_id}` (the first element of its answer). A mailcow failure returns 502.

```json
{
  "recipients": [{"address": "user@example.com", "type": "to"}, {"address": "user@example.com", "type": "smtp"}],
  "header_from": "Sender Name <sender@example.com>",
  "env_from": "sender@example.com",
  "score": 9.72,
  "action": "add header",
  "symbols": [{"group": "hfilter", "name": "HFILTER_URL_ONLY", "groups": ["hfilter"], "weight": 8.2, "score": 8.2, "options": ["1"]}],
  "subject": "Test email",
  "text_plain": "Email body content...",
  "text_html": null,
  "fuzzy_hashes": [{"type": "text", "hash": "abc123..."}]
}
```

`header_from` is the header sender, `env_from` the envelope sender.

---

## Statistics

### GET /stats/dashboard

Current counts:

- `messages`: `24h`, `7d` and `30d` delivery-leg counts, plus `unique_24h` and `unique_7d` message counts.
- `blocked`: `24h`, `7d` and `percentage_24h` for bounced, rejected and spam.
- `deferred` and `auth_failures`: `24h` and `7d`.
- `direction`: `inbound_24h`, `outbound_24h`, `internal_24h`.

A read failure can return HTTP 200 with `error` and zero values, so check `error`.

---

### GET /stats/flow

The Dashboard's mail flow: counts per bar, in the app's time zone. Give either `period`, or `from`, `to` and `bucket`.

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `period` | string | none | `24h` (24 hourly bars), `7d` (28 bars of 6 hours) or `30d` (30 daily bars), the last one up to now |
| `previous` | boolean | `false` | With `period`: the same number of bars right before it |
| `from`, `to` | string | none | A range of instants (ISO 8601), at most 62 days; it snaps to the nearest bar edges, at least one bar, and stops at now |
| `bucket` | string | none | With `from` and `to`: `hour`, `6h` or `day` |

Bars follow the app zone's clock, so a day can be 23 or 25 hours long. Each bar in `buckets` has `start`, `end`, `end_inclusive` (its last microsecond), `partial` (still running), `messages` (each message once, in the bar of its earliest delivery in the range), `deliveries`, `blocked` (bounced, rejected or spam), `deferred`, `auth_failures`, and Rspamd `clean` and `spam`. The answer also has `totals`, `from`, `to`, `to_inclusive`, `bucket`, `zone`, `as_of`, and `older_may_be_gone` (the range starts before the retention period, so older logs may be deleted). A bad parameter returns 422.

---

### GET /stats/timeline

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `hours` | integer | `24` | How many hours back to chart, one bucket per hour |

`{ "timeline": [ {"hour": "2025-12-25T08:00:00Z", "total": 45, "spam": 2, "clean": 43} ] }`

---

### GET /stats/top-spam-triggers

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `limit` | integer | `10` | Number of symbols to return |

The Rspamd symbols seen most often on spam in the last 7 days: `{ "triggers": [ {"symbol": "RCVD_IN_DNSWL_NONE", "count": 456} ] }`. A read error returns `{ "triggers": [], "error": "..." }` with HTTP 200.

---

### GET /stats/top-blocked-ips

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `limit` | integer | `10` | Number of addresses to return |

The addresses with the most Netfilter (Fail2ban) lines in the last 7 days: `{ "blocked_ips": [ {"ip": "198.51.100.53", "count": 45, "last_seen": "2025-12-25T10:30:00Z"} ] }`. A read error returns `{ "blocked_ips": [], "error": "..." }` with HTTP 200.

---

### GET /stats/recent-activity

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `limit` | integer | `20` | Number of messages to return |

The most recently updated messages, newest first: `{ "activity": [ ... ] }`, each with `time`, `sender`, `recipient`, `subject`, `direction`, `status` and `correlation_key`.

---

## Status

### GET /status/containers

The mailcow containers. Containers mailcow stopped reporting stay listed from the app's records.

```json
{
  "containers": {
    "postfix-mailcow": {"name": "postfix", "state": "running", "started_at": "2025-12-20T08:00:00Z", "ignored": false},
    "ipv6nat-mailcow": {"name": "ipv6nat", "state": "exited", "started_at": null, "ignored": true}
  },
  "summary": {"running": 18, "stopped": 0, "total": 18, "ignored": 1}
}
```

An ignored container is listed but not counted: `running`, `stopped` and `total` leave it out, and `ignored` counts them. The dashboard alert and the problem counters follow the summary.

---

### PUT /status/containers/{container}/ignore

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `ignored` | boolean | Required | `true` to ignore the container, `false` to count it again |

Ignores a container by its full name, for example `ipv6nat-mailcow` on a server without IPv6, for every user. Returns `{ "container": "ipv6nat-mailcow", "ignored": true }`. A name the app has never seen returns 404.

---

### GET /status/storage

mailcow's mail storage: `{ "disk": "/dev/sda1", "used": "45G", "total": "100G", "used_percent": "45%" }`.

---

### GET /status/version

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `force` | boolean | `false` | Force a fresh version check |

The running mailcow version against the latest mailcow release on GitHub, checked at most once a day unless `force` is set. Returns `current_version`, `latest_version`, `update_available`, `changelog` and `last_checked`.

---

### GET /status/app-version

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `force` | boolean | `false` | Force a fresh version check |

This app's version against its latest GitHub release, with the same fields as `GET /status/version`; `changelog` is the release's Markdown. The scheduler checks every 6 hours; the endpoint checks itself when the stored result is missing or more than a day old, or with `force`. On failure it returns HTTP 200 with the running version, `latest_version: "unknown"` and `error`.

---

### GET /status/app-version/changelog/{version}

The Markdown changelog of one GitHub release, with or without the `v` prefix: `{ "version": "1.4.6", "changelog": "..." }`. An unknown version returns HTTP 200 with `changelog` set to `Changelog not found for this version`.

---

### GET /status/mailcow-connection

`{ "connected": true, "timestamp": "..." }`: whether the mailcow API answers, with the current UTC time.

---

### GET /status/mailcow-info

Total and active counts from mailcow: `{ "domains": {"total": 5, "active": 5}, "mailboxes": {"total": 25, "active": 23}, "aliases": {"total": 50, "active": 48} }`.

---

### GET /status/summary

Containers, storage and mailcow counts in one call, for the dashboard: `containers` (the summary of `GET /status/containers`), `storage` (`used_percent`, `used`, `total`) and `system` (`domains`, `mailboxes`, `aliases` totals). A part that cannot be read falls back to zeros.

---

## Settings

Secrets are always returned masked as `********` (empty when not set): `mailcow_api_key`, `mailcow_api_key_rw`, `rspamd_password`, `auth_password`, `oauth2_client_secret`, `smtp_password`, `dmarc_imap_password`, `session_secret_key` and `maxmind_license_key`.

### GET /api/settings/info

Configuration, import state, correlation state and background job state, for the Status and Settings pages. Shape, shortened:

```json
{
  "settings_edit_via_ui_enabled": true,
  "settings_migrated": true,
  "editable_config": {"mailcow_url": "https://mail.example.com", "mailcow_api_key": "********", "...": "..."},
  "configuration": {
    "mailcow_url": "https://mail.example.com",
    "server_ip": "192.0.2.10",
    "local_domains": ["example.com"],
    "database_version": "16.4",
    "auth_username": "admin",
    "oauth2_provider_name": null,
    "maxmind_status": {"configured": true, "valid": true, "error": null, "checked_at": "2026-05-15T14:30:00Z"},
    "mailcow_rw_key_status": {"configured": true, "valid": true, "error": null, "checked_at": "2026-10-07T09:12:00Z"},
    "rspamd_password_status": {"configured": true, "valid": true, "error": null, "checked_at": "2026-10-07T09:12:01Z"},
    "...": "..."
  },
  "import_status": {
    "postfix": {"last_import": "2025-12-25T10:30:00Z", "last_fetch_run": "2025-12-25T10:35:00Z", "total_entries": 50000, "oldest_entry": "2025-12-18T00:00:00Z"},
    "rspamd": { "...": "..." },
    "netfilter": { "...": "..." }
  },
  "correlation_status": {"last_update": "2025-12-25T10:30:00Z", "total": 40000, "complete": 39500, "incomplete": 500, "expired": 100, "completion_rate": 98.75},
  "background_jobs": {
    "complete_correlations": {"interval": "120 seconds (2 minutes)", "description": "Links Postfix logs to messages", "status": "running", "last_run": "2026-01-08T12:13:56Z", "error": null, "pending_items": 93}
  },
  "recent_incomplete_correlations": [
    {"message_id": "<unique-id@example.com>", "queue_id": "ABC123", "sender": "user@example.com", "recipient": "other@example.net", "created_at": "2025-12-25T10:28:00Z", "age_minutes": 2}
  ]
}
```

- `configuration` also holds the effective fetch, retention, correlation, title, log level, blacklist, export, scheduler and sign-in values.
- `editable_config`, `default_config` and `settings_migrated` are present only while UI editing is on.
- `auth_username` is null unless Basic is on; `oauth2_provider_name` is null unless OAuth2 is on.
- `mailcow_rw_key_status` and `rspamd_password_status` are `{"configured": false, "valid": false, "error": null}` without that credential, and null when it has not been checked since it or its address last changed.
- The response also has `smtp_configuration`, `dmarc_configuration`, `geoip_configuration` and `raw_logs_required`. Without MaxMind credentials, `geoip_configuration.databases` is `{"City": {"installed": false, "version": null, "last_updated": null}, "ASN": {...}}`.
- If the data cannot be read, the response is still 200, with `error` set and empty `configuration`, `import_status`, `correlation_status` and `background_jobs`.

`background_jobs` has one entry per job (29). What each job does is in the [Background Jobs List](#background-jobs-list).

| Field | Description |
|-------|-------------|
| `interval` / `schedule` | How often the job runs. A job that is off says why, such as `Disabled (feature off)`. |
| `status` | See [Status Values](#status-values) |
| `last_run` | Time of the last run, or null |
| `error` | Error of the last failed run, else null |
| `pending_items` | Items waiting (correlation jobs only) |
| `max_age` / `expire_after` / `retention` | The job's own setting |
| `services` | Raw log services collected (`fetch_raw_logs` only) |
| `enabled`, `feature_disabled`, `disabled_reason`, `settings_section` | Whether the job can run, why not, and which settings section controls it |

---

### GET /api/settings

The editable settings, for the Settings page. Readable while UI editing is off; saved values are loaded only while it is on.

```json
{
  "settings_edit_via_ui_enabled": true,
  "settings_migrated": true,
  "configuration": {"mailcow_url": "https://mail.example.com", "mailcow_api_key": "********", "fetch_interval": 60, "smtp_port": 587, "...": "..."},
  "default_config": { "...": "..." },
  "env_locked_keys": ["mailcow_url", "mailcow_api_key"]
}
```

`configuration` has one key per editable setting, named like its variable in lower case. `default_config` holds the defaults. `env_locked_keys` lists the settings an environment variable sets; the variable always wins over the saved value. It is empty while UI editing is off. The PostgreSQL settings, `SETTINGS_EDIT_VIA_UI_ENABLED`, `AUTH_ENABLED`, `TZ`, `APP_PORT`, `CORS_ALLOWED_ORIGINS` and the legacy `WEBHOOK_*` settings are not included.

---

### PUT /api/settings

Saves settings to the database. Needs `SETTINGS_EDIT_VIA_UI_ENABLED=true`, else 403. The body is a JSON object of setting keys from `GET /api/settings`, with no wrapper:

```json
{ "fetch_interval": 120, "retention_days": 14, "smtp_password": "********", "admin_email": "admin@example.com" }
```

- Omit a key to leave it unchanged. `null` is kept for optional fields and becomes an empty string, zero or false for others; it does not reset to the default.
- For a secret, `********` keeps the stored value and `""` clears it.
- A key an environment variable sets can be saved, but has no effect while the variable is set; no error is returned. Keys that are not editable settings are ignored.
- A changed server or account address cannot reuse a masked stored secret; send the secret again for the new destination.

After saving, the app reloads the settings, the mailcow client and the OAuth2 client, reschedules the interval jobs, and deletes some data of features that are now off (see [purge-feature-data](#post-apisettingspurge-feature-data)). Changing sign-in settings revokes existing sessions; the caller gets a replacement session cookie.

Returns `settings_edit_via_ui_enabled`, `settings_migrated`, `configuration`, `mailcow_rw_key_changed` and `rspamd_password_changed`. Each `*_changed` is `true` when that credential is set after the save and it, or the address it is sent to, changed. A body with no editable change saves nothing and returns the configuration without these two keys.

`rspamd_off_transition` is a token when this save turned Suppressions or Sync with Rspamd off, else `null` (also when it was already off); pass it to `POST /api/suppressions/rspamd/clear` or `purge-feature-data` so a late removal is refused once another save switched again. The Settings page removes nothing without it. `feature_data_errors`, `{part: error}`, is present when deleting the data of a feature that is off failed; the sweep the save starts tries again.

#### Basic Auth Lockout Prevention

When the body sends `basic_auth_enabled` as JSON `true` while Basic is off, it must also confirm the credentials (a string such as `"true"` skips this check):

| Field | Must match |
|-------|------------|
| `verify_username` | `auth_username` in the request, or the stored username (default `admin`) when the request does not change it |
| `verify_password` | `auth_password` in the request, or the stored password when the request omits it or sends `********` |

**Errors (400 unless noted), with their `detail`:**

- UI editing off (403): `Editing settings from UI is disabled. Set SETTINGS_EDIT_VIA_UI_ENABLED=true to enable.`
- Validation: `Invalid settings for: smtp_port`, or `Invalid settings. Check the submitted values.` when no field can be named.
- Unknown feature in `disabled_features`: `disabled_features accepts only known feature names.`
- A server address changed but its stored secret was not sent again: `You changed the server the {names} is sent to. Enter the {names} again: ...`
- A server address changed for a secret set by an environment variable: `The {label} is set by the {SECRET} environment variable, so it can only be sent to a different server from there. ...`
- An invalid address in `admin_email`, `blacklist_alert_email` or `dmarc_error_email`: `{label}: "{bad}" is not an email address. Separate several addresses with commas.`
- Clearing the password while Basic is on: `Cannot clear the password while Basic Auth is enabled. Disable Basic Auth first, or set a new password.`
- Turning Basic on without a password: `Cannot enable Basic Auth without a password. Please set a password first.`
- Turning Basic on without `verify_username` and `verify_password`: `Credential verification required. Please confirm your username and password to enable Basic Auth.`
- Credentials that do not match: `Credential verification failed. The username and password you entered do not match the configured credentials.`

---

### POST /api/settings/import-from-env

Copies every current effective setting (defaults, ENV and saved values) into the database, so you can manage them on the Settings page. Needs UI editing on, else 403. Returns `message`, `settings_edit_via_ui_enabled`, `settings_migrated` (true), `configuration` and `env_locked_keys`.

Afterwards remove only the optional variables you want to manage in the UI. Keep `MAILCOW_URL`, `MAILCOW_API_KEY`, the database values and `SETTINGS_EDIT_VIA_UI_ENABLED`: the app reads them before it loads saved values.

---

### POST /api/settings/purge-feature-data

Deletes all stored data of a feature that is already off (in `disabled_features`). Cannot be undone. Needs UI editing on, else 403. Body: `{ "feature": "dmarc" }`.

| Feature | Tables emptied |
|---------|-----------------|
| `netfilter` | `netfilter_logs` |
| `domains` | `domain_dns_checks` |
| `dmarc` | `dmarc_reports`, `dmarc_records`, `dmarc_syncs`, `tls_reports`, `tls_report_policies` |
| `mailbox-stats` | `alias_statistics`, and `mailbox_statistics` unless Rate Limits is on (it reads each mailbox's limit from that table) |
| `logs` | `raw_service_logs`, only the services nothing collects any more: `dovecot` always stays because message details read it, `ratelimited` stays while Rate Limits is on, `sogo` while Devices is on |
| `blacklist` | `blacklist_checks`, `monitored_hosts` |
| `suppressions` (also its old name `spam-filter`) | `suppression_events`, `spam_suppressions`. The body also needs `"rspamd": "remove"` or `"keep"` for the app's blocks in Rspamd, else 400, and may carry `"transition"` (see `PUT /api/settings`). With `remove`, the list is deleted only after mailcow confirmed the blocks are gone; otherwise it answers 409 or 502 and deletes nothing |
| `quarantine` | `quarantine_rules`, `quarantine_rule_logs` |
| `devices` | `eas_devices` |

Tables are truncated with `CASCADE`. Returns `{ "feature": "dmarc", "tables_purged": {"dmarc_records": 1523, "...": 0}, "total_rows_deleted": 1679 }`.

An unknown feature returns 400 (`Unknown feature: ...`), and so do features without tables, such as `queue`, `rspamd` and `rate-limits`. A feature that is still on returns 400 (`Feature 'dmarc' is currently enabled. Disable it first.`). A failure returns 500 (`Purge failed. Check the application logs.`) and deletes nothing.

`PUT /api/settings` already deletes some data of features that are off: alias statistics, mailbox statistics (when Mailbox Stats and Rate Limits are both off), ActiveSync devices, raw log rows nothing collects and the Rate Limits reset history. The Settings page then calls this endpoint for each newly disabled feature, after confirming that data will be deleted.

---

### GET /settings/health

Database health with timing. Unlike `GET /api/health`, it needs authentication when sign-in is on.

```json
{ "status": "healthy", "timestamp": "2025-12-25T10:30:00Z", "database": {"status": "connected", "response_time_ms": 1.25}, "recent_activity": {"last_5_minutes": {"postfix_imported": 45, "rspamd_imported": 42, "correlations_created": 40}} }
```

A database failure returns 200 with `"status": "unhealthy"`, `timestamp` and `error`.

---

### POST /api/settings/jobs/{job_name}/run

Starts a background job now and returns at once: `{ "status": "started", "job": "fetch_logs", "message": "Job fetch_logs started in background" }`. `job_name` is any ID from [Job Status Data Structure](#job-status-data-structure), including `sync_local_domains`.

An unknown job returns 404. A job that cannot run returns 409 with `The job cannot run.` and the reason, such as its feature being off or a missing read-write key (**Status** > **Jobs** shows the same reason). A job already running returns 409.

---

## GeoIP Management

### GET /api/settings/geoip/status

GeoIP state, polled by the GeoIP setup window during a download.

```json
{
  "configured": true,
  "db_valid": true,
  "databases": {
    "configured": true, "db_valid": true,
    "City": {"available": true, "age_days": 1, "size_mb": 62.3, "last_modified": "2026-04-22T10:00:00"},
    "ASN": {"available": true, "age_days": 0, "size_mb": 11.3, "last_modified": "2026-04-22T18:00:00"}
  },
  "job_status": "success", "job_error": null, "job_last_run": "2026-04-22T18:00:05Z"
}
```

`configured` means the MaxMind Account ID and License Key are set. `db_valid` is true when the databases passed validation, false when they are corrupt, null when not checked yet. `job_*` describe the last Update GeoIP run.

---

### POST /api/settings/geoip/download

Starts downloading the GeoLite2 City and ASN databases that are missing or 7 or more days old, and returns at once: `{ "status": "started", "message": "GeoIP download started in background" }`. Fresh files are kept. After the download the readers are reloaded and validated.

Poll `GET /api/settings/geoip/status`. `job_status` turns `running` only when the task starts, so the first poll can still show the previous result. Without the MaxMind Account ID or License Key, 400 (`MaxMind license key not configured`).

---

### POST /api/settings/maxmind/validate

Checks the MaxMind license key against MaxMind's `secret-scanning.maxmind.com` (5-second timeout) and stores the result, which `maxmind_status` in `GET /api/settings/info` then returns.

Returns `{ "configured": true, "valid": false, "error": "Invalid" }`. `error` is `Invalid`, `Connection error` or `Status {code}`; without a key, `{ "configured": false, "valid": false, "error": null }`.

A `PUT /api/settings` that includes `maxmind_account_id`, or a `maxmind_license_key` other than `********`, clears the stored result. Any Update GeoIP run that ends with a City or ASN file on disk stores the license as valid.

---

### POST /api/settings/mailcow/rw-key/validate

Checks that mailcow accepts the read-write key for writes, without changing anything, and stores the result for `mailcow_rw_key_status` in `GET /api/settings/info`. The Settings page calls it after a new or changed key or mailcow URL is saved, and from **Validate**.

Returns `{ "configured": true, "valid": false, "error": "rejected", "http_status": 401 }`. `error`:

- `rejected` (401): wrong or inactive key, or this server's IP is not allowed for the key
- `read_only` (403): a read-only key
- `connection`: mailcow not reachable
- `unexpected`: any other answer

`http_status` is present when mailcow answered with an error. Without a key: `{ "configured": false, "valid": false, "error": null }`, not stored.

It sends one `POST /api/v1/edit/mlv-key-check`. mailcow checks the key and its allowed IPs before routing, so an accepted key gets `404 route not found` and nothing changes. There is no retry, because every rejected key also counts as a failed login for mailcow's Fail2ban.

---

### POST /api/settings/rspamd/password/validate

Checks that Rspamd accepts the Rspamd password, the way the Rspamd web UI logs in, without changing anything. Stores the result for `rspamd_password_status`. The Settings page calls it after a new or changed password, Rspamd URL or mailcow URL is saved, and from **Validate**.

Same response shape as the read-write key check. `error`:

- `rejected` (401 or 403): wrong password
- `redirected`: a proxy answered with a redirect before Rspamd saw the password; set `RSPAMD_URL`
- `connection`: Rspamd not reachable
- `unexpected`: any other answer

It sends one `GET /rspamd/auth` with the `Password` header, through the mailcow proxy or straight to `RSPAMD_URL` when set; an accepted password gets `200` with `"auth": "ok"`. No retry: a wrong password also counts as a failed login for mailcow's Fail2ban.

---

### POST /api/settings/geoip/validate

Reloads the GeoIP readers and looks up 8.8.8.8 and 1.1.1.1. Returns `{ "valid": true, "city_ok": true, "asn_ok": true, "db_valid": true }`. Only the City lookup decides `valid`; `db_valid` is the stored state after the reload. A missing file returns `valid: false` with `error`, such as `City database file not found`.

---

## SMTP & IMAP Test

Both tests take no body and return `success` and `logs`, the steps in order. In the real output the final success line starts with a check mark and each failure line with a cross mark.

### POST /api/settings/test/smtp

Connects (SSL when `SMTP_USE_SSL` is on or the port is 465, else STARTTLS when `SMTP_USE_TLS` is on), logs in (skipped in relay mode) and sends a test email to the valid addresses in `ADMIN_EMAIL`, or to `SMTP_USER` when `ADMIN_EMAIL` is empty. With no valid address left, the test fails. It sends even while normal SMTP delivery is off.

```json
{ "success": false, "logs": ["Starting SMTP connection test...", "Host: mail.example.com", "Port: 587", "...", "Logging in...", "Authentication failed: (535, b'5.7.8 Error: authentication failed')"] }
```

---

### POST /api/settings/test/imap

Connects, logs in, lists the folders (up to 5 shown), opens the configured folder read-only and counts its messages. Changes no email.

```json
{ "success": true, "logs": ["Starting IMAP connection test...", "Host: mail.example.com", "...", "Selecting folder: INBOX", "Folder selected: 42 messages", "Connection closed", "IMAP test completed successfully"] }
```

---

## Export

- CSV in UTF-8 with a byte order mark, so spreadsheets detect non-English text; decode with `utf-8-sig` in code.
- Newest rows first, at most `CSV_EXPORT_LIMIT` rows (default 10,000).
- Streamed from the database in batches of 500; the web interface still buffers the whole file before saving it.
- Each route also answers `HEAD` with the same headers and no body.
- Text that starts like a formula is prefixed with an apostrophe; numbers, including negative scores, keep their values. Saving and reopening the file in a spreadsheet can remove this escaping, so treat exported content as untrusted when importing it elsewhere.

### GET /export/postfix/csv

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `search` | string or null | Unset | Substring of the log message, sender, recipient or queue ID |
| `sender` | string or null | Unset | Substring of the sender |
| `recipient` | string or null | Unset | Substring of the recipient |
| `status` | string or null | Unset | Exact Postfix status |
| `start_date` | datetime or null | Unset | Earliest log time (ISO 8601) |
| `end_date` | datetime or null | Unset | Latest log time (ISO 8601) |

One row per log line. Columns: Time, Program, Priority, Queue ID, Message ID, Sender, Recipient, Status, Relay, Delay, DSN, Message.

---

### GET /export/rspamd/csv

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

Columns: Time, Message ID, Subject, Sender, Recipients, Score, Required Score, Action, Direction, Is Spam, Has Auth, User, IP, Size, Top Symbols.

---

### GET /export/netfilter/csv

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `search` | string or null | Unset | Substring of the log message, IP or username |
| `ip` | string or null | Unset | Substring of the IP |
| `username` | string or null | Unset | Substring of the username |
| `action` | string or null | Unset | Exact action, as in the Events list; `ban` also matches older `banned` lines |
| `country_code` | string or null | Unset | Two-letter country code, in any case |
| `start_date` | datetime or null | Unset | Earliest log time (ISO 8601) |
| `end_date` | datetime or null | Unset | Latest log time (ISO 8601) |

The filters of the Security **Events** list. Columns: Time, IP, Username, Auth Method, Action, Attempts Left, Rule ID, Priority, Message.

---

### GET /export/messages/csv

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `search` | string or null | Unset | Substring of sender, recipient, subject, Message-ID, queue ID, Rspamd client IP or Rspamd user |
| `sender` | string or null | Unset | Substring of the sender |
| `recipient` | string or null | Unset | Substring of the recipient |
| `direction` | string or null | Unset | Exact direction |
| `status` | string or null | Unset | Exact final status; `spam` also matches messages Rspamd classed as spam |
| `user` | string or null | Unset | Substring of the Rspamd user |
| `ip` | string or null | Unset | Substring of the Rspamd client IP |
| `start_date` | datetime or null | Unset | Earliest `first_seen` (ISO 8601) |
| `end_date` | datetime or null | Unset | Latest `first_seen` (ISO 8601) |

<!-- VERIFY: owner's decision pending (finding 20): one row per delivery leg, ordered by latest activity. Update this sentence once decided. -->
Export messages to a CSV file, one row per delivery leg. The filters mean what they mean in `GET /api/messages`, and blacklisted correlations are left out as there.

Columns: Time, Sender, Recipient, Subject, Direction, Status, Queue ID, Message ID, Spam Score, Is Spam, User, IP, Is Complete.

---

## DMARC

Protocol background and what to do with the results are in [DMARC & TLS](HelpDocs/DMARC.md). Unix timestamps below are seconds.

### GET /api/dmarc/reports/config

`{ "allow_delete": false }`, from `DMARC_ALLOW_REPORT_DELETE` (off by default).

---

### POST /api/dmarc/cache/clear

Clears the in-memory cache of `GET /api/dmarc/domains` (5 minutes) in every app process. No body. Returns `{ "status": "success", "message": "Cache cleared" }`.

---

### GET /api/dmarc/reports/all

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `page` | integer or null | Unset | Page number, at least 1. Omit it for the older unpaginated response. |
| `limit` | integer | `50` | Reports per page, 1 to 200. Used only with `page`. |
| `search` | string or null | Unset | Keeps the reports whose domain or reporter (`org_name`) contains this text, in any case. `%`, `_` and `\` match literally. Leading and trailing spaces are ignored, only the first 255 characters are used, and an empty value lists every report. |
| `sort_by` | string | `created_at` | Orders a paged request by `created_at` (import date), `type`, `domain`, `reporter`, `records` (record or policy count) or `period` (start of the report period). Domain and reporter compare in lower case. Any other value returns `422`. |
| `sort_dir` | string | `desc` | `asc` or `desc`; any other value returns `422`. |

DMARC and TLS report summaries together, newest import first. Each report has `id`, `type` (`dmarc` or `tls`), `domain`, `org_name`, `begin_date`, `end_date`, `record_count`, `created_at` and `report_id`.

With `page`, the response has `reports`, `total`, `allow_delete`, `page`, `limit`, `total_pages`, `sort_by` and `sort_dir`. The sort covers both types and is applied before paging; empty values sort last, and ties fall back to the newest import, then type, then the highest ID. An empty result is page 1 of 1, and a page past the end is clamped to the last page. Imports or deletions between requests can shift reports; reload from page 1. Without `page`, the response has only `reports`, `total` and `allow_delete`, newest first, and ignores the sort. `total` counts the reports that match `search`.

---

### GET /api/dmarc/reports/domains

Report counts per domain, sorted by name. Domain names are compared trimmed and in lower case, so `Example.com` and `example.com` are one domain.

```json
{ "domains": [ {"domain": "example.com", "dmarc_reports": 42, "tls_reports": 7, "last_report": 1767312000} ], "allow_delete": false }
```

`last_report` is the end of the domain's latest report period (DMARC or TLS), as a Unix timestamp, or null.

---

### DELETE /api/dmarc/reports/domains/{domain}

Deletes every DMARC and TLS report of one domain, with their records and policies, in one transaction. Cannot be undone. The domain is matched trimmed and in lower case. Reports that arrive later for it are imported as usual. Each deletion is written to the application log.

Returns `{ "status": "success", "domain": "example.com", "dmarc_reports": 42, "dmarc_records": 310, "tls_reports": 7, "tls_policies": 7 }`. 403 unless `DMARC_ALLOW_REPORT_DELETE=true`; 400 for an empty domain or one longer than 255 characters; 404 when the domain has no reports.

---

### DELETE /api/dmarc/reports/{report_type}/{report_id}

Deletes one report and its records or policies. `report_type` is `dmarc` or `tls`; `report_id` is the database ID. Returns `{ "status": "success", "message": "DMARC report deleted" }` (or `TLS report deleted`).

Deletion off returns 403; an unknown type 400; a non-integer ID 422; a missing report 404.

---

### GET /api/dmarc/domains

Every domain with DMARC or TLS reports, newest `last_report` first, with 30-day statistics.

```json
{
  "domains": [
    {
      "domain": "example.com",
      "report_count": 42, "tls_report_count": 7,
      "first_report": 1764547200, "last_report": 1767312000,
      "has_dmarc": true, "has_tls": true,
      "tls_rpt_status": "success", "tls_first_report": 1764547200, "tls_last_report": 1767225599,
      "stats_30d": {"total_messages": 8234, "unique_ips": 89, "dmarc_pass_pct": 98.5, "tls_success_pct": 100.0, "tls_sessions": 1520},
      "failing_sources": 2,
      "dmarc_record": {"checked": true, "found": true, "status": "success", "policy": "reject"},
      "tls_rpt_record": {"checked": true, "found": true, "status": "success"},
      "on_mailcow": true
    }
  ],
  "total": 1,
  "daily": [ {"date": "2026-01-01", "total": 310, "dmarc_pass": 305, "dmarc_fail": 5} ]
}
```

- `first_report` and `last_report`: start of the first and end of the last DMARC report period (TLS for a domain with only TLS reports).
- `stats_30d` covers reports that started in the last 30 days. `dmarc_pass_pct` counts messages where aligned SPF or aligned DKIM passed (RFC 7489). With no messages or sessions, `dmarc_pass_pct` is `0` and `tls_success_pct` is `100`, so check `total_messages` and `tls_sessions` before reading them as rates.
- `tls_rpt_status`: result of the last stored DNS check of the TLS-RPT record, or null when not checked. Scheduled DNS checks run every 6 hours for active mailcow domains and their alias domains.
- `dmarc_record` and `tls_rpt_record`: from the stored DNS check, or looked up live for a domain without one (a domain not in mailcow). `checked` is false when the record could not be read; `policy` is set when a DMARC record was found.
- `failing_sources`: source IPs that failed DMARC for most of their mail in the last 30 days.
- `on_mailcow`: whether the domain is an active domain or alias domain on this mailcow server, null while the server's domains are not known yet. Read on every request, not cached.
- `daily`: messages per day across every domain in the last 30 days.

The list is cached for 5 minutes. Uploads, IMAP imports, deletions, retention cleanup and `POST /api/dmarc/cache/clear` clear it sooner.

---

### GET /api/dmarc/domains/{domain}/overview

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `days` | integer | `30` | How many days back to read, by report start date |

Report summary and DNS record state for one domain: `domain`, `policy`, `daily_stats`, `totals`, `dmarc_record`, `tls_rpt_record` and `on_mailcow`.

- `policy`: `p`, `sp`, `pct`, `adkim` and `aspf` from the latest report in the period, with defaults `p: "none"`, `pct: 100`, `adkim: "r"`, `aspf: "r"` for missing tags; null without reports.
- `daily_stats` rows: `date`, `total`, `dmarc_pass`, `dmarc_fail`, `spf_pass`, `dkim_pass`.
- `totals`: `total_messages`, `dmarc_pass`, `dmarc_fail`, `unique_ips`, `unique_reporters`, and `dmarc_pass_pct` when reports exist.
- `dmarc_record` and `tls_rpt_record` are full DNS check results (`status`, `message`, `record` and more), from the stored check or a live one; `dmarc_record.settings` holds the parsed tags.

---

### GET /api/dmarc/domains/{domain}/reports

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `days` | integer | `30` | How many days back to read, by report start date |
| `page` | integer | `1` | Page of days, starting at 1 |
| `limit` | integer | `50` | Days per page |

DMARC data per day, newest first: `domain`, `total`, `page`, `limit`, `pages` (0 without data) and `data`. Each day has `date`, `total_messages`, `dmarc_pass_pct`, `spf_pass_pct`, `dkim_pass_pct`, `unique_ips`, `reporters` and `reports` (`report_id`, `org_name`, `begin_date`, `end_date`, `volume`, `dmarc_pass_pct`).

---

### GET /api/dmarc/domains/{domain}/sources

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `days` | integer | `30` | How many days back to read, by report start date |
| `page` | integer | `1` | Page of source addresses, starting at 1 |
| `limit` | integer | `50` | Source addresses per page |

Sending addresses by message count, with GeoIP data, paged like the reports. Each row has `source_ip`, `country_code`, `country_name`, `country_emoji`, `city`, `asn`, `asn_org`, `total_count`, `dmarc_pass`, `dmarc_pass_pct`, `spf_pass`, `spf_pass_pct`, `dkim_pass`, `dkim_pass_pct` and `reporters` (`org_name`, `count`, `dmarc_pass`). Location values can be null.

---

### POST /api/dmarc/upload

Uploads a DMARC or TLS-RPT report as the multipart form field `file`; without it, 422.

```bash
curl -b cookies.txt -F "file=@report.xml.gz" https://logs.example.com/api/dmarc/upload
```

- **TLS-RPT** (RFC 8460 JSON): a name ending in `.json`, `.json.gz` or `.json.zip` (any case), or a ZIP of any name that holds a `.json` member and no `.xml` member; the first `.json` member is read. A report needs `report-id`, a valid `date-range` and at least one policy with a valid `policy-domain`.
- **DMARC**: anything else. Plain XML, gzip-compressed XML or ZIP (the first `.xml` member); the content decides the format, not the name.

Success returns `status: "success"`, `report_type` (`dmarc` or `tls-rpt`), `message`, the database `report_id`, and `records_count` (DMARC) or `policies_count` (TLS). A report ID already stored returns HTTP 200 with `status: "duplicate"`.

An upload over 10 MB returns 413; a report that decompresses to more than 10 MB, or an invalid report, 400. With `DMARC_MANUAL_UPLOAD_ENABLED=false`, 403.

---

### GET /api/dmarc/domains/{domain}/reports/{report_date}/details

One domain's DMARC data for one day (`YYYY-MM-DD`): `domain`, `date`, `totals` and `sources`.

`totals`: `total_messages`, `dmarc_pass`, `dmarc_pass_pct`, `spf_pass`, `spf_pass_pct`, `dkim_pass`, `dkim_pass_pct`, `unique_ips` and `reporters`. `sources` has one row per sending address and reporter, largest volume first, so `unique_ips` counts rows, not distinct addresses. Each row has `source_ip`, `source_name`, location and ASN fields, `header_from`, `envelope_from`, `reporter`, `volume`, `dmarc_pass`, `dmarc_fail`, `spf_pass`, `dkim_pass` and the three pass percentages.

A malformed date returns 400; a day without reports 404.

---

### GET /api/dmarc/domains/{domain}/sources/{source_ip}/details

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `days` | integer | `30` | How many days back to read, by report start date |

One sending address for one domain over the period: `domain`, `source_ip`, `source_name`, location and ASN fields, `totals` (message and pass counts, percentages, `unique_envelopes`, `reporters`) and `envelope_from_groups`. Each group is one envelope-from and reporter, largest volume first, with `envelope_from`, `header_from`, `reporter`, `volume`, `dmarc_pass`, `dmarc_fail`, `spf_aligned`, `dkim_aligned`, `spf_result` and `dkim_result`. No daily breakdown. An address without records in the period returns 404.

---

## DMARC IMAP Auto-Import

The import reads DMARC and TLS report attachments. Configure it under **Settings** > **DMARC & TLS IMAP**; see [Settings](HelpDocs/Settings.md#dmarc--tls-imap). Run history is stored in PostgreSQL and survives restarts.

### GET /api/dmarc/imap/status

Import state, also while the import is off. Returns `enabled`, `configuration` (`host`, `port`, `user`, `folder`, `delete_after`, `interval_seconds`, `interval_minutes`; null values while off; no password), `latest_sync` (null before the first run, else a run record with the history fields except `failed_emails`) and `stats_24h` (`total_syncs`, `total_reports_created`, `total_reports_failed`).

---

### POST /api/dmarc/imap/sync

Queues an import and returns at once: `{ "status": "started", "message": "IMAP import of DMARC and TLS reports started" }`. No body. Import off returns 400; a failure to queue, 500.

Only one import runs at a time. While one runs, scheduled or manual, the response is HTTP 200 with `{ "status": "already_running", "message": "Reports are already being fetched" }` and nothing starts. Read the result from the status or history endpoint. When an import starts, runs still marked `running` (left by an app that stopped during them) become `failed` with "Interrupted: the app stopped during the import".

Manual and scheduled imports send the same notification when some emails fail: by email when SMTP is set up, and to the destinations that receive **DMARC processing errors**. Bounces and emails without reports are skipped, not counted as failures.

---

### GET /api/dmarc/imap/history

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `limit` | integer | `20` | Sync runs per page |
| `page` | integer | `1` | Page to return, starting at 1 |

Import runs, newest first: `total`, `page`, `limit`, `pages` (0 without history) and `data`.

```json
{
  "id": 42, "sync_type": "auto", "status": "success",
  "started_at": "2026-01-12T08:45:20Z", "completed_at": "2026-01-12T08:45:21Z",
  "emails_found": 5, "emails_processed": 5, "reports_created": 4, "reports_duplicate": 0, "reports_failed": 1,
  "error_message": "1 emails failed to process",
  "failed_emails": [ {"email_id": "21", "message_id": "", "subject": "FW: Report", "error": "No DMARC attachments found"} ]
}
```

`sync_type` is `auto` or `manual`. `status` is `success`, `error`, `running` or `failed` (interrupted, or cleaned up as stale). `completed_at` is null while running. `reports_failed` counts failed emails; `email_id` is the IMAP UID. `failed_emails` and `error_message` are null when nothing failed.

---

## TLS-RPT (TLS Reporting)

TLS-RPT reports (RFC 8460) tell you when other mail servers failed to set up TLS while delivering to your domain, which points to MTA-STS policy or certificate problems. Uploads go through [`POST /api/dmarc/upload`](#post-apidmarcupload).

### GET /api/dmarc/domains/{domain}/tls-rpt-record

The domain's TLS-RPT record, from the stored DNS check or a live lookup when the domain has not been checked.

```json
{ "domain": "example.com", "tls_rpt_record": {"status": "success", "message": "TLS-RPT configured", "record": "v=TLSRPTv1; rua=mailto:tls-reports@example.com", "report_uris": ["mailto:tls-reports@example.com"], "warnings": []} }
```

`status` is `success`, `warning` (no record published; `info` then holds the record to publish), `error` (more than one record, or no usable `rua` address) or `unknown` (the lookup failed). `record` is null when nothing is published.

---

### GET /api/dmarc/domains/{domain}/tls-reports

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `days` | integer | `30` | How many days back to read, by report start date |
| `page` | integer | `1` | Page of reports, starting at 1 |
| `limit` | integer | `50` | Reports per page |

Single TLS reports, newest start first: `domain`, `total`, `page`, `limit`, `pages`, `totals` and `data`.

`totals.total_reports` counts every report in the period, but `total_successful_sessions`, `total_failed_sessions`, `overall_success_rate` and `unique_organizations` cover only the current page; `overall_success_rate` is 100 without sessions. Each report has `id`, `report_id`, `organization_name`, `contact_info`, `start_datetime`, `end_datetime`, `successful_sessions`, `failed_sessions`, `total_sessions`, `success_rate` and `policies` (`policy_type`, `policy_domain`, `mx_host`, `successful_sessions`, `failed_sessions`, `failure_details`).

---

### GET /api/dmarc/domains/{domain}/tls-reports/daily

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `days` | integer | `30` | How many days back to read, by report start date |
| `page` | integer | `1` | Page of days, starting at 1 |
| `limit` | integer | `30` | Days per page |

TLS reports per UTC day: `domain`, `total`, `page`, `limit`, `pages`, `totals` (`total_days`, `total_reports`, `total_successful_sessions`, `total_failed_sessions`, `overall_success_rate`) and `data` (`date`, `report_count`, `total_success`, `total_fail`, `total_sessions`, `success_rate`, `organizations`, `organization_count`, `reports`).

---

### GET /api/dmarc/domains/{domain}/tls-reports/{report_date}/details

One day's TLS reports (`YYYY-MM-DD`): `domain`, `date`, `stats` (`total_reports`, `total_providers`, `total_success`, `total_fail`, `total_sessions`, `success_rate`) and `providers`. `providers` has one entry per report, so a provider that sent two reports that day appears twice; entries have `report_id`, `organization_name`, `contact_info`, `start_datetime`, `end_datetime`, `successful_sessions`, `failed_sessions`, `total_sessions`, `success_rate` and `policies`, and each policy adds `total_sessions`, `success_rate` and `failure_details`.

A malformed date returns 400; a day without reports 404.

---

## Blacklist Monitoring

### GET /api/blacklist/summary

The dashboard summary across every active monitored host (WAN IP, transports, relayhosts, manual hosts).

```json
{
  "has_data": true,
  "server_ip": "192.0.2.10",
  "status": "listed",
  "listed_count": 1,
  "total_blacklists": 60,
  "checked_at": "2026-01-25T14:00:00Z",
  "hosts": [
    {"hostname": "192.0.2.10", "source": "system", "status": "listed", "listed_count": 1, "checked_at": "2026-01-25T14:00:00Z"},
    {"hostname": "198.51.100.20", "source": "relayhost:smtp.example.com", "status": "clean", "listed_count": 0, "checked_at": "2026-01-25T14:00:00Z"}
  ],
  "hosts_total": 2,
  "hosts_listed": 1
}
```

Only checks from the last 24 hours count as fresh.

- `has_data`: at least one host has a fresh check.
- `server_ip`: the detected WAN IP, or the single monitored host when it is unknown.
- `status`: `listed` if any host is listed, else `error` if any fresh check failed, else `clean` if any host has fresh data, else `unknown`.
- `listed_count` and `total_blacklists` add up the hosts with fresh data; without fresh data, `total_blacklists` falls back to the number of known blocklists. `checked_at` is the newest stored check, even when stale.
- A host whose latest check is older than 24 hours shows `status: "unknown"` and `listed_count: 0`.
- `hosts_listed` counts listed hosts with fresh data.

---

### Ignored blocklists

A blocklist can be ignored for every monitored address (for example UCEPROTECT Level 3, which lists whole ranges). It is still checked and shown, but a listing on it is not counted and sends no alert. Every response with per-list `results` marks each entry `"ignored": true|false`; `listed_count` and `status` leave ignored listings out, and `ignored_listed_count` says how many were left out. The stored check never changes, so un-ignoring takes effect at once.

### GET /api/blacklist/ignored

`{ "lists": [{ "name": "UCEPROTECT Level 3", "zone": "dnsbl-3.uceprotect.net" }] }`

### PUT /api/blacklist/lists/{zone}/ignore

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `ignored` | boolean | Required | `true` to ignore the blocklist, `false` to count it again |

Returns `{ "zone": "dnsbl-3.uceprotect.net", "name": "UCEPROTECT Level 3", "ignored": true }`. A zone that is not one of the checked blocklists returns 404.

---

### GET /api/blacklist/config

The server-IP cache metadata: `total_blacklists`, `cache_ttl_hours` (24), `cache_valid`, `last_check`, `server_ip`, `listed_count` and `status`. `last_check`, `listed_count` and `status` are null when no valid cache exists, including after 24 hours or a change to the number of applicable blocklists; `server_ip` is detected independently. The monitoring sources and alert addresses are not included.

---

### GET /api/blacklist/monitored

Every active monitored host, after bringing the saved list in line with the enabled sources (server, transports, relayhosts, manual). Returns `hosts`; each has `hostname`, `source`, `last_seen`, `has_data` and `status`, and, when a check is stored, `listed_count`, `total_blacklists`, `checked_at`, `cache_valid` and per-list `results`.

`has_data` means a check is stored; `cache_valid` says whether it is within 24 hours. A host without a check has `status: "unknown"`.

---

### POST /api/blacklist/check

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `host` | string | Unset | Host name or IP to check; omit it to check all monitored hosts in the background |
| `force` | boolean | `false` | Check again even when a result from the last 24 hours exists |

Without `host`: starts a background check of all hosts and returns `{ "status": "started", "message": "Background check started for all hosts" }`; follow it with `GET /api/blacklist/progress`.

With `host`: waits and returns the result, with `server_ip`, `checked_at`, `status`, per-list `results` and the totals `total_blacklists`, `listed_count`, `clean_count`, `error_count` and `timeout_count`. A host name is first resolved to IPv4; if that fails, the name goes to the checker as is. A checker failure returns HTTP 200 with `status: "error"` and `error`, so check the body.

---

### GET /api/blacklist/progress

`{ "in_progress": true, "current": 4, "total": 150, "current_blacklist": "Spamhaus ZEN", "percent": 2 }`. `total` is hosts times blocklists; `current` counts across all hosts.

---

## Reporting

### GET /api/system/summary

The data of the weekly summary email:

| Field | Content |
| --- | --- |
| `timestamp` | When the summary was built (UTC). |
| `traffic` | Mailbox traffic for the last 7 days, with the fields of `GET /api/mailbox-stats/summary`. |
| `system` | Total and active domains, mailboxes and aliases, as in `GET /api/status/mailcow-info`. |
| `storage` | `disk`, `used`, `total` and `used_percent` of mailcow's mail storage. |
| `blacklist` | `status`, `listed_count`, `total_hosts` and the monitored `hosts`. |
| `top_failures` | Up to five active mailboxes with failed outgoing messages, picked from the first 20 by failure rate. |
| `dns_issues` | Active domains with SPF, DKIM or DMARC issues, each with `domain` and `issues`. |
| `queue` | `{count}` of the mail queue; 0 if mailcow cannot be read. |
| `quarantine` | `{count}` of the quarantine; 0 if mailcow cannot be read. |

---

### POST /api/system/summary/email

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `force` | boolean | `false` | Send even when the weekly summary is turned off |

Builds and sends the weekly summary in the background: `{ "status": "queued", "message": "Weekly summary email generation started" }`. With the weekly summary off and no `force`: `{ "status": "skipped", "reason": "Weekly summary disabled" }`.

---

## System Status

### GET /api/status/container-logs

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `lines` | integer | `100` | Number of lines, 10 to 1000 |

The newest lines of this app's own log (`/app/data/container.log`), not mailcow's: `{ "logs": [ ... ] }`. A missing file or read error returns an explanatory line in `logs`.

---

## Raw Logs (Live Log Viewer)

Endpoints behind the **Logs** page. A background worker collects raw logs from the mailcow services, stores them and streams new lines over a WebSocket. Services: `acme`, `api`, `autodiscover`, `dovecot`, `netfilter`, `postfix`, `ratelimited`, `rspamd-history`, `sogo`, `watchdog`.

### GET /api/raw-logs/services

The services selected for the Logs page, with the number of stored lines.

```json
{
  "services": [ {"id": "postfix", "name": "Postfix", "icon": "mail", "description": "Mail transfer agent logs", "has_smart_filters": true, "log_count": 1523} ],
  "ws_connections": 1,
  "raw_logs_enabled": true
}
```

`ws_connections` is the number of open live streams; `raw_logs_enabled` mirrors `RAW_LOGS_ENABLED`.

---

### GET /api/raw-logs/{service}

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

Stored lines of one service: `data`, `page`, `limit`, `total`, `pages` and `service`. Each row is mailcow's log object plus `_id`, `_service` and `_stored_at`. An unknown service returns 404.

---

### GET /api/raw-logs/{service}/smart-filters

`{ "service": "postfix", "filters": [ ... ] }`; each filter has `id`, `label`, `pattern` (one string), `field` (`message` or `program`), `color` and `description`. The Postfix IDs are `postscreen`, `noqueue_reject`, `dnsbl`, `pregreet`, `sender_restrict`, `recipient_restrict`, `relay_restrict` and `connections`; other services have none.

---

### GET /api/raw-logs/worker-status

Raw log settings and worker state: `enabled`, `fetch_interval`, `fetch_count`, `retention_days`, `services`, `jobs` (fetch and cleanup job status) and `ws_connections` (open streams per service). `services` is the Logs page's selection; services other pages need may be collected too.

---

### GET /api/raw-logs/ws-token

A one-time token for the live log WebSocket: `{ "token": "a1b2c3d4e5f6...", "ttl": 30 }`. It works once, expires after 30 seconds and is bound to the caller's session, so it cannot open a stream after sign-out, session expiry or a change to the sign-in settings.

---

### WebSocket: /ws/raw-logs

Live log stream. With authentication on, get a token from `GET /api/raw-logs/ws-token` and connect with it; the server checks and consumes it. With authentication off, no token is needed.

```
wss://logs.example.com/ws/raw-logs?service=postfix&token=<one-time-token>
```

`service` (default `postfix`) is the first service to stream; one not selected for the Logs page falls back to the first selected one. A cross-site `Origin` or `Referer` is refused before the upgrade with HTTP 403 unless its origin is listed in `CORS_ALLOWED_ORIGINS`.

Only lines of the current service are streamed. To switch without reconnecting, send `{"action": "subscribe", "service": "dovecot"}`; the server answers `type: "subscribed"`, or `type: "error"` for a service that is not selected.

Server messages have a `type`:

- `connected`: `{"type": "connected", "service": "postfix", "message": "Connected to postfix log stream"}`
- `new_logs`: `{"type": "new_logs", "service": "postfix", "entries": [{"time": "1776189085", "program": "postfix/smtpd", "priority": "info", "message": "connect from unknown[192.0.2.10]"}], "timestamp": "2026-04-15T01:21:25Z"}`
- `service_counts`: updated line counts per service
- `error`: for example `{"type": "error", "message": "Authentication required"}`, followed by close code 4401

| Close code | Meaning |
|------|---------|
| `4401` | Invalid or missing token |
| `4001` | The session ended or the sign-in settings revoked it |
| `1013` | The client could not receive within the send time budget |
| `1000` | Normal closure |

The web interface reconnects after 3 seconds, except after 4401.

---

## Suppressions and Rspamd maps

Two parts: a recipient suppression list with automatic bounce detection (Outbound > Suppressions, feature `suppressions`), and an editor for Rspamd map files (the Rspamd page, feature `rspamd`).

### Rspamd Maps

#### GET /api/rspamd/config

`{ "rspamd_configured": true, "rw_key_configured": true, "suppression_enabled": false, "suppression_configured": false }`. `rspamd_configured` means a password is set, `rw_key_configured` that a read-write key is set; `suppression_configured` needs suppression on and a read-write key. None of these tests the credentials.

---

#### GET /api/rspamd/maps

The known Rspamd maps: `configured`, `maps`, and `rw_key_configured` when connected. Each map has `filename`, `name`, `category`, `description` and `supports_regex`; maps the suppression list manages also have `managed_by_suppression`. When connected, maps add `map_id`, `loaded`, `editable` and `rspamd_description`.

Without a Rspamd password, `configured` is false and `message` says what to add. A connection failure can return `configured: true`, an `error` and the known maps with HTTP 200, so check `error` before treating the list as live. Use only filenames from this list; others return 404.

---

#### GET /api/rspamd/maps/{filename}

`{ "filename": "global_smtp_from_whitelist.map", "content": "/^alice@example\\.com$/i", "entry_count": 1 }`, sometimes with the map's `metadata`. A known map that is not loaded yet returns empty content, zero entries and a message. An unknown filename returns 404, a missing Rspamd password 400, an Rspamd failure 502.

---

#### PUT /api/rspamd/maps/{filename}

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `content` | string | Required | The whole new map, one entry per line; lines starting with `#` are comments |

Replaces the map through the mailcow API. Before saving, bare addresses become anchored, escaped regular expressions:

```json
{ "success": true, "filename": "global_smtp_from_whitelist.map", "entry_count": 2, "normalized_entries": 2, "content": "/^user@example\\.com$/i\n/^admin@example\\.com$/i", "warnings": [], "api_response": [] }
```

`normalized_entries` counts the converted lines; `content` is what was saved. Warnings do not block the save. Invalid entries return 400 with `detail` holding `message` and `validation_errors`. No read-write key returns 403; an unknown filename 404; a mailcow failure 502.

---

#### POST /api/rspamd/validate

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `content` | string | Required | Map content to check |
| `filename` | string or null | Unset | Accepted but not used |

Checks map entries, including regular expression syntax, without saving. Unlike the save, it does not convert bare addresses first.

```json
{ "valid": false, "entry_count": 2, "errors": [ {"line": 2, "content": "/invalid[/", "severity": "error", "error": "Invalid regex: unterminated character set at position 7"} ], "warnings": [] }
```

---

### Suppressions

The app keeps the list only while Suppressions and **Sync with Rspamd** (`suppression_rspamd_sync`) are on. Otherwise the reads return an empty list, and `POST /api/suppressions`, `PUT` and `DELETE /api/suppressions/{suppression_id}` and `POST /api/suppressions/import` return 409 with `{ "detail": { "code": "sync_off", "message": "Sync with Rspamd is off. Turn it on in Settings to manage suppressions." } }`.

#### GET /api/suppressions

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

`items`, `total`, `page`, `per_page` and `total_pages`. An item:

```json
{
  "id": 1, "email": "bounce@example.com", "type": "email", "reason": "hard_bounce", "source": "auto", "notes": null,
  "bounce_count": 3, "hard_bounce_count": 2, "soft_bounce_count": 1, "last_bounce_dsn": "5.1.1", "last_bounce_message": "User unknown",
  "active": true, "synced_to_rspamd": true,
  "expires_at": "2026-05-01T00:00:00Z", "is_expired": false,
  "expires_in": {"days": 11, "hours": 5, "total_seconds": 968400, "human": "11 days"},
  "created_at": "2026-04-20T10:00:00Z", "updated_at": "2026-04-20T10:00:00Z"
}
```

`expires_at: null` means a permanent block. `expires_in` is present only while `expires_at` is set and in the future.

---

#### GET /api/suppressions/stats

Totals as top-level fields: `total`, `active`, `expired`, `hard_bounce`, `soft_bounce`, `rejected`, `manual`, `pending_sync` (changes waiting to be written to Rspamd, as `pending_count` in `/api/suppressions/rspamd/state`) and `auto_detected`.

---

#### GET /api/suppressions/config

The suppression settings (`suppression_enabled`, `suppression_auto_detect`, `suppression_rspamd_sync`, `list_kept` (the app keeps a list now: Suppressions and the sync on), `suppression_whitelist_domains` as the comma-separated string, `suppression_hard_bounce_action` (`suppress`, `delete` or `ignore`), `suppression_soft_bounce_action`, `suppression_soft_bounce_threshold`, `queue_cleanup_enabled`, `queue_cleanup_block`, `queue_cleanup_threshold_minutes`, `suppression_base_expiry_days`, `suppression_max_expiry_days`) and `rspamd_configured`, `rw_key_configured` and `is_fully_configured`. `is_fully_configured` means suppression is on and a read-write key is set; Rspamd sync also needs `rspamd_configured`.

---

#### POST /api/suppressions

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `email` | string | Required | An address, a domain, or a `/regex/` pattern; stored in lower case |
| `type` | string | `email` | `email` or `domain` |
| `reason` | string | `manual` | `hard_bounce`, `soft_bounce`, `deferred_stuck`, `rejected` or `manual` |
| `notes` | string or null | Unset | Free text |
| `permanent` | boolean | `true` | `true` never expires; `false` uses `expires_at` |
| `expires_at` | string or null | Unset | Expiry (ISO 8601), used only when `permanent` is `false` |

Creates an entry and returns it in the list format, even while automatic suppression is off. With a read-write key, it also tries to delete matching messages from the mail queue; a cleanup failure does not undo the saved entry.

- To block a domain, send `type: "domain"` and a pattern such as `/.+@example\.com/i` in `email`; the API does not convert a bare domain into a pattern. A value starting with `/` skips address validation.
- In Rspamd, a pattern is anchored as a whole (`/^(?:pattern)$/i`). Automatic entries (`source: auto`, from bounces and the deferred queue cleanup) are always written as the exact address, even when they look like a pattern.
- With `permanent: false` and no `expires_at`, the entry expires after `SUPPRESSION_BASE_EXPIRY_DAYS`.
- Re-adding an inactive entry reactivates it as a permanent manual entry.

An existing active entry returns 409 with a plain `detail` string; an unparsable `expires_at` 400; an invalid address, type or reason 422.

---

#### PUT /api/suppressions/{suppression_id}

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `active` | boolean or null | Unset | Turn the entry on or off |
| `notes` | string or null | Unset | Free text |
| `expires_at` | string or null | Unset | New expiry (ISO 8601); `"null"` or `""` makes the entry permanent |

Updates the non-null fields sent and returns the entry; JSON `null` leaves a field unchanged. Sending `active` marks the entry for a new Rspamd sync. An unknown ID returns 404; an unparsable `expires_at` 400.

---

#### GET /api/suppressions/{suppression_id}/events

Block details: what happened to the address, newest first, 20 per `page`. Returns `suppression` (`id`, `email`, `type`, `active`), `total`, `page`, `page_size` and `events`. Each event has `kind` (`hard_bounce`, `soft_bounce`, `rejected`, `deferred_stuck`, `added`, `imported`, `enabled`, `disabled`, `expiry_changed`, `notes_changed`, `before_upgrade`, `loaded_from_rspamd`, `added_in_rspamd`), `outcome` (`created`, `activated`, `extended`, `counted`, `changed`), `recorded_at`, `message_time`, `reason`, `server_reply`, `dsn`, `sender`, `recipient`, `subject`, `queue_id`, `message_id`, `notes`, `expires_at`, `log_lines` (`time`, `program`, `message`), `logs_shortened`, `correlation_key` and `message_available` (the message is still on Messages). Fields the logs did not prove are null. An unknown id returns 404.

#### DELETE /api/suppressions/{suppression_id}

Deletes the entry for good: `{ "deleted": true, "email": "user@example.com", "was_active": true, "needs_rspamd_sync": true }`. While its block may still be in Rspamd, its map lines wait to be removed by the next write; this request does not write. An unknown ID returns 404.

---

#### POST /api/suppressions/import

Imports entries from a CSV file in the multipart field `file`; a name that does not end in `.csv` returns 400.

```csv
email,type,reason,notes
user@example.com,email,manual,Imported entry
/.+@example\.com/i,domain,manual,Domain block
```

A file with a header row is read by column name; without one, the columns are `email,type,reason,notes`. Entries are created permanent, active and unsynced, with source `import`; existing entries and duplicates within the file are skipped. Missing or unknown types become `email`, and missing or unsupported reasons become `manual`. Returns `{ "imported": 10, "skipped": 2, "errors": ["Row 5: empty email"] }`; unlike create, the import does not validate address syntax or convert bare domains into patterns.

---

#### GET /api/suppressions/export

All entries as CSV, with the columns `email,type,reason,source,notes,bounce_count,hard_bounces,soft_bounces,active,expires_at,created_at,_csv_escape_v1`. The last column lists the cells that got a text prefix; keep it when importing the file back, and the import restores those values. Files without it are accepted and never unescaped. This is a list transfer, not a backup of counts or sync state.

---

#### POST /api/suppressions/sync

Brings the list and the managed section of Rspamd's `global_rcpt_blacklist.map` in step. First the section is read into the list: a line deleted there deletes its entry, a line added there becomes a permanent entry with source `rspamd`. Then the list's waiting changes are applied to the map as it is now: `{ "success": true, "written": true, "added": 2, "removed": 1, "synced": 120, "list_added": 1, "list_removed": 0, "pending_count": 0 }`. `added` and `removed` count map lines the write changed; `list_added` and `list_removed` count entries the read changed. Lines outside the markers are kept. Only while Sync with Rspamd (`suppression_rspamd_sync`) is on: with it off, `?after_change=true` (sent by the page after a change) answers `{ "success": true, "written": false, "skipped_off": true }` without reading or writing, and a call without it returns 409 `sync_off`. With `after_change`, the write happens only with the read-write key; without it, the answer has `"written": false`. Without `after_change`, no read-write key returns 403; no `RSPAMD_PASSWORD` 400. Another map write still running 409; a map whose markers are missing or repeated, or that changed during the sync, 409 with `{ "detail": { "code": "section_unclear", "message": "..." } }` (`section_missing`, `map_changed`, `import_failed`, `sync_off`, `connection_changed`); a mailcow failure, or a reply that does not confirm the save, 502 `not_confirmed`. An error after the read changed the list adds `list_changed` (`list_added`, `list_removed`) to `detail`.

#### GET /api/suppressions/rspamd/state

What the app has in Rspamd, read from the map: `{ "sync_on": true, "active_count": 15, "list_count": 18, "pending_count": 3, "writable": true, "readable": true, "managed_count": 12, "reason": null, "reason_text": null }`. `managed_count` counts map lines in the managed section (a line can be a domain or a pattern), `null` when the map cannot be read. `pending_count` counts the list's changes waiting to be written: entries to add, disabled or expired entries to remove, and deleted entries whose lines are still to be removed. `reason` is `no_rw_key`, `no_password`, `no_rw_key_and_password`, `read_failed`, `map_not_found` or `section_unclear`. While the sync is off, the map is read only with `?check_map=true` (`managed_count` is `null` otherwise).

#### POST /api/suppressions/rspamd/clear

Removes the app's blocks after the list stopped being kept (Suppressions or Sync with Rspamd off): empties the managed section and leaves every other line of the map as it is. Optional body `{ "transition": "..." }`, the `rspamd_off_transition` of the save that turned it off. Returns `{ "removed_blocks": 12 }`. While the list is kept again: 409 `sync_on`; with a transition another save replaced: 409 `transition_changed`; both are checked again right before the save, and nothing is removed. When it cannot read or write the map: 409 with `{ "detail": { "code": "no_rw_key", "message": "..." } }`; a refused Read-Write key 502 `rejected_rw_key`; a write mailcow did not confirm 502 `not_confirmed`.

#### POST /api/suppressions/rspamd/import

Loads the app's blocks from the managed section into the list after the list was deleted (Suppressions or Sync with Rspamd turned on again). A read only; nothing is written to Rspamd. Returns `{ "imported": 12, "pending": false, "loaded": true }`; `loaded` is `true` only for the request that did the load, so `imported` is its count. With nothing to load, `{ "imported": 0, "pending": false, "loaded": false }`. Without the Rspamd password, when the app may have blocks there: `"pending": true, "reason": "no_password"`, and automatic blocking waits until they load. Map errors as for clear.

#### POST /api/suppressions/start-fresh

Empties the managed section, then deletes every entry of the list, while the sync is still off (a step before the save that turns it on; 409 `sync_on` once it is on). The list is deleted only after mailcow confirmed the map. Returns `{ "removed_blocks": 12, "deleted_entries": 15 }`; errors as for clear.

---

## Quarantine Auto-Rules

Rules that release or delete quarantined messages automatically. Every endpoint here, including the reads, needs a read-write key and returns 403 without one.

### GET /api/quarantine/rules

All rules, delete rules first, then newest first: `{ "total": 2, "data": [ ... ] }`.

```json
{"id": 1, "name": "Allow billing emails", "match_type": "sender", "match_value": "billing@example.com", "is_regex": false, "action": "release", "enabled": true, "hit_count": 42, "last_hit_at": "2026-04-21T10:30:00Z", "notes": "Trusted billing sender", "created_at": "2026-04-20T08:00:00Z", "updated_at": "2026-04-21T10:30:00Z"}
```

`action` is `release` (deliver to the inbox) or `delete` (remove for good). `hit_count` counts the messages the rule released or deleted; one mailcow refused is not counted.

---

### POST /api/quarantine/rules

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `name` | string | Required | 1 to 255 characters |
| `match_type` | string | Required | `sender`, `sender_domain`, `recipient` or `subject` |
| `match_value` | string | Required | 1 to 500 characters |
| `is_regex` | boolean | `false` | Treat `match_value` as a regular expression |
| `action` | string | Required | `release` or `delete` |
| `notes` | string or null | Unset | Free text |

Creates a rule and returns it. An invalid `match_type` or `action`, an invalid regular expression, or one with nested repetition such as `(a+)+` (it can take very long on some messages) returns 400.

---

### PUT /api/quarantine/rules/{id}

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `name` | string or null | Unset | 1 to 255 characters |
| `match_type` | string or null | Unset | `sender`, `sender_domain`, `recipient` or `subject` |
| `match_value` | string or null | Unset | 1 to 500 characters |
| `is_regex` | boolean or null | Unset | Treat `match_value` as a regular expression |
| `action` | string or null | Unset | `release` or `delete` |
| `enabled` | boolean or null | Unset | Turn the rule on or off |
| `notes` | string or null | Unset | Free text |

Updates the non-null fields sent and returns the rule; JSON `null` leaves a field unchanged. An unknown ID returns 404; invalid values return 400, or 422 for request type and length validation.

---

### DELETE /api/quarantine/rules/{id}

Deletes the rule for good: `{ "success": true, "message": "Rule 'Block spam domain' deleted" }`. An unknown ID returns 404.

---

### POST /api/quarantine/rules/{id}/toggle

Turns the rule on or off and returns it. An unknown ID returns 404.

---

### POST /api/quarantine/rules/test

Dry run of every rule, enabled or not, against the current quarantine. Changes nothing.

```json
{ "total_quarantine": 15, "total_matches": 3, "matches": [ {"quarantine_id": "12345", "sender": "spam@example.org", "recipient": "user@example.com", "subject": "You won a prize!", "rule_id": 1, "rule_name": "Block example.org", "action": "delete", "rule_enabled": true} ] }
```

Each message matches only its first matching rule, and delete rules are checked before release rules. `rule_enabled: false` marks a match the scheduled run would not act on. With no rules or an empty quarantine, the counts are zero and `message` says why.

---

### GET /api/quarantine/rules/logs

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `limit` | integer | `50` | Entries to return, at most 200 |
| `offset` | integer | `0` | Entries to skip, 0 or more |
| `rule_id` | integer or null | Unset | Only actions of this rule |

The actions the scheduled run took, kept for `QUARANTINE_RULES_LOG_RETENTION_DAYS` (default 30): `{ "total": 100, "data": [ ... ] }`.

```json
{"id": 1, "rule_id": 2, "rule_name": "Block spam domain", "action": "delete", "quarantine_id": "12345", "sender": "spam@example.org", "recipient": "user@example.com", "subject": "Buy now!", "matched_field": "sender_domain", "matched_value": "example.org", "created_at": "2026-04-21T10:30:00Z"}
```

---

## Security Alerts (Anomaly Detection)

Alerts from anomaly detection (outbound volume spikes, bursts of failed logins) and from SMTP abuse protection. Unacknowledged alerts appear in the Dashboard's **Needs attention** panel.

### GET /api/security-alerts

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `acknowledged` | boolean or null | Unset | `true` for acknowledged alerts only, `false` for unacknowledged only; omit for all |
| `limit` | integer | `50` | Most alerts to return, 1 to 500 |

Alerts, newest first.

```json
{
  "enabled": true,
  "unacknowledged_count": 2,
  "alerts": [
    {"id": 12, "alert_type": "volume_spike", "severity": "critical", "subject": "user@example.com", "title": "Outbound volume spike: user@example.com", "detail": "Mailbox user@example.com sent 240 messages in the last 15 minutes...", "metric_value": 240.0, "baseline_value": 4.2, "acknowledged": false, "created_at": "2026-07-14T09:12:00Z"}
  ]
}
```

`enabled` reflects `ANOMALY_DETECTION_ENABLED` only; alerts are still listed and can be acknowledged while it is off. `unacknowledged_count` counts every unacknowledged alert, whatever the filter. `alert_type` is `volume_spike`, `auth_failure_burst` or `smtp_abuse_block`; `severity` is `warning` or `critical`.

### GET /api/security-alerts/{alert_id}/activity

The history behind an alert, for its **Show activity** window: outbound messages of the mailbox for a `volume_spike` or `smtp_abuse_block`, failed logins of the username for an `auth_failure_burst`. An unknown alert returns 404.

- `buckets`: `[{start, count, partial}]` per `bucket_minutes` (15), from `baseline_days` before the alert to two hours after it, or to now for a recent alert; the first bucket starts on the hour. `partial` marks the bucket that ends at now. `data_end` is where the buckets end.
- `window_minutes`, `baseline_days`: the check window and baseline the alert was raised with, not today's settings. For `volume_spike` and `auth_failure_burst` they come from the alert's detail; for `smtp_abuse_block`, the window comes from its abuse action. `window_minutes` is null when unknown; `baseline_days` falls back to today's setting.
- `around`: from the window (an hour when it is null) before the alert to an hour after it (`from`, `to`): `total`, and for sent mail `recipient_domains`, `results` and `subjects`, for failed logins `addresses`, `countries`, `networks` and `address_count` (every source address, not only the listed ones). Each list is `[{name, count}]`, most first, up to 6 entries (`subjects` up to 5).
- `alert`: the alert itself.

### POST /api/security-alerts/{alert_id}/acknowledge

Acknowledges one alert, which removes it from **Needs attention**. Returns `{ "status": "success" }`; an unknown ID returns 404.

### POST /api/security-alerts/acknowledge-all

Acknowledges every open alert: `{ "status": "success", "acknowledged": 3 }`.

---

## SMTP Abuse Protection

Stops and restores a mailbox's outgoing (SMTP) access. Receiving mail is never affected. The reads work without a read-write key and while the feature is off. The writes return 403 while `SMTP_ABUSE_ENABLED=false` and 503 without a read-write key.

### GET /api/smtp-abuse/status

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `limit` | integer | `200` | Most mailboxes to count by outbound volume, 1 to 1000; mailboxes this system blocked are always included |

Outgoing volume per mailbox in the current window, with block state and the whitelist. Mailboxes are sorted by `message_count`, highest first.

```json
{
  "enabled": true, "rw_key_configured": true, "threshold": 100, "window_minutes": 60, "unblock_grace_minutes": 60, "revoke_app_passwords": true,
  "mailboxes": [ {"email": "user@example.com", "message_count": 152, "outbound_count": 152, "over_threshold": true, "whitelisted": false, "smtp_access": false, "blocked_by_protection": true} ],
  "whitelist": ["newsletter@example.com"]
}
```

`over_threshold` means strictly above `threshold`. `smtp_access` is `true` when mailcow's state could not be read. `blocked_by_protection` marks mailboxes this system blocked; mailboxes with SMTP turned off in mailcow for another reason (such as a receive-only DMARC report mailbox) are left out.

### GET /api/smtp-abuse/whitelist

The active entries, never blocked automatically: `[ { "email": "newsletter@example.com", "notes": "Marketing sender", "active": true } ]`.

### POST /api/smtp-abuse/whitelist

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `email` | string | Required | Address to whitelist; trimmed and lowercased; up to 254 characters |
| `notes` | string or null | Unset | Note stored with the entry; replaces any earlier note |

Adds or re-activates one entry: `{ "email": "newsletter@example.com", "active": true }`. An invalid address returns 422.

### PUT /api/smtp-abuse/whitelist

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `emails` | array of strings | `[]` | Complete list of addresses to keep active, at most 5000 |

Replaces the whole whitelist (the one-address-per-line editor). Addresses are lowercased, blank entries skipped, and entries that stay keep their notes. Returns `{ "active": ["monitoring@example.com", "newsletter@example.com"], "count": 2 }`. An invalid address or more than 5000 entries returns 422.

### DELETE /api/smtp-abuse/whitelist/{email}

Deactivates an entry: `{ "email": "...", "active": false }`. An address not on the list returns 404.

### POST /api/smtp-abuse/mailboxes/{email}/block

Turns off SMTP for the mailbox now, without checking the whitelist. Also revokes its app passwords (when `SMTP_ABUSE_REVOKE_APP_PASSWORDS=true`), records a security alert, and notifies the operator and the mailbox owner (the owner only when SMTP for notifications is set up).

Returns `{ "email": "user@example.com", "smtp_access": false, "app_passwords_revoked": 2, "message_count": 152 }`. If mailcow refuses the change (for example, the address is an alias), 500; if the mailcow request fails, 502. Unblock has the same errors.

### POST /api/smtp-abuse/mailboxes/{email}/unblock

Turns SMTP back on and starts the grace period (`SMTP_ABUSE_UNBLOCK_GRACE_MINUTES`) in which the mailbox is not blocked automatically, so old messages still inside the window do not block it again. Returns `{ "email": "user@example.com", "smtp_access": true }`.

### GET /api/smtp-abuse/history

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `limit` | integer | `50` | Most recent actions to return, 1 to 500 |

Block and unblock actions, newest first:

```json
[ {"email": "user@example.com", "action": "blocked", "message_count": 152, "threshold": 100, "window_minutes": 60, "automatic": true, "operator": "smtp-abuse", "app_passwords_revoked": 2, "created_at": "2026-07-14T09:15:00Z"} ]
```

`action` is `blocked` or `unblocked`; `operator` is `smtp-abuse` for automatic blocks and `manual` for API actions.

---

## DMARC Insights

### GET /api/dmarc/insights

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `domain` | string or null | Unset | Return only this domain's insight (exact match); omit for every domain with report data in the window |

Policy recommendations and new failing sources (possible spoofing) from the DMARC reports of the last `DMARC_INSIGHTS_WINDOW_DAYS` (default 28). Read-only; never changes DNS.

Without `domain`: `window_days`, `domain_count` and `insights`, only domains with data, most actionable first (low pass rate, then new sources, then tighten recommendations). With `domain`: that domain's insight object alone. A domain without reports in the window returns `{"domain": "...", "has_data": false, "recommendations": [], "new_sources": []}`.

```json
{
  "domain": "example.com", "has_data": true, "window_days": 28, "current_policy": "none", "total_messages": 5400, "pass_rate": 99.8,
  "recommendations": [ {"type": "tighten_policy", "severity": "success", "message": "example.com has a 99.8% DMARC pass rate over 5400 messages under p=none. It looks safe to move to p=quarantine.", "current_policy": "none", "recommended_policy": "quarantine"} ],
  "new_sources": [ {"source_ip": "198.51.100.88", "failing_messages": 80, "first_seen_window_days": 7} ]
}
```

**Recommendation types:** `low_pass_rate` (`warning`: pass rate under 90% with enough volume), `already_strict` (`info`: the policy is `reject`), `insufficient_volume` (`info`: fewer than `DMARC_INSIGHTS_MIN_VOLUME` messages, default 100), `tighten_policy` (`success`: pass rate at or above `DMARC_INSIGHTS_PASS_THRESHOLD`, default 99.5), `monitor` (`info`). Only `tighten_policy` adds `current_policy` and `recommended_policy`.

`new_sources` lists up to 20 addresses, most failing messages first, that fail DMARC and first appeared in the last quarter of the window (at least 3 days, so 7 days with the default 28).

---

## Protection rules

These back **Security** > **Settings**. Rule settings and watch mode work while UI settings editing is off. Enforcing bans needs a read-write key.

### GET /api/protection/rules

Returns `rules`, `trap_suggestions`, `country_suggestions` and `capabilities`. `capabilities` has `can_ban` (a read-write key is set), `geoip` and `raw_logs` (Dovecot raw logs are collected; the breach rule needs them for IMAP logins). `trap_suggestions` are `{name, tries, addresses}` for up to 12 unknown account names tried in the last 7 days; `country_suggestions` are `{code, name, tries}` for up to 12 countries with failed logins in the last 7 days.

### PUT /api/protection/rules

Send `{ "rules": { ... } }`. Omitted rules and fields keep their values; unknown rule keys and fields are ignored. Returns `{ "rules": { ... } }` with the effective rules. Invalid settings return 400.

Setting any ban rule to `enforce` without a read-write key returns 400; this also blocks every save while a stored rule is still in `enforce`. Country codes are uppercased and deduplicated. Switching a rule to `watch`, or turning it off, moves its pending automatic bans back to `watching`.

Every rule has `enabled` (default false) and `notify` (default true). Ban rules also have `mode` (`watch`, the default, or `enforce`) and `ban_hours` (0 to 8760; 0 bans with no end).

| Rule ID | Other fields and defaults | Validation |
| --- | --- | --- |
| `trap` | `names: []`, `ban_hours: 720` | Names are trimmed, lowercased and deduplicated. Each must be an address or bare name of up to 255 characters using letters, digits and `. _ % + -`. A real mailbox or alias, or a bare name equal to a real mailbox's local part, returns 400. Names after the first 500 are dropped without an error. |
| `unknown_accounts` | `threshold: 5`, `window_minutes: 60`, `ban_hours: 168` | Threshold 2 through 100; window 5 through 1440 minutes. |
| `repeat_offender` | `threshold: 3`, `window_days: 30`, `ban_hours: 0` | Threshold 2 through 50; window 1 through 365 days. |
| `subnet` | `threshold: 5`, `window_hours: 24`, `ban_hours: 24` | Threshold 2 through 256 addresses; window 1 through 168 hours. |
| `country` | `countries: []`, `ban_hours: 168` | Two-letter country codes; country matching needs GeoIP. |
| `breach` | `failures: 3`, `window_minutes: 60`, `new_country: true` | Failures 1 through 50; window 5 through 1440 minutes. Alerts only; has no ban mode. |

### GET /api/protection/hits

| Parameter | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `status` | string | `active` | `active`, `history`, `watching`, `dismissed` or `all` |
| `limit` | integer | `200` | Most hits to return, 1 to 1000 |

Returns `hits` and `counts` per status. `active` is watching, pending, banned and alert; `history` is dismissed, expired and undone. History sorts by end time, the other views by last seen. `counts` covers all hits, whatever the filter, and leaves out statuses with no hits.

Each hit has `id`, `ip`, `rule`, `mode` (`watch`, `enforce` or `manual`), `status`, `reason`, `usernames`, `attempts`, `country_code`, `country_name`, `first_seen`, `last_seen`, `ended_at`, `ban_hours`, `banned_at`, `expires_at` (null means no end), `owned` and `error`. A `watching` hit with no activity for 7 days becomes `expired`.

### POST /api/protection/hits/{hit_id}/dismiss

Dismisses a watching or alert hit and returns it; nothing changes in mailcow. Other states are returned unchanged. An unknown ID returns 404.

### POST /api/protection/hits/{hit_id}/ban

Bans a watching hit of a ban rule and returns it with `mode: "manual"`. An unknown ID returns 404; a rule that cannot ban, or no read-write key, 400; a hit that is not watching, 409. If the address is on the allowlist by then, the hit becomes `dismissed` and the endpoint returns 502 with that reason. On any other failure the hit stays `pending` with the error, the next rules run tries again, and the endpoint returns 502.

### POST /api/protection/hits/{hit_id}/undo

Undoes a banned or pending hit and returns it. An unknown ID returns 404; other states 409. Lifting a ban the app added needs a read-write key (400 without); a mailcow failure returns 502. Undoing a pending hit changes nothing in mailcow, and entries the app did not add stay in mailcow. If another rule still bans the same address, that hit takes over the entry and it stays. A dismissed or undone address is left alone by that rule for a week.

---

## Notification Destinations

Where alerts go. Each alert goes to the enabled destinations subscribed to its type. Email routing and exceptions are in [Notifications](Notifications.md).

### GET /api/notifications/types

The fields each service type needs (the form shows only these) and the alert types a destination can subscribe to. Types: `slack`, `discord`, `telegram`, `ntfy`, `gotify`, `webhook`. Alert types: `security`, `blacklist`, `dns_changes`, `dmarc_errors`.

```json
{
  "types": [
    {"id": "telegram", "label": "Telegram", "help": "Create a bot with @BotFather to get the token...", "fields": [
      {"key": "bot_token", "label": "Bot token", "type": "text", "required": true, "secret": true},
      {"key": "chat_id", "label": "Chat ID", "type": "text", "required": true}
    ]}
  ],
  "alert_types": [
    {"id": "security", "label": "Security", "description": "Compromised mailbox detected, authentication attacks, SMTP disabled by abuse protection"}
  ]
}
```

A field can also have `placeholder` and, for the ntfy server URL, `default` (`https://ntfy.sh`). Fields with `secret: true` are masked once saved.

### GET /api/notifications/channels

The destinations, secrets masked as `********`:

```json
{ "channels": [ {"id": 1, "name": "Ops Slack", "channel_type": "slack", "config": {"webhook_url": "********"}, "alert_types": [], "enabled": true, "last_status": "success", "last_error": null, "last_sent_at": "2026-07-27T09:00:00Z"} ] }
```

An empty `alert_types` means every alert. `last_status` is `success`, `failed`, or null before the first delivery; `last_error` holds the failure text (secrets removed, up to 500 characters).

### POST /api/notifications/channels

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `name` | string | Required | 1 to 100 characters; leading and trailing spaces are removed |
| `channel_type` | string | Required | `slack`, `discord`, `telegram`, `ntfy`, `gotify` or `webhook` |
| `config` | object | `{}` | The type's fields from `GET /api/notifications/types`, by `key` |
| `alert_types` | array of strings or null | Unset | Alert type IDs to subscribe to. Empty, unset or all four means every alert. |
| `enabled` | boolean | `true` | Disabled destinations receive no alerts |

```json
{ "name": "Ops Telegram", "channel_type": "telegram", "config": {"bot_token": "123:ABC", "chat_id": "456"}, "alert_types": ["security", "blacklist"], "enabled": true }
```

Creates a destination and returns it as in the list. An unknown `channel_type`, a missing required field or an unknown alert type returns 422. A literal `********` counts as empty here, because nothing is stored yet.

### PUT /api/notifications/channels/{id}

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `name` | string | Required | 1 to 100 characters |
| `channel_type` | string | Required | Same values as for create |
| `config` | object | `{}` | The type's fields; send a secret as `********` to keep the stored value |
| `alert_types` | array of strings or null | Unset | As for create |
| `enabled` | boolean | `true` | As for create |

Replaces the whole destination: an omitted `alert_types` resets it to every alert, and an omitted `enabled` turns it back on. Returns the saved destination.

Changing `server_url` or `url` while keeping a masked secret returns 422 and asks for the secret again, so a stored secret is never sent to a new server. A different service type does not inherit secrets from the old one. An unknown ID returns 404.

### DELETE /api/notifications/channels/{id}

Removes a destination: `{ "status": "success" }`. An unknown ID returns 404.

### POST /api/notifications/channels/{id}/test

Sends "Test notification" to a saved destination, even a disabled one and whatever its alert types, and stores the delivery result. An unknown ID returns 404.

```json
{ "success": true, "logs": ["Channel: Ops Slack (slack)", "Sending test notification...", "Delivered successfully"] }
```

### POST /api/notifications/test

| Field | Type | Default | Constraints and purpose |
| --- | --- | --- | --- |
| `channel_type` | string | Required | One of the six service types |
| `config` | object | `{}` | The type's fields, with real secret values |

Tests settings before saving them (the test button in the editor), with the values exactly as sent: `********` is not replaced by a stored secret, so test stored secrets with the saved-destination test. Returns `success` and `logs`. An unknown `channel_type` returns 422; a missing required field returns `success: false` with the reason in `logs`.

```json
{ "channel_type": "ntfy", "config": {"server_url": "https://ntfy.sh", "topic": "mailcow-alerts"} }
```

## In-app documentation

### GET /api/docs/{doc_name}

A help page as plain-text Markdown, fetched from `documentation/HelpDocs` on the `main` branch on GitHub (10-second timeout). Only these names are accepted: `Domains`, `DMARC`, `Mailbox_Stats`, `IP_Blacklist_Monitor`, `Quarantine`, `Abuse_Protection`, `Rate_Limits`, `Devices`, `Dashboard`, `Messages`, `Security`, `Outbound`, `Rspamd`, `Status`, `Logs`, `Settings` and `About`.

Other names return 404, and so does an HTTP error from GitHub (including a missing file); a network failure returns 503.
