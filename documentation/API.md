# mailcow Logs Viewer - API Documentation

This document describes all available API endpoints for the mailcow Logs Viewer application.

**Base URL:** `http://your-server:8080/api`

**Authentication:** The application supports two authentication methods that can be enabled independently or together:
- **Basic Authentication**: HTTP Basic Auth with username/password
- **OAuth2/OIDC**: OAuth2/OpenID Connect authentication with any standard identity provider

When authentication is enabled, all API endpoints (except public endpoints listed below) require authentication. See [Authentication](#authentication) section for details.

---

## Table of Contents

1. [Authentication](#authentication)
2. [OAuth2 Authentication Endpoints](#oauth2-authentication-endpoints)
3. [Health & Info](#health--info)
4. [Job Status Tracking](#job-status-tracking)
5. [Domains](#domains)
6. [Mailbox Statistics](#mailbox-statistics)
7. [Messages (Unified View)](#messages-unified-view)
8. [Logs](#logs)
   - [Postfix Logs](#postfix-logs)
   - [Rspamd Logs](#rspamd-logs)
   - [Netfilter Logs](#netfilter-logs)
   - [Fail2Ban Configuration](#fail2ban-configuration)
9. [Queue & Quarantine](#queue--quarantine)
10. [Statistics](#statistics)
11. [Status](#status)
12. [Settings](#settings)
    - [GeoIP Management](#geoip-management)
    - [SMTP & IMAP Test](#smtp--imap-test)
13. [Export](#export)
14. [DMARC](#dmarc)
    - [DMARC IMAP Auto-Import](#dmarc-imap-auto-import)
15. [Blacklist Monitoring](#blacklist-monitoring)
16. [Reporting](#reporting)
17. [Raw Logs (Live Log Viewer)](#raw-logs-live-log-viewer)
18. [Spam Filter](#spam-filter)
    - [Rspamd Maps](#rspamd-maps)
    - [Suppressions](#suppressions)
19. [Quarantine Auto-Rules](#quarantine-auto-rules)

---

## Authentication

### Overview

The application supports two authentication methods that can be enabled independently or simultaneously:

1. **Basic Authentication**: Traditional HTTP Basic Auth with username/password
2. **OAuth2/OIDC**: OAuth2/OpenID Connect authentication with any standard identity provider (Authentik, Mailcow, Keycloak, Google, Microsoft, etc.)

**Public Endpoints (No Authentication Required):**
- `GET /api/health` - Health check (for Docker monitoring)
- `GET /api/info` - Application information
- `GET /api/auth/provider-info` - Authentication provider information
- `GET /login` - Login page (HTML)
- `GET /api/auth/login` - OAuth2 login initiation
- `GET /api/auth/callback` - OAuth2 callback handler

**Protected Endpoints (Authentication Required):**
- `GET /api/auth/verify` - Verify Basic Auth credentials (used by login form; returns 401 if invalid)
- All other `/api/*` endpoints

### Authentication Methods

#### Basic Authentication

When `BASIC_AUTH_ENABLED=true` (or legacy `AUTH_ENABLED=true`), use HTTP Basic Authentication:

- Username: `AUTH_USERNAME` (default: `admin`)
- Password: `AUTH_PASSWORD`

**Example Request:**
```bash
curl -u username:password http://your-server:8080/api/info
```

Or with explicit header:
```bash
curl -H "Authorization: Basic $(echo -n 'username:password' | base64)" \
  http://your-server:8080/api/info
```

#### OAuth2/OIDC Authentication

When `OAUTH2_ENABLED=true`, users can authenticate via OAuth2/OIDC. The application supports:
- **OIDC Discovery**: Automatic endpoint discovery via `.well-known/openid-configuration`
- **Manual Configuration**: Explicit endpoint configuration for providers without discovery

**Configuration:** See [OAuth2 Configuration Guide](../documentation/OAuth2_Configuration.md) for detailed setup instructions.

**Authentication Flow:**
1. User initiates login via `GET /api/auth/login`
2. User is redirected to OAuth2 provider
3. After authentication, provider redirects to `GET /api/auth/callback`
4. Application exchanges authorization code for tokens
5. Session is created and HTTP-only cookie is set
6. User is redirected to main application

**Session Management:**
- Sessions are stored server-side with signed session IDs
- HTTP-only cookies prevent XSS attacks
- Session expiration configurable via `SESSION_EXPIRY_HOURS` (default: 24 hours)

### Login Endpoint

#### GET /login

Serves the login page (HTML). This endpoint is always publicly accessible.

**Response:** HTML page with login form

**Features:**
- Dynamically displays available authentication methods
- Shows Basic Auth form if `BASIC_AUTH_ENABLED=true`
- Shows OAuth2 login button if `OAUTH2_ENABLED=true`
- "OR" separator appears only when both methods are enabled

**Note:** When authentication is disabled, accessing this endpoint will automatically redirect to the main application.

---

## Health & Info

### GET /health

Health check endpoint for monitoring and load balancers.

**Authentication:** Not required (public endpoint for Docker health checks)

**Response:**
```json
{
  "status": "healthy",
  "database": "connected",
  "version": "1.5.0",
  "config": {
    "fetch_interval": 60,
    "retention_days": 7,
    "mailcow_url": "https://mail.example.com",
    "blacklist_enabled": true,
    "auth_enabled": false
  }
}
```

---

### GET /info

Application information and configuration.

**Authentication:** Not required (public endpoint)

**Response:**
```json
{
  "name": "mailcow Logs Viewer",
  "version": "2.6.0",
  "mailcow_url": "https://mail.example.com",
  "local_domains": ["example.com", "mail.example.com"],
  "fetch_interval": 60,
  "retention_days": 7,
  "timezone": "UTC",
  "app_title": "mailcow Logs Viewer",
  "app_logo_url": "",
  "blacklist_count": 3,
  "auth_enabled": true,
  "basic_auth_enabled": true,
  "oauth2_enabled": false,
  "disabled_features": ["quarantine", "spam-filter"]
}
```

**Response Fields:**
- `auth_enabled`: Boolean - Whether any authentication is enabled
- `basic_auth_enabled`: Boolean - Whether Basic Authentication is enabled
- `oauth2_enabled`: Boolean - Whether OAuth2/OIDC authentication is enabled
- `disabled_features`: Array of strings - List of currently disabled feature IDs. Valid values: `netfilter`, `queue`, `quarantine`, `spam-filter`, `domains`, `dmarc`, `mailbox-stats`, `logs`, `blacklist`. Empty array if all features are enabled

---

### GET /rw-status

Check if a Read-Write API key (`MAILCOW_API_KEY_RW`) is configured. This is a unified endpoint used by all features that require write access (Fail2Ban settings, Quarantine management, etc.).

**Response:**
```json
{
  "rw_configured": true
}
```

**Response Fields:**
- `rw_configured`: Boolean - `true` if `MAILCOW_API_KEY_RW` is set, `false` otherwise

**Notes:**
- Fetched once by the frontend at startup and cached in a global variable
- Used to conditionally show/hide edit controls, action buttons, and write-operation UI
- Does not validate the key — only checks if it is configured

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

Initiate OAuth2 login flow. Redirects user to OAuth2 provider.

**Authentication:** Not required (public endpoint)

**Response:** HTTP 302 Redirect to OAuth2 provider authorization URL

**Error Responses:**
- `400 Bad Request`: OAuth2 is not enabled
- `500 Internal Server Error`: OAuth2 configuration error

**Notes:**
- Generates CSRF state token for security
- Only works when `OAUTH2_ENABLED=true`
- User will be redirected back to `/api/auth/callback` after authentication

---

### GET /api/auth/callback

Handle OAuth2 callback from provider. This endpoint processes the authorization code and creates a session.

**Authentication:** Not required (public endpoint)

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `code` | string | Authorization code from provider |
| `state` | string | CSRF state token (must match login request) |
| `error` | string | Error code from provider (if authentication failed) |

**Response:** HTTP 302 Redirect to `/` (main application) with session cookie set

**Error Handling:**
- Invalid or missing state token → Redirects to `/login?error=invalid_state`
- Missing authorization code → Redirects to `/login?error=missing_code`
- Provider error → Redirects to `/login?error=oauth2_error`
- Server error → Redirects to `/login?error=server_error`

**Notes:**
- Creates server-side session with user information
- Sets HTTP-only session cookie
- Session expiration controlled by `SESSION_EXPIRY_HOURS`

---

### GET /api/auth/logout

Logout and clear session.

**Authentication:** Not required (but session cookie must be present)

**Response:** HTTP 302 Redirect to `/login` with session cookie cleared

**Notes:**
- Deletes server-side session
- Clears session cookie
- Works for both OAuth2 and Basic Auth sessions

---

### GET /api/auth/status

Check current authentication status and get user information.

**Authentication:** Not required (returns status based on current session/credentials)

**Response (OAuth2 Session):**
```json
{
  "authenticated": true,
  "auth_type": "oauth2",
  "user": {
    "email": "user@example.com",
    "name": "John Doe",
    "sub": "user-id-123"
  }
}
```

**Response (Basic Auth):**
```json
{
  "authenticated": true,
  "auth_type": "basic",
  "user": null
}
```

**Response (Not Authenticated):**
```json
{
  "authenticated": false,
  "auth_type": null,
  "user": null
}
```

**Response Fields:**
- `authenticated`: Boolean - Whether user is authenticated
- `auth_type`: String - Authentication method: `"oauth2"`, `"basic"`, or `null`
- `user`: Object - User information (OAuth2 only, null for Basic Auth)

**Notes:**
- Checks for OAuth2 session cookie first
- Falls back to Basic Auth header if OAuth2 not found
- User object structure depends on OAuth2 provider (varies by provider)

---

### GET /api/auth/verify

Verify Basic Auth credentials. Used by the login form to validate username/password before redirecting to the main app. This endpoint is **not** in the public paths: the middleware validates the `Authorization: Basic` header and returns 401 if credentials are wrong.

**Authentication:** Required (HTTP Basic Auth). Invalid or missing credentials return 401.

**Response (Valid credentials):** `200 OK`
```json
{
  "verified": true
}
```

**Error Responses:**
- `401 Unauthorized`: Invalid or missing Basic Auth credentials (e.g. wrong username or password)

**Notes:**
- Only relevant when Basic Auth is enabled
- Login page calls this endpoint to test credentials; on 401 it shows "Invalid username or password" and does not redirect

---

## Job Status Tracking

### Overview

The application includes a real-time job status tracking system that monitors all background jobs. Each job reports its execution status, timestamp, and any errors that occurred.

### Job Status Data Structure

```python
job_status = {
    'fetch_logs': {'last_run': datetime, 'status': str, 'error': str|None},
    'complete_correlations': {'last_run': datetime, 'status': str, 'error': str|None},
    'update_final_status': {'last_run': datetime, 'status': str, 'error': str|None},
    'expire_correlations': {'last_run': datetime, 'status': str, 'error': str|None},
    'cleanup_logs': {'last_run': datetime, 'status': str, 'error': str|None},
    'check_app_version': {'last_run': datetime, 'status': str, 'error': str|None},
    'dns_check': {'last_run': datetime, 'status': str, 'error': str|None},
    'update_geoip': {'last_run': datetime, 'status': str, 'error': str|None},
    'cleanup_deferred_queue': {'last_run': datetime, 'status': str, 'error': str|None}
}
```

### Status Values

| Status | Description | Badge Color |
|--------|-------------|-------------|
| `running` | Job is currently executing | Blue (bg-blue-500) |
| `success` | Job completed successfully | Green (bg-green-600) |
| `failed` | Job encountered an error | Red (bg-red-600) |
| `idle` | Job hasn't run yet | Gray (bg-gray-500) |
| `scheduled` | Job is scheduled but runs infrequently | Purple (bg-purple-600) |

### Accessing Job Status

Job status is accessible through:
1. **Backend Function**: `get_job_status()` in `scheduler.py`
2. **API Endpoint**: `GET /api/settings/info` (includes `background_jobs` field)
3. **Frontend Display**: Settings page > Background Jobs section

### Background Jobs List

| Job Name | Interval | Description |
|----------|----------|-------------|
| **Fetch Logs** | 60 seconds | Imports Postfix, Rspamd, and Netfilter logs from mailcow API |
| **Complete Correlations** | 120 seconds (2 min) | Links Postfix logs to message correlations |
| **Update Final Status** | 120 seconds (2 min) | Updates message delivery status for late-arriving logs |
| **Expire Correlations** | 60 seconds (1 min) | Marks old incomplete correlations as expired (after 10 minutes) |
| **Cleanup Logs** | Daily at 2 AM | Removes logs older than retention period |
| **Check App Version** | 6 hours | Checks GitHub for application updates |
| **DNS Check** | 6 hours | Validates DNS records (SPF, DKIM, DMARC) for all active domains |
| **Update GeoIP** | Weekly (Sunday 3 AM) | Updates MaxMind GeoIP databases for DMARC source IP enrichment |
| **Detect Suppressions** | 5 minutes | Scans Postfix logs for hard bounces to auto-suppress recipients |
| **Cleanup Deferred Queue** | 5 minutes | Deletes deferred emails stuck longer than threshold and suppresses recipients |
| **Sync Suppressions** | 10 minutes | Syncs active suppressions to Rspamd recipient denylist |
| **Expire Suppressions** | 1 hour | Deactivates expired suppression entries |
| **Process Quarantine Rules** | 5 minutes | Processes quarantine auto-rules (release/delete matching emails) |

### Implementation Details

**Update Function:**
```python
def update_job_status(job_name: str, status: str, error: str = None):
    """Update job execution status"""
    job_status[job_name] = {
        'last_run': datetime.now(timezone.utc),
        'status': status,
        'error': error
    }
```

**Usage in Jobs:**
```python
async def some_background_job():
    try:
        update_job_status('job_name', 'running')
        # ... job logic ...
        update_job_status('job_name', 'success')
    except Exception as e:
        update_job_status('job_name', 'failed', str(e))
```

**UI Display:**
- Compact card layout with status badges
- Icon indicators (⏱ ⏳ 📅 🗂 📋)
- Last run timestamp always visible
- Error messages displayed in red alert boxes
- Pending items count for correlation jobs

---

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
          "message": "SPF configured correctly with strict -all policy. Server IP authorized via ip4:1.2.3.4",
          "record": "v=spf1 mx include:_spf.google.com -all",
          "has_strict_all": true,
          "includes_mx": true,
          "includes": ["_spf.google.com"],
          "warnings": [],
          "dns_lookups": 3
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
      }
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

**DNS Check Status Values:**
- `success`: Check passed with no issues
- `warning`: Check passed but with recommendations for improvement
- `error`: Check failed or record not found
- `unknown`: Check not yet performed

**SPF Status Indicators:**
- **DNS Lookup Limit**: Error if >10 lookups (RFC 7208)
- **Server IP Authorization**: Error if mail server IP not found in SPF
- **Multiple Records**: Error (only one SPF record allowed per domain)
- **Invalid Syntax**: Error (must start with `v=spf1 ` with space)
- **Invalid Mechanisms**: Error (only valid mechanisms allowed)
- `-all`: Strict policy (status: success)
- `~all`: Soft fail (status: success, informational)
- `?all`: Neutral (status: warning) - Provides minimal protection
- `+all`: Pass all (status: error) - Provides no protection
- Missing `all`: No policy defined (status: error)

**New SPF Fields:**
- `dns_lookups`: Integer count of DNS lookups (0-999)
- `warnings`: Array of warning messages

**DKIM Validation:**
- Fetches expected DKIM record from mailcow API
- Queries DNS for actual DKIM record
- Compares expected vs actual records
- `match`: Boolean indicating if records match
- **Parameter Validation**: Checks for security issues
  - `t=y` (Testing mode): Critical error
  - `t=s` (Strict subdomain): Informational only
  - `h=sha1` (Weak hash): Warning
  - `p=` (Empty key): Error - key revoked
  - Unknown key types: Warning

**New DKIM Fields:**
- `warnings`: Array of security warnings (with icons: ❌ ⚠️)
- `info`: Array of informational messages (plain text)
- `parameters`: Dictionary of parsed DKIM tags (v, k, t, h, p, etc.)

**DMARC Policy Types:**
- `reject`: Strict policy (status: success)
- `quarantine`: Moderate policy (status: warning) - Consider upgrading to reject
- `none`: Monitor only (status: warning) - Provides no protection

**Notes:**
- DNS checks are cached in database for performance
- `last_dns_check` only updates from global/scheduled checks, not individual domain checks
- `checked_at` (per domain) updates whenever that specific domain is checked
- All timestamps include UTC timezone indicator ('Z' suffix)

---

### POST /api/domains/check-all-dns

Manually trigger DNS validation for all active domains.

**Description:** 
Performs DNS checks (SPF, DKIM, DMARC) for all active domains and updates the global `last_dns_check` timestamp. Results are cached in database.

**Authentication:** Required

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
- Only checks active domains
- Updates `is_full_check=true` flag in database
- Updates global `last_dns_check` timestamp
- Frontend shows progress with toast notifications
- Returns immediately with status (check runs asynchronously)

---

### POST /api/domains/{domain}/check-dns

Manually trigger DNS validation for a specific domain.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | Domain name to check |

**Authentication:** Required

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
      "message": "SPF configured correctly with strict -all policy. Server IP authorized via ip4:1.2.3.4",
      "record": "v=spf1 mx include:_spf.google.com -all",
      "has_strict_all": true,
      "includes_mx": true,
      "includes": ["_spf.google.com"],
      "warnings": [],
      "dns_lookups": 3
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
- Frontend updates only that domain's section (no page refresh)
- Useful for verifying DNS changes immediately

---

### DNS Check Technical Details

**Async DNS Validation:**
- All DNS queries use async resolvers with 5-second timeout
- Queries run in parallel for performance
- Comprehensive error handling for timeouts, NXDOMAIN, NoAnswer

**SPF Validation:**
- Queries TXT records for SPF (`v=spf1`)
- Validates syntax and structure:
  - Checks for multiple SPF records (RFC violation)
  - Validates `v=spf1` with space after
  - Checks for valid mechanisms only (ip4, ip6, a, mx, include, exists, all)
  - Validates presence of `all` mechanism
- Detects policy: `-all`, `~all`, `?all`, `+all`, or missing
- Checks for `mx` mechanism
- Extracts `include:` directives
- **DNS Lookup Counter** (RFC 7208 compliance):
  - Recursively counts DNS lookups through includes
  - Counts `a`, `mx`, `exists:`, `redirect=`, and `include:` mechanisms
  - Maximum 10 lookups enforced (returns error if exceeded)
  - Returns `dns_lookups` field with count
- **Server IP Authorization**:
  - Fetches server IP from mailcow API once on startup
  - Verifies server IP is authorized via:
    - Direct `ip4:` match (including CIDR ranges)
    - `a` record resolution
    - `mx` record resolution
    - Recursive `include:` checking (up to 10 levels)
  - Returns authorization method in message (e.g., "Server IP authorized via ip4:X.X.X.X")
  - Returns error if server IP not found in SPF record
- Provides policy-specific warnings and recommendations

**DKIM Validation:**
- Fetches expected DKIM value from mailcow API (`/api/v1/get/dkim/{domain}`)
- Queries DNS at `{selector}._domainkey.{domain}`
- Compares expected vs actual records (whitespace-normalized)
- **Parameter Validation**:
  - Parses all DKIM tags (v, k, t, h, p, etc.)
  - **Testing Mode Detection** (`t=y`): Returns critical error
    - Warning: "Emails will pass validation even with invalid signatures"
    - Never use in production
  - **Strict Subdomain Mode** (`t=s`): Returns informational message
    - Only main domain can send, subdomains will fail DKIM
    - Does NOT affect validation status (remains "success")
  - **Revoked Key Detection** (`p=` empty): Returns error
    - Indicates DKIM has been intentionally disabled
  - **Weak Hash Algorithm** (`h=sha1`): Returns warning
    - Recommends upgrade to SHA256
  - **Key Type Validation** (`k=`): Validates rsa or ed25519
- Returns three arrays:
  - `warnings`: Security issues (errors and warnings with icons)
  - `info`: Informational messages (plain text, no status impact)
  - `parameters`: Parsed DKIM parameter dictionary
- Reports mismatch details

**DMARC Validation:**
- Queries TXT records at `_dmarc.{domain}`
- Parses policy (`p=` tag)
- Checks for subdomain policy (`sp=` tag)
- Validates percentage (`pct=` tag)
- Provides policy upgrade recommendations

**Background Checks:**
- Automated DNS checks run every 6 hours via scheduler
- Only checks active domains
- All automated checks marked as `is_full_check=true`
- Results cached in `domain_dns_checks` table

**Caching:**
- DNS results stored in PostgreSQL with JSONB columns
- Indexed on `domain_name` and `checked_at` for performance
- Upsert pattern (update if exists, insert if new)
- `is_full_check` flag distinguishes check types

---

### DNS Validation Examples

#### SPF Examples

**Example 1: Too Many DNS Lookups**
```json
{
  "status": "error",
  "message": "SPF has too many DNS lookups (11). Maximum is 10",
  "record": "v=spf1 include:_spf.exmail.email -all",
  "has_strict_all": true,
  "includes_mx": false,
  "includes": ["_spf.exmail.email"],
  "warnings": [
    "SPF record exceeds the 10 DNS lookup limit with 11 lookups",
    "This will cause SPF validation to fail"
  ],
  "dns_lookups": 11
}
```

**Example 2: Server IP Not Authorized**
```json
{
  "status": "error",
  "message": "Server IP 1.2.3.4 is NOT authorized in SPF record",
  "record": "v=spf1 ip4:1.2.3.4 -all",
  "has_strict_all": true,
  "includes_mx": false,
  "includes": [],
  "warnings": [
    "Mail server IP not found in SPF record"
  ],
  "dns_lookups": 0
}
```

**Example 3: Multiple SPF Records**
```json
{
  "status": "error",
  "message": "Multiple SPF records found (2). Only one is allowed",
  "record": "v=spf1 mx -all; v=spf1 ip4:1.2.3.4 -all",
  "has_strict_all": false,
  "includes_mx": false,
  "includes": [],
  "warnings": [
    "Multiple SPF records invalidate ALL records"
  ]
}
```

**Example 4: Success with Server IP Authorization**
```json
{
  "status": "success",
  "message": "SPF configured correctly with strict -all policy. Server IP authorized via include:_spf.google.com (ip4:1.2.3.4)",
  "record": "v=spf1 include:_spf.google.com -all",
  "has_strict_all": true,
  "includes_mx": false,
  "includes": ["_spf.google.com"],
  "warnings": [],
  "dns_lookups": 3
}
```

#### DKIM Examples

**Example 1: Testing Mode (Critical)**
```json
{
  "status": "error",
  "message": "DKIM is in TESTING mode (t=y) - Emails will pass validation even with invalid signatures. Remove t=y for production!",
  "selector": "dkim",
  "dkim_domain": "dkim._domainkey.example.com",
  "expected_record": "v=DKIM1;k=rsa;t=y;p=MIIBIjANBg...",
  "actual_record": "v=DKIM1;k=rsa;t=y;p=MIIBIjANBg...",
  "match": true,
  "warnings": [],
  "info": [],
  "parameters": {
    "v": "DKIM1",
    "k": "rsa",
    "t": "y",
    "p": "MIIBIjANBg..."
  }
}
```

**Example 2: Strict Subdomain Mode (Informational)**
```json
{
  "status": "success",
  "message": "DKIM configured correctly",
  "selector": "dkim",
  "dkim_domain": "dkim._domainkey.example.com",
  "expected_record": "v=DKIM1;k=rsa;t=s;p=MIIBIjANBg...",
  "actual_record": "v=DKIM1;k=rsa;t=s;p=MIIBIjANBg...",
  "match": true,
  "warnings": [],
  "info": [
    "DKIM uses strict subdomain mode (t=s)"
  ],
  "parameters": {
    "v": "DKIM1",
    "k": "rsa",
    "t": "s",
    "p": "MIIBIjANBg..."
  }
}
```

**Example 3: SHA1 Warning**
```json
{
  "status": "warning",
  "message": "DKIM configured but has warnings",
  "selector": "dkim",
  "dkim_domain": "dkim._domainkey.example.com",
  "expected_record": "v=DKIM1;k=rsa;h=sha1;p=MIIBIjANBg...",
  "actual_record": "v=DKIM1;k=rsa;h=sha1;p=MIIBIjANBg...",
  "match": true,
  "warnings": [
    "⚠️ DKIM uses SHA1 hash algorithm (h=sha1)"
  ],
  "info": [],
  "parameters": {
    "v": "DKIM1",
    "k": "rsa",
    "h": "sha1",
    "p": "MIIBIjANBg..."
  }
}
```

**Example 4: Revoked Key**
```json
{
  "status": "error",
  "message": "DKIM key is revoked (p= is empty)",
  "selector": "dkim",
  "dkim_domain": "dkim._domainkey.example.com",
  "expected_record": "v=DKIM1;k=rsa;p=",
  "actual_record": "v=DKIM1;k=rsa;p=",
  "match": true,
  "warnings": [
    "❌ DKIM key is revoked (p= is empty)"
  ],
  "info": [],
  "parameters": {
    "v": "DKIM1",
    "k": "rsa",
    "p": ""
  }
}
```

**Example 5: Multiple Issues**
```json
{
  "status": "warning",
  "message": "DKIM configured but has warnings",
  "selector": "dkim",
  "dkim_domain": "dkim._domainkey.example.com",
  "expected_record": "v=DKIM1;k=rsa;t=s;h=sha1;p=MIIBIjANBg...",
  "actual_record": "v=DKIM1;k=rsa;t=s;h=sha1;p=MIIBIjANBg...",
  "match": true,
  "warnings": [
    "⚠️ DKIM uses SHA1 hash algorithm (h=sha1)"
  ],
  "info": [
    "DKIM uses strict subdomain mode (t=s)"
  ],
  "parameters": {
    "v": "DKIM1",
    "k": "rsa",
    "t": "s",
    "h": "sha1",
    "p": "MIIBIjANBg..."
  }
}
```

---

## Mailbox Statistics

### GET /api/mailbox-stats/summary

Get summary statistics for all mailboxes.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `date_range` | string | Date range: `today`, `7days`, `30days`, `90days` (default: `30days`) |

**Response:**
```json
{
  "total_mailboxes": 25,
  "active_mailboxes": 23,
  "inactive_mailboxes": 2,
  "total_sent": 1234,
  "total_received": 5678,
  "sent_failed": 45,
  "failure_rate": 3.6,
  "date_range": "30days",
  "start_date": "2026-01-16T00:00:00Z",
  "end_date": "2026-02-16T00:00:00Z"
}
```

---

### GET /api/mailbox-stats/all

Get all mailbox statistics with message counts and aliases (paginated).

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | Filter by domain name |
| `active_only` | bool | Only show active mailboxes (default: `true`) |
| `hide_zero` | bool | Hide mailboxes with zero activity (default: `false`) |
| `search` | string | Search mailbox username, name, or alias address |
| `date_range` | string | Date range: `today`, `7days`, `30days`, `90days` (default: `30days`) |
| `sort_by` | string | Sort by: `sent_total`, `received_total`, `failure_rate`, `quota_used`, `username` |
| `sort_order` | string | Sort order: `asc`, `desc` (default: `desc`) |
| `page` | int | Page number (default: `1`) |
| `page_size` | int | Items per page, 10-100 (default: `50`) |

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
        "sent_failed": 5,
        "received_total": 320,
        "failure_rate": 3.3
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
        }
      ],
      "alias_count": 1,
      "combined_sent": 200,
      "combined_received": 420,
      "combined_total": 620,
      "combined_failed": 7,
      "combined_failure_rate": 3.5,
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
| `aliases` | Array of alias statistics |
| `combined_*` | Combined totals (mailbox + all aliases) |
| `created` / `modified` | Mailbox creation and last update timestamps |

---

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
      "domain": "company.org",
      "mailbox_count": 10
    }
  ]
}
```

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

**Cache Management:**
```python
from app.routers.mailbox_stats import clear_stats_cache

# Clear all stats cache (e.g., after data import)
clear_stats_cache()
```

---

## Messages (Unified View)

### GET /messages

Get unified messages view combining Postfix and Rspamd data.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | int | Page number (default: 1) |
| `limit` | int | Items per page (default: 50, max: 500) |
| `search` | string | Search in sender, recipient, subject, message_id, queue_id |
| `sender` | string | Filter by sender email |
| `recipient` | string | Filter by recipient email |
| `direction` | string | Filter by direction: `inbound`, `outbound`, `internal` |
| `status` | string | Filter by status: `delivered`, `bounced`, `deferred`, `rejected`, `spam`<br>**Note:** `spam` filter checks both `final_status='spam'` and `is_spam=True` from Rspamd |
| `user` | string | Filter by authenticated user |
| `ip` | string | Filter by source IP address |
| `start_date` | datetime | Start date (ISO format) |
| `end_date` | datetime | End date (ISO format) |

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
      "recipient": "recipient@gmail.com",
      "subject": "Hello World",
      "direction": "outbound",
      "final_status": "delivered",
      "is_complete": true,
      "first_seen": "2025-12-25T10:30:00Z",
      "last_seen": "2025-12-25T10:30:05Z",
      "spam_score": 0.5,
      "is_spam": false,
      "user": "user@example.com",
      "ip": "192.168.1.100"
    }
  ]
}
```

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
  "recipient": "recipient@gmail.com",
  "recipients": ["recipient@gmail.com", "cc@gmail.com"],
  "recipient_count": 2,
  "subject": "Hello World",
  "direction": "outbound",
  "final_status": "delivered",
  "is_complete": true,
  "first_seen": "2025-12-25T10:30:00Z",
  "last_seen": "2025-12-25T10:30:05Z",
  "rspamd": {
    "time": "2025-12-25T10:30:00Z",
    "score": 0.5,
    "required_score": 15,
    "action": "no action",
    "symbols": {
      "MAILCOW_AUTH": {"score": -20, "description": "mailcow authenticated"},
      "RCVD_COUNT_ZERO": {"score": 0, "options": ["0"]}
    },
    "is_spam": false,
    "direction": "outbound",
    "ip": "192.168.1.100",
    "user": "user@example.com",
    "has_auth": true,
    "size": 1024
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
      "message": "ABC123DEF: to=<recipient@gmail.com>, relay=gmail-smtp-in.l.google.com...",
      "status": "sent",
      "relay": "gmail-smtp-in.l.google.com[142.251.168.26]:25",
      "delay": 1.5,
      "dsn": "2.0.0"
    }
  ],
  "postfix_by_recipient": {
    "recipient@gmail.com": [...],
    "cc@gmail.com": [...],
    "_system": [...]
  },
  "netfilter": []
}
```

---

## Logs

### Postfix Logs

#### GET /logs/postfix

Get Postfix logs grouped by Queue-ID.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | int | Page number (default: 1) |
| `limit` | int | Items per page (default: 50, max: 500) |
| `search` | string | Search in message, sender, recipient, queue_id |
| `sender` | string | Filter by sender |
| `recipient` | string | Filter by recipient |
| `status` | string | Filter by status: `sent`, `bounced`, `deferred`, `rejected` |
| `queue_id` | string | Filter by specific queue ID |
| `start_date` | datetime | Start date |
| `end_date` | datetime | End date |

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
      "relay": "mail.example.com[1.2.3.4]:25",
      "delay": 1.5,
      "dsn": "2.0.0",
      "correlation_key": "abc123..."
    }
  ]
}
```

---

#### GET /logs/postfix/by-queue/{queue_id}

Get all Postfix logs for a specific Queue-ID with linked Rspamd data.

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
    "symbols": {...},
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

Get Rspamd spam analysis logs.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | int | Page number (default: 1) |
| `limit` | int | Items per page (default: 50, max: 500) |
| `search` | string | Search in subject, sender, message_id |
| `sender` | string | Filter by sender |
| `direction` | string | Filter: `inbound`, `outbound`, `internal`, `unknown` |
| `min_score` | float | Minimum spam score |
| `max_score` | float | Maximum spam score |
| `action` | string | Filter by action: `no action`, `greylist`, `add header`, `reject` |
| `is_spam` | boolean | Filter spam only (`true`) or clean only (`false`) |
| `start_date` | datetime | Start date |
| `end_date` | datetime | End date |

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
      "ip": "192.168.1.100",
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

Get Netfilter authentication failure logs.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | int | Page number (default: 1) |
| `limit` | int | Items per page (default: 50, max: 500) |
| `search` | string | Search in message, IP, username |
| `ip` | string | Filter by IP address |
| `username` | string | Filter by username |
| `action` | string | Filter: `warning`, `banned` |
| `start_date` | datetime | Start date |
| `end_date` | datetime | End date |

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
      "message": "1.1.1.1 matched rule id 3...",
      "ip": "1.1.1.1",
      "rule_id": 3,
      "attempts_left": 9,
      "username": "user@example.com",
      "auth_method": "SASL LOGIN",
      "action": "warning"
    }
  ]
}
```

---

### Fail2Ban Configuration

#### GET /fail2ban

Get current Fail2Ban configuration from mailcow (real-time proxy to `/api/v1/get/fail2ban`).

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
  "whitelist": "127.0.0.1/8\n10.0.0.0/8",
  "blacklist": "",
  "perm_bans": [],
  "active_bans": [...]
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
| `perm_bans` | array | List of permanently banned IPs |
| `active_bans` | array | List of currently active bans |

**Error Responses:**
- `503 Service Unavailable`: Could not reach the mailcow API

#### POST /fail2ban

Update Fail2Ban configuration on mailcow. Requires the Read-Write API key (`MAILCOW_API_KEY_RW`).

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
    "whitelist": "127.0.0.1/8",
    "blacklist": "10.100.6.5/32"
  }
}
```

> **Note:** All parameters must be sent in the request body, not just the ones that changed.

**Response:**
```json
[
  {
    "type": "success",
    "log": ["fail2ban", "edit", { ... }],
    "msg": ["fail2ban_edit_ok"]
  }
]
```

**Error Responses:**
- `400 Bad Request`: Invalid payload or mailcow rejected the update
- `403 Forbidden`: Read-Write API key is not configured
- `503 Service Unavailable`: Could not reach the mailcow API

#### RW Status Check

See [GET /rw-status](#get-rw-status) — unified endpoint for checking Read-Write API key availability.

---

## Queue & Quarantine

### GET /queue

Get current mail queue from mailcow (real-time).

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
        "user@example.com (connect to example.com[1.2.3.4]:25: Connection timed out)"
      ]
    }
  ]
}
```
---

### POST /queue/action

Perform an action on mail queue items. Requires a Read-Write API key (`MAILCOW_API_KEY_RW`).

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
- `500 Internal Server Error`: RW API key not configured or mailcow API error

**Notes:**
- Proxies to mailcow `POST /api/v1/edit/mailq` with `{"items": [...], "attr": {"action": "..."}}`
- For bulk actions (`flush`, `super_delete`), use `["mailqitems-all"]` as items

---

### POST /queue/delete

Delete specific mail queue items. Requires a Read-Write API key (`MAILCOW_API_KEY_RW`).

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
- `500 Internal Server Error`: RW API key not configured or mailcow API error

**Notes:**
- Proxies to mailcow `POST /api/v1/delete/mailq` with queue IDs array
- For deleting ALL items, use `POST /queue/action` with `action: "super_delete"` instead

---

### GET /quarantine

Get quarantined messages from mailcow (real-time).

**Response:**
```json
{
  "total": 3,
  "data": [
    {
      "id": 123,
      "subject": "Suspicious Email",
      "sender": "spammer@evil.com",
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

Quarantine actions require a Read-Write API key. See [GET /rw-status](#get-rw-status) for checking availability.

---

### POST /quarantine/release

Release (approve) quarantined messages on mailcow. Requires a Read-Write API key (`MAILCOW_API_KEY_RW`).

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
- `500 Internal Server Error`: RW API key not configured or mailcow API error

**Notes:**
- Proxies to mailcow `POST /api/v1/edit/qitem` with `{"items": [...], "attr": {"action": "release"}}`
- Released messages are delivered to the original recipient's mailbox
- Supports releasing multiple messages in a single request

---

### POST /quarantine/delete

Permanently delete quarantined messages on mailcow. Requires a Read-Write API key (`MAILCOW_API_KEY_RW`).

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
- `500 Internal Server Error`: RW API key not configured or mailcow API error

**Notes:**
- Proxies to mailcow `POST /api/v1/delete/qitem` with `["id1", "id2"]`
- Deleted messages are permanently removed and cannot be recovered
- Supports deleting multiple messages in a single request

---

### POST /quarantine/learnham

Release quarantined messages and train Rspamd that they are **not spam** (ham). Requires a Read-Write API key (`MAILCOW_API_KEY_RW`).

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
- `500 Internal Server Error`: RW API key not configured or mailcow API error

**Notes:**
- Proxies to mailcow `POST /api/v1/edit/qitem` with `{"items": [...], "attr": {"action": "learnham"}}`
- The message is released to the recipient's mailbox AND Rspamd is trained to recognize similar messages as legitimate
- Supports multiple items in a single request

---

### POST /quarantine/learnspam

Delete quarantined messages and train Rspamd that they are **spam**. Requires a Read-Write API key (`MAILCOW_API_KEY_RW`).

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
- `500 Internal Server Error`: RW API key not configured or mailcow API error

**Notes:**
- Proxies to mailcow `POST /api/v1/edit/qitem` with `{"items": [...], "attr": {"action": "learnspam"}}`
- The message is permanently deleted AND Rspamd is trained to recognize similar messages as spam
- Supports multiple items in a single request

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
- Used by the frontend's email detail modal

---

## Statistics

### GET /stats/dashboard

Get main dashboard statistics.

**Response:**
```json
{
  "messages": {
    "24h": 1234,
    "7d": 8765,
    "30d": 34567
  },
  "spam": {
    "24h": 56,
    "7d": 234,
    "percentage_24h": 4.54
  },
  "failed_deliveries": {
    "24h": 12,
    "7d": 45
  },
  "auth_failures": {
    "24h": 89,
    "7d": 456
  },
  "direction": {
    "inbound_24h": 800,
    "outbound_24h": 434,
    "internal_24h": 120
  }
}
```

---

### GET /stats/timeline

Get message timeline for charts.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `hours` | int | Number of hours to show (default: 24) |

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

Get top spam detection symbols.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | int | Number of results (default: 10) |

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

Get top blocked/warned IP addresses.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | int | Number of results (default: 10) |

**Response:**
```json
{
  "blocked_ips": [
    {
      "ip": "1.1.1.1",
      "count": 45,
      "last_seen": "2025-12-25T10:30:00Z"
    }
  ]
}
```

---

### GET /stats/recent-activity

Get recent message activity stream.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | int | Number of results (default: 20) |

**Response:**
```json
{
  "activity": [
    {
      "time": "2025-12-25T10:30:00Z",
      "sender": "user@example.com",
      "recipient": "other@gmail.com",
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
      "started_at": "2025-12-20T08:00:00Z"
    },
    "dovecot-mailcow": {
      "name": "dovecot",
      "state": "running",
      "started_at": "2025-12-20T08:00:00Z"
    }
  },
  "summary": {
    "running": 18,
    "stopped": 0,
    "total": 18
  }
}
```

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

Get application version and check for updates from GitHub.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `force` | boolean | Force a fresh version check regardless of cache age (default: false) |

**Response:**
```json
{
  "current_version": "1.4.9",
  "latest_version": "1.4.9",
  "update_available": false,
  "changelog": "### Added\n\n#### Background Jobs Enhanced UI\n- Compact layout...",
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

**Description:**
Returns comprehensive system configuration, import status, correlation status, and background job status. When `SETTINGS_EDIT_VIA_UI_ENABLED=true`, also includes editable configuration and migration status.

**Authentication:** Required

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
    "local_domains": ["example.com"],
    "fetch_interval": 60,
    "fetch_count_postfix": 2000,
    "fetch_count_rspamd": 500,
    "fetch_count_netfilter": 500,
    "retention_days": 7,
    "timezone": "UTC",
    "app_title": "mailcow Logs Viewer",
    "log_level": "WARNING",
    "blacklist_enabled": true,
    "blacklist_count": 3,
    "max_search_results": 1000,
    "csv_export_limit": 10000,
    "scheduler_workers": 4,
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
      "status": "scheduled",
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
      "description": "Updates MaxMind GeoIP databases for DMARC source IP enrichment",
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
      "recipient": "other@gmail.com",
      "created_at": "2025-12-25T10:28:00Z",
      "age_minutes": 2
    }
  ]
}
```

**Response Fields (when `SETTINGS_EDIT_VIA_UI_ENABLED=true`):**
- `settings_edit_via_ui_enabled`: Boolean indicating if UI editing is enabled
- `settings_migrated`: Boolean indicating if settings have been migrated from ENV to DB
- `editable_config`: Dictionary of editable settings (sensitive fields masked) - only present when UI editing is enabled

**Background Jobs Status Tracking:**

Each background job reports real-time execution status:

| Field | Type | Description |
|-------|------|-------------|
| `interval` / `schedule` | string | How often the job runs |
| `description` | string | Human-readable job description |
| `status` | string | Current status: `running`, `success`, `failed`, `idle`, `scheduled` |
| `last_run` | datetime | UTC timestamp of last execution (with 'Z' suffix) |
| `error` | string / null | Error message if job failed, otherwise null |
| `pending_items` | int | Number of items waiting (for correlation jobs only) |
| `max_age` / `expire_after` / `retention` | string | Job-specific configuration |

**Status Values:**
- `running` - Job is currently executing
- `success` - Job completed successfully
- `failed` - Job encountered an error
- `idle` - Job hasn't run yet
- `scheduled` - Job is scheduled but runs infrequently (e.g., daily cleanup)

**Job Descriptions:**

1. **fetch_logs**: Fetches Postfix, Rspamd, and Netfilter logs from mailcow API every 60 seconds
2. **complete_correlations**: Links Postfix logs to message correlations every 2 minutes
3. **update_final_status**: Updates message delivery status when late-arriving Postfix logs are found
4. **expire_correlations**: Marks old incomplete correlations as expired after 10 minutes
5. **cleanup_logs**: Removes logs older than retention period (runs daily at 2 AM)
6. **check_app_version**: Checks GitHub for application updates every 6 hours
7. **dns_check**: Validates DNS records (SPF, DKIM, DMARC) for all active domains every 6 hours
8. **update_geoip**: Updates MaxMind GeoLite2 databases (City + ASN) for DMARC source IP enrichment (runs weekly on Sunday at 3 AM)

---

### GET /api/settings

Get editable settings configuration for UI editing.

**Description:**
Returns all settings that can be edited via the web UI, along with feature flags and migration status. Only available when `SETTINGS_EDIT_VIA_UI_ENABLED=true`.

**Authentication:** Required

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
    "app_port": 8080,
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
    "dmarc_imap_host": "imap.gmail.com",
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
- `settings_edit_via_ui_enabled`: Boolean indicating if UI editing is enabled
- `settings_migrated`: Boolean indicating if settings have been migrated from ENV to DB
- `configuration`: Dictionary of all editable settings (sensitive fields are masked with `********`)
- `env_locked_keys`: Array of setting keys where an ENV variable is explicitly set (ENV always overrides DB for these keys)

**Sensitive Fields (Masked):**
- `mailcow_api_key`
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
- Only editable settings are included (PostgreSQL database settings are excluded)

---

### PUT /api/settings

Update settings from web UI.

**Description:**
Updates application settings stored in database. Only available when `SETTINGS_EDIT_VIA_UI_ENABLED=true`. Settings are validated before saving, and all components (including MailcowAPI) are automatically reloaded.

**Authentication:** Required

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
- Non-sensitive fields: Send `null` or omit to use default value

#### Basic Auth Lockout Prevention

When enabling Basic Auth (`basic_auth_enabled` changing from `false` to `true`), the request must include two additional verification fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `verify_username` | string | Yes (when enabling auth) | The username to verify — must match `auth_username` being saved |
| `verify_password` | string | Yes (when enabling auth) | The password to verify — must match `auth_password` being saved |

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

> **Note:** `verify_username` and `verify_password` are only required when enabling Basic Auth (switching from `false` to `true`). They are not needed when disabling Basic Auth or when Basic Auth is already enabled.

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
  }
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
  "detail": "Validation error: 1 validation error for Settings\nmailcow_url\n  Input should be a valid string [type=string_type, input_value=None, input_type=NoneType]"
}
```

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
- Only editable settings are accepted (PostgreSQL settings are filtered out)
- Settings are validated using Pydantic before saving
- `********` for sensitive fields means "keep current value" (not changed)
- Settings are automatically reloaded after saving
- MailcowAPI configuration is automatically updated
- Returns updated configuration with masked sensitive fields
- When enabling Basic Auth, credential verification uses timing-safe comparison (`secrets.compare_digest`)

---

### POST /api/settings/import-from-env

Import current configuration from environment variables to database.

**Description:**
Migrates all current effective settings (from defaults + ENV + existing DB) into database. This allows users to transition from ENV-only management to UI management. After migration, ENV variables can be removed (except `SETTINGS_EDIT_VIA_UI_ENABLED`).

**Authentication:** Required

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

Delete all database data associated with a disabled feature.

**Description:**
When a feature is disabled, this endpoint permanently deletes all stored data from that feature's database tables. The feature must already be disabled (in `disabled_features`). Only available when `SETTINGS_EDIT_VIA_UI_ENABLED=true`.

**Authentication:** Required

**Request Body:**
```json
{
  "feature": "dmarc"
}
```

**Request Fields:**
- `feature`: Feature ID to purge. Valid values: `netfilter`, `domains`, `dmarc`, `mailbox-stats`, `logs`, `blacklist`, `spam-filter`, `quarantine`

**Feature → Tables Mapping:**

| Feature | Tables Truncated |
|---------|-----------------|
| `netfilter` | `netfilter_logs` |
| `domains` | `domain_dns_checks` |
| `dmarc` | `dmarc_reports`, `dmarc_records`, `dmarc_syncs`, `tls_reports`, `tls_report_policies` |
| `mailbox-stats` | `mailbox_statistics`, `alias_statistics` |
| `logs` | `raw_service_logs` |
| `blacklist` | `blacklist_checks`, `monitored_hosts` |
| `spam-filter` | `spam_suppressions` |
| `quarantine` | `quarantine_rules`, `quarantine_rule_logs` |

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

**Notes:**
- Tables are truncated with `CASCADE` to handle foreign key relationships
- The frontend automatically calls this endpoint after saving settings with newly disabled features
- A confirmation dialog warns the user before disabling a feature that data will be deleted
- Features without database tables (e.g., `queue`) are not purgeable — the endpoint returns 400 for unknown features

---

### GET /settings/health

Detailed health check with timing information.

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

---

## GeoIP Management

### GET /api/settings/geoip/status

Get detailed GeoIP status for frontend polling during setup/download.

**Authentication:** Required

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
- `configured`: Boolean — whether MaxMind Account ID and License Key are set
- `db_valid`: Boolean or null — `true` if DB validated, `false` if corrupt, `null` if not yet checked
- `databases`: Object — file-level info for City and ASN databases (size, age, availability)
- `job_status`: String — last GeoIP update job status: `idle`, `running`, `success`, `failed`
- `job_error`: String or null — error message if last job failed
- `job_last_run`: String or null — ISO timestamp of last job execution

**Notes:**
- Used by the GeoIP Setup Modal to poll download progress
- Returns `configured: false` when credentials are not set

---

### POST /api/settings/geoip/download

Trigger GeoIP database download in background.

**Authentication:** Required

**Response:**
```json
{
  "status": "started",
  "message": "GeoIP download started in background"
}
```

**Error Responses:**
- `400`: MaxMind license key not configured

**Notes:**
- Returns immediately; download runs in background
- Use `GET /api/settings/geoip/status` to poll progress (`job_status` field)
- Download includes both GeoLite2-City and GeoLite2-ASN databases
- After download completes, readers are reloaded and validated automatically

---

### POST /api/settings/maxmind/validate

Validate MaxMind license key on-demand. Result is persisted to database.

**Authentication:** Required

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
- `configured`: Boolean — whether a MaxMind license key is present
- `valid`: Boolean — whether the license key passed MaxMind's validation API
- `error`: String or null — error description if validation failed (`"Invalid"`, `"Connection error"`, `"Status {code}"`)

**Notes:**
- Validates against MaxMind's `secret-scanning.maxmind.com` API with a 5-second timeout
- Result is **persisted in the database** (`system_settings` table) so it survives page refreshes and container restarts
- The `maxmind_status` field in `GET /api/settings/info` returns the last persisted result (or `null` if never checked)
- Clearing MaxMind credentials via `PUT /api/settings` automatically clears the persisted validation result
- The scheduled "Update MaxMind Databases" job also marks the license as valid after a successful database download

---

### POST /api/settings/geoip/validate

Validate GeoIP database integrity by running test IP lookups.

**Authentication:** Required

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
- `valid`: Boolean — overall validation result
- `city_ok`: Boolean — City database passed lookup test
- `asn_ok`: Boolean — ASN database passed lookup test
- `db_valid`: Boolean or null — current `_geoip_db_valid` state after reload

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
- Tests lookups against well-known IPs (8.8.8.8, 1.1.1.1)
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
    "Use TLS: true",
    "User: noreply@example.com",
    "Connecting to SMTP server...",
    "Connected",
    "Starting TLS...",
    "TLS established",
    "Logging in...",
    "Login successful",
    "Sending test email...",
    "Test email sent successfully",
    "Connection closed",
    "✓ SMTP test completed successfully"
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
    "Connecting to SMTP server...",
    "✗ Authentication failed: (535, b'5.7.8 Error: authentication failed')"
  ]
}
```

**Response Fields:**
- `success`: Boolean indicating if test passed
- `logs`: Array of log messages showing connection attempt details

**Notes:**
- Sends actual test email to configured admin email address
- Tests full connection flow: connect → TLS → authenticate → send
- Useful for diagnosing SMTP configuration issues
- Returns detailed error messages on failure

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
    "Use SSL: true",
    "User: dmarc@example.com",
    "Folder: INBOX",
    "Connecting to IMAP server...",
    "Connected using SSL",
    "Logging in...",
    "Login successful",
    "Listing mailboxes...",
    "Found 5 mailboxes:",
    "  - \"INBOX\"",
    "  - \"Sent\"",
    "  - \"Drafts\"",
    "  - \"Spam\"",
    "  - \"Trash\"",
    "Selecting folder: INBOX",
    "Folder selected: 42 messages",
    "Searching for emails...",
    "Found 42 emails in folder",
    "Connection closed",
    "✓ IMAP test completed successfully"
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
    "Connecting to IMAP server...",
    "✗ IMAP error: [AUTHENTICATIONFAILED] Authentication failed."
  ]
}
```

**Response Fields:**
- `success`: Boolean indicating if test passed
- `logs`: Array of log messages showing connection attempt details

**Notes:**
- Tests full connection flow: connect → authenticate → list folders → select folder
- Shows available mailboxes and message count
- Useful for diagnosing IMAP configuration issues
- Does not modify or process any emails
- Returns detailed error messages on failure

---

## Export

### GET /export/postfix/csv

Export Postfix logs to CSV file.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `search` | string | Search filter |
| `sender` | string | Filter by sender |
| `recipient` | string | Filter by recipient |
| `status` | string | Filter by status |
| `start_date` | datetime | Start date |
| `end_date` | datetime | End date |

**Response:** CSV file download

**Columns:** Time, Program, Priority, Queue ID, Message ID, Sender, Recipient, Status, Relay, Delay, DSN, Message

---

### GET /export/rspamd/csv

Export Rspamd logs to CSV file.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `search` | string | Search filter |
| `sender` | string | Filter by sender |
| `direction` | string | Filter by direction |
| `min_score` | float | Minimum spam score |
| `max_score` | float | Maximum spam score |
| `is_spam` | boolean | Filter by spam status |
| `start_date` | datetime | Start date |
| `end_date` | datetime | End date |

**Response:** CSV file download

**Columns:** Time, Message ID, Subject, Sender, Recipients, Score, Required Score, Action, Direction, Is Spam, Has Auth, User, IP, Size, Top Symbols

---

### GET /export/netfilter/csv

Export Netfilter logs to CSV file.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `search` | string | Search filter |
| `ip` | string | Filter by IP |
| `username` | string | Filter by username |
| `start_date` | datetime | Start date |
| `end_date` | datetime | End date |

**Response:** CSV file download

**Columns:** Time, IP, Username, Auth Method, Action, Attempts Left, Rule ID, Priority, Message

---

### GET /export/messages/csv

Export Messages (correlations) to CSV file.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `search` | string | Search filter |
| `sender` | string | Filter by sender |
| `recipient` | string | Filter by recipient |
| `direction` | string | Filter by direction |
| `status` | string | Filter by status |
| `user` | string | Filter by authenticated user |
| `ip` | string | Filter by IP address |
| `start_date` | datetime | Start date |
| `end_date` | datetime | End date |

**Response:** CSV file download

**Columns:** Time, Sender, Recipient, Subject, Direction, Status, Queue ID, Message ID, Spam Score, Is Spam, User, IP, Is Complete

---

## DMARC

### Overview

The DMARC module provides comprehensive email authentication monitoring through DMARC (Domain-based Message Authentication, Reporting & Conformance) aggregate reports. It includes automatic report parsing, GeoIP enrichment for source IPs, and detailed analytics.

**Features:**
- Automatic DMARC report parsing (XML, GZ, ZIP formats)
- GeoIP enrichment (country, city, ISP/ASN) via MaxMind databases
- Domain-centric view with daily aggregation
- Source IP analysis with authentication results
- Historical trending and compliance monitoring

---

### GET /api/dmarc/domains

Get list of all domains with DMARC statistics.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | integer | 30 | Number of days to look back (1-365) |

**Response:**
```json
{
  "total_domains": 5,
  "total_messages": 12458,
  "total_unique_ips": 142,
  "overall_dmarc_pass_pct": 97.2,
  "domains": [
    {
      "domain": "example.com",
      "total_messages": 8234,
      "unique_ips": 89,
      "dmarc_pass_pct": 98.5,
      "spf_pass_pct": 99.1,
      "dkim_pass_pct": 98.9,
      "policy_p": "reject",
      "policy_sp": null,
      "last_report_date": 1704758400
    }
  ]
}
```

**Response Fields:**
- `total_domains`: Number of domains with DMARC reports
- `total_messages`: Total email messages across all domains
- `total_unique_ips`: Total unique source IPs
- `overall_dmarc_pass_pct`: Overall DMARC pass rate percentage
- `domains`: Array of domain statistics

**Domain Object Fields:**
- `domain`: Domain name
- `total_messages`: Total messages for this domain
- `unique_ips`: Number of unique source IPs
- `dmarc_pass_pct`: Percentage of messages passing both SPF and DKIM
- `spf_pass_pct`: SPF pass rate
- `dkim_pass_pct`: DKIM pass rate
- `policy_p`: Published DMARC policy (none, quarantine, reject)
- `policy_sp`: Subdomain policy (if different from main policy)
- `last_report_date`: Unix timestamp of most recent report

---

### GET /api/dmarc/domains/{domain}/overview

Get detailed overview for a specific domain with daily breakdown.

**Path Parameters:**
- `domain`: Domain name (URL encoded)

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | integer | 30 | Number of days to look back (1-365) |

**Response:**
```json
{
  "domain": "example.com",
  "total_messages": 8234,
  "unique_ips": 89,
  "unique_reporters": 12,
  "dmarc_pass_pct": 98.5,
  "spf_pass_pct": 99.1,
  "dkim_pass_pct": 98.9,
  "policy": {
    "p": "reject",
    "sp": null,
    "adkim": "r",
    "aspf": "r",
    "pct": 100,
    "fo": "0"
  },
  "daily_stats": [
    {
      "date": 1704758400,
      "total_messages": 287,
      "dmarc_pass_pct": 98.3,
      "spf_pass_pct": 99.0,
      "dkim_pass_pct": 98.6
    }
  ]
}
```

**Response Fields:**
- `domain`: Domain name
- `total_messages`: Total messages in period
- `unique_ips`: Number of unique source IPs
- `unique_reporters`: Number of unique organizations sending reports
- `dmarc_pass_pct`: DMARC pass rate (SPF + DKIM aligned)
- `spf_pass_pct`: SPF pass rate
- `dkim_pass_pct`: DKIM pass rate
- `policy`: Published DMARC policy object
- `daily_stats`: Array of daily statistics

**Policy Object:**
- `p`: Domain policy (none, quarantine, reject)
- `sp`: Subdomain policy
- `adkim`: DKIM alignment mode (r=relaxed, s=strict)
- `aspf`: SPF alignment mode (r=relaxed, s=strict)
- `pct`: Percentage of messages to apply policy to
- `fo`: Failure reporting options

**Daily Stats Object:**
- `date`: Unix timestamp (midnight UTC)
- `total_messages`: Messages for this day
- `dmarc_pass_pct`: DMARC pass rate
- `spf_pass_pct`: SPF pass rate
- `dkim_pass_pct`: DKIM pass rate

---

### GET /api/dmarc/domains/{domain}/reports

Get daily aggregated reports for a specific domain.

**Path Parameters:**
- `domain`: Domain name (URL encoded)

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | integer | 30 | Number of days to look back (1-365) |

**Response:**
```json
{
  "domain": "example.com",
  "reports": [
    {
      "date": 1704758400,
      "report_count": 12,
      "unique_ips": 45,
      "total_messages": 287,
      "dmarc_pass_pct": 98.3,
      "spf_pass_pct": 99.0,
      "dkim_pass_pct": 98.6,
      "reporters": [
        "Google",
        "Microsoft",
        "Yahoo"
      ]
    }
  ]
}
```

**Response Fields:**
- `domain`: Domain name
- `reports`: Array of daily aggregated reports

**Report Object:**
- `date`: Unix timestamp (midnight UTC)
- `report_count`: Number of DMARC reports received for this day
- `unique_ips`: Number of unique source IPs
- `total_messages`: Total messages in all reports
- `dmarc_pass_pct`: DMARC compliance rate
- `spf_pass_pct`: SPF pass rate
- `dkim_pass_pct`: DKIM pass rate
- `reporters`: Array of organizations that sent reports (e.g., "Google", "Microsoft")

---

### GET /api/dmarc/domains/{domain}/sources

Get source IP analysis with GeoIP enrichment.

**Path Parameters:**
- `domain`: Domain name (URL encoded)

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | integer | 30 | Number of days to look back (1-365) |

**Response:**
```json
{
  "domain": "example.com",
  "sources": [
    {
      "source_ip": "8.8.8.8",
      "total_messages": 1250,
      "dmarc_pass_pct": 100.0,
      "spf_pass_pct": 100.0,
      "dkim_pass_pct": 100.0,
      "country_code": "US",
      "country_name": "United States",
      "country_emoji": "🇺🇸",
      "city": "Mountain View",
      "asn": "AS15169",
      "asn_org": "Google LLC",
      "first_seen": 1704153600,
      "last_seen": 1704758400
    },
    {
      "source_ip": "8.8.4.4",
      "total_messages": 1250,
      "dmarc_pass_pct": 100.0,
      "spf_pass_pct": 100.0,
      "dkim_pass_pct": 100.0,
      "country_code": "US",
      "country_name": "United States",
      "country_emoji": "🇺🇸",
      "city": "Mountain View",
      "asn": "AS15169",
      "asn_org": "Google LLC",
      "first_seen": 1704153600,
      "last_seen": 1704758400
    }
  ]
}
```

**Response Fields:**
- `domain`: Domain name
- `sources`: Array of source IP objects (ordered by message count, descending)

**Source Object Fields:**
- `source_ip`: IP address of sending server
- `total_messages`: Number of messages from this IP
- `dmarc_pass_pct`: DMARC pass rate for this IP
- `spf_pass_pct`: SPF pass rate
- `dkim_pass_pct`: DKIM pass rate
- `country_code`: ISO 3166-1 alpha-2 country code (e.g., "US", "IL")
- `country_name`: Full country name
- `country_emoji`: Flag emoji representation (e.g., 🇺🇸, 🇮🇱)
- `city`: City name (from MaxMind City database)
- `asn`: Autonomous System Number (e.g., "AS15169")
- `asn_org`: ISP/Organization name from ASN database
- `first_seen`: Unix timestamp of first message from this IP
- `last_seen`: Unix timestamp of last message from this IP

**GeoIP Notes:**
- GeoIP fields may be `null` if MaxMind databases are not configured
- `country_emoji` defaults to 🌍 (globe) when country is unknown
- GeoIP data requires MaxMind GeoLite2 databases (City + ASN)
- City accuracy varies by IP (typically accurate to city level for data center IPs)
- ASN provides ISP/hosting provider information

---

### POST /api/dmarc/upload

Upload and parse a DMARC aggregate report file.

**Content-Type:** `multipart/form-data`

**Form Data:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file` | file | Yes | DMARC report file (XML, GZ, or ZIP format) |

**Supported File Formats:**
- `.xml` - Raw XML DMARC report
- `.gz` - Gzip-compressed XML report (most common)
- `.zip` - ZIP-compressed XML report (used by Google)

**Request Example:**
```bash
curl -X POST http://your-server:8080/api/dmarc/upload \
  -u username:password \
  -F "file=@google.com!example.com!1704067200!1704153599.xml.gz"
```

**Success Response (201 Created):**
```json
{
  "status": "success",
  "message": "Uploaded report for example.com from Google",
  "report_id": 123,
  "records_count": 45
}
```

**Duplicate Response (200 OK):**
```json
{
  "status": "duplicate",
  "message": "Report 12345678901234567890 already exists"
}
```

**Error Response (400 Bad Request):**
```json
{
  "detail": "Failed to parse DMARC report"
}
```

**Error Response (500 Internal Server Error):**
```json
{
  "detail": "Error message with details"
}
```

**Response Fields:**

**Success Response:**
- `status`: "success"
- `message`: Human-readable description of uploaded report
- `report_id`: Database ID of created report
- `records_count`: Number of source IP records parsed

**Duplicate Response:**
- `status`: "duplicate"
- `message`: Indicates report already exists (based on unique report_id from XML)

**Processing Details:**
1. File is decompressed (if GZ or ZIP)
2. XML is parsed and validated
3. Report metadata extracted (domain, org, date range, policy)
4. Individual records parsed (source IP, counts, auth results)
5. GeoIP enrichment applied to each source IP (if MaxMind configured)
6. Data stored in database with proper indexing
7. Duplicate detection based on unique report_id from XML

**Parsed Data Includes:**
- Report metadata (report ID, organization, date range)
- Domain and published DMARC policy
- Individual source records:
  - Source IP address
  - Message count from this source
  - SPF/DKIM authentication results
  - Policy evaluation (disposition)
  - GeoIP enrichment (country, city, ISP/ASN)

**GeoIP Enrichment:**
- Automatically applied to all source IPs during upload
- Uses MaxMind GeoLite2 databases (if configured)
- Gracefully degrades if databases unavailable
- Enriches with: country, city, ISP, ASN

**File Naming Convention:**
DMARC report filenames typically follow this pattern:
```
<receiver>!<sender-domain>!<begin-timestamp>!<end-timestamp>.<ext>
```
Example: `google.com!example.com!1704067200!1704153599.xml.gz`

**Notes:**
- Reports are identified by unique report_id (from XML)
- Duplicate uploads are detected and rejected gracefully
- Large reports (1000+ records) may take a few seconds to process
- File size limit depends on server configuration (typically 10MB)
- Malformed XML files are rejected with 400 error

---

## DMARC IMAP Auto-Import

The DMARC module supports automatic import of DMARC reports via IMAP. This allows the system to periodically check a mailbox and automatically process incoming reports without manual uploads.

**Features:**
- Automatic periodic syncing from IMAP mailbox
- Configurable sync interval and folder
- Manual sync trigger via API
- Comprehensive sync history tracking
- Email notifications on sync failures
- Support for SSL/TLS connections
- Automatic duplicate detection

**Configuration:**
Set these environment variables to enable IMAP auto-import:
- `DMARC_IMAP_ENABLED=true`
- `DMARC_IMAP_HOST=mail.example.com`
- `DMARC_IMAP_PORT=993`
- `DMARC_IMAP_USE_SSL=true`
- `DMARC_IMAP_USER=dmarc@example.com`
- `DMARC_IMAP_PASSWORD=your-password`
- `DMARC_IMAP_FOLDER=INBOX`
- `DMARC_IMAP_INTERVAL=3600` (seconds between syncs)
- `DMARC_IMAP_DELETE_AFTER=false` (delete processed emails)
- `DMARC_MANUAL_UPLOAD_ENABLED=true` (allow manual uploads)

---

### GET /api/dmarc/imap/status

Get current IMAP auto-import configuration and last sync information.

**Response:**
```json
{
  "enabled": true,
  "manual_upload_enabled": true,
  "host": "mail.example.com",
  "port": 993,
  "use_ssl": true,
  "user": "dmarc@example.com",
  "folder": "INBOX",
  "interval_seconds": 3600,
  "delete_after_processing": false,
  "last_sync": {
    "sync_id": 42,
    "sync_type": "auto",
    "status": "success",
    "started_at": "2026-01-12T08:45:20Z",
    "completed_at": "2026-01-12T08:45:21Z",
    "emails_found": 5,
    "emails_processed": 5,
    "reports_created": 4,
    "reports_duplicate": 0,
    "reports_failed": 1,
    "error_message": null
  }
}
```

**Response Fields:**
- `enabled`: Whether IMAP auto-import is enabled
- `manual_upload_enabled`: Whether manual uploads are still allowed
- `host`: IMAP server hostname
- `port`: IMAP server port (typically 993 for SSL, 143 for non-SSL)
- `use_ssl`: Whether SSL/TLS is used
- `user`: IMAP username/email
- `folder`: Mailbox folder being monitored (e.g., "INBOX")
- `interval_seconds`: Seconds between automatic sync runs
- `delete_after_processing`: Whether emails are deleted after successful processing
- `last_sync`: Last sync operation details (null if never run)

**Last Sync Object:**
- `sync_id`: Unique sync operation ID
- `sync_type`: "auto" (scheduled) or "manual" (API triggered)
- `status`: "success", "error", or "running"
- `started_at`: ISO 8601 timestamp with Z suffix
- `completed_at`: ISO 8601 timestamp with Z suffix (null if running)
- `emails_found`: Number of DMARC emails found in folder
- `emails_processed`: Number of emails successfully processed
- `reports_created`: Number of new DMARC reports created
- `reports_duplicate`: Number of duplicate reports skipped
- `reports_failed`: Number of emails that failed processing
- `error_message`: Error description if sync failed

**Notes:**
- Sensitive information (password) is never returned
- Returns 404 if IMAP auto-import is not configured
- Last sync information persists across restarts

---

### POST /api/dmarc/imap/sync

Manually trigger IMAP sync operation.

**Request:** No body required

**Response:**
```json
{
  "sync_id": 43,
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
}
```

**Error Response (IMAP disabled):**
```json
{
  "status": "disabled",
  "message": "DMARC IMAP sync is not enabled"
}
```

**Error Response (Connection failed):**
```json
{
  "sync_id": 44,
  "sync_type": "manual",
  "status": "error",
  "started_at": "2026-01-12T10:35:00Z",
  "completed_at": "2026-01-12T10:35:30Z",
  "emails_found": 0,
  "emails_processed": 0,
  "reports_created": 0,
  "reports_duplicate": 0,
  "reports_failed": 0,
  "error_message": "[Errno 110] Connection timed out",
  "failed_emails": null
}
```

**Response Fields:**
- `sync_id`: Unique ID for this sync operation
- `sync_type`: Always "manual" for API-triggered syncs
- `status`: "success" or "error"
- `started_at`: ISO 8601 timestamp when sync started
- `completed_at`: ISO 8601 timestamp when sync finished
- `emails_found`: Number of DMARC emails found
- `emails_processed`: Number of emails processed
- `reports_created`: Number of new reports created
- `reports_duplicate`: Number of duplicate reports skipped
- `reports_failed`: Number of emails that failed processing
- `error_message`: Error description if sync failed (null on success)
- `failed_emails`: Array of failed email details (null if none failed)

**Failed Email Object** (when reports_failed > 0):
```json
{
  "email_id": "21",
  "message_id": "",
  "subject": "Report Domain: example.com",
  "error": "Not a valid DMARC report email"
}
```

**Notes:**
- Returns immediately with sync results (synchronous operation)
- Can be called while automatic sync is disabled
- Creates sync history record for tracking
- Duplicate reports are detected and skipped gracefully
- Failed emails are logged but don't prevent other emails from processing
- Email notifications sent if SMTP configured and failures occur

---

### GET /api/dmarc/imap/history

Get history of IMAP sync operations.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 20 | Maximum number of sync records to return (1-100) |

**Response:**
```json
{
  "data": [
    {
      "id": 43,
      "sync_type": "manual",
      "status": "success",
      "started_at": "2026-01-12T10:30:00Z",
      "completed_at": "2026-01-12T10:30:05Z",
      "duration_seconds": 5,
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
      "duration_seconds": 1,
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
- `data`: Array of sync history records (newest first)

**Sync Record Fields:**
- `id`: Unique sync ID
- `sync_type`: "auto" or "manual"
- `status`: "success", "error", or "running"
- `started_at`: ISO 8601 timestamp
- `completed_at`: ISO 8601 timestamp (null if still running)
- `duration_seconds`: Sync duration in seconds (null if still running)
- `emails_found`: Number of emails found
- `emails_processed`: Number of emails processed
- `reports_created`: Number of new reports created
- `reports_duplicate`: Number of duplicates skipped
- `reports_failed`: Number of failed emails
- `error_message`: Error description (null if no errors)
- `failed_emails`: Array of failed email details (null if none)

**Notes:**
- Results ordered by most recent first
- Running syncs show null for completed_at and duration_seconds
- Failed email details include message ID, subject, and error reason
- Useful for debugging sync issues and monitoring system health
- History persists across application restarts

---

## TLS-RPT (TLS Reporting)

### Overview

TLS-RPT (TLS Reporting) provides visibility into TLS connection failures when other mail servers attempt to deliver emails to your domain. This helps identify MTA-STS policy issues and certificate problems.

---

### GET /api/dmarc/domains/{domain}/tls-reports

Get TLS reports for a specific domain (individual reports).

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | Domain name |

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | integer | 30 | Number of days to look back |

**Response:**
```json
{
  "domain": "example.com",
  "total": 15,
  "data": [
    {
      "id": 1,
      "report_id": "2026-01-14T00:00:00Z!example.com!google.com",
      "organization_name": "Google Inc.",
      "start_datetime": "2026-01-14T00:00:00Z",
      "end_datetime": "2026-01-15T00:00:00Z",
      "total_success": 1250,
      "total_fail": 5,
      "success_rate": 99.6
    }
  ]
}
```

---

### GET /api/dmarc/domains/{domain}/tls-reports/daily

Get TLS reports aggregated by date (daily view).

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | Domain name |

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | integer | 30 | Number of days to look back |
| `page` | integer | 1 | Page number |
| `page_size` | integer | 20 | Items per page |

**Response:**
```json
{
  "domain": "example.com",
  "totals": {
    "total_days": 14,
    "total_reports": 28,
    "total_successful_sessions": 15000,
    "total_failed_sessions": 25,
    "overall_success_rate": 99.83
  },
  "data": [
    {
      "date": "2026-01-17",
      "report_count": 3,
      "organization_count": 2,
      "organizations": ["Google Inc.", "Microsoft Corporation"],
      "total_success": 1500,
      "total_fail": 2,
      "success_rate": 99.87
    }
  ]
}
```

---

### GET /api/dmarc/domains/{domain}/tls-reports/{report_date}/details

Get detailed TLS reports for a specific date.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | Domain name |
| `report_date` | string | Date in YYYY-MM-DD format |

**Response:**
```json
{
  "domain": "example.com",
  "date": "2026-01-17",
  "stats": {
    "total_reports": 3,
    "total_providers": 2,
    "total_success": 1500,
    "total_fail": 2,
    "total_sessions": 1502,
    "success_rate": 99.87
  },
  "providers": [
    {
      "report_id": "2026-01-17T00:00:00Z!example.com!google.com",
      "organization_name": "Google Inc.",
      "contact_info": "smtp-tls-reporting@google.com",
      "start_datetime": "2026-01-17T00:00:00Z",
      "end_datetime": "2026-01-18T00:00:00Z",
      "successful_sessions": 1200,
      "failed_sessions": 1,
      "total_sessions": 1201,
      "success_rate": 99.92,
      "policies": [
        {
          "policy_type": "sts",
          "policy_domain": "example.com",
          "mx_host": "mail.example.com",
          "successful_sessions": 1200,
          "failed_sessions": 1,
          "total_sessions": 1201,
          "success_rate": 99.92,
          "failure_details": null
        }
      ]
    }
  ]
}
```

---

### POST /api/dmarc/upload (TLS-RPT Support)

The existing DMARC upload endpoint also accepts TLS-RPT reports.

**Supported TLS-RPT Formats:**
- `.json.gz` - Gzip-compressed JSON (standard format)
- `.json` - Plain JSON

**Detection:**
- File is identified as TLS-RPT if JSON contains `"policies"` array
- TLS-RPT reports use RFC 8460 JSON format

---

## Blacklist Monitoring

### GET /api/blacklist/summary

Get a high-level summary of blacklist status for the main server IP.

**Response:**
```json
{
  "server_ip": "1.2.3.4",
  "checked_at": "2026-01-25T14:00:00Z",
  "total_blacklists": 50,
  "listed_count": 1,
  "clean_count": 48,
  "error_count": 1,
  "status": "listed",
  "has_data": true
}
```

---

### GET /api/blacklist/config

Get blacklist configuration (enabled status, alert email, etc).

**Response:**
```json
{
  "enabled": true,
  "alert_email": "admin@example.com",
  "checks_enabled": true,
  "auto_check_hour": 5
}
```

---

### GET /api/blacklist/monitored

Get status of all monitored hosts (system IP and transport configurations).

**Response:**
```json
{
  "hosts": [
    {
      "hostname": "1.2.3.4",
      "source": "system",
      "active": true,
      "status": "clean",
      "checked_at": "2026-01-25T14:00:00Z",
      "listed_count": 0,
      "total_blacklists": 50,
      "results": [...]
    },
    {
      "hostname": "5.6.7.8",
      "source": "relayhost:smtp.example.com",
      "active": true,
      "status": "listed",
      "checked_at": "2026-01-25T14:00:00Z",
      "listed_count": 2,
      "total_blacklists": 50,
      "results": [...]
    }
  ]
}
```

---

### GET /api/blacklist/check

Trigger a manual blacklist check.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `host` | string | Optional. Host/IP to check. If omitted, checks ALL monitored hosts in a background batch job. |
| `force` | bool | Optional. If `true`, ignores cache and forces a fresh DNS lookup. Default: `false`. |

**Response (Batch Mode - No Host):**
```json
{
  "status": "started",
  "message": "Background check started for all hosts"
}
```

**Response (Single Host):**
```json
{
  "server_ip": "1.2.3.4",
  "status": "clean",
  ... (full results)
}
```

---

### GET /api/blacklist/progress

Get real-time progress of the current blacklist check batch job.

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

Get the weekly system summary report data (JSON).

**Response:**
```json
{
  "date": "25/01/2026",
  "system": {
    "hostname": "mail.example.com",
    "ip": "1.2.3.4",
    "version": "2.2.0",
    "uptime_days": 15
  },
  "counts": {
    "domains": 5,
    "mailboxes": 25,
    "aliases": 50,
    "total_storage": "100G",
    "queue_size": 12,
    "quarantine_count": 5
  },
  "traffic": {
    "sent": 1234,
    "received": 5678,
    "failed": 45,
    "failure_rate": 3.6,
    "bounced": 10,
    "rejected": 5
  },
  "security": {
    "dns_issues": [
      {
        "domain": "example.com",
        "issue": "SPF Record Missing"
      }
    ],
    "blacklist_status": {
      "listed": true,
      "blacklists": ["Spamhaus ZEN"]
    }
  },
  "top_failures": [
    {
      "username": "user@example.com",
      "failed": 15,
      "rate": 10.5
    }
  ]
}
```

---

### POST /api/system/summary/email

Trigger the weekly summary email manually.

**Authentication:** Required

**Response:**
```json
{
  "status": "queued",
  "message": "Weekly summary email generation started"
}
```

---

## Error Responses

All endpoints may return the following error responses:

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
```json
{
  "detail": "Authentication required"
}
```

**Note:** Returned when authentication is enabled but no valid credentials are provided. The response does not include `WWW-Authenticate` header to prevent browser popup dialogs.

### 500 Internal Server Error
```json
{
  "error": "Internal server error",
  "detail": "Error description (only in debug mode)"
}
```

---

## System Status

### GET /api/status/container-logs

Get the application's internal container logs (stdout/stderr).

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `lines` | int | 100 | Number of lines to fetch (min: 10, max: 1000) |

**Authentication:** Required

**Example Request:**
```
GET /api/status/container-logs?lines=50
```

**Response:**
```json
{
  "logs": [
    "2026-01-29 12:00:01 - INFO - Checking for updates...",
    "2026-01-29 12:00:02 - INFO - Database connection successful",
    "2026-01-29 12:00:05 - INFO - [Scheduler] Job 'blacklist_check' executed successfully"
  ]
}
```

---

## Raw Logs (Live Log Viewer)

Endpoints for the Live Log Viewer feature. Provides access to raw logs collected from all mailcow services via a background worker. Logs are stored in a dedicated `raw_service_logs` database table and streamed in real-time via WebSocket.

**Supported Services:** `acme`, `api`, `autodiscover`, `dovecot`, `netfilter`, `postfix`, `ratelimited`, `rspamd-history`, `sogo`, `watchdog`

### GET /api/raw-logs/services

List all enabled services with metadata and log entry counts.

**Authentication:** Required

**Example Request:**
```
GET /api/raw-logs/services
```

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
      "entry_count": 1523
    },
    {
      "id": "dovecot",
      "name": "Dovecot",
      "icon": "inbox",
      "description": "IMAP/POP3 server logs",
      "has_smart_filters": false,
      "entry_count": 980
    }
  ]
}
```

---

### GET /api/raw-logs/{service}

Query stored logs for a specific service with pagination, search, and time filtering.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `service` | string | Service ID (e.g., `postfix`, `dovecot`, `api`) |

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 500 | Number of entries to return (max: 5000) |
| `offset` | int | 0 | Pagination offset |
| `search` | string | - | Full-text search across log message content |
| `since` | ISO 8601 | - | Only return entries newer than this timestamp |
| `smart_filter` | string | - | Apply a predefined smart filter (Postfix only) |

**Authentication:** Required

**Example Request:**
```
GET /api/raw-logs/postfix?limit=100&search=reject&smart_filter=noqueue_reject
```

**Response:**
```json
{
  "service": "postfix",
  "entries": [
    {
      "id": 12345,
      "service": "postfix",
      "time": "2026-04-15T01:21:25Z",
      "message_hash": "a1b2c3d4...",
      "raw_data": {
        "time": "1776189085",
        "program": "postfix/smtpd",
        "priority": "info",
        "message": "NOQUEUE: reject: RCPT from unknown[1.2.3.4]: 554 5.7.1 ..."
      },
      "created_at": "2026-04-15T01:21:30Z"
    }
  ],
  "total": 1523,
  "limit": 100,
  "offset": 0
}
```

---

### GET /api/raw-logs/{service}/smart-filters

Get available smart filter definitions for a specific service. Currently only Postfix has smart filters.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `service` | string | Service ID |

**Authentication:** Required

**Example Request:**
```
GET /api/raw-logs/postfix/smart-filters
```

**Response:**
```json
{
  "service": "postfix",
  "filters": [
    {
      "id": "postscreen",
      "label": "Postscreen",
      "description": "Postscreen connection screening",
      "patterns": ["postscreen"]
    },
    {
      "id": "noqueue_reject",
      "label": "NOQUEUE Reject",
      "description": "Rejected before queuing",
      "patterns": ["NOQUEUE: reject"]
    },
    {
      "id": "dnsbl",
      "label": "DNSBL Block",
      "description": "DNS blacklist blocks",
      "patterns": ["dnsbl", "zen.spamhaus", "bl.spamcop"]
    },
    {
      "id": "pregreet",
      "label": "Pregreet",
      "description": "Pregreet detection (bot behavior)",
      "patterns": ["PREGREET"]
    },
    {
      "id": "sender_restrictions",
      "label": "Sender Restrictions",
      "description": "Sender address restrictions",
      "patterns": ["Sender address rejected", "smtpd_sender_restrictions"]
    },
    {
      "id": "recipient_restrictions",
      "label": "Recipient Restrictions",
      "description": "Recipient address restrictions",
      "patterns": ["Recipient address rejected", "smtpd_recipient_restrictions"]
    },
    {
      "id": "relay_denied",
      "label": "Relay Denied",
      "description": "Relay access denied",
      "patterns": ["Relay access denied"]
    },
    {
      "id": "connections",
      "label": "Connections",
      "description": "Connection events",
      "patterns": ["connect from", "disconnect from"]
    }
  ]
}
```

---

### GET /api/raw-logs/worker-status

Get the health and status of the raw logs background worker.

**Authentication:** Required

**Example Request:**
```
GET /api/raw-logs/worker-status
```

**Response:**
```json
{
  "enabled": true,
  "scheduler_running": true,
  "fetch_interval": 20,
  "retention_days": 2,
  "enabled_services": ["postfix", "dovecot", "sogo", "netfilter", "api", "watchdog"],
  "jobs": {
    "fetch_raw_logs": {
      "last_run": "2026-04-15T01:20:00Z",
      "status": "success",
      "error": null,
      "stats": { "postfix": 15, "dovecot": 3, "api": 8 }
    },
    "cleanup_raw_logs": {
      "last_run": "2026-04-15T03:00:00Z",
      "status": "success",
      "error": null
    }
  }
}
```

---

### GET /api/raw-logs/ws-token

Issue a one-time short-lived token for WebSocket authentication. This endpoint is protected by the standard HTTP authentication middleware, so only authenticated users can obtain a token. The token expires after 30 seconds and can only be used once.

**Authentication:** Required

**Example Request:**
```
GET /api/raw-logs/ws-token
```

**Response:**
```json
{
  "token": "a1b2c3d4e5f6...",
  "ttl": 30
}
```

---

### WebSocket: /ws/raw-logs

Real-time log streaming via WebSocket. Connects to receive new log entries as they are ingested by the background worker.

**Authentication Flow:**
1. Client calls `GET /api/raw-logs/ws-token` (authenticated via HTTP) to obtain a one-time token
2. Client connects to the WebSocket with the token as a query parameter
3. Server validates and consumes the token (single use)
4. If authentication is disabled, the token is accepted but not validated

**Connection URL:**
```
wss://your-server/ws/raw-logs?service=postfix&token=<one-time-token>
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `service` | string | Initial service to stream (e.g., `postfix`) |
| `token` | string | One-time auth token from `/api/raw-logs/ws-token` |

**Client → Server Messages:**

Switch to a different service:
```json
{"action": "subscribe", "service": "dovecot"}
```

**Server → Client Messages:**

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
      "message": "connect from unknown[1.2.3.4]"
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
| `4401` | Authentication required — invalid or missing token |
| `1000` | Normal closure |

**Notes:**
- The WebSocket connection auto-reconnects on drop (3-second delay), except on auth failure (4401)
- Only entries for the currently selected service are streamed
- Use `subscribe` action to change services without reconnecting
- Tokens are single-use and expire after 30 seconds

---

## Spam Filter

The Spam Filter feature provides two capabilities:
1. **Rspamd Maps** — Direct editor for Rspamd map files
2. **Suppressions** — Email suppression list with automatic bounce detection

### Rspamd Maps

#### GET /api/rspamd/config

Check if Rspamd is configured (password set).

**Response:**
```json
{
  "configured": true,
  "rw_configured": true
}
```

**Response Fields:**
- `configured`: Boolean - `true` if `RSPAMD_PASSWORD` is set
- `rw_configured`: Boolean - `true` if `MAILCOW_API_KEY_RW` is set (required for writing)

---

#### GET /api/rspamd/maps

List all available Rspamd map files with metadata.

**Response:**
```json
[
  {
    "filename": "global_smtp_from_whitelist.map",
    "display_name": "Envelope Sender Allowlist",
    "category": "sender",
    "description": "Allowlisted envelope senders",
    "regex": false,
    "entry_count": 5
  }
]
```

---

#### GET /api/rspamd/maps/{filename}

Read the content of a specific Rspamd map file.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `filename` | string | Map filename (e.g., `global_smtp_from_whitelist.map`) |

**Response:**
```json
{
  "filename": "global_smtp_from_whitelist.map",
  "content": "user@example.com\nadmin@example.com",
  "entry_count": 2
}
```

---

#### PUT /api/rspamd/maps/{filename}

Update a Rspamd map file. Requires Read-Write API key.

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
  "message": "Map updated successfully"
}
```

---

#### POST /api/rspamd/validate

Validate regex patterns before saving.

**Request Body:**
```json
{
  "patterns": ["/.*@example\\.com/i", "/invalid[/"]
}
```

**Response:**
```json
{
  "valid": false,
  "errors": [
    {
      "line": 2,
      "pattern": "/invalid[/",
      "error": "unterminated character set"
    }
  ]
}
```

---

### Suppressions

#### GET /api/suppressions

List suppression entries with pagination, search, and filters.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | `1` | Page number |
| `per_page` | integer | `50` | Items per page (max 200) |
| `search` | string | `""` | Search by email address |
| `reason` | string | `""` | Filter by reason: `hard_bounce`, `soft_bounce`, `rejected`, `manual` |
| `active` | string | `""` | Filter by active status: `true` or `false` |
| `sort` | string | `created_at` | Sort field: `email`, `reason`, `bounce_count`, `created_at`, `expires_at` |
| `order` | string | `desc` | Sort order: `asc` or `desc` |

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

Get suppression statistics summary.

**Response:**
```json
{
  "total": 150,
  "active": 120,
  "inactive": 30,
  "synced": 115,
  "pending_sync": 5,
  "expired": 10,
  "by_reason": {
    "hard_bounce": 80,
    "soft_bounce": 40,
    "rejected": 15,
    "manual": 15
  },
  "by_source": {
    "auto": 135,
    "manual": 10,
    "import": 5
  }
}
```

---

#### GET /api/suppressions/config

Get suppression feature configuration.

**Response:**
```json
{
  "enabled": true,
  "auto_detect": true,
  "rspamd_sync": true,
  "rspamd_configured": true,
  "hard_bounce_action": "suppress",
  "soft_bounce_action": "suppress",
  "soft_bounce_threshold": 3,
  "base_expiry_days": 7,
  "max_expiry_days": 90,
  "whitelist_domains": ["example.com"]
}
```

---

#### POST /api/suppressions

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

**Request Fields:**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `email` | string | Yes | — | Email address, domain, or regex pattern |
| `type` | string | No | `email` | `email` or `domain` |
| `reason` | string | No | `manual` | `manual`, `hard_bounce`, `soft_bounce`, `rejected` |
| `notes` | string | No | `null` | Free text notes |
| `permanent` | boolean | No | `true` | `true` = never expires, `false` = uses `expires_at` |
| `expires_at` | string | No | `null` | ISO 8601 datetime (used when `permanent=false`) |

**Response:** `200 OK` — Returns the created suppression object (same format as list item)

**Error Responses:**
- `409 Conflict`: Email already exists in suppression list
- `422 Unprocessable Entity`: Validation error (invalid email/type/reason)

**Notes:**
- Domain type entries are stored as regex patterns (e.g., `/.+@example\.com/i`)
- Regex patterns (starting with `/`) bypass email format validation
- If `permanent=false` and no `expires_at` is provided, default expiry is `base_expiry_days` from config

---

#### PUT /api/suppressions/{suppression_id}

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

**Request Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `active` | boolean | Toggle active/inactive (triggers re-sync) |
| `notes` | string | Update notes |
| `expires_at` | string | ISO datetime to set expiry, or `"null"` / `""` to make permanent |

**Notes:**
- All fields are optional — only provided fields are updated
- Setting `expires_at` to `"null"` or `""` clears the expiry (permanent block)
- Changing `active` sets `synced_to_rspamd = false` to trigger re-sync

---

#### DELETE /api/suppressions/{suppression_id}

Permanently delete a suppression entry.

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

**Request Body:** Multipart form with CSV file

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

Export all suppressions as CSV download.

**Response:** CSV file download with headers `email,type,reason,source,notes,active,bounce_count,expires_at,created_at`

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
- Requires both `RSPAMD_PASSWORD` and `MAILCOW_API_KEY_RW`

---

## Quarantine Auto-Rules

Manage quarantine auto-rules that automatically release or delete quarantined emails based on matching patterns. All endpoints require a Read-Write API key (`MAILCOW_API_KEY_RW`).

### GET /api/quarantine/rules

List all quarantine rules.

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

Create a new quarantine rule.

**Request Body:**
```json
{
  "name": "Block spam domain",
  "match_type": "sender_domain",
  "match_value": "spammer.com",
  "is_regex": false,
  "action": "delete",
  "notes": "Known spam source"
}
```

**Request Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Rule name (1-255 characters) |
| `match_type` | string | Yes | `sender`, `sender_domain`, `recipient`, or `subject` |
| `match_value` | string | Yes | Value or regex pattern to match (1-500 characters) |
| `is_regex` | boolean | No | Whether `match_value` is a regex (default: false) |
| `action` | string | Yes | `release` or `delete` |
| `notes` | string | No | Optional description |

**Response:** The created rule object (same format as GET response)

**Error Responses:**
- `400 Bad Request`: Invalid match_type, action, or regex pattern
- `403 Forbidden`: No Read-Write API key configured

---

### PUT /api/quarantine/rules/{id}

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

Toggle a rule's enabled/disabled state.

**Response:** The updated rule object with `enabled` toggled

---

### POST /api/quarantine/rules/test

Dry-run test all rules (enabled and disabled) against current quarantine items. No actions are taken.

**Response:**
```json
{
  "total_quarantine": 15,
  "total_matches": 3,
  "matches": [
    {
      "quarantine_id": "12345",
      "sender": "spam@bad.com",
      "recipient": "user@example.com",
      "subject": "You won a prize!",
      "rule_id": 1,
      "rule_name": "Block bad.com",
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

Get quarantine rule action history (paginated).

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | `50` | Max results (max: 200) |
| `offset` | integer | `0` | Pagination offset |
| `rule_id` | integer | (none) | Filter by specific rule ID |

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
      "sender": "spam@bad.com",
      "recipient": "user@example.com",
      "subject": "Buy now!",
      "matched_field": "sender_domain",
      "matched_value": "bad.com",
      "created_at": "2026-04-21T10:30:00Z"
    }
  ]
}
```

**Notes:**
- Logs are automatically pruned based on `QUARANTINE_RULES_LOG_RETENTION_DAYS` (default: 30)
- Each entry represents one automated action taken by the scheduler