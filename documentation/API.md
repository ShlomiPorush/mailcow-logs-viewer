# Mailcow Logs Viewer - API Documentation

This document describes all available API endpoints for the Mailcow Logs Viewer application.

**Base URL:** `http://your-server:8080/api`

**Authentication:** When `AUTH_ENABLED=true`, all API endpoints (except `/api/health`) require HTTP Basic Authentication. Include the `Authorization: Basic <base64(username:password)>` header in all requests.

---

## Table of Contents

1. [Authentication](#authentication)
2. [Health & Info](#health--info)
3. [Job Status Tracking](#job-status-tracking)
4. [Domains](#domains)
5. [Mailbox Statistics](#mailbox-statistics)
6. [Messages (Unified View)](#messages-unified-view)
7. [Logs](#logs)
   - [Postfix Logs](#postfix-logs)
   - [Rspamd Logs](#rspamd-logs)
   - [Netfilter Logs](#netfilter-logs)
8. [Queue & Quarantine](#queue--quarantine)
9. [Statistics](#statistics)
10. [Status](#status)
11. [Settings](#settings)
    - [SMTP & IMAP Test](#smtp--imap-test)
12. [Export](#export)
13. [DMARC](#dmarc)
    - [DMARC IMAP Auto-Import](#dmarc-imap-auto-import)

---

## Authentication

### Overview

When authentication is enabled (`AUTH_ENABLED=true`), all API endpoints except `/api/health` require HTTP Basic Authentication.

**Public Endpoints (No Authentication Required):**
- `GET /api/health` - Health check (for Docker monitoring)
- `GET /login` - Login page (HTML)

**Protected Endpoints (Authentication Required):**
- All other `/api/*` endpoints

### Authentication Method

Use HTTP Basic Authentication with the credentials configured in your environment:
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

### Login Endpoint

#### GET /login

Serves the login page (HTML). This endpoint is always publicly accessible.

**Response:** HTML page with login form

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

**Response:**
```json
{
  "name": "Mailcow Logs Viewer",
  "version": "1.5.0",
  "mailcow_url": "https://mail.example.com",
  "local_domains": ["example.com", "mail.example.com"],
  "fetch_interval": 60,
  "retention_days": 7,
  "timezone": "UTC",
  "app_title": "Mailcow Logs Viewer",
  "app_logo_url": "",
  "blacklist_count": 3,
  "auth_enabled": false
}
```

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
    'update_geoip': {'last_run': datetime, 'status': str, 'error': str|None}
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
| **Fetch Logs** | 60 seconds | Imports Postfix, Rspamd, and Netfilter logs from Mailcow API |
| **Complete Correlations** | 120 seconds (2 min) | Links Postfix logs to message correlations |
| **Update Final Status** | 120 seconds (2 min) | Updates message delivery status for late-arriving logs |
| **Expire Correlations** | 60 seconds (1 min) | Marks old incomplete correlations as expired (after 10 minutes) |
| **Cleanup Logs** | Daily at 2 AM | Removes logs older than retention period |
| **Check App Version** | 6 hours | Checks GitHub for application updates |
| **DNS Check** | 6 hours | Validates DNS records (SPF, DKIM, DMARC) for all active domains |
| **Update GeoIP** | Weekly (Sunday 3 AM) | Updates MaxMind GeoIP databases for DMARC source IP enrichment |

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
- Fetches expected DKIM record from Mailcow API
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
  - Fetches server IP from Mailcow API once on startup
  - Verifies server IP is authorized via:
    - Direct `ip4:` match (including CIDR ranges)
    - `a` record resolution
    - `mx` record resolution
    - Recursive `include:` checking (up to 10 levels)
  - Returns authorization method in message (e.g., "Server IP authorized via ip4:X.X.X.X")
  - Returns error if server IP not found in SPF record
- Provides policy-specific warnings and recommendations

**DKIM Validation:**
- Fetches expected DKIM value from Mailcow API (`/api/v1/get/dkim/{domain}`)
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
| `active` | Whether mailbox is active in Mailcow |
| `quota` / `quota_used` | Quota in bytes |
| `percent_in_use` | Quota usage percentage |
| `messages_in_mailbox` | Number of messages stored |
| `last_*_login` | Last login timestamps (null if never) |
| `rl_value` / `rl_frame` | Rate limiting (e.g., 100/m = 100 per minute) |
| `attributes` | Access permissions from Mailcow |
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

## Queue & Quarantine

### GET /queue

Get current mail queue from Mailcow (real-time).

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

### GET /quarantine

Get quarantined messages from Mailcow (real-time).

**Response:**
```json
{
  "total": 3,
  "data": [
    {
      "id": 123,
      "subject": "Suspicious Email",
      "sender": "spammer@evil.com",
      "recipients": ["user@example.com"],
      "created": "2025-12-25T10:30:00Z",
      "reason": "High spam score"
    }
  ]
}
```

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

Get status of all Mailcow containers.

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

Get Mailcow version and update status.

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

Check Mailcow API connection status.

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

Get Mailcow system information.

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

### GET /settings/info

Get system configuration and status information.

**Response:**
```json
{
  "configuration": {
    "mailcow_url": "https://mail.example.com",
    "local_domains": ["example.com"],
    "fetch_interval": 60,
    "fetch_count_postfix": 2000,
    "fetch_count_rspamd": 500,
    "fetch_count_netfilter": 500,
    "retention_days": 7,
    "timezone": "UTC",
    "app_title": "Mailcow Logs Viewer",
    "log_level": "WARNING",
    "blacklist_enabled": true,
    "blacklist_count": 3,
    "max_search_results": 1000,
    "csv_export_limit": 10000,
    "scheduler_workers": 4,
    "auth_enabled": false,
    "auth_username": null,
    "maxmind_status": {
      "configured": true,
      "valid": true,
      "error": null
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
      "description": "Imports logs from Mailcow API",
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

1. **fetch_logs**: Fetches Postfix, Rspamd, and Netfilter logs from Mailcow API every 60 seconds
2. **complete_correlations**: Links Postfix logs to message correlations every 2 minutes
3. **update_final_status**: Updates message delivery status when late-arriving Postfix logs are found
4. **expire_correlations**: Marks old incomplete correlations as expired after 10 minutes
5. **cleanup_logs**: Removes logs older than retention period (runs daily at 2 AM)
6. **check_app_version**: Checks GitHub for application updates every 6 hours
7. **dns_check**: Validates DNS records (SPF, DKIM, DMARC) for all active domains every 6 hours
8. **update_geoip**: Updates MaxMind GeoLite2 databases (City + ASN) for DMARC source IP enrichment (runs weekly on Sunday at 3 AM)

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
      "source_ip": "212.199.162.78",
      "total_messages": 456,
      "dmarc_pass_pct": 98.2,
      "spf_pass_pct": 99.1,
      "dkim_pass_pct": 98.5,
      "country_code": "IL",
      "country_name": "Israel",
      "country_emoji": "🇮🇱",
      "city": "Tel Aviv",
      "asn": "AS8551",
      "asn_org": "Bezeq International Ltd.",
      "first_seen": 1704240000,
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