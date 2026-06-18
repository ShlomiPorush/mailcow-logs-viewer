# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.6.2] - 2026-06-18

### Fixed

#### Manual Execution of Raw Log Jobs Fails with 404 ([#67](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/67))
- **Clicking "Run" on "Fetch Raw Logs" or "Cleanup Raw Logs" background jobs returned `Unknown job` error** — the manual job trigger endpoint was missing both raw log jobs from its job mapping
  - Added `fetch_raw_logs` and `cleanup_raw_logs` to the manual trigger endpoint
  - Correctly reads job status from the raw logs worker's separate status tracking (not the main scheduler)

#### DMARC IMAP Reports with Non-English Subjects Not Imported ([#66](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/66))
- **DMARC reports from providers using non-English subjects were silently skipped** — the IMAP search only matched English subject patterns like "Report Domain:", "DMARC", "Report-ID:"
  - Added new setting `DMARC_IMAP_SCAN_ALL_UNSEEN` (default: off) — when enabled, scans all unread emails for DMARC/TLS-RPT attachments, not just subject-matched ones
  - Recommended for dedicated DMARC mailboxes that receive reports from international providers

#### Scheduler Stability ([#63](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/63))
- **Background jobs skipping with warnings** (`maximum number of running instances reached`, `Run time of job was missed`) after prolonged uptime
  - Added `misfire_grace_time=30` and `coalesce=True` to both schedulers to tolerate delayed jobs and prevent pileups
  - Cached log discovery results for 5 minutes to reduce API calls during fetch cycles
  - Increased default `RAW_LOGS_FETCH_INTERVAL` from 20 to 30 seconds

#### DMARC Daily Reports Not Split by Reporter ([#41](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/41))
- **DMARC report details merged all reporters into a single row** per source IP — when multiple providers (Google, Microsoft, Yahoo, etc.) reported on the same sending IP, only the first reporter was shown
  - Reports are now split by reporter so each provider gets its own row with independent statistics

#### Noisy Error Traceback on Shutdown
- **`CancelledError` traceback logged during graceful shutdown** — APScheduler raised an unhandled exception when `fetch_all_logs` was interrupted mid-cycle by the event loop shutting down
  - `asyncio.CancelledError` is now caught explicitly and logged as a INFO message instead of ERROR traceback

---

## [2.6.1] - 2026-05-17

### Fixed

#### GeoIP Backfill Infinite Loop on Startup
- **Application startup could hang indefinitely** when IP addresses could not be resolved by the GeoIP database
  - The backfill loop fetched rows with `country_code IS NULL`, but only updated them when a valid country was returned — unresolvable IPs were never updated and re-fetched forever
  - Now assigns fallback values (`ZZ` / `Unknown`) for any IP that cannot be resolved, ensuring every row is processed exactly once
  - Thanks to [@P7aM5qzEddT66lE](https://github.com/P7aM5qzEddT66lE) for reporting and submitting the fix ([#58](https://github.com/ShlomiPorush/mailcow-logs-viewer/pull/58))

#### Startup Crash with `DEBUG=true`
- **Application crashed immediately on startup** when `DEBUG=true` was set in environment variables ([#57](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/57))
  - Engine initialization now conditionally applies `pool_size`/`max_overflow` only when using the standard connection pool

#### Settings Page Freeze (~30 Seconds)
- **Settings page could hang for up to 30 seconds**, especially after the application hadn't been accessed for several days
  - Root cause: the `GET /api/settings/info` endpoint made a **synchronous external HTTP call** to MaxMind's license validation API on every page load — if DNS cache expired or the network was slow, TCP connect timeout could block for 30+ seconds
  - MaxMind license validation is now **fully on-demand**: the settings page no longer checks license validity automatically. Instead, a "Validate" button lets users check when they want to
  - Added `POST /api/settings/maxmind/validate` endpoint for on-demand validation

### Changed

#### MaxMind License Status
  - Validation results are now **persisted in the database** (`system_settings` table) and survive page refreshes, container restarts, and re-deployments
  - Clearing MaxMind credentials properly resets the status back to "Not checked"

#### MaxMind Settings UI Improvements
- **"Validate" button** for MaxMind license validation now appears **only when credentials are configured** (not when empty)
- **"Repair" button** added for corrupted GeoIP databases — automatically re-downloads and re-validates database files when "DB Corrupt" status is detected

#### Fail2Ban IP Lists Redesign ([#51](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/51))
- **Added Active Bans list** showing all currently banned IPs with visual distinction between permanent and temporary bans
  - **Permanent bans** (red badge): IPs from the denylist — cannot be unbanned directly, must be removed from the denylist
  - **Temporary bans** (amber badge): dynamically banned by Fail2Ban with remaining ban time displayed and an "Unban" button
  - IPs queued for unbanning show a "Unbanning..." status indicator
- Simplified IP Lists layout from 3 columns to 2 (Allowlist + Denylist) with the Active Bans section below

---

## [2.6.0] - 2026-05-06

### Added

#### Dynamic Feature Toggles
- **Enable or disable application features on-the-fly** from the Settings page without requiring a restart
  - Toggle individual features: Security (Netfilter/Fail2Ban), Queue, Quarantine, Spam Filter, Domains, DMARC, Mailbox Statistics, Logs, Blacklist Monitor
  - Page auto-reloads after toggling features so all UI changes take effect immediately

#### Feature Toggle — UI Integration
- **Navigation tabs** are dynamically hidden/shown based on enabled features
- **Settings page**: Related settings tabs (DMARC, DMARC IMAP, Logs, Spam Filter, Quarantine) are hidden when their feature is disabled

#### Feature Toggle — Background Job Guards
- **Runtime feature checks** added to all feature-specific background jobs — disabling a feature immediately stops its related jobs without restart
  - Previously, feature checks only occurred at startup (job registration). Now each job verifies its feature is still enabled at every execution

#### Feature Toggle — Status Page
- **"Feature Off" badge** on background job cards for disabled features

#### Data Purge on Feature Disable
- **Disabling a feature now purges all related data** from the database (with confirmation warning)

#### Quarantine — Rspamd Training Actions
- **Learn Not Spam**: Release a quarantined message and train Rspamd that it is not spam
- **Learn Spam**: Delete a quarantined message and train Rspamd that it is spam

#### Quarantine — Email Detail Modal
- **Full email details view** — click "Details" or the subject line to open a modal with:
  - Header info: Subject, From (Header), Envelope From, Recipients (with type badges), Score, Action
  - Rspamd Symbols table sorted by absolute score impact; score-0 symbols in a collapsed accordion
  - Email content preview (plain text or HTML body)

### Changed

#### Paginated Log Synchronization
- **Full history import** — Postfix and Rspamd logs are now fetched using paginated API calls, importing the entire mailcow log history instead of only the most recent batch
  - Fetches logs in configurable page sizes (`FETCH_COUNT_POSTFIX`, `FETCH_COUNT_RSPAMD`) with offset-based pagination
  - Postfix and Rspamd run in parallel via `asyncio.gather` for faster data population
- **Log discovery via binary-search probing** — Before fetching begins, the system probes the mailcow API at progressively finer positions (100k → 10k → 1k → 100 → 10 → 1) to determine exactly how many logs exist, enabling accurate progress logging (`Page 5/250 (2%)`) and eliminating blind pagination
- **Configurable page limit** (`FETCH_MAX_PAGES`, default: 50) — Safety cap on pages per cycle. When the limit is reached, the current offset is saved and the next cycle resumes from exactly where it left off, ensuring complete ingestion across multiple runs
- **Early stop on catch-up** — If an entire page contains only duplicates (no new logs), fetching stops early instead of scanning remaining pages unnecessarily
- **Batch existence pre-check** — Each page of logs is checked against the database in a single query before insertion, preventing `UniqueViolation` errors without relying on database-level exception handling
- **Blacklist filtering during ingestion** — Logs matching blacklisted email addresses (`BLACKLIST_EMAILS`) are filtered out during import and their related database records are cleaned up

### Fixed

#### GeoIP Error When MaxMind Not Configured
- **`ERROR - Failed to load GeoIP City database` on every startup**: When MaxMind credentials are not configured, stale or empty `.mmdb` files in the data directory caused repeated ERROR-level log messages. The system now checks that database files are non-empty before attempting to load them, downgrades the message to DEBUG level, and marks GeoIP as unavailable so it does not retry

#### Mailbox Stats — Case-Insensitive Email Matching
- **Alias/mailbox message counts ignored letter case**: If an alias was stored as `test@domain.com` but a message was sent from `TEST@domain.com`, it would not be counted in the mailbox statistics. All sender/recipient comparisons in the mailbox stats module now use case-insensitive matching

#### Mailbox Stats — Query Performance Issue
- **Page took minutes to load and froze on search**: Message counting was done individually for each mailbox and alias, causing hundreds of database queries per page load. Now all counts are calculated in bulk using just 2 queries total, making the page load in seconds

#### Messages — Incorrect Timestamp Displayed
- **All messages showed the same date/time**: The messages page displayed `last_seen` (when the system processed the correlation) instead of `first_seen` (the actual email timestamp from Rspamd). This caused all messages imported in the same batch to show identical times. Now displays the real email time and sorts by it

### Technical

#### New Configuration Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `DISABLED_FEATURES` | `""` (empty) | Comma-separated list of features to disable. Valid values: `netfilter`, `queue`, `quarantine`, `spam-filter`, `domains`, `dmarc`, `mailbox-stats`, `logs`, `blacklist` |
| `FETCH_MAX_PAGES` | `50` | Maximum number of pages to fetch per cycle for Postfix/Rspamd (safety limit to prevent infinite loops) |

#### API Changes
- `GET /api/info` now includes `disabled_features` array in the response — lists all currently disabled feature IDs
- `GET /api/settings/info` background jobs include `feature_disabled: true` for jobs whose feature is turned off
- `POST /api/settings/purge-feature-data` — new endpoint to delete all database data for a disabled feature (body: `{ "feature": "<id>" }`)

#### New API Endpoints
```
POST /api/quarantine/learnham          - Release & train as not spam (requires RW API key)
POST /api/quarantine/learnspam         - Delete & train as spam (requires RW API key)
GET  /api/quarantine/{id}/details      - Get full quarantine item details (proxied from mailcow)
```

---

## [2.5.0] - 2026-04-23

### Added

#### Quarantine Auto-Rules
- **Auto-release or delete quarantined emails** based on user-defined rules
  - Match by Sender, Sender Domain, Recipient, or Subject — using Exact Match, Contains, or Regex
  - Actions: Release (deliver to inbox) or Delete (permanently remove)
  - Delete rules always take priority over Release (acl-style deny/allow)
  - Per-rule Enable/Disable toggle, dry-run testing, and full action history log
  - Safety limit: max actions per run (default: 50)
- **Inline rule creation** from quarantine items — "Rule" button pre-fills sender, recipient, subject
- **New "Quarantine" tab in Settings** and background job on Status page

#### Spam Filter — Rspamd Maps Editor
- **Direct editor for all 13 Rspamd map files** — sender/recipient deny/allow lists, bad words, fishy TLDs, and more
  - Built-in **Regex Wizard** for generating patterns without regex knowledge
  - **Validate** button to check regex syntax before saving
  - Read-only mode when `MAILCOW_API_KEY_RW` is not configured

#### Spam Filter — Email Suppression & Deferred Queue Cleanup
- **Automatic email suppression** — block outgoing emails to recipients that bounce
  - **Hard bounces (5.x.x)**: Detected from Postfix logs, recipients suppressed immediately
  - **Deferred queue cleanup**: Scans the live mail queue every 5 min for emails stuck longer than threshold (default: 60 min) — deletes from queue and suppresses. Replaces log-based soft bounce detection for reliability on busy servers
  - **Progressive blocking**: Each repeat bounce extends suppression (base × bounce count, capped at max)
  - **Immediate Rspamd sync**: Suppressions pushed to Rspamd right away
  - Manual management, import/export CSV, domain regex, permanent or timed blocks, quick-extend buttons
- **"Suppress" button on Queue page** — quick-add recipient to suppression list
- **Background jobs** on Status page: Detect Suppressions, Cleanup Deferred Queue, Sync to Rspamd, Expire Suppressions
- **Spam Filter settings** grouped into clear sections: Hard Bounces, Soft Bounces, Deferred Queue Cleanup, Block Duration, Whitelist

#### MaxMind GeoIP — Robust Initialization & Setup UX
- **Eager-load at startup**, database integrity validation, auto-recovery of corrupt databases
- **Setup Modal** when credentials are configured: credential check → download with progress bar → integrity validation
- **Health badges in settings**: License, DB Health, combined City + ASN info

#### Documentation
- **New `Spam_Filter.md` help page** — Suppressions and Rspamd Maps user guide
- **New `Quarantine.md` help page** — Auto-Rules guide with match modes, quick-fill, and dry-run testing

### Changed
- **Adjusted page width** to `max-w-[1400px]` for better readability on wide screens

### Security
- **Upgraded `python-dotenv` ≥1.2.2** — fixes symlink-following vulnerability

### Technical

#### New Configuration Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `QUARANTINE_RULES_MAX_ACTIONS` | `50` | Max emails to release/delete per scheduler run |
| `QUARANTINE_RULES_INTERVAL` | `5` | Minutes between rule processing runs |
| `QUARANTINE_RULES_LOG_RETENTION_DAYS` | `30` | Days to keep action history |
| `SUPPRESSION_ENABLED` | `false` | Enable the suppression system |
| `SUPPRESSION_AUTO_DETECT` | `true` | Auto-detect hard bounces from Postfix logs |
| `SUPPRESSION_RSPAMD_SYNC` | `true` | Auto-sync suppression list to Rspamd |
| `SUPPRESSION_WHITELIST_DOMAINS` | `""` | Domains that should never be suppressed |
| `SUPPRESSION_HARD_BOUNCE_ACTION` | `suppress` | Hard bounce action: suppress or ignore |
| `SUPPRESSION_SOFT_BOUNCE_ACTION` | `count` | Soft bounce action: suppress, count, or ignore |
| `SUPPRESSION_SOFT_BOUNCE_THRESHOLD` | `3` | Soft bounces before suppression (when action=count) |
| `SUPPRESSION_BASE_EXPIRY_DAYS` | `7` | Base block duration in days (× bounce count) |
| `SUPPRESSION_MAX_EXPIRY_DAYS` | `90` | Maximum block duration cap |
| `QUEUE_CLEANUP_ENABLED` | `true` | Auto-delete stuck deferred emails from queue |
| `QUEUE_CLEANUP_THRESHOLD_MINUTES` | `60` | Minutes before a stuck deferred email is deleted |

#### New API Endpoints
```
GET    /api/quarantine/rules                - List all quarantine rules
POST   /api/quarantine/rules                - Create a new rule
PUT    /api/quarantine/rules/{id}           - Update a rule
DELETE /api/quarantine/rules/{id}           - Delete a rule
PUT    /api/quarantine/rules/{id}/toggle    - Enable/disable a rule
POST   /api/quarantine/rules/test           - Dry-run test all rules against current quarantine
GET    /api/quarantine/rules/logs           - Get action history (paginated)

GET    /api/suppressions                    - List suppressions (paginated, searchable, filterable)
GET    /api/suppressions/stats              - Suppression statistics summary
GET    /api/suppressions/config             - Suppression feature configuration
POST   /api/suppressions                    - Create a suppression (email or domain, permanent or timed)
PUT    /api/suppressions/{id}               - Update suppression (notes, expiry, permanent toggle)
DELETE /api/suppressions/{id}               - Delete a suppression permanently
POST   /api/suppressions/import             - Bulk import from CSV
GET    /api/suppressions/export             - Export all suppressions as CSV
POST   /api/suppressions/sync              - Manual sync to Rspamd

GET    /api/rspamd/config                   - Check Rspamd configuration status
GET    /api/rspamd/maps                     - List all available Rspamd maps
GET    /api/rspamd/maps/{filename}          - Read a specific Rspamd map file
PUT    /api/rspamd/maps/{filename}          - Update a Rspamd map file (requires RW key)
POST   /api/rspamd/validate                - Validate regex patterns

GET    /api/settings/geoip/status           - Detailed GeoIP status (license, DB health, job status)
POST   /api/settings/geoip/download         - Trigger GeoIP database download in background
POST   /api/settings/geoip/validate         - Validate GeoIP database integrity (test IP lookups)
```

---

## [2.4.0] - 2026-04-16

### Added

#### Live Log Viewer
- **New "Logs" page** — live terminal style log viewer for all mailcow services
  - **10 mailcow services supported**: Postfix, Dovecot, SOGo, Netfilter, Ratelimited, Rspamd, Watchdog, ACME, API, Autodiscover
  - **Real-time updates via WebSocket** — new log entries pushed instantly from the server, no polling
  - **Terminal-style dark output** with color-coded log lines (errors red, warnings yellow, success green)
  - **Service sidebar** with entry count badges and quick filter
  - **Postfix Smart Filters** — one-click filter chips for common issues: Postscreen, NOQUEUE Reject, DNSBL Block, Pregreet, Sender/Recipient Restrictions, Relay Denied, Connections
  - **Full-text search** across log messages with highlighted results
  - **Controls**: Pause/Resume, Auto-scroll, Font size selector, Word wrap toggle, Clear display
  - **Status bar**: WebSocket connection indicator (green/red/yellow), entry count, last update time
  - **Timezone-aware timestamps** — dates formatted consistently with the rest of the app (`DD.MM.YYYY, HH:mm:ss`)
- **Date Range Analysis** — full forensic log retrieval by date range
  - **Date Range Picker** with From/To datetime inputs and quick presets (1h, 6h, 24h, 48h)
  - **Infinite scroll pagination** — automatically loads older pages when scrolling up
  - **Status bar indicators** — shows `Loaded X of Y entries` for data availability feedback
- **Live Mode toggle** — dedicated Live button next to Pause with visual active state

#### Background Raw Logs Worker
- **Separate `AsyncIOScheduler` instance** — completely independent from the main scheduler, ensuring log ingestion never impacts existing correlation processing
- **Sequential API fetching** — services fetched one at a time to minimize mailcow API load
- **Pre-check hash deduplication** — queries existing SHA-256 hashes before inserting, preventing duplicate entries without generating database errors
- **Automatic cleanup** — daily job at 3:00 AM removes entries older than retention period
- **Raw JSON storage** — full API response stored as-is in JSONB, frontend defines display templates per service
- **Configurable per-service selection** — users choose which services to collect via checkbox UI in Settings page
- **Graceful handling of unavailable services** — services returning dict/error responses are silently skipped

#### Settings — Logs Tab
- **New "Logs" tab in Settings**
- **Checkbox-based service selection** — choose which mailcow services to collect logs from via checkboxes

#### Status Page — Categorized Background Jobs
- **Background jobs grouped by category** with section headers and icons:

#### New Configuration Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `RAW_LOGS_ENABLED` | `true` | Enable/disable raw log collection |
| `RAW_LOGS_FETCH_INTERVAL` | `20` | Seconds between fetch cycles |
| `RAW_LOGS_FETCH_COUNT` | `1000` | Logs per service per cycle |
| `RAW_LOGS_RETENTION_DAYS` | `2` | Days before auto-cleanup (48 hours) |
| `RAW_LOGS_SERVICES` | `all` | Comma-separated list, or `all` for all 10 services |

#### Quarantine Management Actions
- **Release and delete quarantined emails directly from the UI**: The Quarantine page now supports managing quarantined messages when a Read-Write API key (`MAILCOW_API_KEY_RW`) is configured
  - **Per-item actions**: Each quarantine entry shows "Release" and "Delete" buttons
  - **Bulk actions**
  - **Release All / Delete All**: Toolbar buttons to release or delete all visible quarantine items with confirmation
  - When no Read-Write API key is configured, the quarantine page remains read-only (no buttons or checkboxes shown)

#### Mail Queue Management Actions
- **Manage mail queue items directly from the UI**: The Queue page now supports managing queued messages when a Read-Write API key (`MAILCOW_API_KEY_RW`) is configured
  - **Per-item actions**: Each queue entry shows "Retry" (re-attempt delivery), "Hold"/"Unhold" (context-aware), and "Delete" buttons
  - **Bulk actions**
  - Delete and bulk actions require a confirmation dialog
  - **Queue status badge**: Each item displays a color-coded status badge showing the queue name (active=green, deferred=orange, hold=yellow, bounce/corrupt=red, incoming=blue)
  - When no Read-Write API key is configured, the queue page remains read-only

### Fixed

#### Basic Auth Lockout Prevention
- **Credential verification before enabling Basic Auth from UI**: When toggling Basic Auth ON and clicking Save, a **verification modal** now appears asking the user to type their username and password
  - Credentials are validated both **client-side** and **server-side** (timing-safe comparison)
  - Enabling Basic Auth without a password configured is now blocked with a clear error message
- **Clearing password while Basic Auth is enabled is now blocked**: The server now returns `400 Bad Request` if the password is being cleared while Basic Auth is enabled

#### Read-Write API Key Exposure
- **`MAILCOW_API_KEY_RW` now masked in API responses**: The Read-Write API key was not included in the sensitive keys list. It is now masked with `********` like all other sensitive fields

#### Postfix Log Import Crash on Duplicate Key
- **`duplicate key value violates unique constraint "uq_postfix_log"` causing batch loss**: Fixed by using SAVEPOINT pattern so a single failed log insertion does not roll back the entire batch

### Technical

#### New API Endpoints
```
GET  /api/raw-logs/services              - List enabled services with metadata and entry counts
GET  /api/raw-logs/{service}             - Query stored logs (paginated, searchable, filterable)
GET  /api/raw-logs/{service}/smart-filters - Get smart filter definitions for a service
GET  /api/raw-logs/worker-status         - Worker health and job status
WS   /ws/raw-logs?service={service}      - WebSocket endpoint for real-time log streaming
GET  /api/rw-status                      - Check if Read-Write API key is configured
POST /api/quarantine/release             - Release quarantined messages (requires RW API key)
POST /api/quarantine/delete              - Delete quarantined messages (requires RW API key)
POST /api/queue/action                   - Perform queue action: deliver, hold, unhold, flush, super_delete
POST /api/queue/delete                   - Delete mail queue items (requires RW API key)
```

#### Settings API Changes
- `PUT /api/settings`: When `basic_auth_enabled` is being set to `true`, the request body must now include `verify_username` and `verify_password` fields matching the configured credentials

## [2.3.3] - 2026-03-31

### Added

#### Click-to-Copy for Important Data
- **Click-to-copy on key data fields across the application**: Hovering over copyable values reveals a small clipboard icon; clicking copies the value to clipboard with visual feedback (checkmark animation) and a "Copied!" toast notification

#### Date Range Filter on Messages Page
- **Date range picker for filtering messages by time period**: Same dropdown picker pattern as the Mailbox Statistics page
  - **Quick Select presets**: All Time (default), Today, 7 Days, 30 Days, 90 Days
  - **Custom Range**: Manual From/To date picker with validation

#### Security Events Chart by Country
- **Stacked horizontal bar chart** on the Security page showing ban, warning, and unban events grouped by country

#### Fail2Ban Settings & Editing
- **Fail2Ban configuration viewer on Security page**: Two new collapsible panels display the current Fail2Ban configuration fetched live from the mailcow API
  - **Fail2ban Settings**
  - **Fail2ban IP Lists**
  - Settings are fetched once per session and cached in the frontend
  - Both panels are collapsed by default to keep the Security page clean
- **Fail2Ban settings editing**: When a Read-Write API key is configured, users can edit Fail2Ban settings and IP lists directly from the UI
  - Fields start **disabled** — an "Edit Settings" / "Edit IP Lists" button must be clicked first to prevent accidental changes
  - Save sends all parameters to mailcow's `POST /api/v1/edit/fail2ban` endpoint
  - Warning displayed when no Read-Write API key is configured

#### Read-Write API Key (Dual-Key Architecture)
- **New optional `MAILCOW_API_KEY_RW` environment variable** for write operations (editing Fail2Ban, future edit features)
  - The existing `MAILCOW_API_KEY` remains read-only and is used for all data retrieval
  - Write operations require the separate Read-Write key for security separation
  - If no RW key is configured, edit controls are disabled in the UI

#### Settings Improvements
- **Default value comparison**: Settings fields now show whether they differ from their default value
  - Fields changed from default get an **amber border** highlight
  - **"Reset to default (value)"** button appears on changed fields, showing what the default is
  - **"Clear"** button appears on user-specific fields (credentials, connection details, feature toggles) that have a value
  - User-specific settings (auth, SMTP, IMAP, OAuth2 credentials, etc.) show plain "Clear" instead of "Reset to default" since their values are inherently per-deployment
- **Settings field clearing fixed**: Sensitive fields (API keys, passwords) can now be properly cleared — previously, clearing a field was silently ignored

### Technical

#### New API Endpoints
```
GET  /api/fail2ban           - Get Fail2Ban configuration from mailcow (real-time proxy)
POST /api/fail2ban           - Update Fail2Ban configuration (requires RW API key)
GET  /api/fail2ban/rw-status - Check if Read-Write API key is configured
```

#### Settings API Changes
- `GET /api/settings` and `GET /api/settings/info` now include `default_config` in the response — a map of each editable key to its default value (or `null` for required fields with no default)
- `PUT /api/settings` now uses `********` as the "unchanged" sentinel for sensitive keys; empty string properly clears the value

---

## [2.3.2] - 2026-03-25

### Added

#### DNS-over-HTTPS (DoH) Fallback
- **Automatic DoH fallback when UDP port 53 is blocked**: Some VPS providers block outgoing traffic on UDP port 53, preventing DNS record validation (SPF, DKIM, DMARC) and blacklist checks from working
  - DNS queries now try traditional UDP resolvers first (fast path, no change for most users)
  - If all UDP resolvers fail (timeout/blocked), automatically falls back to DNS-over-HTTPS (DoH) via Cloudflare and Google on port 443
  - Applies to all DNS operations: domain DNS validation, blacklist checking, and hostname resolution
  - No configuration needed — fallback is fully automatic

#### Docker Data Directory Permissions Auto-Fix
- **Automatic permission fix for bind-mounted data directory**: When Docker runs as root, the host `./data` directory is created with root ownership, preventing the application (running as UID 1000) from writing to it
  - New `entrypoint.sh` script detects if the container is running as root
  - If root: automatically fix host directory permissions
  - If non-root: starts the application directly without any permission changes
  - No user action required — the fix is built into the image

### Fixed

#### APP_PORT Ignored After Importing Settings to Database
- **Port misconfiguration after .env import**: When using "Import from ENV" to migrate settings to the database, `APP_PORT` was incorrectly imported as an editable setting
  - `APP_PORT` is a Docker-level setting controlling the host port mapping in `docker-compose.yml`, not an application-level setting
  - After removing `APP_PORT` from `.env` (since it was "migrated" to DB), Docker Compose defaulted to port 8080, while the UI/DB still showed the configured port (e.g. 8083)
  - `app_port` is now excluded from editable settings — it remains an ENV/Docker-only setting

### Changed

#### ENV Variables Now Override Database Settings (Lockout Prevention)
- **Settings priority inverted**: ENV variables now always take precedence over database-stored values (new order: Default → DB → ENV)
  - Previously, DB overrode ENV, meaning a configuration mistake in the UI (e.g., wrong OIDC URL, bad auth password) could lock users out with no way to fix it except editing the database directly
  - Now, setting a value in `.env` / `docker-compose.yml` always overrides the DB value, acting as an "escape hatch" for lockout recovery
  - Fields controlled by ENV are marked with a 🔒 lock icon in the Settings UI
  - DB values are still saved and used as fallback when the ENV variable is removed

---

## [2.3.1] - 2026-03-20

### Fixed

#### Critical Security Fix: Basic Auth Credential Bypass
- **Authentication bypass when using `BASIC_AUTH_ENABLED`**: Fixed a critical vulnerability where `BASIC_AUTH_ENABLED=true` accepted **any username and password**
  - Root cause: `verify_credentials()` checked the deprecated `auth_enabled` field (always `false`) instead of `is_basic_auth_enabled`
  - When only `BASIC_AUTH_ENABLED=true` was set (without the deprecated `AUTH_ENABLED`), credential verification was completely skipped
  - Both `BASIC_AUTH_ENABLED` and legacy `AUTH_ENABLED` now work correctly
  - **All users using `BASIC_AUTH_ENABLED=true` should update immediately**

#### Settings Persistence After Restart
- **Settings saved via UI were lost on restart**: Database-stored settings were not loaded during application startup
  - Startup log messages now show effective configuration values (after DB overrides are applied)

#### ENV Conflict Warning False Positives
- **"This value differs from ENV" warning shown incorrectly**: Warning appeared for settings that differed from defaults, even when no ENV variable was explicitly set
  - Warning now only appears when an ENV variable is explicitly set AND differs from the DB value

#### OAuth2 / Service Config Not Working from UI
- **OAuth2, SMTP, and other services ignored UI settings**: Singleton service instances (`OAuth2Client`, `MailcowAPI`) captured settings by value at import time instead of reading dynamically
  - Service configs are now reloaded after settings save, import-from-env, and on startup

#### Health Endpoint Auth Status
- Fixed `/api/health` reporting incorrect authentication status by using the deprecated `auth_enabled` field instead of the actual `is_authentication_enabled` property

---

## [2.3.0] - 2026-03-19

### Added

#### Settings Management via Web UI
- Added settings editor accessible from Settings page (controlled by `SETTINGS_EDIT_VIA_UI_ENABLED=true`)
- Settings organized into tabs: Mailcow, Fetch, Correlation, Application, Blacklist, Authentication, OAuth2, SMTP, Alerts, DMARC, DMARC IMAP, MaxMind
- Settings stored in database override ENV variables
- Migration tool to import current ENV configuration to database
- Visual warnings for settings where ENV differs from DB

#### SSL Verification Toggle for mailcow API
- **Development Environment Support**: Added `MAILCOW_API_VERIFY_SSL` configuration option to allow connections to mailcow API with self-signed SSL certificates
  - Default: `true` (SSL verification enabled for security)
  - Set to `false` for development environments with self-signed certificates
  - All API calls to mailcow now use consistent SSL verification settings
  - Centralized API client ensures all requests use the same configuration

#### DMARC Record Status and Settings on DMARC Domain Page
- **Domain overview**: On the DMARC tab, when viewing a domain (e.g. after clicking a domain), a **DMARC Record** card now shows the current DNS record status and settings
  - **Parsed settings**: Policy, Subdomain policy, Aggregate report URIs (rua), Forensic report URIs (ruf), DKIM/SPF alignment, Percentage, Failure reporting options (only present tags shown)

#### DMARC Reports Automatic Cleanup
- **Scheduled retention cleanup**: Old DMARC and TLS reports are now automatically deleted based on `DMARC_RETENTION_DAYS` (default: 60 days)

#### Blacklist Notifications – Cleared and Improved
- **Cleared notification**: Email alert when all monitored hosts are no longer on any (actionable) blacklists (previously at least one was listed)
- **Improved notification**: Email alert when the number of listed hosts decreases (e.g. from 3 to 2), with subject "Blacklist Improved – X → Y Host(s) Listed" and list of hosts still listed

#### Alias Domains Support for Mail Direction
- **mailcow alias-domain API**: Sync of alias domains from `/api/v1/get/alias-domain/all` so that emails sent from alias domains are classified correctly
- **Direction fallback**: When Rspamd reports inbound (e.g. user unknown), direction is reclassified to outbound if the sender domain is local (including alias) and at least one recipient is external

### Fixed

#### Alias Domain Mail Shown as Inbound
- **Direction classification**: Emails sent from an alias domain (subdomain configured as alias of the main domain) toward the Internet were incorrectly shown as "inbound" in logs. They are now correctly shown as "outbound" by including alias domains in the local domains cache and applying a sender/recipient fallback when Rspamd does not set MAILCOW_AUTH or user for alias-domain sends.

#### DMARC IMAP Sync Application Freezing
- **Connection Timeout and Thread Pool**: Fixed issue where the application would freeze during IMAP connection attempts
  - IMAP sync operations now run in a thread pool executor to prevent blocking the event loop
  - Improved error messages with detailed host and port information for easier troubleshooting
  - Connection errors are now handled gracefully without crashing the application

#### Basic Auth Login with Wrong Credentials
- **Login validation**: Fixed issue where entering incorrect username or password did not show an error and gave the illusion of successful login
  - Login form now calls `GET /api/auth/verify` (protected endpoint) instead of `/api/info` (public) to validate credentials
  - Invalid credentials now return 401 and display "Invalid username or password" on the login page
  - Credentials and password field are cleared on failure

### Technical

#### New Environment Variables
- `MAILCOW_API_VERIFY_SSL` - Control SSL certificate verification for mailcow API connections (default: `true`)
  - Set to `false` for development environments with self-signed certificates
  - All mailcow API requests respect this setting
- `SETTINGS_EDIT_VIA_UI_ENABLED` - Enable settings editor in UI (default: `false`)
  - Set to `true` to enable settings editor in UI
  - Set to `false` to disable settings editor in UI

---

## [2.2.5] - 2026-02-15

### Added

#### OAuth2/OIDC Authentication Support
- **Generic OAuth2/OIDC Integration**: Complete OAuth2/OIDC authentication support for any standard identity provider
  - Works with Authentik, Mailcow, Keycloak, Google, Microsoft Azure AD, Auth0, and any OAuth2/OIDC provider
  - Supports both OIDC Discovery (automatic endpoint discovery) and manual endpoint configuration
  - Provider-agnostic implementation - no provider-specific code required
  - Dual authentication methods: Both Basic Auth and OAuth2 can be enabled simultaneously
  - Secure session management with HTTP-only cookies
  - **See [OAuth2 Configuration Guide](./documentation/OAuth2_Configuration.md) for detailed setup instructions**

#### mailcow Update Indicator
- **Footer Update Badge**: Added a distinct "Update Available" badge in the footer for Mailcow server updates.
  - Complements the existing header icon.
  - Clickable to view the full changelog in a modal.

#### Live Container Logs
- **Terminal Viewer**: Added a terminal icon `(>_)` in the footer to view application logs directly from the UI.
- **Live Updates**: Logs modal automatically refreshes every 2 seconds for real-time monitoring.
- **Auto-Scroll**: Smart scrolling logic keeps view at the bottom during updates unless user scrolls up.

### Changed

#### Authentication Configuration
- **Simplified Authentication Flags**: Removed `AUTH_METHOD` configuration option
  - Authentication method now determined automatically by enabled flags
  - `BASIC_AUTH_ENABLED=true` enables Basic Auth
  - `OAUTH2_ENABLED=true` enables OAuth2
  - Both can be enabled simultaneously for dual authentication
  - `AUTH_ENABLED` still supported for backward compatibility (deprecated)

- **Login Page Enhancement**: Dynamic authentication method display
  - OAuth2 login button appears when OAuth2 is enabled
  - Basic Auth form appears when Basic Auth is enabled
  - "OR" separator only shown when both methods are available
  - Provider name dynamically displayed on OAuth2 button

#### GDPR Compliance
- **Local Resource Loading**: All external JavaScript and CSS resources now loaded from local server
  - Removed all CDN dependencies (Tailwind CSS, Marked.js, Chart.js, GitHub Markdown CSS)
  - All libraries now served from `/static/assets/libs/` directory
  - Application is now GDPR compliant with no external resource requests
  - No data transfer to third-party CDN services (jsdelivr, cdnjs, etc.)

### Fixed

#### Container Status Counting
- **Stopped Containers Not Counted**: Fixed issue where stopped containers were not being counted in the "Stopped" total on the Status page
  - mailcow API only returns active containers, so stopped containers don't appear in the response
  - Implemented database cache system (`known_containers` table) to track all containers that have been seen
  - Containers are automatically added to cache when first seen in API response
  - Stopped containers (known but not in API response) are now correctly identified and counted as "Stopped"
  - Ensures accurate container counts even when containers are completely stopped

#### IP Blacklist Monitor
- **Spamhaus DNS Query Blocking**: Fixed issue where Spamhaus was blocking DNS queries, causing incorrect "Clean" status when IPs were actually listed on blacklists

#### Domain DNS Checks
- **DNS Reliability**: Added DNS fallback system for all domain DNS validation checks (SPF, DKIM, DMARC) to prevent false negatives due to DNS server failures

### Technical

#### New API Endpoints
```
GET  /api/auth/login          - Initiate OAuth2 login flow
GET  /api/auth/callback       - Handle OAuth2 callback from provider
GET  /api/auth/logout         - Logout and clear session
GET  /api/auth/status         - Check authentication status
GET  /api/auth/provider-info  - Get provider configuration for frontend
```

#### New Environment Variables
- OAuth2/OIDC configuration variables (see `env.example` and [OAuth2 Configuration Guide](./documentation/OAuth2_Configuration.md))
- `BASIC_AUTH_ENABLED` - New flag for Basic Auth (replaces deprecated `AUTH_ENABLED`)

---

## [2.2.0] - 2026-01-28

### Added

#### Weekly Server Summary Report
- **Automated Weekly Email Report**: Comprehensive server status report sent every Friday
  - **System Health**: Mailbox/Alias/Domain counts, Storage usage, Queue & Quarantine stats
  - **Traffic Overview**: Total Sent/Received messages, Failure rates with visual severity indicators
  - **Blacklist Status**: Current status of all monitored hosts (shows detailed RBLs if listed)
  - **DNS Security**: Alerts for domains with critical SPF/DKIM/DMARC configuration errors
  - **Problem Areas**: "Top 5 Worst Mailboxes" table identifying accounts with high failure rates
  - Configurable via `ENABLE_WEEKLY_SUMMARY` (default: true) and `ADMIN_EMAIL`

#### IP Blacklist Monitor
- **DNS Blacklist Checking**: New feature to check mail server IP against ~50 popular DNSBLs
  - Real-time checking against major blacklists: Spamhaus ZEN/SBL/XBL/PBL, Barracuda, SpamCop, SORBS, UCEPROTECT, and more
  - Status page section with summary cards (Server IP, Status, Listed Count, Last Check)
  - Expandable list showing all 50+ blacklist check results
  - "Check Now" button for manual refresh
  - Dashboard summary card for quick status overview

- **Automated Daily Checks**: Background scheduler runs daily at 5:00 AM
  - Results cached for 24 hours to prevent excessive DNS queries
  - Startup check runs 60 seconds after application start
  - Job status visible in Background Jobs section on Status page

- **Email Notifications**: Automatic alerts when server is listed on blacklists
  - Sends detailed HTML email with list of blacklists where server is listed
  - Includes lookup links for each blacklist
  - Configurable via `BLACKLIST_ALERT_EMAIL` (falls back to `ADMIN_EMAIL`)

#### DMARC Reports Management
- **Reports Management Modal**: New popup to view and manage all DMARC and TLS reports
  - Clickable "Manage Reports" link below the domains table
  - Mobile-responsive card layout for smaller screens
  - Color-coded type badges (blue for DMARC, green for TLS)

- **Report Deletion**: Optional ability to delete individual reports
  - Controlled by `DMARC_ALLOW_REPORT_DELETE` environment variable (default: false)
  - When enabled, delete button appears for each report
  - Confirmation dialog before deletion
  - Cascading delete removes associated records (DMARCRecord/TLSReportPolicy)
  - Automatically clears DMARC cache after deletion
  - Refreshes both modal and domains list after successful deletion

### Changes

#### Background Jobs Improvements
- **Manual Job Execution**: Added "Run Now" buttons to each background job card
  - Allows manually triggering any of the 13 background jobs
  - Displays loading state and success/warning toast notifications
  - Toasts now show human-readable job names (e.g. "Alias Statistics")

- **UI Updates**:
  - Wrapped "Background Jobs" section in a collapsible accordion (closed by default) to save space

### Fixed

#### SPF Validation
- **Recursive Redirect Support**: Added full support for SPF `redirect=` mechanism
  - Now correctly follows redirects to target domains
  - Recursively validates IP authorization against the redirected policy

#### DKIM Validation
- **Flexible Tag Parsing**: Improved DKIM record normalization
  - Now correctly handles spaces between tags (e.g., `v=DKIM1; k=rsa` vs `v=DKIM1;k=rsa`)
  - Prevents false negatives when DNS providers add optional whitespace

#### Mailbox Stats
- **Rate Limit Display**: Fixed issue where Rate Limit was displaying as "None" even when configured
  - Adjusted backend ingestion to correctly parse nested Rate Limit objects from Mailcow API response

#### General
- **Naming Consistency**: Renamed "Mailcow" to "mailcow" across the application to match the official product name
  - Updated frontend interface labels and logs
  - Updated backend logs, API descriptions, and configuration fields
  - Updated documentation and README

- **Email Subject Quote Display**: Fixed escaped quotes (`\"`) appearing in email subjects
  - Subjects with double quotes now display correctly without backslashes

- **Job Status Persistence**: Fixed issue where jobs (like `expire_correlations`, `cleanup_logs`) were getting stuck in "running" state if no items were processed.

- **Spam Alias Logic Support**: Enhanced log parsing to correctly handle emails delivered to spam aliases (e.g., `spam@localhost`)
  - Parses `orig_to` field from Postfix logs to identify the real recipient
  - Detects deliveries to `rspamd-pipe-spam` command
  - Marks email status as `SPAM` instead of `CLEAN/Delivered` when routed to spam alias
  - Correctly associates the log with the original recipient

- **Rspamd SPAM_TRAP Detection**: Added support for `SPAM_TRAP` symbol in Rspamd logs
  - Automatically marks emails as `SPAM` if the `SPAM_TRAP` symbol is present in the Rspamd result
  - Updates both the Rspamd log record and the associated correlation status

### Technical

#### New API Endpoints
```
GET    /api/dmarc/reports/config  - Get report management configuration
GET    /api/dmarc/reports/all     - Get all DMARC and TLS reports
DELETE /api/dmarc/reports/{type}/{id} - Delete a specific report
GET /api/blacklist/check        - Get blacklist check results (uses cache)
GET /api/blacklist/check?force=true - Force new check ignoring cache
GET /api/blacklist/config       - Get blacklist configuration
GET /api/blacklist/summary      - Get compact summary for dashboard
POST /api/settings/jobs/{job_name}/run

#### New Environment Variables
- `DMARC_ALLOW_REPORT_DELETE`: Enable/disable report deletion from UI (default: false)
- `BLACKLIST_ALERT_EMAIL`: Email address for blacklist alerts (optional, uses `ADMIN_EMAIL` if not set)
- `ENABLE_WEEKLY_SUMMARY`: Enable/disable weekly server summary report (default: true)

---

## [2.1.2] - 2026-01-20

### Added

#### Mailbox Statistics Page
- **Complete Mailbox Statistics Feature**: New page showing per-mailbox message statistics
  - Summary cards: Total Sent, Received, Failed, and Failure Rate
  - Accordion-style mailbox list with expandable details
  - Message counts aggregated from MessageCorrelation table (not Mailcow API)
  - Per-alias message statistics with sent/received/failed counts
  - Combined totals (mailbox + all its aliases)

- **Clickable Statistics Links**: All stat cards and alias table cells are clickable
  - Click on any stat (Sent, Received, Internal, Delivered, Deferred, Bounced, Rejected) to navigate to Messages page
  - Search automatically pre-filled with the mailbox/alias email address

- **Mailbox Details Display (Domains-style)**:
  - Quota usage with percentage
  - Messages in mailbox count
  - Last IMAP/SMTP/POP3 login times
  - Created and Modified dates
  - Rate limiting settings (value/frame)
  - Access permissions indicators: IMAP, POP3, SMTP, Sieve, SOGo, TLS Enforce
  - Color-coded status dots (green=enabled, red=disabled)

- **Filtering & Search**:
  - **Date Range Picker with Presets**:
    - Quick select preset buttons: Today, 7 Days, 30 Days, 90 Days
    - Custom date range with From/To date inputs
  - Domain filter dropdown
  - Search by mailbox username, name, or alias address
  - "Active Only" checkbox (default: checked)
  - "Hide Zero Activity" checkbox (default: checked) - filters mailboxes and aliases with no messages
  - Sort by: Sent, Received, Failure Rate, Quota Used, Username

- **Pagination**: 50 mailboxes per page with navigation controls

#### Background Jobs
- **Mailbox Statistics Job**: Fetches mailbox data from Mailcow API every 5 minutes
  - Syncs quota, messages, login times, rate limits, and attributes
  - Marks deleted mailboxes as inactive (preserves historical data)
  
- **Alias Statistics Job**: Fetches alias data from Mailcow API every 5 minutes
  - Links aliases to their target mailboxes
  - Marks deleted aliases as inactive (preserves historical data)

#### SMTP Relay Mode
- **No-Authentication SMTP Support**: New option for sending emails through local relay servers without credentials
  - Enable via `SMTP_RELAY_MODE=true` in environment variables
  - When enabled, `SMTP_USER` and `SMTP_PASSWORD` are not required
  - Useful for local Postfix relay servers, internal mail gateways, or trusted SMTP relays
  - Connection test in Settings page properly handles relay mode authentication bypass

#### Clean URL Routing (History API)
- **Shareable URLs for All Pages**: Implemented History API-based routing for the SPA
  - Direct navigation to any tab via clean URLs (e.g., `/dashboard`, `/messages`, `/dmarc`, `/settings`)
  - Browser Back/Forward buttons now work correctly between pages
  - URLs can be bookmarked and shared

- **DMARC Nested Routes**: Deep linking support for all DMARC views
  - `/dmarc` - Domains list
  - `/dmarc/{domain}` - Domain overview
  - `/dmarc/{domain}/reports` - Daily Reports tab
  - `/dmarc/{domain}/sources` - Source IPs tab
  - `/dmarc/{domain}/tls` - TLS Reports tab
  - `/dmarc/{domain}/report/{date}` - Specific daily report details
  - `/dmarc/{domain}/source/{ip}` - Specific source IP details

- **Removed Internal Back Button**: DMARC section no longer uses custom back button
  - Users now use browser's native Back button
  - Cleaner UI without duplicate navigation controls

#### TLS-RPT (TLS Reporting) Support
- **Complete TLS-RPT Implementation**: Full support for TLS aggregate reports (RFC 8460)
  - TLS-RPT parser for JSON reports (gzip compressed)
  - Database models for TLS reports and policies
  - IMAP auto-import support for TLS-RPT emails
  - Manual upload support for TLS-RPT files

- **TLS Reports Tab in DMARC Page**:
  - New "TLS Reports" sub-tab alongside Daily Reports and Source IPs
  - Daily aggregated view showing reports grouped by date
  - Success rate with color-coded progress bars (green ≥95%, yellow ≥80%, red <80%)
  - Provider breakdown with session counts

- **TLS Report Details View**:
  - Click any daily report to see detailed breakdown
  - Stats cards: Sessions, Success Rate, Successful, Failed
  - Providers table with per-provider success rates

- **TLS in Domain List**:
  - TLS Success Rate column in DMARC domains table
  - TLS report count displayed per domain
  - Domains with only TLS reports (no DMARC) now included in list

#### DMARC Navigation Improvements
- **Breadcrumb Navigation**: Clear path indicator for all DMARC views
  - Shows current location: `domain.com > Daily Reports > Jan 14, 2026`
  - Clickable links to navigate back to any level
  - Displayed below page description

#### Mobile Navigation Hamburger Menu
- **Hamburger Menu for Mobile**: 
  - Replaced horizontal scrolling tabs with a proper hamburger menu on mobile devices

### Fixed

#### DMARC Source IPs - Broken Flag Images
- **Fixed broken flag images when MAXMIND is not configured**: When GeoIP integration is not set up, the Source IPs tab was showing broken images
  - Now displays a generic server icon instead of a broken image when country data is unavailable
  - Flag is completely hidden in source details view when no GeoIP data exists
  - Added `onerror` fallback handlers to gracefully handle missing flag files
  - Improves UX for users who haven't configured MAXMIND integration

#### DMARC Parser
- **DMARC 2.0 XML Namespace Support**: Fixed parsing error for DMARC reports using XML namespaces
  - Reports from GMX and other providers using the new format now parse correctly
  - Parser now tries both namespaced and non-namespaced element lookups

### Improved

#### Backend API Performance
- **In-Memory Caching for Statistics API**: Added 5-minute TTL cache for `/api/mailbox-stats/all` endpoint
  - Cache key generated from all query parameters
  - First request fetches from database, subsequent requests return from cache
  - Cache automatically expires after 5 minutes for fresh data
  - Significantly reduces database load and improves response times

- **In-Memory Caching for DMARC API**: Added 5-minute TTL cache for `/api/dmarc/domains` endpoint
  - Reduces heavy database queries for domain statistics
  - Cache cleared on new report imports

#### DMARC IMAP Auto-Import
- **Batch Processing**: Emails are now processed in configurable batches to prevent memory issues
  - New `DMARC_IMAP_BATCH_SIZE` environment variable (default: 10)
  - Processes emails in chunks, re-searching after each batch
  - Progress logging shows batch number and completion status
  - Prevents application crashes when syncing mailboxes with lots of emails

- **UID-Based Email Handling**: Fixed "Invalid messageset" IMAP errors
  - Changed from sequence numbers to UIDs for all IMAP operations
  - UIDs remain stable even after deleting emails during sync
  - Affects SEARCH, FETCH, STORE operations

- **Flexible DMARC Email Detection**: Now supports more email providers
  - Yahoo and other providers that don't include "Report-ID:" now detected correctly
  - Primary validation is now attachment-based (.xml.gz or .zip files)
  - Accepts: "Report Domain:" only, "Report Domain:" + "Submitter:", or "DMARC" keyword
  
- **Improved Error Reporting in Notifications**: 
  - Error notification emails now show actual error messages
  - Parse failures show: "Failed to parse: filename.xml.gz"
  - Processing errors show: "Error processing filename: exception details"
  - Duplicate reports no longer counted as failures

- **Infinite Loop Prevention**: Fixed sync running endlessly when emails fail validation
  - Added `UNSEEN` filter to search criteria
  - Failed or processed emails are marked as Seen and excluded from next search
  - Prevents re-processing the same emails repeatedly

- **Microsoft Outlook Support**: Fixed DMARC reports from Microsoft not being recognized
  - Now detects DMARC reports by filename pattern (contains `!` separator)
  - Supports filenames like: `enterprise.protection.outlook.com!domain!timestamp!timestamp.xml.gz`

- **Enhanced Attachment Extraction**: More robust attachment detection
  - Now supports plain `.xml` files in addition to `.xml.gz` and `.zip`
  - Falls back to Content-Type `name` parameter when filename header is missing
  - Recognizes attachments by Content-Type: `application/gzip`, `application/zip`, `text/xml`, etc.
  - Added debug logging to help troubleshoot attachment detection issues

#### Domains Page - DKIM View Record
- **DKIM Record Viewer**: Added "View Record" functionality for DKIM, similar to SPF
  - Displays the full DNS record name including selector (e.g., `dkim._domainkey.example.com`)
  - Shows the DKIM public key record value
  - Helps users identify exactly which DNS record to configure

### Technical

#### New API Endpoints
```
GET  /api/mailbox-stats/summary
GET  /api/mailbox-stats/all
GET  /api/mailbox-stats/domains
```

#### API Parameters
- `date_range`: today, 7days, 30days, 90days, custom
- `start_date`: Custom start date (YYYY-MM-DD) - required when date_range is 'custom'
- `end_date`: Custom end date (YYYY-MM-DD) - required when date_range is 'custom'
- `domain`: Filter by specific domain
- `active_only`: true/false
- `hide_zero`: true/false (filter zero-activity mailboxes)
- `search`: Search mailbox/alias addresses
- `sort_by`: sent_total, received_total, failure_rate, quota_used, username
- `sort_order`: asc, desc
- `page`, `page_size`: Pagination

---

## [2.0.4] - 2026-01-15

### Fixed

### DMARC Manual Upload Button Not Showing
- Fixed issue where manual upload button was hidden even when enabled in settings

### DKIM Record Validation False Negatives
- Fixed DKIM validation incorrectly reporting mismatch when parameter order differs
- Changed validation from string comparison to parameter-based comparison
- DKIM records now validated correctly regardless of parameter order (e.g., `p=...;s=t` equals `s=t;p=...`)
- Follows RFC standard where DKIM parameter order is insignificant

---

## [2.0.0] - 2026-01-14

### Added

#### DMARC Backend
- Daily data aggregation for performance
- GeoIP enrichment with MaxMind database support (City + ASN)
- Automatic MaxMind database downloads and updates
- Weekly scheduler for MaxMind databases updates (Sunday 3 AM)

#### DMARC Frontend - Complete UI Implementation
- **Domains List View**: 
  - Stats dashboard showing total domains, messages, pass rate, and unique IPs
  - Full domain overview with 30-day statistics
  - Color-coded pass rates (green ≥95%, yellow ≥80%, red <80%)
  - Policy badges (reject/quarantine/none) with appropriate styling
  - Empty state with helpful messaging for first-time users
  
- **Domain Overview Page**:
  - Breadcrumb navigation in DMARC page
  - Domain-specific stats cards (total messages, compliance rate, unique sources)
  - Daily Volume Graph showing 30-day email trends

- **Daily Reports Tab**:
  - Aggregated daily report cards
  - Shows report count, unique IPs, total messages per day
  - SPF and DKIM pass percentages displayed
  - Overall DMARC pass rate
  - Chronological ordering (newest first)
  
- **Source IPs Tab with Complete GeoIP Info**:
  - City names from MaxMind City database
  - ISP/Organization names
  - Country flag emoji display
  - Message counts and pass rates per IP
  
- **Upload DMARC Functionality**:
  - Upload button
  - Supports XML, GZ, and ZIP file formats
  - Toast notifications for success/duplicate/error states
  - Auto-refresh of current view after successful upload
  - Client-side file validation

#### DMARC IMAP Auto-Import System
- **Automatic Report Fetching**: Complete IMAP integration for automatic DMARC report imports
  - Configurable sync interval (default: 1 hour) via `DMARC_IMAP_INTERVAL`
  - Automatic connection to IMAP mailbox and report processing
  - Supports SSL/TLS connections (`DMARC_IMAP_USE_SSL`)
  - Configurable folder monitoring (default: INBOX via `DMARC_IMAP_FOLDER`)
  - Optional email deletion after processing (`DMARC_IMAP_DELETE_AFTER`)
  - Background job runs automatically at specified intervals
  - Manual sync trigger available in DMARC page
  
- **DMARC IMAP Sync History**:
  - Comprehensive sync statistics tracking (emails found, processed, created, duplicates, failed)
  - Interactive modal showing all past sync operations
  - Color-coded status indicators (success/error)
  - Duration display for each sync
  - Failed email count with highlighting
  - "View History" button in DMARC tab
  - Sync history persists across restarts

- **DMARC Error Notifications**: Automatic email alerts for IMAP sync failures
  - Sends detailed error reports when IMAP sync encounters failures
  - Email includes: failed email count, message IDs, subjects, and error descriptions
  - Link to sync history in notification email
  - Only sends when failures occur and SMTP is configured
  - Configurable error recipient via `DMARC_ERROR_EMAIL` (defaults to `ADMIN_EMAIL`)

#### Global SMTP Configuration & Notifications
- **Centralized SMTP Service**: Generic email infrastructure for all notification types
  - Configured via environment variables: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`
  - Support for TLS/SSL connections (`SMTP_USE_TLS`)
  - Configurable sender address (`SMTP_FROM`) and admin email (`ADMIN_EMAIL`)
  - Can be enabled/disabled globally (`SMTP_ENABLED`)
  - Ready for future notification types beyond DMARC

- **Settings UI Enhancements**:
  - New "Global SMTP Configuration" section showing current SMTP settings
  - New "DMARC Management" section showing manual upload and IMAP status
  - Display of SMTP server, port, and admin email when configured
  - Display of IMAP server when auto-import enabled

- **Test Connection Buttons**: 
  - Added diagnostic test buttons in Settings page for both SMTP and IMAP
  - Interactive popup showing connection attempt logs in real-time
  - Tests authentication, server connectivity, mailbox access, and email sending

#### DMARC Tab Enhancements
- **IMAP Sync Controls**: Dynamic UI based on configuration
  - "Sync from IMAP" button appears when IMAP auto-import enabled
  - "Upload Report" button hidden when manual upload disabled (`DMARC_MANUAL_UPLOAD_ENABLED=false`)
  - Last sync information displayed below sync button (time and status icon)

#### MaxMind GeoIP Integration
- **Configuration**:
  - MaxMind account ID and license key via .env
  - `MAXMIND_ACCOUNT_ID` - MaxMind account ID
  - `MAXMIND_LICENSE_KEY` - MaxMind license key
  - Free GeoLite2 databases available at maxmind.com
  - Databases stored in `/app/data/` directory

- **Automatic Database Management**:
  - Auto-downloads MaxMind GeoLite2 databases on first startup
  - Dual database support: GeoLite2-City + GeoLite2-ASN
  - Weekly automatic updates (Sunday 3 AM via scheduler)
  - Database persistence via Docker volume mount (`./data:/app/data`)
  
- **GeoIP Enrichment Service**:
  - Enriches all DMARC source IPs automatically during upload
  - Dual readers for City and ASN lookups
  - City names, Country code, Country name, Country emoji flags
  - ASN Number, ASN organization
  
- **Graceful Degradation**:
  - Works without MaxMind license key (returns null for geo fields)
  - Continues operation if databases unavailable
  - Default globe emoji (🌍) for unknown locations
  - Non-blocking errors (logs warnings but doesn't crash)
  
- **Background Job**:
  - Runs weekly on Sunday at 3 AM
  - Checks database age (updates if >7 days old)
  - Downloads both City and ASN Databases
  - Automatic retry with exponential backoff
  - Status tracking in Status page

- **MaxMind License Validation**: Added real-time validation of MaxMind license key in Settings page
  - Validates license key using MaxMind's validation API
  - Displays status badge: "Configured" (green with checkmark) or "Not configured" (gray)
  - Shows error details if validation fails (red badge with X icon)

#### SPF Validation Enhancements
- **DNS Lookup Counter**: SPF validation now counts and validates DNS lookups according to RFC 7208
  - Recursive counting through `include:` directives
  - Counts `a`, `mx`, `exists:`, `redirect=`, and `include:` mechanisms
  - Maximum limit of 10 DNS lookups enforced
  - Returns error when limit exceeded: "SPF has too many DNS lookups (X). Maximum is 10"

- **Server IP Authorization Check**: SPF validation now verifies mail server IP is authorized
  - Fetches server IP from Mailcow API on startup
  - Caches IP in memory for performance (no repeated API calls)
  - Checks if server IP is authorized via:
    - Direct `ip4:` match (including CIDR ranges)
    - `a` record lookup
    - `mx` record lookup
    - Recursive `include:`
  - Returns error if server IP not found in SPF: "Server IP X.X.X.X is NOT authorized in SPF record"
  - Shows authorization method in success message: "Server IP authorized via ip4:X.X.X.X"

- **Enhanced SPF Validation**: Complete SPF record validation
  - Detects multiple SPF records (RFC violation - only one allowed)
  - Validates basic syntax (`v=spf1` with space)
  - Checks for valid mechanisms only (ip4, ip6, a, mx, include, exists, all)
  - Validates presence of `all` mechanism
  - Prevents infinite loops in circular includes
  - Depth protection (maximum 10 recursion levels)

#### DKIM Parameter Validation
- **Testing Mode Detection** (`t=y`): Critical error detection
  - Detects DKIM testing mode flag
  - Returns error status with message: "DKIM is in TESTING mode (t=y)"
  - Warning: "Emails will pass validation even with invalid signatures. Remove t=y for production!"
  - Prevents false validation in production environments

- **Strict Subdomain Mode Detection** (`t=s`): Informational flag
  - Detects strict subdomain restriction flag
  - Displayed as informational text (not warning)
  - Message: "DKIM uses strict subdomain mode (t=s)"
  - Does NOT affect DKIM status (remains "success")

- **Revoked Key Detection** (`p=` empty): Error detection
  - Detects intentionally disabled DKIM keys
  - Returns error status with message: "DKIM key is revoked (p= is empty)"
  - Indicates DKIM record has been decommissioned

- **Weak Hash Algorithm Detection** (`h=sha1`): Security warning
  - Detects deprecated SHA1 hash algorithm
  - Returns warning status with message: "DKIM uses SHA1 hash algorithm (h=sha1)"
  - Recommendation: "SHA1 is deprecated and insecure. Upgrade to SHA256 (h=sha256)"

- **Key Type Validation** (`k=`): Configuration check
  - Validates key type is `rsa` or `ed25519`
  - Warning for unknown key types
  - Helps identify configuration errors

### Fixed

#### Message Correlation System
- **Final Status Update Job Enhancement**: Fixed correlations not updating when Postfix logs arrive milliseconds after correlation creation
  - Increased batch size from 100 to 500 correlations per run for faster processing
  - Fixes race condition where `status=sent` logs arrived seconds after correlation was marked complete
  - Improved logging to show how many logs were added to each correlation

#### Postfix Log Deduplication
- **UNIQUE Constraint Added**: Postfix logs now have database-level duplicate prevention
  - Automatic cleanup of existing duplicate logs on startup (keeps oldest entry)
  - Import process now silently skips duplicate logs (no error logging)
  - Batched deletion (1000 records at a time) to prevent database locks
  - Handles NULL `queue_id` values correctly using `COALESCE`
  - Prevents duplicate log imports when fetch job runs faster than log generation rate
  - Improved logging shows count of duplicates skipped during import

### Technical

#### New API Endpoints
```
GET  /api/dmarc/domains?days=30
GET  /api/dmarc/domains/{domain}/overview?days=30
GET  /api/dmarc/domains/{domain}/reports?days=30
GET  /api/dmarc/domains/{domain}/sources?days=30
POST /api/dmarc/upload
GET /api/dmarc/imap/status
POST /api/dmarc/imap/sync
GET /api/dmarc/imap/history
POST /api/settings/test/smtp
POST /api/settings/test/imap
```

---

## [1.4.8] - 2026-01-08

### Added

#### Automated Domains DNS Validation
- **Automated Background Checks**:
  - DNS checks run automatically every 6 hours via scheduler
  - Checks only active domains to optimize performance
  - Results cached with timestamps for quick display

- **Manual DNS Verification**:
  - **Global Check**: "Check Now" button in Domains Overview header
    - Updates all active domains simultaneously
    - Updates global "Last checked" timestamp
  - **Single Domain Check**: Individual "Check" button per domain
    - Updates only the specific domain without page refresh
    - Partial UI update for better UX
  - Toast notifications for user feedback on all check operations

- **DNS Check Results Display**:
  - Last check timestamp displayed in page header (global checks only)
  - Last check timestamp per domain in DNS Security Records section

#### Backend Infrastructure
- **New Database Table**: `domain_dns_checks`
  - Stores SPF, DKIM, DMARC validation results as JSONB
  - Includes `checked_at` timestamp and `is_full_check` flag
  - Automatic migration with PostgreSQL artifact cleanup
  
- **New API Endpoints**:
  - `GET /api/domains/all` - Fetch all domains with cached DNS results
  - `POST /api/domains/check-all-dns` - Trigger global DNS check (manual)
  - `POST /api/domains/{domain}/check-dns` - Check specific domain DNS

#### Frontend Enhancements
- **Responsive Design**: Mobile-optimized layout
  - Header elements stack vertically on mobile, horizontal on desktop
  - Centered content on mobile for better readability
  - Check button and timestamp properly aligned on all screen sizes

- **Toast Notifications**: User feedback system
  - Success, error, warning, and info message types
  - Color-coded with icons (✓, ✗, ⚠, ℹ)
  - Auto-dismiss after 4 seconds
  - Manual dismiss option

#### Background Jobs Monitoring & Enhanced UI
- **Real-time Status Tracking**: All background jobs now report execution status (running/success/failed/idle/scheduled), last run timestamp, and error messages
- **Enhanced Visual Design**: 
  - Compact mobile-optimized layout
  - Full-color status badges (solid green/blue/red/gray/purple backgrounds with white text)
  - Icon indicators: ⏱ interval, 📅 schedule, 🗂 retention, ⏳ max age, 📋 pending items
  - Always-visible last run timestamps
- **Complete Job Coverage**: All 7 background jobs now visible in UI (previously only 5 were displayed):
  - Fetch Logs, Complete Correlations, Update Final Status, Expire Correlations, Cleanup Logs, Check App Version, DNS Check

### Changed

#### Queue and Quarantine Page
- **Display Order**: Quarantine page now displays newest messages first
  - Messages sorted by creation timestamp in descending order (newest → oldest)
  - Backend sorting ensures consistent ordering

#### Dashboard - Recent Activity
- **Layout Improvement**: Reorganized Status & Direction display for better readability
  - Status and Direction badges now displayed on first line, right-aligned
  - Timestamp moved to second line below badges

### Background Jobs and Status Page
- Background job status badges now use consistent full-color styling across all themes
- Check App Version and DNS Check jobs now properly displayed in Status page
- Simplified function signatures by removing redundant description parameters

---

## [1.4.7] - 2026-01-06

### Added

#### Domains Management Feature
- **Complete Domains Manager**: New comprehensive interface for Viewing Mailcow domains
  - Real-time DNS security validation (SPF, DKIM, DMARC)
  - Summary statistics dashboard (Total, Active, Inactive domains)
  - Search and filter functionality

#### Domain Information Display
- **Core Statistics**:
  - Mailboxes: used/max with available count
  - Aliases: used/max with available count
  - Storage: used/max (or unlimited)
  - Total message count
  - Created date
  
- **Relay Configuration**:
  - Backup MX status (`backupmx`)
  - Relay All Recipients status (`relay_all_recipients`)
  - Relay Unknown Only status (`relay_unknown_only`)

#### DNS Security Validation
- **Automated DNS Checks**:
  - **SPF (Sender Policy Framework)**:
    - Detects all policy types: `-all`, `~all`, `?all`, `+all`, and missing `all`
    - Color-coded status indicators
    - Policy-specific recommendations
  - **DKIM (DomainKeys Identified Mail)**:
    - Fetches configuration from Mailcow API
    - Queries DNS for actual DKIM record
    - Compares expected vs actual records
  - **DMARC (Domain-based Message Authentication)**:
    - Checks for existence at `_dmarc.domain.com`
    - Validates policy (p=reject/quarantine/none)
    - Recommendations for stricter policy

- **DNS Status Indicators**:
  - Color-coded icons: ✓ (green), ⚠ (amber), ✗ (red), ? (gray)

### Changed

#### Quarantine Page Enhancement
- **UI Redesign**: Completely redesigned Quarantine page to match Messages page layout and design
  - Changed from basic card layout to professional grid-based design
  - Added sender → recipient display with visual arrow indicator
  - Improved visual hierarchy with better spacing and organization
  - Added hover effects for better interactivity
  - Fully responsive design for mobile and desktop
  - Complete dark mode support

- **Additional Information Display**: Enhanced Quarantine page to show more useful information
  - **Recipient (rcpt)**: Now displayed next to sender with arrow (→) separator
  - **Spam Score**: Displayed in metadata row with red highlighting for scores >= 15
  - **Virus Flag**: Purple badge with 🦠 emoji appears when virus is detected
  - **Queue ID (qid)**: Displayed in metadata row for reference
  - **Action Badge**: Action (reject/quarantine) now shown as colored badge instead of plain text
  - **Result Count**: Added total count display in page header (e.g., "Quarantined Messages (3 results)")

### Fixed

#### Quarantine Timestamp Display
- **Timestamp Formatting**: Fixed timestamp display in Quarantine page to be consistent with other pages
  - Quarantine timestamps now properly formatted with UTC timezone indicator ('Z' suffix)
  - Backend endpoint `/api/quarantine` now processes timestamps before returning to frontend

### Technical

#### Backend (`domains.py`)
- **New API Router**: `/api/domains` endpoint
- **DNS Validation Functions**:
  - `check_spf_record()`: Enhanced SPF validation with comprehensive policy detection
  - `check_dkim_record()`: DKIM validation with flexible API response handling
  - `check_dmarc_record()`: DMARC validation with policy checking
- **Async Operations**: All DNS queries use async resolver for better performance
- **Error Handling**: Comprehensive try-except blocks with detailed logging

---

## [1.4.6] - 2026-01-05

### Added

#### Version Check Improvements
- **Periodic Version Check**: Version check now runs automatically every 6 hours (instead of only on container startup)
  - Background scheduler job checks for app updates from GitHub
  - Runs immediately on startup, then every 6 hours

- **Manual Version Check Button**: Added "Check Now" button in Settings page
  - Located next to "Latest Version" badge
  - Allows users to manually trigger version check at any time

#### Settings Page Enhancements
- **Version Information Improvements**:
  - Added last checked date display next to "Latest Version" in Settings page
  - Added clickable version number (Current Version) to view changelog in popup modal
  - Added changelog display in update notification area

- **Mailcow Connection Indicator**: Added connection status indicator in header next to application name
  - Green checkmark when connected to Mailcow
  - Red X when not connected
  - Status updates automatically via `/api/status/mailcow-connection` endpoint

### Changed

#### Version Check Behavior
- **Background Updates**: Version check endpoint now supports `force` parameter to bypass cache
- **UI Updates**: Version information updates in real-time without page refresh
  - Latest version display updates immediately
  - Badge status ("Update Available" / "Up to Date") updates dynamically
  - Update notification message appears/disappears based on check results

#### Settings Page Performance
- **Faster Loading**: Optimized Settings page loading time
  - Page now displays immediately with cached version info
  - Version information updates in background without blocking page display

#### Footer Updates
- **Update Available Button**: Made "Update Available" badge in footer clickable
  - Clicking the badge navigates to Settings page
  - Improved user experience for accessing update information

#### Timezone Handling
- **Consistent Timezone Display**: Fixed timezone handling across all endpoints
  - All timestamps now sent with UTC timezone indicator ('Z' suffix)
  - Time display respects timezone from ENV configuration (TZ variable)
  - Removed hardcoded locale preferences, uses browser's local settings

### Fixed

#### Security Tab
- **Unban Filter Accuracy**: Fixed Unban filter displaying Info results
  - Unban filter now only shows actual unban actions (not all info logs)
  - Removed backward compatibility code that incorrectly included all 'info' results
  - Added separate "Info" filter option in Netfilter action dropdown
  - Users can now filter by Info separately from Unban actions

---

## [1.4.5] - 2026-01-04

### Added

#### Version Check Improvements
- **Periodic Version Check**: Version check now runs automatically every 6 hours (instead of only on container startup)
  - Background scheduler job checks for app updates from GitHub
  - Runs immediately on startup, then every 6 hours
  - Ensures version information stays up-to-date without manual intervention
  - Version check job appears in Status page

- **Manual Version Check Button**: Added "Check Now" button in Settings page
  - Located next to "Latest Version" badge
  - Allows users to manually trigger version check at any time

### Changed

#### Version Check Behavior
- **Background Updates**: Version check endpoint now supports `force` parameter to bypass cache
- **UI Updates**: Version information updates in real-time without page refresh
  - Latest version display updates immediately
  - Badge status ("Update Available" / "Up to Date") updates dynamically
  - Update notification message appears/disappears based on check results

---

## [1.4.4] - 2026-01-04

### Added

#### Email Direction Detection
- **Internal Email Detection**: Added new "internal" direction for emails delivered locally
  - Internal emails require ALL of the following conditions:
    - `relay=dovecot` in Postfix logs (indicates local delivery)
    - Sender domain is in local domains list
    - Recipient domain(s) are in local domains list
  - Prevents inbound emails from external domains being incorrectly marked as internal
  - More accurate than domain-only detection (handles cases where domain mailboxes exist on different servers)
  - Direction is determined after Postfix logs are available (not during initial import)
  - Added "Internal" option to direction filter in Messages page
  - Internal direction displayed with green badge in UI
  - Backend API now tracks internal statistics (`internal_24h` in dashboard stats endpoint)

#### Background Jobs
- **Final Status Update Job**: Added new background job to update final status for correlations
  - Handles cases where Postfix logs arrive after initial correlation
  - Runs at `CORRELATION_CHECK_INTERVAL` frequency (default: 120 seconds)
  - Only checks correlations within `MAX_CORRELATION_AGE_MINUTES` window
  - Prevents emails from remaining without final status when logs arrive late
  - Job appears in Status page with pending items count
  - Respects correlation age limits to avoid infinite checking

### Fixed

#### Messages Page
- **Auto-Refresh Behavior**: Fixed auto-refresh disrupting user's search and pagination
  - Auto-refresh now skips when user has active search or filters
  - Auto-refresh skips when user is not on first page
  - Prevents results from changing while user is browsing/searching
  - Only refreshes when viewing default first page with no filters

- **Spam Filter**: Fixed spam filter not showing results
  - Spam filter now checks both `final_status='spam'` and `is_spam=True` from Rspamd
  - Previously only checked `final_status`, missing emails marked as spam by Rspamd but delivered
  - Now correctly shows all spam emails regardless of delivery status

#### Message Correlation & Display
- **Missing Postfix Logs**: Fixed issue where Postfix logs weren't displayed in Logs tab after correlation was marked complete
  - Now queries all Postfix logs with matching `queue_id` directly from database
  - Ensures all logs are displayed even if they arrive after correlation is marked complete
  - Applied fix to both `/api/message/{correlation_key}/details` and `/api/logs/message/{correlation_key}` endpoints

- **Security Tab Events**: Fixed Security tab in Message Details not showing events from sender's IP address
  - Now uses IP address from Rspamd log to fetch all Netfilter security events for that IP
  - Removed time window restrictions - shows all security events for the sender's IP
  - Displays up to 100 most recent security events to avoid overwhelming the UI

#### UI Improvements
- **Email Subject Truncation**: Fixed long email subjects pushing status indicators off-screen
  - Changed Messages page layout from flex to grid for better control
  - Applied fix to both main Messages page and Recent Activity on Dashboard

- **Email Address Display**: Fixed email addresses with `+` (plus signs) being truncated
  - In Logs tab: Now uses recipients from Postfix logs (which include full addresses with `+`)
  - In Overview tab: Prioritizes recipients from Postfix logs over correlation recipients
  - Postfix logs contain complete addresses while Rspamd may truncate them
  - Fallback to correlation recipients if Postfix logs unavailable

- **Mail Details Display**: Replaced "Total Delay" with "Relay" in Logs tab Mail Details section
  - Relay information is more useful for troubleshooting delivery issues
  - Shows the server where email was delivered (e.g., `dovecot` for local delivery)

- **Message Details Modal Layout**: Improved Overview tab layout for better space utilization
  - Removed "First Seen" field (redundant information)
  - Reduced spacing between sections for more compact display
  - "Additional Details" section always visible at bottom (no scrolling needed)

- **Correlation Status Display**: Simplified status badge in Messages page
  - Changed from "[OK] Linked" / "[...] Pending" to single status badge with emoji
  - Displays email delivery status: ✓ Delivered, ↩ Bounced, ✗ Rejected, ⏳ Deferred, ⚠ Spam, ⏸ Expired
  - If email has final status (delivered/bounced/etc), shows that status
  - If correlation is complete but no final status yet, shows "✓ Linked"
  - If correlation is incomplete (waiting for Postfix logs), shows "⏳ Pending"
  - Removed separate "final_status" badge (now combined into single status indicator)

### Changed

#### Security Tab
- **Result Count Display**: Fixed incorrect result count in Security tab header
  - Resolves issue where count showed only items on current page instead of total results
  
- **Banning/Unbanning Event Classification**: Fixed incorrect categorization of security events
  - "Unbanning" events were incorrectly classified as "banned" instead of "unban"
  - "Banning" events now correctly classified as "ban" (instead of "banned")
  - Improved detection logic using word boundaries to prevent false matches (e.g., "unbanning" containing "banning")
  - Unbanning events now properly displayed with green "UNBAN" badge
  - Banning events now properly displayed with red "BAN" badge
  - Replaced single "Banned" option with distinct "BAN" and "UNBAN" filters

---

## [1.4.3] - 2026-01-01

### Changed

#### Configuration
- **Automatic Domain Detection**: Removed `MAILCOW_LOCAL_DOMAINS` environment variable requirement
  - Active domains are now automatically fetched from Mailcow API (`/api/v1/get/domain/all`)
  - Only active domains are used
  - Domains are cached on application startup
  - No manual domain configuration needed anymore

#### UI Improvements
- **Local Domains Display**: Enhanced domains display in Settings page
  - Changed from comma-separated list to grid layout (columns)
  - Scrollable container for many domains

#### Code Quality
- **Code Cleanup**: Removed unnecessary comments from codebase
  - Removed verbose comments that don't add value
  - Cleaned up phase markers and redundant inline comments
  - Improved code readability

### Fixed

#### Security Tab
- **Timestamp Formatting**: Fixed timestamp display in Security tab to match Messages page format
  - All timestamps now properly formatted with UTC timezone ('Z' suffix)
  - Consistent date/time display across all tabs
- **Banned Filter**: Fixed filter not working correctly for "Banning" messages
  - Now correctly identifies "Banning" (present tense) messages as banned actions
  - Uses priority field ("crit") to determine ban status when message parsing is ambiguous
  - Added support for CIDR notation in ban messages (e.g., "Banning 3.134.148.0/24")
- **View Consistency**: Removed old table view that was sometimes displayed
  - Only card-based view is now used consistently
  - Smart refresh now uses same rendering function as initial load
- **Duplicate Log Prevention**: Fixed duplicate security events appearing in Security tab
  - Added deduplication logic based on message + time + priority combination
  - Frontend filters duplicates before display (handles legacy data)
  - Backend import now checks database for existing logs with same message + time + priority before inserting
  - Prevents duplicate entries from being stored in database during import

#### Import Status
- **Last Fetch Run Time**: Added tracking of when imports run (not just when data is imported)
  - Status page now shows "Last Fetch Run" (when import job ran) separate from "Last Import" (when data was actually imported)
  - Resolves confusion when imports run but no new logs are available
  - All three log types (Postfix, Rspamd, Netfilter) now track fetch run times

#### Netfilter Logging
- **Enhanced Logging**: Added detailed debug logs for Netfilter import process
  - Logs show when fetch starts, how many logs received, how many imported, and how many skipped as duplicates
  - Better error tracking for troubleshooting import delays
- **Import Deduplication**: Improved duplicate detection during Netfilter log import
  - Now checks database for existing logs with same message + time + priority before inserting
  - Uses combination of message + time + priority as unique identifier (instead of time + IP + message)
  - Prevents duplicate entries from being stored in database

### Added

#### Version Management
- **VERSION File**: Version number now managed in single `VERSION` file instead of hardcoded in multiple places
  - Supports both Docker and development environments

#### Footer
- **Application Footer**: Added footer to all pages with:
  - Application name and current version
  - "Update Available" badge when new version is detected

#### Settings Page
- **Version Information Section**: Added version display in Settings page
  - Shows current installed version
  - Shows latest available version from GitHub
  - Displays "Update Available" or "Up to Date" status
  - Link to release notes when update is available

---

## [1.4.2] - 2025-12-31

### Fixed

#### Authentication
- **Login Page Visibility**: Login page now automatically redirects to main app when authentication is disabled
  - When `AUTH_ENABLED=false`, users are no longer shown the login page
  - Direct access to main application without authentication check
  - Logout button is hidden when authentication is disabled

---

## [1.4.0] - 2025-12-31

### Added

#### Security
- **Built-in HTTP Basic Authentication**: Optional authentication system to protect all pages and API endpoints
  - Dedicated login page (`/login`) with modern UI and dark mode support
  - Credentials stored in browser session storage (cleared on browser close)
  - Automatic redirect to login when authentication required
  - All API endpoints protected when authentication is enabled
  - Health check endpoint (`/api/health`) remains accessible for Docker monitoring
  - Logout functionality with automatic redirect to login
- **Authentication Configuration**: New environment variables:
  - `AUTH_ENABLED` (default: false) - Enable/disable authentication
  - `AUTH_USERNAME` (default: admin) - Authentication username
  - `AUTH_PASSWORD` (required if enabled) - Authentication password
- **Settings Page Enhancement**: Authentication status now displayed in Settings page with visual indicator (enabled/disabled badge)

### Changed

#### Documentation
- Updated README.md with comprehensive authentication documentation
- Updated GETTING_STARTED.md with authentication setup instructions
- Added authentication information to Settings page display

### Fixed

#### Infrastructure
- **Docker Healthcheck**: Health check endpoint now accessible without authentication to allow Docker health monitoring
- **Multi-Platform Docker Images**: Docker images now support both AMD64 and ARM64 architectures
  - Images automatically work on Raspberry Pi and other ARM-based devices

### Technical

#### New Configuration Options
```env
# Authentication (optional)
AUTH_ENABLED=false
AUTH_USERNAME=admin
AUTH_PASSWORD=
```

#### API Changes
- `GET /login` - New login page endpoint (public access)
- `GET /api/settings/info` - Now returns authentication status and username

#### Frontend Changes
- Created dedicated `login.html` page with authentication form
- Added authentication state management in JavaScript
- All API calls now use `authenticatedFetch()` wrapper
- Automatic redirect to login page when authentication required
- Logout functionality redirects to login page
- Login page supports dark mode with automatic theme detection

#### Backend Changes
- Added `BasicAuthMiddleware` for global authentication enforcement
- Created `/login` endpoint for login page
- Modified root endpoint to allow access (JavaScript handles redirect)
- Health check endpoint excluded from authentication requirements

#### Infrastructure Changes
- **GitHub Actions Workflow**: Updated Docker build to support multi-platform (linux/amd64, linux/arm64)
- **Docker Image Tagging**: Simplified tagging strategy - only `latest` and version tags (removed `main` tag)
- Docker images now built for both x86_64 and ARM64 architectures simultaneously

---

## [1.3.0] - 2025-12-25

### Added

#### UI Enhancements
- **Result Count Display**: Messages, Security, and Queue pages now show total result count in header (e.g., "All Messages (1,234 results)")
- **Delivery Error Summary**: Logs tab now displays prominent error box at top when delivery fails, extracting error reason from "said:" pattern
- **Security Tab Indicator**: Green/red dot indicator showing if there are security events in the last 24 hours
- **Multiple Recipients Display**: Messages with multiple recipients now show all recipients in Overview and Logs tabs
- **Expired Correlations Counter**: Status page shows count of expired (incomplete) correlations

#### New Features
- **Messages CSV Export**: Added missing `/api/export/messages/csv` endpoint with full filtering support
- **Separate Fetch Parameters**: New ENV variables for granular control:
  - `FETCH_COUNT_POSTFIX` (default: 500)
  - `FETCH_COUNT_RSPAMD` (default: 500)
  - `FETCH_COUNT_NETFILTER` (default: 500)
- **Correlation Expiration System**: Correlations older than `MAX_CORRELATION_AGE_MINUTES` marked as "expired" instead of deleted
- **IP/User Search**: Messages page now supports filtering by IP address and authenticated user

#### Backend Improvements
- **Three-Layer Blacklist Protection**: Blacklist filtering at API fetch, database insert, and display levels
- **Separate Correlation Expiration Job**: Dedicated background job for marking old incomplete correlations
- **Startup Cleanup**: Automatic cleanup of blacklisted entries on container start

### Changed

#### UI Reorganization
- **Postfix Tab → Logs Tab**: Renamed for clarity
- **Security Page Overhaul**: Changed from table layout to card-based UI with better visual hierarchy
- **Settings → Status Migration**: Moved system info, import status, and background jobs to Status page
- **Dashboard Quick Search**: Simplified to single search field (removed separate log type selector)
- **Dashboard Statistics**: Now uses MessageCorrelation table for accurate message counts

#### Backend Changes
- **Postfix Log Deduplication**: Main list now groups by Queue-ID, showing one row per message
- **Rspamd Symbol Options**: Now displays symbol options (e.g., RCVD_COUNT shows actual count)
- **Correlation Expiration Logic**: Changed from deletion to "expired" status marking

### Fixed

#### Critical Fixes
- **UniqueViolation Race Condition**: Fixed database race condition when multiple correlations created simultaneously
- **BCC Blacklist Problem**: Fixed issue where BCC copies bypassed blacklist filtering
- **Queue ID Blacklist Filtering**: Now properly filters queue entries by blacklisted sender/recipient
- **Messages Export**: Fixed empty CSV export (endpoint was missing)

#### UI Fixes
- **Timezone Errors**: All timestamps now properly formatted with UTC indicator
- **Dashboard Timestamp Formatting**: Fixed incorrect date display in recent activity
- **Settings Page Timestamps**: Fixed timestamp display in import status section
- **JavaScript Syntax Errors**: Fixed various JS errors that broke page functionality
- **Emoji Cleanup**: Removed emoji characters that caused encoding issues in logs

#### Data Accuracy
- **Incomplete Correlation Cleanup**: Fixed correlations stuck in incomplete state
- **Postfix Logs Display**: Fixed cases where Postfix logs weren't showing in message details
- **Duplicate Prevention**: Enhanced deduplication in both correlation and display layers

### Technical

#### New Configuration Options
```env
# Separate fetch counts per log type
FETCH_COUNT_POSTFIX=500
FETCH_COUNT_RSPAMD=500
FETCH_COUNT_NETFILTER=500

# Correlation expiration (minutes)
MAX_CORRELATION_AGE_MINUTES=10

# Correlation check interval (seconds)
CORRELATION_CHECK_INTERVAL=120
```

#### Database Changes
- Added `is_expired` field to MessageCorrelation model
- Added indexes for IP and user queries on RspamdLog

#### API Changes
- `GET /api/export/messages/csv` - New endpoint for messages export
- `GET /api/messages` - Added `ip` and `user` query parameters
- `GET /api/stats/dashboard` - Now returns accurate counts from correlations

---

## [1.2.0] - 2025-12-22

### Fixed
- **CRITICAL: Rspamd-Postfix Correlation**
  - Postfix logs now visible in message details
  - Rspamd logs now correctly find and join Postfix correlations
  - Fixed: Rspamd doesn't have Queue-ID, must search Postfix to find it

### Changed
- `correlate_rspamd_log()` - Complete rewrite
  - Now searches Postfix logs to find Queue-ID
  - Method 1: Search by message-id → get Queue-ID from Postfix
  - Method 2: Search by sender+recipient+time → get Queue-ID from Postfix
  - Then attaches to correlation with that Queue-ID

### Technical
- Rspamd logs now actively query Postfix logs table
- Queue-ID extracted from matching Postfix log
- Correlation found/created with that Queue-ID
- Ensures Rspamd and Postfix logs are properly linked

## [1.1.1] - 2025-12-22

### Fixed
- **CRITICAL: Correlation Logic Completely Rewritten**
  - Queue-ID is now the PRIMARY correlation key (not secondary!)
  - Message-ID moved to fallback (only used if no Queue-ID)
  - Fixes cases where messages still appeared as duplicates even after v1.1.0
  - Resolves issue where message-id log line and delivery log lines created separate correlations

### Changed
- `correlate_postfix_log()` - Complete rewrite of priority logic
- Queue-ID now checked FIRST and returns immediately if found
- Message-ID and sender+recipient+time are now pure fallbacks

### Technical
- Old: Message-ID → Queue-ID → fallback
- New: Queue-ID → Message-ID (fallback) → sender+recipient+time (fallback)
- Reason: Queue-ID is the definitive Postfix identifier for a message

## [1.1.0] - 2025-12-22

### Fixed
- **Duplicate Message Entries**: Single emails no longer appear multiple times in Messages view
  - Issue occurred when emails were sent to multiple recipients
  - Each Postfix delivery log was creating a separate correlation
  - Now all deliveries with same Queue-ID correctly attach to single correlation

### Added
- Automatic database migration system
- `migrations.py` module for database maintenance tasks
- Automatic duplicate correlation cleanup on startup
- Migration runs seamlessly without user intervention

### Changed
- Improved Queue-ID correlation logic in `correlate_postfix_log()`
- When Queue-ID exists but no correlation found, immediately creates new correlation with that Queue-ID
- Prevents fallback to methods that could create duplicates
- All documentation now in English only

### Performance
- Migration adds <5 seconds to startup time (one-time per container lifecycle)
- Improved query performance due to fewer duplicate records
- No ongoing performance penalty

## [1.0.0] - 2025-12-17

### Added
- Initial release of Mailcow Logs Viewer
- Dashboard with real-time statistics
- Postfix log viewing and search
- Rspamd spam analysis with direction detection (inbound/outbound)
- Netfilter authentication failure tracking
- Real-time mail queue monitoring
- Real-time quarantine monitoring
- Message correlation across different log sources
- CSV export functionality for all log types
- Background scheduler for periodic log fetching
- Automatic log cleanup based on retention policy
- Pagination for large datasets
- Docker Compose setup with PostgreSQL
- Traefik integration support
- Health check endpoints
- API documentation

### Features
- **Log Collection**: Automatically fetches logs from Mailcow API
- **Smart Correlation**: Links related logs based on message id
- **Direction Detection**: Accurately detects inbound vs outbound emails
- **Duplicate Prevention**: Avoids storing duplicate log entries
- **Search & Filter**: Advanced filtering across all log types
- **Statistics**: Dashboard with 24h/7d/30d metrics
- **Export**: CSV export with applied filters
- **Auto-cleanup**: Removes old logs based on retention policy
- **Responsive UI**: Modern interface built with Tailwind CSS

### Technical
- Python 3.11 + FastAPI backend
- PostgreSQL 15 for data storage
- SQLAlchemy ORM with JSONB support
- APScheduler for background jobs
- Retry logic with exponential backoff
- Comprehensive error handling
- Structured logging
- Docker containerization

### Configuration
- Environment-based configuration
- Configurable fetch interval
- Configurable retention period
- Configurable local domains
- Timezone support
- Debug mode

### Documentation
- Comprehensive README
- Quick start guide
- Project structure documentation
- API documentation
- Deployment guide
- Troubleshooting guide

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for information on how to contribute to this project.

## Support

For issues, questions, or feature requests, please open an issue on GitHub.