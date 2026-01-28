# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
```

#### New Environment Variables
- `DMARC_ALLOW_REPORT_DELETE`: Enable/disable report deletion from UI (default: false)
- `BLACKLIST_ALERT_EMAIL`: Email address for blacklist alerts (optional, uses `ADMIN_EMAIL` if not set)

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