# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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