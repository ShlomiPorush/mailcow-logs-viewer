# mailcow Logs Viewer

A modern, self-hosted dashboard for viewing and analyzing mailcow mail server logs. Built for system administrators and technicians who need quick access to mail delivery status, spam analysis, and authentication failures.

![Main](images/Main.png)

![Messages](images/Messages.png)

![Message Details](images/Message_Details_Overview.png)

![Message Logs](images/Message_Details_Logs.png)

![Security](images/Security.png)

![Domains](images/Domains.png)

![Status](images/Status.png)

---

## Features

### 📊 Dashboard
- Real-time statistics (24h / 7d / 30d)
- Messages, spam, failed deliveries, auth failures, internal emails counts
- Container status overview
- Storage usage with visual indicator
- Quick search across all logs
- Recent activity stream

### 📬 Messages
- Unified view combining Postfix + Rspamd data
- Smart correlation linking related logs
- Multiple recipients display per email
- Direction detection (Inbound/Outbound/Internal)
- Internal email detection (local delivery with relay=dovecot)
- Status tracking (delivered, bounced, deferred, expired, spam)
- Filter by sender, recipient, user, IP, direction
- Result count display
- CSV export
- Smart auto-refresh (skips when searching/filtering)

### 📋 Message Details Modal
- **Overview tab**: Message summary with all recipients (includes addresses with `+` signs)
- **Logs tab**: Complete Postfix delivery timeline with error summary and relay information
- **Spam Analysis tab**: Full Rspamd symbols with scores and descriptions
- **Security tab**: All Netfilter security events for sender's IP address (up to 100 most recent)

### 🔒 Security (Netfilter)
- Failed authentication attempts
- Card-based UI with IP, username, method, action
- Attempt counts and timestamps
- 🔴 Visual indicator in tab when 24h activity exists
- Filter by IP, username, action

### 📮 Queue & Quarantine
- Real-time mail queue from mailcow API
- Deferred messages with reasons
- Quarantined emails
- Search and filter

### 🌐 Domains Overview
- Complete domains overview with DNS validation
- SPF validation with DNS lookup counter and server IP authorization check
- DKIM validation with mailcow configuration comparison
- DMARC policy checking and recommendations
- Automated DNS checks every 6 hours
- Domain info: mailboxes, aliases, storage, relay settings
- Color-coded status indicators (✓ green, ⚠ amber, ✗ red)

### 📊 Mailbox Statistics
- Per-mailbox message statistics (sent, received, failed, failure rate)
- Accordion-style mailbox list with expandable details
- Per-alias statistics with message counts
- Quota usage, login times, rate limits
- Filtering by date range, domain, search, active only, hide zero activity
- Sorting by sent, received, failure rate, quota, username

### 📧 DMARC Reports
- DMARC report viewing and analysis
- GeoIP enrichment with MaxMind (City + ASN)
- Daily aggregated reports with compliance rates
- Manual upload (XML, GZ, ZIP formats)
- IMAP auto-import with configurable sync interval
- Sync history tracking with error notifications

### 📈 Status
- All container states (running/stopped count)
- Storage usage with percentage bar
- System info (domains, mailboxes, aliases)
- Import status per log type
- Background jobs status
- Correlation completion rate
- Expired correlations counter

### ⚙️ Additional
- 🔐 Built-in Basic Authentication
- 🌙 Dark mode
- 📱 Responsive design
- 🔄 Smart auto-refresh (respects user activity)
- 📥 CSV export for all log types
- 🚫 Email blacklist (hide specific addresses from display)
- 🧹 Automatic old log cleanup
- ⏰ Correlation expiration (marks old incomplete correlations)
- 🔄 Background jobs for correlation status updates

---

## Quick Start

```bash
mkdir mailcow-logs-viewer && cd mailcow-logs-viewer

# Download docker-compose.yml and env.example
# Configure .env with your mailcow details

docker compose up -d
# Open http://localhost:8080
```

📖 **Full installation guide:** [Getting Started](documentation/GETTING_STARTED.md)

📘 **Technical Overview: Email Authentication & Monitoring:** How can **mailcow-logs-viewer** help you with this [Read more](documentation/Email_Authentication_Monitoring.md)

---

## Architecture

| Component | Technology |
|-----------|------------|
| Backend | Python 3.11 + FastAPI |
| Database | PostgreSQL 15 |
| Frontend | HTML/JS + Tailwind CSS |
| Scheduler | APScheduler |

---

## Configuration

All settings via environment variables. See **[env.example](env.example)** for full reference.

### Required Settings

| Variable | Description |
|----------|-------------|
| `MAILCOW_URL` | mailcow instance URL |
| `MAILCOW_API_KEY` | mailcow API key |
| `POSTGRES_PASSWORD` | Database password |

### Key Optional Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `FETCH_INTERVAL` | `60` | Seconds between log fetches |
| `FETCH_COUNT_POSTFIX` | `2000` | Postfix records per fetch |
| `FETCH_COUNT_RSPAMD` | `500` | Rspamd records per fetch |
| `RETENTION_DAYS` | `7` | Days to keep logs |
| `BLACKLIST_EMAILS` | (empty) | Emails to hide from display |
| `TZ` | `UTC` | Timezone |
| `AUTH_ENABLED` | `false` | Enable HTTP Basic Authentication |
| `AUTH_USERNAME` | `admin` | Authentication username |
| `AUTH_PASSWORD` | (empty) | Authentication password (required if enabled) |

---

## API

RESTful API for all functionality:

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Health check |
| `GET /api/messages` | Unified messages with filters |
| `GET /api/message/{key}/details` | Full message details |
| `GET /api/logs/postfix` | Postfix logs |
| `GET /api/logs/rspamd` | Rspamd logs |
| `GET /api/logs/netfilter` | Netfilter logs |
| `GET /api/stats/dashboard` | Dashboard statistics |
| `GET /api/status/summary` | System status |
| `GET /api/export/{type}/csv` | CSV export |

📖 **Full API reference:** [API Documentation](documentation/API.md)

---

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](documentation/GETTING_STARTED.md) | Installation guide |
| [API Documentation](documentation/API.md) | API reference |
| [Changelog](CHANGELOG.md) | Version history |
| [env.example](env.example) | Configuration options |

---

## Requirements

- Docker & Docker Compose
- mailcow with API access
- 512MB RAM minimum
- 1GB disk (varies with retention)

---

## Rate Limiting

Currently, there is no rate limiting implemented. For production deployments, consider adding rate limiting via a reverse proxy (e.g., Traefik, Nginx).

---

## Authentication

The application supports built-in HTTP Basic Authentication to protect all pages and API endpoints.

### Enabling Authentication

Add the following to your `.env` file:

```env
AUTH_ENABLED=true
AUTH_USERNAME=your_username
AUTH_PASSWORD=your_secure_password
```

### How It Works

- When authentication is enabled, all pages and API endpoints require valid credentials
- Users are redirected to a dedicated login page (`/login`) if not authenticated
- Credentials are stored in browser session storage (cleared when browser closes)
- The main application page is only accessible after successful authentication
- All API requests automatically include authentication headers

### Security Notes

- Use strong passwords in production
- Credentials are transmitted using HTTP Basic Auth (Base64 encoded)
- For production deployments over the internet, use HTTPS
- Consider using a reverse proxy with additional security layers (rate limiting, IP whitelisting, etc.)

---

## Notes

1. **Timestamps**: All timestamps are returned in ISO 8601 format with UTC timezone (suffix `Z`)
2. **Pagination**: Most list endpoints support `page` and `limit` parameters
3. **Filtering**: Filters are applied server-side before pagination
4. **Export Limits**: CSV exports are limited to `CSV_EXPORT_LIMIT` rows (default: 10,000)
5. **Real-time Data**: Queue and Quarantine endpoints fetch data directly from mailcow API
6. **Cached Data**: All other log data is stored in PostgreSQL and updated periodically

## License

MIT License

---

## Support

- **Logs**: `docker compose logs app`
- **Health**: `http://localhost:8080/api/health`
- **Issues**: Open issue on GitHub

---

## Credits

* **Flags**: Flag icons are sourced from [Flagpedia.net](https://flagpedia.net/).
* **Location Data**: This product includes GeoLite2 data created by MaxMind, available from [https://www.maxmind.com](https://www.maxmind.com).