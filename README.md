# mailcow Logs Viewer

A modern, self-hosted dashboard for monitoring, analyzing, and managing your mailcow mail server. Track email delivery, investigate spam, manage quarantine, detect bounce-based abuse, and validate DNS configurations — all from a single interface.

![Main](images/Main.png)

![Messages](images/Messages.png)

![Message Details](images/Message_Details_Overview.png)

![Message Logs](images/Message_Details_Logs.png)

![Rate Limits](images/Rate_Limits.png)

![Security](images/Security.png)

![Domains](images/Domains.png)

![Status](images/Status.png)

---

## Features

### 📊 Dashboard
- Real-time statistics (24h / 7d / 30d) — messages, spam, bounces, auth failures
- Container status overview and storage usage
- Quick search across all logs and recent activity stream

### 📬 Messages
- Unified view combining Postfix + Rspamd data with smart correlation
- Direction detection (Inbound / Outbound / Internal)
- Status tracking: delivered, bounced, deferred, expired, spam
- Filter by sender, recipient, user, IP, direction
- CSV export, result count display, smart auto-refresh

### 📋 Message Details
- **Overview**: Message summary with all recipients
- **Logs**: Postfix delivery timeline with error summary and relay info
- **Spam Analysis**: Full Rspamd symbols with scores and descriptions
- **Security**: Netfilter events for the sender's IP

### 🔒 Security (Netfilter)
- Failed authentication attempts with IP, username, method, and action
- Security events chart — bans, unbans, and warnings per country
- Fail2Ban management — ban/unban IPs directly (requires RW API key)
- GeoIP enrichment with country flags and ASN info
- Red indicator on tab when 24h activity exists

### 📮 Queue
- Real-time mail queue from mailcow API
- Deferred messages with failure reasons
- **Suppress button** — quick-add any recipient to the suppression list
- Bulk queue operations (delete items, requires RW API key)

### 🛡️ Quarantine
- View quarantined emails with spam scores and quarantine reasons
- **Release / Delete** individual or bulk items
- **Auto-Rules** — automatically release or delete quarantine items based on matching rules
  - Match by Sender, Sender Domain, Recipient, or Subject
  - Exact Match, Contains, and Regex match modes
  - Dry-run testing, action history log, safety limits
  - Inline rule creation from any quarantine email (pre-filled)

### 🚫 Spam Filter — Suppressions & Rspamd Maps
- **Email Suppression List** — automatically block recipients that bounce
  - Hard bounces (5.x.x) detected from Postfix logs
  - Deferred queue cleanup — scans live queue for stuck emails and auto-cleans
  - Progressive blocking with immediate Rspamd sync
  - Manual management, import/export CSV, domain regex support
- **Rspamd Maps Editor** — direct editor for all 13 Rspamd map files
  - Built-in Regex Wizard for email, domain, TLD, and keyword patterns
  - Pattern validation before saving

### 🌐 Domains
- DNS validation for SPF, DKIM, and DMARC with actionable recommendations
- SPF: DNS lookup counter + server IP authorization check
- DKIM: key validation with mailcow configuration comparison
- DMARC: policy analysis with enforcement level recommendations
- Automated DNS checks every 6 hours
- Domain info: mailboxes, aliases, storage, relay settings

### 📊 Mailbox Statistics
- Per-mailbox message stats: sent, received, failed, failure rate
- Per-alias statistics with message counts
- Quota usage, login times, rate limits
- Sorting and filtering by date range, domain, activity

### 📧 DMARC Reports
- DMARC/SMTP-TLS report viewer with compliance analysis
- GeoIP enrichment with MaxMind (City + ASN)
- Manual upload (XML, GZ, ZIP) and IMAP auto-import
- Daily aggregation with sync history and error notifications

### 📝 Logs (Raw Log Viewer)
- Live log viewer for all mailcow services via WebSocket
- 10 services: Postfix, Dovecot, Rspamd, SOGo, Netfilter, ACME, API, Autodiscover, Ratelimited, Watchdog
- Real-time streaming with service filtering and search
- Configurable fetch interval and retention

### 📈 Status
- Container states, storage usage, system info
- Background jobs monitoring with status, intervals, and last run times
- Manual job triggers (Run Now)
- Correlation completion rate

### ⚙️ Settings (Web UI)
- **Full settings editor in the browser** — all configuration manageable via UI when enabled
- Organized into tabs: General, Fetch, Alerts, DMARC, Blacklist, Logs, Spam Filter, Quarantine, Authentication
- ENV variable override indicators (ENV always wins over DB)
- Import settings from `.env` file, reset to defaults
- GeoIP setup modal with download progress and health badges

### 🔐 Authentication
- **Basic Auth** — built-in HTTP Basic Authentication
- **OAuth2/OIDC** — supports any standard provider (Mailcow, Keycloak, Auth0, Google, etc.)
- Both methods can be enabled simultaneously

---

## Quick Start

```bash
mkdir mailcow-logs-viewer && cd mailcow-logs-viewer

# Download docker-compose.yml and env.example
# Configure .env with your mailcow details

docker compose up -d
# Open http://localhost:8080
```

> **Image tags:** use `latest` (or a version tag like `2.7.1`). A `dev` tag also exists on the registries; it is an untested preview built between releases - do not run it on a production server.

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

All settings via environment variables or the **web UI** (when `SETTINGS_EDIT_VIA_UI_ENABLED=true`).

### Required Settings

| Variable | Description |
|----------|-------------|
| `MAILCOW_URL` | mailcow instance URL |
| `MAILCOW_API_KEY` | mailcow Read-Only API key |
| `POSTGRES_PASSWORD` | Database password |

### Key Optional Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `MAILCOW_API_KEY_RW` | (empty) | Read-Write API key — enables edit features (Fail2Ban, Queue, Quarantine, Rspamd sync) |
| `FETCH_INTERVAL` | `60` | Seconds between log fetches |
| `RETENTION_DAYS` | `7` | Days to keep logs |
| `RSPAMD_PASSWORD` | (empty) | Rspamd password — enables Spam Filter maps editor |
| `SUPPRESSION_ENABLED` | `true` | Enable automatic email suppression |
| `BASIC_AUTH_ENABLED` | `true` | Enable HTTP Basic Authentication |
| `SETTINGS_EDIT_VIA_UI_ENABLED` | `true` | Allow managing settings from the web UI |
| `TZ` | `UTC` | Timezone |

📖 **Full reference:** [ENV Settings](documentation/ENV_Settings.md)

---

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](documentation/GETTING_STARTED.md) | Installation and setup guide |
| [ENV Settings](documentation/ENV_Settings.md) | Complete environment variables reference |
| [API Documentation](documentation/API.md) | REST API reference |
| [Settings UI](documentation/Settings_UI.md) | Web-based settings editor guide |
| [OAuth2 Configuration](documentation/OAuth2_Configuration.md) | OAuth2/OIDC setup guide |
| [Reverse Proxy](documentation/Reverse_Proxy.md) | Serving the viewer over HTTPS, including mailcow's own nginx |
| [Upgrade to V2](documentation/UpdateV2.md) | Migration guide from V1 |
| [Changelog](CHANGELOG.md) | Version history |

---

## Requirements

- Docker & Docker Compose
- mailcow with API access
- 512MB RAM minimum
- 1GB disk (varies with retention)

---

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