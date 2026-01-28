# mailcow Logs Viewer - Getting Started

Get up and running in 5 minutes! 🚀

---

# Quick Start (TL;DR)

## Minimum Required Configuration

```bash
mkdir mailcow-logs-viewer && cd mailcow-logs-viewer
# Download docker-compose.yml and env.example, then:
mv env.example .env
nano .env
```

**Update these required settings in `.env`:**

```env
MAILCOW_URL=https://mail.example.com
MAILCOW_API_KEY=your_api_key_here
POSTGRES_PASSWORD=a7f3c8e2-4b1d-4f9a-8c3e-7d2f1a9b5e4c
ADMIN_EMAIL=admin@yourdomain.com
```

**Start:**
```bash
docker compose up -d
```

**Access:** `http://localhost:8080`

---

## Optional Features (all disabled by default)

Add to your `.env` file to enable:

**MaxMind GeoIP** (geographic location data):
```env
MAXMIND_ACCOUNT_ID=your_id
MAXMIND_LICENSE_KEY=your_key
```

And add data volume in `docker-compose.yml`:
```yaml
services:
  app:
    volumes:
      - ./data:/app/data
```

**SMTP Notifications:**
```env
SMTP_ENABLED=true
SMTP_HOST=smtp.yourdomain.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USER=user
SMTP_PASSWORD=pass
SMTP_FROM=noreply@yourdomain.com
```

**DMARC IMAP Auto-Import:**
```env
DMARC_IMAP_ENABLED=true
DMARC_IMAP_HOST=imap.yourdomain.com
DMARC_IMAP_PORT=993
DMARC_IMAP_USE_SSL=true
DMARC_IMAP_USER=dmarc@yourdomain.com
DMARC_IMAP_PASSWORD=your_password
```

**Authentication:**
```env
AUTH_ENABLED=true
AUTH_USERNAME=your_username
AUTH_PASSWORD=your_secure_password
```

---

# Detailed Installation Guide

## Prerequisites

- Docker & Docker Compose installed
- mailcow instance with API access
- mailcow API key (generate from mailcow admin panel)

---

## Installation Steps

### Step 1: Create Project Directory

```bash
mkdir mailcow-logs-viewer
cd mailcow-logs-viewer
```

### Step 2: Download Configuration Files

Download these two files to your project directory:

- 📄 **[docker-compose.yml](../docker-compose.yml)** - Docker Compose configuration
- 📄 **[env.example](../env.example)** - Environment variables template

Then rename the environment file:

```bash
mv env.example .env
```

### Step 3: Configure Environment

Edit the `.env` file and configure the settings for your environment:

```bash
nano .env
```

#### Required Settings

**⚠️ You must update these settings:**

| Variable | Description | Example |
|----------|-------------|---------|
| `MAILCOW_URL` | Your mailcow instance URL | `https://mail.example.com` |
| `MAILCOW_API_KEY` | Your mailcow API key | `abc123-def456...` |
| `POSTGRES_PASSWORD` | Database password<br>⚠️ Avoid special chars (`@:/?#`) - breaks connection strings<br>💡 Use UUID: `uuidgen` or https://it-tools.tech/uuid-generator | `a7f3c8e2-4b1d-4f9a-8c3e-7d2f1a9b5e4c` |
| `ADMIN_EMAIL` | Admin email for notifications | `admin@yourdomain.com` |

**Review all other settings** and adjust as needed for your environment (timezone, fetch intervals, retention period, etc.)

#### Optional: Enable Authentication

For production deployments, enable HTTP Basic Authentication:

```env
AUTH_ENABLED=true
AUTH_USERNAME=your_username
AUTH_PASSWORD=your_secure_password
```

When enabled:
- All pages and API endpoints require authentication
- Users are redirected to a login page if not authenticated
- Use strong passwords in production
- **Important**: Use HTTPS/TLS when exposing over the internet

### Step 4: Get Your mailcow API Key

1. Log in to your mailcow admin panel
2. Navigate to **System** → **Configuration** → **Access**
3. Extend **API** section
4. Copy & Enable **Read-Only Access**
5. Paste the generated API key to your `.env` file

### Step 5: Configure Postfix (Important!)

For optimal message correlation, add this line to your Postfix configuration:

#### Add to `data/conf/postfix/extra.cf`:
```conf
always_add_missing_headers = yes
```

**Why is this needed?**

This ensures Postfix always adds a Message-ID header when missing. The mailcow Logs Viewer uses Message-ID to correlate:
- Rspamd logs (spam filtering)
- Postfix logs (delivery)
- Netfilter logs (authentication)

Without Message-ID, some messages won't be properly linked between log sources.

### Step 6: Start the Application

```bash
docker compose up -d
```

### Step 7: Access the Dashboard

Open your browser:

```
http://localhost:8080
```

**If authentication is enabled**, you'll be redirected to the login page. Enter your credentials to access the dashboard.

Wait 1-2 minutes for the first logs to appear.

---

## Verify Installation

### Check Application Health

```bash
curl http://localhost:8080/api/health
```

Expected response:
```json
{
  "status": "healthy",
  "database": "connected",
  "version": "2.0.0"
}
```

### Check Logs

```bash
docker compose logs -f app
```

You should see:
```
INFO - Starting mailcow Logs Viewer
INFO - Database initialized successfully
INFO - Scheduler started
INFO - ✅ Imported 50 Postfix logs
INFO - ✅ Imported 45 Rspamd logs
```

---

# Optional Features Configuration

## MaxMind GeoIP Integration

Add geographic location data to your DMARC reports and log analysis.

### Setup Steps:

1. Sign up for a free MaxMind account at [https://www.maxmind.com/](https://www.maxmind.com/)
2. Create a **License Key**
3. Copy your **Account ID** and **License Key**
4. Add the credentials to your `.env` file:

```env
MAXMIND_ACCOUNT_ID=your_account_id
MAXMIND_LICENSE_KEY=your_license_key
```

5. **Map the data volume** in your `docker-compose.yml`:

```yaml
services:
  app:
    # ... other configurations
    volumes:
      - ./data:/app/data
```

> [!NOTE]
> The application will automatically download and update the GeoIP database into this folder using the credentials provided.

**If not configured:** The application works normally without GeoIP data.

---

## SMTP Email Notifications

Configure email notifications for system alerts and DMARC processing errors.

Add to your `.env` file:

```env
SMTP_ENABLED=true
SMTP_HOST=smtp.yourdomain.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USER=your_smtp_user
SMTP_PASSWORD=your_smtp_password
SMTP_FROM=noreply@yourdomain.com
```

**If not configured:** No email notifications will be sent (default: `SMTP_ENABLED=false`).

---

## DMARC Configuration

### Retention Period

Control how long DMARC reports are stored:

```env
DMARC_RETENTION_DAYS=60
```

**Default:** 60 days if not specified.

### Manual Upload

Enable/disable manual DMARC report upload via the web interface:

```env
DMARC_MANUAL_UPLOAD_ENABLED=true
```

**Default:** `true` (enabled).

### IMAP Auto-Import

Automatically fetch DMARC reports from an email inbox:

```env
DMARC_IMAP_ENABLED=true
DMARC_IMAP_HOST=imap.yourdomain.com
DMARC_IMAP_PORT=993
DMARC_IMAP_USE_SSL=true
DMARC_IMAP_USER=dmarc@yourdomain.com
DMARC_IMAP_PASSWORD=your_password
DMARC_IMAP_FOLDER=INBOX
DMARC_IMAP_DELETE_AFTER=true
DMARC_IMAP_INTERVAL=3600
DMARC_IMAP_RUN_ON_STARTUP=true
```

**Configuration options:**
- `DMARC_IMAP_DELETE_AFTER`: Delete emails after processing (default: `true`)
- `DMARC_IMAP_INTERVAL`: Check interval in seconds (default: 3600 = 1 hour)
- `DMARC_IMAP_RUN_ON_STARTUP`: Process existing emails on startup (default: `true`)

**If not configured:** IMAP auto-import remains disabled (default: `DMARC_IMAP_ENABLED=false`).

### DMARC Error Notifications

Override the admin email specifically for DMARC processing errors:

```env
DMARC_ERROR_EMAIL=dmarc-alerts@yourdomain.com
```

**If not configured:** Uses `ADMIN_EMAIL` by default.


---

# Troubleshooting

## Common Issues

### No logs appearing?

- Wait 1-2 minutes for the first fetch cycle
- Check `FETCH_INTERVAL` in `.env` (default: 60 seconds)
- View logs: `docker compose logs app | grep -i "imported"`

### Cannot connect to mailcow API?

- Verify `MAILCOW_URL` is correct (no trailing slash)
- Check API key is valid and has read access
- Ensure mailcow is accessible from the container

### Database connection failed?

- Wait 30 seconds for PostgreSQL to fully start
- Check database password in `.env`
- Restart: `docker compose restart`

### Container won't start?

- Verify `ADMIN_EMAIL` is set
- Check Docker logs: `docker compose logs -f`

### Port 8080 already in use?

Change the port mapping in `docker-compose.yml` and restart:
```bash
docker compose down
docker compose up -d
```

### IMAP not working?

- Verify credentials and connection settings
- Check firewall allows outbound connections to IMAP server
- For Gmail: use App Passwords, not your regular password

### No email notifications?

- Ensure `SMTP_ENABLED=true`
- Verify SMTP credentials and server settings
- Check Docker logs for SMTP errors

---

# Updating the Application

To update to the latest version:

```bash
docker compose pull
docker compose up -d
```

**That's it!** The application will automatically:
- Run database migrations
- Initialize new features
- Apply your configuration

---

## Documentation

- **[API Documentation](API.md)** - Full API reference
- **[Changelog](../CHANGELOG.md)** - Version history

---

## Support

**Logs**: `docker compose logs app`  
**Health**: `http://localhost:8080/api/health`  
**Issues**: Open issue on GitHub

---

## Need Help?

If you encounter any issues, please open an issue on GitHub with:
- Your Docker logs
- Your `.env` configuration (remove sensitive data)
- Description of the problem