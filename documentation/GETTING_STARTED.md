# Mailcow Logs Viewer - Getting Started

Get up and running in 5 minutes! 🚀

## Prerequisites

- Docker & Docker Compose installed
- Mailcow instance with API access
- Mailcow API key (generate from Mailcow admin panel)

---

## Installation

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

**⚠️ You must update these required settings:**

| Variable | Description | Example |
|----------|-------------|---------|
| `MAILCOW_URL` | Your Mailcow instance URL | `https://mail.example.com` |
| `MAILCOW_API_KEY` | Your Mailcow API key | `abc123-def456...` |
| `MAILCOW_LOCAL_DOMAINS` | Your email domains | `example.com,domain.net` |
| `POSTGRES_PASSWORD` | Database password<br>⚠️ Avoid special chars (`@:/?#`) - breaks connection strings<br>💡 Use UUID: Linux/Mac: `uuidgen` <br> or online https://it-tools.tech/uuid-generator  | Example: `a7f3c8e2-4b1d-4f9a-8c3e-7d2f1a9b5e4c` |

**Review all other settings** and adjust as needed for your environment (timezone, fetch intervals, retention period, etc.)

### Step 4: Get Your Mailcow API Key

1. Log in to your Mailcow admin panel
2. Navigate to **System** → **Configuration** → **Access**
3. Extend **API** section
4. Copy & Enable **Read-Only Access**
6. Paste the generated API key to your `.env` file

### Step 5: Configure Postfix (Important!)

For optimal message correlation, add this line to your Postfix configuration:

### Add to `data/conf/postfix/extra.cf`:
```conf
always_add_missing_headers = yes
```

**Why is this needed?**

This ensures Postfix always adds a Message-ID header when missing. The Mailcow Logs Viewer uses Message-ID to correlate:
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
  "version": "1.3.0"
}
```

### Check Logs

```bash
docker compose logs -f app
```

You should see:
```
INFO - Starting Mailcow Logs Viewer
INFO - Database initialized successfully
INFO - Scheduler started
INFO - ✅ Imported 50 Postfix logs
INFO - ✅ Imported 45 Rspamd logs
```

---

## Common Issues

### No logs appearing?

- Wait 1-2 minutes for the first fetch cycle
- Check `FETCH_INTERVAL` in `.env` (default: 60 seconds)
- View logs: `docker compose logs app | grep -i "imported"`

### Cannot connect to Mailcow API?

- Verify `MAILCOW_URL` is correct (no trailing slash)
- Check API key is valid and has read access
- Ensure Mailcow is accessible from the container

### Database connection failed?

- Wait 30 seconds for PostgreSQL to fully start
- Check database password in `.env`
- Restart: `docker compose restart`

### Port 8080 already in use?

Change the port mapping in `docker-compose.yml` and restart:
```bash
docker compose down
docker compose up -d
```

---

### Update Application

```bash
docker compose pull
docker compose up -d
```
---

## Documentation

- **[API Documentation](API.md)** - Full API reference
- **[Changelog](../CHANGELOG.md)** - Version history

---

## Support

**Logs**: `docker compose logs app`  
**Health**: `http://localhost:8080/api/health`  
**Issues**: Open issue on GitHub