# Getting started

mailcow Logs Viewer runs next to your mailcow server in Docker. Docker Compose starts the app and a PostgreSQL database, and the app reads mailcow through the mailcow API.

## Before you start

You need:

- Docker with the Compose plugin.
- Network access from the app to your mailcow server's HTTPS address.
- Admin access to mailcow, to create API keys.
- Outbound DNS for the domain and blocklist checks, and outbound HTTPS for version checks, the in-app help and the optional MaxMind downloads.

The app listens on port `8080`. Keep it on a private network while you set it up. Before you open it to the internet, turn on [sign-in](OAuth2_Configuration.md) and put it behind an [HTTPS reverse proxy](Reverse_Proxy.md).

## 1. Create the mailcow API keys

The app needs a read-only key. A second, read-write key is optional: it is needed only to change things in mailcow from the app (release or delete quarantined mail, act on the queue, ban or unban addresses in Fail2ban, edit rate limits, write Rspamd maps, block abusive senders automatically). You can add it later.

In the mailcow admin interface, open **System** > **Configuration**, then **Access** > **Administrators**, and expand **API**:

1. Under **Read-Only Access**, enter the IP address the app connects from in **Allow API access from these IPs/CIDR network notations**, tick **Activate API** and click **Save changes**. Copy the **API key**.
2. If you want the read-write key now, do the same under **Read-Write Access** and copy that key too.

The allowed IPs must include the address mailcow sees when the app connects, which can differ from the address you expect when both run on one host. If mailcow rejects the key later, check this first.

> [!WARNING]
> The read-write key can change mailcow. Everyone who can sign in to the app can use every action it offers, so give sign-in only to mailcow administrators.

## 2. Download the files

On the Docker host:

```sh
mkdir mailcow-logs-viewer
cd mailcow-logs-viewer
curl -fsSLO https://raw.githubusercontent.com/ShlomiPorush/mailcow-logs-viewer/main/docker-compose.yml
curl -fsSL -o .env https://raw.githubusercontent.com/ShlomiPorush/mailcow-logs-viewer/main/env.example
```

You can also save [docker-compose.yml](../docker-compose.yml) and [env.example](../env.example) by hand and rename `env.example` to `.env`.

<!-- VERIFY: Before publishing v3, confirm that the image referenced by docker-compose.yml contains v3. The latest image can still contain the previous release during development. -->
The Compose file uses `ghcr.io/shlomiporush/mailcow-logs-viewer:latest` and `postgres:15-alpine`. To stay on one release, replace `latest` with that version's tag.

## 3. Set the required values

Open `.env` and set these values:

```dotenv
MAILCOW_URL=https://mail.example.com
MAILCOW_API_KEY=replace-with-read-only-key
POSTGRES_USER=mailcowlogs
POSTGRES_PASSWORD=replace-with-a-random-hex-password
POSTGRES_DB=mailcowlogs
POSTGRES_HOST=db
POSTGRES_PORT=5432
SETTINGS_EDIT_VIA_UI_ENABLED=true
BASIC_AUTH_ENABLED=true
AUTH_USERNAME=admin
AUTH_PASSWORD=replace-with-a-long-random-password
```

If you created the read-write key, add it too:

```dotenv
MAILCOW_API_KEY_RW=replace-with-read-write-key
```

- `MAILCOW_URL` is the address of your mailcow web interface, without a trailing slash.
- Use only letters and digits in `POSTGRES_PASSWORD`, for example the output of `openssl rand -hex 32`. The app puts the password into a database URL as it is, so characters such as `@`, `/` or `:` break the connection.
- `SETTINGS_EDIT_VIA_UI_ENABLED=true` lets you change settings in the app. Without it, every setting comes from `.env` and the Settings page is read-only.
- The three `AUTH` lines turn on sign-in with a username and password. Without any sign-in, anyone who can reach the app can read all mail logs.

## 4. Start the app

From the directory with `docker-compose.yml` and `.env`:

```sh
docker compose up -d
docker compose ps
docker compose logs --tail 100 app
```

Check the health endpoint:

```sh
curl http://localhost:8080/api/health
```

A working app answers with HTTP 200 and `{"status":"healthy","database":"connected"}`. HTTP 503 means the app cannot reach its database. The health check does not test the connection to mailcow.

## 5. Sign in

Open `http://localhost:8080` on the Docker host, or the host's private address from your network. Enter the **Username** and **Password** from `.env` and click **Sign In**. When OAuth2 is set up, the login page also shows a **Login with** button for your provider.

![Login page](../images/docs/getting-started-login-light.webp#gh-light-mode-only)
![Login page](../images/docs/getting-started-login-dark.webp#gh-dark-mode-only)

There is no setup wizard and no separate first administrator account. With no sign-in configured, the Dashboard opens directly and shows a warning banner; see [Using the app](Using_the_App.md#signing-in-and-out).

## 6. Check the first import

1. Open **About** and check that **Database** and **mailcow API** are connected.
2. Open **Status** > **Server** and look at **Log import**.
3. Open **Status** > **Jobs** and check **Fetch Logs** for errors.

The app fetches mail logs every 60 seconds. Mailboxes, domains, DNS checks and blocklist checks run on their own schedules, so some pages fill in later. The app sees only the log history that mailcow still keeps; older logs cannot be recovered.

If you added the read-write key, open **Settings** > **Mailcow** and click **Validate** next to **Read-Write API Key**. The check tells you whether mailcow rejects the key, whether it is a read-only key, or whether mailcow cannot be reached.

## 7. Move settings into the app

1. Open **Settings** and click **Migrate Settings from ENV**, then **Import**. This copies your current configuration into the database. Until you do this, the fields on the Settings page cannot be edited.
2. A variable that is set in `.env` always wins over the value saved in the app, and its field shows **Set by ENV**. To manage a value in the app instead, delete its line from `.env` and run `docker compose up -d`. An empty line such as `SMTP_HOST=` still counts as set.
3. Always keep `MAILCOW_URL`, `MAILCOW_API_KEY`, the `POSTGRES_` values and `SETTINGS_EDIT_VIA_UI_ENABLED=true` in `.env`. The app needs them before it can read the saved settings.

[Settings](HelpDocs/Settings.md) describes every tab and setting.

## 8. Add optional connections

| Connection | Where | What it gives you |
| --- | --- | --- |
| Rspamd password | **Settings** > **Mailcow** | Rspamd maps on the Spam Filter page; editing them also needs the read-write key. Leave **Rspamd URL** empty to reach Rspamd through mailcow's `/rspamd` path. |
| SMTP | **Settings** > **SMTP** | Email alerts, test emails and the weekly summary. |
| Alert destinations | **Settings** > **Notifications** | Alerts in Slack, Discord, Telegram, ntfy, Gotify or a JSON webhook. |
| Report mailbox | **Settings** > **DMARC & TLS IMAP** | Automatic import of DMARC and TLS reports over IMAP. |
| MaxMind | **Settings** > **MaxMind** | Country, city and network for IP addresses. |

Certificate checking for SMTP and IMAP is **Off** by default. Set it to **Automatic** or **On** unless the server uses a self-signed certificate. See [Notifications](Notifications.md) and the [environment variable reference](ENV_Settings.md).

## Optional: give every message a Message-ID

The app joins the Rspamd and Postfix log lines of a message by its Message-ID. When a message arrives without a Message-ID header, its Rspamd result (spam score, symbols) is not attached to it. To make Postfix add the header when it is missing, add this line to `data/conf/postfix/extra.cf` in your mailcow directory and restart Postfix (`docker compose restart postfix-mailcow`):

```conf
always_add_missing_headers = yes
```

This also adds missing `From`, `To` and `Date` headers. Postfix warns that adding headers can break a DKIM signature that covers a header the sender left out, so leave it off if you see DKIM failures after the change.

## Data and backups

PostgreSQL keeps its data in the `postgres_data` volume. The app writes only to the `mailcowlogs_data` volume (mounted at `/app/data`) and to a small `/tmp`; the rest of its file system is read-only.

The database holds message history, reports and saved settings. `/app/data` holds the downloaded GeoIP databases and the app's own log. Back up both before an update.

> [!WARNING]
> Do not delete the Compose volumes to fix a startup problem. That deletes all stored history and saved settings. Also, changing `POSTGRES_PASSWORD` later does not change the password of a database that already exists.

## Updating

1. Read the [changelog](../CHANGELOG.md) for the new version.
2. Back up the volumes.
3. If you pinned the image tag, change it to the new version.
4. Pull and restart:

```sh
docker compose pull app
docker compose up -d
docker compose ps
docker compose logs --tail 100 app
```

The app updates its database on startup and does not start if that fails; the reason is in the log. After the update, check `/api/health`, sign in, and look at **About**, **Status** > **Server** and **Status** > **Jobs**.

Sessions live in the app's memory, so every restart or update signs everyone out, even with `SESSION_SECRET_KEY` set.

## If startup or import fails

| Problem | What to check |
| --- | --- |
| The app does not start | Required values in `.env`, the database container's health, the database credentials, and errors in `docker compose logs app`. |
| `/api/health` returns 503 | `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_USER`, `POSTGRES_PASSWORD` and `POSTGRES_DB`. |
| No new messages | **Fetch Logs** in **Status** > **Jobs**, `MAILCOW_URL`, and that the read-only key is on and allows the app's IP address. |
| An action is locked | Add `MAILCOW_API_KEY_RW` and click **Validate** in **Settings** > **Mailcow**. |
| mailcow rejects a key after a network change | Update the key's allowed IPs to the address mailcow now sees. |
| Saving or other actions return 403 behind a proxy | The proxy must pass the original host name; see [Reverse proxy](Reverse_Proxy.md). |
| Port 8080 is taken | Change the host side of the port mapping in `docker-compose.yml`, for example `127.0.0.1:8081:8080`. The app still listens on 8080 inside the container. |
