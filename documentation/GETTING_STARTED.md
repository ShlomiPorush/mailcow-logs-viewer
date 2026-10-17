# Getting started

mailcow Logs Viewer runs next to your mailcow server in Docker: an app container and a PostgreSQL database. It reads mailcow through the mailcow API.

## Before you start

You need Docker with the Compose plugin, admin access to mailcow, and network access from the app to mailcow's HTTPS address. The app also uses outbound DNS for the domain and blocklist checks, and outbound HTTPS for version checks, the in-app help and MaxMind downloads.

Keep the app on a private network while you set it up. Before you open it to the internet, turn on [sign-in](OAuth2_Configuration.md) and put it behind an [HTTPS reverse proxy](Reverse_Proxy.md).

## 1. Create the mailcow API keys

The app needs a read-only key. A read-write key is needed only to change things in mailcow from the app: release or delete quarantined mail, act on the queue, ban and unban addresses, edit rate limits and Rspamd maps, and block abusive senders. You can add it later.

In the mailcow admin interface, open **System** > **Configuration** > **Access** > **Administrators** and expand **API**:

1. Under **Read-Only Access**, enter the IP address the app connects from, tick **Activate API**, click **Save changes** and copy the **API key**.
2. For the read-write key, do the same under **Read-Write Access**.

The allowed IPs must include the address mailcow sees when the app connects. When both run on one host, this can differ from the address you expect. If mailcow rejects the key later, check this first.

> [!WARNING]
> Everyone who can sign in to the app can use every action the read-write key allows. Give sign-in only to mailcow administrators.

## 2. Make Postfix add a Message-ID

The app joins the Postfix and Rspamd log lines of a message by its Message-ID. A message that arrives without one gets no subject, no direction (inbound, outbound or internal), no spam score and no authenticated user, so it is also missing from the counts on the Dashboard, Mailbox Stats and Outgoing spam.

Add this line to `data/conf/postfix/extra.cf` in your mailcow directory:

```conf
always_add_missing_headers = yes
```

Then restart Postfix from the mailcow directory:

```sh
docker compose restart postfix-mailcow
```

Postfix also adds a missing `From`, `To` or `Date` header.

## 3. Download the files

On the Docker host:

```sh
mkdir mailcow-logs-viewer
cd mailcow-logs-viewer
curl -fsSLO https://raw.githubusercontent.com/ShlomiPorush/mailcow-logs-viewer/main/docker-compose.yml
curl -fsSL -o .env https://raw.githubusercontent.com/ShlomiPorush/mailcow-logs-viewer/main/env.example
```

<!-- VERIFY: Before publishing v3, confirm that the image referenced by docker-compose.yml contains v3. The latest image can still contain the previous release during development. -->
The Compose file uses the `latest` image. To stay on one release, replace `latest` with that version's tag.

## 4. Set the required values

Open `.env` and set these values. The other values in the file can stay as they are.

```dotenv
MAILCOW_URL=https://mail.example.com
MAILCOW_API_KEY=replace-with-read-only-key
MAILCOW_API_KEY_RW=replace-with-read-write-key
POSTGRES_PASSWORD=replace-with-a-random-hex-password
SETTINGS_EDIT_VIA_UI_ENABLED=true
BASIC_AUTH_ENABLED=true
AUTH_USERNAME=admin
AUTH_PASSWORD=replace-with-a-long-random-password
```

- `MAILCOW_URL` is your mailcow web address, without a trailing slash.
- Leave out `MAILCOW_API_KEY_RW` if you did not create the read-write key.
- Use only letters and digits in `POSTGRES_PASSWORD`, for example the output of `openssl rand -hex 32`. Characters such as `@`, `/` or `:` break the database connection.
- `SETTINGS_EDIT_VIA_UI_ENABLED=true` lets you change settings in the app. Without it, the Settings page is read-only.
- The `AUTH` lines turn on sign-in. Without sign-in, anyone who can reach the app can read all mail logs.

## 5. Start the app

Run these commands from the directory containing `docker-compose.yml` and `.env`:

```sh
docker compose up -d
curl http://localhost:8080/api/health
```

A working app answers `{"status":"healthy","database":"connected"}`. HTTP 503 means the app cannot reach its database. The health check does not test the connection to mailcow.

## 6. Sign in and check the import

Open `http://<your-server>:8080` and sign in with the username and password from `.env`.

![Login page](../images/docs/getting-started-login-light.webp#gh-light-mode-only)
![Login page](../images/docs/getting-started-login-dark.webp#gh-dark-mode-only)

Then:

1. **About** shows whether the database and the mailcow API are connected.
2. **Status** > **Jobs** shows errors of **Fetch Logs**.
3. If you added the read-write key, click **Validate** next to it in **Settings** > **Mailcow**.

The app fetches mail logs every 60 seconds; other data has its own schedule, so some pages fill in later. It sees only the log history that mailcow still keeps.

## 7. Move settings into the app

Open **Settings** and click **Migrate Settings from ENV**, then **Import**. Until you do this, the Settings page cannot be edited.

A variable set in `.env`, even an empty value such as `SMTP_HOST=`, always wins over the saved value, and its field shows **Set by ENV**. To manage a value in the app, delete its line from `.env` and run `docker compose up -d`. Keep `MAILCOW_URL`, `MAILCOW_API_KEY`, the `POSTGRES_` values and `SETTINGS_EDIT_VIA_UI_ENABLED=true` in `.env`: the app needs them before it can read the saved settings.

From here, add what you need in [Settings](HelpDocs/Settings.md): the Rspamd password for the Spam Filter maps, SMTP and [notifications](Notifications.md) for alerts, a mailbox for DMARC and TLS reports, and MaxMind for IP locations.

## Data and backups

The database lives in the `postgres_data` volume and holds message history, reports and saved settings. The `mailcowlogs_data` volume holds the GeoIP databases and the app's own log. Back up both before an update.

> [!WARNING]
> Do not delete the volumes to fix a startup problem: that deletes all history and saved settings. Changing `POSTGRES_PASSWORD` later does not change the password of an existing database.

## Updating

Read the [changelog](../CHANGELOG.md), back up the volumes, change the image tag if you pinned one, and run:

```sh
docker compose pull app
docker compose up -d
```

The app updates its database on startup and does not start if that fails; the reason is in `docker compose logs app`. An update signs everyone out.

## If something fails

| Problem | What to check |
| --- | --- |
| The app does not start | `docker compose logs app`, the values in `.env` and the database container. |
| `/api/health` returns 503 | The `POSTGRES_` values. |
| No new messages | **Fetch Logs** in **Status** > **Jobs**, `MAILCOW_URL`, and that the read-only key is active and allows the app's IP address. |
| Messages have no subject or spam score | [Step 2](#2-make-postfix-add-a-message-id). |
| An action is locked | Add the read-write key and click **Validate** in **Settings** > **Mailcow**. |
| Saving returns 403 behind a proxy | The proxy must pass the original host name; see [Reverse proxy](Reverse_Proxy.md). |
| Port 8080 is taken | Change the host side of the port mapping in `docker-compose.yml`, for example `127.0.0.1:8081:8080`. |
