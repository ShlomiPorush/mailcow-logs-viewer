# Environment variables

Set these variables in the `.env` file next to `docker-compose.yml`; with the supplied `docker-compose.yml`, the app container reads only that file. After a change, recreate the app with `docker compose up -d`. A plain restart keeps the container's old environment.

## Configuration priority

A variable that is set, even to an empty value (`SMTP_HOST=`), wins over the value saved on the Settings page and locks its field there. Saved values are used only while `SETTINGS_EDIT_VIA_UI_ENABLED=true`. To move variables into the Settings page, see [Settings](HelpDocs/Settings.md#enable-editing-and-migrate-from-env).

The required settings, `SETTINGS_EDIT_VIA_UI_ENABLED`, `APP_PORT` and every variable from [Environment-only and legacy settings](#environment-only-and-legacy-settings) down can be set only here. Notification destinations, ignored containers and blocklists, protection rules, quarantine rules and the outgoing spam whitelist have no variables; you manage them on their pages.

Switches take `true` or `false`. **Required** means the app does not start without it, **Unset** means no value, and **Empty** means an empty string.

## Required settings

The app reads these before it can reach the database, so they stay in `.env`.

| Variable | Default | Effect |
| --- | --- | --- |
| `MAILCOW_URL` | Required | mailcow address, such as `https://mail.example.com`. |
| `MAILCOW_API_KEY` | Required | Read-only mailcow API key. It must be active, and its allowed IPs (mailcow **System** > **Configuration** > **Access** > **Administrators** > **API**) must hold the address mailcow sees for this app, which can change when the app moves to another Docker network. See [Getting started](GETTING_STARTED.md). |
| `POSTGRES_HOST` | `db` | `db` is the database container of the supplied Compose file. |
| `POSTGRES_PORT` | `5432` | |
| `POSTGRES_USER` | Required | `env.example` uses `mailcowlogs`. |
| `POSTGRES_PASSWORD` | Required | Replace the `changeme` from `env.example` with a long random value; hexadecimal avoids characters that break the database URL. |
| `POSTGRES_DB` | Required | `env.example` uses `mailcowlogs`. |

The `db` service in `docker-compose.yml` falls back to `mailcowlogs` and `changeme`, but the app does not: it does not start without these values in `.env`.

## Settings UI configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `SETTINGS_EDIT_VIA_UI_ENABLED` | `false` | `true`, `1` or `yes` lets you edit settings on the Settings page and store them in the database. |

## mailcow API configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `MAILCOW_API_KEY_RW` | Unset | Separate read-write mailcow API key, needed for every action that changes mailcow. Without it the app only monitors. It has its own allowed IPs, with the same rule as `MAILCOW_API_KEY`; check it with **Validate** under **Settings** > **Mailcow**. |
| `RSPAMD_PASSWORD` | Unset | Rspamd UI password, needed to view Rspamd maps. Editing them also needs the read-write key. |
| `RSPAMD_URL` | Empty | Empty reaches Rspamd through the mailcow URL plus `/rspamd`. Set a direct address, such as `http://rspamd-mailcow:11334`, only when that path fails. |
| `MAILCOW_API_TIMEOUT` | `30` | Seconds before a mailcow API request gives up. |
| `MAILCOW_API_VERIFY_SSL` | `true` | Check mailcow's certificate. Turn off only for a test server with a self-signed certificate. |

## Fetch configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `FETCH_INTERVAL` | `60` | Seconds between reads of the message logs. |
| `FETCH_COUNT_POSTFIX` | `2000` | Postfix entries per page. |
| `FETCH_COUNT_RSPAMD` | `500` | Rspamd entries per page. |
| `FETCH_COUNT_NETFILTER` | `500` | Netfilter entries per read. |
| `FETCH_MAX_PAGES` | `50` | Most Postfix and Rspamd pages per read. |
| `RETENTION_DAYS` | `7` | Days to keep message logs. |
| `BLACKLIST_EMAILS` | Empty | Comma-separated addresses the viewer never stores, such as a BCC archive. Mail to them is still delivered. |

## Correlation configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `MAX_CORRELATION_AGE_MINUTES` | `10` | Minutes after which the viewer stops trying to link the log lines of a message. |
| `CORRELATION_CHECK_INTERVAL` | `120` | Seconds between linking runs. |

## Application configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `APP_PORT` | `8080` | Environment only, and used only when the app is started directly with Python. The container always listens on 8080; change the host port in `docker-compose.yml`. |
| `APP_TITLE` | `mailcow Logs Viewer` | Name in the sidebar and the browser tab. |
| `APP_LOGO_URL` | Empty | Logo image address. Empty shows the project icon. |
| `TZ` | Unset (UTC) | The app's time zone, an IANA name such as `Europe/Berlin`. Times on screen, days, times you type, emails, CSV exports and scheduled jobs follow it; the browser's and the containers' zones do not. An unknown name means UTC, and Settings and About say so. Use the time zone of your mailcow server. |
| `LOG_LEVEL` | `WARNING` | `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL`. Anything else means `WARNING`. |
| `DEBUG` | `false` | Logs every SQL statement, puts exception text in API error responses and turns off database connection pooling. Keep off in production. |
| `MAX_SEARCH_RESULTS` | `1000` | Not used by this version. |
| `CSV_EXPORT_LIMIT` | `10000` | Most rows in one CSV export. |
| `SCHEDULER_WORKERS` | `4` | Threads for background jobs such as the IMAP import, 1 to 64. |

## Feature switches

| Variable | Default | Effect |
| --- | --- | --- |
| `DISABLED_FEATURES` | Empty | Comma-separated features to turn off, for example `queue,quarantine`. Their pages disappear and jobs used only by those features stop; shared jobs continue while another enabled page needs them. API routes remain available. |

The names are `netfilter` (Security), `queue`, `quarantine`, `suppressions`, `rspamd` (the Rspamd page), `domains`, `dmarc`, `mailbox-stats`, `rate-limits`, `logs`, `blacklist` (IP Blacklist Monitor) and `devices`. The old name `spam-filter` turns off both `suppressions` and `rspamd`. A feature listed here loses its stored data at startup, as when it is turned off in Settings, including DMARC history and quarantine rules; a feature removed from the list reloads only what the server still has. See [Settings](HelpDocs/Settings.md#features).

## Blacklist configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `BLACKLIST_SOURCE_SERVER_IP` | `true` | Check the WAN address that mailcow reports. Turn off when mail leaves through a relay. |
| `BLACKLIST_SOURCE_TRANSPORTS` | `true` | Check every public address of the active mailcow transports. |
| `BLACKLIST_SOURCE_RELAYHOSTS` | `true` | Check every public address of the active mailcow relayhosts. |
| `BLACKLIST_SOURCE_MANUAL_HOSTS` | Empty | More IPv4 or IPv6 addresses or host names to check, such as `192.0.2.10,relay.example.com`. |
| `BLACKLIST_DNS_SERVERS` | Empty | Comma-separated DNS resolvers for the checks. Empty uses the container's resolver. Spamhaus refuses public resolvers, so use your own. |

## Domain SPF check configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `DOMAIN_SPF_SOURCE_SERVER_IP` | `true` | The WAN address must pass each domain's SPF check. Turn off when mail leaves through a relay. |
| `DOMAIN_SPF_SOURCE_TRANSPORTS` | `false` | The public addresses of the active mailcow transports must pass too. |
| `DOMAIN_SPF_SOURCE_RELAYHOSTS` | `false` | The public addresses of the active mailcow relayhosts must pass too. |
| `DOMAIN_SPF_SOURCE_MANUAL_HOSTS` | Empty | More sending addresses or host names that must pass. Do not add hosts that never send, such as an inbound-only MX. |
| `DOMAIN_SPF_SOURCE_DMARC_HISTORY` | `false` | Addresses that passed SPF in the DMARC reports of the last 30 days must pass too. With relaxed alignment this can raise false warnings for an email service's subdomain. |

## Authentication configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `BASIC_AUTH_ENABLED` | `false` | Sign-in with username and password. Needs a password. |
| `AUTH_USERNAME` | `admin` | |
| `AUTH_PASSWORD` | Empty | The Settings page will not clear it while Basic authentication is on. |
| `AUTH_MAX_FAILURE_CLIENTS` | `10000` | How many client addresses the failed-login counter tracks, at least 1. When full, the oldest make room. |
| `OAUTH2_ENABLED` | `false` | Sign-in through an OAuth2/OIDC provider. |
| `OAUTH2_PROVIDER_NAME` | `OAuth2 Provider` | Text on the login button. |
| `OAUTH2_ISSUER_URL` | Unset | Provider address for discovery. The app reads `/.well-known/openid-configuration` under it. |
| `OAUTH2_USE_OIDC_DISCOVERY` | `true` | Read the endpoints from the discovery document. Turn off to set them by hand. |
| `OAUTH2_AUTHORIZATION_URL` | Unset | Authorization endpoint, only without discovery. |
| `OAUTH2_TOKEN_URL` | Unset | Token endpoint, only without discovery. |
| `OAUTH2_USERINFO_URL` | Unset | UserInfo endpoint, only without discovery. |
| `OAUTH2_CLIENT_ID` | Unset | |
| `OAUTH2_CLIENT_SECRET` | Unset | |
| `OAUTH2_REDIRECT_URI` | Unset | Callback address, exactly as registered with the provider, such as `https://logs.example.com/api/auth/callback`. |
| `OAUTH2_SCOPES` | `openid profile email` | Scopes, separated by spaces. |
| `SESSION_SECRET_KEY` | Empty | Signs the session cookie. Empty uses a temporary key for each run. Set a long random value, for example from `openssl rand -hex 32`. Sessions live in memory, so a restart signs everyone out either way. |
| `SESSION_EXPIRY_HOURS` | `24` | |
| `SESSION_MAX_ENTRIES` | `50` | Most signed-in sessions at once, at least 1. When full, new sign-ins wait; existing sessions stay. |

See [Sign-in configuration](OAuth2_Configuration.md) for provider recipes.

## SMTP configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `SMTP_ENABLED` | `false` | Turns on all email from the app. |
| `SMTP_HOST` | Unset | |
| `SMTP_PORT` | `587` | Port 465 always uses implicit TLS. |
| `SMTP_USE_TLS` | `false` | STARTTLS. Set `true` for port 587. |
| `SMTP_USE_SSL` | `false` | Implicit TLS. Wins over STARTTLS. |
| `SMTP_VERIFY_SSL` | `false` | Certificate check: `false` (off), `auto` (checks host names such as `smtp.example.com`, skips `localhost`, IP addresses and container names) or `true` (always). Use `auto` unless the certificate is self-signed. |
| `SMTP_USER` | Unset | |
| `SMTP_PASSWORD` | Unset | |
| `SMTP_RELAY_MODE` | `false` | Send without logging in, through a relay that trusts this app. Needs `SMTP_HOST` and `SMTP_FROM`. |
| `SMTP_FROM` | Unset | From address, such as `alerts@example.com`. Empty uses `SMTP_USER`. |

## Admin and notification configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `ADMIN_EMAIL` | Unset | Gets alerts, the weekly summary and the SMTP test. Several addresses separated by commas. |
| `BLACKLIST_ALERT_EMAIL` | Unset | Blocklist alerts. Empty uses `ADMIN_EMAIL`. |
| `DMARC_ERROR_EMAIL` | Unset | DMARC and TLS report import errors. Empty uses `ADMIN_EMAIL`. |
| `ENABLE_WEEKLY_SUMMARY` | `true` | Summary email every Monday at 09:00. Needs SMTP and `ADMIN_EMAIL`. |
| `DNS_CHANGE_ALERTS_ENABLED` | `true` | Alert when a domain's SPF, DKIM, DMARC, TLSA, MTA-STS or TLS-RPT record changes, DNSSEC stops validating or a TLSA record stops matching the certificate. A failed lookup is not a change. |

Destinations such as Slack or Telegram are set on the Settings page only; see [Notifications](Notifications.md).

## SMTP abuse protection

| Variable | Default | Effect |
| --- | --- | --- |
| `SMTP_ABUSE_ENABLED` | `false` | Stop a mailbox from sending when it goes over the limit. Needs the read-write key. The mailbox still receives mail. |
| `SMTP_ABUSE_THRESHOLD` | `100` | Messages one mailbox may send in the window. |
| `SMTP_ABUSE_WINDOW_MINUTES` | `60` | Length of the rolling window in minutes. |
| `SMTP_ABUSE_REVOKE_APP_PASSWORDS` | `true` | Also delete the mailbox's app passwords when it is stopped. Mail apps that sign in with one, including IMAP clients, then need a new one. |
| `SMTP_ABUSE_UNBLOCK_GRACE_MINUTES` | `60` | After you let a mailbox send again, it is not stopped again for this many minutes. |
| `SMTP_ABUSE_HELP_ADDRESS` | Empty | Contact named in the email to the stopped mailbox. Empty uses `ADMIN_EMAIL`, then the words `your administrator`. |

## Anomaly detection

| Variable | Default | Effect |
| --- | --- | --- |
| `ANOMALY_DETECTION_ENABLED` | `false` | Alert on sending spikes and bursts of failed logins. Never blocks anything. |
| `ANOMALY_VOLUME_MULTIPLIER` | `5` | How many times its normal rate a mailbox must send to raise an alert. Decimals are allowed. |
| `ANOMALY_VOLUME_MIN_MESSAGES` | `30` | Below this many sent messages in the window, no volume alert. |
| `ANOMALY_BASELINE_DAYS` | `7` | Days of history used to learn each mailbox's normal rate, including batches it sends at the same hour every day. |
| `ANOMALY_AUTH_FAILURE_THRESHOLD` | `20` | Failed logins for one username in the window that raise an alert. |
| `ANOMALY_CHECK_INTERVAL` | `15` | Minutes between checks, and the window each check looks at. |
| `ANOMALY_ALERT_COOLDOWN_HOURS` | `6` | No repeat alert for the same mailbox and problem within this many hours. |

## DMARC configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `DMARC_RETENTION_DAYS` | `60` | Days to keep DMARC and TLS reports. |
| `DMARC_MANUAL_UPLOAD_ENABLED` | `true` | Allow uploading DMARC and TLS reports by hand. |
| `DMARC_ALLOW_REPORT_DELETE` | `false` | Allow deleting reports in the app and through the API. |
| `DMARC_INSIGHTS_WINDOW_DAYS` | `28` | Days of DMARC reports used for policy recommendations. |
| `DMARC_INSIGHTS_PASS_THRESHOLD` | `99.5` | DMARC pass rate (%) needed before a stricter policy is suggested. |
| `DMARC_INSIGHTS_MIN_VOLUME` | `100` | Reported messages needed before any recommendation. |

## DMARC and TLS IMAP auto-import configuration

Use a mailbox that only receives reports: the import reads its unread emails and, with the default `DMARC_IMAP_DELETE_AFTER=true`, deletes each one it imports.

| Variable | Default | Effect |
| --- | --- | --- |
| `DMARC_IMAP_ENABLED` | `false` | Import DMARC and TLS report emails over IMAP. |
| `DMARC_IMAP_HOST` | Unset | |
| `DMARC_IMAP_PORT` | `993` | |
| `DMARC_IMAP_USE_SSL` | `true` | Implicit TLS. With `false` the connection is not encrypted at all (no STARTTLS). |
| `DMARC_IMAP_VERIFY_SSL` | `false` | Certificate check, same values as `SMTP_VERIFY_SSL`. |
| `DMARC_IMAP_USER` | Unset | Such as `reports@example.com`. |
| `DMARC_IMAP_PASSWORD` | Unset | |
| `DMARC_IMAP_FOLDER` | `INBOX` | |
| `DMARC_IMAP_DELETE_AFTER` | `true` | Delete each report email after it is imported. Emails that fail stay, marked as read. |
| `DMARC_IMAP_INTERVAL` | `3600` | Seconds between imports. |
| `DMARC_IMAP_RUN_ON_STARTUP` | `true` | Import once when the app starts. |
| `DMARC_IMAP_BATCH_SIZE` | `10` | Emails per batch. |
| `DMARC_IMAP_SCAN_ALL_UNSEEN` | `false` | Also read unread emails whose subject does not look like a report, for providers with non-English subjects. |

## MaxMind GeoIP configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `MAXMIND_ACCOUNT_ID` | Unset | Needed, with the license key, to download the GeoLite2 databases. |
| `MAXMIND_LICENSE_KEY` | Unset | |

## Raw logs configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `RAW_LOGS_ENABLED` | `true` | Collect logs for the Logs page. Off: the page says collection is off; services needed by other enabled pages are still collected. |
| `RAW_LOGS_FETCH_INTERVAL` | `30` | Seconds between reads. |
| `RAW_LOGS_FETCH_COUNT` | `1000` | Entries per service per read. |
| `RAW_LOGS_RETENTION_DAYS` | `2` | Days to keep raw logs. |
| `RATE_LIMITS_RETENTION_DAYS` | `90` | Days to keep the rate limit log for Rate Limits, 1 to 3650. Never less than `RAW_LOGS_RETENTION_DAYS`. |
| `RAW_LOGS_SERVICES` | `acme,api,autodiscover,dovecot,netfilter,postfix,ratelimited,rspamd-history,sogo,watchdog` | Services the Logs page shows, comma-separated, or `all`. Unknown names are ignored. |

Some services are collected whatever this list says, because other pages read them: `dovecot` for message details and Security, `ratelimited` for Rate Limits and `sogo` for Devices.

## Devices (ActiveSync)

| Variable | Default | Effect |
| --- | --- | --- |
| `EAS_DEVICES_RETENTION_DAYS` | `90` | Days to keep a device after its last ActiveSync request. `0` keeps every device. |

## Spam suppression configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `SUPPRESSION_ENABLED` | `false` | Enables the suppression jobs: bounce detection, deferred queue cleanup, Rspamd sync and expiry. Manual API actions still work while it is off. |
| `SUPPRESSION_AUTO_DETECT` | `true` | Read the Postfix logs for bounces. The Outbound choices set it; set it here only to force it. |
| `SUPPRESSION_RSPAMD_SYNC` | `true` | Sync with Rspamd: keep the suppression list and the app's section of Rspamd's `global_rcpt_blacklist.map` in step, both ways, so mail to the listed addresses is rejected. `false` keeps no list: the app deletes it (Rspamd is not touched), and `true` again loads the app's blocks back from Rspamd. Needs `RSPAMD_PASSWORD` and the read-write key. |
| `SUPPRESSION_HARD_BOUNCE_ACTION` | `suppress` | For permanent failures (5.x.x): `suppress` (block the address and delete its queued mail), `delete` (only delete its queued mail) or `ignore`. With `SUPPRESSION_RSPAMD_SYNC=false`, `suppress` acts as `delete`. |
| `SUPPRESSION_SOFT_BOUNCE_ACTION` | `count` | For temporary failures (4.x.x): `suppress`, `count` (suppress at the threshold) or `ignore`. Used only while `QUEUE_CLEANUP_ENABLED=false`. With `SUPPRESSION_RSPAMD_SYNC=false`, both that block act as `ignore`. |
| `SUPPRESSION_SOFT_BOUNCE_THRESHOLD` | `3` | Soft bounces before `count` suppresses. Used only while `QUEUE_CLEANUP_ENABLED=false`. |
| `QUEUE_CLEANUP_ENABLED` | `true` | Delete messages stuck in the deferred queue longer than the threshold. Needs the read-write key and `SUPPRESSION_ENABLED=true`. |
| `QUEUE_CLEANUP_BLOCK` | `true` | Also block the recipients of the messages `QUEUE_CLEANUP_ENABLED` deletes. Needs `SUPPRESSION_RSPAMD_SYNC=true`; without it the cleanup only deletes. |
| `QUEUE_CLEANUP_THRESHOLD_MINUTES` | `60` | Minutes a deferred message waits before it is deleted. |
| `SUPPRESSION_BASE_EXPIRY_DAYS` | `7` | Block time in days, multiplied by the number of bounces. |
| `SUPPRESSION_MAX_EXPIRY_DAYS` | `90` | Longest block in days. |
| `SUPPRESSION_WHITELIST_DOMAINS` | Empty | Domains never blocked automatically, and whose queued mail is never deleted automatically, such as `example.org`. |

## Quarantine auto-rules configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `QUARANTINE_RULES_MAX_ACTIONS` | `50` | Most messages the rules release or delete in one run. |
| `QUARANTINE_RULES_INTERVAL` | `5` | Minutes between runs. |
| `QUARANTINE_RULES_LOG_RETENTION_DAYS` | `30` | Days to keep the history of what the rules did. |

## Environment-only and legacy settings

| Variable | Default | Effect |
| --- | --- | --- |
| `AUTH_ENABLED` | `false` | Old name for `BASIC_AUTH_ENABLED`. While it is `true`, Basic authentication stays on whatever the newer switch says. |
| `CORS_ALLOWED_ORIGINS` | Empty | Other sites allowed to call the API with the user's session. See [Cross-site requests](#cross-site-requests). |
| `WEBHOOK_ENABLED` | `false` | Old single-webhook switch. On upgrade, an old webhook becomes a destination under **Settings** > **Notifications**. |
| `WEBHOOK_TYPE` | `generic` | Old webhook format: `generic`, `slack`, `discord`, `telegram`, `ntfy` or `gotify`. Read only by that upgrade. |
| `WEBHOOK_URL` | Unset | Old webhook address, copied into the destination on upgrade. Changing it later does not change the destination. |
| `WEBHOOK_TELEGRAM_CHAT_ID` | Unset | Old Telegram chat ID, read only by that upgrade. |

### Login attempt limits and reverse proxies

The [limit on failed Basic sign-ins](OAuth2_Configuration.md#basic-authentication) counts by visitor address. Behind a reverse proxy, Uvicorn takes that address from the proxy only if the proxy is listed here:

| Variable | Default | Effect |
| --- | --- | --- |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | Comma-separated proxy addresses, such as `192.0.2.10`. Ranges (CIDR) are not accepted by the Uvicorn version in the image. Do not use `*` if anyone can reach the app without the proxy. See [Reverse proxy](Reverse_Proxy.md#trusted-proxy-addresses). |

### Cross-site requests

`CORS_ALLOWED_ORIGINS` takes exact origins (scheme, host and optional port, no path), such as `https://portal.example.org`; no wildcard. Empty allows only the app's own pages, which need no entry as long as a reverse proxy passes the original `Host` header. Add a site only if it should call the API with a signed-in user's session. Scripts that send no `Origin` or `Referer` header are not affected but still have to sign in.

## Process and data-directory variables

These are read by the container's start script or the GeoIP downloader, not by the Settings page.

| Variable | Default | Effect |
| --- | --- | --- |
| `GEOIP_DB_DIR` | `/app/data` | Where the GeoIP databases are downloaded. Leave it unchanged: the lookups read from `/app/data`. |
| `APP_MODULE` | `app.main:app` | Application the container starts. Leave unchanged; the demo image sets `demo.main:app`. |
| `UVICORN_LOOP` | `auto` | Event loop. The demo image uses `asyncio`. |

### Demo image variables

These apply only to the `demo` image, which starts `demo.main:app` with made-up data and restarts once a day to reset it.

> [!WARNING]
> The demo clears its database at startup. Give it its own database; never point it at a real installation's database.

| Variable | Default | Effect |
| --- | --- | --- |
| `DEMO_MODE` | `true` in the demo image | A label only. `APP_MODULE=demo.main:app` starts the demo. |
| `DEMO_NOTICE` | Empty | Replaces the text of the demo banner. |
| `DEMO_RESET_TIME` | `00:00` | Daily restart time as `HH:MM`, in the app's time zone (`TZ`). An invalid value means midnight. |
| `DEMO_RESET_AFTER_SECONDS` | Unset | For testing: restart after this many seconds instead of at the daily time. |
