# Settings

**Settings** is where you connect the viewer to mailcow, choose what it collects and keeps, and set up alerts and sign-in. Values you save here are stored in the viewer's database. A value set by an environment variable always wins over them.

## Enable editing and migrate from ENV

Until `SETTINGS_EDIT_VIA_UI_ENABLED=true` is set, the page shows **Editing settings is off** and three read-only panels: **Runtime** (the current fetch, retention and logging values and the credential checks), **Global SMTP Configuration** with **Test SMTP**, and **DMARC & TLS Reports** with **Test IMAP**.

To edit settings here:

1. Set `SETTINGS_EDIT_VIA_UI_ENABLED=true` in `.env` and recreate the app with `docker compose up -d`. A plain restart keeps the old environment.
2. Open **Settings**, click **Migrate Settings from ENV** and confirm with **Import**. This copies the current configuration into the database; until then every field stays read-only.
3. Remove from `.env` the variables you want to manage here. Keep `MAILCOW_URL`, `MAILCOW_API_KEY`, the `POSTGRES_*` values and `SETTINGS_EDIT_VIA_UI_ENABLED`: the app needs them before it can read the database.
4. Recreate the app again. A field whose variable is still set shows **Set by ENV** and stays locked, even when the variable is empty (`SMTP_HOST=`).

<!-- SHOT: settings-env-migration | Settings before migration with Migrate Settings from ENV and disabled fields -->

If you later turn `SETTINGS_EDIT_VIA_UI_ENABLED` off, the app ignores the saved values, so put your sign-in settings back into `.env` first.

## Edit and save

Each category has its own address, such as `/settings/notifications`, and the [search](Search.md) in the top bar finds any setting. Changes in several categories are saved together with **Save changes**, or dropped with **Discard**. **Changed** next to a field means it differs from the default; **Reset to default** puts the default back.

Passwords and keys are never shown. A stored one reads **Stored**, with **Replace** and **Remove**. If you change the server a password is sent to, such as the SMTP host or the mailcow URL, enter the password again in the same save; the app never sends a stored password to a new server.

Most changes apply when you save. A change to the features, the app title or logo, sign-in or the mailcow URL reloads the page. A change to sign-in settings signs out every other session; you stay signed in.

<!-- SHOT: settings-mailcow | Settings > Mailcow with credential validation status, Stored secret controls and a Set by ENV field -->

The sections below follow the menu. Each table gives the variable and the default; [Environment variables](../ENV_Settings.md) describes every variable in full.

## Features

Switches for **Security**, **Queue**, **Quarantine**, **Spam Filter**, **Domains**, **DMARC & TLS**, **Mailbox Stats**, **Rate Limits**, **Devices**, **Logs** and **IP Blacklist Monitor**, all on by default. A feature that is off disappears from the menu, stops its background jobs and hides its category here. The switches are saved in `DISABLED_FEATURES`; if that variable is set, the whole list is locked.

> [!WARNING]
> Turning a feature off deletes the data the viewer stored for it, such as DMARC reports, quarantine rules or device history. Saving asks first (**Disable & Delete Data**); Queue and Rate Limits switch off without asking. Turning a feature on again starts from scratch.

Logs that other pages need keep coming in with the Logs page off: Dovecot for message details and Security, Ratelimited for Rate Limits, SOGo for Devices.

## Application

The port is set in `docker-compose.yml`, not here.

| Setting | Variable | Default | Notes |
| --- | --- | --- | --- |
| **App Title** | `APP_TITLE` | `mailcow Logs Viewer` | |
| **App Logo URL** | `APP_LOGO_URL` | Empty | Empty shows the project icon. |
| **Log Level** | `LOG_LEVEL` | `WARNING` | |
| **Debug** | `DEBUG` | `false` | Keep off in production. |
| **Max Search Results** | `MAX_SEARCH_RESULTS` | `1000` | Not used by this version. |
| **CSV Export Limit** | `CSV_EXPORT_LIMIT` | `10000` | |
| **Scheduler Workers** | `SCHEDULER_WORKERS` | `4` | 1 to 64. |

## Mailcow

The **Status** panel checks the **Read-Write API Key** and the **Rspamd Password** without changing anything in mailcow. **Validate** shows **Accepted** or what is wrong, with a hint when you point at it. Saving a new key or password runs the check by itself.

| Setting | Variable | Default | Notes |
| --- | --- | --- | --- |
| **mailcow URL** | `MAILCOW_URL` | Required | For example `https://mail.example.com`. |
| **mailcow API Key** | `MAILCOW_API_KEY` | Required | The read-only key. mailcow must allow this app's IP address for it. |
| **mailcow API Key (read-write)** | `MAILCOW_API_KEY_RW` | Unset | Needed for every action that changes mailcow. Allow this app's IP address for it too. |
| **Rspamd Password** | `RSPAMD_PASSWORD` | Unset | Needed to view Rspamd maps; editing them also needs the read-write key. |
| **Rspamd URL** | `RSPAMD_URL` | Empty | Empty reaches Rspamd through the mailcow URL plus `/rspamd`. |
| **mailcow API Timeout** | `MAILCOW_API_TIMEOUT` | `30` | Seconds. |
| **mailcow API Verify SSL** | `MAILCOW_API_VERIFY_SSL` | `true` | |

## Fetch

| Setting | Variable | Default | Notes |
| --- | --- | --- | --- |
| **Fetch Interval** | `FETCH_INTERVAL` | `60` | Seconds. |
| **Fetch Count Postfix** | `FETCH_COUNT_POSTFIX` | `2000` | |
| **Fetch Count Rspamd** | `FETCH_COUNT_RSPAMD` | `500` | |
| **Fetch Count Netfilter** | `FETCH_COUNT_NETFILTER` | `500` | |
| **Fetch Max Pages** | `FETCH_MAX_PAGES` | `50` | |
| **Retention Days** | `RETENTION_DAYS` | `7` | Days to keep message logs. |
| **Blacklist Emails** | `BLACKLIST_EMAILS` | Empty | Addresses the viewer never stores, such as a BCC archive. Mail to them is still delivered. |

## Correlation

| Setting | Variable | Default | Notes |
| --- | --- | --- | --- |
| **Max Correlation Age Minutes** | `MAX_CORRELATION_AGE_MINUTES` | `10` | |
| **Correlation Check Interval** | `CORRELATION_CHECK_INTERVAL` | `120` | Seconds. |

## Logs

Collection for the [Logs](Logs.md) page. A service marked **Always collected for** another page keeps coming in even when you switch it off here; only the Logs page stops showing it.

| Setting | Variable | Default | Notes |
| --- | --- | --- | --- |
| **Raw Logs Enabled** | `RAW_LOGS_ENABLED` | `true` | Off: the Logs page keeps what it has and collects nothing new. |
| **Raw Logs Fetch Interval** | `RAW_LOGS_FETCH_INTERVAL` | `30` | Seconds. |
| **Raw Logs Fetch Count** | `RAW_LOGS_FETCH_COUNT` | `1000` | |
| **Raw Logs Retention Days** | `RAW_LOGS_RETENTION_DAYS` | `2` | Also limits the history on Rate Limits. |
| **Raw Logs Services** | `RAW_LOGS_SERVICES` | All ten services | The switches under **Services**. |

## Notifications

**Alert destinations** at the top is where you add, test, edit, turn off and delete destinations (Slack, Telegram, ntfy and others) and choose which alerts each one gets; see [Notifications](../Notifications.md). The address fields take several addresses separated by commas.

| Setting | Variable | Default | Notes |
| --- | --- | --- | --- |
| **Admin Email** | `ADMIN_EMAIL` | Unset | Gets alerts, the weekly summary and **Test SMTP**. |
| **Blacklist Alert Email** | `BLACKLIST_ALERT_EMAIL` | Unset | Empty uses **Admin Email**. |
| **Report Import Error Email** | `DMARC_ERROR_EMAIL` | Unset | DMARC and TLS import errors. Empty uses **Admin Email**. |
| **Enable Weekly Summary** | `ENABLE_WEEKLY_SUMMARY` | `true` | Mondays at 09:00. Needs SMTP and **Admin Email**. |
| **DNS Change Alerts Enabled** | `DNS_CHANGE_ALERTS_ENABLED` | `true` | |

## SMTP

**Test SMTP** sends a real test email to **Admin Email** (or to **SMTP User** when that is empty) using the saved settings, and shows each step of the connection. Save your changes before you test.

For port 587, turn on **SMTP Use TLS** (STARTTLS); port 465 always uses implicit TLS. **SMTP Verify SSL** checks the server's certificate: **Automatic** checks host names such as `smtp.example.com` and skips `localhost`, IP addresses and container names. Keep **Off** only for a self-signed certificate.

| Setting | Variable | Default | Notes |
| --- | --- | --- | --- |
| **SMTP Enabled** | `SMTP_ENABLED` | `false` | Turns on all email from the app. |
| **SMTP Host** | `SMTP_HOST` | Unset | |
| **SMTP Port** | `SMTP_PORT` | `587` | |
| **SMTP Use TLS** | `SMTP_USE_TLS` | `false` | |
| **SMTP Use SSL** | `SMTP_USE_SSL` | `false` | Wins over STARTTLS. |
| **SMTP Verify SSL** | `SMTP_VERIFY_SSL` | `false` | `false`, `auto` or `true` (Off, Automatic, On). |
| **SMTP User** | `SMTP_USER` | Unset | |
| **SMTP Password** | `SMTP_PASSWORD` | Unset | |
| **SMTP Relay Mode** | `SMTP_RELAY_MODE` | `false` | Send without logging in. Needs **SMTP Host** and **SMTP From**. |
| **SMTP From** | `SMTP_FROM` | Unset | Empty uses **SMTP User**. |

## Authentication

Basic authentication and OAuth2/OIDC can be on together. Turning on **Basic Auth Enabled** asks you to type the username and password again (**Verify Credentials**) before it saves, so a typo cannot lock you out. While Basic Auth is on, the password cannot be cleared. Sessions are kept in memory, so everyone signs in again after a restart. See [Sign-in configuration](../OAuth2_Configuration.md).

| Setting | Variable | Default | Notes |
| --- | --- | --- | --- |
| **Basic Auth Enabled** | `BASIC_AUTH_ENABLED` | `false` | |
| **Auth Username** | `AUTH_USERNAME` | `admin` | |
| **Auth Password** | `AUTH_PASSWORD` | Empty | |
| **Auth Max Failure Clients** | `AUTH_MAX_FAILURE_CLIENTS` | `10000` | Client addresses the failed-login counter tracks. When full, the oldest make room. |
| **Oauth2 Enabled** | `OAUTH2_ENABLED` | `false` | |
| **Oauth2 Provider Name** | `OAUTH2_PROVIDER_NAME` | `OAuth2 Provider` | Text on the login button. |
| **Oauth2 Issuer URL** | `OAUTH2_ISSUER_URL` | Unset | |
| **Oauth2 Use OIDC Discovery** | `OAUTH2_USE_OIDC_DISCOVERY` | `true` | Turn off to fill in the three endpoints below. |
| **Oauth2 Authorization URL** | `OAUTH2_AUTHORIZATION_URL` | Unset | Only without discovery. |
| **Oauth2 Token URL** | `OAUTH2_TOKEN_URL` | Unset | Only without discovery. |
| **Oauth2 Userinfo URL** | `OAUTH2_USERINFO_URL` | Unset | Only without discovery. |
| **Oauth2 Client Id** | `OAUTH2_CLIENT_ID` | Unset | |
| **Oauth2 Client Secret** | `OAUTH2_CLIENT_SECRET` | Unset | |
| **Oauth2 Redirect Uri** | `OAUTH2_REDIRECT_URI` | Unset | For example `https://logs.example.com/api/auth/callback`. |
| **Oauth2 Scopes** | `OAUTH2_SCOPES` | `openid profile email` | |
| **Session Secret Key** | `SESSION_SECRET_KEY` | Empty | Set a long random value. |
| **Session Expiry Hours** | `SESSION_EXPIRY_HOURS` | `24` | |
| **Session Max Entries** | `SESSION_MAX_ENTRIES` | `50` | When full, new sign-ins wait; existing sessions stay. |

## Anomaly Detection (Beta)

This beta feature only alerts; it never blocks. It compares what each mailbox sends with its own normal rate and counts failed logins per username. Alerts go to email and your alert destinations and appear on the [Dashboard](Dashboard.md#security-alerts).

| Setting | Variable | Default | Notes |
| --- | --- | --- | --- |
| **Anomaly Detection Enabled** | `ANOMALY_DETECTION_ENABLED` | `false` | |
| **Anomaly Volume Multiplier** | `ANOMALY_VOLUME_MULTIPLIER` | `5` | |
| **Anomaly Volume Min Messages** | `ANOMALY_VOLUME_MIN_MESSAGES` | `30` | |
| **Anomaly Baseline Days** | `ANOMALY_BASELINE_DAYS` | `7` | |
| **Anomaly Auth Failure Threshold** | `ANOMALY_AUTH_FAILURE_THRESHOLD` | `20` | |
| **Anomaly Check Interval** | `ANOMALY_CHECK_INTERVAL` | `15` | Minutes, and the window each check looks at. |
| **Anomaly Alert Cooldown Hours** | `ANOMALY_ALERT_COOLDOWN_HOURS` | `6` | |

## SMTP Abuse (Beta)

This beta feature stops a mailbox from sending when it goes over a limit; receiving is not affected. It needs the read-write API key. The same values, the stopped mailboxes and the whitelist are on the **Outgoing spam** card under **Security** > **Settings**; see [Outgoing spam](Abuse_Protection.md).

| Setting | Variable | Default | Notes |
| --- | --- | --- | --- |
| **SMTP Abuse Enabled** | `SMTP_ABUSE_ENABLED` | `false` | |
| **SMTP Abuse Threshold** | `SMTP_ABUSE_THRESHOLD` | `100` | Messages per mailbox in the window. |
| **SMTP Abuse Window Minutes** | `SMTP_ABUSE_WINDOW_MINUTES` | `60` | |
| **SMTP Abuse Revoke App Passwords** | `SMTP_ABUSE_REVOKE_APP_PASSWORDS` | `true` | |
| **SMTP Abuse Unblock Grace Minutes** | `SMTP_ABUSE_UNBLOCK_GRACE_MINUTES` | `60` | |
| **SMTP Abuse Help Address** | `SMTP_ABUSE_HELP_ADDRESS` | Empty | Empty uses **Admin Email**. |

## Domains

Which sending addresses must pass each domain's SPF check on [Domains](Domains.md), separate from blocklist monitoring. Add only addresses that really send mail: every one must pass, so an inbound-only MX shows as a failure.

| Setting | Variable | Default | Notes |
| --- | --- | --- | --- |
| **Domain SPF Source Server IP** | `DOMAIN_SPF_SOURCE_SERVER_IP` | `true` | The WAN address. Turn off when mail leaves through a relay. |
| **Domain SPF Source Transports** | `DOMAIN_SPF_SOURCE_TRANSPORTS` | `false` | |
| **Domain SPF Source Relayhosts** | `DOMAIN_SPF_SOURCE_RELAYHOSTS` | `false` | |
| **Domain SPF Source Manual Hosts** | `DOMAIN_SPF_SOURCE_MANUAL_HOSTS` | Empty | |
| **Domain SPF Source DMARC History** | `DOMAIN_SPF_SOURCE_DMARC_HISTORY` | `false` | Can raise false warnings with relaxed alignment. |

## DMARC & TLS

**Retention Days**, **Manual Upload Enabled** and **Allow Report Delete** apply to DMARC and TLS reports alike. The **Insights** values only shape the DMARC policy recommendations; nothing here changes your DNS.

| Setting | Variable | Default | Notes |
| --- | --- | --- | --- |
| **Retention Days** | `DMARC_RETENTION_DAYS` | `60` | |
| **Manual Upload Enabled** | `DMARC_MANUAL_UPLOAD_ENABLED` | `true` | |
| **Allow Report Delete** | `DMARC_ALLOW_REPORT_DELETE` | `false` | |
| **DMARC Insights Window Days** | `DMARC_INSIGHTS_WINDOW_DAYS` | `28` | |
| **DMARC Insights Pass Threshold** | `DMARC_INSIGHTS_PASS_THRESHOLD` | `99.5` | Percent. |
| **DMARC Insights Min Volume** | `DMARC_INSIGHTS_MIN_VOLUME` | `100` | |

## DMARC & TLS IMAP

**Test IMAP** logs in with the saved settings, lists the folders and counts the emails in **IMAP Folder** without importing anything. Use a mailbox that only receives reports: the import reads its unread emails and, by default, deletes each one it imports.

| Setting | Variable | Default | Notes |
| --- | --- | --- | --- |
| **IMAP Enabled** | `DMARC_IMAP_ENABLED` | `false` | |
| **IMAP Host** | `DMARC_IMAP_HOST` | Unset | |
| **IMAP Port** | `DMARC_IMAP_PORT` | `993` | |
| **IMAP Use SSL** | `DMARC_IMAP_USE_SSL` | `true` | Off connects without encryption (no STARTTLS). |
| **IMAP Verify SSL** | `DMARC_IMAP_VERIFY_SSL` | `false` | Same choices as **SMTP Verify SSL**. |
| **IMAP User** | `DMARC_IMAP_USER` | Unset | |
| **IMAP Password** | `DMARC_IMAP_PASSWORD` | Unset | |
| **IMAP Folder** | `DMARC_IMAP_FOLDER` | `INBOX` | |
| **IMAP Delete After** | `DMARC_IMAP_DELETE_AFTER` | `true` | Emails that fail to import stay, marked as read. |
| **IMAP Interval** | `DMARC_IMAP_INTERVAL` | `3600` | Seconds. |
| **IMAP Run On Startup** | `DMARC_IMAP_RUN_ON_STARTUP` | `true` | |
| **IMAP Batch Size** | `DMARC_IMAP_BATCH_SIZE` | `10` | |
| **IMAP Scan All Unseen** | `DMARC_IMAP_SCAN_ALL_UNSEEN` | `false` | Also reads unread emails whose subject does not look like a report. |

## MaxMind

A free MaxMind account lets the app download the GeoLite2 City and ASN databases, which turn IP addresses into countries and networks. The **Status** panel shows **License** with **Validate**, **Database Health** and the size and age of each database. **DB Corrupt** comes with **Repair**, which downloads the databases again. The databases update every Sunday at 03:00.

Saving a new license key opens **GeoIP Database Setup**, which checks the key, downloads missing databases and tests them. If a step fails, it says why; click **Close**, fix the account ID or key and save again. After three minutes the window stops waiting for the download; check **Database Health** later.

<!-- SHOT: settings-geoip-setup | GeoIP Database Setup showing the three stages and a download or validation result -->

| Setting | Variable | Default | Notes |
| --- | --- | --- | --- |
| **Maxmind Account Id** | `MAXMIND_ACCOUNT_ID` | Unset | |
| **Maxmind License Key** | `MAXMIND_LICENSE_KEY` | Unset | |

## IP Blacklist (RBL)

Which addresses **Status** > **Blocklists** checks, and the DNS resolver it asks. Spamhaus refuses queries from public resolvers such as Google or Cloudflare, so use your own resolver. Switching on **Blacklist Source Transports** or **Blacklist Source Relayhosts** adds their addresses right away. See [Blocklist monitoring](IP_Blacklist_Monitor.md).

| Setting | Variable | Default | Notes |
| --- | --- | --- | --- |
| **Blacklist Source Server IP** | `BLACKLIST_SOURCE_SERVER_IP` | `true` | The WAN address mailcow reports. |
| **Blacklist Source Transports** | `BLACKLIST_SOURCE_TRANSPORTS` | `true` | |
| **Blacklist Source Relayhosts** | `BLACKLIST_SOURCE_RELAYHOSTS` | `true` | |
| **Blacklist Source Manual Hosts** | `BLACKLIST_SOURCE_MANUAL_HOSTS` | Empty | For example `192.0.2.10,relay.example.com`. |
| **Blacklist DNS Servers** | `BLACKLIST_DNS_SERVERS` | Empty | Empty uses the container's resolver. |

## Spam Filter

Automatic bounce handling for [Spam Filter](Spam_Filter.md). Nothing happens until **Suppression Enabled** is on, even though the other switches start on.

| Setting | Variable | Default | Notes |
| --- | --- | --- | --- |
| **Suppression Enabled** | `SUPPRESSION_ENABLED` | `false` | |
| **Suppression Auto Detect** | `SUPPRESSION_AUTO_DETECT` | `true` | |
| **Suppression Rspamd Sync** | `SUPPRESSION_RSPAMD_SYNC` | `true` | Needs the Rspamd password and the read-write key. |
| **Suppression Hard Bounce Action** | `SUPPRESSION_HARD_BOUNCE_ACTION` | `suppress` | |
| **Suppression Soft Bounce Action** | `SUPPRESSION_SOFT_BOUNCE_ACTION` | `count` | Used only while **Queue Cleanup Enabled** is off. |
| **Suppression Soft Bounce Threshold** | `SUPPRESSION_SOFT_BOUNCE_THRESHOLD` | `3` | Used only while **Queue Cleanup Enabled** is off. |
| **Queue Cleanup Enabled** | `QUEUE_CLEANUP_ENABLED` | `true` | Needs the read-write key. |
| **Queue Cleanup Threshold Minutes** | `QUEUE_CLEANUP_THRESHOLD_MINUTES` | `60` | |
| **Suppression Base Expiry Days** | `SUPPRESSION_BASE_EXPIRY_DAYS` | `7` | Multiplied by the number of bounces. |
| **Suppression Max Expiry Days** | `SUPPRESSION_MAX_EXPIRY_DAYS` | `90` | |
| **Suppression Whitelist Domains** | `SUPPRESSION_WHITELIST_DOMAINS` | Empty | |

## Quarantine

Limits for the rules on **Quarantine** > **Rules**.

| Setting | Variable | Default | Notes |
| --- | --- | --- | --- |
| **Quarantine Rules Max Actions** | `QUARANTINE_RULES_MAX_ACTIONS` | `50` | Most messages released or deleted in one run. |
| **Quarantine Rules Interval** | `QUARANTINE_RULES_INTERVAL` | `5` | Minutes. |
| **Quarantine Rules Log Retention Days** | `QUARANTINE_RULES_LOG_RETENTION_DAYS` | `30` | |

## Devices

| Setting | Variable | Default | Notes |
| --- | --- | --- | --- |
| **Retention Days** | `EAS_DEVICES_RETENTION_DAYS` | `90` | Days a device that stopped syncing stays on [Devices](Devices.md). `0` keeps every device. |

## When something is missing

- **Every field is read-only**: the settings are not migrated yet. Click **Migrate Settings from ENV**.
- **A category is missing**: its feature is off. Turn it on under **Features**.
- **A field shows Set by ENV**: change it in `.env` and recreate the app. A password set this way reads **Stored in the environment**.
- **Saving says a password is set by an environment variable**: you changed the server it is sent to. Change the server in `.env` too, or undo the change.
- **The app stops at startup with a settings error**: it could not read the saved settings from the database. It stops rather than start with your saved sign-in turned off, and starts once the database answers.

PostgreSQL values, `SETTINGS_EDIT_VIA_UI_ENABLED`, `CORS_ALLOWED_ORIGINS`, `TZ` and the container options are set only in the environment; see [Environment variables](../ENV_Settings.md).
