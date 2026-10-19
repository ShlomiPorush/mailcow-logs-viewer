# Settings

Values you save here are stored in the viewer's database. A value set by an environment variable always wins over them.

## Enable editing and migrate from ENV

Until `SETTINGS_EDIT_VIA_UI_ENABLED=true` is set, the page only shows the current values, with **Test SMTP** and **Test IMAP**.

To edit settings here:

1. Set `SETTINGS_EDIT_VIA_UI_ENABLED=true` in `.env` and recreate the app with `docker compose up -d`. A plain restart keeps the old environment.
2. Click **Migrate Settings from ENV** and confirm. This copies the current configuration into the database; until then every field stays read-only.
3. Remove from `.env` the variables you want to manage here. Keep `MAILCOW_URL`, `MAILCOW_API_KEY`, the `POSTGRES_*` values and `SETTINGS_EDIT_VIA_UI_ENABLED`: the app needs them before it can read the database.
4. Recreate the app again. A field whose variable is still set shows **Set by ENV** and stays locked, even when the variable is empty (`SMTP_HOST=`).

![Settings before migration](../../images/docs/settings-env-migration-light.webp#gh-light-mode-only)
![Settings before migration](../../images/docs/settings-env-migration-dark.webp#gh-dark-mode-only)

If you later turn `SETTINGS_EDIT_VIA_UI_ENABLED` off, the app ignores the saved values, so put your sign-in settings back into `.env` first.

## Edit and save

**Save changes** saves the changes in every category at once. **Changed** next to a field means it differs from the default, not from the last save.

Passwords and keys are never shown. A stored one reads **Stored**, with **Replace** and **Remove**. If you change the server a password is sent to, such as the SMTP host or the mailcow URL, enter the password again in the same save; the app never sends a stored password to a new server.

Most changes apply when you save. A change to the features, the app title or logo, sign-in or the mailcow URL reloads the page. A change to sign-in settings signs out every other session; you stay signed in.

![Settings, Mailcow](../../images/docs/settings-mailcow-light.webp#gh-light-mode-only)
![Settings, Mailcow](../../images/docs/settings-mailcow-dark.webp#gh-dark-mode-only)

Every field is also an environment variable, for example **App Title** is `APP_TITLE`. [Environment variables](../ENV_Settings.md) lists them with their defaults.

## Features

All features are on by default. A feature that is off disappears from the menu, stops the background jobs used only by it and hides its category here; shared jobs continue while another enabled page needs them. Its API routes remain available. The **Logs** category stays, because the logs other pages read are collected and kept by its settings: with the Logs page off, Dovecot still comes in for message details and Security, Ratelimited for Rate Limits and SOGo for Devices. The switches are saved in `DISABLED_FEATURES`; if that variable is set, the whole list is locked.

> [!WARNING]
> Turning a feature off deletes the data the viewer stored for it, such as DMARC reports, quarantine rules or device history. Saving asks first (**Disable & Delete Data**); only Queue, which stores nothing, switches off without asking. The same happens at startup to a feature listed in `DISABLED_FEATURES`. Turning a feature on again reloads only what is still on the server: Spam Filter loads back the blocks this app left in Rspamd (as **From Rspamd** entries), the others fetch or check again. Turning Security off takes out of Fail2ban only this app's temporary bans; permanent bans and bans added outside the app stay.

## Application

**Time Zone** is the time zone the whole app works in; see [Using the app](../Using_the_App.md#time-zone). Saving a new one reloads the page and moves the scheduled jobs at once. The port is set in `docker-compose.yml`, not here.

## Mailcow

**Validate** in the **Status** panel checks the read-write API key and the Rspamd password without changing anything in mailcow. Saving a new key or password runs the check by itself.

## Logs

Collection for the [Logs](Logs.md) page. A service marked **Always collected for** another page keeps coming in even when you switch it off here; only the Logs page stops showing it.

## Notifications

For **Alert destinations** (Slack, Telegram, ntfy and others) and which alert goes where, see [Notifications](../Notifications.md). The address fields take several addresses separated by commas.

## SMTP

**Test SMTP** sends a real test email to **Admin Email** (or to **SMTP User** when that is empty) using the saved settings, and shows each step of the connection. Save your changes before you test.

For port 587, turn on **SMTP Use TLS** (STARTTLS); port 465 always uses implicit TLS. **SMTP Verify SSL** checks the server's certificate: **Automatic** checks host names such as `smtp.example.com` and skips `localhost`, IP addresses and container names. Keep **Off** only for a self-signed certificate.

## Authentication

Basic authentication and OAuth2/OIDC can be on together. Turning on **Basic Auth Enabled** asks you to type the username and password again before it saves, so a typo cannot lock you out. See [Sign-in configuration](../OAuth2_Configuration.md).

## Anomaly Detection (Beta)

This beta feature only alerts; it never blocks. It compares what each mailbox sends with its own normal rate and counts failed logins per username. Alerts go to email and your alert destinations and appear on the [Dashboard](Dashboard.md#security-alerts).

## SMTP Abuse (Beta)

This beta feature stops a mailbox from sending when it goes over a limit. The mailbox still receives mail; if its app passwords are revoked too, mail apps that sign in with one stop working. It needs the read-write API key. The same values, the stopped mailboxes and the whitelist are on the **Outgoing spam** card under **Security** > **Settings**; see [Outgoing spam](Abuse_Protection.md).

## Domains

Which sending addresses must pass each domain's SPF check on [Domains](Domains.md), separate from blocklist monitoring. Add only addresses that really send mail: every one must pass, so an inbound-only MX shows as a failure.

## DMARC & TLS

**Retention Days**, **Manual Upload Enabled** and **Allow Report Delete** apply to DMARC and TLS reports alike. The **Insights** values only shape the DMARC policy recommendations; nothing here changes your DNS.

## DMARC & TLS IMAP

**Test IMAP** logs in with the saved settings, lists the folders and counts the emails in **IMAP Folder** without importing anything. Use a mailbox that only receives reports: the import reads its unread emails and, by default, deletes each one it imports.

## MaxMind

A free MaxMind account lets the app download the GeoLite2 City and ASN databases, which turn IP addresses into countries and networks. The databases update every Sunday at 03:00; saving or removing the license key adds or removes that update at once. **Repair**, shown with **DB Corrupt**, downloads the databases again.

Saving a new license key opens **GeoIP Database Setup**, which checks the key, downloads missing databases and tests them. If a step fails, fix the account ID or key and save again. After three minutes the window stops waiting for the download; check **Database Health** later.

![GeoIP Database Setup](../../images/docs/settings-geoip-setup-light.webp#gh-light-mode-only)
![GeoIP Database Setup](../../images/docs/settings-geoip-setup-dark.webp#gh-dark-mode-only)

## IP Blacklist (RBL)

Which addresses **Status** > **Blocklists** checks, and the DNS resolver it asks. Spamhaus refuses queries from public resolvers such as Google or Cloudflare, so use your own resolver. Switching on **Blacklist Source Transports** or **Blacklist Source Relayhosts** adds their addresses right away. See [Blocklist monitoring](IP_Blacklist_Monitor.md).

## Queue Management

What happens when outgoing mail cannot be delivered. The blocked addresses are listed on [Spam Filter](Spam_Filter.md) > **Suppressions**. **Sync with Rspamd** (on by default) keeps the list and this app's Rspamd blocks in step, both ways; off, the list does not change what Rspamd blocks. Nothing is blocked automatically until **Handle undeliverable mail automatically** is on (off by default).

- **Permanent delivery failure** (5.x.x) and **Temporary delivery failure** (4.x.x) are one choice each. A temporary failure is deleted after its minutes in the queue (the default), or stays in the queue while the address is blocked after a number of failures, at the first one, or not at all.
- The app reads the Postfix logs only when a choice needs them.
- A value set in the environment closes only the options it rules out, and the choice names the variable.

## Quarantine

Limits for the rules on **Quarantine** > **Auto-Rules**. A new **Quarantine Rules Interval** applies when you save it.

## When something is missing

- **Every field is read-only**: the settings are not migrated yet. Click **Migrate Settings from ENV**.
- **A category is missing**: its feature is off. Turn it on under **Features**.
- **A field shows Set by ENV**: change it in `.env` and recreate the app. A password set this way reads **Stored in the environment**.
- **Saving says a password is set by an environment variable**: you changed the server it is sent to. Change the server in `.env` too, or undo the change.
- **The app stops at startup with a settings error**: it could not read the saved settings from the database. It stops rather than start with your saved sign-in turned off, and starts once the database answers.

PostgreSQL values, `SETTINGS_EDIT_VIA_UI_ENABLED`, `CORS_ALLOWED_ORIGINS` and the container options are set only in the environment; see [Environment variables](../ENV_Settings.md).
