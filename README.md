# mailcow Logs Viewer

A self-hosted dashboard for mailcow mail servers. Read message delivery logs, security events, DNS checks, DMARC and TLS reports, queue and quarantine data from one app. A read-write API key also lets you ban addresses, release mail, manage the queue and edit Rspamd maps.

![Dashboard](images/Main-light.png#gh-light-mode-only)
![Dashboard](images/Main-dark.png#gh-dark-mode-only)

## What it does

| Page | What you get |
|---|---|
| [Dashboard](documentation/HelpDocs/Dashboard.md) | What needs attention now, mail flow of the last 24 hours, security alerts with the activity behind them, server health. |
| [Messages](documentation/HelpDocs/Messages.md) | Messages linked across Postfix, Rspamd and Dovecot, with filters, delivery details and CSV export. |
| [Queue](documentation/HelpDocs/Queue.md) | The Postfix queue with the reason each message is waiting. Flush, hold, release and delete. |
| [Quarantine](documentation/HelpDocs/Quarantine.md) | Quarantined mail with its spam score and symbols. Release or delete, and rules that do it for you. |
| [Security](documentation/HelpDocs/Security.md) | Every address that tried to log in and what was done about it. Fail2ban settings, allowlist and denylist, and protection rules that catch trap accounts, unknown accounts, repeat offenders, attacking networks and countries. |
| [Outgoing spam](documentation/HelpDocs/Abuse_Protection.md) | Turns off sending for a mailbox that sends far more than you allow, and tells you. |
| [Spam Filter](documentation/HelpDocs/Spam_Filter.md) | Suppression of recipients that keep bouncing, and an editor for mailcow's Rspamd maps. |
| [DMARC & TLS](documentation/HelpDocs/DMARC.md) | DMARC and TLS reports per domain and sender, imported from a mailbox or uploaded, with what to fix before a stricter policy. |
| [Domains](documentation/HelpDocs/Domains.md) | SPF, DKIM, DMARC, MTA-STS, DNSSEC and DANE checks for every domain, with alerts when a record changes. |
| [Status](documentation/HelpDocs/Status.md) | Containers, storage, background jobs and [blocklist checks](documentation/HelpDocs/IP_Blacklist_Monitor.md) for your sending addresses. |
| [Mailbox Stats](documentation/HelpDocs/Mailbox_Stats.md) | Sent and received mail per mailbox and alias, quota, last logins, and [rate limits](documentation/HelpDocs/Rate_Limits.md). |
| [Devices](documentation/HelpDocs/Devices.md) | Phones, tablets and Outlook clients that sync over ActiveSync. |
| [Logs](documentation/HelpDocs/Logs.md) | Live and past logs of ten mailcow services. |
| [Notifications](documentation/Notifications.md) | Alerts by email and to Slack, Discord, Telegram, ntfy, Gotify or your own webhook. |

Configure the app with [environment variables](documentation/ENV_Settings.md). To edit supported settings in the browser, enable and migrate [Settings](documentation/HelpDocs/Settings.md); environment values take priority. Sign in with [Basic authentication or OAuth2/OIDC](documentation/OAuth2_Configuration.md). The interface has light and dark themes and a phone layout.

![Messages](images/Messages-light.png#gh-light-mode-only)
![Messages](images/Messages-dark.png#gh-dark-mode-only)

![Message Logs](images/Message_Details_Logs-light.png#gh-light-mode-only)
![Message Logs](images/Message_Details_Logs-dark.png#gh-dark-mode-only)

![Security](images/Security-light.png#gh-light-mode-only)
![Security](images/Security-dark.png#gh-dark-mode-only)

![Domains](images/Domains-light.png#gh-light-mode-only)
![Domains](images/Domains-dark.png#gh-dark-mode-only)

![Rate Limits](images/Rate_Limits-light.png#gh-light-mode-only)
![Rate Limits](images/Rate_Limits-dark.png#gh-dark-mode-only)

![Status](images/Status-light.png#gh-light-mode-only)
![Status](images/Status-dark.png#gh-dark-mode-only)

## Quick start

You need Docker with Docker Compose, and a mailcow server with a read-only API key, created in the mailcow admin interface under **System** > **Configuration** > **Access** > **Administrators** > **API**.

1. Create a directory and save [docker-compose.yml](docker-compose.yml) and [env.example](env.example) in it.
2. Copy `env.example` to `.env` and set at least `MAILCOW_URL`, `MAILCOW_API_KEY` and `POSTGRES_PASSWORD`. Turn on sign-in (`BASIC_AUTH_ENABLED=true` with `AUTH_USERNAME` and `AUTH_PASSWORD`), since anyone who can open the app can read all mail logs.
3. Start it with `docker compose up -d` and open `http://<your-server>:8080`.

The full steps, the read-write key and updating are in [Getting started](documentation/GETTING_STARTED.md). To serve the app over HTTPS, see [Reverse proxy](documentation/Reverse_Proxy.md).

The Compose file uses the `latest` release image. Pin a version tag to control upgrades.

## Documentation

The documentation is also published at [shlomiporush.github.io/mailcow-logs-viewer](https://shlomiporush.github.io/mailcow-logs-viewer/), and each page's help opens from the help button next to its title in the app.

- [Getting started](documentation/GETTING_STARTED.md)
- [Using the app](documentation/Using_the_App.md)
- [Settings](documentation/HelpDocs/Settings.md)
- [Environment variables](documentation/ENV_Settings.md)
- [Sign-in: Basic authentication and OAuth2/OIDC](documentation/OAuth2_Configuration.md)
- [Reverse proxy](documentation/Reverse_Proxy.md)
- [Notifications](documentation/Notifications.md)
- [API](documentation/API.md)
- [Upgrading from v1 to v2](documentation/UpdateV2.md)
- [Changelog](CHANGELOG.md)

## Help and issues

- The app's own log: `docker compose logs app`, or **View Container Logs** at the bottom of the sidebar.
- Health check: `http://<your-server>:8080/api/health`.
- Bugs and feature requests: [open an issue](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues).

## License

MIT License.

## Credits

- Flag icons from [Flagpedia.net](https://flagpedia.net/).
- This product includes GeoLite2 data created by MaxMind, available from [https://www.maxmind.com](https://www.maxmind.com).
