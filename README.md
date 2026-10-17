# mailcow Logs Viewer

A self-hosted dashboard for mailcow mail servers. It collects mailcow's logs and reports into one place, so you can see what happened to every message, who is attacking the server and whether your domains are set up right. With a read-write API key it can also act: ban addresses, release mail, manage the queue and edit Rspamd maps.

![Dashboard](images/Main-light.png#gh-light-mode-only)
![Dashboard](images/Main-dark.png#gh-dark-mode-only)

## Features

- Follow every message from arrival to delivery, with its spam score and full log, and export the list to CSV.
- See the mail queue and the quarantine, and act on them. Rules can release or delete quarantined mail for you.
- See failed logins, ban and unban addresses, and use protection rules to block attackers based on trap-account hits, repeat bans, network or country.
- Turn off sending for a mailbox that sends more mail than you allow.
- Read DMARC and TLS reports, and find out what to fix before you move to a stricter DMARC policy.
- Check SPF, DKIM, DMARC, MTA-STS, DNSSEC and DANE for every domain, and get an alert when a record changes.
- Watch containers, storage, background jobs and blocklist listings of your sending addresses.
- Per-mailbox mail counts, quota and rate limits, ActiveSync devices, and live logs of mailcow's services.
- Alerts by email, Slack, Discord, Telegram, ntfy, Gotify or your own webhook.
- Sign-in with a password or OAuth2/OIDC, light and dark themes, and a phone layout.

## Screenshots

<div class="gallery" markdown>

**Messages**
![Messages](images/docs/messages-light.webp#gh-light-mode-only)
![Messages](images/docs/messages-dark.webp#gh-dark-mode-only)

**Queue**
![Queue](images/docs/queue-light.webp#gh-light-mode-only)
![Queue](images/docs/queue-dark.webp#gh-dark-mode-only)

**Quarantine**
![Quarantine](images/docs/quarantine-messages-light.webp#gh-light-mode-only)
![Quarantine](images/docs/quarantine-messages-dark.webp#gh-dark-mode-only)

**Security**
![Security](images/docs/security-overview-light.webp#gh-light-mode-only)
![Security](images/docs/security-overview-dark.webp#gh-dark-mode-only)

**DMARC & TLS**
![DMARC & TLS](images/docs/dmarc-domain-light.webp#gh-light-mode-only)
![DMARC & TLS](images/docs/dmarc-domain-dark.webp#gh-dark-mode-only)

**Domains**
![Domains](images/docs/domains-open-light.webp#gh-light-mode-only)
![Domains](images/docs/domains-open-dark.webp#gh-dark-mode-only)

**Status**
![Status](images/docs/status-server-light.webp#gh-light-mode-only)
![Status](images/docs/status-server-dark.webp#gh-dark-mode-only)

**Spam Filter**
![Spam Filter](images/docs/spam-filter-maps-light.webp#gh-light-mode-only)
![Spam Filter](images/docs/spam-filter-maps-dark.webp#gh-dark-mode-only)

**Mailbox Stats**
![Mailbox Stats](images/docs/mailbox-stats-statistics-light.webp#gh-light-mode-only)
![Mailbox Stats](images/docs/mailbox-stats-statistics-dark.webp#gh-dark-mode-only)

</div>

## Quick start

You need Docker with Docker Compose, and a mailcow server with a read-only API key, created in the mailcow admin interface under **System** > **Configuration** > **Access** > **Administrators** > **API**.

1. In mailcow, add `always_add_missing_headers = yes` to `data/conf/postfix/extra.cf` and restart Postfix. Without a Message-ID on every message, much of the app cannot link the logs of a message; see [Getting started](documentation/GETTING_STARTED.md#2-make-postfix-add-a-message-id).
2. Create a directory and save [docker-compose.yml](docker-compose.yml) and [env.example](env.example) in it.
3. Copy `env.example` to `.env` and set at least `MAILCOW_URL`, `MAILCOW_API_KEY` and `POSTGRES_PASSWORD`. Turn on sign-in (`BASIC_AUTH_ENABLED=true` with `AUTH_USERNAME` and `AUTH_PASSWORD`), since anyone who can open the app can read all mail logs.
4. Start it with `docker compose up -d` and open `http://<your-server>:8080`.

The full steps are in [Getting started](documentation/GETTING_STARTED.md). To serve the app over HTTPS, see [Reverse proxy](documentation/Reverse_Proxy.md).

## Documentation

The documentation is published at [shlomiporush.github.io/mailcow-logs-viewer](https://shlomiporush.github.io/mailcow-logs-viewer/). In the app, the help button next to a page title opens that page's help.

- [Getting started](documentation/GETTING_STARTED.md)
- [Using the app](documentation/Using_the_App.md)
- [Settings](documentation/HelpDocs/Settings.md)
- [Environment variables](documentation/ENV_Settings.md)
- [Sign-in: Basic authentication and OAuth2/OIDC](documentation/OAuth2_Configuration.md)
- [Reverse proxy](documentation/Reverse_Proxy.md)
- [Notifications](documentation/Notifications.md)
- [API](documentation/API.md)
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
