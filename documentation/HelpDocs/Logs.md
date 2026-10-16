# Logs

The Logs page shows the raw log lines of each mailcow service: live as they arrive, and back through the lines the app has stored. A background job reads the logs through the mailcow API every 30 seconds by default, keeps them for 2 days, and streams new lines to the open page.

![Logs](../../images/docs/logs-light.webp#gh-light-mode-only)
![Logs](../../images/docs/logs-dark.webp#gh-dark-mode-only)

## Services

The **Service** column on the left lists the services that are switched on under **Settings** > **Logs**, each with the number of lines stored for it (shown in thousands as `K` above 999). The page opens on Postfix, or on the first service in the list when Postfix is off. A click opens another service.

| Service | What its log holds |
|---|---|
| **Postfix** | Mail sent and received (MTA) |
| **Rspamd** | Spam filter verdicts |
| **Dovecot** | IMAP and POP3 logins and mail delivery |
| **SOGo** | Webmail, calendars, contacts and ActiveSync |
| **Netfilter** | Fail2ban bans and failed logins |
| **Ratelimited** | Senders that hit a rate limit |
| **ACME** | TLS certificate renewals |
| **API** | Requests to the mailcow API |
| **Autodiscover** | Mail client setup requests |
| **Watchdog** | Container health checks |

On a narrow screen the column folds into one row that names the open service and its count. Tap it to choose another service.

## The log view

Entries show their time, program and message. Timestamps follow the [shared time-zone rules](../Using_the_App.md#shared-behavior). Line colors follow keywords:

- Red: the message contains reject, error, blocked, denied, failed or fatal.
- Yellow: warning, pregreet or timeout.
- Green: sent, connect from, login, delivered or success.
- Grey: disconnect, removed or noqueue.

Three services have their own line format:

- **Rspamd:** sender and recipients, the subject, the score in brackets and the action, then the client IP. The score is red from the reject threshold (15 when the line does not say), orange from the add header threshold (8 when the line does not say), yellow from 0, and green below 0.
- **API:** the HTTP method (GET green, POST yellow, PUT blue, DELETE red), the address that was called, the client it came from and the first 200 characters of the data.
- **Watchdog:** the container, its health points now and in total, the change since the last check and its level. The line is red when the health dropped or the level is above 200, and yellow above 100.

A service starts with its newest 500 lines. Scroll to the oldest end for 500 more. The live stream adds new entries and limits the view to 5000 lines.

The status bar shows **Connected**, **Paused** or **Disconnected**, loaded and stored counts, the last arrival time and the service.

## Toolbar

| Button | What it does |
|---|---|
| **Pause** / **Resume** | Stops the live stream, and starts it again. While paused no new lines arrive. |
| **Live** | Goes back to live mode: clears a loaded time range, reloads the newest lines and reconnects the stream. It is shown pressed while you are live. |
| **Auto-scroll** | Keeps the newest line in view as new lines arrive. On by default. |
| **Newest last** / **Newest first** | Puts the newest line at the bottom, as `tail -f` does, or at the top. The browser remembers the order. |
| Font size | Changes the log text size. |
| **Wrap** | Wraps long lines. Off, a long line scrolls sideways. On by default. |
| **Clear** | Empties the view ("Display cleared. New logs will appear here."), and clears the search, the quick filters and the time range. Older lines are not loaded back; new live lines appear as they come. |

### Search

"Search logs..." filters loaded lines when you press Enter or the search button. It searches program and message text, plus structured fields such as Rspamd addresses, subject and action or API request data.

The filter badge gives matching and loaded counts. Its close button, **Clear search**, or an empty search clears both text and quick filters.

The search does not ask the server. To search further back, load a longer time range first.

## Range

**Range:** loads every stored line of a period, replacing the view:

- **1h**, **6h**, **24h** and **48h** load the period up to now.
- **Custom** opens **From date** and **To date** fields with date and time, and **Load**.

<!-- VERIFY: while a time range is loaded the stream stays connected (loadDateRangeLogs does not disconnect it), so new live lines may still be added at the end of the range. Check in the browser and say so if they are. -->

Ranges load in pages of 1000 with progress. The existing live stream stays connected, so newer entries can appear outside the requested range. Use **Pause** for a fixed historical view, or **Live** to reload the latest lines. Only retained logs are available (2 days by default).

## Quick Filters

For Postfix, **Quick Filters:** offers chips that pick out common kinds of lines. They filter the lines loaded in the view.

| Chip | Shows lines where |
|---|---|
| **Postscreen** | The program is `postfix/postscreen` (connection screening before SMTP) |
| **NOQUEUE Reject** | The message contains `NOQUEUE: reject` (refused before it got a queue ID) |
| **DNSBL Block** | The message contains `blocked using` (refused because of a DNS blocklist) |
| **Pregreet** | The message contains `PREGREET` (the client spoke before the server greeted it) |
| **Sender Restriction** | The message contains `Sender address rejected` |
| **Recipient Restriction** | The message contains `Recipient address rejected` |
| **Relay Denied** | The message contains `Relay access denied` |
| **Connections** | The message contains `CONNECT` |

Multiple chips match with OR; text search and chips match with AND. **Show all 8** expands collapsed filters, and **Show less** folds them. Selected chips remain visible.

## The live stream

The WebSocket stream at `/ws/raw-logs` opens with a service and closes when you leave Logs. Dropped connections retry after 3 seconds unless paused.

- With sign-in on, the stream gets a one-time token that is valid for 30 seconds. When your session ends (you sign out in another tab, it expires, or the sign-in settings change), the stream closes. A page that is still signed in reconnects by itself; otherwise it goes to the login page.
- The stream is refused when the request comes from another website's page.
- Behind a reverse proxy, the proxy must pass WebSocket connections for `/ws/raw-logs`. See [Reverse proxy](../Reverse_Proxy.md).

## Settings that change this page

All of these are under **Settings** > **Logs**, except the feature switch.

| Setting | Default | Effect |
|---|---|---|
| **Raw Logs Enabled** (`RAW_LOGS_ENABLED`) | On | Collects the services ticked under Services for this page. Off, the page shows **Live Log Viewer is Disabled** instead of logs. |
| **Raw Logs Fetch Interval** (`RAW_LOGS_FETCH_INTERVAL`) | 30 seconds | How often the logs are read from mailcow. |
| **Raw Logs Fetch Count** (`RAW_LOGS_FETCH_COUNT`) | 1000 | Lines read per service in each fetch. For Postfix and Rspamd the app also reads further back when more lines arrived than one fetch holds, up to 10 extra pages per fetch. |
| **Raw Logs Retention Days** (`RAW_LOGS_RETENTION_DAYS`) | 2 | Days the lines are kept. Older lines are deleted every day at 3:00. |
| **Raw Logs Services** (`RAW_LOGS_SERVICES`) | All ten | The services this page shows, one switch per service. In the environment variable, a comma-separated list or `all`. |

Some services are read by other pages too. Their rows say "Always collected for" and the page names:

- **Dovecot** for **Message details** (the mailbox delivery and Sieve results) and **Security** (the alert on a login after failed attempts).
- **Ratelimited** for **Rate Limits**.
- **SOGo** for **Devices**.

These services keep being collected while their dependent pages need them, even if hidden here. Dovecot always supports message details. Ratelimited and SOGo stop only when neither Logs nor Rate Limits or Devices needs them. An environment value for `RAW_LOGS_SERVICES` locks the switches.

Turning off the **Logs** feature under **Settings** > **Features** removes the page from the menu and stops collecting the services only this page uses.

## When something is missing

- **"Live Log Viewer is Disabled".** **Raw Logs Enabled** is off. The switch is under **Settings** > **Logs**. **Open Settings** goes to Settings.
- **"No log services available".** No service is switched on under **Settings** > **Logs** > **Services**.
- **No log entries found.**: wait for collection. A service your mailcow version does not offer stays empty; a fetch failure can also delay entries.
- **The dot is red and says Disconnected.** The page retries dropped connections every 3 seconds, but stops after authentication is refused. Sign in again if needed; for repeated connection failures, check WebSocket proxy forwarding.
- **"Failed to load logs" or "Failed to load log services" with an error.** The app's database or server did not answer. **View Container Logs** in the sidebar tools shows the error.
- **Older lines are gone.** They are older than **Raw Logs Retention Days**.
