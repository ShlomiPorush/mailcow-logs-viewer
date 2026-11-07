# Logs

Raw service logs are collected from mailcow every 30 seconds and kept for 2 days by default. New lines stream to the open page.

![Logs](../../images/docs/logs-light.webp#gh-light-mode-only)
![Logs](../../images/docs/logs-dark.webp#gh-dark-mode-only)

## Services

Service counts are stored lines, not messages. The page opens on Postfix, or the first enabled service if Postfix is off. Configure the services under **Settings** > **Logs**.

## The log view

For ordinary log lines, colors follow keywords, checked in this order:

- Red: reject, error, blocked, denied, failed or fatal.
- Yellow: warning, pregreet or timeout.
- Green: sent, connect from, login, delivered or success.
- Grey: disconnect, removed or noqueue.

Special formats use other rules:

- **Rspamd** scores are red from the reject threshold (15 if absent), orange from the add-header threshold (8 if absent), yellow from 0 and green below 0.
- **API** colors the HTTP method: GET green, POST yellow, PUT blue and DELETE red. Request data is limited to the first 200 characters.
- **Watchdog** shows current and total health points, their change and the level. Lines turn red when health drops or the level exceeds 200, yellow above 100.

A service starts with its newest 500 lines. Scrolling to the oldest end loads 500 more. The live stream limits the view to 5000 lines.

## Toolbar

**Pause** stops incoming lines. **Live** clears a loaded time range, reloads the newest lines and reconnects the stream.

**Clear** empties the display and resets the search, quick filters and time range. It does not delete stored logs. Older lines are not loaded back automatically; new live lines appear as they arrive.

### Search

Search runs on Enter and matches program and message text plus structured fields such as Rspamd addresses, subject and action or API request data.

It searches only loaded lines, without asking the server. Load a longer time range to search further back. The filter count compares matching lines with loaded lines, not all stored logs. Clearing search also clears quick filters.

## Range

A range replaces the view with retained lines for that period. Presets end at now; custom ranges accept dates and times. Ranges load in batches of 1000.

New live lines are not added to a loaded range. Use **Live** to return to the latest lines. Retention still applies, even when you request an older range.

## Quick Filters

Postfix quick filters search only loaded lines. Multiple chips match with OR; the text search and chips match with AND.

**Postscreen** covers connection screening before SMTP. **NOQUEUE Reject** means a message was refused before receiving a queue ID. **DNSBL Block** finds blocklist refusals; **Pregreet** finds clients that spoke before the server greeted them.

## The live stream

Dropped connections retry after 3 seconds unless paused. A session ending closes the stream; it reconnects if you are still signed in, otherwise returns to login.

A reverse proxy must forward WebSocket connections for `/ws/raw-logs`. See [Reverse proxy](../Reverse_Proxy.md).

## Settings that change this page

Under **Settings** > **Logs**:

| Setting | Default | Effect |
|---|---|---|
| **Raw Logs Enabled** (`RAW_LOGS_ENABLED`) | On | Collects the selected services for this page. Off, the viewer is disabled. |
| **Raw Logs Fetch Interval** (`RAW_LOGS_FETCH_INTERVAL`) | 30 seconds | How often mailcow logs are fetched. |
| **Raw Logs Fetch Count** (`RAW_LOGS_FETCH_COUNT`) | 1000 | Lines fetched per service. Postfix and Rspamd can read up to 10 extra pages when one fetch is not enough. |
| **Raw Logs Retention Days** (`RAW_LOGS_RETENTION_DAYS`) | 2 | Days retained. Cleanup runs daily at 3:00. |
| **Rate Limits Retention Days** (`RATE_LIMITS_RETENTION_DAYS`) | 90 | Days the Ratelimited lines are kept, for **Rate Limits**. Never less than Raw Logs Retention Days. |
| **Raw Logs Services** (`RAW_LOGS_SERVICES`) | All ten | A comma-separated service list, or `all`. An environment value locks the UI switches. |

Some services remain collected even when hidden here or the Logs feature is off:

- Dovecot always supplies message details, and also Security when enabled.
- Ratelimited supplies Rate Limits when enabled.
- SOGo supplies Devices when enabled.

Ratelimited and SOGo stop only when neither Logs nor their dependent feature needs them. Turning off Logs under **Settings** > **Features** stops collecting services used only by this page. The Logs settings remain available because they also control collection and retention for the other pages.

## When something is missing

- **Live Log Viewer is Disabled.** Enable **Raw Logs Enabled** under **Settings** > **Logs**.
- **No log services available.** Enable a service under **Settings** > **Logs** > **Services**.
- **No log entries found.** Wait for collection. A service your mailcow version does not offer stays empty; fetch failures can also delay entries.
- **Disconnected.** Check sign-in and WebSocket proxy forwarding. Authentication refusal stops automatic retries.
- **Failed to load logs** or **Failed to load log services.** Check **View Container Logs** for database or server errors.
- Older lines may have expired under **Raw Logs Retention Days**.
