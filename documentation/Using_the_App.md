# Using the app

## Sidebar

- The server card at the top shows the mailcow connection and the number of problems. A problem is a lost connection to mailcow, a stopped container or a listing on a blocklist. The card opens [Status](HelpDocs/Status.md).
- The counters next to the pages count messages in the queue, quarantined messages, failed logins of the last 24 hours (**Security**), DMARC domains with a recommendation (**DMARC & TLS**) and problems (**Status**). They update every 5 minutes and when you press **Refresh**.
- **View Container Logs** at the bottom shows the last 500 lines of this app's own log. Look there first when something in the app fails.

## Refresh

**Refresh** reloads the open page and the sidebar counters; on DMARC & TLS it also clears cached report figures. The Dashboard, Messages, Security, Queue, Quarantine, Status, Settings and Spam Filter pages also update every 30 seconds while they are open, except while message details are open in a window over the page. Other pages update when reopened or refreshed manually.

## Feature switches

Turning a feature off under **Settings** > **Features** hides its page and asks before deleting feature data, such as Security logs, DMARC and TLS reports or quarantine rules; jobs and data needed by other enabled features stay. See [Settings](HelpDocs/Settings.md#features).

## Signing in and out

Sign-in is set up in **Settings** > **Authentication**; see [Sign-in](OAuth2_Configuration.md). When a session expires, you return to the page you were on after you sign in again. Restarting or updating the app signs everyone out.

With no sign-in configured, the Dashboard shows **Authentication is off**. **Dismiss** hides the banner in this browser, for setups where a reverse proxy in front of the app already signs users in.

## The read-write API key

Changing mailcow needs the read-write API key (`MAILCOW_API_KEY_RW`): queue and quarantine actions, bans, rate limits and Rspamd maps. Without it, these areas show a lock and **Open Settings**, and the data stays readable. Add the key under **Settings** > **Mailcow**.

## Time zone

The app shows times in the time zone set by `TZ` in `.env`, for example `TZ=Europe/Berlin`. Without `TZ`, or with `TZ=UTC`, it shows them in your browser's time zone.

Exceptions:

- The date filters on Messages and the activity chart of a security alert always use your browser's time zone.
- Mailbox Stats counts whole days in `TZ`, or in UTC when `TZ` is not set.

## Copying

Values with a copy icon copy on click. The browser allows this only over HTTPS or on `localhost`; over plain HTTP, select the text and copy it yourself.
