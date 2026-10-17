# Using the app

What works the same on every page.

## Sidebar

- The server card at the top shows the mailcow connection and the number of problems. A problem is a lost connection to mailcow, a stopped container or a listing on a blocklist. The card opens [Status](HelpDocs/Status.md).
- The counters next to the pages count messages in the queue, quarantined messages, failed logins of the last 24 hours (**Security**), DMARC domains with a recommendation (**DMARC & TLS**) and problems (**Status**). They update every 5 minutes and when you press **Refresh**.
- The foot of the sidebar shows this app's version and the mailcow version, with a link when a newer version is out.
- **View Container Logs** at the bottom shows the last 500 lines of this app's own log. Look there first when something in the app fails.

On a phone, the main pages sit in a tab bar at the bottom, and **More** opens the rest.

Every page and tab has its own address, so you can bookmark and share it.

## Refresh

**Refresh** reloads the open page and the sidebar counters. The Dashboard, Messages, Security, Queue, Quarantine, Status, Settings and Spam Filter pages also update every 30 seconds while they are open, except while a window is open over the page.

## Feature switches

**Settings** > **Features** turns off a page and its background jobs. Turning a feature off deletes its data, for example Security logs, DMARC and TLS reports or quarantine rules, and the app asks before it does. See [Settings](HelpDocs/Settings.md#features).

## Signing in and out

Sign-in is set up in **Settings** > **Authentication**; see [Sign-in](OAuth2_Configuration.md). When a session expires, you return to the page you were on after you sign in again. Restarting or updating the app signs everyone out.

With no sign-in configured, the Dashboard shows **Authentication is off**. **Dismiss** hides the banner in this browser, for setups where a reverse proxy in front of the app already signs users in.

## The read-write API key

Changing mailcow needs the read-write API key (`MAILCOW_API_KEY_RW`): queue and quarantine actions, bans, rate limits and Rspamd maps. Without it, these areas show a lock and **Open Settings**, and the data stays readable. Add the key under **Settings** > **Mailcow**.

## Time zone

Timestamps use `TZ` when it names a zone other than UTC. With `TZ` unset or set to `UTC`, they use your browser's local time. Date filters and some chart labels always use browser time.

## Copying

Values with a copy icon copy on click. The browser allows this only over HTTPS or on `localhost`; over plain HTTP, select the text and copy it yourself.
