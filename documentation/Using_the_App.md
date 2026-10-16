# Using the app

What every page shares: the sidebar, the top bar, the phone layout, the theme, page addresses and the notices that are not tied to one page.

## Sidebar

- The app's name and logo sit at the top and lead to the Dashboard. Both come from **App Title** and **App Logo URL** under **Settings** > **Application**.
- The server card under it shows the host name of your mailcow server, a mark for the mailcow connection (green for **Connected to mailcow**, red for **Not connected to mailcow**, gray for **Connection status unknown**) and either **No problems** or the number of problems. A problem is a lost connection to mailcow, a stopped container or a listing on a blocklist. The card opens [Status](HelpDocs/Status.md).
- The pages are grouped: **Dashboard**; **Mail** with **Messages**, **Queue** and **Quarantine**; **Protection** with **Security**, **Spam Filter** and **DMARC & TLS**; **Server** with **Status**, **Domains**, **Mailbox Stats**, **Devices** and **Logs**; then **Settings** and **About**. A page whose feature is turned off under **Settings** > **Features** disappears, and a group whose pages are all off loses its heading.
- Counters next to a page show what may need a look: messages in the queue, quarantined messages, failed logins of the last 24 hours on **Security**, DMARC domains with a recommendation on **DMARC & TLS**, and problems on **Status** (in red). They are read when the app opens, every 5 minutes, and when you press **Refresh**.
- Point at a page with tabs to open a tab directly from its menu.
- **Collapse menu** folds the sidebar into icons; **Expand menu** opens it again. The browser remembers your choice. Narrower screens use the icon rail automatically.
- The foot of the sidebar shows this app's version and the mailcow version (`mailcow: v...`). When a newer version exists, a link such as **v3.0.1 available** or **mailcow 2026-09 available** appears next to it and opens the release notes in a window. A mailcow update also shows an update icon.
- The tools at the very bottom are **Switch theme**, **Refresh**, **Logout** (only when sign-in is on), a link to the project on GitHub, and **View Container Logs**.

## Top bar

On wider screens the top bar holds the app name, page title, page actions and [Search](HelpDocs/Search.md). Breadcrumbs show the group, page and open tab. Click a page or tab in them to return to it.

The Messages page keeps its own three-column layout and has no top bar.

## Phones

On a phone:

- A slim top bar shows the logo, the app's name, the name of the open page, a problems pill when there are problems (it opens Status), the search button and the tools (theme, Refresh, Logout, GitHub, container logs).
- A tab bar at the bottom has **Dashboard**, **Messages**, **Security**, **Status** (with a dot when there are problems) and **More**, which opens every page in a sheet with the same counters as the sidebar.
- Windows open as bottom sheets. Pull down from the top to close one.

## Theme

**Switch theme** changes between the light and the dark theme. The browser remembers the choice. Until you pick one, the app follows the light or dark setting of your system.

## Refresh and automatic updates

**Refresh** reloads the open page and the sidebar counters. On DMARC & TLS it also clears the app's cached DMARC figures first.

The Dashboard, Messages, Security, Queue, Quarantine, Status, Settings and Spam Filter pages also update themselves every 30 seconds while they are open. The update waits while a message window is open over the page. Other pages update when you press **Refresh** or open them again.

## Feature switches

**Settings** > **Features** hides disabled pages and stops their jobs. Disabling through Settings asks for confirmation and deletes feature data: Security logs, cached DNS checks, DMARC/TLS reports, suppressions or quarantine rules and history, depending on the feature. Logs keeps services needed by other pages. Review the deletion notice before saving. See [Settings](HelpDocs/Settings.md#features).

## Page addresses

Every page and every tab has its own address, so you can bookmark it, share it, reload it and reach it with the browser's Back button:

| Page | Address | Tabs |
|---|---|---|
| Dashboard | `/` | |
| Messages | `/messages` | |
| Queue | `/queue` | |
| Quarantine | `/quarantine` | `/quarantine/rules` |
| Security | `/security` | `/security/lists`, `/security/settings`, `/security/events` |
| Spam Filter | `/spam-filter` | `/spam-filter/maps` |
| DMARC & TLS | `/dmarc` | a domain, sender or report day, see [DMARC & TLS](HelpDocs/DMARC.md) |
| Status | `/status` | `/status/blocklists`, `/status/jobs` |
| Domains | `/domains` | |
| Mailbox Stats | `/mailbox-stats` | `/mailbox-stats/rate-limits` |
| Devices | `/devices` | |
| Logs | `/logs` | |
| Settings | `/settings` | `/settings/<tab>`, for example `/settings/auth` |
| About | `/about` | |

- The first tab of a page has the page's own address, for example `/security` for **Overview**.
- An address with an unknown tab opens the page's first tab. An unknown page opens the Dashboard.
- The older addresses `/security/protection`, `/security/fail2ban` and `/security/abuse` open the Security **Settings** tab.
- A page with tabs opened from the sidebar returns to the tab you last used on it.
- With a window or sheet open, the browser's Back button (or a phone's back gesture) closes it and stays on the page.
- The address of a page whose feature is turned off shows **Logs is disabled** (with the name of the page), a line that the feature was turned off by the administrator, and a **Go to Dashboard** button. The address stays as it was. You turn the feature back on under **Settings** > **Features**.

## Signing in and out

When sign-in is set up (Basic authentication or OAuth2), **Logout** in the sidebar tools ends your session and shows the login page. When a session expires, the next request takes you to the login page, and after you sign in you return to the page you were on. Sign-in is set up in **Settings** > **Authentication**; see [Getting started](GETTING_STARTED.md) and [OAuth2 configuration](OAuth2_Configuration.md).

With no sign-in configured, the Dashboard shows a banner: **Authentication is off**, "Anyone who can open this page can see all mail logs and change settings." **Set up sign-in** opens **Settings** > **Authentication**. **Dismiss** hides the banner for good in this browser, for setups where a reverse proxy in front of the app already signs users in. The banner goes away by itself once Basic authentication or OAuth2 is on.

## The read-write API key

The app reads mailcow with a read-only API key. Changing mailcow needs a second, read-write API key (`MAILCOW_API_KEY_RW`), for example for queue actions, quarantine, bans, rate limits and Rspamd maps. Without it, affected pages show a locked area and **Open Settings**. Add the key under **Settings** > **Mailcow** > **Connection**. The page data stays readable.

## Shared behavior

- Click a value with a copy icon to copy it. The app uses the browser clipboard API, which needs HTTPS or `localhost`.
- Notices appear at the bottom of the screen.
- Actions that ask for confirmation show a dialog. **Cancel** cancels the action. Individual pages describe which actions ask first.
- Shared timestamps use `TZ` when it names a zone other than UTC. With `TZ` unset or set to `UTC`, they use your browser's local time. Date filters and some chart labels also use browser time.
- A help button next to some page titles opens that page's documentation in a window. The app fetches the text from the project's GitHub repository.
- **View Container Logs** opens a window named `container.log` with the last 500 lines of this app's own log, updated every 2 seconds. It is useful when something in the app fails.
