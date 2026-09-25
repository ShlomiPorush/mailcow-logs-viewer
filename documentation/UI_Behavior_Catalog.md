# UI Behavior Catalog

The web UI has grown over many releases. Next to the pages and buttons that everyone sees, it carries a long tail of small behaviors that no mockup shows and nobody remembers: a value that copies on click, a tooltip that explains an abbreviation, the wording of a confirmation, a flag next to an IP address, the text of an empty list.

This catalog lists them, so that a redesign keeps every one of them on purpose or drops it on purpose, never by accident.

## How to use it during a redesign

1. Redesign one page at a time.
2. Before the page is considered done, go through its rows in every table below (use the Page column).
3. For each row, either confirm it still works in the new design, or record the decision to drop or change it in the pull request.
4. Check the invariants below on every page.
5. When the code changes, regenerate the tables: `node .github/scripts/ui-catalog.cjs --write`. A row that disappears from the tables without a decision is a regression.

Pages, modals, actions, handler functions, API calls, form fields, drop-down options and the settings on the Settings page are also guarded automatically by `.github/tests/ui-inventory.test.cjs` against `ui-inventory.baseline.json`, and `backend/tests/test_settings_ui_coverage.py` fails when an editable setting has no place on the Settings page. This catalog covers what those tests cannot: how things look and behave, and what the UI shows when a feature is off or not configured.

## Invariants for every page

- **Everything is served locally.** The browser loads no external resource: no CDN, no remote web fonts, no remote images. Chart.js, marked, DOMPurify, the Markdown CSS, the design system (`assets/css/ui.css`), its fonts (`assets/fonts/`, with their OFL licences), the compiled utility classes (`assets/css/utilities.css`) and the flag images live under `frontend/assets/`. A redesign that adds a font or a library must add it as a local file; `.github/tests/local-assets.test.cjs` fails on any external script, stylesheet, image or font. (The in-app help pages are fetched by the backend from GitHub, see `backend/app/routers/documentation.py`; the browser still only talks to the app.)
- **Light and dark theme.** The theme toggle is stored in `localStorage` ("theme") and every page, modal and badge has a dark variant.
- **Desktop and mobile.** The sidebar (desktop) carries the brand, a server card (connection indicator, mailcow host, problem count, opens Status), the pages grouped as Mail, Protection and Server with counters (Queue and Quarantine items, failed logins in 24 h on Security, DMARC insights, problems on Status, from `loadNavCounters`), and at the bottom the versions, the update links and the tools (theme, Refresh, Logout, GitHub, container logs). Below 1100 px it is an icon rail where counters become dots. On phones (below 760 px) a top bar shows the page name, a problems pill (opens Status) and the theme and Refresh buttons (`placeShellUtilities` moves them there), and a bottom tab bar (Dashboard, Messages, Security, Status with a problems dot, More) opens every page in a sheet (`toggleMobileMenu`, `navigateToMobile`). On phones a filter panel keeps its search field and opens the other filters on demand. Every page must stay usable on a phone.
- **Escaping.** Anything that comes from the server or from mail headers is rendered through `escapeHtml`, and values placed inside inline handlers through `escapeJsArg` (see `frontend/utils.js`). New markup must keep this; mail headers are attacker-controlled.
- **Mail content keeps its own direction.** Subjects, addresses and quarantine rule values can be in Hebrew or Arabic, so the element that shows them carries `dir="auto"`, and `copyableText` wraps its text in `<bdi>`. The browser then lays out each value in its own direction without moving the text around it (scores, arrows, the copy icon). A rule in the `<style>` block of `index.html` keeps `[dir="auto"]` aligned left, so a Hebrew subject stays next to its label instead of jumping to the far edge. Keep this on every place that shows mail content.
- **Country flags are PNG images, never emoji.** Most use is on desktop, and Windows does not render flag emoji (it shows two letters instead). The images live in `frontend/assets/flags/` in three sizes.
- **Markdown keeps its styling.** Help pages and changelogs are rendered by `renderMarkdown` (marked, then DOMPurify, `frontend/utils.js`) into a `.markdown-body` element inside `#changelog-content` or `.update-changelog-content`. Their look comes from the local `github-markdown.min.css` plus the overrides in the `<style>` block of `index.html` (the `.markdown-body` rules, about lines 270 to 470), which also carry the dark theme. A redesign that renames these containers or drops those rules breaks every help page and changelog, even though nothing else changes.
- **Dates follow the app timezone.** Times are formatted with `Intl.DateTimeFormat` in `appTimezone`, which the backend reports (`formatTime` in `frontend/utils.js`, and `frontend/rate-limits.js`), not in the browser's timezone. Counts use thousands separators (`toLocaleString()`).
- **Custom branding.** The header title and logo come from settings (`app_title`, `app_logo_url`, see `/api/info`): a custom logo replaces the default icon (`#app-logo`, `#default-logo`) and the title can differ per installation. The footer repeats the title.
- **Sidebar indicators.** The server card holds the mailcow connection indicator (`#mailcow-connection-indicator`) and the problem count; the sidebar foot holds the app version and its "Update Available" link (opens Settings), the mailcow version with its "Update Available" link and update icon (`#mailcow-update-icon`, both open the mailcow update dialog), and the tools. There is no page footer. Each is easy to lose in a new layout.
- **Status indicators inside tabs.** The Security tab of the message details shows a red or green dot for whether the message has security events.
- **Messages and the reading pane.** The Messages page has three columns from 1280 px: facets (Outcome and Direction with counts from `/api/messages/facets`, which counts exactly as the list does, the time presets and a custom range, More filters with sender, recipient, user and IP, Export CSV), the list, and the reading pane. From 1000 px the facets become chips above the list; below that the list stands alone and a message opens as a full-screen dialog. A list row shows sender, time (time of day for today, date before), subject, the outcome tag, direction, recipient, spam, folder and deliveries; queue ID, message ID, score, user and IP are in the reading pane. On a wide screen the first message opens in the pane and the open row is marked; the smart refresh keeps running while a message is docked. The pane (`#message-modal`, docked as `ui-docked`) shows the subject, From/To/When and the outcome above the tabs (`renderMessageHeader`), and the Overview tab tells "What happened" as steps built from the Postfix, Rspamd and Dovecot logs (`buildDeliverySteps`), then Identifiers. Every id, tab and handler is the same as a dialog (`message-details.js`).
- **Badges** use the recipes in `APP_COLORS` (soft fill plus a subtle border, squared corners, not rounded pills). Pages already on the v3 design use `uiStatusTag` and `uiDirectionTag` (`frontend/utils.js`) instead: the tone follows the meaning (delivered and sent green, deferred amber, bounced and rejected red, spam its own colour, anything else neutral) and the text is the status itself.
- **Cache busting.** Every changed frontend file gets a new `?v=` in `index.html`, or browsers keep the old copy.
- **Utility classes are compiled, not generated in the browser.** The Tailwind utilities the markup still uses are built once into `assets/css/utilities.css` (`bash .github/scripts/build-utilities-css.sh`, Tailwind 3.4.17). After adding or changing a utility class, rebuild it and bump its `?v=`; CI fails when the file does not match the markup. A class assembled at runtime (`bg-${color}-100`) must be in the safelist of `.github/tailwind/tailwind.config.cjs` (`utilities-css.test.cjs` checks this). New UI is built on the `ui-` components instead.

## Manual checks per behavior

| Behavior | What to check |
|---|---|
| Click to copy | Hovering the value shows a faint background and a copy icon. Clicking copies the exact value (not the truncated display), the icon turns into a check mark for 1.5 s, and a toast says "Copied: <value>". The Clipboard API only works in a secure context (HTTPS or localhost); on plain HTTP the click shows "Failed to copy". |
| Tooltips | Hovering shows the same text as before. Dynamic tooltips show the full value where the cell truncates it. |
| Toasts | One toast at a time (a new one replaces the old), bottom of the screen, colour by type (success, error, warning, info), disappears after about 4 s. The wording is part of the product; keep it. |
| Confirmation dialogs | Every action listed here still asks first, with the same title and message, and Escape/Enter still work where noted under keyboard handling. |
| Country flags | The flag image appears next to IP addresses where listed, at the listed size, with no emoji fallback and no external image source. Check on Windows. |
| Markdown | Open a help page, the changelog from the footer, and the update changelog in Settings, in light and dark theme. Headings, paragraphs, nested lists (three levels), inline code, code blocks, tables, block quotes and links all look as before, the background stays transparent, and nothing is unreadable in dark mode. |
| Controls wired in JavaScript | Each listed button, tab or form still reacts. These are invisible to the automatic inventory test. |
| Filters and view options | Every drop-down keeps its options in the same order and wording, and filtering or sorting still changes the list. |
| Charts | The chart renders with data, hover shows its tooltip, and it is readable in both themes. |
| Colour thresholds | The value changes colour at the listed threshold (for example storage above 75% and above 90%). |
| Dates and numbers | Times match the timezone set in the app, not the browser's; large counts keep their separators. |
| Help topics | Each help button opens the listed topic. |
| Empty states | An empty list shows its sentence, not a blank area or a broken table. |
| Loading states | A spinner or "Loading..." appears while data loads; the page never shows stale data without an indicator. |
| Persisted preferences | The preference survives a reload. |
| Auto refresh | The page refreshes on its own at the listed interval, and stops when you leave it. |
| Address bar | The URL changes as listed, so the view can be bookmarked, shared and reloaded. |
| Keyboard | The listed keys still close or confirm the dialog. |
| Gated states | Each state in the next section still appears under its condition, with the same explanation and the same way out (a link or the place to configure it). Run the browser pass in both modes (see below). |

## Gated and conditional states

Many parts of the UI change with the configuration: a feature can be turned off, a key or password can be missing, settings can be read-only. These states are easy to miss in a redesign because a normal test instance never shows them. Each row names the condition, what the user sees and where it is rendered.

### Global (navigation, header, footer)

| Condition | What the user sees | Rendered by |
|---|---|---|
| A feature is listed in `disabled_features` (`/api/info`; env `DISABLED_FEATURES`: netfilter, queue, quarantine, spam-filter, domains, dmarc, mailbox-stats, rate-limits, logs, blacklist) | Its entry disappears from the sidebar, the phone tab bar and the sheet; a group whose pages are all off loses its heading | `applyFeatureToggles` (`tab-<id>`, `tabbar-<id>`, `mobile-tab-<id>`, `[data-nav-group]`) |
| Only `mailbox-stats` is disabled, `rate-limits` is on | The tab stays and is relabelled "Rate Limits"; the Statistics view and the view switcher are hidden | `applyFeatureToggles`, `setNavTabLabel` |
| Both `mailbox-stats` and `rate-limits` are disabled | The tab is hidden | `applyFeatureToggles` |
| `rate-limits` is disabled | The Rate Limits view button is hidden and the page falls back to Statistics | `applyFeatureToggles`, `mailboxStatsSwitchView` |
| The URL of a disabled feature is opened directly | The page is replaced by "{Label} is disabled", "This feature has been turned off by the administrator in Settings → Application → Features." and a Go to Dashboard button; the URL stays | `switchTab` |
| `auth_enabled` | The Logout button is shown; without it the auth check is skipped | `checkAuthentication`, `#logout-btn` |
| mailcow connection (`/api/status/mailcow-connection`) | Header indicator: green "Connected to mailcow", red "Not connected to mailcow", or grey "Connection status unknown" | `#mailcow-connection-indicator` |
| App update available (`/api/status/app-version`) | Footer badge "Update Available" that opens the changelog modal | `#update-badge` |
| mailcow update available (`/api/status/version`) | Header icon and footer badge with the title "Update available: {version}", both open the mailcow update modal | `#mailcow-update-icon`, `#mailcow-update-badge` |

### Login page (`login.html`)

| Condition | What the user sees | Rendered by |
|---|---|---|
| Authentication is off | Redirect to the app | inline script |
| `oauth2_enabled` (`/api/auth/provider-info`) | The OAuth2 button with the provider name | `#oauth2-section` |
| `basic_auth_enabled` is false | The username and password form is hidden | `#login-form` |
| Both methods on | An "OR" separator between them | `#auth-separator` |
| `?error=` in the URL | A red error box, with its own text for `oauth2_error`, `invalid_state`, `missing_code`, `no_token`, `session_capacity` ("Login capacity reached...") and `server_error` | `#login-error` |

### Missing Read-Write mailcow API key (`MAILCOW_API_KEY_RW`)

The same missing key is handled in two ways today. Some pages explain it; others hide their controls without a word.

| Page | What the user sees | Rendered by |
|---|---|---|
| Security, Fail2ban | Locked area "Editing Fail2ban is locked": editing needs a Read-Write API key (`MAILCOW_API_KEY_RW`), configure it in Settings → Mailcow → Connection, with an Open Settings button. Edit buttons removed, fields stay disabled, Unban hidden | `loadFail2BanSettings`, `uiLocked` |
| Security, netfilter log | Ban and Unban buttons are removed from the rows, and a locked area "Ban and Unban are locked" above the list says why and where to configure the key | `renderNetfilterData`, `uiLocked` |
| Security, Abuse protection | Locked area "Abuse protection controls are locked" with the reason ("SMTP abuse protection is disabled" and/or "a Read-Write mailcow API key is not configured") above the activity, which stays readable; all actions hidden | `renderSmtpAbusePanel`, `uiLocked` |
| Queue | Toolbar, checkboxes and Retry/Hold/Unhold/Delete are gone, and a locked area "Queue actions are locked" says why and where to configure the key. Suppress stays | `applyQueueFilters`, `uiLocked` |
| Quarantine | Bulk and per-item Release/Delete/Learn, the details modal actions and the whole Auto-Rules section are hidden, and a locked area "Quarantine actions are locked" names them and where to configure the key. Details stays | `renderQuarantineData`, `initQuarantineRules`, `uiLocked` |
| Spam Filter | Locked area "Read-Only Mode": MAILCOW_API_KEY_RW is not configured, you can view maps but cannot save changes, with Open Settings (the Save button of the map editor itself is not gated) | `renderRspamdMapsList` |
| Mailbox Stats, Rate Limits | Locked area "Editing rate limits is locked" with the Read-Write key sentence and Open Settings; Edit, Apply to filtered, the bulk panel and Reset counter are hidden | `renderRateLimitReadOnlyNotice` |

The v3 redesign replaces these with one consistent locked-area component that says what is missing and where to configure it (decided 2026-09-25): `uiLocked(title, text)` in `frontend/utils.js`, styled by `.ui-locked`, always with an Open Settings button. Pages move to it as they are redesigned; the rows above say which already use it.

### Features that are off or not configured

| Page | Condition | What the user sees | Rendered by |
|---|---|---|---|
| Dashboard | `blacklist` disabled | The blacklist card is hidden | `#dashboard-blacklist-card` |
| Dashboard | Unacknowledged security alerts | Red banner "Security Alerts (N)" with severity chips, Dismiss and Dismiss all | `loadDashboardSecurityAlerts` |
| Message details | `netfilter` disabled | The Security tab of the modal is hidden | `#modal-tab-netfilter` |
| Security | SMTP abuse protection off | "Automatic protection is off. Enable it under Settings → SMTP Abuse." | `renderSmtpAbusePanel` |
| Security | No GeoIP data | "No GeoIP data available. Configure MaxMind to enable country statistics." (also shown when MaxMind is configured but there is no data yet) | `#country-chart-empty` |
| Spam Filter | `RSPAMD_PASSWORD` missing | Locked area "Rspamd Not Configured" with the message and a Go to Settings button | `loadRspamdMaps` |
| DMARC | Manual upload disabled | The Upload Report button is hidden | `updateDmarcControls` |
| DMARC | IMAP sync disabled | The Sync from IMAP block and the last sync line are hidden | `updateDmarcControls` |
| DMARC | Report deletion disabled | "(Deletion disabled)" and no delete column or buttons | `renderReportsManagementTable` |
| DMARC | Policy insights available | Blue banner "DMARC Insights (N)" | `loadDmarcInsights` |
| Mailbox Stats | Domain limits unreadable | Amber strip "Domain limits could not be read from mailcow: {error}" | `renderRateLimitConfigCard` |
| Logs | Raw log collection off | Locked area "Live Log Viewer is Disabled" with the place to enable it (Settings → Raw Logs) and Open Settings | `loadLogViewer` |
| Logs | No services enabled | Locked area "No log services available" with "Enable services in Settings → Raw Logs." and Open Settings | `loadLogViewer` |
| Logs | WebSocket state | Green, yellow or red dot with Connected, Paused or Disconnected | `updateWsIndicator` |
| Status | `blacklist` disabled | The IP Blacklist Monitor section is hidden | `#blacklist-section` |
| Status | A job's feature is off | Job card faded with a "feature off" badge, no Run button | `renderJobCard` |
| Status | A job is disabled for another reason | The Run button is hidden and a "disabled" tag explains it (tooltip: turned off in its settings) | `renderJobCard` |
| Status | A job is running | Run button disabled, "Job is running" | `renderJobCard` |

### Settings

| Condition | What the user sees | Rendered by |
|---|---|---|
| `SETTINGS_EDIT_VIA_UI_ENABLED` is off | Read-only cards with the current values, under a locked area "Editing settings is off" that says to set `SETTINGS_EDIT_VIA_UI_ENABLED=true` and restart the container | `renderSettings`, `uiLocked` |
| Editing is on | "Edit configuration" with the note "Priority: Default → DB → ENV. Environment variables always override DB values and cannot be changed from here." | `renderSettings` |
| Settings not migrated yet | Only a "Migrate Settings from ENV" button, no Save button | `renderSettings` |
| A key is set by an environment variable | The field is disabled, with a lock icon and "Controlled by ENV variable - cannot be changed from here." | `renderSettingsEditField` |
| `DISABLED_FEATURES` or `RAW_LOGS_SERVICES` set by the environment | Checkboxes disabled, "Locked by ENV (DISABLED_FEATURES)" or "Controlled by ENV variable." | `renderSettingsEditField` |
| A value differs from its default | Amber highlight with "Reset to default" or "Clear" | `renderSettingsEditField` |
| A feature is disabled | Its Settings tab is hidden | `SETTINGS_TAB_FEATURE_MAP` |
| MaxMind | "Not checked", "Not configured", "License Valid" or a red error; database "DB Healthy", "DB Corrupt" with Repair, or "Downloading..." | `renderMaxMindStatus`, `renderGeoIPDbStatus` |
| Turning Basic Auth on without a password | A toast, then the "Verify Credentials" modal | `renderSettings` |
| Disabling a feature that has data | The warning "Disabling a feature permanently deletes its stored data." and a confirmation modal before the purge | `showFeatureDisableConfirmModal` |
| Notification destination disabled or failing | Faded card with a "disabled" tag, a coloured status dot and the last error | `renderNotificationChannels` |

### Checking the gated states in a browser

`UI_SMOKE=1 bash .github/scripts/smoke.sh <image>` runs the browser pass twice: once with every feature on and settings editable, and once locked, with every feature in `DISABLED_FEATURES` and `SETTINGS_EDIT_VIA_UI_ENABLED` off. Both runs have no Read-Write key, no Rspamd password and no MaxMind key, so the locked banners above render in both.

## How this catalog was checked

The tables are generated from the code. On 2026-09-24 the catalog was also compared against a running instance with real data: every page, every sub-tab and view switch, the Settings tabs and the detail views were opened in a headless browser (read-only: no save, delete, ban, release or run). That pass added the controls wired in JavaScript, the drop-down options, charts, colour thresholds, tooltips set from JavaScript, and the timezone, header and footer invariants. No data from that instance is recorded here.

<!-- generated:start (node .github/scripts/ui-catalog.cjs --write) -->

## Reference tables

Generated from the code. Do not edit by hand; run `node .github/scripts/ui-catalog.cjs --write` after a change.

| Behaviour | Count |
|---|---|
| [Click to copy](#click-to-copy) | 34 |
| [Tooltips](#tooltips) | 128 |
| [Toasts](#toasts) | 133 |
| [Confirmation dialogs](#confirmation-dialogs) | 27 |
| [Country flags](#country-flags) | 5 |
| [Markdown rendering](#markdown-rendering) | 4 |
| [Controls wired in JavaScript](#controls-wired-in-javascript) | 28 |
| [Filters, sorting and view options](#filters-sorting-and-view-options) | 11 |
| [Charts](#charts) | 3 |
| [Colour thresholds](#colour-thresholds) | 44 |
| [Help topics](#help-topics) | 8 |
| [Empty states](#empty-states) | 37 |
| [Loading states](#loading-states) | 18 |
| [Persisted preferences](#persisted-preferences) | 4 |
| [Auto refresh and timers](#auto-refresh-and-timers) | 5 |
| [Address bar and deep links](#address-bar-and-deep-links) | 6 |
| [Keyboard handling](#keyboard-handling) | 4 |
| [Badge colours](#badge-colours) | 11 |

### Click to copy

Fields that copy their value on click (hover shows a copy icon and "Click to copy").

| Page | What | Code |
|---|---|---|
| Message details | copies: `data.sender \|\| '-'` | `frontend/message-details.js:443` (renderMessageHeader) |
| Message details | copies: `r` | `frontend/message-details.js:444` (renderMessageHeader) |
| Message details | copies: `recipients[0] \|\| '-'` | `frontend/message-details.js:444` (renderMessageHeader) |
| Message details | copies: `data.queue_id` | `frontend/message-details.js:526` (renderOverviewTab) |
| Message details | copies: `rspamd.user` | `frontend/message-details.js:528` (renderOverviewTab) |
| Message details | copies: `r` | `frontend/message-details.js:533` (renderOverviewTab) |
| Message details | copies: `data.message_id` | `frontend/message-details.js:534` (renderOverviewTab) |
| Message details | copies: `Array.from(recipientsFromPostfix)[0]` | `frontend/message-details.js:679` (renderPostfixTab) |
| Message details | copies: `data.recipients[0]` | `frontend/message-details.js:681` (renderPostfixTab) |
| Message details | copies: `sender` | `frontend/message-details.js:690` (renderPostfixTab) |
| Message details | copies: `queueId` | `frontend/message-details.js:693` (renderPostfixTab) |
| Message details | copies: `clientIp` | `frontend/message-details.js:694` (renderPostfixTab) |
| Message details | copies: `recipient` | `frontend/message-details.js:708` (renderPostfixTab) |
| Message details | copies: `log.ip` | `frontend/message-details.js:832` (renderNetfilterTab) |
| Message details | copies: `log.username` | `frontend/message-details.js:835` (renderNetfilterTab) |
| Security | copies: `log.ip` | `frontend/app.js:991` (renderNetfilterData) |
| Security | copies: `log.username` | `frontend/app.js:992` (renderNetfilterData) |
| Queue | copies: `item.sender` | `frontend/app.js:2367` (applyQueueFilters) |
| Queue | copies: `qid` | `frontend/app.js:2368` (applyQueueFilters) |
| Queue | copies: `emailOnly` | `frontend/app.js:2383` (applyQueueFilters) |
| Quarantine | copies: `item.sender \|\| 'Unknown'` | `frontend/app.js:2727` (renderQuarantineData) |
| Quarantine | copies: `item.rcpt \|\| 'Unknown'` | `frontend/app.js:2731` (renderQuarantineData) |
| Quarantine | copies: `item.qid` | `frontend/app.js:2744` (renderQuarantineData) |
| Quarantine | copies: `r.address` | `frontend/app.js:2976` (renderQuarantineDetailContent) |
| Quarantine | copies: `data.subject \|\| '-'` | `frontend/app.js:3013` (renderQuarantineDetailContent) |
| Quarantine | copies: `data.header_from \|\| '-'` | `frontend/app.js:3018` (renderQuarantineDetailContent) |
| Quarantine | copies: `data.env_from \|\| '-'` | `frontend/app.js:3022` (renderQuarantineDetailContent) |
| Spam filter | copies: `displayEmail` | `frontend/spam_filter.js:497` (renderSuppressionItem) |
| Status | copies: `item.message_id \|\| 'N/A'` | `frontend/app.js:4462` (renderStatusCorrelation) |
| Status | copies: `item.sender \|\| 'N/A'` | `frontend/app.js:4466` (renderStatusCorrelation) |
| Status | copies: `item.recipient \|\| 'N/A'` | `frontend/app.js:4466` (renderStatusCorrelation) |
| Shared | copies: `ip` | `frontend/app.js:4687` (renderGeoIPInfo) |
| Shared | copies: `ip` | `frontend/app.js:4694` (renderGeoIPInfo) |
| Shared | copyToClipboard: `'${safeText}'` | `frontend/utils.js:452` (copyableText) |

### Tooltips

Native `title` tooltips. Dynamic ones show the expression that builds the text.

| Page | What | Code |
|---|---|---|
| Shell | "Server status" | `frontend/index.html:396` |
| Shell | "mailcow connection status" | `frontend/index.html:397` |
| Shell | "Dashboard" | `frontend/index.html:408` |
| Shell | "Messages" | `frontend/index.html:412` |
| Shell | "Queue" | `frontend/index.html:413` |
| Shell | "Quarantine" | `frontend/index.html:414` |
| Shell | "Security" | `frontend/index.html:418` |
| Shell | "Spam Filter" | `frontend/index.html:419` |
| Shell | "DMARC" | `frontend/index.html:420` |
| Shell | "Status" | `frontend/index.html:424` |
| Shell | "Domains" | `frontend/index.html:425` |
| Shell | "Mailbox Stats" | `frontend/index.html:426` |
| Shell | "Logs" | `frontend/index.html:427` |
| Shell | "Settings" | `frontend/index.html:430` |
| Shell | "mailcow update available" | `frontend/index.html:439` |
| Shell | "Switch theme" | `frontend/index.html:447` |
| Shell | "Refresh" | `frontend/index.html:459` |
| Shell | "Logout" | `frontend/index.html:464` |
| Shell | "Created with ❤️ - GitHub" | `frontend/index.html:469` |
| Shell | "View Container Logs" | `frontend/index.html:473` |
| Shell | set in JS: dynamic: `data.app_title` | `frontend/app.js:412` (loadAppInfo) |
| Shell | set in JS: dynamic: `== 'Not connected to mailcow') problems.push('not connected to mailcow')` | `frontend/app.js:541` (loadNavCounters) |
| Shell | set in JS: dynamic: `problems.join(', ')` | `frontend/app.js:551` (loadNavCounters) |
| Shell | set in JS: dynamic: `problems.join(', ')` | `frontend/app.js:557` (loadNavCounters) |
| Shell | set in JS: "Connected to mailcow" | `frontend/app.js:583` (loadMailcowConnectionStatus) |
| Shell | set in JS: "Not connected to mailcow" | `frontend/app.js:592` (loadMailcowConnectionStatus) |
| Shell | set in JS: "Connection status unknown" | `frontend/app.js:607` (loadMailcowConnectionStatus) |
| Shell | set in JS: dynamic: ``Update available: v${data.latest_version}`` | `frontend/app.js:627` (loadAppVersionStatus) |
| Shell | set in JS: dynamic: ``Update available: ${data.latest_version}`` | `frontend/app.js:706` (loadMailcowVersionStatus) |
| Shell | set in JS: dynamic: ``Update available: ${data.latest_version}`` | `frontend/app.js:713` (loadMailcowVersionStatus) |
| Dashboard | "Dismiss" | `frontend/app.js:1460` (loadDashboardSecurityAlerts) |
| Dashboard | dynamic: `${escapeHtml(msg.subject \|\| 'No subject')}` | `frontend/app.js:1568` (loadRecentActivity) |
| Messages | dynamic: `${escapeHtml(formatTime(msg.first_seen))}` | `frontend/app.js:867` (renderMessageRow) |
| Messages | dynamic: `${escapeHtml(msg.subject \|\| 'No subject')}` | `frontend/app.js:869` (renderMessageRow) |
| Messages | dynamic: `${escapeHtml(msg.recipient \|\| '')}` | `frontend/app.js:874` (renderMessageRow) |
| Message details | "This delivery attempt never reached a final outcome" | `frontend/message-details.js:355` (renderRelatedDeliveries) |
| Message details | dynamic: `${escapeHtml(hasSubject ? data.subject : 'No subject')}` | `frontend/message-details.js:441` (renderMessageHeader) |
| Message details | dynamic: `${escapeHtml(data.message_id)}` | `frontend/message-details.js:534` (renderOverviewTab) |
| Message details | dynamic: `${escapeHtml(sender)}` | `frontend/message-details.js:690` (renderPostfixTab) |
| Message details | dynamic: `${escapeHtml(relay)}` | `frontend/message-details.js:695` (renderPostfixTab) |
| Message details | set in JS: dynamic: `== step.title) { prev.count = (prev.count \|\| 1) + 1` | `frontend/message-details.js:494` (buildDeliverySteps) |
| Security | dynamic: `Unban ${escapeHtml(log.ip)}/32` | `frontend/app.js:997` (renderNetfilterData) |
| Security | dynamic: `Ban ${escapeHtml(log.ip)}/32` | `frontend/app.js:998` (renderNetfilterData) |
| Security | "This feature is new - please report any issues on GitHub" | `frontend/index.html:744` |
| Security | "Help - Abuse Protection" | `frontend/index.html:748` |
| Queue | "Retry delivery" | `frontend/app.js:2392` (applyQueueFilters) |
| Queue | "Release from hold" | `frontend/app.js:2398` (applyQueueFilters) |
| Queue | "Hold message" | `frontend/app.js:2404` (applyQueueFilters) |
| Queue | "Delete from queue" | `frontend/app.js:2410` (applyQueueFilters) |
| Queue | dynamic: `Suppress ${escapeHtml(emailOnly)}` | `frontend/app.js:2419` (applyQueueFilters) |
| Quarantine | "Click to view details" | `frontend/app.js:2733` (renderQuarantineData) |
| Quarantine | "Queue ID" | `frontend/app.js:2744` (renderQuarantineData) |
| Quarantine | "View details" | `frontend/app.js:2748` (renderQuarantineData) |
| Quarantine | "Release message" | `frontend/app.js:2754` (renderQuarantineData) |
| Quarantine | "Delete message" | `frontend/app.js:2759` (renderQuarantineData) |
| Quarantine | "Release & train as Not Spam" | `frontend/app.js:2764` (renderQuarantineData) |
| Quarantine | "Delete & train as Spam" | `frontend/app.js:2769` (renderQuarantineData) |
| Quarantine | "Create auto-rule from this email" | `frontend/app.js:2774` (renderQuarantineData) |
| Quarantine | dynamic: `${escapeHtml(opts)}` | `frontend/app.js:2994` (renderQuarantineDetailContent) |
| Quarantine | dynamic: `${rule.enabled ? 'Click to disable this rule' : 'Click to enable this rule'}` | `frontend/app.js:3166` (loadQuarantineRules) |
| Quarantine | "Edit" | `frontend/app.js:3172` (loadQuarantineRules) |
| Quarantine | "Delete" | `frontend/app.js:3176` (loadQuarantineRules) |
| Quarantine | dynamic: `${escapeHtml(m.subject \|\| '')}` | `frontend/app.js:3438` (testQuarantineRules) |
| Quarantine | dynamic: `${escapeHtml(log.sender \|\| '')} → ${escapeHtml(log.recipient \|\| '')}` | `frontend/app.js:3522` (loadQuarantineRuleHistory) |
| Quarantine | dynamic: `Rule: ${escapeHtml(log.rule_name \|\| '')}` | `frontend/app.js:3525` (loadQuarantineRuleHistory) |
| Quarantine | "Help - Quarantine Auto-Rules" | `frontend/index.html:845` |
| Spam filter | "Help - Spam Filter" | `frontend/index.html:907` |
| Spam filter | "Clear all filters" | `frontend/index.html:972` |
| Spam filter | "Sync suppression list to Rspamd" | `frontend/index.html:984` |
| Spam filter | "Synced to Rspamd" | `frontend/spam_filter.js:477` (renderSuppressionItem) |
| Spam filter | "Pending sync to Rspamd" | `frontend/spam_filter.js:479` (renderSuppressionItem) |
| Spam filter | "Will be removed from Rspamd on next sync" | `frontend/spam_filter.js:484` (renderSuppressionItem) |
| Spam filter | "' + escapeHtml(s.email) + '" | `frontend/spam_filter.js:498` (renderSuppressionItem) |
| Spam filter | dynamic: `${escapeHtml(s.notes)}` | `frontend/spam_filter.js:509` (renderSuppressionItem) |
| Spam filter | "Edit suppression" | `frontend/spam_filter.js:514` (renderSuppressionItem) |
| Spam filter | dynamic: `${s.active ? 'Deactivate' : 'Reactivate'}` | `frontend/spam_filter.js:517` (renderSuppressionItem) |
| Spam filter | "Delete permanently" | `frontend/spam_filter.js:520` (renderSuppressionItem) |
| Status | dynamic: `${escapeHtml(detail)}` | `frontend/app.js:4389` (renderBlacklistStatus) |
| Status | dynamic: `${escapeHtml(detail)}` | `frontend/app.js:4391` (renderBlacklistStatus) |
| Status | "View info" | `frontend/app.js:4392` (renderBlacklistStatus) |
| Status | "Help - IP Blacklist Monitor" | `frontend/index.html:1070` |
| Domains | "OK" | `frontend/domains.js:242` (renderDomainAccordionRow) |
| Domains | "Warning" | `frontend/domains.js:243` (renderDomainAccordionRow) |
| Domains | "Error" | `frontend/domains.js:244` (renderDomainAccordionRow) |
| Domains | "Unknown" | `frontend/domains.js:245` (renderDomainAccordionRow) |
| Domains | "Check DNS for this domain" | `frontend/domains.js:412` (renderDomainAccordionRow) |
| Domains | "Check DNS for this domain" | `frontend/domains.js:733` (checkSingleDomainDNS) |
| Domains | "OK" | `frontend/domains.js:754` (checkSingleDomainDNS) |
| Domains | "Warning" | `frontend/domains.js:755` (checkSingleDomainDNS) |
| Domains | "Error" | `frontend/domains.js:756` (checkSingleDomainDNS) |
| Domains | "Unknown" | `frontend/domains.js:757` (checkSingleDomainDNS) |
| Domains | "Help - Domains Information" | `frontend/index.html:1165` |
| DMARC | "DMARC Reports" | `frontend/dmarc.js:366` (loadDmarcDomains) |
| DMARC | "TLS Reports" | `frontend/dmarc.js:367` (loadDmarcDomains) |
| DMARC | "Delete report" | `frontend/dmarc.js:1646` (renderReportsManagementTable) |
| DMARC | "Delete" | `frontend/dmarc.js:1681` (renderReportsManagementTable) |
| DMARC | "Help - DMARC Information" | `frontend/index.html:1197` |
| Mailbox stats | "Help - Mailbox Statistics" | `frontend/index.html:1403` |
| Mailbox stats | "Address on a mailcow alias domain that points at this mailbox" | `frontend/mailbox-stats.js:556` (renderMailboxStatsAccordion) |
| Mailbox stats | set in JS: dynamic: `isRateLimits ? 'Help - Rate Limits' : 'Help - Mailbox Statistics'` | `frontend/mailbox-stats.js:83` (mailboxStatsSwitchView) |
| Logs | "Pause/Resume live updates" | `frontend/index.html:1710` |
| Logs | "Live mode - show latest logs" | `frontend/index.html:1720` |
| Logs | "Auto-scroll to new entries" | `frontend/index.html:1730` |
| Logs | "Toggle sort order (newest at bottom / newest at top)" | `frontend/index.html:1740` |
| Logs | "Toggle word wrap" | `frontend/index.html:1761` |
| Logs | "Search" | `frontend/index.html:1778` |
| Logs | "Clear search" | `frontend/index.html:1785` |
| Logs | "Clear display" | `frontend/index.html:1795` |
| Logs | "From date" | `frontend/index.html:1823` |
| Logs | "To date" | `frontend/index.html:1828` |
| Logs | dynamic: `${escapeHtml(f.description \|\| '')}` | `frontend/logs-viewer.js:232` (loadSmartFilters) |
| Logs | "Clear all filters" | `frontend/logs-viewer.js:1227` (updateFilterBadge) |
| Settings | "Last delivery succeeded" | `frontend/notifications.js:67` (renderNotificationChannels) |
| Settings | "Last delivery failed" | `frontend/notifications.js:69` (renderNotificationChannels) |
| Settings | "Not used yet" | `frontend/notifications.js:70` (renderNotificationChannels) |
| Settings | dynamic: `${escapeHtml(ch.last_error)}` | `frontend/notifications.js:83` (renderNotificationChannels) |
| Settings | "Click to view changelog" | `frontend/settings.js:965` (renderSettings) |
| Settings | "Click to view changelog" | `frontend/settings.js:966` (renderSettings) |
| Settings | dynamic: `${escapeHtml(domain)}` | `frontend/settings.js:1091` (renderSettings) |
| Shared | dynamic: `${escapeHtml(title)}` | `frontend/utils.js:158` (uiCorrelationTag) |
| Shared | "The feature this job belongs to is turned off in Settings" | `frontend/utils.js:588` (renderJobCard) |
| Shared | "This job is turned off in its settings, so it cannot be run" | `frontend/utils.js:591` (renderJobCard) |
| Shared | dynamic: `${isRunning ? 'Job is running' : 'Run this job now'}` | `frontend/utils.js:625` (renderJobCard) |
| app.js (mixed) | set in JS: dynamic: `label` | `frontend/app.js:286` (setNavTabLabel) |
| app.js (mixed) | set in JS: dynamic: `title \|\| ''` | `frontend/app.js:499` (setNavCount) |
| Modal: container-logs-modal | "Refresh" | `frontend/index.html:497` |
| Modal: container-logs-modal | "Close" | `frontend/index.html:505` |
| Modal: message-modal | "Close" | `frontend/index.html:1903` |

### Toasts

Transient notifications from `showToast(message, type)` (utils.js). Type defaults to info.

| Page | What | Code |
|---|---|---|
| Messages | "Please select both start and end dates" [warning] | `frontend/app.js:3642` (applyMessagesCustomDateRange) |
| Messages | "Start date must be before end date" [warning] | `frontend/app.js:3651` (applyMessagesCustomDateRange) |
| Security | "IP ' + ip + ' unbanned successfully" [success] | `frontend/app.js:1025` (unbanIP) |
| Security | dynamic: `'Failed to unban: ' + (result.msg \|\| result.detail \|\| 'Unknown error')` [error] | `frontend/app.js:1032` (unbanIP) |
| Security | dynamic: `'Failed to unban IP: ' + err.message` [error] | `frontend/app.js:1039` (unbanIP) |
| Security | dynamic: ``IP ${ip} added to blacklist`` [success] | `frontend/app.js:1066` (banIP) |
| Security | dynamic: `'Failed to ban: ' + (result.msg \|\| result.detail \|\| 'Unknown error')` [error] | `frontend/app.js:1073` (banIP) |
| Security | dynamic: `'Failed to ban IP: ' + err.message` [error] | `frontend/app.js:1080` (banIP) |
| Security | "Failed to dismiss alert" [error] | `frontend/app.js:1485` (acknowledgeSecurityAlert) |
| Security | "All security alerts dismissed" [success] | `frontend/app.js:1493` (acknowledgeAllSecurityAlerts) |
| Security | "Failed to dismiss alerts" [error] | `frontend/app.js:1495` (acknowledgeAllSecurityAlerts) |
| Security | "Fail2Ban settings saved successfully" [success] | `frontend/app.js:2170` (loadFail2BanSettings) |
| Security | dynamic: `'Failed to save Fail2Ban settings: ' + (result.msg \|\| result.detail \|\| 'U...` [error] | `frontend/app.js:2174` (loadFail2BanSettings) |
| Security | dynamic: `'Failed to save Fail2Ban settings: ' + err.message` [error] | `frontend/app.js:2177` (loadFail2BanSettings) |
| Security | "Fail2Ban IP lists saved successfully" [success] | `frontend/app.js:2223` (loadFail2BanSettings) |
| Security | dynamic: `'Failed to save Fail2Ban IP lists: ' + (result.msg \|\| result.detail \|\| 'U...` [error] | `frontend/app.js:2226` (loadFail2BanSettings) |
| Security | dynamic: `'Failed to save Fail2Ban IP lists: ' + err.message` [error] | `frontend/app.js:2229` (loadFail2BanSettings) |
| Security | dynamic: `detail.detail \|\| `Could not ${action} SMTP`` [error] | `frontend/smtp-abuse.js:170` (smtpAbuseAction) |
| Security | dynamic: `action === 'block' ? 'SMTP disabled' : 'SMTP re-enabled'` [success] | `frontend/smtp-abuse.js:173` (smtpAbuseAction) |
| Security | dynamic: ``Could not ${action} SMTP`` [error] | `frontend/smtp-abuse.js:176` (smtpAbuseAction) |
| Security | dynamic: `detail.detail \|\| 'Could not save whitelist'` [error] | `frontend/smtp-abuse.js:203` (saveSmtpAbuseWhitelist) |
| Security | "Whitelist saved" [success] | `frontend/smtp-abuse.js:207` (saveSmtpAbuseWhitelist) |
| Security | "Could not save whitelist" [error] | `frontend/smtp-abuse.js:210` (saveSmtpAbuseWhitelist) |
| Security | "Could not remove whitelist entry" [error] | `frontend/smtp-abuse.js:218` (removeSmtpAbuseWhitelist) |
| Security | "Whitelist entry removed" [success] | `frontend/smtp-abuse.js:219` (removeSmtpAbuseWhitelist) |
| Security | "Could not remove whitelist entry" [error] | `frontend/smtp-abuse.js:222` (removeSmtpAbuseWhitelist) |
| Queue | dynamic: `result.msg \|\| `${labels[action] \|\| action} completed`` [success] | `frontend/app.js:2529` (queueAction) |
| Queue | dynamic: ``Queue action failed: ` + (result.msg \|\| result.detail \|\| 'Unknown error')` [error] | `frontend/app.js:2533` (queueAction) |
| Queue | dynamic: ``Queue action failed: ` + err.message` [error] | `frontend/app.js:2536` (queueAction) |
| Queue | dynamic: `result.msg \|\| 'Message deleted from queue'` [success] | `frontend/app.js:2556` (queueDeleteRequest) |
| Queue | dynamic: `'Failed to delete from queue: ' + (result.msg \|\| result.detail \|\| 'Unknow...` [error] | `frontend/app.js:2560` (queueDeleteRequest) |
| Queue | dynamic: `'Failed to delete from queue: ' + err.message` [error] | `frontend/app.js:2563` (queueDeleteRequest) |
| Quarantine | dynamic: `result.msg \|\| `Message(s) ${actionLabels[action] \|\| action} successfully`` [success] | `frontend/app.js:2900` (quarantineAction) |
| Quarantine | dynamic: ``Failed to ${action} message(s): ` + (result.msg \|\| result.detail \|\| 'Unk...` [error] | `frontend/app.js:2904` (quarantineAction) |
| Quarantine | dynamic: ``Failed to ${action} message(s): ` + err.message` [error] | `frontend/app.js:2907` (quarantineAction) |
| Quarantine | "Rule not found" [error] | `frontend/app.js:3196` (showEditQuarantineRuleModal) |
| Quarantine | "Rule name is required" [error] | `frontend/app.js:3343` (saveQuarantineRule) |
| Quarantine | "Match value is required" [error] | `frontend/app.js:3344` (saveQuarantineRule) |
| Quarantine | dynamic: `isEdit ? 'Rule updated' : 'Rule created'` [success] | `frontend/app.js:3376` (saveQuarantineRule) |
| Quarantine | dynamic: `'Failed to save rule: ' + err.message` [error] | `frontend/app.js:3379` (saveQuarantineRule) |
| Quarantine | "Rule deleted" [success] | `frontend/app.js:3390` (deleteQuarantineRule) |
| Quarantine | dynamic: `'Failed to delete rule: ' + err.message` [error] | `frontend/app.js:3393` (deleteQuarantineRule) |
| Quarantine | dynamic: ``Rule ${rule.enabled ? 'enabled' : 'disabled'}`` [success] | `frontend/app.js:3403` (toggleQuarantineRule) |
| Quarantine | dynamic: `'Failed to toggle rule: ' + err.message` [error] | `frontend/app.js:3406` (toggleQuarantineRule) |
| Quarantine | "Testing rules against quarantine..." [info] | `frontend/app.js:3412` (testQuarantineRules) |
| Quarantine | dynamic: ``No matches found (${data.total_quarantine} quarantine items checked)`` [info] | `frontend/app.js:3419` (testQuarantineRules) |
| Quarantine | dynamic: `'Test failed: ' + err.message` [error] | `frontend/app.js:3487` (testQuarantineRules) |
| Spam filter | dynamic: ``Cannot save: ${valData.errors.length} validation error(s). Fix them first.`` [error] | `frontend/spam_filter.js:359` (saveMapContent) |
| Spam filter | dynamic: `'Validation failed: ' + e.message` [error] | `frontend/spam_filter.js:364` (saveMapContent) |
| Spam filter | dynamic: ``Map saved (${result.entry_count} entries). ${result.normalized_entries} bare...` [success] | `frontend/spam_filter.js:389` (saveMapContent) |
| Spam filter | dynamic: ``Map saved successfully (${result.entry_count} entries)`` [success] | `frontend/spam_filter.js:391` (saveMapContent) |
| Spam filter | dynamic: `'Failed to save map: ' + error.message` [error] | `frontend/spam_filter.js:399` (saveMapContent) |
| Spam filter | dynamic: `type === 'domain' ? 'Domain name is required' : 'Email address is required'` [error] | `frontend/spam_filter.js:694` (renderSuppressionItem) |
| Spam filter | "Enter a plain domain name, for example example.com" [error] | `frontend/spam_filter.js:706` (renderSuppressionItem) |
| Spam filter | "This address is already suppressed" [error] | `frontend/spam_filter.js:730` (renderSuppressionItem) |
| Spam filter | dynamic: ``Suppression added: ${email}`` [success] | `frontend/spam_filter.js:739` (renderSuppressionItem) |
| Spam filter | dynamic: `error.message` [error] | `frontend/spam_filter.js:747` (renderSuppressionItem) |
| Spam filter | "Please set an expiry date" [error] | `frontend/spam_filter.js:853` (renderSuppressionItem) |
| Spam filter | "Suppression updated" [success] | `frontend/spam_filter.js:868` (renderSuppressionItem) |
| Spam filter | dynamic: `error.message` [error] | `frontend/spam_filter.js:874` (renderSuppressionItem) |
| Spam filter | dynamic: ``Suppression ${newActive ? 'activated' : 'deactivated'}`` [success] | `frontend/spam_filter.js:888` (renderSuppressionItem) |
| Spam filter | dynamic: `error.message` [error] | `frontend/spam_filter.js:894` (renderSuppressionItem) |
| Spam filter | dynamic: ``Suppression deleted: ${email}`` [success] | `frontend/spam_filter.js:905` (renderSuppressionItem) |
| Spam filter | dynamic: `error.message` [error] | `frontend/spam_filter.js:911` (renderSuppressionItem) |
| Spam filter | dynamic: ``Synced ${result.synced} suppressions to Rspamd (${result.newly_synced} new)`` [success] | `frontend/spam_filter.js:955` (renderSuppressionItem) |
| Spam filter | dynamic: `'Sync failed: ' + error.message` [error] | `frontend/spam_filter.js:959` (renderSuppressionItem) |
| Spam filter | dynamic: ``Imported ${result.imported} suppressions (${result.skipped} skipped)`` [success] | `frontend/spam_filter.js:995` (renderSuppressionItem) |
| Spam filter | dynamic: `'Import failed: ' + error.message` [error] | `frontend/spam_filter.js:1001` (renderSuppressionItem) |
| Spam filter | dynamic: ``Pattern added: ${pattern}`` [success] | `frontend/spam_filter.js:1184` (renderSuppressionItem) |
| Status | "Starting blacklist check..." [info] | `frontend/app.js:4109` (checkBlacklists) |
| Status | "Blacklist check completed" [success] | `frontend/app.js:4155` (checkBlacklists) |
| Status | dynamic: ``Check completed for ${host}`` [success] | `frontend/app.js:4183` (checkBlacklists) |
| Status | dynamic: ``Failed to check: ${error.message}`` [error] | `frontend/app.js:4192` (checkBlacklists) |
| Status | dynamic: ``Job "${displayName}" started successfully`` [success] | `frontend/app.js:4606` (triggerBackgroundJob) |
| Status | dynamic: ``Job "${displayName}" is already running`` [warning] | `frontend/app.js:4615` (triggerBackgroundJob) |
| Status | dynamic: ``Failed to start job: ${error.message}`` [error] | `frontend/app.js:4618` (triggerBackgroundJob) |
| Domains | "DNS check already in progress" [warning] | `frontend/domains.js:634` (checkAllDomainsDNS) |
| Domains | dynamic: ``✓ Checked ${result.domains_checked} domains`` [success] | `frontend/domains.js:654` (checkAllDomainsDNS) |
| Domains | "DNS check failed" [error] | `frontend/domains.js:657` (checkAllDomainsDNS) |
| Domains | "Failed to check DNS" [error] | `frontend/domains.js:661` (checkAllDomainsDNS) |
| Domains | "DNS check already in progress" [warning] | `frontend/domains.js:675` (checkSingleDomainDNS) |
| Domains | dynamic: ``Checking DNS for ${domainName}...`` [info] | `frontend/domains.js:680` (checkSingleDomainDNS) |
| Domains | dynamic: ``✓ DNS checked for ${domainName}`` [success] | `frontend/domains.js:694` (checkSingleDomainDNS) |
| Domains | dynamic: ``Failed to check DNS for ${domainName}`` [error] | `frontend/domains.js:782` (checkSingleDomainDNS) |
| Domains | "Failed to check DNS" [error] | `frontend/domains.js:786` (checkSingleDomainDNS) |
| DMARC | "Manual upload is disabled" [error] | `frontend/dmarc.js:1316` (uploadDmarcReport) |
| DMARC | dynamic: ``${reportType} report uploaded: ${count} ${countLabel}`` [success] | `frontend/dmarc.js:1329` (uploadDmarcReport) |
| DMARC | dynamic: ``${reportType} report already exists`` [warning] | `frontend/dmarc.js:1341` (uploadDmarcReport) |
| DMARC | "Failed to upload report" [error] | `frontend/dmarc.js:1346` (uploadDmarcReport) |
| DMARC | "IMAP sync is not enabled" [error] | `frontend/dmarc.js:1424` (triggerDmarcSync) |
| DMARC | "Sync is already in progress" [info] | `frontend/dmarc.js:1439` (triggerDmarcSync) |
| DMARC | "IMAP sync started" [success] | `frontend/dmarc.js:1441` (triggerDmarcSync) |
| DMARC | "Failed to start sync" [error] | `frontend/dmarc.js:1455` (triggerDmarcSync) |
| DMARC | "Report deletion is disabled" [error] | `frontend/dmarc.js:1722` (deleteReport) |
| DMARC | dynamic: ``${reportType.toUpperCase()} report deleted`` [success] | `frontend/dmarc.js:1730` (deleteReport) |
| DMARC | "Failed to delete report" [error] | `frontend/dmarc.js:1744` (deleteReport) |
| Mailbox stats | "Please select both start and end dates" [error] | `frontend/mailbox-stats.js:740` (applyCustomDateRange) |
| Mailbox stats | "Start date must be before end date" [error] | `frontend/mailbox-stats.js:748` (applyCustomDateRange) |
| Mailbox stats | dynamic: `detail.detail \|\| 'Could not reset the counter'` [error] | `frontend/rate-limits.js:645` (resetRateLimitCounter) |
| Mailbox stats | dynamic: ``${user} can send again`` [success] | `frontend/rate-limits.js:649` (resetRateLimitCounter) |
| Mailbox stats | "Could not reset the counter" [error] | `frontend/rate-limits.js:658` (resetRateLimitCounter) |
| Mailbox stats | "Enter how many messages to allow, as a whole number" [error] | `frontend/rate-limits.js:939` (applyRateLimitBulk) |
| Mailbox stats | dynamic: `detail.detail \|\| 'Could not apply the rate limit'` [error] | `frontend/rate-limits.js:971` (applyRateLimitBulk) |
| Mailbox stats | dynamic: ``Nothing was changed${tail}`` [warning] | `frontend/rate-limits.js:1015` (applyRateLimitBulk) |
| Mailbox stats | dynamic: `value === 0 ? `Limit removed from ${changed}${tail}` : `Limit set on ${change...` [success] | `frontend/rate-limits.js:1018` (applyRateLimitBulk) |
| Mailbox stats | "Could not apply the rate limit" [error] | `frontend/rate-limits.js:1023` (applyRateLimitBulk) |
| Mailbox stats | "Enter how many messages to allow, as a whole number" [error] | `frontend/rate-limits.js:1116` (saveRateLimit) |
| Mailbox stats | dynamic: `detail.detail \|\| 'Could not save the rate limit'` [error] | `frontend/rate-limits.js:1153` (submitRateLimit) |
| Mailbox stats | dynamic: `value === 0 ? `${name} now sends without a limit` : `${name} is limited to ${...` [success] | `frontend/rate-limits.js:1158` (submitRateLimit) |
| Mailbox stats | "Could not save the rate limit" [error] | `frontend/rate-limits.js:1189` (submitRateLimit) |
| Settings | dynamic: `detail.detail \|\| 'Could not save destination'` [error] | `frontend/notifications.js:253` (saveNotificationChannel) |
| Settings | dynamic: `isNew ? 'Destination added' : 'Destination updated'` [success] | `frontend/notifications.js:256` (saveNotificationChannel) |
| Settings | "Could not save destination" [error] | `frontend/notifications.js:260` (saveNotificationChannel) |
| Settings | "Could not delete destination" [error] | `frontend/notifications.js:275` (deleteNotificationChannel) |
| Settings | "Destination deleted" [success] | `frontend/notifications.js:276` (deleteNotificationChannel) |
| Settings | "Could not delete destination" [error] | `frontend/notifications.js:279` (deleteNotificationChannel) |
| Settings | "Cannot enable Basic Auth without a password. Please set a password first." [error] | `frontend/settings.js:1758` (renderSettings) |
| Settings | "Basic Auth enabled successfully! You will need to log in on your next visit." [success] | `frontend/settings.js:1804` (renderSettings) |
| Settings | dynamic: ``Purging data for ${purgeableNewlyDisabled.length} disabled feature(s)...`` [info] | `frontend/settings.js:1821` (renderSettings) |
| Settings | "Features updated - reloading..." [success] | `frontend/settings.js:1835` (renderSettings) |
| Settings | dynamic: `'Failed to save: ' + (err.message \|\| err)` [error] | `frontend/settings.js:1844` (renderSettings) |
| Settings | "MaxMind license is valid" [success] | `frontend/settings.js:2106` (validateMaxMindLicense) |
| Settings | dynamic: `'MaxMind license validation failed: ' + result.error` [error] | `frontend/settings.js:2108` (validateMaxMindLicense) |
| Settings | "Failed to validate MaxMind license" [error] | `frontend/settings.js:2117` (validateMaxMindLicense) |
| Settings | "GeoIP database re-download started…" [info] | `frontend/settings.js:2142` (repairGeoIPDatabase) |
| Settings | "GeoIP databases repaired successfully" [success] | `frontend/settings.js:2165` (repairGeoIPDatabase) |
| Settings | "GeoIP databases re-downloaded but validation still failed" [error] | `frontend/settings.js:2167` (repairGeoIPDatabase) |
| Settings | "GeoIP repair timed out - check Status page for progress" [warning] | `frontend/settings.js:2180` (repairGeoIPDatabase) |
| Settings | dynamic: `'Failed to repair GeoIP databases: ' + error.message` [error] | `frontend/settings.js:2191` (repairGeoIPDatabase) |
| Shared | "Download started." [success] | `frontend/export.js:34` (exportCSV) |
| Shared | dynamic: `error.message \|\| 'Could not export CSV. Please try again.'` [error] | `frontend/export.js:37` (exportCSV) |
| Shared | dynamic: `'Copied: ' + text` [success] | `frontend/utils.js:427` (copyToClipboard) |
| Shared | "Failed to copy" [error] | `frontend/utils.js:442` (copyToClipboard) |

### Confirmation dialogs

Every action that asks before it acts. Losing one turns a guarded action into a one-click action.

| Page | What | Code |
|---|---|---|
| Security | showConfirmModal: dynamic: `{ title: 'Unban IP', message: 'Unban IP ' + ipWithMask + '?', confirmText: 'U...` | `frontend/app.js:1012` (unbanIP) |
| Security | showConfirmModal: dynamic: `{ title: 'Ban IP', message: `Are you sure you want to permanently ban ${ipWit...` | `frontend/app.js:1049` (banIP) |
| Security | showConfirmModal: dynamic: `{ title: action === 'block' ? 'Disable SMTP' : 'Re-enable SMTP', message: `${...` | `frontend/smtp-abuse.js:155` (smtpAbuseAction) |
| Queue | showConfirmModal: dynamic: `{ title: 'Retry Delivery', message: `Retry delivery of ${ids.length} message(...` | `frontend/app.js:2475` (queueBulkRetry) |
| Queue | showConfirmModal: dynamic: `{ title: 'Delete Messages', message: `Permanently delete ${ids.length} messag...` | `frontend/app.js:2482` (queueBulkDelete) |
| Queue | showConfirmModal: dynamic: `{ title: 'Delete Message', message: 'Delete this message from the queue?', co...` | `frontend/app.js:2501` (queueDeleteItem) |
| Queue | showConfirmModal: dynamic: `{ title: 'Flush Queue', message: 'Flush (retry delivery of) ALL messages in t...` | `frontend/app.js:2506` (queueFlushAll) |
| Queue | showConfirmModal: dynamic: `{ title: 'Delete All', message: 'Permanently delete ALL messages from the que...` | `frontend/app.js:2511` (queueDeleteAll) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete Message', message: 'Are you sure you want to permanently del...` | `frontend/app.js:2823` (quarantineDelete) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Not Spam', message: 'Release this message and train Rspamd that it ...` | `frontend/app.js:2828` (quarantineLearnHam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Mark as Spam', message: 'Delete this message and train Rspamd that ...` | `frontend/app.js:2833` (quarantineLearnSpam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Release Messages', message: `Release ${ids.length} quarantined mess...` | `frontend/app.js:2840` (quarantineBulkRelease) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete Messages', message: `Permanently delete ${ids.length} quaran...` | `frontend/app.js:2847` (quarantineBulkDelete) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Not Spam', message: `Release ${ids.length} message(s) and train Rsp...` | `frontend/app.js:2854` (quarantineBulkLearnHam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Mark as Spam', message: `Delete ${ids.length} message(s) and train ...` | `frontend/app.js:2861` (quarantineBulkLearnSpam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Release All', message: `Release ALL ${allIds.length} quarantined me...` | `frontend/app.js:2868` (quarantineReleaseAll) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete All', message: `Permanently delete ALL ${allIds.length} quar...` | `frontend/app.js:2875` (quarantineDeleteAll) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete Rule', message: `Delete rule "${ruleName}"?`, confirmText: '...` | `frontend/app.js:3384` (deleteQuarantineRule) |
| Spam filter | showConfirmModal: dynamic: `{ title: 'Delete Suppression', message: `Delete suppression for ${email}? Thi...` | `frontend/spam_filter.js:899` (renderSuppressionItem) |
| DMARC | showConfirmModal: dynamic: `{ title: 'Delete Report', message: `Are you sure you want to delete this ${re...` | `frontend/dmarc.js:1712` (deleteReport) |
| Mailbox stats | showConfirmModal: dynamic: `{ title: 'Reset rate limit counter', message: `Let ${user} send again straigh...` | `frontend/rate-limits.js:629` (resetRateLimitCounter) |
| Mailbox stats | showConfirmModal: dynamic: `{ title: value === 0 ? 'Remove rate limits' : 'Apply rate limit', message: va...` | `frontend/rate-limits.js:947` (applyRateLimitBulk) |
| Mailbox stats | showConfirmModal: dynamic: `{ title: 'Remove rate limit', message: `Remove the rate limit on ${name}? It ...` | `frontend/rate-limits.js:1125` (removeRateLimit) |
| Settings | showConfirmModal: dynamic: `{ title: 'Delete destination', message: `Delete "${channel ? channel.name : '...` | `frontend/notifications.js:266` (deleteNotificationChannel) |
| Settings | showFeatureDisableConfirmModal: dynamic: `purgeableNewlyDisabled` | `frontend/settings.js:1788` (renderSettings) |
| Settings | showConfirmModal: dynamic: `{ title: 'Import from ENV', message: 'Import current configuration from ENV i...` | `frontend/settings.js:1850` (renderSettings) |
| Shared | confirm: dynamic: `` | `frontend/utils.js:504` |

### Country flags

PNG flags served locally from `frontend/assets/flags/<size>/<cc>.png` (sizes 16x12, 24x18, 48x36), no emoji and no external source.

| Page | What | Code |
|---|---|---|
| Message details | renderGeoIPInfo(rspamd, '16x12') | `frontend/message-details.js:527` (renderOverviewTab) |
| Security | getFlagUrl(log.country_code, '16x12') | `frontend/app.js:975` (renderNetfilterData) |
| Security | getFlagUrl(d.country_code, '24x18') | `frontend/app.js:1662` (loadSecurityCountryChart) |
| Shared | getFlagUrl(rspamdData.country_code, size) | `frontend/app.js:4690` (renderGeoIPInfo) |
| Shared | getFlagUrl(record.country_code, size) | `frontend/app.js:4733` (renderGeoIPForDMARC) |

### Markdown rendering

Places that render Markdown (help pages, changelogs) through `renderMarkdown` (marked, then DOMPurify) into a `.markdown-body` element.

| Page | What | Code |
|---|---|---|
| Settings | renders `versionInfo.changelog` | `frontend/settings.js:924` (updateVersionInfoUI) |
| Settings | renders `changelogText` | `frontend/settings.js:1542` (renderSettings) |
| Modal: changelog-modal | renders `markdownContent` | `frontend/app.js:652` (showMarkdownModal) |
| Modal: changelog-modal | renders `changelog` | `frontend/app.js:4646` (showChangelogModal) |

### Controls wired in JavaScript

Buttons, tabs and fields whose behavior is attached with `addEventListener` instead of an inline handler. The automatic inventory test does not see these, so they need a manual check.

| Page | What | Code |
|---|---|---|
| Shell | change on `px)')` | `frontend/app.js:467` (loadAppInfo) |
| Shell | click on `document` | `frontend/router.js:317` |
| Messages | click on `document` | `frontend/app.js:3672` |
| Message details | click on `messageModal` | `frontend/message-details.js:878` |
| Message details | click on `modalContent` | `frontend/message-details.js:888` |
| Security | click on `editSettingsBtn` | `frontend/app.js:2108` (loadFail2BanSettings) |
| Security | click on `editIpBtn` | `frontend/app.js:2124` (loadFail2BanSettings) |
| Security | submit on `settingsForm` | `frontend/app.js:2135` (loadFail2BanSettings) |
| Security | submit on `ipForm` | `frontend/app.js:2188` (loadFail2BanSettings) |
| Spam filter | click on `document` | `frontend/spam_filter.js:1024` (renderSuppressionItem) |
| DMARC | click on `modal` | `frontend/dmarc.js:1475` (showDmarcSyncHistory) |
| Mailbox stats | click on `document` | `frontend/mailbox-stats.js:671` (toggleDateRangePicker) |
| Settings | click on `cancelBtn` | `frontend/settings.js:114` (showBasicAuthVerifyModal) |
| Settings | click on `confirmBtn` | `frontend/settings.js:115` (showBasicAuthVerifyModal) |
| Settings | click on `overlay` | `frontend/settings.js:129` (showBasicAuthVerifyModal) |
| Settings | click on `cancelBtn` | `frontend/settings.js:204` (showFeatureDisableConfirmModal) |
| Settings | click on `confirmBtn` | `frontend/settings.js:205` (showFeatureDisableConfirmModal) |
| Settings | click on `overlay` | `frontend/settings.js:212` (showFeatureDisableConfirmModal) |
| Settings | click on `btn` | `frontend/settings.js:1673` (renderSettings) |
| Settings | change on `tabSelect` | `frontend/settings.js:1680` (renderSettings) |
| Settings | click on `btn` | `frontend/settings.js:1687` (renderSettings) |
| Settings | change on `cb` | `frontend/settings.js:1717` (renderSettings) |
| Settings | click on `closeBtn` | `frontend/settings.js:1933` (showGeoIPSetupModal) |
| Settings | click on `modal` | `frontend/settings.js:2387` (showConnectionTestModal) |
| Shared | click on `cancelBtn` | `frontend/utils.js:570` (showConfirmModal) |
| Shared | click on `okBtn` | `frontend/utils.js:571` (showConfirmModal) |
| app.js (mixed) | click on `changelogModal` | `frontend/app.js:4841` |
| app.js (mixed) | click on `changelogContent` | `frontend/app.js:4849` |

### Filters, sorting and view options

Drop-down lists in the page markup with their options. The option wording and order are part of the product.

| Page | What | Code |
|---|---|---|
| Dashboard | `dashboard-search-status`: All Statuses / Delivered / Sent / Deferred / Bounced / Rejected / Discarded (Sieve) / Expired | `frontend/index.html:573` |
| Messages | `messages-filter-direction`: All Directions / Inbound / Outbound / Internal | `frontend/index.html:676` |
| Messages | `messages-filter-status`: All Statuses / Delivered / Deferred / Bounced / Rejected / Spam / Discarded (Sieve) | `frontend/index.html:682` |
| Security | `netfilter-filter-action`: All Actions / BAN / UNBAN / Warning / Info | `frontend/index.html:765` |
| Security | `netfilter-filter-country`: All Countries | `frontend/index.html:772` |
| Quarantine | `quarantine-sort`: Newest first / Score: high to low / Score: low to high | `frontend/index.html:888` |
| Spam filter | `suppression-filter-reason`: All Reasons / Hard Bounce / Soft Bounce / Deferred Stuck / Rejected / Manual | `frontend/index.html:952` |
| Spam filter | `suppression-filter-active`: Active Only / All / Inactive / Expired | `frontend/index.html:962` |
| Mailbox stats | `mailbox-stats-domain-filter`: All Domains | `frontend/index.html:1607` |
| Mailbox stats | `mailbox-stats-sort`: Sent (High to Low) / Received (High to Low) / Failure Rate (High to Low) / Quota Used (High to Low) / Username (A-Z) | `frontend/index.html:1611` |
| Logs | `logs-fontsize`: 10px / 11px / 12px / 13px / 14px / 16px | `frontend/index.html:1748` |

### Charts

Chart.js charts (local library). Check hover tooltips, legend and both themes.

| Page | What | Code |
|---|---|---|
| Security | bar chart on `ctx` | `frontend/app.js:1753` (loadSecurityCountryChart) |
| DMARC | line chart on `ctx` | `frontend/dmarc.js:592` (renderDmarcChart) |
| Mailbox stats | bar chart on `canvas.getContext('2d')` | `frontend/rate-limits.js:276` (renderRateLimitChart) |

### Colour thresholds

Values whose colour changes at a threshold (for example storage turns yellow and red, a high spam score turns red).

| Page | What | Code |
|---|---|---|
| Quarantine | `sc > 0` turns red | `frontend/app.js:2986` (renderQuarantineDetailContent) |
| Quarantine | `sc < 0` turns green | `frontend/app.js:2987` (renderQuarantineDetailContent) |
| Status | `usedPercent > 90` turns red | `frontend/app.js:4015` (loadStatusStorage) |
| Status | `usedPercent > 75` turns yellow | `frontend/app.js:4016` (loadStatusStorage) |
| Status | `usedPercent > 90` turns red | `frontend/app.js:4018` (loadStatusStorage) |
| Status | `usedPercent > 75` turns yellow | `frontend/app.js:4019` (loadStatusStorage) |
| DMARC | `passRate >= 95` turns green | `frontend/dmarc.js:345` (loadDmarcDomains) |
| DMARC | `passRate >= 80` turns yellow | `frontend/dmarc.js:345` (loadDmarcDomains) |
| DMARC | `passRate >= 95` turns green | `frontend/dmarc.js:346` (loadDmarcDomains) |
| DMARC | `passRate >= 80` turns yellow | `frontend/dmarc.js:346` (loadDmarcDomains) |
| DMARC | `passRate >= 95` turns green | `frontend/dmarc.js:347` (loadDmarcDomains) |
| DMARC | `stats.tls_success_pct >= 95` turns green | `frontend/dmarc.js:390` (loadDmarcDomains) |
| DMARC | `stats.tls_success_pct >= 80` turns yellow | `frontend/dmarc.js:390` (loadDmarcDomains) |
| DMARC | `stats.tls_success_pct >= 95` turns green | `frontend/dmarc.js:392` (loadDmarcDomains) |
| DMARC | `stats.tls_success_pct >= 80` turns yellow | `frontend/dmarc.js:392` (loadDmarcDomains) |
| DMARC | `passRate >= 95` turns green | `frontend/dmarc.js:404` (loadDmarcDomains) |
| DMARC | `passPct >= 95` turns green | `frontend/dmarc.js:639` (loadDomainReports) |
| DMARC | `passPct >= 95` turns green | `frontend/dmarc.js:702` (loadDomainSources) |
| DMARC | `s.spf_pass_pct >= 95` turns green | `frontend/dmarc.js:741` (loadDomainSources) |
| DMARC | `s.dkim_pass_pct >= 95` turns green | `frontend/dmarc.js:746` (loadDomainSources) |
| DMARC | `successRate >= 95` turns green | `frontend/dmarc.js:816` (loadDomainTLSReports) |
| DMARC | `successRate >= 80` turns yellow | `frontend/dmarc.js:816` (loadDomainTLSReports) |
| DMARC | `day.success_rate >= 95` turns green | `frontend/dmarc.js:843` (loadDomainTLSReports) |
| DMARC | `day.success_rate >= 80` turns yellow | `frontend/dmarc.js:844` (loadDomainTLSReports) |
| DMARC | `day.success_rate >= 95` turns green | `frontend/dmarc.js:846` (loadDomainTLSReports) |
| DMARC | `day.success_rate >= 80` turns yellow | `frontend/dmarc.js:846` (loadDomainTLSReports) |
| DMARC | `successRate >= 95` turns green | `frontend/dmarc.js:931` (loadTLSReportDetails) |
| DMARC | `successRate >= 80` turns yellow | `frontend/dmarc.js:931` (loadTLSReportDetails) |
| DMARC | `p.success_rate >= 95` turns green | `frontend/dmarc.js:992` (loadTLSReportDetails) |
| DMARC | `p.success_rate >= 80` turns yellow | `frontend/dmarc.js:992` (loadTLSReportDetails) |
| DMARC | `p.success_rate >= 95` turns green | `frontend/dmarc.js:1012` (loadTLSReportDetails) |
| DMARC | `p.success_rate >= 80` turns yellow | `frontend/dmarc.js:1012` (loadTLSReportDetails) |
| DMARC | `s.dmarc_pass_pct >= 95` turns green | `frontend/dmarc.js:1111` (loadReportDetails) |
| DMARC | `s.spf_pass_pct >= 95` turns green | `frontend/dmarc.js:1112` (loadReportDetails) |
| DMARC | `s.dkim_pass_pct >= 95` turns green | `frontend/dmarc.js:1113` (loadReportDetails) |
| DMARC | `dmarcPct >= 95` turns green | `frontend/dmarc.js:1230` (loadSourceDetails) |
| DMARC | `spfPct >= 95` turns green | `frontend/dmarc.js:1231` (loadSourceDetails) |
| DMARC | `dkimPct >= 95` turns green | `frontend/dmarc.js:1232` (loadSourceDetails) |
| DMARC | `sync.reports_failed > 0` turns red | `frontend/dmarc.js:1520` (showDmarcSyncHistory) |
| Mailbox stats | `mb.combined_failure_rate >= 10` turns red | `frontend/mailbox-stats.js:315` (renderMailboxStatsAccordion) |
| Mailbox stats | `mb.combined_failure_rate >= 5` turns yellow | `frontend/mailbox-stats.js:316` (renderMailboxStatsAccordion) |
| Mailbox stats | `quotaPercent >= 90` turns red | `frontend/mailbox-stats.js:321` (renderMailboxStatsAccordion) |
| Mailbox stats | `quotaPercent >= 75` turns yellow | `frontend/mailbox-stats.js:321` (renderMailboxStatsAccordion) |
| Mailbox stats | `alias.failure_rate >= 5` turns red | `frontend/mailbox-stats.js:567` (renderMailboxStatsAccordion) |

### Help topics

In-app help buttons; the topic is the Markdown file name under documentation/HelpDocs.

| Page | What | Code |
|---|---|---|
| Security | topic "Abuse_Protection" | `frontend/index.html:746` |
| Quarantine | topic "Quarantine" | `frontend/index.html:845` |
| Spam filter | topic "Spam_Filter" | `frontend/index.html:906` |
| Status | topic "IP_Blacklist_Monitor" | `frontend/index.html:1069` |
| Domains | topic "Domains" | `frontend/index.html:1164` |
| DMARC | topic "DMARC" | `frontend/index.html:1196` |
| Mailbox stats | topic "Mailbox_Stats" | `frontend/index.html:1401` |
| Mailbox stats | topic dynamic: `'${isRateLimits ? 'Rate_Limits' : 'Mailbox_Stats'}'` | `frontend/mailbox-stats.js:82` (mailboxStatsSwitchView) |

### Empty states

Text shown when a list or panel has nothing to show.

| Page | What | Code |
|---|---|---|
| Shell | "No changelog available" | `frontend/app.js:633` (loadAppVersionStatus) |
| Shell | "No changelog available" | `frontend/app.js:694` (loadMailcowVersionStatus) |
| Dashboard | "No blacklist data yet" | `frontend/app.js:4247` (loadDashboardBlacklistSummary) |
| Messages | "No messages found" | `frontend/app.js:893` (renderMessagesData) |
| Messages | "No messages found" | `frontend/app.js:3792` (loadMessages) |
| Message details | "No modal data available" | `frontend/message-details.js:70` (switchModalTab) |
| Message details | "No delivery steps recorded yet" | `frontend/message-details.js:502` (renderDeliverySteps) |
| Message details | "No Postfix delivery logs available" | `frontend/message-details.js:577` (renderPostfixTab) |
| Message details | "No Postfix delivery logs available" | `frontend/message-details.js:582` (renderPostfixTab) |
| Message details | "No spam analysis data available" | `frontend/message-details.js:744` (renderSpamTab) |
| Security | "No logs found" | `frontend/app.js:930` (renderNetfilterData) |
| Security | "No matching entries" | `frontend/smtp-abuse.js:137` (renderSmtpAbusePanel) |
| Queue | "No matching queue entries" | `frontend/app.js:2310` (applyQueueFilters) |
| Quarantine | "No quarantined messages" | `frontend/app.js:2633` (loadQuarantine) |
| Quarantine | "No quarantined messages" | `frontend/app.js:2661` (renderQuarantineData) |
| Quarantine | "No actions recorded yet" | `frontend/app.js:3515` (loadQuarantineRuleHistory) |
| Status | "No container information available" | `frontend/app.js:3899` (loadStatusContainers) |
| Status | "No changelog available" | `frontend/app.js:3933` (loadStatusSystem) |
| Domains | "No domains found" | `frontend/domains.js:83` (renderDomains) |
| Domains | "No domains with DNS issues found" | `frontend/domains.js:216` (filterDomains) |
| Domains | "No domains found matching" | `frontend/domains.js:217` (filterDomains) |
| DMARC | "No daily reports available" | `frontend/dmarc.js:631` (loadDomainReports) |
| DMARC | "No sources found" | `frontend/dmarc.js:689` (loadDomainSources) |
| DMARC | "No sources found" | `frontend/dmarc.js:1088` (loadReportDetails) |
| DMARC | "No data found" | `frontend/dmarc.js:1208` (loadSourceDetails) |
| DMARC | "No sync history yet" | `frontend/dmarc.js:1482` (showDmarcSyncHistory) |
| DMARC | "No reports found" | `frontend/dmarc.js:1598` (renderReportsManagementTable) |
| Mailbox stats | "No mailboxes found" | `frontend/mailbox-stats.js:301` (renderMailboxStatsAccordion) |
| Logs | "No log services available" | `frontend/logs-viewer.js:90` (loadLogViewer) |
| Logs | "No log entries found" | `frontend/logs-viewer.js:459` (renderLogEntries) |
| Settings | "No logs available" | `frontend/notifications.js:288` (testNotificationChannel) |
| Settings | "No logs available" | `frontend/notifications.js:305` (testNotificationChannelDraft) |
| Settings | "No changelog available" | `frontend/settings.js:1513` (renderSettings) |
| Settings | "No logs available" | `frontend/settings.js:2319` (testSmtpConnection) |
| Settings | "No logs available" | `frontend/settings.js:2345` (testImapConnection) |
| Modal: changelog-modal | "No changelog available" | `frontend/app.js:4648` (showChangelogModal) |
| Modal: container-logs-modal | "No logs available" | `frontend/app.js:4924` (fetchContainerLogs) |

### Loading states

Functions that render a spinner or "Loading..." while data is fetched.

| Page | What | Code |
|---|---|---|
| Messages | 1 loading indicator(s) | `frontend/app.js:3756` (loadMessages) |
| Message details | 1 loading indicator(s) | `frontend/message-details.js:99` (viewMessageDetails) |
| Security | 1 loading indicator(s) | `frontend/app.js:1846` (loadNetfilterLogs) |
| Queue | 1 loading indicator(s) | `frontend/app.js:2260` (loadQueue) |
| Quarantine | 1 loading indicator(s) | `frontend/app.js:2613` (loadQuarantine) |
| Quarantine | 1 loading indicator(s) | `frontend/app.js:2934` (showQuarantineDetails) |
| Quarantine | 1 loading indicator(s) | `frontend/app.js:3507` (loadQuarantineRuleHistory) |
| Status | 2 loading indicator(s) | `frontend/app.js:4101` (checkBlacklists) |
| Status | 1 loading indicator(s) | `frontend/app.js:4593` (triggerBackgroundJob) |
| Domains | 1 loading indicator(s) | `frontend/domains.js:641` (checkAllDomainsDNS) |
| DMARC | 1 loading indicator(s) | `frontend/dmarc.js:134` (loadDmarc) |
| Logs | 1 loading indicator(s) | `frontend/logs-viewer.js:1096` (loadDateRangeLogs) |
| Settings | 3 loading indicator(s) | `frontend/settings.js:1559` (renderSettings) |
| Settings | 2 loading indicator(s) | `frontend/settings.js:1890` (showGeoIPSetupModal) |
| Settings | 1 loading indicator(s) | `frontend/settings.js:2080` (validateMaxMindLicense) |
| Settings | 1 loading indicator(s) | `frontend/settings.js:2126` (repairGeoIPDatabase) |
| Settings | 1 loading indicator(s) | `frontend/settings.js:2284` (renderGeoIPDbStatus) |
| Shared | 1 loading indicator(s) | `frontend/utils.js:626` (renderJobCard) |

### Persisted preferences

Settings the browser remembers between visits.

| Page | What | Code |
|---|---|---|
| Shell | localStorage getItem "theme" | `frontend/app.js:4799` (initDarkMode) |
| Shell | localStorage setItem "theme" | `frontend/app.js:4814` (toggleDarkMode) |
| Logs | localStorage getItem "logsNewestFirst" | `frontend/logs-viewer.js:17` |
| Logs | localStorage setItem "logsNewestFirst" | `frontend/logs-viewer.js:532` (toggleLogSortOrder) |

### Auto refresh and timers

Background refreshes and polling.

| Page | What | Code |
|---|---|---|
| Shell | every 5 * 60 * 1000 ms | `frontend/app.js:469` (loadAppInfo) |
| Shell | every AUTO_REFRESH_INTERVAL ms | `frontend/app.js:752` (startAutoRefresh) |
| Status | every 1000 ms | `frontend/app.js:4138` (checkBlacklists) |
| Settings | every 2000 ms | `frontend/settings.js:2011` (showGeoIPSetupModal) |
| Modal: container-logs-modal | every 2000 ms | `frontend/app.js:4960` (loadContainerLogs) |

### Address bar and deep links

Places that change the URL so a view can be bookmarked or shared.

| Page | What | Code |
|---|---|---|
| Shell | replaceState | `frontend/app.js:1293` (switchTab) |
| Shell | pushState | `frontend/router.js:154` (navigateTo) |
| Shell | replaceState | `frontend/router.js:222` (initRouter) |
| DMARC | pushState | `frontend/dmarc.js:467` (loadDomainOverview) |
| DMARC | pushState | `frontend/dmarc.js:1056` (loadReportDetails) |
| DMARC | pushState | `frontend/dmarc.js:1162` (loadSourceDetails) |

### Keyboard handling

Key handlers; the keys are read from the handler body.

| Page | What | Code |
|---|---|---|
| Message details | keydown: Escape | `frontend/message-details.js:894` |
| Settings | keydown: Escape, Enter | `frontend/settings.js:118` (showBasicAuthVerifyModal) |
| Settings | keydown: Escape, Enter | `frontend/settings.js:207` (showFeatureDisableConfirmModal) |
| Modal: changelog-modal | keydown: Escape | `frontend/app.js:4829` |

### Badge colours

Named colour recipes in `APP_COLORS` (utils.js). Badges are squared, soft fill plus subtle border.

| Page | What | Code |
|---|---|---|
| Shared | directions.inbound | `frontend/utils.js` (APP_COLORS) |
| Shared | directions.outbound | `frontend/utils.js` (APP_COLORS) |
| Shared | directions.internal | `frontend/utils.js` (APP_COLORS) |
| Shared | statuses.delivered | `frontend/utils.js` (APP_COLORS) |
| Shared | statuses.sent | `frontend/utils.js` (APP_COLORS) |
| Shared | statuses.deferred | `frontend/utils.js` (APP_COLORS) |
| Shared | statuses.bounced | `frontend/utils.js` (APP_COLORS) |
| Shared | statuses.rejected | `frontend/utils.js` (APP_COLORS) |
| Shared | statuses.spam | `frontend/utils.js` (APP_COLORS) |
| Shared | statuses.discarded | `frontend/utils.js` (APP_COLORS) |
| Shared | statuses.expired | `frontend/utils.js` (APP_COLORS) |

<!-- generated:end -->
