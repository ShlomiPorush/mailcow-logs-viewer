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
- **Queue and Quarantine tables.** One row per item with the actions at the end of the row and the bulk actions (Select All, the Selected actions, Flush All or Release All, Delete All) above the table. A queue row shows every recipient, the sender, how long ago it was queued, the queue ID and the last response per recipient; with several recipients Suppress opens a menu of them. A quarantine row shows Release and Delete, and a More menu (`uiMenu`, a popover so the table cannot clip it) holds Details, Not Spam, Spam and Rule; the subject also opens Details. The page subtitles count what is in the queue (`updateQueueSummary`) and what is held. On phones the rows stack.
- **Status.** Key figures on top (containers running, blocklists listing you, mail storage used with amber above 75% and red above 90%, this app's version with the update link to Settings); the blocklists figure hides with the `blacklist` feature like its section. Containers are a grid with stopped ones first and in red. Blocklists are a table per monitored host with the listing lists named, Check now per host (`checkHost`) and Check Now for all with its progress bar (`checkBlacklists`); "All N lists" opens every result and stays open across refreshes. Background jobs are a table grouped by category with how often they run, the last result (feature off and disabled explain a missing Run), the last run, errors under the row and Run (`triggerBackgroundJob`). Log import, message linking with the recent incomplete ones, the mailcow system (with the mailcow update) and storage follow.
- **Domains.** A table with one row per domain: mailboxes and aliases under the name (with "open for the fix" when SPF, DKIM or DMARC has an error or a warning), a tag per DNS check (SPF, DKIM, DMARC, TLSA, MTA-STS; the tooltip gives the message) and storage. There is no MX check, so there is no MX column. A row opens its details (`toggleDomainDetails`): the domain facts, the DNS records with View Record, Checked IPs, warnings, info and Expected Value, Check for this domain (`checkSingleDomainDNS`, which re-renders the row open) and the alias domains. The subtitle counts domains, inactive ones and those that need a DNS change; the head keeps Last checked and Check Now (`checkAllDomainsDNS`); search and "Show only domains with issues" filter the rows (`filterDomains`).
- **DMARC.** Key figures on top of every view, rates as a number with a bar (green from 95%, amber from 80%, red below). The domains view has DMARC Insights (each with Open), a domains table (a row opens the domain) and Manage Reports. A domain shows its DMARC record from DNS (policy tags, View Record, warnings), the 30 day chart in the theme colours, and tabs for Daily Reports, Source IPs and TLS Reports, each a table whose row opens its details. A breadcrumb (DMARC / domain / tab / item) leads back. Upload Report shows only when manual upload is enabled, Sync from IMAP only when IMAP is enabled, with the last sync and View History. The sync history and Manage Reports are dialogs; deletion shows only when allowed.
- **Mailbox Stats and Rate Limits.** One page with two tabs (Statistics, Rate Limits; each hides with its feature). Statistics: key figures for the chosen period, search, the period picker (presets and a custom range), domain, sort, Active Only, Hide Zero Activity and Reset, then a table of mailboxes; a row opens quota, messages, dates, rate limit, access with last logins, counts that open Messages filtered on the address, and the aliases with their own clickable counts. Rate Limits: the activity chart with its window, Blocked senders (search, Reset counter, a sender opens its refused messages) and Configured limits (All, Mailboxes, Domains, search, Apply to filtered, Edit per row). Without the Read-Write key the editing and Reset counter are removed and a locked area says why.
- **Spam Filter.** Two tabs. Suppressions: key figures, a filter bar (search, reason, state, Clear) with Add Suppression, Sync to Rspamd and a More menu (Export CSV, Import CSV), and a table with the address (domain patterns shown as the domain), reason and source tags, bounces, expiry, Rspamd sync state, age and Edit, Disable or Enable, Delete. Add and Edit are v3 dialogs. Rspamd Maps: maps grouped by category as rows that open the editor (Regex Wizard for regex maps, Validate with line errors and warnings, Save Changes); without Rspamd configured a locked area leads to Settings, without the Read-Write key a locked area says maps are read-only.
- **Settings.** Version Information (current version opens its changelog, the latest version with Up to Date or Update Available, Last checked and Check Now, the update note with the changelog) and Configuration (mailcow URL, server IP, authentication, local domains) as key and value panels; local domains as chips when there are any. With editing off, a locked area explains it and the runtime values, SMTP and DMARC status show read-only with Test SMTP and Test IMAP. With editing on, Edit configuration has the categories as a side menu (a picker on narrow screens), groups of fields, a mark on values that differ from their default, Reset to default or Clear, fields locked by ENV, the feature toggles (disabling one warns that its data is deleted), status facts on the SMTP, DMARC IMAP and MaxMind tabs, and the alert destinations with a v3 dialog.
- **Shared dialogs and notices.** Confirmations (`showConfirmModal`) are a v3 dialog in the current theme: the confirm button is red for destructive actions, Escape and Cancel both cancel. Toasts (`showToast`) sit at the bottom corner (above the tab bar on phones) with a tone per type and close by themselves after four seconds. The quarantine details, rule, rule test, GeoIP setup, connection test and alert destination dialogs use the same frame. The Logs page keeps its toggles (Pause, Live, Auto-scroll, Wrap), service list and quick filters as `aria-pressed` and `aria-current` states. A disabled feature shows a locked area with Go to Dashboard.
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
| Security, Settings, Fail2ban card | Locked area "Editing Fail2ban is locked": editing needs a Read-Write API key (`MAILCOW_API_KEY_RW`), configure it in Settings → Mailcow → Connection, with an Open Settings button. The fields stay visible and disabled | `securityCardHtml`, `uiLocked` |
| Security, Lists | Locked area "The lists are read-only here" says why and where to configure the key. Add and Remove are gone; Remove on a ban a rule wrote stays, because it goes through the rule | `renderSecurityLists`, `uiLocked` |
| Security, Settings, rule cards | Ban in Watch first / Ban is disabled with the title "Banning needs the Read-Write API key"; the rules can still watch | `securityCardBody` |
| Security, netfilter log | Ban and Unban buttons are removed from the rows, and a locked area "Ban and Unban are locked" above the list says why and where to configure the key | `renderNetfilterData`, `uiLocked` |
| Security, Overview | Ban, Allow, Unban and Ban for good are removed from the address rows, and a locked area "Ban, Allow and Unban are locked" above the list says why and where to configure the key. Ban now on a rule's catch needs the key too; Dismiss and Undo stay | `securityDescribe`, `renderSecurityOverview`, `uiLocked` |
| Security, Overview | Until the Fail2ban data has loaded the Banned count shows "-", Fail2ban in the Protection row shows "?", and Ban and Allow are not offered. When mailcow does not answer, a note under the filters says its bans are not shown and nothing can be banned from here | `securityDescribe`, `securityProtections`, `renderSecurityOverview` |
| Security, Settings, Outgoing spam card | Locked area "Abuse protection controls are locked" above the activity, which stays readable; all actions hidden. Without the Read-Write key it says the key is needed, with Open Settings; when the protection is off it points to the card's own switch | `renderSmtpAbusePanel`, `uiLocked` |
| Queue | Toolbar, checkboxes and Retry/Hold/Unhold/Delete are gone, and a locked area "Queue actions are locked" says why and where to configure the key. Suppress stays | `applyQueueFilters`, `uiLocked` |
| Quarantine | Bulk and per-item Release/Delete/Learn, the details modal actions and the whole Auto-Rules section are hidden, and a locked area "Quarantine actions are locked" names them and where to configure the key. Details stays | `renderQuarantineData`, `initQuarantineRules`, `uiLocked` |
| Spam Filter | Locked area "Read-Only Mode": MAILCOW_API_KEY_RW is not configured, you can view maps but cannot save changes, with Open Settings (the Save button of the map editor itself is not gated) | `renderRspamdMapsList` |
| Mailbox Stats, Rate Limits | Locked area "Editing rate limits is locked" with the Read-Write key sentence and Open Settings; Edit, Apply to filtered, the bulk panel and Reset counter are hidden | `renderRateLimitReadOnlyNotice` |

The v3 redesign replaces these with one consistent locked-area component that says what is missing and where to configure it (decided 2026-09-25): `uiLocked(title, text)` in `frontend/utils.js`, styled by `.ui-locked`, always with an Open Settings button. Pages move to it as they are redesigned; the rows above say which already use it.

### Features that are off or not configured

| Page | Condition | What the user sees | Rendered by |
|---|---|---|---|
| Dashboard | `blacklist` disabled | The blacklist card is hidden | `#dashboard-blacklist-card` |
| Dashboard | Unacknowledged security alerts | Rows in Needs attention with a severity tag, the time and Dismiss, and a Dismiss all alerts button in the panel head | `loadDashboardSecurityAlerts` |
| Dashboard | A server check needs a look | Needs attention lists mailcow not reachable, a blocklist listing, stopped containers, DMARC insights and app or mailcow updates, each with a button to where it is handled; with nothing, "Nothing needs attention right now." | `loadDashboardAttention` |
| Message details | `netfilter` disabled | The Security tab of the modal is hidden | `#modal-tab-netfilter` |
| Security, Settings, Outgoing spam card | SMTP abuse protection off | The card's switch is off, and inside "Automatic protection is off." with a locked area that points to the switch When editing settings is off, the switch is disabled and a locked area "Editing settings is off" says how to turn it on | `securityCardHtml`, `renderSmtpAbusePanel` |
| Security, Settings, Countries card | No GeoIP | The switch is disabled, the card shows "Needs MaxMind GeoIP" and a locked area "Needs GeoIP"; the Overview's Protection row shows a cross with "needs MaxMind GeoIP" | `securityCardHtml`, `securityProtections` |
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
| [Click to copy](#click-to-copy) | 53 |
| [Tooltips](#tooltips) | 198 |
| [Toasts](#toasts) | 144 |
| [Confirmation dialogs](#confirmation-dialogs) | 29 |
| [Country flags](#country-flags) | 6 |
| [Markdown rendering](#markdown-rendering) | 4 |
| [Controls wired in JavaScript](#controls-wired-in-javascript) | 33 |
| [Filters, sorting and view options](#filters-sorting-and-view-options) | 11 |
| [Charts](#charts) | 2 |
| [Colour thresholds](#colour-thresholds) | 0 |
| [Help topics](#help-topics) | 8 |
| [Empty states](#empty-states) | 43 |
| [Loading states](#loading-states) | 21 |
| [Persisted preferences](#persisted-preferences) | 6 |
| [Auto refresh and timers](#auto-refresh-and-timers) | 5 |
| [Address bar and deep links](#address-bar-and-deep-links) | 17 |
| [Keyboard handling](#keyboard-handling) | 8 |
| [Badge colours](#badge-colours) | 11 |

### Click to copy

Fields that copy their value on click (hover shows a copy icon and "Click to copy").

| Page | What | Code |
|---|---|---|
| Message details | copies: `data.sender \|\| '-'` | `frontend/message-details.js:456` (renderMessageHeader) |
| Message details | copies: `r` | `frontend/message-details.js:457` (renderMessageHeader) |
| Message details | copies: `recipients[0] \|\| '-'` | `frontend/message-details.js:457` (renderMessageHeader) |
| Message details | copies: `ip` | `frontend/message-details.js:481` (buildDeliverySteps) |
| Message details | copies: `user` | `frontend/message-details.js:482` (buildDeliverySteps) |
| Message details | copies: `qid` | `frontend/message-details.js:486` (buildDeliverySteps) |
| Message details | copies: `target` | `frontend/message-details.js:490` (buildDeliverySteps) |
| Message details | copies: `rspamd.ip` | `frontend/message-details.js:556` (renderOverviewTab) |
| Message details | copies: `rspamd.user` | `frontend/message-details.js:558` (renderOverviewTab) |
| Message details | copies: `data.queue_id` | `frontend/message-details.js:559` (renderOverviewTab) |
| Message details | copies: `data.message_id` | `frontend/message-details.js:560` (renderOverviewTab) |
| Message details | copies: `Array.from(recipientsFromPostfix)[0]` | `frontend/message-details.js:687` (renderPostfixTab) |
| Message details | copies: `data.recipients[0]` | `frontend/message-details.js:689` (renderPostfixTab) |
| Message details | copies: `sender` | `frontend/message-details.js:698` (renderPostfixTab) |
| Message details | copies: `queueId` | `frontend/message-details.js:701` (renderPostfixTab) |
| Message details | copies: `clientIp` | `frontend/message-details.js:702` (renderPostfixTab) |
| Message details | copies: `recipient` | `frontend/message-details.js:716` (renderPostfixTab) |
| Message details | copies: `log.ip` | `frontend/message-details.js:840` (renderNetfilterTab) |
| Message details | copies: `log.username` | `frontend/message-details.js:843` (renderNetfilterTab) |
| Security | copies: `log.username` | `frontend/app.js:1081` (renderNetfilterData) |
| Security | copies: `log.ip` | `frontend/app.js:1086` (renderNetfilterData) |
| Security | copies: `a.ip` | `frontend/security.js:289` (securityRow) |
| Security | copies: `u` | `frontend/security.js:394` (securityDetail) |
| Security | copies: `h.ip` | `frontend/security.js:474` (securityHistoryRows) |
| Security | copies: `entry` | `frontend/security.js:682` (renderSecurityLists) |
| Queue | copies: `r.email` | `frontend/app.js:2189` (applyQueueFilters) |
| Queue | copies: `item.sender` | `frontend/app.js:2190` (applyQueueFilters) |
| Queue | copies: `qid` | `frontend/app.js:2190` (applyQueueFilters) |
| Quarantine | copies: `r.address` | `frontend/app.js:2687` (renderQuarantineDetailContent) |
| Quarantine | copies: `data.subject \|\| '-'` | `frontend/app.js:2715` (renderQuarantineDetailContent) |
| Quarantine | copies: `data.header_from \|\| '-'` | `frontend/app.js:2716` (renderQuarantineDetailContent) |
| Quarantine | copies: `data.env_from \|\| '-'` | `frontend/app.js:2717` (renderQuarantineDetailContent) |
| Spam filter | copies: `displayEmail` | `frontend/spam_filter.js:488` (renderSuppressionItem) |
| Status | copies: `item.message_id \|\| 'N/A'` | `frontend/app.js:4226` (renderStatusCorrelation) |
| Status | copies: `item.sender \|\| 'N/A'` | `frontend/app.js:4227` (renderStatusCorrelation) |
| Status | copies: `item.recipient \|\| 'N/A'` | `frontend/app.js:4227` (renderStatusCorrelation) |
| Domains | copies: `domain.domain_name` | `frontend/domains.js:192` (renderDomainAccordionRow) |
| Domains | copies: `entry.ip \|\| ''` | `frontend/domains.js:245` (renderSpfCheckedIps) |
| Domains | copies: `aliasDomain.domain_name` | `frontend/domains.js:268` (renderAliasDomain) |
| Domains | copies: `check.dkim_domain` | `frontend/domains.js:296` (renderDNSCheck) |
| Domains | copies: `check.record \|\| check.actual_record` | `frontend/domains.js:297` (renderDNSCheck) |
| Domains | copies: `check.expected_record` | `frontend/domains.js:319` (renderDNSCheck) |
| Mailbox stats | copies: `mb.username` | `frontend/mailbox-stats.js:330` (renderMailboxStatsAccordion) |
| Mailbox stats | copies: `alias.alias_address` | `frontend/mailbox-stats.js:372` (renderMailboxStatsAccordion) |
| Mailbox stats | copies: `group.user` | `frontend/rate-limits.js:362` (renderRateLimitSendersTable) |
| Mailbox stats | copies: `group.user` | `frontend/rate-limits.js:451` (renderRateLimitSenderDetail) |
| Mailbox stats | copies: `event.rcpt` | `frontend/rate-limits.js:566` (renderRateLimitEventRow) |
| Mailbox stats | copies: `event.qid` | `frontend/rate-limits.js:568` (renderRateLimitEventRow) |
| Mailbox stats | copies: `name` | `frontend/rate-limits.js:979` (renderRateLimitConfigRow) |
| Shared | copies: `ip` | `frontend/app.js:4476` (renderGeoIPInfo) |
| Shared | copies: `ip` | `frontend/app.js:4483` (renderGeoIPInfo) |
| Shared | copyToClipboard: `'${safeText}'` | `frontend/utils.js:550` (copyableText) |
| Not rendered (possible dead code) | copies: `a.ip` | `frontend/security.js:320` (renderSecuritySheet) |

### Tooltips

Native `title` tooltips. Dynamic ones show the expression that builds the text.

| Page | What | Code |
|---|---|---|
| Shell | "Dashboard" | `frontend/index.html:385` |
| Shell | "Collapse menu" | `frontend/index.html:403` |
| Shell | "Server status" | `frontend/index.html:404` |
| Shell | "mailcow connection status" | `frontend/index.html:405` |
| Shell | "Dashboard" | `frontend/index.html:416` |
| Shell | "Messages" | `frontend/index.html:420` |
| Shell | "Queue" | `frontend/index.html:421` |
| Shell | "Quarantine" | `frontend/index.html:422` |
| Shell | "Security" | `frontend/index.html:426` |
| Shell | "Spam Filter" | `frontend/index.html:427` |
| Shell | "DMARC &amp; TLS" | `frontend/index.html:428` |
| Shell | "Status" | `frontend/index.html:432` |
| Shell | "Domains" | `frontend/index.html:433` |
| Shell | "Mailbox Stats" | `frontend/index.html:434` |
| Shell | "Logs" | `frontend/index.html:435` |
| Shell | "Settings" | `frontend/index.html:438` |
| Shell | "About" | `frontend/index.html:439` |
| Shell | "mailcow update available" | `frontend/index.html:448` |
| Shell | "Switch theme" | `frontend/index.html:456` |
| Shell | "Refresh" | `frontend/index.html:468` |
| Shell | "Logout" | `frontend/index.html:473` |
| Shell | "Created with ❤️ - GitHub" | `frontend/index.html:478` |
| Shell | "View Container Logs" | `frontend/index.html:482` |
| Shell | set in JS: dynamic: `data.app_title` | `frontend/app.js:428` (loadAppInfo) |
| Shell | set in JS: dynamic: `== 'Not connected to mailcow') problems.push('not connected to mailcow')` | `frontend/app.js:564` (loadNavCounters) |
| Shell | set in JS: dynamic: `problems.join(', ')` | `frontend/app.js:574` (loadNavCounters) |
| Shell | set in JS: dynamic: `problems.join(', ')` | `frontend/app.js:580` (loadNavCounters) |
| Shell | set in JS: "Connected to mailcow" | `frontend/app.js:606` (loadMailcowConnectionStatus) |
| Shell | set in JS: "Not connected to mailcow" | `frontend/app.js:615` (loadMailcowConnectionStatus) |
| Shell | set in JS: "Connection status unknown" | `frontend/app.js:630` (loadMailcowConnectionStatus) |
| Shell | set in JS: dynamic: ``Update available: v${data.latest_version}`` | `frontend/app.js:650` (loadAppVersionStatus) |
| Shell | set in JS: dynamic: ``Update available: ${data.latest_version}`` | `frontend/app.js:732` (loadMailcowVersionStatus) |
| Shell | set in JS: dynamic: ``Update available: ${data.latest_version}`` | `frontend/app.js:739` (loadMailcowVersionStatus) |
| Shell | set in JS: dynamic: `label` | `frontend/app.js:4896` (syncNavToggle) |
| Dashboard | "Dismiss" | `frontend/app.js:1599` (loadDashboardSecurityAlerts) |
| Dashboard | dynamic: `${mailFlowHour(s.t)} to ${mailFlowHour(s.t + 3600000)}: ${s.clean.toLocaleStr...` | `frontend/app.js:1799` (loadMailFlowChart) |
| Dashboard | dynamic: `${escapeHtml(formatTime(msg.time))}` | `frontend/app.js:1917` (loadRecentActivity) |
| Dashboard | dynamic: `${escapeHtml(state)}` | `frontend/app.js:1918` (loadRecentActivity) |
| Dashboard | dynamic: `${escapeHtml(msg.subject \|\| 'No subject')}` | `frontend/app.js:1920` (loadRecentActivity) |
| Dashboard | "Each message counts once, as on the Messages page; a message to three recipients is one message and three d..." | `frontend/index.html:577` |
| Messages | dynamic: `${escapeHtml(formatTime(msg.first_seen))}` | `frontend/app.js:895` (renderMessageRow) |
| Messages | dynamic: `${escapeHtml(msg.subject \|\| 'No subject')}` | `frontend/app.js:897` (renderMessageRow) |
| Messages | dynamic: `${escapeHtml(msg.recipient \|\| '')}` | `frontend/app.js:902` (renderMessageRow) |
| Messages | "Filter by sender, recipient, user or IP" | `frontend/index.html:656` |
| Message details | "This delivery attempt never reached a final outcome" | `frontend/message-details.js:361` (renderRelatedDeliveries) |
| Message details | "Open Spam Analysis" | `frontend/message-details.js:446` (renderMessageHeader) |
| Message details | dynamic: `${escapeHtml(hasSubject ? data.subject : 'No subject')}` | `frontend/message-details.js:454` (renderMessageHeader) |
| Message details | dynamic: `${escapeHtml(sender)}` | `frontend/message-details.js:698` (renderPostfixTab) |
| Message details | dynamic: `${escapeHtml(relay)}` | `frontend/message-details.js:703` (renderPostfixTab) |
| Message details | set in JS: dynamic: `== step.title) { prev.count = (prev.count \|\| 1) + 1` | `frontend/message-details.js:516` (buildDeliverySteps) |
| Security | dynamic: `${escapeHtml(formatTime(log.time))}` | `frontend/app.js:1085` (renderNetfilterData) |
| Security | dynamic: `${escapeHtml(place + org)}` | `frontend/app.js:1089` (renderNetfilterData) |
| Security | dynamic: `Unban ${escapeHtml(log.ip)}/32` | `frontend/app.js:1091` (renderNetfilterData) |
| Security | dynamic: `Ban ${escapeHtml(log.ip)}/32` | `frontend/app.js:1092` (renderNetfilterData) |
| Security | "Show the log line" | `frontend/app.js:1093` (renderNetfilterData) |
| Security | "Caught by a rule and waiting for you" | `frontend/index.html:746` |
| Security | dynamic: `${escapeHtml(`${name}: ${label}${note ? `, ${note}` : ''}`)}` | `frontend/security.js:187` (securityProtections) |
| Security | "Lift the ban; the rule leaves it alone for a week" | `frontend/security.js:232` (securityDescribe) |
| Security | "Not an attack: the rule leaves it alone for a week" | `frontend/security.js:233` (securityDescribe) |
| Security | dynamic: `Unban ${escapeHtml(a.ip)}/32` | `frontend/security.js:246` (securityDescribe) |
| Security | "Put it on the denylist" | `frontend/security.js:247` (securityDescribe) |
| Security | "Put it on the Fail2ban blacklist now" | `frontend/security.js:269` (securityDescribe) |
| Security | dynamic: `Ban ${escapeHtml(a.ip)}/32` | `frontend/security.js:276` (securityDescribe) |
| Security | dynamic: `Never ban ${escapeHtml(a.ip)}/32` | `frontend/security.js:277` (securityDescribe) |
| Security | dynamic: `${escapeHtml(a.country)}` | `frontend/security.js:289` (securityRow) |
| Security | dynamic: `${escapeHtml(formatTime(h.last_seen))}` | `frontend/security.js:375` (securityDetail) |
| Security | dynamic: `${escapeHtml([a.city, a.country].filter(Boolean).join(', '))}` | `frontend/security.js:390` (securityDetail) |
| Security | "Show every country" | `frontend/security.js:531` (renderSecurityOverview) |
| Security | dynamic: `${n.toLocaleString()} ${label}` | `frontend/security.js:603` (securityCountryBars) |
| Security | dynamic: `${escapeHtml(`${r.country_name}: ${r.total.toLocaleString()} events`)}` | `frontend/security.js:606` (securityCountryBars) |
| Security | "Watched by the Countries rule" | `frontend/security.js:607` (securityCountryBars) |
| Security | dynamic: `${escapeHtml(n.asn)}` | `frontend/security.js:643` (renderSecurityCountries) |
| Security | "Lift the ban; the rule leaves it alone for a week" | `frontend/security.js:692` (renderSecurityLists) |
| Security | "Note what it catches; ban nothing" | `frontend/security.js:1011` (securityCardBody) |
| Security | dynamic: `${caps.can_ban ? 'Put what it catches on the Fail2ban blacklist' : 'Banning n...` | `frontend/security.js:1012` (securityCardBody) |
| Security | "Remove" | `frontend/security.js:1022` (securityCardBody) |
| Security | dynamic: `${s.tries} tries from ${s.addresses} address${s.addresses === 1 ? '' : 'es'}` | `frontend/security.js:1028` (securityCardBody) |
| Security | "Remove" | `frontend/security.js:1034` (securityCardBody) |
| Security | dynamic: `${s.tries} failed logins` | `frontend/security.js:1040` (securityCardBody) |
| Security | "This feature is new - please report any issues on GitHub" | `frontend/security.js:1071` (securityCardHtml) |
| Security | "Help - Abuse Protection" | `frontend/security.js:1072` (securityCardHtml) |
| Security | dynamic: `${escapeHtml(disabled ? why : on ? `Turn ${name} off` : `Turn ${name} on`)}` | `frontend/security.js:1092` (securityToggle) |
| Queue | "Retry delivery of every message in the queue" | `frontend/app.js:2160` (applyQueueFilters) |
| Queue | dynamic: `Suppress ${escapeHtml(recipients[0].email)}` | `frontend/app.js:2183` (applyQueueFilters) |
| Queue | dynamic: `${escapeHtml(formatTime(queued))}` | `frontend/app.js:2190` (applyQueueFilters) |
| Queue | "Retry delivery" | `frontend/app.js:2199` (applyQueueFilters) |
| Queue | "Release from hold" | `frontend/app.js:2201` (applyQueueFilters) |
| Queue | "Hold message" | `frontend/app.js:2202` (applyQueueFilters) |
| Queue | "Delete from queue" | `frontend/app.js:2203` (applyQueueFilters) |
| Quarantine | "View details" | `frontend/app.js:2472` (renderQuarantineData) |
| Quarantine | dynamic: `${escapeHtml(formatTime(item.created))}` | `frontend/app.js:2478` (renderQuarantineData) |
| Quarantine | "Release message" | `frontend/app.js:2481` (renderQuarantineData) |
| Quarantine | "Release and train as not spam" | `frontend/app.js:2482` (renderQuarantineData) |
| Quarantine | "Delete and train as spam" | `frontend/app.js:2483` (renderQuarantineData) |
| Quarantine | "Create an auto-rule from this message" | `frontend/app.js:2484` (renderQuarantineData) |
| Quarantine | "Delete message" | `frontend/app.js:2485` (renderQuarantineData) |
| Quarantine | "View details" | `frontend/app.js:2486` (renderQuarantineData) |
| Quarantine | "Close" | `frontend/app.js:2644` (showQuarantineDetails) |
| Quarantine | dynamic: `${escapeHtml(opts)}` | `frontend/app.js:2701` (renderQuarantineDetailContent) |
| Quarantine | "Delete & train as Spam" | `frontend/app.js:2751` (renderQuarantineDetailContent) |
| Quarantine | "Release & train as Not Spam" | `frontend/app.js:2752` (renderQuarantineDetailContent) |
| Quarantine | dynamic: `${rule.enabled ? 'Click to disable this rule' : 'Click to enable this rule'}` | `frontend/app.js:2831` (loadQuarantineRules) |
| Quarantine | "Edit" | `frontend/app.js:2833` (loadQuarantineRules) |
| Quarantine | "Delete" | `frontend/app.js:2834` (loadQuarantineRules) |
| Quarantine | "Close" | `frontend/app.js:2890` (_showQuarantineRuleModal) |
| Quarantine | dynamic: `${escapeHtml(m.subject \|\| '')}` | `frontend/app.js:3078` (testQuarantineRules) |
| Quarantine | "Close" | `frontend/app.js:3102` (testQuarantineRules) |
| Quarantine | dynamic: `${escapeHtml(log.sender \|\| '')} → ${escapeHtml(log.recipient \|\| '')}` | `frontend/app.js:3154` (loadQuarantineRuleHistory) |
| Quarantine | dynamic: `Rule: ${escapeHtml(log.rule_name \|\| '')}` | `frontend/app.js:3155` (loadQuarantineRuleHistory) |
| Quarantine | "Help - Quarantine" | `frontend/index.html:841` |
| Spam filter | "Help - Spam Filter" | `frontend/index.html:915` |
| Spam filter | "Clear all filters" | `frontend/index.html:968` |
| Spam filter | "Sync suppression list to Rspamd" | `frontend/index.html:971` |
| Spam filter | "More" | `frontend/index.html:973` |
| Spam filter | dynamic: `${escapeHtml(displayDesc)}` | `frontend/spam_filter.js:142` (renderRspamdMapsList) |
| Spam filter | "Close" | `frontend/spam_filter.js:208` (openMapEditor) |
| Spam filter | "Synced to Rspamd" | `frontend/spam_filter.js:472` (renderSuppressionItem) |
| Spam filter | dynamic: `${suppressionSyncLocked() ? 'Not synced: syncing to Rspamd needs the Read-Wri...` | `frontend/spam_filter.js:473` (renderSuppressionItem) |
| Spam filter | "Will be removed from Rspamd on next sync" | `frontend/spam_filter.js:476` (renderSuppressionItem) |
| Spam filter | dynamic: `${escapeHtml(s.email)}` | `frontend/spam_filter.js:489` (renderSuppressionItem) |
| Spam filter | dynamic: `${escapeHtml(s.notes)}` | `frontend/spam_filter.js:492` (renderSuppressionItem) |
| Spam filter | dynamic: `${escapeHtml(formatTime(s.created_at))}` | `frontend/spam_filter.js:498` (renderSuppressionItem) |
| Spam filter | "Edit suppression" | `frontend/spam_filter.js:500` (renderSuppressionItem) |
| Spam filter | dynamic: `${s.active ? 'Deactivate' : 'Reactivate'}` | `frontend/spam_filter.js:501` (renderSuppressionItem) |
| Spam filter | "Delete permanently" | `frontend/spam_filter.js:502` (renderSuppressionItem) |
| Spam filter | set in JS: dynamic: `locked ? 'Syncing to Rspamd needs the Read-Write API key' : 'Sync suppression...` | `frontend/spam_filter.js:390` (updateSuppressionSyncLock) |
| Status | "Click to view changelog" | `frontend/about.js:123` (aboutVersionPanel) |
| Status | dynamic: `Stop counting and alerting on ${escapeHtml(c.name)}` | `frontend/app.js:3598` (renderStatusAttention) |
| Status | dynamic: `Keep checking ${escapeHtml(r.name)} but never count or alert on it` | `frontend/app.js:3605` (renderStatusAttention) |
| Status | dynamic: `Stop counting and alerting on ${escapeHtml(c.name)}` | `frontend/app.js:3743` (loadStatusContainers) |
| Status | dynamic: `${escapeHtml(c.ignored ? 'Ignored: shown here but never counted or alerted' :...` | `frontend/app.js:3746` (loadStatusContainers) |
| Status | dynamic: `Look up on ${escapeHtml(r.name)}` | `frontend/app.js:4109` (renderBlacklistStatus) |
| Status | dynamic: `${r.ignored ? 'Count and alert on this list again' : 'Keep checking this list...` | `frontend/app.js:4112` (renderBlacklistStatus) |
| Status | dynamic: `${host.checked_at ? escapeHtml(formatTime(host.checked_at)) : ''}` | `frontend/app.js:4135` (renderBlacklistStatus) |
| Status | "Run Check for this Host" | `frontend/app.js:4136` (renderBlacklistStatus) |
| Status | dynamic: `${escapeHtml(detail(r))}` | `frontend/app.js:4151` (renderBlacklistStatus) |
| Status | dynamic: `${d.last_fetch_run ? escapeHtml(formatTime(d.last_fetch_run)) : ''}` | `frontend/app.js:4192` (renderStatusImport) |
| Status | dynamic: `${d.last_import ? escapeHtml(formatTime(d.last_import)) : ''}` | `frontend/app.js:4193` (renderStatusImport) |
| Status | "Help - IP Blacklist Monitor" | `frontend/index.html:1038` |
| Domains | dynamic: `${data.last_dns_check ? escapeHtml(formatTime(data.last_dns_check)) : ''}` | `frontend/domains.js:73` (renderDomains) |
| Domains | dynamic: `${escapeHtml(`${label}: ${check.message \|\| 'Not checked'}`)}` | `frontend/domains.js:157` (dnsStatusTag) |
| Domains | dynamic: `${dns.checked_at ? escapeHtml(formatTime(dns.checked_at)) : ''}` | `frontend/domains.js:166` (renderDomainDnsSection) |
| Domains | "Check DNS for this domain" | `frontend/domains.js:169` (renderDomainDnsSection) |
| Domains | dynamic: `${escapeHtml(text)}` | `frontend/domains.js:280` (getAliasStatusIcon) |
| Domains | "Help - Domains Information" | `frontend/index.html:1068` |
| DMARC | "The daily DNS check covers the mailcow domains. Open the domain to check it now." | `frontend/dmarc.js:710` (tlsRptStatusTag) |
| DMARC | dynamic: `${escapeHtml(formatTime(sync.started_at))}` | `frontend/dmarc.js:1227` (updateDmarcControls) |
| DMARC | "Delete report" | `frontend/dmarc.js:1417` (renderReportsManagementTable) |
| DMARC | "Help - DMARC Information" | `frontend/index.html:1087` |
| DMARC | set in JS: dynamic: `allowed ? '' : 'Manual upload is turned off in Settings, DMARC'` | `frontend/dmarc.js:1200` (updateDmarcControls) |
| DMARC | set in JS: "IMAP sync is not set up" | `frontend/dmarc.js:1211` (updateDmarcControls) |
| DMARC | set in JS: "" | `frontend/dmarc.js:1219` (updateDmarcControls) |
| Mailbox stats | "Help - Mailbox Statistics" | `frontend/index.html:1222` |
| Mailbox stats | "Open these messages" | `frontend/mailbox-stats.js:294` (mailboxStatLink) |
| Mailbox stats | "Address on a mailcow alias domain that points at this mailbox" | `frontend/mailbox-stats.js:374` (renderMailboxStatsAccordion) |
| Mailbox stats | "Resetting a counter needs the Read-Write API key (MAILCOW_API_KEY_RW)" | `frontend/rate-limits.js:141` |
| Mailbox stats | dynamic: `${escapeHtml(formatTime(group.last_seen))}` | `frontend/rate-limits.js:364` (renderRateLimitSendersTable) |
| Mailbox stats | set in JS: dynamic: `isRateLimits ? 'Help - Rate Limits' : 'Help - Mailbox Statistics'` | `frontend/mailbox-stats.js:86` (mailboxStatsSwitchView) |
| Logs | "Pause/Resume live updates" | `frontend/index.html:1344` |
| Logs | "Live mode - show latest logs" | `frontend/index.html:1348` |
| Logs | "Auto-scroll to new entries" | `frontend/index.html:1351` |
| Logs | "Toggle sort order (newest at bottom / newest at top)" | `frontend/index.html:1354` |
| Logs | "Toggle word wrap" | `frontend/index.html:1365` |
| Logs | "Clear display" | `frontend/index.html:1368` |
| Logs | "Search" | `frontend/index.html:1375` |
| Logs | "Clear search" | `frontend/index.html:1376` |
| Logs | "From date" | `frontend/index.html:1392` |
| Logs | "To date" | `frontend/index.html:1394` |
| Logs | dynamic: `${escapeHtml(f.description \|\| '')}` | `frontend/logs-viewer.js:211` (loadSmartFilters) |
| Logs | "Clear all filters" | `frontend/logs-viewer.js:1209` (updateFilterBadge) |
| Settings | "Last delivery succeeded" | `frontend/notifications.js:67` (renderNotificationChannels) |
| Settings | "Last delivery failed" | `frontend/notifications.js:69` (renderNotificationChannels) |
| Settings | "Not used yet" | `frontend/notifications.js:70` (renderNotificationChannels) |
| Settings | dynamic: `${escapeHtml(ch.last_error)}` | `frontend/notifications.js:78` (renderNotificationChannels) |
| Settings | "Close" | `frontend/notifications.js:152` (renderNotificationChannelModal) |
| Settings | "Set by an environment variable, change it there" | `frontend/settings.js:609` (renderSettingsEditField) |
| Settings | "Differs from the default" | `frontend/settings.js:654` (renderSettingsEditField) |
| Settings | "Differs from the default" | `frontend/settings.js:671` (renderSettingsEditField) |
| Settings | "Add a MaxMind Account ID and License Key first" | `frontend/settings.js:1749` (maxmindValidateButton) |
| Settings | "Close" | `frontend/settings.js:1841` (showConnectionTestModal) |
| Shared | dynamic: `${escapeHtml(title)}` | `frontend/utils.js:164` (uiCorrelationTag) |
| Shared | "Close" | `frontend/utils.js:575` (showToast) |
| Shared | "The feature this job belongs to is turned off in Settings" | `frontend/utils.js:661` (renderJobCard) |
| Shared | dynamic: `${escapeHtml(job.disabled_reason \|\| 'This job is turned off in its settings...` | `frontend/utils.js:664` (renderJobCard) |
| Shared | dynamic: `${escapeHtml(job.description)}` | `frontend/utils.js:698` (renderJobCard) |
| Shared | dynamic: `${job.last_run ? escapeHtml(formatTime(job.last_run)) : ''}` | `frontend/utils.js:700` (renderJobCard) |
| Shared | dynamic: `${isRunning ? 'Job is running' : 'Run this job now'}` | `frontend/utils.js:704` (renderJobCard) |
| Shared | dynamic: `${escapeHtml(job.disabled_reason \|\| '')}` | `frontend/utils.js:707` (renderJobCard) |
| app.js (mixed) | dynamic: `Look up on ${escapeHtml(r.name)}` | `frontend/app.js:3585` (blocklistLookupLink) |
| app.js (mixed) | set in JS: dynamic: `label` | `frontend/app.js:286` (setNavTabLabel) |
| app.js (mixed) | set in JS: dynamic: `title \|\| ''` | `frontend/app.js:521` (setNavCount) |
| Not rendered (possible dead code) | "Close" | `frontend/security.js:321` (renderSecuritySheet) |
| Modal: changelog-modal | "Close" | `frontend/index.html:1493` |
| Modal: container-logs-modal | "Refresh" | `frontend/index.html:1525` |
| Modal: container-logs-modal | "Close" | `frontend/index.html:1533` |
| Modal: dmarc-reports-management-modal | "Close" | `frontend/index.html:1584` |
| Modal: dmarc-sync-history-modal | "Close" | `frontend/index.html:1571` |
| Modal: message-modal | "Close" | `frontend/index.html:1466` |

### Toasts

Transient notifications from `showToast(message, type)` (utils.js). Type defaults to info.

| Page | What | Code |
|---|---|---|
| Messages | "Please select both start and end dates" [warning] | `frontend/app.js:3334` (applyMessagesCustomDateRange) |
| Messages | "Start date must be before end date" [warning] | `frontend/app.js:3343` (applyMessagesCustomDateRange) |
| Security | "IP ' + ip + ' unbanned successfully" [success] | `frontend/app.js:1128` (unbanIP) |
| Security | dynamic: `'Failed to unban: ' + (result.msg \|\| result.detail \|\| 'Unknown error')` [error] | `frontend/app.js:1135` (unbanIP) |
| Security | dynamic: `'Failed to unban IP: ' + err.message` [error] | `frontend/app.js:1142` (unbanIP) |
| Security | dynamic: ``IP ${ip} added to blacklist`` [success] | `frontend/app.js:1169` (banIP) |
| Security | dynamic: `'Failed to ban: ' + (result.msg \|\| result.detail \|\| 'Unknown error')` [error] | `frontend/app.js:1176` (banIP) |
| Security | dynamic: `'Failed to ban IP: ' + err.message` [error] | `frontend/app.js:1183` (banIP) |
| Security | "Failed to dismiss alert" [error] | `frontend/app.js:1813` (acknowledgeSecurityAlert) |
| Security | "All security alerts dismissed" [success] | `frontend/app.js:1821` (acknowledgeAllSecurityAlerts) |
| Security | "Failed to dismiss alerts" [error] | `frontend/app.js:1823` (acknowledgeAllSecurityAlerts) |
| Security | dynamic: ``Could not load the history: ${error.message}`` [error] | `frontend/security.js:106` (loadSecurityHistory) |
| Security | dynamic: ``${entry} removed from the ${label}`` [success] | `frontend/security.js:734` (securityRemoveFromList) |
| Security | dynamic: ``Could not remove ${entry}: ${error.message}`` [error] | `frontend/security.js:738` (securityRemoveFromList) |
| Security | dynamic: ``Saved ${list}`` [success] | `frontend/security.js:863` (saveSecuritySettings) |
| Security | dynamic: ``Failed to save the Fail2ban settings: ${error.message}`` [error] | `frontend/security.js:881` (saveSecurityF2b) |
| Security | dynamic: ``Could not save the outgoing spam settings: ${error.message}`` [error] | `frontend/security.js:899` (saveSecurityAbuse) |
| Security | dynamic: `detail.detail \|\| `Could not ${action} SMTP`` [error] | `frontend/smtp-abuse.js:171` (smtpAbuseAction) |
| Security | dynamic: `action === 'block' ? 'SMTP disabled' : 'SMTP re-enabled'` [success] | `frontend/smtp-abuse.js:174` (smtpAbuseAction) |
| Security | dynamic: ``Could not ${action} SMTP`` [error] | `frontend/smtp-abuse.js:177` (smtpAbuseAction) |
| Security | dynamic: `detail.detail \|\| 'Could not save whitelist'` [error] | `frontend/smtp-abuse.js:206` (saveSmtpAbuseWhitelist) |
| Security | "Whitelist saved" [success] | `frontend/smtp-abuse.js:210` (saveSmtpAbuseWhitelist) |
| Security | "Could not save whitelist" [error] | `frontend/smtp-abuse.js:214` (saveSmtpAbuseWhitelist) |
| Security | "Could not remove whitelist entry" [error] | `frontend/smtp-abuse.js:223` (removeSmtpAbuseWhitelist) |
| Security | "Whitelist entry removed" [success] | `frontend/smtp-abuse.js:224` (removeSmtpAbuseWhitelist) |
| Security | "Could not remove whitelist entry" [error] | `frontend/smtp-abuse.js:227` (removeSmtpAbuseWhitelist) |
| Queue | dynamic: `result.msg \|\| `${labels[action] \|\| action} completed`` [success] | `frontend/app.js:2310` (queueAction) |
| Queue | dynamic: ``Queue action failed: ` + (result.msg \|\| result.detail \|\| 'Unknown error')` [error] | `frontend/app.js:2314` (queueAction) |
| Queue | dynamic: ``Queue action failed: ` + err.message` [error] | `frontend/app.js:2317` (queueAction) |
| Queue | dynamic: `result.msg \|\| 'Message deleted from queue'` [success] | `frontend/app.js:2337` (queueDeleteRequest) |
| Queue | dynamic: `'Failed to delete from queue: ' + (result.msg \|\| result.detail \|\| 'Unknow...` [error] | `frontend/app.js:2341` (queueDeleteRequest) |
| Queue | dynamic: `'Failed to delete from queue: ' + err.message` [error] | `frontend/app.js:2344` (queueDeleteRequest) |
| Quarantine | dynamic: `result.msg \|\| `Message(s) ${actionLabels[action] \|\| action} successfully`` [success] | `frontend/app.js:2615` (quarantineAction) |
| Quarantine | dynamic: ``Failed to ${action} message(s): ` + (result.msg \|\| result.detail \|\| 'Unk...` [error] | `frontend/app.js:2619` (quarantineAction) |
| Quarantine | dynamic: ``Failed to ${action} message(s): ` + err.message` [error] | `frontend/app.js:2622` (quarantineAction) |
| Quarantine | "Rule not found" [error] | `frontend/app.js:2850` (showEditQuarantineRuleModal) |
| Quarantine | "Rule name is required" [error] | `frontend/app.js:2983` (saveQuarantineRule) |
| Quarantine | "Match value is required" [error] | `frontend/app.js:2984` (saveQuarantineRule) |
| Quarantine | dynamic: `isEdit ? 'Rule updated' : 'Rule created'` [success] | `frontend/app.js:3016` (saveQuarantineRule) |
| Quarantine | dynamic: `'Failed to save rule: ' + err.message` [error] | `frontend/app.js:3019` (saveQuarantineRule) |
| Quarantine | "Rule deleted" [success] | `frontend/app.js:3030` (deleteQuarantineRule) |
| Quarantine | dynamic: `'Failed to delete rule: ' + err.message` [error] | `frontend/app.js:3033` (deleteQuarantineRule) |
| Quarantine | dynamic: ``Rule ${rule.enabled ? 'enabled' : 'disabled'}`` [success] | `frontend/app.js:3043` (toggleQuarantineRule) |
| Quarantine | dynamic: `'Failed to toggle rule: ' + err.message` [error] | `frontend/app.js:3046` (toggleQuarantineRule) |
| Quarantine | "Testing rules against quarantine..." [info] | `frontend/app.js:3052` (testQuarantineRules) |
| Quarantine | dynamic: ``No matches found (${data.total_quarantine} quarantine items checked)`` [info] | `frontend/app.js:3059` (testQuarantineRules) |
| Quarantine | dynamic: `'Test failed: ' + err.message` [error] | `frontend/app.js:3119` (testQuarantineRules) |
| Spam filter | dynamic: ``Cannot save: ${valData.errors.length} validation error(s). Fix them first.`` [error] | `frontend/spam_filter.js:327` (saveMapContent) |
| Spam filter | dynamic: `'Validation failed: ' + e.message` [error] | `frontend/spam_filter.js:332` (saveMapContent) |
| Spam filter | dynamic: ``Map saved (${result.entry_count} entries). ${result.normalized_entries} bare...` [success] | `frontend/spam_filter.js:357` (saveMapContent) |
| Spam filter | dynamic: ``Map saved successfully (${result.entry_count} entries)`` [success] | `frontend/spam_filter.js:359` (saveMapContent) |
| Spam filter | dynamic: `'Failed to save map: ' + error.message` [error] | `frontend/spam_filter.js:369` (saveMapContent) |
| Spam filter | dynamic: `type === 'domain' ? 'Domain name is required' : 'Email address is required'` [error] | `frontend/spam_filter.js:648` (createSuppression) |
| Spam filter | "Enter a plain domain name, for example example.com" [error] | `frontend/spam_filter.js:660` (createSuppression) |
| Spam filter | "This address is already suppressed" [error] | `frontend/spam_filter.js:684` (createSuppression) |
| Spam filter | dynamic: ``Suppression added: ${email}`` [success] | `frontend/spam_filter.js:693` (createSuppression) |
| Spam filter | dynamic: `error.message` [error] | `frontend/spam_filter.js:701` (createSuppression) |
| Spam filter | "Please set an expiry date" [error] | `frontend/spam_filter.js:789` (saveEditSuppression) |
| Spam filter | "Suppression updated" [success] | `frontend/spam_filter.js:804` (saveEditSuppression) |
| Spam filter | dynamic: `error.message` [error] | `frontend/spam_filter.js:810` (saveEditSuppression) |
| Spam filter | dynamic: ``Suppression ${newActive ? 'activated' : 'deactivated'}`` [success] | `frontend/spam_filter.js:824` (toggleSuppression) |
| Spam filter | dynamic: `error.message` [error] | `frontend/spam_filter.js:830` (toggleSuppression) |
| Spam filter | dynamic: ``Suppression deleted: ${email}`` [success] | `frontend/spam_filter.js:841` (deleteSuppression) |
| Spam filter | dynamic: `error.message` [error] | `frontend/spam_filter.js:847` (deleteSuppression) |
| Spam filter | dynamic: ``Synced ${result.synced} suppressions to Rspamd (${result.newly_synced} new)`` [success] | `frontend/spam_filter.js:893` (syncSuppressionsToRspamd) |
| Spam filter | dynamic: `'Sync failed: ' + error.message` [error] | `frontend/spam_filter.js:897` (syncSuppressionsToRspamd) |
| Spam filter | dynamic: ``Imported ${result.imported} suppressions (${result.skipped} skipped)`` [success] | `frontend/spam_filter.js:933` (importSuppressions) |
| Spam filter | dynamic: `'Import failed: ' + error.message` [error] | `frontend/spam_filter.js:939` (importSuppressions) |
| Spam filter | dynamic: ``Pattern added: ${pattern}`` [success] | `frontend/spam_filter.js:1122` (regexWizardAdd) |
| Status | dynamic: `ignored ? `${container.replace('-mailcow', '')} is ignored. It no longer coun...` [success] | `frontend/app.js:3681` (setContainerIgnored) |
| Status | dynamic: ``Could not change the container: ${e.message}`` [error] | `frontend/app.js:3685` (setContainerIgnored) |
| Status | "Starting blacklist check..." [info] | `frontend/app.js:3916` (checkBlacklists) |
| Status | "Blacklist check completed" [success] | `frontend/app.js:3960` (checkBlacklists) |
| Status | dynamic: ``Check completed for ${host}`` [success] | `frontend/app.js:3988` (checkBlacklists) |
| Status | dynamic: ``Failed to check: ${error.message}`` [error] | `frontend/app.js:3997` (checkBlacklists) |
| Status | dynamic: ``Job "${displayName}" started successfully`` [success] | `frontend/app.js:4395` (triggerBackgroundJob) |
| Status | dynamic: ``Job "${displayName}" is already running`` [warning] | `frontend/app.js:4404` (triggerBackgroundJob) |
| Status | dynamic: ``Failed to start job: ${error.message}`` [error] | `frontend/app.js:4407` (triggerBackgroundJob) |
| Domains | "DNS check already in progress" [warning] | `frontend/domains.js:330` (checkAllDomainsDNS) |
| Domains | dynamic: ``✓ Checked ${result.domains_checked} domains`` [success] | `frontend/domains.js:349` (checkAllDomainsDNS) |
| Domains | "DNS check failed" [error] | `frontend/domains.js:352` (checkAllDomainsDNS) |
| Domains | "Failed to check DNS" [error] | `frontend/domains.js:356` (checkAllDomainsDNS) |
| Domains | "DNS check already in progress" [warning] | `frontend/domains.js:367` (checkSingleDomainDNS) |
| Domains | dynamic: ``Checking DNS for ${domainName}...`` [info] | `frontend/domains.js:372` (checkSingleDomainDNS) |
| Domains | dynamic: ``✓ DNS checked for ${domainName}`` [success] | `frontend/domains.js:382` (checkSingleDomainDNS) |
| Domains | dynamic: ``Failed to check DNS for ${domainName}`` [error] | `frontend/domains.js:397` (checkSingleDomainDNS) |
| Domains | "Failed to check DNS" [error] | `frontend/domains.js:401` (checkSingleDomainDNS) |
| DMARC | "Manual upload is disabled" [error] | `frontend/dmarc.js:1139` (uploadDmarcReport) |
| DMARC | dynamic: ``${reportType} report uploaded: ${count} ${countLabel}`` [success] | `frontend/dmarc.js:1152` (uploadDmarcReport) |
| DMARC | dynamic: ``${reportType} report already exists`` [warning] | `frontend/dmarc.js:1157` (uploadDmarcReport) |
| DMARC | "Failed to upload report" [error] | `frontend/dmarc.js:1162` (uploadDmarcReport) |
| DMARC | "IMAP sync is not enabled" [error] | `frontend/dmarc.js:1243` (triggerDmarcSync) |
| DMARC | "Sync is already in progress" [info] | `frontend/dmarc.js:1258` (triggerDmarcSync) |
| DMARC | "IMAP sync started" [success] | `frontend/dmarc.js:1260` (triggerDmarcSync) |
| DMARC | "Failed to start sync" [error] | `frontend/dmarc.js:1274` (triggerDmarcSync) |
| DMARC | "Report deletion is disabled" [error] | `frontend/dmarc.js:1435` (deleteReport) |
| DMARC | dynamic: ``${reportType.toUpperCase()} report deleted`` [success] | `frontend/dmarc.js:1443` (deleteReport) |
| DMARC | "Failed to delete report" [error] | `frontend/dmarc.js:1457` (deleteReport) |
| Mailbox stats | "Please select both start and end dates" [error] | `frontend/mailbox-stats.js:531` (applyCustomDateRange) |
| Mailbox stats | "Start date must be before end date" [error] | `frontend/mailbox-stats.js:539` (applyCustomDateRange) |
| Mailbox stats | dynamic: `detail.detail \|\| 'Could not reset the counter'` [error] | `frontend/rate-limits.js:591` (resetRateLimitCounter) |
| Mailbox stats | dynamic: ``${user} can send again`` [success] | `frontend/rate-limits.js:595` (resetRateLimitCounter) |
| Mailbox stats | "Could not reset the counter" [error] | `frontend/rate-limits.js:604` (resetRateLimitCounter) |
| Mailbox stats | "Enter how many messages to allow, as a whole number" [error] | `frontend/rate-limits.js:868` (applyRateLimitBulk) |
| Mailbox stats | dynamic: `detail.detail \|\| 'Could not apply the rate limit'` [error] | `frontend/rate-limits.js:900` (applyRateLimitBulk) |
| Mailbox stats | dynamic: ``Nothing was changed${tail}`` [warning] | `frontend/rate-limits.js:944` (applyRateLimitBulk) |
| Mailbox stats | dynamic: `value === 0 ? `Limit removed from ${changed}${tail}` : `Limit set on ${change...` [success] | `frontend/rate-limits.js:947` (applyRateLimitBulk) |
| Mailbox stats | "Could not apply the rate limit" [error] | `frontend/rate-limits.js:952` (applyRateLimitBulk) |
| Mailbox stats | "Enter how many messages to allow, as a whole number" [error] | `frontend/rate-limits.js:1040` (saveRateLimit) |
| Mailbox stats | dynamic: `detail.detail \|\| 'Could not save the rate limit'` [error] | `frontend/rate-limits.js:1077` (submitRateLimit) |
| Mailbox stats | dynamic: `value === 0 ? `${name} now sends without a limit` : `${name} is limited to ${...` [success] | `frontend/rate-limits.js:1082` (submitRateLimit) |
| Mailbox stats | "Could not save the rate limit" [error] | `frontend/rate-limits.js:1113` (submitRateLimit) |
| Settings | dynamic: `detail.detail \|\| 'Could not save destination'` [error] | `frontend/notifications.js:234` (saveNotificationChannel) |
| Settings | dynamic: `isNew ? 'Destination added' : 'Destination updated'` [success] | `frontend/notifications.js:237` (saveNotificationChannel) |
| Settings | "Could not save destination" [error] | `frontend/notifications.js:241` (saveNotificationChannel) |
| Settings | "Could not delete destination" [error] | `frontend/notifications.js:256` (deleteNotificationChannel) |
| Settings | "Destination deleted" [success] | `frontend/notifications.js:257` (deleteNotificationChannel) |
| Settings | "Could not delete destination" [error] | `frontend/notifications.js:260` (deleteNotificationChannel) |
| Settings | "Cannot enable Basic Auth without a password. Please set a password first." [error] | `frontend/settings.js:1299` (renderSettings) |
| Settings | "Basic Auth enabled successfully! You will need to log in on your next visit." [success] | `frontend/settings.js:1344` (renderSettings) |
| Settings | dynamic: ``Purging data for ${purgeableNewlyDisabled.length} disabled feature(s)...`` [info] | `frontend/settings.js:1361` (renderSettings) |
| Settings | "Features updated - reloading..." [success] | `frontend/settings.js:1375` (renderSettings) |
| Settings | dynamic: `'Failed to save: ' + (err.message \|\| err)` [error] | `frontend/settings.js:1383` (renderSettings) |
| Settings | "MaxMind license is valid" [success] | `frontend/settings.js:1645` (validateMaxMindLicense) |
| Settings | dynamic: `'MaxMind license validation failed: ' + result.error` [error] | `frontend/settings.js:1647` (validateMaxMindLicense) |
| Settings | "Failed to validate MaxMind license" [error] | `frontend/settings.js:1656` (validateMaxMindLicense) |
| Settings | "GeoIP database re-download started…" [info] | `frontend/settings.js:1681` (repairGeoIPDatabase) |
| Settings | "GeoIP databases repaired successfully" [success] | `frontend/settings.js:1704` (repairGeoIPDatabase) |
| Settings | "GeoIP databases re-downloaded but validation still failed" [error] | `frontend/settings.js:1706` (repairGeoIPDatabase) |
| Settings | "GeoIP repair timed out - check Status page for progress" [warning] | `frontend/settings.js:1719` (repairGeoIPDatabase) |
| Settings | dynamic: `'Failed to repair GeoIP databases: ' + error.message` [error] | `frontend/settings.js:1730` (repairGeoIPDatabase) |
| Shared | "Download started." [success] | `frontend/export.js:34` (exportCSV) |
| Shared | dynamic: `error.message \|\| 'Could not export CSV. Please try again.'` [error] | `frontend/export.js:37` (exportCSV) |
| Shared | dynamic: `'Copied: ' + text` [success] | `frontend/utils.js:525` (copyToClipboard) |
| Shared | "Failed to copy" [error] | `frontend/utils.js:540` (copyToClipboard) |
| app.js (mixed) | dynamic: ``IP ${ip} added to the allowlist`` [success] | `frontend/app.js:1206` (allowIP) |
| app.js (mixed) | dynamic: `'Failed to allow: ' + (result.msg \|\| result.detail \|\| 'Unknown error')` [error] | `frontend/app.js:1212` (allowIP) |
| app.js (mixed) | dynamic: `'Failed to allow IP: ' + err.message` [error] | `frontend/app.js:1214` (allowIP) |
| app.js (mixed) | dynamic: `ignored ? `${data.name} is ignored for every address.` : `${data.name} counts...` [success] | `frontend/app.js:4178` (setBlocklistIgnored) |
| app.js (mixed) | dynamic: ``Could not change the blocklist: ${e.message}`` [error] | `frontend/app.js:4182` (setBlocklistIgnored) |
| app.js (mixed) | "Protection rules saved" [success] | `frontend/protection.js:175` (saveProtectionRules) |
| app.js (mixed) | dynamic: ``Could not save the rules: ${error.message}`` [error] | `frontend/protection.js:178` (saveProtectionRules) |
| app.js (mixed) | dynamic: `done(data)` [success] | `frontend/protection.js:190` (protectionHitAction) |
| app.js (mixed) | dynamic: ``Could not ${action === 'ban' ? 'ban' : action}: ${error.message}`` [error] | `frontend/protection.js:198` (protectionHitAction) |

### Confirmation dialogs

Every action that asks before it acts. Losing one turns a guarded action into a one-click action.

| Page | What | Code |
|---|---|---|
| Security | showConfirmModal: dynamic: `{ title: 'Unban IP', message: 'Unban IP ' + ipWithMask + '?', confirmText: 'U...` | `frontend/app.js:1115` (unbanIP) |
| Security | showConfirmModal: dynamic: `{ title: 'Ban IP', message: `Are you sure you want to permanently ban ${ipWit...` | `frontend/app.js:1152` (banIP) |
| Security | showConfirmModal: dynamic: `{ title: `Remove from the ${label}`, message: `Remove ${entry} from the Fail2...` | `frontend/security.js:726` (securityRemoveFromList) |
| Security | showConfirmModal: dynamic: `{ title: action === 'block' ? 'Disable SMTP' : 'Re-enable SMTP', message: `${...` | `frontend/smtp-abuse.js:156` (smtpAbuseAction) |
| Queue | showConfirmModal: dynamic: `{ title: 'Retry Delivery', message: `Retry delivery of ${ids.length} message(...` | `frontend/app.js:2256` (queueBulkRetry) |
| Queue | showConfirmModal: dynamic: `{ title: 'Delete Messages', message: `Permanently delete ${ids.length} messag...` | `frontend/app.js:2263` (queueBulkDelete) |
| Queue | showConfirmModal: dynamic: `{ title: 'Delete Message', message: 'Delete this message from the queue?', co...` | `frontend/app.js:2282` (queueDeleteItem) |
| Queue | showConfirmModal: dynamic: `{ title: 'Flush Queue', message: 'Flush (retry delivery of) ALL messages in t...` | `frontend/app.js:2287` (queueFlushAll) |
| Queue | showConfirmModal: dynamic: `{ title: 'Delete All', message: 'Permanently delete ALL messages from the que...` | `frontend/app.js:2292` (queueDeleteAll) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete Message', message: 'Are you sure you want to permanently del...` | `frontend/app.js:2538` (quarantineDelete) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Not Spam', message: 'Release this message and train Rspamd that it ...` | `frontend/app.js:2543` (quarantineLearnHam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Mark as Spam', message: 'Delete this message and train Rspamd that ...` | `frontend/app.js:2548` (quarantineLearnSpam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Release Messages', message: `Release ${ids.length} quarantined mess...` | `frontend/app.js:2555` (quarantineBulkRelease) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete Messages', message: `Permanently delete ${ids.length} quaran...` | `frontend/app.js:2562` (quarantineBulkDelete) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Not Spam', message: `Release ${ids.length} message(s) and train Rsp...` | `frontend/app.js:2569` (quarantineBulkLearnHam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Mark as Spam', message: `Delete ${ids.length} message(s) and train ...` | `frontend/app.js:2576` (quarantineBulkLearnSpam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Release All', message: `Release ALL ${allIds.length} quarantined me...` | `frontend/app.js:2583` (quarantineReleaseAll) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete All', message: `Permanently delete ALL ${allIds.length} quar...` | `frontend/app.js:2590` (quarantineDeleteAll) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete Rule', message: `Delete rule "${ruleName}"?`, confirmText: '...` | `frontend/app.js:3024` (deleteQuarantineRule) |
| Spam filter | showConfirmModal: dynamic: `{ title: 'Delete Suppression', message: `Delete suppression for ${email}? Thi...` | `frontend/spam_filter.js:835` (deleteSuppression) |
| DMARC | showConfirmModal: dynamic: `{ title: 'Delete Report', message: `Are you sure you want to delete this ${re...` | `frontend/dmarc.js:1425` (deleteReport) |
| Mailbox stats | showConfirmModal: dynamic: `{ title: 'Reset rate limit counter', message: `Let ${user} send again straigh...` | `frontend/rate-limits.js:575` (resetRateLimitCounter) |
| Mailbox stats | showConfirmModal: dynamic: `{ title: value === 0 ? 'Remove rate limits' : 'Apply rate limit', message: va...` | `frontend/rate-limits.js:876` (applyRateLimitBulk) |
| Mailbox stats | showConfirmModal: dynamic: `{ title: 'Remove rate limit', message: `Remove the rate limit on ${name}? It ...` | `frontend/rate-limits.js:1049` (removeRateLimit) |
| Settings | showConfirmModal: dynamic: `{ title: 'Delete destination', message: `Delete "${channel ? channel.name : '...` | `frontend/notifications.js:247` (deleteNotificationChannel) |
| Settings | showFeatureDisableConfirmModal: dynamic: `purgeableNewlyDisabled` | `frontend/settings.js:1329` (renderSettings) |
| Settings | showConfirmModal: dynamic: `{ title: 'Import from ENV', message: 'Import current configuration from ENV i...` | `frontend/settings.js:1389` (renderSettings) |
| Shared | confirm: dynamic: `` | `frontend/utils.js:595` |
| app.js (mixed) | showConfirmModal: dynamic: `{ title: 'Allow IP', message: `Add ${ipWithMask} to the Fail2Ban allowlist?\\...` | `frontend/app.js:1193` (allowIP) |

### Country flags

PNG flags served locally from `frontend/assets/flags/<size>/<cc>.png` (sizes 16x12, 24x18, 48x36), no emoji and no external source.

| Page | What | Code |
|---|---|---|
| Message details | getFlagUrl(rspamd.country_code, '16x12') | `frontend/message-details.js:550` (renderOverviewTab) |
| Message details | getFlagUrl(rspamd.country_code, '16x12') | `frontend/message-details.js:550` (renderOverviewTab) |
| Security | getFlagUrl(log.country_code, '16x12') | `frontend/app.js:1078` (renderNetfilterData) |
| Security | getFlagUrl(code, '16x12') | `frontend/security.js:117` (securityFlag) |
| Shared | getFlagUrl(rspamdData.country_code, size) | `frontend/app.js:4479` (renderGeoIPInfo) |
| Shared | getFlagUrl(record.country_code, size) | `frontend/app.js:4522` (renderGeoIPForDMARC) |

### Markdown rendering

Places that render Markdown (help pages, changelogs) through `renderMarkdown` (marked, then DOMPurify) into a `.markdown-body` element.

| Page | What | Code |
|---|---|---|
| Status | renders `versionInfo.changelog` | `frontend/about.js:172` (wireVersionPanel) |
| Settings | renders `versionInfo.changelog` | `frontend/settings.js:831` (updateVersionInfoUI) |
| Modal: changelog-modal | renders `markdownContent` | `frontend/app.js:677` (showMarkdownModal) |
| Modal: changelog-modal | renders `changelog` | `frontend/app.js:4435` (showChangelogModal) |

### Controls wired in JavaScript

Buttons, tabs and fields whose behavior is attached with `addEventListener` instead of an inline handler. The automatic inventory test does not see these, so they need a manual check.

| Page | What | Code |
|---|---|---|
| Shell | change on `px)')` | `frontend/app.js:488` (loadAppInfo) |
| Shell | click on `document` | `frontend/router.js:479` |
| Messages | click on `document` | `frontend/app.js:3365` |
| Message details | click on `messageModal` | `frontend/message-details.js:886` |
| Message details | click on `modalContent` | `frontend/message-details.js:896` |
| Spam filter | click on `document` | `frontend/spam_filter.js:962` |
| DMARC | click on `modal` | `frontend/dmarc.js:1294` (showDmarcSyncHistory) |
| Mailbox stats | click on `document` | `frontend/mailbox-stats.js:467` (toggleDateRangePicker) |
| Settings | click on `cancelBtn` | `frontend/settings.js:99` (showBasicAuthVerifyModal) |
| Settings | click on `confirmBtn` | `frontend/settings.js:100` (showBasicAuthVerifyModal) |
| Settings | click on `overlay` | `frontend/settings.js:114` (showBasicAuthVerifyModal) |
| Settings | click on `cancelBtn` | `frontend/settings.js:166` (showFeatureDisableConfirmModal) |
| Settings | click on `confirmBtn` | `frontend/settings.js:167` (showFeatureDisableConfirmModal) |
| Settings | click on `overlay` | `frontend/settings.js:174` (showFeatureDisableConfirmModal) |
| Settings | click on `btn` | `frontend/settings.js:1144` (renderSettings) |
| Settings | change on `tabSelect` | `frontend/settings.js:1164` (renderSettings) |
| Settings | click on `btn` | `frontend/settings.js:1171` (renderSettings) |
| Settings | change on `cb` | `frontend/settings.js:1197` (renderSettings) |
| Settings | input on `form` | `frontend/settings.js:1228` (renderSettings) |
| Settings | change on `form` | `frontend/settings.js:1229` (renderSettings) |
| Settings | click on `btn` | `frontend/settings.js:1231` (renderSettings) |
| Settings | click on `btn` | `frontend/settings.js:1237` (renderSettings) |
| Settings | input on `search` | `frontend/settings.js:1239` (renderSettings) |
| Settings | click on `closeBtn` | `frontend/settings.js:1472` (showGeoIPSetupModal) |
| Settings | click on `modal` | `frontend/settings.js:1857` (showConnectionTestModal) |
| Shared | click on `cancelBtn` | `frontend/utils.js:643` (showConfirmModal) |
| Shared | click on `okBtn` | `frontend/utils.js:644` (showConfirmModal) |
| Shared | click on `document` | `frontend/utils.js:844` |
| app.js (mixed) | click on `changelogModal` | `frontend/app.js:4630` |
| app.js (mixed) | click on `changelogContent` | `frontend/app.js:4638` |
| app.js (mixed) | click on `el` | `frontend/app.js:4832` (showNavFlyout) |
| app.js (mixed) | click on `item` | `frontend/app.js:4855` (initNavFlyouts) |
| Not rendered (possible dead code) | click on `document` | `frontend/security.js:582` |

### Filters, sorting and view options

Drop-down lists in the page markup with their options. The option wording and order are part of the product.

| Page | What | Code |
|---|---|---|
| Dashboard | `dashboard-search-status`: All Statuses / Delivered / Sent / Deferred / Bounced / Rejected / Discarded (Sieve) / Expired | `frontend/index.html:545` |
| Messages | `messages-filter-direction`: All Directions / Inbound / Outbound / Internal | `frontend/index.html:664` |
| Messages | `messages-filter-status`: All Statuses / Delivered / Deferred / Bounced / Rejected / Spam / Discarded (Sieve) | `frontend/index.html:670` |
| Security | `netfilter-filter-action`: All Actions / BAN / UNBAN / Warning / Info | `frontend/index.html:766` |
| Security | `netfilter-filter-country`: All Countries | `frontend/index.html:773` |
| Quarantine | `quarantine-sort`: Newest first / Score: high to low / Score: low to high | `frontend/index.html:857` |
| Spam filter | `suppression-filter-reason`: All Reasons / Hard Bounce / Soft Bounce / Deferred Stuck / Rejected / Manual | `frontend/index.html:950` |
| Spam filter | `suppression-filter-active`: Active Only / All / Inactive / Expired | `frontend/index.html:960` |
| Mailbox stats | `mailbox-stats-domain-filter`: All Domains | `frontend/index.html:1279` |
| Mailbox stats | `mailbox-stats-sort`: Sent (High to Low) / Received (High to Low) / Failure Rate (High to Low) / Quota Used (High to Low) / Username (A-Z) | `frontend/index.html:1282` |
| Logs | `logs-fontsize`: 10px / 11px / 12px / 13px / 14px / 16px | `frontend/index.html:1357` |

### Charts

Chart.js charts (local library). Check hover tooltips, legend and both themes.

| Page | What | Code |
|---|---|---|
| DMARC | line chart on `ctx` | `frontend/dmarc.js:559` (dmarcLineChart) |
| Mailbox stats | bar chart on `canvas.getContext('2d')` | `frontend/rate-limits.js:262` (renderRateLimitChart) |

### Colour thresholds

Values whose colour changes at a threshold (for example storage turns yellow and red, a high spam score turns red).

| Page | What | Code |
|---|---|---|

### Help topics

In-app help buttons; the topic is the Markdown file name under documentation/HelpDocs.

| Page | What | Code |
|---|---|---|
| Security | topic "Abuse_Protection" | `frontend/security.js:1072` (securityCardHtml) |
| Quarantine | topic "Quarantine" | `frontend/index.html:841` |
| Spam filter | topic "Spam_Filter" | `frontend/index.html:914` |
| Status | topic "IP_Blacklist_Monitor" | `frontend/index.html:1037` |
| Domains | topic "Domains" | `frontend/index.html:1067` |
| DMARC | topic "DMARC" | `frontend/index.html:1086` |
| Mailbox stats | topic "Mailbox_Stats" | `frontend/index.html:1220` |
| Mailbox stats | topic dynamic: `'${isRateLimits ? 'Rate_Limits' : 'Mailbox_Stats'}'` | `frontend/mailbox-stats.js:85` (mailboxStatsSwitchView) |

### Empty states

Text shown when a list or panel has nothing to show.

| Page | What | Code |
|---|---|---|
| Shell | "No changelog available" | `frontend/app.js:658` (loadAppVersionStatus) |
| Shell | "No changelog available" | `frontend/app.js:719` (loadMailcowVersionStatus) |
| Messages | "No messages found" | `frontend/app.js:921` (renderMessagesData) |
| Messages | "No messages found" | `frontend/app.js:3495` (loadMessages) |
| Message details | "No modal data available" | `frontend/message-details.js:70` (switchModalTab) |
| Message details | "No delivery steps recorded yet" | `frontend/message-details.js:524` (renderDeliverySteps) |
| Message details | "No Postfix delivery logs available" | `frontend/message-details.js:585` (renderPostfixTab) |
| Message details | "No Postfix delivery logs available" | `frontend/message-details.js:590` (renderPostfixTab) |
| Message details | "No spam analysis data available" | `frontend/message-details.js:752` (renderSpamTab) |
| Security | "No logs found" | `frontend/app.js:1029` (renderNetfilterData) |
| Security | "No network data yet" | `frontend/security.js:642` (renderSecurityCountries) |
| Security | "No trap names yet" | `frontend/security.js:1022` (securityCardBody) |
| Security | "No countries yet" | `frontend/security.js:1034` (securityCardBody) |
| Security | "No matching entries" | `frontend/smtp-abuse.js:137` (renderSmtpAbusePanel) |
| Queue | "No matching queue entries" | `frontend/app.js:2139` (applyQueueFilters) |
| Quarantine | "No quarantined messages" | `frontend/app.js:2435` (renderQuarantineData) |
| Quarantine | "No actions recorded yet" | `frontend/app.js:3147` (loadQuarantineRuleHistory) |
| Status | "No changelog available" | `frontend/about.js:158` (wireVersionPanel) |
| Status | "No container information available" | `frontend/app.js:3757` (loadStatusContainers) |
| Status | "No changelog available" | `frontend/app.js:3792` (loadStatusSystem) |
| Domains | "No domains found" | `frontend/domains.js:91` (renderDomains) |
| Domains | "No domains with DNS issues found" | `frontend/domains.js:147` (filterDomains) |
| Domains | "No domains found matching" | `frontend/domains.js:148` (filterDomains) |
| DMARC | "No DMARC reports yet" | `frontend/dmarc.js:369` (loadDmarcDomains) |
| DMARC | "No daily reports available" | `frontend/dmarc.js:593` (loadDomainReports) |
| DMARC | "No sources found" | `frontend/dmarc.js:627` (loadDomainSources) |
| DMARC | "No TLS reports yet" | `frontend/dmarc.js:752` (loadTlsDomains) |
| DMARC | "No daily reports available" | `frontend/dmarc.js:864` (loadTlsDomain) |
| DMARC | "No providers found" | `frontend/dmarc.js:879` (loadTlsDomain) |
| DMARC | "No providers found" | `frontend/dmarc.js:937` (loadTLSReportDetails) |
| DMARC | "No sources found" | `frontend/dmarc.js:997` (loadReportDetails) |
| DMARC | "No data found" | `frontend/dmarc.js:1081` (loadSourceDetails) |
| DMARC | "No sync history yet" | `frontend/dmarc.js:1301` (showDmarcSyncHistory) |
| DMARC | "No reports found" | `frontend/dmarc.js:1383` (renderReportsManagementTable) |
| Mailbox stats | "No mailboxes found" | `frontend/mailbox-stats.js:309` (renderMailboxStatsAccordion) |
| Logs | "No log services available" | `frontend/logs-viewer.js:90` (loadLogViewer) |
| Logs | "No log entries found" | `frontend/logs-viewer.js:476` (renderLogEntries) |
| Settings | "No logs available" | `frontend/notifications.js:269` (testNotificationChannel) |
| Settings | "No logs available" | `frontend/notifications.js:286` (testNotificationChannelDraft) |
| Settings | "No logs available" | `frontend/settings.js:1794` (testSmtpConnection) |
| Settings | "No logs available" | `frontend/settings.js:1820` (testImapConnection) |
| Modal: changelog-modal | "No changelog available" | `frontend/app.js:4437` (showChangelogModal) |
| Modal: container-logs-modal | "No logs available" | `frontend/app.js:4713` (fetchContainerLogs) |

### Loading states

Functions that render a spinner or "Loading..." while data is fetched.

| Page | What | Code |
|---|---|---|
| Messages | 1 loading indicator(s) | `frontend/app.js:3468` (loadMessages) |
| Message details | 1 loading indicator(s) | `frontend/message-details.js:99` (viewMessageDetails) |
| Security | 1 loading indicator(s) | `frontend/app.js:1981` (loadNetfilterLogs) |
| Security | 1 loading indicator(s) | `frontend/security.js:376` (securityDetail) |
| Security | 1 loading indicator(s) | `frontend/security.js:468` (securityHistoryRows) |
| Security | 1 loading indicator(s) | `frontend/security.js:618` (securityCountryPanel) |
| Security | 1 loading indicator(s) | `frontend/security.js:634` (renderSecurityCountries) |
| Security | 1 loading indicator(s) | `frontend/security.js:666` (renderSecurityLists) |
| Security | 2 loading indicator(s) | `frontend/security.js:1061` (securityCardHtml) |
| Security | 1 loading indicator(s) | `frontend/smtp-abuse.js:39` (renderSmtpAbusePanel) |
| Queue | 1 loading indicator(s) | `frontend/app.js:2071` (loadQueue) |
| Quarantine | 1 loading indicator(s) | `frontend/app.js:2400` (loadQuarantine) |
| Quarantine | 1 loading indicator(s) | `frontend/app.js:3139` (loadQuarantineRuleHistory) |
| Status | 3 loading indicator(s) | `frontend/about.js:190` (wireVersionPanel) |
| Status | 1 loading indicator(s) | `frontend/app.js:3617` (renderStatusAttention) |
| Status | 2 loading indicator(s) | `frontend/app.js:3908` (checkBlacklists) |
| Status | 1 loading indicator(s) | `frontend/app.js:4382` (triggerBackgroundJob) |
| Logs | 1 loading indicator(s) | `frontend/logs-viewer.js:1091` (loadDateRangeLogs) |
| Settings | 2 loading indicator(s) | `frontend/settings.js:1429` (showGeoIPSetupModal) |
| Settings | 1 loading indicator(s) | `frontend/settings.js:1619` (validateMaxMindLicense) |
| Settings | 1 loading indicator(s) | `frontend/settings.js:1665` (repairGeoIPDatabase) |

### Persisted preferences

Settings the browser remembers between visits.

| Page | What | Code |
|---|---|---|
| Shell | localStorage getItem "theme" | `frontend/app.js:4588` (initDarkMode) |
| Shell | localStorage setItem "theme" | `frontend/app.js:4603` (toggleDarkMode) |
| Shell | localStorage getItem "navCollapsed" | `frontend/index.html:18` |
| Logs | localStorage getItem "logsNewestFirst" | `frontend/logs-viewer.js:17` |
| Logs | localStorage setItem "logsNewestFirst" | `frontend/logs-viewer.js:549` (toggleLogSortOrder) |
| app.js (mixed) | localStorage setItem "navCollapsed" | `frontend/app.js:4902` (toggleNavCollapsed) |

### Auto refresh and timers

Background refreshes and polling.

| Page | What | Code |
|---|---|---|
| Shell | every 5 * 60 * 1000 ms | `frontend/app.js:490` (loadAppInfo) |
| Shell | every AUTO_REFRESH_INTERVAL ms | `frontend/app.js:778` (startAutoRefresh) |
| Status | every 1000 ms | `frontend/app.js:3943` (checkBlacklists) |
| Settings | every 2000 ms | `frontend/settings.js:1550` (showGeoIPSetupModal) |
| Modal: container-logs-modal | every 2000 ms | `frontend/app.js:4749` (loadContainerLogs) |

### Address bar and deep links

Places that change the URL so a view can be bookmarked or shared.

| Page | What | Code |
|---|---|---|
| Shell | replaceState | `frontend/app.js:1410` (switchTab) |
| Shell | replaceState | `frontend/router.js:71` (routerSyncSubpage) |
| Shell | pushState | `frontend/router.js:72` (routerSyncSubpage) |
| Shell | replaceState | `frontend/router.js:239` (navigateTo) |
| Shell | pushState | `frontend/router.js:241` (navigateTo) |
| Shell | pushState | `frontend/router.js:291` (syncOverlayHistory) |
| Shell | replaceState | `frontend/router.js:383` (initRouter) |
| DMARC | replaceState | `frontend/dmarc.js:214` (handleDmarcRoute) |
| DMARC | pushState | `frontend/dmarc.js:434` (loadDomainOverview) |
| DMARC | replaceState | `frontend/dmarc.js:663` (dmarcSwitchSubTab) |
| DMARC | pushState | `frontend/dmarc.js:664` (dmarcSwitchSubTab) |
| DMARC | replaceState | `frontend/dmarc.js:797` (tlsSwitchSubTab) |
| DMARC | pushState | `frontend/dmarc.js:798` (tlsSwitchSubTab) |
| DMARC | pushState | `frontend/dmarc.js:814` (loadTlsDomain) |
| DMARC | pushState | `frontend/dmarc.js:911` (loadTLSReportDetails) |
| DMARC | pushState | `frontend/dmarc.js:971` (loadReportDetails) |
| DMARC | pushState | `frontend/dmarc.js:1039` (loadSourceDetails) |

### Keyboard handling

Key handlers; the keys are read from the handler body.

| Page | What | Code |
|---|---|---|
| Message details | keydown: Escape | `frontend/message-details.js:902` |
| Settings | keydown: Escape, Enter | `frontend/settings.js:103` (showBasicAuthVerifyModal) |
| Settings | keydown: Escape, Enter | `frontend/settings.js:169` (showFeatureDisableConfirmModal) |
| Shared | keydown | `frontend/utils.js:641` (showConfirmModal) |
| app.js (mixed) | keydown: ArrowDown, ArrowUp, Escape, ArrowLeft | `frontend/app.js:4810` (showNavFlyout) |
| app.js (mixed) | keydown | `frontend/app.js:4856` (initNavFlyouts) |
| Not rendered (possible dead code) | keydown | `frontend/security.js:588` |
| Modal: changelog-modal | keydown: Escape | `frontend/app.js:4618` |

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
