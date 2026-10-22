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
- **Desktop and mobile.** The sidebar (desktop) carries the brand, a server card (connection indicator, mailcow host, problem count, opens Status), the pages grouped as Mail, Protection and Server with counters (Queue and Quarantine items, failed logins in 24 h on Security, DMARC insights, problems on Status, from `loadNavCounters`), and at the bottom the versions, the update links and the tools (theme, Refresh, Logout, GitHub, container logs). Below 1100 px it is an icon rail where counters become dots. On phones (below 760 px) a top bar shows the page name, the Needs attention bell (`attnWindowOpen`) and the theme and Refresh buttons (`placeShellUtilities` moves them there), and a bottom tab bar (Dashboard, Messages, Security, Status with a problems dot, More) opens every page in a sheet (`toggleMobileMenu`, `navigateToMobile`). On phones a filter panel keeps its search field and opens the other filters on demand. Every page must stay usable on a phone.
- **Escaping.** Anything that comes from the server or from mail headers is rendered through `escapeHtml`, and values placed inside inline handlers through `escapeJsArg` (see `frontend/utils.js`). New markup must keep this; mail headers are attacker-controlled.
- **Mail content keeps its own direction.** Subjects, addresses and quarantine rule values can be in Hebrew or Arabic, so the element that shows them carries `dir="auto"`, and `copyableText` wraps its text in `<bdi>`. The browser then lays out each value in its own direction without moving the text around it (scores, arrows, the copy icon). A rule in the `<style>` block of `index.html` keeps `[dir="auto"]` aligned left, so a Hebrew subject stays next to its label instead of jumping to the far edge. Keep this on every place that shows mail content.
- **Country flags are PNG images, never emoji.** Most use is on desktop, and Windows does not render flag emoji (it shows two letters instead). The images live in `frontend/assets/flags/` in three sizes.
- **Markdown keeps its styling.** Help pages and changelogs are rendered by `renderMarkdown` (marked, then DOMPurify, `frontend/utils.js`) into a `.markdown-body` element inside `#changelog-content` or `.update-changelog-content`. Their look comes from the local `github-markdown.min.css` plus the overrides in the `<style>` block of `index.html` (the `.markdown-body` rules, about lines 270 to 470), which also carry the dark theme. A redesign that renames these containers or drops those rules breaks every help page and changelog, even though nothing else changes.
- **Dates follow the app timezone.** Times are formatted with `Intl.DateTimeFormat` in `appTimezone`, which the backend reports from `TZ` (`formatTime` in `frontend/utils.js`, and `frontend/rate-limits.js`). With `TZ` unset or `UTC` they are shown in the browser's timezone. The Dashboard's Mail flow and the alert window's chart write dates as numbers, like `formatTime` (`formatDay`, `formatDayMonth`). Counts use thousands separators (`toLocaleString()`).
- **Custom branding.** The header title and logo come from settings (`app_title`, `app_logo_url`, see `/api/info`): a custom logo replaces the default icon (`#app-logo`, `#default-logo`) and the title can differ per installation. The footer repeats the title.
- **Sidebar indicators.** The server card holds the mailcow connection indicator (`#mailcow-connection-indicator`) and the problem count; the sidebar foot holds the app version and its "Update Available" link (opens Settings), the mailcow version with its "Update Available" link and update icon (`#mailcow-update-icon`, both open the mailcow update dialog), and the tools. There is no page footer. Each is easy to lose in a new layout.
- **Status indicators inside tabs.** The Security tab of the message details shows a red count of the message's security events, and nothing when there are none.
- **Dashboard.** Mail flow has three periods (24 hours in hourly bars, 7 days in 6-hour bars, 30 days in daily bars, in the app's time zone), each figure compared with the period before. Mail flow and the alert window's chart zoom in time: drag across bars, Ctrl+wheel or a trackpad pinch, a pinch on a phone, or the buttons under the chart; a sideways drag moves a zoomed chart. Under each chart an overview strip shows the whole period with a window over the part shown: drag the window, drag an edge or click beside it; for the keyboard its edges are sliders (arrows by one bar, Page Up and Page Down by a bigger step, Home and End). Every change snaps to the chart's bars (whole hours of the app's zone on the Dashboard, quarters in the alert window), except where the data ends. View these messages, or the Messages figure, opens Messages for the picked bar, or for the time shown. In a narrow panel (a phone) the period picker sits beside the title in short words (24h, 7d, 30d), the title names only a picked bar's or a zoom's span (its days without the year) with Clear as a × beside it, and the row with View these messages is gone. Mail flow keeps one size in every state: logs older than the retention are a shaded part of the chart. Needs attention is as tall as its items up to 380 px (340 px on phones); past that they scroll inside it, with a line that counts them, and at the end of the list the page scrolls on. The alert window keeps Dismiss and Open in Messages (or Security) in a footer that stays while its content scrolls. Dismiss and Dismiss all act at once and offer Undo for 10 seconds (`offerAlertUndo`); Dismiss all names its count and leaves an alert that arrived later open, and an alert another tab dismissed says "Already dismissed". Mail storage, To review and Banned now show their last 7 days as a line under the figure (hourly samples kept 90 days, the Trend Samples job on Status): no line until a day of samples, a break where an hour has no sample, and a card whose source did not answer says Unknown.
- **Messages and the reading pane.** The Messages page has three columns from 1280 px: facets (Outcome and Direction with counts from `/api/messages/facets`, which counts exactly as the list does, the time presets and a custom range, More filters with sender, recipient, user and IP, Export CSV), the list, and the reading pane. From 1000 px the facets become chips above the list; below that the list stands alone and a message opens as a full-screen dialog. A list row shows sender, time (time of day for today, date before), subject, the outcome tag, direction, recipient, spam, folder and deliveries; queue ID, message ID, score, user and IP are in the reading pane. On a wide screen the first message opens in the pane and the open row is marked; the smart refresh keeps running while a message is docked. The pane (`#message-modal`, docked as `ui-docked`) shows the subject, From/To/When and the outcome above the tabs (`renderMessageHeader`), and the Overview tab tells "What happened" as steps built from the Postfix, Rspamd and Dovecot logs (`buildDeliverySteps`), then Identifiers. Every id, tab and handler is the same as a dialog (`message-details.js`). The list loads one list at a time: new filters, a new order or the auto refresh drop what an older list still had on its way; the next page starts after the last message shown (a cursor, so nothing is skipped or shown twice), and a next page that failed waits for Try again. Sort, beside the search, is one button that turns the time order around (Newest first, Oldest first), its arrow showing which. The details scroll as one, with the tabs and the timeline's head pinned at the top. With several recipients, To is one line with "All N recipients", the outcome counts recipients with a count per other status that opens those recipients (not when the message as a whole was rejected, spam or discarded, or nothing is logged per recipient yet), and the Logs tab has a Recipients list (search, a count per status, problems first with their server, reason and attempts, six rows then Show all). A click on a recipient, or a pick in Recipient in the timeline's head, shows only its lines; with no recipient picked, a status or a search in the list narrows the timeline the same way; the lines of the whole message stay, dimmed and marked "All recipients".
- **Outbound > Queue and Quarantine tables.** One row per item with the actions at the end of the row and the bulk actions (Select All, the Selected actions, Flush All or Release All, Delete All) above the table. A queue row shows every recipient, the sender, how long ago it was queued, the queue ID and the last response per recipient; with several recipients Suppress opens a menu of them. A quarantine row shows Release, Not spam, Spam, Rule and Delete as buttons (only Details without the Read-Write key); the subject also opens Details. The page subtitles count what is in the queue (`updateQueueSummary`) with the blocked recipients (`loadSuppressionStats`), and what is held. On phones the rows stack.
- **Status.** Key figures on top (containers running, blocklists listing you, mail storage used with amber above 75% and red above 90%, this app's version with the update link to Settings); the blocklists figure hides with the `blacklist` feature like its section. Containers are a grid with stopped ones first and in red. Blocklists are a table per monitored host with the listing lists named, Check now per host (`checkHost`) and Check Now for all with its progress bar (`checkBlacklists`); "All N lists" opens every result and stays open across refreshes. Background jobs are a table grouped by category with how often they run, the last result (feature off and disabled explain a missing Run), the last run, errors under the row and Run (`triggerBackgroundJob`). Log import, message linking with the recent incomplete ones, the mailcow system (with the mailcow update) and storage follow.
- **Domains.** A table with one row per domain: mailboxes and aliases under the name (with "open for the fix" when SPF, DKIM or DMARC has an error or a warning), a result per DNS check, as a word on wide screens and on a phone as an icon (check for OK, exclamation mark for a warning, cross for an error, each named for screen readers; SPF, DKIM, DMARC, TLSA, MTA-STS; the tooltip gives the message) and storage; on a phone the checks are two even lines of three, each name beside its result, and storage is only in the details, where each fact takes one line. There is no MX check, so there is no MX column. A row opens its details (`toggleDomainDetails`): the domain facts, the DNS records with View Record, Checked IPs, warnings, info and Expected Value, Check for this domain (`checkSingleDomainDNS`, which re-renders the row open) and the alias domains. The subtitle counts domains, inactive ones and those that need a DNS change; the head keeps Last checked and Check Now (`checkAllDomainsDNS`, on the title line on a phone); search and "Show only domains with issues" filter the rows (`filterDomains`).
- **DMARC.** One page for DMARC and TLS, no tabs. All domains: the last 30 days in figures, messages per day across the domains, a domains table (policy, pass rate, TLS-RPT, encrypted, failing senders; a row opens the domain) and, beside it, a To do list built from the records, the failing senders and DMARC Insights. A domain: messages per day (a day opens its reports), a calendar with one square per day over the reports kept (its colour follows the day's pass rate and grows stronger with more mail, a day without reports is an empty square, a day before the retention is hatched, a day opens its reports; one Tab stop, arrows by day and by week, Home, End and Enter; on a phone it scrolls sideways from the newest weeks), the mail flow (domain, senders, reporting receivers), senders grouped by network and failing first (a row opens the sender), daily reports, and TLS (figures, chart, a row per receiver); beside it To do and Records, where SPF and DKIM open a window with how much mail passed and each sender's share, weakest first (a sender opens its details), and DMARC opens a window with the record, its settings, the current record under its own heading, the record check's notes as a coloured box, the three policies as a choice in their colours (None red, Quarantine amber, Reject green; `dmarcPickPolicy`; the next stricter one picked first) showing what the picked one would do and its record to copy. Rates show green from 95%, amber from 80%, red below. Old addresses (/dmarc/tls, /dmarc/<domain>/sources) open the matching screen. Breadcrumbs lead back. Upload Report shows only when manual upload is enabled, Fetch reports (pulls them from the IMAP mailbox) only when IMAP is enabled, with the last fetch and View History; on a phone Fetch reports and an Upload Report icon sit on the title line, and the last fetch and Manage Reports are one line of links under the description. To do uses the dashboard's alert rows. On a phone a domain card puts each figure's name beside its value; a domain leaves out the mail flow (the Senders table says the same) and its Daily reports start folded, and a record window puts each fact's name beside its value. On a phone the sender, report day and TLS day pages show their figures with each name beside its value, two to a line, and their tables as lists (the name and its count on a line, then the details and the results as coloured tags, then who reported it). The fetch history, Manage Reports and the record windows are dialogs. Manage Reports lists the reports by domain (sortable columns, Delete all per domain with the counts in the confirmation) above all reports, paged, with a search by domain or reporter that filters them on the server (`searchReportsManagement`) and column headers that sort them on the server across pages (`sortReportsManagement`); deletion shows only when allowed.
- **Mailbox Stats and Rate Limits.** One page with two tabs (Statistics, Rate Limits; each hides with its feature). Statistics: key figures for the chosen period, search with the Sort button, the period picker (presets and a custom range), domain, Active Only and Hide Zero Activity behind the Filters icon, and Clear filters, then a table of mailboxes; a row opens quota, messages, dates, rate limit, access with last logins, counts that open Messages filtered on the address, and the aliases with their own clickable counts. On a phone a mailbox shows its address with the activity chart, storage and aliases, services and four figures; the counts are two lists (Traffic, Sent mail) with every count still opening Messages; an alias shows only its non-zero counts and a tap (`toggleMailboxAlias`) opens all of them. Rate Limits: the activity chart with its window, Blocked senders (search, Reset counter, a sender opens its refused messages) and Configured limits (All, Mailboxes, Domains, search, Apply to filtered, Edit per row). Without the Read-Write key the editing and Reset counter are removed and a locked area says why.
- **Outbound and Rspamd.** Outbound has the tabs Queue and Suppressions; a tab whose feature is off is hidden, and a page with one tab left shows no tab bar (`TAB_FEATURES`, `applyTabFeatures`). The Rspamd page holds the maps, with its own feature. Old addresses (`/queue`, `/spam-filter`, `/spam-filter/maps`, `/settings/spam_filter`) and history entries open the new place (`canonicalRoute`). Open in Rspamd, in the More menu of Suppressions, opens the Recipient Denylist there (`openRspamdMap`). Suppressions: key figures, a filter bar (search, reason, state, Clear) with Add Suppression and a More menu (Export CSV, Import CSV), and a table with the address (domain patterns shown as the domain), reason and source tags, bounces, expiry, Rspamd sync state, age and Edit, Disable or Enable, Delete. Add and Edit are v3 dialogs. Rspamd: maps grouped by category as rows that open the editor (Regex Wizard for regex maps, Validate with line errors and warnings, Save Changes); without Rspamd configured a locked area leads to Settings, without the Read-Write key a locked area says maps are read-only.
- **Settings.** Version Information (current version opens its changelog, the latest version with Up to Date or Update Available, Last checked and Check Now, the update note with the changelog) and Configuration (mailcow URL, server IP, authentication, local domains) as key and value panels; local domains as chips when there are any. With editing off, a locked area explains it and the runtime values, SMTP and DMARC status show read-only with Test SMTP and Test IMAP. With editing on, Edit configuration has the categories as a side menu (a picker on narrow screens), groups of fields, a mark on values that differ from their default, Reset to default or Clear, fields locked by ENV, the feature toggles (disabling one warns that its data is deleted), status facts on the SMTP, DMARC IMAP and MaxMind tabs, and the alert destinations with a v3 dialog.
- **Shared dialogs and notices.** Confirmations (`showConfirmModal`) are a v3 dialog in the current theme: the confirm button is red for destructive actions; Escape, Cancel and a click outside cancel. A click outside closes a dialog only when the press started outside too (`uiBackdropClick`), so a text selection that ends there keeps it open; a click that ends a text selection in a list row leaves the row closed (`uiRowHeld`). Dialogs, sheets and the phone menus are layers (`router.js`): Escape and Back close only the top one, focus moves into a layer and back to what opened it, and the page behind is inert. A dialog with typed fields does not close on a click outside and asks "Discard your changes?" before dropping them; leaving a page with unsaved changes asks "Leave without saving?" (`uiConfirmLeave`), and the browser asks when the tab closes. Toasts (`showToast`) sit at the bottom corner (above the tab bar on phones) with a tone per type and close by themselves after four seconds, waiting while the pointer or the focus is on them; a toast can carry an action (Undo, Retry, Refresh) and stays while it runs. Every list whose column headers hide on phones has one Sort button at every size, beside its search or at the end of its header row: a menu with Sort by and Order (worded per column), the same order as the headers, Default order where the list names no default column, and a dot when the order is not the default; Manage Reports has no Sort button (its headers sort) and the Status import table does not sort. Filters on Security, the mail queue and Mailbox Stats is a funnel icon with the number in use. The browser tab names the page and its tab; Back and Forward return a page to where it was scrolled. Hover styles apply only where a pointer can hover; spacing follows the reading direction (charts and the DMARC calendar stay left to right); animations stay under reduced motion. The quarantine details, rule, rule test, GeoIP setup, connection test and alert destination dialogs use the same frame. The Logs page keeps its toggles (Pause, Live, Auto-scroll, Wrap), service list and quick filters as `aria-pressed` and `aria-current` states. On the Logs page and in the container log a click on a line selects the whole line, with Copy at its end (`data-line-select`). On the Logs page selecting text turns Auto-scroll off and keeps new lines from trimming the selected ones, and lines that arrive meanwhile show "N new lines" at the newest edge, which goes there and turns Auto-scroll on; the container log pauses its refresh while text is selected in it. A disabled feature shows a locked area with Go to Dashboard.
- **Badges** use the recipes in `APP_COLORS` (soft fill plus a subtle border, squared corners, not rounded pills). Pages already on the v3 design use `uiStatusTag` and `uiDirectionTag` (`frontend/utils.js`) instead: the tone follows the meaning (delivered and sent green, deferred amber, bounced and rejected red, spam its own colour, anything else neutral) and the text is the status itself.
- **Cache busting.** Every changed frontend file gets a new `?v=` in `index.html`, or browsers keep the old copy.
- **Utility classes are compiled, not generated in the browser.** The Tailwind utilities the markup still uses are built once into `assets/css/utilities.css` (`bash .github/scripts/build-utilities-css.sh`, Tailwind 3.4.17). After adding or changing a utility class, rebuild it and bump its `?v=`; CI fails when the file does not match the markup. A class assembled at runtime (`bg-${color}-100`) must be in the safelist of `.github/tailwind/tailwind.config.cjs` (`utilities-css.test.cjs` checks this). New UI is built on the `ui-` components instead.

## Manual checks per behavior

| Behavior | What to check |
|---|---|
| Click to copy | Hovering the value (with a pointer) shows a faint background and a copy icon. Clicking copies the exact value (not the truncated display), the icon turns into a check mark for 1.5 s, and a toast says "Copied: <value>". The Clipboard API only works in a secure context (HTTPS or localhost); on plain HTTP the click says "Copying needs HTTPS. Select the text and copy it yourself." |
| Tooltips | Hovering shows the same text as before. Dynamic tooltips show the full value where the cell truncates it. |
| Toasts | One toast at a time (a new one replaces the old), bottom of the screen, colour by type (success, error, warning, info), disappears after about 4 s, waiting while the pointer or the focus is on it. Undo after Dismiss on the Dashboard stays 10 s; Retry and Refresh stay until used or closed; a toast stays while its action runs. The wording is part of the product; keep it. |
| Confirmation dialogs | Every action listed here still asks first, with the same title and message, and Escape/Enter still work where noted under keyboard handling. |
| Country flags | The flag image appears next to IP addresses where listed, at the listed size, with no emoji fallback and no external image source. Check on Windows. |
| Markdown | Open a help page, the changelog from the footer, and the update changelog in Settings, in light and dark theme. Headings, paragraphs, nested lists (three levels), inline code, code blocks, tables, block quotes and links all look as before, the background stays transparent, and nothing is unreadable in dark mode. |
| Controls wired in JavaScript | Each listed button, tab or form still reacts. These are invisible to the automatic inventory test. |
| Filters and view options | Every drop-down keeps its options in the same order and wording, the Sort button and the column headers show the same order, and filtering or sorting still changes the list. |
| Charts | The chart renders with data, hover shows its tooltip, and it is readable in both themes. Mail flow and the alert window's chart zoom with a drag, Ctrl+wheel, a pinch and the buttons, keep their size, and the strip under them follows the zoom. |
| Colour thresholds | The value changes colour at the listed threshold (for example storage above 75% and above 90%). |
| Dates and numbers | Times match the `TZ` set for the app, or the browser's timezone when `TZ` is unset or UTC; large counts keep their separators. |
| Help topics | Each help button opens the listed topic. |
| Empty states | An empty list shows its sentence, not a blank area or a broken table. |
| Loading states | A spinner or "Loading..." appears while data loads; the page never shows stale data without an indicator. |
| Persisted preferences | The preference survives a reload. |
| Auto refresh | The page refreshes on its own at the listed interval, and stops when you leave it. |
| Address bar | The URL changes as listed, so the view can be bookmarked, shared and reloaded. |
| Keyboard | Escape closes only the top layer; Enter still confirms where noted; sortable headers and rows that open on click work with Enter and Space; the strip's edges move with the arrows, Page Up, Page Down, Home and End; the DMARC calendar is one Tab stop with arrows by day and by week. |
| Gated states | Each state in the next section still appears under its condition, with the same explanation and the same way out (a link or the place to configure it). Run the browser pass in both modes (see below). |

## Gated and conditional states

Many parts of the UI change with the configuration: a feature can be turned off, a key or password can be missing, settings can be read-only. These states are easy to miss in a redesign because a normal test instance never shows them. Each row names the condition, what the user sees and where it is rendered.

### Global (navigation, header, footer)

| Condition | What the user sees | Rendered by |
|---|---|---|
| A feature is listed in `disabled_features` (`/api/info`; env `DISABLED_FEATURES`: netfilter, queue, quarantine, suppressions, rspamd, domains, dmarc, mailbox-stats, rate-limits, logs, blacklist, devices; the old `spam-filter` means suppressions and rspamd) | Its entry disappears from the sidebar, the phone tab bar and the sheet; Outbound goes only when both its features are off, otherwise only the tab goes; a group whose pages are all off loses its heading | `applyFeatureToggles` (`tab-<id>`, `tabbar-<id>`, `mobile-tab-<id>`, `[data-nav-group]`) |
| Only `mailbox-stats` is disabled, `rate-limits` is on | The tab stays and is relabelled "Rate Limits"; the Statistics view and the view switcher are hidden | `applyFeatureToggles`, `setNavTabLabel` |
| Both `mailbox-stats` and `rate-limits` are disabled | The tab is hidden | `applyFeatureToggles` |
| `rate-limits` is disabled | The Rate Limits view button is hidden and the page falls back to Statistics | `applyFeatureToggles`, `mailboxStatsSwitchView` |
| The URL of a disabled feature is opened directly | The page is replaced by "{Label} is disabled", "This feature has been turned off by the administrator in Settings → Features." and a Go to Dashboard button; the URL stays | `switchTab` |
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
| Security, Overview | Ban, Allow, Unban and Ban permanently are removed from the address rows, and a locked area "Ban, Allow and Unban are locked" above the list says why and where to configure the key. The Ban button on a rule's catch (it shows the rule's ban length, Ban 1w or Ban 30d) needs the key too; Dismiss and Undo stay | `securityDescribe`, `renderSecurityOverview`, `uiLocked` |
| Security, Overview | Until the Fail2ban data has loaded the Banned count shows "-", Fail2ban in the Protection row shows "?", and Ban and Allow are not offered. When mailcow does not answer, a note under the filters says its bans are not shown and nothing can be banned from here | `securityDescribe`, `securityProtections`, `renderSecurityOverview` |
| Security, Settings, Outgoing spam card | Locked area "Abuse protection controls are locked" above the activity, which stays readable; all actions hidden. Without the Read-Write key it says the key is needed, with Open Settings; when the protection is off it points to the card's own switch | `renderSmtpAbusePanel`, `uiLocked` |
| Outbound, Queue | Toolbar, checkboxes and Retry/Hold/Unhold/Delete are gone, and a locked area "Queue actions are locked" says why and where to configure the key. Suppress stays | `applyQueueFilters`, `uiLocked` |
| Quarantine | Bulk and per-item Release/Delete/Learn, the details modal actions and the whole Auto-Rules section are hidden, and a locked area "Quarantine actions are locked" names them and where to configure the key. Details stays | `renderQuarantineData`, `initQuarantineRules`, `uiLocked` |
| Rspamd | Locked area "Read-Only Mode": MAILCOW_API_KEY_RW is not configured, you can view maps but cannot save changes, with Open Settings (the Save button of the map editor itself is not gated) | `renderRspamdMapsList` |
| Mailbox Stats, Rate Limits | Locked area "Editing rate limits is locked" with the Read-Write key sentence and Open Settings; Edit, Apply to filtered, the bulk panel and Reset counter are hidden | `renderRateLimitReadOnlyNotice` |

The v3 redesign replaces these with one consistent locked-area component that says what is missing and where to configure it (decided 2026-09-25): `uiLocked(title, text)` in `frontend/utils.js`, styled by `.ui-locked`, always with an Open Settings button. Pages move to it as they are redesigned; the rows above say which already use it.

### Features that are off or not configured

| Page | Condition | What the user sees | Rendered by |
|---|---|---|---|
| Dashboard | `blacklist` disabled | The blacklist card is hidden | `#dashboard-blacklist-card` |
| Dashboard | Unacknowledged security alerts | Rows in Needs attention with a severity tag, the time and Dismiss, and a Dismiss all alerts button in the panel head | `loadDashboardSecurityAlerts` |
| Dashboard | A server check needs a look | Needs attention lists mailcow not reachable, a blocklist listing, stopped containers, DMARC insights and app or mailcow updates, each with a button to where it is handled; with nothing, "Nothing needs attention right now."; a check that could not run keeps what it showed and says "Some checks could not run." with Retry | `loadDashboardAttention` |
| Every page with the top bar, and every page on a phone | Needs attention has items | The header bell counts every open item (red for a failing one or a critical alert, amber for warnings, plain for news, a grey dot when a check could not run) and opens the same rows in a window under it, a sheet on a phone; desktop Messages has no top bar and no bell | `updateAttentionBell`, `attnWindowOpen` |
| Message details | `netfilter` disabled | The Security tab of the modal is hidden | `#modal-tab-netfilter` |
| Security, Settings, Outgoing spam card | SMTP abuse protection off | The card's switch is off, and inside "Automatic protection is off." with a locked area that points to the switch When editing settings is off, the switch is disabled and a locked area "Editing settings is off" says how to turn it on | `securityCardHtml`, `renderSmtpAbusePanel` |
| Security, Settings, Countries card | No GeoIP | The switch is disabled, the card shows "Needs MaxMind GeoIP" and a locked area "Needs GeoIP"; the Overview's Protection row shows a cross with "needs MaxMind GeoIP" | `securityCardHtml`, `securityProtections` |
| Security | No GeoIP data | "No country for these addresses. Configure MaxMind to see where they come from." (also shown when MaxMind is configured but the listed addresses have no country) | `#country-chart-empty` |
| Rspamd | `RSPAMD_PASSWORD` missing | Locked area "Rspamd Not Configured" with the message and a Go to Settings button | `loadRspamdMaps` |
| DMARC | Manual upload disabled | The Upload Report button is hidden | `updateDmarcControls` |
| DMARC | IMAP sync disabled | The Fetch reports button and the last sync line are hidden | `updateDmarcControls` |
| DMARC | Report deletion disabled | Locked area "Deleting reports is off" in Manage Reports with Open Settings, and no Delete or Delete all buttons | `renderReportsDomains`, `renderReportsManagementTable` |
| DMARC | Policy insights available | No banner: a domain whose policy only monitors gets a To do item with the first recommendation as its text, and the sidebar counter and Needs attention on the Dashboard count the domains with insights | `dmarcHomeTasks`, `loadNavCounters`, `loadDashboardAttention` |
| Mailbox Stats | Domain limits unreadable | Amber strip "Domain limits could not be read from mailcow: {error}" | `renderRateLimitConfigCard` |
| Logs | Raw log collection off | Locked area "Live Log Viewer is Disabled" with the place to enable it (Settings → Logs) and Open Settings | `loadLogViewer` |
| Logs | No services enabled | Locked area "No log services available" with "Enable services in Settings → Logs." and Open Settings | `loadLogViewer` |
| Logs | WebSocket state | Green, yellow or red dot with Connected, Paused or Disconnected | `updateWsIndicator` |
| Status | `blacklist` disabled | The IP Blacklist Monitor section is hidden | `#blacklist-section` |
| Status | A job's feature is off | Job card faded with a "feature off" badge, no Run button | `renderJobCard` |
| Status | A job is disabled for another reason | The Run button is hidden and a "disabled" tag explains it (tooltip: turned off in its settings) | `renderJobCard` |
| Status | A job is running | Run button disabled, "Job is running" | `renderJobCard` |

### Settings

| Condition | What the user sees | Rendered by |
|---|---|---|
| `SETTINGS_EDIT_VIA_UI_ENABLED` is off | Read-only cards with the current values, under a locked area "Editing settings is off" that says to set `SETTINGS_EDIT_VIA_UI_ENABLED=true` in `.env` and run `docker compose up -d`; the search in the top bar shows no settings | `renderSettings`, `uiLocked`, `gsOff` |
| Editing is on | "Edit configuration" with the note "Priority: Default → DB → ENV. Environment variables always override DB values and cannot be changed from here." | `renderSettings` |
| Settings not migrated yet | Only a "Migrate Settings from ENV" button with a short explanation, no Save button; the form fields are read-only until the migration | `renderSettings` |
| A key is set by an environment variable | The field is disabled, with a lock icon and "Controlled by ENV variable - cannot be changed from here." | `renderSettingsEditField` |
| `DISABLED_FEATURES` or `RAW_LOGS_SERVICES` set by the environment | Switches disabled, "Set by ENV (DISABLED_FEATURES), change it there" or "Set by ENV (RAW_LOGS_SERVICES), change it there" | `renderSettingsEditField` |
| A Logs service another page reads (`raw_logs_required` in `/api/settings/info`) | Its row says "Always collected for <pages>"; switching it off only hides it on the Logs page | `renderSettingsEditField` |
| A value differs from its default | Amber highlight with "Reset to default" or "Clear" | `renderSettingsEditField` |
| A feature is disabled | Its Settings tab is hidden | `SETTINGS_TAB_FEATURE_MAP` |
| Saving settings | The page reloads, with "Features updated - reloading..." or "Settings saved - reloading...", only when features, the app title or logo, Basic Auth or OAuth2, or the mailcow URL changed: the rest of the app reads them once at page load. Any other save refreshes Settings in place with "Settings saved" | `renderSettings` (`SETTINGS_READ_AT_PAGE_LOAD`) |
| mailcow Read-Write API key and Rspamd password | Each: "Not checked", "Not configured", "Accepted" or a red "Rejected", "Read-only key", "Redirected", "Connection error", "Unexpected answer" whose tooltip says what to fix, and when it was last checked; checked right after a new or changed key, password or URL is saved (the message is shown again after the page reloads), and from Validate | `renderCredentialStatus`, `validateCredential` |
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
| [Click to copy](#click-to-copy) | 55 |
| [Tooltips](#tooltips) | 267 |
| [Toasts](#toasts) | 171 |
| [Confirmation dialogs](#confirmation-dialogs) | 34 |
| [Country flags](#country-flags) | 7 |
| [Markdown rendering](#markdown-rendering) | 4 |
| [Controls wired in JavaScript](#controls-wired-in-javascript) | 45 |
| [Filters, sorting and view options](#filters-sorting-and-view-options) | 10 |
| [Charts](#charts) | 1 |
| [Colour thresholds](#colour-thresholds) | 0 |
| [Help topics](#help-topics) | 17 |
| [Empty states](#empty-states) | 40 |
| [Loading states](#loading-states) | 26 |
| [Persisted preferences](#persisted-preferences) | 6 |
| [Auto refresh and timers](#auto-refresh-and-timers) | 6 |
| [Address bar and deep links](#address-bar-and-deep-links) | 2 |
| [Keyboard handling](#keyboard-handling) | 12 |
| [Badge colours](#badge-colours) | 11 |

### Click to copy

Fields that copy their value on click (hover shows a copy icon and "Click to copy").

| Page | What | Code |
|---|---|---|
| Message details | copies: `host` | `frontend/message-details.js:480` (renderRelay) |
| Message details | copies: `r.address` | `frontend/message-details.js:831` (renderRecipientRows) |
| Message details | copies: `recipients[0] \|\| '-'` | `frontend/message-details.js:892` (renderMessageHeader) |
| Message details | copies: `data.sender \|\| '-'` | `frontend/message-details.js:909` (renderMessageHeader) |
| Message details | copies: `ip` | `frontend/message-details.js:940` (buildDeliverySteps) |
| Message details | copies: `user` | `frontend/message-details.js:941` (buildDeliverySteps) |
| Message details | copies: `qid` | `frontend/message-details.js:945` (buildDeliverySteps) |
| Message details | copies: `target` | `frontend/message-details.js:949` (buildDeliverySteps) |
| Message details | copies: `rspamd.ip` | `frontend/message-details.js:1034` (renderOverviewTab) |
| Message details | copies: `rspamd.user` | `frontend/message-details.js:1036` (renderOverviewTab) |
| Message details | copies: `data.queue_id` | `frontend/message-details.js:1037` (renderOverviewTab) |
| Message details | copies: `data.message_id` | `frontend/message-details.js:1038` (renderOverviewTab) |
| Message details | copies: `Array.from(recipientsFromPostfix)[0]` | `frontend/message-details.js:1171` (renderPostfixTab) |
| Message details | copies: `data.recipients[0]` | `frontend/message-details.js:1173` (renderPostfixTab) |
| Message details | copies: `clientIp` | `frontend/message-details.js:1183` (renderPostfixTab) |
| Message details | copies: `log.ip` | `frontend/message-details.js:1309` (renderNetfilterTab) |
| Message details | copies: `log.username` | `frontend/message-details.js:1312` (renderNetfilterTab) |
| Security | copies: `log.username` | `frontend/app.js:1501` (renderNetfilterData) |
| Security | copies: `log.ip` | `frontend/app.js:1506` (renderNetfilterData) |
| Security | copies: `a.ip` | `frontend/security.js:397` (securityRow) |
| Security | copies: `a.ip` | `frontend/security.js:407` (securityRow) |
| Security | copies: `a.ip` | `frontend/security.js:425` (renderSecuritySheet) |
| Security | copies: `u` | `frontend/security.js:458` (securityDetail) |
| Security | copies: `h.ip` | `frontend/security.js:599` (securityHistoryRows) |
| Security | copies: `entry` | `frontend/security.js:806` (renderSecurityLists) |
| Outbound | copies: `r.email` | `frontend/app.js:3173` (applyQueueFilters) |
| Outbound | copies: `item.sender` | `frontend/app.js:3174` (applyQueueFilters) |
| Outbound | copies: `qid` | `frontend/app.js:3174` (applyQueueFilters) |
| Outbound | copies: `displayEmail` | `frontend/spam_filter.js:649` (renderSuppressionItem) |
| Quarantine | copies: `r.address` | `frontend/app.js:3643` (renderQuarantineDetailContent) |
| Quarantine | copies: `data.subject \|\| '-'` | `frontend/app.js:3674` (renderQuarantineDetailContent) |
| Quarantine | copies: `data.header_from \|\| '-'` | `frontend/app.js:3675` (renderQuarantineDetailContent) |
| Quarantine | copies: `data.env_from \|\| '-'` | `frontend/app.js:3676` (renderQuarantineDetailContent) |
| Status | copies: `item.message_id \|\| 'N/A'` | `frontend/app.js:5255` (renderStatusCorrelation) |
| Status | copies: `item.sender \|\| 'N/A'` | `frontend/app.js:5256` (renderStatusCorrelation) |
| Status | copies: `item.recipient \|\| 'N/A'` | `frontend/app.js:5256` (renderStatusCorrelation) |
| Domains | copies: `domain.domain_name` | `frontend/domains.js:214` (renderDomainAccordionRow) |
| Domains | copies: `entry.ip \|\| ''` | `frontend/domains.js:283` (renderSpfCheckedIps) |
| Domains | copies: `aliasDomain.domain_name` | `frontend/domains.js:306` (renderAliasDomain) |
| Domains | copies: `check.dkim_domain` | `frontend/domains.js:334` (renderDNSCheck) |
| Domains | copies: `check.record \|\| check.actual_record` | `frontend/domains.js:335` (renderDNSCheck) |
| Domains | copies: `check.expected_record` | `frontend/domains.js:357` (renderDNSCheck) |
| DMARC | copyToClipboard: `'${escapeJsArg(text)}'` | `frontend/dmarc.js:664` (dmarcCopyBlock) |
| Mailbox stats | copies: `mb.username` | `frontend/mailbox-stats.js:473` (renderMailboxStatsAccordion) |
| Mailbox stats | copies: `alias.alias_address` | `frontend/mailbox-stats.js:517` (renderMailboxStatsAccordion) |
| Mailbox stats | copies: `group.user` | `frontend/rate-limits.js:361` (renderRateLimitSendersTable) |
| Mailbox stats | copies: `group.user` | `frontend/rate-limits.js:452` (renderRateLimitSenderDetail) |
| Mailbox stats | copies: `event.rcpt` | `frontend/rate-limits.js:567` (renderRateLimitEventRow) |
| Mailbox stats | copies: `event.qid` | `frontend/rate-limits.js:569` (renderRateLimitEventRow) |
| Mailbox stats | copies: `name` | `frontend/rate-limits.js:1010` (renderRateLimitConfigRow) |
| Shared | copies: `ip` | `frontend/app.js:5528` (renderGeoIPInfo) |
| Shared | copies: `ip` | `frontend/app.js:5535` (renderGeoIPInfo) |
| Shared | copyToClipboard: `'${safeText}'` | `frontend/utils.js:647` (copyableText) |
| Devices | copies: `d.username` | `frontend/devices.js:147` (renderDeviceRow) |
| Devices | copies: `d.last_ip` | `frontend/devices.js:151` (renderDeviceRow) |

### Tooltips

Native `title` tooltips. Dynamic ones show the expression that builds the text.

| Page | What | Code |
|---|---|---|
| Shell | "Dashboard" | `frontend/index.html:400` |
| Shell | "Search" | `frontend/index.html:409` |
| Shell | "Collapse menu" | `frontend/index.html:439` |
| Shell | "Server status" | `frontend/index.html:440` |
| Shell | "mailcow connection status" | `frontend/index.html:441` |
| Shell | "Dashboard" | `frontend/index.html:452` |
| Shell | "Messages" | `frontend/index.html:456` |
| Shell | "Outbound" | `frontend/index.html:457` |
| Shell | "Quarantine" | `frontend/index.html:458` |
| Shell | "Security" | `frontend/index.html:462` |
| Shell | "Rspamd" | `frontend/index.html:463` |
| Shell | "DMARC &amp; TLS" | `frontend/index.html:464` |
| Shell | "Status" | `frontend/index.html:468` |
| Shell | "Domains" | `frontend/index.html:469` |
| Shell | "Mailbox Stats" | `frontend/index.html:470` |
| Shell | "Devices" | `frontend/index.html:471` |
| Shell | "Logs" | `frontend/index.html:472` |
| Shell | "Settings" | `frontend/index.html:475` |
| Shell | "About" | `frontend/index.html:476` |
| Shell | "mailcow update available" | `frontend/index.html:485` |
| Shell | "Switch theme" | `frontend/index.html:493` |
| Shell | "Refresh" | `frontend/index.html:505` |
| Shell | "Logout" | `frontend/index.html:510` |
| Shell | "Created with ❤️ - GitHub" | `frontend/index.html:515` |
| Shell | "View Container Logs" | `frontend/index.html:519` |
| Shell | set in JS: dynamic: `== 'Not connected to mailcow') problems.push('not connected to mailcow')` | `frontend/app.js:861` (loadNavCounters) |
| Shell | set in JS: dynamic: `problems.join(', ')` | `frontend/app.js:871` (loadNavCounters) |
| Shell | set in JS: dynamic: `problems.join(', ')` | `frontend/app.js:877` (loadNavCounters) |
| Shell | set in JS: "Connected to mailcow" | `frontend/app.js:903` (loadMailcowConnectionStatus) |
| Shell | set in JS: "Not connected to mailcow" | `frontend/app.js:912` (loadMailcowConnectionStatus) |
| Shell | set in JS: "Connection status unknown" | `frontend/app.js:927` (loadMailcowConnectionStatus) |
| Shell | set in JS: dynamic: ``Update available: v${data.latest_version}`` | `frontend/app.js:947` (loadAppVersionStatus) |
| Shell | set in JS: dynamic: ``Update available: ${data.latest_version}`` | `frontend/app.js:1057` (loadMailcowVersionStatus) |
| Shell | set in JS: dynamic: ``Update available: ${data.latest_version}`` | `frontend/app.js:1064` (loadMailcowVersionStatus) |
| Shell | set in JS: dynamic: `label` | `frontend/app.js:5987` (syncNavToggle) |
| Dashboard | "What happened before and around this alert" | `frontend/app.js:2045` (loadDashboardSecurityAlerts) |
| Dashboard | "Dismiss" | `frontend/app.js:2046` (loadDashboardSecurityAlerts) |
| Dashboard | dynamic: `${escapeHtml(mailFlowSpan(b.s, b.e))}: ${Number(b.messages).toLocaleString()}...` | `frontend/app.js:2533` (renderMailFlowChart) |
| Dashboard | "Logs older than the retention days are cleaned up" | `frontend/app.js:2537` (renderMailFlowChart) |
| Dashboard | "Dismiss" | `frontend/index.html:582` |
| Dashboard | "Help - Dashboard" | `frontend/index.html:588` |
| Dashboard | "Each message counts once, as on the Messages page; a message to three recipients is one message and three d..." | `frontend/index.html:615` |
| Dashboard | set in JS: dynamic: `text` | `frontend/app.js:2590` (renderMailFlowStats) |
| Dashboard | set in JS: dynamic: `lines.filter(Boolean).join(', ')` | `frontend/app.js:2610` (renderMailFlowStats) |
| Messages | dynamic: `${escapeHtml(formatTime(msg.first_seen))}` | `frontend/app.js:1222` (renderMessageRow) |
| Messages | dynamic: `${escapeHtml(msg.subject \|\| 'No subject')}` | `frontend/app.js:1224` (renderMessageRow) |
| Messages | dynamic: `${escapeHtml(msg.recipient \|\| '')}` | `frontend/app.js:1229` (renderMessageRow) |
| Messages | "Help - Messages" | `frontend/index.html:658` |
| Messages | "Filter by sender, recipient, user or IP" | `frontend/index.html:700` |
| Messages | set in JS: dynamic: `said` | `frontend/app.js:1335` (renderMessagesSort) |
| Message details | "Show every recipient" | `frontend/message-details.js:354` (renderLogTimeline) |
| Message details | "This delivery attempt never reached a final outcome" | `frontend/message-details.js:424` (renderRelatedDeliveries) |
| Message details | "Click to copy" | `frontend/message-details.js:480` (renderRelay) |
| Message details | dynamic: `Show the logs of ${escapeHtml(r.address)}` | `frontend/message-details.js:830` (renderRecipientRows) |
| Message details | "Open Spam Analysis" | `frontend/message-details.js:899` (renderMessageHeader) |
| Message details | dynamic: `${escapeHtml(hasSubject ? data.subject : 'No subject')}` | `frontend/message-details.js:907` (renderMessageHeader) |
| Message details | "Security events" | `frontend/message-details.js:1329` (updateSecurityTabIndicator) |
| Message details | set in JS: dynamic: `== step.title) { prev.count = (prev.count \|\| 1) + 1` | `frontend/message-details.js:994` (buildDeliverySteps) |
| Security | dynamic: `${escapeHtml(formatTime(log.time))}` | `frontend/app.js:1505` (renderNetfilterData) |
| Security | dynamic: `${escapeHtml(place + org)}` | `frontend/app.js:1509` (renderNetfilterData) |
| Security | dynamic: `Unban ${escapeHtml(log.ip)}` | `frontend/app.js:1511` (renderNetfilterData) |
| Security | dynamic: `Put ${escapeHtml(fail2banEntry(log.ip))} on the denylist; it stays until removed` | `frontend/app.js:1512` (renderNetfilterData) |
| Security | "Show the log line" | `frontend/app.js:1513` (renderNetfilterData) |
| Security | "Help - Security" | `frontend/index.html:785` |
| Security | "Addresses that are not banned" | `frontend/index.html:794` |
| Security | "Filters" | `frontend/index.html:822` |
| Security | dynamic: `${escapeHtml(`${name}: ${label}${note ? `, ${note}` : ''}`)}` | `frontend/security.js:246` (securityProtectionButton) |
| Security | "Lift the ban; the rule leaves it alone for a week" | `frontend/security.js:290` (securityDescribe) |
| Security | "Not an attack: the rule leaves it alone for a week" | `frontend/security.js:291` (securityDescribe) |
| Security | dynamic: `Remove ${escapeHtml(a.listedAs)} from the allowlist` | `frontend/security.js:298` (securityDescribe) |
| Security | dynamic: `Remove ${escapeHtml(a.listedAs)} from the denylist` | `frontend/security.js:305` (securityDescribe) |
| Security | dynamic: `Unban ${escapeHtml(a.ip)}` | `frontend/security.js:324` (securityDescribe) |
| Security | dynamic: `Unban ${escapeHtml(a.bannedThrough)}` | `frontend/security.js:332` (securityDescribe) |
| Security | "Put it on the denylist" | `frontend/security.js:333` (securityDescribe) |
| Security | dynamic: `Unban ${escapeHtml(fail2banBare(a.f2b.network \|\| a.ip))}` | `frontend/security.js:341` (securityDescribe) |
| Security | "Put it on the denylist" | `frontend/security.js:342` (securityDescribe) |
| Security | dynamic: `${escapeHtml(length.title)}` | `frontend/security.js:365` (securityDescribe) |
| Security | dynamic: `Put ${escapeHtml(fail2banEntry(a.ip))} on the denylist; it stays until removed` | `frontend/security.js:372` (securityDescribe) |
| Security | dynamic: `Never ban ${escapeHtml(fail2banEntry(a.ip))}` | `frontend/security.js:373` (securityDescribe) |
| Security | dynamic: `Attempts ${securityWindowText()}` | `frontend/security.js:380` (securityAttempts) |
| Security | dynamic: `${escapeHtml(country)}` | `frontend/security.js:385` (securityPlaceFlag) |
| Security | dynamic: `${escapeHtml(formatTime(h.last_seen))}` | `frontend/security.js:439` (securityDetail) |
| Security | dynamic: `${escapeHtml([a.city, a.country].filter(Boolean).join(', '))}` | `frontend/security.js:454` (securityDetail) |
| Security | dynamic: `${escapeHtml(`${n.asn_org}: ${n.attempts.toLocaleString()} attempts from ${n....` | `frontend/security.js:588` (securityNetworkRows) |
| Security | "The oldest log line kept" | `frontend/security.js:657` (renderSecurityOverview) |
| Security | "Show every country" | `frontend/security.js:666` (renderSecurityOverview) |
| Security | "Show every network" | `frontend/security.js:667` (renderSecurityOverview) |
| Security | dynamic: `${Number(n).toLocaleString()} ${label}` | `frontend/security.js:728` (securityCountryBars) |
| Security | dynamic: `${escapeHtml(`${r.country_name}: ${r.attempts.toLocaleString()} attempts from...` | `frontend/security.js:731` (securityCountryBars) |
| Security | "Watched by the Countries rule" | `frontend/security.js:732` (securityCountryBars) |
| Security | dynamic: `Replace it with ${escapeHtml(old.address)}/128` | `frontend/security.js:813` (renderSecurityLists) |
| Security | "Lift the ban; the rule leaves it alone for a week" | `frontend/security.js:829` (renderSecurityLists) |
| Security | "Note what it catches; ban nothing" | `frontend/security.js:1216` (securityCardBody) |
| Security | dynamic: `${caps.can_ban ? 'Put what it catches on the Fail2ban denylist' : 'Banning ne...` | `frontend/security.js:1217` (securityCardBody) |
| Security | "Remove" | `frontend/security.js:1227` (securityCardBody) |
| Security | dynamic: `${escapeHtml(String(s.tries))} tries from ${escapeHtml(String(s.addresses))} ...` | `frontend/security.js:1233` (securityCardBody) |
| Security | "Remove" | `frontend/security.js:1239` (securityCardBody) |
| Security | dynamic: `${escapeHtml(String(s.tries))} failed logins` | `frontend/security.js:1248` (securityCardBody) |
| Security | "This feature is new - please report any issues on GitHub" | `frontend/security.js:1280` (securityCardHtml) |
| Security | "Help - Outgoing spam" | `frontend/security.js:1281` (securityCardHtml) |
| Security | dynamic: `${escapeHtml(disabled ? why : on ? `Turn ${name} off` : `Turn ${name} on`)}` | `frontend/security.js:1301` (securityToggle) |
| Outbound | "Retry delivery of every message in the queue" | `frontend/app.js:3144` (applyQueueFilters) |
| Outbound | dynamic: `Suppress ${escapeHtml(recipients[0].email)}` | `frontend/app.js:3167` (applyQueueFilters) |
| Outbound | dynamic: `${escapeHtml(formatTime(queued))}` | `frontend/app.js:3174` (applyQueueFilters) |
| Outbound | "Retry delivery" | `frontend/app.js:3183` (applyQueueFilters) |
| Outbound | "Release from hold" | `frontend/app.js:3185` (applyQueueFilters) |
| Outbound | "Hold message" | `frontend/app.js:3186` (applyQueueFilters) |
| Outbound | "Delete from queue" | `frontend/app.js:3187` (applyQueueFilters) |
| Outbound | "Help - Outbound" | `frontend/index.html:865` |
| Outbound | "Filters" | `frontend/index.html:886` |
| Outbound | "More" | `frontend/index.html:914` |
| Outbound | "Synced to Rspamd" | `frontend/spam_filter.js:633` (renderSuppressionItem) |
| Outbound | dynamic: `${suppressionSyncLocked() ? 'Not synced: syncing to Rspamd needs the Read-Wri...` | `frontend/spam_filter.js:634` (renderSuppressionItem) |
| Outbound | "Waiting to be removed from Rspamd" | `frontend/spam_filter.js:637` (renderSuppressionItem) |
| Outbound | dynamic: `${escapeHtml(s.email)}` | `frontend/spam_filter.js:650` (renderSuppressionItem) |
| Outbound | dynamic: `${escapeHtml(s.notes)}` | `frontend/spam_filter.js:653` (renderSuppressionItem) |
| Outbound | dynamic: `${escapeHtml(formatTime(s.created_at))}` | `frontend/spam_filter.js:659` (renderSuppressionItem) |
| Outbound | "Edit suppression" | `frontend/spam_filter.js:662` (renderSuppressionItem) |
| Outbound | dynamic: `${s.active ? 'Deactivate' : 'Reactivate'}` | `frontend/spam_filter.js:663` (renderSuppressionItem) |
| Outbound | "Delete permanently" | `frontend/spam_filter.js:664` (renderSuppressionItem) |
| Outbound | dynamic: `${escapeHtml(tip)}` | `frontend/spam_filter.js:718` (suppressionSourceTag) |
| Outbound | "Recorded" | `frontend/spam_filter.js:743` (blockEventHtml) |
| Outbound | set in JS: dynamic: `[name, sub && sub !== name ? sub : '', appTitleText].filter(Boolean).join(' · ')` | `frontend/app.js:561` (queueDocumentTitle) |
| Quarantine | "View details" | `frontend/app.js:3429` (renderQuarantineData) |
| Quarantine | dynamic: `${escapeHtml(formatTime(item.created))}` | `frontend/app.js:3435` (renderQuarantineData) |
| Quarantine | "Release message" | `frontend/app.js:3438` (renderQuarantineData) |
| Quarantine | "Release and train as not spam" | `frontend/app.js:3439` (renderQuarantineData) |
| Quarantine | "Delete and train as spam" | `frontend/app.js:3440` (renderQuarantineData) |
| Quarantine | "Create an auto-rule from this message" | `frontend/app.js:3441` (renderQuarantineData) |
| Quarantine | "Delete message" | `frontend/app.js:3442` (renderQuarantineData) |
| Quarantine | "View details" | `frontend/app.js:3443` (renderQuarantineData) |
| Quarantine | "Close" | `frontend/app.js:3600` (showQuarantineDetails) |
| Quarantine | dynamic: `${escapeHtml(opts)}` | `frontend/app.js:3657` (renderQuarantineDetailContent) |
| Quarantine | "Delete & train as Spam" | `frontend/app.js:3710` (renderQuarantineDetailContent) |
| Quarantine | "Release & train as Not Spam" | `frontend/app.js:3711` (renderQuarantineDetailContent) |
| Quarantine | dynamic: `${escapeHtml(`Look for` | `frontend/app.js:3832` (loadQuarantineRules) |
| Quarantine | dynamic: `${rule.enabled ? 'Click to disable this rule' : 'Click to enable this rule'}` | `frontend/app.js:3833` (loadQuarantineRules) |
| Quarantine | "Edit" | `frontend/app.js:3835` (loadQuarantineRules) |
| Quarantine | "Delete" | `frontend/app.js:3836` (loadQuarantineRules) |
| Quarantine | "Close" | `frontend/app.js:3923` (_showQuarantineRuleModal) |
| Quarantine | dynamic: `${escapeHtml(m.subject \|\| '')}` | `frontend/app.js:4132` (testQuarantineRules) |
| Quarantine | "Close" | `frontend/app.js:4158` (testQuarantineRules) |
| Quarantine | dynamic: `${escapeHtml(log.sender \|\| '')} → ${escapeHtml(log.recipient \|\| '')}` | `frontend/app.js:4213` (loadQuarantineRuleHistory) |
| Quarantine | dynamic: `Rule: ${escapeHtml(log.rule_name \|\| '')}` | `frontend/app.js:4214` (loadQuarantineRuleHistory) |
| Quarantine | "Help - Quarantine" | `frontend/index.html:960` |
| Rspamd | "Help - Rspamd" | `frontend/index.html:1030` |
| Rspamd | dynamic: `${escapeHtml(displayDesc)}` | `frontend/spam_filter.js:123` (renderRspamdMapsList) |
| Rspamd | "Close" | `frontend/spam_filter.js:191` (openMapEditor) |
| Status | "Click to view changelog" | `frontend/about.js:134` (aboutVersionPanel) |
| Status | dynamic: `Stop counting and alerting on ${escapeHtml(c.name)}` | `frontend/app.js:4630` (renderStatusAttention) |
| Status | dynamic: `Keep checking ${escapeHtml(r.name)} but never count or alert on it` | `frontend/app.js:4637` (renderStatusAttention) |
| Status | dynamic: `Stop counting and alerting on ${escapeHtml(c.name)}` | `frontend/app.js:4772` (loadStatusContainers) |
| Status | dynamic: `${escapeHtml(c.ignored ? 'Ignored: shown here but never counted or alerted' :...` | `frontend/app.js:4775` (loadStatusContainers) |
| Status | dynamic: `Look up on ${escapeHtml(r.name)}` | `frontend/app.js:5138` (renderBlacklistStatus) |
| Status | dynamic: `${r.ignored ? 'Count and alert on this list again' : 'Keep checking this list...` | `frontend/app.js:5141` (renderBlacklistStatus) |
| Status | dynamic: `${host.checked_at ? escapeHtml(formatTime(host.checked_at)) : ''}` | `frontend/app.js:5164` (renderBlacklistStatus) |
| Status | "Run Check for this Host" | `frontend/app.js:5165` (renderBlacklistStatus) |
| Status | dynamic: `${escapeHtml(detail(r))}` | `frontend/app.js:5180` (renderBlacklistStatus) |
| Status | dynamic: `${d.last_fetch_run ? escapeHtml(formatTime(d.last_fetch_run)) : ''}` | `frontend/app.js:5221` (renderStatusImport) |
| Status | dynamic: `${d.last_import ? escapeHtml(formatTime(d.last_import)) : ''}` | `frontend/app.js:5222` (renderStatusImport) |
| Status | dynamic: `${escapeHtml(formatTime(correlation.last_update))}` | `frontend/app.js:5245` (renderStatusCorrelation) |
| Status | "Help - Status" | `frontend/index.html:1049` |
| Status | "Help - IP Blacklist Monitor" | `frontend/index.html:1094` |
| Domains | dynamic: `${escapeHtml(`${label}: ${check.message \|\| 'Not checked'}`)}` | `frontend/domains.js:178` (dnsStatusTag) |
| Domains | dynamic: `${dns.checked_at ? escapeHtml(formatTime(dns.checked_at)) : ''}` | `frontend/domains.js:187` (renderDomainDnsSection) |
| Domains | "Check DNS for this domain" | `frontend/domains.js:190` (renderDomainDnsSection) |
| Domains | dynamic: `${escapeHtml(text)}` | `frontend/domains.js:318` (getAliasStatusIcon) |
| Domains | "Help - Domains Information" | `frontend/index.html:1124` |
| DMARC | "This domain is not on this server." | `frontend/dmarc.js:44` (dmarcNotOnServer) |
| DMARC | dynamic: `${escapeHtml(words + maybe)}` | `frontend/dmarc.js:316` (dmarcCalendarCard) |
| DMARC | dynamic: `${escapeHtml(formatTime(sync.started_at))}` | `frontend/dmarc.js:1061` (updateDmarcControls) |
| DMARC | "Delete all reports of this domain" | `frontend/dmarc.js:1263` (renderReportsDomains) |
| DMARC | "Delete report" | `frontend/dmarc.js:1402` (renderReportsManagementTable) |
| DMARC | "Help - DMARC Information" | `frontend/index.html:1148` |
| DMARC | "Upload Report" | `frontend/index.html:1158` |
| DMARC | set in JS: "Fetching reports needs IMAP set up in Settings" | `frontend/dmarc.js:1045` (updateDmarcControls) |
| DMARC | set in JS: "" | `frontend/dmarc.js:1053` (updateDmarcControls) |
| Mailbox stats | "Help - Mailbox Statistics" | `frontend/index.html:1188` |
| Mailbox stats | "Filters" | `frontend/index.html:1219` |
| Mailbox stats | "Open these messages" | `frontend/mailbox-stats.js:333` (mailboxStatLink) |
| Mailbox stats | dynamic: `${escapeHtml(tip)}` | `frontend/mailbox-stats.js:375` (mailboxServices) |
| Mailbox stats | dynamic: `${escapeHtml(label)}` | `frontend/mailbox-stats.js:388` (mailboxSparkline) |
| Mailbox stats | dynamic: `${escapeHtml(tip)}` | `frontend/mailbox-stats.js:428` (openMailboxActivity) |
| Mailbox stats | "When this app first read the mailbox from mailcow" | `frontend/mailbox-stats.js:490` (renderMailboxStatsAccordion) |
| Mailbox stats | "When this app last read the mailbox from mailcow" | `frontend/mailbox-stats.js:490` (renderMailboxStatsAccordion) |
| Mailbox stats | "Address on a mailcow alias domain that points at this mailbox" | `frontend/mailbox-stats.js:519` (renderMailboxStatsAccordion) |
| Mailbox stats | "Resetting a counter needs the Read-Write API key (MAILCOW_API_KEY_RW)" | `frontend/rate-limits.js:152` |
| Mailbox stats | dynamic: `${escapeHtml(formatTime(group.last_seen))}` | `frontend/rate-limits.js:363` (renderRateLimitSendersTable) |
| Mailbox stats | set in JS: dynamic: `isRateLimits ? 'Help - Rate Limits' : 'Help - Mailbox Statistics'` | `frontend/mailbox-stats.js:97` (mailboxStatsSwitchView) |
| Logs | "Help - Logs" | `frontend/index.html:1322` |
| Logs | "Pause/Resume live updates" | `frontend/index.html:1346` |
| Logs | "Live mode - show latest logs" | `frontend/index.html:1350` |
| Logs | "Auto-scroll to new entries" | `frontend/index.html:1353` |
| Logs | "Toggle sort order (newest at bottom / newest at top)" | `frontend/index.html:1356` |
| Logs | "Toggle word wrap" | `frontend/index.html:1367` |
| Logs | "Clear display" | `frontend/index.html:1370` |
| Logs | "Search" | `frontend/index.html:1377` |
| Logs | "Clear search" | `frontend/index.html:1378` |
| Logs | "From date" | `frontend/index.html:1394` |
| Logs | "To date" | `frontend/index.html:1396` |
| Logs | "Go to the newest line and turn auto-scroll on" | `frontend/index.html:1418` |
| Logs | dynamic: `${escapeHtml(f.description \|\| '')}` | `frontend/logs-viewer.js:212` (loadSmartFilters) |
| Logs | "Clear all filters" | `frontend/logs-viewer.js:1268` (updateFilterBadge) |
| Settings | "Help - Settings" | `frontend/index.html:1459` |
| Settings | "Last delivery succeeded" | `frontend/notifications.js:67` (renderNotificationChannels) |
| Settings | "Last delivery failed" | `frontend/notifications.js:69` (renderNotificationChannels) |
| Settings | "Not used yet" | `frontend/notifications.js:70` (renderNotificationChannels) |
| Settings | dynamic: `${escapeHtml(ch.last_error)}` | `frontend/notifications.js:78` (renderNotificationChannels) |
| Settings | "Close" | `frontend/notifications.js:152` (renderNotificationChannelModal) |
| Settings | "Set by an environment variable, change it there" | `frontend/settings.js:451` (settingsBounceChoice) |
| Settings | "Differs from the default" | `frontend/settings.js:452` (settingsBounceChoice) |
| Settings | "Set by an environment variable, change it there" | `frontend/settings.js:1193` (renderSettingsEditField) |
| Settings | "Differs from the default" | `frontend/settings.js:1240` (renderSettingsEditField) |
| Settings | "Differs from the default" | `frontend/settings.js:1275` (renderSettingsEditField) |
| Settings | dynamic: `${escapeHtml(known[1])}` | `frontend/settings.js:2565` (renderCredentialStatus) |
| Settings | dynamic: `${escapeHtml(CREDENTIAL_CHECKS[name].missing)}` | `frontend/settings.js:2576` (credentialValidateButton) |
| Settings | "Add a MaxMind Account ID and License Key first" | `frontend/settings.js:2649` (maxmindValidateButton) |
| Settings | "Close" | `frontend/settings.js:2746` (showConnectionTestModal) |
| Shared | dynamic: `${escapeHtml(title)}` | `frontend/utils.js:164` (uiCorrelationTag) |
| Shared | "Close" | `frontend/utils.js:678` (showToast) |
| Shared | "The feature this job belongs to is turned off in Settings" | `frontend/utils.js:979` (renderJobCard) |
| Shared | dynamic: `${escapeHtml(job.disabled_reason \|\| 'This job is turned off in its settings...` | `frontend/utils.js:982` (renderJobCard) |
| Shared | dynamic: `${escapeHtml(job.description)}` | `frontend/utils.js:1016` (renderJobCard) |
| Shared | dynamic: `${job.last_run ? escapeHtml(formatTime(job.last_run)) : ''}` | `frontend/utils.js:1018` (renderJobCard) |
| Shared | dynamic: `${isRunning ? 'Job is running' : 'Run this job now'}` | `frontend/utils.js:1022` (renderJobCard) |
| Shared | dynamic: `${escapeHtml(job.disabled_reason \|\| '')}` | `frontend/utils.js:1025` (renderJobCard) |
| Shared | "Close" | `frontend/utils.js:1671` (uiSheetShow) |
| Shared | dynamic: `${escapeHtml(label)}` | `frontend/utils.js:2548` (uiPicker) |
| Shared | set in JS: dynamic: `formatTime(iso)` | `frontend/utils.js:435` (uiAgo) |
| Shared | set in JS: dynamic: `said` | `frontend/utils.js:1476` (uiSortControlSync) |
| Shared | set in JS: "Copy line" | `frontend/utils.js:1580` |
| Shared | set in JS: dynamic: `name` | `frontend/utils.js:1869` (uiFilterBarSync) |
| app.js (mixed) | dynamic: `${escapeHtml(tip)}` | `frontend/alert-activity.js:171` (alertActivityChart) |
| app.js (mixed) | "Earlier" | `frontend/alert-activity.js:182` (alertActivityChart) |
| app.js (mixed) | "Zoom out" | `frontend/alert-activity.js:183` (alertActivityChart) |
| app.js (mixed) | "Zoom in (or pinch, drag across columns, Ctrl+wheel)" | `frontend/alert-activity.js:184` (alertActivityChart) |
| app.js (mixed) | "Later" | `frontend/alert-activity.js:185` (alertActivityChart) |
| app.js (mixed) | "Reset zoom" | `frontend/alert-activity.js:186` (alertActivityChart) |
| app.js (mixed) | dynamic: `${escapeHtml(r.name)}` | `frontend/alert-activity.js:275` (alertActivityList) |
| app.js (mixed) | "Earlier" | `frontend/app.js:2484` (mailFlowFoot) |
| app.js (mixed) | "Zoom out" | `frontend/app.js:2485` (mailFlowFoot) |
| app.js (mixed) | "Zoom in (or pinch, drag across bars, Ctrl+wheel)" | `frontend/app.js:2486` (mailFlowFoot) |
| app.js (mixed) | "Later" | `frontend/app.js:2487` (mailFlowFoot) |
| app.js (mixed) | "Reset zoom" | `frontend/app.js:2488` (mailFlowFoot) |
| app.js (mixed) | dynamic: `Look up on ${escapeHtml(r.name)}` | `frontend/app.js:4617` (blocklistLookupLink) |
| app.js (mixed) | set in JS: dynamic: `label` | `frontend/app.js:382` (setNavTabLabel) |
| app.js (mixed) | set in JS: dynamic: `title \|\| ''` | `frontend/app.js:818` (setNavCount) |
| about | "Help - About" | `frontend/index.html:1445` |
| Devices | dynamic: `SOGo answered HTTP ${Number(status)}` | `frontend/devices.js:122` (deviceStatusTag) |
| Devices | dynamic: `${escapeHtml(network)}` | `frontend/devices.js:131` (deviceLocation) |
| Devices | dynamic: `${escapeHtml(`Device ID ${d.device_id}${d.model ? ` (reported as ${d.device_t...` | `frontend/devices.js:149` (renderDeviceRow) |
| Devices | dynamic: `${escapeHtml(DEVICE_CLIENT_NOTE[client] \|\| 'Recognised from how the app nam...` | `frontend/devices.js:149` (renderDeviceRow) |
| Devices | dynamic: `${escapeHtml(formatTime(d.first_seen))}` | `frontend/devices.js:153` (renderDeviceRow) |
| Devices | dynamic: `${escapeHtml(formatTime(d.last_seen))}` | `frontend/devices.js:154` (renderDeviceRow) |
| Devices | "Help - Devices" | `frontend/index.html:1282` |
| Devices | set in JS: dynamic: `data.last_run ? formatTime(data.last_run) : ''` | `frontend/devices.js:68` (renderDevicesSummary) |
| Modal: alert-activity-modal | dynamic: `${escapeHtml(s.name)}` | `frontend/alert-activity.js:340` (renderAlertActivity) |
| Modal: alert-activity-modal | "Close" | `frontend/index.html:1610` |
| Modal: alert-activity-modal | "Dismiss the alert" | `frontend/index.html:1615` |
| Modal: changelog-modal | "Close" | `frontend/index.html:1513` |
| Modal: container-logs-modal | "Refresh" | `frontend/index.html:1546` |
| Modal: container-logs-modal | "Close" | `frontend/index.html:1554` |
| Modal: dmarc-record-modal | "Close" | `frontend/index.html:1660` |
| Modal: dmarc-reports-management-modal | "Close" | `frontend/index.html:1635` |
| Modal: dmarc-sync-history-modal | "Close" | `frontend/index.html:1596` |
| Modal: mailbox-activity-modal | "Close" | `frontend/index.html:1625` |
| Modal: message-modal | "Close" | `frontend/index.html:1482` |

### Toasts

Transient notifications from `showToast(message, type)` (utils.js). Type defaults to info.

| Page | What | Code |
|---|---|---|
| Dashboard | dynamic: `back ? `${back} in Needs attention` : 'Nothing to undo: dismissed again since'` [back ? 'success' ...] | `frontend/app.js:2731` (undoAlertDismissal) |
| Dashboard | dynamic: ``Could not undo: ${e.message \|\| 'no answer'}.`` [error] | `frontend/app.js:2733` (undoAlertDismissal) |
| Messages | "Please select both start and end dates" [warning] | `frontend/app.js:4371` (applyMessagesCustomDateRange) |
| Messages | "Start date must be before end date" [warning] | `frontend/app.js:4381` (applyMessagesCustomDateRange) |
| Security | dynamic: `lifted.map(fail2banBare).join(', ') + ' unbanned successfully'` [success] | `frontend/app.js:1562` (unbanIP) |
| Security | dynamic: `'Failed to unban: ' + (result.msg \|\| result.detail \|\| 'Unknown error')` [error] | `frontend/app.js:1571` (unbanIP) |
| Security | dynamic: `'Failed to unban IP: ' + err.message` [error] | `frontend/app.js:1578` (unbanIP) |
| Security | dynamic: `result.already ? result.msg : `IP ${ip} added to the denylist`` [success] | `frontend/app.js:1605` (banIP) |
| Security | dynamic: `'Failed to ban: ' + (result.msg \|\| result.detail \|\| 'Unknown error')` [error] | `frontend/app.js:1613` (banIP) |
| Security | dynamic: `'Failed to ban IP: ' + err.message` [error] | `frontend/app.js:1620` (banIP) |
| Security | "Already dismissed" [info] | `frontend/app.js:2675` (acknowledgeSecurityAlert) |
| Security | dynamic: ``Could not dismiss the alert: ${e.message \|\| 'no answer'}. Try again.`` [error] | `frontend/app.js:2678` (acknowledgeSecurityAlert) |
| Security | "Already dismissed" [info] | `frontend/app.js:2692` (acknowledgeAllSecurityAlerts) |
| Security | dynamic: ``Could not dismiss the alerts: ${e.message \|\| 'no answer'}. Try again.`` [error] | `frontend/app.js:2696` (acknowledgeAllSecurityAlerts) |
| Security | dynamic: ``Could not load the history: ${error.message}`` [error] | `frontend/security.js:114` (loadSecurityHistory) |
| Security | dynamic: ``${entry} removed from the ${label}`` [success] | `frontend/security.js:872` (securityRemoveFromList) |
| Security | dynamic: ``Could not remove ${entry}: ${error.message}`` [error] | `frontend/security.js:876` (securityRemoveFromList) |
| Security | dynamic: ``${entry} replaced with ${single} on the ${label}`` [success] | `frontend/security.js:899` (securityRepairListEntry) |
| Security | dynamic: ``Could not repair ${entry}: ${error.message}`` [error] | `frontend/security.js:901` (securityRepairListEntry) |
| Security | dynamic: ``Saved ${list}`` [success] | `frontend/security.js:1066` (saveSecuritySettings) |
| Security | dynamic: ``Failed to save the Fail2ban settings: ${error.message}`` [error] | `frontend/security.js:1084` (saveSecurityF2b) |
| Security | dynamic: ``Could not save the outgoing spam settings: ${error.message}`` [error] | `frontend/security.js:1102` (saveSecurityAbuse) |
| Security | dynamic: `detail.detail \|\| `Could not ${action} SMTP`` [error] | `frontend/smtp-abuse.js:174` (smtpAbuseAction) |
| Security | dynamic: `action === 'block' ? 'SMTP disabled' : 'SMTP re-enabled'` [success] | `frontend/smtp-abuse.js:177` (smtpAbuseAction) |
| Security | dynamic: ``Could not ${action} SMTP`` [error] | `frontend/smtp-abuse.js:180` (smtpAbuseAction) |
| Security | dynamic: `detail.detail \|\| 'Could not save whitelist'` [error] | `frontend/smtp-abuse.js:209` (saveSmtpAbuseWhitelist) |
| Security | "Whitelist saved" [success] | `frontend/smtp-abuse.js:213` (saveSmtpAbuseWhitelist) |
| Security | "Could not save whitelist" [error] | `frontend/smtp-abuse.js:217` (saveSmtpAbuseWhitelist) |
| Security | "Could not remove whitelist entry" [error] | `frontend/smtp-abuse.js:226` (removeSmtpAbuseWhitelist) |
| Security | "Whitelist entry removed" [success] | `frontend/smtp-abuse.js:227` (removeSmtpAbuseWhitelist) |
| Security | "Could not remove whitelist entry" [error] | `frontend/smtp-abuse.js:230` (removeSmtpAbuseWhitelist) |
| Outbound | dynamic: `result.msg \|\| `${labels[action] \|\| action} completed`` [success] | `frontend/app.js:3294` (queueAction) |
| Outbound | dynamic: ``Queue action failed: ` + (result.msg \|\| result.detail \|\| 'Unknown error')` [error] | `frontend/app.js:3298` (queueAction) |
| Outbound | dynamic: ``Queue action failed: ` + err.message` [error] | `frontend/app.js:3301` (queueAction) |
| Outbound | dynamic: `result.msg \|\| 'Message deleted from queue'` [success] | `frontend/app.js:3321` (queueDeleteRequest) |
| Outbound | dynamic: `'Failed to delete from queue: ' + (result.msg \|\| result.detail \|\| 'Unknow...` [error] | `frontend/app.js:3325` (queueDeleteRequest) |
| Outbound | dynamic: `'Failed to delete from queue: ' + err.message` [error] | `frontend/app.js:3328` (queueDeleteRequest) |
| Outbound | dynamic: `type === 'domain' ? 'Domain name is required' : 'Email address is required'` [error] | `frontend/spam_filter.js:902` (createSuppression) |
| Outbound | "Enter a plain domain name, for example example.com" [error] | `frontend/spam_filter.js:914` (createSuppression) |
| Outbound | "This address is already suppressed" [error] | `frontend/spam_filter.js:941` (createSuppression) |
| Outbound | dynamic: ``Suppression added: ${email}`` [success] | `frontend/spam_filter.js:947` (createSuppression) |
| Outbound | dynamic: `error.message` [error] | `frontend/spam_filter.js:955` (createSuppression) |
| Outbound | "Please set an expiry date" [error] | `frontend/spam_filter.js:1041` (saveEditSuppression) |
| Outbound | "Suppression updated" [success] | `frontend/spam_filter.js:1059` (saveEditSuppression) |
| Outbound | dynamic: `error.message` [error] | `frontend/spam_filter.js:1065` (saveEditSuppression) |
| Outbound | dynamic: ``Suppression ${newActive ? 'activated' : 'deactivated'}`` [success] | `frontend/spam_filter.js:1079` (toggleSuppression) |
| Outbound | dynamic: `error.message` [error] | `frontend/spam_filter.js:1085` (toggleSuppression) |
| Outbound | dynamic: ``Suppression deleted: ${email}`` [success] | `frontend/spam_filter.js:1096` (deleteSuppression) |
| Outbound | dynamic: `error.message` [error] | `frontend/spam_filter.js:1102` (deleteSuppression) |
| Outbound | dynamic: `text` [info] | `frontend/spam_filter.js:1126` (autoSyncToRspamd) |
| Outbound | dynamic: ``Imported ${result.imported} suppressions (${result.skipped} skipped)`` [success] | `frontend/spam_filter.js:1162` (importSuppressions) |
| Outbound | dynamic: `'Import failed: ' + error.message` [error] | `frontend/spam_filter.js:1168` (importSuppressions) |
| Quarantine | dynamic: `result.msg \|\| `Message(s) ${actionLabels[action] \|\| action} successfully`` [success] | `frontend/app.js:3571` (quarantineAction) |
| Quarantine | dynamic: ``Failed to ${action} message(s): ` + (result.msg \|\| result.detail \|\| 'Unk...` [error] | `frontend/app.js:3575` (quarantineAction) |
| Quarantine | dynamic: ``Failed to ${action} message(s): ` + err.message` [error] | `frontend/app.js:3578` (quarantineAction) |
| Quarantine | "Rule not found" [error] | `frontend/app.js:3852` (showEditQuarantineRuleModal) |
| Quarantine | "Rule name is required" [error] | `frontend/app.js:4022` (saveQuarantineRule) |
| Quarantine | "Match value is required" [error] | `frontend/app.js:4023` (saveQuarantineRule) |
| Quarantine | dynamic: `doneMessage \|\| (isEdit ? 'Rule updated' : 'Rule created')` [success] | `frontend/app.js:4059` (_submitQuarantineRule) |
| Quarantine | dynamic: `'Failed to save rule: ' + err.message` [error] | `frontend/app.js:4062` (_submitQuarantineRule) |
| Quarantine | "Rule not found" [error] | `frontend/app.js:4069` (repairQuarantineRule) |
| Quarantine | "Rule deleted" [success] | `frontend/app.js:4083` (deleteQuarantineRule) |
| Quarantine | dynamic: `'Failed to delete rule: ' + err.message` [error] | `frontend/app.js:4086` (deleteQuarantineRule) |
| Quarantine | dynamic: ``Rule ${rule.enabled ? 'enabled' : 'disabled'}`` [success] | `frontend/app.js:4096` (toggleQuarantineRule) |
| Quarantine | dynamic: `'Failed to toggle rule: ' + err.message` [error] | `frontend/app.js:4099` (toggleQuarantineRule) |
| Quarantine | "Testing rules against quarantine..." [info] | `frontend/app.js:4106` (testQuarantineRules) |
| Quarantine | dynamic: ``No matches found (${data.total_quarantine} quarantine items checked)`` [info] | `frontend/app.js:4113` (testQuarantineRules) |
| Quarantine | dynamic: `'Test failed: ' + err.message` [error] | `frontend/app.js:4178` (testQuarantineRules) |
| Rspamd | dynamic: ``Cannot save: ${valData.errors.length} validation error(s). Fix them first.`` [error] | `frontend/spam_filter.js:324` (saveMapContent) |
| Rspamd | dynamic: `'Validation failed: ' + e.message` [error] | `frontend/spam_filter.js:329` (saveMapContent) |
| Rspamd | dynamic: ``Map saved (${uiCountLabel(result.entry_count, 'entry', 'entries')}). ${resul...` [success] | `frontend/spam_filter.js:354` (saveMapContent) |
| Rspamd | dynamic: ``Map saved successfully (${uiCountLabel(result.entry_count, 'entry', 'entries...` [success] | `frontend/spam_filter.js:356` (saveMapContent) |
| Rspamd | dynamic: `'Failed to save map: ' + error.message` [error] | `frontend/spam_filter.js:366` (saveMapContent) |
| Rspamd | dynamic: ``Pattern added: ${pattern}`` [success] | `frontend/spam_filter.js:1351` (regexWizardAdd) |
| Status | dynamic: `ignored ? `${container.replace('-mailcow', '')} is ignored. It no longer coun...` [success] | `frontend/app.js:4709` (setContainerIgnored) |
| Status | dynamic: ``Could not change the container: ${e.message}`` [error] | `frontend/app.js:4713` (setContainerIgnored) |
| Status | "Starting blacklist check..." [info] | `frontend/app.js:4949` (checkBlacklists) |
| Status | "Blacklist check completed" [success] | `frontend/app.js:4993` (checkBlacklists) |
| Status | dynamic: ``Check completed for ${host}`` [success] | `frontend/app.js:5021` (checkBlacklists) |
| Status | dynamic: ``Failed to check: ${error.message}`` [error] | `frontend/app.js:5030` (checkBlacklists) |
| Status | dynamic: ``Job "${displayName}" started successfully`` [success] | `frontend/app.js:5437` (triggerBackgroundJob) |
| Status | dynamic: ``Job "${displayName}" is already running`` [warning] | `frontend/app.js:5446` (triggerBackgroundJob) |
| Status | dynamic: ``Failed to start job: ${error.message}`` [error] | `frontend/app.js:5449` (triggerBackgroundJob) |
| Domains | "DNS check already in progress" [warning] | `frontend/domains.js:368` (checkAllDomainsDNS) |
| Domains | dynamic: ``Checked ${result.domains_checked} domains`` [success] | `frontend/domains.js:387` (checkAllDomainsDNS) |
| Domains | "DNS check failed" [error] | `frontend/domains.js:390` (checkAllDomainsDNS) |
| Domains | "Failed to check DNS" [error] | `frontend/domains.js:394` (checkAllDomainsDNS) |
| Domains | "DNS check already in progress" [warning] | `frontend/domains.js:405` (checkSingleDomainDNS) |
| Domains | dynamic: ``Checking DNS for ${domainName}...`` [info] | `frontend/domains.js:410` (checkSingleDomainDNS) |
| Domains | dynamic: ``DNS checked for ${domainName}`` [success] | `frontend/domains.js:420` (checkSingleDomainDNS) |
| Domains | dynamic: ``Failed to check DNS for ${domainName}`` [error] | `frontend/domains.js:435` (checkSingleDomainDNS) |
| Domains | "Failed to check DNS" [error] | `frontend/domains.js:439` (checkSingleDomainDNS) |
| DMARC | "Manual upload is disabled" [error] | `frontend/dmarc.js:976` (uploadDmarcReport) |
| DMARC | dynamic: ``${reportType} report uploaded: ${count} ${countLabel}`` [success] | `frontend/dmarc.js:989` (uploadDmarcReport) |
| DMARC | dynamic: ``${reportType} report already exists`` [warning] | `frontend/dmarc.js:994` (uploadDmarcReport) |
| DMARC | "Failed to upload report" [error] | `frontend/dmarc.js:999` (uploadDmarcReport) |
| DMARC | "Fetching reports needs IMAP set up in Settings" [error] | `frontend/dmarc.js:1081` (triggerDmarcSync) |
| DMARC | "Reports are already being fetched" [info] | `frontend/dmarc.js:1096` (triggerDmarcSync) |
| DMARC | "Fetching reports from the mailbox" [success] | `frontend/dmarc.js:1098` (triggerDmarcSync) |
| DMARC | "Could not start fetching reports. Try again." [error] | `frontend/dmarc.js:1112` (triggerDmarcSync) |
| DMARC | "Report deletion is disabled" [error] | `frontend/dmarc.js:1285` (deleteDomainReports) |
| DMARC | dynamic: ``Deleted ${reportsCount(result.dmarc_reports, 'DMARC')} and ${reportsCount(re...` [success] | `frontend/dmarc.js:1291` (deleteDomainReports) |
| DMARC | dynamic: ``${domain} has no reports left`` [info] | `frontend/dmarc.js:1293` (deleteDomainReports) |
| DMARC | "Failed to delete the reports" [error] | `frontend/dmarc.js:1298` (deleteDomainReports) |
| DMARC | "Report deletion is disabled" [error] | `frontend/dmarc.js:1420` (deleteReport) |
| DMARC | dynamic: ``${reportType.toUpperCase()} report deleted`` [success] | `frontend/dmarc.js:1428` (deleteReport) |
| DMARC | "Failed to delete report" [error] | `frontend/dmarc.js:1433` (deleteReport) |
| Mailbox stats | "Please select both start and end dates" [error] | `frontend/mailbox-stats.js:629` (applyCustomDateRange) |
| Mailbox stats | "Start date must be before end date" [error] | `frontend/mailbox-stats.js:637` (applyCustomDateRange) |
| Mailbox stats | dynamic: `detail.detail \|\| 'Could not reset the counter'` [error] | `frontend/rate-limits.js:592` (resetRateLimitCounter) |
| Mailbox stats | dynamic: ``${user} can send again`` [success] | `frontend/rate-limits.js:596` (resetRateLimitCounter) |
| Mailbox stats | "Could not reset the counter" [error] | `frontend/rate-limits.js:605` (resetRateLimitCounter) |
| Mailbox stats | "Enter how many messages to allow, as a whole number" [error] | `frontend/rate-limits.js:899` (applyRateLimitBulk) |
| Mailbox stats | dynamic: `detail.detail \|\| 'Could not apply the rate limit'` [error] | `frontend/rate-limits.js:931` (applyRateLimitBulk) |
| Mailbox stats | dynamic: ``Nothing was changed${tail}`` [warning] | `frontend/rate-limits.js:975` (applyRateLimitBulk) |
| Mailbox stats | dynamic: `value === 0 ? `Limit removed from ${changed}${tail}` : `Limit set on ${change...` [success] | `frontend/rate-limits.js:978` (applyRateLimitBulk) |
| Mailbox stats | "Could not apply the rate limit" [error] | `frontend/rate-limits.js:983` (applyRateLimitBulk) |
| Mailbox stats | "Enter how many messages to allow, as a whole number" [error] | `frontend/rate-limits.js:1072` (saveRateLimit) |
| Mailbox stats | dynamic: `detail.detail \|\| 'Could not save the rate limit'` [error] | `frontend/rate-limits.js:1109` (submitRateLimit) |
| Mailbox stats | dynamic: `value === 0 ? `${name} now sends without a limit` : `${name} is limited to ${...` [success] | `frontend/rate-limits.js:1114` (submitRateLimit) |
| Mailbox stats | "Could not save the rate limit" [error] | `frontend/rate-limits.js:1145` (submitRateLimit) |
| Settings | dynamic: `uiApiErrorText(detail, 'Could not save destination')` [error] | `frontend/notifications.js:243` (saveNotificationChannel) |
| Settings | dynamic: `isNew ? 'Destination added' : 'Destination updated'` [success] | `frontend/notifications.js:246` (saveNotificationChannel) |
| Settings | "Could not save destination" [error] | `frontend/notifications.js:250` (saveNotificationChannel) |
| Settings | "Could not delete destination" [error] | `frontend/notifications.js:265` (deleteNotificationChannel) |
| Settings | "Destination deleted" [success] | `frontend/notifications.js:266` (deleteNotificationChannel) |
| Settings | "Could not delete destination" [error] | `frontend/notifications.js:269` (deleteNotificationChannel) |
| Settings | "Save the mailcow or Rspamd connection change first, then turn Sync with Rspamd on or off." [error] | `frontend/settings.js:692` (settingsRspamdTransition) |
| Settings | dynamic: `bad.length === 1 ? `${name}: ${first.validationMessage}` : `${bad.length} fie...` [error] | `frontend/settings.js:1381` (settingsCheckFields) |
| Settings | "Cannot enable Basic Auth without a password. Please set a password first." [error] | `frontend/settings.js:1990` (renderSettings) |
| Settings | dynamic: ``Sync with Rspamd is still off. ${settingsErrorText(body, res.statusText)}`` [error] | `frontend/settings.js:2041` (renderSettings) |
| Settings | dynamic: ``Sync with Rspamd is still off. Rspamd could not be reached: ${freshErr.messa...` [error] | `frontend/settings.js:2045` (renderSettings) |
| Settings | dynamic: `...checkToast` [info] | `frontend/settings.js:2084` (renderSettings) |
| Settings | "Basic Auth enabled successfully! You will need to log in on your next visit." [success] | `frontend/settings.js:2086` (renderSettings) |
| Settings | dynamic: ``Purging data for ${purgeableNewlyDisabled.length} disabled feature(s)...`` [info] | `frontend/settings.js:2102` (renderSettings) |
| Settings | dynamic: `featuresChanged ? 'Features updated - reloading...' : 'Settings saved - reloa...` [success] | `frontend/settings.js:2156` (renderSettings) |
| Settings | "Settings saved" [success] | `frontend/settings.js:2161` (renderSettings) |
| Settings | dynamic: `'Failed to save: ' + (err.message \|\| err)` [error] | `frontend/settings.js:2165` (renderSettings) |
| Settings | dynamic: `'Import failed: ' + (err.message \|\| err)` [error] | `frontend/settings.js:2182` (renderSettings) |
| Settings | "MaxMind license is valid" [success] | `frontend/settings.js:2434` (validateMaxMindLicense) |
| Settings | dynamic: `'MaxMind license validation failed: ' + result.error` [error] | `frontend/settings.js:2436` (validateMaxMindLicense) |
| Settings | "Failed to validate MaxMind license" [error] | `frontend/settings.js:2445` (validateMaxMindLicense) |
| Settings | "GeoIP database re-download started…" [info] | `frontend/settings.js:2470` (repairGeoIPDatabase) |
| Settings | "GeoIP databases repaired successfully" [success] | `frontend/settings.js:2493` (repairGeoIPDatabase) |
| Settings | "GeoIP databases re-downloaded but validation still failed" [error] | `frontend/settings.js:2495` (repairGeoIPDatabase) |
| Settings | "GeoIP repair timed out - check Status page for progress" [warning] | `frontend/settings.js:2508` (repairGeoIPDatabase) |
| Settings | dynamic: `'Failed to repair GeoIP databases: ' + error.message` [error] | `frontend/settings.js:2519` (repairGeoIPDatabase) |
| Settings | dynamic: `...toast` [info] | `frontend/settings.js:2610` (validateCredential) |
| Settings | dynamic: `...toast` [info] | `frontend/settings.js:2617` (validateCredential) |
| Settings | dynamic: `String(toast[0])` [toast[1] === 'suc...] | `frontend/settings.js:2634` (showSettingsToastAfterReload) |
| Shared | "Download started." [success] | `frontend/export.js:36` (exportCSV) |
| Shared | dynamic: `error.message \|\| 'Could not export CSV. Please try again.'` [error] | `frontend/export.js:39` (exportCSV) |
| Shared | "Copying needs HTTPS. Select the text and copy it yourself." [error] | `frontend/utils.js:618` (copyToClipboard) |
| Shared | dynamic: `'Copied: ' + text` [success] | `frontend/utils.js:622` (copyToClipboard) |
| Shared | "Failed to copy" [error] | `frontend/utils.js:637` (copyToClipboard) |
| Shared | "Could not copy. Press Ctrl+C to copy the selected line." [error] | `frontend/utils.js:1627` (uiLineCopy) |
| Shared | "Line copied" [success] | `frontend/utils.js:1628` (uiLineCopy) |
| app.js (mixed) | "Could not sign out. Try again in a moment." [error] | `frontend/app.js:132` (handleLogout) |
| app.js (mixed) | dynamic: `result.already ? result.msg : `IP ${ip} added to the allowlist`` [success] | `frontend/app.js:1643` (allowIP) |
| app.js (mixed) | dynamic: `'Failed to allow: ' + (result.msg \|\| result.detail \|\| 'Unknown error')` [error] | `frontend/app.js:1649` (allowIP) |
| app.js (mixed) | dynamic: `'Failed to allow IP: ' + err.message` [error] | `frontend/app.js:1651` (allowIP) |
| app.js (mixed) | dynamic: `message` [success] | `frontend/app.js:2701` (offerAlertUndo) |
| app.js (mixed) | dynamic: `message` [warning] | `frontend/app.js:2705` (offerAlertsRefresh) |
| app.js (mixed) | "Needs attention is up to date" [success] | `frontend/app.js:2708` (offerAlertsRefresh) |
| app.js (mixed) | dynamic: `ignored ? `${data.name} is ignored for every address.` : `${data.name} counts...` [success] | `frontend/app.js:5207` (setBlocklistIgnored) |
| app.js (mixed) | dynamic: ``Could not change the blocklist: ${e.message}`` [error] | `frontend/app.js:5211` (setBlocklistIgnored) |
| app.js (mixed) | "No such country. Pick one from the list, or type its two-letter code." [error] | `frontend/protection.js:198` (addProtectionCountry) |
| app.js (mixed) | "Protection rules saved" [success] | `frontend/protection.js:225` (saveProtectionRules) |
| app.js (mixed) | dynamic: ``Could not save the rules: ${error.message}`` [error] | `frontend/protection.js:228` (saveProtectionRules) |
| app.js (mixed) | dynamic: `done(data)` [success] | `frontend/protection.js:240` (protectionHitAction) |
| app.js (mixed) | dynamic: ``Could not ${action === 'ban' ? 'ban' : action}: ${error.message}`` [error] | `frontend/protection.js:248` (protectionHitAction) |

### Confirmation dialogs

Every action that asks before it acts. Losing one turns a guarded action into a one-click action.

| Page | What | Code |
|---|---|---|
| Security | showConfirmModal: dynamic: `{ title: 'Unban IP', message: 'Unban ' + ip + '?', confirmText: 'Unban' }` | `frontend/app.js:1547` (unbanIP) |
| Security | showConfirmModal: dynamic: `{ title: 'Ban IP', message: `Are you sure you want to permanently ban ${ipWit...` | `frontend/app.js:1588` (banIP) |
| Security | showConfirmModal: dynamic: `{ title: `Remove from the ${label}`, message: `Remove ${entry} from the Fail2...` | `frontend/security.js:864` (securityRemoveFromList) |
| Security | showConfirmModal: dynamic: `{ title: 'Repair the entry', message: `Replace ${entry} with ${single} on the...` | `frontend/security.js:891` (securityRepairListEntry) |
| Security | showConfirmModal: dynamic: `{ title: action === 'block' ? 'Disable SMTP' : 'Re-enable SMTP', message: `${...` | `frontend/smtp-abuse.js:158` (smtpAbuseAction) |
| Outbound | showConfirmModal: dynamic: `{ title: 'Retry Delivery', message: `Retry delivery of ${ids.length} message(...` | `frontend/app.js:3240` (queueBulkRetry) |
| Outbound | showConfirmModal: dynamic: `{ title: 'Delete Messages', message: `Permanently delete ${ids.length} messag...` | `frontend/app.js:3247` (queueBulkDelete) |
| Outbound | showConfirmModal: dynamic: `{ title: 'Delete Message', message: 'Delete this message from the queue?', co...` | `frontend/app.js:3266` (queueDeleteItem) |
| Outbound | showConfirmModal: dynamic: `{ title: 'Flush Queue', message: 'Flush (retry delivery of) ALL messages in t...` | `frontend/app.js:3271` (queueFlushAll) |
| Outbound | showConfirmModal: dynamic: `{ title: 'Delete All', message: 'Permanently delete ALL messages from the que...` | `frontend/app.js:3276` (queueDeleteAll) |
| Outbound | showConfirmModal: dynamic: `{ title: 'Delete Suppression', message: `Delete suppression for ${email}? Thi...` | `frontend/spam_filter.js:1090` (deleteSuppression) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete Message', message: 'Are you sure you want to permanently del...` | `frontend/app.js:3494` (quarantineDelete) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Not Spam', message: 'Release this message and train Rspamd that it ...` | `frontend/app.js:3499` (quarantineLearnHam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Mark as Spam', message: 'Delete this message and train Rspamd that ...` | `frontend/app.js:3504` (quarantineLearnSpam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Release Messages', message: `Release ${ids.length} quarantined mess...` | `frontend/app.js:3511` (quarantineBulkRelease) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete Messages', message: `Permanently delete ${ids.length} quaran...` | `frontend/app.js:3518` (quarantineBulkDelete) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Not Spam', message: `Release ${ids.length} message(s) and train Rsp...` | `frontend/app.js:3525` (quarantineBulkLearnHam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Mark as Spam', message: `Delete ${ids.length} message(s) and train ...` | `frontend/app.js:3532` (quarantineBulkLearnSpam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Release All', message: `Release ALL ${allIds.length} quarantined me...` | `frontend/app.js:3539` (quarantineReleaseAll) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete All', message: `Permanently delete ALL ${allIds.length} quar...` | `frontend/app.js:3546` (quarantineDeleteAll) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete Rule', message: `Delete rule "${ruleName}"?`, confirmText: '...` | `frontend/app.js:4077` (deleteQuarantineRule) |
| DMARC | showConfirmModal: dynamic: `{ title: 'Delete All Reports', message: `Delete all reports for ${domain}?\\n...` | `frontend/dmarc.js:1274` (deleteDomainReports) |
| DMARC | showConfirmModal: dynamic: `{ title: 'Delete Report', message: `Are you sure you want to delete this ${re...` | `frontend/dmarc.js:1410` (deleteReport) |
| Mailbox stats | showConfirmModal: dynamic: `{ title: 'Reset rate limit counter', message: `Let ${user} send again straigh...` | `frontend/rate-limits.js:576` (resetRateLimitCounter) |
| Mailbox stats | showConfirmModal: dynamic: `{ title: value === 0 ? 'Remove rate limits' : 'Apply rate limit', message: va...` | `frontend/rate-limits.js:907` (applyRateLimitBulk) |
| Mailbox stats | showConfirmModal: dynamic: `{ title: 'Remove rate limit', message: `Remove the rate limit on ${name}? It ...` | `frontend/rate-limits.js:1081` (removeRateLimit) |
| Settings | showConfirmModal: dynamic: `{ title: 'Delete destination', message: `Delete "${channel ? channel.name : '...` | `frontend/notifications.js:256` (deleteNotificationChannel) |
| Settings | confirm: dynamic: `turning // Suppressions off has its own confirmation` | `frontend/settings.js:703` (settingsRspamdTransition) |
| Settings | showFeatureDisableConfirmModal: dynamic: `confirmNewlyDisabled` | `frontend/settings.js:2024` (renderSettings) |
| Settings | showConfirmModal: dynamic: `{ title: 'Import from ENV', message: 'Import current configuration from ENV i...` | `frontend/settings.js:2171` (renderSettings) |
| Shared | confirm: dynamic: `` | `frontend/utils.js:760` |
| Shared | showConfirmModal: dynamic: `{ title: 'Discard your changes?', message: 'What you changed in this window i...` | `frontend/utils.js:875` (uiCloseGuarded) |
| Shared | showConfirmModal: dynamic: `{ title: 'Leave without saving?', message: `You have ${changes}. Leaving drop...` | `frontend/utils.js:956` (uiConfirmLeave) |
| app.js (mixed) | showConfirmModal: dynamic: `{ title: 'Allow IP', message: `Add ${ipWithMask} to the Fail2Ban allowlist?\\...` | `frontend/app.js:1630` (allowIP) |

### Country flags

PNG flags served locally from `frontend/assets/flags/<size>/<cc>.png` (sizes 16x12, 24x18, 48x36), no emoji and no external source.

| Page | What | Code |
|---|---|---|
| Message details | getFlagUrl(rspamd.country_code, '16x12') | `frontend/message-details.js:1028` (renderOverviewTab) |
| Message details | getFlagUrl(rspamd.country_code, '16x12') | `frontend/message-details.js:1028` (renderOverviewTab) |
| Security | getFlagUrl(log.country_code, '16x12') | `frontend/app.js:1498` (renderNetfilterData) |
| Security | getFlagUrl(code, '16x12') | `frontend/security.js:125` (securityFlag) |
| Shared | getFlagUrl(rspamdData.country_code, size) | `frontend/app.js:5531` (renderGeoIPInfo) |
| Shared | getFlagUrl(record.country_code, size) | `frontend/app.js:5574` (renderGeoIPForDMARC) |
| Devices | getFlagUrl(d.country_code, '16x12') | `frontend/devices.js:129` (deviceLocation) |

### Markdown rendering

Places that render Markdown (help pages, changelogs) through `renderMarkdown` (marked, then DOMPurify) into a `.markdown-body` element.

| Page | What | Code |
|---|---|---|
| Status | renders `versionInfo.changelog` | `frontend/about.js:194` (wireVersionPanel) |
| Settings | renders `versionInfo.changelog` | `frontend/settings.js:1519` (updateVersionInfoUI) |
| Modal: changelog-modal | renders `markdownContent` | `frontend/app.js:983` (showMarkdownModal) |
| Modal: changelog-modal | renders `changelog` | `frontend/app.js:5477` (showChangelogModal) |

### Controls wired in JavaScript

Buttons, tabs and fields whose behavior is attached with `addEventListener` instead of an inline handler. The automatic inventory test does not see these, so they need a manual check.

| Page | What | Code |
|---|---|---|
| Shell | change on `px)')` | `frontend/app.js:635` (loadAppInfo) |
| Shell | change on `px)')` | `frontend/app.js:636` (loadAppInfo) |
| Shell | click on `document` | `frontend/router.js:836` |
| Messages | click on `document` | `frontend/app.js:4403` |
| Message details | click on `messageModal` | `frontend/message-details.js:1359` |
| Outbound | click on `modal` | `frontend/spam_filter.js:766` (showBlockDetails) |
| Outbound | click on `document` | `frontend/spam_filter.js:1191` |
| Quarantine | click on `testModal` | `frontend/app.js:4176` (testQuarantineRules) |
| DMARC | click on `modal` | `frontend/dmarc.js:1132` (showDmarcSyncHistory) |
| Settings | click on `cancelBtn` | `frontend/settings.js:116` (showBasicAuthVerifyModal) |
| Settings | click on `confirmBtn` | `frontend/settings.js:117` (showBasicAuthVerifyModal) |
| Settings | click on `cancelBtn` | `frontend/settings.js:176` (showFeatureDisableConfirmModal) |
| Settings | click on `confirmBtn` | `frontend/settings.js:177` (showFeatureDisableConfirmModal) |
| Settings | click on `overlay` | `frontend/settings.js:184` (showFeatureDisableConfirmModal) |
| Settings | input on `el` | `frontend/settings.js:1365` (settingsCheckFields) |
| Settings | click on `btn` | `frontend/settings.js:1836` (renderSettings) |
| Settings | change on `tabSelect` | `frontend/settings.js:1856` (renderSettings) |
| Settings | click on `btn` | `frontend/settings.js:1863` (renderSettings) |
| Settings | change on `cb` | `frontend/settings.js:1894` (renderSettings) |
| Settings | input on `form` | `frontend/settings.js:1940` (renderSettings) |
| Settings | change on `form` | `frontend/settings.js:1941` (renderSettings) |
| Settings | input on `form` | `frontend/settings.js:1946` (renderSettings) |
| Settings | change on `form` | `frontend/settings.js:1949` (renderSettings) |
| Settings | click on `btn` | `frontend/settings.js:1954` (renderSettings) |
| Settings | click on `closeBtn` | `frontend/settings.js:2257` (showGeoIPSetupModal) |
| Settings | click on `modal` | `frontend/settings.js:2762` (showConnectionTestModal) |
| Shared | click on `button` | `frontend/utils.js:686` (showToast) |
| Shared | click on `overlay` | `frontend/utils.js:804` (showConfirmModal) |
| Shared | click on `cancelBtn` | `frontend/utils.js:805` (showConfirmModal) |
| Shared | click on `okBtn` | `frontend/utils.js:806` (showConfirmModal) |
| Shared | click on `overlay` | `frontend/utils.js:845` (showChoiceModal) |
| Shared | click on `overlay.querySelector('[data-cancel]')` | `frontend/utils.js:846` (showChoiceModal) |
| Shared | click on `btn` | `frontend/utils.js:847` (showChoiceModal) |
| Shared | click on `document` | `frontend/utils.js:1339` |
| Shared | click on `document` | `frontend/utils.js:1565` |
| Shared | click on `copy` | `frontend/utils.js:1585` |
| Shared | click on `box` | `frontend/utils.js:2063` (uiTimeZoom) |
| Shared | click on `document` | `frontend/utils.js:2739` |
| Shared | input on `document` | `frontend/utils.js:2762` |
| app.js (mixed) | click on `changelogModal` | `frontend/app.js:5672` |
| app.js (mixed) | click on `changelogContent` | `frontend/app.js:5680` |
| app.js (mixed) | click on `el` | `frontend/app.js:5921` (showNavFlyout) |
| app.js (mixed) | click on `item` | `frontend/app.js:5946` (initNavFlyouts) |
| app.js (mixed) | input on `input` | `frontend/search.js:570` (initGlobalSearch) |
| app.js (mixed) | click on `panel` | `frontend/search.js:607` (initGlobalSearch) |

### Filters, sorting and view options

Drop-down lists in the page markup with their options. The option wording and order are part of the product.

| Page | What | Code |
|---|---|---|
| Messages | `messages-filter-direction`: All Directions / Inbound / Outbound / Internal | `frontend/index.html:708` |
| Messages | `messages-filter-status`: All Statuses / Delivered / Deferred / Bounced / Rejected / Spam / Discarded (Sieve) | `frontend/index.html:714` |
| Security | `netfilter-filter-action`: All Actions / BAN / UNBAN / Warning / Info | `frontend/index.html:812` |
| Security | `netfilter-filter-country`: All Countries | `frontend/index.html:819` |
| Outbound | `suppression-filter-reason`: All Reasons / Hard Bounce / Soft Bounce / Deferred Stuck / Rejected / Manual | `frontend/index.html:927` |
| Outbound | `suppression-filter-active`: Active Only / All / Inactive / Expired | `frontend/index.html:936` |
| Mailbox stats | `mailbox-stats-domain-filter`: All Domains | `frontend/index.html:1244` |
| Logs | `logs-fontsize`: 10px / 11px / 12px / 13px / 14px / 16px | `frontend/index.html:1359` |
| Devices | `devices-type-filter`: All device types | `frontend/index.html:1301` |
| Devices | `devices-seen-filter`: Any time / Seen in 24 hours / New this week / Not seen for 30 days | `frontend/index.html:1304` |

### Charts

Chart.js charts (local library). Check hover tooltips, legend and both themes.

| Page | What | Code |
|---|---|---|
| Mailbox stats | bar chart on `canvas.getContext('2d')` | `frontend/rate-limits.js:260` (renderRateLimitChart) |

### Colour thresholds

Values whose colour changes at a threshold (for example storage turns yellow and red, a high spam score turns red).

| Page | What | Code |
|---|---|---|

### Help topics

In-app help buttons; the topic is the Markdown file name under documentation/HelpDocs.

| Page | What | Code |
|---|---|---|
| Dashboard | topic "Dashboard" | `frontend/index.html:588` |
| Messages | topic "Messages" | `frontend/index.html:658` |
| Security | topic "Security" | `frontend/index.html:785` |
| Security | topic "Abuse_Protection" | `frontend/security.js:1281` (securityCardHtml) |
| Outbound | topic "Outbound" | `frontend/index.html:865` |
| Quarantine | topic "Quarantine" | `frontend/index.html:960` |
| Rspamd | topic "Rspamd" | `frontend/index.html:1030` |
| Status | topic "Status" | `frontend/index.html:1049` |
| Status | topic "IP_Blacklist_Monitor" | `frontend/index.html:1093` |
| Domains | topic "Domains" | `frontend/index.html:1123` |
| DMARC | topic "DMARC" | `frontend/index.html:1147` |
| Mailbox stats | topic "Mailbox_Stats" | `frontend/index.html:1186` |
| Mailbox stats | topic dynamic: `'${isRateLimits ? 'Rate_Limits' : 'Mailbox_Stats'}'` | `frontend/mailbox-stats.js:96` (mailboxStatsSwitchView) |
| Logs | topic "Logs" | `frontend/index.html:1322` |
| Settings | topic "Settings" | `frontend/index.html:1459` |
| about | topic "About" | `frontend/index.html:1445` |
| Devices | topic "Devices" | `frontend/index.html:1282` |

### Empty states

Text shown when a list or panel has nothing to show.

| Page | What | Code |
|---|---|---|
| Shell | "No changelog available" | `frontend/app.js:1044` (loadMailcowVersionStatus) |
| Messages | "No messages found" | `frontend/app.js:1251` |
| Messages | "No messages found" | `frontend/app.js:1262` (showMessagesFirstPage) |
| Message details | "No modal data available" | `frontend/message-details.js:75` (switchModalTab) |
| Message details | "No delivery logged yet" | `frontend/message-details.js:827` (renderRecipientRows) |
| Message details | "No delivery steps recorded yet" | `frontend/message-details.js:1002` (renderDeliverySteps) |
| Message details | "No Postfix delivery logs available" | `frontend/message-details.js:1064` (renderPostfixTab) |
| Message details | "No Postfix delivery logs available" | `frontend/message-details.js:1071` (renderPostfixTab) |
| Message details | "No spam analysis data available" | `frontend/message-details.js:1221` (renderSpamTab) |
| Security | "No logs found" | `frontend/app.js:1447` (renderNetfilterData) |
| Security | "No network data yet" | `frontend/security.js:581` (securityNetworkPanel) |
| Security | "No trap names yet" | `frontend/security.js:1227` (securityCardBody) |
| Security | "No countries yet" | `frontend/security.js:1239` (securityCardBody) |
| Security | "No matching entries" | `frontend/smtp-abuse.js:139` (renderSmtpAbusePanel) |
| Outbound | "No matching queue entries" | `frontend/app.js:3123` (applyQueueFilters) |
| Quarantine | "No quarantined messages" | `frontend/app.js:3392` (renderQuarantineData) |
| Quarantine | "No actions recorded yet" | `frontend/app.js:4206` (loadQuarantineRuleHistory) |
| Status | "No changelog available" | `frontend/about.js:180` (wireVersionPanel) |
| Status | "No container information available" | `frontend/app.js:4786` (loadStatusContainers) |
| Status | "No changelog available" | `frontend/app.js:4821` (loadStatusSystem) |
| Domains | "No domains found" | `frontend/domains.js:90` (renderDomains) |
| Domains | "No domains with DNS issues found" | `frontend/domains.js:156` (filterDomains) |
| Domains | "No domains found matching" | `frontend/domains.js:157` (filterDomains) |
| DMARC | "No mail in the last 30 days', dmarcTag('mut', 'No data" | `frontend/dmarc.js:556` (dmarcRecordsCard) |
| DMARC | "No signed mail in the reports" | `frontend/dmarc.js:560` (dmarcRecordsCard) |
| DMARC | "No mail in the last 30 days, so the reports cannot tell yet" | `frontend/dmarc.js:702` (dmarcPolicyPlan) |
| DMARC | "No signed mail in the reports" | `frontend/dmarc.js:768` (dmarcDmarcRecord) |
| DMARC | "No fetches yet" | `frontend/dmarc.js:1139` (showDmarcSyncHistory) |
| DMARC | "No reports found" | `frontend/dmarc.js:1372` (renderReportsManagementTable) |
| Mailbox stats | "No mailboxes found" | `frontend/mailbox-stats.js:453` (renderMailboxStatsAccordion) |
| Logs | "No log services available" | `frontend/logs-viewer.js:93` (loadLogViewer) |
| Logs | "No log entries found" | `frontend/logs-viewer.js:493` (renderLogEntries) |
| Settings | "No logs available" | `frontend/notifications.js:278` (testNotificationChannel) |
| Settings | "No logs available" | `frontend/notifications.js:295` (testNotificationChannelDraft) |
| Settings | "No logs available" | `frontend/settings.js:2694` (testSmtpConnection) |
| Settings | "No logs available" | `frontend/settings.js:2720` (testImapConnection) |
| app.js (mixed) | "No changelog available" | `frontend/app.js:971` (showAppUpdateModal) |
| Devices | "No ActiveSync devices yet" | `frontend/devices.js:97` (renderDevicesList) |
| Modal: changelog-modal | "No changelog available" | `frontend/app.js:5479` (showChangelogModal) |
| Modal: container-logs-modal | "No logs available" | `frontend/app.js:5800` (fetchContainerLogs) |

### Loading states

Functions that render a spinner or "Loading..." while data is fetched.

| Page | What | Code |
|---|---|---|
| Dashboard | 1 loading indicator(s) | `frontend/app.js:2355` (loadMailFlowChart) |
| Messages | 1 loading indicator(s) | `frontend/app.js:4511` (loadMessages) |
| Message details | 1 loading indicator(s) | `frontend/message-details.js:121` (viewMessageDetails) |
| Security | 1 loading indicator(s) | `frontend/app.js:2929` (loadNetfilterLogs) |
| Security | 1 loading indicator(s) | `frontend/security.js:440` (securityDetail) |
| Security | 1 loading indicator(s) | `frontend/security.js:581` (securityNetworkPanel) |
| Security | 1 loading indicator(s) | `frontend/security.js:593` (securityHistoryRows) |
| Security | 1 loading indicator(s) | `frontend/security.js:645` (renderSecurityOverview) |
| Security | 1 loading indicator(s) | `frontend/security.js:742` (securityCountryPanel) |
| Security | 1 loading indicator(s) | `frontend/security.js:758` (renderSecurityCountries) |
| Security | 1 loading indicator(s) | `frontend/security.js:790` (renderSecurityLists) |
| Security | 2 loading indicator(s) | `frontend/security.js:1269` (securityCardHtml) |
| Security | 1 loading indicator(s) | `frontend/smtp-abuse.js:39` (renderSmtpAbusePanel) |
| Outbound | 1 loading indicator(s) | `frontend/app.js:3046` (loadQueue) |
| Quarantine | 1 loading indicator(s) | `frontend/app.js:3354` (loadQuarantine) |
| Quarantine | 1 loading indicator(s) | `frontend/app.js:4198` (loadQuarantineRuleHistory) |
| Status | 3 loading indicator(s) | `frontend/about.js:212` (wireVersionPanel) |
| Status | 1 loading indicator(s) | `frontend/app.js:4649` (renderStatusAttention) |
| Status | 2 loading indicator(s) | `frontend/app.js:4941` (checkBlacklists) |
| Status | 1 loading indicator(s) | `frontend/app.js:5424` (triggerBackgroundJob) |
| DMARC | 1 loading indicator(s) | `frontend/dmarc.js:648` (openDmarcRecord) |
| Logs | 1 loading indicator(s) | `frontend/logs-viewer.js:1153` (loadDateRangeLogs) |
| Settings | 2 loading indicator(s) | `frontend/settings.js:2214` (showGeoIPSetupModal) |
| Settings | 1 loading indicator(s) | `frontend/settings.js:2408` (validateMaxMindLicense) |
| Settings | 1 loading indicator(s) | `frontend/settings.js:2454` (repairGeoIPDatabase) |
| Modal: alert-activity-modal | 1 loading indicator(s) | `frontend/alert-activity.js:31` (openAlertActivity) |

### Persisted preferences

Settings the browser remembers between visits.

| Page | What | Code |
|---|---|---|
| Shell | localStorage getItem "theme" | `frontend/app.js:5640` (initDarkMode) |
| Shell | localStorage setItem "theme" | `frontend/app.js:5655` (toggleDarkMode) |
| Shell | localStorage getItem "navCollapsed" | `frontend/index.html:18` |
| Logs | localStorage getItem "logsNewestFirst" | `frontend/logs-viewer.js:20` |
| Logs | localStorage setItem "logsNewestFirst" | `frontend/logs-viewer.js:570` (toggleLogSortOrder) |
| app.js (mixed) | localStorage setItem "navCollapsed" | `frontend/app.js:5993` (toggleNavCollapsed) |

### Auto refresh and timers

Background refreshes and polling.

| Page | What | Code |
|---|---|---|
| Shell | every 5 * 60 * 1000 ms | `frontend/app.js:639` (loadAppInfo) |
| Shell | every AUTO_REFRESH_INTERVAL ms | `frontend/app.js:1103` (startAutoRefresh) |
| Status | every 1000 ms | `frontend/app.js:4976` (checkBlacklists) |
| Settings | every 2000 ms | `frontend/settings.js:2339` (showGeoIPSetupModal) |
| Shared | every 30000 ms | `frontend/utils.js:437` (uiAgo) |
| Modal: container-logs-modal | every 2000 ms | `frontend/app.js:5841` (loadContainerLogs) |

### Address bar and deep links

Places that change the URL so a view can be bookmarked or shared.

| Page | What | Code |
|---|---|---|
| Shell | pushState | `frontend/router.js:89` (routerPush) |
| Shell | replaceState | `frontend/router.js:93` (routerReplace) |

### Keyboard handling

Key handlers; the keys are read from the handler body.

| Page | What | Code |
|---|---|---|
| Shell | keydown | `frontend/router.js:367` |
| Shell | keydown | `frontend/router.js:391` |
| Message details | keydown | `frontend/message-details.js:1368` |
| Settings | keydown: Enter | `frontend/settings.js:121` (showBasicAuthVerifyModal) |
| Settings | keydown: Enter | `frontend/settings.js:180` (showFeatureDisableConfirmModal) |
| Shared | keydown | `frontend/utils.js:1350` |
| Shared | keydown | `frontend/utils.js:2351` (uiTimeOverview) |
| Shared | keydown: ArrowDown, ArrowUp, Escape | `frontend/utils.js:2771` |
| app.js (mixed) | keydown: ArrowDown, ArrowUp, Escape | `frontend/app.js:5897` (showNavFlyout) |
| app.js (mixed) | keydown | `frontend/app.js:5947` (initNavFlyouts) |
| app.js (mixed) | keydown: ArrowDown, ArrowUp, ArrowLeft, ArrowRight | `frontend/search.js:573` (initGlobalSearch) |
| app.js (mixed) | keydown | `frontend/search.js:634` (initGlobalSearch) |

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
