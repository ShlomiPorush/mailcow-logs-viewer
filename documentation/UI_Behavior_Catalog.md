# UI Behavior Catalog

The web UI has grown over many releases. Next to the pages and buttons that everyone sees, it carries a long tail of small behaviors that no mockup shows and nobody remembers: a value that copies on click, a tooltip that explains an abbreviation, the wording of a confirmation, a flag next to an IP address, the text of an empty list.

This catalog lists them, so that a redesign keeps every one of them on purpose or drops it on purpose, never by accident.

## How to use it during a redesign

1. Redesign one page at a time.
2. Before the page is considered done, go through its rows in every table below (use the Page column).
3. For each row, either confirm it still works in the new design, or record the decision to drop or change it in the pull request.
4. Check the invariants below on every page.
5. When the code changes, regenerate the tables: `node .github/scripts/ui-catalog.cjs --write`. A row that disappears from the tables without a decision is a regression.

Pages, modals, actions, handler functions and API calls are also guarded automatically by `.github/tests/ui-inventory.test.cjs` against `ui-inventory.baseline.json`. This catalog covers what that test cannot: how things look and behave.

## Invariants for every page

- **Everything is served locally.** The browser loads no external resource: no CDN, no web fonts, no remote images. Tailwind, Chart.js, marked, DOMPurify, the Markdown CSS and the flag images live under `frontend/assets/`. A redesign that adds a font or a library must add it as a local file. (The in-app help pages are fetched by the backend from GitHub, see `backend/app/routers/documentation.py`; the browser still only talks to the app.)
- **Light and dark theme.** The theme toggle is stored in `localStorage` ("theme") and every page, modal and badge has a dark variant.
- **Desktop and mobile.** The navigation has a mobile menu (`toggleMobileMenu`, `navigateToMobile`); every page must stay usable on a phone.
- **Escaping.** Anything that comes from the server or from mail headers is rendered through `escapeHtml`, and values placed inside inline handlers through `escapeJsArg` (see `frontend/utils.js`). New markup must keep this; mail headers are attacker-controlled.
- **Mail content keeps its own direction.** Subjects, addresses and quarantine rule values can be in Hebrew or Arabic, so the element that shows them carries `dir="auto"`, and `copyableText` wraps its text in `<bdi>`. The browser then lays out each value in its own direction without moving the text around it (scores, arrows, the copy icon). A rule in the `<style>` block of `index.html` keeps `[dir="auto"]` aligned left, so a Hebrew subject stays next to its label instead of jumping to the far edge. Keep this on every place that shows mail content.
- **Country flags are PNG images, never emoji.** Most use is on desktop, and Windows does not render flag emoji (it shows two letters instead). The images live in `frontend/assets/flags/` in three sizes.
- **Markdown keeps its styling.** Help pages and changelogs are rendered by `renderMarkdown` (marked, then DOMPurify, `frontend/utils.js`) into a `.markdown-body` element inside `#changelog-content` or `.update-changelog-content`. Their look comes from the local `github-markdown.min.css` plus the overrides in the `<style>` block of `index.html` (the `.markdown-body` rules, about lines 270 to 470), which also carry the dark theme. A redesign that renames these containers or drops those rules breaks every help page and changelog, even though nothing else changes.
- **Dates follow the app timezone.** Times are formatted with `Intl.DateTimeFormat` in `appTimezone`, which the backend reports (`formatTime` in `frontend/utils.js`, and `frontend/rate-limits.js`), not in the browser's timezone. Counts use thousands separators (`toLocaleString()`).
- **Custom branding.** The header title and logo come from settings (`app_title`, `app_logo_url`, see `/api/info`): a custom logo replaces the default icon (`#app-logo`, `#default-logo`) and the title can differ per installation. The footer repeats the title.
- **Header and footer indicators.** The header shows the mailcow connection indicator (`#mailcow-connection-indicator`), a "mailcow update available" button (`#mailcow-update-icon`), the theme toggle, Refresh and Logout. The footer shows the app version, the mailcow version, an "Update Available" badge that opens Settings, the GitHub link and the container logs button. Each is easy to lose in a new layout.
- **Status indicators inside tabs.** The Security tab of the message details shows a red or green dot for whether the message has security events.
- **Badges** use the recipes in `APP_COLORS` (soft fill plus a subtle border, squared corners, not rounded pills).
- **Cache busting.** Every changed frontend file gets a new `?v=` in `index.html`, or browsers keep the old copy.

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

## How this catalog was checked

The tables are generated from the code. On 2026-09-24 the catalog was also compared against a running instance with real data: every page, every sub-tab and view switch, the Settings tabs and the detail views were opened in a headless browser (read-only: no save, delete, ban, release or run). That pass added the controls wired in JavaScript, the drop-down options, charts, colour thresholds, tooltips set from JavaScript, and the timezone, header and footer invariants. No data from that instance is recorded here.

<!-- generated:start (node .github/scripts/ui-catalog.cjs --write) -->

## Reference tables

Generated from the code. Do not edit by hand; run `node .github/scripts/ui-catalog.cjs --write` after a change.

| Behaviour | Count |
|---|---|
| [Click to copy](#click-to-copy) | 34 |
| [Tooltips](#tooltips) | 106 |
| [Toasts](#toasts) | 133 |
| [Confirmation dialogs](#confirmation-dialogs) | 27 |
| [Country flags](#country-flags) | 5 |
| [Markdown rendering](#markdown-rendering) | 4 |
| [Controls wired in JavaScript](#controls-wired-in-javascript) | 27 |
| [Filters, sorting and view options](#filters-sorting-and-view-options) | 11 |
| [Charts](#charts) | 3 |
| [Colour thresholds](#colour-thresholds) | 54 |
| [Help topics](#help-topics) | 8 |
| [Empty states](#empty-states) | 35 |
| [Loading states](#loading-states) | 18 |
| [Persisted preferences](#persisted-preferences) | 4 |
| [Auto refresh and timers](#auto-refresh-and-timers) | 4 |
| [Address bar and deep links](#address-bar-and-deep-links) | 6 |
| [Keyboard handling](#keyboard-handling) | 4 |
| [Badge colours](#badge-colours) | 11 |

### Click to copy

Fields that copy their value on click (hover shows a copy icon and "Click to copy").

| Page | What | Code |
|---|---|---|
| Message details | copies: `r` | `frontend/message-details.js:409` (renderOverviewTab) |
| Message details | copies: `recipientsToDisplay[0] \|\| '-'` | `frontend/message-details.js:419` (renderOverviewTab) |
| Message details | copies: `data.recipient` | `frontend/message-details.js:427` (renderOverviewTab) |
| Message details | copies: `data.sender \|\| '-'` | `frontend/message-details.js:442` (renderOverviewTab) |
| Message details | copies: `data.queue_id` | `frontend/message-details.js:469` (renderOverviewTab) |
| Message details | copies: `data.message_id` | `frontend/message-details.js:475` (renderOverviewTab) |
| Message details | copies: `data.rspamd.user` | `frontend/message-details.js:537` (renderOverviewTab) |
| Message details | copies: `sender` | `frontend/message-details.js:681` (renderPostfixTab) |
| Message details | copies: `Array.from(recipientsFromPostfix)[0]` | `frontend/message-details.js:687` (renderPostfixTab) |
| Message details | copies: `data.recipients[0]` | `frontend/message-details.js:692` (renderPostfixTab) |
| Message details | copies: `queueId` | `frontend/message-details.js:704` (renderPostfixTab) |
| Message details | copies: `clientIp` | `frontend/message-details.js:710` (renderPostfixTab) |
| Message details | copies: `recipient` | `frontend/message-details.js:732` (renderPostfixTab) |
| Message details | copies: `log.ip` | `frontend/message-details.js:890` (renderNetfilterTab) |
| Message details | copies: `log.username` | `frontend/message-details.js:894` (renderNetfilterTab) |
| Security | copies: `log.ip` | `frontend/app.js:884` (renderNetfilterData) |
| Security | copies: `log.username` | `frontend/app.js:885` (renderNetfilterData) |
| Queue | copies: `item.sender` | `frontend/app.js:2313` (applyQueueFilters) |
| Queue | copies: `qid` | `frontend/app.js:2314` (applyQueueFilters) |
| Queue | copies: `emailOnly` | `frontend/app.js:2329` (applyQueueFilters) |
| Quarantine | copies: `item.sender \|\| 'Unknown'` | `frontend/app.js:2670` (renderQuarantineData) |
| Quarantine | copies: `item.rcpt \|\| 'Unknown'` | `frontend/app.js:2674` (renderQuarantineData) |
| Quarantine | copies: `item.qid` | `frontend/app.js:2687` (renderQuarantineData) |
| Quarantine | copies: `r.address` | `frontend/app.js:2919` (renderQuarantineDetailContent) |
| Quarantine | copies: `data.subject \|\| '-'` | `frontend/app.js:2956` (renderQuarantineDetailContent) |
| Quarantine | copies: `data.header_from \|\| '-'` | `frontend/app.js:2961` (renderQuarantineDetailContent) |
| Quarantine | copies: `data.env_from \|\| '-'` | `frontend/app.js:2965` (renderQuarantineDetailContent) |
| Spam filter | copies: `displayEmail` | `frontend/spam_filter.js:510` (renderSuppressionItem) |
| Status | copies: `item.message_id \|\| 'N/A'` | `frontend/app.js:4403` (renderStatusCorrelation) |
| Status | copies: `item.sender \|\| 'N/A'` | `frontend/app.js:4407` (renderStatusCorrelation) |
| Status | copies: `item.recipient \|\| 'N/A'` | `frontend/app.js:4407` (renderStatusCorrelation) |
| Shared | copies: `ip` | `frontend/app.js:4628` (renderGeoIPInfo) |
| Shared | copies: `ip` | `frontend/app.js:4635` (renderGeoIPInfo) |
| Shared | copyToClipboard: `'${safeText}'` | `frontend/utils.js:375` (copyableText) |

### Tooltips

Native `title` tooltips. Dynamic ones show the expression that builds the text.

| Page | What | Code |
|---|---|---|
| Shell | "mailcow connection status" | `frontend/index.html:533` |
| Shell | "mailcow update available" | `frontend/index.html:542` |
| Shell | "View Container Logs" | `frontend/index.html:2636` |
| Shell | set in JS: dynamic: `data.app_title` | `frontend/app.js:402` (loadAppInfo) |
| Shell | set in JS: "Connected to mailcow" | `frontend/app.js:472` (loadMailcowConnectionStatus) |
| Shell | set in JS: "Not connected to mailcow" | `frontend/app.js:481` (loadMailcowConnectionStatus) |
| Shell | set in JS: "Connection status unknown" | `frontend/app.js:496` (loadMailcowConnectionStatus) |
| Shell | set in JS: dynamic: ``Update available: v${data.latest_version}`` | `frontend/app.js:516` (loadAppVersionStatus) |
| Shell | set in JS: dynamic: ``Update available: ${data.latest_version}`` | `frontend/app.js:595` (loadMailcowVersionStatus) |
| Shell | set in JS: dynamic: ``Update available: ${data.latest_version}`` | `frontend/app.js:602` (loadMailcowVersionStatus) |
| Dashboard | "Dismiss" | `frontend/app.js:1355` (loadDashboardSecurityAlerts) |
| Dashboard | dynamic: `${escapeHtml(msg.subject \|\| 'No subject')}` | `frontend/app.js:1497` (loadRecentActivity) |
| Messages | dynamic: `${escapeHtml(msg.subject \|\| 'No subject')}` | `frontend/app.js:769` (renderMessagesData) |
| Messages | dynamic: `${msg.final_status \|\| (msg.is_complete ? 'Correlation complete' : 'Waiting ...` | `frontend/app.js:775` (renderMessagesData) |
| Messages | "Queue ID" | `frontend/app.js:785` (renderMessagesData) |
| Messages | dynamic: `Message ID: ${escapeHtml(msg.message_id)}` | `frontend/app.js:786` (renderMessagesData) |
| Messages | dynamic: `${escapeHtml(msg.subject \|\| 'No subject')}` | `frontend/app.js:3693` (loadMessages) |
| Messages | dynamic: `${msg.final_status \|\| (msg.is_complete ? 'Correlation complete' : 'Waiting ...` | `frontend/app.js:3699` (loadMessages) |
| Messages | "Queue ID" | `frontend/app.js:3709` (loadMessages) |
| Messages | dynamic: `Message ID: ${escapeHtml(msg.message_id)}` | `frontend/app.js:3710` (loadMessages) |
| Message details | "This delivery attempt never reached a final outcome" | `frontend/message-details.js:335` (renderRelatedDeliveries) |
| Message details | dynamic: `${escapeHtml(data.subject)}` | `frontend/message-details.js:447` (renderOverviewTab) |
| Message details | dynamic: `${escapeHtml(data.message_id)}` | `frontend/message-details.js:475` (renderOverviewTab) |
| Message details | dynamic: `${escapeHtml(sender)}` | `frontend/message-details.js:681` (renderPostfixTab) |
| Message details | dynamic: `${escapeHtml(relay)}` | `frontend/message-details.js:716` (renderPostfixTab) |
| Security | dynamic: `Unban ${escapeHtml(log.ip)}/32` | `frontend/app.js:891` (renderNetfilterData) |
| Security | dynamic: `Ban ${escapeHtml(log.ip)}/32` | `frontend/app.js:892` (renderNetfilterData) |
| Security | "This feature is new - please report any issues on GitHub" | `frontend/index.html:1253` |
| Security | "Help - Abuse Protection" | `frontend/index.html:1257` |
| Queue | "Retry delivery" | `frontend/app.js:2338` (applyQueueFilters) |
| Queue | "Release from hold" | `frontend/app.js:2344` (applyQueueFilters) |
| Queue | "Hold message" | `frontend/app.js:2350` (applyQueueFilters) |
| Queue | "Delete from queue" | `frontend/app.js:2356` (applyQueueFilters) |
| Queue | dynamic: `Suppress ${escapeHtml(emailOnly)}` | `frontend/app.js:2365` (applyQueueFilters) |
| Quarantine | "Click to view details" | `frontend/app.js:2676` (renderQuarantineData) |
| Quarantine | "Queue ID" | `frontend/app.js:2687` (renderQuarantineData) |
| Quarantine | "View details" | `frontend/app.js:2691` (renderQuarantineData) |
| Quarantine | "Release message" | `frontend/app.js:2697` (renderQuarantineData) |
| Quarantine | "Delete message" | `frontend/app.js:2702` (renderQuarantineData) |
| Quarantine | "Release & train as Not Spam" | `frontend/app.js:2707` (renderQuarantineData) |
| Quarantine | "Delete & train as Spam" | `frontend/app.js:2712` (renderQuarantineData) |
| Quarantine | "Create auto-rule from this email" | `frontend/app.js:2717` (renderQuarantineData) |
| Quarantine | dynamic: `${escapeHtml(opts)}` | `frontend/app.js:2937` (renderQuarantineDetailContent) |
| Quarantine | dynamic: `${rule.enabled ? 'Click to disable this rule' : 'Click to enable this rule'}` | `frontend/app.js:3109` (loadQuarantineRules) |
| Quarantine | "Edit" | `frontend/app.js:3115` (loadQuarantineRules) |
| Quarantine | "Delete" | `frontend/app.js:3119` (loadQuarantineRules) |
| Quarantine | dynamic: `${escapeHtml(m.subject \|\| '')}` | `frontend/app.js:3381` (testQuarantineRules) |
| Quarantine | dynamic: `${escapeHtml(log.sender \|\| '')} → ${escapeHtml(log.recipient \|\| '')}` | `frontend/app.js:3465` (loadQuarantineRuleHistory) |
| Quarantine | dynamic: `Rule: ${escapeHtml(log.rule_name \|\| '')}` | `frontend/app.js:3468` (loadQuarantineRuleHistory) |
| Quarantine | "Help - Quarantine Auto-Rules" | `frontend/index.html:1411` |
| Spam filter | "Help - Spam Filter" | `frontend/index.html:1494` |
| Spam filter | "Clear all filters" | `frontend/index.html:1562` |
| Spam filter | "Sync suppression list to Rspamd" | `frontend/index.html:1574` |
| Spam filter | "Synced to Rspamd" | `frontend/spam_filter.js:490` (renderSuppressionItem) |
| Spam filter | "Pending sync to Rspamd" | `frontend/spam_filter.js:492` (renderSuppressionItem) |
| Spam filter | "Will be removed from Rspamd on next sync" | `frontend/spam_filter.js:497` (renderSuppressionItem) |
| Spam filter | "' + escapeHtml(s.email) + '" | `frontend/spam_filter.js:511` (renderSuppressionItem) |
| Spam filter | dynamic: `${escapeHtml(s.notes)}` | `frontend/spam_filter.js:522` (renderSuppressionItem) |
| Spam filter | "Edit suppression" | `frontend/spam_filter.js:527` (renderSuppressionItem) |
| Spam filter | dynamic: `${s.active ? 'Deactivate' : 'Reactivate'}` | `frontend/spam_filter.js:530` (renderSuppressionItem) |
| Spam filter | "Delete permanently" | `frontend/spam_filter.js:533` (renderSuppressionItem) |
| Status | dynamic: `${escapeHtml(detail)}` | `frontend/app.js:4330` (renderBlacklistStatus) |
| Status | dynamic: `${escapeHtml(detail)}` | `frontend/app.js:4332` (renderBlacklistStatus) |
| Status | "View info" | `frontend/app.js:4333` (renderBlacklistStatus) |
| Status | "Help - IP Blacklist Monitor" | `frontend/index.html:1667` |
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
| Domains | "Help - Domains Information" | `frontend/index.html:1776` |
| DMARC | "DMARC Reports" | `frontend/dmarc.js:366` (loadDmarcDomains) |
| DMARC | "TLS Reports" | `frontend/dmarc.js:367` (loadDmarcDomains) |
| DMARC | "Delete report" | `frontend/dmarc.js:1646` (renderReportsManagementTable) |
| DMARC | "Delete" | `frontend/dmarc.js:1681` (renderReportsManagementTable) |
| DMARC | "Help - DMARC Information" | `frontend/index.html:1809` |
| Mailbox stats | "Help - Mailbox Statistics" | `frontend/index.html:2031` |
| Mailbox stats | "Address on a mailcow alias domain that points at this mailbox" | `frontend/mailbox-stats.js:556` (renderMailboxStatsAccordion) |
| Mailbox stats | set in JS: dynamic: `isRateLimits ? 'Help - Rate Limits' : 'Help - Mailbox Statistics'` | `frontend/mailbox-stats.js:83` (mailboxStatsSwitchView) |
| Logs | "Pause/Resume live updates" | `frontend/index.html:2338` |
| Logs | "Live mode - show latest logs" | `frontend/index.html:2348` |
| Logs | "Auto-scroll to new entries" | `frontend/index.html:2358` |
| Logs | "Toggle sort order (newest at bottom / newest at top)" | `frontend/index.html:2368` |
| Logs | "Toggle word wrap" | `frontend/index.html:2389` |
| Logs | "Search" | `frontend/index.html:2406` |
| Logs | "Clear search" | `frontend/index.html:2413` |
| Logs | "Clear display" | `frontend/index.html:2423` |
| Logs | "From date" | `frontend/index.html:2451` |
| Logs | "To date" | `frontend/index.html:2456` |
| Logs | dynamic: `${escapeHtml(f.description \|\| '')}` | `frontend/logs-viewer.js:243` (loadSmartFilters) |
| Logs | "Clear all filters" | `frontend/logs-viewer.js:1238` (updateFilterBadge) |
| Settings | "Last delivery succeeded" | `frontend/notifications.js:67` (renderNotificationChannels) |
| Settings | "Last delivery failed" | `frontend/notifications.js:69` (renderNotificationChannels) |
| Settings | "Not used yet" | `frontend/notifications.js:70` (renderNotificationChannels) |
| Settings | dynamic: `${escapeHtml(ch.last_error)}` | `frontend/notifications.js:83` (renderNotificationChannels) |
| Settings | "Click to view changelog" | `frontend/settings.js:963` (renderSettings) |
| Settings | "Click to view changelog" | `frontend/settings.js:964` (renderSettings) |
| Settings | dynamic: `${escapeHtml(domain)}` | `frontend/settings.js:1089` (renderSettings) |
| Shared | dynamic: `${isRunning ? 'Job is running' : 'Run this job now'}` | `frontend/utils.js:547` (renderJobCard) |
| Modal: container-logs-modal | "Refresh" | `frontend/index.html:2663` |
| Modal: container-logs-modal | "Close" | `frontend/index.html:2671` |

### Toasts

Transient notifications from `showToast(message, type)` (utils.js). Type defaults to info.

| Page | What | Code |
|---|---|---|
| Messages | "Please select both start and end dates" [warning] | `frontend/app.js:3592` (applyMessagesCustomDateRange) |
| Messages | "Start date must be before end date" [warning] | `frontend/app.js:3601` (applyMessagesCustomDateRange) |
| Security | "IP ' + ip + ' unbanned successfully" [success] | `frontend/app.js:919` (unbanIP) |
| Security | dynamic: `'Failed to unban: ' + (result.msg \|\| result.detail \|\| 'Unknown error')` [error] | `frontend/app.js:926` (unbanIP) |
| Security | dynamic: `'Failed to unban IP: ' + err.message` [error] | `frontend/app.js:933` (unbanIP) |
| Security | dynamic: ``IP ${ip} added to blacklist`` [success] | `frontend/app.js:960` (banIP) |
| Security | dynamic: `'Failed to ban: ' + (result.msg \|\| result.detail \|\| 'Unknown error')` [error] | `frontend/app.js:967` (banIP) |
| Security | dynamic: `'Failed to ban IP: ' + err.message` [error] | `frontend/app.js:974` (banIP) |
| Security | "Failed to dismiss alert" [error] | `frontend/app.js:1382` (acknowledgeSecurityAlert) |
| Security | "All security alerts dismissed" [success] | `frontend/app.js:1390` (acknowledgeAllSecurityAlerts) |
| Security | "Failed to dismiss alerts" [error] | `frontend/app.js:1392` (acknowledgeAllSecurityAlerts) |
| Security | "Fail2Ban settings saved successfully" [success] | `frontend/app.js:2110` (loadFail2BanSettings) |
| Security | dynamic: `'Failed to save Fail2Ban settings: ' + (result.msg \|\| result.detail \|\| 'U...` [error] | `frontend/app.js:2114` (loadFail2BanSettings) |
| Security | dynamic: `'Failed to save Fail2Ban settings: ' + err.message` [error] | `frontend/app.js:2117` (loadFail2BanSettings) |
| Security | "Fail2Ban IP lists saved successfully" [success] | `frontend/app.js:2163` (loadFail2BanSettings) |
| Security | dynamic: `'Failed to save Fail2Ban IP lists: ' + (result.msg \|\| result.detail \|\| 'U...` [error] | `frontend/app.js:2166` (loadFail2BanSettings) |
| Security | dynamic: `'Failed to save Fail2Ban IP lists: ' + err.message` [error] | `frontend/app.js:2169` (loadFail2BanSettings) |
| Security | dynamic: `detail.detail \|\| `Could not ${action} SMTP`` [error] | `frontend/smtp-abuse.js:176` (smtpAbuseAction) |
| Security | dynamic: `action === 'block' ? 'SMTP disabled' : 'SMTP re-enabled'` [success] | `frontend/smtp-abuse.js:179` (smtpAbuseAction) |
| Security | dynamic: ``Could not ${action} SMTP`` [error] | `frontend/smtp-abuse.js:182` (smtpAbuseAction) |
| Security | dynamic: `detail.detail \|\| 'Could not save whitelist'` [error] | `frontend/smtp-abuse.js:209` (saveSmtpAbuseWhitelist) |
| Security | "Whitelist saved" [success] | `frontend/smtp-abuse.js:213` (saveSmtpAbuseWhitelist) |
| Security | "Could not save whitelist" [error] | `frontend/smtp-abuse.js:216` (saveSmtpAbuseWhitelist) |
| Security | "Could not remove whitelist entry" [error] | `frontend/smtp-abuse.js:224` (removeSmtpAbuseWhitelist) |
| Security | "Whitelist entry removed" [success] | `frontend/smtp-abuse.js:225` (removeSmtpAbuseWhitelist) |
| Security | "Could not remove whitelist entry" [error] | `frontend/smtp-abuse.js:228` (removeSmtpAbuseWhitelist) |
| Queue | dynamic: `result.msg \|\| `${labels[action] \|\| action} completed`` [success] | `frontend/app.js:2475` (queueAction) |
| Queue | dynamic: ``Queue action failed: ` + (result.msg \|\| result.detail \|\| 'Unknown error')` [error] | `frontend/app.js:2479` (queueAction) |
| Queue | dynamic: ``Queue action failed: ` + err.message` [error] | `frontend/app.js:2482` (queueAction) |
| Queue | dynamic: `result.msg \|\| 'Message deleted from queue'` [success] | `frontend/app.js:2502` (queueDeleteRequest) |
| Queue | dynamic: `'Failed to delete from queue: ' + (result.msg \|\| result.detail \|\| 'Unknow...` [error] | `frontend/app.js:2506` (queueDeleteRequest) |
| Queue | dynamic: `'Failed to delete from queue: ' + err.message` [error] | `frontend/app.js:2509` (queueDeleteRequest) |
| Quarantine | dynamic: `result.msg \|\| `Message(s) ${actionLabels[action] \|\| action} successfully`` [success] | `frontend/app.js:2843` (quarantineAction) |
| Quarantine | dynamic: ``Failed to ${action} message(s): ` + (result.msg \|\| result.detail \|\| 'Unk...` [error] | `frontend/app.js:2847` (quarantineAction) |
| Quarantine | dynamic: ``Failed to ${action} message(s): ` + err.message` [error] | `frontend/app.js:2850` (quarantineAction) |
| Quarantine | "Rule not found" [error] | `frontend/app.js:3139` (showEditQuarantineRuleModal) |
| Quarantine | "Rule name is required" [error] | `frontend/app.js:3286` (saveQuarantineRule) |
| Quarantine | "Match value is required" [error] | `frontend/app.js:3287` (saveQuarantineRule) |
| Quarantine | dynamic: `isEdit ? 'Rule updated' : 'Rule created'` [success] | `frontend/app.js:3319` (saveQuarantineRule) |
| Quarantine | dynamic: `'Failed to save rule: ' + err.message` [error] | `frontend/app.js:3322` (saveQuarantineRule) |
| Quarantine | "Rule deleted" [success] | `frontend/app.js:3333` (deleteQuarantineRule) |
| Quarantine | dynamic: `'Failed to delete rule: ' + err.message` [error] | `frontend/app.js:3336` (deleteQuarantineRule) |
| Quarantine | dynamic: ``Rule ${rule.enabled ? 'enabled' : 'disabled'}`` [success] | `frontend/app.js:3346` (toggleQuarantineRule) |
| Quarantine | dynamic: `'Failed to toggle rule: ' + err.message` [error] | `frontend/app.js:3349` (toggleQuarantineRule) |
| Quarantine | "Testing rules against quarantine..." [info] | `frontend/app.js:3355` (testQuarantineRules) |
| Quarantine | dynamic: ``No matches found (${data.total_quarantine} quarantine items checked)`` [info] | `frontend/app.js:3362` (testQuarantineRules) |
| Quarantine | dynamic: `'Test failed: ' + err.message` [error] | `frontend/app.js:3430` (testQuarantineRules) |
| Spam filter | dynamic: ``Cannot save: ${valData.errors.length} validation error(s). Fix them first.`` [error] | `frontend/spam_filter.js:372` (saveMapContent) |
| Spam filter | dynamic: `'Validation failed: ' + e.message` [error] | `frontend/spam_filter.js:377` (saveMapContent) |
| Spam filter | dynamic: ``Map saved (${result.entry_count} entries). ${result.normalized_entries} bare...` [success] | `frontend/spam_filter.js:402` (saveMapContent) |
| Spam filter | dynamic: ``Map saved successfully (${result.entry_count} entries)`` [success] | `frontend/spam_filter.js:404` (saveMapContent) |
| Spam filter | dynamic: `'Failed to save map: ' + error.message` [error] | `frontend/spam_filter.js:412` (saveMapContent) |
| Spam filter | dynamic: `type === 'domain' ? 'Domain name is required' : 'Email address is required'` [error] | `frontend/spam_filter.js:707` (renderSuppressionItem) |
| Spam filter | "Enter a plain domain name, for example example.com" [error] | `frontend/spam_filter.js:719` (renderSuppressionItem) |
| Spam filter | "This address is already suppressed" [error] | `frontend/spam_filter.js:743` (renderSuppressionItem) |
| Spam filter | dynamic: ``Suppression added: ${email}`` [success] | `frontend/spam_filter.js:752` (renderSuppressionItem) |
| Spam filter | dynamic: `error.message` [error] | `frontend/spam_filter.js:760` (renderSuppressionItem) |
| Spam filter | "Please set an expiry date" [error] | `frontend/spam_filter.js:866` (renderSuppressionItem) |
| Spam filter | "Suppression updated" [success] | `frontend/spam_filter.js:881` (renderSuppressionItem) |
| Spam filter | dynamic: `error.message` [error] | `frontend/spam_filter.js:887` (renderSuppressionItem) |
| Spam filter | dynamic: ``Suppression ${newActive ? 'activated' : 'deactivated'}`` [success] | `frontend/spam_filter.js:901` (renderSuppressionItem) |
| Spam filter | dynamic: `error.message` [error] | `frontend/spam_filter.js:907` (renderSuppressionItem) |
| Spam filter | dynamic: ``Suppression deleted: ${email}`` [success] | `frontend/spam_filter.js:918` (renderSuppressionItem) |
| Spam filter | dynamic: `error.message` [error] | `frontend/spam_filter.js:924` (renderSuppressionItem) |
| Spam filter | dynamic: ``Synced ${result.synced} suppressions to Rspamd (${result.newly_synced} new)`` [success] | `frontend/spam_filter.js:968` (renderSuppressionItem) |
| Spam filter | dynamic: `'Sync failed: ' + error.message` [error] | `frontend/spam_filter.js:972` (renderSuppressionItem) |
| Spam filter | dynamic: ``Imported ${result.imported} suppressions (${result.skipped} skipped)`` [success] | `frontend/spam_filter.js:1008` (renderSuppressionItem) |
| Spam filter | dynamic: `'Import failed: ' + error.message` [error] | `frontend/spam_filter.js:1014` (renderSuppressionItem) |
| Spam filter | dynamic: ``Pattern added: ${pattern}`` [success] | `frontend/spam_filter.js:1197` (renderSuppressionItem) |
| Status | "Starting blacklist check..." [info] | `frontend/app.js:4030` (checkBlacklists) |
| Status | "Blacklist check completed" [success] | `frontend/app.js:4076` (checkBlacklists) |
| Status | dynamic: ``Check completed for ${host}`` [success] | `frontend/app.js:4104` (checkBlacklists) |
| Status | dynamic: ``Failed to check: ${error.message}`` [error] | `frontend/app.js:4113` (checkBlacklists) |
| Status | dynamic: ``Job "${displayName}" started successfully`` [success] | `frontend/app.js:4547` (triggerBackgroundJob) |
| Status | dynamic: ``Job "${displayName}" is already running`` [warning] | `frontend/app.js:4556` (triggerBackgroundJob) |
| Status | dynamic: ``Failed to start job: ${error.message}`` [error] | `frontend/app.js:4559` (triggerBackgroundJob) |
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
| Mailbox stats | dynamic: `detail.detail \|\| 'Could not reset the counter'` [error] | `frontend/rate-limits.js:650` (resetRateLimitCounter) |
| Mailbox stats | dynamic: ``${user} can send again`` [success] | `frontend/rate-limits.js:654` (resetRateLimitCounter) |
| Mailbox stats | "Could not reset the counter" [error] | `frontend/rate-limits.js:663` (resetRateLimitCounter) |
| Mailbox stats | "Enter how many messages to allow, as a whole number" [error] | `frontend/rate-limits.js:944` (applyRateLimitBulk) |
| Mailbox stats | dynamic: `detail.detail \|\| 'Could not apply the rate limit'` [error] | `frontend/rate-limits.js:976` (applyRateLimitBulk) |
| Mailbox stats | dynamic: ``Nothing was changed${tail}`` [warning] | `frontend/rate-limits.js:1020` (applyRateLimitBulk) |
| Mailbox stats | dynamic: `value === 0 ? `Limit removed from ${changed}${tail}` : `Limit set on ${change...` [success] | `frontend/rate-limits.js:1023` (applyRateLimitBulk) |
| Mailbox stats | "Could not apply the rate limit" [error] | `frontend/rate-limits.js:1028` (applyRateLimitBulk) |
| Mailbox stats | "Enter how many messages to allow, as a whole number" [error] | `frontend/rate-limits.js:1121` (saveRateLimit) |
| Mailbox stats | dynamic: `detail.detail \|\| 'Could not save the rate limit'` [error] | `frontend/rate-limits.js:1158` (submitRateLimit) |
| Mailbox stats | dynamic: `value === 0 ? `${name} now sends without a limit` : `${name} is limited to ${...` [success] | `frontend/rate-limits.js:1163` (submitRateLimit) |
| Mailbox stats | "Could not save the rate limit" [error] | `frontend/rate-limits.js:1194` (submitRateLimit) |
| Settings | dynamic: `detail.detail \|\| 'Could not save destination'` [error] | `frontend/notifications.js:253` (saveNotificationChannel) |
| Settings | dynamic: `isNew ? 'Destination added' : 'Destination updated'` [success] | `frontend/notifications.js:256` (saveNotificationChannel) |
| Settings | "Could not save destination" [error] | `frontend/notifications.js:260` (saveNotificationChannel) |
| Settings | "Could not delete destination" [error] | `frontend/notifications.js:275` (deleteNotificationChannel) |
| Settings | "Destination deleted" [success] | `frontend/notifications.js:276` (deleteNotificationChannel) |
| Settings | "Could not delete destination" [error] | `frontend/notifications.js:279` (deleteNotificationChannel) |
| Settings | "Cannot enable Basic Auth without a password. Please set a password first." [error] | `frontend/settings.js:1763` (renderSettings) |
| Settings | "Basic Auth enabled successfully! You will need to log in on your next visit." [success] | `frontend/settings.js:1809` (renderSettings) |
| Settings | dynamic: ``Purging data for ${purgeableNewlyDisabled.length} disabled feature(s)...`` [info] | `frontend/settings.js:1826` (renderSettings) |
| Settings | "Features updated - reloading..." [success] | `frontend/settings.js:1840` (renderSettings) |
| Settings | dynamic: `'Failed to save: ' + (err.message \|\| err)` [error] | `frontend/settings.js:1849` (renderSettings) |
| Settings | "MaxMind license is valid" [success] | `frontend/settings.js:2111` (validateMaxMindLicense) |
| Settings | dynamic: `'MaxMind license validation failed: ' + result.error` [error] | `frontend/settings.js:2113` (validateMaxMindLicense) |
| Settings | "Failed to validate MaxMind license" [error] | `frontend/settings.js:2122` (validateMaxMindLicense) |
| Settings | "GeoIP database re-download started…" [info] | `frontend/settings.js:2147` (repairGeoIPDatabase) |
| Settings | "GeoIP databases repaired successfully" [success] | `frontend/settings.js:2170` (repairGeoIPDatabase) |
| Settings | "GeoIP databases re-downloaded but validation still failed" [error] | `frontend/settings.js:2172` (repairGeoIPDatabase) |
| Settings | "GeoIP repair timed out - check Status page for progress" [warning] | `frontend/settings.js:2185` (repairGeoIPDatabase) |
| Settings | dynamic: `'Failed to repair GeoIP databases: ' + error.message` [error] | `frontend/settings.js:2196` (repairGeoIPDatabase) |
| Shared | "Download started." [success] | `frontend/export.js:34` (exportCSV) |
| Shared | dynamic: `error.message \|\| 'Could not export CSV. Please try again.'` [error] | `frontend/export.js:37` (exportCSV) |
| Shared | dynamic: `'Copied: ' + text` [success] | `frontend/utils.js:350` (copyToClipboard) |
| Shared | "Failed to copy" [error] | `frontend/utils.js:365` (copyToClipboard) |

### Confirmation dialogs

Every action that asks before it acts. Losing one turns a guarded action into a one-click action.

| Page | What | Code |
|---|---|---|
| Security | showConfirmModal: dynamic: `{ title: 'Unban IP', message: 'Unban IP ' + ipWithMask + '?', confirmText: 'U...` | `frontend/app.js:906` (unbanIP) |
| Security | showConfirmModal: dynamic: `{ title: 'Ban IP', message: `Are you sure you want to permanently ban ${ipWit...` | `frontend/app.js:943` (banIP) |
| Security | showConfirmModal: dynamic: `{ title: action === 'block' ? 'Disable SMTP' : 'Re-enable SMTP', message: `${...` | `frontend/smtp-abuse.js:161` (smtpAbuseAction) |
| Queue | showConfirmModal: dynamic: `{ title: 'Retry Delivery', message: `Retry delivery of ${ids.length} message(...` | `frontend/app.js:2421` (queueBulkRetry) |
| Queue | showConfirmModal: dynamic: `{ title: 'Delete Messages', message: `Permanently delete ${ids.length} messag...` | `frontend/app.js:2428` (queueBulkDelete) |
| Queue | showConfirmModal: dynamic: `{ title: 'Delete Message', message: 'Delete this message from the queue?', co...` | `frontend/app.js:2447` (queueDeleteItem) |
| Queue | showConfirmModal: dynamic: `{ title: 'Flush Queue', message: 'Flush (retry delivery of) ALL messages in t...` | `frontend/app.js:2452` (queueFlushAll) |
| Queue | showConfirmModal: dynamic: `{ title: 'Delete All', message: 'Permanently delete ALL messages from the que...` | `frontend/app.js:2457` (queueDeleteAll) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete Message', message: 'Are you sure you want to permanently del...` | `frontend/app.js:2766` (quarantineDelete) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Not Spam', message: 'Release this message and train Rspamd that it ...` | `frontend/app.js:2771` (quarantineLearnHam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Mark as Spam', message: 'Delete this message and train Rspamd that ...` | `frontend/app.js:2776` (quarantineLearnSpam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Release Messages', message: `Release ${ids.length} quarantined mess...` | `frontend/app.js:2783` (quarantineBulkRelease) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete Messages', message: `Permanently delete ${ids.length} quaran...` | `frontend/app.js:2790` (quarantineBulkDelete) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Not Spam', message: `Release ${ids.length} message(s) and train Rsp...` | `frontend/app.js:2797` (quarantineBulkLearnHam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Mark as Spam', message: `Delete ${ids.length} message(s) and train ...` | `frontend/app.js:2804` (quarantineBulkLearnSpam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Release All', message: `Release ALL ${allIds.length} quarantined me...` | `frontend/app.js:2811` (quarantineReleaseAll) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete All', message: `Permanently delete ALL ${allIds.length} quar...` | `frontend/app.js:2818` (quarantineDeleteAll) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete Rule', message: `Delete rule "${ruleName}"?`, confirmText: '...` | `frontend/app.js:3327` (deleteQuarantineRule) |
| Spam filter | showConfirmModal: dynamic: `{ title: 'Delete Suppression', message: `Delete suppression for ${email}? Thi...` | `frontend/spam_filter.js:912` (renderSuppressionItem) |
| DMARC | showConfirmModal: dynamic: `{ title: 'Delete Report', message: `Are you sure you want to delete this ${re...` | `frontend/dmarc.js:1712` (deleteReport) |
| Mailbox stats | showConfirmModal: dynamic: `{ title: 'Reset rate limit counter', message: `Let ${user} send again straigh...` | `frontend/rate-limits.js:634` (resetRateLimitCounter) |
| Mailbox stats | showConfirmModal: dynamic: `{ title: value === 0 ? 'Remove rate limits' : 'Apply rate limit', message: va...` | `frontend/rate-limits.js:952` (applyRateLimitBulk) |
| Mailbox stats | showConfirmModal: dynamic: `{ title: 'Remove rate limit', message: `Remove the rate limit on ${name}? It ...` | `frontend/rate-limits.js:1130` (removeRateLimit) |
| Settings | showConfirmModal: dynamic: `{ title: 'Delete destination', message: `Delete "${channel ? channel.name : '...` | `frontend/notifications.js:266` (deleteNotificationChannel) |
| Settings | showFeatureDisableConfirmModal: dynamic: `purgeableNewlyDisabled` | `frontend/settings.js:1793` (renderSettings) |
| Settings | showConfirmModal: dynamic: `{ title: 'Import from ENV', message: 'Import current configuration from ENV i...` | `frontend/settings.js:1855` (renderSettings) |
| Shared | confirm: dynamic: `` | `frontend/utils.js:427` |

### Country flags

PNG flags served locally from `frontend/assets/flags/<size>/<cc>.png` (sizes 16x12, 24x18, 48x36), no emoji and no external source.

| Page | What | Code |
|---|---|---|
| Message details | renderGeoIPInfo(data.rspamd, '16x12') | `frontend/message-details.js:536` (renderOverviewTab) |
| Security | getFlagUrl(log.country_code, '16x12') | `frontend/app.js:867` (renderNetfilterData) |
| Security | getFlagUrl(d.country_code, '24x18') | `frontend/app.js:1598` (loadSecurityCountryChart) |
| Shared | getFlagUrl(rspamdData.country_code, size) | `frontend/app.js:4631` (renderGeoIPInfo) |
| Shared | getFlagUrl(record.country_code, size) | `frontend/app.js:4674` (renderGeoIPForDMARC) |

### Markdown rendering

Places that render Markdown (help pages, changelogs) through `renderMarkdown` (marked, then DOMPurify) into a `.markdown-body` element.

| Page | What | Code |
|---|---|---|
| Settings | renders `versionInfo.changelog` | `frontend/settings.js:924` (updateVersionInfoUI) |
| Settings | renders `changelogText` | `frontend/settings.js:1541` (renderSettings) |
| Modal: changelog-modal | renders `markdownContent` | `frontend/app.js:541` (showMarkdownModal) |
| Modal: changelog-modal | renders `changelog` | `frontend/app.js:4587` (showChangelogModal) |

### Controls wired in JavaScript

Buttons, tabs and fields whose behavior is attached with `addEventListener` instead of an inline handler. The automatic inventory test does not see these, so they need a manual check.

| Page | What | Code |
|---|---|---|
| Shell | click on `document` | `frontend/router.js:317` |
| Messages | click on `document` | `frontend/app.js:3625` |
| Message details | click on `messageModal` | `frontend/message-details.js:933` |
| Message details | click on `modalContent` | `frontend/message-details.js:943` |
| Security | click on `editSettingsBtn` | `frontend/app.js:2048` (loadFail2BanSettings) |
| Security | click on `editIpBtn` | `frontend/app.js:2064` (loadFail2BanSettings) |
| Security | submit on `settingsForm` | `frontend/app.js:2075` (loadFail2BanSettings) |
| Security | submit on `ipForm` | `frontend/app.js:2128` (loadFail2BanSettings) |
| Spam filter | click on `document` | `frontend/spam_filter.js:1037` (renderSuppressionItem) |
| DMARC | click on `modal` | `frontend/dmarc.js:1475` (showDmarcSyncHistory) |
| Mailbox stats | click on `document` | `frontend/mailbox-stats.js:671` (toggleDateRangePicker) |
| Settings | click on `cancelBtn` | `frontend/settings.js:114` (showBasicAuthVerifyModal) |
| Settings | click on `confirmBtn` | `frontend/settings.js:115` (showBasicAuthVerifyModal) |
| Settings | click on `overlay` | `frontend/settings.js:129` (showBasicAuthVerifyModal) |
| Settings | click on `cancelBtn` | `frontend/settings.js:204` (showFeatureDisableConfirmModal) |
| Settings | click on `confirmBtn` | `frontend/settings.js:205` (showFeatureDisableConfirmModal) |
| Settings | click on `overlay` | `frontend/settings.js:212` (showFeatureDisableConfirmModal) |
| Settings | click on `btn` | `frontend/settings.js:1678` (renderSettings) |
| Settings | change on `tabSelect` | `frontend/settings.js:1685` (renderSettings) |
| Settings | click on `btn` | `frontend/settings.js:1692` (renderSettings) |
| Settings | change on `cb` | `frontend/settings.js:1722` (renderSettings) |
| Settings | click on `closeBtn` | `frontend/settings.js:1938` (showGeoIPSetupModal) |
| Settings | click on `modal` | `frontend/settings.js:2392` (showConnectionTestModal) |
| Shared | click on `cancelBtn` | `frontend/utils.js:493` (showConfirmModal) |
| Shared | click on `okBtn` | `frontend/utils.js:494` (showConfirmModal) |
| app.js (mixed) | click on `changelogModal` | `frontend/app.js:4782` |
| app.js (mixed) | click on `changelogContent` | `frontend/app.js:4790` |

### Filters, sorting and view options

Drop-down lists in the page markup with their options. The option wording and order are part of the product.

| Page | What | Code |
|---|---|---|
| Dashboard | `dashboard-search-status`: All Statuses / Delivered / Sent / Deferred / Bounced / Rejected / Discarded (Sieve) / Expired | `frontend/index.html:928` |
| Messages | `messages-filter-direction`: All Directions / Inbound / Outbound / Internal | `frontend/index.html:1037` |
| Messages | `messages-filter-status`: All Statuses / Delivered / Deferred / Bounced / Rejected / Spam / Discarded (Sieve) | `frontend/index.html:1044` |
| Security | `netfilter-filter-action`: All Actions / BAN / UNBAN / Warning / Info | `frontend/index.html:1289` |
| Security | `netfilter-filter-country`: All Countries | `frontend/index.html:1297` |
| Quarantine | `quarantine-sort`: Newest first / Score: high to low / Score: low to high | `frontend/index.html:1468` |
| Spam filter | `suppression-filter-reason`: All Reasons / Hard Bounce / Soft Bounce / Deferred Stuck / Rejected / Manual | `frontend/index.html:1542` |
| Spam filter | `suppression-filter-active`: Active Only / All / Inactive / Expired | `frontend/index.html:1552` |
| Mailbox stats | `mailbox-stats-domain-filter`: All Domains | `frontend/index.html:2235` |
| Mailbox stats | `mailbox-stats-sort`: Sent (High to Low) / Received (High to Low) / Failure Rate (High to Low) / Quota Used (High to Low) / Username (A-Z) | `frontend/index.html:2239` |
| Logs | `logs-fontsize`: 10px / 11px / 12px / 13px / 14px / 16px | `frontend/index.html:2376` |

### Charts

Chart.js charts (local library). Check hover tooltips, legend and both themes.

| Page | What | Code |
|---|---|---|
| Security | bar chart on `ctx` | `frontend/app.js:1688` (loadSecurityCountryChart) |
| DMARC | line chart on `ctx` | `frontend/dmarc.js:592` (renderDmarcChart) |
| Mailbox stats | bar chart on `canvas.getContext('2d')` | `frontend/rate-limits.js:281` (renderRateLimitChart) |

### Colour thresholds

Values whose colour changes at a threshold (for example storage turns yellow and red, a high spam score turns red).

| Page | What | Code |
|---|---|---|
| Dashboard | `containers.stopped > 0` turns red | `frontend/app.js:1417` (loadDashboardStatusSummary) |
| Dashboard | `usedPercent > 90` turns red | `frontend/app.js:1428` (loadDashboardStatusSummary) |
| Dashboard | `usedPercent > 75` turns yellow | `frontend/app.js:1429` (loadDashboardStatusSummary) |
| Dashboard | `usedPercent > 90` turns red | `frontend/app.js:1442` (loadDashboardStatusSummary) |
| Dashboard | `usedPercent > 75` turns yellow | `frontend/app.js:1442` (loadDashboardStatusSummary) |
| Messages | `msg.spam_score >= 15` turns red | `frontend/app.js:787` (renderMessagesData) |
| Messages | `msg.spam_score >= 15` turns red | `frontend/app.js:3711` (loadMessages) |
| Message details | `score > 0` turns red | `frontend/message-details.js:821` (renderSpamTab) |
| Message details | `score < 0` turns green | `frontend/message-details.js:822` (renderSpamTab) |
| Quarantine | `item.score >= 15` turns red | `frontend/app.js:2688` (renderQuarantineData) |
| Quarantine | `sc > 0` turns red | `frontend/app.js:2929` (renderQuarantineDetailContent) |
| Quarantine | `sc < 0` turns green | `frontend/app.js:2930` (renderQuarantineDetailContent) |
| Status | `usedPercent > 90` turns red | `frontend/app.js:3936` (loadStatusStorage) |
| Status | `usedPercent > 75` turns yellow | `frontend/app.js:3937` (loadStatusStorage) |
| Status | `usedPercent > 90` turns red | `frontend/app.js:3939` (loadStatusStorage) |
| Status | `usedPercent > 75` turns yellow | `frontend/app.js:3940` (loadStatusStorage) |
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
| Security | topic "Abuse_Protection" | `frontend/index.html:1255` |
| Quarantine | topic "Quarantine" | `frontend/index.html:1411` |
| Spam filter | topic "Spam_Filter" | `frontend/index.html:1492` |
| Status | topic "IP_Blacklist_Monitor" | `frontend/index.html:1665` |
| Domains | topic "Domains" | `frontend/index.html:1774` |
| DMARC | topic "DMARC" | `frontend/index.html:1807` |
| Mailbox stats | topic "Mailbox_Stats" | `frontend/index.html:2029` |
| Mailbox stats | topic dynamic: `'${isRateLimits ? 'Rate_Limits' : 'Mailbox_Stats'}'` | `frontend/mailbox-stats.js:82` (mailboxStatsSwitchView) |

### Empty states

Text shown when a list or panel has nothing to show.

| Page | What | Code |
|---|---|---|
| Shell | "No changelog available" | `frontend/app.js:522` (loadAppVersionStatus) |
| Shell | "No changelog available" | `frontend/app.js:583` (loadMailcowVersionStatus) |
| Dashboard | "No blacklist data yet" | `frontend/app.js:4168` (loadDashboardBlacklistSummary) |
| Messages | "No messages found" | `frontend/app.js:752` (renderMessagesData) |
| Messages | "No messages found" | `frontend/app.js:3676` (loadMessages) |
| Message details | "No modal data available" | `frontend/message-details.js:35` (switchModalTab) |
| Message details | "No Postfix delivery logs available" | `frontend/message-details.js:558` (renderPostfixTab) |
| Message details | "No Postfix delivery logs available" | `frontend/message-details.js:566` (renderPostfixTab) |
| Message details | "No spam analysis data available" | `frontend/message-details.js:771` (renderSpamTab) |
| Security | "No logs found" | `frontend/app.js:826` (renderNetfilterData) |
| Security | "No matching entries" | `frontend/smtp-abuse.js:137` (renderSmtpAbusePanel) |
| Queue | "No matching queue entries" | `frontend/app.js:2250` (applyQueueFilters) |
| Quarantine | "No quarantined messages" | `frontend/app.js:2579` (loadQuarantine) |
| Quarantine | "No quarantined messages" | `frontend/app.js:2607` (renderQuarantineData) |
| Quarantine | "No actions recorded yet" | `frontend/app.js:3458` (loadQuarantineRuleHistory) |
| Status | "No container information available" | `frontend/app.js:3820` (loadStatusContainers) |
| Status | "No changelog available" | `frontend/app.js:3854` (loadStatusSystem) |
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
| Logs | "No log entries found" | `frontend/logs-viewer.js:470` (renderLogEntries) |
| Settings | "No logs available" | `frontend/notifications.js:288` (testNotificationChannel) |
| Settings | "No logs available" | `frontend/notifications.js:305` (testNotificationChannelDraft) |
| Settings | "No changelog available" | `frontend/settings.js:1512` (renderSettings) |
| Settings | "No logs available" | `frontend/settings.js:2324` (testSmtpConnection) |
| Settings | "No logs available" | `frontend/settings.js:2350` (testImapConnection) |
| Modal: changelog-modal | "No changelog available" | `frontend/app.js:4589` (showChangelogModal) |
| Modal: container-logs-modal | "No logs available" | `frontend/app.js:4865` (fetchContainerLogs) |

### Loading states

Functions that render a spinner or "Loading..." while data is fetched.

| Page | What | Code |
|---|---|---|
| Messages | 1 loading indicator(s) | `frontend/app.js:3641` (loadMessages) |
| Message details | 1 loading indicator(s) | `frontend/message-details.js:59` (viewMessageDetails) |
| Security | 1 loading indicator(s) | `frontend/app.js:1781` (loadNetfilterLogs) |
| Queue | 1 loading indicator(s) | `frontend/app.js:2200` (loadQueue) |
| Quarantine | 1 loading indicator(s) | `frontend/app.js:2559` (loadQuarantine) |
| Quarantine | 1 loading indicator(s) | `frontend/app.js:2877` (showQuarantineDetails) |
| Quarantine | 1 loading indicator(s) | `frontend/app.js:3450` (loadQuarantineRuleHistory) |
| Status | 2 loading indicator(s) | `frontend/app.js:4022` (checkBlacklists) |
| Status | 1 loading indicator(s) | `frontend/app.js:4534` (triggerBackgroundJob) |
| Domains | 1 loading indicator(s) | `frontend/domains.js:641` (checkAllDomainsDNS) |
| DMARC | 1 loading indicator(s) | `frontend/dmarc.js:134` (loadDmarc) |
| Logs | 1 loading indicator(s) | `frontend/logs-viewer.js:1107` (loadDateRangeLogs) |
| Settings | 3 loading indicator(s) | `frontend/settings.js:1558` (renderSettings) |
| Settings | 2 loading indicator(s) | `frontend/settings.js:1895` (showGeoIPSetupModal) |
| Settings | 1 loading indicator(s) | `frontend/settings.js:2085` (validateMaxMindLicense) |
| Settings | 1 loading indicator(s) | `frontend/settings.js:2131` (repairGeoIPDatabase) |
| Settings | 1 loading indicator(s) | `frontend/settings.js:2289` (renderGeoIPDbStatus) |
| Shared | 1 loading indicator(s) | `frontend/utils.js:548` (renderJobCard) |

### Persisted preferences

Settings the browser remembers between visits.

| Page | What | Code |
|---|---|---|
| Shell | localStorage getItem "theme" | `frontend/app.js:4740` (initDarkMode) |
| Shell | localStorage setItem "theme" | `frontend/app.js:4755` (toggleDarkMode) |
| Logs | localStorage getItem "logsNewestFirst" | `frontend/logs-viewer.js:17` |
| Logs | localStorage setItem "logsNewestFirst" | `frontend/logs-viewer.js:543` (toggleLogSortOrder) |

### Auto refresh and timers

Background refreshes and polling.

| Page | What | Code |
|---|---|---|
| Shell | every AUTO_REFRESH_INTERVAL ms | `frontend/app.js:641` (startAutoRefresh) |
| Status | every 1000 ms | `frontend/app.js:4059` (checkBlacklists) |
| Settings | every 2000 ms | `frontend/settings.js:2016` (showGeoIPSetupModal) |
| Modal: container-logs-modal | every 2000 ms | `frontend/app.js:4901` (loadContainerLogs) |

### Address bar and deep links

Places that change the URL so a view can be bookmarked or shared.

| Page | What | Code |
|---|---|---|
| Shell | replaceState | `frontend/app.js:1187` (switchTab) |
| Shell | pushState | `frontend/router.js:154` (navigateTo) |
| Shell | replaceState | `frontend/router.js:222` (initRouter) |
| DMARC | pushState | `frontend/dmarc.js:467` (loadDomainOverview) |
| DMARC | pushState | `frontend/dmarc.js:1056` (loadReportDetails) |
| DMARC | pushState | `frontend/dmarc.js:1162` (loadSourceDetails) |

### Keyboard handling

Key handlers; the keys are read from the handler body.

| Page | What | Code |
|---|---|---|
| Message details | keydown: Escape | `frontend/message-details.js:949` |
| Settings | keydown: Escape, Enter | `frontend/settings.js:118` (showBasicAuthVerifyModal) |
| Settings | keydown: Escape, Enter | `frontend/settings.js:207` (showFeatureDisableConfirmModal) |
| Modal: changelog-modal | keydown: Escape | `frontend/app.js:4770` |

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
