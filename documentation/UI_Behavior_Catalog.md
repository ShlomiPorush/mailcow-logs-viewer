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
- **Country flags are PNG images, never emoji.** Most use is on desktop, and Windows does not render flag emoji (it shows two letters instead). The images live in `frontend/assets/flags/` in three sizes.
- **Markdown keeps its styling.** Help pages and changelogs are rendered by `renderMarkdown` (marked, then DOMPurify, `frontend/utils.js`) into a `.markdown-body` element inside `#changelog-content` or `.update-changelog-content`. Their look comes from the local `github-markdown.min.css` plus the overrides in the `<style>` block of `index.html` (the `.markdown-body` rules, about lines 270 to 470), which also carry the dark theme. A redesign that renames these containers or drops those rules breaks every help page and changelog, even though nothing else changes.
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
| Help topics | Each help button opens the listed topic. |
| Empty states | An empty list shows its sentence, not a blank area or a broken table. |
| Loading states | A spinner or "Loading..." appears while data loads; the page never shows stale data without an indicator. |
| Persisted preferences | The preference survives a reload. |
| Auto refresh | The page refreshes on its own at the listed interval, and stops when you leave it. |
| Address bar | The URL changes as listed, so the view can be bookmarked, shared and reloaded. |
| Keyboard | The listed keys still close or confirm the dialog. |

## Open questions and findings

- **Dead code: the old Postfix and Rspamd log lists.** `loadPostfixLogs` and `loadRspamdLogs` (`frontend/app.js`) render into `#postfix-logs` and `#rspamd-logs`, which have not existed in `index.html` at any point in the repository history. Nothing reaches them: the only callers are their own pagination (rendered inside them) and `applyPostfixFilters`, `clearPostfixFilters`, `applyRspamdFilters` and `clearRspamdFilters`, which nothing calls. Their rows are listed under "Not rendered (possible dead code)". Remove them rather than port them.
- **Dead code: `getFlagEmoji`** (`frontend/dmarc.js`) is defined and never called, in line with the PNG-only rule above.

<!-- generated:start (node .github/scripts/ui-catalog.cjs --write) -->

## Reference tables

Generated from the code. Do not edit by hand; run `node .github/scripts/ui-catalog.cjs --write` after a change.

| Behaviour | Count |
|---|---|
| [Click to copy](#click-to-copy) | 34 |
| [Tooltips](#tooltips) | 99 |
| [Toasts](#toasts) | 133 |
| [Confirmation dialogs](#confirmation-dialogs) | 27 |
| [Country flags](#country-flags) | 5 |
| [Markdown rendering](#markdown-rendering) | 4 |
| [Help topics](#help-topics) | 8 |
| [Empty states](#empty-states) | 37 |
| [Loading states](#loading-states) | 20 |
| [Persisted preferences](#persisted-preferences) | 4 |
| [Auto refresh and timers](#auto-refresh-and-timers) | 4 |
| [Address bar and deep links](#address-bar-and-deep-links) | 6 |
| [Keyboard handling](#keyboard-handling) | 4 |
| [Badge colours](#badge-colours) | 11 |

### Click to copy

Fields that copy their value on click (hover shows a copy icon and "Click to copy").

| Page | What | Code |
|---|---|---|
| Message details | copies: `r` | `frontend/message-details.js:493` (renderOverviewTab) |
| Message details | copies: `recipientsToDisplay[0] \|\| '-'` | `frontend/message-details.js:503` (renderOverviewTab) |
| Message details | copies: `data.recipient` | `frontend/message-details.js:511` (renderOverviewTab) |
| Message details | copies: `data.sender \|\| '-'` | `frontend/message-details.js:526` (renderOverviewTab) |
| Message details | copies: `data.queue_id` | `frontend/message-details.js:553` (renderOverviewTab) |
| Message details | copies: `data.message_id` | `frontend/message-details.js:559` (renderOverviewTab) |
| Message details | copies: `data.rspamd.user` | `frontend/message-details.js:621` (renderOverviewTab) |
| Message details | copies: `sender` | `frontend/message-details.js:765` (renderPostfixTab) |
| Message details | copies: `Array.from(recipientsFromPostfix)[0]` | `frontend/message-details.js:771` (renderPostfixTab) |
| Message details | copies: `data.recipients[0]` | `frontend/message-details.js:776` (renderPostfixTab) |
| Message details | copies: `queueId` | `frontend/message-details.js:788` (renderPostfixTab) |
| Message details | copies: `clientIp` | `frontend/message-details.js:794` (renderPostfixTab) |
| Message details | copies: `recipient` | `frontend/message-details.js:816` (renderPostfixTab) |
| Message details | copies: `log.ip` | `frontend/message-details.js:974` (renderNetfilterTab) |
| Message details | copies: `log.username` | `frontend/message-details.js:978` (renderNetfilterTab) |
| Security | copies: `log.ip` | `frontend/app.js:888` (renderNetfilterData) |
| Security | copies: `log.username` | `frontend/app.js:889` (renderNetfilterData) |
| Queue | copies: `item.sender` | `frontend/app.js:2519` (applyQueueFilters) |
| Queue | copies: `qid` | `frontend/app.js:2520` (applyQueueFilters) |
| Queue | copies: `emailOnly` | `frontend/app.js:2535` (applyQueueFilters) |
| Quarantine | copies: `item.sender \|\| 'Unknown'` | `frontend/app.js:2876` (renderQuarantineData) |
| Quarantine | copies: `item.rcpt \|\| 'Unknown'` | `frontend/app.js:2880` (renderQuarantineData) |
| Quarantine | copies: `item.qid` | `frontend/app.js:2893` (renderQuarantineData) |
| Quarantine | copies: `r.address` | `frontend/app.js:3125` (renderQuarantineDetailContent) |
| Quarantine | copies: `data.subject \|\| '-'` | `frontend/app.js:3162` (renderQuarantineDetailContent) |
| Quarantine | copies: `data.header_from \|\| '-'` | `frontend/app.js:3167` (renderQuarantineDetailContent) |
| Quarantine | copies: `data.env_from \|\| '-'` | `frontend/app.js:3171` (renderQuarantineDetailContent) |
| Spam filter | copies: `displayEmail` | `frontend/spam_filter.js:510` (renderSuppressionItem) |
| Status | copies: `item.message_id \|\| 'N/A'` | `frontend/app.js:4609` (renderStatusCorrelation) |
| Status | copies: `item.sender \|\| 'N/A'` | `frontend/app.js:4613` (renderStatusCorrelation) |
| Status | copies: `item.recipient \|\| 'N/A'` | `frontend/app.js:4613` (renderStatusCorrelation) |
| Shared | copies: `ip` | `frontend/app.js:4834` (renderGeoIPInfo) |
| Shared | copies: `ip` | `frontend/app.js:4841` (renderGeoIPInfo) |
| Shared | copyToClipboard: `'${safeText}'` | `frontend/utils.js:375` (copyableText) |

### Tooltips

Native `title` tooltips. Dynamic ones show the expression that builds the text.

| Page | What | Code |
|---|---|---|
| Shell | "mailcow connection status" | `frontend/index.html:527` |
| Shell | "mailcow update available" | `frontend/index.html:536` |
| Shell | "View Container Logs" | `frontend/index.html:2630` |
| Dashboard | "Dismiss" | `frontend/app.js:1359` (loadDashboardSecurityAlerts) |
| Dashboard | dynamic: `${escapeHtml(msg.subject \|\| 'No subject')}` | `frontend/app.js:1501` (loadRecentActivity) |
| Messages | dynamic: `${escapeHtml(msg.subject \|\| 'No subject')}` | `frontend/app.js:773` (renderMessagesData) |
| Messages | dynamic: `${msg.final_status \|\| (msg.is_complete ? 'Correlation complete' : 'Waiting ...` | `frontend/app.js:779` (renderMessagesData) |
| Messages | "Queue ID" | `frontend/app.js:789` (renderMessagesData) |
| Messages | dynamic: `Message ID: ${escapeHtml(msg.message_id)}` | `frontend/app.js:790` (renderMessagesData) |
| Messages | dynamic: `${escapeHtml(msg.subject \|\| 'No subject')}` | `frontend/app.js:3899` (loadMessages) |
| Messages | dynamic: `${msg.final_status \|\| (msg.is_complete ? 'Correlation complete' : 'Waiting ...` | `frontend/app.js:3905` (loadMessages) |
| Messages | "Queue ID" | `frontend/app.js:3915` (loadMessages) |
| Messages | dynamic: `Message ID: ${escapeHtml(msg.message_id)}` | `frontend/app.js:3916` (loadMessages) |
| Message details | "This delivery attempt never reached a final outcome" | `frontend/message-details.js:419` (renderRelatedDeliveries) |
| Message details | dynamic: `${escapeHtml(data.subject)}` | `frontend/message-details.js:531` (renderOverviewTab) |
| Message details | dynamic: `${escapeHtml(data.message_id)}` | `frontend/message-details.js:559` (renderOverviewTab) |
| Message details | dynamic: `${escapeHtml(sender)}` | `frontend/message-details.js:765` (renderPostfixTab) |
| Message details | dynamic: `${escapeHtml(relay)}` | `frontend/message-details.js:800` (renderPostfixTab) |
| Security | dynamic: `Unban ${escapeHtml(log.ip)}/32` | `frontend/app.js:895` (renderNetfilterData) |
| Security | dynamic: `Ban ${escapeHtml(log.ip)}/32` | `frontend/app.js:896` (renderNetfilterData) |
| Security | "This feature is new - please report any issues on GitHub" | `frontend/index.html:1247` |
| Security | "Help - Abuse Protection" | `frontend/index.html:1251` |
| Queue | "Retry delivery" | `frontend/app.js:2544` (applyQueueFilters) |
| Queue | "Release from hold" | `frontend/app.js:2550` (applyQueueFilters) |
| Queue | "Hold message" | `frontend/app.js:2556` (applyQueueFilters) |
| Queue | "Delete from queue" | `frontend/app.js:2562` (applyQueueFilters) |
| Queue | dynamic: `Suppress ${escapeHtml(emailOnly)}` | `frontend/app.js:2571` (applyQueueFilters) |
| Quarantine | "Click to view details" | `frontend/app.js:2882` (renderQuarantineData) |
| Quarantine | "Queue ID" | `frontend/app.js:2893` (renderQuarantineData) |
| Quarantine | "View details" | `frontend/app.js:2897` (renderQuarantineData) |
| Quarantine | "Release message" | `frontend/app.js:2903` (renderQuarantineData) |
| Quarantine | "Delete message" | `frontend/app.js:2908` (renderQuarantineData) |
| Quarantine | "Release & train as Not Spam" | `frontend/app.js:2913` (renderQuarantineData) |
| Quarantine | "Delete & train as Spam" | `frontend/app.js:2918` (renderQuarantineData) |
| Quarantine | "Create auto-rule from this email" | `frontend/app.js:2923` (renderQuarantineData) |
| Quarantine | dynamic: `${escapeHtml(opts)}` | `frontend/app.js:3143` (renderQuarantineDetailContent) |
| Quarantine | dynamic: `${rule.enabled ? 'Click to disable this rule' : 'Click to enable this rule'}` | `frontend/app.js:3315` (loadQuarantineRules) |
| Quarantine | "Edit" | `frontend/app.js:3321` (loadQuarantineRules) |
| Quarantine | "Delete" | `frontend/app.js:3325` (loadQuarantineRules) |
| Quarantine | dynamic: `${escapeHtml(m.subject \|\| '')}` | `frontend/app.js:3587` (testQuarantineRules) |
| Quarantine | dynamic: `${escapeHtml(log.sender \|\| '')} → ${escapeHtml(log.recipient \|\| '')}` | `frontend/app.js:3671` (loadQuarantineRuleHistory) |
| Quarantine | dynamic: `Rule: ${escapeHtml(log.rule_name \|\| '')}` | `frontend/app.js:3674` (loadQuarantineRuleHistory) |
| Quarantine | "Help - Quarantine Auto-Rules" | `frontend/index.html:1405` |
| Spam filter | "Help - Spam Filter" | `frontend/index.html:1488` |
| Spam filter | "Clear all filters" | `frontend/index.html:1556` |
| Spam filter | "Sync suppression list to Rspamd" | `frontend/index.html:1568` |
| Spam filter | "Synced to Rspamd" | `frontend/spam_filter.js:490` (renderSuppressionItem) |
| Spam filter | "Pending sync to Rspamd" | `frontend/spam_filter.js:492` (renderSuppressionItem) |
| Spam filter | "Will be removed from Rspamd on next sync" | `frontend/spam_filter.js:497` (renderSuppressionItem) |
| Spam filter | "' + escapeHtml(s.email) + '" | `frontend/spam_filter.js:511` (renderSuppressionItem) |
| Spam filter | dynamic: `${escapeHtml(s.notes)}` | `frontend/spam_filter.js:522` (renderSuppressionItem) |
| Spam filter | "Edit suppression" | `frontend/spam_filter.js:527` (renderSuppressionItem) |
| Spam filter | dynamic: `${s.active ? 'Deactivate' : 'Reactivate'}` | `frontend/spam_filter.js:530` (renderSuppressionItem) |
| Spam filter | "Delete permanently" | `frontend/spam_filter.js:533` (renderSuppressionItem) |
| Status | dynamic: `${escapeHtml(detail)}` | `frontend/app.js:4536` (renderBlacklistStatus) |
| Status | dynamic: `${escapeHtml(detail)}` | `frontend/app.js:4538` (renderBlacklistStatus) |
| Status | "View info" | `frontend/app.js:4539` (renderBlacklistStatus) |
| Status | "Help - IP Blacklist Monitor" | `frontend/index.html:1661` |
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
| Domains | "Help - Domains Information" | `frontend/index.html:1770` |
| DMARC | "DMARC Reports" | `frontend/dmarc.js:375` (loadDmarcDomains) |
| DMARC | "TLS Reports" | `frontend/dmarc.js:376` (loadDmarcDomains) |
| DMARC | "Delete report" | `frontend/dmarc.js:1655` (renderReportsManagementTable) |
| DMARC | "Delete" | `frontend/dmarc.js:1690` (renderReportsManagementTable) |
| DMARC | "Help - DMARC Information" | `frontend/index.html:1803` |
| Mailbox stats | "Help - Mailbox Statistics" | `frontend/index.html:2025` |
| Mailbox stats | "Address on a mailcow alias domain that points at this mailbox" | `frontend/mailbox-stats.js:556` (renderMailboxStatsAccordion) |
| Logs | "Pause/Resume live updates" | `frontend/index.html:2332` |
| Logs | "Live mode - show latest logs" | `frontend/index.html:2342` |
| Logs | "Auto-scroll to new entries" | `frontend/index.html:2352` |
| Logs | "Toggle sort order (newest at bottom / newest at top)" | `frontend/index.html:2362` |
| Logs | "Toggle word wrap" | `frontend/index.html:2383` |
| Logs | "Search" | `frontend/index.html:2400` |
| Logs | "Clear search" | `frontend/index.html:2407` |
| Logs | "Clear display" | `frontend/index.html:2417` |
| Logs | "From date" | `frontend/index.html:2445` |
| Logs | "To date" | `frontend/index.html:2450` |
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
| Not rendered (possible dead code) | dynamic: `${escapeHtml(log.subject \|\| 'No subject')}` | `frontend/app.js:1718` (loadRspamdLogs) |
| Modal: container-logs-modal | "Refresh" | `frontend/index.html:2657` |
| Modal: container-logs-modal | "Close" | `frontend/index.html:2665` |

### Toasts

Transient notifications from `showToast(message, type)` (utils.js). Type defaults to info.

| Page | What | Code |
|---|---|---|
| Messages | "Please select both start and end dates" [warning] | `frontend/app.js:3798` (applyMessagesCustomDateRange) |
| Messages | "Start date must be before end date" [warning] | `frontend/app.js:3807` (applyMessagesCustomDateRange) |
| Security | "IP ' + ip + ' unbanned successfully" [success] | `frontend/app.js:923` (unbanIP) |
| Security | dynamic: `'Failed to unban: ' + (result.msg \|\| result.detail \|\| 'Unknown error')` [error] | `frontend/app.js:930` (unbanIP) |
| Security | dynamic: `'Failed to unban IP: ' + err.message` [error] | `frontend/app.js:937` (unbanIP) |
| Security | dynamic: ``IP ${ip} added to blacklist`` [success] | `frontend/app.js:964` (banIP) |
| Security | dynamic: `'Failed to ban: ' + (result.msg \|\| result.detail \|\| 'Unknown error')` [error] | `frontend/app.js:971` (banIP) |
| Security | dynamic: `'Failed to ban IP: ' + err.message` [error] | `frontend/app.js:978` (banIP) |
| Security | "Failed to dismiss alert" [error] | `frontend/app.js:1386` (acknowledgeSecurityAlert) |
| Security | "All security alerts dismissed" [success] | `frontend/app.js:1394` (acknowledgeAllSecurityAlerts) |
| Security | "Failed to dismiss alerts" [error] | `frontend/app.js:1396` (acknowledgeAllSecurityAlerts) |
| Security | "Fail2Ban settings saved successfully" [success] | `frontend/app.js:2316` (loadFail2BanSettings) |
| Security | dynamic: `'Failed to save Fail2Ban settings: ' + (result.msg \|\| result.detail \|\| 'U...` [error] | `frontend/app.js:2320` (loadFail2BanSettings) |
| Security | dynamic: `'Failed to save Fail2Ban settings: ' + err.message` [error] | `frontend/app.js:2323` (loadFail2BanSettings) |
| Security | "Fail2Ban IP lists saved successfully" [success] | `frontend/app.js:2369` (loadFail2BanSettings) |
| Security | dynamic: `'Failed to save Fail2Ban IP lists: ' + (result.msg \|\| result.detail \|\| 'U...` [error] | `frontend/app.js:2372` (loadFail2BanSettings) |
| Security | dynamic: `'Failed to save Fail2Ban IP lists: ' + err.message` [error] | `frontend/app.js:2375` (loadFail2BanSettings) |
| Security | dynamic: `detail.detail \|\| `Could not ${action} SMTP`` [error] | `frontend/smtp-abuse.js:176` (smtpAbuseAction) |
| Security | dynamic: `action === 'block' ? 'SMTP disabled' : 'SMTP re-enabled'` [success] | `frontend/smtp-abuse.js:179` (smtpAbuseAction) |
| Security | dynamic: ``Could not ${action} SMTP`` [error] | `frontend/smtp-abuse.js:182` (smtpAbuseAction) |
| Security | dynamic: `detail.detail \|\| 'Could not save whitelist'` [error] | `frontend/smtp-abuse.js:209` (saveSmtpAbuseWhitelist) |
| Security | "Whitelist saved" [success] | `frontend/smtp-abuse.js:213` (saveSmtpAbuseWhitelist) |
| Security | "Could not save whitelist" [error] | `frontend/smtp-abuse.js:216` (saveSmtpAbuseWhitelist) |
| Security | "Could not remove whitelist entry" [error] | `frontend/smtp-abuse.js:224` (removeSmtpAbuseWhitelist) |
| Security | "Whitelist entry removed" [success] | `frontend/smtp-abuse.js:225` (removeSmtpAbuseWhitelist) |
| Security | "Could not remove whitelist entry" [error] | `frontend/smtp-abuse.js:228` (removeSmtpAbuseWhitelist) |
| Queue | dynamic: `result.msg \|\| `${labels[action] \|\| action} completed`` [success] | `frontend/app.js:2681` (queueAction) |
| Queue | dynamic: ``Queue action failed: ` + (result.msg \|\| result.detail \|\| 'Unknown error')` [error] | `frontend/app.js:2685` (queueAction) |
| Queue | dynamic: ``Queue action failed: ` + err.message` [error] | `frontend/app.js:2688` (queueAction) |
| Queue | dynamic: `result.msg \|\| 'Message deleted from queue'` [success] | `frontend/app.js:2708` (queueDeleteRequest) |
| Queue | dynamic: `'Failed to delete from queue: ' + (result.msg \|\| result.detail \|\| 'Unknow...` [error] | `frontend/app.js:2712` (queueDeleteRequest) |
| Queue | dynamic: `'Failed to delete from queue: ' + err.message` [error] | `frontend/app.js:2715` (queueDeleteRequest) |
| Quarantine | dynamic: `result.msg \|\| `Message(s) ${actionLabels[action] \|\| action} successfully`` [success] | `frontend/app.js:3049` (quarantineAction) |
| Quarantine | dynamic: ``Failed to ${action} message(s): ` + (result.msg \|\| result.detail \|\| 'Unk...` [error] | `frontend/app.js:3053` (quarantineAction) |
| Quarantine | dynamic: ``Failed to ${action} message(s): ` + err.message` [error] | `frontend/app.js:3056` (quarantineAction) |
| Quarantine | "Rule not found" [error] | `frontend/app.js:3345` (showEditQuarantineRuleModal) |
| Quarantine | "Rule name is required" [error] | `frontend/app.js:3492` (saveQuarantineRule) |
| Quarantine | "Match value is required" [error] | `frontend/app.js:3493` (saveQuarantineRule) |
| Quarantine | dynamic: `isEdit ? 'Rule updated' : 'Rule created'` [success] | `frontend/app.js:3525` (saveQuarantineRule) |
| Quarantine | dynamic: `'Failed to save rule: ' + err.message` [error] | `frontend/app.js:3528` (saveQuarantineRule) |
| Quarantine | "Rule deleted" [success] | `frontend/app.js:3539` (deleteQuarantineRule) |
| Quarantine | dynamic: `'Failed to delete rule: ' + err.message` [error] | `frontend/app.js:3542` (deleteQuarantineRule) |
| Quarantine | dynamic: ``Rule ${rule.enabled ? 'enabled' : 'disabled'}`` [success] | `frontend/app.js:3552` (toggleQuarantineRule) |
| Quarantine | dynamic: `'Failed to toggle rule: ' + err.message` [error] | `frontend/app.js:3555` (toggleQuarantineRule) |
| Quarantine | "Testing rules against quarantine..." [info] | `frontend/app.js:3561` (testQuarantineRules) |
| Quarantine | dynamic: ``No matches found (${data.total_quarantine} quarantine items checked)`` [info] | `frontend/app.js:3568` (testQuarantineRules) |
| Quarantine | dynamic: `'Test failed: ' + err.message` [error] | `frontend/app.js:3636` (testQuarantineRules) |
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
| Status | "Starting blacklist check..." [info] | `frontend/app.js:4236` (checkBlacklists) |
| Status | "Blacklist check completed" [success] | `frontend/app.js:4282` (checkBlacklists) |
| Status | dynamic: ``Check completed for ${host}`` [success] | `frontend/app.js:4310` (checkBlacklists) |
| Status | dynamic: ``Failed to check: ${error.message}`` [error] | `frontend/app.js:4319` (checkBlacklists) |
| Status | dynamic: ``Job "${displayName}" started successfully`` [success] | `frontend/app.js:4753` (triggerBackgroundJob) |
| Status | dynamic: ``Job "${displayName}" is already running`` [warning] | `frontend/app.js:4762` (triggerBackgroundJob) |
| Status | dynamic: ``Failed to start job: ${error.message}`` [error] | `frontend/app.js:4765` (triggerBackgroundJob) |
| Domains | "DNS check already in progress" [warning] | `frontend/domains.js:634` (checkAllDomainsDNS) |
| Domains | dynamic: ``✓ Checked ${result.domains_checked} domains`` [success] | `frontend/domains.js:654` (checkAllDomainsDNS) |
| Domains | "DNS check failed" [error] | `frontend/domains.js:657` (checkAllDomainsDNS) |
| Domains | "Failed to check DNS" [error] | `frontend/domains.js:661` (checkAllDomainsDNS) |
| Domains | "DNS check already in progress" [warning] | `frontend/domains.js:675` (checkSingleDomainDNS) |
| Domains | dynamic: ``Checking DNS for ${domainName}...`` [info] | `frontend/domains.js:680` (checkSingleDomainDNS) |
| Domains | dynamic: ``✓ DNS checked for ${domainName}`` [success] | `frontend/domains.js:694` (checkSingleDomainDNS) |
| Domains | dynamic: ``Failed to check DNS for ${domainName}`` [error] | `frontend/domains.js:782` (checkSingleDomainDNS) |
| Domains | "Failed to check DNS" [error] | `frontend/domains.js:786` (checkSingleDomainDNS) |
| DMARC | "Manual upload is disabled" [error] | `frontend/dmarc.js:1325` (uploadDmarcReport) |
| DMARC | dynamic: ``${reportType} report uploaded: ${count} ${countLabel}`` [success] | `frontend/dmarc.js:1338` (uploadDmarcReport) |
| DMARC | dynamic: ``${reportType} report already exists`` [warning] | `frontend/dmarc.js:1350` (uploadDmarcReport) |
| DMARC | "Failed to upload report" [error] | `frontend/dmarc.js:1355` (uploadDmarcReport) |
| DMARC | "IMAP sync is not enabled" [error] | `frontend/dmarc.js:1433` (triggerDmarcSync) |
| DMARC | "Sync is already in progress" [info] | `frontend/dmarc.js:1448` (triggerDmarcSync) |
| DMARC | "IMAP sync started" [success] | `frontend/dmarc.js:1450` (triggerDmarcSync) |
| DMARC | "Failed to start sync" [error] | `frontend/dmarc.js:1464` (triggerDmarcSync) |
| DMARC | "Report deletion is disabled" [error] | `frontend/dmarc.js:1731` (deleteReport) |
| DMARC | dynamic: ``${reportType.toUpperCase()} report deleted`` [success] | `frontend/dmarc.js:1739` (deleteReport) |
| DMARC | "Failed to delete report" [error] | `frontend/dmarc.js:1753` (deleteReport) |
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
| Security | showConfirmModal: dynamic: `{ title: 'Unban IP', message: 'Unban IP ' + ipWithMask + '?', confirmText: 'U...` | `frontend/app.js:910` (unbanIP) |
| Security | showConfirmModal: dynamic: `{ title: 'Ban IP', message: `Are you sure you want to permanently ban ${ipWit...` | `frontend/app.js:947` (banIP) |
| Security | showConfirmModal: dynamic: `{ title: action === 'block' ? 'Disable SMTP' : 'Re-enable SMTP', message: `${...` | `frontend/smtp-abuse.js:161` (smtpAbuseAction) |
| Queue | showConfirmModal: dynamic: `{ title: 'Retry Delivery', message: `Retry delivery of ${ids.length} message(...` | `frontend/app.js:2627` (queueBulkRetry) |
| Queue | showConfirmModal: dynamic: `{ title: 'Delete Messages', message: `Permanently delete ${ids.length} messag...` | `frontend/app.js:2634` (queueBulkDelete) |
| Queue | showConfirmModal: dynamic: `{ title: 'Delete Message', message: 'Delete this message from the queue?', co...` | `frontend/app.js:2653` (queueDeleteItem) |
| Queue | showConfirmModal: dynamic: `{ title: 'Flush Queue', message: 'Flush (retry delivery of) ALL messages in t...` | `frontend/app.js:2658` (queueFlushAll) |
| Queue | showConfirmModal: dynamic: `{ title: 'Delete All', message: 'Permanently delete ALL messages from the que...` | `frontend/app.js:2663` (queueDeleteAll) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete Message', message: 'Are you sure you want to permanently del...` | `frontend/app.js:2972` (quarantineDelete) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Not Spam', message: 'Release this message and train Rspamd that it ...` | `frontend/app.js:2977` (quarantineLearnHam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Mark as Spam', message: 'Delete this message and train Rspamd that ...` | `frontend/app.js:2982` (quarantineLearnSpam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Release Messages', message: `Release ${ids.length} quarantined mess...` | `frontend/app.js:2989` (quarantineBulkRelease) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete Messages', message: `Permanently delete ${ids.length} quaran...` | `frontend/app.js:2996` (quarantineBulkDelete) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Not Spam', message: `Release ${ids.length} message(s) and train Rsp...` | `frontend/app.js:3003` (quarantineBulkLearnHam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Mark as Spam', message: `Delete ${ids.length} message(s) and train ...` | `frontend/app.js:3010` (quarantineBulkLearnSpam) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Release All', message: `Release ALL ${allIds.length} quarantined me...` | `frontend/app.js:3017` (quarantineReleaseAll) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete All', message: `Permanently delete ALL ${allIds.length} quar...` | `frontend/app.js:3024` (quarantineDeleteAll) |
| Quarantine | showConfirmModal: dynamic: `{ title: 'Delete Rule', message: `Delete rule "${ruleName}"?`, confirmText: '...` | `frontend/app.js:3533` (deleteQuarantineRule) |
| Spam filter | showConfirmModal: dynamic: `{ title: 'Delete Suppression', message: `Delete suppression for ${email}? Thi...` | `frontend/spam_filter.js:912` (renderSuppressionItem) |
| DMARC | showConfirmModal: dynamic: `{ title: 'Delete Report', message: `Are you sure you want to delete this ${re...` | `frontend/dmarc.js:1721` (deleteReport) |
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
| Message details | renderGeoIPInfo(data.rspamd, '16x12') | `frontend/message-details.js:620` (renderOverviewTab) |
| Security | getFlagUrl(log.country_code, '16x12') | `frontend/app.js:871` (renderNetfilterData) |
| Security | getFlagUrl(d.country_code, '24x18') | `frontend/app.js:1804` (loadSecurityCountryChart) |
| Shared | getFlagUrl(rspamdData.country_code, size) | `frontend/app.js:4837` (renderGeoIPInfo) |
| Shared | getFlagUrl(record.country_code, size) | `frontend/app.js:4880` (renderGeoIPForDMARC) |

### Markdown rendering

Places that render Markdown (help pages, changelogs) through `renderMarkdown` (marked, then DOMPurify) into a `.markdown-body` element.

| Page | What | Code |
|---|---|---|
| Settings | renders `versionInfo.changelog` | `frontend/settings.js:924` (updateVersionInfoUI) |
| Settings | renders `changelogText` | `frontend/settings.js:1541` (renderSettings) |
| Modal: changelog-modal | renders `markdownContent` | `frontend/app.js:545` (showMarkdownModal) |
| Modal: changelog-modal | renders `changelog` | `frontend/app.js:4793` (showChangelogModal) |

### Help topics

In-app help buttons; the topic is the Markdown file name under documentation/HelpDocs.

| Page | What | Code |
|---|---|---|
| Security | topic "Abuse_Protection" | `frontend/index.html:1249` |
| Quarantine | topic "Quarantine" | `frontend/index.html:1405` |
| Spam filter | topic "Spam_Filter" | `frontend/index.html:1486` |
| Status | topic "IP_Blacklist_Monitor" | `frontend/index.html:1659` |
| Domains | topic "Domains" | `frontend/index.html:1768` |
| DMARC | topic "DMARC" | `frontend/index.html:1801` |
| Mailbox stats | topic "Mailbox_Stats" | `frontend/index.html:2023` |
| Mailbox stats | topic dynamic: `'${isRateLimits ? 'Rate_Limits' : 'Mailbox_Stats'}'` | `frontend/mailbox-stats.js:82` (mailboxStatsSwitchView) |

### Empty states

Text shown when a list or panel has nothing to show.

| Page | What | Code |
|---|---|---|
| Shell | "No changelog available" | `frontend/app.js:526` (loadAppVersionStatus) |
| Shell | "No changelog available" | `frontend/app.js:587` (loadMailcowVersionStatus) |
| Dashboard | "No blacklist data yet" | `frontend/app.js:4374` (loadDashboardBlacklistSummary) |
| Messages | "No messages found" | `frontend/app.js:756` (renderMessagesData) |
| Messages | "No messages found" | `frontend/app.js:3882` (loadMessages) |
| Message details | "No modal data available" | `frontend/message-details.js:119` (switchModalTab) |
| Message details | "No Postfix delivery logs available" | `frontend/message-details.js:642` (renderPostfixTab) |
| Message details | "No Postfix delivery logs available" | `frontend/message-details.js:650` (renderPostfixTab) |
| Message details | "No spam analysis data available" | `frontend/message-details.js:855` (renderSpamTab) |
| Security | "No logs found" | `frontend/app.js:830` (renderNetfilterData) |
| Security | "No matching entries" | `frontend/smtp-abuse.js:137` (renderSmtpAbusePanel) |
| Queue | "No matching queue entries" | `frontend/app.js:2456` (applyQueueFilters) |
| Quarantine | "No quarantined messages" | `frontend/app.js:2785` (loadQuarantine) |
| Quarantine | "No quarantined messages" | `frontend/app.js:2813` (renderQuarantineData) |
| Quarantine | "No actions recorded yet" | `frontend/app.js:3664` (loadQuarantineRuleHistory) |
| Status | "No container information available" | `frontend/app.js:4026` (loadStatusContainers) |
| Status | "No changelog available" | `frontend/app.js:4060` (loadStatusSystem) |
| Domains | "No domains found" | `frontend/domains.js:83` (renderDomains) |
| Domains | "No domains with DNS issues found" | `frontend/domains.js:216` (filterDomains) |
| Domains | "No domains found matching" | `frontend/domains.js:217` (filterDomains) |
| DMARC | "No daily reports available" | `frontend/dmarc.js:640` (loadDomainReports) |
| DMARC | "No sources found" | `frontend/dmarc.js:698` (loadDomainSources) |
| DMARC | "No sources found" | `frontend/dmarc.js:1097` (loadReportDetails) |
| DMARC | "No data found" | `frontend/dmarc.js:1217` (loadSourceDetails) |
| DMARC | "No sync history yet" | `frontend/dmarc.js:1491` (showDmarcSyncHistory) |
| DMARC | "No reports found" | `frontend/dmarc.js:1607` (renderReportsManagementTable) |
| Mailbox stats | "No mailboxes found" | `frontend/mailbox-stats.js:301` (renderMailboxStatsAccordion) |
| Logs | "No log entries found" | `frontend/logs-viewer.js:470` (renderLogEntries) |
| Settings | "No logs available" | `frontend/notifications.js:288` (testNotificationChannel) |
| Settings | "No logs available" | `frontend/notifications.js:305` (testNotificationChannelDraft) |
| Settings | "No changelog available" | `frontend/settings.js:1512` (renderSettings) |
| Settings | "No logs available" | `frontend/settings.js:2324` (testSmtpConnection) |
| Settings | "No logs available" | `frontend/settings.js:2350` (testImapConnection) |
| Not rendered (possible dead code) | "No logs found" | `frontend/app.js:1594` (loadPostfixLogs) |
| Not rendered (possible dead code) | "No logs found" | `frontend/app.js:1695` (loadRspamdLogs) |
| Modal: changelog-modal | "No changelog available" | `frontend/app.js:4795` (showChangelogModal) |
| Modal: container-logs-modal | "No logs available" | `frontend/app.js:5077` (fetchContainerLogs) |

### Loading states

Functions that render a spinner or "Loading..." while data is fetched.

| Page | What | Code |
|---|---|---|
| Messages | 1 loading indicator(s) | `frontend/app.js:3847` (loadMessages) |
| Message details | 1 loading indicator(s) | `frontend/message-details.js:28` (viewPostfixDetails) |
| Message details | 1 loading indicator(s) | `frontend/message-details.js:143` (viewMessageDetails) |
| Security | 1 loading indicator(s) | `frontend/app.js:1987` (loadNetfilterLogs) |
| Queue | 1 loading indicator(s) | `frontend/app.js:2406` (loadQueue) |
| Quarantine | 1 loading indicator(s) | `frontend/app.js:2765` (loadQuarantine) |
| Quarantine | 1 loading indicator(s) | `frontend/app.js:3083` (showQuarantineDetails) |
| Quarantine | 1 loading indicator(s) | `frontend/app.js:3656` (loadQuarantineRuleHistory) |
| Status | 2 loading indicator(s) | `frontend/app.js:4228` (checkBlacklists) |
| Status | 1 loading indicator(s) | `frontend/app.js:4740` (triggerBackgroundJob) |
| Domains | 1 loading indicator(s) | `frontend/domains.js:641` (checkAllDomainsDNS) |
| DMARC | 1 loading indicator(s) | `frontend/dmarc.js:134` (loadDmarc) |
| Logs | 1 loading indicator(s) | `frontend/logs-viewer.js:1107` (loadDateRangeLogs) |
| Settings | 3 loading indicator(s) | `frontend/settings.js:1558` (renderSettings) |
| Settings | 2 loading indicator(s) | `frontend/settings.js:1895` (showGeoIPSetupModal) |
| Settings | 1 loading indicator(s) | `frontend/settings.js:2085` (validateMaxMindLicense) |
| Settings | 1 loading indicator(s) | `frontend/settings.js:2131` (repairGeoIPDatabase) |
| Settings | 1 loading indicator(s) | `frontend/settings.js:2289` (renderGeoIPDbStatus) |
| Shared | 1 loading indicator(s) | `frontend/utils.js:548` (renderJobCard) |
| Not rendered (possible dead code) | 1 loading indicator(s) | `frontend/app.js:1670` (loadRspamdLogs) |

### Persisted preferences

Settings the browser remembers between visits.

| Page | What | Code |
|---|---|---|
| Shell | localStorage getItem "theme" | `frontend/app.js:4952` (initDarkMode) |
| Shell | localStorage setItem "theme" | `frontend/app.js:4967` (toggleDarkMode) |
| Logs | localStorage getItem "logsNewestFirst" | `frontend/logs-viewer.js:17` |
| Logs | localStorage setItem "logsNewestFirst" | `frontend/logs-viewer.js:543` (toggleLogSortOrder) |

### Auto refresh and timers

Background refreshes and polling.

| Page | What | Code |
|---|---|---|
| Shell | every AUTO_REFRESH_INTERVAL ms | `frontend/app.js:645` (startAutoRefresh) |
| Status | every 1000 ms | `frontend/app.js:4265` (checkBlacklists) |
| Settings | every 2000 ms | `frontend/settings.js:2016` (showGeoIPSetupModal) |
| Modal: container-logs-modal | every 2000 ms | `frontend/app.js:5113` (loadContainerLogs) |

### Address bar and deep links

Places that change the URL so a view can be bookmarked or shared.

| Page | What | Code |
|---|---|---|
| Shell | replaceState | `frontend/app.js:1191` (switchTab) |
| Shell | pushState | `frontend/router.js:154` (navigateTo) |
| Shell | replaceState | `frontend/router.js:222` (initRouter) |
| DMARC | pushState | `frontend/dmarc.js:476` (loadDomainOverview) |
| DMARC | pushState | `frontend/dmarc.js:1065` (loadReportDetails) |
| DMARC | pushState | `frontend/dmarc.js:1171` (loadSourceDetails) |

### Keyboard handling

Key handlers; the keys are read from the handler body.

| Page | What | Code |
|---|---|---|
| Message details | keydown: Escape | `frontend/message-details.js:1033` |
| Settings | keydown: Escape, Enter | `frontend/settings.js:118` (showBasicAuthVerifyModal) |
| Settings | keydown: Escape, Enter | `frontend/settings.js:207` (showFeatureDisableConfirmModal) |
| Modal: changelog-modal | keydown: Escape | `frontend/app.js:4982` |

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
