# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- **Responsive bounce detection** - Scan and save automatically detected suppressions in a background worker. Database sessions now close before Rspamd synchronization and queue cleanup, while existing bounce rules are preserved. Issue: [#197](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/197).

- **Responsive manual DNS checks** - Save results and load alias mappings outside the request event loop when checking one or all domains. Manual and background checks share the same worker-owned persistence, preserving responses and notification ordering. Issue: [#195](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/195).

- **Responsive background DNS checks** - Save background DNS results in a worker so database delays do not hold up other requests. DNS-change notifications still follow a successful commit, and failed domains do not stop the remaining checks. Issue: [#193](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/193).

- **Responsive monitored-host synchronization** - Save monitored hosts in a background worker so database work does not delay other requests. Source discovery, activation tracking and the subsequent blacklist check retain their existing behavior. Issue: [#191](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/191).

- **Responsive GeoIP status updates** - Save GeoIP license status in a background worker so database delays do not hold up other requests after an update. Download and reader-reload behavior is unchanged. Issue: [#189](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/189).

- **Responsive alias synchronization** - Process alias statistics in a background worker so database work does not delay other requests. Forwarding targets, catch-all flags and inactive-alias tracking retain their existing behavior. Issue: [#187](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/187).

- **Responsive mailbox synchronization** - Process mailbox statistics in a background worker so database work does not delay other requests. Quotas, rate limits and inactive-mailbox tracking retain their existing behavior. Issue: [#185](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/185).

- **Responsive domain synchronization** - Save alias-domain mappings in a background worker so database delays do not hold up other requests. Domain discovery and cache updates retain their existing behavior. Issue: [#183](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/183).

- **Responsive Rspamd imports** - Process Rspamd history pages, GeoIP enrichment and database writes in a background worker while API pagination stays asynchronous. Spam fields, blacklist cleanup, duplicate detection and resume offsets are preserved. Issue: [#181](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/181).

- **Responsive Postfix imports** - Process each Postfix log page and its message-status updates in a background worker while API pagination remains asynchronous. Resume offsets, blacklist cleanup and duplicate detection are preserved. Issue: [#179](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/179).

- **Responsive Netfilter imports** - Keep Netfilter API requests asynchronous while parsing, GeoIP enrichment and database writes run in a background worker. Overlapping batches are serialized to preserve duplicate detection. Issue: [#177](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/177).

- **Responsive Dovecot delivery updates** - Process stored Dovecot delivery events in a background worker, preserving delivery verdicts and retries without blocking other requests. Overlapping runs are serialized to protect pending events and the saved progress marker. Issue: [#175](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/175).

- **Responsive message correlation** - Build Rspamd/Postfix message correlations in a background worker so database work does not block other requests. BCC cleanup still finishes first; blacklist handling, delivery-leg ownership and batch limits are preserved. Issue: [#173](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/173).

- **Responsive correlation completion** - Complete messages with late Postfix logs in a background worker, keeping database work off the request event loop. Queue ownership, status rules, age limits and batch size remain unchanged. Issue: [#171](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/171).

- **Responsive late message status updates** - Run database work for late Postfix status updates in a background worker so it does not block other requests. Status priorities, correlation age limits and batch size remain unchanged. Issue: [#169](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/169).

- **Lighter suppression expiry** - Deactivate expired spam suppressions with one database update in a background worker, keeping other requests responsive. Expiry boundaries and pending Rspamd synchronization remain unchanged. Issue: [#167](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/167).

- **Bounded database reads for CSV downloads** - Fetch export data in batches instead of loading every matching record before sending the file. Message exports include related spam data in the same query. Existing filters, limits, empty-result behavior and CSV formatting are preserved, and database sessions close when downloads finish or disconnect. Issue: [#165](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/165).

- **Lighter CSV database queries** - Load only fields used by CSV downloads, leaving raw log payloads and other unused columns in the database. Export fields, filtering, ordering and limits remain unchanged. Issue: [#163](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/163).

- **Lighter correlation expiry** - Expire old incomplete message correlations with one database update in a background worker, instead of loading and updating every match on the request event loop. Age boundaries, completed correlations and Dovecot discard outcomes are preserved. Issue: [#161](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/161).

- **Lower CSV row preparation memory usage** - Format export rows as the download is written instead of building a second full list of dictionaries. CSV fields, Unicode support, formula protection and suppression re-import remain unchanged. Database results are still loaded before streaming. Issue: [#159](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/159).

- **Responsive BCC queue cleanup** - Run blacklist cleanup before message correlation in the scheduler worker pool so slow database operations do not block unrelated requests. Cleanup rules and the order of correlation steps remain unchanged. Issue: [#157](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/157).

- **Paged report management** - Browse DMARC and TLS report history 50 reports at a time, with page controls and a total count. Existing API calls without a page remain supported. Issue: [#155](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/155).

- **Lighter report management queries** - Load only the summary columns needed by the report list, leaving raw XML/JSON report bodies in the database. Counts, ordering and response fields remain unchanged. Issue: [#153](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/153).

- **Fewer report management queries** - Fetch DMARC and TLS report counts in two queries instead of one extra query per report. Reports with no records remain visible, and response fields and ordering stay unchanged. Issue: [#151](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/151).

- **Lower CSV serialization memory usage** - Write CSV downloads in chunks instead of building full text and byte copies before sending them. Unicode support, formula protection and suppression re-import remain unchanged. Source rows are still loaded before serialization. Issue: [#149](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/149).

- **Responsive retention cleanup** - Run log and DMARC/TLS retention cleanup in the configured scheduler worker pool so database deletes do not block the event loop. Retention periods and deletion rules stay unchanged. Issue: [#147](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/147).

- **Responsive requests during database health checks** - Run the synchronous health probe in a worker thread so a slow database does not block unrelated requests on the event loop. Issue: [#145](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/145).

- **Responsive live-log broadcasts** - Send updates to viewers independently, disconnect stalled clients after a bounded wait, and preserve message ordering during concurrent broadcasts and service changes. Issue: [#143](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/143).

- **Expired login data cleanup** - Reclaim expired sessions, old failed-login counters and abandoned OAuth states every minute, including when clients never return. Active logins and current rate limits are preserved. Issue: [#141](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/141).

- **Accurate database health status** - Return HTTP 503 when the database health check fails so Docker and external monitors can detect the outage. The healthy response remains HTTP 200. Issue: [#139](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/139).

- **Multilingual CSV downloads** - Add a UTF-8 BOM to all CSV exports so spreadsheet applications can recognize non-English text. Issue: [#137](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/137).

### Security

- **CSV downloads treat formula-like text as text** ([#137](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/137)) - protect all log and suppression exports without changing stored data or negative numeric scores. Downloads omit empty filters and show request errors instead of saving them as CSV. Suppression exports include an escape marker so importing them restores the original addresses and notes; older CSV files remain supported. Thanks to [@ShlomiPorush](https://github.com/ShlomiPorush)

- **OAuth login stays in the browser that started it** ([#135](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/135)) - callbacks now require a matching temporary browser cookie and expire after ten minutes. Login attempts are single-use, including failed callbacks, and concurrent tabs remain supported. Restart an expired login from the login page. Thanks to [@ShlomiPorush](https://github.com/ShlomiPorush)

- **Safer report upload parsing** ([#133](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/133)) - update the web framework and form parser to reject oversized text fields and move temporary-file rollover off the request loop. Normal file uploads retain their existing limits. Thanks to [@ShlomiPorush](https://github.com/ShlomiPorush)

- **Login attempt limits apply consistently** ([#130](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/130)) - password checks share one failure counter, and client addresses follow the server's trusted-proxy configuration. Direct access and existing sessions continue to work without new settings. Users behind an untrusted proxy share its counter; see the optional `FORWARDED_ALLOW_IPS` setting in the environment guide for per-client limits. Thanks to [@ShlomiPorush](https://github.com/ShlomiPorush)

### Added

- **MTA-STS check on the Domains page** ([#83](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/83)) - validates each domain's `_mta-sts` DNS record, policy file and MX coverage, wired into the existing DNS change alerts. Thanks to [@q16marvin](https://github.com/q16marvin)
- **Sieve discards show "Discarded" instead of a false "Delivered"** ([#65](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/65)) - Dovecot LMTP lines are correlated into each message, and the dialog shows the mailbox outcome (folder, forward, reject reason). Requires the `dovecot` raw log service. Thanks to [@mrclschstr](https://github.com/mrclschstr) and [@Meeppoo](https://github.com/Meeppoo)
- **mailcow alias domains are recognized** ([#92](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/92)) - alias traffic counts toward the target mailbox in Mailbox Statistics, and alias domains get their own DNS checks. Thanks to [@Neocridas](https://github.com/Neocridas)
- **Rate Limits view** - who is hitting mailcow's sending limits (activity chart, per-sender history), one-click counter reset with an audit badge, and every mailbox and domain limit viewable and editable, including a bulk apply on the filtered selection. Feature id `rate-limits`, works independently of Mailbox Stats
- **DMARC page shows a loading state** on its first load, and slow requests are logged for diagnosis

### Changed

- **Disabling Mailbox Stats or Rate Limits now removes their leftover data** - alias statistics, the counter-reset audit, and the shared mailbox table once both are off

### Fixed

- **A suppressed address could block innocent recipients** - suppression map entries were compiled as unanchored regexes, so suppressing e@example.com also rejected every address containing it. Entries are now anchored and escaped, and existing maps migrate automatically
- **Dashboard message timeline was silently empty** - an invalid query expression made the endpoint always fail. Spotted in [@Meeppoo](https://github.com/Meeppoo)'s branch for #65
- **Mail from outside between two hosted domains was mislabeled "internal"** - internal now also requires a local origin
- **Live Logs could miss lines during a burst or after downtime** - the collector now pages deeper until it reaches lines it already has, instead of only taking the newest 1000
- **A forwarded message hid the delivery it came from** ([#36](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/36)) - every delivery of a message is now tracked on its own, and the dialog links the related deliveries. Thanks to [@piperino721](https://github.com/piperino721)
- **Mailbox Statistics counted a forwarded message several times** ([#36](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/36)) - a message now counts once per mailbox, by its most successful delivery
- **A message that was deferred and then delivered kept showing "Deferred"** ([#114](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/114)) - late delivery logs now refresh the message whenever they arrive


## [2.7.1] - 2026-09-10

### Added

- **The viewer has its own icon** - a project icon now appears as the browser favicon, in the application header and on the login page, with Android and Apple touch icon sizes and a theme colour for mobile browsers. Setting `APP_LOGO_URL` still replaces it with your own logo; leaving it empty now shows the project icon instead of nothing

### Security

- **Live log endpoints were reachable without logging in** - the raw-logs router was mounted twice, once under `/api` and once at the site root so the WebSocket had a clean address. The second mount also published its regular endpoints at `/raw-logs/...`, where the authentication check does not apply, and one of them hands out the token that opens the live log stream. Anyone who could reach the web interface could read the mail server logs without credentials. Only the WebSocket route is mounted at the root now, and a test fails if any other endpoint ever escapes `/api` again. **If your instance is reachable from the internet, upgrade.**
- **The mailcow password is no longer stored in the browser** - signing in used to keep the username and password in the browser session storage in clear text, where any script on the page could read them. The password is now sent once, at login, and the server replies with a session cookie that JavaScript cannot read at all. Nothing changes in how you log in. Two notes: restarting the container signs everyone out (sessions are held in memory), and API scripts that send the password on every request keep working unchanged
- **Log lines could inject HTML into the viewer** - four values shown on the Logs page (the watchdog health counters and an unparsable timestamp) were written into the page without escaping. Mail server log content is influenced from outside, so a crafted value could have run script in the browser of whoever was watching the page. Every value on that page is escaped now, along with the error messages shown when a page fails to load
- **A crafted address could stall the server** - the address check used by the abuse-protection whitelist slowed down with the square of the input length on certain crafted values, so a single request could freeze the application for seconds. Addresses are now length-capped and matched with a pattern that cannot backtrack, and a bulk whitelist update is limited to 5000 entries
- **Domain suppressions built a safer pattern** - adding a domain to the suppression list turned it into a regular expression by escaping only the dots, so an unusual domain name could change the resulting Rspamd rule. Only plain domain names are accepted now, and every special character is escaped
- **Tighter Spamhaus zone matching** - a blacklist zone whose name merely ended with `spamhaus.org` (for example a lookalike domain) was treated as a genuine Spamhaus zone. Only real subdomains of `spamhaus.org` count now

### Fixed

- **Excessive DNS queries to the mailcow host** ([#84](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/84)) - every call to the mailcow API opened a new connection, so the background jobs re-resolved the mailcow hostname hundreds of times per hour and ignored the record TTL, which showed up as a tenfold increase in DNS traffic. The API client is now reused and keeps idle connections alive between polls. Thanks to [@sOliverBa](https://github.com/sOliverBa) for the unbound measurements that pinned it down
- **Rspamd map rewritten every sync even when nothing changed** ([#80](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/80)) - the suppression sync embedded a timestamp comment in `global_rcpt_blacklist.map`, so every 10-minute sync produced "new" content, forcing Rspamd to truncate, rewrite and reload the map each time - occasionally logging a harmless "regexp map is empty" warning when it re-read mid-write. The map is now only written when the suppression entries actually changed, so the warning can appear at most on real updates. Thanks to [@Neocridas](https://github.com/Neocridas) for the accurate diagnosis
- **Weekly Summary Report was never sent since 2.7.0** ([#81](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/81)) - scheduled and on-demand summaries failed with "object dict can't be used in 'await' expression" before the email step, because the blacklist helper became a plain function in 2.7.0 while the report still awaited it. The report builds and sends again. Thanks to [@piperino721](https://github.com/piperino721) for confirming the scheduled runs were affected too
- **"Run" on the DMARC IMAP Sync job returned 404** ([#82](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/82)) - the job was listed on the Status page but missing from the manual job runner. It can now be started from the Status page like every other job, and a test keeps the two lists in sync
- **Detect Suppressions crashed when a recipient bounced more than once per scan** - each bounce log line created its own suppression insert, and duplicates within one batch violated the unique email index, failing the whole job (no suppressions were saved). Repeated bounces now update the pending entry, so the recipient is suppressed once with an accurate bounce count
- **"Run Check for this Host" button did nothing** - the per-host check button on the Status page referenced a function that was removed back around v2.3, throwing a console error on every click. It now runs a forced check for that host with the same progress bar as the main Check button
- **Deleted relayhosts/transports came back after sync** - the immediate settings reconcile could not tell a host deactivated by its source toggle from one removed in mailcow, and reactivated it on the next page load. Re-adding rows is now exclusively the sync job's responsibility (which reads the live mailcow state)
- **DNSBL answers outside 127.0.0.0/8 are no longer treated as listings** - a resolver that rewrites NXDOMAIN (ISP ad redirection, captive portal) can answer RBL queries with arbitrary addresses; per RFC 5782 those are now reported as "unknown" with an explanation instead of a false "listed". Also hardened the DoH fallback against Spamhaus rejection codes
- **False Spamhaus listings from filtering resolvers** ([#78](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/78)) - a local DNS blocker (router adblock, Pi-hole, ISP filter) that intercepts the RBL domain can answer with `127.0.0.1`, which counted as "listed". Per RFC 5782 `127.0.0.1` is never a valid listing; additionally, answers from Spamhaus zones are validated against Spamhaus's documented return codes (`127.0.0.2-11`) - anything else is reported as "unknown" with the raw answer shown

### Changed

- **Anomaly detection learns daily send patterns** - a mailbox that sends a large batch at the same time every day (scheduled reports, digests) no longer triggers a daily volume-spike alert. The detector compares the burst against the same time-of-day slot on previous days: recurring similar volume there means "scheduled", while a burst at an unusual hour - or one far above the usual batch size - still alerts. No whitelist needed, so off-schedule abuse of the same mailbox is still caught
- **Blacklist zone cards show the raw DNS answer on hover** - hovering a listed/error entry now reveals the actual DNSBL response code (e.g. `127.0.0.3`), which distinguishes a genuine listing from resolver interference when comparing with the RBL's own lookup page
- **Deactivated monitored hosts are purged after 30 days** - hosts removed from mailcow or from the source settings are kept (inactive) for 30 days in case they return, then deleted by the daily cleanup job. Active hosts are never affected

## [2.7.0] - 2026-07-30

### Added

- **Per-check IP sources for blacklist monitoring and SPF checks** ([#76](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/76), [#23](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/23)) - each check now has its own configurable IP sources instead of one global list. Blacklist monitoring: toggle the auto-detected WAN IP, mailcow transports and relayhosts independently (`BLACKLIST_SOURCE_SERVER_IP` / `_TRANSPORTS` / `_RELAYHOSTS`), plus `BLACKLIST_SOURCE_MANUAL_HOSTS` for extra IPs or hostnames - including hosts unrelated to this mailcow server. Domain SPF checks: choose which IPs must pass each domain's SPF record (`DOMAIN_SPF_SOURCE_SERVER_IP` / `_TRANSPORTS` / `_RELAYHOSTS` / `_MANUAL_HOSTS`), so relay setups validate the relay IPs instead of the WAN IP. A new `DOMAIN_SPF_SOURCE_DMARC_HISTORY` source additionally validates the SPF-passing sender IPs observed in the last 30 days of DMARC aggregate reports. IPv6 is supported end to end (including `ip6:` mechanisms, AAAA lookups and nibble-reversed RBL queries). Configuration model and the DMARC-history idea from [PR #77](https://github.com/ShlomiPorush/mailcow-logs-viewer/pull/77) by [@Meeppoo](https://github.com/Meeppoo)
- **Sort quarantine by score** ([#75](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/75)) - the Quarantine page can now sort by spam score in both directions (highest first to spot extreme spam, lowest first to find false positives). The chosen sort survives refreshes and message actions
- **Notification destinations** - send alerts to Slack, Discord, Telegram, ntfy, Gotify or a custom JSON endpoint, alongside email. Add **as many destinations as you like** under Settings → Notifications; each one asks only for the fields that service actually needs (Telegram: bot token + chat ID, ntfy: server + topic) and the endpoint URL is built for you. Per-destination enable/disable, "Send test", and last-delivery status. An existing single-webhook configuration is migrated automatically
- **Choose which alerts each destination receives** - every notification now belongs to a named type (Security, IP blacklist, DNS record changes, DMARC processing errors), each with a short explanation in the UI, so it is clear what the app sends and where. Tick the types per destination, e.g. security alerts to your phone and everything else to a team channel. Existing destinations keep receiving all alerts
- **Anomaly detection (beta)** - background job that flags likely compromised mailboxes (a mailbox sending far above its own baseline) and auth-failure bursts (brute-force / credential stuffing). Alerts appear as a dashboard banner and are sent via email + webhook. Tunable under Settings → Anomaly Detection; off by default. **Beta**: this feature has seen limited real-world testing - please report issues
- **SMTP abuse protection (beta)** - automatically disables SMTP (sending) for a mailbox that exceeds a hard outbound limit, the usual signature of a compromised account. Receiving over IMAP is never affected, app passwords are revoked, and both the operator and the mailbox owner are notified. Includes a whitelist, manual disable/re-enable controls under Security → Abuse Protection, and an audit trail. Requires a Read-Write mailcow API key; off by default. **Beta**: this feature has seen limited real-world testing - please report issues. **Contributed by [@jongautur](https://github.com/jongautur) ([#73](https://github.com/ShlomiPorush/mailcow-logs-viewer/pull/73))**
- **TLSA (DANE) checks and DNS change alerts** ([#72](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/72)) - the Domains page now also checks the TLSA (DANE) records published for each domain's mail servers, alongside SPF, DKIM and DMARC. When any of those four records changes, an alert naming the domain and showing the old and new value is sent by email and to your notification destinations, so you can update the records at your registrar. A failed DNS lookup is never treated as a change
- **DMARC insights** - the DMARC page now shows policy recommendations (e.g. "safe to move from p=none to p=quarantine" when pass rate and volume are healthy) and flags new sending sources that are failing DMARC (possible spoofing)
- **Documentation** for all of the above: new environment variables in `ENV_Settings.md`, new endpoints in `API.md`, and an in-app help page for Abuse Protection

### Fixed

- **Blacklist alerts never reached notification destinations when no email was configured** - both blacklist alert paths (new listing, cleared/improved) were skipped entirely unless an admin email was set, so webhook-only setups received nothing. Alerts now fire when either an email or at least one notification destination is configured
- **Times shown ahead by 1-2 hours** ([#19](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/19)) - when the PostgreSQL container ran with a non-UTC `TZ` (e.g. `Europe/Berlin`), timestamps were shifted to local wall time at insert, then labeled UTC and shifted again in the browser - showing times ahead by exactly the UTC offset (1h in winter, 2h in summer). Every DB session is now pinned to UTC, so the database container's timezone no longer matters. Entries stored before the fix keep the old shift until they age out with `RETENTION_DAYS`
- **Relay hosts in `[host]:port` form were never monitored** - Postfix bracket syntax (e.g. `[relay.example.com]:587`) was parsed incorrectly, leaving a stray `]` that made DNS resolution fail silently. Thanks to @Meeppoo for spotting it
- **Relay pools are now fully monitored** - a relay hostname with multiple A records (round-robin pool) had only its first IP monitored; all public IPs are now resolved (honoring `BLACKLIST_DNS_SERVERS`) and monitored, so a listing on any pool member is caught
- **Blacklist host sync no longer stops when the Domains page is disabled** - the transports/relayhosts sync only feeds blacklist monitoring, so it is now gated on the blacklist feature instead
- **Dashboard blacklist card covers all monitored hosts** - the summary card previously reflected only the auto-detected WAN IP; it now aggregates every monitored host (configured outbound IPs, transports, relayhosts) and shows how many are listed. Idea from [PR #77](https://github.com/ShlomiPorush/mailcow-logs-viewer/pull/77) by [@Meeppoo](https://github.com/Meeppoo)
- **SPF check transparency** - the Domains page SPF card gained an expandable "Checked IPs" section showing exactly which IPs were validated, where each came from (configured or auto-detected) and its per-IP verdict. Idea from [PR #77](https://github.com/ShlomiPorush/mailcow-logs-viewer/pull/77) by [@Meeppoo](https://github.com/Meeppoo)
- **Modal flash on page load fixed** and the transports sync status card now follows the blacklist feature flag. Both from [PR #77](https://github.com/ShlomiPorush/mailcow-logs-viewer/pull/77) by [@Meeppoo](https://github.com/Meeppoo)
- **Spamhaus blacklist checks stopped working** - Spamhaus rejects DNSBL queries that arrive through public resolvers (Google, Cloudflare, Quad9, DoH), answering with a `127.255.255.x` rejection code. The app queried only public resolvers, and a 2.3.2 refactor had removed the retry that used to work around it, so all four Spamhaus zones silently returned "error". RBL lookups now use your own resolver first (configurable via `BLACKLIST_DNS_SERVERS`), retry other resolvers when a query is rejected, explain the rejection in the UI, and a host whose Spamhaus zones could not be checked is reported as **unknown instead of clean**
- **Live Log Viewer WebSocket dropped intermittently (regression in 2.6.3)** - `get_ws_token` was mistakenly converted from `async def` to `def` in the 2.6.3 endpoint-threadpooling change, moving it to a worker thread while the async WebSocket endpoint kept reading/mutating the same in-memory token store on the event loop. Under load (busy server + reconnect loop) this raced the token store and dropped connections (1006). Restored to `async` and made the token cleanup snapshot-safe
- **Mailbox stats summary crashed on an empty database** (`total_sent_failed` variable-name mismatch) - affected fresh installs before the first stats sync
- Removed sourcemap references from vendored chart.js/DOMPurify (harmless 404s for `.map` files in the logs)
- **DMARC pass rate was drastically understated** - the domains table, top summary and per-domain charts counted a message as passing DMARC only when BOTH aligned SPF and aligned DKIM passed. Per RFC 7489 either one is sufficient, and common legitimate flows pass only one (forwarding breaks SPF but DKIM survives). All views now use the correct either-passes rule, matching the Insights panel
- **Confirmation dialogs and toasts now HTML-escape their message** - user-influenced values (channel names, rule names, email addresses, domains) were interpolated into `innerHTML` unescaped, allowing stored HTML/script injection by anyone able to influence those names

### Changed

- **Blacklist zone list cleaned up and made IPv6-honest** - removed the 9 SORBS zones (SORBS shut down in 2024, so those checks were meaningless) and the CBL zone (absorbed into Spamhaus XBL). IPv6 addresses are now checked only against zones that actually serve IPv6 (Spamhaus, s5h.net) instead of reporting a false "clean" from ~26 IPv4-only lists that cannot even hold an IPv6 listing. Cached results are re-scanned once after upgrading because the zone count changed
- **Rspamd maps failed with a 302 behind a reverse proxy** ([#71](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/71)) - when the app runs outside mailcow's Docker network, the proxy in front of mailcow can redirect `/rspamd` before the password header is evaluated. New `RSPAMD_URL` setting points straight at the Rspamd controller (e.g. `http://rspamd-mailcow:11334`); the 302 error message now names it too. Thanks to [@curiosity71](https://github.com/curiosity71) for the diagnosis
- **Settings reorganised** - excluded email addresses moved to the Fetch tab (they are excluded during fetching), OAuth2 merged into the Authentication tab, and the Blacklist tab is now clearly the IP blacklist (RBL) monitor
- **Settings navigation on mobile** - the category list is replaced by a single sticky picker that stays visible while scrolling, so switching category no longer means scrolling back to the top. The desktop sidebar is unchanged
- **Settings "Edit configuration" redesigned** - the 17 categories that used to wrap across several rows of tabs are now a grouped vertical sidebar (Connection / Notifications / Security / Email Data / Features & Advanced), with the fields on the right. Categories for disabled features are hidden and their group header collapses when empty. Also fixes a pre-existing quirk where the highlighted tab could be a skipped/empty one. No change to the fields, saving, or ENV-lock behavior
- Security-headers middleware reimplemented as a pure ASGI middleware (was `@app.middleware("http")` / `BaseHTTPMiddleware`), which by construction never touches WebSocket connections - hardening against proxy/WebSocket edge cases
- **Schema migrations moved to Alembic** - new schema changes are now versioned Alembic revisions (`backend/alembic/`) applied automatically on startup; existing installs adopt it transparently via a no-op baseline, and the legacy startup migrations are frozen at their 2.6.3 state
- **Frontend split into modules** - the monolithic `app.js` was split into per-page scripts (`utils.js`, `settings.js`, `domains.js`, `dmarc.js`, `logs-viewer.js`, `mailbox-stats.js`, `notifications.js`, `smtp-abuse.js`). No behavior change; relevant if you carry local frontend patches

---

## [2.6.3] - 2026-07-12

### Security

- **Decompression bomb protection** - a malicious compressed DMARC/TLS-RPT report (emailed or uploaded) could exhaust memory and crash the container; size limits are now enforced
- **XSS fixes** - malicious data inside DMARC reports could execute scripts in the browser via inline `onclick` handlers; markdown content (docs, changelogs) is now also sanitized with DOMPurify
- **Hardened XML parsing** - DMARC reports are parsed with `defusedxml` to block entity-expansion attacks
- **Security headers** added to all responses (`Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`)
- **Brute-force protection** - after 10 failed login attempts within 15 minutes, further attempts are blocked temporarily
- **Less info exposed without login** - `/api/info` and `/api/health` no longer reveal the mailcow URL, hosted domains, or configuration to unauthenticated visitors

### Fixed

- **"Sync Transports & Relayhosts" job crashed** when a relayhost hostname was long (e.g. Microsoft 365 relays) - the database column was too short ([#70](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/70))
- **Security tab showed old, unrelated events** - now limited to 1 hour around the message, as the tab always claimed ([#68](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/68))
- **"Test SMTP" / "Test IMAP" buttons refreshed the page** instead of showing the test results
- **Some logs were silently lost** when a large backlog was imported across multiple fetch cycles
- **OAuth2 login always failed** when `SESSION_SECRET_KEY` was not configured
- **App froze during slow operations** - database queries, email sending, and SMTP/IMAP connection tests no longer block the entire application
- **Postfix logs page was slow on large databases** - replaced hundreds of queries per page view with a single paginated query
- **Live log viewer memory leak** - the page now keeps at most 5,000 log lines, so leaving the Logs tab open no longer slows the browser
- **Error responses leaked internal details** - 500 errors now return a generic message (full errors still go to the server log)
- Internal cleanups: removed a duplicate background-job definition and a duplicate migration, deduplicated helper functions, stricter exception handling

### Added

- **Log Viewer sort order toggle** - choose between newest entries at the bottom (default) or at the top; the choice is remembered ([#69](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/69))
- **Automated tests + CI** - pytest suite for the backend and a GitHub Actions workflow that runs on every push/PR

---

## [2.6.2] - 2026-06-18

### Fixed

#### Manual Execution of Raw Log Jobs Fails with 404 ([#67](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/67))
- **Clicking "Run" on "Fetch Raw Logs" or "Cleanup Raw Logs" background jobs returned `Unknown job` error** — the manual job trigger endpoint was missing both raw log jobs from its job mapping
  - Added `fetch_raw_logs` and `cleanup_raw_logs` to the manual trigger endpoint
  - Correctly reads job status from the raw logs worker's separate status tracking (not the main scheduler)

#### DMARC IMAP Reports with Non-English Subjects Not Imported ([#66](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/66))
- **DMARC reports from providers using non-English subjects were silently skipped** — the IMAP search only matched English subject patterns like "Report Domain:", "DMARC", "Report-ID:"
  - Added new setting `DMARC_IMAP_SCAN_ALL_UNSEEN` (default: off) — when enabled, scans all unread emails for DMARC/TLS-RPT attachments, not just subject-matched ones
  - Recommended for dedicated DMARC mailboxes that receive reports from international providers

#### Scheduler Stability ([#63](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/63))
- **Background jobs skipping with warnings** (`maximum number of running instances reached`, `Run time of job was missed`) after prolonged uptime
  - Added `misfire_grace_time=30` and `coalesce=True` to both schedulers to tolerate delayed jobs and prevent pileups
  - Cached log discovery results for 5 minutes to reduce API calls during fetch cycles
  - Increased default `RAW_LOGS_FETCH_INTERVAL` from 20 to 30 seconds

#### DMARC Daily Reports Not Split by Reporter ([#41](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/41))
- **DMARC report details merged all reporters into a single row** per source IP — when multiple providers (Google, Microsoft, Yahoo, etc.) reported on the same sending IP, only the first reporter was shown
  - Reports are now split by reporter so each provider gets its own row with independent statistics

#### Noisy Error Traceback on Shutdown
- **`CancelledError` traceback logged during graceful shutdown** — APScheduler raised an unhandled exception when `fetch_all_logs` was interrupted mid-cycle by the event loop shutting down
  - `asyncio.CancelledError` is now caught explicitly and logged as a INFO message instead of ERROR traceback

---

## [2.6.1] - 2026-05-17

### Fixed

#### GeoIP Backfill Infinite Loop on Startup
- **Application startup could hang indefinitely** when IP addresses could not be resolved by the GeoIP database
  - The backfill loop fetched rows with `country_code IS NULL`, but only updated them when a valid country was returned — unresolvable IPs were never updated and re-fetched forever
  - Now assigns fallback values (`ZZ` / `Unknown`) for any IP that cannot be resolved, ensuring every row is processed exactly once
  - Thanks to [@P7aM5qzEddT66lE](https://github.com/P7aM5qzEddT66lE) for reporting and submitting the fix ([#58](https://github.com/ShlomiPorush/mailcow-logs-viewer/pull/58))

#### Startup Crash with `DEBUG=true`
- **Application crashed immediately on startup** when `DEBUG=true` was set in environment variables ([#57](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/57))
  - Engine initialization now conditionally applies `pool_size`/`max_overflow` only when using the standard connection pool

#### Settings Page Freeze (~30 Seconds)
- **Settings page could hang for up to 30 seconds**, especially after the application hadn't been accessed for several days
  - Root cause: the `GET /api/settings/info` endpoint made a **synchronous external HTTP call** to MaxMind's license validation API on every page load — if DNS cache expired or the network was slow, TCP connect timeout could block for 30+ seconds
  - MaxMind license validation is now **fully on-demand**: the settings page no longer checks license validity automatically. Instead, a "Validate" button lets users check when they want to
  - Added `POST /api/settings/maxmind/validate` endpoint for on-demand validation

### Changed

#### MaxMind License Status
  - Validation results are now **persisted in the database** (`system_settings` table) and survive page refreshes, container restarts, and re-deployments
  - Clearing MaxMind credentials properly resets the status back to "Not checked"

#### MaxMind Settings UI Improvements
- **"Validate" button** for MaxMind license validation now appears **only when credentials are configured** (not when empty)
- **"Repair" button** added for corrupted GeoIP databases — automatically re-downloads and re-validates database files when "DB Corrupt" status is detected

#### Fail2Ban IP Lists Redesign ([#51](https://github.com/ShlomiPorush/mailcow-logs-viewer/issues/51))
- **Added Active Bans list** showing all currently banned IPs with visual distinction between permanent and temporary bans
  - **Permanent bans** (red badge): IPs from the denylist — cannot be unbanned directly, must be removed from the denylist
  - **Temporary bans** (amber badge): dynamically banned by Fail2Ban with remaining ban time displayed and an "Unban" button
  - IPs queued for unbanning show a "Unbanning..." status indicator
- Simplified IP Lists layout from 3 columns to 2 (Allowlist + Denylist) with the Active Bans section below

---

## [2.6.0] - 2026-05-06

### Added

#### Dynamic Feature Toggles
- **Enable or disable application features on-the-fly** from the Settings page without requiring a restart
  - Toggle individual features: Security (Netfilter/Fail2Ban), Queue, Quarantine, Spam Filter, Domains, DMARC, Mailbox Statistics, Logs, Blacklist Monitor
  - Page auto-reloads after toggling features so all UI changes take effect immediately

#### Feature Toggle — UI Integration
- **Navigation tabs** are dynamically hidden/shown based on enabled features
- **Settings page**: Related settings tabs (DMARC, DMARC IMAP, Logs, Spam Filter, Quarantine) are hidden when their feature is disabled

#### Feature Toggle — Background Job Guards
- **Runtime feature checks** added to all feature-specific background jobs — disabling a feature immediately stops its related jobs without restart
  - Previously, feature checks only occurred at startup (job registration). Now each job verifies its feature is still enabled at every execution

#### Feature Toggle — Status Page
- **"Feature Off" badge** on background job cards for disabled features

#### Data Purge on Feature Disable
- **Disabling a feature now purges all related data** from the database (with confirmation warning)

#### Quarantine — Rspamd Training Actions
- **Learn Not Spam**: Release a quarantined message and train Rspamd that it is not spam
- **Learn Spam**: Delete a quarantined message and train Rspamd that it is spam

#### Quarantine — Email Detail Modal
- **Full email details view** — click "Details" or the subject line to open a modal with:
  - Header info: Subject, From (Header), Envelope From, Recipients (with type badges), Score, Action
  - Rspamd Symbols table sorted by absolute score impact; score-0 symbols in a collapsed accordion
  - Email content preview (plain text or HTML body)

### Changed

#### Paginated Log Synchronization
- **Full history import** — Postfix and Rspamd logs are now fetched using paginated API calls, importing the entire mailcow log history instead of only the most recent batch
  - Fetches logs in configurable page sizes (`FETCH_COUNT_POSTFIX`, `FETCH_COUNT_RSPAMD`) with offset-based pagination
  - Postfix and Rspamd run in parallel via `asyncio.gather` for faster data population
- **Log discovery via binary-search probing** — Before fetching begins, the system probes the mailcow API at progressively finer positions (100k → 10k → 1k → 100 → 10 → 1) to determine exactly how many logs exist, enabling accurate progress logging (`Page 5/250 (2%)`) and eliminating blind pagination
- **Configurable page limit** (`FETCH_MAX_PAGES`, default: 50) — Safety cap on pages per cycle. When the limit is reached, the current offset is saved and the next cycle resumes from exactly where it left off, ensuring complete ingestion across multiple runs
- **Early stop on catch-up** — If an entire page contains only duplicates (no new logs), fetching stops early instead of scanning remaining pages unnecessarily
- **Batch existence pre-check** — Each page of logs is checked against the database in a single query before insertion, preventing `UniqueViolation` errors without relying on database-level exception handling
- **Blacklist filtering during ingestion** — Logs matching blacklisted email addresses (`BLACKLIST_EMAILS`) are filtered out during import and their related database records are cleaned up

### Fixed

#### GeoIP Error When MaxMind Not Configured
- **`ERROR - Failed to load GeoIP City database` on every startup**: When MaxMind credentials are not configured, stale or empty `.mmdb` files in the data directory caused repeated ERROR-level log messages. The system now checks that database files are non-empty before attempting to load them, downgrades the message to DEBUG level, and marks GeoIP as unavailable so it does not retry

#### Mailbox Stats — Case-Insensitive Email Matching
- **Alias/mailbox message counts ignored letter case**: If an alias was stored as `test@domain.com` but a message was sent from `TEST@domain.com`, it would not be counted in the mailbox statistics. All sender/recipient comparisons in the mailbox stats module now use case-insensitive matching

#### Mailbox Stats — Query Performance Issue
- **Page took minutes to load and froze on search**: Message counting was done individually for each mailbox and alias, causing hundreds of database queries per page load. Now all counts are calculated in bulk using just 2 queries total, making the page load in seconds

#### Messages — Incorrect Timestamp Displayed
- **All messages showed the same date/time**: The messages page displayed `last_seen` (when the system processed the correlation) instead of `first_seen` (the actual email timestamp from Rspamd). This caused all messages imported in the same batch to show identical times. Now displays the real email time and sorts by it

### Technical

#### New Configuration Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `DISABLED_FEATURES` | `""` (empty) | Comma-separated list of features to disable. Valid values: `netfilter`, `queue`, `quarantine`, `spam-filter`, `domains`, `dmarc`, `mailbox-stats`, `logs`, `blacklist` |
| `FETCH_MAX_PAGES` | `50` | Maximum number of pages to fetch per cycle for Postfix/Rspamd (safety limit to prevent infinite loops) |

#### API Changes
- `GET /api/info` now includes `disabled_features` array in the response — lists all currently disabled feature IDs
- `GET /api/settings/info` background jobs include `feature_disabled: true` for jobs whose feature is turned off
- `POST /api/settings/purge-feature-data` — new endpoint to delete all database data for a disabled feature (body: `{ "feature": "<id>" }`)

#### New API Endpoints
```
POST /api/quarantine/learnham          - Release & train as not spam (requires RW API key)
POST /api/quarantine/learnspam         - Delete & train as spam (requires RW API key)
GET  /api/quarantine/{id}/details      - Get full quarantine item details (proxied from mailcow)
```

---

## [2.5.0] - 2026-04-23

### Added

#### Quarantine Auto-Rules
- **Auto-release or delete quarantined emails** based on user-defined rules
  - Match by Sender, Sender Domain, Recipient, or Subject — using Exact Match, Contains, or Regex
  - Actions: Release (deliver to inbox) or Delete (permanently remove)
  - Delete rules always take priority over Release (acl-style deny/allow)
  - Per-rule Enable/Disable toggle, dry-run testing, and full action history log
  - Safety limit: max actions per run (default: 50)
- **Inline rule creation** from quarantine items — "Rule" button pre-fills sender, recipient, subject
- **New "Quarantine" tab in Settings** and background job on Status page

#### Spam Filter — Rspamd Maps Editor
- **Direct editor for all 13 Rspamd map files** — sender/recipient deny/allow lists, bad words, fishy TLDs, and more
  - Built-in **Regex Wizard** for generating patterns without regex knowledge
  - **Validate** button to check regex syntax before saving
  - Read-only mode when `MAILCOW_API_KEY_RW` is not configured

#### Spam Filter — Email Suppression & Deferred Queue Cleanup
- **Automatic email suppression** — block outgoing emails to recipients that bounce
  - **Hard bounces (5.x.x)**: Detected from Postfix logs, recipients suppressed immediately
  - **Deferred queue cleanup**: Scans the live mail queue every 5 min for emails stuck longer than threshold (default: 60 min) — deletes from queue and suppresses. Replaces log-based soft bounce detection for reliability on busy servers
  - **Progressive blocking**: Each repeat bounce extends suppression (base × bounce count, capped at max)
  - **Immediate Rspamd sync**: Suppressions pushed to Rspamd right away
  - Manual management, import/export CSV, domain regex, permanent or timed blocks, quick-extend buttons
- **"Suppress" button on Queue page** — quick-add recipient to suppression list
- **Background jobs** on Status page: Detect Suppressions, Cleanup Deferred Queue, Sync to Rspamd, Expire Suppressions
- **Spam Filter settings** grouped into clear sections: Hard Bounces, Soft Bounces, Deferred Queue Cleanup, Block Duration, Whitelist

#### MaxMind GeoIP — Robust Initialization & Setup UX
- **Eager-load at startup**, database integrity validation, auto-recovery of corrupt databases
- **Setup Modal** when credentials are configured: credential check → download with progress bar → integrity validation
- **Health badges in settings**: License, DB Health, combined City + ASN info

#### Documentation
- **New `Spam_Filter.md` help page** — Suppressions and Rspamd Maps user guide
- **New `Quarantine.md` help page** — Auto-Rules guide with match modes, quick-fill, and dry-run testing

### Changed
- **Adjusted page width** to `max-w-[1400px]` for better readability on wide screens

### Security
- **Upgraded `python-dotenv` ≥1.2.2** — fixes symlink-following vulnerability

### Technical

#### New Configuration Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `QUARANTINE_RULES_MAX_ACTIONS` | `50` | Max emails to release/delete per scheduler run |
| `QUARANTINE_RULES_INTERVAL` | `5` | Minutes between rule processing runs |
| `QUARANTINE_RULES_LOG_RETENTION_DAYS` | `30` | Days to keep action history |
| `SUPPRESSION_ENABLED` | `false` | Enable the suppression system |
| `SUPPRESSION_AUTO_DETECT` | `true` | Auto-detect hard bounces from Postfix logs |
| `SUPPRESSION_RSPAMD_SYNC` | `true` | Auto-sync suppression list to Rspamd |
| `SUPPRESSION_WHITELIST_DOMAINS` | `""` | Domains that should never be suppressed |
| `SUPPRESSION_HARD_BOUNCE_ACTION` | `suppress` | Hard bounce action: suppress or ignore |
| `SUPPRESSION_SOFT_BOUNCE_ACTION` | `count` | Soft bounce action: suppress, count, or ignore |
| `SUPPRESSION_SOFT_BOUNCE_THRESHOLD` | `3` | Soft bounces before suppression (when action=count) |
| `SUPPRESSION_BASE_EXPIRY_DAYS` | `7` | Base block duration in days (× bounce count) |
| `SUPPRESSION_MAX_EXPIRY_DAYS` | `90` | Maximum block duration cap |
| `QUEUE_CLEANUP_ENABLED` | `true` | Auto-delete stuck deferred emails from queue |
| `QUEUE_CLEANUP_THRESHOLD_MINUTES` | `60` | Minutes before a stuck deferred email is deleted |

#### New API Endpoints
```
GET    /api/quarantine/rules                - List all quarantine rules
POST   /api/quarantine/rules                - Create a new rule
PUT    /api/quarantine/rules/{id}           - Update a rule
DELETE /api/quarantine/rules/{id}           - Delete a rule
PUT    /api/quarantine/rules/{id}/toggle    - Enable/disable a rule
POST   /api/quarantine/rules/test           - Dry-run test all rules against current quarantine
GET    /api/quarantine/rules/logs           - Get action history (paginated)

GET    /api/suppressions                    - List suppressions (paginated, searchable, filterable)
GET    /api/suppressions/stats              - Suppression statistics summary
GET    /api/suppressions/config             - Suppression feature configuration
POST   /api/suppressions                    - Create a suppression (email or domain, permanent or timed)
PUT    /api/suppressions/{id}               - Update suppression (notes, expiry, permanent toggle)
DELETE /api/suppressions/{id}               - Delete a suppression permanently
POST   /api/suppressions/import             - Bulk import from CSV
GET    /api/suppressions/export             - Export all suppressions as CSV
POST   /api/suppressions/sync              - Manual sync to Rspamd

GET    /api/rspamd/config                   - Check Rspamd configuration status
GET    /api/rspamd/maps                     - List all available Rspamd maps
GET    /api/rspamd/maps/{filename}          - Read a specific Rspamd map file
PUT    /api/rspamd/maps/{filename}          - Update a Rspamd map file (requires RW key)
POST   /api/rspamd/validate                - Validate regex patterns

GET    /api/settings/geoip/status           - Detailed GeoIP status (license, DB health, job status)
POST   /api/settings/geoip/download         - Trigger GeoIP database download in background
POST   /api/settings/geoip/validate         - Validate GeoIP database integrity (test IP lookups)
```

---

## [2.4.0] - 2026-04-16

### Added

#### Live Log Viewer
- **New "Logs" page** — live terminal style log viewer for all mailcow services
  - **10 mailcow services supported**: Postfix, Dovecot, SOGo, Netfilter, Ratelimited, Rspamd, Watchdog, ACME, API, Autodiscover
  - **Real-time updates via WebSocket** — new log entries pushed instantly from the server, no polling
  - **Terminal-style dark output** with color-coded log lines (errors red, warnings yellow, success green)
  - **Service sidebar** with entry count badges and quick filter
  - **Postfix Smart Filters** — one-click filter chips for common issues: Postscreen, NOQUEUE Reject, DNSBL Block, Pregreet, Sender/Recipient Restrictions, Relay Denied, Connections
  - **Full-text search** across log messages with highlighted results
  - **Controls**: Pause/Resume, Auto-scroll, Font size selector, Word wrap toggle, Clear display
  - **Status bar**: WebSocket connection indicator (green/red/yellow), entry count, last update time
  - **Timezone-aware timestamps** — dates formatted consistently with the rest of the app (`DD.MM.YYYY, HH:mm:ss`)
- **Date Range Analysis** — full forensic log retrieval by date range
  - **Date Range Picker** with From/To datetime inputs and quick presets (1h, 6h, 24h, 48h)
  - **Infinite scroll pagination** — automatically loads older pages when scrolling up
  - **Status bar indicators** — shows `Loaded X of Y entries` for data availability feedback
- **Live Mode toggle** — dedicated Live button next to Pause with visual active state

#### Background Raw Logs Worker
- **Separate `AsyncIOScheduler` instance** — completely independent from the main scheduler, ensuring log ingestion never impacts existing correlation processing
- **Sequential API fetching** — services fetched one at a time to minimize mailcow API load
- **Pre-check hash deduplication** — queries existing SHA-256 hashes before inserting, preventing duplicate entries without generating database errors
- **Automatic cleanup** — daily job at 3:00 AM removes entries older than retention period
- **Raw JSON storage** — full API response stored as-is in JSONB, frontend defines display templates per service
- **Configurable per-service selection** — users choose which services to collect via checkbox UI in Settings page
- **Graceful handling of unavailable services** — services returning dict/error responses are silently skipped

#### Settings — Logs Tab
- **New "Logs" tab in Settings**
- **Checkbox-based service selection** — choose which mailcow services to collect logs from via checkboxes

#### Status Page — Categorized Background Jobs
- **Background jobs grouped by category** with section headers and icons:

#### New Configuration Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `RAW_LOGS_ENABLED` | `true` | Enable/disable raw log collection |
| `RAW_LOGS_FETCH_INTERVAL` | `20` | Seconds between fetch cycles |
| `RAW_LOGS_FETCH_COUNT` | `1000` | Logs per service per cycle |
| `RAW_LOGS_RETENTION_DAYS` | `2` | Days before auto-cleanup (48 hours) |
| `RAW_LOGS_SERVICES` | `all` | Comma-separated list, or `all` for all 10 services |

#### Quarantine Management Actions
- **Release and delete quarantined emails directly from the UI**: The Quarantine page now supports managing quarantined messages when a Read-Write API key (`MAILCOW_API_KEY_RW`) is configured
  - **Per-item actions**: Each quarantine entry shows "Release" and "Delete" buttons
  - **Bulk actions**
  - **Release All / Delete All**: Toolbar buttons to release or delete all visible quarantine items with confirmation
  - When no Read-Write API key is configured, the quarantine page remains read-only (no buttons or checkboxes shown)

#### Mail Queue Management Actions
- **Manage mail queue items directly from the UI**: The Queue page now supports managing queued messages when a Read-Write API key (`MAILCOW_API_KEY_RW`) is configured
  - **Per-item actions**: Each queue entry shows "Retry" (re-attempt delivery), "Hold"/"Unhold" (context-aware), and "Delete" buttons
  - **Bulk actions**
  - Delete and bulk actions require a confirmation dialog
  - **Queue status badge**: Each item displays a color-coded status badge showing the queue name (active=green, deferred=orange, hold=yellow, bounce/corrupt=red, incoming=blue)
  - When no Read-Write API key is configured, the queue page remains read-only

### Fixed

#### Basic Auth Lockout Prevention
- **Credential verification before enabling Basic Auth from UI**: When toggling Basic Auth ON and clicking Save, a **verification modal** now appears asking the user to type their username and password
  - Credentials are validated both **client-side** and **server-side** (timing-safe comparison)
  - Enabling Basic Auth without a password configured is now blocked with a clear error message
- **Clearing password while Basic Auth is enabled is now blocked**: The server now returns `400 Bad Request` if the password is being cleared while Basic Auth is enabled

#### Read-Write API Key Exposure
- **`MAILCOW_API_KEY_RW` now masked in API responses**: The Read-Write API key was not included in the sensitive keys list. It is now masked with `********` like all other sensitive fields

#### Postfix Log Import Crash on Duplicate Key
- **`duplicate key value violates unique constraint "uq_postfix_log"` causing batch loss**: Fixed by using SAVEPOINT pattern so a single failed log insertion does not roll back the entire batch

### Technical

#### New API Endpoints
```
GET  /api/raw-logs/services              - List enabled services with metadata and entry counts
GET  /api/raw-logs/{service}             - Query stored logs (paginated, searchable, filterable)
GET  /api/raw-logs/{service}/smart-filters - Get smart filter definitions for a service
GET  /api/raw-logs/worker-status         - Worker health and job status
WS   /ws/raw-logs?service={service}      - WebSocket endpoint for real-time log streaming
GET  /api/rw-status                      - Check if Read-Write API key is configured
POST /api/quarantine/release             - Release quarantined messages (requires RW API key)
POST /api/quarantine/delete              - Delete quarantined messages (requires RW API key)
POST /api/queue/action                   - Perform queue action: deliver, hold, unhold, flush, super_delete
POST /api/queue/delete                   - Delete mail queue items (requires RW API key)
```

#### Settings API Changes
- `PUT /api/settings`: When `basic_auth_enabled` is being set to `true`, the request body must now include `verify_username` and `verify_password` fields matching the configured credentials

## [2.3.3] - 2026-03-31

### Added

#### Click-to-Copy for Important Data
- **Click-to-copy on key data fields across the application**: Hovering over copyable values reveals a small clipboard icon; clicking copies the value to clipboard with visual feedback (checkmark animation) and a "Copied!" toast notification

#### Date Range Filter on Messages Page
- **Date range picker for filtering messages by time period**: Same dropdown picker pattern as the Mailbox Statistics page
  - **Quick Select presets**: All Time (default), Today, 7 Days, 30 Days, 90 Days
  - **Custom Range**: Manual From/To date picker with validation

#### Security Events Chart by Country
- **Stacked horizontal bar chart** on the Security page showing ban, warning, and unban events grouped by country

#### Fail2Ban Settings & Editing
- **Fail2Ban configuration viewer on Security page**: Two new collapsible panels display the current Fail2Ban configuration fetched live from the mailcow API
  - **Fail2ban Settings**
  - **Fail2ban IP Lists**
  - Settings are fetched once per session and cached in the frontend
  - Both panels are collapsed by default to keep the Security page clean
- **Fail2Ban settings editing**: When a Read-Write API key is configured, users can edit Fail2Ban settings and IP lists directly from the UI
  - Fields start **disabled** — an "Edit Settings" / "Edit IP Lists" button must be clicked first to prevent accidental changes
  - Save sends all parameters to mailcow's `POST /api/v1/edit/fail2ban` endpoint
  - Warning displayed when no Read-Write API key is configured

#### Read-Write API Key (Dual-Key Architecture)
- **New optional `MAILCOW_API_KEY_RW` environment variable** for write operations (editing Fail2Ban, future edit features)
  - The existing `MAILCOW_API_KEY` remains read-only and is used for all data retrieval
  - Write operations require the separate Read-Write key for security separation
  - If no RW key is configured, edit controls are disabled in the UI

#### Settings Improvements
- **Default value comparison**: Settings fields now show whether they differ from their default value
  - Fields changed from default get an **amber border** highlight
  - **"Reset to default (value)"** button appears on changed fields, showing what the default is
  - **"Clear"** button appears on user-specific fields (credentials, connection details, feature toggles) that have a value
  - User-specific settings (auth, SMTP, IMAP, OAuth2 credentials, etc.) show plain "Clear" instead of "Reset to default" since their values are inherently per-deployment
- **Settings field clearing fixed**: Sensitive fields (API keys, passwords) can now be properly cleared — previously, clearing a field was silently ignored

### Technical

#### New API Endpoints
```
GET  /api/fail2ban           - Get Fail2Ban configuration from mailcow (real-time proxy)
POST /api/fail2ban           - Update Fail2Ban configuration (requires RW API key)
GET  /api/fail2ban/rw-status - Check if Read-Write API key is configured
```

#### Settings API Changes
- `GET /api/settings` and `GET /api/settings/info` now include `default_config` in the response — a map of each editable key to its default value (or `null` for required fields with no default)
- `PUT /api/settings` now uses `********` as the "unchanged" sentinel for sensitive keys; empty string properly clears the value

---

## [2.3.2] - 2026-03-25

### Added

#### DNS-over-HTTPS (DoH) Fallback
- **Automatic DoH fallback when UDP port 53 is blocked**: Some VPS providers block outgoing traffic on UDP port 53, preventing DNS record validation (SPF, DKIM, DMARC) and blacklist checks from working
  - DNS queries now try traditional UDP resolvers first (fast path, no change for most users)
  - If all UDP resolvers fail (timeout/blocked), automatically falls back to DNS-over-HTTPS (DoH) via Cloudflare and Google on port 443
  - Applies to all DNS operations: domain DNS validation, blacklist checking, and hostname resolution
  - No configuration needed — fallback is fully automatic

#### Docker Data Directory Permissions Auto-Fix
- **Automatic permission fix for bind-mounted data directory**: When Docker runs as root, the host `./data` directory is created with root ownership, preventing the application (running as UID 1000) from writing to it
  - New `entrypoint.sh` script detects if the container is running as root
  - If root: automatically fix host directory permissions
  - If non-root: starts the application directly without any permission changes
  - No user action required — the fix is built into the image

### Fixed

#### APP_PORT Ignored After Importing Settings to Database
- **Port misconfiguration after .env import**: When using "Import from ENV" to migrate settings to the database, `APP_PORT` was incorrectly imported as an editable setting
  - `APP_PORT` is a Docker-level setting controlling the host port mapping in `docker-compose.yml`, not an application-level setting
  - After removing `APP_PORT` from `.env` (since it was "migrated" to DB), Docker Compose defaulted to port 8080, while the UI/DB still showed the configured port (e.g. 8083)
  - `app_port` is now excluded from editable settings — it remains an ENV/Docker-only setting

### Changed

#### ENV Variables Now Override Database Settings (Lockout Prevention)
- **Settings priority inverted**: ENV variables now always take precedence over database-stored values (new order: Default → DB → ENV)
  - Previously, DB overrode ENV, meaning a configuration mistake in the UI (e.g., wrong OIDC URL, bad auth password) could lock users out with no way to fix it except editing the database directly
  - Now, setting a value in `.env` / `docker-compose.yml` always overrides the DB value, acting as an "escape hatch" for lockout recovery
  - Fields controlled by ENV are marked with a 🔒 lock icon in the Settings UI
  - DB values are still saved and used as fallback when the ENV variable is removed

---

## [2.3.1] - 2026-03-20

### Fixed

#### Critical Security Fix: Basic Auth Credential Bypass
- **Authentication bypass when using `BASIC_AUTH_ENABLED`**: Fixed a critical vulnerability where `BASIC_AUTH_ENABLED=true` accepted **any username and password**
  - Root cause: `verify_credentials()` checked the deprecated `auth_enabled` field (always `false`) instead of `is_basic_auth_enabled`
  - When only `BASIC_AUTH_ENABLED=true` was set (without the deprecated `AUTH_ENABLED`), credential verification was completely skipped
  - Both `BASIC_AUTH_ENABLED` and legacy `AUTH_ENABLED` now work correctly
  - **All users using `BASIC_AUTH_ENABLED=true` should update immediately**

#### Settings Persistence After Restart
- **Settings saved via UI were lost on restart**: Database-stored settings were not loaded during application startup
  - Startup log messages now show effective configuration values (after DB overrides are applied)

#### ENV Conflict Warning False Positives
- **"This value differs from ENV" warning shown incorrectly**: Warning appeared for settings that differed from defaults, even when no ENV variable was explicitly set
  - Warning now only appears when an ENV variable is explicitly set AND differs from the DB value

#### OAuth2 / Service Config Not Working from UI
- **OAuth2, SMTP, and other services ignored UI settings**: Singleton service instances (`OAuth2Client`, `MailcowAPI`) captured settings by value at import time instead of reading dynamically
  - Service configs are now reloaded after settings save, import-from-env, and on startup

#### Health Endpoint Auth Status
- Fixed `/api/health` reporting incorrect authentication status by using the deprecated `auth_enabled` field instead of the actual `is_authentication_enabled` property

---

## [2.3.0] - 2026-03-19

### Added

#### Settings Management via Web UI
- Added settings editor accessible from Settings page (controlled by `SETTINGS_EDIT_VIA_UI_ENABLED=true`)
- Settings organized into tabs: Mailcow, Fetch, Correlation, Application, Blacklist, Authentication, OAuth2, SMTP, Alerts, DMARC, DMARC IMAP, MaxMind
- Settings stored in database override ENV variables
- Migration tool to import current ENV configuration to database
- Visual warnings for settings where ENV differs from DB

#### SSL Verification Toggle for mailcow API
- **Development Environment Support**: Added `MAILCOW_API_VERIFY_SSL` configuration option to allow connections to mailcow API with self-signed SSL certificates
  - Default: `true` (SSL verification enabled for security)
  - Set to `false` for development environments with self-signed certificates
  - All API calls to mailcow now use consistent SSL verification settings
  - Centralized API client ensures all requests use the same configuration

#### DMARC Record Status and Settings on DMARC Domain Page
- **Domain overview**: On the DMARC tab, when viewing a domain (e.g. after clicking a domain), a **DMARC Record** card now shows the current DNS record status and settings
  - **Parsed settings**: Policy, Subdomain policy, Aggregate report URIs (rua), Forensic report URIs (ruf), DKIM/SPF alignment, Percentage, Failure reporting options (only present tags shown)

#### DMARC Reports Automatic Cleanup
- **Scheduled retention cleanup**: Old DMARC and TLS reports are now automatically deleted based on `DMARC_RETENTION_DAYS` (default: 60 days)

#### Blacklist Notifications – Cleared and Improved
- **Cleared notification**: Email alert when all monitored hosts are no longer on any (actionable) blacklists (previously at least one was listed)
- **Improved notification**: Email alert when the number of listed hosts decreases (e.g. from 3 to 2), with subject "Blacklist Improved – X → Y Host(s) Listed" and list of hosts still listed

#### Alias Domains Support for Mail Direction
- **mailcow alias-domain API**: Sync of alias domains from `/api/v1/get/alias-domain/all` so that emails sent from alias domains are classified correctly
- **Direction fallback**: When Rspamd reports inbound (e.g. user unknown), direction is reclassified to outbound if the sender domain is local (including alias) and at least one recipient is external

### Fixed

#### Alias Domain Mail Shown as Inbound
- **Direction classification**: Emails sent from an alias domain (subdomain configured as alias of the main domain) toward the Internet were incorrectly shown as "inbound" in logs. They are now correctly shown as "outbound" by including alias domains in the local domains cache and applying a sender/recipient fallback when Rspamd does not set MAILCOW_AUTH or user for alias-domain sends.

#### DMARC IMAP Sync Application Freezing
- **Connection Timeout and Thread Pool**: Fixed issue where the application would freeze during IMAP connection attempts
  - IMAP sync operations now run in a thread pool executor to prevent blocking the event loop
  - Improved error messages with detailed host and port information for easier troubleshooting
  - Connection errors are now handled gracefully without crashing the application

#### Basic Auth Login with Wrong Credentials
- **Login validation**: Fixed issue where entering incorrect username or password did not show an error and gave the illusion of successful login
  - Login form now calls `GET /api/auth/verify` (protected endpoint) instead of `/api/info` (public) to validate credentials
  - Invalid credentials now return 401 and display "Invalid username or password" on the login page
  - Credentials and password field are cleared on failure

### Technical

#### New Environment Variables
- `MAILCOW_API_VERIFY_SSL` - Control SSL certificate verification for mailcow API connections (default: `true`)
  - Set to `false` for development environments with self-signed certificates
  - All mailcow API requests respect this setting
- `SETTINGS_EDIT_VIA_UI_ENABLED` - Enable settings editor in UI (default: `false`)
  - Set to `true` to enable settings editor in UI
  - Set to `false` to disable settings editor in UI

---

## [2.2.5] - 2026-02-15

### Added

#### OAuth2/OIDC Authentication Support
- **Generic OAuth2/OIDC Integration**: Complete OAuth2/OIDC authentication support for any standard identity provider
  - Works with Authentik, Mailcow, Keycloak, Google, Microsoft Azure AD, Auth0, and any OAuth2/OIDC provider
  - Supports both OIDC Discovery (automatic endpoint discovery) and manual endpoint configuration
  - Provider-agnostic implementation - no provider-specific code required
  - Dual authentication methods: Both Basic Auth and OAuth2 can be enabled simultaneously
  - Secure session management with HTTP-only cookies
  - **See [OAuth2 Configuration Guide](./documentation/OAuth2_Configuration.md) for detailed setup instructions**

#### mailcow Update Indicator
- **Footer Update Badge**: Added a distinct "Update Available" badge in the footer for Mailcow server updates.
  - Complements the existing header icon.
  - Clickable to view the full changelog in a modal.

#### Live Container Logs
- **Terminal Viewer**: Added a terminal icon `(>_)` in the footer to view application logs directly from the UI.
- **Live Updates**: Logs modal automatically refreshes every 2 seconds for real-time monitoring.
- **Auto-Scroll**: Smart scrolling logic keeps view at the bottom during updates unless user scrolls up.

### Changed

#### Authentication Configuration
- **Simplified Authentication Flags**: Removed `AUTH_METHOD` configuration option
  - Authentication method now determined automatically by enabled flags
  - `BASIC_AUTH_ENABLED=true` enables Basic Auth
  - `OAUTH2_ENABLED=true` enables OAuth2
  - Both can be enabled simultaneously for dual authentication
  - `AUTH_ENABLED` still supported for backward compatibility (deprecated)

- **Login Page Enhancement**: Dynamic authentication method display
  - OAuth2 login button appears when OAuth2 is enabled
  - Basic Auth form appears when Basic Auth is enabled
  - "OR" separator only shown when both methods are available
  - Provider name dynamically displayed on OAuth2 button

#### GDPR Compliance
- **Local Resource Loading**: All external JavaScript and CSS resources now loaded from local server
  - Removed all CDN dependencies (Tailwind CSS, Marked.js, Chart.js, GitHub Markdown CSS)
  - All libraries now served from `/static/assets/libs/` directory
  - Application is now GDPR compliant with no external resource requests
  - No data transfer to third-party CDN services (jsdelivr, cdnjs, etc.)

### Fixed

#### Container Status Counting
- **Stopped Containers Not Counted**: Fixed issue where stopped containers were not being counted in the "Stopped" total on the Status page
  - mailcow API only returns active containers, so stopped containers don't appear in the response
  - Implemented database cache system (`known_containers` table) to track all containers that have been seen
  - Containers are automatically added to cache when first seen in API response
  - Stopped containers (known but not in API response) are now correctly identified and counted as "Stopped"
  - Ensures accurate container counts even when containers are completely stopped

#### IP Blacklist Monitor
- **Spamhaus DNS Query Blocking**: Fixed issue where Spamhaus was blocking DNS queries, causing incorrect "Clean" status when IPs were actually listed on blacklists

#### Domain DNS Checks
- **DNS Reliability**: Added DNS fallback system for all domain DNS validation checks (SPF, DKIM, DMARC) to prevent false negatives due to DNS server failures

### Technical

#### New API Endpoints
```
GET  /api/auth/login          - Initiate OAuth2 login flow
GET  /api/auth/callback       - Handle OAuth2 callback from provider
GET  /api/auth/logout         - Logout and clear session
GET  /api/auth/status         - Check authentication status
GET  /api/auth/provider-info  - Get provider configuration for frontend
```

#### New Environment Variables
- OAuth2/OIDC configuration variables (see `env.example` and [OAuth2 Configuration Guide](./documentation/OAuth2_Configuration.md))
- `BASIC_AUTH_ENABLED` - New flag for Basic Auth (replaces deprecated `AUTH_ENABLED`)

---

## [2.2.0] - 2026-01-28

### Added

#### Weekly Server Summary Report
- **Automated Weekly Email Report**: Comprehensive server status report sent every Friday
  - **System Health**: Mailbox/Alias/Domain counts, Storage usage, Queue & Quarantine stats
  - **Traffic Overview**: Total Sent/Received messages, Failure rates with visual severity indicators
  - **Blacklist Status**: Current status of all monitored hosts (shows detailed RBLs if listed)
  - **DNS Security**: Alerts for domains with critical SPF/DKIM/DMARC configuration errors
  - **Problem Areas**: "Top 5 Worst Mailboxes" table identifying accounts with high failure rates
  - Configurable via `ENABLE_WEEKLY_SUMMARY` (default: true) and `ADMIN_EMAIL`

#### IP Blacklist Monitor
- **DNS Blacklist Checking**: New feature to check mail server IP against ~50 popular DNSBLs
  - Real-time checking against major blacklists: Spamhaus ZEN/SBL/XBL/PBL, Barracuda, SpamCop, SORBS, UCEPROTECT, and more
  - Status page section with summary cards (Server IP, Status, Listed Count, Last Check)
  - Expandable list showing all 50+ blacklist check results
  - "Check Now" button for manual refresh
  - Dashboard summary card for quick status overview

- **Automated Daily Checks**: Background scheduler runs daily at 5:00 AM
  - Results cached for 24 hours to prevent excessive DNS queries
  - Startup check runs 60 seconds after application start
  - Job status visible in Background Jobs section on Status page

- **Email Notifications**: Automatic alerts when server is listed on blacklists
  - Sends detailed HTML email with list of blacklists where server is listed
  - Includes lookup links for each blacklist
  - Configurable via `BLACKLIST_ALERT_EMAIL` (falls back to `ADMIN_EMAIL`)

#### DMARC Reports Management
- **Reports Management Modal**: New popup to view and manage all DMARC and TLS reports
  - Clickable "Manage Reports" link below the domains table
  - Mobile-responsive card layout for smaller screens
  - Color-coded type badges (blue for DMARC, green for TLS)

- **Report Deletion**: Optional ability to delete individual reports
  - Controlled by `DMARC_ALLOW_REPORT_DELETE` environment variable (default: false)
  - When enabled, delete button appears for each report
  - Confirmation dialog before deletion
  - Cascading delete removes associated records (DMARCRecord/TLSReportPolicy)
  - Automatically clears DMARC cache after deletion
  - Refreshes both modal and domains list after successful deletion

### Changes

#### Background Jobs Improvements
- **Manual Job Execution**: Added "Run Now" buttons to each background job card
  - Allows manually triggering any of the 13 background jobs
  - Displays loading state and success/warning toast notifications
  - Toasts now show human-readable job names (e.g. "Alias Statistics")

- **UI Updates**:
  - Wrapped "Background Jobs" section in a collapsible accordion (closed by default) to save space

### Fixed

#### SPF Validation
- **Recursive Redirect Support**: Added full support for SPF `redirect=` mechanism
  - Now correctly follows redirects to target domains
  - Recursively validates IP authorization against the redirected policy

#### DKIM Validation
- **Flexible Tag Parsing**: Improved DKIM record normalization
  - Now correctly handles spaces between tags (e.g., `v=DKIM1; k=rsa` vs `v=DKIM1;k=rsa`)
  - Prevents false negatives when DNS providers add optional whitespace

#### Mailbox Stats
- **Rate Limit Display**: Fixed issue where Rate Limit was displaying as "None" even when configured
  - Adjusted backend ingestion to correctly parse nested Rate Limit objects from Mailcow API response

#### General
- **Naming Consistency**: Renamed "Mailcow" to "mailcow" across the application to match the official product name
  - Updated frontend interface labels and logs
  - Updated backend logs, API descriptions, and configuration fields
  - Updated documentation and README

- **Email Subject Quote Display**: Fixed escaped quotes (`\"`) appearing in email subjects
  - Subjects with double quotes now display correctly without backslashes

- **Job Status Persistence**: Fixed issue where jobs (like `expire_correlations`, `cleanup_logs`) were getting stuck in "running" state if no items were processed.

- **Spam Alias Logic Support**: Enhanced log parsing to correctly handle emails delivered to spam aliases (e.g., `spam@localhost`)
  - Parses `orig_to` field from Postfix logs to identify the real recipient
  - Detects deliveries to `rspamd-pipe-spam` command
  - Marks email status as `SPAM` instead of `CLEAN/Delivered` when routed to spam alias
  - Correctly associates the log with the original recipient

- **Rspamd SPAM_TRAP Detection**: Added support for `SPAM_TRAP` symbol in Rspamd logs
  - Automatically marks emails as `SPAM` if the `SPAM_TRAP` symbol is present in the Rspamd result
  - Updates both the Rspamd log record and the associated correlation status

### Technical

#### New API Endpoints
```
GET    /api/dmarc/reports/config  - Get report management configuration
GET    /api/dmarc/reports/all     - Get all DMARC and TLS reports
DELETE /api/dmarc/reports/{type}/{id} - Delete a specific report
GET /api/blacklist/check        - Get blacklist check results (uses cache)
GET /api/blacklist/check?force=true - Force new check ignoring cache
GET /api/blacklist/config       - Get blacklist configuration
GET /api/blacklist/summary      - Get compact summary for dashboard
POST /api/settings/jobs/{job_name}/run

#### New Environment Variables
- `DMARC_ALLOW_REPORT_DELETE`: Enable/disable report deletion from UI (default: false)
- `BLACKLIST_ALERT_EMAIL`: Email address for blacklist alerts (optional, uses `ADMIN_EMAIL` if not set)
- `ENABLE_WEEKLY_SUMMARY`: Enable/disable weekly server summary report (default: true)

---

## [2.1.2] - 2026-01-20

### Added

#### Mailbox Statistics Page
- **Complete Mailbox Statistics Feature**: New page showing per-mailbox message statistics
  - Summary cards: Total Sent, Received, Failed, and Failure Rate
  - Accordion-style mailbox list with expandable details
  - Message counts aggregated from MessageCorrelation table (not Mailcow API)
  - Per-alias message statistics with sent/received/failed counts
  - Combined totals (mailbox + all its aliases)

- **Clickable Statistics Links**: All stat cards and alias table cells are clickable
  - Click on any stat (Sent, Received, Internal, Delivered, Deferred, Bounced, Rejected) to navigate to Messages page
  - Search automatically pre-filled with the mailbox/alias email address

- **Mailbox Details Display (Domains-style)**:
  - Quota usage with percentage
  - Messages in mailbox count
  - Last IMAP/SMTP/POP3 login times
  - Created and Modified dates
  - Rate limiting settings (value/frame)
  - Access permissions indicators: IMAP, POP3, SMTP, Sieve, SOGo, TLS Enforce
  - Color-coded status dots (green=enabled, red=disabled)

- **Filtering & Search**:
  - **Date Range Picker with Presets**:
    - Quick select preset buttons: Today, 7 Days, 30 Days, 90 Days
    - Custom date range with From/To date inputs
  - Domain filter dropdown
  - Search by mailbox username, name, or alias address
  - "Active Only" checkbox (default: checked)
  - "Hide Zero Activity" checkbox (default: checked) - filters mailboxes and aliases with no messages
  - Sort by: Sent, Received, Failure Rate, Quota Used, Username

- **Pagination**: 50 mailboxes per page with navigation controls

#### Background Jobs
- **Mailbox Statistics Job**: Fetches mailbox data from Mailcow API every 5 minutes
  - Syncs quota, messages, login times, rate limits, and attributes
  - Marks deleted mailboxes as inactive (preserves historical data)
  
- **Alias Statistics Job**: Fetches alias data from Mailcow API every 5 minutes
  - Links aliases to their target mailboxes
  - Marks deleted aliases as inactive (preserves historical data)

#### SMTP Relay Mode
- **No-Authentication SMTP Support**: New option for sending emails through local relay servers without credentials
  - Enable via `SMTP_RELAY_MODE=true` in environment variables
  - When enabled, `SMTP_USER` and `SMTP_PASSWORD` are not required
  - Useful for local Postfix relay servers, internal mail gateways, or trusted SMTP relays
  - Connection test in Settings page properly handles relay mode authentication bypass

#### Clean URL Routing (History API)
- **Shareable URLs for All Pages**: Implemented History API-based routing for the SPA
  - Direct navigation to any tab via clean URLs (e.g., `/dashboard`, `/messages`, `/dmarc`, `/settings`)
  - Browser Back/Forward buttons now work correctly between pages
  - URLs can be bookmarked and shared

- **DMARC Nested Routes**: Deep linking support for all DMARC views
  - `/dmarc` - Domains list
  - `/dmarc/{domain}` - Domain overview
  - `/dmarc/{domain}/reports` - Daily Reports tab
  - `/dmarc/{domain}/sources` - Source IPs tab
  - `/dmarc/{domain}/tls` - TLS Reports tab
  - `/dmarc/{domain}/report/{date}` - Specific daily report details
  - `/dmarc/{domain}/source/{ip}` - Specific source IP details

- **Removed Internal Back Button**: DMARC section no longer uses custom back button
  - Users now use browser's native Back button
  - Cleaner UI without duplicate navigation controls

#### TLS-RPT (TLS Reporting) Support
- **Complete TLS-RPT Implementation**: Full support for TLS aggregate reports (RFC 8460)
  - TLS-RPT parser for JSON reports (gzip compressed)
  - Database models for TLS reports and policies
  - IMAP auto-import support for TLS-RPT emails
  - Manual upload support for TLS-RPT files

- **TLS Reports Tab in DMARC Page**:
  - New "TLS Reports" sub-tab alongside Daily Reports and Source IPs
  - Daily aggregated view showing reports grouped by date
  - Success rate with color-coded progress bars (green ≥95%, yellow ≥80%, red <80%)
  - Provider breakdown with session counts

- **TLS Report Details View**:
  - Click any daily report to see detailed breakdown
  - Stats cards: Sessions, Success Rate, Successful, Failed
  - Providers table with per-provider success rates

- **TLS in Domain List**:
  - TLS Success Rate column in DMARC domains table
  - TLS report count displayed per domain
  - Domains with only TLS reports (no DMARC) now included in list

#### DMARC Navigation Improvements
- **Breadcrumb Navigation**: Clear path indicator for all DMARC views
  - Shows current location: `domain.com > Daily Reports > Jan 14, 2026`
  - Clickable links to navigate back to any level
  - Displayed below page description

#### Mobile Navigation Hamburger Menu
- **Hamburger Menu for Mobile**: 
  - Replaced horizontal scrolling tabs with a proper hamburger menu on mobile devices

### Fixed

#### DMARC Source IPs - Broken Flag Images
- **Fixed broken flag images when MAXMIND is not configured**: When GeoIP integration is not set up, the Source IPs tab was showing broken images
  - Now displays a generic server icon instead of a broken image when country data is unavailable
  - Flag is completely hidden in source details view when no GeoIP data exists
  - Added `onerror` fallback handlers to gracefully handle missing flag files
  - Improves UX for users who haven't configured MAXMIND integration

#### DMARC Parser
- **DMARC 2.0 XML Namespace Support**: Fixed parsing error for DMARC reports using XML namespaces
  - Reports from GMX and other providers using the new format now parse correctly
  - Parser now tries both namespaced and non-namespaced element lookups

### Improved

#### Backend API Performance
- **In-Memory Caching for Statistics API**: Added 5-minute TTL cache for `/api/mailbox-stats/all` endpoint
  - Cache key generated from all query parameters
  - First request fetches from database, subsequent requests return from cache
  - Cache automatically expires after 5 minutes for fresh data
  - Significantly reduces database load and improves response times

- **In-Memory Caching for DMARC API**: Added 5-minute TTL cache for `/api/dmarc/domains` endpoint
  - Reduces heavy database queries for domain statistics
  - Cache cleared on new report imports

#### DMARC IMAP Auto-Import
- **Batch Processing**: Emails are now processed in configurable batches to prevent memory issues
  - New `DMARC_IMAP_BATCH_SIZE` environment variable (default: 10)
  - Processes emails in chunks, re-searching after each batch
  - Progress logging shows batch number and completion status
  - Prevents application crashes when syncing mailboxes with lots of emails

- **UID-Based Email Handling**: Fixed "Invalid messageset" IMAP errors
  - Changed from sequence numbers to UIDs for all IMAP operations
  - UIDs remain stable even after deleting emails during sync
  - Affects SEARCH, FETCH, STORE operations

- **Flexible DMARC Email Detection**: Now supports more email providers
  - Yahoo and other providers that don't include "Report-ID:" now detected correctly
  - Primary validation is now attachment-based (.xml.gz or .zip files)
  - Accepts: "Report Domain:" only, "Report Domain:" + "Submitter:", or "DMARC" keyword
  
- **Improved Error Reporting in Notifications**: 
  - Error notification emails now show actual error messages
  - Parse failures show: "Failed to parse: filename.xml.gz"
  - Processing errors show: "Error processing filename: exception details"
  - Duplicate reports no longer counted as failures

- **Infinite Loop Prevention**: Fixed sync running endlessly when emails fail validation
  - Added `UNSEEN` filter to search criteria
  - Failed or processed emails are marked as Seen and excluded from next search
  - Prevents re-processing the same emails repeatedly

- **Microsoft Outlook Support**: Fixed DMARC reports from Microsoft not being recognized
  - Now detects DMARC reports by filename pattern (contains `!` separator)
  - Supports filenames like: `enterprise.protection.outlook.com!domain!timestamp!timestamp.xml.gz`

- **Enhanced Attachment Extraction**: More robust attachment detection
  - Now supports plain `.xml` files in addition to `.xml.gz` and `.zip`
  - Falls back to Content-Type `name` parameter when filename header is missing
  - Recognizes attachments by Content-Type: `application/gzip`, `application/zip`, `text/xml`, etc.
  - Added debug logging to help troubleshoot attachment detection issues

#### Domains Page - DKIM View Record
- **DKIM Record Viewer**: Added "View Record" functionality for DKIM, similar to SPF
  - Displays the full DNS record name including selector (e.g., `dkim._domainkey.example.com`)
  - Shows the DKIM public key record value
  - Helps users identify exactly which DNS record to configure

### Technical

#### New API Endpoints
```
GET  /api/mailbox-stats/summary
GET  /api/mailbox-stats/all
GET  /api/mailbox-stats/domains
```

#### API Parameters
- `date_range`: today, 7days, 30days, 90days, custom
- `start_date`: Custom start date (YYYY-MM-DD) - required when date_range is 'custom'
- `end_date`: Custom end date (YYYY-MM-DD) - required when date_range is 'custom'
- `domain`: Filter by specific domain
- `active_only`: true/false
- `hide_zero`: true/false (filter zero-activity mailboxes)
- `search`: Search mailbox/alias addresses
- `sort_by`: sent_total, received_total, failure_rate, quota_used, username
- `sort_order`: asc, desc
- `page`, `page_size`: Pagination

---

## [2.0.4] - 2026-01-15

### Fixed

### DMARC Manual Upload Button Not Showing
- Fixed issue where manual upload button was hidden even when enabled in settings

### DKIM Record Validation False Negatives
- Fixed DKIM validation incorrectly reporting mismatch when parameter order differs
- Changed validation from string comparison to parameter-based comparison
- DKIM records now validated correctly regardless of parameter order (e.g., `p=...;s=t` equals `s=t;p=...`)
- Follows RFC standard where DKIM parameter order is insignificant

---

## [2.0.0] - 2026-01-14

### Added

#### DMARC Backend
- Daily data aggregation for performance
- GeoIP enrichment with MaxMind database support (City + ASN)
- Automatic MaxMind database downloads and updates
- Weekly scheduler for MaxMind databases updates (Sunday 3 AM)

#### DMARC Frontend - Complete UI Implementation
- **Domains List View**: 
  - Stats dashboard showing total domains, messages, pass rate, and unique IPs
  - Full domain overview with 30-day statistics
  - Color-coded pass rates (green ≥95%, yellow ≥80%, red <80%)
  - Policy badges (reject/quarantine/none) with appropriate styling
  - Empty state with helpful messaging for first-time users
  
- **Domain Overview Page**:
  - Breadcrumb navigation in DMARC page
  - Domain-specific stats cards (total messages, compliance rate, unique sources)
  - Daily Volume Graph showing 30-day email trends

- **Daily Reports Tab**:
  - Aggregated daily report cards
  - Shows report count, unique IPs, total messages per day
  - SPF and DKIM pass percentages displayed
  - Overall DMARC pass rate
  - Chronological ordering (newest first)
  
- **Source IPs Tab with Complete GeoIP Info**:
  - City names from MaxMind City database
  - ISP/Organization names
  - Country flag emoji display
  - Message counts and pass rates per IP
  
- **Upload DMARC Functionality**:
  - Upload button
  - Supports XML, GZ, and ZIP file formats
  - Toast notifications for success/duplicate/error states
  - Auto-refresh of current view after successful upload
  - Client-side file validation

#### DMARC IMAP Auto-Import System
- **Automatic Report Fetching**: Complete IMAP integration for automatic DMARC report imports
  - Configurable sync interval (default: 1 hour) via `DMARC_IMAP_INTERVAL`
  - Automatic connection to IMAP mailbox and report processing
  - Supports SSL/TLS connections (`DMARC_IMAP_USE_SSL`)
  - Configurable folder monitoring (default: INBOX via `DMARC_IMAP_FOLDER`)
  - Optional email deletion after processing (`DMARC_IMAP_DELETE_AFTER`)
  - Background job runs automatically at specified intervals
  - Manual sync trigger available in DMARC page
  
- **DMARC IMAP Sync History**:
  - Comprehensive sync statistics tracking (emails found, processed, created, duplicates, failed)
  - Interactive modal showing all past sync operations
  - Color-coded status indicators (success/error)
  - Duration display for each sync
  - Failed email count with highlighting
  - "View History" button in DMARC tab
  - Sync history persists across restarts

- **DMARC Error Notifications**: Automatic email alerts for IMAP sync failures
  - Sends detailed error reports when IMAP sync encounters failures
  - Email includes: failed email count, message IDs, subjects, and error descriptions
  - Link to sync history in notification email
  - Only sends when failures occur and SMTP is configured
  - Configurable error recipient via `DMARC_ERROR_EMAIL` (defaults to `ADMIN_EMAIL`)

#### Global SMTP Configuration & Notifications
- **Centralized SMTP Service**: Generic email infrastructure for all notification types
  - Configured via environment variables: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`
  - Support for TLS/SSL connections (`SMTP_USE_TLS`)
  - Configurable sender address (`SMTP_FROM`) and admin email (`ADMIN_EMAIL`)
  - Can be enabled/disabled globally (`SMTP_ENABLED`)
  - Ready for future notification types beyond DMARC

- **Settings UI Enhancements**:
  - New "Global SMTP Configuration" section showing current SMTP settings
  - New "DMARC Management" section showing manual upload and IMAP status
  - Display of SMTP server, port, and admin email when configured
  - Display of IMAP server when auto-import enabled

- **Test Connection Buttons**: 
  - Added diagnostic test buttons in Settings page for both SMTP and IMAP
  - Interactive popup showing connection attempt logs in real-time
  - Tests authentication, server connectivity, mailbox access, and email sending

#### DMARC Tab Enhancements
- **IMAP Sync Controls**: Dynamic UI based on configuration
  - "Sync from IMAP" button appears when IMAP auto-import enabled
  - "Upload Report" button hidden when manual upload disabled (`DMARC_MANUAL_UPLOAD_ENABLED=false`)
  - Last sync information displayed below sync button (time and status icon)

#### MaxMind GeoIP Integration
- **Configuration**:
  - MaxMind account ID and license key via .env
  - `MAXMIND_ACCOUNT_ID` - MaxMind account ID
  - `MAXMIND_LICENSE_KEY` - MaxMind license key
  - Free GeoLite2 databases available at maxmind.com
  - Databases stored in `/app/data/` directory

- **Automatic Database Management**:
  - Auto-downloads MaxMind GeoLite2 databases on first startup
  - Dual database support: GeoLite2-City + GeoLite2-ASN
  - Weekly automatic updates (Sunday 3 AM via scheduler)
  - Database persistence via Docker volume mount (`./data:/app/data`)
  
- **GeoIP Enrichment Service**:
  - Enriches all DMARC source IPs automatically during upload
  - Dual readers for City and ASN lookups
  - City names, Country code, Country name, Country emoji flags
  - ASN Number, ASN organization
  
- **Graceful Degradation**:
  - Works without MaxMind license key (returns null for geo fields)
  - Continues operation if databases unavailable
  - Default globe emoji (🌍) for unknown locations
  - Non-blocking errors (logs warnings but doesn't crash)
  
- **Background Job**:
  - Runs weekly on Sunday at 3 AM
  - Checks database age (updates if >7 days old)
  - Downloads both City and ASN Databases
  - Automatic retry with exponential backoff
  - Status tracking in Status page

- **MaxMind License Validation**: Added real-time validation of MaxMind license key in Settings page
  - Validates license key using MaxMind's validation API
  - Displays status badge: "Configured" (green with checkmark) or "Not configured" (gray)
  - Shows error details if validation fails (red badge with X icon)

#### SPF Validation Enhancements
- **DNS Lookup Counter**: SPF validation now counts and validates DNS lookups according to RFC 7208
  - Recursive counting through `include:` directives
  - Counts `a`, `mx`, `exists:`, `redirect=`, and `include:` mechanisms
  - Maximum limit of 10 DNS lookups enforced
  - Returns error when limit exceeded: "SPF has too many DNS lookups (X). Maximum is 10"

- **Server IP Authorization Check**: SPF validation now verifies mail server IP is authorized
  - Fetches server IP from Mailcow API on startup
  - Caches IP in memory for performance (no repeated API calls)
  - Checks if server IP is authorized via:
    - Direct `ip4:` match (including CIDR ranges)
    - `a` record lookup
    - `mx` record lookup
    - Recursive `include:`
  - Returns error if server IP not found in SPF: "Server IP X.X.X.X is NOT authorized in SPF record"
  - Shows authorization method in success message: "Server IP authorized via ip4:X.X.X.X"

- **Enhanced SPF Validation**: Complete SPF record validation
  - Detects multiple SPF records (RFC violation - only one allowed)
  - Validates basic syntax (`v=spf1` with space)
  - Checks for valid mechanisms only (ip4, ip6, a, mx, include, exists, all)
  - Validates presence of `all` mechanism
  - Prevents infinite loops in circular includes
  - Depth protection (maximum 10 recursion levels)

#### DKIM Parameter Validation
- **Testing Mode Detection** (`t=y`): Critical error detection
  - Detects DKIM testing mode flag
  - Returns error status with message: "DKIM is in TESTING mode (t=y)"
  - Warning: "Emails will pass validation even with invalid signatures. Remove t=y for production!"
  - Prevents false validation in production environments

- **Strict Subdomain Mode Detection** (`t=s`): Informational flag
  - Detects strict subdomain restriction flag
  - Displayed as informational text (not warning)
  - Message: "DKIM uses strict subdomain mode (t=s)"
  - Does NOT affect DKIM status (remains "success")

- **Revoked Key Detection** (`p=` empty): Error detection
  - Detects intentionally disabled DKIM keys
  - Returns error status with message: "DKIM key is revoked (p= is empty)"
  - Indicates DKIM record has been decommissioned

- **Weak Hash Algorithm Detection** (`h=sha1`): Security warning
  - Detects deprecated SHA1 hash algorithm
  - Returns warning status with message: "DKIM uses SHA1 hash algorithm (h=sha1)"
  - Recommendation: "SHA1 is deprecated and insecure. Upgrade to SHA256 (h=sha256)"

- **Key Type Validation** (`k=`): Configuration check
  - Validates key type is `rsa` or `ed25519`
  - Warning for unknown key types
  - Helps identify configuration errors

### Fixed

#### Message Correlation System
- **Final Status Update Job Enhancement**: Fixed correlations not updating when Postfix logs arrive milliseconds after correlation creation
  - Increased batch size from 100 to 500 correlations per run for faster processing
  - Fixes race condition where `status=sent` logs arrived seconds after correlation was marked complete
  - Improved logging to show how many logs were added to each correlation

#### Postfix Log Deduplication
- **UNIQUE Constraint Added**: Postfix logs now have database-level duplicate prevention
  - Automatic cleanup of existing duplicate logs on startup (keeps oldest entry)
  - Import process now silently skips duplicate logs (no error logging)
  - Batched deletion (1000 records at a time) to prevent database locks
  - Handles NULL `queue_id` values correctly using `COALESCE`
  - Prevents duplicate log imports when fetch job runs faster than log generation rate
  - Improved logging shows count of duplicates skipped during import

### Technical

#### New API Endpoints
```
GET  /api/dmarc/domains?days=30
GET  /api/dmarc/domains/{domain}/overview?days=30
GET  /api/dmarc/domains/{domain}/reports?days=30
GET  /api/dmarc/domains/{domain}/sources?days=30
POST /api/dmarc/upload
GET /api/dmarc/imap/status
POST /api/dmarc/imap/sync
GET /api/dmarc/imap/history
POST /api/settings/test/smtp
POST /api/settings/test/imap
```

---

## [1.4.8] - 2026-01-08

### Added

#### Automated Domains DNS Validation
- **Automated Background Checks**:
  - DNS checks run automatically every 6 hours via scheduler
  - Checks only active domains to optimize performance
  - Results cached with timestamps for quick display

- **Manual DNS Verification**:
  - **Global Check**: "Check Now" button in Domains Overview header
    - Updates all active domains simultaneously
    - Updates global "Last checked" timestamp
  - **Single Domain Check**: Individual "Check" button per domain
    - Updates only the specific domain without page refresh
    - Partial UI update for better UX
  - Toast notifications for user feedback on all check operations

- **DNS Check Results Display**:
  - Last check timestamp displayed in page header (global checks only)
  - Last check timestamp per domain in DNS Security Records section

#### Backend Infrastructure
- **New Database Table**: `domain_dns_checks`
  - Stores SPF, DKIM, DMARC validation results as JSONB
  - Includes `checked_at` timestamp and `is_full_check` flag
  - Automatic migration with PostgreSQL artifact cleanup
  
- **New API Endpoints**:
  - `GET /api/domains/all` - Fetch all domains with cached DNS results
  - `POST /api/domains/check-all-dns` - Trigger global DNS check (manual)
  - `POST /api/domains/{domain}/check-dns` - Check specific domain DNS

#### Frontend Enhancements
- **Responsive Design**: Mobile-optimized layout
  - Header elements stack vertically on mobile, horizontal on desktop
  - Centered content on mobile for better readability
  - Check button and timestamp properly aligned on all screen sizes

- **Toast Notifications**: User feedback system
  - Success, error, warning, and info message types
  - Color-coded with icons (✓, ✗, ⚠, ℹ)
  - Auto-dismiss after 4 seconds
  - Manual dismiss option

#### Background Jobs Monitoring & Enhanced UI
- **Real-time Status Tracking**: All background jobs now report execution status (running/success/failed/idle/scheduled), last run timestamp, and error messages
- **Enhanced Visual Design**: 
  - Compact mobile-optimized layout
  - Full-color status badges (solid green/blue/red/gray/purple backgrounds with white text)
  - Icon indicators: ⏱ interval, 📅 schedule, 🗂 retention, ⏳ max age, 📋 pending items
  - Always-visible last run timestamps
- **Complete Job Coverage**: All 7 background jobs now visible in UI (previously only 5 were displayed):
  - Fetch Logs, Complete Correlations, Update Final Status, Expire Correlations, Cleanup Logs, Check App Version, DNS Check

### Changed

#### Queue and Quarantine Page
- **Display Order**: Quarantine page now displays newest messages first
  - Messages sorted by creation timestamp in descending order (newest → oldest)
  - Backend sorting ensures consistent ordering

#### Dashboard - Recent Activity
- **Layout Improvement**: Reorganized Status & Direction display for better readability
  - Status and Direction badges now displayed on first line, right-aligned
  - Timestamp moved to second line below badges

### Background Jobs and Status Page
- Background job status badges now use consistent full-color styling across all themes
- Check App Version and DNS Check jobs now properly displayed in Status page
- Simplified function signatures by removing redundant description parameters

---

## [1.4.7] - 2026-01-06

### Added

#### Domains Management Feature
- **Complete Domains Manager**: New comprehensive interface for Viewing Mailcow domains
  - Real-time DNS security validation (SPF, DKIM, DMARC)
  - Summary statistics dashboard (Total, Active, Inactive domains)
  - Search and filter functionality

#### Domain Information Display
- **Core Statistics**:
  - Mailboxes: used/max with available count
  - Aliases: used/max with available count
  - Storage: used/max (or unlimited)
  - Total message count
  - Created date
  
- **Relay Configuration**:
  - Backup MX status (`backupmx`)
  - Relay All Recipients status (`relay_all_recipients`)
  - Relay Unknown Only status (`relay_unknown_only`)

#### DNS Security Validation
- **Automated DNS Checks**:
  - **SPF (Sender Policy Framework)**:
    - Detects all policy types: `-all`, `~all`, `?all`, `+all`, and missing `all`
    - Color-coded status indicators
    - Policy-specific recommendations
  - **DKIM (DomainKeys Identified Mail)**:
    - Fetches configuration from Mailcow API
    - Queries DNS for actual DKIM record
    - Compares expected vs actual records
  - **DMARC (Domain-based Message Authentication)**:
    - Checks for existence at `_dmarc.domain.com`
    - Validates policy (p=reject/quarantine/none)
    - Recommendations for stricter policy

- **DNS Status Indicators**:
  - Color-coded icons: ✓ (green), ⚠ (amber), ✗ (red), ? (gray)

### Changed

#### Quarantine Page Enhancement
- **UI Redesign**: Completely redesigned Quarantine page to match Messages page layout and design
  - Changed from basic card layout to professional grid-based design
  - Added sender → recipient display with visual arrow indicator
  - Improved visual hierarchy with better spacing and organization
  - Added hover effects for better interactivity
  - Fully responsive design for mobile and desktop
  - Complete dark mode support

- **Additional Information Display**: Enhanced Quarantine page to show more useful information
  - **Recipient (rcpt)**: Now displayed next to sender with arrow (→) separator
  - **Spam Score**: Displayed in metadata row with red highlighting for scores >= 15
  - **Virus Flag**: Purple badge with 🦠 emoji appears when virus is detected
  - **Queue ID (qid)**: Displayed in metadata row for reference
  - **Action Badge**: Action (reject/quarantine) now shown as colored badge instead of plain text
  - **Result Count**: Added total count display in page header (e.g., "Quarantined Messages (3 results)")

### Fixed

#### Quarantine Timestamp Display
- **Timestamp Formatting**: Fixed timestamp display in Quarantine page to be consistent with other pages
  - Quarantine timestamps now properly formatted with UTC timezone indicator ('Z' suffix)
  - Backend endpoint `/api/quarantine` now processes timestamps before returning to frontend

### Technical

#### Backend (`domains.py`)
- **New API Router**: `/api/domains` endpoint
- **DNS Validation Functions**:
  - `check_spf_record()`: Enhanced SPF validation with comprehensive policy detection
  - `check_dkim_record()`: DKIM validation with flexible API response handling
  - `check_dmarc_record()`: DMARC validation with policy checking
- **Async Operations**: All DNS queries use async resolver for better performance
- **Error Handling**: Comprehensive try-except blocks with detailed logging

---

## [1.4.6] - 2026-01-05

### Added

#### Version Check Improvements
- **Periodic Version Check**: Version check now runs automatically every 6 hours (instead of only on container startup)
  - Background scheduler job checks for app updates from GitHub
  - Runs immediately on startup, then every 6 hours

- **Manual Version Check Button**: Added "Check Now" button in Settings page
  - Located next to "Latest Version" badge
  - Allows users to manually trigger version check at any time

#### Settings Page Enhancements
- **Version Information Improvements**:
  - Added last checked date display next to "Latest Version" in Settings page
  - Added clickable version number (Current Version) to view changelog in popup modal
  - Added changelog display in update notification area

- **Mailcow Connection Indicator**: Added connection status indicator in header next to application name
  - Green checkmark when connected to Mailcow
  - Red X when not connected
  - Status updates automatically via `/api/status/mailcow-connection` endpoint

### Changed

#### Version Check Behavior
- **Background Updates**: Version check endpoint now supports `force` parameter to bypass cache
- **UI Updates**: Version information updates in real-time without page refresh
  - Latest version display updates immediately
  - Badge status ("Update Available" / "Up to Date") updates dynamically
  - Update notification message appears/disappears based on check results

#### Settings Page Performance
- **Faster Loading**: Optimized Settings page loading time
  - Page now displays immediately with cached version info
  - Version information updates in background without blocking page display

#### Footer Updates
- **Update Available Button**: Made "Update Available" badge in footer clickable
  - Clicking the badge navigates to Settings page
  - Improved user experience for accessing update information

#### Timezone Handling
- **Consistent Timezone Display**: Fixed timezone handling across all endpoints
  - All timestamps now sent with UTC timezone indicator ('Z' suffix)
  - Time display respects timezone from ENV configuration (TZ variable)
  - Removed hardcoded locale preferences, uses browser's local settings

### Fixed

#### Security Tab
- **Unban Filter Accuracy**: Fixed Unban filter displaying Info results
  - Unban filter now only shows actual unban actions (not all info logs)
  - Removed backward compatibility code that incorrectly included all 'info' results
  - Added separate "Info" filter option in Netfilter action dropdown
  - Users can now filter by Info separately from Unban actions

---

## [1.4.5] - 2026-01-04

### Added

#### Version Check Improvements
- **Periodic Version Check**: Version check now runs automatically every 6 hours (instead of only on container startup)
  - Background scheduler job checks for app updates from GitHub
  - Runs immediately on startup, then every 6 hours
  - Ensures version information stays up-to-date without manual intervention
  - Version check job appears in Status page

- **Manual Version Check Button**: Added "Check Now" button in Settings page
  - Located next to "Latest Version" badge
  - Allows users to manually trigger version check at any time

### Changed

#### Version Check Behavior
- **Background Updates**: Version check endpoint now supports `force` parameter to bypass cache
- **UI Updates**: Version information updates in real-time without page refresh
  - Latest version display updates immediately
  - Badge status ("Update Available" / "Up to Date") updates dynamically
  - Update notification message appears/disappears based on check results

---

## [1.4.4] - 2026-01-04

### Added

#### Email Direction Detection
- **Internal Email Detection**: Added new "internal" direction for emails delivered locally
  - Internal emails require ALL of the following conditions:
    - `relay=dovecot` in Postfix logs (indicates local delivery)
    - Sender domain is in local domains list
    - Recipient domain(s) are in local domains list
  - Prevents inbound emails from external domains being incorrectly marked as internal
  - More accurate than domain-only detection (handles cases where domain mailboxes exist on different servers)
  - Direction is determined after Postfix logs are available (not during initial import)
  - Added "Internal" option to direction filter in Messages page
  - Internal direction displayed with green badge in UI
  - Backend API now tracks internal statistics (`internal_24h` in dashboard stats endpoint)

#### Background Jobs
- **Final Status Update Job**: Added new background job to update final status for correlations
  - Handles cases where Postfix logs arrive after initial correlation
  - Runs at `CORRELATION_CHECK_INTERVAL` frequency (default: 120 seconds)
  - Only checks correlations within `MAX_CORRELATION_AGE_MINUTES` window
  - Prevents emails from remaining without final status when logs arrive late
  - Job appears in Status page with pending items count
  - Respects correlation age limits to avoid infinite checking

### Fixed

#### Messages Page
- **Auto-Refresh Behavior**: Fixed auto-refresh disrupting user's search and pagination
  - Auto-refresh now skips when user has active search or filters
  - Auto-refresh skips when user is not on first page
  - Prevents results from changing while user is browsing/searching
  - Only refreshes when viewing default first page with no filters

- **Spam Filter**: Fixed spam filter not showing results
  - Spam filter now checks both `final_status='spam'` and `is_spam=True` from Rspamd
  - Previously only checked `final_status`, missing emails marked as spam by Rspamd but delivered
  - Now correctly shows all spam emails regardless of delivery status

#### Message Correlation & Display
- **Missing Postfix Logs**: Fixed issue where Postfix logs weren't displayed in Logs tab after correlation was marked complete
  - Now queries all Postfix logs with matching `queue_id` directly from database
  - Ensures all logs are displayed even if they arrive after correlation is marked complete
  - Applied fix to both `/api/message/{correlation_key}/details` and `/api/logs/message/{correlation_key}` endpoints

- **Security Tab Events**: Fixed Security tab in Message Details not showing events from sender's IP address
  - Now uses IP address from Rspamd log to fetch all Netfilter security events for that IP
  - Removed time window restrictions - shows all security events for the sender's IP
  - Displays up to 100 most recent security events to avoid overwhelming the UI

#### UI Improvements
- **Email Subject Truncation**: Fixed long email subjects pushing status indicators off-screen
  - Changed Messages page layout from flex to grid for better control
  - Applied fix to both main Messages page and Recent Activity on Dashboard

- **Email Address Display**: Fixed email addresses with `+` (plus signs) being truncated
  - In Logs tab: Now uses recipients from Postfix logs (which include full addresses with `+`)
  - In Overview tab: Prioritizes recipients from Postfix logs over correlation recipients
  - Postfix logs contain complete addresses while Rspamd may truncate them
  - Fallback to correlation recipients if Postfix logs unavailable

- **Mail Details Display**: Replaced "Total Delay" with "Relay" in Logs tab Mail Details section
  - Relay information is more useful for troubleshooting delivery issues
  - Shows the server where email was delivered (e.g., `dovecot` for local delivery)

- **Message Details Modal Layout**: Improved Overview tab layout for better space utilization
  - Removed "First Seen" field (redundant information)
  - Reduced spacing between sections for more compact display
  - "Additional Details" section always visible at bottom (no scrolling needed)

- **Correlation Status Display**: Simplified status badge in Messages page
  - Changed from "[OK] Linked" / "[...] Pending" to single status badge with emoji
  - Displays email delivery status: ✓ Delivered, ↩ Bounced, ✗ Rejected, ⏳ Deferred, ⚠ Spam, ⏸ Expired
  - If email has final status (delivered/bounced/etc), shows that status
  - If correlation is complete but no final status yet, shows "✓ Linked"
  - If correlation is incomplete (waiting for Postfix logs), shows "⏳ Pending"
  - Removed separate "final_status" badge (now combined into single status indicator)

### Changed

#### Security Tab
- **Result Count Display**: Fixed incorrect result count in Security tab header
  - Resolves issue where count showed only items on current page instead of total results
  
- **Banning/Unbanning Event Classification**: Fixed incorrect categorization of security events
  - "Unbanning" events were incorrectly classified as "banned" instead of "unban"
  - "Banning" events now correctly classified as "ban" (instead of "banned")
  - Improved detection logic using word boundaries to prevent false matches (e.g., "unbanning" containing "banning")
  - Unbanning events now properly displayed with green "UNBAN" badge
  - Banning events now properly displayed with red "BAN" badge
  - Replaced single "Banned" option with distinct "BAN" and "UNBAN" filters

---

## [1.4.3] - 2026-01-01

### Changed

#### Configuration
- **Automatic Domain Detection**: Removed `MAILCOW_LOCAL_DOMAINS` environment variable requirement
  - Active domains are now automatically fetched from Mailcow API (`/api/v1/get/domain/all`)
  - Only active domains are used
  - Domains are cached on application startup
  - No manual domain configuration needed anymore

#### UI Improvements
- **Local Domains Display**: Enhanced domains display in Settings page
  - Changed from comma-separated list to grid layout (columns)
  - Scrollable container for many domains

#### Code Quality
- **Code Cleanup**: Removed unnecessary comments from codebase
  - Removed verbose comments that don't add value
  - Cleaned up phase markers and redundant inline comments
  - Improved code readability

### Fixed

#### Security Tab
- **Timestamp Formatting**: Fixed timestamp display in Security tab to match Messages page format
  - All timestamps now properly formatted with UTC timezone ('Z' suffix)
  - Consistent date/time display across all tabs
- **Banned Filter**: Fixed filter not working correctly for "Banning" messages
  - Now correctly identifies "Banning" (present tense) messages as banned actions
  - Uses priority field ("crit") to determine ban status when message parsing is ambiguous
  - Added support for CIDR notation in ban messages (e.g., "Banning 3.134.148.0/24")
- **View Consistency**: Removed old table view that was sometimes displayed
  - Only card-based view is now used consistently
  - Smart refresh now uses same rendering function as initial load
- **Duplicate Log Prevention**: Fixed duplicate security events appearing in Security tab
  - Added deduplication logic based on message + time + priority combination
  - Frontend filters duplicates before display (handles legacy data)
  - Backend import now checks database for existing logs with same message + time + priority before inserting
  - Prevents duplicate entries from being stored in database during import

#### Import Status
- **Last Fetch Run Time**: Added tracking of when imports run (not just when data is imported)
  - Status page now shows "Last Fetch Run" (when import job ran) separate from "Last Import" (when data was actually imported)
  - Resolves confusion when imports run but no new logs are available
  - All three log types (Postfix, Rspamd, Netfilter) now track fetch run times

#### Netfilter Logging
- **Enhanced Logging**: Added detailed debug logs for Netfilter import process
  - Logs show when fetch starts, how many logs received, how many imported, and how many skipped as duplicates
  - Better error tracking for troubleshooting import delays
- **Import Deduplication**: Improved duplicate detection during Netfilter log import
  - Now checks database for existing logs with same message + time + priority before inserting
  - Uses combination of message + time + priority as unique identifier (instead of time + IP + message)
  - Prevents duplicate entries from being stored in database

### Added

#### Version Management
- **VERSION File**: Version number now managed in single `VERSION` file instead of hardcoded in multiple places
  - Supports both Docker and development environments

#### Footer
- **Application Footer**: Added footer to all pages with:
  - Application name and current version
  - "Update Available" badge when new version is detected

#### Settings Page
- **Version Information Section**: Added version display in Settings page
  - Shows current installed version
  - Shows latest available version from GitHub
  - Displays "Update Available" or "Up to Date" status
  - Link to release notes when update is available

---

## [1.4.2] - 2025-12-31

### Fixed

#### Authentication
- **Login Page Visibility**: Login page now automatically redirects to main app when authentication is disabled
  - When `AUTH_ENABLED=false`, users are no longer shown the login page
  - Direct access to main application without authentication check
  - Logout button is hidden when authentication is disabled

---

## [1.4.0] - 2025-12-31

### Added

#### Security
- **Built-in HTTP Basic Authentication**: Optional authentication system to protect all pages and API endpoints
  - Dedicated login page (`/login`) with modern UI and dark mode support
  - Credentials stored in browser session storage (cleared on browser close)
  - Automatic redirect to login when authentication required
  - All API endpoints protected when authentication is enabled
  - Health check endpoint (`/api/health`) remains accessible for Docker monitoring
  - Logout functionality with automatic redirect to login
- **Authentication Configuration**: New environment variables:
  - `AUTH_ENABLED` (default: false) - Enable/disable authentication
  - `AUTH_USERNAME` (default: admin) - Authentication username
  - `AUTH_PASSWORD` (required if enabled) - Authentication password
- **Settings Page Enhancement**: Authentication status now displayed in Settings page with visual indicator (enabled/disabled badge)

### Changed

#### Documentation
- Updated README.md with comprehensive authentication documentation
- Updated GETTING_STARTED.md with authentication setup instructions
- Added authentication information to Settings page display

### Fixed

#### Infrastructure
- **Docker Healthcheck**: Health check endpoint now accessible without authentication to allow Docker health monitoring
- **Multi-Platform Docker Images**: Docker images now support both AMD64 and ARM64 architectures
  - Images automatically work on Raspberry Pi and other ARM-based devices

### Technical

#### New Configuration Options
```env
# Authentication (optional)
AUTH_ENABLED=false
AUTH_USERNAME=admin
AUTH_PASSWORD=
```

#### API Changes
- `GET /login` - New login page endpoint (public access)
- `GET /api/settings/info` - Now returns authentication status and username

#### Frontend Changes
- Created dedicated `login.html` page with authentication form
- Added authentication state management in JavaScript
- All API calls now use `authenticatedFetch()` wrapper
- Automatic redirect to login page when authentication required
- Logout functionality redirects to login page
- Login page supports dark mode with automatic theme detection

#### Backend Changes
- Added `BasicAuthMiddleware` for global authentication enforcement
- Created `/login` endpoint for login page
- Modified root endpoint to allow access (JavaScript handles redirect)
- Health check endpoint excluded from authentication requirements

#### Infrastructure Changes
- **GitHub Actions Workflow**: Updated Docker build to support multi-platform (linux/amd64, linux/arm64)
- **Docker Image Tagging**: Simplified tagging strategy - only `latest` and version tags (removed `main` tag)
- Docker images now built for both x86_64 and ARM64 architectures simultaneously

---

## [1.3.0] - 2025-12-25

### Added

#### UI Enhancements
- **Result Count Display**: Messages, Security, and Queue pages now show total result count in header (e.g., "All Messages (1,234 results)")
- **Delivery Error Summary**: Logs tab now displays prominent error box at top when delivery fails, extracting error reason from "said:" pattern
- **Security Tab Indicator**: Green/red dot indicator showing if there are security events in the last 24 hours
- **Multiple Recipients Display**: Messages with multiple recipients now show all recipients in Overview and Logs tabs
- **Expired Correlations Counter**: Status page shows count of expired (incomplete) correlations

#### New Features
- **Messages CSV Export**: Added missing `/api/export/messages/csv` endpoint with full filtering support
- **Separate Fetch Parameters**: New ENV variables for granular control:
  - `FETCH_COUNT_POSTFIX` (default: 500)
  - `FETCH_COUNT_RSPAMD` (default: 500)
  - `FETCH_COUNT_NETFILTER` (default: 500)
- **Correlation Expiration System**: Correlations older than `MAX_CORRELATION_AGE_MINUTES` marked as "expired" instead of deleted
- **IP/User Search**: Messages page now supports filtering by IP address and authenticated user

#### Backend Improvements
- **Three-Layer Blacklist Protection**: Blacklist filtering at API fetch, database insert, and display levels
- **Separate Correlation Expiration Job**: Dedicated background job for marking old incomplete correlations
- **Startup Cleanup**: Automatic cleanup of blacklisted entries on container start

### Changed

#### UI Reorganization
- **Postfix Tab → Logs Tab**: Renamed for clarity
- **Security Page Overhaul**: Changed from table layout to card-based UI with better visual hierarchy
- **Settings → Status Migration**: Moved system info, import status, and background jobs to Status page
- **Dashboard Quick Search**: Simplified to single search field (removed separate log type selector)
- **Dashboard Statistics**: Now uses MessageCorrelation table for accurate message counts

#### Backend Changes
- **Postfix Log Deduplication**: Main list now groups by Queue-ID, showing one row per message
- **Rspamd Symbol Options**: Now displays symbol options (e.g., RCVD_COUNT shows actual count)
- **Correlation Expiration Logic**: Changed from deletion to "expired" status marking

### Fixed

#### Critical Fixes
- **UniqueViolation Race Condition**: Fixed database race condition when multiple correlations created simultaneously
- **BCC Blacklist Problem**: Fixed issue where BCC copies bypassed blacklist filtering
- **Queue ID Blacklist Filtering**: Now properly filters queue entries by blacklisted sender/recipient
- **Messages Export**: Fixed empty CSV export (endpoint was missing)

#### UI Fixes
- **Timezone Errors**: All timestamps now properly formatted with UTC indicator
- **Dashboard Timestamp Formatting**: Fixed incorrect date display in recent activity
- **Settings Page Timestamps**: Fixed timestamp display in import status section
- **JavaScript Syntax Errors**: Fixed various JS errors that broke page functionality
- **Emoji Cleanup**: Removed emoji characters that caused encoding issues in logs

#### Data Accuracy
- **Incomplete Correlation Cleanup**: Fixed correlations stuck in incomplete state
- **Postfix Logs Display**: Fixed cases where Postfix logs weren't showing in message details
- **Duplicate Prevention**: Enhanced deduplication in both correlation and display layers

### Technical

#### New Configuration Options
```env
# Separate fetch counts per log type
FETCH_COUNT_POSTFIX=500
FETCH_COUNT_RSPAMD=500
FETCH_COUNT_NETFILTER=500

# Correlation expiration (minutes)
MAX_CORRELATION_AGE_MINUTES=10

# Correlation check interval (seconds)
CORRELATION_CHECK_INTERVAL=120
```

#### Database Changes
- Added `is_expired` field to MessageCorrelation model
- Added indexes for IP and user queries on RspamdLog

#### API Changes
- `GET /api/export/messages/csv` - New endpoint for messages export
- `GET /api/messages` - Added `ip` and `user` query parameters
- `GET /api/stats/dashboard` - Now returns accurate counts from correlations

---

## [1.2.0] - 2025-12-22

### Fixed
- **CRITICAL: Rspamd-Postfix Correlation**
  - Postfix logs now visible in message details
  - Rspamd logs now correctly find and join Postfix correlations
  - Fixed: Rspamd doesn't have Queue-ID, must search Postfix to find it

### Changed
- `correlate_rspamd_log()` - Complete rewrite
  - Now searches Postfix logs to find Queue-ID
  - Method 1: Search by message-id → get Queue-ID from Postfix
  - Method 2: Search by sender+recipient+time → get Queue-ID from Postfix
  - Then attaches to correlation with that Queue-ID

### Technical
- Rspamd logs now actively query Postfix logs table
- Queue-ID extracted from matching Postfix log
- Correlation found/created with that Queue-ID
- Ensures Rspamd and Postfix logs are properly linked

## [1.1.1] - 2025-12-22

### Fixed
- **CRITICAL: Correlation Logic Completely Rewritten**
  - Queue-ID is now the PRIMARY correlation key (not secondary!)
  - Message-ID moved to fallback (only used if no Queue-ID)
  - Fixes cases where messages still appeared as duplicates even after v1.1.0
  - Resolves issue where message-id log line and delivery log lines created separate correlations

### Changed
- `correlate_postfix_log()` - Complete rewrite of priority logic
- Queue-ID now checked FIRST and returns immediately if found
- Message-ID and sender+recipient+time are now pure fallbacks

### Technical
- Old: Message-ID → Queue-ID → fallback
- New: Queue-ID → Message-ID (fallback) → sender+recipient+time (fallback)
- Reason: Queue-ID is the definitive Postfix identifier for a message

## [1.1.0] - 2025-12-22

### Fixed
- **Duplicate Message Entries**: Single emails no longer appear multiple times in Messages view
  - Issue occurred when emails were sent to multiple recipients
  - Each Postfix delivery log was creating a separate correlation
  - Now all deliveries with same Queue-ID correctly attach to single correlation

### Added
- Automatic database migration system
- `migrations.py` module for database maintenance tasks
- Automatic duplicate correlation cleanup on startup
- Migration runs seamlessly without user intervention

### Changed
- Improved Queue-ID correlation logic in `correlate_postfix_log()`
- When Queue-ID exists but no correlation found, immediately creates new correlation with that Queue-ID
- Prevents fallback to methods that could create duplicates
- All documentation now in English only

### Performance
- Migration adds <5 seconds to startup time (one-time per container lifecycle)
- Improved query performance due to fewer duplicate records
- No ongoing performance penalty

## [1.0.0] - 2025-12-17

### Added
- Initial release of Mailcow Logs Viewer
- Dashboard with real-time statistics
- Postfix log viewing and search
- Rspamd spam analysis with direction detection (inbound/outbound)
- Netfilter authentication failure tracking
- Real-time mail queue monitoring
- Real-time quarantine monitoring
- Message correlation across different log sources
- CSV export functionality for all log types
- Background scheduler for periodic log fetching
- Automatic log cleanup based on retention policy
- Pagination for large datasets
- Docker Compose setup with PostgreSQL
- Traefik integration support
- Health check endpoints
- API documentation

### Features
- **Log Collection**: Automatically fetches logs from Mailcow API
- **Smart Correlation**: Links related logs based on message id
- **Direction Detection**: Accurately detects inbound vs outbound emails
- **Duplicate Prevention**: Avoids storing duplicate log entries
- **Search & Filter**: Advanced filtering across all log types
- **Statistics**: Dashboard with 24h/7d/30d metrics
- **Export**: CSV export with applied filters
- **Auto-cleanup**: Removes old logs based on retention policy
- **Responsive UI**: Modern interface built with Tailwind CSS

### Technical
- Python 3.11 + FastAPI backend
- PostgreSQL 15 for data storage
- SQLAlchemy ORM with JSONB support
- APScheduler for background jobs
- Retry logic with exponential backoff
- Comprehensive error handling
- Structured logging
- Docker containerization

### Configuration
- Environment-based configuration
- Configurable fetch interval
- Configurable retention period
- Configurable local domains
- Timezone support
- Debug mode

### Documentation
- Comprehensive README
- Quick start guide
- Project structure documentation
- API documentation
- Deployment guide
- Troubleshooting guide

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for information on how to contribute to this project.

## Support

For issues, questions, or feature requests, please open an issue on GitHub.
