// =============================================================================
// SETTINGS PAGE - config editor, GeoIP/MaxMind, jobs, SMTP/IMAP connection tests
// =============================================================================
// Split out of app.js (phase 4). Classic script sharing the global scope;
// loaded after utils.js and app.js in index.html.

// =============================================================================
// SETTINGS PAGE
// =============================================================================

// The open section; it has its own address (/settings/notifications). null: the first one
let settingsTab = null;
let settingsFirstTab = null;

// Labels the key cannot spell well. Next to the other addresses, "Error Email" alone would not say whose errors
const SETTINGS_LABEL_OVERRIDES = {
    dmarc_error_email: 'Report Import Error Email',
    eas_devices_retention_days: 'Retention Days',
    tz: 'Time Zone',
    // Outbound: what the setting does, in words; the search shows these names
    suppression_enabled: 'Handle undeliverable mail automatically',
    suppression_auto_detect: 'Read the mail logs for failures',
    suppression_rspamd_sync: 'Sync with Rspamd',
    suppression_hard_bounce_action: 'Permanent delivery failure',
    suppression_soft_bounce_action: 'Temporary delivery failure',
    queue_cleanup_enabled: 'Delete delayed mail',
    queue_cleanup_block: 'Block the recipients of deleted delayed mail',
    queue_cleanup_threshold_minutes: 'Queue age before deletion (minutes)',
    suppression_soft_bounce_threshold: 'Temporary failures before blocking',
    suppression_base_expiry_days: 'Base block length (days)',
    suppression_max_expiry_days: 'Maximum block length (days)',
    suppression_whitelist_domains: 'Exclude these domains'
};

const SETTINGS_LOCK_ICON = '<svg width="12" height="12" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true"><path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd"></path></svg>';

// Settings the API returns masked as ******** (same list as the backend)
const SETTINGS_SENSITIVE_KEYS = ['mailcow_api_key', 'mailcow_api_key_rw', 'auth_password', 'oauth2_client_secret', 'smtp_password',
    'dmarc_imap_password', 'session_secret_key', 'maxmind_license_key', 'rspamd_password'];

/**
 * Show a verification modal before enabling Basic Auth.
 * The user must type the username and password to confirm they know
 * the credentials. Returns {username, password} on confirm, or null on cancel.
 */
function showBasicAuthVerifyModal() {
    return new Promise((resolve) => {
        // Remove any existing modal
        const existing = document.getElementById('basic-auth-verify-modal');
        if (existing) existing.remove();

        const overlay = document.createElement('div');
        overlay.id = 'basic-auth-verify-modal';
        overlay.className = 'ui-dialog-backdrop ui-confirm';
        overlay.setAttribute('role', 'dialog');
        overlay.setAttribute('aria-label', 'Verify Credentials');

        overlay.innerHTML = `
            <div class="ui-dialog ui-dialog-fit ui-dialog-sm">
                <div class="ui-dialog-head"><h3>Verify Credentials</h3></div>
                <div class="ui-dialog-body ui-form-stack">
                    <div class="ui-banner ui-banner-warn"><div><b>Confirm before enabling Basic Auth</b>
                        <p>Type the credentials you configured to verify you can log in after enabling authentication.</p></div></div>
                    <label class="ui-label" for="verify-auth-username">Username
                        <input type="text" id="verify-auth-username" class="ui-input" autocomplete="off" placeholder="Enter username"></label>
                    <label class="ui-label" for="verify-auth-password">Password
                        <input type="password" id="verify-auth-password" class="ui-input" autocomplete="off" placeholder="Enter password"></label>
                    <p id="verify-auth-error" class="ui-banner ui-banner-fail" style="display:none"></p>
                </div>
                <div class="ui-dialog-foot">
                    <button type="button" id="verify-auth-cancel" class="ui-btn">Cancel</button>
                    <button type="button" id="verify-auth-confirm" class="ui-btn ui-btn-primary">Verify & Enable</button>
                </div>
            </div>
        `;

        document.body.appendChild(overlay);

        const usernameInput = document.getElementById('verify-auth-username');
        const passwordInput = document.getElementById('verify-auth-password');
        const errorEl = document.getElementById('verify-auth-error');
        const cancelBtn = document.getElementById('verify-auth-cancel');
        const confirmBtn = document.getElementById('verify-auth-confirm');

        // Focus username field
        setTimeout(() => usernameInput.focus(), 100);

        function cleanup() {
            overlay.remove();
        }

        function doCancel() {
            cleanup();
            resolve(null);
        }

        function doConfirm() {
            const username = usernameInput.value.trim();
            const password = passwordInput.value;
            if (!username) {
                errorEl.textContent = 'Please enter a username.';
                errorEl.style.display = 'flex';
                usernameInput.focus();
                return;
            }
            if (!password) {
                errorEl.textContent = 'Please enter a password.';
                errorEl.style.display = 'flex';
                passwordInput.focus();
                return;
            }
            cleanup();
            resolve({ username, password });
        }

        cancelBtn.addEventListener('click', doCancel);
        confirmBtn.addEventListener('click', doConfirm);

        // Allow Enter to confirm, Escape to cancel
        overlay.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                e.preventDefault();
                doCancel();
            } else if (e.key === 'Enter') {
                e.preventDefault();
                doConfirm();
            }
        });

        // Click outside to cancel
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) doCancel();
        });
    });
}

/**
 * Shows a confirmation modal when features are being disabled.
 * Lists the features and warns about permanent data deletion.
 * @param {string[]} featureIds - Array of feature IDs being newly disabled
 * @returns {Promise<boolean>} true if confirmed, false if cancelled
 */
function showFeatureDisableConfirmModal(featureIds) {
    return new Promise((resolve) => {
        const existing = document.getElementById('feature-disable-confirm-modal');
        if (existing) existing.remove();

        // Build feature list HTML
        const featureListHtml = featureIds.map(id => {
            const feat = TOGGLEABLE_FEATURES.find(f => f.id === id);
            return `<li><b>${escapeHtml(feat ? feat.label : id)}</b>${feat && feat.description ? ` <span class="ui-muted">${escapeHtml(feat.description)}</span>` : ''}</li>`;
        }).join('');
        const many = featureIds.length !== 1;

        const overlay = document.createElement('div');
        overlay.id = 'feature-disable-confirm-modal';
        overlay.className = 'ui-dialog-backdrop ui-confirm';
        overlay.setAttribute('role', 'alertdialog');
        overlay.setAttribute('aria-label', 'Disable features');

        overlay.innerHTML = `
            <div class="ui-dialog ui-dialog-fit ui-dialog-sm">
                <div class="ui-dialog-head"><h3>Disable ${many ? featureIds.length + ' Features' : 'Feature'}?</h3></div>
                <div class="ui-dialog-body ui-form-stack">
                    <div class="ui-banner ui-banner-fail"><div><b>Stored data will be deleted</b>
                        <p>All database records for ${many ? 'these features' : 'this feature'} will be permanently deleted. This cannot be undone.</p></div></div>
                    <div><p class="ui-label">Features being disabled</p><ul class="ui-disable-list">${featureListHtml}</ul></div>
                </div>
                <div class="ui-dialog-foot">
                    <button type="button" id="feature-disable-cancel" class="ui-btn">Cancel</button>
                    <button type="button" id="feature-disable-confirm" class="ui-btn ui-btn-danger-solid">Disable & Delete Data</button>
                </div>
            </div>
        `;

        document.body.appendChild(overlay);

        const cancelBtn = document.getElementById('feature-disable-cancel');
        const confirmBtn = document.getElementById('feature-disable-confirm');

        function cleanup() { overlay.remove(); }

        cancelBtn.addEventListener('click', () => { cleanup(); resolve(false); });
        confirmBtn.addEventListener('click', () => { cleanup(); resolve(true); });

        overlay.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') { e.preventDefault(); cleanup(); resolve(false); }
            else if (e.key === 'Enter') { e.preventDefault(); cleanup(); resolve(true); }
        });

        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) { cleanup(); resolve(false); }
        });

        // Focus confirm button
        setTimeout(() => confirmBtn.focus(), 100);
    });
}

// Per-field descriptions (from env.example comments)
var SETTINGS_FIELD_DESCRIPTIONS = {
    // Anomaly detection
    anomaly_detection_enabled: 'Watch each mailbox against its own normal sending pattern and alert on suspicious changes. Alerts only - nothing is ever blocked by this feature.',
    anomaly_check_interval: 'How often to look for anomalies (minutes). This is also the size of the window each run examines.',
    anomaly_volume_multiplier: 'How many times above its own normal rate a mailbox must send before alerting. Example: 5 = sending five times more than usual for that mailbox.',
    anomaly_volume_min_messages: 'Noise floor: a mailbox must send at least this many messages in the window before a spike can alert. Prevents alerts on tiny numbers (2 messages instead of the usual 0).',
    anomaly_baseline_days: 'How many days of history are used to learn what "normal" looks like for each mailbox.',
    anomaly_auth_failure_threshold: 'Alert when a username collects this many failed login attempts within the window - typically a brute-force or password-guessing attack.',
    anomaly_alert_cooldown_hours: 'After an alert for a mailbox, stay quiet about the same problem for this many hours. Prevents alert storms during an ongoing incident.',

    // SMTP abuse protection
    smtp_abuse_enabled: 'Automatically disable sending (SMTP) for a mailbox that crosses the limit below. The mailbox still receives mail; if its app passwords are revoked too, mail apps that sign in with one stop working. Requires a Read-Write mailcow API key.',
    smtp_abuse_threshold: 'Maximum messages a single mailbox may send within the time window. Above this, sending is disabled for that mailbox. Set it comfortably above your busiest legitimate sender.',
    smtp_abuse_window_minutes: 'The rolling time window used to count messages. Example: 100 messages / 60 minutes.',
    smtp_abuse_revoke_app_passwords: 'Also delete the mailbox app passwords when blocking. Recommended: a compromised account usually sends through an app password, so revoking cuts the attacker off even if they know the password.',
    smtp_abuse_unblock_grace_minutes: 'After you re-enable a mailbox manually, do not block it again automatically for this long. Without it the mailbox would be blocked again within a minute, because the old messages are still inside the counting window.',
    smtp_abuse_help_address: 'Support address shown to the user in the email telling them their sending was paused. Falls back to the admin email.',

    // DMARC insights
    dmarc_insights_window_days: 'How many days of DMARC reports to analyse when suggesting a policy change.',
    dmarc_insights_pass_threshold: 'Minimum DMARC pass rate (%) before suggesting a stricter policy. Higher = more cautious advice.',
    dmarc_insights_min_volume: 'Minimum number of reported messages before any recommendation is made, so advice is not based on a handful of messages.',

    // Rspamd
    rspamd_url: 'Address of the Rspamd controller. Leave empty to reach it through mailcow itself (mailcow URL + /rspamd) - correct for most setups, including when this app runs on a different server. Only set it if this app can reach Rspamd directly on the network and the path through mailcow fails (for example a 302 from a reverse proxy). Same Docker network as mailcow: http://rspamd-mailcow:11334',

    // DNS change alerts
    dns_change_alerts_enabled: 'Alert when a domain SPF, DKIM, DMARC, TLSA, MTA-STS or TLS-RPT record changes, when DNSSEC stops validating, or when a TLSA record no longer matches the mail server certificate, so you can update the records at your registrar. The alert names the domain and shows the old and new value. A failed DNS lookup never counts as a change.',

    // Blacklist checks
    blacklist_dns_servers: 'DNS resolvers used for blacklist (RBL) lookups, comma-separated. Spamhaus rejects queries coming from public resolvers (Google, Cloudflare, Quad9), so this should be your own resolver - in a mailcow setup: 172.22.1.254. Leave empty to use the container default.',
    blacklist_source_server_ip: 'Monitor the auto-detected WAN IP (reported by the mailcow status API) on spam blacklists (RBLs). Turn this off when outbound mail leaves through a relay host, so only the other sources are monitored. Default: true.',
    blacklist_source_transports: 'Monitor the public IPs of active mailcow transports on spam blacklists. Each transport nexthop is resolved to all of its public IPs, so relay pools with several addresses are fully covered. Default: true.',
    blacklist_source_relayhosts: 'Monitor the public IPs of active mailcow relayhosts (sender-dependent transports) on spam blacklists. Default: true.',
    blacklist_source_manual_hosts: 'Additional hosts to monitor on spam blacklists, comma-separated. Accepts IPv4/IPv6 addresses and hostnames (a hostname is resolved to all of its public IPs). Monitored in addition to the sources above - these may also be hosts unrelated to this mailcow server.',

    // Domain SPF check sources
    domain_spf_source_server_ip: 'Validate the auto-detected WAN IP against each domain SPF record. Turn this off when outbound mail leaves through a relay host and the WAN IP is not supposed to be in your SPF records. Default: true.',
    domain_spf_source_transports: 'Also validate the public IPs resolved from active mailcow transport nexthops against each domain SPF record. Enable when outbound mail leaves through transports whose IPs must be authorized in your SPF records. Default: false.',
    domain_spf_source_relayhosts: 'Also validate the public IPs resolved from active mailcow relayhosts against each domain SPF record. Default: false.',
    domain_spf_source_manual_hosts: 'Additional hosts that must pass each domain SPF check, comma-separated. Accepts IPv4/IPv6 addresses and hostnames. Outbound sending addresses only - every entry must pass the SPF check, so do not add addresses that never send mail (such as an inbound-only MX).',
    domain_spf_source_dmarc_history: 'Also validate source IPs observed with a passing SPF result in the last 30 days of imported DMARC aggregate reports for each domain. Caution: with relaxed SPF alignment, an IP sending from an ESP subdomain can appear as an aligned pass without being listed in the domain own SPF record, which then shows up as a false warning here. Default: false.',

    mailcow_url: 'Your mailcow instance URL (without trailing slash).',
    mailcow_api_key: 'mailcow API key (Read-Only). Generate from System → Configuration → Access → Administrators → API in mailcow admin. Required permissions: Read access to logs. In mailcow the key must be active, and its allowed IPs must include the address this app connects from.',
    mailcow_api_key_rw: 'mailcow API key (Read-Write). Optional. Generate a separate key from System → Configuration → Access → Administrators → API with write permissions. Used for actions such as quarantine, queue, Fail2Ban, rate limits and Rspamd maps. In mailcow the key must be active, and its allowed IPs must include the address this app connects from.',
    mailcow_api_timeout: 'API request timeout in seconds.',
    mailcow_api_verify_ssl: 'Verify SSL certificates when connecting to mailcow API. Set to false for development with self-signed certificates. Default: true.',
    fetch_interval: 'Seconds between log fetches from mailcow. Lower = more frequent updates, higher load. Default: 60.',
    fetch_count_postfix: 'Postfix logs to fetch per API request (page size for paginated fetching). The system paginates through all available logs until catching up. Default: 2000.',
    fetch_count_rspamd: 'Rspamd logs to fetch per API request (page size for paginated fetching). The system paginates through all available logs until catching up. Default: 500.',
    fetch_count_netfilter: 'Netfilter logs to fetch per request. Default: 500.',
    fetch_max_pages: 'Maximum number of pages to fetch per cycle for Postfix/Rspamd. Safety limit to prevent infinite loops. Total logs per cycle = page size × max pages. Default: 50.',
    retention_days: 'Days to keep logs in database. Older logs are automatically deleted. Recommended: 7 for most, 30 for compliance. Default: 7.',
    max_correlation_age_minutes: 'Stop searching for correlations older than this (minutes).',
    correlation_check_interval: 'Seconds between correlation completion checks. Default: 120.',
    app_port: 'Application port (internal container port). Default: 8080.',
    log_level: 'Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL. Default: WARNING.',
    app_title: 'Application title (shown in browser tab).',
    app_logo_url: 'Logo URL (optional; leave empty to use the default project icon).',
    tz: "The app's time zone. Default: UTC.",
    debug: 'Enable debug mode (shows detailed errors). Use only for development. Never enable in production. Default: false.',
    max_search_results: 'Maximum records to return in search results. Default: 1000.',
    csv_export_limit: 'CSV export row limit. Default: 10000.',
    scheduler_workers: 'Thread pool size for blocking scheduler jobs (e.g. the DMARC & TLS IMAP import). Valid range: 1-64. Default: 4.',
    blacklist_emails: 'Comma-separated email addresses to hide from logs (e.g. BCC archive, monitoring). These emails are NOT stored in the database.',
    auth_enabled: 'Deprecated: use Basic auth enabled. When enabled, enables Basic Auth. Default: false.',
    basic_auth_enabled: 'Enable Basic HTTP authentication. When enabled, ALL pages and API require login. Default: false.',
    auth_username: 'Basic auth username. Default: admin.',
    auth_password: 'Basic auth password (required if Basic auth enabled). Leave empty to disable. Use a strong password in production.',
    oauth2_enabled: 'Enable OAuth2/OIDC authentication. Works with Mailcow, Keycloak, etc. Default: false.',
    oauth2_provider_name: 'Display name for the OAuth2 provider (e.g. Mailcow, Keycloak).',
    oauth2_issuer_url: 'OIDC Discovery: set issuer URL and endpoints are auto-discovered. Mailcow: https://mail.example.com. Keycloak: https://keycloak.example.com/realms/myrealm',
    oauth2_authorization_url: 'Manual: OAuth2 authorization endpoint (if discovery not supported).',
    oauth2_token_url: 'Manual: OAuth2 token endpoint.',
    oauth2_userinfo_url: 'Manual: OAuth2 UserInfo endpoint.',
    oauth2_client_id: 'OAuth2 Client ID from your provider.',
    oauth2_client_secret: 'OAuth2 Client Secret from your provider.',
    oauth2_redirect_uri: 'OAuth2 Redirect URI (callback). Must match the URI configured in your OAuth2 provider.',
    oauth2_scopes: 'OAuth2 scopes to request. Default: openid profile email.',
    oauth2_use_oidc_discovery: 'Enable OIDC discovery (uses .well-known/openid-configuration). Default: true.',
    session_secret_key: 'Secret key for signing session cookies. REQUIRED if OAuth2 enabled. Generate: openssl rand -hex 32. Use a strong secret in production.',
    session_expiry_hours: 'Session expiration in hours. Default: 24.',
    session_max_entries: 'Maximum active login sessions per process. At capacity, new logins wait until a session expires or a user signs out. Existing sessions stay signed in. Default: 50.',
    auth_max_failure_clients: 'Maximum client addresses tracked for failed Basic Auth attempts per process. At capacity, new addresses must wait before trying Basic Auth. Existing sessions remain usable. Default: 10000.',
    smtp_enabled: 'Enable SMTP for sending notifications (alerts, weekly summary).',
    smtp_host: 'SMTP server hostname.',
    smtp_port: 'SMTP server port (587 for TLS, 465 for SSL, 25 for plain).',
    smtp_use_tls: 'Use STARTTLS for SMTP. Recommended.',
    smtp_use_ssl: 'Use implicit SSL for SMTP (usually port 465).',
    smtp_verify_ssl: 'Check the SMTP server certificate before the password is sent, so nobody between this app and the server can read it. Off (default) does not check. Automatic checks host names such as smtp.example.com and skips localhost, IP addresses and container names. On always checks. Automatic or On is recommended; keep Off only for a server with a self-signed certificate.',
    smtp_user: 'SMTP username (usually email address).',
    smtp_password: 'SMTP password.',
    smtp_from: 'From address for emails (defaults to SMTP user if not set).',
    smtp_relay_mode: 'Relay mode: for local relay servers that do not require authentication. When enabled, username and password are not required.',
    admin_email: 'Administrator email for system notifications. Separate several addresses with commas.',
    blacklist_alert_email: 'Email for IP blacklist alerts (uses Admin email if not set). Separate several addresses with commas.',
    dmarc_retention_days: 'How many days DMARC and TLS reports are kept. Default: 60.',
    dmarc_manual_upload_enabled: 'Allow uploading DMARC and TLS reports by hand on the DMARC & TLS page. Default: true.',
    dmarc_allow_report_delete: 'Allow deleting DMARC and TLS reports from the UI. Default: false.',
    enable_weekly_summary: 'Enable weekly summary email report (sent to admin email). Default: true.',
    dmarc_imap_enabled: 'Import DMARC and TLS reports automatically from an IMAP mailbox.',
    dmarc_imap_host: 'IMAP server hostname (e.g. imap.gmail.com).',
    dmarc_imap_port: 'IMAP server port (993 for SSL, 143 for non-SSL). Default: 993.',
    dmarc_imap_use_ssl: 'Use SSL/TLS for IMAP connection. Default: true.',
    dmarc_imap_verify_ssl: 'Check the IMAP server certificate before the password is sent, so nobody between this app and the server can read it. Off (default) does not check. Automatic checks host names such as imap.example.com and skips localhost, IP addresses and container names. On always checks. Automatic or On is recommended; keep Off only for a server with a self-signed certificate.',
    dmarc_imap_user: 'IMAP username (email address).',
    dmarc_imap_password: 'IMAP password.',
    dmarc_imap_folder: 'IMAP folder to scan for DMARC and TLS reports. Default: INBOX.',
    dmarc_imap_delete_after: 'Delete emails after successful processing. Default: true.',
    dmarc_imap_interval: 'Interval between IMAP syncs in seconds. Default: 3600 (1 hour).',
    dmarc_imap_run_on_startup: 'Run IMAP sync once on application startup. Default: true.',
    dmarc_imap_batch_size: 'Number of emails to process per batch. Default: 10.',
    dmarc_imap_scan_all_unseen: 'Scan all unread emails for DMARC/TLS-RPT attachments, not just those matching known subject patterns. Enable if you receive reports from providers that use non-English subjects. Only recommended for dedicated DMARC mailboxes.',
    dmarc_error_email: 'Email for errors while importing DMARC and TLS reports (defaults to the Admin email if not set). Separate several addresses with commas.',
    maxmind_account_id: 'MaxMind Account ID for GeoIP database downloads. Required to download GeoLite2 databases.',
    maxmind_license_key: 'MaxMind License Key for GeoIP database downloads. Required to download GeoLite2 databases. Keep this secret.',
    disabled_features: 'Disable features to hide their pages and stop their background jobs. Core features (Dashboard, Messages, Settings, Status) are always enabled.',
    raw_logs_enabled: 'Collect the services ticked below for the Logs page. When off, the Logs page says collection is off and shows no logs. The services other pages read (listed under Services) are collected either way.',
    raw_logs_fetch_interval: 'Seconds between raw log fetch cycles. Lower = more frequent updates. Default: 30.',
    raw_logs_fetch_count: 'Number of log entries to fetch per service per cycle. Higher values catch more logs but increase API load. Default: 1000.',
    raw_logs_retention_days: 'Days to keep raw logs in the database. Older logs are automatically deleted at 3:00 AM daily. Default: 2.',
    rate_limits_retention_days: 'Days to keep the senders that hit a rate limit, for the Rate Limits page. Never less than Raw Logs Retention Days. Default: 90.',
    eas_devices_retention_days: 'Days to keep a device that stopped syncing before it is removed from the Devices page. 0 keeps every device. Default: 90.',
    raw_logs_services: 'The services the Logs page shows. A service marked Always collected keeps coming in when switched off here, because another page reads it; the Logs page then just does not show it.',
    rspamd_password: 'Rspamd UI/API password for reading Rspamd map data. Required to view and edit Rspamd maps.',
    suppression_enabled: 'Off pauses automatic handling and block expiry. Manual changes still work.',
    suppression_auto_detect: 'On when a choice below needs the mail logs. Set by those choices, not on its own.',
    suppression_rspamd_sync: "Keeps the suppression list and this app's part of the Rspamd recipient denylist in step, both ways: changes on either side reach the other. Off, this app keeps no suppression list: turning it off deletes the list, turning it on loads this app's blocks back from Rspamd. Needs the Rspamd password and a read-write API key.",
    suppression_whitelist_domains: 'No automatic blocks or queue deletion. Separate exact domains with commas; subdomains are not included.',
    suppression_hard_bounce_action: 'What happens when the receiving server rejects a message permanently (5.x.x).',
    suppression_soft_bounce_action: 'What happens when delivery fails for now (4.x.x) and the queue is not cleaned.',
    suppression_soft_bounce_threshold: 'Failures before the address is blocked. Each failed retry counts, even for the same message.',
    suppression_base_expiry_days: 'Repeated failures increase the block length.',
    suppression_max_expiry_days: 'The longest a block grows with repeated failures.',
    quarantine_rules_max_actions: 'Safety limit: maximum emails to release/delete per scheduler run. Prevents accidental mass-processing from overly broad rules. Default: 50.',
    quarantine_rules_interval: 'Minutes between quarantine rule processing runs. Lower = faster response to new quarantine items, higher = less API load on mailcow. Default: 5.',
    quarantine_rules_log_retention_days: 'Days to keep quarantine auto-rule action history. Older action logs are automatically cleaned up. Default: 30.',
    queue_cleanup_enabled: 'Delete delayed mail after some time in the queue.',
    queue_cleanup_block: 'Also block the recipients of the delayed mail deleted. Needs Sync with Rspamd.',
    queue_cleanup_threshold_minutes: 'Minutes in the queue before delayed mail is deleted.'
};

// Settings with a few short choices, shown as a segmented control (.ui-seg, as on the Security page).
// A hidden input holds the value, so the form saves it like any other field
const SETTINGS_SEGMENTED_OPTIONS = {
    smtp_verify_ssl: [['false', 'Off'], ['auto', 'Automatic'], ['true', 'On']],
    dmarc_imap_verify_ssl: [['false', 'Off'], ['auto', 'Automatic'], ['true', 'On']]
};

function settingsPickSegment(btn) {
    const group = btn.closest('.ui-seg');
    const field = group && group.parentElement.querySelector('input[type="hidden"]');
    if (field === null || field === undefined || btn.disabled) return;
    field.value = btn.getAttribute('data-value');
    group.querySelectorAll('button').forEach(b => b.setAttribute('aria-pressed', String(b === btn)));
    field.form && field.form.dispatchEvent(new Event('input', { bubbles: true }));
}

// Outbound: one choice per kind of delivery failure. The stored
// settings and their ENV variables stay as they are: the radios only set the
// hidden fields that the form saves. A temporary failure has three stored
// settings behind its one choice: queue cleanup on (blocking its recipients
// or not), or else the action. Reading the mail logs (suppression_auto_detect)
// has no switch of its own: it is on exactly when a choice needs it, and a
// choice that has no effect without it shows as what really happens.
// A block reaches Rspamd only through Sync with Rspamd: while it is off, the
// options that block are not available, and the one picked shows as its twin
// that does not block, which is what the jobs do then.
const SETTINGS_SOFT_BOUNCE_QUEUE = { value: 'queue', needs: 'rw sync',
    label: 'Delete after {minutes} minutes in the queue and block the recipients', hint: 'Checked every 5 minutes.' };
const SETTINGS_SOFT_BOUNCE_QUEUE_DELETE = { value: 'queue_delete', needs: 'rw',
    label: 'Delete after {minutes} minutes in the queue', hint: 'Does not block the recipients. Checked every 5 minutes.' };
const SETTINGS_CHOICE_NOTES = {
    rw: 'Add a read-write API key in Settings > mailcow. Nothing happens without it.',
    'rw-queue': 'Add a read-write API key in Settings > mailcow to delete queued mail.'
};
const SETTINGS_LOG_CHOICES = { hard: ['suppress', 'delete'], soft: ['count', 'suppress'] };
// What a choice that blocks does while Sync with Rspamd is off
const SETTINGS_SYNC_TWINS = { hard: { suppress: 'delete' }, soft: { queue: 'queue_delete', count: 'ignore', suppress: 'ignore' } };
// Settings that do nothing while another switch is off: shown greyed out and
// unclickable until it is on. Groups say it with needs:, single fields here.
const SETTINGS_FIELD_NEEDS = {};

function settingsShowNeeds(root) {
    Object.entries(SETTINGS_FIELD_NEEDS).forEach(([key, parent]) => {
        const row = root.querySelector('#edit-' + key)?.closest('.ui-set-field, .ui-set-bool, .ui-set-wide');
        if (row) row.dataset.needs = parent;
    });
    // A choice's options say what they need on their own (settingsApplySync)
    root.querySelectorAll('[data-needs]:not(.ui-set-choice-opt)').forEach(el => {
        // Every switch named must be on
        const parents = el.dataset.needs.split(' ').map(id => root.querySelector('#edit-' + id)).filter(Boolean);
        const off = parents.some(parent => !parent.checked);
        el.inert = off;
        el.classList.toggle('is-off', off);
    });
}

function settingsBounceChoice(kind, config, lockedKeys, defaults) {
    const soft = kind === 'soft';
    const actionKey = soft ? 'suppression_soft_bounce_action' : 'suppression_hard_bounce_action';
    const keys = soft ? ['queue_cleanup_enabled', 'queue_cleanup_block', actionKey, 'queue_cleanup_threshold_minutes', 'suppression_soft_bounce_threshold']
        : [actionKey, 'suppression_auto_detect'];
    const locked = key => lockedKeys.has(key);
    const action = String(config[actionKey] ?? '');
    const logsOn = config.suppression_auto_detect === true;
    const queueOn = soft && config.queue_cleanup_enabled === true;
    const blockOn = config.queue_cleanup_block !== false;
    const needsLogs = value => SETTINGS_LOG_CHOICES[kind].includes(value);
    // What happens today: an action that needs the logs does nothing while they are not read
    const picked = queueOn ? (blockOn ? 'queue' : 'queue_delete') : needsLogs(action) && !logsOn ? 'ignore' : action;
    const options = soft ? [SETTINGS_SOFT_BOUNCE_QUEUE, SETTINGS_SOFT_BOUNCE_QUEUE_DELETE, ...SETTINGS_FIELD_OPTIONS[actionKey]]
        : SETTINGS_FIELD_OPTIONS[actionKey];
    const isQueue = value => value === 'queue' || value === 'queue_delete';
    // A value set by ENV rules out the options that would change it; the rest stay open
    const open = value => (soft
        ? (!locked('queue_cleanup_enabled') || isQueue(value) === queueOn)
            && (!isQueue(value) || !locked('queue_cleanup_block') || (value === 'queue') === blockOn)
            && (!locked(actionKey) || isQueue(value) || value === action)
        : !locked(actionKey) || value === action || value === (SETTINGS_SYNC_TWINS.hard[action] || action))
        && !(locked('suppression_auto_detect') && !logsOn && needsLogs(value));
    const number = key => '<input type="number" min="1" class="ui-input ui-set-choice-num" id="edit-' + key + '" name="' + key + '" value="' +
        escapeHtml(String(config[key] ?? '')) + '" aria-label="' + escapeHtml(settingsFieldLabel(key)) + '"' + (locked(key) ? ' disabled' : '') + '>';
    // The minutes show in both queue options; the one stored field is hidden below them
    const minutes = '<input type="number" min="1" class="ui-input ui-set-choice-num" data-mirror="queue_cleanup_threshold_minutes" value="' +
        escapeHtml(String(config.queue_cleanup_threshold_minutes ?? '')) + '" aria-label="' + escapeHtml(settingsFieldLabel('queue_cleanup_threshold_minutes')) + '"' +
        (locked('queue_cleanup_threshold_minutes') ? ' disabled' : '') + ' oninput="settingsMirror(this)">';
    const group = 'choice-' + kind;
    const rows = options.map(o => {
        const id = group + '-' + o.value;
        const text = o.label.split(/(\{minutes\}|\{count\})/).filter(Boolean).map(part =>
            part === '{minutes}' ? minutes
                : part === '{count}' ? number('suppression_soft_bounce_threshold')
                : '<label for="' + id + '">' + escapeHtml(part.trim()) + '</label>').join(' ');
        return '<div class="ui-set-choice-opt' + (o.value === picked ? ' is-picked' : '') + '" data-needs="' + escapeHtml(o.needs || '') + '" onclick="settingsPickCard(event, this)">' +
            '<input type="radio" id="' + id + '" name="' + group + '" value="' + escapeHtml(o.value) + '" data-choice' +
            (o.value === picked ? ' checked' : '') + (open(o.value) ? '' : ' disabled data-locked="1"') + ' onchange="settingsPickBounce(this)">' +
            '<div class="ui-set-choice-text"><div>' + text + '</div>' + (o.hint ? '<small class="ui-set-desc">' + escapeHtml(o.hint) + '</small>' : '') +
            ((o.needs || '').split(' ').includes('sync') ? '<small class="ui-set-desc" data-sync-need hidden>Needs Sync with Rspamd.</small>' : '') +
            '<small class="ui-set-choice-note" data-note hidden></small></div></div>';
    }).join('');
    const checkbox = (key, on) => '<input type="checkbox" hidden id="edit-' + key + '" name="' + key + '"' + (on ? ' checked' : '') + (locked(key) ? ' disabled' : '') + '>';
    const carriers = soft
        ? checkbox('queue_cleanup_enabled', queueOn) + checkbox('queue_cleanup_block', blockOn) +
          '<input type="hidden" id="edit-queue_cleanup_threshold_minutes" name="queue_cleanup_threshold_minutes" value="' +
          escapeHtml(String(config.queue_cleanup_threshold_minutes ?? '')) + '"' + (locked('queue_cleanup_threshold_minutes') ? ' disabled' : '') + '>'
        : checkbox('suppression_auto_detect', logsOn);
    const lockedNames = keys.concat(soft ? ['suppression_auto_detect'] : []).filter(locked).map(key => key.toUpperCase());
    // The defaults Reset returns to: every key of the choice that is not set by ENV
    const resetTo = Object.fromEntries(keys.filter(key => !locked(key) && defaults[key] !== undefined).map(key => [key, defaults[key]]));
    const differs = key => typeof resetTo[key] === 'boolean' ? config[key] !== resetTo[key]
        : typeof resetTo[key] === 'number' ? Number(config[key]) !== resetTo[key] : String(config[key] ?? '') !== String(resetTo[key] ?? '');
    const changed = Object.keys(resetTo).some(differs);
    return '<div class="ui-set-field ui-set-wide ui-set-choice' + (changed ? ' is-changed' : '') + '" data-choice="' + kind + '" data-rw="' +
            (config.mailcow_api_key_rw ? '1' : '0') + '" data-defaults="' + escapeHtml(JSON.stringify(resetTo)) + '" data-loaded="' + escapeHtml(picked) + '">' +
        '<div class="ui-set-choice-head"><span class="ui-label" id="label-' + group + '">What should happen?</span>' +
            (lockedNames.length ? '<span class="ui-set-pill" title="Set by an environment variable, change it there">' + SETTINGS_LOCK_ICON + ' Set by ENV: ' + escapeHtml(lockedNames.join(', ')) + '</span>' : '') +
            '<span class="ui-set-pill is-changed" title="Differs from the default"' + (changed ? '' : ' hidden') + '>Changed</span></div>' +
        '<small class="ui-set-choice-note" data-sync-changed hidden></small>' +
        '<div class="ui-set-choice-list" role="radiogroup" aria-labelledby="label-' + group + '">' + rows + '</div>' +
        carriers + '<input type="hidden" id="edit-' + actionKey + '" name="' + actionKey + '" value="' + escapeHtml(action) + '" data-saved="' + escapeHtml(action) + '"' + (locked(actionKey) ? ' disabled' : '') + '>' +
        (Object.keys(resetTo).length ? '<button type="button" class="ui-set-clear is-reset" onclick="settingsResetChoice(this)"' + (changed ? '' : ' hidden') + '>↺ Reset to default</button>' : '') +
        '</div>';
}

// The minutes typed in either queue option: the stored field and the other option follow
function settingsMirror(input) {
    const key = input.dataset.mirror;
    const field = document.getElementById('edit-' + key);
    if (field && !field.disabled) field.value = input.value;
    document.querySelectorAll('[data-mirror="' + key + '"]').forEach(other => { if (other !== input) other.value = input.value; });
}

// The minutes shown from the stored field (after Reset or a restore)
function settingsShowMirrors() {
    document.querySelectorAll('[data-mirror]').forEach(input => {
        const field = document.getElementById('edit-' + input.dataset.mirror);
        if (field) input.value = field.value;
    });
}

// The stored settings from the picked options of both choices. While the logs
// are not read the actions do nothing, so they stay as saved: going back to
// what the page loaded with leaves nothing to save
function settingsSyncBounce() {
    const picked = kind => { const r = document.querySelector('input[name="choice-' + kind + '"]:checked'); return r ? r.value : ''; };
    const field = key => document.getElementById('edit-' + key);
    const set = (el, value) => { if (!el || el.disabled) return; if (el.type === 'checkbox') el.checked = value; else el.value = value; };
    const hard = picked('hard'), soft = picked('soft');
    const logs = settingsSyncLogs();
    const logsField = field('suppression_auto_detect');
    const reading = logsField ? logsField.checked : logs;
    const hardField = field('suppression_hard_bounce_action'), softField = field('suppression_soft_bounce_action');
    if (hard && hardField) set(hardField, reading ? hard : hardField.dataset.saved);
    if (soft && softField) {
        const queue = soft === 'queue' || soft === 'queue_delete';
        set(field('queue_cleanup_enabled'), queue);
        if (queue) set(field('queue_cleanup_block'), soft === 'queue');
        set(softField, queue || !reading ? softField.dataset.saved : soft);
    }
    settingsShowEffective();
}

// Reading the logs: on exactly when a picked option needs it (unless ENV sets it)
function settingsSyncLogs() {
    const picked = kind => { const r = document.querySelector('input[name="choice-' + kind + '"]:checked'); return r ? r.value : ''; };
    const logs = SETTINGS_LOG_CHOICES.hard.includes(picked('hard')) || SETTINGS_LOG_CHOICES.soft.includes(picked('soft'));
    const logsField = document.getElementById('edit-suppression_auto_detect');
    if (logsField && !logsField.disabled) logsField.checked = logs;
    return logs;
}

// Each choice shows what will really happen with the stored values: a value
// set by ENV can make one choice act once the other turns reading the logs
// on, and with Sync with Rspamd off a choice that blocks acts as its twin
function settingsShowEffective() {
    const field = key => document.getElementById('edit-' + key);
    const logsField = field('suppression_auto_detect');
    const reading = !logsField || logsField.checked;
    const sync = field('suppression_rspamd_sync');
    const syncOn = !sync || sync.checked;
    const effective = (kind, value) => {
        const shown = !reading && SETTINGS_LOG_CHOICES[kind].includes(value) ? 'ignore' : value;
        return syncOn ? shown : (SETTINGS_SYNC_TWINS[kind][shown] || shown);
    };
    const show = (kind, value) => {
        const radios = [...document.querySelectorAll('input[name="choice-' + kind + '"]')];
        if (radios.some(r => r.value === value)) radios.forEach(r => { r.checked = r.value === value; });
    };
    const hardField = field('suppression_hard_bounce_action');
    if (hardField) show('hard', effective('hard', hardField.value));
    const queue = field('queue_cleanup_enabled'), block = field('queue_cleanup_block'), softField = field('suppression_soft_bounce_action');
    if (softField) show('soft', queue && queue.checked ? effective('soft', block && !block.checked ? 'queue_delete' : 'queue') : effective('soft', softField.value));
}

// Sync with Rspamd turned off on the page: the options that block are not
// available, and a picked one moves to its twin, saying so. Turned on again
// before saving, the choices come back as they were.
let settingsSyncSnapshot = null;
const SETTINGS_SYNC_CARRIERS = ['suppression_hard_bounce_action', 'suppression_soft_bounce_action', 'queue_cleanup_enabled', 'queue_cleanup_block', 'suppression_auto_detect'];

function settingsApplySync(toggled) {
    const sync = document.getElementById('edit-suppression_rspamd_sync');
    if (!sync || !document.querySelector('.ui-set-choice')) return;
    const on = sync.checked;
    // A page drawn again (after saving, or Reset) starts from what it shows
    if (!toggled) settingsSyncSnapshot = null;
    const field = key => document.getElementById('edit-' + key);
    const picked = kind => { const r = document.querySelector('input[name="choice-' + kind + '"]:checked'); return r ? r.value : ''; };
    if (toggled && !on) {
        settingsSyncSnapshot = SETTINGS_SYNC_CARRIERS.map(key => {
            const el = field(key);
            return [key, el ? (el.type === 'checkbox' ? el.checked : el.value) : null];
        });
        ['hard', 'soft'].forEach(kind => {
            const twin = SETTINGS_SYNC_TWINS[kind][picked(kind)];
            const radio = twin && document.querySelector('input[name="choice-' + kind + '"][value="' + twin + '"]');
            if (radio) radio.checked = true;
        });
        settingsSyncBounce();
    } else if (toggled && on && settingsSyncSnapshot) {
        settingsSyncSnapshot.forEach(([key, value]) => {
            const el = field(key);
            if (!el || el.disabled || value === null) return;
            if (el.type === 'checkbox') el.checked = value; else el.value = value;
        });
        settingsSyncSnapshot = null;
    }
    document.querySelectorAll('.ui-set-choice-opt').forEach(opt => {
        if (!(opt.dataset.needs || '').split(' ').includes('sync')) return;
        const radio = opt.querySelector('input[type="radio"]');
        opt.inert = !on;
        radio.disabled = !on || radio.dataset.locked === '1';
        const need = opt.querySelector('[data-sync-need]');
        if (need) need.hidden = on;
    });
    settingsShowEffective();
    // Each choice says what it changed to while the sync is off
    const minutes = (field('queue_cleanup_threshold_minutes') || {}).value || '';
    const notes = {
        delete: 'Changed to "Delete its queued mail": Sync with Rspamd is off.',
        queue_delete: `Changed to "Delete after ${minutes} minutes in the queue": Sync with Rspamd is off.`,
        ignore: 'Changed to "Do nothing; keep retrying": Sync with Rspamd is off.'
    };
    document.querySelectorAll('.ui-set-choice').forEach(box => {
        const kind = box.dataset.choice;
        const twin = SETTINGS_SYNC_TWINS[kind][box.dataset.loaded];
        const note = box.querySelector('[data-sync-changed]');
        const show = !on && twin && picked(kind) === twin;
        note.textContent = show ? notes[twin] : '';
        note.hidden = !show;
    });
    document.querySelectorAll('.ui-set-choice').forEach(settingsShowChoice);
    const form = sync.form;
    if (toggled && form) form.dispatchEvent(new Event('input', { bubbles: true }));
}

function settingsPickBounce(radio) {
    const box = radio.closest('.ui-set-choice');
    if (!box || radio.matches(':disabled')) return;
    settingsSyncBounce();
    document.querySelectorAll('.ui-set-choice').forEach(settingsShowChoice);
}

// The whole card picks its option. The radio, its labels and the number field handle their own clicks
function settingsPickCard(event, card) {
    if (event.target.closest('input, label')) return;
    const radio = card.querySelector('input[type="radio"]');
    if (!radio || radio.matches(':disabled') || radio.checked) return;
    radio.checked = true;
    radio.focus({ preventScroll: true });
    radio.dispatchEvent(new Event('change', { bubbles: true }));
}

// The picked option stands out and says what it still needs to work, and the
// choice is marked Changed, with Reset, while any of its settings is not the default
function settingsShowChoice(box) {
    const rw = box.dataset.rw === '1';
    box.querySelectorAll('.ui-set-choice-opt').forEach(opt => {
        const radio = opt.querySelector('input[type="radio"]');
        const needs = (opt.dataset.needs || '').split(' ');
        const missing = !radio.checked || rw ? null : needs.includes('rw') ? 'rw' : needs.includes('rw-queue') ? 'rw-queue' : null;
        const note = opt.querySelector('[data-note]');
        opt.classList.toggle('is-picked', radio.checked);
        note.textContent = missing ? SETTINGS_CHOICE_NOTES[missing] : '';
        note.hidden = !missing;
    });
    const changed = Object.entries(JSON.parse(box.dataset.defaults || '{}')).some(([key, value]) => {
        const el = document.getElementById('edit-' + key);
        if (!el) return false;
        if (el.type === 'checkbox') return el.checked !== (value === true);
        return typeof value === 'number' ? Number(el.value) !== value : el.value !== String(value);
    });
    box.classList.toggle('is-changed', changed);
    box.querySelectorAll('.ui-set-pill.is-changed, .is-reset').forEach(el => { el.hidden = !changed; });
}

function settingsResetChoice(btn) {
    const box = btn.closest('.ui-set-choice');
    const form = box.closest('form');
    Object.entries(JSON.parse(box.dataset.defaults || '{}')).forEach(([key, value]) => {
        const el = document.getElementById('edit-' + key);
        if (!el || el.disabled) return;
        if (el.type === 'checkbox') el.checked = value === true;
        else el.value = String(value);
    });
    // The choices show the defaults; reading the logs follows them. The actions
    // keep their defaults: settingsSyncBounce would put a saved action back
    settingsShowMirrors();
    settingsShowEffective();
    settingsSyncLogs();
    settingsShowEffective();
    settingsApplySync(false);
    if (form) form.dispatchEvent(new Event('input', { bubbles: true }));
}

// ── The app's blocks in Rspamd when the sync goes off or on ──
// The list is synced with Rspamd while Suppressions and "Sync with Rspamd" are
// on. When the sync stops, or Suppressions is turned off with its list, the
// user says what happens to the blocks already in Rspamd; when it starts
// again, what is written there.
const SETTINGS_RSPAMD_CONNECTION_KEYS = ['mailcow_url', 'mailcow_api_key_rw', 'rspamd_password', 'rspamd_url'];

function settingsPlural(n, one, many) { return n === 1 ? one : many; }

function settingsErrorText(body, fallback) {
    const detail = body && body.detail;
    if (detail && typeof detail === 'object') return detail.message || fallback;
    return detail || fallback;
}

async function settingsRspamdState() {
    // The map is read even while the sync is off: the questions below need it
    const res = await authenticatedFetch('/api/suppressions/rspamd/state?check_map=true');
    if (!res.ok) throw new Error('Could not read the Rspamd state');
    return res.json();
}

// Returns null when the user cancels, else { action, feature_off } where action is
// none, keep, remove (after the save), apply (after the save) or fresh (before it)
async function settingsRspamdTransition(payload, data, newDisabled) {
    const locked = new Set(data.env_locked_keys || []);
    const before = data.editable_config || {};
    const value = key => (key in payload && !locked.has(key)) ? payload[key] : before[key];
    const wasDisabled = new Set((window.disabledFeatures || []).map(s => s.trim().toLowerCase()));
    const featureWasOn = !wasDisabled.has('suppressions'), featureOn = !newDisabled.has('suppressions');
    const wasOn = featureWasOn && before.suppression_rspamd_sync === true;
    const nowOn = featureOn && value('suppression_rspamd_sync') === true;
    const featureOff = featureWasOn && !featureOn;
    // Suppressions turned on again with the sync: its list was deleted while it
    // was off, and the blocks this app left in Rspamd are loaded back into it
    // (a read only), so nothing here is applied or removed. With the sync off
    // the app keeps no list, so there is nothing to load.
    if (!featureWasOn && featureOn) return { action: nowOn ? 'import' : 'none', feature_on: true };
    if (wasOn === nowOn && !featureOff) return { action: 'none' };
    // Removing talks to the old connection, writing to the new one: never both in one save
    const connectionChanged = SETTINGS_RSPAMD_CONNECTION_KEYS.some(key => key in payload && !locked.has(key)
        && payload[key] !== '********' && String(payload[key] ?? '') !== String(before[key] ?? ''));
    if (connectionChanged) {
        showToast('Save the mailcow or Rspamd connection change first, then turn Sync with Rspamd on or off.', 'error');
        return null;
    }
    let state;
    try { state = await settingsRspamdState(); } catch (e) { state = { readable: false, writable: false, managed_count: null, active_count: null, reason_text: 'Rspamd cannot be reached.' }; }
    const n = state.managed_count;
    const blocks = count => `${count} ${settingsPlural(count, 'block', 'blocks')}`;

    if (!nowOn || featureOff) {
        // Going off: the list is deleted, like the list of a feature that is off
        if (n === 0) {
            // Nothing of ours in Rspamd: only the list to confirm (turning
            // Suppressions off has its own confirmation)
            const rows = state.list_count || 0;
            if (!featureOff && rows > 0) {
                const ok = await showChoiceModal({
                    title: 'Turn off Sync with Rspamd?',
                    message: `This app's saved list (${rows} ${settingsPlural(rows, 'entry', 'entries')}) will be deleted. None of its blocks is in Rspamd, so turning the sync on again does not bring them back.`,
                    choices: [{ value: 'off', label: 'Turn off', kind: 'danger' }]
                });
                if (!ok) return null;
            }
            return { action: 'none', feature_off: featureOff, purge_rspamd: state.writable ? 'remove' : 'keep' };
        }
        const lead = featureOff ? 'Suppressions will turn off and the saved list will be deleted.' : "Sync with Rspamd will stop and this app's saved list will be deleted.";
        if (n === null || !state.writable) {
            const why = state.reason_text || 'Rspamd cannot be reached.';
            const message = n === null
                ? `${lead} We cannot check or remove this app's Rspamd blocks now: ${why}`
                : `${lead} ${blocks(n)} from this app remain in Rspamd. They cannot be removed now: ${why}`;
            const keep = await showChoiceModal({ title: "Keep this app's Rspamd blocks?", message, choices: [{ value: 'keep', label: 'Keep blocks', kind: 'primary' }] });
            return keep ? { action: 'keep', feature_off: featureOff } : null;
        }
        const picked = await showChoiceModal({
            title: "Keep this app's Rspamd blocks?",
            message: `${lead} ${blocks(n)} from this app remain in Rspamd. Remove them or keep them?`,
            choices: [{ value: 'keep', label: 'Keep blocks' }, { value: 'remove', label: 'Remove blocks', kind: 'danger' }]
        });
        return picked ? { action: picked, feature_off: featureOff, count: n } : null;
    }

    // Coming back on: the list was deleted while the sync was off, and this
    // app's blocks load back from Rspamd (a read only)
    const pending = state.pending_count;
    if (!pending) return { action: 'import' };
    // Changes still wait only when deleting the list failed: what mailcow
    // changed comes into the list first, then they are written
    if (!state.readable) {
        // What is in Rspamd now cannot be checked: say so before anything is written there
        const why = state.reason_text || 'Rspamd cannot be reached.';
        const ok = await showChoiceModal({
            title: 'Turn on Sync with Rspamd?',
            message: `We cannot check this app's Rspamd blocks now: ${why} Turning on the sync writes the list's waiting changes once Rspamd can be reached.`,
            choices: [{ value: 'apply', label: 'Turn on', kind: 'primary' }]
        });
        return ok ? { action: 'apply', count: pending } : null;
    }
    const changes = `${pending} waiting ${settingsPlural(pending, 'change', 'changes')}`;
    const picked = await showChoiceModal({
        title: 'Turn on Sync with Rspamd?',
        message: `Apply the ${changes} to Rspamd, or start fresh? Starting fresh deletes the whole list and removes this app's Rspamd blocks. Other Rspamd entries stay.`,
        choices: [{ value: 'fresh', label: 'Start fresh', kind: 'danger' }, { value: 'apply', label: 'Apply changes', kind: 'primary' }]
    });
    return picked ? { action: picked, count: pending } : null;
}

// After the save: carry out the choice. Returns the toast to show, [text, kind]
async function settingsRspamdAfterSave(plan, saved) {
    if (plan.action === 'remove' && !plan.feature_off) {
        // Bound to this save: refused once another save turned the sync on or off
        // again. A save that did not turn it off (another window did first) has none
        const transition = saved && saved.rspamd_off_transition;
        if (!transition) return ["Sync with Rspamd was already off (changed in another window). Nothing was removed from Rspamd.", 'error'];
        const res = await authenticatedFetch('/api/suppressions/rspamd/clear', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ transition })
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) {
            return [(body.detail && body.detail.code === 'not_confirmed')
                ? 'Sync with Rspamd is off. Block removal could not be confirmed. Check Rspamd before retrying.'
                : `Sync with Rspamd is off, but this app's Rspamd blocks could not be removed: ${settingsErrorText(body, res.statusText)}`, 'error'];
        }
        return [`Sync with Rspamd is off. Removed ${body.removed_blocks} app ${settingsPlural(body.removed_blocks, 'block', 'blocks')} from Rspamd.`, 'success'];
    }
    if (plan.action === 'keep' && !plan.feature_off) return ['Sync with Rspamd is off. Existing Rspamd blocks were kept.', 'success'];
    if (plan.action === 'apply') {
        // What changed in mailcow comes in first, then the list's waiting changes are written
        const res = await authenticatedFetch('/api/suppressions/sync?after_change=true', { method: 'POST' });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) return [`Sync with Rspamd is on, but Rspamd was not updated yet: ${settingsErrorText(body, res.statusText)}`, 'error'];
        const list = (body.list_added || body.list_removed)
            ? ` List updated from Rspamd: ${body.list_added || 0} added, ${body.list_removed || 0} deleted.` : '';
        if (body.written) return [`Sync with Rspamd is on. Rspamd updated: ${body.added} added, ${body.removed} removed.${list}`, 'success'];
        if (body.pending_count) return [`Sync with Rspamd is on, but ${body.pending_count} ${settingsPlural(body.pending_count, 'change waits', 'changes wait')}: the Read-Write API key is not set.${list}`, 'error'];
        return [`Sync with Rspamd is on. Rspamd is already up to date.${list}`, 'success'];
    }
    if (plan.action === 'import') {
        const what = plan.feature_on ? 'Suppressions are on' : 'Sync with Rspamd is on';
        const res = await authenticatedFetch('/api/suppressions/rspamd/import', { method: 'POST' });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) return [`${what}, but this app's Rspamd blocks could not be loaded yet: ${settingsErrorText(body, res.statusText)} They load on the next try.`, 'error'];
        if (body.reason === 'no_password') return [`${what}, but this app's Rspamd blocks load only once the Rspamd password is set.`, 'error'];
        // The count belongs to this request only when it did the load
        if (!body.loaded) return [`${what}.`, 'success'];
        return body.imported
            ? [`${what}. Loaded ${body.imported} ${settingsPlural(body.imported, 'block', 'blocks')} from Rspamd.`, 'success']
            : [`${what}. No blocks of this app were in Rspamd.`, 'success'];
    }
    if (plan.action === 'fresh') return ['Started fresh. The list is empty and this app\'s Rspamd blocks are removed. Sync with Rspamd is on.', 'success'];
    return null;
}

// Predefined options for settings fields (renders as dropdown instead of text input)
const SETTINGS_FIELD_OPTIONS = {
    webhook_type: [
        { value: 'generic', label: 'Generic - JSON POST {title, message, ...}' },
        { value: 'slack', label: 'Slack - Incoming Webhook' },
        { value: 'discord', label: 'Discord - Webhook URL' },
        { value: 'telegram', label: 'Telegram - Bot API (set chat ID)' },
        { value: 'ntfy', label: 'ntfy - topic URL' },
        { value: 'gotify', label: 'Gotify - /message?token=...' }
    ],
    // The Outbound bounce choices (settingsBounceChoice): {count} is the number field
    suppression_hard_bounce_action: [
        { value: 'suppress', label: 'Block new mail to the address and delete its queued mail', needs: 'logs rw-queue sync' },
        { value: 'delete', label: 'Delete its queued mail', needs: 'logs rw-queue', hint: 'Does not block new mail to the address.' },
        { value: 'ignore', label: 'Do nothing' }
    ],
    suppression_soft_bounce_action: [
        { value: 'count', label: 'Keep retrying; block new mail after {count} failures', needs: 'logs sync',
            hint: 'Each failed retry counts, even for the same message.' },
        { value: 'suppress', label: 'Keep retrying; block new mail at the first failure', needs: 'logs sync' },
        { value: 'ignore', label: 'Do nothing; keep retrying' }
    ]
};

// The IANA time zones this browser knows, UTC first; none where the browser
// cannot list them (the field is then a text box)
function settingsTimeZoneNames() {
    let names = [];
    try {
        names = Intl.supportedValuesOf('timeZone');
    } catch (e) {
        return [];
    }
    return ['UTC', ...names.filter(name => name !== 'UTC')];
}

const SETTINGS_TZ_NOT_SET = 'Not set (UTC)';

// The Time Zone picker writes its choice to the hidden field the form saves
function settingsPickZone(option) {
    const field = document.getElementById('edit-tz');
    if (!field || field.disabled) return;
    field.value = option.dataset.value;
    settingsShowZone(field);
    field.form && field.form.dispatchEvent(new Event('input', { bubbles: true }));
}

// The button and the chosen option follow the hidden field; the note about
// the saved zone goes once another one is picked
function settingsShowZone(field) {
    const host = field.parentElement.querySelector('.ui-picker');
    if (!host) return;
    host.querySelector('.ui-picker-btn > span').textContent = field.value || SETTINGS_TZ_NOT_SET;
    host.querySelectorAll('[role="option"]').forEach(o => o.setAttribute('aria-selected', String(o.dataset.value === field.value)));
    const note = field.parentElement.querySelector('[data-zone-note]');
    if (note) note.hidden = field.value !== field.dataset.saved;
}

function settingsTimeZoneKnown(name) {
    try {
        new Intl.DateTimeFormat('en-US', { timeZone: name });
        return true;
    } catch (e) {
        return false;
    }
}

// Edit form tabs (same order as env.example sections) with descriptions from env.example
// Keys grouped logically within each tab
var SETTINGS_EDIT_TABS = [
    {
        id: 'mailcow', label: 'Mailcow', description: 'Your mailcow instance URL and API credentials. API key needs read access to logs (generate from System → Configuration → Access → Administrators → API in mailcow admin). Set verify SSL to false only for development with self-signed certificates.', groups: [
            { label: 'Connection', keys: ['mailcow_url', 'mailcow_api_key', 'mailcow_api_key_rw'] },
            { label: 'Rspamd', keys: ['rspamd_password', 'rspamd_url'] },
            { label: 'Advanced', keys: ['mailcow_api_timeout', 'mailcow_api_verify_ssl'] }
        ]
    },
    {
        id: 'fetch', label: 'Fetch', description: 'How often to fetch logs from mailcow and how many records per request. Lower interval = more frequent updates, higher load. Retention: how many days to keep logs in the database (older logs are deleted).', groups: [
            { label: 'Timing', keys: ['fetch_interval'] },
            { label: 'Counts per Request', keys: ['fetch_count_postfix', 'fetch_count_rspamd', 'fetch_count_netfilter'] },
            { label: 'Pagination', keys: ['fetch_max_pages'] },
            { label: 'Retention', keys: ['retention_days'] },
            { label: 'Excluded addresses', keys: ['blacklist_emails'] }
        ]
    },
    {
        id: 'correlation', label: 'Correlation', description: 'Correlation links Postfix logs to messages. Max age: stop searching for correlations older than this (minutes). Check interval: how often to run the correlation job (seconds).', groups: [
            { label: 'Settings', keys: ['max_correlation_age_minutes', 'correlation_check_interval'] }
        ]
    },
    {
        id: 'application', label: 'Application', description: 'Web app port, title, logo and time zone. Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL. Debug mode shows detailed errors (do not enable in production). Search/CSV limits and scheduler worker count.', groups: [
            { label: 'Basic', keys: ['app_port', 'app_title', 'app_logo_url'] },
            { label: 'Time', keys: ['tz'] },
            { label: 'Logging', keys: ['log_level', 'debug'] },
            { label: 'Limits', keys: ['max_search_results', 'csv_export_limit', 'scheduler_workers'] }
        ]
    },
    {
        id: 'features', label: 'Features', description: 'Turn off what you do not use. A feature that is off disappears from the menu and stops its background jobs. Turning a feature off deletes its stored data, so you are asked first.', groups: [
            { label: 'Features', keys: ['disabled_features'] }
        ]
    },
    {
        id: 'blacklist', label: 'IP Blacklist (RBL)', description: 'The blacklist monitor checks whether your mail server IPs are listed on spam blacklists (Spamhaus and others). Choose which hosts are monitored below. Note: Spamhaus refuses queries sent through public DNS resolvers, so point this at your own resolver if the Spamhaus checks come back as unknown.', groups: [
            { label: 'Monitoring sources', keys: ['blacklist_source_server_ip', 'blacklist_source_transports', 'blacklist_source_relayhosts', 'blacklist_source_manual_hosts'] },
            { label: 'DNS resolver', keys: ['blacklist_dns_servers'] }
        ]
    },
    {
        id: 'domains', label: 'Domains', description: 'DNS checks for your domains (SPF, DKIM, DMARC, DNSSEC, DANE, MTA-STS) on the Domains page. Choose which sending IPs must pass each domain SPF record - with a relay setup the relay IPs matter, not the auto-detected WAN IP.', groups: [
            { label: 'SPF check sources', keys: ['domain_spf_source_server_ip', 'domain_spf_source_transports', 'domain_spf_source_relayhosts', 'domain_spf_source_manual_hosts', 'domain_spf_source_dmarc_history'] }
        ]
    },
    {
        id: 'auth', label: 'Authentication', description: 'How users sign in to this app. Basic authentication protects every page and API endpoint with a username and password. OAuth2/OIDC signs users in through an external provider (mailcow, Keycloak, ...). Both can be enabled at the same time.', groups: [
            { label: 'Basic Auth', keys: ['basic_auth_enabled', 'auth_username', 'auth_password', 'auth_max_failure_clients'] },
            { label: 'OAuth2 / OIDC', keys: ['oauth2_enabled', 'oauth2_provider_name'] },
            { label: 'OAuth2 - Discovery (automatic)', keys: ['oauth2_issuer_url', 'oauth2_use_oidc_discovery'] },
            { label: 'OAuth2 - Endpoints (only without discovery)', keys: ['oauth2_authorization_url', 'oauth2_token_url', 'oauth2_userinfo_url'] },
            { label: 'OAuth2 - Credentials', keys: ['oauth2_client_id', 'oauth2_client_secret', 'oauth2_redirect_uri', 'oauth2_scopes'] },
            { label: 'Sessions', keys: ['session_secret_key', 'session_expiry_hours', 'session_max_entries'] }
        ]
    },
    {
        id: 'smtp', label: 'SMTP', description: 'SMTP for sending notifications (alerts, weekly summary). Relay mode: for local relay servers that do not require authentication (only host and from address needed).', groups: [
            { label: 'Enable', keys: ['smtp_enabled'] },
            { label: 'Server', keys: ['smtp_host', 'smtp_port'] },
            { label: 'Security', keys: ['smtp_use_tls', 'smtp_use_ssl', 'smtp_verify_ssl'] },
            { label: 'Authentication', keys: ['smtp_user', 'smtp_password', 'smtp_relay_mode'] },
            { label: 'From Address', keys: ['smtp_from'] }
        ]
    },
    {
        id: 'notifications', label: 'Notifications', description: 'Where alerts are delivered. Add one or more destinations (Slack, Telegram, ntfy, ...) below and choose which alerts each one receives, plus the email addresses used for the different alert types.', groups: [
            { label: 'Email addresses', keys: ['admin_email', 'blacklist_alert_email', 'dmarc_error_email', 'enable_weekly_summary'] },
            { label: 'Alert types', keys: ['dns_change_alerts_enabled'] }
        ]
    },
    {
        id: 'smtp_abuse', label: 'SMTP Abuse (Beta)', description: 'Beta - please report issues on GitHub. Enforcement layer: automatically disables SMTP (sending) for a mailbox that exceeds a hard outbound limit - the usual signature of a compromised account. The mailbox still receives mail; if its app passwords are revoked too, mail apps that sign in with one stop working. Requires a Read-Write mailcow API key. Manage blocked mailboxes and the whitelist under Security → Settings → Outgoing spam.', groups: [
            { label: 'Enable', keys: ['smtp_abuse_enabled'] },
            { label: 'Limit', keys: ['smtp_abuse_threshold', 'smtp_abuse_window_minutes'] },
            { label: 'Response', keys: ['smtp_abuse_revoke_app_passwords', 'smtp_abuse_unblock_grace_minutes', 'smtp_abuse_help_address'] }
        ]
    },
    {
        id: 'anomaly', label: 'Anomaly Detection (Beta)', description: 'Beta - please report issues on GitHub. Detect compromised mailboxes and auth attacks. Alerts when a mailbox sends far above its own baseline (possible account takeover). Daily send patterns are learned automatically - a mailbox that sends a big batch at the same hour every day will not alert unless it bursts off-schedule or far above its usual size or when a username accumulates many auth failures. Alerts go to email + webhook and appear on the dashboard.', groups: [
            { label: 'Enable', keys: ['anomaly_detection_enabled'] },
            { label: 'Volume Spike', keys: ['anomaly_volume_multiplier', 'anomaly_volume_min_messages', 'anomaly_baseline_days'] },
            { label: 'Auth Failures', keys: ['anomaly_auth_failure_threshold'] },
            { label: 'Timing', keys: ['anomaly_check_interval', 'anomaly_alert_cooldown_hours'] }
        ]
    },
    {
        id: 'dmarc', label: 'DMARC & TLS', description: 'How long DMARC and TLS reports are kept (days). Allow uploading reports by hand and deleting them from the UI. Weekly summary: enable email report sent to admin.', groups: [
            { label: 'Retention', keys: ['dmarc_retention_days'] },
            { label: 'Features', keys: ['dmarc_manual_upload_enabled', 'dmarc_allow_report_delete'] },
            { label: 'Insights (policy recommendations)', keys: ['dmarc_insights_window_days', 'dmarc_insights_pass_threshold', 'dmarc_insights_min_volume'] }
        ]
    },
    {
        id: 'dmarc_imap', label: 'DMARC & TLS IMAP', description: 'Import DMARC and TLS reports automatically from an IMAP mailbox: the address in the rua= of your DMARC and TLS-RPT records. Set host, port, user, password and folder (e.g. INBOX). Delete after: remove emails after processing. Interval in seconds; run on startup to sync once at start.', groups: [
            { label: 'Enable', keys: ['dmarc_imap_enabled'] },
            { label: 'Connection', keys: ['dmarc_imap_host', 'dmarc_imap_port', 'dmarc_imap_use_ssl', 'dmarc_imap_verify_ssl'] },
            { label: 'Authentication', keys: ['dmarc_imap_user', 'dmarc_imap_password'] },
            { label: 'Settings', keys: ['dmarc_imap_folder', 'dmarc_imap_delete_after', 'dmarc_imap_interval', 'dmarc_imap_run_on_startup', 'dmarc_imap_batch_size', 'dmarc_imap_scan_all_unseen'] }
        ]
    },
    {
        id: 'maxmind', label: 'MaxMind', description: 'MaxMind GeoIP database configuration for IP geolocation. Account ID and License Key are required to download GeoLite2 databases. Status shows whether databases are configured and up to date.', groups: [
            { label: 'Credentials', keys: ['maxmind_account_id', 'maxmind_license_key'] },
            { label: 'Status', keys: [] }  // Status will be displayed separately, not as editable field
        ]
    },
    {
        id: 'logs', label: 'Logs', description: 'Live log viewer settings. Controls background collection of raw logs from mailcow services. Logs are stored in a separate database table and streamed via WebSocket to the Logs page. Adjust fetch interval and retention to balance freshness vs. storage usage.', groups: [
            { label: 'Enable', keys: ['raw_logs_enabled'] },
            { label: 'Fetch Settings', keys: ['raw_logs_fetch_interval', 'raw_logs_fetch_count'] },
            { label: 'Retention', keys: ['raw_logs_retention_days', 'rate_limits_retention_days'] },
            { label: 'Services', keys: ['raw_logs_services'] }
        ]
    },
    {
        id: 'devices', label: 'Devices', description: 'The Devices page lists the phones and tablets that sync over ActiveSync. It reads the SOGo log through the mailcow API every minute.', groups: [
            { label: 'Retention', keys: ['eas_devices_retention_days'] }
        ]
    },
    {
        // Was spam_filter (Queue Management); the old address opens this one (router.js). Hidden while Suppressions is off
        id: 'outbound', label: 'Outbound', description: 'Choose what happens when outgoing mail cannot be delivered. Blocked addresses are listed on Outbound > Suppressions.', groups: [
            // The sync belongs to the list, not to the automatic handling: a list kept by hand syncs too
            { label: 'Rspamd', keys: ['suppression_rspamd_sync'] },
            { label: 'Automatic handling', keys: ['suppression_enabled'] },
            // Reading the logs is set by the choices (settingsSyncBounce)
            { label: 'Permanent delivery failure', choice: 'hard', needs: 'suppression_enabled', keys: ['suppression_hard_bounce_action', 'suppression_auto_detect'],
                intro: 'The receiving server rejected the message permanently. (5.x.x)' },
            { label: 'Temporary delivery failure', choice: 'soft', needs: 'suppression_enabled',
                keys: ['queue_cleanup_enabled', 'queue_cleanup_block', 'suppression_soft_bounce_action', 'queue_cleanup_threshold_minutes', 'suppression_soft_bounce_threshold'],
                intro: 'Postfix keeps the message and retries. (4.x.x)' },
            // A block reaches Rspamd only through the sync: without it nothing is blocked
            { label: 'How long to block', needs: 'suppression_enabled suppression_rspamd_sync', keys: ['suppression_base_expiry_days', 'suppression_max_expiry_days'] },
            { label: 'Exceptions', needs: 'suppression_enabled', keys: ['suppression_whitelist_domains'] }
        ]
    },
    {
        id: 'quarantine', label: 'Quarantine', description: 'Quarantine auto-rules settings. Rules automatically release or delete quarantined emails based on sender, domain, recipient, or subject patterns. Requires a Read-Write API key.', groups: [
            { label: 'Auto-Rules Scheduler', keys: ['quarantine_rules_max_actions', 'quarantine_rules_interval', 'quarantine_rules_log_retention_days'] }
        ]
    }
];

// Groups the Edit-configuration tabs into a vertical sidebar. Order here =
// display order. A group with no visible tabs is omitted; any visible tab not
// listed here falls into the last group automatically (so new tabs never
// silently disappear).
var SETTINGS_TAB_GROUPS = [
    { label: 'General', tabs: ['features', 'application'] },
    { label: 'mailcow', tabs: ['mailcow', 'fetch', 'correlation', 'logs'] },
    { label: 'Alerts', tabs: ['notifications', 'smtp'] },
    { label: 'Security', tabs: ['auth', 'anomaly', 'smtp_abuse'] },
    { label: 'Data', tabs: ['domains', 'dmarc', 'dmarc_imap', 'maxmind', 'blacklist', 'outbound', 'quarantine', 'devices', 'other'] }
];

// A stored secret shows as Stored with Replace and Remove; the hidden field
// keeps the mask, which the save leaves untouched
function settingsReplaceSecret(btn) {
    const box = btn.closest('.ui-set-secret');
    if (!box) return;
    const hidden = box.querySelector('input[type="hidden"]');
    const input = document.createElement('input');
    input.type = 'password';
    input.name = hidden.name;
    input.id = hidden.id;
    input.className = 'ui-input';
    input.placeholder = 'New value';
    input.autocomplete = 'new-password';
    box.replaceWith(input);
    input.focus();
    input.form && input.form.dispatchEvent(new Event('input', { bubbles: true }));
}

function settingsRemoveSecret(btn) {
    const box = btn.closest('.ui-set-secret');
    if (!box) return;
    const hidden = box.querySelector('input[type="hidden"]');
    const state = box.querySelector('.ui-set-secret-state');
    const removing = hidden.value === '********';
    hidden.value = removing ? '' : '********';
    if (state) state.textContent = removing ? 'Removed when you save' : 'Stored';
    box.classList.toggle('is-removing', removing);
    btn.textContent = removing ? 'Keep' : 'Remove';
    hidden.form && hidden.form.dispatchEvent(new Event('input', { bubbles: true }));
}

// Raw log services other pages read (/api/settings/info), collected whatever is ticked
let settingsRawLogsRequired = {};

// A setting's label, spelled from its key with the acronyms in capitals (SSL, IMAP, TLS, etc.).
// Settings for both DMARC and TLS reports drop the DMARC_ prefix of their key (IMAP Host, Retention Days);
// the DMARC-only ones (Insights) keep it
function settingsFieldLabel(key) {
    const labelKey = SETTINGS_LABEL_OVERRIDES[key] ? null
        : /^dmarc_(imap_|retention_days$|manual_upload_enabled$|allow_report_delete$)/.test(key) ? key.slice('dmarc_'.length) : key;
    const label = SETTINGS_LABEL_OVERRIDES[key] || labelKey.replace(/_/g, ' ').replace(/\b\w/g, function (l) { return l.toUpperCase(); });
    return label.replace(/\bSsl\b/gi, 'SSL').replace(/\bImap\b/gi, 'IMAP').replace(/\bTls\b/gi, 'TLS')
        .replace(/\bOauth\b/gi, 'OAuth').replace(/\bOidc\b/gi, 'OIDC').replace(/\bApi\b/gi, 'API')
        .replace(/\bUrl\b/gi, 'URL').replace(/\bIp\b/gi, 'IP').replace(/\bDns\b/gi, 'DNS')
        .replace(/\bDmarc\b/gi, 'DMARC').replace(/\bSpf\b/gi, 'SPF').replace(/\bDkim\b/gi, 'DKIM')
        .replace(/\bSmtp\b/gi, 'SMTP').replace(/\bCsv\b/gi, 'CSV').replace(/\bEnv\b/gi, 'ENV')
        .replace(/\bDb\b/gi, 'DB').replace(/\bRw\b/g, '(read-write)').replace(/^Mailcow\b/, 'mailcow');
}

// Settings sections that belong to a feature: they are hidden while it is off
const SETTINGS_TAB_FEATURE_MAP = {
    'domains': 'domains',
    'blacklist': 'blacklist',
    'dmarc': 'dmarc',
    'dmarc_imap': 'dmarc',
    // Not 'logs': the raw logs other pages read are fetched and kept by its settings either way
    'outbound': 'suppressions',
    'quarantine': 'quarantine',
    'devices': 'devices'
};

function settingsTabOff(tabId) {
    const feature = SETTINGS_TAB_FEATURE_MAP[tabId];
    return !!(feature && window.disabledFeatures && window.disabledFeatures.includes(feature));
}

// Every setting with its label and section, for the search in the top bar. It
// comes from the sections above, so the Settings page need not be open
function settingsSearchIndex() {
    const items = [];
    SETTINGS_EDIT_TABS.forEach(function (tab) {
        if (settingsTabOff(tab.id)) return;
        (tab.groups || []).forEach(function (group) {
            group.keys.forEach(function (key) {
                items.push({ key: key, label: settingsFieldLabel(key), tab: tab.id, tabLabel: tab.label, group: group.label });
            });
        });
    });
    return items;
}

function renderSettingsEditField(key, value, sensitiveKeys, description, envLocked, defaultValue) {
    const keyAttr = escapeHtml(key); // setting names go into ids, names and data attributes
    const LOCK = SETTINGS_LOCK_ICON;
    // Special renderer for disabled_features - checkboxes for feature toggles
    if (key === 'disabled_features') {
        const disabledSet = new Set(
            (value || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
        );
        const isLocked = envLocked;

        let html = `<div class="ui-set-wide ui-set-featurelist">`;

        if (isLocked) {
            html += `<p class="ui-set-env">${LOCK} Set by ENV (DISABLED_FEATURES), change it there</p>`;
        }

        html += `<div class="ui-set-features">`;

        for (const feature of TOGGLEABLE_FEATURES) {
            const isEnabled = !disabledSet.has(feature.id);
            const checkedAttr = isEnabled ? 'checked' : '';
            const disabledAttr = isLocked ? 'disabled' : '';

            html += `<label class="ui-feature ${isEnabled ? 'is-on' : 'is-off'}${isLocked ? ' is-locked' : ''}">
                <input type="checkbox" ${checkedAttr} ${disabledAttr} class="ui-check"
                    onchange="updateDisabledFeaturesCheckbox('${feature.id}', this.checked, this)">
                <span><b>${feature.label}</b><small>${feature.description}</small></span>
            </label>`;
        }

        html += `</div>
            <input type="hidden" id="setting-disabled_features" name="disabled_features" value="${escapeHtml(value || '')}">
        </div>`;

        return html;
    }

    // Special renderer for raw_logs_services: one row per service with a
    // switch, like Features. A service another page reads says so on its row:
    // it keeps coming in with the switch off, which the switch alone would hide.
    if (key === 'raw_logs_services') {
        const ALL_LOG_SERVICES = [
            { id: 'postfix', label: 'Postfix', description: 'Mail sent and received (MTA)' },
            { id: 'rspamd-history', label: 'Rspamd', description: 'Spam filter verdicts' },
            { id: 'dovecot', label: 'Dovecot', description: 'IMAP and POP3 logins and mail delivery' },
            { id: 'sogo', label: 'SOGo', description: 'Webmail, calendars, contacts and ActiveSync' },
            { id: 'netfilter', label: 'Netfilter', description: 'Fail2ban bans and failed logins' },
            { id: 'ratelimited', label: 'Ratelimited', description: 'Senders that hit a rate limit' },
            { id: 'acme', label: 'ACME', description: 'TLS certificate renewals' },
            { id: 'api', label: 'API', description: 'Requests to the mailcow API' },
            { id: 'autodiscover', label: 'Autodiscover', description: 'Mail client setup requests' },
            { id: 'watchdog', label: 'Watchdog', description: 'Container health checks' }
        ];
        const enabledServices = (value || '').split(',').map(function(s) { return s.trim().toLowerCase(); }).filter(Boolean);
        const all = enabledServices.includes('all');
        const disabledAttr = envLocked ? 'disabled' : '';

        let html = '<div class="ui-set-wide ui-set-featurelist">';
        if (description && description.trim()) html += '<p class="ui-set-desc">' + escapeHtml(description) + '</p>';
        if (envLocked) html += '<p class="ui-set-env">' + LOCK + ' Set by ENV (RAW_LOGS_SERVICES), change it there</p>';
        html += '<div class="ui-set-features">';
        ALL_LOG_SERVICES.forEach(function(svc) {
            const on = all || enabledServices.includes(svc.id);
            const usedBy = settingsRawLogsRequired[svc.id];
            const also = usedBy ? '<small class="ui-set-also">Always collected for ' + escapeHtml(usedBy.join(', ')) + '</small>' : '';
            html += '<label class="ui-feature ' + (on ? 'is-on' : 'is-off') + (envLocked ? ' is-locked' : '') + '">' +
                '<input type="checkbox" class="raw-logs-service-cb ui-check" data-service="' + svc.id + '" ' + (on ? 'checked' : '') + ' ' + disabledAttr + '>' +
                '<span><b>' + escapeHtml(svc.label) + '</b><small>' + escapeHtml(svc.description) + '</small>' + also + '</span></label>';
        });
        html += '</div>';
        html += '<input type="hidden" id="edit-raw_logs_services" name="raw_logs_services" value="' + escapeHtml(value || '') + '">';
        return html + '</div>';
    }

    const isBool = typeof value === 'boolean';
    const isNum = typeof value === 'number';
    const sensitive = sensitiveKeys.includes(key);
    const displayVal = value === null || value === undefined ? '' : (isBool ? value : String(value));
    const label = settingsFieldLabel(key);
    const descHtml = (description && description.trim()) ? '<p class="ui-set-desc">' + escapeHtml(description) + '</p>' : '';
    const disabledAttr = envLocked ? 'disabled' : '';
    const envLockedHtml = '';
    const labelLockIcon = envLocked ? ' <span class="ui-set-pill" title="Set by an environment variable, change it there">' + LOCK + ' Set by ENV</span>' : '';

    // Determine if changed from default
    const hasDefault = defaultValue !== null && defaultValue !== undefined;
    // User-specific settings: show plain "Clear" instead of "Reset to default" since
    // these are inherently unique per deployment (credentials, feature toggles, connection details)
    const USER_SPECIFIC_KEYS = new Set([
        'mailcow_url', 'mailcow_api_key', 'mailcow_api_key_rw',
        'basic_auth_enabled', 'auth_username', 'auth_password',
        'oauth2_enabled', 'oauth2_provider_name', 'oauth2_issuer_url', 'oauth2_use_oidc_discovery',
        'oauth2_authorization_url', 'oauth2_token_url', 'oauth2_userinfo_url',
        'oauth2_client_id', 'oauth2_client_secret', 'oauth2_redirect_uri', 'oauth2_scopes',
        'session_secret_key',
        'smtp_enabled', 'smtp_host', 'smtp_port', 'smtp_user', 'smtp_password', 'smtp_from',
        'admin_email', 'blacklist_alert_email', 'dmarc_error_email',
        'dmarc_imap_enabled', 'dmarc_imap_host', 'dmarc_imap_port',
        'dmarc_imap_user', 'dmarc_imap_password', 'dmarc_imap_folder',
        'maxmind_account_id', 'maxmind_license_key',
        'app_title', 'app_logo_url', 'blacklist_emails', 'local_domains',
        'enable_weekly_summary'
    ]);
    const isUserSpecific = USER_SPECIFIC_KEYS.has(key);
    const isChanged = hasDefault && !sensitive && !isUserSpecific && (function() {
        // An empty time zone is UTC, the default
        if (key === 'tz') return (String(value || '').trim() || 'UTC') !== (String(defaultValue || '').trim() || 'UTC');
        if (isBool) return value !== defaultValue;
        if (isNum) return Number(value) !== Number(defaultValue);
        return String(value || '') !== String(defaultValue || '');
    })();
    // A stored secret is not a changed setting: it gets a plain Clear and no marker
    const isSensitiveChanged = false;

    // Clear/Reset button HTML (not shown for env-locked fields)
    let clearBtnHtml = '';
    if (!envLocked) {
        if (hasDefault && !isUserSpecific && (isChanged || isSensitiveChanged)) {
            const defaultLabel = sensitive || String(defaultValue) === '' ? 'empty' : escapeHtml(String(defaultValue));
            clearBtnHtml = '<button type="button" class="settings-clear-btn ui-set-clear is-reset" data-key="' + keyAttr + '" data-default="' + escapeHtml(String(defaultValue)) + '" data-sensitive="' + sensitive + '" data-isbool="' + isBool + '">' +
                '↺ Reset to default' + (isBool ? ': ' + defaultLabel : ' (' + defaultLabel + ')') + '</button>';
        } else if (!isBool && String(displayVal).trim() !== '' && !(sensitive && displayVal === '') && !(hasDefault && !isUserSpecific && String(displayVal) === String(defaultValue))) {
            clearBtnHtml = '<button type="button" class="settings-clear-btn ui-set-clear" data-key="' + keyAttr + '" data-default="' + (hasDefault ? escapeHtml(String(defaultValue)) : '') + '" data-sensitive="' + sensitive + '" data-isbool="false">' +
                '× Clear</button>';
        }
    }

    // A value that differs from its default is marked, so a changed setting stands out
    const changed = (isChanged || isSensitiveChanged) && !envLocked ? ' is-changed' : '';
    const changedPill = changed ? ' <span class="ui-set-pill is-changed" title="Differs from the default">Changed</span>' : '';

    // A stored secret: say so, and offer Replace and Remove instead of a masked field
    if (sensitive && displayVal === '********') {
        return '<div class="ui-set-field' + (envLocked ? ' is-locked' : '') + '"><label class="ui-label">' + escapeHtml(label) + labelLockIcon + '</label>' + descHtml +
            '<div class="ui-set-secret"><span class="ui-set-secret-state">' + (envLocked ? 'Stored in the environment' : 'Stored') + '</span>' +
            (envLocked ? '' : '<button type="button" class="ui-btn ui-btn-sm" onclick="settingsReplaceSecret(this)">Replace</button>' +
                '<button type="button" class="ui-btn ui-btn-sm" onclick="settingsRemoveSecret(this)">Remove</button>') +
            '<input type="hidden" id="edit-' + keyAttr + '" name="' + keyAttr + '" value="********"' + (envLocked ? ' disabled' : '') + '></div></div>';
    }

    const segments = SETTINGS_SEGMENTED_OPTIONS[key];
    if (segments) {
        const current = segments.some(([v]) => v === String(displayVal)) ? String(displayVal) : segments[0][0];
        const buttons = segments.map(([v, text]) =>
            '<button type="button" data-value="' + escapeHtml(v) + '" aria-pressed="' + (v === current) + '" ' + disabledAttr +
            ' onclick="settingsPickSegment(this)">' + escapeHtml(text) + '</button>').join('');
        // Changed marker and Reset as for every other field; Reset names the default option (Off)
        const defaultOption = segments.find(([v]) => v === String(defaultValue));
        const segClearHtml = clearBtnHtml && defaultOption
            ? clearBtnHtml.replace(/\(([^()]*)\)<\/button>$/, '(' + escapeHtml(defaultOption[1]) + ')</button>')
            : clearBtnHtml;
        return '<div class="ui-set-field ui-set-seg' + (envLocked ? ' is-locked' : '') + changed + '"><span class="ui-label" id="label-' + keyAttr + '">' + escapeHtml(label) + labelLockIcon + changedPill + '</span>' +
            descHtml +
            '<div class="ui-seg" role="group" aria-labelledby="label-' + keyAttr + '">' + buttons + '</div>' +
            '<input type="hidden" id="edit-' + keyAttr + '" name="' + keyAttr + '" value="' + escapeHtml(current) + '"' + (envLocked ? ' disabled' : '') + '>' +
            segClearHtml + '</div>';
    }

    if (isBool) {
        // The whole row toggles, like a Features row: the row is the label (so its text is phrasing content)
        const asSpan = html => html.replace(/^<p /, '<span ').replace(/<\/p>$/, '</span>');
        return '<div class="ui-set-bool' + (envLocked ? ' is-locked' : (isChanged ? ' is-changed' : '')) + '">' +
            '<label for="edit-' + keyAttr + '" class="ui-set-bool-main">' +
            '<input type="checkbox" id="edit-' + keyAttr + '" name="' + keyAttr + '" ' + (displayVal ? 'checked' : '') + ' ' + disabledAttr + ' class="ui-check">' +
            '<span class="ui-set-bool-text"><span class="ui-set-bool-label">' + escapeHtml(label) + labelLockIcon + (envLocked ? '' : (isChanged ? ' <span class="ui-set-pill is-changed" title="Differs from the default">Changed</span>' : '')) + '</span>' + asSpan(descHtml) + asSpan(envLockedHtml) + '</span></label>' +
            clearBtnHtml + '</div>';
    }

    const zones = key === 'tz' ? settingsTimeZoneNames() : [];
    if (zones.length) {
        const current = String(displayVal).trim();
        // A name the server or this browser does not know: the app runs in UTC until it is fixed
        const unknown = current !== '' && (!settingsTimeZoneKnown(current)
            || (typeof appTimezoneStatus !== 'undefined' && appTimezoneStatus.valid === false && appTimezoneStatus.configured === current));
        const names = current && !zones.includes(current) ? [current, ...zones] : zones;
        // A long list, so a picker with a search (utils.js, uiPicker); the hidden field holds the value
        const options = [{ value: '', label: SETTINGS_TZ_NOT_SET }, ...names.map(name => ({ value: name, label: name + (name === current && unknown ? ' (unknown)' : '') }))]
            .map(o => ({ ...o, selected: o.value === current, onclick: 'settingsPickZone(this)' }));
        const picker = uiPicker({
            id: 'settings-' + key, label, value: escapeHtml(current || SETTINGS_TZ_NOT_SET), options, search: 'Search time zones',
            field: true, labelledBy: 'label-' + keyAttr, disabled: envLocked
        });
        // The description already says to pick the server's zone; only a name the app cannot use needs a word more
        const note = unknown
            ? '<small class="ui-text-warn" role="status" data-zone-note>' + escapeHtml(`"${current}" is not a known time zone, so the app uses UTC. `) +
                (envLocked ? 'Fix TZ in the environment.' : 'Pick a time zone from the list.') + '</small>'
            : '';
        return '<div class="ui-set-field' + (envLocked ? ' is-locked' : '') + '"><span class="ui-label" id="label-' + keyAttr + '">' + escapeHtml(label) + labelLockIcon + changedPill + '</span>' +
            descHtml + picker +
            '<input type="hidden" id="edit-' + keyAttr + '" name="' + keyAttr + '" value="' + escapeHtml(current) + '" data-saved="' + escapeHtml(current) + '"' + (envLocked ? ' disabled' : '') + '>' +
            note + clearBtnHtml + '</div>';
    }

    // Dropdown for fields with predefined options
    const fieldOptions = SETTINGS_FIELD_OPTIONS[key];
    if (fieldOptions) {
        let optionsHtml = '';
        fieldOptions.forEach(function(opt) {
            const selected = String(displayVal) === opt.value ? 'selected' : '';
            optionsHtml += '<option value="' + escapeHtml(opt.value) + '" ' + selected + '>' + escapeHtml(opt.label) + '</option>';
        });
        return '<div class="ui-set-field' + (envLocked ? ' is-locked' : '') + '"><label for="edit-' + keyAttr + '" class="ui-label">' + escapeHtml(label) + labelLockIcon + changedPill + '</label>' +
            descHtml +
            '<select id="edit-' + keyAttr + '" name="' + keyAttr + '" ' + disabledAttr + ' class="ui-select' + changed + '">' +
            optionsHtml + '</select>' +
            clearBtnHtml +
            envLockedHtml + '</div>';
    }

    const inputType = sensitive ? 'password' : (isNum ? 'number' : 'text');
    const placeholder = envLocked ? 'Set by ENV' : (sensitive ? 'Not set' : '');
    const valAttr = (isBool ? '' : displayVal);
    return '<div class="ui-set-field' + (envLocked ? ' is-locked' : '') + '"><label for="edit-' + keyAttr + '" class="ui-label">' + escapeHtml(label) + labelLockIcon + changedPill + '</label>' +
        descHtml +
        '<input type="' + inputType + '" id="edit-' + keyAttr + '" name="' + keyAttr + '" value="' + escapeHtml(valAttr) + '" placeholder="' + escapeHtml(placeholder) + '" ' + disabledAttr + ' class="ui-input' + changed + '">' +
        clearBtnHtml +
        envLockedHtml + '</div>';
}

async function loadSettings() {
    const loading = document.getElementById('settings-loading');
    const content = document.getElementById('settings-content');

    if (!loading || !content) {
        console.error('Settings elements not found');
        return;
    }

    loading.classList.remove('hidden');
    content.classList.add('hidden');

    try {
        // Load settings info first (most important)
        const settingsResponse = await authenticatedFetch('/api/settings/info');

        if (!settingsResponse.ok) {
            throw new Error(`HTTP ${settingsResponse.status}`);
        }

        const data = await settingsResponse.json();
        settingsRawLogsRequired = data.raw_logs_required || {};

        // Always fetch GET /api/settings so we have the UI-edit flag and editable_config (in case /info omits them or env just enabled)
        try {
            const editableRes = await authenticatedFetch('/api/settings');
            if (editableRes.ok) {
                const editableData = await editableRes.json();
                if (data.settings_edit_via_ui_enabled === undefined) data.settings_edit_via_ui_enabled = editableData.settings_edit_via_ui_enabled;
                if (data.settings_edit_via_ui_enabled && !data.editable_config) data.editable_config = editableData.configuration || {};
                if (editableData.default_config) data.default_config = editableData.default_config;
                if (editableData.settings_migrated !== undefined) data.settings_migrated = editableData.settings_migrated;
                if (editableData.env_locked_keys) data.env_locked_keys = editableData.env_locked_keys;
            }
        } catch (e) {
            console.warn('Could not load editable settings:', e);
        }

        // Use cached version info if available to show page immediately
        if (versionInfoCache.app_version) {
            data.app_version = versionInfoCache.app_version;
        }
        if (versionInfoCache.version_info) {
            data.version_info = versionInfoCache.version_info;
        }

        // Render settings immediately with cached or default data
        renderSettings(content, data);

        loading.classList.add('hidden');
        content.classList.remove('hidden');
        showSettingsToastAfterReload();

        // Load app info and version status in parallel (non-blocking)
        (async () => {
            try {
                const [appInfoResponse, versionResponse] = await Promise.all([
                    authenticatedFetch('/api/info'),
                    authenticatedFetch('/api/status/app-version')
                ]);

                const appInfo = appInfoResponse.ok ? await appInfoResponse.json() : null;
                const versionInfo = versionResponse.ok ? await versionResponse.json() : null;

                // Update cache
                if (appInfo) {
                    versionInfoCache.app_version = appInfo.version;
                }
                if (versionInfo) {
                    versionInfoCache.version_info = versionInfo;
                }

                // Update UI with fresh data
                if (appInfo || versionInfo) {
                    const currentData = { ...data };
                    if (appInfo) {
                        currentData.app_version = appInfo.version;
                    }
                    if (versionInfo) {
                        currentData.version_info = versionInfo;
                    }
                    renderSettings(content, currentData);
                }
            } catch (error) {
                console.error('Failed to load version info:', error);
                // Page is already shown, so just log the error
            }
        })();

    } catch (error) {
        console.error('Failed to load settings:', error);
        loading.innerHTML = `
            <div class="ui-empty">
                <p class="ui-text-fail">Failed to load settings</p>
                <p>${escapeHtml(error.message)}</p>
            </div>
        `;
    }
}

// The latest version, its state and the update note, by id
function renderLatestVersionState(versionInfo) {
    // The server answers "unknown" when GitHub could not be reached
    if (versionInfo.latest_version === 'unknown') return `Not known ${uiTag('Check failed', 'warn')}`;
    const tag = versionInfo.update_available ? uiTag('Update Available', 'ok')
        : versionInfo.latest_version ? uiTag('Up to Date', 'info') : '';
    return `${versionInfo.latest_version ? `v${escapeHtml(versionInfo.latest_version)}` : 'Checking...'} ${tag}`;
}

function renderUpdateNote(versionInfo) {
    if (!versionInfo.update_available) return '';
    return `
        <div class="ui-alert ui-alert-info ui-set-update">
            <span class="ui-alert-bar"></span>
            <div class="ui-alert-text">
                <div class="ui-alert-title"><b>Update available!</b></div>
                <p>A new version (v${escapeHtml(versionInfo.latest_version)}) is available on GitHub.</p>
                ${versionInfo.changelog ? `<div class="update-changelog-content markdown-body ui-set-changelog"></div>` : ''}
                <a href="https://github.com/ShlomiPorush/mailcow-logs-viewer/releases/latest" target="_blank" rel="noopener noreferrer" class="ui-link">View release notes →</a>
            </div>
        </div>`;
}

function updateVersionInfoUI(versionInfo) {
    const latest = document.getElementById('settings-latest-version');
    if (latest) latest.innerHTML = renderLatestVersionState(versionInfo);
    const checked = document.getElementById('settings-version-checked');
    if (checked) checked.textContent = versionInfo.last_checked ? `Last checked: ${formatDate(versionInfo.last_checked)}` : '';
    const note = document.getElementById('settings-update-note');
    if (note) {
        note.innerHTML = renderUpdateNote(versionInfo);
        const changelogEl = note.querySelector('.update-changelog-content');
        if (changelogEl && typeof marked !== 'undefined' && versionInfo.changelog) {
            marked.setOptions({ breaks: true, gfm: true });
            changelogEl.innerHTML = renderMarkdown(versionInfo.changelog);
        }
    }
}

function renderSettings(content, data) {
    const config = data.configuration || {};
    const appVersion = data.app_version || 'Unknown';
    const versionInfo = data.version_info || {};

    // Sync MaxMind status: backend DB is the source of truth.
    // Frontend cache only bridges the gap between a validate click and next full reload.
    if (config.maxmind_status !== null && config.maxmind_status !== undefined) {
        // Backend returned a persisted result from DB - use it
        _cachedMaxMindStatus = config.maxmind_status;
    } else if (_cachedMaxMindStatus) {
        // Backend returned null (never checked) but we just validated in this session - show it
        config.maxmind_status = _cachedMaxMindStatus;
    }

    const kv = (label, value, cls = '') => `<div class="ui-kv"><span>${label}</span><b class="${cls}">${value}</b></div>`;
    const readOnlyFacts = [
        ['Fetch Interval', `${escapeHtml(String(config.fetch_interval || 0))} seconds`],
        ['Fetch Count (Postfix)', `${escapeHtml(String(config.fetch_count_postfix || config.fetch_count || 0))} per request`],
        ['Fetch Count (Rspamd)', `${escapeHtml(String(config.fetch_count_rspamd || config.fetch_count || 0))} per request`],
        ['Fetch Count (Netfilter)', `${escapeHtml(String(config.fetch_count_netfilter || config.fetch_count || 0))} per request`],
        ['Max Pages per Cycle', `${escapeHtml(String(config.fetch_max_pages || 50))}`],
        ['Retention', `${escapeHtml(String(config.retention_days || 0))} days`],
        ['Max Correlation Age', `${escapeHtml(String(config.max_correlation_age_minutes || 10))} minutes`],
        ['Correlation Check', `${escapeHtml(String(config.correlation_check_interval || 120))} seconds`],
        ['Timezone', escapeHtml(config.timezone || 'N/A')],
        ['Log Level', escapeHtml(config.log_level || 'INFO')],
        ['Blacklist', config.blacklist_enabled ? `Enabled (${escapeHtml(String(config.blacklist_count))} emails)` : 'Disabled'],
        ['Scheduler Workers', `${escapeHtml(String(config.scheduler_workers || 4))}`],
    ];

    const editing = !!(data.settings_edit_via_ui_enabled && data.editable_config);
    content.innerHTML = `
        ${!data.settings_edit_via_ui_enabled ? `<div class="ui-list-note ui-flush">${uiLocked('Editing settings is off',
            'These values come from the environment and are shown read-only. To change them here, set <code>SETTINGS_EDIT_VIA_UI_ENABLED=true</code> in <code>.env</code> and run <code>docker compose up -d</code>. A restart does not read <code>.env</code> again.', '')}</div>` : ''}

        ${!data.settings_edit_via_ui_enabled ? `
        <section class="ui-panel">
            <div class="ui-panel-head">Runtime</div>
            <div class="ui-md-ids ui-set-facts">
                ${readOnlyFacts.map(([label, value]) => `<div class="ui-md-fact"><span>${label}</span><div>${value}</div></div>`).join('')}
                ${Object.keys(CREDENTIAL_CHECKS).map(name => `<div class="ui-md-fact"><span>${CREDENTIAL_CHECKS[name].label}</span>${credentialCheckFact(name, config[name + '_status'], '')}</div>`).join('')}
                <div class="ui-md-fact"><span>MaxMind Status</span>
                    <div class="ui-chip-row">
                        <span id="maxmind-license-status">${renderMaxMindStatus(data.configuration.maxmind_status)}</span>
                        ${data.geoip_configuration ? renderGeoIPDbStatus(data.geoip_configuration) : ''}
                        ${maxmindValidateButton(data.geoip_configuration)}
                    </div>
                </div>
            </div>
        </section>
        ` : ''}

        ${data.settings_edit_via_ui_enabled && data.editable_config ? (function () {
            const sensitiveKeys = SETTINGS_SENSITIVE_KEYS;
            const envLockedKeys = new Set(data.env_locked_keys || []);
            const defaults = data.default_config || {};
            const allAssignedKeys = new Set(SETTINGS_EDIT_TABS.flatMap(function (t) { return (t.groups || []).flatMap(function (g) { return g.keys; }); }));
            const configKeys = Object.keys(data.editable_config);
            const otherKeys = configKeys.filter(function (k) { return !allAssignedKeys.has(k); });
            const tabs = otherKeys.length ? SETTINGS_EDIT_TABS.concat([{ id: 'other', label: 'Other', groups: [{ label: 'Settings', keys: otherKeys }] }]) : SETTINGS_EDIT_TABS;

            // Hide tabs for disabled features
            const filteredTabs = tabs.filter(function (tab) { return !settingsTabOff(tab.id); });

            // A tab is shown only if it's feature-enabled (already in filteredTabs)
            // AND has at least one editable key (maxmind is the exception - it
            // shows status even with no editable keys).
            const tabById = {};
            filteredTabs.forEach(function (t) { tabById[t.id] = t; });
            const isTabVisible = function (tab) {
                if (!tab) return false;
                if (tab.id === 'maxmind') return true;
                return (tab.groups || [])
                    .flatMap(function (g) { return g.keys; })
                    .some(function (k) { return data.editable_config[k] !== undefined; });
            };
            const visibleIds = filteredTabs.filter(isTabVisible).map(function (t) { return t.id; });

            // Group the visible tabs. Groups with none are dropped; any visible
            // tab not assigned to a group is appended to the last group.
            const grouped = SETTINGS_TAB_GROUPS.map(function (g) {
                return { label: g.label, tabs: g.tabs.filter(function (id) { return visibleIds.indexOf(id) !== -1; }) };
            });
            const assignedIds = new Set(SETTINGS_TAB_GROUPS.reduce(function (acc, g) { return acc.concat(g.tabs); }, []));
            const leftover = visibleIds.filter(function (id) { return !assignedIds.has(id); });
            if (leftover.length && grouped.length) {
                grouped[grouped.length - 1].tabs = grouped[grouped.length - 1].tabs.concat(leftover);
            }
            const firstVisibleId = visibleIds.length ? visibleIds[0] : null;

            // Mobile: a single sticky category picker instead of the long list.
            // It stays visible while scrolling, so switching category never
            // means scrolling back to the top.
            let mobileNavHtml = '<div class="settings-mobile-nav">'
                + '<label for="settings-tab-select" class="sr-only">Settings category</label>'
                + '<select id="settings-tab-select" class="ui-select">';
            grouped.forEach(function (group) {
                if (!group.tabs.length) return;
                mobileNavHtml += '<optgroup label="' + escapeHtml(group.label) + '">';
                group.tabs.forEach(function (id) {
                    const tab = tabById[id];
                    if (!tab) return;
                    const selected = id === firstVisibleId ? ' selected' : '';
                    mobileNavHtml += '<option value="' + id + '"' + selected + '>' + escapeHtml(tab.label) + '</option>';
                });
                mobileNavHtml += '</optgroup>';
            });
            mobileNavHtml += '</select></div>';

            // Desktop: grouped category sidebar (the search in the top bar finds a setting)
            let navHtml = '<nav class="settings-edit-nav" aria-label="Settings categories">';
            grouped.forEach(function (group) {
                if (!group.tabs.length) return;
                navHtml += '<div class="ui-set-navgroup"><p>' + escapeHtml(group.label) + '</p><div>';
                group.tabs.forEach(function (id) {
                    const tab = tabById[id];
                    if (!tab) return;
                    // The open category is marked with aria-current (styled in ui.css like the main navigation)
                    const active = id === firstVisibleId ? ' aria-current="true"' : '';
                    navHtml += '<button type="button" class="settings-edit-tab"' + active + ' data-tab="' + id + '">' + escapeHtml(tab.label) + '</button>';
                });
                navHtml += '</div></div>';
            });
            navHtml += '</nav>';

            // Mobile picker sits above the layout so it can stick to the top;
            // on desktop the sidebar sits beside the content.
            let tabsHtml = '';
            filteredTabs.forEach(function (tab, idx) {
                const allKeysInTab = (tab.groups || []).flatMap(function (g) { return g.keys; });
                const keysInTab = allKeysInTab.filter(function (k) { return data.editable_config[k] !== undefined; });
                // Show tab if it has keys OR if it's maxmind tab (which shows status)
                if (keysInTab.length === 0 && tab.id !== 'maxmind') return;
                // The visible panel is the one matching the active sidebar item
                const hidden = ' hidden';
                const desc = '<h2 class="ui-set-title">' + escapeHtml(tab.label) + '</h2>' + (tab.description ? '<p class="ui-set-tabdesc">' + escapeHtml(tab.description) + '</p>' : '');
                tabsHtml += '<div id="settings-tab-panel-' + tab.id + '" class="settings-edit-panel' + hidden + '">' + desc;

                // A small grid of facts at the top of a tab: SMTP, DMARC & TLS IMAP and MaxMind status
                const statusBlock = function (facts) {
                    return '<section class="ui-panel ui-set-group"><h3 class="ui-set-group-title">Status</h3><div class="ui-md-ids ui-set-facts">'
                        + facts.map(function (f) { return '<div class="ui-md-fact"><span>' + f[0] + '</span><div class="ui-chip-row">' + f[1] + '</div></div>'; }).join('')
                        + '</div></section>';
                };
                const onOff = function (on, offTone) { return on ? uiTag('Enabled', 'ok') : uiTag('Disabled', offTone || ''); };

                // The Mailcow tab says whether mailcow accepts the Read-Write key and Rspamd its password
                if (tab.id === 'mailcow') {
                    tabsHtml += '<section class="ui-panel ui-set-group"><h3 class="ui-set-group-title">Status</h3><div class="ui-md-ids ui-set-facts">'
                        + Object.keys(CREDENTIAL_CHECKS).map(function (name) {
                            return '<div class="ui-md-fact"><span>' + CREDENTIAL_CHECKS[name].label + '</span>' + credentialCheckFact(name, config[name + '_status'], '-tab') + '</div>';
                        }).join('')
                        + '</div></section>';
                }

                // Special handling for SMTP tab - add Global SMTP Configuration
                if (tab.id === 'smtp' && data.smtp_configuration) {
                    const facts = [['SMTP Enabled', onOff(data.smtp_configuration.enabled) + '<button type="button" onclick="testSmtpConnection()" class="ui-btn ui-btn-sm">Test SMTP</button>']];
                    if (data.smtp_configuration.enabled) {
                        facts.push(['Server', '<span class="ui-mono">' + escapeHtml(data.smtp_configuration.host) + ':' + escapeHtml(data.smtp_configuration.port) + '</span>']);
                        facts.push(['Admin Email', '<span class="ui-mono">' + escapeHtml(data.smtp_configuration.admin_email || 'N/A') + '</span>']);
                    }
                    tabsHtml += statusBlock(facts);
                }

                // Notifications tab - channel manager (rendered by notifications.js)
                if (tab.id === 'notifications') {
                    tabsHtml += '<section id="notification-channels-panel" class="ui-panel ui-set-channels"></section>';
                }

                // Special handling for the DMARC & TLS IMAP tab - add the report management facts
                if (tab.id === 'dmarc_imap' && data.dmarc_configuration) {
                    const facts = [
                        ['IMAP Auto-Import', onOff(data.dmarc_configuration.imap_sync_enabled) + '<button type="button" onclick="testImapConnection()" class="ui-btn ui-btn-sm">Test IMAP</button>'],
                        ['Manual Upload', onOff(data.dmarc_configuration.manual_upload_enabled, 'fail')]
                    ];
                    if (data.dmarc_configuration.imap_sync_enabled) {
                        facts.push(['IMAP Server', '<span class="ui-mono">' + escapeHtml(data.dmarc_configuration.imap_host || 'N/A') + '</span>']);
                    }
                    tabsHtml += statusBlock(facts);
                }

                // Special handling for MaxMind tab
                if (tab.id === 'maxmind') {
                    const geoipCfg = data.geoip_configuration || {};
                    const dbs = geoipCfg.databases || {};
                    const cityDb = dbs.City || {};
                    const asnDb = dbs.ASN || {};
                    const dbLine = function (name, db) {
                        return db.available
                            ? '<span>' + name + ': ' + escapeHtml(String(db.size_mb)) + 'MB <small class="ui-muted">(' + escapeHtml(String(db.age_days)) + 'd old)</small></span>'
                            : '<span class="ui-muted">' + name + ': Not installed</span>';
                    };
                    tabsHtml += statusBlock([
                        ['License', '<span id="maxmind-license-status-tab">' + renderMaxMindStatus(data.configuration.maxmind_status) + '</span>'
                            + maxmindValidateButton(data.geoip_configuration)],
                        ['Database Health', '<span id="geoip-db-status" class="ui-chip-row">' + (renderGeoIPDbStatus(geoipCfg) || '<span class="ui-muted">Not configured</span>') + '</span>'],
                        ['Databases', (cityDb.available || asnDb.available) ? dbLine('City', cityDb) + dbLine('ASN', asnDb) : '<span class="ui-muted">Not installed</span>']
                    ]);
                }

                // Groups are separated by a rule so a long tab reads as a few
                // small sections instead of one dense wall of fields.
                let renderedGroups = 0;
                (tab.groups || []).forEach(function (group) {
                    const groupKeys = group.keys.filter(function (k) { return data.editable_config[k] !== undefined; });
                    if (groupKeys.length === 0) return;
                    renderedGroups++;
                    tabsHtml += '<section class="ui-panel ui-set-group"' + (group.needs ? ' data-needs="' + escapeHtml(group.needs) + '"' : '') + '><h3 class="ui-set-group-title">' + escapeHtml(group.label) + '</h3>' +
                        (group.intro ? '<p class="ui-set-desc ui-set-group-intro">' + escapeHtml(group.intro) + '</p>' : '') + '<div class="ui-set-grid">';
                    if (group.choice) tabsHtml += settingsBounceChoice(group.choice, data.editable_config, envLockedKeys, defaults);
                    else groupKeys.forEach(function (key) {
                        tabsHtml += renderSettingsEditField(key, data.editable_config[key], sensitiveKeys, SETTINGS_FIELD_DESCRIPTIONS[key] || '', envLockedKeys.has(key), defaults[key]);
                    });
                    tabsHtml += '</div></section>';
                });
                tabsHtml += '</div>';
            });
            return mobileNavHtml + `
        <!-- Edit Configuration (only when SETTINGS_EDIT_VIA_UI_ENABLED) -->
        <div class="settings-edit-layout ui-set-edit">
            ${navHtml}
            <div class="settings-edit-content">
                ${!data.settings_migrated ? `<div class="ui-set-actions" id="settings-edit-actions">
                    <button type="button" id="settings-import-env-btn" class="ui-btn ui-btn-primary">Migrate Settings from ENV</button>
                    <p class="ui-set-migrate-note">Click once to copy your current configuration into the database. After that you can edit the fields below and save.</p>
                </div>` : ''}
                <form id="settings-edit-form" class="ui-set-form">
                    <!-- Until the first migration nothing can be saved, so the fields stay
                         read-only instead of accepting edits that would be lost -->
                    <fieldset class="ui-set-fieldset"${data.settings_migrated ? '' : ' disabled'}>
                    ` + tabsHtml + `
                    </fieldset>
                </form>
            </div>
        </div>
        ${uiSaveBar('settings-savebar', { form: 'settings-edit-form', discard: 'loadSettings()' })}
        `;
        })() : ''}

        ${!data.settings_edit_via_ui_enabled ? `
        <div class="ui-dash-grid ui-status-pair">
            <!-- Global SMTP Configuration -->
            <section class="ui-panel">
                <div class="ui-panel-head">Global SMTP Configuration
                    <button type="button" onclick="testSmtpConnection()" class="ui-btn ui-btn-sm ui-head-actions">Test SMTP</button></div>
                <div class="ui-kv"><span>SMTP Enabled</span><b>${data.smtp_configuration?.enabled ? uiTag('Enabled', 'ok') : uiTag('Disabled', '')}</b></div>
                ${data.smtp_configuration?.enabled ? `
                <div class="ui-kv"><span>Server</span><b class="ui-mono ui-kv-small">${escapeHtml(String(data.smtp_configuration.host))}:${escapeHtml(String(data.smtp_configuration.port))}</b></div>
                <div class="ui-kv"><span>Admin Email</span><b class="ui-mono ui-kv-small">${escapeHtml(data.smtp_configuration.admin_email || 'N/A')}</b></div>
                ` : ''}
            </section>

            <!-- DMARC & TLS report management -->
            <section class="ui-panel">
                <div class="ui-panel-head">DMARC &amp; TLS Reports
                    <button type="button" onclick="testImapConnection()" class="ui-btn ui-btn-sm ui-head-actions">Test IMAP</button></div>
                <div class="ui-kv"><span>IMAP Auto-Import</span><b>${data.dmarc_configuration?.imap_sync_enabled ? uiTag('Enabled', 'ok') : uiTag('Disabled', '')}</b></div>
                <div class="ui-kv"><span>Manual Upload</span><b>${data.dmarc_configuration?.manual_upload_enabled ? uiTag('Enabled', 'ok') : uiTag('Disabled', 'fail')}</b></div>
                ${data.dmarc_configuration?.imap_sync_enabled ? `<div class="ui-kv"><span>IMAP Server</span><b class="ui-mono ui-kv-small">${escapeHtml(data.dmarc_configuration.imap_host || 'N/A')}</b></div>` : ''}
            </section>
        </div>
        ` : ''}
    `;

    // Edit configuration: form submit, Import from ENV, and tab switching
    if (data.settings_edit_via_ui_enabled && data.editable_config) {
        // Notification destinations are managed outside the settings form
        if (typeof loadNotificationChannels === 'function') {
            loadNotificationChannels();
        }

        // Switching is shared by the desktop sidebar and the mobile picker, so
        // the two can never disagree about which category is open.
        const switchSettingsTab = function (tabId, scrollToTop) {
            settingsTab = tabId;
            if (typeof routerSyncSubpage === 'function') routerSyncSubpage('settings', tabId);
            content.querySelectorAll('.settings-edit-tab').forEach(function (b) {
                const isActive = b.getAttribute('data-tab') === tabId;
                if (isActive) b.setAttribute('aria-current', 'true');
                else b.removeAttribute('aria-current');
            });
            content.querySelectorAll('.settings-edit-panel').forEach(function (panel) {
                panel.classList.add('hidden');
            });
            const panel = content.querySelector('#settings-tab-panel-' + tabId);
            if (panel) panel.classList.remove('hidden');

            const select = content.querySelector('#settings-tab-select');
            if (select && select.value !== tabId) select.value = tabId;

            // A newly opened category starts at its top, not where the last one was scrolled to
            if (scrollToTop && window.matchMedia('(max-width: 1023px)').matches) {
                // On mobile, bring the sticky picker back to the top of the viewport.
                // Scroll the page's own area only: scrollIntoView also scrolled the
                // app frame, which hid the top bar
                const anchor = content.querySelector('.settings-mobile-nav');
                let scroller = anchor && anchor.parentElement;
                while (scroller && !/(auto|scroll)/.test(getComputedStyle(scroller).overflowY)) scroller = scroller.parentElement;
                if (anchor && panel && scroller) {
                    const target = panel.getBoundingClientRect().top - scroller.getBoundingClientRect().top + scroller.scrollTop - anchor.offsetHeight - 8;
                    if (target < scroller.scrollTop) scroller.scrollTo({ top: Math.max(0, target), behavior: 'smooth' });
                }
            } else if (scrollToTop) {
                // On a wide screen the categories scroll in their own column beside the sidebar
                const column = content.querySelector('.settings-edit-content');
                if (column && column.scrollTop > 0) column.scrollTo({ top: 0 });
            }
        };

        content.querySelectorAll('.settings-edit-tab').forEach(function (btn) {
            btn.addEventListener('click', function () {
                switchSettingsTab(btn.getAttribute('data-tab'), true);
            });
        });

        // The section the address names (/settings/notifications), or the first one
        window.settingsShowTab = id => switchSettingsTab(id, false);
        const firstTabBtn = content.querySelector('.settings-edit-tab');
        settingsFirstTab = firstTabBtn ? firstTabBtn.getAttribute('data-tab') : null;
        if (settingsTab && content.querySelector('#settings-tab-panel-' + CSS.escape(settingsTab))) {
            switchSettingsTab(settingsTab, false);
        } else if (settingsFirstTab) {
            const named = settingsTab;
            settingsTab = settingsFirstTab;
            if (named && typeof routerSyncSubpage === 'function') routerSyncSubpage('settings', settingsFirstTab, true);
            switchSettingsTab(settingsFirstTab, false);
        }

        const tabSelect = content.querySelector('#settings-tab-select');
        if (tabSelect) {
            tabSelect.addEventListener('change', function () {
                switchSettingsTab(tabSelect.value, true);
            });
        }

        // Clear/Reset button handlers
        content.querySelectorAll('.settings-clear-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                const key = btn.getAttribute('data-key');
                const defaultVal = btn.getAttribute('data-default');
                const isSensitive = btn.getAttribute('data-sensitive') === 'true';
                const isBool = btn.getAttribute('data-isbool') === 'true';
                const el = content.querySelector('[name="' + CSS.escape(key) + '"]');
                if (!el) return;
                if (isBool) {
                    el.checked = defaultVal === 'true';
                } else if (isSensitive) {
                    el.value = '';
                    el.type = 'text'; // Show cleared field
                } else {
                    el.value = defaultVal || '';
                    // A segmented control shows the value with its pressed button
                    const seg = el.parentElement && el.parentElement.querySelector('.ui-seg');
                    if (seg) seg.querySelectorAll('button').forEach(b => b.setAttribute('aria-pressed', String(b.getAttribute('data-value') === el.value)));
                    // So does the Time Zone picker
                    if (key === 'tz') settingsShowZone(el);
                }
                // The field is back at its default, so it is no longer marked as changed
                const parent = el.closest('.ui-set-bool, .ui-set-field');
                if (parent) parent.classList.remove('is-changed');
                el.classList.remove('is-changed');
                // Remove the clear button itself
                btn.remove();
            });
        });

        // Raw Logs Services checkboxes - sync checked values to hidden input
        content.querySelectorAll('.raw-logs-service-cb').forEach(function(cb) {
            cb.addEventListener('change', function() {
                const allCbs = content.querySelectorAll('.raw-logs-service-cb');
                const selected = [];
                allCbs.forEach(function(c) { if (c.checked) selected.push(c.getAttribute('data-service')); });
                const row = cb.closest('.ui-feature');
                if (row) { row.classList.toggle('is-on', cb.checked); row.classList.toggle('is-off', !cb.checked); }
                const hiddenInput = content.querySelector('#edit-raw_logs_services');
                if (hiddenInput) hiddenInput.value = selected.join(',');
            });
        });

        const form = content.querySelector('#settings-edit-form');
        const importBtn = content.querySelector('#settings-import-env-btn');

        // Unsaved changes: compare every field with the value it loaded with. The
        // bounce choices' radios (data-choice) only set other fields, so they are not counted
        const fieldValue = el => el.type === 'checkbox' ? String(el.checked) : el.value;
        const initialValues = new Map();
        if (form) form.querySelectorAll('[name]:not([data-choice])').forEach(el => initialValues.set(el.name, fieldValue(el)));
        const updateDirty = () => {
            if (!form) return;
            const dirty = new Set();
            form.querySelectorAll('[name]:not([data-choice])').forEach(el => {
                if (initialValues.has(el.name) && initialValues.get(el.name) !== fieldValue(el)) dirty.add(el.name);
            });
            uiSaveBarUpdate('settings-savebar', dirty.size);
            // Mark the sections that hold a change
            content.querySelectorAll('.settings-edit-tab').forEach(tabBtn => {
                const panel = content.querySelector('#settings-tab-panel-' + tabBtn.getAttribute('data-tab'));
                const has = !!panel && [...panel.querySelectorAll('[name]')].some(el => dirty.has(el.name));
                tabBtn.classList.toggle('has-changes', has);
            });
        };
        if (form) {
            form.addEventListener('input', updateDirty);
            form.addEventListener('change', updateDirty);
            // An Outbound choice says when it needs the read-write key, and
            // whether it differs from the default, also after typing in its number fields
            const showChoices = () => content.querySelectorAll('.ui-set-choice').forEach(settingsShowChoice);
            showChoices();
            form.addEventListener('input', showChoices);
            settingsShowNeeds(content);
            settingsApplySync(false);
            form.addEventListener('change', event => {
                if (event.target && event.target.id === 'edit-suppression_rspamd_sync') settingsApplySync(true);
                settingsShowNeeds(content);
            });
            // Clearing and resetting change a field without an input event
            content.querySelectorAll('.settings-clear-btn').forEach(btn => btn.addEventListener('click', () => setTimeout(() => { updateDirty(); settingsShowNeeds(content); })));
        }

        if (form) {
            form.onsubmit = async (e) => {
                e.preventDefault();
                const payload = {};
                const sensitiveKeys = SETTINGS_SENSITIVE_KEYS;
                for (const key of Object.keys(data.editable_config)) {
                    const el = form.querySelector('[name="' + CSS.escape(key) + '"]');
                    if (!el) continue;
                    if (el.type === 'checkbox') {
                        payload[key] = el.checked;
                    } else {
                        const val = el.value;
                        // For sensitive keys: skip only if still masked (unchanged), send empty string if cleared
                        if (sensitiveKeys.includes(key) && val === '********') continue;
                        if (typeof data.editable_config[key] === 'number') payload[key] = val === '' ? 0 : Number(val);
                        else payload[key] = val === '' ? '' : val;
                    }
                }

                // ── Basic Auth lockout prevention ──────────────────────────
                // Detect if basic_auth_enabled is being turned ON
                const wasBasicAuthEnabled = data.editable_config.basic_auth_enabled === true ||
                    (data.configuration && data.configuration.basic_auth_enabled === true);
                const isEnablingBasicAuth = payload.basic_auth_enabled === true && !wasBasicAuthEnabled;

                if (isEnablingBasicAuth) {
                    // Check that password is set (not empty and not masked-unchanged)
                    const passwordEl = form.querySelector('[name="auth_password"]');
                    const passwordVal = passwordEl ? passwordEl.value : '';
                    if (!passwordVal || passwordVal === '********' && !data.editable_config.auth_password) {
                        showToast('Cannot enable Basic Auth without a password. Please set a password first.', 'error');
                        return;
                    }

                    // Show verification modal and wait for user input
                    const verified = await showBasicAuthVerifyModal();
                    if (!verified) return; // User cancelled

                    // Add verification credentials to payload
                    payload.verify_username = verified.username;
                    payload.verify_password = verified.password;
                }
                // ──────────────────────────────────────────────────────────

                // ── Feature disable confirmation ─────────────────────────
                // Detect if any features are being newly disabled
                const PURGEABLE_FEATURES = ['netfilter', 'domains', 'dmarc', 'mailbox-stats', 'logs', 'blacklist', 'suppressions', 'quarantine', 'devices'];
                // Rate Limits has no purge call, but the save itself deletes its reset history
                const CONFIRM_FEATURES = [...PURGEABLE_FEATURES, 'rate-limits'];
                let newlyDisabledFeatures = [];
                let featuresChanged = false;
                if ('disabled_features' in payload) {
                    const oldDisabled = new Set(
                        (window.disabledFeatures || []).map(s => s.trim().toLowerCase())
                    );
                    const newDisabled = new Set(
                        (payload.disabled_features || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
                    );
                    newlyDisabledFeatures = [...newDisabled].filter(f => !oldDisabled.has(f));
                    featuresChanged = newlyDisabledFeatures.length > 0 || [...oldDisabled].some(f => !newDisabled.has(f));

                    // Show confirmation modal if any feature with stored data is being disabled
                    const confirmNewlyDisabled = newlyDisabledFeatures.filter(f => CONFIRM_FEATURES.includes(f));
                    if (confirmNewlyDisabled.length > 0) {
                        const confirmed = await showFeatureDisableConfirmModal(confirmNewlyDisabled);
                        if (!confirmed) return; // User cancelled
                    }
                }
                // ──────────────────────────────────────────────────────────

                // The app's Rspamd blocks when the sync goes off or on
                const newDisabledSet = new Set('disabled_features' in payload
                    ? (payload.disabled_features || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
                    : (window.disabledFeatures || []).map(s => s.trim().toLowerCase()));
                const rspamdPlan = await settingsRspamdTransition(payload, data, newDisabledSet);
                if (rspamdPlan === null) return;
                if (rspamdPlan.action === 'fresh') {
                    try {
                        const res = await authenticatedFetch('/api/suppressions/start-fresh', { method: 'POST' });
                        if (!res.ok) {
                            const body = await res.json().catch(() => ({}));
                            showToast(`Sync with Rspamd is still off. ${settingsErrorText(body, res.statusText)}`, 'error');
                            return;
                        }
                    } catch (freshErr) {
                        showToast(`Sync with Rspamd is still off. Rspamd could not be reached: ${freshErr.message || freshErr}`, 'error');
                        return;
                    }
                }

                try {
                    uiSaveBarBusy('settings-savebar', true);
                    const res = await authenticatedFetch('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
                    if (!res.ok) {
                        const err = await res.json().catch(() => ({}));
                        throw new Error(err.detail || res.statusText);
                    }
                    const saved = await res.json().catch(() => ({}));
                    uiSaveBarBusy('settings-savebar', false);
                    // A new or changed Read-Write key or Rspamd password is checked right away;
                    // a failure is the answer to show, so it wins over a success
                    let checkToast = null;
                    for (const name of Object.keys(CREDENTIAL_CHECKS)) {
                        if (!saved[name + '_changed']) continue;
                        const toast = await validateCredential(name);
                        if (toast && !(checkToast && checkToast[1] === 'error')) checkToast = toast;
                    }
                    // What happened to the app's Rspamd blocks is the answer to show for this save
                    let rspamdToast;
                    try {
                        rspamdToast = await settingsRspamdAfterSave(rspamdPlan, saved);
                    } catch (rspamdErr) {
                        rspamdToast = [`Settings saved, but Rspamd could not be reached: ${rspamdErr.message || rspamdErr}`, 'error'];
                    }
                    if (rspamdToast && !(checkToast && checkToast[1] === 'error')) checkToast = rspamdToast;
                    // The list of Suppressions (or a sync) turned off could not be deleted yet:
                    // the sweep the save started tries again
                    if (saved.feature_data_errors && saved.feature_data_errors['suppressions']) {
                        const listText = 'The saved suppression list could not be deleted yet. It is tried again in a few minutes.';
                        checkToast = checkToast && checkToast[1] === 'error'
                            ? [`${checkToast[0]} ${listText}`, 'error'] : [`Settings saved, but the saved suppression list could not be deleted yet. It is tried again in a few minutes.`, 'error'];
                    }
                    if (checkToast) showToast(...checkToast);
                    if (isEnablingBasicAuth) {
                        showToast('Basic Auth enabled successfully! You will need to log in on your next visit.', 'success');
                    }
                    
                    // Detect if MaxMind credentials were changed - show setup modal
                    const _maxmindChanged = ('maxmind_account_id' in payload || 'maxmind_license_key' in payload);
                    if (_maxmindChanged) _cachedMaxMindStatus = null; // Clear stale validation cache
                    const _maxmindHasValues = (payload.maxmind_license_key && payload.maxmind_license_key !== '' && payload.maxmind_license_key !== '********');
                    // The rest of the app reads features, title, logo, sign-in and the mailcow
                    // address once, when the page loads: a change to one of them reloads it.
                    // Any other save refreshes Settings in place.
                    const shellChanged = SETTINGS_READ_AT_PAGE_LOAD.some(key =>
                        key in payload && String(payload[key] ?? '') !== String(data.editable_config[key] ?? ''));
                    const needsReload = featuresChanged || shellChanged;
                    if (needsReload) {
                        const purgeableNewlyDisabled = newlyDisabledFeatures.filter(f => PURGEABLE_FEATURES.includes(f));
                        if (purgeableNewlyDisabled.length > 0) {
                            showToast(`Purging data for ${purgeableNewlyDisabled.length} disabled feature(s)...`, 'info');
                            for (const feature of purgeableNewlyDisabled) {
                                // The suppression list goes with what was chosen for its Rspamd blocks.
                                // Removing belongs to this save: one that did not turn Suppressions
                                // off (another window did first) removes nothing
                                const wanted = rspamdPlan.purge_rspamd || (rspamdPlan.action === 'remove' ? 'remove' : 'keep');
                                const transition = saved.rspamd_off_transition || null;
                                const notOurs = wanted === 'remove' && !transition;
                                const body = feature === 'suppressions'
                                    ? { feature, rspamd: notOurs ? 'keep' : wanted, transition } : { feature };
                                let failed = null;
                                try {
                                    const res = await authenticatedFetch('/api/settings/purge-feature-data', {
                                        method: 'POST',
                                        headers: { 'Content-Type': 'application/json' },
                                        body: JSON.stringify(body)
                                    });
                                    if (!res.ok) failed = settingsErrorText(await res.json().catch(() => ({})), res.statusText);
                                } catch (purgeErr) {
                                    failed = purgeErr.message || String(purgeErr);
                                }
                                if (feature === 'suppressions') {
                                    const toast = notOurs && rspamdPlan.action === 'remove' && !failed
                                        ? ['Suppressions were already off (changed in another window). The saved list was deleted; nothing was removed from Rspamd.', 'error']
                                        : failed
                                        ? [rspamdPlan.action === 'remove'
                                            ? `Suppressions are off. The saved list was deleted, but this app's Rspamd blocks could not be removed: ${failed}`
                                            : 'Suppressions are off, but the saved list could not be deleted. Try again.', 'error']
                                        : [rspamdPlan.action === 'remove' ? "Suppressions are off. The saved list and this app's Rspamd blocks were removed."
                                            : rspamdPlan.action === 'keep' ? 'Suppressions are off. The saved list was deleted. Existing Rspamd blocks were kept.'
                                            : 'Suppressions are off. The saved list was deleted.', 'success'];
                                    if (toast[1] === 'error' || !(checkToast && checkToast[1] === 'error')) checkToast = toast;
                                } else if (failed) {
                                    checkToast = [`The data of ${feature} could not be deleted. Try again.`, 'error'];
                                }
                            }
                        }

                        // The credential check's answer is shown again after the reload
                        if (checkToast) {
                            try { sessionStorage.setItem(SETTINGS_TOAST_AFTER_RELOAD, JSON.stringify(checkToast)); } catch (e) { /* private mode: the status tag still shows it */ }
                        }
                    }

                    if (_maxmindChanged && _maxmindHasValues) {
                        // The form reloads now, so the save bar clears behind the window. On
                        // close the window shows the new GeoIP status, or reloads the page when
                        // the same save changed what the page reads at load.
                        showGeoIPSetupModal(needsReload);
                        await loadSettings();
                        return;
                    }

                    if (needsReload) {
                        showToast(featuresChanged ? 'Features updated - reloading...' : 'Settings saved - reloading...', 'success');
                        setTimeout(() => location.reload(), 600);
                        return;
                    }

                    if (!checkToast && !isEnablingBasicAuth) showToast('Settings saved', 'success');
                    await loadSettings();
                } catch (err) {
                    uiSaveBarBusy('settings-savebar', false);
                    showToast('Failed to save: ' + (err.message || err), 'error');
                }
            };
        }
        if (importBtn) {
            importBtn.onclick = async () => {
                if (!await showConfirmModal({ title: 'Import from ENV', message: 'Import current configuration from ENV into DB? This will overwrite existing DB-stored values.', confirmText: 'Import' })) return;
                try {
                    importBtn.disabled = true;
                    const res = await authenticatedFetch('/api/settings/import-from-env', { method: 'POST' });
                    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText);
                    const result = await res.json();
                    if (result.env_locked_keys) {
                        data.env_locked_keys = result.env_locked_keys;
                    }
                    await loadSettings();
                } catch (err) {
                    alert('Import failed: ' + (err.message || err));
                } finally {
                    importBtn.disabled = false;
                }
            };
        }
    }
}

// reloadPage: reload the whole page on close instead of only Settings
async function showGeoIPSetupModal(reloadPage = false) {
    // Create modal overlay
    const overlay = document.createElement('div');
    overlay.id = 'geoip-setup-overlay';
    overlay.className = 'ui-dialog-backdrop';
    overlay.style.animation = 'fadeIn 0.2s ease-out';
    
    overlay.innerHTML = `
        <div class="ui-dialog ui-dialog-fit ui-dialog-sm">
            <div class="ui-dialog-head">
                <h3>
                    <svg class="w-5 h-5 ui-text-info" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                    GeoIP Database Setup
                </h3>
            </div>
            <div class="ui-dialog-body ui-geo-steps" id="geoip-setup-steps">
                <div id="geoip-step-1" class="ui-geo-step">
                    <div id="geoip-step-1-icon" class="ui-geo-icon">
                        <svg class="w-5 h-5 ui-text-info animate-spin" fill="none" viewBox="0 0 24 24">
                            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                        </svg>
                    </div>
                    <div>
                        <p class="ui-geo-title">Checking credentials</p>
                        <p id="geoip-step-1-detail" class="ui-set-desc">Verifying MaxMind configuration</p>
                    </div>
                </div>
                <div id="geoip-step-2" class="ui-geo-step opacity-40">
                    <div id="geoip-step-2-icon" class="ui-geo-icon">
                        <div class="ui-geo-pending"></div>
                    </div>
                    <div>
                        <p class="ui-geo-title">Download databases</p>
                        <p id="geoip-step-2-detail" class="ui-set-desc">Waiting...</p>
                        <div id="geoip-progress-bar" class="hidden ui-meter ui-meter-info ui-geo-bar">
                            <i id="geoip-progress-fill" style="width: 0%"></i>
                        </div>
                    </div>
                </div>
                <div id="geoip-step-3" class="ui-geo-step opacity-40">
                    <div id="geoip-step-3-icon" class="ui-geo-icon">
                        <div class="ui-geo-pending"></div>
                    </div>
                    <div>
                        <p class="ui-geo-title">Validate database integrity</p>
                        <p id="geoip-step-3-detail" class="ui-set-desc">Waiting...</p>
                    </div>
                </div>
            </div>
            <div class="ui-dialog-foot">
                <button id="geoip-setup-close-btn" class="ui-btn" disabled>
                    Close
                </button>
            </div>
        </div>
    `;
    
    document.body.appendChild(overlay);
    
    const closeBtn = document.getElementById('geoip-setup-close-btn');
    closeBtn.addEventListener('click', async () => {
        overlay.remove();
        if (reloadPage) {
            location.reload();
            return;
        }
        await loadSettings();
    });
    
    const setStepStatus = (step, status, detail) => {
        const iconEl = document.getElementById(`geoip-step-${step}-icon`);
        const stepEl = document.getElementById(`geoip-step-${step}`);
        const detailEl = document.getElementById(`geoip-step-${step}-detail`);
        
        stepEl.classList.remove('opacity-40');
        if (detail) detailEl.textContent = detail;
        
        if (status === 'running') {
            iconEl.innerHTML = '<svg class="w-5 h-5 ui-text-info animate-spin" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path></svg>';
        } else if (status === 'success') {
            iconEl.innerHTML = '<svg class="w-5 h-5 ui-text-ok" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path></svg>';
        } else if (status === 'error') {
            iconEl.innerHTML = '<svg class="w-5 h-5 ui-text-fail" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path></svg>';
        } else if (status === 'skipped') {
            iconEl.innerHTML = '<svg class="w-5 h-5 ui-muted" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-11a1 1 0 10-2 0v3.586L7.707 9.293a1 1 0 00-1.414 1.414l3 3a1 1 0 001.414 0l3-3a1 1 0 00-1.414-1.414L11 10.586V7z" clip-rule="evenodd"></path></svg>';
        }
    };
    
    try {
        // ── Step 1: Verify credentials are configured ──
        const credRes = await authenticatedFetch('/api/settings/geoip/status');
        if (!credRes.ok) throw new Error('Failed to check status');
        const credStatus = await credRes.json();
        
        if (credStatus.configured) {
            // Validate the license key (stores result server-side for future page loads)
            const valLicRes = await authenticatedFetch('/api/settings/maxmind/validate', { method: 'POST' });
            const valLicData = valLicRes.ok ? await valLicRes.json() : null;
            
            if (valLicData && valLicData.valid) {
                _cachedMaxMindStatus = valLicData;
                setStepStatus(1, 'success', 'Credentials configured');
            } else if (valLicData && valLicData.error) {
                _cachedMaxMindStatus = valLicData;
                setStepStatus(1, 'error', 'License validation failed: ' + valLicData.error);
                closeBtn.disabled = false;
                return;
            } else {
                setStepStatus(1, 'success', 'Credentials configured');
            }
        } else {
            setStepStatus(1, 'error', 'MaxMind Account ID or License Key is missing');
            closeBtn.disabled = false;
            return;
        }
        
        // ── Step 2: Check/Download databases ──
        setStepStatus(2, 'running', 'Checking existing databases...');
        
        const statusRes = await authenticatedFetch('/api/settings/geoip/status');
        const geoipStatus = await statusRes.json();
        const cityAvail = geoipStatus.databases?.City?.available;
        const asnAvail = geoipStatus.databases?.ASN?.available;
        
        if (cityAvail && asnAvail) {
            setStepStatus(2, 'success', 'Databases already installed');
        } else {
            // Need to download
            setStepStatus(2, 'running', 'Downloading GeoIP databases...');
            const progressBar = document.getElementById('geoip-progress-bar');
            const progressFill = document.getElementById('geoip-progress-fill');
            progressBar.classList.remove('hidden');
            
            // Trigger download
            await authenticatedFetch('/api/settings/geoip/download', { method: 'POST' });
            
            // Poll for completion
            let progress = 5;
            progressFill.style.width = progress + '%';
            
            const downloadComplete = await new Promise((resolve) => {
                let polls = 0;
                const interval = setInterval(async () => {
                    polls++;
                    if (polls > 90) { // 90 * 2s = 3 minutes
                        clearInterval(interval);
                        resolve(false);
                        return;
                    }
                    
                    // Animate progress (fake but smooth)
                    progress = Math.min(90, progress + (90 - progress) * 0.08);
                    progressFill.style.width = progress + '%';
                    
                    try {
                        const res = await authenticatedFetch('/api/settings/geoip/status');
                        const st = await res.json();
                        
                        if (st.job_status === 'success') {
                            progressFill.style.width = '100%';
                            clearInterval(interval);
                            setTimeout(() => resolve(true), 400);
                        } else if (st.job_status === 'failed') {
                            clearInterval(interval);
                            resolve(st.job_error || 'Download failed');
                        }
                    } catch (e) { /* continue */ }
                }, 2000);
            });
            
            if (downloadComplete === true) {
                setStepStatus(2, 'success', 'Databases downloaded successfully');
            } else {
                const errMsg = typeof downloadComplete === 'string' ? downloadComplete : 'Download failed - check logs for details';
                // Check if it's a credentials error
                const isCredError = errMsg.toLowerCase().includes('401') || errMsg.toLowerCase().includes('unauthorized') || errMsg.toLowerCase().includes('invalid');
                if (isCredError) {
                    setStepStatus(1, 'error', 'Invalid credentials - download rejected by MaxMind');
                }
                setStepStatus(2, 'error', errMsg);
                closeBtn.disabled = false;
                return;
            }
        }
        
        // ── Step 3: Validate DB integrity ──
        setStepStatus(3, 'running', 'Running test queries...');
        
        const valRes = await authenticatedFetch('/api/settings/geoip/validate', { method: 'POST' });
        const valData = await valRes.json();
        
        if (valData.valid) {
            setStepStatus(3, 'success', 'Database integrity verified - GeoIP is ready');
        } else {
            setStepStatus(3, 'error', valData.error || 'Validation failed - database may be corrupt');
        }
        
    } catch (err) {
        console.error('GeoIP setup error:', err);
    }
    
    closeBtn.disabled = false;
}

// Cache last MaxMind validation result so re-renders don't lose it
var _cachedMaxMindStatus = null;

async function validateMaxMindLicense() {
    // Show checking state on all MaxMind status badges
    const checkingHtml = `
        <span class="ui-tag ui-tag-info">
            <svg class="w-3 h-3 mr-1 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
            </svg>
            Checking…
        </span>
    `;
    ['maxmind-license-status', 'maxmind-license-status-tab'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = checkingHtml;
    });

    try {
        const response = await authenticatedFetch('/api/settings/maxmind/validate', { method: 'POST' });
        const result = response.ok ? await response.json() : { configured: true, valid: false, error: 'Request failed' };
        
        // Cache the result so re-renders preserve it
        _cachedMaxMindStatus = result;

        const statusHtml = renderMaxMindStatus(result);
        ['maxmind-license-status', 'maxmind-license-status-tab'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.innerHTML = statusHtml;
        });

        if (result.valid) {
            showToast('MaxMind license is valid', 'success');
        } else if (result.error) {
            showToast('MaxMind license validation failed: ' + result.error, 'error');
        }
    } catch (error) {
        console.error('Failed to validate MaxMind license:', error);
        const errorHtml = renderMaxMindStatus({ configured: true, valid: false, error: 'Connection error' });
        ['maxmind-license-status', 'maxmind-license-status-tab'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.innerHTML = errorHtml;
        });
        showToast('Failed to validate MaxMind license', 'error');
    }
}

async function repairGeoIPDatabase() {
    const statusEl = document.getElementById('geoip-db-status');
    if (statusEl) {
        statusEl.innerHTML = `
            <span class="ui-tag ui-tag-info">
                <svg class="w-3 h-3 mr-1 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                </svg>
                Repairing…
            </span>
        `;
    }

    try {
        // Step 1: Trigger re-download of databases
        const downloadRes = await authenticatedFetch('/api/settings/geoip/download', { method: 'POST' });
        if (!downloadRes.ok) {
            throw new Error('Failed to start download');
        }

        showToast('GeoIP database re-download started…', 'info');

        // Step 2: Poll geoip/status until download completes (max 60s)
        let attempts = 0;
        const maxAttempts = 30;
        const pollInterval = 2000;
        
        const pollStatus = async () => {
            attempts++;
            try {
                const statusRes = await authenticatedFetch('/api/settings/geoip/status');
                if (statusRes.ok) {
                    const data = await statusRes.json();
                    if (data.job_status === 'idle' && attempts > 2) {
                        // Download finished - now validate
                        const validateRes = await authenticatedFetch('/api/settings/geoip/validate', { method: 'POST' });
                        if (validateRes.ok) {
                            const result = await validateRes.json();
                            if (statusEl) {
                                const cfg = { db_valid: result.valid, databases: data.databases };
                                statusEl.innerHTML = renderGeoIPDbStatus(cfg);
                            }
                            if (result.valid) {
                                showToast('GeoIP databases repaired successfully', 'success');
                            } else {
                                showToast('GeoIP databases re-downloaded but validation still failed', 'error');
                            }
                        }
                        return;
                    }
                }
            } catch (e) {
                console.error('Poll error:', e);
            }
            
            if (attempts < maxAttempts) {
                setTimeout(pollStatus, pollInterval);
            } else {
                showToast('GeoIP repair timed out - check Status page for progress', 'warning');
                if (statusEl) {
                    statusEl.innerHTML = '<span class="text-xs text-gray-500">Check Status page</span>';
                }
            }
        };

        setTimeout(pollStatus, pollInterval);

    } catch (error) {
        console.error('Failed to repair GeoIP databases:', error);
        showToast('Failed to repair GeoIP databases: ' + error.message, 'error');
        if (statusEl) {
            statusEl.innerHTML = renderGeoIPDbStatus({ db_valid: false });
        }
    }
}

// Credentials checked against their server, changing nothing there. Each
// failure says what it means and what to do about it.
const CREDENTIAL_CHECKS = {
    mailcow_rw_key: {
        label: 'Read-Write API Key',
        endpoint: '/api/settings/mailcow/rw-key/validate',
        missing: 'Add a Read-Write API key first',
        accepted: 'mailcow accepted the Read-Write API key',
        errors: {
            rejected: ['Rejected', 'mailcow rejected the Read-Write API key. Check in mailcow under System → Configuration → Access → Administrators → API that the key is correct and active, and that the IP address of this server is allowed.'],
            read_only: ['Read-only key', 'This is a read-only API key. Paste the Read-Write key from System → Configuration → Access → Administrators → API in mailcow.'],
            connection: ['Connection error', 'Could not reach mailcow to check the Read-Write API key. Check the mailcow URL and try again.'],
            unexpected: ['Unexpected answer', 'mailcow gave an unexpected answer when checking the Read-Write API key. Check the mailcow URL and the application logs.']
        }
    },
    rspamd_password: {
        label: 'Rspamd Password',
        endpoint: '/api/settings/rspamd/password/validate',
        missing: 'Add the Rspamd password first',
        accepted: 'Rspamd accepted the password',
        errors: {
            rejected: ['Rejected', 'Rspamd rejected the password. Use the Rspamd UI password set in mailcow under System → Configuration → Access → Rspamd UI.'],
            redirected: ['Redirected', 'A proxy answered before Rspamd could check the password. Set the Rspamd URL to reach Rspamd directly, for example http://rspamd-mailcow:11334.'],
            connection: ['Connection error', 'Could not reach Rspamd to check the password. Check the Rspamd URL, or the mailcow URL when it is empty, and try again.'],
            unexpected: ['Unexpected answer', 'Rspamd gave an unexpected answer when checking the password. Check the Rspamd URL and the application logs.']
        }
    }
};

function credentialCheckError(name, status) {
    const errors = CREDENTIAL_CHECKS[name].errors;
    return errors[status && status.error] || errors.unexpected;
}

function renderCredentialStatus(name, status) {
    if (status === null || status === undefined) return uiTag('Not checked', '');
    if (!status.configured) return uiTag('Not configured', '');
    if (status.valid) return uiTag('Accepted', 'ok');
    const known = credentialCheckError(name, status);
    return `<span title="${escapeHtml(known[1])}">${uiTag(known[0], 'fail')}</span>`;
}

function credentialCheckedAt(status) {
    if (!status || status.configured === false) return '';
    return status.checked_at ? 'Checked ' + escapeHtml(formatTime(status.checked_at)) : 'Not checked yet';
}

// Validate needs the credential; without it the button stays, disabled, and says so
function credentialValidateButton(name, status) {
    return status && status.configured === false
        ? `<button type="button" class="ui-btn ui-btn-sm" disabled title="${escapeHtml(CREDENTIAL_CHECKS[name].missing)}">Validate</button>`
        : `<button type="button" onclick="validateCredential('${name}', true)" class="ui-btn ui-btn-sm">Validate</button>`;
}

// One fact: the status tag, Validate, and when it was last checked. The ids
// carry a suffix because the read-only facts and the Mailcow tab both show it.
function credentialCheckFact(name, status, suffix) {
    const id = 'credential-' + name + suffix;
    return `<div class="ui-chip-row"><span id="${id}-status">${renderCredentialStatus(name, status)}</span>${credentialValidateButton(name, status)}</div>`
        + `<span id="${id}-checked" class="ui-md-sub">${credentialCheckedAt(status)}</span>`;
}

// Run one check and show its result; returns the toast it calls for, and shows it when asked
async function validateCredential(name, toastNow) {
    const check = CREDENTIAL_CHECKS[name];
    const show = (part, html) => ['', '-tab'].forEach(suffix => {
        const el = document.getElementById('credential-' + name + suffix + '-' + part);
        if (el) el.innerHTML = html;
    });
    show('status', uiTag('Checking…', 'info'));
    let result;
    try {
        const response = await authenticatedFetch(check.endpoint, { method: 'POST' });
        result = response.ok ? await response.json() : { configured: true, valid: false, error: 'unexpected' };
    } catch (error) {
        console.error('Failed to check the ' + check.label + ':', error); // nosemgrep: javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring
        result = { configured: true, valid: false, error: 'connection' };
    }
    if (result.stale) {
        // Changed while it was checked: this answer is about the old one, and
        // the check of the new one says what holds now
        show('status', renderCredentialStatus(name, null));
        show('checked', 'Changed while it was checked. Validate again.');
        const toast = [`The ${check.label} changed while it was checked. Validate it again.`, 'info'];
        if (toastNow) showToast(...toast);
        return null;
    }
    show('status', renderCredentialStatus(name, result));
    show('checked', credentialCheckedAt(result.configured ? { ...result, checked_at: new Date().toISOString() } : result));
    if (!result.configured) return null;
    const toast = result.valid ? [check.accepted, 'success'] : [credentialCheckError(name, result)[1], 'error'];
    if (toastNow) showToast(...toast);
    return toast;
}

// Settings the rest of the app reads once, when the page loads (from /api/info; the
// time zone is one of them); saving a change to one reloads the page so it takes effect everywhere
const SETTINGS_READ_AT_PAGE_LOAD = ['app_title', 'app_logo_url', 'basic_auth_enabled', 'oauth2_enabled', 'mailcow_url', 'tz'];

// A toast that has to outlive the reload after saving (a credential check)
const SETTINGS_TOAST_AFTER_RELOAD = 'settingsToastAfterReload';

function showSettingsToastAfterReload() {
    let toast = null;
    try {
        toast = JSON.parse(sessionStorage.getItem(SETTINGS_TOAST_AFTER_RELOAD) || 'null');
        sessionStorage.removeItem(SETTINGS_TOAST_AFTER_RELOAD);
    } catch (e) { /* private mode or a bad value: nothing to show */ }
    if (Array.isArray(toast)) showToast(String(toast[0]), toast[1] === 'success' ? 'success' : 'error');
}

function renderMaxMindStatus(status) {
    // null/undefined = not checked yet (user must click 'Validate License')
    if (status === null || status === undefined) return uiTag('Not checked', '');
    if (!status.configured) return uiTag('Not configured', '');
    return status.valid ? uiTag('License Valid', 'ok') : uiTag(status.error || 'Invalid', 'fail');
}

// Validate needs a MaxMind Account ID and License Key; without them the button stays, disabled, and says so
function maxmindValidateButton(geoipConfig) {
    if (!geoipConfig) return '';
    return geoipConfig.enabled
        ? '<button type="button" onclick="validateMaxMindLicense()" class="ui-btn ui-btn-sm">Validate</button>'
        : '<button type="button" class="ui-btn ui-btn-sm" disabled title="Add a MaxMind Account ID and License Key first">Validate</button>';
}

function renderGeoIPDbStatus(geoipConfig) {
    if (!geoipConfig) return '';

    // Don't show DB status if MaxMind is not configured
    if (geoipConfig.enabled === false) return '';

    const dbValid = geoipConfig.db_valid;

    if (dbValid === true) return uiTag('DB Healthy', 'ok');
    if (dbValid === false) {
        return `
            <span id="geoip-db-status" class="ui-chip-row">
                ${uiTag('DB Corrupt', 'fail')}
                <button type="button" onclick="repairGeoIPDatabase()" class="ui-btn ui-btn-sm">Repair</button>
            </span>
        `;
    }
    // null = not checked yet - could be downloading
    const dbs = geoipConfig.databases || {};
    const cityAvail = dbs.City && dbs.City.available;
    return cityAvail ? uiTag('Checking...', '') : uiTag('Downloading...', 'warn');
}

// =============================================================================
// TEST IMAP / SMTP
// =============================================================================

async function testSmtpConnection() {
    showConnectionTestModal('SMTP Connection Test', 'Testing SMTP connection...');

    try {
        const response = await authenticatedFetch('/api/settings/test/smtp', {
            method: 'POST'
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const result = await response.json();

        // Ensure logs is an array
        const logs = result.logs || ['No logs available'];
        updateConnectionTestModal(result.success ? 'success' : 'error', logs);

    } catch (error) {
        updateConnectionTestModal('error', [
            'Failed to test SMTP connection',
            `Error: ${error.message}`
        ]);
    }
}

async function testImapConnection() {
    showConnectionTestModal('IMAP Connection Test', 'Testing IMAP connection...');

    try {
        const response = await authenticatedFetch('/api/settings/test/imap', {
            method: 'POST'
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const result = await response.json();

        // Ensure logs is an array
        const logs = result.logs || ['No logs available'];
        updateConnectionTestModal(result.success ? 'success' : 'error', logs);

    } catch (error) {
        updateConnectionTestModal('error', [
            'Failed to test IMAP connection',
            `Error: ${error.message}`
        ]);
    }
}

function showConnectionTestModal(title, message) {
    const modal = document.createElement('div');
    modal.id = 'connection-test-modal';
    modal.className = 'ui-dialog-backdrop';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-label', title);
    modal.innerHTML = `
        <div class="ui-dialog ui-dialog-fit ui-dialog-md">
            <div class="ui-dialog-head">
                <h3>${escapeHtml(title)}</h3>
                <button onclick="closeConnectionTestModal()" class="ui-icon-btn" title="Close" aria-label="Close">
                    <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="ui-dialog-body">
                <div id="connection-test-content">
                    <div class="ui-loading"><div class="loading"></div><p>${escapeHtml(message)}</p></div>
                </div>
            </div>
            <div class="ui-dialog-foot">
                <button onclick="closeConnectionTestModal()" class="ui-btn">Close</button>
            </div>
        </div>
    `;

    // Close on backdrop click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            closeConnectionTestModal();
        }
    });

    document.body.appendChild(modal);
}

function updateConnectionTestModal(status, logs) {
    const content = document.getElementById('connection-test-content');
    if (!content) return;

    // Ensure logs is an array
    if (!Array.isArray(logs)) {
        logs = ['Error: Invalid response format'];
    }

    const ok = status === 'success';
    content.innerHTML = `
        <div class="ui-md-verdict-bar ${ok ? 'ui-md-verdict-ok' : 'ui-md-verdict-fail'}">${ok ? 'Connection Successful' : 'Connection Failed'}</div>
        <div class="ui-set-log">
            ${logs.map(log => {
        let tone = '';
        if (log.includes('✓')) tone = 'ok';
        if (log.includes('✗') || log.includes('ERROR')) tone = 'fail';
        if (log.includes('WARNING')) tone = 'warn';
        return `<div class="${tone ? `is-${tone}` : ''}">${escapeHtml(log)}</div>`;
    }).join('')}
        </div>
    `;
}

function closeConnectionTestModal() {
    const modal = document.getElementById('connection-test-modal');
    if (modal) {
        modal.remove();
    }
}
