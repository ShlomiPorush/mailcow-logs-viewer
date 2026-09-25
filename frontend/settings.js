// =============================================================================
// SETTINGS PAGE - config editor, GeoIP/MaxMind, jobs, SMTP/IMAP connection tests
// =============================================================================
// Split out of app.js (phase 4). Classic script sharing the global scope;
// loaded after utils.js and app.js in index.html.

// =============================================================================
// SETTINGS PAGE
// =============================================================================

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
        overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);';

        overlay.innerHTML = `
            <div style="background:var(--color-bg-primary, #1f2937);border:1px solid var(--color-border, #374151);border-radius:12px;padding:28px;max-width:420px;width:90%;box-shadow:0 25px 50px rgba(0,0,0,0.4);">
                <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;">
                    <div style="width:40px;height:40px;border-radius:10px;background:linear-gradient(135deg,#f59e0b,#d97706);display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                        <svg width="20" height="20" fill="none" stroke="white" stroke-width="2" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                        </svg>
                    </div>
                    <div>
                        <h3 style="margin:0;font-size:16px;font-weight:600;color:#f3f4f6;">Verify Credentials</h3>
                        <p style="margin:4px 0 0;font-size:13px;color:#9ca3af;">Confirm your username and password before enabling Basic Auth</p>
                    </div>
                </div>
                <div style="background:#292524;border:1px solid #44403c;border-radius:8px;padding:14px;margin-bottom:20px;">
                    <p style="margin:0;font-size:12px;color:#fbbf24;display:flex;align-items:center;gap:6px;">
                        <svg width="14" height="14" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path></svg>
                        Type the credentials you configured to verify you can log in after enabling authentication.
                    </p>
                </div>
                <div style="margin-bottom:14px;">
                    <label style="display:block;font-size:13px;font-weight:500;color:#d1d5db;margin-bottom:6px;">Username</label>
                    <input type="text" id="verify-auth-username" autocomplete="off" placeholder="Enter username"
                        style="width:100%;padding:9px 12px;border-radius:6px;border:1px solid #4b5563;background:#111827;color:#f3f4f6;font-size:14px;outline:none;box-sizing:border-box;"
                        onfocus="this.style.borderColor='#3b82f6';this.style.boxShadow='0 0 0 2px rgba(59,130,246,0.3)'"
                        onblur="this.style.borderColor='#4b5563';this.style.boxShadow='none'">
                </div>
                <div style="margin-bottom:22px;">
                    <label style="display:block;font-size:13px;font-weight:500;color:#d1d5db;margin-bottom:6px;">Password</label>
                    <input type="password" id="verify-auth-password" autocomplete="off" placeholder="Enter password"
                        style="width:100%;padding:9px 12px;border-radius:6px;border:1px solid #4b5563;background:#111827;color:#f3f4f6;font-size:14px;outline:none;box-sizing:border-box;"
                        onfocus="this.style.borderColor='#3b82f6';this.style.boxShadow='0 0 0 2px rgba(59,130,246,0.3)'"
                        onblur="this.style.borderColor='#4b5563';this.style.boxShadow='none'">
                </div>
                <p id="verify-auth-error" style="display:none;margin:0 0 14px;font-size:12px;color:#ef4444;padding:8px 12px;background:#1c1917;border:1px solid #7f1d1d;border-radius:6px;"></p>
                <div style="display:flex;justify-content:flex-end;gap:10px;">
                    <button type="button" id="verify-auth-cancel"
                        style="padding:9px 18px;border-radius:6px;border:1px solid #4b5563;background:transparent;color:#d1d5db;font-size:13px;font-weight:500;cursor:pointer;transition:all 0.15s;"
                        onmouseover="this.style.background='#374151'" onmouseout="this.style.background='transparent'">
                        Cancel
                    </button>
                    <button type="button" id="verify-auth-confirm"
                        style="padding:9px 18px;border-radius:6px;border:none;background:linear-gradient(135deg,#f59e0b,#d97706);color:#1f2937;font-size:13px;font-weight:600;cursor:pointer;transition:all 0.15s;"
                        onmouseover="this.style.opacity='0.9'" onmouseout="this.style.opacity='1'">
                        Verify & Enable
                    </button>
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
                errorEl.style.display = 'block';
                usernameInput.focus();
                return;
            }
            if (!password) {
                errorEl.textContent = 'Please enter a password.';
                errorEl.style.display = 'block';
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
            return `<li style="padding:4px 0;color:#f3f4f6;font-size:14px;">
                <span style="color:#ef4444;margin-right:6px;">✕</span>${feat ? feat.label : id}
                <span style="color:#6b7280;font-size:12px;margin-left:4px;">- ${feat ? feat.description : ''}</span>
            </li>`;
        }).join('');

        const overlay = document.createElement('div');
        overlay.id = 'feature-disable-confirm-modal';
        overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);';

        overlay.innerHTML = `
            <div style="background:var(--color-bg-primary, #1f2937);border:1px solid var(--color-border, #374151);border-radius:12px;padding:28px;max-width:520px;width:90%;box-shadow:0 25px 50px rgba(0,0,0,0.4);">
                <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;">
                    <div style="width:40px;height:40px;border-radius:10px;background:linear-gradient(135deg,#ef4444,#dc2626);display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                        <svg width="20" height="20" fill="none" stroke="white" stroke-width="2" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                        </svg>
                    </div>
                    <div>
                        <h3 style="margin:0;font-size:16px;font-weight:600;color:#f3f4f6;">Disable ${featureIds.length === 1 ? 'Feature' : featureIds.length + ' Features'}?</h3>
                        <p style="margin:4px 0 0;font-size:13px;color:#9ca3af;">This action will permanently delete stored data</p>
                    </div>
                </div>
                <div style="background:#1c1917;border:1px solid #7f1d1d;border-radius:8px;padding:14px;margin-bottom:16px;">
                    <p style="margin:0 0 8px;font-size:12px;color:#fca5a5;display:flex;align-items:center;gap:6px;font-weight:500;">
                        <svg width="14" height="14" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path></svg>
                        All database records for ${featureIds.length === 1 ? 'this feature' : 'these features'} will be permanently deleted. This cannot be undone.
                    </p>
                </div>
                <div style="margin-bottom:20px;">
                    <p style="margin:0 0 8px;font-size:13px;color:#9ca3af;font-weight:500;">Features being disabled:</p>
                    <ul style="margin:0;padding:0 0 0 4px;list-style:none;">${featureListHtml}</ul>
                </div>
                <div style="display:flex;justify-content:flex-end;gap:10px;">
                    <button type="button" id="feature-disable-cancel"
                        style="padding:9px 18px;border-radius:6px;border:1px solid #4b5563;background:transparent;color:#d1d5db;font-size:13px;font-weight:500;cursor:pointer;transition:all 0.15s;"
                        onmouseover="this.style.background='#374151'" onmouseout="this.style.background='transparent'">
                        Cancel
                    </button>
                    <button type="button" id="feature-disable-confirm"
                        style="padding:9px 18px;border-radius:6px;border:none;background:linear-gradient(135deg,#ef4444,#dc2626);color:white;font-size:13px;font-weight:600;cursor:pointer;transition:all 0.15s;"
                        onmouseover="this.style.opacity='0.9'" onmouseout="this.style.opacity='1'">
                        Disable & Delete Data
                    </button>
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
    smtp_abuse_enabled: 'Automatically disable sending (SMTP) for a mailbox that crosses the limit below. Receiving over IMAP is never affected. Requires a Read-Write mailcow API key.',
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
    dns_change_alerts_enabled: 'Alert when a domain SPF, DKIM, DMARC or TLSA (DANE) record changes, so you can update the records at your registrar. The alert names the domain and shows the old and new value. A failed DNS lookup never counts as a change.',

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
    mailcow_api_key: 'mailcow API key (Read-Only). Generate from System → API in mailcow admin. Required permissions: Read access to logs.',
    mailcow_api_key_rw: 'mailcow API key (Read-Write). Optional. Generate a separate key from System → API with write permissions. Used only for edit operations (e.g. Fail2Ban settings).',
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
    tz: 'Timezone for log display (e.g. Europe/London, America/New_York). Default: UTC.',
    app_title: 'Application title (shown in browser tab).',
    app_logo_url: 'Logo URL (optional; leave empty to use the default project icon).',
    debug: 'Enable debug mode (shows detailed errors). Use only for development. Never enable in production. Default: false.',
    max_search_results: 'Maximum records to return in search results. Default: 1000.',
    csv_export_limit: 'CSV export row limit. Default: 10000.',
    scheduler_workers: 'Thread pool size for blocking scheduler jobs (e.g. DMARC IMAP sync). Valid range: 1-64. Default: 4.',
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
    smtp_user: 'SMTP username (usually email address).',
    smtp_password: 'SMTP password.',
    smtp_from: 'From address for emails (defaults to SMTP user if not set).',
    smtp_relay_mode: 'Relay mode: for local relay servers that do not require authentication. When enabled, username and password are not required.',
    admin_email: 'Administrator email for system notifications.',
    blacklist_alert_email: 'Email for IP blacklist alerts (uses Admin email if not set).',
    dmarc_retention_days: 'DMARC reports retention in days. Default: 60.',
    dmarc_manual_upload_enabled: 'Allow manual upload of DMARC reports via the UI. Default: true.',
    dmarc_allow_report_delete: 'Allow deleting DMARC/TLS reports from the UI. Default: false.',
    enable_weekly_summary: 'Enable weekly summary email report (sent to admin email). Default: true.',
    dmarc_imap_enabled: 'Enable automatic DMARC report import from IMAP mailbox.',
    dmarc_imap_host: 'IMAP server hostname (e.g. imap.gmail.com).',
    dmarc_imap_port: 'IMAP server port (993 for SSL, 143 for non-SSL). Default: 993.',
    dmarc_imap_use_ssl: 'Use SSL/TLS for IMAP connection. Default: true.',
    dmarc_imap_user: 'IMAP username (email address).',
    dmarc_imap_password: 'IMAP password.',
    dmarc_imap_folder: 'IMAP folder to scan for DMARC reports. Default: INBOX.',
    dmarc_imap_delete_after: 'Delete emails after successful processing. Default: true.',
    dmarc_imap_interval: 'Interval between IMAP syncs in seconds. Default: 3600 (1 hour).',
    dmarc_imap_run_on_startup: 'Run IMAP sync once on application startup. Default: true.',
    dmarc_imap_batch_size: 'Number of emails to process per batch. Default: 10.',
    dmarc_imap_scan_all_unseen: 'Scan all unread emails for DMARC/TLS-RPT attachments, not just those matching known subject patterns. Enable if you receive reports from providers that use non-English subjects. Only recommended for dedicated DMARC mailboxes.',
    dmarc_error_email: 'Email for DMARC error notifications (defaults to Admin email if not set).',
    maxmind_account_id: 'MaxMind Account ID for GeoIP database downloads. Required to download GeoLite2 databases.',
    maxmind_license_key: 'MaxMind License Key for GeoIP database downloads. Required to download GeoLite2 databases. Keep this secret.',
    disabled_features: 'Disable features to hide their pages and stop their background jobs. Core features (Dashboard, Messages, Settings, Status) are always enabled.',
    raw_logs_enabled: 'Enable background raw log collection for the Logs page. When disabled, no logs are fetched and the Logs page shows historical data only.',
    raw_logs_fetch_interval: 'Seconds between raw log fetch cycles. Lower = more frequent updates. Default: 20.',
    raw_logs_fetch_count: 'Number of log entries to fetch per service per cycle. Higher values catch more logs but increase API load. Default: 1000.',
    raw_logs_retention_days: 'Days to keep raw logs in the database. Older logs are automatically deleted at 3:00 AM daily. Default: 2.',
    raw_logs_services: 'Select which mailcow services to collect logs from. Unchecked services will not be fetched or displayed.',
    rspamd_password: 'Rspamd UI/API password for reading Rspamd map data. Required to view and edit Rspamd maps.',
    suppression_enabled: 'Master switch for the spam suppression system. When enabled, bounced/rejected recipients are automatically blocked from receiving future emails.',
    suppression_auto_detect: 'Automatically scan Postfix logs to detect hard bounce (5.x.x) errors and add recipients to the suppression list.',
    suppression_rspamd_sync: 'Sync the suppression list to Rspamd\'s global_rcpt_blacklist.map so blocked emails are rejected at SMTP level. Requires Rspamd password.',
    suppression_whitelist_domains: 'Domains listed here will never be suppressed, even if they bounce. Comma-separated (e.g., gmail.com, outlook.com).',
    suppression_hard_bounce_action: 'What to do when a permanent delivery failure (5.x.x) is detected.',
    suppression_soft_bounce_action: 'What to do when a temporary delivery failure (4.x.x) is detected in Postfix logs. Note: deferred emails stuck in the queue are handled separately by Queue Cleanup below.',
    suppression_soft_bounce_threshold: 'How many soft bounces from Postfix logs before the recipient is suppressed (only applies when action is "Count then suppress").',
    suppression_base_expiry_days: 'How long to block a recipient. Multiplied by bounce count for repeat offenders (e.g., 7 days × 3 bounces = 21 days). Used by all suppression types. Default: 7.',
    suppression_max_expiry_days: 'Maximum block duration cap, regardless of bounce count. Default: 90.',
    quarantine_rules_max_actions: 'Safety limit: maximum emails to release/delete per scheduler run. Prevents accidental mass-processing from overly broad rules. Default: 50.',
    quarantine_rules_interval: 'Minutes between quarantine rule processing runs. Lower = faster response to new quarantine items, higher = less API load on mailcow. Default: 5.',
    quarantine_rules_log_retention_days: 'Days to keep quarantine auto-rule action history. Older action logs are automatically cleaned up. Default: 30.',
    queue_cleanup_enabled: 'Automatically monitor the mail queue for deferred emails. If an email has been stuck longer than the threshold, it is deleted from the queue and the recipient is suppressed.',
    queue_cleanup_threshold_minutes: 'How long (in minutes) a deferred email must be stuck in the queue before it is automatically deleted and the recipient suppressed. Default: 60 (1 hour).'
};

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
    suppression_hard_bounce_action: [
        { value: 'suppress', label: 'Suppress - block the recipient immediately' },
        { value: 'ignore', label: 'Ignore - do nothing' }
    ],
    suppression_soft_bounce_action: [
        { value: 'suppress', label: 'Suppress - block immediately on first soft bounce' },
        { value: 'count', label: 'Count then suppress - block after reaching threshold' },
        { value: 'ignore', label: 'Ignore - do nothing (let Postfix retry)' }
    ]
};

// Edit form tabs (same order as env.example sections) with descriptions from env.example
// Keys grouped logically within each tab
var SETTINGS_EDIT_TABS = [
    {
        id: 'mailcow', label: 'Mailcow', description: 'Your mailcow instance URL and API credentials. API key needs read access to logs (generate from System → API in mailcow admin). Set verify SSL to false only for development with self-signed certificates.', groups: [
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
        id: 'application', label: 'Application', description: 'Web app port, title and logo. Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL. Debug mode shows detailed errors (do not enable in production). Search/CSV limits and scheduler worker count.', groups: [
            { label: 'Basic', keys: ['app_port', 'app_title', 'app_logo_url'] },
            { label: 'Logging', keys: ['log_level', 'debug'] },
            { label: 'Limits', keys: ['max_search_results', 'csv_export_limit', 'scheduler_workers'] },
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
        id: 'domains', label: 'Domains', description: 'DNS checks for your domains (SPF, DKIM, DMARC, TLSA) on the Domains page. Choose which sending IPs must pass each domain SPF record - with a relay setup the relay IPs matter, not the auto-detected WAN IP.', groups: [
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
            { label: 'Security', keys: ['smtp_use_tls', 'smtp_use_ssl'] },
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
        id: 'smtp_abuse', label: 'SMTP Abuse (Beta)', description: 'Beta - please report issues on GitHub. Enforcement layer: automatically disables SMTP (sending) for a mailbox that exceeds a hard outbound limit - the usual signature of a compromised account. Receiving over IMAP is never affected. Requires a Read-Write mailcow API key. Manage blocked mailboxes and the whitelist under Security → Abuse Protection.', groups: [
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
        id: 'dmarc', label: 'DMARC', description: 'DMARC reports retention (days). Allow manual upload of reports via UI. Allow deleting DMARC/TLS reports from the UI. Weekly summary: enable email report sent to admin.', groups: [
            { label: 'Retention', keys: ['dmarc_retention_days'] },
            { label: 'Features', keys: ['dmarc_manual_upload_enabled', 'dmarc_allow_report_delete'] },
            { label: 'Insights (policy recommendations)', keys: ['dmarc_insights_window_days', 'dmarc_insights_pass_threshold', 'dmarc_insights_min_volume'] }
        ]
    },
    {
        id: 'dmarc_imap', label: 'DMARC IMAP', description: 'Automatically import DMARC reports from an IMAP mailbox. Set host, port, user, password and folder (e.g. INBOX). Delete after: remove emails after processing. Interval in seconds; run on startup to sync once at start.', groups: [
            { label: 'Enable', keys: ['dmarc_imap_enabled'] },
            { label: 'Connection', keys: ['dmarc_imap_host', 'dmarc_imap_port', 'dmarc_imap_use_ssl'] },
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
            { label: 'Retention', keys: ['raw_logs_retention_days'] },
            { label: 'Services', keys: ['raw_logs_services'] }
        ]
    },
    {
        id: 'spam_filter', label: 'Spam Filter', description: 'Automatic bounce handling. Hard bounces are detected from Postfix logs, deferred (soft bounce) emails directly in the mail queue, and the block duration grows with each repeat bounce. The Rspamd connection itself (password and address) is configured under Mailcow.', groups: [
            { label: 'Suppression', keys: ['suppression_enabled', 'suppression_auto_detect', 'suppression_rspamd_sync'] },
            { label: 'Hard Bounces (5.x.x)', keys: ['suppression_hard_bounce_action'] },
            { label: 'Soft Bounces (4.x.x) - Log Detection', keys: ['suppression_soft_bounce_action', 'suppression_soft_bounce_threshold'] },
            { label: 'Deferred Queue Cleanup', keys: ['queue_cleanup_enabled', 'queue_cleanup_threshold_minutes'] },
            { label: 'Block Duration', keys: ['suppression_base_expiry_days', 'suppression_max_expiry_days'] },
            { label: 'Whitelist', keys: ['suppression_whitelist_domains'] }
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
    { label: 'Connection', tabs: ['mailcow', 'fetch', 'correlation', 'logs'] },
    { label: 'Notifications', tabs: ['notifications', 'smtp'] },
    { label: 'Security', tabs: ['auth', 'anomaly', 'smtp_abuse'] },
    { label: 'Email Data', tabs: ['domains', 'dmarc', 'dmarc_imap', 'maxmind'] },
    { label: 'Features & Advanced', tabs: ['blacklist', 'spam_filter', 'quarantine', 'application', 'other'] }
];

function renderSettingsEditField(key, value, sensitiveKeys, description, envLocked, defaultValue) {
    const LOCK = '<svg width="12" height="12" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true"><path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd"></path></svg>';
    // Special renderer for disabled_features - checkboxes for feature toggles
    if (key === 'disabled_features') {
        const disabledSet = new Set(
            (value || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
        );
        const isLocked = envLocked;

        let html = `<div class="ui-set-field ui-set-wide">
            <span class="ui-label">Feature Toggles</span>
            <p class="ui-set-desc">Uncheck features to hide them from the UI and stop their background jobs. <b class="ui-text-fail">Disabling a feature permanently deletes its stored data.</b></p>`;

        if (isLocked) {
            html += `<p class="ui-set-env">${LOCK} Locked by ENV (DISABLED_FEATURES)</p>`;
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
            <input type="hidden" id="setting-disabled_features" name="disabled_features" value="${value || ''}">
        </div>`;

        return html;
    }

    // Special renderer for raw_logs_services - checkboxes
    if (key === 'raw_logs_services') {
        const ALL_LOG_SERVICES = [
            { id: 'acme', label: 'ACME (SSL Certificates)' },
            { id: 'api', label: 'API (Access Logs)' },
            { id: 'autodiscover', label: 'Autodiscover' },
            { id: 'dovecot', label: 'Dovecot (IMAP/POP3)' },
            { id: 'netfilter', label: 'Netfilter (Firewall)' },
            { id: 'postfix', label: 'Postfix (MTA)' },
            { id: 'ratelimited', label: 'Ratelimited' },
            { id: 'rspamd-history', label: 'Rspamd (Spam Filter)' },
            { id: 'sogo', label: 'SOGo (Groupware)' },
            { id: 'watchdog', label: 'Watchdog (Monitoring)' }
        ];
        const enabledServices = (value || '').split(',').map(function(s) { return s.trim().toLowerCase(); }).filter(Boolean);
        const disabledAttr = envLocked ? 'disabled' : '';
        const envLockedHtml = envLocked ? '<p class="ui-set-env">' + LOCK + ' Controlled by ENV variable.</p>' : '';
        const descHtml = (description && description.trim()) ? '<p class="ui-set-desc">' + escapeHtml(description) + '</p>' : '';

        let checkboxesHtml = '<div class="ui-set-checks">';
        ALL_LOG_SERVICES.forEach(function(svc) {
            const checked = enabledServices.includes(svc.id) ? 'checked' : '';
            checkboxesHtml += '<label class="ui-check-label">' +
                '<input type="checkbox" class="raw-logs-service-cb ui-check" data-service="' + svc.id + '" ' + checked + ' ' + disabledAttr + '>' +
                escapeHtml(svc.label) + '</label>';
        });
        checkboxesHtml += '</div>';

        // Hidden input that holds the comma-separated value
        checkboxesHtml += '<input type="hidden" id="edit-raw_logs_services" name="raw_logs_services" value="' + escapeHtml(value || '') + '">';

        return '<div class="ui-set-field ui-set-wide' + (envLocked ? ' is-locked' : '') + '">' + descHtml + checkboxesHtml + envLockedHtml + '</div>';
    }

    const isBool = typeof value === 'boolean';
    const isNum = typeof value === 'number';
    const sensitive = sensitiveKeys.includes(key);
    const displayVal = value === null || value === undefined ? '' : (isBool ? value : String(value));
    // Convert key to label with proper acronym capitalization (SSL, IMAP, TLS, etc.)
    let label = key.replace(/_/g, ' ').replace(/\b\w/g, function (l) { return l.toUpperCase(); });
    // Fix common acronyms
    label = label.replace(/\bSsl\b/gi, 'SSL').replace(/\bImap\b/gi, 'IMAP').replace(/\bTls\b/gi, 'TLS')
        .replace(/\bOauth\b/gi, 'OAuth').replace(/\bOidc\b/gi, 'OIDC').replace(/\bApi\b/gi, 'API')
        .replace(/\bUrl\b/gi, 'URL').replace(/\bIp\b/gi, 'IP').replace(/\bDns\b/gi, 'DNS')
        .replace(/\bDmarc\b/gi, 'DMARC').replace(/\bSpf\b/gi, 'SPF').replace(/\bDkim\b/gi, 'DKIM')
        .replace(/\bSmtp\b/gi, 'SMTP').replace(/\bCsv\b/gi, 'CSV').replace(/\bEnv\b/gi, 'ENV')
        .replace(/\bDb\b/gi, 'DB');
    const descHtml = (description && description.trim()) ? '<p class="ui-set-desc">' + escapeHtml(description) + '</p>' : '';
    const disabledAttr = envLocked ? 'disabled' : '';
    const envLockedHtml = envLocked ? '<p class="ui-set-env">' + LOCK + ' Controlled by ENV variable - cannot be changed from here.</p>' : '';
    const labelLockIcon = envLocked ? ' <span class="ui-set-lock" title="Controlled by ENV">' + LOCK + '</span>' : '';

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
        if (isBool) return value !== defaultValue;
        if (isNum) return Number(value) !== Number(defaultValue);
        return String(value || '') !== String(defaultValue || '');
    })();
    // For sensitive keys with a value set (masked), consider them "changed" from empty default
    const isSensitiveChanged = sensitive && hasDefault && displayVal === '********';

    // Clear/Reset button HTML (not shown for env-locked fields)
    let clearBtnHtml = '';
    if (!envLocked) {
        if (hasDefault && !isUserSpecific && (isChanged || isSensitiveChanged)) {
            const defaultLabel = sensitive ? '(empty)' : escapeHtml(String(defaultValue));
            clearBtnHtml = '<button type="button" class="settings-clear-btn ui-set-clear is-reset" data-key="' + key + '" data-default="' + escapeHtml(String(defaultValue)) + '" data-sensitive="' + sensitive + '" data-isbool="' + isBool + '">' +
                '↺ Reset to default' + (isBool ? ': ' + defaultLabel : ' (' + defaultLabel + ')') + '</button>';
        } else if (!isBool && String(displayVal).trim() !== '' && !(sensitive && displayVal === '') && !(hasDefault && !isUserSpecific && String(displayVal) === String(defaultValue))) {
            clearBtnHtml = '<button type="button" class="settings-clear-btn ui-set-clear" data-key="' + key + '" data-default="' + (hasDefault ? escapeHtml(String(defaultValue)) : '') + '" data-sensitive="' + sensitive + '" data-isbool="false">' +
                '× Clear</button>';
        }
    }

    // A value that differs from its default is marked, so a changed setting stands out
    const changed = (isChanged || isSensitiveChanged) && !envLocked ? ' is-changed' : '';

    if (isBool) {
        return '<div class="ui-set-bool' + (envLocked ? ' is-locked' : (isChanged ? ' is-changed' : '')) + '">' +
            '<div class="ui-set-bool-main">' +
            '<input type="checkbox" id="edit-' + key + '" name="' + key + '" ' + (displayVal ? 'checked' : '') + ' ' + disabledAttr + ' class="ui-check">' +
            '<div><label for="edit-' + key + '" class="ui-set-bool-label">' + escapeHtml(label) + labelLockIcon + '</label>' + descHtml + envLockedHtml + '</div></div>' +
            clearBtnHtml + '</div>';
    }

    // Dropdown for fields with predefined options
    const fieldOptions = SETTINGS_FIELD_OPTIONS[key];
    if (fieldOptions) {
        let optionsHtml = '';
        fieldOptions.forEach(function(opt) {
            const selected = String(displayVal) === opt.value ? 'selected' : '';
            optionsHtml += '<option value="' + escapeHtml(opt.value) + '" ' + selected + '>' + escapeHtml(opt.label) + '</option>';
        });
        return '<div class="ui-set-field' + (envLocked ? ' is-locked' : '') + '"><label for="edit-' + key + '" class="ui-label">' + escapeHtml(label) + labelLockIcon + '</label>' +
            descHtml +
            '<select id="edit-' + key + '" name="' + key + '" ' + disabledAttr + ' class="ui-select' + changed + '">' +
            optionsHtml + '</select>' +
            clearBtnHtml +
            envLockedHtml + '</div>';
    }

    const inputType = sensitive ? 'password' : (isNum ? 'number' : 'text');
    const placeholder = envLocked ? 'Controlled by ENV' : '';
    const valAttr = (isBool ? '' : displayVal);
    return '<div class="ui-set-field' + (envLocked ? ' is-locked' : '') + '"><label for="edit-' + key + '" class="ui-label">' + escapeHtml(label) + labelLockIcon + '</label>' +
        descHtml +
        '<input type="' + inputType + '" id="edit-' + key + '" name="' + key + '" value="' + escapeHtml(valAttr) + '" placeholder="' + escapeHtml(placeholder) + '" ' + disabledAttr + ' class="ui-input' + changed + '">' +
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
        ['Fetch Interval', `${config.fetch_interval || 0} seconds`],
        ['Fetch Count (Postfix)', `${config.fetch_count_postfix || config.fetch_count || 0} per request`],
        ['Fetch Count (Rspamd)', `${config.fetch_count_rspamd || config.fetch_count || 0} per request`],
        ['Fetch Count (Netfilter)', `${config.fetch_count_netfilter || config.fetch_count || 0} per request`],
        ['Max Pages per Cycle', `${config.fetch_max_pages || 50}`],
        ['Retention', `${config.retention_days || 0} days`],
        ['Max Correlation Age', `${config.max_correlation_age_minutes || 10} minutes`],
        ['Correlation Check', `${config.correlation_check_interval || 120} seconds`],
        ['Timezone', escapeHtml(config.timezone || 'N/A')],
        ['Log Level', escapeHtml(config.log_level || 'INFO')],
        ['Blacklist', config.blacklist_enabled ? `Enabled (${config.blacklist_count} emails)` : 'Disabled'],
        ['Scheduler Workers', `${config.scheduler_workers || 4}`],
    ];

    content.innerHTML = `
        ${!data.settings_edit_via_ui_enabled ? `<div class="ui-list-note ui-flush">${uiLocked('Editing settings is off',
            'These values come from the environment and are shown read-only. To change them here, set <code>SETTINGS_EDIT_VIA_UI_ENABLED=true</code> and restart the container.', '')}</div>` : ''}

        <div class="ui-dash-grid ui-status-pair">
            <!-- Version Information Section -->
            <section class="ui-panel">
                <div class="ui-panel-head">Version Information</div>
                <div class="ui-kv"><span>Current Version</span><b><button type="button" id="current-version-text" class="ui-link-row ui-link" title="Click to view changelog">v${escapeHtml(appVersion)}</button></b></div>
                <div class="ui-kv"><span>Latest Version</span><b id="settings-latest-version">${renderLatestVersionState(versionInfo)}</b></div>
                <div class="ui-set-version-foot">
                    <span id="settings-version-checked" class="ui-muted">${versionInfo.last_checked ? `Last checked: ${formatDate(versionInfo.last_checked)}` : ''}</span>
                    <button id="check-version-btn" class="ui-btn ui-btn-sm">
                        <svg id="check-version-icon" width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                        </svg>
                        <span id="check-version-text">Check Now</span>
                    </button>
                </div>
                <div id="settings-update-note">${renderUpdateNote(versionInfo)}</div>
            </section>

            <!-- Configuration Section -->
            <section class="ui-panel">
                <div class="ui-panel-head">Configuration</div>
                ${kv('mailcow URL', escapeHtml(config.mailcow_url || 'N/A'), 'ui-mono ui-kv-small')}
                ${kv('Server IP', config.server_ip ? `<span class="ui-text-ok">✓</span> ${escapeHtml(config.server_ip)}` : '<span class="ui-muted">Not available</span>', 'ui-mono ui-kv-small')}
                ${kv('Authentication', config.auth_enabled
                    ? `${uiTag('Enabled', 'ok')} ${config.basic_auth_enabled ? uiTag('Basic Auth', 'info') : ''} ${config.oauth2_enabled ? uiTag(`OAuth2${config.oauth2_provider_name ? ` (${config.oauth2_provider_name})` : ''}`, 'spam') : ''}`
                    : uiTag('Disabled', ''))}
                ${config.auth_enabled && config.basic_auth_enabled && config.auth_username ? `<p class="ui-kv-note">Basic Auth Username: ${escapeHtml(config.auth_username)}</p>` : ''}
                ${config.local_domains && config.local_domains.length > 0 ? '' : kv('Local Domains', '<span class="ui-muted">N/A</span>')}
            </section>
        </div>

        ${config.local_domains && config.local_domains.length > 0 ? `
        <section class="ui-panel">
            <div class="ui-panel-head">Local Domains <span class="ui-count">${config.local_domains.length}</span></div>
            <div class="ui-set-domains">${config.local_domains.map(domain => `<span class="ui-code-chip" title="${escapeHtml(domain)}">${escapeHtml(domain)}</span>`).join('')}</div>
        </section>` : ''}

        ${!data.settings_edit_via_ui_enabled ? `
        <section class="ui-panel">
            <div class="ui-panel-head">Runtime</div>
            <div class="ui-md-ids ui-set-facts">
                ${readOnlyFacts.map(([label, value]) => `<div class="ui-md-fact"><span>${label}</span><div>${value}</div></div>`).join('')}
                <div class="ui-md-fact"><span>MaxMind Status</span>
                    <div class="ui-chip-row">
                        <span id="maxmind-license-status">${renderMaxMindStatus(data.configuration.maxmind_status)}</span>
                        ${data.geoip_configuration ? renderGeoIPDbStatus(data.geoip_configuration) : ''}
                        ${data.geoip_configuration && data.geoip_configuration.enabled ? '<button type="button" onclick="validateMaxMindLicense()" class="ui-btn ui-btn-sm">Validate</button>' : ''}
                    </div>
                </div>
            </div>
        </section>
        ` : ''}

        ${data.settings_edit_via_ui_enabled && data.editable_config ? (function () {
            const sensitiveKeys = ['mailcow_api_key', 'mailcow_api_key_rw', 'auth_password', 'oauth2_client_secret', 'smtp_password', 'dmarc_imap_password', 'session_secret_key', 'maxmind_license_key'];
            const envLockedKeys = new Set(data.env_locked_keys || []);
            const defaults = data.default_config || {};
            const allAssignedKeys = new Set(SETTINGS_EDIT_TABS.flatMap(function (t) { return (t.groups || []).flatMap(function (g) { return g.keys; }); }));
            const configKeys = Object.keys(data.editable_config);
            const otherKeys = configKeys.filter(function (k) { return !allAssignedKeys.has(k); });
            const tabs = otherKeys.length ? SETTINGS_EDIT_TABS.concat([{ id: 'other', label: 'Other', groups: [{ label: 'Settings', keys: otherKeys }] }]) : SETTINGS_EDIT_TABS;

            // Map settings tabs to features - hide tabs for disabled features
            const SETTINGS_TAB_FEATURE_MAP = {
                'domains': 'domains',
                'blacklist': 'blacklist',
                'dmarc': 'dmarc',
                'dmarc_imap': 'dmarc',
                'logs': 'logs',
                'spam_filter': 'spam-filter',
                'quarantine': 'quarantine'
            };
            const filteredTabs = tabs.filter(function (tab) {
                const feature = SETTINGS_TAB_FEATURE_MAP[tab.id];
                if (feature && window.disabledFeatures && window.disabledFeatures.includes(feature)) return false;
                return true;
            });

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

            // Desktop: grouped category sidebar
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
            let tabsHtml = mobileNavHtml
                + '<div class="settings-edit-layout">' + navHtml
                + '<div class="settings-edit-content">';
            filteredTabs.forEach(function (tab, idx) {
                const allKeysInTab = (tab.groups || []).flatMap(function (g) { return g.keys; });
                const keysInTab = allKeysInTab.filter(function (k) { return data.editable_config[k] !== undefined; });
                // Show tab if it has keys OR if it's maxmind tab (which shows status)
                if (keysInTab.length === 0 && tab.id !== 'maxmind') return;
                // The visible panel is the one matching the active sidebar item
                const hidden = tab.id === firstVisibleId ? '' : ' hidden';
                const desc = tab.description ? '<p class="ui-set-tabdesc">' + escapeHtml(tab.description) + '</p>' : '';
                tabsHtml += '<div id="settings-tab-panel-' + tab.id + '" class="settings-edit-panel' + hidden + '">' + desc;

                // A small grid of facts at the top of a tab: SMTP, DMARC IMAP and MaxMind status
                const statusBlock = function (facts) {
                    return '<div class="ui-set-group"><h4 class="ui-md-h">Status</h4><div class="ui-md-ids ui-set-facts">'
                        + facts.map(function (f) { return '<div class="ui-md-fact"><span>' + f[0] + '</span><div class="ui-chip-row">' + f[1] + '</div></div>'; }).join('')
                        + '</div></div>';
                };
                const onOff = function (on, offTone) { return on ? uiTag('Enabled', 'ok') : uiTag('Disabled', offTone || ''); };

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
                    tabsHtml += '<div id="notification-channels-panel" class="ui-set-group"></div>';
                }

                // Special handling for DMARC IMAP tab - add DMARC Management
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
                            ? '<span>' + name + ': ' + db.size_mb + 'MB <small class="ui-muted">(' + db.age_days + 'd old)</small></span>'
                            : '<span class="ui-muted">' + name + ': Not installed</span>';
                    };
                    tabsHtml += statusBlock([
                        ['License', '<span id="maxmind-license-status-tab">' + renderMaxMindStatus(data.configuration.maxmind_status) + '</span>'
                            + (data.geoip_configuration && data.geoip_configuration.enabled ? '<button type="button" onclick="validateMaxMindLicense()" class="ui-btn ui-btn-sm">Validate</button>' : '')],
                        ['Database Health', '<span id="geoip-db-status" class="ui-chip-row">' + renderGeoIPDbStatus(geoipCfg) + '</span>'],
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
                    tabsHtml += '<div class="ui-set-group"><h4 class="ui-md-h">' + escapeHtml(group.label) + '</h4><div class="ui-set-grid">';
                    groupKeys.forEach(function (key) {
                        tabsHtml += renderSettingsEditField(key, data.editable_config[key], sensitiveKeys, SETTINGS_FIELD_DESCRIPTIONS[key] || '', envLockedKeys.has(key), defaults[key]);
                    });
                    tabsHtml += '</div></div>';
                });
                tabsHtml += '</div>';
            });
            tabsHtml += '</div></div>';  // close .settings-edit-content and .settings-edit-layout
            return `
        <!-- Edit Configuration (only when SETTINGS_EDIT_VIA_UI_ENABLED) -->
        <section class="ui-panel ui-set-edit">
            <div class="ui-panel-head ui-rl-head">
                <div>
                    <h3 class="ui-h2">Edit configuration</h3>
                    <p class="ui-muted">Priority: Default → DB → ENV. Environment variables always override DB values and cannot be changed from here.</p>
                </div>
                <div class="ui-rl-tools" id="settings-edit-actions">
                    ${!data.settings_migrated ? '<button type="button" id="settings-import-env-btn" class="ui-btn ui-btn-primary">Migrate Settings from ENV</button>' : ''}
                    ${data.settings_migrated ? '<button type="submit" form="settings-edit-form" id="settings-save-btn" class="ui-btn ui-btn-primary">Save changes</button>' : ''}
                </div>
            </div>
            <form id="settings-edit-form" class="ui-set-form">
                ` + tabsHtml + `
            </form>
        </section>
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

            <!-- DMARC Management -->
            <section class="ui-panel">
                <div class="ui-panel-head">DMARC Management
                    <button type="button" onclick="testImapConnection()" class="ui-btn ui-btn-sm ui-head-actions">Test IMAP</button></div>
                <div class="ui-kv"><span>IMAP Auto-Import</span><b>${data.dmarc_configuration?.imap_sync_enabled ? uiTag('Enabled', 'ok') : uiTag('Disabled', '')}</b></div>
                <div class="ui-kv"><span>Manual Upload</span><b>${data.dmarc_configuration?.manual_upload_enabled ? uiTag('Enabled', 'ok') : uiTag('Disabled', 'fail')}</b></div>
                ${data.dmarc_configuration?.imap_sync_enabled ? `<div class="ui-kv"><span>IMAP Server</span><b class="ui-mono ui-kv-small">${escapeHtml(data.dmarc_configuration.imap_host || 'N/A')}</b></div>` : ''}
            </section>
        </div>
        ` : ''}
    `;

    // Add event listener for version number click (changelog popup)
    const currentVersionText = document.getElementById('current-version-text');

    const loadCurrentVersionChangelog = async () => {
        try {
            // Remove 'v' prefix if present for API call
            const versionForApi = appVersion.startsWith('v') ? appVersion.substring(1) : appVersion;
            const response = await authenticatedFetch(`/api/status/app-version/changelog/${versionForApi}`);
            if (response.ok) {
                const data = await response.json();
                showChangelogModal(data.changelog || 'No changelog available');
            } else {
                showChangelogModal('Failed to load changelog');
            }
        } catch (error) {
            console.error('Failed to load changelog:', error);
            showChangelogModal('Failed to load changelog');
        }
    };

    if (currentVersionText) {
        currentVersionText.onclick = loadCurrentVersionChangelog;
    }

    // Render markdown in changelog sections if marked.js is available
    // Use versionInfo from the data object directly instead of data attributes
    if (typeof marked !== 'undefined' && versionInfo && versionInfo.changelog) {
        marked.setOptions({
            breaks: true,
            gfm: true
        });
        const changelogElements = content.querySelectorAll('.update-changelog-content');
        changelogElements.forEach(el => {
            // Use the changelog directly from versionInfo object
            const changelogText = versionInfo.changelog;
            if (changelogText) {
                el.innerHTML = renderMarkdown(changelogText);
            }
        });
    }

    // Add event listener for version check button
    const checkVersionBtn = document.getElementById('check-version-btn');
    if (checkVersionBtn) {
        // Use onclick to avoid duplicate listeners (simpler approach)
        checkVersionBtn.onclick = async () => {
            const btn = checkVersionBtn;
            const icon = document.getElementById('check-version-icon');
            const text = document.getElementById('check-version-text');

            // Disable button and show loading state
            btn.disabled = true;
            if (icon) {
                icon.classList.add('animate-spin');
            }
            if (text) {
                text.textContent = 'Checking...';
            }

            try {
                // Force check for updates
                const response = await authenticatedFetch('/api/status/app-version?force=true');
                const versionInfo = await response.json();

                // Update cache
                versionInfoCache.version_info = versionInfo;

                // Update UI directly without reloading the page
                updateVersionInfoUI(versionInfo);

                // Show success state - green button with "Done"
                btn.classList.add('ui-btn-done');
                if (text) {
                    text.textContent = 'Done';
                }
                if (icon) {
                    icon.classList.remove('animate-spin');
                    // Change icon to checkmark
                    const path = icon.querySelector('path');
                    if (path) {
                        path.setAttribute('d', 'M5 13l4 4L19 7');
                    }
                }

                // Re-enable button immediately after success (but keep green color)
                btn.disabled = false;

                // Reset button after 3 seconds
                setTimeout(() => {
                    btn.classList.remove('ui-btn-done');
                    if (text) {
                        text.textContent = 'Check Now';
                    }
                    if (icon) {
                        const path = icon.querySelector('path');
                        if (path) {
                            path.setAttribute('d', 'M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15');
                        }
                    }
                }, 3000);

            } catch (error) {
                console.error('Failed to check version:', error);
                // Show error message
                btn.classList.add('ui-btn-failed');
                if (text) {
                    text.textContent = 'Error';
                }
                if (icon) {
                    icon.classList.remove('animate-spin');
                }

                // Reset button after 2 seconds
                setTimeout(() => {
                    btn.classList.remove('ui-btn-failed');
                    if (text) {
                        text.textContent = 'Check Now';
                    }
                    if (icon) {
                        const path = icon.querySelector('path');
                        if (path) {
                            path.setAttribute('d', 'M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15');
                        }
                    }
                    btn.disabled = false;
                }, 2000);
            }
        };
    }

    // Edit configuration: form submit, Import from ENV, and tab switching
    if (data.settings_edit_via_ui_enabled && data.editable_config) {
        // Notification destinations are managed outside the settings form
        if (typeof loadNotificationChannels === 'function') {
            loadNotificationChannels();
        }

        // Switching is shared by the desktop sidebar and the mobile picker, so
        // the two can never disagree about which category is open.
        const switchSettingsTab = function (tabId, scrollToTop) {
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

            // On mobile, bring the sticky picker back to the top of the
            // viewport so the new category starts at its first field.
            if (scrollToTop && window.matchMedia('(max-width: 1023px)').matches) {
                const anchor = content.querySelector('.settings-mobile-nav');
                if (anchor) anchor.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        };

        content.querySelectorAll('.settings-edit-tab').forEach(function (btn) {
            btn.addEventListener('click', function () {
                switchSettingsTab(btn.getAttribute('data-tab'), false);
            });
        });

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
                const el = content.querySelector('[name="' + key + '"]');
                if (!el) return;
                if (isBool) {
                    el.checked = defaultVal === 'true';
                } else if (isSensitive) {
                    el.value = '';
                    el.type = 'text'; // Show cleared field
                } else {
                    el.value = defaultVal || '';
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
                const hiddenInput = content.querySelector('#edit-raw_logs_services');
                if (hiddenInput) hiddenInput.value = selected.join(',');
            });
        });

        const form = content.querySelector('#settings-edit-form');
        const importBtn = content.querySelector('#settings-import-env-btn');
        if (form) {
            form.onsubmit = async (e) => {
                e.preventDefault();
                const payload = {};
                const sensitiveKeys = ['mailcow_api_key', 'mailcow_api_key_rw', 'auth_password', 'oauth2_client_secret', 'smtp_password', 'dmarc_imap_password', 'session_secret_key', 'maxmind_license_key'];
                for (const key of Object.keys(data.editable_config)) {
                    const el = form.querySelector('[name="' + key + '"]');
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
                const PURGEABLE_FEATURES = ['netfilter', 'domains', 'dmarc', 'mailbox-stats', 'logs', 'blacklist', 'spam-filter', 'quarantine'];
                let newlyDisabledFeatures = [];
                if ('disabled_features' in payload) {
                    const oldDisabled = new Set(
                        (window.disabledFeatures || []).map(s => s.trim().toLowerCase())
                    );
                    const newDisabled = new Set(
                        (payload.disabled_features || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
                    );
                    newlyDisabledFeatures = [...newDisabled].filter(f => !oldDisabled.has(f));

                    // Show confirmation modal if any purgeable features are being disabled
                    const purgeableNewlyDisabled = newlyDisabledFeatures.filter(f => PURGEABLE_FEATURES.includes(f));
                    if (purgeableNewlyDisabled.length > 0) {
                        const confirmed = await showFeatureDisableConfirmModal(purgeableNewlyDisabled);
                        if (!confirmed) return; // User cancelled
                    }
                }
                // ──────────────────────────────────────────────────────────

                try {
                    const saveBtn = content.querySelector('#settings-save-btn');
                    if (saveBtn) saveBtn.disabled = true;
                    const res = await authenticatedFetch('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
                    if (!res.ok) {
                        const err = await res.json().catch(() => ({}));
                        throw new Error(err.detail || res.statusText);
                    }
                    if (saveBtn) saveBtn.disabled = false;
                    if (isEnablingBasicAuth) {
                        showToast('Basic Auth enabled successfully! You will need to log in on your next visit.', 'success');
                    }
                    
                    // Detect if MaxMind credentials were changed - show setup modal
                    const _maxmindChanged = ('maxmind_account_id' in payload || 'maxmind_license_key' in payload);
                    if (_maxmindChanged) _cachedMaxMindStatus = null; // Clear stale validation cache
                    const _maxmindHasValues = (payload.maxmind_license_key && payload.maxmind_license_key !== '' && payload.maxmind_license_key !== '********');
                    if (_maxmindChanged && _maxmindHasValues) {
                        // Modal handles loadSettings on close
                        showGeoIPSetupModal();
                        return;
                    }
                    
                    // If disabled_features changed, purge data for newly disabled features and reload
                    if ('disabled_features' in payload) {
                        const purgeableNewlyDisabled = newlyDisabledFeatures.filter(f => PURGEABLE_FEATURES.includes(f));
                        if (purgeableNewlyDisabled.length > 0) {
                            showToast(`Purging data for ${purgeableNewlyDisabled.length} disabled feature(s)...`, 'info');
                            for (const feature of purgeableNewlyDisabled) {
                                try {
                                    await authenticatedFetch('/api/settings/purge-feature-data', {
                                        method: 'POST',
                                        headers: { 'Content-Type': 'application/json' },
                                        body: JSON.stringify({ feature })
                                    });
                                } catch (purgeErr) {
                                    console.warn(`Failed to purge data for feature '${feature}':`, purgeErr); // nosemgrep: javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring
                                }
                            }
                        }

                        showToast('Features updated - reloading...', 'success');
                        setTimeout(() => location.reload(), 600);
                        return;
                    }

                    await loadSettings();
                } catch (err) {
                    const saveBtn = content.querySelector('#settings-save-btn');
                    if (saveBtn) saveBtn.disabled = false;
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

async function showGeoIPSetupModal() {
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

function renderMaxMindStatus(status) {
    // null/undefined = not checked yet (user must click 'Validate License')
    if (status === null || status === undefined) return uiTag('Not checked', '');
    if (!status.configured) return uiTag('Not configured', '');
    return status.valid ? uiTag('License Valid', 'ok') : uiTag(status.error || 'Invalid', 'fail');
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
        <div class="ui-md-verdict-bar ${ok ? 'ui-md-verdict-ok' : 'ui-md-verdict-fail'}">${ok ? '✓ Connection Successful' : '✗ Connection Failed'}</div>
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
