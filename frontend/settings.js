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
    mailcow_api_key: 'Read-only API key',
    mailcow_api_key_rw: 'Read-write API key',
    mailcow_api_timeout: 'API timeout (seconds)',
    mailcow_api_verify_ssl: 'Verify TLS certificates',
    rspamd_password: 'Rspamd password',
    fetch_interval: 'Fetch message and security logs every (seconds)',
    fetch_count_postfix: 'Postfix logs per request',
    fetch_count_rspamd: 'Rspamd logs per request',
    fetch_count_netfilter: 'Netfilter logs per request',
    fetch_max_pages: 'Maximum pages per fetch',
    retention_days: 'Keep mail logs (days)',
    blacklist_emails: 'Exclude email addresses',
    max_correlation_age_minutes: 'Stop linking after (minutes)',
    correlation_check_interval: 'Check for links every (seconds)',
    app_port: 'Container port',
    app_title: 'App title',
    app_logo_url: 'Logo URL',
    log_level: 'Log level',
    date_format: 'Date format',
    time_format: 'Time format',
    debug: 'Debug mode',
    max_search_results: 'Maximum search results',
    csv_export_limit: 'Maximum CSV rows',
    scheduler_workers: 'Background jobs at once',
    blacklist_dns_servers: 'DNS resolvers',
    blacklist_source_server_ip: 'mailcow public IP',
    blacklist_source_transports: 'Transport IPs',
    blacklist_source_relayhosts: 'Relayhost IPs',
    blacklist_source_manual_hosts: 'Additional hosts',
    domain_spf_source_server_ip: 'mailcow public IP',
    domain_spf_source_transports: 'Transport IPs',
    domain_spf_source_relayhosts: 'Relayhost IPs',
    domain_spf_source_manual_hosts: 'Additional sending hosts',
    domain_spf_source_dmarc_history: 'IPs from DMARC reports',
    basic_auth_enabled: 'Enable Basic Auth',
    auth_username: 'Username',
    auth_password: 'Password',
    auth_max_failure_clients: 'Maximum tracked sign-in addresses',
    oauth2_enabled: 'Enable OAuth2 / OIDC',
    oauth2_provider_name: 'Provider name',
    oauth2_issuer_url: 'Issuer URL',
    oauth2_authorization_url: 'Authorization URL',
    oauth2_token_url: 'Token URL',
    oauth2_userinfo_url: 'User info URL',
    oauth2_client_id: 'Client ID',
    oauth2_client_secret: 'Client secret',
    oauth2_redirect_uri: 'Redirect URI',
    oauth2_scopes: 'Scopes',
    oauth2_use_oidc_discovery: 'Discover endpoints automatically',
    session_secret_key: 'Session signing key',
    session_max_entries: 'Maximum active sessions',
    smtp_enabled: 'Enable email delivery',
    smtp_host: 'SMTP host',
    smtp_port: 'SMTP port',
    smtp_use_tls: 'Use STARTTLS',
    smtp_use_ssl: 'Use implicit TLS',
    smtp_verify_ssl: 'Verify TLS certificates',
    smtp_user: 'SMTP username',
    smtp_password: 'SMTP password',
    smtp_from: 'From address',
    smtp_relay_mode: 'Send without authentication',
    admin_email: 'Admin email',
    blacklist_alert_email: 'Blocklist alert email',
    enable_weekly_summary: 'Send weekly summary',
    dns_change_alerts_enabled: 'Alert on DNS changes',
    smtp_abuse_enabled: 'Block mailboxes over the limit',
    smtp_abuse_threshold: 'Message limit',
    smtp_abuse_window_minutes: 'Count messages over (minutes)',
    smtp_abuse_revoke_app_passwords: 'Revoke app passwords when blocking',
    smtp_abuse_unblock_grace_minutes: 'Pause blocking after re-enabling (minutes)',
    smtp_abuse_help_address: 'Support email',
    anomaly_detection_enabled: 'Enable anomaly alerts',
    anomaly_check_interval: 'Check every (minutes)',
    anomaly_volume_multiplier: 'Sending rate multiplier',
    anomaly_volume_min_messages: 'Minimum messages before a volume alert',
    anomaly_baseline_days: 'Learn usual sending over (days)',
    anomaly_auth_failure_threshold: 'Failed logins before an alert',
    anomaly_alert_cooldown_hours: 'Wait before repeating an alert (hours)',
    dmarc_retention_days: 'Keep reports (days)',
    dmarc_manual_upload_enabled: 'Allow report uploads',
    dmarc_allow_report_delete: 'Allow report deletion',
    dmarc_insights_window_days: 'Review reports from the last (days)',
    dmarc_insights_pass_threshold: 'Minimum DMARC pass rate (%)',
    dmarc_insights_min_volume: 'Minimum messages before a suggestion',
    dmarc_imap_enabled: 'Import reports automatically',
    dmarc_imap_host: 'IMAP host',
    dmarc_imap_port: 'IMAP port',
    dmarc_imap_use_ssl: 'Use TLS',
    dmarc_imap_verify_ssl: 'Verify TLS certificates',
    dmarc_imap_user: 'IMAP username',
    dmarc_imap_password: 'IMAP password',
    dmarc_imap_folder: 'Report folders',
    dmarc_imap_delete_after: 'Delete emails after import',
    dmarc_imap_interval: 'Import every (seconds)',
    dmarc_imap_run_on_startup: 'Import when the app starts',
    dmarc_imap_batch_size: 'Emails per batch',
    dmarc_imap_scan_all_unseen: 'Check all unread emails',
    maxmind_account_id: 'MaxMind account ID',
    maxmind_license_key: 'MaxMind license key',
    raw_logs_enabled: 'Collect service logs for the Logs page',
    raw_logs_fetch_interval: 'Fetch service logs every (seconds)',
    raw_logs_fetch_count: 'Logs per service per fetch',
    raw_logs_retention_days: 'Keep service logs (days)',
    rate_limits_retention_days: 'Keep rate limit history (days)',
    raw_logs_services: 'Services',
    quarantine_rules_max_actions: 'Maximum actions per run',
    quarantine_rules_interval: 'Run Auto-Rules every (minutes)',
    quarantine_rules_log_retention_days: 'Keep Auto-Rules history (days)',
    dmarc_error_email: 'Report import error email',
    eas_devices_retention_days: 'Keep inactive devices (days)',
    tz: 'Time zone',
    // Outbound: what the setting does, in words; the search shows these names
    suppression_enabled: 'Handle undeliverable mail automatically',
    suppression_auto_detect: 'Read the mail logs for failures',
    suppression_rspamd_sync: 'Sync with Rspamd',
    suppression_hard_bounce_action: 'Permanent delivery failure',
    suppression_soft_bounce_action: 'Temporary delivery failure',
    suppression_hard_bounce_excluded_codes: 'Excluded permanent failure codes',
    suppression_soft_bounce_excluded_codes: 'Excluded temporary failure codes',
    suppression_hard_bounce_standard_codes: 'Exclude failures unrelated to the recipient address',
    suppression_soft_bounce_standard_codes: 'Exclude failures unrelated to the recipient address',
    queue_cleanup_enabled: 'Delete delayed mail',
    queue_cleanup_block: 'Block the recipients of deleted delayed mail',
    queue_cleanup_threshold_minutes: 'Queue age before deletion (minutes)',
    suppression_soft_bounce_threshold: 'Temporary failures before blocking',
    suppression_base_expiry_days: 'Base block length (days)',
    suppression_max_expiry_days: 'Maximum block length (days)',
    suppression_whitelist_domains: 'Exclude these domains',
    agent_access_enabled: 'Enable agent access',
    agent_access_url: 'App URL',
    agent_access_max_days: 'Maximum access duration (days)',
    session_idle_enabled: 'Sign out after inactivity',
    session_idle_timeout_minutes: 'Inactivity limit (minutes)',
    session_expiry_hours: 'Longest session (hours)'
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

        // X, Cancel, Escape and Back cancel; a click outside does nothing, since
        // the fields hold what was typed
        const { backdrop: overlay } = uiDialog({
            id: 'basic-auth-verify-modal', title: 'Verify credentials', size: 'sm', backdropClass: 'ui-confirm',
            close: doCancel, bodyClass: 'ui-form-stack',
            body: `
                    <div class="ui-banner ui-banner-warn"><div><b>Enable Basic Auth</b>
                        <p>Enter the username and password you configured to confirm you can sign in.</p></div></div>
                    <label class="ui-label" for="verify-auth-username">Username
                        <input type="text" id="verify-auth-username" class="ui-input" autocomplete="off" placeholder="Enter username"></label>
                    <label class="ui-label" for="verify-auth-password">Password
                        <input type="password" id="verify-auth-password" class="ui-input" autocomplete="off" placeholder="Enter password"></label>
                    <p id="verify-auth-error" class="ui-banner ui-banner-fail" style="display:none"></p>`,
            foot: `<button type="button" id="verify-auth-cancel" class="ui-btn">Cancel</button>
                <button type="button" id="verify-auth-confirm" class="ui-btn ui-btn-primary">Verify and enable</button>`,
        });

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
                errorEl.textContent = 'Enter a username.';
                errorEl.style.display = 'flex';
                usernameInput.focus();
                return;
            }
            if (!password) {
                errorEl.textContent = 'Enter a password.';
                errorEl.style.display = 'flex';
                passwordInput.focus();
                return;
            }
            cleanup();
            resolve({ username, password });
        }

        cancelBtn.addEventListener('click', doCancel);
        confirmBtn.addEventListener('click', doConfirm);

        // Enter in a field confirms; on a button (X, Cancel) it presses that button.
        // Escape cancels through the layers (router.js); a click outside does
        // nothing, since the fields hold what was typed
        overlay.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.target.closest('button')) {
                e.preventDefault();
                doConfirm();
            }
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

        // A question: no X; Cancel, Escape, Back, a click outside and a pull down cancel
        const { backdrop: overlay } = uiDialog({
            id: 'feature-disable-confirm-modal', title: `Disable ${many ? featureIds.length + ' features' : 'feature'}?`,
            label: 'Disable features', size: 'sm', role: 'alertdialog', backdropClass: 'ui-confirm', bodyClass: 'ui-form-stack',
            body: `
                    <div class="ui-banner ui-banner-fail"><div><b>Stored data will be deleted</b>
                        <p>All database records for ${many ? 'these features' : 'this feature'} will be permanently deleted. This cannot be undone.</p></div></div>
                    <div><p class="ui-label">Features being disabled</p><ul class="ui-disable-list">${featureListHtml}</ul></div>`,
            foot: `<button type="button" id="feature-disable-cancel" class="ui-btn">Cancel</button>
                <button type="button" id="feature-disable-confirm" class="ui-btn ui-btn-danger-solid">Disable and delete data</button>`,
        });

        const cancelBtn = document.getElementById('feature-disable-cancel');
        const confirmBtn = document.getElementById('feature-disable-confirm');

        function cleanup() { overlay.remove(); }

        cancelBtn.addEventListener('click', () => { cleanup(); resolve(false); });
        confirmBtn.addEventListener('click', () => { cleanup(); resolve(true); });

        // Enter confirms, but on Cancel it presses Cancel; Escape cancels through
        // the layers (router.js)
        overlay.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.target.closest('button')) { e.preventDefault(); cleanup(); resolve(true); }
        });

        overlay.addEventListener('click', (e) => {
            if (uiBackdropClick(e)) { cleanup(); resolve(false); }
        });

        // Focus confirm button
        setTimeout(() => confirmBtn.focus(), 100);
    });
}

// The short line under a field: only what the name does not say and what must be known
// before changing it (a consequence, a requirement, a value that has to be right)
var SETTINGS_FIELD_DESCRIPTIONS = {
    // mailcow
    mailcow_api_key: 'Needs read access to logs.',
    mailcow_api_key_rw: 'Optional. Needed for actions that change mailcow.',
    rspamd_password: 'Needed to view and edit Rspamd maps.',
    rspamd_url: 'Leave empty for most setups.',
    mailcow_api_verify_ssl: 'Turn off only for a trusted server with a self-signed certificate.',

    // Fetch
    retention_days: 'Older mail logs are deleted automatically.',
    blacklist_emails: 'Separate addresses with commas.',

    // Application
    app_title: 'Shown in the browser tab.',
    app_logo_url: 'Leave empty to use the project icon.',
    scheduler_workers: 'More jobs at once can speed up updates but use more database connections.',
    debug: 'Shows detailed errors. Use only for development or troubleshooting.',

    // Blocklists
    blacklist_dns_servers: 'Use your own resolver. In mailcow: 172.22.1.254.',
    blacklist_source_server_ip: 'Turn off if your server sends only through a relay.',
    blacklist_source_manual_hosts: 'Separate hosts with commas.',

    // Domains
    domain_spf_source_server_ip: 'Turn off if this IP does not send mail for your domains.',
    domain_spf_source_manual_hosts: "If a host is not allowed by a domain's SPF record, that domain shows an SPF error on the Domains page. Separate hosts with commas.",
    domain_spf_source_dmarc_history: 'Can cause false warnings.',

    // Authentication
    auth_password: 'Required for Basic Auth.',
    auth_max_failure_clients: 'Tracks failed Basic Auth sign-ins by IP address. Lower values make it easier to evade limits by switching addresses.',
    oauth2_enabled: 'Uses an external sign-in provider.',
    oauth2_provider_name: 'Shown on the sign-in button.',
    oauth2_issuer_url: 'Use the issuer URL from your provider.',
    oauth2_redirect_uri: 'Must match the redirect URI registered with your provider.',
    session_secret_key: 'Changing this key signs out other users, cancels OAuth2 sign-ins in progress and disconnects all agents. Each agent must be connected again.',
    session_expiry_hours: 'Counts from sign-in, even while the user is active. Shortening it signs out users already past the new limit.',
    session_max_entries: 'When full, new sign-ins must wait.',

    // Agents
    agent_access_url: 'Changing this address stops every agent from working. Connect each agent again using the new address.',
    agent_access_max_days: 'Existing access keeps its end date. To change it, edit the agent in the list below.',

    // SMTP
    smtp_port: '587 for STARTTLS, 465 for implicit TLS, 25 for plain.',
    smtp_use_tls: 'Keep on unless you use implicit TLS or a trusted local relay.',
    smtp_use_ssl: 'Port 465 uses implicit TLS even if this is off.',
    smtp_verify_ssl: 'Use Off only for a trusted server with a self-signed certificate. Automatic skips localhost, IP addresses and container names.',
    smtp_from: 'Required when sending without authentication. Otherwise, leave empty to use the SMTP username.',
    smtp_relay_mode: 'Use only with a trusted relay. Requires a From address.',

    // Notifications
    admin_email: 'Receives system alerts and summaries. Separate addresses with commas.',
    blacklist_alert_email: 'Leave empty to use Admin email. Separate addresses with commas.',
    enable_weekly_summary: 'Emails the weekly report to Admin email.',
    dns_change_alerts_enabled: "Sends an alert when a domain's DNS records change.",

    // Outgoing spam
    smtp_abuse_enabled: 'Needs a read-write API key.',
    smtp_abuse_threshold: 'Set this above your busiest normal sender.',
    smtp_abuse_revoke_app_passwords: 'Mail apps that use them lose access.',
    smtp_abuse_help_address: 'Leave empty to use Admin email.',

    // Anomaly detection
    anomaly_detection_enabled: 'Sends alerts without blocking mailboxes or banning IPs.',
    anomaly_check_interval: 'Each check examines this period of recent activity.',

    // DMARC & TLS
    dmarc_retention_days: 'Older DMARC and TLS reports are deleted automatically.',
    dmarc_allow_report_delete: 'Lets users with write access delete DMARC and TLS reports.',

    // DMARC & TLS IMAP
    dmarc_imap_port: 'Use 993 for SSL/TLS. Port 143 sends the connection unencrypted and requires Use TLS to be off.',
    dmarc_imap_use_ssl: 'Without TLS, the IMAP password is sent unencrypted.',
    dmarc_imap_verify_ssl: 'Use Off only for a trusted server with a self-signed certificate. Automatic skips localhost, IP addresses and container names.',
    dmarc_imap_delete_after: 'Permanently deletes imported emails from the mailbox.',
    dmarc_imap_scan_all_unseen: 'Use a dedicated report mailbox. Emails without reports are marked as read, so other users could lose track of unread mail.',
    dmarc_error_email: 'Leave empty to use Admin email. Separate addresses with commas.',

    // Logs
    raw_logs_retention_days: 'Older service logs are deleted daily.',
    rate_limits_retention_days: 'Cannot be shorter than service log retention.',
    eas_devices_retention_days: 'Set to 0 to keep inactive devices indefinitely.',
    raw_logs_services: 'Turning a service off hides it from Logs. Services marked Always collected are still collected for other pages.',

    // Outbound and Quarantine
    suppression_enabled: 'Turning this off pauses automatic handling and block expiry. Manual changes still work.',
    suppression_rspamd_sync: 'Turning it off deletes the suppression list. Needs the Rspamd password and a read-write API key.',
    suppression_whitelist_domains: 'Separate exact domains with commas. Subdomains are not included.',
    suppression_hard_bounce_excluded_codes: 'For these codes, the app does not block the address, count the failure, or delete queued mail. Postfix still returns the message to the sender.',
    suppression_soft_bounce_excluded_codes: 'For these codes, the app does not block the address or count the failure, and the message stays in the queue.',
    suppression_hard_bounce_standard_codes: 'Includes full mailboxes, sending limits, sender or message problems, network failures, and policy rejections.',
    suppression_soft_bounce_standard_codes: 'Includes full mailboxes, sending limits, sender or message problems, network failures, and policy rejections.',
    suppression_soft_bounce_threshold: 'Each failed retry counts, including retries for the same message.',
    suppression_base_expiry_days: 'Repeated failures increase the block length.',
    queue_cleanup_block: 'Requires Sync with Rspamd.',
    quarantine_rules_max_actions: 'Requires a read-write API key.',
    quarantine_rules_log_retention_days: 'Older action history is deleted automatically.',
};

// The longer explanation behind a field's "i" (uiHelp): text or a list of paragraphs.
// Only for fields that need one, and never the only place of a warning
var SETTINGS_FIELD_HELP = {
    // mailcow
    mailcow_api_key: [
        'Create the key in mailcow > System > Configuration > Access > Administrators > API.',
        'The key must be active, and its allowed IPs must include the address this app connects from.',
    ],
    mailcow_api_key_rw: [
        'Used for quarantine, queue, Fail2Ban, rate limits and Rspamd maps.',
        'Create a separate key with write access in mailcow > System > Configuration > Access > Administrators > API.',
        'The key must be active, and its allowed IPs must include the address this app connects from.',
    ],
    rspamd_url: [
        'Empty uses the mailcow URL with /rspamd. This works for most setups, even when this app runs on another server.',
        'Set it only if the path through mailcow fails, for example with a 302 from a reverse proxy, and this app can reach Rspamd directly.',
        'On the same Docker network as mailcow: http://rspamd-mailcow:11334',
    ],

    // Fetch
    fetch_interval: 'Fetches Postfix, Rspamd and Netfilter logs for Messages, Message linking and Security. Lower values update these pages more often but add load on mailcow.',
    fetch_count_postfix: 'The size of one page of logs. The app keeps fetching pages until it catches up.',
    fetch_count_rspamd: 'The size of one page of logs. The app keeps fetching pages until it catches up.',
    fetch_max_pages: 'A safety limit for Postfix and Rspamd. The most logs in one fetch is the logs per request multiplied by this number.',
    max_correlation_age_minutes: 'The app tries to link Postfix and Rspamd logs from the same message until this much time has passed since it first started tracking the message.',
    retention_days: 'Recommended: 7 for most setups, 30 for compliance.',
    blacklist_emails: 'Mail to or from these addresses is not stored or shown in Messages. Useful for a BCC archive, for example.',

    // Application
    scheduler_workers: [
        'Sets how many background jobs can run at the same time, from 1 to 64.',
        'Most background jobs share this limit, including log storage, Message linking, blocklist checks and report imports. With fewer workers, a slow report import can delay other jobs.',
    ],

    // Blocklists
    blacklist_dns_servers: 'Spamhaus rejects queries from public resolvers such as Google, Cloudflare and Quad9. Separate resolvers with commas. Leave empty to use the container resolver.',
    blacklist_source_transports: 'Checks the public IPs of active mailcow transports. Each next hop is resolved to all its public IPv4 addresses, so relay pools with several addresses are covered.',
    blacklist_source_relayhosts: 'Checks the public IPs of active mailcow relayhosts (sender-dependent transports).',
    blacklist_source_manual_hosts: 'Accepts IP addresses and hostnames. A hostname covers its public IPv4 addresses, so enter IPv6 addresses directly. These are checked in addition to the sources above and can be hosts unrelated to this mailcow server.',

    // Domains
    domain_spf_source_transports: "Checks the public IPs of active mailcow transports against each domain's SPF record. Turn on when mail leaves through transports whose IPs must be in your SPF records.",
    domain_spf_source_relayhosts: "Checks the public IPs of active mailcow relayhosts against each domain's SPF record.",
    domain_spf_source_manual_hosts: 'Accepts IP addresses and hostnames. A hostname covers its public IPv4 addresses, so enter IPv6 addresses directly. Do not add addresses that never send mail, such as an inbound-only MX.',
    domain_spf_source_dmarc_history: [
        'Uses IPs with a passing SPF result in the last 30 days of DMARC reports for each domain.',
        "With relaxed SPF alignment, an IP sending from a subdomain of an email service can pass without being in the domain's own SPF record. It then shows as a false warning.",
    ],

    // Authentication
    auth_max_failure_clients: [
        'The app keeps a count of failed sign-ins for each IP address to slow down password guessing. IPv6 addresses in the same /64 network share one count.',
        'When the table is full, the address whose last failed sign-in is oldest is removed to make room. A full table does not stop new addresses from signing in.',
        'A larger limit makes it harder for an attacker using many addresses to push earlier counts out of the table. Tracking 10,000 addresses uses roughly 10 MB of memory.',
    ],
    oauth2_enabled: 'Works with mailcow, Keycloak, Authentik and other OAuth2 or OIDC providers.',
    oauth2_issuer_url: [
        'The endpoints are discovered from this address.',
        'mailcow: https://mail.example.com',
        'Keycloak: https://keycloak.example.com/realms/myrealm',
    ],
    session_secret_key: [
        'Signs the cookies used to stay signed in and verifies OAuth2 sign-ins returning from the provider. It is used for Basic Auth as well as OAuth2.',
        'Use Generate to fill in a random key, then save. If left empty, the app creates a temporary key when it starts.',
    ],
    session_expiry_hours: [
        'Activity does not restart this time limit. The app warns users five minutes before it ends.',
        'A session cannot last longer than the limit in effect when the user signed in. To use a longer limit, the user must sign in again.',
        'Sign-out after inactivity is controlled separately by the inactivity settings.',
    ],
    session_idle_enabled: 'Typing, clicking, scrolling with the wheel and touching count as activity. Pages that refresh by themselves do not. A minute before sign-out, the page asks whether you are still there.',
    session_max_entries: 'Counts active sessions per process. New sign-ins wait until a session expires or a user signs out. Existing sessions stay signed in.',

    // Agents
    agent_access_url: 'The HTTPS address agents use to reach this app, without a path, such as https://logs.example.com.',

    // SMTP
    smtp_verify_ssl: [
        'Checks the server certificate before the password is sent, so nobody in between can read it.',
        'Off: no check. Use only for a server with a self-signed certificate.',
        'Automatic: checks host names such as smtp.example.com. Skips localhost, IP addresses and container names.',
        'On: always checks.',
    ],

    // Notifications
    dns_change_alerts_enabled: [
        'Covers SPF, DKIM, DMARC, TLSA, MTA-STS and TLS-RPT records, DNSSEC that stops validating, and a TLSA record that no longer matches the mail server certificate.',
        'The alert names the domain and shows the old and new value. A failed DNS lookup never counts as a change.',
    ],

    // Outgoing spam
    smtp_abuse_enabled: 'Disables sending for a mailbox that goes over the limit. The mailbox can still receive mail. If SMTP is set up, the owner gets an email.',
    smtp_abuse_threshold: 'The most messages one mailbox may send in the period below. Above this, sending is disabled for that mailbox.',
    smtp_abuse_revoke_app_passwords: 'Recommended. A compromised mailbox usually sends through an app password, so deleting them cuts off the attacker.',
    smtp_abuse_unblock_grace_minutes: 'After you re-enable a mailbox, it is not blocked again for this long. Without this pause it would be blocked again within a minute, because its old messages are still being counted.',
    smtp_abuse_help_address: 'Shown in the email that tells the mailbox owner that sending was paused.',

    // Anomaly detection
    anomaly_volume_multiplier: 'How far above its usual rate a mailbox must send before an alert. For example, 5 means five times its usual rate.',
    anomaly_volume_min_messages: 'A mailbox must send at least this many messages in the check period before a spike can alert. This avoids alerts on tiny numbers, such as 2 messages instead of the usual 0.',
    anomaly_auth_failure_threshold: 'Alerts when one username collects this many failed logins in the check period, which usually means password guessing.',
    anomaly_alert_cooldown_hours: 'After an alert, the same alert for the same mailbox or username stays quiet for this long. This prevents a flood of alerts during one incident.',

    // DMARC & TLS
    dmarc_insights_pass_threshold: 'A stricter policy can be suggested at or above this rate. A higher rate gives more cautious advice.',

    // DMARC & TLS IMAP
    dmarc_imap_enabled: 'Connects to the IMAP mailbox below on a schedule and imports the DMARC and TLS reports it finds. Use a mailbox that receives reports sent to the rua= addresses in your DMARC and TLS-RPT records.',
    dmarc_imap_port: 'SSL/TLS protects the connection from the start. STARTTLS, which upgrades an unencrypted connection to TLS, is not supported.',
    dmarc_imap_verify_ssl: [
        'Checks the server certificate before the password is sent, so nobody in between can read it.',
        'Off: no check. Use only for a server with a self-signed certificate.',
        'Automatic: checks host names such as imap.example.com. Skips localhost, IP addresses and container names.',
        'On: always checks.',
    ],
    dmarc_imap_folder: 'Choose one or more folders. Turn on With subfolders for a folder to import reports from that folder and all its subfolders, including any created later.',
    dmarc_imap_delete_after: 'If the server cannot remove single emails, they are marked as deleted and left for your mail client to remove.',
    dmarc_imap_scan_all_unseen: [
        'Normally, the app checks only unread emails whose subjects look like DMARC or TLS reports. Turn this on to check every unread email in the chosen folders and any subfolders included with With subfolders.',
        'Useful when reports arrive with subjects in other languages. Emails without reports are never deleted.',
    ],

    // Logs
    raw_logs_enabled: [
        'Collects raw logs from the mailcow services selected below for the Logs page.',
        'Dovecot logs are also collected for message details and Security. Ratelimited logs are collected while Rate Limits is enabled, and SOGo logs while Devices is enabled. These pages keep the logs they need when collection for the Logs page is off.',
    ],
    raw_logs_fetch_interval: 'Fetches raw logs from the services selected for the Logs page, plus any service logs needed by other pages. This schedule still applies to those services when collection for the Logs page is off.',
    raw_logs_fetch_count: 'Higher values catch more logs but add load on mailcow.',
    rate_limits_retention_days: 'Keeps the senders that hit a rate limit, for the Rate Limits page.',

    // Outbound and Quarantine
    suppression_rspamd_sync: "Keeps the suppression list and this app's part of the Rspamd recipient denylist in step, in both directions. Turning it on loads this app's blocks back from Rspamd.",
    suppression_whitelist_domains: 'These domains are excluded from automatic blocking and queue deletion.',
    quarantine_rules_max_actions: 'The most messages Auto-Rules can release or delete in one run. This prevents mass processing from a rule that is too broad.',
    quarantine_rules_interval: 'Lower values react faster to new quarantine items. Higher values add less load on mailcow.',
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
    label: 'Delete mail queued for {minutes} minutes and block new mail to those recipient addresses', hint: 'Checked every 5 minutes.' };
const SETTINGS_SOFT_BOUNCE_QUEUE_DELETE = { value: 'queue_delete', needs: 'rw',
    label: 'Delete mail queued for {minutes} minutes', hint: 'New mail to those recipient addresses is still allowed. Checked every 5 minutes.' };
const SETTINGS_CHOICE_NOTES = {
    rw: 'Add a read-write API key in Settings > mailcow. Nothing happens without it.',
    'rw-queue': 'Add a read-write API key in Settings > mailcow to delete queued mail.'
};
const SETTINGS_LOG_CHOICES = { hard: ['suppress', 'delete'], soft: ['count', 'suppress'] };
// What a choice that blocks does while Sync with Rspamd is off
const SETTINGS_SYNC_TWINS = { hard: { suppress: 'delete' }, soft: { queue: 'queue_delete', count: 'ignore', suppress: 'ignore' } };
// Settings that do nothing while another switch is off: shown greyed out and
// unclickable until it is on. Groups say it with needs:, single fields here.
const SETTINGS_FIELD_NEEDS = {
    session_idle_timeout_minutes: 'session_idle_enabled'
};

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
        '<div class="ui-set-choice-head"><span class="ui-label" id="label-' + group + '">Action</span>' +
            (lockedNames.length ? '<span class="ui-set-pill" title="Set by an environment variable, change it there">' + SETTINGS_LOCK_ICON + ' Set by ENV: ' + escapeHtml(lockedNames.join(', ')) + '</span>' : '') +
            '<span class="ui-set-pill is-changed" title="Differs from the default"' + (changed ? '' : ' hidden') + '>Changed</span></div>' +
        '<small class="ui-set-choice-note" data-sync-changed hidden></small>' +
        '<div class="ui-set-choice-list" role="radiogroup" aria-labelledby="label-' + group + '">' + rows + '</div>' +
        carriers + '<input type="hidden" id="edit-' + actionKey + '" name="' + actionKey + '" value="' + escapeHtml(action) + '" data-saved="' + escapeHtml(action) + '"' + (locked(actionKey) ? ' disabled' : '') + '>' +
        (Object.keys(resetTo).length ? '<button type="button" class="ui-set-clear is-reset" onclick="settingsResetChoice(this)"' + (changed ? '' : ' hidden') + '>Reset to default</button>' : '') +
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
        delete: 'Sync with Rspamd is off. Changed to "Delete queued mail to the failed recipient address".',
        queue_delete: `Sync with Rspamd is off. Changed to "Delete mail queued for ${minutes} minutes".`,
        ignore: 'Sync with Rspamd is off. Changed to "Do nothing; keep retrying delivery".'
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

// ── Codes left alone ──
// Each delivery failure choice has a list of status codes it leaves alone: no
// block, no count, no queue deletion. The stored setting is a comma list in a
// hidden field, so the save and Changed work as for any field; the chips and
// the Add field only edit it.
const SETTINGS_CODE_KEYS = { hard: 'suppression_hard_bounce_excluded_codes', soft: 'suppression_soft_bounce_excluded_codes' };
// The enhanced status codes registered at IANA (RFC 3463 and the RFCs after
// it), subject.detail with a plain name based on the registry's text. Codes that only report
// success, and the deprecated X.6.10, are left out: no failure carries them.
const SETTINGS_STATUS_CODES = [
    ['0.0', 'Unspecified failure'],
    ['1.0', 'Other address problem'], ['1.1', 'Invalid recipient address'], ['1.2', 'Invalid recipient domain'],
    ['1.3', 'Invalid recipient address format'], ['1.4', 'Recipient address matches multiple mailboxes'],
    ['1.6', 'Mailbox moved without a forwarding address'], ['1.7', 'Invalid sender address format'],
    ['1.8', 'Invalid sender domain'], ['1.9', 'Message relayed to a non-compliant mail server'], ['1.10', 'Recipient domain does not accept mail (null MX)'],
    ['2.0', 'Other or unspecified mailbox problem'], ['2.1', 'Mailbox disabled'], ['2.2', 'Mailbox full'],
    ['2.3', 'Message exceeds the mailbox size limit'], ['2.4', 'Mailing list expansion problem'],
    ['3.0', 'Other or unspecified mail system problem'], ['3.1', 'Mail system full'], ['3.2', 'Mail system not accepting messages'],
    ['3.3', 'Mail system does not support the requested features'], ['3.4', 'Message exceeds the mail system size limit'], ['3.5', 'Mail system configuration error'],
    ['4.0', 'Other or unspecified network or routing problem'], ['4.1', 'No response from the receiving server'], ['4.2', 'Connection failed during delivery'],
    ['4.3', 'Directory server failure'], ['4.4', 'Cannot find a delivery route'], ['4.5', 'Mail system congestion'], ['4.6', 'Routing loop detected'],
    ['4.7', 'Delivery time expired'],
    ['5.0', 'Other or unspecified protocol error'], ['5.1', 'Invalid command'], ['5.2', 'Syntax error'], ['5.3', 'Too many recipients'],
    ['5.4', 'Invalid command arguments'], ['5.5', 'Wrong protocol version'], ['5.6', 'Authentication response too long'],
    ['6.0', 'Other or unspecified message content error'], ['6.1', 'Message format not supported'], ['6.2', 'Message conversion required but not allowed'],
    ['6.3', 'Message conversion required but not supported'], ['6.5', 'Message conversion failed'], ['6.6', 'Message content not available'],
    ['6.7', 'Non-ASCII sender or recipient address not permitted'], ['6.8', 'Sending client does not allow a required UTF-8 reply'],
    ['6.9', 'Cannot deliver a message with UTF-8 headers'],
    ['7.0', 'Other or unspecified security problem'], ['7.1', 'Delivery not authorized'], ['7.2', 'Sender not allowed to send to the mailing list'],
    ['7.3', 'Security conversion required but not possible'], ['7.4', 'Security features not supported'], ['7.5', 'Cryptographic failure'],
    ['7.6', 'Cryptographic algorithm not supported'], ['7.7', 'Message integrity failure'], ['7.8', 'Invalid authentication credentials'],
    ['7.9', 'Authentication method too weak'], ['7.10', 'Encryption required'], ['7.11', 'Encryption required for the authentication method'],
    ['7.12', 'A password transition is needed'], ['7.13', 'User account disabled'], ['7.14', 'Trust relationship required'],
    ['7.15', 'Message priority too low'], ['7.16', 'Message too large for its priority'], ['7.17', 'Mailbox owner has changed'],
    ['7.18', 'Domain owner has changed'], ['7.19', 'Cannot verify recipient ownership history (RRVS)'], ['7.20', 'No passing DKIM signature found'],
    ['7.21', 'No acceptable DKIM signature found'], ['7.22', 'No valid author-matched DKIM signature found'], ['7.23', 'SPF validation failed'],
    ['7.24', 'SPF validation error'], ['7.25', 'Reverse DNS validation failed'], ['7.26', 'Multiple authentication checks failed'],
    ['7.27', 'Sender domain does not accept mail (null MX)'], ['7.28', 'Mail flood detected'], ['7.29', 'ARC validation failed'], ['7.30', 'REQUIRETLS support required']
];
const SETTINGS_STATUS_CODE_NAMES = new Map(SETTINGS_STATUS_CODES);
// Codes no registry lists, by the provider that sends them
const SETTINGS_PROVIDER_CODE_NAMES = new Map([
    ['5.2.121', "Recipient's hourly limit from one sender (Microsoft)"], ['5.2.122', "Recipient's hourly limit (Microsoft)"],
    ['5.4.8', 'MTA-STS validation failed (Microsoft)'], ['5.4.300', 'Message expired (Microsoft)']
]);
// A whole subject: x stands for every detail, also codes no list has (Microsoft's 5.7.509)
const SETTINGS_CODE_SUBJECT_NAMES = new Map([
    ['4', 'All network and routing codes'], ['5', 'All protocol codes'],
    ['6', 'All message content and media codes'], ['7', 'All security and policy codes']
]);
const SETTINGS_STANDARD_KEYS = { hard: 'suppression_hard_bounce_standard_codes', soft: 'suppression_soft_bounce_standard_codes' };
// The standard codes, by subject: failures about the sender, the message, the
// network or policy, which say nothing about the recipient's address. Kept
// equal to STANDARD_CODES in backend/app/services/bounce_policy.py (a test compares them)
const SETTINGS_STANDARD_CODES = {
    5: [
        ['Sender address', ['5.1.7', '5.1.8', '5.1.9']],
        ['Mailbox', ['5.2.2', '5.2.3', '5.2.4', '5.2.121', '5.2.122']],
        ['Mail system', ['5.3.1', '5.3.2', '5.3.3', '5.3.4', '5.3.5']],
        ['Network and routing', ['5.4.0', '5.4.2', '5.4.3', '5.4.5', '5.4.6', '5.4.7', '5.4.8', '5.4.300']],
        ['Protocol', ['5.5.1', '5.5.2', '5.5.3', '5.5.4', '5.5.5', '5.5.6']],
        ['Message content', ['5.6.x']],
        ['Security and policy', ['5.7.x']]
    ],
    4: [
        ['Unspecified failure', ['4.0.0']],
        ['Sender address', ['4.1.7', '4.1.8', '4.1.9']],
        ['Mailbox', ['4.2.1', '4.2.2', '4.2.3', '4.2.4']],
        ['Mail system', ['4.3.1', '4.3.2', '4.3.3', '4.3.4', '4.3.5']],
        ['Network and routing', ['4.4.x']],
        ['Protocol', ['4.5.x']],
        ['Message content', ['4.6.x']],
        ['Security and policy', ['4.7.x']]
    ]
};
// What the mail logs had in the last days, read once per Settings load: { days, permanent, temporary }
let settingsCodesSeen = null;

function settingsCodeName(code) {
    code = String(code);
    if (code.endsWith('.x')) return SETTINGS_CODE_SUBJECT_NAMES.get(code.split('.')[1]) || '';
    return SETTINGS_STATUS_CODE_NAMES.get(code.slice(2)) || SETTINGS_PROVIDER_CODE_NAMES.get(code) || '';
}

// Whether a code is one of the standard codes of its class
function settingsStandardCovers(code) {
    const [cls, subject] = String(code).split('.');
    return (SETTINGS_STANDARD_CODES[cls] || []).some(([, codes]) => codes.includes(code) || codes.includes(cls + '.' + subject + '.x'));
}

// The standard codes of a box are left alone now: its switch is on (or set on by ENV)
function settingsStandardOn(box) {
    const toggle = document.getElementById('edit-' + SETTINGS_STANDARD_KEYS[box.dataset.codes]);
    return !!toggle && toggle.checked;
}

// The switch for the standard codes, with the list it leaves alone (read only)
function settingsStandardCodes(kind, cls, config, lockedKeys, defaults) {
    const key = SETTINGS_STANDARD_KEYS[kind];
    if (config[key] === undefined) return '';
    const groups = SETTINGS_STANDARD_CODES[cls].map(([title, codes]) => '<div><h5>' + escapeHtml(title) + '</h5>' +
        codes.map(code => '<span><b>' + escapeHtml(code) + '</b>' + escapeHtml(settingsCodeName(code)) + '</span>').join('') + '</div>').join('');
    return '<div class="ui-set-codes-std">' +
        renderSettingsEditField(key, config[key], [], SETTINGS_FIELD_DESCRIPTIONS[key] || '', lockedKeys.has(key), defaults[key]) +
        '<details class="ui-set-codes-std-list"><summary>View excluded codes</summary><div class="ui-set-codes-groups">' + groups + '</div></details></div>';
}

// A well-formed code of the class ('5' or '4') without leading zeros, or ''
function settingsCodeOf(text, cls) {
    const match = String(text || '').trim().match(/^([45])\.(\d{1,3})\.(\d{1,3})$/);
    return match && match[1] === cls ? `${cls}.${Number(match[2])}.${Number(match[3])}` : '';
}

function settingsCodeList(field) {
    return String(field.value || '').split(/[\s,]+/).filter(Boolean);
}

function settingsBounceCodes(kind, config, lockedKeys, defaults) {
    const key = SETTINGS_CODE_KEYS[kind];
    if (config[key] === undefined) return '';
    const locked = lockedKeys.has(key);
    const cls = kind === 'hard' ? '5' : '4';
    const id = 'codes-' + kind;
    const desc = SETTINGS_FIELD_DESCRIPTIONS[key];
    // The registered codes in the shared picker (MP-4: searchable by code and meaning); a pick adds at once
    const picker = locked ? '' : uiPicker({
        id: 'settings-' + id, label: 'Status codes', value: 'Select a code', field: true, labelledBy: 'label-' + id + '-also',
        search: 'Search codes', options: SETTINGS_STATUS_CODES.map(([code, name]) => ({
            label: `${cls}.${code} ${name}`, value: `${cls}.${code}`, onclick: `settingsPickCode('${kind}', '${cls}.${code}')`
        }))
    });
    return '<div class="ui-set-field ui-set-wide ui-set-codes' + (locked ? ' is-locked' : '') + '" data-codes="' + kind + '" data-class="' + cls + '" data-default="' +
            escapeHtml(String(defaults[key] ?? '')) + '">' +
        '<div class="ui-set-choice-head"><span class="ui-label" id="label-' + id + '">Status code exceptions</span>' +
            (locked ? '<span class="ui-set-pill" title="Set by an environment variable, change it there">' + SETTINGS_LOCK_ICON + ' Set by ENV: ' + escapeHtml(key.toUpperCase()) + '</span>' : '') +
            '<span class="ui-set-pill is-changed" title="Differs from the default" hidden>Changed</span></div>' +
        '<small class="ui-set-desc">' + escapeHtml(desc) + '</small>' +
        settingsStandardCodes(kind, cls, config, lockedKeys, defaults) +
        '<span class="ui-label ui-set-codes-also" id="label-' + id + '-also">Additional codes to exclude</span>' +
        '<div class="ui-chip-row" data-codes-list aria-labelledby="label-' + id + '-also"></div>' +
        // A code the registry does not list (a provider's own, such as 5.7.509) is typed beside it
        (locked ? '' : '<div class="ui-sec-ladd ui-flush ui-set-codes-add">' + picker +
            '<span class="ui-set-codes-other"><input type="text" class="ui-input" id="' + id + '-other" autocomplete="off" spellcheck="false" maxlength="20"' +
                ' placeholder="Enter a ' + cls + '.x.x code" aria-label="Enter a ' + cls + '.x.x code" oninput="settingsCodeTyped(this)"' +
                ' onkeydown="if (event.key === \'Enter\') { event.preventDefault(); settingsAddCode(this); }">' +
            '<button type="button" class="ui-btn" onclick="settingsAddCode(this)">Add</button></span></div>' +
            '<small class="ui-set-codes-error ui-text-fail" data-codes-error role="status" hidden></small>') +
        '<div class="ui-set-codes-seen" data-codes-seen hidden></div>' +
        '<input type="hidden" id="edit-' + key + '" name="' + key + '" value="' + escapeHtml(String(config[key] ?? '')) + '"' + (locked ? ' disabled' : '') + '>' +
        (locked ? '' : '<button type="button" class="ui-set-clear is-reset" onclick="settingsResetCodes(this)" hidden>↺ Reset to default (' +
            escapeHtml(String(defaults[key] ?? '') || 'empty') + ')</button>') +
        '</div>';
}

// The chips, the codes seen in the logs that are not in the list yet, and Changed
function settingsShowCodes(box) {
    const field = box.querySelector('input[type="hidden"]');
    if (!field) return;
    const locked = field.disabled;
    const codes = settingsCodeList(field);
    const chip = code => {
        const name = settingsCodeName(code);
        return '<span class="ui-sec-chip"><b>' + escapeHtml(code) + '</b>' + (name ? ' ' + escapeHtml(name) : '') +
            (locked ? '' : '<button type="button" data-code="' + escapeHtml(code) + '" onclick="settingsRemoveCode(this)" aria-label="Remove ' +
                escapeHtml(code) + '" title="Remove">&times;</button>') + '</span>';
    };
    box.querySelector('[data-codes-list]').innerHTML = codes.length ? codes.map(chip).join('') : '<span class="ui-muted">No additional codes</span>';
    // A code the standard codes leave alone is not offered again while their switch is on
    const standard = settingsStandardOn(box);
    box.dataset.standard = String(standard);
    const covered = code => standard && settingsStandardCovers(code);
    box.querySelectorAll('.ui-picker-panel [role="option"]').forEach(option => {
        const on = covered(option.dataset.value);
        option.disabled = on;
        let tag = option.querySelector('small');
        if (on && !tag) {
            tag = document.createElement('small');
            tag.textContent = 'Already excluded';
            option.appendChild(tag);
        } else if (!on && tag) tag.remove();
    });
    const seenBox = box.querySelector('[data-codes-seen]');
    const seen = settingsCodesSeen && !locked
        ? (settingsCodesSeen[box.dataset.class === '5' ? 'permanent' : 'temporary'] || []).filter(s => !codes.includes(s.code) && !covered(s.code)) : [];
    seenBox.hidden = !seen.length;
    seenBox.innerHTML = seen.length ? '<h4 class="ui-set-codes-h">Seen in mail logs in the last ' + escapeHtml(uiCountLabel(settingsCodesSeen.days, 'day', 'days')) + '</h4>' +
        '<div class="ui-chip-row">' + seen.map(s => {
            const name = settingsCodeName(s.code);
            return '<button type="button" class="ui-chip" data-code="' + escapeHtml(s.code) + '" onclick="settingsAddSeenCode(this)" title="' +
                escapeHtml(uiCountLabel(s.count, 'failure', 'failures')) + '">+ <b>' + escapeHtml(s.code) + '</b>' + (name ? ' ' + escapeHtml(name) : '') +
                ' <small>' + escapeHtml(Number(s.count).toLocaleString()) + '</small></button>';
        }).join('') + '</div>' : '';
    const changed = !locked && field.value !== box.dataset.default;
    box.classList.toggle('is-changed', changed);
    // The list's own marker and Reset: the switch row inside has its own
    box.querySelectorAll(':scope > .ui-set-choice-head .ui-set-pill.is-changed, :scope > .is-reset').forEach(el => { el.hidden = !changed; });
}

function settingsSetCodes(box, codes) {
    const field = box.querySelector('input[type="hidden"]');
    if (!field || field.disabled) return;
    const order = code => code.split('.').map(Number);
    const sorted = [...new Set(codes)].sort((a, b) => {
        const x = order(a), y = order(b);
        return x[1] - y[1] || x[2] - y[2];
    });
    field.value = sorted.join(',');
    // A code went in or out: an earlier "Enter a code" no longer applies
    const other = box.querySelector('.ui-set-codes-other input');
    if (other) settingsCodeTyped(other);
    settingsShowCodes(box);
    field.form && field.form.dispatchEvent(new Event('input', { bubbles: true }));
}

// A code typed in the Other field
function settingsAddCode(el) {
    const box = el.closest('.ui-set-codes');
    const input = box.querySelector('.ui-set-codes-other input');
    const error = box.querySelector('[data-codes-error]');
    const cls = box.dataset.class;
    if (!input.value.trim()) return false;
    const code = settingsCodeOf(input.value, cls);
    if (!code) {
        error.textContent = `Enter a valid ${cls}.x.x code, such as ${cls}.2.2, or select one from the list.`;
        error.hidden = false;
        input.setAttribute('aria-invalid', 'true');
        return false;
    }
    settingsCodeTyped(input);
    settingsSetCodes(box, settingsCodeList(box.querySelector('input[type="hidden"]')).concat(code));
    input.value = '';
    input.focus();
    return true;
}

function settingsCodeTyped(input) {
    const error = input.closest('.ui-set-codes').querySelector('[data-codes-error]');
    error.hidden = true;
    input.removeAttribute('aria-invalid');
}

// A pick from the picker's list
function settingsPickCode(kind, code) {
    const box = document.querySelector('.ui-set-codes[data-codes="' + kind + '"]');
    if (box) settingsSetCodes(box, settingsCodeList(box.querySelector('input[type="hidden"]')).concat(code));
}

function settingsAddSeenCode(btn) {
    const box = btn.closest('.ui-set-codes');
    settingsSetCodes(box, settingsCodeList(box.querySelector('input[type="hidden"]')).concat(btn.dataset.code));
}

function settingsRemoveCode(btn) {
    const box = btn.closest('.ui-set-codes');
    const code = btn.dataset.code;
    settingsSetCodes(box, settingsCodeList(box.querySelector('input[type="hidden"]')).filter(c => c !== code));
    // The focus stays in the list: on the next chip, else on the Add field
    const next = box.querySelector('[data-codes-list] button') || box.querySelector('.ui-picker-btn');
    if (next) next.focus();
}

function settingsResetCodes(btn) {
    const box = btn.closest('.ui-set-codes');
    settingsSetCodes(box, String(box.dataset.default || '').split(/[\s,]+/).filter(Boolean));
}

// A list does nothing while its choice is Do nothing: shown dimmed, like a setting whose switch is off
function settingsShowCodesNeeds() {
    document.querySelectorAll('.ui-set-codes').forEach(box => {
        const picked = document.querySelector('input[name="choice-' + box.dataset.codes + '"]:checked');
        const off = !!picked && picked.value === 'ignore';
        box.inert = off;
        box.classList.toggle('is-off', off);
    });
}

async function settingsLoadCodesSeen(content) {
    const boxes = content.querySelectorAll('.ui-set-codes');
    if (!boxes.length) return;
    try {
        const res = await authenticatedFetch('/api/suppressions/bounce-codes');
        // Without it the lists work as before, only without suggestions
        if (!res.ok) return;
        settingsCodesSeen = await res.json();
    } catch (e) {
        return;
    }
    boxes.forEach(settingsShowCodes);
}

// ── The app's blocks in Rspamd when the sync goes off or on ──
// The list is synced with Rspamd while Suppressions and "Sync with Rspamd" are
// on. When the sync stops, or Suppressions is turned off with its list, the
// user says what happens to the blocks already in Rspamd; when it starts
// again, what is written there.
const SETTINGS_RSPAMD_CONNECTION_KEYS = ['mailcow_url', 'mailcow_api_key_rw', 'rspamd_password', 'rspamd_url'];

function settingsPlural(n, one, many) { return n === 1 ? one : many; }

function settingsErrorText(body, fallback) {
    return uiApiErrorText(body, fallback);
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
                    title: 'Turn off sync with Rspamd?',
                    message: `Deletes this app's saved list (${rows} ${settingsPlural(rows, 'entry', 'entries')}). These entries cannot be restored from Rspamd.`,
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
            title: 'Turn on sync with Rspamd?',
            message: `We cannot check this app's Rspamd blocks now: ${why} Turning on the sync writes the list's waiting changes once Rspamd can be reached.`,
            choices: [{ value: 'apply', label: 'Turn on', kind: 'primary' }]
        });
        return ok ? { action: 'apply', count: pending } : null;
    }
    const changes = `${pending} waiting ${settingsPlural(pending, 'change', 'changes')}`;
    const picked = await showChoiceModal({
        title: 'Turn on sync with Rspamd?',
        message: `Apply the ${changes}, or start fresh? Starting fresh deletes the whole list and this app's Rspamd blocks, while keeping other Rspamd entries.`,
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
        if (body.pending_count) return [`Sync with Rspamd is on, but ${body.pending_count} ${settingsPlural(body.pending_count, 'change waits', 'changes wait')}: a read-write API key is missing. Add it in Settings > mailcow > Connection.${list}`, 'error'];
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
    if (plan.action === 'fresh') return ['Sync with Rspamd is on. The list and this app\'s Rspamd blocks were cleared.', 'success'];
    return null;
}

// Texts of the session signing key's Generate and of the Basic Auth password's Remove while it is off
const SETTINGS_GENERATE_KEY = 'Generate';
const SETTINGS_PASSWORD_REMOVE_OFF = 'Turn off Basic Auth to remove the password.';

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
    // The levels the backend accepts (config.py); anything else runs as WARNING
    log_level: ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'].map(level => ({ value: level, label: level })),
    // How dates and times are written (utils.js)
    date_format: [
        { value: 'browser', label: 'Browser' },
        { value: 'DD/MM/YYYY', label: 'DD/MM/YYYY' },
        { value: 'MM/DD/YYYY', label: 'MM/DD/YYYY' },
        { value: 'DD.MM.YYYY', label: 'DD.MM.YYYY' },
        { value: 'YYYY-MM-DD', label: 'YYYY-MM-DD' }
    ],
    time_format: [
        { value: '24h', label: '24-hour (13:05)' },
        { value: '12h', label: '12-hour (1:05 PM)' },
        { value: 'browser', label: 'Browser' }
    ],
    // The Outbound bounce choices (settingsBounceChoice): {count} is the number field
    suppression_hard_bounce_action: [
        { value: 'suppress', label: 'Block new mail to the failed recipient address and delete queued mail to that address', needs: 'logs rw-queue sync' },
        { value: 'delete', label: 'Delete queued mail to the failed recipient address', needs: 'logs rw-queue', hint: 'New mail to that recipient address is still allowed.' },
        { value: 'ignore', label: 'Do nothing' }
    ],
    suppression_soft_bounce_action: [
        { value: 'count', label: 'Keep retrying delivery; block new mail to the recipient address after {count} failures', needs: 'logs sync',
            hint: 'Each failed retry counts, even for the same message.' },
        { value: 'suppress', label: 'Keep retrying delivery; block new mail to the recipient address after the first failure', needs: 'logs sync' },
        { value: 'ignore', label: 'Do nothing; keep retrying delivery' }
    ]
};

// The log level that runs: the backend reads it in any letters and runs anything else as WARNING
function settingsLogLevel(value) {
    const level = String(value || '').trim().toUpperCase();
    return SETTINGS_FIELD_OPTIONS.log_level.some(opt => opt.value === level) ? level : 'WARNING';
}

// Agents > App address for agents: the address to offer, which the person can
// change. The OAuth2 callback names the app's public address when it is set;
// otherwise the address this page is open at. Only an address the server
// accepts (https, or http on this computer) is offered, else ''
function settingsAgentUrlSuggestion(redirectUri, pageOrigin) {
    for (const candidate of [redirectUri, pageOrigin]) {
        let url;
        try {
            url = new URL(String(candidate || '').trim());
        } catch (e) {
            continue;
        }
        const host = url.hostname.toLowerCase();
        const loopback = host === 'localhost' || host === '[::1]' || /^127\.\d+\.\d+\.\d+$/.test(host);
        if (url.protocol === 'https:' || (url.protocol === 'http:' && loopback)) return url.origin;
    }
    return '';
}

// The suggestion shows in the empty field. With agent access on, it becomes the
// field's value (an unsaved change) when the form opens and when the switch is
// turned on; fill is false while typing, so a cleared field stays empty
function settingsSuggestAgentUrl(root, fill) {
    const field = root && root.querySelector('#edit-agent_access_url');
    if (!field || field.disabled) return;
    const redirect = root.querySelector('#edit-oauth2_redirect_uri');
    const suggestion = settingsAgentUrlSuggestion(redirect ? redirect.value : '', location.origin);
    field.placeholder = suggestion;
    const on = root.querySelector('#edit-agent_access_enabled');
    if (fill && on && on.checked && !field.value.trim() && suggestion) {
        field.value = suggestion;
        field.dispatchEvent(new Event('input', { bubbles: true }));
    }
}

// Agent access needs sign-in, so a person can approve each agent: with Basic
// Auth and OAuth2 both off the switch is locked and says where to turn sign-in
// on. Turning the last one off in this form also turns agent access off
function settingsLockAgentAccess(root, signInChanged, signInElsewhere) {
    const toggle = root && root.querySelector('#edit-agent_access_enabled');
    const row = toggle && toggle.closest('.ui-set-bool');
    if (!row) return;
    const signIn = !!signInElsewhere || ['basic_auth_enabled', 'oauth2_enabled'].some(key => {
        const box = root.querySelector('#edit-' + key);
        return !!box && box.checked;
    });
    if (!signIn && signInChanged && toggle.checked && !toggle.disabled) {
        toggle.checked = false;
        toggle.dispatchEvent(new Event('input', { bubbles: true }));
    }
    // Only the switch is locked and dimmed: the note stays readable, also to a screen reader
    const main = row.querySelector('.ui-set-bool-main') || toggle;
    main.inert = !signIn;
    main.classList.toggle('is-off', !signIn);
    let note = row.querySelector('[data-agent-lock]');
    if (signIn) {
        if (note) note.remove();
        return;
    }
    if (!note) {
        note = document.createElement('small');
        note.className = 'ui-text-warn';
        note.setAttribute('role', 'status');
        note.dataset.agentLock = '';
        note.textContent = 'Turn on Basic Auth or OAuth2 in Settings > Authentication first.';
        row.appendChild(note);
    }
}

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

// How far a zone's clock is from UTC now (daylight saving included), as
// "UTC+03:00"; '' for a name this browser does not know
function settingsZoneOffset(name) {
    try {
        const part = new Intl.DateTimeFormat('en-US', { timeZone: name || 'UTC', timeZoneName: 'longOffset' })
            .formatToParts(new Date()).find(p => p.type === 'timeZoneName');
        if (!part) return '';
        return part.value === 'GMT' ? 'UTC+00:00' : part.value.replace('GMT', 'UTC');
    } catch (e) {
        return '';
    }
}

// The picker's button: the zone's name, then its offset
function settingsZoneButton(name) {
    const offset = settingsZoneOffset(name);
    return escapeHtml(name || SETTINGS_TZ_NOT_SET) + (offset ? ` <small class="ui-zone-offset">${offset}</small>` : '');
}

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
    host.querySelector('.ui-picker-btn > span').innerHTML = settingsZoneButton(field.value);
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
        id: 'mailcow', label: 'mailcow', description: 'Connect this app to mailcow and Rspamd.', groups: [
            { label: 'Connection', keys: ['mailcow_url', 'mailcow_api_key', 'mailcow_api_key_rw'] },
            { label: 'Rspamd', keys: ['rspamd_password', 'rspamd_url'] },
            { label: 'Advanced', keys: ['mailcow_api_timeout', 'mailcow_api_verify_ssl'] }
        ]
    },
    {
        id: 'fetch', label: 'Fetch', description: 'Choose how often to fetch mail logs, how long to keep them and how to link logs from the same message.', groups: [
            { label: 'Timing', keys: ['fetch_interval'] },
            { label: 'Logs per request', keys: ['fetch_count_postfix', 'fetch_count_rspamd', 'fetch_count_netfilter'] },
            { label: 'Pagination', keys: ['fetch_max_pages'] },
            { label: 'Retention', keys: ['retention_days'] },
            { label: 'Excluded addresses', keys: ['blacklist_emails'] },
            { label: 'Message linking', keys: ['max_correlation_age_minutes', 'correlation_check_interval'] }
        ]
    },
    {
        id: 'application', label: 'Application', description: 'Set the app appearance, time display, and search limits.', groups: [
            { label: 'Appearance', keys: ['app_port', 'app_title', 'app_logo_url'] },
            { label: 'Time', keys: ['tz', 'date_format', 'time_format'] },
            { label: 'Logging', keys: ['log_level', 'debug'] },
            { label: 'Limits', keys: ['max_search_results', 'csv_export_limit', 'scheduler_workers'] }
        ]
    },
    {
        id: 'features', label: 'Features', description: 'Choose which features to use. Turning a feature off deletes its stored data. You will be asked to confirm when you save.', groups: [
            { label: 'Features', keys: ['disabled_features'] }
        ]
    },
    {
        id: 'blacklist', label: 'Blocklists', description: 'Choose which sending IPs to check against blocklists.', groups: [
            { label: 'Monitoring sources', keys: ['blacklist_source_server_ip', 'blacklist_source_transports', 'blacklist_source_relayhosts', 'blacklist_source_manual_hosts'] },
            { label: 'DNS resolver', keys: ['blacklist_dns_servers'] }
        ]
    },
    {
        id: 'domains', label: 'Domains', description: "Choose which sending IPs to check against your domains' SPF records.", groups: [
            { label: 'SPF check sources', keys: ['domain_spf_source_server_ip', 'domain_spf_source_transports', 'domain_spf_source_relayhosts', 'domain_spf_source_manual_hosts', 'domain_spf_source_dmarc_history'] }
        ]
    },
    {
        id: 'auth', label: 'Authentication', description: 'Choose how users sign in and how long they stay signed in.', groups: [
            { label: 'Basic Auth', intro: 'Changing sign-in methods, credentials or provider endpoints signs out other users and disconnects agents.', keys: ['basic_auth_enabled', 'auth_username', 'auth_password', 'auth_max_failure_clients'] },
            { label: 'OAuth2 / OIDC', keys: ['oauth2_enabled', 'oauth2_provider_name'] },
            { label: 'Endpoint discovery', keys: ['oauth2_issuer_url', 'oauth2_use_oidc_discovery'] },
            { label: 'Manual endpoints', keys: ['oauth2_authorization_url', 'oauth2_token_url', 'oauth2_userinfo_url'] },
            { label: 'Provider credentials', keys: ['oauth2_client_id', 'oauth2_client_secret', 'oauth2_redirect_uri', 'oauth2_scopes'] },
            { label: 'Session limits', intro: 'These limits apply to browser sessions, including Basic Auth and OAuth2 / OIDC. Agents and API tokens are not affected.', keys: ['session_idle_enabled', 'session_idle_timeout_minutes', 'session_expiry_hours'] },
            { label: 'Sessions', keys: ['session_secret_key', 'session_max_entries'] }
        ]
    },
    {
        // Managed outside the form (users.js), so it has no fields of its own
        id: 'users', label: 'Users', description: 'Manage who can sign in and what each user can do.', groups: []
    },
    {
        id: 'agents', label: 'Agents', description: 'Allow AI agents, such as Claude Code and Codex, to access and use this app.', groups: [
            { label: 'Access', keys: ['agent_access_enabled', 'agent_access_url', 'agent_access_max_days'] }
        ]
    },
    {
        id: 'smtp', label: 'SMTP', description: 'Set up email delivery for alerts and reports.', groups: [
            { label: 'Enable', keys: ['smtp_enabled'] },
            { label: 'Server', keys: ['smtp_host', 'smtp_port'] },
            { label: 'Security', keys: ['smtp_use_tls', 'smtp_use_ssl', 'smtp_verify_ssl'] },
            { label: 'Authentication', keys: ['smtp_user', 'smtp_password', 'smtp_relay_mode'] },
            { label: 'Sender', keys: ['smtp_from'] }
        ]
    },
    {
        id: 'notifications', label: 'Notifications', description: 'Choose where to send alerts.', groups: [
            { label: 'Email addresses', keys: ['admin_email', 'blacklist_alert_email', 'dmarc_error_email', 'enable_weekly_summary'] },
            { label: 'Alert types', keys: ['dns_change_alerts_enabled'] }
        ]
    },
    {
        id: 'smtp_abuse', label: 'SMTP Abuse', description: 'Block sending from mailboxes that exceed a fixed message limit within a set time. See and manage them in Security > Settings > Outgoing spam.', groups: [
            { label: 'Enable', keys: ['smtp_abuse_enabled'] },
            { label: 'Limit', keys: ['smtp_abuse_threshold', 'smtp_abuse_window_minutes'] },
            { label: 'Response', keys: ['smtp_abuse_revoke_app_passwords', 'smtp_abuse_unblock_grace_minutes', 'smtp_abuse_help_address'] }
        ]
    },
    {
        id: 'anomaly', label: 'Anomaly detection', description: 'Get alerts about unusual sending and repeated failed logins.', groups: [
            { label: 'Enable', keys: ['anomaly_detection_enabled'] },
            { label: 'Sending spikes', keys: ['anomaly_volume_multiplier', 'anomaly_volume_min_messages', 'anomaly_baseline_days'] },
            { label: 'Failed logins', keys: ['anomaly_auth_failure_threshold'] },
            { label: 'Timing', keys: ['anomaly_check_interval', 'anomaly_alert_cooldown_hours'] }
        ]
    },
    {
        id: 'dmarc', label: 'DMARC & TLS', description: 'Manage report retention, uploads, deletion, and policy suggestions.', groups: [
            { label: 'Retention', keys: ['dmarc_retention_days'] },
            { label: 'Features', keys: ['dmarc_manual_upload_enabled', 'dmarc_allow_report_delete'] },
            { label: 'Policy suggestions', keys: ['dmarc_insights_window_days', 'dmarc_insights_pass_threshold', 'dmarc_insights_min_volume'] }
        ]
    },
    {
        id: 'dmarc_imap', label: 'DMARC & TLS IMAP', description: 'Import DMARC and TLS reports from a mailbox.', groups: [
            { label: 'Enable', keys: ['dmarc_imap_enabled'] },
            { label: 'Connection', keys: ['dmarc_imap_host', 'dmarc_imap_port', 'dmarc_imap_use_ssl', 'dmarc_imap_verify_ssl'] },
            { label: 'Authentication', keys: ['dmarc_imap_user', 'dmarc_imap_password'] },
            { label: 'Settings', keys: ['dmarc_imap_folder', 'dmarc_imap_delete_after', 'dmarc_imap_interval', 'dmarc_imap_run_on_startup', 'dmarc_imap_batch_size', 'dmarc_imap_scan_all_unseen'] }
        ]
    },
    {
        id: 'maxmind', label: 'MaxMind', description: 'Set up GeoIP to show where IP addresses are located.', groups: [
            { label: 'Credentials', keys: ['maxmind_account_id', 'maxmind_license_key'] },
            { label: 'Status', keys: [] }  // Status will be displayed separately, not as editable field
        ]
    },
    {
        id: 'logs', label: 'Logs', description: 'Choose which service logs to collect and how long to keep them.', groups: [
            { label: 'Enable', keys: ['raw_logs_enabled'] },
            { label: 'Collection', keys: ['raw_logs_fetch_interval', 'raw_logs_fetch_count'] },
            { label: 'Retention', keys: ['raw_logs_retention_days', 'rate_limits_retention_days'] },
            { label: 'Services', keys: ['raw_logs_services'] }
        ]
    },
    {
        id: 'devices', label: 'Devices', description: 'Choose how long to keep inactive devices.', groups: [
            { label: 'Retention', keys: ['eas_devices_retention_days'] }
        ]
    },
    {
        // Was spam_filter (Queue Management); the old address opens this one (router.js). Hidden while Suppressions is off
        id: 'outbound', label: 'Outbound', description: 'Choose what happens when outgoing mail cannot be delivered.', groups: [
            // The sync belongs to the list, not to the automatic handling: a list kept by hand syncs too
            { label: 'Rspamd', keys: ['suppression_rspamd_sync'] },
            { label: 'Automatic handling', keys: ['suppression_enabled'] },
            // Reading the logs is set by the choices (settingsSyncBounce)
            // Each choice is followed by the codes it leaves alone (settingsBounceCodes)
            { label: 'Permanent delivery failure', choice: 'hard', needs: 'suppression_enabled',
                keys: ['suppression_hard_bounce_action', 'suppression_auto_detect', 'suppression_hard_bounce_standard_codes', 'suppression_hard_bounce_excluded_codes'],
                intro: 'The receiving server rejected the message permanently. (5.x.x)' },
            { label: 'Temporary delivery failure', choice: 'soft', needs: 'suppression_enabled',
                keys: ['queue_cleanup_enabled', 'queue_cleanup_block', 'suppression_soft_bounce_action', 'queue_cleanup_threshold_minutes', 'suppression_soft_bounce_threshold',
                    'suppression_soft_bounce_standard_codes', 'suppression_soft_bounce_excluded_codes'],
                intro: 'Postfix keeps the message and retries. (4.x.x)' },
            // A block reaches Rspamd only through the sync: without it nothing is blocked
            { label: 'Block duration', needs: 'suppression_enabled suppression_rspamd_sync', keys: ['suppression_base_expiry_days', 'suppression_max_expiry_days'] },
            { label: 'Exceptions', needs: 'suppression_enabled', keys: ['suppression_whitelist_domains'] }
        ]
    },
    {
        id: 'quarantine', label: 'Quarantine', description: 'Set how often Auto-Rules run and how many messages they can release or delete.', groups: [
            { label: 'Auto-Rules schedule', keys: ['quarantine_rules_max_actions', 'quarantine_rules_interval', 'quarantine_rules_log_retention_days'] }
        ]
    }
];

// Groups the Edit-configuration tabs into a vertical sidebar. Order here =
// display order. A group with no visible tabs is omitted; any visible tab not
// listed here falls into the last group automatically (so new tabs never
// silently disappear).
var SETTINGS_TAB_GROUPS = [
    { label: 'General', tabs: ['features', 'application'] },
    { label: 'mailcow', tabs: ['mailcow', 'fetch', 'logs'] },
    { label: 'Alerts', tabs: ['notifications', 'smtp'] },
    { label: 'Security', tabs: ['auth', 'users', 'agents', 'anomaly', 'smtp_abuse'] },
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

// The Basic Auth password cannot be removed while Basic Auth is on: its Remove is
// off then, and a removal already chosen is taken back
function settingsLockPasswordRemove(root) {
    const btn = root && root.querySelector('[data-needs-basic-off]');
    const basic = root && root.querySelector('#edit-basic_auth_enabled');
    if (!btn || !basic) return;
    const on = basic.type === 'checkbox' ? basic.checked : basic.value === 'true';
    if (on && btn.closest('.is-removing')) settingsRemoveSecret(btn);
    btn.disabled = on;
    btn.title = on ? SETTINGS_PASSWORD_REMOVE_OFF : '';
    const note = root.querySelector('[data-remove-note]');
    if (note) note.classList.toggle('hidden', !on);
}

// Session signing key: a new random key, 32 bytes as hex, into a new-value field
function settingsGenerateSecret(btn) {
    const field = btn.closest('.ui-set-field');
    const replace = field && field.querySelector('.ui-set-secret button');
    if (replace) settingsReplaceSecret(replace);
    const input = field && field.querySelector('input[type="password"]');
    if (!input) return;
    input.value = Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.focus();
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
    const help = SETTINGS_FIELD_HELP[key] ? uiHelp(label, SETTINGS_FIELD_HELP[key]) : '';
    // The "i" sits beside the name, outside its label: a button does not belong in a label
    const fieldName = name => help ? '<div class="ui-set-name">' + name + help + '</div>' : name;
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
        'enable_weekly_summary', 'agent_access_enabled', 'agent_access_url'
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
                'Reset to default' + (isBool ? ': ' + defaultLabel : ' (' + defaultLabel + ')') + '</button>';
        } else if (!isBool && String(displayVal).trim() !== '' && !(sensitive && displayVal === '') && !(hasDefault && !isUserSpecific && String(displayVal) === String(defaultValue))) {
            clearBtnHtml = '<button type="button" class="settings-clear-btn ui-set-clear" data-key="' + keyAttr + '" data-default="' + (hasDefault ? escapeHtml(String(defaultValue)) : '') + '" data-sensitive="' + sensitive + '" data-isbool="false">' +
                'Clear</button>';
        }
    }

    // IMAP folders: the chosen folders as rows, and a button that opens the folder
    // picker (settingsChooseFolders). The hidden field carries the value into the save
    if (key === 'dmarc_imap_folder') {
        const raw = value === null || value === undefined ? '' : String(value);
        return '<div class="ui-set-field' + (envLocked ? ' is-locked' : '') + '">' + fieldName('<span class="ui-label" id="label-' + keyAttr + '">' + escapeHtml(label) + '</span>') +
            descHtml +
            (envLocked ? '<p class="ui-set-env">' + LOCK + ' Set by ENV (DMARC_IMAP_FOLDER), change it there</p>' : '') +
            '<div class="ui-set-folders" role="group" aria-labelledby="label-' + keyAttr + '"><ul class="ui-set-folder-rows" data-folder-rows>' + settingsFolderRows(raw) + '</ul>' +
            (envLocked ? '' : '<div><button type="button" class="ui-btn ui-btn-sm" onclick="settingsChooseFolders()">Choose folders</button></div>') + '</div>' +
            '<input type="hidden" id="edit-' + keyAttr + '" name="' + keyAttr + '" value="' + uiEntityAttr(raw) + '"' + (envLocked ? ' disabled' : '') + '>' +
            clearBtnHtml + '</div>';
    }

    // A value that differs from its default is marked, so a changed setting stands out
    const changed = (isChanged || isSensitiveChanged) && !envLocked ? ' is-changed' : '';
    const changedPill = changed ? ' <span class="ui-set-pill is-changed" title="Differs from the default">Changed</span>' : '';

    const generateHtml = key === 'session_secret_key' && !envLocked
        ? '<div><button type="button" class="ui-btn ui-btn-sm" onclick="settingsGenerateSecret(this)">' + escapeHtml(SETTINGS_GENERATE_KEY) + '</button></div>' : '';

    // A stored secret: say so, and offer Replace and Remove instead of a masked field
    if (sensitive && displayVal === '********') {
        return '<div class="ui-set-field' + (envLocked ? ' is-locked' : '') + '">' + fieldName('<label class="ui-label">' + escapeHtml(label) + labelLockIcon + '</label>') + descHtml +
            '<div class="ui-set-secret"><span class="ui-set-secret-state">' + (envLocked ? 'Stored in the environment' : 'Stored') + '</span>' +
            (envLocked ? '' : '<button type="button" class="ui-btn ui-btn-sm" onclick="settingsReplaceSecret(this)">Replace</button>' +
                '<button type="button" class="ui-btn ui-btn-sm" onclick="settingsRemoveSecret(this)"' + (key === 'auth_password' ? ' data-needs-basic-off' : '') + '>Remove</button>') +
            '<input type="hidden" id="edit-' + keyAttr + '" name="' + keyAttr + '" value="********"' + (envLocked ? ' disabled' : '') + '></div>' +
            (key === 'auth_password' && !envLocked ? '<small class="ui-muted hidden" data-remove-note>' + escapeHtml(SETTINGS_PASSWORD_REMOVE_OFF) + '</small>' : '') +
            generateHtml + '</div>';
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
        return '<div class="ui-set-field ui-set-seg' + (envLocked ? ' is-locked' : '') + changed + '">' + fieldName('<span class="ui-label" id="label-' + keyAttr + '">' + escapeHtml(label) + labelLockIcon + changedPill + '</span>') +
            descHtml +
            '<div class="ui-seg" role="group" aria-labelledby="label-' + keyAttr + '">' + buttons + '</div>' +
            '<input type="hidden" id="edit-' + keyAttr + '" name="' + keyAttr + '" value="' + escapeHtml(current) + '"' + (envLocked ? ' disabled' : '') + '>' +
            segClearHtml + '</div>';
    }

    if (isBool) {
        // The whole row toggles, like a Features row: the row is the label (so its text is phrasing content)
        const asSpan = html => html.replace(/^<p /, '<span ').replace(/<\/p>$/, '</span>');
        const boolName = escapeHtml(label) + labelLockIcon + (envLocked ? '' : (isChanged ? ' <span class="ui-set-pill is-changed" title="Differs from the default">Changed</span>' : ''));
        const boolBox = '<input type="checkbox" id="edit-' + keyAttr + '" name="' + keyAttr + '" ' + (displayVal ? 'checked' : '') + ' ' + disabledAttr + ' class="ui-check">';
        const boolRow = help
            ? '<div class="ui-set-bool-main">' + boolBox + '<div class="ui-set-bool-text">' +
                fieldName('<label for="edit-' + keyAttr + '" class="ui-set-bool-label">' + boolName + '</label>') + descHtml + '</div></div>'
            : '<label for="edit-' + keyAttr + '" class="ui-set-bool-main">' + boolBox +
                '<span class="ui-set-bool-text"><span class="ui-set-bool-label">' + boolName + '</span>' + asSpan(descHtml) + asSpan(envLockedHtml) + '</span></label>';
        return '<div class="ui-set-bool' + (envLocked ? ' is-locked' : (isChanged ? ' is-changed' : '')) + '">' + boolRow +
            clearBtnHtml + '</div>';
    }

    const zones = key === 'tz' ? settingsTimeZoneNames() : [];
    if (zones.length) {
        const current = String(displayVal).trim();
        // A name the server or this browser does not know: the app runs in UTC until it is fixed
        const unknown = current !== '' && (!settingsTimeZoneKnown(current)
            || (typeof appTimezoneStatus !== 'undefined' && appTimezoneStatus.valid === false && appTimezoneStatus.configured === current));
        const names = current && !zones.includes(current) ? [current, ...zones] : zones;
        // A long list, so a picker with a search (utils.js, uiPicker); the hidden field holds the value.
        // Each zone shows its offset from UTC at its end
        const options = [{ value: '', label: SETTINGS_TZ_NOT_SET }, ...names.map(name => ({ value: name, label: name + (name === current && unknown ? ' (unknown)' : '') }))]
            .map(o => ({ ...o, hint: settingsZoneOffset(o.value) || undefined, selected: o.value === current, onclick: 'settingsPickZone(this)' }));
        const picker = uiPicker({
            id: 'settings-' + key, label, value: settingsZoneButton(current), options, search: 'Search time zones',
            field: true, labelledBy: 'label-' + keyAttr, disabled: envLocked
        });
        // The description already says to pick the server's zone; only a name the app cannot use needs a word more
        const note = unknown
            ? '<small class="ui-text-warn" role="status" data-zone-note>' + escapeHtml(`"${current}" is not a known time zone, so the app uses UTC. `) +
                (envLocked ? 'Fix TZ in the environment.' : 'Pick a time zone from the list.') + '</small>'
            : '';
        return '<div class="ui-set-field' + (envLocked ? ' is-locked' : '') + '">' + fieldName('<span class="ui-label" id="label-' + keyAttr + '">' + escapeHtml(label) + labelLockIcon + changedPill + '</span>') +
            descHtml + picker +
            '<input type="hidden" id="edit-' + keyAttr + '" name="' + keyAttr + '" value="' + escapeHtml(current) + '" data-saved="' + escapeHtml(current) + '"' + (envLocked ? ' disabled' : '') + '>' +
            note + clearBtnHtml + '</div>';
    }

    // Dropdown for fields with predefined options
    const fieldOptions = SETTINGS_FIELD_OPTIONS[key];
    if (fieldOptions) {
        let optionsHtml = '';
        // A stored level in other letters, or one the backend does not know, shows as what runs
        const current = key === 'log_level' ? settingsLogLevel(displayVal) : String(displayVal);
        fieldOptions.forEach(function(opt) {
            const selected = current === opt.value ? 'selected' : '';
            optionsHtml += '<option value="' + escapeHtml(opt.value) + '" ' + selected + '>' + escapeHtml(opt.label) + '</option>';
        });
        return '<div class="ui-set-field' + (envLocked ? ' is-locked' : '') + '">' + fieldName('<label for="edit-' + keyAttr + '" class="ui-label">' + escapeHtml(label) + labelLockIcon + changedPill + '</label>') +
            descHtml +
            '<select id="edit-' + keyAttr + '" name="' + keyAttr + '" ' + disabledAttr + ' class="ui-select' + changed + '">' +
            optionsHtml + '</select>' +
            clearBtnHtml +
            envLockedHtml + '</div>';
    }

    const inputType = sensitive ? 'password' : (isNum ? 'number' : 'text');
    const placeholder = envLocked ? 'Set by ENV' : (sensitive ? 'Not set' : '');
    const valAttr = (isBool ? '' : displayVal);
    return '<div class="ui-set-field' + (envLocked ? ' is-locked' : '') + '">' + fieldName('<label for="edit-' + keyAttr + '" class="ui-label">' + escapeHtml(label) + labelLockIcon + changedPill + '</label>') +
        descHtml +
        '<input type="' + inputType + '" id="edit-' + keyAttr + '" name="' + keyAttr + '" value="' + escapeHtml(valAttr) + '" placeholder="' + escapeHtml(placeholder) + '" ' + disabledAttr + ' class="ui-input' + changed + '">' +
        generateHtml + clearBtnHtml +
        envLockedHtml + '</div>';
}

// Before a save: every changed field must hold a value it accepts (a number in a
// number field, at least its minimum). The first one that does not is opened in
// its section, marked, and says what is wrong under it; nothing is sent
function settingsCheckFields(form, initialValues, fieldValue) {
    form.querySelectorAll('[aria-invalid="true"]').forEach(el => el.removeAttribute('aria-invalid'));
    form.querySelectorAll('.ui-set-invalid').forEach(el => el.remove());
    const bad = [...form.querySelectorAll('input, select, textarea')].filter(el => {
        if (el.disabled || el.type === 'hidden') return false;
        const name = el.name || el.dataset.mirror;
        if (name && initialValues.has(name) && initialValues.get(name) === fieldValue(el)) return false;
        return !el.checkValidity();
    });
    // A value shown twice (a mirror of one setting) is named once, where it can be edited
    const usable = el => !el.closest('[inert]') && el.getClientRects().length > 0;
    const keyOf = el => el.name || el.dataset.mirror;
    const named = bad.filter((el, i) => {
        const key = keyOf(el);
        if (!key) return true;
        const same = bad.filter(other => keyOf(other) === key);
        return el === (same.find(usable) || same[0]);
    });
    bad.length = 0;
    bad.push(...named);
    if (!bad.length) return true;
    bad.forEach(el => {
        el.setAttribute('aria-invalid', 'true');
        const note = document.createElement('small');
        note.className = 'ui-set-invalid ui-text-fail';
        note.id = `${el.id || el.name}-invalid`;
        note.textContent = el.validationMessage || 'This value is not valid.';
        el.setAttribute('aria-describedby', [el.getAttribute('aria-describedby'), note.id].filter(Boolean).join(' '));
        // Under the field's line, not inside a sentence the field is part of
        const line = el.closest('.ui-set-choice-opt, .ui-set-field, .ui-set-bool, .ui-set-wide');
        if (line) line.appendChild(note);
        else el.insertAdjacentElement('afterend', note);
        el.addEventListener('input', () => {
            el.removeAttribute('aria-invalid');
            note.remove();
        }, { once: true });
    });
    const first = bad[0];
    // Its section opens first, so the field can take the focus
    const panel = first.closest('[id^="settings-tab-panel-"]');
    if (panel && panel.classList.contains('hidden')) {
        const tab = form.closest('#settings-content')?.querySelector(`.settings-edit-tab[data-tab="${panel.id.replace('settings-tab-panel-', '')}"]`);
        if (tab) tab.click();
    }
    first.focus({ preventScroll: true });   // Settings' own area scrolls, not the app frame (scrollIntoView can pan a phone's window)
    { let area = first.parentElement; while (area && !(area.scrollHeight > area.clientHeight && /auto|scroll/.test(getComputedStyle(area).overflowY))) area = area.parentElement; if (area) area.scrollTop += first.getBoundingClientRect().top - area.getBoundingClientRect().top - area.clientHeight / 2; }
    const label = first.closest('.ui-set-field, .ui-set-bool, .ui-set-wide')?.querySelector('.ui-label');
    const name = label ? label.textContent.replace(/\s+/g, ' ').trim() : 'A field';
    showToast(bad.length === 1 ? `${name}: ${first.validationMessage}` : `${bad.length} fields need a valid value, starting with ${name}`, 'error');
    return false;
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
                data.legacy_auth_enabled = editableData.legacy_auth_enabled === true;
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
                if ((appInfo || versionInfo) && !uiUnsavedCount({ route: 'settings', reload: true })) {
                    const currentData = { ...data };
                    if (appInfo) {
                        currentData.app_version = appInfo.version;
                    }
                    if (versionInfo) {
                        currentData.version_info = versionInfo;
                    }
                    renderSettings(content, currentData);
                    // A picker open meanwhile (Time Zone, codes left alone) keeps its search and the focus (MP-2)
                    uiPickerRefocus();
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
                <p class="ui-text-fail">Could not load settings. Reload this page to try again.</p>
                <p>${escapeHtml(error.message)}</p>
            </div>
        `;
    }
}

// The latest version, its state and the update note, by id
function renderLatestVersionState(versionInfo) {
    // The server answers "unknown" when GitHub could not be reached
    if (versionInfo.latest_version === 'unknown') return `Not known ${uiTag('Check failed', 'warn')}`;
    const tag = versionInfo.update_available ? uiTag('Update available', 'ok')
        : versionInfo.latest_version ? uiTag('Up to date', 'info') : '';
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
                <a href="https://github.com/ShlomiPorush/mailcow-logs-viewer/releases/latest" target="_blank" rel="noopener noreferrer" class="ui-link">View release notes</a>
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
        ['Fetch interval', `${escapeHtml(String(config.fetch_interval || 0))} seconds`],
        ['Postfix logs per request', `${escapeHtml(String(config.fetch_count_postfix || config.fetch_count || 0))} per request`],
        ['Rspamd logs per request', `${escapeHtml(String(config.fetch_count_rspamd || config.fetch_count || 0))} per request`],
        ['Netfilter logs per request', `${escapeHtml(String(config.fetch_count_netfilter || config.fetch_count || 0))} per request`],
        ['Maximum pages per fetch', `${escapeHtml(String(config.fetch_max_pages || 50))}`],
        ['Retention', `${escapeHtml(String(config.retention_days || 0))} days`],
        ['Stop linking after', `${escapeHtml(String(config.max_correlation_age_minutes || 10))} minutes`],
        ['Check for links every', `${escapeHtml(String(config.correlation_check_interval || 120))} seconds`],
        ['Time zone', escapeHtml(config.timezone || 'N/A')],
        ['Date format', escapeHtml(config.date_format || 'browser')],
        ['Time format', escapeHtml(config.time_format || '24h')],
        ['Log level', escapeHtml(settingsLogLevel(config.log_level))],
        ['Excluded email addresses', config.blacklist_enabled ? `Enabled (${escapeHtml(String(config.blacklist_count))} addresses)` : 'Disabled'],
        ['Background job workers', `${escapeHtml(String(config.scheduler_workers || 4))}`],
    ];

    const editing = !!(data.settings_edit_via_ui_enabled && data.editable_config);
    content.innerHTML = `
        ${!data.settings_edit_via_ui_enabled ? `<div class="ui-list-note ui-flush">${uiLocked('Editing settings is off',
            'To edit settings here, set <code>SETTINGS_EDIT_VIA_UI_ENABLED=true</code> in <code>.env</code> and run <code>docker compose up -d</code>.', '')}</div>` : ''}

        ${!data.settings_edit_via_ui_enabled ? `
        <section class="ui-panel">
            <div class="ui-panel-head">Runtime</div>
            <div class="ui-md-ids ui-set-facts">
                ${readOnlyFacts.map(([label, value]) => `<div class="ui-md-fact"><span>${label}</span><div>${value}</div></div>`).join('')}
                ${Object.keys(CREDENTIAL_CHECKS).map(name => `<div class="ui-md-fact"><span>${CREDENTIAL_CHECKS[name].label}</span>${credentialCheckFact(name, config[name + '_status'], '')}</div>`).join('')}
                <div class="ui-md-fact"><span>MaxMind status</span>
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
                if (tab.id === 'maxmind' || tab.id === 'users') return true;
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
                if (keysInTab.length === 0 && tab.id !== 'maxmind' && tab.id !== 'users') return;
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
                    const facts = [['Email delivery', onOff(data.smtp_configuration.enabled) + '<button type="button" onclick="testSmtpConnection()" class="ui-btn ui-btn-sm">Send test email</button>']];
                    if (data.smtp_configuration.enabled) {
                        facts.push(['Server', '<span class="ui-mono">' + escapeHtml(data.smtp_configuration.host) + ':' + escapeHtml(data.smtp_configuration.port) + '</span>']);
                        facts.push(['Admin email', '<span class="ui-mono">' + escapeHtml(data.smtp_configuration.admin_email || 'N/A') + '</span>']);
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
                        ['Automatic report import', onOff(data.dmarc_configuration.imap_sync_enabled) + '<button type="button" onclick="testImapConnection()" class="ui-btn ui-btn-sm">Test IMAP connection</button>'],
                        ['Report uploads', onOff(data.dmarc_configuration.manual_upload_enabled, 'fail')]
                    ];
                    if (data.dmarc_configuration.imap_sync_enabled) {
                        facts.push(['IMAP server', '<span class="ui-mono">' + escapeHtml(data.dmarc_configuration.imap_host || 'N/A') + '</span>']);
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
                        ['Database status', '<span id="geoip-db-status" class="ui-chip-row">' + (renderGeoIPDbStatus(geoipCfg) || '<span class="ui-muted">Not configured</span>') + '</span>'],
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
                    if (group.choice) tabsHtml += settingsBounceChoice(group.choice, data.editable_config, envLockedKeys, defaults)
                        + settingsBounceCodes(group.choice, data.editable_config, envLockedKeys, defaults);
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
            <!-- The column scrolls on a wide screen; a section redrawn by its refresh keeps the place (app.js uiReplaceKeepingFocus) -->
            <div class="settings-edit-content" data-keep-scroll>
                ${!data.settings_migrated ? `<div class="ui-set-actions" id="settings-edit-actions">
                    <button type="button" id="settings-import-env-btn" class="ui-btn ui-btn-primary">Migrate Settings from ENV</button>
                    <p class="ui-set-migrate-note">Copy your current configuration to the database to start editing settings here.</p>
                </div>` : ''}
                <form id="settings-edit-form" class="ui-set-form">
                    <!-- Until the first migration nothing can be saved, so the fields stay
                         read-only instead of accepting edits that would be lost -->
                    <fieldset class="ui-set-fieldset"${data.settings_migrated ? '' : ' disabled'}>
                    ` + tabsHtml + `
                    </fieldset>
                </form>
                <!-- Connected agents (agents.js) under the Agents section. Outside the form:
                     its buttons act at once, and the fieldset above is disabled until migration -->
                <div class="hidden" data-tab-extra="users"><div id="users-panel" class="ui-agent-sections"></div></div>
                <div class="hidden" data-tab-extra="agents"><div id="agents-panel" class="ui-agent-sections"></div></div>
            </div>
        </div>
        ${uiSaveBar('settings-savebar', { form: 'settings-edit-form', discard: 'loadSettings()' })}
        `;
        })() : ''}

        ${!data.settings_edit_via_ui_enabled ? `
        <div class="ui-dash-grid ui-status-pair">
            <!-- Global SMTP Configuration -->
            <section class="ui-panel">
                <div class="ui-panel-head">SMTP configuration
                    <button type="button" onclick="testSmtpConnection()" class="ui-btn ui-btn-sm ui-head-actions">Send test email</button></div>
                <div class="ui-kv"><span>Email delivery</span><b>${data.smtp_configuration?.enabled ? uiTag('Enabled', 'ok') : uiTag('Disabled', '')}</b></div>
                ${data.smtp_configuration?.enabled ? `
                <div class="ui-kv"><span>Server</span><b class="ui-mono ui-kv-small">${escapeHtml(String(data.smtp_configuration.host))}:${escapeHtml(String(data.smtp_configuration.port))}</b></div>
                <div class="ui-kv"><span>Admin email</span><b class="ui-mono ui-kv-small">${escapeHtml(data.smtp_configuration.admin_email || 'N/A')}</b></div>
                ` : ''}
            </section>

            <!-- DMARC & TLS report management -->
            <section class="ui-panel">
                <div class="ui-panel-head">DMARC &amp; TLS reports
                    <button type="button" onclick="testImapConnection()" class="ui-btn ui-btn-sm ui-head-actions">Test IMAP connection</button></div>
                <div class="ui-kv"><span>Automatic report import</span><b>${data.dmarc_configuration?.imap_sync_enabled ? uiTag('Enabled', 'ok') : uiTag('Disabled', '')}</b></div>
                <div class="ui-kv"><span>Report uploads</span><b>${data.dmarc_configuration?.manual_upload_enabled ? uiTag('Enabled', 'ok') : uiTag('Disabled', 'fail')}</b></div>
                ${data.dmarc_configuration?.imap_sync_enabled ? `<div class="ui-kv"><span>IMAP server</span><b class="ui-mono ui-kv-small">${escapeHtml(data.dmarc_configuration.imap_host || 'N/A')}</b></div>` : ''}
            </section>
        </div>

        <!-- Users (users.js) and connected agents (agents.js): managed here even while editing settings is off -->
        <div id="users-panel" class="ui-agent-sections"></div>
        <div id="agents-panel" class="ui-agent-sections"></div>
        ` : ''}
    `;

    if (typeof loadUsersPanel === 'function') {
        loadUsersPanel();
    }
    if (typeof loadAgentsPanel === 'function') {
        loadAgentsPanel();
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
            // Parts of a section that live outside the form (Agents)
            content.querySelectorAll('[data-tab-extra]').forEach(function (extra) {
                extra.classList.toggle('hidden', extra.getAttribute('data-tab-extra') !== tabId);
            });

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
        // Message linking was a section of its own; its old address opens Fetch, where it is now
        if (settingsTab === 'correlation') {
            settingsTab = 'fetch';
            if (typeof routerSyncSubpage === 'function') routerSyncSubpage('settings', 'fetch', true);
        }
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
                    // So do the IMAP folder rows
                    if (key === 'dmarc_imap_folder') settingsShowFolders(el);
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
        // The folder picker asks whether the IMAP connection has unsaved changes
        settingsFieldUnsaved = name => {
            const el = form && form.querySelector('[name="' + CSS.escape(name) + '"]');
            return !!el && initialValues.has(name) && initialValues.get(name) !== fieldValue(el);
        };
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
        // Leaving Settings drops what is not saved; moving between its sections keeps it
        uiUnsavedRegister('settings', {
            count: () => {
                if (!form || !form.isConnected || !form.getClientRects().length) return 0;
                let n = 0;
                form.querySelectorAll('[name]:not([data-choice])').forEach(el => {
                    if (initialValues.has(el.name) && initialValues.get(el.name) !== fieldValue(el)) n++;
                });
                return n;
            },
            keeps: target => target.route === 'settings' && !target.reload,
        });
        if (form) {
            form.addEventListener('input', updateDirty);
            form.addEventListener('change', updateDirty);
            // An Outbound choice says when it needs the read-write key, and
            // whether it differs from the default, also after typing in its number fields
            const showChoices = () => content.querySelectorAll('.ui-set-choice').forEach(settingsShowChoice);
            showChoices();
            form.addEventListener('input', showChoices);
            // The codes left alone: their chips, and dimmed while their choice is Do nothing
            content.querySelectorAll('.ui-set-codes').forEach(settingsShowCodes);
            // A box follows its standard codes switch (Reset on its row: the clear buttons below)
            const followStandard = () => content.querySelectorAll('.ui-set-codes').forEach(box => {
                if (String(settingsStandardOn(box)) !== box.dataset.standard) settingsShowCodes(box);
            });
            form.addEventListener('change', followStandard);
            form.addEventListener('input', followStandard);
            settingsShowCodesNeeds();
            form.addEventListener('change', settingsShowCodesNeeds);
            form.addEventListener('input', settingsShowCodesNeeds);
            settingsLoadCodesSeen(content);
            settingsShowNeeds(content);
            settingsLockPasswordRemove(content);
            settingsApplySync(false);
            settingsSuggestAgentUrl(content, true);
            settingsLockAgentAccess(content, false, data.legacy_auth_enabled);
            form.addEventListener('change', event => {
                if (event.target && event.target.id === 'edit-suppression_rspamd_sync') settingsApplySync(true);
                if (event.target && ['edit-basic_auth_enabled', 'edit-oauth2_enabled'].includes(event.target.id)) settingsLockAgentAccess(content, true, data.legacy_auth_enabled);
                settingsSuggestAgentUrl(content, !!event.target && event.target.id === 'edit-agent_access_enabled');
                settingsShowNeeds(content);
                settingsLockPasswordRemove(content);
            });
            form.addEventListener('input', () => settingsSuggestAgentUrl(content, false));
            // Clearing and resetting change a field without an input event
            content.querySelectorAll('.settings-clear-btn').forEach(btn => btn.addEventListener('click', () => setTimeout(() => { updateDirty(); settingsShowNeeds(content); settingsLockPasswordRemove(content); settingsSuggestAgentUrl(content, false); content.querySelectorAll('.ui-set-codes').forEach(settingsShowCodes); })));
        }

        if (form) {
            // The fields are checked here, so a problem is named under its field (not in a browser bubble)
            form.noValidate = true;
            form.onsubmit = async (e) => {
                e.preventDefault();
                if (!settingsCheckFields(form, initialValues, fieldValue)) return;
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
                        showToast('Set a password before enabling Basic Auth.', 'error');
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
                        throw new Error(uiApiErrorText(err, res.statusText));
                    }
                    const saved = await res.json().catch(() => ({}));
                    // Saved: these values are the new start, so a reload asks nothing about them
                    form.querySelectorAll('[name]:not([data-choice])').forEach(el => initialValues.set(el.name, fieldValue(el)));
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
                        showToast('Basic Auth enabled.', 'success');
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
                    showToast('Could not save settings. Try again. Details: ' + (err.message || err), 'error');
                }
            };
        }
        if (importBtn) {
            importBtn.onclick = async () => {
                if (!await showConfirmModal({ title: 'Migrate settings from ENV', message: 'Copy the current environment settings to the database? This replaces any settings already stored there.', confirmText: 'Migrate' })) return;
                try {
                    importBtn.disabled = true;
                    const res = await authenticatedFetch('/api/settings/import-from-env', { method: 'POST' });
                    if (!res.ok) throw new Error(uiApiErrorText(await res.json().catch(() => ({})), res.statusText));
                    const result = await res.json();
                    if (result.env_locked_keys) {
                        data.env_locked_keys = result.env_locked_keys;
                    }
                    await loadSettings();
                } catch (err) {
                    showToast('Could not migrate settings. Try again. Details: ' + (err.message || err), 'error');
                } finally {
                    importBtn.disabled = false;
                }
            };
        }
    }
}

// reloadPage: reload the whole page on close instead of only Settings
async function showGeoIPSetupModal(reloadPage = false) {
    // X, Close, Escape, Back and a click outside close it once the setup is done;
    // while it runs both buttons are off, so nothing stops it halfway
    const closeWhenDone = () => {
        const button = document.getElementById('geoip-setup-close-btn');
        if (button && !button.disabled) button.click();
    };
    const { backdrop: overlay, dialog } = uiDialog({
        id: 'geoip-setup-overlay', title: 'GeoIP database setup', size: 'sm',
        close: closeWhenDone, backdropClose: closeWhenDone,
        bodyId: 'geoip-setup-steps', bodyClass: 'ui-geo-steps',
        body: `
                <div id="geoip-step-1" class="ui-geo-step">
                    <div id="geoip-step-1-icon" class="ui-geo-icon">
                        <svg class="w-5 h-5 ui-text-info animate-spin" fill="none" viewBox="0 0 24 24">
                            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                        </svg>
                    </div>
                    <div>
                        <p class="ui-geo-title">Checking credentials</p>
                        <p id="geoip-step-1-detail" class="ui-set-desc">Checking MaxMind credentials</p>
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
                        <p class="ui-geo-title">Check the databases</p>
                        <p id="geoip-step-3-detail" class="ui-set-desc">Waiting...</p>
                    </div>
                </div>`,
        foot: `<button id="geoip-setup-close-btn" class="ui-btn" disabled>
                    Close
                </button>`,
    });

    const closeBtn = document.getElementById('geoip-setup-close-btn');
    const closeX = dialog.querySelector('[data-dialog-x]');
    closeX.disabled = true;
    // The setup is over (done or failed): the window can close
    const setupOver = () => { closeBtn.disabled = false; closeX.disabled = false; };
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
        if (!credRes.ok) throw new Error('Could not read GeoIP status. Check your connection and try again.');
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
                setStepStatus(1, 'error', 'Could not validate the license. Check your MaxMind credentials. Details: ' + valLicData.error);
                setupOver();
                return;
            } else {
                setStepStatus(1, 'success', 'Credentials configured');
            }
        } else {
            setStepStatus(1, 'error', 'Add a MaxMind account ID and license key in Settings > MaxMind.');
            setupOver();
            return;
        }
        
        // ── Step 2: Check/Download databases ──
        setStepStatus(2, 'running', 'Checking existing databases...');
        
        const statusRes = await authenticatedFetch('/api/settings/geoip/status');
        const geoipStatus = await statusRes.json();
        const cityAvail = geoipStatus.databases?.City?.available;
        const asnAvail = geoipStatus.databases?.ASN?.available;
        
        if (cityAvail && asnAvail) {
            setStepStatus(2, 'success', 'Databases installed');
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
                setStepStatus(2, 'success', 'Download job finished');
            } else {
                const errMsg = typeof downloadComplete === 'string' ? downloadComplete : 'The download did not finish in time. Check Status for progress.';
                // Check if it's a credentials error
                const isCredError = errMsg.toLowerCase().includes('401') || errMsg.toLowerCase().includes('unauthorized') || errMsg.toLowerCase().includes('invalid');
                if (isCredError) {
                    setStepStatus(1, 'error', 'MaxMind rejected the download. Check your account ID and license key.');
                }
                setStepStatus(2, 'error', errMsg);
                setupOver();
                return;
            }
        }
        
        // ── Step 3: Validate DB integrity ──
        setStepStatus(3, 'running', 'Checking the databases...');
        
        const valRes = await authenticatedFetch('/api/settings/geoip/validate', { method: 'POST' });
        const valData = await valRes.json();
        
        if (valData.valid) {
            setStepStatus(3, 'success', 'Database check passed. GeoIP is ready.');
        } else {
            setStepStatus(3, 'error', valData.error || 'Database check failed. Check the application logs, then close this window and try Repair.');
        }
        
    } catch (err) {
        console.error('GeoIP setup error:', err);
    }
    
    setupOver();
}

// Cache last MaxMind validation result so re-renders don't lose it
var _cachedMaxMindStatus = null;

async function validateMaxMindLicense() {
    // Show checking state on all MaxMind status badges
    const checkingHtml = `
        <span class="ui-tag ui-tag-info">
            <svg class="w-3 h-3 me-1 animate-spin" fill="none" viewBox="0 0 24 24">
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
            showToast('Could not validate the MaxMind license. Check your credentials. Details: ' + result.error, 'error');
        }
    } catch (error) {
        console.error('Failed to validate MaxMind license:', error);
        const errorHtml = renderMaxMindStatus({ configured: true, valid: false, error: 'Connection error' });
        ['maxmind-license-status', 'maxmind-license-status-tab'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.innerHTML = errorHtml;
        });
        showToast('Could not validate the MaxMind license. Check your connection and try again.', 'error');
    }
}

async function repairGeoIPDatabase() {
    const statusEl = document.getElementById('geoip-db-status');
    if (statusEl) {
        statusEl.innerHTML = `
            <span class="ui-tag ui-tag-info">
                <svg class="w-3 h-3 me-1 animate-spin" fill="none" viewBox="0 0 24 24">
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
            throw new Error('Could not start the download. Check your MaxMind credentials and try again.');
        }

        showToast('GeoIP download check started...', 'info');

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
                                showToast('GeoIP database check passed.', 'success');
                            } else {
                                showToast('Database check still failed after the download. Check the application logs.', 'error');
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
                showToast('The repair is taking longer than expected. Check Status for progress.', 'warning');
                if (statusEl) {
                    statusEl.innerHTML = '<span class="text-xs text-gray-500">Check Status page</span>';
                }
            }
        };

        setTimeout(pollStatus, pollInterval);

    } catch (error) {
        console.error('Failed to repair GeoIP databases:', error);
        showToast('Could not repair the GeoIP databases. Check Status and try again. Details: ' + error.message, 'error');
        if (statusEl) {
            statusEl.innerHTML = renderGeoIPDbStatus({ db_valid: false });
        }
    }
}

// Credentials checked against their server, changing nothing there. Each
// failure says what it means and what to do about it.
const CREDENTIAL_CHECKS = {
    mailcow_rw_key: {
        label: 'Read-write API key',
        endpoint: '/api/settings/mailcow/rw-key/validate',
        missing: 'Add a read-write API key first',
        accepted: 'mailcow accepted the read-write API key',
        errors: {
            rejected: ['Rejected', "mailcow rejected the read-write API key. Check that the key is active and allows this server's IP in mailcow > System > Configuration > Access > Administrators > API. A key from mailcow.conf takes its allowed IPs from API_ALLOW_FROM in that file."],
            read_only: ['Read-only key', 'This key is read-only. Enter a read-write API key from mailcow > System > Configuration > Access > Administrators > API.'],
            connection: ['Connection error', 'Could not reach mailcow to check the read-write API key. Check the mailcow URL and try again.'],
            unexpected: ['Unexpected answer', 'mailcow returned an unexpected response for the read-write API key. Check the mailcow URL and the application logs.']
        }
    },
    rspamd_password: {
        label: 'Rspamd password',
        endpoint: '/api/settings/rspamd/password/validate',
        missing: 'Add the Rspamd password first',
        accepted: 'Rspamd accepted the password',
        errors: {
            rejected: ['Rejected', 'Rspamd rejected the password. Enter the password from mailcow > System > Configuration > Access > Rspamd UI.'],
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
const SETTINGS_READ_AT_PAGE_LOAD = ['app_title', 'app_logo_url', 'basic_auth_enabled', 'oauth2_enabled', 'mailcow_url', 'tz', 'date_format', 'time_format'];

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
    return status.valid ? uiTag('License valid', 'ok') : uiTag(status.error || 'Invalid', 'fail');
}

// Validate needs a MaxMind Account ID and License Key; without them the button stays, disabled, and says so
function maxmindValidateButton(geoipConfig) {
    if (!geoipConfig) return '';
    return geoipConfig.enabled
        ? '<button type="button" onclick="validateMaxMindLicense()" class="ui-btn ui-btn-sm">Validate</button>'
        : '<button type="button" class="ui-btn ui-btn-sm" disabled title="Add a MaxMind account ID and license key first">Validate</button>';
}

function renderGeoIPDbStatus(geoipConfig) {
    if (!geoipConfig) return '';

    // Don't show DB status if MaxMind is not configured
    if (geoipConfig.enabled === false) return '';

    const dbValid = geoipConfig.db_valid;

    if (dbValid === true) return uiTag('Databases ready', 'ok');
    if (dbValid === false) {
        return `
            <span id="geoip-db-status" class="ui-chip-row">
                ${uiTag('Database check failed', 'fail')}
                <button type="button" onclick="repairGeoIPDatabase()" class="ui-btn ui-btn-sm">Repair</button>
            </span>
        `;
    }
    // null = not checked yet - could be downloading
    const dbs = geoipConfig.databases || {};
    const cityAvail = dbs.City && dbs.City.available;
    return cityAvail ? uiTag('Not checked', '') : uiTag('Not installed', 'warn');
}

// =============================================================================
// TEST IMAP / SMTP
// =============================================================================

async function testSmtpConnection() {
    const run = showConnectionTestModal('SMTP connection test', 'Testing SMTP connection...');

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
        updateConnectionTestModal(result.success ? 'success' : 'error', logs, run);

    } catch (error) {
        updateConnectionTestModal('error', [
            'Could not test SMTP. Check your connection and try again.',
            `Error: ${error.message}`
        ], run);
    }
}

async function testImapConnection() {
    const run = showConnectionTestModal('IMAP connection test', 'Testing IMAP connection...');

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
        updateConnectionTestModal(result.success ? 'success' : 'error', logs, run);

    } catch (error) {
        updateConnectionTestModal('error', [
            'Could not test IMAP. Check your connection and try again.',
            `Error: ${error.message}`
        ], run);
    }
}

// One test window at a time. Each opening is a new run: a reply that comes back
// after its window was closed, or after another test opened, is dropped
let connectionTestRun = 0;
function showConnectionTestModal(title, message) {
    document.getElementById('connection-test-modal')?.remove();
    connectionTestRun += 1;
    // Results only, nothing typed: a click outside closes it
    uiDialog({
        id: 'connection-test-modal', title, size: 'md', close: closeConnectionTestModal, backdropClose: closeConnectionTestModal,
        body: `<div id="connection-test-content">
                    <div class="ui-loading" role="status"><div class="loading"></div><p>${escapeHtml(message)}</p></div>
                </div>`,
        foot: '<button onclick="closeConnectionTestModal()" class="ui-btn">Close</button>',
    });
    return connectionTestRun;
}

function updateConnectionTestModal(status, logs, run) {
    const content = document.getElementById('connection-test-content');
    if (!content || (run !== undefined && run !== connectionTestRun)) return;

    // Ensure logs is an array
    if (!Array.isArray(logs)) {
        logs = ['Error: Invalid response format'];
    }

    const ok = status === 'success';
    content.innerHTML = `
        <div class="ui-md-verdict-bar ${ok ? 'ui-md-verdict-ok' : 'ui-md-verdict-fail'}">${ok ? 'Test passed' : 'Test failed'}</div>
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

// =============================================================================
// IMAP folders (dmarc_imap_folder): a JSON list, each item a folder name or
// {"name": ..., "subfolders": true} (the folder and every folder below it, also
// ones added later). Any other value is one folder name from before, used as
// stored. The same rule as parse_setting in backend/app/services/imap_folders.py
// =============================================================================

const SETTINGS_FOLDER_ICON = '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linejoin="round" d="M3 6.5A1.5 1.5 0 0 1 4.5 5h4.6l2 2.2h8.4A1.5 1.5 0 0 1 21 8.7v9.8a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18.5z"/></svg>';
const SETTINGS_IMAP_CONNECTION_KEYS = ['dmarc_imap_host', 'dmarc_imap_port', 'dmarc_imap_use_ssl', 'dmarc_imap_verify_ssl', 'dmarc_imap_user', 'dmarc_imap_password'];

// Whether a field differs from the value it loaded with; set when the settings form is built
let settingsFieldUnsaved = () => false;

// Folder names and the JSON value go into markup with uiEntityAttr (utils.js), not
// escapeHtml: that one drops the backslash of \", which changes a name or breaks the JSON

// { entries: [{ name, subfolders, item }] } for the list form (item: the stored
// item, written back as it was while unchanged), { legacy: name } for one folder name
function settingsParseFolders(value) {
    const text = typeof value === 'string' ? value : '';
    if (!text.trim()) return { legacy: 'INBOX' };
    let items;
    try { items = JSON.parse(text); } catch (e) { return { legacy: text }; }
    if (!Array.isArray(items) || !items.length) return { legacy: text };
    const entries = [];
    for (const item of items) {
        if (typeof item === 'string' && item) {
            entries.push({ name: item, subfolders: false, item });
        } else if (item && typeof item === 'object' && !Array.isArray(item)
            && Object.keys(item).every(k => k === 'name' || k === 'subfolders')
            && typeof item.name === 'string' && item.name
            && (item.subfolders === undefined || typeof item.subfolders === 'boolean')) {
            entries.push({ name: item.name, subfolders: item.subfolders === true, item });
        } else {
            return { legacy: text };
        }
    }
    return { entries };
}

// The rows of the field: one per chosen folder, or the one folder name from before
function settingsFolderRows(value) {
    const parsed = settingsParseFolders(value);
    const list = parsed.entries || [{ name: parsed.legacy, subfolders: false }];
    return list.map(e => '<li class="ui-set-folder" title="' + uiEntityAttr(e.name) + '">' + SETTINGS_FOLDER_ICON +
        '<span class="ui-set-folder-name" dir="auto">' + uiEntityAttr(e.name) + '</span>' +
        (e.subfolders ? uiTag('With subfolders', 'info') : '') + '</li>').join('');
}

function settingsShowFolders(input) {
    const field = input && input.closest('.ui-set-field');
    const rows = field && field.querySelector('[data-folder-rows]');
    if (rows) rows.innerHTML = settingsFolderRows(input.value);
}

// One picker at a time. Each opening is a new run, and closing ends it: a folder
// list that comes back for a closed or reopened picker is dropped
let settingsFoldersRun = 0;
async function settingsChooseFolders() {
    const input = document.getElementById('edit-dmarc_imap_folder');
    if (!input || input.disabled) return;
    document.getElementById('settings-folders-modal')?.remove();
    const run = ++settingsFoldersRun;
    const close = () => {
        settingsFoldersRun += 1;
        document.getElementById('settings-folders-modal')?.remove();
    };
    const { body, foot } = uiDialog({
        id: 'settings-folders-modal', title: 'Choose folders', size: 'md', close, footClass: 'ui-set-tree-foot',
        body: '<div class="ui-loading" role="status"><div class="loading"></div><p>Reading the folders on the server...</p></div>',
        foot: '<button type="button" class="ui-btn" data-folders-close>Cancel</button>',
    });
    foot.querySelector('[data-folders-close]').addEventListener('click', close);
    const say = text => {
        body.innerHTML = '<p class="ui-set-tree-msg" role="status">' + uiEntityAttr(text) + '</p>';
        foot.innerHTML = '<button type="button" class="ui-btn" data-folders-close>Close</button>';
        foot.querySelector('[data-folders-close]').addEventListener('click', close);
    };
    // The folders come from the saved connection, so an unsaved one would show another mailbox
    if (SETTINGS_IMAP_CONNECTION_KEYS.some(name => settingsFieldUnsaved(name))) {
        say('Save the connection settings first, then choose folders.');
        return;
    }
    let result = null;
    let failure = '';
    try {
        const res = await authenticatedFetch('/api/settings/imap/folders', { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (res.ok) result = data;
        else failure = settingsErrorText(data, '');
    } catch (err) {
        failure = '';
    }
    if (run !== settingsFoldersRun || !body.isConnected) return;
    if (!result) {
        say(failure || 'The folders could not be loaded. Try again in a moment.');
        return;
    }
    if (!result.ok) {
        say(result.message || 'The folders could not be read from the server. Try again in a moment.');
        return;
    }
    settingsFolderPicker(result, input, body, foot, close);
}

function settingsFolderPicker(result, input, body, foot, close) {
    const folders = (Array.isArray(result.folders) ? result.folders : []).filter(f => f && typeof f.name === 'string' && f.name);
    const byName = new Map(folders.map(f => [f.name, f]));
    // INBOX is one folder in any case (RFC 3501); every other name is matched exactly
    const inbox = folders.find(f => f.name.toUpperCase() === 'INBOX');
    const listed = name => byName.get(name) || (inbox && name.toUpperCase() === 'INBOX' ? inbox : null);
    // A folder's parent: the listed folder whose name and its delimiter are the longest start of this name
    const parentOf = new Map();
    folders.forEach(f => {
        for (let i = f.name.length - 1; i > 0; i--) {
            const p = byName.get(f.name.slice(0, i));
            if (p && p !== f && p.delimiter && f.name.startsWith(p.name + p.delimiter)) { parentOf.set(f, p); break; }
        }
    });
    const kids = new Map();
    const roots = [];
    folders.forEach(f => {
        const p = parentOf.get(f);
        if (!p) roots.push(f);
        else (kids.get(p) || kids.set(p, []).get(p)).push(f);
    });
    const rows = [];
    const walk = (list, depth) => list.forEach(f => {
        const p = parentOf.get(f);
        rows.push({ f, depth, label: p ? f.name.slice(p.name.length + p.delimiter.length) : f.name });
        walk(kids.get(f) || [], depth + 1);
    });
    walk(roots, 0);

    // The choice being made, by folder: { name, subfolders, item, folder, legacy }.
    // A name the server does not list keeps its own name as key and is shown at the top
    const draft = new Map();
    const missing = [];
    const add = (name, subfolders, item, legacy) => {
        const folder = listed(name);
        const key = folder ? folder.name : name;
        if (draft.has(key)) {
            // The same folder twice: one entry that keeps the subfolders if either had them
            const known = draft.get(key);
            if (subfolders && !known.subfolders) {
                known.subfolders = true;
                known.item = null;
            }
            return;
        }
        const entry = { name, subfolders, item, folder, legacy };
        draft.set(key, entry);
        if (!folder) missing.push({ key, entry });
    };
    // The picker starts from the field's current value, so an unsaved earlier choice wins
    const parsed = settingsParseFolders(input.value);
    if (parsed.entries) {
        parsed.entries.forEach(e => add(e.name, e.subfolders, e.item, false));
    } else {
        // A folder name from before is used as stored. The server matched the saved one;
        // another (Clear sets INBOX) counts as found only when it is plain text,
        // which reads the same before and after decoding
        const saved = result.legacy && result.legacy.value === input.value ? result.legacy : null;
        const match = saved ? (saved.name ? listed(saved.name) : null)
            : (/^[\x20-\x7e]+$/.test(parsed.legacy) && !parsed.legacy.includes('&') ? listed(parsed.legacy) : null);
        if (match) add(match.name, false, null, false);
        else add(saved ? saved.value : parsed.legacy, false, null, true);
    }

    const coverOf = f => {
        for (const e of draft.values()) {
            if (e.subfolders && e.folder && e.folder !== f && e.folder.delimiter && f.name.startsWith(e.folder.name + e.folder.delimiter)) return e;
        }
        return null;
    };
    const indent = depth => 'padding-inline-start:' + (8 + depth * 22) + 'px';
    const treeHtml = () => {
        const top = missing.map((m, i) => {
            const on = draft.has(m.key);
            return '<div class="ui-set-tree-node is-missing" style="' + indent(0) + '">' +
                '<label class="ui-set-tree-pick"><input type="checkbox" class="ui-check" data-missing="' + i + '"' + (on ? ' checked' : '') + '>' +
                SETTINGS_FOLDER_ICON + '<span class="ui-set-tree-name" dir="auto">' + uiEntityAttr(m.entry.name) + '</span></label>' +
                (m.entry.subfolders ? uiTag('With subfolders', 'info') : '') + uiTag('Not found on the server', 'warn') + '</div>';
        }).join('');
        return top + rows.map((row, i) => {
            const f = row.f;
            const own = draft.get(f.name);
            const cover = coverOf(f);
            const subs = !!(own && own.subfolders) && !cover;
            const name = '<span class="ui-set-tree-name" dir="auto">' + uiEntityAttr(row.label) + '</span>';
            const pick = f.selectable !== false
                ? '<label class="ui-set-tree-pick"><input type="checkbox" class="ui-check" data-pick="' + i + '"' + (own || cover ? ' checked' : '') + (cover ? ' disabled' : '') + '>' + SETTINGS_FOLDER_ICON + name + '</label>'
                : '<span class="ui-set-tree-pick"><span class="ui-set-tree-gap"></span>' + SETTINGS_FOLDER_ICON + name + '</span>';
            // Offered on folders that have subfolders now (as in the design), and kept on one
            // already read with its subfolders, so that choice can still be turned off
            const subsBox = f.can_have_children && !cover && ((kids.get(f) || []).length > 0 || subs)
                ? '<label class="ui-set-tree-subs' + (subs ? ' is-on' : '') + '"><input type="checkbox" class="ui-check" data-subs="' + i + '"' + (subs ? ' checked' : '') +
                    ' aria-label="' + uiEntityAttr(f.name) + ' with subfolders">With subfolders</label>'
                : '';
            return '<div class="ui-set-tree-node' + (cover ? ' is-covered' : '') + (f.selectable === false ? ' is-noselect' : '') + '" style="' + indent(row.depth) + '" title="' + uiEntityAttr(f.name) + '">' + pick + subsBox + '</div>' +
                (subs ? '<p class="ui-set-tree-future" style="padding-inline-start:' + (38 + row.depth * 22) + 'px">Subfolders added later are read too.</p>' : '');
        }).join('');
    };

    const unreadable = Number(result.unreadable) || 0;
    body.innerHTML = '<p class="ui-set-tree-intro">' + uiEntityAttr('Folders in ' + (result.user || '') + ' on ' + (result.host || '')) + '</p>' +
        (rows.length || missing.length ? '' : '<p class="ui-set-tree-msg">The server listed no folders.</p>') +
        '<div class="ui-set-tree" data-folder-tree></div>' +
        (unreadable > 0 ? '<p class="ui-set-tree-note">' + uiEntityAttr(uiCountLabel(unreadable, 'folder', 'folders') + ' could not be read from the server\'s folder list.') + '</p>' : '');
    foot.innerHTML = '<span class="ui-set-tree-sum" aria-live="polite"></span>' +
        '<button type="button" class="ui-btn" data-folders-close>Cancel</button>' +
        '<button type="button" class="ui-btn ui-btn-primary" data-folders-apply>Use these folders</button>';
    const tree = body.querySelector('[data-folder-tree]');
    const sum = foot.querySelector('.ui-set-tree-sum');
    const apply = foot.querySelector('[data-folders-apply]');
    foot.querySelector('[data-folders-close]').addEventListener('click', close);

    const redraw = () => {
        // The tree is drawn again on every change; the box that was used keeps the focus
        const active = document.activeElement && tree.contains(document.activeElement) ? document.activeElement : null;
        const focusKey = active ? ['pick', 'subs', 'missing'].map(k => active.dataset[k] !== undefined ? '[data-' + k + '="' + active.dataset[k] + '"]' : '').join('') : '';
        tree.innerHTML = treeHtml();
        if (focusKey) tree.querySelector(focusKey)?.focus();
        const blocking = [...draft.values()].find(e => e.legacy);
        const now = rows.filter(row => row.f.selectable !== false && (draft.has(row.f.name) || coverOf(row.f))).length;
        const later = [...draft.values()].filter(e => e.subfolders && e.folder).length;
        apply.disabled = !draft.size || !!blocking;
        sum.classList.toggle('is-blocked', apply.disabled);
        sum.textContent = blocking ? 'Uncheck ' + blocking.name + ' to save a new choice.'
            : !draft.size ? 'Choose at least one folder.'
            : now + ' ' + settingsPlural(now, 'folder', 'folders') + ' now' + (later ? ', plus new subfolders of ' + (later === 1 ? 'one folder' : later + ' folders') : '');
    };

    tree.addEventListener('change', event => {
        const box = event.target;
        if (!box || box.type !== 'checkbox') return;
        if (box.dataset.missing !== undefined) {
            const m = missing[Number(box.dataset.missing)];
            if (box.checked) draft.set(m.key, m.entry); else draft.delete(m.key);
        } else if (box.dataset.pick !== undefined) {
            const f = rows[Number(box.dataset.pick)].f;
            if (!box.checked) draft.delete(f.name);
            else if (!draft.has(f.name)) draft.set(f.name, { name: f.name, subfolders: false, item: null, folder: f, legacy: false });
        } else if (box.dataset.subs !== undefined) {
            const f = rows[Number(box.dataset.subs)].f;
            const own = draft.get(f.name);
            if (box.checked) {
                // The subfolders are read through this folder now, so they are no longer named one by one
                const below = f.name + (f.delimiter || '');
                [...draft.keys()].forEach(key => { if (f.delimiter && key !== f.name && key.startsWith(below)) draft.delete(key); });
                draft.set(f.name, own ? { ...own, subfolders: true, item: own.subfolders ? own.item : null }
                    : { name: f.name, subfolders: true, item: null, folder: f, legacy: false });
            } else if (own) {
                // A folder that cannot be read itself is only there for its subfolders
                if (f.selectable === false) draft.delete(f.name);
                else draft.set(f.name, { ...own, subfolders: false, item: own.subfolders ? null : own.item });
            }
        }
        redraw();
    });

    apply.addEventListener('click', () => {
        if (apply.disabled) return;
        // Names the server does not list first, as shown, then the server's order
        const order = [];
        missing.forEach(m => { if (draft.get(m.key) === m.entry) order.push(m.entry); });
        const seen = new Set();
        folders.forEach(f => {
            const e = draft.get(f.name);
            if (e && !seen.has(e)) { seen.add(e); order.push(e); }
        });
        if (!order.length) return;
        input.value = JSON.stringify(order.map(e => e.item !== null ? e.item : (e.subfolders ? { name: e.name, subfolders: true } : e.name)));
        // The save bar counts it like a typed change
        input.dispatchEvent(new Event('change', { bubbles: true }));
        settingsShowFolders(input);
        close();
    });

    redraw();
}
