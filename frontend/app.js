// =============================================================================
// MAILCOW LOGS VIEWER - COMPLETE FRONTEND
// Part 1: Core, Global State, Dashboard, Postfix, Rspamd, Netfilter
// =============================================================================

// Shared helpers (colors, escaping, formatting, clipboard, toasts) live in
// utils.js, which is loaded before this file.

// =============================================================================
// NAVIGATION HELPERS
// =============================================================================

/**
 * Navigate to Messages page with pre-filled filters
 * @param {Object} options - Filter options
 * @param {string} options.email - Email address to filter by
 * @param {string} options.filterType - 'sender' | 'recipient' | 'search'
 * @param {string} options.direction - 'inbound' | 'outbound' | 'internal'
 * @param {string} options.status - 'delivered' | 'bounced' | 'deferred' | 'rejected'
 */
function navigateToMessagesWithFilter(options) {
    // Clear existing filters first
    const filterSearch = document.getElementById('messages-filter-search');
    const filterSender = document.getElementById('messages-filter-sender');
    const filterRecipient = document.getElementById('messages-filter-recipient');
    const filterDirection = document.getElementById('messages-filter-direction');
    const filterStatus = document.getElementById('messages-filter-status');
    const filterUser = document.getElementById('messages-filter-user');
    const filterIp = document.getElementById('messages-filter-ip');

    // Reset all filters
    if (filterSearch) filterSearch.value = '';
    if (filterSender) filterSender.value = '';
    if (filterRecipient) filterRecipient.value = '';
    if (filterDirection) filterDirection.value = '';
    if (filterStatus) filterStatus.value = '';
    if (filterUser) filterUser.value = '';
    if (filterIp) filterIp.value = '';

    // Set email filter based on type
    if (options.email) {
        if (options.filterType === 'sender') {
            if (filterSender) filterSender.value = options.email;
        } else if (options.filterType === 'recipient') {
            if (filterRecipient) filterRecipient.value = options.email;
        } else {
            // Default: use search field
            if (filterSearch) filterSearch.value = options.email;
        }
    }

    // Set direction filter
    if (options.direction && filterDirection) {
        filterDirection.value = options.direction;
    }

    // Set status filter
    if (options.status && filterStatus) {
        filterStatus.value = options.status;
    }

    // Navigate to Messages tab
    navigateTo('messages');

    // Apply filters after navigation
    setTimeout(() => {
        if (typeof applyMessagesFilters === 'function') {
            applyMessagesFilters();
        }
    }, 100);
}

// =============================================================================
// AUTHENTICATION SYSTEM
// =============================================================================

// DMARC imap
let dmarcImapStatus = null;
let dmarcConfiguration = null;

// Send the browser to the login page, dropping any client-side state; signing
// in again returns to the page that was open
function redirectToLogin() {
    const here = window.location.pathname + window.location.search;
    window.location.replace(here === '/' ? '/login' : `/login?next=${encodeURIComponent(here)}`);
}

// Enhanced fetch with authentication.
// Both login methods (OAuth2 and Basic Auth) end up with the same HttpOnly
// session cookie, which the browser attaches automatically. No credential is
// held in JavaScript, so an XSS in the page has nothing to read.
async function authenticatedFetch(url, options = {}) {
    const headers = {
        ...options.headers,
    };

    const response = await fetch(url, {
        ...options,
        headers,
        credentials: 'include' // Send the session cookie
    });

    // Handle 401 Unauthorized - the session expired or the server restarted
    if (response.status === 401) {
        redirectToLogin();
        throw new Error('Authentication required');
    }

    return response;
}

// Handle logout - one path for both login methods, since both are backed by
// the same server-side session.
function handleLogout() {
    window.location.href = '/api/auth/logout';
}

// Check authentication on page load.
// OAuth2 and Basic Auth both end up with a session cookie, so one check
// covers them: no session means the browser goes back to the login page.
async function checkAuthentication() {
    // First check if authentication is enabled
    try {
        const infoResponse = await fetch('/api/info', { credentials: 'include' });
        if (infoResponse.ok) {
            const infoData = await infoResponse.json();
            // If authentication is disabled, allow access
            if (!infoData.auth_enabled) {
                return true;
            }
        }
    } catch (e) {
        // If we can't check, assume auth is enabled for safety
        console.warn('Could not check auth status, assuming enabled');
    }

    try {
        const statusResponse = await fetch('/api/auth/status', { credentials: 'include' });
        if (statusResponse.ok) {
            const statusData = await statusResponse.json();
            if (statusData.authenticated) {
                const logoutBtn = document.getElementById('logout-btn');
                if (logoutBtn) logoutBtn.classList.remove('hidden');
                return true;
            }
        }
    } catch (e) {
        // Could not reach the status endpoint - treat as not authenticated
    }

    redirectToLogin();
    return false;
}

// =============================================================================
// EXISTING CODE CONTINUES...
// =============================================================================

// Global state
let currentTab = 'dashboard';
let appTimezone = 'UTC'; // Default timezone, will be updated from API
let currentPage = {
    netfilter: 1,
    messages: 1
};
let currentFilters = {
    netfilter: {},
    queue: {},
    messages: {}
};

// Global RW API key status (shared across all features)
let mailcowRwConfigured = false;

// Feature toggles - features in this list are disabled (hidden from UI, jobs stopped)
window.disabledFeatures = [];

// All toggleable feature definitions (for settings UI)
const TOGGLEABLE_FEATURES = [
    { id: 'netfilter', label: 'Security', description: 'Fail2Ban management and security events' },
    { id: 'queue', label: 'Queue', description: 'Mail queue monitoring' },
    { id: 'quarantine', label: 'Quarantine', description: 'Quarantined emails and auto-rules' },
    { id: 'spam-filter', label: 'Spam Filter', description: 'Bounce suppression and Rspamd maps' },
    { id: 'domains', label: 'Domains', description: 'Domain DNS analysis and transports' },
    { id: 'dmarc', label: 'DMARC & TLS', description: 'DMARC/TLS reports and IMAP sync' },
    { id: 'mailbox-stats', label: 'Mailbox Stats', description: 'Mailbox and alias statistics' },
    { id: 'rate-limits', label: 'Rate Limits', description: 'Sender rate limit hits and the configured limits' },
    { id: 'logs', label: 'Logs', description: 'Raw service log viewer' },
    { id: 'blacklist', label: 'IP Blacklist Monitor', description: 'DNS blacklist monitoring for your IPs' },
];

function isFeatureDisabled(featureId) {
    return window.disabledFeatures.includes(featureId);
}

function applyFeatureToggles() {
    // Hide the sidebar, sheet and phone tab bar entries of disabled features
    const navIds = feature => [`tab-${feature}`, `mobile-tab-${feature}`, `tabbar-${feature}`];
    for (const feature of window.disabledFeatures) {
        for (const id of navIds(feature)) {
            const el = document.getElementById(id);
            if (el) el.style.display = 'none';
        }
    }
    // Ensure enabled features are visible (in case of settings change)
    for (const feature of TOGGLEABLE_FEATURES) {
        if (!window.disabledFeatures.includes(feature.id)) {
            for (const id of navIds(feature.id)) {
                const el = document.getElementById(id);
                if (el) el.style.display = '';
            }
        }
    }
    // A navigation group whose pages are all off loses its heading too
    document.querySelectorAll('[data-nav-group]').forEach(group => {
        const visible = [...group.querySelectorAll('button')].some(btn => btn.style.display !== 'none');
        group.style.display = visible ? '' : 'none';
    });
    
    // Special handling for blacklist feature - it doesn't have its own tab,
    // it's a section inside the Domains page
    const blacklistSection = document.getElementById('blacklist-section');
    const dashboardBlacklistCard = document.getElementById('dashboard-blacklist-card');
    const statusBlacklistKpi = document.getElementById('status-kpi-blocklists-cell');
    const statusBlacklistTab = document.getElementById('status-tab-btn-blocklists');
    const blacklistOff = window.disabledFeatures.includes('blacklist');
    if (blacklistOff && typeof statusTab !== 'undefined' && statusTab === 'blocklists') statusShowTab('server');
    [blacklistSection, dashboardBlacklistCard, statusBlacklistKpi, statusBlacklistTab].forEach(el => {
        if (el) el.style.display = blacklistOff ? 'none' : '';
    });

    // Same for rate-limits - it is a view inside the Mailbox Stats page,
    // so the feature toggle hides its switcher button instead of a tab
    const mailboxStatsOff = window.disabledFeatures.includes('mailbox-stats');
    const rateLimitsOff = window.disabledFeatures.includes('rate-limits');

    const rateLimitsViewBtn = document.getElementById('mailbox-stats-view-rate-limits');
    if (rateLimitsOff) {
        if (rateLimitsViewBtn) rateLimitsViewBtn.style.display = 'none';
        // Never leave the user stranded on a view that just disappeared
        if (typeof mailboxStatsView !== 'undefined' && mailboxStatsView === 'rate-limits' && !mailboxStatsOff) {
            mailboxStatsSwitchView('statistics');
        }
    } else {
        if (rateLimitsViewBtn) rateLimitsViewBtn.style.display = '';
    }

    // The mirror case: Rate Limits does not depend on Mailbox Stats. With
    // Mailbox Stats off and Rate Limits on, the page stays reachable and
    // becomes the Rate Limits page - Statistics is the view that disappears,
    // and with one view left the switcher itself has nothing to offer.
    const statsViewBtn = document.getElementById('mailbox-stats-view-statistics');
    // Not 'mailbox-stats-view-*': that prefix is the switcher's button query
    const viewSwitcher = document.getElementById('mailbox-stats-views');
    if (mailboxStatsOff && !rateLimitsOff) {
        if (statsViewBtn) statsViewBtn.style.display = 'none';
        if (viewSwitcher) viewSwitcher.style.display = 'none';
        if (typeof mailboxStatsView !== 'undefined' && mailboxStatsView === 'statistics') {
            if (currentTab === 'mailbox-stats') {
                mailboxStatsSwitchView('rate-limits');
            } else {
                // Only remember it - switching now would fetch for a hidden page
                mailboxStatsView = 'rate-limits';
            }
        }
    } else {
        if (statsViewBtn) statsViewBtn.style.display = '';
        if (viewSwitcher) viewSwitcher.style.display = '';
    }

    // The tab is shared by both features, so it only goes when both are off,
    // and it says what it actually opens
    const mailboxTabLabel = mailboxStatsOff && !rateLimitsOff ? 'Rate Limits' : 'Mailbox Stats';
    for (const tabId of ['tab-mailbox-stats', 'mobile-tab-mailbox-stats']) {
        const tab = document.getElementById(tabId);
        if (!tab) continue;
        tab.style.display = mailboxStatsOff && rateLimitsOff ? 'none' : '';
        setNavTabLabel(tab, mailboxTabLabel);
    }
}

// A nav tab is an <svg> icon followed by its label, in a .ui-nav-label span
// (or, in older markup, a bare text node), so only the label text changes.
function setNavTabLabel(tab, label) {
    const span = tab.querySelector('.ui-nav-label');
    if (span) {
        if (span.textContent !== label) span.textContent = label;
        tab.title = label;
        return;
    }
    for (let i = tab.childNodes.length - 1; i >= 0; i--) {
        const node = tab.childNodes[i];
        if (node.nodeType !== Node.TEXT_NODE) continue;
        const current = node.textContent.trim();
        if (!current) continue;
        if (current !== label) node.textContent = node.textContent.replace(current, label);
        return;
    }
    tab.appendChild(document.createTextNode(label));
}

function updateDisabledFeaturesCheckbox(featureId, isChecked, el) {
    // Update the hidden input value
    const hiddenInput = document.getElementById('setting-disabled_features');
    if (!hiddenInput) return;

    const currentDisabled = new Set(
        hiddenInput.value.split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
    );

    if (isChecked) {
        // Feature is being enabled (checked) - remove from disabled list
        currentDisabled.delete(featureId);
    } else {
        // Feature is being disabled (unchecked) - add to disabled list
        currentDisabled.add(featureId);
    }

    hiddenInput.value = Array.from(currentDisabled).sort().join(',');

    // Mark the toggle on or off
    const label = el ? el.closest('label') : null;
    if (label) {
        label.classList.toggle('is-on', isChecked);
        label.classList.toggle('is-off', !isChecked);
    }
}


async function fetchRwStatus() {
    try {
        const res = await authenticatedFetch('/api/rw-status');
        if (res.ok) {
            const data = await res.json();
            mailcowRwConfigured = data.rw_configured;
        }
    } catch (e) {
        console.warn('Failed to fetch RW status:', e);
        mailcowRwConfigured = false;
    }
    showQuarantineRulesAccess();
    // The key decides which actions the Security page offers; the flag may land after it drew
    if (currentTab === 'netfilter') {
        renderSecurityOverview();
        renderSecurityLists();
        renderSecuritySettings();
    }
}

// Auto-Rules release and delete held mail in mailcow, so they need the Read-Write key.
// The tab is always there; without the key it says what is missing. Returns whether rules can run.
function showQuarantineRulesAccess() {
    document.getElementById('quarantine-rules-section')?.classList.toggle('hidden', !mailcowRwConfigured);
    const locked = document.getElementById('quarantine-rules-locked');
    if (locked) {
        locked.classList.toggle('hidden', mailcowRwConfigured);
        locked.innerHTML = mailcowRwConfigured ? ''
            : uiLocked('Auto-Rules are locked', `Rules release or delete held messages in mailcow by themselves, so they ${UI_RW_KEY_TEXT}`);
    }
    return mailcowRwConfigured;
}

// Auto-refresh configuration
const AUTO_REFRESH_INTERVAL = 30000; // 30 seconds
let autoRefreshTimer = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', async () => {
    uiInitMenus();
    console.log('=== mailcow Logs Viewer Initializing ===');

    // Check authentication first
    const isAuthenticated = await checkAuthentication();
    if (!isAuthenticated) {
        console.log('Authentication required - showing login modal');
        return;
    }

    // Check if all required elements exist
    const requiredElements = [
        'app-title',
        'content-dashboard',
        'content-messages',
        'content-netfilter',
        'content-queue',
        'content-quarantine',
        'content-status',
        'content-settings',
        'content-domains'
    ];

    const missing = requiredElements.filter(id => !document.getElementById(id));
    if (missing.length > 0) {
        console.error('Missing required elements:', missing);
    } else {
        console.log('[OK] All required DOM elements found');
    }

    await loadAppInfo();
    loadMailcowVersionStatus();
    fetchRwStatus();

    // Initialize router and get initial route from URL
    const routeInfo = typeof initRouter === 'function' ? initRouter() : { baseRoute: 'dashboard', params: {} };
    const initialTab = routeInfo.baseRoute || routeInfo;
    const initialParams = routeInfo.params || {};
    console.log('Initial tab from URL:', initialTab, 'params:', initialParams);

    // Load the initial tab (use switchTab to ensure proper initialization)
    switchTab(initialTab, initialParams);

    // Start auto-refresh for all tabs
    startAutoRefresh();

    console.log('=== Initialization Complete ===');
});

// =============================================================================
// APP INFO & VERSION
// =============================================================================

async function loadAppInfo() {
    try {
        // Use regular fetch since this is called after authentication check
        const response = await authenticatedFetch('/api/info');
        const data = await response.json();

        if (data.app_title) {
            document.getElementById('app-title').textContent = data.app_title;
            document.title = data.app_title;
            // The phone top bar names the app above the page
            const phoneTitle = document.getElementById('mtop-app-title');
            if (phoneTitle) phoneTitle.textContent = data.app_title;

            // Update footer app name
            const footerName = document.getElementById('app-name-footer');
            if (footerName) {
                footerName.textContent = data.app_title;
            }
        }

        if (data.app_logo_url) {
            const logoImg = document.getElementById('app-logo');
            logoImg.src = data.app_logo_url;
            logoImg.classList.remove('hidden');
            document.getElementById('default-logo').classList.add('hidden');
            const phoneLogo = document.getElementById('mtop-logo');
            if (phoneLogo) phoneLogo.src = data.app_logo_url;
        }

        // Update footer version
        const footerVersion = document.getElementById('app-version-footer');
        if (footerVersion && data.version) {
            footerVersion.textContent = `v${data.version}`;
        }

        // Show/hide logout button based on auth status
        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            if (data.auth_enabled) {
                logoutBtn.classList.remove('hidden');
            } else {
                logoutBtn.classList.add('hidden');
            }
        }

        // Store timezone for date formatting
        if (data.timezone) {
            appTimezone = data.timezone;
            console.log('Timezone loaded from API:', appTimezone);
        } else {
            console.warn('No timezone in API response, using default:', appTimezone);
        }

        // Load disabled features and apply tab hiding
        if (data.disabled_features && Array.isArray(data.disabled_features)) {
            window.disabledFeatures = data.disabled_features;
            console.log('Disabled features:', window.disabledFeatures);
            applyFeatureToggles();
        }

        // Load app version status for update check
        await loadAppVersionStatus();

        // Load mailcow connection status
        await loadMailcowConnectionStatus();

        // Sidebar counters and server card
        placeShellUtilities();
        window.matchMedia('(max-width: 760px)').addEventListener('change', placeShellUtilities);
        loadNavCounters();
        setInterval(loadNavCounters, 5 * 60 * 1000);
    } catch (error) {
        console.error('Failed to load app info:', error);
    }
}

// =============================================================================
// SIDEBAR: SERVER CARD, COUNTERS AND TOOLS
// =============================================================================

// The Refresh and theme buttons live in the sidebar foot; on phones, where the
// sidebar is hidden, the same elements move into the top bar.
function placeShellUtilities() {
    const tools = document.getElementById('ui-utilities');
    const phoneSlot = document.getElementById('ui-mtop-actions');
    const foot = document.getElementById('app-footer');
    if (!tools || !phoneSlot || !foot) return;
    if (window.matchMedia('(max-width: 760px)').matches) {
        if (tools.parentNode !== phoneSlot) phoneSlot.appendChild(tools);
    } else if (tools.parentNode !== foot) {
        foot.appendChild(tools);
    }
}

// The sidebar and the phone More sheet show the same counters
function setNavCount(page, count, isFail, title) {
    for (const el of [document.getElementById(`nav-count-${page}`), document.getElementById(`mobile-nav-count-${page}`)]) {
        if (!el) continue;
        if (count > 0) {
            el.textContent = count.toLocaleString();
            el.classList.toggle('is-fail', !!isFail);
            el.title = title || '';
            el.classList.remove('hidden');
        } else {
            el.classList.add('hidden');
        }
    }
}

// Counters next to the pages that can need attention, and the problems shown
// on the server card, the phone top bar and the Status tab.
async function loadNavCounters() {
    const off = feature => (window.disabledFeatures || []).includes(feature);
    const get = async url => {
        try {
            const res = await authenticatedFetch(url);
            return res.ok ? await res.json() : null;
        } catch (e) {
            return null;
        }
    };
    const [dashboard, queue, quarantine, insights, summary, blacklist, info] = await Promise.all([
        off('netfilter') ? null : get('/api/logs/netfilter/overview'),
        off('queue') ? null : get('/api/queue'),
        off('quarantine') ? null : get('/api/quarantine'),
        off('dmarc') ? null : get('/api/dmarc/insights'),
        get('/api/status/summary'),
        off('blacklist') ? null : get('/api/blacklist/summary'),
        get('/api/settings/info'),
    ]);

    const failedLogins = dashboard ? dashboard.failed_logins || 0 : 0;
    setNavCount('netfilter', failedLogins, false, `${failedLogins} failed logins in the last 24 hours`);
    const queued = queue && Array.isArray(queue.data) ? queue.data.length : 0;
    setNavCount('queue', queued, false, `${queued} messages in the queue`);
    const held = quarantine ? (quarantine.total || (quarantine.data || []).length) : 0;
    setNavCount('quarantine', held, false, `${held} quarantined messages`);
    const dmarcActions = insights ? (insights.insights || []).filter(i =>
        i.recommendations.some(r => r.type === 'tighten_policy' || r.type === 'low_pass_rate') ||
        (i.new_sources && i.new_sources.length > 0)).length : 0;
    setNavCount('dmarc', dmarcActions, false, `${dmarcActions} DMARC insights`);

    const problems = [];
    const indicator = document.getElementById('mailcow-connection-indicator');
    if (indicator && indicator.title === 'Not connected to mailcow') problems.push('not connected to mailcow');
    const stopped = summary && summary.containers ? summary.containers.stopped || 0 : 0;
    if (stopped > 0) problems.push(`${stopped} container${stopped === 1 ? '' : 's'} stopped`);
    if (blacklist && blacklist.status === 'listed') problems.push('listed on a blocklist');
    setNavCount('status', problems.length, true, problems.join(', '));

    const label = problems.length === 0 ? 'No problems' : `${problems.length} problem${problems.length === 1 ? '' : 's'}`;
    const small = document.getElementById('ui-server-problems');
    if (small) {
        small.textContent = label;
        small.title = problems.join(', ');
        small.classList.toggle('has-problems', problems.length > 0);
    }
    const pill = document.getElementById('ui-problems-pill');
    if (pill) {
        pill.textContent = label;
        pill.title = problems.join(', ');
        pill.classList.toggle('hidden', problems.length === 0);
    }
    const pip = document.getElementById('tabbar-pip-status');
    if (pip) pip.classList.toggle('hidden', problems.length === 0);

    const host = document.getElementById('ui-server-host');
    const url = info && info.configuration ? info.configuration.mailcow_url : '';
    if (host && url) {
        try { host.textContent = new URL(url).hostname; } catch (e) { host.textContent = url; }
    }
}

async function loadMailcowConnectionStatus() {
    try {
        const response = await authenticatedFetch('/api/status/mailcow-connection');
        if (!response.ok) return;

        const data = await response.json();
        const indicator = document.getElementById('mailcow-connection-indicator');

        if (indicator) {
            indicator.classList.remove('hidden');
            if (data.connected) {
                indicator.classList.remove('text-red-500');
                indicator.classList.add('text-green-500');
                indicator.title = 'Connected to mailcow';
                // Update SVG to checkmark
                const svg = indicator.querySelector('svg');
                if (svg) {
                    svg.innerHTML = '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>';
                }
            } else {
                indicator.classList.remove('text-green-500');
                indicator.classList.add('text-red-500');
                indicator.title = 'Not connected to mailcow';
                // Update SVG to X
                const svg = indicator.querySelector('svg');
                if (svg) {
                    svg.innerHTML = '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path>';
                }
            }
        }
    } catch (error) {
        console.error('Failed to load mailcow connection status:', error);
        const indicator = document.getElementById('mailcow-connection-indicator');
        if (indicator) {
            indicator.classList.remove('hidden');
            indicator.classList.remove('text-green-500');
            indicator.classList.add('text-gray-400');
            indicator.title = 'Connection status unknown';
        }
    }
}

async function loadAppVersionStatus() {
    try {
        const response = await authenticatedFetch('/api/status/app-version');
        if (!response.ok) return;

        const data = await response.json();
        const updateBadge = document.getElementById('update-badge');
        const footerVersion = document.getElementById('app-version-footer');

        if (footerVersion) {
            footerVersion.textContent = `v${data.current_version}`;
        }

        if (updateBadge && data.update_available) {
            updateBadge.classList.remove('hidden');
            updateBadge.title = `Update available: v${data.latest_version}`;
            // Say which product the update is for (the mailcow line has its own)
            updateBadge.textContent = `v${data.latest_version} available`;

            // Allow clicking badge to view changelog
            appUpdateInfo = data;
            updateBadge.onclick = (e) => {
                e.preventDefault();
                e.stopPropagation();
                showAppUpdateModal();
            };
        } else if (updateBadge) {
            updateBadge.classList.add('hidden');
        }
    } catch (error) {
        console.error('Failed to load app version status:', error);
    }
}

// The available app update; the header badge and the dashboard alert open its changelog
let appUpdateInfo = null;

function showAppUpdateModal() {
    if (!appUpdateInfo) return;
    showMarkdownModal(`Update: v${appUpdateInfo.latest_version}`, appUpdateInfo.changelog || 'No changelog available');
}

// Helper to show markdown content in the changelog modal
function showMarkdownModal(title, markdownContent) {
    let htmlContent = markdownContent;
    try {
        if (typeof marked !== 'undefined') {
            marked.setOptions({
                breaks: true,
                gfm: true
            });
            htmlContent = renderMarkdown(markdownContent);
        }
    } catch (e) {
        console.error('Failed to parse markdown:', e);
    }

    // On a phone it opens in a sheet that grows to the full screen as it is read
    if (uiIsPhone()) {
        uiSheetShow('markdown-sheet', {
            label: title,
            head: `<h3 class="ui-sheet-title">${escapeHtml(title)}</h3>`,
            body: `<div class="markdown-body">${htmlContent}</div>`,
            expand: true
        });
        return;
    }

    const modal = document.getElementById('changelog-modal');
    const modalTitle = modal?.querySelector('h3');
    const content = document.getElementById('changelog-content');

    if (modal && content) {
        if (modalTitle) {
            modalTitle.textContent = title;
        }

        // Add some basic styling for markdown content
        content.innerHTML = `<div class="markdown-body">${htmlContent}</div>`;
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    }
}

async function loadMailcowVersionStatus() {
    try {
        const response = await authenticatedFetch('/api/status/version');
        if (!response.ok) return;

        const data = await response.json();
        const updateIcon = document.getElementById('mailcow-update-icon');
        const footerVersion = document.getElementById('mailcow-version-footer');
        const footerUpdateBadge = document.getElementById('mailcow-update-badge');

        // Update footer version text
        if (footerVersion && data.current_version) {
            footerVersion.textContent = `mailcow: v${data.current_version}`;
        }

        // Handle update indicators (both header icon and footer badge)
        if (data.update_available) {
            // Update global state for the shared modal function
            window.mailcowUpdateVersion = data.latest_version;
            window.mailcowUpdateName = data.name || '';
            window.mailcowUpdateChangelog = data.changelog || 'No changelog available';
            if (footerUpdateBadge) footerUpdateBadge.textContent = `mailcow ${data.latest_version} available`;

            // Function to handle clicks using the shared logic
            const handleClick = (e) => {
                e.preventDefault();
                e.stopPropagation();
                showMailcowUpdateModal();
            };

            // Header Icon
            if (updateIcon) {
                updateIcon.classList.remove('hidden');
                updateIcon.title = `Update available: ${data.latest_version}`;
                updateIcon.onclick = handleClick;
            }

            // Footer Badge
            if (footerUpdateBadge) {
                footerUpdateBadge.classList.remove('hidden');
                footerUpdateBadge.title = `Update available: ${data.latest_version}`;
                footerUpdateBadge.onclick = handleClick;
            }
        } else {
            if (updateIcon) updateIcon.classList.add('hidden');
            if (footerUpdateBadge) footerUpdateBadge.classList.add('hidden');
        }
    } catch (error) {
        console.error('Failed to load mailcow version status:', error);
    }
}

// =============================================================================
// AUTO-REFRESH SYSTEM - Smart refresh (only updates when data changes)
// =============================================================================

// Cache for last fetched data (to compare and detect changes)
let lastDataCache = {
    messages: null,
    netfilter: null,
    queue: null,
    quarantine: null,
    dashboard: null,
    settings: null
};

// Cache for version info (separate from settings cache, doesn't update on smart refresh)
let versionInfoCache = {
    app_version: null,
    version_info: null
};

function startAutoRefresh() {
    // Clear existing timer if any
    if (autoRefreshTimer) {
        clearInterval(autoRefreshTimer);
    }

    // Set up auto-refresh interval
    autoRefreshTimer = setInterval(() => {
        smartRefreshCurrentTab();
    }, AUTO_REFRESH_INTERVAL);

    console.log(`[OK] Auto-refresh started (every ${AUTO_REFRESH_INTERVAL / 1000}s)`);
}

function stopAutoRefresh() {
    if (autoRefreshTimer) {
        clearInterval(autoRefreshTimer);
        autoRefreshTimer = null;
        console.log('[STOP] Auto-refresh stopped');
    }
}

// Smart refresh - fetches data silently and only updates if changed
async function smartRefreshCurrentTab() {
    // Don't refresh if modal is open
    const modal = document.getElementById('message-modal');
    if (modal && !modal.classList.contains('hidden') && !modal.classList.contains('ui-docked')) {
        return;
    }

    try {
        switch (currentTab) {
            case 'dashboard':
                await smartRefreshDashboard();
                break;
            case 'messages':
                await smartRefreshMessages();
                break;
            case 'netfilter':
                await smartRefreshNetfilter();
                await loadSecurityOverview();
                fail2banSettingsLoaded = false;
                loadFail2BanSettings();
                if (typeof refreshProtectionHits === 'function') refreshProtectionHits();
                break;
            case 'queue':
                await smartRefreshQueue();
                break;
            case 'quarantine':
                await smartRefreshQuarantine();
                break;
            case 'status':
                await loadStatus(); // Status is fast, just reload
                break;
            case 'settings':
                await smartRefreshSettings();
                break;
            case 'spam-filter':
                await smartRefreshSpamFilter();
                break;
        }
    } catch (error) {
        console.error('Auto-refresh error:', error);
    }
}

// Helper to check if data changed
function hasDataChanged(newData, cacheKey) {
    const oldData = lastDataCache[cacheKey];
    if (!oldData) return true;

    // Compare JSON strings for simple change detection
    const newJson = JSON.stringify(newData);
    const oldJson = JSON.stringify(oldData);
    return newJson !== oldJson;
}

// Smart refresh for Messages - only update if new messages arrived
// Only refreshes if there are no active filters/search (to avoid disrupting user's view)
async function smartRefreshMessages() {
    const filters = currentFilters.messages || {};

    // Don't refresh if user has active search or filters
    const hasActiveFilters = filters.search || filters.sender || filters.recipient ||
        filters.direction || filters.status || filters.user || filters.ip;

    // Don't refresh if user is not on first page
    if (hasActiveFilters || currentPage.messages > 1) {
        return; // Skip refresh to avoid disrupting user's view
    }

    const params = new URLSearchParams({
        page: currentPage.messages,
        limit: 50
    });

    if (filters.search) params.append('search', filters.search);
    if (filters.sender) params.append('sender', filters.sender);
    if (filters.recipient) params.append('recipient', filters.recipient);
    if (filters.direction) params.append('direction', filters.direction);
    if (filters.status) params.append('status', filters.status);
    if (filters.user) params.append('user', filters.user);
    if (filters.ip) params.append('ip', filters.ip);

    const response = await authenticatedFetch(`/api/messages?${params}`);
    if (!response.ok) return;

    const data = await response.json();

    if (hasDataChanged(data, 'messages')) {
        console.log('[REFRESH] Messages data changed, updating UI');
        lastDataCache.messages = data;
        renderMessagesData(data);
    }
}

// Render messages without loading spinner
// One row of the Messages list (also used by the smart refresh), as in the
// mockup: sender and time, subject, then the outcome tag and the direction.
// Queue ID, message ID, score, user and IP are in the reading pane.
function renderMessageRow(msg) {
    const tone = messageRowTone(msg);
    return `
        <div class="ui-msg-item${tone ? ` ui-msg-${tone}` : ''}" data-key="${escapeHtml(msg.correlation_key || '')}" onclick="viewMessageDetails('${escapeJsArg(msg.correlation_key)}')">
            <div class="ui-msg-l1">
                <b class="ui-msg-from">${escapeHtml(msg.sender || 'Unknown')}</b>
                <time title="${escapeHtml(formatTime(msg.first_seen))}">${formatListTime(msg.first_seen)}</time>
            </div>
            <p class="ui-msg-sub" dir="auto" title="${escapeHtml(msg.subject || 'No subject')}">${escapeHtml(msg.subject || 'No subject')}</p>
            <div class="ui-msg-l3">
                ${uiCorrelationTag(msg)}
                ${msg.direction ? uiDirectionTag(msg.direction) : ''}
                ${msg.is_spam ? '<span class="ui-tag ui-tag-spam">SPAM</span>' : ''}
                <span class="ui-msg-to" title="${escapeHtml(msg.recipient || '')}">to ${escapeHtml(msg.recipient || 'Unknown')}</span>
                ${renderMailboxFolderHint(msg)}
                ${renderDeliveriesChip(msg)}
            </div>
        </div>`;
}

// The coloured edge of a row follows its final status.
function messageRowTone(msg) {
    const tone = UI_STATUS_TONE[msg.final_status];
    if (tone) return tone;
    return msg.is_complete === false ? 'warn' : '';
}

function renderMessagesData(data) {
    const container = document.getElementById('messages-logs');
    if (!container) return;

    if (!data.data || data.data.length === 0) {
        container.innerHTML = '<p class="ui-empty">No messages found</p>';
        return;
    }

    renderMessagesList(container, data);
    if (typeof markSelectedMessageRow === 'function' && window.openMessageKey) markSelectedMessageRow(window.openMessageKey);
}

// ---------- Messages list: the next page loads as the end scrolls into view ----------
const messagesPaging = { page: 1, pages: 1, total: 0, loading: false, observer: null };

function messagesQueryParams(page) {
    const filters = currentFilters.messages || {};
    const params = new URLSearchParams({ page: page, limit: 50 });
    for (const key of ['search', 'sender', 'recipient', 'direction', 'user', 'status', 'ip', 'start_date', 'end_date']) {
        if (filters[key]) params.append(key, filters[key]);
    }
    return params;
}

function messagesMoreText() {
    if (messagesPaging.page < messagesPaging.pages) return 'Loading more...';
    return messagesPaging.total ? `All ${messagesPaging.total} messages shown` : '';
}

function renderMessagesList(container, data) {
    messagesPaging.page = data.page || 1;
    messagesPaging.pages = data.pages || 1;
    messagesPaging.total = data.total || data.data.length;
    container.innerHTML = `
        <div class="ui-msg-list">${data.data.map(renderMessageRow).join('')}</div>
        <p id="messages-more" class="ui-msg-more" aria-live="polite">${messagesMoreText()}</p>
    `;
    watchMessagesEnd(container);
}

function watchMessagesEnd(container) {
    if (messagesPaging.observer) messagesPaging.observer.disconnect();
    const sentinel = document.getElementById('messages-more');
    if (!sentinel || typeof IntersectionObserver === 'undefined') return;
    // The list scrolls inside its own column; on narrow screens the page scrolls
    const root = container.scrollHeight > container.clientHeight + 1 || getComputedStyle(container).overflowY !== 'visible' ? container : null;
    messagesPaging.observer = new IntersectionObserver(entries => {
        if (entries.some(e => e.isIntersecting)) loadMoreMessages();
    }, { root, rootMargin: '0px 0px 600px 0px' });
    messagesPaging.observer.observe(sentinel);
}

async function loadMoreMessages() {
    if (messagesPaging.loading || messagesPaging.page >= messagesPaging.pages) return;
    const list = document.querySelector('#messages-logs .ui-msg-list');
    const more = document.getElementById('messages-more');
    if (!list) return;
    messagesPaging.loading = true;
    const next = messagesPaging.page + 1;
    try {
        const response = await authenticatedFetch(`/api/messages?${messagesQueryParams(next)}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        // New mail can shift a page; never show the same message twice
        const seen = new Set([...list.querySelectorAll('.ui-msg-item[data-key]')].map(row => row.dataset.key));
        list.insertAdjacentHTML('beforeend', (data.data || []).filter(msg => !seen.has(msg.correlation_key || '')).map(renderMessageRow).join(''));
        messagesPaging.page = next;
        messagesPaging.pages = data.pages || messagesPaging.pages;
        currentPage.messages = next;
        if (more) more.textContent = messagesMoreText();
        if (typeof markSelectedMessageRow === 'function' && window.openMessageKey) markSelectedMessageRow(window.openMessageKey);
    } catch (error) {
        if (more) more.innerHTML = `Could not load more messages. <button type="button" class="ui-link-row ui-link" onclick="loadMoreMessages()">Try again</button>`;
    } finally {
        messagesPaging.loading = false;
    }
    // A short page may leave the end still in view
    const sentinel = document.getElementById('messages-more');
    const container = document.getElementById('messages-logs');
    if (sentinel && container && messagesPaging.page < messagesPaging.pages) {
        const r = sentinel.getBoundingClientRect();
        const box = container.getBoundingClientRect();
        if (r.top < Math.max(box.bottom, window.innerHeight) + 600) loadMoreMessages();
    }
}

// Deduplicate netfilter logs based on message + time + priority
function deduplicateNetfilterLogs(logs) {
    if (!logs || logs.length === 0) return [];

    const seen = new Set();
    const uniqueLogs = [];

    for (const log of logs) {
        // Create unique key from message + time + priority
        const key = `${log.message || ''}|${log.time || ''}|${log.priority || ''}`;

        if (!seen.has(key)) {
            seen.add(key);
            uniqueLogs.push(log);
        }
    }

    return uniqueLogs;
}

// Render netfilter without loading spinner (for smart refresh)
function renderNetfilterData(data) {
    const container = document.getElementById('netfilter-logs');
    if (!container) return;

    if (!data.data || data.data.length === 0) {
        container.innerHTML = '<p class="ui-empty">No logs found</p>';
        return;
    }

    // Deduplicate logs
    const uniqueLogs = deduplicateNetfilterLogs(data.data);

    // Update count display with total count from API (like Messages page)
    const countEl = document.getElementById('security-count');
    if (countEl) {
        countEl.textContent = data.total ? `(${data.total.toLocaleString()} results)` : '';
    }

    // Build a set of currently banned IPs for quick lookup
    const activeBannedIPs = new Set();
    if (fail2banActiveBans && fail2banActiveBans.length > 0) {
        fail2banActiveBans.forEach(function(ban) {
            if (ban.ip) activeBannedIPs.add(ban.ip);
            if (ban.network) {
                // Extract base IP from network notation like "1.2.3.0/24"
                const baseIp = ban.network.split('/')[0];
                activeBannedIPs.add(baseIp);
                activeBannedIPs.add(ban.network);
            }
        });
    }

    // Without a Read-Write key the Ban and Unban buttons are not offered; say so
    const lockedNote = mailcowRwConfigured ? '' : `<div class="ui-list-note">${uiLocked('Ban and Unban are locked', `Banning or unbanning an IP from this list ${UI_RW_KEY_TEXT}`)}</div>`;

    const tabCount = document.getElementById('security-tab-n-events');
    if (tabCount) {
        tabCount.textContent = data.total ? data.total.toLocaleString() : '';
        tabCount.classList.toggle('hidden', !data.total);
    }

    container.innerHTML = `
        ${lockedNote}
        <div class="ui-ev-list">
            <div class="ui-ev-row ui-ev-head"><span>When</span><span>Address</span><span>Account</span><span>Action</span><span>Where</span><span></span></div>
            ${uniqueLogs.map((log, index) => {
                const isBan = log.action === 'ban' || log.action === 'banned';
                const isWarningOrUnban = log.action === 'warning' || log.action === 'unban';
                // Check if IP is in the blacklist (with or without /32)
                const ipInBlacklist = log.ip && fail2banBlacklist.some(entry => entry === log.ip || entry === log.ip + '/32');
                // Show unban if: banned OR already in blacklist
                const showUnban = mailcowRwConfigured && log.ip && (isBan || ipInBlacklist);
                // Show ban if: warning/unban AND NOT already in blacklist
                const showBan = mailcowRwConfigured && log.ip && isWarningOrUnban && !ipInBlacklist;
                const flagUrl = log.country_code ? getFlagUrl(log.country_code, '16x12') : '';
                const place = [log.country_name, log.city].filter(Boolean).join(', ');
                const org = log.asn_org ? ` (${log.asn_org})` : '';
                const account = log.username && log.username !== '-' ? copyableText(log.username)
                    : (log.attempts_left !== null && log.attempts_left !== undefined ? `<span class="ui-muted">${log.attempts_left} attempts left</span>` : '<span class="ui-muted">-</span>');
                return `
                <div class="ui-ev-row ui-msg-${uiActionTone(log.action)}">
                    <time class="ui-muted" title="${escapeHtml(formatTime(log.time))}">${formatListTime(log.time)}</time>
                    <b class="ui-mono">${log.ip ? copyableText(log.ip) : '-'}</b>
                    <span class="ui-ev-account">${account}</span>
                    <span>${uiActionTag(log.action)}</span>
                    <span class="ui-ev-where" title="${escapeHtml(place + org)}">${flagUrl ? `<img src="${flagUrl}" alt="" width="16" height="12" onerror="this.style.display='none'">` : ''}${escapeHtml(place || '-')}</span>
                    <span class="ui-st-acts">
                        ${showUnban ? `<button onclick="unbanIP('${escapeJsArg(log.ip)}', this)" class="ui-btn ui-btn-sm" title="Unban ${escapeHtml(log.ip)}/32">Unban</button>` : ''}
                        ${showBan ? `<button onclick="banIP('${escapeJsArg(log.ip)}', this)" class="ui-btn ui-btn-sm ui-btn-danger" title="Ban ${escapeHtml(log.ip)}/32">Ban</button>` : ''}
                        <button type="button" class="ui-icon-btn ui-icon-btn-sm ui-ev-toggle" aria-expanded="false" aria-controls="ev-detail-${index}" title="Show the log line" onclick="toggleEventDetail(this)"><svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg></button>
                    </span>
                    <div class="ui-ev-detail" id="ev-detail-${index}" hidden>
                        <p class="ui-mono">${escapeHtml(log.message || '-')}</p>
                        ${place || org ? `<p class="ui-muted">${escapeHtml([log.country_name, log.city].filter(Boolean).join(' '))}${escapeHtml(org)}</p>` : ''}
                    </div>
                </div>`;
            }).join('')}
        </div>
        ${renderPagination('netfilter', data.page, data.pages)}
    `;
}

function toggleEventDetail(btn) {
    const detail = document.getElementById(btn.getAttribute('aria-controls'));
    if (!detail) return;
    detail.hidden = !detail.hidden;
    btn.setAttribute('aria-expanded', !detail.hidden);
}

async function unbanIP(ip, btnEl) {
    const ipWithMask = ip.includes('/') ? ip : ip + '/32';
    if (!await showConfirmModal({ title: 'Unban IP', message: 'Unban IP ' + ipWithMask + '?', confirmText: 'Unban' })) return;
    try {
        if (btnEl) {
            btnEl.disabled = true;
            btnEl.textContent = 'Unbanning...';
        }
        const res = await authenticatedFetch('/api/fail2ban/unban', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ipWithMask })
        });
        const result = await res.json();
        if (res.ok && result.status === 'success') {
            showToast('IP ' + ip + ' unbanned successfully', 'success');
            // mailcow queues the unban and lifts it a few seconds later: the address
            // leaves the lists now, and Fail2ban is asked again once it has acted
            const bare = entry => String(entry || '').replace(/\/(32|128)$/, '');
            if (fail2banActiveBans) fail2banActiveBans = fail2banActiveBans.filter(b => bare(b.ip || b.network) !== bare(ip));
            renderSecurityOverview();
            refreshSecurityAddresses();
            setTimeout(() => { fail2banSettingsLoaded = false; loadFail2BanSettings(); }, 5000);
            smartRefreshNetfilter();
        } else {
            showToast('Failed to unban: ' + (result.msg || result.detail || 'Unknown error'), 'error');
            if (btnEl) {
                btnEl.disabled = false;
                btnEl.textContent = 'Unban';
            }
        }
    } catch (err) {
        showToast('Failed to unban IP: ' + err.message, 'error');
        if (btnEl) {
            btnEl.disabled = false;
            btnEl.textContent = 'Unban';
        }
    }
}

async function banIP(ip, btnEl) {
    const ipWithMask = ip.includes('/') ? ip : ip + '/32';
    if (!await showConfirmModal({ title: 'Ban IP', message: `Are you sure you want to permanently ban ${ipWithMask}?\n\nThis will add the IP to the Fail2Ban blacklist.`, confirmText: 'Ban', isDangerous: true })) return;

    if (btnEl) {
        btnEl.disabled = true;
        btnEl.innerHTML = '<span class="loading-spinner-sm"></span>Banning...';
    }

    try {
        const response = await authenticatedFetch('/api/fail2ban/ban', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ipWithMask })
        });

        const result = await response.json();

        if (result.status === 'success') {
            showToast(`IP ${ip} added to blacklist`, 'success');
            // Refresh fail2ban data and netfilter logs
            fail2banSettingsLoaded = false;
            fail2banActiveBans = null;
            loadFail2BanSettings();
            smartRefreshNetfilter();
        } else {
            showToast('Failed to ban: ' + (result.msg || result.detail || 'Unknown error'), 'error');
            if (btnEl) {
                btnEl.disabled = false;
                btnEl.textContent = 'Ban';
            }
        }
    } catch (err) {
        showToast('Failed to ban IP: ' + err.message, 'error');
        if (btnEl) {
            btnEl.disabled = false;
            btnEl.textContent = 'Ban';
        }
    }
}

async function allowIP(ip, btnEl) {
    const ipWithMask = ip.includes('/') ? ip : ip + '/32';
    if (!await showConfirmModal({ title: 'Allow IP', message: `Add ${ipWithMask} to the Fail2Ban allowlist?\n\nFailed attempts from this address will never lead to a ban.`, confirmText: 'Allow' })) return;
    if (btnEl) {
        btnEl.disabled = true;
        btnEl.textContent = 'Allowing...';
    }
    try {
        const res = await authenticatedFetch('/api/fail2ban/allow', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ipWithMask })
        });
        const result = await res.json();
        if (res.ok && result.status === 'success') {
            showToast(`IP ${ip} added to the allowlist`, 'success');
            fail2banSettingsLoaded = false;
            fail2banActiveBans = null;
            loadFail2BanSettings();
            return;
        }
        showToast('Failed to allow: ' + (result.msg || result.detail || 'Unknown error'), 'error');
    } catch (err) {
        showToast('Failed to allow IP: ' + err.message, 'error');
    }
    if (btnEl) {
        btnEl.disabled = false;
        btnEl.textContent = 'Allow';
    }
}

async function loadNetfilterCountries() {
    try {
        const select = document.getElementById('netfilter-filter-country');
        if (!select) return;
        
        const response = await authenticatedFetch('/api/logs/netfilter/countries');
        if (!response.ok) return;
        
        const countries = await response.json();
        
        // Preserve current selection
        const currentValue = select.value;
        
        // Clear existing options except the "All Countries" default
        select.innerHTML = '<option value="">All Countries</option>';
        
        for (const c of countries) {
            const opt = document.createElement('option');
            opt.value = c.code;
            opt.textContent = `${c.name || c.code}`;
            select.appendChild(opt);
        }
        
        // Restore selection
        if (currentValue) select.value = currentValue;
    } catch (err) {
        console.error('Failed to load netfilter countries:', err);
    }
}

// Smart refresh for Netfilter
async function smartRefreshNetfilter() {
    const filters = currentFilters.netfilter || {};
    const params = new URLSearchParams({
        page: currentPage.netfilter || 1,
        limit: 50,
        ...filters
    });

    const response = await authenticatedFetch(`/api/logs/netfilter?${params}`);
    if (!response.ok) return;

    const data = await response.json();

    if (hasDataChanged(data, 'netfilter')) {
        console.log('[REFRESH] Netfilter data changed, updating UI');
        lastDataCache.netfilter = data;
        // Use renderNetfilterData to update content without loading spinner (like Messages page)
        renderNetfilterData(data);
    }
}


// Smart refresh for Queue
async function smartRefreshQueue() {
    const response = await authenticatedFetch('/api/queue');
    if (!response.ok) return;

    const data = await response.json();

    if (hasDataChanged(data, 'queue')) {
        console.log('[REFRESH] Queue data changed, updating UI');
        lastDataCache.queue = data;
        allQueueData = data.data || [];
        updateQueueSummary();
        applyQueueFilters();
    }
}

// Smart refresh for Quarantine
async function smartRefreshQuarantine() {
    const response = await authenticatedFetch('/api/quarantine');
    if (!response.ok) return;

    const data = await response.json();

    if (hasDataChanged(data, 'quarantine')) {
        console.log('[REFRESH] Quarantine data changed, updating UI');
        lastDataCache.quarantine = data;
        renderQuarantineData(data);
    }
}

// Smart refresh for Dashboard
async function smartRefreshDashboard() {
    try {
        const response = await authenticatedFetch('/api/stats/dashboard');
        if (!response.ok) return;

        const data = await response.json();

        if (hasDataChanged(data, 'dashboard')) {
            console.log('[REFRESH] Dashboard data changed, updating UI');
            lastDataCache.dashboard = data;

            // Update stats without full reload
            dashboardStats = data;
            renderMailFlowStats();
        }

        // Also refresh recent activity and status summary
        loadRecentActivity();
        loadMailFlowChart();
        loadDashboardStatusSummary();
        loadDashboardSecurity();
    } catch (error) {
        console.error('Dashboard refresh error:', error);
    }
}

// Smart refresh for Settings
async function smartRefreshSettings() {
    try {
        const response = await authenticatedFetch('/api/settings/info');
        if (!response.ok) return;

        const data = await response.json();
        if (data.settings_edit_via_ui_enabled && !data.editable_config) {
            try {
                const editableRes = await authenticatedFetch('/api/settings');
                if (editableRes.ok) {
                    const editableData = await editableRes.json();
                    data.editable_config = editableData.configuration || {};
                }
            } catch (e) { /* ignore */ }
        }

        if (hasDataChanged(data, 'settings')) {
            const content = document.getElementById('settings-content');
            if (content && !content.classList.contains('hidden') && content.querySelector('#settings-edit-form')) {
                // User is on Settings tab with edit form open - skip auto-refresh to avoid interrupting (e.g. switching tabs)
                return;
            }
            console.log('[REFRESH] Settings data changed, updating UI');
            lastDataCache.settings = data;

            if (content && !content.classList.contains('hidden')) {
                // Preserve version info from cache (don't reload it on smart refresh)
                if (versionInfoCache.app_version) {
                    data.app_version = versionInfoCache.app_version;
                }
                if (versionInfoCache.version_info) {
                    data.version_info = versionInfoCache.version_info;
                }

                renderSettings(content, data);
            }
        }
    } catch (error) {
        console.error('Settings refresh error:', error);
    }
}

// =============================================================================
// TAB SWITCHING
// =============================================================================

function switchTab(tab, params = {}) {
    console.log('Switching to tab:', tab, 'params:', params);

    // Block disabled features - show a "Feature Disabled" page.
    // Exception: the Mailbox Stats page also hosts Rate Limits, so it stays
    // open while that feature is on, even with Mailbox Stats itself off.
    const hostsEnabledRateLimits = tab === 'mailbox-stats'
        && !window.disabledFeatures.includes('rate-limits');
    if (window.disabledFeatures.includes(tab) && !hostsEnabledRateLimits) {
        const feature = TOGGLEABLE_FEATURES.find(f => f.id === tab);
        const featureLabel = feature ? feature.label : tab;
        console.warn(`Feature '${tab}' is disabled`);

        currentTab = tab;

        // Hide all tab contents
        document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));

        // Show current tab with a disabled message
        const tabContent = document.getElementById(`content-${tab}`);
        if (tabContent) {
            tabContent.classList.remove('hidden');
            tabContent.innerHTML = `
                <div class="ui-disabled-page">
                    ${uiLocked(`${featureLabel} is disabled`, 'This feature has been turned off by the administrator in Settings → Application → Features.',
                        `<button onclick="navigateTo('dashboard')" class="ui-btn ui-btn-primary">Go to Dashboard</button>`)}
                </div>`;
        }

        // Update URL to reflect the disabled page (don't silently change to dashboard)
        const newPath = typeof buildPath === 'function' ? buildPath(tab) : `/${tab}`;
        if (window.location.pathname !== newPath) {
            history.replaceState({ route: tab, params: {} }, '', newPath);
        }
        return;
    }

    // The page is already open and only its tab changed (Back, Forward, the
    // sidebar flyout): switch the tab without loading the page again
    const tabPage = typeof SUBPAGES !== 'undefined' ? SUBPAGES[tab] : null;
    const pageEl = document.getElementById(`content-${tab}`);
    if (tabPage && params.sub && currentTab === tab && pageEl && !pageEl.classList.contains('hidden')) {
        tabPage.show(params.sub);
        return;
    }

    currentTab = tab;

    // Mark the current page in the sidebar and in the phone tab bar; "More"
    // is marked when the page is only reachable through the sheet
    document.querySelectorAll('[id^="tab-"], [id^="tabbar-"]').forEach(btn => btn.removeAttribute('aria-current'));
    for (const id of [`tab-${tab}`, `tabbar-${tab}`]) {
        const btn = document.getElementById(id);
        if (btn) btn.setAttribute('aria-current', 'page');
    }
    const moreBtn = document.getElementById('hamburger-btn');
    if (moreBtn) moreBtn.classList.toggle('ui-more-current', !document.getElementById(`tabbar-${tab}`));

    // Update mobile menu state and label
    if (typeof updateMobileMenuActiveState === 'function') {
        updateMobileMenuActiveState(tab);
    }
    if (typeof updateCurrentTabLabel === 'function') {
        updateCurrentTabLabel(tab);
    }

    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.add('hidden');
    });

    // Show current tab content
    const tabContent = document.getElementById(`content-${tab}`);
    if (tabContent) {
        tabContent.classList.remove('hidden');
    } else {
        console.error(`Tab content not found: content-${tab}`);
    }

    // Open the tab the address names, and correct an address that named none
    if (tabPage) {
        const sub = params.sub || tabPage.current();
        routerSyncSubpage(tab, sub, true);
        tabPage.select(sub);
    }

    // Load tab data
    console.log('Loading data for tab:', tab);
    // Disconnect log WebSocket when switching away from logs
    if (tab !== 'logs' && typeof disconnectLogWebSocket === 'function') {
        disconnectLogWebSocket();
    }

    switch (tab) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'messages':
            loadMessages(1);
            break;
        case 'netfilter':
            loadSecurityOverview();
            loadNetfilterLogs(1);
            loadFail2BanSettings();
            if (typeof loadProtection === 'function') loadProtection();
            loadNetfilterCountries();
            loadSmtpAbusePanel();
            loadSecurityAppSettings();
            loadSecurityCountryChart(securityChartDays);
            break;
        case 'queue':
            loadQueue();
            break;
        case 'quarantine':
            loadQuarantine();
            initQuarantineRules();
            break;
        case 'status':
            loadStatus();
            break;
        case 'domains':
            loadDomains();
            break;
        case 'dmarc':
            // Refresh passes no params: reload what the address shows (the TLS tab stays open)
            handleDmarcRoute(Object.keys(params).length ? params : parseRoute().params);
            break;
        case 'mailbox-stats':
            initMailboxStatsPage();
            break;
        case 'logs':
            loadLogViewer();
            break;
        case 'settings':
            loadSettings();
            break;
        case 'about':
            loadAbout();
            break;
        case 'spam-filter':
            loadSpamFilter();
            break;
        default:
            console.warn('Unknown tab:', tab);
    }
}

async function refreshAllData() {
    if (currentTab === 'dmarc') {
        try {
            await authenticatedFetch('/api/dmarc/cache/clear', { method: 'POST' });
            console.log('DMARC cache cleared');
        } catch (e) {
            console.error('Failed to clear DMARC cache:', e);
        }
    }
    switchTab(currentTab);
    loadNavCounters();
}

// =============================================================================
// DASHBOARD
// =============================================================================

async function loadDashboard() {
    try {
        console.log('Loading Dashboard...');

        const response = await authenticatedFetch('/api/stats/dashboard');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('Dashboard data:', data);

        dashboardStats = data;
        renderMailFlowStats();

        loadRecentActivity();
        loadDashboardStatusSummary();
        loadDashboardBlacklistSummary();
        loadDashboardHealth();
        loadDashboardSecurityAlerts();
        loadDashboardAttention();
        loadDashboardSecurity();
        loadMailFlowChart();
    } catch (error) {
        console.error('Failed to load dashboard:', error);
    }
}

async function loadDashboardSecurityAlerts() {
    const container = document.getElementById('dashboard-security-alerts');
    if (!container) return;
    const dismissAll = document.getElementById('dashboard-dismiss-all');
    try {
        const response = await authenticatedFetch('/api/security-alerts?acknowledged=false&limit=20');
        if (!response.ok) { container.classList.add('hidden'); updateAttentionState(); return; }
        const data = await response.json();
        const alerts = data.alerts || [];
        if (alerts.length === 0) {
            container.classList.add('hidden');
            container.innerHTML = '';
            if (dismissAll) dismissAll.classList.add('hidden');
            updateAttentionState();
            return;
        }

        container.innerHTML = alerts.map(a => {
            const critical = a.severity === 'critical';
            return `
                <div class="ui-alert ${critical ? 'ui-alert-fail' : 'ui-alert-warn'}">
                    <span class="ui-alert-bar"></span>
                    <div class="ui-alert-text">
                        <div class="ui-alert-title">
                            <span class="ui-tag ${critical ? 'ui-tag-fail' : 'ui-tag-warn'}">${escapeHtml((a.severity || 'warning').toUpperCase())}</span>
                            <b>${escapeHtml(a.title)}</b>
                        </div>
                        <p>${escapeHtml(a.detail || '')}</p>
                        <p class="ui-muted">${escapeHtml(formatTime(a.created_at))}</p>
                    </div>
                    <button type="button" onclick="acknowledgeSecurityAlert(${a.id})" class="ui-btn ui-btn-sm" title="Dismiss">Dismiss</button>
                </div>`;
        }).join('');
        container.classList.remove('hidden');
        if (dismissAll) dismissAll.classList.remove('hidden');
    } catch (e) {
        console.warn('Failed to load security alerts:', e);
        container.classList.add('hidden');
    }
    updateAttentionState();
}

// The count and the "all clear" line of Needs attention follow what is in it
function updateAttentionState() {
    const panel = document.getElementById('dashboard-attention-panel');
    if (!panel) return;
    const rows = panel.querySelectorAll('.ui-alert').length;
    const count = document.getElementById('dashboard-attention-count');
    if (count) count.textContent = rows ? String(rows) : '';
    const clear = document.getElementById('dashboard-attention-clear');
    if (clear) clear.classList.toggle('hidden', rows > 0);
}

// Server checks that need a look, each with the place to handle it
async function loadDashboardAttention() {
    const container = document.getElementById('dashboard-attention');
    if (!container) return;
    const off = feature => (window.disabledFeatures || []).includes(feature);
    const get = async url => {
        try {
            const res = await authenticatedFetch(url);
            return res.ok ? await res.json() : null;
        } catch (e) {
            return null;
        }
    };
    const [blacklist, summary, insights, appVersion, mailcowVersion, connection] = await Promise.all([
        off('blacklist') ? null : get('/api/blacklist/summary'),
        get('/api/status/summary'),
        off('dmarc') ? null : get('/api/dmarc/insights'),
        get('/api/status/app-version'),
        get('/api/status/version'),
        get('/api/status/mailcow-connection'),
    ]);
    const items = [];
    if (connection && connection.connected === false) {
        items.push({ tone: 'fail', title: 'mailcow is not reachable', detail: 'The mailcow API did not answer, so logs and server data may be out of date.', action: 'Open settings', onclick: "navigateTo('settings')" });
    }
    if (blacklist && blacklist.status === 'listed') {
        // Name the host that is actually listed, with its own list count
        const listedHosts = (blacklist.hosts || []).filter(h => h.status === 'listed');
        const first = listedHosts[0];
        const title = listedHosts.length > 1
            ? `${listedHosts.length} of your addresses are on a blocklist`
            : `${first ? first.hostname : (blacklist.server_ip || 'Your server')} is on a blocklist`;
        const detail = listedHosts.length > 1
            ? `${listedHosts.map(h => h.hostname).join(', ')}. Outbound mail to some providers may bounce.`
            : `Listed on ${first ? first.listed_count : blacklist.listed_count} of ${first && first.total_blacklists ? first.total_blacklists : blacklist.total_blacklists} lists. Outbound mail to some providers may bounce.`;
        items.push({ tone: 'fail', title, detail, action: 'Check listing', onclick: "navigateTo('status')" });
    }
    const containers = summary && summary.containers ? summary.containers : null;
    if (containers && containers.stopped > 0) {
        items.push({ tone: 'fail', title: containers.stopped === 1 ? 'A mailcow container is stopped' : `${containers.stopped} mailcow containers are stopped`,
            detail: `${containers.running || 0} of ${containers.total || 0} containers are running.`, action: 'Open status', onclick: "navigateTo('status')" });
    }
    const dmarc = insights ? (insights.insights || []).filter(i =>
        i.recommendations.some(r => r.type === 'tighten_policy' || r.type === 'low_pass_rate') || (i.new_sources && i.new_sources.length > 0)) : [];
    if (dmarc.length) {
        const first = dmarc[0].recommendations[0];
        items.push({ tone: 'warn', title: dmarc.length === 1 ? `DMARC needs attention for ${dmarc[0].domain}` : `DMARC needs attention for ${dmarc.length} domains`,
            detail: first ? first.message : 'New sources are failing DMARC.', action: 'Open DMARC', onclick: "navigateTo('dmarc')" });
    }
    if (appVersion && appVersion.update_available) {
        appUpdateInfo = appVersion;
        items.push({ tone: 'info', title: `Version ${appVersion.latest_version} is available`,
            detail: `You are running ${appVersion.current_version}. See what changed before updating.`, action: 'Read changes', onclick: 'showAppUpdateModal()' });
    }
    if (mailcowVersion && mailcowVersion.update_available) {
        items.push({ tone: 'info', title: `mailcow ${mailcowVersion.latest_version} is available`,
            detail: `You are running ${mailcowVersion.current_version}.`, action: 'Read changes', onclick: 'showMailcowUpdateModal()' });
    }
    container.innerHTML = items.map(item => `
        <div class="ui-alert ui-alert-${item.tone}">
            <span class="ui-alert-bar"></span>
            <div class="ui-alert-text"><div class="ui-alert-title"><b>${escapeHtml(item.title)}</b></div><p>${escapeHtml(item.detail)}</p></div>
            <button type="button" class="ui-btn ui-btn-sm" onclick="${item.onclick}">${escapeHtml(item.action)}</button>
        </div>`).join('');
    updateAttentionState();
}

// The dashboard's mail flow: the 24-hour figures, or those of one hour picked on the chart
let dashboardStats = null;
let mailFlowSlots = [];
let mailFlowPicked = null; // start of the picked hour (ms), or null for all 24 hours

function mailFlowHour(t) {
    return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', hour12: false,
        timeZone: appTimezone && appTimezone !== 'UTC' ? appTimezone : undefined }).format(new Date(t));
}

// A click on a bar shows that hour's numbers; the same bar again, or All 24 hours, goes back
function pickMailFlowHour(t) {
    mailFlowPicked = t === null || mailFlowPicked === t ? null : t;
    renderMailFlowStats();
}

function renderMailFlowStats() {
    const d = dashboardStats;
    if (!d) return;
    const slot = mailFlowPicked === null ? null : mailFlowSlots.find(s => s.t === mailFlowPicked);
    if (!slot) mailFlowPicked = null;
    const set = (id, text) => { const el = document.getElementById(id); if (el) el.textContent = text; };
    const n = v => (v || 0).toLocaleString();
    if (slot) {
        set('stat-messages-24h', n(slot.unique_messages));
        set('stat-blocked-24h', n(slot.blocked));
        set('stat-deferred-24h', n(slot.deferred));
        set('stat-auth-failures-24h', n(slot.auth_failures));
        set('stat-messages-note', `${n(slot.messages)} deliveries, 24h: ${n(d.messages.unique_24h)}`);
        set('stat-blocked-note', `24h: ${n(d.blocked['24h'])}`);
        set('stat-deferred-note', `24h: ${n(d.deferred['24h'])}`);
        set('stat-auth-failures-note', `24h: ${n(d.auth_failures['24h'])}`);
        set('dashboard-flow-title', `Mail flow, ${mailFlowHour(slot.t)} to ${mailFlowHour(slot.t + 3600000)}`);
    } else {
        set('stat-messages-24h', n(d.messages.unique_24h ?? d.messages['24h']));
        set('stat-blocked-24h', n(d.blocked['24h']));
        set('stat-deferred-24h', n(d.deferred['24h']));
        set('stat-auth-failures-24h', n(d.auth_failures['24h']));
        set('stat-messages-note', `${n(d.messages['24h'])} deliveries, 7d: ${n(d.messages.unique_7d ?? d.messages['7d'])}`);
        set('stat-blocked-note', `7d: ${n(d.blocked['7d'])} (${d.blocked.percentage_24h}%)`);
        set('stat-deferred-note', `7d: ${n(d.deferred['7d'])}`);
        set('stat-auth-failures-note', `7d: ${n(d.auth_failures['7d'])}`);
        set('dashboard-flow-title', 'Mail flow, last 24 hours');
    }
    document.getElementById('dashboard-flow-reset')?.classList.toggle('hidden', !slot);
    document.getElementById('dashboard-flow-view')?.classList.toggle('hidden', !slot);
    const bars = document.querySelector('#dashboard-flow-chart .ui-flow-bars');
    if (bars) {
        bars.classList.toggle('has-pick', !!slot);
        bars.querySelectorAll('.ui-flow-bar').forEach(b => b.setAttribute('aria-pressed', String(!!slot && Number(b.dataset.t) === slot.t)));
    }
}

// The picked hour's messages on the Messages page: its time filter set to that hour, the other filters cleared.
// Messages counts by the same first-seen time as the chart's Messages figure, so the two agree.
function openMailFlowHourMessages() {
    const slot = mailFlowSlots.find(s => s.t === mailFlowPicked);
    if (!slot) return;
    const start = new Date(slot.t).toISOString();
    const end = new Date(slot.t + 3600000 - 1).toISOString();
    ['search', 'sender', 'recipient', 'user', 'ip', 'direction', 'status'].forEach(key => {
        const el = document.getElementById(`messages-filter-${key}`);
        if (el) el.value = '';
    });
    document.getElementById('messages-date-range').value = 'custom';
    document.getElementById('messages-start-date').value = start;
    document.getElementById('messages-end-date').value = end;
    // The custom range picker shows the day the hour is on
    const day = new Intl.DateTimeFormat('en-CA', { year: 'numeric', month: '2-digit', day: '2-digit',
        timeZone: appTimezone && appTimezone !== 'UTC' ? appTimezone : undefined }).format(new Date(slot.t));
    document.getElementById('messages-date-range-start').value = day;
    document.getElementById('messages-date-range-end').value = day;
    const dayLabel = new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric',
        timeZone: appTimezone && appTimezone !== 'UTC' ? appTimezone : undefined }).format(new Date(slot.t));
    document.getElementById('messages-date-range-label').textContent = `${dayLabel}, ${mailFlowHour(slot.t)} to ${mailFlowHour(slot.t + 3600000)}`;
    setMessagesDatePresetActive(null);
    currentFilters.messages = { start_date: start, end_date: end };
    currentPage.messages = 1;
    navigateTo('messages');
}

// Hourly messages over the last 24 hours, clean and spam (Rspamd), as bars over a time axis
async function loadMailFlowChart() {
    const chart = document.getElementById('dashboard-flow-chart');
    if (!chart) return;
    let rows = [];
    try {
        const res = await authenticatedFetch('/api/stats/timeline?hours=24');
        if (res.ok) rows = (await res.json()).timeline || [];
    } catch (e) {
        rows = [];
    }
    const byHour = new Map(rows.map(r => [new Date(r.hour).getTime(), r]));
    // Hours are counted from the epoch, so any time zone lines up with the UTC buckets
    const now = Math.floor(Date.now() / 3600000) * 3600000;
    const slots = [];
    for (let i = 23; i >= 0; i--) {
        const t = now - i * 3600 * 1000;
        const r = byHour.get(t) || {};
        slots.push({ t, clean: r.clean || 0, spam: r.spam || 0, messages: r.messages || 0, unique_messages: r.unique_messages || 0, blocked: r.blocked || 0,
            deferred: r.deferred || 0, auth_failures: r.auth_failures || 0 });
    }
    mailFlowSlots = slots;
    const max = Math.max(1, ...slots.map(s => s.clean + s.spam));
    // The axis names every third hour (every sixth on phones) and ends at now
    const label = (s, i) => i === slots.length - 1 ? '<span class="is-major">Now</span>'
        : i % 6 === 0 ? `<span class="is-major">${mailFlowHour(s.t)}</span>`
        : i % 3 === 0 ? `<span class="is-minor">${mailFlowHour(s.t)}</span>` : '<span></span>';
    chart.innerHTML = `
        <div class="ui-flow-bars" role="group" aria-label="Messages per hour">${slots.map(s => `
            <button type="button" class="ui-flow-bar" data-t="${s.t}" aria-pressed="false" onclick="pickMailFlowHour(${s.t})"
                title="${mailFlowHour(s.t)} to ${mailFlowHour(s.t + 3600000)}: ${s.clean.toLocaleString()} clean, ${s.spam.toLocaleString()} spam. Click for this hour's numbers">
                <i class="ui-flow-spam" style="height: ${(s.spam / max) * 100}%"></i>
                <i class="ui-flow-clean" style="height: ${(s.clean / max) * 100}%"></i>
            </button>`).join('')}</div>
        <div class="ui-flow-axis" aria-hidden="true">${slots.map(label).join('')}</div>
        <div class="ui-flow-legend"><span><i class="ui-flow-clean"></i>Clean</span><span><i class="ui-flow-spam"></i>Spam</span></div>`;
    renderMailFlowStats();
}

async function acknowledgeSecurityAlert(alertId) {
    try {
        await authenticatedFetch(`/api/security-alerts/${alertId}/acknowledge`, { method: 'POST' });
        loadDashboardSecurityAlerts();
    } catch (e) {
        showToast('Failed to dismiss alert', 'error');
    }
}

async function acknowledgeAllSecurityAlerts() {
    try {
        await authenticatedFetch('/api/security-alerts/acknowledge-all', { method: 'POST' });
        loadDashboardSecurityAlerts();
        showToast('All security alerts dismissed', 'success');
    } catch (e) {
        showToast('Failed to dismiss alerts', 'error');
    }
}

// One dashboard health card: the big value, its tone and the line under it
function setDashKpi(id, value, tone, note) {
    const el = document.getElementById(id);
    if (el) { el.textContent = value; el.className = tone ? `ui-${tone}` : ''; }
    const noteEl = document.getElementById(`${id}-note`);
    if (noteEl && note !== undefined) noteEl.textContent = note;
}

// The Security card: whether the protections are on, and the Security page's two
// lists with the same real counts. Which protections are on is read once; the
// Security page keeps it current when it is opened.
async function loadDashboardSecurity() {
    const panel = document.getElementById('dashboard-security-panel');
    if (!panel) return;
    if (isFeatureDisabled('netfilter')) {
        panel.classList.add('hidden');
        return;
    }
    panel.classList.remove('hidden');
    const get = async url => {
        try {
            const res = await authenticatedFetch(url);
            return res.ok ? await res.json() : null;
        } catch (e) {
            return null;
        }
    };
    const [page, rules, abuse] = await Promise.all([
        get('/api/security/addresses?list=review&limit=1'),
        protectionSaved ? null : get('/api/protection/rules'),
        smtpAbuseStatus ? null : get('/api/smtp-abuse/status?limit=1'),
        fail2banSettingsLoaded ? null : loadFail2BanSettings(),
    ]);
    if (rules) {
        protectionCaps = rules.capabilities || protectionCaps;
        if (!protectionDirty) {
            protectionRules = rules.rules;
            protectionSaved = JSON.parse(JSON.stringify(rules.rules));
        }
    }
    if (abuse) smtpAbuseStatus = abuse;
    renderDashboardSecurity(page);
}

function renderDashboardSecurity(page) {
    const box = document.getElementById('dashboard-security');
    if (!box) return;
    const counts = page ? page.all_counts : null;
    const n = key => counts ? counts[key].toLocaleString() : '-';
    const protections = securityProtectionItems();
    const on = protections.filter(p => p.state === 'on');
    box.innerHTML = `
        <div class="ui-stats ui-dash-sec-stats">
            <button type="button" class="ui-stat" onclick="openSecurityList('review')"><span>To review</span><b>${n('review')}</b><small>Not banned</small></button>
            <button type="button" class="ui-stat" onclick="openSecurityList('banned')"><span>Banned now</span><b${counts && counts.banned ? ' class="ui-text-fail"' : ''}>${n('banned')}</b><small>By Fail2ban and the rules</small></button>
        </div>
        <button type="button" class="ui-dash-sec-prot${on.length ? ' is-on' : ''}" onclick="openSecuritySettings()" title="Open the protection settings">
            <span class="ui-prot-mark" aria-hidden="true">${on.length ? '✓' : '✕'}</span><b>Protection ${on.length} of ${protections.length} on</b>
            ${on.length ? `<span class="ui-dash-sec-on">${on.map(p => escapeHtml(p.name)).join(' · ')}</span>` : ''}
        </button>`;
}

// Jobs, message linking and the app version for the dashboard health cards
async function loadDashboardHealth() {
    try {
        const [infoRes, versionRes] = await Promise.all([authenticatedFetch('/api/settings/info'), authenticatedFetch('/api/status/app-version')]);
        if (infoRes.ok) {
            const info = await infoRes.json();
            const jobs = summarizeJobs(info.background_jobs || {});
            setDashKpi('dash-kpi-jobs', `${jobs.healthy} of ${jobs.running} healthy`, jobs.failed.length ? 'fail' : '',
                jobs.failed.length ? `${jobs.failed.map(([name]) => name).join(', ')} failed` : (jobs.off ? `${jobs.off} off with their feature` : 'None failed'));
            const c = info.correlation_status || {};
            setDashKpi('dash-kpi-linking', `${c.completion_rate || 0}%`, c.incomplete ? 'warn' : '',
                `${(c.complete || 0).toLocaleString()} of ${(c.total || 0).toLocaleString()} complete`);
        }
        if (versionRes.ok) {
            const v = await versionRes.json();
            setDashKpi('dash-kpi-version', v.current_version || '-', '', v.update_available ? `${v.latest_version} available` : 'Up to date');
        }
    } catch (error) {
        console.error('Failed to load dashboard health:', error);
    }
}

async function loadDashboardStatusSummary() {
    try {
        console.log('Loading Dashboard Status Summary...');

        const response = await authenticatedFetch('/api/status/summary');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('Status summary data:', data);

        // Containers: red when one is stopped; ignored ones are only mentioned
        const containers = data.containers || {};
        setDashKpi('dash-kpi-containers', `${containers.running || 0} of ${containers.total || 0} running`, containers.stopped > 0 ? 'fail' : '',
            [containers.stopped ? `${containers.stopped} stopped` : 'All running', containers.ignored ? `${containers.ignored} ignored` : ''].filter(Boolean).join(', '));

        // Storage: amber above 75%, red above 90%
        const storage = data.storage || {};
        const usedPercent = parseInt(storage.used_percent) || 0;
        const storageLevel = usedPercent > 90 ? 'fail' : usedPercent > 75 ? 'warn' : '';
        setDashKpi('dash-kpi-storage', `${storage.used_percent || '0%'} used`, storageLevel, `${storage.used || '0'} of ${storage.total || '0'}`);

        const systemDiv = document.getElementById('dashboard-system-summary');
        const system = data.system || {};
        systemDiv.innerHTML = `
            <div class="ui-kv"><span>Domains</span><b>${(system.domains || 0).toLocaleString()}</b></div>
            <div class="ui-kv"><span>Mailboxes</span><b>${(system.mailboxes || 0).toLocaleString()}</b></div>
            <div class="ui-kv"><span>Aliases</span><b>${(system.aliases || 0).toLocaleString()}</b></div>
        `;
    } catch (error) {
        console.error('Failed to load status summary:', error);
    }
}

async function loadRecentActivity() {
    const container = document.getElementById('recent-activity');

    try {
        console.log('Loading Recent Activity...');

        const response = await authenticatedFetch('/api/stats/recent-activity?limit=11');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('Recent Activity data:', data);

        if (data.activity.length === 0) {
            container.innerHTML = '<p class="ui-empty">No recent activity</p>';
            return;
        }

        // One compact row per message: time, outcome dot, who, subject
        container.innerHTML = data.activity.map(msg => {
            const tone = UI_STATUS_TONE[msg.status] || '';
            const state = `${msg.status || 'unknown'}${msg.direction ? `, ${msg.direction}` : ''}`;
            return `
            <div class="ui-mrow" onclick="viewMessageDetails('${escapeJsArg(msg.correlation_key)}')">
                <time title="${escapeHtml(formatTime(msg.time))}">${formatListTime(msg.time)}</time>
                <i class="ui-mdot${tone ? ` ui-mdot-${tone}` : ''}" title="${escapeHtml(state)}"></i>
                <span class="ui-mrow-who">${escapeHtml(msg.sender || 'Unknown')} → ${escapeHtml(msg.recipient || 'Unknown')}</span>
                <span class="ui-mrow-sub" dir="auto" title="${escapeHtml(msg.subject || 'No subject')}">${escapeHtml(msg.subject || 'No subject')}</span>
            </div>`;
        }).join('');
    } catch (error) {
        console.error('Failed to load recent activity:', error);
        document.getElementById('recent-activity').innerHTML = `<p class="ui-empty ui-text-fail">Failed to load activity: ${escapeHtml(error.message)}</p>`;
    }
}

function performDashboardSearch() {
    const query = document.getElementById('dashboard-search-query').value;
    const status = document.getElementById('dashboard-search-status').value;

    // Set filters on Messages page
    document.getElementById('messages-filter-search').value = query;
    document.getElementById('messages-filter-sender').value = '';
    document.getElementById('messages-filter-recipient').value = '';
    document.getElementById('messages-filter-direction').value = '';
    document.getElementById('messages-filter-status').value = status;
    document.getElementById('messages-filter-user').value = '';

    // Apply filters
    currentFilters.messages = {
        search: query,
        status: status
    };
    currentPage.messages = 1;

    // Switch to Messages tab and load
    switchTab('messages');
}

// =============================================================================
// NETFILTER LOGS
// =============================================================================

function applyNetfilterFilters() {
    currentFilters.netfilter = {
        ip: document.getElementById('netfilter-filter-ip').value,
        username: document.getElementById('netfilter-filter-username').value,
        action: document.getElementById('netfilter-filter-action').value,
        country_code: document.getElementById('netfilter-filter-country').value
    };
    currentPage.netfilter = 1;
    loadNetfilterLogs();
}

function clearNetfilterFilters() {
    document.getElementById('netfilter-filter-ip').value = '';
    document.getElementById('netfilter-filter-username').value = '';
    document.getElementById('netfilter-filter-action').value = '';
    document.getElementById('netfilter-filter-country').value = '';
    currentFilters.netfilter = {};
    currentPage.netfilter = 1;
    loadNetfilterLogs();
}

async function loadNetfilterLogs(page = 1) {
    const container = document.getElementById('netfilter-logs');

    try {
        container.innerHTML = '<div class="ui-loading"><div class="loading"></div><p>Loading...</p></div>';

        const filters = currentFilters.netfilter || {};
        const params = new URLSearchParams({
            page: page,
            limit: 50,
            ...filters
        });

        console.log('Loading Netfilter logs:', `/api/logs/netfilter?${params}`);

        const response = await authenticatedFetch(`/api/logs/netfilter?${params}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('Netfilter data:', data);

        // Store in cache for smart refresh comparison
        lastDataCache.netfilter = data;

        // Use shared render function (includes GeoIP info & unban buttons)
        renderNetfilterData(data);

        currentPage.netfilter = page;
    } catch (error) {
        console.error('Failed to load Netfilter logs:', error);
        document.getElementById('netfilter-logs').innerHTML = `<p class="ui-empty ui-text-fail">Failed to load logs: ${escapeHtml(error.message)}</p>`;
        const countEl = document.getElementById('security-count');
        if (countEl) countEl.textContent = '';
    }
}

// =============================================================================
// FAIL2BAN SETTINGS
// =============================================================================

let fail2banSettingsLoaded = false;
let fail2banActiveBans = null;   // null until mailcow has answered
let fail2banBlacklist = [];
let fail2banWhitelist = [];
let fail2banPermBans = [];
let fail2banPolicy = null;       // how Fail2ban bans: times, attempts, window, network size

// Fail2ban's bans, lists and policy from mailcow. The Security page shows them in
// the Overview, the Lists and the Fail2ban card; an action resets the flag to reload.
async function loadFail2BanSettings() {
    if (fail2banSettingsLoaded) return;
    try {
        const response = await authenticatedFetch('/api/fail2ban');
        if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        const data = await response.json();
        const list = value => (value || '').replace(/\n/g, ',').split(',').map(e => e.trim()).filter(e => e);
        fail2banSettingsLoaded = true;
        fail2banLoadError = false;
        fail2banActiveBans = data.active_bans || [];
        fail2banPermBans = data.perm_bans || [];
        fail2banBlacklist = list(data.blacklist);
        fail2banWhitelist = list(data.whitelist);
        fail2banPolicy = {
            ban_time: data.ban_time, max_ban_time: data.max_ban_time, ban_time_increment: !!Number(data.ban_time_increment),
            max_attempts: data.max_attempts, retry_window: data.retry_window,
            netban_ipv4: data.netban_ipv4, netban_ipv6: data.netban_ipv6
        };
    } catch (error) {
        console.error('Failed to load Fail2Ban settings:', error);
        fail2banLoadError = true;
    }
    renderSecurityOverview();
    refreshSecurityAddresses();   // a ban, an unban or a list entry moves an address between the lists
    if (!securityEditing()) {
        renderSecurityLists();
        renderSecuritySettings();
    }
    // The events' Ban and Unban buttons depend on the denylist
    if (lastDataCache.netfilter && mailcowRwConfigured) renderNetfilterData(lastDataCache.netfilter);
}

// =============================================================================
// Part 2: Queue, Quarantine, Messages, Status, Postfix Details
// =============================================================================

// =============================================================================
// QUEUE
// =============================================================================

let allQueueData = [];

async function loadQueue() {
    const container = document.getElementById('queue-logs');

    try {
        container.innerHTML = '<div class="ui-loading"><div class="loading"></div><p>Loading...</p></div>';

        console.log('Loading Queue...');

        const response = await authenticatedFetch('/api/queue');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('Queue data:', data);

        allQueueData = data.data || [];
        updateQueueSummary();
        applyQueueFilters();
    } catch (error) {
        console.error('Failed to load queue:', error);
        document.getElementById('queue-logs').innerHTML = `<p class="ui-empty ui-text-fail">Failed to load queue: ${escapeHtml(error.message)}</p>`;
        const countEl = document.getElementById('queue-count');
        if (countEl) countEl.textContent = '';
    }
}

function updateQueueSummary() {
    const el = document.getElementById('queue-summary');
    if (!el) return;
    if (!allQueueData.length) {
        el.textContent = 'The queue is empty.';
        return;
    }
    const count = name => allQueueData.filter(i => (i.queue_name || '').toLowerCase() === name).length;
    const parts = [];
    if (count('deferred')) parts.push(`${count('deferred')} waiting to retry`);
    if (count('hold')) parts.push(`${count('hold')} on hold`);
    if (count('active')) parts.push(`${count('active')} being delivered`);
    const other = allQueueData.length - count('deferred') - count('hold') - count('active');
    if (other) parts.push(`${other} other`);
    el.textContent = `${allQueueData.length} ${allQueueData.length === 1 ? 'message' : 'messages'}: ${parts.join(', ')}. Postfix retries deferred mail on its own.`;
}

function applyQueueFilters() {
    const searchTerm = document.getElementById('queue-filter-search')?.value.toLowerCase() || '';
    const queueId = document.getElementById('queue-filter-queue-id')?.value.toLowerCase() || '';

    let filteredData = allQueueData;

    if (searchTerm) {
        filteredData = filteredData.filter(item =>
            item.sender.toLowerCase().includes(searchTerm) ||
            item.recipients.some(r => r.toLowerCase().includes(searchTerm))
        );
    }

    if (queueId) {
        filteredData = filteredData.filter(item =>
            item.queue_id.toLowerCase().includes(queueId)
        );
    }

    const container = document.getElementById('queue-logs');

    // Update count display
    const countEl = document.getElementById('queue-count');
    if (countEl) {
        countEl.textContent = `(${filteredData.length.toLocaleString()} items)`;
    }

    if (filteredData.length === 0) {
        container.innerHTML = '<p class="ui-empty">No matching queue entries</p>';
        return;
    }

    const canAct = mailcowRwConfigured;

    const lockedNote = canAct ? '' : `<div class="ui-list-note">${uiLocked('Queue actions are locked', `Retry, hold, release, delete and flush ${UI_RW_KEY_TEXT}`)}</div>`;
    const cols = canAct
        ? '--ui-cols: 20px minmax(200px, 1.6fr) 84px minmax(240px, 2.8fr) 70px 318px; --ui-table-min: 1000px'
        : '--ui-cols: minmax(200px, 1.6fr) 84px minmax(240px, 2.8fr) 70px; --ui-table-min: 640px';

    container.innerHTML = `
        ${lockedNote}
        <div class="ui-table ui-stack" style="${cols}">
        ${canAct ? `
            <div class="ui-toolbar ui-table-tools">
                <button onclick="queueSelectAll()" id="queue-select-all-btn" class="ui-btn ui-btn-sm">Select All</button>
                <button onclick="queueBulkRetry()" id="queue-bulk-retry-btn" class="hidden ui-btn ui-btn-sm ui-btn-primary">Retry Selected</button>
                <button onclick="queueBulkDelete()" id="queue-bulk-delete-btn" class="hidden ui-btn ui-btn-sm ui-btn-danger-solid">Delete Selected</button>
                <span id="queue-selection-count" class="hidden ui-muted"></span>
                <span class="ui-toolbar-gap"></span>
                <button onclick="queueFlushAll()" id="queue-flush-all-btn" class="ui-btn ui-btn-sm ui-btn-primary" title="Retry delivery of every message in the queue">
                    <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                    Flush All
                </button>
                <button onclick="queueDeleteAll()" id="queue-delete-all-btn" class="ui-btn ui-btn-sm ui-btn-danger-solid">Delete All</button>
            </div>
        ` : ''}
            <div class="ui-tr ui-tr-head">${canAct ? '<span></span>' : ''}<span>Recipient</span><span>State</span><span>Last response</span><span class="ui-td-end">Size</span>${canAct ? '<span class="ui-td-end">Actions</span>' : ''}</div>
            ${filteredData.map(item => {
                const qid = item.queue_id || '';
                const queueName = (item.queue_name || '').toLowerCase();
                const isHold = queueName === 'hold';
                const queueTone = { hold: '', deferred: 'warn', active: 'ok', incoming: 'info', bounce: 'fail', corrupt: 'fail' }[queueName] || '';
                const stateText = isHold ? 'On hold' : (item.queue_name || 'unknown').replace(/^./, c => c.toUpperCase());
                // "user@example.com (connect to ...: Connection timed out)" -> address and response
                const recipients = item.recipients.map(r => {
                    const email = r.split(' ')[0].replace(/[<>]/g, '').trim();
                    const rest = r.includes(' ') ? r.substring(r.indexOf(' ')).trim().replace(/^\((.*)\)$/, '$1') : '';
                    return { email, response: rest };
                });
                const responses = recipients.filter(r => r.response);
                const queued = new Date(item.arrival_time * 1000).toISOString();
                const suppress = recipients.length === 1
                    ? `<button onclick="showAddSuppressionModal('${escapeJsArg(recipients[0].email)}')" title="Suppress ${escapeHtml(recipients[0].email)}" class="ui-btn ui-btn-sm">Suppress</button>`
                    : uiMenu('Suppress', recipients.map(r => `<button type="button" role="menuitem" onclick="showAddSuppressionModal('${escapeJsArg(r.email)}')">${escapeHtml(r.email)}</button>`).join(''));
                return `
                <div class="ui-tr ui-q-row" data-queue-id="${escapeHtml(qid)}">
                    ${canAct ? `<input type="checkbox" class="queue-checkbox ui-check" value="${escapeHtml(qid)}" onchange="queueUpdateSelection()" aria-label="Select ${escapeHtml(qid)}" />` : ''}
                    <div class="ui-td ui-q-who">
                        <div>${recipients.map(r => copyableText(r.email)).join(', ')}</div>
                        <small>From ${copyableText(item.sender)}, queued <span title="${escapeHtml(formatTime(queued))}">${formatAgo(queued)}</span>, ID ${copyableText(qid)}</small>
                    </div>
                    <span class="ui-td">${uiTag(stateText, queueTone)}</span>
                    <div class="ui-td ui-td-wrap ui-mono ui-q-resp">${responses.length
                        ? responses.map(r => `<div>${recipients.length > 1 ? `<span class="ui-muted">${escapeHtml(r.email)}:</span> ` : ''}${escapeHtml(r.response)}</div>`).join('')
                        : `<span class="ui-muted">${isHold ? 'Put on hold' : '-'}</span>`}</div>
                    <span class="ui-td ui-td-end">${formatSize(item.message_size)}</span>
                    ${canAct ? `
                    <span class="ui-td ui-td-end ui-row-actions">
                        <button onclick="queueRetry('${escapeJsArg(qid)}')" title="Retry delivery" class="queue-action-btn ui-btn ui-btn-sm">Retry</button>
                        ${isHold
                            ? `<button onclick="queueUnhold('${escapeJsArg(qid)}')" title="Release from hold" class="queue-action-btn ui-btn ui-btn-sm">Unhold</button>`
                            : `<button onclick="queueHold('${escapeJsArg(qid)}')" title="Hold message" class="queue-action-btn ui-btn ui-btn-sm">Hold</button>`}
                        <button onclick="queueDeleteItem('${escapeJsArg(qid)}')" title="Delete from queue" class="queue-action-btn ui-btn ui-btn-sm ui-btn-danger">Delete</button>
                        ${suppress}
                    </span>` : ''}
                </div>`;
            }).join('')}
        </div>
    `;
}

function clearQueueFilters() {
    document.getElementById('queue-filter-search').value = '';
    document.getElementById('queue-filter-queue-id').value = '';
    applyQueueFilters();
}

// --- Queue selection helpers ---

function queueUpdateSelection() {
    const checked = document.querySelectorAll('.queue-checkbox:checked');
    // With rows selected the actions are about them; Delete All steps aside
    const deleteAll = document.getElementById('queue-delete-all-btn');
    if (deleteAll) deleteAll.classList.toggle('hidden', checked.length > 0);
    const bulkRetry = document.getElementById('queue-bulk-retry-btn');
    const bulkDelete = document.getElementById('queue-bulk-delete-btn');
    const countLabel = document.getElementById('queue-selection-count');

    if (checked.length > 0) {
        if (bulkRetry) { bulkRetry.classList.remove('hidden'); bulkRetry.classList.add('inline-flex'); }
        if (bulkDelete) { bulkDelete.classList.remove('hidden'); bulkDelete.classList.add('inline-flex'); }
        if (countLabel) { countLabel.classList.remove('hidden'); countLabel.textContent = `${checked.length} selected`; }
    } else {
        if (bulkRetry) { bulkRetry.classList.add('hidden'); bulkRetry.classList.remove('inline-flex'); }
        if (bulkDelete) { bulkDelete.classList.add('hidden'); bulkDelete.classList.remove('inline-flex'); }
        if (countLabel) { countLabel.classList.add('hidden'); countLabel.textContent = ''; }
    }
}

function queueSelectAll() {
    const checkboxes = document.querySelectorAll('.queue-checkbox');
    const allChecked = Array.from(checkboxes).every(cb => cb.checked);
    checkboxes.forEach(cb => { cb.checked = !allChecked; });
    const btn = document.getElementById('queue-select-all-btn');
    if (btn) btn.textContent = allChecked ? 'Select All' : 'Deselect All';
    queueUpdateSelection();
}

function queueGetSelectedIds() {
    return Array.from(document.querySelectorAll('.queue-checkbox:checked')).map(cb => cb.value);
}

async function queueBulkRetry() {
    const ids = queueGetSelectedIds();
    if (ids.length === 0) return;
    if (!await showConfirmModal({ title: 'Retry Delivery', message: `Retry delivery of ${ids.length} message(s)?`, confirmText: 'Retry' })) return;
    await queueAction('deliver', ids);
}

async function queueBulkDelete() {
    const ids = queueGetSelectedIds();
    if (ids.length === 0) return;
    if (!await showConfirmModal({ title: 'Delete Messages', message: `Permanently delete ${ids.length} message(s) from the queue?`, confirmText: 'Delete', isDangerous: true })) return;
    await queueDeleteRequest(ids);
}

// --- Queue action helpers ---

async function queueRetry(qid) {
    await queueAction('deliver', [String(qid)]);
}

async function queueHold(qid) {
    await queueAction('hold', [String(qid)]);
}

async function queueUnhold(qid) {
    await queueAction('unhold', [String(qid)]);
}

async function queueDeleteItem(qid) {
    if (!await showConfirmModal({ title: 'Delete Message', message: 'Delete this message from the queue?', confirmText: 'Delete', isDangerous: true })) return;
    await queueDeleteRequest([String(qid)]);
}

async function queueFlushAll() {
    if (!await showConfirmModal({ title: 'Flush Queue', message: 'Flush (retry delivery of) ALL messages in the queue?', confirmText: 'Flush All' })) return;
    await queueAction('flush', ['mailqitems-all']);
}

async function queueDeleteAll() {
    if (!await showConfirmModal({ title: 'Delete All', message: 'Permanently delete ALL messages from the queue? This cannot be undone.', confirmText: 'Delete All', isDangerous: true })) return;
    await queueAction('super_delete', ['mailqitems-all']);
}

async function queueAction(action, itemIds) {
    document.querySelectorAll('.queue-action-btn, .queue-checkbox, #queue-flush-all-btn, #queue-delete-all-btn, #queue-select-all-btn, #queue-bulk-retry-btn, #queue-bulk-delete-btn')
        .forEach(el => { el.disabled = true; el.style.opacity = '0.5'; });

    try {
        const res = await authenticatedFetch('/api/queue/action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ items: itemIds, action: action })
        });

        const result = await res.json();
        if (res.ok && result.status === 'success') {
            const labels = { deliver: 'Retry delivery', hold: 'Hold', unhold: 'Unhold', flush: 'Flush all', super_delete: 'Delete all' };
            showToast(result.msg || `${labels[action] || action} completed`, 'success');
            lastDataCache.queue = null;
            await loadQueue();
        } else {
            showToast(`Queue action failed: ` + (result.msg || result.detail || 'Unknown error'), 'error');
        }
    } catch (err) {
        showToast(`Queue action failed: ` + err.message, 'error');
    } finally {
        document.querySelectorAll('.queue-action-btn, .queue-checkbox, #queue-flush-all-btn, #queue-delete-all-btn, #queue-select-all-btn, #queue-bulk-retry-btn, #queue-bulk-delete-btn')
            .forEach(el => { el.disabled = false; el.style.opacity = ''; });
    }
}

async function queueDeleteRequest(itemIds) {
    document.querySelectorAll('.queue-action-btn, .queue-checkbox, #queue-flush-all-btn, #queue-delete-all-btn, #queue-select-all-btn, #queue-bulk-retry-btn, #queue-bulk-delete-btn')
        .forEach(el => { el.disabled = true; el.style.opacity = '0.5'; });

    try {
        const res = await authenticatedFetch('/api/queue/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ items: itemIds })
        });

        const result = await res.json();
        if (res.ok && result.status === 'success') {
            showToast(result.msg || 'Message deleted from queue', 'success');
            lastDataCache.queue = null;
            await loadQueue();
        } else {
            showToast('Failed to delete from queue: ' + (result.msg || result.detail || 'Unknown error'), 'error');
        }
    } catch (err) {
        showToast('Failed to delete from queue: ' + err.message, 'error');
    } finally {
        document.querySelectorAll('.queue-action-btn, .queue-checkbox, #queue-flush-all-btn, #queue-delete-all-btn, #queue-select-all-btn, #queue-bulk-retry-btn, #queue-bulk-delete-btn')
            .forEach(el => { el.disabled = false; el.style.opacity = ''; });
    }
}

// =============================================================================
// QUARANTINE
// =============================================================================

// Client-side sort state for the quarantine list ('newest' matches the backend default order)
let quarantineSortOrder = 'newest';
// Last quarantine payload rendered (used to re-sort without re-fetching)
let quarantineLastData = null;

// Return a sorted copy of quarantine items based on quarantineSortOrder.
// Items without a numeric score are placed last in both score directions.
// Reject is the strong verdict; add header and the softer ones read as a warning
function quarantineActionTone(action) {
    return ['reject', 'discard'].includes(String(action || '').toLowerCase()) ? 'fail' : 'warn';
}

function sortQuarantineItems(items) {
    const sorted = [...items];
    if (quarantineSortOrder !== 'score_desc' && quarantineSortOrder !== 'score_asc') {
        return sorted; // 'newest' - keep backend order (newest first)
    }
    const scoreOf = (item) => (typeof item.score === 'number' && isFinite(item.score)) ? item.score : null;
    sorted.sort((a, b) => {
        const sa = scoreOf(a);
        const sb = scoreOf(b);
        if (sa === null && sb === null) return 0;
        if (sa === null) return 1;
        if (sb === null) return -1;
        return quarantineSortOrder === 'score_asc' ? sa - sb : sb - sa;
    });
    return sorted;
}

// Handler for the #quarantine-sort dropdown - re-sorts the already-fetched list
function applyQuarantineSort() {
    if (typeof uiClearTableSort === 'function') uiClearTableSort('quarantine-logs');
    const select = document.getElementById('quarantine-sort');
    if (select) quarantineSortOrder = select.value;
    if (quarantineLastData) {
        renderQuarantineData(quarantineLastData);
    } else {
        loadQuarantine();
    }
}

async function loadQuarantine() {
    const container = document.getElementById('quarantine-logs');

    try {
        container.innerHTML = '<div class="ui-loading"><div class="loading"></div><p>Loading...</p></div>';

        console.log('Loading Quarantine...');

        const response = await authenticatedFetch('/api/quarantine');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('Quarantine data:', data);

        renderQuarantineData(data);
    } catch (error) {
        console.error('Failed to load quarantine:', error);
        document.getElementById('quarantine-logs').innerHTML = `<p class="ui-empty ui-text-fail">Failed to load quarantine: ${escapeHtml(error.message)}</p>`;
    }
}

// Render quarantine without loading spinner (for smart refresh)
function renderQuarantineData(data) {
    const container = document.getElementById('quarantine-logs');
    if (!container) return;

    // Keep the latest payload so sort changes can re-render without a re-fetch
    quarantineLastData = data;
    const summary = document.getElementById('quarantine-summary');
    if (summary) {
        const total = data.total || (data.data || []).length;
        summary.textContent = total
            ? `${total.toLocaleString()} ${total === 1 ? 'message' : 'messages'} held as likely spam. Releasing one delivers it to the recipient.`
            : 'Nothing is held right now.';
    }

    if (!data.data || data.data.length === 0) {
        container.innerHTML = '<p class="ui-empty">No quarantined messages</p>';
        return;
    }

    const canAct = mailcowRwConfigured;
    const items = sortQuarantineItems(data.data);

    const lockedNote = canAct ? '' : `<div class="ui-list-note">${uiLocked('Quarantine actions are locked', `Release, delete, spam learning and the auto-rules ${UI_RW_KEY_TEXT}`)}</div>`;
    const cols = canAct
        ? '--ui-cols: 20px minmax(200px, 2fr) minmax(150px, 1.3fr) minmax(120px, 1fr) 56px 64px 336px; --ui-table-min: 1080px'
        : '--ui-cols: minmax(200px, 2fr) minmax(150px, 1.3fr) minmax(120px, 1fr) 56px 64px 76px; --ui-table-min: 760px';

    container.innerHTML = `
        ${lockedNote}
        <div class="ui-table ui-stack" style="${cols}">
        ${!canAct ? '' : `
            <div class="ui-toolbar ui-table-tools">
                <button onclick="quarantineSelectAll()" id="quarantine-select-all-btn" class="ui-btn ui-btn-sm">Select All</button>
                <button onclick="quarantineBulkRelease()" id="quarantine-bulk-release-btn" class="hidden ui-btn ui-btn-sm ui-btn-primary">Release Selected</button>
                <button onclick="quarantineBulkDelete()" id="quarantine-bulk-delete-btn" class="hidden ui-btn ui-btn-sm ui-btn-danger-solid">Delete Selected</button>
                <button onclick="quarantineBulkLearnHam()" id="quarantine-bulk-learnham-btn" class="hidden ui-btn ui-btn-sm ui-btn-primary">Not Spam</button>
                <button onclick="quarantineBulkLearnSpam()" id="quarantine-bulk-learnspam-btn" class="hidden ui-btn ui-btn-sm ui-btn-primary">Learn Spam</button>
                <span id="quarantine-selection-count" class="hidden ui-muted"></span>
                <span class="ui-toolbar-gap"></span>
                <button onclick="quarantineReleaseAll()" id="quarantine-release-all-btn" class="ui-btn ui-btn-sm ui-btn-primary">Release All</button>
                <button onclick="quarantineDeleteAll()" id="quarantine-delete-all-btn" class="ui-btn ui-btn-sm ui-btn-danger-solid">Delete All</button>
            </div>
        `}
            <div class="ui-tr ui-tr-head">${canAct ? '<span></span>' : ''}<span>Message</span><span>For</span><span>Why</span><span class="ui-td-end">Score</span><span>Held</span><span class="ui-td-end">Actions</span></div>
            ${items.map(item => {
                const itemId = item.id !== undefined ? item.id : '';
                const idArg = escapeJsArg(String(itemId));
                const hasScore = item.score !== undefined && item.score !== null;
                return `
                <div class="ui-tr ui-q-row" data-quarantine-id="${escapeHtml(String(itemId))}" onclick="quarantineRowClick(event, '${idArg}')">
                    ${canAct ? `<input type="checkbox" class="quarantine-checkbox ui-check" value="${escapeHtml(String(itemId))}" onchange="quarantineUpdateSelection()" aria-label="Select message" />` : ''}
                    <div class="ui-td ui-q-who">
                        <button type="button" class="ui-link-row" dir="auto" title="View details" onclick="showQuarantineDetails('${idArg}')">${escapeHtml(item.subject || 'No subject')}</button>
                        <small>${escapeHtml(item.sender || 'Unknown')}${item.qid ? `, ID ${escapeHtml(item.qid)}` : ''}</small>
                    </div>
                    <span class="ui-td">${escapeHtml(item.rcpt || 'Unknown')}</span>
                    <span class="ui-td ui-td-wrap">${uiTag(item.action || 'Quarantined', quarantineActionTone(item.action))}${item.virus_flag ? ` ${uiTag('Virus', 'spam')}` : ''}</span>
                    <span class="ui-td ui-td-end${hasScore && item.score >= 15 ? ' ui-text-fail' : ''}"><small class="ui-sec-unit">Score </small>${hasScore ? item.score.toFixed(1) : '-'}</span>
                    <time class="ui-td" title="${escapeHtml(formatTime(item.created))}"><small class="ui-sec-unit">Held </small>${formatAgo(item.created).replace(' ago', '')}</time>
                    <span class="ui-td ui-td-end ui-row-actions">
                        ${canAct ? `
                            <button onclick="quarantineRelease('${idArg}')" title="Release message" class="quarantine-action-btn ui-btn ui-btn-sm">Release</button>
                            <button onclick="quarantineLearnHam('${idArg}')" title="Release and train as not spam" class="quarantine-action-btn ui-btn ui-btn-sm">Not spam</button>
                            <button onclick="quarantineLearnSpam('${idArg}')" title="Delete and train as spam" class="quarantine-action-btn ui-btn ui-btn-sm">Spam</button>
                            <button onclick="showAddRuleFromQuarantine('${escapeJsArg(item.sender || '')}', '${escapeJsArg(item.rcpt || '')}', '${escapeJsArg(item.subject || '')}')" title="Create an auto-rule from this message" class="quarantine-action-btn ui-btn ui-btn-sm">Rule</button>
                            <button onclick="quarantineDelete('${idArg}')" title="Delete message" class="quarantine-action-btn ui-btn ui-btn-sm ui-btn-danger">Delete</button>
                        ` : `<button onclick="showQuarantineDetails('${idArg}')" title="View details" class="quarantine-action-btn ui-btn ui-btn-sm">Details</button>`}
                    </span>
                </div>`;
            }).join('')}
        </div>
    `;
}

// --- Quarantine action helpers ---

// A click on the row opens the message, like the Messages list; its buttons,
// checkbox and copyable values keep their own click
function quarantineRowClick(event, itemId) {
    if (event.target.closest('button, a, input, select, label, .copyable, [role="menu"]')) return;
    if (window.getSelection && String(window.getSelection())) return;
    showQuarantineDetails(itemId);
}

function quarantineUpdateSelection() {
    const checked = document.querySelectorAll('.quarantine-checkbox:checked');
    const bulkBtns = ['quarantine-bulk-release-btn', 'quarantine-bulk-delete-btn', 'quarantine-bulk-learnham-btn', 'quarantine-bulk-learnspam-btn'];
    const countLabel = document.getElementById('quarantine-selection-count');

    // With rows selected the actions are about them; Release All and Delete All step aside
    ['quarantine-release-all-btn', 'quarantine-delete-all-btn'].forEach(id => { const el = document.getElementById(id); if (el) el.classList.toggle('hidden', checked.length > 0); });
    if (checked.length > 0) {
        bulkBtns.forEach(id => { const el = document.getElementById(id); if (el) { el.classList.remove('hidden'); el.classList.add('inline-flex'); } });
        if (countLabel) { countLabel.classList.remove('hidden'); countLabel.textContent = `${checked.length} selected`; }
    } else {
        bulkBtns.forEach(id => { const el = document.getElementById(id); if (el) { el.classList.add('hidden'); el.classList.remove('inline-flex'); } });
        if (countLabel) { countLabel.classList.add('hidden'); countLabel.textContent = ''; }
    }
}

function quarantineSelectAll() {
    const checkboxes = document.querySelectorAll('.quarantine-checkbox');
    const allChecked = Array.from(checkboxes).every(cb => cb.checked);
    checkboxes.forEach(cb => { cb.checked = !allChecked; });
    const btn = document.getElementById('quarantine-select-all-btn');
    if (btn) btn.textContent = allChecked ? 'Select All' : 'Deselect All';
    quarantineUpdateSelection();
}

function quarantineGetSelectedIds() {
    return Array.from(document.querySelectorAll('.quarantine-checkbox:checked')).map(cb => cb.value);
}

async function quarantineRelease(itemId) {
    await quarantineAction('release', [String(itemId)]);
}

async function quarantineDelete(itemId) {
    if (!await showConfirmModal({ title: 'Delete Message', message: 'Are you sure you want to permanently delete this quarantined message?', confirmText: 'Delete', isDangerous: true })) return;
    await quarantineAction('delete', [String(itemId)]);
}

async function quarantineLearnHam(itemId) {
    if (!await showConfirmModal({ title: 'Not Spam', message: 'Release this message and train Rspamd that it is not spam?', confirmText: 'Not Spam' })) return;
    await quarantineAction('learnham', [String(itemId)]);
}

async function quarantineLearnSpam(itemId) {
    if (!await showConfirmModal({ title: 'Mark as Spam', message: 'Delete this message and train Rspamd that it IS spam?', confirmText: 'Spam', isDangerous: true })) return;
    await quarantineAction('learnspam', [String(itemId)]);
}

async function quarantineBulkRelease() {
    const ids = quarantineGetSelectedIds();
    if (ids.length === 0) return;
    if (!await showConfirmModal({ title: 'Release Messages', message: `Release ${ids.length} quarantined message(s)?`, confirmText: 'Release' })) return;
    await quarantineAction('release', ids);
}

async function quarantineBulkDelete() {
    const ids = quarantineGetSelectedIds();
    if (ids.length === 0) return;
    if (!await showConfirmModal({ title: 'Delete Messages', message: `Permanently delete ${ids.length} quarantined message(s)?`, confirmText: 'Delete', isDangerous: true })) return;
    await quarantineAction('delete', ids);
}

async function quarantineBulkLearnHam() {
    const ids = quarantineGetSelectedIds();
    if (ids.length === 0) return;
    if (!await showConfirmModal({ title: 'Not Spam', message: `Release ${ids.length} message(s) and train Rspamd as not spam?`, confirmText: 'Not Spam' })) return;
    await quarantineAction('learnham', ids);
}

async function quarantineBulkLearnSpam() {
    const ids = quarantineGetSelectedIds();
    if (ids.length === 0) return;
    if (!await showConfirmModal({ title: 'Mark as Spam', message: `Delete ${ids.length} message(s) and train Rspamd as spam?`, confirmText: 'Spam', isDangerous: true })) return;
    await quarantineAction('learnspam', ids);
}

async function quarantineReleaseAll() {
    const allIds = Array.from(document.querySelectorAll('.quarantine-checkbox')).map(cb => cb.value).filter(Boolean);
    if (allIds.length === 0) return;
    if (!await showConfirmModal({ title: 'Release All', message: `Release ALL ${allIds.length} quarantined message(s)?`, confirmText: 'Release All' })) return;
    await quarantineAction('release', allIds);
}

async function quarantineDeleteAll() {
    const allIds = Array.from(document.querySelectorAll('.quarantine-checkbox')).map(cb => cb.value).filter(Boolean);
    if (allIds.length === 0) return;
    if (!await showConfirmModal({ title: 'Delete All', message: `Permanently delete ALL ${allIds.length} quarantined message(s)? This cannot be undone.`, confirmText: 'Delete All', isDangerous: true })) return;
    await quarantineAction('delete', allIds);
}

async function quarantineAction(action, itemIds) {
    const allBtns = '.quarantine-action-btn, .quarantine-checkbox, #quarantine-bulk-release-btn, #quarantine-bulk-delete-btn, #quarantine-bulk-learnham-btn, #quarantine-bulk-learnspam-btn, #quarantine-select-all-btn, #quarantine-release-all-btn, #quarantine-delete-all-btn';
    document.querySelectorAll(allBtns).forEach(el => { el.disabled = true; el.style.opacity = '0.5'; });

    try {
        const endpoints = {
            'release': '/api/quarantine/release',
            'delete': '/api/quarantine/delete',
            'learnham': '/api/quarantine/learnham',
            'learnspam': '/api/quarantine/learnspam'
        };
        const endpoint = endpoints[action] || '/api/quarantine/' + action;
        const res = await authenticatedFetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ items: itemIds })
        });

        const result = await res.json();
        const actionLabels = { release: 'released', delete: 'deleted', learnham: 'released & marked as not spam', learnspam: 'deleted & marked as spam' };
        if (res.ok && result.status === 'success') {
            showToast(result.msg || `Message(s) ${actionLabels[action] || action} successfully`, 'success');
            lastDataCache.quarantine = null;
            await loadQuarantine();
        } else {
            showToast(`Failed to ${action} message(s): ` + (result.msg || result.detail || 'Unknown error'), 'error');
        }
    } catch (err) {
        showToast(`Failed to ${action} message(s): ` + err.message, 'error');
    } finally {
        document.querySelectorAll(allBtns).forEach(el => { el.disabled = false; el.style.opacity = ''; });
    }
}

// --- Quarantine Detail View ---

async function showQuarantineDetails(itemId) {
    const existing = document.getElementById('quarantine-detail-modal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = 'quarantine-detail-modal';
    modal.className = 'ui-dialog-backdrop';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-label', 'Quarantine Item Details');
    modal.onclick = event => { if (event.target === modal) closeQuarantineDetails(); };
    modal.innerHTML = `
        <div class="ui-dialog ui-dialog-fit">
            <div class="ui-dialog-head">
                <h3>Quarantine Item Details</h3>
                <button onclick="closeQuarantineDetails()" class="ui-icon-btn" title="Close" aria-label="Close">
                    <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="ui-dialog-body" id="quarantine-detail-content">
                <div class="ui-loading"><div class="loading"></div><p>Loading details...</p></div>
            </div>
            <div id="quarantine-detail-footer" class="hidden"></div>
        </div>
    `;
    document.body.appendChild(modal);
    document.body.style.overflow = 'hidden';

    try {
        const res = await authenticatedFetch(`/api/quarantine/${itemId}/details`);
        if (!res.ok) throw new Error('Failed to fetch details');
        const data = await res.json();
        renderQuarantineDetailContent(data, itemId);
    } catch (err) {
        document.getElementById('quarantine-detail-content').innerHTML = `
            <div class="ui-empty">
                <p class="ui-text-fail">Failed to load details</p>
                <p>${escapeHtml(err.message)}</p>
            </div>`;
    }
}

function closeQuarantineDetails() {
    const modal = document.getElementById('quarantine-detail-modal');
    if (modal) modal.remove();
    document.body.style.overflow = '';
}

function renderQuarantineDetailContent(data, itemId) {
    const content = document.getElementById('quarantine-detail-content');
    const footer = document.getElementById('quarantine-detail-footer');
    if (!content) return;

    const allSymbols = (data.symbols || []);
    const activeSymbols = allSymbols.filter(s => (s.score || 0) !== 0).sort((a, b) => Math.abs(b.score || 0) - Math.abs(a.score || 0));
    const zeroSymbols = allSymbols.filter(s => (s.score || 0) === 0).sort((a, b) => (a.name || '').localeCompare(b.name || ''));

    const recipientsHtml = (data.recipients || []).map(r =>
        `<span class="ui-qd-rcpt"><small class="${r.type === 'smtp' ? 'ui-text-info' : 'ui-muted'}">${escapeHtml(r.type)}</small> ${copyableText(r.address)}</span>`
    ).join(' ');

    const score = data.score || 0;
    const scoreTone = score >= 15 ? 'fail' : score >= 6 ? 'warn' : 'ok';

    const buildSymbolRows = (syms) => syms.map(s => {
        const sc = s.score || 0;
        const tone = sc > 0 ? 'ui-text-fail' : sc < 0 ? 'ui-text-ok' : 'ui-muted';
        const opts = (s.options || []).join(', ');
        return `<tr>
            <td class="ui-mono">${escapeHtml(s.name || '')}</td>
            <td class="ui-muted">${escapeHtml(s.group || '')}</td>
            <td class="ui-td-end ${tone}"><b>${sc !== 0 ? (sc > 0 ? '+' : '') + sc.toFixed(2) : '0'}</b></td>
            <td class="ui-muted ui-qd-opts" title="${escapeHtml(opts)}">${escapeHtml(opts)}</td>
        </tr>`;
    }).join('');

    const symbolTable = rows => `<div class="ui-dtable-scroll"><table class="ui-dtable"><thead><tr>
        <th>Symbol</th><th>Group</th><th class="ui-td-end">Score</th><th>Details</th>
    </tr></thead><tbody>${rows}</tbody></table></div>`;

    const textContent = data.text_plain || data.text_html || '';
    const canAct = mailcowRwConfigured;

    content.innerHTML = `
        <div class="ui-qd">
            <div class="ui-md-ids ui-qd-facts">
                <div class="ui-md-fact ui-qd-wide"><span>Subject</span><div dir="auto">${copyableText(data.subject || '-')}</div></div>
                <div class="ui-md-fact"><span>From (Header)</span><div>${copyableText(data.header_from || '-')}</div></div>
                <div class="ui-md-fact"><span>Envelope From</span><div class="ui-mono">${copyableText(data.env_from || '-')}</div></div>
                <div class="ui-md-fact ui-qd-wide"><span>Recipients</span><div class="ui-chip-row">${recipientsHtml || '<span class="ui-muted">-</span>'}</div></div>
                <div class="ui-md-fact"><span>Score</span><div class="ui-text-${scoreTone}"><b>${score.toFixed(2)}</b></div></div>
                <div class="ui-md-fact"><span>Action</span><div>${uiTag(data.action || '-', quarantineActionTone(data.action))}</div></div>
            </div>

            <div>
                <h4 class="ui-md-h">Rspamd Symbols</h4>
                ${activeSymbols.length > 0 ? symbolTable(buildSymbolRows(activeSymbols)) : '<p class="ui-muted">No active symbols</p>'}
                ${zeroSymbols.length > 0 ? `
                <details class="ui-dns-more">
                    <summary>Informational symbols (score 0) - ${zeroSymbols.length} items</summary>
                    ${symbolTable(buildSymbolRows(zeroSymbols))}
                </details>` : ''}
            </div>

            ${textContent ? `
            <div>
                <h4 class="ui-md-h">Email Content</h4>
                <pre class="ui-qd-text" dir="auto">${escapeHtml(textContent)}</pre>
            </div>` : ''}

            ${data.fuzzy_hashes && data.fuzzy_hashes.length > 0 ? `
            <div>
                <h4 class="ui-md-h">Fuzzy Hashes</h4>
                <div class="ui-qd-text">${data.fuzzy_hashes.map(h => escapeHtml(JSON.stringify(h))).join('<br>')}</div>
            </div>` : ''}
        </div>
    `;

    // Footer with the actions
    if (footer && canAct) {
        footer.className = 'ui-dialog-foot';
        footer.innerHTML = `
            <button onclick="closeQuarantineDetails(); quarantineLearnSpam('${itemId}')" class="ui-btn" title="Delete & train as Spam">Spam</button>
            <button onclick="closeQuarantineDetails(); quarantineLearnHam('${itemId}')" class="ui-btn" title="Release & train as Not Spam">Not Spam</button>
            <span class="ui-toolbar-gap"></span>
            <button onclick="closeQuarantineDetails(); quarantineDelete('${itemId}')" class="ui-btn ui-btn-danger">Delete</button>
            <button onclick="closeQuarantineDetails(); quarantineRelease('${itemId}')" class="ui-btn ui-btn-primary">Release</button>
        `;
    } else if (footer) {
        // The list's locked note sits behind the dialog: say it here too
        footer.className = 'ui-dialog-foot ui-dialog-foot-note';
        footer.innerHTML = uiLocked('Quarantine actions are locked', `Release, delete and spam learning ${UI_RW_KEY_TEXT}`);
    }
}

// =============================================================================
// QUARANTINE AUTO-RULES
// =============================================================================

let _quarantineRulesCache = null;

async function initQuarantineRules() {
    const section = document.getElementById('quarantine-rules-section');
    if (!section) return;
    
    // Ensure RW status is loaded (may not be ready on first page load)
    if (!mailcowRwConfigured) {
        await fetchRwStatus();
    }
    
    if (showQuarantineRulesAccess()) {
        loadQuarantineRules();
    }
}

// Quarantine tabs: the held messages, and the Auto-Rules that handle them
let quarantineTab = 'messages';
function quarantineShowTab(tab) {
    quarantineTab = tab;
    routerSyncSubpage('quarantine', tab);
    ['messages', 'rules'].forEach(name => {
        const btn = document.getElementById(`quarantine-tab-btn-${name}`);
        if (btn) { btn.classList.toggle('active', name === tab); btn.setAttribute('aria-selected', name === tab); }
        const panel = document.getElementById(`quarantine-tab-${name}`);
        if (panel) panel.classList.toggle('hidden', name !== tab);
    });
}

async function loadQuarantineRules() {
    const container = document.getElementById('quarantine-rules-list');
    if (!container) return;
    
    try {
        const res = await authenticatedFetch('/api/quarantine/rules');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        _quarantineRulesCache = data;
        
        const countEl = document.getElementById('quarantine-rules-count');
        const activeCount = data.data.filter(r => r.enabled).length;
        if (countEl) countEl.textContent = activeCount > 0 ? `(${activeCount} active)` : '';
        const tabCount = document.getElementById('quarantine-tab-n-rules');
        if (tabCount) { tabCount.textContent = activeCount || ''; tabCount.classList.toggle('hidden', !activeCount); }
        
        if (!data.data || data.data.length === 0) {
            container.innerHTML = '<p class="ui-empty">No rules configured. Click "Add Rule" to create one.</p>';
            return;
        }
        
        container.innerHTML = `<div class="ui-table ui-stack ui-qr-table">${data.data.map(rule => {
            const matchLabels = { sender: 'Sender', sender_domain: 'Sender Domain', recipient: 'Recipient', subject: 'Subject' };
            const actionLabel = rule.action === 'delete' ? 'Delete' : 'Release';

            return `
            <div class="ui-tr${rule.enabled ? '' : ' ui-row-off'}">
                <div class="ui-td ui-q-who">
                    <div><b dir="auto">${escapeHtml(rule.name)}</b> ${uiTag(actionLabel, rule.action === 'delete' ? 'fail' : 'ok')}
                        ${rule.is_regex ? uiTag('Regex', 'info') : ''} ${!rule.enabled ? uiTag('Disabled', '') : ''}</div>
                    <small>${matchLabels[rule.match_type] || rule.match_type}: <code class="ui-mono" dir="auto">${escapeHtml(rule.match_value)}</code></small>
                    <small>Hits: ${rule.hit_count}${rule.last_hit_at ? ' · Last: ' + formatTime(rule.last_hit_at) : ''}${rule.notes ? ' · ' + escapeHtml(rule.notes) : ''}</small>
                </div>
                <span class="ui-td ui-td-end ui-row-actions">
                    <button onclick="toggleQuarantineRule(${rule.id})" title="${rule.enabled ? 'Click to disable this rule' : 'Click to enable this rule'}"
                        class="ui-btn ui-btn-sm${rule.enabled ? ' ui-btn-on' : ''}">${rule.enabled ? 'Enabled' : 'Disabled'}</button>
                    <button onclick="showEditQuarantineRuleModal(${rule.id})" title="Edit" class="ui-btn ui-btn-sm">Edit</button>
                    <button onclick="deleteQuarantineRule(${rule.id}, '${escapeJsArg(rule.name)}')" title="Delete" class="ui-btn ui-btn-sm ui-btn-danger">Delete</button>
                </span>
            </div>`;
        }).join('')}</div>`;
    } catch (err) {
        console.error('Failed to load quarantine rules:', err);
        container.innerHTML = `<p class="ui-empty ui-text-fail">Failed to load rules: ${escapeHtml(err.message)}</p>`;
    }
}

function showAddQuarantineRuleModal() {
    _showQuarantineRuleModal(null, null);
}

function showEditQuarantineRuleModal(ruleId) {
    const rule = _quarantineRulesCache?.data?.find(r => r.id === ruleId);
    if (!rule) { showToast('Rule not found', 'error'); return; }
    _showQuarantineRuleModal(rule, null);
}

function showAddRuleFromQuarantine(sender, recipient, subject) {
    // Pre-fill with data from the quarantine email
    const senderDomain = sender.includes('@') ? sender.split('@').pop() : '';
    const prefill = { sender, recipient, subject, senderDomain };
    _showQuarantineRuleModal(null, prefill);
}

function _showQuarantineRuleModal(rule, prefill) {
    const isEdit = !!rule;
    const title = isEdit ? 'Edit Rule' : 'Add Quarantine Rule';
    
    // Determine default values: edit mode uses rule data, prefill uses quarantine data
    const defaultName = isEdit ? escapeHtml(rule.name) : (prefill ? escapeHtml(`Rule for ${prefill.sender}`) : '');
    const defaultMatchType = isEdit ? rule.match_type : (prefill ? 'sender' : 'sender');
    const defaultMatchValue = isEdit ? escapeHtml(rule.match_value) : (prefill ? escapeHtml(prefill.sender) : '');
    const defaultAction = isEdit ? rule.action : 'release';
    const defaultIsRegex = isEdit ? rule.is_regex : false;
    const defaultNotes = isEdit && rule.notes ? escapeHtml(rule.notes) : '';
    
    // For pre-fill mode, provide quick-fill buttons for sender/domain/recipient
    const prefillButtons = prefill ? `
        <div class="ui-qr-prefill">
            <span class="ui-label">Quick fill from email:</span>
            <div class="ui-chip-row">
                <button type="button" onclick="qrulePrefill('sender', '${escapeJsArg(prefill.sender)}')" class="ui-chip">Sender: ${escapeHtml(prefill.sender)}</button>
                ${prefill.senderDomain ? `<button type="button" onclick="qrulePrefill('sender_domain', '${escapeJsArg(prefill.senderDomain)}')" class="ui-chip">Domain: ${escapeHtml(prefill.senderDomain)}</button>` : ''}
                <button type="button" onclick="qrulePrefill('recipient', '${escapeJsArg(prefill.recipient)}')" class="ui-chip">Recipient: ${escapeHtml(prefill.recipient)}</button>
            </div>
        </div>
    ` : '';

    const html = `
    <div class="ui-dialog-backdrop" id="quarantine-rule-modal-overlay" role="dialog" aria-label="${title}">
        <div class="ui-dialog ui-dialog-fit ui-dialog-sm">
            <div class="ui-dialog-head">
                <h3>${title}</h3>
                <button onclick="closeQuarantineRuleModal()" class="ui-icon-btn" title="Close" aria-label="Close">
                    <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="ui-dialog-body ui-form">
                ${prefillButtons}
                <label><span class="ui-label">Rule Name</span>
                    <input type="text" id="qrule-name" value="${defaultName}" class="ui-input" placeholder="e.g., Allow notifications from service X">
                </label>
                <div class="ui-qr-pair">
                    <label><span class="ui-label">Match Type</span>
                        <select id="qrule-match-type" class="ui-select">
                            <option value="sender" ${defaultMatchType === 'sender' ? 'selected' : ''}>Sender</option>
                            <option value="sender_domain" ${defaultMatchType === 'sender_domain' ? 'selected' : ''}>Sender Domain</option>
                            <option value="recipient" ${defaultMatchType === 'recipient' ? 'selected' : ''}>Recipient</option>
                            <option value="subject" ${defaultMatchType === 'subject' ? 'selected' : ''}>Subject</option>
                        </select>
                    </label>
                    <label><span class="ui-label">Action</span>
                        <select id="qrule-action" class="ui-select">
                            <option value="release" ${defaultAction === 'release' ? 'selected' : ''}>✅ Release</option>
                            <option value="delete" ${defaultAction === 'delete' ? 'selected' : ''}>🗑️ Delete</option>
                        </select>
                    </label>
                </div>
                <label><span class="ui-label">Match Value</span>
                    <input type="text" id="qrule-match-value" value="${defaultMatchValue}" class="ui-input ui-mono" placeholder="e.g., noreply@example.com">
                </label>
                <label><span class="ui-label">Match Mode</span>
                    <select id="qrule-match-mode" onchange="updateQRuleMatchHelp()" class="ui-select">
                        <option value="exact" ${!defaultIsRegex ? 'selected' : ''}>Exact Match - matches the full value exactly</option>
                        <option value="contains" ${defaultIsRegex && !(isEdit && rule.match_value.startsWith('^')) ? 'selected' : ''}>Contains - matches if value appears anywhere</option>
                        <option value="regex" ${defaultIsRegex && isEdit && rule.match_value.startsWith('^') ? 'selected' : ''}>Regex (advanced) - custom regular expression</option>
                    </select>
                    <small id="qrule-match-help" class="ui-muted"></small>
                </label>
                <label><span class="ui-label">Notes (optional)</span>
                    <textarea id="qrule-notes" rows="2" class="ui-textarea" placeholder="Why this rule exists...">${defaultNotes}</textarea>
                </label>
                <div class="ui-alert ui-alert-warn ui-qr-note">
                    <span class="ui-alert-bar"></span>
                    <div class="ui-alert-text"><p><b>Priority:</b> Delete rules always take priority over Release rules. If both match, the email will be deleted.</p></div>
                </div>
            </div>
            <div class="ui-dialog-foot">
                <button onclick="closeQuarantineRuleModal()" class="ui-btn">Cancel</button>
                <button onclick="saveQuarantineRule(${isEdit ? rule.id : 'null'})" class="ui-btn ui-btn-primary">${isEdit ? 'Save Changes' : 'Create Rule'}</button>
            </div>
        </div>
    </div>`;

    document.body.insertAdjacentHTML('beforeend', html); // nosemgrep: typescript.react.security.audit.react-unsanitized-method.react-unsanitized-method
    updateQRuleMatchHelp();
}

function qrulePrefill(matchType, value) {
    const typeEl = document.getElementById('qrule-match-type');
    const valueEl = document.getElementById('qrule-match-value');
    const nameEl = document.getElementById('qrule-name');
    if (typeEl) typeEl.value = matchType;
    if (valueEl) valueEl.value = value;
    // Update rule name if it's still auto-generated
    if (nameEl && nameEl.value.startsWith('Rule for ')) {
        const labels = { sender: 'Sender', sender_domain: 'Domain', recipient: 'Recipient' };
        nameEl.value = `${labels[matchType] || matchType}: ${value}`;
    }
}

function updateQRuleMatchHelp() {
    const mode = document.getElementById('qrule-match-mode')?.value;
    const helpEl = document.getElementById('qrule-match-help');
    if (!helpEl) return;
    const hints = {
        exact: 'Example: noreply@example.com - will only match this exact address',
        contains: 'Example: example.com - will match any value containing "example.com"',
        regex: 'Example: ^.*@(spam|junk)\\.com$ - advanced pattern matching'
    };
    helpEl.textContent = hints[mode] || '';
}

function closeQuarantineRuleModal() {
    const overlay = document.getElementById('quarantine-rule-modal-overlay');
    if (overlay) overlay.remove();
}

async function saveQuarantineRule(ruleId) {
    const name = document.getElementById('qrule-name')?.value?.trim();
    const matchType = document.getElementById('qrule-match-type')?.value;
    let matchValue = document.getElementById('qrule-match-value')?.value?.trim();
    const matchMode = document.getElementById('qrule-match-mode')?.value || 'exact';
    const action = document.getElementById('qrule-action')?.value;
    const notes = document.getElementById('qrule-notes')?.value?.trim() || null;
    
    if (!name) { showToast('Rule name is required', 'error'); return; }
    if (!matchValue) { showToast('Match value is required', 'error'); return; }
    
    // Convert match mode to is_regex + match_value
    let isRegex = false;
    if (matchMode === 'contains') {
        // Auto-wrap in regex for "contains" mode (escape special chars)
        const escaped = matchValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        matchValue = escaped;
        isRegex = true;
    } else if (matchMode === 'regex') {
        isRegex = true;
    }
    
    const body = { name, match_type: matchType, match_value: matchValue, is_regex: isRegex, action, notes };
    
    try {
        const isEdit = ruleId !== null;
        const url = isEdit ? `/api/quarantine/rules/${ruleId}` : '/api/quarantine/rules';
        const method = isEdit ? 'PUT' : 'POST';
        
        const res = await authenticatedFetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}`);
        }
        
        closeQuarantineRuleModal();
        showToast(isEdit ? 'Rule updated' : 'Rule created', 'success');
        await loadQuarantineRules();
    } catch (err) {
        showToast('Failed to save rule: ' + err.message, 'error');
    }
}

async function deleteQuarantineRule(ruleId, ruleName) {
    if (!await showConfirmModal({ title: 'Delete Rule', message: `Delete rule "${ruleName}"?`, confirmText: 'Delete', isDangerous: true })) return;
    
    try {
        const res = await authenticatedFetch(`/api/quarantine/rules/${ruleId}`, { method: 'DELETE' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        
        showToast('Rule deleted', 'success');
        await loadQuarantineRules();
    } catch (err) {
        showToast('Failed to delete rule: ' + err.message, 'error');
    }
}

async function toggleQuarantineRule(ruleId) {
    try {
        const res = await authenticatedFetch(`/api/quarantine/rules/${ruleId}/toggle`, { method: 'POST' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        
        const rule = await res.json();
        showToast(`Rule ${rule.enabled ? 'enabled' : 'disabled'}`, 'success');
        await loadQuarantineRules();
    } catch (err) {
        showToast('Failed to toggle rule: ' + err.message, 'error');
    }
}

async function testQuarantineRules() {
    try {
        showToast('Testing rules against quarantine...', 'info');
        const res = await authenticatedFetch('/api/quarantine/rules/test', { method: 'POST' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        
        const data = await res.json();
        
        if (data.total_matches === 0) {
            showToast(`No matches found (${data.total_quarantine} quarantine items checked)`, 'info');
            return;
        }
        
        // Group matches by rule
        const byRule = {};
        for (const m of data.matches) {
            const key = m.rule_id;
            if (!byRule[key]) {
                byRule[key] = { rule_name: m.rule_name, action: m.action, rule_enabled: m.rule_enabled, items: [] };
            }
            byRule[key].items.push(m);
        }
        
        const groupsHtml = Object.values(byRule).map(group => {
            const tone = group.action === 'delete' ? 'fail' : 'ok';
            const itemsHtml = group.items.map(m => `
                <div class="ui-qt-item${group.rule_enabled ? ` ui-qt-${tone}` : ''}">
                    <div>${escapeHtml(m.sender || '?')} → ${escapeHtml(m.recipient || '?')}</div>
                    <small class="ui-muted" dir="auto" title="${escapeHtml(m.subject || '')}">${escapeHtml((m.subject || 'No subject').substring(0, 80))}</small>
                </div>
            `).join('');

            return `
            <div class="ui-qt-group${!group.rule_enabled ? ' ui-row-off' : ''}">
                <div class="ui-list-head">
                    <b dir="auto">${escapeHtml(group.rule_name)}</b> ${uiTag(group.action, tone)}
                    ${!group.rule_enabled ? uiTag('Disabled - will not execute', '') : ''}
                    <span class="ui-muted ui-head-actions">${group.items.length} match${group.items.length !== 1 ? 'es' : ''}</span>
                </div>
                <div class="ui-qt-items">${itemsHtml}</div>
            </div>`;
        }).join('');

        const disabledCount = data.matches.filter(m => !m.rule_enabled).length;
        const activeCount = data.matches.length - disabledCount;
        const noMatches = data.total_matches === 0;

        const html = `
        <div class="ui-dialog-backdrop" id="qrule-test-modal" role="dialog" aria-label="Test Results">
            <div class="ui-dialog ui-dialog-fit ui-dialog-sm">
                <div class="ui-dialog-head">
                    <h3>Test Results</h3>
                    <button onclick="document.getElementById('qrule-test-modal').remove()" class="ui-icon-btn" title="Close" aria-label="Close">
                        <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                    </button>
                </div>
                <div class="ui-dialog-body ui-form">
                    <div class="ui-kpis">
                        <div class="ui-kpi"><b>${data.total_matches}</b>matched</div>
                        <div class="ui-kpi"><b class="ui-muted">${data.total_quarantine}</b>total</div>
                    </div>
                    ${disabledCount > 0 ? `<p class="ui-text-warn">⚠ ${disabledCount} from disabled rules</p>` : ''}
                    ${noMatches ? '<p class="ui-empty">No quarantine items matched any rules.</p>' : groupsHtml}
                    <p class="ui-kv-note ui-list-foot">This is a dry-run preview. No actions were taken.</p>
                </div>
            </div>
        </div>`;
        document.body.insertAdjacentHTML('beforeend', html);
    } catch (err) {
        showToast('Test failed: ' + err.message, 'error');
    }
}

function toggleQuarantineRuleHistory() {
    const section = document.getElementById('quarantine-rules-history');
    if (!section) return;
    
    if (section.classList.contains('hidden')) {
        section.classList.remove('hidden');
        loadQuarantineRuleHistory();
    } else {
        section.classList.add('hidden');
    }
}

async function loadQuarantineRuleHistory() {
    const container = document.getElementById('quarantine-rules-history-list');
    if (!container) return;
    
    container.innerHTML = '<p class="ui-empty">Loading...</p>';

    try {
        const res = await authenticatedFetch('/api/quarantine/rules/logs?limit=20');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        if (!data.data || data.data.length === 0) {
            container.innerHTML = '<p class="ui-empty">No actions recorded yet</p>';
            return;
        }

        container.innerHTML = `<div class="ui-qt-history">${data.data.map(log => `
            <div class="ui-qt-hrow">
                ${uiTag(log.action, log.action === 'delete' ? 'fail' : 'ok')}
                <span class="ui-q-who" title="${escapeHtml(log.sender || '')} → ${escapeHtml(log.recipient || '')}">${escapeHtml(log.sender || '?')} → ${escapeHtml(log.recipient || '?')}</span>
                <span class="ui-muted" title="Rule: ${escapeHtml(log.rule_name || '')}">${formatTime(log.created_at)}</span>
            </div>
        `).join('')}</div>`;
    } catch (err) {
        container.innerHTML = `<p class="ui-empty ui-text-fail">Failed: ${escapeHtml(err.message)}</p>`;
    }
}

// =============================================================================
// MESSAGES TAB (UNIFIED VIEW)
// =============================================================================

function applyMessagesFilters() {
    currentFilters.messages = {
        search: document.getElementById('messages-filter-search').value,
        sender: document.getElementById('messages-filter-sender').value,
        recipient: document.getElementById('messages-filter-recipient').value,
        direction: document.getElementById('messages-filter-direction').value,
        user: document.getElementById('messages-filter-user').value,
        status: document.getElementById('messages-filter-status').value,
        ip: document.getElementById('messages-filter-ip').value,
        date_range: document.getElementById('messages-date-range').value,
        start_date: document.getElementById('messages-start-date').value,
        end_date: document.getElementById('messages-end-date').value
    };
    currentPage.messages = 1;
    loadMessages();
}

// The filters panel next to the search (sender, recipient, user, IP)
function toggleMessagesFilters(open) {
    const panel = document.getElementById('messages-more-filters');
    const btn = document.getElementById('messages-filters-btn');
    if (!panel) return;
    const show = typeof open === 'boolean' ? open : panel.classList.contains('hidden');
    panel.classList.toggle('hidden', !show);
    if (btn) btn.setAttribute('aria-expanded', show);
    if (show) { const first = panel.querySelector('input'); if (first) first.focus(); }
}

// How many filters are on, for the button badge and the Clear filters link
function updateMessagesFilterState() {
    const f = currentFilters.messages || {};
    const advanced = ['sender', 'recipient', 'user', 'ip'].filter(k => f[k]).length;
    const any = advanced || f.search || f.status || f.direction || f.start_date || f.end_date || f.date_range;
    const badge = document.getElementById('messages-filters-n');
    if (badge) { badge.textContent = advanced || ''; badge.classList.toggle('hidden', !advanced); }
    const clear = document.getElementById('messages-clear-filters');
    if (clear) clear.classList.toggle('hidden', !any);
}

function clearMessagesFilters() {
    document.getElementById('messages-filter-search').value = '';
    document.getElementById('messages-filter-sender').value = '';
    document.getElementById('messages-filter-recipient').value = '';
    document.getElementById('messages-filter-direction').value = '';
    document.getElementById('messages-filter-user').value = '';
    document.getElementById('messages-filter-status').value = '';
    document.getElementById('messages-filter-ip').value = '';
    // Reset date range
    document.getElementById('messages-date-range').value = '';
    document.getElementById('messages-start-date').value = '';
    document.getElementById('messages-end-date').value = '';
    document.getElementById('messages-date-range-start').value = '';
    document.getElementById('messages-date-range-end').value = '';
    document.getElementById('messages-date-range-label').textContent = 'All Time';
    setMessagesDatePresetActive('');
    currentFilters.messages = {};
    currentPage.messages = 1;
    loadMessages();
}

// =============================================================================
// MESSAGES DATE RANGE PICKER
// =============================================================================

// Marks the chosen preset chip; null marks none (a custom range).
function setMessagesDatePresetActive(preset) {
    document.querySelectorAll('.messages-date-preset-btn').forEach(btn => {
        btn.setAttribute('aria-pressed', String(preset !== null && btn.getAttribute('data-preset') === preset));
    });
}

// Where the facets are hidden: outcome, direction and time open their choices in a panel, one at a time
const MESSAGES_PICKERS = ['status', 'direction', 'time'];

function toggleMessagesPicker(kind, open) {
    MESSAGES_PICKERS.forEach(k => {
        const panel = document.getElementById(`messages-${k}-panel`);
        const button = document.getElementById(k === 'time' ? 'messages-date-range-label' : `messages-${k}-pick`);
        if (!panel || !button) return;
        const show = k === kind && (open === undefined ? panel.classList.contains('hidden') : open);
        panel.classList.toggle('hidden', !show);
        button.setAttribute('aria-expanded', String(show));
        if (show && k === 'time') {
            // The custom range starts from the one in use
            document.getElementById('messages-time-start').value = document.getElementById('messages-date-range-start').value;
            document.getElementById('messages-time-end').value = document.getElementById('messages-date-range-end').value;
        }
    });
}

function toggleMessagesTimePanel(open) {
    toggleMessagesPicker('time', open);
}

function applyMessagesTimePanelRange() {
    document.getElementById('messages-date-range-start').value = document.getElementById('messages-time-start').value;
    document.getElementById('messages-date-range-end').value = document.getElementById('messages-time-end').value;
    applyMessagesCustomDateRange();
}

function toggleMessagesDateRangePicker() {
    const dropdown = document.getElementById('messages-date-range-dropdown');
    const arrow = document.getElementById('messages-date-range-arrow');
    const isHidden = dropdown.classList.contains('hidden');
    dropdown.classList.toggle('hidden');
    arrow.style.transform = isHidden ? 'rotate(180deg)' : '';
}

// Where a Messages time preset starts ('' for all time)
function messagesPresetStart(preset, now = new Date()) {
    const d = new Date(now);
    if (preset === 'today') { d.setHours(0, 0, 0, 0); return d.toISOString(); }
    const days = { '7days': 7, '30days': 30, '90days': 90 }[preset];
    if (!days) return '';
    d.setDate(d.getDate() - days);
    return d.toISOString();
}

function selectMessagesDatePreset(preset) {
    const labels = { '': 'All Time', 'today': 'Today', '7days': 'Last 7 Days', '30days': 'Last 30 Days', '90days': 'Last 90 Days' };
    document.getElementById('messages-date-range-label').textContent = labels[preset] || 'All Time';
    document.getElementById('messages-date-range').value = preset;

    // Calculate actual dates for the API
    const now = new Date();
    let startDate = '';
    let endDate = now.toISOString();

    if (preset === 'today') {
        const todayStart = new Date(now);
        todayStart.setHours(0, 0, 0, 0);
        startDate = todayStart.toISOString();
    } else if (preset === '7days') {
        const d = new Date(now);
        d.setDate(d.getDate() - 7);
        startDate = d.toISOString();
    } else if (preset === '30days') {
        const d = new Date(now);
        d.setDate(d.getDate() - 30);
        startDate = d.toISOString();
    } else if (preset === '90days') {
        const d = new Date(now);
        d.setDate(d.getDate() - 90);
        startDate = d.toISOString();
    } else {
        // All Time
        startDate = '';
        endDate = '';
    }

    document.getElementById('messages-start-date').value = startDate;
    document.getElementById('messages-end-date').value = endDate;

    setMessagesDatePresetActive(preset);

    // Close dropdown and apply
    document.getElementById('messages-date-range-dropdown').classList.add('hidden');
    document.getElementById('messages-date-range-arrow').style.transform = '';
    toggleMessagesTimePanel(false);
    applyMessagesFilters();
}

function applyMessagesCustomDateRange() {
    const startInput = document.getElementById('messages-date-range-start').value;
    const endInput = document.getElementById('messages-date-range-end').value;

    if (!startInput || !endInput) {
        showToast('Please select both start and end dates', 'warning');
        return;
    }

    const startDate = new Date(startInput);
    const endDate = new Date(endInput);
    endDate.setHours(23, 59, 59, 999);

    if (startDate > endDate) {
        showToast('Start date must be before end date', 'warning');
        return;
    }

    document.getElementById('messages-date-range').value = 'custom';
    document.getElementById('messages-start-date').value = startDate.toISOString();
    document.getElementById('messages-end-date').value = endDate.toISOString();

    // Format label
    const fmt = (d) => d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    document.getElementById('messages-date-range-label').textContent = `${fmt(startDate)} - ${fmt(endDate)}`;

    setMessagesDatePresetActive(null);

    // Close dropdown and apply
    document.getElementById('messages-date-range-dropdown').classList.add('hidden');
    document.getElementById('messages-date-range-arrow').style.transform = '';
    toggleMessagesTimePanel(false);
    applyMessagesFilters();
}

// Close messages date range picker on outside click
document.addEventListener('click', function(e) {
    const pickers = document.getElementById('messages-pickers');
    if (pickers && !pickers.contains(e.target)) toggleMessagesPicker(null, false);
    const container = document.getElementById('messages-date-range-picker-container');
    if (container && !container.contains(e.target)) {
        const dropdown = document.getElementById('messages-date-range-dropdown');
        const arrow = document.getElementById('messages-date-range-arrow');
        if (dropdown && !dropdown.classList.contains('hidden')) {
            dropdown.classList.add('hidden');
            if (arrow) arrow.style.transform = '';
        }
    }
});

// =============================================================================
// MESSAGES FACETS (counts per outcome and direction, /api/messages/facets)
// =============================================================================

const MESSAGE_STATUS_FACETS = [['', 'All messages'], ['delivered', 'Delivered'], ['deferred', 'Deferred'], ['bounced', 'Bounced'],
    ['rejected', 'Rejected'], ['spam', 'Spam'], ['discarded', 'Discarded (Sieve)']];
const MESSAGE_DIRECTION_FACETS = [['', 'Any direction'], ['inbound', 'Inbound'], ['outbound', 'Outbound'], ['internal', 'Internal']];

function messagesFilterParams(filters) {
    const params = new URLSearchParams();
    for (const key of ['search', 'sender', 'recipient', 'direction', 'user', 'status', 'ip', 'start_date', 'end_date']) {
        if (filters[key]) params.append(key, filters[key]);
    }
    return params;
}

// Choosing a facet sets the outcome or direction filter and reloads the list
function setMessagesFacet(kind, value) {
    const select = document.getElementById(kind === 'status' ? 'messages-filter-status' : 'messages-filter-direction');
    if (select) select.value = value;
    toggleMessagesPicker(null, false);
    applyMessagesFilters();
}

function renderFacetList(kind, entries, counts, current) {
    return entries.map(([value, label]) => {
        const count = counts ? counts[value || 'all'] : undefined;
        const tone = kind === 'status' && value ? (UI_STATUS_TONE[value] || '') : '';
        return `<button type="button" class="ui-fct" aria-pressed="${String(current === value)}" onclick="setMessagesFacet('${kind}', '${value}')">
            ${kind === 'status' && value ? `<i class="ui-fct-dot${tone ? ` ui-fct-${tone}` : ''}"></i>` : ''}${kind === 'direction' && value ? `<i class="ui-fct-dot ui-dir-${value}"></i>` : ''}<span>${escapeHtml(label)}</span>
            <small>${count === undefined ? '' : String(count)}</small></button>`;
    }).join('');
}

async function loadMessageFacets(filters) {
    const statusList = document.getElementById('messages-facet-status');
    const directionList = document.getElementById('messages-facet-direction');
    let data = null;
    try {
        const params = messagesFilterParams(filters);
        for (const preset of ['today', '7days', '30days', '90days']) params.append('since', `${preset}:${messagesPresetStart(preset)}`);
        const response = await authenticatedFetch(`/api/messages/facets?${params}`);
        if (response.ok) data = await response.json();
    } catch (e) {
        console.warn('Failed to load message facets:', e);
    }
    const status = filters.status || '';
    const direction = filters.direction || '';
    if (statusList) statusList.innerHTML = renderFacetList('status', MESSAGE_STATUS_FACETS, data && data.status, status);
    if (directionList) directionList.innerHTML = renderFacetList('direction', MESSAGE_DIRECTION_FACETS, data && data.direction, direction);
    // The time presets get their counts like the other facets
    document.querySelectorAll('.messages-date-preset-btn').forEach(btn => {
        const count = data && data.time ? data.time[btn.dataset.preset || 'all'] : undefined;
        let small = btn.querySelector('small');
        if (!small) { small = document.createElement('small'); btn.appendChild(small); }
        small.textContent = count === undefined ? '' : String(count);
    });
    // Phones and tablets: the same facets behind the Outcome and Direction buttons, which name the choice in use
    const pick = (kind, entries, counts, current, anyLabel) => {
        const options = document.getElementById(`messages-${kind}-options`);
        if (options) options.innerHTML = renderFacetList(kind, entries, counts, current);
        const button = document.getElementById(`messages-${kind}-pick`);
        const chosen = entries.find(([value]) => value === current);
        if (button) {
            button.textContent = current && chosen ? chosen[1] : anyLabel;
            button.classList.toggle('is-set', !!current);
        }
    };
    pick('status', MESSAGE_STATUS_FACETS, data && data.status, status, 'All outcomes');
    pick('direction', MESSAGE_DIRECTION_FACETS, data && data.direction, direction, 'Any direction');
    const timeButton = document.getElementById('messages-date-range-label');
    if (timeButton) timeButton.classList.toggle('is-set', !!(filters.start_date || filters.end_date));
}

// After the list renders: keep the open message marked, and on wide screens
// show the first message in the reading pane, as a mail client does.
function afterMessagesRendered(data) {
    if (typeof markSelectedMessageRow === 'function' && window.openMessageKey) markSelectedMessageRow(window.openMessageKey);
    const modal = document.getElementById('message-modal');
    const slot = typeof messageReaderSlot === 'function' ? messageReaderSlot() : null;
    if (slot && modal && modal.classList.contains('hidden') && data.data && data.data.length) {
        viewMessageDetails(data.data[0].correlation_key);
    }
}

async function loadMessages(page = 1) {
    const container = document.getElementById('messages-logs');

    try {
        container.innerHTML = '<div class="ui-loading"><div class="loading"></div><p>Loading...</p></div>';

        const filters = currentFilters.messages || {};
        loadMessageFacets(filters);
        updateMessagesFilterState();
        // The list grows as it scrolls, so a new load always starts at the top
        page = 1;
        const params = messagesQueryParams(page);
        container.scrollTop = 0;

        console.log('Loading Messages:', `/api/messages?${params}`);

        const response = await authenticatedFetch(`/api/messages?${params}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('Messages data:', data);

        // Update count display
        const countEl = document.getElementById('messages-count');
        if (countEl) {
            countEl.textContent = `${data.total || 0} messages`;
        }

        if (!data.data || data.data.length === 0) {
            container.innerHTML = '<p class="ui-empty">No messages found</p>';
            return;
        }

        renderMessagesList(container, data);
        afterMessagesRendered(data);

        currentPage.messages = page;
    } catch (error) {
        console.error('Failed to load messages:', error);
        document.getElementById('messages-logs').innerHTML = `<p class="ui-empty ui-text-fail">Failed to load messages: ${escapeHtml(error.message)}</p>`;
        const countEl = document.getElementById('messages-count');
        if (countEl) countEl.textContent = '';
    }
}

// =============================================================================
// STATUS TAB
// =============================================================================

// ---------- Status page ----------
// What each loader found, so the attention list and the tab counters can be
// built from one place once any of them finishes
const statusState = { containers: null, blocklists: null, jobs: null };
let statusTab = 'server';

// A dashboard card opens its tab on the Status page
function openStatusTab(tab) {
    statusShowTab(tab);
    navigateTo('status');
}

// One summary of the background jobs for Status and the dashboard
function summarizeJobs(jobs) {
    const all = statusJobCategories(jobs || {}).flatMap(cat => cat.jobs.filter(j => j[2]));
    const isOff = job => job.feature_disabled === true || job.status === 'disabled' || job.enabled === false;
    const failed = all.filter(([, , job]) => !isOff(job) && job.status === 'failed');
    const off = all.filter(([, , job]) => isOff(job)).length;
    return { all, isOff, failed, off, healthy: all.length - failed.length - off, running: all.length - off };
}
let statusCtrFilter = 'all';
let statusJobFilterValue = 'all';

function statusShowTab(tab) {
    statusTab = tab;
    routerSyncSubpage('status', tab);
    document.querySelectorAll('.ui-st-tabs .modal-tab').forEach(btn => {
        const on = btn.id === `status-tab-btn-${tab}`;
        btn.classList.toggle('active', on);
        btn.setAttribute('aria-selected', on);
    });
    document.querySelectorAll('.ui-st-panel').forEach(panel => panel.classList.toggle('hidden', panel.id !== `status-tab-${tab}`));
}

function setStatusTabCount(tab, count, isFail) {
    const el = document.getElementById(`status-tab-n-${tab}`);
    if (!el) return;
    el.textContent = count;
    el.classList.toggle('hidden', !count);
    el.classList.toggle('is-fail', !!isFail);
}

function statusContainerFilter(filter) {
    statusCtrFilter = filter;
    document.querySelectorAll('[data-ctr-filter]').forEach(b => b.setAttribute('aria-pressed', b.dataset.ctrFilter === filter));
    document.querySelectorAll('#status-containers .ui-ctr').forEach(row => {
        row.hidden = filter === 'problems' && !row.classList.contains('is-down');
    });
}

function statusJobFilter(filter) {
    statusJobFilterValue = filter;
    document.querySelectorAll('[data-job-filter]').forEach(b => b.setAttribute('aria-pressed', b.dataset.jobFilter === filter));
    document.querySelectorAll('#status-jobs .ui-jg').forEach(group => {
        let shown = 0;
        group.querySelectorAll('.ui-jobrow').forEach(row => {
            const show = filter === 'all' || (filter === 'problems' && row.classList.contains('is-failed'))
                || (filter === 'off' && row.classList.contains('is-off'));
            row.hidden = !show;
            if (show) shown++;
        });
        group.hidden = shown === 0;
        // Filtered: open what matches. All: back to failures plus what the user opened
        group.open = filter === 'all' ? (group.hasAttribute('data-failed') || statusJobsOpen.has(group.dataset.group)) : shown > 0;
    });
}

// A clickable link to a provider's own lookup page
function blocklistLookupLink(r, label) {
    if (!/^https:\/\//.test(r.info_url || '')) return '';
    return `<a href="${escapeHtml(r.info_url)}" target="_blank" rel="noopener noreferrer" class="ui-btn ui-btn-sm" title="Look up on ${escapeHtml(r.name)}">${label}</a>`;
}

// Needs attention: stopped containers, blocklist listings and failed jobs,
// each with the action that resolves it
function renderStatusAttention() {
    const box = document.getElementById('status-attention');
    const count = document.getElementById('status-attention-count');
    if (!box) return;
    const items = [];
    for (const c of statusState.containers || []) {
        if (c.ignored || c.running) continue;
        items.push({ tone: 'fail', title: `${c.name} is stopped`, detail: `State: ${c.state}. It is not running, so what it does is off until it starts again.`,
            actions: `<button type="button" class="ui-btn ui-btn-sm" onclick="setContainerIgnored('${escapeJsArg(c.container)}', true)" title="Stop counting and alerting on ${escapeHtml(c.name)}">Ignore</button>` });
    }
    const blOff = (window.disabledFeatures || []).includes('blacklist');
    for (const host of blOff ? [] : (statusState.blocklists || [])) {
        for (const r of (host.results || []).filter(x => x.listed && !x.ignored)) {
            items.push({ tone: 'fail', title: `${host.hostname} is on ${r.name}`,
                detail: `${host.source || 'system'}, listed on ${host.listed_count || 1} of ${host.total_blacklists || '?'} lists. Mail to some providers may bounce.`,
                actions: `${blocklistLookupLink(r, 'Look up')}<button type="button" class="ui-btn ui-btn-sm" onclick="setBlocklistIgnored('${escapeJsArg(r.zone)}', true)" title="Keep checking ${escapeHtml(r.name)} but never count or alert on it">Ignore this list</button>` });
        }
    }
    for (const job of statusState.jobs || []) {
        if (!job.failed) continue;
        items.push({ tone: 'warn', title: `${job.name} failed`, detail: job.error || 'The last run did not finish.',
            actions: `<button type="button" class="ui-btn ui-btn-sm" onclick="triggerBackgroundJob('${escapeJsArg(job.key)}', this, '${escapeJsArg(job.name)}')">Run now</button>` });
    }
    const loaded = statusState.containers && statusState.jobs;
    if (count) count.textContent = items.length ? String(items.length) : '';
    if (!items.length) {
        box.innerHTML = loaded ? '<p class="ui-st-allgood">Everything is running. Nothing needs you right now.</p>'
            : '<div class="ui-loading"><div class="loading"></div><p>Loading...</p></div>';
        return;
    }
    box.innerHTML = items.map(item => `
        <div class="ui-alert ui-alert-${item.tone}">
            <span class="ui-alert-bar"></span>
            <div class="ui-alert-text"><div class="ui-alert-title"><b>${escapeHtml(item.title)}</b></div><p>${escapeHtml(item.detail)}</p></div>
            <div class="ui-st-acts">${item.actions}</div>
        </div>`).join('');
}

async function loadStatus() {
    try {
        await Promise.all([
            loadStatusContainers(),
            loadStatusSystem(),
            loadStatusStorage(),
            loadStatusExtended(),
            loadStatusAppVersion()
        ]);
        const lastChecked = document.getElementById('status-last-checked');
        if (lastChecked) {
            const now = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', hour12: false,
                timeZone: appTimezone && appTimezone !== 'UTC' ? appTimezone : undefined }).format(new Date());
            lastChecked.textContent = `Last checked: ${now}`;
        }
        renderStatusAttention();
    } catch (error) {
        console.error('Failed to load status:', error);
    }
}

function setStatusKpi(id, value, tone) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = value;
    el.className = tone ? `ui-${tone}` : '';
}

// The version of this app, and whether an update is out
async function loadStatusAppVersion() {
    const note = document.getElementById('status-kpi-version-note');
    try {
        const res = await authenticatedFetch('/api/status/app-version');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        setStatusKpi('status-kpi-version', data.current_version || '-');
        if (note) {
            note.innerHTML = data.update_available
                ? `<button type="button" class="ui-link-row ui-text-info" onclick="switchTab('settings')">Update ${escapeHtml(data.latest_version)} available</button>`
                : 'Up to date';
        }
    } catch (error) {
        setStatusKpi('status-kpi-version', '-');
        if (note) note.textContent = 'Version';
    }
}

async function setContainerIgnored(container, ignored) {
    try {
        const res = await authenticatedFetch(`/api/status/containers/${encodeURIComponent(container)}/ignore`, {
            method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ignored })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        showToast(ignored ? `${container.replace('-mailcow', '')} is ignored. It no longer counts or alerts.` : `${container.replace('-mailcow', '')} counts again.`, 'success');
        loadStatusContainers();
        loadNavCounters();
    } catch (e) {
        showToast(`Could not change the container: ${e.message}`, 'error');
    }
}

async function loadStatusContainers() {
    try {
        const response = await authenticatedFetch('/api/status/containers');
        let data = await response.json();

        const container = document.getElementById('status-containers');

        let containersData = data.containers || data;

        if (Array.isArray(containersData) && containersData.length === 1 && typeof containersData[0] === 'object') {
            containersData = containersData[0];
        }

        let containersList = [];
        if (Array.isArray(containersData)) {
            containersList = containersData;
        } else if (containersData && typeof containersData === 'object') {
            containersList = Object.entries(containersData).map(([key, value]) => ({
                name: (value.name || key).replace('-mailcow', ''),
                container: key,
                state: value.state || 'unknown',
                started_at: value.started_at || null,
                ignored: !!value.ignored
            }));
        }

        const note = document.getElementById('status-containers-note');
        if (containersList.length > 0) {
            // Only 'running' is running; paused, exited, restarting, dead and the rest count as stopped
            // Ignored containers (stopped on purpose) are shown but never counted
            const isRunning = c => (c.state || 'unknown').toString().toLowerCase().trim() === 'running';
            const counted = containersList.filter(c => !c.ignored);
            const running = counted.filter(isRunning).length;
            const stopped = counted.length - running;
            const ignoredCount = containersList.length - counted.length;
            setStatusKpi('status-kpi-containers', `${running} of ${counted.length} running`, stopped > 0 ? 'fail' : '');
            const summaryText = [stopped ? `${stopped} stopped` : 'All running', ignoredCount ? `${ignoredCount} ignored` : ''].filter(Boolean).join(', ');
            if (note) note.textContent = summaryText;
            const summary = document.getElementById('status-containers-summary');
            if (summary) summary.textContent = summaryText;
            setStatusTabCount('server', stopped, true);
            statusState.containers = containersList.map(c => ({ ...c, running: isRunning(c) }));

            // Stopped containers first, so they are seen; ignored ones last
            const rank = c => c.ignored ? 2 : (isRunning(c) ? 1 : 0);
            const ordered = [...containersList].sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));
            // One tile per container: state dot, name, uptime, and Ignore where it applies
            container.innerHTML = `<div class="ui-ctrs">${ordered.map(c => {
                const up = isRunning(c);
                const since = c.started_at ? formatAgo(c.started_at).replace(' ago', '') : '';
                const arg = escapeJsArg(c.container);
                // A stopped container can be ignored; an ignored one can be counted again
                const action = c.ignored
                    ? `<button type="button" class="ui-btn ui-btn-sm" onclick="setContainerIgnored('${arg}', false)">Stop ignoring</button>`
                    : (up ? '' : `<button type="button" class="ui-btn ui-btn-sm" onclick="setContainerIgnored('${arg}', true)" title="Stop counting and alerting on ${escapeHtml(c.name)}">Ignore</button>`);
                const state = c.ignored ? 'ignored' : (up ? (since ? `up ${since}` : 'running') : String(c.state || 'unknown'));
                return `
                <div class="ui-ctr${c.ignored ? ' is-ignored' : (up ? '' : ' is-down')}" title="${escapeHtml(c.ignored ? 'Ignored: shown here but never counted or alerted' : (c.started_at ? `Started ${formatTime(c.started_at)}` : 'Start time unknown'))}">
                    <i class="ui-mdot${c.ignored ? '' : (up ? ' ui-mdot-ok' : ' ui-mdot-fail')}"></i>
                    <b>${escapeHtml(c.name)}</b>
                    <small>${escapeHtml(state)}</small>${action ? `<span class="ui-ctr-act">${action}</span>` : ''}
                </div>`;
            }).join('')}</div>`;
            statusContainerFilter(statusCtrFilter);
            renderStatusAttention();
        } else {
            setStatusKpi('status-kpi-containers', '-');
            if (note) note.textContent = '';
            container.innerHTML = '<p class="ui-empty ui-panel">No container information available</p>';
        }
    } catch (error) {
        console.error('Failed to load containers status:', error);
        setStatusKpi('status-kpi-containers', '-');
        document.getElementById('status-containers').innerHTML = '<p class="ui-empty ui-panel ui-text-fail">Failed to load containers</p>';
    }
}

async function loadStatusSystem() {
    const container = document.getElementById('status-system');

    try {
        console.log('Loading System Info...');

        // Fetch both system info and version status
        const [infoResponse, versionResponse] = await Promise.all([
            authenticatedFetch('/api/status/mailcow-info'),
            authenticatedFetch('/api/status/version')
        ]);

        if (!infoResponse.ok) {
            throw new Error(`HTTP ${infoResponse.status}: ${infoResponse.statusText}`);
        }

        const data = await infoResponse.json();
        const versionData = versionResponse.ok ? await versionResponse.json() : null;

        console.log('System info data:', data);

        let versionHtml = '';
        if (versionData && versionData.current_version) {
            // Store data globally to avoid passing complex strings in HTML
            window.mailcowUpdateVersion = versionData.latest_version;
            window.mailcowUpdateName = versionData.name || ''; // Store release title
            window.mailcowUpdateChangelog = versionData.changelog || 'No changelog available';

            const updateBadge = versionData.update_available
                ? ` <button onclick="showMailcowUpdateModal()" class="ui-tag ui-tag-info ui-tag-btn">Update Available</button>`
                : '';
            versionHtml = `v${escapeHtml(versionData.current_version)}${updateBadge}`;
        }

        const row = (label, part) => `<dt>${label}</dt><dd>${(part.total || 0).toLocaleString()} <small>${(part.active || 0).toLocaleString()} active</small></dd>`;
        container.innerHTML = `
            <div class="ui-srv-big">${versionHtml || 'mailcow'}</div>
            <dl class="ui-srv-dl">
                ${row('Domains', data.domains || {})}
                ${row('Mailboxes', data.mailboxes || {})}
                ${row('Aliases', data.aliases || {})}
            </dl>
        `;
    } catch (error) {
        console.error('Failed to load system info:', error);
        document.getElementById('status-system').innerHTML = `<p class="ui-empty ui-text-fail">Failed to load system info: ${escapeHtml(error.message)}</p>`;
    }
}

function showMailcowUpdateModal() {
    if (window.mailcowUpdateVersion && window.mailcowUpdateChangelog) {
        // Use release name as title if available, otherwise fallback to version
        const title = window.mailcowUpdateName
            ? `Update Available: ${window.mailcowUpdateName}`
            : `mailcow Update: ${window.mailcowUpdateVersion}`;

        showMarkdownModal(title, window.mailcowUpdateChangelog);
    }
}



async function loadStatusStorage() {
    const container = document.getElementById('status-storage');

    try {
        console.log('Loading Storage Info...');

        const response = await authenticatedFetch('/api/status/storage');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        let rawData = await response.json();
        console.log('Storage info data:', rawData);

        // Handle mailcow API format: [{ "type": "info", "disk": "/dev/sdb1", ... }]
        let data = rawData;
        if (Array.isArray(rawData) && rawData.length > 0) {
            data = rawData[0]; // Take first element
        }
        const usedPercent = parseInt(data.used_percent) || 0;
        // Amber above 75%, red above 90%
        const level = usedPercent > 90 ? 'fail' : usedPercent > 75 ? 'warn' : 'ok';
        setStatusKpi('status-kpi-storage', `${data.used_percent || `${usedPercent}%`} used`, level === 'ok' ? '' : level);
        const storageNote = document.getElementById('status-kpi-storage-note');
        if (storageNote) storageNote.textContent = [data.used && data.total ? `${data.used} of ${data.total}` : '', data.disk || ''].filter(Boolean).join(', ');

        const size = [data.used && data.total ? `${data.used} of ${data.total}` : '', data.disk ? `on ${data.disk}` : ''].filter(Boolean).join(' ');
        container.innerHTML = `
            <div class="ui-srv-big${level === 'ok' ? '' : ` ui-text-${level}`}">${escapeHtml(String(data.used_percent || '0%'))} used</div>
            <div class="ui-meter ui-${level}"><i style="width: ${usedPercent}%"></i></div>
            ${size ? `<small>${escapeHtml(size)}</small>` : ''}
        `;
    } catch (error) {
        console.error('Failed to load storage info:', error);
        setStatusKpi('status-kpi-storage', '-');
        document.getElementById('status-storage').innerHTML = `<p class="ui-empty ui-text-fail">Failed to load storage info: ${escapeHtml(error.message)}</p>`;
    }
}

async function loadStatusExtended() {
    try {
        const response = await authenticatedFetch('/api/settings/info');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        console.log('Extended status data loaded:', data);

        // Render Import Status
        renderStatusImport(data.import_status || {});

        // Render Correlation Status
        renderStatusCorrelation(data.correlation_status || {}, data.recent_incomplete_correlations || []);

        // Render Background Jobs
        renderStatusJobs(data.background_jobs || {});

        // Load Blacklist Status separately
        loadBlacklistStatus();

    } catch (error) {
        console.error('Failed to load extended status:', error);
        document.getElementById('status-import').innerHTML = `<p class="ui-empty ui-text-fail">Failed to load: ${escapeHtml(error.message)}</p>`;
        document.getElementById('status-correlation').innerHTML = `<p class="ui-empty ui-text-fail">Failed to load: ${escapeHtml(error.message)}</p>`;
        document.getElementById('status-jobs').innerHTML = `<p class="ui-empty ui-text-fail">Failed to load: ${escapeHtml(error.message)}</p>`;
    }
}

function checkHost(hostname) {
    return checkBlacklists(true, hostname);
}

async function checkBlacklists(force = false, host = null) {
    const btn = document.getElementById('blacklist-check-btn');
    const container = document.getElementById('status-blacklist');

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `
            <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            Running...
        `;
    }

    showToast('Starting blacklist check...', 'info');

    // Inject temporary progress bar at the top
    if (container) {
        // Remove existing temp progress if any
        const existing = document.getElementById('blacklist-temp-progress');
        if (existing) existing.remove();

        const progressHtml = `
            <div id="blacklist-temp-progress" class="ui-panel ui-bl-progress">
                <div class="ui-bl-progress-head">
                    <span class="ui-text-info">
                        <svg class="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        Running Scan...
                    </span>
                    <span id="blacklist-progress-text" class="ui-muted">Initializing...</span>
                </div>
                <div class="ui-meter ui-meter-info"><i id="blacklist-progress-bar" style="width: 0%"></i></div>
            </div>
        `;
        container.insertAdjacentHTML('afterbegin', progressHtml);
    }

    // Start progress polling
    let progressInterval = setInterval(async () => {
        try {
            const progressRes = await authenticatedFetch('/api/blacklist/progress');
            if (progressRes.ok) {
                const progress = await progressRes.json();
                const progressBar = document.getElementById('blacklist-progress-bar');
                const progressText = document.getElementById('blacklist-progress-text');

                if (progressBar) {
                    progressBar.style.width = `${progress.percent}%`;
                }
                if (progressText) {
                    progressText.textContent = `${progress.current}/${progress.total} scanned${progress.current_blacklist ? ` - ${progress.current_blacklist}` : ''}`;
                }

                if (!progress.in_progress && progress.current >= progress.total) {
                    clearInterval(progressInterval);
                    showToast('Blacklist check completed', 'success');
                    // Remove progress bar
                    const temp = document.getElementById('blacklist-temp-progress');
                    if (temp) temp.remove();

                    await loadBlacklistStatus(); // Refresh data!
                }
            }
        } catch (e) {
            // Ignore progress errors
        }
    }, 1000);

    try {
        const params = new URLSearchParams();
        if (force) params.set('force', 'true');
        if (host) params.set('host', host);
        const qs = params.toString();
        const response = await authenticatedFetch(`/api/blacklist/check${qs ? '?' + qs : ''}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        if (host) {
            // Single-host checks return the finished result directly - the
            // all-hosts path returns immediately and the poller finishes up
            clearInterval(progressInterval);
            const temp = document.getElementById('blacklist-temp-progress');
            if (temp) temp.remove();
            showToast(`Check completed for ${host}`, 'success');
            await loadBlacklistStatus();
        }
    } catch (error) {
        clearInterval(progressInterval);
        const temp = document.getElementById('blacklist-temp-progress');
        if (temp) temp.remove();

        console.error('Failed to check blacklists:', error);
        showToast(`Failed to check: ${error.message}`, 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                </svg>
                Check Now
            `;
        }
    }
}

async function loadBlacklistStatus() {
    const container = document.getElementById('status-blacklist');
    if (!container) return;

    // Skip refresh if details are expanded (to prevent closing)
    // We check if any sub-details are open
    const detailsElement = container.querySelector('details[open]');
    if (detailsElement) {
        // console.log('Skipping blacklist refresh: details are expanded');
        // return;
    }

    try {
        const response = await authenticatedFetch('/api/blacklist/monitored');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        renderBlacklistStatus(data);
    } catch (error) {
        console.error('Failed to load blacklist status:', error);
        container.innerHTML = `<p class="ui-empty ui-text-fail">Failed to load: ${escapeHtml(error.message)}</p>`;
    }
}


async function loadDashboardBlacklistSummary() {
    if (!document.getElementById('dash-kpi-blocklists')) return;
    try {
        const response = await authenticatedFetch('/api/blacklist/summary');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (!data.has_data) {
            setDashKpi('dash-kpi-blocklists', '-', '', 'No check yet; the first one runs by itself');
            return;
        }
        // Count addresses, like the Status page, and name the listed ones
        const hosts = data.hosts || [];
        const listedHosts = hosts.filter(h => h.status === 'listed');
        const checked = data.checked_at ? `checked ${formatAgo(data.checked_at)}` : '';
        if (data.status === 'listed') {
            setDashKpi('dash-kpi-blocklists', `${listedHosts.length || data.hosts_listed || 1} of ${hosts.length || 1} listed`, 'fail',
                listedHosts.map(h => `${h.hostname} on ${h.listed_count} of ${h.total_blacklists || '?'}`).join(', '));
        } else if (data.status === 'error') {
            setDashKpi('dash-kpi-blocklists', 'Check error', 'warn', checked);
        } else if (data.status === 'clean') {
            setDashKpi('dash-kpi-blocklists', `${hosts.length || 1} clean`, '', [`${hosts.length} address${hosts.length === 1 ? '' : 'es'}`, checked].filter(Boolean).join(', '));
        } else {
            setDashKpi('dash-kpi-blocklists', 'Unknown', '', checked);
        }
    } catch (error) {
        console.error('Failed to load blacklist summary:', error);
        setDashKpi('dash-kpi-blocklists', '-', '', 'Could not load');
    }
}


function renderBlacklistStatus(data) {
    const container = document.getElementById('status-blacklist');
    if (!container) return;

    if (!data.hosts || data.hosts.length === 0) {
        setStatusKpi('status-kpi-blocklists', '-');
        container.innerHTML = `
            <div class="ui-empty ui-panel">
                <b>No Monitored Hosts</b>
                <p>Syncing monitoring targets...</p>
            </div>
        `;
        return;
    }

    // Addresses on at least one list, out of the checked addresses (same as the dashboard)
    const withData = data.hosts.filter(host => host.has_data);
    const listed = withData.filter(host => (host.listed_count || 0) > 0).length;
    setStatusKpi('status-kpi-blocklists', withData.length ? `${listed} of ${withData.length} listed` : '-', listed > 0 ? 'fail' : '');
    setStatusTabCount('blocklists', listed, true);
    statusState.blocklists = data.hosts;

    // Every list the admin ignores, once, with the way back
    const ignoredLists = new Map();
    data.hosts.forEach(host => (host.results || []).forEach(r => { if (r.ignored && r.zone) ignoredLists.set(r.zone, r.name); }));
    const blNote = document.getElementById('status-kpi-blocklists-note');
    if (blNote) blNote.textContent = ignoredLists.size ? `${ignoredLists.size} list${ignoredLists.size === 1 ? '' : 's'} ignored for every address` : 'Addresses on a blocklist';
    const blSummary = document.getElementById('status-blacklist-summary');
    if (blSummary) blSummary.textContent = `${data.hosts.length} address${data.hosts.length === 1 ? '' : 'es'}${listed ? `, ${listed} listed` : ''}`;

    // Preserve which hosts show all their lists
    const openStates = {};
    container.querySelectorAll('details').forEach(el => {
        if (el.open && el.id) openStates[el.id] = true;
    });

    const RESULT_TONE = { clean: 'ok', listed: 'fail', error: 'warn', timeout: 'warn' };
    const detail = r => r.response ? `${r.name}: ${r.response}` : r.name;
    const lookupIcon = r => /^https:\/\//.test(r.info_url || '')
        ? `<a href="${escapeHtml(r.info_url)}" target="_blank" rel="noopener noreferrer" class="ui-bl-link" title="Look up on ${escapeHtml(r.name)}" aria-label="Look up on ${escapeHtml(r.name)}"><svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg></a>`
        : '';
    const ignoreToggle = r => r.zone && r.zone !== 'unknown'
        ? `<button type="button" class="ui-bl-ign" onclick="setBlocklistIgnored('${escapeJsArg(r.zone)}', ${!r.ignored})" title="${r.ignored ? 'Count and alert on this list again' : 'Keep checking this list but never count or alert on it'}">${r.ignored ? 'Stop ignoring' : 'Ignore'}</button>`
        : '';

    container.innerHTML = `
        <div class="ui-st-hosts">
        ${data.hosts.map((host, index) => {
            const hostId = `host-${index}`;
            const results = host.results || [];
            const listedOn = results.filter(r => r.listed && !r.ignored);
            const others = results.filter(r => !(r.listed && !r.ignored));
            const total = host.total_blacklists || 0;
            const result = !host.has_data ? uiTag('Not checked yet', '')
                : host.status === 'listed' ? uiTag(`Listed on ${host.listed_count || 0} of ${total}`, 'fail')
                : host.status === 'error' ? uiTag('Check error', 'warn')
                : host.status === 'clean' ? uiTag(`Clean on ${total}`, 'ok')
                : uiTag('Unknown', '');
            return `
            <section class="ui-panel ui-bl-row">
                <div class="ui-st-host-head">
                    <b class="ui-mono">${escapeHtml(host.hostname)}</b>
                    <span class="ui-tag ui-tag-line">${escapeHtml(host.source || 'system')}</span>
                    ${result}
                    <span class="ui-st-host-tools">
                        <span class="ui-muted" title="${host.checked_at ? escapeHtml(formatTime(host.checked_at)) : ''}">${host.checked_at ? `checked ${formatAgo(host.checked_at)}` : 'never checked'}</span>
                        <button onclick="checkHost('${escapeJsArg(host.hostname)}')" class="ui-btn ui-btn-sm" title="Run Check for this Host">Check now</button>
                    </span>
                </div>
                ${listedOn.map(r => `
                <div class="ui-st-listing">
                    <div><b>${escapeHtml(r.name)}</b><small>${escapeHtml(r.response ? `Answer ${r.response}` : 'Listed')}</small></div>
                    <span class="ui-st-acts">${blocklistLookupLink(r, 'Look up')}<button type="button" class="ui-btn ui-btn-sm" onclick="setBlocklistIgnored('${escapeJsArg(r.zone)}', true)">Ignore list</button></span>
                </div>`).join('')}
                ${host.has_data && others.length ? `
                <details id="${hostId}" class="ui-bl-all"${openStates[hostId] ? ' open' : ''}>
                    <summary>${listedOn.length ? `${others.length} other lists` : `All ${others.length} lists`}</summary>
                    <div class="ui-bl-grid">
                        ${others.map(r => {
                            const tone = r.ignored ? '' : (RESULT_TONE[r.status] || '');
                            const state = r.listed ? 'listed, ignored' : (r.ignored ? 'ignored' : (r.status || 'unknown'));
                            return `<span class="ui-bl-item${tone ? ` ui-bl-${tone}` : ''}${r.ignored ? ' is-ignored' : ''}" title="${escapeHtml(detail(r))}"><i class="ui-mdot${tone ? ` ui-mdot-${tone}` : ''}"></i>${escapeHtml(r.name)}${lookupIcon(r)}<small>${escapeHtml(state)}</small>${ignoreToggle(r)}</span>`;
                        }).join('')}
                    </div>
                </details>` : ''}
            </section>`;
        }).join('')}
        ${ignoredLists.size ? `
            <section class="ui-panel">
                <div class="ui-panel-head">Ignored lists <span class="ui-count">${ignoredLists.size}</span></div>
                ${[...ignoredLists].map(([zone, name]) => `
                <div class="ui-st-listing">
                    <div><b>${escapeHtml(name)}</b><small>Checked and shown, never counted or alerted, for every address</small></div>
                    <span class="ui-st-acts"><button type="button" class="ui-btn ui-btn-sm" onclick="setBlocklistIgnored('${escapeJsArg(zone)}', false)">Stop ignoring</button></span>
                </div>`).join('')}
            </section>` : ''}
        </div>
    `;
    renderStatusAttention();
}

async function setBlocklistIgnored(zone, ignored) {
    try {
        const res = await authenticatedFetch(`/api/blacklist/lists/${encodeURIComponent(zone)}/ignore`, {
            method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ignored })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        showToast(ignored ? `${data.name} is ignored for every address.` : `${data.name} counts again.`, 'success');
        loadBlacklistStatus();
        loadNavCounters();
    } catch (e) {
        showToast(`Could not change the blocklist: ${e.message}`, 'error');
    }
}

function renderStatusImport(imports) {
    const container = document.getElementById('status-import');
    const row = (title, d) => `
        <div class="ui-tr">
            <b class="ui-td">${title}</b>
            ${d ? `
            <span class="ui-td" title="${d.last_fetch_run ? escapeHtml(formatTime(d.last_fetch_run)) : ''}"><small class="ui-sec-unit">Last Fetch Run </small>${d.last_fetch_run ? formatAgo(d.last_fetch_run) : 'Never'}</span>
            <span class="ui-td" title="${d.last_import ? escapeHtml(formatTime(d.last_import)) : ''}"><small class="ui-sec-unit">Last Import </small>${d.last_import ? formatAgo(d.last_import) : 'Never'}</span>
            <span class="ui-td ui-td-end"><small class="ui-sec-unit">Total Entries </small>${(d.total_entries || 0).toLocaleString()}</span>
            <span class="ui-td"><small class="ui-sec-unit">Oldest Entry </small>${d.oldest_entry ? formatTime(d.oldest_entry) : '-'}</span>
            ` : '<span class="ui-td ui-muted">No data</span><span></span><span></span><span></span>'}
        </div>`;
    container.innerHTML = `
        <div class="ui-table ui-stack" style="--ui-cols: minmax(130px, 1fr) minmax(110px, 1fr) minmax(110px, 1fr) 110px minmax(150px, 1.2fr); --ui-table-min: 660px">
            <div class="ui-tr ui-tr-head"><span>Source</span><span>Last Fetch Run</span><span>Last Import</span><span class="ui-td-end">Total Entries</span><span>Oldest Entry</span></div>
            ${row('Postfix Logs', imports.postfix)}
            ${row('Rspamd Logs', imports.rspamd)}
            ${row('Netfilter Logs', imports.netfilter)}
        </div>
    `;
}

function renderStatusCorrelation(correlation, incompleteList) {
    const container = document.getElementById('status-correlation');
    setStatusKpi('status-kpi-linking', `${correlation.completion_rate || 0}%`, correlation.incomplete ? 'warn' : '');
    const linkingNote = document.getElementById('status-kpi-linking-note');
    if (linkingNote) linkingNote.textContent = `${(correlation.complete || 0).toLocaleString()} of ${(correlation.total || 0).toLocaleString()} complete, ${(correlation.incomplete || 0).toLocaleString()} waiting`;
    container.innerHTML = `
        <div class="ui-srv-big${correlation.incomplete ? ' ui-text-warn' : ''}">${correlation.completion_rate || 0}%</div>
        <small>${(correlation.complete || 0).toLocaleString()} of ${(correlation.total || 0).toLocaleString()} complete, ${(correlation.incomplete || 0).toLocaleString()} incomplete, ${(correlation.expired || 0).toLocaleString()} expired</small>
        ${correlation.last_update ? `<small>Updated ${formatTime(correlation.last_update)}</small>` : ''}
    `;
    const pending = document.getElementById('status-correlation-pending');
    if (pending) pending.innerHTML = incompleteList.length > 0 ? `
        <section class="ui-sec-block">
            <div class="ui-list-head"><h2 class="ui-h2">Waiting to be linked</h2> <span class="ui-count">${incompleteList.length}</span></div>
            <div class="ui-table ui-stack" style="--ui-cols: minmax(180px, 1.4fr) minmax(220px, 2fr) 90px; --ui-table-min: 560px">
                <div class="ui-tr ui-tr-head"><span>Message ID</span><span>From and to</span><span class="ui-td-end">Age</span></div>
                ${incompleteList.map(item => `
                    <div class="ui-tr">
                        <span class="ui-td ui-mono">${copyableText(item.message_id || 'N/A')}</span>
                        <span class="ui-td">${copyableText(item.sender || 'N/A')} → ${copyableText(item.recipient || 'N/A')}</span>
                        <span class="ui-td ui-td-end ui-text-warn">${item.age_minutes}m ago</span>
                    </div>`).join('')}
            </div>
            <p class="ui-kv-note ui-list-foot">These will be automatically completed or expired within 1-2 minutes</p>
        </section>` : '';
}

function renderStatusJobs(jobs) {
    const container = document.getElementById('status-jobs');
    const categories = statusJobCategories(jobs);
    renderStatusJobsTable(container, categories, jobs);
}

function statusJobCategories(jobs) {
    return [
        {
            title: 'Log Processing',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"></path>',
            jobs: [
                ['Fetch Logs', 'fetch_logs', jobs.fetch_logs],
                ['Cleanup Logs', 'cleanup_logs', jobs.cleanup_logs]
            ]
        },
        {
            title: 'Correlation Engine',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path>',
            jobs: [
                ['Complete Correlations', 'complete_correlations', jobs.complete_correlations],
                ['Update Final Status', 'update_final_status', jobs.update_final_status],
                ['Expire Correlations', 'expire_correlations', jobs.expire_correlations],
                ['Dovecot Deliveries', 'correlate_dovecot', jobs.correlate_dovecot]
            ]
        },
        {
            title: 'Data Sync',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>',
            jobs: [
                ['Sync Active Domains', 'sync_local_domains', jobs.sync_local_domains],
                ['Mailbox Statistics', 'mailbox_stats', jobs.mailbox_stats],
                ['Alias Statistics', 'alias_stats', jobs.alias_stats],
                ['Sync Transports & Relayhosts', 'sync_transports', jobs.sync_transports]
            ]
        },
        {
            title: 'DMARC & TLS',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>',
            jobs: [
                ['DMARC & TLS IMAP Import', 'dmarc_imap_sync', jobs.dmarc_imap_sync],
                ['Cleanup DMARC & TLS Reports', 'cleanup_dmarc_reports', jobs.cleanup_dmarc_reports],
                ['Weekly Summary Report', 'send_weekly_summary', jobs.send_weekly_summary]
            ]
        },
        {
            title: 'Security & Monitoring',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>',
            jobs: [
                ['DNS Check (All Domains)', 'dns_check', jobs.dns_check],
                ['IP Blacklist Check (All Hosts)', 'blacklist_check', jobs.blacklist_check],
                ['Protection Rules', 'protection_rules', jobs.protection_rules]
            ]
        },
        {
            title: 'System',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>',
            jobs: [
                ['Check App Version', 'check_app_version', jobs.check_app_version],
                ['Update MaxMind Databases', 'update_geoip', jobs.update_geoip]
            ]
        },
        {
            title: 'Live Logs',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>',
            jobs: [
                ['Fetch Raw Logs', 'fetch_raw_logs', jobs.fetch_raw_logs],
                ['Cleanup Raw Logs', 'cleanup_raw_logs', jobs.cleanup_raw_logs]
            ]
        },
        {
            title: 'Spam Filter',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z"></path>',
            jobs: [
                ['Detect Suppressions', 'detect_suppressions', jobs.detect_suppressions],
                ['Sync to Rspamd', 'sync_suppressions', jobs.sync_suppressions],
                ['Expire Suppressions', 'expire_suppressions', jobs.expire_suppressions],
                ['Cleanup Deferred Queue', 'cleanup_deferred_queue', jobs.cleanup_deferred_queue]
            ]
        },
        {
            title: 'Quarantine',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01"></path>',
            jobs: [
                ['Process Quarantine Rules', 'process_quarantine_rules', jobs.process_quarantine_rules]
            ]
        }
    ];
}

function renderStatusJobsTable(container, categories, jobs) {
    // Failed and switched-off jobs feed the attention list, the card and the filter
    const summary = summarizeJobs(jobs);
    const all = summary.all;
    const isOff = summary.isOff;
    statusState.jobs = all.map(([name, key, job]) => ({ name, key, failed: !isOff(job) && job.status === 'failed', error: job.error || '' }));
    const failed = summary.failed.length;
    const off = summary.off;
    setStatusKpi('status-kpi-jobs', `${all.length - failed - off} of ${all.length - off} healthy`, failed ? 'fail' : '');
    const jobsNote = [failed ? `${failed} failed` : 'None failed', off ? `${off} off because a feature or setting is off` : ''].filter(Boolean).join(', ');
    const kpiNote = document.getElementById('status-kpi-jobs-note');
    if (kpiNote) kpiNote.textContent = jobsNote;
    const jobsSummary = document.getElementById('status-jobs-summary');
    if (jobsSummary) jobsSummary.textContent = `${all.length} jobs, ${jobsNote.charAt(0).toLowerCase()}${jobsNote.slice(1)}`;
    setStatusTabCount('jobs', failed, true);

    const isFailed = job => !isOff(job) && job.status === 'failed';
    const chevron = '<svg class="ui-collapse-chevron" width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>';
    let html = '';
    for (const cat of categories) {
        // Skip categories where no jobs exist
        const validJobs = cat.jobs.filter(j => j[2]);
        if (validJobs.length === 0) continue;
        const catFailed = validJobs.filter(j => isFailed(j[2])).length;
        const catOff = validJobs.filter(j => isOff(j[2])).length;
        const note = [catFailed ? `<span class="ui-text-fail">${catFailed} failed</span>` : 'all OK', catOff ? `${catOff} off` : ''].filter(Boolean).join(' · ');
        // A group with a failure opens by itself; the others keep what the user chose
        const open = catFailed > 0 || statusJobsOpen.has(cat.title);
        html += `
            <details class="ui-panel ui-collapse ui-jg" data-group="${escapeHtml(cat.title)}"${catFailed ? ' data-failed' : ''}${open ? ' open' : ''} ontoggle="statusJobGroupToggled(this)">
                <summary class="ui-panel-head">${escapeHtml(cat.title)} <span class="ui-count">${validJobs.length} ${validJobs.length === 1 ? 'job' : 'jobs'} · ${note}</span>${chevron}</summary>
                <div class="ui-jg-body">${validJobs.map(j => renderJobCard(j[0], j[1], j[2])).join('')}</div>
            </details>`;
    }
    container.innerHTML = `<div class="ui-jgs">${html}</div>`;
    statusJobFilter(statusJobFilterValue);
    renderStatusAttention();
}

// Which job groups the user opened, so a refresh keeps them open
const statusJobsOpen = new Set();
function statusJobGroupToggled(el) {
    // Only an unfiltered view records the choice; a filter opens groups by itself
    if (statusJobFilterValue !== 'all') return;
    if (el.open) statusJobsOpen.add(el.dataset.group); else statusJobsOpen.delete(el.dataset.group);
}

async function triggerBackgroundJob(jobKey, buttonEl, jobName = null) {
    if (!buttonEl) return;

    // Use jobName if provided, otherwise fallback to jobKey
    const displayName = jobName || jobKey;

    // Disable button and show loading
    buttonEl.disabled = true;
    const originalContent = buttonEl.innerHTML;
    // Keep width to prevent layout shift if possible, or just standard loading state
    buttonEl.innerHTML = '<span class="inline-block animate-spin w-3 h-3 border-2 border-current border-t-transparent rounded-full"></span> Running...';
    buttonEl.classList.add('opacity-50', 'cursor-not-allowed');

    try {
        const response = await authenticatedFetch(`/api/settings/jobs/${jobKey}/run`, {
            method: 'POST'
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || `HTTP ${response.status}`);
        }

        showToast(`Job "${displayName}" started successfully`, 'success');

        // Refresh the status page after a short delay
        setTimeout(() => {
            loadStatusExtended();
        }, 1000);

    } catch (error) {
        if (error.message.includes('409')) {
            showToast(`Job "${displayName}" is already running`, 'warning');
        } else {
            console.error(`Failed to trigger job ${jobKey}:`, error); // nosemgrep: javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring
            showToast(`Failed to start job: ${error.message}`, 'error');
        }
    } finally {
        // Re-enable button
        buttonEl.disabled = false;
        buttonEl.innerHTML = originalContent;
        buttonEl.classList.remove('opacity-50', 'cursor-not-allowed');
    }
}

// =============================================================================
// POSTFIX DETAILS MODAL
// =============================================================================

function showChangelogModal(changelog) {
    const modal = document.getElementById('changelog-modal');
    const modalTitle = modal?.querySelector('h3');
    const content = document.getElementById('changelog-content');

    if (modal && content) {
        if (modalTitle) {
            modalTitle.textContent = 'Changelog';
        }
        if (typeof marked !== 'undefined' && changelog) {
            marked.setOptions({
                breaks: true,
                gfm: true
            });
            content.innerHTML = renderMarkdown(changelog);
        } else {
            content.textContent = changelog || 'No changelog available';
        }
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    }
}

function closeChangelogModal() {
    const modal = document.getElementById('changelog-modal');
    if (modal) {
        modal.classList.add('hidden');
        document.body.style.overflow = '';
        const modalTitle = modal.querySelector('h3');
        if (modalTitle) {
            modalTitle.textContent = 'Changelog';
        }
    }
}

// =============================================================================
// GEOIP RENDERING AND FLAGS
// =============================================================================

function getFlagUrl(countryCode, size = '24x18') {
    if (!countryCode || countryCode.length !== 2) {
        return null;
    }
    return `/static/assets/flags/${size}/${countryCode.toLowerCase()}.png`;
}

function renderGeoIPInfo(rspamdData, size = '24x18') {
    if (!rspamdData || !rspamdData.ip) {
        return '';
    }

    const ip = rspamdData.ip;
    const hasGeoIP = rspamdData.country_code;

    if (!hasGeoIP) {
        return `<p>Source IP: ${copyableText(ip)}</p>`;
    }

    const flagUrl = getFlagUrl(rspamdData.country_code, size);
    const [width, height] = size.split('x').map(Number);

    // Use a list to store the parts of the info string
    let parts = [`<strong>${copyableText(ip)}</strong>`];

    if (rspamdData.country_name && flagUrl) {
        // Wrap image and country name in a span to keep them together and aligned
        const countryPart =
            `<br><span style="display: inline-flex; align-items: baseline; gap: 4px; vertical-align: baseline; margin-top: 5px;">` +
            `<img src="${flagUrl}" alt="${escapeHtml(rspamdData.country_name)}" ` +
            `style="width:${width}px; height:${height}px; display: block;" ` +
            `onerror="this.style.display='none'">` +
            `${escapeHtml(rspamdData.country_name)}` +
            `</span>`;
        parts.push(countryPart);
    }

    if (rspamdData.city) {
        parts.push(escapeHtml(rspamdData.city));
    }

    if (rspamdData.asn_org) {
        parts.push(`(${escapeHtml(rspamdData.asn_org)})`);
    }

    // Use white-space: nowrap on the container if you want to prevent the whole line from breaking
    return `<p style="margin: 0;">Source: ${parts.join(' ')}</p>`;
}

function renderGeoIPForDMARC(record, size = '24x18') {
    if (!record || !record.source_ip) {
        return '';
    }

    const ip = record.source_ip;
    const hasGeoIP = record.country_code;

    if (!hasGeoIP) {
        return escapeHtml(ip);
    }

    // Build flag URL
    const flagUrl = getFlagUrl(record.country_code, size);
    const [width, height] = size.split('x').map(Number);

    // Build location string
    let parts = [];

    if (record.country_name) {
        parts.push(escapeHtml(record.country_name));
    }

    if (record.city) {
        parts.push(escapeHtml(record.city));
    }

    if (record.asn_org) {
        parts.push(escapeHtml(record.asn_org));
    }

    const locationText = parts.join(', ');

    // Return flag + location inline
    if (flagUrl && locationText) {
        return `<img src="${flagUrl}" alt="${escapeHtml(record.country_name || '')}" style="width:${width}px; height:${height}px; vertical-align:middle; margin-right:4px;" onerror="this.style.display='none'">${locationText}`;
    }

    return locationText || escapeHtml(ip);
}


// =============================================================================
// PAGINATION & HELPER FUNCTIONS
// =============================================================================

function renderPagination(type, currentPage, totalPages) {
    if (totalPages <= 1) return '';

    return `
        <div class="ui-pagination">
            <button onclick="loadLogs('${type}', ${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''} class="ui-btn">
                Previous
            </button>
            <span class="ui-muted">Page ${currentPage} of ${totalPages}</span>
            <button onclick="loadLogs('${type}', ${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''} class="ui-btn">
                Next
            </button>
        </div>
    `;
}

function loadLogs(type, page) {
    currentPage[type] = page;
    switch (type) {
        case 'messages':
            loadMessages(page);
            break;
        case 'netfilter':
            loadNetfilterLogs(page);
            break;
    }
}

// =============================================================================
// DARK MODE
// =============================================================================

function initDarkMode() {
    const theme = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

    if (theme === 'dark' || (!theme && prefersDark)) {
        document.documentElement.classList.add('dark');
        document.getElementById('theme-toggle-light-icon').classList.remove('hidden');
    } else {
        document.documentElement.classList.remove('dark');
        document.getElementById('theme-toggle-dark-icon').classList.remove('hidden');
    }
}

function toggleDarkMode() {
    document.documentElement.classList.toggle('dark');
    const isDark = document.documentElement.classList.contains('dark');
    localStorage.setItem('theme', isDark ? 'dark' : 'light');

    document.getElementById('theme-toggle-dark-icon').classList.toggle('hidden');
    document.getElementById('theme-toggle-light-icon').classList.toggle('hidden');
}

// Initialize dark mode
initDarkMode();

// =============================================================================
// MODAL EVENT LISTENERS
// =============================================================================

document.addEventListener('DOMContentLoaded', function () {
    // ESC key to close modal
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            const changelogModal = document.getElementById('changelog-modal');
            if (changelogModal && !changelogModal.classList.contains('hidden')) {
                closeChangelogModal();
            }
        }
    });

    // Changelog modal event listeners
    const changelogModal = document.getElementById('changelog-modal');
    if (changelogModal) {
        changelogModal.addEventListener('click', function (e) {
            if (e.target.id === 'changelog-modal') {
                closeChangelogModal();
            }
        });

        const changelogContent = changelogModal.querySelector('.bg-white, .dark\\:bg-gray-800');
        if (changelogContent) {
            changelogContent.addEventListener('click', function (e) {
                e.stopPropagation();
            });
        }
    }
});

// =============================================================================
// HELP DOCUMENTATION MODAL
// =============================================================================

async function showHelpModal(docName) {
    try {
        const response = await authenticatedFetch(`/api/docs/${docName}`);

        if (!response.ok) {
            throw new Error(`Failed to load documentation: ${response.statusText}`);
        }

        const markdown = await response.text();
        showMarkdownModal(`Help - ${docName}`, markdown);

    } catch (error) {
        console.error('Failed to load help documentation:', error);
        if (uiIsPhone()) {
            uiSheetShow('markdown-sheet', { label: 'Help', head: '<h3 class="ui-sheet-title">Help</h3>',
                body: '<p class="ui-text-fail">Failed to load help documentation. Please try again later.</p>' });
            return;
        }

        const modal = document.getElementById('changelog-modal');
        const modalTitle = modal?.querySelector('h3');
        const content = document.getElementById('changelog-content');

        if (modal && content) {
            if (modalTitle) {
                modalTitle.textContent = 'Help';
            }
            content.innerHTML = '<p class="text-red-500">Failed to load help documentation. Please try again later.</p>';
            modal.classList.remove('hidden');
            document.body.style.overflow = 'hidden';
        }
    }
}

// =============================================================================
// CONSOLE LOG
// =============================================================================

console.log('[OK] mailcow Logs Viewer - Complete Frontend Loaded');
console.log('Features: Dashboard, Messages, Postfix, Rspamd, Netfilter, Queue, Quarantine, Status, Mailbox Stats, Settings');
console.log('UI: Dark mode, Modals with tabs, Responsive design');

// =============================================================================
// CONTAINER LOGS MODAL
// =============================================================================

let containerLogsInterval = null;

async function fetchContainerLogs(silent = false) {
    const content = document.getElementById('container-logs-content');

    if (content && !silent) {
        content.textContent = 'Loading logs...';
    }

    try {
        const response = await authenticatedFetch('/api/status/container-logs?lines=500');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        if (content && data.logs) {
            const isScrolledToBottom = content.parentElement
                ? (content.parentElement.scrollHeight - content.parentElement.scrollTop === content.parentElement.clientHeight)
                : true;

            if (data.logs.length === 0) {
                if (!silent) content.textContent = 'No logs available.';
            } else {
                content.textContent = data.logs.join('');
            }

            // Auto-scroll to bottom if it was already at bottom or if it's the first load
            if (!silent || isScrolledToBottom) {
                const container = content.parentElement;
                if (container) {
                    container.scrollTop = container.scrollHeight;
                }
            }
        }
    } catch (error) {
        console.error('Failed to load container logs:', error);
        if (content && !silent) {
            content.textContent = `Failed to load logs: ${error.message}`;
        }
    }
}

function loadContainerLogs() {
    const modal = document.getElementById('container-logs-modal');

    if (modal) {
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    }

    // Initial load
    fetchContainerLogs(false);

    // Clear existing interval just in case
    if (containerLogsInterval) clearInterval(containerLogsInterval);

    // Set auto-refresh every 2 seconds
    containerLogsInterval = setInterval(() => {
        fetchContainerLogs(true);
    }, 2000);
}

function closeContainerLogsModal() {
    const modal = document.getElementById('container-logs-modal');
    if (modal) {
        modal.classList.add('hidden');
        document.body.style.overflow = '';
    }

    // Stop auto-refresh
    if (containerLogsInterval) {
        clearInterval(containerLogsInterval);
        containerLogsInterval = null;
    }
}

function loadMailboxStatsPage(page) {
    loadMailboxStatsList(page);
}

// =============================================================================
// Sidebar sub-pages: hovering or focusing a page with tabs shows its tabs next
// to it. The items come from the page's own tab buttons, so a tab hidden by a
// switched-off feature is not offered.
// =============================================================================

const NAV_SUBPAGE_TABS = {
    quarantine: '#quarantine-tabs:not(.hidden)',
    netfilter: '.ui-se-tabs',
    'spam-filter': '#content-spam-filter .ui-page-tabs',
    status: '.ui-st-tabs',
    'mailbox-stats': '#mailbox-stats-views',
    dmarc: '#dmarc-page-tabs'
};
let navFlyout = null;
let navFlyoutTimer = null;

function navSubpageTabs(page) {
    const list = document.querySelector(NAV_SUBPAGE_TABS[page]);
    if (!list) return [];
    return [...list.querySelectorAll('[role="tab"]')].filter(btn => !btn.hidden && !btn.classList.contains('hidden') && btn.style.display !== 'none');
}

function hideNavFlyout() {
    clearTimeout(navFlyoutTimer);
    if (navFlyout) navFlyout.classList.remove('is-open');
}

function showNavFlyout(item, page) {
    clearTimeout(navFlyoutTimer);
    const tabs = navSubpageTabs(page);
    if (tabs.length < 2) return hideNavFlyout();
    if (!navFlyout) {
        navFlyout = document.createElement('div');
        navFlyout.className = 'ui-fly';
        navFlyout.setAttribute('role', 'menu');
        navFlyout.addEventListener('mouseenter', () => clearTimeout(navFlyoutTimer));
        navFlyout.addEventListener('mouseleave', () => { navFlyoutTimer = setTimeout(hideNavFlyout, 150); });
        navFlyout.addEventListener('keydown', e => {
            const items = [...navFlyout.querySelectorAll('.ui-fly-item')];
            const i = items.indexOf(document.activeElement);
            if (e.key === 'ArrowDown') { e.preventDefault(); items[(i + 1) % items.length].focus(); }
            if (e.key === 'ArrowUp') { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); }
            if (e.key === 'Escape' || e.key === 'ArrowLeft') { e.preventDefault(); hideNavFlyout(); navFlyout.owner && navFlyout.owner.focus(); }
        });
        navFlyout.addEventListener('focusout', e => { if (!navFlyout.contains(e.relatedTarget)) hideNavFlyout(); });
        document.body.appendChild(navFlyout);
    }
    const onPage = item.getAttribute('aria-current') === 'page';
    const label = item.querySelector('.ui-nav-label');
    navFlyout.owner = item;
    navFlyout.innerHTML = `<div class="ui-fly-title">${escapeHtml(label ? label.textContent : page)}</div>` + tabs.map((btn, i) => {
        const copy = btn.cloneNode(true);
        const count = copy.querySelector('.ui-tab-n');
        const countText = count && !count.classList.contains('hidden') ? count.textContent.trim() : '';
        if (count) count.remove();
        const on = onPage && (btn.classList.contains('active') || btn.getAttribute('aria-selected') === 'true');
        return `<button type="button" role="menuitem" class="ui-fly-item${on ? ' is-on' : ''}" data-i="${i}">
            <span>${copy.innerHTML.trim()}</span>${countText ? `<small class="ui-nav-count${count.classList.contains('is-fail') ? ' is-fail' : ''}">${escapeHtml(countText)}</small>` : ''}</button>`;
    }).join('');
    navFlyout.querySelectorAll('.ui-fly-item').forEach(el => el.addEventListener('click', () => {
        // The tab first, so the page opens on it; a tab that navigates by itself needs nothing more
        tabs[Number(el.dataset.i)].click();
        hideNavFlyout();
        if (currentTab !== page) navigateTo(page);
    }));
    const rect = item.getBoundingClientRect();
    navFlyout.style.top = `${Math.max(8, Math.min(rect.top - 6, window.innerHeight - navFlyout.offsetHeight - 8))}px`;
    navFlyout.style.left = `${rect.right + 8}px`;
    navFlyout.classList.add('is-open');
    navFlyout.style.top = `${Math.max(8, Math.min(rect.top - 6, window.innerHeight - navFlyout.offsetHeight - 8))}px`;
}

function initNavFlyouts() {
    Object.keys(NAV_SUBPAGE_TABS).forEach(page => {
        const item = document.getElementById(`tab-${page}`);
        if (!item) return;
        item.classList.toggle('has-sub', navSubpageTabs(page).length > 1);
        item.setAttribute('aria-haspopup', 'menu');
        item.addEventListener('mouseenter', () => showNavFlyout(item, page));
        item.addEventListener('mouseleave', () => { navFlyoutTimer = setTimeout(hideNavFlyout, 150); });
        item.addEventListener('focus', () => showNavFlyout(item, page));
        item.addEventListener('blur', e => { if (!navFlyout || !navFlyout.contains(e.relatedTarget)) navFlyoutTimer = setTimeout(hideNavFlyout, 150); });
        item.addEventListener('click', hideNavFlyout);
        item.addEventListener('keydown', e => {
            if (e.key !== 'ArrowRight') return;
            e.preventDefault();
            showNavFlyout(item, page);
            const first = navFlyout && navFlyout.querySelector('.ui-fly-item');
            if (first) first.focus();
        });
    });
    window.addEventListener('resize', hideNavFlyout);
}
document.addEventListener('DOMContentLoaded', initNavFlyouts);

// =============================================================================
// The app frame never scrolls the window. A phone keyboard can pan the window to
// show a field and leave it panned when it closes, which hid the top bar and left
// an empty band at the bottom on every page. Once no field is being edited, the
// window goes back to the top.
// =============================================================================

function resetWindowPan() {
    const el = document.activeElement;
    const editing = el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName));
    if (editing) return;
    if (window.scrollX || window.scrollY || document.scrollingElement.scrollTop) window.scrollTo(0, 0);
}
window.addEventListener('scroll', resetWindowPan, { passive: true });
document.addEventListener('focusout', () => setTimeout(resetWindowPan, 300));
if (window.visualViewport) window.visualViewport.addEventListener('resize', () => setTimeout(resetWindowPan, 100));

// =============================================================================
// The desktop sidebar folds into the icon rail and stays that way next time.
// The class is set in the page head before it draws; this only toggles it.
// =============================================================================

function syncNavToggle() {
    const collapsed = document.documentElement.classList.contains('ui-nav-collapsed');
    const btn = document.getElementById('ui-nav-toggle');
    if (!btn) return;
    const label = collapsed ? 'Expand menu' : 'Collapse menu';
    btn.setAttribute('aria-label', label);
    btn.title = label;
    btn.setAttribute('aria-expanded', String(!collapsed));
}

function toggleNavCollapsed() {
    const collapsed = document.documentElement.classList.toggle('ui-nav-collapsed');
    try { localStorage.setItem('navCollapsed', collapsed ? '1' : '0'); } catch (e) { /* private mode: it just is not remembered */ }
    if (typeof hideNavFlyout === 'function') hideNavFlyout();
    syncNavToggle();
}
document.addEventListener('DOMContentLoaded', syncNavToggle);
