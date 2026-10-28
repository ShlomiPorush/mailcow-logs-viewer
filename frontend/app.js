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
 * @param {string} options.ip - Source IP to filter by
 * @param {string} options.address - From or to this address, matched whole (it has no field of its own)
 * @param {string} options.domain - From or to an address on this domain (the part after the last @)
 * @param {boolean} options.exact - Match the email and the IP whole, not as a part (the entity card)
 * @param {string} options.datePreset - A time preset ('today', '7days', '30days', '90days'), or
 * @param {string} options.start - with options.end, an exact range (ISO instants, the end inclusive)
 * @returns {Promise<boolean>} whether the Messages page opened
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
        } else if (options.filterType === 'user') {
            // The mailbox that logged in, whichever address or alias it sent from
            if (filterUser) filterUser.value = options.email;
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

    if (options.ip && filterIp) filterIp.value = options.ip;

    // Whole values (the entity card): the fields set here, and an address or a
    // domain, which have no field. A filter changed later drops them (applyMessagesFilters)
    const field = el => (el ? el.value : '');
    messagesExact = options.exact || options.address || options.domain ? {
        sender: options.exact ? field(filterSender) : '', recipient: options.exact ? field(filterRecipient) : '',
        user: options.exact ? field(filterUser) : '', ip: options.exact ? field(filterIp) : '',
        address: options.address || '', domain: options.domain || '',
    } : null;

    // The period, when one is given: a preset up to now, or an exact range
    if (options.datePreset && MESSAGES_ROLLING_PRESETS.includes(options.datePreset)) messagesShowDatePreset(options.datePreset);
    else if (options.start && options.end) messagesShowRange(options.start, options.end);

    // Navigate to Messages tab
    return navigateTo('messages').then(moved => {
        // Apply filters after navigation
        if (moved) setTimeout(() => { if (typeof applyMessagesFilters === 'function') applyMessagesFilters(); }, 100);
        return moved;
    });
}

// =============================================================================
// AUTHENTICATION SYSTEM
// =============================================================================

// DMARC imap
let dmarcImapStatus = null;
let dmarcConfiguration = null;

// Send the browser to the login page, dropping any client-side state; signing
// in again returns to the page that was open. reason: why the server ended the
// session (session_idle, session_expired), which the login page explains; the
// address is built by session-guard.js (sessionGuardLoginPath)
function redirectToLogin(reason) {
    if (typeof uiUnsavedClear === 'function') uiUnsavedClear();
    const here = window.location.pathname + window.location.search;
    window.location.replace(typeof sessionGuardLoginPath === 'function' ? sessionGuardLoginPath(reason, here)
        : here === '/' ? '/login' : `/login?next=${encodeURIComponent(here)}`);
}

// Why the server ended the session, from a 401 (session-guard.js); '' when it gave no reason
async function loginReasonOf(response) {
    return typeof sessionGuardReasonOf === 'function' ? sessionGuardReasonOf(response) : '';
}

// Enhanced fetch with authentication.
// Both login methods (OAuth2 and Basic Auth) end up with the same HttpOnly
// session cookie, which the browser attaches automatically. No credential is
// held in JavaScript, so an XSS in the page has nothing to read.
// timeout (ms, for the pages' own refreshes): a request that has not answered by
// then, its body included, is aborted, so it neither holds the next refresh nor
// answers after it
async function authenticatedFetch(url, options = {}) {
    const { timeout, ...rest } = options;
    const headers = {
        ...rest.headers,
    };
    let timer = null;
    if (timeout && typeof AbortController === 'function') {
        const control = new AbortController();
        const outer = rest.signal;
        if (outer) {
            if (outer.aborted) control.abort();
            else outer.addEventListener('abort', () => control.abort(), { once: true });
        }
        timer = setTimeout(() => control.abort(), timeout);
        rest.signal = control.signal;
    }

    try {
        const response = await fetch(url, {
            ...rest,
            headers,
            credentials: 'include' // Send the session cookie
        });

        // Handle 401 Unauthorized - the session ended (a limit, which the login
        // page explains) or the server restarted
        if (response.status === 401) {
            redirectToLogin(await loginReasonOf(response));
            throw new Error('Authentication required');
        }

        // The timer stays to the end of the body (reading it is part of the request);
        // after that its abort does nothing
        return response;
    } catch (error) {
        clearTimeout(timer);
        throw error;
    }
}

// The reason the server gave for a failed request (FastAPI's `detail`), or its status
async function responseError(response) {
    let detail = '';
    try {
        detail = (await response.json()).detail;
    } catch (e) {
        // not JSON
    }
    return new Error(typeof detail === 'string' && detail ? detail : `HTTP ${response.status}`);
}

// Handle logout - one path for both login methods, since both are backed by
// the same server-side session. POST only: a GET that logs out could be
// triggered by any other site.
async function handleLogout() {
    // Changes not saved yet: ask now, while Stay still leaves a working session
    if (typeof uiConfirmLeave === 'function' && !(await uiConfirmLeave(undefined, { keep: true }))) return;
    try {
        const response = await authenticatedFetch('/api/auth/logout', { method: 'POST' });
        if (!response.ok) {
            showToast('Could not sign out. Try again in a moment.', 'error');
            return;
        }
    } catch (e) {
        // A 401 means the session is already gone; authenticatedFetch has
        // sent the browser to the login page. Otherwise nothing changed, and
        // the changes are still guarded.
        return;
    }
    if (typeof uiUnsavedClear === 'function') uiUnsavedClear();
    window.location.href = '/login';
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

    // A session a limit ended says so, in the header or the body, whatever the status
    let reason = '';
    try {
        const statusResponse = await fetch('/api/auth/status', { credentials: 'include' });
        if (statusResponse.ok) {
            const statusData = await statusResponse.json();
            if (statusData.authenticated) {
                const logoutBtn = document.getElementById('logout-btn');
                if (logoutBtn) logoutBtn.classList.remove('hidden');
                return true;
            }
            reason = statusData.reason;
        } else if (statusResponse.status === 401) {
            reason = await loginReasonOf(statusResponse);
        }
    } catch (e) {
        // Could not reach the status endpoint - treat as not authenticated
    }

    redirectToLogin(reason);
    return false;
}

// =============================================================================
// EXISTING CODE CONTINUES...
// =============================================================================

// Global state
let currentTab = 'dashboard';
let appTimezone = 'UTC'; // The app's time zone (utils.js appTz), from /api/info
// Whether the configured TZ is a known zone, and the name as configured ('' when unset)
let appTimezoneStatus = { valid: true, configured: '' };
// How dates and times are written (utils.js appDateFmt, appTimeFmt), from /api/info
let appDateFormat = 'browser';
let appTimeFormat = '24h';
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
// The first RW status check; Queue and Quarantine wait for it before drawing their rows
let rwStatusReady = Promise.resolve();

// Feature toggles - features in this list are disabled (hidden from UI, jobs stopped)
window.disabledFeatures = [];

// All toggleable feature definitions (for settings UI)
const TOGGLEABLE_FEATURES = [
    { id: 'netfilter', label: 'Security', description: 'Fail2Ban management and security events' },
    { id: 'queue', label: 'Queue', description: 'Outbound > Queue: mail waiting in the Postfix queue' },
    { id: 'suppressions', label: 'Suppressions', description: 'Outbound > Suppressions: recipients blocked after failed delivery' },
    { id: 'quarantine', label: 'Quarantine', description: 'Quarantined emails and auto-rules' },
    { id: 'rspamd', label: 'Rspamd', description: 'The Rspamd maps that allow or block mail, incoming and outgoing' },
    { id: 'domains', label: 'Domains', description: 'Domain DNS analysis and transports' },
    { id: 'dmarc', label: 'DMARC & TLS', description: 'DMARC/TLS reports and IMAP sync' },
    { id: 'mailbox-stats', label: 'Mailbox Stats', description: 'Mailbox and alias statistics' },
    { id: 'rate-limits', label: 'Rate Limits', description: 'Sender rate limit hits and the configured limits' },
    { id: 'devices', label: 'Devices', description: 'ActiveSync phones and tablets, read from the SOGo log' },
    { id: 'logs', label: 'Logs', description: 'Raw service log viewer' },
    { id: 'blacklist', label: 'IP Blacklist Monitor', description: 'DNS blacklist monitoring for your IPs' },
];

function isFeatureDisabled(featureId) {
    return window.disabledFeatures.includes(featureId);
}

// Pages whose tabs belong to different features: tab -> feature. A tab whose
// feature is off is hidden, and the page goes only when all of them are off.
const TAB_FEATURES = {
    outbound: { queue: 'queue', suppressions: 'suppressions' }
};

function tabFeatureOn(page, tab) {
    const feature = TAB_FEATURES[page] && TAB_FEATURES[page][tab];
    return !feature || !isFeatureDisabled(feature);
}

// The tab asked for while its feature is on, otherwise the first one that is on
function pageTabOn(page, tab) {
    const tabs = Object.keys(TAB_FEATURES[page]);
    return tabs.includes(tab) && tabFeatureOn(page, tab) ? tab : (tabs.find(t => tabFeatureOn(page, t)) || tabs[0]);
}

function pageAllOff(page) {
    return !Object.keys(TAB_FEATURES[page]).some(tab => tabFeatureOn(page, tab));
}

// A page shows "is disabled" while its features are off. The Mailbox Stats
// page also hosts Rate Limits, so it stays open while that feature is on.
function pageIsOff(page) {
    if (TAB_FEATURES[page]) return pageAllOff(page);
    if (page === 'mailbox-stats' && !isFeatureDisabled('rate-limits')) return false;
    return isFeatureDisabled(page);
}

// Hide the tabs of features that are off; a page with one tab left shows no tab bar
function applyTabFeatures(page) {
    const prefix = `${page}-tab-btn-`;
    let shown = 0;
    for (const tab of Object.keys(TAB_FEATURES[page])) {
        const btn = document.getElementById(prefix + tab);
        const on = tabFeatureOn(page, tab);
        if (btn) btn.classList.toggle('hidden', !on);
        if (on) shown++;
    }
    const bar = document.getElementById(`${page}-tabs`);
    if (bar) bar.classList.toggle('hidden', shown < 2);
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
    // Suppressions can open the map they are written to while the Rspamd page is on
    const openMap = document.getElementById('suppression-open-map');
    if (openMap) openMap.style.display = isFeatureDisabled('rspamd') ? 'none' : '';

    // Outbound stays while one of its features is on
    for (const page of Object.keys(TAB_FEATURES)) {
        for (const id of [`tab-${page}`, `mobile-tab-${page}`, `tabbar-${page}`]) {
            const el = document.getElementById(id);
            if (el) el.style.display = pageAllOff(page) ? 'none' : '';
        }
        applyTabFeatures(page);
    }
    // A tab that just went is not left open: the page shows its first tab that is on
    if (typeof outboundTab !== 'undefined' && outboundTab !== pageTabOn('outbound', outboundTab)) {
        if (currentTab === 'outbound' && !pageAllOff('outbound')) outboundShowTab(outboundTab);
        else outboundTab = pageTabOn('outbound', outboundTab);
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
    // Same for the Queue and Quarantine rows and their actions
    if (currentTab === 'outbound' && allQueueData.length) applyQueueFilters();
    if (currentTab === 'quarantine' && quarantineLastData) renderQuarantineData(quarantineLastData);
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
        'content-outbound',
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
    rwStatusReady = fetchRwStatus().catch(() => {});

    // Initialize router and get initial route from URL
    const routeInfo = typeof initRouter === 'function' ? initRouter() : { baseRoute: 'dashboard', params: {} };
    const initialTab = routeInfo.baseRoute || routeInfo;
    const initialParams = routeInfo.params || {};
    console.log('Initial tab from URL:', initialTab, 'params:', initialParams);

    // Load the initial tab (use switchTab to ensure proper initialization)
    switchTab(initialTab, initialParams);

    // The open page refreshes itself from now on
    startPageRefresh();

    console.log('=== Initialization Complete ===');
});

// =============================================================================
// APP INFO & VERSION
// =============================================================================

// The authentication-off banner can be dismissed for good in this browser: a
// reverse proxy in front of the app may already sign users in.
const AUTH_OFF_BANNER_DISMISSED_KEY = 'authOffBannerDismissed';

function authOffBannerDismissed() {
    try { return localStorage.getItem(AUTH_OFF_BANNER_DISMISSED_KEY) === '1'; } catch (e) { return false; }
}

function dismissAuthOffBanner() {
    try { localStorage.setItem(AUTH_OFF_BANNER_DISMISSED_KEY, '1'); } catch (e) { /* private mode: it just is not remembered */ }
    const banner = document.getElementById('auth-off-banner');
    if (banner) banner.classList.add('hidden');
}

// The zone every time follows (/api/info `timezone`). The server sends only a
// known zone; one this browser cannot use would make every time throw, so UTC.
function setAppTimezone(info) {
    let zone = (info && info.timezone) || 'UTC';
    try {
        new Intl.DateTimeFormat('en-US', { timeZone: zone });
    } catch (e) {
        console.warn('Unknown time zone from the server, using UTC:', zone);
        zone = 'UTC';
    }
    appTimezone = zone;
    appTimezoneStatus = {
        valid: !info || info.timezone_valid !== false,
        configured: (info && typeof info.timezone_configured === 'string') ? info.timezone_configured : '',
    };
    // utils.js falls back to the defaults for a value it does not know
    if (info && typeof info.date_format === 'string') appDateFormat = info.date_format;
    if (info && typeof info.time_format === 'string') appTimeFormat = info.time_format;
}

// The browser tab names the page and its open tab: "Mailbox Stats · Rate Limits · mailcow Logs Viewer"
let appTitleText = document.title;
let documentTitleQueued = false;
function queueDocumentTitle() {
    if (documentTitleQueued) return;
    documentTitleQueued = true;
    requestAnimationFrame(() => {
        documentTitleQueued = false;
        if (typeof currentTab === 'undefined' || !currentTab) return;
        const name = TAB_LABELS[currentTab] || currentTab;
        const sub = topbarSubLabel(currentTab);
        document.title = [name, sub && sub !== name ? sub : '', appTitleText].filter(Boolean).join(' · ');
    });
}

async function loadAppInfo() {
    try {
        // Use regular fetch since this is called after authentication check
        const response = await authenticatedFetch('/api/info');
        const data = await response.json();

        if (data.app_title) {
            document.getElementById('app-title').textContent = data.app_title;
            appTitleText = data.app_title;
            queueDocumentTitle();
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

        // Without any sign-in, everyone who reaches the app has full access: say so
        // on the Dashboard. Only an explicit false shows it, never a missing field.
        const authOffBanner = document.getElementById('auth-off-banner');
        if (authOffBanner) authOffBanner.classList.toggle('hidden', data.auth_enabled !== false || authOffBannerDismissed());

        setAppTimezone(data);

        // Load disabled features and apply tab hiding
        if (data.disabled_features && Array.isArray(data.disabled_features)) {
            window.disabledFeatures = data.disabled_features;
            console.log('Disabled features:', window.disabledFeatures);
            applyFeatureToggles();
        }
        // With editing off the Settings page has no fields for the search to open
        window.settingsEditable = data.settings_edit_via_ui_enabled !== false;

        // The update check asks GitHub and the connection check asks mailcow, which
        // takes its whole timeout when it cannot be reached: the page the address
        // names opens without waiting for either
        loadAppVersionStatus();
        const connectionChecked = loadMailcowConnectionStatus();

        // Sidebar counters and server card
        placeShellUtilities();
        window.matchMedia('(max-width: 760px)').addEventListener('change', placeShellUtilities);
        window.matchMedia('(max-width: 760px)').addEventListener('change', () => placeTopbar());
        watchTopbarCrumbs();
        // The Status counter counts a mailcow that is not connected
        connectionChecked.then(startNavCounters);
        // Needs attention, for the Dashboard and the bell on every page
        startAttention();
    } catch (error) {
        console.error('Failed to load app info:', error);
    }
}

// =============================================================================
// SIDEBAR: SERVER CARD, COUNTERS AND TOOLS
// =============================================================================

// The theme and logout buttons live in the sidebar foot; on phones, where the
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

// =============================================================================
// WIDE SCREENS: THE TOP BAR
// =============================================================================
// One bar runs across the top: the app's name with the menu toggle, the page's
// title and the page's actions. They are the page's own elements, moved up while
// the page is open and put back when it is left, so every id, button and listener
// stays as it was. Under the bar the page starts with breadcrumbs, then its
// description. Messages keeps its own layout and has no bar; phones keep theirs.
const TOPBAR_SKIP = new Set(['messages']);
let topbarMoves = [];     // [element, placeholder] pairs, to put back in reverse
let topbarRoute = null;

function topbarMove(el, target) {
    if (!el || !target) return;
    const mark = document.createComment('topbar');
    el.replaceWith(mark);
    target.appendChild(el);
    topbarMoves.push([el, mark]);
}

function topbarRestore() {
    for (const [el, mark] of topbarMoves.reverse()) mark.replaceWith(el);
    topbarMoves = [];
    document.querySelectorAll('.ui-page-crumbs, .ui-head-slot, .ui-head-links').forEach(el => el.remove());
}

function placeTopbar(route = topbarRoute) {
    topbarRoute = route;
    const bar = document.getElementById('ui-topbar');
    if (!bar) return;
    topbarRestore();
    const page = route ? document.getElementById(`content-${route}`) : null;
    const head = page ? page.querySelector('.ui-page-head') : null;
    const intro = head ? head.firstElementChild : null;
    const title = intro ? intro.querySelector('.ui-h1') : null;
    const on = !!title && !TOPBAR_SKIP.has(route) && !window.matchMedia('(max-width: 760px)').matches;
    document.documentElement.classList.toggle('ui-has-topbar', on);
    if (!on) {
        placeHeadPrimary(route, intro, title);
        return;
    }

    const brandSlot = document.getElementById('ui-topbar-brand');
    topbarMove(document.querySelector('.ui-sidenav .ui-brand'), brandSlot);
    topbarMove(document.getElementById('ui-nav-toggle'), brandSlot);
    const crumbs = document.createElement('nav');
    crumbs.className = 'ui-crumbs ui-page-crumbs';
    crumbs.setAttribute('aria-label', 'You are here');
    title.before(crumbs);
    topbarMove(title, document.getElementById('ui-topbar-title'));
    [...head.children].filter(el => el !== intro).forEach(el => topbarMove(el, document.getElementById('ui-topbar-actions')));
    // The DMARC sync note is too tall for the bar: it stays with the description
    if (route === 'dmarc') topbarMove(document.getElementById('dmarc-last-sync-info'), intro);
    updateTopbarCrumbs();
}

// Phones: the page's main action (Check Now, Fetch reports) sits on the title's line
function placeHeadPrimary(route, intro, title) {
    if (!title || !window.matchMedia('(max-width: 760px)').matches) return;
    const primary = intro.parentNode.querySelector('.ui-head-primary');
    if (!primary) return;
    const slot = document.createElement('span');
    slot.className = 'ui-head-slot';
    title.after(slot);
    topbarMove(primary, slot);
    // DMARC: the last fetch and Manage Reports share one line of links under the description
    if (route === 'dmarc') {
        const links = document.createElement('div');
        links.className = 'ui-head-links';
        intro.appendChild(links);
        ['dmarc-last-sync-info', 'dmarc-manage-btn'].forEach(id => topbarMove(document.getElementById(id), links));
        // Upload Report is an icon beside Fetch reports
        topbarMove(document.getElementById('dmarc-upload-btn'), slot);
    }
}

// The tab open on the page: Security's Overview, a Status tab, a Settings section
function topbarSubLabel(route) {
    const page = document.getElementById(`content-${route}`);
    const tab = page && page.querySelector('[role="tab"][aria-selected="true"], [role="tab"].active, .settings-edit-nav [aria-current="true"]');
    if (!tab) return '';
    const label = tab.cloneNode(true);
    label.querySelectorAll('.ui-tab-n, .ui-count, .ui-nav-count, .hidden').forEach(n => n.remove());
    return label.textContent.replace(/\s+/g, ' ').trim();
}

// Something opened inside a tab (a Rspamd map, a DMARC domain or report) joins the
// crumbs, and the tab's crumb leads back to its list. A level in between that has an
// action ({ label, action }) leads back to it. It holds only while that tab is open.
let topbarPageCrumbs = null;   // { route, sub, back, labels: [label or { label, action }] }

function setPageCrumbs(route, sub, back, labels) {
    topbarPageCrumbs = labels && labels.length ? { route, sub, back, labels } : null;
    updateTopbarCrumbs();
}

function updateTopbarCrumbs() {
    queueDocumentTitle();
    const nav = document.querySelector('.ui-page-crumbs');
    if (!nav || !topbarRoute) return;
    const route = topbarRoute;
    const item = document.getElementById(`tab-${route}`);
    const group = item && item.closest('.ui-nav-group');
    const groupLabel = group && group.querySelector('.ui-nav-group-label');
    const name = TAB_LABELS[route] || route;
    const sub = topbarSubLabel(route);
    const parts = [];
    if (groupLabel) parts.push(`<span class="ui-crumb-group">${escapeHtml(groupLabel.textContent.trim())}</span>`);
    const inner = topbarPageCrumbs && topbarPageCrumbs.route === route && topbarPageCrumbs.sub === sub ? topbarPageCrumbs : null;
    // A page without tabs (DMARC & TLS) leads back from a level inside it by its name
    parts.push(sub ? `<button type="button" class="ui-crumb" onclick="topbarOpenPage('${escapeJsArg(route)}')">${escapeHtml(name)}</button>`
        : inner ? `<button type="button" class="ui-crumb" onclick="${inner.back}">${escapeHtml(name)}</button>`
        : `<span class="ui-crumb-current" aria-current="page">${escapeHtml(name)}</span>`);
    if (sub && sub !== name) {
        parts.push(inner ? `<button type="button" class="ui-crumb" onclick="${inner.back}">${escapeHtml(sub)}</button>`
            : `<span class="ui-crumb-current" aria-current="page">${escapeHtml(sub)}</span>`);
    }
    if (inner) {
        inner.labels.forEach((item, i) => {
            const label = typeof item === 'string' ? item : item.label;
            const action = typeof item === 'string' ? null : item.action;
            parts.push(i === inner.labels.length - 1 ? `<span class="ui-crumb-current" aria-current="page">${escapeHtml(label)}</span>`
                : action ? `<button type="button" class="ui-crumb" onclick="${escapeHtml(action)}">${escapeHtml(label)}</button>`
                : `<span class="ui-crumb-group">${escapeHtml(label)}</span>`);
        });
    }
    nav.innerHTML = parts.join('<span class="ui-crumb-sep" aria-hidden="true">›</span>');
}

// The page's name in the crumbs opens the page at its first tab
function topbarOpenPage(route) {
    if (typeof SUBPAGES !== 'undefined' && SUBPAGES[route]) navigateTo(route, { sub: subpageFirst(route) });
    else if (route === 'dmarc' && typeof dmarcOpenTab === 'function') dmarcOpenTab();
    else navigateTo(route);
}

// A tab opened on the page, by a click or by Back, changes the last crumb
function watchTopbarCrumbs() {
    const content = document.querySelector('.ui-content');
    if (!content || typeof MutationObserver === 'undefined') return;
    let queued = false;
    new MutationObserver(records => {
        if (queued || !records.some(r => r.target.matches && r.target.matches('[role="tab"], .settings-edit-tab'))) return;
        queued = true;
        requestAnimationFrame(() => { queued = false; updateTopbarCrumbs(); });
    }).observe(content, { subtree: true, attributes: true, attributeFilter: ['aria-selected', 'aria-current', 'class'] });
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
// The counters are read every five minutes; a hidden browser tab reads nothing
// and catches up when it is shown
const NAV_COUNTERS_EVERY = 5 * 60 * 1000;
let navCountersAt = 0;

let navCountersPending = false;
function navCountersTick() {
    if (navCountersPending || document.hidden || Date.now() - navCountersAt < NAV_COUNTERS_EVERY - 2000) return;
    // The connection is read again first, as at load: an open page shows mailcow
    // back without a reload, and the Status counter counts it. One read at a
    // time, however long it takes, so an older answer never lands after a newer one
    navCountersAt = Date.now();
    navCountersPending = true;
    loadMailcowConnectionStatus().finally(() => { navCountersPending = false; }).then(loadNavCounters);
}

function startNavCounters() {
    loadNavCounters();
    setInterval(navCountersTick, PAGE_REFRESH_TICK);
    document.addEventListener('visibilitychange', navCountersTick);
}

async function loadNavCounters() {
    navCountersAt = Date.now();
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
    setNavCount('outbound', queued, false, `${queued} messages in the queue`);
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
    // On a phone the header bell has these too, with the rest of Needs attention
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
                // Read again every few minutes: no tone of an earlier answer stays
                indicator.classList.remove('text-red-500', 'text-gray-400');
                indicator.classList.add('text-green-500');
                indicator.title = 'Connected to mailcow';
                // Update SVG to checkmark
                const svg = indicator.querySelector('svg');
                if (svg) {
                    svg.innerHTML = '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>';
                }
            } else {
                indicator.classList.remove('text-green-500', 'text-gray-400');
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
            indicator.classList.remove('text-green-500', 'text-red-500');
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
    let htmlContent = escapeHtml(markdownContent); // shown as text if marked is missing or fails
    try {
        if (typeof marked !== 'undefined') {
            marked.setOptions({
                breaks: true,
                gfm: true
            });
            htmlContent = renderMarkdown(markdownContent);
            // A link to another site opens in a new tab, so the app stays where it was
            const tpl = document.createElement('template');
            tpl.innerHTML = htmlContent;
            tpl.content.querySelectorAll('a[href^="http"]').forEach(a => {
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
            });
            htmlContent = tpl.innerHTML;
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
            expand: true,
            progress: true
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
        revealChangelogModal(modal);
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
// PAGE REFRESH - the open page reads its data again on its own
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

// Every page that changes by itself has a refresher: how often it runs (a
// number, or a function of the page's open tab) and what it reads. A tick every
// 30 seconds runs the open page's refresher when it is due and not already on
// its way; an answer that has not come in 20 seconds frees the next one. A
// hidden browser tab reads nothing and catches up when it is shown. Each
// refresher draws only what changed, and checks when its answer arrives that
// nobody is working in what it would redraw.
const PAGE_REFRESH_TICK = 30000;
const PAGE_REFRESH_TIMEOUT = 20000;
const pageRefreshers = {};
const pageRefreshState = { route: null, at: 0, timer: null };

function registerPageRefresh(route, every, run) {
    pageRefreshers[route] = { every, run, busy: false };
}

function pageRefreshEvery(refresher) {
    return typeof refresher.every === 'function' ? refresher.every() : refresher.every;
}

// The page was just loaded: its next refresh is a full cadence away
function pageRefreshLoaded(route) {
    pageRefreshState.route = route;
    pageRefreshState.at = Date.now();
}

// A load that failed: the next tick tries again, whatever the cadence
function pageRefreshRetry(route) {
    if (pageRefreshState.route === route) pageRefreshState.at = 0;
}

// The open page's refresher, now. Nothing for a page that is off, while a
// message dialog covers the page, or while the last run is still on its way
async function pageRefreshNow() {
    const route = currentTab;
    const refresher = pageRefreshers[route];
    if (!refresher || refresher.busy || pageIsOff(route)) return;
    const modal = document.getElementById('message-modal');
    if (modal && !modal.classList.contains('hidden') && !modal.classList.contains('ui-docked')) return;
    refresher.busy = true;
    pageRefreshState.route = route;
    pageRefreshState.at = Date.now();
    try {
        await Promise.race([refresher.run(), new Promise(resolve => setTimeout(resolve, PAGE_REFRESH_TIMEOUT))]);
    } catch (error) {
        console.error(`Refresh of ${route} failed:`, error);
    } finally {
        refresher.busy = false;
    }
}

function pageRefreshTick() {
    if (document.hidden) return;
    const refresher = pageRefreshers[currentTab];
    if (!refresher) return;
    // A page opened before the first tick counts from when it was opened
    if (pageRefreshState.route !== currentTab) pageRefreshLoaded(currentTab);
    if (Date.now() - pageRefreshState.at >= pageRefreshEvery(refresher) - 2000) pageRefreshNow();
}

function startPageRefresh() {
    if (pageRefreshState.timer) return;
    pageRefreshState.timer = setInterval(pageRefreshTick, PAGE_REFRESH_TICK);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) pageRefreshTick(); });
}

registerPageRefresh('dashboard', 30000, () => smartRefreshDashboard());
registerPageRefresh('messages', 30000, () => smartRefreshMessages());
registerPageRefresh('netfilter', 30000, async () => {
    await smartRefreshNetfilter();
    await loadSecurityOverview();
    fail2banSettingsLoaded = false;
    loadFail2BanSettings();
    if (typeof refreshProtectionHits === 'function') refreshProtectionHits();
    // Outgoing spam: its check runs every minute
    if (typeof refreshSmtpAbusePanel === 'function' && Date.now() - smtpAbuseLoadedAt >= 58000) refreshSmtpAbusePanel();
});
registerPageRefresh('outbound', 30000, async () => {
    // The queue feeds the page's summary and the sidebar counter on both tabs
    if (!isFeatureDisabled('queue')) await smartRefreshQueue();
    if (!isFeatureDisabled('suppressions')) {
        if (outboundTab === 'suppressions') await smartRefreshSuppressions();
        else await loadSuppressionStats();
    }
});
registerPageRefresh('quarantine', 30000, async () => {
    await smartRefreshQuarantine();
    // The Auto-Rules tab: the rules with their hits, and the history while it is open
    if (quarantineTab !== 'rules' || !showQuarantineRulesAccess()) return;
    await loadQuarantineRules({ quiet: true });
    const history = document.getElementById('quarantine-rules-history');
    if (history && !history.classList.contains('hidden')) await loadQuarantineRuleHistory({ quiet: true });
});
registerPageRefresh('status', 30000, async () => {
    statusQuiet = true;
    try {
        await loadStatus();
    } finally {
        statusQuiet = false;
    }
});
// The maps list (never a map open in the editor)
registerPageRefresh('rspamd', 60000, () => refreshRspamdMaps());
registerPageRefresh('settings', 30000, () => smartRefreshSettings());
// DNS is checked every six hours and mailcow is asked for the domains on each read
registerPageRefresh('domains', 5 * 60 * 1000, () => refreshDomains());
// The server keeps the DMARC lists for five minutes, and clears them when reports come in or go
registerPageRefresh('dmarc', 5 * 60 * 1000, () => dmarcReload(true));
registerPageRefresh('mailbox-stats', () => mailboxStatsRefreshEvery(), () => refreshMailboxStatsPage());
// The ActiveSync log is read every minute
registerPageRefresh('devices', 60000, () => loadDevices(devicesPage, { quiet: true }));

// Helper to check if data changed
function hasDataChanged(newData, cacheKey) {
    const oldData = lastDataCache[cacheKey];
    if (!oldData) return true;

    // Compare JSON strings for simple change detection
    const newJson = JSON.stringify(newData);
    const oldJson = JSON.stringify(oldData);
    return newJson !== oldJson;
}

// The Messages refresh, with every filter. At the edge where new mail lands (the
// top, newest first; the end of a whole list, oldest first) the list takes it in
// by itself. Anywhere else it stays as it is, and the new mail is counted on the
// server against the list's watermark and offered as "N new messages" at that
// edge, as the Logs page offers new lines. Nothing happens while the list loads.
async function smartRefreshMessages() {
    const filters = currentFilters.messages || {};
    const busy = () => messagesFullLoad || messagesPaging.loading;
    if (messagesRefreshing || busy()) return;
    // No list is shown (its load failed): load it again
    if (!lastDataCache.messages) return loadMessages();

    // The list takes new mail in where it lands, not while text in it is selected
    const free = () => messagesAtNewEdge() && !uiTextHeld(document.getElementById('messages-logs'));
    const gen = messagesGen;
    messagesRefreshing = true;
    try {
        if (messagesOrder === 'desc' && free()) {
            const response = await messagesFetch(`/api/messages?${messagesQueryParams()}`, PAGE_REFRESH_TIMEOUT);
            if (!response.ok) return;
            const data = await response.json();
            // Meanwhile the list was loaded again or more of it is loading
            if (gen !== messagesGen || busy()) return;
            // Still free when the answer comes (the user may have scrolled or started selecting)
            if (free()) {
                if (!messagesSameAsShown(data)) {
                    // A list drawn again is a new one, and its counts with it; the focus stays on its row
                    const now = messagesNewGeneration();
                    uiKeepFocus(document.getElementById('messages-logs'), 'data-key', () => renderMessagesData(data));
                    loadMessageFacets(filters, now);
                } else {
                    // Nothing new matches: the counts may still have moved with other mail
                    if (data.watermark != null) messagesNew.watermark = data.watermark;
                    loadMessageFacets(filters, gen);
                }
                return;
            }
        }
        // Oldest first, a list not loaded to its end gets the new mail by paging to it
        if (messagesOrder === 'asc' && messagesPaging.cursor) {
            loadMessageFacets(filters, gen);
            return;
        }
        if (messagesNew.watermark === null) return;
        const params = messagesFilterParams(filters);
        params.set('after_id', messagesNew.watermark);
        const response = await messagesFetch(`/api/messages/new?${params}`, PAGE_REFRESH_TIMEOUT);
        if (!response.ok) return;
        const data = await response.json();
        if (gen !== messagesGen || busy()) return;
        messagesNew.count = data.count || 0;
        // At the end of the whole list, oldest first, the list is read again (new mail,
        // and messages whose status changed) and drawn again when anything changed
        if (messagesOrder === 'asc' && free()) {
            messagesRefreshing = false;
            await messagesShowNew({ quiet: true });
            return;
        }
        renderMessagesNew();
        loadMessageFacets(filters, gen);
    } catch (error) {
        if (error.name !== 'AbortError') console.error('Messages refresh failed:', error);
    } finally {
        messagesRefreshing = false;
    }
}

// New mail since the list was read: the watermark the list came with (the
// newest message stored then) and how many messages came after it
const messagesNew = { watermark: null, count: 0 };

// Whether an answer brings nothing new over the rows shown, row for row as far
// as it goes (a first page against the top of a longer list)
function messagesSameAsShown(data) {
    const shown = lastDataCache.messages;
    if (!shown) return false;
    const rows = data.data || [];
    const had = shown.data || [];
    return data.total === shown.total && rows.length <= had.length && JSON.stringify(rows) === JSON.stringify(had.slice(0, rows.length));
}

// The element the list scrolls in: its own column on wide screens, the page
// below 1000 px (whichever element of it scrolls)
function messagesScroller(container) {
    for (let el = container; el && el !== document.body; el = el.parentElement) {
        const overflow = getComputedStyle(el).overflowY;
        if ((overflow === 'auto' || overflow === 'scroll') && el.scrollHeight > el.clientHeight + 1) return el;
    }
    return document.scrollingElement || document.documentElement;
}

// The part of the screen the scroller shows
function messagesInView(scroller) {
    if (scroller === document.scrollingElement || scroller === document.documentElement) return { top: 0, bottom: window.innerHeight };
    const box = scroller.getBoundingClientRect();
    return { top: box.top, bottom: box.bottom };
}

// Whether the list shows the edge where new mail lands: its first row, newest
// first; the last row of the whole list, oldest first. An empty list is all edge
function messagesAtNewEdge() {
    const container = document.getElementById('messages-logs');
    if (!container || !container.getClientRects().length) return false;
    const rows = container.querySelectorAll('.ui-msg-item');
    if (!rows.length) return true;
    const view = messagesInView(messagesScroller(container));
    if (messagesOrder === 'asc') {
        return !messagesPaging.cursor && rows[rows.length - 1].getBoundingClientRect().bottom <= view.bottom + 8;
    }
    return rows[0].getBoundingClientRect().top >= view.top - 8;
}

// "N new messages" at the edge where new mail lands, sticky so it stays in view
function renderMessagesNew() {
    const list = document.querySelector('#messages-logs .ui-msg-list');
    let wrap = document.getElementById('messages-new-wrap');
    const count = messagesNew.count;
    if (!list || !count) {
        if (wrap) wrap.hidden = true;
        return;
    }
    if (!wrap) {
        wrap = document.createElement('div');
        wrap.id = 'messages-new-wrap';
        wrap.className = 'ui-msg-new-wrap';
        wrap.innerHTML = `<button type="button" class="ui-msg-new" onclick="messagesShowNew()">
            <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d=""></path></svg>
            <span></span></button>`;
    }
    const top = messagesOrder !== 'asc';
    wrap.classList.toggle('is-top', top);
    // Where the page scrolls, the search bar stays on top: the button goes under it
    const bar = document.querySelector('#content-messages .ui-msg-searchbar');
    const sticky = bar && getComputedStyle(bar).position === 'sticky';
    wrap.style.setProperty('--ui-msg-new-top', sticky ? `${bar.offsetHeight}px` : '0px');
    if (top ? list.previousElementSibling !== wrap : list.nextElementSibling !== wrap) {
        if (top) list.before(wrap); else list.after(wrap);
    }
    wrap.querySelector('path').setAttribute('d', top ? 'M5 15l7-7 7 7' : 'M19 9l-7 7-7-7');
    wrap.querySelector('span').textContent = `${count.toLocaleString()} new ${count === 1 ? 'message' : 'messages'}`;
    wrap.hidden = false;
}

// Show the new mail: newest first, the list from its top; oldest first, the list
// read again as long as it is plus the new messages, at its end
async function messagesShowNew({ quiet = false } = {}) {
    const container = document.getElementById('messages-logs');
    if (!container) return;
    if (messagesOrder === 'asc') {
        // As many rows as are shown and the new ones, page by page; taken in quietly
        // only if the user is still at the end when they have all come
        const shown = container.querySelectorAll('.ui-msg-item').length;
        const stillFree = () => messagesAtNewEdge() && !uiTextHeld(container);
        await loadMessages({ quiet, rows: Math.max(50, shown + messagesNew.count), toEnd: true, applyIf: quiet ? stillFree : null });
        return;
    }
    // Where the page scrolls, back to the start of the list (its own column starts at the top on loading)
    const scroller = messagesScroller(container);
    await loadMessages();
    if (scroller !== container) scroller.scrollTop = 0;
}

function messagesScrollToEnd(container) {
    const scroller = messagesScroller(container);
    scroller.scrollTop = scroller.scrollHeight;
}

// Render messages without loading spinner
// One row of the Messages list (also used by the smart refresh), as in the
// mockup: sender and time, subject, then the outcome tag and the direction.
// Queue ID, message ID, score, user and IP are in the reading pane.
// A click anywhere on the row opens the message (selecting its text does not,
// uiRowHeld); the keyboard opens it on its time, a real button named after the
// subject whose click reaches the row. The row itself is no button: the sender
// and recipient in it are buttons of their own (uiEntity), and the subject stays
// text that can be selected (a browser selects no text inside a button)
function renderMessageRow(msg) {
    const tone = messageRowTone(msg);
    return `
        <div class="ui-msg-item${tone ? ` ui-msg-${tone}` : ''}" data-key="${escapeHtml(msg.correlation_key || '')}"${msg.message_id ? ` data-mid="${encodeURIComponent(msg.message_id)}"` : ''} onclick="if (!uiRowHeld(event)) viewMessageDetails('${escapeJsArg(msg.correlation_key)}')">
            <div class="ui-msg-l1">
                <b class="ui-msg-from">${msg.sender ? uiEntity('address', msg.sender, { plain: true }) : 'Unknown'}</b>
                <button type="button" class="ui-row-open ui-msg-at" aria-label="${msg.first_seen ? `${escapeHtml(formatListTime(msg.first_seen))}, open` : 'Open'} the message: ${escapeHtml(msg.subject || 'No subject')}">${uiTime(msg.first_seen, formatListTime(msg.first_seen), { title: formatTime(msg.first_seen) })}</button>
            </div>
            <p class="ui-msg-sub" dir="auto" title="${escapeHtml(msg.subject || 'No subject')}">${escapeHtml(msg.subject || 'No subject')}</p>
            <div class="ui-msg-l3">
                ${uiCorrelationTag(msg)}
                ${msg.direction ? uiDirectionTag(msg.direction) : ''}
                ${msg.is_spam ? '<span class="ui-tag ui-tag-spam">SPAM</span>' : ''}
                <span class="ui-msg-to" title="${escapeHtml(msg.recipient || '')}">to ${msg.recipient ? uiEntity('address', msg.recipient, { plain: true }) : 'Unknown'}</span>
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
    showMessagesFirstPage(container, data);
    if (typeof markSelectedMessageRow === 'function' && window.openMessageKey) markSelectedMessageRow(window.openMessageKey);
}

// A first page of the list, from a full load or the auto refresh: the rows (or
// "No messages found"), the count, where the next page starts, and the answer
// the refresh compares the next one with
function showMessagesFirstPage(container, data) {
    // The watermark moves with any new mail, also mail the filters leave out: not part of the comparison
    lastDataCache.messages = { ...data, watermark: null };
    messagesNew.watermark = data.watermark ?? null;
    messagesNew.count = 0;
    const rows = data.data || [];
    messagesPaging.page = 1;
    messagesPaging.total = data.total || rows.length;
    messagesPaging.cursor = rows.length ? data.next_cursor || null : null;
    currentPage.messages = 1;
    setMessagesCount(messagesPaging.total);
    if (!rows.length) {
        container.innerHTML = '<p class="ui-empty">No messages found</p>';
        return;
    }
    renderMessagesList(container, data);
}

function setMessagesCount(total) {
    const countEl = document.getElementById('messages-count');
    if (countEl) countEl.textContent = total === null ? '' : uiCountLabel(total || 0, 'message', 'messages');
}

// ---------- Messages list: the next page loads as the end scrolls into view ----------
// page: pages shown; cursor: where the next page starts (null at the end);
// failed: the last page could not load, until Try again
const messagesPaging = { page: 1, pages: 1, total: 0, cursor: null, loading: false, failed: false, observer: null };
// One list at a time. Every full load, and every redraw by the auto refresh,
// starts a new generation: the requests of the older one are aborted (so none
// of them holds up the new list), and their answers and errors are dropped.
let messagesGen = 0;
let messagesFullLoad = false;      // a full load is on its way
let messagesRefreshing = false;    // an auto refresh is on its way
const messagesRequests = new Set();

function messagesNewGeneration() {
    messagesGen++;
    messagesRequests.forEach(control => control.abort());
    messagesRequests.clear();
    messagesPaging.loading = false;
    messagesPaging.failed = false;
    return messagesGen;
}

// A request of the list's and its answer, read in full while it can still be
// aborted (a new generation aborts it, also while its body is coming in)
async function messagesFetch(url, timeout = 0) {
    const control = typeof AbortController === 'function' ? new AbortController() : null;
    if (control) messagesRequests.add(control);
    try {
        const response = await authenticatedFetch(url, { ...(control ? { signal: control.signal } : {}), ...(timeout ? { timeout } : {}) });
        const data = response.ok ? await response.json() : null;
        return { ok: response.ok, status: response.status, statusText: response.statusText, json: async () => data };
    } finally {
        if (control) messagesRequests.delete(control);
    }
}

// The Messages filters every request sends: the list, its facet counts and the
// new-mail count (the CSV export sends currentFilters.messages as it is).
// exact, address and domain come from an entity card (messagesExact)
const MESSAGES_FILTER_KEYS = ['search', 'sender', 'recipient', 'direction', 'user', 'status', 'ip', 'address', 'domain', 'exact', 'start_date', 'end_date'];

// The filters an entity card opened Messages with ("Show messages"), matched
// whole and not as a part: the sender, recipient, user and IP it set, and an
// address or a domain, which have no field (from or to them). They hold until
// a field the card filled is changed or cleared (another condition added keeps
// them, and is matched whole too); a chip above the list names them and takes
// them off (updateMessagesFilterState). Filters set any other way drop them:
// they hold only while the filters in use are the ones they made (filters).
let messagesExact = null;   // { sender, recipient, user, ip, address, domain, filters } or null
const MESSAGES_EXACT_FIELDS = ['sender', 'recipient', 'user', 'ip'];

// The fields' filters with the whole-value ones that still hold
function messagesWithExact(fields) {
    // Filters set since by anything but the card's: its whole values went with them
    if (messagesExact && messagesExact.filters && currentFilters.messages !== messagesExact.filters) messagesExact = null;
    const x = messagesExact;
    if (x && MESSAGES_EXACT_FIELDS.some(key => x[key] && (fields[key] || '') !== x[key])) messagesExact = null;
    if (!messagesExact) return fields;
    const filters = { ...fields, exact: 'true', ...(x.address ? { address: x.address } : {}), ...(x.domain ? { domain: x.domain } : {}) };
    x.filters = filters;
    return filters;
}

// What the chip says: each whole value, as a person reads the filter
function messagesExactParts(x) {
    const parts = [];
    if (x.address) parts.push(['From or to', x.address]);
    if (x.domain) parts.push(['From or to', `@${x.domain}`]);
    if (x.sender) parts.push(['From', x.sender]);
    if (x.recipient) parts.push(['To', x.recipient]);
    if (x.user) parts.push(['Signed in as', x.user]);
    if (x.ip) parts.push(['IP', x.ip]);
    return parts;
}

// The chip's X: the whole values go, with the fields they had set; the period stays
function clearMessagesExact() {
    if (messagesExact) {
        MESSAGES_EXACT_FIELDS.forEach(key => {
            const el = messagesExact[key] && document.getElementById(`messages-filter-${key}`);
            if (el) el.value = '';
        });
    }
    messagesExact = null;
    applyMessagesFilters();
}

// The list's query; with a cursor, the page that starts after it, holding only
// what the first page's watermark (upto) held
function messagesQueryParams(cursor = null, limit = 50, upto = null) {
    const filters = messagesRangeFilters(currentFilters.messages || {});
    const params = new URLSearchParams({ page: 1, limit });
    for (const key of MESSAGES_FILTER_KEYS) {
        if (filters[key]) params.append(key, filters[key]);
    }
    if (messagesOrder === 'asc') params.append('order', 'asc');
    if (cursor) params.append('cursor', cursor);
    if (cursor && upto !== null && upto !== undefined) params.append('upto_id', upto);
    return params;
}

// The Messages list's order, by the time each message was first seen: newest
// first (as it arrives) or oldest first. Its Sort button beside the search turns
// the order around, and its arrow shows which one is in use.
// An order is not a filter: clearing the filters keeps it.
let messagesOrder = 'desc';
const MESSAGES_ORDER_ICONS = {
    desc: '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 4.5h14M3 9h10M3 13.5h7m7.5-4.5v11m0 0l-3.5-3.5m3.5 3.5l3.5-3.5"></path></svg>',
    asc: '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 4.5h14M3 9h10M3 13.5h7m7.5 6.5V9m0 0l-3.5 3.5M17.5 9l3.5 3.5"></path></svg>',
};
function renderMessagesSort() {
    const slot = document.getElementById('messages-sort');
    if (!slot) return;
    let button = slot.querySelector('button');
    if (!button) {
        slot.innerHTML = `<button type="button" class="ui-icon-btn ui-sort-btn-icon" onclick="setMessagesOrder(messagesOrder === 'asc' ? 'desc' : 'asc')"></button>`;
        button = slot.querySelector('button');
    }
    const asc = messagesOrder === 'asc';
    button.innerHTML = MESSAGES_ORDER_ICONS[asc ? 'asc' : 'desc'];
    button.setAttribute('aria-label', `Sort: ${asc ? 'Oldest first' : 'Newest first'}`);
    button.title = asc ? 'Oldest first. Click for newest first' : 'Newest first. Click for oldest first';
    button.classList.toggle('is-set', asc);
}
// Shown with the page, before its list arrives
document.addEventListener('DOMContentLoaded', renderMessagesSort);
function setMessagesOrder(order) {
    messagesOrder = order === 'asc' ? 'asc' : 'desc';
    renderMessagesSort();
    loadMessages();
}

function messagesMoreText() {
    if (messagesPaging.cursor) return 'Loading more...';
    return messagesPaging.total ? `All ${messagesPaging.total} messages shown` : '';
}

function renderMessagesList(container, data) {
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

// The next page, after the last message shown. A page that fails says so with
// Try again and waits for it; it does not ask again by itself.
async function loadMoreMessages(retry = false) {
    if (retry) messagesPaging.failed = false;
    if (messagesPaging.loading || messagesPaging.failed || !messagesPaging.cursor) return;
    const list = document.querySelector('#messages-logs .ui-msg-list');
    if (!list) return;
    messagesPaging.loading = true;
    const gen = messagesGen;
    try {
        const response = await messagesFetch(`/api/messages?${messagesQueryParams(messagesPaging.cursor, 50, messagesNew.watermark)}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        // The list was loaded again meanwhile: this page is not part of it
        if (gen !== messagesGen) return;
        // Never show a message twice: by its row, and by its Message-ID (another of
        // its deliveries may stand for it now, when the first one was cleaned up)
        const seen = new Set([...list.querySelectorAll('.ui-msg-item[data-key]')].map(row => row.dataset.key));
        const ids = new Set([...list.querySelectorAll('.ui-msg-item[data-mid]')].map(row => row.dataset.mid));
        const added = (data.data || []).filter(msg => !seen.has(msg.correlation_key || '') && !(msg.message_id && ids.has(encodeURIComponent(msg.message_id))));
        list.insertAdjacentHTML('beforeend', added.map(renderMessageRow).join(''));
        // What the refresh compares with is the whole list shown
        if (lastDataCache.messages) lastDataCache.messages = { ...lastDataCache.messages, data: (lastDataCache.messages.data || []).concat(added), total: data.total ?? lastDataCache.messages.total, next_cursor: data.next_cursor || null };
        messagesPaging.page += 1;
        currentPage.messages = messagesPaging.page;
        messagesPaging.cursor = data.next_cursor || null;
        // The count as it is now, not as it was when the list was drawn
        messagesPaging.total = data.total ?? messagesPaging.total;
        setMessagesCount(messagesPaging.total);
        const more = document.getElementById('messages-more');
        if (more) more.textContent = messagesMoreText();
        if (typeof markSelectedMessageRow === 'function' && window.openMessageKey) markSelectedMessageRow(window.openMessageKey);
    } catch (error) {
        // An error for an older list, or its request aborted, says nothing about the one shown
        if (gen !== messagesGen) return;
        messagesPaging.failed = true;
        const more = document.getElementById('messages-more');
        if (more) more.innerHTML = `Could not load more messages. <button type="button" class="ui-link-row ui-link" onclick="loadMoreMessages(true)">Try again</button>`;
    } finally {
        if (gen === messagesGen) messagesPaging.loading = false;
    }
    if (gen !== messagesGen || messagesPaging.failed) return;
    // A short page may leave the end still in view (only while the list is on the screen)
    const sentinel = document.getElementById('messages-more');
    const container = document.getElementById('messages-logs');
    if (sentinel && container && messagesPaging.cursor && sentinel.getClientRects().length) {
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
        const emptyCount = document.getElementById('security-count');
        if (emptyCount) emptyCount.textContent = uiCountLabel(0, 'event', 'events');
        return;
    }

    // Deduplicate logs
    const uniqueLogs = deduplicateNetfilterLogs(data.data);

    // Update count display with total count from API (like Messages page)
    const countEl = document.getElementById('security-count');
    if (countEl) {
        countEl.textContent = uiCountLabel(data.total || 0, 'event', 'events');
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
                // Check if IP is in the blacklist (with or without /32, or /128)
                const ipInBlacklist = log.ip && fail2banBlacklist.some(entry => entry === log.ip || entry === fail2banEntry(log.ip));
                // Show unban if: banned OR already in blacklist
                const showUnban = mailcowRwConfigured && log.ip && (isBan || ipInBlacklist);
                // Show ban if: warning/unban AND NOT already in blacklist
                const showBan = mailcowRwConfigured && log.ip && isWarningOrUnban && !ipInBlacklist;
                const flagUrl = log.country_code ? getFlagUrl(log.country_code, '16x12') : '';
                const place = [log.country_name, log.city].filter(Boolean).join(', ');
                const org = log.asn_org ? ` (${log.asn_org})` : '';
                const account = log.username && log.username !== '-' ? uiEntity('address', log.username)
                    : (log.attempts_left !== null && log.attempts_left !== undefined ? `<span class="ui-muted">${escapeHtml(String(log.attempts_left))} attempts left</span>` : '<span class="ui-muted">-</span>');
                return `
                <div class="ui-ev-row ui-msg-${uiActionTone(log.action)}">
                    ${uiTime(log.time, formatListTime(log.time), { title: formatTime(log.time), cls: 'ui-muted' })}
                    <b class="ui-mono">${log.ip ? uiEntity('ip', log.ip, { mono: true }) : '-'}</b>
                    <span class="ui-ev-account">${account}</span>
                    <span>${uiActionTag(log.action)}</span>
                    <span class="ui-ev-where" title="${escapeHtml(place + org)}">${flagUrl ? `<img src="${flagUrl}" alt="" width="16" height="12" onerror="this.style.display='none'">` : ''}${escapeHtml(place || '-')}</span>
                    <span class="ui-st-acts">
                        ${showUnban ? `<button onclick="unbanIP('${escapeJsArg(log.ip)}', this)" class="ui-btn ui-btn-sm" title="Unban ${escapeHtml(log.ip)}">Unban</button>` : ''}
                        ${showBan ? `<button onclick="banIP('${escapeJsArg(log.ip)}', this)" class="ui-btn ui-btn-sm ui-btn-danger" title="Put ${escapeHtml(fail2banEntry(log.ip))} on the denylist; it stays until removed">Ban permanently</button>` : ''}
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

// A single address as a Fail2ban list entry: /32 for IPv4, /128 for IPv6. mailcow
// reads the prefix as a network, so 2001:db8::1/32 would be all of 2001:db8::/32.
function fail2banEntry(ip) {
    return ip.includes('/') ? ip : `${ip}/${ip.includes(':') ? 128 : 32}`;
}

// The address a single-address entry holds; a network entry stays as it is
function fail2banBare(entry) {
    const value = String(entry || '');
    return value.replace(value.includes(':') ? /\/128$/ : /\/32$/, '');
}

async function unbanIP(ip, btnEl) {
    const ipWithMask = fail2banEntry(ip);
    if (!await showConfirmModal({ title: 'Unban IP', message: 'Unban ' + ip + '?', confirmText: 'Unban' })) return;
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
            // Fail2ban may have banned the whole network around the address: name what was lifted
            const lifted = result.networks || [ipWithMask];
            showToast(lifted.map(fail2banBare).join(', ') + ' unbanned successfully', 'success');
            // mailcow queues the unban and lifts it a few seconds later: the address
            // leaves the lists now, and Fail2ban is asked again once it has acted
            if (fail2banActiveBans) fail2banActiveBans = fail2banActiveBans.filter(b => !lifted.includes(b.network) && fail2banBare(b.ip || b.network) !== fail2banBare(ip));
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
    const ipWithMask = fail2banEntry(ip);
    if (!await showConfirmModal({ title: 'Ban IP', message: `Are you sure you want to permanently ban ${ipWithMask}?\n\nThis will add the IP to the Fail2Ban denylist.`, confirmText: 'Ban', isDangerous: true })) return;

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
            showToast(result.already ? result.msg : `IP ${ip} added to the denylist`, 'success');
            // Refresh fail2ban data and netfilter logs
            fail2banSettingsLoaded = false;
            fail2banActiveBans = null;
            loadFail2BanSettings();
            smartRefreshNetfilter();
            return true;
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
    const ipWithMask = fail2banEntry(ip);
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
            showToast(result.already ? result.msg : `IP ${ip} added to the allowlist`, 'success');
            fail2banSettingsLoaded = false;
            fail2banActiveBans = null;
            loadFail2BanSettings();
            return true;
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
        select.innerHTML = '<option value="" data-short="All">All Countries</option>';
        
        for (const c of countries) {
            const opt = document.createElement('option');
            opt.value = c.code;
            opt.textContent = `${c.name || c.code}`;
            select.appendChild(opt);
        }
        
        // Restore selection
        if (currentValue) select.value = currentValue;
        uiFilterBarSync();
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
    if (queueActing) return;
    const id = ++queueAsked;
    const kept = queueListKept();
    const response = await authenticatedFetch('/api/queue');
    if (!response.ok) return;

    const data = await response.json();
    await rwStatusReady;
    const listKept = await kept;
    if (queueActing || !queueTakeTurn(id)) return;
    const suppressChanged = listKept !== queueSuppressOn;
    queueSuppressOn = listKept;

    // Drawn also when a load still shows Loading: that older load's answer is dropped now
    if (hasDataChanged(data, 'queue') || suppressChanged || queueLoading) {
        queueLoading = false;
        console.log('[REFRESH] Queue data changed, updating UI');
        lastDataCache.queue = data;
        allQueueData = data.data || [];
        updateQueueSummary();
        applyQueueFilters();
    }
}

// Smart refresh for Quarantine
async function smartRefreshQuarantine() {
    if (quarantineActing) return;
    const id = ++quarantineAsked;
    const response = await authenticatedFetch('/api/quarantine', { timeout: PAGE_REFRESH_TIMEOUT });
    if (!response.ok) return;

    const data = await response.json();
    await rwStatusReady;
    if (quarantineActing || !quarantineTakeTurn(id)) return;

    if (hasDataChanged(data, 'quarantine')) {
        console.log('[REFRESH] Quarantine data changed, updating UI');
        lastDataCache.quarantine = data;
        renderQuarantineData(data);
    }
}

// Smart refresh for Dashboard
// When the Dashboard's blocklist and health figures were last read
let dashboardKpisAt = 0;

async function smartRefreshDashboard() {
    try {
        refreshMailFlowChart();
        loadDashboardStatusSummary();
        loadDashboardSecurity();
        // Needs attention has its own refresh on every page (attentionRefresh); the trends,
        // the blocklists and the health figures every five minutes
        if (Date.now() - dashboardTrendsAt >= 300000) loadDashboardTrends();
        if (Date.now() - dashboardKpisAt >= 300000) {
            dashboardKpisAt = Date.now();
            loadDashboardBlacklistSummary();
            loadDashboardHealth();
        }
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
    if (pageIsOff(tab)) {
        const feature = TOGGLEABLE_FEATURES.find(f => f.id === tab);
        const featureLabel = feature ? feature.label : (TAB_LABELS[tab] || tab);
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
                    ${uiLocked(`${featureLabel} is disabled`, 'This feature has been turned off by the administrator in Settings → Features.',
                        `<button onclick="navigateTo('dashboard')" class="ui-btn ui-btn-primary">Go to Dashboard</button>`)}
                </div>`;
        }

        // Update URL to reflect the disabled page (don't silently change to dashboard)
        const newPath = typeof buildPath === 'function' ? buildPath(tab) : `/${tab}`;
        if (window.location.pathname !== newPath) {
            routerReplace({ route: tab, params: {} }, newPath);
        }
        queueDocumentTitle();
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
    // The page loads below: its own refresh comes a full cadence later
    pageRefreshLoaded(tab);

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
    placeTopbar(tab);

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
            loadMessages();
            break;
        case 'netfilter':
            loadSecurityOverview();
            loadNetfilterLogs(1);
            loadFail2BanSettings();
            if (typeof loadProtection === 'function') loadProtection();
            loadNetfilterCountries();
            loadSmtpAbusePanel();
            loadSecurityAppSettings();
            break;
        case 'outbound':
            loadOutbound();
            break;
        case 'quarantine':
            loadQuarantine();
            initQuarantineRules();
            break;
        case 'rspamd':
            // Not refreshed on the timer: the map editor would drop unsaved changes
            loadRspamdMaps();
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
        case 'devices':
            loadDevices();
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
        default:
            console.warn('Unknown tab:', tab);
    }
    queueDocumentTitle();
}

// =============================================================================
// DASHBOARD
// =============================================================================

async function loadDashboard() {
    try {
        console.log('Loading Dashboard...');
        loadDashboardStatusSummary();
        loadDashboardBlacklistSummary();
        loadDashboardHealth();
        dashboardKpisAt = Date.now();
        // Needs attention as last read, and read again what is due
        renderAttention();
        attentionRefresh();
        loadDashboardSecurity();
        loadDashboardTrends();
        loadMailFlowChart();
    } catch (error) {
        console.error('Failed to load dashboard:', error);
    }
}

// =============================================================================
// Needs attention: the Dashboard panel and the header bell show one state, read
// by one refresh on every page (alerts every 30 seconds, server checks every
// five minutes). A load that a newer one replaced is dropped when it answers, so
// a list read before a Dismiss never brings the dismissed alert back
// =============================================================================

const ATTENTION_ALERTS_EVERY = 30000;
const ATTENTION_CHECKS_EVERY = 5 * 60 * 1000;
// The server checks, each read on its own: one that fails keeps what it showed
const ATTENTION_CHECKS = ['connection', 'blocklist', 'containers', 'fail2ban', 'dmarc', 'appVersion', 'mailcowVersion'];
const ATTENTION_FAILED = { failed: true };
const attention = {
    ready: false, // the refresh starts once the app's features are known
    timeout: 20000, // a read without an answer by then has failed
    // ok: null before the first answer, then whether the last one came
    alerts: { seq: 0, busy: null, latest: null, at: 0, ok: null, list: [], total: 0, critical: 0 },
    // ok and items per check
    checks: { seq: 0, busy: null, latest: null, at: 0, ok: {}, items: {} },
};

// The alerts Needs attention shows (by id, for the words of an Undo), and every
// open alert the last list had: Dismiss all changes those and no alert that came after
const dashboardAlerts = new Map();
let dashboardOpenAlertIds = [];

// One load of a source at a time. With force (after a Dismiss or an Undo, or a
// Retry) a load on its way is replaced and its answer dropped; without, it is joined
function attentionLoad(state, force, read) {
    if (state.busy && !force) return state.busy;
    const seq = ++state.seq;
    const run = (async () => {
        const answer = await read();
        if (seq !== state.seq) return state.latest;
        return answer();
    })();
    state.busy = run;
    state.latest = run;
    run.finally(() => { if (state.busy === run) state.busy = null; });
    return run;
}

// One read of a source's answer. A read that has not answered in 20 seconds has
// failed, so a request that hangs never holds the refresh that comes after it
function attentionRead(url) {
    return Promise.race([
        (async () => {
            try {
                const res = await authenticatedFetch(url);
                return res.ok ? await res.json() : ATTENTION_FAILED;
            } catch (e) {
                console.warn(`Needs attention could not read ${url}:`, e);
                return ATTENTION_FAILED;
            }
        })(),
        new Promise(resolve => setTimeout(() => resolve(ATTENTION_FAILED), attention.timeout)),
    ]);
}

// The open security alerts (anomaly detection); true when the list was read
function loadDashboardSecurityAlerts({ force = true } = {}) {
    const s = attention.alerts;
    return attentionLoad(s, force, async () => {
        const read = await attentionRead('/api/security-alerts?acknowledged=false&limit=20');
        const data = read === ATTENTION_FAILED ? null : read;
        return () => {
            s.at = Date.now();
            // A failed read keeps the alerts the last one had
            if (!data) { s.ok = false; renderAttention(); return false; }
            const alerts = data.alerts || [];
            s.ok = true;
            s.list = alerts;
            // All open alerts, also those past the 20 rows shown
            s.total = Number.isFinite(data.unacknowledged_count) ? data.unacknowledged_count : alerts.length;
            s.critical = Number.isFinite(data.unacknowledged_critical) ? data.unacknowledged_critical
                : alerts.filter(a => a.severity === 'critical').length;
            dashboardAlerts.clear();
            alerts.forEach(a => dashboardAlerts.set(Number(a.id), a));
            dashboardOpenAlertIds = data.unacknowledged_ids || alerts.map(a => Number(a.id));
            renderAttention();
            return true;
        };
    });
}

// "Dismiss all 25 alerts"; one alone is "Dismiss 1 alert" (a narrow panel drops the last word)
function renderDismissAll(button) {
    if (!button) return;
    const count = dashboardOpenAlertIds.length, n = count.toLocaleString();
    const words = count === 1 ? ['Dismiss 1', 'alert'] : [`Dismiss all ${n}`, 'alerts'];
    button.innerHTML = `${words[0]}<span class="ui-attn-wide">&nbsp;${words[1]}</span>`;
    button.setAttribute('aria-label', words.join(' '));
    button.classList.toggle('is-off', !attention.alerts.list.length);
}

// The rows of the alerts. In the bell's window an action that opens another
// window closes this one first, so the next gives the focus back to the bell
function attentionAlertRows(where) {
    return attention.alerts.list.map(a => {
        const id = Number(a.id);
        const critical = a.severity === 'critical';
        const first = where === 'bell' ? 'attnBellOpen();' : '';
        return `
            <div class="ui-alert ui-alert-go ${critical ? 'ui-alert-fail' : 'ui-alert-warn'}" data-key="alert-${id}" onclick="if (uiAlertRowClick(event)) { ${first} openAlertActivity(${id}) }">
                <span class="ui-alert-bar"></span>
                <div class="ui-alert-text">
                    <div class="ui-alert-title">
                        <span class="ui-tag ${critical ? 'ui-tag-fail' : 'ui-tag-warn'}">${escapeHtml((a.severity || 'warning').toUpperCase())}</span>
                        <b>${escapeHtml(a.title)}</b>
                    </div>
                    <p>${escapeHtml(a.detail || '')}</p>
                    <p class="ui-muted">${escapeHtml(formatTime(a.created_at))}</p>
                </div>
                <div class="ui-alert-acts">
                    <button type="button" onclick="${first} openAlertActivity(${id})" class="ui-btn ui-btn-sm" title="What happened before and around this alert">Show activity</button>
                    <button type="button" onclick="acknowledgeSecurityAlert(${id})" class="ui-btn ui-btn-sm" title="Dismiss">Dismiss</button>
                </div>
            </div>`;
    }).join('');
}

// A Needs attention row whose action opens a popup opens it from anywhere on
// the row; its buttons keep their own actions, and selecting text opens nothing
function uiAlertRowClick(event) {
    return !event.target.closest('button, a') && !uiRowHeld(event);
}

// How many items, of which tone, and whether every check could run
function attentionStatus() {
    const a = attention.alerts, c = attention.checks;
    const items = ATTENTION_CHECKS.flatMap(k => c.items[k] || []);
    const total = items.length + a.total;
    const tone = items.some(i => i.tone === 'fail') || a.critical > 0 ? 'fail'
        : items.some(i => i.tone === 'warn') || a.total > 0 ? 'warn' : 'info';
    const failed = a.ok === false || ATTENTION_CHECKS.some(k => c.ok[k] === false);
    const loading = a.ok === null || ATTENTION_CHECKS.some(k => c.ok[k] === undefined);
    return { total, tone, failed, loading };
}

// Under the items: all clear only when every check ran and found nothing; a check
// that could not run says so (what it showed before stays) and offers Retry
function renderAttentionNote(el, status) {
    if (!el) return;
    const html = status.failed
        ? 'Some checks could not run. <button type="button" class="ui-link-row ui-link" onclick="attentionRetry()">Retry</button>'
        : !status.loading && status.total === 0 ? 'Nothing needs attention right now.' : '';
    if (el.dataset.shown !== html) {
        el.innerHTML = html;
        el.dataset.shown = html;
    }
    el.classList.toggle('hidden', !html);
}

function attentionRetry() {
    if (attention.alerts.ok === false) loadDashboardSecurityAlerts();
    if (ATTENTION_CHECKS.some(k => attention.checks.ok[k] === false)) loadDashboardAttention();
}

// The count, the note and Dismiss all of the Dashboard panel and the bell's window;
// a list that scrolls fades at its foot while more is below, and on the Dashboard
// the line under it says how many items there are
function updateAttentionState() {
    const status = attentionStatus();
    const count = document.getElementById('dashboard-attention-count');
    if (count) count.textContent = status.total ? status.total.toLocaleString() : '';
    const winCount = document.getElementById('attn-win-count');
    if (winCount) winCount.textContent = status.total ? status.total.toLocaleString() : '';
    renderAttentionNote(document.getElementById('dashboard-attention-clear'), status);
    renderAttentionNote(document.getElementById('attn-win-state'), status);
    renderDismissAll(document.getElementById('dashboard-dismiss-all'));
    renderDismissAll(document.getElementById('attn-win-dismiss-all'));
    document.querySelectorAll('.ui-attn-scroll').forEach(scroll => {
        const overflows = scroll.scrollHeight > scroll.clientHeight + 1;
        scroll.classList.toggle('has-more', overflows && scroll.scrollTop + scroll.clientHeight < scroll.scrollHeight - 2);
        scroll.tabIndex = overflows || scroll.id === 'attn-win-scroll' ? 0 : -1;
        if (scroll.id !== 'dashboard-attention-scroll') return;
        const more = document.getElementById('dashboard-attention-more');
        if (!more) return;
        // Only while the items pass the cap; otherwise it takes no room
        more.classList.toggle('is-off', !overflows);
        more.textContent = overflows ? `${uiCountLabel(status.total, 'item', 'items')}. Scroll the list for the rest` : ' ';
    });
    updateAttentionBell(status);
}
if (typeof document !== 'undefined' && document.addEventListener) {
    document.addEventListener('scroll', event => {
        if (event.target instanceof Element && event.target.classList.contains('ui-attn-scroll')) updateAttentionState();
    }, true);
    window.addEventListener('resize', () => updateAttentionState());
}

// The bell: the count of every open item, red for a failing one, amber for a
// warning, plain for news only; a grey dot when a check could not run and
// nothing is known to need a look
function updateAttentionBell(status = attentionStatus()) {
    const label = status.total ? `Needs attention, ${uiCountLabel(status.total, 'item', 'items')}`
        : status.failed ? 'Needs attention, some checks could not run' : 'Needs attention';
    document.querySelectorAll('.ui-bell').forEach(bell => {
        bell.setAttribute('aria-label', label);
        const badge = bell.querySelector('.ui-bell-n');
        if (!badge) return;
        badge.textContent = status.total ? (status.total > 99 ? '99+' : String(status.total)) : '';
        badge.className = `ui-bell-n is-${status.total ? status.tone : status.failed ? 'unknown' : 'none'}`;
    });
}

// Replace what a box shows, only when it changed, keeping the focus where it
// was (the same item and action, else the item next to it, else the box) and
// the box's scroll; a focus outside the box is left alone
function uiReplaceKeepingFocus(container, html) {
    if (container.dataset.shown === html) return false;
    const active = document.activeElement;
    let keep = null;
    if (active && container.contains(active)) {
        const item = active.closest('[data-key]');
        const items = [...container.querySelectorAll('[data-key]')];
        keep = { key: item && item.dataset.key, action: active.textContent.trim(), at: Math.max(0, items.indexOf(item)) };
    }
    const scroller = container.closest('.ui-attn-scroll, [data-keep-scroll]');
    const top = scroller ? scroller.scrollTop : 0;
    container.innerHTML = html;
    container.dataset.shown = html;
    if (scroller) scroller.scrollTop = top;
    if (keep) {
        const items = [...container.querySelectorAll('[data-key]')];
        const same = keep.key ? items.find(i => i.dataset.key === keep.key) : null;
        const item = same || items[Math.min(keep.at, items.length - 1)];
        const buttons = item ? [...item.querySelectorAll('button')] : [];
        const target = (same && buttons.find(b => b.textContent.trim() === keep.action)) || buttons[0] || scroller || null;
        if (target) target.focus({ preventScroll: true });
    }
    return true;
}

// Server checks that need a look, each with the place to handle it: go is the
// page it opens, popup an action that opens a window
function attentionCheckItems(key, data) {
    if (!data) return [];
    if (key === 'connection') {
        return data.connected === false ? [{ tone: 'fail', title: 'mailcow is not reachable', detail: 'The mailcow API did not answer, so logs and server data may be out of date.',
            action: 'Open settings', onclick: "navigateTo('settings')", go: ['settings'] }] : [];
    }
    if (key === 'blocklist') {
        if (data.status !== 'listed') return [];
        // Name the host that is actually listed, with its own list count
        const listedHosts = (data.hosts || []).filter(h => h.status === 'listed');
        const first = listedHosts[0];
        const title = listedHosts.length > 1
            ? `${listedHosts.length} of your addresses are on a blocklist`
            : `${first ? first.hostname : (data.server_ip || 'Your server')} is on a blocklist`;
        const detail = listedHosts.length > 1
            ? `${listedHosts.map(h => h.hostname).join(', ')}. Outbound mail to some providers may bounce.`
            : `Listed on ${first ? first.listed_count : data.listed_count} of ${first && first.total_blacklists ? first.total_blacklists : data.total_blacklists} lists. Outbound mail to some providers may bounce.`;
        return [{ tone: 'fail', title, detail, action: 'Check listing', onclick: "navigateTo('status')", go: ['status'] }];
    }
    if (key === 'containers') {
        const containers = data.containers;
        if (!containers || !(containers.stopped > 0)) return [];
        return [{ tone: 'fail', title: containers.stopped === 1 ? 'A mailcow container is stopped' : `${containers.stopped} mailcow containers are stopped`,
            detail: `${containers.running || 0} of ${containers.total || 0} containers are running.`, action: 'Open status', onclick: "navigateTo('status')", go: ['status'] }];
    }
    if (key === 'fail2ban') {
        // Single IPv6 addresses an earlier version wrote as /32 networks
        const legacy = data.legacy_entries || [];
        if (!legacy.length) return [];
        const first = legacy[0];
        return [{ tone: 'warn',
            title: legacy.length === 1 ? `A Fail2ban entry ${first.list === 'whitelist' ? 'exempts' : 'blocks'} the whole ${first.network} network` : `${legacy.length} Fail2ban entries cover whole /32 networks`,
            detail: legacy.length === 1 ? `An earlier version wrote ${first.address} as ${first.entry}. Repair it on the Security page's Lists tab.`
                : 'An earlier version wrote single IPv6 addresses as networks. Repair them on the Security page\'s Lists tab.',
            action: 'Open lists', onclick: "navigateTo('netfilter', { sub: 'lists' })", go: ['netfilter', { sub: 'lists' }] }];
    }
    if (key === 'dmarc') {
        const dmarc = (data.insights || []).filter(i =>
            i.recommendations.some(r => r.type === 'tighten_policy' || r.type === 'low_pass_rate') || (i.new_sources && i.new_sources.length > 0));
        if (!dmarc.length) return [];
        const first = dmarc[0].recommendations[0];
        return [{ tone: 'warn', title: dmarc.length === 1 ? `DMARC needs attention for ${dmarc[0].domain}` : `DMARC needs attention for ${dmarc.length} domains`,
            detail: first ? first.message : 'New sources are failing DMARC.', action: 'Open DMARC', onclick: "navigateTo('dmarc')", go: ['dmarc'] }];
    }
    if (key === 'appVersion') {
        if (!data.update_available) return [];
        appUpdateInfo = data;
        return [{ tone: 'info', title: `Version ${data.latest_version} is available`,
            detail: `You are running ${data.current_version}. See what changed before updating.`, action: 'Read changes', onclick: 'showAppUpdateModal()', popup: true }];
    }
    if (key === 'mailcowVersion') {
        if (!data.update_available) return [];
        // What its Read changes shows (showMailcowUpdateModal), from this same answer
        window.mailcowUpdateVersion = data.latest_version;
        window.mailcowUpdateName = data.name || '';
        window.mailcowUpdateChangelog = data.changelog || 'No changelog available';
        return [{ tone: 'info', title: `mailcow ${data.latest_version} is available`,
            detail: `You are running ${data.current_version}.`, action: 'Read changes', onclick: 'showMailcowUpdateModal()', popup: true }];
    }
    return [];
}

// The server checks; a check whose read fails keeps the items it had and is
// tried again in a minute. A blocklist check that ended in an error has failed
// too, and so have container counts read without an answer from mailcow
function loadDashboardAttention({ force = true } = {}) {
    const s = attention.checks;
    return attentionLoad(s, force, async () => {
        const off = feature => (window.disabledFeatures || []).includes(feature);
        const get = attentionRead;
        const [blocklistRead, summary, dmarc, appVersion, mailcowVersion, connection, fail2ban] = await Promise.all([
            off('blacklist') ? null : get('/api/blacklist/summary'),
            get('/api/status/summary'),
            off('dmarc') ? null : get('/api/dmarc/insights'),
            get('/api/status/app-version'),
            get('/api/status/version'),
            get('/api/status/mailcow-connection'),
            off('netfilter') ? null : get('/api/fail2ban'),
        ]);
        const answered = data => data && data !== ATTENTION_FAILED;
        const blocklist = answered(blocklistRead) && blocklistRead.status === 'error' ? ATTENTION_FAILED : blocklistRead;
        const containers = answered(summary) && summary.containers_known === false ? ATTENTION_FAILED : summary;
        const read = { connection, blocklist, containers, fail2ban, dmarc, appVersion, mailcowVersion };
        return () => {
            for (const key of ATTENTION_CHECKS) {
                if (read[key] === ATTENTION_FAILED) { s.ok[key] = false; continue; }
                s.ok[key] = true;
                s.items[key] = attentionCheckItems(key, read[key]);
            }
            const failed = ATTENTION_CHECKS.some(k => s.ok[k] === false);
            s.at = failed ? Date.now() - ATTENTION_CHECKS_EVERY + 60000 : Date.now();
            renderAttention();
        };
    });
}

function attentionCheckRows(where) {
    return ATTENTION_CHECKS.flatMap(k => attention.checks.items[k] || []).map(item => {
        const act = where !== 'bell' ? item.onclick
            : item.go ? `attnBellGo(${escapeHtml(JSON.stringify(item.go))})` : `attnBellOpen(); ${item.onclick}`;
        return `
        <div class="ui-alert ui-alert-${item.tone}${item.popup ? ' ui-alert-go' : ''}" data-key="check-${escapeHtml(item.title)}"${item.popup ? ` onclick="if (uiAlertRowClick(event)) { ${act} }"` : ''}>
            <span class="ui-alert-bar"></span>
            <div class="ui-alert-text"><div class="ui-alert-title"><b>${escapeHtml(item.title)}</b></div><p>${escapeHtml(item.detail)}</p></div>
            <button type="button" class="ui-btn ui-btn-sm" onclick="${act}">${escapeHtml(item.action)}</button>
        </div>`;
    }).join('');
}

// Both places from the one state
function renderAttention() {
    for (const [where, checksId, alertsId] of [['dashboard', 'dashboard-attention', 'dashboard-security-alerts'], ['bell', 'attn-win-checks', 'attn-win-alerts']]) {
        const checks = document.getElementById(checksId);
        if (checks) uiReplaceKeepingFocus(checks, attentionCheckRows(where));
        const alerts = document.getElementById(alertsId);
        if (alerts) {
            uiReplaceKeepingFocus(alerts, attentionAlertRows(where));
            alerts.classList.toggle('hidden', !attention.alerts.list.length);
        }
    }
    updateAttentionState();
}

// One refresh for every page: what is older than its cadence is read again.
// A hidden browser tab reads nothing; it catches up when it is shown
function attentionRefresh({ force = false } = {}) {
    if (!attention.ready) return;
    if (!force && document.hidden) return;
    const now = Date.now();
    if (force || now - attention.alerts.at >= ATTENTION_ALERTS_EVERY - 2000) loadDashboardSecurityAlerts({ force });
    if (force || now - attention.checks.at >= ATTENTION_CHECKS_EVERY - 2000) loadDashboardAttention({ force });
}

// Once the app's features are known (a feature turned off is not checked)
function startAttention() {
    if (attention.ready) return;
    attention.ready = true;
    attentionRefresh();
    setInterval(attentionRefresh, ATTENTION_ALERTS_EVERY);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) attentionRefresh(); });
    // The window belongs to the bell it opened from: past 760px that one is gone
    window.matchMedia('(max-width: 760px)').addEventListener('change', event => {
        if (attnWindow && attnWindow.phone !== event.matches) attnWindowClose();
    });
}

// The bell's window: under the bell on a wide screen, a sheet on a phone. It is
// a layer like any dialog (router.js): Escape, Back and a click beside it close
// it, and the focus goes back to the bell
let attnWindow = null;
function attnWindowOpen(bell) {
    if (attnWindow && attnWindow.el.isConnected) { attnWindowClose(); return; }
    attnWindow = null;
    const phone = window.matchMedia('(max-width: 760px)').matches;
    const head = `<h2 id="attn-win-title" class="ui-attn-win-title">Needs attention <span id="attn-win-count" class="ui-count"></span></h2>
        <button type="button" id="attn-win-dismiss-all" class="ui-btn ui-btn-sm is-off" onclick="acknowledgeAllSecurityAlerts()"></button>`;
    const list = `<div id="attn-win-checks"></div><div id="attn-win-alerts" class="hidden"></div><p id="attn-win-state" class="ui-dash-clear hidden"></p>`;
    const foot = `<div class="ui-attn-win-foot"><button type="button" class="ui-link-row ui-attn-win-go" onclick="attnBellGo(['dashboard'])">Open the Dashboard</button></div>`;
    uiLayerOpener(bell);
    let el;
    if (phone) {
        el = uiSheetShow('attn-sheet', { label: 'Needs attention', head, body: list + foot, onClose: () => attnWindowClose() });
        const body = el.querySelector('.ui-sheet-body');
        body.dataset.keepScroll = '';
        body.tabIndex = -1;
    } else {
        el = document.createElement('div');
        el.id = 'attn-window';
        el.className = 'ui-dialog-backdrop ui-attn-backdrop';
        el.innerHTML = `<section class="ui-attn-win" role="dialog" aria-labelledby="attn-win-title">
            <div class="ui-attn-win-head">${head}<button type="button" class="ui-icon-btn ui-attn-win-x" onclick="attnWindowClose()" aria-label="Close" title="Close">${UI_CLOSE_ICON}</button></div>
            <div id="attn-win-scroll" class="ui-attn-scroll ui-attn-win-list" data-keep-scroll tabindex="0">${list}</div>${foot}</section>`;
        // A click beside it; not a press that began inside (a text selection) and ended there
        el.addEventListener('click', event => { if (uiBackdropClick(event)) attnWindowClose(); });
        document.body.appendChild(el);
        const at = bell.getBoundingClientRect();
        const panel = el.firstElementChild;
        panel.style.top = `${Math.round(at.bottom + 8)}px`;
        panel.style.right = `${Math.max(16, Math.round(document.documentElement.clientWidth - at.right))}px`;
    }
    attnWindow = { bell, el, phone };
    document.querySelectorAll('.ui-bell').forEach(b => {
        b.setAttribute('aria-expanded', String(b === bell));
        if (b === bell) b.setAttribute('aria-controls', el.id);
    });
    renderAttention();
    attentionRefresh();
}

// toPage: a move to another page, which takes the focus instead of the bell
function attnWindowClose({ toPage = false } = {}) {
    const w = attnWindow;
    if (!w) return;
    attnWindow = null;
    if (toPage) uiLayerReturn(w.el, null);
    if (w.phone) uiSheetClose('attn-sheet');
    else w.el.remove();
    document.querySelectorAll('.ui-bell').forEach(b => {
        b.setAttribute('aria-expanded', 'false');
        b.removeAttribute('aria-controls');
    });
}

// An action that opens a page: the window closes once the move is made (a move
// cancelled over unsaved changes leaves it open)
async function attnBellGo(go) {
    const moved = await navigateTo(go[0], go[1] || {});
    if (moved && attnWindow) attnWindowClose({ toPage: true });
}

// An action that opens another window: this one closes, and the next gives the
// focus back to the bell when it closes
function attnBellOpen() {
    const w = attnWindow;
    if (!w) return;
    attnWindowClose();
    uiLayerOpener(w.bell);
}

// The dashboard's mail flow (/api/stats/flow): a period of 24 hours, 7 days or
// 30 days in bars cut at the app's own hours, quarters of the day and days;
// the four figures over the period, with the period before it under them, or
// those of one bar picked on the chart. The chart zooms in time (uiTimeZoom):
// a zoomed span asks the server again, in shorter bars as it narrows. A strip
// under it (uiTimeOverview) shows the whole period with the span shown.
// Two loaders: the period's own answer (its figures, the strip, the limits)
// and the zoomed span's. One view revision tells both whether an answer still
// belongs to what is shown: a change of period or of zoom makes an answer
// asked before it stale, and it is dropped.
const DASH_PERIODS = {
    '24h': { name: '24 hours', last: 'last 24 hours', all: 'All 24 hours' },
    '7d': { name: '7 days', last: 'last 7 days', all: 'All 7 days' },
    '30d': { name: '30 days', last: 'last 30 days', all: 'All 30 days' },
};
const dashFlow = {
    period: '24h',
    data: null,      // the bars and totals shown
    full: null,      // the period's own answer (the strip draws it, zoomed or not)
    prev: null,      // the period before (no zoom)
    limits: null,    // the period's span: how far the chart zooms out and moves
    zoom: null,      // { from, to } (ms), a span inside the period
    pick: null,      // a bar's start (ms)
    view: 0,         // the view revision: up one at every change of period or zoom
    periodGen: 0, periodControl: null, zoomGen: 0, zoomControl: null,
    loadedAt: 0, zoomer: null, overview: null, previewing: false,
    stale: false,    // an answer was set aside under a gesture: ask again when it ends
    dataView: -1,    // the view revision the chart shows
    failed: false,   // the last load failed: the next refresh tries again, zoomed or not
};

function mailFlowHour(t) {
    return formatClock(t);
}

// A span with the dates as the rest of the app writes them: "21/10/2026, 06:00 to 12:00",
// "14/10/2026 to 16/10/2026", or one whole day: "14/10/2026". `to` is where the span ends
// (not in it), so a span of whole days ends at the midnight after its last day.
// day: formatDayMonth leaves the year out
function mailFlowSpan(from, to, day = formatDay) {
    const end = to - 1;
    const sameDay = zonedDateString(from) === zonedDateString(end);
    if (isZonedMidnight(from) && isZonedMidnight(to)) return sameDay ? day(from) : `${day(from)} to ${day(end)}`;
    if (sameDay) return `${day(from)}, ${mailFlowHour(from)} to ${mailFlowHour(to)}`;
    return `${day(from)}, ${mailFlowHour(from)} to ${day(end)}, ${mailFlowHour(to)}`;
}

// The bar length for a span: an hour up to two days, six hours up to ten, else a day
function mailFlowBucketFor(len) {
    return len <= 48 * 3600000 ? 'hour' : len <= 10 * 86400000 ? '6h' : 'day';
}

function setDashFlowPeriod(period) {
    if (!DASH_PERIODS[period]) return;
    dashFlow.period = period;
    dashFlow.zoom = null;
    dashFlow.pick = null;
    dashFlow.full = null;
    dashFlow.view++;
    document.querySelectorAll('#dashboard-flow-period button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.period === period)));
    loadMailFlowChart();
}

// A click on a bar shows its numbers; the same bar again, or All, goes back
function pickMailFlowHour(t) {
    dashFlow.pick = t === null || dashFlow.pick === t ? null : t;
    renderMailFlowStats();
}

// The buttons step by whole bars, so the server shows the span asked for:
// in keeps the middle half of the bars, earlier and later move by half of them
function dashFlowStep(step) {
    const l = dashFlow.limits, d = dashFlow.data;
    if (!l || !d) return;
    if (step === 'reset') { dashFlowZoom(null); return; }
    const bars = d.buckets.map(b => ({ s: Date.parse(b.start), e: Date.parse(b.end) }));
    const n = bars.length;
    if (!n) return;
    const shown = { from: bars[0].s, to: bars[n - 1].e };
    const len = shown.to - shown.from;
    const k = Math.max(1, Math.floor(n / 2));
    if (step === 'in') {
        if (n < 2) return;
        const i = Math.floor((n - k) / 2);
        dashFlowZoom({ from: bars[i].s, to: bars[i + k - 1].e });
    } else if (step === 'earlier') {
        const from = Math.max(l.from, shown.from - (k < n ? bars[k].s - bars[0].s : len));
        dashFlowZoom({ from, to: from + len });
    } else if (step === 'later') {
        const to = Math.min(l.to, shown.to + (k < n ? bars[n - 1].e - bars[n - 1 - k].e : len));
        dashFlowZoom({ from: to - len, to });
    } else {
        dashFlowZoom(uiTimeZoomStep(shown, l, step));
    }
}

function dashFlowZoom(span) {
    const l = dashFlow.limits;
    // Zoomed all the way out is no zoom
    dashFlow.zoom = !span || (l && span.from <= l.from + 1 && span.to >= l.to - 1) ? null : { from: span.from, to: span.to };
    dashFlow.pick = null;
    dashFlow.view++;
    dashFlow.stale = false;
    // Back to the whole period: its answer is here already
    if (!dashFlow.zoom && dashFlow.full) {
        dashFlow.zoomGen++;
        if (dashFlow.zoomControl) dashFlow.zoomControl.abort();
        dashFlow.data = dashFlow.full;
        dashFlow.failed = false;
        renderMailFlowChart();
        return;
    }
    loadMailFlowChart();
}

// A gesture on the chart or a drag on the strip is on: nothing is redrawn under it
function mailFlowBusy() {
    return dashFlow.previewing || !!(dashFlow.overview && dashFlow.overview.busy());
}

// A gesture or a strip drag ended with no new span: what was set aside under it is asked for now
function mailFlowSettle() {
    if (dashFlow.stale && !mailFlowBusy()) loadMailFlowChart();
}

function mailFlowGet(query, control) {
    return authenticatedFetch(`/api/stats/flow?${query}`, control ? { signal: control.signal } : {}).then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
    });
}

function mailFlowFailed() {
    const chart = document.getElementById('dashboard-flow-chart');
    if (!chart) return;
    dashFlow.failed = true;
    const failed = '<p class="ui-empty ui-text-fail ui-flow-failed">Could not load the mail flow. It tries again on the next refresh.</p>';
    // In the chart's own frame, so the panel keeps its size; no gesture outlives the chart it was on
    if (dashFlow.zoomer) { dashFlow.zoomer.destroy(); dashFlow.zoomer = null; }
    dashFlow.previewing = false;
    const view = chart.querySelector('.ui-flow-view');
    if (view) view.innerHTML = failed;
    else chart.innerHTML = mailFlowFrame(failed);
}

function loadMailFlowChart() {
    const chart = document.getElementById('dashboard-flow-chart');
    if (!chart) return;
    // A gesture is on: it asks again when it ends
    if (mailFlowBusy()) return;
    dashFlow.stale = false;
    // Before the first answer: the chart's whole frame, so the panel has its size from the start
    if (!chart.querySelector('.ui-flow-view')) chart.innerHTML = mailFlowFrame('<p class="ui-empty ui-flow-failed" role="status">Loading...</p>');
    if (dashFlow.zoom && dashFlow.full) loadMailFlowZoom();
    else loadMailFlowPeriod();
}

// The period's own answer and the period before: the figures with no zoom, the
// strip and the limits. Zoomed, only the strip and the limits follow it: the
// zoom stays where it is, kept inside the new limits (dropped if nothing is left).
async function loadMailFlowPeriod() {
    const gen = ++dashFlow.periodGen;
    if (dashFlow.periodControl) dashFlow.periodControl.abort();
    const control = typeof AbortController === 'function' ? new AbortController() : null;
    dashFlow.periodControl = control;
    const period = dashFlow.period;
    try {
        const [data, prev] = await Promise.all([mailFlowGet(`period=${period}`, control), mailFlowGet(`period=${period}&previous=true`, control)]);
        if (gen !== dashFlow.periodGen || period !== dashFlow.period) return;
        dashFlow.full = data;
        dashFlow.prev = prev;
        dashFlow.loadedAt = Date.now();
        dashFlow.limits = { from: Date.parse(data.from), to: Date.parse(data.to), min: 3600000 };
        if (!dashFlow.zoom) {
            // A gesture is on: the answer waits in full; the gesture's end draws (or asks again)
            if (mailFlowBusy()) { dashFlow.stale = true; return; }
            dashFlow.data = data;
            dashFlow.failed = false;
            renderMailFlowChart();
            return;
        }
        const l = dashFlow.limits, z = dashFlow.zoom;
        const from = Math.max(z.from, l.from), to = Math.min(z.to, l.to);
        const moved = from !== z.from || to !== z.to;
        if (mailFlowBusy()) {
            // Under a gesture the zoom still moves inside the new limits; its end asks for it
            if (moved) { dashFlow.zoom = to - from >= l.min ? { from, to } : null; dashFlow.view++; }
            dashFlow.stale = true;
            return;
        }
        if (moved) { dashFlowZoom(to - from >= l.min ? { from, to } : null); return; }
        // A zoom made before this period's answer came (a period switch, then Zoom in): its own answer now
        if (dashFlow.dataView !== dashFlow.view) { loadMailFlowZoom(); return; }
        renderMailFlowOverview(true);
    } catch (error) {
        if (gen !== dashFlow.periodGen || (error && error.name === 'AbortError')) return;
        // Under a gesture nothing is drawn: the gesture's end asks again
        if (mailFlowBusy()) { dashFlow.failed = true; dashFlow.stale = true; return; }
        // Zoomed, the strip keeps its last picture; the next refresh tries again
        if (!dashFlow.zoom) mailFlowFailed();
    }
}

// The zoomed span, in bars as short as it allows; the zoom becomes what the
// server shows (it snaps to the nearest bar edges)
async function loadMailFlowZoom() {
    const z = dashFlow.zoom, view = dashFlow.view;
    const gen = ++dashFlow.zoomGen;
    if (dashFlow.zoomControl) dashFlow.zoomControl.abort();
    const control = typeof AbortController === 'function' ? new AbortController() : null;
    dashFlow.zoomControl = control;
    const iso = t => new Date(t).toISOString();
    try {
        const data = await mailFlowGet(`from=${iso(z.from)}&to=${iso(z.to)}&bucket=${mailFlowBucketFor(z.to - z.from)}`, control);
        if (gen !== dashFlow.zoomGen || view !== dashFlow.view) return;
        if (mailFlowBusy()) { dashFlow.stale = true; return; }
        dashFlow.data = data;
        dashFlow.failed = false;
        dashFlow.zoom = { from: Date.parse(data.from), to: Date.parse(data.to) };
        const l = dashFlow.limits;
        if (l) dashFlow.limits = { ...l, to: Math.max(l.to, dashFlow.zoom.to) };
        // Snapped out to the whole period: that is no zoom (the period before and the refresh come back)
        if (l && dashFlow.zoom.from <= l.from + 1 && dashFlow.zoom.to >= l.to - 1) dashFlow.zoom = null;
        renderMailFlowChart();
    } catch (error) {
        if (gen !== dashFlow.zoomGen || view !== dashFlow.view || (error && error.name === 'AbortError')) return;
        if (mailFlowBusy()) { dashFlow.failed = true; dashFlow.stale = true; return; }
        mailFlowFailed();
    }
}

// The auto refresh: the period every minute for 24 hours, every five minutes
// for longer ones; zoomed, it refreshes the strip and leaves the zoom as it is
function refreshMailFlowChart() {
    if (mailFlowBusy()) return;
    if (dashFlow.failed) { loadMailFlowChart(); return; }
    const every = dashFlow.period === '24h' ? 60000 : 300000;
    if (Date.now() - dashFlow.loadedAt >= every) loadMailFlowPeriod();
}

// The strip under the chart: the whole period, a window over the span shown.
// alone: only the strip is drawn again (the zoomed chart stays), the focus kept
function renderMailFlowOverview(alone = false) {
    const strip = document.querySelector('#dashboard-flow-chart .ui-ov');
    if (!strip) return;
    const draw = () => {
        if (dashFlow.overview) { dashFlow.overview.destroy(); dashFlow.overview = null; }
        const full = dashFlow.full, l = dashFlow.limits;
        if (!full || !l) { strip.innerHTML = ''; return; }
        const bars = full.buckets.map(b => ({ s: Date.parse(b.start), e: Date.parse(b.end), v: b.clean + b.spam }));
        const max = Math.max(1, ...bars.map(b => b.v));
        const kept = full.kept_from ? Date.parse(full.kept_from) : null;
        const i = kept === null ? -1 : bars.findIndex(b => kept < b.e);
        const gone = kept === null || kept <= l.from ? 0 : i < 0 ? 1 : (i + Math.max(0, kept - bars[i].s) / (bars[i].e - bars[i].s)) / bars.length;
        strip.innerHTML = `<div class="ui-ov-bars" aria-hidden="true">${bars.map(b => `<i style="height:${Math.max(6, b.v / max * 100)}%"></i>`).join('')}</div>`
            + (gone ? `<div class="ui-ov-gone" style="width:${gone * 100}%" aria-hidden="true"></div>` : '');
        const edges = bars.map(b => b.s).concat(l.to);
        const big = dashFlow.period === '24h' ? 6 * 3600000 : dashFlow.period === '7d' ? 86400000 : 7 * 86400000;
        dashFlow.overview = uiTimeOverview(strip, {
            limits: () => dashFlow.limits,
            span: () => dashFlow.zoom || dashFlow.limits,
            snap: uiNearestLocalHour,
            // One step is one bar of the strip; a big step is six hours on 24 hours, a day on 7 days, a week on 30 days
            step: (t, dir, isBig) => (isBig ? t + dir * big
                : dir > 0 ? (edges.find(e => e > t + 1) ?? l.to) : ([...edges].reverse().find(e => e < t - 1) ?? l.from)),
            label: t => `${formatDay(t)}, ${mailFlowHour(t)}`,
            change: span => dashFlowZoom(span),
            idle: mailFlowSettle,
        });
    };
    if (alone) uiRedrawKeepingFocus(strip, draw);
    else draw();
}

// The foot under the chart: the legend, the zoom buttons and the actions, all
// always there (what is not in use keeps its place), so the panel keeps its size
function mailFlowFoot(can) {
    const off = on => (on ? '' : ' disabled');
    // The Messages figure opens the same messages: it is on when View these messages is
    const figure = document.getElementById('dashboard-flow-messages');
    if (figure) figure.disabled = !can.view;
    return `<div class="ui-flow-foot">
            <div class="ui-flow-legend"><span><i class="ui-flow-clean"></i>Clean</span><span><i class="ui-flow-spam"></i>Spam</span></div>
            <div class="ui-flow-zoom" role="group" aria-label="Zoom the chart">
                <button type="button" class="ui-icon-btn ui-icon-btn-sm" onclick="dashFlowStep('earlier')" aria-label="Earlier" title="Earlier"${off(can.earlier)}>&lsaquo;</button>
                <button type="button" class="ui-icon-btn ui-icon-btn-sm" onclick="dashFlowStep('out')" aria-label="Zoom out" title="Zoom out"${off(can.out)}>&minus;</button>
                <button type="button" class="ui-icon-btn ui-icon-btn-sm" onclick="dashFlowStep('in')" aria-label="Zoom in" title="Zoom in (or pinch, drag across bars, Ctrl+wheel)"${off(can.in)}>+</button>
                <button type="button" class="ui-icon-btn ui-icon-btn-sm" onclick="dashFlowStep('later')" aria-label="Later" title="Later"${off(can.later)}>&rsaquo;</button>
                <button type="button" class="ui-icon-btn ui-icon-btn-sm${can.zoomed ? '' : ' is-off'}" onclick="dashFlowStep('reset')" aria-label="Reset zoom" title="Reset zoom"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v5h5"/></svg></button>
            </div>
            <span class="ui-flow-actions">
                <button type="button" id="dashboard-flow-view" class="ui-btn ui-btn-sm" onclick="openMailFlowHourMessages()"${off(can.view)}>View these messages</button>
                <button type="button" id="dashboard-flow-reset" class="ui-more is-off" onclick="pickMailFlowHour(null)">Clear</button>
            </span>
        </div>`;
}

// The chart's frame with a line in place of the bars (loading, or a first load that failed)
function mailFlowFrame(inner) {
    return `<div class="ui-flow-view">${inner}</div><div class="ui-flow-axis" aria-hidden="true"></div><div class="ui-ov" data-zoom></div>${mailFlowFoot({})}`;
}

function renderMailFlowChart() {
    const chart = document.getElementById('dashboard-flow-chart');
    const d = dashFlow.data;
    if (!chart || !d) return;
    const bars = d.buckets.map(b => ({ ...b, s: Date.parse(b.start), e: Date.parse(b.end) }));
    const max = Math.max(1, ...bars.map(b => b.clean + b.spam));
    const n = bars.length;
    // Axis: hours every third (sixth on phones), the start of each day for six-hour bars, every fifth day
    const label = (b, i) => {
        const p = zonedParts(b.s);
        if (i === n - 1 && b.partial) return '<span class="is-major">Now</span>';
        if (d.bucket === 'hour') return p.hour % 6 === 0 ? `<span class="is-major">${formatClock(b.s, { compact: true })}</span>` : p.hour % 3 === 0 ? `<span class="is-minor">${formatClock(b.s, { compact: true })}</span>` : '<span></span>';
        if (d.bucket === '6h') return p.hour < 6 ? `<span class="is-major">${escapeHtml(formatDayMonth(b.s))}</span>` : '<span></span>';
        // Every fifth day, not near Now
        return (n <= 10 || (i % 5 === 0 && i < n - 5)) ? `<span class="is-major">${escapeHtml(formatDayMonth(b.s))}</span>` : '<span></span>';
    };
    const zoomed = !!dashFlow.zoom;
    dashFlow.dataView = dashFlow.view;
    const shown = { from: Date.parse(d.from), to: Date.parse(d.to) };
    // The part older than the logs kept (retention): shaded, so empty bars there do not read as quiet
    const kept = d.kept_from ? Date.parse(d.kept_from) : null;
    let gone = 0;
    if (kept !== null && kept > shown.from) {
        const i = bars.findIndex(b => kept < b.e);
        gone = i < 0 ? 1 : (i + Math.max(0, kept - bars[i].s) / (bars[i].e - bars[i].s)) / n;
    }
    if (dashFlow.zoomer) { dashFlow.zoomer.destroy(); dashFlow.zoomer = null; }
    uiRedrawKeepingFocus(chart, () => { chart.innerHTML = `
        <div class="ui-flow-view">
            <div class="ui-flow-bars" role="group" aria-label="Messages per ${d.bucket === 'day' ? 'day' : d.bucket === '6h' ? 'six hours' : 'hour'}" data-zoom>${bars.map(b => `
                <button type="button" class="ui-flow-bar${b.partial ? ' is-partial' : ''}" data-t="${b.s}" data-start="${b.s}" data-end="${b.e}" aria-pressed="false" onclick="pickMailFlowHour(${b.s})"
                    title="${escapeHtml(mailFlowSpan(b.s, b.e))}: ${Number(b.messages).toLocaleString()} messages, ${Number(b.clean).toLocaleString()} clean, ${Number(b.spam).toLocaleString()} spam${b.partial ? ', so far' : ''}. Click for its numbers">
                    <i class="ui-flow-spam" style="height: ${(b.spam / max) * 100}%"></i>
                    <i class="ui-flow-clean" style="height: ${(b.clean / max) * 100}%"></i>
                </button>`).join('')}</div>
            ${gone ? `<div class="ui-flow-gone" style="width:${gone * 100}%" title="Logs older than the retention days are cleaned up">${gone > .2 ? '<span>Logs cleaned up</span>' : ''}</div>` : ''}
            <div class="ui-flow-band hidden" aria-hidden="true"></div>
        </div>
        <div class="ui-flow-axis" aria-hidden="true">${bars.map(label).join('')}</div>
        <div class="ui-ov" data-zoom role="group" aria-label="The whole period, with the span shown"></div>
        ${mailFlowFoot({ zoomed, earlier: zoomed && shown.from > dashFlow.limits.from, out: zoomed, in: shown.to - shown.from > dashFlow.limits.min, later: zoomed && shown.to < dashFlow.limits.to, view: true })}`;
        renderMailFlowOverview(); });
    const box = chart.querySelector('.ui-flow-bars');
    const view = chart.querySelector('.ui-flow-view');
    const band = chart.querySelector('.ui-flow-band');
    dashFlow.zoomer = uiTimeZoom(box, {
        bars: () => [...box.querySelectorAll('.ui-flow-bar')],
        span: () => dashFlow.zoom || dashFlow.limits,
        limits: () => dashFlow.limits,
        preview: (span, kind) => {
            if (!dashFlow.previewing) {
                // The gesture is on: an answer still on its way is set aside
                dashFlow.previewing = true;
                if (dashFlow.zoomControl) dashFlow.zoomControl.abort();
                dashFlow.zoomGen++;
            }
            if (kind === 'select') {
                const r = view.getBoundingClientRect();
                band.classList.remove('hidden');
                band.style.left = `${span.x1 - r.left}px`;
                band.style.width = `${span.x2 - span.x1}px`;
                return;
            }
            // Pinch, move or wheel: the bars stretch and slide to where the new span will be
            const len = shown.to - shown.from, next = span.to - span.from;
            const k = len / next;
            const x = -(span.from - shown.from) / len * view.clientWidth * k;
            box.style.transformOrigin = '0 0';
            box.style.transform = `translateX(${x}px) scaleX(${k})`;
        },
        change: span => { dashFlow.previewing = false; dashFlowZoom({ from: span.from, to: span.to }); },
        cancel: () => {
            dashFlow.previewing = false;
            box.style.transform = '';
            band.classList.add('hidden');
            loadMailFlowChart();
        },
    });
    renderMailFlowStats();
}

function renderMailFlowStats() {
    const d = dashFlow.data;
    if (!d) return;
    const period = DASH_PERIODS[dashFlow.period];
    const bar = dashFlow.pick === null ? null : d.buckets.find(b => Date.parse(b.start) === dashFlow.pick);
    if (!bar) dashFlow.pick = null;
    // A line cut short on a narrow screen shows in full on hover
    const set = (id, text) => { const el = document.getElementById(id); if (el) { el.textContent = text; if (el.tagName === 'SMALL') el.title = text; } };
    const n = v => (v || 0).toLocaleString();
    const src = bar || d.totals;
    set('stat-messages-24h', n(src.messages));
    set('stat-blocked-24h', n(src.blocked));
    set('stat-deferred-24h', n(src.deferred));
    set('stat-auth-failures-24h', n(src.auth_failures));
    // Under each figure: the whole span for a bar, the period before for a period
    const p = dashFlow.prev && dashFlow.prev.totals;
    const before = key => {
        if (bar) return `${dashFlow.zoom ? 'Shown' : period.name}: ${n(d.totals[key])}`;
        if (dashFlow.zoom || !p) return '';
        // A period before the oldest logs kept may hold only part of its mail (the note under the chart says why)
        return `Previous: ${n(p[key])}${dashFlow.prev.older_may_be_gone ? ' (partial)' : ''}`;
    };
    // Two lines under Messages, always both: the deliveries, and the span before or shown
    const note = document.getElementById('stat-messages-note');
    if (note) {
        const lines = [`${n(src.deliveries)} deliveries`, before('messages')];
        note.innerHTML = lines.map(line => `<span>${escapeHtml(line) || '&nbsp;'}</span>`).join('');
        note.title = lines.filter(Boolean).join(', ');
    }
    set('stat-blocked-note', before('blocked'));
    set('stat-deferred-note', before('deferred'));
    set('stat-auth-failures-note', before('auth_failures'));
    // The title in two lengths: in a narrow panel (a phone) the picker names the period,
    // so the short one says only a picked bar's or a zoom's span, its days without the year
    const shown = bar ? [Date.parse(bar.start), Date.parse(bar.end)] : dashFlow.zoom ? [Date.parse(d.from), Date.parse(d.to)] : null;
    const soFar = bar && bar.partial ? ', so far' : '';
    const long = document.querySelector('#dashboard-flow-title .ui-flow-long');
    const short = document.querySelector('#dashboard-flow-title .ui-flow-short');
    if (long) long.textContent = `Mail flow, ${shown ? mailFlowSpan(...shown) : period.last}${soFar}`;
    if (short) short.textContent = shown ? `${mailFlowSpan(...shown, formatDayMonth)}${soFar}` : 'Mail flow';
    // Clear keeps its place when nothing is picked, so the row does not move; the narrow
    // panel's Clear beside the title shows only with a bar picked
    document.getElementById('dashboard-flow-reset')?.classList.toggle('is-off', !bar);
    document.getElementById('dashboard-flow-clear')?.classList.toggle('hidden', !bar);
    const bars = document.querySelector('#dashboard-flow-chart .ui-flow-bars');
    if (bars) {
        bars.classList.toggle('has-pick', !!bar);
        bars.querySelectorAll('.ui-flow-bar').forEach(b => b.setAttribute('aria-pressed', String(!!bar && Number(b.dataset.t) === dashFlow.pick)));
    }
}

// The Messages period set to an exact range, without applying it: the custom
// range picker shows its days, in the app's zone like its Apply reads
function messagesShowRange(start, endInclusive, label = '') {
    document.getElementById('messages-date-range').value = 'custom';
    document.getElementById('messages-start-date').value = start;
    document.getElementById('messages-end-date').value = endInclusive;
    document.getElementById('messages-date-range-start').value = zonedDateString(Date.parse(start));
    document.getElementById('messages-date-range-end').value = zonedDateString(Date.parse(endInclusive));
    document.getElementById('messages-date-range-label').textContent = label || mailFlowSpan(Date.parse(start), Date.parse(endInclusive) + 1);
    setMessagesDatePresetActive(null);
}

// The Messages page over a span of time (and a mailbox): every other filter
// cleared, the exact start and end kept (its date picker shows their days and
// keeps them until another range is applied). endInclusive: the last moment
// in it, as the Messages page's end is inclusive.
function openMessagesRange({ start, endInclusive, user = '', label = '' }) {
    ['search', 'sender', 'recipient', 'user', 'ip', 'direction', 'status'].forEach(key => {
        const el = document.getElementById(`messages-filter-${key}`);
        if (el) el.value = '';
    });
    if (user) {
        const field = document.getElementById('messages-filter-user');
        if (field) field.value = user;
    }
    messagesExact = null;
    messagesShowRange(start, endInclusive, label);
    currentFilters.messages = { start_date: start, end_date: endInclusive, ...(user ? { user } : {}) };
    currentPage.messages = 1;
    navigateTo('messages');
}

// The picked bar's messages, else those of all the bars shown, on the Messages page.
// It shows the messages with a delivery in that time: a message counted in an
// earlier bar (its first delivery) shows there too.
function openMailFlowHourMessages() {
    const d = dashFlow.data;
    if (!d) return;
    const bar = dashFlow.pick === null ? null : d.buckets.find(b => Date.parse(b.start) === dashFlow.pick);
    if (bar) openMessagesRange({ start: bar.start, endInclusive: bar.end_inclusive });
    else openMessagesRange({ start: d.from, endInclusive: d.to_inclusive });
}

// Dismissing acts at once; the answer's receipt lets Undo re-open exactly what it
// changed, for 10 seconds (longer while the pointer or the focus is on the toast)
async function acknowledgeSecurityAlert(alertId) {
    const alert = dashboardAlerts.get(Number(alertId)) || (typeof alertActivity !== 'undefined' && alertActivity && Number(alertActivity.alert.id) === Number(alertId) ? alertActivity.alert : null);
    // Its title, with the mailbox or username when the title does not already name it
    const name = !alert ? 'the alert' : alert.subject && !String(alert.title).includes(alert.subject) ? `${alert.title}: ${alert.subject}` : alert.title;
    try {
        const res = await authenticatedFetch(`/api/security-alerts/${alertId}/acknowledge`, { method: 'POST' });
        if (!res.ok) throw new Error(res.status === 404 ? 'it is gone' : `the server answered ${res.status}`);
        const done = await res.json();
        loadDashboardSecurityAlerts();
        if (!done.receipt) { showToast('Already dismissed', 'info'); return; }
        offerAlertUndo(done.receipt, 'Alert dismissed', `Undo dismissing ${name}`);
    } catch (e) {
        showToast(`Could not dismiss the alert: ${e.message || 'no answer'}. Try again.`, 'error');
    }
}

async function acknowledgeAllSecurityAlerts() {
    const ids = dashboardOpenAlertIds.slice();
    if (!ids.length) return;
    try {
        const res = await authenticatedFetch('/api/security-alerts/acknowledge-all', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids }),
        });
        if (!res.ok) throw new Error(`the server answered ${res.status}`);
        const done = await res.json();
        loadDashboardSecurityAlerts();
        if (!done.receipt) { showToast('Already dismissed', 'info'); return; }
        const words = `${uiCountLabel(done.acknowledged, 'alert', 'alerts')} dismissed`;
        offerAlertUndo(done.receipt, words, `Undo dismissing ${uiCountLabel(done.acknowledged, 'alert', 'alerts')}`);
    } catch (e) {
        showToast(`Could not dismiss the alerts: ${e.message || 'no answer'}. Try again.`, 'error');
    }
}

function offerAlertUndo(receipt, message, undoName) {
    showToast(message, 'success', { duration: 10000, action: { label: 'Undo', ariaLabel: undoName, onAction: () => undoAlertDismissal(receipt, undoName) } });
}

function offerAlertsRefresh(message) {
    showToast(message, 'warning', { duration: Infinity, action: { label: 'Refresh', ariaLabel: 'Refresh Needs attention', onAction: async () => {
        // The next message takes the keyboard over from this one, whether it worked or not
        if (!(await loadDashboardSecurityAlerts())) offerAlertsRefresh('Needs attention could not be refreshed. Try again.');
        else showToast('Needs attention is up to date', 'success');
    } } });
}

// Re-open what a dismissal changed. A failure says so and offers Retry until closed.
async function undoAlertDismissal(receipt, undoName) {
    try {
        const res = await authenticatedFetch(`/api/security-alerts/acknowledgements/${encodeURIComponent(receipt)}/undo`, { method: 'POST' });
        if (!res.ok) throw new Error(`the server answered ${res.status}`);
        const done = await res.json();
        const shown = await loadDashboardSecurityAlerts();
        const back = done.restored ? `${uiCountLabel(done.restored, 'alert', 'alerts')} back` : '';
        if (!shown) {
            offerAlertsRefresh(back ? `${back}, but Needs attention could not be refreshed.` : 'Needs attention could not be refreshed.');
            return;
        }
        // With the bell's window open the keyboard goes to the first alert back there (its
        // Dismiss), else to its list; on the Dashboard the same in Needs attention; on
        // another page it stays with the message
        const place = attnWindow ? ['#attn-win-alerts', attnWindow.phone ? '#attn-sheet .ui-sheet-body' : '#attn-win-scroll']
            : typeof currentTab === 'undefined' || currentTab === 'dashboard' ? ['#dashboard-security-alerts', '#dashboard-attention-scroll'] : null;
        if (place) {
            const row = done.ids && done.ids.map(id => document.querySelector(`${place[0]} [data-key="alert-${Number(id)}"]`)).find(Boolean);
            const target = row ? [...row.querySelectorAll('button')].find(b => b.textContent.trim() === 'Dismiss') : document.querySelector(place[1]);
            if (target) target.focus({ preventScroll: false });
        }
        showToast(back ? `${back} in Needs attention` : 'Nothing to undo: dismissed again since', back ? 'success' : 'info');
    } catch (e) {
        showToast(`Could not undo: ${e.message || 'no answer'}.`, 'error', { duration: Infinity, action: { label: 'Retry', ariaLabel: `Retry: ${undoName}`, onAction: () => undoAlertDismissal(receipt, undoName) } });
    }
}

// The figures' trends (/api/stats/trends): loaded with the Dashboard and every five minutes, painted
// into each figure's place, and again whenever a card is drawn anew
const DASH_TRENDS = {
    storage_used: { label: 'Mail storage used', format: v => `${Math.round(v)}%` },
    security_review: { label: 'Addresses to review', format: v => `${Math.round(v)}`, feature: 'netfilter' },
    security_banned: { label: 'Addresses banned', format: v => `${Math.round(v)}`, feature: 'netfilter' },
};
let dashboardTrends = null;
let dashboardTrendsAt = 0;

async function loadDashboardTrends() {
    dashboardTrendsAt = Date.now();
    const names = Object.keys(DASH_TRENDS).filter(n => !DASH_TRENDS[n].feature || !isFeatureDisabled(DASH_TRENDS[n].feature));
    try {
        const res = await authenticatedFetch(`/api/stats/trends?names=${names.join(',')}&days=7`);
        if (!res.ok) return;
        dashboardTrends = (await res.json()).trends || {};
        paintDashboardTrends();
    } catch (e) {
        console.warn('Failed to load trends:', e);
    }
}

function paintDashboardTrends() {
    document.querySelectorAll('.ui-spark[data-trend]').forEach(el => {
        const name = el.dataset.trend, meta = DASH_TRENDS[name];
        if (!meta || !dashboardTrends || !(name in dashboardTrends)) { el.innerHTML = ''; return; }
        el.innerHTML = uiSparkline(dashboardTrends[name], { days: 7, label: meta.label, format: meta.format });
    });
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
    renderDashboardSecurity(page || dashboardSecurityPage);
}

let dashboardSecurityPage = null;
let dashboardProtectionsOpen = false;   // the protection line folds out into every protection

function renderDashboardSecurity(page = dashboardSecurityPage) {
    dashboardSecurityPage = page;
    const box = document.getElementById('dashboard-security');
    if (!box) return;
    // Without Fail2ban's answer neither list is known (its bans and lists are missing)
    const known = !page || page.fail2ban_known !== false;
    const counts = page && known ? page.all_counts : null;
    const n = key => counts ? Number(counts[key]).toLocaleString() : page ? 'Unknown' : '-';
    const protections = securityProtectionItems();
    const on = protections.filter(securityProtectionOn);
    // The line's own mark: a tick when anything acts, an eye when everything on only watches
    const lineState = on.some(p => p.state === 'on') ? 'on' : on.length ? 'watch' : 'off';
    box.innerHTML = `
        <div class="ui-stats ui-dash-sec-stats">
            <button type="button" class="ui-stat" onclick="openSecurityList('review')"><span>To review</span><b>${n('review')}</b><small>${known ? 'Not banned' : 'Fail2ban did not answer'}</small><span class="ui-spark" data-trend="security_review"></span></button>
            <button type="button" class="ui-stat" onclick="openSecurityList('banned')"><span>Banned now</span><b${counts && counts.banned ? ' class="ui-text-fail"' : ''}>${n('banned')}</b><small>${known ? 'By Fail2ban and the rules' : 'Fail2ban did not answer'}</small><span class="ui-spark" data-trend="security_banned"></span></button>
        </div>
        <button type="button" class="ui-dash-sec-prot is-${lineState}" aria-expanded="${dashboardProtectionsOpen}" aria-controls="dashboard-protections"
            onclick="dashboardProtectionsOpen = !dashboardProtectionsOpen; renderDashboardSecurity()">
            <span class="ui-prot-mark" aria-hidden="true">${securityProtectionMark(lineState)}</span><b>Protection ${on.length} of ${protections.length} on</b><span class="ui-dash-sec-chev" aria-hidden="true"></span>
            ${on.length && !dashboardProtectionsOpen ? `<span class="ui-dash-sec-on">${on.map(p => escapeHtml(p.name)).join(' · ')}</span>` : ''}
        </button>
        ${dashboardProtectionsOpen ? `<div id="dashboard-protections" class="ui-dash-sec-list">${protections.map(p => securityProtectionButton(p, 'openSecurityProtection')).join('')}</div>` : ''}`;
    paintDashboardTrends();
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
            if (c.known === false || !info.correlation_status) setDashKpi('dash-kpi-linking', 'Unknown', '', 'Could not count');
            else setDashKpi('dash-kpi-linking', `${c.completion_rate || 0}%`, c.incomplete ? 'warn' : '',
                `${(c.complete || 0).toLocaleString()} of ${(c.total || 0).toLocaleString()} complete`);
        }
        if (versionRes.ok) {
            const v = await versionRes.json();
            setDashKpi('dash-kpi-version', v.current_version || '-', '', v.update_available ? `${v.latest_version} available`
                : v.latest_version === 'unknown' ? 'Update check failed' : 'Up to date');
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
        if (storage.known === false) setDashKpi('dash-kpi-storage', 'Unknown', '', 'mailcow did not answer');
        else setDashKpi('dash-kpi-storage', `${storage.used_percent || '0%'} used`, storageLevel, `${storage.used || '0'} of ${storage.total || '0'}`);

        const systemDiv = document.getElementById('dashboard-system-summary');
        const system = data.system || {};
        systemDiv.innerHTML = `
            <div class="ui-kv"><span>Domains</span><b>${Number(system.domains || 0).toLocaleString()}</b></div>
            <div class="ui-kv"><span>Mailboxes</span><b>${Number(system.mailboxes || 0).toLocaleString()}</b></div>
            <div class="ui-kv"><span>Aliases</span><b>${Number(system.aliases || 0).toLocaleString()}</b></div>
        `;
    } catch (error) {
        console.error('Failed to load status summary:', error);
    }
}

// =============================================================================
// NETFILTER LOGS
// =============================================================================

// The filters an entity card opened the Events with ("Show security events",
// openSecurityEventsFor in security.js): an IP or an account matched whole, or
// the accounts on a domain, over the card's period. They hold until the IP or
// Username field it filled is changed or cleared (another condition added keeps
// them); a chip beside the count names them and takes them off. Filters set any
// other way (the search's address row, an alert, Security's own links) drop
// them: they hold only while the filters in use are the ones they made
// (filters). The CSV export sends them too (currentFilters.netfilter).
let netfilterExact = null;   // { ip, username, domain, start_date, end_date, period, filters } or null

function netfilterFilterFields() {
    return {
        ip: document.getElementById('netfilter-filter-ip').value,
        username: document.getElementById('netfilter-filter-username').value,
        action: document.getElementById('netfilter-filter-action').value,
        country_code: document.getElementById('netfilter-filter-country').value
    };
}

// The fields' filters with the whole-value ones that still hold
function netfilterWithExact(fields) {
    // Filters set since by anything but the card's (an alert, the search): its whole values went with them
    if (netfilterExact && netfilterExact.filters && currentFilters.netfilter !== netfilterExact.filters) netfilterExact = null;
    const x = netfilterExact;
    if (x && ((x.ip && (fields.ip || '') !== x.ip) || (x.username && (fields.username || '') !== x.username))) netfilterExact = null;
    if (!netfilterExact) return fields;
    const filters = {
        ...fields, ...(x.ip ? { exact_ip: 'true' } : {}), ...(x.username ? { exact_username: 'true' } : {}),
        ...(x.domain ? { username_domain: x.domain } : {}),
        ...(x.start_date ? { start_date: x.start_date } : {}), ...(x.end_date ? { end_date: x.end_date } : {}),
    };
    x.filters = filters;
    return filters;
}

// The chip, as the Security Overview's country and network chips (security.js renderSecurityOverview)
function renderNetfilterExact() {
    // Filters set since by anything but the card's: its whole values went with them
    if (netfilterExact && netfilterExact.filters && currentFilters.netfilter !== netfilterExact.filters) netfilterExact = null;
    const slot = document.getElementById('netfilter-exact');
    if (!slot) return;
    const x = netfilterExact;
    const what = !x ? '' : x.ip ? ['IP', x.ip] : x.username ? ['Account', x.username] : x.domain ? ['Accounts on', x.domain] : '';
    slot.innerHTML = what ? `<span class="ui-sec-filter" title="Matched whole, not as a part of a longer value"><span>${escapeHtml(what[0])} <bdi>${escapeHtml(what[1])}</bdi>${x.period ? `, ${escapeHtml(x.period)}` : ''}</span><button type="button" onclick="clearNetfilterExact()" aria-label="Remove this filter" title="Remove this filter">&times;</button></span>` : '';
}

// The chip's X: the whole values go, with the fields they had set, and the period
function clearNetfilterExact() {
    if (netfilterExact) {
        if (netfilterExact.ip) document.getElementById('netfilter-filter-ip').value = '';
        if (netfilterExact.username) document.getElementById('netfilter-filter-username').value = '';
    }
    netfilterExact = null;
    applyNetfilterFilters();
}

function applyNetfilterFilters() {
    currentFilters.netfilter = netfilterWithExact(netfilterFilterFields());
    currentPage.netfilter = 1;
    loadNetfilterLogs();
}

function clearNetfilterFilters() {
    document.getElementById('netfilter-filter-ip').value = '';
    document.getElementById('netfilter-filter-username').value = '';
    document.getElementById('netfilter-filter-action').value = '';
    document.getElementById('netfilter-filter-country').value = '';
    netfilterExact = null;
    currentFilters.netfilter = {};
    currentPage.netfilter = 1;
    loadNetfilterLogs();
}

async function loadNetfilterLogs(page = 1) {
    const container = document.getElementById('netfilter-logs');
    uiFilterBarSync();
    renderNetfilterExact();

    try {
        container.innerHTML = '<div class="ui-loading" role="status"><div class="loading"></div><p>Loading...</p></div>';

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
let fail2banLegacy = [];         // single IPv6 addresses an earlier version wrote as /32 networks
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
        fail2banLegacy = data.legacy_entries || [];
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
    if (!securityListsTyping()) renderSecurityLists();
    if (!securityEditing()) renderSecuritySettings();
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
// Suppress shows only while the app keeps a suppression list (Sync with Rspamd
// on), read again with each load; unknown (an error, Suppressions off) shows none
let queueSuppressOn = false;
// Loads and auto refreshes share one order: an answer older than the one
// drawn is dropped, so neither undoes a newer one
let queueAsked = 0;
let queueApplied = 0;
let queueLoading = false;  // the list shows Loading until an answer draws it

function queueListKept() {
    return authenticatedFetch('/api/suppressions/config')
        .then(r => (r.ok ? r.json() : null))
        .then(config => !!(config && config.list_kept === true))
        .catch(() => false);
}

// Whether the answer of request id may be drawn (no newer one was); takes its turn
function queueTakeTurn(id) {
    if (id < queueApplied) return false;
    queueApplied = id;
    return true;
}

async function loadQueue() {
    const container = document.getElementById('queue-logs');
    uiFilterBarSync();
    const id = ++queueAsked;

    try {
        container.innerHTML = '<div class="ui-loading" role="status"><div class="loading"></div><p>Loading...</p></div>';
        queueLoading = true;

        console.log('Loading Queue...');

        const kept = queueListKept();
        const response = await authenticatedFetch('/api/queue');
        if (!response.ok) {
            throw await responseError(response);
        }

        const data = await response.json();
        console.log('Queue data:', data);
        await rwStatusReady;
        const listKept = await kept;
        if (!queueTakeTurn(id)) return;

        queueLoading = false;
        queueSuppressOn = listKept;
        allQueueData = data.data || [];
        updateQueueSummary();
        applyQueueFilters();
    } catch (error) {
        if (!queueTakeTurn(id)) return;
        queueLoading = false;
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

// A list's checked rows across a redraw: checked again by value, the ones
// gone (or filtered out) dropped, and its selection bar told
function keepCheckedRows(selector, draw, update) {
    const checked = new Set([...document.querySelectorAll(`${selector}:checked`)].map(cb => cb.value));
    draw();
    if (!checked.size) return;
    document.querySelectorAll(selector).forEach(cb => { if (checked.has(cb.value)) cb.checked = true; });
    update();
}

// Set while a queue action runs: the refresh leaves the list alone until it is done
let queueActing = 0;

function applyQueueFilters() {
    keepCheckedRows('.queue-checkbox', drawQueueRows, queueUpdateSelection);
}

function drawQueueRows() {
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
        countEl.textContent = uiCountLabel(filteredData.length, 'message', 'messages');
    }

    if (filteredData.length === 0) {
        container.innerHTML = '<p class="ui-empty">No matching queue entries</p>';
        return;
    }

    const canAct = mailcowRwConfigured;

    const lockedNote = canAct ? '' : `<div class="ui-list-note">${uiLocked('Queue actions are locked', `Retry, hold, release, delete and flush ${UI_RW_KEY_TEXT}`)}</div>`;
    const cols = canAct
        ? '--ui-cols: 20px minmax(200px, 1.6fr) 84px minmax(240px, 2.8fr) 70px 318px; --ui-table-min: 1000px'
        : '--ui-cols: minmax(200px, 1.6fr) 84px minmax(240px, 2.8fr) 70px 104px; --ui-table-min: 740px';

    container.innerHTML = `
        ${lockedNote}
        <div class="ui-table ui-stack" data-sort-at="queue-filter-search" data-sort-name="mail queue" style="${cols}">
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
            <div class="ui-tr ui-tr-head">${canAct ? '<span></span>' : ''}<span data-sort-kind="text">Recipient</span><span data-sort-kind="text">State</span><span data-sort-kind="text">Last response</span><span class="ui-td-end" data-sort-kind="number">Size</span><span class="ui-td-end">Actions</span></div>
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
                const suppress = !queueSuppressOn ? '' : recipients.length === 1
                    ? `<button onclick="showAddSuppressionModal('${escapeJsArg(recipients[0].email)}', '${escapeJsArg(qid)}')" title="Suppress ${escapeHtml(recipients[0].email)}" class="ui-btn ui-btn-sm">Suppress</button>`
                    : uiMenu('Suppress', recipients.map(r => `<button type="button" role="menuitem" onclick="showAddSuppressionModal('${escapeJsArg(r.email)}', '${escapeJsArg(qid)}')">${escapeHtml(r.email)}</button>`).join(''));
                return `
                <div class="ui-tr ui-q-row" data-queue-id="${escapeHtml(qid)}">
                    ${canAct ? `<input type="checkbox" class="queue-checkbox ui-check" value="${escapeHtml(qid)}" onchange="queueUpdateSelection()" aria-label="Select ${escapeHtml(qid)}" />` : ''}
                    <div class="ui-td ui-q-who">
                        <div>${recipients.map(r => uiEntity('address', r.email)).join(', ')}</div>
                        <small>From ${uiEntity('address', item.sender)}, queued <span title="${escapeHtml(formatTime(queued))}">${formatAgo(queued)}</span>, ID ${copyableText(qid)}</small>
                    </div>
                    <span class="ui-td">${uiTag(stateText, queueTone)}</span>
                    <div class="ui-td ui-td-wrap ui-mono ui-q-resp">${responses.length
                        ? responses.map(r => `<div>${recipients.length > 1 ? `<span class="ui-muted">${escapeHtml(r.email)}:</span> ` : ''}${escapeHtml(r.response)}</div>`).join('')
                        : `<span class="ui-muted">${isHold ? 'Put on hold' : '-'}</span>`}</div>
                    <span class="ui-td ui-td-end">${formatSize(item.message_size)}</span>
                    <span class="ui-td ui-td-end ui-row-actions">
                    ${canAct ? `
                        <button onclick="queueRetry('${escapeJsArg(qid)}')" title="Retry delivery" class="queue-action-btn ui-btn ui-btn-sm">Retry</button>
                        ${isHold
                            ? `<button onclick="queueUnhold('${escapeJsArg(qid)}')" title="Release from hold" class="queue-action-btn ui-btn ui-btn-sm">Unhold</button>`
                            : `<button onclick="queueHold('${escapeJsArg(qid)}')" title="Hold message" class="queue-action-btn ui-btn ui-btn-sm">Hold</button>`}
                        <button onclick="queueDeleteItem('${escapeJsArg(qid)}')" title="Delete from queue" class="queue-action-btn ui-btn ui-btn-sm ui-btn-danger">Delete</button>` : ''}
                        ${suppress}
                    </span>
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
    const selectAll = document.getElementById('queue-select-all-btn');
    const rows = document.querySelectorAll('.queue-checkbox').length;
    if (selectAll) selectAll.textContent = rows && checked.length === rows ? 'Deselect All' : 'Select All';

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
    queueActing++;
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
        queueActing--;
        document.querySelectorAll('.queue-action-btn, .queue-checkbox, #queue-flush-all-btn, #queue-delete-all-btn, #queue-select-all-btn, #queue-bulk-retry-btn, #queue-bulk-delete-btn')
            .forEach(el => { el.disabled = false; el.style.opacity = ''; });
    }
}

async function queueDeleteRequest(itemIds) {
    queueActing++;
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
        queueActing--;
        document.querySelectorAll('.queue-action-btn, .queue-checkbox, #queue-flush-all-btn, #queue-delete-all-btn, #queue-select-all-btn, #queue-bulk-retry-btn, #queue-bulk-delete-btn')
            .forEach(el => { el.disabled = false; el.style.opacity = ''; });
    }
}

// =============================================================================
// QUARANTINE
// =============================================================================

// Client-side sort state for the quarantine list ('newest' matches the backend default order)
// Last quarantine payload rendered (used to re-sort without re-fetching)
let quarantineLastData = null;

// Reject is the strong verdict; add header and the softer ones read as a warning
function quarantineActionTone(action) {
    return ['reject', 'discard'].includes(String(action || '').toLowerCase()) ? 'fail' : 'warn';
}


// Loads, refreshes and the reload after an action share one order: an answer
// older than the one drawn is dropped, so a handled message never comes back
let quarantineAsked = 0;
let quarantineApplied = 0;
let quarantineActing = 0;   // an action runs: the refresh leaves the list alone

function quarantineTakeTurn(id) {
    if (id < quarantineApplied) return false;
    quarantineApplied = id;
    return true;
}

async function loadQuarantine() {
    const container = document.getElementById('quarantine-logs');
    uiFilterBarSync();
    const id = ++quarantineAsked;

    try {
        container.innerHTML = '<div class="ui-loading" role="status"><div class="loading"></div><p>Loading...</p></div>';

        console.log('Loading Quarantine...');

        const response = await authenticatedFetch('/api/quarantine');
        if (!response.ok) {
            throw await responseError(response);
        }

        const data = await response.json();
        console.log('Quarantine data:', data);
        await rwStatusReady;
        if (!quarantineTakeTurn(id)) return;

        lastDataCache.quarantine = data;
        renderQuarantineData(data);
    } catch (error) {
        if (!quarantineTakeTurn(id)) return;
        // Nothing is shown: the next refresh draws what it gets, even an answer like the last one
        lastDataCache.quarantine = null;
        console.error('Failed to load quarantine:', error);
        document.getElementById('quarantine-logs').innerHTML = `<p class="ui-empty ui-text-fail">Failed to load quarantine: ${escapeHtml(error.message)}</p>`;
    }
}

// The list, also from the smart refresh and a new sort: checked rows stay checked
function renderQuarantineData(data) {
    keepCheckedRows('.quarantine-checkbox', () => drawQuarantineRows(data), quarantineUpdateSelection);
}

function drawQuarantineRows(data) {
    const container = document.getElementById('quarantine-logs');
    if (!container) return;

    // Keep the latest payload so sort changes can re-render without a re-fetch
    quarantineLastData = data;
    const summary = document.getElementById('quarantine-summary');
    const countEl = document.getElementById('quarantine-count');
    if (countEl) countEl.textContent = uiCountLabel(data.total || (data.data || []).length, 'message', 'messages');
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
    const items = data.data;

    const lockedNote = canAct ? '' : `<div class="ui-list-note">${uiLocked('Quarantine actions are locked', `Release, delete, spam learning and the auto-rules ${UI_RW_KEY_TEXT}`)}</div>`;
    const cols = canAct
        ? '--ui-cols: 20px minmax(200px, 2fr) minmax(150px, 1.3fr) minmax(120px, 1fr) 56px 64px 336px; --ui-table-min: 1080px'
        : '--ui-cols: minmax(200px, 2fr) minmax(150px, 1.3fr) minmax(120px, 1fr) 56px 64px 76px; --ui-table-min: 760px';

    container.innerHTML = `
        ${lockedNote}
        <div class="ui-table ui-stack" data-sort-at="quarantine-list-summary" data-sort-name="quarantined messages" data-sort-default="Held:desc" style="${cols}">
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
            <div class="ui-tr ui-tr-head">${canAct ? '<span></span>' : ''}<span data-sort-kind="text">Message</span><span data-sort-kind="text">For</span><span data-sort-kind="text">Why</span><span class="ui-td-end" data-sort-kind="number">Score</span><span data-sort-kind="date">Held</span><span class="ui-td-end">Actions</span></div>
            ${items.map(item => {
                const itemId = item.id !== undefined ? item.id : '';
                const idArg = escapeJsArg(String(itemId));
                const hasScore = item.score !== undefined && item.score !== null;
                return `
                <div class="ui-tr ui-q-row" data-quarantine-id="${escapeHtml(String(itemId))}" onclick="quarantineRowClick(event, '${idArg}')">
                    ${canAct ? `<input type="checkbox" class="quarantine-checkbox ui-check" value="${escapeHtml(String(itemId))}" onchange="quarantineUpdateSelection()" aria-label="Select message" />` : ''}
                    <div class="ui-td ui-q-who">
                        <button type="button" class="ui-link-row" dir="auto" title="View details" onclick="showQuarantineDetails('${idArg}')">${escapeHtml(item.subject || 'No subject')}</button>
                        <small>${item.sender ? uiEntity('address', item.sender, { plain: true }) : 'Unknown'}${item.qid ? `, ID ${escapeHtml(item.qid)}` : ''}</small>
                    </div>
                    <span class="ui-td">${item.rcpt ? uiEntity('address', item.rcpt, { plain: true }) : 'Unknown'}</span>
                    <span class="ui-td ui-td-wrap">${uiTag(item.action || 'Quarantined', quarantineActionTone(item.action))}${item.virus_flag ? ` ${uiTag('Virus', 'spam')}` : ''}</span>
                    <span class="ui-td ui-td-end${hasScore && item.score >= 15 ? ' ui-text-fail' : ''}"${hasScore && isFinite(Number(item.score)) ? ` data-sort="${Number(item.score)}"` : ''}><small class="ui-sec-unit">Score </small>${hasScore ? item.score.toFixed(1) : '-'}</span>
                    <time class="ui-td" title="${escapeHtml(formatTime(item.created))}"${isFinite(Date.parse(item.created)) ? ` data-sort="${Date.parse(item.created)}"` : ''}><small class="ui-sec-unit">Held </small>${formatAgo(item.created).replace(' ago', '')}</time>
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
    if (event.target.closest('button, a, input, select, label, .copyable, .ui-ent, [role="menu"]') || uiRowHeld(event)) return;
    showQuarantineDetails(itemId);
}

function quarantineUpdateSelection() {
    const checked = document.querySelectorAll('.quarantine-checkbox:checked');
    const bulkBtns = ['quarantine-bulk-release-btn', 'quarantine-bulk-delete-btn', 'quarantine-bulk-learnham-btn', 'quarantine-bulk-learnspam-btn'];
    const countLabel = document.getElementById('quarantine-selection-count');
    const selectAll = document.getElementById('quarantine-select-all-btn');
    const rows = document.querySelectorAll('.quarantine-checkbox').length;
    if (selectAll) selectAll.textContent = rows && checked.length === rows ? 'Deselect All' : 'Select All';

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
    quarantineActing++;

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
        quarantineActing--;
        document.querySelectorAll(allBtns).forEach(el => { el.disabled = false; el.style.opacity = ''; });
    }
}

// --- Quarantine Detail View ---

async function showQuarantineDetails(itemId) {
    const existing = document.getElementById('quarantine-detail-modal');
    if (existing) existing.remove();

    uiDialog({
        id: 'quarantine-detail-modal', title: 'Quarantine Item Details', size: 'wide',
        close: closeQuarantineDetails, backdropClose: closeQuarantineDetails,
        bodyId: 'quarantine-detail-content',
        body: '<div class="ui-loading" role="status"><div class="loading"></div><p>Loading details...</p></div>',
        // Filled with the actions (or why they are locked) once the item has loaded
        footId: 'quarantine-detail-footer', footHidden: true,
    });
    document.body.style.overflow = 'hidden';

    try {
        const res = await authenticatedFetch(`/api/quarantine/${encodeURIComponent(itemId)}/details`);
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
        `<span class="ui-qd-rcpt"><small class="${r.type === 'smtp' ? 'ui-text-info' : 'ui-muted'}">${escapeHtml(r.type)}</small> ${uiEntity('address', r.address)}</span>`
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

    // mailcow sends a literal '-' as text_plain when the message has no plain-text part;
    // text_html is already converted to plain text by mailcow, so fall back to it.
    const plainText = (data.text_plain || '').trim();
    const textContent = (plainText && plainText !== '-') ? data.text_plain : (data.text_html || '');
    const canAct = mailcowRwConfigured;

    content.innerHTML = `
        <div class="ui-qd">
            <div class="ui-md-ids ui-qd-facts">
                <div class="ui-md-fact ui-qd-wide"><span>Subject</span><div dir="auto">${copyableText(data.subject || '-')}</div></div>
                <div class="ui-md-fact"><span>From (Header)</span><div>${uiEntity('address', data.header_from || '-')}</div></div>
                <div class="ui-md-fact"><span>Envelope From</span><div class="ui-mono">${uiEntity('address', data.env_from || '-', { mono: true })}</div></div>
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
            <button onclick="closeQuarantineDetails(); quarantineLearnSpam('${escapeJsArg(itemId)}')" class="ui-btn" title="Delete & train as Spam">Spam</button>
            <button onclick="closeQuarantineDetails(); quarantineLearnHam('${escapeJsArg(itemId)}')" class="ui-btn" title="Release & train as Not Spam">Not Spam</button>
            <span class="ui-toolbar-gap"></span>
            <button onclick="closeQuarantineDetails(); quarantineDelete('${escapeJsArg(itemId)}')" class="ui-btn ui-btn-danger">Delete</button>
            <button onclick="closeQuarantineDetails(); quarantineRelease('${escapeJsArg(itemId)}')" class="ui-btn ui-btn-primary">Release</button>
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

// Show one tab of a page with tabs: its button, its panel
function showPageTab(page, tab) {
    Object.keys(TAB_FEATURES[page]).forEach(name => {
        const btn = document.getElementById(`${page}-tab-btn-${name}`);
        if (btn) { btn.classList.toggle('active', name === tab); btn.setAttribute('aria-selected', name === tab); }
        const panel = document.getElementById(`${page}-tab-${name}`);
        if (panel) panel.classList.toggle('hidden', name !== tab);
    });
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

// Outbound tabs: the mail waiting to leave, and the recipients it is no
// longer sent to (spam_filter.js). Each has its own feature.
let outboundTab = 'queue';
function outboundShowTab(tab, load = true) {
    const asked = tab;
    tab = pageTabOn('outbound', tab);
    outboundTab = tab;
    routerSyncSubpage('outbound', tab, tab !== asked);
    showPageTab('outbound', tab);
    if (!load || currentTab !== 'outbound') return;
    // An opened tab shows what is there now, as the page did on its own
    if (tab === 'suppressions') loadSuppressionsTab();
    else if (!isFeatureDisabled('queue')) loadQueue();
}

// The page opened: the queue (also for the summary and the sidebar counter),
// and the suppressions: their list on their tab, otherwise their count
function loadOutbound() {
    applyTabFeatures('outbound');
    const queueOn = !isFeatureDisabled('queue'), suppressionsOn = !isFeatureDisabled('suppressions');
    const queueSummary = document.getElementById('queue-summary');
    const suppressionSummary = document.getElementById('suppression-summary');
    if (queueSummary && !queueOn) queueSummary.textContent = '';
    if (suppressionSummary && !suppressionsOn) suppressionSummary.textContent = '';
    if (queueOn) loadQueue();
    outboundShowTab(outboundTab, false);
    if (outboundTab === 'suppressions') loadSuppressionsTab();
    else if (suppressionsOn) loadSuppressionStats();
}

// quiet (the refresh): a read that fails leaves the rules shown as they are
async function loadQuarantineRules({ quiet = false } = {}) {
    const container = document.getElementById('quarantine-rules-list');
    if (!container) return;
    
    try {
        const res = await authenticatedFetch('/api/quarantine/rules', quiet ? { timeout: PAGE_REFRESH_TIMEOUT } : {});
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        _quarantineRulesCache = data;
        
        const countEl = document.getElementById('quarantine-rules-count');
        const activeCount = data.data.filter(r => r.enabled).length;
        if (countEl) countEl.textContent = uiCountLabel(data.data.length, 'rule', 'rules');
        const tabCount = document.getElementById('quarantine-tab-n-rules');
        if (tabCount) { tabCount.textContent = activeCount || ''; tabCount.classList.toggle('hidden', !activeCount); }
        
        // Drawn again only when something changed, the focus kept on its row (the refresh calls this too)
        if (!data.data || data.data.length === 0) {
            uiReplaceKeepingFocus(container, '<p class="ui-empty">No rules configured. Click "Add Rule" to create one.</p>');
            return;
        }
        
        uiReplaceKeepingFocus(container, `<div class="ui-table ui-stack ui-qr-table">${data.data.map(rule => {
            const matchLabels = { sender: 'Sender', sender_domain: 'Sender Domain', recipient: 'Recipient', subject: 'Subject' };
            const actionLabel = rule.action === 'delete' ? 'Delete' : 'Release';
            const repair = quarantineRuleRepair(rule);

            return `
            <div class="ui-tr${rule.enabled ? '' : ' ui-row-off'}" data-key="rule-${Number(rule.id)}">
                <div class="ui-td ui-q-who">
                    <div><b dir="auto">${escapeHtml(rule.name)}</b> ${uiTag(actionLabel, rule.action === 'delete' ? 'fail' : 'ok')}
                        ${rule.is_regex ? uiTag('Regex', 'info') : ''} ${!rule.enabled ? uiTag('Disabled', '') : ''} ${repair ? uiTag('Check', 'warn') : ''}</div>
                    <small>${escapeHtml(matchLabels[rule.match_type] || rule.match_type)}: <code class="ui-mono" dir="auto">${escapeHtml(rule.match_value)}</code></small>
                    ${repair ? '<small class="ui-text-warn">Looks for a backslash. An earlier version may have changed this rule when it was edited.</small>' : ''}
                    <small>Hits: ${escapeHtml(String(rule.hit_count))}${rule.last_hit_at ? ' · Last: ' + formatTime(rule.last_hit_at) : ''}${rule.notes ? ' · ' + escapeHtml(rule.notes) : ''}</small>
                </div>
                <span class="ui-td ui-td-end ui-row-actions">
                    ${repair ? `<button onclick="repairQuarantineRule(${Number(rule.id)})" title="${escapeHtml(`Look for "${repair.text}" instead`)}" class="ui-btn ui-btn-sm">Repair</button>` : ''}
                    <button onclick="toggleQuarantineRule(${Number(rule.id)})" title="${rule.enabled ? 'Click to disable this rule' : 'Click to enable this rule'}"
                        class="ui-btn ui-btn-sm${rule.enabled ? ' ui-btn-on' : ''}">${rule.enabled ? 'Enabled' : 'Disabled'}</button>
                    <button onclick="showEditQuarantineRuleModal(${Number(rule.id)})" title="Edit" class="ui-btn ui-btn-sm">Edit</button>
                    <button onclick="deleteQuarantineRule(${Number(rule.id)}, '${escapeJsArg(rule.name)}')" title="Delete" class="ui-btn ui-btn-sm ui-btn-danger">Delete</button>
                </span>
            </div>`;
        }).join('')}</div>`);
    } catch (err) {
        console.error('Failed to load quarantine rules:', err);
        if (quiet && _quarantineRulesCache) return;
        uiReplaceKeepingFocus(container, `<p class="ui-empty ui-text-fail">Failed to load rules: ${escapeHtml(err.message)}</p>`);
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

// A Contains rule is saved as a regex that only escapes its text. Read such a
// rule back as Contains with the plain text, so saving it again does not escape
// it twice; any other regex is Regex, with or without a leading ^.
const QRULE_REGEX_SPECIAL = '.*+?^${}()|[]\\';
function quarantineRuleMatchMode(rule) {
    const value = rule.match_value || '';
    if (!rule.is_regex) return { mode: 'exact', value };
    let text = '';
    for (let i = 0; i < value.length; i++) {
        if (value[i] === '\\' && i + 1 < value.length && QRULE_REGEX_SPECIAL.includes(value[i + 1])) {
            text += value[++i];
        } else if (QRULE_REGEX_SPECIAL.includes(value[i])) {
            return { mode: 'regex', value };
        } else {
            text += value[i];
        }
    }
    return { mode: 'contains', value: text };
}

// Earlier versions escaped a Contains rule's text again when it was edited, so
// the rule came to look for backslashes. A Contains rule whose text is itself
// only escaped text may be one of those: its Repair saves that text as the
// pattern, which removes one level of escaping. Null for any other rule.
function quarantineRuleRepair(rule) {
    const ruleMode = quarantineRuleMatchMode(rule);
    if (ruleMode.mode !== 'contains' || !ruleMode.value.includes('\\')) return null;
    const once = quarantineRuleMatchMode({ is_regex: true, match_value: ruleMode.value });
    return once.mode === 'contains' ? { pattern: ruleMode.value, text: once.value } : null;
}

function _showQuarantineRuleModal(rule, prefill) {
    const isEdit = !!rule;
    const title = isEdit ? 'Edit Rule' : 'Add Quarantine Rule';
    const ruleMode = isEdit ? quarantineRuleMatchMode(rule) : { mode: 'exact', value: '' };

    // Determine default values: edit mode uses rule data, prefill uses quarantine data
    const defaultName = isEdit ? escapeHtml(rule.name) : (prefill ? escapeHtml(`Rule for ${prefill.sender}`) : '');
    const defaultMatchType = isEdit ? rule.match_type : (prefill ? 'sender' : 'sender');
    const defaultMatchValue = isEdit ? escapeHtml(ruleMode.value) : (prefill ? escapeHtml(prefill.sender) : '');
    const defaultAction = isEdit ? rule.action : 'release';
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

    const body = `
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
                            <option value="release" ${defaultAction === 'release' ? 'selected' : ''}>Release</option>
                            <option value="delete" ${defaultAction === 'delete' ? 'selected' : ''}>Delete</option>
                        </select>
                    </label>
                </div>
                <label><span class="ui-label">Match Value</span>
                    <input type="text" id="qrule-match-value" value="${defaultMatchValue}" class="ui-input ui-mono" placeholder="e.g., noreply@example.com">
                </label>
                <label><span class="ui-label">Match Mode</span>
                    <select id="qrule-match-mode" onchange="updateQRuleMatchHelp()" class="ui-select">
                        <option value="exact" ${ruleMode.mode === 'exact' ? 'selected' : ''}>Exact Match - matches the full value exactly</option>
                        <option value="contains" ${ruleMode.mode === 'contains' ? 'selected' : ''}>Contains - matches if value appears anywhere</option>
                        <option value="regex" ${ruleMode.mode === 'regex' ? 'selected' : ''}>Regex (advanced) - custom regular expression</option>
                    </select>
                    <small id="qrule-match-help" class="ui-muted"></small>
                </label>
                <label><span class="ui-label">Notes (optional)</span>
                    <textarea id="qrule-notes" rows="2" class="ui-textarea" placeholder="Why this rule exists...">${defaultNotes}</textarea>
                </label>
                <div class="ui-alert ui-alert-warn ui-qr-note">
                    <span class="ui-alert-bar"></span>
                    <div class="ui-alert-text"><p><b>Priority:</b> Delete rules always take priority over Release rules. If both match, the email will be deleted.</p></div>
                </div>`;

    uiDialog({
        id: 'quarantine-rule-modal-overlay', title, size: 'sm', close: closeQuarantineRuleModal, bodyClass: 'ui-form', body,
        foot: `<button onclick="closeQuarantineRuleModal()" class="ui-btn">Cancel</button>
            <button onclick="saveQuarantineRule(${isEdit ? Number(rule.id) : 'null'})" class="ui-btn ui-btn-primary">${isEdit ? 'Save Changes' : 'Create Rule'}</button>`,
    });
    updateQRuleMatchHelp();
    uiGuardDialog(document.getElementById('quarantine-rule-modal-overlay'));
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

// Close, Cancel, Escape and Back ask before dropping typed changes; a save closes at once
function closeQuarantineRuleModal(saved = false) {
    const overlay = document.getElementById('quarantine-rule-modal-overlay');
    if (!overlay) return;
    if (saved) {
        uiDialogSaved(overlay);
        overlay.remove();
    } else uiCloseGuarded(overlay, () => overlay.remove());
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
    await _submitQuarantineRule(ruleId, body);
}

// Create (ruleId null) or update a rule, then draw the list again
async function _submitQuarantineRule(ruleId, body, doneMessage) {
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
        
        closeQuarantineRuleModal(true);
        showToast(doneMessage || (isEdit ? 'Rule updated' : 'Rule created'), 'success');
        await loadQuarantineRules();
    } catch (err) {
        showToast('Failed to save rule: ' + err.message, 'error');
    }
}

async function repairQuarantineRule(ruleId) {
    const rule = _quarantineRulesCache?.data?.find(r => r.id === ruleId);
    const repair = rule && quarantineRuleRepair(rule);
    if (!repair) { showToast('Rule not found', 'error'); return; }
    await _submitQuarantineRule(ruleId, {
        name: rule.name, match_type: rule.match_type, match_value: repair.pattern,
        is_regex: true, action: rule.action, notes: rule.notes || null,
    }, 'Rule repaired');
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
    const opener = layerLastAction || document.activeElement;
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
                    <div>${uiEntity('address', m.sender || '?', { plain: true })} → ${uiEntity('address', m.recipient || '?', { plain: true })}</div>
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

        document.getElementById('qrule-test-modal')?.remove();
        uiLayerOpener(opener);
        // Results only, nothing typed: a click outside closes it
        const closeTest = () => document.getElementById('qrule-test-modal')?.remove();
        uiDialog({
            id: 'qrule-test-modal', title: 'Test Results', size: 'sm', close: closeTest, backdropClose: closeTest, bodyClass: 'ui-form',
            body: `
                    <div class="ui-kpis">
                        <div class="ui-kpi"><b>${escapeHtml(String(data.total_matches))}</b>matched</div>
                        <div class="ui-kpi"><b class="ui-muted">${escapeHtml(String(data.total_quarantine))}</b>total</div>
                    </div>
                    ${disabledCount > 0 ? `<p class="ui-text-warn">${disabledCount} from disabled rules</p>` : ''}
                    ${noMatches ? '<p class="ui-empty">No quarantine items matched any rules.</p>' : groupsHtml}
                    <p class="ui-kv-note ui-list-foot">This is a dry-run preview. No actions were taken.</p>`,
        });
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

// quiet (the refresh): no Loading, and drawn again only when something changed
async function loadQuarantineRuleHistory({ quiet = false } = {}) {
    const container = document.getElementById('quarantine-rules-history-list');
    if (!container) return;
    
    if (!quiet) uiReplaceKeepingFocus(container, '<p class="ui-empty">Loading...</p>');

    try {
        const res = await authenticatedFetch('/api/quarantine/rules/logs?limit=20', quiet ? { timeout: PAGE_REFRESH_TIMEOUT } : {});
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        if (!data.data || data.data.length === 0) {
            uiReplaceKeepingFocus(container, '<p class="ui-empty">No actions recorded yet</p>');
            return;
        }

        uiReplaceKeepingFocus(container, `<div class="ui-qt-history">${data.data.map(log => `
            <div class="ui-qt-hrow">
                ${uiTag(log.action, log.action === 'delete' ? 'fail' : 'ok')}
                <span class="ui-q-who" title="${escapeHtml(log.sender || '')} → ${escapeHtml(log.recipient || '')}">${uiEntity('address', log.sender || '?', { plain: true })} → ${uiEntity('address', log.recipient || '?', { plain: true })}</span>
                ${uiTime(log.created_at, formatTime(log.created_at), { title: `Rule: ${log.rule_name || ''}`, cls: 'ui-muted' })}
            </div>
        `).join('')}</div>`);
    } catch (err) {
        // A refresh that failed leaves the history as it was
        if (quiet) return;
        uiReplaceKeepingFocus(container, `<p class="ui-empty ui-text-fail">Failed: ${escapeHtml(err.message)}</p>`);
    }
}

// =============================================================================
// MESSAGES TAB (UNIFIED VIEW)
// =============================================================================

function applyMessagesFilters() {
    currentFilters.messages = messagesWithExact({
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
    });
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
    // Filters set since by anything but the card's (openMessagesRange, a search): its whole values went with them
    if (messagesExact && messagesExact.filters && currentFilters.messages !== messagesExact.filters) messagesExact = null;
    const f = currentFilters.messages || {};
    const advanced = ['sender', 'recipient', 'user', 'ip', 'address', 'domain'].filter(k => f[k]).length;
    const any = advanced || f.search || f.status || f.direction || f.start_date || f.end_date || f.date_range;
    const badge = document.getElementById('messages-filters-n');
    if (badge) { badge.textContent = advanced || ''; badge.classList.toggle('hidden', !advanced); }
    const button = document.getElementById('messages-filters-btn');
    if (button) button.setAttribute('aria-label', advanced ? `Filters, ${advanced} in use` : 'Filters');
    const clear = document.getElementById('messages-clear-filters');
    if (clear) clear.classList.toggle('hidden', !any);
    // The whole values an entity card set, as the Security page's filter chip (security.js renderSecurityOverview)
    const chips = document.getElementById('messages-exact');
    if (chips) {
        const parts = f.exact && messagesExact ? messagesExactParts(messagesExact) : [];
        chips.innerHTML = parts.length ? `<span class="ui-sec-filter" title="Matched whole, not as a part of a longer value. While this is on, a sender, recipient, user or IP added is matched whole too"><span>${parts.map(([label, value]) =>
            `${escapeHtml(label)} <bdi>${escapeHtml(value)}</bdi>`).join(', ')}</span><button type="button" onclick="clearMessagesExact()" aria-label="Remove this filter" title="Remove this filter">&times;</button></span>` : '';
    }
}

function clearMessagesFilters() {
    document.getElementById('messages-filter-search').value = '';
    document.getElementById('messages-filter-sender').value = '';
    document.getElementById('messages-filter-recipient').value = '';
    document.getElementById('messages-filter-direction').value = '';
    document.getElementById('messages-filter-user').value = '';
    document.getElementById('messages-filter-status').value = '';
    document.getElementById('messages-filter-ip').value = '';
    messagesExact = null;
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

// They are pickers (utils.js, uiPicker): this opens one, or closes them and gives the focus back
function toggleMessagesPicker(kind, open) {
    if (kind && open !== false) {
        uiPickerOpen(`messages-${kind}`);
        return;
    }
    MESSAGES_PICKERS.forEach(k => {
        if (uiPickerIsOpen(`messages-${k}`)) uiPickerClose(`messages-${k}`, { returnFocus: true });
    });
}

// The custom range in the Time picker starts from the one in use
function messagesTimePanelOpened() {
    document.getElementById('messages-time-start').value = document.getElementById('messages-date-range-start').value;
    document.getElementById('messages-time-end').value = document.getElementById('messages-date-range-end').value;
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

// Where a Messages time preset starts ('' for all time): today is the day in the
// app's zone, and "Last 7 Days" is the last 7 x 24 hours, the same window as
// Mailbox Stats and the Dashboard, also across a daylight saving change
function messagesPresetStart(preset, now = new Date()) {
    if (preset === 'today') return zonedDayStart(zonedDateString(now)).toISOString();
    const days = { '7days': 7, '30days': 30, '90days': 90 }[preset];
    if (!days) return '';
    return new Date(new Date(now).getTime() - days * 86400000).toISOString();
}

// The filters as a request sends them: a time preset covers its period up to
// now, so its start is worked out at every request (Today moves to the next day
// at midnight) and it has no end; a custom range, or one opened from the chart,
// stays as it was chosen
const MESSAGES_ROLLING_PRESETS = ['today', '7days', '30days', '90days'];
function messagesRangeFilters(filters, now = new Date()) {
    if (!MESSAGES_ROLLING_PRESETS.includes(filters.date_range)) return filters;
    return { ...filters, start_date: messagesPresetStart(filters.date_range, now), end_date: '' };
}

// The Messages period set to a preset, without applying it
function messagesShowDatePreset(preset, now = new Date()) {
    const labels = { '': 'All Time', 'today': 'Today', '7days': 'Last 7 Days', '30days': 'Last 30 Days', '90days': 'Last 90 Days' };
    document.getElementById('messages-date-range-label').textContent = labels[preset] || 'All Time';
    document.getElementById('messages-date-range').value = preset;

    // The range the API reads; All Time has none
    const startDate = messagesPresetStart(preset, now);
    document.getElementById('messages-start-date').value = startDate;
    document.getElementById('messages-end-date').value = startDate ? new Date(now).toISOString() : '';

    setMessagesDatePresetActive(preset);
}

function selectMessagesDatePreset(preset, now = new Date()) {
    messagesShowDatePreset(preset, now);

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

    // The range is whole days in the app's zone: from the first day's start to the
    // last moment before the day after the last one (23 or 25 hours on a DST change)
    const startDate = zonedDayStart(startInput);
    const endDate = new Date(zonedDayStart(addDaysToDateString(endInput, 1)).getTime() - 1);

    if (startDate > endDate) {
        showToast('Start date must be before end date', 'warning');
        return;
    }

    document.getElementById('messages-date-range').value = 'custom';
    document.getElementById('messages-start-date').value = startDate.toISOString();
    document.getElementById('messages-end-date').value = endDate.toISOString();

    // The label names the days as picked
    const fmt = day => formatDayKey(day);
    document.getElementById('messages-date-range-label').textContent = `${fmt(startInput)} - ${fmt(endInput)}`;

    setMessagesDatePresetActive(null);

    // Close dropdown and apply
    document.getElementById('messages-date-range-dropdown').classList.add('hidden');
    document.getElementById('messages-date-range-arrow').style.transform = '';
    toggleMessagesTimePanel(false);
    applyMessagesFilters();
}

// Close messages date range picker on outside click
document.addEventListener('click', function(e) {
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
    filters = messagesRangeFilters(filters);
    const params = new URLSearchParams();
    for (const key of MESSAGES_FILTER_KEYS) {
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

// In the facets column the choices are toggle buttons; in a picker they are its options
function renderFacetList(kind, entries, counts, current, asOptions = false) {
    return entries.map(([value, label]) => {
        const count = counts ? counts[value || 'all'] : undefined;
        const tone = kind === 'status' && value ? (UI_STATUS_TONE[value] || '') : '';
        const state = asOptions ? `role="option" tabindex="-1" aria-selected="${String(current === value)}"` : `aria-pressed="${String(current === value)}"`;
        return `<button type="button" class="ui-fct" ${state} onclick="setMessagesFacet('${kind}', '${value}')">
            ${kind === 'status' && value ? `<i class="ui-fct-dot${tone ? ` ui-fct-${tone}` : ''}"></i>` : ''}${kind === 'direction' && value ? `<i class="ui-fct-dot ui-dir-${value}"></i>` : ''}<span>${escapeHtml(label)}</span>
            <small>${count === undefined ? '' : escapeHtml(String(count))}</small></button>`;
    }).join('');
}

// gen: the list these counts belong to; counts for an older list are dropped
async function loadMessageFacets(filters, gen = messagesGen) {
    const statusList = document.getElementById('messages-facet-status');
    const directionList = document.getElementById('messages-facet-direction');
    let data = null;
    try {
        const params = messagesFilterParams(filters);
        for (const preset of ['today', '7days', '30days', '90days']) params.append('since', `${preset}:${messagesPresetStart(preset)}`);
        const response = await messagesFetch(`/api/messages/facets?${params}`);
        if (response.ok) data = await response.json();
    } catch (e) {
        if (e.name !== 'AbortError') console.warn('Failed to load message facets:', e);
    }
    if (gen !== messagesGen) return;
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
        if (options) options.innerHTML = renderFacetList(kind, entries, counts, current, true);
        const button = document.getElementById(`messages-${kind}-pick`);
        const valueLabel = document.getElementById(`messages-${kind}-value`);
        const chosen = entries.find(([value]) => value === current);
        if (valueLabel) valueLabel.textContent = current && chosen ? chosen[1] : anyLabel;
        if (button) button.classList.toggle('is-set', !!current);
    };
    pick('status', MESSAGE_STATUS_FACETS, data && data.status, status, 'All');
    pick('direction', MESSAGE_DIRECTION_FACETS, data && data.direction, direction, 'Any');
    // Options redrawn while the picker is open keep the focus inside it
    uiPickerRefocus();
    const timeButton = document.getElementById('messages-time-pick');
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

// A new list. quiet keeps the one shown until the answer replaces it; rows reads
// that many at once (500 a request, from the first page's watermark); applyIf,
// asked when everything has come, may still keep the list shown; toEnd scrolls
// to its end (oldest first, where new mail is)
async function loadMessages({ quiet = false, rows = 50, toEnd = false, applyIf = null } = {}) {
    const container = document.getElementById('messages-logs');
    renderMessagesSort();
    // A new list: whatever the older one still has on its way is aborted
    const gen = messagesNewGeneration();
    messagesFullLoad = true;
    if (!quiet) container.innerHTML = '<div class="ui-loading" role="status"><div class="loading"></div><p>Loading...</p></div>';
    const filters = currentFilters.messages || {};
    loadMessageFacets(filters, gen);
    updateMessagesFilterState();
    // The list grows as it scrolls, so a new load always starts at the top
    if (!quiet) container.scrollTop = 0;
    try {
        const timeout = quiet ? PAGE_REFRESH_TIMEOUT : 0;
        const response = await messagesFetch(`/api/messages?${messagesQueryParams(null, Math.min(500, rows))}`, timeout);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        const data = await response.json();
        while (data.next_cursor && (data.data || []).length < rows && gen === messagesGen) {
            const next = await messagesFetch(`/api/messages?${messagesQueryParams(data.next_cursor, Math.min(500, rows - data.data.length), data.watermark)}`, timeout);
            if (!next.ok) throw new Error(`HTTP ${next.status}: ${next.statusText}`);
            const page = await next.json();
            data.data = data.data.concat(page.data || []);
            data.next_cursor = page.next_cursor;
            data.total = page.total ?? data.total;
        }
        if (gen !== messagesGen) return;
        // The user moved on meanwhile: the list stays, and the new mail is offered
        if (applyIf && !applyIf()) {
            renderMessagesNew();
            return;
        }
        // A quiet read that brings nothing new leaves the list as it is
        if (quiet && messagesSameAsShown(data) && (data.data || []).length === (lastDataCache.messages.data || []).length) {
            if (data.watermark != null) messagesNew.watermark = data.watermark;
            messagesNew.count = 0;
            renderMessagesNew();
            return;
        }
        if (quiet) uiKeepFocus(container, 'data-key', () => showMessagesFirstPage(container, data));
        else showMessagesFirstPage(container, data);
        afterMessagesRendered(data);
        if (toEnd) messagesScrollToEnd(container);
    } catch (error) {
        // A newer load is on its way or shown (this one may have been aborted for it)
        if (gen !== messagesGen) return;
        // A quiet load that failed leaves the list as it was
        if (quiet) return;
        console.error('Failed to load messages:', error);
        container.innerHTML = `<p class="ui-empty ui-text-fail">Failed to load messages: ${escapeHtml(error.message)}. <button type="button" class="ui-link-row ui-link" onclick="loadMessages()">Try again</button></p>`;
        setMessagesCount(null);
        // Nothing is shown: no next page, and the next refresh draws what it gets
        messagesPaging.page = 1;
        messagesPaging.cursor = null;
        messagesPaging.total = 0;
        currentPage.messages = 1;
        lastDataCache.messages = null;
    } finally {
        if (gen === messagesGen) messagesFullLoad = false;
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
            : '<div class="ui-loading" role="status"><div class="loading"></div><p>Loading...</p></div>';
        return;
    }
    box.innerHTML = items.map(item => `
        <div class="ui-alert ui-alert-${item.tone}">
            <span class="ui-alert-bar"></span>
            <div class="ui-alert-text"><div class="ui-alert-title"><b>${escapeHtml(item.title)}</b></div><p>${escapeHtml(item.detail)}</p></div>
            <div class="ui-st-acts">${item.actions}</div>
        </div>`).join('');
}

// Set while the page's refresh reads Status: a read that fails keeps what is
// shown, and a section with selected text or the keyboard on one of its
// controls is drawn on the next refresh (checked when the answer is drawn)
let statusQuiet = false;
function statusHold(container) {
    if (!statusQuiet || !container) return false;
    const active = document.activeElement;
    return uiTextHeld(container) || Boolean(active && container.contains(active) && active.matches(':focus-visible'));
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
        uiAgo(lastChecked, new Date().toISOString(), 'Updated ');
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
                ? `<button type="button" class="ui-link-row ui-text-info" onclick="navigateTo('settings')">Update ${escapeHtml(data.latest_version)} available</button>`
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
        if (!response.ok) throw await responseError(response);
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
            if (!statusHold(container)) container.innerHTML = `<div class="ui-ctrs">${ordered.map(c => {
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
            if (!statusHold(container)) container.innerHTML = '<p class="ui-empty ui-panel">No container information available</p>';
        }
    } catch (error) {
        console.error('Failed to load containers status:', error);
        setStatusKpi('status-kpi-containers', '-');
        if (!statusQuiet) document.getElementById('status-containers').innerHTML = `<p class="ui-empty ui-panel ui-text-fail">Failed to load containers: ${escapeHtml(error.message)}</p>`;
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
            throw await responseError(infoResponse);
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

        const row = (label, part) => `<dt>${label}</dt><dd>${Number(part.total || 0).toLocaleString()} <small>${Number(part.active || 0).toLocaleString()} active</small></dd>`;
        if (!statusHold(container)) container.innerHTML = `
            <div class="ui-srv-big">${versionHtml || 'mailcow'}</div>
            <dl class="ui-srv-dl">
                ${row('Domains', data.domains || {})}
                ${row('Mailboxes', data.mailboxes || {})}
                ${row('Aliases', data.aliases || {})}
            </dl>
        `;
    } catch (error) {
        console.error('Failed to load system info:', error);
        if (!statusQuiet) document.getElementById('status-system').innerHTML = `<p class="ui-empty ui-text-fail">Failed to load system info: ${escapeHtml(error.message)}</p>`;
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
            throw await responseError(response);
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
        if (!statusHold(container)) container.innerHTML = `
            <div class="ui-srv-big${level === 'ok' ? '' : ` ui-text-${level}`}">${escapeHtml(String(data.used_percent || '0%'))} used</div>
            <div class="ui-meter ui-${level}"><i style="width: ${usedPercent}%"></i></div>
            ${size ? `<small>${escapeHtml(size)}</small>` : ''}
        `;
    } catch (error) {
        console.error('Failed to load storage info:', error);
        setStatusKpi('status-kpi-storage', '-');
        if (!statusQuiet) document.getElementById('status-storage').innerHTML = `<p class="ui-empty ui-text-fail">Failed to load storage info: ${escapeHtml(error.message)}</p>`;
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
        renderStatusCorrelation(data.correlation_status || {}, data.recent_incomplete_correlations || [], (data.configuration || {}).max_correlation_age_minutes);

        // Render Background Jobs
        renderStatusJobs(data.background_jobs || {});

        // Load Blacklist Status separately (awaited, so the refresh knows when it is drawn)
        await loadBlacklistStatus();

    } catch (error) {
        console.error('Failed to load extended status:', error);
        if (!statusQuiet) document.getElementById('status-import').innerHTML = `<p class="ui-empty ui-text-fail">Failed to load: ${escapeHtml(error.message)}</p>`;
        if (!statusQuiet) document.getElementById('status-correlation').innerHTML = `<p class="ui-empty ui-text-fail">Failed to load: ${escapeHtml(error.message)}</p>`;
        if (!statusQuiet) document.getElementById('status-jobs').innerHTML = `<p class="ui-empty ui-text-fail">Failed to load: ${escapeHtml(error.message)}</p>`;
    }
}

function checkHost(hostname) {
    return checkBlacklists(true, hostname);
}

// The Check all now button as the page has it, put back when a check ends
let blacklistCheckBtnIdle = null;

async function checkBlacklists(force = false, host = null) {
    const btn = document.getElementById('blacklist-check-btn');
    const container = document.getElementById('status-blacklist');

    if (btn) {
        if (blacklistCheckBtnIdle === null) blacklistCheckBtnIdle = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = `
            <svg class="animate-spin -ms-1 me-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
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
        const response = await authenticatedFetch(`/api/blacklist/check${qs ? '?' + qs : ''}`, { method: 'POST' });
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const body = await response.json().catch(() => null);
        if (body && body.status === 'busy') {
            // Another check runs (the schedule's, an entity card's): nothing was started.
            // Checking every host, the progress shown is that check's, and the list
            // is read again when it ends; one host stops here
            showToast(body.message || 'A blocklist check is already running. Try again when it is done.', 'warning');
            if (host) {
                clearInterval(progressInterval);
                const temp = document.getElementById('blacklist-temp-progress');
                if (temp) temp.remove();
            }
            return;
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
            btn.innerHTML = blacklistCheckBtnIdle;
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
        if (!statusQuiet) container.innerHTML = `<p class="ui-empty ui-text-fail">Failed to load: ${escapeHtml(error.message)}</p>`;
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
        const fig = data.figure && data.figure.valid ? data.figure : null;
        if (data.status === 'listed') {
            // The figure its trend samples: listed of all monitored addresses
            setDashKpi('dash-kpi-blocklists', fig ? `${fig.value} of ${fig.of} listed` : `${listedHosts.length || data.hosts_listed || 1} of ${hosts.length || 1} listed`, 'fail',
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
        if (!statusHold(container)) container.innerHTML = `
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

    // Preserve which hosts show all their lists, and a scan's progress at the top
    const progress = document.getElementById('blacklist-temp-progress');
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

    if (!statusHold(container)) container.innerHTML = `
        <div class="ui-st-hosts">
        ${data.hosts.map(host => {
            const hostId = `bl-host-${String(host.hostname).replace(/[^A-Za-z0-9_-]/g, '-')}`;
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
                    <b class="ui-mono">${uiEntity('ip', host.hostname, { mono: true, plain: true })}</b>
                    <span class="ui-tag ui-tag-line">${escapeHtml(host.source || 'system')}</span>
                    ${result}
                    <span class="ui-st-host-tools">
                        ${host.checked_at ? uiTime(host.checked_at, `checked ${formatAgo(host.checked_at)}`, { title: formatTime(host.checked_at), cls: 'ui-muted' }) : '<span class="ui-muted">never checked</span>'}
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
    if (progress) container.prepend(progress);
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
            <span class="ui-td"><small class="ui-sec-unit">Last Fetch Run </small>${d.last_fetch_run ? uiTime(d.last_fetch_run, formatAgo(d.last_fetch_run), { title: formatTime(d.last_fetch_run) }) : 'Never'}</span>
            <span class="ui-td"><small class="ui-sec-unit">Last Import </small>${d.last_import ? uiTime(d.last_import, formatAgo(d.last_import), { title: formatTime(d.last_import) }) : 'Never'}</span>
            <span class="ui-td ui-td-end"><small class="ui-sec-unit">Total Entries </small>${Number(d.total_entries || 0).toLocaleString()}</span>
            <span class="ui-td"><small class="ui-sec-unit">Oldest Entry </small>${d.oldest_entry ? uiTime(d.oldest_entry, formatTime(d.oldest_entry)) : '-'}</span>
            ` : '<span class="ui-td ui-muted">No data</span><span></span><span></span><span></span>'}
        </div>`;
    if (!statusHold(container)) container.innerHTML = `
        <div class="ui-table ui-stack" data-nosort style="--ui-cols: minmax(130px, 1fr) minmax(110px, 1fr) minmax(110px, 1fr) 110px minmax(150px, 1.2fr); --ui-table-min: 660px">
            <div class="ui-tr ui-tr-head"><span>Source</span><span>Last Fetch Run</span><span>Last Import</span><span class="ui-td-end">Total Entries</span><span>Oldest Entry</span></div>
            ${row('Postfix Logs', imports.postfix)}
            ${row('Rspamd Logs', imports.rspamd)}
            ${row('Netfilter Logs', imports.netfilter)}
        </div>
    `;
}

function renderStatusCorrelation(correlation, incompleteList, maxAgeMinutes) {
    const container = document.getElementById('status-correlation');
    setStatusKpi('status-kpi-linking', `${correlation.completion_rate || 0}%`, correlation.incomplete ? 'warn' : '');
    const linkingNote = document.getElementById('status-kpi-linking-note');
    if (linkingNote) linkingNote.textContent = `${(correlation.complete || 0).toLocaleString()} of ${(correlation.total || 0).toLocaleString()} complete, ${(correlation.incomplete || 0).toLocaleString()} waiting`;
    if (!statusHold(container)) container.innerHTML = `
        <div class="ui-srv-big${correlation.incomplete ? ' ui-text-warn' : ''}">${escapeHtml(String(correlation.completion_rate || 0))}%</div>
        <small>${Number(correlation.complete || 0).toLocaleString()} of ${Number(correlation.total || 0).toLocaleString()} complete, ${Number(correlation.incomplete || 0).toLocaleString()} incomplete, ${Number(correlation.expired || 0).toLocaleString()} expired</small>
        ${correlation.last_update ? `<small title="${escapeHtml(formatTime(correlation.last_update))}">Updated ${formatAgo(correlation.last_update)}</small>` : ''}
    `;
    const pending = document.getElementById('status-correlation-pending');
    if (pending) pending.innerHTML = incompleteList.length > 0 ? `
        <section class="ui-sec-block">
            <div class="ui-list-head" id="status-pending-head"><h2 class="ui-h2">Waiting to be linked</h2> <span class="ui-count">${incompleteList.length}</span></div>
            <div class="ui-table ui-stack" data-sort-at="status-pending-head" data-sort-name="messages waiting to be linked" style="--ui-cols: minmax(180px, 1.4fr) minmax(220px, 2fr) 90px; --ui-table-min: 560px">
                <div class="ui-tr ui-tr-head"><span data-sort-kind="text">Message ID</span><span data-sort-kind="text">From and to</span><span class="ui-td-end" data-sort-kind="date">Age</span></div>
                ${incompleteList.map(item => `
                    <div class="ui-tr">
                        <span class="ui-td ui-mono">${copyableText(item.message_id || 'N/A')}</span>
                        <span class="ui-td">${uiEntity('address', item.sender || 'N/A')} → ${uiEntity('address', item.recipient || 'N/A')}</span>
                        <span class="ui-td ui-td-end ui-text-warn">${escapeHtml(String(item.age_minutes))}m ago</span>
                    </div>`).join('')}
            </div>
            <p class="ui-kv-note ui-list-foot">Each is linked when its delivery logs arrive, or marked expired once it is ${escapeHtml(String(maxAgeMinutes || 10))} minutes old.</p>
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
                ['Sync Transports & Relayhosts', 'sync_transports', jobs.sync_transports],
                ['Turned-Off Features', 'feature_data_sweep', jobs.feature_data_sweep],
                ['Trend Samples', 'trend_samples', jobs.trend_samples]
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
                ['Protection Rules', 'protection_rules', jobs.protection_rules],
                ['Anomaly Detection', 'anomaly_detection', jobs.anomaly_detection],
                ['Outgoing Spam', 'smtp_abuse', jobs.smtp_abuse]
            ]
        },
        {
            title: 'System',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>',
            jobs: [
                ['Check App Version', 'check_app_version', jobs.check_app_version],
                ['Credential Checks', 'check_credentials', jobs.check_credentials],
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
            title: 'Devices',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"></path>',
            jobs: [
                ['ActiveSync Devices', 'eas_devices', jobs.eas_devices],
                ['Cleanup ActiveSync Devices', 'cleanup_eas_devices', jobs.cleanup_eas_devices]
            ]
        },
        {
            title: 'Outbound',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z"></path>',
            jobs: [
                ['Detect Suppressions', 'detect_suppressions', jobs.detect_suppressions],
                ['Sync with Rspamd', 'sync_suppressions', jobs.sync_suppressions],
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
    if (!statusHold(container)) container.innerHTML = `<div class="ui-jgs">${html}</div>`;
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
        revealChangelogModal(modal);
    }
}

// The changelog, help and update texts share one dialog: each opens at the top of
// what it holds, not where the one before was scrolled to
function revealChangelogModal(modal) {
    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
    // Only once it is shown: a hidden element cannot be scrolled
    const body = modal.querySelector('.ui-dialog-body');
    if (body) body.scrollTop = 0;
    uiReadProgress(modal.querySelector('.ui-dialog-head'), body);
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
    if (typeof countryCode !== 'string' || !/^[a-z]{2}$/i.test(countryCode)) {
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
        return `<img src="${flagUrl}" alt="${escapeHtml(record.country_name || '')}" style="width:${width}px; height:${height}px; vertical-align:middle; margin-inline-end:4px;" onerror="this.style.display='none'">${locationText}`;
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
            <button onclick="loadLogs('${type}', ${Number(currentPage) - 1})" ${currentPage === 1 ? 'disabled' : ''} class="ui-btn">
                Previous
            </button>
            <span class="ui-muted">Page ${Number(currentPage)} of ${Number(totalPages)}</span>
            <button onclick="loadLogs('${type}', ${Number(currentPage) + 1})" ${currentPage === totalPages ? 'disabled' : ''} class="ui-btn">
                Next
            </button>
        </div>
    `;
}

function loadLogs(type, page) {
    currentPage[type] = page;
    switch (type) {
        case 'messages':
            loadMessages();
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
    // Changelog modal event listeners
    const changelogModal = document.getElementById('changelog-modal');
    if (changelogModal) {
        changelogModal.addEventListener('click', function (e) {
            if (uiBackdropClick(e)) {
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

const DOCS_SITE_URL = 'https://shlomiporush.github.io/mailcow-logs-viewer/';
const DOCS_REPO_URL = 'https://github.com/ShlomiPorush/mailcow-logs-viewer/blob/main/';

// A help page is also a page of the documentation site (documentation/HelpDocs).
// In the app its screenshots are left out, since the page itself is on screen,
// and its relative links, which work on the site, point to the site instead.
// A link to a section of the same page goes there too: the window's headings
// have no anchors. docName is the file's name, such as Mailbox_Stats.
function helpDocMarkdown(markdown, docName) {
    return markdown
        .replace(/^[ \t]*!\[[^\]]*\]\([^)\s]*\)[ \t]*$/gm, '')
        .replace(/(\]\()([^)\s]+)(\))/g, (match, open, target, close) => {
            if (/^[a-z][a-z0-9+.-]*:/i.test(target)) return match;
            if (target.startsWith('#')) return `${open}${DOCS_SITE_URL}HelpDocs/${docName}/${target}${close}`;
            const [path, anchor] = target.split('#');
            const hash = anchor ? `#${anchor}` : '';
            const parts = ['documentation', 'HelpDocs'];
            for (const segment of path.split('/')) {
                if (segment === '..') parts.pop();
                else if (segment && segment !== '.') parts.push(segment);
            }
            const file = parts.join('/');
            let url;
            if (file === 'README.md') url = DOCS_SITE_URL;
            else if (file === 'CHANGELOG.md') url = `${DOCS_SITE_URL}changelog/`;
            else if (file.startsWith('documentation/') && file.endsWith('.md')) {
                url = `${DOCS_SITE_URL}${file.slice('documentation/'.length, -'.md'.length)}/`;
            } else url = DOCS_REPO_URL + file;
            return `${open}${url}${hash}${close}`;
        });
}

// title: the name the page shows, when it is not the document's file name
async function showHelpModal(docName, title) {
    // The window opens after the request; the focus goes back to this Help button
    const opener = layerLastAction || document.activeElement;
    try {
        const response = await authenticatedFetch(`/api/docs/${docName}`);

        if (!response.ok) {
            throw new Error(`Failed to load documentation: ${response.statusText}`);
        }

        const markdown = helpDocMarkdown(await response.text(), docName);
        uiLayerOpener(opener);
        // Else the document's file name, read as words: Mailbox_Stats is Mailbox Stats
        showMarkdownModal(`Help - ${title || docName.replace(/_/g, ' ')}`, markdown);

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
            revealChangelogModal(modal);
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

// Whether the log is scrolled to its newest line (a few pixels short counts)
function containerLogsAtEnd(content) {
    const box = content.parentElement;
    return !box || box.scrollHeight - box.scrollTop - box.clientHeight <= 4;
}

async function fetchContainerLogs(silent = false) {
    const content = document.getElementById('container-logs-content');

    // The refresh leaves the log as it is while the user selects text in it or
    // reads further up, and while the browser tab is hidden
    if (content && silent && (uiTextHeld(content) || !containerLogsAtEnd(content) || document.hidden)) return;

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
            if (silent && (uiTextHeld(content) || !containerLogsAtEnd(content))) return;
            const isScrolledToBottom = containerLogsAtEnd(content);

            if (data.logs.length === 0) {
                if (!silent) content.textContent = 'No logs available.';
            } else {
                content.replaceChildren(...data.logs.join('').replace(/\r?\n$/, '').split(/\r?\n/).map(text => {
                    const line = document.createElement('span');
                    line.className = 'ui-log-line';
                    line.textContent = text;
                    return line;
                }));
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

    // Clear existing interval just in case
    if (containerLogsInterval) clearInterval(containerLogsInterval);

    // A log opens at its end, so on a phone its sheet fills the screen first: after
    // this frame, once the dialog watcher (uiDialogSheet) has prepared the sheet,
    // which would undo it. Then the log loads, goes to its end and keeps following
    requestAnimationFrame(() => {
        if (modal && modal.classList.contains('hidden')) return;
        if (modal) uiDialogSheetFull(modal);
        fetchContainerLogs(false);
        // Set auto-refresh every 2 seconds
        if (containerLogsInterval) clearInterval(containerLogsInterval);
        containerLogsInterval = setInterval(() => {
            fetchContainerLogs(true);
        }, 2000);
    });
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

// =============================================================================
// Sidebar sub-pages: hovering or focusing a page with tabs shows its tabs next
// to it. The items come from the page's own tab buttons, so a tab hidden by a
// switched-off feature is not offered.
// =============================================================================

const NAV_SUBPAGE_TABS = {
    quarantine: '#quarantine-tabs:not(.hidden)',
    outbound: '#outbound-tabs:not(.hidden)',
    netfilter: '.ui-se-tabs',
    status: '.ui-st-tabs',
    'mailbox-stats': '#mailbox-stats-views'
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
            // Back toward the sidebar: Left, or Right when the page reads right to left
            const back = getComputedStyle(navFlyout).direction === 'rtl' ? 'ArrowRight' : 'ArrowLeft';
            if (e.key === 'Escape' || e.key === back) { e.preventDefault(); hideNavFlyout(); navFlyout.owner && navFlyout.owner.focus(); }
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
    // Beside the sidebar: to its right, or to its left when the page reads right to left
    const rtl = getComputedStyle(item).direction === 'rtl';
    navFlyout.style.left = `${rtl ? rect.left - navFlyout.offsetWidth - 8 : rect.right + 8}px`;
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
