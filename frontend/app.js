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

// Send the browser to the login page, dropping any client-side state.
function redirectToLogin() {
    window.location.replace('/login');
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
    postfix: 1,
    rspamd: 1,
    netfilter: 1,
    messages: 1
};
let currentFilters = {
    postfix: {},
    rspamd: {},
    netfilter: {},
    queue: {},
    messages: {}
};

// Modal state
let currentModalTab = 'overview';
let currentModalData = null;

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
    { id: 'dmarc', label: 'DMARC', description: 'DMARC/TLS reports and IMAP sync' },
    { id: 'mailbox-stats', label: 'Mailbox Stats', description: 'Mailbox and alias statistics' },
    { id: 'rate-limits', label: 'Rate Limits', description: 'Sender rate limit hits and the configured limits' },
    { id: 'logs', label: 'Logs', description: 'Raw service log viewer' },
    { id: 'blacklist', label: 'IP Blacklist Monitor', description: 'DNS blacklist monitoring for your IPs' },
];

function isFeatureDisabled(featureId) {
    return window.disabledFeatures.includes(featureId);
}

function applyFeatureToggles() {
    // Hide desktop and mobile tabs for disabled features
    for (const feature of window.disabledFeatures) {
        // Desktop tab
        const tab = document.getElementById(`tab-${feature}`);
        if (tab) tab.style.display = 'none';
        // Mobile tab
        const mobileTab = document.getElementById(`mobile-tab-${feature}`);
        if (mobileTab) mobileTab.style.display = 'none';
    }
    // Ensure enabled features are visible (in case of settings change)
    for (const feature of TOGGLEABLE_FEATURES) {
        if (!window.disabledFeatures.includes(feature.id)) {
            const tab = document.getElementById(`tab-${feature.id}`);
            if (tab) tab.style.display = '';
            const mobileTab = document.getElementById(`mobile-tab-${feature.id}`);
            if (mobileTab) mobileTab.style.display = '';
        }
    }
    
    // Special handling for blacklist feature - it doesn't have its own tab,
    // it's a section inside the Domains page
    const blacklistSection = document.getElementById('blacklist-section');
    const dashboardBlacklistCard = document.getElementById('dashboard-blacklist-card');
    if (window.disabledFeatures.includes('blacklist')) {
        if (blacklistSection) blacklistSection.style.display = 'none';
        if (dashboardBlacklistCard) dashboardBlacklistCard.style.display = 'none';
    } else {
        if (blacklistSection) blacklistSection.style.display = '';
        if (dashboardBlacklistCard) dashboardBlacklistCard.style.display = '';
    }

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

// A nav tab is an <svg> icon followed by its label in a bare text node, so the
// label is swapped on that node and the icon and markup are left alone.
function setNavTabLabel(tab, label) {
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

    // Update visual styling of the label
    const label = el ? el.closest('label') : null;
    if (label) {
        if (isChecked) {
            label.classList.remove('border-gray-200', 'dark:border-gray-700', 'bg-gray-50/50', 'dark:bg-gray-800/50', 'opacity-60');
            label.classList.add('border-green-200', 'dark:border-green-700/50', 'bg-green-50/50', 'dark:bg-green-900/10');
        } else {
            label.classList.remove('border-green-200', 'dark:border-green-700/50', 'bg-green-50/50', 'dark:bg-green-900/10');
            label.classList.add('border-gray-200', 'dark:border-gray-700', 'bg-gray-50/50', 'dark:bg-gray-800/50', 'opacity-60');
        }
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
}

// Auto-refresh configuration
const AUTO_REFRESH_INTERVAL = 30000; // 30 seconds
let autoRefreshTimer = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', async () => {
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
    } catch (error) {
        console.error('Failed to load app info:', error);
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

            // Allow clicking badge to view changelog
            updateBadge.onclick = (e) => {
                e.preventDefault();
                e.stopPropagation();
                showMarkdownModal(`Update: v${data.latest_version}`, data.changelog || 'No changelog available');
            };
        } else if (updateBadge) {
            updateBadge.classList.add('hidden');
        }
    } catch (error) {
        console.error('Failed to load app version status:', error);
    }
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

    const modal = document.getElementById('changelog-modal');
    const modalTitle = modal?.querySelector('h3');
    const content = document.getElementById('changelog-content');

    if (modal && content) {
        if (modalTitle) {
            modalTitle.textContent = title;
        }

        // Add some basic styling for markdown content
        content.innerHTML = `<div class="markdown-body prose dark:prose-invert max-w-none">${htmlContent}</div>`;
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
    if (modal && !modal.classList.contains('hidden')) {
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
function renderMessagesData(data) {
    const container = document.getElementById('messages-logs');
    if (!container) return;

    if (!data.data || data.data.length === 0) {
        container.innerHTML = '<p class="text-gray-500 dark:text-gray-400 text-center py-8">No messages found</p>';
        return;
    }

    container.innerHTML = `
        <div class="space-y-3">
            ${data.data.map(msg => `
                <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition cursor-pointer" onclick="viewMessageDetails('${msg.correlation_key}')">
                    <div class="grid grid-cols-1 sm:grid-cols-[1fr_auto] gap-2 mb-2 items-start">
                        <div class="min-w-0 overflow-hidden">
                            <div class="flex flex-wrap items-center gap-2 mb-1">
                                <span class="text-sm font-medium text-gray-900 dark:text-white">${escapeHtml(msg.sender || 'Unknown')}</span>
                                <svg class="w-4 h-4 text-gray-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                                </svg>
                                <span class="text-sm text-gray-600 dark:text-gray-300">${escapeHtml(msg.recipient || 'Unknown')}</span>
                            </div>
                            <p class="text-xs text-gray-500 dark:text-gray-400 truncate" title="${escapeHtml(msg.subject || 'No subject')}">${escapeHtml(msg.subject || 'No subject')}</p>
                        </div>
                        <div class="flex flex-wrap items-center gap-2 flex-shrink-0 sm:justify-end">
                            ${(() => {
            const correlationStatus = getCorrelationStatusDisplay(msg);
            if (correlationStatus) {
                return `<span class="inline-block px-2 py-0.5 text-xs font-medium rounded ${correlationStatus.class}" title="${msg.final_status || (msg.is_complete ? 'Correlation complete' : 'Waiting for Postfix logs')}">${correlationStatus.display}</span>`;
            }
            return '';
        })()}
                            ${msg.direction ? `<span class="inline-block px-2 py-0.5 text-xs font-medium rounded ${getDirectionClass(msg.direction)}">${msg.direction}</span>` : ''}
                            ${msg.is_spam !== null ? `<span class="inline-block px-2 py-0.5 text-xs font-medium rounded ${msg.is_spam ? 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300' : 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300'}">${msg.is_spam ? 'SPAM' : 'CLEAN'}</span>` : ''}
                        </div>
                    </div>
                    <div class="flex flex-wrap items-center gap-4 text-xs text-gray-500 dark:text-gray-400">
                        <span>${formatTime(msg.first_seen)}</span>
                        ${msg.queue_id ? `<span class="font-mono" title="Queue ID">Q: ${msg.queue_id}</span>` : ''}
                        ${msg.message_id ? `<span class="font-mono truncate max-w-xs" title="Message ID: ${escapeHtml(msg.message_id)}">MID: ${escapeHtml(msg.message_id.substring(0, 20))}${msg.message_id.length > 20 ? '...' : ''}</span>` : ''}
                        ${msg.spam_score !== null ? `<span>Score: <span class="${msg.spam_score >= 15 ? 'text-red-600 dark:text-red-400 font-semibold' : 'text-gray-600 dark:text-gray-300'}">${msg.spam_score.toFixed(1)}</span></span>` : ''}
                        ${msg.user ? `<span>User: ${escapeHtml(msg.user)}</span>` : ''}
                        ${msg.ip ? `<span>IP: ${msg.ip}</span>` : ''}
                    </div>
                </div>
            `).join('')}
        </div>
        ${renderPagination('messages', data.page, data.pages)}
    `;
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
        container.innerHTML = '<p class="text-gray-500 dark:text-gray-400 text-center py-8">No logs found</p>';
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

    container.innerHTML = `
        <div class="space-y-3">
            ${uniqueLogs.map(log => {
                const isBan = log.action === 'ban' || log.action === 'banned';
                const isWarningOrUnban = log.action === 'warning' || log.action === 'unban';
                // Check if IP is in the blacklist (with or without /32)
                const ipInBlacklist = log.ip && fail2banBlacklist.some(entry => entry === log.ip || entry === log.ip + '/32');
                // Show unban if: banned OR already in blacklist
                const showUnban = mailcowRwConfigured && log.ip && (isBan || ipInBlacklist);
                // Show ban if: warning/unban AND NOT already in blacklist
                const showBan = mailcowRwConfigured && log.ip && isWarningOrUnban && !ipInBlacklist;
                // GeoIP rendering
                let geoHtml = '';
                if (log.country_code) {
                    const flagUrl = getFlagUrl(log.country_code, '16x12');
                    let geoParts = [];
                    if (log.country_name && flagUrl) {
                        geoParts.push('<img src="' + flagUrl + '" alt="' + escapeHtml(log.country_name) + '" style="width:16px;height:12px;display:inline-block;vertical-align:middle" onerror="this.style.display=\'none\'"> ' + escapeHtml(log.country_name));
                    }
                    if (log.city) geoParts.push(escapeHtml(log.city));
                    if (log.asn_org) geoParts.push('(' + escapeHtml(log.asn_org) + ')');
                    if (geoParts.length > 0) {
                        geoHtml = '<div class="text-xs text-gray-500 dark:text-gray-400 mt-1 flex items-center gap-1 flex-wrap">' +
                            '<svg class="w-3 h-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 11a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>' +
                            geoParts.join(' ') + '</div>';
                    }
                }
                return `
                <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition">
                    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                        <div class="flex flex-wrap items-center gap-2">
                            <span class="font-mono text-sm font-semibold text-gray-900 dark:text-white">${log.ip ? copyableText(log.ip) : '-'}</span>
                            ${log.username && log.username !== '-' ? `<span class="text-sm text-blue-600 dark:text-blue-400">${copyableText(log.username)}</span>` : ''}
                            <span class="inline-block px-2 py-0.5 text-xs font-medium rounded ${getActionClass(log.action)}">${getActionLabel(log.action)}</span>
                            ${log.attempts_left !== null && log.attempts_left !== undefined ? `<span class="text-xs text-gray-500 dark:text-gray-400">${log.attempts_left} attempts left</span>` : ''}
                        </div>
                        <div class="flex items-center gap-2">
                            <span class="text-xs text-gray-500 dark:text-gray-400">${formatTime(log.time)}</span>
                            ${showUnban ? `<button onclick="unbanIP('${escapeJsArg(log.ip)}', this)" class="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-semibold rounded-md bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-400 hover:bg-green-200 dark:hover:bg-green-800/60 border border-green-300 dark:border-green-700 transition-colors cursor-pointer" title="Unban ${escapeHtml(log.ip)}/32"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z"></path></svg>Unban</button>` : ''}
                            ${showBan ? `<button onclick="banIP('${escapeJsArg(log.ip)}', this)" class="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-semibold rounded-md bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-400 hover:bg-red-200 dark:hover:bg-red-800/60 border border-red-300 dark:border-red-700 transition-colors cursor-pointer" title="Ban ${escapeHtml(log.ip)}/32"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>Ban</button>` : ''}
                        </div>
                    </div>
                    <p class="text-sm text-gray-700 dark:text-gray-300 break-words">${escapeHtml(log.message || '-')}</p>
                    ${geoHtml}
                </div>`;
            }).join('')}
        </div>
        ${renderPagination('netfilter', data.page, data.pages)}
    `;
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
            // Refresh fail2ban data and netfilter logs
            fail2banSettingsLoaded = false;
            fail2banActiveBans = null;
            loadFail2BanSettings();
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
            document.getElementById('stat-messages-24h').textContent = data.messages['24h'].toLocaleString();
            document.getElementById('stat-messages-7d').textContent = data.messages['7d'].toLocaleString();
            document.getElementById('stat-blocked-24h').textContent = data.blocked['24h'].toLocaleString();
            document.getElementById('stat-blocked-7d').textContent = data.blocked['7d'].toLocaleString();
            document.getElementById('stat-blocked-percentage').textContent = data.blocked.percentage_24h;
            document.getElementById('stat-deferred-24h').textContent = data.deferred['24h'].toLocaleString();
            document.getElementById('stat-deferred-7d').textContent = data.deferred['7d'].toLocaleString();
            document.getElementById('stat-auth-failures-24h').textContent = data.auth_failures['24h'].toLocaleString();
            document.getElementById('stat-auth-failures-7d').textContent = data.auth_failures['7d'].toLocaleString();
        }

        // Also refresh recent activity and status summary
        loadRecentActivity();
        loadDashboardStatusSummary();
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
                <div class="flex items-center justify-center min-h-[60vh]">
                    <div class="text-center max-w-md">
                        <div class="w-16 h-16 mx-auto mb-6 rounded-full bg-gray-100 dark:bg-gray-700 flex items-center justify-center">
                            <svg class="w-8 h-8 text-gray-400 dark:text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
                                    d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                            </svg>
                        </div>
                        <h2 class="text-xl font-semibold text-gray-700 dark:text-gray-300 mb-2">${escapeHtml(featureLabel)} is disabled</h2>
                        <p class="text-gray-500 dark:text-gray-400 mb-6">This feature has been turned off by the administrator in Settings → Application → Features.</p>
                        <button onclick="navigateTo('dashboard')"
                            class="px-5 py-2.5 bg-blue-500 hover:bg-blue-600 text-white rounded-lg text-sm font-medium transition-colors">
                            Go to Dashboard
                        </button>
                    </div>
                </div>`;
        }

        // Update URL to reflect the disabled page (don't silently change to dashboard)
        const newPath = typeof buildPath === 'function' ? buildPath(tab) : `/${tab}`;
        if (window.location.pathname !== newPath) {
            history.replaceState({ route: tab, params: {} }, '', newPath);
        }
        return;
    }

    currentTab = tab;

    // Update active tab button (desktop)
    document.querySelectorAll('[id^="tab-"]').forEach(btn => {
        btn.classList.remove('tab-active');
        btn.classList.add('text-gray-500', 'dark:text-gray-400');
    });
    const activeBtn = document.getElementById(`tab-${tab}`);
    if (activeBtn) {
        activeBtn.classList.add('tab-active');
        activeBtn.classList.remove('text-gray-500', 'dark:text-gray-400');
    }

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
            loadNetfilterLogs(1);
            loadFail2BanSettings();
            loadNetfilterCountries();
            loadSmtpAbusePanel();
            loadSecurityCountryChart(30);
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
            handleDmarcRoute(params);
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

        document.getElementById('stat-messages-24h').textContent = data.messages['24h'].toLocaleString();
        document.getElementById('stat-messages-7d').textContent = data.messages['7d'].toLocaleString();
        document.getElementById('stat-blocked-24h').textContent = data.blocked['24h'].toLocaleString();
        document.getElementById('stat-blocked-7d').textContent = data.blocked['7d'].toLocaleString();
        document.getElementById('stat-blocked-percentage').textContent = data.blocked.percentage_24h;
        document.getElementById('stat-deferred-24h').textContent = data.deferred['24h'].toLocaleString();
        document.getElementById('stat-deferred-7d').textContent = data.deferred['7d'].toLocaleString();
        document.getElementById('stat-auth-failures-24h').textContent = data.auth_failures['24h'].toLocaleString();
        document.getElementById('stat-auth-failures-7d').textContent = data.auth_failures['7d'].toLocaleString();

        loadRecentActivity();
        loadDashboardStatusSummary();
        loadDashboardBlacklistSummary();
        loadDashboardSecurityAlerts();
    } catch (error) {
        console.error('Failed to load dashboard:', error);
    }
}

async function loadDashboardSecurityAlerts() {
    const container = document.getElementById('dashboard-security-alerts');
    if (!container) return;
    try {
        const response = await authenticatedFetch('/api/security-alerts?acknowledged=false&limit=20');
        if (!response.ok) { container.classList.add('hidden'); return; }
        const data = await response.json();
        const alerts = data.alerts || [];
        if (alerts.length === 0) {
            container.classList.add('hidden');
            container.innerHTML = '';
            return;
        }

        const rows = alerts.map(a => {
            const sev = a.severity === 'critical'
                ? 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300'
                : 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300';
            return `
                <div class="flex items-start justify-between gap-3 py-2 border-t border-red-200 dark:border-red-800/50 first:border-t-0">
                    <div class="min-w-0">
                        <div class="flex items-center gap-2 flex-wrap">
                            <span class="inline-block px-2 py-0.5 text-xs font-semibold rounded ${sev}">${escapeHtml((a.severity || 'warning').toUpperCase())}</span>
                            <span class="text-sm font-semibold text-gray-900 dark:text-white">${escapeHtml(a.title)}</span>
                        </div>
                        <p class="text-xs text-gray-600 dark:text-gray-400 mt-1">${escapeHtml(a.detail || '')}</p>
                        <p class="text-xs text-gray-400 mt-1">${escapeHtml(formatTime(a.created_at))}</p>
                    </div>
                    <button type="button" onclick="acknowledgeSecurityAlert(${a.id})" class="flex-shrink-0 px-2 py-1 text-xs rounded bg-white/70 dark:bg-gray-800 border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700" title="Dismiss">Dismiss</button>
                </div>`;
        }).join('');

        container.innerHTML = `
            <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
                <div class="flex items-center justify-between mb-2">
                    <div class="flex items-center gap-2">
                        <svg class="w-5 h-5 text-red-600 dark:text-red-400" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path></svg>
                        <h3 class="text-sm font-semibold text-red-800 dark:text-red-300">Security Alerts (${alerts.length})</h3>
                    </div>
                    <button type="button" onclick="acknowledgeAllSecurityAlerts()" class="px-2 py-1 text-xs rounded bg-white/70 dark:bg-gray-800 border border-red-300 dark:border-red-700 text-red-700 dark:text-red-300 hover:bg-red-100 dark:hover:bg-red-900/40">Dismiss all</button>
                </div>
                ${rows}
            </div>`;
        container.classList.remove('hidden');
    } catch (e) {
        console.warn('Failed to load security alerts:', e);
        container.classList.add('hidden');
    }
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

async function loadDashboardStatusSummary() {
    try {
        console.log('Loading Dashboard Status Summary...');

        const response = await authenticatedFetch('/api/status/summary');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('Status summary data:', data);

        const containersDiv = document.getElementById('dashboard-containers-summary');
        const containers = data.containers || {};
        containersDiv.innerHTML = `
            <div class="flex justify-between items-center">
                <span class="text-sm text-gray-600 dark:text-gray-400">Running</span>
                <span class="text-lg font-semibold text-green-600 dark:text-green-400">${containers.running || 0}</span>
            </div>
            <div class="flex justify-between items-center">
                <span class="text-sm text-gray-600 dark:text-gray-400">Stopped</span>
                <span class="text-lg font-semibold ${containers.stopped > 0 ? 'text-red-600 dark:text-red-400' : 'text-gray-600 dark:text-gray-400'}">${containers.stopped || 0}</span>
            </div>
            <div class="flex justify-between items-center pt-2 border-t border-gray-200 dark:border-gray-700">
                <span class="text-sm font-medium text-gray-700 dark:text-gray-300">Total</span>
                <span class="text-lg font-semibold text-gray-900 dark:text-white">${containers.total || 0}</span>
            </div>
        `;

        const storageDiv = document.getElementById('dashboard-storage-summary');
        const storage = data.storage || {};
        const usedPercent = parseInt(storage.used_percent) || 0;
        const storageColor = usedPercent > 90 ? 'text-red-600 dark:text-red-400' :
            usedPercent > 75 ? 'text-yellow-600 dark:text-yellow-400' :
                'text-green-600 dark:text-green-400';
        storageDiv.innerHTML = `
            <div class="flex justify-between items-center">
                <span class="text-sm text-gray-600 dark:text-gray-400">Used</span>
                <span class="text-lg font-semibold ${storageColor}">${storage.used_percent || '0%'}</span>
            </div>
            <div class="flex justify-between items-center">
                <span class="text-sm text-gray-600 dark:text-gray-400">Available</span>
                <span class="text-sm text-gray-900 dark:text-white">${storage.used || '0'} / ${storage.total || '0'}</span>
            </div>
            <div class="mt-2">
                <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div class="h-2 rounded-full ${usedPercent > 90 ? 'bg-red-600' : usedPercent > 75 ? 'bg-yellow-600' : 'bg-green-600'}" style="width: ${usedPercent}%"></div>
                </div>
            </div>
        `;

        const systemDiv = document.getElementById('dashboard-system-summary');
        const system = data.system || {};
        systemDiv.innerHTML = `
            <div class="flex justify-between items-center">
                <span class="text-sm text-gray-600 dark:text-gray-400">Domains</span>
                <span class="text-lg font-semibold text-gray-900 dark:text-white">${system.domains || 0}</span>
            </div>
            <div class="flex justify-between items-center">
                <span class="text-sm text-gray-600 dark:text-gray-400">Mailboxes</span>
                <span class="text-lg font-semibold text-gray-900 dark:text-white">${system.mailboxes || 0}</span>
            </div>
            <div class="flex justify-between items-center">
                <span class="text-sm text-gray-600 dark:text-gray-400">Aliases</span>
                <span class="text-lg font-semibold text-gray-900 dark:text-white">${system.aliases || 0}</span>
            </div>
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
            container.innerHTML = '<p class="text-gray-500 dark:text-gray-400 text-center py-8">No recent activity</p>';
            return;
        }

        container.innerHTML = data.activity.map(msg => `
            <div class="grid grid-cols-1 sm:grid-cols-[1fr_auto] gap-2 p-3 sm:p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition cursor-pointer items-start" onclick="viewMessageDetails('${msg.correlation_key}')">
                <div class="min-w-0 overflow-hidden">
                    <div class="flex flex-wrap items-center gap-2 mb-1">
                        <span class="text-sm font-medium text-gray-900 dark:text-white">${escapeHtml(msg.sender || 'Unknown')}</span>
                        <svg class="w-4 h-4 text-gray-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                        </svg>
                        <span class="text-sm text-gray-600 dark:text-gray-300">${escapeHtml(msg.recipient || 'Unknown')}</span>
                    </div>
                    <p class="text-xs text-gray-500 dark:text-gray-400 truncate" title="${escapeHtml(msg.subject || 'No subject')}">${escapeHtml(msg.subject || 'No subject')}</p>
                </div>
                <div class="flex flex-col items-end gap-1 flex-shrink-0">
                    <div class="flex items-center gap-2">
                        <span class="inline-block px-2 py-1 text-xs font-medium rounded ${getStatusClass(msg.status)}">${msg.status || 'unknown'}</span>
                        ${msg.direction ? `<span class="inline-block px-2 py-0.5 text-xs font-medium rounded ${getDirectionClass(msg.direction)}">${msg.direction}</span>` : ''}
                    </div>
                    <p class="text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap">${formatTime(msg.time)}</p>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load recent activity:', error);
        document.getElementById('recent-activity').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load activity: ${escapeHtml(error.message)}</p>`;
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
// POSTFIX LOGS
// =============================================================================

function applyPostfixFilters() {
    currentFilters.postfix = {
        search: document.getElementById('postfix-filter-search').value,
        sender: document.getElementById('postfix-filter-sender').value,
        recipient: document.getElementById('postfix-filter-recipient').value
    };
    currentPage.postfix = 1;
    loadPostfixLogs();
}

function clearPostfixFilters() {
    document.getElementById('postfix-filter-search').value = '';
    document.getElementById('postfix-filter-sender').value = '';
    document.getElementById('postfix-filter-recipient').value = '';
    currentFilters.postfix = {};
    currentPage.postfix = 1;
    loadPostfixLogs();
}

async function loadPostfixLogs(page = 1) {
    const container = document.getElementById('postfix-logs');

    // Show loading immediately
    container.innerHTML = '<div class="text-center py-8"><div class="loading mx-auto mb-4"></div><p class="text-gray-500 dark:text-gray-400">Loading Postfix logs... This may take a few moments.</p></div>';

    try {
        const filters = currentFilters.postfix || {};
        const params = new URLSearchParams({
            page: page,
            limit: 50
        });

        if (filters.search) params.append('search', filters.search);
        if (filters.sender) params.append('sender', filters.sender);
        if (filters.recipient) params.append('recipient', filters.recipient);

        console.log('Loading Postfix logs:', `/api/logs/postfix?${params}`);
        const startTime = performance.now();

        const response = await authenticatedFetch(`/api/logs/postfix?${params}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        const loadTime = ((performance.now() - startTime) / 1000).toFixed(2);
        console.log(`Postfix data loaded in ${loadTime}s:`, data); // nosemgrep: javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring

        if (!data.data || data.data.length === 0) {
            container.innerHTML = '<p class="text-gray-500 dark:text-gray-400 text-center py-8">No logs found</p>';
            return;
        }

        container.innerHTML = `
            <div class="mobile-scroll overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                    <thead class="bg-gray-50 dark:bg-gray-700">
                        <tr>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Time</th>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Queue ID</th>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">From</th>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">To</th>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Status</th>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider hide-mobile">Relay</th>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider hide-mobile">Delay</th>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider hide-mobile">DSN</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                        ${data.data.map(log => `
                            <tr class="hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer" onclick="${log.queue_id ? `viewPostfixDetails('${log.queue_id}')` : ''}">
                                <td class="px-3 sm:px-4 py-3 text-xs sm:text-sm text-gray-900 dark:text-gray-100 whitespace-nowrap">${formatTime(log.time)}</td>
                                <td class="px-3 sm:px-4 py-3 text-xs sm:text-sm font-mono text-gray-600 dark:text-gray-300">${log.queue_id || '-'}</td>
                                <td class="px-3 sm:px-4 py-3 text-xs sm:text-sm text-gray-900 dark:text-gray-100 max-w-xs truncate">${escapeHtml(log.sender || '-')}</td>
                                <td class="px-3 sm:px-4 py-3 text-xs sm:text-sm text-gray-900 dark:text-gray-100 max-w-xs truncate">${escapeHtml(log.recipient || '-')}</td>
                                <td class="px-3 sm:px-4 py-3 text-xs sm:text-sm">
                                    <span class="inline-block px-2 py-1 text-xs font-medium rounded ${getStatusClass(log.status)}">${log.status || 'unknown'}</span>
                                </td>
                                <td class="px-3 sm:px-4 py-3 text-xs sm:text-sm text-gray-600 dark:text-gray-300 hide-mobile">${escapeHtml(log.relay || '-')}</td>
                                <td class="px-3 sm:px-4 py-3 text-xs sm:text-sm text-gray-600 dark:text-gray-300 hide-mobile">${log.delay ? log.delay.toFixed(2) + 's' : '-'}</td>
                                <td class="px-3 sm:px-4 py-3 text-xs sm:text-sm text-gray-600 dark:text-gray-300 hide-mobile">${log.dsn || '-'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
            ${renderPagination('postfix', data.page, data.pages)}
        `;

        currentPage.postfix = page;
    } catch (error) {
        console.error('Failed to load Postfix logs:', error);
        document.getElementById('postfix-logs').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load logs: ${escapeHtml(error.message)}</p>`;
    }
}

// =============================================================================
// RSPAMD LOGS
// =============================================================================

function applyRspamdFilters() {
    currentFilters.rspamd = {
        search: document.getElementById('rspamd-filter-search').value,
        direction: document.getElementById('rspamd-filter-direction').value,
        is_spam: document.getElementById('rspamd-filter-spam').value,
        min_score: document.getElementById('rspamd-filter-score').value
    };
    currentPage.rspamd = 1;
    loadRspamdLogs();
}

function clearRspamdFilters() {
    document.getElementById('rspamd-filter-search').value = '';
    document.getElementById('rspamd-filter-direction').value = '';
    document.getElementById('rspamd-filter-spam').value = '';
    document.getElementById('rspamd-filter-score').value = '';
    currentFilters.rspamd = {};
    currentPage.rspamd = 1;
    loadRspamdLogs();
}

async function loadRspamdLogs(page = 1) {
    const container = document.getElementById('rspamd-logs');

    try {
        container.innerHTML = '<div class="text-center py-8"><div class="loading mx-auto mb-4"></div><p class="text-gray-500 dark:text-gray-400">Loading...</p></div>';

        const filters = currentFilters.rspamd || {};
        const params = new URLSearchParams({
            page: page,
            limit: 50
        });

        if (filters.search) params.append('search', filters.search);
        if (filters.direction) params.append('direction', filters.direction);
        if (filters.is_spam === 'true') params.append('is_spam', 'true');
        if (filters.is_spam === 'false') params.append('is_spam', 'false');
        if (filters.min_score) params.append('min_score', filters.min_score);

        console.log('Loading Rspamd logs:', `/api/logs/rspamd?${params}`);

        const response = await authenticatedFetch(`/api/logs/rspamd?${params}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('Rspamd data:', data);

        if (!data.data || data.data.length === 0) {
            container.innerHTML = '<p class="text-gray-500 dark:text-gray-400 text-center py-8">No logs found</p>';
            return;
        }

        container.innerHTML = `
            <div class="mobile-scroll overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                    <thead class="bg-gray-50 dark:bg-gray-700">
                        <tr>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Time</th>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">From</th>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Subject</th>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Direction</th>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Score</th>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Action</th>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider hide-mobile">Symbols</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                        ${data.data.map(log => `
                            <tr class="hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer" onclick="${log.correlation_key ? `viewMessageDetails('${log.correlation_key}')` : ''}">
                                <td class="px-3 sm:px-4 py-3 text-xs sm:text-sm text-gray-900 dark:text-gray-100 whitespace-nowrap">${formatTime(log.time)}</td>
                                <td class="px-3 sm:px-4 py-3 text-xs sm:text-sm text-gray-900 dark:text-gray-100 max-w-xs truncate">${escapeHtml(log.sender_smtp || '-')}</td>
                                <td class="px-3 sm:px-4 py-3 text-xs sm:text-sm text-gray-900 dark:text-gray-100 max-w-xs truncate" title="${escapeHtml(log.subject || 'No subject')}">${escapeHtml(log.subject || 'No subject')}</td>
                                <td class="px-3 sm:px-4 py-3 text-xs sm:text-sm">
                                    <span class="inline-block px-2 py-1 text-xs font-medium rounded ${getDirectionClass(log.direction)}">${log.direction}</span>
                                </td>
                                <td class="px-3 sm:px-4 py-3 text-xs sm:text-sm">
                                    <span class="${log.score >= log.required_score ? 'text-red-600 dark:text-red-400 font-semibold' : 'text-gray-600 dark:text-gray-300'}">${log.score.toFixed(2)}</span>
                                    <span class="text-gray-400 dark:text-gray-500">/${log.required_score}</span>
                                </td>
                                <td class="px-3 sm:px-4 py-3 text-xs sm:text-sm text-gray-600 dark:text-gray-300">${log.action}</td>
                                <td class="px-3 sm:px-4 py-3 text-xs text-gray-500 dark:text-gray-400 max-w-xs truncate hide-mobile">${log.symbols ? Object.keys(log.symbols).slice(0, 3).join(', ') : '-'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
            ${renderPagination('rspamd', data.page, data.pages)}
        `;

        currentPage.rspamd = page;
    } catch (error) {
        console.error('Failed to load Rspamd logs:', error);
        document.getElementById('rspamd-logs').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load logs: ${escapeHtml(error.message)}</p>`;
    }
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

let securityCountryChart = null;

async function loadSecurityCountryChart(days = 30) {
    // Update period button styles
    document.querySelectorAll('.country-chart-period-btn').forEach(btn => {
        btn.className = 'country-chart-period-btn px-3 py-1.5 text-xs font-medium rounded-md border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors';
    });
    const activeBtn = document.getElementById(`country-chart-${days}d`);
    if (activeBtn) {
        activeBtn.className = 'country-chart-period-btn px-3 py-1.5 text-xs font-medium rounded-md border border-blue-500 bg-blue-500 text-white transition-colors';
    }

    try {
        const response = await authenticatedFetch(`/api/logs/netfilter/stats/by-country?days=${days}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const result = await response.json();
        const data = result.data || [];

        const container = document.getElementById('country-chart-container');
        const emptyMsg = document.getElementById('country-chart-empty');

        // Filter out countries with 0 total (ban+warning+unban)
        const filteredData = data.filter(d => (d.ban + d.warning + d.unban) > 0);

        if (filteredData.length === 0) {
            container.classList.add('hidden');
            emptyMsg.classList.remove('hidden');
            return;
        }
        container.classList.remove('hidden');
        emptyMsg.classList.add('hidden');


        // Preload flag images for chart labels
        const flagImages = {};
        const flagPromises = filteredData.map(d => {
            const url = getFlagUrl(d.country_code, '24x18');
            if (!url) return Promise.resolve();
            return new Promise(resolve => {
                const img = new Image();
                img.onload = () => { flagImages[d.country_code] = img; resolve(); };
                img.onerror = () => resolve();
                img.src = url;
            });
        });
        await Promise.all(flagPromises);


        // Destroy old chart if exists
        if (securityCountryChart) {
            securityCountryChart.destroy();
            securityCountryChart = null;
        }

        const isDark = document.documentElement.classList.contains('dark');
        const gridColor = isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';
        const textColor = isDark ? '#d1d5db' : '#374151';

        // Dataset visibility state: track which action types are shown
        const datasetKeys = ['ban', 'warning', 'unban'];
        const visibleSets = { ban: true, warning: true, unban: true };

        const datasetColors = {
            ban:     isDark ? 'rgba(239,68,68,0.8)' : 'rgba(220,38,38,0.8)',
            warning: isDark ? 'rgba(251,191,36,0.8)' : 'rgba(217,119,6,0.8)',
            unban:   isDark ? 'rgba(34,197,94,0.8)' : 'rgba(22,163,74,0.8)'
        };
        const datasetLabels = { ban: 'Ban', warning: 'Warning', unban: 'Unban' };

        // Build chart data filtered by visible datasets
        function buildChartData() {
            // Filter: only keep countries that have > 0 events in any VISIBLE dataset
            const visible = filteredData.filter(d => {
                let sum = 0;
                for (const key of datasetKeys) {
                    if (visibleSets[key]) sum += d[key];
                }
                return sum > 0;
            });

            // Sort by visible total descending
            visible.sort((a, b) => {
                let sumA = 0, sumB = 0;
                for (const key of datasetKeys) {
                    if (visibleSets[key]) { sumA += a[key]; sumB += b[key]; }
                }
                return sumB - sumA;
            });

            return visible;
        }

        function updateChart() {
            const visible = buildChartData();

            if (visible.length === 0) {
                container.classList.add('hidden');
                emptyMsg.classList.remove('hidden');
                return;
            }
            container.classList.remove('hidden');
            emptyMsg.classList.add('hidden');

            // Dynamic height
            const chartHeight = Math.min(350, Math.max(120, visible.length * 32));
            container.style.height = chartHeight + 'px';

            // Update chart data in place
            securityCountryChart.data.labels = visible.map(d => d.country_name);
            datasetKeys.forEach((key, i) => {
                securityCountryChart.data.datasets[i].data = visible.map(d => d[key]);
            });

            // Store visible data reference for flag plugin and tooltip
            securityCountryChart._visibleData = visible;

            securityCountryChart.update();
        }

        const initialVisible = buildChartData();

        // Dynamic height
        const chartHeight = Math.min(350, Math.max(120, initialVisible.length * 32));
        container.style.height = chartHeight + 'px';

        const ctx = document.getElementById('security-country-chart').getContext('2d');
        securityCountryChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: initialVisible.map(d => d.country_name),
                datasets: datasetKeys.map(key => ({
                    label: datasetLabels[key],
                    data: initialVisible.map(d => d[key]),
                    backgroundColor: datasetColors[key],
                    borderRadius: 3
                }))
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                        labels: { color: textColor, padding: 15, usePointStyle: true, pointStyle: 'rectRounded' },
                        onClick: (e, legendItem, legend) => {
                            const key = datasetKeys[legendItem.datasetIndex];
                            visibleSets[key] = !visibleSets[key];

                            // Toggle the dataset hidden state
                            const meta = legend.chart.getDatasetMeta(legendItem.datasetIndex);
                            meta.hidden = !visibleSets[key];

                            // Rebuild data with only countries that have visible events
                            updateChart();
                        }
                    },
                    tooltip: {
                        callbacks: {
                            title: (items) => items[0].label,
                            afterTitle: (items) => {
                                const d = securityCountryChart._visibleData?.[items[0].dataIndex];
                                if (!d) return '';
                                let sum = 0;
                                for (const key of datasetKeys) {
                                    if (visibleSets[key]) sum += d[key];
                                }
                                return `Total: ${sum} events`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        stacked: true,
                        grid: { color: gridColor },
                        ticks: { color: textColor }
                    },
                    y: {
                        stacked: true,
                        grid: { display: false },
                        ticks: { color: textColor, padding: 30 }
                    }
                },
                layout: {
                    padding: { left: 8 }
                }
            },
            plugins: [{
                id: 'flagIcons',
                afterDraw: (chart) => {
                    const yScale = chart.scales.y;
                    if (!yScale) return;
                    const visible = chart._visibleData || initialVisible;
                    const ctx = chart.ctx;
                    yScale.ticks.forEach((tick, i) => {
                        const d = visible[i];
                        if (!d) return;
                        const flagImg = flagImages[d.country_code];
                        if (!flagImg) return;
                        const y = yScale.getPixelForTick(i);
                        const xPos = yScale.right - 28;
                        ctx.drawImage(flagImg, xPos, y - 6, 24, 18);
                    });
                }
            }]
        });

        // Store initial visible data reference
        securityCountryChart._visibleData = initialVisible;
    } catch (e) {
        console.error('Failed to load security country chart:', e);
    }
}

async function loadNetfilterLogs(page = 1) {
    const container = document.getElementById('netfilter-logs');

    try {
        container.innerHTML = '<div class="text-center py-8"><div class="loading mx-auto mb-4"></div><p class="text-gray-500 dark:text-gray-400">Loading...</p></div>';

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
        document.getElementById('netfilter-logs').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load logs: ${escapeHtml(error.message)}</p>`;
        const countEl = document.getElementById('security-count');
        if (countEl) countEl.textContent = '';
    }
}

// =============================================================================
// FAIL2BAN SETTINGS
// =============================================================================

let fail2banSettingsLoaded = false;
let fail2banActiveBans = null;
let fail2banBlacklist = [];

async function loadFail2BanSettings() {
    // Only load once per session (settings don't change often)
    if (fail2banSettingsLoaded) return;

    const settingsContainer = document.getElementById('fail2ban-settings');
    const ipListsContainer = document.getElementById('fail2ban-ip-lists');
    if (!settingsContainer) return;

    try {
        const response = await authenticatedFetch('/api/fail2ban');

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        const canEdit = mailcowRwConfigured;
        fail2banSettingsLoaded = true;
        fail2banActiveBans = data.active_bans || [];

        // Store blacklist entries globally for button logic
        const rawBlacklist = data.blacklist || '';
        fail2banBlacklist = rawBlacklist.replace(/\n/g, ',').split(',').map(e => e.trim()).filter(e => e);

        // Re-render netfilter logs if they were already loaded (race condition fix)
        // Now after blacklist is loaded, so buttons correctly reflect blacklist state
        if (lastDataCache.netfilter && mailcowRwConfigured) {
            renderNetfilterData(lastDataCache.netfilter);
        }

        // Parse for UI display
        const whitelistEntries = (data.whitelist || '').split('\n').filter(e => e.trim());
        const blacklistEntries = fail2banBlacklist;
        const permBans = data.perm_bans || [];

        // Render settings as editable form or read-only
        const rwBanner = canEdit ? '' : `
            <div class="mb-4 px-4 py-3 rounded-lg bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 text-yellow-800 dark:text-yellow-300 text-sm flex items-center gap-2">
                <span class="text-lg">🔒</span>
                <span>Editing requires a <strong>Read-Write API key</strong> (<code>MAILCOW_API_KEY_RW</code>). Configure it in Settings → Mailcow → Connection.</span>
            </div>
        `;

        settingsContainer.innerHTML = `
            ${rwBanner}
            <form id="fail2ban-edit-form">
                ${canEdit ? `
                    <div class="mb-3 flex justify-end" id="fail2ban-edit-btn-row">
                        <button type="button" id="fail2ban-enable-edit-btn"
                            class="px-3 py-1.5 bg-gray-200 dark:bg-gray-600 hover:bg-gray-300 dark:hover:bg-gray-500 text-gray-700 dark:text-gray-200 text-sm font-medium rounded-lg transition-colors flex items-center gap-1.5">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg>
                            Edit Settings
                        </button>
                    </div>
                ` : ''}
                <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                    <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3">
                        <label class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1 block">Ban Time (seconds)</label>
                        <input type="number" name="ban_time" value="${data.ban_time}" min="60"
                            class="w-full px-2 py-1.5 text-sm font-semibold rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            disabled />
                        <div class="text-xs text-gray-400 dark:text-gray-500 mt-0.5">${formatSeconds(data.ban_time)}</div>
                    </div>

                    <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3">
                        <label class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1 block">Max. Ban Time (seconds)</label>
                        <input type="number" name="max_ban_time" value="${data.max_ban_time}" min="60"
                            class="w-full px-2 py-1.5 text-sm font-semibold rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            disabled />
                        <div class="text-xs text-gray-400 dark:text-gray-500 mt-0.5">${formatSeconds(data.max_ban_time)}</div>
                    </div>

                    <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3">
                        <label class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1 block">Ban Time Increment</label>
                        <div class="mt-1">
                            <label class="relative inline-flex items-center cursor-pointer opacity-60" id="fail2ban-increment-label">
                                <input type="checkbox" name="ban_time_increment" ${data.ban_time_increment ? 'checked' : ''} disabled
                                    class="sr-only peer" />
                                <div class="w-9 h-5 bg-gray-300 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-600 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
                                <span class="ml-2 text-sm text-gray-700 dark:text-gray-300">${data.ban_time_increment ? 'Enabled' : 'Disabled'}</span>
                            </label>
                        </div>
                    </div>

                    <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3">
                        <label class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1 block">Max. Attempts</label>
                        <input type="number" name="max_attempts" value="${data.max_attempts}" min="1"
                            class="w-full px-2 py-1.5 text-sm font-semibold rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            disabled />
                    </div>

                    <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3">
                        <label class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1 block">Retry Window (seconds)</label>
                        <input type="number" name="retry_window" value="${data.retry_window}" min="1"
                            class="w-full px-2 py-1.5 text-sm font-semibold rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            disabled />
                        <div class="text-xs text-gray-400 dark:text-gray-500 mt-0.5">${formatSeconds(data.retry_window)}</div>
                    </div>

                    <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3">
                        <label class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1 block">Subnet Ban IPv4</label>
                        <div class="flex items-center gap-1">
                            <span class="text-sm text-gray-500 dark:text-gray-400">/</span>
                            <input type="number" name="netban_ipv4" value="${data.netban_ipv4}" min="8" max="32"
                                class="w-full px-2 py-1.5 text-sm font-semibold font-mono rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                disabled />
                        </div>
                    </div>

                    <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3">
                        <label class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1 block">Subnet Ban IPv6</label>
                        <div class="flex items-center gap-1">
                            <span class="text-sm text-gray-500 dark:text-gray-400">/</span>
                            <input type="number" name="netban_ipv6" value="${data.netban_ipv6}" min="8" max="128"
                                class="w-full px-2 py-1.5 text-sm font-semibold font-mono rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                disabled />
                        </div>
                    </div>
                </div>

                <div class="mt-4 flex justify-end" id="fail2ban-save-row" style="display:none">
                    <button type="submit" id="fail2ban-save-btn"
                        class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg shadow transition-colors focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 dark:focus:ring-offset-gray-800 flex items-center gap-2">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
                        Save Settings
                    </button>
                </div>
            </form>
        `;

        // Build unified active bans list (permanent + temporary)
        const activeBans = data.active_bans || [];
        const permBanNetworks = new Set(permBans.map(b => b.network || b.ip));
        // Temporary bans = active_bans entries NOT in perm_bans
        const tempBans = activeBans.filter(b => !permBanNetworks.has(b.network));
        // Sort both lists by IP address
        const ipSort = (a, b) => (a.ip || a.network || '').localeCompare(b.ip || b.network || '', undefined, { numeric: true });
        permBans.sort(ipSort);
        tempBans.sort(ipSort);
        const totalBans = permBans.length + tempBans.length;

        // Render IP lists in separate accordion (editable textareas)
        if (ipListsContainer) {
            ipListsContainer.innerHTML = `
                <form id="fail2ban-ip-form">
                    ${canEdit ? `
                        <div class="mb-3 flex justify-end" id="fail2ban-ip-edit-btn-row">
                            <button type="button" id="fail2ban-ip-enable-edit-btn"
                                class="px-3 py-1.5 bg-gray-200 dark:bg-gray-600 hover:bg-gray-300 dark:hover:bg-gray-500 text-gray-700 dark:text-gray-200 text-sm font-medium rounded-lg transition-colors flex items-center gap-1.5">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg>
                                Edit IP Lists
                            </button>
                        </div>
                    ` : ''}
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3">
                            <label class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2 block">Allowlisted <span class="text-gray-400 dark:text-gray-500">(${whitelistEntries.length})</span></label>
                            <textarea name="whitelist" rows="4" placeholder="One IP/network per line"
                                class="w-full px-2 py-1.5 text-sm font-mono rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-green-700 dark:text-green-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-y"
                                disabled>${escapeHtml((data.whitelist || '').replace(/,/g, '\n'))}</textarea>
                        </div>

                        <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3">
                            <label class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2 block">Denylisted <span class="text-gray-400 dark:text-gray-500">(${blacklistEntries.length})</span></label>
                            <textarea name="blacklist" rows="4" placeholder="One IP/network per line"
                                class="w-full px-2 py-1.5 text-sm font-mono rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-red-700 dark:text-red-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-y"
                                disabled>${escapeHtml((data.blacklist || '').replace(/,/g, '\n'))}</textarea>
                        </div>
                    </div>

                    <div class="mt-3 px-1 text-xs text-gray-500 dark:text-gray-400 italic">
                        A denylisted host or network will always outweigh an allowlisted entity. List updates will take a few seconds to be applied.
                    </div>

                    <div class="mt-3 flex justify-end" id="fail2ban-ip-save-row" style="display:none">
                        <button type="submit" id="fail2ban-ip-save-btn"
                            class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg shadow transition-colors focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 dark:focus:ring-offset-gray-800 flex items-center gap-2">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
                            Save IP Lists
                        </button>
                    </div>
                </form>

                <!-- Active Bans List -->
                <div class="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                    <div class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-3">
                        Active Bans <span class="text-gray-400 dark:text-gray-500">(${totalBans})</span>
                    </div>
                    ${totalBans > 0 ? `
                        <div class="space-y-2">
                            ${permBans.map(ban => `
                                <div class="flex items-center justify-between bg-gray-50 dark:bg-gray-700/50 rounded-lg px-3 py-2">
                                    <div class="flex items-center gap-3">
                                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400">Permanent</span>
                                        <span class="text-sm font-mono text-gray-900 dark:text-white">${escapeHtml(ban.network || ban.ip)}</span>
                                    </div>
                                </div>
                            `).join('')}
                            ${tempBans.map(ban => `
                                <div class="flex items-center justify-between bg-gray-50 dark:bg-gray-700/50 rounded-lg px-3 py-2">
                                    <div class="flex items-center gap-3">
                                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400">Temporary</span>
                                        <span class="text-sm font-mono text-gray-900 dark:text-white">${escapeHtml(ban.network || ban.ip)}</span>
                                        ${ban.banned_until ? `<span class="text-xs text-gray-500 dark:text-gray-400">${escapeHtml(ban.banned_until)} left</span>` : ''}
                                        ${ban.queued_for_unban ? `<span class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400">Unbanning...</span>` : ''}
                                    </div>
                                    ${canEdit && !ban.queued_for_unban ? `
                                        <button type="button" onclick="unbanIP('${escapeJsArg(ban.ip || ban.network)}', this)"
                                            class="px-2.5 py-1 text-xs font-medium rounded-md border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-400 hover:bg-red-50 hover:border-red-300 hover:text-red-700 dark:hover:bg-red-900/20 dark:hover:border-red-700 dark:hover:text-red-400 transition-colors">
                                            Unban
                                        </button>
                                    ` : ''}
                                </div>
                            `).join('')}
                        </div>
                    ` : '<div class="text-sm text-gray-400 dark:text-gray-500">No active bans</div>'}
                </div>
            `;
        }

        // Attach save handlers if edit is enabled
        if (canEdit) {
            // Edit Settings button handler
            const editSettingsBtn = document.getElementById('fail2ban-enable-edit-btn');
            if (editSettingsBtn) {
                editSettingsBtn.addEventListener('click', () => {
                    // Enable all inputs in settings form
                    const form = document.getElementById('fail2ban-edit-form');
                    form.querySelectorAll('input').forEach(el => { el.disabled = false; });
                    // Fix toggle opacity
                    const incrementLabel = document.getElementById('fail2ban-increment-label');
                    if (incrementLabel) incrementLabel.classList.remove('opacity-60');
                    // Hide edit button, show save button
                    document.getElementById('fail2ban-edit-btn-row').style.display = 'none';
                    document.getElementById('fail2ban-save-row').style.display = 'flex';
                });
            }

            // Edit IP Lists button handler
            const editIpBtn = document.getElementById('fail2ban-ip-enable-edit-btn');
            if (editIpBtn) {
                editIpBtn.addEventListener('click', () => {
                    const form = document.getElementById('fail2ban-ip-form');
                    form.querySelectorAll('textarea').forEach(el => { el.disabled = false; });
                    document.getElementById('fail2ban-ip-edit-btn-row').style.display = 'none';
                    document.getElementById('fail2ban-ip-save-row').style.display = 'flex';
                });
            }

            // Save settings form
            const settingsForm = document.getElementById('fail2ban-edit-form');
            if (settingsForm) {
                settingsForm.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const btn = document.getElementById('fail2ban-save-btn');
                    const origText = btn.innerHTML;
                    btn.disabled = true;
                    btn.innerHTML = '<div class="loading-sm mr-2"></div> Saving...';

                    try {
                        // Collect ALL settings values (must send everything)
                        const ipForm = document.getElementById('fail2ban-ip-form');
                        const whitelist = ipForm ? ipForm.querySelector('[name="whitelist"]').value.split('\n').filter(l => l.trim()).join(',') : data.whitelist || '';
                        const blacklist = ipForm ? ipForm.querySelector('[name="blacklist"]').value.split('\n').filter(l => l.trim()).join(',') : data.blacklist || '';

                        const payload = {
                            attr: {
                                ban_time: settingsForm.querySelector('[name="ban_time"]').value,
                                max_ban_time: settingsForm.querySelector('[name="max_ban_time"]').value,
                                ban_time_increment: settingsForm.querySelector('[name="ban_time_increment"]').checked ? '1' : '0',
                                max_attempts: settingsForm.querySelector('[name="max_attempts"]').value,
                                retry_window: settingsForm.querySelector('[name="retry_window"]').value,
                                netban_ipv4: settingsForm.querySelector('[name="netban_ipv4"]').value,
                                netban_ipv6: settingsForm.querySelector('[name="netban_ipv6"]').value,
                                whitelist: whitelist,
                                blacklist: blacklist
                            }
                        };

                        const res = await authenticatedFetch('/api/fail2ban', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(payload)
                        });

                        const result = await res.json();
                        if (res.ok && result.status === 'success') {
                            showToast('Fail2Ban settings saved successfully', 'success');
                            // Reset loaded flag so next open fetches fresh data
                            fail2banSettingsLoaded = false;
                        } else {
                            showToast('Failed to save Fail2Ban settings: ' + (result.msg || result.detail || 'Unknown error'), 'error');
                        }
                    } catch (err) {
                        showToast('Failed to save Fail2Ban settings: ' + err.message, 'error');
                    } finally {
                        btn.disabled = false;
                        btn.innerHTML = origText;
                    }
                });
            }

            // Save IP lists form
            const ipForm = document.getElementById('fail2ban-ip-form');
            if (ipForm) {
                ipForm.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const btn = document.getElementById('fail2ban-ip-save-btn');
                    const origText = btn.innerHTML;
                    btn.disabled = true;
                    btn.innerHTML = '<div class="loading-sm mr-2"></div> Saving...';

                    try {
                        // Collect ALL values from both forms (must send everything)
                        const sForm = document.getElementById('fail2ban-edit-form');
                        const whitelist = ipForm.querySelector('[name="whitelist"]').value.split('\n').filter(l => l.trim()).join(',');
                        const blacklist = ipForm.querySelector('[name="blacklist"]').value.split('\n').filter(l => l.trim()).join(',');

                        const payload = {
                            attr: {
                                ban_time: sForm.querySelector('[name="ban_time"]').value,
                                max_ban_time: sForm.querySelector('[name="max_ban_time"]').value,
                                ban_time_increment: sForm.querySelector('[name="ban_time_increment"]').checked ? '1' : '0',
                                max_attempts: sForm.querySelector('[name="max_attempts"]').value,
                                retry_window: sForm.querySelector('[name="retry_window"]').value,
                                netban_ipv4: sForm.querySelector('[name="netban_ipv4"]').value,
                                netban_ipv6: sForm.querySelector('[name="netban_ipv6"]').value,
                                whitelist: whitelist,
                                blacklist: blacklist
                            }
                        };

                        const res = await authenticatedFetch('/api/fail2ban', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(payload)
                        });

                        const result = await res.json();
                        if (res.ok && result.status === 'success') {
                            showToast('Fail2Ban IP lists saved successfully', 'success');
                            fail2banSettingsLoaded = false;
                        } else {
                            showToast('Failed to save Fail2Ban IP lists: ' + (result.msg || result.detail || 'Unknown error'), 'error');
                        }
                    } catch (err) {
                        showToast('Failed to save Fail2Ban IP lists: ' + err.message, 'error');
                    } finally {
                        btn.disabled = false;
                        btn.innerHTML = origText;
                    }
                });
            }
        }
    } catch (error) {
        console.error('Failed to load Fail2Ban settings:', error);
        settingsContainer.innerHTML = `<p class="text-red-500 text-center py-4">Failed to load Fail2Ban settings: ${escapeHtml(error.message)}</p>`;
        if (ipListsContainer) {
            ipListsContainer.innerHTML = `<p class="text-red-500 text-center py-4">Failed to load IP lists</p>`;
        }
    }
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
        container.innerHTML = '<div class="text-center py-8"><div class="loading mx-auto mb-4"></div><p class="text-gray-500 dark:text-gray-400">Loading...</p></div>';

        console.log('Loading Queue...');

        const response = await authenticatedFetch('/api/queue');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('Queue data:', data);

        allQueueData = data.data || [];
        applyQueueFilters();
    } catch (error) {
        console.error('Failed to load queue:', error);
        document.getElementById('queue-logs').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load queue: ${escapeHtml(error.message)}</p>`;
        const countEl = document.getElementById('queue-count');
        if (countEl) countEl.textContent = '';
    }
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
        container.innerHTML = '<p class="text-gray-500 dark:text-gray-400 text-center py-8">No matching queue entries</p>';
        return;
    }

    const canAct = mailcowRwConfigured;

    container.innerHTML = `
        ${canAct ? `
            <div class="mb-4 flex flex-wrap items-center gap-2">
                <button onclick="queueSelectAll()" id="queue-select-all-btn"
                    class="px-3 py-1.5 text-xs font-medium rounded-md border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors">
                    Select All
                </button>
                <button onclick="queueBulkRetry()" id="queue-bulk-retry-btn"
                    class="hidden px-3 py-1.5 text-xs font-medium rounded-md border border-blue-500 bg-blue-500 text-white hover:bg-blue-600 transition-colors flex items-center gap-1">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                    Retry Selected
                </button>
                <button onclick="queueBulkDelete()" id="queue-bulk-delete-btn"
                    class="hidden px-3 py-1.5 text-xs font-medium rounded-md border border-red-500 bg-red-500 text-white hover:bg-red-600 transition-colors flex items-center gap-1">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                    Delete Selected
                </button>
                <span id="queue-selection-count" class="hidden text-xs text-gray-500 dark:text-gray-400"></span>

                <div class="flex-1"></div>

                <button onclick="queueFlushAll()" id="queue-flush-all-btn"
                    class="px-3 py-1.5 text-xs font-medium rounded-md border border-blue-500 bg-blue-500 text-white hover:bg-blue-600 transition-colors flex items-center gap-1">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                    Flush All
                </button>
                <button onclick="queueDeleteAll()" id="queue-delete-all-btn"
                    class="px-3 py-1.5 text-xs font-medium rounded-md border border-red-500 bg-red-500 text-white hover:bg-red-600 transition-colors flex items-center gap-1">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                    Delete All
                </button>
            </div>
        ` : ''}
        <div class="space-y-4">
            ${filteredData.map(item => {
                const qid = item.queue_id || '';
                const queueName = (item.queue_name || '').toLowerCase();
                const isHold = queueName === 'hold';
                // Status badge colors
                const statusColors = {
                    hold: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300',
                    deferred: 'bg-orange-100 dark:bg-orange-900/30 text-orange-800 dark:text-orange-300',
                    active: 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300',
                    incoming: 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300',
                    bounce: 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300',
                    corrupt: 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300',
                };
                const badgeColor = statusColors[queueName] || 'bg-gray-100 dark:bg-gray-600 text-gray-800 dark:text-gray-200';
                return `
                <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4 bg-gray-50 dark:bg-gray-700/50" data-queue-id="${qid}">
                    <div class="flex flex-col sm:flex-row sm:justify-between sm:items-start mb-2 gap-2">
                        <div class="flex-1 flex items-start gap-3">
                            ${canAct ? `
                                <input type="checkbox" class="queue-checkbox mt-1 flex-shrink-0 w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 dark:focus:ring-blue-600 dark:ring-offset-gray-800 dark:bg-gray-700 dark:border-gray-600 cursor-pointer"
                                    value="${qid}" onchange="queueUpdateSelection()" />
                            ` : ''}
                            <div>
                                <p class="text-sm font-medium text-gray-900 dark:text-white">From: ${copyableText(item.sender)}</p>
                                <p class="text-sm text-gray-600 dark:text-gray-300">Queue ID: ${copyableText(qid)}</p>
                            </div>
                        </div>
                        <div class="flex items-center gap-2">
                            <span class="inline-block px-2 py-0.5 text-xs font-semibold rounded ${badgeColor} uppercase">${escapeHtml(item.queue_name || 'unknown')}</span>
                            <span class="text-xs text-gray-500 dark:text-gray-400">${formatTime(new Date(item.arrival_time * 1000).toISOString())}</span>
                        </div>
                    </div>
                    <div class="mb-2">
                        <p class="text-sm font-medium text-gray-700 dark:text-gray-300">Recipients:</p>
                        ${item.recipients.map(r => {
                            const emailOnly = r.split(' ')[0].replace(/[<>]/g, '').trim();
                            const errorPart = r.substring(r.indexOf(' ')).trim();
                            const hasError = errorPart && errorPart !== emailOnly && r.includes(' ');
                            return `<div class="ml-1 py-0.5">
                                <span class="text-sm font-medium text-gray-800 dark:text-gray-200">${copyableText(emailOnly)}</span>
                                ${hasError ? `<p class="text-xs text-gray-500 dark:text-gray-400 mt-0.5 break-words">${escapeHtml(errorPart)}</p>` : ''}
                            </div>`;
                        }).join('')}
                    </div>
                    <div class="flex flex-wrap items-center justify-between gap-2">
                        <span class="text-xs text-gray-500 dark:text-gray-400">Size: ${formatSize(item.message_size)}</span>
                        <div class="flex items-center gap-2 flex-shrink-0">
                            ${canAct ? `
                                <button onclick="queueRetry('${qid}')" title="Retry delivery"
                                    class="queue-action-btn px-2.5 py-1 text-xs font-medium rounded-md border border-blue-300 dark:border-blue-700 text-blue-700 dark:text-blue-400 hover:bg-blue-100 dark:hover:bg-blue-900/30 transition-colors flex items-center gap-1">
                                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                                    Retry
                                </button>
                                ${isHold ? `
                                    <button onclick="queueUnhold('${qid}')" title="Release from hold"
                                        class="queue-action-btn px-2.5 py-1 text-xs font-medium rounded-md border border-green-300 dark:border-green-700 text-green-700 dark:text-green-400 hover:bg-green-100 dark:hover:bg-green-900/30 transition-colors flex items-center gap-1">
                                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                                        Unhold
                                    </button>
                                ` : `
                                    <button onclick="queueHold('${qid}')" title="Hold message"
                                        class="queue-action-btn px-2.5 py-1 text-xs font-medium rounded-md border border-yellow-300 dark:border-yellow-700 text-yellow-700 dark:text-yellow-400 hover:bg-yellow-100 dark:hover:bg-yellow-900/30 transition-colors flex items-center gap-1">
                                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                                        Hold
                                    </button>
                                `}
                                <button onclick="queueDeleteItem('${qid}')" title="Delete from queue"
                                    class="queue-action-btn px-2.5 py-1 text-xs font-medium rounded-md border border-red-300 dark:border-red-700 text-red-700 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-900/30 transition-colors flex items-center gap-1">
                                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                                    Delete
                                </button>
                            ` : ''}
                            ${item.recipients.map(r => {
                                const emailOnly = r.split(' ')[0].replace(/[<>]/g, '');
                                return `
                                <button onclick="showAddSuppressionModal('${escapeJsArg(emailOnly)}')" title="Suppress ${escapeHtml(emailOnly)}"
                                    class="px-2.5 py-1 text-xs font-medium rounded-md border border-purple-300 dark:border-purple-700 text-purple-700 dark:text-purple-400 hover:bg-purple-100 dark:hover:bg-purple-900/30 transition-colors flex items-center gap-1">
                                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"></path></svg>
                                    Suppress
                                </button>`;
                            }).join('')}
                        </div>
                    </div>
                </div>
            `;
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
        container.innerHTML = '<div class="text-center py-8"><div class="loading mx-auto mb-4"></div><p class="text-gray-500 dark:text-gray-400">Loading...</p></div>';

        console.log('Loading Quarantine...');

        const response = await authenticatedFetch('/api/quarantine');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('Quarantine data:', data);

        // Update counter display
        const countEl = document.getElementById('quarantine-count');
        if (countEl) {
            countEl.textContent = data.total ? `(${data.total.toLocaleString()} results)` : '';
        }

        if (!data.data || data.data.length === 0) {
            quarantineLastData = data;
            container.innerHTML = '<p class="text-gray-500 dark:text-gray-400 text-center py-8">No quarantined messages</p>';
            return;
        }

        renderQuarantineData(data);
    } catch (error) {
        console.error('Failed to load quarantine:', error);
        document.getElementById('quarantine-logs').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load quarantine: ${escapeHtml(error.message)}</p>`;
        const countEl = document.getElementById('quarantine-count');
        if (countEl) countEl.textContent = '';
    }
}

// Render quarantine without loading spinner (for smart refresh)
function renderQuarantineData(data) {
    const container = document.getElementById('quarantine-logs');
    if (!container) return;

    // Keep the latest payload so sort changes can re-render without a re-fetch
    quarantineLastData = data;

    // Update counter display
    const countEl = document.getElementById('quarantine-count');
    if (countEl) {
        countEl.textContent = data.total ? `(${data.total.toLocaleString()} results)` : '';
    }

    if (!data.data || data.data.length === 0) {
        container.innerHTML = '<p class="text-gray-500 dark:text-gray-400 text-center py-8">No quarantined messages</p>';
        return;
    }

    const canAct = mailcowRwConfigured;
    const items = sortQuarantineItems(data.data);

    container.innerHTML = `
        ${!canAct ? '' : `
            <div class="mb-4 flex flex-wrap items-center gap-2">
                <button onclick="quarantineSelectAll()" id="quarantine-select-all-btn"
                    class="px-3 py-1.5 text-xs font-medium rounded-md border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors">
                    Select All
                </button>
                <button onclick="quarantineBulkRelease()" id="quarantine-bulk-release-btn"
                    class="hidden px-3 py-1.5 text-xs font-medium rounded-md border border-green-500 bg-green-500 text-white hover:bg-green-600 transition-colors flex items-center gap-1">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
                    Release Selected
                </button>
                <button onclick="quarantineBulkDelete()" id="quarantine-bulk-delete-btn"
                    class="hidden px-3 py-1.5 text-xs font-medium rounded-md border border-red-500 bg-red-500 text-white hover:bg-red-600 transition-colors flex items-center gap-1">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                    Delete Selected
                </button>
                <button onclick="quarantineBulkLearnHam()" id="quarantine-bulk-learnham-btn"
                    class="hidden px-3 py-1.5 text-xs font-medium rounded-md border border-emerald-500 bg-emerald-500 text-white hover:bg-emerald-600 transition-colors flex items-center gap-1">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                    Not Spam
                </button>
                <button onclick="quarantineBulkLearnSpam()" id="quarantine-bulk-learnspam-btn"
                    class="hidden px-3 py-1.5 text-xs font-medium rounded-md border border-orange-500 bg-orange-500 text-white hover:bg-orange-600 transition-colors flex items-center gap-1">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"></path></svg>
                    Learn Spam
                </button>
                <span id="quarantine-selection-count" class="hidden text-xs text-gray-500 dark:text-gray-400"></span>

                <div class="flex-1"></div>

                <button onclick="quarantineReleaseAll()" id="quarantine-release-all-btn"
                    class="px-3 py-1.5 text-xs font-medium rounded-md border border-green-500 bg-green-500 text-white hover:bg-green-600 transition-colors flex items-center gap-1">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
                    Release All
                </button>
                <button onclick="quarantineDeleteAll()" id="quarantine-delete-all-btn"
                    class="px-3 py-1.5 text-xs font-medium rounded-md border border-red-500 bg-red-500 text-white hover:bg-red-600 transition-colors flex items-center gap-1">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                    Delete All
                </button>
            </div>
        `}
        <div class="space-y-3">
            ${items.map(item => {
                const itemId = item.id !== undefined ? item.id : '';
                return `
                <div class="border border-red-200 dark:border-red-900/50 rounded-lg p-4 bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/30 transition" data-quarantine-id="${itemId}">
                    <div class="grid grid-cols-1 sm:grid-cols-[1fr_auto] gap-2 mb-2 items-start">
                        <div class="min-w-0 overflow-hidden flex items-start gap-3">
                            ${canAct ? `
                                <input type="checkbox" class="quarantine-checkbox mt-1 flex-shrink-0 w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 dark:focus:ring-blue-600 dark:ring-offset-gray-800 dark:bg-gray-700 dark:border-gray-600 cursor-pointer"
                                    value="${itemId}" onchange="quarantineUpdateSelection()" />
                            ` : ''}
                            <div class="min-w-0 overflow-hidden">
                                <div class="flex flex-wrap items-center gap-2 mb-1">
                                    <span class="text-sm font-medium text-gray-900 dark:text-white">${copyableText(item.sender || 'Unknown')}</span>
                                    <svg class="w-4 h-4 text-gray-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                                    </svg>
                                    <span class="text-sm text-gray-600 dark:text-gray-300">${copyableText(item.rcpt || 'Unknown')}</span>
                                </div>
                                <p class="text-xs text-gray-500 dark:text-gray-400 truncate cursor-pointer hover:text-blue-500 dark:hover:text-blue-400 transition-colors" title="Click to view details" onclick="showQuarantineDetails('${itemId}')">${escapeHtml(item.subject || 'No subject')}</p>
                            </div>
                        </div>
                        <div class="flex flex-wrap items-center gap-2 flex-shrink-0 sm:justify-end">
                            <span class="inline-block px-2 py-0.5 text-xs font-medium rounded bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300">${item.action || 'Quarantined'}</span>
                            ${item.virus_flag ? '<span class="inline-block px-2 py-0.5 text-xs font-medium rounded bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300">🦠 VIRUS</span>' : ''}
                        </div>
                    </div>
                    <div class="flex flex-col gap-2">
                        <div class="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-600 dark:text-gray-400">
                            <span>${formatTime(item.created)}</span>
                            ${item.qid ? `<span class="font-mono" title="Queue ID">Q: ${copyableText(item.qid)}</span>` : ''}
                            ${item.score !== undefined && item.score !== null ? `<span>Score: <span class="${item.score >= 15 ? 'text-red-600 dark:text-red-400 font-semibold' : 'text-gray-600 dark:text-gray-300'}">${item.score.toFixed(1)}</span></span>` : ''}
                        </div>
                        <div class="flex flex-wrap gap-1">
                            <button onclick="showQuarantineDetails('${itemId}')" title="View details"
                                class="quarantine-action-btn px-2 py-1 text-xs font-medium rounded-md border border-blue-300 dark:border-blue-700 text-blue-700 dark:text-blue-400 hover:bg-blue-100 dark:hover:bg-blue-900/30 transition-colors flex items-center justify-center gap-1">
                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path></svg>
                                Details
                            </button>
                            ${canAct ? `
                                <button onclick="quarantineRelease('${itemId}')" title="Release message"
                                    class="quarantine-action-btn px-2 py-1 text-xs font-medium rounded-md border border-green-300 dark:border-green-700 text-green-700 dark:text-green-400 hover:bg-green-100 dark:hover:bg-green-900/30 transition-colors flex items-center justify-center gap-1">
                                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
                                    Release
                                </button>
                                <button onclick="quarantineDelete('${itemId}')" title="Delete message"
                                    class="quarantine-action-btn px-2 py-1 text-xs font-medium rounded-md border border-red-300 dark:border-red-700 text-red-700 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-900/30 transition-colors flex items-center justify-center gap-1">
                                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                                    Delete
                                </button>
                                <button onclick="quarantineLearnHam('${itemId}')" title="Release & train as Not Spam"
                                    class="quarantine-action-btn px-2 py-1 text-xs font-medium rounded-md border border-emerald-300 dark:border-emerald-700 text-emerald-700 dark:text-emerald-400 hover:bg-emerald-100 dark:hover:bg-emerald-900/30 transition-colors flex items-center justify-center gap-1">
                                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                                    Not Spam
                                </button>
                                <button onclick="quarantineLearnSpam('${itemId}')" title="Delete & train as Spam"
                                    class="quarantine-action-btn px-2 py-1 text-xs font-medium rounded-md border border-orange-300 dark:border-orange-700 text-orange-700 dark:text-orange-400 hover:bg-orange-100 dark:hover:bg-orange-900/30 transition-colors flex items-center justify-center gap-1">
                                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"></path></svg>
                                    Spam
                                </button>
                                <button onclick="showAddRuleFromQuarantine('${escapeJsArg(item.sender || '')}', '${escapeJsArg(item.rcpt || '')}', '${escapeJsArg(item.subject || '')}')" title="Create auto-rule from this email"
                                    class="quarantine-action-btn px-2 py-1 text-xs font-medium rounded-md border border-amber-300 dark:border-amber-700 text-amber-700 dark:text-amber-400 hover:bg-amber-100 dark:hover:bg-amber-900/30 transition-colors flex items-center justify-center gap-1">
                                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
                                    Rule
                                </button>
                            ` : ''}
                        </div>
                    </div>
                </div>
            `;
            }).join('')}
        </div>
    `;
}

// --- Quarantine action helpers ---

function quarantineUpdateSelection() {
    const checked = document.querySelectorAll('.quarantine-checkbox:checked');
    const bulkBtns = ['quarantine-bulk-release-btn', 'quarantine-bulk-delete-btn', 'quarantine-bulk-learnham-btn', 'quarantine-bulk-learnspam-btn'];
    const countLabel = document.getElementById('quarantine-selection-count');

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
    // Create modal backdrop
    const existing = document.getElementById('quarantine-detail-modal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = 'quarantine-detail-modal';
    modal.className = 'fixed inset-0 z-[9999] flex items-center justify-center p-4';
    modal.innerHTML = `
        <div class="absolute inset-0 bg-black/60 backdrop-blur-sm" onclick="closeQuarantineDetails()"></div>
        <div class="relative bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
            <div class="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white">Quarantine Item Details</h3>
                <button onclick="closeQuarantineDetails()" class="p-1 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors">
                    <svg class="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="flex-1 overflow-y-auto p-4" id="quarantine-detail-content">
                <div class="flex items-center justify-center py-12">
                    <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
                    <span class="ml-3 text-gray-500 dark:text-gray-400">Loading details...</span>
                </div>
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
            <div class="text-center py-12 text-red-500">
                <p class="font-medium">Failed to load details</p>
                <p class="text-sm mt-1">${escapeHtml(err.message)}</p>
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
        `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300">
            <span class="font-medium uppercase text-[10px] ${r.type === 'smtp' ? 'text-blue-500' : 'text-gray-400'}">${escapeHtml(r.type)}</span>
            ${copyableText(r.address)}
        </span>`
    ).join(' ');

    const scoreColor = (data.score || 0) >= 15 ? 'text-red-600 dark:text-red-400' :
                       (data.score || 0) >= 6 ? 'text-orange-500 dark:text-orange-400' :
                       'text-green-600 dark:text-green-400';

    const buildSymbolRows = (syms) => syms.map(s => {
        const sc = s.score || 0;
        const cls = sc > 0 ? 'text-red-600 dark:text-red-400 font-semibold' :
                    sc < 0 ? 'text-green-600 dark:text-green-400 font-semibold' :
                    'text-gray-400 dark:text-gray-500';
        const opts = (s.options || []).join(', ');
        return `<tr class="border-b border-gray-100 dark:border-gray-700/50 hover:bg-gray-50 dark:hover:bg-gray-700/30">
            <td class="py-1.5 px-2 font-mono text-gray-800 dark:text-gray-200">${escapeHtml(s.name || '')}</td>
            <td class="py-1.5 px-2 text-gray-500 dark:text-gray-400">${escapeHtml(s.group || '')}</td>
            <td class="py-1.5 px-2 text-right ${cls}">${sc !== 0 ? (sc > 0 ? '+' : '') + sc.toFixed(2) : '0'}</td>
            <td class="py-1.5 px-2 text-gray-400 dark:text-gray-500 max-w-xs truncate" title="${escapeHtml(opts)}">${escapeHtml(opts)}</td>
        </tr>`;
    }).join('');

    const symbolTableHead = `<table class="w-full text-xs"><thead><tr class="border-b border-gray-200 dark:border-gray-700 text-left">
        <th class="py-2 px-2 font-medium text-gray-500 dark:text-gray-400">Symbol</th>
        <th class="py-2 px-2 font-medium text-gray-500 dark:text-gray-400">Group</th>
        <th class="py-2 px-2 font-medium text-gray-500 dark:text-gray-400 text-right">Score</th>
        <th class="py-2 px-2 font-medium text-gray-500 dark:text-gray-400">Details</th>
    </tr></thead>`;

    const textContent = data.text_plain || data.text_html || '';
    const canAct = mailcowRwConfigured;

    content.innerHTML = `
        <div class="space-y-5">
            <div class="space-y-3">
                <div>
                    <label class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Subject</label>
                    <p class="text-sm font-medium text-gray-900 dark:text-white mt-0.5">${copyableText(data.subject || '-')}</p>
                </div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                        <label class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">From (Header)</label>
                        <p class="text-sm text-gray-800 dark:text-gray-200 mt-0.5">${copyableText(data.header_from || '-')}</p>
                    </div>
                    <div>
                        <label class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Envelope From</label>
                        <p class="text-sm text-gray-800 dark:text-gray-200 mt-0.5 font-mono">${copyableText(data.env_from || '-')}</p>
                    </div>
                </div>
                <div>
                    <label class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Recipients</label>
                    <div class="flex flex-wrap gap-1 mt-1">${recipientsHtml || '<span class="text-sm text-gray-500">-</span>'}</div>
                </div>
                <div class="flex items-center gap-4">
                    <div>
                        <label class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Score</label>
                        <p class="text-lg font-bold ${scoreColor} mt-0.5">${(data.score || 0).toFixed(2)}</p>
                    </div>
                    <div>
                        <label class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Action</label>
                        <p class="mt-0.5"><span class="inline-block px-2 py-0.5 text-xs font-medium rounded bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300">${escapeHtml(data.action || '-')}</span></p>
                    </div>
                </div>
            </div>

            <div>
                <h4 class="text-sm font-semibold text-gray-900 dark:text-white mb-2 flex items-center gap-2">
                    <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path></svg>
                    Rspamd Symbols
                </h4>
                ${activeSymbols.length > 0 ? `<div class="overflow-x-auto">${symbolTableHead}<tbody>${buildSymbolRows(activeSymbols)}</tbody></table></div>` : '<p class="text-gray-500 text-sm">No active symbols</p>'}
                ${zeroSymbols.length > 0 ? `
                <details class="mt-2">
                    <summary class="text-xs text-gray-500 dark:text-gray-400 cursor-pointer hover:text-gray-700 dark:hover:text-gray-300 select-none py-1">
                        Informational symbols (score 0) - ${zeroSymbols.length} items
                    </summary>
                    <div class="overflow-x-auto mt-1">${symbolTableHead}<tbody>${buildSymbolRows(zeroSymbols)}</tbody></table></div>
                </details>` : ''}
            </div>

            ${textContent ? `
            <div>
                <h4 class="text-sm font-semibold text-gray-900 dark:text-white mb-2 flex items-center gap-2">
                    <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
                    Email Content
                </h4>
                <pre class="text-xs bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap max-h-64 overflow-y-auto text-gray-800 dark:text-gray-200">${escapeHtml(textContent)}</pre>
            </div>` : ''}

            ${data.fuzzy_hashes && data.fuzzy_hashes.length > 0 ? `
            <div>
                <h4 class="text-sm font-semibold text-gray-900 dark:text-white mb-2">Fuzzy Hashes</h4>
                <div class="text-xs font-mono bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-3">${data.fuzzy_hashes.map(h => escapeHtml(JSON.stringify(h))).join('<br>')}</div>
            </div>` : ''}
        </div>
    `;

    // Render sticky footer with action buttons
    if (footer && canAct) {
        footer.className = 'grid grid-cols-4 gap-1.5 p-3 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900/50';
        footer.innerHTML = `
            <button onclick="closeQuarantineDetails(); quarantineRelease('${itemId}')"
                class="py-2 text-xs font-medium rounded-md bg-green-500 text-white hover:bg-green-600 transition-colors flex items-center justify-center gap-1">
                <svg class="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
                Release
            </button>
            <button onclick="closeQuarantineDetails(); quarantineDelete('${itemId}')"
                class="py-2 text-xs font-medium rounded-md bg-red-500 text-white hover:bg-red-600 transition-colors flex items-center justify-center gap-1">
                <svg class="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                Delete
            </button>
            <button onclick="closeQuarantineDetails(); quarantineLearnHam('${itemId}')"
                class="py-2 text-xs font-medium rounded-md bg-emerald-500 text-white hover:bg-emerald-600 transition-colors flex items-center justify-center gap-1">
                <svg class="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                Not Spam
            </button>
            <button onclick="closeQuarantineDetails(); quarantineLearnSpam('${itemId}')"
                class="py-2 text-xs font-medium rounded-md bg-orange-500 text-white hover:bg-orange-600 transition-colors flex items-center justify-center gap-1">
                <svg class="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"></path></svg>
                Spam
            </button>
        `;
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
    
    if (mailcowRwConfigured) {
        section.classList.remove('hidden');
        loadQuarantineRules();
    }
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
        
        if (!data.data || data.data.length === 0) {
            container.innerHTML = '<p class="text-gray-500 dark:text-gray-400 text-center py-4 text-sm">No rules configured. Click "Add Rule" to create one.</p>';
            return;
        }
        
        container.innerHTML = data.data.map(rule => {
            const matchLabels = { sender: 'Sender', sender_domain: 'Sender Domain', recipient: 'Recipient', subject: 'Subject' };
            const actionColor = rule.action === 'delete' ? 'red' : 'green';
            const actionLabel = rule.action === 'delete' ? 'Delete' : 'Release';
            
            return `
            <div class="border ${rule.enabled ? 'border-gray-200 dark:border-gray-700' : 'border-gray-100 dark:border-gray-800 opacity-60'} rounded-lg p-3 bg-white dark:bg-gray-800 hover:border-gray-300 dark:hover:border-gray-600 transition">
                <div class="flex items-center justify-between gap-3">
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-2 mb-1 flex-wrap">
                            <span class="font-medium text-sm text-gray-900 dark:text-white">${escapeHtml(rule.name)}</span>
                            <span class="px-2 py-0.5 text-xs rounded-full bg-${actionColor}-100 dark:bg-${actionColor}-900/30 text-${actionColor}-700 dark:text-${actionColor}-300">${actionLabel}</span>
                            ${rule.is_regex ? '<span class="px-2 py-0.5 text-xs rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300">Regex</span>' : ''}
                            ${!rule.enabled ? '<span class="px-2 py-0.5 text-xs rounded-full bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400">Disabled</span>' : ''}
                        </div>
                        <p class="text-xs text-gray-500 dark:text-gray-400">
                            <span class="font-medium">${matchLabels[rule.match_type] || rule.match_type}:</span> 
                            <code class="bg-gray-100 dark:bg-gray-700 px-1 rounded">${escapeHtml(rule.match_value)}</code>
                        </p>
                        <p class="text-xs text-gray-400 dark:text-gray-500 mt-1">
                            Hits: ${rule.hit_count}${rule.last_hit_at ? ' · Last: ' + formatTime(rule.last_hit_at) : ''}
                            ${rule.notes ? ' · ' + escapeHtml(rule.notes) : ''}
                        </p>
                    </div>
                    <div class="flex items-center gap-1 flex-shrink-0">
                        <button onclick="toggleQuarantineRule(${rule.id})" title="${rule.enabled ? 'Click to disable this rule' : 'Click to enable this rule'}"
                            class="px-2 py-1 text-xs rounded-md font-medium transition ${rule.enabled 
                                ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300 hover:bg-green-200 dark:hover:bg-green-900/50' 
                                : 'bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-600'}">
                            ${rule.enabled ? 'Enabled' : 'Disabled'}
                        </button>
                        <button onclick="showEditQuarantineRuleModal(${rule.id})" title="Edit"
                            class="p-1.5 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition text-gray-400 hover:text-blue-500">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg>
                        </button>
                        <button onclick="deleteQuarantineRule(${rule.id}, '${escapeJsArg(rule.name)}')" title="Delete"
                            class="p-1.5 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition text-gray-400 hover:text-red-500">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                        </button>
                    </div>
                </div>
            </div>`;
        }).join('');
    } catch (err) {
        console.error('Failed to load quarantine rules:', err);
        container.innerHTML = `<p class="text-red-500 text-center py-4 text-sm">Failed to load rules: ${escapeHtml(err.message)}</p>`;
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
    const defaultName = isEdit ? escapeHtml(rule.name) : (prefill ? `Rule for ${prefill.sender}` : '');
    const defaultMatchType = isEdit ? rule.match_type : (prefill ? 'sender' : 'sender');
    const defaultMatchValue = isEdit ? escapeHtml(rule.match_value) : (prefill ? escapeHtml(prefill.sender) : '');
    const defaultAction = isEdit ? rule.action : 'release';
    const defaultIsRegex = isEdit ? rule.is_regex : false;
    const defaultNotes = isEdit && rule.notes ? escapeHtml(rule.notes) : '';
    
    // For pre-fill mode, provide quick-fill buttons for sender/domain/recipient
    const prefillButtons = prefill ? `
        <div class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-3 mb-4">
            <p class="text-xs font-medium text-blue-700 dark:text-blue-300 mb-2">Quick fill from email:</p>
            <div class="flex flex-wrap gap-1.5">
                <button type="button" onclick="qrulePrefill('sender', '${escapeJsArg(prefill.sender)}')"
                    class="px-2 py-1 text-xs rounded bg-blue-100 dark:bg-blue-800 text-blue-700 dark:text-blue-300 hover:bg-blue-200 dark:hover:bg-blue-700 transition">Sender: ${escapeHtml(prefill.sender)}</button>
                ${prefill.senderDomain ? `<button type="button" onclick="qrulePrefill('sender_domain', '${escapeJsArg(prefill.senderDomain)}')"
                    class="px-2 py-1 text-xs rounded bg-blue-100 dark:bg-blue-800 text-blue-700 dark:text-blue-300 hover:bg-blue-200 dark:hover:bg-blue-700 transition">Domain: ${escapeHtml(prefill.senderDomain)}</button>` : ''}
                <button type="button" onclick="qrulePrefill('recipient', '${escapeJsArg(prefill.recipient)}')"
                    class="px-2 py-1 text-xs rounded bg-blue-100 dark:bg-blue-800 text-blue-700 dark:text-blue-300 hover:bg-blue-200 dark:hover:bg-blue-700 transition">Recipient: ${escapeHtml(prefill.recipient)}</button>
            </div>
        </div>
    ` : '';
    
    const html = `
    <div class="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4" id="quarantine-rule-modal-overlay">
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white">${title}</h3>
                <button onclick="closeQuarantineRuleModal()" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 space-y-4">
                ${prefillButtons}
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Rule Name</label>
                    <input type="text" id="qrule-name" value="${defaultName}" 
                        class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg" placeholder="e.g., Allow notifications from service X">
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Match Type</label>
                        <select id="qrule-match-type" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg">
                            <option value="sender" ${defaultMatchType === 'sender' ? 'selected' : ''}>Sender</option>
                            <option value="sender_domain" ${defaultMatchType === 'sender_domain' ? 'selected' : ''}>Sender Domain</option>
                            <option value="recipient" ${defaultMatchType === 'recipient' ? 'selected' : ''}>Recipient</option>
                            <option value="subject" ${defaultMatchType === 'subject' ? 'selected' : ''}>Subject</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Action</label>
                        <select id="qrule-action" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg">
                            <option value="release" ${defaultAction === 'release' ? 'selected' : ''}>✅ Release</option>
                            <option value="delete" ${defaultAction === 'delete' ? 'selected' : ''}>🗑️ Delete</option>
                        </select>
                    </div>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Match Value</label>
                    <input type="text" id="qrule-match-value" value="${defaultMatchValue}"
                        class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg font-mono" placeholder="e.g., noreply@example.com">
                    <div class="mt-2">
                        <label class="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Match Mode</label>
                        <select id="qrule-match-mode" onchange="updateQRuleMatchHelp()" class="w-full px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg">
                            <option value="exact" ${!defaultIsRegex ? 'selected' : ''}>Exact Match - matches the full value exactly</option>
                            <option value="contains" ${defaultIsRegex && !(isEdit && rule.match_value.startsWith('^')) ? 'selected' : ''}>Contains - matches if value appears anywhere</option>
                            <option value="regex" ${defaultIsRegex && isEdit && rule.match_value.startsWith('^') ? 'selected' : ''}>Regex (advanced) - custom regular expression</option>
                        </select>
                        <p id="qrule-match-help" class="text-xs text-gray-400 dark:text-gray-500 mt-1"></p>
                    </div>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Notes (optional)</label>
                    <textarea id="qrule-notes" rows="2" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg" placeholder="Why this rule exists...">${defaultNotes}</textarea>
                </div>
                <div class="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg p-3">
                    <p class="text-xs text-amber-700 dark:text-amber-300">
                        <strong>Priority:</strong> Delete rules always take priority over Release rules. If both match, the email will be deleted.
                    </p>
                </div>
            </div>
            <div class="px-6 py-4 border-t border-gray-200 dark:border-gray-700 flex justify-end gap-2">
                <button onclick="closeQuarantineRuleModal()" class="px-4 py-2 text-sm font-medium rounded-lg border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
                <button onclick="saveQuarantineRule(${isEdit ? rule.id : 'null'})" class="px-4 py-2 text-sm font-medium rounded-lg bg-amber-500 hover:bg-amber-600 text-white transition">
                    ${isEdit ? 'Save Changes' : 'Create Rule'}
                </button>
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
            const actionColor = group.action === 'delete' ? 'red' : 'green';
            const itemsHtml = group.items.map(m => `
                <div class="py-1.5 pl-3 border-l-2 ${group.rule_enabled ? 'border-' + actionColor + '-300 dark:border-' + actionColor + '-700' : 'border-gray-300 dark:border-gray-600'}">
                    <div class="text-xs text-gray-700 dark:text-gray-300">${escapeHtml(m.sender || '?')} → ${escapeHtml(m.recipient || '?')}</div>
                    <div class="text-xs text-gray-400 dark:text-gray-500 truncate" title="${escapeHtml(m.subject || '')}">${escapeHtml((m.subject || 'No subject').substring(0, 80))}</div>
                </div>
            `).join('');
            
            return `
            <div class="mb-4 ${!group.rule_enabled ? 'opacity-50' : ''}">
                <div class="flex items-center gap-2 mb-1.5 flex-wrap">
                    <span class="font-medium text-sm text-gray-900 dark:text-white">${escapeHtml(group.rule_name)}</span>
                    <span class="px-1.5 py-0.5 text-xs rounded bg-${actionColor}-100 dark:bg-${actionColor}-900/30 text-${actionColor}-700 dark:text-${actionColor}-300">${group.action}</span>
                    ${!group.rule_enabled ? '<span class="px-1.5 py-0.5 text-xs rounded bg-gray-200 dark:bg-gray-700 text-gray-500 dark:text-gray-400">Disabled - will not execute</span>' : ''}
                    <span class="text-xs text-gray-400 ml-auto">${group.items.length} match${group.items.length !== 1 ? 'es' : ''}</span>
                </div>
                <div class="space-y-1">${itemsHtml}</div>
            </div>`;
        }).join('');
        
        const disabledCount = data.matches.filter(m => !m.rule_enabled).length;
        const activeCount = data.matches.length - disabledCount;
        const noMatches = data.total_matches === 0;
        
        const html = `
        <div class="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4" id="qrule-test-modal">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-lg max-h-[80vh] overflow-y-auto">
                <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
                    <h3 class="text-lg font-semibold text-gray-900 dark:text-white">Test Results</h3>
                    <button onclick="document.getElementById('qrule-test-modal').remove()" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                    </button>
                </div>
                <div class="p-6">
                    <div class="flex items-center gap-3 mb-4 pb-3 border-b border-gray-100 dark:border-gray-700">
                        <div class="text-center">
                            <div class="text-2xl font-bold text-gray-900 dark:text-white">${data.total_matches}</div>
                            <div class="text-xs text-gray-500">matched</div>
                        </div>
                        <div class="text-center text-gray-300 dark:text-gray-600">/</div>
                        <div class="text-center">
                            <div class="text-2xl font-bold text-gray-400">${data.total_quarantine}</div>
                            <div class="text-xs text-gray-500">total</div>
                        </div>
                        ${disabledCount > 0 ? `<div class="ml-auto text-xs text-amber-600 dark:text-amber-400">⚠ ${disabledCount} from disabled rules</div>` : ''}
                    </div>
                    ${noMatches ? '<p class="text-sm text-gray-500 text-center py-4">No quarantine items matched any rules.</p>' : groupsHtml}
                    <p class="text-xs text-gray-400 dark:text-gray-500 mt-4 pt-3 border-t border-gray-100 dark:border-gray-700 text-center">This is a dry-run preview. No actions were taken.</p>
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
    
    container.innerHTML = '<p class="text-gray-400 text-xs text-center py-2">Loading...</p>';
    
    try {
        const res = await authenticatedFetch('/api/quarantine/rules/logs?limit=20');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        
        if (!data.data || data.data.length === 0) {
            container.innerHTML = '<p class="text-gray-400 text-xs text-center py-2">No actions recorded yet</p>';
            return;
        }
        
        container.innerHTML = data.data.map(log => `
            <div class="flex items-center gap-2 py-1.5 border-b border-gray-100 dark:border-gray-700/50 text-xs">
                <span class="px-1.5 py-0.5 rounded ${log.action === 'delete' ? 'bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400' : 'bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-400'}">${log.action}</span>
                <span class="text-gray-500 dark:text-gray-400 flex-1 truncate" title="${escapeHtml(log.sender || '')} → ${escapeHtml(log.recipient || '')}">
                    ${escapeHtml(log.sender || '?')} → ${escapeHtml(log.recipient || '?')}
                </span>
                <span class="text-gray-400 dark:text-gray-500 flex-shrink-0" title="Rule: ${escapeHtml(log.rule_name || '')}">${formatTime(log.created_at)}</span>
            </div>
        `).join('');
    } catch (err) {
        container.innerHTML = `<p class="text-red-500 text-xs text-center py-2">Failed: ${escapeHtml(err.message)}</p>`;
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
    // Reset preset button styles
    document.querySelectorAll('.messages-date-preset-btn').forEach(btn => {
        if (btn.getAttribute('data-preset') === '') {
            btn.className = 'messages-date-preset-btn px-3 py-1.5 text-xs font-medium rounded-md border border-blue-500 bg-blue-500 text-white transition-colors';
        } else {
            btn.className = 'messages-date-preset-btn px-3 py-1.5 text-xs font-medium rounded-md border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors';
        }
    });
    currentFilters.messages = {};
    currentPage.messages = 1;
    loadMessages();
}

// =============================================================================
// MESSAGES DATE RANGE PICKER
// =============================================================================

function toggleMessagesDateRangePicker() {
    const dropdown = document.getElementById('messages-date-range-dropdown');
    const arrow = document.getElementById('messages-date-range-arrow');
    const isHidden = dropdown.classList.contains('hidden');
    dropdown.classList.toggle('hidden');
    arrow.style.transform = isHidden ? 'rotate(180deg)' : '';
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

    // Update preset button styles
    document.querySelectorAll('.messages-date-preset-btn').forEach(btn => {
        if (btn.getAttribute('data-preset') === preset) {
            btn.className = 'messages-date-preset-btn px-3 py-1.5 text-xs font-medium rounded-md border border-blue-500 bg-blue-500 text-white transition-colors';
        } else {
            btn.className = 'messages-date-preset-btn px-3 py-1.5 text-xs font-medium rounded-md border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors';
        }
    });

    // Close dropdown and apply
    document.getElementById('messages-date-range-dropdown').classList.add('hidden');
    document.getElementById('messages-date-range-arrow').style.transform = '';
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

    // Reset preset button styles
    document.querySelectorAll('.messages-date-preset-btn').forEach(btn => {
        btn.className = 'messages-date-preset-btn px-3 py-1.5 text-xs font-medium rounded-md border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors';
    });

    // Close dropdown and apply
    document.getElementById('messages-date-range-dropdown').classList.add('hidden');
    document.getElementById('messages-date-range-arrow').style.transform = '';
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

async function loadMessages(page = 1) {
    const container = document.getElementById('messages-logs');

    try {
        container.innerHTML = '<div class="text-center py-8"><div class="loading mx-auto mb-4"></div><p class="text-gray-500 dark:text-gray-400">Loading...</p></div>';

        const filters = currentFilters.messages || {};
        const params = new URLSearchParams({
            page: page,
            limit: 50
        });

        if (filters.search) params.append('search', filters.search);
        if (filters.sender) params.append('sender', filters.sender);
        if (filters.recipient) params.append('recipient', filters.recipient);
        if (filters.direction) params.append('direction', filters.direction);
        if (filters.user) params.append('user', filters.user);
        if (filters.status) params.append('status', filters.status);
        if (filters.ip) params.append('ip', filters.ip);
        if (filters.start_date) params.append('start_date', filters.start_date);
        if (filters.end_date) params.append('end_date', filters.end_date);

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
            countEl.textContent = data.total ? `(${data.total.toLocaleString()} results)` : '';
        }

        if (!data.data || data.data.length === 0) {
            container.innerHTML = '<p class="text-gray-500 dark:text-gray-400 text-center py-8">No messages found</p>';
            return;
        }

        container.innerHTML = `
            <div class="space-y-3">
                ${data.data.map(msg => `
                    <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition cursor-pointer" onclick="viewMessageDetails('${msg.correlation_key}')">
                        <div class="grid grid-cols-1 sm:grid-cols-[1fr_auto] gap-2 mb-2 items-start">
                            <div class="min-w-0 overflow-hidden">
                                <div class="flex flex-wrap items-center gap-2 mb-1">
                                    <span class="text-sm font-medium text-gray-900 dark:text-white">${escapeHtml(msg.sender || 'Unknown')}</span>
                                    <svg class="w-4 h-4 text-gray-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                                    </svg>
                                    <span class="text-sm text-gray-600 dark:text-gray-300">${escapeHtml(msg.recipient || 'Unknown')}</span>
                                </div>
                                <p class="text-xs text-gray-500 dark:text-gray-400 truncate" title="${escapeHtml(msg.subject || 'No subject')}">${escapeHtml(msg.subject || 'No subject')}</p>
                            </div>
                            <div class="flex flex-wrap items-center gap-2 flex-shrink-0 sm:justify-end">
                                ${(() => {
                const correlationStatus = getCorrelationStatusDisplay(msg);
                if (correlationStatus) {
                    return `<span class="inline-block px-2 py-0.5 text-xs font-medium rounded ${correlationStatus.class}" title="${msg.final_status || (msg.is_complete ? 'Correlation complete' : 'Waiting for Postfix logs')}">${correlationStatus.display}</span>`;
                }
                return '';
            })()}
                                ${msg.direction ? `<span class="inline-block px-2 py-0.5 text-xs font-medium rounded ${getDirectionClass(msg.direction)}">${msg.direction}</span>` : ''}
                                ${msg.is_spam !== null ? `<span class="inline-block px-2 py-0.5 text-xs font-medium rounded ${msg.is_spam ? 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300' : 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300'}">${msg.is_spam ? 'SPAM' : 'CLEAN'}</span>` : ''}
                            </div>
                        </div>
                        <div class="flex flex-wrap items-center gap-4 text-xs text-gray-500 dark:text-gray-400">
                            <span>${formatTime(msg.first_seen)}</span>
                            ${msg.queue_id ? `<span class="font-mono" title="Queue ID">Q: ${msg.queue_id}</span>` : ''}
                            ${msg.message_id ? `<span class="font-mono truncate max-w-xs" title="Message ID: ${escapeHtml(msg.message_id)}">MID: ${escapeHtml(msg.message_id.substring(0, 20))}${msg.message_id.length > 20 ? '...' : ''}</span>` : ''}
                            ${msg.spam_score !== null ? `<span>Score: <span class="${msg.spam_score >= 15 ? 'text-red-600 dark:text-red-400 font-semibold' : 'text-gray-600 dark:text-gray-300'}">${msg.spam_score.toFixed(1)}</span></span>` : ''}
                            ${msg.user ? `<span>User: ${escapeHtml(msg.user)}</span>` : ''}
                            ${msg.ip ? `<span>IP: ${msg.ip}</span>` : ''}
                        </div>
                    </div>
                `).join('')}
            </div>
            ${renderPagination('messages', data.page, data.pages)}
        `;

        currentPage.messages = page;
    } catch (error) {
        console.error('Failed to load messages:', error);
        document.getElementById('messages-logs').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load messages: ${escapeHtml(error.message)}</p>`;
        const countEl = document.getElementById('messages-count');
        if (countEl) countEl.textContent = '';
    }
}

// =============================================================================
// STATUS TAB
// =============================================================================

async function loadStatus() {
    try {
        await Promise.all([
            loadStatusContainers(),
            loadStatusSystem(),
            loadStatusStorage(),
            loadStatusExtended()
        ]);
    } catch (error) {
        console.error('Failed to load status:', error);
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
                started_at: value.started_at || null
            }));
        }

        if (containersList.length > 0) {
            // Normalize states and count: only 'running' is running, everything else is stopped
            // This includes: paused, exited, stopped, created, restarting, removing, dead, unknown, etc.
            const running = containersList.filter(c => {
                const state = (c.state || 'unknown').toString().toLowerCase().trim();
                return state === 'running';
            }).length;
            const stopped = containersList.length - running;
            const total = containersList.length;

            container.innerHTML = `
                <!-- Summary FIRST -->
                <div class="mb-4 pb-4 border-b border-gray-200 dark:border-gray-700">
                    <div class="grid grid-cols-3 gap-4 text-center">
                        <div>
                            <p class="text-xs text-gray-500 dark:text-gray-400">Total</p>
                            <p class="text-xl font-bold text-gray-900 dark:text-white">${total}</p>
                        </div>
                        <div>
                            <p class="text-xs text-gray-500 dark:text-gray-400">Running</p>
                            <p class="text-xl font-bold text-green-600 dark:text-green-400">${running}</p>
                        </div>
                        <div>
                            <p class="text-xs text-gray-500 dark:text-gray-400">Stopped</p>
                            <p class="text-xl font-bold text-red-600 dark:text-red-400">${stopped}</p>
                        </div>
                    </div>
                </div>
                
                <!-- Containers list -->
                <div class="space-y-2 max-h-96 overflow-y-auto" style="scrollbar-width: thin;">
                    ${containersList.map(c => `
                        <div class="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                            <div class="flex items-center gap-3 flex-1">
                                <div class="w-2 h-2 rounded-full flex-shrink-0 ${c.state === 'running' ? 'bg-green-500' : 'bg-red-500'}"></div>
                                <div class="min-w-0 flex-1">
                                    <p class="text-sm font-medium text-gray-900 dark:text-white truncate">${escapeHtml(c.name)}</p>
                                    <p class="text-xs text-gray-500 dark:text-gray-400">${c.started_at ? new Date(c.started_at).toLocaleString('he-IL', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Unknown'}</p>
                                </div>
                            </div>
                            <span class="text-xs px-2 py-1 rounded flex-shrink-0 ${c.state === 'running' ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300' : 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300'}">${c.state}</span>
                        </div>
                    `).join('')}
                </div>
            `;
        } else {
            container.innerHTML = '<p class="text-gray-500 dark:text-gray-400 text-center py-8">No container information available</p>';
        }
    } catch (error) {
        console.error('Failed to load containers status:', error);
        document.getElementById('status-containers').innerHTML = '<p class="text-red-500 text-center py-8">Failed to load containers</p>';
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

            const updateBadge = versionData.update_available ?
                `<button onclick="showMailcowUpdateModal()" 
                    class="ml-2 px-2 py-0.5 bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 rounded text-xs font-medium hover:bg-blue-200 dark:hover:bg-blue-900/50 cursor-pointer transition-colors">
                    Update Available
                </button>` : '';

            versionHtml = `
                <div class="mt-4 pt-4 border-t border-gray-100 dark:border-gray-700 mx-1">
                    <div class="flex items-center justify-between">
                        <span class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">mailcow Version</span>
                        <div class="flex items-center">
                            <span class="text-sm font-bold text-gray-900 dark:text-white">v${versionData.current_version}</span>
                            ${updateBadge}
                        </div>
                    </div>
                </div>
            `;
        }

        container.innerHTML = `
            <div class="space-y-4">
                <div class="grid grid-cols-2 gap-4">
                    <div class="text-center p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                        <p class="text-xs text-gray-500 dark:text-gray-400 uppercase mb-1">Domains</p>
                        <p class="text-2xl font-bold text-gray-900 dark:text-white">${data.domains.total}</p>
                        <p class="text-xs text-green-600 dark:text-green-400 mt-1">${data.domains.active} active</p>
                    </div>
                    <div class="text-center p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                        <p class="text-xs text-gray-500 dark:text-gray-400 uppercase mb-1">Mailboxes</p>
                        <p class="text-2xl font-bold text-gray-900 dark:text-white">${data.mailboxes.total}</p>
                        <p class="text-xs text-green-600 dark:text-green-400 mt-1">${data.mailboxes.active} active</p>
                    </div>
                </div>
                <div class="text-center p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                    <p class="text-xs text-gray-500 dark:text-gray-400 uppercase mb-1">Aliases</p>
                    <p class="text-2xl font-bold text-gray-900 dark:text-white">${data.aliases.total}</p>
                    <p class="text-xs text-green-600 dark:text-green-400 mt-1">${data.aliases.active} active</p>
                </div>
                ${versionHtml}
            </div>
        `;
    } catch (error) {
        console.error('Failed to load system info:', error);
        document.getElementById('status-system').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load system info: ${escapeHtml(error.message)}</p>`;
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
        const storageColor = usedPercent > 90 ? 'bg-red-600' :
            usedPercent > 75 ? 'bg-yellow-600' :
                'bg-green-600';
        const textColor = usedPercent > 90 ? 'text-red-600 dark:text-red-400' :
            usedPercent > 75 ? 'text-yellow-600 dark:text-yellow-400' :
                'text-green-600 dark:text-green-400';

        container.innerHTML = `
            <div class="space-y-6">
                <div class="text-center">
                    <p class="text-5xl font-bold ${textColor} mb-2">${data.used_percent}</p>
                    <p class="text-sm text-gray-600 dark:text-gray-400">Storage Used</p>
                </div>
                
                <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-4">
                    <div class="${storageColor} h-4 rounded-full transition-all duration-300" style="width: ${usedPercent}%"></div>
                </div>
                
                <div class="grid grid-cols-2 gap-4 text-center">
                    <div>
                        <p class="text-xs text-gray-500 dark:text-gray-400 mb-1">Used</p>
                        <p class="text-lg font-semibold text-gray-900 dark:text-white">${data.used}</p>
                    </div>
                    <div>
                        <p class="text-xs text-gray-500 dark:text-gray-400 mb-1">Total</p>
                        <p class="text-lg font-semibold text-gray-900 dark:text-white">${data.total}</p>
                    </div>
                </div>
                
                <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3">
                    <p class="text-xs text-gray-600 dark:text-gray-400">
                        <svg class="inline w-4 h-4 mr-1" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>
                        </svg>
                        Disk: ${data.disk}
                    </p>
                </div>
            </div>
        `;
    } catch (error) {
        console.error('Failed to load storage info:', error);
        document.getElementById('status-storage').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load storage info: ${escapeHtml(error.message)}</p>`;
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
        document.getElementById('status-import').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load: ${escapeHtml(error.message)}</p>`;
        document.getElementById('status-correlation').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load: ${escapeHtml(error.message)}</p>`;
        document.getElementById('status-jobs').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load: ${escapeHtml(error.message)}</p>`;
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
            <div id="blacklist-temp-progress" class="mb-4 p-4 bg-white dark:bg-gray-800 rounded-lg border border-blue-200 dark:border-blue-900 shadow-sm">
                <div class="flex justify-between items-center mb-2">
                    <span class="text-sm font-medium text-blue-700 dark:text-blue-400 flex items-center gap-2">
                        <svg class="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        Running Scan...
                    </span>
                    <span id="blacklist-progress-text" class="text-xs text-gray-500 dark:text-gray-400">Initializing...</span>
                </div>
                <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div id="blacklist-progress-bar" class="bg-blue-600 h-2 rounded-full transition-all duration-300" style="width: 0%"></div>
                </div>
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
        container.innerHTML = `<p class="text-red-500 text-center py-8">Failed to load: ${escapeHtml(error.message)}</p>`;
    }
}


async function loadDashboardBlacklistSummary() {
    const container = document.getElementById('dashboard-blacklist-summary');
    if (!container) return;

    try {
        const response = await authenticatedFetch('/api/blacklist/summary');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        console.log('Status summary data:', data);

        if (!data.has_data) {
            container.innerHTML = `
                <div class="text-center py-4">
                    <p class="text-sm text-gray-500 dark:text-gray-400">No blacklist data yet</p>
                    <p class="text-xs text-gray-400 dark:text-gray-500 mt-1">The first check runs automatically</p>
                </div>`;
            return;
        }

        const statusBadge = {
            listed: '<span class="text-red-600 dark:text-red-400 font-semibold">&#10007; Listed</span>',
            error: '<span class="text-yellow-600 dark:text-yellow-400 font-semibold">! Check Error</span>',
            clean: '<span class="text-green-600 dark:text-green-400 font-semibold">&#10003; Clean</span>',
            unknown: '<span class="text-gray-500 dark:text-gray-400 font-semibold">Unknown</span>'
        }[data.status] || `<span class="text-gray-500 dark:text-gray-400">${escapeHtml(String(data.status))}</span>`;

        const rows = [`
            <div class="flex justify-between items-center">
                <span class="text-sm text-gray-600 dark:text-gray-300">Status</span>
                ${statusBadge}
            </div>`];

        if ((data.hosts_total || 0) > 1) {
            rows.push(`
                <div class="flex justify-between items-center">
                    <span class="text-sm text-gray-600 dark:text-gray-300">Hosts Listed</span>
                    <span class="text-sm font-medium text-gray-900 dark:text-white">${data.hosts_listed}/${data.hosts_total}</span>
                </div>`);
        } else {
            const ip = (data.hosts && data.hosts[0] && data.hosts[0].hostname) || data.server_ip;
            if (ip) {
                rows.push(`
                    <div class="flex justify-between items-center">
                        <span class="text-sm text-gray-600 dark:text-gray-300">IP</span>
                        <span class="text-sm font-mono text-gray-900 dark:text-white">${escapeHtml(ip)}</span>
                    </div>`);
            }
        }
        rows.push(`
            <div class="flex justify-between items-center">
                <span class="text-sm text-gray-600 dark:text-gray-300">Listed On</span>
                <span class="text-sm font-medium text-gray-900 dark:text-white">${data.listed_count}/${data.total_blacklists}</span>
            </div>`);
        if (data.checked_at) {
            rows.push(`
                <div class="flex justify-between items-center">
                    <span class="text-sm text-gray-600 dark:text-gray-300">Last Check</span>
                    <span class="text-xs text-gray-500 dark:text-gray-400">${escapeHtml(new Date(data.checked_at).toLocaleString())}</span>
                </div>`);
        }

        container.innerHTML = `<div class="space-y-3">${rows.join('')}</div>`;
    } catch (error) {
        console.error('Failed to load blacklist summary:', error);
        container.innerHTML = `<p class="text-gray-500 dark:text-gray-400 text-center text-sm">Error loading</p>`;
    }
}


function renderBlacklistStatus(data) {
    const container = document.getElementById('status-blacklist');
    if (!container) return;

    if (!data.hosts || data.hosts.length === 0) {
        container.innerHTML = `
            <div class="text-center py-8">
                <svg class="w-12 h-12 mx-auto text-gray-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                </svg>
                <h3 class="text-lg font-medium text-gray-900 dark:text-white">No Monitored Hosts</h3>
                <p class="text-gray-500 dark:text-gray-400 mt-2">Syncing monitoring targets...</p>
            </div>
        `;
        return;
    }

    // Preserve open states
    const openStates = {};
    container.querySelectorAll('details').forEach(el => {
        if (el.open && el.id) openStates[el.id] = true;
    });

    let html = '<div class="space-y-4">';

    data.hosts.forEach((host, index) => {
        const hostId = `host-${index}`;
        const isOpen = openStates[hostId] || false;

        let statusColor = 'gray';
        let statusText = 'Unknown';
        let statusIcon = '?';

        if (host.status === 'clean') {
            statusColor = 'green';
            statusText = 'Clean';
            statusIcon = '✓';
        } else if (host.status === 'listed') {
            statusColor = 'red';
            statusText = 'Listed';
            statusIcon = '✗';
        } else if (host.status === 'error') {
            statusColor = 'yellow';
            statusText = 'Error';
            statusIcon = '!';
        }

        const listedCount = host.listed_count || 0;
        const totalCount = host.total_blacklists || 0;
        const lastCheck = host.checked_at ? formatTime(host.checked_at) : 'Never';
        const hostname = escapeHtml(host.hostname);
        const source = escapeHtml(host.source || 'system');

        // Host card
        html += `
            <details id="${hostId}" class="group bg-gray-50 dark:bg-gray-700/50 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden" ${isOpen ? 'open' : ''}>
                <summary class="list-none px-4 py-3 cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 transition flex items-center justify-between select-none">
                    <div class="flex items-center gap-3">
                        <div class="p-2 rounded-full bg-${statusColor}-100 dark:bg-${statusColor}-900/30 text-${statusColor}-600 dark:text-${statusColor}-400">
                             <span class="font-bold text-lg w-5 h-5 flex items-center justify-center">${statusIcon}</span>
                        </div>
                        <div>
                            <h3 class="font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                                ${hostname}
                                <span class="text-xs px-2 py-0.5 rounded-full bg-gray-200 dark:bg-gray-600 text-gray-600 dark:text-gray-300">${source}</span>
                            </h3>
                            <p class="text-xs text-gray-500 dark:text-gray-400">
                                ${statusText} • Listed on ${listedCount}/${totalCount} • Last check: ${lastCheck}
                            </p>
                        </div>
                    </div>
                    <svg class="w-5 h-5 text-gray-400 transition-transform duration-200 group-open:rotate-180" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                    </svg>
                </summary>
                
                <div class="px-4 pb-4 pt-1 border-t border-gray-200 dark:border-gray-700">
        `;

        if (host.has_data && host.results) {
            html += '<div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-2 mb-4 max-h-96 overflow-y-auto custom-scrollbar p-1">';
            host.results.forEach(result => {
                let color = 'gray';
                let icon = '?';

                if (result.status === 'clean') {
                    color = 'green';
                    icon = '✓';
                } else if (result.listed) {
                    color = 'red';
                    icon = '✗';
                } else if (result.status === 'error') {
                    color = 'yellow';
                    icon = '!';
                } else if (result.status === 'timeout') {
                    color = 'orange';
                    icon = '⏱';
                }

                // The raw DNS answer distinguishes a real listing (127.0.0.x)
                // from resolver interference - surface it on hover
                const detail = result.response
                    ? `${result.name}: ${result.response}`
                    : result.name;
                html += `
                    <div class="px-2 py-1.5 rounded bg-${color}-50 dark:bg-${color}-900/10 border border-${color}-100 dark:border-${color}-900/30 text-xs flex items-center justify-between group/item relative hover:bg-${color}-100 dark:hover:bg-${color}-900/20 transition cursor-default">
                        <span class="font-medium text-${color}-700 dark:text-${color}-300 truncate mr-1" title="${escapeHtml(detail)}">${escapeHtml(result.name)}</span>
                        <div class="flex items-center">
                            <span class="text-${color}-600 dark:text-${color}-400 font-bold" title="${escapeHtml(detail)}">${icon}</span>
                            ${result.info_url ? `<a href="${result.info_url}" target="_blank" class="ml-1 text-${color}-400 hover:text-${color}-600" title="View info"><svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg></a>` : ''}
                        </div>
                    </div>
                `;
            });
            html += '</div>';
        }

        html += `
                    <div class="mt-2 text-center">
                         <button onclick="checkHost('${hostname}')" class="text-sm text-blue-600 dark:text-blue-400 hover:underline">Run Check for this Host</button>
                    </div>
                </div>
            </details>
        `;
    });

    html += '</div>';
    container.innerHTML = html;
}

function renderStatusImport(imports) {
    const container = document.getElementById('status-import');
    container.innerHTML = `
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            ${renderImportCard('Postfix Logs', imports.postfix, 'blue')}
            ${renderImportCard('Rspamd Logs', imports.rspamd, 'purple')}
            ${renderImportCard('Netfilter Logs', imports.netfilter, 'red')}
        </div>
    `;
}

function renderStatusCorrelation(correlation, incompleteList) {
    const container = document.getElementById('status-correlation');
    container.innerHTML = `
        <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-4">
            <div class="p-4 bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900/20 dark:to-blue-800/20 rounded-lg text-center">
                <p class="text-2xl font-bold text-blue-600 dark:text-blue-400">${correlation.total || 0}</p>
                <p class="text-xs text-gray-600 dark:text-gray-400 mt-1">Total</p>
            </div>
            <div class="p-4 bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900/20 dark:to-green-800/20 rounded-lg text-center">
                <p class="text-2xl font-bold text-green-600 dark:text-green-400">${correlation.complete || 0}</p>
                <p class="text-xs text-gray-600 dark:text-gray-400 mt-1">Complete</p>
            </div>
            <div class="p-4 bg-gradient-to-br from-yellow-50 to-yellow-100 dark:from-yellow-900/20 dark:to-yellow-800/20 rounded-lg text-center">
                <p class="text-2xl font-bold text-yellow-600 dark:text-yellow-400">${correlation.incomplete || 0}</p>
                <p class="text-xs text-gray-600 dark:text-gray-400 mt-1">Incomplete</p>
            </div>
            <div class="p-4 bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-700/20 dark:to-gray-600/20 rounded-lg text-center">
                <p class="text-2xl font-bold text-gray-500 dark:text-gray-400">${correlation.expired || 0}</p>
                <p class="text-xs text-gray-600 dark:text-gray-400 mt-1">Expired</p>
            </div>
            <div class="p-4 bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900/20 dark:to-purple-800/20 rounded-lg text-center">
                <p class="text-2xl font-bold text-purple-600 dark:text-purple-400">${correlation.completion_rate || 0}%</p>
                <p class="text-xs text-gray-600 dark:text-gray-400 mt-1">Success Rate</p>
            </div>
        </div>
        ${correlation.last_update ? `
            <p class="text-sm text-gray-600 dark:text-gray-400 text-center">
                Last updated: ${formatTime(correlation.last_update)}
            </p>
        ` : ''}
        
        ${incompleteList.length > 0 ? `
            <div class="mt-4 p-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
                <h4 class="text-sm font-semibold text-yellow-800 dark:text-yellow-300 mb-2">Recent Incomplete Correlations</h4>
                <div class="space-y-2">
                    ${incompleteList.map(item => `
                        <div class="p-2 bg-white dark:bg-gray-800 rounded text-xs">
                            <div class="flex justify-between items-start mb-1">
                                <span class="font-mono text-gray-600 dark:text-gray-400">${copyableText(item.message_id || 'N/A')}</span>
                                <span class="text-yellow-600 dark:text-yellow-400">${item.age_minutes}m ago</span>
                            </div>
                            <div class="text-gray-500 dark:text-gray-400">
                                ${copyableText(item.sender || 'N/A')} => ${copyableText(item.recipient || 'N/A')}
                            </div>
                        </div>
                    `).join('')}
                </div>
                <p class="text-xs text-yellow-700 dark:text-yellow-400 mt-2">
                    These will be automatically completed or expired within 1-2 minutes
                </p>
            </div>
        ` : ''}
    `;
}

function renderStatusJobs(jobs) {
    const container = document.getElementById('status-jobs');
    
    const categories = [
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
                ['Expire Correlations', 'expire_correlations', jobs.expire_correlations]
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
            title: 'DMARC & Reports',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>',
            jobs: [
                ['DMARC IMAP Import', 'dmarc_imap_sync', jobs.dmarc_imap_sync],
                ['Cleanup DMARC Reports', 'cleanup_dmarc_reports', jobs.cleanup_dmarc_reports],
                ['Weekly Summary Report', 'send_weekly_summary', jobs.send_weekly_summary]
            ]
        },
        {
            title: 'Security & Monitoring',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>',
            jobs: [
                ['DNS Check (All Domains)', 'dns_check', jobs.dns_check],
                ['IP Blacklist Check (All Hosts)', 'blacklist_check', jobs.blacklist_check]
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
    
    let html = '';
    for (const cat of categories) {
        // Skip categories where no jobs exist
        const validJobs = cat.jobs.filter(j => j[2]);
        if (validJobs.length === 0) continue;
        
        html += `
            <div class="mb-6">
                <div class="flex items-center gap-2 mb-3">
                    <svg class="w-4 h-4 text-gray-400 dark:text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">${cat.icon}</svg>
                    <h4 class="text-sm font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">${cat.title}</h4>
                </div>
                <div class="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-3">
                    ${cat.jobs.map(j => renderJobCard(j[0], j[1], j[2])).join('')}
                </div>
            </div>`;
    }
    container.innerHTML = html;
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

async function viewPostfixDetails(queueId) {
    if (!queueId) {
        console.error('No queue ID provided');
        return;
    }

    console.log('Loading Postfix details for queue ID:', queueId);

    const modal = document.getElementById('message-modal');
    const content = document.getElementById('message-modal-content');

    if (!modal || !content) {
        console.error('Modal elements not found');
        return;
    }

    // Block body scroll
    document.body.style.overflow = 'hidden';

    modal.classList.remove('hidden');
    content.innerHTML = '<div class="text-center py-8"><div class="loading mx-auto mb-4"></div><p class="text-gray-500 dark:text-gray-400">Loading...</p></div>';

    try {
        const response = await authenticatedFetch(`/api/logs/postfix/by-queue/${queueId}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('Postfix details loaded:', data);

        if (data.logs && data.logs.length > 0) {
            // Sort logs by time
            const sortedLogs = data.logs.sort((a, b) => new Date(a.time) - new Date(b.time));

            // Extract key information
            let sender = null, recipient = null;
            sortedLogs.forEach(log => {
                if (log.sender && !sender) sender = log.sender;
                if (log.recipient && !recipient) recipient = log.recipient;
            });

            // CRITICAL: Store FULL data in currentModalData
            currentModalData = {
                queue_id: queueId,
                sender: sender || 'Unknown',
                recipient: recipient || 'Unknown',
                subject: 'Postfix Log Details',
                direction: null,
                final_status: null,
                first_seen: sortedLogs[0].time,
                postfix: sortedLogs,
                rspamd: data.rspamd || null,
                netfilter: []
            };

            currentModalTab = 'overview';  // Start with Overview

            // Update Security tab indicator
            updateSecurityTabIndicator(currentModalData);

            // Reset modal tabs
            document.querySelectorAll('[id^="modal-tab-"]').forEach(btn => {
                btn.classList.remove('active');
            });
            const overviewTab = document.getElementById('modal-tab-overview');
            if (overviewTab) {
                overviewTab.classList.add('active');
            }

            console.log('currentModalData set:', currentModalData);

            // Render the Overview tab
            renderModalTab('overview', currentModalData);

        } else {
            content.innerHTML = '<p class="text-gray-500 dark:text-gray-400 text-center py-8">No logs found for this Queue ID</p>';
        }
    } catch (error) {
        console.error('Failed to load Postfix details:', error);
        content.innerHTML = `<p class="text-red-500 text-center py-8">Failed to load Postfix details: ${escapeHtml(error.message)}</p>`;
    }
}

// =============================================================================
// Part 3: Message Modal with Tabs, Helper Functions, Export, Dark Mode
// =============================================================================

// =============================================================================
// MESSAGE MODAL WITH TABS
// =============================================================================

function switchModalTab(tab) {
    console.log('Switching modal tab to:', tab);
    currentModalTab = tab;

    // Update tab buttons
    document.querySelectorAll('[id^="modal-tab-"]').forEach(btn => {
        btn.classList.remove('active');
    });
    const activeTab = document.getElementById(`modal-tab-${tab}`);
    if (activeTab) {
        activeTab.classList.add('active');
    } else {
        console.error('Modal tab button not found:', `modal-tab-${tab}`);
    }

    // Render content
    if (currentModalData) {
        renderModalTab(tab, currentModalData);
    } else {
        console.error('No modal data available');
    }
}

async function viewMessageDetails(correlationKey) {
    if (!correlationKey) {
        console.error('No correlation key provided');
        return;
    }

    console.log('Loading message details for:', correlationKey);

    const modal = document.getElementById('message-modal');
    const content = document.getElementById('message-modal-content');

    if (!modal || !content) {
        console.error('Modal elements not found');
        return;
    }

    // Block body scroll
    document.body.style.overflow = 'hidden';

    modal.classList.remove('hidden');
    content.innerHTML = '<div class="text-center py-8"><div class="loading mx-auto mb-4"></div><p class="text-gray-500 dark:text-gray-400">Loading...</p></div>';

    try {
        const response = await authenticatedFetch(`/api/message/${correlationKey}/details`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('Message details loaded:', data);

        currentModalData = data;
        currentModalTab = 'overview';

        // Update Security tab indicator
        updateSecurityTabIndicator(data);

        // Hide Security tab if netfilter feature is disabled
        const netfilterTab = document.getElementById('modal-tab-netfilter');
        if (netfilterTab) {
            netfilterTab.style.display = window.disabledFeatures.includes('netfilter') ? 'none' : '';
        }

        document.querySelectorAll('[id^="modal-tab-"]').forEach(btn => {
            btn.classList.remove('active');
        });
        const overviewTab = document.getElementById('modal-tab-overview');
        if (overviewTab) {
            overviewTab.classList.add('active');
        }

        renderModalTab('overview', data);
    } catch (error) {
        console.error('Failed to load message details:', error);
        content.innerHTML = `<p class="text-red-500 text-center py-8">Failed to load message details: ${escapeHtml(error.message)}</p>`;
    }
}

function renderModalTab(tab, data) {
    const content = document.getElementById('message-modal-content');

    switch (tab) {
        case 'overview':
            renderOverviewTab(content, data);
            break;
        case 'postfix':
            renderPostfixTab(content, data);
            break;
        case 'spam':
            renderSpamTab(content, data);
            break;
        case 'netfilter':
            renderNetfilterTab(content, data);
            break;
    }
}

function renderOverviewTab(content, data) {
    // Collect recipients from Postfix logs if available (these have full addresses including +)
    let recipientsFromPostfix = new Set();
    if (data.postfix && data.postfix.length > 0) {
        data.postfix.forEach(log => {
            if (log.recipient) {
                recipientsFromPostfix.add(log.recipient);
            }
        });
    }

    // Use Postfix recipients if available, otherwise fall back to correlation recipients
    const recipientsToDisplay = recipientsFromPostfix.size > 0
        ? Array.from(recipientsFromPostfix)
        : (data.recipients || []);

    // Build recipients section for right column
    let recipientsRightColumn = '';
    if (recipientsToDisplay.length > 0) {
        if (recipientsToDisplay.length > 1) {
            recipientsRightColumn = `
                <div>
                    <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Recipients (${recipientsToDisplay.length})</p>
                    <div class="mt-2 space-y-1 max-h-32 overflow-y-auto">
                        ${recipientsToDisplay.map(r => `
                            <div class="flex items-center gap-2">
                                <svg class="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                                </svg>
                                <span class="text-sm text-gray-900 dark:text-white">${copyableText(r)}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        } else {
            recipientsRightColumn = `
                <div>
                    <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">To</p>
                    <p class="text-sm font-semibold text-gray-900 dark:text-white mt-1">${copyableText(recipientsToDisplay[0] || '-')}</p>
                </div>
            `;
        }
    } else if (data.recipient) {
        recipientsRightColumn = `
            <div>
                <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">To</p>
                <p class="text-sm font-semibold text-gray-900 dark:text-white mt-1">${copyableText(data.recipient)}</p>
            </div>
        `;
    }

    content.innerHTML = `
        <div class="flex flex-col h-full">
            <div class="flex-1 overflow-y-auto min-h-0">
                <div class="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-gray-800 dark:to-gray-700 p-4 rounded-lg">
                    <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-3">Message Overview</h3>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <!-- Left Column -->
                        <div class="space-y-3">
                            <div>
                                <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">From</p>
                                <p class="text-sm font-semibold text-gray-900 dark:text-white mt-1">${copyableText(data.sender || '-')}</p>
                            </div>
                            ${data.subject && data.subject !== 'Postfix Log Details' ? `
                                <div class="min-w-0">
                                    <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Subject</p>
                                    <p class="text-sm text-gray-900 dark:text-white mt-1 truncate" title="${escapeHtml(data.subject)}">${escapeHtml(data.subject)}</p>
                                </div>
                            ` : ''}
                            ${data.final_status || data.direction ? `
                                <div>
                                    <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-1">Status & Direction</p>
                                    <div class="flex items-center gap-2 flex-wrap">
                                        ${data.final_status ? `<span class="inline-block px-3 py-1 text-xs font-medium rounded ${getStatusClass(data.final_status)}">${data.final_status}</span>` : ''}
                                        ${data.direction ? `<span class="inline-block px-3 py-1 text-xs font-medium rounded ${getDirectionClass(data.direction)}">${data.direction}</span>` : ''}
                                    </div>
                                </div>
                            ` : ''}
                        </div>
                        <!-- Right Column -->
                        <div class="space-y-3">
                            ${recipientsRightColumn}
                            ${data.queue_id ? `
                                <div>
                                    <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Queue ID</p>
                                    <p class="text-xs font-mono text-gray-600 dark:text-gray-400 mt-1">${copyableText(data.queue_id)}</p>
                                </div>
                            ` : ''}
                            ${data.message_id ? `
                                <div>
                                    <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Message ID</p>
                                    <p class="text-xs font-mono text-gray-600 dark:text-gray-400 mt-1 break-all">${copyableText(data.message_id)}</p>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                </div>
                ${data.rspamd ? `
                    <div class="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-3 sm:p-4 mt-1">
                        <h4 class="text-sm sm:text-md font-semibold text-gray-900 dark:text-white mb-3">Quick Spam Summary</h4>
                        <div class="grid grid-cols-3 gap-2">
                            <div class="text-center">
                                <p class="text-lg sm:text-2xl font-bold ${data.rspamd.score >= (data.rspamd.required_score || 15) ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'}">
                                    ${data.rspamd.score.toFixed(2)}
                                </p>
                                <p class="text-[10px] sm:text-xs text-gray-500 dark:text-gray-400 mt-1">Score</p>
                            </div>
                            <div class="text-center">
                                <p class="text-sm sm:text-lg font-semibold text-gray-900 dark:text-white truncate">
                                    ${data.rspamd.action}
                                </p>
                                <p class="text-[10px] sm:text-xs text-gray-500 dark:text-gray-400 mt-1">Action</p>
                            </div>
                            <div class="text-center">
                                <p class="text-sm sm:text-lg font-semibold ${data.rspamd.is_spam ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'}">
                                    ${data.rspamd.is_spam ? 'SPAM' : 'CLEAN'}
                                </p>
                                <p class="text-[10px] sm:text-xs text-gray-500 dark:text-gray-400 mt-1">Class</p>
                            </div>
                        </div>
                        <p class="text-[10px] sm:text-xs text-gray-500 dark:text-gray-400 text-center mt-3">
                            See "Spam Analysis" tab for details
                        </p>
                    </div>
                ` : data.postfix && data.postfix.length > 0 ? `
                    <div class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mt-3">
                    <div class="flex items-start gap-3">
                        <svg class="w-5 h-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>
                        </svg>
                        <div>
                            <p class="text-sm font-medium text-blue-900 dark:text-blue-300">Postfix Delivery Logs</p>
                            <p class="text-xs text-blue-800 dark:text-blue-400 mt-1">Click "Logs" tab to see complete delivery timeline (${data.postfix.length} entries)</p>
                        </div>
                    </div>
                    </div>
                ` : ''}
            </div>
            ${data.rspamd ? `
                <div class="flex-shrink-0 mt-auto pt-3 border-t border-gray-200 dark:border-gray-700">
                    <div class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
                        <div class="flex items-start gap-3">
                            <svg class="w-5 h-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>
                            </svg>
                            <div class="flex-1">
                                <p class="text-sm font-medium text-blue-900 dark:text-blue-300 mb-2">Additional Details</p>
                                <div class="space-y-1 text-xs text-blue-800 dark:text-blue-400">
                                    ${data.rspamd.ip ? renderGeoIPInfo(data.rspamd, '16x12') : ''}
                                    ${data.rspamd.user ? `<p>Authenticated User: ${copyableText(data.rspamd.user)}</p>` : ''}
                                    ${data.rspamd.size ? `<p>Message Size: ${formatSize(data.rspamd.size)}</p>` : ''}
                                    ${data.rspamd.has_auth ? `<p>Authentication: Verified (MAILCOW_AUTH)</p>` : ''}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            ` : ''}
        </div>
    `;
}

function renderPostfixTab(content, data) {
    if (!data.postfix || data.postfix.length === 0) {
        content.innerHTML = `
            <div class="text-center py-12">
                <svg class="w-16 h-16 mx-auto text-gray-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"></path>
                </svg>
                <p class="text-gray-500 dark:text-gray-400">No Postfix delivery logs available</p>
            </div>
        `;
        return;
    }

    // Extract key information from logs
    let sender = null, clientIp = null, relay = null;
    let messageId = null, finalStatus = null, totalDelay = null, queueId = null;
    let errorReasons = [];
    let recipientsFromPostfix = new Set(); // Collect all unique recipients from Postfix logs

    data.postfix.forEach(log => {
        if (log.queue_id && !queueId) queueId = log.queue_id;
        if (log.sender && !sender) sender = log.sender;
        if (log.relay && !relay) relay = log.relay;
        if (log.message_id && !messageId) messageId = log.message_id;
        if (log.status) finalStatus = log.status;
        if (log.delay) totalDelay = log.delay;
        // Collect recipients from Postfix logs (these have the full address including +)
        if (log.recipient) {
            recipientsFromPostfix.add(log.recipient);
        }

        if (!clientIp && log.message) {
            const ipMatch = log.message.match(/client=.*?\[(\d+\.\d+\.\d+\.\d+)\]/);
            if (ipMatch) clientIp = ipMatch[1];
        }

        // Extract error reasons for non-sent statuses
        if (log.status && log.status !== 'sent' && log.message) {
            // Look for "said:" pattern (remote server response)
            const saidMatch = log.message.match(/said:\s*(.+?)(?:\s*\(in reply|$)/i);
            if (saidMatch) {
                errorReasons.push({
                    recipient: log.recipient,
                    status: log.status,
                    reason: saidMatch[1].trim()
                });
            } else if (log.status === 'deferred' || log.status === 'bounced') {
                // Look for parenthetical reason
                const parenMatch = log.message.match(/status=\w+\s*\((.+?)\)$/);
                if (parenMatch) {
                    errorReasons.push({
                        recipient: log.recipient,
                        status: log.status,
                        reason: parenMatch[1].trim()
                    });
                }
            }
        }
    });

    // Generate unique ID for accordion
    const accordionId = 'postfix-accordion-' + Date.now();

    // Separate system logs from recipient logs
    const postfixByRecipient = data.postfix_by_recipient || {};
    const systemLogs = postfixByRecipient['_system'] || [];
    const recipientEntries = Object.entries(postfixByRecipient).filter(([key]) => key !== '_system');

    // Build error summary section
    const errorSummaryHtml = errorReasons.length > 0 ? `
        <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
            <div class="flex items-start gap-3">
                <svg class="w-6 h-6 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <div class="flex-1">
                    <h4 class="text-md font-semibold text-red-800 dark:text-red-300 mb-2">Delivery Error</h4>
                    ${errorReasons.map(err => `
                        <div class="mb-2 last:mb-0">
                            ${err.recipient ? `<p class="text-sm font-medium text-red-700 dark:text-red-400">${escapeHtml(err.recipient)}</p>` : ''}
                            <p class="text-sm text-red-600 dark:text-red-300 mt-1">${escapeHtml(err.reason)}</p>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    ` : '';

    content.innerHTML = `
        <div class="space-y-6">
            ${errorSummaryHtml}
            <!-- Mail Details Header -->
            <div class="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-gray-800 dark:to-gray-700 p-4 rounded-lg">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-3">Mail Details</h3>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    ${sender ? `
                        <div>
                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">From</p>
                            <p class="text-sm font-semibold text-gray-900 dark:text-white mt-1">${copyableText(sender)}</p>
                        </div>
                    ` : ''}
                    ${recipientsFromPostfix.size > 0 ? `
                        <div>
                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">To (${recipientsFromPostfix.size})</p>
                            <p class="text-sm font-semibold text-gray-900 dark:text-white mt-1">${recipientsFromPostfix.size === 1 ? copyableText(Array.from(recipientsFromPostfix)[0]) : `${recipientsFromPostfix.size} recipients`}</p>
                        </div>
                    ` : (data.recipients && data.recipients.length > 0 ? `
                        <div>
                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">To (${data.recipients.length})</p>
                            <p class="text-sm font-semibold text-gray-900 dark:text-white mt-1">${data.recipients.length === 1 ? copyableText(data.recipients[0]) : `${data.recipients.length} recipients`}</p>
                        </div>
                    ` : '')}
                    ${clientIp ? `
                        <div>
                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Client IP</p>
                            <p class="text-sm font-mono font-semibold text-gray-900 dark:text-white mt-1">${copyableText(clientIp)}</p>
                        </div>
                    ` : ''}
                    ${queueId ? `
                        <div>
                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Queue ID</p>
                            <p class="text-sm font-mono font-semibold text-gray-900 dark:text-white mt-1">${copyableText(queueId)}</p>
                        </div>
                    ` : ''}
                    ${finalStatus ? `
                        <div>
                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Final Status</p>
                            <span class="inline-block px-3 py-1 text-sm font-medium rounded ${getStatusClass(finalStatus)} mt-1">${finalStatus}</span>
                        </div>
                    ` : ''}
                    ${relay ? `
                        <div>
                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Relay</p>
                            <p class="text-sm font-mono font-semibold text-gray-900 dark:text-white mt-1 truncate" title="${escapeHtml(relay)}">${escapeHtml(relay)}</p>
                        </div>
                    ` : ''}
                    ${messageId ? `
                        <div class="md:col-span-2">
                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Message ID</p>
                            <p class="text-xs font-mono text-gray-700 dark:text-gray-300 mt-1 break-all">${copyableText(messageId)}</p>
                        </div>
                    ` : ''}
                </div>
            </div>
            
            <!-- Delivery Summary by Recipient (if multiple recipients) -->
            ${recipientEntries.length > 1 ? `
                <div class="border-t border-gray-200 dark:border-gray-700 pt-4">
                    <h4 class="text-md font-semibold text-gray-900 dark:text-white mb-3">Delivery Summary by Recipient</h4>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                        ${recipientEntries.map(([recipient, logs]) => {
        const statusLog = logs.find(l => l.status) || logs[0];
        return `
                                <div class="p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg border border-gray-200 dark:border-gray-600">
                                    <div class="flex items-center justify-between">
                                        <span class="text-sm text-gray-900 dark:text-white truncate flex-1">${copyableText(recipient)}</span>
                                        ${statusLog.status ? `<span class="ml-2 inline-block px-2 py-0.5 text-xs font-medium rounded ${getStatusClass(statusLog.status)}">${statusLog.status}</span>` : ''}
                                    </div>
                                    ${statusLog.relay ? `<p class="text-xs text-gray-500 dark:text-gray-400 mt-1 truncate">via ${escapeHtml(statusLog.relay)}</p>` : ''}
                                </div>
                            `;
    }).join('')}
                    </div>
                </div>
            ` : ''}
            
            <!-- Complete Log Timeline - ALWAYS show all logs -->
            <div>
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-md font-semibold text-gray-900 dark:text-white">Complete Log Timeline</h4>
                    <span class="text-xs text-gray-500 dark:text-gray-400">${data.postfix.length} entries</span>
                </div>
                <div class="space-y-2 max-h-96 overflow-y-auto">
                    ${data.postfix.map(log => `
                        <div class="p-3 bg-gray-50 dark:bg-gray-700/50 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                            <div class="flex justify-between items-start mb-1">
                                <div class="flex items-center gap-2 flex-wrap">
                                    <span class="text-xs font-mono text-gray-600 dark:text-gray-300">${formatTime(log.time)}</span>
                                    ${log.program ? `<span class="text-xs px-2 py-0.5 rounded bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300">${log.program}</span>` : ''}
                                    ${log.recipient ? `<span class="text-xs text-gray-500 dark:text-gray-400">=> ${escapeHtml(log.recipient)}</span>` : ''}
                                </div>
                                ${log.status ? `<span class="inline-block px-2 py-0.5 text-xs font-medium rounded ${getStatusClass(log.status)}">${log.status}</span>` : ''}
                            </div>
                            <p class="text-xs text-gray-700 dark:text-gray-300 font-mono break-all leading-relaxed">${escapeHtml(log.message)}</p>
                            ${log.relay ? `<p class="text-xs text-gray-500 dark:text-gray-400 mt-1">Relay: ${escapeHtml(log.relay)}</p>` : ''}
                            ${log.delay ? `<p class="text-xs text-gray-500 dark:text-gray-400">Delay: ${log.delay.toFixed(2)}s</p>` : ''}
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

// Accordion toggle function
function toggleAccordion(id) {
    const content = document.getElementById(id);
    const icon = document.getElementById(id + '-icon');

    if (content.classList.contains('hidden')) {
        content.classList.remove('hidden');
        icon.style.transform = 'rotate(180deg)';
    } else {
        content.classList.add('hidden');
        icon.style.transform = 'rotate(0deg)';
    }
}

function renderSpamTab(content, data) {
    if (!data.rspamd) {
        content.innerHTML = `
            <div class="text-center py-12">
                <svg class="w-16 h-16 mx-auto text-gray-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                </svg>
                <p class="text-gray-500 dark:text-gray-400">No spam analysis data available</p>
            </div>
        `;
        return;
    }

    content.innerHTML = `
        <div class="space-y-6">
            <div class="grid grid-cols-3 gap-2 sm:gap-4">
                <div class="bg-gray-50 dark:bg-gray-700/50 p-2 sm:p-4 rounded-lg text-center">
                    <p class="text-[10px] sm:text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-1 sm:mb-2 truncate">Score</p>
                    <p class="text-lg sm:text-3xl font-bold ${data.rspamd.score >= (data.rspamd.required_score || 15) ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'}">
                        ${data.rspamd.score.toFixed(2)}
                    </p>
                    <p class="text-[9px] sm:text-xs text-gray-500 dark:text-gray-400 mt-1">Limit: ${data.rspamd.required_score || 15}</p>
                </div>
                <div class="bg-gray-50 dark:bg-gray-700/50 p-2 sm:p-4 rounded-lg text-center">
                    <p class="text-[10px] sm:text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-1 sm:mb-2 truncate">Action</p>
                    <p class="text-sm sm:text-xl font-semibold text-gray-900 dark:text-white truncate">
                        ${data.rspamd.action}
                    </p>
                </div>
                <div class="bg-gray-50 dark:bg-gray-700/50 p-2 sm:p-4 rounded-lg text-center">
                    <p class="text-[10px] sm:text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-1 sm:mb-2 truncate">Class</p>
                    <p class="text-sm sm:text-xl font-semibold ${data.rspamd.is_spam ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'}">
                        ${data.rspamd.is_spam ? 'SPAM' : 'CLEAN'}
                    </p>
                </div>
            </div>
            
            ${data.rspamd.symbols && Object.keys(data.rspamd.symbols).length > 0 ? `
                <div>
                    <h4 class="text-md font-semibold text-gray-900 dark:text-white mb-3">Detection Symbols</h4>
                    <div class="space-y-2 max-h-[29rem] overflow-y-auto">
                        ${Object.entries(data.rspamd.symbols)
                .sort((a, b) => {
                    const scoreA = a[1].score || a[1].metric_score || 0;
                    const scoreB = b[1].score || b[1].metric_score || 0;
                    if (scoreA === 0 && scoreB !== 0) return 1;
                    if (scoreA !== 0 && scoreB === 0) return -1;
                    return Math.abs(scoreB) - Math.abs(scoreA);
                })
                .map(([name, details]) => {
                    const score = details.score || details.metric_score || 0;
                    const description = details.description || '';
                    const options = details.options || [];
                    const scoreClass = score > 0 ? 'text-red-600 dark:text-red-400' :
                        score < 0 ? 'text-green-600 dark:text-green-400' :
                            'text-gray-500 dark:text-gray-400';
                    return `
                                    <div class="flex items-start justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                                        <div class="flex-1">
                                            <span class="text-sm font-semibold text-gray-900 dark:text-white">${name}</span>
                                            ${description ? `<p class="text-xs text-gray-600 dark:text-gray-400 mt-1">${escapeHtml(description)}</p>` : ''}
                                            ${options.length > 0 ? `<p class="text-xs font-mono text-blue-600 dark:text-blue-400 mt-1">${options.map(o => escapeHtml(o)).join(', ')}</p>` : ''}
                                        </div>
                                        <span class="ml-3 text-sm font-mono font-bold ${scoreClass}">${score > 0 ? '+' : ''}${score.toFixed(2)}</span>
                                    </div>
                                `;
                }).join('')}
                    </div>
                </div>
            ` : ''}
        </div>
    `;
}

function renderNetfilterTab(content, data) {
    if (!data.netfilter || data.netfilter.length === 0) {
        content.innerHTML = `
            <div class="text-center py-12">
                <svg class="w-16 h-16 mx-auto text-gray-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                </svg>
                <p class="text-gray-500 dark:text-gray-400">No security events detected</p>
                <p class="text-xs text-gray-400 dark:text-gray-500 mt-2">This is good - no failed authentication attempts from this sender</p>
            </div>
        `;
        return;
    }

    content.innerHTML = `
        <div class="space-y-4">
            <div class="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
                <div class="flex items-start gap-3">
                    <svg class="w-5 h-5 text-yellow-600 dark:text-yellow-400 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
                    </svg>
                    <div>
                        <p class="text-sm font-medium text-yellow-900 dark:text-yellow-300">Security Events Detected</p>
                        <p class="text-xs text-yellow-800 dark:text-yellow-400 mt-1">${data.netfilter.length} authentication event(s) from the sender's IP within 1 hour of this message</p>
                    </div>
                </div>
            </div>
            
            <h3 class="text-lg font-semibold text-gray-900 dark:text-white">Related Security Events</h3>
            <div class="space-y-2">
                ${data.netfilter.map(log => `
                    <div class="p-3 bg-gray-50 dark:bg-gray-700/50 rounded">
                        <div class="flex justify-between items-start mb-2">
                            <div class="flex items-center gap-2">
                                <span class="text-xs font-mono text-gray-600 dark:text-gray-300">${formatTime(log.time)}</span>
                                <span class="text-xs font-mono font-semibold text-gray-900 dark:text-white">${copyableText(log.ip)}</span>
                            </div>
                            <span class="inline-block px-2 py-0.5 text-xs font-medium rounded ${getActionClass(log.action)}">${getActionLabel(log.action)}</span>
                        </div>
                        ${log.username ? `<p class="text-xs text-gray-700 dark:text-gray-300">User: ${copyableText(log.username)}</p>` : ''}
                        ${log.auth_method ? `<p class="text-xs text-gray-600 dark:text-gray-400">Method: ${log.auth_method}</p>` : ''}
                        ${log.attempts_left !== null ? `<p class="text-xs text-gray-600 dark:text-gray-400">Attempts remaining: ${log.attempts_left}</p>` : ''}
                        <p class="text-xs text-gray-500 dark:text-gray-400 mt-1 font-mono">${escapeHtml(log.message)}</p>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}

function updateSecurityTabIndicator(data) {
    const securityTab = document.getElementById('modal-tab-netfilter');
    if (!securityTab) return;

    const hasSecurityEvents = data.netfilter && data.netfilter.length > 0;
    const indicator = hasSecurityEvents ? '🔴' : '🟢';

    securityTab.innerHTML = `<span class="text-xs sm:text-sm font-medium">Security ${indicator}</span>`;
}

function closeMessageModal() {
    const modal = document.getElementById('message-modal');
    if (modal) {
        modal.classList.add('hidden');
        currentModalData = null;
        // Restore body scroll
        document.body.style.overflow = '';
        // Reset security tab indicator
        const securityTab = document.getElementById('modal-tab-netfilter');
        if (securityTab) {
            securityTab.innerHTML = '<span class="text-sm font-medium">Security</span>';
        }
    }
}

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
// EXPORT CSV
// =============================================================================

async function exportCSV(type) {
    try {
        const filters = currentFilters[type] || {};
        const params = new URLSearchParams(filters);

        const response = await authenticatedFetch(`/api/export/${type}/csv?${params}`);
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${type}_logs_${new Date().getTime()}.csv`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    } catch (error) {
        console.error('Failed to export CSV:', error);
        alert('Failed to export CSV');
    }
}

// =============================================================================
// PAGINATION & HELPER FUNCTIONS
// =============================================================================

function renderPagination(type, currentPage, totalPages) {
    if (totalPages <= 1) return '';

    return `
        <div class="flex flex-col sm:flex-row justify-center items-center gap-2 sm:gap-3 mt-6">
            <button onclick="loadLogs('${type}', ${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''} class="w-full sm:w-auto px-4 py-2 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed transition">
                Previous
            </button>
            <span class="text-sm text-gray-600 dark:text-gray-400">Page ${currentPage} of ${totalPages}</span>
            <button onclick="loadLogs('${type}', ${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''} class="w-full sm:w-auto px-4 py-2 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed transition">
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
        case 'postfix':
            loadPostfixLogs(page);
            break;
        case 'rspamd':
            loadRspamdLogs(page);
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
    const messageModal = document.getElementById('message-modal');
    if (messageModal) {
        messageModal.addEventListener('click', function (e) {
            // Close modal if clicking on the backdrop (not the content)
            if (e.target.id === 'message-modal') {
                closeMessageModal();
            }
        });

        // Prevent clicks inside modal content from closing
        const modalContent = messageModal.querySelector('.bg-white');
        if (modalContent) {
            modalContent.addEventListener('click', function (e) {
                e.stopPropagation();
            });
        }
    }

    // ESC key to close modal
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            const modal = document.getElementById('message-modal');
            if (modal && !modal.classList.contains('hidden')) {
                closeMessageModal();
            }
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
