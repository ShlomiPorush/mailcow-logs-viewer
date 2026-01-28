// =============================================================================
// MAILCOW LOGS VIEWER - COMPLETE FRONTEND
// Part 1: Core, Global State, Dashboard, Postfix, Rspamd, Netfilter
// =============================================================================

// =============================================================================
// GLOBAL COLOR CONFIGURATION
// Edit these values to customize colors across the entire application
// =============================================================================

const APP_COLORS = {
    // Email Direction Colors
    directions: {
        inbound: {
            // Indigo
            badge: 'bg-indigo-100 dark:bg-indigo-500/10 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-500/20',
            bg: 'bg-indigo-100 dark:bg-indigo-500/25',
            text: 'text-indigo-700 dark:text-indigo-400'
        },
        outbound: {
            // Blue
            badge: 'bg-blue-100 dark:bg-blue-500/10 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-500/20',
            bg: 'bg-blue-100 dark:bg-blue-500/25',
            text: 'text-blue-700 dark:text-blue-400'
        },
        internal: {
            // Teal
            badge: 'bg-teal-100 dark:bg-teal-500/10 text-teal-800 dark:text-teal-300 border border-teal-200 dark:border-teal-500/20',
            bg: 'bg-teal-100 dark:bg-teal-500/25',
            text: 'text-teal-700 dark:text-teal-400'
        }
    },
    statuses: {
        delivered: {
            // Emerald
            badge: 'bg-emerald-100 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-500/20',
            bg: 'bg-emerald-100 dark:bg-emerald-500/25',
            text: 'text-emerald-700 dark:text-emerald-400'
        },
        sent: {
            // Green
            badge: 'bg-green-100 dark:bg-green-500/10 text-green-700 dark:text-green-300 border border-green-200 dark:border-green-500/20',
            bg: 'bg-green-100 dark:bg-green-500/25',
            text: 'text-green-700 dark:text-green-400'
        },
        deferred: {
            // Yellow (Fixed: Changed from Amber to Yellow)
            badge: 'bg-yellow-100 dark:bg-yellow-500/10 text-yellow-700 dark:text-yellow-300 border border-yellow-200 dark:border-yellow-500/20',
            bg: 'bg-yellow-100 dark:bg-yellow-500/25',
            text: 'text-yellow-700 dark:text-yellow-400'
        },
        bounced: {
            // Orange
            badge: 'bg-orange-100 dark:bg-orange-500/10 text-orange-700 dark:text-orange-300 border border-orange-200 dark:border-orange-500/20',
            bg: 'bg-orange-100 dark:bg-orange-500/25',
            text: 'text-orange-700 dark:text-orange-400'
        },
        rejected: {
            // Red
            badge: 'bg-red-100 dark:bg-red-500/10 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-500/20',
            bg: 'bg-red-100 dark:bg-red-500/25',
            text: 'text-red-700 dark:text-red-400'
        },
        spam: {
            // Fuchsia
            badge: 'bg-fuchsia-100 dark:bg-fuchsia-500/10 text-fuchsia-700 dark:text-fuchsia-300 border border-fuchsia-200 dark:border-fuchsia-500/20',
            bg: 'bg-fuchsia-100 dark:bg-fuchsia-500/25',
            text: 'text-fuchsia-700 dark:text-fuchsia-400'
        },
        expired: {
            // Zinc
            badge: 'bg-zinc-100 dark:bg-zinc-500/10 text-zinc-700 dark:text-zinc-300 border border-zinc-200 dark:border-zinc-500/20',
            bg: 'bg-zinc-100 dark:bg-zinc-500/25',
            text: 'text-zinc-700 dark:text-zinc-400'
        }
    },
    // Default color for unknown values
    default: {
        badge: 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300',
        bg: 'bg-gray-100 dark:bg-gray-700',
        text: 'text-gray-600 dark:text-gray-400'
    }
};

// Helper functions for accessing colors
function getDirectionBadgeClass(direction) {
    return APP_COLORS.directions[direction]?.badge || APP_COLORS.default.badge;
}

function getDirectionBgClass(direction) {
    return APP_COLORS.directions[direction]?.bg || APP_COLORS.default.bg;
}

function getDirectionTextClass(direction) {
    return APP_COLORS.directions[direction]?.text || APP_COLORS.default.text;
}

function getStatusBadgeClass(status) {
    return APP_COLORS.statuses[status]?.badge || APP_COLORS.default.badge;
}

function getStatusBgClass(status) {
    return APP_COLORS.statuses[status]?.bg || APP_COLORS.default.bg;
}

function getStatusTextClass(status) {
    return APP_COLORS.statuses[status]?.text || APP_COLORS.default.text;
}

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

// Authentication state
let authCredentials = null;
// DMARC imap
let dmarcImapStatus = null;
let dmarcConfiguration = null;

// Load saved credentials from sessionStorage
function loadAuthCredentials() {
    try {
        const saved = sessionStorage.getItem('auth_credentials');
        if (saved) {
            authCredentials = JSON.parse(saved);
        }
    } catch (e) {
        console.error('Failed to load auth credentials:', e);
        authCredentials = null;
    }
}

// Save credentials to sessionStorage
function saveAuthCredentials(username, password) {
    try {
        authCredentials = { username, password };
        sessionStorage.setItem('auth_credentials', JSON.stringify(authCredentials));
    } catch (e) {
        console.error('Failed to save auth credentials:', e);
    }
}

// Clear credentials
function clearAuthCredentials() {
    authCredentials = null;
    try {
        sessionStorage.removeItem('auth_credentials');
    } catch (e) {
        console.error('Failed to clear auth credentials:', e);
    }
}

// Create Basic Auth header
function getAuthHeader() {
    if (!authCredentials) return {};
    const credentials = btoa(`${authCredentials.username}:${authCredentials.password}`);
    return {
        'Authorization': `Basic ${credentials}`
    };
}

// Enhanced fetch with authentication
async function authenticatedFetch(url, options = {}) {
    const headers = {
        ...options.headers,
        ...getAuthHeader()
    };

    const response = await fetch(url, {
        ...options,
        headers
    });

    // Handle 401 Unauthorized
    if (response.status === 401) {
        clearAuthCredentials();
        showLoginModal();
        throw new Error('Authentication required');
    }

    return response;
}

// Handle login form submission (not used in main app, only in login.html)
async function handleLogin(event) {
    event.preventDefault();

    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    const errorDiv = document.getElementById('login-error');
    const errorText = document.getElementById('login-error-text');
    const submitBtn = document.getElementById('login-submit');
    const submitText = document.getElementById('login-submit-text');
    const submitLoading = document.getElementById('login-submit-loading');

    // Hide error
    if (errorDiv) errorDiv.classList.add('hidden');

    // Show loading
    if (submitText) submitText.classList.add('hidden');
    if (submitLoading) submitLoading.classList.remove('hidden');
    if (submitBtn) submitBtn.disabled = true;

    try {
        // Save credentials
        saveAuthCredentials(username, password);

        // Test authentication with a simple API call
        const response = await authenticatedFetch('/api/info');

        if (response.ok) {
            // Success - redirect to main app
            window.location.href = '/';
        } else {
            throw new Error('Authentication failed');
        }
    } catch (error) {
        // Show error
        if (errorDiv) {
            errorDiv.classList.remove('hidden');
            if (errorText) {
                errorText.textContent = error.message || 'Invalid username or password';
            }
        }

        // Clear password field
        const passwordField = document.getElementById('login-password');
        if (passwordField) passwordField.value = '';

        // Clear credentials
        clearAuthCredentials();
    } finally {
        // Hide loading
        if (submitText) submitText.classList.remove('hidden');
        if (submitLoading) submitLoading.classList.add('hidden');
        if (submitBtn) submitBtn.disabled = false;
    }
}

// Handle logout
function handleLogout() {
    clearAuthCredentials();
    // Redirect to login page
    window.location.href = '/login';
}

// Check authentication on page load
async function checkAuthentication() {
    // First check if authentication is enabled
    try {
        const infoResponse = await fetch('/api/info');
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

    // Authentication is enabled, check credentials
    loadAuthCredentials();

    if (!authCredentials) {
        // No credentials saved, redirect to login
        window.location.href = '/login';
        return false;
    }

    try {
        // Test if credentials are still valid
        const response = await authenticatedFetch('/api/info');
        if (response.ok) {
            // Show logout button if auth is enabled
            const logoutBtn = document.getElementById('logout-btn');
            if (logoutBtn) logoutBtn.classList.remove('hidden');
            return true;
        } else {
            // Invalid credentials, redirect to login
            window.location.href = '/login';
            return false;
        }
    } catch (error) {
        // Authentication error, redirect to login
        window.location.href = '/login';
        return false;
    }
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

    loadAppInfo();

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

        if (updateBadge && data.update_available) {
            updateBadge.classList.remove('hidden');
            updateBadge.title = `Update available: v${data.latest_version}`;
        } else if (updateBadge) {
            updateBadge.classList.add('hidden');
        }
    } catch (error) {
        console.error('Failed to load app version status:', error);
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
                        <span>${formatTime(msg.last_seen)}</span>
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

    container.innerHTML = `
        <div class="space-y-3">
            ${uniqueLogs.map(log => `
                <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition">
                    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                        <div class="flex flex-wrap items-center gap-2">
                            <span class="font-mono text-sm font-semibold text-gray-900 dark:text-white">${log.ip || '-'}</span>
                            ${log.username && log.username !== '-' ? `<span class="text-sm text-blue-600 dark:text-blue-400">${escapeHtml(log.username)}</span>` : ''}
                            <span class="inline-block px-2 py-0.5 text-xs font-medium rounded ${getActionClass(log.action)}">${getActionLabel(log.action)}</span>
                            ${log.attempts_left !== null && log.attempts_left !== undefined ? `<span class="text-xs text-gray-500 dark:text-gray-400">${log.attempts_left} attempts left</span>` : ''}
                        </div>
                        <span class="text-xs text-gray-500 dark:text-gray-400">${formatTime(log.time)}</span>
                    </div>
                    <p class="text-sm text-gray-700 dark:text-gray-300 break-words">${escapeHtml(log.message || '-')}</p>
                </div>
            `).join('')}
        </div>
        ${renderPagination('netfilter', data.page, data.pages)}
    `;
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

// Render quarantine without loading spinner
function renderQuarantineData(data) {
    const container = document.getElementById('quarantine-logs');
    if (!container) return;

    if (!data.data || data.data.length === 0) {
        container.innerHTML = '<p class="text-gray-500 dark:text-gray-400 text-center py-8">No quarantined messages</p>';
        return;
    }

    container.innerHTML = `
        <div class="space-y-4">
            ${data.data.map(item => `
                <div class="border border-red-200 dark:border-red-900/50 rounded-lg p-4 bg-red-50 dark:bg-red-900/20">
                    <div class="flex flex-col sm:flex-row sm:justify-between sm:items-start mb-2 gap-2">
                        <div class="flex-1">
                            <p class="text-sm font-medium text-gray-900 dark:text-white">${escapeHtml(item.subject || 'No subject')}</p>
                            <p class="text-sm text-gray-600 dark:text-gray-300">From: ${escapeHtml(item.sender)}</p>
                        </div>
                        <span class="text-xs text-gray-500 dark:text-gray-400">${formatTime(item.created)}</span>
                    </div>
                    <p class="text-xs text-red-600 dark:text-red-400 mt-2">${item.reason || 'Quarantined'}</p>
                </div>
            `).join('')}
        </div>
    `;
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

        if (hasDataChanged(data, 'settings')) {
            console.log('[REFRESH] Settings data changed, updating UI');
            lastDataCache.settings = data;

            const content = document.getElementById('settings-content');
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
    switch (tab) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'messages':
            loadMessages(1);
            break;
        case 'netfilter':
            loadNetfilterLogs(1);
            break;
        case 'queue':
            loadQueue();
            break;
        case 'quarantine':
            loadQuarantine();
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
            loadMailboxStats();
            break;
        case 'settings':
            loadSettings();
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
    } catch (error) {
        console.error('Failed to load dashboard:', error);
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
        document.getElementById('recent-activity').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load activity: ${error.message}</p>`;
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
        console.log(`Postfix data loaded in ${loadTime}s:`, data);

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
        document.getElementById('postfix-logs').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load logs: ${error.message}</p>`;
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
        document.getElementById('rspamd-logs').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load logs: ${error.message}</p>`;
    }
}

// =============================================================================
// NETFILTER LOGS
// =============================================================================

function applyNetfilterFilters() {
    currentFilters.netfilter = {
        ip: document.getElementById('netfilter-filter-ip').value,
        username: document.getElementById('netfilter-filter-username').value,
        action: document.getElementById('netfilter-filter-action').value
    };
    currentPage.netfilter = 1;
    loadNetfilterLogs();
}

function clearNetfilterFilters() {
    document.getElementById('netfilter-filter-ip').value = '';
    document.getElementById('netfilter-filter-username').value = '';
    document.getElementById('netfilter-filter-action').value = '';
    currentFilters.netfilter = {};
    currentPage.netfilter = 1;
    loadNetfilterLogs();
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

        if (!data.data || data.data.length === 0) {
            container.innerHTML = '<p class="text-gray-500 dark:text-gray-400 text-center py-8">No logs found</p>';
            const countEl = document.getElementById('security-count');
            if (countEl) countEl.textContent = '';
            return;
        }

        // Deduplicate logs based on message + time + priority
        const uniqueLogs = deduplicateNetfilterLogs(data.data);

        // Update count display with total count from API (like Messages page)
        const countEl = document.getElementById('security-count');
        if (countEl) {
            countEl.textContent = data.total ? `(${data.total.toLocaleString()} results)` : '';
        }

        container.innerHTML = `
            <div class="space-y-3">
                ${uniqueLogs.map(log => `
                    <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition">
                        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                            <div class="flex flex-wrap items-center gap-2">
                                <span class="font-mono text-sm font-semibold text-gray-900 dark:text-white">${log.ip || '-'}</span>
                                ${log.username && log.username !== '-' ? `<span class="text-sm text-blue-600 dark:text-blue-400">${escapeHtml(log.username)}</span>` : ''}
                                <span class="inline-block px-2 py-0.5 text-xs font-medium rounded ${getActionClass(log.action)}">${getActionLabel(log.action)}</span>
                                ${log.attempts_left !== null && log.attempts_left !== undefined ? `<span class="text-xs text-gray-500 dark:text-gray-400">${log.attempts_left} attempts left</span>` : ''}
                            </div>
                            <span class="text-xs text-gray-500 dark:text-gray-400">${formatTime(log.time)}</span>
                        </div>
                        <p class="text-sm text-gray-700 dark:text-gray-300 break-words">${escapeHtml(log.message || '-')}</p>
                    </div>
                `).join('')}
            </div>
            ${renderPagination('netfilter', data.page, data.pages)}
        `;

        currentPage.netfilter = page;
    } catch (error) {
        console.error('Failed to load Netfilter logs:', error);
        document.getElementById('netfilter-logs').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load logs: ${error.message}</p>`;
        const countEl = document.getElementById('security-count');
        if (countEl) countEl.textContent = '';
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
        document.getElementById('queue-logs').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load queue: ${error.message}</p>`;
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

    container.innerHTML = `
        <div class="space-y-4">
            ${filteredData.map(item => `
                <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4 bg-gray-50 dark:bg-gray-700/50">
                    <div class="flex flex-col sm:flex-row sm:justify-between sm:items-start mb-2 gap-2">
                        <div class="flex-1">
                            <p class="text-sm font-medium text-gray-900 dark:text-white">From: ${escapeHtml(item.sender)}</p>
                            <p class="text-sm text-gray-600 dark:text-gray-300">Queue ID: ${item.queue_id}</p>
                        </div>
                        <span class="text-xs text-gray-500 dark:text-gray-400">${formatTime(new Date(item.arrival_time * 1000).toISOString())}</span>
                    </div>
                    <div class="mb-2">
                        <p class="text-sm font-medium text-gray-700 dark:text-gray-300">Recipients:</p>
                        ${item.recipients.map(r => `<p class="text-sm text-gray-600 dark:text-gray-400">${escapeHtml(r)}</p>`).join('')}
                    </div>
                    <div class="flex items-center justify-between">
                        <span class="text-xs text-gray-500 dark:text-gray-400">Size: ${formatSize(item.message_size)}</span>
                    </div>
                </div>
            `).join('')}
        </div>
    `;
}

function clearQueueFilters() {
    document.getElementById('queue-filter-search').value = '';
    document.getElementById('queue-filter-queue-id').value = '';
    applyQueueFilters();
}

// =============================================================================
// QUARANTINE
// =============================================================================

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

        // ⭐ NEW: Update counter display
        const countEl = document.getElementById('quarantine-count');
        if (countEl) {
            countEl.textContent = data.total ? `(${data.total.toLocaleString()} results)` : '';
        }

        if (!data.data || data.data.length === 0) {
            container.innerHTML = '<p class="text-gray-500 dark:text-gray-400 text-center py-8">No quarantined messages</p>';
            return;
        }

        // ⭐ NEW: Use separate render function
        renderQuarantineData(data);
    } catch (error) {
        console.error('Failed to load quarantine:', error);
        document.getElementById('quarantine-logs').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load quarantine: ${error.message}</p>`;
        // ⭐ NEW: Clear counter on error
        const countEl = document.getElementById('quarantine-count');
        if (countEl) countEl.textContent = '';
    }
}

// Render quarantine without loading spinner (for smart refresh)
function renderQuarantineData(data) {
    const container = document.getElementById('quarantine-logs');
    if (!container) return;

    // Update counter display
    const countEl = document.getElementById('quarantine-count');
    if (countEl) {
        countEl.textContent = data.total ? `(${data.total.toLocaleString()} results)` : '';
    }

    if (!data.data || data.data.length === 0) {
        container.innerHTML = '<p class="text-gray-500 dark:text-gray-400 text-center py-8">No quarantined messages</p>';
        return;
    }

    container.innerHTML = `
        <div class="space-y-3">
            ${data.data.map(item => `
                <div class="border border-red-200 dark:border-red-900/50 rounded-lg p-4 bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/30 transition">
                    <div class="grid grid-cols-1 sm:grid-cols-[1fr_auto] gap-2 mb-2 items-start">
                        <div class="min-w-0 overflow-hidden">
                            <div class="flex flex-wrap items-center gap-2 mb-1">
                                <span class="text-sm font-medium text-gray-900 dark:text-white">${escapeHtml(item.sender || 'Unknown')}</span>
                                <svg class="w-4 h-4 text-gray-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                                </svg>
                                <span class="text-sm text-gray-600 dark:text-gray-300">${escapeHtml(item.rcpt || 'Unknown')}</span>
                            </div>
                            <p class="text-xs text-gray-500 dark:text-gray-400 truncate" title="${escapeHtml(item.subject || 'No subject')}">${escapeHtml(item.subject || 'No subject')}</p>
                        </div>
                        <div class="flex flex-wrap items-center gap-2 flex-shrink-0 sm:justify-end">
                            <span class="inline-block px-2 py-0.5 text-xs font-medium rounded bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300">${item.action || 'Quarantined'}</span>
                            ${item.virus_flag ? '<span class="inline-block px-2 py-0.5 text-xs font-medium rounded bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300">🦠 VIRUS</span>' : ''}
                        </div>
                    </div>
                    <div class="flex flex-wrap items-center gap-4 text-xs text-gray-600 dark:text-gray-400">
                        <span>${formatTime(item.created)}</span>
                        ${item.qid ? `<span class="font-mono" title="Queue ID">Q: ${item.qid}</span>` : ''}
                        ${item.score !== undefined && item.score !== null ? `<span>Score: <span class="${item.score >= 15 ? 'text-red-600 dark:text-red-400 font-semibold' : 'text-gray-600 dark:text-gray-300'}">${item.score.toFixed(1)}</span></span>` : ''}
                    </div>
                </div>
            `).join('')}
        </div>
    `;
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
        ip: document.getElementById('messages-filter-ip').value
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
    currentFilters.messages = {};
    currentPage.messages = 1;
    loadMessages();
}

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
                            <span>${formatTime(msg.last_seen)}</span>
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
        document.getElementById('messages-logs').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load messages: ${error.message}</p>`;
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
            const running = containersList.filter(c => c.state === 'running').length;
            const stopped = containersList.filter(c => c.state !== 'running').length;
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

        const response = await authenticatedFetch('/api/status/mailcow-info');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('System info data:', data);

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
            </div>
        `;
    } catch (error) {
        console.error('Failed to load system info:', error);
        document.getElementById('status-system').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load system info: ${error.message}</p>`;
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
        document.getElementById('status-storage').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load storage info: ${error.message}</p>`;
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
        document.getElementById('status-import').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load: ${error.message}</p>`;
        document.getElementById('status-correlation').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load: ${error.message}</p>`;
        document.getElementById('status-jobs').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load: ${error.message}</p>`;
    }
}

async function checkBlacklists(force = false) {
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
        const response = await authenticatedFetch(`/api/blacklist/check${force ? '?force=true' : ''}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        // Poller handles completion
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
        container.innerHTML = `<p class="text-red-500 text-center py-8">Failed to load: ${error.message}</p>`;
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
        const hostname = escapeHtml(host.hostname); // This is the IP

        // Parse source to check for stored FQDN
        let sourceRaw = host.source || 'system';
        let sourceLabel = sourceRaw;
        let displayHostname = hostname;

        if (sourceRaw.includes(':')) {
            const parts = sourceRaw.split(':');
            sourceLabel = parts[0]; // e.g. transport
            const fqdn = parts.slice(1).join(':'); // e.g. mx.example.com
            if (fqdn && fqdn !== hostname) {
                displayHostname = `${hostname} <span class="text-gray-500 font-normal">(${escapeHtml(fqdn).toLowerCase()})</span>`;
            }
        }

        const source = escapeHtml(sourceLabel).toLowerCase();

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
                                ${displayHostname}
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

        // Inner results (only if data exists)
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

                html += `
                    <div class="px-2 py-1.5 rounded bg-${color}-50 dark:bg-${color}-900/10 border border-${color}-100 dark:border-${color}-900/30 text-xs flex items-center justify-between group/item relative hover:bg-${color}-100 dark:hover:bg-${color}-900/20 transition cursor-default">
                        <span class="font-medium text-${color}-700 dark:text-${color}-300 truncate mr-1" title="${escapeHtml(result.name)}">${escapeHtml(result.name)}</span>
                        <div class="flex items-center">
                            <span class="text-${color}-600 dark:text-${color}-400 font-bold">${icon}</span>
                            ${result.info_url ? `<a href="${result.info_url}" target="_blank" class="ml-1 text-${color}-400 hover:text-${color}-600" title="View info"><svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg></a>` : ''}
                        </div>
                    </div>
                `;
            });
            html += '</div>';
            // Currently /monitored does NOT return the full 'results' array (50 items) to save bandwidth?
            // Checking blacklist.py: It DOES NOT return 'results'. 
            // We should fetch details on demand OR include them.
            // Given the user wants to see " Listed On 0/50... should be dynamic", they likely want to see the list.
            // I forgot to include 'results' in /monitored. 
            // But for now, let's just show "Listed" items or a "Load Details" placeholder?
            // User requested: "Status page section will show... server IP and all those in Transport".
            // AND they complained about blacklist list being static.
            // It's better if I modify blacklist.py to return 'results' OR fetch them here.

            // Since I haven't modified blacklist.py to return results, I will assume I need to fetch them individually?
            // No, that's too many requests.
            // I SHOULD have included results in /monitored. 

            // Let me pause here and update blacklist.py to include results, OR...
            // actually, let's check blacklist.py content I wrote.
            // I wrote: `status_data.update({ ... "results": check.results ... })` ? 
            // Let's check Step 1213 output.
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

async function checkHost(hostname) {
    if (!hostname) return;
    try {
        showToast('Starting check for ' + hostname + '...', 'info');
        // We can trigger the specific check via API
        const response = await authenticatedFetch(`/api/blacklist/check?host=${hostname}&force=true`);
        if (response.ok) {
            showToast('Check completed for ' + hostname, 'success');
            loadBlacklistStatus();
        } else {
            showToast('Check failed', 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

// Dashboard blacklist summary loader
async function loadDashboardBlacklistSummary() {
    const container = document.getElementById('dashboard-blacklist-summary');
    if (!container) return;

    try {
        const response = await authenticatedFetch('/api/blacklist/summary');
        if (!response.ok) {
            container.innerHTML = `<p class="text-gray-500 dark:text-gray-400 text-center text-sm">Unable to load</p>`;
            return;
        }

        const data = await response.json();

        if (!data.has_data) {
            container.innerHTML = `
                <div class="text-center">
                    <p class="text-sm text-gray-500 dark:text-gray-400">No data</p>
                    <p class="text-xs text-gray-400 dark:text-gray-500 mt-1">Check will run automatically</p>
                </div>
            `;
            return;
        }

        const statusColor = data.status === 'clean' ? 'green' : data.status === 'listed' ? 'red' : 'yellow';
        const statusIcon = data.status === 'clean' ? '✓' : data.status === 'listed' ? '✗' : '?';
        const statusText = data.status === 'clean' ? 'Clean' : data.status === 'listed' ? 'Listed' : 'Unknown';

        container.innerHTML = `
            <div class="space-y-3">
                <div class="flex items-center justify-between">
                    <span class="text-sm text-gray-600 dark:text-gray-400">Status</span>
                    <span class="text-sm font-semibold text-${statusColor}-600 dark:text-${statusColor}-400">${statusIcon} ${statusText}</span>
                </div>
                <div class="flex items-center justify-between">
                    <span class="text-sm text-gray-600 dark:text-gray-400">Listed On</span>
                    <span class="text-sm font-semibold ${data.listed_count > 0 ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'}">${data.listed_count}/${data.total_blacklists}</span>
                </div>
                <div class="flex items-center justify-between">
                    <span class="text-sm text-gray-600 dark:text-gray-400">IP</span>
                    <span class="text-xs font-mono text-gray-700 dark:text-gray-300">${data.server_ip || '-'}</span>
                </div>
                ${data.checked_at ? `
                    <p class="text-xs text-gray-400 dark:text-gray-500 text-center pt-2 border-t border-gray-200 dark:border-gray-700">
                        ${formatTime(data.checked_at)}
                    </p>
                ` : ''}
            </div>
        `;
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

                html += `
                    <div class="px-2 py-1.5 rounded bg-${color}-50 dark:bg-${color}-900/10 border border-${color}-100 dark:border-${color}-900/30 text-xs flex items-center justify-between group/item relative hover:bg-${color}-100 dark:hover:bg-${color}-900/20 transition cursor-default">
                        <span class="font-medium text-${color}-700 dark:text-${color}-300 truncate mr-1" title="${escapeHtml(result.name)}">${escapeHtml(result.name)}</span>
                        <div class="flex items-center">
                            <span class="text-${color}-600 dark:text-${color}-400 font-bold">${icon}</span>
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
                                <span class="font-mono text-gray-600 dark:text-gray-400">${escapeHtml(item.message_id || 'N/A')}</span>
                                <span class="text-yellow-600 dark:text-yellow-400">${item.age_minutes}m ago</span>
                            </div>
                            <div class="text-gray-500 dark:text-gray-400">
                                ${escapeHtml(item.sender || 'N/A')} => ${escapeHtml(item.recipient || 'N/A')}
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
    container.innerHTML = `
        <div class="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
            ${renderJobCard('Fetch Logs', 'fetch_logs', jobs.fetch_logs)}
            ${renderJobCard('Complete Correlations', 'complete_correlations', jobs.complete_correlations)}
            ${renderJobCard('Update Final Status', 'update_final_status', jobs.update_final_status)}
            ${renderJobCard('Expire Correlations', 'expire_correlations', jobs.expire_correlations)}
            ${renderJobCard('Cleanup Logs', 'cleanup_logs', jobs.cleanup_logs)}
            ${renderJobCard('Check App Version', 'check_app_version', jobs.check_app_version)}
            ${renderJobCard('DNS Check (All Domains)', 'dns_check', jobs.dns_check)}
            ${renderJobCard('Sync Active Domains', 'sync_local_domains', jobs.sync_local_domains)}
            ${renderJobCard('DMARC IMAP Import', 'dmarc_imap_sync', jobs.dmarc_imap_sync)}
            ${renderJobCard('Update MaxMind Databases', 'update_geoip', jobs.update_geoip)}
            ${renderJobCard('Mailbox Statistics', 'mailbox_stats', jobs.mailbox_stats)}
            ${renderJobCard('Alias Statistics', 'alias_stats', jobs.alias_stats)}
            ${renderJobCard('IP Blacklist Check (All Hosts)', 'blacklist_check', jobs.blacklist_check)}
            ${renderJobCard('Sync Transports & Relayhosts', 'sync_transports', jobs.sync_transports)}
            ${renderJobCard('Weekly Summary Report', 'send_weekly_summary', jobs.send_weekly_summary)}
        </div>
    `;
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
            console.error(`Failed to trigger job ${jobKey}:`, error);
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
        content.innerHTML = `<p class="text-red-500 text-center py-8">Failed to load Postfix details: ${error.message}</p>`;
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
        content.innerHTML = `<p class="text-red-500 text-center py-8">Failed to load message details: ${error.message}</p>`;
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
                                <span class="text-sm text-gray-900 dark:text-white">${escapeHtml(r)}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        } else {
            recipientsRightColumn = `
                <div>
                    <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">To</p>
                    <p class="text-sm font-semibold text-gray-900 dark:text-white mt-1">${escapeHtml(recipientsToDisplay[0] || '-')}</p>
                </div>
            `;
        }
    } else if (data.recipient) {
        recipientsRightColumn = `
            <div>
                <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">To</p>
                <p class="text-sm font-semibold text-gray-900 dark:text-white mt-1">${escapeHtml(data.recipient)}</p>
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
                                <p class="text-sm font-semibold text-gray-900 dark:text-white mt-1">${escapeHtml(data.sender || '-')}</p>
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
                                    <p class="text-xs font-mono text-gray-600 dark:text-gray-400 mt-1">${data.queue_id}</p>
                                </div>
                            ` : ''}
                            ${data.message_id ? `
                                <div>
                                    <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Message ID</p>
                                    <p class="text-xs font-mono text-gray-600 dark:text-gray-400 mt-1 break-all">${escapeHtml(data.message_id)}</p>
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
                                    ${data.rspamd.user ? `<p>Authenticated User: ${escapeHtml(data.rspamd.user)}</p>` : ''}
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
                            <p class="text-sm font-semibold text-gray-900 dark:text-white mt-1">${escapeHtml(sender)}</p>
                        </div>
                    ` : ''}
                    ${recipientsFromPostfix.size > 0 ? `
                        <div>
                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">To (${recipientsFromPostfix.size})</p>
                            <p class="text-sm font-semibold text-gray-900 dark:text-white mt-1">${recipientsFromPostfix.size === 1 ? escapeHtml(Array.from(recipientsFromPostfix)[0]) : `${recipientsFromPostfix.size} recipients`}</p>
                        </div>
                    ` : (data.recipients && data.recipients.length > 0 ? `
                        <div>
                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">To (${data.recipients.length})</p>
                            <p class="text-sm font-semibold text-gray-900 dark:text-white mt-1">${data.recipients.length === 1 ? escapeHtml(data.recipients[0]) : `${data.recipients.length} recipients`}</p>
                        </div>
                    ` : '')}
                    ${clientIp ? `
                        <div>
                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Client IP</p>
                            <p class="text-sm font-mono font-semibold text-gray-900 dark:text-white mt-1">${clientIp}</p>
                        </div>
                    ` : ''}
                    ${queueId ? `
                        <div>
                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Queue ID</p>
                            <p class="text-sm font-mono font-semibold text-gray-900 dark:text-white mt-1">${queueId}</p>
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
                            <p class="text-xs font-mono text-gray-700 dark:text-gray-300 mt-1 break-all">${escapeHtml(messageId)}</p>
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
                                        <span class="text-sm text-gray-900 dark:text-white truncate flex-1">${escapeHtml(recipient)}</span>
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
                                <span class="text-xs font-mono font-semibold text-gray-900 dark:text-white">${log.ip}</span>
                            </div>
                            <span class="inline-block px-2 py-0.5 text-xs font-medium rounded ${getActionClass(log.action)}">${getActionLabel(log.action)}</span>
                        </div>
                        ${log.username ? `<p class="text-xs text-gray-700 dark:text-gray-300">User: ${escapeHtml(log.username)}</p>` : ''}
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
            content.innerHTML = marked.parse(changelog);
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
        return `<p>Source IP: ${escapeHtml(ip)}</p>`;
    }

    const flagUrl = getFlagUrl(rspamdData.country_code, size);
    const [width, height] = size.split('x').map(Number);

    // Use a list to store the parts of the info string
    let parts = [`<strong>${escapeHtml(ip)}</strong>`];

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

function formatTime(isoString) {
    if (!isoString) return '-';
    const date = new Date(isoString);
    // Use timezone from app configuration if set, otherwise use browser's local timezone
    // The date is already in UTC (with 'Z' suffix), so browser will convert it correctly
    try {
        if (appTimezone && appTimezone !== 'UTC') {
            // Use Intl.DateTimeFormat with app timezone
            const formatter = new Intl.DateTimeFormat(undefined, {
                day: '2-digit',
                month: '2-digit',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false,
                timeZone: appTimezone
            });
            return formatter.format(date);
        } else {
            // Use browser's local timezone and locale
            return date.toLocaleString(undefined, {
                day: '2-digit',
                month: '2-digit',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false
            });
        }
    } catch (e) {
        // Fallback to browser's local timezone if timezone is invalid
        console.warn('Invalid timezone, using browser local timezone:', appTimezone, e);
        return date.toLocaleString(undefined, {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });
    }
}

function formatDate(isoString) {
    if (!isoString) return '-';
    // Use formatTime for consistent date/time formatting
    return formatTime(isoString);
}

function formatSize(bytes) {
    if (!bytes) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

function getStatusClass(status) {
    const statusColors = APP_COLORS.statuses[status];
    if (statusColors) {
        return statusColors.badge;
    }
    return APP_COLORS.default.badge;
}

function getCorrelationStatusDisplay(msg) {
    // If there's a final_status, show it with emoji
    if (msg.final_status) {
        const statusEmoji = {
            'delivered': '✓',
            'sent': '✓',
            'bounced': '↩',
            'rejected': '✗',
            'deferred': '⏳',
            'spam': '⚠',
            'expired': '⏸'
        };
        const statusText = {
            'delivered': 'Delivered',
            'sent': 'Sent',
            'bounced': 'Bounced',
            'rejected': 'Rejected',
            'deferred': 'Deferred',
            'spam': 'Spam',
            'expired': 'Expired'
        };
        const emoji = statusEmoji[msg.final_status] || '•';
        const text = statusText[msg.final_status] || msg.final_status;
        return { display: `${emoji} ${text}`, class: getStatusClass(msg.final_status) };
    }

    // If no final_status but correlation is complete, show Linked
    if (msg.is_complete === true) {
        return { display: '✓ Linked', class: 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300' };
    }

    // If correlation is not complete, show Pending
    if (msg.is_complete === false) {
        return { display: '⏳ Pending', class: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300' };
    }

    return null;
}

function getDirectionClass(direction) {
    const directionColors = APP_COLORS.directions[direction];
    if (directionColors) {
        return directionColors.badge;
    }
    return APP_COLORS.default.badge;
}

function getActionLabel(action) {
    switch (action) {
        case 'ban':
            return 'BAN';
        case 'unban':
            return 'UNBAN';
        case 'banned':
            return 'BAN'; // Legacy support
        case 'warning':
            return 'warning';
        case 'info':
            return 'info';
        default:
            return action || 'warning';
    }
}

function getActionClass(action) {
    switch (action) {
        case 'ban':
        case 'banned': // Legacy support
            return 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300';
        case 'unban':
            return 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300';
        case 'warning':
            return 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300';
        case 'info':
            return 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300';
        default:
            return 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300';
    }
}

function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    let cleanText = String(text).replace(/\\"/g, '"');
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return cleanText.replace(/[&<>"']/g, function (m) { return map[m]; });
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
// DOMAINS TAB - Domains management with DNS validation
// =============================================================================

async function loadDomains() {
    const loading = document.getElementById('domains-loading');
    const content = document.getElementById('domains-content');

    if (!loading || !content) {
        console.error('Domains elements not found');
        return;
    }

    loading.classList.remove('hidden');
    content.classList.add('hidden');

    try {
        const response = await authenticatedFetch('/api/domains/all');

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        renderDomains(content, data);

        loading.classList.add('hidden');
        content.classList.remove('hidden');

    } catch (error) {
        console.error('Failed to load domains:', error);
        loading.innerHTML = `
            <div class="text-center py-12">
                <svg class="w-16 h-16 mx-auto text-red-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <p class="text-red-500">Failed to load domains</p>
                <p class="text-sm text-gray-500 dark:text-gray-400 mt-2">${escapeHtml(error.message)}</p>
            </div>
        `;
    }
}

function renderDomains(container, data) {
    const domains = data.domains || [];

    const dnsCheckInfo = document.getElementById('dns-check-info');
    if (dnsCheckInfo) {
        const lastCheck = data.last_dns_check
            ? formatTime(data.last_dns_check)
            : '<span class="text-gray-400">Never</span>';

        dnsCheckInfo.innerHTML = `
            <div class="text-right">
                <p class="text-xs text-gray-500 dark:text-gray-400">Last checked:</p>
                <p class="text-sm font-medium text-gray-900 dark:text-white">${lastCheck}</p>
            </div>
            <button 
                id="check-all-dns-btn"
                onclick="checkAllDomainsDNS()" 
                class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition text-sm font-medium flex items-center gap-2">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                </svg>
                Check Now
            </button>
        `;
    }

    if (domains.length === 0) {
        container.innerHTML = `
            <div class="text-center py-12">
                <svg class="w-16 h-16 mx-auto text-gray-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
                </svg>
                <p class="text-gray-500 dark:text-gray-400">No domains found</p>
            </div>
        `;
        return;
    }

    // Summary cards
    const summaryHTML = `
        <div class="grid grid-cols-3 gap-4 mb-6">
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-4 border border-gray-200 dark:border-gray-700">
                <div class="flex items-center justify-between mb-1">
                    <h3 class="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Total</h3>
                    <svg class="w-5 h-5 text-blue-500 opacity-80" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path>
                    </svg>
                </div>
                <p class="text-2xl font-bold text-gray-900 dark:text-white">${data.total || 0}</p>
            </div>
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-4 border border-gray-200 dark:border-gray-700">
                <div class="flex items-center justify-between mb-1">
                    <h3 class="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Active</h3>
                    <svg class="w-5 h-5 text-green-500 opacity-80" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                </div>
                <p class="text-2xl font-bold text-green-600 dark:text-green-400">${data.active || 0}</p>
            </div>
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-4 border border-gray-200 dark:border-gray-700">
                <div class="flex items-center justify-between mb-1">
                    <h3 class="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Inactive</h3>
                    <svg class="w-5 h-5 text-gray-400 opacity-80" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"></path>
                    </svg>
                </div>
                <p class="text-2xl font-bold text-gray-600 dark:text-gray-400">${(data.total || 0) - (data.active || 0)}</p>
            </div>
        </div>
    `;

    // Search/Filter bar
    const filterHTML = `
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 px-4 py-2">
            <div class="flex items-center gap-3 flex-wrap">
                <div class="flex items-center gap-3 flex-1 min-w-0">
                    <svg class="w-5 h-5 text-gray-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                    </svg>
                    <input 
                        type="text" 
                        id="domain-search-input"
                        placeholder="Search domains..." 
                        class="flex-1 px-3 py-2 text-sm border-0 bg-transparent text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-0 min-w-0"
                        oninput="filterDomains()"
                    >
                    <!-- Domain count badge -->
                    <span id="domain-count-badge" class="px-3 py-1 text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-full whitespace-nowrap">
                        ${domains.length} domains
                    </span>
                </div>
            </div>
        </div>
        <div class="flex items-center gap-4 py-4 text-sm font-medium text-gray-300 pl-10">
            <div class="flex items-center gap-4 flex-shrink-0">
                <!-- Filter: Show only domains with issues -->
                <label class="flex items-center gap-2 cursor-pointer">
                    <input 
                        type="checkbox" 
                        id="filter-issues-only"
                        class="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 dark:focus:ring-blue-600 dark:ring-offset-gray-800 focus:ring-2 dark:bg-gray-700 dark:border-gray-600"
                        onchange="filterDomains()"
                    >
                    <span class="text-sm font-medium text-gray-700 dark:text-gray-300 whitespace-nowrap">Show only domains with issues</span>
                </label>
            </div>
        </div>
    `;

    // Domains list with accordion style
    const domainsHTML = domains.map(domain => renderDomainAccordionRow(domain)).join('');

    container.innerHTML = summaryHTML + filterHTML + `
        <div id="domains-list" class="space-y-2">
            ${domainsHTML}
        </div>
    `;

    // Store domains data for filtering
    window.domainsData = domains;
}

// Filter domains based on search input and issues checkbox
function filterDomains() {
    const searchInput = document.getElementById('domain-search-input');
    const issuesCheckbox = document.getElementById('filter-issues-only');
    const domainsList = document.getElementById('domains-list');
    const countBadge = document.getElementById('domain-count-badge');

    if (!searchInput || !domainsList || !window.domainsData) return;

    const searchTerm = searchInput.value.toLowerCase().trim();
    const showIssuesOnly = issuesCheckbox ? issuesCheckbox.checked : false;

    // Filter domains
    let filteredDomains = window.domainsData.filter(domain => {
        // Search filter
        const matchesSearch = domain.domain_name.toLowerCase().includes(searchTerm);

        // Issues filter - check if domain has any DNS issues
        let hasIssues = false;
        if (showIssuesOnly) {
            const dns = domain.dns_checks || {};
            const spf = dns.spf || {};
            const dkim = dns.dkim || {};
            const dmarc = dns.dmarc || {};

            // Check if any DNS check has error or warning status
            hasIssues =
                spf.status === 'error' || spf.status === 'warning' ||
                dkim.status === 'error' || dkim.status === 'warning' ||
                dmarc.status === 'error' || dmarc.status === 'warning';
        }

        return matchesSearch && (!showIssuesOnly || hasIssues);
    });

    // Update count badge
    if (countBadge) {
        countBadge.textContent = `${filteredDomains.length} domain${filteredDomains.length !== 1 ? 's' : ''}`;
    }

    // Re-render filtered domains
    if (filteredDomains.length === 0) {
        const noResultsMessage = showIssuesOnly && searchTerm === ''
            ? 'No domains with DNS issues found'
            : `No domains found matching "${escapeHtml(searchTerm)}"`;

        domainsList.innerHTML = `
            <div class="text-center py-12 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                <svg class="w-16 h-16 mx-auto text-gray-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                </svg>
                <p class="text-gray-500 dark:text-gray-400">${noResultsMessage}</p>
            </div>
        `;
    } else {
        domainsList.innerHTML = filteredDomains.map(domain => renderDomainAccordionRow(domain)).join('');
    }
}

function renderDomainAccordionRow(domain) {
    const dns = domain.dns_checks || {};
    const spf = dns.spf || { status: 'unknown', message: 'Not checked' };
    const dkim = dns.dkim || { status: 'unknown', message: 'Not checked' };
    const dmarc = dns.dmarc || { status: 'unknown', message: 'Not checked' };

    // Status icons for inline display
    const getStatusIcon = (status) => {
        if (status === 'success') return '<span class="text-green-500" title="OK">✓</span>';
        if (status === 'warning') return '<span class="text-amber-500" title="Warning">⚠</span>';
        if (status === 'error') return '<span class="text-red-500" title="Error">✗</span>';
        return '<span class="text-gray-400" title="Unknown">?</span>';
    };

    const domainId = `domain-${escapeHtml(domain.domain_name).replace(/\./g, '-')}`;

    return `
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 overflow-hidden">
            <!-- Summary Row - Clickable -->
            <div class="p-4 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/30 transition" onclick="toggleDomainDetails('${domainId}')">
                <!-- Desktop Layout (lg and up) -->
                <div class="hidden lg:grid lg:grid-cols-[minmax(0,350px)_1fr_minmax(0,280px)] items-center gap-4">
                    <!-- Left: Expand Icon + Domain Name + Status (max 350px) -->
                    <div class="flex items-center gap-3 min-w-0">
                        <svg id="${domainId}-icon-desktop" class="w-5 h-5 text-gray-400 transition-transform flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                        </svg>
                        
                        <div class="flex items-center gap-2 min-w-0">
                            <h3 class="text-base font-bold text-gray-900 dark:text-white truncate">${escapeHtml(domain.domain_name)}</h3>
                            ${domain.active ?
            '<span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-200 flex-shrink-0">Active</span>' :
            '<span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200 flex-shrink-0">Inactive</span>'
        }
                        </div>
                    </div>
                    
                    <!-- Center: DNS Status Indicators -->
                    <div class="flex items-center justify-center">
                        <div class="flex items-center gap-4 px-4 py-2 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                            <div class="flex items-center gap-1.5">
                                <span class="font-medium text-xs text-gray-600 dark:text-gray-400">SPF</span>
                                ${getStatusIcon(spf.status)}
                            </div>
                            <div class="w-px h-4 bg-gray-300 dark:bg-gray-600"></div>
                            <div class="flex items-center gap-1.5">
                                <span class="font-medium text-xs text-gray-600 dark:text-gray-400">DKIM</span>
                                ${getStatusIcon(dkim.status)}
                            </div>
                            <div class="w-px h-4 bg-gray-300 dark:bg-gray-600"></div>
                            <div class="flex items-center gap-1.5">
                                <span class="font-medium text-xs text-gray-600 dark:text-gray-400">DMARC</span>
                                ${getStatusIcon(dmarc.status)}
                            </div>
                        </div>
                    </div>
                    
                    <!-- Right: Quick Stats (max 280px) - Right aligned -->
                    <div class="flex items-center justify-end gap-4 text-xs min-w-0">
                        <div class="text-right min-w-0">
                            <p class="text-gray-500 dark:text-gray-400 text-xs">Mailboxes</p>
                            <p class="font-semibold text-gray-900 dark:text-white truncate">${domain.mboxes_in_domain}/${domain.max_num_mboxes_for_domain}</p>
                        </div>
                        <div class="text-right min-w-0">
                            <p class="text-gray-500 dark:text-gray-400 text-xs">Aliases</p>
                            <p class="font-semibold text-gray-900 dark:text-white truncate">${domain.aliases_in_domain}/${domain.max_num_aliases_for_domain}</p>
                        </div>
                        <div class="text-right min-w-0">
                            <p class="text-gray-500 dark:text-gray-400 text-xs">Storage</p>
                            <p class="font-semibold text-gray-900 dark:text-white truncate">${formatBytes(domain.bytes_total)}</p>
                        </div>
                    </div>
                </div>
                
                <!-- Mobile/Tablet Layout (below lg) -->
                <div class="flex lg:hidden items-start justify-between gap-3">
                    <!-- Left: Expand Icon + Domain Name + Status -->
                    <div class="flex items-center gap-3 min-w-0 flex-1">
                        <svg id="${domainId}-icon-mobile" class="w-5 h-5 text-gray-400 transition-transform flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                        </svg>
                        
                        <div class="min-w-0">
                            <h3 class="text-base font-bold text-gray-900 dark:text-white truncate">${escapeHtml(domain.domain_name)}</h3>
                            ${domain.active ?
            '<span class="inline-block px-2 py-0.5 text-xs font-semibold rounded-full bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-200 mt-1">Active</span>' :
            '<span class="inline-block px-2 py-0.5 text-xs font-semibold rounded-full bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200 mt-1">Inactive</span>'
        }
                        </div>
                    </div>
                    
                    <!-- Right: DNS Status (Vertical) -->
                    <div class="flex flex-col gap-0.5 text-right flex-shrink-0">
                        <div class="flex items-center justify-end gap-1.5">
                            <span class="font-medium text-xs text-gray-600 dark:text-gray-400">SPF:</span>
                            ${getStatusIcon(spf.status)}
                        </div>
                        <div class="flex items-center justify-end gap-1.5">
                            <span class="font-medium text-xs text-gray-600 dark:text-gray-400">DKIM:</span>
                            ${getStatusIcon(dkim.status)}
                        </div>
                        <div class="flex items-center justify-end gap-1.5">
                            <span class="font-medium text-xs text-gray-600 dark:text-gray-400">DMARC:</span>
                            ${getStatusIcon(dmarc.status)}
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Details Section - Hidden by default -->
            <div id="${domainId}-details" class="hidden border-t border-gray-200 dark:border-gray-700">
                <!-- Domain Stats -->
                <div class="p-6 bg-gray-50 dark:bg-gray-700/30">
                    <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
                        <div>
                            <p class="text-xs text-gray-500 dark:text-gray-400 font-medium mb-1">Mailboxes</p>
                            <p class="text-lg font-bold text-gray-900 dark:text-white">${domain.mboxes_in_domain} / ${domain.max_num_mboxes_for_domain}</p>
                            <p class="text-xs text-gray-500 dark:text-gray-400">${domain.mboxes_left} available</p>
                        </div>
                        <div>
                            <p class="text-xs text-gray-500 dark:text-gray-400 font-medium mb-1">Aliases</p>
                            <p class="text-lg font-bold text-gray-900 dark:text-white">${domain.aliases_in_domain} / ${domain.max_num_aliases_for_domain}</p>
                            <p class="text-xs text-gray-500 dark:text-gray-400">${domain.aliases_left} available</p>
                        </div>
                        <div>
                            <p class="text-xs text-gray-500 dark:text-gray-400 font-medium mb-1">Storage Used</p>
                            <p class="text-lg font-bold text-gray-900 dark:text-white">${formatBytes(domain.bytes_total)}</p>
                            ${domain.max_quota_for_domain > 0 ?
            `<p class="text-xs text-gray-500 dark:text-gray-400">${formatBytes(domain.max_quota_for_domain)} max</p>` :
            '<p class="text-xs text-gray-500 dark:text-gray-400">Unlimited</p>'
        }
                        </div>
                        <div>
                            <p class="text-xs text-gray-500 dark:text-gray-400 font-medium mb-1">Total Messages</p>
                            <p class="text-lg font-bold text-gray-900 dark:text-white">${domain.msgs_total.toLocaleString()}</p>
                        </div>
                    </div>
                    
                    <!-- Additional Domain Info -->
                    <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mt-4 pt-4 border-t border-gray-200 dark:border-gray-600">
                        <div>
                            <p class="text-xs text-gray-500 dark:text-gray-400 font-medium mb-1">Created Date</p>
                            <p class="text-sm font-semibold text-gray-900 dark:text-white">${domain.created ? formatDate(domain.created) : 'N/A'}</p>
                        </div>
                        <div>
                            <p class="text-xs text-gray-500 dark:text-gray-400 font-medium mb-1">Backup MX</p>
                            <p class="text-sm font-semibold text-gray-900 dark:text-white">${domain.backupmx == 1 ? 'Yes' : 'No'}</p>
                        </div>
                        <div>
                            <p class="text-xs text-gray-500 dark:text-gray-400 font-medium mb-1">Relay All Recipients</p>
                            <p class="text-sm font-semibold text-gray-900 dark:text-white">${domain.relay_all_recipients == 1 ? 'Yes' : 'No'}</p>
                        </div>
                        <div>
                            <p class="text-xs text-gray-500 dark:text-gray-400 font-medium mb-1">Relay Unknown Only</p>
                            <p class="text-sm font-semibold text-gray-900 dark:text-white">${domain.relay_unknown_only == 1 ? 'Yes' : 'No'}</p>
                        </div>
                    </div>
                </div>
                
                <!-- DNS Checks -->
                <div class="p-6">
                    <div class="flex items-center justify-between mb-4">
                        <h4 class="text-sm font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                            <svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                            </svg>
                            DNS Security Records
                        </h4>
                        <div class="flex items-center gap-3">
                            <div class="text-right">
                                <p class="text-xs text-gray-500 dark:text-gray-400">Last checked:</p>
                                <p class="text-xs font-medium text-gray-900 dark:text-white">
                                    ${dns.checked_at ? formatTime(dns.checked_at) : '<span class="text-gray-400">Not checked</span>'}
                                </p>
                            </div>
                            <button 
                                onclick="event.stopPropagation(); checkSingleDomainDNS('${escapeHtml(domain.domain_name)}')"
                                class="px-3 py-1.5 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded transition flex items-center gap-1.5"
                                title="Check DNS for this domain">
                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                                </svg>
                                Check
                            </button>
                        </div>
                    </div>
                    <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
                        ${renderDNSCheck('SPF', spf)}
                        ${renderDNSCheck('DKIM', dkim)}
                        ${renderDNSCheck('DMARC', dmarc)}
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Toggle domain details accordion
function toggleDomainDetails(domainId) {
    const details = document.getElementById(`${domainId}-details`);
    const iconDesktop = document.getElementById(`${domainId}-icon-desktop`);
    const iconMobile = document.getElementById(`${domainId}-icon-mobile`);

    if (details.classList.contains('hidden')) {
        details.classList.remove('hidden');
        if (iconDesktop) iconDesktop.style.transform = 'rotate(90deg)';
        if (iconMobile) iconMobile.style.transform = 'rotate(90deg)';
    } else {
        details.classList.add('hidden');
        if (iconDesktop) iconDesktop.style.transform = 'rotate(0deg)';
        if (iconMobile) iconMobile.style.transform = 'rotate(0deg)';
    }
}

function renderDNSCheck(type, check) {
    const statusColors = {
        'success': 'border-green-500 bg-green-50 dark:bg-green-900/20',
        'warning': 'border-amber-500 bg-amber-50 dark:bg-amber-900/20',
        'error': 'border-red-500 bg-red-50 dark:bg-red-900/20',
        'unknown': 'border-gray-300 bg-gray-50 dark:bg-gray-800'
    };

    const statusTextColors = {
        'success': 'text-green-700 dark:text-green-400',
        'warning': 'text-amber-700 dark:text-amber-400',
        'error': 'text-red-700 dark:text-red-400',
        'unknown': 'text-gray-600 dark:text-gray-400'
    };

    const statusIcons = {
        'success': '<svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>',
        'warning': '<svg class="w-5 h-5 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>',
        'error': '<svg class="w-5 h-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>',
        'unknown': '<svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>'
    };

    const status = check.status || 'unknown';

    return `
        <div class="border ${statusColors[status]} rounded-lg p-4">
            <div class="flex items-start justify-between mb-2">
                <h5 class="text-sm font-semibold text-gray-900 dark:text-white">${type}</h5>
                ${statusIcons[status]}
            </div>
            <p class="text-sm ${statusTextColors[status]} font-medium mb-2">${escapeHtml(check.message || 'No information')}</p>
            
            ${check.record || check.actual_record ? `
                <details class="mt-3">
                    <summary class="text-xs text-gray-600 dark:text-gray-400 cursor-pointer hover:text-gray-900 dark:hover:text-gray-200 font-medium">
                        View Record
                    </summary>
                    <div class="mt-2 p-2 bg-white dark:bg-gray-900 rounded border border-gray-200 dark:border-gray-700">
                        ${check.dkim_domain ? `
                            <p class="text-xs text-gray-500 dark:text-gray-400 mb-2">
                                <span class="font-medium">Record Name:</span> 
                                <span class="font-mono text-gray-700 dark:text-gray-300">${escapeHtml(check.dkim_domain)}</span>
                            </p>
                        ` : ''}
                        <code class="text-xs text-gray-700 dark:text-gray-300 break-all block leading-relaxed">${escapeHtml(check.record || check.actual_record)}</code>
                    </div>
                </details>
            ` : ''}
            
            ${check.warnings && check.warnings.length > 0 ? `
                <div class="mt-3 space-y-1">
                    ${check.warnings.map(warning => `
                        <div class="flex items-start gap-2 text-xs ${statusTextColors['warning']}">
                            <svg class="w-3 h-3 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                            </svg>
                            <span>${escapeHtml(warning)}</span>
                        </div>
                    `).join('')}
                </div>
            ` : ''}
            
            ${check.info && check.info.length > 0 ? `
                <div class="mt-3 space-y-1">
                    ${check.info.map(info => `
                        <div class="text-xs text-gray-600 dark:text-gray-400 px-2 py-1 bg-gray-50 dark:bg-gray-800/50 rounded">
                            ${escapeHtml(info)}
                        </div>
                    `).join('')}
                </div>
            ` : ''}
            
            ${check.status === 'error' && check.expected_record ? `
                <details class="mt-3">
                    <summary class="text-xs text-gray-600 dark:text-gray-400 cursor-pointer hover:text-gray-900 dark:hover:text-gray-200 font-medium">
                        Expected Value
                    </summary>
                    <div class="mt-2 p-2 bg-white dark:bg-gray-900 rounded border border-gray-200 dark:border-gray-700">
                        <code class="text-xs text-gray-700 dark:text-gray-300 break-all block leading-relaxed">${escapeHtml(check.expected_record)}</code>
                    </div>
                </details>
            ` : ''}
        </div>
    `;
}

let dnsCheckInProgress = false;

async function checkAllDomainsDNS() {
    if (dnsCheckInProgress) {
        showToast('DNS check already in progress', 'warning');
        return;
    }

    const button = document.getElementById('check-all-dns-btn');
    if (button) {
        button.disabled = true;
        button.innerHTML = '<svg class="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> Checking...';
    }

    dnsCheckInProgress = true;

    try {
        const response = await authenticatedFetch('/api/domains/check-all-dns', {
            method: 'POST'
        });

        const result = await response.json();

        if (result.status === 'success') {
            showToast(`✓ Checked ${result.domains_checked} domains`, 'success');
            setTimeout(() => loadDomains(), 1000);
        } else {
            showToast('DNS check failed', 'error');
        }
    } catch (error) {
        console.error('Failed:', error);
        showToast('Failed to check DNS', 'error');
    } finally {
        dnsCheckInProgress = false;

        if (button) {
            button.disabled = false;
            button.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg> Check Now';
        }
    }
}


async function checkSingleDomainDNS(domainName) {
    if (dnsCheckInProgress) {
        showToast('DNS check already in progress', 'warning');
        return;
    }

    dnsCheckInProgress = true;
    showToast(`Checking DNS for ${domainName}...`, 'info');

    // Find and update the button
    const domainId = `domain-${domainName.replace(/\./g, '-')}`;
    const detailsDiv = document.getElementById(`${domainId}-details`);

    try {
        const response = await authenticatedFetch(`/api/domains/${encodeURIComponent(domainName)}/check-dns`, {
            method: 'POST'
        });

        const result = await response.json();

        if (result.status === 'success') {
            showToast(`✓ DNS checked for ${domainName}`, 'success');

            // Update only this domain's DNS section
            if (detailsDiv) {
                const dnsSection = detailsDiv.querySelector('.p-6:last-child');
                if (dnsSection) {
                    // Get updated domain data
                    const domainsResponse = await authenticatedFetch('/api/domains/all');
                    const domainsData = await domainsResponse.json();
                    const updatedDomain = domainsData.domains.find(d => d.domain_name === domainName);

                    if (updatedDomain) {
                        // Re-render just the DNS section
                        const dns = updatedDomain.dns_checks || {};
                        const spf = dns.spf || { status: 'unknown', message: 'Not checked' };
                        const dkim = dns.dkim || { status: 'unknown', message: 'Not checked' };
                        const dmarc = dns.dmarc || { status: 'unknown', message: 'Not checked' };

                        dnsSection.innerHTML = `
                            <div class="flex items-center justify-between mb-4">
                                <h4 class="text-sm font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                                    <svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                                    </svg>
                                    DNS Security Records
                                </h4>
                                <div class="flex items-center gap-3">
                                    <div class="text-right">
                                        <p class="text-xs text-gray-500 dark:text-gray-400">Last checked:</p>
                                        <p class="text-xs font-medium text-gray-900 dark:text-white">
                                            ${dns.checked_at ? formatTime(dns.checked_at) : '<span class="text-gray-400">Not checked</span>'}
                                        </p>
                                    </div>
                                    <button 
                                        data-domain="${escapeHtml(updatedDomain.domain_name)}"
                                        onclick="event.stopPropagation(); checkSingleDomainDNS(this.dataset.domain)"
                                        class="px-3 py-1.5 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded transition flex items-center gap-1.5"
                                        title="Check DNS for this domain">
                                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                                        </svg>
                                        Check
                                    </button>
                                </div>
                            </div>
                            <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
                                ${renderDNSCheck('SPF', spf)}
                                ${renderDNSCheck('DKIM', dkim)}
                                ${renderDNSCheck('DMARC', dmarc)}
                            </div>
                        `;

                        // Update inline badges in summary row
                        const summaryRow = document.querySelector(`[onclick*="toggleDomainDetails('${domainId}')"]`);
                        if (summaryRow) {
                            const getStatusIcon = (status) => {
                                if (status === 'success') return '<span class="text-green-500" title="OK">✓</span>';
                                if (status === 'warning') return '<span class="text-amber-500" title="Warning">⚠</span>';
                                if (status === 'error') return '<span class="text-red-500" title="Error">✗</span>';
                                return '<span class="text-gray-400" title="Unknown">?</span>';
                            };

                            const badgesContainer = summaryRow.querySelector('.flex.items-center.gap-2.text-base');
                            if (badgesContainer) {
                                badgesContainer.innerHTML = `
                                    <span class="flex items-center gap-1">
                                        <span class="text-xs text-gray-500 dark:text-gray-400">SPF:</span>
                                        ${getStatusIcon(spf.status)}
                                    </span>
                                    <span class="flex items-center gap-1">
                                        <span class="text-xs text-gray-500 dark:text-gray-400">DKIM:</span>
                                        ${getStatusIcon(dkim.status)}
                                    </span>
                                    <span class="flex items-center gap-1">
                                        <span class="text-xs text-gray-500 dark:text-gray-400">DMARC:</span>
                                        ${getStatusIcon(dmarc.status)}
                                    </span>
                                `;
                            }
                        }
                    }
                }
            }
        } else {
            showToast(`Failed to check DNS for ${domainName}`, 'error');
        }
    } catch (error) {
        console.error('Failed:', error);
        showToast('Failed to check DNS', 'error');
    } finally {
        dnsCheckInProgress = false;
    }
}


function formatBytes(bytes) {
    if (bytes === 0 || bytes === '0') return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// =============================================================================
// SETTINGS PAGE
// =============================================================================

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
            <div class="text-center py-12">
                <svg class="w-16 h-16 mx-auto text-red-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <p class="text-red-500">Failed to load settings</p>
                <p class="text-sm text-gray-500 dark:text-gray-400 mt-2">${error.message}</p>
            </div>
        `;
    }
}

function updateVersionInfoUI(versionInfo) {
    // Find the container with Latest Version by searching for the label
    const allContainers = document.querySelectorAll('#settings-content .p-4.bg-gray-50');
    let latestVersionContainer = null;

    for (const container of allContainers) {
        const label = container.querySelector('.text-xs.uppercase');
        if (label && label.textContent.trim() === 'LATEST VERSION') {
            latestVersionContainer = container;
            break;
        }
    }

    if (!latestVersionContainer) {
        return;
    }

    // Update version text
    const versionTextEl = latestVersionContainer.querySelector('.text-lg.font-semibold');
    if (versionTextEl) {
        versionTextEl.textContent = versionInfo.latest_version ? `v${versionInfo.latest_version}` : 'Checking...';
    }

    // Update last_checked date
    const badgeContainer = latestVersionContainer.querySelector('.flex.items-center');
    if (badgeContainer) {
        // Find or create last_checked span
        let lastCheckedSpan = Array.from(badgeContainer.querySelectorAll('span.text-xs.text-gray-500, span.text-xs.text-gray-400'))
            .find(span => span.textContent.includes('Last checked'));

        if (versionInfo.last_checked) {
            if (!lastCheckedSpan) {
                lastCheckedSpan = document.createElement('span');
                lastCheckedSpan.className = 'text-xs text-gray-500 dark:text-gray-400';
                const button = badgeContainer.querySelector('button');
                if (button) {
                    badgeContainer.insertBefore(lastCheckedSpan, button);
                } else {
                    badgeContainer.appendChild(lastCheckedSpan);
                }
            }
            lastCheckedSpan.textContent = `(Last checked: ${formatDate(versionInfo.last_checked)})`;
        } else if (lastCheckedSpan) {
            lastCheckedSpan.remove();
        }

        // Remove existing badges (but keep the button and last_checked span)
        const existingBadges = Array.from(badgeContainer.querySelectorAll('span.px-2.py-1.rounded.text-xs'));
        existingBadges.forEach(badge => {
            badge.remove();
        });

        // Add new badge if needed
        if (versionInfo.update_available) {
            const badge = document.createElement('span');
            badge.className = 'px-2 py-1 bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300 rounded text-xs font-medium';
            badge.textContent = 'Update Available';
            const button = badgeContainer.querySelector('button');
            if (button) {
                badgeContainer.insertBefore(badge, button);
            } else {
                badgeContainer.appendChild(badge);
            }
        } else if (versionInfo.latest_version && !versionInfo.update_available) {
            const badge = document.createElement('span');
            badge.className = 'px-2 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 rounded text-xs font-medium';
            badge.textContent = 'Up to Date';
            const button = badgeContainer.querySelector('button');
            if (button) {
                badgeContainer.insertBefore(badge, button);
            } else {
                badgeContainer.appendChild(badge);
            }
        }
    }

    // Update or create update message
    const versionSection = latestVersionContainer.closest('.bg-white, .dark\\:bg-gray-800');
    if (versionSection) {
        // Remove existing update message
        const existingMessages = versionSection.querySelectorAll('.bg-green-50, .dark\\:bg-green-900\\/20');
        existingMessages.forEach(msg => {
            if (msg.textContent.includes('Update available')) {
                msg.remove();
            }
        });

        // Add new update message if update is available
        if (versionInfo.update_available) {
            const gridContainer = versionSection.querySelector('.grid.grid-cols-1');
            if (gridContainer && gridContainer.parentNode) {
                const messageDiv = document.createElement('div');
                messageDiv.className = 'mt-4 p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg';
                messageDiv.innerHTML = `
                    <p class="text-sm text-green-800 dark:text-green-300">
                        <strong>Update available!</strong> A new version (v${versionInfo.latest_version}) is available on GitHub.
                    </p>
                    ${versionInfo.changelog ? `
                        <div class="mt-3 border border-green-200 dark:border-green-800 rounded p-3 bg-white dark:bg-gray-800">
                            <p class="text-xs font-semibold text-green-800 dark:text-green-300 mb-2">Changelog:</p>
                            <div class="update-changelog-content markdown-body" style="max-height: 16rem; overflow-y: auto; overflow-x: hidden; display: block;"></div>
                        </div>
                    ` : ''}
                    <a href="https://github.com/ShlomiPorush/mailcow-logs-viewer/releases/latest" target="_blank" rel="noopener noreferrer" class="text-sm text-green-600 dark:text-green-400 hover:underline mt-2 inline-block">
                        View release notes →
                    </a>
                `;
                gridContainer.parentNode.insertBefore(messageDiv, gridContainer.nextSibling);

                // Render markdown in changelog if marked.js is available
                // Do this immediately after inserting to DOM
                if (typeof marked !== 'undefined' && versionInfo.changelog) {
                    marked.setOptions({
                        breaks: true,
                        gfm: true
                    });
                    const changelogEl = messageDiv.querySelector('.update-changelog-content');
                    if (changelogEl && versionInfo.changelog) {
                        // Use the full changelog text directly
                        changelogEl.innerHTML = marked.parse(versionInfo.changelog);
                    }
                }
            }
        }
    }
}

function renderSettings(content, data) {
    const config = data.configuration || {};
    const appVersion = data.app_version || 'Unknown';
    const versionInfo = data.version_info || {};

    content.innerHTML = `
        <!-- Version Information Section -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 mb-6">
            <div class="p-4 border-b border-gray-200 dark:border-gray-700">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                    <svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path>
                    </svg>
                    Version Information
                </h3>
            </div>
            <div class="p-4">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div class="p-4 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-2">Current Version</p>
                        <div class="flex items-center gap-2">
                            <p id="current-version-text" class="text-lg font-semibold text-gray-900 dark:text-white cursor-pointer hover:text-blue-600 dark:hover:text-blue-400 transition-colors" title="Click to view changelog">v${appVersion}</p>
                            <svg class="w-4 h-4 text-blue-500 dark:text-blue-400 cursor-pointer" fill="none" stroke="currentColor" viewBox="0 0 24 24" title="Click to view changelog">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                            </svg>
                        </div>
                    </div>
                    <div class="p-4 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-2">Latest Version</p>
                        <div class="flex items-center gap-2 flex-wrap">
                            <p class="text-lg font-semibold text-gray-900 dark:text-white">${versionInfo.latest_version ? `v${versionInfo.latest_version}` : 'Checking...'}</p>
                            ${versionInfo.last_checked ? `
                                <span class="text-xs text-gray-500 dark:text-gray-400">
                                    (Last checked: ${formatDate(versionInfo.last_checked)})
                                </span>
                            ` : ''}
                            ${versionInfo.update_available ? `
                                <span class="px-2 py-1 bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300 rounded text-xs font-medium">
                                    Update Available
                                </span>
                            ` : versionInfo.latest_version && !versionInfo.update_available ? `
                                <span class="px-2 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 rounded text-xs font-medium">
                                    Up to Date
                                </span>
                            ` : ''}
                            <button id="check-version-btn" class="px-3 py-1.5 bg-blue-500 hover:bg-blue-600 text-white rounded text-xs font-medium transition-colors duration-200 flex items-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed">
                                <svg id="check-version-icon" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                                </svg>
                                <span id="check-version-text">Check Now</span>
                            </button>
                        </div>
                    </div>
                </div>
                ${versionInfo.update_available ? `
                    <div class="mt-4 p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
                        <p class="text-sm text-green-800 dark:text-green-300">
                            <strong>Update available!</strong> A new version (v${versionInfo.latest_version}) is available on GitHub.
                        </p>
                        ${versionInfo.changelog ? `
                            <div class="mt-3 border border-green-200 dark:border-green-800 rounded p-3 bg-white dark:bg-gray-800">
                                <p class="text-xs font-semibold text-green-800 dark:text-green-300 mb-2">Changelog:</p>
                                <div class="update-changelog-content markdown-body" style="max-height: 16rem; overflow-y: auto; overflow-x: hidden; display: block;"></div>
                            </div>
                        ` : ''}
                        <a href="https://github.com/ShlomiPorush/mailcow-logs-viewer/releases/latest" target="_blank" rel="noopener noreferrer" class="text-sm text-green-600 dark:text-green-400 hover:underline mt-2 inline-block">
                            View release notes →
                        </a>
                    </div>
                ` : ''}
            </div>
        </div>

        <!-- Configuration Section -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
            <div class="p-4 border-b border-gray-200 dark:border-gray-700">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                    <svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path>
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                    </svg>
                    Configuration
                </h3>
            </div>
            <div class="p-4">
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    <div class="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">mailcow URL</p>
                        <p class="text-sm text-gray-900 dark:text-white mt-1 font-mono break-all">${escapeHtml(config.mailcow_url || 'N/A')}</p>
                    </div>
                    <div class="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Server IP</p>
                        <p class="text-sm text-gray-900 dark:text-white mt-1 font-mono">
                            ${config.server_ip ?
            `<span class="inline-flex items-center gap-1.5">
                                    <svg class="w-3.5 h-3.5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                    </svg>
                                    ${escapeHtml(config.server_ip)}
                                </span>`
            : '<span class="text-gray-400">Not available</span>'
        }
                        </p>
                    </div>
                    <div class="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Authentication</p>
                        <p class="text-sm text-gray-900 dark:text-white mt-1">
                            ${config.auth_enabled ?
            `<span class="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400">
                                    <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
                                    </svg>
                                    Enabled
                                </span>` :
            `<span class="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-400">
                                    Disabled
                                </span>`
        }
                        </p>
                        ${config.auth_enabled && config.auth_username ?
            `<p class="text-xs text-gray-500 dark:text-gray-400 mt-1">Username: ${escapeHtml(config.auth_username)}</p>` :
            ''
        }
                    </div>
                    <div class="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg ${config.local_domains && config.local_domains.length > 0 ? 'col-span-1 md:col-span-2 lg:col-span-3' : ''}">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-2">
                            Local Domains
                            ${config.local_domains && config.local_domains.length > 0 ?
            `<span class="ml-1 text-gray-400 dark:text-gray-500 font-normal">(${config.local_domains.length})</span>` :
            ''
        }
                        </p>
                        ${config.local_domains && config.local_domains.length > 0 ?
            `<div class="mt-2 max-h-64 overflow-y-auto">
                                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                                    ${config.local_domains.map(domain => `
                                        <div class="text-sm text-gray-900 dark:text-white font-mono px-3 py-1.5 bg-white dark:bg-gray-800 rounded border border-gray-200 dark:border-gray-600 truncate" title="${escapeHtml(domain)}">
                                            ${escapeHtml(domain)}
                                        </div>
                                    `).join('')}
                                </div>
                            </div>` :
            '<p class="text-sm text-gray-500 dark:text-gray-400 mt-1">N/A</p>'
        }
                    </div>
                    <div class="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Fetch Interval</p>
                        <p class="text-sm text-gray-900 dark:text-white mt-1">${config.fetch_interval || 0} seconds</p>
                    </div>
                    <div class="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Fetch Count (Postfix)</p>
                        <p class="text-sm text-gray-900 dark:text-white mt-1">${config.fetch_count_postfix || config.fetch_count || 0} per request</p>
                    </div>
                    <div class="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Fetch Count (Rspamd)</p>
                        <p class="text-sm text-gray-900 dark:text-white mt-1">${config.fetch_count_rspamd || config.fetch_count || 0} per request</p>
                    </div>
                    <div class="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Fetch Count (Netfilter)</p>
                        <p class="text-sm text-gray-900 dark:text-white mt-1">${config.fetch_count_netfilter || config.fetch_count || 0} per request</p>
                    </div>
                    <div class="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Retention</p>
                        <p class="text-sm text-gray-900 dark:text-white mt-1">${config.retention_days || 0} days</p>
                    </div>
                    <div class="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Max Correlation Age</p>
                        <p class="text-sm text-gray-900 dark:text-white mt-1">${config.max_correlation_age_minutes || 10} minutes</p>
                    </div>
                    <div class="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Correlation Check</p>
                        <p class="text-sm text-gray-900 dark:text-white mt-1">${config.correlation_check_interval || 120} seconds</p>
                    </div>
                    <div class="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Timezone</p>
                        <p class="text-sm text-gray-900 dark:text-white mt-1">${escapeHtml(config.timezone || 'N/A')}</p>
                    </div>
                    <div class="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Log Level</p>
                        <p class="text-sm text-gray-900 dark:text-white mt-1">${config.log_level || 'INFO'}</p>
                    </div>
                    <div class="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Blacklist</p>
                        <p class="text-sm text-gray-900 dark:text-white mt-1">${config.blacklist_enabled ? `Enabled (${config.blacklist_count} emails)` : 'Disabled'}</p>
                    </div>
                    <div class="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Scheduler Workers</p>
                        <p class="text-sm text-gray-900 dark:text-white mt-1">${config.scheduler_workers || 4}</p>
                    </div>
                    <div class="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">MaxMind Status</p>
                        <p class="text-sm text-gray-900 dark:text-white mt-1">
                            ${renderMaxMindStatus(data.configuration.maxmind_status)}
                        </p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Global SMTP Configuration -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
            <div class="p-4 border-b border-gray-200 dark:border-gray-700">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                    <svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
                    </svg>
                    Global SMTP Configuration
                </h3>
            </div>
            <div class="p-4">
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    <div class="p-4 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-2">SMTP Enabled</p>
                        <div class="flex items-center gap-2 flex-wrap">
                            ${data.smtp_configuration?.enabled ?
            `<span class="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400">
                                    <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
                                    </svg>
                                    Enabled
                                </span>` :
            `<span class="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-400">Disabled</span>`
        }
                            <button onclick="testSmtpConnection()" class="px-3 py-1.5 bg-blue-500 hover:bg-blue-600 text-white rounded text-xs font-medium transition-colors duration-200 flex items-center gap-1.5">
                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                </svg>
                                <span>Test SMTP</span>
                            </button>
                        </div>
                    </div>
                    ${data.smtp_configuration?.enabled ? `
                    <div class="p-4 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-2">Server</p>
                        <p class="text-sm text-gray-900 dark:text-white font-mono">${data.smtp_configuration.host}:${data.smtp_configuration.port}</p>
                    </div>
                    <div class="p-4 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-2">Admin Email</p>
                        <p class="text-sm text-gray-900 dark:text-white font-mono">${data.smtp_configuration.admin_email || 'N/A'}</p>
                    </div>
                    ` : ''}
                </div>
            </div>
        </div>

        <!-- DMARC Management -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
            <div class="p-4 border-b border-gray-200 dark:border-gray-700">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                    <svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                    </svg>
                    DMARC Management
                </h3>
            </div>
            <div class="p-4">
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    <div class="p-4 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-2">IMAP Auto-Import</p>
                        <div class="flex items-center gap-2 flex-wrap">
                            ${data.dmarc_configuration?.imap_sync_enabled ?
            `<span class="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400">
                                    <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
                                    </svg>
                                    Enabled
                                </span>` :
            `<span class="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-400">Disabled</span>`
        }
                            <button onclick="testImapConnection()" class="px-3 py-1.5 bg-blue-500 hover:bg-blue-600 text-white rounded text-xs font-medium transition-colors duration-200 flex items-center gap-1.5">
                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                </svg>
                                <span>Test IMAP</span>
                            </button>
                        </div>
                    </div>
                    <div class="p-4 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-2">Manual Upload</p>
                        <p class="text-sm text-gray-900 dark:text-white">
                            ${data.dmarc_configuration?.manual_upload_enabled ?
            `<span class="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400">
                                    <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
                                    </svg>
                                    Enabled
                                </span>` :
            `<span class="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400">Disabled</span>`
        }
                        </p>
                    </div>
                    ${data.dmarc_configuration?.imap_sync_enabled ? `
                    <div class="p-4 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-2">IMAP Server</p>
                        <p class="text-sm text-gray-900 dark:text-white font-mono">${data.dmarc_configuration.imap_host || 'N/A'}</p>
                    </div>
                    ` : ''}
                </div>
            </div>
        </div>
    `;

    // Add event listener for version number click (changelog popup)
    const currentVersionText = document.getElementById('current-version-text');
    const currentVersionIcon = currentVersionText?.parentElement?.querySelector('svg');

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
    if (currentVersionIcon) {
        currentVersionIcon.onclick = loadCurrentVersionChangelog;
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
                el.innerHTML = marked.parse(changelogText);
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
                btn.classList.remove('bg-blue-500', 'hover:bg-blue-600');
                btn.classList.add('bg-green-500', 'hover:bg-green-600');
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
                    btn.classList.remove('bg-green-500', 'hover:bg-green-600');
                    btn.classList.add('bg-blue-500', 'hover:bg-blue-600');
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
                btn.classList.remove('bg-blue-500', 'hover:bg-blue-600');
                btn.classList.add('bg-red-500', 'hover:bg-red-600');
                if (text) {
                    text.textContent = 'Error';
                }
                if (icon) {
                    icon.classList.remove('animate-spin');
                }

                // Reset button after 2 seconds
                setTimeout(() => {
                    btn.classList.remove('bg-red-500', 'hover:bg-red-600');
                    btn.classList.add('bg-blue-500', 'hover:bg-blue-600');
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
}

function renderMaxMindStatus(status) {
    if (!status || !status.configured) {
        return `
            <span class="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-400">
                Not configured
            </span>
        `;
    }

    if (status.valid) {
        return `
            <span class="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400">
                <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
                </svg>
                Configured
            </span>
        `;
    }

    return `
        <span class="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400">
            <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path>
            </svg>
            ${escapeHtml(status.error || 'Invalid')}
        </span>
    `;
}

function renderImportCard(title, data, color) {
    if (!data) {
        return `<div class="p-4 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
            <p class="font-semibold text-gray-900 dark:text-white">${title}</p>
            <p class="text-sm text-gray-500 dark:text-gray-400 mt-2">No data</p>
        </div>`;
    }

    const colorClasses = {
        blue: 'border-blue-200 dark:border-blue-800 bg-blue-50 dark:bg-blue-900/20',
        purple: 'border-purple-200 dark:border-purple-800 bg-purple-50 dark:bg-purple-900/20',
        red: 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20'
    };

    return `
        <div class="p-4 border ${colorClasses[color]} rounded-lg">
            <p class="font-semibold text-gray-900 dark:text-white mb-3">${title}</p>
            <div class="space-y-2 text-sm">
                <div>
                    <p class="text-xs text-gray-500 dark:text-gray-400">Last Fetch Run</p>
                    <p class="text-gray-900 dark:text-white font-medium">${data.last_fetch_run ? formatTime(data.last_fetch_run) : 'Never'}</p>
                </div>
                <div>
                    <p class="text-xs text-gray-500 dark:text-gray-400">Last Import</p>
                    <p class="text-gray-900 dark:text-white">${data.last_import ? formatTime(data.last_import) : 'Never'}</p>
                </div>
                <div>
                    <p class="text-xs text-gray-500 dark:text-gray-400">Total Entries</p>
                    <p class="text-gray-900 dark:text-white font-semibold">${(data.total_entries || 0).toLocaleString()}</p>
                </div>
                ${data.oldest_entry ? `
                    <div>
                        <p class="text-xs text-gray-500 dark:text-gray-400">Oldest Entry</p>
                        <p class="text-gray-900 dark:text-white">${formatTime(data.oldest_entry)}</p>
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

function renderJobCard(name, jobKey, job) {
    if (!job) {
        return '';
    }

    const isRunning = job.status === 'running';
    const isDisabled = job.status === 'disabled' || job.enabled === false;

    let statusBadge = '';

    switch (job.status) {
        case 'running':
            statusBadge = '<span class="px-2 py-1 text-xs font-medium rounded bg-blue-500 text-white">running</span>';
            break;
        case 'success':
            statusBadge = '<span class="px-2 py-1 text-xs font-medium rounded bg-green-600 dark:bg-green-500 text-white">success</span>';
            break;
        case 'failed':
            statusBadge = '<span class="px-2 py-1 text-xs font-medium rounded bg-red-600 dark:bg-red-500 text-white">failed</span>';
            break;
        case 'scheduled':
            statusBadge = '<span class="px-2 py-1 text-xs font-medium rounded bg-purple-600 dark:bg-purple-500 text-white">scheduled</span>';
            break;
        default:
            statusBadge = '<span class="px-2 py-1 text-xs font-medium rounded bg-gray-500 text-white">idle</span>';
    }

    return `
        <div class="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
            <div class="flex items-start justify-between gap-3 mb-2">
                <div class="flex-1 min-w-0">
                    <h4 class="font-semibold text-gray-900 dark:text-white text-sm">${name}</h4>
                    <p class="text-xs text-gray-500 dark:text-gray-400 mt-0.5">${job.description || ''}</p>
                </div>
                <div class="flex flex-col items-end gap-1.5">
                    ${statusBadge}
                    ${!isDisabled ? `
                        <button 
                            onclick="triggerBackgroundJob('${jobKey}', this, '${name.replace(/'/g, "\\'")}')" 
                            class="px-2 py-1 text-xs font-medium rounded transition-colors flex items-center gap-1 ${isRunning
                ? 'bg-gray-200 dark:bg-gray-600 text-gray-400 dark:text-gray-500 cursor-not-allowed'
                : 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 hover:bg-blue-200 dark:hover:bg-blue-900/50'}"
                            ${isRunning ? 'disabled' : ''}
                            title="${isRunning ? 'Job is running' : 'Run this job now'}">
                            ${isRunning ? '<span class="inline-block animate-spin w-3 h-3 border-2 border-current border-t-transparent rounded-full"></span>' : '<span class="text-[10px]">▶</span>'}
                            Run
                        </button>
                    ` : ''}
                </div>
            </div>
            
            <div class="flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-600 dark:text-gray-400">
                ${job.interval ? `<span>⏱ ${job.interval}</span>` : ''}
                ${job.schedule ? `<span>📅 ${job.schedule}</span>` : ''}
                ${job.retention ? `<span>🗂 ${job.retention}</span>` : ''}
                ${job.max_age ? `<span>⏳ Max: ${job.max_age}</span>` : ''}
                ${job.expire_after ? `<span>⏱ Expire: ${job.expire_after}</span>` : ''}
                ${job.pending_items !== undefined ? `<span class="font-medium text-yellow-600 dark:text-yellow-400">📋 Pending: ${job.pending_items}</span>` : ''}
            </div>
            
            ${job.last_run ? `
                <div class="mt-2 pt-2 border-t border-gray-200 dark:border-gray-600">
                    <p class="text-xs text-gray-500 dark:text-gray-400">
                        Last run: <span class="text-gray-900 dark:text-white font-medium">${formatTime(job.last_run)}</span>
                    </p>
                </div>
            ` : ''}
            
            ${job.error ? `
                <div class="mt-2 p-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded">
                    <p class="text-xs text-red-700 dark:text-red-300 font-mono break-all">${escapeHtml(job.error)}</p>
                </div>
            ` : ''}
        </div>
    `;
}

function showToast(message, type = 'info') {
    // Remove existing toast if any
    const existingToast = document.getElementById('toast-notification');
    if (existingToast) {
        existingToast.remove();
    }

    const colors = {
        'success': 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-200 border-green-500',
        'error': 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-200 border-red-500',
        'warning': 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-200 border-yellow-500',
        'info': 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-200 border-blue-500'
    };

    const icons = {
        'success': '✓',
        'error': '✗',
        'warning': '⚠',
        'info': 'ℹ'
    };

    const toast = document.createElement('div');
    toast.id = 'toast-notification';
    toast.className = `fixed bottom-4 right-4 z-50 ${colors[type]} border-l-4 p-4 rounded shadow-lg max-w-md animate-slide-in`;
    toast.innerHTML = `
        <div class="flex items-start gap-3">
            <span class="text-xl font-bold flex-shrink-0">${icons[type]}</span>
            <p class="text-sm flex-1">${message}</p>
            <button onclick="this.parentElement.parentElement.remove()" class="text-lg font-bold hover:opacity-70 flex-shrink-0">×</button>
        </div>
    `;

    document.body.appendChild(toast);

    // Auto-remove after 4 seconds
    setTimeout(() => {
        if (toast.parentElement) {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.3s';
            setTimeout(() => toast.remove(), 300);
        }
    }, 4000);
}

// =============================================================================
// DMARC PAGE
// =============================================================================

// DMARC Navigation State
let dmarcState = {
    currentView: 'domains',
    currentDomain: null,
    currentSubTab: 'reports',
    currentReportDate: null,
    currentSourceIp: null,
    chartInstance: null,
    // Breadcrumb tracking: { label: string, action: function or null }
    breadcrumb: [],
    detailType: null // 'report', 'source', 'tls'
};

// Update breadcrumb display
function updateDmarcBreadcrumb() {
    const container = document.getElementById('dmarc-breadcrumb');
    if (!container) return;

    if (dmarcState.breadcrumb.length === 0) {
        container.innerHTML = '';
        container.classList.add('hidden');
        return;
    }

    container.classList.remove('hidden');
    // Display as horizontal flex row
    container.innerHTML = `<div class="flex items-center flex-wrap gap-1 text-sm">
        ${dmarcState.breadcrumb.map((item, idx) => {
        const isLast = idx === dmarcState.breadcrumb.length - 1;
        const separator = idx > 0 ? '<svg class="w-3 h-3 text-gray-400 mx-1 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>' : '';

        if (isLast) {
            return `${separator}<span class="text-gray-600 dark:text-gray-300">${escapeHtml(item.label)}</span>`;
        } else {
            return `${separator}<button onclick="${item.action}" class="text-blue-600 dark:text-blue-400 hover:underline">${escapeHtml(item.label)}</button>`;
        }
    }).join('')}
    </div>`;
}

// Set breadcrumb for different views (without "DMARC Reports" since title is static)
function setDmarcBreadcrumb(type, data = {}) {
    switch (type) {
        case 'domains':
            // On domains list, no breadcrumb needed (we're at root)
            dmarcState.breadcrumb = [];
            break;
        case 'domain':
            // Just show domain name
            dmarcState.breadcrumb = [
                { label: data.domain, action: null }
            ];
            break;
        case 'reportDetails':
            dmarcState.breadcrumb = [
                { label: data.domain, action: `loadDomainOverview('${data.domain}')` },
                { label: 'Daily Reports', action: `loadDomainOverview('${data.domain}'); setTimeout(() => dmarcSwitchSubTab('reports'), 100)` },
                { label: data.date, action: null }
            ];
            break;
        case 'sourceDetails':
            dmarcState.breadcrumb = [
                { label: data.domain, action: `loadDomainOverview('${data.domain}')` },
                { label: 'Source IPs', action: `loadDomainOverview('${data.domain}'); setTimeout(() => dmarcSwitchSubTab('sources'), 100)` },
                { label: data.ip, action: null }
            ];
            break;
        case 'tlsDetails':
            dmarcState.breadcrumb = [
                { label: data.domain, action: `loadDomainOverview('${data.domain}')` },
                { label: 'TLS Reports', action: `loadDomainOverview('${data.domain}'); setTimeout(() => dmarcSwitchSubTab('tls'), 100)` },
                { label: data.date, action: null }
            ];
            break;
    }
    updateDmarcBreadcrumb();
}

async function loadDmarcSettings() {
    try {
        const response = await authenticatedFetch('/api/settings/info');
        if (!response.ok) {
            dmarcConfiguration = null;
            return;
        }

        const data = await response.json();
        dmarcConfiguration = data.dmarc_configuration || {};
        console.log('DMARC settings loaded:', dmarcConfiguration);

    } catch (error) {
        console.error('Error loading DMARC settings:', error);
        dmarcConfiguration = null;
    }
}

async function loadDmarc() {
    console.log('Loading DMARC tab...');
    dmarcState.currentView = 'domains';
    dmarcState.currentDomain = null;
    dmarcState.detailType = null;
    dmarcState.currentReportDate = null;
    dmarcState.currentSourceIp = null;

    // Destroy chart if exists
    if (dmarcState.chartInstance) {
        dmarcState.chartInstance.destroy();
        dmarcState.chartInstance = null;
    }

    // Hide all sub-views and show main domains view
    document.getElementById('dmarc-overview-view').classList.add('hidden');
    document.getElementById('dmarc-report-details-view').classList.add('hidden');
    document.getElementById('dmarc-source-details-view').classList.add('hidden');
    document.getElementById('dmarc-domains-view').classList.remove('hidden');
    document.getElementById('dmarc-page-title').textContent = 'DMARC Reports';

    // Update breadcrumb
    setDmarcBreadcrumb('domains');

    await loadDmarcSettings();
    await loadDmarcImapStatus();
    await loadDmarcDomains();
}

/**
 * Handle DMARC route based on URL params
 * Called from switchTab when navigating to DMARC
 * @param {Object} params - Route params { domain, type, id }
 */
async function handleDmarcRoute(params = {}) {
    console.log('handleDmarcRoute called with:', params);

    // If no domain specified, load domains list
    if (!params.domain) {
        await loadDmarc();
        return;
    }

    // Load settings first if not loaded
    if (!dmarcConfiguration) {
        await loadDmarcSettings();
    }

    // Load IMAP status if not loaded
    await loadDmarcImapStatus();

    // If type is specified with an id, load that specific view
    if (params.type && params.id) {
        switch (params.type) {
            case 'report':
                // First load domain overview (don't update URL), then report details
                await loadDomainOverview(params.domain, false);
                await loadReportDetails(params.domain, params.id, false);
                return;
            case 'source':
                // First load domain overview (don't update URL), then source details
                await loadDomainOverview(params.domain, false);
                await loadSourceDetails(params.domain, params.id, false);
                return;
        }
    }

    // Load the domain overview (don't update URL since we came from router)
    await loadDomainOverview(params.domain, false);

    // If type is specified (without id), navigate to sub-tab
    if (params.type) {
        switch (params.type) {
            case 'reports':
                dmarcSwitchSubTab('reports');
                break;
            case 'sources':
                dmarcSwitchSubTab('sources');
                break;
            case 'tls':
                dmarcSwitchSubTab('tls');
                break;
        }
    }
}

function getFlagEmoji(countryCode) {
    if (!countryCode || countryCode.length !== 2) return '🌍';
    const codePoints = countryCode
        .toUpperCase()
        .split('')
        .map(char => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
}

// =============================================================================
// DOMAINS LIST
// =============================================================================

function getPolicyBadgeClass(policy) {
    switch (policy) {
        case 'reject':
            return 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300';
        case 'quarantine':
            return 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300';
        case 'none':
        default:
            return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300';
    }
}

async function loadDmarcDomains() {
    try {
        const response = await authenticatedFetch('/api/dmarc/domains');
        if (!response.ok) throw new Error('Failed to load domains');

        const data = await response.json();
        const domains = data.domains || [];

        const totalMessages = domains.reduce((sum, d) => sum + (d.stats_30d?.total_messages || 0), 0);
        const totalUniqueIps = domains.reduce((sum, d) => sum + (d.stats_30d?.unique_ips || 0), 0);
        const totalPass = domains.reduce((sum, d) => {
            const msgs = d.stats_30d?.total_messages || 0;
            const pct = d.stats_30d?.dmarc_pass_pct || 0;
            return sum + (msgs * pct / 100);
        }, 0);
        const overallPassPct = totalMessages > 0 ? Math.round((totalPass / totalMessages) * 100) : 0;

        const mainStatsContainer = document.getElementById('dmarc-main-stats-container');
        if (mainStatsContainer) {
            mainStatsContainer.innerHTML = `
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                    <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4 border border-gray-100 dark:border-gray-700">
                        <div class="flex items-center justify-between mb-2">
                            <h3 class="text-xs font-medium text-gray-500 dark:text-gray-400">Total Domains</h3>
                            <svg class="w-6 h-6 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path></svg>
                        </div>
                        <div class="text-2xl font-bold text-gray-900 dark:text-white">${data.total || 0}</div>
                    </div>

                    <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4 border border-gray-100 dark:border-gray-700">
                        <div class="flex items-center justify-between mb-2">
                            <h3 class="text-xs font-medium text-gray-500 dark:text-gray-400">Total Messages</h3>
                            <svg class="w-6 h-6 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
                        </div>
                        <div class="text-2xl font-bold text-gray-900 dark:text-white">${totalMessages.toLocaleString()}</div>
                    </div>

                    <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4 border border-gray-100 dark:border-gray-700">
                        <div class="flex items-center justify-between mb-2">
                            <h3 class="text-xs font-medium text-gray-500 dark:text-gray-400">DMARC Pass</h3>
                            <svg class="w-6 h-6 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                        </div>
                        <div class="text-2xl font-bold text-green-600 dark:text-green-400">${overallPassPct}%</div>
                    </div>

                    <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4 border border-gray-100 dark:border-gray-700">
                        <div class="flex items-center justify-between mb-2">
                            <h3 class="text-xs font-medium text-gray-500 dark:text-gray-400">Unique IPs</h3>
                            <svg class="w-6 h-6 text-orange-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 11a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
                        </div>
                        <div class="text-2xl font-bold text-gray-900 dark:text-white">${totalUniqueIps.toLocaleString()}</div>
                    </div>
                </div>
            `;
        }

        const domainsList = document.getElementById('dmarc-domains-list');

        if (domains.length === 0) {
            domainsList.innerHTML = `<tr><td colspan="5" class="px-6 py-12 text-center text-gray-500 dark:text-gray-400 text-sm">No domains found in the reporting period.</td></tr>`;
            return;
        }

        domainsList.innerHTML = domains.map(domain => {
            const stats = domain.stats_30d || {};
            const passRate = stats.dmarc_pass_pct || 0;

            // Status colors
            const passColor = passRate >= 95 ? 'text-green-500' : passRate >= 80 ? 'text-yellow-500' : 'text-red-500';
            const barBg = passRate >= 95 ? 'bg-green-500' : passRate >= 80 ? 'bg-yellow-500' : 'bg-red-500';
            const badgeBg = passRate >= 95 ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400';

            const firstDate = domain.first_report ? new Date(domain.first_report * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '-';
            const lastDate = domain.last_report ? new Date(domain.last_report * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '-';
            // Badge for TLS-only domains
            const hasTls = domain.has_tls;
            const hasDmarc = domain.has_dmarc !== false; // default true for backwards compat
            const tlsBadge = hasTls && !hasDmarc ? '<span class="ml-2 inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] font-medium rounded bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400"><svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>TLS</span>' : '';

            return `
                <tr class="hidden md:table-row hover:bg-gray-50 dark:hover:bg-gray-700/30 cursor-pointer transition-colors" onclick="loadDomainOverview('${escapeHtml(domain.domain)}')">
                    <td class="px-6 py-4 border-r border-gray-200 dark:border-gray-700/50 text-base font-bold text-blue-600 dark:text-blue-400 hover:underline">
                        ${escapeHtml(domain.domain)}${tlsBadge}
                    </td>
                    <td class="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 border-r border-gray-200 dark:border-gray-700/50">
                        ${firstDate} - ${lastDate}
                    </td>
                    <td class="px-6 py-4 text-center text-sm text-gray-900 dark:text-gray-100 border-r border-gray-200 dark:border-gray-700/50">
                        <div class="flex flex-col items-center gap-0.5">
                            ${domain.report_count > 0 ? `<span title="DMARC Reports">${domain.report_count}</span>` : ''}
                            ${domain.tls_report_count > 0 ? `<span class="text-xs text-green-600 dark:text-green-400" title="TLS Reports">+${domain.tls_report_count} TLS</span>` : ''}
                            ${!domain.report_count && !domain.tls_report_count ? '0' : ''}
                        </div>
                    </td>
                    <td class="px-6 py-4 text-sm text-gray-900 dark:text-gray-100 font-bold border-r border-gray-200 dark:border-gray-700/50">
                        ${(stats.total_messages || 0).toLocaleString()}
                    </td>
                    <td class="px-6 py-4 text-sm text-gray-900 dark:text-gray-100 font-bold border-r border-gray-200 dark:border-gray-700/50">
                        ${stats.unique_ips || 0}
                    </td>
                    <td class="px-6 py-4 border-r border-gray-200 dark:border-gray-700/50">
                        ${hasDmarc ? `
                        <div class="flex items-center gap-3">
                            <span class="text-sm font-bold ${passColor} min-w-[40px]">${passRate}%</span>
                            <div class="w-16 bg-gray-200 dark:bg-gray-700 rounded-full h-1.5 overflow-hidden">
                                <div class="${barBg} h-full" style="width: ${passRate}%"></div>
                            </div>
                        </div>
                        ` : '<span class="text-gray-400">-</span>'}
                    </td>
                    <td class="px-6 py-4">
                        ${hasTls ? `
                        <div class="flex items-center gap-3">
                            <span class="text-sm font-bold ${stats.tls_success_pct >= 95 ? 'text-green-500' : stats.tls_success_pct >= 80 ? 'text-yellow-500' : 'text-red-500'} min-w-[40px]">${stats.tls_success_pct || 100}%</span>
                            <div class="w-16 bg-gray-200 dark:bg-gray-700 rounded-full h-1.5 overflow-hidden">
                                <div class="${stats.tls_success_pct >= 95 ? 'bg-green-500' : stats.tls_success_pct >= 80 ? 'bg-yellow-500' : 'bg-red-500'} h-full" style="width: ${stats.tls_success_pct || 100}%"></div>
                            </div>
                        </div>
                        ` : '<span class="text-gray-400">-</span>'}
                    </td>
                </tr>

                <div class="md:hidden block mb-4 mx-2 rounded-2xl p-5 hover:opacity-90 cursor-pointer transition-all shadow-lg bg-gray-100 dark:bg-gray-800" 
                    onclick="loadDomainOverview('${escapeHtml(domain.domain)}')">
                    
                    <div class="flex justify-between items-center mb-1">
                        <div class="text-base font-bold text-blue-600 dark:text-blue-400">${escapeHtml(domain.domain)}${tlsBadge}</div>
                        <span class="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-bold rounded-lg ${hasDmarc ? (passRate >= 95 ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400') : 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'}">
                            ${hasDmarc ? passRate + '% Pass' : '<svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>TLS Only'}
                        </span>
                    </div>
                    
                    <div class="w-full bg-gray-300 dark:bg-gray-700 rounded-full h-1.5 overflow-hidden mb-6">
                        <div class="${barBg} h-full" style="width: ${passRate}%"></div>
                    </div>
                    
                    <div class="grid grid-cols-2 gap-x-8 gap-y-6">
                        <div class="border-l-[3px] border-blue-500/50 pl-3">
                            <div class="text-[10px] text-gray-500 dark:text-gray-400 uppercase font-bold tracking-wider">Messages</div>
                            <div class="text-sm font-bold text-gray-900 dark:text-white">${(stats.total_messages || 0).toLocaleString()}</div>
                        </div>
                        <div class="border-l-[3px] border-purple-500/50 pl-3">
                            <div class="text-[10px] text-gray-500 dark:text-gray-400 uppercase font-bold tracking-wider">Unique IPs</div>
                            <div class="text-sm font-bold text-gray-900 dark:text-white">${stats.unique_ips || 0}</div>
                        </div>
                        <div class="border-l-[3px] border-gray-500/50 pl-3">
                            <div class="text-[10px] text-gray-500 dark:text-gray-400 uppercase font-bold tracking-wider">Reports</div>
                            <div class="text-sm font-bold text-gray-900 dark:text-white">
                                ${domain.report_count || 0}${domain.tls_report_count > 0 ? ` <span class="text-xs text-green-600 dark:text-green-400">+${domain.tls_report_count} TLS</span>` : ''}
                            </div>
                        </div>
                        <div class="border-l-[3px] border-orange-500/50 pl-3">
                            <div class="text-[10px] text-gray-500 dark:text-gray-400 uppercase font-bold tracking-wider">Period</div>
                            <div class="text-sm font-bold text-gray-900 dark:text-white">${firstDate} - ${lastDate}</div>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        // Update the manage reports link with total count
        const manageReportsLink = document.getElementById('dmarc-manage-reports-link');
        if (manageReportsLink) {
            const totalReports = domains.reduce((sum, d) => sum + (d.report_count || 0) + (d.tls_report_count || 0), 0);
            manageReportsLink.innerHTML = `
                <span class="text-gray-500 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 cursor-pointer transition-colors" onclick="showReportsManagementModal()">
                    📋 Manage Reports (${totalReports} total)
                </span>
            `;
            manageReportsLink.classList.remove('hidden');
        }

    } catch (error) {
        console.error('Error loading DMARC domains:', error);
    }
}

async function loadDomainOverview(domain, updateUrl = true) {
    dmarcState.currentView = 'overview';
    dmarcState.currentDomain = domain;
    dmarcState.detailType = null;

    // Update URL if requested (skip when called from handleDmarcRoute to avoid duplicate history)
    if (updateUrl && typeof buildPath === 'function') {
        const newPath = buildPath('dmarc', { domain });
        if (window.location.pathname !== newPath) {
            history.pushState({ route: 'dmarc', params: { domain } }, '', newPath);
        }
    }

    // Update breadcrumb
    setDmarcBreadcrumb('domain', { domain });

    document.getElementById('dmarc-domains-view').classList.add('hidden');
    document.getElementById('dmarc-overview-view').classList.remove('hidden');
    document.getElementById('dmarc-report-details-view').classList.add('hidden');
    document.getElementById('dmarc-source-details-view').classList.add('hidden');
    // Title stays static as "DMARC Reports"

    try {
        const response = await authenticatedFetch(`/api/dmarc/domains/${encodeURIComponent(domain)}/overview?days=30`);
        const data = await response.json();
        const totals = data.totals || {};

        // Render the stats grid with 3 columns on mobile and icons
        // This replaces the old manual textContent updates
        const statsContainer = document.getElementById('dmarc-overview-stats-container');
        if (statsContainer) {
            statsContainer.innerHTML = `
                <div class="grid grid-cols-3 gap-2 sm:gap-4 mb-6">
                    <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-3 sm:p-6 border border-gray-100 dark:border-gray-700">
                        <div class="flex items-center justify-between mb-1 sm:mb-2">
                            <h3 class="text-[10px] sm:text-sm font-medium text-gray-500 dark:text-gray-400">Total Messages</h3>
                            <svg class="w-5 h-5 sm:w-7 sm:h-7 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
                            </svg>
                        </div>
                        <div class="text-lg sm:text-3xl font-bold text-gray-900 dark:text-white">${(totals.total_messages || 0).toLocaleString()}</div>
                        <div class="text-[9px] sm:text-xs text-gray-500 dark:text-gray-400 mt-1">Last 30 days</div>
                    </div>

                    <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-3 sm:p-6 border border-gray-100 dark:border-gray-700">
                        <div class="flex items-center justify-between mb-1 sm:mb-2">
                            <h3 class="text-[10px] sm:text-sm font-medium text-gray-500 dark:text-gray-400">DMARC Pass</h3>
                            <svg class="w-5 h-5 sm:w-7 sm:h-7 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                            </svg>
                        </div>
                        <div class="text-lg sm:text-3xl font-bold text-green-600 dark:text-green-400">${totals.dmarc_pass_pct ? `${totals.dmarc_pass_pct}%` : '-'}</div>
                        <div class="text-[9px] sm:text-xs text-gray-500 dark:text-gray-400 mt-1">SPF + DKIM Pass</div>
                    </div>

                    <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-3 sm:p-6 border border-gray-100 dark:border-gray-700">
                        <div class="flex items-center justify-between mb-1 sm:mb-2">
                            <h3 class="text-[10px] sm:text-sm font-medium text-gray-500 dark:text-gray-400">Sources</h3>
                            <svg class="w-5 h-5 sm:w-7 sm:h-7 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path>
                            </svg>
                        </div>
                        <div class="text-lg sm:text-3xl font-bold text-gray-900 dark:text-white">${(totals.unique_ips || 0).toLocaleString()}</div>
                        <div class="text-[9px] sm:text-xs text-gray-500 dark:text-gray-400 mt-1">${totals.unique_reporters || 0} reporters</div>
                    </div>
                </div>
            `;
        }

        renderDmarcChart(data.daily_stats || []);

        // Load initial sub-tab content based on current state
        if (dmarcState.currentSubTab === 'reports') {
            await loadDomainReports(domain);
        } else if (dmarcState.currentSubTab === 'sources') {
            await loadDomainSources(domain);
        } else if (dmarcState.currentSubTab === 'tls') {
            await loadDomainTLSReports(domain);
        } else {
            // Default to reports
            await loadDomainReports(domain);
        }
    } catch (error) {
        console.error('Error loading domain overview:', error);
    }
}

function renderDmarcChart(dailyStats) {
    const canvas = document.getElementById('dmarc-chart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    if (dmarcState.chartInstance) {
        dmarcState.chartInstance.destroy();
    }

    // Fix: Remove * 1000 because d.date is an ISO string, not a timestamp
    const labels = dailyStats.map(d => {
        const date = new Date(d.date);
        return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    });

    dmarcState.chartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Total Messages',
                    data: dailyStats.map(d => d.total || 0), // Use 'total' from dmarc.py
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'DMARC Pass',
                    data: dailyStats.map(d => d.dmarc_pass || 0), // Use 'dmarc_pass' from dmarc.py
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    fill: true,
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: { y: { beginAtZero: true } }
        }
    });
}

async function loadDomainReports(domain) {
    try {
        const response = await authenticatedFetch(`/api/dmarc/domains/${encodeURIComponent(domain)}/reports?days=30`);
        const data = await response.json();
        const reports = data.data || [];
        const reportsList = document.getElementById('dmarc-reports-list');

        if (reports.length === 0) {
            reportsList.innerHTML = `<div class="text-center py-12"><p class="text-gray-500 text-sm">No daily reports available.</p></div>`;
            return;
        }

        reportsList.innerHTML = reports.map(report => {
            const date = new Date(report.date);
            const dateStr = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
            const passPct = report.dmarc_pass_pct || 0;
            const passColor = passPct >= 95 ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400';

            return `
                <div class="bg-gray-50 dark:bg-gray-700/50 border border-gray-100 dark:border-gray-700 rounded-xl p-3 mb-4 cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors" onclick="loadReportDetails('${escapeHtml(domain)}', '${report.date}')">
                    
                    <div class="flex items-center justify-between">
                        <div class="flex items-center gap-3">
                            <div class="p-2 bg-white dark:bg-gray-800 rounded-lg shadow-sm flex-shrink-0">
                                <svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                                </svg>
                            </div>
                            <div class="text-sm font-bold text-blue-600 dark:text-blue-400 hover:underline">${dateStr}</div>
                        </div>
                        
                        <span class="inline-flex items-center px-2.5 py-1 text-xs font-bold rounded-lg ${passColor}">
                            ${passPct}% Pass
                        </span>
                    </div>

                    <div class="border-t border-gray-200 dark:border-gray-600 my-3"></div>

                    <div class="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-500 dark:text-gray-400">
                        <div class="flex items-center gap-1">
                            <span class="font-bold text-gray-900 dark:text-white">${(report.total_messages || 0).toLocaleString()}</span>
                            <span>messages</span>
                        </div>
                        <span class="hidden sm:block text-gray-300 dark:text-gray-600">•</span>
                        <div>${report.unique_ips} Unique IPs</div>
                        <span class="hidden sm:block text-gray-300 dark:text-gray-600">•</span>
                        <div>${report.reports.length} Reporters</div>
                    </div>
                    
                </div>`;
        }).join('');
    } catch (error) {
        console.error('Error loading reports:', error);
    }
}

async function loadDomainSources(domain) {
    try {
        const response = await authenticatedFetch(`/api/dmarc/domains/${encodeURIComponent(domain)}/sources?days=30`);
        if (!response.ok) throw new Error('Failed to load sources');

        const data = await response.json();
        const sources = data.data || [];
        const sourcesList = document.getElementById('dmarc-sources-list');

        if (sources.length === 0) {
            sourcesList.innerHTML = '<p class="text-center py-12 text-gray-500 text-sm">No sources found.</p>';
            return;
        }

        sourcesList.innerHTML = `
            <div class="space-y-3">
                ${sources.map(s => {
            const providerName = s.asn_org || 'Unknown Provider';
            const hasGeoData = s.country_code && s.country_code.length === 2;
            const flagUrl = hasGeoData ? `/static/assets/flags/24x18/${s.country_code.toLowerCase()}.png` : null;

            // Status Badge Logic
            const passPct = s.dmarc_pass_pct || 0;
            const passColor = passPct >= 95 ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400';

            // Icon: show flag if available, otherwise show a generic server icon
            const iconHtml = hasGeoData && flagUrl
                ? `<img src="${flagUrl}" alt="${s.country_name || 'Unknown'}" class="w-5 h-3.5 object-cover rounded-sm" onerror="this.parentElement.innerHTML='<svg class=\\'w-5 h-5 text-gray-400\\' fill=\\'none\\' stroke=\\'currentColor\\' viewBox=\\'0 0 24 24\\'><path stroke-linecap=\\'round\\' stroke-linejoin=\\'round\\' stroke-width=\\'2\\' d=\\'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01\\'></path></svg>'">`
                : `<svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path></svg>`;

            return `
                    <div class="bg-gray-50 dark:bg-gray-700/50 border border-gray-100 dark:border-gray-700 rounded-xl p-4 cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors shadow-sm" 
                         onclick="loadSourceDetails('${escapeHtml(domain)}', '${escapeHtml(s.source_ip)}')">
                        
                        <div class="flex items-start justify-between gap-3">
                            <div class="flex items-center gap-3 min-w-0 flex-1">
                                <div class="p-2 bg-white dark:bg-gray-800 rounded-lg shadow-sm flex-shrink-0">
                                    ${iconHtml}
                                </div>
                                <div class="min-w-0 flex-1">
                                    <div class="text-sm font-bold text-blue-600 dark:text-blue-400 hover:underline truncate">${escapeHtml(providerName)}</div>
                                    <div class="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">
                                        ${escapeHtml(s.source_ip)} ${s.country_name ? `• ${escapeHtml(s.country_name)}` : ''}
                                    </div>
                                </div>
                            </div>
                            
                            <span class="inline-flex items-center px-2.5 py-1 text-xs font-bold rounded-lg ${passColor} flex-shrink-0">
                                ${passPct}% Pass
                            </span>
                        </div>

                        <div class="border-t border-gray-200 dark:border-gray-600 my-3"></div>

                        <div class="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-gray-500 dark:text-gray-400">
                            <div class="flex items-center gap-1">
                                <span class="font-bold text-gray-900 dark:text-white">${(s.total_count || 0).toLocaleString()}</span>
                                <span class="font-medium">messages</span>
                            </div>
                            <span class="text-gray-300 dark:text-gray-600">•</span>
                            <div class="flex items-center gap-1">
                                <span>SPF:</span>
                                <span class="${s.spf_pass_pct >= 95 ? 'text-green-600 dark:text-green-400' : 'text-red-500'} font-bold">${s.spf_pass_pct}%</span>
                            </div>
                            <span class="text-gray-300 dark:text-gray-600">•</span>
                            <div class="flex items-center gap-1">
                                <span>DKIM:</span>
                                <span class="${s.dkim_pass_pct >= 95 ? 'text-green-600 dark:text-green-400' : 'text-red-500'} font-bold">${s.dkim_pass_pct}%</span>
                            </div>
                        </div>
                    </div>`;
        }).join('')}
            </div>
        `;
    } catch (error) {
        console.error('Error loading sources:', error);
    }
}

// =============================================================================
// TLS REPORTS TAB
// =============================================================================

function dmarcSwitchSubTab(tab) {
    dmarcState.currentSubTab = tab;

    // Update tab buttons
    document.getElementById('dmarc-subtab-reports').classList.remove('active');
    document.getElementById('dmarc-subtab-sources').classList.remove('active');
    document.getElementById('dmarc-subtab-tls')?.classList.remove('active');
    document.getElementById(`dmarc-subtab-${tab}`)?.classList.add('active');

    // Update tab content
    document.getElementById('dmarc-reports-content').classList.add('hidden');
    document.getElementById('dmarc-sources-content').classList.add('hidden');
    document.getElementById('dmarc-tls-content')?.classList.add('hidden');

    // Show selected tab content
    if (tab === 'reports') {
        document.getElementById('dmarc-reports-content').classList.remove('hidden');
        loadDomainReports(dmarcState.currentDomain);
    } else if (tab === 'sources') {
        document.getElementById('dmarc-sources-content').classList.remove('hidden');
        loadDomainSources(dmarcState.currentDomain);
    } else if (tab === 'tls') {
        document.getElementById('dmarc-tls-content')?.classList.remove('hidden');
        loadDomainTLSReports(dmarcState.currentDomain);
    }
}

async function loadDomainTLSReports(domain) {
    const tlsList = document.getElementById('dmarc-tls-list');
    if (!tlsList) return;

    try {
        // Use daily aggregated API
        const response = await authenticatedFetch(`/api/dmarc/domains/${encodeURIComponent(domain)}/tls-reports/daily?days=30`);
        if (!response.ok) throw new Error('Failed to load TLS reports');

        const data = await response.json();
        const dailyReports = data.data || [];
        const totals = data.totals || {};

        if (dailyReports.length === 0) {
            tlsList.innerHTML = `
                <div class="text-center py-12">
                    <svg class="w-12 h-12 mx-auto text-gray-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                    </svg>
                    <p class="text-gray-500 dark:text-gray-400 text-sm">No TLS-RPT reports found for this domain.</p>
                    <p class="text-gray-400 dark:text-gray-500 text-xs mt-2">TLS reports will appear here once received from email providers.</p>
                </div>`;
            return;
        }

        // Render summary stats
        const successRate = totals.overall_success_rate || 100;
        const successColor = successRate >= 95 ? 'text-green-500' : successRate >= 80 ? 'text-yellow-500' : 'text-red-500';

        tlsList.innerHTML = `
            <!-- TLS Summary -->
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 text-center">
                    <div class="text-xs text-gray-500 dark:text-gray-400 uppercase font-medium mb-1">Days</div>
                    <div class="text-2xl font-bold text-gray-900 dark:text-white">${totals.total_days || 0}</div>
                </div>
                <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 text-center">
                    <div class="text-xs text-gray-500 dark:text-gray-400 uppercase font-medium mb-1">Reports</div>
                    <div class="text-2xl font-bold text-gray-900 dark:text-white">${totals.total_reports || 0}</div>
                </div>
                <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 text-center">
                    <div class="text-xs text-gray-500 dark:text-gray-400 uppercase font-medium mb-1">Success Rate</div>
                    <div class="text-2xl font-bold ${successColor}">${successRate}%</div>
                </div>
                <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 text-center">
                    <div class="text-xs text-gray-500 dark:text-gray-400 uppercase font-medium mb-1">Sessions</div>
                    <div class="text-2xl font-bold text-gray-900 dark:text-white">${((totals.total_successful_sessions || 0) + (totals.total_failed_sessions || 0)).toLocaleString()}</div>
                </div>
            </div>
            
            <!-- Daily TLS Reports List -->
            <div class="space-y-3">
                ${dailyReports.map(day => {
            const dateFormatted = new Date(day.date).toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' });
            const rateColor = day.success_rate >= 95 ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' :
                day.success_rate >= 80 ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400' :
                    'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400';
            const barColor = day.success_rate >= 95 ? 'bg-green-500' : day.success_rate >= 80 ? 'bg-yellow-500' : 'bg-red-500';

            return `
                        <div class="bg-gray-50 dark:bg-gray-700/50 border border-gray-100 dark:border-gray-700 rounded-xl p-4 cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors" onclick="loadTLSReportDetails('${escapeHtml(domain)}', '${day.date}')">
                            <div class="flex items-start justify-between gap-3 mb-3">
                                <div class="flex items-center gap-3 min-w-0 flex-1">
                                    <div class="p-2 bg-white dark:bg-gray-800 rounded-lg shadow-sm flex-shrink-0">
                                        <svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                                        </svg>
                                    </div>
                                    <div class="min-w-0 flex-1">
                                        <div class="text-sm font-bold text-gray-900 dark:text-white">${dateFormatted}</div>
                                        <div class="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">
                                            ${day.report_count} report${day.report_count !== 1 ? 's' : ''} from ${day.organization_count} provider${day.organization_count !== 1 ? 's' : ''}
                                        </div>
                                    </div>
                                </div>
                                <span class="inline-flex items-center px-2.5 py-1 text-xs font-bold rounded-lg ${rateColor}">
                                    ${day.success_rate}%
                                </span>
                            </div>
                            
                            <!-- Progress bar -->
                            <div class="w-full bg-gray-200 dark:bg-gray-600 rounded-full h-1.5 mb-3">
                                <div class="${barColor} h-full rounded-full" style="width: ${day.success_rate}%"></div>
                            </div>
                            
                            <!-- Stats -->
                            <div class="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs">
                                <div class="flex items-center gap-2">
                                    <svg class="w-4 h-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                                    </svg>
                                    <span class="text-gray-500 dark:text-gray-400">Success:</span>
                                    <span class="font-bold text-green-600 dark:text-green-400">${(day.total_success || 0).toLocaleString()}</span>
                                </div>
                                <div class="flex items-center gap-2">
                                    <svg class="w-4 h-4 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                                    </svg>
                                    <span class="text-gray-500 dark:text-gray-400">Failed:</span>
                                    <span class="font-bold text-red-600 dark:text-red-400">${(day.total_fail || 0).toLocaleString()}</span>
                                </div>
                                <div class="flex items-center gap-2">
                                    <span class="text-gray-500 dark:text-gray-400">Providers:</span>
                                    <span class="font-medium text-gray-700 dark:text-gray-300">${day.organizations.join(', ')}</span>
                                </div>
                            </div>
                        </div>
                    `;
        }).join('')}
            </div>
        `;

    } catch (error) {
        console.error('Error loading TLS reports:', error);
        tlsList.innerHTML = `
            <div class="text-center py-12">
                <svg class="w-12 h-12 mx-auto text-red-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <p class="text-red-500 text-sm">Failed to load TLS reports.</p>
            </div>`;
    }
}

async function loadTLSReportDetails(domain, reportDate) {
    const tlsList = document.getElementById('dmarc-tls-list');
    if (!tlsList) return;

    dmarcState.detailType = 'tls';
    const dateFormatted = new Date(reportDate).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    setDmarcBreadcrumb('tlsDetails', { domain, date: dateFormatted });

    try {
        const response = await authenticatedFetch(`/api/dmarc/domains/${encodeURIComponent(domain)}/tls-reports/${reportDate}/details`);
        if (!response.ok) throw new Error('Failed to load TLS report details');

        const data = await response.json();
        const stats = data.stats || {};
        const providers = data.providers || [];

        const dateFormatted = new Date(reportDate).toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' });
        const successRate = stats.success_rate || 100;
        const successColor = successRate >= 95 ? 'text-green-500' : successRate >= 80 ? 'text-yellow-500' : 'text-red-500';

        tlsList.innerHTML = `
            <!-- Back Button -->
            <div class="mb-6">
                <button onclick="loadDomainTLSReports('${escapeHtml(domain)}')" class="flex items-center gap-2 text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 transition-colors">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"></path>
                    </svg>
                    <span class="font-medium">Back to Daily Reports</span>
                </button>
            </div>
            
            <!-- Header -->
            <div class="flex items-center justify-between mb-6">
                <div>
                    <h3 class="text-lg font-bold text-gray-900 dark:text-white">${dateFormatted}</h3>
                    <p class="text-sm text-gray-500 dark:text-gray-400">TLS Report Details for ${escapeHtml(domain)}</p>
                </div>
            </div>
            
            <!-- Stats Cards -->
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 text-center border border-gray-100 dark:border-gray-700">
                    <div class="text-xs text-gray-500 dark:text-gray-400 uppercase font-medium mb-1">Sessions</div>
                    <div class="text-2xl font-bold text-gray-900 dark:text-white">${(stats.total_sessions || 0).toLocaleString()}</div>
                </div>
                <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 text-center border border-gray-100 dark:border-gray-700">
                    <div class="text-xs text-gray-500 dark:text-gray-400 uppercase font-medium mb-1">Success Rate</div>
                    <div class="text-2xl font-bold ${successColor}">${successRate}%</div>
                </div>
                <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 text-center border border-gray-100 dark:border-gray-700">
                    <div class="text-xs text-gray-500 dark:text-gray-400 uppercase font-medium mb-1">Successful</div>
                    <div class="text-2xl font-bold text-green-600 dark:text-green-400">${(stats.total_success || 0).toLocaleString()}</div>
                </div>
                <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 text-center border border-gray-100 dark:border-gray-700">
                    <div class="text-xs text-gray-500 dark:text-gray-400 uppercase font-medium mb-1">Failed</div>
                    <div class="text-2xl font-bold text-red-600 dark:text-red-400">${(stats.total_fail || 0).toLocaleString()}</div>
                </div>
            </div>
            
            <!-- Providers Table -->
            <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg border border-gray-100 dark:border-gray-700">
                <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-600">
                    <h4 class="text-sm font-bold text-gray-900 dark:text-white">Providers (${stats.total_providers || 0})</h4>
                </div>
                
                <!-- Desktop Table -->
                <div class="hidden md:block overflow-x-auto">
                    <table class="min-w-full">
                        <thead class="bg-gray-100 dark:bg-gray-700">
                            <tr>
                                <th class="px-4 py-3 text-left text-xs font-bold text-gray-600 dark:text-gray-400 uppercase">Provider</th>
                                <th class="px-4 py-3 text-center text-xs font-bold text-gray-600 dark:text-gray-400 uppercase">Sessions</th>
                                <th class="px-4 py-3 text-center text-xs font-bold text-gray-600 dark:text-gray-400 uppercase">Success</th>
                                <th class="px-4 py-3 text-center text-xs font-bold text-gray-600 dark:text-gray-400 uppercase">Failed</th>
                                <th class="px-4 py-3 text-center text-xs font-bold text-gray-600 dark:text-gray-400 uppercase">Rate</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-200 dark:divide-gray-600">
                            ${providers.map(p => {
            const rateColor = p.success_rate >= 95 ? 'text-green-600 dark:text-green-400' : p.success_rate >= 80 ? 'text-yellow-600 dark:text-yellow-400' : 'text-red-600 dark:text-red-400';
            return `
                                <tr class="hover:bg-gray-100 dark:hover:bg-gray-700/50 transition-colors">
                                    <td class="px-4 py-3">
                                        <div class="font-medium text-gray-900 dark:text-white">${escapeHtml(p.organization_name || 'Unknown')}</div>
                                        <div class="text-xs text-gray-500 dark:text-gray-400">${p.policies?.length || 0} policies</div>
                                    </td>
                                    <td class="px-4 py-3 text-center text-sm font-medium text-gray-900 dark:text-white">${(p.total_sessions || 0).toLocaleString()}</td>
                                    <td class="px-4 py-3 text-center text-sm font-medium text-green-600 dark:text-green-400">${(p.successful_sessions || 0).toLocaleString()}</td>
                                    <td class="px-4 py-3 text-center text-sm font-medium text-red-600 dark:text-red-400">${(p.failed_sessions || 0).toLocaleString()}</td>
                                    <td class="px-4 py-3 text-center text-sm font-bold ${rateColor}">${p.success_rate}%</td>
                                </tr>`;
        }).join('')}
                        </tbody>
                    </table>
                </div>
                
                <!-- Mobile Cards -->
                <div class="md:hidden divide-y divide-gray-200 dark:divide-gray-600">
                    ${providers.map(p => {
            const rateColor = p.success_rate >= 95 ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' : p.success_rate >= 80 ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400' : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400';
            return `
                        <div class="p-4">
                            <div class="flex justify-between items-start mb-2">
                                <div class="font-medium text-gray-900 dark:text-white">${escapeHtml(p.organization_name || 'Unknown')}</div>
                                <span class="px-2 py-0.5 text-xs font-bold rounded ${rateColor}">${p.success_rate}%</span>
                            </div>
                            <div class="grid grid-cols-3 gap-2 text-xs">
                                <div><span class="text-gray-500">Sessions:</span> <span class="font-bold">${p.total_sessions}</span></div>
                                <div><span class="text-gray-500">Success:</span> <span class="font-bold text-green-600">${p.successful_sessions}</span></div>
                                <div><span class="text-gray-500">Failed:</span> <span class="font-bold text-red-600">${p.failed_sessions}</span></div>
                            </div>
                        </div>`;
        }).join('')}
                </div>
            </div>
        `;

    } catch (error) {
        console.error('Error loading TLS report details:', error);
        tlsList.innerHTML = `
            <div class="text-center py-12">
                <svg class="w-12 h-12 mx-auto text-red-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <p class="text-red-500 text-sm">Failed to load TLS report details.</p>
                <button onclick="loadDomainTLSReports('${escapeHtml(domain)}')" class="mt-4 text-blue-600 hover:underline">Back to Daily Reports</button>
            </div>`;
    }
}

// =============================================================================
// REPORT DETAILS
// =============================================================================

async function loadReportDetails(domain, reportDate, updateUrl = true) {
    dmarcState.currentView = 'report_details';
    dmarcState.currentReportDate = reportDate;
    dmarcState.detailType = 'report';

    // Update URL if requested
    if (updateUrl && typeof buildPath === 'function') {
        const newPath = buildPath('dmarc', { domain, type: 'report', id: reportDate });
        if (window.location.pathname !== newPath) {
            history.pushState({ route: 'dmarc', params: { domain, type: 'report', id: reportDate } }, '', newPath);
        }
    }

    document.getElementById('dmarc-domains-view').classList.add('hidden');
    document.getElementById('dmarc-overview-view').classList.add('hidden');
    document.getElementById('dmarc-report-details-view').classList.remove('hidden');
    document.getElementById('dmarc-source-details-view').classList.add('hidden');

    const dateObj = new Date(reportDate);
    const dateStr = dateObj.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    const shortDate = dateObj.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    // Title stays static as "DMARC Reports"

    // Update breadcrumb
    setDmarcBreadcrumb('reportDetails', { domain, date: shortDate });

    try {
        const response = await authenticatedFetch(`/api/dmarc/domains/${encodeURIComponent(domain)}/reports/${reportDate}/details`);
        const data = await response.json();
        const totals = data.totals || {};

        /* Inject icons and stats grid */
        const statsContainer = document.getElementById('report-details-stats-container');
        if (statsContainer) {
            statsContainer.innerHTML = generateDetailStatsGrid(totals);
        }

        const sources = data.sources || [];
        const sourcesList = document.getElementById('report-detail-sources-list');

        if (sources.length === 0) {
            sourcesList.innerHTML = '<p class="text-center py-12 text-gray-500">No sources found.</p>';
            return;
        }

        sourcesList.innerHTML = `
            <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead class="bg-gray-50 dark:bg-gray-700">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">From: domain</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Envelope from: domain</th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Volume</th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">DMARC pass</th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">SPF aligned</th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">DKIM aligned</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Reporter</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                    ${sources.map(s => {
            const providerName = s.asn_org || s.source_name || 'Unknown';
            const hasGeoData = s.country_code && s.country_code.length === 2;
            const flagUrl = hasGeoData ? `/static/assets/flags/48x36/${s.country_code.toLowerCase()}.png` : null;
            const dmarcColor = s.dmarc_pass_pct >= 95 ? 'text-green-600 dark:text-green-400' : s.dmarc_pass_pct === 0 ? 'text-red-600 dark:text-red-400' : 'text-gray-900 dark:text-gray-100';
            const spfColor = s.spf_pass_pct >= 95 ? 'text-green-600 dark:text-green-400' : s.spf_pass_pct === 0 ? 'text-red-600 dark:text-red-400' : 'text-gray-900 dark:text-gray-100';
            const dkimColor = s.dkim_pass_pct >= 95 ? 'text-green-600 dark:text-green-400' : s.dkim_pass_pct === 0 ? 'text-red-600 dark:text-red-400' : 'text-gray-900 dark:text-gray-100';

            // Icon: show flag if available, otherwise show a generic server icon
            const iconHtml = hasGeoData && flagUrl
                ? `<img src="${flagUrl}" alt="${s.country_name || 'Unknown'}" class="w-6 h-4 object-cover rounded-sm shadow-sm" style="border: 1px solid rgba(0,0,0,0.1);" onerror="this.outerHTML='<svg class=\\'w-6 h-5 text-gray-400\\' fill=\\'none\\' stroke=\\'currentColor\\' viewBox=\\'0 0 24 24\\'><path stroke-linecap=\\'round\\' stroke-linejoin=\\'round\\' stroke-width=\\'2\\' d=\\'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01\\'></path></svg>'">`
                : `<svg class="w-6 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path></svg>`;

            return `
                        <tr class="hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer" onclick="loadSourceDetails('${escapeHtml(domain)}', '${escapeHtml(s.source_ip)}')">
                            <td class="px-6 py-4">
                                <div class="flex items-center gap-2">
                                    ${iconHtml}
                                    <div>
                                        <div class="text-sm font-medium text-blue-600 dark:text-blue-400 hover:underline">${escapeHtml(providerName)}</div>
                                        <div class="text-xs text-gray-500">${escapeHtml(s.source_ip)}</div>
                                    </div>
                                </div>
                            </td>
                            <td class="px-6 py-4 text-sm text-gray-900 dark:text-gray-100">${escapeHtml(s.header_from || '-')}</td>
                            <td class="px-6 py-4 text-sm text-gray-900 dark:text-gray-100">${escapeHtml(s.envelope_from || '-')}</td>
                            <td class="px-6 py-4 text-sm text-right text-gray-900 dark:text-gray-100">${(s.volume || 0).toLocaleString()}</td>
                            <td class="px-6 py-4 text-right"><span class="text-sm font-medium ${dmarcColor}">${s.dmarc_pass_pct}%</span></td>
                            <td class="px-6 py-4 text-right"><span class="text-sm ${spfColor}">${s.spf_pass_pct}%</span></td>
                            <td class="px-6 py-4 text-right"><span class="text-sm ${dkimColor}">${s.dkim_pass_pct}%</span></td>
                            <td class="px-6 py-4 text-sm text-gray-900 dark:text-gray-100">${escapeHtml(s.reporter || '-')}</td>
                        </tr>`;
        }).join('')}
                </tbody>
            </table>
        `;
    } catch (error) {
        console.error('Error loading report details:', error);
    }
}


// =============================================================================
// SOURCE DETAILS
// =============================================================================

async function loadSourceDetails(domain, sourceIp, updateUrl = true) {
    dmarcState.currentView = 'source_details';
    dmarcState.currentSourceIp = sourceIp;
    dmarcState.detailType = 'source';

    // Update URL if requested
    if (updateUrl && typeof buildPath === 'function') {
        const newPath = buildPath('dmarc', { domain, type: 'source', id: sourceIp });
        if (window.location.pathname !== newPath) {
            history.pushState({ route: 'dmarc', params: { domain, type: 'source', id: sourceIp } }, '', newPath);
        }
    }

    document.getElementById('dmarc-domains-view').classList.add('hidden');
    document.getElementById('dmarc-overview-view').classList.add('hidden');
    document.getElementById('dmarc-report-details-view').classList.add('hidden');
    document.getElementById('dmarc-source-details-view').classList.remove('hidden');
    // Title stays static as "DMARC Reports"

    // Update breadcrumb
    setDmarcBreadcrumb('sourceDetails', { domain, ip: sourceIp });

    try {
        const response = await authenticatedFetch(`/api/dmarc/domains/${encodeURIComponent(domain)}/sources/${encodeURIComponent(sourceIp)}/details?days=30`);
        const data = await response.json();

        /* Update Header Info */
        const hasGeoData = data.country_code && data.country_code.length === 2;
        const flagImg = document.getElementById('source-detail-flag');
        if (hasGeoData) {
            const flagUrl = `/static/assets/flags/48x36/${data.country_code.toLowerCase()}.png`;
            flagImg.src = flagUrl;
            flagImg.style.display = '';
            flagImg.onerror = function () { this.style.display = 'none'; };
        } else {
            flagImg.style.display = 'none';
        }
        document.getElementById('source-detail-name').textContent = data.source_name || data.asn_org || 'Unknown Provider';
        document.getElementById('source-detail-ip').textContent = sourceIp;

        const location = [data.city, data.country_name].filter(Boolean).join(', ') || 'Unknown location';
        document.getElementById('source-detail-location').textContent = location;
        document.getElementById('source-detail-asn').textContent = data.asn ? `ASN ${data.asn}` : 'No ASN';

        /* Inject icons and stats grid */
        const totals = data.totals || {};
        const statsContainer = document.getElementById('source-details-stats-container');
        if (statsContainer) {
            statsContainer.innerHTML = generateDetailStatsGrid(totals);
        }

        const envelopes = data.envelope_from_groups || [];
        const envelopeList = document.getElementById('source-detail-envelope-list');

        if (envelopes.length === 0) {
            envelopeList.innerHTML = '<p class="text-center py-12 text-gray-500">No data found.</p>';
            return;
        }

        envelopeList.innerHTML = `
            <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead class="bg-gray-50 dark:bg-gray-700">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">From: domain</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Envelope from: domain</th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Volume</th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">DMARC pass</th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">SPF aligned</th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">DKIM aligned</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Reporter</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                    ${envelopes.map(env => {
            const dmarcPct = env.volume > 0 ? Math.round((env.dmarc_pass / env.volume) * 100) : 0;
            const spfPct = env.volume > 0 ? Math.round((env.spf_aligned / env.volume) * 100) : 0;
            const dkimPct = env.volume > 0 ? Math.round((env.dkim_aligned / env.volume) * 100) : 0;
            const dmarcColor = dmarcPct >= 95 ? 'text-green-600 dark:text-green-400' : dmarcPct === 0 ? 'text-red-600 dark:text-red-400' : 'text-gray-900 dark:text-gray-100';
            const spfColor = spfPct >= 95 ? 'text-green-600 dark:text-green-400' : spfPct === 0 ? 'text-red-600 dark:text-red-400' : 'text-gray-900 dark:text-gray-100';
            const dkimColor = dkimPct >= 95 ? 'text-green-600 dark:text-green-400' : dkimPct === 0 ? 'text-red-600 dark:text-red-400' : 'text-gray-900 dark:text-gray-100';

            return `
                        <tr class="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                            <td class="px-6 py-4 text-sm text-gray-900 dark:text-gray-100">${escapeHtml(env.header_from || '-')}</td>
                            <td class="px-6 py-4 text-sm text-gray-900 dark:text-gray-100">${escapeHtml(env.envelope_from || '-')}</td>
                            <td class="px-6 py-4 text-sm text-right text-gray-900 dark:text-gray-100">${(env.volume || 0).toLocaleString()}</td>
                            <td class="px-6 py-4 text-right"><span class="text-sm font-medium ${dmarcColor}">${dmarcPct}%</span></td>
                            <td class="px-6 py-4 text-right"><span class="text-sm ${spfColor}">${spfPct}%</span></td>
                            <td class="px-6 py-4 text-right"><span class="text-sm ${dkimColor}">${dkimPct}%</span></td>
                            <td class="px-6 py-4 text-sm text-gray-900 dark:text-gray-100">${escapeHtml(env.reporter || '-')}</td>
                        </tr>`;
        }).join('')}
                </tbody>
            </table>
        `;
    } catch (error) {
        console.error('Error loading source details:', error);
    }
}


function generateDetailStatsGrid(totals) {
    return `
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4 border border-gray-100 dark:border-gray-700">
                <div class="flex items-center justify-between mb-2">
                    <h3 class="text-xs font-medium text-gray-500 dark:text-gray-400">Volume</h3>
                    <svg class="w-6 h-6 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
                </div>
                <div class="text-2xl font-bold text-gray-900 dark:text-white">${(totals.total_messages || 0).toLocaleString()}</div>
            </div>

            <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4 border border-gray-100 dark:border-gray-700">
                <div class="flex items-center justify-between mb-2">
                    <h3 class="text-xs font-medium text-gray-500 dark:text-gray-400">DMARC Pass</h3>
                    <svg class="w-6 h-6 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                </div>
                <div class="text-2xl font-bold text-gray-900 dark:text-white">${(totals.dmarc_pass || 0).toLocaleString()}</div>
                <div class="text-xs text-green-600 dark:text-green-400 mt-1">${totals.dmarc_pass_pct || 0}%</div>
            </div>

            <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4 border border-gray-100 dark:border-gray-700">
                <div class="flex items-center justify-between mb-2">
                    <h3 class="text-xs font-medium text-gray-500 dark:text-gray-400">SPF Aligned</h3>
                    <svg class="w-6 h-6 text-orange-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                </div>
                <div class="text-2xl font-bold text-gray-900 dark:text-white">${(totals.spf_pass || 0).toLocaleString()}</div>
                <div class="text-xs text-orange-500 mt-1">${totals.spf_pass_pct || 0}%</div>
            </div>

            <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4 border border-gray-100 dark:border-gray-700">
                <div class="flex items-center justify-between mb-2">
                    <h3 class="text-xs font-medium text-gray-500 dark:text-gray-400">DKIM Aligned</h3>
                    <svg class="w-6 h-6 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path></svg>
                </div>
                <div class="text-2xl font-bold text-gray-900 dark:text-white">${(totals.dkim_pass || 0).toLocaleString()}</div>
                <div class="text-xs text-purple-500 mt-1">${totals.dkim_pass_pct || 0}%</div>
            </div>
        </div>
    `;
}




// =============================================================================
// UPLOAD
// =============================================================================

async function uploadDmarcReport(event) {
    const file = event.target.files[0];
    if (!file) return;

    try {
        const formData = new FormData();
        formData.append('file', file);

        const response = await authenticatedFetch('/api/dmarc/upload', {
            method: 'POST',
            body: formData
        });

        if (response.status === 403) {
            showToast('Manual upload is disabled', 'error');
            event.target.value = '';
            return;
        }

        if (!response.ok) throw new Error('Upload failed');

        const result = await response.json();
        const reportType = result.report_type === 'tls-rpt' ? 'TLS-RPT' : 'DMARC';

        if (result.status === 'success') {
            const count = result.records_count || result.policies_count || 0;
            const countLabel = result.report_type === 'tls-rpt' ? 'policies' : 'records';
            showToast(`${reportType} report uploaded: ${count} ${countLabel}`, 'success');

            if (dmarcState.currentView === 'domains') {
                loadDmarcDomains();
            } else if (dmarcState.currentDomain) {
                loadDomainOverview(dmarcState.currentDomain);
                // If TLS report was uploaded and we're on TLS tab, refresh it
                if (result.report_type === 'tls-rpt' && dmarcState.currentSubTab === 'tls') {
                    loadDomainTLSReports(dmarcState.currentDomain);
                }
            }
        } else if (result.status === 'duplicate') {
            showToast(`${reportType} report already exists`, 'warning');
        }

    } catch (error) {
        console.error('Upload error:', error);
        showToast('Failed to upload report', 'error');
    }

    event.target.value = '';
}

// =============================================================================
// IMAP
// =============================================================================

async function loadDmarcImapStatus() {
    try {
        const response = await authenticatedFetch('/api/dmarc/imap/status');
        if (!response.ok) {
            dmarcImapStatus = null;
            return;
        }

        dmarcImapStatus = await response.json();
        updateDmarcControls();

    } catch (error) {
        console.error('Error loading DMARC IMAP status:', error);
        dmarcImapStatus = null;
    }
}

function updateDmarcControls() {
    const uploadBtn = document.getElementById('dmarc-upload-btn');
    const syncContainer = document.getElementById('dmarc-sync-container');
    const lastSyncInfo = document.getElementById('dmarc-last-sync-info');

    // Toggle upload button
    if (uploadBtn) {
        if (dmarcConfiguration?.manual_upload_enabled === true) {
            uploadBtn.classList.remove('hidden');
        } else {
            uploadBtn.classList.add('hidden');
        }
    }

    // Toggle sync container
    if (dmarcImapStatus && dmarcImapStatus.enabled) {
        syncContainer.classList.remove('hidden');

        // Update last sync info to match Domains Overview style
        if (dmarcImapStatus.latest_sync) {
            const sync = dmarcImapStatus.latest_sync;
            const timeStr = formatTime(sync.started_at);

            let statusPrefix = '';
            if (sync.status === 'success') statusPrefix = '✓ ';
            if (sync.status === 'error') statusPrefix = '✗ ';
            if (sync.status === 'running') statusPrefix = '⟳ ';

            lastSyncInfo.innerHTML = `
                <div class="flex flex-col items-center lg:items-end">
                    <span class="${sync.status === 'error' ? 'text-red-500' : 'text-green-500'} font-medium">
                        ${statusPrefix}Last sync: ${timeStr}
                    </span>
                    <button onclick="showDmarcSyncHistory()" class="text-blue-600 dark:text-blue-400 hover:underline text-[11px] mt-0.5">
                        View History
                    </button>
                </div>
            `;
        } else {
            lastSyncInfo.innerHTML = '<span class="text-gray-500 italic">Never synced</span>';
        }
    } else {
        syncContainer.classList.add('hidden');
    }
}

async function triggerDmarcSync() {
    const btn = document.getElementById('dmarc-sync-btn');
    const btnText = document.getElementById('dmarc-sync-btn-text');

    if (!dmarcImapStatus || !dmarcImapStatus.enabled) {
        showToast('IMAP sync is not enabled', 'error');
        return;
    }

    btn.disabled = true;
    btnText.textContent = 'Syncing...';

    try {
        const response = await authenticatedFetch('/api/dmarc/imap/sync', {
            method: 'POST'
        });

        const result = await response.json();

        if (result.status === 'already_running') {
            showToast('Sync is already in progress', 'info');
        } else if (result.status === 'started') {
            showToast('IMAP sync started', 'success');

            // Immediate UI update to show "Running" state
            await loadDmarcImapStatus();

            // Delayed update to catch the final result (success/fail)
            setTimeout(async () => {
                await loadDmarcImapStatus();
                await loadDmarcDomains();
            }, 5000); // Increased to 5s to give the sync time to work
        }

    } catch (error) {
        console.error('Error triggering sync:', error);
        showToast('Failed to start sync', 'error');
    } finally {
        btn.disabled = false;
        btnText.textContent = 'Sync from IMAP';
    }
}


async function showDmarcSyncHistory() {
    const modal = document.getElementById('dmarc-sync-history-modal');
    const content = document.getElementById('dmarc-sync-history-content');

    modal.classList.remove('hidden');

    const closeOnBackdrop = (e) => {
        if (e.target === modal) {
            closeDmarcSyncHistoryModal();
            modal.removeEventListener('click', closeOnBackdrop);
        }
    };
    modal.addEventListener('click', closeOnBackdrop);

    try {
        const response = await authenticatedFetch('/api/dmarc/imap/history?limit=20');
        const data = await response.json();

        if (data.data.length === 0) {
            content.innerHTML = '<p class="text-center py-12 text-gray-500">No sync history yet</p>';
            return;
        }

        content.innerHTML = `
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                    <thead class="bg-gray-50 dark:bg-gray-700">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Date</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                            <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Emails</th>
                            <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Created</th>
                            <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Duplicate</th>
                            <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Failed</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Duration</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                        ${data.data.map(sync => {
            const statusClass = sync.status === 'success' ? 'text-green-600' :
                sync.status === 'error' ? 'text-red-600' : 'text-blue-600';
            const date = formatDate(sync.started_at);
            const duration = sync.duration_seconds ? `${Math.round(sync.duration_seconds)}s` : '-';

            return `
                                <tr class="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                                    <td class="px-6 py-4 text-sm text-gray-900 dark:text-white">${date}</td>
                                    <td class="px-6 py-4 text-sm">
                                        <span class="px-2 py-1 rounded text-xs ${sync.sync_type === 'manual' ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-800'}">
                                            ${sync.sync_type}
                                        </span>
                                    </td>
                                    <td class="px-6 py-4 text-sm font-medium ${statusClass}">${sync.status}</td>
                                    <td class="px-6 py-4 text-sm text-right text-gray-900 dark:text-white">${sync.emails_found || 0}</td>
                                    <td class="px-6 py-4 text-sm text-right text-green-600">${sync.reports_created || 0}</td>
                                    <td class="px-6 py-4 text-sm text-right text-gray-500">${sync.reports_duplicate || 0}</td>
                                    <td class="px-6 py-4 text-sm text-right ${sync.reports_failed > 0 ? 'text-red-600' : 'text-gray-900 dark:text-white'}">${sync.reports_failed || 0}</td>
                                    <td class="px-6 py-4 text-sm text-gray-900 dark:text-white">${duration}</td>
                                </tr>
                            `;
        }).join('')}
                    </tbody>
                </table>
            </div>
        `;

    } catch (error) {
        console.error('Error loading sync history:', error);
        content.innerHTML = '<p class="text-center py-12 text-red-500">Failed to load sync history</p>';
    }
}

function closeDmarcSyncHistoryModal() {
    document.getElementById('dmarc-sync-history-modal').classList.add('hidden');
}

// =============================================================================
// REPORTS MANAGEMENT
// =============================================================================

async function showReportsManagementModal() {
    const modal = document.getElementById('dmarc-reports-management-modal');
    const content = document.getElementById('dmarc-reports-management-content');

    modal.classList.remove('hidden');

    const closeOnBackdrop = (e) => {
        if (e.target === modal) {
            closeReportsManagementModal();
            modal.removeEventListener('click', closeOnBackdrop);
        }
    };
    modal.addEventListener('click', closeOnBackdrop);

    // Show loading
    content.innerHTML = `
        <div class="text-center py-12">
            <div class="loading mx-auto mb-4"></div>
            <p class="text-gray-500 dark:text-gray-400">Loading reports...</p>
        </div>
    `;

    try {
        const response = await authenticatedFetch('/api/dmarc/reports/all');
        const data = await response.json();

        renderReportsManagementTable(data.reports || [], data.allow_delete);

    } catch (error) {
        console.error('Error loading reports:', error);
        content.innerHTML = '<p class="text-center py-12 text-red-500">Failed to load reports</p>';
    }
}

function closeReportsManagementModal() {
    document.getElementById('dmarc-reports-management-modal').classList.add('hidden');
}

function renderReportsManagementTable(reports, allowDelete) {
    const content = document.getElementById('dmarc-reports-management-content');

    if (reports.length === 0) {
        content.innerHTML = `
            <div class="text-center py-12">
                <svg class="w-12 h-12 mx-auto text-gray-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                </svg>
                <p class="text-gray-500 dark:text-gray-400">No reports found</p>
            </div>
        `;
        return;
    }

    const deleteHeader = allowDelete ? '<th class="px-4 py-3 text-center text-xs font-bold text-gray-600 dark:text-gray-400 uppercase">Actions</th>' : '';
    const deleteHeaderMobile = allowDelete ? 'Actions' : '';

    content.innerHTML = `
        <div class="mb-4 flex justify-between items-center">
            <p class="text-sm text-gray-600 dark:text-gray-400">
                Total: <span class="font-bold">${reports.length}</span> reports
                ${!allowDelete ? '<span class="ml-2 text-xs text-yellow-600 dark:text-yellow-400">(Deletion disabled)</span>' : ''}
            </p>
        </div>
        
        <!-- Desktop Table -->
        <div class="hidden md:block overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead class="bg-gray-50 dark:bg-gray-700">
                    <tr>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-600 dark:text-gray-400 uppercase">Import Date</th>
                        <th class="px-4 py-3 text-center text-xs font-bold text-gray-600 dark:text-gray-400 uppercase">Type</th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-600 dark:text-gray-400 uppercase">Domain</th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-600 dark:text-gray-400 uppercase">Reporter</th>
                        <th class="px-4 py-3 text-right text-xs font-bold text-gray-600 dark:text-gray-400 uppercase">Records</th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-600 dark:text-gray-400 uppercase">Period</th>
                        ${deleteHeader}
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                    ${reports.map(report => {
        const importDate = report.created_at ? new Date(report.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '-';
        const beginDate = report.begin_date ? new Date(report.begin_date * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '-';
        const endDate = report.end_date ? new Date(report.end_date * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '-';
        const typeClass = report.type === 'dmarc' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400' : 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400';
        const deleteBtn = allowDelete ? `
                            <td class="px-4 py-3 text-center">
                                <button onclick="deleteReport('${report.type}', ${report.id}, '${escapeHtml(report.domain)}')" 
                                    class="text-red-500 hover:text-red-700 dark:hover:text-red-400 transition-colors" title="Delete report">
                                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                                    </svg>
                                </button>
                            </td>
                        ` : '';

        return `
                            <tr class="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                                <td class="px-4 py-3 text-sm text-gray-900 dark:text-white">${importDate}</td>
                                <td class="px-4 py-3 text-center">
                                    <span class="px-2 py-1 text-xs font-bold rounded ${typeClass}">${report.type.toUpperCase()}</span>
                                </td>
                                <td class="px-4 py-3 text-sm font-medium text-gray-900 dark:text-white">${escapeHtml(report.domain)}</td>
                                <td class="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">${escapeHtml(report.org_name || '-')}</td>
                                <td class="px-4 py-3 text-sm text-right text-gray-900 dark:text-white font-medium">${report.record_count}</td>
                                <td class="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">${beginDate} - ${endDate}</td>
                                ${deleteBtn}
                            </tr>
                        `;
    }).join('')}
                </tbody>
            </table>
        </div>
        
        <!-- Mobile Cards -->
        <div class="md:hidden space-y-3">
            ${reports.map(report => {
        const importDate = report.created_at ? new Date(report.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '-';
        const beginDate = report.begin_date ? new Date(report.begin_date * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '-';
        const endDate = report.end_date ? new Date(report.end_date * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '-';
        const typeClass = report.type === 'dmarc' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400' : 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400';
        const deleteBtn = allowDelete ? `
                    <button onclick="deleteReport('${report.type}', ${report.id}, '${escapeHtml(report.domain)}')" 
                        class="text-red-500 hover:text-red-700 p-1" title="Delete">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                        </svg>
                    </button>
                ` : '';

        return `
                    <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                        <div class="flex justify-between items-start mb-2">
                            <div>
                                <span class="px-2 py-0.5 text-xs font-bold rounded ${typeClass}">${report.type.toUpperCase()}</span>
                                <span class="ml-2 text-sm font-medium text-gray-900 dark:text-white">${escapeHtml(report.domain)}</span>
                            </div>
                            ${deleteBtn}
                        </div>
                        <div class="grid grid-cols-2 gap-2 text-xs">
                            <div><span class="text-gray-500">Reporter:</span> <span class="text-gray-900 dark:text-white">${escapeHtml(report.org_name || '-')}</span></div>
                            <div><span class="text-gray-500">Records:</span> <span class="font-bold text-gray-900 dark:text-white">${report.record_count}</span></div>
                            <div><span class="text-gray-500">Imported:</span> <span class="text-gray-900 dark:text-white">${importDate}</span></div>
                            <div><span class="text-gray-500">Period:</span> <span class="text-gray-900 dark:text-white">${beginDate} - ${endDate}</span></div>
                        </div>
                    </div>
                `;
    }).join('')}
        </div>
    `;
}

async function deleteReport(reportType, reportId, domain) {
    if (!confirm(`Are you sure you want to delete this ${reportType.toUpperCase()} report for ${domain}?\n\nThis action cannot be undone.`)) {
        return;
    }

    try {
        const response = await authenticatedFetch(`/api/dmarc/reports/${reportType}/${reportId}`, {
            method: 'DELETE'
        });

        if (response.status === 403) {
            showToast('Report deletion is disabled', 'error');
            return;
        }

        if (!response.ok) {
            throw new Error('Failed to delete report');
        }

        showToast(`${reportType.toUpperCase()} report deleted`, 'success');

        // Refresh the modal
        await showReportsManagementModal();

        // Refresh domains list if visible
        if (dmarcState.currentView === 'domains') {
            await loadDmarcDomains();
        }

    } catch (error) {
        console.error('Error deleting report:', error);
        showToast('Failed to delete report', 'error');
    }
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
    modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
    modal.innerHTML = `
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-2xl w-full mx-4 max-h-[80vh] overflow-hidden flex flex-col">
            <div class="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white">${escapeHtml(title)}</h3>
                <button onclick="closeConnectionTestModal()" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                </button>
            </div>
            <div class="p-4 overflow-y-auto flex-1">
                <div id="connection-test-content" class="space-y-2">
                    <div class="flex items-center gap-2 text-gray-600 dark:text-gray-400">
                        <div class="loading"></div>
                        <span>${escapeHtml(message)}</span>
                    </div>
                </div>
            </div>
            <div class="p-4 border-t border-gray-200 dark:border-gray-700 flex justify-end">
                <button onclick="closeConnectionTestModal()" class="px-4 py-2 bg-gray-500 hover:bg-gray-600 text-white rounded transition-colors">
                    Close
                </button>
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

    const statusColor = status === 'success' ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400';
    const statusIcon = status === 'success' ?
        '<svg class="w-6 h-6" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path></svg>' :
        '<svg class="w-6 h-6" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path></svg>';

    content.innerHTML = `
        <div class="flex items-center gap-3 mb-4 p-3 rounded ${status === 'success' ? 'bg-green-50 dark:bg-green-900/20' : 'bg-red-50 dark:bg-red-900/20'}">
            <div class="${statusColor}">
                ${statusIcon}
            </div>
            <span class="font-semibold ${statusColor}">
                ${status === 'success' ? 'Connection Successful' : 'Connection Failed'}
            </span>
        </div>
        <div class="bg-gray-900 text-gray-100 p-4 rounded font-mono text-xs overflow-x-auto">
            ${logs.map(log => {
        let color = 'text-gray-300';
        if (log.includes('✓')) color = 'text-green-400';
        if (log.includes('✗') || log.includes('ERROR')) color = 'text-red-400';
        if (log.includes('WARNING')) color = 'text-yellow-400';
        return `<div class="${color}">${escapeHtml(log)}</div>`;
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
// HELP DOCUMENTATION MODAL
// =============================================================================

async function showHelpModal(docName) {
    try {
        const response = await authenticatedFetch(`/api/docs/${docName}`);

        if (!response.ok) {
            throw new Error(`Failed to load documentation: ${response.statusText}`);
        }

        const markdown = await response.text();

        let htmlContent = markdown;
        if (typeof marked !== 'undefined') {
            marked.setOptions({
                breaks: true,
                gfm: true
            });
            htmlContent = marked.parse(markdown);
        }

        const modal = document.getElementById('changelog-modal');
        const modalTitle = modal?.querySelector('h3');
        const content = document.getElementById('changelog-content');

        if (modal && content) {
            if (modalTitle) {
                modalTitle.textContent = `Help - ${docName}`;
            }

            content.innerHTML = htmlContent;
            modal.classList.remove('hidden');
            document.body.style.overflow = 'hidden';
        }
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
// MAILBOX STATISTICS - REDESIGNED WITH MESSAGE COUNTS
// =============================================================================

// Cached mailbox stats data
let mailboxStatsCache = {
    summary: null,
    mailboxes: null,
    domains: null,
    lastLoad: null,
    expandedMailboxes: new Set() // Track expanded accordion states
};

async function loadMailboxStats() {
    console.log('Loading mailbox statistics...');

    // Show loading state
    const loading = document.getElementById('mailbox-stats-loading');
    const content = document.getElementById('mailbox-stats-content');

    if (loading) loading.classList.remove('hidden');
    if (content) content.classList.add('hidden');

    try {
        const dateRange = document.getElementById('mailbox-stats-date-range')?.value || '30days';
        const customStartDate = document.getElementById('mailbox-stats-start-date')?.value || '';
        const customEndDate = document.getElementById('mailbox-stats-end-date')?.value || '';

        // Build summary URL with optional custom date range
        let summaryUrl = `/api/mailbox-stats/summary?date_range=${dateRange}`;
        if (dateRange === 'custom' && customStartDate && customEndDate) {
            summaryUrl += `&start_date=${encodeURIComponent(customStartDate)}&end_date=${encodeURIComponent(customEndDate)}`;
        }

        // Load summary and domains in parallel
        const [summaryRes, domainsRes] = await Promise.all([
            authenticatedFetch(summaryUrl),
            authenticatedFetch('/api/mailbox-stats/domains')
        ]);

        if (!summaryRes.ok || !domainsRes.ok) {
            throw new Error('Failed to fetch mailbox statistics');
        }

        const summary = await summaryRes.json();
        const domains = await domainsRes.json();

        mailboxStatsCache.summary = summary;
        mailboxStatsCache.domains = domains.domains || [];

        // Render summary cards
        renderMailboxStatsSummary(summary);

        // Populate domain filter
        populateMailboxStatsDomainFilter(mailboxStatsCache.domains);

        // Load all mailboxes
        await loadMailboxStatsList();

        // Update last update time
        const lastUpdateEl = document.getElementById('mailbox-stats-last-update');
        if (lastUpdateEl && summary.last_update) {
            lastUpdateEl.textContent = `Last updated: ${formatTime(summary.last_update)}`;
        }

        // Show content, hide loading
        if (loading) loading.classList.add('hidden');
        if (content) content.classList.remove('hidden');

        mailboxStatsCache.lastLoad = new Date();

    } catch (error) {
        console.error('Error loading mailbox stats:', error);
        if (loading) {
            loading.innerHTML = `
                <div class="text-center py-12">
                    <svg class="w-12 h-12 text-red-500 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                    <p class="text-red-500 mb-2">Failed to load mailbox statistics</p>
                    <p class="text-gray-500 dark:text-gray-400 text-sm">${error.message}</p>
                    <button onclick="loadMailboxStats()" class="mt-4 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">Retry</button>
                </div>
            `;
        }
    }
}

function refreshMailboxStats() {
    loadMailboxStats();
}

function renderMailboxStatsSummary(summary) {
    // Update summary cards (new 4-card design: Sent, Received, Failed, Failure Rate)
    const sentEl = document.getElementById('mailbox-stats-sent');
    const receivedEl = document.getElementById('mailbox-stats-received');
    const failedEl = document.getElementById('mailbox-stats-failed');
    const failureRateEl = document.getElementById('mailbox-stats-failure-rate');

    if (sentEl) sentEl.textContent = (summary.total_sent || 0).toLocaleString();
    if (receivedEl) receivedEl.textContent = (summary.total_received || 0).toLocaleString();
    if (failedEl) failedEl.textContent = (summary.sent_failed || 0).toLocaleString();
    if (failureRateEl) failureRateEl.textContent = `${summary.failure_rate || 0}%`;

    // Update date labels based on selected range
    const dateRange = document.getElementById('mailbox-stats-date-range')?.value || '30days';
    let dateLabel;

    if (dateRange === 'custom') {
        const startDate = document.getElementById('mailbox-stats-start-date')?.value;
        const endDate = document.getElementById('mailbox-stats-end-date')?.value;
        if (startDate && endDate) {
            dateLabel = `${formatDateShort(startDate)} - ${formatDateShort(endDate)}`;
        } else {
            dateLabel = 'Custom Range';
        }
    } else {
        dateLabel = dateRange === 'today' ? 'Today' :
            dateRange === '7days' ? 'Last 7 days' :
                dateRange === '90days' ? 'Last 90 days' : 'Last 30 days';
    }

    ['sent', 'recv', 'failed', 'rate'].forEach(s => {
        const el = document.getElementById(`mailbox-stats-date-label-${s}`);
        if (el) el.textContent = dateLabel;
    });
}

function populateMailboxStatsDomainFilter(domains) {
    const select = document.getElementById('mailbox-stats-domain-filter');
    if (!select) return;

    // Clear existing options except "All Domains"
    select.innerHTML = '<option value="">All Domains</option>';

    // Add domain options
    domains.forEach(d => {
        const option = document.createElement('option');
        option.value = d.domain;
        option.textContent = `${d.domain} (${d.mailbox_count})`;
        select.appendChild(option);
    });
}

// Current page for pagination
let mailboxStatsPage = 1;

async function loadMailboxStatsList(page = 1) {
    mailboxStatsPage = page;
    const dateRange = document.getElementById('mailbox-stats-date-range')?.value || '30days';
    const customStartDate = document.getElementById('mailbox-stats-start-date')?.value || '';
    const customEndDate = document.getElementById('mailbox-stats-end-date')?.value || '';
    const domainFilter = document.getElementById('mailbox-stats-domain-filter')?.value || '';
    const sortValue = document.getElementById('mailbox-stats-sort')?.value || 'sent_total-desc';
    const activeOnly = document.getElementById('mailbox-stats-active-only')?.checked ?? true;
    const hideZero = document.getElementById('mailbox-stats-hide-zero')?.checked ?? false;
    const search = document.getElementById('mailbox-stats-search')?.value || '';

    const [sortBy, sortOrder] = sortValue.split('-');

    let url = `/api/mailbox-stats/all?date_range=${dateRange}&sort_by=${sortBy}&sort_order=${sortOrder}&page=${page}&page_size=50`;

    // Add custom date range parameters if using custom mode
    if (dateRange === 'custom' && customStartDate && customEndDate) {
        url += `&start_date=${encodeURIComponent(customStartDate)}&end_date=${encodeURIComponent(customEndDate)}`;
    }

    if (domainFilter) url += `&domain=${encodeURIComponent(domainFilter)}`;
    if (activeOnly) url += '&active_only=true';
    else url += '&active_only=false';
    if (hideZero) url += '&hide_zero=true';
    if (search) url += `&search=${encodeURIComponent(search)}`;

    try {
        const response = await authenticatedFetch(url);
        if (!response.ok) throw new Error('Failed to fetch mailboxes');

        const data = await response.json();
        mailboxStatsCache.mailboxes = data.mailboxes || [];

        // Update count
        const countEl = document.getElementById('mailbox-stats-count');
        if (countEl) countEl.textContent = `${data.total || 0} mailboxes`;

        // Update pagination info
        const pageInfoEl = document.getElementById('mailbox-stats-page-info');
        if (pageInfoEl && data.total_pages > 1) {
            pageInfoEl.textContent = `Page ${data.page} of ${data.total_pages}`;
        } else if (pageInfoEl) {
            pageInfoEl.textContent = '';
        }

        renderMailboxStatsAccordion(data.mailboxes || [], data.page, data.total_pages);

    } catch (error) {
        console.error('Error loading mailbox list:', error);
    }
}

function renderMailboxStatsAccordion(mailboxes, page = 1, totalPages = 1) {
    const container = document.getElementById('mailbox-stats-list');
    if (!container) return;

    if (mailboxes.length === 0) {
        container.innerHTML = `
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-8 text-center">
                <svg class="w-12 h-12 text-gray-400 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"></path>
                </svg>
                <p class="text-gray-500 dark:text-gray-400">No mailboxes found</p>
            </div>
        `;
        return;
    }

    // Build mailbox rows first
    let html = mailboxes.map((mb, index) => {
        const isExpanded = mailboxStatsCache.expandedMailboxes.has(mb.username);
        const statusClass = mb.active
            ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
            : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300';

        // Failure rate color
        const failureColor = mb.combined_failure_rate >= 10 ? 'text-red-600 dark:text-red-400'
            : mb.combined_failure_rate >= 5 ? 'text-yellow-600 dark:text-yellow-400'
                : 'text-green-600 dark:text-green-400';

        // Quota bar
        const quotaPercent = mb.percent_in_use || 0;
        const quotaColor = quotaPercent >= 90 ? 'bg-red-500' : quotaPercent >= 75 ? 'bg-yellow-500' : 'bg-blue-500';

        return `
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden mb-2">
                <!-- Accordion Header -->
                <div onclick="toggleMailboxAccordion('${escapeHtml(mb.username)}')" 
                     class="cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
                    <div class="px-4 py-3">
                        <!-- Desktop: 3-column grid | Mobile: stacked layout -->
                        <div class="hidden md:grid md:grid-cols-3 items-center gap-2">
                            <!-- Zone 1: Mailbox Info (Desktop) -->
                            <div class="flex items-center gap-3 min-w-0">
                                <svg id="accordion-icon-${index}" class="w-5 h-5 text-gray-400 transition-transform flex-shrink-0 ml-1 ${isExpanded ? 'rotate-90' : ''}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                                </svg>
                                <div class="min-w-0">
                                    <div class="font-medium text-gray-900 dark:text-white truncate">${escapeHtml(mb.username)}</div>
                                    <div class="flex items-center gap-2 mt-0.5">
                                        <span class="px-2 py-0.5 text-xs font-medium rounded-full ${statusClass}">${mb.active ? 'Active' : 'Inactive'}</span>
                                        ${mb.name ? `<span class="text-xs text-gray-500 dark:text-gray-400 truncate">${escapeHtml(mb.name)}</span>` : ''}
                                    </div>
                                </div>
                            </div>
                            
                            <!-- Zone 2: Stats Badges (Desktop - center) -->
                            <div class="flex flex-row items-center justify-center gap-1">
                                <span class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium ${getDirectionBadgeClass('outbound')} whitespace-nowrap">
                                    ↑ ${mb.combined_sent.toLocaleString()} Sent
                                </span>
                                <span class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium ${getDirectionBadgeClass('inbound')} whitespace-nowrap">
                                    ↓ ${mb.combined_received.toLocaleString()} Received
                                </span>
                                <span class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium ${getStatusBadgeClass('delivered')} whitespace-nowrap">
                                    ✓ ${(mb.combined_delivered || 0).toLocaleString()} Delivered
                                </span>
                                <span class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium ${getStatusBadgeClass('bounced')} whitespace-nowrap">
                                    ${mb.combined_failure_rate}% Failed
                                </span>
                            </div>
                            
                            <!-- Zone 3: Aliases + Storage (Desktop - right) -->
                            <div class="flex items-center justify-end gap-6">
                                <div class="text-center">
                                    <p class="text-xs text-gray-500 dark:text-gray-400">Aliases</p>
                                    <p class="text-sm font-semibold text-gray-900 dark:text-white">${mb.alias_count || 0}</p>
                                </div>
                                <div class="text-center">
                                    <p class="text-xs text-gray-500 dark:text-gray-400">Storage</p>
                                    <p class="text-sm font-semibold text-gray-900 dark:text-white">${mb.quota_used_formatted}</p>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Mobile Layout: Stacked -->
                        <div class="md:hidden">
                            <!-- Row 1: Arrow + Email + Active indicator on right -->
                            <div class="flex items-center gap-3">
                                <svg id="accordion-icon-mobile-${index}" class="w-5 h-5 text-gray-400 transition-transform flex-shrink-0 ${isExpanded ? 'rotate-90' : ''}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                                </svg>
                                <div class="min-w-0 flex-1">
                                    <div class="font-medium text-gray-900 dark:text-white">${escapeHtml(mb.username)}</div>
                                </div>
                                <!-- Active indicator dot on right -->
                                <div class="flex items-center gap-1.5 flex-shrink-0">
                                    <span class="w-2.5 h-2.5 rounded-full ${mb.active ? 'bg-green-500' : 'bg-red-500'}"></span>
                                    <span class="text-xs text-gray-500 dark:text-gray-400">${mb.active ? 'Active' : 'Inactive'}</span>
                                </div>
                            </div>
                            
                            <!-- Row 2: Direction badges (Sent, Received) -->
                            <div class="flex gap-1 mt-2 ml-8">
                                <span class="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium ${getDirectionBadgeClass('outbound')} whitespace-nowrap">
                                    ↑ ${mb.combined_sent.toLocaleString()} Sent
                                </span>
                                <span class="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium ${getDirectionBadgeClass('inbound')} whitespace-nowrap">
                                    ↓ ${mb.combined_received.toLocaleString()} Received
                                </span>
                            </div>
                            
                            <!-- Row 3: Status badges (Delivered, Failed) -->
                            <div class="flex gap-1 mt-1 ml-8">
                                <span class="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium ${getStatusBadgeClass('delivered')} whitespace-nowrap">
                                    ✓ ${(mb.combined_delivered || 0).toLocaleString()} Delivered
                                </span>
                                <span class="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium ${getStatusBadgeClass('bounced')} whitespace-nowrap">
                                    ${mb.combined_failure_rate}% Failed
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Accordion Content (Domains-style layout) -->
                <div id="accordion-content-${index}" class="${isExpanded ? '' : 'hidden'} border-t border-gray-200 dark:border-gray-700">
                    <!-- Mailbox Info Section -->
                    <div class="p-6 bg-gray-50 dark:bg-gray-700/30">
                        <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
                            <div>
                                <p class="text-xs text-gray-500 dark:text-gray-400 font-medium mb-1">Quota Used</p>
                                <p class="text-lg font-bold text-gray-900 dark:text-white">${mb.quota_used_formatted} / ${mb.quota_formatted}</p>
                                <p class="text-xs text-gray-500 dark:text-gray-400">${mb.percent_in_use || 0}% used</p>
                            </div>
                            <div>
                                <p class="text-xs text-gray-500 dark:text-gray-400 font-medium mb-1">Messages in Mailbox</p>
                                <p class="text-lg font-bold text-gray-900 dark:text-white">${(mb.messages_in_mailbox || 0).toLocaleString()}</p>
                            </div>
                            <div>
                                <p class="text-xs text-gray-500 dark:text-gray-400 font-medium mb-1">Created / Modified</p>
                                <p class="text-xs text-gray-900 dark:text-white">${mb.created ? formatTime(mb.created) : 'N/A'}</p>
                                <p class="text-xs text-gray-500 dark:text-gray-400">${mb.modified ? formatTime(mb.modified) : 'N/A'}</p>
                            </div>
                            <div>
                                <p class="text-xs text-gray-500 dark:text-gray-400 font-medium mb-1">Rate Limit</p>
                                <p class="text-sm font-semibold text-gray-900 dark:text-white">${mb.rl_value ? mb.rl_value + '/' + (mb.rl_frame === 's' ? 'sec' : mb.rl_frame === 'm' ? 'min' : mb.rl_frame === 'h' ? 'hour' : mb.rl_frame === 'd' ? 'day' : mb.rl_frame || 'min') : 'None'}</p>
                            </div>
                        </div>
                        
                        <!-- Access Permissions with Last Login Dates -->
                        <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 mt-4 pt-4 border-t border-gray-200 dark:border-gray-600">
                            <div class="flex flex-col">
                                <div class="flex items-center gap-2">
                                    <span class="w-2 h-2 rounded-full ${mb.attributes?.imap_access === '1' ? 'bg-green-500' : 'bg-red-500'}"></span>
                                    <span class="text-xs font-medium text-gray-700 dark:text-gray-300">IMAP</span>
                                </div>
                                <span class="text-xs text-gray-500 dark:text-gray-400 ml-4">${mb.last_imap_login ? formatTime(mb.last_imap_login) : 'Never'}</span>
                            </div>
                            <div class="flex flex-col">
                                <div class="flex items-center gap-2">
                                    <span class="w-2 h-2 rounded-full ${mb.attributes?.pop3_access === '1' ? 'bg-green-500' : 'bg-red-500'}"></span>
                                    <span class="text-xs font-medium text-gray-700 dark:text-gray-300">POP3</span>
                                </div>
                                <span class="text-xs text-gray-500 dark:text-gray-400 ml-4">${mb.last_pop3_login ? formatTime(mb.last_pop3_login) : 'Never'}</span>
                            </div>
                            <div class="flex flex-col">
                                <div class="flex items-center gap-2">
                                    <span class="w-2 h-2 rounded-full ${mb.attributes?.smtp_access === '1' ? 'bg-green-500' : 'bg-red-500'}"></span>
                                    <span class="text-xs font-medium text-gray-700 dark:text-gray-300">SMTP</span>
                                </div>
                                <span class="text-xs text-gray-500 dark:text-gray-400 ml-4">${mb.last_smtp_login ? formatTime(mb.last_smtp_login) : 'Never'}</span>
                            </div>
                            <div class="flex flex-col">
                                <div class="flex items-center gap-2">
                                    <span class="w-2 h-2 rounded-full ${mb.attributes?.sieve_access === '1' ? 'bg-green-500' : 'bg-red-500'}"></span>
                                    <span class="text-xs font-medium text-gray-700 dark:text-gray-300">Sieve</span>
                                </div>
                            </div>
                            <div class="flex flex-col">
                                <div class="flex items-center gap-2">
                                    <span class="w-2 h-2 rounded-full ${mb.attributes?.tls_enforce_in === '1' || mb.attributes?.tls_enforce_out === '1' ? 'bg-green-500' : 'bg-gray-400'}"></span>
                                    <span class="text-xs font-medium text-gray-700 dark:text-gray-300">TLS Enforce</span>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Message Stats Section -->
                    <div class="p-6">
                        <h4 class="text-sm font-semibold text-gray-900 dark:text-white mb-4">Message Statistics</h4>
                        
                        <!-- Direction Stats Row -->
                        <div class="grid grid-cols-3 gap-2 mb-4">
                            <div class="p-3 ${getDirectionBgClass('outbound')} rounded-lg text-center cursor-pointer hover:opacity-80 transition-opacity"
                                 onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeHtml(mb.username)}', filterType: 'search', direction: 'outbound' })">
                                <div class="text-xl font-bold ${getDirectionTextClass('outbound')}">${mb.combined_sent || 0}</div>
                                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">Sent</div>
                            </div>
                            <div class="p-3 ${getDirectionBgClass('inbound')} rounded-lg text-center cursor-pointer hover:opacity-80 transition-opacity"
                                 onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeHtml(mb.username)}', filterType: 'search', direction: 'inbound' })">
                                <div class="text-xl font-bold ${getDirectionTextClass('inbound')}">${mb.combined_received || 0}</div>
                                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">Received</div>
                            </div>
                            <div class="p-3 ${getDirectionBgClass('internal')} rounded-lg text-center cursor-pointer hover:opacity-80 transition-opacity"
                                 onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeHtml(mb.username)}', filterType: 'search', direction: 'internal' })">
                                <div class="text-xl font-bold ${getDirectionTextClass('internal')}">${mb.combined_internal || 0}</div>
                                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">Internal</div>
                            </div>
                        </div>
                        
                        <!-- Status Stats Row -->
                        <div class="grid grid-cols-4 gap-2">
                            <div class="p-3 ${getStatusBgClass('delivered')} rounded-lg text-center cursor-pointer hover:opacity-80 transition-opacity"
                                 onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeHtml(mb.username)}', filterType: 'search', status: 'delivered' })">
                                <div class="text-xl font-bold ${getStatusTextClass('delivered')}">${mb.combined_delivered || 0}</div>
                                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">Delivered</div>
                            </div>
                            <div class="p-3 ${getStatusBgClass('deferred')} rounded-lg text-center cursor-pointer hover:opacity-80 transition-opacity"
                                 onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeHtml(mb.username)}', filterType: 'search', status: 'deferred' })">
                                <div class="text-xl font-bold ${getStatusTextClass('deferred')}">${(mb.mailbox_counts?.sent_deferred || 0) + (mb.aliases || []).reduce((sum, a) => sum + (a.sent_deferred || 0), 0)}</div>
                                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">Deferred</div>
                            </div>
                            <div class="p-3 ${getStatusBgClass('bounced')} rounded-lg text-center cursor-pointer hover:opacity-80 transition-opacity"
                                 onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeHtml(mb.username)}', filterType: 'search', status: 'bounced' })">
                                <div class="text-xl font-bold ${getStatusTextClass('bounced')}">${(mb.mailbox_counts?.sent_bounced || 0) + (mb.aliases || []).reduce((sum, a) => sum + (a.sent_bounced || 0), 0)}</div>
                                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">Bounced</div>
                            </div>
                            <div class="p-3 ${getStatusBgClass('rejected')} rounded-lg text-center cursor-pointer hover:opacity-80 transition-opacity"
                                 onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeHtml(mb.username)}', filterType: 'search', status: 'rejected' })">
                                <div class="text-xl font-bold ${getStatusTextClass('rejected')}">${(mb.mailbox_counts?.sent_rejected || 0) + (mb.aliases || []).reduce((sum, a) => sum + (a.sent_rejected || 0), 0)}</div>
                                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">Rejected</div>
                            </div>
                        </div>
                    </div>
                        
                    <!-- Aliases Section -->
                    ${mb.aliases && mb.aliases.length > 0 ? `
                        <div class="p-6 border-t border-gray-200 dark:border-gray-700">
                            <h4 class="text-sm font-semibold text-gray-900 dark:text-white mb-4">Aliases (${mb.aliases.length})</h4>
                            <div class="overflow-x-auto">
                                <table class="min-w-full text-sm">
                                    <thead>
                                        <tr class="text-xs text-gray-500 dark:text-gray-400 uppercase">
                                            <th class="text-left py-2 pr-4">Alias</th>
                                            <th class="text-center py-2 px-2">Sent</th>
                                            <th class="text-center py-2 px-2">Received</th>
                                            <th class="text-center py-2 px-2">Internal</th>
                                            <th class="text-center py-2 px-2">Delivered</th>
                                            <th class="text-center py-2 px-2">Deferred</th>
                                            <th class="text-center py-2 px-2">Bounced</th>
                                            <th class="text-center py-2 px-2">Rejected</th>
                                            <th class="text-center py-2 pl-2">Fail %</th>
                                        </tr>
                                    </thead>
                                    <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
                                        ${(() => {
                    const hideZero = document.getElementById('mailbox-stats-hide-zero')?.checked ?? true;
                    const filteredAliases = hideZero
                        ? mb.aliases.filter(a => (a.sent_total || 0) + (a.received_total || 0) > 0)
                        : mb.aliases;
                    return filteredAliases.map(alias => `
                                                <tr class="hover:bg-gray-50 dark:hover:bg-gray-700/30">
                                                    <td class="py-2 pr-4">
                                                        <div class="flex items-center gap-2">
                                                            <span class="text-gray-900 dark:text-white">${escapeHtml(alias.alias_address)}</span>
                                                            ${alias.is_catch_all ? '<span class="px-1.5 py-0.5 text-xs bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300 rounded">catch-all</span>' : ''}
                                                            ${!alias.active ? '<span class="px-1.5 py-0.5 text-xs bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400 rounded">inactive</span>' : ''}
                                                        </div>
                                                    </td>
                                                    <td class="text-center py-2 px-2 ${getDirectionTextClass('outbound')} cursor-pointer hover:underline" onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeHtml(alias.alias_address)}', filterType: 'search', direction: 'outbound' })">${alias.sent_total || 0}</td>
                                                    <td class="text-center py-2 px-2 ${getDirectionTextClass('inbound')} cursor-pointer hover:underline" onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeHtml(alias.alias_address)}', filterType: 'search', direction: 'inbound' })">${alias.received_total || 0}</td>
                                                    <td class="text-center py-2 px-2 ${getDirectionTextClass('internal')} cursor-pointer hover:underline" onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeHtml(alias.alias_address)}', filterType: 'search', direction: 'internal' })">${alias.direction_internal || 0}</td>
                                                    <td class="text-center py-2 px-2 ${getStatusTextClass('delivered')} cursor-pointer hover:underline" onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeHtml(alias.alias_address)}', filterType: 'search', status: 'delivered' })">${alias.sent_delivered || 0}</td>
                                                    <td class="text-center py-2 px-2 ${getStatusTextClass('deferred')} cursor-pointer hover:underline" onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeHtml(alias.alias_address)}', filterType: 'search', status: 'deferred' })">${alias.sent_deferred || 0}</td>
                                                    <td class="text-center py-2 px-2 ${getStatusTextClass('bounced')} cursor-pointer hover:underline" onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeHtml(alias.alias_address)}', filterType: 'search', status: 'bounced' })">${alias.sent_bounced || 0}</td>
                                                    <td class="text-center py-2 px-2 ${getStatusTextClass('rejected')} cursor-pointer hover:underline" onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeHtml(alias.alias_address)}', filterType: 'search', status: 'rejected' })">${alias.sent_rejected || 0}</td>
                                                    <td class="text-center py-2 pl-2 ${alias.failure_rate >= 5 ? 'text-red-600 dark:text-red-400' : 'text-gray-500'}">${alias.failure_rate || 0}%</td>
                                                </tr>
                                            `).join('');
                })()}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }).join('');

    // Add pagination controls if there are multiple pages
    if (totalPages > 1) {
        html += `
            <div class="flex items-center justify-center gap-2 mt-4 p-4 bg-white dark:bg-gray-800 rounded-lg shadow">
                <button onclick="loadMailboxStatsPage(1)" ${page === 1 ? 'disabled' : ''} 
                    class="px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded ${page === 1 ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-100 dark:hover:bg-gray-700'}">
                    First
                </button>
                <button onclick="loadMailboxStatsPage(${page - 1})" ${page === 1 ? 'disabled' : ''} 
                    class="px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded ${page === 1 ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-100 dark:hover:bg-gray-700'}">
                    Previous
                </button>
                <span class="px-4 py-1.5 text-sm text-gray-700 dark:text-gray-300">
                    Page ${page} of ${totalPages}
                </span>
                <button onclick="loadMailboxStatsPage(${page + 1})" ${page === totalPages ? 'disabled' : ''} 
                    class="px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded ${page === totalPages ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-100 dark:hover:bg-gray-700'}">
                    Next
                </button>
                <button onclick="loadMailboxStatsPage(${totalPages})" ${page === totalPages ? 'disabled' : ''} 
                    class="px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded ${page === totalPages ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-100 dark:hover:bg-gray-700'}">
                    Last
                </button>
            </div>
        `;
    }

    container.innerHTML = html;
}

function toggleMailboxAccordion(username) {
    const mailboxes = mailboxStatsCache.mailboxes || [];
    const index = mailboxes.findIndex(m => m.username === username);
    if (index === -1) return;

    const content = document.getElementById(`accordion-content-${index}`);
    const icon = document.getElementById(`accordion-icon-${index}`);

    if (content) {
        const isHidden = content.classList.contains('hidden');
        content.classList.toggle('hidden');

        if (isHidden) {
            mailboxStatsCache.expandedMailboxes.add(username);
        } else {
            mailboxStatsCache.expandedMailboxes.delete(username);
        }
    }

    if (icon) {
        icon.classList.toggle('rotate-90');
    }
}

// =============================================================================
// DATE RANGE PICKER
// =============================================================================

// Date range picker state
let dateRangePickerOpen = false;

function toggleDateRangePicker() {
    const dropdown = document.getElementById('date-range-dropdown');
    const arrow = document.getElementById('date-range-arrow');

    if (!dropdown) return;

    dateRangePickerOpen = !dateRangePickerOpen;

    if (dateRangePickerOpen) {
        dropdown.classList.remove('hidden');
        arrow?.classList.add('rotate-180');

        // Set default dates for custom range inputs
        const today = new Date();
        const thirtyDaysAgo = new Date(today);
        thirtyDaysAgo.setDate(today.getDate() - 30);

        const startInput = document.getElementById('date-range-start');
        const endInput = document.getElementById('date-range-end');

        if (startInput && !startInput.value) {
            startInput.value = thirtyDaysAgo.toISOString().split('T')[0];
        }
        if (endInput && !endInput.value) {
            endInput.value = today.toISOString().split('T')[0];
        }

        // Add click outside listener
        setTimeout(() => {
            document.addEventListener('click', closeDateRangePickerOnClickOutside);
        }, 0);
    } else {
        closeDateRangePicker();
    }
}

function closeDateRangePicker() {
    const dropdown = document.getElementById('date-range-dropdown');
    const arrow = document.getElementById('date-range-arrow');

    if (dropdown) dropdown.classList.add('hidden');
    if (arrow) arrow.classList.remove('rotate-180');
    dateRangePickerOpen = false;

    document.removeEventListener('click', closeDateRangePickerOnClickOutside);
}

function closeDateRangePickerOnClickOutside(e) {
    const container = document.getElementById('date-range-picker-container');
    if (container && !container.contains(e.target)) {
        closeDateRangePicker();
    }
}

function selectDatePreset(preset) {
    // Update hidden input
    const hiddenInput = document.getElementById('mailbox-stats-date-range');
    if (hiddenInput) hiddenInput.value = preset;

    // Clear custom date inputs
    document.getElementById('mailbox-stats-start-date').value = '';
    document.getElementById('mailbox-stats-end-date').value = '';

    // Update label
    const labelMap = {
        'today': 'Today',
        '7days': 'Last 7 Days',
        '30days': 'Last 30 Days',
        '90days': 'Last 90 Days'
    };
    const label = document.getElementById('date-range-label');
    if (label) label.textContent = labelMap[preset] || preset;

    // Update active state on buttons
    updateDatePresetButtons(preset);

    // Close dropdown and reload data
    closeDateRangePicker();
    loadMailboxStats();
}

function updateDatePresetButtons(activePreset) {
    const buttons = document.querySelectorAll('.date-preset-btn');
    buttons.forEach(btn => {
        const preset = btn.getAttribute('data-preset');
        if (preset === activePreset) {
            btn.className = 'date-preset-btn px-3 py-1.5 text-xs font-medium rounded-md border border-blue-500 bg-blue-500 text-white transition-colors';
        } else {
            btn.className = 'date-preset-btn px-3 py-1.5 text-xs font-medium rounded-md border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors';
        }
    });
}

function applyCustomDateRange() {
    const startInput = document.getElementById('date-range-start');
    const endInput = document.getElementById('date-range-end');

    if (!startInput?.value || !endInput?.value) {
        showToast('Please select both start and end dates', 'error');
        return;
    }

    const startDate = new Date(startInput.value);
    const endDate = new Date(endInput.value);

    if (startDate > endDate) {
        showToast('Start date must be before end date', 'error');
        return;
    }

    // Set to custom mode
    const hiddenInput = document.getElementById('mailbox-stats-date-range');
    if (hiddenInput) hiddenInput.value = 'custom';

    // Store custom dates
    document.getElementById('mailbox-stats-start-date').value = startInput.value;
    document.getElementById('mailbox-stats-end-date').value = endInput.value;

    // Update label with date range
    const label = document.getElementById('date-range-label');
    if (label) {
        const startFormatted = formatDateShort(startInput.value);
        const endFormatted = formatDateShort(endInput.value);
        label.textContent = `${startFormatted} - ${endFormatted}`;
    }

    // Clear active state on preset buttons (none active for custom)
    updateDatePresetButtons('custom');

    // Close dropdown and reload data
    closeDateRangePicker();
    loadMailboxStats();
}

function formatDateShort(dateStr) {
    const date = new Date(dateStr);
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    const day = date.getDate().toString().padStart(2, '0');
    return `${day}/${month}`;
}

function applyMailboxStatsFilters() {
    loadMailboxStatsList(1); // Reset to page 1 when filters change
}

function resetMailboxStatsFilters() {
    // Reset search
    const searchEl = document.getElementById('mailbox-stats-search');
    if (searchEl) searchEl.value = '';

    // Reset date range to 30 days
    const dateRangeEl = document.getElementById('mailbox-stats-date-range');
    if (dateRangeEl) dateRangeEl.value = '30days';

    // Reset custom date inputs
    const startDateEl = document.getElementById('mailbox-stats-start-date');
    if (startDateEl) startDateEl.value = '';
    const endDateEl = document.getElementById('mailbox-stats-end-date');
    if (endDateEl) endDateEl.value = '';

    // Reset date range label
    const labelEl = document.getElementById('date-range-label');
    if (labelEl) labelEl.textContent = 'Last 30 Days';

    // Update preset buttons
    updateDatePresetButtons('30days');

    // Reset the date picker inputs as well
    const startInput = document.getElementById('date-range-start');
    const endInput = document.getElementById('date-range-end');
    if (startInput) startInput.value = '';
    if (endInput) endInput.value = '';

    // Reset domain filter
    const domainEl = document.getElementById('mailbox-stats-domain-filter');
    if (domainEl) domainEl.value = '';

    // Reset sort
    const sortEl = document.getElementById('mailbox-stats-sort');
    if (sortEl) sortEl.value = 'sent_total-desc';

    // Set active only to checked (default)
    const activeOnlyEl = document.getElementById('mailbox-stats-active-only');
    if (activeOnlyEl) activeOnlyEl.checked = true;

    // Set hide zero to unchecked (default)
    const hideZeroEl = document.getElementById('mailbox-stats-hide-zero');
    if (hideZeroEl) hideZeroEl.checked = true;

    // Reload everything
    loadMailboxStats();
}

function loadMailboxStatsPage(page) {
    loadMailboxStatsList(page);
}

