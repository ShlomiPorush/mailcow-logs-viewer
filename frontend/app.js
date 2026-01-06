// =============================================================================
// MAILCOW LOGS VIEWER - COMPLETE FRONTEND
// Part 1: Core, Global State, Dashboard, Postfix, Rspamd, Netfilter
// =============================================================================

// =============================================================================
// AUTHENTICATION SYSTEM
// =============================================================================

// Authentication state
let authCredentials = null;

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
    console.log('=== Mailcow Logs Viewer Initializing ===');
    
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
    loadDashboard();
    
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
                indicator.title = 'Connected to Mailcow';
                // Update SVG to checkmark
                const svg = indicator.querySelector('svg');
                if (svg) {
                    svg.innerHTML = '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>';
                }
            } else {
                indicator.classList.remove('text-green-500');
                indicator.classList.add('text-red-500');
                indicator.title = 'Not connected to Mailcow';
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
    
    console.log(`[OK] Auto-refresh started (every ${AUTO_REFRESH_INTERVAL/1000}s)`);
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

function switchTab(tab) {
    console.log('Switching to tab:', tab);
    currentTab = tab;
    
    // Update active tab button
    document.querySelectorAll('[id^="tab-"]').forEach(btn => {
        btn.classList.remove('tab-active');
        btn.classList.add('text-gray-500', 'dark:text-gray-400');
    });
    const activeBtn = document.getElementById(`tab-${tab}`);
    if (activeBtn) {
        activeBtn.classList.add('tab-active');
        activeBtn.classList.remove('text-gray-500', 'dark:text-gray-400');
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
        case 'settings':
            loadSettings();
            break;
        default:
            console.warn('Unknown tab:', tab);
    }
}

function refreshAllData() {
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
        
        const response = await authenticatedFetch('/api/stats/recent-activity?limit=10');
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
                        ${msg.direction ? `<span class="inline-block px-2 py-0.5 text-xs font-medium rounded ${getDirectionClass(msg.direction)}">${msg.direction}</span>` : ''}
                    </div>
                    <p class="text-xs text-gray-500 dark:text-gray-400 truncate" title="${escapeHtml(msg.subject || 'No subject')}">${escapeHtml(msg.subject || 'No subject')}</p>
                </div>
                <div class="flex items-center gap-2 flex-shrink-0 sm:justify-end">
                    <span class="inline-block px-2 py-1 text-xs font-medium rounded ${getStatusClass(msg.status)}">${msg.status || 'unknown'}</span>
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
                                    <p class="text-xs text-gray-500 dark:text-gray-400">${c.started_at ? new Date(c.started_at).toLocaleString('he-IL', {day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit'}) : 'Unknown'}</p>
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
        
    } catch (error) {
        console.error('Failed to load extended status:', error);
        document.getElementById('status-import').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load: ${error.message}</p>`;
        document.getElementById('status-correlation').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load: ${error.message}</p>`;
        document.getElementById('status-jobs').innerHTML = `<p class="text-red-500 text-center py-8">Failed to load: ${error.message}</p>`;
    }
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
        <div class="space-y-3">
            ${renderJobCard('Fetch Logs', jobs.fetch_logs, 'Imports logs from Mailcow API')}
            ${renderJobCard('Complete Correlations', jobs.complete_correlations, 'Links Postfix logs to messages')}
            ${renderJobCard('Update Final Status', jobs.update_final_status, 'Updates final status for correlations with late-arriving Postfix logs')}
            ${renderJobCard('Expire Correlations', jobs.expire_correlations, 'Marks old incomplete correlations as expired')}
            ${renderJobCard('Cleanup Old Logs', jobs.cleanup_logs, 'Removes logs older than retention period')}
        </div>
    `;
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
                    <div class="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 mt-1">
                    <h4 class="text-md font-semibold text-gray-900 dark:text-white mb-3">Quick Spam Summary</h4>
                    <div class="grid grid-cols-3 gap-4">
                        <div class="text-center">
                            <p class="text-2xl font-bold ${data.rspamd.score >= (data.rspamd.required_score || 15) ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'}">${data.rspamd.score.toFixed(2)}</p>
                            <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">Score</p>
                        </div>
                        <div class="text-center">
                            <p class="text-lg font-semibold text-gray-900 dark:text-white">${data.rspamd.action}</p>
                            <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">Action</p>
                        </div>
                        <div class="text-center">
                            <p class="text-lg font-semibold ${data.rspamd.is_spam ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'}">${data.rspamd.is_spam ? 'SPAM' : 'CLEAN'}</p>
                            <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">Classification</p>
                        </div>
                    </div>
                    <p class="text-xs text-gray-500 dark:text-gray-400 text-center mt-3">
                        Click "Spam Analysis" tab for detailed breakdown
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
                                    ${data.rspamd.ip ? `<p>Source IP: ${data.rspamd.ip}</p>` : ''}
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
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div class="bg-gray-50 dark:bg-gray-700/50 p-4 rounded-lg text-center">
                    <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-2">Spam Score</p>
                    <p class="text-3xl font-bold ${data.rspamd.score >= (data.rspamd.required_score || 15) ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'}">${data.rspamd.score.toFixed(2)}</p>
                    <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">Threshold: ${data.rspamd.required_score || 15}</p>
                </div>
                <div class="bg-gray-50 dark:bg-gray-700/50 p-4 rounded-lg text-center">
                    <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-2">Action Taken</p>
                    <p class="text-xl font-semibold text-gray-900 dark:text-white">${data.rspamd.action}</p>
                </div>
                <div class="bg-gray-50 dark:bg-gray-700/50 p-4 rounded-lg text-center">
                    <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-2">Classification</p>
                    <p class="text-xl font-semibold ${data.rspamd.is_spam ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'}">${data.rspamd.is_spam ? 'SPAM' : 'CLEAN'}</p>
                </div>
            </div>
            
            ${data.rspamd.symbols && Object.keys(data.rspamd.symbols).length > 0 ? `
                <div>
                    <h4 class="text-md font-semibold text-gray-900 dark:text-white mb-3">Detection Symbols</h4>
                    <div class="space-y-2 max-h-96 overflow-y-auto">
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
    
    securityTab.innerHTML = `<span class="text-sm font-medium">Security ${indicator}</span>`;
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
    const content = document.getElementById('changelog-content');
    if (modal && content) {
        // Render markdown if marked.js is available, otherwise show as plain text
        if (typeof marked !== 'undefined' && changelog) {
            // Configure marked options
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
    }
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
    switch (status) {
        case 'sent':
        case 'delivered':
            return 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300';
        case 'bounced':
            return 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300';
        case 'deferred':
            return 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300';
        case 'rejected':
            return 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300';
        case 'spam':
            return 'bg-orange-100 dark:bg-orange-900/30 text-orange-800 dark:text-orange-300';
        case 'expired':
            return 'bg-slate-100 dark:bg-slate-900/30 text-slate-800 dark:text-slate-300';
        default:
            return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300';
    }
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
    switch (direction) {
        case 'inbound':
            return 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300';
        case 'outbound':
            return 'bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300';
        case 'internal':
            return 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300';
        default:
            return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300';
    }
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
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
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

document.addEventListener('DOMContentLoaded', function() {
    const messageModal = document.getElementById('message-modal');
    if (messageModal) {
        messageModal.addEventListener('click', function(e) {
            // Close modal if clicking on the backdrop (not the content)
            if (e.target.id === 'message-modal') {
                closeMessageModal();
            }
        });
        
        // Prevent clicks inside modal content from closing
        const modalContent = messageModal.querySelector('.bg-white');
        if (modalContent) {
            modalContent.addEventListener('click', function(e) {
                e.stopPropagation();
            });
        }
    }
    
    // ESC key to close modal
    document.addEventListener('keydown', function(e) {
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
        changelogModal.addEventListener('click', function(e) {
            if (e.target.id === 'changelog-modal') {
                closeChangelogModal();
            }
        });
        
        const changelogContent = changelogModal.querySelector('.bg-white, .dark\\:bg-gray-800');
        if (changelogContent) {
            changelogContent.addEventListener('click', function(e) {
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
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-500 dark:text-gray-400 font-medium">Total Domains</p>
                        <p class="text-3xl font-bold text-gray-900 dark:text-white mt-1">${data.total || 0}</p>
                    </div>
                    <div class="bg-blue-100 dark:bg-blue-900/30 rounded-lg p-3">
                        <svg class="w-8 h-8 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path>
                        </svg>
                    </div>
                </div>
            </div>
            
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-500 dark:text-gray-400 font-medium">Active Domains</p>
                        <p class="text-3xl font-bold text-green-600 dark:text-green-400 mt-1">${data.active || 0}</p>
                    </div>
                    <div class="bg-green-100 dark:bg-green-900/30 rounded-lg p-3">
                        <svg class="w-8 h-8 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                    </div>
                </div>
            </div>
            
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-500 dark:text-gray-400 font-medium">Inactive Domains</p>
                        <p class="text-3xl font-bold text-gray-500 dark:text-gray-400 mt-1">${(data.total || 0) - (data.active || 0)}</p>
                    </div>
                    <div class="bg-gray-100 dark:bg-gray-700 rounded-lg p-3">
                        <svg class="w-8 h-8 text-gray-500 dark:text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"></path>
                        </svg>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Search/Filter bar
    const filterHTML = `
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 p-4 mb-4">
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
                </div>
                
                <div class="flex items-center gap-4 flex-shrink-0">
                    <!-- Filter: Show only domains with issues -->
                    <label class="flex items-center gap-2 cursor-pointer">
                        <input 
                            type="checkbox" 
                            id="filter-issues-only"
                            class="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 dark:focus:ring-blue-600 dark:ring-offset-gray-800 focus:ring-2 dark:bg-gray-700 dark:border-gray-600"
                            onchange="filterDomains()"
                        >
                        <span class="text-sm font-medium text-gray-700 dark:text-gray-300 whitespace-nowrap">Show issues only</span>
                    </label>
                    
                    <!-- Domain count badge -->
                    <span id="domain-count-badge" class="px-3 py-1 text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-full whitespace-nowrap">
                        ${domains.length} domains
                    </span>
                </div>
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
                    <h4 class="text-sm font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                        <svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                        </svg>
                        DNS Security Records
                    </h4>
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
        'success': 'border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-900/20',
        'warning': 'border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20',
        'error': 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20',
        'unknown': 'border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800'
    };
    
    const statusTextColors = {
        'success': 'text-green-700 dark:text-green-300',
        'warning': 'text-amber-700 dark:text-amber-300',
        'error': 'text-red-700 dark:text-red-300',
        'unknown': 'text-gray-500 dark:text-gray-400'
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
            
            ${check.record ? `
                <details class="mt-3">
                    <summary class="text-xs text-gray-600 dark:text-gray-400 cursor-pointer hover:text-gray-900 dark:hover:text-gray-200 font-medium">
                        View Record
                    </summary>
                    <div class="mt-2 p-2 bg-white dark:bg-gray-900 rounded border border-gray-200 dark:border-gray-700">
                        <code class="text-xs text-gray-700 dark:text-gray-300 break-all block leading-relaxed">${escapeHtml(check.record)}</code>
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
                        <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Mailcow URL</p>
                        <p class="text-sm text-gray-900 dark:text-white mt-1 font-mono break-all">${escapeHtml(config.mailcow_url || 'N/A')}</p>
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

function renderJobCard(title, data, description) {
    if (!data) {
        return `<div class="p-3 bg-gray-50 dark:bg-gray-700/30 rounded">
            <p class="font-semibold text-gray-900 dark:text-white">${title}</p>
            <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">No data</p>
        </div>`;
    }
    
    const statusColors = {
        running: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300',
        scheduled: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
        stopped: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'
    };
    
    return `
        <div class="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
            <div class="flex justify-between items-start mb-2">
                <div>
                    <p class="font-semibold text-gray-900 dark:text-white">${title}</p>
                    <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">${description}</p>
                </div>
                <span class="px-2 py-1 text-xs font-medium rounded ${statusColors[data.status] || statusColors.running}">
                    ${data.status || 'unknown'}
                </span>
            </div>
            <div class="flex items-center gap-4 text-sm text-gray-600 dark:text-gray-400">
                ${data.interval ? `<span>Interval: ${data.interval}</span>` : ''}
                ${data.schedule ? `<span>Schedule: ${data.schedule}</span>` : ''}
                ${data.retention ? `<span>Retention: ${data.retention}</span>` : ''}
                ${data.expire_after ? `<span>Expire after: ${data.expire_after}</span>` : ''}
                ${data.max_age ? `<span>Max age: ${data.max_age}</span>` : ''}
                ${data.pending_items !== undefined ? `<span>Pending: ${data.pending_items}</span>` : ''}
            </div>
        </div>
    `;
}

// =============================================================================
// CONSOLE LOG
// =============================================================================

console.log('[OK] Mailcow Logs Viewer - Complete Frontend Loaded');
console.log('Features: Dashboard, Messages, Postfix, Rspamd, Netfilter, Queue, Quarantine, Status, Settings');
console.log('UI: Dark mode, Modals with tabs, Responsive design');