// =============================================================================
// MAILBOX STATISTICS - summary, per-mailbox accordion, date range picker
// =============================================================================
// Split out of app.js (phase 5). Classic script sharing the global scope;
// loaded after utils.js and app.js in index.html.

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

// =============================================================================
// VIEW SWITCHER - Statistics | Rate Limits
// =============================================================================
// Rate Limits is a view of this page rather than a page of its own. The
// switcher follows the Spam Filter recipe in index.html; the code for the
// view itself stays in rate-limits.js.

let mailboxStatsView = 'statistics';

const MAILBOX_STATS_VIEW_HEADINGS = {
    'statistics': {
        title: 'Mailbox Statistics',
        subtitle: 'View message statistics per mailbox and aliases'
    },
    'rate-limits': {
        title: 'Rate Limits',
        subtitle: "Who is running into mailcow's sending limits, and what each mailbox and domain is allowed to send"
    }
};


// Entry point for the page. Re-entering through the switcher keeps the active
// view across navigation and makes the header Refresh reload the view you are
// actually looking at.
function initMailboxStatsPage() {
    mailboxStatsSwitchView(mailboxStatsView);
}


function mailboxStatsSwitchView(view) {
    // The feature can be turned off while the Rate Limits view is open
    if (view === 'rate-limits' && window.disabledFeatures && window.disabledFeatures.includes('rate-limits')) {
        view = 'statistics';
    }
    mailboxStatsView = view;

    document.querySelectorAll('[id^="mailbox-stats-view-"]').forEach(btn => {
        btn.classList.remove('active');
    });
    const activeBtn = document.getElementById(`mailbox-stats-view-${view}`);
    if (activeBtn) activeBtn.classList.add('active');

    const headings = MAILBOX_STATS_VIEW_HEADINGS[view] || MAILBOX_STATS_VIEW_HEADINGS['statistics'];
    const title = document.getElementById('mailbox-stats-page-title');
    if (title) title.textContent = headings.title;
    const subtitle = document.getElementById('mailbox-stats-page-subtitle');
    if (subtitle) subtitle.textContent = headings.subtitle;

    // The help doc and the last-update stamp belong to Statistics
    const helpBtn = document.getElementById('mailbox-stats-help-btn');
    if (helpBtn) helpBtn.style.display = view === 'statistics' ? '' : 'none';
    const headerInfo = document.getElementById('mailbox-stats-header-info');
    if (headerInfo) headerInfo.style.display = view === 'statistics' ? '' : 'none';

    const statisticsView = document.getElementById('mailbox-stats-statistics-view');
    const rateLimitsView = document.getElementById('mailbox-stats-rate-limits-view');

    if (view === 'rate-limits') {
        if (statisticsView) statisticsView.classList.add('hidden');
        if (rateLimitsView) rateLimitsView.classList.remove('hidden');
        loadRateLimits();
    } else {
        if (rateLimitsView) rateLimitsView.classList.add('hidden');
        if (statisticsView) statisticsView.classList.remove('hidden');
        loadMailboxStats();
    }
}


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
                    <p class="text-gray-500 dark:text-gray-400 text-sm">${escapeHtml(error.message)}</p>
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
        option.textContent = d.alias_of
            ? `${d.domain} (alias of ${d.alias_of})`
            : `${d.domain} (${d.mailbox_count})`;
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
                <div onclick="toggleMailboxAccordion('${escapeJsArg(mb.username)}')" 
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
                                 onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeJsArg(mb.username)}', filterType: 'search', direction: 'outbound' })">
                                <div class="text-xl font-bold ${getDirectionTextClass('outbound')}">${mb.combined_sent || 0}</div>
                                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">Sent</div>
                            </div>
                            <div class="p-3 ${getDirectionBgClass('inbound')} rounded-lg text-center cursor-pointer hover:opacity-80 transition-opacity"
                                 onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeJsArg(mb.username)}', filterType: 'search', direction: 'inbound' })">
                                <div class="text-xl font-bold ${getDirectionTextClass('inbound')}">${mb.combined_received || 0}</div>
                                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">Received</div>
                            </div>
                            <div class="p-3 ${getDirectionBgClass('internal')} rounded-lg text-center cursor-pointer hover:opacity-80 transition-opacity"
                                 onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeJsArg(mb.username)}', filterType: 'search', direction: 'internal' })">
                                <div class="text-xl font-bold ${getDirectionTextClass('internal')}">${mb.combined_internal || 0}</div>
                                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">Internal</div>
                            </div>
                        </div>
                        
                        <!-- Status Stats Row -->
                        <div class="grid grid-cols-4 gap-2">
                            <div class="p-3 ${getStatusBgClass('delivered')} rounded-lg text-center cursor-pointer hover:opacity-80 transition-opacity"
                                 onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeJsArg(mb.username)}', filterType: 'search', status: 'delivered' })">
                                <div class="text-xl font-bold ${getStatusTextClass('delivered')}">${mb.combined_delivered || 0}</div>
                                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">Delivered</div>
                            </div>
                            <div class="p-3 ${getStatusBgClass('deferred')} rounded-lg text-center cursor-pointer hover:opacity-80 transition-opacity"
                                 onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeJsArg(mb.username)}', filterType: 'search', status: 'deferred' })">
                                <div class="text-xl font-bold ${getStatusTextClass('deferred')}">${(mb.mailbox_counts?.sent_deferred || 0) + (mb.aliases || []).reduce((sum, a) => sum + (a.sent_deferred || 0), 0)}</div>
                                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">Deferred</div>
                            </div>
                            <div class="p-3 ${getStatusBgClass('bounced')} rounded-lg text-center cursor-pointer hover:opacity-80 transition-opacity"
                                 onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeJsArg(mb.username)}', filterType: 'search', status: 'bounced' })">
                                <div class="text-xl font-bold ${getStatusTextClass('bounced')}">${(mb.mailbox_counts?.sent_bounced || 0) + (mb.aliases || []).reduce((sum, a) => sum + (a.sent_bounced || 0), 0)}</div>
                                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">Bounced</div>
                            </div>
                            <div class="p-3 ${getStatusBgClass('rejected')} rounded-lg text-center cursor-pointer hover:opacity-80 transition-opacity"
                                 onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeJsArg(mb.username)}', filterType: 'search', status: 'rejected' })">
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
                                                            ${alias.is_domain_alias ? '<span class="px-1.5 py-0.5 text-xs bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300 rounded" title="Address on a mailcow alias domain that points at this mailbox">domain alias</span>' : ''}
                                                            ${!alias.active ? '<span class="px-1.5 py-0.5 text-xs bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400 rounded">inactive</span>' : ''}
                                                        </div>
                                                    </td>
                                                    <td class="text-center py-2 px-2 ${getDirectionTextClass('outbound')} cursor-pointer hover:underline" onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeJsArg(alias.alias_address)}', filterType: 'search', direction: 'outbound' })">${alias.sent_total || 0}</td>
                                                    <td class="text-center py-2 px-2 ${getDirectionTextClass('inbound')} cursor-pointer hover:underline" onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeJsArg(alias.alias_address)}', filterType: 'search', direction: 'inbound' })">${alias.received_total || 0}</td>
                                                    <td class="text-center py-2 px-2 ${getDirectionTextClass('internal')} cursor-pointer hover:underline" onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeJsArg(alias.alias_address)}', filterType: 'search', direction: 'internal' })">${alias.direction_internal || 0}</td>
                                                    <td class="text-center py-2 px-2 ${getStatusTextClass('delivered')} cursor-pointer hover:underline" onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeJsArg(alias.alias_address)}', filterType: 'search', status: 'delivered' })">${alias.sent_delivered || 0}</td>
                                                    <td class="text-center py-2 px-2 ${getStatusTextClass('deferred')} cursor-pointer hover:underline" onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeJsArg(alias.alias_address)}', filterType: 'search', status: 'deferred' })">${alias.sent_deferred || 0}</td>
                                                    <td class="text-center py-2 px-2 ${getStatusTextClass('bounced')} cursor-pointer hover:underline" onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeJsArg(alias.alias_address)}', filterType: 'search', status: 'bounced' })">${alias.sent_bounced || 0}</td>
                                                    <td class="text-center py-2 px-2 ${getStatusTextClass('rejected')} cursor-pointer hover:underline" onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeJsArg(alias.alias_address)}', filterType: 'search', status: 'rejected' })">${alias.sent_rejected || 0}</td>
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
                    class="px-3 py-1.5 text-sm text-gray-900 dark:text-white border border-gray-300 dark:border-gray-600 rounded ${page === 1 ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-100 dark:hover:bg-gray-700'}">
                    First
                </button>
                <button onclick="loadMailboxStatsPage(${page - 1})" ${page === 1 ? 'disabled' : ''} 
                    class="px-3 py-1.5 text-sm text-gray-900 dark:text-white border border-gray-300 dark:border-gray-600 rounded ${page === 1 ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-100 dark:hover:bg-gray-700'}">
                    Previous
                </button>
                <span class="px-4 py-1.5 text-sm text-gray-700 dark:text-gray-300">
                    Page ${page} of ${totalPages}
                </span>
                <button onclick="loadMailboxStatsPage(${page + 1})" ${page === totalPages ? 'disabled' : ''} 
                    class="px-3 py-1.5 text-sm text-gray-900 dark:text-white border border-gray-300 dark:border-gray-600 rounded ${page === totalPages ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-100 dark:hover:bg-gray-700'}">
                    Next
                </button>
                <button onclick="loadMailboxStatsPage(${totalPages})" ${page === totalPages ? 'disabled' : ''} 
                    class="px-3 py-1.5 text-sm text-gray-900 dark:text-white border border-gray-300 dark:border-gray-600 rounded ${page === totalPages ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-100 dark:hover:bg-gray-700'}">
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
