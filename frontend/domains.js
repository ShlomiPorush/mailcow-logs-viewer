// =============================================================================
// DOMAINS - domain list, DNS validation (SPF/DKIM/DMARC checks)
// =============================================================================
// Split out of app.js (phase 5). Classic script sharing the global scope;
// loaded after utils.js and app.js in index.html.

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
    const tlsa = dns.tlsa || { status: 'unknown', message: 'Not checked' };
    const mtaSts = dns.mta_sts || { status: 'unknown', message: 'Not checked' };

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
                                onclick="event.stopPropagation(); checkSingleDomainDNS('${escapeJsArg(domain.domain_name)}')"
                                class="px-3 py-1.5 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded transition flex items-center gap-1.5"
                                title="Check DNS for this domain">
                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                                </svg>
                                Check
                            </button>
                        </div>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                        ${renderDNSCheck('SPF', spf)}
                        ${renderDNSCheck('DKIM', dkim)}
                        ${renderDNSCheck('DMARC', dmarc)}
                        ${renderDNSCheck('TLSA', tlsa)}
                        ${renderDNSCheck('MTA-STS', mtaSts)}
                    </div>

                    ${(domain.alias_domains || []).length ? `
                    <div class="mt-6">
                        <h4 class="text-sm font-semibold text-gray-900 dark:text-white mb-1">Alias domains</h4>
                        <p class="text-xs text-gray-500 dark:text-gray-400 mb-3">These domains deliver to the same mailboxes and send with their own DNS records</p>
                        ${domain.alias_domains.map(ad => renderAliasDomain(ad)).join('')}
                    </div>
                    ` : ''}
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

// Label for an SPF checked_ips[].source value (per-check IP sources)
function spfIpSourceLabel(source) {
    if (source === 'configured') return 'Configured';
    if (source === 'auto-detected') return 'Auto-detected WAN';
    if (source === 'transport') return 'Transport';
    if (source === 'relayhost') return 'Relay host';
    if (source === 'dmarc-history') return 'DMARC history';
    return source || 'Unknown';
}

// Expandable list of the IPs validated against the SPF record.
// Cached DNS checks from before this field existed lack checked_ips.
function renderSpfCheckedIps(check) {
    const checkedIps = check.checked_ips;
    if (!Array.isArray(checkedIps) || checkedIps.length === 0) return '';

    const rows = checkedIps.map(entry => `
        <div class="flex items-center justify-between gap-2 p-2 bg-white dark:bg-gray-900 rounded border border-gray-200 dark:border-gray-700">
            <div class="min-w-0">
                <code class="text-xs text-gray-700 dark:text-gray-300 break-all block">${escapeHtml(entry.ip || '')}</code>
                <span class="text-xs text-gray-400 dark:text-gray-500">${escapeHtml(spfIpSourceLabel(entry.source))}</span>
            </div>
            ${entry.authorized
                ? '<span class="flex-shrink-0 px-2 py-0.5 text-xs font-semibold rounded-full bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-200">Authorized</span>'
                : '<span class="flex-shrink-0 px-2 py-0.5 text-xs font-semibold rounded-full bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-200">Not authorized</span>'}
        </div>
    `).join('');

    return `
        <details class="mt-3" data-testid="spf-checked-ips">
            <summary class="text-xs text-gray-600 dark:text-gray-400 cursor-pointer hover:text-gray-900 dark:hover:text-gray-200 font-medium">
                Checked IPs (${checkedIps.length})
            </summary>
            <div class="mt-2 space-y-1">
                ${rows}
            </div>
        </details>
    `;
}

function renderAliasDomain(aliasDomain) {
    const dns = aliasDomain.dns_checks || {};
    const spf = dns.spf || { status: 'unknown', message: 'Not checked yet' };
    const dkim = dns.dkim || { status: 'unknown', message: 'Not checked yet' };
    const dmarc = dns.dmarc || { status: 'unknown', message: 'Not checked yet' };
    const tlsa = dns.tlsa || { status: 'unknown', message: 'Not checked yet' };
    const mtaSts = dns.mta_sts || { status: 'unknown', message: 'Not checked yet' };
    const detailsId = `alias-domain-${aliasDomain.domain_name.replace(/[^a-z0-9]/gi, '-')}`;
    return `
        <div class="border border-gray-200 dark:border-gray-700 rounded-lg mb-2">
            <div class="flex items-center justify-between px-4 py-2 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/30"
                 onclick="document.getElementById('${detailsId}').classList.toggle('hidden')">
                <div class="flex items-center gap-2">
                    <span class="font-medium text-gray-900 dark:text-white text-sm">${escapeHtml(aliasDomain.domain_name)}</span>
                    <span class="px-1.5 py-0.5 text-xs bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300 rounded">alias</span>
                </div>
                <div class="flex items-center gap-3 text-sm">
                    <span>SPF ${getAliasStatusIcon(spf.status)}</span>
                    <span>DKIM ${getAliasStatusIcon(dkim.status)}</span>
                    <span>DMARC ${getAliasStatusIcon(dmarc.status)}</span>
                    <span>TLSA ${getAliasStatusIcon(tlsa.status)}</span>
                    <span>MTA-STS ${getAliasStatusIcon(mtaSts.status)}</span>
                </div>
            </div>
            <div id="${detailsId}" class="hidden px-4 pb-4">
                <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 mt-2">
                    ${renderDNSCheck('SPF', spf)}
                    ${renderDNSCheck('DKIM', dkim)}
                    ${renderDNSCheck('DMARC', dmarc)}
                    ${renderDNSCheck('TLSA', tlsa)}
                    ${renderDNSCheck('MTA-STS', mtaSts)}
                </div>
            </div>
        </div>
    `;
}

function getAliasStatusIcon(status) {
    if (status === 'success') return '<span class="text-green-500">✓</span>';
    if (status === 'warning') return '<span class="text-amber-500">⚠</span>';
    if (status === 'error') return '<span class="text-red-500">✗</span>';
    return '<span class="text-gray-400">?</span>';
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

            ${renderSpfCheckedIps(check)}

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
                        const tlsa = dns.tlsa || { status: 'unknown', message: 'Not checked' };
                        const mtaSts = dns.mta_sts || { status: 'unknown', message: 'Not checked' };

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
                            <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                                ${renderDNSCheck('SPF', spf)}
                                ${renderDNSCheck('DKIM', dkim)}
                                ${renderDNSCheck('DMARC', dmarc)}
                                ${renderDNSCheck('TLSA', tlsa)}
                                ${renderDNSCheck('MTA-STS', mtaSts)}
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
