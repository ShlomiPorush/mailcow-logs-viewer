// =============================================================================
// DMARC & TLS-RPT - domains list, reports, sources, upload, IMAP sync, management
// =============================================================================
// Split out of app.js (phase 2). Classic script sharing the global scope;
// loaded after utils.js and app.js in index.html.

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

    // Show a loading placeholder before the data requests start
    const domainsList = document.getElementById('dmarc-domains-list');
    if (domainsList) {
        domainsList.innerHTML = `<tr><td colspan="7" class="px-6 py-12 text-center"><div class="flex justify-center"><div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div><div class="mt-3 text-sm text-gray-500 dark:text-gray-400">Loading DMARC reports...</div></td></tr>`;
    }

    // Run the three requests in parallel - they do not depend on each other
    await Promise.all([loadDmarcSettings(), loadDmarcImapStatus(), loadDmarcDomains()]);

    // Ordering is not guaranteed in parallel, so refresh the controls once everything settled
    updateDmarcControls();
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

    // Load settings (only if missing) and IMAP status in parallel
    const initialLoads = [loadDmarcImapStatus()];
    if (!dmarcConfiguration) {
        initialLoads.push(loadDmarcSettings());
    }
    await Promise.all(initialLoads);

    // Ordering is not guaranteed in parallel, so refresh the controls once everything settled
    updateDmarcControls();

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

async function loadDmarcInsights() {
    const container = document.getElementById('dmarc-insights-container');
    if (!container) return;
    try {
        const response = await authenticatedFetch('/api/dmarc/insights');
        if (!response.ok) { container.classList.add('hidden'); return; }
        const data = await response.json();
        const insights = (data.insights || []).filter(i =>
            i.recommendations.some(r => r.type === 'tighten_policy' || r.type === 'low_pass_rate') ||
            (i.new_sources && i.new_sources.length > 0)
        );
        if (insights.length === 0) { container.classList.add('hidden'); container.innerHTML = ''; return; }

        const cards = insights.map(i => {
            const recs = i.recommendations.map(r => {
                const tone = r.severity === 'success' ? 'text-green-700 dark:text-green-400'
                    : r.severity === 'warning' ? 'text-yellow-700 dark:text-yellow-400'
                    : 'text-gray-600 dark:text-gray-400';
                const action = r.type === 'tighten_policy'
                    ? `<span class="ml-1 inline-block px-1.5 py-0.5 text-[10px] font-semibold rounded bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300">p=${escapeHtml(r.current_policy)} → p=${escapeHtml(r.recommended_policy)}</span>`
                    : '';
                return `<li class="text-xs ${tone}">${escapeHtml(r.message)}${action}</li>`;
            }).join('');

            const newSrc = (i.new_sources && i.new_sources.length)
                ? `<div class="mt-2 text-xs text-red-700 dark:text-red-400"><span class="font-semibold">${i.new_sources.length} new failing source(s):</span> ${i.new_sources.slice(0, 5).map(s => escapeHtml(s.source_ip) + ' (' + s.failing_messages + ')').join(', ')}</div>`
                : '';

            return `
                <div class="p-3 border-t border-blue-200 dark:border-blue-800/50 first:border-t-0">
                    <div class="flex items-center gap-2 flex-wrap">
                        <span class="text-sm font-semibold text-gray-900 dark:text-white">${escapeHtml(i.domain)}</span>
                        <span class="text-xs text-gray-500 dark:text-gray-400">p=${escapeHtml(i.current_policy)} · ${i.pass_rate}% pass · ${i.total_messages.toLocaleString()} msgs</span>
                    </div>
                    <ul class="mt-1 space-y-0.5 list-disc list-inside">${recs}</ul>
                    ${newSrc}
                </div>`;
        }).join('');

        container.innerHTML = `
            <div class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
                <div class="flex items-center gap-2 p-3 border-b border-blue-200 dark:border-blue-800/50">
                    <svg class="w-5 h-5 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    <h3 class="text-sm font-semibold text-blue-800 dark:text-blue-300">DMARC Insights (${insights.length})</h3>
                    <span class="text-xs text-blue-600/70 dark:text-blue-400/70">last ${data.window_days} days</span>
                </div>
                ${cards}
            </div>`;
        container.classList.remove('hidden');
    } catch (e) {
        console.warn('Failed to load DMARC insights:', e);
        container.classList.add('hidden');
    }
}

async function loadDmarcDomains() {
    try {
        const response = await authenticatedFetch('/api/dmarc/domains');
        if (!response.ok) throw new Error('Failed to load domains');

        const data = await response.json();
        const domains = data.domains || [];

        // Insights load independently - never block the domains table on them
        loadDmarcInsights();

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
            domainsList.innerHTML = `<tr><td colspan="7" class="px-6 py-12 text-center text-gray-500 dark:text-gray-400 text-sm">No domains found in the reporting period.</td></tr>`;
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
                <tr class="hidden md:table-row hover:bg-gray-50 dark:hover:bg-gray-700/30 cursor-pointer transition-colors" onclick="loadDomainOverview('${escapeJsArg(domain.domain)}')">
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
                    onclick="loadDomainOverview('${escapeJsArg(domain.domain)}')">
                    
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
        const domainsList = document.getElementById('dmarc-domains-list');
        if (domainsList) {
            domainsList.innerHTML = `<tr><td colspan="7" class="px-6 py-12 text-center text-sm text-red-500 dark:text-red-400">Failed to load DMARC reports. Refresh the page to try again.</td></tr>`;
        }
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
        const dmarcRecord = data.dmarc_record || null;

        // Build DMARC Record card HTML (status + settings from DNS). Card and policy colors by policy level.
        const dmarcRecordCardHtml = (() => {
            if (!dmarcRecord) return '';
            const settings = dmarcRecord.settings || {};
            const policyLevel = (dmarcRecord.policy || settings.policy || 'unknown').toLowerCase();
            const policyCardColors = { reject: 'border-green-500 bg-green-50 dark:bg-green-900/20', quarantine: 'border-amber-500 bg-amber-50 dark:bg-amber-900/20', none: 'border-red-500 bg-red-50 dark:bg-red-900/20', unknown: 'border-gray-300 bg-gray-50 dark:bg-gray-800' };
            const policyTextColors = { reject: 'text-green-700 dark:text-green-400', quarantine: 'text-amber-700 dark:text-amber-400', none: 'text-red-700 dark:text-red-400', unknown: 'text-gray-600 dark:text-gray-400' };
            const cardColor = policyCardColors[policyLevel] || policyCardColors.unknown;
            const messageColor = policyTextColors[policyLevel] || policyTextColors.unknown;
            const labels = { policy: 'Policy', subdomain_policy: 'Subdomain policy', aggregate_report_uris: 'Aggregate report URIs (rua)', forensic_report_uris: 'Forensic report URIs (ruf)', dkim_alignment: 'DKIM alignment', spf_alignment: 'SPF alignment', percentage: 'Percentage', failure_reporting_options: 'Failure reporting options' };
            const formatVal = (v) => Array.isArray(v) ? v.join(', ') : String(v);
            const formatUriAsEmail = (uri) => { const email = String(uri).replace(/^mailto:/i, '').trim(); return `<a href="${escapeHtml(uri)}" class="text-blue-600 dark:text-blue-400 hover:underline break-all">${escapeHtml(email)}</a>`; };
            const policyLevelColor = (p) => policyTextColors[(String(p || '').toLowerCase())] || policyTextColors.unknown;
            const formatCell = (k, v) => {
                if ((k === 'aggregate_report_uris' || k === 'forensic_report_uris') && Array.isArray(v) && v.length) return v.map(formatUriAsEmail).join(', ');
                if (k === 'policy' || k === 'subdomain_policy') return `<span class="font-semibold ${policyLevelColor(v)}">${escapeHtml(formatVal(v))}</span>`;
                return escapeHtml(formatVal(v));
            };
            const settingsRows = Object.keys(labels).filter(k => settings[k] !== undefined && settings[k] !== '').map(k => `<tr class="border-b border-gray-100 dark:border-gray-700"><td class="py-1.5 pr-3 text-xs font-medium text-gray-500 dark:text-gray-400">${escapeHtml(labels[k])}</td><td class="py-1.5 text-xs text-gray-900 dark:text-gray-200 break-all">${formatCell(k, settings[k])}</td></tr>`).join('');
            return `
                <div class="mb-6 border ${cardColor} rounded-lg p-4">
                    <h3 class="text-sm font-semibold text-gray-900 dark:text-white mb-2">DMARC Record</h3>
                    <p class="text-sm ${messageColor} font-medium mb-3">${escapeHtml(dmarcRecord.message || 'No information')}</p>
                    ${settingsRows ? `<div class="overflow-x-auto"><table class="w-full text-left"><tbody>${settingsRows}</tbody></table></div>` : ''}
                    ${dmarcRecord.record ? `<details class="mt-3"><summary class="text-xs text-gray-600 dark:text-gray-400 cursor-pointer hover:text-gray-900 dark:hover:text-gray-200 font-medium">View Record</summary><div class="mt-2 p-2 bg-white dark:bg-gray-900 rounded border border-gray-200 dark:border-gray-700"><code class="text-xs text-gray-700 dark:text-gray-300 break-all block leading-relaxed">${escapeHtml(dmarcRecord.record)}</code></div></details>` : ''}
                    ${(dmarcRecord.warnings && dmarcRecord.warnings.length) ? `<div class="mt-3 space-y-1">${dmarcRecord.warnings.map(w => `<div class="flex items-start gap-2 text-xs ${policyTextColors['none']}"><span>${escapeHtml(w)}</span></div>`).join('')}</div>` : ''}
                </div>
            `;
        })();

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
                ${dmarcRecordCardHtml}
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
                <div class="bg-gray-50 dark:bg-gray-700/50 border border-gray-100 dark:border-gray-700 rounded-xl p-3 mb-4 cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors" onclick="loadReportDetails('${escapeJsArg(domain)}', '${report.date}')">
                    
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
                         onclick="loadSourceDetails('${escapeJsArg(domain)}', '${escapeJsArg(s.source_ip)}')">
                        
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
                        <div class="bg-gray-50 dark:bg-gray-700/50 border border-gray-100 dark:border-gray-700 rounded-xl p-4 cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors" onclick="loadTLSReportDetails('${escapeJsArg(domain)}', '${day.date}')">
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
                <button onclick="loadDomainTLSReports('${escapeJsArg(domain)}')" class="flex items-center gap-2 text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 transition-colors">
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
                <button onclick="loadDomainTLSReports('${escapeJsArg(domain)}')" class="mt-4 text-blue-600 hover:underline">Back to Daily Reports</button>
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
                        <tr class="hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer" onclick="loadSourceDetails('${escapeJsArg(domain)}', '${escapeJsArg(s.source_ip)}')">
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
                                <button onclick="deleteReport('${report.type}', ${report.id}, '${escapeJsArg(report.domain)}')" 
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
                    <button onclick="deleteReport('${report.type}', ${report.id}, '${escapeJsArg(report.domain)}')" 
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
    if (!await showConfirmModal({ title: 'Delete Report', message: `Are you sure you want to delete this ${reportType.toUpperCase()} report for ${domain}?\n\nThis action cannot be undone.`, confirmText: 'Delete', isDangerous: true })) {
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
