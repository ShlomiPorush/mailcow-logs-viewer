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
    detailType: null, // 'report', 'source', 'tls'
    tab: 'dmarc', // the page tab: 'dmarc' or 'tls'
    tlsSubTab: 'reports',
    tlsChartInstance: null
};

const DMARC_PAGE_SUBTITLES = {
    dmarc: "What receivers report about mail sent in your domains' name",
    tls: 'Whether other mail servers reached your domains over an encrypted connection, as they report it'
};

// The DMARC and TLS tabs of the page: mark the tab, nothing else
function dmarcShowPageTab(tab) {
    dmarcState.tab = tab;
    ['dmarc', 'tls'].forEach(name => {
        const btn = document.getElementById(`dmarc-tab-btn-${name}`);
        if (btn) {
            btn.classList.toggle('active', name === tab);
            btn.setAttribute('aria-selected', name === tab ? 'true' : 'false');
        }
    });
    const subtitle = document.getElementById('dmarc-subtitle');
    if (subtitle) subtitle.textContent = DMARC_PAGE_SUBTITLES[tab];
}

// A tab click: its own address, /dmarc or /dmarc/tls
function dmarcOpenTab(tab) {
    dmarcState.tab = tab;
    navigateTo('dmarc', tab === 'tls' ? { tab: 'tls' } : {});
}

// Pass rates: green from 95%, amber from 80%, red below
function dmarcTone(pct) {
    return pct >= 95 ? 'ok' : pct >= 80 ? 'warn' : 'fail';
}

function dmarcRate(pct) {
    const value = Number(pct) || 0;
    const tone = dmarcTone(value);
    return `<span class="ui-rate"><b class="ui-text-${tone}">${value}%</b><span class="ui-meter ui-${tone}"><i style="width: ${Math.min(100, Math.max(0, value))}%"></i></span></span>`;
}

// Alignment columns: green at 95% and up, red at 0%, plain in between
function dmarcPctCell(pct) {
    const tone = pct >= 95 ? 'ok' : pct === 0 ? 'fail' : '';
    return `<span class="ui-td ui-td-end${tone ? ` ui-text-${tone}` : ''}">${pct}%</span>`;
}

function dmarcKpis(items) {
    return `<div class="ui-kpis">${items.map(([value, label, tone, note]) => `
        <div class="ui-kpi"><b class="${tone ? `ui-${tone}` : ''}">${value}</b>${label}${note ? `<small class="ui-kpi-note">${note}</small>` : ''}</div>`).join('')}
    </div>`;
}

function dmarcFlag(countryCode, countryName, size = '24x18') {
    if (!countryCode || countryCode.length !== 2) return '';
    return `<img class="ui-flag" src="/static/assets/flags/${size}/${countryCode.toLowerCase()}.png" alt="${escapeHtml(countryName || countryCode)}" onerror="this.remove()">`;
}

function dmarcShowView(view) {
    ['dmarc-domains-view', 'dmarc-overview-view', 'dmarc-report-details-view', 'dmarc-source-details-view',
        'dmarc-tls-domains-view', 'dmarc-tls-domain-view', 'dmarc-tls-details-view'].forEach(id => {
        document.getElementById(id).classList.toggle('hidden', id !== view);
    });
}

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
    container.innerHTML = `
        ${dmarcState.tab === 'tls'
            ? `<button type="button" class="ui-crumb" onclick="dmarcOpenTab('tls')">TLS</button>`
            : `<button type="button" class="ui-crumb" onclick="dmarcOpenTab('dmarc')">DMARC</button>`}
        ${dmarcState.breadcrumb.map((item, idx) => {
        const isLast = idx === dmarcState.breadcrumb.length - 1;
        const separator = '<span class="ui-crumb-sep" aria-hidden="true">/</span>';
        return isLast
            ? `${separator}<span class="ui-crumb-current">${escapeHtml(item.label)}</span>`
            : `${separator}<button type="button" class="ui-crumb" onclick="${item.action}">${escapeHtml(item.label)}</button>`;
    }).join('')}`;
}

// Set breadcrumb for different views (without "DMARC & TLS Reports" since title is static)
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
                { label: data.domain, action: `loadDomainOverview('${escapeJsArg(data.domain)}')` },
                { label: 'Daily Reports', action: `loadDomainOverview('${escapeJsArg(data.domain)}'); setTimeout(() => dmarcSwitchSubTab('reports'), 100)` },
                { label: data.date, action: null }
            ];
            break;
        case 'sourceDetails':
            dmarcState.breadcrumb = [
                { label: data.domain, action: `loadDomainOverview('${escapeJsArg(data.domain)}')` },
                { label: 'Source IPs', action: `loadDomainOverview('${escapeJsArg(data.domain)}'); setTimeout(() => dmarcSwitchSubTab('sources'), 100)` },
                { label: data.ip, action: null }
            ];
            break;
        case 'tlsDomain':
            dmarcState.breadcrumb = [
                { label: data.domain, action: null }
            ];
            break;
        case 'tlsDetails':
            dmarcState.breadcrumb = [
                { label: data.domain, action: `loadTlsDomain('${escapeJsArg(data.domain)}')` },
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

    dmarcDestroyCharts();

    // Hide all sub-views and show main domains view
    dmarcShowView('dmarc-domains-view');
    document.getElementById('dmarc-page-title').textContent = 'DMARC & TLS Reports';

    // Update breadcrumb
    setDmarcBreadcrumb('domains');

    // Show a loading placeholder before the data requests start
    const domainsList = document.getElementById('dmarc-domains-list');
    if (domainsList) {
        domainsList.innerHTML = '<div class="ui-loading"><div class="loading"></div><p>Loading DMARC reports...</p></div>';
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

    // An address from before TLS had its own tab (/dmarc/example.com/tls) opens it there
    if (params.domain && params.type === 'tls') {
        params = { tab: 'tls', domain: params.domain, id: params.id };
        const path = buildPath('dmarc', params);
        history.replaceState({ route: 'dmarc', params }, '', path);
    }

    dmarcShowPageTab(params.tab === 'tls' ? 'tls' : 'dmarc');
    if (params.tab === 'tls') {
        if (!dmarcConfiguration) loadDmarcSettings().then(updateDmarcControls);
        loadDmarcImapStatus().then(updateDmarcControls);
        if (params.domain && params.id && params.id !== 'providers') await loadTLSReportDetails(params.domain, params.id, false);
        else if (params.domain) await loadTlsDomain(params.domain, params.id === 'providers' ? 'providers' : 'reports', false);
        else await loadTlsDomains();
        return;
    }

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

    // The address names the tab (/dmarc/example.com/sources); the overview opens on it
    dmarcState.currentSubTab = DMARC_SUBTABS.includes(params.type) ? params.type : 'reports';
    await loadDomainOverview(params.domain, false);
}

// =============================================================================
// DOMAINS LIST
// =============================================================================

function getPolicyBadgeClass(policy) {
    switch (policy) {
        case 'reject':
            return 'ui-tag ui-tag-fail';
        case 'quarantine':
            return 'ui-tag ui-tag-warn';
        case 'none':
        default:
            return 'ui-tag';
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

        const rows = insights.map(i => {
            const failing = i.new_sources && i.new_sources.length > 0;
            const recs = i.recommendations.map(r => {
                const tone = r.severity === 'success' ? 'ui-text-ok' : r.severity === 'warning' ? 'ui-text-warn' : '';
                const action = r.type === 'tighten_policy'
                    ? ` ${uiTag(`p=${r.current_policy} → p=${r.recommended_policy}`, 'ok')}`
                    : '';
                return `<li class="${tone}">${escapeHtml(r.message)}${action}</li>`;
            }).join('');

            const newSrc = failing
                ? `<p class="ui-text-fail"><b>${i.new_sources.length} new failing source(s):</b> ${i.new_sources.slice(0, 5).map(s => escapeHtml(s.source_ip) + ' (' + s.failing_messages + ')').join(', ')}</p>`
                : '';

            return `
                <div class="ui-alert ${failing ? 'ui-alert-fail' : 'ui-alert-warn'}">
                    <span class="ui-alert-bar"></span>
                    <div class="ui-alert-text">
                        <div class="ui-alert-title"><b>${escapeHtml(i.domain)}</b>
                            <span class="ui-muted">p=${escapeHtml(i.current_policy)}, ${i.pass_rate}% pass, ${i.total_messages.toLocaleString()} msgs</span></div>
                        <ul class="ui-insight-list">${recs}</ul>
                        ${newSrc}
                    </div>
                    <button type="button" class="ui-btn ui-btn-sm" onclick="loadDomainOverview('${escapeJsArg(i.domain)}')">Open</button>
                </div>`;
        }).join('');

        container.innerHTML = `
            <section class="ui-panel">
                <div class="ui-panel-head">DMARC Insights <span class="ui-count">${insights.length}</span>
                    <span class="ui-muted ui-head-actions">last ${data.window_days} days</span></div>
                ${rows}
            </section>`;
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
        const allDomains = data.domains || [];
        // TLS reports have their own tab
        const domains = allDomains.filter(d => d.has_dmarc !== false);

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
            mainStatsContainer.innerHTML = dmarcKpis([
                [domains.length, 'Total Domains'],
                [totalMessages.toLocaleString(), 'Total Messages'],
                [`${overallPassPct}%`, 'DMARC Pass', totalMessages ? dmarcTone(overallPassPct) : ''],
                [totalUniqueIps.toLocaleString(), 'Unique IPs'],
            ]);
        }

        const domainsList = document.getElementById('dmarc-domains-list');
        dmarcUpdateManageButton(allDomains);

        if (domains.length === 0) {
            domainsList.innerHTML = '<p class="ui-empty">No DMARC reports yet.</p>';
            return;
        }

        const day = ts => ts ? new Date(ts * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '-';
        domainsList.innerHTML = `
            <div class="ui-tr ui-tr-head"><span>Domain</span><span>Activity Period</span><span class="ui-td-end">Reports</span><span class="ui-td-end">Messages (30d)</span><span class="ui-td-end">Unique IPs</span><span>DMARC Pass</span></div>
            ${domains.map(domain => {
            const stats = domain.stats_30d || {};
            return `
                <div class="ui-tr" onclick="loadDomainOverview('${escapeJsArg(domain.domain)}')">
                    <span class="ui-td"><b>${escapeHtml(domain.domain)}</b></span>
                    <span class="ui-td"><small class="ui-sec-unit">Period </small>${day(domain.first_report)} - ${day(domain.last_report)}</span>
                    <span class="ui-td ui-td-end"><small class="ui-sec-unit">Reports </small>${domain.report_count || 0}</span>
                    <span class="ui-td ui-td-end"><small class="ui-sec-unit">Messages </small>${(stats.total_messages || 0).toLocaleString()}</span>
                    <span class="ui-td ui-td-end"><small class="ui-sec-unit">Unique IPs </small>${stats.unique_ips || 0}</span>
                    <span class="ui-td"><small class="ui-sec-unit">DMARC </small>${dmarcRate(stats.dmarc_pass_pct || 0)}</span>
                </div>`;
        }).join('')}`;

    } catch (error) {
        console.error('Error loading DMARC domains:', error);
        const domainsList = document.getElementById('dmarc-domains-list');
        if (domainsList) {
            domainsList.innerHTML = '<p class="ui-empty ui-text-fail">Failed to load DMARC reports. Refresh the page to try again.</p>';
        }
    }
}

// TLS-RPT record (_smtp._tls): where sending servers deliver their TLS reports.
// Same card as the DMARC record; the edge colour follows the check result.
function renderTlsRptRecordCard(record) {
    if (!record) return '';
    const tone = { success: 'ok', warning: 'warn', error: 'fail' }[record.status] || '';
    // Report URIs come from DNS: only mailto: becomes a link, anything else stays text
    const formatUri = (uri) => {
        const text = String(uri).trim();
        if (!/^mailto:/i.test(text)) return escapeHtml(text);
        return `<a href="${escapeHtml(text)}" class="ui-link">${escapeHtml(text.replace(/^mailto:/i, ''))}</a>`;
    };
    const uris = Array.isArray(record.report_uris) ? record.report_uris : [];
    const list = (items, cls) => (Array.isArray(items) && items.length)
        ? `<ul class="${cls} ui-dmarc-record-warn">${items.map(n => `<li>${escapeHtml(n)}</li>`).join('')}</ul>` : '';
    return `
        <section class="ui-panel ui-dmarc-record${tone ? ` ui-dmarc-${tone}` : ''}">
            <div class="ui-panel-head">TLS-RPT Record</div>
            <p class="ui-dmarc-record-msg${tone ? ` ui-text-${tone}` : ''}">${escapeHtml(record.message || 'No information')}</p>
            ${uris.length ? `<div class="ui-kv"><span>Report addresses (rua)</span><b class="ui-kv-small">${uris.map(formatUri).join(', ')}</b></div>` : ''}
            ${record.record ? `<details class="ui-dns-more ui-dmarc-record-raw"><summary>View Record</summary><div class="ui-dns-code"><code>${escapeHtml(record.record)}</code></div></details>` : ''}
            ${list(record.warnings, 'ui-dns-warnings')}
            ${list(record.info, 'ui-dns-info')}
        </section>
    `;
}

async function loadDomainOverview(domain, updateUrl = true) {
    dmarcState.currentView = 'overview';
    dmarcState.currentDomain = domain;
    dmarcState.detailType = null;
    if (updateUrl) dmarcState.currentSubTab = 'reports';

    // Update URL if requested (skip when called from handleDmarcRoute to avoid duplicate history)
    if (updateUrl && typeof buildPath === 'function') {
        const newPath = buildPath('dmarc', { domain });
        if (window.location.pathname !== newPath) {
            history.pushState({ route: 'dmarc', params: { domain } }, '', newPath);
        }
    }

    // Update breadcrumb
    setDmarcBreadcrumb('domain', { domain });
    dmarcShowView('dmarc-overview-view');

    try {
        const response = await authenticatedFetch(`/api/dmarc/domains/${encodeURIComponent(domain)}/overview?days=30`);
        const data = await response.json();
        const totals = data.totals || {};
        const dmarcRecord = data.dmarc_record || null;

        // DMARC record from DNS: reject is the goal, quarantine is on the way, none protects nothing
        const dmarcRecordCardHtml = (() => {
            if (!dmarcRecord) return '';
            const settings = dmarcRecord.settings || {};
            const policyLevel = (dmarcRecord.policy || settings.policy || 'unknown').toLowerCase();
            const POLICY_TONE = { reject: 'ok', quarantine: 'warn', none: 'fail' };
            // No policy to judge (no record, or one that does not parse): the check result colours it, like the TLS-RPT card
            const tone = POLICY_TONE[policyLevel] || { success: 'ok', warning: 'warn', error: 'fail' }[dmarcRecord.status] || '';
            const labels = { policy: 'Policy', subdomain_policy: 'Subdomain policy', aggregate_report_uris: 'Aggregate report URIs (rua)', forensic_report_uris: 'Forensic report URIs (ruf)', dkim_alignment: 'DKIM alignment', spf_alignment: 'SPF alignment', percentage: 'Percentage', failure_reporting_options: 'Failure reporting options' };
            const formatVal = (v) => Array.isArray(v) ? v.join(', ') : String(v);
            // Report URIs come from DNS: only mailto: becomes a link, anything else stays text
            const formatUriAsEmail = (uri) => {
                const text = String(uri).trim();
                if (!/^mailto:/i.test(text)) return escapeHtml(text);
                return `<a href="${escapeHtml(text)}" class="ui-link">${escapeHtml(text.replace(/^mailto:/i, ''))}</a>`;
            };
            const formatCell = (k, v) => {
                if ((k === 'aggregate_report_uris' || k === 'forensic_report_uris') && Array.isArray(v) && v.length) return v.map(formatUriAsEmail).join(', ');
                if (k === 'policy' || k === 'subdomain_policy') return uiTag(formatVal(v), POLICY_TONE[String(v || '').toLowerCase()] || '');
                return escapeHtml(formatVal(v));
            };
            const settingsRows = Object.keys(labels).filter(k => settings[k] !== undefined && settings[k] !== '')
                .map(k => `<div class="ui-kv"><span>${escapeHtml(labels[k])}</span><b class="ui-kv-small">${formatCell(k, settings[k])}</b></div>`).join('');
            return `
                <section class="ui-panel ui-dmarc-record${tone ? ` ui-dmarc-${tone}` : ''}">
                    <div class="ui-panel-head">DMARC Record</div>
                    <p class="ui-dmarc-record-msg${tone ? ` ui-text-${tone}` : ''}">${escapeHtml(dmarcRecord.message || 'No information')}</p>
                    ${settingsRows}
                    ${dmarcRecord.record ? `<details class="ui-dns-more ui-dmarc-record-raw"><summary>View Record</summary><div class="ui-dns-code"><code>${escapeHtml(dmarcRecord.record)}</code></div></details>` : ''}
                    ${(dmarcRecord.warnings && dmarcRecord.warnings.length) ? `<ul class="ui-dns-warnings ui-dmarc-record-warn">${dmarcRecord.warnings.map(w => `<li>${escapeHtml(w)}</li>`).join('')}</ul>` : ''}
                </section>
            `;
        })();

        const statsContainer = document.getElementById('dmarc-overview-stats-container');
        if (statsContainer) {
            statsContainer.innerHTML = `
                ${dmarcKpis([
                    [(totals.total_messages || 0).toLocaleString(), 'Total Messages', '', 'Last 30 days'],
                    [totals.dmarc_pass_pct ? `${totals.dmarc_pass_pct}%` : '-', 'DMARC Pass', totals.dmarc_pass_pct ? dmarcTone(totals.dmarc_pass_pct) : '', 'SPF + DKIM Pass'],
                    [(totals.unique_ips || 0).toLocaleString(), 'Sources', '', `${totals.unique_reporters || 0} reporters`],
                ])}
                ${dmarcRecordCardHtml}
            `;
        }

        renderDmarcChart(data.daily_stats || []);

        // Load initial sub-tab content based on current state
        dmarcShowSubTabPanel(dmarcState.currentSubTab);
        if (dmarcState.currentSubTab === 'reports') {
            await loadDomainReports(domain);
        } else if (dmarcState.currentSubTab === 'sources') {
            await loadDomainSources(domain);
        } else {
            // Default to reports
            await loadDomainReports(domain);
        }
    } catch (error) {
        console.error('Error loading domain overview:', error);
    }
}

// The chart follows the theme: ink for all mail, green for mail that passed
function dmarcChartColor(name, fallback) {
    const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return value || fallback;
}

function dmarcDestroyCharts() {
    ['chartInstance', 'tlsChartInstance'].forEach(key => {
        if (dmarcState[key]) {
            dmarcState[key].destroy();
            dmarcState[key] = null;
        }
    });
}

function renderDmarcChart(dailyStats) {
    dmarcLineChart('dmarc-chart', 'chartInstance', dailyStats, [
        ['Total Messages', d => d.total || 0, '--ui-ink', '#111814'],
        ['DMARC Pass', d => d.dmarc_pass || 0, '--ui-ok', '#12803F'],
    ]);
}

// The TLS tab's chart: the same lines, for TLS sessions
function renderTlsChart(dailyStats) {
    dmarcLineChart('dmarc-tls-chart', 'tlsChartInstance', dailyStats, [
        ['Total Sessions', d => d.total_sessions || 0, '--ui-ink', '#111814'],
        ['TLS Success', d => d.total_success || 0, '--ui-ok', '#12803F'],
    ]);
}

// Two lines by day: all of it in ink, the part that passed in green
function dmarcLineChart(canvasId, stateKey, dailyStats, series) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    if (dmarcState[stateKey]) {
        dmarcState[stateKey].destroy();
    }

    // d.date is an ISO date string, not a timestamp
    const labels = dailyStats.map(d => {
        const date = new Date(d.date);
        return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    });
    const muted = dmarcChartColor('--ui-muted', '#6B736E');
    const line = dmarcChartColor('--ui-line', '#E3E6E4');

    dmarcState[stateKey] = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: series.map(([label, value, color, fallback]) => ({
                label,
                data: dailyStats.map(value),
                borderColor: dmarcChartColor(color, fallback),
                backgroundColor: 'transparent',
                borderWidth: 2,
                pointRadius: 0,
                tension: 0.3
            }))
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: muted, boxWidth: 10, boxHeight: 10 } } },
            scales: {
                x: { ticks: { color: muted }, grid: { display: false } },
                y: { beginAtZero: true, ticks: { color: muted }, grid: { color: line } }
            }
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
            reportsList.innerHTML = '<p class="ui-empty">No daily reports available.</p>';
            return;
        }

        reportsList.innerHTML = `
            <div class="ui-table ui-stack" style="--ui-cols: minmax(130px, 1.2fr) 110px 100px 100px minmax(140px, 1fr); --ui-table-min: 600px">
                <div class="ui-tr ui-tr-head"><span>Date</span><span class="ui-td-end">Messages</span><span class="ui-td-end">Unique IPs</span><span class="ui-td-end">Reporters</span><span>DMARC Pass</span></div>
                ${reports.map(report => {
            const dateStr = new Date(report.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
            return `
                <div class="ui-tr" onclick="loadReportDetails('${escapeJsArg(domain)}', '${report.date}')">
                    <b class="ui-td">${dateStr}</b>
                    <span class="ui-td ui-td-end"><small class="ui-sec-unit">Messages </small>${(report.total_messages || 0).toLocaleString()}</span>
                    <span class="ui-td ui-td-end"><small class="ui-sec-unit">Unique IPs </small>${report.unique_ips}</span>
                    <span class="ui-td ui-td-end"><small class="ui-sec-unit">Reporters </small>${report.reports.length}</span>
                    <span class="ui-td">${dmarcRate(report.dmarc_pass_pct || 0)}</span>
                </div>`;
        }).join('')}
            </div>`;
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
            sourcesList.innerHTML = '<p class="ui-empty">No sources found.</p>';
            return;
        }

        sourcesList.innerHTML = `
            <div class="ui-table ui-stack" style="--ui-cols: minmax(220px, 2fr) 100px 80px 80px minmax(140px, 1fr); --ui-table-min: 660px">
                <div class="ui-tr ui-tr-head"><span>Source</span><span class="ui-td-end">Messages</span><span class="ui-td-end">SPF</span><span class="ui-td-end">DKIM</span><span>DMARC Pass</span></div>
                ${sources.map(s => `
                <div class="ui-tr" onclick="loadSourceDetails('${escapeJsArg(domain)}', '${escapeJsArg(s.source_ip)}')">
                    <div class="ui-td ui-q-who">
                        <div>${dmarcFlag(s.country_code, s.country_name)}${escapeHtml(s.asn_org || 'Unknown Provider')}</div>
                        <small>${escapeHtml(s.source_ip)}${s.country_name ? `, ${escapeHtml(s.country_name)}` : ''}</small>
                    </div>
                    <span class="ui-td ui-td-end"><small class="ui-sec-unit">Messages </small>${(s.total_count || 0).toLocaleString()}</span>
                    <span class="ui-td ui-td-end ${s.spf_pass_pct >= 95 ? 'ui-text-ok' : 'ui-text-fail'}"><small class="ui-sec-unit">SPF </small>${s.spf_pass_pct}%</span>
                    <span class="ui-td ui-td-end ${s.dkim_pass_pct >= 95 ? 'ui-text-ok' : 'ui-text-fail'}"><small class="ui-sec-unit">DKIM </small>${s.dkim_pass_pct}%</span>
                    <span class="ui-td">${dmarcRate(s.dmarc_pass_pct || 0)}</span>
                </div>`).join('')}
            </div>`;
    } catch (error) {
        console.error('Error loading sources:', error);
    }
}

// =============================================================================
// TLS REPORTS TAB
// =============================================================================

function dmarcSwitchSubTab(tab, replaceUrl = false) {
    dmarcState.currentSubTab = tab;

    // Each tab has its own address (/dmarc/example.com/sources); Daily Reports is the domain's own
    if (typeof currentTab !== 'undefined' && currentTab === 'dmarc' && dmarcState.currentDomain && typeof buildPath === 'function') {
        const params = tab === 'reports' ? { domain: dmarcState.currentDomain } : { domain: dmarcState.currentDomain, type: tab };
        const path = buildPath('dmarc', params);
        if (window.location.pathname !== path) {
            if (replaceUrl) history.replaceState({ route: 'dmarc', params }, '', path);
            else history.pushState({ route: 'dmarc', params }, '', path);
        }
    }

    dmarcShowSubTabPanel(tab);

    // Load the selected tab's content
    if (tab === 'reports') {
        loadDomainReports(dmarcState.currentDomain);
    } else if (tab === 'sources') {
        loadDomainSources(dmarcState.currentDomain);
    }
}

const DMARC_SUBTABS = ['reports', 'sources'];

// Mark the tab and show its panel, without loading anything
function dmarcShowSubTabPanel(tab) {
    DMARC_SUBTABS.forEach(name => {
        const button = document.getElementById(`dmarc-subtab-${name}`);
        if (button) {
            button.classList.toggle('active', name === tab);
            button.setAttribute('aria-selected', name === tab ? 'true' : 'false');
        }
        document.getElementById(`dmarc-${name}-content`)?.classList.toggle('hidden', name !== tab);
    });
}

// Manage Reports sits with Upload Report in the page head and counts both kinds of report
function dmarcUpdateManageButton(domains) {
    const manageBtn = document.getElementById('dmarc-manage-btn');
    if (!manageBtn) return;
    const totalReports = domains.reduce((sum, d) => sum + (d.report_count || 0) + (d.tls_report_count || 0), 0);
    manageBtn.textContent = `Manage Reports (${totalReports})`;
    manageBtn.classList.toggle('hidden', totalReports === 0);
}

// The last DNS check of a domain's TLS-RPT record, for the TLS domains list
function tlsRptStatusTag(status) {
    const tags = {
        success: ['Published', 'ok'],
        warning: ['Not published', 'warn'],
        error: ['Problem', 'fail'],
        unknown: ['Unknown', ''],
    };
    if (!tags[status]) {
        return `<span title="The daily DNS check covers the mailcow domains. Open the domain to check it now.">${uiTag('Not checked', '')}</span>`;
    }
    const [text, tone] = tags[status];
    return uiTag(text, tone);
}

// TLS tab: the domains that receive TLS reports, laid out like the DMARC domains list
async function loadTlsDomains() {
    dmarcState.currentView = 'tls_domains';
    dmarcState.currentDomain = null;
    dmarcState.detailType = null;
    dmarcDestroyCharts();
    dmarcShowView('dmarc-tls-domains-view');
    setDmarcBreadcrumb('domains');

    const list = document.getElementById('dmarc-tls-domains-list');
    const quiet = document.getElementById('dmarc-tls-quiet-domains');
    if (list) list.innerHTML = '<div class="ui-loading"><div class="loading"></div><p>Loading TLS reports...</p></div>';
    try {
        const response = await authenticatedFetch('/api/dmarc/domains');
        if (!response.ok) throw new Error('Failed to load domains');
        const allDomains = (await response.json()).domains || [];
        dmarcUpdateManageButton(allDomains);
        const domains = allDomains.filter(d => d.has_tls)
            .sort((a, b) => (b.tls_last_report || 0) - (a.tls_last_report || 0));

        const sessions = domains.reduce((sum, d) => sum + ((d.stats_30d || {}).tls_sessions || 0), 0);
        const successful = domains.reduce((sum, d) => sum + ((d.stats_30d || {}).tls_sessions || 0) * ((d.stats_30d || {}).tls_success_pct ?? 100) / 100, 0);
        const overallPct = sessions > 0 ? Math.round(successful / sessions * 100) : 0;
        const checked = domains.filter(d => d.tls_rpt_status).length;
        const published = domains.filter(d => d.tls_rpt_status === 'success').length;
        const stats = document.getElementById('dmarc-tls-stats-container');
        if (stats) {
            stats.innerHTML = dmarcKpis([
                [domains.length, 'Total Domains'],
                [sessions.toLocaleString(), 'Total Sessions'],
                [`${overallPct}%`, 'TLS Success', sessions ? dmarcTone(overallPct) : ''],
                [checked ? `${published} of ${checked}` : '-', 'TLS-RPT Published', checked && published < checked ? 'warn' : ''],
            ]);
        }

        // Domains with DMARC reports and no TLS report: most often no TLS-RPT record
        const noTls = allDomains.filter(d => !d.has_tls);
        if (quiet) {
            quiet.classList.toggle('hidden', !noTls.length);
            quiet.innerHTML = noTls.length ? `No TLS reports from ${noTls.map(d => `<button type="button" class="ui-link" onclick="loadTlsDomain('${escapeJsArg(d.domain)}')">${escapeHtml(d.domain)}</button>`).join(', ')}. Open a domain to check its TLS-RPT record.` : '';
        }

        if (!list) return;
        if (!domains.length) {
            list.innerHTML = '<p class="ui-empty">No TLS reports yet.</p>';
            return;
        }
        const day = ts => ts ? new Date(ts * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '-';
        list.innerHTML = `
            <div class="ui-tr ui-tr-head"><span>Domain</span><span>Activity Period</span><span class="ui-td-end">Reports</span><span class="ui-td-end">Sessions (30d)</span><span>TLS-RPT Record</span><span>TLS Success</span></div>
            ${domains.map(d => {
            const s = d.stats_30d || {};
            return `
                <div class="ui-tr" onclick="loadTlsDomain('${escapeJsArg(d.domain)}')">
                    <span class="ui-td"><b>${escapeHtml(d.domain)}</b></span>
                    <span class="ui-td"><small class="ui-sec-unit">Period </small>${day(d.tls_first_report)} - ${day(d.tls_last_report)}</span>
                    <span class="ui-td ui-td-end"><small class="ui-sec-unit">Reports </small>${d.tls_report_count || 0}</span>
                    <span class="ui-td ui-td-end"><small class="ui-sec-unit">Sessions </small>${(s.tls_sessions || 0).toLocaleString()}</span>
                    <span class="ui-td"><small class="ui-sec-unit">Record </small>${tlsRptStatusTag(d.tls_rpt_status)}</span>
                    <span class="ui-td"><small class="ui-sec-unit">TLS </small>${dmarcRate(s.tls_success_pct ?? 100)}</span>
                </div>`;
        }).join('')}`;
    } catch (error) {
        console.error('Error loading TLS domains:', error);
        if (list) list.innerHTML = '<p class="ui-empty ui-text-fail">Failed to load TLS reports. Refresh the page to try again.</p>';
    }
}

const TLS_SUBTABS = ['reports', 'providers'];

// Mark the TLS sub-tab and show its panel, like dmarcShowSubTabPanel
function tlsShowSubTabPanel(tab) {
    TLS_SUBTABS.forEach(name => {
        const button = document.getElementById(`tls-subtab-${name}`);
        if (button) {
            button.classList.toggle('active', name === tab);
            button.setAttribute('aria-selected', name === tab ? 'true' : 'false');
        }
        document.getElementById(`tls-${name}-content`)?.classList.toggle('hidden', name !== tab);
    });
}

// Daily Reports is the domain's own address; Providers is /dmarc/tls/<domain>/providers
function tlsSwitchSubTab(tab, replaceUrl = false) {
    dmarcState.tlsSubTab = tab;
    if (dmarcState.currentDomain) {
        const params = tab === 'providers' ? { tab: 'tls', domain: dmarcState.currentDomain, id: 'providers' } : { tab: 'tls', domain: dmarcState.currentDomain };
        const path = buildPath('dmarc', params);
        if (window.location.pathname !== path) {
            if (replaceUrl) history.replaceState({ route: 'dmarc', params }, '', path);
            else history.pushState({ route: 'dmarc', params }, '', path);
        }
    }
    tlsShowSubTabPanel(tab);
}

// TLS tab, one domain: the same layout as a DMARC domain
async function loadTlsDomain(domain, subTab = 'reports', updateUrl = true) {
    dmarcState.currentView = 'tls_domain';
    dmarcState.currentDomain = domain;
    dmarcState.detailType = null;
    dmarcState.tlsSubTab = subTab;
    dmarcShowPageTab('tls');
    if (updateUrl) {
        const params = { tab: 'tls', domain };
        const path = buildPath('dmarc', params);
        if (window.location.pathname !== path) history.pushState({ route: 'dmarc', params }, '', path);
    }
    setDmarcBreadcrumb('tlsDomain', { domain });
    dmarcShowView('dmarc-tls-domain-view');
    tlsShowSubTabPanel(subTab);

    const statsContainer = document.getElementById('dmarc-tls-overview-stats-container');
    const reportsList = document.getElementById('dmarc-tls-list');
    const providersList = document.getElementById('dmarc-tls-providers-list');
    if (statsContainer) statsContainer.innerHTML = '';
    if (reportsList) reportsList.innerHTML = '<div class="ui-loading"><div class="loading"></div><p>Loading reports...</p></div>';

    try {
        const [dailyRes, recordRes] = await Promise.all([
            authenticatedFetch(`/api/dmarc/domains/${encodeURIComponent(domain)}/tls-reports/daily?days=30`),
            authenticatedFetch(`/api/dmarc/domains/${encodeURIComponent(domain)}/tls-rpt-record`).catch(() => null),
        ]);
        if (!dailyRes.ok) throw new Error('Failed to load TLS reports');
        const data = await dailyRes.json();
        const record = recordRes && recordRes.ok ? (await recordRes.json()).tls_rpt_record : null;
        if (dmarcState.currentDomain !== domain) return;
        const days = data.data || [];
        const totals = data.totals || {};
        const sessions = (totals.total_successful_sessions || 0) + (totals.total_failed_sessions || 0);

        // Every provider across the 30 days, from the reports of each day
        const byProvider = {};
        days.forEach(d => (d.reports || []).forEach(r => {
            const name = r.organization_name || 'Unknown';
            const p = byProvider[name] || (byProvider[name] = { name, reports: 0, success: 0, fail: 0 });
            p.reports += 1;
            p.success += r.successful_sessions || 0;
            p.fail += r.failed_sessions || 0;
        }));
        const providers = Object.values(byProvider).sort((a, b) => (b.success + b.fail) - (a.success + a.fail));

        if (statsContainer) {
            statsContainer.innerHTML = `
                ${dmarcKpis([
                    [sessions.toLocaleString(), 'Total Sessions', '', 'Last 30 days'],
                    [sessions ? `${totals.overall_success_rate}%` : '-', 'TLS Success', sessions ? dmarcTone(totals.overall_success_rate) : '', 'Encrypted sessions'],
                    [providers.length.toLocaleString(), 'Providers', '', `${totals.total_reports || 0} reports`],
                ])}
                ${renderTlsRptRecordCard(record)}
            `;
        }

        renderTlsChart([...days].reverse());

        if (reportsList) {
            reportsList.innerHTML = !days.length ? '<p class="ui-empty">No daily reports available.</p>' : `
                <div class="ui-table ui-stack" style="--ui-cols: minmax(130px, 1.2fr) 110px 100px 100px minmax(140px, 1fr); --ui-table-min: 600px">
                    <div class="ui-tr ui-tr-head"><span>Date</span><span class="ui-td-end">Sessions</span><span class="ui-td-end">Failed</span><span class="ui-td-end">Reporters</span><span>TLS Success</span></div>
                    ${days.map(d => `
                    <div class="ui-tr" onclick="loadTLSReportDetails('${escapeJsArg(domain)}', '${escapeJsArg(d.date)}')">
                        <b class="ui-td">${new Date(d.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}</b>
                        <span class="ui-td ui-td-end"><small class="ui-sec-unit">Sessions </small>${(d.total_sessions || 0).toLocaleString()}</span>
                        <span class="ui-td ui-td-end${d.total_fail ? ' ui-text-fail' : ''}"><small class="ui-sec-unit">Failed </small>${(d.total_fail || 0).toLocaleString()}</span>
                        <span class="ui-td ui-td-end"><small class="ui-sec-unit">Reporters </small>${d.organization_count || 0}</span>
                        <span class="ui-td">${dmarcRate(d.success_rate)}</span>
                    </div>`).join('')}
                </div>`;
        }

        if (providersList) {
            providersList.innerHTML = !providers.length ? '<p class="ui-empty">No providers found.</p>' : `
                <div class="ui-table ui-stack" style="--ui-cols: minmax(220px, 2fr) 100px 80px 80px minmax(140px, 1fr); --ui-table-min: 660px">
                    <div class="ui-tr ui-tr-head"><span>Provider</span><span class="ui-td-end">Sessions</span><span class="ui-td-end">Success</span><span class="ui-td-end">Failed</span><span>TLS Success</span></div>
                    ${providers.map(p => {
                    const total = p.success + p.fail;
                    const pct = total ? Math.round(p.success / total * 10000) / 100 : 100;
                    return `
                    <div class="ui-tr">
                        <div class="ui-td ui-q-who"><div>${escapeHtml(p.name)}</div><small>${p.reports} report${p.reports === 1 ? '' : 's'}</small></div>
                        <span class="ui-td ui-td-end"><small class="ui-sec-unit">Sessions </small>${total.toLocaleString()}</span>
                        <span class="ui-td ui-td-end ui-text-ok"><small class="ui-sec-unit">Success </small>${p.success.toLocaleString()}</span>
                        <span class="ui-td ui-td-end${p.fail ? ' ui-text-fail' : ''}"><small class="ui-sec-unit">Failed </small>${p.fail.toLocaleString()}</span>
                        <span class="ui-td">${dmarcRate(pct)}</span>
                    </div>`;
                }).join('')}
                </div>`;
        }
    } catch (error) {
        console.error('Error loading TLS reports:', error);
        if (reportsList) reportsList.innerHTML = '<p class="ui-empty ui-text-fail">Failed to load TLS reports.</p>';
    }
}

// TLS tab, one day: its own view, like the DMARC report details
async function loadTLSReportDetails(domain, reportDate, updateUrl = true) {
    dmarcState.currentView = 'tls_details';
    dmarcState.currentDomain = domain;
    dmarcState.detailType = 'tls';
    dmarcShowPageTab('tls');
    if (updateUrl) {
        const params = { tab: 'tls', domain, id: reportDate };
        const path = buildPath('dmarc', params);
        if (window.location.pathname !== path) history.pushState({ route: 'dmarc', params }, '', path);
    }
    dmarcShowView('dmarc-tls-details-view');
    const shortDate = new Date(reportDate).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    setDmarcBreadcrumb('tlsDetails', { domain, date: shortDate });

    const statsContainer = document.getElementById('tls-details-stats-container');
    const list = document.getElementById('tls-detail-providers-list');
    if (list) list.innerHTML = '<div class="ui-loading"><div class="loading"></div><p>Loading providers...</p></div>';
    try {
        const response = await authenticatedFetch(`/api/dmarc/domains/${encodeURIComponent(domain)}/tls-reports/${encodeURIComponent(reportDate)}/details`);
        if (!response.ok) throw new Error('Failed to load TLS report details');
        const data = await response.json();
        const stats = data.stats || {};
        const providers = data.providers || [];

        if (statsContainer) {
            statsContainer.innerHTML = dmarcKpis([
                [(stats.total_sessions || 0).toLocaleString(), 'Sessions'],
                [(stats.total_success || 0).toLocaleString(), 'Successful', '', `${stats.success_rate ?? 100}%`],
                [(stats.total_fail || 0).toLocaleString(), 'Failed', stats.total_fail ? 'fail' : ''],
                [(stats.total_providers || providers.length).toLocaleString(), 'Providers'],
            ]);
        }
        if (!list) return;
        if (!providers.length) {
            list.innerHTML = '<p class="ui-empty">No providers found.</p>';
            return;
        }
        list.innerHTML = `
            <div class="ui-table ui-stack" style="--ui-cols: minmax(200px, 2fr) 100px 100px 90px minmax(140px, 1fr); --ui-table-min: 640px">
                <div class="ui-tr ui-tr-head"><span>Provider</span><span class="ui-td-end">Sessions</span><span class="ui-td-end">Success</span><span class="ui-td-end">Failed</span><span>TLS Success</span></div>
                ${providers.map(p => `
                <div class="ui-tr">
                    <div class="ui-td ui-q-who"><div>${escapeHtml(p.organization_name || 'Unknown')}</div><small>${p.policies?.length || 0} policies</small></div>
                    <span class="ui-td ui-td-end"><small class="ui-sec-unit">Sessions </small>${(p.total_sessions || 0).toLocaleString()}</span>
                    <span class="ui-td ui-td-end ui-text-ok"><small class="ui-sec-unit">Success </small>${(p.successful_sessions || 0).toLocaleString()}</span>
                    <span class="ui-td ui-td-end${p.failed_sessions ? ' ui-text-fail' : ''}"><small class="ui-sec-unit">Failed </small>${(p.failed_sessions || 0).toLocaleString()}</span>
                    <span class="ui-td">${dmarcRate(p.success_rate)}</span>
                </div>`).join('')}
            </div>`;
    } catch (error) {
        console.error('Error loading TLS report details:', error);
        if (list) list.innerHTML = '<p class="ui-empty ui-text-fail">Failed to load TLS report details.</p>';
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

    dmarcShowView('dmarc-report-details-view');

    const shortDate = new Date(reportDate).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    // Title stays static as "DMARC & TLS Reports"

    // Update breadcrumb
    setDmarcBreadcrumb('reportDetails', { domain, date: shortDate });

    try {
        const response = await authenticatedFetch(`/api/dmarc/domains/${encodeURIComponent(domain)}/reports/${reportDate}/details`);
        const data = await response.json();
        const totals = data.totals || {};

        const statsContainer = document.getElementById('report-details-stats-container');
        if (statsContainer) {
            statsContainer.innerHTML = generateDetailStatsGrid(totals);
        }

        const sources = data.sources || [];
        const sourcesList = document.getElementById('report-detail-sources-list');

        if (sources.length === 0) {
            sourcesList.innerHTML = '<p class="ui-empty">No sources found.</p>';
            return;
        }

        sourcesList.innerHTML = `
            <div class="ui-table ui-stack" style="--ui-cols: minmax(200px, 1.8fr) minmax(120px, 1fr) minmax(120px, 1fr) 80px 80px 80px 80px minmax(110px, 1fr); --ui-table-min: 1000px">
                <div class="ui-tr ui-tr-head"><span>Source</span><span>From: domain</span><span>Envelope from: domain</span><span class="ui-td-end">Volume</span><span class="ui-td-end">DMARC pass</span><span class="ui-td-end">SPF aligned</span><span class="ui-td-end">DKIM aligned</span><span>Reporter</span></div>
                ${sources.map(s => `
                <div class="ui-tr" onclick="loadSourceDetails('${escapeJsArg(domain)}', '${escapeJsArg(s.source_ip)}')">
                    <div class="ui-td ui-q-who">
                        <div>${dmarcFlag(s.country_code, s.country_name)}${escapeHtml(s.asn_org || s.source_name || 'Unknown')}</div>
                        <small>${escapeHtml(s.source_ip)}</small>
                    </div>
                    <span class="ui-td">${escapeHtml(s.header_from || '-')}</span>
                    <span class="ui-td">${escapeHtml(s.envelope_from || '-')}</span>
                    <span class="ui-td ui-td-end">${(s.volume || 0).toLocaleString()}</span>
                    ${dmarcPctCell(s.dmarc_pass_pct)}
                    ${dmarcPctCell(s.spf_pass_pct)}
                    ${dmarcPctCell(s.dkim_pass_pct)}
                    <span class="ui-td">${escapeHtml(s.reporter || '-')}</span>
                </div>`).join('')}
            </div>
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

    dmarcShowView('dmarc-source-details-view');
    // Title stays static as "DMARC & TLS Reports"

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

        const totals = data.totals || {};
        const statsContainer = document.getElementById('source-details-stats-container');
        if (statsContainer) {
            statsContainer.innerHTML = generateDetailStatsGrid(totals);
        }

        const envelopes = data.envelope_from_groups || [];
        const envelopeList = document.getElementById('source-detail-envelope-list');

        if (envelopes.length === 0) {
            envelopeList.innerHTML = '<p class="ui-empty">No data found.</p>';
            return;
        }

        envelopeList.innerHTML = `
            <div class="ui-table ui-stack" style="--ui-cols: minmax(140px, 1.2fr) minmax(140px, 1.2fr) 80px 80px 80px 80px minmax(110px, 1fr); --ui-table-min: 820px">
                <div class="ui-tr ui-tr-head"><span>From: domain</span><span>Envelope from: domain</span><span class="ui-td-end">Volume</span><span class="ui-td-end">DMARC pass</span><span class="ui-td-end">SPF aligned</span><span class="ui-td-end">DKIM aligned</span><span>Reporter</span></div>
                ${envelopes.map(env => {
            const pct = count => env.volume > 0 ? Math.round((count / env.volume) * 100) : 0;
            return `
                <div class="ui-tr">
                    <span class="ui-td">${escapeHtml(env.header_from || '-')}</span>
                    <span class="ui-td">${escapeHtml(env.envelope_from || '-')}</span>
                    <span class="ui-td ui-td-end">${(env.volume || 0).toLocaleString()}</span>
                    ${dmarcPctCell(pct(env.dmarc_pass))}
                    ${dmarcPctCell(pct(env.spf_aligned))}
                    ${dmarcPctCell(pct(env.dkim_aligned))}
                    <span class="ui-td">${escapeHtml(env.reporter || '-')}</span>
                </div>`;
        }).join('')}
            </div>
        `;
    } catch (error) {
        console.error('Error loading source details:', error);
    }
}


function generateDetailStatsGrid(totals) {
    return dmarcKpis([
        [(totals.total_messages || 0).toLocaleString(), 'Volume'],
        [(totals.dmarc_pass || 0).toLocaleString(), 'DMARC Pass', '', `${totals.dmarc_pass_pct || 0}%`],
        [(totals.spf_pass || 0).toLocaleString(), 'SPF Aligned', '', `${totals.spf_pass_pct || 0}%`],
        [(totals.dkim_pass || 0).toLocaleString(), 'DKIM Aligned', '', `${totals.dkim_pass_pct || 0}%`],
    ]);
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

            // Reload what the page shows, on either tab
            handleDmarcRoute(parseRoute().params);
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

        if (dmarcImapStatus.latest_sync) {
            const sync = dmarcImapStatus.latest_sync;
            const tone = sync.status === 'error' ? 'ui-text-fail' : sync.status === 'running' ? 'ui-text-info' : 'ui-text-ok';
            const state = sync.status === 'error' ? 'failed' : sync.status === 'running' ? 'running' : 'done';
            lastSyncInfo.innerHTML = `
                <span class="${tone}" title="${escapeHtml(formatTime(sync.started_at))}">Last sync ${state}: ${formatAgo(sync.started_at)}</span>
                <button type="button" onclick="showDmarcSyncHistory()" class="ui-link-row ui-link">View History</button>
            `;
        } else {
            lastSyncInfo.innerHTML = '<span class="ui-muted">Never synced</span>';
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
            content.innerHTML = '<p class="ui-empty">No sync history yet</p>';
            return;
        }

        const STATUS_TONE = { success: 'ok', error: 'fail', running: 'info' };
        content.innerHTML = `
            <div class="ui-table ui-stack" style="--ui-cols: minmax(150px, 1.4fr) 80px 90px 70px 70px 80px 70px 80px; --ui-table-min: 760px">
                <div class="ui-tr ui-tr-head"><span>Date</span><span>Type</span><span>Status</span><span class="ui-td-end">Emails</span><span class="ui-td-end">Created</span><span class="ui-td-end">Duplicate</span><span class="ui-td-end">Failed</span><span>Duration</span></div>
                ${data.data.map(sync => `
                <div class="ui-tr">
                    <span class="ui-td">${formatDate(sync.started_at)}</span>
                    <span class="ui-td">${uiTag(sync.sync_type, sync.sync_type === 'manual' ? 'info' : '')}</span>
                    <span class="ui-td">${uiTag(sync.status, STATUS_TONE[sync.status] || '')}</span>
                    <span class="ui-td ui-td-end"><small class="ui-sec-unit">Emails </small>${sync.emails_found || 0}</span>
                    <span class="ui-td ui-td-end ui-text-ok"><small class="ui-sec-unit">Created </small>${sync.reports_created || 0}</span>
                    <span class="ui-td ui-td-end ui-muted"><small class="ui-sec-unit">Duplicate </small>${sync.reports_duplicate || 0}</span>
                    <span class="ui-td ui-td-end${sync.reports_failed > 0 ? ' ui-text-fail' : ''}"><small class="ui-sec-unit">Failed </small>${sync.reports_failed || 0}</span>
                    <span class="ui-td">${sync.duration_seconds ? `${Math.round(sync.duration_seconds)}s` : '-'}</span>
                </div>`).join('')}
            </div>
        `;

    } catch (error) {
        console.error('Error loading sync history:', error);
        content.innerHTML = '<p class="ui-empty ui-text-fail">Failed to load sync history</p>';
    }
}

function closeDmarcSyncHistoryModal() {
    document.getElementById('dmarc-sync-history-modal').classList.add('hidden');
}

// =============================================================================
// REPORTS MANAGEMENT
// =============================================================================
// This part runs in the pagination test with only document, authenticatedFetch,
// escapeHtml, escapeJsArg, console, showToast, showConfirmModal and dmarcState.

const reportsManagementState = { page: 1, limit: 50, request: 0 };

async function showReportsManagementModal() {
    const modal = document.getElementById('dmarc-reports-management-modal');
    modal.classList.remove('hidden');
    modal.onclick = (event) => {
        if (event.target === modal) closeReportsManagementModal();
    };
    await loadReportsManagementPage(1);
}

async function loadReportsManagementPage(page) {
    if (!Number.isInteger(page) || page < 1) return;
    const request = ++reportsManagementState.request;
    const content = document.getElementById('dmarc-reports-management-content');

    // Show loading
    content.innerHTML = '<div class="ui-loading"><div class="loading"></div><p>Loading reports...</p></div>';

    try {
        const response = await authenticatedFetch(`/api/dmarc/reports/all?page=${page}&limit=${reportsManagementState.limit}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (request !== reportsManagementState.request) return;
        reportsManagementState.page = data.page;
        renderReportsManagementTable(data.reports || [], data.allow_delete, data);

    } catch (error) {
        if (request !== reportsManagementState.request) return;
        console.error('Error loading reports:', error);
        content.innerHTML = `<div class="ui-empty"><p class="ui-text-fail">Failed to load reports. Please try again.</p>
            <button onclick="loadReportsManagementPage(${page})" class="ui-btn ui-btn-sm">Retry</button></div>`;
    }
}

function closeReportsManagementModal() {
    reportsManagementState.request++;
    document.getElementById('dmarc-reports-management-modal').classList.add('hidden');
}

function renderReportsManagementTable(reports, allowDelete, { total, page, total_pages: totalPages }) {
    const content = document.getElementById('dmarc-reports-management-content');

    if (reports.length === 0) {
        content.innerHTML = '<p class="ui-empty">No reports found</p>';
        return;
    }

    const pageButton = (label, target, disabled) => `<button onclick="loadReportsManagementPage(${target})" ${disabled ? 'disabled' : ''} class="ui-btn ui-btn-sm">${label}</button>`;
    const pagination = totalPages > 1 ? `<nav aria-label="Report pages" class="ui-pager">
        ${pageButton('First', 1, page === 1)}
        ${pageButton('Previous', page - 1, page === 1)}
        <span class="ui-muted">Page ${page} of ${totalPages}</span>
        ${pageButton('Next', page + 1, page === totalPages)}
        ${pageButton('Last', totalPages, page === totalPages)}
    </nav>` : '';
    const dateTime = value => value ? new Date(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '-';
    const day = ts => ts ? new Date(ts * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '-';
    const cols = allowDelete
        ? '--ui-cols: minmax(150px, 1.2fr) 70px minmax(140px, 1.2fr) minmax(120px, 1fr) 70px minmax(110px, .9fr) 80px'
        : '--ui-cols: minmax(150px, 1.2fr) 70px minmax(140px, 1.2fr) minmax(120px, 1fr) 70px minmax(110px, .9fr)';

    content.innerHTML = `
        <p class="ui-muted ui-mgmt-total">
            Total: <span class="ui-strong">${total}</span> reports
            ${!allowDelete ? '<span class="ui-tag ui-tag-warn">Deletion disabled</span>' : ''}
        </p>
        <div data-nosort class="ui-table ui-stack" style="${cols}; --ui-table-min: 780px">
            <div class="ui-tr ui-tr-head"><span>Import Date</span><span>Type</span><span>Domain</span><span>Reporter</span><span class="ui-td-end">Records</span><span>Period</span>${allowDelete ? '<span class="ui-td-end">Actions</span>' : ''}</div>
            ${reports.map(report => `
            <div class="ui-tr">
                <span class="ui-td">${dateTime(report.created_at)}</span>
                <span class="ui-td"><span class="ui-tag${report.type === 'dmarc' ? ' ui-tag-info' : ' ui-tag-ok'}">${report.type.toUpperCase()}</span></span>
                <b class="ui-td">${escapeHtml(report.domain)}</b>
                <span class="ui-td">${escapeHtml(report.org_name || '-')}</span>
                <span class="ui-td ui-td-end"><small class="ui-sec-unit">Records </small>${report.record_count}</span>
                <span class="ui-td">${day(report.begin_date)} - ${day(report.end_date)}</span>
                ${allowDelete ? `<span class="ui-td ui-td-end ui-row-actions"><button onclick="deleteReport('${report.type}', ${report.id}, '${escapeJsArg(report.domain)}')" class="ui-btn ui-btn-sm ui-btn-danger" title="Delete report">Delete</button></span>` : ''}
            </div>`).join('')}
        </div>
        ${pagination}
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
        if (!document.getElementById('dmarc-reports-management-modal').classList.contains('hidden')) {
            await loadReportsManagementPage(reportsManagementState.page);
        }

        // Refresh domains list if visible
        if (dmarcState.currentView === 'domains') {
            await loadDmarcDomains();
        }

    } catch (error) {
        console.error('Error deleting report:', error);
        showToast('Failed to delete report', 'error');
    }
}
