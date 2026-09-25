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
    const disabled = window.disabledFeatures || [];
    // The feature can be turned off while the Rate Limits view is open
    if (view === 'rate-limits' && disabled.includes('rate-limits')) {
        view = 'statistics';
    }
    // The mirror: Rate Limits does not depend on Mailbox Stats, so with
    // Mailbox Stats off this page is the Rate Limits page and Statistics is
    // not a view you can reach - including on first entry. The guard above
    // runs first, so with both features off nothing bounces back here.
    if (view === 'statistics' && disabled.includes('mailbox-stats') && !disabled.includes('rate-limits')) {
        view = 'rate-limits';
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

    // The help button next to the title follows the view - each view opens
    // its own doc. The last-update stamp belongs to Statistics only.
    const helpBtn = document.getElementById('mailbox-stats-help-btn');
    if (helpBtn) {
        const isRateLimits = view === 'rate-limits';
        helpBtn.style.display = '';
        helpBtn.setAttribute('onclick', `showHelpModal('${isRateLimits ? 'Rate_Limits' : 'Mailbox_Stats'}')`);
        helpBtn.title = isRateLimits ? 'Help - Rate Limits' : 'Help - Mailbox Statistics';
    }
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
                <div class="ui-empty">
                    <p class="ui-text-fail">Failed to load mailbox statistics</p>
                    <p>${escapeHtml(error.message)}</p>
                    <button onclick="loadMailboxStats()" class="ui-btn ui-btn-sm">Retry</button>
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

// A count that opens Messages filtered on this address
function mailboxStatLink(email, filter, value, label, tone) {
    const args = `{ email: '${escapeJsArg(email)}', filterType: 'search', ${filter} }`;
    return `<button type="button" class="ui-kpi ui-kpi-btn" onclick="event.stopPropagation(); navigateToMessagesWithFilter(${args})" title="Open these messages">
        <b class="${tone ? `ui-${tone}` : ''}">${(value || 0).toLocaleString()}</b>${label}</button>`;
}

function mailboxRateLimitLabel(mb) {
    if (!mb.rl_value) return 'None';
    const frame = { s: 'sec', m: 'min', h: 'hour', d: 'day' }[mb.rl_frame] || mb.rl_frame || 'min';
    return `${mb.rl_value}/${frame}`;
}

function renderMailboxStatsAccordion(mailboxes, page = 1, totalPages = 1) {
    const container = document.getElementById('mailbox-stats-list');
    if (!container) return;

    if (mailboxes.length === 0) {
        container.innerHTML = '<p class="ui-empty ui-panel">No mailboxes found</p>';
        return;
    }

    const hideZero = document.getElementById('mailbox-stats-hide-zero')?.checked ?? true;
    const sum = (mb, key) => (mb.aliases || []).reduce((total, a) => total + (a[key] || 0), 0);
    const access = (on, label, last) => `
        <div class="ui-md-fact"><span><i class="ui-mdot ${on ? 'ui-mdot-ok' : 'ui-mdot-fail'}"></i> ${label}</span>
            ${last !== undefined ? `<div>${last ? formatTime(last) : 'Never'}</div>` : `<div>${on ? 'On' : 'Off'}</div>`}</div>`;

    let html = `
        <div class="ui-table ui-stack ui-ms-table">
            <div class="ui-tr ui-tr-head"><span>Mailbox</span><span class="ui-td-end">Sent</span><span class="ui-td-end">Received</span><span class="ui-td-end">Delivered</span><span class="ui-td-end">Failed</span><span class="ui-td-end">Aliases</span><span class="ui-td-end">Storage</span></div>
            ${mailboxes.map((mb, index) => {
        const isExpanded = mailboxStatsCache.expandedMailboxes.has(mb.username);
        const failTone = mb.combined_failure_rate >= 10 ? 'fail' : mb.combined_failure_rate >= 5 ? 'warn' : '';
        const aliases = (mb.aliases || []).filter(a => !hideZero || (a.sent_total || 0) + (a.received_total || 0) > 0);
        const email = mb.username;
        return `
            <div class="ui-tr ui-ms-row" onclick="toggleMailboxAccordion('${escapeJsArg(mb.username)}')">
                <div class="ui-td ui-q-who">
                    <div><svg id="accordion-icon-${index}" class="ui-domain-chevron" width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"${isExpanded ? ' style="transform: rotate(90deg)"' : ''}><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>${escapeHtml(mb.username)} ${mb.active ? '' : uiTag('Inactive', 'fail')}</div>
                    ${mb.name ? `<small>${escapeHtml(mb.name)}</small>` : ''}
                </div>
                <span class="ui-td ui-td-end"><small class="ui-sec-unit">Sent </small>${mb.combined_sent.toLocaleString()}</span>
                <span class="ui-td ui-td-end"><small class="ui-sec-unit">Received </small>${mb.combined_received.toLocaleString()}</span>
                <span class="ui-td ui-td-end"><small class="ui-sec-unit">Delivered </small>${(mb.combined_delivered || 0).toLocaleString()}</span>
                <span class="ui-td ui-td-end${failTone ? ` ui-text-${failTone}` : ''}"><small class="ui-sec-unit">Failed </small>${mb.combined_failure_rate}%</span>
                <span class="ui-td ui-td-end"><small class="ui-sec-unit">Aliases </small>${mb.alias_count || 0}</span>
                <span class="ui-td ui-td-end"><small class="ui-sec-unit">Storage </small>${mb.quota_used_formatted}</span>

                <div id="accordion-content-${index}" class="ui-domain-details${isExpanded ? '' : ' hidden'}" onclick="event.stopPropagation()">
                    <div class="ui-md-ids">
                        <div class="ui-md-fact"><span>Quota Used</span><div>${mb.quota_used_formatted} / ${mb.quota_formatted}</div><small class="ui-muted">${mb.percent_in_use || 0}% used</small></div>
                        <div class="ui-md-fact"><span>Messages in Mailbox</span><div>${(mb.messages_in_mailbox || 0).toLocaleString()}</div></div>
                        <div class="ui-md-fact"><span>Created / Modified</span><div>${mb.created ? formatTime(mb.created) : 'N/A'}</div><small class="ui-muted">${mb.modified ? formatTime(mb.modified) : 'N/A'}</small></div>
                        <div class="ui-md-fact"><span>Rate Limit</span><div>${escapeHtml(mailboxRateLimitLabel(mb))}</div></div>
                        ${access(mb.attributes?.imap_access === '1', 'IMAP', mb.last_imap_login || null)}
                        ${access(mb.attributes?.pop3_access === '1', 'POP3', mb.last_pop3_login || null)}
                        ${access(mb.attributes?.smtp_access === '1', 'SMTP', mb.last_smtp_login || null)}
                        ${access(mb.attributes?.sieve_access === '1', 'Sieve')}
                        ${access(mb.attributes?.tls_enforce_in === '1' || mb.attributes?.tls_enforce_out === '1', 'TLS Enforce')}
                    </div>

                    <h4 class="ui-md-h">Message Statistics</h4>
                    <div class="ui-kpis ui-ms-counts">
                        ${mailboxStatLink(email, "direction: 'outbound'", mb.combined_sent, 'Sent')}
                        ${mailboxStatLink(email, "direction: 'inbound'", mb.combined_received, 'Received')}
                        ${mailboxStatLink(email, "direction: 'internal'", mb.combined_internal, 'Internal')}
                        ${mailboxStatLink(email, "status: 'delivered'", mb.combined_delivered, 'Delivered', 'ok')}
                        ${mailboxStatLink(email, "status: 'deferred'", (mb.mailbox_counts?.sent_deferred || 0) + sum(mb, 'sent_deferred'), 'Deferred', 'warn')}
                        ${mailboxStatLink(email, "status: 'bounced'", (mb.mailbox_counts?.sent_bounced || 0) + sum(mb, 'sent_bounced'), 'Bounced', 'fail')}
                        ${mailboxStatLink(email, "status: 'rejected'", (mb.mailbox_counts?.sent_rejected || 0) + sum(mb, 'sent_rejected'), 'Rejected', 'fail')}
                    </div>

                    ${mb.aliases && mb.aliases.length > 0 ? `
                        <h4 class="ui-md-h">Aliases (${mb.aliases.length})</h4>
                        <div class="ui-table ui-stack ui-ms-aliases">
                            <div class="ui-tr ui-tr-head"><span>Alias</span><span class="ui-td-end">Sent</span><span class="ui-td-end">Received</span><span class="ui-td-end">Internal</span><span class="ui-td-end">Delivered</span><span class="ui-td-end">Deferred</span><span class="ui-td-end">Bounced</span><span class="ui-td-end">Rejected</span><span class="ui-td-end">Fail %</span></div>
                            ${aliases.map(alias => {
            const go = (filter, value, label, tone) => `<button type="button" class="ui-td ui-td-end ui-link-cell${tone ? ` ui-text-${tone}` : ''}" onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeJsArg(alias.alias_address)}', filterType: 'search', ${filter} })"><small class="ui-sec-unit">${label} </small>${value || 0}</button>`;
            return `
                            <div class="ui-tr">
                                <span class="ui-td">${escapeHtml(alias.alias_address)}
                                    ${alias.is_catch_all ? uiTag('catch-all', 'warn') : ''}
                                    ${alias.is_domain_alias ? '<span class="ui-tag ui-tag-info" title="Address on a mailcow alias domain that points at this mailbox">domain alias</span>' : ''}
                                    ${!alias.active ? uiTag('inactive', '') : ''}</span>
                                ${go("direction: 'outbound'", alias.sent_total, 'Sent')}
                                ${go("direction: 'inbound'", alias.received_total, 'Received')}
                                ${go("direction: 'internal'", alias.direction_internal, 'Internal')}
                                ${go("status: 'delivered'", alias.sent_delivered, 'Delivered', 'ok')}
                                ${go("status: 'deferred'", alias.sent_deferred, 'Deferred', 'warn')}
                                ${go("status: 'bounced'", alias.sent_bounced, 'Bounced', 'fail')}
                                ${go("status: 'rejected'", alias.sent_rejected, 'Rejected', 'fail')}
                                <span class="ui-td ui-td-end${alias.failure_rate >= 5 ? ' ui-text-fail' : ' ui-muted'}"><small class="ui-sec-unit">Fail </small>${alias.failure_rate || 0}%</span>
                            </div>`;
        }).join('')}
                        </div>
                    ` : ''}
                </div>
            </div>`;
    }).join('')}
        </div>`;

    // Add pagination controls if there are multiple pages
    if (totalPages > 1) {
        const pageButton = (label, target, disabled) => `<button onclick="loadMailboxStatsPage(${target})" ${disabled ? 'disabled' : ''} class="ui-btn ui-btn-sm">${label}</button>`;
        html += `
            <nav class="ui-pager" aria-label="Mailbox pages">
                ${pageButton('First', 1, page === 1)}
                ${pageButton('Previous', page - 1, page === 1)}
                <span class="ui-muted">Page ${page} of ${totalPages}</span>
                ${pageButton('Next', page + 1, page === totalPages)}
                ${pageButton('Last', totalPages, page === totalPages)}
            </nav>
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
        if (icon) icon.style.transform = isHidden ? 'rotate(90deg)' : '';
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
        if (arrow) arrow.style.transform = 'rotate(180deg)';

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
    if (arrow) arrow.style.transform = '';
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
        btn.setAttribute('aria-pressed', btn.getAttribute('data-preset') === activePreset ? 'true' : 'false');
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
