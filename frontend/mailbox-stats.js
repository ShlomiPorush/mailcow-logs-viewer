let mailboxStatsCache = {
    summary: null,
    mailboxes: null,
    domains: null,
    lastLoad: null,
    expandedMailboxes: new Set(),
    openAliases: new Set()
};

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


function initMailboxStatsPage() {
    mailboxStatsSwitchView(mailboxStatsView);
}


function mailboxStatsSwitchView(view) {
    if (mailboxStatsView === 'rate-limits' && view !== 'rate-limits'
        && uiUnsavedCount({ route: 'mailbox-stats', params: { sub: view }, reload: true })) {
        uiConfirmLeave({ route: 'mailbox-stats', params: { sub: view }, reload: true }).then(ok => { if (ok) mailboxStatsSwitchView(view); });
        return;
    }
    const requested = view;
    const disabled = window.disabledFeatures || [];
    if (view === 'rate-limits' && disabled.includes('rate-limits')) {
        view = 'statistics';
    }
    if (view === 'statistics' && disabled.includes('mailbox-stats') && !disabled.includes('rate-limits')) {
        view = 'rate-limits';
    }
    mailboxStatsView = view;
    routerSyncSubpage('mailbox-stats', view, view !== requested);

    document.querySelectorAll('[id^="mailbox-stats-view-"]').forEach(btn => {
        btn.classList.remove('active');
        btn.setAttribute('aria-selected', 'false');
    });
    const activeBtn = document.getElementById(`mailbox-stats-view-${view}`);
    if (activeBtn) {
        activeBtn.classList.add('active');
        activeBtn.setAttribute('aria-selected', 'true');
    }

    const headings = MAILBOX_STATS_VIEW_HEADINGS[view] || MAILBOX_STATS_VIEW_HEADINGS['statistics'];
    const title = document.getElementById('mailbox-stats-page-title');
    if (title) title.textContent = headings.title;
    const subtitle = document.getElementById('mailbox-stats-page-subtitle');
    if (subtitle) subtitle.textContent = headings.subtitle;

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

    const loading = document.getElementById('mailbox-stats-loading');
    const content = document.getElementById('mailbox-stats-content');

    uiLoadingShow(loading);
    if (content) content.classList.add('hidden');

    try {
        const [summaryRes, domainsRes] = await Promise.all([
            authenticatedFetch(mailboxStatsSummaryUrl()),
            authenticatedFetch('/api/mailbox-stats/domains')
        ]);

        if (!summaryRes.ok) throw await responseError(summaryRes);
        if (!domainsRes.ok) throw await responseError(domainsRes);

        const summary = await summaryRes.json();
        const domains = await domainsRes.json();
        const failed = summary.error || domains.error;
        if (failed) throw new Error(failed);

        mailboxStatsCache.summary = summary;
        mailboxStatsCache.domains = domains.domains || [];

        renderMailboxStatsSummary(summary);

        populateMailboxStatsDomainFilter(mailboxStatsCache.domains);

        await loadMailboxStatsList();

        const lastUpdateEl = document.getElementById('mailbox-stats-last-update');
        if (lastUpdateEl && summary.last_update) {
            uiAgo(lastUpdateEl, summary.last_update, 'Updated ');
        }

        if (loading) loading.classList.add('hidden');
        if (content) content.classList.remove('hidden');

        mailboxStatsCache.lastLoad = new Date();

    } catch (error) {
        console.error('Error loading mailbox stats:', error);
        if (loading) {
            loading.innerHTML = `
                <div class="ui-empty">
                    <p class="ui-text-fail">Failed to load mailbox statistics</p>
                    <p>${escapeHtml(uiErrorText(error))}</p>
                    <button type="button" onclick="loadMailboxStats()" class="ui-btn ui-btn-sm">Try again</button>
                </div>
            `;
        }
    }
}

function mailboxStatsRefreshEvery() {
    return mailboxStatsView === 'rate-limits' ? 60000 : 5 * 60 * 1000;
}

function refreshMailboxStatsPage() {
    return mailboxStatsView === 'rate-limits' ? refreshRateLimits() : refreshMailboxStats();
}

async function refreshMailboxStats() {
    const content = document.getElementById('mailbox-stats-content');
    const list = document.getElementById('mailbox-stats-list');
    if (!content || !list) return;
    if (content.classList.contains('hidden') || !mailboxStatsCache.mailboxes) return loadMailboxStats();
    if (mailboxStatsLoading || uiTextHeld(list)) return;
    const seq = ++mailboxStatsSeq;
    mailboxStatsLoading = true;
    let drawn = false;
    try {
        const pages = Math.max(1, mailboxStatsPage);
        const quiet = { timeout: PAGE_REFRESH_TIMEOUT };
        const [summaryRes, domainsRes, ...pageRes] = await Promise.all([
            authenticatedFetch(mailboxStatsSummaryUrl(), quiet),
            authenticatedFetch('/api/mailbox-stats/domains', quiet),
            ...Array.from({ length: pages }, (_, i) => authenticatedFetch(mailboxStatsListUrl(i + 1), quiet))
        ]);
        if (!summaryRes.ok || !domainsRes.ok || pageRes.some(r => !r.ok)) return;
        const summary = await summaryRes.json();
        const domainsAnswer = await domainsRes.json();
        const answers = await Promise.all(pageRes.map(r => r.json()));
        if ([summary, domainsAnswer, ...answers].some(a => a.error)) return;
        const domains = domainsAnswer.domains || [];
        if (seq !== mailboxStatsSeq) return;
        const seen = new Set();
        const mailboxes = answers.flatMap(a => a.mailboxes || []).filter(m => !seen.has(m.username) && seen.add(m.username));
        const last = answers[answers.length - 1];
        renderMailboxStatsSummary(summary);
        const lastUpdateEl = document.getElementById('mailbox-stats-last-update');
        if (lastUpdateEl && summary.last_update) uiAgo(lastUpdateEl, summary.last_update, 'Updated ');
        if (JSON.stringify(domains) !== JSON.stringify(mailboxStatsCache.domains)) populateMailboxStatsDomainFilter(domains);
        mailboxStatsCache.summary = summary;
        mailboxStatsCache.domains = domains;
        const same = JSON.stringify(mailboxes) === JSON.stringify(mailboxStatsCache.mailboxes)
            && last.total_pages === mailboxStatsTotalPages && JSON.stringify(last.activity_buckets || []) === JSON.stringify(mailboxStatsCache.activityBuckets || []);
        if (same || uiTextHeld(list)) return;
        mailboxStatsCache.mailboxes = mailboxes;
        mailboxStatsTotalPages = last.total_pages || 1;
        mailboxStatsCache.activityUnit = last.activity_unit || 'day';
        mailboxStatsCache.activityBuckets = last.activity_buckets || [];
        const countEl = document.getElementById('mailbox-stats-count');
        if (countEl) countEl.textContent = uiCountLabel(last.total || 0, 'mailbox', 'mailboxes');
        uiKeepRowInView(list, '.ui-ms-row', 'data-ms-user', () => uiKeepFocus(list, 'data-ms-user', () =>
            renderMailboxStatsAccordion(mailboxes, pages, mailboxStatsTotalPages, last.total || 0)));
        drawn = true;
    } catch (error) {
        console.error('Mailbox statistics refresh failed:', error);
    } finally {
        if (seq === mailboxStatsSeq) {
            mailboxStatsLoading = false;
            if (!drawn) mailboxStatsWatchMore(mailboxStatsPage < mailboxStatsTotalPages);
        }
    }
}

function mailboxStatsSummaryUrl() {
    const dateRange = document.getElementById('mailbox-stats-date-range')?.value || '30days';
    const customStartDate = document.getElementById('mailbox-stats-start-date')?.value || '';
    const customEndDate = document.getElementById('mailbox-stats-end-date')?.value || '';
    let url = `/api/mailbox-stats/summary?date_range=${dateRange}`;
    if (dateRange === 'custom' && customStartDate && customEndDate) {
        url += `&start_date=${encodeURIComponent(customStartDate)}&end_date=${encodeURIComponent(customEndDate)}`;
    }
    return url;
}

function renderMailboxStatsSummary(summary) {
    const sentEl = document.getElementById('mailbox-stats-sent');
    const receivedEl = document.getElementById('mailbox-stats-received');
    const failedEl = document.getElementById('mailbox-stats-failed');
    const failureRateEl = document.getElementById('mailbox-stats-failure-rate');

    if (sentEl) sentEl.textContent = (summary.total_sent || 0).toLocaleString();
    if (receivedEl) receivedEl.textContent = (summary.total_received || 0).toLocaleString();
    if (failedEl) failedEl.textContent = (summary.sent_failed || 0).toLocaleString();
    if (failureRateEl) failureRateEl.textContent = `${summary.failure_rate || 0}%`;

    const dateRange = document.getElementById('mailbox-stats-date-range')?.value || '30days';
    let dateLabel;

    if (dateRange === 'custom') {
        const startDate = document.getElementById('mailbox-stats-start-date')?.value;
        const endDate = document.getElementById('mailbox-stats-end-date')?.value;
        if (startDate && endDate) {
            dateLabel = `${formatDayKey(startDate)} - ${formatDayKey(endDate)}`;
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
    const picked = select.value;

    select.innerHTML = '<option value="" data-short="All">All Domains</option>';

    domains.forEach(d => {
        const option = document.createElement('option');
        option.value = d.domain;
        option.textContent = d.alias_of
            ? `${d.domain} (alias of ${d.alias_of})`
            : `${d.domain} (${d.mailbox_count})`;
        select.appendChild(option);
    });
    if (picked && domains.some(d => d.domain === picked)) select.value = picked;
    uiFilterBarSync();
}

let mailboxStatsPage = 1;
let mailboxStatsTotalPages = 1;
let mailboxStatsLoading = false;
let mailboxStatsSeq = 0;
let mailboxStatsMoreObserver = null;

function mailboxStatsListUrl(page) {
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

    if (dateRange === 'custom' && customStartDate && customEndDate) {
        url += `&start_date=${encodeURIComponent(customStartDate)}&end_date=${encodeURIComponent(customEndDate)}`;
    }

    if (domainFilter) url += `&domain=${encodeURIComponent(domainFilter)}`;
    if (activeOnly) url += '&active_only=true';
    else url += '&active_only=false';
    if (hideZero) url += '&hide_zero=true';
    if (search) url += `&search=${encodeURIComponent(search)}`;
    return url;
}

async function loadMailboxStatsList(page = 1) {
    uiFilterBarSync();
    if (page > 1 && (mailboxStatsLoading || page > mailboxStatsTotalPages)) return;
    const seq = ++mailboxStatsSeq;
    mailboxStatsLoading = true;
    mailboxStatsPage = page;
    const url = mailboxStatsListUrl(page);

    try {
        const response = await authenticatedFetch(url);
        if (!response.ok) throw await responseError(response);

        const data = await response.json();
        if (data.error) throw new Error(data.error);
        if (seq !== mailboxStatsSeq) return;
        const loaded = data.mailboxes || [];
        if (page > 1) {
            const have = new Set(mailboxStatsCache.mailboxes.map(m => m.username));
            mailboxStatsCache.mailboxes = mailboxStatsCache.mailboxes.concat(loaded.filter(m => !have.has(m.username)));
        } else {
            mailboxStatsCache.mailboxes = loaded;
        }
        mailboxStatsTotalPages = data.total_pages || 1;
        mailboxStatsCache.activityUnit = data.activity_unit || 'day';
        mailboxStatsCache.activityBuckets = data.activity_buckets || [];

        const countEl = document.getElementById('mailbox-stats-count');
        if (countEl) countEl.textContent = uiCountLabel(data.total || 0, 'mailbox', 'mailboxes');

        renderMailboxStatsAccordion(mailboxStatsCache.mailboxes, data.page, data.total_pages, data.total || 0);

    } catch (error) {
        console.error('Error loading mailbox list:', error);
    } finally {
        if (seq === mailboxStatsSeq) mailboxStatsLoading = false;
    }
}

function mailboxStatsWatchMore(more) {
    if (mailboxStatsMoreObserver) mailboxStatsMoreObserver.disconnect();
    mailboxStatsMoreObserver = null;
    const sentinel = document.getElementById('mailbox-stats-more');
    if (!more || !sentinel || typeof IntersectionObserver === 'undefined') return;
    mailboxStatsMoreObserver = new IntersectionObserver(entries => {
        if (!entries.some(e => e.isIntersecting)) return;
        mailboxStatsMoreObserver.disconnect();
        loadMailboxStatsList(mailboxStatsPage + 1);
    }, { rootMargin: '0px 0px 400px 0px' });
    mailboxStatsMoreObserver.observe(sentinel);
}

function mailboxStatLink(email, filter, value, label, tone) {
    const args = `{ email: '${escapeJsArg(email)}', filterType: 'search', ${filter} }`;
    return `<button type="button" class="ui-kpi ui-kpi-btn" onclick="event.stopPropagation(); navigateToMessagesWithFilter(${args})" title="Open these messages">
        <b class="${!value ? 'ui-zero' : tone ? `ui-${tone}` : ''}">${(value || 0).toLocaleString()}</b>${label}</button>`;
}

function mailboxCountGroups(email, c) {
    return `<div class="ui-kpis ui-ms-counts">
        <div class="ui-ms-group"><h5 class="ui-ms-group-h">Traffic</h5>
            ${mailboxStatLink(email, "direction: 'outbound'", c.sent, 'Sent', 'dir-out')}
            ${mailboxStatLink(email, "direction: 'inbound'", c.received, 'Received', 'dir-in')}
            ${mailboxStatLink(email, "direction: 'internal'", c.internal, 'Internal', 'dir-int')}</div>
        <div class="ui-ms-group"><h5 class="ui-ms-group-h">Sent mail</h5>
            ${mailboxStatLink(email, "status: 'delivered'", c.delivered, 'Delivered', 'ok')}
            ${mailboxStatLink(email, "status: 'deferred'", c.deferred, 'Deferred', 'warn')}
            ${mailboxStatLink(email, "status: 'bounced'", c.bounced, 'Bounced', 'fail')}
            ${mailboxStatLink(email, "status: 'rejected'", c.rejected, 'Rejected', 'fail')}</div>
    </div>`;
}

function toggleMailboxAlias(row, address) {
    const open = !row.classList.contains('is-open');
    row.classList.toggle('is-open', open);
    row.querySelector('.ui-ms-alias-chev')?.setAttribute('aria-expanded', String(open));
    if (open) mailboxStatsCache.openAliases.add(address);
    else mailboxStatsCache.openAliases.delete(address);
}

function mailboxIsShared(mb) {
    return String((mb.attributes || {}).shared ?? '0').trim() === '1';
}

function mailboxStateTags(mb) {
    return (!mb.active ? uiTag('Inactive', 'fail')
        : mb.login_disabled ? '<span class="ui-tag ui-tag-warn" title="mailcow does not let it sign in. Mail is still delivered to it.">Login disabled</span>' : '')
        + (mailboxIsShared(mb) ? ' <span class="ui-tag ui-tag-info" title="A shared mailbox: people open it from their own mailbox, it has no login of its own">Shared</span>' : '');
}

function mailboxServices(mb) {
    const at = mb.attributes || {};
    const shared = mailboxIsShared(mb);
    const services = [
        ['IMAP', at.imap_access === '1', shared ? undefined : mb.last_imap_login],
        ['POP3', at.pop3_access === '1', shared ? undefined : mb.last_pop3_login],
        ['SMTP', at.smtp_access === '1', shared ? undefined : mb.last_smtp_login],
        ['Sieve', at.sieve_access === '1'],
        ['TLS', at.tls_enforce_in === '1' || at.tls_enforce_out === '1'],
    ];
    return `<span class="ui-ms-svcs">${services.map(([label, on, last]) => {
        const name = label === 'TLS' ? 'TLS enforced' : label;
        const tip = `${name}: ${on ? 'on' : 'off'}${last !== undefined ? `, last login ${last ? formatTime(last) : 'never'}` : ''}`;
        return `<span class="ui-ms-svc${on ? ' is-on' : ''}" title="${escapeHtml(tip)}"><i></i>${label}</span>`;
    }).join('')}</span>`;
}

function mailboxSparkline(mb) {
    const act = mb.activity || { sent: [], received: [] };
    const totals = act.sent.map((s, i) => s + (act.received[i] || 0));
    const sum = totals.reduce((a, b) => a + b, 0);
    const w = 96, h = 24, n = totals.length;
    const max = Math.max(1, ...totals);
    const pts = totals.map((v, i) => `${n > 1 ? (i / (n - 1) * w).toFixed(1) : w / 2},${(h - 2 - v / max * (h - 4)).toFixed(1)}`).join(' ');
    const label = `Activity of ${mb.username}: ${sum.toLocaleString()} messages. Open the chart`;
    return `<button type="button" class="ui-ms-spark${sum ? '' : ' is-empty'}" onclick="event.stopPropagation(); openMailboxActivity('${escapeJsArg(mb.username)}')" aria-label="${escapeHtml(label)}" title="${escapeHtml(label)}">
        <svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true">${n ? `<polygon points="0,${h} ${pts} ${w},${h}"></polygon><polyline points="${pts}"></polyline>` : ''}</svg></button>`;
}

function mailboxActivityLabel(bucket, unit) {
    if (unit !== 'hour') return formatDayKey(bucket, { year: false, weekday: 'short' });
    return `${formatDayMonth(bucket, { weekday: 'short' })}, ${formatClock(bucket)}`;
}

function openMailboxActivity(username) {
    const mb = (mailboxStatsCache.mailboxes || []).find(m => m.username === username);
    if (!mb) return;
    const unit = mailboxStatsCache.activityUnit || 'day';
    const buckets = mailboxStatsCache.activityBuckets || [];
    const act = mb.activity || { sent: [], received: [] };
    const totals = buckets.map((_, i) => (act.sent[i] || 0) + (act.received[i] || 0));
    const top = Math.ceil(Math.max(4, ...totals) / 4) * 4;
    let busiest = null;
    totals.forEach((v, i) => { if (v > 0 && (busiest === null || v > totals[busiest])) busiest = i; });
    const range = document.getElementById('date-range-label')?.textContent || '';
    document.getElementById('mailbox-activity-title').textContent = mb.username;
    document.getElementById('mailbox-activity-content').innerHTML = `
        <p class="ui-muted ui-aa-sub">${mb.name ? `${escapeHtml(mb.name)} · ` : ''}${escapeHtml(range)}, aliases included</p>
        <div class="ui-aa-strip">
            <div><small>Sent</small><b>${mb.combined_sent.toLocaleString()}</b></div>
            <div><small>Received</small><b>${mb.combined_received.toLocaleString()}</b></div>
            <div><small>Failed</small><b${mb.combined_failure_rate >= 10 ? ' class="ui-text-fail"' : ''}>${mb.combined_failure_rate}%</b></div>
            <div><small>Busiest ${unit}</small><b>${busiest === null ? '-' : escapeHtml(mailboxActivityLabel(buckets[busiest], unit))}</b></div>
        </div>
        <section>
            <div class="ui-aa-head"><b>Messages per ${unit}</b><span class="ui-muted">sent and received</span></div>
            ${buckets.length ? `<div class="ui-aa-chart">
                <div class="ui-aa-grid">${[top, top * .75, top * .5, top * .25, 0].map(v => `<i><span>${Math.round(v)}</span></i>`).join('')}</div>
                <div class="ui-aa-cols ui-ma-cols">${buckets.map((b, i) => {
                    const sent = act.sent[i] || 0, recv = act.received[i] || 0;
                    const tip = `${mailboxActivityLabel(b, unit)}: ${sent} sent, ${recv} received`;
                    return `<span class="ui-aa-col" title="${escapeHtml(tip)}"><i class="is-sent" style="height:${sent / top * 100}%"></i><i class="is-recv" style="height:${recv / top * 100}%"></i></span>`;
                }).join('')}</div>
            </div>
            <div class="ui-aa-x"><span>${escapeHtml(mailboxActivityLabel(buckets[0], unit))}</span><span>${escapeHtml(mailboxActivityLabel(buckets[buckets.length - 1], unit))}</span></div>
            <p class="ui-aa-legend"><span><i class="is-sent"></i>Sent</span><span><i class="is-recv"></i>Received</span></p>` : '<p class="ui-empty">No activity in this range.</p>'}
        </section>
        <div class="ui-aa-acts"><button type="button" class="ui-btn" onclick="closeMailboxActivity(); navigateToMessagesWithFilter({ email: '${escapeJsArg(mb.username)}', filterType: 'search' })">Open its messages</button></div>`;
    document.getElementById('mailbox-activity-modal').classList.remove('hidden');
}

function closeMailboxActivity() {
    document.getElementById('mailbox-activity-modal').classList.add('hidden');
}

let openMailboxSeq = 0;
async function openMailboxFor(address, { preset = '', startDay = '', endDay = '', onMoved = null } = {}) {
    const wanted = String(address || '').trim().toLowerCase();
    if (!wanted) return false;
    const seq = ++openMailboxSeq;
    if (preset) mailboxStatsShowPreset(preset);
    else if (startDay && endDay) {
        document.getElementById('mailbox-stats-date-range').value = 'custom';
        document.getElementById('mailbox-stats-start-date').value = startDay;
        document.getElementById('mailbox-stats-end-date').value = endDay;
        const label = document.getElementById('date-range-label');
        if (label) label.textContent = `${formatDayKey(startDay)} - ${formatDayKey(endDay)}`;
        updateDatePresetButtons('custom');
    }
    const search = document.getElementById('mailbox-stats-search');
    if (search) search.value = wanted;
    const domain = document.getElementById('mailbox-stats-domain-filter');
    if (domain) domain.value = '';
    const activeOnly = document.getElementById('mailbox-stats-active-only');
    if (activeOnly) activeOnly.checked = false;
    const hideZero = document.getElementById('mailbox-stats-hide-zero');
    if (hideZero) hideZero.checked = false;
    if (!(await navigateTo('mailbox-stats', { sub: 'statistics' }))) return false;
    if (typeof onMoved === 'function') onMoved();
    let data = null;
    const asked = mailboxStatsListUrl(1);
    try {
        const response = await authenticatedFetch(`${asked}&username=${encodeURIComponent(wanted)}`);
        if (response.ok) data = await response.json();
    } catch (e) {
        data = null;
    }
    const page = document.getElementById('content-mailbox-stats');
    if (seq !== openMailboxSeq || (typeof currentTab !== 'undefined' && currentTab !== 'mailbox-stats')
        || (page && page.classList.contains('hidden')) || mailboxStatsView !== 'statistics'
        || mailboxStatsListUrl(1) !== asked) return true;
    if (!data) {
        showToast('The mailbox could not be loaded. Try again in a moment.', 'error');
        return true;
    }
    const mailboxes = Array.isArray(data.mailboxes) ? data.mailboxes : [];
    const mb = mailboxes.find(m => String(m.username || '').toLowerCase() === wanted);
    if (!mb) {
        showToast('This mailbox is not in Mailbox Stats yet. Its statistics are fetched from mailcow every few minutes.', 'warning');
        return true;
    }
    const cached = mailboxStatsCache.mailboxes || [];
    const at = cached.findIndex(m => m.username === mb.username);
    mailboxStatsCache.mailboxes = at < 0 ? [...cached, mb] : cached.map((m, i) => (i === at ? mb : m));
    mailboxStatsCache.activityUnit = data.activity_unit || 'day';
    mailboxStatsCache.activityBuckets = data.activity_buckets || [];
    openMailboxActivity(mb.username);
    return true;
}

function mailboxRateLimitLabel(mb) {
    if (!mb.rl_value) return 'None';
    const frame = { s: 'sec', m: 'min', h: 'hour', d: 'day' }[mb.rl_frame] || mb.rl_frame || 'min';
    return `${mb.rl_value}/${frame}`;
}

function renderMailboxStatsAccordion(mailboxes, page = 1, totalPages = 1, total = 0) {
    const container = document.getElementById('mailbox-stats-list');
    if (!container) return;

    if (mailboxes.length === 0) {
        const bar = document.getElementById('mailbox-stats-search')?.closest('.ui-fbar');
        container.innerHTML = bar && uiFilterBarOn(bar) ? `
            <div class="ui-empty ui-panel">
                <p><b>No mailboxes match these filters</b></p>
                <p><button onclick="resetMailboxStatsFilters()" class="ui-btn ui-btn-sm">Clear filters</button></p>
            </div>` : '<p class="ui-empty ui-panel">Mailboxes with mail in this period show up here.</p>';
        mailboxStatsWatchMore(false);
        return;
    }

    const hideZero = document.getElementById('mailbox-stats-hide-zero')?.checked ?? true;
    const sum = (mb, key) => (mb.aliases || []).reduce((total, a) => total + (a[key] || 0), 0);
    const lastLogin = (label, last) => `<div class="ui-md-fact"><span>Last ${label} login</span><div>${last ? formatTime(last) : 'Never'}</div></div>`;

    let html = `
        <div class="ui-table ui-stack ui-ms-table" data-sort-handler="mailboxStatsSortBy" data-sort-at="mailbox-stats-search" data-sort-name="mailboxes" data-sort-default="Sent:desc">
            <div class="ui-tr ui-tr-head"><span data-sort-key="username" data-sort-kind="text"${mailboxStatsSortAttr('username')}>Mailbox</span><span>Activity</span><span class="ui-td-end" data-sort-key="sent_total" data-sort-kind="number"${mailboxStatsSortAttr('sent_total')}>Sent</span><span class="ui-td-end" data-sort-key="received_total" data-sort-kind="number"${mailboxStatsSortAttr('received_total')}>Received</span><span class="ui-td-end">Delivered</span><span class="ui-td-end" data-sort-key="failure_rate" data-sort-kind="number"${mailboxStatsSortAttr('failure_rate')}>Failed</span><span class="ui-td-end">Aliases</span><span class="ui-td-end" data-sort-key="quota_used" data-sort-kind="number"${mailboxStatsSortAttr('quota_used')}>Storage</span></div>
            ${mailboxes.map((mb, index) => {
        const isExpanded = mailboxStatsCache.expandedMailboxes.has(mb.username);
        const failTone = mb.combined_failure_rate >= 10 ? 'fail' : mb.combined_failure_rate >= 5 ? 'warn' : '';
        const aliases = (mb.aliases || []).filter(a => !hideZero || (a.sent_total || 0) + (a.received_total || 0) > 0);
        const email = mb.username;
        return `
            <div class="ui-tr ui-ms-row" data-ms-user="${escapeHtml(mb.username)}" onclick="if (!uiRowHeld(event)) toggleMailboxAccordion('${escapeJsArg(mb.username)}')">
                <div class="ui-td ui-q-who">
                    <div><button type="button" class="ui-row-chev" aria-expanded="${isExpanded}" aria-controls="accordion-content-${index}" aria-label="Details of ${escapeHtml(email)}" onclick="event.stopPropagation(); toggleMailboxAccordion('${escapeJsArg(mb.username)}')"><svg id="accordion-icon-${index}" class="ui-domain-chevron" width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"${isExpanded ? ' style="transform: rotate(90deg)"' : ''}><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg></button>${uiEntity('address', mb.username)} ${mailboxStateTags(mb)}</div>
                    ${mb.name ? `<small class="ui-ms-name">${escapeHtml(mb.name)}</small>` : ''}
                    <small class="ui-ms-sub">${escapeHtml(mb.quota_used_formatted)} · ${uiCountLabel(mb.alias_count || 0, 'alias', 'aliases')}</small>
                    ${mailboxServices(mb)}
                </div>
                <span class="ui-td ui-ms-spark-cell"><small class="ui-sec-unit">Activity </small>${mailboxSparkline(mb)}</span>
                <span class="ui-td ui-td-end"><small class="ui-sec-unit">Sent </small>${mb.combined_sent.toLocaleString()}</span>
                <span class="ui-td ui-td-end"><small class="ui-sec-unit">Received </small>${mb.combined_received.toLocaleString()}</span>
                <span class="ui-td ui-td-end"><small class="ui-sec-unit">Delivered </small>${(mb.combined_delivered || 0).toLocaleString()}</span>
                <span class="ui-td ui-td-end${failTone ? ` ui-text-${failTone}` : ''}"><small class="ui-sec-unit">Failed </small>${mb.combined_failure_rate}%</span>
                <span class="ui-td ui-td-end ui-ms-wide"><small class="ui-sec-unit">Aliases </small>${mb.alias_count || 0}</span>
                <span class="ui-td ui-td-end ui-ms-wide"><small class="ui-sec-unit">Storage </small>${mb.quota_used_formatted}</span>

                <div id="accordion-content-${index}" class="ui-domain-details${isExpanded ? '' : ' hidden'}" onclick="event.stopPropagation()">
                    <div class="ui-md-ids">
                        <div class="ui-md-fact ui-md-fact-inline"><span>Quota<span class="ui-ms-wide-only"> Used</span></span><div>${mb.quota_used_formatted} / ${mb.quota_formatted}</div><small class="ui-muted">${mb.percent_in_use || 0}%<span class="ui-ms-wide-only"> used</span></small><small class="ui-muted ui-ms-msgs">${(mb.messages_in_mailbox || 0).toLocaleString()} messages</small></div>
                        <div class="ui-md-fact ui-ms-msgs-fact"><span>Messages in Mailbox</span><div>${(mb.messages_in_mailbox || 0).toLocaleString()}</div></div>
                        <div class="ui-md-fact"><span>First seen / Last synced</span><div title="When this app first read the mailbox from mailcow">${mb.created ? formatTime(mb.created) : 'N/A'}</div><small class="ui-muted" title="When this app last read the mailbox from mailcow">${mb.modified ? formatTime(mb.modified) : 'N/A'}</small></div>
                        <div class="ui-md-fact"><span>Rate Limit</span><div>${escapeHtml(mailboxRateLimitLabel(mb))}</div></div>
                        ${mailboxIsShared(mb) ? '<div class="ui-md-fact"><span>Login</span><div>Shared mailbox, no login of its own</div></div>'
                            : lastLogin('IMAP', mb.last_imap_login) + lastLogin('POP3', mb.last_pop3_login) + lastLogin('SMTP', mb.last_smtp_login)
                                + (mb.last_sogo_login ? lastLogin('SOGo', mb.last_sogo_login) : '')}
                    </div>

                    <h4 class="ui-md-h">Message Statistics</h4>
                    ${mailboxCountGroups(email, {
                        sent: mb.combined_sent,
                        received: mb.combined_received,
                        internal: mb.combined_internal,
                        delivered: mb.combined_delivered,
                        deferred: (mb.mailbox_counts?.sent_deferred || 0) + sum(mb, 'sent_deferred'),
                        bounced: (mb.mailbox_counts?.sent_bounced || 0) + sum(mb, 'sent_bounced'),
                        rejected: (mb.mailbox_counts?.sent_rejected || 0) + sum(mb, 'sent_rejected'),
                    })}

                    ${mb.aliases && mb.aliases.length > 0 ? `
                        <h4 class="ui-md-h">Aliases (${mb.aliases.length})</h4>
                        <div class="ui-table ui-stack ui-ms-aliases" data-sort-icon="off">
                            <div class="ui-tr ui-tr-head"><span>Alias</span><span class="ui-td-end">Sent</span><span class="ui-td-end">Received</span><span class="ui-td-end">Internal</span><span class="ui-td-end">Delivered</span><span class="ui-td-end">Deferred</span><span class="ui-td-end">Bounced</span><span class="ui-td-end">Rejected</span><span class="ui-td-end">Fail %</span></div>
                            ${aliases.map(alias => {
            const go = (filter, value, label, tone) => `<button type="button" class="ui-td ui-td-end ui-link-cell ui-ms-count${!value ? ' is-zero ui-zero' : tone ? ` ui-text-${tone}` : ''}" onclick="event.stopPropagation(); navigateToMessagesWithFilter({ email: '${escapeJsArg(alias.alias_address)}', filterType: 'search', ${filter} })"><small class="ui-sec-unit">${label} </small>${value || 0}</button>`;
            const open = mailboxStatsCache.openAliases.has(alias.alias_address);
            return `
                            <div class="ui-tr ui-ms-alias${open ? ' is-open' : ''}" onclick="if (!uiRowHeld(event)) toggleMailboxAlias(this, '${escapeJsArg(alias.alias_address)}')">
                                <span class="ui-td ui-ms-alias-name"><button type="button" class="ui-ms-alias-chev" aria-expanded="${open}" aria-label="All counts of ${escapeHtml(alias.alias_address)}"><svg class="ui-domain-chevron" width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg></button>${uiEntity('address', alias.alias_address)}
                                    ${alias.is_catch_all ? uiTag('catch-all', 'warn') : ''}
                                    ${alias.is_domain_alias ? '<span class="ui-tag ui-tag-info" title="Address on a mailcow alias domain that points at this mailbox">domain alias</span>' : ''}
                                    ${!alias.active ? uiTag('inactive', '') : ''}</span>
                                ${go("direction: 'outbound'", alias.sent_total, 'Sent', 'dir-out')}
                                ${go("direction: 'inbound'", alias.received_total, 'Received', 'dir-in')}
                                ${go("direction: 'internal'", alias.direction_internal, 'Internal', 'dir-int')}
                                ${go("status: 'delivered'", alias.sent_delivered, 'Delivered', 'ok')}
                                ${go("status: 'deferred'", alias.sent_deferred, 'Deferred', 'warn')}
                                ${go("status: 'bounced'", alias.sent_bounced, 'Bounced', 'fail')}
                                ${go("status: 'rejected'", alias.sent_rejected, 'Rejected', 'fail')}
                                <span class="ui-td ui-td-end ui-ms-alias-fail${alias.failure_rate >= 5 ? ' ui-text-fail' : ' ui-muted'}"><small class="ui-sec-unit">Fail </small>${alias.failure_rate || 0}%</span>
                                <div class="ui-ms-alias-more" onclick="event.stopPropagation()">${mailboxCountGroups(alias.alias_address, {
                                    sent: alias.sent_total, received: alias.received_total, internal: alias.direction_internal,
                                    delivered: alias.sent_delivered, deferred: alias.sent_deferred, bounced: alias.sent_bounced, rejected: alias.sent_rejected,
                                })}</div>
                            </div>`;
        }).join('')}
                        </div>
                    ` : ''}
                </div>
            </div>`;
    }).join('')}
        </div>`;

    if (page < totalPages) html += '<p id="mailbox-stats-more" class="ui-msg-more" aria-live="polite">Loading more...</p>';
    else if (totalPages > 1) html += `<p class="ui-msg-more">All ${uiCountLabel(total || mailboxes.length, 'mailbox', 'mailboxes')} shown</p>`;

    container.innerHTML = html;
    mailboxStatsWatchMore(page < totalPages);
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
        icon?.closest('.ui-row-chev')?.setAttribute('aria-expanded', String(isHidden));
    }
}

function mailboxStatsPeriodOpened(now = new Date()) {
    const today = zonedDateString(now);
    const startInput = document.getElementById('date-range-start');
    const endInput = document.getElementById('date-range-end');
    if (startInput && !startInput.value) startInput.value = addDaysToDateString(today, -30);
    if (endInput && !endInput.value) endInput.value = today;
}

function closeDateRangePicker() {
    if (uiPickerIsOpen('mailbox-stats-period')) uiPickerClose('mailbox-stats-period', { returnFocus: true });
}

function selectDatePreset(preset) {
    mailboxStatsShowPreset(preset);
    closeDateRangePicker();
    loadMailboxStats();
}

function mailboxStatsShowPreset(preset) {
    const hiddenInput = document.getElementById('mailbox-stats-date-range');
    if (hiddenInput) hiddenInput.value = preset;

    document.getElementById('mailbox-stats-start-date').value = '';
    document.getElementById('mailbox-stats-end-date').value = '';

    const labelMap = {
        'today': 'Today',
        '7days': 'Last 7 Days',
        '30days': 'Last 30 Days',
        '90days': 'Last 90 Days'
    };
    const label = document.getElementById('date-range-label');
    if (label) label.textContent = labelMap[preset] || preset;

    updateDatePresetButtons(preset);
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

    const hiddenInput = document.getElementById('mailbox-stats-date-range');
    if (hiddenInput) hiddenInput.value = 'custom';

    document.getElementById('mailbox-stats-start-date').value = startInput.value;
    document.getElementById('mailbox-stats-end-date').value = endInput.value;

    const label = document.getElementById('date-range-label');
    if (label) {
        const startFormatted = formatDayKey(startInput.value);
        const endFormatted = formatDayKey(endInput.value);
        label.textContent = `${startFormatted} - ${endFormatted}`;
    }

    updateDatePresetButtons('custom');

    closeDateRangePicker();
    loadMailboxStats();
}

function applyMailboxStatsFilters() {
    loadMailboxStatsList(1);
}

function resetMailboxStatsFilters() {
    const searchEl = document.getElementById('mailbox-stats-search');
    if (searchEl) searchEl.value = '';

    const dateRangeEl = document.getElementById('mailbox-stats-date-range');
    if (dateRangeEl) dateRangeEl.value = '30days';

    const startDateEl = document.getElementById('mailbox-stats-start-date');
    if (startDateEl) startDateEl.value = '';
    const endDateEl = document.getElementById('mailbox-stats-end-date');
    if (endDateEl) endDateEl.value = '';

    const labelEl = document.getElementById('date-range-label');
    if (labelEl) labelEl.textContent = 'Last 30 Days';

    updateDatePresetButtons('30days');

    const startInput = document.getElementById('date-range-start');
    const endInput = document.getElementById('date-range-end');
    if (startInput) startInput.value = '';
    if (endInput) endInput.value = '';

    const domainEl = document.getElementById('mailbox-stats-domain-filter');
    if (domainEl) domainEl.value = '';

    const sortEl = document.getElementById('mailbox-stats-sort');
    if (sortEl) sortEl.value = 'sent_total-desc';

    const activeOnlyEl = document.getElementById('mailbox-stats-active-only');
    if (activeOnlyEl) activeOnlyEl.checked = true;

    const hideZeroEl = document.getElementById('mailbox-stats-hide-zero');
    if (hideZeroEl) hideZeroEl.checked = true;

    loadMailboxStats();
}

function mailboxStatsSortAttr(key) {
    const [by, order] = (document.getElementById('mailbox-stats-sort')?.value || 'sent_total-desc').split('-');
    return ` aria-sort="${by === key ? (order === 'asc' ? 'ascending' : 'descending') : 'none'}"`;
}

function mailboxStatsSortBy(key, order) {
    const field = document.getElementById('mailbox-stats-sort');
    if (!field) return;
    field.value = `${key}-${order}`;
    applyMailboxStatsFilters();
}
