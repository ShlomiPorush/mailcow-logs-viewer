// =============================================================================
// RATE LIMITS - who is hitting mailcow's sender rate limits, and the limits
// =============================================================================
// Classic script sharing the global scope; loaded after utils.js and app.js
// in index.html.
//
// This is a view of the Mailbox Stats page, not a page of its own. The view
// switcher lives in mailbox-stats.js. One scrolling page, three cards:
// activity over time, the blocked senders (master-detail), and the configured
// limits of every mailbox and domain in one table.
//
// Two things here are easy to confuse:
//   the LIMIT is configuration - so many messages per time frame
//   the COUNTER is what a blocked sender is stuck behind right now; releasing
//   it lets them send again without changing their limit

// Neutral badge following the APP_COLORS formula in utils.js: soft fill,
// subtle border, readable in both themes.
const RATE_LIMIT_NEUTRAL_BADGE =
    'bg-gray-100 dark:bg-gray-500/10 text-gray-700 dark:text-gray-300 border border-gray-200 dark:border-gray-500/20';

// Badge shape used across the app for status and direction chips
const RATE_LIMIT_BADGE_SHAPE = 'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium';

const RATE_LIMIT_FRAME_LABELS = {
    s: 'second',
    m: 'minute',
    h: 'hour',
    d: 'day'
};

// Chips of the configured limits table
const RATE_LIMIT_CHIP_SHAPE = 'px-2.5 py-1 text-xs font-medium rounded-full border transition-colors';
const RATE_LIMIT_CHIP_ACTIVE = 'bg-blue-500 border-blue-500 text-white';
const RATE_LIMIT_CHIP_INACTIVE =
    'border-blue-300 dark:border-blue-700 text-blue-700 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20';

let rateLimitWindowHours = 720;
let rateLimitSenderSearch = '';
let rateLimitConfigSearch = '';
// 'all' | 'mailbox' | 'domain'
let rateLimitConfigFilter = 'all';
let rateLimitEventsData = null;
let rateLimitConfigData = null;
// { kind: 'mailbox' | 'domain', name: string } while one row's form is open
let rateLimitEditing = null;
// Address of the sender whose detail panel is open, kept across reloads
let rateLimitSelectedSender = null;
let rateLimitChart = null;


async function loadRateLimits() {
    const loading = document.getElementById('rate-limits-loading');
    const content = document.getElementById('rate-limits-content');

    if (!loading || !content) {
        console.error('Rate Limits elements not found');
        return;
    }

    loading.classList.remove('hidden');
    content.classList.add('hidden');
    rateLimitEditing = null;
    destroyRateLimitChart();

    try {
        const [eventsResponse, limitsResponse] = await Promise.all([
            authenticatedFetch(`/api/rate-limits/events?hours=${rateLimitWindowHours}`),
            authenticatedFetch('/api/rate-limits/limits')
        ]);

        if (!eventsResponse.ok) {
            throw new Error(`HTTP ${eventsResponse.status}`);
        }
        if (!limitsResponse.ok) {
            throw new Error(`HTTP ${limitsResponse.status}`);
        }

        rateLimitEventsData = await eventsResponse.json();
        rateLimitConfigData = await limitsResponse.json();

        loading.classList.add('hidden');
        content.classList.remove('hidden');

        // The chart measures its container, so the content has to be visible
        // before anything is drawn into it
        renderRateLimitActivityCard();
        renderRateLimitSendersCard();
        renderRateLimitConfigCard();

    } catch (error) {
        console.error('Failed to load rate limits:', error);
        loading.innerHTML = `
            <div class="text-center py-12">
                <svg class="w-16 h-16 mx-auto text-red-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <p class="text-red-500">Failed to load rate limits</p>
                <p class="text-sm text-gray-500 dark:text-gray-400 mt-2">${escapeHtml(error.message)}</p>
            </div>
        `;
    }
}


function changeRateLimitWindow(value) {
    const hours = parseInt(value, 10);
    if (!Number.isFinite(hours)) return;
    rateLimitWindowHours = hours;
    loadRateLimits();
}


function renderRateLimitBadge(limit) {
    if (!limit || !limit.value) {
        return `<span class="${RATE_LIMIT_BADGE_SHAPE} ${RATE_LIMIT_NEUTRAL_BADGE} whitespace-nowrap">No limit</span>`;
    }
    const frame = limit.frame ? `/${escapeHtml(limit.frame)}` : '';
    return `<span class="${RATE_LIMIT_BADGE_SHAPE} ${getDirectionBadgeClass('outbound')} whitespace-nowrap">${escapeHtml(String(limit.value))}${frame}</span>`;
}


// Read-only notice above the configured limits - same banner Fail2ban
// Settings shows when the Read-Write key is missing
function renderRateLimitReadOnlyNotice() {
    const data = rateLimitConfigData || {};
    if (data.rw_key_configured !== false) return '';
    return `
        <div class="mx-4 my-3 px-4 py-3 rounded-lg bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 text-yellow-800 dark:text-yellow-300 text-sm flex items-center gap-2">
            <span class="text-lg">&#128274;</span>
            <span>Editing requires a <strong>Read-Write API key</strong> (<code>MAILCOW_API_KEY_RW</code>). Configure it in Settings &rarr; Mailcow &rarr; Connection.</span>
        </div>
    `;
}


// ---- Card 1: rate limit activity --------------------------------------------

function renderRateLimitActivityCard() {
    const container = document.getElementById('rate-limits-activity-card');
    if (!container) return;

    const data = rateLimitEventsData || {};
    const hits = data.total_events || 0;
    const senders = (data.by_sender || []).length;
    const subtitle = hits === 0
        ? 'No blocked sends in this window'
        : `${hits.toLocaleString()} blocked ${hits === 1 ? 'send' : 'sends'}`
            + ` from ${senders} ${senders === 1 ? 'sender' : 'senders'}`;

    const options = [
        { hours: 24, label: 'Last 24 hours' },
        { hours: 168, label: 'Last 7 days' },
        { hours: 720, label: 'Last 30 days' }
    ].map(option => `
        <option value="${option.hours}" ${option.hours === rateLimitWindowHours ? 'selected' : ''}>${option.label}</option>
    `).join('');

    const buckets = data.by_bucket || [];
    const hasHits = buckets.some(bucket => (bucket.count || 0) > 0);

    container.innerHTML = `
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow">
            <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex flex-wrap items-center justify-between gap-3">
                <div>
                    <h3 class="text-lg font-semibold text-gray-900 dark:text-white">Rate limit activity</h3>
                    <p class="text-sm text-gray-600 dark:text-gray-400">${escapeHtml(subtitle)}</p>
                </div>
                <select id="rate-limit-window" onchange="changeRateLimitWindow(this.value)"
                    class="px-3 py-2 text-sm rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300">
                    ${options}
                </select>
            </div>
            ${hasHits
            ? `
                <div class="p-4">
                    <div style="height: 180px;">
                        <canvas id="rate-limits-chart"></canvas>
                    </div>
                </div>
            `
            : `
                <div class="px-4 py-10 text-center">
                    <p class="text-gray-700 dark:text-gray-300 font-medium">Nobody hit a rate limit in this window</p>
                    <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">Widen the window to look further back.</p>
                </div>
            `}
        </div>
    `;

    if (hasHits) renderRateLimitChart(buckets, data.bucket === 'hour' ? 'hour' : 'day');
}


// The API buckets in UTC. An hour bucket is a moment, so it is localised like
// every other timestamp; a day bucket is a date, so it is labelled verbatim.
function rateLimitBucketLabel(bucket, granularity) {
    if (!bucket) return '';

    if (granularity === 'hour') {
        const date = new Date(`${bucket}:00Z`);
        const options = { hour: '2-digit', minute: '2-digit', hour12: false };
        try {
            if (typeof appTimezone !== 'undefined' && appTimezone && appTimezone !== 'UTC') {
                return new Intl.DateTimeFormat(undefined, { ...options, timeZone: appTimezone }).format(date);
            }
        } catch (e) {
            console.warn('Invalid timezone, using browser local timezone:', appTimezone, e);
        }
        return date.toLocaleTimeString(undefined, options);
    }

    const [year, month, day] = bucket.split('-').map(Number);
    return new Date(year, (month || 1) - 1, day || 1)
        .toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
}


function destroyRateLimitChart() {
    if (rateLimitChart) {
        rateLimitChart.destroy();
        rateLimitChart = null;
    }
}


function renderRateLimitChart(buckets, granularity) {
    const canvas = document.getElementById('rate-limits-chart');
    if (!canvas || typeof Chart === 'undefined') return;

    destroyRateLimitChart();

    const isDark = document.documentElement.classList.contains('dark');
    const gridColor = isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';
    const textColor = isDark ? '#d1d5db' : '#374151';

    rateLimitChart = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
            labels: buckets.map(bucket => rateLimitBucketLabel(bucket.bucket, granularity)),
            datasets: [{
                label: 'Blocked sends',
                data: buckets.map(bucket => bucket.count || 0),
                backgroundColor: isDark ? 'rgba(239,68,68,0.8)' : 'rgba(220,38,38,0.8)',
                borderRadius: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: textColor, maxRotation: 0, autoSkipPadding: 12 }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: gridColor },
                    ticks: { color: textColor, precision: 0 }
                }
            }
        }
    });
}


// ---- Card 2: the blocked senders --------------------------------------------

// Recency first: the sender stuck right now outranks last week's noise
function rateLimitSenders() {
    const data = rateLimitEventsData || {};
    return (data.by_sender || []).slice()
        .sort((a, b) => (b.last_seen || '').localeCompare(a.last_seen || ''));
}


function renderRateLimitSendersCard() {
    const container = document.getElementById('rate-limits-senders-card');
    if (!container) return;

    const senders = rateLimitSenders();
    // A sender that fell out of the window closes back to the table
    if (rateLimitSelectedSender && !senders.some(group => group.user === rateLimitSelectedSender)) {
        rateLimitSelectedSender = null;
    }
    const detailMode = !!rateLimitSelectedSender;

    const header = `
        <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex flex-wrap items-center justify-between gap-3">
            <div>
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white">Blocked senders</h3>
                <p class="text-sm text-gray-600 dark:text-gray-400">Mail that mailcow refused because the sender ran out of allowance</p>
            </div>
            ${senders.length === 0 || detailMode ? '' : `
                <input type="text" value="${escapeHtml(rateLimitSenderSearch)}" placeholder="Search..."
                    oninput="filterRateLimitSenders(this.value)"
                    class="w-56 px-3 py-2 text-sm rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300">
            `}
        </div>
    `;

    let body;
    if (senders.length === 0) {
        body = `
            <div class="px-4 py-10 text-center">
                <p class="text-gray-700 dark:text-gray-300 font-medium">Nobody hit a rate limit in this window</p>
                <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">Widen the window to look further back.</p>
            </div>
        `;
    } else if (detailMode) {
        body = renderRateLimitSenderDetail(senders.find(group => group.user === rateLimitSelectedSender));
    } else {
        body = renderRateLimitSendersTable(senders);
    }

    container.innerHTML = `<div class="bg-white dark:bg-gray-800 rounded-lg shadow">${header}${body}</div>`;

    if (!detailMode && senders.length && rateLimitSenderSearch) {
        filterRateLimitSenders(rateLimitSenderSearch);
    }
}


function renderRateLimitSendersTable(senders) {
    const canWrite = !rateLimitConfigData || rateLimitConfigData.rw_key_configured !== false;

    const rows = senders.map(group => {
        const resetButton = (canWrite && group.last_rl_hash)
            ? `
                <button type="button"
                    onclick="event.stopPropagation(); resetRateLimitCounter('${escapeJsArg(group.user)}', '${escapeJsArg(group.last_rl_hash)}')"
                    class="px-3 py-1.5 text-xs font-medium rounded-lg bg-blue-600 hover:bg-blue-700 text-white whitespace-nowrap">
                    Reset counter
                </button>
            `
            : '';
        return `
            <tr data-rl-sender="${escapeHtml((group.user || '').toLowerCase())}"
                class="hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer"
                onclick="selectRateLimitSender('${escapeJsArg(group.user)}')">
                <td class="px-3 sm:px-4 py-3 font-mono text-xs sm:text-sm text-gray-900 dark:text-gray-100 break-all">${escapeHtml(group.user)}</td>
                <td class="px-3 sm:px-4 py-3">
                    <span class="${RATE_LIMIT_BADGE_SHAPE} ${getStatusBadgeClass('rejected')} whitespace-nowrap">${group.events}</span>
                </td>
                <td class="px-3 sm:px-4 py-3 text-xs sm:text-sm text-gray-900 dark:text-gray-100 whitespace-nowrap">${escapeHtml(formatTime(group.last_seen))}</td>
                <td class="px-3 sm:px-4 py-3">${renderRateLimitBadge(group.current_limit)}</td>
                <td class="px-3 sm:px-4 py-3">
                    ${group.last_reset ? `<span class="${RATE_LIMIT_BADGE_SHAPE} ${getStatusBadgeClass('delivered')} whitespace-nowrap">Reset ${escapeHtml(formatTime(group.last_reset))}</span>` : ''}
                </td>
                <td class="px-3 sm:px-4 py-3 text-right whitespace-nowrap">${resetButton}</td>
            </tr>
        `;
    }).join('');

    return `
        <div class="mobile-scroll overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead class="bg-gray-50 dark:bg-gray-700">
                    <tr>
                        <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Sender</th>
                        <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Hits</th>
                        <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Last hit</th>
                        <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Limit</th>
                        <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Last reset</th>
                        <th class="px-3 sm:px-4 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider"></th>
                    </tr>
                </thead>
                <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                    ${rows}
                    <tr data-rl-sender-noresults class="hidden">
                        <td colspan="6" class="px-3 sm:px-4 py-8 text-center text-sm text-gray-500 dark:text-gray-400">No matches</td>
                    </tr>
                </tbody>
            </table>
        </div>
    `;
}


// Clicking a row swaps the whole card body for that sender's detail view
function selectRateLimitSender(user) {
    rateLimitSelectedSender = user;
    renderRateLimitSendersCard();
}


function backToRateLimitSenders() {
    rateLimitSelectedSender = null;
    renderRateLimitSendersCard();
}


// Rows are hidden in place, so the search box never loses focus while typing
function filterRateLimitSenders(query) {
    rateLimitSenderSearch = query || '';
    const card = document.getElementById('rate-limits-senders-card');
    if (!card) return;

    const q = rateLimitSenderSearch.trim().toLowerCase();
    let shown = 0;
    card.querySelectorAll('tbody tr[data-rl-sender]').forEach(tr => {
        const match = !q || (tr.dataset.rlSender || '').includes(q);
        tr.classList.toggle('hidden', !match);
        if (match) shown++;
    });

    const empty = card.querySelector('[data-rl-sender-noresults]');
    if (empty) empty.classList.toggle('hidden', shown !== 0);
}


function renderRateLimitSenderDetail(group) {
    if (!group) return '';

    const canWrite = !rateLimitConfigData || rateLimitConfigData.rw_key_configured !== false;
    const recent = group.recent || [];

    const resetButton = (canWrite && group.last_rl_hash)
        ? `
            <button type="button"
                onclick="resetRateLimitCounter('${escapeJsArg(group.user)}', '${escapeJsArg(group.last_rl_hash)}')"
                class="px-3 py-1.5 text-xs font-medium rounded-lg bg-blue-600 hover:bg-blue-700 text-white whitespace-nowrap">
                Reset counter
            </button>
        `
        : '';

    const resetBadge = group.last_reset
        ? `<span class="${RATE_LIMIT_BADGE_SHAPE} ${getStatusBadgeClass('delivered')} whitespace-nowrap">Reset ${escapeHtml(formatTime(group.last_reset))}</span>`
        : '';

    const events = recent.length === 0
        ? '<p class="px-4 py-6 text-sm text-gray-500 dark:text-gray-400">No details were recorded for these hits</p>'
        : `
            <div class="mobile-scroll overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                    <thead class="bg-gray-50 dark:bg-gray-700">
                        <tr>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Time</th>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Recipient</th>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Subject</th>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Queue id</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                        ${recent.map(renderRateLimitEventRow).join('')}
                    </tbody>
                </table>
            </div>
        `;

    return `
        <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex flex-wrap items-start justify-between gap-3">
            <div class="min-w-0">
                <button type="button" onclick="backToRateLimitSenders()"
                    class="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-medium rounded-lg border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 mb-3">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"></path>
                    </svg>
                    All senders
                </button>
                <p class="font-mono text-sm text-gray-900 dark:text-gray-100 break-all">${escapeHtml(group.user)}</p>
                <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">Last hit ${escapeHtml(formatTime(group.last_seen))}</p>
                <div class="flex flex-wrap items-center gap-2 mt-2">
                    ${renderRateLimitBadge(group.current_limit)}
                    ${resetBadge}
                </div>
            </div>
            ${resetButton}
        </div>
        ${events}
    `;
}


function renderRateLimitEventRow(event) {
    const subject = event.subject || '';
    const shortened = subject.length > 70 ? `${subject.slice(0, 70)}...` : subject;

    return `
        <tr class="border-t border-gray-200 dark:border-gray-700">
            <td class="px-4 py-2 text-sm text-gray-700 dark:text-gray-300 whitespace-nowrap">${escapeHtml(formatTime(event.time))}</td>
            <td class="px-4 py-2 font-mono text-sm text-gray-700 dark:text-gray-300 break-all">${escapeHtml(event.rcpt)}</td>
            <td class="px-4 py-2 text-sm text-gray-700 dark:text-gray-300">${shortened
                ? escapeHtml(shortened)
                : '<span class="text-gray-400">No subject</span>'}</td>
            <td class="px-4 py-2 font-mono text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap">${escapeHtml(event.qid)}</td>
        </tr>
    `;
}


async function resetRateLimitCounter(user, rlHash) {
    const confirmed = await showConfirmModal({
        title: 'Reset rate limit counter',
        message: `Let ${user} send again straight away? This clears the counter they are stuck behind. Their limit stays as it is.`,
        confirmText: 'Reset counter'
    });
    if (!confirmed) return;

    try {
        const response = await authenticatedFetch('/api/rate-limits/reset', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rl_hash: rlHash, user: user })
        });

        if (!response.ok) {
            const detail = await response.json().catch(() => ({}));
            showToast(detail.detail || 'Could not reset the counter', 'error');
            return;
        }

        showToast(`${user} can send again`, 'success');
        loadRateLimits();
    } catch (error) {
        console.error('Failed to reset rate limit counter:', error);
        showToast('Could not reset the counter', 'error');
    }
}


// ---- Card 3: the configured limits ------------------------------------------
// Mailboxes and domains share one table. A domain limit caps all of its
// mailboxes together, so seeing both side by side is the whole point.

function renderRateLimitConfigCard() {
    const container = document.getElementById('rate-limits-config-card');
    if (!container) return;

    const data = rateLimitConfigData || {};
    const canWrite = data.rw_key_configured !== false;

    // Domains first: the broader cap explains the mailboxes underneath it
    const rows = (data.domains || []).map(domain => renderRateLimitConfigRow(
        'domain', domain.domain, domain.rl_value, domain.rl_frame, canWrite))
        .concat((data.mailboxes || []).map(mailbox => renderRateLimitConfigRow(
            'mailbox', mailbox.username, mailbox.rl_value, mailbox.rl_frame, canWrite)))
        .join('');

    const chips = [
        { id: 'all', label: 'All' },
        { id: 'mailbox', label: 'Mailboxes' },
        { id: 'domain', label: 'Domains' }
    ].map(chip => `
        <button type="button" onclick="setRateLimitConfigFilter('${chip.id}')"
            data-rl-chip="${chip.id}"
            class="${RATE_LIMIT_CHIP_SHAPE} ${chip.id === rateLimitConfigFilter ? RATE_LIMIT_CHIP_ACTIVE : RATE_LIMIT_CHIP_INACTIVE}">
            ${chip.label}
        </button>
    `).join('');

    const domainsError = data.domains_error
        ? `
            <div class="px-4 py-2 text-sm text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-500/10 border-b border-amber-200 dark:border-amber-500/20">
                Domain limits could not be read from mailcow: ${escapeHtml(data.domains_error)}
            </div>
        `
        : '';

    const table = `
        <div class="mobile-scroll overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead class="bg-gray-50 dark:bg-gray-700">
                    <tr>
                        <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Type</th>
                        <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Name</th>
                        <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Limit</th>
                        <th class="px-3 sm:px-4 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider"></th>
                    </tr>
                </thead>
                <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                    ${rows}
                    <tr data-rl-noresults class="hidden">
                        <td colspan="4" class="px-3 sm:px-4 py-8 text-center text-sm text-gray-500 dark:text-gray-400">No matches</td>
                    </tr>
                </tbody>
            </table>
        </div>
    `;

    const empty = `
        <div class="px-4 py-10 text-center">
            <p class="text-gray-700 dark:text-gray-300 font-medium">Nothing is limited yet</p>
            <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">Mailboxes and domains send without a cap until you set one.</p>
        </div>
    `;

    container.innerHTML = `
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow">
            <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex flex-wrap items-center justify-between gap-3">
                <div>
                    <h3 class="text-lg font-semibold text-gray-900 dark:text-white">Configured limits</h3>
                    <p class="text-sm text-gray-600 dark:text-gray-400">How much each mailbox and domain is allowed to send</p>
                </div>
                <div class="flex flex-wrap items-center gap-2">
                    ${chips}
                    <input type="text" value="${escapeHtml(rateLimitConfigSearch)}" placeholder="Search..."
                        oninput="filterRateLimitConfigRows(this.value)"
                        class="w-56 px-3 py-2 text-sm rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300">
                </div>
            </div>
            ${renderRateLimitReadOnlyNotice()}
            ${domainsError}
            ${rows ? table : empty}
        </div>
    `;

    if (rows) applyRateLimitConfigFilters();
}


function setRateLimitConfigFilter(kind) {
    rateLimitConfigFilter = kind;
    const card = document.getElementById('rate-limits-config-card');
    if (!card) return;

    card.querySelectorAll('[data-rl-chip]').forEach(btn => {
        const isActive = btn.dataset.rlChip === kind;
        btn.className = `${RATE_LIMIT_CHIP_SHAPE} `
            + (isActive ? RATE_LIMIT_CHIP_ACTIVE : RATE_LIMIT_CHIP_INACTIVE);
    });
    applyRateLimitConfigFilters();
}


function filterRateLimitConfigRows(query) {
    rateLimitConfigSearch = query || '';
    applyRateLimitConfigFilters();
}


// Rows are hidden in place, so the search box never loses focus while typing
function applyRateLimitConfigFilters() {
    const card = document.getElementById('rate-limits-config-card');
    if (!card) return;

    const q = rateLimitConfigSearch.trim().toLowerCase();
    let shown = 0;
    card.querySelectorAll('tbody tr[data-rl-name]').forEach(tr => {
        const matchesName = !q || (tr.dataset.rlName || '').includes(q);
        const matchesKind = rateLimitConfigFilter === 'all' || tr.dataset.rlKind === rateLimitConfigFilter;
        const match = matchesName && matchesKind;
        tr.classList.toggle('hidden', !match);
        if (match && !tr.hasAttribute('data-rl-editrow')) shown++;
    });

    const empty = card.querySelector('[data-rl-noresults]');
    if (empty) empty.classList.toggle('hidden', shown !== 0);
}


function renderRateLimitConfigRow(kind, name, value, frame, canWrite) {
    const editing = rateLimitEditing
        && rateLimitEditing.kind === kind
        && rateLimitEditing.name === name;

    // Edit and Cancel share one recipe so the action column never changes
    // size, and text-sm keeps them exactly as tall as the edit form's fields
    const actionButton = 'px-3 py-1.5 text-sm font-medium rounded-lg border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700';
    const action = !canWrite
        ? ''
        : (editing
            ? `
                <button type="button" onclick="closeRateLimitEdit()" class="${actionButton}">
                    Cancel
                </button>
            `
            : `
                <button type="button" onclick="openRateLimitEdit('${kind}', '${escapeJsArg(name)}')" class="${actionButton}">
                    Edit
                </button>
            `);

    const row = `
        <tr data-rl-name="${escapeHtml(name.toLowerCase())}" data-rl-kind="${kind}" class="hover:bg-gray-50 dark:hover:bg-gray-700">
            <td class="px-3 sm:px-4 py-3">
                <span class="${RATE_LIMIT_BADGE_SHAPE} ${RATE_LIMIT_NEUTRAL_BADGE} whitespace-nowrap">${kind === 'domain' ? 'Domain' : 'Mailbox'}</span>
            </td>
            <td class="px-3 sm:px-4 py-3 text-xs sm:text-sm font-mono text-gray-900 dark:text-gray-100 break-all">${escapeHtml(name)}</td>
            <td class="px-3 sm:px-4 py-3">${renderRateLimitBadge(value ? { value: value, frame: frame } : null)}</td>
            <td class="px-3 sm:px-4 py-3 text-right whitespace-nowrap">${action}</td>
        </tr>
    `;

    return editing ? row + renderRateLimitEditForm(kind, name, value, frame) : row;
}


function renderRateLimitEditForm(kind, name, value, frame) {
    const selected = frame || 'h';
    const frames = Object.keys(RATE_LIMIT_FRAME_LABELS).map(key => `
        <option value="${key}" ${key === selected ? 'selected' : ''}>per ${RATE_LIMIT_FRAME_LABELS[key]}</option>
    `).join('');

    return `
        <tr data-rl-name="${escapeHtml(name.toLowerCase())}" data-rl-kind="${kind}" data-rl-editrow class="bg-gray-50 dark:bg-gray-900/30">
            <td colspan="4" class="px-3 sm:px-4 py-3">
                <div class="flex flex-wrap items-center gap-3">
                    <label for="rate-limit-value" class="text-sm text-gray-600 dark:text-gray-400">Allow</label>
                    <input id="rate-limit-value" type="number" min="0" step="1" value="${value ? escapeHtml(String(value)) : ''}"
                        placeholder="messages"
                        class="w-32 px-3 py-1.5 text-sm rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white">
                    <select id="rate-limit-frame"
                        class="px-3 py-1.5 text-sm rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white">
                        ${frames}
                    </select>
                    <button type="button" onclick="saveRateLimit('${kind}', '${escapeJsArg(name)}')"
                        class="px-3 py-1.5 text-sm font-medium rounded-lg border border-transparent bg-blue-600 hover:bg-blue-700 text-white">
                        Save
                    </button>
                    <button type="button" onclick="removeRateLimit('${kind}', '${escapeJsArg(name)}')"
                        class="px-3 py-1.5 text-sm font-medium rounded-lg border border-red-300 dark:border-red-500/40 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10">
                        Remove limit
                    </button>
                </div>
            </td>
        </tr>
    `;
}


function openRateLimitEdit(kind, name) {
    rateLimitEditing = { kind: kind, name: name };
    renderRateLimitConfigCard();
}


function closeRateLimitEdit() {
    rateLimitEditing = null;
    renderRateLimitConfigCard();
}


async function saveRateLimit(kind, name) {
    const valueInput = document.getElementById('rate-limit-value');
    const frameSelect = document.getElementById('rate-limit-frame');
    if (!valueInput || !frameSelect) return;

    const value = parseInt(valueInput.value, 10);
    if (!Number.isFinite(value) || value < 0) {
        showToast('Enter how many messages to allow, as a whole number', 'error');
        return;
    }

    await submitRateLimit(kind, name, value, frameSelect.value);
}


async function removeRateLimit(kind, name) {
    const confirmed = await showConfirmModal({
        title: 'Remove rate limit',
        message: `Remove the rate limit on ${name}? It will be able to send without a cap.`,
        confirmText: 'Remove limit',
        isDangerous: true
    });
    if (!confirmed) return;

    const frameSelect = document.getElementById('rate-limit-frame');
    await submitRateLimit(kind, name, 0, frameSelect ? frameSelect.value : 'h');
}


async function submitRateLimit(kind, name, value, frame) {
    const url = kind === 'mailbox' ? '/api/rate-limits/mailbox' : '/api/rate-limits/domain';
    const payload = kind === 'mailbox'
        ? { mailbox: name, value: value, frame: frame }
        : { domain: name, value: value, frame: frame };

    try {
        const response = await authenticatedFetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const detail = await response.json().catch(() => ({}));
            showToast(detail.detail || 'Could not save the rate limit', 'error');
            return;
        }

        const frameLabel = RATE_LIMIT_FRAME_LABELS[frame] || frame;
        showToast(value === 0
            ? `${name} now sends without a limit`
            : `${name} is limited to ${value} per ${frameLabel}`, 'success');

        rateLimitEditing = null;
        loadRateLimits();
    } catch (error) {
        console.error('Failed to save rate limit:', error);
        showToast('Could not save the rate limit', 'error');
    }
}
