// =============================================================================
// RATE LIMITS - who is hitting mailcow's sender rate limits, and the limits
// =============================================================================
// Classic script sharing the global scope; loaded after utils.js and app.js
// in index.html.
//
// This is a view of the Mailbox Stats page, not a page of its own. The view
// switcher lives in mailbox-stats.js; the tabs below follow the DMARC sub-tab
// recipe (index.html) and the Spam Filter switching logic.
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

let rateLimitWindowHours = 720;
let rateLimitSearch = { hits: '', mailbox: '', domain: '' };
let rateLimitEventsData = null;
let rateLimitConfigData = null;
// { kind: 'mailbox' | 'domain', name: string } while one row's form is open
let rateLimitEditing = null;
let rateLimitsTab = 'hits';


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

        updateRateLimitSummary();
        renderRateLimitHits();
        renderRateLimitMailboxes();
        renderRateLimitDomains();
        // Keep whichever tab was open across reloads
        rateLimitsSwitchTab(rateLimitsTab);

        loading.classList.add('hidden');
        content.classList.remove('hidden');

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


// The panels are rendered together, so switching only swaps what is visible
function rateLimitsSwitchTab(tab) {
    rateLimitsTab = tab;

    document.querySelectorAll('[id^="rate-limits-subtab-"]').forEach(btn => {
        btn.classList.remove('active');
    });
    const activeBtn = document.getElementById(`rate-limits-subtab-${tab}`);
    if (activeBtn) activeBtn.classList.add('active');

    ['hits', 'mailboxes', 'domains'].forEach(name => {
        const panel = document.getElementById(`rate-limits-tab-${name}`);
        if (panel) panel.classList.toggle('hidden', name !== tab);
    });
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


// Read-only notice shared by both limits tabs - same banner Fail2ban
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


// ---- Recent rate limit hits -------------------------------------------------

function updateRateLimitSummary() {
    const events = rateLimitEventsData || {};
    const config = rateLimitConfigData || {};
    const senders = events.by_sender || [];
    const windowLabel = rateLimitWindowHours === 24 ? 'Last 24 hours'
        : rateLimitWindowHours === 168 ? 'Last 7 days' : 'Last 30 days';
    const set = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    };
    set('rate-limits-sum-senders', senders.length);
    set('rate-limits-sum-senders-label', windowLabel);
    set('rate-limits-sum-hits', (events.total_events || 0).toLocaleString());
    set('rate-limits-sum-hits-label', windowLabel);
    set('rate-limits-sum-resets', senders.filter(s => s.last_reset).length);
    set('rate-limits-sum-limits',
        (config.mailboxes || []).length + (config.domains || []).filter(d => d.rl_value).length);
}


function renderRateLimitHits() {
    const container = document.getElementById('rate-limits-tab-hits');
    if (!container) return;

    const data = rateLimitEventsData || {};
    const canWrite = !rateLimitConfigData || rateLimitConfigData.rw_key_configured !== false;
    // Recency first: the sender stuck right now outranks last week's noise
    const senders = (data.by_sender || []).slice()
        .sort((a, b) => (b.last_seen || '').localeCompare(a.last_seen || ''));

    const options = [
        { hours: 24, label: 'Last 24 hours' },
        { hours: 168, label: 'Last 7 days' },
        { hours: 720, label: 'Last 30 days' }
    ].map(option => `
        <option value="${option.hours}" ${option.hours === rateLimitWindowHours ? 'selected' : ''}>${option.label}</option>
    `).join('');

    const body = senders.length === 0
        ? `
            <div class="px-4 py-10 text-center">
                <p class="text-gray-700 dark:text-gray-300 font-medium">Nobody hit a rate limit in this window</p>
                <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">Widen the window to look further back.</p>
            </div>
        `
        : `
            <div class="mobile-scroll overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                    <thead class="bg-gray-50 dark:bg-gray-700">
                        <tr>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Sender</th>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Hits</th>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Last hit</th>
                            <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Limit</th>
                            <th class="px-3 sm:px-4 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider"></th>
                        </tr>
                    </thead>
                    <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                        ${senders.map((group, index) => renderRateLimitSenderRow(group, index, canWrite)).join('')}
                        <tr data-rl-noresults class="hidden">
                            <td colspan="5" class="px-3 sm:px-4 py-8 text-center text-sm text-gray-500 dark:text-gray-400">No matches</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        `;

    container.innerHTML = `
        <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex flex-wrap items-center justify-between gap-3">
            <p class="text-sm text-gray-600 dark:text-gray-400">Mail that mailcow refused because the sender ran out of allowance</p>
            <div class="flex items-center gap-2">
                <input type="text" value="${escapeHtml(rateLimitSearch.hits || '')}" placeholder="Search..."
                    oninput="filterRateLimitRows('hits', this.value)"
                    class="w-44 px-3 py-2 text-sm rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300">
                <select id="rate-limit-window" onchange="changeRateLimitWindow(this.value)"
                    class="px-3 py-2 text-sm rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300">
                    ${options}
                </select>
            </div>
        </div>
        ${body}
    `;
    if (rateLimitSearch.hits) filterRateLimitRows('hits', rateLimitSearch.hits);
}


function renderRateLimitSenderRow(group, index, canWrite) {
    const rowId = `rate-limit-sender-${index}`;
    const recent = group.recent || [];

    const resetButton = (canWrite && group.last_rl_hash)
        ? `
            <button type="button"
                onclick="event.stopPropagation(); resetRateLimitCounter('${escapeJsArg(group.user)}', '${escapeJsArg(group.last_rl_hash)}')"
                class="px-3 py-1.5 text-xs font-medium rounded-lg bg-blue-600 hover:bg-blue-700 text-white whitespace-nowrap">
                Reset counter
            </button>
        `
        : '';

    const details = recent.length === 0
        ? '<p class="px-3 sm:px-4 py-3 text-sm text-gray-500 dark:text-gray-400">No details were recorded for these hits</p>'
        : `
            <div class="overflow-x-auto">
                <table class="min-w-full">
                    <thead>
                        <tr class="text-left text-xs uppercase tracking-wider text-gray-500 dark:text-gray-400">
                            <th class="px-3 sm:px-4 py-2">Time</th>
                            <th class="px-3 sm:px-4 py-2">Recipient</th>
                            <th class="px-3 sm:px-4 py-2">Subject</th>
                            <th class="px-3 sm:px-4 py-2">Queue id</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200 dark:divide-gray-700">${recent.map(renderRateLimitEventRow).join('')}</tbody>
                </table>
            </div>
        `;

    return `
        <tr data-rl-name="${escapeHtml((group.user || '').toLowerCase())}"
            class="hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer" onclick="toggleRateLimitSender('${rowId}')">
            <td class="px-3 sm:px-4 py-3">
                <div class="flex items-center gap-2 min-w-0">
                    <svg id="${rowId}-icon" class="w-4 h-4 text-gray-400 transition-transform flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                    </svg>
                    <span class="font-mono text-xs sm:text-sm text-gray-900 dark:text-gray-100 truncate">${escapeHtml(group.user)}</span>
                </div>
            </td>
            <td class="px-3 sm:px-4 py-3">
                <span class="${RATE_LIMIT_BADGE_SHAPE} ${getStatusBadgeClass('rejected')} whitespace-nowrap">${group.events}</span>
            </td>
            <td class="px-3 sm:px-4 py-3 text-xs sm:text-sm text-gray-900 dark:text-gray-100 whitespace-nowrap">${escapeHtml(formatTime(group.last_seen))}</td>
            <td class="px-3 sm:px-4 py-3">${renderRateLimitBadge(group.current_limit)}</td>
            <td class="px-3 sm:px-4 py-3 text-right whitespace-nowrap">
                ${group.last_reset ? `<span class="${RATE_LIMIT_BADGE_SHAPE} ${getStatusBadgeClass('delivered')} whitespace-nowrap mr-2">Reset ${escapeHtml(formatTime(group.last_reset))}</span>` : ''}
                ${resetButton}
            </td>
        </tr>
        <tr id="${rowId}" data-rl-name="${escapeHtml((group.user || '').toLowerCase())}" data-rl-detail class="hidden">
            <td colspan="5" class="p-0 bg-gray-50 dark:bg-gray-900/30">
                ${details}
            </td>
        </tr>
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


function toggleRateLimitSender(rowId) {
    const details = document.getElementById(rowId);
    const icon = document.getElementById(`${rowId}-icon`);
    if (!details) return;

    const opened = !details.classList.toggle('hidden');
    if (icon) {
        icon.classList.toggle('rotate-90', opened);
    }
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


// ---- Configured limits ------------------------------------------------------

function renderRateLimitLimitsTable(rows) {
    return `
        <div class="mobile-scroll overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead class="bg-gray-50 dark:bg-gray-700">
                    <tr>
                        <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Name</th>
                        <th class="px-3 sm:px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Limit</th>
                        <th class="px-3 sm:px-4 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider"></th>
                    </tr>
                </thead>
                <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                    ${rows}
                    <tr data-rl-noresults class="hidden">
                        <td colspan="3" class="px-3 sm:px-4 py-8 text-center text-sm text-gray-500 dark:text-gray-400">No matches</td>
                    </tr>
                </tbody>
            </table>
        </div>
    `;
}


// One search box per limits tab. Filtering hides rows in place so the input
// never loses focus while typing.
function renderRateLimitSearch(kind, subtitle) {
    return `
        <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex flex-wrap items-center justify-between gap-3">
            <p class="text-sm text-gray-600 dark:text-gray-400">${subtitle}</p>
            <input type="text" value="${escapeHtml(rateLimitSearch[kind] || '')}" placeholder="Search..."
                oninput="filterRateLimitRows('${kind}', this.value)"
                class="w-56 px-3 py-2 text-sm rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300">
        </div>
    `;
}


function filterRateLimitRows(kind, query) {
    rateLimitSearch[kind] = query;
    const containerId = kind === 'mailbox' ? 'rate-limits-tab-mailboxes'
        : kind === 'domain' ? 'rate-limits-tab-domains' : 'rate-limits-tab-hits';
    const container = document.getElementById(containerId);
    if (!container) return;
    const q = (query || '').trim().toLowerCase();
    let shown = 0;
    container.querySelectorAll('tbody tr[data-rl-name]').forEach(tr => {
        const match = !q || tr.dataset.rlName.includes(q);
        if (tr.hasAttribute('data-rl-detail')) {
            // Expanded event details collapse when the filter changes, so the
            // chevron state can never disagree with what is visible
            tr.classList.add('hidden');
            const icon = document.getElementById(`${tr.id}-icon`);
            if (icon) icon.classList.remove('rotate-90');
            return;
        }
        tr.classList.toggle('hidden', !match);
        if (match && !tr.hasAttribute('data-rl-editrow')) shown++;
    });
    const empty = container.querySelector('[data-rl-noresults]');
    if (empty) empty.classList.toggle('hidden', shown !== 0);
}


function renderRateLimitEmptyBody(text) {
    return `
        <div class="px-4 py-10 text-center">
            <p class="text-gray-700 dark:text-gray-300 font-medium">Nothing is limited yet</p>
            <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">${text}</p>
        </div>
    `;
}


function renderRateLimitMailboxes() {
    const container = document.getElementById('rate-limits-tab-mailboxes');
    if (!container) return;

    const data = rateLimitConfigData || {};
    const mailboxes = data.mailboxes || [];
    const canWrite = data.rw_key_configured !== false;

    const rows = mailboxes.map(mailbox => renderRateLimitConfigRow(
        'mailbox', mailbox.username, mailbox.rl_value, mailbox.rl_frame, canWrite)).join('');

    container.innerHTML = `
        ${renderRateLimitSearch('mailbox', 'How much each mailbox is allowed to send')}
        ${renderRateLimitReadOnlyNotice()}
        ${rows ? renderRateLimitLimitsTable(rows) : renderRateLimitEmptyBody('Mailboxes send without a cap until you set one.')}
    `;
    if (rateLimitSearch.mailbox) filterRateLimitRows('mailbox', rateLimitSearch.mailbox);
}


function renderRateLimitDomains() {
    const container = document.getElementById('rate-limits-tab-domains');
    if (!container) return;

    const data = rateLimitConfigData || {};
    const domains = data.domains || [];
    const canWrite = data.rw_key_configured !== false;

    const domainsError = data.domains_error
        ? `
            <div class="px-4 py-2 text-sm text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-500/10 border-b border-amber-200 dark:border-amber-500/20">
                Domain limits could not be read from mailcow: ${escapeHtml(data.domains_error)}
            </div>
        `
        : '';

    const rows = domains.map(domain => renderRateLimitConfigRow(
        'domain', domain.domain, domain.rl_value, domain.rl_frame, canWrite)).join('');

    container.innerHTML = `
        ${renderRateLimitSearch('domain', 'A domain limit caps all of its mailboxes together')}
        ${renderRateLimitReadOnlyNotice()}
        ${domainsError}
        ${rows ? renderRateLimitLimitsTable(rows) : renderRateLimitEmptyBody('Domains send without a cap until you set one.')}
    `;
    if (rateLimitSearch.domain) filterRateLimitRows('domain', rateLimitSearch.domain);
}


// Re-render only the tab that owns the row being edited
function renderRateLimitConfigured() {
    renderRateLimitMailboxes();
    renderRateLimitDomains();
}


function renderRateLimitConfigRow(kind, name, value, frame, canWrite) {
    const editing = rateLimitEditing
        && rateLimitEditing.kind === kind
        && rateLimitEditing.name === name;

    // Edit and Cancel share one recipe so the action column never changes size
    const actionButton = 'px-3 py-1.5 text-xs font-medium rounded-lg border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700';
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
        <tr data-rl-name="${escapeHtml(name.toLowerCase())}" class="hover:bg-gray-50 dark:hover:bg-gray-700">
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
        <tr data-rl-name="${escapeHtml(name.toLowerCase())}" data-rl-editrow class="bg-gray-50 dark:bg-gray-900/30">
            <td colspan="3" class="px-3 sm:px-4 py-3">
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
                        class="px-3 py-1.5 text-xs font-medium rounded-lg bg-blue-600 hover:bg-blue-700 text-white">
                        Save
                    </button>
                    <button type="button" onclick="removeRateLimit('${kind}', '${escapeJsArg(name)}')"
                        class="px-3 py-1.5 text-xs font-medium rounded-lg border border-red-300 dark:border-red-500/40 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10">
                        Remove limit
                    </button>
                </div>
            </td>
        </tr>
    `;
}


function openRateLimitEdit(kind, name) {
    rateLimitEditing = { kind: kind, name: name };
    renderRateLimitConfigured();
}


function closeRateLimitEdit() {
    rateLimitEditing = null;
    renderRateLimitConfigured();
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
