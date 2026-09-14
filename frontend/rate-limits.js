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

let rateLimitWindowHours = 168;
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

function renderRateLimitHits() {
    const container = document.getElementById('rate-limits-tab-hits');
    if (!container) return;

    const data = rateLimitEventsData || {};
    const senders = data.by_sender || [];
    const canWrite = !rateLimitConfigData || rateLimitConfigData.rw_key_configured !== false;

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
            <div class="divide-y divide-gray-200 dark:divide-gray-700">
                ${senders.map((group, index) => renderRateLimitSenderRow(group, index, canWrite)).join('')}
            </div>
        `;

    container.innerHTML = `
        <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex flex-wrap items-center justify-between gap-3">
            <div class="flex flex-wrap items-center gap-2">
                <p class="text-sm text-gray-600 dark:text-gray-400">Mail that mailcow refused because the sender ran out of allowance</p>
                <span class="${RATE_LIMIT_BADGE_SHAPE} ${RATE_LIMIT_NEUTRAL_BADGE} whitespace-nowrap">
                    ${data.total_events || 0} hits from ${senders.length} sender${senders.length === 1 ? '' : 's'}
                </span>
            </div>
            <select id="rate-limit-window" onchange="changeRateLimitWindow(this.value)"
                class="px-3 py-2 text-sm rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300">
                ${options}
            </select>
        </div>
        ${body}
    `;
}


function renderRateLimitSenderRow(group, index, canWrite) {
    const rowId = `rate-limit-sender-${index}`;
    const recent = group.recent || [];

    const resetButton = (canWrite && group.last_rl_hash)
        ? `
            <button type="button"
                onclick="event.stopPropagation(); resetRateLimitCounter('${escapeJsArg(group.user)}', '${escapeJsArg(group.last_rl_hash)}')"
                class="px-2.5 py-1.5 text-xs font-medium rounded bg-blue-600 hover:bg-blue-700 text-white whitespace-nowrap">
                Reset counter
            </button>
        `
        : '';

    const details = recent.length === 0
        ? '<p class="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">No details were recorded for these hits</p>'
        : `
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead>
                        <tr class="text-left text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">
                            <th class="px-4 py-2">Time</th>
                            <th class="px-4 py-2">Recipient</th>
                            <th class="px-4 py-2">Subject</th>
                            <th class="px-4 py-2">Queue id</th>
                        </tr>
                    </thead>
                    <tbody>${recent.map(renderRateLimitEventRow).join('')}</tbody>
                </table>
            </div>
        `;

    return `
        <div>
            <div class="px-4 py-3 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/30 transition"
                onclick="toggleRateLimitSender('${rowId}')">
                <div class="flex flex-wrap items-center gap-3">
                    <svg id="${rowId}-icon" class="w-4 h-4 text-gray-400 transition-transform flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                    </svg>
                    <div class="min-w-0 flex-1">
                        <p class="font-mono text-sm text-gray-900 dark:text-white truncate">${escapeHtml(group.user)}</p>
                        <p class="text-xs text-gray-500 dark:text-gray-400 mt-0.5">Last hit ${escapeHtml(formatTime(group.last_seen))}</p>
                    </div>
                    <span class="${RATE_LIMIT_BADGE_SHAPE} ${getStatusBadgeClass('rejected')} whitespace-nowrap">
                        ${group.events} hit${group.events === 1 ? '' : 's'}
                    </span>
                    ${renderRateLimitBadge(group.current_limit)}
                    ${group.last_reset ? `<span class="${RATE_LIMIT_BADGE_SHAPE} ${getStatusBadgeClass('delivered')} whitespace-nowrap">Counter reset ${escapeHtml(formatTime(group.last_reset))}</span>` : ''}
                    ${resetButton}
                </div>
            </div>
            <div id="${rowId}" class="hidden bg-gray-50 dark:bg-gray-900/30 border-t border-gray-200 dark:border-gray-700">
                ${details}
            </div>
        </div>
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
        <div class="overflow-x-auto">
            <table class="w-full">
                <thead>
                    <tr class="text-left text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">
                        <th class="px-4 py-2">Name</th>
                        <th class="px-4 py-2">Limit</th>
                        <th class="px-4 py-2"></th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    `;
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
        <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
            <p class="text-sm text-gray-600 dark:text-gray-400">How much each mailbox is allowed to send</p>
        </div>
        ${renderRateLimitReadOnlyNotice()}
        ${rows ? renderRateLimitLimitsTable(rows) : renderRateLimitEmptyBody('Mailboxes send without a cap until you set one.')}
    `;
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
        <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
            <p class="text-sm text-gray-600 dark:text-gray-400">A domain limit caps all of its mailboxes together</p>
        </div>
        ${renderRateLimitReadOnlyNotice()}
        ${domainsError}
        ${rows ? renderRateLimitLimitsTable(rows) : renderRateLimitEmptyBody('Domains send without a cap until you set one.')}
    `;
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

    const action = !canWrite
        ? ''
        : (editing
            ? `
                <button type="button" onclick="closeRateLimitEdit()"
                    class="px-2 py-1 text-xs font-medium rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700">
                    Cancel
                </button>
            `
            : `
                <button type="button" onclick="openRateLimitEdit('${kind}', '${escapeJsArg(name)}')"
                    class="px-2 py-1 text-xs font-medium rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700">
                    Edit
                </button>
            `);

    const row = `
        <tr class="border-t border-gray-200 dark:border-gray-700">
            <td class="px-4 py-2.5 font-mono text-sm text-gray-900 dark:text-white break-all">${escapeHtml(name)}</td>
            <td class="px-4 py-2.5">${renderRateLimitBadge(value ? { value: value, frame: frame } : null)}</td>
            <td class="px-4 py-2.5 text-right whitespace-nowrap">${action}</td>
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
        <tr class="bg-gray-50 dark:bg-gray-900/30 border-t border-gray-200 dark:border-gray-700">
            <td colspan="3" class="px-4 py-3">
                <div class="flex flex-wrap items-center gap-3">
                    <label for="rate-limit-value" class="text-sm text-gray-600 dark:text-gray-400">Allow</label>
                    <input id="rate-limit-value" type="number" min="0" step="1" value="${value ? escapeHtml(String(value)) : ''}"
                        placeholder="messages"
                        class="w-32 px-3 py-1.5 text-sm rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white">
                    <select id="rate-limit-frame"
                        class="px-3 py-1.5 text-sm rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white">
                        ${frames}
                    </select>
                    <button type="button" onclick="saveRateLimit('${kind}', '${escapeJsArg(name)}')"
                        class="px-3 py-1.5 text-xs font-medium rounded bg-blue-600 hover:bg-blue-700 text-white">
                        Save
                    </button>
                    <button type="button" onclick="removeRateLimit('${kind}', '${escapeJsArg(name)}')"
                        class="px-3 py-1.5 text-xs font-medium rounded border border-red-300 dark:border-red-500/40 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10">
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
