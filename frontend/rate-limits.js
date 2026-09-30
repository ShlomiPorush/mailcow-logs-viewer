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


const RATE_LIMIT_FRAME_LABELS = {
    s: 'second',
    m: 'minute',
    h: 'hour',
    d: 'day'
};


// Edit, Cancel and Apply to filtered share one size so the action column
// never changes width
const RATE_LIMIT_ACTION_BUTTON = 'ui-btn ui-btn-sm';
// The one thing a form on this page actually does
const RATE_LIMIT_SAVE_BUTTON = 'ui-btn ui-btn-sm ui-btn-primary';

let rateLimitWindowHours = 720;
let rateLimitSenderSearch = '';
let rateLimitConfigSearch = '';
// 'all' | 'mailbox' | 'domain'
let rateLimitConfigFilter = 'all';
let rateLimitEventsData = null;
let rateLimitConfigData = null;
// { kind: 'mailbox' | 'domain', name: string } while one row's form is open
let rateLimitEditing = null;
// The "Apply to filtered" panel: whether it is open and what was typed into
// it, kept here so re-rendering the card never loses either
let rateLimitBulkOpen = false;
let rateLimitBulkValue = '';
let rateLimitBulkFrame = 'h';
// Address of the sender whose detail panel is open, kept across reloads
let rateLimitSelectedSender = null;
// One sender's full collected history, keyed by address:
// { events: [...], total: n } once it is read, { failed: true } if the read
// failed. Kept so stepping in and out of a sender does not fetch it again.
let rateLimitSenderEvents = {};
// The address whose history is in flight right now, so re-rendering the open
// detail does not fire the same request twice
let rateLimitSenderEventsInFlight = null;
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
    rateLimitBulkOpen = false;
    // Fresh data means the cached histories are stale
    rateLimitSenderEvents = {};
    rateLimitSenderEventsInFlight = null;
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
            <div class="ui-empty">
                <p class="ui-text-fail">Failed to load rate limits</p>
                <p>${escapeHtml(error.message)}</p>
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
    if (!limit || !limit.value) return uiTag('No limit', '');
    return uiTag(`${limit.value}${limit.frame ? `/${limit.frame}` : ''}`, 'info');
}


// The head of each card: a title, one line about it, and its tools
function rateLimitCardHead(title, subtitle, tools = '') {
    return `
        <div class="ui-panel-head ui-rl-head">
            <div><h3 class="ui-h2">${escapeHtml(title)}</h3><p class="ui-muted">${escapeHtml(subtitle)}</p></div>
            ${tools ? `<div class="ui-rl-tools">${tools}</div>` : ''}
        </div>`;
}


// Read-only notice above the configured limits - same banner Fail2ban
// Settings shows when the Read-Write key is missing
function renderRateLimitReadOnlyNotice() {
    const data = rateLimitConfigData || {};
    if (data.rw_key_configured !== false) return '';
    return `<div class="ui-list-note">${uiLocked('Editing rate limits is locked', `Editing ${UI_RW_KEY_TEXT}`)}</div>`;
}


// ---- Card 1: rate limit activity --------------------------------------------

function renderRateLimitActivityCard() {
    const container = document.getElementById('rate-limits-activity-card');
    if (!container) return;

    const data = rateLimitEventsData || {};
    const hits = data.total_events || 0;
    const senders = data.window_senders || 0;
    const subtitle = hits === 0
        ? 'No blocked sends in this window'
        : `${hits.toLocaleString()} blocked ${hits === 1 ? 'send' : 'sends'}`
            + ` from ${senders} ${senders === 1 ? 'sender' : 'senders'}`;

    const options = [
        { hours: 24, label: 'Last 24 hours' },
        { hours: 168, label: 'Last 7 days' },
        { hours: 720, label: 'Last 30 days' },
        { hours: 2160, label: 'Last 90 days' },
        { hours: 8760, label: 'Last year' }
    ].map(option => `
        <option value="${option.hours}" ${option.hours === rateLimitWindowHours ? 'selected' : ''}>${option.label}</option>
    `).join('');

    const buckets = data.by_bucket || [];
    const hasHits = buckets.some(bucket => (bucket.count || 0) > 0);

    container.innerHTML = `
        <section class="ui-panel">
            ${rateLimitCardHead('Rate limit activity', subtitle, `
                <select id="rate-limit-window" onchange="changeRateLimitWindow(this.value)" class="ui-select ui-select-auto" aria-label="Window">
                    ${options}
                </select>`)}
            ${hasHits
            ? '<div class="ui-chart-body"><div class="ui-rl-chart"><canvas id="rate-limits-chart"></canvas></div></div>'
            : `
                <div class="ui-empty">
                    <p><b>Nobody hit a rate limit in this window</b></p>
                    <p>Widen the window to look further back.</p>
                </div>
            `}
        </section>
    `;

    if (hasHits) renderRateLimitChart(buckets, data.bucket === 'hour' ? 'hour' : 'day');
}


// The API buckets in UTC. An hour bucket is a moment, so it is localised like
// every other timestamp; a day bucket is a date, so it is labelled verbatim.
// Labels are numeric (14.09) like every other date in the app, never month
// names, which would follow the browser language instead of the UI language.
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

    const [, month, day] = bucket.split('-');
    return `${day}.${month}`;
}


// Short timestamp for narrow screens: day.month and the time, no year, no
// seconds. Same timezone handling as formatTime in utils.js.
function rateLimitShortTime(isoString) {
    if (!isoString) return '-';
    const date = new Date(isoString);
    const options = { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false };
    try {
        if (typeof appTimezone !== 'undefined' && appTimezone && appTimezone !== 'UTC') {
            return new Intl.DateTimeFormat(undefined, { ...options, timeZone: appTimezone }).format(date);
        }
    } catch (e) {
        console.warn('Invalid timezone, using browser local timezone:', appTimezone, e);
    }
    return date.toLocaleString(undefined, options);
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

    // Theme colours from the design tokens: muted text, hairline grid, red bars
    const token = (name, fallback) => getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
    const gridColor = token('--ui-line', 'rgba(0,0,0,0.1)');
    const textColor = token('--ui-muted', '#6B736E');
    const barColor = token('--ui-fail', '#C42B1C');

    rateLimitChart = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
            labels: buckets.map(bucket => rateLimitBucketLabel(bucket.bucket, granularity)),
            datasets: [{
                label: 'Blocked sends',
                data: buckets.map(bucket => bucket.count || 0),
                backgroundColor: barColor,
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

    const header = rateLimitCardHead('Blocked senders', 'Mail that mailcow refused because the sender ran out of allowance',
        senders.length === 0 || detailMode ? '' : `
            <input type="text" value="${escapeHtml(rateLimitSenderSearch)}" placeholder="Search..." aria-label="Search senders"
                oninput="filterRateLimitSenders(this.value)" class="ui-input ui-rl-search">`);

    let body;
    if (senders.length === 0) {
        body = `
            <div class="ui-empty">
                <p><b>No rate limit hits have been collected</b></p>
                <p>Senders that run out of allowance will show up here.</p>
            </div>
        `;
    } else if (detailMode) {
        body = renderRateLimitSenderDetail(senders.find(group => group.user === rateLimitSelectedSender));
    } else {
        body = renderRateLimitSendersTable(senders);
    }

    container.innerHTML = `<section class="ui-panel">${header}${body}</section>`;

    if (!detailMode && senders.length && rateLimitSenderSearch) {
        filterRateLimitSenders(rateLimitSenderSearch);
    }
    // The detail is painted at once from the rows /events already carried;
    // the rest of that sender's history arrives after this
    if (detailMode) loadRateLimitSenderHistory(rateLimitSelectedSender);
}


function renderRateLimitSendersTable(senders) {
    const canWrite = !rateLimitConfigData || rateLimitConfigData.rw_key_configured !== false;

    const rows = senders.map(group => {
        const resetButton = (canWrite && group.last_rl_hash)
            ? `
                <button type="button"
                    onclick="event.stopPropagation(); resetRateLimitCounter('${escapeJsArg(group.user)}', '${escapeJsArg(group.last_rl_hash)}')"
                    class="ui-btn ui-btn-sm ui-btn-primary">
                    Reset counter
                </button>
            `
            : '';
        return `
            <tr data-rl-sender="${escapeHtml((group.user || '').toLowerCase())}" class="ui-dtable-link"
                onclick="selectRateLimitSender('${escapeJsArg(group.user)}')">
                <td class="ui-mono ui-dtable-wrap">${escapeHtml(group.user)}</td>
                <td>${uiTag(group.events, 'fail')}</td>
                <td class="ui-nowrap" title="${escapeHtml(formatTime(group.last_seen))}">${formatAgo(group.last_seen)}</td>
                <td class="hide-mobile">${renderRateLimitBadge(group.current_limit)}</td>
                <td class="hide-mobile">${group.last_reset ? uiTag(`Reset ${formatAgo(group.last_reset)}`, 'ok') : ''}</td>
                <!-- On a phone the action lives in the detail view a tap away;
                     a button beyond the scroll edge is a button nobody finds -->
                <td class="ui-td-end ui-nowrap hide-mobile">${resetButton}</td>
            </tr>
        `;
    }).join('');

    return `
        <div class="ui-dtable-scroll">
            <table class="ui-dtable">
                <thead>
                    <tr><th>Sender</th><th>Hits</th><th>Last hit</th><th class="hide-mobile">Limit</th><th class="hide-mobile">Last reset</th><th class="hide-mobile"></th></tr>
                </thead>
                <tbody>
                    ${rows}
                    <tr data-rl-sender-noresults class="hidden">
                        <td colspan="6" class="ui-empty">No matches</td>
                    </tr>
                </tbody>
            </table>
        </div>
    `;
}


// Clicking a row swaps the whole card body for that sender's detail view
function selectRateLimitSender(user) {
    rateLimitSelectedSender = user;
    // A read that failed last time is worth another try when the reader comes
    // back to this sender
    const cached = rateLimitSenderEvents[user];
    if (cached && cached.failed) delete rateLimitSenderEvents[user];
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

    const resetButton = (canWrite && group.last_rl_hash)
        ? `
            <button type="button"
                onclick="resetRateLimitCounter('${escapeJsArg(group.user)}', '${escapeJsArg(group.last_rl_hash)}')"
                class="ui-btn ui-btn-sm ui-btn-primary">
                Reset counter
            </button>
        `
        : '';

    const resetBadge = group.last_reset
        ? uiTag(`Reset ${formatTime(group.last_reset)}`, 'ok')
        : '';

    return `
        <div class="ui-rl-sender">
            <div>
                <button type="button" onclick="backToRateLimitSenders()" class="ui-btn ui-btn-sm">← All senders</button>
                <p class="ui-mono ui-dtable-wrap"><b>${escapeHtml(group.user)}</b></p>
                <p class="ui-muted">Last hit ${escapeHtml(formatTime(group.last_seen))}</p>
                <div class="ui-chip-row">
                    ${renderRateLimitBadge(group.current_limit)}
                    ${resetBadge}
                </div>
            </div>
            ${resetButton}
        </div>
        <div data-rl-sender-events>${renderRateLimitSenderEvents(group)}</div>
    `;
}


// The refused messages of the open sender: the handful /events already carried
// until the full history lands, then all of it. Only this block is repainted
// when it does, so the panel above it never flickers.
function renderRateLimitSenderEvents(group) {
    const cached = rateLimitSenderEvents[group.user];
    const loaded = !!(cached && cached.events);
    const rows = loaded ? cached.events : (group.recent || []);

    if (rows.length === 0) {
        return '<p class="ui-empty">No details were recorded for these hits</p>';
    }

    // Before the history lands, the hit count from /events is the real total
    const total = loaded ? cached.total : (group.events || rows.length);
    const count = loaded && cached.total > rows.length
        ? `Showing ${rows.length.toLocaleString()} of ${cached.total.toLocaleString()}`
        : `${total.toLocaleString()} refused ${total === 1 ? 'message' : 'messages'}`;

    // A quiet line rather than a spinner: the rows already on screen stay
    // readable while the rest is on its way
    let note = '';
    if (total > rows.length) {
        if (cached && cached.failed) {
            note = `Showing the latest ${rows.length} only - full history failed to load`;
        } else if (!loaded) {
            note = 'Loading full history...';
        }
    }

    return `
        <p class="ui-muted ui-rl-note">${escapeHtml(count)}</p>
        <div class="ui-dtable-scroll">
            <table class="ui-dtable">
                <thead>
                    <tr><th>Time</th><th>Recipient</th><th>Subject</th><th class="hide-mobile">Queue id</th></tr>
                </thead>
                <tbody>
                    ${rows.map(renderRateLimitEventRow).join('')}
                </tbody>
            </table>
        </div>
        ${note ? `<p class="ui-muted ui-rl-note">${escapeHtml(note)}</p>` : ''}
    `;
}


// Everything this viewer collected about one sender, not just the rows the big
// /events response carries. Read once per sender and kept until the page data
// is reloaded.
async function loadRateLimitSenderHistory(user) {
    if (!user || rateLimitSenderEvents[user] || rateLimitSenderEventsInFlight === user) return;
    rateLimitSenderEventsInFlight = user;

    try {
        const response = await authenticatedFetch(
            `/api/rate-limits/sender-events?user=${encodeURIComponent(user)}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const data = await response.json();
        const events = data.events || [];
        rateLimitSenderEvents[user] = {
            events: events,
            total: Number.isFinite(data.total) ? data.total : events.length
        };
    } catch (error) {
        console.error('Failed to load the full history of a blocked sender:', error);
        // The rows already on screen stay; only the note changes
        rateLimitSenderEvents[user] = { failed: true };
    } finally {
        if (rateLimitSenderEventsInFlight === user) rateLimitSenderEventsInFlight = null;
    }

    // The reader may have gone back, or opened another sender, while this was
    // in flight - an answer nobody is looking at is dropped
    if (rateLimitSelectedSender !== user) return;
    refreshRateLimitSenderEvents(user);
}


function refreshRateLimitSenderEvents(user) {
    const card = document.getElementById('rate-limits-senders-card');
    const area = card && card.querySelector('[data-rl-sender-events]');
    if (!area) return;

    const group = rateLimitSenders().find(entry => entry.user === user);
    if (!group) return;
    area.innerHTML = renderRateLimitSenderEvents(group);
}


function renderRateLimitEventRow(event) {
    const subject = event.subject || '';
    const shortened = subject.length > 70 ? `${subject.slice(0, 70)}...` : subject;

    // On a narrow screen every cell keeps its natural width and the table
    // scrolls sideways inside its card. Squeezed columns that snap addresses
    // in half are worse than a scroll.
    return `
        <tr>
            <td class="ui-nowrap"><span class="ui-phone-only">${escapeHtml(rateLimitShortTime(event.time))}</span><span class="ui-phone-hide">${escapeHtml(formatTime(event.time))}</span></td>
            <td class="ui-mono ui-dtable-wrap">${escapeHtml(event.rcpt)}</td>
            <td>${shortened ? `<span dir="auto">${escapeHtml(shortened)}</span>` : '<span class="ui-muted">No subject</span>'}</td>
            <td class="ui-mono ui-muted ui-nowrap hide-mobile">${escapeHtml(event.qid)}</td>
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
        // Update in place. A full reload would flash the loading screen and
        // throw the reader back to the top of the page for a one-row change.
        const group = ((rateLimitEventsData || {}).by_sender || [])
            .find(entry => entry.user === user);
        if (group) group.last_reset = new Date().toISOString();
        renderRateLimitSendersCard();
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
        <button type="button" onclick="setRateLimitConfigFilter('${chip.id}')" data-rl-chip="${chip.id}"
            class="ui-chip" aria-pressed="${chip.id === rateLimitConfigFilter ? 'true' : 'false'}">${chip.label}</button>
    `).join('');

    const domainsError = data.domains_error
        ? `
            <p class="ui-rl-warning">Domain limits could not be read from mailcow: ${escapeHtml(data.domains_error)}</p>
        `
        : '';

    const table = `
        <div class="ui-dtable-scroll">
            <table class="ui-dtable">
                <thead>
                    <tr><th class="hide-mobile">Type</th><th>Name</th><th>Limit</th><th></th></tr>
                </thead>
                <tbody>
                    ${rows}
                    <tr data-rl-noresults class="hidden">
                        <td colspan="4" class="ui-empty">No matches</td>
                    </tr>
                </tbody>
            </table>
        </div>
    `;

    const empty = `
        <div class="ui-empty">
            <p><b>Nothing is limited yet</b></p>
            <p>Mailboxes and domains send without a cap until you set one.</p>
        </div>
    `;

    container.innerHTML = `
        <section class="ui-panel">
            ${rateLimitCardHead('Configured limits', 'How much each mailbox and domain is allowed to send', `
                ${chips}
                <input type="text" value="${escapeHtml(rateLimitConfigSearch)}" placeholder="Search..." aria-label="Search limits"
                    oninput="filterRateLimitConfigRows(this.value)" class="ui-input ui-rl-search">
                ${canWrite && rows ? `<button type="button" onclick="toggleRateLimitBulkPanel()" class="${RATE_LIMIT_ACTION_BUTTON}">Apply to filtered</button>` : ''}`)}
            ${renderRateLimitBulkPanel()}
            ${renderRateLimitReadOnlyNotice()}
            ${domainsError}
            ${rows ? table : empty}
        </section>
    `;

    if (rows) applyRateLimitConfigFilters();
}


function setRateLimitConfigFilter(kind) {
    rateLimitConfigFilter = kind;
    const card = document.getElementById('rate-limits-config-card');
    if (!card) return;

    card.querySelectorAll('[data-rl-chip]').forEach(btn => {
        btn.setAttribute('aria-pressed', btn.dataset.rlChip === kind ? 'true' : 'false');
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

    refreshRateLimitBulkPanel();
}


// ---- Apply one limit to everything the filter shows --------------------------
// Set 100/m on every mailbox of one domain in a single action, instead of
// opening 40 rows one after another. What gets changed is exactly what the
// table shows: search plus the type chips, nothing hidden.

// The match applyRateLimitConfigFilters runs on the rows, run against the data
// instead of the DOM - the counts have to be right even while the table is
// being rebuilt, and the DOM is only ever a picture of this
function rateLimitConfigMatches(kind, name) {
    const q = rateLimitConfigSearch.trim().toLowerCase();
    const matchesName = !q || (name || '').toLowerCase().includes(q);
    const matchesKind = rateLimitConfigFilter === 'all' || kind === rateLimitConfigFilter;
    return matchesName && matchesKind;
}


// The names the configured limits card currently shows, by kind
function rateLimitFilteredTargets() {
    const data = rateLimitConfigData || {};
    return {
        mailboxes: (data.mailboxes || [])
            .filter(entry => rateLimitConfigMatches('mailbox', entry.username))
            .map(entry => entry.username),
        domains: (data.domains || [])
            .filter(entry => rateLimitConfigMatches('domain', entry.domain))
            .map(entry => entry.domain)
    };
}


// "1 mailbox", "12 mailboxes" - used by the caption, the confirmation and the
// toast, so the three never disagree
function rateLimitCountLabel(count, singular, plural) {
    return `${count} ${count === 1 ? singular : plural}`;
}


// What the action covers, in words. A kind nobody selected is left out rather
// than shown as "0 domains".
function rateLimitBulkScope(mailboxes, domains) {
    const parts = [];
    if (mailboxes) parts.push(rateLimitCountLabel(mailboxes, 'mailbox', 'mailboxes'));
    if (domains) parts.push(rateLimitCountLabel(domains, 'domain', 'domains'));
    return parts.join(' and ');
}


function rateLimitBulkCaption(mailboxes, domains) {
    if (!mailboxes && !domains) return 'Nothing matches the current filter';
    return 'Set one limit for everything the filter currently shows: '
        + `${rateLimitCountLabel(mailboxes, 'mailbox', 'mailboxes')}`
        + ` and ${rateLimitCountLabel(domains, 'domain', 'domains')}`;
}


function renderRateLimitBulkPanel() {
    const data = rateLimitConfigData || {};
    if (!rateLimitBulkOpen || data.rw_key_configured === false) return '';

    const targets = rateLimitFilteredTargets();
    const nothing = !targets.mailboxes.length && !targets.domains.length;

    const frames = Object.keys(RATE_LIMIT_FRAME_LABELS).map(key => `
        <option value="${key}" ${key === rateLimitBulkFrame ? 'selected' : ''}>per ${RATE_LIMIT_FRAME_LABELS[key]}</option>
    `).join('');

    return `
        <div class="ui-rl-form">
            <p data-rl-bulk-caption class="ui-muted">${escapeHtml(rateLimitBulkCaption(targets.mailboxes.length, targets.domains.length))}</p>
            <div class="ui-rl-form-row">
                <label for="rate-limit-bulk-value" class="ui-muted">Allow</label>
                <input id="rate-limit-bulk-value" type="number" min="0" step="1" value="${escapeHtml(rateLimitBulkValue)}"
                    placeholder="messages" oninput="setRateLimitBulkValue(this.value)" class="ui-input ui-rl-number">
                <select id="rate-limit-bulk-frame" onchange="setRateLimitBulkFrame(this.value)" class="ui-select ui-select-auto">
                    ${frames}
                </select>
                <button type="button" data-rl-bulk-apply onclick="applyRateLimitBulk()" ${nothing ? 'disabled' : ''}
                    class="${RATE_LIMIT_SAVE_BUTTON}">
                    Apply
                </button>
                <button type="button" onclick="closeRateLimitBulkPanel()" class="${RATE_LIMIT_ACTION_BUTTON}">
                    Cancel
                </button>
            </div>
        </div>
    `;
}


// Typing in the search box never re-renders the card (it would lose focus), so
// the panel's counts are refreshed in place whenever the filter changes
function refreshRateLimitBulkPanel() {
    const card = document.getElementById('rate-limits-config-card');
    const caption = card && card.querySelector('[data-rl-bulk-caption]');
    if (!caption) return;

    const targets = rateLimitFilteredTargets();
    const nothing = !targets.mailboxes.length && !targets.domains.length;
    caption.textContent = rateLimitBulkCaption(targets.mailboxes.length, targets.domains.length);

    const apply = card.querySelector('[data-rl-bulk-apply]');
    if (apply) apply.disabled = nothing;
}


function setRateLimitBulkValue(value) {
    rateLimitBulkValue = value || '';
}


function setRateLimitBulkFrame(frame) {
    rateLimitBulkFrame = frame || 'h';
}


function toggleRateLimitBulkPanel() {
    rateLimitBulkOpen = !rateLimitBulkOpen;
    // One open form at a time: a row being edited and a bulk apply above it
    // are two answers to the same question
    if (rateLimitBulkOpen) rateLimitEditing = null;
    renderRateLimitConfigCard();
}


function closeRateLimitBulkPanel() {
    rateLimitBulkOpen = false;
    renderRateLimitConfigCard();
}


async function applyRateLimitBulk() {
    const targets = rateLimitFilteredTargets();
    if (!targets.mailboxes.length && !targets.domains.length) return;

    const value = parseInt(rateLimitBulkValue, 10);
    if (!Number.isFinite(value) || value < 0) {
        showToast('Enter how many messages to allow, as a whole number', 'error');
        return;
    }

    const frame = rateLimitBulkFrame;
    const frameLabel = RATE_LIMIT_FRAME_LABELS[frame] || frame;
    const scope = rateLimitBulkScope(targets.mailboxes.length, targets.domains.length);

    const confirmed = await showConfirmModal({
        title: value === 0 ? 'Remove rate limits' : 'Apply rate limit',
        message: value === 0
            ? `Remove the limit from ${scope}? They will be able to send without a cap.`
            : `Set ${value} per ${frameLabel} on ${scope}?`,
        confirmText: value === 0 ? 'Remove limits' : 'Apply',
        isDangerous: value === 0
    });
    if (!confirmed) return;

    try {
        const response = await authenticatedFetch('/api/rate-limits/bulk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                mailboxes: targets.mailboxes,
                domains: targets.domains,
                value: value,
                frame: frame
            })
        });

        if (!response.ok) {
            const detail = await response.json().catch(() => ({}));
            showToast(detail.detail || 'Could not apply the rate limit', 'error');
            return;
        }

        const result = await response.json().catch(() => ({}));
        // A name the server did not recognise keeps the limit it already had
        const skipped = (result.skipped || []).map(name => String(name).toLowerCase());
        const untouched = new Set(skipped);
        const applied = names => new Set(names.filter(name => !untouched.has(name.toLowerCase())));
        const mailboxes = applied(targets.mailboxes);
        const domains = applied(targets.domains);

        // Update the rows in place instead of reloading the whole page - an
        // apply should not flash the loading screen or lose scroll position
        const newValue = value === 0 ? null : value;
        const newFrame = value === 0 ? null : frame;
        const config = rateLimitConfigData || {};
        (config.mailboxes || []).forEach(entry => {
            if (!mailboxes.has(entry.username)) return;
            entry.rl_value = newValue;
            entry.rl_frame = newFrame;
        });
        (config.domains || []).forEach(entry => {
            if (!domains.has(entry.domain)) return;
            entry.rl_value = newValue;
            entry.rl_frame = newFrame;
        });

        rateLimitBulkOpen = false;
        renderRateLimitConfigCard();

        // A mailbox's limit also shows on its row in Blocked senders
        const senderNames = new Set(Array.from(mailboxes, name => name.toLowerCase()));
        let sendersChanged = false;
        ((rateLimitEventsData || {}).by_sender || []).forEach(group => {
            if (!senderNames.has(group.user)) return;
            group.current_limit = newValue ? { value: newValue, frame: newFrame } : null;
            sendersChanged = true;
        });
        if (sendersChanged) renderRateLimitSendersCard();

        const changed = rateLimitBulkScope(result.mailboxes_updated || 0, result.domains_updated || 0);
        const tail = skipped.length ? `, ${skipped.length} skipped` : '';
        if (!changed) {
            showToast(`Nothing was changed${tail}`, 'warning');
            return;
        }
        showToast(value === 0
            ? `Limit removed from ${changed}${tail}`
            : `Limit set on ${changed}${tail}`, 'success');
    } catch (error) {
        console.error('Failed to apply the rate limit in bulk:', error);
        showToast('Could not apply the rate limit', 'error');
    }
}


function renderRateLimitConfigRow(kind, name, value, frame, canWrite) {
    const editing = rateLimitEditing
        && rateLimitEditing.kind === kind
        && rateLimitEditing.name === name;

    const action = !canWrite
        ? ''
        : (editing
            ? `
                <button type="button" onclick="closeRateLimitEdit()" class="${RATE_LIMIT_ACTION_BUTTON}">
                    Cancel
                </button>
            `
            : `
                <button type="button" onclick="openRateLimitEdit('${kind}', '${escapeJsArg(name)}')" class="${RATE_LIMIT_ACTION_BUTTON}">
                    Edit
                </button>
            `);

    const row = `
        <tr data-rl-name="${escapeHtml(name.toLowerCase())}" data-rl-kind="${kind}">
            <td class="hide-mobile">${uiTag(kind === 'domain' ? 'Domain' : 'Mailbox', '')}</td>
            <td class="ui-mono ui-dtable-wrap">${escapeHtml(name)}</td>
            <td>${renderRateLimitBadge(value ? { value: value, frame: frame } : null)}</td>
            <td class="ui-td-end ui-nowrap">${action}</td>
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
        <tr data-rl-name="${escapeHtml(name.toLowerCase())}" data-rl-kind="${kind}" data-rl-editrow class="ui-rl-editrow">
            <td colspan="4">
                <div class="ui-rl-form-row">
                    <label for="rate-limit-value" class="ui-muted">Allow</label>
                    <input id="rate-limit-value" type="number" min="0" step="1" value="${value ? escapeHtml(String(value)) : ''}"
                        placeholder="messages" class="ui-input ui-rl-number">
                    <select id="rate-limit-frame" class="ui-select ui-select-auto">
                        ${frames}
                    </select>
                    <button type="button" onclick="saveRateLimit('${kind}', '${escapeJsArg(name)}')"
                        class="${RATE_LIMIT_SAVE_BUTTON}">
                        Save
                    </button>
                    <button type="button" onclick="removeRateLimit('${kind}', '${escapeJsArg(name)}')" class="ui-btn ui-btn-sm ui-btn-danger">
                        Remove limit
                    </button>
                </div>
            </td>
        </tr>
    `;
}


function openRateLimitEdit(kind, name) {
    rateLimitEditing = { kind: kind, name: name };
    // One open form at a time, in both directions
    rateLimitBulkOpen = false;
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

        // Update the row in place instead of reloading the whole page - a
        // save should not flash the loading screen or lose scroll position
        const newValue = value === 0 ? null : value;
        const newFrame = value === 0 ? null : frame;
        const config = rateLimitConfigData || {};
        const row = kind === 'mailbox'
            ? (config.mailboxes || []).find(entry => entry.username === name)
            : (config.domains || []).find(entry => entry.domain === name);
        if (row) {
            row.rl_value = newValue;
            row.rl_frame = newFrame;
        }
        renderRateLimitConfigCard();

        // A mailbox's limit also shows on its row in Blocked senders
        if (kind === 'mailbox') {
            const group = ((rateLimitEventsData || {}).by_sender || [])
                .find(entry => entry.user === name.toLowerCase());
            if (group) {
                group.current_limit = newValue ? { value: newValue, frame: newFrame } : null;
                renderRateLimitSendersCard();
            }
        }
    } catch (error) {
        console.error('Failed to save rate limit:', error);
        showToast('Could not save the rate limit', 'error');
    }
}
