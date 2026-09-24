// Message details modal: state, rendering, entry points, and interactions.
// Loaded after app.js; uses authenticatedFetch, renderGeoIPInfo, and utils.js helpers.

// Modal state
let currentModalTab = 'overview';
let currentModalData = null;

// =============================================================================
// Part 3: Message Modal with Tabs, Helper Functions, Export, Dark Mode
// =============================================================================

// =============================================================================
// MESSAGE MODAL WITH TABS
// =============================================================================

function switchModalTab(tab) {
    console.log('Switching modal tab to:', tab);
    currentModalTab = tab;

    // Update tab buttons
    document.querySelectorAll('[id^="modal-tab-"]').forEach(btn => {
        btn.classList.remove('active');
    });
    const activeTab = document.getElementById(`modal-tab-${tab}`);
    if (activeTab) {
        activeTab.classList.add('active');
    } else {
        console.error('Modal tab button not found:', `modal-tab-${tab}`);
    }

    // Render content
    if (currentModalData) {
        renderModalTab(tab, currentModalData);
    } else {
        console.error('No modal data available');
    }
}

async function viewMessageDetails(correlationKey) {
    if (!correlationKey) {
        console.error('No correlation key provided');
        return;
    }

    console.log('Loading message details for:', correlationKey);

    const modal = document.getElementById('message-modal');
    const content = document.getElementById('message-modal-content');

    if (!modal || !content) {
        console.error('Modal elements not found');
        return;
    }

    // Block body scroll
    document.body.style.overflow = 'hidden';

    modal.classList.remove('hidden');
    content.innerHTML = '<div class="text-center py-8"><div class="loading mx-auto mb-4"></div><p class="text-gray-500 dark:text-gray-400">Loading...</p></div>';

    try {
        const response = await authenticatedFetch(`/api/message/${correlationKey}/details`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('Message details loaded:', data);

        currentModalData = data;
        currentModalTab = 'overview';

        // Update Security tab indicator
        updateSecurityTabIndicator(data);

        // Hide Security tab if netfilter feature is disabled
        const netfilterTab = document.getElementById('modal-tab-netfilter');
        if (netfilterTab) {
            netfilterTab.style.display = window.disabledFeatures.includes('netfilter') ? 'none' : '';
        }

        document.querySelectorAll('[id^="modal-tab-"]').forEach(btn => {
            btn.classList.remove('active');
        });
        const overviewTab = document.getElementById('modal-tab-overview');
        if (overviewTab) {
            overviewTab.classList.add('active');
        }

        renderModalTab('overview', data);
    } catch (error) {
        console.error('Failed to load message details:', error);
        content.innerHTML = `<p class="text-red-500 text-center py-8">Failed to load message details: ${escapeHtml(error.message)}</p>`;
    }
}

function renderModalTab(tab, data) {
    const content = document.getElementById('message-modal-content');

    switch (tab) {
        case 'overview':
            renderOverviewTab(content, data);
            break;
        case 'postfix':
            renderPostfixTab(content, data);
            break;
        case 'spam':
            renderSpamTab(content, data);
            break;
        case 'netfilter':
            renderNetfilterTab(content, data);
            break;
    }
}

function folderIconSvg(sizeClasses) {
    return `<svg class="${sizeClasses} flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"></path></svg>`;
}

// Delivery outcome Dovecot reported for the last hop (issue #65).
// Postfix logs status=sent as soon as it hands the message to Dovecot over
// LMTP, so what happened afterwards - stored, filed into Junk, forwarded or
// dropped by a Sieve rule - is only visible here.
const DOVECOT_VERDICTS = {
    discarded: {
        icon: '⊘',
        label: 'Discarded by Sieve',
        fallback: 'A Sieve rule dropped this message - it never reached the mailbox.',
        box: 'bg-slate-50 dark:bg-slate-900/40 border-slate-300 dark:border-slate-600',
        title: 'text-slate-800 dark:text-slate-200',
        body: 'text-slate-600 dark:text-slate-400'
    },
    rejected: {
        icon: '✗',
        label: 'Rejected by Sieve',
        fallback: 'A Sieve rule refused this message and reported it back to the sender.',
        box: 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800',
        title: 'text-red-800 dark:text-red-300',
        body: 'text-red-600 dark:text-red-400'
    },
    failed: {
        icon: '!',
        label: 'Delivery to mailbox failed',
        fallback: 'Dovecot could not store this message.',
        box: 'bg-orange-50 dark:bg-orange-900/20 border-orange-200 dark:border-orange-800',
        title: 'text-orange-800 dark:text-orange-300',
        body: 'text-orange-600 dark:text-orange-400'
    },
    forwarded: {
        icon: '→',
        label: 'Forwarded by Sieve',
        fallback: 'A Sieve rule redirected this message.',
        box: 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800',
        title: 'text-blue-800 dark:text-blue-300',
        body: 'text-blue-600 dark:text-blue-400'
    },
    stored: {
        icon: '✓',
        label: 'Stored in mailbox',
        fallback: 'Dovecot wrote this message to the mailbox.',
        box: 'bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800',
        title: 'text-emerald-800 dark:text-emerald-300',
        body: 'text-emerald-600 dark:text-emerald-400'
    }
};

function getDovecotVerdictText(dovecot) {
    const verdict = DOVECOT_VERDICTS[dovecot.status];
    switch (dovecot.status) {
        case 'stored':
            return dovecot.mailbox
                ? `Stored in the folder "${dovecot.mailbox}".`
                : verdict.fallback;
        case 'forwarded':
            return dovecot.detail
                ? `Redirected to ${dovecot.detail}.`
                : verdict.fallback;
        case 'failed':
            return dovecot.detail
                ? `${dovecot.detail}${dovecot.mailbox ? ` (target folder: ${dovecot.mailbox})` : ''}`
                : verdict.fallback;
        case 'rejected':
            return dovecot.detail ? `Reason: ${dovecot.detail}` : verdict.fallback;
        default:
            return verdict.fallback;
    }
}

function renderDovecotSummary(dovecot) {
    if (!dovecot || !dovecot.status || !DOVECOT_VERDICTS[dovecot.status]) return '';
    // A normal store is already shown as the folder chip next to the status;
    // the callout is reserved for outcomes that need explaining.
    if (dovecot.status === 'stored') return '';
    const verdict = DOVECOT_VERDICTS[dovecot.status];

    return `
        <div class="border ${verdict.box} rounded-lg p-4 mt-3">
            <div class="flex items-start gap-3">
                <span class="text-lg leading-none ${verdict.title}">${verdict.icon}</span>
                <div class="min-w-0">
                    <p class="text-sm font-semibold ${verdict.title}">Mailbox delivery: ${verdict.label}</p>
                    <p class="text-xs ${verdict.body} mt-1 break-words">${escapeHtml(getDovecotVerdictText(dovecot))}</p>
                </div>
            </div>
        </div>
    `;
}

function renderDovecotTimelineRow(log) {
    return `
        <div class="p-3 bg-gray-50 dark:bg-gray-700/50 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition">
            <div class="flex justify-between items-start mb-1">
                <div class="flex items-center gap-2 flex-wrap">
                    <span class="text-xs font-mono text-gray-600 dark:text-gray-300">${formatTime(log.time)}</span>
                    <span class="text-xs px-2 py-0.5 rounded bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300">dovecot</span>
                    ${log.recipient ? `<span class="text-xs text-gray-500 dark:text-gray-400">=> ${escapeHtml(log.recipient)}</span>` : ''}
                </div>
                ${log.verdict && DOVECOT_VERDICTS[log.verdict] ? `<span class="text-xs px-2 py-0.5 rounded ${getStatusClass(log.verdict === 'stored' ? 'delivered' : log.verdict)}">${log.verdict}</span>` : ''}
            </div>
            <p class="text-xs font-mono text-gray-700 dark:text-gray-300 break-all">${escapeHtml(log.message || '')}</p>
        </div>
    `;
}

function renderPostfixTimelineRow(log) {
    return `
        <div class="p-3 bg-gray-50 dark:bg-gray-700/50 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition">
            <div class="flex justify-between items-start mb-1">
                <div class="flex items-center gap-2 flex-wrap">
                    <span class="text-xs font-mono text-gray-600 dark:text-gray-300">${formatTime(log.time)}</span>
                    ${log.program ? `<span class="text-xs px-2 py-0.5 rounded bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300">${log.program}</span>` : ''}
                    ${log.recipient ? `<span class="text-xs text-gray-500 dark:text-gray-400">=> ${escapeHtml(log.recipient)}</span>` : ''}
                </div>
                ${log.status ? `<span class="inline-block px-2 py-0.5 text-xs font-medium rounded ${getStatusClass(log.status)}">${log.status}</span>` : ''}
            </div>
            <p class="text-xs text-gray-700 dark:text-gray-300 font-mono break-all leading-relaxed">${escapeHtml(log.message)}</p>
            ${log.relay ? `<p class="text-xs text-gray-500 dark:text-gray-400 mt-1">Relay: ${escapeHtml(log.relay)}</p>` : ''}
            ${log.delay ? `<p class="text-xs text-gray-500 dark:text-gray-400">Delay: ${log.delay.toFixed(2)}s</p>` : ''}
        </div>
    `;
}

// One chronological timeline for the whole delivery: Postfix lines and the
// Dovecot LMTP lines of the last hop, interleaved by time - each line already
// carries its program tag, so no separate section is needed.
function renderLogTimeline(postfixLogs, dovecotLogs) {
    const entries = (postfixLogs || []).map(log => ({ dovecot: false, log }))
        .concat((dovecotLogs || []).map(log => ({ dovecot: true, log })))
        .sort((a, b) => ((a.log.time || '') < (b.log.time || '') ? -1 : 1));

    const sources = [...new Set(entries.map(e => timelineSource(e)))];
    const filterBar = sources.length > 1 ? `
        <div class="flex flex-wrap items-center gap-1.5" id="log-timeline-filters">
            <button data-source="" onclick="filterLogTimeline(this)"
                class="px-2.5 py-1 text-xs rounded border bg-blue-100 dark:bg-blue-500/10 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-500/20">All</button>
            ${sources.map(s => `
                <button data-source="${escapeHtml(s)}" onclick="filterLogTimeline(this)"
                    class="px-2.5 py-1 text-xs rounded border bg-gray-100 dark:bg-gray-700/50 text-gray-600 dark:text-gray-300 border-gray-200 dark:border-gray-600">${escapeHtml(s)}</button>
            `).join('')}
        </div>
    ` : '';

    return `
        <div class="flex-1 min-h-0 flex flex-col">
            <div class="flex items-center justify-between gap-3 mb-3 flex-shrink-0">
                <div class="flex items-baseline gap-2 min-w-0">
                    <h4 class="text-md font-semibold text-gray-900 dark:text-white whitespace-nowrap">Complete Log Timeline</h4>
                    <span class="text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap" id="log-timeline-count">${entries.length} entries</span>
                </div>
                ${filterBar}
            </div>
            <div class="space-y-2 flex-1 min-h-0 overflow-y-auto" id="log-timeline-entries">
                ${entries.map(e => `<div data-log-source="${escapeHtml(timelineSource(e))}">${e.dovecot ? renderDovecotTimelineRow(e.log) : renderPostfixTimelineRow(e.log)}</div>`).join('')}
            </div>
        </div>
    `;
}

function renderRelatedDeliveries(data) {
    // A forwarded or otherwise re-submitted message is delivered several
    // times under one Message-ID (issue #36). Shown as one chronological
    // journey - the current leg included - so the sequence of deliveries
    // explains itself.
    const others = data.related_deliveries;
    if (!others || others.length === 0) return '';

    const legs = others.concat([{
        correlation_key: data.correlation_key,
        sender: data.sender,
        recipient: data.recipient,
        direction: data.direction,
        final_status: data.final_status,
        first_seen: data.first_seen,
        queue_id: data.queue_id,
        dovecot_status: data.dovecot ? data.dovecot.status : null,
        dovecot_mailbox: data.dovecot ? data.dovecot.mailbox : null,
        current: true
    }]).sort((a, b) => (a.first_seen || '9') < (b.first_seen || '9') ? -1 : 1);

    const statusCounts = {};
    legs.forEach(leg => {
        const s = leg.final_status || 'never completed';
        statusCounts[s] = (statusCounts[s] || 0) + 1;
    });
    const statusSummary = Object.entries(statusCounts).map(([s, n]) => `${n} ${escapeHtml(s)}`).join(', ');

    return `
        <div class="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-3 sm:p-4 mt-3">
            <!-- Collapsed by default so several legs do not push the rest of
                 the overview down; the summary line already tells the story -->
            <div class="flex items-center justify-between cursor-pointer select-none" onclick="toggleDeliveryJourney()">
                <div>
                    <h4 class="text-sm sm:text-md font-semibold text-gray-900 dark:text-white">Delivery journey</h4>
                    <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">This message passed through the server ${legs.length} times: ${statusSummary}.</p>
                </div>
                <svg id="delivery-journey-chevron" class="w-4 h-4 text-gray-400 flex-shrink-0 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                </svg>
            </div>
            <div class="space-y-2 mt-3 hidden" id="delivery-journey-legs">
                ${legs.map((leg, i) => `
                    <div class="p-3 rounded ${leg.current
                        ? 'bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-700'
                        : 'bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition cursor-pointer'}"
                        ${leg.current ? '' : `onclick="viewMessageDetails('${escapeHtml(leg.correlation_key)}')"`}>
                        <div class="flex justify-between items-start gap-2 flex-wrap">
                            <div class="flex items-center gap-2 min-w-0">
                                <span class="text-xs font-semibold text-gray-400 dark:text-gray-500 flex-shrink-0">${i + 1}.</span>
                                <span class="text-sm text-gray-900 dark:text-white break-all">${escapeHtml(leg.sender || '-')} =&gt; ${escapeHtml(leg.recipient || '-')}</span>
                                ${leg.current ? '<span class="text-xs px-2 py-0.5 rounded bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300 flex-shrink-0">viewing</span>' : ''}
                            </div>
                            <div class="flex items-center gap-2 flex-wrap">
                                ${leg.final_status
                                    ? `<span class="text-xs px-2 py-0.5 rounded ${getStatusClass(leg.final_status)}">${escapeHtml(leg.final_status)}</span>`
                                    : '<span class="text-xs px-2 py-0.5 rounded bg-gray-200 dark:bg-gray-600 text-gray-600 dark:text-gray-300" title="This delivery attempt never reached a final outcome">no final status</span>'}
                                ${leg.dovecot_status === 'stored' && leg.dovecot_mailbox ? `<span class="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded bg-amber-100 dark:bg-amber-500/10 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-500/20">${folderIconSvg('w-3 h-3')}${escapeHtml(leg.dovecot_mailbox)}</span>` : ''}
                                <span class="text-xs font-mono text-gray-500 dark:text-gray-400">${formatTime(leg.first_seen)}</span>
                            </div>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}

function timelineSource(entry) {
    // Filtering is by the main source; the per-program detail stays visible
    // as each line's own tag
    return entry.dovecot ? 'dovecot' : 'postfix';
}

// Filter the dialog's log timeline by source. One source at a time; the
// empty source is "All".
function filterLogTimeline(button) {
    const source = button.dataset.source;
    const active = 'px-2.5 py-1 text-xs rounded border bg-blue-100 dark:bg-blue-500/10 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-500/20';
    const idle = 'px-2.5 py-1 text-xs rounded border bg-gray-100 dark:bg-gray-700/50 text-gray-600 dark:text-gray-300 border-gray-200 dark:border-gray-600';
    document.querySelectorAll('#log-timeline-filters button').forEach(b => {
        b.className = b === button ? active : idle;
    });
    let shown = 0, total = 0;
    document.querySelectorAll('#log-timeline-entries > [data-log-source]').forEach(row => {
        total += 1;
        const match = !source || row.dataset.logSource === source;
        row.classList.toggle('hidden', !match);
        if (match) shown += 1;
    });
    const count = document.getElementById('log-timeline-count');
    if (count) count.textContent = source ? `${shown} of ${total} entries` : `${total} entries`;
}

function toggleDeliveryJourney() {
    const legs = document.getElementById('delivery-journey-legs');
    const chevron = document.getElementById('delivery-journey-chevron');
    const open = legs.classList.toggle('hidden');
    if (chevron) chevron.style.transform = open ? '' : 'rotate(180deg)';
}

function renderOverviewTab(content, data) {
    // Collect recipients from Postfix logs if available (these have full addresses including +)
    let recipientsFromPostfix = new Set();
    if (data.postfix && data.postfix.length > 0) {
        data.postfix.forEach(log => {
            if (log.recipient) {
                recipientsFromPostfix.add(log.recipient);
            }
        });
    }

    // Use Postfix recipients if available, otherwise fall back to correlation recipients
    const recipientsToDisplay = recipientsFromPostfix.size > 0
        ? Array.from(recipientsFromPostfix)
        : (data.recipients || []);

    // Build recipients section for right column
    let recipientsRightColumn = '';
    if (recipientsToDisplay.length > 0) {
        if (recipientsToDisplay.length > 1) {
            recipientsRightColumn = `
                <div>
                    <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Recipients (${recipientsToDisplay.length})</p>
                    <div class="mt-2 space-y-1 max-h-32 overflow-y-auto">
                        ${recipientsToDisplay.map(r => `
                            <div class="flex items-center gap-2">
                                <svg class="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                                </svg>
                                <span class="text-sm text-gray-900 dark:text-white">${copyableText(r)}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        } else {
            recipientsRightColumn = `
                <div>
                    <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">To</p>
                    <p class="text-sm font-semibold text-gray-900 dark:text-white mt-1">${copyableText(recipientsToDisplay[0] || '-')}</p>
                </div>
            `;
        }
    } else if (data.recipient) {
        recipientsRightColumn = `
            <div>
                <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">To</p>
                <p class="text-sm font-semibold text-gray-900 dark:text-white mt-1">${copyableText(data.recipient)}</p>
            </div>
        `;
    }

    content.innerHTML = `
        <div class="flex flex-col h-full">
            <div class="flex-1 overflow-y-auto min-h-0">
                <div class="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-gray-800 dark:to-gray-700 p-4 rounded-lg">
                    <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-3">Message Overview</h3>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <!-- Left Column -->
                        <div class="space-y-3">
                            <div>
                                <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">From</p>
                                <p class="text-sm font-semibold text-gray-900 dark:text-white mt-1">${copyableText(data.sender || '-')}</p>
                            </div>
                            ${data.subject && data.subject !== 'Postfix Log Details' ? `
                                <div class="min-w-0">
                                    <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Subject</p>
                                    <p class="text-sm text-gray-900 dark:text-white mt-1 truncate" dir="auto" title="${escapeHtml(data.subject)}">${escapeHtml(data.subject)}</p>
                                </div>
                            ` : ''}
                            ${data.final_status || data.direction ? `
                                <div>
                                    <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-1">Status & Direction</p>
                                    <div class="flex items-center gap-2 flex-wrap">
                                        ${data.final_status ? `<span class="inline-block px-3 py-1 text-xs font-medium rounded ${getStatusClass(data.final_status)}">${data.final_status}</span>` : ''}
                                        ${data.direction ? `<span class="inline-block px-3 py-1 text-xs font-medium rounded ${getDirectionClass(data.direction)}">${data.direction}</span>` : ''}
                                        ${data.dovecot && data.dovecot.status === 'stored' && data.dovecot.mailbox ? `<span class="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-medium rounded bg-amber-100 dark:bg-amber-500/10 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-500/20">${folderIconSvg('w-3.5 h-3.5')}${escapeHtml(data.dovecot.mailbox)}</span>` : ''}
                                    </div>
                                </div>
                            ` : ''}
                        </div>
                        <!-- Right Column -->
                        <div class="space-y-3">
                            ${recipientsRightColumn}
                            ${data.queue_id || data.message_id ? `
                                <div class="flex gap-4">
                                    ${data.queue_id ? `
                                        <div class="flex-shrink-0">
                                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Queue ID</p>
                                            <p class="text-xs font-mono text-gray-600 dark:text-gray-400 mt-1 whitespace-nowrap">${copyableText(data.queue_id)}</p>
                                        </div>
                                    ` : ''}
                                    ${data.message_id ? `
                                        <div class="min-w-0 flex-1">
                                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Message ID</p>
                                            <p class="text-xs font-mono text-gray-600 dark:text-gray-400 mt-1 truncate" title="${escapeHtml(data.message_id)}">${copyableText(data.message_id)}</p>
                                        </div>
                                    ` : ''}
                                </div>
                            ` : ''}
                        </div>
                    </div>
                </div>
                ${renderRelatedDeliveries(data)}
                ${renderDovecotSummary(data.dovecot)}
                ${data.rspamd ? `
                    <div class="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-3 sm:p-4 mt-1 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/30 transition" onclick="switchModalTab('spam')">
                        <div class="flex items-baseline gap-2 mb-3">
                            <h4 class="text-sm sm:text-md font-semibold text-gray-900 dark:text-white">Quick Spam Summary</h4>
                            <span class="text-[10px] sm:text-xs text-gray-500 dark:text-gray-400">See "Spam Analysis" tab for details</span>
                        </div>
                        <div class="grid grid-cols-3 gap-2">
                            <div class="text-center">
                                <p class="text-lg sm:text-2xl font-bold ${data.rspamd.score >= (data.rspamd.required_score || 15) ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'}">
                                    ${data.rspamd.score.toFixed(2)}
                                </p>
                                <p class="text-[10px] sm:text-xs text-gray-500 dark:text-gray-400 mt-1">Score</p>
                            </div>
                            <div class="text-center">
                                <p class="text-sm sm:text-lg font-semibold text-gray-900 dark:text-white truncate">
                                    ${data.rspamd.action}
                                </p>
                                <p class="text-[10px] sm:text-xs text-gray-500 dark:text-gray-400 mt-1">Action</p>
                            </div>
                            <div class="text-center">
                                <p class="text-sm sm:text-lg font-semibold ${data.rspamd.is_spam ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'}">
                                    ${data.rspamd.is_spam ? 'SPAM' : 'CLEAN'}
                                </p>
                                <p class="text-[10px] sm:text-xs text-gray-500 dark:text-gray-400 mt-1">Class</p>
                            </div>
                        </div>
                    </div>
                ` : data.postfix && data.postfix.length > 0 ? `
                    <div class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mt-3">
                    <div class="flex items-start gap-3">
                        <svg class="w-5 h-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>
                        </svg>
                        <div>
                            <p class="text-sm font-medium text-blue-900 dark:text-blue-300">Postfix Delivery Logs</p>
                            <p class="text-xs text-blue-800 dark:text-blue-400 mt-1">Click "Logs" tab to see complete delivery timeline (${data.postfix.length} entries)</p>
                        </div>
                    </div>
                    </div>
                ` : ''}
            </div>
            ${data.rspamd ? `
                <div class="flex-shrink-0 mt-auto pt-3 border-t border-gray-200 dark:border-gray-700">
                    <div class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
                        <div class="flex items-start gap-3">
                            <svg class="w-5 h-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>
                            </svg>
                            <div class="flex-1">
                                <p class="text-sm font-medium text-blue-900 dark:text-blue-300 mb-2">Additional Details</p>
                                <div class="space-y-1 text-xs text-blue-800 dark:text-blue-400">
                                    ${data.rspamd.ip ? renderGeoIPInfo(data.rspamd, '16x12') : ''}
                                    ${data.rspamd.user ? `<p>Authenticated User: ${copyableText(data.rspamd.user)}</p>` : ''}
                                    ${data.rspamd.size ? `<p>Message Size: ${formatSize(data.rspamd.size)}</p>` : ''}
                                    ${data.rspamd.has_auth ? `<p>Authentication: Verified (MAILCOW_AUTH)</p>` : ''}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            ` : ''}
        </div>
    `;
}

function renderPostfixTab(content, data) {
    // Dovecot handles the hop after Postfix, so its lines are part of the
    // same delivery timeline, interleaved by time and tagged per line.
    const dovecotLogs = (data.dovecot && data.dovecot.logs) ? data.dovecot.logs : [];

    if (!data.postfix || data.postfix.length === 0) {
        content.innerHTML = dovecotLogs.length ? `
            <div class="space-y-6">
                <p class="text-sm text-gray-500 dark:text-gray-400">No Postfix delivery logs available</p>
                ${renderLogTimeline([], dovecotLogs)}
            </div>
        ` : `
            <div class="text-center py-12">
                <svg class="w-16 h-16 mx-auto text-gray-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"></path>
                </svg>
                <p class="text-gray-500 dark:text-gray-400">No Postfix delivery logs available</p>
            </div>
        `;
        return;
    }

    // Extract key information from logs
    let sender = null, clientIp = null, relay = null;
    let messageId = null, finalStatus = null, totalDelay = null, queueId = null;
    let errorReasons = [];
    let recipientsFromPostfix = new Set(); // Collect all unique recipients from Postfix logs

    data.postfix.forEach(log => {
        if (log.queue_id && !queueId) queueId = log.queue_id;
        if (log.sender && !sender) sender = log.sender;
        if (log.relay && !relay) relay = log.relay;
        if (log.message_id && !messageId) messageId = log.message_id;
        if (log.status) finalStatus = log.status;
        if (log.delay) totalDelay = log.delay;
        // Collect recipients from Postfix logs (these have the full address including +)
        if (log.recipient) {
            recipientsFromPostfix.add(log.recipient);
        }

        if (!clientIp && log.message) {
            const ipMatch = log.message.match(/client=.*?\[(\d+\.\d+\.\d+\.\d+)\]/);
            if (ipMatch) clientIp = ipMatch[1];
        }

        // Extract error reasons for non-sent statuses
        if (log.status && log.status !== 'sent' && log.message) {
            // Look for "said:" pattern (remote server response)
            const saidMatch = log.message.match(/said:\s*(.+?)(?:\s*\(in reply|$)/i);
            if (saidMatch) {
                errorReasons.push({
                    recipient: log.recipient,
                    status: log.status,
                    reason: saidMatch[1].trim()
                });
            } else if (log.status === 'deferred' || log.status === 'bounced') {
                // Look for parenthetical reason
                const parenMatch = log.message.match(/status=\w+\s*\((.+?)\)$/);
                if (parenMatch) {
                    errorReasons.push({
                        recipient: log.recipient,
                        status: log.status,
                        reason: parenMatch[1].trim()
                    });
                }
            }
        }
    });

    // Generate unique ID for accordion
    const accordionId = 'postfix-accordion-' + Date.now();

    // Separate system logs from recipient logs
    const postfixByRecipient = data.postfix_by_recipient || {};
    const systemLogs = postfixByRecipient['_system'] || [];
    const recipientEntries = Object.entries(postfixByRecipient).filter(([key]) => key !== '_system');

    // Every retry logs the same error again; one line with an attempt count
    // says the same thing without crowding the log timeline off the screen
    const dedupedErrors = [];
    const errorsSeen = new Map();
    errorReasons.forEach(err => {
        const key = `${err.recipient || ''}|${err.status}|${err.reason}`;
        const existing = errorsSeen.get(key);
        if (existing) {
            existing.count++;
        } else {
            const entry = { ...err, count: 1 };
            errorsSeen.set(key, entry);
            dedupedErrors.push(entry);
        }
    });

    // Build error summary section. The list is capped so many distinct errors
    // scroll inside the box instead of squeezing the timeline below it.
    const errorSummaryHtml = dedupedErrors.length > 0 ? `
        <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 flex-shrink-0">
            <div class="flex items-start gap-3">
                <svg class="w-6 h-6 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <div class="flex-1 min-w-0">
                    <h4 class="text-md font-semibold text-red-800 dark:text-red-300 mb-2">Delivery Error</h4>
                    <div class="max-h-40 overflow-y-auto pr-1">
                        ${dedupedErrors.map(err => `
                            <div class="mb-2 last:mb-0">
                                ${err.recipient || err.count > 1 ? `
                                    <div class="flex flex-wrap items-center gap-2">
                                        ${err.recipient ? `<p class="text-sm font-medium text-red-700 dark:text-red-400">${escapeHtml(err.recipient)}</p>` : ''}
                                        ${err.count > 1 ? `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 dark:bg-red-500/10 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-500/20 whitespace-nowrap">${err.count} attempts</span>` : ''}
                                    </div>
                                ` : ''}
                                <p class="text-sm text-red-600 dark:text-red-300 mt-1">${escapeHtml(err.reason)}</p>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        </div>
    ` : '';

    content.innerHTML = `
        <div class="h-full flex flex-col min-h-0 gap-6">
            ${errorSummaryHtml}
            <!-- Compact mail summary strip so the logs get the room. The
                 full details live in the Overview tab -->
            <div class="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-gray-800 dark:to-gray-700 p-4 rounded-lg flex-shrink-0">
                <div class="grid grid-cols-2 md:grid-cols-4 gap-x-5 gap-y-3">
                    ${sender ? `
                        <div class="min-w-0">
                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">From</p>
                            <p class="text-sm font-semibold text-gray-900 dark:text-white truncate mt-0.5" title="${escapeHtml(sender)}">${copyableText(sender)}</p>
                        </div>
                    ` : ''}
                    ${recipientsFromPostfix.size > 0 ? `
                        <div class="min-w-0">
                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">To (${recipientsFromPostfix.size})</p>
                            <p class="text-sm font-semibold text-gray-900 dark:text-white truncate mt-0.5">${recipientsFromPostfix.size === 1 ? copyableText(Array.from(recipientsFromPostfix)[0]) : `${recipientsFromPostfix.size} recipients`}</p>
                        </div>
                    ` : (data.recipients && data.recipients.length > 0 ? `
                        <div class="min-w-0">
                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">To (${data.recipients.length})</p>
                            <p class="text-sm font-semibold text-gray-900 dark:text-white truncate mt-0.5">${data.recipients.length === 1 ? copyableText(data.recipients[0]) : `${data.recipients.length} recipients`}</p>
                        </div>
                    ` : '')}
                    ${finalStatus ? `
                        <div>
                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Final Status</p>
                            <span class="inline-block px-2.5 py-0.5 text-xs font-medium rounded ${getStatusClass(finalStatus)} mt-0.5">${finalStatus}</span>
                        </div>
                    ` : ''}
                    ${queueId ? `
                        <div class="min-w-0">
                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Queue ID</p>
                            <p class="text-sm font-mono text-gray-900 dark:text-white truncate mt-0.5">${copyableText(queueId)}</p>
                        </div>
                    ` : ''}
                    ${clientIp ? `
                        <div class="min-w-0">
                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Client IP</p>
                            <p class="text-sm font-mono text-gray-900 dark:text-white truncate mt-0.5">${copyableText(clientIp)}</p>
                        </div>
                    ` : ''}
                    ${relay ? `
                        <div class="min-w-0">
                            <p class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Relay</p>
                            <p class="text-sm font-mono text-gray-900 dark:text-white truncate mt-0.5" title="${escapeHtml(relay)}">${escapeHtml(relay)}</p>
                        </div>
                    ` : ''}
                </div>
            </div>

            <!-- Delivery Summary by Recipient (if multiple recipients) -->
            ${recipientEntries.length > 1 ? `
                <div class="border-t border-gray-200 dark:border-gray-700 pt-4">
                    <h4 class="text-md font-semibold text-gray-900 dark:text-white mb-3">Delivery Summary by Recipient</h4>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                        ${recipientEntries.map(([recipient, logs]) => {
        const statusLog = logs.find(l => l.status) || logs[0];
        return `
                                <div class="p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg border border-gray-200 dark:border-gray-600">
                                    <div class="flex items-center justify-between">
                                        <span class="text-sm text-gray-900 dark:text-white truncate flex-1">${copyableText(recipient)}</span>
                                        ${statusLog.status ? `<span class="ml-2 inline-block px-2 py-0.5 text-xs font-medium rounded ${getStatusClass(statusLog.status)}">${statusLog.status}</span>` : ''}
                                    </div>
                                    ${statusLog.relay ? `<p class="text-xs text-gray-500 dark:text-gray-400 mt-1 truncate">via ${escapeHtml(statusLog.relay)}</p>` : ''}
                                </div>
                            `;
    }).join('')}
                    </div>
                </div>
            ` : ''}

            <!-- Complete Log Timeline - the header and filters stay put, the
                 entry list takes the remaining height and scrolls alone -->
            ${renderLogTimeline(data.postfix, dovecotLogs)}
        </div>
    `;
}

// Accordion toggle function
function toggleAccordion(id) {
    const content = document.getElementById(id);
    const icon = document.getElementById(id + '-icon');

    if (content.classList.contains('hidden')) {
        content.classList.remove('hidden');
        icon.style.transform = 'rotate(180deg)';
    } else {
        content.classList.add('hidden');
        icon.style.transform = 'rotate(0deg)';
    }
}

function renderSpamTab(content, data) {
    if (!data.rspamd) {
        content.innerHTML = `
            <div class="text-center py-12">
                <svg class="w-16 h-16 mx-auto text-gray-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                </svg>
                <p class="text-gray-500 dark:text-gray-400">No spam analysis data available</p>
            </div>
        `;
        return;
    }

    content.innerHTML = `
        <div class="space-y-6">
            <div class="grid grid-cols-3 gap-2 sm:gap-3">
                <div class="bg-gray-50 dark:bg-gray-700/50 p-2 sm:p-3 rounded-lg text-center">
                    <p class="text-[10px] sm:text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-0.5 sm:mb-1 truncate">Score</p>
                    <p class="text-base sm:text-2xl font-bold ${data.rspamd.score >= (data.rspamd.required_score || 15) ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'}">
                        ${data.rspamd.score.toFixed(2)}
                    </p>
                    <p class="text-[9px] sm:text-xs text-gray-500 dark:text-gray-400">Limit: ${data.rspamd.required_score || 15}</p>
                </div>
                <div class="bg-gray-50 dark:bg-gray-700/50 p-2 sm:p-3 rounded-lg text-center">
                    <p class="text-[10px] sm:text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-0.5 sm:mb-1 truncate">Action</p>
                    <p class="text-sm sm:text-lg font-semibold text-gray-900 dark:text-white truncate">
                        ${data.rspamd.action}
                    </p>
                </div>
                <div class="bg-gray-50 dark:bg-gray-700/50 p-2 sm:p-3 rounded-lg text-center">
                    <p class="text-[10px] sm:text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-0.5 sm:mb-1 truncate">Class</p>
                    <p class="text-sm sm:text-lg font-semibold ${data.rspamd.is_spam ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'}">
                        ${data.rspamd.is_spam ? 'SPAM' : 'CLEAN'}
                    </p>
                </div>
            </div>

            ${data.rspamd.symbols && Object.keys(data.rspamd.symbols).length > 0 ? `
                <div>
                    <div class="flex items-center justify-between mb-3">
                        <h4 class="text-md font-semibold text-gray-900 dark:text-white">Detection Symbols</h4>
                        <button data-hiding="1" onclick="toggleZeroSymbols(this)"
                            class="px-2.5 py-1 text-xs rounded border bg-blue-100 dark:bg-blue-500/10 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-500/20">Show zero scores</button>
                    </div>
                    <div class="space-y-2 max-h-[29rem] overflow-y-auto" id="spam-symbols-list">
                        ${Object.entries(data.rspamd.symbols)
                .sort((a, b) => {
                    const scoreA = a[1].score || a[1].metric_score || 0;
                    const scoreB = b[1].score || b[1].metric_score || 0;
                    if (scoreA === 0 && scoreB !== 0) return 1;
                    if (scoreA !== 0 && scoreB === 0) return -1;
                    return Math.abs(scoreB) - Math.abs(scoreA);
                })
                .map(([name, details]) => {
                    const score = details.score || details.metric_score || 0;
                    const description = details.description || '';
                    const options = details.options || [];
                    const scoreClass = score > 0 ? 'text-red-600 dark:text-red-400' :
                        score < 0 ? 'text-green-600 dark:text-green-400' :
                            'text-gray-500 dark:text-gray-400';
                    return `
                                    <div data-zero-score="${score === 0 ? '1' : '0'}" class="flex items-start justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition${score === 0 ? ' hidden' : ''}">
                                        <div class="flex-1">
                                            <span class="text-sm font-semibold text-gray-900 dark:text-white">${name}</span>
                                            ${description ? `<p class="text-xs text-gray-600 dark:text-gray-400 mt-1">${escapeHtml(description)}</p>` : ''}
                                            ${options.length > 0 ? `<p class="text-xs font-mono text-blue-600 dark:text-blue-400 mt-1">${options.map(o => escapeHtml(o)).join(', ')}</p>` : ''}
                                        </div>
                                        <span class="ml-3 text-sm font-mono font-bold ${scoreClass}">${score > 0 ? '+' : ''}${score.toFixed(2)}</span>
                                    </div>
                                `;
                }).join('')}
                    </div>
                </div>
            ` : ''}
        </div>
    `;
}

// Hide or show the zero-score detection symbols in the Spam tab
function toggleZeroSymbols(button) {
    const hiding = button.dataset.hiding !== '1';
    button.dataset.hiding = hiding ? '1' : '0';
    button.textContent = hiding ? 'Show zero scores' : 'Hide zero scores';
    button.className = hiding
        ? 'px-2.5 py-1 text-xs rounded border bg-blue-100 dark:bg-blue-500/10 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-500/20'
        : 'px-2.5 py-1 text-xs rounded border bg-gray-100 dark:bg-gray-700/50 text-gray-600 dark:text-gray-300 border-gray-200 dark:border-gray-600';
    document.querySelectorAll('#spam-symbols-list > [data-zero-score="1"]').forEach(row => {
        row.classList.toggle('hidden', hiding);
    });
}

function renderNetfilterTab(content, data) {
    if (!data.netfilter || data.netfilter.length === 0) {
        content.innerHTML = `
            <div class="text-center py-12">
                <svg class="w-16 h-16 mx-auto text-gray-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                </svg>
                <p class="text-gray-500 dark:text-gray-400">No security events detected</p>
                <p class="text-xs text-gray-400 dark:text-gray-500 mt-2">This is good - no failed authentication attempts from this sender</p>
            </div>
        `;
        return;
    }

    content.innerHTML = `
        <div class="space-y-4">
            <div class="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
                <div class="flex items-start gap-3">
                    <svg class="w-5 h-5 text-yellow-600 dark:text-yellow-400 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
                    </svg>
                    <div>
                        <p class="text-sm font-medium text-yellow-900 dark:text-yellow-300">Security Events Detected</p>
                        <p class="text-xs text-yellow-800 dark:text-yellow-400 mt-1">${data.netfilter.length} authentication event(s) from the sender's IP within 1 hour of this message</p>
                    </div>
                </div>
            </div>

            <h3 class="text-lg font-semibold text-gray-900 dark:text-white">Related Security Events</h3>
            <div class="space-y-2">
                ${data.netfilter.map(log => `
                    <div class="p-3 bg-gray-50 dark:bg-gray-700/50 rounded">
                        <div class="flex justify-between items-start mb-2">
                            <div class="flex items-center gap-2">
                                <span class="text-xs font-mono text-gray-600 dark:text-gray-300">${formatTime(log.time)}</span>
                                <span class="text-xs font-mono font-semibold text-gray-900 dark:text-white">${copyableText(log.ip)}</span>
                            </div>
                            <span class="inline-block px-2 py-0.5 text-xs font-medium rounded ${getActionClass(log.action)}">${getActionLabel(log.action)}</span>
                        </div>
                        ${log.username ? `<p class="text-xs text-gray-700 dark:text-gray-300">User: ${copyableText(log.username)}</p>` : ''}
                        ${log.auth_method ? `<p class="text-xs text-gray-600 dark:text-gray-400">Method: ${log.auth_method}</p>` : ''}
                        ${log.attempts_left !== null ? `<p class="text-xs text-gray-600 dark:text-gray-400">Attempts remaining: ${log.attempts_left}</p>` : ''}
                        <p class="text-xs text-gray-500 dark:text-gray-400 mt-1 font-mono">${escapeHtml(log.message)}</p>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}

function updateSecurityTabIndicator(data) {
    const securityTab = document.getElementById('modal-tab-netfilter');
    if (!securityTab) return;

    const hasSecurityEvents = data.netfilter && data.netfilter.length > 0;
    const indicator = hasSecurityEvents ? '🔴' : '🟢';

    securityTab.innerHTML = `<span class="text-xs sm:text-sm font-medium">Security ${indicator}</span>`;
}

function closeMessageModal() {
    const modal = document.getElementById('message-modal');
    if (modal) {
        modal.classList.add('hidden');
        currentModalData = null;
        // Restore body scroll
        document.body.style.overflow = '';
        // Reset security tab indicator
        const securityTab = document.getElementById('modal-tab-netfilter');
        if (securityTab) {
            securityTab.innerHTML = '<span class="text-sm font-medium">Security</span>';
        }
    }
}

document.addEventListener('DOMContentLoaded', function () {
    const messageModal = document.getElementById('message-modal');
    if (messageModal) {
        messageModal.addEventListener('click', function (e) {
            // Close modal if clicking on the backdrop (not the content)
            if (e.target.id === 'message-modal') {
                closeMessageModal();
            }
        });

        // Prevent clicks inside modal content from closing
        const modalContent = messageModal.querySelector('.bg-white');
        if (modalContent) {
            modalContent.addEventListener('click', function (e) {
                e.stopPropagation();
            });
        }
    }

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            const modal = document.getElementById('message-modal');
            if (modal && !modal.classList.contains('hidden')) {
                closeMessageModal();
            }
        }
    });
});
