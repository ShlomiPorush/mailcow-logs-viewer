// Message details: state, rendering, entry points, and interactions.
// Loaded after app.js; uses authenticatedFetch, renderGeoIPInfo, and utils.js helpers.
//
// The same element (#message-modal) is shown in two ways: as a dialog over any
// page, or, on the Messages page of a wide screen, docked as a reading pane
// next to the list (#messages-reader). Every id and handler is the same in both.

// Modal state
let currentModalTab = 'overview';
let currentModalData = null;
let messageModalHome = null;

// =============================================================================
// DIALOG OR READING PANE
// =============================================================================

// The reading pane is used on the Messages page when the screen is wide enough
// for the list and the message side by side.
function messageReaderSlot() {
    if (typeof window.matchMedia !== 'function' || !window.matchMedia('(min-width: 1200px)').matches) return null;
    if (typeof currentTab === 'undefined' || currentTab !== 'messages') return null;
    return document.getElementById('messages-reader');
}

function placeMessageModal(modal) {
    const slot = messageReaderSlot();
    if (!modal.parentNode || typeof modal.parentNode.insertBefore !== 'function') return false;
    if (!messageModalHome) messageModalHome = { parent: modal.parentNode, next: modal.nextSibling };
    if (slot) {
        if (modal.parentNode !== slot) slot.appendChild(modal);
        modal.classList.add('ui-docked');
        return true;
    }
    if (modal.parentNode !== messageModalHome.parent) messageModalHome.parent.insertBefore(modal, messageModalHome.next);
    modal.classList.remove('ui-docked');
    return false;
}

function markSelectedMessageRow(correlationKey) {
    if (typeof document.querySelectorAll !== 'function') return;
    document.querySelectorAll('.ui-msg-item[data-key]').forEach(row => {
        const selected = row.dataset.key === correlationKey;
        row.classList[selected ? 'add' : 'remove']('is-selected');
    });
}

// =============================================================================
// MESSAGE DETAILS WITH TABS
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

    const docked = placeMessageModal(modal);
    // A dialog blocks the page behind it; the reading pane does not
    if (!docked) document.body.style.overflow = 'hidden';
    else markSelectedMessageRow(correlationKey);

    modal.classList.remove('hidden');
    content.innerHTML = '<div class="ui-loading"><div class="loading"></div><p>Loading...</p></div>';

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
        content.innerHTML = `<p class="ui-empty ui-text-fail">Failed to load message details: ${escapeHtml(error.message)}</p>`;
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
    return `<svg class="${sizeClasses}" width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"></path></svg>`;
}

// A labelled value in a facts grid
function mdFact(label, valueHtml, extra = '') {
    return `<div class="ui-md-fact${extra ? ` ${extra}` : ''}"><span>${label}</span><div>${valueHtml}</div></div>`;
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
        tone: ''
    },
    rejected: {
        icon: '✗',
        label: 'Rejected by Sieve',
        fallback: 'A Sieve rule refused this message and reported it back to the sender.',
        tone: 'fail'
    },
    failed: {
        icon: '!',
        label: 'Delivery to mailbox failed',
        fallback: 'Dovecot could not store this message.',
        tone: 'warn'
    },
    forwarded: {
        icon: '→',
        label: 'Forwarded by Sieve',
        fallback: 'A Sieve rule redirected this message.',
        tone: 'info'
    },
    stored: {
        icon: '✓',
        label: 'Stored in mailbox',
        fallback: 'Dovecot wrote this message to the mailbox.',
        tone: 'ok'
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
        <div class="ui-banner${verdict.tone ? ` ui-banner-${verdict.tone}` : ' ui-banner-muted'}">
            <span class="ui-md-verdict-icon" aria-hidden="true">${verdict.icon}</span>
            <div class="ui-md-verdict">Mailbox delivery: ${verdict.label}
                <p>${escapeHtml(getDovecotVerdictText(dovecot))}</p>
            </div>
        </div>
    `;
}

function renderDovecotTimelineRow(log) {
    return `
        <div class="ui-md-log">
            <div class="ui-md-log-head">
                <span class="ui-mono ui-muted">${formatTime(log.time)}</span>
                <span class="ui-tag ui-tag-spam">dovecot</span>
                ${log.recipient ? `<span class="ui-muted">=> ${escapeHtml(log.recipient)}</span>` : ''}
                ${log.verdict && DOVECOT_VERDICTS[log.verdict] ? `<span class="ui-md-log-status">${uiTag(log.verdict, UI_STATUS_TONE[log.verdict === 'stored' ? 'delivered' : log.verdict])}</span>` : ''}
            </div>
            <p class="ui-md-log-msg">${escapeHtml(log.message || '')}</p>
        </div>
    `;
}

function renderPostfixTimelineRow(log) {
    return `
        <div class="ui-md-log">
            <div class="ui-md-log-head">
                <span class="ui-mono ui-muted">${formatTime(log.time)}</span>
                ${log.program ? `<span class="ui-tag ui-tag-info">${escapeHtml(log.program)}</span>` : ''}
                ${log.recipient ? `<span class="ui-muted">=> ${escapeHtml(log.recipient)}</span>` : ''}
                ${log.status ? `<span class="ui-md-log-status">${uiStatusTag(log.status)}</span>` : ''}
            </div>
            <p class="ui-md-log-msg">${escapeHtml(log.message)}</p>
            ${log.relay ? `<p class="ui-md-log-note">Relay: ${escapeHtml(log.relay)}</p>` : ''}
            ${log.delay ? `<p class="ui-md-log-note">Delay: ${log.delay.toFixed(2)}s</p>` : ''}
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
        <div class="ui-chip-row" id="log-timeline-filters">
            <button data-source="" onclick="filterLogTimeline(this)" class="ui-chip" aria-pressed="true">All</button>
            ${sources.map(s => `
                <button data-source="${escapeHtml(s)}" onclick="filterLogTimeline(this)" class="ui-chip" aria-pressed="false">${escapeHtml(s)}</button>
            `).join('')}
        </div>
    ` : '';

    return `
        <div class="ui-md-timeline">
            <div class="ui-md-timeline-head">
                <h4 class="ui-md-h">Complete Log Timeline <span class="ui-muted" id="log-timeline-count">${entries.length} entries</span></h4>
                ${filterBar}
            </div>
            <div class="ui-md-timeline-entries" id="log-timeline-entries">
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
        <section class="ui-md-card">
            <!-- Collapsed by default so several legs do not push the rest of
                 the overview down; the summary line already tells the story -->
            <div class="ui-md-toggle" onclick="toggleDeliveryJourney()">
                <div>
                    <h4 class="ui-md-h">Delivery journey</h4>
                    <p class="ui-muted">This message passed through the server ${legs.length} times: ${statusSummary}.</p>
                </div>
                <svg id="delivery-journey-chevron" width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                </svg>
            </div>
            <div class="ui-md-legs hidden" id="delivery-journey-legs">
                ${legs.map((leg, i) => `
                    <div class="ui-md-leg${leg.current ? ' is-current' : ''}"
                        ${leg.current ? '' : `onclick="viewMessageDetails('${escapeHtml(leg.correlation_key)}')"`}>
                        <span class="ui-muted">${i + 1}.</span>
                        <span class="ui-md-leg-who">${escapeHtml(leg.sender || '-')} =&gt; ${escapeHtml(leg.recipient || '-')}</span>
                        ${leg.current ? '<span class="ui-tag ui-tag-info">viewing</span>' : ''}
                        <span class="ui-md-leg-meta">
                            ${leg.final_status
                                ? uiStatusTag(leg.final_status)
                                : '<span class="ui-tag" title="This delivery attempt never reached a final outcome">no final status</span>'}
                            ${leg.dovecot_status === 'stored' && leg.dovecot_mailbox ? `<span class="ui-tag ui-tag-warn ui-md-folder">${folderIconSvg('ui-md-folder-icon')}${escapeHtml(leg.dovecot_mailbox)}</span>` : ''}
                            <span class="ui-mono ui-muted">${formatTime(leg.first_seen)}</span>
                        </span>
                    </div>
                `).join('')}
            </div>
        </section>
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
    document.querySelectorAll('#log-timeline-filters button').forEach(b => {
        b.setAttribute('aria-pressed', String(b === button));
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

    let recipientsFact = '';
    if (recipientsToDisplay.length > 1) {
        recipientsFact = mdFact(`Recipients (${recipientsToDisplay.length})`,
            `<div class="ui-md-recipients">${recipientsToDisplay.map(r => `<div>${copyableText(r)}</div>`).join('')}</div>`, 'ui-md-fact-wide');
    } else if (recipientsToDisplay.length === 1) {
        recipientsFact = mdFact('To', copyableText(recipientsToDisplay[0] || '-'));
    } else if (data.recipient) {
        recipientsFact = mdFact('To', copyableText(data.recipient));
    }

    const statusTags = data.final_status || data.direction ? `
        <div class="ui-md-tags">
            ${data.final_status ? uiStatusTag(data.final_status) : ''}
            ${data.direction ? uiDirectionTag(data.direction) : ''}
            ${data.dovecot && data.dovecot.status === 'stored' && data.dovecot.mailbox ? `<span class="ui-tag ui-tag-warn ui-md-folder">${folderIconSvg('ui-md-folder-icon')}${escapeHtml(data.dovecot.mailbox)}</span>` : ''}
        </div>` : '';

    const hasSubject = data.subject && data.subject !== 'Postfix Log Details';

    content.innerHTML = `
        <div class="ui-md-fill">
            <div class="ui-md-stack">
                <section class="ui-md-card">
                    <h3 class="ui-md-title">Message Overview</h3>
                    ${hasSubject ? `<p class="ui-md-subject" dir="auto" title="${escapeHtml(data.subject)}">${escapeHtml(data.subject)}</p>` : ''}
                    ${statusTags}
                    <div class="ui-md-facts">
                        ${mdFact('From', copyableText(data.sender || '-'))}
                        ${recipientsFact}
                        ${data.queue_id ? mdFact('Queue ID', `<span class="ui-mono">${copyableText(data.queue_id)}</span>`) : ''}
                        ${data.message_id ? mdFact('Message ID', `<span class="ui-mono" title="${escapeHtml(data.message_id)}">${copyableText(data.message_id)}</span>`, 'ui-md-fact-wide') : ''}
                    </div>
                </section>
                ${renderRelatedDeliveries(data)}
                ${renderDovecotSummary(data.dovecot)}
                ${data.rspamd ? `
                    <section class="ui-md-card ui-md-clickable" onclick="switchModalTab('spam')">
                        <div class="ui-md-card-head">
                            <h4 class="ui-md-h">Quick Spam Summary</h4>
                            <span class="ui-muted">See "Spam Analysis" tab for details</span>
                        </div>
                        <div class="ui-md-figures">
                            <div><b class="${data.rspamd.score >= (data.rspamd.required_score || 15) ? 'ui-text-fail' : 'ui-text-ok'}">${data.rspamd.score.toFixed(2)}</b><span>Score</span></div>
                            <div><b>${escapeHtml(String(data.rspamd.action))}</b><span>Action</span></div>
                            <div><b class="${data.rspamd.is_spam ? 'ui-text-fail' : 'ui-text-ok'}">${data.rspamd.is_spam ? 'SPAM' : 'CLEAN'}</b><span>Class</span></div>
                        </div>
                    </section>
                ` : data.postfix && data.postfix.length > 0 ? `
                    <div class="ui-banner">
                        <div>Postfix Delivery Logs
                            <p>Click "Logs" tab to see complete delivery timeline (${data.postfix.length} entries)</p>
                        </div>
                    </div>
                ` : ''}
            </div>
            ${data.rspamd ? `
                <div class="ui-md-footer">
                    <div class="ui-banner">
                        <div>Additional Details
                            <div class="ui-md-extra">
                                ${data.rspamd.ip ? renderGeoIPInfo(data.rspamd, '16x12') : ''}
                                ${data.rspamd.user ? `<p>Authenticated User: ${copyableText(data.rspamd.user)}</p>` : ''}
                                ${data.rspamd.size ? `<p>Message Size: ${formatSize(data.rspamd.size)}</p>` : ''}
                                ${data.rspamd.has_auth ? `<p>Authentication: Verified (MAILCOW_AUTH)</p>` : ''}
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
            <div class="ui-md-fill">
                <p class="ui-muted">No Postfix delivery logs available</p>
                ${renderLogTimeline([], dovecotLogs)}
            </div>
        ` : `
            <div class="ui-empty">
                <b>No Postfix delivery logs available</b>
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

    // Separate system logs from recipient logs
    const postfixByRecipient = data.postfix_by_recipient || {};
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
        <div class="ui-banner ui-banner-fail ui-md-errors">
            <div>Delivery Error
                <div class="ui-md-error-list">
                    ${dedupedErrors.map(err => `
                        <div class="ui-md-error">
                            ${err.recipient || err.count > 1 ? `
                                <div class="ui-md-tags">
                                    ${err.recipient ? `<b>${escapeHtml(err.recipient)}</b>` : ''}
                                    ${err.count > 1 ? `<span class="ui-tag ui-tag-fail">${err.count} attempts</span>` : ''}
                                </div>
                            ` : ''}
                            <p>${escapeHtml(err.reason)}</p>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    ` : '';

    let toFact = '';
    if (recipientsFromPostfix.size > 0) {
        toFact = mdFact(`To (${recipientsFromPostfix.size})`, recipientsFromPostfix.size === 1 ? copyableText(Array.from(recipientsFromPostfix)[0]) : `${recipientsFromPostfix.size} recipients`);
    } else if (data.recipients && data.recipients.length > 0) {
        toFact = mdFact(`To (${data.recipients.length})`, data.recipients.length === 1 ? copyableText(data.recipients[0]) : `${data.recipients.length} recipients`);
    }

    content.innerHTML = `
        <div class="ui-md-fill">
            ${errorSummaryHtml}
            <!-- Compact mail summary strip so the logs get the room. The
                 full details live in the Overview tab -->
            <div class="ui-md-facts ui-md-strip">
                ${sender ? mdFact('From', `<span title="${escapeHtml(sender)}">${copyableText(sender)}</span>`) : ''}
                ${toFact}
                ${finalStatus ? mdFact('Final Status', uiStatusTag(finalStatus)) : ''}
                ${queueId ? mdFact('Queue ID', `<span class="ui-mono">${copyableText(queueId)}</span>`) : ''}
                ${clientIp ? mdFact('Client IP', `<span class="ui-mono">${copyableText(clientIp)}</span>`) : ''}
                ${relay ? mdFact('Relay', `<span class="ui-mono" title="${escapeHtml(relay)}">${escapeHtml(relay)}</span>`) : ''}
            </div>

            <!-- Delivery Summary by Recipient (if multiple recipients) -->
            ${recipientEntries.length > 1 ? `
                <section>
                    <h4 class="ui-md-h">Delivery Summary by Recipient</h4>
                    <div class="ui-md-recipient-grid">
                        ${recipientEntries.map(([recipient, logs]) => {
        const statusLog = logs.find(l => l.status) || logs[0];
        return `
                                <div class="ui-md-card">
                                    <div class="ui-md-tags">
                                        <span class="ui-md-grow">${copyableText(recipient)}</span>
                                        ${statusLog.status ? uiStatusTag(statusLog.status) : ''}
                                    </div>
                                    ${statusLog.relay ? `<p class="ui-muted ui-md-truncate">via ${escapeHtml(statusLog.relay)}</p>` : ''}
                                </div>
                            `;
    }).join('')}
                    </div>
                </section>
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
            <div class="ui-empty">
                <b>No spam analysis data available</b>
            </div>
        `;
        return;
    }

    content.innerHTML = `
        <div class="ui-md-stack">
            <div class="ui-md-figures ui-md-card">
                <div><b class="${data.rspamd.score >= (data.rspamd.required_score || 15) ? 'ui-text-fail' : 'ui-text-ok'}">${data.rspamd.score.toFixed(2)}</b><span>Score</span><small>Limit: ${data.rspamd.required_score || 15}</small></div>
                <div><b>${escapeHtml(String(data.rspamd.action))}</b><span>Action</span></div>
                <div><b class="${data.rspamd.is_spam ? 'ui-text-fail' : 'ui-text-ok'}">${data.rspamd.is_spam ? 'SPAM' : 'CLEAN'}</b><span>Class</span></div>
            </div>

            ${data.rspamd.symbols && Object.keys(data.rspamd.symbols).length > 0 ? `
                <section>
                    <div class="ui-md-card-head">
                        <h4 class="ui-md-h">Detection Symbols</h4>
                        <button data-hiding="1" onclick="toggleZeroSymbols(this)" class="ui-chip" aria-pressed="false">Show zero scores</button>
                    </div>
                    <div class="ui-md-symbols" id="spam-symbols-list">
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
                    const scoreClass = score > 0 ? 'ui-text-fail' : score < 0 ? 'ui-text-ok' : 'ui-muted';
                    return `
                                    <div data-zero-score="${score === 0 ? '1' : '0'}" class="ui-md-symbol${score === 0 ? ' hidden' : ''}">
                                        <div class="ui-md-grow">
                                            <b>${escapeHtml(name)}</b>
                                            ${description ? `<p class="ui-muted">${escapeHtml(description)}</p>` : ''}
                                            ${options.length > 0 ? `<p class="ui-mono ui-md-options">${options.map(o => escapeHtml(o)).join(', ')}</p>` : ''}
                                        </div>
                                        <b class="ui-mono ${scoreClass}">${score > 0 ? '+' : ''}${score.toFixed(2)}</b>
                                    </div>
                                `;
                }).join('')}
                    </div>
                </section>
            ` : ''}
        </div>
    `;
}

// Hide or show the zero-score detection symbols in the Spam tab
function toggleZeroSymbols(button) {
    const hiding = button.dataset.hiding !== '1';
    button.dataset.hiding = hiding ? '1' : '0';
    button.textContent = hiding ? 'Show zero scores' : 'Hide zero scores';
    button.setAttribute('aria-pressed', String(!hiding));
    document.querySelectorAll('#spam-symbols-list > [data-zero-score="1"]').forEach(row => {
        row.classList.toggle('hidden', hiding);
    });
}

// Tone of a netfilter action tag (the label comes from getActionLabel)
function netfilterActionTone(action) {
    if (action === 'ban' || action === 'banned') return 'fail';
    if (action === 'unban') return 'ok';
    if (action === 'info') return 'info';
    return 'warn';
}

function renderNetfilterTab(content, data) {
    if (!data.netfilter || data.netfilter.length === 0) {
        content.innerHTML = `
            <div class="ui-empty">
                <b>No security events detected</b>
                This is good - no failed authentication attempts from this sender
            </div>
        `;
        return;
    }

    content.innerHTML = `
        <div class="ui-md-stack">
            <div class="ui-banner ui-banner-warn">
                <div>Security Events Detected
                    <p>${data.netfilter.length} authentication event(s) from the sender's IP within 1 hour of this message</p>
                </div>
            </div>

            <h3 class="ui-md-h">Related Security Events</h3>
            <div class="ui-md-stack-tight">
                ${data.netfilter.map(log => `
                    <div class="ui-md-log">
                        <div class="ui-md-log-head">
                            <span class="ui-mono ui-muted">${formatTime(log.time)}</span>
                            <b class="ui-mono">${copyableText(log.ip)}</b>
                            <span class="ui-md-log-status"><span class="ui-tag ui-tag-${netfilterActionTone(log.action)}">${getActionLabel(log.action)}</span></span>
                        </div>
                        ${log.username ? `<p>User: ${copyableText(log.username)}</p>` : ''}
                        ${log.auth_method ? `<p class="ui-muted">Method: ${escapeHtml(log.auth_method)}</p>` : ''}
                        ${log.attempts_left !== null ? `<p class="ui-muted">Attempts remaining: ${log.attempts_left}</p>` : ''}
                        <p class="ui-md-log-msg">${escapeHtml(log.message)}</p>
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

    securityTab.innerHTML = `<span>Security ${indicator}</span>`;
}

function closeMessageModal() {
    const modal = document.getElementById('message-modal');
    if (modal) {
        modal.classList.add('hidden');
        currentModalData = null;
        // Restore body scroll
        document.body.style.overflow = '';
        markSelectedMessageRow(null);
        // Reset security tab indicator
        const securityTab = document.getElementById('modal-tab-netfilter');
        if (securityTab) {
            securityTab.innerHTML = '<span>Security</span>';
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
        const modalContent = messageModal.querySelector('.ui-dialog');
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
