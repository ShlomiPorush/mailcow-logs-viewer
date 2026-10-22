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
    if (typeof window.matchMedia !== 'function' || !window.matchMedia('(min-width: 1000px)').matches) return null;
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
    // A dialog opens over every dialog already open (Block details opens a
    // message from its own dialog): the last one on the page is on top
    if (document.body && typeof document.body.appendChild === 'function') document.body.appendChild(modal);
    else if (modal.parentNode !== messageModalHome.parent) messageModalHome.parent.insertBefore(modal, messageModalHome.next);
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
        btn.setAttribute('aria-selected', 'false');
    });
    const activeTab = document.getElementById(`modal-tab-${tab}`);
    if (activeTab) {
        activeTab.classList.add('active');
        activeTab.setAttribute('aria-selected', 'true');
    } else {
        console.error('Modal tab button not found:', `modal-tab-${tab}`);
    }

    // Render content
    if (currentModalData) {
        renderModalTab(tab, currentModalData);
    } else {
        console.error('No modal data available');
    }

    // Scrolled past the header, the new tab starts right under the pinned tabs
    const body = document.getElementById('message-modal-body');
    const header = document.getElementById('message-modal-header');
    if (body && header && typeof header.offsetHeight === 'number' && body.scrollTop > header.offsetHeight) body.scrollTop = header.offsetHeight;
}

// The timeline's head sticks right under the tabs, whatever their height
function measureMessageTabs() {
    const body = document.getElementById('message-modal-body');
    const tabs = body && typeof body.querySelector === 'function' ? body.querySelector('.ui-tabs') : null;
    if (tabs && tabs.offsetHeight && body.style && typeof body.style.setProperty === 'function') {
        body.style.setProperty('--ui-md-tabs-h', `${tabs.offsetHeight}px`);
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
    window.openMessageKey = correlationKey;
    const header = document.getElementById('message-modal-header');
    if (header) header.innerHTML = '';
    // Each message opens at its top, not where the one before was scrolled to
    const body = document.getElementById('message-modal-body');
    if (body) body.scrollTop = 0;
    content.innerHTML = '<div class="ui-loading" role="status"><div class="loading"></div><p>Loading...</p></div>';

    try {
        const response = await authenticatedFetch(`/api/message/${encodeURIComponent(correlationKey)}/details`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('Message details loaded:', data);

        currentModalData = data;
        currentModalTab = 'overview';
        mdRecipients = messageRecipients(data);
        mdOwners = mdAddressOwners(data);
        Object.assign(mdView, { status: '', query: '', all: false, picked: -1, source: '' });
        if (typeof uiPickers !== 'undefined') delete uiPickers.query['md-rcpt-pick'];

        renderMessageHeader(data);
        measureMessageTabs();

        // Update Security tab indicator
        updateSecurityTabIndicator(data);

        // Hide Security tab if netfilter feature is disabled
        const netfilterTab = document.getElementById('modal-tab-netfilter');
        if (netfilterTab) {
            netfilterTab.style.display = window.disabledFeatures.includes('netfilter') ? 'none' : '';
        }

        document.querySelectorAll('[id^="modal-tab-"]').forEach(btn => {
            btn.classList.remove('active');
            btn.setAttribute('aria-selected', 'false');
        });
        const overviewTab = document.getElementById('modal-tab-overview');
        if (overviewTab) {
            overviewTab.classList.add('active');
            overviewTab.setAttribute('aria-selected', 'true');
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
// One Identifiers row: the label on the left, the value (and a note) on the right
function mdIdRow(label, valueHtml, noteHtml = '') {
    return `<div class="ui-md-idrow"><dt>${label}</dt><dd><span class="ui-md-idval">${valueHtml}</span>${noteHtml ? `<small>${noteHtml}</small>` : ''}</dd></div>`;
}

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

// With one recipient picked, a line logged for no recipient in particular
// belongs to every recipient: it stays, dimmed and marked
const MD_SHARED_TAG = '<span class="ui-tag ui-tag-line">All recipients</span>';

function renderDovecotTimelineRow(log, shared = false) {
    return `
        <div class="ui-md-log${shared ? ' is-shared' : ''}">
            <div class="ui-md-log-head">
                <span class="ui-mono ui-muted">${formatTime(log.time)}</span>
                <span class="ui-tag ui-tag-spam">dovecot</span>${shared ? MD_SHARED_TAG : ''}
                ${log.recipient ? `<span class="ui-muted">=> ${escapeHtml(log.recipient)}</span>` : ''}
                ${log.verdict && DOVECOT_VERDICTS[log.verdict] ? `<span class="ui-md-log-status">${uiTag(log.verdict, UI_STATUS_TONE[log.verdict === 'stored' ? 'delivered' : log.verdict])}</span>` : ''}
            </div>
            <p class="ui-md-log-msg">${escapeHtml(log.message || '')}</p>
        </div>
    `;
}

function renderPostfixTimelineRow(log, shared = false) {
    return `
        <div class="ui-md-log${shared ? ' is-shared' : ''}">
            <div class="ui-md-log-head">
                <span class="ui-mono ui-muted">${formatTime(log.time)}</span>
                ${log.program ? `<span class="ui-tag ui-tag-info">${escapeHtml(log.program)}</span>` : ''}${shared ? MD_SHARED_TAG : ''}
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
            <button type="button" data-source="" data-md-focus="source-" onclick="filterLogTimeline(this)" class="ui-chip" aria-pressed="${!mdView.source}">All</button>
            ${sources.map(s => `
                <button type="button" data-source="${escapeHtml(s)}" data-md-focus="source-${escapeHtml(s)}" onclick="filterLogTimeline(this)" class="ui-chip" aria-pressed="${mdView.source === s}">${escapeHtml(s)}</button>
            `).join('')}
        </div>
    ` : '';

    // One source, and for a message to many one recipient: its own lines and
    // the ones every recipient shares
    const picked = mdRecipients.length > 1 && mdView.picked >= 0 ? mdRecipients[mdView.picked] : null;
    // A line counts for the address the sender wrote (an alias), Dovecot's
    // lines through the mailbox they name
    const lineFor = e => {
        if (!e.log.recipient) return '';
        const key = mdAddressKey(e.dovecot ? e.log.recipient : mdLineAddress(e.log));
        return e.dovecot ? (mdOwners.get(key) || key) : key;
    };
    const shown = entries.filter(e => (!mdView.source || timelineSource(e) === mdView.source)
        && (!picked || !lineFor(e) || lineFor(e) === picked.key));
    const own = picked ? shown.filter(e => lineFor(e) === picked.key).length : 0;
    const count = picked ? `${own} for this recipient, ${shown.length - own} shared`
        : shown.length === entries.length ? `${entries.length} entries` : `${shown.length} of ${entries.length} entries`;
    const picker = mdRecipients.length > 1 ? `
        ${uiPicker({
            id: 'md-rcpt-pick', label: 'Recipient', set: !!picked, search: 'Find a recipient', panelLabel: 'Show the logs of',
            value: picked ? `<bdi>${escapeHtml(picked.address)}</bdi>` : 'All recipients',
            options: [{ label: 'All recipients', value: -1, selected: !picked, onclick: 'pickMessageRecipient(-1)' }]
                .concat(mdRecipients.map((r, i) => ({ label: r.address, hint: mdStatusInfo(r.status).word, value: i, selected: mdView.picked === i, onclick: `pickMessageRecipient(${i})` }))),
        })}
        ${picked ? `<button type="button" class="ui-icon-btn ui-icon-btn-sm" onclick="pickMessageRecipient(-1)" title="Show every recipient" aria-label="Show every recipient"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>` : ''}` : '';

    return `
        <div class="ui-md-timeline" id="md-timeline">
            <div class="ui-md-timeline-head">
                <h4 class="ui-md-h">Complete Log Timeline <span class="ui-muted" id="log-timeline-count">${count}</span></h4>
                <div class="ui-md-timeline-tools">${picker}${filterBar}</div>
            </div>
            <div class="ui-md-timeline-entries" id="log-timeline-entries">
                ${shown.length ? shown.map(e => {
                    const shared = !!picked && !lineFor(e);
                    return `<div data-log-source="${escapeHtml(timelineSource(e))}">${e.dovecot ? renderDovecotTimelineRow(e.log, shared) : renderPostfixTimelineRow(e.log, shared)}</div>`;
                }).join('') : '<p class="ui-muted">No log lines for this filter</p>'}
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
            <div class="ui-md-toggle" role="button" tabindex="0" data-row-open aria-expanded="false" aria-controls="delivery-journey-legs" onclick="if (!uiRowHeld(event)) toggleDeliveryJourney()">
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
                        ${leg.current ? 'aria-current="true"' : `role="button" tabindex="0" data-row-open onclick="if (!uiRowHeld(event)) viewMessageDetails('${escapeJsArg(leg.correlation_key)}')"`}>
                        <span class="ui-muted">${i + 1}.</span>
                        <span class="ui-md-leg-who">${escapeHtml(leg.sender || '-')} =&gt; ${escapeHtml(leg.recipient || '-')}</span>
                        ${leg.current ? '<span class="ui-tag ui-tag-info">viewing</span>' : ''}
                        <span class="ui-md-leg-meta">
                            <span class="ui-mono ui-muted ui-md-leg-time">${formatTime(leg.first_seen)}</span>
                            ${leg.final_status
                                ? uiStatusTag(leg.final_status)
                                : '<span class="ui-tag" title="This delivery attempt never reached a final outcome">no final status</span>'}
                            ${leg.dovecot_status === 'stored' && leg.dovecot_mailbox ? `<span class="ui-tag ui-tag-warn ui-md-folder">${folderIconSvg('ui-md-folder-icon')}${escapeHtml(leg.dovecot_mailbox)}</span>` : ''}
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
    mdView.source = button.dataset.source || '';
    mdRedrawTimeline();
}

function toggleDeliveryJourney() {
    const legs = document.getElementById('delivery-journey-legs');
    const chevron = document.getElementById('delivery-journey-chevron');
    const open = legs.classList.toggle('hidden');
    if (chevron) chevron.style.transform = open ? '' : 'rotate(180deg)';
    document.querySelector('.ui-md-toggle[aria-controls="delivery-journey-legs"]')?.setAttribute('aria-expanded', String(!open));
}

// =============================================================================
// READING PANE HEADER AND "WHAT HAPPENED"
// =============================================================================

// Host part of a Postfix relay such as "mx.example.com[192.0.2.1]:25"
function relayHost(relay) {
    if (!relay) return '';
    const host = String(relay).split('[')[0];
    return host === 'none' ? '' : host;
}

// =============================================================================
// RECIPIENTS OF A MESSAGE TO MANY (issue #476)
// =============================================================================

// The recipients of the open message, and what the Logs tab shows of them:
// a status filter, a search, the whole list or its first rows, the recipient
// whose lines the timeline shows (-1: all) and the timeline's source
let mdRecipients = [];
let mdOwners = new Map();
const mdView = { status: '', query: '', all: false, picked: -1, source: '' };
const MD_RCPT_ROWS = 6;

// Postfix's status of one recipient: its word, the word after a count, its tone,
// and its place in the list (problems first)
const MD_RCPT_STATUS = {
    bounced: { word: 'Bounced', many: 'bounced', tone: 'fail', rank: 0 },
    rejected: { word: 'Rejected', many: 'rejected', tone: 'fail', rank: 0 },
    expired: { word: 'Expired', many: 'expired', tone: 'fail', rank: 0 },
    deferred: { word: 'Deferred', many: 'deferred', tone: 'warn', rank: 1 },
    none: { word: 'Not logged', many: 'not logged yet', tone: '', rank: 2 },
    sent: { word: 'Delivered', many: 'delivered', tone: 'ok', rank: 3 },
};

function mdStatusInfo(status) {
    if (MD_RCPT_STATUS[status]) return MD_RCPT_STATUS[status];
    const word = String(status);
    return { word: word.charAt(0).toUpperCase() + word.slice(1), many: word, tone: 'info', rank: 1 };
}

// What the remote server or Postfix said about a delivery that did not go through
function mdFailureReason(log) {
    const message = (log && log.message) || '';
    const said = message.match(/said:\s*(.+?)(?:\s*\(in reply|$)/i);
    if (said) return said[1].trim();
    const paren = message.match(/status=\w+\s*\((.+?)\)$/);
    return paren ? paren[1].trim() : '';
}

const mdAddressKey = address => String(address || '').trim().toLowerCase();

// The address the sender wrote for one Postfix delivery line: orig_to when
// Postfix expanded an alias or a forward, else the address it delivered to.
// Read only from the fixed start of the line, as the server parses it
// (correlation.py): an address cannot supply it.
const MD_PF_ADDR = '(?:"(?:[^"\\\\]|\\\\.)*"|[^>"])*';
const MD_ORIG_TO_RE = new RegExp(`^[0-9A-F]+: to=<${MD_PF_ADDR}>, orig_to=<(${MD_PF_ADDR})>, `);
function mdLineAddress(log) {
    const orig = String(log.message || '').match(MD_ORIG_TO_RE);
    return (orig && orig[1]) || log.recipient || '';
}

// Which written address each delivered address belongs to (alias -> mailbox)
function mdAddressOwners(data) {
    const owners = new Map();
    (data.postfix || []).forEach(log => {
        if (log.recipient) owners.set(mdAddressKey(log.recipient), mdAddressKey(mdLineAddress(log)));
    });
    return owners;
}

// Dovecot's verdict for one recipient, as the server resolves a delivery
// (resolve_session_verdicts): a store cancels a pending discard ("discarded if
// not explicitly delivered"), and the most severe definite verdict wins. The
// pending marker is told by the end of its line, which Dovecot writes.
const MD_DOVECOT_SEVERITY = { stored: 0, forwarded: 1, failed: 2, discarded: 3, rejected: 4 };
const MD_DISCARD_MARK_RE = /: marked message to be discarded[^<>:]*$/i;
function mdMailboxVerdict(lines) {
    const marker = log => log.verdict === 'discarded' && MD_DISCARD_MARK_RE.test(String(log.message || ''));
    const definite = lines.filter(log => MD_DOVECOT_SEVERITY[log.verdict] !== undefined && !marker(log));
    if (definite.length) {
        return definite.reduce((a, log) => {
            const s = MD_DOVECOT_SEVERITY[log.verdict], sa = MD_DOVECOT_SEVERITY[a.verdict];
            return s > sa || (s === sa && (log.time || '') >= (a.time || '')) ? log : a;
        }).verdict;
    }
    return lines.some(marker) ? 'discarded' : null;
}

// Every recipient with the outcome of its own delivery: the recipients Rspamd
// saw, in their order, then any address only Postfix logged. A delivery to an
// alias counts for the alias, with the mailboxes it reached. The outcome is the
// last status Postfix logged for the address (for an alias, its worst mailbox);
// none yet reads as "not logged", and a message that expired in the queue
// expires every recipient still waiting.
function messageRecipients(data) {
    const byKey = new Map();
    const add = address => {
        const key = mdAddressKey(address);
        if (!key) return null;
        if (!byKey.has(key)) byKey.set(key, { address: String(address).trim(), key, logs: [], dovecot: [] });
        return byKey.get(key);
    };
    const owners = mdAddressOwners(data);
    const written = new Set(owners.values());
    // A mailbox an alias expanded to is not a recipient of its own
    const expanded = new Set([...owners].filter(([to, owner]) => to !== owner).map(([to]) => to));
    (data.recipients || []).forEach(address => {
        const key = mdAddressKey(address);
        if (!expanded.has(key) || written.has(key)) add(address);
    });
    (data.postfix || []).forEach(log => { if (log.recipient) add(mdLineAddress(log)).logs.push(log); });
    if (!byKey.size && data.recipient) add(data.recipient);
    ((data.dovecot && data.dovecot.logs) || []).forEach(log => {
        const key = mdAddressKey(log.recipient);
        const recipient = byKey.get(owners.get(key) || key);
        if (recipient) recipient.dovecot.push(log);
    });
    const expiry = (data.postfix || []).filter(log => !log.recipient && String(log.status || '').toLowerCase() === 'expired').length > 0;
    const rank = status => mdStatusInfo(status).rank;
    return [...byKey.values()].map(r => {
        // Per mailbox reached (one, unless an alias expanded): its last status
        const reached = new Map();
        r.logs.filter(log => log.status).forEach(log => {
            const to = mdAddressKey(log.recipient);
            const seen = reached.get(to) || { address: log.recipient, attempts: 0, last: null };
            seen.attempts += 1;
            if (!seen.last || (log.time || '') >= (seen.last.time || '')) seen.last = log;
            reached.set(to, seen);
        });
        const statusOf = log => { const raw = String(log.status).toLowerCase(); return raw === 'delivered' ? 'sent' : raw === 'reject' ? 'rejected' : raw; };
        const worst = [...reached.values()].reduce((a, t) => (!a || rank(statusOf(t.last)) < rank(statusOf(a.last))
            || (rank(statusOf(t.last)) === rank(statusOf(a.last)) && (t.last.time || '') >= (a.last.time || '')) ? t : a), null);
        const last = worst ? worst.last : null;
        let status = last ? statusOf(last) : 'none';
        if (expiry && (status === 'deferred' || status === 'none')) status = 'expired';
        // Postfix handed it to Dovecot, which may still have dropped it
        const mailbox = mdMailboxVerdict(r.dovecot);
        const reason = last && status !== 'sent' ? mdFailureReason(last)
            : status === 'sent' && mailbox && mailbox !== 'stored' ? `Mailbox delivery: ${DOVECOT_VERDICTS[mailbox].label}` : '';
        const delivered = [...reached.keys()].filter(to => to !== r.key).map(to => reached.get(to).address);
        return { ...r, status, last, attempts: worst ? worst.attempts : 0, relay: last ? last.relay : '', reason, delivered };
    });
}

function mdStatusCounts(recipients) {
    const counts = {};
    recipients.forEach(r => { counts[r.status] = (counts[r.status] || 0) + 1; });
    return counts;
}

// The statuses present, in list order, each with its count
function mdStatusList(recipients) {
    const counts = mdStatusCounts(recipients);
    return Object.keys(counts)
        .sort((a, b) => mdStatusInfo(a).rank - mdStatusInfo(b).rank || a.localeCompare(b))
        .map(status => ({ status, count: counts[status], ...mdStatusInfo(status) }));
}

// The outcome of a message to many in one sentence: how many got it. None when
// nothing is logged per recipient yet, or the message as a whole was stopped.
function recipientsVerdict(data, recipients) {
    if (recipients.length < 2 || ['rejected', 'spam', 'discarded'].includes(data.final_status)) return null;
    const counts = mdStatusCounts(recipients);
    const n = recipients.length;
    if ((counts.none || 0) === n) return null;
    const delivered = counts.sent || 0;
    if (delivered === n) return { tone: 'ok', text: `Delivered to all ${n} recipients` };
    if (delivered) return { tone: 'warn', text: `Delivered to ${delivered} of ${n} recipients` };
    const waiting = counts.deferred || counts.none;
    const failed = recipients.some(r => mdStatusInfo(r.status).tone === 'fail');
    return { tone: failed ? 'fail' : 'warn', text: waiting ? `Not delivered yet to any of the ${n} recipients` : `Not delivered to any of the ${n} recipients` };
}

// The header's link, a status count and a "View" in What happened open the list
function showMessageRecipients(status) {
    Object.assign(mdView, { status: status || '', query: '', all: !status });
    switchModalTab('postfix');
    mdReveal('md-rcpts');
}

function mdReveal(id) {
    const el = document.getElementById(id);
    if (!el || typeof el.scrollIntoView !== 'function') return;
    if (typeof uiDialogSheetFull === 'function') uiDialogSheetFull(document.getElementById('message-modal'));
    el.scrollIntoView({ block: 'start', behavior: 'smooth' });
}

// Redraws part of the Logs tab, and gives the focus back to the control that
// had it (a redraw replaces it)
function mdRedraw(id, html) {
    const slot = document.getElementById(id);
    if (!slot) return;
    const active = document.activeElement;
    const focusKey = active && slot.contains && slot.contains(active) && active.dataset ? active.dataset.mdFocus : null;
    slot.innerHTML = html;
    if (focusKey && typeof slot.querySelectorAll === 'function') {
        const again = [...slot.querySelectorAll('[data-md-focus]')].find(el => el.dataset.mdFocus === focusKey);
        if (again) again.focus({ preventScroll: true });
    }
}

function mdRedrawRecipients() {
    mdRedraw('md-rcpt-results', renderRecipientRows());
}

function mdRedrawTimeline() {
    const data = currentModalData || {};
    mdRedraw('md-timeline-slot', renderLogTimeline(data.postfix, (data.dovecot && data.dovecot.logs) || []));
}

function searchMessageRecipients(query) {
    mdView.query = query;
    mdView.all = false;
    mdRedrawRecipients();
}

function filterMessageRecipients(status) {
    mdView.status = status;
    mdView.all = false;
    mdRedrawRecipients();
}

function moreMessageRecipients() {
    mdView.all = !mdView.all;
    mdRedrawRecipients();
}

// A row shows its recipient's lines in the timeline; a second click shows all
// again. The picker in the timeline's head sets the same (-1: all).
function pickMessageRecipient(index, toggle = false) {
    mdView.picked = toggle && mdView.picked === index ? -1 : index;
    mdRedrawRecipients();
    mdRedrawTimeline();
    if (mdView.picked >= 0) mdReveal('md-timeline');
}

function renderRecipientRows() {
    const query = mdView.query.trim().toLowerCase();
    const rows = mdRecipients.map((r, index) => ({ r, index }))
        .filter(({ r }) => (!mdView.status || r.status === mdView.status) && (!query || r.address.toLowerCase().includes(query)))
        .sort((a, b) => mdStatusInfo(a.r.status).rank - mdStatusInfo(b.r.status).rank || a.r.address.localeCompare(b.r.address));
    const shown = mdView.all ? rows : rows.slice(0, MD_RCPT_ROWS);
    const chip = (status, word, count) => `<button type="button" class="ui-chip" data-md-focus="status-${escapeHtml(status)}" aria-pressed="${mdView.status === status}" onclick="filterMessageRecipients('${escapeJsArg(status)}')">${escapeHtml(word)} <small>${count}</small></button>`;
    const row = ({ r, index }) => {
        const info = mdStatusInfo(r.status);
        const host = relayHost(r.relay);
        const sub = !r.last ? `<span>${r.status === 'none' ? 'No delivery logged yet' : 'No delivery attempt logged'}</span>`
            : `<span>${host ? `via ${escapeHtml(host)}` : escapeHtml(info.word)}</span>${r.delivered.length ? `<span>· to <bdi>${escapeHtml(r.delivered.join(', '))}</bdi></span>` : ''}${r.attempts > 1 ? `<span>· ${r.attempts} attempts</span>` : ''}${r.last.time ? `<span>· ${escapeHtml(formatTime(r.last.time))}</span>` : ''}`;
        return `
            <div class="ui-md-rrow" role="button" tabindex="0" data-row-open data-md-focus="row-${index}" aria-pressed="${mdView.picked === index}" title="Show the logs of ${escapeHtml(r.address)}" onclick="if (!uiRowHeld(event)) pickMessageRecipient(${index}, true)">
                <span class="ui-md-rrow-addr"><bdi>${escapeHtml(r.address)}</bdi></span>${uiTag(info.word, info.tone)}
                <span class="ui-md-rrow-sub">${sub}</span>
                ${r.reason ? `<span class="ui-md-rrow-why ${info.tone && info.tone !== 'ok' ? `ui-text-${info.tone}` : 'ui-muted'}">${escapeHtml(r.reason)}</span>` : ''}
            </div>`;
    };
    return `
        <div class="ui-chip-row">
            ${chip('', 'All', mdRecipients.length)}
            ${mdStatusList(mdRecipients).map(s => chip(s.status, s.word, s.count)).join('')}
        </div>
        <div class="ui-md-rlist">${shown.length ? shown.map(row).join('') : '<div class="ui-md-rnone">No recipient matches</div>'}</div>
        ${rows.length > MD_RCPT_ROWS ? `<button type="button" class="ui-btn ui-btn-sm ui-md-rmore" data-md-focus="more" onclick="moreMessageRecipients()">${mdView.all ? 'Show fewer' : `Show all ${rows.length}`}</button>` : ''}`;
}

function renderRecipientsSection() {
    if (mdRecipients.length < 2) return '';
    return `
        <section class="ui-md-rcpts" id="md-rcpts">
            <div class="ui-md-rcpts-head">
                <h4 class="ui-md-h">Recipients <span class="ui-muted">${mdRecipients.length}</span></h4>
                <input type="search" class="ui-input" placeholder="Find a recipient" aria-label="Find a recipient" autocomplete="off" spellcheck="false" value="${escapeHtml(mdView.query)}" oninput="searchMessageRecipients(this.value)">
            </div>
            <div class="ui-md-rcpts" id="md-rcpt-results">${renderRecipientRows()}</div>
        </section>`;
}

// The outcome of the message in one sentence, with its tone
function messageVerdict(data) {
    const status = data.final_status;
    const lastSent = (data.postfix || []).filter(l => l.status === 'sent').pop();
    const dovecot = data.dovecot || {};
    switch (status) {
        case 'delivered':
        case 'sent':
            if (dovecot.status === 'stored' && dovecot.mailbox) return { tone: 'ok', text: `Delivered to the folder "${dovecot.mailbox}"` };
            return { tone: 'ok', text: relayHost(lastSent && lastSent.relay) ? `Delivered to ${relayHost(lastSent.relay)}` : 'Delivered' };
        case 'deferred': return { tone: 'warn', text: 'Deferred, Postfix will try again' };
        case 'bounced': return { tone: 'fail', text: 'Bounced back to the sender' };
        case 'rejected': return { tone: 'fail', text: 'Rejected' };
        case 'spam': return { tone: 'spam', text: 'Marked as spam' };
        case 'discarded': return { tone: '', text: 'Discarded by a Sieve rule' };
        case 'expired': return { tone: '', text: 'Expired in the queue' };
        default:
            return data.is_complete === false ? { tone: 'info', text: 'In progress, waiting for Postfix logs' } : { tone: 'info', text: 'Linked' };
    }
}

// Subject, From/To/When and the outcome, above the tabs
function renderMessageHeader(data) {
    const header = document.getElementById('message-modal-header');
    if (!header) return;
    const recipients = (data.recipients && data.recipients.length) ? data.recipients : (data.recipient ? [data.recipient] : []);
    // A message to many: To stays one line, and the outcome counts recipients
    const all = messageRecipients(data);
    const many = all.length > 1;
    const counted = recipientsVerdict(data, all);
    const verdict = counted || messageVerdict(data);
    // Each status but Delivered, as a count that opens those recipients
    const tally = counted ? mdStatusList(all).filter(s => s.status !== 'sent') : [];
    const toHtml = many
        ? `<div class="ui-md-to"><span class="ui-md-to-list">${all.slice(0, 12).map(r => `<bdi>${escapeHtml(r.address)}</bdi>`).join(', ')}</span><button type="button" class="ui-md-link" onclick="showMessageRecipients('')">All ${all.length} recipients</button></div>`
        : copyableText(recipients[0] || '-');
    const facts = [];
    if (data.rspamd && data.rspamd.size) facts.push(formatSize(data.rspamd.size));
    if (data.direction) facts.push(data.direction);
    // The spam summary sits here, in view, and opens the Spam Analysis tab
    const r = data.rspamd;
    const spamHtml = r && typeof r.score === 'number' ? `
            <button type="button" class="ui-md-spam" onclick="switchModalTab('spam')" title="Open Spam Analysis">
                <span><small>Spam score</small><b class="${r.score >= (r.required_score || 15) ? 'ui-text-fail' : 'ui-text-ok'}">${r.score.toFixed(2)}</b></span>
                <span><small>Action</small><b>${escapeHtml(String(r.action || '-'))}</b></span>
                <span><small>Class</small><b class="${r.is_spam ? 'ui-text-fail' : 'ui-text-ok'}">${r.is_spam ? 'SPAM' : 'CLEAN'}</b></span>
                <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
            </button>` : '';
    const hasSubject = data.subject && data.subject !== 'Postfix Log Details';
    header.innerHTML = `
        <h2 class="ui-md-subject" dir="auto" title="${escapeHtml(hasSubject ? data.subject : 'No subject')}">${escapeHtml(hasSubject ? data.subject : 'No subject')}</h2>
        <div class="ui-md-who">
            <span>From</span><div>${copyableText(data.sender || '-')}</div>
            <span>${many ? `To (${all.length})` : 'To'}</span><div>${toHtml}</div>
            <span>When</span><div>${formatTime(data.first_seen)}</div>
        </div>
        <div class="ui-md-verdict-bar${verdict.tone ? ` ui-md-verdict-${verdict.tone}` : ''}">
            <div>${escapeHtml(verdict.text)}
            ${facts.length ? `<small>${escapeHtml(facts.join(', '))}</small>` : ''}
            ${tally.length ? `<div class="ui-md-tally">${tally.map(s => `<button type="button" class="ui-tag${s.tone ? ` ui-tag-${s.tone}` : ''}" onclick="showMessageRecipients('${escapeJsArg(s.status)}')">${s.count} ${escapeHtml(s.many)}</button>`).join('')}</div>` : ''}</div>
            ${spamHtml}
        </div>`;
}

// The delivery told as steps: received, scanned, queued, delivered or not,
// and what Dovecot did with it. Built from the same logs as the Logs tab.
function buildDeliverySteps(data) {
    const steps = [];
    const add = (time, tone, title, detail, html) => steps.push({ time: time || '', tone, title, detail, ...(html || {}) });
    // A message to many is told per outcome with its number of recipients, not
    // one step per delivery: 25 deliveries to one relay are not 25 attempts
    const recipients = messageRecipients(data);
    const many = recipients.length > 1;
    for (const log of data.postfix || []) {
        if (many && log.status && !/NOQUEUE: reject/i.test(log.message || '')) continue;
        const message = log.message || '';
        const program = log.program || 'postfix';
        if (/NOQUEUE: reject/i.test(message)) {
            add(log.time, 'fail', 'Rejected while receiving', program);
        } else if (/client=/.test(message) && /smtpd/.test(program)) {
            const ip = (message.match(/client=.*?\[([^\]]+)\]/) || [])[1];
            const user = (message.match(/sasl_username=(\S+)/) || [])[1];
            add(log.time, 'ok', ip ? `Received from ${ip}` : 'Received', `${program}${user ? `, authenticated as ${user}` : ''}`, {
                titleHtml: ip ? `Received from ${copyableText(ip)}` : '',
                detailHtml: `${escapeHtml(program)}${user ? `, authenticated as ${copyableText(user)}` : ''}`
            });
        } else if (/cleanup/.test(program) && /message-id=/.test(message)) {
            const qid = log.queue_id || data.queue_id;
            add(log.time, 'ok', qid ? `Queued as ${qid}` : 'Queued', program, { titleHtml: qid ? `Queued as ${copyableText(qid)}` : '' });
        } else if (log.status) {
            const target = relayHost(log.relay) || log.recipient || '';
            const detail = `status=${log.status}${log.dsn ? ` (${log.dsn})` : ''}`;
            if (log.status === 'sent') add(log.time, 'ok', target ? `Delivered to ${target}` : 'Delivered', detail, { titleHtml: target ? `Delivered to ${copyableText(target)}` : '' });
            else if (log.status === 'deferred') add(log.time, 'warn', target ? `Deferred for ${target}` : 'Deferred', detail);
            else if (log.status === 'bounced') add(log.time, 'fail', target ? `Bounced for ${target}` : 'Bounced', detail);
            else add(log.time, 'fail', `${log.status.charAt(0).toUpperCase()}${log.status.slice(1)}`, detail);
        }
    }
    if (many) {
        const plural = n => `${n} recipient${n === 1 ? '' : 's'}`;
        mdStatusList(recipients).forEach(group => {
            const list = recipients.filter(r => r.status === group.status);
            const time = list.map(r => (r.last && r.last.time) || '').sort().pop();
            let title = `${group.word} for ${plural(list.length)}`, detail = '';
            if (group.status === 'sent') {
                const hosts = [...new Set(list.map(r => relayHost(r.relay)).filter(Boolean))];
                title = `Delivered to ${plural(list.length)}`;
                detail = hosts.length === 1 ? `via ${hosts[0]}` : hosts.length ? `via ${hosts.length} servers` : '';
            } else if (group.status === 'deferred') {
                detail = 'Postfix will try again';
            } else if (group.status === 'none') {
                title = `${plural(list.length)} with no delivery logged yet`;
            }
            const view = `<button type="button" class="ui-md-link" onclick="showMessageRecipients('${escapeJsArg(group.status)}')">View</button>`;
            add(time || '9', group.tone || 'info', title, detail, { detailHtml: `${detail ? `${escapeHtml(detail)} ` : ''}${view}`, showTime: !!time });
        });
    }
    if (data.rspamd && typeof data.rspamd.score === 'number') {
        add(data.rspamd.time, data.rspamd.is_spam ? 'fail' : 'ok', `Rspamd score ${data.rspamd.score.toFixed(1)}`,
            data.rspamd.action || '');
    }
    const dovecot = data.dovecot;
    if (dovecot && dovecot.status && DOVECOT_VERDICTS[dovecot.status]) {
        const verdict = DOVECOT_VERDICTS[dovecot.status];
        const last = (dovecot.logs || []).slice(-1)[0];
        const handOver = (data.postfix || []).filter(log => log.status === 'sent' && /dovecot/i.test(log.relay || '')).slice(-1)[0];
        const time = last ? last.time : handOver ? handOver.time : '';
        add(time || '9', verdict.tone || 'warn', verdict.label, getDovecotVerdictText(dovecot), { showTime: !!time });
    }
    // Steps logged in the same second keep the order mail flows in
    const stage = step => /^(Rejected|Received)/.test(step.title) ? 0 : /^Queued/.test(step.title) ? 1 : /^Rspamd/.test(step.title) ? 2
        : /^(Delivered|Deferred|Bounced)/.test(step.title) ? 3 : 4;
    steps.sort((a, b) => (a.time < b.time ? -1 : a.time > b.time ? 1 : stage(a) - stage(b)));
    // A retry logs the same step again; one line with the number of attempts
    const merged = [];
    for (const step of steps) {
        const prev = merged[merged.length - 1];
        if (prev && prev.title === step.title) { prev.count = (prev.count || 1) + 1; prev.time = step.time; prev.detail = step.detail; prev.detailHtml = step.detailHtml; continue; }
        merged.push({ ...step });
    }
    return merged;
}

function renderDeliverySteps(data) {
    const steps = buildDeliverySteps(data);
    if (!steps.length) return '<p class="ui-muted">No delivery steps recorded yet.</p>';
    return `<ol class="ui-steps">${steps.map(step => `
        <li class="${step.tone ? `ui-step-${step.tone}` : ''}">
            ${step.time && step.time !== '9' && step.showTime !== false ? `<time class="ui-step-time" datetime="${escapeHtml(step.time)}">${escapeHtml(formatTime(step.time))}</time>` : ''}
            <b>${step.titleHtml || escapeHtml(step.title)}${step.count > 1 ? ` <span class="ui-tag">${step.count} attempts</span>` : ''}</b>
            <span>${step.detailHtml || escapeHtml(step.detail)}</span>
        </li>`).join('')}</ol>`;
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
    const recipientsToDisplay = recipientsFromPostfix.size > 0
        ? Array.from(recipientsFromPostfix)
        : (data.recipients || []);

    const rspamd = data.rspamd || {};
    // Where the client address is from: flag, country and city, network owner
    const geoNote = rspamd.country_code ? [
        getFlagUrl(rspamd.country_code, '16x12') ? `<img src="${getFlagUrl(rspamd.country_code, '16x12')}" alt="" width="16" height="12" onerror="this.style.display='none'">` : '',
        escapeHtml([rspamd.country_name, rspamd.city].filter(Boolean).join(', ')),
        rspamd.asn_org ? `<span class="ui-muted">· ${escapeHtml(rspamd.asn_org)}</span>` : ''
    ].filter(Boolean).join(' ') : '';
    // Who sent it first; the IDs, which are only copied, last
    const identifiers = [
        rspamd.ip ? mdIdRow('Client IP', `<span class="ui-mono">${copyableText(rspamd.ip)}</span>`, geoNote) : '',
        (rspamd.user && rspamd.user !== 'unknown') || rspamd.has_auth ? mdIdRow('Authenticated user',
            rspamd.user && rspamd.user !== 'unknown' ? copyableText(rspamd.user) : '<span class="ui-muted">Unknown user</span>', rspamd.has_auth ? 'Verified (MAILCOW_AUTH)' : '') : '',
        data.queue_id ? mdIdRow('Queue ID', `<span class="ui-mono">${copyableText(data.queue_id)}</span>`) : '',
        data.message_id ? mdIdRow('Message ID', `<span class="ui-mono">${copyableText(data.message_id)}</span>`) : '',

    ].join('');

    content.innerHTML = `
        <div class="ui-md-stack">
            <section>
                <h4 class="ui-md-h">What happened</h4>
                ${renderDeliverySteps(data)}
            </section>
            ${renderDovecotSummary(data.dovecot)}
            ${renderRelatedDeliveries(data)}
            ${identifiers ? `<section><h4 class="ui-md-h">Identifiers</h4><dl class="ui-md-idlist">${identifiers}</dl></section>` : ''}
        </div>
    `;
}

function renderPostfixTab(content, data) {
    // Dovecot handles the hop after Postfix, so its lines are part of the
    // same delivery timeline, interleaved by time and tagged per line.
    const dovecotLogs = (data.dovecot && data.dovecot.logs) ? data.dovecot.logs : [];

    if (!data.postfix || data.postfix.length === 0) {
        // The header and What happened link to the recipients: they are here too
        content.innerHTML = dovecotLogs.length ? `
            <div class="ui-md-fill">
                <p class="ui-muted">No Postfix delivery logs available</p>
                ${renderRecipientsSection()}
                <div id="md-timeline-slot">${renderLogTimeline([], dovecotLogs)}</div>
            </div>
        ` : `
            <div class="ui-md-fill">
                <div class="ui-empty">
                    <b>No Postfix delivery logs available</b>
                </div>
                ${renderRecipientsSection()}
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

    // Postfix's lines carry neither; the message has both
    sender = sender || data.sender || null;
    queueId = queueId || data.queue_id || null;

    // A message to many lists its recipients with their outcome and reason, so
    // the strip and the error box speak for a single recipient only
    const many = mdRecipients.length > 1;

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
    const errorSummaryHtml = dedupedErrors.length > 0 && !many ? `
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
    if (many) {
        // The Recipients list below names them all
    } else if (recipientsFromPostfix.size > 0) {
        toFact = mdFact(`To (${recipientsFromPostfix.size})`, recipientsFromPostfix.size === 1 ? copyableText(Array.from(recipientsFromPostfix)[0]) : `${recipientsFromPostfix.size} recipients`);
    } else if (data.recipients && data.recipients.length > 0) {
        toFact = mdFact(`To (${data.recipients.length})`, data.recipients.length === 1 ? copyableText(data.recipients[0]) : `${data.recipients.length} recipients`);
    }

    const stripFacts = [
        sender ? mdFact('From', `<span title="${escapeHtml(sender)}">${copyableText(sender)}</span>`) : '',
        toFact,
        finalStatus && !many ? mdFact('Final Status', uiStatusTag(finalStatus)) : '',
        queueId ? mdFact('Queue ID', `<span class="ui-mono">${copyableText(queueId)}</span>`) : '',
        clientIp ? mdFact('Client IP', `<span class="ui-mono">${copyableText(clientIp)}</span>`) : '',
        relay && !many ? mdFact('Relay', `<span class="ui-mono" title="${escapeHtml(relay)}">${escapeHtml(relay)}</span>`) : '',
    ].join('');

    content.innerHTML = `
        <div class="ui-md-fill">
            ${errorSummaryHtml}
            <!-- Compact mail summary strip so the logs get the room. The
                 full details live in the Overview tab -->
            ${stripFacts ? `<div class="ui-md-facts ui-md-strip">${stripFacts}</div>` : ''}

            ${renderRecipientsSection()}

            <!-- Complete Log Timeline: its head and filters stay under the tabs -->
            <div id="md-timeline-slot">${renderLogTimeline(data.postfix, dovecotLogs)}</div>
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
                <div><b class="${data.rspamd.score >= (data.rspamd.required_score || 15) ? 'ui-text-fail' : 'ui-text-ok'}">${Number(data.rspamd.score).toFixed(2)}</b><span>Score</span><small>Limit: ${escapeHtml(String(data.rspamd.required_score || 15))}</small></div>
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
                            <span class="ui-md-log-status">${uiActionTag(log.action)}</span>
                        </div>
                        ${log.username ? `<p>User: ${copyableText(log.username)}</p>` : ''}
                        ${log.auth_method ? `<p class="ui-muted">Method: ${escapeHtml(log.auth_method)}</p>` : ''}
                        ${log.attempts_left !== null ? `<p class="ui-muted">Attempts remaining: ${escapeHtml(String(log.attempts_left))}</p>` : ''}
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

    // A red count of the security events, as on the page tabs; none, no count
    const events = data.netfilter ? data.netfilter.length : 0;
    const indicator = events ? ` <span class="ui-tab-n is-fail" title="Security events">${events}</span>` : '';

    securityTab.innerHTML = `<span>Security</span>${indicator}`;
}

function closeMessageModal() {
    const modal = document.getElementById('message-modal');
    if (modal) {
        modal.classList.add('hidden');
        currentModalData = null;
        window.openMessageKey = null;
        // Restore body scroll
        document.body.style.overflow = '';
        markSelectedMessageRow(null);
        // Reset security tab indicator
        const securityTab = document.getElementById('modal-tab-netfilter');
        if (securityTab) {
            securityTab.innerHTML = '<span>Security</span>';
        }
        const header = document.getElementById('message-modal-header');
        if (header) header.innerHTML = '';
    }
}

document.addEventListener('DOMContentLoaded', function () {
    const messageModal = document.getElementById('message-modal');
    if (messageModal) {
        // Close modal if clicking on the backdrop (not the content). A click
        // inside goes on to the page's own handlers: the drop-downs in it
        // (uiPicker) open and close there
        messageModal.addEventListener('click', function (e) {
            if (uiBackdropClick(e)) {
                closeMessageModal();
            }
        });
    }

    // As a dialog the layers in router.js close it; docked beside the list,
    // Escape still closes it when no dialog is open
    document.addEventListener('keydown', function (e) {
        if (e.key !== 'Escape' || e.defaultPrevented) return;
        const modal = document.getElementById('message-modal');
        if (modal && modal.classList.contains('ui-docked') && !modal.classList.contains('hidden')
            && !(typeof openOverlays === 'function' && openOverlays().length)) {
            closeMessageModal();
        }
    });
});
