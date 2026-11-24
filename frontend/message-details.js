let currentModalTab = 'overview';
let currentModalData = null;
let messageModalHome = null;

function messageReaderSlot() {
    if (typeof window.matchMedia !== 'function' || !window.matchMedia('(min-width: 1000px)').matches) return null;
    if (typeof currentTab === 'undefined' || currentTab !== 'messages') return null;
    const card = document.getElementById('entity-card');
    if (card && !card.classList.contains('hidden')) return null;
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

function switchModalTab(tab) {
    console.log('Switching modal tab to:', tab);
    currentModalTab = tab;

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

    if (currentModalData) {
        renderModalTab(tab, currentModalData);
    } else {
        console.error('No modal data available');
    }

    const body = document.getElementById('message-modal-body');
    const header = document.getElementById('message-modal-header');
    if (body && header && typeof header.offsetHeight === 'number' && body.scrollTop > header.offsetHeight) body.scrollTop = header.offsetHeight;
}

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
    if (!docked) document.body.style.overflow = 'hidden';
    else markSelectedMessageRow(correlationKey);

    modal.classList.remove('hidden');
    window.openMessageKey = correlationKey;
    const header = document.getElementById('message-modal-header');
    if (header) header.innerHTML = '';
    const body = document.getElementById('message-modal-body');
    if (body) body.scrollTop = 0;
    content.innerHTML = '<div class="ui-loading" role="status"><div class="loading"></div><p>Loading...</p></div>';

    try {
        const response = await authenticatedFetch(`/api/message/${encodeURIComponent(correlationKey)}/details`);
        if (!response.ok) {
            throw await responseError(response);
        }

        const data = await response.json();
        if (window.openMessageKey !== correlationKey) return;
        console.log('Message details loaded:', data);

        currentModalData = data;
        currentModalTab = 'overview';
        mdRecipients = messageRecipients(data);
        mdOtherRecipients = messageRecipientsAll(data, mdRecipients).slice(mdRecipients.length);
        mdOwners = mdAddressOwners(data);
        Object.assign(mdView, { status: '', query: '', all: false, picked: -1, source: '' });
        if (typeof uiPickers !== 'undefined') delete uiPickers.query['md-rcpt-pick'];

        renderMessageHeader(data);
        measureMessageTabs();

        updateSecurityTabIndicator(data);

        const netfilterTab = document.getElementById('modal-tab-netfilter');
        if (netfilterTab) {
            netfilterTab.style.display = window.disabledFeatures.includes('netfilter') ? 'none' : '';
        }
        const spamTab = document.getElementById('modal-tab-spam');
        if (spamTab) spamTab.style.display = mdNoMessageId(data) ? 'none' : '';

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
        if (window.openMessageKey !== correlationKey) return;
        console.error('Failed to load message details:', error);
        content.innerHTML = `<p class="ui-empty ui-text-fail">Failed to load message details: ${escapeHtml(uiErrorText(error))}</p>`;
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

function mdIdRow(label, valueHtml, noteHtml = '') {
    return `<div class="ui-md-idrow"><dt>${label}</dt><dd><span class="ui-md-idval">${valueHtml}</span>${noteHtml ? `<small>${noteHtml}</small>` : ''}</dd></div>`;
}

function mdFact(label, valueHtml, extra = '') {
    return `<div class="ui-md-fact${extra ? ` ${extra}` : ''}"><span>${label}</span><div>${valueHtml}</div></div>`;
}

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

    const picked = mdRecipients.length > 1 && mdView.picked >= 0 ? mdRecipients[mdView.picked] : null;
    const query = mdView.query.trim();
    const listed = !picked && mdRecipients.length > 1 && (mdView.status || query)
        ? new Set(mdListedRecipients().map(({ r }) => r.key)) : null;
    const narrowed = !!(picked || listed);
    const ownersOf = e => mdLineOwners(e.log, e.dovecot);
    const ownLine = owners => (picked ? owners.includes(picked.key) : owners.some(key => listed.has(key)));
    const shown = entries.filter(e => (!mdView.source || timelineSource(e) === mdView.source)
        && (!narrowed || !ownersOf(e).length || ownLine(ownersOf(e))));
    const listName = listed ? `${[mdView.status ? mdStatusInfo(mdView.status).word : '', query ? `"${query}"` : ''].filter(Boolean).join(' ')} (${listed.size})` : '';
    const count = shown.length === entries.length ? `${entries.length} entries` : `${shown.length} of ${entries.length} entries`;
    const picker = mdRecipients.length > 1 ? `
        ${uiPicker({
            id: 'md-rcpt-pick', label: 'Recipient', set: narrowed, search: 'Find a recipient', panelLabel: 'Show the logs of', panelClass: 'ui-md-rcpt-panel', onOpen: 'mdRecipientPickerOpen',
            value: picked ? `<bdi>${escapeHtml(picked.address)}</bdi>` : listed ? `<bdi>${escapeHtml(listName)}</bdi>` : 'All recipients',
            options: [{ label: 'All recipients', value: -1, selected: !narrowed, onclick: 'pickMessageRecipient(-1)' }]
                .concat(mdRecipients.map((r, i) => ({ r, i })).sort((a, b) => mdRecipientOrder(a.r, b.r)).map(({ r, i }) => {
                    const status = mdStatusInfo(r.status);
                    return { label: r.address, hint: status.word, dot: status.tone, value: i, selected: mdView.picked === i, onclick: `pickMessageRecipient(${i})` };
                })),
        })}
        ${narrowed ? `<button type="button" class="ui-icon-btn ui-icon-btn-sm" onclick="pickMessageRecipient(-1)" title="Show every recipient" aria-label="Show every recipient"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>` : ''}` : '';

    return `
        <div class="ui-md-timeline" id="md-timeline">
            <div class="ui-md-timeline-head">
                <h4 class="ui-md-h">Complete Log Timeline <span class="ui-muted" id="log-timeline-count">${count}</span></h4>
                <div class="ui-md-timeline-tools">${picker}${filterBar}</div>
            </div>
            <div class="ui-md-timeline-entries" id="log-timeline-entries">
                ${shown.length ? shown.map(e => {
                    const shared = narrowed && !ownersOf(e).length;
                    return `<div data-log-source="${escapeHtml(timelineSource(e))}">${e.dovecot ? renderDovecotTimelineRow(e.log, shared) : renderPostfixTimelineRow(e.log, shared)}</div>`;
                }).join('') : '<p class="ui-muted">No log lines for this filter</p>'}
            </div>
        </div>
    `;
}

function renderRelatedDeliveries(data) {
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
                        ${leg.current ? 'aria-current="true"' : `onclick="if (!uiRowHeld(event)) viewMessageDetails('${escapeJsArg(leg.correlation_key)}')"`}>
                        ${leg.current ? `<span class="ui-muted">${i + 1}.</span>` : `<button type="button" class="ui-row-open ui-muted" aria-label="Open delivery ${i + 1}: ${escapeHtml(leg.sender || '-')} to ${escapeHtml(leg.recipient || '-')}">${i + 1}.</button>`}
                        <span class="ui-md-leg-who">${uiEntity('address', leg.sender || '-', { plain: true })} =&gt; ${uiEntity('address', leg.recipient || '-', { plain: true })}</span>
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
    return entry.dovecot ? 'dovecot' : 'postfix';
}

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

function relayHost(relay) {
    if (!relay) return '';
    const host = String(relay).split('[')[0];
    return host === 'none' ? '' : host;
}

function relayParts(relay) {
    const m = /^([^[\]]+)\[([^\]]+)\](?::(\d+))?$/.exec(String(relay || ''));
    return m ? { host: m[1], ip: m[2], port: m[3] || '' } : { host: String(relay || ''), ip: '', port: '' };
}

function renderRelay(relay, copy = true) {
    const { host, ip, port } = relayParts(relay);
    const named = ip && ip !== host;
    const name = host === 'none' || !copy ? `<bdi>${escapeHtml(host)}</bdi>` : copyableText(host).replace(' title="Click to copy"', '');
    const tip = named ? ` data-ip="${escapeHtml(ip)}" data-tip="IP ${escapeHtml(ip)}"` : '';
    return `<span class="ui-md-relay">
        <span class="ui-md-relay-host${ip && !named ? ' ui-mono' : ''}" data-host="${escapeHtml(host)}"${tip}${copy ? ' tabindex="0"' : ''} onpointerenter="mdRelayTipFit(this)" onfocus="mdRelayTipFit(this)" onpointerup="mdRelayTipTap(event, this)">${name}${named ? `<span class="ui-sr-only">, IP ${escapeHtml(ip)}</span>` : ''}</span>
        ${port ? `<span class="ui-md-relay-port">:${escapeHtml(port)}</span>` : ''}
    </span>`;
}

function mdRelayTipFit(el) {
    const name = el.querySelector('bdi');
    const cut = !!name && name.scrollWidth > name.clientWidth;
    const { host, ip } = el.dataset;
    const tip = cut ? (ip ? `${host} · IP ${ip}` : host) : (ip ? `IP ${ip}` : '');
    if (tip) el.dataset.tip = tip;
    else delete el.dataset.tip;
}

function mdRelayTipTap(event, el) {
    if (event.pointerType === 'mouse') return;
    mdRelayTipFit(el);
    if (!el.dataset.tip) return;
    el.classList.add('is-tip');
    clearTimeout(el.tipTimer);
    el.tipTimer = setTimeout(() => el.classList.remove('is-tip'), 2500);
    el.tapClick = true;
    clearTimeout(el.tapTimer);
    el.tapTimer = setTimeout(() => { el.tapClick = false; }, 600);
}

function mdRelayTapped(event) {
    const host = event.target && event.target.closest ? event.target.closest('.ui-md-relay-host') : null;
    if (!host || !host.tapClick || event.pointerType === 'mouse') return false;
    host.tapClick = false;
    return true;
}

function mdRelayTip(root) {
    root.querySelectorAll('.ui-md-relay-host').forEach(mdRelayTipFit);
}

let mdRecipients = [];
let mdOtherRecipients = [];
let mdOwners = new Map();
const mdView = { status: '', query: '', all: false, picked: -1, source: '' };
const MD_RCPT_ROWS = 6;

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

function mdFailureReason(log) {
    const message = (log && log.message) || '';
    const said = message.match(/said:\s*(.+?)(?:\s*\(in reply|$)/i);
    if (said) return said[1].trim();
    const paren = message.match(/status=\w+\s*\((.+?)\)$/);
    return paren ? paren[1].trim() : '';
}

const mdAddressKey = address => String(address || '').trim().toLowerCase();

const MD_PF_ADDR = '(?:"(?:[^"\\\\]|\\\\.)*"|[^>"])*';
const MD_ORIG_TO_RE = new RegExp(`^[0-9A-F]+: to=<${MD_PF_ADDR}>, orig_to=<(${MD_PF_ADDR})>, `);
function mdLineAddress(log) {
    const orig = String(log.message || '').match(MD_ORIG_TO_RE);
    return (orig && orig[1]) || log.recipient || '';
}

function mdAddressOwners(data) {
    const owners = new Map();
    (data.postfix || []).forEach(log => {
        if (!log.recipient) return;
        const to = mdAddressKey(log.recipient);
        if (!owners.has(to)) owners.set(to, new Set());
        owners.get(to).add(mdAddressKey(mdLineAddress(log)));
    });
    return owners;
}

function mdLineOwners(log, dovecot) {
    if (!log.recipient) return [];
    if (!dovecot) return [mdAddressKey(mdLineAddress(log))];
    const key = mdAddressKey(log.recipient);
    return [...(mdOwners.get(key) || [key])];
}

const MD_DOVECOT_SEVERITY = { stored: 0, forwarded: 1, failed: 2, discarded: 3, rejected: 4 };
const MD_DISCARD_MARK_RE = /: marked message to be discarded[^<>:]*$/i;
const MD_DOVECOT_PREFIX_RE = /^(?:dovecot:\s*)?(?:lmtp|lda)\(([^)]*)\)((?:<[^>]*>)*)/i;
function mdDovecotSession(log) {
    const ids = (String(log.message || '').trim().match(MD_DOVECOT_PREFIX_RE) || [])[2] || '';
    const sessions = ids.match(/<[^>]*>/g) || [];
    return sessions.length ? sessions[sessions.length - 1].slice(1, -1) : '';
}
function mdDeliveryVerdict(lines) {
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

function mdMailboxVerdict(lines) {
    const deliveries = new Map();
    lines.forEach(log => {
        const key = `${mdDovecotSession(log)}|${mdAddressKey(log.recipient)}`;
        if (!deliveries.has(key)) deliveries.set(key, []);
        deliveries.get(key).push(log);
    });
    return [...deliveries.values()].map(mdDeliveryVerdict).filter(Boolean)
        .reduce((a, v) => (!a || MD_DOVECOT_SEVERITY[v] > MD_DOVECOT_SEVERITY[a] ? v : a), null);
}

function messageRecipients(data) {
    const byKey = new Map();
    const add = address => {
        const key = mdAddressKey(address);
        if (!key) return null;
        if (!byKey.has(key)) byKey.set(key, { address: String(address).trim(), key, logs: [], dovecot: [] });
        return byKey.get(key);
    };
    const owners = mdAddressOwners(data);
    const written = new Set([...owners.values()].flatMap(set => [...set]));
    const expanded = new Set([...owners].filter(([to, set]) => !set.has(to)).map(([to]) => to));
    const listed = (data.recipients || []).map(mdAddressKey);
    const deliveredTo = new Set((data.postfix || []).filter(log => log.recipient).map(log => mdAddressKey(log.recipient)));
    const listedSet = new Set(listed);
    const fromPostfix = listedSet.size > 0 && listedSet.size === deliveredTo.size && [...listedSet].every(key => deliveredTo.has(key));
    (data.recipients || []).forEach(address => {
        const key = mdAddressKey(address);
        if (!fromPostfix || !expanded.has(key) || written.has(key)) add(address);
    });
    (data.postfix || []).forEach(log => { if (log.recipient) add(mdLineAddress(log)).logs.push(log); });
    if (!byKey.size && data.recipient) add(data.recipient);
    ((data.dovecot && data.dovecot.logs) || []).forEach(log => {
        const key = mdAddressKey(log.recipient);
        [...(owners.get(key) || [key])].forEach(owner => { if (byKey.has(owner)) byKey.get(owner).dovecot.push(log); });
    });
    const expiry = (data.postfix || []).filter(log => !log.recipient && String(log.status || '').toLowerCase() === 'expired').length > 0;
    const rank = status => mdStatusInfo(status).rank;
    return [...byKey.values()].map(r => {
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
        const mailbox = mdMailboxVerdict(r.dovecot);
        const reason = last && status !== 'sent' ? mdFailureReason(last)
            : status === 'sent' && mailbox && mailbox !== 'stored' ? `Mailbox delivery: ${DOVECOT_VERDICTS[mailbox].label}` : '';
        const delivered = [...reached.keys()].filter(to => to !== r.key).map(to => reached.get(to).address);
        return { ...r, status, last, attempts: worst ? worst.attempts : 0, relay: last ? last.relay : '', reason, delivered };
    });
}

function messageRecipientsAll(data, own = messageRecipients(data)) {
    const seen = new Set(own.map(r => r.key));
    const others = [];
    (data.related_deliveries || []).forEach(leg => (leg.recipients || []).forEach(address => {
        const key = mdAddressKey(address);
        if (!key || seen.has(key)) return;
        seen.add(key);
        others.push({ address: String(address).trim(), key, leg });
    }));
    return own.concat(others);
}

function mdStatusCounts(recipients) {
    const counts = {};
    recipients.forEach(r => { counts[r.status] = (counts[r.status] || 0) + 1; });
    return counts;
}

function mdRecipientOrder(a, b) {
    return mdStatusInfo(a.status).rank - mdStatusInfo(b.status).rank || a.address.localeCompare(b.address);
}

function mdStatusList(recipients) {
    const counts = mdStatusCounts(recipients);
    return Object.keys(counts)
        .sort((a, b) => mdStatusInfo(a).rank - mdStatusInfo(b).rank || a.localeCompare(b))
        .map(status => ({ status, count: counts[status], ...mdStatusInfo(status) }));
}

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

function showMessageRecipients(status) {
    Object.assign(mdView, { status: status || '', query: '', all: !status, picked: -1 });
    switchModalTab('postfix');
    mdReveal('md-rcpts');
}

function mdReveal(id) {
    const el = document.getElementById(id);
    if (!el || typeof el.scrollIntoView !== 'function') return;
    if (typeof uiDialogSheetFull === 'function') uiDialogSheetFull(document.getElementById('message-modal'));
    el.scrollIntoView({ block: 'start', behavior: 'smooth' });
}

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
    const list = document.getElementById('md-rcpt-results');
    if (list) mdRelayTip(list);
}

function mdRedrawTimeline() {
    const data = currentModalData || {};
    mdRedraw('md-timeline-slot', renderLogTimeline(data.postfix, (data.dovecot && data.dovecot.logs) || []));
}

function searchMessageRecipients(query) {
    mdView.query = query;
    mdView.all = false;
    mdRedrawRecipients();
    mdRedrawTimeline();
}

function filterMessageRecipients(status) {
    mdView.status = status;
    mdView.all = false;
    mdRedrawRecipients();
    mdRedrawTimeline();
}

function mdRecipientPickerOpen() {
    const body = document.getElementById('message-modal-body');
    const head = document.querySelector('#md-timeline .ui-md-timeline-head');
    if (!body || !head) return;
    const tabs = body.querySelector(':scope > .ui-tabs');
    const gap = head.getBoundingClientRect().top - (tabs || body).getBoundingClientRect().bottom;
    if (gap > 1) body.scrollTop += gap;
}

function mdListedRecipients() {
    const query = mdView.query.trim().toLowerCase();
    return mdRecipients.map((r, index) => ({ r, index }))
        .filter(({ r }) => (!mdView.status || r.status === mdView.status) && (!query || r.address.toLowerCase().includes(query)));
}

function moreMessageRecipients() {
    mdView.all = !mdView.all;
    mdRedrawRecipients();
}

function pickMessageRecipient(index, toggle = false) {
    mdView.picked = toggle && mdView.picked === index ? -1 : index;
    if (index < 0) {
        Object.assign(mdView, { status: '', query: '' });
        const search = document.querySelector('#md-rcpts input[type="search"]');
        if (search) search.value = '';
    }
    mdRedrawRecipients();
    mdRedrawTimeline();
    if (mdView.picked >= 0) mdReveal('md-timeline');
}

function renderRecipientRows() {
    const rows = mdListedRecipients().sort((a, b) => mdRecipientOrder(a.r, b.r));
    const shown = mdView.all ? rows : rows.slice(0, MD_RCPT_ROWS);
    const chip = (status, word, count) => `<button type="button" class="ui-chip" data-md-focus="status-${escapeHtml(status)}" aria-pressed="${mdView.status === status}" onclick="filterMessageRecipients('${escapeJsArg(status)}')">${escapeHtml(word)} <small>${count}</small></button>`;
    const row = ({ r, index }) => {
        const info = mdStatusInfo(r.status);
        const host = relayHost(r.relay);
        const sub = !r.last ? `<span>${r.status === 'none' ? 'No delivery logged yet' : 'No delivery attempt logged'}</span>`
            : `${host ? `<span class="ui-md-rrow-via">via ${renderRelay(r.relay, false)}</span>` : `<span>${escapeHtml(info.word)}</span>`}${r.delivered.length ? `<span>· to <bdi>${escapeHtml(r.delivered.join(', '))}</bdi></span>` : ''}${r.attempts > 1 ? `<span>· ${r.attempts} attempts</span>` : ''}${r.last.time ? `<span>· ${escapeHtml(formatTime(r.last.time))}</span>` : ''}`;
        return `
            <div class="ui-md-rrow" title="Show the logs of ${escapeHtml(r.address)}" onclick="if (!uiRowHeld(event) && !mdRelayTapped(event)) pickMessageRecipient(${index}, true)">
                <span class="ui-md-rrow-addr">${uiEntity('address', r.address)}</span><button type="button" data-md-focus="row-${index}" aria-pressed="${mdView.picked === index}" aria-label="${escapeHtml(info.word)}, show the logs of ${escapeHtml(r.address)}" onfocus="mdRelayTip(this.parentElement)" class="ui-row-open ui-tag${info.tone ? ` ui-tag-${info.tone}` : ''}">${escapeHtml(info.word)}</button>
                <span class="ui-md-rrow-sub">${sub}</span>
                ${r.reason ? `<span class="ui-md-rrow-why ${info.tone && info.tone !== 'ok' ? `ui-text-${info.tone}` : 'ui-muted'}">${escapeHtml(r.reason)}</span>` : ''}
            </div>`;
    };
    return `
        ${mdRecipients.length > 1 ? `<div class="ui-chip-row">
            ${chip('', 'All', mdRecipients.length)}
            ${mdStatusList(mdRecipients).map(s => chip(s.status, s.word, s.count)).join('')}
        </div>` : ''}
        <div class="ui-md-rlist">${shown.length ? shown.map(row).join('') : '<div class="ui-md-rnone">No recipient matches</div>'}</div>
        ${rows.length > MD_RCPT_ROWS ? `<button type="button" class="ui-btn ui-btn-sm ui-md-rmore" data-md-focus="more" onclick="moreMessageRecipients()">${mdView.all ? 'Show fewer' : `Show all ${rows.length}`}</button>` : ''}
        ${renderOtherDeliveryRecipients()}`;
}

function renderOtherDeliveryRecipients() {
    const query = mdView.query.trim().toLowerCase();
    const others = mdView.status ? [] : mdOtherRecipients.filter(r => !query || r.address.toLowerCase().includes(query));
    if (!others.length) return '';
    const outcome = r => {
        const leg = r.leg;
        let word = 'no final status';
        let tone = '';
        if (leg.final_status) {
            const status = leg.final_status === 'delivered' ? 'sent' : leg.final_status;
            const info = mdStatusInfo(status);
            word = info.word;
            tone = (MD_RCPT_STATUS[status] ? info.tone : UI_STATUS_TONE[leg.final_status]) || '';
        }
        return `<button type="button" aria-label="${escapeHtml(word)}, open the delivery to ${escapeHtml(r.address)}" class="ui-row-open ui-tag${tone ? ` ui-tag-${tone}` : ''}">${escapeHtml(word)}</button>`;
    };
    const row = r => `
            <div class="ui-md-rrow" title="Open the delivery to ${escapeHtml(r.address)}" onclick="if (!uiRowHeld(event)) viewMessageDetails('${escapeJsArg(r.leg.correlation_key)}')">
                <span class="ui-md-rrow-addr">${uiEntity('address', r.address)}</span>${outcome(r)}
                <span class="ui-md-rrow-sub"><span>In another delivery of this message</span>${r.leg.first_seen ? `<span>· ${escapeHtml(formatTime(r.leg.first_seen))}</span>` : ''}</span>
            </div>`;
    return `
        <h5 class="ui-md-sub">Other deliveries of this message</h5>
        <div class="ui-md-rlist">${others.map(row).join('')}</div>`;
}

function renderRecipientsSection() {
    const total = mdRecipients.length + mdOtherRecipients.length;
    if (total < 2) return '';
    return `
        <section class="ui-md-rcpts" id="md-rcpts">
            <div class="ui-md-rcpts-head">
                <h4 class="ui-md-h">Recipients <span class="ui-muted">${total}</span></h4>
                <input type="search" class="ui-input" placeholder="Find a recipient" aria-label="Find a recipient" autocomplete="off" spellcheck="false" value="${escapeHtml(mdView.query)}" oninput="searchMessageRecipients(this.value)">
            </div>
            <div class="ui-md-rcpts" id="md-rcpt-results">${renderRecipientRows()}</div>
        </section>`;
}

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
            if (data.queue_id_reused) return { tone: 'info', text: 'Outcome unknown: Postfix gave its queue ID to another message too' };
            return data.is_complete === false ? { tone: 'info', text: 'In progress, waiting for Postfix logs' } : { tone: 'info', text: 'Linked' };
    }
}

function renderMessageHeader(data) {
    const header = document.getElementById('message-modal-header');
    if (!header) return;
    const recipients = (data.recipients && data.recipients.length) ? data.recipients : (data.recipient ? [data.recipient] : []);
    const own = messageRecipients(data);
    const all = messageRecipientsAll(data, own);
    const many = all.length > 1;
    const counted = recipientsVerdict(data, own);
    const verdict = counted || messageVerdict(data);
    const tally = counted ? mdStatusList(own).filter(s => s.status !== 'sent') : [];
    const toHtml = many
        ? `<div class="ui-md-to"><span class="ui-md-to-list">${all.slice(0, 12).map(r => uiEntity('address', r.address, { plain: true })).join(', ')}</span><button type="button" class="ui-md-link" onclick="showMessageRecipients('')">All ${all.length} recipients</button></div>`
        : uiEntity('address', all.length ? all[0].address : (recipients[0] || '-'));
    const facts = [];
    if (data.rspamd && data.rspamd.size) facts.push(formatSize(data.rspamd.size));
    if (data.direction) facts.push(data.direction);
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
            <span>From</span><div>${uiEntity('address', data.sender || '-')}</div>
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

function buildDeliverySteps(data) {
    const steps = [];
    const add = (time, tone, title, detail, html) => steps.push({ time: time || '', tone, title, detail, ...(html || {}) });
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
                titleHtml: ip ? `Received from ${uiEntity('ip', ip)}` : '',
                detailHtml: `${escapeHtml(program)}${user ? `, authenticated as ${uiEntity('address', user)}` : ''}`
            });
        } else if (/cleanup/.test(program) && /message-id=/.test(message)) {
            const qid = log.queue_id || data.queue_id;
            add(log.time, 'ok', qid ? `Queued as ${qid}` : 'Queued', program, { titleHtml: qid ? `Queued as ${copyableText(qid)}` : '' });
        } else if (log.status) {
            const target = relayHost(log.relay) || log.recipient || '';
            const detail = `status=${log.status}${log.dsn ? ` (${log.dsn})` : ''}`;
            if (log.status === 'sent') add(log.time, 'ok', target ? `Delivered to ${target}` : 'Delivered', detail, { titleHtml: target ? `Delivered to ${uiEntity('address', target)}` : '' });
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
    const stage = step => /^(Rejected|Received)/.test(step.title) ? 0 : /^Queued/.test(step.title) ? 1 : /^Rspamd/.test(step.title) ? 2
        : /^(Delivered|Deferred|Bounced)/.test(step.title) ? 3 : 4;
    steps.sort((a, b) => (a.time < b.time ? -1 : a.time > b.time ? 1 : stage(a) - stage(b)));
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
    const client = data.client || {};
    const clientIp = rspamd.ip || client.ip;
    const clientUser = rspamd.user || client.user;
    const place = rspamd.country_code ? rspamd : client;
    const geoNote = place.country_code ? [
        getFlagUrl(place.country_code, '16x12') ? `<img src="${getFlagUrl(place.country_code, '16x12')}" alt="" width="16" height="12" onerror="this.style.display='none'">` : '',
        escapeHtml([place.country_name, place.city].filter(Boolean).join(', ')),
        place.asn_org ? `<span class="ui-muted">· ${escapeHtml(place.asn_org)}</span>` : ''
    ].filter(Boolean).join(' ') : '';
    const identifiers = [
        clientIp ? mdIdRow('Client IP', `<span class="ui-mono">${uiEntity('ip', clientIp, { mono: true })}</span>`, geoNote) : '',
        (clientUser && clientUser !== 'unknown') || rspamd.has_auth ? mdIdRow('Authenticated user',
            clientUser && clientUser !== 'unknown' ? uiEntity('address', clientUser) : '<span class="ui-muted">Unknown user</span>', rspamd.has_auth ? 'Verified (MAILCOW_AUTH)' : '') : '',
        data.queue_id ? mdIdRow('Queue ID', `<span class="ui-mono">${copyableText(data.queue_id)}</span>`) : '',
        data.message_id ? mdIdRow('Message ID', `<span class="ui-mono">${copyableText(data.message_id)}</span>`) : '',
        mdNoMessageId(data) ? mdIdRow('Message ID', '<span class="ui-muted">Missing</span>', 'Without a Message-ID it could not be linked to its spam scan. Only what Postfix logged is shown') : '',

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
    const dovecotLogs = (data.dovecot && data.dovecot.logs) ? data.dovecot.logs : [];

    if (!data.postfix || data.postfix.length === 0) {
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

    let clientIp = null, relay = null;
    let messageId = null, finalStatus = null, totalDelay = null;
    let errorReasons = [];
    let recipientsFromPostfix = new Set();

    data.postfix.forEach(log => {
        if (log.relay && !relay) relay = log.relay;
        if (log.message_id && !messageId) messageId = log.message_id;
        if (log.status) finalStatus = log.status;
        if (log.delay) totalDelay = log.delay;
        if (log.recipient) {
            recipientsFromPostfix.add(log.recipient);
        }

        if (!clientIp && log.message) {
            const ipMatch = log.message.match(/client=.*?\[(\d+\.\d+\.\d+\.\d+)\]/);
            if (ipMatch) clientIp = ipMatch[1];
        }

        if (log.status && log.status !== 'sent' && log.message) {
            const saidMatch = log.message.match(/said:\s*(.+?)(?:\s*\(in reply|$)/i);
            if (saidMatch) {
                errorReasons.push({
                    recipient: log.recipient,
                    status: log.status,
                    reason: saidMatch[1].trim()
                });
            } else if (log.status === 'deferred' || log.status === 'bounced') {
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


    const many = mdRecipients.length > 1;

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

    const errorSummaryHtml = dedupedErrors.length > 0 && !many ? `
        <div class="ui-banner ui-banner-fail ui-md-errors">
            <div>Delivery Error
                <div class="ui-md-error-list">
                    ${dedupedErrors.map(err => `
                        <div class="ui-md-error">
                            ${err.recipient || err.count > 1 ? `
                                <div class="ui-md-tags">
                                    ${err.recipient ? `<b>${uiEntity('address', err.recipient, { plain: true })}</b>` : ''}
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
    } else if (recipientsFromPostfix.size > 0) {
        toFact = mdFact(`This delivery (${recipientsFromPostfix.size})`, recipientsFromPostfix.size === 1 ? uiEntity('address', Array.from(recipientsFromPostfix)[0]) : `${recipientsFromPostfix.size} recipients`);
    } else if (data.recipients && data.recipients.length > 0) {
        toFact = mdFact(`This delivery (${data.recipients.length})`, data.recipients.length === 1 ? uiEntity('address', data.recipients[0]) : `${data.recipients.length} recipients`);
    }

    const relays = [...new Set(mdRecipients.map(r => r.relay).filter(Boolean))];
    const stripRelay = many ? (relays.length === 1 ? relays[0] : '') : relay;
    const stripFacts = [
        toFact,
        finalStatus && !many ? mdFact('Final Status', uiStatusTag(finalStatus)) : '',
        clientIp ? mdFact('Client IP', `<span class="ui-mono">${uiEntity('ip', clientIp, { mono: true })}</span>`) : '',
        stripRelay ? mdFact('Relay', renderRelay(stripRelay)) : '',
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
    mdRelayTip(content);
}

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

function mdNoMessageId(data) {
    return String(data.correlation_key || '').startsWith('noid-');
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
                            <b class="ui-mono">${uiEntity('ip', log.ip, { mono: true })}</b>
                            <span class="ui-md-log-status">${uiActionTag(log.action)}</span>
                        </div>
                        ${log.username ? `<p>User: ${uiEntity('address', log.username)}</p>` : ''}
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
        document.body.style.overflow = '';
        markSelectedMessageRow(null);
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
        messageModal.addEventListener('click', function (e) {
            if (uiBackdropClick(e)) {
                closeMessageModal();
            }
        });
    }

    document.addEventListener('keydown', function (e) {
        if (e.key !== 'Escape' || e.defaultPrevented) return;
        const modal = document.getElementById('message-modal');
        if (modal && modal.classList.contains('ui-docked') && !modal.classList.contains('hidden')
            && !(typeof openOverlays === 'function' && openOverlays().length)) {
            closeMessageModal();
        }
    });
});
