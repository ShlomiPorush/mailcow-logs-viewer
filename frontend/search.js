// =============================================================================
// SEARCH - the search in the top bar: pages, settings, messages, domains,
// mailboxes and addresses, each in its own tab with the first few under All
// =============================================================================
// Classic script sharing the global scope; loaded after the page scripts, whose
// functions open what a result points to.

const GS_CATEGORIES = [
    { id: 'pages', label: 'Pages' },
    { id: 'settings', label: 'Settings' },
    { id: 'messages', label: 'Messages', feature: null },
    { id: 'domains', label: 'Domains', feature: 'domains' },
    { id: 'mailboxes', label: 'Mailboxes', feature: 'mailbox-stats' },
    { id: 'addresses', label: 'IP addresses', feature: 'netfilter' }
];
// Results a category's tab lists, and how many of them All shows
const GS_LIMIT = 10;
const GS_SUMMARY = 3;
// The server is asked from this many characters; pages and settings answer from the first
const GS_SERVER_FROM = 2;
const GS_SHORT = 'Type one more character to search the messages, domains, mailboxes and addresses too.';

const GS_ICONS = {
    pages: '<path d="M7 3h7l5 5v13H7zM14 3v5h5M10 13h6M10 17h6"/>',
    settings: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"/>',
    messages: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
    domains: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 010 18M12 3a14 14 0 000 18"/>',
    mailboxes: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0116 0"/>',
    addresses: '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/>'
};

// The tabs of a page, read from its tab buttons so their names live in one place
const GS_PAGE_TABS = {
    netfilter: 'security-tab-btn-',
    quarantine: 'quarantine-tab-btn-',
    'spam-filter': 'spam-subtab-',
    status: 'status-tab-btn-',
    dmarc: 'dmarc-tab-btn-',
    'mailbox-stats': 'mailbox-stats-view-'
};

let gsQuery = '';
let gsTab = 'all';
let gsActive = 0;
let gsResults = {};
let gsShown = [];
let gsTimer = null;
let gsController = null;
let gsDomains = null;
let gsDomainsAt = 0;

function gsEl(id) { return document.getElementById(id); }

function gsOff(category) {
    return !!(category.feature && window.disabledFeatures && window.disabledFeatures.includes(category.feature));
}

function gsMatch(text, q) {
    return String(text || '').toLowerCase().includes(q);
}

// The query in a result, marked
function gsMark(text, q) {
    const value = String(text || '');
    const at = q ? value.toLowerCase().indexOf(q) : -1;
    if (at < 0) return escapeHtml(value);
    return escapeHtml(value.slice(0, at)) + '<mark>' + escapeHtml(value.slice(at, at + q.length)) + '</mark>'
        + escapeHtml(value.slice(at + q.length));
}

function gsVisible(el) {
    return !!el && el.style.display !== 'none' && !el.classList.contains('hidden');
}

// ----------------------------------------------------------------- the indexes

function gsSearchPages(q) {
    const items = [];
    document.querySelectorAll('.ui-sidenav .ui-nav-item[id^="tab-"]').forEach(button => {
        if (!gsVisible(button)) return;
        const route = button.id.slice(4);
        const page = (button.querySelector('.ui-nav-label') || button).textContent.trim();
        const group = button.closest('[data-nav-group]')?.querySelector('.ui-nav-group-label, .ui-nav-head')?.textContent.trim() || '';
        if (gsMatch(page, q)) items.push({ title: page, sub: group ? group + ' page' : 'Page', open: () => navigateTo(route) });
        const prefix = GS_PAGE_TABS[route];
        if (!prefix) return;
        document.querySelectorAll(`#content-${route} [role="tab"][id^="${prefix}"]`).forEach(tab => {
            if (!gsVisible(tab)) return;
            const copy = tab.cloneNode(true);
            copy.querySelectorAll('.ui-tab-n').forEach(n => n.remove());
            const name = copy.textContent.trim();
            const sub = tab.id.slice(prefix.length);
            if (!name || !(gsMatch(name, q) || gsMatch(page, q))) return;
            items.push({ title: name, sub: page + ' › tab',
                open: () => route === 'dmarc' ? dmarcOpenTab(sub) : navigateTo(route, { sub }) });
        });
    });
    return items;
}

function gsSearchSettings(q) {
    if (typeof settingsSearchIndex !== 'function') return [];
    // Names that hold the text first, then the ones only their key holds
    const found = settingsSearchIndex().filter(s => gsMatch(s.label, q) || gsMatch(s.key, q));
    return [...found.filter(s => gsMatch(s.label, q)), ...found.filter(s => !gsMatch(s.label, q))]
        .map(s => ({ title: s.label, sub: 'Settings › ' + s.tabLabel + (gsMatch(s.label, q) ? '' : ' · ' + s.key),
            open: () => gsOpenSetting(s) }));
}

// ----------------------------------------------------------------- the server

async function gsJson(url, signal) {
    const response = await authenticatedFetch(url, { signal });
    if (!response.ok) throw new Error('HTTP ' + response.status);
    return response.json();
}

async function gsSearchMessages(q, signal) {
    const data = await gsJson(`/api/messages?search=${encodeURIComponent(q)}&page=1&limit=${GS_LIMIT}`, signal);
    return {
        count: data.total || 0,
        items: (data.data || []).map(m => ({
            title: m.subject || '(no subject)',
            sub: (m.sender || '') + ' → ' + (m.recipient || ''),
            at: formatAgo(m.first_seen || m.last_seen),
            open: () => viewMessageDetails(m.correlation_key),
            // A message opens over the search, which stays for the next one
            keep: true
        })),
        more: { label: 'Open in Messages', open: () => navigateToMessagesWithFilter({ email: q, filterType: 'search' }) }
    };
}

async function gsSearchDomains(q, signal) {
    // One list for the whole time the search is in use: it has no search of its own
    if (!gsDomains || Date.now() - gsDomainsAt > 60000) {
        gsDomains = (await gsJson('/api/domains/all', signal)).domains || [];
        gsDomainsAt = Date.now();
    }
    const found = gsDomains.filter(d => gsMatch(d.domain_name, q));
    return {
        count: found.length,
        items: found.slice(0, GS_LIMIT).map(d => ({
            title: d.domain_name,
            sub: uiCountLabel(d.mboxes_in_domain || 0, 'mailbox', 'mailboxes') + (d.active === false ? ' · Inactive' : ''),
            open: () => gsOpenDomain(d.domain_name)
        }))
    };
}

async function gsSearchMailboxes(q, signal) {
    const data = await gsJson(`/api/mailbox-stats/all?search=${encodeURIComponent(q)}&active_only=false&page=1&page_size=${GS_LIMIT}`, signal);
    return {
        count: data.total || 0,
        items: (data.mailboxes || []).map(m => ({
            title: m.username,
            sub: m.name || 'Mailbox',
            open: () => gsOpenMailbox(m.username)
        })),
        more: { label: 'Open in Mailbox Stats', open: () => gsOpenMailbox(null, q) }
    };
}

async function gsSearchAddresses(q, signal) {
    // Only what can be part of an address: the list is read from the logs
    if (!/^[0-9a-f.:]+$/i.test(q)) return { count: 0, items: [] };
    const url = list => `/api/security/addresses?list=${list}&q=${encodeURIComponent(q)}&limit=${GS_LIMIT}`;
    const [review, banned] = await Promise.all([gsJson(url('review'), signal), gsJson(url('banned'), signal)]);
    const rows = [...(banned.items || []), ...(review.items || [])]
        .sort((a, b) => String(b.last_seen || '').localeCompare(String(a.last_seen || '')));
    const counts = review.counts || {};
    return {
        count: (counts.review || 0) + (counts.banned || 0),
        items: rows.slice(0, GS_LIMIT).map(a => ({
            title: a.ip,
            sub: [a.state === 'banned' ? 'Banned' : 'To review', a.country, uiCountLabel(a.attempts || 0, 'attempt', 'attempts')].filter(Boolean).join(' · '),
            at: formatAgo(a.last_seen),
            open: () => gsOpenAddress(a.ip)
        }))
    };
}

const GS_REMOTE = { messages: gsSearchMessages, domains: gsSearchDomains, mailboxes: gsSearchMailboxes, addresses: gsSearchAddresses };

// ----------------------------------------------------------------- searching

function gsRun(raw) {
    const q = raw.trim().toLowerCase();
    gsQuery = raw.trim();
    clearTimeout(gsTimer);
    if (gsController) gsController.abort();
    gsController = null;
    gsActive = 0;
    if (!q) {
        gsTab = 'all';
        gsResults = {};
        gsRender();
        return;
    }
    gsResults = {
        pages: { count: 0, items: gsSearchPages(q) },
        settings: { count: 0, items: gsSearchSettings(q) }
    };
    gsResults.pages.count = gsResults.pages.items.length;
    gsResults.settings.count = gsResults.settings.items.length;
    const remote = GS_CATEGORIES.filter(c => GS_REMOTE[c.id] && !gsOff(c));
    if (q.length < GS_SERVER_FROM) {
        remote.forEach(c => { gsResults[c.id] = { short: true, count: 0, items: [] }; });
        gsRender();
        return;
    }
    remote.forEach(c => { gsResults[c.id] = { loading: true, count: 0, items: [] }; });
    gsRender();
    // The server is asked once typing pauses; an older search is cancelled
    gsTimer = setTimeout(() => {
        const controller = new AbortController();
        gsController = controller;
        remote.forEach(c => {
            GS_REMOTE[c.id](q, controller.signal)
                .then(result => { if (gsController === controller) { gsResults[c.id] = result; gsRender(); } })
                .catch(() => { if (gsController === controller) { gsResults[c.id] = { failed: true, count: 0, items: [] }; gsRender(); } });
        });
    }, 200);
}

// ----------------------------------------------------------------- drawing

function gsIcon(id) {
    return `<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24" aria-hidden="true">${GS_ICONS[id]}</svg>`;
}

function gsItem(category, item, q) {
    const index = gsShown.push(item) - 1;
    return `<button type="button" class="ui-gs-item${index === gsActive ? ' is-active' : ''}" data-gs-index="${index}" role="option" aria-selected="${index === gsActive}">
        <span class="ui-gs-ic">${gsIcon(category)}</span><b>${gsMark(item.title, q)}</b><small>${gsMark(item.sub, q)}</small>${item.at ? `<span class="ui-gs-at">${escapeHtml(item.at)}</span>` : ''}</button>`;
}

function gsCountText(result) {
    if (!result || result.short) return '';
    if (result.loading) return '…';
    if (result.failed) return '!';
    return result.count.toLocaleString();
}

function gsRender() {
    const panel = gsEl('ui-gs-panel');
    if (!panel) return;
    const root = gsEl('ui-gs');
    root.classList.toggle('has-q', !!gsQuery);
    gsShown = [];
    if (!gsQuery) {
        panel.innerHTML = '';
        return;
    }
    const q = gsQuery.toLowerCase();
    const categories = GS_CATEGORIES.filter(c => !gsOff(c));
    const loading = categories.some(c => gsResults[c.id]?.loading);
    const short = categories.some(c => gsResults[c.id]?.short);
    const total = categories.reduce((n, c) => n + (gsResults[c.id]?.count || 0), 0);
    if (gsTab !== 'all' && !categories.some(c => c.id === gsTab)) gsTab = 'all';

    const tab = (id, label, text, empty) => `<button type="button" class="ui-gs-tab${gsTab === id ? ' is-on' : ''}${empty ? ' is-empty' : ''}" data-gs-tab="${id}" role="tab" aria-selected="${gsTab === id}">${label}<span class="ui-gs-n">${text}</span></button>`;
    const tabs = tab('all', 'All', loading ? '…' : total.toLocaleString(), false)
        + categories.map(c => {
            const r = gsResults[c.id];
            return tab(c.id, c.label, gsCountText(r), r && !r.loading && !r.count);
        }).join('');

    let body = '';
    if (gsTab === 'all') {
        categories.forEach(c => {
            const r = gsResults[c.id];
            if (!r || !r.count) return;
            body += `<div class="ui-gs-sec"><span>${escapeHtml(c.label)} · ${r.count.toLocaleString()}</span>${r.count > GS_SUMMARY ? `<button type="button" class="ui-link" data-gs-tab="${c.id}">See all</button>` : ''}</div>`
                + r.items.slice(0, GS_SUMMARY).map(item => gsItem(c.id, item, q)).join('');
        });
        if (!body) body = `<p class="ui-gs-empty">${loading ? 'Searching…' : short ? GS_SHORT : `Nothing found for “${escapeHtml(gsQuery)}”`}</p>`;
        else if (loading) body += '<p class="ui-gs-wait">Still searching…</p>';
        else if (short) body += `<p class="ui-gs-wait">${GS_SHORT}</p>`;
    } else {
        const r = gsResults[gsTab] || { count: 0, items: [] };
        if (r.more && r.count) {
            const index = gsShown.push(r.more) - 1;
            body += `<button type="button" class="ui-gs-more${index === gsActive ? ' is-active' : ''}" data-gs-index="${index}"><span><b>${r.count.toLocaleString()}</b> found</span><span class="ui-link">${escapeHtml(r.more.label)}</span></button>`;
        }
        body += r.items.map(item => gsItem(gsTab, item, q)).join('');
        if (r.count > r.items.length && !r.more) body += `<p class="ui-gs-wait">The first ${r.items.length} of ${r.count.toLocaleString()}</p>`;
        if (r.short) body = `<p class="ui-gs-empty">${GS_SHORT}</p>`;
        else if (r.loading) body = '<p class="ui-gs-empty">Searching…</p>';
        else if (r.failed) body = '<p class="ui-gs-empty">This search failed. Try again in a moment.</p>';
        else if (!r.items.length) body = `<p class="ui-gs-empty">Nothing found for “${escapeHtml(gsQuery)}”</p>`;
    }
    if (gsActive >= gsShown.length) gsActive = Math.max(0, gsShown.length - 1);

    panel.innerHTML = `<nav class="ui-gs-tabs" role="tablist" aria-label="Result types">${tabs}</nav>
        <div class="ui-gs-body" role="listbox" aria-label="Results">${body}</div>
        <div class="ui-gs-keys" aria-hidden="true"><span><kbd>↑</kbd><kbd>↓</kbd> move</span><span><kbd>Tab</kbd> type</span><span><kbd>Enter</kbd> open</span><span><kbd>Esc</kbd> close</span></div>`;
    panel.querySelector('.ui-gs-item.is-active, .ui-gs-more.is-active')?.scrollIntoView({ block: 'nearest' });
}

// ----------------------------------------------------------------- opening and closing

function gsPhone() {
    return window.matchMedia('(max-width: 760px)').matches;
}

function gsOpen() {
    const root = gsEl('ui-gs');
    if (!root) return;
    // On a phone the search covers the screen, above the bar it is hidden in
    if (gsPhone() && root.parentElement !== document.body) {
        root.dataset.home = 'topbar';
        document.body.appendChild(root);
        root.classList.add('is-sheet');
        document.documentElement.classList.add('ui-gs-locked');
    }
    root.classList.add('is-open');
    gsEl('ui-gs-input').setAttribute('aria-expanded', 'true');
    gsRender();
}

function gsClose(clear) {
    const root = gsEl('ui-gs');
    if (!root) return;
    const input = gsEl('ui-gs-input');
    // The next search starts again from All
    if (clear) {
        input.value = '';
        gsTab = 'all';
        gsRun('');
    }
    root.classList.remove('is-open');
    input.setAttribute('aria-expanded', 'false');
    if (root.classList.contains('is-sheet')) {
        root.classList.remove('is-sheet');
        document.documentElement.classList.remove('ui-gs-locked');
        gsEl('ui-topbar').insertBefore(root, gsEl('ui-topbar-actions'));
    }
    if (document.activeElement === input) input.blur();
}

function gsChoose(index) {
    const item = gsShown[index];
    if (!item) return;
    if (item.keep) {
        const input = gsEl('ui-gs-input');
        input.blur();
        item.open();
        // Back from the message, the keys work in the search again (not on a phone: no keyboard)
        const modal = gsEl('message-modal');
        if (modal && !gsPhone()) {
            const watch = new MutationObserver(() => {
                if (!modal.classList.contains('hidden')) return;
                watch.disconnect();
                if (gsEl('ui-gs').classList.contains('is-open')) input.focus({ preventScroll: true });
            });
            watch.observe(modal, { attributes: true, attributeFilter: ['class'] });
        }
        return;
    }
    gsClose(true);
    item.open();
}

function gsSetTab(id) {
    gsTab = id;
    gsActive = 0;
    gsRender();
}

// Wait for something a page draws after loading
function gsWaitFor(find, timeout = 8000) {
    return new Promise(resolve => {
        const started = Date.now();
        const look = () => {
            const found = find();
            if (found || Date.now() - started > timeout) resolve(found || null);
            else setTimeout(look, 100);
        };
        look();
    });
}

// A bar that stays at the top while scrolling (a page's tabs on a phone) can hide the
// start of what was opened: scroll it out from under the bar
function gsUncover(el) {
    const top = el.getBoundingClientRect();
    const hit = document.elementFromPoint(top.left + Math.min(top.width / 2, 40), Math.max(top.top, 0) + 2);
    if (!hit || el.contains(hit)) return;
    let cover = hit;
    while (cover && !['sticky', 'fixed'].includes(getComputedStyle(cover).position)) cover = cover.parentElement;
    if (!cover) return;
    const gap = cover.getBoundingClientRect().bottom - top.top + 12;
    if (gap <= 0) return;
    let scroller = el.parentElement;
    while (scroller && !(/(auto|scroll)/.test(getComputedStyle(scroller).overflowY) && scroller.scrollHeight > scroller.clientHeight)) scroller = scroller.parentElement;
    (scroller || document.scrollingElement).scrollBy(0, -gap);
}

// A field is brought to the middle; details (block 'start') from their top, below the bar
function gsReveal(el, block = 'center') {
    if (!el) return;
    el.classList.add('ui-gs-target');
    el.scrollIntoView({ block });
    if (block === 'start') gsUncover(el);
    el.classList.remove('ui-gs-flash');
    void el.offsetWidth;
    el.classList.add('ui-gs-flash');
    setTimeout(() => el.classList.remove('ui-gs-flash'), 2000);
}

function gsPageOpen(route) {
    const page = gsEl('content-' + route);
    return !!page && !page.classList.contains('hidden');
}

async function gsOpenSetting(setting) {
    navigateTo('settings', { sub: setting.tab });
    const find = () => {
        const el = gsEl('edit-' + setting.key) || gsEl('setting-' + setting.key);
        return el && el.offsetParent ? el : null;
    };
    const show = el => {
        gsReveal(el.closest('.ui-set-field, .ui-set-bool, .ui-set-wide') || el);
        if (el.type !== 'hidden') el.focus({ preventScroll: true });
    };
    let field = await gsWaitFor(find);
    if (!field) return;
    show(field);
    // The page is drawn again when the version check answers: find the field again
    const started = Date.now();
    const keep = () => {
        if (Date.now() - started > 4000) return;
        if (!field.isConnected) {
            field = find();
            if (!field) return;
            show(field);
        }
        setTimeout(keep, 150);
    };
    setTimeout(keep, 150);
}

async function gsOpenDomain(name) {
    navigateTo('domains');
    const id = domainRowId(name);
    const details = await gsWaitFor(() => gsEl(id + '-details'));
    if (!details) return;
    if (details.classList.contains('hidden')) toggleDomainDetails(id);
    gsReveal([...document.querySelectorAll('[data-domain-row]')].find(el => el.dataset.domainRow === name) || details, 'start');
}

// One mailbox opened, or the list searched for the text (username null)
async function gsOpenMailbox(username, text) {
    const field = gsEl('mailbox-stats-search');
    if (field) field.value = username || text;
    const already = gsPageOpen('mailbox-stats') && mailboxStatsView === 'statistics';
    navigateTo('mailbox-stats', { sub: 'statistics' });
    if (already) applyMailboxStatsFilters();
    if (!username) return;
    const found = await gsWaitFor(() => (mailboxStatsCache.mailboxes || []).some(m => m.username === username));
    if (!found) return;
    const index = mailboxStatsCache.mailboxes.findIndex(m => m.username === username);
    const content = gsEl('accordion-content-' + index);
    if (content && content.classList.contains('hidden')) toggleMailboxAccordion(username);
    gsReveal(content ? content.parentElement : null, 'start');
}

// The Security page's events for the address
function gsOpenAddress(ip) {
    ['netfilter-filter-username', 'netfilter-filter-action', 'netfilter-filter-country'].forEach(id => {
        const field = gsEl(id);
        if (field) field.value = '';
    });
    const field = gsEl('netfilter-filter-ip');
    if (field) field.value = ip;
    currentFilters.netfilter = { ip, username: '', action: '', country_code: '' };
    currentPage.netfilter = 1;
    const already = gsPageOpen('netfilter');
    navigateTo('netfilter', { sub: 'events' });
    if (already) applyNetfilterFilters();
}

// ----------------------------------------------------------------- wiring

function initGlobalSearch() {
    const root = gsEl('ui-gs');
    const input = gsEl('ui-gs-input');
    const panel = gsEl('ui-gs-panel');
    if (!root || !input || !panel) return;

    input.addEventListener('focus', gsOpen);
    input.addEventListener('input', () => gsRun(input.value));
    input.addEventListener('keydown', event => {
        if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault();
            if (!gsShown.length) return;
            gsActive = (gsActive + (event.key === 'ArrowDown' ? 1 : -1) + gsShown.length) % gsShown.length;
            gsRender();
        } else if (event.key === 'Enter') {
            event.preventDefault();
            gsChoose(gsActive);
        } else if (event.key === 'Tab' && gsQuery) {
            event.preventDefault();
            const ids = ['all', ...GS_CATEGORIES.filter(c => !gsOff(c)).map(c => c.id)];
            gsSetTab(ids[(ids.indexOf(gsTab) + (event.shiftKey ? -1 : 1) + ids.length) % ids.length]);
        } else if (event.key === 'Escape') {
            event.preventDefault();
            event.stopPropagation();
            gsClose(true);
        }
    });
    // A click on a result or a tab keeps the focus in the field. On a phone a tab
    // lets the keyboard go instead: the search is done, the results need the room
    const sheet = () => root.classList.contains('is-sheet');
    panel.addEventListener('mousedown', event => {
        if (event.target.closest('button') && !sheet()) event.preventDefault();
    });
    panel.addEventListener('click', event => {
        const tab = event.target.closest('[data-gs-tab]');
        if (tab) {
            gsSetTab(tab.dataset.gsTab);
            if (sheet()) input.blur();
            else input.focus();
            return;
        }
        const item = event.target.closest('[data-gs-index]');
        if (item) gsChoose(Number(item.dataset.gsIndex));
    });
    gsEl('ui-gs-cancel')?.addEventListener('click', () => gsClose(true));
    gsEl('ui-gs-phone')?.addEventListener('click', () => { gsOpen(); input.focus(); });

    // A click outside closes it; an empty field goes back to its narrow size
    document.addEventListener('mousedown', event => {
        // A message opened from the search is a dialog over it: the search waits behind
        if (event.target.closest && event.target.closest('.ui-dialog-backdrop, .ui-sheet')) return;
        if (root.classList.contains('is-open') && !root.contains(event.target) && !root.classList.contains('is-sheet')) gsClose(false);
    });
    input.addEventListener('blur', () => {
        setTimeout(() => {
            if (!root.contains(document.activeElement) && !input.value && !root.classList.contains('is-sheet')) gsClose(false);
        }, 0);
    });

    // "/" from anywhere that is not a field opens the search
    document.addEventListener('keydown', event => {
        if (event.key !== '/' || event.ctrlKey || event.metaKey || event.altKey) return;
        const target = event.target;
        if (target && (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName))) return;
        // Not over a dialog or a sheet
        if ([...document.querySelectorAll('.ui-sheet, [role="dialog"], .modal')].some(el => el.getClientRects().length)) return;
        event.preventDefault();
        if (gsPhone()) gsEl('ui-gs-phone')?.click();
        else input.focus();
    });
}

document.addEventListener('DOMContentLoaded', initGlobalSearch);
