// =============================================================================
// SEARCH - the search in the top bar: pages, settings, background jobs,
// messages, domains, mailboxes, suppressions and addresses, each in its own tab
// with the first few under All
// =============================================================================
// Classic script sharing the global scope; loaded after the page scripts, whose
// functions open what a result points to.
//
// The results are a grid: a row holds the result and, for an IP address, a
// mailbox, a domain or a background job, the buttons that act on it (Card, Ban,
// Allow, Run), shown on the active row and on hover. On a phone the buttons fold
// into one "..." row menu. The field keeps the focus: Up and Down move the active
// row, Enter opens it (an entity's card, a job on Status > Jobs), Right moves into
// the row's buttons and Left or Escape back to the field.

const GS_CATEGORIES = [
    { id: 'pages', label: 'Pages' },
    { id: 'settings', label: 'Settings' },
    { id: 'jobs', label: 'Background jobs', feature: null },
    { id: 'messages', label: 'Messages', feature: null },
    { id: 'domains', label: 'Domains', feature: 'domains' },
    { id: 'mailboxes', label: 'Mailboxes', feature: 'mailbox-stats' },
    { id: 'suppressions', label: 'Suppressions', feature: 'suppressions' },
    { id: 'addresses', label: 'IP addresses', feature: 'netfilter' }
];
// Results a category's tab lists, and how many of them All shows
const GS_LIMIT = 10;
const GS_SUMMARY = 3;
// The server is asked from this many characters; pages and settings answer from the first
const GS_SERVER_FROM = 2;
const GS_SHORT = 'Type one more character to search the messages, domains, mailboxes, suppressions, addresses and background jobs too.';
// Words that list every background job
const GS_JOB_WORDS = /^(run|run now|jobs?|background|background jobs?)$/;

const GS_ICONS = {
    pages: '<path d="M7 3h7l5 5v13H7zM14 3v5h5M10 13h6M10 17h6"/>',
    settings: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"/>',
    messages: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
    domains: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 010 18M12 3a14 14 0 000 18"/>',
    mailboxes: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0116 0"/>',
    suppressions: '<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>',
    addresses: '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/>',
    jobs: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>'
};
// The three dots of the Suppressions More button (index.html)
const GS_DOTS = '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><circle cx="5" cy="12" r="1.8"></circle><circle cx="12" cy="12" r="1.8"></circle><circle cx="19" cy="12" r="1.8"></circle></svg>';

// The tabs of a page, read from its tab buttons so their names live in one place
const GS_PAGE_TABS = {
    netfilter: 'security-tab-btn-',
    quarantine: 'quarantine-tab-btn-',
    outbound: 'outbound-tab-btn-',
    status: 'status-tab-btn-',
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
let gsListKept = null;
let gsListKeptAt = 0;
let gsJobs = null;
let gsJobsAt = 0;

function gsEl(id) { return document.getElementById(id); }

function gsOff(category) {
    // A setting result opens its field, which only the edit form has
    if (category.id === 'settings' && window.settingsEditable === false) return true;
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
            keep: 'message-modal'
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
        items: found.slice(0, GS_LIMIT).map(d => gsEntityItem('domain', d.domain_name, {
            sub: uiCountLabel(d.mboxes_in_domain || 0, 'mailbox', 'mailboxes') + (d.active === false ? ' · Inactive' : ''),
            open: () => gsOpenDomain(d.domain_name)
        }))
    };
}

async function gsSearchMailboxes(q, signal) {
    const data = await gsJson(`/api/mailbox-stats/all?search=${encodeURIComponent(q)}&active_only=false&page=1&page_size=${GS_LIMIT}`, signal);
    return {
        count: data.total || 0,
        items: (data.mailboxes || []).map(m => gsEntityItem('address', m.username, {
            sub: m.name || 'Mailbox',
            open: () => gsOpenMailbox(m.username)
        })),
        more: { label: 'Open in Mailbox Stats', open: () => gsOpenMailbox(null, q) }
    };
}

// The app keeps a suppression list only while Sync with Rspamd is on: with it
// off the category is not shown at all
async function gsSearchSuppressions(q, signal) {
    if (gsListKept === null || Date.now() - gsListKeptAt > 60000) {
        gsListKept = (await gsJson('/api/suppressions/config', signal)).list_kept === true;
        gsListKeptAt = Date.now();
    }
    if (!gsListKept) return { hidden: true, count: 0, items: [] };
    const data = await gsJson(`/api/suppressions?search=${encodeURIComponent(q)}&active_filter=&page=1&per_page=${GS_LIMIT}`, signal);
    const shown = value => (typeof _cleanRegexDomain === 'function' ? _cleanRegexDomain(value) : value);
    const state = s => (s.is_expired ? 'Expired' : s.active ? 'Active' : 'Inactive');
    return {
        count: data.total || 0,
        items: (data.items || []).map(s => ({
            title: shown(s.email),
            sub: [state(s), String(s.reason || '').replace('_', ' '), s.notes].filter(Boolean).join(' · '),
            at: formatAgo(s.created_at),
            // By the value shown: a domain block opens by its domain, which the list finds
            open: () => gsOpenSuppressions(shown(s.email))
        })),
        more: { label: 'Open in Suppressions', open: () => gsOpenSuppressions(q) }
    };
}

async function gsSearchAddresses(q, signal) {
    // Only what can be part of an address: the list is read from the logs
    if (!/^[0-9a-f.:/]+$/i.test(q)) return { count: 0, items: [] };
    const url = list => `/api/security/addresses?list=${list}&q=${encodeURIComponent(q)}&limit=${GS_LIMIT}`;
    const [review, banned] = await Promise.all([gsJson(url('review'), signal), gsJson(url('banned'), signal)]);
    const rows = [...(banned.items || []), ...(review.items || [])]
        .sort((a, b) => String(b.last_seen || '').localeCompare(String(a.last_seen || '')));
    const counts = review.counts || {};
    const items = rows.slice(0, GS_LIMIT).map(a => {
        const fields = {
            sub: [a.state === 'banned' ? 'Banned' : 'To review', a.country, uiCountLabel(a.attempts || 0, 'attempt', 'attempts')].filter(Boolean).join(' · '),
            at: formatAgo(a.last_seen),
            // A banned network has no events of its own: it opens on the Banned list
            open: () => a.network_size ? gsOpenBannedNetwork() : gsOpenAddress(a.ip)
        };
        // One address opens its card and has Ban and Allow; a network keeps its list
        return a.network_size ? { title: a.ip, ...fields } : gsEntityItem('ip', a.ip, fields);
    });
    let count = (counts.review || 0) + (counts.banned || 0);
    // One valid address typed that the lists do not hold still gets its row: its
    // card, Ban and Allow, and what the app keeps about it (read as its card reads it)
    const typed = q.trim();
    if (entityKindOf(typed) === 'ip' && !rows.some(a => String(a.ip).toLowerCase() === typed.toLowerCase())) {
        const { value, sub } = await gsTypedIp(typed, signal);
        items.unshift(gsEntityItem('ip', value, { sub, title: typed }));
        count += 1;
    }
    return { count, items };
}

// The sources of the IP card that hold activity, and how a count of each reads
const GS_IP_ACTIVITY = [
    ['messages', s => s.count, 'message', 'messages'],
    ['security', s => s.events, 'security event', 'security events'],
    ['protection', s => s.count, 'protection catch', 'protection catches'],
    ['devices', s => s.count, 'device', 'devices'],
    ['dmarc', s => s.messages, 'DMARC message', 'DMARC messages'],
];

// A typed address the lists do not hold, as its card has it (GET /api/entities/ip,
// the card's own period): what it holds, or "No activity" only when every source
// of activity was read and holds nothing. A source that is off or failed, or a
// card that could not be read, says nothing either way. The value comes back as
// the server writes it (IPv6 compressed, an IPv4 mapped into IPv6 as IPv4)
async function gsTypedIp(ip, signal) {
    let data = null;
    try {
        data = await gsJson(`/api/entities/ip?value=${encodeURIComponent(ip)}`, signal);
    } catch (error) {
        // An older search, cancelled: dropped with it
        if (error && error.name === 'AbortError') throw error;
    }
    const sources = (data && data.sources) || {};
    const value = data && entityKindOf(data.value) === 'ip' ? data.value : ip;
    const read = GS_IP_ACTIVITY.filter(([name]) => sources[name] && sources[name].state === 'ok');
    const found = read.map(([name, n, one, many]) => [Number(n(sources[name])) || 0, one, many]).filter(([n]) => n > 0);
    const range = (data && data.range) || {};
    const days = Math.round((Date.parse(range.end) - Date.parse(range.start)) / 86400000);
    const within = days > 0 ? ` in the last ${uiCountLabel(days, 'day', 'days')}` : '';
    if (found.length) return { value, sub: found.map(([n, one, many]) => uiCountLabel(n, one, many)).join(' · ') + within };
    if (data && read.length === GS_IP_ACTIVITY.length) return { value, sub: `No activity${within}` };
    return { value, sub: 'Not in these results' };
}

// A row for an IP address, an email address (a mailbox) or a domain: Enter and a
// click open its card. A value that is not one of its kind (as the server reads it,
// entityKindOf in utils.js) keeps the way it opened before, without buttons.
// title: what the row shows, when it is not the value (the address as typed)
function gsEntityItem(kind, value, { sub = '', at = '', open = null, title = '' } = {}) {
    const text = String(value || '').trim();
    if (entityKindOf(text) !== kind) return { title: title || text, sub, at, open: open || (() => {}) };
    return { title: title || text, sub, at, entity: { kind, value: text }, hint: 'card', keep: 'entity-card',
        open: () => openEntityCard(kind, text, { from: gsOpener() }) };
}

// What gets the focus back when a card or a question opened from the search closes:
// the field (its rows are drawn again meanwhile). On a phone the search itself
function gsOpener() {
    return gsPhone() ? null : gsEl('ui-gs-input');
}

// The jobs the Status page lists, in its order and with its names (app.js
// statusJobCategories), that the server reports. Each of them is in the manual-run
// map of POST /api/settings/jobs/{job}/run (a test holds the two together); a job
// the server reports that is not among them is not offered
function gsJobList() {
    if (!gsJobs || typeof statusJobCategories !== 'function') return [];
    return statusJobCategories(gsJobs).flatMap(c => c.jobs).filter(([, , job]) => job);
}

// Off as the Status page reads it (utils.js renderJobCard)
function gsJobOff(job) {
    return job.status === 'disabled' || job.enabled === false || job.feature_disabled === true;
}

// "5 minutes" as "Every 5 minutes", "1 hour" as "Every hour"; a time of day stays as written
function gsJobEvery(text) {
    if (!/^\d/.test(text)) return text;
    return 'Every ' + text.replace(/^1 (second|minute|hour|day)\b/, '$1');
}

function gsJobItem(name, key, job) {
    const off = gsJobOff(job);
    const running = !off && job.status === 'running';
    const finished = { success: 'finished', failed: 'failed' }[job.status];
    const state = off ? `Off: ${job.feature_disabled ? 'its feature is turned off in Settings' : (job.disabled_reason || 'it is turned off in its settings')}`
        : running ? 'Running now'
        : job.last_run ? `Last run ${formatAgo(job.last_run)}${finished ? `, ${finished}` : ''}` : 'Not run yet';
    return {
        title: name,
        sub: off ? state : [state, gsJobEvery(jobRunsText(job))].filter(Boolean).join(' · '),
        job: { key, name, description: job.description || '', off, running },
        hint: 'job',
        open: () => gsOpenJob(key)
    };
}

async function gsSearchJobs(q, signal) {
    // The Status page's own answer, read again after a while (and after a run)
    if (!gsJobs || Date.now() - gsJobsAt > 30000) {
        const data = await gsJson('/api/settings/info', signal);
        if (!data || data.error || !data.background_jobs) throw new Error('No jobs');
        gsJobs = data.background_jobs;
        gsJobsAt = Date.now();
    }
    const every = GS_JOB_WORDS.test(q);
    const found = gsJobList().filter(([name, , job]) => every || gsMatch(name, q) || gsMatch(job.description, q));
    return {
        count: found.length,
        items: found.map(([name, key, job]) => gsJobItem(name, key, job)),
        more: { label: 'Open in Status', open: () => navigateTo('status', { sub: 'jobs' }) }
    };
}

const GS_REMOTE = { jobs: gsSearchJobs, messages: gsSearchMessages, domains: gsSearchDomains, mailboxes: gsSearchMailboxes,
    suppressions: gsSearchSuppressions, addresses: gsSearchAddresses };

// The kind typed comes first: one IP address puts IP addresses first, a word for
// the jobs (run, jobs) Background jobs, and so does a job's name when no page has it
function gsLead(q) {
    if (!q) return null;
    if (entityKindOf(q) === 'ip') return 'addresses';
    if (GS_JOB_WORDS.test(q)) return 'jobs';
    if (!(gsResults.pages && gsResults.pages.count) && gsJobList().some(([name]) => gsMatch(name, q))) return 'jobs';
    return null;
}

// The kinds shown, in the order of their tabs and groups
function gsCategories() {
    const list = GS_CATEGORIES.filter(c => !gsOff(c) && !gsResults[c.id]?.hidden);
    const at = list.findIndex(c => c.id === gsLead(gsQuery.toLowerCase()));
    if (at > 0) list.unshift(list.splice(at, 1)[0]);
    return list;
}

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

// ----------------------------------------------------------------- row actions

const gsRw = () => typeof mailcowRwConfigured !== 'undefined' && !!mailcowRwConfigured;

// What a row offers, as it stands now: an entity its card, one IP address Ban and
// Allow too with the Read-Write key (without it they are not offered, as in the
// card); a job Run, unless it is off; while it runs, Run is there but unavailable
function gsActs(item) {
    if (item.entity) {
        const acts = [{ act: 'card' }];
        if (item.entity.kind === 'ip' && gsRw()) acts.push({ act: 'ban' }, { act: 'allow' });
        return acts;
    }
    if (item.job && !item.job.off) return [{ act: 'run', disabled: item.job.running }];
    return [];
}

function gsActTitle(item, act) {
    const entry = item.entity && typeof fail2banEntry === 'function' ? fail2banEntry(item.entity.value) : item.title;
    const what = item.entity ? { ip: 'IP address', address: 'address', domain: 'domain' }[item.entity.kind] : '';
    return {
        card: `Open the card of this ${what}`,
        // The titles of the card's Ban and Allow (entity-card.js entityCardActionsHtml)
        ban: `Put ${entry} on the Fail2ban denylist; it stays until removed`,
        allow: `Never ban ${entry}`,
        run: item.job && item.job.running ? 'Job is running' : 'Run this job now'
    }[act];
}

const GS_ACT_LABELS = { card: 'Card', ban: 'Ban', allow: 'Allow', run: 'Run' };
const GS_MENU_LABELS = { card: 'Open card', job: 'Open job', ban: 'Ban', allow: 'Allow', run: 'Run' };

// The buttons at the row's end (Ban in red text, as on the Security list rows), and
// for a phone one "..." button with the same in a row menu (the Suppressions More
// menu, index.html). The menu leads with what a tap on the row does, and is left
// out when that is all it would hold. Buttons are reached with the arrows, not Tab
function gsActsHtml(index, item, acts) {
    if (!acts.length) return '';
    const value = item.title;
    const buttons = acts.map(({ act, disabled }) => `<button type="button" class="ui-btn ui-btn-sm${act === 'ban' ? ' ui-btn-danger' : ''}" tabindex="-1" data-gs-act="${act}" data-gs-at="${index}"`
        + ` aria-label="${escapeHtml(`${GS_ACT_LABELS[act]} ${value}`)}" title="${escapeHtml(gsActTitle(item, act))}"${disabled ? ' disabled' : ''}>${GS_ACT_LABELS[act]}</button>`).join('');
    const menuActs = [item.entity ? 'card' : 'job', ...acts.filter(a => a.act !== 'card' && !a.disabled).map(a => a.act)];
    const menu = menuActs.length < 2 ? '' : uiMenu(`Actions for ${value}`,
        menuActs.map(act => `<button type="button" role="menuitem"${act === 'ban' ? ' class="ui-text-fail"' : ''} data-gs-act="${act}" data-gs-at="${index}">${GS_MENU_LABELS[act]}</button>`).join(''),
        { icon: GS_DOTS, cls: 'ui-gs-dots', attrs: 'tabindex="-1" data-gs-act="menu"' });
    return `<div class="ui-gs-acts" role="gridcell">${buttons}${menu}</div>`;
}

function gsItem(category, item, q) {
    const index = gsShown.push(item) - 1;
    const on = index === gsActive;
    return `<div class="ui-gs-row${on ? ' is-active' : ''}" role="row" data-gs-index="${index}">`
        + `<div class="ui-gs-item" id="ui-gs-opt-${index}" role="gridcell" aria-selected="${on}">`
        + `<span class="ui-gs-ic">${gsIcon(category)}</span><b>${gsMark(item.title, q)}</b><small>${gsMark(item.sub, q)}</small>${item.at ? `<span class="ui-gs-at">${escapeHtml(item.at)}</span>` : ''}</div>`
        + gsActsHtml(index, item, gsActs(item))
        + '</div>';
}

function gsCountText(result) {
    if (!result || result.short) return '';
    if (result.loading) return '…';
    if (result.failed) return '!';
    return Number(result.count).toLocaleString();
}

// The panel's three parts, made once: the grid keeps its id, which the field's
// aria-controls names, while its rows are drawn again
function gsPanelParts() {
    const panel = gsEl('ui-gs-panel');
    if (!panel) return null;
    if (!gsEl('ui-gs-grid')) {
        panel.innerHTML = '<nav class="ui-gs-tabs" role="tablist" aria-label="Result types"></nav>'
            + '<div class="ui-gs-body" id="ui-gs-grid" role="grid" aria-label="Results" aria-readonly="true"></div>'
            + '<div class="ui-gs-keys" aria-hidden="true"></div>';
    }
    return { panel, tabs: panel.querySelector('.ui-gs-tabs'), grid: gsEl('ui-gs-grid'), keys: panel.querySelector('.ui-gs-keys') };
}
let gsDrawn = '';   // the query and tab last drawn: a new one starts at the top

function gsRender() {
    const parts = gsPanelParts();
    if (!parts) return;
    const { panel, grid } = parts;
    const root = gsEl('ui-gs');
    root.classList.toggle('has-q', !!gsQuery);
    gsShown = [];
    if (!gsQuery) {
        parts.tabs.innerHTML = grid.innerHTML = parts.keys.innerHTML = '';
        gsDrawn = '';
        gsEl('ui-gs-input').removeAttribute('aria-activedescendant');
        return;
    }
    const q = gsQuery.toLowerCase();
    // A category that has nothing to search right now (no suppression list) is left out
    const categories = gsCategories();
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

    // Every line of the results is a row of the grid: a note too
    const note = (cls, html) => `<p class="${cls}" role="row"><span role="gridcell">${html}</span></p>`;
    let body = '';
    if (gsTab === 'all') {
        categories.forEach(c => {
            const r = gsResults[c.id];
            if (!r || !r.count) return;
            body += `<div class="ui-gs-sec" role="row"><span role="gridcell">${escapeHtml(c.label)} · ${Number(r.count).toLocaleString()}</span>${r.count > GS_SUMMARY ? `<span role="gridcell"><button type="button" class="ui-link" data-gs-tab="${c.id}">See all</button></span>` : ''}</div>`
                + r.items.slice(0, GS_SUMMARY).map(item => gsItem(c.id, item, q)).join('');
        });
        if (!body) body = note('ui-gs-empty', loading ? 'Searching…' : short ? GS_SHORT : `Nothing found for “${escapeHtml(gsQuery)}”`);
        else if (loading) body += note('ui-gs-wait', 'Still searching…');
        else if (short) body += note('ui-gs-wait', GS_SHORT);
    } else {
        const r = gsResults[gsTab] || { count: 0, items: [] };
        if (r.more && r.count) {
            const index = gsShown.push(r.more) - 1;
            body += `<div role="row"><div class="ui-gs-more${index === gsActive ? ' is-active' : ''}" id="ui-gs-opt-${index}" data-gs-index="${index}" role="gridcell" aria-selected="${index === gsActive}"><span><b>${Number(r.count).toLocaleString()}</b> found</span><span class="ui-link">${escapeHtml(r.more.label)}</span></div></div>`;
        }
        body += r.items.map(item => gsItem(gsTab, item, q)).join('');
        if (r.count > r.items.length && !r.more) body += note('ui-gs-wait', `The first ${r.items.length} of ${Number(r.count).toLocaleString()}`);
        if (r.short) body = note('ui-gs-empty', GS_SHORT);
        else if (r.loading) body = note('ui-gs-empty', 'Searching…');
        else if (r.failed) body = note('ui-gs-empty', 'This search failed. Try again in a moment.');
        else if (!r.items.length) body = note('ui-gs-empty', `Nothing found for “${escapeHtml(gsQuery)}”`);
    }
    if (gsActive >= gsShown.length) gsActive = Math.max(0, gsShown.length - 1);
    // Enter opens an entity's card and a job on Status > Jobs: the keys line says which
    const hint = (gsShown[gsActive] || {}).hint;
    const enter = hint === 'card' ? 'open card' : hint === 'job' ? 'open job' : 'open';

    // A row's button that had the focus goes with the redraw: the keys stay in the search
    const inActs = !!(document.activeElement && panel.contains(document.activeElement) && document.activeElement.closest('.ui-gs-acts'));
    parts.tabs.innerHTML = tabs;
    grid.innerHTML = body;
    parts.keys.innerHTML = `<span><kbd>↑</kbd><kbd>↓</kbd> move</span><span><kbd>Tab</kbd> type</span><span><kbd>Enter</kbd> ${enter}</span><span><kbd>Esc</kbd> close</span>`;
    if (gsDrawn !== `${gsTab}|${gsQuery}`) {
        gsDrawn = `${gsTab}|${gsQuery}`;
        grid.scrollTop = 0;
    }
    const active = panel.querySelector('.ui-gs-row.is-active > .ui-gs-item, .ui-gs-more.is-active');
    active?.closest('[role="row"]').scrollIntoView({ block: 'nearest' });
    if (inActs) gsToField();
    // The field keeps the focus while Up and Down move: a screen reader reads the active result
    const input = gsEl('ui-gs-input');
    if (active && gsEl('ui-gs').classList.contains('is-open')) input.setAttribute('aria-activedescendant', active.id);
    else input.removeAttribute('aria-activedescendant');
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
    input.removeAttribute('aria-activedescendant');
    if (root.classList.contains('is-sheet')) {
        root.classList.remove('is-sheet');
        document.documentElement.classList.remove('ui-gs-locked');
        gsEl('ui-topbar').insertBefore(root, gsEl('ui-topbar-actions'));
    }
    if (document.activeElement === input) input.blur();
}

// item.keep names the dialog a result opens over the search (a message, a card),
// which stays for the next one
function gsChoose(index) {
    const item = gsShown[index];
    if (!item) return;
    if (item.keep) {
        const input = gsEl('ui-gs-input');
        const page = location.pathname + location.search;
        input.blur();
        item.open();
        const layer = gsEl(item.keep);
        if (layer) {
            const watch = new MutationObserver(() => {
                if (!layer.classList.contains('hidden')) return;
                watch.disconnect();
                if (!gsEl('ui-gs').classList.contains('is-open')) return;
                // It moved to another page (Show messages in a card): the search is done
                // there, and the focus goes to that page, not back to the field
                if (location.pathname + location.search !== page) {
                    if (typeof uiLayerReturn === 'function') uiLayerReturn(layer, null);
                    gsClose(true);
                }
                // Back from it, the keys work in the search again (not on a phone: no keyboard)
                else if (!gsPhone()) input.focus({ preventScroll: true });
            });
            watch.observe(layer, { attributes: true, attributeFilter: ['class'] });
        }
        return;
    }
    gsClose(true);
    item.open();
}

// The field again, the caret at its end, while the search is open (not on a phone)
function gsToField() {
    const input = gsEl('ui-gs-input');
    if (!input || !gsEl('ui-gs').classList.contains('is-open') || gsPhone()) return;
    input.focus({ preventScroll: true });
    const end = input.value.length;
    try { input.setSelectionRange(end, end); } catch (e) { /* a field that has no caret */ }
}

// A kind's results read again (after a ban or a run), the tab and the active row kept
function gsRefresh(id) {
    const asked = gsQuery;
    const q = asked.toLowerCase();
    if (id === 'jobs') gsJobs = null;
    if (!q || q.length < GS_SERVER_FROM || !GS_REMOTE[id]) return Promise.resolve();
    return GS_REMOTE[id](q, undefined)
        .then(result => { if (gsQuery === asked) { gsResults[id] = result; gsRender(); } })
        .catch(() => {});
}

// A row's button, or its item in the phone row menu
async function gsAct(index, act, button) {
    const item = gsShown[index];
    if (!item) return;
    if (act === 'card' || act === 'job') return gsChoose(index);
    const offered = gsActs(item).find(a => a.act === act);
    if (!offered || offered.disabled) return;
    // A menu item is not a button banIP can show its progress on
    const own = button && !button.closest('.ui-menu') ? button : null;
    const opener = gsOpener();
    if (opener && typeof uiLayerOpener === 'function') uiLayerOpener(opener);
    if (act === 'ban' || act === 'allow') {
        // Their own confirmation, as on the Security list and in the card
        const done = await (act === 'ban' ? banIP : allowIP)(item.entity.value, own);
        if (done) await gsRefresh('addresses');
        gsToField();
        return;
    }
    if (act === 'run') return gsRunJob(item.job);
}

// What a job does, as the end of a sentence: the Status page's description
function gsJobEffect(description) {
    const text = String(description || '').trim().replace(/\.$/, '');
    if (!text) return '';
    // "Imports logs" reads "imports logs"; a name in capitals ("DNS") stays
    return /^[A-Z][a-z]/.test(text) ? text.charAt(0).toLowerCase() + text.slice(1) : text;
}

// Run asks first, naming the job and what it does; the run itself is the Status
// page's (app.js runBackgroundJob), which says when the job is already running or
// cannot run now. The row then shows the job as the server has it
async function gsRunJob(job) {
    if (!job || job.off || job.running) return;
    const effect = gsJobEffect(job.description);
    const ok = await showConfirmModal({
        title: `Run ${job.name}`,
        message: `${job.name} runs once now, outside its schedule${effect ? `, and ${effect}` : ''}.`,
        confirmText: 'Run',
        // What it does can write to mailcow: the question starts on Cancel
        focusCancel: true
    });
    if (ok) {
        await runBackgroundJob(job.key, job.name);
        await gsRefresh('jobs');
    }
    gsToField();
}

// A kind's tab starts on its first result, after the box that opens them all
function gsSetTab(id) {
    gsTab = id;
    const r = gsResults[id];
    gsActive = r && r.more && r.count && r.items.length ? 1 : 0;
    gsRender();
}

function gsStepTab(step) {
    // The same kinds as the tabs drawn, in their order: one with nothing to search is left out
    const ids = ['all', ...gsCategories().map(c => c.id)];
    gsSetTab(ids[(ids.indexOf(gsTab) + step + ids.length) % ids.length]);
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
    if (!(await navigateTo('settings', { sub: setting.tab }))) return;
    const row = el => el.closest('.ui-set-field, .ui-set-bool, .ui-set-wide');
    const find = () => {
        const el = gsEl('edit-' + setting.key) || gsEl('setting-' + setting.key);
        // A value kept in a hidden field (the Time Zone picker, Features) is seen through its row
        const box = el && (el.type === 'hidden' || el.hidden) ? row(el) : el;
        return box && box.offsetParent ? el : null;
    };
    const show = el => {
        gsReveal(row(el) || el);
        // A hidden field takes the focus through the control that sets it
        const target = el.type !== 'hidden' && !el.hidden ? el : row(el)
            && row(el).querySelector('button:not([disabled]), select:not([disabled]), input:not([type="hidden"]):not([disabled])');
        if (target) target.focus({ preventScroll: true });
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
    if (!(await navigateTo('domains'))) return;
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
    if (!(await navigateTo('mailbox-stats', { sub: 'statistics' }))) return;
    if (already) applyMailboxStatsFilters();
    if (!username) return;
    const found = await gsWaitFor(() => (mailboxStatsCache.mailboxes || []).some(m => m.username === username));
    if (!found) return;
    const index = mailboxStatsCache.mailboxes.findIndex(m => m.username === username);
    const content = gsEl('accordion-content-' + index);
    if (content && content.classList.contains('hidden')) toggleMailboxAccordion(username);
    gsReveal(content ? content.parentElement : null, 'start');
}

// Outbound > Suppressions, listing what the search found in every state
async function gsOpenSuppressions(text) {
    const search = gsEl('suppression-search');
    if (search) search.value = text;
    const reason = gsEl('suppression-filter-reason');
    if (reason) reason.value = '';
    const active = gsEl('suppression-filter-active');
    if (active) active.value = '';
    // The list keeps the filters it was last asked with: it reads them again from the fields
    suppressionQuery = null;
    const already = gsPageOpen('outbound') && outboundTab === 'suppressions';
    if (!(await navigateTo('outbound', { sub: 'suppressions' }))) return;
    if (already) loadSuppressions(1);
}

// Security > Banned with every country and network, since a network row has neither
function gsOpenBannedNetwork() {
    securityCountry = null;
    securityNetwork = null;
    if (gsPageOpen('netfilter') && securityTab === 'overview') setSecurityFilter('banned');
    else openSecurityList('banned');
}

// The Security page's events for the address
async function gsOpenAddress(ip) {
    ['netfilter-filter-username', 'netfilter-filter-action', 'netfilter-filter-country'].forEach(id => {
        const field = gsEl(id);
        if (field) field.value = '';
    });
    const field = gsEl('netfilter-filter-ip');
    if (field) field.value = ip;
    currentFilters.netfilter = { ip, username: '', action: '', country_code: '' };
    currentPage.netfilter = 1;
    const already = gsPageOpen('netfilter');
    if (!(await navigateTo('netfilter', { sub: 'events' }))) return;
    if (already) applyNetfilterFilters();
}

// Status > Jobs, on the job's row: its group opened, every job shown
async function gsOpenJob(key) {
    if (!(await navigateTo('status', { sub: 'jobs' }))) return;
    const find = () => [...document.querySelectorAll('#status-jobs .ui-jobrow[data-job]')].find(row => row.dataset.job === key) || null;
    const show = row => {
        if (row.hidden && typeof statusJobFilter === 'function') statusJobFilter('all');
        const group = row.closest('details');
        if (group && !group.open) group.open = true;
        gsReveal(row, 'start');
    };
    let row = await gsWaitFor(find);
    if (!row) return;
    show(row);
    // The page draws its jobs again once its own read answers: find the row again
    const started = Date.now();
    const keep = () => {
        if (Date.now() - started > 4000) return;
        if (!row.isConnected) {
            row = find();
            if (!row) return;
            show(row);
        }
        setTimeout(keep, 150);
    };
    setTimeout(keep, 150);
}

// The controls of a row's button cell that can be used here: the buttons on a
// desktop, the "..." button on a phone (the CSS shows one or the other)
function gsActControls(cell) {
    const all = [...cell.querySelectorAll(':scope > button')];
    return all.filter(b => !b.disabled && (gsPhone() ? b.classList.contains('ui-gs-dots') : !b.classList.contains('ui-gs-dots')));
}

// Right at the end of the field: into the active row's first button
function gsIntoActs() {
    const input = gsEl('ui-gs-input');
    if (input.selectionStart !== input.value.length || input.selectionEnd !== input.value.length) return false;
    const cell = gsEl('ui-gs-panel').querySelector('.ui-gs-row.is-active > .ui-gs-acts');
    const first = cell ? gsActControls(cell)[0] : null;
    if (!first) return false;
    first.focus({ preventScroll: true });
    return true;
}

// Between a row's buttons; back past the first one is the field again
function gsStepAct(cell, from, step) {
    const controls = gsActControls(cell);
    const next = controls.indexOf(from) + step;
    if (next < 0) gsToField();
    else if (next < controls.length) controls[next].focus({ preventScroll: true });
}

// ----------------------------------------------------------------- wiring

function initGlobalSearch() {
    const root = gsEl('ui-gs');
    const input = gsEl('ui-gs-input');
    const panel = gsEl('ui-gs-panel');
    if (!root || !input || !panel) return;
    gsPanelParts();

    input.addEventListener('focus', gsOpen);
    input.addEventListener('input', () => gsRun(input.value));
    // The keys work from the field and from a tab or a result that has the focus:
    // Up and Down move in the results, Left and Right on a tab switch the kind.
    // Right from the end of the field goes into the active row's buttons, where Left
    // and Right move between them; Left from the first one, or Escape, goes back
    root.addEventListener('keydown', event => {
        // A row menu that is open keeps its own keys (Escape closes it)
        if (event.target.closest('.ui-menu')) return;
        // While an input method composes a word, its keys are the word's, not the search's
        if (event.isComposing || event.keyCode === 229) return;
        const plain = !event.shiftKey && !event.ctrlKey && !event.metaKey && !event.altKey;
        const onTab = !!event.target.closest('[data-gs-tab]');
        const inPanel = panel.contains(event.target);
        const inActs = event.target.closest('.ui-gs-acts');
        if (event.target !== input && !inPanel) return;
        const rtl = getComputedStyle(root).direction === 'rtl';
        const forward = rtl ? 'ArrowLeft' : 'ArrowRight';
        const backward = rtl ? 'ArrowRight' : 'ArrowLeft';
        if (inActs && plain && (event.key === forward || event.key === backward)) {
            event.preventDefault();
            gsStepAct(inActs, event.target, event.key === forward ? 1 : -1);
        } else if (inActs && event.key === 'Escape') {
            event.preventDefault();
            event.stopPropagation();
            gsToField();
        } else if (event.target === input && event.key === forward && plain && gsIntoActs()) {
            event.preventDefault();
        } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault();
            if (!gsShown.length) return;
            gsActive = (gsActive + (event.key === 'ArrowDown' ? 1 : -1) + gsShown.length) % gsShown.length;
            gsRender();
            if (inPanel && !root.classList.contains('is-sheet')) input.focus({ preventScroll: true });
        } else if ((event.key === 'ArrowLeft' || event.key === 'ArrowRight') && onTab) {
            event.preventDefault();
            gsStepTab((event.key === 'ArrowRight') !== rtl ? 1 : -1);
            panel.querySelector('.ui-gs-tab.is-on')?.focus();
        } else if (event.key === 'Enter' && !inPanel) {
            event.preventDefault();
            gsChoose(gsActive);
        } else if (event.key === 'Tab' && gsQuery) {
            event.preventDefault();
            gsStepTab(event.shiftKey ? -1 : 1);
            if (inPanel && !root.classList.contains('is-sheet')) input.focus({ preventScroll: true });
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
        if (event.target.closest('button, [data-gs-index]') && !sheet()) event.preventDefault();
    });
    panel.addEventListener('click', event => {
        const tab = event.target.closest('[data-gs-tab]');
        if (tab) {
            gsSetTab(tab.dataset.gsTab);
            if (sheet()) input.blur();
            else input.focus();
            return;
        }
        // A row's button (or the item of its menu) acts and leaves the row; the "..."
        // button only opens its menu
        const act = event.target.closest('[data-gs-act]');
        if (act) {
            if (act.dataset.gsAct !== 'menu') gsAct(Number(act.dataset.gsAt), act.dataset.gsAct, act);
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
