const GS_CATEGORIES = [
    { id: 'pages', label: 'Pages' },
    { id: 'settings', label: 'Settings', area: 'admin' },
    { id: 'jobs', label: 'Background jobs', feature: null, area: 'status' },
    { id: 'messages', label: 'Messages', feature: null, area: 'messages' },
    { id: 'domains', label: 'Domains', feature: 'domains', area: 'domains' },
    { id: 'mailboxes', label: 'Mailboxes', feature: 'mailbox-stats', area: 'mailboxes' },
    { id: 'suppressions', label: 'Suppressions', feature: 'suppressions', area: 'outbound' },
    { id: 'addresses', label: 'IP addresses', feature: 'netfilter', area: 'security' }
];
const GS_LIMIT = 10;
const GS_SUMMARY = 3;
const GS_SERVER_FROM = 2;
const GS_SHORT = 'Type one more character to search the messages, domains, mailboxes, suppressions, addresses and background jobs too.';
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
const GS_DOTS = '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><circle cx="5" cy="12" r="1.8"></circle><circle cx="12" cy="12" r="1.8"></circle><circle cx="19" cy="12" r="1.8"></circle></svg>';

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
    if (category.area && !userCan(category.area)) return true;
    if (category.id === 'settings' && window.settingsEditable === false) return true;
    return !!(category.feature && window.disabledFeatures && window.disabledFeatures.includes(category.feature));
}

function gsMatch(text, q) {
    return String(text || '').toLowerCase().includes(q);
}

function gsMark(text, q) {
    const value = String(text || '');
    const at = q ? value.toLowerCase().indexOf(q) : -1;
    if (at < 0) return escapeHtml(value);
    return escapeHtml(value.slice(0, at)) + '<mark>' + escapeHtml(value.slice(at, at + q.length)) + '</mark>'
        + escapeHtml(value.slice(at + q.length));
}

function gsVisible(el) {
    return !!el && el.style.display !== 'none' && !el.classList.contains('hidden') && !el.classList.contains('ui-no-view');
}

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
    if (typeof settingsSearchIndex !== 'function' || !userIsAdmin()) return [];
    const found = settingsSearchIndex().filter(s => gsMatch(s.label, q) || gsMatch(s.key, q));
    return [...found.filter(s => gsMatch(s.label, q)), ...found.filter(s => !gsMatch(s.label, q))]
        .map(s => ({ title: s.label, sub: 'Settings › ' + s.tabLabel + (gsMatch(s.label, q) ? '' : ' · ' + s.key),
            open: () => gsOpenSetting(s) }));
}

async function gsJson(url, signal) {
    const response = await authenticatedFetch(url, { signal });
    if (!response.ok) throw await responseError(response);
    return response.json();
}

async function gsSearchMessages(q, signal) {
    const data = await gsJson(`/api/messages?search=${encodeURIComponent(q)}&page=1&limit=${GS_LIMIT}`, signal);
    return {
        count: data.total || 0,
        items: (data.data || []).map(m => ({
            title: m.subject || '(no subject)',
            sub: (m.sender || '') + ' → ' + (m.recipient || ''),
            subTag: renderRecipientMore(m),
            at: formatAgo(m.first_seen || m.last_seen),
            open: () => viewMessageDetails(m.correlation_key),
            keep: 'message-modal'
        })),
        more: { label: 'Open in Messages', open: () => navigateToMessagesWithFilter({ email: q, filterType: 'search' }) }
    };
}

async function gsSearchDomains(q, signal) {
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
    if (data.error) throw new Error(data.error);
    return {
        count: data.total || 0,
        items: (data.mailboxes || []).map(m => gsEntityItem('address', m.username, {
            sub: m.name || 'Mailbox',
            open: () => gsOpenMailbox(m.username)
        })),
        more: { label: 'Open in Mailbox Stats', open: () => gsOpenMailbox(null, q) }
    };
}

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
            open: () => gsOpenSuppressions(shown(s.email))
        })),
        more: { label: 'Open in Suppressions', open: () => gsOpenSuppressions(q) }
    };
}

async function gsSearchAddresses(q, signal) {
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
            open: () => a.network_size ? gsOpenBannedNetwork() : gsOpenAddress(a.ip)
        };
        return a.network_size ? { title: a.ip, ...fields } : gsEntityItem('ip', a.ip, fields);
    });
    let count = (counts.review || 0) + (counts.banned || 0);
    const typed = q.trim();
    if (entityKindOf(typed) === 'ip' && !rows.some(a => String(a.ip).toLowerCase() === typed.toLowerCase())) {
        const { value, sub } = await gsTypedIp(typed, signal);
        items.unshift(gsEntityItem('ip', value, { sub, title: typed }));
        count += 1;
    }
    return { count, items };
}

const GS_IP_ACTIVITY = [
    ['messages', s => s.count, 'message', 'messages'],
    ['security', s => s.events, 'security event', 'security events'],
    ['protection', s => s.count, 'protection catch', 'protection catches'],
    ['devices', s => s.count, 'device', 'devices'],
    ['dmarc', s => s.messages, 'DMARC message', 'DMARC messages'],
];

async function gsTypedIp(ip, signal) {
    if (!userCanOpenEntity('ip')) return { value: ip, sub: 'Not in these results' };
    let data = null;
    try {
        data = await gsJson(`/api/entities/ip?value=${encodeURIComponent(ip)}`, signal);
    } catch (error) {
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
    const unread = GS_IP_ACTIVITY.filter(([name]) => !sources[name] || !['ok', 'disabled'].includes(sources[name].state));
    if (data && read.length && !unread.length) return { value, sub: `No activity${within}` };
    return { value, sub: 'Not in these results' };
}

function gsEntityItem(kind, value, { sub = '', at = '', open = null, title = '' } = {}) {
    const text = String(value || '').trim();
    if (entityKindOf(text) !== kind || !userCanOpenEntity(kind)) return { title: title || text, sub, at, open: open || (() => {}) };
    return { title: title || text, sub, at, entity: { kind, value: text }, hint: 'card', keep: 'entity-card',
        open: () => openEntityCard(kind, text, { from: gsOpener() }) };
}

function gsOpener() {
    return gsPhone() ? null : gsEl('ui-gs-input');
}

function gsJobList() {
    if (!gsJobs || typeof statusJobCategories !== 'function') return [];
    return statusJobCategories(gsJobs).flatMap(c => c.jobs).filter(([, , job]) => job);
}

function gsJobOff(job) {
    return job.status === 'disabled' || job.enabled === false || job.feature_disabled === true;
}

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

function gsLead(q) {
    if (!q) return null;
    if (entityKindOf(q) === 'ip') return 'addresses';
    if (GS_JOB_WORDS.test(q)) return 'jobs';
    if (!(gsResults.pages && gsResults.pages.count) && gsJobList().some(([name]) => gsMatch(name, q))) return 'jobs';
    return null;
}

function gsCategories() {
    const list = GS_CATEGORIES.filter(c => !gsOff(c) && !gsResults[c.id]?.hidden);
    const at = list.findIndex(c => c.id === gsLead(gsQuery.toLowerCase()));
    if (at > 0) list.unshift(list.splice(at, 1)[0]);
    return list;
}

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

function gsIcon(id) {
    return `<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24" aria-hidden="true">${GS_ICONS[id]}</svg>`;
}

const gsRw = () => typeof mailcowRwConfigured !== 'undefined' && !!mailcowRwConfigured;

function gsActs(item) {
    if (item.entity) {
        const acts = [{ act: 'card' }];
        if (item.entity.kind === 'ip' && gsRw() && userCan('security', 'write')) acts.push({ act: 'ban' }, { act: 'allow' });
        return acts;
    }
    if (item.job && !item.job.off && userIsAdmin()) return [{ act: 'run', disabled: item.job.running }];
    return [];
}

function gsActTitle(item, act) {
    const entry = item.entity && typeof fail2banEntry === 'function' ? fail2banEntry(item.entity.value) : item.title;
    const what = item.entity ? { ip: 'IP address', address: 'address', domain: 'domain' }[item.entity.kind] : '';
    return {
        card: `Open the card of this ${what}`,
        ban: `Put ${entry} on the Fail2ban denylist; it stays until removed`,
        allow: `Never ban ${entry}`,
        run: item.job && item.job.running ? 'Job is running' : 'Run this job now'
    }[act];
}

const GS_ACT_LABELS = { card: 'Card', ban: 'Ban', allow: 'Allow', run: 'Run' };
const GS_MENU_LABELS = { card: 'Open card', job: 'Open job', ban: 'Ban', allow: 'Allow', run: 'Run' };

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
        + `<span class="ui-gs-ic">${gsIcon(category)}</span><b>${gsMark(item.title, q)}</b>${item.subTag ? `<small class="ui-gs-sub"><span>${gsMark(item.sub, q)}</span>${item.subTag}</small>` : `<small>${gsMark(item.sub, q)}</small>`}${item.at ? `<span class="ui-gs-at">${escapeHtml(item.at)}</span>` : ''}</div>`
        + gsActsHtml(index, item, gsActs(item))
        + '</div>';
}

function gsCountText(result) {
    if (!result || result.short) return '';
    if (result.loading) return '…';
    if (result.failed) return '!';
    return Number(result.count).toLocaleString();
}

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
let gsDrawn = '';

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

    const note = (cls, html) => `<p class="${cls}" role="row"><span role="gridcell">${html}</span></p>`;
    let body = '';
    if (gsTab === 'all') {
        categories.forEach(c => {
            const r = gsResults[c.id];
            if (!r || !r.count) return;
            body += `<div class="ui-gs-sec" role="row"><span role="gridcell">${escapeHtml(c.label)} · ${Number(r.count).toLocaleString()}</span>${r.count > GS_SUMMARY ? `<span role="gridcell"><button type="button" class="ui-link" data-gs-tab="${c.id}">See all</button></span>` : ''}</div>`
                + r.items.slice(0, GS_SUMMARY).map(item => gsItem(c.id, item, q)).join('');
        });
        const failed = categories.filter(c => gsResults[c.id] && gsResults[c.id].failed).map(c => c.label);
        const notSearched = failed.length ? `Could not search ${failed.join(', ')}. Try again in a moment.` : '';
        if (!body) body = note('ui-gs-empty', loading ? 'Searching…' : short ? GS_SHORT
            : `Nothing found for “${escapeHtml(gsQuery)}”${notSearched ? `. ${escapeHtml(notSearched)}` : ''}`);
        else if (loading) body += note('ui-gs-wait', 'Still searching…');
        else if (short) body += note('ui-gs-wait', GS_SHORT);
        else if (notSearched) body += note('ui-gs-wait', escapeHtml(notSearched));
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
    const hint = (gsShown[gsActive] || {}).hint;
    const enter = hint === 'card' ? 'open card' : hint === 'job' ? 'open job' : 'open';

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
    const input = gsEl('ui-gs-input');
    if (active && gsEl('ui-gs').classList.contains('is-open')) input.setAttribute('aria-activedescendant', active.id);
    else input.removeAttribute('aria-activedescendant');
}

function gsPhone() {
    return window.matchMedia('(max-width: 760px)').matches;
}

function gsOpen() {
    const root = gsEl('ui-gs');
    if (!root) return;
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
                if (location.pathname + location.search !== page) {
                    if (typeof uiLayerReturn === 'function') uiLayerReturn(layer, null);
                    gsClose(true);
                }
                else if (!gsPhone()) input.focus({ preventScroll: true });
            });
            watch.observe(layer, { attributes: true, attributeFilter: ['class'] });
        }
        return;
    }
    gsClose(true);
    item.open();
}

function gsToField() {
    const input = gsEl('ui-gs-input');
    if (!input || !gsEl('ui-gs').classList.contains('is-open') || gsPhone()) return;
    input.focus({ preventScroll: true });
    const end = input.value.length;
    try { input.setSelectionRange(end, end); } catch (e) {}
}

function gsRefresh(id) {
    const asked = gsQuery;
    const q = asked.toLowerCase();
    if (id === 'jobs') gsJobs = null;
    if (!q || q.length < GS_SERVER_FROM || !GS_REMOTE[id]) return Promise.resolve();
    return GS_REMOTE[id](q, undefined)
        .then(result => { if (gsQuery === asked) { gsResults[id] = result; gsRender(); } })
        .catch(() => {});
}

async function gsAct(index, act, button) {
    const item = gsShown[index];
    if (!item) return;
    if (act === 'card' || act === 'job') return gsChoose(index);
    const offered = gsActs(item).find(a => a.act === act);
    if (!offered || offered.disabled) return;
    const own = button && !button.closest('.ui-menu') ? button : null;
    const opener = gsOpener();
    if (opener && typeof uiLayerOpener === 'function') uiLayerOpener(opener);
    if (act === 'ban' || act === 'allow') {
        const done = await (act === 'ban' ? banIP : allowIP)(item.entity.value, own);
        if (done) await gsRefresh('addresses');
        gsToField();
        return;
    }
    if (act === 'run') return gsRunJob(item.job);
}

function gsJobEffect(description) {
    const text = String(description || '').trim().replace(/\.$/, '');
    if (!text) return '';
    return /^[A-Z][a-z]/.test(text) ? text.charAt(0).toLowerCase() + text.slice(1) : text;
}

async function gsRunJob(job) {
    if (!job || job.off || job.running) return;
    const effect = gsJobEffect(job.description);
    const ok = await showConfirmModal({
        title: `Run ${job.name}`,
        message: `${job.name} runs once now, outside its schedule${effect ? `, and ${effect}` : ''}.`,
        confirmText: 'Run',
        focusCancel: true
    });
    if (ok) {
        await runBackgroundJob(job.key, job.name);
        await gsRefresh('jobs');
    }
    gsToField();
}

function gsSetTab(id) {
    gsTab = id;
    const r = gsResults[id];
    gsActive = r && r.more && r.count && r.items.length ? 1 : 0;
    gsRender();
}

function gsStepTab(step) {
    const ids = ['all', ...gsCategories().map(c => c.id)];
    gsSetTab(ids[(ids.indexOf(gsTab) + step + ids.length) % ids.length]);
}

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
        for (let fold = el && el.closest('details:not([open])'); fold; fold = fold.parentElement.closest('details:not([open])')) fold.open = true;
        const box = el && (el.type === 'hidden' || el.hidden) ? row(el) : el;
        return box && box.offsetParent ? el : null;
    };
    const show = el => {
        gsReveal(row(el) || el);
        const target = el.type !== 'hidden' && !el.hidden ? el : row(el)
            && (row(el).querySelector('[data-search-focus]:not([disabled])')
                || row(el).querySelector('button:not([disabled]), select:not([disabled]), input:not([type="hidden"]):not([disabled])'));
        if (target) target.focus({ preventScroll: true });
    };
    let field = await gsWaitFor(find);
    if (!field) return;
    show(field);
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

async function gsOpenSuppressions(text) {
    const search = gsEl('suppression-search');
    if (search) search.value = text;
    const reason = gsEl('suppression-filter-reason');
    if (reason) reason.value = '';
    const active = gsEl('suppression-filter-active');
    if (active) active.value = '';
    suppressionQuery = null;
    const already = gsPageOpen('outbound') && outboundTab === 'suppressions';
    if (!(await navigateTo('outbound', { sub: 'suppressions' }))) return;
    if (already) loadSuppressions(1);
}

function gsOpenBannedNetwork() {
    securityCountry = null;
    securityNetwork = null;
    if (gsPageOpen('netfilter') && securityTab === 'overview') setSecurityFilter('banned');
    else openSecurityList('banned');
}

async function gsOpenAddress(ip) {
    ['netfilter-filter-username', 'netfilter-filter-action', 'netfilter-filter-country'].forEach(id => {
        const field = gsEl(id);
        if (field) field.value = '';
    });
    const field = gsEl('netfilter-filter-ip');
    if (field) field.value = ip;
    setNetfilterFilters({ ip, username: '', action: '', country_code: '' });
    currentPage.netfilter = 1;
    const already = gsPageOpen('netfilter');
    if (!(await navigateTo('netfilter', { sub: 'events' }))) return;
    if (already) applyNetfilterFilters();
}

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

function gsActControls(cell) {
    const all = [...cell.querySelectorAll(':scope > button')];
    return all.filter(b => !b.disabled && (gsPhone() ? b.classList.contains('ui-gs-dots') : !b.classList.contains('ui-gs-dots')));
}

function gsIntoActs() {
    const input = gsEl('ui-gs-input');
    if (input.selectionStart !== input.value.length || input.selectionEnd !== input.value.length) return false;
    const cell = gsEl('ui-gs-panel').querySelector('.ui-gs-row.is-active > .ui-gs-acts');
    const first = cell ? gsActControls(cell)[0] : null;
    if (!first) return false;
    first.focus({ preventScroll: true });
    return true;
}

function gsStepAct(cell, from, step) {
    const controls = gsActControls(cell);
    const next = controls.indexOf(from) + step;
    if (next < 0) gsToField();
    else if (next < controls.length) controls[next].focus({ preventScroll: true });
}

function initGlobalSearch() {
    const root = gsEl('ui-gs');
    const input = gsEl('ui-gs-input');
    const panel = gsEl('ui-gs-panel');
    if (!root || !input || !panel) return;
    gsPanelParts();

    input.addEventListener('focus', gsOpen);
    input.addEventListener('input', () => gsRun(input.value));
    root.addEventListener('keydown', event => {
        if (event.target.closest('.ui-menu')) return;
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

    document.addEventListener('mousedown', event => {
        if (event.target.closest && event.target.closest('.ui-dialog-backdrop, .ui-sheet')) return;
        if (root.classList.contains('is-open') && !root.contains(event.target) && !root.classList.contains('is-sheet')) gsClose(false);
    });
    input.addEventListener('blur', () => {
        setTimeout(() => {
            if (!root.contains(document.activeElement) && !input.value && !root.classList.contains('is-sheet')) gsClose(false);
        }, 0);
    });

    document.addEventListener('keydown', event => {
        if (event.key !== '/' || event.ctrlKey || event.metaKey || event.altKey) return;
        const target = event.target;
        if (target && (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName))) return;
        if ([...document.querySelectorAll('.ui-sheet, [role="dialog"], .modal')].some(el => el.getClientRects().length && !el.classList.contains('ui-docked'))) return;
        const field = gsPhone() || input.getClientRects().length ? null : document.getElementById('messages-filter-search');
        if (!gsPhone() && !input.getClientRects().length && !(field && field.getClientRects().length)) return;
        event.preventDefault();
        if (gsPhone()) gsEl('ui-gs-phone')?.click();
        else (field || input).focus();
    });
}

document.addEventListener('DOMContentLoaded', initGlobalSearch);
