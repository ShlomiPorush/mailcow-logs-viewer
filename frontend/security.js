// =============================================================================
// SECURITY PAGE - Overview
// Every address that tried to sign in or that a protection caught, once, with
// what happened to it and why: to review, banned (by Fail2ban or by a rule),
// tried and not banned, and the rules' history. Above it, which protections are
// on; beside it, where the attacks come from.
// Classic script sharing the global scope; loaded after app.js, smtp-abuse.js
// and protection.js, whose loaders call back into the functions here.
// =============================================================================

let securityOverview = null;     // /api/logs/netfilter/overview?hours=24
let securityHits = [];           // the rules' open hits: watching, pending, banned, alert
let securityHistory = null;      // closed hits, loaded when the History filter opens
let securityFilter = 'review';
let securityCountry = null;      // a country picked in the chart filters the list
let securityOpenRow = null;      // the address whose details are open
let securityRawLog = {};         // ip -> log lines, or 'loading' / 'error'
let securityShowAll = false;
let securityChartDays = 30;
let securityCountries = null;    // /stats/by-country
let securityNetworks = null;     // /stats/by-network
let fail2banLoadError = false;   // mailcow could not be asked about Fail2ban
let securityStripOpen = false;   // on a phone the Protection row folds into one chip
let securityCountryPicker = false;  // on a phone the countries open from the filter row

// A phone: the list gets its own layout (one line per address, details in a sheet)
const securityPhone = () => window.matchMedia('(max-width: 760px)').matches;

const SECURITY_LIST_PREVIEW = 25;
const SECURITY_FILTERS = [['review', 'To review'], ['banned', 'Banned'], ['quiet', 'Tried, not banned'], ['history', 'History']];
const SECURITY_RULE_ORDER = ['trap', 'unknown_accounts', 'repeat_offender', 'subnet', 'country', 'breach'];
const SECURITY_RULE_NAMES = {
    trap: 'Trap accounts', unknown_accounts: 'Unknown accounts', repeat_offender: 'Repeat offenders',
    subnet: 'Attacking networks', country: 'Countries', breach: 'Possible stolen password'
};

// ----------------------------------------------------------------- tabs

let securityTab = 'overview';
// The old addresses of the tabs that became Settings cards still open them
const SECURITY_TAB_ALIASES = { protection: null, fail2ban: 'fail2ban', abuse: 'abuse' };

function securityShowTab(tab) {
    let card;
    if (tab in SECURITY_TAB_ALIASES) {
        card = SECURITY_TAB_ALIASES[tab];
        tab = 'settings';
    }
    securityTab = tab;
    routerSyncSubpage('netfilter', tab, card !== undefined);
    document.querySelectorAll('.ui-se-tabs .modal-tab').forEach(btn => {
        const on = btn.id === `security-tab-btn-${tab}`;
        btn.classList.toggle('active', on);
        btn.setAttribute('aria-selected', on);
    });
    ['overview', 'lists', 'settings', 'events'].forEach(name => {
        const panel = document.getElementById(`security-tab-${name}`);
        if (panel) panel.classList.toggle('hidden', name !== tab);
    });
    if (tab !== 'overview' && document.getElementById('security-sheet')) securityCloseSheet();
    if (card) securityOpenCard(card);
}

// ----------------------------------------------------------------- loading

async function loadSecurityOverview() {
    try {
        const res = await authenticatedFetch('/api/logs/netfilter/overview?hours=24');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        securityOverview = await res.json();
        renderSecurityOverview();
    } catch (err) {
        console.error('Failed to load security overview:', err);
        const list = document.getElementById('security-list');
        if (list) list.innerHTML = `<p class="ui-empty ui-text-fail">Failed to load: ${escapeHtml(err.message)}</p>`;
    }
}

// The rules' open hits; the protection loader and the page timer call this
async function loadProtectionOverview() {
    try {
        const res = await authenticatedFetch('/api/protection/hits?status=active&limit=500');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        securityHits = data.hits || [];
        if (securityFilter === 'history') loadSecurityHistory();
        renderSecurityOverview();
        // The page's timer must not redraw a card or a list someone is working in
        if (!securityEditing()) {
            renderSecurityLists();      // which denylist entries a rule wrote
            renderSecuritySettings();   // how many each rule would ban
        }
    } catch (error) {
        console.error('Failed to load the protection hits:', error);
    }
}

async function loadSecurityHistory() {
    try {
        const res = await authenticatedFetch('/api/protection/hits?status=history&limit=200');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        securityHistory = (await res.json()).hits || [];
    } catch (error) {
        securityHistory = [];
        showToast(`Could not load the history: ${error.message}`, 'error');
    }
    renderSecurityOverview();
}

// ----------------------------------------------------------------- the addresses

const securityBare = entry => String(entry || '').replace(/\/(32|128)$/, '');

// The country's flag, before its name; nothing when the code is unknown
function securityFlag(code) {
    const url = code ? getFlagUrl(code, '16x12') : '';
    return url ? `<img class="ui-sec-flag" src="${url}" alt="" width="16" height="12" onerror="this.remove()">` : '';
}

// The code of a country the chart or the list named
function securityCountryCode(name) {
    const row = securityCountries && securityCountries.data.find(r => r.country_name === name);
    if (row) return row.country_code;
    const source = securityOverview && securityOverview.sources.find(s => s.country_name === name);
    return source ? source.country_code : '';
}
const securityOnList = (list, ip) => list.some(entry => securityBare(entry) === ip);

// One entry per address, from the last day's attempts, the rules' hits and Fail2ban's bans
function securityAddresses() {
    const map = new Map();
    const get = ip => {
        if (!map.has(ip)) map.set(ip, { ip, tries: 0, users: [], services: [], hits: [], country: '', countryCode: '', city: '', org: '', last: '' });
        return map.get(ip);
    };
    const seen = (a, iso) => { if (iso && iso > a.last) a.last = iso; };
    for (const s of (securityOverview && securityOverview.sources) || []) {
        const a = get(s.ip);
        Object.assign(a, { tries: s.failed_logins, attempts: s.attempts, users: s.usernames.slice(), services: s.services.slice(),
            country: s.country_name || '', countryCode: s.country_code || '', city: s.city || '', org: s.asn_org || '' });
        seen(a, s.last_seen);
    }
    for (const h of securityHits) {
        const a = get(h.ip);
        a.hits.push(h);
        a.country = a.country || h.country_name || '';
        a.countryCode = a.countryCode || h.country_code || '';
        (h.usernames || []).forEach(u => { if (!a.users.includes(u)) a.users.push(u); });
        seen(a, h.last_seen);
    }
    const permanent = new Set(fail2banPermBans.map(b => b.network || b.ip));
    for (const ban of fail2banActiveBans || []) {
        if (permanent.has(ban.network)) continue;
        const a = get(securityBare(ban.ip || ban.network));
        a.f2b = ban;
    }
    for (const a of map.values()) a.state = securityState(a);
    return [...map.values()];
}

// Where an address stands: review, banned, quiet, or a list (shown on the Lists, not here)
function securityState(a) {
    const open = a.hits.find(h => h.status === 'banned');
    if (fail2banActiveBans !== null && securityOnList(fail2banWhitelist, a.ip)) return 'allow';
    if (open) return 'banned';
    if (a.f2b) return 'banned';
    if (fail2banActiveBans !== null && securityOnList(fail2banBlacklist, a.ip)) return 'deny';
    if (a.hits.some(h => ['watching', 'pending', 'alert'].includes(h.status))) return 'review';
    return 'quiet';
}

function securityList(key, addresses) {
    if (key === 'history') return [];
    return addresses.filter(a => a.state === key && (key !== 'quiet' || a.tries > 0))
        .sort((x, y) => (y.last || '').localeCompare(x.last || ''));
}

// ----------------------------------------------------------------- what protects the server

function securityProtections() {
    const rules = (typeof protectionSaved !== 'undefined' && protectionSaved) || (typeof protectionRules !== 'undefined' && protectionRules);
    const caps = typeof protectionCaps !== 'undefined' ? protectionCaps : {};
    const item = (state, name, note, open) => {
        const mark = state === 'on' ? '✓' : state === 'unknown' ? '?' : '✕';
        const label = state === 'on' ? 'On' : state === 'unknown' ? 'Unknown' : 'Off';
        return `<button type="button" class="ui-prot-item is-${state}" onclick="${open}" title="${escapeHtml(`${name}: ${label}${note ? `, ${note}` : ''}`)}">
            <span class="ui-prot-mark" aria-label="${label}">${mark}</span>${escapeHtml(name)}${note ? `<small>${escapeHtml(note)}</small>` : ''}</button>`;
    };
    const f2b = fail2banLoadError ? item('unknown', 'Fail2ban', 'mailcow did not answer', "securityOpenProtection('fail2ban')")
        : fail2banPolicy ? item('on', 'Fail2ban', `${fail2banPolicy.max_attempts} tries, ${formatSeconds(fail2banPolicy.ban_time)}`, "securityOpenProtection('fail2ban')")
        : item('unknown', 'Fail2ban', '', "securityOpenProtection('fail2ban')");
    const rule = key => {
        if (!rules || !rules[key]) return '';
        const r = rules[key];
        const needs = key === 'country' && !caps.geoip ? 'needs MaxMind GeoIP' : '';
        if (needs) return item('off', SECURITY_RULE_NAMES[key], needs, `securityOpenProtection('${key}')`);
        if (!r.enabled) return item('off', SECURITY_RULE_NAMES[key], '', `securityOpenProtection('${key}')`);
        const doing = key === 'breach' ? 'alerts' : r.mode === 'enforce' && caps.can_ban ? 'bans' : 'watching';
        return item('on', SECURITY_RULE_NAMES[key], doing, `securityOpenProtection('${key}')`);
    };
    const abuse = typeof smtpAbuseStatus !== 'undefined' && smtpAbuseStatus
        ? item(smtpAbuseStatus.enabled ? 'on' : 'off', 'Outgoing spam', '', "securityOpenProtection('abuse')") : '';
    const items = [f2b, ...SECURITY_RULE_ORDER.map(rule), abuse].filter(Boolean);
    const on = items.filter(html => html.includes('is-on')).length;
    // On a phone the row folds into one chip that opens the list
    const summary = `<button type="button" class="ui-prot-sum" aria-expanded="${securityStripOpen}" onclick="securityStripOpen = !securityStripOpen; renderSecurityOverview()">
        Protection <b>${on} of ${items.length} on</b></button>`;
    return `${summary}<span class="ui-prot-title">Protection</span>${items.join('')}`;
}

// ----------------------------------------------------------------- one row

function securityRuleName(rule) {
    return SECURITY_RULE_NAMES[rule] || rule;
}

// The tag, the sentence that says why, and what can be done
function securityDescribe(a) {
    const rw = mailcowRwConfigured;
    const ipArg = escapeJsArg(a.ip);
    const hit = a.hits.find(h => h.status === 'banned') || a.hits.find(h => h.status === 'alert')
        || a.hits.find(h => h.status === 'pending') || a.hits.find(h => h.status === 'watching');
    const known = fail2banActiveBans !== null;
    const id = hit ? Number(hit.id) : 0;
    const B = 'type="button" class="ui-btn ui-btn-sm"';
    const undo = `<button ${B} onclick="undoProtectionHit(${id}, this)" title="Lift the ban; the rule leaves it alone for a week">Undo</button>`;
    const dismiss = `<button ${B} onclick="dismissProtectionHit(${id})" title="Not an attack: the rule leaves it alone for a week">Dismiss</button>`;
    if (a.state === 'banned' && hit && hit.status === 'banned') {
        return {
            tag: `${uiTag('Banned', 'fail')}<span class="ui-sec-by">by ${escapeHtml(securityRuleName(hit.rule))}</span>`,
            why: `${escapeHtml(hit.reason || '')}. Banned ${formatAgo(hit.banned_at || hit.last_seen)}, <b>${hit.expires_at ? `until ${escapeHtml(formatTime(hit.expires_at))}` : 'until removed'}</b>.`,
            acts: undo
        };
    }
    if (a.state === 'banned') {
        const tries = a.tries ? `${a.tries.toLocaleString()} failed login${a.tries === 1 ? '' : 's'} today. ` : '';
        return {
            tag: `${uiTag('Banned', 'fail')}<span class="ui-sec-by">by Fail2ban</span>`,
            why: `${tries}<b>${a.f2b.banned_until ? `${escapeHtml(a.f2b.banned_until)} left` : 'Banned now'}</b>, then Fail2ban lets it try again.${a.f2b.queued_for_unban ? ' Unbanning...' : ''}`,
            acts: rw && !a.f2b.queued_for_unban ? `<button ${B} onclick="unbanIP('${ipArg}', this)" title="Unban ${escapeHtml(a.ip)}/32">Unban</button>
                <button type="button" class="ui-btn ui-btn-sm ui-btn-danger" onclick="banIP('${ipArg}', this)" title="Put it on the denylist">Ban for good</button>` : ''
        };
    }
    if (a.state === 'review' && hit.status === 'alert') {
        return {
            tag: uiTag(securityRuleName(hit.rule), 'fail'),
            why: `${escapeHtml(hit.reason || '')}, ${formatAgo(hit.last_seen)}. <b>Alert only: nothing was banned.</b>`,
            acts: dismiss
        };
    }
    if (a.state === 'review' && hit.status === 'pending') {
        return {
            tag: uiTag(hit.error ? 'Not banned yet' : 'Banning', 'warn'),
            why: `${escapeHtml(securityRuleName(hit.rule))}: ${escapeHtml(hit.reason || '')}.${hit.error ? ` <span class="ui-text-fail">${escapeHtml(hit.error)}</span>` : ' The ban is written on the next run.'}`,
            acts: undo
        };
    }
    if (a.state === 'review') {
        const canBan = typeof protectionCaps !== 'undefined' && protectionCaps.can_ban;
        return {
            tag: uiTag(`Would ban: ${securityRuleName(hit.rule)}`, 'warn'),
            why: `${escapeHtml(hit.reason || '')}, ${formatAgo(hit.last_seen)}. The rule is watching, so nothing was banned.`,
            acts: (canBan ? `<button type="button" class="ui-btn ui-btn-sm ui-btn-danger" onclick="banProtectionHit(${id}, this)" title="Put it on the Fail2ban blacklist now">Ban now</button>` : '') + dismiss
        };
    }
    const policy = fail2banPolicy ? ` Fail2ban bans at ${fail2banPolicy.max_attempts} within ${formatSeconds(fail2banPolicy.retry_window)}.` : '';
    return {
        tag: uiTag('Not banned', ''),
        why: `${a.tries.toLocaleString()} failed login${a.tries === 1 ? '' : 's'} today${a.services.length ? ` (${escapeHtml(a.services.join(', '))})` : ''}.${policy}`,
        acts: rw && known ? `<button type="button" class="ui-btn ui-btn-sm ui-btn-danger" onclick="banIP('${ipArg}', this)" title="Ban ${escapeHtml(a.ip)}/32">Ban</button>
            <button ${B} onclick="allowIP('${ipArg}', this)" title="Never ban ${escapeHtml(a.ip)}/32">Allow</button>` : ''
    };
}

function securityRow(a) {
    const d = securityDescribe(a);
    const open = securityOpenRow === a.ip;
    const where = a.country || a.last ? `${a.country ? `${securityFlag(a.countryCode)}${escapeHtml(a.country)}` : ''}${a.country && a.last ? ' · ' : ''}${a.last ? formatAgo(a.last) : ''}` : '';
    return `
        <div class="ui-sec-row${open ? ' is-open' : ''}" onclick="securityRowClick(event, '${escapeJsArg(a.ip)}')" role="button" tabindex="0"
             onkeydown="if (event.key === 'Enter' && event.target === this) securityToggleRow('${escapeJsArg(a.ip)}')" aria-expanded="${open}">
            <div class="ui-sec-main">
                <div class="ui-sec-top">${a.country ? `<span class="ui-sec-pflag" title="${escapeHtml(a.country)}">${securityFlag(a.countryCode)}</span>` : ''}<b class="ui-mono">${copyableText(a.ip)}</b>${d.tag}${where ? `<small class="ui-muted ui-sec-where">${where}</small>` : ''}</div>
                <p class="ui-sec-why">${d.why}</p>
            </div>
            <div class="ui-sec-acts">${d.acts}</div>
            ${open && !securityPhone() ? securityDetail(a) : ''}
        </div>`;
}

// On a phone an address opens in a sheet from the bottom, so the list stays where it was
function renderSecuritySheet(addresses) {
    let sheet = document.getElementById('security-sheet');
    const a = securityPhone() && securityOpenRow && securityTab === 'overview' && addresses.find(x => x.ip === securityOpenRow);
    if (!a) {
        if (sheet) sheet.remove();
        document.body.classList.remove('ui-sec-sheet-on');
        return;
    }
    if (!sheet) {
        sheet = document.createElement('div');
        sheet.id = 'security-sheet';
        sheet.className = 'ui-sec-sheet';
        document.body.appendChild(sheet);
    }
    const d = securityDescribe(a);
    const scroll = sheet.querySelector('.ui-sec-sheet-body');
    const keep = scroll ? scroll.scrollTop : 0;
    sheet.innerHTML = `
        <div class="ui-sec-sheet-back" onclick="securityCloseSheet()"></div>
        <section class="ui-sec-sheet-panel" role="dialog" aria-label="${escapeHtml(a.ip)}">
            <div class="ui-sec-sheet-head">
                <div class="ui-sec-top"><b class="ui-mono">${copyableText(a.ip)}</b>${d.tag}</div>
                <button type="button" class="ui-icon-btn" onclick="securityCloseSheet()" aria-label="Close" title="Close">&times;</button>
            </div>
            <div class="ui-sec-sheet-body">
                <p class="ui-sec-why">${d.why}</p>
                ${d.acts ? `<div class="ui-sec-acts">${d.acts}</div>` : ''}
                ${securityDetail(a)}
            </div>
        </section>`;
    const body = sheet.querySelector('.ui-sec-sheet-body');
    if (body) body.scrollTop = keep;
    document.body.classList.add('ui-sec-sheet-on');
}

function securityCloseSheet() {
    securityOpenRow = null;
    renderSecurityOverview();
}

// The summary of one address, then its raw log lines
function securityDetail(a) {
    const lines = securityRawLog[a.ip];
    const hitsText = a.hits.map(h => `<div class="ui-sec-ev"><time title="${escapeHtml(formatTime(h.last_seen))}">${formatAgo(h.last_seen)}</time><span>${escapeHtml(securityRuleName(h.rule))}: ${escapeHtml(h.reason || '')}</span>${protectionStatus(h)}</div>`).join('');
    const raw = lines === 'loading' ? '<p class="ui-muted">Loading...</p>'
        : lines === 'error' ? '<p class="ui-text-fail">Could not load the log lines.</p>'
        : !lines || !lines.length ? '<p class="ui-muted">No log lines for this address.</p>'
        : `<pre class="ui-sec-raw">${lines.map(e => `<span class="ui-muted">${escapeHtml(formatTime(e.time))}</span> <span class="ui-sec-act is-${escapeHtml(e.action || '')}">${escapeHtml((e.action || '').padEnd(7))}</span> ${escapeHtml(e.message || '')}`).join('\n')}</pre>`;
    return `
        <div class="ui-sec-detail" onclick="event.stopPropagation()">
            <div class="ui-sec-facts">
                <div><h4>From</h4>${a.country ? securityFlag(a.countryCode) : ''}${escapeHtml([a.city, a.country].filter(Boolean).join(', ') || 'Unknown')}${a.org ? `<br><span class="ui-muted">${escapeHtml(a.org)}</span>` : ''}</div>
                <div><h4>Failed logins today</h4>${a.tries ? a.tries.toLocaleString() : '<span class="ui-muted">None</span>'}${a.services.length ? `<br><span class="ui-muted">${escapeHtml(a.services.join(', '))}</span>` : ''}</div>
                ${a.hits.length ? `<div><h4>Caught by</h4>${escapeHtml([...new Set(a.hits.map(h => securityRuleName(h.rule)))].join(', '))}</div>` : ''}
            </div>
            ${a.users.length ? `<div><h4>Accounts it tried</h4><div class="ui-chip-row">${a.users.map(u => `<span class="ui-sec-chip">${copyableText(u)}</span>`).join('')}</div></div>` : ''}
            ${hitsText ? `<div><h4>What the rules said</h4>${hitsText}</div>` : ''}
            <div><h4>Raw log${Array.isArray(lines) && lines.length ? ` <span class="ui-muted">${lines.length} newest lines</span>` : ''}</h4>${raw}
                <div class="ui-sec-more"><button type="button" class="ui-btn ui-btn-sm" onclick="securityOpenEvents('${escapeJsArg(a.ip)}')">All events of this address</button></div></div>
        </div>`;
}

// A click on the row opens it; a click on a button, a link or copyable text inside does not
function securityRowClick(event, ip) {
    if (event.target.closest('button, a, input, .copyable, .ui-sec-detail')) return;
    securityToggleRow(ip);
}

async function securityToggleRow(ip) {
    securityOpenRow = securityOpenRow === ip ? null : ip;
    renderSecurityOverview();
    if (!securityOpenRow || Array.isArray(securityRawLog[ip])) return;
    securityRawLog[ip] = 'loading';
    try {
        const res = await authenticatedFetch(`/api/logs/netfilter?ip=${encodeURIComponent(ip)}&exact_ip=true&limit=40`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        securityRawLog[ip] = (await res.json()).data || [];
    } catch (e) {
        securityRawLog[ip] = 'error';
    }
    renderSecurityOverview();
}

// The Events tab, filtered to one address
function securityOpenEvents(ip) {
    securityShowTab('events');
    const field = document.getElementById('netfilter-filter-ip');
    if (field) field.value = ip;
    applyNetfilterFilters();
}

// Someone is working in the Settings cards or the Lists: an open card, unsaved
// changes, or the focus in one of their fields
function securityEditing() {
    const focus = document.activeElement;
    return securityCard !== null || securityChangeCount() > 0
        || !!(focus && focus.closest && focus.closest('#security-cards, #security-lists'));
}

function setSecurityFilter(key) {
    securityFilter = key;
    securityOpenRow = null;
    securityShowAll = false;
    if (key === 'history' && securityHistory === null) { loadSecurityHistory(); }
    renderSecurityOverview();
}

function pickSecurityCountry(name) {
    securityCountry = securityCountry === name ? null : name;
    securityOpenRow = null;
    securityCountryPicker = false;
    renderSecurityOverview();
    renderSecurityCountries();
}

function securityHistoryRows() {
    if (securityHistory === null) return '<div class="ui-loading"><div class="loading"></div><p>Loading...</p></div>';
    const rows = securityHistory.filter(h => !securityCountry || h.country_name === securityCountry);
    if (!rows.length) return '<p class="ui-empty">Nothing here yet. Ended, undone and dismissed catches are kept here.</p>';
    return rows.map(h => `
        <div class="ui-sec-row is-static">
            <div class="ui-sec-main">
                <div class="ui-sec-top"><b class="ui-mono">${copyableText(h.ip)}</b>${protectionStatus(h)}<span class="ui-sec-by">${escapeHtml(securityRuleName(h.rule))}</span>
                    <small class="ui-muted ui-sec-where">${h.country_name ? `${securityFlag(h.country_code)}${escapeHtml(h.country_name)} · ` : ''}${formatAgo(h.ended_at || h.last_seen)}</small></div>
                <p class="ui-sec-why">${escapeHtml(h.reason || '')}</p>
            </div>
        </div>`).join('');
}

// ----------------------------------------------------------------- render

function renderSecurityOverview() {
    const strip = document.getElementById('security-protections');
    if (strip) {
        strip.innerHTML = securityProtections();
        strip.classList.toggle('is-open', securityStripOpen);
    }
    const box = document.getElementById('security-list');
    if (!box) return;
    if (!securityOverview) return;

    const addresses = securityAddresses();
    const inCountry = a => !securityCountry || a.country === securityCountry;
    const count = key => key === 'history' ? null : securityList(key, addresses).filter(inCountry).length;
    const reviewCount = securityList('review', addresses).length;
    const tabCount = document.getElementById('security-tab-n-overview');
    if (tabCount) {
        tabCount.textContent = reviewCount ? reviewCount.toLocaleString() : '';
        tabCount.classList.toggle('hidden', !reviewCount);
    }

    const known = fail2banActiveBans !== null;
    const segs = SECURITY_FILTERS.map(([key, label]) => {
        const n = key === 'banned' && !known && !fail2banLoadError ? '-' : count(key);
        return `<button type="button" aria-pressed="${securityFilter === key}" onclick="setSecurityFilter('${key}')">${label}${n === null ? '' : ` <b>${typeof n === 'number' ? n.toLocaleString() : n}</b>`}</button>`;
    }).join('');
    const list = securityList(securityFilter, addresses).filter(inCountry);
    const shown = securityShowAll ? list : list.slice(0, SECURITY_LIST_PREVIEW);
    const rwNote = !mailcowRwConfigured && securityFilter !== 'history'
        ? `<div class="ui-list-note">${uiLocked('Ban, Allow and Unban are locked', `Changing Fail2ban from this list ${UI_RW_KEY_TEXT}`)}</div>` : '';
    const f2bNote = fail2banLoadError && securityFilter !== 'history'
        ? `<p class="ui-sec-note ui-text-fail">mailcow did not answer about Fail2ban, so its bans are not shown and nothing can be banned from here. The next refresh tries again.</p>` : '';
    const empty = {
        review: 'Nothing to review. What the protection rules catch while they watch shows up here.',
        banned: known ? 'Nothing is banned right now.' : fail2banLoadError ? 'The bans are not known while mailcow does not answer.' : 'Checking Fail2ban...',
        quiet: 'No address failed to log in today without being stopped.',
    }[securityFilter];
    const source = securityOverview;
    const more = securityFilter === 'quiet' && source.source_count > source.sources.length
        ? `<p class="ui-sec-note">The ${source.sources.length} addresses with the most attempts today, of ${source.source_count.toLocaleString()}.</p>` : '';

    box.innerHTML = `
        <div class="ui-panel-head ui-sec-head">
            <div class="ui-seg ui-sec-seg" role="group" aria-label="Show">${segs}</div>
            <span class="ui-popover-host ui-sec-chost">
                <button type="button" class="ui-msg-range${securityCountry ? ' is-set' : ''}" aria-expanded="${securityCountryPicker}" aria-controls="security-country-panel"
                    onclick="securityCountryPicker = !securityCountryPicker; renderSecurityOverview()">${securityCountry ? `${securityFlag(securityCountryCode(securityCountry))}${escapeHtml(securityCountry)}` : 'Country: All'}</button>
                <span id="security-country-panel" class="ui-popover ui-sec-cpanel${securityCountryPicker ? '' : ' hidden'}" role="dialog" aria-label="Where attacks come from">${securityCountryPanel()}</span>
            </span>
            ${securityCountry ? `<span class="ui-sec-filter">${securityFlag(securityCountryCode(securityCountry))}${escapeHtml(securityCountry)}<button type="button" onclick="pickSecurityCountry(null)" aria-label="Show every country" title="Show every country">&times;</button></span>` : ''}
        </div>
        ${rwNote}${f2bNote}
        <div class="ui-sec-list">${securityFilter === 'history' ? securityHistoryRows()
            : shown.map(securityRow).join('') || `<p class="ui-empty">${escapeHtml(empty)}</p>`}</div>
        ${list.length > SECURITY_LIST_PREVIEW ? `<div class="ui-list-more"><button type="button" class="ui-btn ui-btn-sm" onclick="securityShowAll = !securityShowAll; renderSecurityOverview()" aria-expanded="${securityShowAll}">${securityShowAll ? 'Show fewer' : `Show all ${list.length.toLocaleString()}`}</button></div>` : ''}
        ${more}`;
    // The filters stick right under the tabs, which stick to the top on a phone
    const tabs = document.querySelector('.ui-se-tabs');
    if (tabs) box.style.setProperty('--ui-sec-stick', `${tabs.offsetHeight}px`);
    renderSecuritySheet(addresses);
}

// ----------------------------------------------------------------- where attacks come from

async function loadSecurityCountryChart(days = securityChartDays) {
    securityChartDays = days;
    renderSecurityCountries();
    try {
        const [countries, networks] = await Promise.all([
            authenticatedFetch(`/api/logs/netfilter/stats/by-country?days=${days}`),
            authenticatedFetch(`/api/logs/netfilter/stats/by-network?days=${days}`)
        ]);
        securityCountries = countries.ok ? await countries.json() : { data: [] };
        securityNetworks = networks.ok ? await networks.json() : { data: [] };
    } catch (error) {
        console.error('Failed to load where the attacks come from:', error);
        securityCountries = securityCountries || { data: [] };
        securityNetworks = securityNetworks || { data: [] };
    }
    renderSecurityCountries();
    if (securityCountryPicker) renderSecurityOverview();
}

// A tap outside the country picker closes it; Escape closes it and the sheet
document.addEventListener('click', event => {
    if (securityCountryPicker && !event.target.closest('.ui-sec-chost')) {
        securityCountryPicker = false;
        renderSecurityOverview();
    }
});
document.addEventListener('keydown', event => {
    if (event.key !== 'Escape') return;
    if (securityCountryPicker) { securityCountryPicker = false; renderSecurityOverview(); }
    else if (document.getElementById('security-sheet')) securityCloseSheet();
});

function securityWatchedCountries() {
    return new Set(((typeof protectionSaved !== 'undefined' && protectionSaved && protectionSaved.country) || {}).countries || []);
}

function securityCountryBars() {
    const watched = securityWatchedCountries();
    const rows = securityCountries ? securityCountries.data : [];
    const max = rows.length ? Math.max(...rows.map(r => r.total)) : 1;
    return rows.map(r => {
        const part = (n, cls, label) => n ? `<i class="${cls}" style="width:${(n / max) * 100}%" title="${n.toLocaleString()} ${label}"></i>` : '';

        return `<button type="button" class="ui-sec-bar${securityCountry === r.country_name ? ' is-on' : ''}" onclick="pickSecurityCountry('${escapeJsArg(r.country_name)}')"
                title="${escapeHtml(`${r.country_name}: ${r.total.toLocaleString()} events`)}" aria-pressed="${securityCountry === r.country_name}">
            <span class="ui-sec-bar-name">${securityFlag(r.country_code)}${escapeHtml(r.country_name)}${watched.has(r.country_code) ? '<i class="ui-sec-watch" title="Watched by the Countries rule"></i>' : ''}</span>
            <span class="ui-sec-bar-track">${part(r.ban, 'is-ban', 'bans')}${part(r.warning, 'is-warn', 'warnings')}${part(r.unban, 'is-unban', 'unbans')}</span>
            <em>${r.total.toLocaleString()}</em></button>`;
    }).join('');
}

// The phone's country picker: the period, the countries, and All
function securityCountryPanel() {
    const rows = securityCountries ? securityCountries.data : null;
    const range = [7, 30, 90].map(d => `<button type="button" aria-pressed="${securityChartDays === d}" onclick="loadSecurityCountryChart(${d})">${d}D</button>`).join('');
    return `<span class="ui-sec-cpanel-head"><b>Where attacks come from</b><span class="ui-seg" role="group" aria-label="Period">${range}</span></span>
        ${rows === null ? '<span class="ui-muted">Loading...</span>'
            : !rows.length ? '<span class="ui-muted">No GeoIP data available. Configure MaxMind to enable country statistics.</span>'
            : `<span class="ui-sec-bars">${securityCountryBars()}</span>`}
        ${securityCountry ? '<button type="button" class="ui-btn ui-btn-sm ui-sec-call" onclick="pickSecurityCountry(null)">Every country</button>' : ''}`;
}

function renderSecurityCountries() {
    const box = document.getElementById('security-countries');
    if (!box) return;
    const watched = securityWatchedCountries();
    const range = [7, 30, 90].map(d => `<button type="button" id="country-chart-${d}d" aria-pressed="${securityChartDays === d}" onclick="loadSecurityCountryChart(${d})">${d}D</button>`).join('');
    const rows = securityCountries ? securityCountries.data : null;
    const networks = securityNetworks ? securityNetworks.data : null;
    box.innerHTML = `
        <section class="ui-panel">
            <div class="ui-panel-head">Where attacks come from <div class="ui-seg ui-head-actions" role="group" aria-label="Period">${range}</div></div>
            ${rows === null ? '<div class="ui-loading"><div class="loading"></div><p>Loading...</p></div>'
                : !rows.length ? '<p id="country-chart-empty" class="ui-empty">No GeoIP data available. Configure MaxMind to enable country statistics.</p>'
                : `<div class="ui-sec-bars">${securityCountryBars()}</div>
                   <p class="ui-sec-legend"><span><i class="is-ban"></i>Ban</span><span><i class="is-warn"></i>Warning</span><span><i class="is-unban"></i>Unban</span>${watched.size ? '<span><i class="ui-sec-watch"></i>Watched by the Countries rule</span>' : ''}</p>
                   <p class="ui-sec-note">Pick a country to see its addresses.</p>`}
        </section>
        <section class="ui-panel ui-sec-networks">
            <div class="ui-panel-head">Networks that try most <span class="ui-count">${securityChartDays} days</span></div>
            ${networks === null ? '' : !networks.length ? '<p class="ui-empty">No network data yet.</p>'
                : networks.map(n => `<div class="ui-sec-net"><span title="${escapeHtml(n.asn)}">${escapeHtml(n.asn_org)}</span><small class="ui-muted">${n.addresses.toLocaleString()} address${n.addresses === 1 ? '' : 'es'}</small><b>${n.attempts.toLocaleString()}</b></div>`).join('')}
        </section>`;
}


// =============================================================================
// SECURITY PAGE - Lists: the allowlist and the denylist, one address per row
// =============================================================================

function renderSecurityLists() {
    const box = document.getElementById('security-lists');
    if (!box) return;
    const count = document.getElementById('security-tab-n-lists');
    if (count) {
        const n = fail2banActiveBans === null ? 0 : fail2banWhitelist.length + fail2banBlacklist.length;
        count.textContent = n ? n.toLocaleString() : '';
        count.classList.toggle('hidden', !n);
    }
    if (fail2banLoadError) {
        box.innerHTML = '<p class="ui-empty ui-text-fail">mailcow did not answer about Fail2ban, so its lists cannot be shown. The next refresh tries again.</p>';
        return;
    }
    if (fail2banActiveBans === null) {
        box.innerHTML = '<div class="ui-loading"><div class="loading"></div><p>Loading...</p></div>';
        return;
    }
    const rw = mailcowRwConfigured;
    const tried = ip => {
        const s = securityOverview && securityOverview.sources.find(src => src.ip === securityBare(ip));
        return s ? s.failed_logins : 0;
    };
    // A ban a rule wrote is on the denylist too; it is lifted through the rule
    const ruleBans = new Map(securityHits.filter(h => h.status === 'banned' && h.owned).map(h => [h.ip, h]));
    const addForm = (list, placeholder) => rw ? `
        <form class="ui-sec-ladd" onsubmit="event.preventDefault(); securityAddToList('${list}', this.elements.ip.value, this)">
            <input type="text" name="ip" class="ui-input" placeholder="${placeholder}" aria-label="Address or network" maxlength="64">
            <button type="submit" class="ui-btn">Add</button>
        </form>` : '';
    const row = (entry, note, action) => `
        <div class="ui-sec-lrow"><b class="ui-mono">${copyableText(entry)}</b><span class="ui-sec-why">${note}</span><span class="ui-sec-acts">${action}</span></div>`;
    const allowRows = fail2banWhitelist.map(entry => {
        const n = tried(entry);
        return row(entry, n ? `Failed ${n.toLocaleString()} login${n === 1 ? '' : 's'} today, never banned` : '',
            rw ? `<button type="button" class="ui-btn ui-btn-sm" onclick="securityRemoveFromList('whitelist', '${escapeJsArg(entry)}', this)">Remove</button>` : '');
    }).join('');
    const denyRows = fail2banBlacklist.map(entry => {
        const hit = ruleBans.get(securityBare(entry));
        if (hit) {
            return row(entry, `Added by ${escapeHtml(securityRuleName(hit.rule))}, ${hit.expires_at ? `until ${escapeHtml(formatTime(hit.expires_at))}` : 'until removed'}`,
                `<button type="button" class="ui-btn ui-btn-sm" onclick="undoProtectionHit(${Number(hit.id)}, this)" title="Lift the ban; the rule leaves it alone for a week">Remove</button>`);
        }
        const n = tried(entry);
        return row(entry, `Added by hand${n ? `, still tried ${n.toLocaleString()} time${n === 1 ? '' : 's'} today` : ''}`,
            rw ? `<button type="button" class="ui-btn ui-btn-sm" onclick="securityRemoveFromList('blacklist', '${escapeJsArg(entry)}', this)">Remove</button>` : '');
    }).join('');
    box.innerHTML = `
        ${rw ? '' : `<div class="ui-list-note ui-flush">${uiLocked('The lists are read-only here', `Changing the allowlist and the denylist ${UI_RW_KEY_TEXT}`)}</div>`}
        <div class="ui-sec-lists">
            <section class="ui-panel">
                <div class="ui-panel-head">Allowlist <span class="ui-count">${fail2banWhitelist.length}</span></div>
                <p class="ui-sec-note">Never banned, by Fail2ban or by the rules. Your own offices and monitoring belong here.</p>
                ${addForm('whitelist', 'Address or network, like 192.0.2.0/24')}
                ${allowRows || '<p class="ui-empty">The allowlist is empty.</p>'}
            </section>
            <section class="ui-panel">
                <div class="ui-panel-head">Denylist <span class="ui-count">${fail2banBlacklist.length}</span></div>
                <p class="ui-sec-note">Banned until removed. The denylist wins over the allowlist. Changes take a few seconds to apply.</p>
                ${addForm('blacklist', 'Address or network')}
                ${denyRows || '<p class="ui-empty">The denylist is empty.</p>'}
            </section>
        </div>`;
}

async function securityAddToList(list, value, form) {
    const ip = String(value || '').trim();
    if (!ip) return;
    const button = form && form.querySelector('button');
    if (list === 'whitelist') await allowIP(ip, button);
    else await banIP(ip, button);
}

async function securityRemoveFromList(list, entry, button) {
    const label = list === 'whitelist' ? 'allowlist' : 'denylist';
    if (!await showConfirmModal({ title: `Remove from the ${label}`, message: `Remove ${entry} from the Fail2ban ${label}?`, confirmText: 'Remove' })) return;
    if (button) button.disabled = true;
    try {
        const res = await authenticatedFetch('/api/fail2ban/remove', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip: entry, list })
        });
        const result = await res.json().catch(() => ({}));
        if (!res.ok || result.status !== 'success') throw new Error(result.msg || result.detail || `HTTP ${res.status}`);
        showToast(`${entry} removed from the ${label}`, 'success');
        fail2banSettingsLoaded = false;
        loadFail2BanSettings();
    } catch (error) {
        showToast(`Could not remove ${entry}: ${error.message}`, 'error');
        if (button) button.disabled = false;
    }
}

// =============================================================================
// SECURITY PAGE - Settings: one card per protection, the same ones as the
// Overview's Protection row. A closed card says in one sentence what the
// protection does; an open card turns that sentence into fields.
// =============================================================================

let securityCard = null;          // the open card
let securityF2bDraft = null;      // unsaved Fail2ban policy
let securityAppSettings = null;   // GET /api/settings, for the outgoing spam settings
let securityAbuseDraft = {};      // unsaved outgoing spam settings

const SECURITY_CARDS = ['fail2ban', 'trap', 'unknown_accounts', 'repeat_offender', 'subnet', 'country', 'breach', 'abuse'];
const SECURITY_ABUSE_KEYS = ['smtp_abuse_enabled', 'smtp_abuse_threshold', 'smtp_abuse_window_minutes',
    'smtp_abuse_unblock_grace_minutes', 'smtp_abuse_revoke_app_passwords', 'smtp_abuse_help_address'];
const SECURITY_F2B_KEYS = ['max_attempts', 'retry_window', 'ban_time', 'ban_time_increment', 'max_ban_time', 'netban_ipv4', 'netban_ipv6'];

async function loadSecurityAppSettings() {
    try {
        const res = await authenticatedFetch('/api/settings');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        securityAppSettings = await res.json();
    } catch (error) {
        console.error('Failed to load the app settings:', error);
        securityAppSettings = null;
    }
    renderSecuritySettings();
}

// A protection in the Overview's row opens its own card
function securityOpenProtection(key) {
    securityShowTab('settings');
    securityOpenCard(key);
}

function securityOpenCard(key) {
    securityCard = key;
    renderSecuritySettings();
    if (!key) return;
    // After the layout settles (the card that closed changed it), the card's top goes to
    // the top of whatever scrolls it (the tab on a wide screen, the page on a phone),
    // and it takes the focus so the keyboard starts there
    requestAnimationFrame(() => {
        const card = document.getElementById(`security-card-${key}`);
        if (!card) return;
        let scroller = card.parentElement;
        while (scroller && !(scroller.scrollHeight > scroller.clientHeight && /(auto|scroll)/.test(getComputedStyle(scroller).overflowY))) {
            scroller = scroller.parentElement;
        }
        // On a phone the tabs stick to the top of the page and would cover the card's head
        const tabs = document.querySelector('.ui-se-tabs');
        const covered = tabs && scroller && scroller.contains(tabs) && getComputedStyle(tabs).position === 'sticky' ? tabs.offsetHeight : 0;
        if (scroller) scroller.scrollTop += card.getBoundingClientRect().top - scroller.getBoundingClientRect().top - covered - 10;
        card.focus({ preventScroll: true });
    });
}

// ----------------------------------------------------------------- unsaved changes, one save bar

function securityF2bValues() {
    return { ...(fail2banPolicy || {}), ...(securityF2bDraft || {}) };
}

function securityF2bChanges() {
    if (!securityF2bDraft || !fail2banPolicy) return [];
    return SECURITY_F2B_KEYS.filter(k => k in securityF2bDraft && String(securityF2bDraft[k]) !== String(fail2banPolicy[k]));
}

function securityAbuseValue(key) {
    if (key in securityAbuseDraft) return securityAbuseDraft[key];
    return securityAppSettings ? securityAppSettings.configuration[key] : undefined;
}

function securityAbuseChanges() {
    if (!securityAppSettings) return [];
    return Object.keys(securityAbuseDraft).filter(k => String(securityAbuseDraft[k]) !== String(securityAppSettings.configuration[k]));
}

function securityChangeCount() {
    return protectionChangeCount() + securityF2bChanges().length + securityAbuseChanges().length
        + (smtpAbuseWhitelistDraft !== null ? 1 : 0);
}

function securityUpdateSaveBar() {
    uiSaveBarUpdate('security-savebar', securityChangeCount());
}

function setSecurityF2b(key, value) {
    securityF2bDraft = { ...(securityF2bDraft || {}), [key]: value };
    renderSecuritySettings();
}

function setSecurityAbuse(key, value) {
    securityAbuseDraft = { ...securityAbuseDraft, [key]: value };
    renderSecuritySettings();
}

function discardSecuritySettings() {
    if (protectionSaved) protectionRules = JSON.parse(JSON.stringify(protectionSaved));
    protectionDirty = false;
    securityF2bDraft = null;
    securityAbuseDraft = {};
    smtpAbuseWhitelistDraft = null;
    renderProtection();
    renderSmtpAbusePanel();
    securityUpdateSaveBar();
}

// Save what changed, group by group, and say in one message what was saved. A group
// that fails says why in its own message and keeps its changes on screen.
async function saveSecuritySettings() {
    uiSaveBarBusy('security-savebar', true);
    const saved = [];
    if (protectionChangeCount() && await saveProtectionRules(true)) saved.push('the protection rules');
    if (securityF2bChanges().length && await saveSecurityF2b()) saved.push('Fail2ban');
    if (securityAbuseChanges().length && await saveSecurityAbuse()) saved.push('outgoing spam');
    if (smtpAbuseWhitelistDraft !== null && await saveSmtpAbuseWhitelist(true)) saved.push('the whitelist');
    uiSaveBarBusy('security-savebar', false);
    securityUpdateSaveBar();
    if (saved.length) {
        const list = saved.length > 1 ? `${saved.slice(0, -1).join(', ')} and ${saved[saved.length - 1]}` : saved[0];
        showToast(`Saved ${list}`, 'success');
    }
}

async function saveSecurityF2b() {
    const values = securityF2bValues();
    try {
        const res = await authenticatedFetch('/api/fail2ban/policy', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(Object.fromEntries(SECURITY_F2B_KEYS.map(k => [k, values[k]])))
        });
        const result = await res.json().catch(() => ({}));
        if (!res.ok || result.status !== 'success') throw new Error(result.msg || result.detail || `HTTP ${res.status}`);
        securityF2bDraft = null;
        fail2banSettingsLoaded = false;
        await loadFail2BanSettings();
        return true;
    } catch (error) {
        showToast(`Failed to save the Fail2ban settings: ${error.message}`, 'error');
        return false;
    }
}

async function saveSecurityAbuse() {
    const body = Object.fromEntries(securityAbuseChanges().map(k => [k, securityAbuseDraft[k]]));
    try {
        const res = await authenticatedFetch('/api/settings', {
            method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
        });
        const result = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(result.detail || `HTTP ${res.status}`);
        securityAbuseDraft = {};
        await loadSecurityAppSettings();
        loadSmtpAbusePanel();
        return true;
    } catch (error) {
        showToast(`Could not save the outgoing spam settings: ${error.message}`, 'error');
        return false;
    }
}

// ----------------------------------------------------------------- the cards

const securityNum = (value, onchange, min, max, label, width = 5, disabled = false) =>
    `<input type="number" class="ui-sec-in" style="width:${width + 2}ch" min="${min}"${max ? ` max="${max}"` : ''} value="${escapeHtml(String(value ?? ''))}"
        onchange="${onchange}" aria-label="${escapeHtml(label)}" ${disabled ? 'disabled' : ''}>`;

function securityBanText(hours) {
    const h = Number(hours);
    const known = PROTECTION_BAN_LENGTHS.find(([v]) => v === h);
    return h === 0 ? 'until removed by hand' : `for ${known ? known[1] : `${h} hours`}`;
}

function securityBanSelect(rule, hours) {
    const h = Number(hours);
    const lengths = PROTECTION_BAN_LENGTHS.some(([v]) => v === h) ? PROTECTION_BAN_LENGTHS : [...PROTECTION_BAN_LENGTHS, [h, `${h} hours`]];
    return `<select class="ui-sec-in" onchange="setProtectionRule('${rule}', 'ban_hours', this.value)" aria-label="Ban length">
        ${lengths.map(([v, text]) => `<option value="${v}" ${v === h ? 'selected' : ''}>${v === 0 ? 'until removed by hand' : `for ${escapeHtml(text)}`}</option>`).join('')}</select>`;
}

// What a rule does, as one sentence; with edit, its values are fields
function securityRuleSentence(key, edit) {
    const r = protectionRules[key];
    const caps = protectionCaps;
    const num = (field, min, max, label, width) => edit
        ? securityNum(r[field], `setProtectionRule('${key}', '${field}', this.value)`, min, max, label, width)
        : `<b>${escapeHtml(String(r[field]))}</b>`;
    const banning = r.mode === 'enforce' && caps.can_ban;
    const verb = edit ? `Ban ${securityBanSelect(key, r.ban_hours)}` : banning ? `Bans ${securityBanText(r.ban_hours)}` : `Watches, and would ban ${securityBanText(r.ban_hours)},`;
    const mail = !edit && r.notify ? ' You get an email.' : '';
    switch (key) {
        case 'trap': return `${verb} anyone who tries one of <b>${r.names.length} trap name${r.names.length === 1 ? '' : 's'}</b>.${mail}`;
        case 'unknown_accounts': return `${verb} an address that tries ${num('threshold', 2, 100, 'Number of accounts', 3)} accounts that do not exist within ${num('window_minutes', 5, 1440, 'Minutes', 4)} minutes.${mail}`;
        case 'repeat_offender': return `${verb} an address Fail2ban banned ${num('threshold', 2, 50, 'Number of bans', 3)} times within ${num('window_days', 1, 365, 'Days', 3)} days.${mail}`;
        case 'subnet': return `${verb} a whole network (IPv4 /24) when ${num('threshold', 2, 256, 'Number of addresses', 3)} of its addresses attack within ${num('window_hours', 1, 168, 'Hours', 3)} hours.${mail}`;
        case 'country': return `${verb} an address that fails to log in from one of <b>${r.countries.length} countr${r.countries.length === 1 ? 'y' : 'ies'}</b>.${mail}`;
        case 'breach': return `${edit ? 'Alert' : 'Alerts'} when an account logs in after ${num('failures', 1, 50, 'Number of failed tries', 3)} failed tries from the same address within ${num('window_minutes', 5, 1440, 'Minutes', 4)} minutes${!edit && r.new_country && caps.geoip ? ', or from a country it did not use in 30 days' : ''}. Never bans.${mail}`;
        default: return '';
    }
}

function securityF2bSentence(edit) {
    const v = securityF2bValues();
    const off = !mailcowRwConfigured;
    if (!edit) {
        return `An address that fails <b>${v.max_attempts} logins</b> within <b>${formatSeconds(v.retry_window)}</b> is banned for <b>${formatSeconds(v.ban_time)}</b>${v.ban_time_increment ? `, longer each time it comes back, up to <b>${formatSeconds(v.max_ban_time)}</b>` : ''}.`;
    }
    const n = (key, min, max, label, width) => securityNum(v[key], `setSecurityF2b('${key}', this.value)`, min, max, label, width, off);
    const hint = key => `<span class="ui-sec-hint">${formatSeconds(v[key])}</span>`;
    return `An address that fails ${n('max_attempts', 1, 0, 'Failed logins before a ban', 3)} logins within ${n('retry_window', 1, 0, 'Retry window in seconds', 6)} seconds ${hint('retry_window')}
        is banned for ${n('ban_time', 60, 0, 'Ban time in seconds', 6)} seconds ${hint('ban_time')},
        <label class="ui-sec-inline"><input type="checkbox" class="ui-check" ${v.ban_time_increment ? 'checked' : ''} ${off ? 'disabled' : ''} onchange="setSecurityF2b('ban_time_increment', this.checked)"> longer each time it comes back</label>,
        up to ${n('max_ban_time', 60, 0, 'Longest ban in seconds', 7)} seconds ${hint('max_ban_time')}.`;
}

function securityAbuseSentence(edit) {
    const val = key => securityAbuseValue(key);
    if (!securityAppSettings) return 'Stops a mailbox from sending when it suddenly sends far more than usual.';
    const editable = securityAppSettings.settings_edit_via_ui_enabled;
    const locked = key => !editable || (securityAppSettings.env_locked_keys || []).includes(key);
    if (!edit) {
        return `Stops a mailbox from sending when it sends more than <b>${val('smtp_abuse_threshold')} messages</b> within <b>${val('smtp_abuse_window_minutes')} minutes</b>. Receiving is never affected.`;
    }
    const n = (key, min, label, width) => securityNum(val(key), `setSecurityAbuse('${key}', Number(this.value))`, min, 0, label, width, locked(key));
    return `Stop a mailbox from sending when it sends more than ${n('smtp_abuse_threshold', 1, 'Messages', 5)} messages within ${n('smtp_abuse_window_minutes', 1, 'Minutes the messages are counted in', 4)} minutes.
        After you let it send again, wait ${n('smtp_abuse_unblock_grace_minutes', 0, 'Minutes before it can be stopped again', 4)} minutes before it can be stopped again.`;
}

// The parts of a card that only an open card shows
function securityCardBody(key) {
    const caps = protectionCaps;
    const R = protectionRules;
    if (key === 'fail2ban') {
        const v = securityF2bValues();
        const off = mailcowRwConfigured ? '' : 'disabled';
        return `
            <div class="ui-sec-fields">
                <label class="ui-sec-field"><span>Ban the network, IPv4<small>Prefix length; ${escapeHtml(String(v.netban_ipv4))} bans ${Number(v.netban_ipv4) === 32 ? 'just the address' : 'the whole network'}</small></span>
                    <input type="number" class="ui-input" min="8" max="32" value="${escapeHtml(String(v.netban_ipv4))}" onchange="setSecurityF2b('netban_ipv4', this.value)" ${off}></label>
                <label class="ui-sec-field"><span>Ban the network, IPv6<small>Prefix length; ${escapeHtml(String(v.netban_ipv6))} bans ${Number(v.netban_ipv6) === 128 ? 'just the address' : 'the whole network'}</small></span>
                    <input type="number" class="ui-input" min="8" max="128" value="${escapeHtml(String(v.netban_ipv6))}" onchange="setSecurityF2b('netban_ipv6', this.value)" ${off}></label>
            </div>
            <p class="ui-sec-note ui-flush">The allowlist and the denylist are on the Lists tab.</p>`;
    }
    if (key === 'abuse') {
        const editable = securityAppSettings && securityAppSettings.settings_edit_via_ui_enabled;
        const envLocked = k => securityAppSettings && (securityAppSettings.env_locked_keys || []).includes(k);
        const revoke = securityAbuseValue('smtp_abuse_revoke_app_passwords');
        return `
            ${securityAppSettings && !editable ? uiLocked('Editing settings is off', 'These values come from the environment and are shown read-only. To change them here, set <code>SETTINGS_EDIT_VIA_UI_ENABLED=true</code> and restart the container.') : ''}
            <div class="ui-sec-fields">
                <label class="ui-sec-field"><span>Revoke its app passwords<small>When a mailbox is stopped, its app passwords stop working too</small></span>
                    <span><input type="checkbox" class="ui-check" ${revoke ? 'checked' : ''} ${!editable || envLocked('smtp_abuse_revoke_app_passwords') ? 'disabled' : ''} onchange="setSecurityAbuse('smtp_abuse_revoke_app_passwords', this.checked)"> On</span></label>
                <label class="ui-sec-field"><span>Who users should contact<small>Shown to the mailbox owner when sending is stopped</small></span>
                    <input type="text" class="ui-input" value="${escapeHtml(securityAbuseValue('smtp_abuse_help_address') || '')}" ${!editable || envLocked('smtp_abuse_help_address') ? 'disabled' : ''} onchange="setSecurityAbuse('smtp_abuse_help_address', this.value)" placeholder="support@example.com"></label>
            </div>
            <div id="smtp-abuse-panel"></div>`;
    }
    const r = R[key];
    const mode = key === 'breach' ? '' : `
        <div class="ui-sec-mode">
            <div class="ui-seg" role="group" aria-label="What the rule does">
                <button type="button" aria-pressed="${r.mode !== 'enforce'}" onclick="setProtectionMode('${key}', 'watch')" title="Note what it would ban; ban nothing">Watch first</button>
                <button type="button" aria-pressed="${r.mode === 'enforce'}" onclick="setProtectionMode('${key}', 'enforce')" ${caps.can_ban ? '' : 'disabled'} title="${caps.can_ban ? 'Put what it catches on the Fail2ban blacklist' : 'Banning needs the Read-Write API key'}">Ban</button>
            </div>
            <span class="ui-muted">${r.mode === 'enforce' ? 'Bans as soon as it catches an address.' : 'Notes who it would ban, and bans nothing. You decide on the Overview.'}</span>
        </div>`;
    const notify = `<label class="ui-sec-inline"><input type="checkbox" class="ui-check" ${r.notify ? 'checked' : ''} onchange="setProtectionRule('${key}', 'notify', this.checked)"> ${key === 'breach' ? 'Email me on every alert' : 'Email me when it bans'}</label>`;
    let extra = '';
    if (key === 'trap') {
        const suggest = protectionSuggestions.filter(s => !r.names.includes(s.name));
        extra = `
            <h4>Trap names</h4>
            <div class="ui-chip-row">${r.names.length ? r.names.map(name => `<span class="ui-sec-chip">${escapeHtml(name)}<button type="button" onclick="removeTrapName('${escapeJsArg(name)}')" aria-label="Remove ${escapeHtml(name)}" title="Remove">&times;</button></span>`).join('') : '<span class="ui-muted">No trap names yet</span>'}</div>
            <form class="ui-sec-ladd ui-flush" onsubmit="event.preventDefault(); addTrapName(this.elements.name.value); this.reset();">
                <input type="text" name="name" class="ui-input" placeholder="admin or admin@example.com" aria-label="Trap account name" maxlength="255">
                <button type="submit" class="ui-btn">Add</button>
            </form>
            ${suggest.length ? `<h4>Tried in the last 7 days, and no such mailbox here</h4>
                <div class="ui-chip-row">${suggest.map(s => `<button type="button" class="ui-chip" onclick="addTrapName('${escapeJsArg(s.name)}')" title="${s.tries} tries from ${s.addresses} address${s.addresses === 1 ? '' : 'es'}">+ ${escapeHtml(s.name)} <small>${s.tries}</small></button>`).join('')}</div>` : ''}
            <p class="ui-sec-note ui-flush">A real mailbox or alias can never be a trap name.</p>`;
    } else if (key === 'country') {
        const suggest = protectionCountrySuggestions.filter(s => !r.countries.includes(s.code));
        extra = `
            <h4>Countries</h4>
            <div class="ui-chip-row">${r.countries.length ? r.countries.map(code => `<span class="ui-sec-chip">${securityFlag(code)}${escapeHtml(protectionCountryName(code))}<button type="button" onclick="removeProtectionCountry('${escapeJsArg(code)}')" aria-label="Remove ${escapeHtml(code)}" title="Remove">&times;</button></span>`).join('') : '<span class="ui-muted">No countries yet</span>'}</div>
            <form class="ui-sec-ladd ui-flush" onsubmit="event.preventDefault(); addProtectionCountry(this.elements.code.value); this.reset();">
                <input type="text" name="code" class="ui-input" placeholder="Two-letter code, for example CN" aria-label="Country code" maxlength="2">
                <button type="submit" class="ui-btn">Add</button>
            </form>
            ${suggest.length ? `<h4>Failed logins in the last 7 days came from</h4>
                <div class="ui-chip-row">${suggest.map(s => `<button type="button" class="ui-chip" onclick="addProtectionCountry('${escapeJsArg(s.code)}')" title="${s.tries} failed logins">+ ${securityFlag(s.code)}${escapeHtml(s.name)} <small>${s.tries}</small></button>`).join('')}</div>` : ''}
            <p class="ui-sec-note ui-flush">Only failed logins are caught. A user who logs in from one of these countries is not affected.</p>`;
    } else if (key === 'unknown_accounts') {
        extra = '<p class="ui-sec-note ui-flush">An address with a successful login in the last day is never caught, so a user who mistyped the address is safe.</p>';
    } else if (key === 'subnet') {
        extra = '<p class="ui-sec-note ui-flush">A network that holds an allowlisted address, an internal address or the mailcow server is never caught.</p>';
    } else if (key === 'breach') {
        extra = `
            <label class="ui-sec-inline"><input type="checkbox" class="ui-check" ${r.new_country ? 'checked' : ''} ${caps.geoip ? '' : 'disabled'} onchange="setProtectionRule('breach', 'new_country', this.checked)"> Also alert on a login from a country the account did not use in 30 days${caps.geoip ? '' : ' (needs GeoIP)'}</label>
            <p class="ui-sec-note ui-flush">${caps.raw_logs ? 'SMTP and IMAP logins are checked.' : 'Only SMTP logins are checked. IMAP logins need Live Logs to be on.'}</p>`;
    }
    return `${mode}<div class="ui-sec-card-foot">${notify}</div>${extra}`;
}

function securityCardHtml(key) {
    const open = securityCard === key;
    const isRule = !!SECURITY_RULE_NAMES[key];
    const name = isRule ? SECURITY_RULE_NAMES[key] : key === 'fail2ban' ? 'Fail2ban' : 'Outgoing spam';
    let on = true, toggle = '', status = '', locked = '', sentence = '', caught = '';
    if (key === 'fail2ban') {
        if (fail2banLoadError) return securityCardShell(key, name, open, uiTag('No answer', 'warn'), '', '', '<p class="ui-text-fail">mailcow did not answer about Fail2ban. The next refresh tries again.</p>', '');
        if (!fail2banPolicy) return securityCardShell(key, name, open, '', '', '', '<p class="ui-muted">Loading...</p>', '');
        status = uiTag('Always on', 'ok');
        sentence = securityF2bSentence(open);
        if (open && !mailcowRwConfigured) locked = uiLocked('Editing Fail2ban is locked', `Editing ${UI_RW_KEY_TEXT}`);
    } else if (key === 'abuse') {
        const enabled = securityAbuseValue('smtp_abuse_enabled');
        const editable = securityAppSettings && securityAppSettings.settings_edit_via_ui_enabled
            && !(securityAppSettings.env_locked_keys || []).includes('smtp_abuse_enabled');
        on = !!enabled;
        toggle = securityToggle(key, on, !editable, `setSecurityAbuse('smtp_abuse_enabled', ${!on})`, editable ? '' : 'Editing settings is off');
        status = `${on ? uiTag('Stops mailboxes', 'fail') : uiTag('Off', '')}<span class="ui-tag ui-tag-warn ui-tab-tag" title="This feature is new - please report any issues on GitHub">Beta</span>
            <button type="button" onclick="event.stopPropagation(); showHelpModal('Abuse_Protection')" class="ui-icon-btn ui-help-btn" title="Help - Abuse Protection" aria-label="Help - Abuse Protection"><svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg></button>`;
        sentence = securityAbuseSentence(open);
    } else {
        if (protectionLoadError) return securityCardShell(key, name, open, '', '', '', `<p class="ui-text-fail">Failed to load the protection rules: ${escapeHtml(protectionLoadError)}</p>`, '');
        if (!protectionRules) return securityCardShell(key, name, open, '', '', '', '<p class="ui-muted">Loading...</p>', '');
        const r = protectionRules[key];
        const needsGeo = key === 'country' && !protectionCaps.geoip;
        on = r.enabled && !needsGeo;
        toggle = securityToggle(key, on, needsGeo, `setProtectionRule('${key}', 'enabled', ${!r.enabled})`, needsGeo ? 'Needs MaxMind GeoIP' : '');
        status = needsGeo ? uiTag('Needs MaxMind GeoIP', '') : !r.enabled ? uiTag('Off', '') : key === 'breach' ? uiTag('Alerts', 'warn')
            : r.mode === 'enforce' && protectionCaps.can_ban ? uiTag('Bans', 'fail') : uiTag('Watching', 'warn');
        const would = key === 'breach' ? 0 : securityHits.filter(h => h.rule === key && h.status === 'watching').length;
        caught = r.enabled && would ? `<span class="ui-sec-caught">${would.toLocaleString()} would ban</span>` : '';
        if (needsGeo) locked = uiLocked('Needs GeoIP', 'This rule knows the country of an address only with the MaxMind GeoIP databases.');
        sentence = securityRuleSentence(key, open);
    }
    return securityCardShell(key, name, open, `${status}${caught}`, toggle, locked, `<p class="ui-sec-sent">${sentence}</p>`, open ? securityCardBody(key) : '', on);
}

function securityToggle(key, on, disabled, action, why) {
    return `<button type="button" class="ui-sec-toggle${on ? ' is-on' : ''}" aria-pressed="${on}" ${disabled ? `disabled title="${escapeHtml(why)}"` : `title="${on ? 'Turn off' : 'Turn on'}"`}
        onclick="event.stopPropagation(); ${action}" aria-label="${on ? 'On' : 'Off'}"><span class="ui-prot-mark">${on ? '✓' : '✕'}</span></button>`;
}

function securityCardShell(key, name, open, status, toggle, locked, sentence, body, on = true) {
    return `
        <article class="ui-sec-card${open ? ' is-open' : ''}${on ? '' : ' is-off'}" id="security-card-${key}" tabindex="-1" aria-label="${escapeHtml(name)}" ${open ? '' : `onclick="securityOpenCard('${key}')"`}>
            <div class="ui-sec-card-head">${toggle}<h3>${escapeHtml(name)}</h3>${status}
                <span class="ui-sec-card-act">${open
                    ? `<button type="button" class="ui-btn ui-btn-sm" onclick="event.stopPropagation(); securityOpenCard(null)">Done</button>`
                    : `<button type="button" class="ui-btn ui-btn-sm" aria-label="Edit ${escapeHtml(name)}">Edit</button>`}</span></div>
            ${locked}
            ${sentence}
            ${body}
        </article>`;
}

function renderSecuritySettings() {
    const box = document.getElementById('security-cards');
    if (!box) return;
    box.innerHTML = SECURITY_CARDS.map(securityCardHtml).join('');
    if (securityCard === 'abuse') renderSmtpAbusePanel();
    securityUpdateSaveBar();
}
