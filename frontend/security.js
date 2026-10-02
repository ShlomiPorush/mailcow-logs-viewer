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

const SECURITY_LIST_PREVIEW = 25;
const SECURITY_FILTERS = [['review', 'To review'], ['banned', 'Banned'], ['quiet', 'Tried, not banned'], ['history', 'History']];
const SECURITY_RULE_ORDER = ['trap', 'unknown_accounts', 'repeat_offender', 'subnet', 'country', 'breach'];
const SECURITY_RULE_NAMES = {
    trap: 'Trap accounts', unknown_accounts: 'Unknown accounts', repeat_offender: 'Repeat offenders',
    subnet: 'Attacking networks', country: 'Countries', breach: 'Possible stolen password'
};

// ----------------------------------------------------------------- tabs

let securityTab = 'overview';
function securityShowTab(tab) {
    securityTab = tab;
    routerSyncSubpage('netfilter', tab);
    document.querySelectorAll('.ui-se-tabs .modal-tab').forEach(btn => {
        const on = btn.id === `security-tab-btn-${tab}`;
        btn.classList.toggle('active', on);
        btn.setAttribute('aria-selected', on);
    });
    ['overview', 'events', 'protection', 'fail2ban', 'abuse'].forEach(name => {
        const panel = document.getElementById(`security-tab-${name}`);
        if (panel) panel.classList.toggle('hidden', name !== tab);
    });
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
        if (securityFilter === 'history') securityHistory = null;
        renderSecurityOverview();
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
    return `<span class="ui-prot-title">Protection</span>${f2b}${SECURITY_RULE_ORDER.map(rule).join('')}${abuse}`;
}

// A protection opens where it is set up
function securityOpenProtection(key) {
    securityShowTab(key === 'fail2ban' ? 'fail2ban' : key === 'abuse' ? 'abuse' : 'protection');
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
    const where = [a.country, a.last ? formatAgo(a.last) : ''].filter(Boolean).join(' · ');
    return `
        <div class="ui-sec-row${open ? ' is-open' : ''}" onclick="securityRowClick(event, '${escapeJsArg(a.ip)}')" role="button" tabindex="0"
             onkeydown="if (event.key === 'Enter' && event.target === this) securityToggleRow('${escapeJsArg(a.ip)}')" aria-expanded="${open}">
            <div class="ui-sec-main">
                <div class="ui-sec-top"><b class="ui-mono">${copyableText(a.ip)}</b>${d.tag}${where ? `<small class="ui-muted">${escapeHtml(where)}</small>` : ''}</div>
                <p class="ui-sec-why">${d.why}</p>
            </div>
            <div class="ui-sec-acts">${d.acts}</div>
            ${open ? securityDetail(a) : ''}
        </div>`;
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
                <div><h4>From</h4>${escapeHtml([a.city, a.country].filter(Boolean).join(', ') || 'Unknown')}${a.org ? `<br><span class="ui-muted">${escapeHtml(a.org)}</span>` : ''}</div>
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
                    <small class="ui-muted">${escapeHtml([h.country_name, formatAgo(h.ended_at || h.last_seen)].filter(Boolean).join(' · '))}</small></div>
                <p class="ui-sec-why">${escapeHtml(h.reason || '')}</p>
            </div>
        </div>`).join('');
}

// ----------------------------------------------------------------- render

function renderSecurityOverview() {
    const strip = document.getElementById('security-protections');
    if (strip) strip.innerHTML = securityProtections();
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
        <div class="ui-panel-head">
            <div class="ui-seg ui-sec-seg" role="group" aria-label="Show">${segs}</div>
            ${securityCountry ? `<span class="ui-sec-filter">${escapeHtml(securityCountry)}<button type="button" onclick="pickSecurityCountry(null)" aria-label="Show every country" title="Show every country">&times;</button></span>` : ''}
        </div>
        ${rwNote}${f2bNote}
        <div class="ui-sec-list">${securityFilter === 'history' ? securityHistoryRows()
            : shown.map(securityRow).join('') || `<p class="ui-empty">${escapeHtml(empty)}</p>`}</div>
        ${list.length > SECURITY_LIST_PREVIEW ? `<div class="ui-list-more"><button type="button" class="ui-btn ui-btn-sm" onclick="securityShowAll = !securityShowAll; renderSecurityOverview()" aria-expanded="${securityShowAll}">${securityShowAll ? 'Show fewer' : `Show all ${list.length.toLocaleString()}`}</button></div>` : ''}
        ${more}`;
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
}

function renderSecurityCountries() {
    const box = document.getElementById('security-countries');
    if (!box) return;
    const watched = new Set(((typeof protectionSaved !== 'undefined' && protectionSaved && protectionSaved.country) || {}).countries || []);
    const range = [7, 30, 90].map(d => `<button type="button" id="country-chart-${d}d" aria-pressed="${securityChartDays === d}" onclick="loadSecurityCountryChart(${d})">${d}D</button>`).join('');
    const rows = securityCountries ? securityCountries.data : null;
    const max = rows && rows.length ? Math.max(...rows.map(r => r.total)) : 1;
    const bar = r => {
        const part = (n, cls, label) => n ? `<i class="${cls}" style="width:${(n / max) * 100}%" title="${n.toLocaleString()} ${label}"></i>` : '';
        const flag = r.country_code ? getFlagUrl(r.country_code, '24x18') : '';
        return `<button type="button" class="ui-sec-bar${securityCountry === r.country_name ? ' is-on' : ''}" onclick="pickSecurityCountry('${escapeJsArg(r.country_name)}')"
                title="${escapeHtml(`${r.country_name}: ${r.total.toLocaleString()} events`)}" aria-pressed="${securityCountry === r.country_name}">
            <span class="ui-sec-bar-name">${flag ? `<img src="${flag}" alt="" width="16" height="12" onerror="this.style.display='none'">` : ''}${escapeHtml(r.country_name)}${watched.has(r.country_code) ? '<i class="ui-sec-watch" title="Watched by the Countries rule"></i>' : ''}</span>
            <span class="ui-sec-bar-track">${part(r.ban, 'is-ban', 'bans')}${part(r.warning, 'is-warn', 'warnings')}${part(r.unban, 'is-unban', 'unbans')}</span>
            <em>${r.total.toLocaleString()}</em></button>`;
    };
    const networks = securityNetworks ? securityNetworks.data : null;
    box.innerHTML = `
        <section class="ui-panel">
            <div class="ui-panel-head">Where attacks come from <div class="ui-seg ui-head-actions" role="group" aria-label="Period">${range}</div></div>
            ${rows === null ? '<div class="ui-loading"><div class="loading"></div><p>Loading...</p></div>'
                : !rows.length ? '<p id="country-chart-empty" class="ui-empty">No GeoIP data available. Configure MaxMind to enable country statistics.</p>'
                : `<div class="ui-sec-bars">${rows.map(bar).join('')}</div>
                   <p class="ui-sec-legend"><span><i class="is-ban"></i>Ban</span><span><i class="is-warn"></i>Warning</span><span><i class="is-unban"></i>Unban</span>${watched.size ? '<span><i class="ui-sec-watch"></i>Watched by the Countries rule</span>' : ''}</p>
                   <p class="ui-sec-note">Pick a country to see its addresses.</p>`}
        </section>
        <section class="ui-panel ui-sec-networks">
            <div class="ui-panel-head">Networks that try most <span class="ui-count">${securityChartDays} days</span></div>
            ${networks === null ? '' : !networks.length ? '<p class="ui-empty">No network data yet.</p>'
                : networks.map(n => `<div class="ui-sec-net"><span title="${escapeHtml(n.asn)}">${escapeHtml(n.asn_org)}</span><small class="ui-muted">${n.addresses.toLocaleString()} address${n.addresses === 1 ? '' : 'es'}</small><b>${n.attempts.toLocaleString()}</b></div>`).join('')}
        </section>`;
}
