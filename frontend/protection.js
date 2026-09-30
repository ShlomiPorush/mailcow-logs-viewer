// =============================================================================
// PROTECTION RULES (Security page, Protection tab and the Overview panel)
// The rules read the failed logins and catch the addresses that attack. A rule
// in watch mode only notes what it would ban; in ban mode the address goes on
// the Fail2ban blacklist for the rule's ban length. The breach alert never bans.
// =============================================================================

let protectionRules = null;
let protectionCaps = { can_ban: false, geoip: false, raw_logs: false };
let protectionSuggestions = [];
let protectionCountrySuggestions = [];
let protectionHits = [];
let protectionCounts = {};
let protectionFilter = 'active';
let protectionDirty = false;

const PROTECTION_RULE_LABELS = {
    trap: 'Trap account',
    unknown_accounts: 'Unknown accounts',
    repeat_offender: 'Repeat offender',
    subnet: 'Attacking network',
    country: 'Country',
    breach: 'Possible stolen password'
};
const PROTECTION_BAN_RULES = ['trap', 'unknown_accounts', 'repeat_offender', 'subnet', 'country'];
const PROTECTION_BAN_LENGTHS = [[1, '1 hour'], [6, '6 hours'], [24, '1 day'], [168, '7 days'], [720, '30 days'], [2160, '90 days'], [0, 'Until removed by hand']];

async function loadProtection() {
    const panel = document.getElementById('protection-panel');
    if (!panel) return;
    try {
        const [rulesRes, hitsRes] = await Promise.all([
            authenticatedFetch('/api/protection/rules'),
            authenticatedFetch(`/api/protection/hits?status=${protectionFilter}`)
        ]);
        if (!rulesRes.ok || !hitsRes.ok) throw new Error(`HTTP ${rulesRes.ok ? hitsRes.status : rulesRes.status}`);
        const rulesData = await rulesRes.json();
        const hitsData = await hitsRes.json();
        // Unsaved edits stay on screen through the page's own refresh
        if (!protectionDirty) protectionRules = rulesData.rules;
        protectionCaps = rulesData.capabilities || protectionCaps;
        protectionSuggestions = rulesData.trap_suggestions || [];
        protectionCountrySuggestions = rulesData.country_suggestions || [];
        protectionHits = hitsData.hits || [];
        protectionCounts = hitsData.counts || {};
        renderProtection();
    } catch (error) {
        console.error('Failed to load protection rules:', error);
        panel.innerHTML = `<p class="ui-empty ui-text-fail">Failed to load the protection rules: ${escapeHtml(error.message)}</p>`;
    }
    loadProtectionOverview();
}

// Only the hits refresh on the page's timer; the rule editors keep their state
async function refreshProtectionHits() {
    loadProtectionOverview();
    if (!document.getElementById('protection-hits')) return;
    try {
        const res = await authenticatedFetch(`/api/protection/hits?status=${protectionFilter}`);
        if (!res.ok) return;
        const data = await res.json();
        protectionHits = data.hits || [];
        protectionCounts = data.counts || {};
        const box = document.getElementById('protection-hits');
        if (box) box.innerHTML = renderProtectionHits();
        updateProtectionCounts();
    } catch (e) { /* the next refresh tries again */ }
}

function protectionOpenCount(counts) {
    return (counts.watching || 0) + (counts.pending || 0) + (counts.alert || 0);
}

function updateProtectionCounts() {
    const n = document.getElementById('security-tab-n-protection');
    if (n) {
        const open = protectionOpenCount(protectionCounts);
        n.textContent = open || '';
        n.classList.toggle('hidden', !open);
    }
    const seg = document.getElementById('protection-seg-active');
    if (seg) seg.textContent = `Active${protectionActiveCount() ? ` ${protectionActiveCount()}` : ''}`;
}

function protectionActiveCount() {
    return protectionOpenCount(protectionCounts) + (protectionCounts.banned || 0);
}

// ----------------------------------------------------------------- rule cards

function protectionNum(rule, key, min, max, label) {
    const value = protectionRules[rule][key];
    return `<input type="number" class="ui-input ui-prot-num" min="${min}" max="${max}" value="${escapeHtml(String(value))}" onchange="setProtectionRule('${rule}', '${key}', this.value)" aria-label="${escapeHtml(label)}">`;
}

function protectionToggle(rule) {
    return `<label class="ui-check-label"><input type="checkbox" class="ui-check" ${protectionRules[rule].enabled ? 'checked' : ''} onchange="setProtectionRule('${rule}', 'enabled', this.checked)"> On</label>`;
}

// Watch or ban, how long, and whether to send an email: the same for every banning rule
function protectionBanControls(rule) {
    const r = protectionRules[rule];
    const lengths = PROTECTION_BAN_LENGTHS.some(([h]) => h === Number(r.ban_hours))
        ? PROTECTION_BAN_LENGTHS : [...PROTECTION_BAN_LENGTHS, [Number(r.ban_hours), `${r.ban_hours} hours`]];
    const canBan = protectionCaps.can_ban;
    return `
        <div class="ui-prot-controls">
            <div class="ui-seg" role="group" aria-label="What the rule does">
                <button type="button" aria-pressed="${r.mode !== 'enforce'}" onclick="setProtectionMode('${rule}', 'watch')" title="Note what it would ban; ban nothing">Watch</button>
                <button type="button" aria-pressed="${r.mode === 'enforce'}" onclick="setProtectionMode('${rule}', 'enforce')" ${canBan ? '' : 'disabled'} title="${canBan ? 'Put what it catches on the Fail2ban blacklist' : 'Banning needs the Read-Write API key'}">Ban</button>
            </div>
            <label class="ui-prot-inline">Ban for
                <select class="ui-select ui-select-auto" onchange="setProtectionRule('${rule}', 'ban_hours', this.value)" aria-label="Ban length">
                    ${lengths.map(([h, text]) => `<option value="${h}" ${Number(r.ban_hours) === h ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}
                </select>
            </label>
            ${protectionNotify(rule, 'Email me when it bans')}
        </div>`;
}

function protectionNotify(rule, text) {
    return `<label class="ui-check-label ui-prot-inline"><input type="checkbox" class="ui-check" ${protectionRules[rule].notify ? 'checked' : ''} onchange="setProtectionRule('${rule}', 'notify', this.checked)"> ${escapeHtml(text)}</label>`;
}

function protectionRuleCard(rule, title, description, body, locked) {
    const on = protectionRules[rule].enabled;
    const banning = PROTECTION_BAN_RULES.includes(rule);
    const mode = !on ? uiTag('Off', '') : !banning ? uiTag('Alerts', 'warn')
        : protectionRules[rule].mode === 'enforce' ? uiTag('Bans', 'fail') : uiTag('Watching', 'warn');
    return `
        <section class="ui-panel ui-prot-rule${on ? '' : ' ui-prot-off'}">
            <div class="ui-prot-rule-head">
                <div><h3>${escapeHtml(title)} ${mode}</h3><p class="ui-muted">${description}</p></div>
                ${protectionToggle(rule)}
            </div>
            ${locked || ''}
            ${body}
            ${banning ? protectionBanControls(rule) : ''}
        </section>`;
}

function renderProtection() {
    const panel = document.getElementById('protection-panel');
    if (!panel || !protectionRules) return;
    const R = protectionRules;
    const trapNames = R.trap.names.length
        ? R.trap.names.map(name => `<span class="ui-prot-name">${escapeHtml(name)}<button type="button" onclick="removeTrapName('${escapeJsArg(name)}')" aria-label="Remove ${escapeHtml(name)}" title="Remove">&times;</button></span>`).join('')
        : '<span class="ui-muted">No trap names yet</span>';
    const trapSuggest = protectionSuggestions.filter(s => !R.trap.names.includes(s.name));
    const countryNames = R.country.countries.length
        ? R.country.countries.map(code => `<span class="ui-prot-name">${escapeHtml(protectionCountryName(code))}<button type="button" onclick="removeProtectionCountry('${escapeJsArg(code)}')" aria-label="Remove ${escapeHtml(code)}" title="Remove">&times;</button></span>`).join('')
        : '<span class="ui-muted">No countries yet</span>';
    const countrySuggest = protectionCountrySuggestions.filter(s => !R.country.countries.includes(s.code));

    panel.innerHTML = `
        ${protectionCaps.can_ban ? '' : `<div class="ui-list-note ui-flush">${uiLocked('The rules can only watch', `Banning ${UI_RW_KEY_TEXT}`)}</div>`}
        <p class="ui-muted ui-prot-intro">Every rule starts by watching: it notes what it would ban, and bans nothing until you switch it to Ban. The Fail2ban allowlist, internal networks and the mailcow server are never caught.</p>
        <div class="ui-prot-rules">
            ${protectionRuleCard('trap', 'Trap accounts', 'Account names that have no mailbox. An address that tries one is caught at once.', `
                <div class="ui-prot-names">${trapNames}</div>
                <form class="ui-prot-add" onsubmit="event.preventDefault(); addTrapName(this.elements.name.value); this.reset();">
                    <input type="text" name="name" class="ui-input" placeholder="admin or admin@example.com" aria-label="Trap account name" maxlength="255">
                    <button type="submit" class="ui-btn">Add</button>
                </form>
                ${trapSuggest.length ? `
                    <div class="ui-prot-suggest">
                        <span class="ui-muted">Tried in the last 7 days and do not exist here:</span>
                        <div class="ui-chip-row">${trapSuggest.map(s => `
                            <button type="button" class="ui-chip" onclick="addTrapName('${escapeJsArg(s.name)}')" title="${s.tries} tries from ${s.addresses} address${s.addresses === 1 ? '' : 'es'}">+ ${escapeHtml(s.name)} <small>${s.tries}</small></button>`).join('')}
                        </div>
                    </div>` : ''}`)}
            ${protectionRuleCard('unknown_accounts', 'Unknown accounts', 'An address that keeps guessing accounts that do not exist here.', `
                <p class="ui-prot-sentence">Catch an address that tries
                    ${protectionNum('unknown_accounts', 'threshold', 2, 100, 'Number of accounts')}
                    accounts that do not exist within
                    ${protectionNum('unknown_accounts', 'window_minutes', 5, 1440, 'Minutes')}
                    minutes.</p>
                <p class="ui-muted ui-prot-note">An address with a successful login in the last day is never caught by this rule, so a user who mistyped the address is safe.</p>`)}
            ${protectionRuleCard('repeat_offender', 'Repeat offenders', 'An address Fail2ban keeps banning comes back after every ban. Keep it out for longer.', `
                <p class="ui-prot-sentence">Catch an address Fail2ban banned
                    ${protectionNum('repeat_offender', 'threshold', 2, 50, 'Number of bans')}
                    times within
                    ${protectionNum('repeat_offender', 'window_days', 1, 365, 'Days')}
                    days.</p>`)}
            ${protectionRuleCard('subnet', 'Attacking networks', 'Attacks that come from many addresses of one network. The whole network (IPv4 /24) is caught.', `
                <p class="ui-prot-sentence">Catch a network when
                    ${protectionNum('subnet', 'threshold', 2, 256, 'Number of addresses')}
                    of its addresses attack within
                    ${protectionNum('subnet', 'window_hours', 1, 168, 'Hours')}
                    hours.</p>
                <p class="ui-muted ui-prot-note">A network that holds an allowlisted address, an internal address or the mailcow server is never caught.</p>`)}
            ${protectionRuleCard('country', 'Countries', 'Failed logins from countries you never expect a user in.', `
                <div class="ui-prot-names">${countryNames}</div>
                <form class="ui-prot-add" onsubmit="event.preventDefault(); addProtectionCountry(this.elements.code.value); this.reset();">
                    <input type="text" name="code" class="ui-input" placeholder="Two-letter code, for example CN" aria-label="Country code" maxlength="2">
                    <button type="submit" class="ui-btn">Add</button>
                </form>
                ${countrySuggest.length ? `
                    <div class="ui-prot-suggest">
                        <span class="ui-muted">Failed logins in the last 7 days came from:</span>
                        <div class="ui-chip-row">${countrySuggest.map(s => `
                            <button type="button" class="ui-chip" onclick="addProtectionCountry('${escapeJsArg(s.code)}')" title="${s.tries} failed logins">+ ${escapeHtml(s.name)} <small>${s.tries}</small></button>`).join('')}
                        </div>
                    </div>` : ''}
                <p class="ui-muted ui-prot-note">Only failed logins are caught. A user who logs in from one of these countries is not affected.</p>`,
                protectionCaps.geoip ? '' : uiLocked('Needs GeoIP', 'This rule knows the country of an address only with the MaxMind GeoIP databases.'))}
            ${protectionRuleCard('breach', 'Possible stolen password', 'A successful login that looks like someone else is using the password. It sends an alert and never bans, so the real user is not locked out.', `
                <p class="ui-prot-sentence">Alert when an account logs in after
                    ${protectionNum('breach', 'failures', 1, 50, 'Number of failed tries')}
                    failed tries from the same address within
                    ${protectionNum('breach', 'window_minutes', 5, 1440, 'Minutes')}
                    minutes.</p>
                <label class="ui-check-label"><input type="checkbox" class="ui-check" ${R.breach.new_country ? 'checked' : ''} ${protectionCaps.geoip ? '' : 'disabled'} onchange="setProtectionRule('breach', 'new_country', this.checked)"> Also alert on a login from a country the account did not use in 30 days${protectionCaps.geoip ? '' : ' (needs GeoIP)'}</label>
                ${protectionNotify('breach', 'Email me on every alert')}
                <p class="ui-muted ui-prot-note">${protectionCaps.raw_logs ? 'SMTP and IMAP logins are checked.' : 'Only SMTP logins are checked. IMAP logins need Live Logs to be on.'}</p>`)}
        </div>
        <div class="ui-prot-save${protectionDirty ? '' : ' hidden'}" id="protection-savebar">
            <span>Unsaved changes to the rules</span>
            <button type="button" class="ui-btn" onclick="protectionDirty = false; loadProtection()">Discard</button>
            <button type="button" class="ui-btn ui-btn-primary" onclick="saveProtectionRules()">Save</button>
        </div>
        <div class="ui-list-head">
            <h2 class="ui-h2">What the rules caught</h2>
            <div class="ui-seg ui-head-actions" role="group" aria-label="Show">
                <button type="button" id="protection-seg-active" aria-pressed="${protectionFilter === 'active'}" onclick="setProtectionFilter('active')">Active${protectionActiveCount() ? ` ${protectionActiveCount()}` : ''}</button>
                <button type="button" aria-pressed="${protectionFilter === 'history'}" onclick="setProtectionFilter('history')">History</button>
            </div>
        </div>
        <div id="protection-hits">${renderProtectionHits()}</div>
    `;
    updateProtectionCounts();
}

function protectionCountryName(code) {
    const known = protectionCountrySuggestions.find(s => s.code === code);
    return known ? `${known.name} (${code})` : code;
}

// ----------------------------------------------------------------- hits

function protectionStatus(hit) {
    switch (hit.status) {
        case 'watching': return uiTag('Would ban', 'warn');
        case 'pending': return uiTag(hit.error ? 'Not banned yet' : 'Banning', 'warn');
        case 'banned': return uiTag(hit.expires_at ? `Banned until ${formatTime(hit.expires_at)}` : 'Banned until removed', 'fail');
        case 'alert': return uiTag('Alert', 'fail');
        case 'expired': return uiTag('Ban ended', '');
        case 'undone': return uiTag('Ban undone', '');
        case 'dismissed': return uiTag('Dismissed', '');
        default: return uiTag(hit.status, '');
    }
}

function protectionActions(hit) {
    const id = Number(hit.id);
    const buttons = [];
    if (hit.status === 'watching' && hit.rule !== 'breach' && protectionCaps.can_ban) {
        buttons.push(`<button type="button" class="ui-btn ui-btn-sm ui-btn-danger" onclick="banProtectionHit(${id}, this)" title="Put it on the Fail2ban blacklist now">Ban now</button>`);
    }
    if (hit.status === 'watching' || hit.status === 'alert') {
        buttons.push(`<button type="button" class="ui-btn ui-btn-sm" onclick="dismissProtectionHit(${id})" title="Not an attack: stop listing it; the rule leaves it alone for a week">Dismiss</button>`);
    }
    if (hit.status === 'banned' || hit.status === 'pending') {
        buttons.push(`<button type="button" class="ui-btn ui-btn-sm" onclick="undoProtectionHit(${id}, this)" title="Lift the ban; the rule leaves it alone for a week">Undo</button>`);
    }
    return buttons.join('');
}

function renderProtectionHits() {
    if (!protectionHits.length) {
        const anyOn = protectionRules && Object.values(protectionRules).some(r => r.enabled);
        return `<p class="ui-empty ui-panel">${protectionFilter === 'active'
            ? (anyOn ? 'Nothing caught yet. New logins are checked after every log fetch.' : 'Turn on a rule above to see what it catches.')
            : 'Nothing here yet. Ended, undone and dismissed hits are kept here.'}</p>`;
    }
    return `
        <div class="ui-table ui-stack" style="--ui-cols: 100px minmax(150px, 1fr) 150px minmax(220px, 2fr) minmax(130px, 1fr) 150px; --ui-table-min: 920px">
            <div class="ui-tr ui-tr-head"><span>Last try</span><span>Address</span><span>Rule</span><span>Why</span><span>Status</span><span></span></div>
            ${protectionHits.map(hit => `
                <div class="ui-tr${hit.status === 'alert' || hit.status === 'watching' ? ' ui-tr-attn' : ''}">
                    <span class="ui-td" title="${escapeHtml(formatTime(hit.last_seen))}" data-sort="${escapeHtml(hit.last_seen || '')}">${formatAgo(hit.last_seen)}</span>
                    <span class="ui-td ui-q-who"><div class="ui-mono">${copyableText(hit.ip)}</div>${hit.country_name ? `<small>${escapeHtml(hit.country_name)}</small>` : ''}</span>
                    <span class="ui-td">${uiTag(PROTECTION_RULE_LABELS[hit.rule] || hit.rule, hit.rule === 'trap' || hit.rule === 'breach' ? 'fail' : 'warn')}</span>
                    <span class="ui-td ui-td-wrap"><span>${escapeHtml(hit.reason || '')}</span>${hit.usernames.length && !['breach', 'trap'].includes(hit.rule) ? `<small class="ui-muted ui-prot-tried">Tried ${hit.usernames.slice(0, 6).map(u => escapeHtml(u)).join(', ')}${hit.usernames.length > 6 ? ` and ${hit.usernames.length - 6} more` : ''}</small>` : ''}${hit.error ? `<small class="ui-text-fail ui-prot-tried">${escapeHtml(hit.error)}</small>` : ''}</span>
                    <span class="ui-td">${protectionStatus(hit)}</span>
                    <span class="ui-td ui-td-end ui-prot-acts">${protectionActions(hit)}</span>
                </div>`).join('')}
        </div>`;
}

// ----------------------------------------------------------------- Security Overview

// The Overview shows what the rules caught that still needs a look
async function loadProtectionOverview() {
    const box = document.getElementById('security-decide');
    if (!box) return;
    try {
        const res = await authenticatedFetch('/api/protection/hits?status=active&limit=200');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const hits = data.hits || [];
        const counts = data.counts || {};
        const review = hits.filter(h => ['alert', 'watching', 'pending'].includes(h.status));
        const kpi = document.getElementById('security-kpi-decide');
        if (kpi) {
            kpi.textContent = protectionOpenCount(counts).toLocaleString();
            kpi.className = counts.alert ? 'ui-fail' : protectionOpenCount(counts) ? 'ui-warn' : '';
        }
        const note = document.getElementById('security-decide-note');
        if (note) note.textContent = counts.banned ? `${counts.banned} banned by the rules now` : '';
        const shown = review.sort((a, b) => (a.status === 'alert' ? 0 : 1) - (b.status === 'alert' ? 0 : 1)).slice(0, 6);
        box.innerHTML = !shown.length
            ? `<p class="ui-st-allgood">Nothing to review. ${counts.banned ? 'The rules are banning what they catch.' : 'What the protection rules catch shows up here.'}</p>`
            : `${shown.map(hit => `
                <div class="ui-st-listing">
                    <div><b class="ui-mono">${copyableText(hit.ip)}</b> ${protectionStatus(hit)}<small title="${escapeHtml(hit.reason || '')}">${escapeHtml(PROTECTION_RULE_LABELS[hit.rule] || hit.rule)}: ${escapeHtml(hit.reason || '')}, ${formatAgo(hit.last_seen)}</small></div>
                    <span class="ui-st-acts">${protectionActions(hit)}</span>
                </div>`).join('')}
               <div class="ui-list-more"><button type="button" class="ui-btn ui-btn-sm" onclick="securityShowTab('protection')">${review.length > shown.length ? `Review all ${review.length}` : 'Open the rules'}</button></div>`;
    } catch (error) {
        box.innerHTML = `<p class="ui-empty ui-text-fail">Failed to load: ${escapeHtml(error.message)}</p>`;
    }
}

// ----------------------------------------------------------------- editing

function markProtectionDirty() {
    protectionDirty = true;
    const bar = document.getElementById('protection-savebar');
    if (bar) bar.classList.remove('hidden');
}

function setProtectionRule(rule, key, value) {
    if (!protectionRules) return;
    protectionRules[rule][key] = value;
    markProtectionDirty();
}

function setProtectionMode(rule, mode) {
    if (!protectionRules) return;
    protectionRules[rule].mode = mode;
    protectionDirty = true;
    renderProtection();
}

function addTrapName(value) {
    const name = String(value || '').trim().toLowerCase();
    if (!name || !protectionRules) return;
    if (!protectionRules.trap.names.includes(name)) protectionRules.trap.names.push(name);
    protectionDirty = true;
    renderProtection();
}

function removeTrapName(name) {
    if (!protectionRules) return;
    protectionRules.trap.names = protectionRules.trap.names.filter(n => n !== name);
    protectionDirty = true;
    renderProtection();
}

function addProtectionCountry(value) {
    const code = String(value || '').trim().toUpperCase();
    if (!code || !protectionRules) return;
    if (!protectionRules.country.countries.includes(code)) protectionRules.country.countries.push(code);
    protectionDirty = true;
    renderProtection();
}

function removeProtectionCountry(code) {
    if (!protectionRules) return;
    protectionRules.country.countries = protectionRules.country.countries.filter(c => c !== code);
    protectionDirty = true;
    renderProtection();
}

async function saveProtectionRules() {
    try {
        const res = await authenticatedFetch('/api/protection/rules', {
            method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ rules: protectionRules })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        protectionRules = data.rules;
        protectionDirty = false;
        showToast('Protection rules saved', 'success');
        loadProtection();
    } catch (error) {
        showToast(`Could not save the rules: ${error.message}`, 'error');
    }
}

function setProtectionFilter(filter) {
    protectionFilter = filter;
    loadProtection();
}

async function protectionHitAction(id, action, button, done) {
    if (button) button.disabled = true;
    try {
        const res = await authenticatedFetch(`/api/protection/hits/${id}/${action}`, { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        if (done) showToast(done(data), 'success');
        refreshProtectionHits();
        if (action !== 'dismiss' && typeof loadFail2BanSettings === 'function') {
            // The blacklist changed: show it on the Fail2ban tab and in the address states
            fail2banSettingsLoaded = false;
            fail2banActiveBans = null;
            loadFail2BanSettings();
        }
    } catch (error) {
        showToast(`Could not ${action === 'ban' ? 'ban' : action}: ${error.message}`, 'error');
        if (button) button.disabled = false;
    }
}

function banProtectionHit(id, button) {
    protectionHitAction(id, 'ban', button, hit => `${hit.ip} is on the Fail2ban blacklist`);
}

function undoProtectionHit(id, button) {
    protectionHitAction(id, 'undo', button, hit => `The ban on ${hit.ip} is lifted`);
}

function dismissProtectionHit(id) {
    protectionHitAction(id, 'dismiss', null, null);
}
