// =============================================================================
// PROTECTION RULES (Security page, Protection tab)
// The rules read the failed logins and note which addresses they would ban and
// why. Watch mode only: nothing is banned. The admin manages the rules here and
// reviews what they caught.
// =============================================================================

let protectionRules = null;
let protectionSuggestions = [];
let protectionHits = [];
let protectionCounts = {};
let protectionFilter = 'watching';
let protectionDirty = false;

const PROTECTION_RULE_LABELS = { trap: 'Trap account', unknown_accounts: 'Unknown accounts' };

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
        protectionSuggestions = rulesData.trap_suggestions || [];
        protectionHits = hitsData.hits || [];
        protectionCounts = hitsData.counts || {};
        renderProtection();
    } catch (error) {
        console.error('Failed to load protection rules:', error);
        panel.innerHTML = `<p class="ui-empty ui-text-fail">Failed to load the protection rules: ${escapeHtml(error.message)}</p>`;
    }
}

// Only the hits refresh on the page's timer; the rule editors keep their state
async function refreshProtectionHits() {
    if (!document.getElementById('protection-hits')) return;
    try {
        const res = await authenticatedFetch(`/api/protection/hits?status=${protectionFilter}`);
        if (!res.ok) return;
        const data = await res.json();
        protectionHits = data.hits || [];
        protectionCounts = data.counts || {};
        const box = document.getElementById('protection-hits');
        if (box) box.innerHTML = renderProtectionHits();
        updateProtectionTabCount();
    } catch (e) { /* the next refresh tries again */ }
}

function updateProtectionTabCount() {
    const n = document.getElementById('security-tab-n-protection');
    if (!n) return;
    const watching = protectionCounts.watching || 0;
    n.textContent = watching || '';
    n.classList.toggle('hidden', !watching);
}

function renderProtection() {
    const panel = document.getElementById('protection-panel');
    if (!panel || !protectionRules) return;
    const trap = protectionRules.trap;
    const ua = protectionRules.unknown_accounts;
    panel.innerHTML = `
        <div class="ui-list-note ui-flush">${uiLocked('Watch mode',
            'The rules only note which addresses they would ban and why. Nothing is banned. Review what they catch here before banning is added.', '')}</div>
        <div class="ui-prot-rules">
            <section class="ui-panel ui-prot-rule">
                <div class="ui-prot-rule-head">
                    <div><h3>Trap accounts</h3><p class="ui-muted">Account names that have no mailbox. An address that tries one is caught at once.</p></div>
                    <label class="ui-check-label"><input type="checkbox" class="ui-check" ${trap.enabled ? 'checked' : ''} onchange="setProtectionRule('trap', 'enabled', this.checked)"> On</label>
                </div>
                <div class="ui-prot-names">
                    ${trap.names.length ? trap.names.map(name => `<span class="ui-prot-name">${escapeHtml(name)}<button type="button" onclick="removeTrapName('${escapeJsArg(name)}')" aria-label="Remove ${escapeHtml(name)}" title="Remove">&times;</button></span>`).join('') : '<span class="ui-muted">No trap names yet</span>'}
                </div>
                <form class="ui-prot-add" onsubmit="event.preventDefault(); addTrapName(this.elements.name.value); this.reset();">
                    <input type="text" name="name" class="ui-input" placeholder="admin or admin@example.com" aria-label="Trap account name" maxlength="255">
                    <button type="submit" class="ui-btn">Add</button>
                </form>
                ${protectionSuggestions.length ? `
                    <div class="ui-prot-suggest">
                        <span class="ui-muted">Tried in the last 7 days and do not exist here:</span>
                        <div class="ui-chip-row">${protectionSuggestions.filter(s => !trap.names.includes(s.name)).map(s => `
                            <button type="button" class="ui-chip" onclick="addTrapName('${escapeJsArg(s.name)}')" title="${s.tries} tries from ${s.addresses} address${s.addresses === 1 ? '' : 'es'}">+ ${escapeHtml(s.name)} <small>${s.tries}</small></button>`).join('')}
                        </div>
                    </div>` : ''}
            </section>
            <section class="ui-panel ui-prot-rule">
                <div class="ui-prot-rule-head">
                    <div><h3>Unknown accounts</h3><p class="ui-muted">An address that keeps guessing accounts that do not exist here.</p></div>
                    <label class="ui-check-label"><input type="checkbox" class="ui-check" ${ua.enabled ? 'checked' : ''} onchange="setProtectionRule('unknown_accounts', 'enabled', this.checked)"> On</label>
                </div>
                <p class="ui-prot-sentence">Catch an address that tries
                    <input type="number" class="ui-input ui-prot-num" min="2" max="100" value="${escapeHtml(String(ua.threshold))}" onchange="setProtectionRule('unknown_accounts', 'threshold', this.value)" aria-label="Number of accounts">
                    accounts that do not exist within
                    <input type="number" class="ui-input ui-prot-num" min="5" max="1440" value="${escapeHtml(String(ua.window_minutes))}" onchange="setProtectionRule('unknown_accounts', 'window_minutes', this.value)" aria-label="Minutes">
                    minutes.</p>
                <p class="ui-muted ui-prot-note">An address with a successful login in the last day is never caught by this rule, so a user who mistyped the address is safe.</p>
            </section>
        </div>
        <div class="ui-prot-save${protectionDirty ? '' : ' hidden'}" id="protection-savebar">
            <span>Unsaved changes to the rules</span>
            <button type="button" class="ui-btn" onclick="protectionDirty = false; loadProtection()">Discard</button>
            <button type="button" class="ui-btn ui-btn-primary" onclick="saveProtectionRules()">Save</button>
        </div>
        <div class="ui-list-head">
            <h2 class="ui-h2">What the rules caught</h2>
            <div class="ui-seg ui-head-actions" role="group" aria-label="Show">
                <button type="button" aria-pressed="${protectionFilter === 'watching'}" onclick="setProtectionFilter('watching')">Would ban${protectionCounts.watching ? ` ${protectionCounts.watching}` : ''}</button>
                <button type="button" aria-pressed="${protectionFilter === 'dismissed'}" onclick="setProtectionFilter('dismissed')">Dismissed</button>
            </div>
        </div>
        <div id="protection-hits">${renderProtectionHits()}</div>
    `;
    updateProtectionTabCount();
}

function renderProtectionHits() {
    if (!protectionHits.length) {
        return `<p class="ui-empty ui-panel">${protectionFilter === 'watching'
            ? (protectionRules && (protectionRules.trap.enabled || protectionRules.unknown_accounts.enabled)
                ? 'Nothing caught yet. New failed logins are checked after every log fetch.'
                : 'Turn on a rule above to see which addresses it would ban.')
            : 'Nothing dismissed.'}</p>`;
    }
    return `
        <div class="ui-table ui-stack" style="--ui-cols: 110px minmax(150px, 1fr) 130px minmax(220px, 2fr) 60px 90px; --ui-table-min: 820px">
            <div class="ui-tr ui-tr-head"><span>Last try</span><span>Address</span><span>Rule</span><span>Why</span><span class="ui-td-end">Tries</span><span></span></div>
            ${protectionHits.map(hit => `
                <div class="ui-tr">
                    <span class="ui-td" title="${escapeHtml(formatTime(hit.last_seen))}" data-sort="${escapeHtml(hit.last_seen || '')}">${formatAgo(hit.last_seen)}</span>
                    <span class="ui-td ui-q-who"><div class="ui-mono">${copyableText(hit.ip)}</div>${hit.country_name ? `<small>${escapeHtml(hit.country_name)}</small>` : ''}</span>
                    <span class="ui-td">${uiTag(PROTECTION_RULE_LABELS[hit.rule] || hit.rule, hit.rule === 'trap' ? 'fail' : 'warn')}</span>
                    <span class="ui-td ui-td-wrap"><span>${escapeHtml(hit.reason || '')}</span><small class="ui-muted ui-prot-tried">Tried ${hit.usernames.slice(0, 6).map(u => escapeHtml(u)).join(', ')}${hit.usernames.length > 6 ? ` and ${hit.usernames.length - 6} more` : ''}</small></span>
                    <span class="ui-td ui-td-end">${hit.attempts}</span>
                    <span class="ui-td ui-td-end">${hit.status === 'watching' ? `<button type="button" class="ui-btn ui-btn-sm" onclick="dismissProtectionHit(${Number(hit.id)})" title="Not an attack: stop listing it">Dismiss</button>` : ''}</span>
                </div>`).join('')}
        </div>`;
}

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

async function dismissProtectionHit(id) {
    try {
        const res = await authenticatedFetch(`/api/protection/hits/${id}/dismiss`, { method: 'POST' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        refreshProtectionHits();
    } catch (error) {
        showToast(`Could not dismiss: ${error.message}`, 'error');
    }
}
