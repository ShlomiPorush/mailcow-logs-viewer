// =============================================================================
// PROTECTION RULES (Security page: their data and editing; security.js draws them)
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
let protectionDirty = false;
let protectionSaved = null;  // the rules as stored, to count unsaved changes

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

let protectionLoadError = null;

async function loadProtection() {
    try {
        const [rulesRes, hitsRes] = await Promise.all([
            authenticatedFetch('/api/protection/rules'),
            authenticatedFetch('/api/protection/hits?status=active&limit=500')
        ]);
        if (!rulesRes.ok || !hitsRes.ok) throw new Error(`HTTP ${rulesRes.ok ? hitsRes.status : rulesRes.status}`);
        const rulesData = await rulesRes.json();
        const hitsData = await hitsRes.json();
        // Unsaved edits stay on screen through the page's own refresh
        if (!protectionDirty) {
            protectionRules = rulesData.rules;
            protectionSaved = JSON.parse(JSON.stringify(rulesData.rules));
        }
        protectionCaps = rulesData.capabilities || protectionCaps;
        protectionSuggestions = rulesData.trap_suggestions || [];
        protectionCountrySuggestions = rulesData.country_suggestions || [];
        protectionHits = hitsData.hits || [];
        protectionCounts = hitsData.counts || {};
        protectionLoadError = null;
        renderProtection();
    } catch (error) {
        console.error('Failed to load protection rules:', error);
        protectionLoadError = error.message;
        renderSecuritySettings();
    }
    loadProtectionOverview();
}

// Only the hits refresh on the page's timer; the rule editors keep their state
function refreshProtectionHits() {
    loadProtectionOverview();
}

function protectionOpenCount(counts) {
    return (counts.watching || 0) + (counts.pending || 0) + (counts.alert || 0);
}

// ----------------------------------------------------------------- rule cards
// The rules are edited in the Security page's Settings cards (security.js)

function renderProtection() {
    renderSecuritySettings();
    markProtectionDirty();
    // The Overview shows which rules are on, and the countries the Countries rule watches
    renderSecurityOverview();
    renderSecurityCountries();
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

// ----------------------------------------------------------------- editing

// Count the settings that differ from the stored rules, like the Settings page
function protectionChangeCount() {
    if (!protectionRules || !protectionSaved) return 0;
    let n = 0;
    for (const [rule, values] of Object.entries(protectionRules)) {
        for (const [key, value] of Object.entries(values)) {
            const saved = (protectionSaved[rule] || {})[key];
            // Number inputs hand over strings; 5 and "5" are the same setting
            if (String(JSON.stringify(value)).replace(/"/g, '') !== String(JSON.stringify(saved)).replace(/"/g, '')) n++;
        }
    }
    return n;
}

function markProtectionDirty() {
    const n = protectionChangeCount();
    protectionDirty = n > 0;
    securityUpdateSaveBar();
}

function discardProtectionRules() {
    protectionRules = JSON.parse(JSON.stringify(protectionSaved));
    protectionDirty = false;
    renderProtection();
}

function setProtectionRule(rule, key, value) {
    if (!protectionRules) return;
    protectionRules[rule][key] = value;
    renderProtection();
}

function setProtectionMode(rule, mode) {
    if (!protectionRules) return;
    protectionRules[rule].mode = mode;
    renderProtection();
}

function addTrapName(value) {
    const name = String(value || '').trim().toLowerCase();
    if (!name || !protectionRules) return;
    if (!protectionRules.trap.names.includes(name)) protectionRules.trap.names.push(name);
    renderProtection();
}

function removeTrapName(name) {
    if (!protectionRules) return;
    protectionRules.trap.names = protectionRules.trap.names.filter(n => n !== name);
    renderProtection();
}

function addProtectionCountry(value) {
    const code = String(value || '').trim().toUpperCase();
    if (!code || !protectionRules) return;
    if (!protectionRules.country.countries.includes(code)) protectionRules.country.countries.push(code);
    renderProtection();
}

function removeProtectionCountry(code) {
    if (!protectionRules) return;
    protectionRules.country.countries = protectionRules.country.countries.filter(c => c !== code);
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
        protectionSaved = JSON.parse(JSON.stringify(data.rules));
        protectionDirty = false;
        showToast('Protection rules saved', 'success');
        loadProtection();
    } catch (error) {
        showToast(`Could not save the rules: ${error.message}`, 'error');
        return false;
    }
    return true;
}

async function protectionHitAction(id, action, button, done) {
    if (button) button.disabled = true;
    try {
        const res = await authenticatedFetch(`/api/protection/hits/${id}/${action}`, { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        if (done) showToast(done(data), 'success');
        refreshProtectionHits();
        if (action !== 'dismiss') {
            // The blacklist changed: show it in the Overview and the Lists
            fail2banSettingsLoaded = false;
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
