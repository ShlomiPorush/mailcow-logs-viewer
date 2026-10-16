// =============================================================================
// PROTECTION RULES (Security page: their data and editing; security.js draws them)
// The rules read the failed logins and catch the addresses that attack. A rule
// in watch mode only notes what it catches; in ban mode the address goes on
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

// Every country GeoIP can name, by its ISO 3166-1 code, named in English by the
// browser itself. Unions, test codes and retired codes the browser also knows are left out.
const PROTECTION_NOT_COUNTRIES = new Set(('EU EZ UN QO XA XB ZZ AC CP CQ DG EA IC TA '
    + 'AN BU CS DD DY FX NT SU TP YD YU ZR HV NH RH UK VD').split(' '));
let protectionCountryList = null;

function protectionCountries() {
    if (protectionCountryList) return protectionCountryList;
    protectionCountryList = [];
    let names;
    try {
        names = new Intl.DisplayNames(['en'], { type: 'region', fallback: 'none' });
    } catch (e) {
        return protectionCountryList;
    }
    for (let a = 65; a <= 90; a++) {
        for (let b = 65; b <= 90; b++) {
            const code = String.fromCharCode(a, b);
            const name = PROTECTION_NOT_COUNTRIES.has(code) ? null : names.of(code);
            if (name && name !== code) protectionCountryList.push({ code, name });
        }
    }
    protectionCountryList.sort((x, y) => x.name.localeCompare(y.name));
    return protectionCountryList;
}

function protectionCountryName(code) {
    const known = protectionCountrySuggestions.find(s => s.code === code) || protectionCountries().find(c => c.code === code);
    return known ? `${known.name} (${code})` : code;
}

// A country from the field: a pick from the list ("Indonesia (ID)"), a name, or a two-letter code
function protectionCountryCode(value) {
    const text = String(value || '').trim();
    const picked = text.match(/\(([A-Za-z]{2})\)$/);
    if (picked) return picked[1].toUpperCase();
    if (/^[A-Za-z]{2}$/.test(text)) return text.toUpperCase();
    const named = protectionCountries().find(c => c.name.toLowerCase() === text.toLowerCase());
    return named ? named.code : '';
}

// A pick from the list is added at once, without pressing Add
function protectionCountryPicked(field) {
    if (/\([A-Za-z]{2}\)$/.test(field.value.trim()) && addProtectionCountry(field.value)) field.value = '';
}

// ----------------------------------------------------------------- hits

function protectionStatus(hit) {
    switch (hit.status) {
        case 'watching': return uiTag('Watching', 'warn');
        case 'pending': return uiTag(hit.error ? 'Not banned yet' : 'Banning', 'warn');
        case 'banned': return uiTag(hit.expires_at ? `Banned until ${formatTime(hit.expires_at)}` : 'Banned until removed', 'fail');
        case 'alert': return uiTag('Alert', 'fail');
        // A watched catch that went quiet was never banned
        case 'expired': return uiTag(hit.mode === 'watch' ? 'No new activity' : 'Ban ended', '');
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
    if (!String(value || '').trim() || !protectionRules) return false;
    const code = protectionCountryCode(value);
    if (!code) {
        showToast('No such country. Pick one from the list, or type its two-letter code.', 'error');
        return false;
    }
    if (!protectionRules.country.countries.includes(code)) protectionRules.country.countries.push(code);
    renderProtection();
    // The field is drawn again: the next country can be typed right away
    const field = document.querySelector('#security-card-country input[name="code"]');
    if (field) field.focus();
    return true;
}

function removeProtectionCountry(code) {
    if (!protectionRules) return;
    protectionRules.country.countries = protectionRules.country.countries.filter(c => c !== code);
    renderProtection();
}

async function saveProtectionRules(quiet = false) {
    try {
        const res = await authenticatedFetch('/api/protection/rules', {
            method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ rules: protectionRules })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        protectionRules = data.rules;
        protectionSaved = JSON.parse(JSON.stringify(data.rules));
        protectionDirty = false;
        if (!quiet) showToast('Protection rules saved', 'success');
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
