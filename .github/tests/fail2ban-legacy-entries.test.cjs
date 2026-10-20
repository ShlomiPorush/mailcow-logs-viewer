// A single IPv6 address an earlier version wrote to a Fail2ban list as /32 covers
// the whole /32 network. The Lists tab marks such an entry and offers Repair, and
// the Dashboard's Needs attention says so while one is left.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');

// Any DOM access returns another inert stub, so a file's top-level code runs
function stub() {
    const fn = function () { return proxy; };
    const proxy = new Proxy(fn, {
        get: (_, key) => (key === Symbol.toPrimitive ? () => '' : key === 'length' ? 0 : proxy),
        apply: () => proxy,
        construct: () => proxy,
    });
    return proxy;
}

// The frontend, with one element that keeps what is written into it
function load(elementId) {
    const context = vm.createContext({
        document: stub(), window: { matchMedia: () => ({ matches: false }), addEventListener() {}, disabledFeatures: [] },
        localStorage: stub(), navigator: stub(), location: stub(), console: { log() {}, error() {}, warn() {} },
        setTimeout() {}, setInterval() {}, appTimezone: 'UTC',
    });
    for (const file of ['utils.js', 'app.js', 'smtp-abuse.js', 'protection.js', 'security.js']) {
        vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    }
    const element = { innerHTML: '', textContent: '', classList: { add() {}, remove() {}, toggle() {} } };
    context.document = { getElementById: id => (id === elementId ? element : null), querySelectorAll: () => [] };
    return { context, element };
}

const LEGACY = [
    { list: 'whitelist', entry: '2001:db8::2/32', address: '2001:db8::2', network: '2001:db8::/32' },
    { list: 'blacklist', entry: '2001:db8::1/32', address: '2001:db8::1', network: '2001:db8::/32' },
];

function lists(rw) {
    const { context, element } = load('security-lists');
    vm.runInContext(`mailcowRwConfigured = ${rw}; fail2banActiveBans = [];
        fail2banWhitelist = ['192.0.2.10', '2001:db8::2/32'];
        fail2banBlacklist = ['2001:db8::/32', '2001:db8::1/32', '2001:db8::5/128'];
        fail2banLegacy = ${JSON.stringify(LEGACY)};`, context);
    context.renderSecurityLists();
    // One string per row: the entry, its note and its buttons
    return element.innerHTML.split('class="ui-sec-lrow"').slice(1);
}

test('an entry an earlier version wrote as a /32 network is tagged with what it really covers', () => {
    const rows = lists(true);
    const row = entry => rows.find(r => r.includes(`>${entry}<`) || r.includes(`'${entry}'`));
    const denied = row('2001:db8::1/32');
    assert.match(denied, /ui-tag-warn">Whole network</);
    assert.match(denied, /Blocks the whole 2001:db8::\/32 network\. An earlier version wrote this single address as a network\./);
    assert.match(denied, /securityRepairListEntry\('blacklist', '2001:db8::1\/32', this\)/);
    assert.match(denied, /Replace it with 2001:db8::1\/128/);
    const allowed = row('2001:db8::2/32');
    assert.match(allowed, /Exempts the whole 2001:db8::\/32 network from Fail2ban\./);
    assert.match(allowed, /securityRepairListEntry\('whitelist', '2001:db8::2\/32', this\)/);
    // A network written on purpose and single addresses are left as they were
    for (const entry of ['2001:db8::/32', '2001:db8::5/128', '192.0.2.10']) {
        assert.doesNotMatch(row(entry), /Whole network|Repair/, entry);
    }
});

test('without the Read-Write key the tag stays and Repair is not offered', () => {
    const rows = lists(false).join('');
    assert.match(rows, /Whole network/);
    assert.doesNotMatch(rows, /securityRepairListEntry/);
});

test('Repair sends the entry and its list, and reads the list again', async () => {
    const { context } = load('none');
    vm.runInContext(`fail2banLegacy = ${JSON.stringify(LEGACY)}; fail2banSettingsLoaded = true;`, context);
    const sent = [];
    const asked = [];
    let reloaded = 0;
    context.showConfirmModal = async options => { asked.push(options.message); return true; };
    context.showToast = () => {};
    context.loadFail2BanSettings = () => { reloaded++; };
    context.authenticatedFetch = async (url, options) => {
        sent.push([url, JSON.parse(options.body)]);
        return { ok: true, json: async () => ({ status: 'success' }) };
    };
    await context.securityRepairListEntry('blacklist', '2001:db8::1/32', null);
    assert.deepEqual(sent, [['/api/fail2ban/repair', { entry: '2001:db8::1/32', list: 'blacklist' }]]);
    assert.match(asked[0], /Replace 2001:db8::1\/32 with 2001:db8::1\/128 on the denylist\?/);
    assert.equal(reloaded, 1);
});

async function attention(fail2ban, disabled = []) {
    const { context, element } = load('dashboard-attention');
    context.window.disabledFeatures = disabled;
    const asked = [];
    context.authenticatedFetch = async url => {
        asked.push(url);
        const body = url === '/api/fail2ban' ? fail2ban : {};
        return { ok: true, json: async () => body };
    };
    await context.loadDashboardAttention();
    return { html: element.innerHTML, asked };
}

test('Needs attention has a row while such an entry is left, and opens the Lists tab', async () => {
    const one = await attention({ legacy_entries: [LEGACY[1]] });
    assert.match(one.html, /A Fail2ban entry blocks the whole 2001:db8::\/32 network/);
    assert.match(one.html, /An earlier version wrote 2001:db8::1 as 2001:db8::1\/32\./);
    assert.match(one.html, /navigateTo\('netfilter', \{ sub: 'lists' \}\)">Open lists</);
    const both = await attention({ legacy_entries: LEGACY });
    assert.match(both.html, /2 Fail2ban entries cover whole \/32 networks/);
    const none = await attention({ legacy_entries: [] });
    assert.doesNotMatch(none.html, /Fail2ban/);
    const off = await attention({ legacy_entries: LEGACY }, ['netfilter']);
    assert.doesNotMatch(off.html, /Fail2ban/);
    assert.ok(!off.asked.includes('/api/fail2ban'));
});
