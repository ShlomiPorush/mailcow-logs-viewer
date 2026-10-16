// The Security page's actions say and send what really happens: a single
// IPv6 address is written to the Fail2ban lists as /128, not as a /32 network;
// a button is offered only when the server will take its request; and the texts
// describe the period and the settings in force.
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

function load() {
    const context = vm.createContext({
        document: stub(), window: { matchMedia: () => ({ matches: false }), addEventListener() {} }, localStorage: stub(), navigator: stub(),
        location: stub(), console: { log() {}, error() {}, warn() {} }, setTimeout() {}, setInterval() {}, appTimezone: 'UTC',
    });
    for (const file of ['utils.js', 'app.js', 'smtp-abuse.js', 'protection.js', 'security.js']) {
        vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    }
    return context;
}

// Confirms every dialog and records what is asked and what is sent
function recordRequests(context) {
    const sent = [];
    const asked = [];
    context.showConfirmModal = async options => { asked.push(options.message); return true; };
    context.showToast = () => {};
    context.authenticatedFetch = async (url, options = {}) => {
        sent.push([url, options.body ? JSON.parse(options.body) : null]);
        return { ok: true, json: async () => ({ status: 'success' }) };
    };
    for (const name of ['loadFail2BanSettings', 'smartRefreshNetfilter', 'renderSecurityOverview', 'refreshSecurityAddresses', 'loadSmtpAbusePanel']) {
        context[name] = () => {};
    }
    return { sent, asked };
}

test('a single address goes on the Fail2ban lists as /32 for IPv4 and /128 for IPv6', async () => {
    const context = load();
    const { sent, asked } = recordRequests(context);
    await context.banIP('2001:db8::1');
    await context.allowIP('2001:db8::2');
    await context.unbanIP('2001:db8::3');
    await context.banIP('198.51.100.7');
    await context.banIP('2001:db8::/64');
    assert.deepEqual(sent.map(([url, body]) => [url, body.ip]), [
        ['/api/fail2ban/ban', '2001:db8::1/128'],
        ['/api/fail2ban/allow', '2001:db8::2/128'],
        ['/api/fail2ban/unban', '2001:db8::3/128'],
        ['/api/fail2ban/ban', '198.51.100.7/32'],
        ['/api/fail2ban/ban', '2001:db8::/64'],
    ]);
    assert.ok(asked.every(message => !/2001:db8::\d\/32/.test(message)), asked.join('\n'));
});

test('a /32 IPv6 entry is a network, not the address it starts with', () => {
    const context = load();
    const bare = entry => vm.runInContext(`securityBare(${JSON.stringify(entry)})`, context);
    assert.equal(bare('2001:db8::1/128'), '2001:db8::1');
    assert.equal(bare('2001:db8::1/32'), '2001:db8::1/32');
    assert.equal(bare('198.51.100.7/32'), '198.51.100.7');
});

function address(overrides = {}) {
    return { ip: '203.0.113.7', tries: 4, attempts: 4, users: [], services: [], hits: [], f2b: null, listedAs: null, state: 'quiet', ...overrides };
}

test('the address buttons name the entry they write', () => {
    const context = load();
    vm.runInContext('mailcowRwConfigured = true; fail2banActiveBans = []', context);
    const { acts } = context.securityDescribe(address({ ip: '2001:db8::9' }));
    assert.match(acts, /2001:db8::9\/128/);
    assert.doesNotMatch(acts, /2001:db8::9\/32/);
});

