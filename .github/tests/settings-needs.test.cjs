// Settings that do nothing while their feature's switch is off are greyed out and
// cannot be edited until it is on (settingsShowNeeds): OAuth2 under its switch,
// SMTP under Enable SMTP, and the Outgoing spam limit and response under its own.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');

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
    const base = stub();
    const window = new Proxy({}, { get: (_, key) => key === 'matchMedia' ? () => ({ matches: false, addEventListener() {} }) : base[key] });
    const context = vm.createContext({
        document: stub(), window, localStorage: stub(), sessionStorage: stub(), navigator: stub(), location: stub(),
        console: { log() {}, error() {}, warn() {} }, setTimeout() {}, setInterval() {}, appTimezone: 'UTC', URL,
    });
    for (const file of ['utils.js', 'settings.js']) vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    return context;
}

const context = load();
const tab = id => vm.runInContext('SETTINGS_EDIT_TABS', context).find(t => t.id === id);
const needsOf = (id, label) => tab(id).groups.find(g => g.label === label).needs;

test('the OAuth2 settings need OAuth2 on', () => {
    for (const label of ['OAuth2 - Discovery (automatic)', 'OAuth2 - Endpoints (only without discovery)', 'OAuth2 - Credentials']) {
        assert.equal(needsOf('auth', label), 'oauth2_enabled', label);
    }
    // The provider name shares a group with the switch itself, so it says so on its own
    assert.equal(vm.runInContext('SETTINGS_FIELD_NEEDS', context).oauth2_provider_name, 'oauth2_enabled');
});

test('the SMTP settings need SMTP on', () => {
    for (const label of ['Server', 'Security', 'Authentication', 'From Address']) assert.equal(needsOf('smtp', label), 'smtp_enabled', label);
});

test('the Outgoing spam limit and response need it on', () => {
    for (const label of ['Limit', 'Response']) assert.equal(needsOf('smtp_abuse', label), 'smtp_abuse_enabled', label);
});

test('a group never needs a switch it holds itself (it could not be turned on again)', () => {
    const bad = vm.runInContext('SETTINGS_EDIT_TABS', context).flatMap(t => (t.groups || [])
        .filter(g => g.needs && g.needs.split(' ').some(key => (g.keys || []).includes(key)))
        .map(g => `${t.id} > ${g.label}`));
    assert.deepEqual([...bad], []);
});
