// The search in the top bar finds suppressions: in every state, and not at
// all while Sync with Rspamd is off (the app keeps no list then).
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

function loadSearch(answers) {
    const asked = [];
    const document = new Proxy(stub(), { get: () => stub() });
    const context = vm.createContext({
        document, window: { disabledFeatures: [] }, localStorage: stub(), navigator: stub(), location: stub(),
        console: { log() {}, error() {}, warn() {} }, setTimeout() {}, setInterval() {}, appTimezone: 'UTC', URLSearchParams,
    });
    vm.runInContext(fs.readFileSync(path.join(frontend, 'utils.js'), 'utf8'), context);
    vm.runInContext(fs.readFileSync(path.join(frontend, 'search.js'), 'utf8'), context);
    context.authenticatedFetch = async url => {
        asked.push(url);
        const key = Object.keys(answers).find(prefix => url.startsWith(prefix));
        return { ok: true, status: 200, json: async () => answers[key] };
    };
    return { context, asked };
}

test('suppressions are searched in every state and open the list filtered to the address', async () => {
    const { context, asked } = loadSearch({
        '/api/suppressions/config': { list_kept: true },
        '/api/suppressions?': { total: 2, items: [
            { email: 'gone@example.org', active: true, is_expired: false, reason: 'hard_bounce', notes: null, created_at: '2026-10-01T00:00:00Z' },
            { email: 'old@example.org', active: false, is_expired: true, reason: 'soft_bounce', notes: 'by hand', created_at: '2026-09-01T00:00:00Z' },
        ] },
    });
    const result = await context.gsSearchSuppressions('example.org');
    assert.equal(result.count, 2);
    assert.deepEqual(result.items.map(i => i.title), ['gone@example.org', 'old@example.org']);
    assert.match(result.items[0].sub, /^Active · hard bounce$/);
    assert.match(result.items[1].sub, /^Expired · soft bounce · by hand$/);
    assert.equal(result.more.label, 'Open in Suppressions');
    const listed = asked.find(url => url.startsWith('/api/suppressions?'));
    assert.match(listed, /search=example\.org/);
    assert.match(listed, /active_filter=&/, 'every state, not only active');
});

test('with Sync with Rspamd off the category is left out and the list is not asked for', async () => {
    const { context, asked } = loadSearch({ '/api/suppressions/config': { list_kept: false } });
    const result = await context.gsSearchSuppressions('example.org');
    assert.equal(result.hidden, true);
    assert.ok(!asked.some(url => url.startsWith('/api/suppressions?')));
});

test('a domain block opens the list by its domain, and a hidden kind is skipped by the keyboard', async () => {
    const { context } = loadSearch({
        '/api/suppressions/config': { list_kept: true },
        '/api/suppressions?': { total: 1, items: [
            { email: '/^.+@example\.org$/i', active: true, is_expired: false, reason: 'manual', created_at: '2026-10-01T00:00:00Z' },
        ] },
    });
    const opened = [];
    context.gsOpenSuppressions = text => opened.push(text);
    const result = await context.gsSearchSuppressions('example');
    result.items[0].open();
    // spam_filter.js is not loaded here, so the title is the stored value; the open uses the shown one
    assert.deepEqual(opened, [result.items[0].title]);

    // Suppressions has nothing to search (sync off): the keyboard steps over it
    vm.runInContext(`gsResults = { suppressions: { hidden: true, count: 0, items: [] } }; gsTab = 'mailboxes'; gsSetTab = id => { gsTab = id; };`, context);
    context.gsStepTab(1);
    assert.equal(vm.runInContext('gsTab', context), 'addresses');
    context.gsStepTab(-1);
    assert.equal(vm.runInContext('gsTab', context), 'mailboxes');
});
