// Validate: an answer about a key that changed while it was checked is not
// shown as the state of the new key.
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

test('a stale answer asks to validate again and shows no result', async () => {
    const elements = {};
    const document = new Proxy(stub(), {
        get: (target, key) => key === 'getElementById' ? id => (elements[id] = elements[id] || { innerHTML: '' }) : stub(),
    });
    const base = stub();
    const window = new Proxy({}, { get: (_, key) => key === 'matchMedia' ? () => ({ matches: false, addEventListener() {} }) : base[key] });
    const context = vm.createContext({
        document, window, localStorage: stub(), sessionStorage: stub(), navigator: stub(), location: stub(),
        console: { log() {}, error() {}, warn() {} }, setTimeout() {}, setInterval() {}, appTimezone: 'UTC',
    });
    for (const file of ['utils.js', 'settings.js']) vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    const toasts = [];
    context.showToast = (text, kind) => toasts.push([text, kind]);
    context.authenticatedFetch = async () => ({ ok: true, json: async () => ({ configured: true, valid: true, error: null, stale: true }) });
    const returned = await context.validateCredential('mailcow_rw_key', true);
    assert.equal(returned, null);
    const status = elements['credential-mailcow_rw_key-status'].innerHTML;
    assert.doesNotMatch(status, /Accepted/);
    assert.match(elements['credential-mailcow_rw_key-checked'].innerHTML, /Changed while it was checked/);
    assert.equal(toasts.length, 1);
    assert.match(toasts[0][0], /changed while it was checked\. Validate it again\./);
});
