// Click to copy must always answer with a notice. Browsers offer
// navigator.clipboard only on HTTPS and localhost, so over plain HTTP the call
// is missing and must not throw before the user is told.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

function load(navigator) {
    const toasts = [];
    const context = vm.createContext({
        document: { getElementById: () => null, addEventListener() {}, querySelectorAll: () => [] },
        window: {}, navigator, console: { log() {}, error() {}, warn() {} }, setTimeout() {}, setInterval() {},
    });
    vm.runInContext(fs.readFileSync(path.join(__dirname, '../../frontend/utils.js'), 'utf8'), context);
    context.showToast = (message, type) => toasts.push({ message, type });
    return { context, toasts };
}

const settle = () => new Promise(resolve => setImmediate(resolve));

test('over plain HTTP (no navigator.clipboard) copying says it failed instead of throwing', async () => {
    const { context, toasts } = load({});
    assert.doesNotThrow(() => context.copyToClipboard('user@example.com'));
    await settle();
    assert.equal(toasts.length, 1);
    assert.equal(toasts[0].type, 'error');
    assert.match(toasts[0].message, /HTTPS/);
});

test('a refused copy says it failed', async () => {
    const { context, toasts } = load({ clipboard: { writeText: () => Promise.reject(new Error('denied')) } });
    context.copyToClipboard('user@example.com');
    await settle();
    assert.deepEqual(toasts.map(t => t.type), ['error']);
});

test('a copy that works says what was copied', async () => {
    const { context, toasts } = load({ clipboard: { writeText: () => Promise.resolve() } });
    context.copyToClipboard('user@example.com');
    await settle();
    assert.deepEqual(toasts, [{ message: 'Copied: user@example.com', type: 'success' }]);
});

test('a secret copied with a label is not shown: the notice names it only', async () => {
    const { context, toasts } = load({ clipboard: { writeText: () => Promise.resolve() } });
    context.copyToClipboard('Secret-Pass-123!', undefined, 'Password');
    await settle();
    assert.deepEqual(toasts, [{ message: 'Password copied', type: 'success' }]);
});
