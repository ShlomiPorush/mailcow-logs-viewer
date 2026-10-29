// The signed-in person's access as the page follows it (issue #544): a status read
// while the page is open (the session check, a refused call) that gives other access
// than the page was drawn with reloads the page once; and a refused call (403 for lack
// of access) is said by one message, not followed by the caller's own error.
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

// Just enough of an element for showToast
function element() {
    const classes = new Set();
    return {
        innerHTML: '', textContent: '', style: {}, dataset: {}, parentElement: null, isConnected: true,
        classList: { add: c => classes.add(c), remove: c => classes.delete(c), contains: c => classes.has(c), toggle() {} },
        setAttribute() {}, removeAttribute() {}, addEventListener() {}, matches: () => false, contains: () => false,
        querySelector: () => ({ addEventListener() {}, focus() {}, setAttribute() {} }), querySelectorAll: () => [],
        remove() { this.isConnected = false; }, focus() {},
    };
}

function load({ fetch } = {}) {
    const toasts = [];
    const reloads = [];
    const elements = {};
    const own = {
        hidden: false,
        documentElement: element(),
        body: { appendChild: el => toasts.push(el.innerHTML.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim()) },
        createElement: () => element(),
        // Each id its own element, except the toast: each one here is a new toast
        getElementById: id => (id === 'toast-notification' ? null : (elements[id] = elements[id] || element())),
        querySelectorAll: () => [],
        querySelector: () => null,
        addEventListener() {},
    };
    const base = stub();
    const document = new Proxy(own, { get: (t, key) => key in t ? t[key] : base[key] });
    const win = { disabledFeatures: [], location: { pathname: '/', href: 'http://app/', reload: () => reloads.push(1) },
        matchMedia: () => ({ matches: false, addEventListener() {} }), addEventListener() {} };
    const window = new Proxy(win, { get: (t, key) => key in t ? t[key] : base[key], set: (t, key, v) => { t[key] = v; return true; } });
    const context = vm.createContext({
        document, window, history: { replaceState() {}, pushState() {} }, localStorage: stub(), navigator: stub(),
        location: win.location, console: { log() {}, error() {}, warn() {} },
        // A timer runs at once: the reload after "Your access changed." is seen here
        setTimeout: fn => { fn(); return 0; }, clearTimeout() {}, setInterval() {}, requestAnimationFrame() {},
        MutationObserver: function () { return { observe() {} }; }, appTimezone: 'UTC', fetch,
    });
    for (const file of ['utils.js', 'router.js', 'app.js']) vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    return { run: code => vm.runInContext(code, context), toasts, reloads };
}

const VIEWER = { authenticated: true, is_admin: false, scopes: ['status:read', 'messages:read'] };

test('the same access, in any order, keeps the page; other access reloads it once', () => {
    const p = load();
    p.run(`setAppAccess(${JSON.stringify(VIEWER)})`);
    assert.equal(p.run(`appAccessCheck(${JSON.stringify({ ...VIEWER, scopes: ['messages:read', 'status:read'] })})`), false);
    assert.equal(p.run(`appAccessCheck(${JSON.stringify({ ...VIEWER, user_name: 'renamed' })})`), false);
    assert.deepEqual(p.reloads, []);
    // An action granted: the page reloads into it, with a word first
    assert.equal(p.run(`appAccessCheck(${JSON.stringify({ ...VIEWER, scopes: [...VIEWER.scopes, 'status:write'] })})`), true);
    assert.equal(p.reloads.length, 1);
    assert.ok(p.toasts.some(t => t.includes('Your access changed.')));
    // Another answer before the reload happens does not reload again
    p.run(`appAccessCheck(${JSON.stringify({ ...VIEWER, is_admin: true })})`);
    assert.equal(p.reloads.length, 1);
});

test('admin and a view taken away count as a change; a signed-out or unknown answer does not', () => {
    const p = load();
    p.run(`setAppAccess(${JSON.stringify(VIEWER)})`);
    assert.equal(p.run(`appAccessCheck(${JSON.stringify({ authenticated: false })})`), false);
    assert.equal(p.run('appAccessCheck(null)'), false);
    assert.equal(p.run(`appAccessKey(${JSON.stringify(VIEWER)}) === appAccessKey(${JSON.stringify({ ...VIEWER, scopes: ['messages:read'] })})`), false);
    assert.equal(p.run(`appAccessKey(${JSON.stringify(VIEWER)}) === appAccessKey(${JSON.stringify({ ...VIEWER, is_admin: true })})`), false);
});

test('without sign-in (no status read) nothing is compared', () => {
    const p = load();
    assert.equal(p.run(`appAccessCheck(${JSON.stringify(VIEWER)})`), false);
    assert.deepEqual(p.reloads, []);
});

test('the session check and a refused call both compare the access', () => {
    const guard = fs.readFileSync(path.join(frontend, 'session-guard.js'), 'utf8');
    const send = guard.slice(guard.indexOf('async function sessionGuardSend'), guard.indexOf('function sessionGuardHandle'));
    assert.match(send, /appAccessCheck\(body\)/);
    const app = fs.readFileSync(path.join(frontend, 'app.js'), 'utf8');
    const refresh = app.slice(app.indexOf('async function refreshAppAccess'), app.indexOf('// Hide the tabs of features'));
    assert.match(refresh, /appAccessCheck\(/);
});

function refusing(detail) {
    return async url => url === '/api/auth/status'
        ? { ok: true, status: 200, json: async () => ({ authenticated: true, is_admin: false, scopes: [] }) }
        : { ok: false, status: 403, headers: { get: () => null }, json: async () => ({ detail }), clone() { return { json: async () => ({ detail }) }; } };
}

test('a call refused for lack of access shows one message, not the caller\'s error as well', async () => {
    const p = load({ fetch: refusing('You do not have permission for this.') });
    // The common caller: it shows its own error when the answer is not ok
    await p.run(`(async () => {
        const response = await authenticatedFetch('/api/status/containers/x/ignore', { method: 'PUT' });
        if (!response.ok) showToast('HTTP ' + response.status, 'error');
        showToast('Could not save the change. Try again.', 'error');
    })()`);
    assert.deepEqual(p.toasts.filter(t => t), ['✗ You do not have permission for this.']);
});

test('another 403 keeps the caller\'s own message', async () => {
    const p = load({ fetch: refusing('Report deletion is disabled') });
    await p.run(`(async () => {
        const response = await authenticatedFetch('/api/dmarc/reports/dmarc/1', { method: 'DELETE' });
        if (!response.ok) showToast('Report deletion is disabled', 'error');
    })()`);
    assert.deepEqual(p.toasts.filter(t => t), ['✗ Report deletion is disabled']);
});
