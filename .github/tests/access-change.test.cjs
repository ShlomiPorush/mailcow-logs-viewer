// The signed-in person's access as the page follows it (issue #544): a status read
// while the page is open (the session check, a refused call) that gives other access
// than the page was drawn with reloads the page once; a refused call (403 for lack of
// access) is said by the shared message, and words already on screen are not shown twice.
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
        innerHTML: '', textContent: '', style: {}, dataset: {}, parentElement: null, isConnected: true, offsetHeight: 50,
        classList: { add: c => classes.add(c), remove: c => classes.delete(c), contains: c => classes.has(c), toggle() {} },
        setAttribute() {}, removeAttribute() {}, addEventListener() {}, matches: () => false, contains: () => false,
        querySelector: () => ({ addEventListener() {}, focus() {}, setAttribute() {} }), querySelectorAll: () => [],
        remove() { this.isConnected = false; }, focus() {},
    };
}

function load({ fetch } = {}) {
    const toasts = [];
    const shown = [];
    const reloads = [];
    const timers = [];
    const elements = {};
    const own = {
        hidden: false,
        documentElement: element(),
        body: { appendChild: el => { shown.push(el); toasts.push(el.innerHTML.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim()); } },
        createElement: () => element(),
        // Each id its own element; the toast is the one on screen, while it is there
        getElementById: id => (id.startsWith('toast-')
            ? shown.filter(el => el.isConnected && el.id === id).pop() || null
            : (elements[id] = elements[id] || element())),
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
        // Timers wait in a queue; the test runs the ones of a given delay (flush)
        setTimeout: (fn, ms) => { timers.push({ fn, ms }); return timers.length; }, clearTimeout() {}, setInterval() {}, requestAnimationFrame() {},
        MutationObserver: function () { return { observe() {} }; }, appTimezone: 'UTC', fetch,
        getComputedStyle: () => ({ bottom: '18px' }),
    });
    for (const file of ['utils.js', 'router.js', 'app.js']) vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    // Runs the waiting timers of this delay (and what they start, when it has the same delay)
    const flush = ms => {
        for (let i = 0; i < timers.length; i++) {
            if (timers[i].ms === ms && !timers[i].done) { timers[i].done = true; timers[i].fn(); }
        }
    };
    // What is on screen now, in the order shown, with each toast's id and its place from the bottom
    const visible = () => shown.filter(el => el.isConnected).map(el => ({ id: el.id, bottom: el.style.bottom || '',
        text: el.innerHTML.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim() }));
    return { run: code => vm.runInContext(code, context), toasts, reloads, flush, visible };
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
    p.flush(1500);
    assert.equal(p.reloads.length, 1);
    assert.ok(p.toasts.some(t => t.includes('Your access changed.')));
    // Another answer before the reload happens does not reload again
    p.run(`appAccessCheck(${JSON.stringify({ ...VIEWER, is_admin: true })})`);
    assert.equal(p.reloads.length, 1);
});

test('a reload the person cancels (unsaved changes) is asked again by the next check, not in a loop', () => {
    const p = load();
    p.run(`setAppAccess(${JSON.stringify(VIEWER)})`);
    const other = JSON.stringify({ ...VIEWER, is_admin: true });
    p.run(`appAccessCheck(${other})`);
    p.flush(1500);
    assert.equal(p.reloads.length, 1);
    // The browser asked about the unsaved changes and the person stayed: the page runs on.
    // A check within the next seconds asks nothing more
    p.run(`appAccessCheck(${other})`);
    p.flush(1500);
    assert.equal(p.reloads.length, 1);
    // A few seconds on (the first toast has faded by then), the next check asks again, once
    p.flush(5000);
    p.run(`document.getElementById('toast-notification').remove()`);
    p.run(`appAccessCheck(${other})`);
    p.flush(1500);
    assert.equal(p.reloads.length, 2);
    assert.equal(p.toasts.filter(t => t.includes('Your access changed.')).length, 2);
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

test('a refused call whose caller repeats the server\'s words shows one message', async () => {
    const p = load({ fetch: refusing('You do not have permission for this.') });
    // The caller passes the server's detail through (users.js deleteUser)
    await p.run(`(async () => {
        const response = await authenticatedFetch('/api/users/1', { method: 'DELETE' });
        const body = await response.json();
        if (!response.ok) showToast(body.detail, 'error');
    })()`);
    assert.deepEqual(p.toasts.filter(t => t), ['✗ You do not have permission for this.']);
    assert.deepEqual(p.visible().map(t => t.text), ['✗ You do not have permission for this.']);
});

test('the same words twice show once while on screen, and again once gone', () => {
    const p = load();
    p.run(`showToast('Saved', 'success'); showToast('Saved', 'success')`);
    assert.deepEqual(p.toasts, ['✓ Saved']);
    p.run(`document.getElementById('toast-notification').remove(); showToast('Saved', 'success')`);
    assert.deepEqual(p.toasts, ['✓ Saved', '✓ Saved']);
});

test('a refusal and an unrelated error show both, also one that names 403', async () => {
    const p = load({ fetch: refusing('You do not have permission for this.') });
    await p.run(`(async () => {
        const refused = authenticatedFetch('/api/status/containers/x/ignore', { method: 'PUT' });
        // Another request fails meanwhile, for its own reason
        showToast('The proxy answered 403. Check its settings and try again.', 'error');
        await refused;
        // Later, an error of its own: shown
        showToast('Could not save the user. Try again.', 'error');
    })()`);
    assert.deepEqual(p.toasts.filter(t => t), [
        '✗ The proxy answered 403. Check its settings and try again.',
        '✗ You do not have permission for this.',
        '✗ Could not save the user. Try again.',
    ]);
    // On screen: the refusal, and the latest error under it
    assert.deepEqual(p.visible().map(t => t.text), ['✗ You do not have permission for this.', '✗ Could not save the user. Try again.']);
});

test('a caller\'s own words after a refusal show under it, and the refusal stays on screen', async () => {
    const p = load({ fetch: refusing('You do not have permission for this.') });
    await p.run(`(async () => {
        const response = await authenticatedFetch('/api/status/containers/x/ignore', { method: 'PUT' });
        if (!response.ok) showToast('Could not change the container: HTTP ' + response.status, 'error');
    })()`);
    // Both on screen, the refusal first, lifted above the caller's toast (18 + 50 + 8)
    assert.deepEqual(p.visible(), [
        { id: 'toast-refusal', bottom: '76px', text: '✗ You do not have permission for this.' },
        { id: 'toast-notification', bottom: '', text: '✗ Could not change the container: HTTP 403' },
    ]);
    // The next toast replaces the caller's one; the refusal still stays, as itself only once
    p.run(`showToast('Could not save the user. Try again.', 'error'); showToast('You do not have permission for this.', 'error')`);
    assert.deepEqual(p.visible().map(t => [t.id, t.text]), [
        ['toast-refusal', '✗ You do not have permission for this.'],
        ['toast-notification', '✗ Could not save the user. Try again.'],
    ]);
    // Once the refusal is gone, toasts replace each other as before
    p.run(`document.getElementById('toast-refusal').remove(); showToast('Saved', 'success'); showToast('Done', 'success')`);
    assert.deepEqual(p.visible().map(t => t.text), ['✓ Done']);
});

test('another 403 keeps the caller\'s own message', async () => {
    const p = load({ fetch: refusing('Report deletion is disabled') });
    await p.run(`(async () => {
        const response = await authenticatedFetch('/api/dmarc/reports/dmarc/1', { method: 'DELETE' });
        if (!response.ok) showToast('Report deletion is disabled', 'error');
    })()`);
    assert.deepEqual(p.toasts.filter(t => t), ['✗ Report deletion is disabled']);
});
