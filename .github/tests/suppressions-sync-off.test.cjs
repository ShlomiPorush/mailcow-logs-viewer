// Spam Filter > Suppressions while Sync with Rspamd is off: the app keeps no
// list, so the page shows only a note, asks for no list, and an older answer
// about the sync never undoes a newer one.
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

// spam_filter.js with elements that keep their HTML and their hidden class
function loadPage() {
    const elements = {};
    const element = () => {
        const classes = new Set();
        return {
            innerHTML: '', textContent: '', value: '', style: {}, remove() {}, focus() {},
            classList: {
                toggle: (name, on) => { (on === undefined ? !classes.has(name) : on) ? classes.add(name) : classes.delete(name); },
                add: name => classes.add(name), remove: name => classes.delete(name), contains: name => classes.has(name),
            },
        };
    };
    const document = new Proxy(stub(), {
        get: (target, key) => key === 'getElementById' ? id => (elements[id] = elements[id] || element()) : stub(),
    });
    const base = stub();
    const window = new Proxy({}, { get: (_, key) => key === 'matchMedia' ? () => ({ matches: false, addEventListener() {} }) : base[key] });
    const context = vm.createContext({
        document, window, localStorage: stub(), navigator: stub(), location: stub(), IntersectionObserver: function () { return stub(); },
        console: { log() {}, error() {}, warn() {} }, setTimeout() {}, setInterval() {}, appTimezone: 'UTC', URLSearchParams,
    });
    for (const file of ['utils.js', 'spam_filter.js']) vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    context.uiFilterBarSync = () => {};
    return { context, elements, hidden: id => elements[id] && elements[id].classList.contains('hidden') };
}

const STATE = on => ({ sync_on: on, active_count: 0, list_count: 0, pending_count: 0, writable: true, readable: on, reason: null });

test('with the sync off the page shows only a note and asks for no list', async () => {
    const page = loadPage();
    const asked = [];
    page.context.authenticatedFetch = async url => {
        asked.push(url);
        return { ok: true, json: async () => (url.startsWith('/api/suppressions/rspamd/state') ? STATE(false) : { items: [], total: 0, total_pages: 1 }) };
    };
    await page.context.loadSuppressionSyncNote();
    assert.equal(page.hidden('suppression-off-note'), false);
    assert.match(page.elements['suppression-off-note'].innerHTML, /Turn it on in Settings to load and manage this app's blocks/);
    assert.equal(page.hidden('suppression-list-card'), true);
    assert.equal(page.hidden('suppression-stats'), true);
    asked.length = 0;
    await page.context.loadSuppressions(1);
    assert.ok(!asked.some(url => url.startsWith('/api/suppressions?')), 'no list is asked for while the sync is off');
});

test('an older answer about the sync never undoes a newer one', async () => {
    const page = loadPage();
    const answers = [];
    page.context.authenticatedFetch = url => url.startsWith('/api/suppressions/rspamd/state')
        ? new Promise(resolve => answers.push(on => resolve({ ok: true, json: async () => STATE(on) })))
        : Promise.resolve({ ok: true, json: async () => ({ items: [], total: 0, total_pages: 1 }) });
    const older = page.context.loadSuppressionSyncNote();
    const newer = page.context.loadSuppressionSyncNote();
    answers[1](false);   // turned off since
    await newer;
    answers[0](true);
    await older;
    assert.equal(page.hidden('suppression-list-card'), true);
    assert.equal(page.hidden('suppression-off-note'), false);
});

test('turned on again, the list comes back', async () => {
    const page = loadPage();
    let on = false;
    const asked = [];
    page.context.authenticatedFetch = async url => {
        asked.push(url);
        return { ok: true, json: async () => (url.startsWith('/api/suppressions/rspamd/state') ? STATE(on) : { items: [], total: 0, total_pages: 1 }) };
    };
    await page.context.loadSuppressionSyncNote();
    on = true;
    asked.length = 0;
    await page.context.loadSuppressionSyncNote();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(page.hidden('suppression-list-card'), false);
    assert.equal(page.hidden('suppression-off-note'), true);
    assert.ok(asked.some(url => url.startsWith('/api/suppressions?')), 'the list loads once the sync is on');
});

// settings.js with the same inert page
function loadSettings() {
    const document = new Proxy(stub(), { get: (target, key) => stub() });
    const base = stub();
    const window = new Proxy({}, { get: (_, key) => key === 'matchMedia' ? () => ({ matches: false, addEventListener() {} }) : base[key] });
    const context = vm.createContext({
        document, window, localStorage: stub(), sessionStorage: stub(), navigator: stub(), location: stub(),
        console: { log() {}, error() {}, warn() {} }, setTimeout() {}, setInterval() {}, appTimezone: 'UTC',
    });
    for (const file of ['utils.js', 'settings.js']) vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    return context;
}

test('Remove runs only with the token of the save that turned the sync off', async () => {
    const context = loadSettings();
    const asked = [];
    context.authenticatedFetch = async (url, options) => {
        asked.push([url, options && options.body]);
        return { ok: true, json: async () => ({ removed_blocks: 3 }) };
    };
    // Another window turned the sync off first: this save named no transition
    const [text, kind] = await context.settingsRspamdAfterSave({ action: 'remove' }, { rspamd_off_transition: null });
    assert.equal(asked.length, 0, 'nothing is removed');
    assert.equal(kind, 'error');
    assert.match(text, /already off \(changed in another window\)\. Nothing was removed from Rspamd\./);
    const [done] = await context.settingsRspamdAfterSave({ action: 'remove' }, { rspamd_off_transition: 'T1' });
    assert.deepEqual(asked, [['/api/suppressions/rspamd/clear', JSON.stringify({ transition: 'T1' })]]);
    assert.match(done, /Removed 3 app blocks from Rspamd/);
});
