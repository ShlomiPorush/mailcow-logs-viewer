// Outbound (Queue and Suppressions) and the Rspamd Maps tab of Quarantine:
// old addresses and old history entries open the new place, and each tab
// follows its own feature switch, the page going only when all are off.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');

// Any other DOM access returns another inert stub, so a file's top-level code runs
function stub() {
    const fn = function () { return proxy; };
    const proxy = new Proxy(fn, {
        get: (_, key) => (key === Symbol.toPrimitive ? () => '' : key === 'length' ? 0 : proxy),
        apply: () => proxy,
        construct: () => proxy,
    });
    return proxy;
}

function element() {
    const classes = new Set();
    return {
        innerHTML: '', textContent: '', value: '', style: {}, attributes: {},
        classList: {
            add: c => classes.add(c), remove: c => classes.delete(c), contains: c => classes.has(c),
            toggle: (c, force) => { const on = force === undefined ? !classes.has(c) : !!force; if (on) classes.add(c); else classes.delete(c); return on; },
        },
        setAttribute(name, value) { this.attributes[name] = String(value); },
        removeAttribute(name) { delete this.attributes[name]; },
        childNodes: [], appendChild() {},
        querySelector: () => null, querySelectorAll: () => [], remove() {}, focus() {},
    };
}

function load(files, { pathname = '/', disabled = [] } = {}) {
    const elements = {};
    const calls = { switchTab: [], replaceState: [], pushState: [] };
    const listeners = {};
    const document = new Proxy(stub(), {
        get: (target, key) => key === 'getElementById' ? id => (elements[id] = elements[id] || element())
            : key === 'querySelectorAll' ? () => [] : key === 'querySelector' ? () => null : stub(),
    });
    const base = stub();
    const own = {
        disabledFeatures: disabled,
        location: { pathname, href: 'http://app' + pathname },
        matchMedia: () => ({ matches: false, addEventListener() {} }),
        addEventListener: (type, fn) => { listeners[type] = fn; },
    };
    const window = new Proxy(own, { get: (t, key) => key in t ? t[key] : base[key], set: (t, key, v) => { t[key] = v; return true; } });
    const history = {
        state: null,
        replaceState: (state, _, url) => calls.replaceState.push({ state, url }),
        pushState: (state, _, url) => calls.pushState.push({ state, url }),
    };
    const context = vm.createContext({
        document, window, history, localStorage: stub(), navigator: stub(), location: own.location,
        console: { log() {}, error() {}, warn() {} }, setTimeout() {}, setInterval() {}, requestAnimationFrame() {},
        MutationObserver: function () { return { observe() {} }; }, appTimezone: 'UTC',
    });
    for (const file of files) vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    vm.runInContext(`window.disabledFeatures = ${JSON.stringify(disabled)};`, context);
    return { context, elements, calls, listeners };
}

// Objects made in the page's realm, compared by value
const plain = value => JSON.parse(JSON.stringify(value));

function loadRouter(pathname) {
    const r = load(['router.js'], { pathname });
    // The pages' own state, kept in app.js
    vm.runInContext(`var outboundTab = 'queue', quarantineTab = 'messages', settingsTab = 'features', settingsFirstTab = 'features';`, r.context);
    r.context.switchTab = (route, params) => r.calls.switchTab.push({ route, params });
    return r;
}

test('the old addresses open the new places', () => {
    const cases = [
        ['/queue', 'outbound', 'queue', '/outbound'],
        ['/spam-filter', 'outbound', 'suppressions', '/outbound/suppressions'],
        ['/spam-filter/suppressions', 'outbound', 'suppressions', '/outbound/suppressions'],
        ['/spam-filter/maps', 'quarantine', 'maps', '/quarantine/maps'],
        ['/settings/spam_filter', 'settings', 'outbound', '/settings/outbound'],
    ];
    for (const [pathname, route, sub, canonical] of cases) {
        const r = loadRouter(pathname);
        const info = r.context.initRouter();
        assert.equal(info.baseRoute, route, pathname);
        assert.equal(info.params.sub, sub, pathname);
        // The address bar shows the new address, without a new history entry
        assert.equal(r.calls.replaceState.at(-1).url, canonical, pathname);
        assert.equal(r.calls.pushState.length, 0);
    }
});

test('the new addresses stay as they are', () => {
    for (const [pathname, route, sub] of [['/outbound', 'outbound', 'queue'], ['/outbound/suppressions', 'outbound', 'suppressions'],
        ['/quarantine/maps', 'quarantine', 'maps'], ['/quarantine/rules', 'quarantine', 'rules']]) {
        const r = loadRouter(pathname);
        const info = r.context.initRouter();
        assert.deepEqual([info.baseRoute, info.params.sub, info.moved], [route, sub, undefined], pathname);
        assert.equal(r.calls.replaceState.at(-1).url, pathname);
    }
    const r = loadRouter('/');
    assert.equal(r.context.buildPath('outbound', { sub: 'queue' }), '/outbound');
    assert.equal(r.context.buildPath('outbound', { sub: 'suppressions' }), '/outbound/suppressions');
    assert.equal(r.context.buildPath('quarantine', { sub: 'maps' }), '/quarantine/maps');
});

test('Back into a history entry of the old version opens the new place', () => {
    const r = loadRouter('/dashboard');
    r.context.initRouter();
    r.listeners.popstate({ state: { route: 'spam-filter', params: { sub: 'maps' } } });
    assert.deepEqual(plain(r.calls.switchTab.at(-1)), { route: 'quarantine', params: { sub: 'maps' } });
    assert.equal(r.calls.replaceState.at(-1).url, '/quarantine/maps');
    r.listeners.popstate({ state: { route: 'queue', params: {} } });
    assert.deepEqual(plain(r.calls.switchTab.at(-1)), { route: 'outbound', params: { sub: 'queue' } });
    assert.equal(r.calls.replaceState.at(-1).url, '/outbound');
});

test('a link to an old page name opens the new place', () => {
    const r = loadRouter('/dashboard');
    r.context.navigateTo('spam-filter', { sub: 'suppressions' });
    assert.deepEqual(plain(r.calls.switchTab.at(-1)), { route: 'outbound', params: { sub: 'suppressions' } });
    assert.equal(r.calls.pushState.at(-1).url, '/outbound/suppressions');
});

function loadApp(disabled) {
    const a = load(['utils.js', 'router.js', 'app.js'], { disabled });
    a.synced = [];
    a.context.routerSyncSubpage = (route, sub, replace = false) => a.synced.push({ route, sub, replace });
    return a;
}

const hidden = (a, id) => a.elements[id].classList.contains('hidden');

test('each Outbound tab follows its own switch', () => {
    const cases = [
        [[], ['', false, false, false]],
        [['queue'], ['', true, false, true]],
        [['suppressions'], ['', false, true, true]],
        [['queue', 'suppressions'], ['none', true, true, true]],
    ];
    for (const [disabled, [nav, queueGone, suppressionsGone, barGone]] of cases) {
        const a = loadApp(disabled);
        a.context.applyFeatureToggles();
        assert.equal(a.elements['tab-outbound'].style.display, nav, `nav, off: ${disabled}`);
        assert.equal(a.elements['mobile-tab-outbound'].style.display, nav, `sheet, off: ${disabled}`);
        assert.equal(hidden(a, 'outbound-tab-btn-queue'), queueGone, `Queue tab, off: ${disabled}`);
        assert.equal(hidden(a, 'outbound-tab-btn-suppressions'), suppressionsGone, `Suppressions tab, off: ${disabled}`);
        // One tab left: no tab bar
        assert.equal(hidden(a, 'outbound-tabs'), barGone, `tab bar, off: ${disabled}`);
    }
});

test('Quarantine stays while only Rspamd Maps is on, and Maps go with their own switch', () => {
    let a = loadApp(['quarantine']);
    a.context.applyFeatureToggles();
    assert.equal(a.elements['tab-quarantine'].style.display, '');
    assert.equal(hidden(a, 'quarantine-tab-btn-messages'), true);
    assert.equal(hidden(a, 'quarantine-tab-btn-rules'), true);
    assert.equal(hidden(a, 'quarantine-tab-btn-maps'), false);
    assert.equal(a.context.pageTabOn('quarantine', 'messages'), 'maps');

    a = loadApp(['rspamd-maps']);
    a.context.applyFeatureToggles();
    assert.equal(a.elements['tab-quarantine'].style.display, '');
    assert.equal(hidden(a, 'quarantine-tab-btn-maps'), true);
    assert.equal(hidden(a, 'quarantine-tabs'), false);
    assert.equal(a.context.pageTabOn('quarantine', 'maps'), 'messages');

    a = loadApp(['quarantine', 'rspamd-maps']);
    a.context.applyFeatureToggles();
    assert.equal(a.elements['tab-quarantine'].style.display, 'none');
});

test('a tab whose switch is off opens the first tab that is on', () => {
    const a = loadApp(['queue']);
    assert.equal(a.context.pageTabOn('outbound', 'queue'), 'suppressions');
    assert.equal(a.context.pageTabOn('outbound', 'nonsense'), 'suppressions');
    vm.runInContext(`outboundTab = 'queue'; currentTab = 'dashboard';`, a.context);
    a.context.applyFeatureToggles();
    assert.equal(vm.runInContext('outboundTab', a.context), 'suppressions');
});

test('a page goes only when all of its switches are off', () => {
    let a = loadApp(['queue', 'suppressions']);
    a.context.switchTab('outbound', { sub: 'queue' });
    assert.match(a.elements['content-outbound'].innerHTML, /Outbound is disabled/);

    a = loadApp(['queue']);
    let loaded = [];
    a.context.loadQueue = () => loaded.push('queue');
    a.context.loadSuppressionsTab = () => loaded.push('suppressions');
    a.context.loadSuppressionStats = () => loaded.push('stats');
    a.context.switchTab('outbound', { sub: 'queue' });
    assert.doesNotMatch(a.elements['content-outbound'].innerHTML, /is disabled/);
    // Queue is off: only the Suppressions tab shows, and the queue is not asked
    assert.deepEqual(loaded, ['suppressions']);
    assert.equal(hidden(a, 'outbound-tab-suppressions'), false);
    assert.equal(hidden(a, 'outbound-tab-queue'), true);

    a = loadApp(['quarantine']);
    loaded = [];
    a.context.loadQuarantine = () => loaded.push('quarantine');
    a.context.initQuarantineRules = () => loaded.push('rules');
    a.context.loadRspamdMaps = () => loaded.push('maps');
    a.context.switchTab('quarantine', { sub: 'messages' });
    assert.deepEqual(loaded, ['maps'], 'Quarantine off: its messages are not asked, the maps load once');
});

test('the old feature name is not used in the code any more', () => {
    // Only the alias in the router (old addresses) may still name spam-filter
    for (const file of fs.readdirSync(frontend).filter(f => f.endsWith('.js') || f.endsWith('.html'))) {
        const text = fs.readFileSync(path.join(frontend, file), 'utf8');
        const uses = text.match(/['"`]spam-filter['"`]/g) || [];
        assert.equal(uses.length, file === 'router.js' ? 1 : 0, file);
    }
});

test('falling back from a tab that is off replaces the history entry instead of adding one', () => {
    // Queue off, Outbound open on Suppressions, Back to an entry that names the Queue tab
    let a = loadApp(['queue']);
    a.context.loadSuppressionsTab = () => {};
    a.context.loadSuppressionStats = () => {};
    a.context.switchTab('outbound', { sub: 'suppressions' });
    a.synced.length = 0;
    a.context.switchTab('outbound', { sub: 'queue' });
    assert.deepEqual(plain(a.synced), [{ route: 'outbound', sub: 'suppressions', replace: true }]);

    // A tab the user picks adds an entry, as before
    a = loadApp([]);
    a.context.loadQueue = () => {};
    a.context.loadSuppressionsTab = () => {};
    a.context.loadSuppressionStats = () => {};
    a.context.switchTab('outbound', { sub: 'queue' });
    a.synced.length = 0;
    a.context.outboundShowTab('suppressions');
    assert.deepEqual(plain(a.synced), [{ route: 'outbound', sub: 'suppressions', replace: false }]);

    // Quarantine off: the Messages tab falls back to the maps the same way
    a = loadApp(['quarantine']);
    a.context.loadRspamdMaps = () => {};
    a.context.switchTab('quarantine', { sub: 'maps' });
    a.synced.length = 0;
    a.context.switchTab('quarantine', { sub: 'messages' });
    assert.deepEqual(plain(a.synced), [{ route: 'quarantine', sub: 'maps', replace: true }]);
});
