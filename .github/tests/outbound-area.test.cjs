// Outbound (Queue and Suppressions) and the Rspamd page (the maps): old
// addresses and old history entries open the new place, and each Outbound tab
// follows its own feature switch, the page going only when both are off.
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
        ['/spam-filter/maps', 'rspamd', undefined, '/rspamd'],
        ['/quarantine/maps', 'rspamd', undefined, '/rspamd'],
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
        ['/rspamd', 'rspamd', undefined], ['/quarantine/rules', 'quarantine', 'rules']]) {
        const r = loadRouter(pathname);
        const info = r.context.initRouter();
        assert.deepEqual([info.baseRoute, info.params.sub, info.moved], [route, sub, undefined], pathname);
        assert.equal(r.calls.replaceState.at(-1).url, pathname);
    }
    const r = loadRouter('/');
    assert.equal(r.context.buildPath('outbound', { sub: 'queue' }), '/outbound');
    assert.equal(r.context.buildPath('outbound', { sub: 'suppressions' }), '/outbound/suppressions');
    assert.equal(r.context.buildPath('rspamd', {}), '/rspamd');
});

test('Back into a history entry of the old version opens the new place', () => {
    const r = loadRouter('/dashboard');
    r.context.initRouter();
    r.listeners.popstate({ state: { route: 'spam-filter', params: { sub: 'maps' } } });
    assert.deepEqual(plain(r.calls.switchTab.at(-1)), { route: 'rspamd', params: {} });
    assert.equal(r.calls.replaceState.at(-1).url, '/rspamd');
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

test('the Rspamd page has its own switch, and Quarantine keeps its two tabs', () => {
    let a = loadApp(['rspamd']);
    a.context.applyFeatureToggles();
    assert.equal(a.elements['tab-rspamd'].style.display, 'none');
    assert.equal(a.elements['mobile-tab-rspamd'].style.display, 'none');
    assert.equal(a.elements['tab-quarantine'].style.display, '');
    // Suppressions no longer offer to open the map
    assert.equal(a.elements['suppression-open-map'].style.display, 'none');

    a = loadApp(['quarantine']);
    a.context.applyFeatureToggles();
    assert.equal(a.elements['tab-quarantine'].style.display, 'none');
    assert.equal(a.elements['tab-rspamd'].style.display, '');
    assert.equal(a.elements['suppression-open-map'].style.display, '');

    a = loadApp(['suppressions', 'rspamd']);
    a.context.switchTab('rspamd', {});
    assert.match(a.elements['content-rspamd'].innerHTML, /Rspamd is disabled/);
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

    a = loadApp([]);
    loaded = [];
    a.context.loadRspamdMaps = () => loaded.push('maps');
    a.context.switchTab('rspamd', {});
    assert.deepEqual(loaded, ['maps'], 'the Rspamd page loads its maps once');
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
});

test('opening the Queue tab loads the queue again, as opening the page did', () => {
    const a = loadApp([]);
    const loaded = [];
    a.context.loadQueue = () => loaded.push('queue');
    a.context.loadSuppressionsTab = () => loaded.push('suppressions');
    a.context.loadSuppressionStats = () => loaded.push('stats');
    a.context.switchTab('outbound', { sub: 'suppressions' });
    assert.deepEqual(loaded, ['queue', 'suppressions'], 'the page: the queue for its summary, the list of its tab');
    loaded.length = 0;
    a.context.outboundShowTab('queue');
    assert.deepEqual(loaded, ['queue']);
});

test('Suppressions open the map they are written to on the Rspamd page', async () => {
    const a = load(['utils.js', 'router.js', 'app.js', 'spam_filter.js'], { disabled: [] });
    const opened = [], went = [];
    a.context.navigateTo = route => went.push(route);
    a.context.openMapEditor = name => opened.push(name);
    a.context.renderRspamdMapsList = () => {};
    a.context.authenticatedFetch = async () => ({ ok: true, json: async () => ({
        configured: true, rw_key_configured: true, maps: [{ filename: 'global_rcpt_blacklist.map', name: 'Recipient Denylist' }] }) });
    a.context.openRspamdMap('global_rcpt_blacklist.map');
    assert.deepEqual(went, ['rspamd']);
    await a.context.loadRspamdMaps();
    assert.deepEqual(opened, ['global_rcpt_blacklist.map']);
    // Only once: the next visit shows the list
    await a.context.loadRspamdMaps();
    assert.deepEqual(opened, ['global_rcpt_blacklist.map']);
});

test('a page that says it is disabled is not refreshed on the timer', async () => {
    const a = loadApp(['quarantine']);
    let asked = 0;
    a.context.smartRefreshQuarantine = async () => { asked++; };
    a.context.document.getElementById('message-modal').classList.add('hidden');
    a.context.switchTab('quarantine', { sub: 'messages' });
    await a.context.pageRefreshNow();
    assert.equal(asked, 0);
    const b = loadApp([]);
    b.context.smartRefreshQuarantine = async () => { asked++; };
    b.context.loadQuarantine = () => {};
    b.context.initQuarantineRules = () => {};
    b.context.document.getElementById('message-modal').classList.add('hidden');
    b.context.switchTab('quarantine', { sub: 'messages' });
    await b.context.pageRefreshNow();
    assert.equal(asked, 1);
});
