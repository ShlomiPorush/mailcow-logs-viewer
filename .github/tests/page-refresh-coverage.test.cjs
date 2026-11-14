// Every page updates by itself: each page the app routes to (TAB_LABELS in
// router.js) registers a refresh with registerPageRefresh (app.js), or is
// listed below with the reason it has none. A new page without either fails
// here, so it cannot ship without a refresh by accident.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');

// Pages with no refresh of their own, and why
const NO_REFRESH = {
    about: 'shows the app version and links; Check Now asks for updates on demand',
    logs: 'live already: its lines stream over a WebSocket',
};

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
    const base = stub();
    const own = { getElementById: () => base, querySelectorAll: () => [], querySelector: () => null, addEventListener() {} };
    const document = new Proxy(own, { get: (t, key) => key in t ? t[key] : base[key] });
    const win = { disabledFeatures: [], location: { pathname: '/', href: 'http://app/' },
        matchMedia: () => ({ matches: false, addEventListener() {} }), addEventListener() {} };
    const window = new Proxy(win, { get: (t, key) => key in t ? t[key] : base[key], set: (t, key, v) => { t[key] = v; return true; } });
    const context = vm.createContext({
        document, window, history: { replaceState() {}, pushState() {} }, localStorage: stub(), navigator: stub(),
        location: win.location, console: { log() {}, error() {}, warn() {} },
        setTimeout() {}, setInterval() {}, requestAnimationFrame() {},
        MutationObserver: function () { return { observe() {} }; }, appTimezone: 'UTC',
    });
    for (const file of ['utils.js', 'router.js', 'app.js']) vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    return {
        pages: Object.keys(vm.runInContext('TAB_LABELS', context)),
        refreshed: Object.keys(vm.runInContext('pageRefreshers', context)),
    };
}

test('every page refreshes itself, or says why it does not', () => {
    const { pages, refreshed } = load();
    assert.ok(pages.length > 10, 'the pages are read from TAB_LABELS');
    const missing = pages.filter(page => !refreshed.includes(page) && !NO_REFRESH[page]);
    assert.deepEqual(missing, [],
        `Pages without a refresh: ${missing.join(', ')}. Register one with registerPageRefresh in app.js ` +
        '(draw only what changed and never what the user is working in), or add the page to NO_REFRESH in this test with the reason');
});

test('the pages without a refresh are real pages that still have none', () => {
    const { pages, refreshed } = load();
    for (const page of Object.keys(NO_REFRESH)) {
        assert.ok(pages.includes(page), `${page} in NO_REFRESH is not a page any more`);
        assert.ok(!refreshed.includes(page), `${page} refreshes now: remove it from NO_REFRESH`);
    }
});

test('every refresh belongs to a page', () => {
    const { pages, refreshed } = load();
    assert.deepEqual(refreshed.filter(page => !pages.includes(page)), []);
});
