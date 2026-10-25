// The open page refreshes itself: a tick runs its refresher when the page's
// cadence is due, never twice at once, never while the browser tab is hidden
// or a message dialog covers the page, and a hidden tab catches up when shown.
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

function load() {
    const elements = {};
    const listeners = {};
    const own = {
        hidden: false,
        getElementById: id => (elements[id] = elements[id] || element()),
        querySelectorAll: () => [],
        querySelector: () => null,
        addEventListener: (type, fn) => { (listeners[type] = listeners[type] || []).push(fn); },
    };
    const base = stub();
    const document = new Proxy(own, { get: (t, key) => key in t ? t[key] : base[key] });
    const win = { disabledFeatures: [], location: { pathname: '/', href: 'http://app/' },
        matchMedia: () => ({ matches: false, addEventListener() {} }), addEventListener() {} };
    const window = new Proxy(win, { get: (t, key) => key in t ? t[key] : base[key], set: (t, key, v) => { t[key] = v; return true; } });
    const timers = [];
    const context = vm.createContext({
        document, window, history: { replaceState() {}, pushState() {} }, localStorage: stub(), navigator: stub(),
        location: win.location, console: { log() {}, error() {}, warn() {} },
        setTimeout() {}, setInterval: (fn, ms) => timers.push({ fn, ms }), requestAnimationFrame() {},
        MutationObserver: function () { return { observe() {} }; }, appTimezone: 'UTC',
    });
    for (const file of ['utils.js', 'router.js', 'app.js']) vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    const run = code => vm.runInContext(code, context);
    // A page of our own, counting its runs; each run waits until it is let go
    run(`var refreshRuns = 0, refreshRelease = null;
        registerPageRefresh('testpage', 60000, () => { refreshRuns++; return new Promise(r => { refreshRelease = r; }); });
        currentTab = 'testpage';`);
    elements['message-modal'] = element();
    elements['message-modal'].classList.add('hidden');
    const show = () => (listeners.visibilitychange || []).forEach(fn => fn());
    return { context, run, own, elements, timers, show };
}

// Moves the page's last refresh back, as if that much time had passed
const ago = (p, ms) => p.run(`pageRefreshState.route = currentTab; pageRefreshState.at = Date.now() - ${ms}`);

test('a tick runs the open page only when its cadence is due', () => {
    const p = load();
    p.run(`pageRefreshLoaded('testpage')`);
    p.run('pageRefreshTick()');
    assert.equal(p.run('refreshRuns'), 0);
    ago(p, 59000);
    p.run('pageRefreshTick()');
    assert.equal(p.run('refreshRuns'), 1);
});

test('a run on its way is not started again', () => {
    const p = load();
    ago(p, 60000);
    p.run('pageRefreshNow()');
    p.run('pageRefreshNow()');
    assert.equal(p.run('refreshRuns'), 1);
});

test('a hidden browser tab reads nothing and catches up when shown', () => {
    const p = load();
    p.run('startPageRefresh()');
    assert.equal(p.timers.at(-1).ms, 30000);
    ago(p, 120000);
    p.own.hidden = true;
    p.timers.at(-1).fn();
    assert.equal(p.run('refreshRuns'), 0);
    p.own.hidden = false;
    p.show();
    assert.equal(p.run('refreshRuns'), 1);
});

test('a failed load is tried again on the next tick', () => {
    const p = load();
    p.run(`pageRefreshLoaded('testpage')`);
    p.run(`pageRefreshRetry('testpage')`);
    p.run('pageRefreshTick()');
    assert.equal(p.run('refreshRuns'), 1);
});

test('a message dialog over the page holds the refresh; the docked pane does not', () => {
    const p = load();
    const modal = p.elements['message-modal'];
    modal.classList.remove('hidden');
    ago(p, 60000);
    p.run('pageRefreshNow()');
    assert.equal(p.run('refreshRuns'), 0);
    modal.classList.add('ui-docked');
    p.run('pageRefreshNow()');
    assert.equal(p.run('refreshRuns'), 1);
});

test('a page without a refresher, or one that is off, asks for nothing', () => {
    const p = load();
    p.run(`currentTab = 'about'`);
    ago(p, 600000);
    p.run('pageRefreshTick()');
    p.run(`currentTab = 'testpage'; pageIsOff = () => true`);
    p.run('pageRefreshNow()');
    assert.equal(p.run('refreshRuns'), 0);
});

test('the sidebar counters wait for a shown tab and their five minutes', () => {
    const p = load();
    let reads = 0;
    p.context.loadNavCounters = () => { reads++; p.run('navCountersAt = Date.now()'); };
    p.run('navCountersAt = Date.now() - 6 * 60 * 1000');
    p.own.hidden = true;
    p.run('navCountersTick()');
    assert.equal(reads, 0);
    p.own.hidden = false;
    p.run('navCountersTick()');
    p.run('navCountersTick()');
    assert.equal(reads, 1);
});
