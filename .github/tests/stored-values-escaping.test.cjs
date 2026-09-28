// Stored values that reach inline HTML must stay data. Each case renders a
// value that tries to leave its context (close an attribute, close a JS
// string) and checks the markup and the inline handler the way a browser
// reads them: HTML entities decoded first, then the handler run as JS.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');

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

function load(files, extra = {}) {
    const context = vm.createContext({
        document: stub(), window: {}, localStorage: stub(), navigator: stub(), location: stub(),
        console: { log() {}, error() {}, warn() {} }, setTimeout() {}, setInterval() {}, appTimezone: 'UTC',
        ...extra,
    });
    for (const file of files) vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    return context;
}

function decodeEntities(value) {
    return value.replace(/&(#\d+|#x[0-9a-f]+|quot|amp|lt|gt|apos);/gi, (m, e) => {
        const named = { quot: '"', amp: '&', lt: '<', gt: '>', apos: "'" };
        if (e[0] === '#') return String.fromCodePoint(e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
        return named[e.toLowerCase()];
    });
}

// Run every onclick in ``html`` in a sandbox that records the calls it makes
function runHandlers(html, functions) {
    const calls = [];
    const sandbox = { window: {}, setTimeout() {} };
    for (const name of functions) sandbox[name] = (...args) => calls.push([name, ...args]);
    vm.createContext(sandbox);
    const handlers = [...html.matchAll(/onclick=(["'])(.*?)\1/g)].map(m => decodeEntities(m[2]));
    for (const handler of handlers) {
        try { vm.runInContext(handler, sandbox); } catch { /* a broken handler is also contained */ }
    }
    return { calls, handlers, injected: sandbox.window.injected || sandbox.injected };
}

test('the DMARC breadcrumb passes the domain as data', () => {
    const context = load(['utils.js', 'dmarc.js']);
    const domain = "x');window.injected=1;('";
    let html = '';
    for (const view of ['reportDetails', 'sourceDetails', 'tlsDetails']) {
        context.setDmarcBreadcrumb(view, { domain, date: '2026-01-01', ip: '192.0.2.1' });
        html += vm.runInContext('dmarcState', context).breadcrumb.map(item => `<button onclick="${item.action}"></button>`).join('');
    }
    const { calls, injected } = runHandlers(html, ['loadDomainOverview', 'dmarcSwitchSubTab']);
    assert.equal(injected, undefined);
    assert.ok(calls.length > 0);
    for (const [name, arg] of calls.filter(c => c[0] === 'loadDomainOverview')) {
        assert.equal(name, 'loadDomainOverview');
        assert.equal(arg, domain);
    }
});

test('a report URI is only a link when it is a mailto address', () => {
    const src = fs.readFileSync(path.join(frontend, 'dmarc.js'), 'utf8');
    const start = src.indexOf('const formatUriAsEmail');
    assert.ok(start > 0);
    // The helper is local to a render function; evaluate it on its own
    const body = src.slice(start, src.indexOf('};', start) + 2);
    const context = load(['utils.js']);
    vm.runInContext(body.replace('const formatUriAsEmail', 'globalThis.formatUriAsEmail'), context);
    assert.match(context.formatUriAsEmail('mailto:dmarc@example.com'), /^<a href="mailto:dmarc@example.com"/);
    assert.doesNotMatch(context.formatUriAsEmail('javascript:alert(1)'), /<a /);
});

test('the disabled_features field keeps its value inside the attribute', () => {
    const context = load(['utils.js', 'settings.js'], {
        TOGGLEABLE_FEATURES: [{ id: 'queue', label: 'Queue', description: 'Mail queue monitoring' }],
    });
    const html = context.renderSettingsEditField('disabled_features', 'queue" data-injected="1', [], '', false, '');
    const input = html.match(/<input type="hidden" id="setting-disabled_features"[^>]*>/)[0];
    assert.doesNotMatch(input, /data-injected="1"/);
    assert.match(input, /value="queue&quot; data-injected=&quot;1"/);
});

test('the suppression Edit button passes only the row id', () => {
    const context = load(['utils.js', 'spam_filter.js']);
    const notes = "&#34;});window.injected=1;//' \"); window.injected=1; //";
    const row = context.renderSuppressionItem({
        id: 7, email: 'user@example.com', type: 'email', reason: 'manual', source: 'manual',
        notes, active: true, synced_to_rspamd: false, created_at: '2026-01-01T00:00:00Z',
        expires_at: null, bounce_count: 1,
    });
    const { calls, handlers, injected } = runHandlers(row, ['showEditSuppressionModalById', 'toggleSuppression', 'deleteSuppression']);
    assert.equal(injected, undefined);
    assert.ok(handlers.every(h => !h.includes('injected')), 'no stored text inside a handler');
    assert.deepEqual(calls.find(c => c[0] === 'showEditSuppressionModalById'), ['showEditSuppressionModalById', 7]);
});

test('the Edit button opens the row it belongs to', () => {
    const opened = [];
    const context = load(['utils.js', 'spam_filter.js']);
    context.showEditSuppressionModal = s => opened.push(s);
    vm.runInContext('suppressionItemsById.set(7, { id: 7, email: "user@example.com" })', context);
    context.showEditSuppressionModalById(7);
    context.showEditSuppressionModalById(8);
    assert.deepEqual(opened.map(s => s.email), ['user@example.com']);
});

test('the Logs page passes a service name as data', () => {
    const elements = {};
    const document = new Proxy(stub(), {
        get: (target, key) => key === 'getElementById'
            ? id => (elements[id] = elements[id] || { innerHTML: '', classList: stub(), style: {} })
            : stub(),
    });
    const context = load(['utils.js', 'logs-viewer.js'], { document });
    const id = "x');window.injected=1;('\" data-injected=\"1";
    context.renderLogServiceList([{ id, name: 'X', icon: 'file', log_count: 0 }]);
    const html = elements['logs-service-list'].innerHTML;
    assert.doesNotMatch(html, /data-injected="1"/);
    const { calls, injected } = runHandlers(html, ['selectLogService']);
    assert.equal(injected, undefined);
    assert.deepEqual(calls, [['selectLogService', id]]);
});
