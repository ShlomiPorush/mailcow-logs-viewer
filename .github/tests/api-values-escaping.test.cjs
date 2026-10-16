// Values that come from the API (mail logs, DMARC reports, mailcow data) must
// stay text when a page renders them. Each case feeds a markup payload or a
// value that tries to leave a JS string, and checks the markup and the inline
// handlers the way a browser reads them: entities decoded first, then the
// handler run as JS.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');
const PAYLOAD = '<img src=x onerror=alert(1)>';
const BREAKOUT = "x');window.injected=1;('";

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

// app.js reads the viewport at load; a desktop window, inert otherwise
function appWindow() {
    const base = stub();
    return new Proxy({}, { get: (_, key) => key === 'matchMedia' ? () => ({ matches: false, addEventListener() {} }) : base[key] });
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
    return { calls, injected: sandbox.window.injected || sandbox.injected };
}

test('a domain row keeps the domain and its counts as text and opens itself', () => {
    const context = load(['utils.js', 'domains.js']);
    const domain = `${BREAKOUT}${PAYLOAD}.example.com`;
    const html = context.renderDomainAccordionRow({
        domain_name: domain, active: true, dns_checks: {}, bytes_total: 0,
        mboxes_in_domain: PAYLOAD, aliases_in_domain: 1, max_num_mboxes_for_domain: 10, mboxes_left: PAYLOAD,
        max_num_aliases_for_domain: 10, aliases_left: 9, msgs_total: 0,
    });
    assert.doesNotMatch(html, /<img/);
    const { calls, injected } = runHandlers(html, ['toggleDomainDetails', 'copyToClipboard']);
    assert.equal(injected, undefined);
    const toggle = calls.find(c => c[0] === 'toggleDomainDetails');
    assert.ok(toggle, 'the row toggles its details');
    // The toggle names the element the row actually rendered
    assert.ok(html.includes(`id="${toggle[1]}-details"`));
    // An ordinary domain keeps the id it always had
    assert.equal(context.domainRowId('mail.example.com'), 'domain-mail-example-com');
});

test('a related delivery opens with its correlation key as data', () => {
    const context = load(['utils.js', 'message-details.js'], { formatTime: v => v || '-' });
    context.formatTime = v => v || '-';
    const html = context.renderRelatedDeliveries({
        correlation_key: 'current', sender: 'a@example.com', recipient: 'b@example.com', final_status: 'delivered',
        related_deliveries: [{ correlation_key: BREAKOUT, sender: 'a@example.com', recipient: 'c@example.com', final_status: 'delivered' }],
    });
    const { calls, injected } = runHandlers(html, ['viewMessageDetails', 'copyToClipboard']);
    assert.equal(injected, undefined);
    assert.deepEqual(calls.filter(c => c[0] === 'viewMessageDetails'), [['viewMessageDetails', BREAKOUT]]);
});

test('a suppression row shows its counts and expiry as text', () => {
    const context = load(['utils.js', 'spam_filter.js']);
    const html = context.renderSuppressionItem({
        id: 7, email: 'user@example.com', type: 'email', reason: 'manual', source: 'manual', notes: '', active: true,
        synced_to_rspamd: false, created_at: '2026-01-01T00:00:00Z', expires_at: '2026-02-01T00:00:00Z',
        expires_in: { human: PAYLOAD }, bounce_count: 2, hard_bounce_count: PAYLOAD, soft_bounce_count: 1,
    });
    assert.doesNotMatch(html, /<img/);
    assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
});

test('the changelog dialog shows the text, not markup, when marked is missing', () => {
    const element = () => ({ innerHTML: '', textContent: '', style: {}, classList: { add() {}, remove() {} }, querySelector: () => null });
    const elements = { 'changelog-modal': element(), 'changelog-content': element() };
    const document = new Proxy(stub(), {
        get: (target, key) => key === 'getElementById' ? id => (elements[id] = elements[id] || element())
            : key === 'body' ? { style: {} } : stub(),
    });
    const context = load(['utils.js', 'app.js'], { document, window: appWindow() });
    context.showMarkdownModal('Update', `# Notes\n${PAYLOAD}`);
    const html = elements['changelog-content'].innerHTML;
    assert.doesNotMatch(html, /<img/);
    assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
});

test('a flag image is built only from a two-letter country code', () => {
    const context = load(['utils.js', 'app.js'], { window: appWindow() });
    assert.equal(context.getFlagUrl('DE', '16x12'), '/static/assets/flags/16x12/de.png');
    assert.equal(context.getFlagUrl('">'), null);
    assert.equal(context.getFlagUrl('1<'), null);
    assert.equal(context.getFlagUrl(null), null);
});

test('DMARC reporter names such as __proto__ are counted like any other name', () => {
    const context = load(['utils.js', 'dmarc.js']);
    const reporters = [{ org_name: '__proto__', count: 3, dmarc_pass: 1 }, { org_name: 'constructor', count: 2, dmarc_pass: 2 }];
    const groups = context.dmarcGroups([
        { asn_org: '__proto__', source_ip: '192.0.2.1', total_count: 5, dmarc_pass: 3, reporters },
    ]);
    assert.equal(groups.length, 1);
    assert.equal(groups[0].name, '__proto__');
    const counts = Object.fromEntries(groups[0].reporters.map(r => [r.org_name, r.count]));
    assert.equal(counts.__proto__, 3);
    assert.equal(counts.constructor, 2);
    assert.equal(vm.runInContext('Object.prototype.count', context), undefined);
});
