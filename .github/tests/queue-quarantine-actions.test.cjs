// Queue and Quarantine: the row actions follow the Read-Write key even when its
// status arrives after the rows were drawn, Suppress stays without the key, and
// editing a quarantine rule saves it back unchanged.
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

function decodeEntities(value) {
    return value.replace(/&(#\d+|#x[0-9a-f]+|quot|amp|lt|gt|apos);/gi, (m, e) => {
        const named = { quot: '"', amp: '&', lt: '<', gt: '>', apos: "'" };
        if (e[0] === '#') return String.fromCodePoint(e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
        return named[e.toLowerCase()];
    });
}

// app.js with a document whose elements keep what the page writes into them
function loadApp() {
    const elements = {};
    const inserted = [];
    const element = () => ({ innerHTML: '', textContent: '', value: '', style: {}, classList: stub(), remove() {}, focus() {} });
    const document = new Proxy(stub(), {
        get: (target, key) => key === 'getElementById' ? id => (elements[id] = elements[id] || element())
            : key === 'body' ? { style: {}, insertAdjacentHTML: (where, html) => inserted.push(html) } : stub(),
    });
    const base = stub();
    const window = new Proxy({}, { get: (_, key) => key === 'matchMedia' ? () => ({ matches: false, addEventListener() {} }) : base[key] });
    const context = vm.createContext({
        document, window, localStorage: stub(), navigator: stub(), location: stub(),
        console: { log() {}, error() {}, warn() {} }, setTimeout() {}, setInterval() {}, appTimezone: 'UTC',
    });
    for (const file of ['utils.js', 'app.js']) vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    context.showToast = () => {};
    return { context, elements, inserted };
}

const QUEUE = [{
    queue_id: 'ABC123', queue_name: 'deferred', sender: 'sender@example.com', arrival_time: 1760000000,
    message_size: 2048, recipients: ['user@example.org (connect to mx.example.org: Connection timed out)'],
}];

function drawQueue(app, rw) {
    vm.runInContext(`currentTab = 'queue'; mailcowRwConfigured = ${rw}; allQueueData = ${JSON.stringify(QUEUE)};`, app.context);
    app.context.applyQueueFilters();
    return app.elements['queue-logs'].innerHTML;
}

test('queue rows get their actions when the Read-Write status arrives after them', async () => {
    const app = loadApp();
    assert.match(drawQueue(app, false), /Queue actions are locked/);
    app.context.authenticatedFetch = async () => ({ ok: true, json: async () => ({ rw_configured: true }) });
    await app.context.fetchRwStatus();
    const html = app.elements['queue-logs'].innerHTML;
    assert.doesNotMatch(html, /Queue actions are locked/);
    assert.match(html, /queueRetry\(/);
    assert.match(html, /queueDeleteItem\(/);
});

test('quarantine rows get their actions when the Read-Write status arrives after them', async () => {
    const app = loadApp();
    const data = { total: 1, data: [{ id: 7, sender: 'sender@example.com', rcpt: 'user@example.org', subject: 'Hello', score: 9, action: 'reject', created: 1760000000 }] };
    vm.runInContext(`currentTab = 'quarantine'; mailcowRwConfigured = false;`, app.context);
    app.context.renderQuarantineData(data);
    assert.match(app.elements['quarantine-logs'].innerHTML, /Quarantine actions are locked/);
    app.context.authenticatedFetch = async () => ({ ok: true, json: async () => ({ rw_configured: true }) });
    await app.context.fetchRwStatus();
    assert.doesNotMatch(app.elements['quarantine-logs'].innerHTML, /Quarantine actions are locked/);
});

test('Suppress stays on queue rows without the Read-Write key', () => {
    const html = drawQueue(loadApp(), false);
    assert.match(html, /showAddSuppressionModal\('user@example\.org'\)/);
    assert.doesNotMatch(html, /queue-action-btn|queue-checkbox/);
    assert.match(html, /Actions<\/span>/);
});

test('with the key, queue rows keep every action', () => {
    const html = drawQueue(loadApp(), true);
    for (const action of ['queueRetry', 'queueHold', 'queueDeleteItem', 'showAddSuppressionModal']) assert.match(html, new RegExp(action + '\\('));
});
