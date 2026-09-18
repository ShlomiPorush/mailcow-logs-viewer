const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../../frontend/dmarc.js'), 'utf8');
const start = source.indexOf('const reportsManagementState =');
const end = source.length;
assert.ok(start > 0 && end > start);

function harness() {
    const content = { innerHTML: '' };
    const classes = new Set(['hidden']);
    const modal = { classList: {
        add: value => classes.add(value), remove: value => classes.delete(value),
        contains: value => classes.has(value)
    } };
    const requests = [];
    const context = vm.createContext({
        document: { getElementById: id => id.endsWith('-modal') ? modal : content },
        authenticatedFetch: url => new Promise(resolve => requests.push({ url, resolve })),
        escapeHtml: value => value, escapeJsArg: value => value,
        console: { error() {} }, showToast() {}, showConfirmModal: async () => true,
        dmarcState: { currentView: 'reports' }
    });
    vm.runInContext(source.slice(start, end), context);
    const run = expression => vm.runInContext(expression, context);
    function resolve(index, page = 1, status = 200) {
        requests[index].resolve({ ok: status === 200, status, json: async () => ({
            reports: [{ id: page, type: 'dmarc', domain: 'example.com', record_count: 0 }],
            page, total_pages: 3, total: 101, allow_delete: true
        }) });
    }
    return { run, resolve, requests, content, modal };
}

test('requests one page and renders the total with boundary controls', async () => {
    const h = harness();
    const pending = h.run('showReportsManagementModal()');
    assert.equal(h.requests[0].url, '/api/dmarc/reports/all?page=1&limit=50');
    h.resolve(0);
    await pending;
    assert.match(h.content.innerHTML, />101<\/span> reports/);
    assert.match(h.content.innerHTML, /Page 1 of 3/);
    assert.match(h.content.innerHTML, /loadReportsManagementPage\(0\)" disabled/);
});

test('late responses cannot replace a newer page or a closed dialog', async () => {
    const h = harness();
    const old = h.run('loadReportsManagementPage(1)');
    const current = h.run('loadReportsManagementPage(2)');
    h.resolve(1, 2);
    await current;
    h.resolve(0, 1);
    await old;
    assert.match(h.content.innerHTML, /Page 2 of 3/);
    const closing = h.run('loadReportsManagementPage(3)');
    h.run('closeReportsManagementModal()');
    h.resolve(2, 3);
    await closing;
    assert.doesNotMatch(h.content.innerHTML, /Page 3 of 3/);
});

test('request errors offer a retry for the requested page', async () => {
    const h = harness();
    const pending = h.run('loadReportsManagementPage(2)');
    h.resolve(0, 2, 503);
    await pending;
    assert.match(h.content.innerHTML, /Failed to load reports/);
    assert.match(h.content.innerHTML, /loadReportsManagementPage\(2\)/);
});

test('deleting a report reloads the current page and accepts server clamping', async () => {
    const h = harness();
    const opening = h.run('showReportsManagementModal()');
    h.resolve(0, 3);
    await opening;
    const deleting = h.run("deleteReport('dmarc', 3, 'example.com')");
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(h.requests[1].url, '/api/dmarc/reports/dmarc/3');
    h.resolve(1);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(h.requests[2].url, '/api/dmarc/reports/all?page=3&limit=50');
    h.resolve(2, 2);
    await deleting;
    assert.match(h.content.innerHTML, /Page 2 of 3/);
});
