const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

// Exercise the shipped handler, without booting unrelated page modules.
const source = fs.readFileSync(path.join(__dirname, '../../frontend/app.js'), 'utf8');
const handler = source.match(/async function exportCSV\(type\) \{[\s\S]*?\n\}/)?.[0];
assert.ok(handler, 'The CSV download handler must be present');

function harness(filters, status = 200, contentType = 'text/csv; charset=utf-8') {
    const result = { urls: [], downloads: 0, blobs: 0, notices: [] };
    const response = {
        ok: status >= 200 && status < 300, status,
        headers: { get: () => contentType },
        blob: async () => { result.blobs++; return {}; }
    };
    const context = vm.createContext({
        URLSearchParams, Date,
        currentFilters: { messages: filters },
        authenticatedFetch: async url => { result.urls.push(url); return response; },
        window: { URL: { createObjectURL: () => 'blob:test', revokeObjectURL: () => {} } },
        document: {
            body: { appendChild: () => {}, removeChild: () => {} },
            createElement: () => ({ click: () => { result.downloads++; } })
        },
        showToast: (message, type) => result.notices.push({ message, type }),
        alert: message => result.notices.push({ message }),
        console: { error: () => {} }
    });
    vm.runInContext(handler, context);
    return { result, run: () => context.exportCSV('messages') };
}

test('empty date filters are omitted, while selected filters, zero and false survive', async () => {
    const h = harness({ search: 'mail, subject', start_date: '', end_date: '', sender: null,
        recipient: undefined, direction: ' ', min_score: 0, is_spam: false });
    await h.run();
    const params = new URL(h.result.urls[0], 'http://viewer.test').searchParams;
    assert.equal(params.has('start_date'), false);
    assert.equal(params.has('end_date'), false);
    assert.equal(params.has('sender'), false);
    assert.equal(params.has('recipient'), false);
    assert.equal(params.has('direction'), false);
    assert.equal(params.get('search'), 'mail, subject');
    assert.equal(params.get('min_score'), '0');
    assert.equal(params.get('is_spam'), 'false');
    assert.equal(h.result.downloads, 1);
});

test('selected dates are preserved', async () => {
    const h = harness({ start_date: '2026-01-01T00:00', end_date: '2026-01-02T00:00' });
    await h.run();
    const params = new URL(h.result.urls[0], 'http://viewer.test').searchParams;
    assert.equal(params.get('start_date'), '2026-01-01T00:00');
    assert.equal(params.get('end_date'), '2026-01-02T00:00');
    assert.equal(h.result.downloads, 1);
});

for (const status of [401, 404, 422, 500]) {
    test(`HTTP ${status} displays an error instead of downloading JSON as CSV`, async () => {
        const h = harness({}, status, 'application/json');
        await h.run();
        assert.equal(h.result.downloads, 0);
        assert.equal(h.result.blobs, 0);
        assert.equal(h.result.notices.length, 1);
        assert.equal(h.result.notices[0].type, 'error');
    });
}

test('a successful HTML login response is not saved as CSV', async () => {
    const h = harness({}, 200, 'text/html');
    await h.run();
    assert.equal(h.result.downloads, 0);
    assert.equal(h.result.notices[0].type, 'error');
});
