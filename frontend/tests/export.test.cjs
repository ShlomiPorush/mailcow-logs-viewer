const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

function harness(status = 200, contentType = 'text/csv; charset=utf-8') {
    const requests = [];
    const downloads = [];
    const toasts = [];
    const context = vm.createContext({
        URLSearchParams,
        console: { error() {} },
        currentFilters: { messages: { sender: 'user@example.com', search: ' ', min_score: 0, is_spam: false } },
        async authenticatedFetch(url, options) {
            requests.push({ url, options });
            return {
                ok: status === 200,
                status,
                headers: { get: () => contentType },
                blob() { throw new Error('Download must not buffer a Blob'); },
            };
        },
        document: {
            body: { appendChild() {} },
            createElement(tag) {
                assert.equal(tag, 'a');
                return {
                    click() { downloads.push({ href: this.href, download: this.download }); },
                    remove() {},
                };
            },
        },
        showToast(message, type) { toasts.push({ message, type }); },
    });
    vm.runInContext(readFileSync(join(__dirname, '..', 'export.js'), 'utf8'), context);
    return { context, requests, downloads, toasts };
}

test('preflight validates filters before a native download without buffering CSV', async () => {
    const state = harness();
    await state.context.exportCSV('messages');
    assert.equal(state.requests.length, 1);
    assert.equal(state.requests[0].options.method, 'HEAD');
    assert.equal(state.downloads.length, 1);
    assert.equal(state.downloads[0].href, state.requests[0].url);
    assert.equal(state.downloads[0].download, ''); // Use the server filename.
    const params = new URL(state.downloads[0].href, 'https://example.com').searchParams;
    assert.equal(params.get('sender'), 'user@example.com');
    assert.equal(params.get('min_score'), '0');
    assert.equal(params.get('is_spam'), 'false');
    assert.equal(params.has('search'), false);
    assert.deepEqual(state.toasts, [{ message: 'Download started.', type: 'success' }]);
});

for (const [status, contentType, message] of [
    [404, 'application/json', 'No data to export. Try different filters.'],
    [422, 'application/json', 'Could not export CSV. Check the filters and try again.'],
    [500, 'application/json', 'Could not export CSV. Please try again.'],
    [200, 'text/html', 'Could not export CSV. Refresh the page and try again.'],
]) {
    test(`preflight ${status} ${contentType} prevents a download and reports the error`, async () => {
        const state = harness(status, contentType);
        await state.context.exportCSV('messages');
        assert.equal(state.downloads.length, 0);
        assert.deepEqual(state.toasts, [{ message, type: 'error' }]);
    });
}

test('an expired session handled by authenticatedFetch cannot start a download', async () => {
    const state = harness();
    state.context.authenticatedFetch = async () => { throw new Error('Authentication required'); };
    await state.context.exportCSV('messages');
    assert.equal(state.downloads.length, 0);
    assert.equal(state.toasts[0].type, 'error');
});
