// Queue and Quarantine refresh by themselves: rows the user checked stay checked
// through a redraw (and the selection bar says so), a row that left the list
// leaves the selection, nothing is redrawn while an action of the list runs, and
// an answer older than the one drawn is dropped. Runs in a real DOM (jsdom),
// installed by CI outside the repository; set A11Y_MODULES to its node_modules:
//   npm install --no-save --prefix /tmp/a11y jsdom axe-core
//   A11Y_MODULES=/tmp/a11y/node_modules node --test .github/tests/list-refresh.a11y.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');

const BODY = `
    <section id="content-outbound"><p id="queue-summary"></p><span id="queue-count"></span>
        <input id="queue-filter-search" value=""><input id="queue-filter-queue-id" value="">
        <div id="queue-logs"></div></section>
    <section id="content-quarantine"><p id="quarantine-summary"></p><span id="quarantine-count"></span>
        <div id="quarantine-logs"></div></section>`;

const item = id => ({ queue_id: id, queue_name: 'deferred', sender: 's@example.com', arrival_time: 1760000000, message_size: 100, recipients: [`${id.toLowerCase()}@example.org`] });
const held = id => ({ id, subject: `Held ${id}`, sender: 's@example.com', rcpt: 'r@example.org', action: 'reject', score: 9, created: '2026-10-24T10:00:00Z' });

function page() {
    const dom = new JSDOM(`<!doctype html><html lang="en"><head><title>t</title></head><body>${BODY}</body></html>`,
        { runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/outbound' });
    const w = dom.window;
    w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    const run = source => {
        const script = w.document.createElement('script');
        script.textContent = source;
        w.document.head.appendChild(script);
    };
    [read('utils.js'), read('router.js'), read('app.js')].forEach(run);
    run(`mailcowRwConfigured = true; rwStatusReady = Promise.resolve();
        var served = {}; authenticatedFetch = async url => {
            const answer = served[url.split('?')[0]];
            const data = typeof answer === 'function' ? await answer() : answer;
            return { ok: true, json: async () => data };
        };`);
    return { w, run, $: s => w.document.querySelector(s), $$: s => [...w.document.querySelectorAll(s)] };
}

const checked = (p, cls) => p.$$(`.${cls}:checked`).map(cb => cb.value);

test('a Queue refresh keeps the checked rows, and drops one that left', async () => {
    const p = page();
    p.w.served['/api/queue'] = { data: [item('A1'), item('B2'), item('C3')] };
    p.w.served['/api/suppressions/config'] = { list_kept: false };
    await p.w.loadQueue();
    for (const id of ['B2', 'C3']) p.$(`.queue-checkbox[value="${id}"]`).checked = true;
    p.w.queueUpdateSelection();
    p.w.served['/api/queue'] = { data: [item('A1'), item('B2'), item('D4')] };
    await p.w.smartRefreshQueue();
    assert.deepEqual(p.$$('.queue-checkbox').map(cb => cb.value), ['A1', 'B2', 'D4']);
    assert.deepEqual(checked(p, 'queue-checkbox'), ['B2']);
    assert.equal(p.$('#queue-selection-count').textContent, '1 selected');
    assert.ok(!p.$('#queue-bulk-retry-btn').classList.contains('hidden'));
    assert.ok(p.$('#queue-delete-all-btn').classList.contains('hidden'));
});

test('every row checked reads Deselect All, also after a redraw', async () => {
    const p = page();
    p.w.served['/api/queue'] = { data: [item('A1'), item('B2')] };
    p.w.served['/api/suppressions/config'] = { list_kept: false };
    await p.w.loadQueue();
    p.w.queueSelectAll();
    assert.equal(p.$('#queue-select-all-btn').textContent, 'Deselect All');
    p.w.served['/api/queue'] = { data: [item('A1'), item('B2')], changed: true };
    await p.w.smartRefreshQueue();
    assert.equal(p.$('#queue-select-all-btn').textContent, 'Deselect All');
});

test('nothing is redrawn while a Queue action runs', async () => {
    const p = page();
    p.w.served['/api/queue'] = { data: [item('A1')] };
    p.w.served['/api/suppressions/config'] = { list_kept: false };
    await p.w.loadQueue();
    p.run('queueActing = 1');
    p.w.served['/api/queue'] = { data: [item('A1'), item('B2')] };
    await p.w.smartRefreshQueue();
    assert.equal(p.$$('.queue-checkbox').length, 1);
});

test('a Quarantine refresh keeps the checked rows', async () => {
    const p = page();
    p.w.served['/api/quarantine'] = { data: [held(1), held(2)], total: 2 };
    await p.w.loadQuarantine();
    p.$('.quarantine-checkbox[value="2"]').checked = true;
    p.w.quarantineUpdateSelection();
    p.w.served['/api/quarantine'] = { data: [held(3), held(1), held(2)], total: 3 };
    await p.w.smartRefreshQuarantine();
    assert.equal(p.$$('.quarantine-checkbox').length, 3);
    assert.deepEqual(checked(p, 'quarantine-checkbox'), ['2']);
    assert.equal(p.$('#quarantine-selection-count').textContent, '1 selected');
});

test('a Quarantine answer older than the one drawn is dropped', async () => {
    const p = page();
    p.w.served['/api/quarantine'] = { data: [held(1), held(2)], total: 2 };
    await p.w.loadQuarantine();
    // A refresh still on its way when the reload after a release answers
    let late;
    p.w.served['/api/quarantine'] = () => new Promise(resolve => { late = () => resolve({ data: [held(1), held(2)], total: 2 }); });
    const refresh = p.w.smartRefreshQuarantine();
    await new Promise(resolve => setTimeout(resolve, 0));
    p.w.served['/api/quarantine'] = { data: [held(2)], total: 1 };
    await p.w.loadQuarantine();
    late();
    await refresh;
    assert.deepEqual(p.$$('.quarantine-checkbox').map(cb => cb.value), ['2']);
});

test('nothing is redrawn while a Quarantine action runs', async () => {
    const p = page();
    p.w.served['/api/quarantine'] = { data: [held(1)], total: 1 };
    await p.w.loadQuarantine();
    p.run('quarantineActing = 1');
    p.w.served['/api/quarantine'] = { data: [held(1), held(2)], total: 2 };
    await p.w.smartRefreshQuarantine();
    assert.equal(p.$$('.quarantine-checkbox').length, 1);
});

test('a Quarantine that failed to load is drawn by the next refresh, even with the answer it had before', async () => {
    const p = page();
    p.w.served['/api/quarantine'] = { data: [held(1)], total: 1 };
    await p.w.loadQuarantine();
    p.w.served['/api/quarantine'] = () => { throw new Error('down'); };
    await p.w.loadQuarantine();
    assert.equal(p.$$('.quarantine-checkbox').length, 0);
    p.w.served['/api/quarantine'] = { data: [held(1)], total: 1 };
    await p.w.smartRefreshQuarantine();
    assert.equal(p.$$('.quarantine-checkbox').length, 1);
});
