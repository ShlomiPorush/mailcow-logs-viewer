// A browser west of UTC, where a date read as UTC midnight is the day before
process.env.TZ = 'America/Los_Angeles';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../../frontend/app.js'), 'utf8');
const extract = signature => {
    const code = source.match(new RegExp(`${signature.replace(/[()]/g, '\\$&')} \\{[\\s\\S]*?\\n\\}`))?.[0];
    assert.ok(code, `${signature} must be present`);
    return code;
};

function harness(filters) {
    const elements = {};
    const element = id => elements[id] || (elements[id] = { value: '', textContent: '', style: {}, classList: { add() {} } });
    const calls = { urls: [], rendered: 0, applied: 0, toasts: [] };
    const context = vm.createContext({
        URLSearchParams,
        currentFilters: { messages: filters },
        currentPage: { messages: 1 },
        lastDataCache: {},
        document: { getElementById: element },
        authenticatedFetch: async url => { calls.urls.push(url); return { ok: true, json: async () => ({ data: [] }) }; },
        hasDataChanged: () => true,
        renderMessagesData: () => { calls.rendered++; },
        showToast: (...args) => calls.toasts.push(args),
        setMessagesDatePresetActive() {},
        toggleMessagesTimePanel() {},
        applyMessagesFilters: () => { calls.applied++; },
        console: { log() {} },
    });
    vm.runInContext([
        extract('async function smartRefreshMessages()'),
        extract('function messagesQueryParams(page)'),
        extract('function applyMessagesCustomDateRange()'),
    ].join('\n'), context);
    return { calls, element, run: expression => vm.runInContext(expression, context) };
}

test('the auto refresh keeps a time range that is the only filter', async () => {
    const h = harness({ date_range: 'custom', start_date: '2026-10-13T07:00:00.000Z', end_date: '2026-10-14T06:59:59.999Z' });
    await h.run('smartRefreshMessages()');
    assert.equal(h.calls.urls.length, 1);
    const params = new URL(h.calls.urls[0], 'http://viewer.test').searchParams;
    assert.equal(params.get('start_date'), '2026-10-13T07:00:00.000Z');
    assert.equal(params.get('end_date'), '2026-10-14T06:59:59.999Z');
    assert.equal(params.get('page'), '1');
});

test('the auto refresh still leaves a search alone', async () => {
    const h = harness({ search: 'invoice' });
    await h.run('smartRefreshMessages()');
    assert.equal(h.calls.urls.length, 0);
});

test('a custom range covers the chosen days in the browser time zone', () => {
    const h = harness({});
    h.element('messages-date-range-start').value = '2026-10-13';
    h.element('messages-date-range-end').value = '2026-10-14';
    h.run('applyMessagesCustomDateRange()');
    assert.equal(h.element('messages-start-date').value, '2026-10-13T07:00:00.000Z');
    assert.equal(h.element('messages-end-date').value, '2026-10-15T06:59:59.999Z');
    assert.equal(h.element('messages-date-range-label').textContent, 'Oct 13 - Oct 14');
    assert.equal(h.calls.applied, 1);
});

test('a one-day custom range is that whole day', () => {
    const h = harness({});
    h.element('messages-date-range-start').value = '2026-10-13';
    h.element('messages-date-range-end').value = '2026-10-13';
    h.run('applyMessagesCustomDateRange()');
    const start = new Date(h.element('messages-start-date').value);
    const end = new Date(h.element('messages-end-date').value);
    assert.equal(start.getDate(), 13);
    assert.equal(start.getHours(), 0);
    assert.equal(end.getDate(), 13);
    assert.equal(end.getHours(), 23);
    assert.equal(h.element('messages-date-range-label').textContent, 'Oct 13 - Oct 13');
});
