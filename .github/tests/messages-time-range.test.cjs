// The browser is in New York and the app's zone is Europe/Berlin: a day on the
// Messages page is a day in the app's zone, never the browser's (nor UTC's)
process.env.TZ = 'America/New_York';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../../frontend/app.js'), 'utf8');
const utils = fs.readFileSync(path.join(__dirname, '../../frontend/utils.js'), 'utf8');
const zoneHelpers = utils.slice(utils.indexOf('function appTz()'), utils.indexOf('function formatSeconds('));
// A top-level function of app.js, by name, up to its closing brace
const extract = name => {
    const start = source.search(new RegExp(`^(async )?function ${name}\\(`, 'm'));
    assert.ok(start >= 0, `${name} must be present`);
    return source.slice(start, source.indexOf('\n}', start) + 2);
};

function harness(filters, appTimezone = 'Europe/Berlin') {
    const elements = {};
    const element = id => elements[id] || (elements[id] = { value: '', textContent: '', style: {}, classList: { add() {} } });
    const calls = { urls: [], rendered: 0, applied: 0, toasts: [], navigated: [] };
    const context = vm.createContext({
        URLSearchParams,
        appTimezone,
        currentFilters: { messages: filters },
        currentPage: { messages: 1 },
        lastDataCache: {},
        mailFlowSlots: [],
        mailFlowPicked: null,
        document: { getElementById: element },
        authenticatedFetch: async url => { calls.urls.push(url); return { ok: true, json: async () => ({ data: [] }) }; },
        hasDataChanged: () => true,
        renderMessagesData: () => { calls.rendered++; },
        showToast: (...args) => calls.toasts.push(args),
        setMessagesDatePresetActive() {},
        toggleMessagesTimePanel() {},
        applyMessagesFilters: () => { calls.applied++; },
        navigateTo: (...args) => calls.navigated.push(args),
        console: { log() {} },
        messagesOrder: 'desc',   // the list's order as it opens: newest first
        messagesGen: 0,   // the list's load generation (an older answer is dropped)
        messagesPaging: { loading: false },   // no next page on its way
    });
    vm.runInContext(zoneHelpers, context);
    vm.runInContext([
        extract('smartRefreshMessages'),
        extract('messagesQueryParams'),
        extract('applyMessagesCustomDateRange'),
        extract('messagesPresetStart'),
        extract('selectMessagesDatePreset'),
        extract('mailFlowHour'),
        extract('openMailFlowHourMessages'),
    ].join('\n'), context);
    return { calls, element, context, run: expression => vm.runInContext(expression, context) };
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

test('a custom range covers the chosen days in the app time zone', () => {
    const h = harness({});
    h.element('messages-date-range-start').value = '2026-10-13';
    h.element('messages-date-range-end').value = '2026-10-14';
    h.run('applyMessagesCustomDateRange()');
    assert.equal(h.element('messages-start-date').value, '2026-10-12T22:00:00.000Z');
    assert.equal(h.element('messages-end-date').value, '2026-10-14T21:59:59.999Z');
    assert.equal(h.element('messages-date-range-label').textContent, 'Oct 13 - Oct 14');
    assert.equal(h.calls.applied, 1);
});

test('a one-day custom range is that whole day', () => {
    const h = harness({});
    h.element('messages-date-range-start').value = '2026-10-13';
    h.element('messages-date-range-end').value = '2026-10-13';
    h.run('applyMessagesCustomDateRange()');
    // Read back in the app's zone: from 00:00 to 23:59 on the 13th
    const start = h.context.zonedParts(h.element('messages-start-date').value);
    const end = h.context.zonedParts(h.element('messages-end-date').value);
    assert.equal(start.day, 13);
    assert.equal(start.hour, 0);
    assert.equal(end.day, 13);
    assert.equal(end.hour, 23);
    assert.equal(end.minute, 59);
    assert.equal(h.element('messages-date-range-label').textContent, 'Oct 13 - Oct 13');
});

test('a one-day range on a daylight saving change is 23 or 25 hours long', () => {
    for (const [day, hours, from] of [['2026-03-29', 23, '2026-03-28T23:00:00.000Z'], ['2026-10-25', 25, '2026-10-24T22:00:00.000Z']]) {
        const h = harness({});
        h.element('messages-date-range-start').value = day;
        h.element('messages-date-range-end').value = day;
        h.run('applyMessagesCustomDateRange()');
        const start = h.element('messages-start-date').value;
        const end = h.element('messages-end-date').value;
        assert.equal(start, from);
        assert.equal((Date.parse(end) + 1 - Date.parse(start)) / 3600000, hours, day);
    }
});

test('Today starts at midnight in the app time zone', () => {
    const h = harness({});
    // 02:30 UTC on 2026-10-25 is 03:30 in Berlin, still the 24th in New York
    h.context.__now = new Date('2026-10-25T02:30:00Z');
    h.run("selectMessagesDatePreset('today', __now)");
    assert.equal(h.element('messages-start-date').value, '2026-10-24T22:00:00.000Z');
    assert.equal(h.element('messages-end-date').value, '2026-10-25T02:30:00.000Z');
    assert.equal(h.run("messagesPresetStart('today', __now)"), '2026-10-24T22:00:00.000Z');
});

test('Last 7, 30 and 90 Days are that many times 24 hours back, like Mailbox Stats, across a daylight saving change', () => {
    const h = harness({});
    // 14:00 CEST on 2026-03-29: 7 x 24 hours back is 13:00 CET on 2026-03-22, the
    // same window the server counts for Mailbox Stats and the Dashboard
    h.context.__now = new Date('2026-03-29T12:00:00Z');
    h.run("selectMessagesDatePreset('7days', __now)");
    assert.equal(h.element('messages-start-date').value, '2026-03-22T12:00:00.000Z');
    assert.equal(h.element('messages-end-date').value, '2026-03-29T12:00:00.000Z');
    // Back over the end of summer time, too
    h.context.__now = new Date('2026-11-01T12:00:00Z');
    assert.equal(h.run("messagesPresetStart('7days', __now)"), '2026-10-25T12:00:00.000Z');
    assert.equal(h.run("messagesPresetStart('30days', __now)"), '2026-10-02T12:00:00.000Z');
    assert.equal(h.run("messagesPresetStart('90days', __now)"), '2026-08-03T12:00:00.000Z');
    h.run("selectMessagesDatePreset('', __now)");
    assert.equal(h.element('messages-start-date').value, '');
    assert.equal(h.element('messages-end-date').value, '');
});

test('the Dashboard hour opens Messages on that hour, with its day in the app zone', () => {
    for (const zone of ['UTC', 'Europe/Berlin']) {
        const h = harness({}, zone);
        // 23:00 UTC on 2026-10-24 (01:00 on the 25th in Berlin, 19:00 on the 24th in New York)
        const t = Date.parse('2026-10-24T23:00:00Z');
        h.run(`mailFlowSlots = [{ t: ${t} }]; mailFlowPicked = ${t}; openMailFlowHourMessages()`);
        const day = zone === 'UTC' ? '2026-10-24' : '2026-10-25';
        assert.equal(h.element('messages-date-range-start').value, day, zone);
        assert.equal(h.element('messages-date-range-end').value, day, zone);
        assert.equal(h.element('messages-date-range-label').textContent,
            zone === 'UTC' ? 'Oct 24, 23:00 to 00:00' : 'Oct 25, 01:00 to 02:00', zone);
        assert.equal(h.element('messages-start-date').value, '2026-10-24T23:00:00.000Z');
        // Apply on the filled day covers the hour
        h.run('applyMessagesCustomDateRange()');
        assert.ok(Date.parse(h.element('messages-start-date').value) <= t, zone);
        assert.ok(Date.parse(h.element('messages-end-date').value) >= t + 3600000 - 1, zone);
    }
});
