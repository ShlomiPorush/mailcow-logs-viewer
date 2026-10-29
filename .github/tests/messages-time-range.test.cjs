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
    const calls = { urls: [], rendered: 0, applied: 0, toasts: [], navigated: [], newShown: 0, showNew: [], facets: 0, loaded: [] };
    let context;
    context = vm.createContext({
        __edge: true,   // the list shows the edge where new mail lands
        __newCount: 0,   // what /api/messages/new answers
        messagesAtNewEdge: () => context.__edge,
        messagesNew: { watermark: 41, count: 0 },
        renderMessagesNew: () => { calls.newShown++; },
        messagesShowNew: options => { calls.showNew.push(options); },
        MESSAGES_ROLLING_PRESETS: ['today', '7days', '30days', '90days'],
        messagesExact: null,   // no entity card set whole values
        URLSearchParams,
        appTimezone,
        currentFilters: { messages: filters },
        currentPage: { messages: 1 },
        lastDataCache: { messages: { data: [{ correlation_key: 'shown' }], total: 1 } },   // a list is shown
        __held: false,   // text in the list is selected
        uiTextHeld: () => context.__held,
        uiKeepFocus: (container, key, draw) => draw(),
        PAGE_REFRESH_TIMEOUT: 20000,
        loadMessages: options => { calls.loaded.push(options); },
        dashFlow: { data: null, pick: null, zoom: null },   // the dashboard's mail flow
        document: { getElementById: element },
        authenticatedFetch: async url => {
            calls.urls.push(url);
            const answer = url.startsWith('/api/messages/new') ? { count: context.__newCount, watermark: 99 } : { data: [] };
            return { ok: true, json: async () => answer };
        },
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
        messagesPaging: { loading: false, page: 1 },   // the first page shown, no next page on its way
        messagesFullLoad: false,   // no full load on its way
        messagesRefreshing: false,
        messagesFetch: url => context.authenticatedFetch(url),   // the list's requests, as the page makes them
        messagesNewGeneration: () => ++context.messagesGen,
        loadMessageFacets: () => { calls.facets++; },
        messagesNoId: false,   // the whole list, not the messages without a Message-ID
        refreshMessagesNoId: () => {},
    });
    vm.runInContext(zoneHelpers, context);
    vm.runInContext([
        source.match(/^const MESSAGES_FILTER_KEYS = .*$/m)[0],
        extract('smartRefreshMessages'),
        extract('messagesQueryParams'),
        extract('messagesFilterParams'),
        extract('messagesSameAsShown'),
        extract('messagesRangeFilters'),
        extract('applyMessagesCustomDateRange'),
        extract('messagesPresetStart'),
        extract('messagesShowDatePreset'),
        extract('selectMessagesDatePreset'),
        extract('messagesShowRange'),
        extract('mailFlowHour'),
        extract('mailFlowSpan'),
        extract('openMessagesRange'),
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

const query = url => new URL(url, 'http://viewer.test');

test('at its top the auto refresh redraws a searched list too', async () => {
    const h = harness({ search: 'invoice', status: 'bounced' });
    await h.run('smartRefreshMessages()');
    assert.equal(h.calls.urls.length, 1);
    const params = query(h.calls.urls[0]).searchParams;
    assert.equal(query(h.calls.urls[0]).pathname, '/api/messages');
    assert.equal(params.get('search'), 'invoice');
    assert.equal(params.get('status'), 'bounced');
    assert.equal(h.calls.rendered, 1);
});

test('scrolled away, the list stays and the new mail is counted from its watermark', async () => {
    const h = harness({ search: 'invoice' });
    h.context.__edge = false;
    h.context.__newCount = 3;
    await h.run('smartRefreshMessages()');
    assert.equal(h.calls.urls.length, 1);
    const url = query(h.calls.urls[0]);
    assert.equal(url.pathname, '/api/messages/new');
    assert.equal(url.searchParams.get('after_id'), '41');
    assert.equal(url.searchParams.get('search'), 'invoice');
    assert.equal(h.calls.rendered, 0);
    assert.equal(h.run('messagesNew.count'), 3);
    assert.equal(h.calls.newShown, 1);
});

test('an answer that comes after the user scrolled away redraws nothing', async () => {
    const h = harness({});
    h.context.authenticatedFetch = async url => { h.calls.urls.push(url); h.context.__edge = false; return { ok: true, json: async () => ({ data: [] }) }; };
    await h.run('smartRefreshMessages()');
    assert.equal(h.calls.rendered, 0);
});

test('a list without a watermark, or loading, asks for nothing', async () => {
    const h = harness({});
    h.context.__edge = false;
    h.run('messagesNew.watermark = null');
    await h.run('smartRefreshMessages()');
    h.run('messagesNew.watermark = 41; messagesPaging.loading = true');
    await h.run('smartRefreshMessages()');
    assert.equal(h.calls.urls.length, 0);
});

test('oldest first, new mail comes by paging until the whole list is loaded', async () => {
    const h = harness({});
    h.run("messagesOrder = 'asc'; messagesPaging.cursor = '2026-10-13T07:00:00|5'");
    h.context.__edge = false;
    await h.run('smartRefreshMessages()');
    assert.equal(h.calls.urls.length, 0);
});

test('oldest first, at the end of the whole list the new mail is taken in quietly', async () => {
    const h = harness({});
    h.run("messagesOrder = 'asc'; messagesPaging.cursor = null");
    h.context.__newCount = 2;
    await h.run('smartRefreshMessages()');
    assert.equal(query(h.calls.urls[0]).pathname, '/api/messages/new');
    assert.deepEqual(JSON.parse(JSON.stringify(h.calls.showNew)), [{ quiet: true }]);
    // Further up, it is offered instead
    const away = harness({});
    away.run("messagesOrder = 'asc'; messagesPaging.cursor = null");
    away.context.__edge = false;
    away.context.__newCount = 2;
    await away.run('smartRefreshMessages()');
    assert.equal(away.calls.showNew.length, 0);
    assert.equal(away.calls.newShown, 1);
});

test('a time preset reads its period up to now at every request', async () => {
    // Chosen yesterday: Today is now today, up to now
    const h = harness({ date_range: 'today', start_date: '2026-10-23T22:00:00.000Z', end_date: '2026-10-24T09:00:00.000Z' });
    await h.run('smartRefreshMessages()');
    const params = query(h.calls.urls[0]).searchParams;
    assert.equal(params.get('start_date'), h.run('messagesPresetStart("today")'));
    // Up to now: no end at all, so nothing stored meanwhile falls outside it
    assert.equal(params.get('end_date'), null);
    // A custom range stays as it was chosen
    const fixed = harness({ date_range: 'custom', start_date: '2026-10-13T07:00:00.000Z', end_date: '2026-10-14T06:59:59.999Z' });
    fixed.context.__edge = false;
    await fixed.run('smartRefreshMessages()');
    assert.equal(query(fixed.calls.urls[0]).searchParams.get('end_date'), '2026-10-14T06:59:59.999Z');
});

test('a custom range covers the chosen days in the app time zone', () => {
    const h = harness({});
    h.run("appDateFormat = 'DD.MM.YYYY'");
    h.element('messages-date-range-start').value = '2026-10-13';
    h.element('messages-date-range-end').value = '2026-10-14';
    h.run('applyMessagesCustomDateRange()');
    assert.equal(h.element('messages-start-date').value, '2026-10-12T22:00:00.000Z');
    assert.equal(h.element('messages-end-date').value, '2026-10-14T21:59:59.999Z');
    assert.equal(h.element('messages-date-range-label').textContent, '13.10.2026 - 14.10.2026');
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
    assert.equal(h.element('messages-date-range-label').textContent, `${h.run("formatDayKey('2026-10-13')")} - ${h.run("formatDayKey('2026-10-13')")}`);
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
        // The bar as /api/stats/flow sends it: its start and its last microsecond
        h.run(`dashFlow.data = { buckets: [{ start: '2026-10-24T23:00:00.000000Z', end_inclusive: '2026-10-24T23:59:59.999999Z' }] };
            dashFlow.pick = ${t}; openMailFlowHourMessages()`);
        const day = zone === 'UTC' ? '2026-10-24' : '2026-10-25';
        assert.equal(h.element('messages-date-range-start').value, day, zone);
        assert.equal(h.element('messages-date-range-end').value, day, zone);
        assert.equal(h.element('messages-date-range-label').textContent,
            `${h.run(`formatDay(Date.parse('${day}T12:00:00Z'))`)}, ${zone === 'UTC' ? '23:00 to 00:00' : '01:00 to 02:00'}`, zone);
        assert.equal(h.element('messages-start-date').value, '2026-10-24T23:00:00.000000Z');
        assert.equal(h.element('messages-end-date').value, '2026-10-24T23:59:59.999999Z');
        // Apply on the filled day covers the hour
        h.run('applyMessagesCustomDateRange()');
        assert.ok(Date.parse(h.element('messages-start-date').value) <= t, zone);
        assert.ok(Date.parse(h.element('messages-end-date').value) >= t + 3600000 - 1, zone);
    }
});

test('the Dashboard chart with no bar picked opens Messages on the span shown', () => {
    const h = harness({}, 'Europe/Berlin');
    h.run(`dashFlow.data = { buckets: [], from: '2026-10-21T04:00:00.000000Z', to_inclusive: '2026-10-21T09:59:59.999999Z' };
        dashFlow.zoom = { from: 1, to: 2 }; dashFlow.pick = null; openMailFlowHourMessages()`);
    assert.equal(h.element('messages-start-date').value, '2026-10-21T04:00:00.000000Z');
    assert.equal(h.element('messages-end-date').value, '2026-10-21T09:59:59.999999Z');
    assert.equal(h.element('messages-date-range-label').textContent, `${h.run("formatDay(Date.parse('2026-10-21T12:00:00Z'))")}, 06:00 to 12:00`);
    assert.deepEqual(h.calls.navigated, [['messages']]);
    // Not zoomed and nothing picked: the whole period shown
    const plain = harness({}, 'UTC');
    plain.run(`dashFlow.data = { buckets: [], from: '2026-10-20T12:00:00.000000Z', to_inclusive: '2026-10-21T11:59:59.999999Z' }; openMailFlowHourMessages()`);
    assert.equal(plain.element('messages-start-date').value, '2026-10-20T12:00:00.000000Z');
    assert.equal(plain.element('messages-end-date').value, '2026-10-21T11:59:59.999999Z');
    assert.deepEqual(plain.calls.navigated, [['messages']]);
});

test('text selected in the list holds the redraw: the new mail is counted instead', async () => {
    const h = harness({});
    h.context.__held = true;
    h.context.__newCount = 1;
    await h.run('smartRefreshMessages()');
    assert.equal(query(h.calls.urls[0]).pathname, '/api/messages/new');
    assert.equal(h.calls.rendered, 0);
    assert.equal(h.calls.newShown, 1);
});

test('the counts beside the list are read on every refresh, also when the list did not change', async () => {
    const h = harness({ status: 'bounced' });
    h.run('lastDataCache.messages = { data: [] }');
    h.context.authenticatedFetch = async url => { h.calls.urls.push(url); return { ok: true, json: async () => ({ data: [], watermark: 77 }) }; };
    await h.run('smartRefreshMessages()');
    assert.equal(h.calls.rendered, 0);
    assert.equal(h.calls.facets, 1);
    // Nothing new matched up to 77: later counts start from there
    assert.equal(h.run('messagesNew.watermark'), 77);
});

test('a list that could not load is loaded again by the refresh', async () => {
    const h = harness({});
    h.run('lastDataCache.messages = null');
    await h.run('smartRefreshMessages()');
    assert.equal(h.calls.loaded.length, 1);
    assert.equal(h.calls.urls.length, 0);
});

test('the next pages of a list hold only what its first page held', () => {
    const h = harness({});
    const params = h.run("messagesQueryParams('2026-10-13T07:00:00|5', 50, 41)");
    assert.equal(params.get('upto_id'), '41');
    assert.equal(h.run('messagesQueryParams(null, 50, 41)').get('upto_id'), null);
});
