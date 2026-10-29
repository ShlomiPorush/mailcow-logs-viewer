// The browser is in New York; the chart follows the app's zone, not the browser's
process.env.TZ = 'America/New_York';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../../frontend/alert-activity.js'), 'utf8');
const app = fs.readFileSync(path.join(__dirname, '../../frontend/app.js'), 'utf8');
const AT = new Date('2026-10-13T12:00:00Z');
// The time helpers the chart formats and groups with, in the app's zone
const utils = fs.readFileSync(path.join(__dirname, '../../frontend/utils.js'), 'utf8');
const zoneHelpers = utils.slice(utils.indexOf('function appTz()'), utils.indexOf('function formatSeconds('));
// The zoom steps the buttons take
const zoomSteps = utils.slice(utils.indexOf('function uiTimeZoomClamp('), utils.indexOf('function uiTimeZoom('));

// What GET /api/security-alerts/{id}/activity answers: quarters of an hour
// from the baseline period before the alert to two hours after it
function activity(alert, { baselineDays = 7, window = 15, around = {}, at = AT } = {}) {
    const buckets = [];
    for (let t = at.getTime() - baselineDays * 86400000; t < at.getTime() + 2 * 3600000; t += 15 * 60000) {
        buckets.push({ start: new Date(t).toISOString(), count: 1 });
    }
    return {
        alert: { id: 1, severity: 'critical', title: 'title', created_at: at.toISOString(), acknowledged: false, ...alert },
        bucket_minutes: 15, window_minutes: window, baseline_days: baselineDays, buckets,
        around: { total: 0, ...around },
    };
}

// browserLocale: the language of the browser, for formats that name no locale
function harness(appTimezone = 'UTC', { browserLocale } = {}) {
    const elements = {};
    const element = id => elements[id] || (elements[id] = { innerHTML: '', textContent: '', value: '',
        classList: { add() {}, remove() {}, toggle() {}, contains: () => false }, querySelector: () => null });
    const opened = [];
    const context = vm.createContext({
        document: { getElementById: element, addEventListener() {}, querySelector: () => null },
        escapeHtml: value => String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;'),
        escapeJsArg: value => value,
        // An entity value (utils.js) as its text: these tests read the figures, not the buttons
        uiEntity: (kind, value) => String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;'),
        uiCountLabel: (n, one, many) => `${n} ${n === 1 ? one : many}`,
        formatTime: value => value,
        authenticatedFetch: async () => ({ ok: false, status: 500 }),
        // The dashboard's helpers the window uses (app.js, utils.js)
        mailFlowSpan: (from, to) => `${new Date(from).toISOString()} to ${new Date(to).toISOString()}`,
        openMessagesRange: options => opened.push(options),
        uiTimeZoom: () => ({ destroy() {}, busy: () => false }),
        uiRedrawKeepingFocus: (container, draw) => draw(),
        uiTimeOverview: () => ({ destroy() {}, busy: () => false }),
        appTimezone,
    });
    if (browserLocale) {
        context.__locale = browserLocale;
        vm.runInContext(`{ const Format = Intl.DateTimeFormat;
            Intl.DateTimeFormat = function (locale, options) { return new Format(locale ?? __locale, options); }; }`, context);
    }
    vm.runInContext(zoneHelpers, context);
    vm.runInContext(zoomSteps, context);
    vm.runInContext(source, context);
    const run = expression => vm.runInContext(expression, context);
    return {
        render(data, range = '24h') {
            context.__data = data;
            run(`alertActivity = __data; alertActivityRange = '${range}'; alertActivityZoom = null; alertActivityPick = null; renderAlertActivity();`);
            // The content, and the footer's button to go on (Open in Messages or Security)
            return `${element('alert-activity-content').innerHTML}<foot>${element('alert-activity-open').innerHTML}</foot>`;
        },
        // The columns the range buttons show
        columns(data, range) {
            context.__data = data;
            return run(`alertActivityRange = '${range}'; alertActivityColumns(__data, alertActivityRangeSpan(__data))`);
        },
        run,
        opened,
        context,
    };
}

const figure = (html, label) => html.match(new RegExp(`<small>${label}</small><b[^>]*>([^<]*)</b>`))?.[1];

test('an SMTP block shows the mailbox sent mail, its limit and Open in Messages', () => {
    const html = harness().render(activity({ alert_type: 'smtp_abuse_block', subject: 'user@example.com', metric_value: 40, baseline_value: 30 },
        { window: 60, around: { total: 3, recipient_domains: [{ name: 'example.net', count: 3 }], results: [], subjects: [] } }));
    assert.match(html, /What it sent/);
    assert.equal(figure(html, "Sent in the alert's 60 minutes"), '40');
    assert.equal(figure(html, 'The limit, in 60 minutes'), '30');
    assert.doesNotMatch(html, /Failed logins|Open in Security|ui-aa-usual/);
    assert.match(html, /<foot><button [^>]*onclick="openAlertActivityMessages\(\)">Open in Messages<\/button><\/foot>/);
});

test('an SMTP block whose window is not known says so instead of using today\'s window', () => {
    const at = AT.getTime();
    const html = harness().render(activity({ alert_type: 'smtp_abuse_block', subject: 'user@example.com', metric_value: 40, baseline_value: 30 },
        { window: null, around: { total: 3, from: new Date(at - 3600000).toISOString(), to: new Date(at + 3600000).toISOString(),
            recipient_domains: [{ name: 'example.net', count: 3 }], results: [], subjects: [] } }));
    assert.equal(figure(html, 'Counted for the block'), '40');
    assert.equal(figure(html, 'The window'), 'Unknown');
    assert.equal(figure(html, 'The limit'), '30');
    assert.doesNotMatch(html, /null|NaN|an hour<\/small>|is-alert"/);
    assert.match(html, /from 60 minutes before it to an hour after/);
});

test('a spike or a burst whose window is not known says so instead of showing null', () => {
    const at = AT.getTime();
    const around = { total: 0, from: new Date(at - 3600000).toISOString(), to: new Date(at + 3600000).toISOString() };
    const spike = harness().render(activity({ alert_type: 'volume_spike', subject: 'user@example.com', metric_value: 40, baseline_value: 0.5 },
        { window: null, around: { ...around, recipient_domains: [], results: [], subjects: [] } }));
    assert.equal(figure(spike, 'Counted for the alert'), '40');
    assert.equal(figure(spike, 'The window'), 'Unknown');
    assert.equal(figure(spike, 'Usual, an hour \\(7 days\\)'), '0.50');
    assert.doesNotMatch(spike, /null|NaN|for the block|is-alert"/);
    const burst = harness().render(activity({ alert_type: 'auth_failure_burst', subject: 'user@example.com', metric_value: 12, baseline_value: 10 },
        { window: null, around: { ...around, addresses: [], countries: [], networks: [] } }));
    assert.equal(figure(burst, 'Counted for the alert'), '12');
    assert.equal(figure(burst, 'The window'), 'Unknown');
    assert.equal(figure(burst, 'The alert starts at'), '10');
    assert.doesNotMatch(burst, /null|NaN|is-alert"/);
    assert.match(burst, /from 60 minutes before it to an hour after/);
});

test('a volume spike keeps its usual rate and opens Messages on the mailbox that logged in', () => {
    const html = harness().render(activity({ alert_type: 'volume_spike', subject: 'user@example.com', metric_value: 40, baseline_value: 0.5 }));
    assert.equal(figure(html, 'Usual, an hour \\(7 days\\)'), '0.50');
    assert.match(html, /ui-aa-usual/);
    assert.match(html, /onclick="openAlertActivityMessages\(\)"/);
});

test('Open in Messages asks for the mailbox around the alert, or in the picked column', () => {
    const at = AT.getTime();
    const around = { total: 3, from: new Date(at - 3600000).toISOString(), to: new Date(at + 3600000).toISOString(), recipient_domains: [], results: [], subjects: [] };
    const h = harness();
    h.render(activity({ alert_type: 'volume_spike', subject: 'user@example.com', metric_value: 40, baseline_value: 0.5 }, { around }));
    h.run('openAlertActivityMessages()');
    assert.deepEqual(JSON.parse(JSON.stringify(h.opened.pop())), { start: around.from, endInclusive: around.to, user: 'user@example.com' });
    // A picked quarter of an hour: that quarter only, to its last microsecond
    const html = h.render(activity({ alert_type: 'volume_spike', subject: 'user@example.com', metric_value: 40, baseline_value: 0.5 }, { around }));
    assert.match(html, /aria-pressed="false"[^>]*onclick="pickAlertActivityColumn\(\d+\)"/);
    h.run(`pickAlertActivityColumn(${at})`);
    assert.match(h.run("document.getElementById('alert-activity-open').innerHTML"), />Open this time in Messages</);
    h.run('openAlertActivityMessages()');
    assert.deepEqual(JSON.parse(JSON.stringify(h.opened.pop())),
        { start: new Date(at).toISOString(), endInclusive: new Date(at + 15 * 60000 - 1).toISOString().replace('Z', '999Z'), user: 'user@example.com' });
});

test('a zoom snaps to the quarters, the end of the data is an edge, and the range\'s own span is no zoom', () => {
    const h = harness();
    const data = activity({ alert_type: 'volume_spike', baseline_value: 0.5 });
    const first = Date.parse(data.buckets[0].start);
    const last = Date.parse(data.buckets[data.buckets.length - 1].start);
    // The data ends seven minutes into its last quarter
    data.data_end = new Date(last + 7 * 60000).toISOString();
    h.render(data, '24h');
    const Q = 15 * 60000;
    h.context.__span = { from: first + 10 * Q + 4 * 60000, to: first + 18 * Q + 9 * 60000 };
    h.run('alertActivityShow(alertActivity, __span)');
    assert.deepEqual(JSON.parse(JSON.stringify(h.run('alertActivityZoom'))), { from: first + 10 * Q, to: first + 19 * Q });
    // Up to just short of the end of the data: the end itself, not the next quarter
    h.context.__span = { from: last - 8 * Q, to: last + 6 * 60000 };
    h.run('alertActivityShow(alertActivity, __span)');
    assert.equal(h.run('alertActivityZoom.to'), last + 7 * 60000);
    // The shortest span at the end of the data starts on a quarter: a whole hour of columns, not 55 minutes
    const end = last + 7 * 60000;
    h.context.__span = { from: end - 20 * 60000, to: end };
    h.run('alertActivityShow(alertActivity, __span)');
    const z = h.run('alertActivityZoom');
    assert.equal(z.to, end);
    assert.equal((z.from - first) % Q, 0, 'on a quarter');
    assert.ok(z.to - z.from >= 3600000, 'at least an hour');
    // The 24 hours start off the quarters; the strip shows them from the next quarter: one step back is a zoom
    h.run("alertActivityZoom = null; alertActivityRange = '24h'");
    const shown = JSON.parse(JSON.stringify(h.run('alertActivityShown(alertActivity, alertActivityRangeSpan(alertActivity))')));
    h.context.__span = { from: shown.from - Q, to: shown.to };
    h.run('alertActivityShow(alertActivity, __span)');
    assert.equal(h.run('alertActivityZoom && alertActivityZoom.from'), shown.from - Q, 'the first step back moves the start');
    // The pressed range's own span: no zoom
    h.run('__span = alertActivityRangeSpan(alertActivity); alertActivityShow(alertActivity, __span)');
    assert.equal(h.run('alertActivityZoom'), null);
});

test('the columns stop where the data ends, and a zoom shows a span inside it', () => {
    const h = harness();
    const data = activity({ alert_type: 'volume_spike', baseline_value: 0.5 });
    // The data ends five minutes into its last quarter (now, for a recent alert)
    const last = Date.parse(data.buckets[data.buckets.length - 1].start);
    // ...to the microsecond, as the server sends it
    data.data_end = new Date(last + 5 * 60000 + 123).toISOString().replace('Z', '456Z');
    data.buckets[data.buckets.length - 1].partial = true;
    const { cols } = h.columns(data, '24h');
    assert.equal(cols[cols.length - 1].end.getTime(), last + 5 * 60000 + 123);
    h.render(data, '24h');
    // Its messages in Messages: up to that exact moment, not a millisecond short of it
    data.alert.subject = 'user@example.com';
    data.around = { ...data.around, from: data.buckets[0].start, to: data.data_end };
    h.run(`pickAlertActivityColumn(${last})`);
    h.run('openAlertActivityMessages()');
    assert.equal(h.opened.pop().endInclusive, data.data_end);
    // An older alert: its data ends on a whole quarter, counted up to, not at, that end
    const old = activity({ alert_type: 'volume_spike', subject: 'user@example.com', baseline_value: 0.5 }, { around: data.around });
    const oldLast = Date.parse(old.buckets[old.buckets.length - 1].start);
    old.data_end = new Date(oldLast + 15 * 60000).toISOString().replace('Z', '000Z');
    h.render(old, '24h');
    h.run(`pickAlertActivityColumn(${oldLast})`);
    h.run('openAlertActivityMessages()');
    assert.equal(h.opened.pop().endInclusive, new Date(oldLast + 15 * 60000 - 1).toISOString().replace('Z', '999Z'));
    h.render(data, '24h');
    h.run('alertActivityStep("in")');
    const zoom = h.run('alertActivityZoom');
    assert.ok(zoom && zoom.to - zoom.from < 26 * 3600000 / 2 + 1, JSON.stringify(zoom));
    h.run('alertActivityStep("reset")');
    assert.equal(h.run('alertActivityZoom'), null);
});

test('From addresses counts every address, not only the six listed', () => {
    const addresses = Array.from({ length: 6 }, (_, i) => ({ name: `192.0.2.${i + 1}`, count: 2 }));
    const html = harness().render(activity({ alert_type: 'auth_failure_burst', subject: 'user@example.com', metric_value: 18, baseline_value: 10 },
        { around: { total: 18, addresses, address_count: 9, countries: [], networks: [] } }));
    assert.equal(figure(html, 'From addresses'), '9');
    assert.match(html, /<foot><button [^>]*>Open in Security<\/button><\/foot>/);
});

test('the long period covers the whole baseline, not always 7 days', () => {
    const h = harness();
    const long = h.columns(activity({ alert_type: 'volume_spike' }, { baselineDays: 14 }), '7d');
    const span = (long.cols[long.cols.length - 1].start - long.cols[0].start) / 86400000;
    assert.ok(span > 13.9, `the chart spans ${span} days`);
    // Two-hour columns keep a 14-day chart about as dense as a 7-day one
    assert.equal(long.minutes, 120);
    const week = h.columns(activity({ alert_type: 'volume_spike' }, { baselineDays: 7 }), '7d');
    assert.equal(week.minutes, 60);
    assert.ok((week.cols[week.cols.length - 1].start - week.cols[0].start) / 86400000 > 6.9);
    assert.equal(h.columns(activity({ alert_type: 'volume_spike' }, { baselineDays: 14 }), '24h').minutes, 15);
});

test('Messages can be opened filtered by the authenticated user', () => {
    const code = app.match(/function navigateToMessagesWithFilter\(options\) \{[\s\S]*?\n\}/)?.[0];
    assert.ok(code);
    const fields = {};
    const context = vm.createContext({
        document: { getElementById: id => fields[id] || (fields[id] = { value: 'old' }) },
        navigateTo() { return Promise.resolve(true); }, setTimeout() {},
    });
    vm.runInContext(code, context);
    vm.runInContext("navigateToMessagesWithFilter({ email: 'user@example.com', filterType: 'user' })", context);
    assert.equal(fields['messages-filter-user'].value, 'user@example.com');
    assert.equal(fields['messages-filter-sender'].value, '');
    assert.equal(fields['messages-filter-search'].value, '');
});

// ---------- times in the app's zone ----------

test('the alert mark and the time axis are in the app zone, the dates written as the rest of the app writes them', () => {
    // 12:00 UTC is 14:00 in Berlin (08:00 in New York); the last quarter starts at 13:45 UTC
    for (const browserLocale of [undefined, 'de-DE', 'he-IL']) {
        const html = harness('Europe/Berlin', { browserLocale }).render(activity({ alert_type: 'volume_spike', subject: 'user@example.com', metric_value: 40, baseline_value: 0.5 }));
        assert.match(html, /<span>Alert 14:00<\/span>/, browserLocale);
        // The date of formatTime in that browser language (13.10.2026, 10/13/2026), then the time
        const h = harness('Europe/Berlin', { browserLocale });
        const date = h.run("formatTime('2026-10-13T13:45:00Z').split(', ')[0]");
        assert.ok(html.includes(`<span>${date}, 15:45</span></div>`), `${browserLocale}: ${date}`);
    }
});

test('on the night the clocks go back, columns are spans of time that do not overlap, and the mark sits on the alert', () => {
    // 01:30 UTC on 2026-10-25 is the second 02:30 in Berlin; the alert's quarter holds 50 messages
    const at = new Date('2026-10-25T01:30:00Z');
    const data = activity({ alert_type: 'volume_spike', subject: 'user@example.com', metric_value: 50, baseline_value: 0.5 }, { baselineDays: 14, at });
    data.buckets.find(b => b.start === at.toISOString()).count = 50;
    const h = harness('Europe/Berlin');
    const { cols, minutes } = h.columns(data, '7d');
    assert.equal(minutes, 120);
    for (const [i, c] of cols.entries()) {
        assert.ok(c.start < c.end, `${c.start.toISOString()} has a length`);
        if (cols[i + 1]) assert.equal(c.end.getTime(), cols[i + 1].start.getTime(), `${c.start.toISOString()} ends where the next starts`);
        // A column counts exactly the quarters inside its span
        const inside = data.buckets.filter(b => Date.parse(b.start) >= c.start && Date.parse(b.start) < c.end);
        assert.equal(c.count, inside.reduce((n, b) => n + b.count, 0), c.start.toISOString());
    }
    // 02:00 CEST, 02:00 CET and 04:00 CET start columns: the two 02:00 are an hour apart
    const starts = cols.map(c => c.start.toISOString());
    for (const s of ['2026-10-24T22:00:00.000Z', '2026-10-25T00:00:00.000Z', '2026-10-25T01:00:00.000Z', '2026-10-25T03:00:00.000Z']) assert.ok(starts.includes(s), s);
    // The mark sits on the column that counted the alert's 50
    const html = h.render(data, '7d');
    const tips = [...html.matchAll(/<button type="button" class="ui-aa-col[^"]*"[^>]*? aria-label="([^"]*)"/g)].map(m => m[1]);
    const left = Number(html.match(/<div class="ui-aa-mark" style="left:([\d.]+)%"/)[1]);
    const marked = Math.floor(left / 100 * tips.length);
    // [01:00Z, 03:00Z) is 02:00 to 04:00 CET: seven quarters of 1 and the alert's 50
    // The date as formatDay writes it in this machine's language
    const oct25 = h.run("formatDay(Date.parse('2026-10-25T12:00:00Z'))");
    assert.ok(tips[marked].startsWith(`${oct25}, 02:00: 57 sent`), tips[marked]);
    assert.match(html, /<span>Alert 02:30<\/span>/);
});

test('hour columns start on whole hours of the app zone, also in a zone half an hour off', () => {
    const zoned = (zone, t) => Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone: zone, hour: 'numeric', minute: 'numeric', hourCycle: 'h23' })
        .formatToParts(t.getTime()).map(p => [p.type, Number(p.value)]));
    for (const [zone, at] of [['Asia/Kolkata', AT], ['Europe/Berlin', new Date('2026-11-10T12:00:00Z')]]) {
        const h = harness(zone);
        for (const days of [7, 14]) {
            const { cols, minutes } = h.columns(activity({ alert_type: 'volume_spike' }, { baselineDays: days, at }), '7d');
            for (const c of cols.slice(1)) {
                const p = zoned(zone, c.start);
                assert.equal(p.minute, 0, `${zone}, ${days} days: ${c.start.toISOString()}`);
                // Two-hour columns start on even hours there (in winter Berlin is UTC+1, so not on even UTC hours)
                assert.equal(p.hour % (minutes / 60), 0, `${zone}, ${days} days: ${c.start.toISOString()}`);
            }
        }
    }
});

// A steady 4 messages an hour (1 a quarter) and a usual rate of 4 an hour: in
// every column, whatever its real length, the bar sits on the usual level
const steadyCases = [
    // The clocks go forward: 00:00 CET to 04:00 CEST is three real hours
    ['Europe/Berlin', '2026-03-29T12:00:00Z', 14],
    // The data ends 2 hours after the alert, in the middle of a column
    ['Europe/Berlin', '2026-03-28T23:30:00Z', 14],
    ['Europe/Berlin', '2026-10-25T01:30:00Z', 14],
    // Half an hour off UTC, so the data starts in the middle of a column
    ['Asia/Kolkata', '2026-10-13T12:00:00Z', 14],
    // Five-hour columns do not divide a day: 20:00 to 00:00 is four hours
    ['Europe/Berlin', '2026-03-29T12:00:00Z', 35],
];

function steadyChart(zone, at, baselineDays) {
    const data = activity({ alert_type: 'volume_spike', subject: 'user@example.com', metric_value: 1, baseline_value: 4 },
        { baselineDays, at: new Date(at) });
    const h = harness(zone);
    return { data, h, ...h.columns(data, '7d') };
}

test('each column counts only what falls in its own span, from the first quarter to the last', () => {
    // The alert at 23:30 UTC on 2026-03-28: the last column runs from 00:00 CET to
    // the end of the data at 01:30 UTC (03:30 CEST), two and a half real hours
    const { cols: lastDay } = steadyChart(...steadyCases[1]);
    const last = lastDay[lastDay.length - 1];
    assert.equal(last.start.toISOString(), '2026-03-28T23:00:00.000Z');
    assert.equal(last.end.toISOString(), '2026-03-29T01:30:00.000Z');
    assert.equal(last.count, 10);
    for (const [zone, at, days] of steadyCases) {
        const { data, cols } = steadyChart(zone, at, days);
        const label = `${zone}, ${at}, ${days} days`;
        assert.equal(cols[0].start.toISOString(), new Date(data.buckets[0].start).toISOString(), `${label}: the first column starts with the data`);
        const lastQuarter = Date.parse(data.buckets[data.buckets.length - 1].start) + data.bucket_minutes * 60000;
        assert.equal(cols[cols.length - 1].end.getTime(), lastQuarter, `${label}: the last column ends with the data`);
        for (const [i, c] of cols.entries()) {
            if (cols[i + 1]) assert.equal(c.end.getTime(), cols[i + 1].start.getTime(), `${label}: ${c.start.toISOString()} ends where the next starts`);
            const inside = data.buckets.filter(b => Date.parse(b.start) >= c.start && Date.parse(b.start) < c.end);
            assert.equal(c.count, inside.reduce((n, b) => n + b.count, 0), `${label}: ${c.start.toISOString()}`);
        }
    }
});

const drawnColumns = html => [...html.matchAll(/<button type="button" class="ui-aa-col[^"]*"[^>]*? aria-label="([^"]*)"[^>]*><i style="height:([\d.]+)%"><\/i>(?:<b class="ui-aa-norm" style="bottom:([\d.]+)%"><\/b>)?<\/button>/g)];

test('normal traffic sits on the usual level of every column, also one a clock change made longer or shorter', () => {
    // 00:00 CET to 04:00 CEST on 2026-03-29 is three real hours: 12 messages are usual there, not a rise
    {
        const { data, h } = steadyChart(...steadyCases[0]);
        const html = h.render(data, '7d');
        const line = html.match(/<div class="ui-aa-usual" style="bottom:([\d.]+)%"/);
        const mar29 = h.run("formatDay(Date.parse('2026-03-29T12:00:00Z'))");
        const [tip, bar, own] = drawnColumns(html).find(c => c[1].startsWith(`${mar29}, 00:00`)).slice(1);
        assert.equal(tip, `${mar29}, 00:00: 12 sent in 3 hours`);
        assert.equal(Number(own ?? line?.[1]), Number(bar));
    }
    for (const [zone, at, days] of steadyCases) {
        const { data, h } = steadyChart(zone, at, days);
        const html = h.render(data, '7d');
        const line = html.match(/<div class="ui-aa-usual" style="bottom:([\d.]+)%"/);
        const cols = drawnColumns(html);
        assert.ok(cols.length > 100, `${zone}, ${at}: the columns are drawn`);
        for (const [, tip, bar, own] of cols) {
            const usual = Number(own ?? line?.[1]);
            assert.ok(Math.abs(Number(bar) - usual) < 1e-9, `${zone}, ${at}, ${days} days: "${tip}" is at ${bar}%, its usual level at ${usual}%`);
        }
    }
});
