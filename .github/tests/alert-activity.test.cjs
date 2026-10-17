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
    const element = id => elements[id] || (elements[id] = { innerHTML: '', textContent: '', classList: { add() {}, remove() {}, contains: () => false } });
    const context = vm.createContext({
        document: { getElementById: element, addEventListener() {} },
        escapeHtml: value => String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;'),
        escapeJsArg: value => value,
        uiCountLabel: (n, one, many) => `${n} ${n === 1 ? one : many}`,
        formatTime: value => value,
        authenticatedFetch: async () => ({ ok: false, status: 500 }),
        appTimezone,
    });
    if (browserLocale) {
        context.__locale = browserLocale;
        vm.runInContext(`{ const Format = Intl.DateTimeFormat;
            Intl.DateTimeFormat = function (locale, options) { return new Format(locale ?? __locale, options); }; }`, context);
    }
    vm.runInContext(zoneHelpers, context);
    vm.runInContext(source, context);
    const run = expression => vm.runInContext(expression, context);
    return {
        render(data, range = '24h') {
            context.__data = data;
            run(`alertActivity = __data; alertActivityRange = '${range}'; renderAlertActivity();`);
            return element('alert-activity-content').innerHTML;
        },
        columns(data, range) {
            context.__data = data;
            return run(`alertActivityRange = '${range}'; alertActivityColumns(__data)`);
        },
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
    assert.match(html, /navigateToMessagesWithFilter\(\{ email: 'user@example\.com', filterType: 'user' \}\)/);
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
    assert.match(html, /filterType: 'user'/);
});

test('From addresses counts every address, not only the six listed', () => {
    const addresses = Array.from({ length: 6 }, (_, i) => ({ name: `192.0.2.${i + 1}`, count: 2 }));
    const html = harness().render(activity({ alert_type: 'auth_failure_burst', subject: 'user@example.com', metric_value: 18, baseline_value: 10 },
        { around: { total: 18, addresses, address_count: 9, countries: [], networks: [] } }));
    assert.equal(figure(html, 'From addresses'), '9');
    assert.match(html, /Open in Security/);
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
        navigateTo() {}, setTimeout() {},
    });
    vm.runInContext(code, context);
    vm.runInContext("navigateToMessagesWithFilter({ email: 'user@example.com', filterType: 'user' })", context);
    assert.equal(fields['messages-filter-user'].value, 'user@example.com');
    assert.equal(fields['messages-filter-sender'].value, '');
    assert.equal(fields['messages-filter-search'].value, '');
});

// ---------- times in the app's zone ----------

test('the alert mark and the time axis are in the app zone, written like every other label in any browser language', () => {
    // 12:00 UTC is 14:00 in Berlin (08:00 in New York); the last quarter starts at 13:45 UTC
    for (const browserLocale of [undefined, 'de-DE', 'he-IL']) {
        const html = harness('Europe/Berlin', { browserLocale }).render(activity({ alert_type: 'volume_spike', subject: 'user@example.com', metric_value: 40, baseline_value: 0.5 }));
        assert.match(html, /<span>Alert 14:00<\/span>/, browserLocale);
        assert.match(html, /<div class="ui-aa-x"><span>[^<]*<\/span><span>Tue, Oct 13, 15:45<\/span><\/div>/, browserLocale);
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
    const tips = [...html.matchAll(/<span class="ui-aa-col[^"]*" data-tip="([^"]*)"/g)].map(m => m[1]);
    const left = Number(html.match(/<div class="ui-aa-mark" style="left:([\d.]+)%"/)[1]);
    const marked = Math.floor(left / 100 * tips.length);
    // [01:00Z, 03:00Z) is 02:00 to 04:00 CET: seven quarters of 1 and the alert's 50
    assert.match(tips[marked], /^Sun, Oct 25, 02:00: 57 sent/);
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
