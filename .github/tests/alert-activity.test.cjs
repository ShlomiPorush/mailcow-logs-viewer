const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../../frontend/alert-activity.js'), 'utf8');
const app = fs.readFileSync(path.join(__dirname, '../../frontend/app.js'), 'utf8');
const AT = new Date('2026-10-13T12:00:00Z');

// What GET /api/security-alerts/{id}/activity answers: quarters of an hour
// from the baseline period before the alert to two hours after it
function activity(alert, { baselineDays = 7, window = 15, around = {} } = {}) {
    const buckets = [];
    for (let t = AT.getTime() - baselineDays * 86400000; t < AT.getTime() + 2 * 3600000; t += 15 * 60000) {
        buckets.push({ start: new Date(t).toISOString(), count: 1 });
    }
    return {
        alert: { id: 1, severity: 'critical', title: 'title', created_at: AT.toISOString(), acknowledged: false, ...alert },
        bucket_minutes: 15, window_minutes: window, baseline_days: baselineDays, buckets,
        around: { total: 0, ...around },
    };
}

function harness() {
    const elements = {};
    const element = id => elements[id] || (elements[id] = { innerHTML: '', textContent: '', classList: { add() {}, remove() {}, contains: () => false } });
    const context = vm.createContext({
        document: { getElementById: element, addEventListener() {} },
        escapeHtml: value => String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;'),
        escapeJsArg: value => value,
        uiCountLabel: (n, one, many) => `${n} ${n === 1 ? one : many}`,
        formatTime: value => value,
        authenticatedFetch: async () => ({ ok: false, status: 500 }),
    });
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
