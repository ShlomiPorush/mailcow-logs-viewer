// Needs attention and the bell show one short line per alert, built from its
// numbers; what to do is in its Show activity window. The stored detail (emails,
// channels) keeps the long text.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');

function stub() {
    const fn = function () { return proxy; };
    const proxy = new Proxy(fn, {
        get: (_, key) => (key === Symbol.toPrimitive ? () => '' : key === 'length' ? 0 : proxy),
        apply: () => proxy,
        construct: () => proxy,
    });
    return proxy;
}

function load() {
    const context = vm.createContext({
        document: stub(), window: { matchMedia: () => ({ matches: false }), addEventListener() {} }, localStorage: stub(),
        sessionStorage: stub(), navigator: stub(), location: stub(), console: { log() {}, error() {}, warn() {} },
        setTimeout() {}, setInterval() {}, clearTimeout() {}, URLSearchParams, Intl,
    });
    for (const file of ['utils.js', 'app.js', 'alert-activity.js']) vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    return context;
}

const spikeDetail = 'Mailbox user@example.com sent 34 messages in the last 15 minutes (136/hour), about 136.0x its baseline of 1.0/hour over the past 7 days.\n\nThis can indicate a compromised mailbox sending spam.';

test('a volume spike says how much was sent, in which window, and how many times usual', () => {
    const c = load();
    const line = a => c.attentionAlertLine(a);
    assert.equal(line({ alert_type: 'volume_spike', metric_value: 34, baseline_value: 1, detail: spikeDetail }), 'Sent 34 messages in 15 minutes, about 136 times usual.');
    // No usual rate: no ratio is made up
    assert.equal(line({ alert_type: 'volume_spike', metric_value: 34, baseline_value: 0, detail: spikeDetail }), 'Sent 34 messages in 15 minutes.');
    // A window the detail does not name is left out, not taken from today's setting
    assert.equal(line({ alert_type: 'volume_spike', metric_value: 1, baseline_value: 1, detail: 'Something else.' }), 'Sent 1 message.');
    assert.equal(line({ alert_type: 'volume_spike', metric_value: null, detail: spikeDetail }), 'Unusual sending was detected.');
});

test('a sign-in burst and a sending block say what happened in one line', () => {
    const c = load();
    assert.equal(c.attentionAlertLine({ alert_type: 'auth_failure_burst', metric_value: 62, baseline_value: 20,
        detail: "62 authentication failures for 'user@example.com' from 4 source IP(s) in the last 15 minutes.\n\nThis can indicate an attack." }),
    '62 failed sign-ins in 15 minutes.');
    const block = 'SMTP sending was disabled for user@example.com after 140 outbound messages in 60 minutes (limit: 100).\n\nIMAP access is unchanged. App passwords revoked: 0.\nReview the mailbox.';
    assert.equal(c.attentionAlertLine({ alert_type: 'smtp_abuse_block', metric_value: 140, baseline_value: 100, detail: block }), 'Sending stopped after 140 messages in 60 minutes.');
    assert.match(c.attentionAlertAdvice({ alert_type: 'smtp_abuse_block', detail: block }), /Outgoing spam\.$/);
    assert.match(c.attentionAlertAdvice({ alert_type: 'smtp_abuse_block', detail: block.replace('revoked: 0', 'revoked: 2') }), /new app passwords\.$/);
    // A kind this version does not know has no activity: the first line it was stored with
    assert.equal(c.attentionAlertLine({ alert_type: 'something_new', detail: 'x\n\nmore' }), 'x');
});

// The alerts that used to go only by email (stored_alerts.py) show the line they were
// stored with, open their page instead of activity, and are dismissed in their own area
const STORED = [
    ['dns_change', 'domains', 'DNS changes detected for example.com', 'SPF and DKIM changed.', 'Open domain'],
    ['dmarc_import_failed', 'dmarc', 'DMARC & TLS report import errors', 'Could not fully import 3 report emails.', 'Open fetch history'],
    ['protection_breach', 'security', 'Possible stolen password: user@example.com', 'An unusual sign-in may mean someone else has access.', 'Open Security'],
    ['protection_ban_failed', 'security', 'Protection rules could not ban addresses', 'Could not ban 2 addresses or networks.', 'Open Security'],
];

test('an alert that opens its page shows its stored line, its Open button and Dismiss for its area', () => {
    const c = load();
    for (const [type, area, title, line, open] of STORED) {
        vm.runInContext(`attention.alerts.list = ${JSON.stringify([{ id: 7, alert_type: type, severity: 'warning', title, detail: line, created_at: '2026-11-10T10:00:00Z' }])}`, c);
        for (const where of ['dashboard', 'bell']) {
            const html = c.attentionAlertRows(where);
            assert.match(html, new RegExp(`<p>${line.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}</p>`), type);
            assert.match(html, new RegExp(`onclick="openStoredAlert\\(7, '${where === 'bell' ? 'bell' : 'page'}'\\)" class="ui-btn ui-btn-sm">${open}</button>`), type);
            assert.doesNotMatch(html, /Show activity|openAlertActivity/, type);
            assert.match(html, new RegExp(`onclick="acknowledgeSecurityAlert\\(7\\)"[^>]*data-acts="alerts ${area}"`), type);
            assert.ok(!/[\u2010-\u2015\u2212]/.test(line + title + open), `${type}: no dash characters`);
        }
    }
    // Activity stays with the alerts that have it
    vm.runInContext(`attention.alerts.list = ${JSON.stringify([{ id: 8, alert_type: 'auth_failure_burst', severity: 'warning', title: 't', detail: '', created_at: '2026-11-10T10:00:00Z' }])}`, c);
    assert.match(c.attentionAlertRows('dashboard'), /openAlertActivity\(8\)[\s\S]*data-acts="alerts security"/);
    // A kind this version does not know: no way on, and only an admin dismisses it
    vm.runInContext(`attention.alerts.list = ${JSON.stringify([{ id: 9, alert_type: 'something_new', severity: 'warning', title: 't', detail: 'x', created_at: '2026-11-10T10:00:00Z' }])}`, c);
    const unknown = c.attentionAlertRows('dashboard');
    assert.doesNotMatch(unknown, /ui-alert-go|openAlertActivity|openStoredAlert/);
    assert.match(unknown, /data-acts="alerts admin"/);
});

test('the row shows the short line, and the activity window the advice', () => {
    const c = load();
    vm.runInContext(`attention.alerts.list = [{ id: 1, alert_type: 'volume_spike', severity: 'critical', title: 'Outbound volume spike: user@example.com',
        metric_value: 34, baseline_value: 1, detail: ${JSON.stringify(spikeDetail)}, created_at: '2026-11-10T10:00:00Z' }]`, c);
    const html = c.attentionAlertRows('dashboard');
    assert.match(html, /<p>Sent 34 messages in 15 minutes, about 136 times usual\.<\/p>/);
    assert.doesNotMatch(html, /compromised/);
    const activity = fs.readFileSync(path.join(frontend, 'alert-activity.js'), 'utf8');
    assert.match(activity, /<p class="ui-aa-advice">\$\{escapeHtml\(attentionAlertAdvice\(a\)\)\}<\/p>/);
});

test('the check rows keep to one short line', () => {
    const c = load();
    const one = (key, data) => c.attentionCheckItems(key, data)[0].detail;
    assert.equal(one('blocklist', { status: 'listed', hosts: [{ hostname: 'mail.example.com', status: 'listed', listed_count: 1, total_blacklists: 1 }] }), 'On 1 of 1 list; some mail may bounce.');
    assert.equal(one('blocklist', { status: 'listed', hosts: [{ hostname: 'a.example.com', status: 'listed' }, { hostname: 'b.example.com', status: 'listed' }] }), 'Mail to some providers may bounce.');
    const insight = (over) => ({ domain: 'example.com', pass_rate: 81.6, new_sources: [], recommendations: [{ type: 'low_pass_rate' }], ...over });
    assert.equal(one('dmarc', { insights: [insight()] }), 'Only 82% passed mail identity checks.');
    assert.equal(one('dmarc', { insights: [insight(), insight({ domain: 'example.org' })] }), 'example.com: Only 82% passed mail identity checks.');
    // The reason the row is there, not whatever recommendation comes first
    assert.equal(one('dmarc', { insights: [insight({ recommendations: [{ type: 'monitor' }], new_sources: [{}] })] }), 'Mail from a new source failed identity checks.');
    assert.equal(one('dmarc', { insights: [insight({ recommendations: [{ type: 'tighten_policy' }] })] }), 'Reports suggest stronger protection is safe.');
    for (const [key, data] of [['connection', { connected: false }], ['fail2ban', { legacy_entries: [{ list: 'blacklist', network: '2001:db8::/32', address: '2001:db8::1', entry: '2001:db8::/32' }] }]]) {
        assert.ok(one(key, data).length <= 60, key);
    }
});

test('a DMARC line names its domain only while it fits, and blocklist counts must make sense', () => {
    const c = load();
    const one = (key, data) => c.attentionCheckItems(key, data)[0].detail;
    const line = 'Only 82% passed mail identity checks.';
    const named = length => ({ domain: 'a'.repeat(length - line.length - 2 - '.example.com'.length) + '.example.com', pass_rate: 82, new_sources: [], recommendations: [{ type: 'low_pass_rate' }] });
    const two = first => ({ insights: [first, { ...first, domain: 'example.org' }] });
    assert.equal(one('dmarc', two(named(60))).length, 60);
    assert.equal(one('dmarc', two(named(61))), 'Review mail identity checks and protection settings.');
    const host = over => ({ status: 'listed', hosts: [{ hostname: 'mail.example.com', status: 'listed', listed_count: 1, total_blacklists: 3, ...over }] });
    assert.equal(one('blocklist', host({})), 'On 1 of 3 lists; some mail may bounce.');
    for (const bad of [{ listed_count: null }, { listed_count: -1 }, { listed_count: 1.5 }, { listed_count: 4 }, { listed_count: '' }]) {
        assert.equal(one('blocklist', host(bad)), 'Mail to some providers may bounce.', JSON.stringify(bad));
    }
});
