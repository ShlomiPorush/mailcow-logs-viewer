const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../../frontend/dmarc.js'), 'utf8');
const start = source.indexOf('// The domain shown in the record window');
const end = source.indexOf('function dmarcDmarcRecord', start);
assert.ok(start > 0 && end > start);

function load() {
    const context = vm.createContext({
        escapeHtml: value => String(value),
        escapeJsArg: value => String(value),
        dmarcNum: value => String(value),
        dmarcTag: (tone, text) => `<span class="tag">${text}</span>`,
        dmarcCopyBlock: text => `<code>${text}</code>`,
    });
    vm.runInContext(source.slice(start, end), context);
    return context;
}

// A domain on p=none: one sender fails, the others pass on 95% or more
const domain = {
    name: 'example.com',
    record: { record: 'v=DMARC1; p=none; rua=mailto:dmarc@example.com', policy: 'none', settings: { aggregate_report_uris: ['mailto:dmarc@example.com'] } },
    groups: [{ passPct: 100, total: 700, pass: 700 }, { passPct: 0, total: 61, pass: 0 }],
};

test('picking a stricter policy explains it and gives its record', () => {
    const { dmarcPolicyPlan } = load();
    const plan = dmarcPolicyPlan(domain, 'reject');
    assert.match(plan, /Ready\./);
    assert.match(plan, /would have refused <b>61<\/b> messages/);
    assert.match(plan, /p=reject; rua=mailto:dmarc@example\.com/);
});

test('the policy in place needs no record', () => {
    const { dmarcPolicyPlan } = load();
    const plan = dmarcPolicyPlan(domain, 'none');
    assert.match(plan, /This is the policy in place\./);
    assert.doesNotMatch(plan, /<code>/);
});

test('the choice is a radio group with the picked policy checked', () => {
    const { dmarcPolicyChoice } = load();
    const html = dmarcPolicyChoice(domain, 'quarantine');
    assert.match(html, /role="radiogroup"/);
    assert.equal((html.match(/role="radio"/g) || []).length, 3);
    assert.match(html, /aria-checked="true" tabindex="0" data-policy="quarantine"/);
    assert.match(html, /data-policy="none"[^>]*>\s*<span class="ui-dm-pol-t"><span>None <span class="tag">Monitoring<\/span><\/span><span class="tag">Now<\/span>/);
    // Each policy in its colour: None red, Quarantine orange, Reject green
    assert.match(html, /class="ui-dm-fail"[^>]*data-policy="none"/);
    assert.match(html, /class="ui-dm-warn is-on"[^>]*data-policy="quarantine"/);
    assert.match(html, /class="ui-dm-ok"[^>]*data-policy="reject"/);
});

// A record with every optional tag the picker must keep
const tagged = {
    name: 'example.com',
    record: {
        record: 'v=DMARC1; p=none; sp=quarantine; pct=50; rua=mailto:dmarc@example.com,mailto:reports@example.net; ruf=mailto:forensic@example.com; adkim=s; aspf=r; fo=1',
        policy: 'none',
        settings: { aggregate_report_uris: ['mailto:dmarc@example.com', 'mailto:reports@example.net'] },
    },
    groups: [{ passPct: 100, total: 700, pass: 700 }],
};

test('the record to publish changes only the policy and keeps every other tag', () => {
    const { dmarcPolicyPlan } = load();
    assert.match(dmarcPolicyPlan(tagged, 'reject'),
        /<code>_dmarc\.example\.com {2}TXT {2}"v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:dmarc@example\.com,mailto:reports@example\.net; ruf=mailto:forensic@example\.com; adkim=s; aspf=r; fo=1"<\/code>/);
});

test('without a record the record to publish is a new one', () => {
    const { dmarcPolicyPlan } = load();
    const plan = dmarcPolicyPlan({ ...tagged, record: {} }, 'quarantine');
    assert.match(plan, /<code>_dmarc\.example\.com {2}TXT {2}"v=DMARC1; p=quarantine; rua=mailto:dmarc@example\.com"<\/code>/);
});

test('the forecast counts the messages that failed DMARC, from every sender', () => {
    const { dmarcPolicyPlan } = load();
    const plan = dmarcPolicyPlan({ ...domain, groups: [
        { passPct: 100, total: 700, pass: 700 }, { passPct: 98, total: 300, pass: 294 },
        { passPct: 40, total: 10, pass: 4 }, { passPct: 0, total: 61, pass: 0 },
    ] }, 'reject');
    // 6 + 6 + 61 failed; the 4 that passed in the weak group are not refused
    assert.match(plan, /would have refused <b>73<\/b> messages/);
});

test('no mail is not Ready', () => {
    const { dmarcPolicyPlan } = load();
    const plan = dmarcPolicyPlan({ ...domain, groups: [] }, 'quarantine');
    assert.doesNotMatch(plan, /Ready\./);
    assert.match(plan, /No mail in the last 30 days/);
});

test('no sender passing on most of its mail is not Ready', () => {
    const { dmarcPolicyPlan } = load();
    const plan = dmarcPolicyPlan({ ...domain, groups: [{ passPct: 10, total: 100, pass: 10 }] }, 'quarantine');
    assert.doesNotMatch(plan, /Ready\./);
    assert.match(plan, /Not yet\./);
});

test('the record window spells out the alignment', () => {
    const recordWindow = source.slice(start, source.indexOf('// SPF or DKIM for the domain'));
    const context = vm.createContext({
        escapeHtml: value => String(value),
        escapeJsArg: value => String(value),
        dmarcNum: value => String(value),
        dmarcPct: value => `${Math.round(value)}%`,
        dmarcTag: (tone, text) => `<span class="tag">${text}</span>`,
        dmarcCopyBlock: text => `<code>${text}</code>`,
    });
    vm.runInContext(recordWindow, context);
    const html = context.dmarcDmarcRecord({ ...tagged, spfPct: 100, dkimSeen: true,
        record: { ...tagged.record, settings: { spf_alignment: 'r', dkim_alignment: 's' } } });
    assert.match(html, /<dt>Alignment<\/dt><dd>SPF relaxed, DKIM strict<\/dd>/);
    const unset = context.dmarcDmarcRecord({ ...tagged, spfPct: 100, dkimSeen: true });
    assert.match(unset, /<dt>Alignment<\/dt><dd>SPF relaxed, DKIM relaxed<\/dd>/);
});
