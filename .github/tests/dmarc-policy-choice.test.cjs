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
    record: { record: 'v=DMARC1; p=none', policy: 'none', settings: { aggregate_report_uris: ['mailto:dmarc@example.com'] } },
    groups: [{ passPct: 100, total: 700 }, { passPct: 0, total: 61 }],
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
