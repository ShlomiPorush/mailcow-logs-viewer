// The Messages list shows how many recipients a message has, counted on the
// server (backend/app/services/message_recipients.py); the message dialog
// counts them here, in messageRecipients(). The shared cases in
// backend/tests/fixtures/recipient_count_cases.json run through both: this
// side runs the dialog's count, test_recipient_count_parity.py the server's.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const root = path.join(__dirname, '../..');
const fixture = JSON.parse(fs.readFileSync(path.join(root, 'backend/tests/fixtures/recipient_count_cases.json'), 'utf8'));
const QUEUE = '4F2A1B3C9D';

function dialog() {
    const element = () => ({ innerHTML: '', style: {}, dataset: {}, setAttribute() {}, getAttribute: () => null,
        classList: { add() {}, remove() {}, contains: () => false }, addEventListener() {}, querySelector: () => null, querySelectorAll: () => [] });
    const document = { body: { style: {} }, getElementById: element, querySelector: () => null, querySelectorAll: () => [], addEventListener() {} };
    const context = vm.createContext({ document, window: { disabledFeatures: [] }, console: { log() {}, error() {} },
        renderGeoIPInfo: () => '', appTimezone: 'UTC', setTimeout: () => 0, clearTimeout: () => {} });
    vm.runInContext(fs.readFileSync(path.join(root, 'frontend/utils.js'), 'utf8'), context);
    vm.runInContext(fs.readFileSync(path.join(root, 'frontend/message-details.js'), 'utf8'), context);
    return context;
}

// What the details answer holds for the case's own delivery
function details(c) {
    const at = s => new Date(Date.UTC(2026, 9, 28, 12, 0, s)).toISOString();
    const postfix = c.postfix.map(l => ({ time: at(l.at), program: 'postfix/lmtp', status: 'sent', recipient: l.to,
        message: fixture.line.replace('{queue}', QUEUE).replace('{to}', l.to).replace('{orig}', l.orig_to ? `orig_to=<${l.orig_to}>, ` : '') }));
    return { recipient: c.recipient, recipients: c.recipients, postfix, final_status: 'delivered' };
}

// The server leaves out a delivery to or from an excluded address: its own
// recipient, or an address a line of its queue names (such as orig_to)
const shown = (c, leg) => {
    const excluded = (c.excluded || []).map(a => a.toLowerCase());
    const named = [leg.recipient, ...leg.postfix.flatMap(l => [l.to, l.orig_to])].filter(Boolean).map(a => a.toLowerCase());
    return !named.some(a => excluded.includes(a));
};

test('the shared cases are there, multi-delivery ones included', () => {
    assert.ok(fixture.cases.length >= 13);
    assert.ok(fixture.cases.filter(c => (c.other_legs || []).length).length >= 4);
});

for (const c of fixture.cases) {
    test(`the dialog's header counts: ${c.name}`, () => {
        const md = dialog();
        // Each other delivery's recipients, as its own dialog lists them and the server sends them
        const related = (c.other_legs || []).filter(leg => shown(c, leg)).map((leg, i) => {
            const addresses = Array.from(md.messageRecipients(details(leg)), r => r.address);
            assert.deepEqual([...addresses].sort(), [...leg.resolved].sort());
            return { correlation_key: `leg-${i}`, final_status: 'delivered', first_seen: '2026-10-28T12:00:30Z', recipients: addresses };
        });
        const all = md.messageRecipientsAll({ ...details(c), related_deliveries: related });
        assert.equal(all.length, c.expected, Array.from(all, r => r.address).join(', '));
    });
}
