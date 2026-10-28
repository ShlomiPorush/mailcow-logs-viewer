// A Messages row names its first recipient and, when the message has more,
// a quiet "+N" beside it, like a mail client; a screen reader hears "and N
// more recipients". Runs the real row (app.js renderMessageRow) and the global
// search's message row in a real DOM (jsdom) with axe-core. jsdom is installed
// by CI outside the repository; set A11Y_MODULES to its node_modules:
//   npm install --no-save --prefix /tmp/a11y jsdom axe-core
//   A11Y_MODULES=/tmp/a11y/node_modules node --test .github/tests/messages-recipient-count.a11y.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));
const axeSource = fs.readFileSync(path.join(modules, 'axe-core', 'axe.min.js'), 'utf8');

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');

const message = (key, recipient_count) => ({ correlation_key: key, message_id: `<${key}@example.com>`, sender: 's@example.com',
    recipient: 'r@example.net', recipient_count, subject: 'Weekly notes', direction: 'inbound', final_status: 'delivered',
    is_complete: true, first_seen: '2026-10-24T10:00:00Z' });

function page() {
    const dom = new JSDOM(`<!doctype html><html lang="en"><head><title>t</title></head><body><main><div id="messages-logs"></div><div id="gs"></div></main></body></html>`,
        { runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/messages' });
    const w = dom.window;
    w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    const run = source => {
        const script = w.document.createElement('script');
        script.textContent = source;
        w.document.head.appendChild(script);
    };
    [read('utils.js'), read('router.js'), read('app.js'), read('search.js')].forEach(run);
    run('checkAuthentication = async () => false;');
    return { w, run, $: s => w.document.querySelector(s) };
}

// What a screen reader reads out of an element: its text without aria-hidden parts
function spoken(node) {
    if (node.nodeType === 3) return node.textContent;
    if (node.nodeType !== 1 || node.getAttribute('aria-hidden') === 'true') return '';
    return [...node.childNodes].map(spoken).join('');
}

test('one recipient: the row names it, with no count', () => {
    const p = page();
    p.$('#messages-logs').innerHTML = p.w.renderMessageRow(message('one', 1));
    assert.equal(p.$('.ui-msg-to').textContent, 'to r@example.net');
    assert.equal(p.$('.ui-rcpt-more'), null);
    // An answer without the count (an older server) shows the row as before
    p.$('#messages-logs').innerHTML = p.w.renderMessageRow(message('old'));
    assert.equal(p.$('.ui-rcpt-more'), null);
});

test('a message delivered twice is one email: its row counts recipients, not deliveries', () => {
    const p = page();
    p.$('#messages-logs').innerHTML = p.w.renderMessageRow({ ...message('twice', 2), deliveries: 2 });
    assert.doesNotMatch(p.$('.ui-msg-item').textContent, /Deliveries/);
    assert.equal(p.$('.ui-rcpt-more [aria-hidden="true"]').textContent, '+1');
});

test('three recipients: "+2" beside the address, read as "and 2 more recipients"', async () => {
    const p = page();
    p.$('#messages-logs').innerHTML = p.w.renderMessageRow(message('one', 1)) + p.w.renderMessageRow(message('three', 3));
    const row = p.$('.ui-msg-item[data-key="three"]');
    const tag = row.querySelector('.ui-msg-to > .ui-rcpt-more');
    assert.ok(tag, 'the count sits with the address');
    assert.equal(tag.previousElementSibling.className, 'ui-ent', 'right after the address');
    assert.equal(tag.querySelector('[aria-hidden="true"]').textContent, '+2');
    assert.equal(tag.getAttribute('title'), 'and 2 more recipients');
    assert.match(spoken(row.querySelector('.ui-msg-to')).replace(/\s+/g, ' '), /^to r@example\.net and 2 more recipients$/);
    assert.ok(!spoken(row).includes('+2'), 'the "+2" itself is not read out');

    p.run(axeSource);
    const result = await p.w.axe.run(p.w.document, { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } });
    assert.deepEqual(Array.from(result.violations, v => `${v.id}: ${v.nodes.map(n => n.target).join(', ')}`), []);
});

test('a long address loses the end of its local part, never its domain', () => {
    const p = page();
    const long = { ...message('long', 3), recipient: 'finance-department-notifications@example.net' };
    p.$('#messages-logs').innerHTML = p.w.renderMessageRow(long);
    // jsdom has no layout: the line is as wide as room characters, its shown text 8px a character
    const line = p.$('.ui-msg-to');
    const shown = () => line.textContent.length - [...line.querySelectorAll('.ui-sr-only')].reduce((n, el) => n + el.textContent.length, 0);
    let room = 34;
    Object.defineProperty(line, 'clientWidth', { get: () => room * 8 });
    Object.defineProperty(line, 'scrollWidth', { get: () => shown() * 8 });
    p.w.uiFitAddresses([line]);
    const btn = line.querySelector('.ui-ent-btn');
    assert.match(btn.textContent, /^finance-[a-z-]*[a-z]…@example\.net$/);
    assert.ok(shown() <= room && shown() >= room - 2, 'as much as fits');
    assert.equal(line.querySelector('.ui-rcpt-more [aria-hidden="true"]').textContent, '+2', 'the count stays whole');
    // The button opens, copies and is named by the whole address
    assert.equal(btn.dataset.entityValue, long.recipient);
    assert.equal(line.querySelector('.ui-ent-copy').dataset.entityCopy, long.recipient);
    assert.equal(btn.getAttribute('aria-label'), long.recipient);
    assert.equal(btn.title, long.recipient);
    // Wide enough again: the whole address, and the button's own name and tooltip
    room = 80;
    p.w.uiFitAddresses([line]);
    assert.equal(btn.textContent, long.recipient);
    assert.equal(btn.getAttribute('aria-label'), null);
    assert.equal(btn.title, 'Open the card of this address');
    // Room for the domain and no more: no letter of the local part, the domain whole
    room = 16 + 2;   // "to ", the ellipsis and "@example.net", "+2"
    p.w.uiFitAddresses([line]);
    assert.equal(btn.textContent, '…@example.net');
    assert.ok(!line.classList.contains('is-over'));
    // A domain longer than the line: the domain itself ends in an ellipsis (CSS)
    room = 12;
    p.w.uiFitAddresses([line]);
    assert.ok(line.classList.contains('is-over'));
    assert.ok(line.querySelector('.ui-fit-dom').textContent === '@example.net', 'the domain is never cut in the text');
});

test('a cut never splits a character', () => {
    const p = page();
    // A letter outside the Basic Multilingual Plane is two UTF-16 units
    const odd = { ...message('odd', 1), recipient: '\u{10400}\u{10401}\u{10402}\u{10403}\u{10404}\u{10405}@example.net' };
    p.$('#messages-logs').innerHTML = p.w.renderMessageRow(odd);
    const line = p.$('.ui-msg-to');
    // Each UTF-16 unit is as wide as a letter here, so every length of cut is tried
    const shown = () => line.textContent.length;
    let room = 0;
    Object.defineProperty(line, 'clientWidth', { get: () => room * 8 });
    Object.defineProperty(line, 'scrollWidth', { get: () => shown() * 8 });
    for (room = 17; room <= 28; room++) {
        p.w.uiFitAddresses([line]);
        const text = line.querySelector('.ui-ent-btn').textContent;
        assert.ok(!/[\uD800-\uDFFF]/.test(text.replace(/[\u{10000}-\u{10FFFF}]/gu, '')), `no lone surrogate at ${room}: ${JSON.stringify(text)}`);
    }
});

test('a row that is not an address keeps its text', () => {
    const p = page();
    p.$('#messages-logs').innerHTML = p.w.renderMessageRow({ ...message('odd', 1), sender: 'MAILER-DAEMON', recipient: null });
    assert.equal(p.$('.ui-msg-from').textContent, 'MAILER-DAEMON');
    assert.equal(p.$('.ui-msg-to').textContent, 'to Unknown');
    p.w.uiFitAddresses([p.$('.ui-msg-from'), p.$('.ui-msg-to')]);
    assert.equal(p.$('.ui-msg-from').textContent, 'MAILER-DAEMON');
});

test('the global search shows the same count on a message', () => {
    const p = page();
    p.$('#gs').innerHTML = p.w.gsItem('messages', { title: 'Weekly notes', sub: 's@example.com → r@example.net',
        subTag: p.w.renderRecipientMore(message('two', 2)) }, '');
    const sub = p.$('.ui-gs-item small.ui-gs-sub');
    assert.ok(sub, 'the line with a tag keeps its text apart from the tag');
    assert.equal(sub.querySelector('.ui-rcpt-more').getAttribute('title'), 'and 1 more recipient');
    assert.equal(spoken(sub).replace(/\s+/g, ' '), 's@example.com → r@example.net and 1 more recipient');
});
