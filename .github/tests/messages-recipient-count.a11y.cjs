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
    const tag = row.querySelector('.ui-msg-rcpt > .ui-rcpt-more');
    assert.ok(tag, 'the count sits with the address');
    assert.equal(tag.previousElementSibling.className, 'ui-msg-to', 'right after the address');
    assert.equal(tag.querySelector('[aria-hidden="true"]').textContent, '+2');
    assert.equal(tag.getAttribute('title'), 'and 2 more recipients');
    assert.match(spoken(row.querySelector('.ui-msg-rcpt')).replace(/\s+/g, ' '), /^to r@example\.net and 2 more recipients$/);
    assert.ok(!spoken(row).includes('+2'), 'the "+2" itself is not read out');

    p.run(axeSource);
    const result = await p.w.axe.run(p.w.document, { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } });
    assert.deepEqual(Array.from(result.violations, v => `${v.id}: ${v.nodes.map(n => n.target).join(', ')}`), []);
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
