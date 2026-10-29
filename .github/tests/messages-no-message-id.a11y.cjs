// Messages without a Message-ID in a real DOM (jsdom) with axe-core: the
// summary line names how many of the time range shown are not in the list,
// and switches the list to them and back. There the outcome, direction, the
// other filters and the export are hidden and dropped, the list asks the other
// endpoint and does not refresh by itself. The rows and the reading pane are
// the Messages ones. jsdom is installed by CI outside the repository; set
// A11Y_MODULES to its node_modules:
//   npm install --no-save --prefix /tmp/a11y jsdom axe-core
//   A11Y_MODULES=/tmp/a11y/node_modules node --test .github/tests/messages-no-message-id.a11y.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));
const axeSource = fs.readFileSync(path.join(modules, 'axe-core', 'axe.min.js'), 'utf8');

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');

// The real Messages page of index.html
function messagesPage() {
    const html = read('index.html');
    const start = html.indexOf('<div id="content-messages"');
    const end = html.indexOf('<!-- Netfilter Tab -->');
    assert.ok(start > 0 && end > start, 'the Messages page is found in index.html');
    return html.slice(start, end);
}

const ROW = { correlation_key: 'k1', message_id: '<m1@example.com>', sender: 's@example.com', recipient: 'r@example.org',
    recipient_count: 1, subject: 'Weekly notes', direction: 'inbound', final_status: 'delivered', is_complete: true,
    first_seen: '2026-10-24T10:00:00Z' };
const NOID = { correlation_key: 'noid-41', message_id: null, queue_id: 'D41A', sender: 'scanner@example.com',
    recipient: 'office@example.com', recipient_count: 1, subject: null, direction: null, final_status: 'delivered',
    is_complete: true, first_seen: '2026-10-24T09:00:00Z', queue_id_reused: false };

function page() {
    const dom = new JSDOM(`<!doctype html><html lang="en"><head><title>t</title></head><body><main>${messagesPage()}</main></body></html>`,
        { runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/messages' });
    const w = dom.window;
    w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    w.Element.prototype.getClientRects = function () { return this.isConnected ? [{}] : []; };
    const run = source => {
        const script = w.document.createElement('script');
        script.textContent = source;
        w.document.head.appendChild(script);
    };
    [read('utils.js'), read('router.js'), read('app.js')].forEach(run);
    run(`checkAuthentication = async () => false; var asked = []; var noidTotal = 3;
        afterMessagesRendered = () => {};
        authenticatedFetch = async url => {
            asked.push(url);
            const json = url.startsWith('/api/messages/without-message-id')
                ? { total: noidTotal, data: noidTotal ? [${JSON.stringify(NOID)}] : [], next_cursor: null }
                : url.startsWith('/api/messages/facets') ? { status: { all: 1 }, direction: { all: 1 } }
                : url.startsWith('/api/messages/new') ? { count: 0, watermark: 9 }
                : { total: 1, data: [${JSON.stringify(ROW)}], next_cursor: null, watermark: 9 };
            return { ok: true, status: 200, json: async () => json };
        };`);
    const $ = s => w.document.querySelector(s);
    const settle = () => new Promise(resolve => w.setTimeout(resolve, 0));
    return { w, run, $, settle, asked: () => w.asked };
}

const params = url => new URL(url, 'http://localhost').searchParams;

test('the summary line counts the messages without a Message-ID of the time range and search shown', async () => {
    const p = page();
    p.$('#messages-filter-search').value = 'scanner';
    p.$('#messages-start-date').value = '2026-10-20T00:00:00Z';
    p.w.applyMessagesFilters();
    await p.settle(); await p.settle();
    const link = p.$('#messages-noid');
    assert.ok(!link.classList.contains('hidden'));
    assert.equal(link.textContent, '3 more without a Message-ID');
    const count = p.asked().find(url => url.startsWith('/api/messages/without-message-id'));
    assert.equal(params(count).get('limit'), '1');
    assert.equal(params(count).get('search'), 'scanner');
    assert.equal(params(count).get('start_date'), '2026-10-20T00:00:00Z');

    // None: no link
    p.run('noidTotal = 0');
    await p.w.loadMessages();
    await p.settle(); await p.settle();
    assert.ok(link.classList.contains('hidden'));
});

test('the link shows them in the list, with only the filters that apply, and back', async () => {
    const p = page();
    p.$('#messages-filter-sender').value = 'boss@example.com';
    p.$('#messages-filter-search').value = 'scanner';
    p.$('#messages-filter-status').value = 'bounced';
    p.w.applyMessagesFilters();
    await p.settle(); await p.settle();
    p.asked().length = 0;

    p.$('#messages-noid').click();
    await p.settle(); await p.settle();
    const page_ = p.$('#content-messages');
    assert.ok(page_.classList.contains('is-noid'), 'the page hides what does not apply');
    for (const selector of ['#messages-facet-status', '#messages-facet-direction', '#messages-filters-btn',
        '#messages-more-filters', '#messages-status-host', '#messages-direction-host', '.ui-fct-export']) {
        assert.ok(p.$(selector).hasAttribute('data-noid-hide'), `${selector} is hidden there`);
    }
    assert.deepEqual(JSON.parse(p.w.eval('JSON.stringify(currentFilters.messages)')), { search: 'scanner' });
    assert.equal(p.$('#messages-filter-sender').value, '');
    const list = p.asked().filter(url => url.startsWith('/api/messages'));
    assert.ok(list.every(url => url.startsWith('/api/messages/without-message-id')), list.join(', '));
    assert.equal(params(list[0]).get('search'), 'scanner');
    assert.equal(params(list[0]).get('sender'), null);
    assert.equal(p.$('#messages-count').textContent, '3 messages without a Message-ID');
    const row = p.$('.ui-msg-item[data-key="noid-41"]');
    assert.ok(row, 'the row is drawn by the Messages row');
    assert.match(row.textContent, /No subject/);
    assert.equal(p.$('#messages-noid').textContent, 'Show all messages');

    // A filter the list ignores cannot come back through Apply
    p.$('#messages-filter-ip').value = '192.0.2.1';
    p.w.applyMessagesFilters();
    assert.deepEqual(Object.keys(p.w.eval('currentFilters.messages')).sort(), ['search']);

    // No refresh by itself
    p.asked().length = 0;
    await p.w.smartRefreshMessages();
    assert.equal(p.asked().length, 0);

    // Back to every message
    p.$('#messages-noid').click();
    await p.settle(); await p.settle();
    assert.ok(!page_.classList.contains('is-noid'));
    assert.ok(p.asked().some(url => url.startsWith('/api/messages?')));
    assert.equal(p.$('#messages-noid').textContent, '3 more without a Message-ID');
});

test('the auto refresh counts them again, and a failed count keeps the last one', async () => {
    const p = page();
    p.run('noidTotal = 0');
    await p.w.loadMessages();
    await p.settle(); await p.settle();
    assert.ok(p.$('#messages-noid').classList.contains('hidden'));
    // One arrives while the page is open
    p.run('noidTotal = 1; messagesAtNewEdge = () => false');
    await p.w.smartRefreshMessages();
    await p.settle(); await p.settle();
    assert.equal(p.$('#messages-noid').textContent, '1 more without a Message-ID');
    p.run(`const answer = authenticatedFetch;
        authenticatedFetch = async url => url.startsWith('/api/messages/without-message-id') ? { ok: false, status: 500, json: async () => ({}) } : answer(url);`);
    await p.w.smartRefreshMessages();
    await p.settle(); await p.settle();
    assert.equal(p.$('#messages-noid').textContent, '1 more without a Message-ID');
});

test('the summary line with the link has no accessibility violations', async () => {
    const p = page();
    await p.w.loadMessages();
    await p.settle(); await p.settle();
    p.run(axeSource);
    const result = await p.w.axe.run(p.$('.ui-msg-summary'), { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } });
    assert.deepEqual(Array.from(result.violations, v => `${v.id}: ${v.nodes.map(n => n.target).join(', ')}`), []);
});

test('opening Messages with filters from elsewhere shows the whole list again', async () => {
    const p = page();
    await p.w.loadMessages();
    await p.settle(); await p.settle();
    p.$('#messages-noid').click();
    await p.settle(); await p.settle();
    assert.ok(p.$('#content-messages').classList.contains('is-noid'));
    // An entity card's Show messages, from the Messages page or another page
    p.asked().length = 0;
    p.w.navigateToMessagesWithFilter({ address: 'boss@example.com' });
    await new Promise(resolve => p.w.setTimeout(resolve, 150));
    await p.settle(); await p.settle();
    assert.ok(!p.$('#content-messages').classList.contains('is-noid'));
    const list = p.asked().filter(url => url.startsWith('/api/messages?'));
    assert.ok(list.length, 'the whole list is asked');
    assert.equal(params(list[list.length - 1]).get('address'), 'boss@example.com');
    // And a time range opened from the dashboard
    p.$('#messages-noid').click();
    await p.settle(); await p.settle();
    p.w.openMessagesRange({ start: '2026-10-24T10:00:00Z', endInclusive: '2026-10-24T10:59:59Z' });
    await p.settle(); await p.settle();
    assert.ok(!p.$('#content-messages').classList.contains('is-noid'));
});

test('a redraw of the list by the auto refresh does not drop the count', async () => {
    const p = page();
    p.run('noidTotal = 0');
    await p.w.loadMessages();
    await p.settle(); await p.settle();
    // New mail redraws the list at its top while the count is on its way
    p.run(`noidTotal = 2; messagesAtNewEdge = () => true; lastDataCache.messages = { stale: true };
        const answer = authenticatedFetch;
        authenticatedFetch = async (url, options) => {
            if (url.startsWith('/api/messages/without-message-id')) await new Promise(resolve => setTimeout(resolve, 30));
            return answer(url, options);
        };`);
    await p.w.smartRefreshMessages();
    await new Promise(resolve => p.w.setTimeout(resolve, 60));
    await p.settle();
    assert.equal(p.$('#messages-noid').textContent, '2 more without a Message-ID');
});

test('the answer for a message opened before another one is not shown', async () => {
    const dom = new JSDOM(`<!doctype html><html lang="en"><head><title>t</title></head><body>
        <div id="message-modal" class="hidden"><div id="message-modal-header"></div><div id="message-modal-body"><div id="message-modal-content"></div></div></div>
        </body></html>`, { runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/messages' });
    const w = dom.window;
    w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    const run = source => { const s = w.document.createElement('script'); s.textContent = source; w.document.head.appendChild(s); };
    [read('utils.js'), read('message-details.js')].forEach(run);
    run(`window.disabledFeatures = []; var release = {};
        authenticatedFetch = url => new Promise(resolve => { release[url.split('/')[3]] = data => resolve({ ok: true, json: async () => data }); });`);
    const details = (key, sender) => ({ correlation_key: key, sender, recipient: 'office@example.com', recipients: ['office@example.com'],
        recipient_count: 1, subject: null, final_status: 'delivered', is_complete: true, first_seen: '2026-10-24T10:00:00Z',
        related_deliveries: [], rspamd: null, dovecot: null, postfix: [], postfix_by_recipient: {}, netfilter: [], client: null, queue_id_reused: false });
    const first = w.viewMessageDetails('noid-1');
    const second = w.viewMessageDetails('noid-2');
    w.release['noid-2'](details('noid-2', 'second@example.com'));
    await second;
    w.release['noid-1'](details('noid-1', 'first@example.com'));
    await first;
    const header = w.document.getElementById('message-modal-header').textContent;
    assert.match(header, /second@example\.com/);
    assert.doesNotMatch(header, /first@example\.com/);
});
