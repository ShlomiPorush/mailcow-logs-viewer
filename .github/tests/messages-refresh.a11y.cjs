const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');

const BODY = `<section id="content-messages"><span id="messages-count"></span><div id="messages-logs" class="ui-msg-items"></div></section>`;

const message = n => ({ correlation_key: `k${n}`, message_id: `<m${n}@example.com>`, sender: 's@example.com', recipient: 'r@example.org',
    subject: `Message ${n}`, direction: 'inbound', final_status: 'delivered', first_seen: '2026-10-24T10:00:00Z' });

const rowOf = p => p.w.document.activeElement.closest('[data-key]');

function page() {
    const dom = new JSDOM(`<!doctype html><html lang="en"><head><title>t</title></head><body>${BODY}</body></html>`,
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
    run(`checkAuthentication = async () => false; var asked = []; var total = 700;
        loadMessageFacets = () => {}; afterMessagesRendered = () => {}; updateMessagesFilterState = () => {};
        authenticatedFetch = async url => {
            asked.push(url);
            const q = new URL(url, 'http://localhost').searchParams;
            const limit = Number(q.get('limit') || 50), after = q.get('cursor') ? Number(q.get('cursor').split('|')[1]) : 0;
            const rows = [];
            for (let n = after + 1; n <= Math.min(total, after + limit); n++) rows.push((${message.toString()})(n));
            const last = rows.length ? after + rows.length : after;
            return { ok: true, status: 200, json: async () => ({ total, data: rows, watermark: Number(q.get('upto_id') || 900),
                next_cursor: last < total ? '2026-10-24T10:00:00|' + last : null }) };
        };
        messagesOrder = 'asc';`);
    return { w, run, $$: s => [...w.document.querySelectorAll(s)] };
}

test('a list longer than one request is read page by page from its first watermark, and drawn once', async () => {
    const p = page();
    await p.w.loadMessages({ rows: 620, quiet: true });
    assert.equal(p.$$('.ui-msg-item').length, 620);
    const list = p.w.asked.filter(url => url.startsWith('/api/messages?'));
    assert.equal(list.length, 2);
    const second = new URL(list[1], 'http://localhost').searchParams;
    assert.equal(second.get('limit'), '120');
    assert.equal(second.get('upto_id'), '900');
    assert.ok(second.get('cursor'));
});

test('new mail that comes after the user moved away keeps the list and is offered', async () => {
    const p = page();
    await p.w.loadMessages({ rows: 50 });
    p.run('messagesNew.count = 2');
    await p.w.loadMessages({ rows: 52, quiet: true, toEnd: true, applyIf: () => false });
    assert.equal(p.$$('.ui-msg-item').length, 50);
    const offer = p.w.document.getElementById('messages-new-wrap');
    assert.ok(offer && !offer.hidden);
    assert.equal(offer.textContent.trim(), '2 new messages');
});

test('a redraw at the top gives the focus back to its row', async () => {
    const p = page();
    p.run("messagesOrder = 'desc'");
    await p.w.loadMessages({ rows: 50 });
    p.$$('.ui-msg-item .ui-row-open')[3].focus();
    assert.equal(rowOf(p).dataset.key, 'k4');
    p.run("messagesAtNewEdge = () => true; lastDataCache.messages = { stale: true }");
    await p.w.smartRefreshMessages();
    assert.equal(rowOf(p).dataset.key, 'k4');
    assert.ok(p.w.document.activeElement.matches('.ui-row-open'), 'on the button that opens the row');
});

test('oldest first at the end, a status change is drawn with nothing new, and the focus stays', async () => {
    const p = page();
    p.run('total = 30');
    await p.w.loadMessages({ rows: 50 });
    p.$$('.ui-msg-item .ui-row-open')[29].focus();
    p.run(`messagesAtNewEdge = () => true;
        const read = authenticatedFetch;
        authenticatedFetch = async url => url.startsWith('/api/messages/new') ? { ok: true, status: 200, json: async () => ({ count: 0, watermark: 900 }) } : read(url);
        lastDataCache.messages.data[2] = { ...lastDataCache.messages.data[2], final_status: 'deferred' };`);
    p.w.asked.length = 0;
    await p.w.smartRefreshMessages();
    assert.ok(p.w.asked.some(url => url.startsWith('/api/messages?')), 'the list was read again');
    assert.equal(p.w.eval('lastDataCache.messages.data[2].final_status'), 'delivered');
    assert.equal(rowOf(p).dataset.key, 'k30');
    p.$$('.ui-msg-item')[0].dataset.mark = '1';
    await p.w.smartRefreshMessages();
    assert.equal(p.$$('.ui-msg-item')[0].dataset.mark, '1');
});

test('the focus goes back to the same control of its row, also when the control says something new', () => {
    const p = page();
    p.run(`document.getElementById('messages-logs').innerHTML = '<div data-key="a"><button>4 Sent</button><button>Open</button></div>';`);
    p.w.document.querySelector('[data-key="a"] button').focus();
    p.w.uiKeepFocus(p.w.document.getElementById('messages-logs'), 'data-key', () => {
        p.w.document.getElementById('messages-logs').innerHTML = '<div data-key="a"><button>5 Sent</button><button>Open</button></div>';
    });
    assert.equal(p.w.document.activeElement.textContent, '5 Sent');
});
