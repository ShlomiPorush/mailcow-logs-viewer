// Entity values and the entity card (utils.js uiEntity, entity-card.js) in a real
// DOM (jsdom): a value opens its card and not the row it sits in, a late answer
// for a card opened before is dropped, Escape closes the card before the dialog
// under it, and a source that is off or failed never shows as zero.
//   A11Y_MODULES=/tmp/a11y/node_modules node --test .github/tests/entity-card.a11y.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');
const html = read('index.html');
// The card's own markup, as index.html has it
const CARD = html.slice(html.indexOf('<div id="entity-card"'), html.indexOf('<!-- Changelog Modal -->'));

const STYLE = '.hidden { display: none; } .ui-dialog-backdrop { z-index: 50; }';

// Pages the card draws with, standing in for app.js and devices.js
const STUBS = `
    window.fetches = [];
    function authenticatedFetch(url) { return new Promise(resolve => window.fetches.push({ url, resolve })); }
    function renderMessageRow(m) { return '<div class="ui-msg-item">' + escapeHtml(m.subject) + '</div>'; }
    function renderDeviceRow(d) { return '<div class="ui-tr">' + escapeHtml(d.device_type) + '</div>'; }
    function getFlagUrl() { return null; }
    function navigateTo() {}
    function viewMessageDetails() {}`;

function page(body) {
    const dom = new JSDOM(`<!doctype html><html lang="en"><head><title>t</title><style>${STYLE}</style></head><body>${body}${CARD}</body></html>`,
        { runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/messages' });
    const w = dom.window;
    w.Element.prototype.getClientRects = function () { return this.isConnected && !this.closest('.hidden') ? [{}] : []; };
    w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    if (!('inert' in w.HTMLElement.prototype)) {
        Object.defineProperty(w.HTMLElement.prototype, 'inert', { configurable: true,
            get() { return this.hasAttribute('inert'); },
            set(value) { if (value) this.setAttribute('inert', ''); else this.removeAttribute('inert'); } });
    }
    const run = source => { const s = w.document.createElement('script'); s.textContent = source; w.document.head.appendChild(s); };
    [read('utils.js'), read('router.js'), STUBS, read('entity-card.js'), 'watchOverlays();'].forEach(run);
    w.document.dispatchEvent(new w.Event('DOMContentLoaded'));
    return w;
}

const frame = w => new Promise(resolve => w.requestAnimationFrame(() => setTimeout(resolve, 0)));
const settle = async w => { await frame(w); await frame(w); };
const answer = (w, i, body, status = 200) => w.fetches[i].resolve({ ok: status < 400, status, json: async () => body });

const range = { start: '2026-10-21T12:00:00Z', end: '2026-10-28T12:00:00Z' };
const ok = extra => ({ state: 'ok', reason: null, ...extra });
function ipCard(value, sources = {}) {
    return { kind: 'ip', value, display: value, range,
        sources: {
            messages: ok({ count: 2, items: [] }), security: ok({ events: 3, rule_matches: 3, bans: 0, unbans: 0, items: [] }),
            lists: ok({ allowlisted_as: null, denylisted_as: null, ban: null }), protection: ok({ count: 0, open: 0, items: [] }),
            devices: ok({ count: 0, items: [] }), dmarc: ok({ messages: 0, reports: 0, domains: 0, by_domain: [], records: [] }),
            rbl: ok({ checked: false, monitored: false }), geo: ok({ country_code: null, country_name: null, city: null, asn: null, asn_org: null }),
            ...sources },
        timeline: { items: [], truncated: false, left_out: [] } };
}

test('kinds are told apart as the API reads them, and other values stay text', () => {
    const w = page('');
    const kind = v => w.entityKindOf(v);
    assert.equal(kind('203.0.113.45'), 'ip');
    assert.equal(kind('2001:db8::1f'), 'ip');
    assert.equal(kind('::ffff:192.0.2.1'), 'ip');
    assert.equal(kind('ann@example.com'), 'address');
    assert.equal(kind('"a@b"@example.com'), 'address', 'split on the last @');
    assert.equal(kind('example.com'), 'domain');
    assert.equal(kind('example.com.'), 'domain');
    for (const v of ['192.0.2.0/24', 'fe80::1%eth0', '256.1.1.1', 'ann@', '@example.com', 'a b@example.com', 'localhost', '-', 'unknown', '1.2.3']) {
        assert.equal(kind(v), null, v);
    }
    // A network is not an IP: it stays click to copy
    assert.match(w.uiEntity('ip', '192.0.2.0/24'), /class="copyable/);
    assert.doesNotMatch(w.uiEntity('ip', '192.0.2.0/24'), /data-entity-kind/);
    assert.equal(w.uiEntity('address', 'MAILER-DAEMON', { plain: true }), 'MAILER-DAEMON');
    // A kind asked for that the value is not: not a card of another kind
    assert.doesNotMatch(w.uiEntity('ip', 'mail.example.com'), /data-entity-kind/);
});

test('a value is a button that carries its value as data, never in a handler', () => {
    const w = page('<div id="host"></div>');
    const value = `o'neil"&<x>@example.com`;
    const host = w.document.getElementById('host');
    host.innerHTML = w.uiEntity('address', value);
    const button = host.querySelector('[data-entity-kind]');
    assert.equal(button.tagName, 'BUTTON');
    assert.equal(button.type, 'button');
    assert.equal(button.dataset.entityKind, 'address');
    assert.equal(button.dataset.entityValue, value);
    assert.equal(host.querySelector('[data-entity-copy]').dataset.entityCopy, value);
    assert.equal(host.querySelectorAll('[onclick]').length, 0);
    assert.equal(button.textContent, value);
});

test('a click on a value opens its card and not the row it sits in', async () => {
    const w = page(`<div id="row" role="button" tabindex="0" data-row-open onclick="window.rowOpened = (window.rowOpened || 0) + 1"></div>`);
    const row = w.document.getElementById('row');
    row.innerHTML = `${w.uiEntity('address', 'ann@example.com')} ${w.uiEntity('ip', '203.0.113.45')}`;
    row.querySelector('[data-entity-kind="ip"]').click();
    await settle(w);
    assert.equal(w.rowOpened, undefined, 'the row did not open');
    const card = w.document.getElementById('entity-card');
    assert.ok(!card.classList.contains('hidden'));
    assert.equal(w.fetches[0].url, '/api/entities/ip?value=203.0.113.45');
    // Enter on the value: the row's own key handler leaves it to the button
    const button = row.querySelector('[data-entity-kind="address"]');
    button.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
    assert.equal(w.rowOpened, undefined, 'Enter on the value does not open the row');
    // A click on the row itself still opens it
    row.click();
    assert.equal(w.rowOpened, 1);
});

test('the copy icon copies and opens nothing', async () => {
    const w = page(`<div id="row" onclick="window.rowOpened = 1"></div>`);
    const copied = [];
    Object.defineProperty(w.navigator, 'clipboard', { configurable: true, value: { writeText: text => { copied.push(text); return Promise.resolve(); } } });
    const row = w.document.getElementById('row');
    row.innerHTML = w.uiEntity('ip', '203.0.113.45');
    row.querySelector('[data-entity-copy]').click();
    await settle(w);
    assert.deepEqual(copied, ['203.0.113.45']);
    assert.equal(w.rowOpened, undefined);
    assert.ok(w.document.getElementById('entity-card').classList.contains('hidden'));
});

test('an answer for a card opened before the last one is dropped', async () => {
    const w = page('');
    w.openEntityCard('ip', '192.0.2.10');
    w.openEntityCard('ip', '192.0.2.20');
    answer(w, 1, ipCard('192.0.2.20'));
    await settle(w);
    answer(w, 0, ipCard('192.0.2.10'));
    await settle(w);
    const header = w.document.getElementById('entity-card-header').textContent;
    assert.match(header, /192\.0\.2\.20/);
    assert.doesNotMatch(header, /192\.0\.2\.10/);
    // Closed while loading: nothing draws into the closed card
    w.openEntityCard('ip', '192.0.2.30');
    w.closeEntityCard();
    answer(w, 2, ipCard('192.0.2.30'));
    await settle(w);
    assert.equal(w.document.getElementById('entity-card-content').innerHTML, '');
});

test('a card opened from a dialog comes over it, and Escape closes the card first', async () => {
    const w = page(`
        <div id="msg" class="ui-dialog-backdrop" role="dialog" aria-label="Message"><div class="ui-dialog">
            <div class="ui-dialog-head"><h3>Message</h3><button type="button" aria-label="Close" onclick="document.getElementById('msg').classList.add('hidden')">x</button></div>
            <div class="ui-dialog-body" id="msg-body"></div></div></div>`);
    w.document.getElementById('msg-body').innerHTML = w.uiEntity('address', 'ann@example.com');
    await settle(w);
    w.document.querySelector('#msg-body [data-entity-kind]').click();
    await settle(w);
    const card = w.document.getElementById('entity-card');
    assert.equal(w.document.body.lastElementChild, card, 'the card is last on the page, so on top');
    w.document.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
    await settle(w);
    assert.ok(card.classList.contains('hidden'), 'Escape closed the card');
    assert.ok(!w.document.getElementById('msg').classList.contains('hidden'), 'the message stays open');
});

test('a source that is off or failed says so, never zero', async () => {
    const w = page('');
    w.openEntityCard('ip', '198.51.100.23');
    answer(w, 0, ipCard('198.51.100.23', {
        dmarc: { state: 'disabled', reason: 'The DMARC & TLS feature is turned off.' },
        security: { state: 'error', reason: 'Could not read the security events. The details are in the container log.' },
    }));
    await settle(w);
    const content = w.document.getElementById('entity-card-content');
    const tile = label => [...content.querySelectorAll('.ui-st-card')].find(t => t.querySelector('.ui-st-card-label').textContent.startsWith(label));
    assert.match(tile('DMARC reports').textContent, /Disabled in Settings/);
    assert.match(tile('DMARC reports').textContent, /turned off/);
    assert.match(tile('Security events').textContent, /Could not be read/);
    assert.doesNotMatch(tile('Security events').querySelector('b').textContent, /\d/);
    const tabs = w.document.getElementById('entity-card-tabs').textContent;
    assert.match(tabs, /DMARC\s*Off/);
    assert.match(tabs, /Security\s*Error/);
    w.entityCardTab('dmarc');
    assert.match(content.textContent, /Disabled in Settings/);
    w.entityCardTab('security');
    assert.match(content.textContent, /Could not read security events/);
});

test('a card that cannot load says why', async () => {
    const w = page('');
    w.openEntityCard('ip', '192.0.2.40');
    answer(w, 0, { detail: 'Enter one IP address, like 192.0.2.1 or 2001:db8::1.' }, 422);
    await settle(w);
    const content = w.document.getElementById('entity-card-content').textContent;
    assert.match(content, /Could not load this card/);
    assert.match(content, /Enter one IP address/);
});

// ---------------------------------------------------------------- review fixes

// The pages themselves (app.js renderMessageRow, message-details.js), for the rows
function appPage(body) {
    const dom = new JSDOM(`<!doctype html><html lang="en"><head><title>t</title><style>${STYLE}</style></head><body>${body}${CARD}</body></html>`,
        { runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/dashboard' });
    const w = dom.window;
    w.Element.prototype.getClientRects = function () { return this.isConnected && !this.closest('.hidden') ? [{}] : []; };
    w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    const run = source => { const s = w.document.createElement('script'); s.textContent = source; w.document.head.appendChild(s); };
    [read('utils.js'), read('router.js'), read('app.js'), read('message-details.js'), read('entity-card.js')].forEach(run);
    run('checkAuthentication = async () => false; window.fetches = []; authenticatedFetch = url => new Promise(resolve => window.fetches.push({ url, resolve }));');
    return { w, run };
}

const axeSource = fs.readFileSync(path.join(modules, 'axe-core', 'axe.min.js'), 'utf8');
async function nestedInteractive(w, root) {
    w.eval(axeSource);
    const result = await w.axe.run(root, { runOnly: { type: 'rule', values: ['nested-interactive'] } });
    return Array.from(result.violations.flatMap(v => v.nodes.map(n => n.html.slice(0, 80))));
}

test('U1: failed logins with the Fail2ban lists unknown never say "not banned"', async () => {
    const w = page('');
    w.openEntityCard('ip', '203.0.113.45');
    answer(w, 0, ipCard('203.0.113.45', { lists: { state: 'error', reason: 'mailcow did not answer, so the allowlist, denylist and bans are not known.' } }));
    await settle(w);
    const bar = w.document.querySelector('#entity-card-header .ui-md-verdict-bar').textContent;
    assert.doesNotMatch(bar, /not banned/i);
    assert.match(bar, /ban state not known/i);
    assert.match(bar, /3 failed logins/);
    assert.match(bar, /mailcow did not answer/);
});

test('U2: Open Settings from a card over a message closes both once the move is made', async () => {
    const view = id => `<div id="${id}" class="ui-dialog-backdrop" role="dialog" aria-label="${id}"><div class="ui-dialog">
        <div class="ui-dialog-head"><h3>${id}</h3><button type="button" aria-label="Close" onclick="document.getElementById('${id}').classList.add('hidden')">x</button></div>
        <div class="ui-dialog-body" id="${id}-body"><input type="search" aria-label="Find"></div></div></div>`;
    const form = `<div id="editor" class="ui-dialog-backdrop" role="dialog" aria-label="Editor"><div class="ui-dialog">
        <div class="ui-dialog-head"><h3>Editor</h3><button type="button" aria-label="Close" onclick="document.getElementById('editor').classList.add('hidden')">x</button></div>
        <div class="ui-dialog-body"><input type="text" aria-label="Name"></div></div></div>`;
    for (const confirmed of [true, false]) {
        const w = page(form + view('msg'));
        const moves = [];
        w.navigateTo = route => { moves.push(route); return Promise.resolve(confirmed); };
        w.document.getElementById('msg-body').insertAdjacentHTML('beforeend', w.uiEntity('ip', '203.0.113.45'));
        w.document.querySelector('#msg-body [data-entity-kind]').click();
        answer(w, 0, ipCard('203.0.113.45', { dmarc: { state: 'disabled', reason: 'The DMARC & TLS feature is turned off.' } }));
        await settle(w);
        w.entityCardTab('dmarc');
        [...w.document.querySelectorAll('#entity-card-content button')].find(b => b.textContent === 'Open Settings').click();
        await settle(w);
        const shown = id => !w.document.getElementById(id).classList.contains('hidden');
        assert.deepEqual(moves, ['settings']);
        if (confirmed) {
            assert.ok(!shown('entity-card'), 'the card closed');
            assert.ok(!shown('msg'), 'the message under it closed too, so it does not cover Settings');
            assert.ok(shown('editor'), 'a dialog with fields of its own stays, with its own question');
        } else {
            assert.ok(shown('entity-card') && shown('msg'), 'the move was not made (changes kept): all stays');
        }
    }
});

test('U3: a click that ends a selection, or one with a modifier, leaves the row to decide', async () => {
    const w = page(`<div id="row" onclick="window.rowOpened = (window.rowOpened || 0) + 1"><span id="text">Subject text</span> </div>`);
    const row = w.document.getElementById('row');
    row.insertAdjacentHTML('beforeend', w.uiEntity('address', 'ann@example.com'));
    const button = row.querySelector('[data-entity-kind]');
    const click = init => button.dispatchEvent(new w.MouseEvent('click', { bubbles: true, cancelable: true, detail: 1, ...init }));
    const card = () => !w.document.getElementById('entity-card').classList.contains('hidden');
    for (const init of [{ shiftKey: true }, { ctrlKey: true }, { metaKey: true }, { altKey: true }, { button: 1 }]) {
        w.rowOpened = 0;
        click(init);
        await settle(w);
        assert.ok(!card(), `no card on ${JSON.stringify(init)}`);
        assert.equal(w.rowOpened, 1, `the click went on to the row on ${JSON.stringify(init)}`);
    }
    // The end of a drag that selected text over the value
    const range = w.document.createRange();
    range.setStart(w.document.getElementById('text').firstChild, 3);
    range.setEnd(button.querySelector('bdi').firstChild, 3);
    w.getSelection().removeAllRanges();
    w.getSelection().addRange(range);
    w.rowOpened = 0;
    click({});
    await settle(w);
    assert.ok(!card(), 'no card at the end of a selection');
    assert.equal(w.rowOpened, 1, 'the row saw the click (its own uiRowHeld decides)');
    // A plain click, and the keyboard (detail 0), still open it
    w.getSelection().removeAllRanges();
    click({ detail: 0 });
    await settle(w);
    assert.ok(card(), 'Enter or Space opens the card');
});

test('U4: message, recipient and delivery rows hold buttons but are no buttons themselves', async () => {
    const { w } = appPage('<div id="list"></div>');
    const opened = [];
    w.viewMessageDetails = key => opened.push(key);
    const list = w.document.getElementById('list');
    list.innerHTML = w.renderMessageRow({ correlation_key: 'k1', sender: 'ann@example.com', recipient: 'bob@example.net', subject: 'Hello',
        first_seen: '2026-10-28T10:00:00Z', final_status: 'delivered', is_complete: true, direction: 'inbound' });
    // Recipients and deliveries of a message, drawn by message-details.js itself
    const at = s => `2026-01-01T00:00:0${s}Z`;
    const data = { correlation_key: 'k1', sender: 'ann@example.com', recipient: 'a@example.net', first_seen: at(5), final_status: 'deferred',
        recipients: ['a@example.net', 'b@example.net'], dovecot: null, rspamd: null,
        related_deliveries: [{ correlation_key: 'k0', sender: 'ann@example.com', recipient: 'old@example.net', first_seen: at(1), final_status: 'delivered' }],
        postfix: [
            { time: at(0), program: 'postfix/qmgr', message: 'Q1: from=<ann@example.com>, nrcpt=2 (queue active)' },
            { time: at(2), program: 'postfix/smtp', recipient: 'a@example.net', status: 'sent', relay: 'mx.example.net[192.0.2.9]:25', message: 'Q1: to=<a@example.net>, status=sent (250 ok)' },
            { time: at(3), program: 'postfix/smtp', recipient: 'b@example.net', status: 'deferred', relay: 'mx.example.net[192.0.2.9]:25', message: 'Q1: to=<b@example.net>, status=deferred (451 later)' }] };
    w.eval('mdRecipients = messageRecipients(' + JSON.stringify(data) + '); mdOwners = mdAddressOwners(' + JSON.stringify(data) + ');');
    list.insertAdjacentHTML('beforeend', `<div id="rcpts">${w.renderRecipientRows()}</div>${w.renderRelatedDeliveries(data)}`);
    assert.deepEqual(await nestedInteractive(w, list), []);
    assert.equal(list.querySelectorAll('[role="button"] button, [tabindex] button, button button').length, 0);

    // Messages row: its time is the button that opens it, named after the subject (the
    // subject stays text that can be selected); the values open their cards
    const row = list.querySelector('.ui-msg-item');
    const open = row.querySelector('.ui-row-open');
    assert.equal(open.tagName, 'BUTTON');
    assert.equal(open.getAttribute('aria-label'), 'Open the message: Hello');
    assert.equal(row.querySelector('.ui-msg-sub').closest('button'), null, 'the subject is no button');
    assert.ok(!row.hasAttribute('role') && !row.hasAttribute('tabindex'));
    const tabbable = [...row.querySelectorAll('button')].filter(b => !b.matches('.ui-ent-copy'));
    assert.deepEqual(Array.from(tabbable, b => b.getAttribute('aria-label') || b.textContent.trim()), ['ann@example.com', 'Open the message: Hello', 'bob@example.net']);
    open.click();            // Enter on a button is its click
    assert.deepEqual(opened, ['k1']);
    row.querySelector('.ui-msg-l3').click();   // anywhere on the row, with the mouse
    assert.deepEqual(opened, ['k1', 'k1']);
    row.querySelector('[data-entity-kind]').click();
    await settle(w);
    assert.deepEqual(opened, ['k1', 'k1'], 'a value opens its card, not the message');
    assert.ok(!w.document.getElementById('entity-card').classList.contains('hidden'));
    w.closeEntityCard();

    // Recipient rows: the status is the toggle that shows that recipient's logs
    const toggles = [...list.querySelectorAll('#rcpts .ui-md-rrow > .ui-row-open')];
    assert.equal(toggles.length, 2);
    assert.match(toggles[0].getAttribute('aria-label'), /^Show the logs of /);
    toggles.find(t => t.getAttribute('aria-label') === 'Show the logs of b@example.net').click();
    assert.equal(w.eval('mdView.picked'), w.eval("mdRecipients.findIndex(r => r.key === 'b@example.net')"));
    // A delivery leg opens its message from its number
    const leg = list.querySelector('.ui-md-leg:not(.is-current) .ui-row-open');
    assert.match(leg.getAttribute('aria-label'), /^Open delivery 1: /);
    leg.click();
    assert.deepEqual(opened, ['k1', 'k1', 'k0']);
});

test('U5: the value in the card header is a copy button the keyboard reaches', async () => {
    const w = page('');
    const copied = [];
    Object.defineProperty(w.navigator, 'clipboard', { configurable: true, value: { writeText: text => { copied.push(text); return Promise.resolve(); } } });
    w.openEntityCard('ip', '203.0.113.45');
    answer(w, 0, ipCard('203.0.113.45'));
    await settle(w);
    const value = w.document.querySelector('#entity-card-header .ui-ent-title button[data-entity-copy]');
    assert.ok(value, 'a button');
    assert.equal(value.type, 'button');
    assert.equal(value.textContent.trim(), '203.0.113.45');
    assert.equal(value.querySelectorAll('[onclick]').length + (value.hasAttribute('onclick') ? 1 : 0), 0);
    value.click();
    await settle(w);
    assert.deepEqual(copied, ['203.0.113.45']);
});

test('U6: with sources off and nothing found, the card says what it could not read', async () => {
    const w = page('');
    w.openEntityCard('ip', '198.51.100.23');
    const card = ipCard('198.51.100.23', { security: { state: 'disabled', reason: 'The Security feature is turned off.' }, devices: { state: 'error', reason: 'x' } });
    answer(w, 0, { ...card, timeline: { items: [], truncated: false, left_out: ['security', 'devices'] } });
    await settle(w);
    const header = w.document.getElementById('entity-card-header').textContent;
    const content = () => w.document.getElementById('entity-card-content').textContent;
    for (const [where, text] of [['header', header], ['Recent', content()]]) {
        assert.doesNotMatch(text, /Nothing stored/, where);
        assert.match(text, /sources that could be read/, where);
        assert.match(text, /Security events, Devices/, where);
    }
    w.entityCardTab('timeline');
    const timeline = content();
    assert.ok(timeline.indexOf('Not included') >= 0 && timeline.indexOf('Not included') < timeline.indexOf('Nothing found'),
        'the sources left out are named before the empty list');
});

test('U7: a card opened from code gives the focus back to its opener', async () => {
    const w = page('<main><section class="ui-page"><h1>Page</h1><button id="opener" type="button">Open</button></section></main>');
    const opener = w.document.getElementById('opener');
    opener.focus();
    w.document.body.focus();     // the focus moved on; no click or key named the opener
    w.openEntityCard('ip', '203.0.113.45', { from: opener });
    answer(w, 0, ipCard('203.0.113.45'));
    await settle(w);
    w.document.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
    await settle(w);
    assert.ok(w.document.getElementById('entity-card').classList.contains('hidden'));
    assert.equal(w.document.activeElement, opener);
});

test('U8: a subject reads in its own direction, names inside sentences are isolated', async () => {
    const w = page('');
    w.openEntityCard('ip', '203.0.113.45');
    const items = [
        { time: '2026-10-28T10:00:00Z', kind: 'message', label: 'Message', sender: 'ann@example.com', recipient: 'bob@example.net', subject: 'مرحبا بالعالم', status: 'delivered' },
        { time: '2026-10-28T09:00:00Z', kind: 'device_last_seen', label: 'Device last seen', username: 'ann@example.com', device_type: 'iPhone', device_id: 'D1', ip: '203.0.113.45' },
    ];
    answer(w, 0, { ...ipCard('203.0.113.45'), timeline: { items, truncated: false, left_out: [] } });
    await settle(w);
    w.entityCardTab('timeline');
    const content = w.document.getElementById('entity-card-content');
    const subject = [...content.querySelectorAll('li > span')].find(s => s.textContent === 'مرحبا بالعالم');
    assert.ok(subject, 'the subject is shown');
    assert.equal(subject.getAttribute('dir'), 'auto');
    const device = [...content.querySelectorAll('li > b bdi')].map(b => b.textContent);
    assert.ok(device.includes('iPhone'), 'the device name is isolated');
});
