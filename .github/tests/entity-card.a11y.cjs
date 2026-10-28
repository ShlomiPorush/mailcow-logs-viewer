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
