const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');

const alert = (id, alert_type = 'volume_spike') => ({ id, alert_type, severity: 'warning', title: `Alert ${id}`, detail: 'detail', created_at: '2026-10-22T10:00:00Z' });

function page({ still = false } = {}) {
    const dom = new JSDOM('<!doctype html><html lang="en"><head><title>t</title><style>.hidden { display: none; }</style></head><body><span id="theme-toggle-light-icon" class="hidden"></span><span id="theme-toggle-dark-icon" class="hidden"></span><main><div id="list"></div></main></body></html>',
        { runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/dashboard' });
    const w = dom.window;
    w.Element.prototype.getClientRects = function () { return this.isConnected && !this.closest('.hidden') ? [{}] : []; };
    Object.defineProperty(w.HTMLElement.prototype, 'offsetWidth', { configurable: true, get: () => 300 });
    w.matchMedia = query => ({ matches: still && query.includes('reduce'), addEventListener() {}, removeEventListener() {} });
    Object.defineProperty(w.document, 'scrollingElement', { get: () => w.document.documentElement });
    const run = source => {
        const script = w.document.createElement('script');
        script.textContent = source;
        w.document.head.appendChild(script);
    };
    [read('utils.js'), read('router.js'), read('app.js')].forEach(run);
    w.dismissed = [];
    w.fail = false;
    run(`acknowledgeSecurityAlert = async id => { window.dismissed.push(id); await null;
        if (!window.fail) document.querySelector('[data-key="alert-' + id + '"]')?.remove(); };
        openAlertActivity = id => { window.opened = (window.opened || 0) + 1; };`);
    return w;
}

function draw(w, alerts) {
    w.eval(`attention.alerts.list = ${JSON.stringify(alerts)}`);
    w.document.getElementById('list').innerHTML = w.attentionAlertRows('dashboard');
}

function swipe(w, target, steps, { type = 'touch', end = 'pointerup' } = {}) {
    const fire = (name, x, y) => target.dispatchEvent(new w.PointerEvent(name, { bubbles: true, pointerId: 1, pointerType: type, clientX: x, clientY: y }));
    fire('pointerdown', 150, 20);
    for (const [dx, dy] of steps) fire('pointermove', 150 + dx, 20 + dy);
    const [dx, dy] = steps.at(-1) || [0, 0];
    fire(end, 150 + dx, 20 + dy);
}

const flush = () => new Promise(resolve => setTimeout(resolve, 0));
const row = (w, id) => w.document.querySelector(`[data-key="alert-${id}"]`);

test('a swipe past the distance, to either side, dismisses through the X', async () => {
    for (const dx of [-120, 120]) {
        const w = page();
        draw(w, [alert(1), alert(2)]);
        const r = row(w, 1);
        assert.ok(r.hasAttribute('data-swipe'));
        swipe(w, r.querySelector('.ui-alert-text'), [[dx / 4, 0], [dx / 2, 1], [dx, 2]]);
        assert.equal(r.style.transform, `translateX(${dx < 0 ? '-' : ''}100%)`, `${dx}: the row goes out on its side`);
        await flush();
        assert.deepEqual(w.dismissed, [1], `${dx}`);
        assert.equal(row(w, 1), null);
        assert.ok(row(w, 2), 'the other alert stays');
    }
});

test('the row follows the finger, and a shorter swipe slides back', async () => {
    const w = page();
    draw(w, [alert(1)]);
    const r = row(w, 1);
    const fire = (name, x) => r.dispatchEvent(new w.PointerEvent(name, { bubbles: true, pointerId: 1, pointerType: 'touch', clientX: x, clientY: 20 }));
    fire('pointerdown', 150);
    fire('pointermove', 110);
    assert.equal(r.style.transform, 'translateX(-40px)');
    fire('pointermove', 90);
    fire('pointerup', 90);
    assert.equal(r.style.transform, '');
    assert.match(r.style.transition, /transform 0?\.2s/); // jsdom 31 serializes .2s as 0.2s, as browsers do
    await flush();
    assert.deepEqual(w.dismissed, []);
});

test('a move that starts up or down is left to scrolling', async () => {
    const w = page();
    draw(w, [alert(1)]);
    const r = row(w, 1);
    swipe(w, r, [[3, 20], [150, 30]]);
    assert.equal(r.style.transform, '');
    await flush();
    assert.deepEqual(w.dismissed, []);
});

test('only a touch swipe of a row with a shown, enabled X moves; a check does not', async () => {
    const w = page();
    draw(w, [alert(1)]);
    swipe(w, row(w, 1), [[-60, 0], [-150, 0]], { type: 'mouse' });
    assert.equal(row(w, 1).style.transform, '', 'a mouse drag');
    row(w, 1).querySelector('.ui-alert-x').classList.add('hidden');
    swipe(w, row(w, 1), [[-60, 0], [-150, 0]]);
    assert.equal(row(w, 1).style.transform, '', 'no access: the X is hidden');
    row(w, 1).querySelector('.ui-alert-x').classList.remove('hidden');
    row(w, 1).querySelector('.ui-alert-x').disabled = true;
    swipe(w, row(w, 1), [[-60, 0], [-150, 0]]);
    assert.equal(row(w, 1).style.transform, '', 'busy: the X is off');
    await flush();
    assert.deepEqual(w.dismissed, []);
    w.eval(`attention.checks.items.blocklist = [{ tone: 'fail', title: 'Listed', detail: 'd', action: 'Check listing', onclick: 'void 0' }]`);
    w.document.getElementById('list').innerHTML = w.attentionCheckRows('dashboard');
    const check = w.document.querySelector('#list .ui-alert');
    assert.equal(check.hasAttribute('data-swipe'), false);
    swipe(w, check, [[-60, 0], [-150, 0]]);
    assert.equal(check.style.transform, '');
});

test('a dismiss that does not go through brings the row back', async () => {
    const w = page();
    w.fail = true;
    draw(w, [alert(1)]);
    const r = row(w, 1);
    swipe(w, r, [[-60, 0], [-150, 0]]);
    assert.equal(r.style.transform, 'translateX(-100%)');
    await flush();
    await flush();
    assert.deepEqual(w.dismissed, [1]);
    assert.equal(r.style.transform, '', 'back in place');
    assert.equal(r.style.opacity, '');
});

test('the click a swipe ends with does not open the row; a later click does', async () => {
    const w = page();
    w.fail = true;
    draw(w, [alert(1)]);
    const r = row(w, 1);
    swipe(w, r, [[-30, 0], [-50, 0]]);
    r.querySelector('.ui-alert-text').click();
    assert.equal(w.opened, undefined, 'the click right after a swipe');
    w.eval('uiSwipeEndedAt = 0');
    r.querySelector('.ui-alert-text').click();
    assert.equal(w.opened, 1, 'a click on its own');
});

test('the row slides back with its animation under reduced motion too', () => {
    const w = page({ still: true });
    draw(w, [alert(1)]);
    const r = row(w, 1);
    swipe(w, r, [[-30, 0], [-50, 0]]);
    assert.equal(r.style.transform, '');
    assert.match(r.style.transition, /transform 0?\.2s/); // jsdom 31 serializes .2s as 0.2s, as browsers do
});
