// The overview strip under a zoomable chart (utils.js uiTimeOverview): the
// window's moves, its edges' bounds and snapping, the hour of the app's zone,
// and the two edges as sliders for the keyboard, on a stand-in strip
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const utils = fs.readFileSync(path.join(__dirname, '../../frontend/utils.js'), 'utf8');
const zoneHelpers = utils.slice(utils.indexOf('function appTz()'), utils.indexOf('function formatSeconds('));
const code = utils.slice(utils.indexOf('// The span a drag of the window by dt makes'), utils.indexOf('// Phones: every dialog opens like the help sheet'));
const H = 3600000, Q = 15 * 60000;
const plain = o => JSON.parse(JSON.stringify(o));

// A stand-in for the few DOM calls the strip makes
function fakeElement(tag = 'div') {
    const attrs = {}, listeners = {}, children = [];
    const el = {
        tagName: tag.toUpperCase(), className: '', dataset: {}, style: {}, tabIndex: -1, children, parent: null,
        setAttribute: (k, v) => { attrs[k] = String(v); }, getAttribute: k => (k in attrs ? attrs[k] : null),
        append: (...nodes) => nodes.forEach(n => { n.parent = el; children.push(n); }),
        remove: () => { if (el.parent) el.parent.children.splice(el.parent.children.indexOf(el), 1); },
        querySelectorAll: sel => children.filter(c => sel.split(',').some(s => c.className.split(' ').includes(s.trim().replace('.', '')))),
        closest: sel => (el.className.split(' ').includes(sel.replace('.', '')) ? el : null),
        addEventListener: (type, fn) => { listeners[type] = fn; }, removeEventListener: type => { delete listeners[type]; },
        getBoundingClientRect: () => ({ left: 0, width: 240 }), setPointerCapture() {},
        fire: (type, props) => listeners[type]({ preventDefault() {}, ...props }),
    };
    return el;
}

function load(appTimezone = 'UTC') {
    const context = vm.createContext({ setTimeout, clearTimeout, Math, Number, Date, Intl, appTimezone, document: { createElement: fakeElement } });
    vm.runInContext(zoneHelpers + '\n' + code, context);
    return context;
}

test('the window moves inside the limits, keeps its length, and snaps', () => {
    const c = load();
    const limits = { from: 0, to: 24 * H, min: H };
    const hour = t => Math.round(t / H) * H;
    assert.deepEqual(plain(c.uiOverviewMove({ from: 4 * H, to: 8 * H }, 2.4 * H, limits, hour)), { from: 6 * H, to: 10 * H });
    // Pushed past an end: it stops there, same length
    assert.deepEqual(plain(c.uiOverviewMove({ from: 4 * H, to: 8 * H }, -9 * H, limits, hour)), { from: 0, to: 4 * H });
    assert.deepEqual(plain(c.uiOverviewMove({ from: 4 * H, to: 8 * H }, 30 * H, limits, hour)), { from: 20 * H, to: 24 * H });
    // Centered at a time
    assert.deepEqual(plain(c.uiOverviewCenter({ from: 0, to: 4 * H }, 12 * H, limits, hour)), { from: 10 * H, to: 14 * H });
});

test('an edge keeps the shortest span from the other one, and the end of the data is an edge too', () => {
    const c = load();
    // The data ends at 10:07, inside a quarter
    const limits = { from: 0, to: 10 * H + 7 * 60000, min: H };
    const quarter = t => (t >= limits.to - 1 ? limits.to : Math.round(t / Q) * Q);
    const span = { from: 6 * H, to: 9 * H };
    assert.deepEqual(plain(c.uiOverviewEdge(span, 'start', 8.6 * H, limits, quarter)), { from: 8 * H, to: 9 * H });
    assert.deepEqual(plain(c.uiOverviewEdge(span, 'end', 6.2 * H, limits, quarter)), { from: 6 * H, to: 7 * H });
    assert.deepEqual(plain(c.uiOverviewEdge(span, 'end', 99 * H, limits, quarter)), { from: 6 * H, to: limits.to });
    // A snap that would round past the data's end stays at the end
    assert.deepEqual(plain(c.uiOverviewEdge(span, 'end', 10 * H + 6 * 60000, limits, t => Math.round(t / Q) * Q)), { from: 6 * H, to: 10 * H });
    assert.deepEqual(plain(c.uiOverviewEdge(span, 'start', -5 * H, limits, quarter)), { from: 0, to: 9 * H });
});

test('the nearest whole hour is the app zone\'s, also half an hour off and on the night the clocks change', () => {
    assert.equal(load('UTC').uiNearestLocalHour(Date.parse('2026-10-21T10:29:00Z')), Date.parse('2026-10-21T10:00:00Z'));
    assert.equal(load('UTC').uiNearestLocalHour(Date.parse('2026-10-21T10:31:00Z')), Date.parse('2026-10-21T11:00:00Z'));
    // Kolkata is UTC+5:30: its whole hours fall on :30 UTC
    assert.equal(load('Asia/Kolkata').uiNearestLocalHour(Date.parse('2026-10-21T10:20:00Z')), Date.parse('2026-10-21T10:30:00Z'));
    // Berlin, 25 October 2026: 03:00 CEST becomes 02:00 CET at 01:00 UTC
    const berlin = load('Europe/Berlin');
    assert.equal(berlin.uiNearestLocalHour(Date.parse('2026-10-25T00:50:00Z')), Date.parse('2026-10-25T01:00:00Z'));
    assert.equal(berlin.uiNearestLocalHour(Date.parse('2026-10-25T01:10:00Z')), Date.parse('2026-10-25T01:00:00Z'));
});

test('the two edges are sliders: their values and bounds, arrows, Home and End, asked once a moment after the last key', async () => {
    const c = load();
    const box = fakeElement();
    let span = { from: 6 * H, to: 12 * H };
    const limits = { from: 0, to: 24 * H, min: H };
    const changes = [];
    c.__box = box;
    c.__opts = {
        limits: () => limits, span: () => span, snap: t => Math.round(t / H) * H,
        step: (t, dir, big) => t + dir * (big ? 6 : 1) * H, label: t => `${t / H}:00`,
        change: next => { changes.push(next); span = next; },
    };
    const strip = vm.runInContext('uiTimeOverview(__box, __opts)', c);
    const [, start, end] = box.children;
    assert.equal(start.getAttribute('role'), 'slider');
    assert.equal(start.getAttribute('aria-label'), 'Start of the span shown');
    assert.equal(start.getAttribute('aria-valuetext'), '6:00');
    // The start goes no later than the end less the shortest span, the end no earlier than the start plus it
    assert.equal(start.getAttribute('aria-valuemax'), String(11 * H));
    assert.equal(end.getAttribute('aria-valuemin'), String(7 * H));
    box.fire('keydown', { target: start, key: 'ArrowRight' });
    box.fire('keydown', { target: start, key: 'ArrowRight' });
    assert.equal(start.getAttribute('aria-valuetext'), '8:00', 'drawn at once');
    assert.equal(strip.busy(), true);
    assert.equal(changes.length, 0, 'not asked yet');
    await new Promise(r => setTimeout(r, 400));
    assert.deepEqual(plain(changes), [{ from: 8 * H, to: 12 * H }], 'asked once');
    box.fire('keydown', { target: end, key: 'Home' });
    await new Promise(r => setTimeout(r, 400));
    assert.deepEqual(plain(changes.at(-1)), { from: 8 * H, to: 9 * H }, 'Home takes the end only as far as the shortest span');
    box.fire('keydown', { target: start, key: 'End' });
    await new Promise(r => setTimeout(r, 400));
    assert.deepEqual(plain(changes.at(-1)), { from: 8 * H, to: 9 * H }, 'End takes the start no further either');
    strip.destroy();
});

test('a drag of the window moves it; a press beside it centers it there; a mostly vertical drag is left to the page', () => {
    const c = load();
    const box = fakeElement();
    let span = { from: 0, to: 6 * H };
    const limits = { from: 0, to: 24 * H, min: H };
    const changes = [];
    c.__box = box;
    c.__opts = { limits: () => limits, span: () => span, snap: t => Math.round(t / H) * H, step: t => t, label: String,
        change: next => { changes.push(next); span = next; } };
    vm.runInContext('uiTimeOverview(__box, __opts)', c);
    const win = box.children[0];
    // 240px for 24 hours: 10px an hour; drag the window 40px right
    box.fire('pointerdown', { target: win, pointerId: 1, pointerType: 'mouse', button: 0, clientX: 30, clientY: 10 });
    box.fire('pointermove', { pointerId: 1, clientX: 70, clientY: 11 });
    box.fire('pointerup', { pointerId: 1, clientX: 70, clientY: 11 });
    assert.deepEqual(plain(changes.at(-1)), { from: 4 * H, to: 10 * H });
    box.fire('pointerdown', { target: box, pointerId: 2, pointerType: 'mouse', button: 0, clientX: 200, clientY: 10 });
    box.fire('pointerup', { pointerId: 2, clientX: 200, clientY: 10 });
    assert.deepEqual(plain(changes.at(-1)), { from: 17 * H, to: 23 * H });
    box.fire('pointerdown', { target: win, pointerId: 3, pointerType: 'touch', button: 0, clientX: 190, clientY: 10 });
    box.fire('pointermove', { pointerId: 3, clientX: 193, clientY: 40 });
    box.fire('pointerup', { pointerId: 3, clientX: 193, clientY: 40 });
    assert.equal(changes.length, 2, 'the page scrolled, nothing moved');
});
