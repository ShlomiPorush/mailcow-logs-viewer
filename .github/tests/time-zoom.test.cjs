// The time zoom of the bar charts (utils.js): the button steps, and the gesture
// state machine driven with pointer events on a stand-in chart
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const utils = fs.readFileSync(path.join(__dirname, '../../frontend/utils.js'), 'utf8');
const code = utils.slice(utils.indexOf('function uiTimeZoomClamp('), utils.indexOf('// Phones: every dialog opens like the help sheet'));
const H = 3600000;

function load() {
    const context = vm.createContext({ setTimeout, clearTimeout, Math, Number });
    vm.runInContext(code, context);
    return context;
}

// A chart 240px wide at x 0, with 24 bars of an hour each from 0
function chart({ span = { from: 0, to: 24 * H }, limits = { from: 0, to: 24 * H, min: H } } = {}) {
    const listeners = {};
    const bars = Array.from({ length: 24 }, (_, i) => ({
        dataset: { start: String(i * H), end: String((i + 1) * H) },
        getBoundingClientRect: () => ({ left: i * 10, right: i * 10 + 10 }),
    }));
    const box = {
        captured: new Set(),
        addEventListener: (type, fn) => { listeners[type] = fn; },
        removeEventListener: type => { delete listeners[type]; },
        getBoundingClientRect: () => ({ left: 0, width: 240 }),
        setPointerCapture(id) { this.captured.add(id); },
    };
    const seen = { previews: [], changes: [], cancels: 0 };
    const zoom = load().uiTimeZoom(box, {
        bars: () => bars,
        span: () => span,
        limits: () => limits,
        preview: (s, kind) => seen.previews.push([kind, s]),
        change: s => seen.changes.push(s),
        cancel: () => { seen.cancels++; },
    });
    const fire = (type, props) => listeners[type]({ pointerType: 'touch', button: 0, target: box, preventDefault() {}, stopPropagation() {}, ...props });
    return { fire, seen, zoom, box, bars };
}

test('the buttons step in, out, earlier and later, and stay inside the data', () => {
    const c = load();
    const limits = { from: 0, to: 24 * H, min: H };
    const plain = o => JSON.parse(JSON.stringify(o));
    assert.deepEqual(plain(c.uiTimeZoomStep({ from: 0, to: 24 * H }, limits, 'in')), { from: 6 * H, to: 18 * H });
    assert.deepEqual(plain(c.uiTimeZoomStep({ from: 6 * H, to: 18 * H }, limits, 'out')), { from: 0, to: 24 * H });
    assert.deepEqual(plain(c.uiTimeZoomStep({ from: 6 * H, to: 18 * H }, limits, 'earlier')), { from: 0, to: 12 * H });
    assert.deepEqual(plain(c.uiTimeZoomStep({ from: 12 * H, to: 24 * H }, limits, 'later')), { from: 12 * H, to: 24 * H });
    // Never shorter than the shortest span, never longer than the data
    assert.deepEqual(plain(c.uiTimeZoomStep({ from: 0, to: H }, limits, 'in')), { from: 0, to: H });
    assert.deepEqual(plain(c.uiTimeZoomClamp({ from: -5 * H, to: 40 * H }, limits)), { from: 0, to: 24 * H });
});

test('a drag across bars zooms to them; a press without a move is left as a click', () => {
    const { fire, seen } = chart();
    fire('pointerdown', { pointerId: 1, pointerType: 'mouse', clientX: 45, clientY: 50 });
    fire('pointermove', { pointerId: 1, pointerType: 'mouse', clientX: 75, clientY: 51 });
    fire('pointerup', { pointerId: 1, pointerType: 'mouse', clientX: 75, clientY: 51 });
    assert.deepEqual(JSON.parse(JSON.stringify(seen.changes)), [{ from: 4 * H, to: 8 * H }]);
    const click = chart();
    click.fire('pointerdown', { pointerId: 1, clientX: 45, clientY: 50 });
    click.fire('pointerup', { pointerId: 1, clientX: 46, clientY: 50 });
    assert.equal(click.seen.changes.length, 0);
    assert.equal(click.zoom.busy(), false);
});

test('a finger going mostly up or down leaves the page to scroll', () => {
    const { fire, seen, zoom } = chart({ span: { from: 6 * H, to: 12 * H } });
    fire('pointerdown', { pointerId: 1, clientX: 100, clientY: 50 });
    fire('pointermove', { pointerId: 1, clientX: 103, clientY: 90 });
    assert.equal(zoom.busy(), false);
    assert.equal(seen.previews.length, 0);
});

test('a zoomed chart moves under one finger, though the bar hands its own capture over to the chart', () => {
    const { fire, seen, zoom, bars } = chart({ span: { from: 6 * H, to: 12 * H } });
    fire('pointerdown', { pointerId: 7, clientX: 60, clientY: 50, target: bars[6] });
    fire('pointermove', { pointerId: 7, clientX: 80, clientY: 51, target: bars[6] });
    // The bar under the finger had the touch's implicit capture; it bubbles up as it goes
    fire('lostpointercapture', { pointerId: 7, target: bars[6] });
    assert.equal(zoom.busy(), true, 'the move goes on');
    fire('pointermove', { pointerId: 7, clientX: 120, clientY: 51 });
    fire('pointerup', { pointerId: 7, clientX: 120, clientY: 51 });
    assert.equal(seen.cancels, 0);
    assert.equal(seen.changes.length, 1);
    // 60px of 240 is a quarter of the 6 hours shown: an hour and a half earlier
    assert.deepEqual(JSON.parse(JSON.stringify(seen.changes[0])), { from: 4.5 * H, to: 10.5 * H });
});

test('the chart losing a finger mid-move calls the move off', () => {
    const { fire, seen, zoom, box } = chart({ span: { from: 6 * H, to: 12 * H } });
    fire('pointerdown', { pointerId: 7, clientX: 60, clientY: 50 });
    fire('pointermove', { pointerId: 7, clientX: 80, clientY: 51 });
    fire('lostpointercapture', { pointerId: 7, target: box });
    assert.equal(seen.cancels, 1);
    assert.equal(zoom.busy(), false);
    assert.equal(seen.changes.length, 0);
});

test('two fingers apart zoom in around them; lifting one goes on as a move without a jump', () => {
    const { fire, seen } = chart();
    fire('pointerdown', { pointerId: 1, clientX: 100, clientY: 50 });
    fire('pointerdown', { pointerId: 2, clientX: 140, clientY: 50 });
    fire('pointermove', { pointerId: 1, clientX: 80, clientY: 50 });
    fire('pointermove', { pointerId: 2, clientX: 160, clientY: 50 });
    const pinch = seen.previews.at(-1);
    assert.equal(pinch[0], 'pinch');
    // Twice as far apart: half the span, the time under their middle (12:00) stays under it
    assert.equal(pinch[1].to - pinch[1].from, 12 * H);
    assert.equal(pinch[1].from + (120 / 240) * 12 * H, 12 * H);
    fire('pointerup', { pointerId: 2, clientX: 160, clientY: 50 });
    assert.equal(seen.changes.length, 0, 'one finger is still down');
    fire('pointermove', { pointerId: 1, clientX: 80, clientY: 50 });
    assert.deepEqual(seen.previews.at(-1)[1], pinch[1], 'no jump when a finger lifts');
    fire('pointerup', { pointerId: 1, clientX: 80, clientY: 50 });
    assert.equal(seen.changes.length, 1);
});

test('the click that ends a gesture does not pick a bar', () => {
    const { fire } = chart();
    fire('pointerdown', { pointerId: 1, pointerType: 'mouse', clientX: 45, clientY: 50 });
    fire('pointermove', { pointerId: 1, pointerType: 'mouse', clientX: 75, clientY: 50 });
    fire('pointerup', { pointerId: 1, pointerType: 'mouse', clientX: 75, clientY: 50 });
    let stopped = false;
    fire('click', { stopPropagation() { stopped = true; } });
    assert.equal(stopped, true);
    stopped = false;
    fire('click', { stopPropagation() { stopped = true; } });
    assert.equal(stopped, false, 'the next click picks as usual');
});
