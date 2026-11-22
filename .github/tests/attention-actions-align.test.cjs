// On screens wider than a phone, every row of the Dashboard's Needs attention keeps an X's
// slot at its end (24px and the 8px gap): an alert's X sits in it, after the button and
// centered in the row, and a row without one (a check such as "Read changes", or an alert
// the person may not dismiss) leaves it empty. So every button ends at one edge and every X
// at the row's end. The X comes after the button in the markup too, so the keyboard meets
// them in the order the eye does. The bell (no buttons) and phones keep their layout.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');
const css = fs.readFileSync(path.join(frontend, 'assets/css/ui.css'), 'utf8');
const app = fs.readFileSync(path.join(frontend, 'app.js'), 'utf8');

const SLOT = '#dashboard-attention-panel .ui-alert { padding-inline-end: calc(var(--ui-pad-x) + 32px); }';
const X = '#dashboard-attention-panel .ui-alert > .ui-alert-x { align-self: center; margin-block: 0; margin-inline-end: -32px; }';
// The gap between the button and the X: the rows with an X use 8px (the bell and phone grid rule)
const GAP = ':is(#dashboard-attention-panel, .ui-attn-win, #attn-sheet) .ui-alert:has(> .ui-alert-x) { grid-template-columns: minmax(0, 1fr) auto; column-gap: 8px; }';

test('wider than a phone, every row keeps the X\'s slot and the X sits in it, centered', () => {
    const at = css.indexOf(SLOT);
    assert.ok(at >= 0, 'no slot for the X at the end of every row');
    const media = css.lastIndexOf('@media', at);
    assert.equal(css.slice(media, css.indexOf('{', media)).trim(), '@media screen and (min-width: 761px)');
    assert.ok(css.indexOf(X) > at, 'the X moves into the slot (24px + the 8px gap = 32px)');
    assert.ok(css.includes(GAP));
    assert.ok(css.indexOf(X) > css.indexOf('.ui-alert > .ui-alert-x { width: 24px; height: 24px; flex: none; align-self: flex-start;'));
    // Neither earlier try: the X above the button, or the X before it
    assert.doesNotMatch(css, /#dashboard-attention-panel \.ui-alert:has\(> \.ui-alert-x\) \{ display: grid;/);
    assert.doesNotMatch(css, /\.ui-alert-x \+ \.ui-alert-acts/);
    // A long address in a title breaks rather than running into the button
    assert.ok(css.includes('.ui-alert-title b { overflow-wrap: anywhere; }'));
});

test('the X comes after the row\'s buttons in the markup', () => {
    const at = app.indexOf('function attentionAlertRows(');
    const body = app.slice(at, app.indexOf('\n}', at));
    const x = body.indexOf('class="ui-icon-btn ui-icon-btn-sm ui-alert-x"');
    const acts = body.indexOf('<div class="ui-alert-acts">');
    assert.ok(x > 0 && acts > 0 && acts < x, 'the buttons, then the X');
});
