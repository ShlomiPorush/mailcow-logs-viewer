// On screens wider than a phone, an alert row in the Dashboard's Needs attention puts its X
// just before its button, both centered in the row, so every button ends at the same edge as
// the button of a row without an X (a check such as "Read changes"); an X with no button sits
// at that edge. The X comes before the button in the markup too, so the keyboard meets them
// in the order the eye does. The bell (no buttons) and phones (buttons under the text) keep
// their layout.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');
const css = fs.readFileSync(path.join(frontend, 'assets/css/ui.css'), 'utf8');
const app = fs.readFileSync(path.join(frontend, 'app.js'), 'utf8');

const X = '#dashboard-attention-panel .ui-alert > .ui-alert-x { align-self: center; margin-block: 0; }';

test('wider than a phone, the X sits just before the button, both centered in the row', () => {
    const at = css.indexOf(X);
    assert.ok(at >= 0, 'no wide-screen rule for the X');
    assert.equal(css.slice(css.lastIndexOf('@media', at), css.indexOf('{', css.lastIndexOf('@media', at))).trim(), '@media screen and (min-width: 761px)');
    // The row's own 8px gap (the bell and phone grid rule) keeps the X close to the button
    assert.ok(css.includes(':is(#dashboard-attention-panel, .ui-attn-win, #attn-sheet) .ui-alert:has(> .ui-alert-x) { grid-template-columns: minmax(0, 1fr) auto; column-gap: 8px; }'));
    // Not the end column of D14's first try (the X above the button)
    assert.doesNotMatch(css, /#dashboard-attention-panel \.ui-alert:has\(> \.ui-alert-x\) \{ display: grid;/);
    assert.doesNotMatch(css, /> \.ui-alert-acts \{ grid-column: 2; grid-row: 2;/);
    // After the base rule it overrides (the X at the top, beside the title)
    assert.ok(at > css.indexOf('.ui-alert > .ui-alert-x { width: 24px; height: 24px; flex: none; align-self: flex-start;'));
    // A long address in a title breaks rather than running into the X beside it
    assert.ok(css.includes('.ui-alert-title b { overflow-wrap: anywhere; }'));
});

test('the X comes just before the row\'s buttons in the markup', () => {
    const at = app.indexOf('function attentionAlertRows(');
    const body = app.slice(at, app.indexOf('\n}', at));
    const x = body.indexOf('class="ui-icon-btn ui-icon-btn-sm ui-alert-x"');
    const acts = body.indexOf('<div class="ui-alert-acts">');
    assert.ok(x > 0 && acts > 0 && x < acts, 'the X before the buttons');
    assert.ok(x > body.indexOf('<div class="ui-alert-text">'), 'after the text');
});
