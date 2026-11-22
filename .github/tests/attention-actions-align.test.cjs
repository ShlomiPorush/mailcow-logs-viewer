// On screens wider than a phone, an alert row in the Dashboard's Needs attention puts its X
// and its button in one column at the row's end, the X on top, so every button ends at the
// same edge as the button of a row without an X (a check such as "Read changes"). The bell
// (no buttons) and phones (buttons under the text) keep their layout.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const css = fs.readFileSync(path.join(__dirname, '../../frontend/assets/css/ui.css'), 'utf8');
const row = '#dashboard-attention-panel .ui-alert:has(> .ui-alert-x)';

function wideBlock() {
    const marker = `${row} { display: grid;`;
    const at = css.indexOf(marker);
    assert.ok(at >= 0, 'no wide-screen rule for alert rows with an X');
    const open = css.lastIndexOf('@media', at);
    return { open, at, head: css.slice(open, css.indexOf('{', open)) };
}

test('wider than a phone, the X and the button share the end column, the X on top', () => {
    const { head } = wideBlock();
    assert.equal(head.trim(), '@media screen and (min-width: 761px)');
    assert.ok(css.includes(`${row} { display: grid; grid-template-columns: minmax(0, 1fr) auto; column-gap: 14px; row-gap: 6px; }`));
    assert.ok(css.includes(`${row} > .ui-alert-text { grid-column: 1; grid-row: 1 / span 2; }`));
    assert.ok(css.includes(`${row} > .ui-alert-x { grid-column: 2; grid-row: 1; justify-self: end; }`));
    assert.ok(css.includes(`${row} > .ui-alert-acts { grid-column: 2; grid-row: 2; justify-self: end; align-self: center; }`));
});

test('the rule comes after the bell and phone grid, which it overrides at equal specificity', () => {
    const { at } = wideBlock();
    assert.ok(at > css.indexOf(':is(#dashboard-attention-panel, .ui-attn-win, #attn-sheet) .ui-alert:has(> .ui-alert-x) > :not(.ui-alert-x) { grid-column: 1; }'));
    assert.ok(at > css.indexOf(':is(#dashboard-attention-panel, .ui-attn-win, #attn-sheet) .ui-alert > .ui-alert-x { grid-column: 2; grid-row: 1; }'));
});
