// The keyboard's place is always visible (ui.css): the app's focus ring applies
// everywhere at zero specificity, and the menu items keep a ring of their own
// instead of only a faint tint.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const css = fs.readFileSync(path.join(__dirname, '../../frontend/assets/css/ui.css'), 'utf8');
const rule = selector => {
    const at = css.indexOf(`${selector} {`);
    assert.ok(at >= 0, `${selector} has a rule`);
    return css.slice(at, css.indexOf('}', at));
};

test('the focus ring applies app-wide, not only under a .ui class nothing has', () => {
    assert.match(rule(':where(:focus-visible)'), /outline: 2px solid var\(--ui-focus\)/);
    assert.doesNotMatch(css, /:where\(\.ui\) :focus-visible/);
});

test('the focus colour is set for the light and the dark theme', () => {
    assert.match(css, /:root \{[^}]*--ui-focus:/);
    assert.match(css, /\.dark \{[^}]*--ui-focus:/);
});

test('menu and flyout items show the ring when the keyboard is on them', () => {
    for (const selector of ['.ui-menu button:focus-visible', '.ui-fly-item:focus-visible']) {
        const body = rule(selector);
        assert.doesNotMatch(body, /outline: none/, selector);
        assert.match(body, /outline: 2px solid var\(--ui-focus\)/, selector);
    }
});

test('hovering a menu or flyout item does not take the keyboard ring away', () => {
    // The hover rules come later in the file with outline: none; they must skip a focused item
    assert.match(css, /\.ui-menu button:hover:not\(:focus-visible\) \{[^}]*outline: none/);
    assert.match(css, /\.ui-fly-item:hover:not\(:focus-visible\) \{[^}]*outline: none/);
    assert.doesNotMatch(css, /\.ui-menu button:hover \{/);
    assert.doesNotMatch(css, /\.ui-fly-item:hover \{/);
});
