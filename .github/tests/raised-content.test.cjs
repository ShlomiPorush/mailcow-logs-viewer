// The page sits in its own raised panel next to the side menu, on screens wider than a
// phone (ui.css, the last block): the window, the top bar and the side menu on the page
// tone (--ui-page), the page under the bar on the page's surface (--ui-bg) with a thin
// edge, rounded top corners and a gap at the far side. The colors, edge and radius are the
// existing tokens; the dark page tone is a shade derived from --ui-bg, not a new color.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const css = fs.readFileSync(path.join(__dirname, '../../frontend/assets/css/ui.css'), 'utf8');

// The panel's block: the one with the page tone on the body (other blocks share the query)
const PANEL = 'body, .ui-sidenav { background: var(--ui-page); }';

function panelStart(query) {
    const marker = css.indexOf(PANEL);
    assert.ok(marker >= 0, 'no panel rules');
    return css.lastIndexOf(`@media ${query} {`, marker);
}

function block(query) {
    const at = panelStart(query);
    assert.ok(at >= 0, `no @media ${query} block`);
    let depth = 0;
    for (let i = css.indexOf('{', at); i < css.length; i++) {
        if (css[i] === '{') depth++;
        if (css[i] === '}' && --depth === 0) return css.slice(at, i + 1);
    }
    throw new Error('unclosed block');
}

test('the page tone is an existing color in light and a shade of the page in dark', () => {
    const light = css.slice(css.indexOf(':root {'), css.indexOf('}', css.indexOf(':root {')));
    const dark = css.slice(css.indexOf('.dark {'), css.indexOf('}', css.indexOf('.dark {')));
    assert.match(light, /--ui-page: var\(--ui-panel\);/);
    assert.match(dark, /--ui-page: color-mix\(in srgb, var\(--ui-bg\) 60%, #000\);/);
});

test('only screens wider than a phone get the panel, from the existing tokens', () => {
    const panel = block('screen and (min-width: 761px)');
    assert.doesNotMatch(panel, /#[0-9a-fA-F]{3,8}\b|rgb\(/, 'no new color');
    assert.match(panel, /body, \.ui-sidenav \{ background: var\(--ui-page\); \}/);
    assert.match(panel, /html\.ui-has-topbar \.ui-topbar \{ background: var\(--ui-page\); border-bottom: 0; \}/);
    // The search box and the bell read as fields on the page tone
    assert.match(panel, /\.ui-topbar \.ui-gs-box, \.ui-topbar \.ui-bell \{ background: var\(--ui-bg\); \}/);
    assert.match(panel, /\.ui-sidenav \.ui-server \{ background: var\(--ui-bg\); \}/);
    // The panel: the page's surface, a hairline on top and both sides, rounded top corners, a gap at the far side
    assert.match(panel, /\.ui-main \{ margin-inline-end: 8px; background: var\(--ui-bg\); border: 1px solid var\(--ui-line\); border-bottom: 0;\s*border-start-start-radius: var\(--ui-radius\); border-start-end-radius: var\(--ui-radius\); \}/);
    assert.doesNotMatch(panel, /box-shadow: 0 [1-9]/, 'a hairline, no shadow');
    // Messages has no top bar: its panel starts just below the window's top
    assert.match(panel, /html:not\(\.ui-has-topbar\) \.ui-main \{ margin-block-start: 8px; height: calc\(100vh - 8px\); height: calc\(100dvh - 8px\); \}/);
});

test('the panel block comes after the rules it overrides', () => {
    const at = panelStart('screen and (min-width: 761px)');
    assert.ok(at > css.indexOf('html.ui-has-topbar .ui-topbar { grid-area: top;'));
    assert.ok(at > css.lastIndexOf('.ui-main { display: flex;'));
    assert.ok(at > css.indexOf('.ui-gs-box { display: flex;'));
});
