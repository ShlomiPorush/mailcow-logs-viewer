// A finger needs a bigger target than a mouse pointer (ui.css): on a touch screen
// every control is at least 44px (WCAG 2.5.5) and a checkbox 24px (WCAG 2.5.8);
// on a phone, Sign out is in the More sheet, away from the top bar's theme switch;
// on a tablet the icon rail names each page under its icon.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');
const css = fs.readFileSync(path.join(frontend, 'assets/css/ui.css'), 'utf8');
const html = fs.readFileSync(path.join(frontend, 'index.html'), 'utf8');
// The body of an @media block, from its opening brace to the matching closing one
function media(query) {
    const start = css.indexOf(`@media ${query} {`);
    assert.ok(start !== -1, `ui.css has @media ${query}`);
    let depth = 0;
    for (let i = css.indexOf('{', start); i < css.length; i++) {
        if (css[i] === '{') depth++;
        if (css[i] === '}' && --depth === 0) return css.slice(start, i);
    }
    throw new Error('unclosed block');
}

test('on a touch screen the controls and checkboxes are big enough for a finger', () => {
    const touch = media('(pointer: coarse)');
    assert.match(touch, /--ui-ctl-h: 44px/);
    for (const selector of ['.ui-btn-sm', '.ui-chip', '.ui-seg button']) assert.ok(touch.includes(selector), selector);
    assert.match(touch, /\.ui-icon-btn[^{]*\{[^}]*min-width: 44px; min-height: 44px/);
    assert.match(touch, /input\[type="checkbox"\][^{]*\{[^}]*min-width: 24px; min-height: 24px/);
});

test('on a phone Sign out is in the More sheet, not beside the theme switch', () => {
    assert.match(css, /\.ui-mtop-actions \.ui-utilities > :not\(#theme-toggle\) \{ display: none; \}/);
    assert.match(html, /id="mobile-logout" class="mobile-menu-item hidden"/);
    assert.match(html, /onclick="closeMobileMenu\(\); handleLogout\(\)" id="mobile-logout"/);
});

test('on a tablet the rail names each page under its icon', () => {
    const rail = media('(min-width: 761px) and (max-width: 1100px)');
    assert.match(rail, /\.ui-sidenav \.ui-nav-label[^{]*\{[^}]*display: block/);
});
