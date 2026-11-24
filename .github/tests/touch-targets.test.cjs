const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');
const css = fs.readFileSync(path.join(frontend, 'assets/css/ui.css'), 'utf8');
const html = fs.readFileSync(path.join(frontend, 'index.html'), 'utf8');
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

test('on a touch screen the controls keep their size; only the tiny ones grow', () => {
    const touch = media('(pointer: coarse)');
    assert.doesNotMatch(touch, /--ui-ctl-h/);
    assert.doesNotMatch(touch, /44px/);
    assert.match(touch, /\.ui-sec-chip button, \.ui-set-clear \{ min-width: 24px; min-height: 24px; \}/);
    assert.match(touch, /input\[type="checkbox"\]:not\(:is\(\.ui-set-bool, \.ui-feature\) \.ui-check\)[^{]*\{[^}]*min-width: 20px; min-height: 20px/);
});

test('on a phone Sign out is in the More sheet, not beside the theme switch', () => {
    assert.match(css, /\.ui-mtop-actions \.ui-utilities > :not\(#theme-toggle\) \{ display: none; \}/);
    assert.match(html, /id="mobile-logout" class="mobile-menu-item ui-mobile-logout hidden"/);
    assert.match(css, /\.hidden\[class\*="ui-"\] \{ display: none !important; \}/);
    assert.match(html, /onclick="closeMobileMenu\(\); handleLogout\(\)" id="mobile-logout"/);
});

test('on a tablet the rail names each page under its icon', () => {
    const rail = media('(min-width: 761px) and (max-width: 1100px)');
    assert.match(rail, /\.ui-sidenav \.ui-nav-label[^{]*\{[^}]*display: block/);
});
