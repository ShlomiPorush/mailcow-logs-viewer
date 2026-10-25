// The API reference at /docs (frontend/api-docs.html, api-docs.js) draws
// /openapi.json with the local Scalar bundle. Scalar can talk to scalar.com in
// several ways: an AI agent that uploads the document, a hosted client the
// document's address is sent to, a request proxy, developer tools, telemetry
// and web fonts. The CSP does not stop a link that opens a new tab, so the
// page must turn each of them off itself.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const FRONTEND = path.join(__dirname, '..', '..', 'frontend');
const LIBS = path.join(FRONTEND, 'assets', 'libs');
// An element the bundle starts a reference of its own on, however the id is written
const SECOND_REFERENCE_ID = /\bid\s*=\s*["']?api-reference(?=["'\s>/])/i;

// Each comment becomes a space, not nothing, so the pieces around a removed
// comment cannot join into a new "<!--" that hides real markup
function withoutComments(html) {
    return html.replace(/<!--[\s\S]*?-->/g, ' ');
}

// Runs api-docs.js and returns what it passed to Scalar
function scalarCall(dark) {
    const calls = [];
    const context = vm.createContext({
        document: { documentElement: { classList: { contains: name => name === 'dark' && dark } } },
        Scalar: { createApiReference: (target, options) => calls.push({ target, options }) },
    });
    vm.runInContext(fs.readFileSync(path.join(FRONTEND, 'api-docs.js'), 'utf8'), context);
    assert.equal(calls.length, 1);
    return calls[0];
}

test('the reference reads this server\'s document and nothing on it reaches scalar.com', () => {
    const { target, options } = scalarCall(false);
    assert.equal(target, '#api-docs');
    assert.equal(options.url, '/openapi.json');
    assert.equal(options.telemetry, false);
    assert.equal(options.proxyUrl, '');
    assert.equal(options.withDefaultFonts, false);
    assert.equal(options.hideClientButton, true);
    assert.equal(options.showDeveloperTools, 'never');
    assert.equal(options.agent.disabled, true);
    assert.equal(options.mcp.disabled, true);
    assert.equal(options.persistAuth, false);
    assert.ok(!('hideTestRequestButton' in options) || options.hideTestRequestButton === false,
        'Test Request runs on this server and stays');
    assert.doesNotMatch(JSON.stringify(options), /scalar\.com/i);
});

test('the reference follows the app\'s theme and has no toggle of its own', () => {
    assert.equal(scalarCall(true).options.forceDarkModeState, 'dark');
    assert.equal(scalarCall(false).options.forceDarkModeState, 'light');
    assert.equal(scalarCall(false).options.hideDarkModeToggle, true);
});

test('the page loads its files with a version stamp, so an update is never served from cache', () => {
    const html = fs.readFileSync(path.join(FRONTEND, 'api-docs.html'), 'utf8');
    const refs = [...html.matchAll(/(?:src|href)="(\/static\/[^"]+\.(?:css|js)[^"]*)"/g)].map(m => m[1]);
    assert.deepEqual(refs.sort(), [
        '/static/api-docs.js?v=1',
        '/static/assets/css/ui.css?v=1',
        '/static/assets/libs/scalar-api-reference.min.js?v=1',
    ]);
    // Configured by api-docs.js only. The bundle also starts a reference of its
    // own, with Scalar's defaults (its fonts, its hosted client, its proxy), on
    // an element with id="api-reference" or a data-spec/data-spec-url attribute
    const markup = withoutComments(html);
    assert.ok(!SECOND_REFERENCE_ID.test(markup), 'no element may have id="api-reference"');
    assert.ok(!/\bdata-(?:spec|spec-url|url|configuration|proxy-url)\b/i.test(markup));
});

test('the check for a second reference catches every way to write the id', () => {
    for (const html of ['<div id="api-reference">', "<div id='api-reference'>", '<div ID=api-reference>', '<div id = api-reference >']) {
        assert.ok(SECOND_REFERENCE_ID.test(html), html);
    }
    assert.ok(!SECOND_REFERENCE_ID.test('<div id="api-reference-x">'));
});

test('removing comments cannot hide an element behind a comment it builds', () => {
    // A browser ends "<!<!--x-->" at the first ">" and keeps the div
    const html = '<!<!--x-->--<div id="api-reference">-->';
    assert.ok(SECOND_REFERENCE_ID.test(withoutComments(html)));
    assert.ok(!SECOND_REFERENCE_ID.test(withoutComments('<!-- <div id="api-reference"> -->')));
});

test('the sidebar tools and the phone\'s More sheet link to the reference and the documentation site', () => {
    const html = fs.readFileSync(path.join(FRONTEND, 'index.html'), 'utf8');
    const docsSite = fs.readFileSync(path.join(FRONTEND, 'app.js'), 'utf8').match(/const DOCS_SITE_URL = '([^']+)'/)[1];
    for (const [id, href] of [['api-docs-link', '/docs'], ['mobile-api-docs-link', '/docs'],
        ['docs-site-link', docsSite], ['mobile-docs-site-link', docsSite]]) {
        const tag = html.match(new RegExp(`<a [^>]*id="${id}"[^>]*>`));
        assert.ok(tag, `${id} is missing`);
        assert.ok(tag[0].includes(`href="${href}"`), `${id} goes to ${href}`);
        assert.ok(tag[0].includes('target="_blank"') && tag[0].includes('rel="noopener'), `${id} opens a new tab without access to the app`);
    }
});

test('the Scalar bundle ships with its licence and without a source map reference', () => {
    const bundle = fs.readFileSync(path.join(LIBS, 'scalar-api-reference.min.js'), 'utf8');
    assert.match(bundle.slice(0, 200), /@scalar\/api-reference \d+\.\d+\.\d+/);
    assert.ok(!bundle.includes('sourceMappingURL'));
    assert.match(fs.readFileSync(path.join(LIBS, 'scalar-api-reference.LICENSE.txt'), 'utf8'), /MIT License[\s\S]*Scalar/);
});
