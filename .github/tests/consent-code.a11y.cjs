// The approval page (authorize.html) in a real DOM (jsdom). For an agent that
// connects with a code it shows the code to compare and the agent's own name,
// says no "Browser returns to", and after the answer stays put: the agent
// collects the answer itself. For an MCP app it shows where the browser goes back to.
// Set A11Y_MODULES to jsdom's node_modules to run it locally (see layers.a11y.cjs).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));

const frontend = path.join(__dirname, '../../frontend');

const AREAS = [
    { id: 'security', label: 'Security', view: 'Bans and alerts', act: 'Ban and unban' },
    { id: 'logs', label: 'Logs', view: 'Raw logs', act: '' },
];

function page(client, answer) {
    const html = fs.readFileSync(path.join(frontend, 'authorize.html'), 'utf8')
        .replace(/<script src="\/static\/authorize\.js[^"]*"><\/script>/, '');
    // The page's theme script asks matchMedia before anything else runs
    const beforeParse = win => { win.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} }); };
    const dom = new JSDOM(html, { runScripts: 'dangerously', pretendToBeVisual: true, beforeParse,
        url: 'https://logs.example.com/oauth/consent?request=r1' });
    const w = dom.window;
    w.fetch = async () => ({ ok: true, status: 200, json: async () => answer });
    const script = w.document.createElement('script');
    script.textContent = fs.readFileSync(path.join(frontend, 'authorize.js'), 'utf8');
    w.document.head.appendChild(script);
    w.consentRender({
        client, areas: AREAS, preselected_views: ['security'], periods: [{ days: 7, label: '7 days' }],
        default_days: 7, app_title: 'mailcow Logs Viewer', signed_in_as: 'admin',
    });
    return w;
}

const shown = (w, id) => !w.document.getElementById(id).classList.contains('hidden');

test('a code request shows the code and the agent\'s own name, and no return address', () => {
    const w = page({ declared_name: 'Claude Code on DESK', kind: 'device', user_code: 'BCDF-GHJK', redirect_uri: null }, {});
    assert.ok(shown(w, 'consent-code'));
    assert.equal(w.document.getElementById('consent-code-value').textContent, 'BCDF-GHJK');
    assert.equal(w.document.getElementById('consent-declared').textContent, 'Claude Code on DESK');
    assert.match(w.document.getElementById('consent-identity').textContent, /Name supplied by agent.*same code/);
    assert.ok(!shown(w, 'consent-return'));
});

test('after approving a code request the page says it is done and goes nowhere', async () => {
    const w = page({ declared_name: 'Claude Code', kind: 'device', user_code: 'BCDF-GHJK', redirect_uri: null }, { done: true });
    await w.consentAnswer(true);
    assert.ok(shown(w, 'consent-done'));
    assert.equal(w.document.getElementById('consent-done-title').textContent, 'Access allowed');
    assert.equal(w.location.href, 'https://logs.example.com/oauth/consent?request=r1');
});

test('an MCP app shows where the browser goes back to, and no code', () => {
    const w = page({ declared_name: 'Claude Code', kind: 'cimd', publisher: 'claude.ai',
        redirect_uri: 'http://localhost:43250/callback' }, {});
    assert.ok(!shown(w, 'consent-code'));
    assert.ok(shown(w, 'consent-return'));
    assert.equal(w.document.getElementById('consent-redirect').textContent, 'http://localhost:43250/callback');
});
