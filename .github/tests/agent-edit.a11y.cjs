// Settings > Agents > Edit in a real DOM (jsdom): the dialog shows the agent's
// current access, Take action includes View, and saving sends the version of the
// access the dialog opened with, also when the list reloaded meanwhile (so an
// older dialog cannot pass for an edit of newer access).
// Set A11Y_MODULES to jsdom's node_modules to run it locally (see layers.a11y.cjs).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');

const DATA = version => ({
    live: true, areas: [
        { id: 'security', label: 'Security', view: 'Bans and alerts', act: 'Ban and unban' },
        { id: 'logs', label: 'Logs', view: 'Raw logs', act: '' },
    ],
    periods: [{ days: 7, label: '7 days' }, { days: 30, label: '30 days' }],
    agents: [{ id: 5, name: 'Claude Code', state: 'connected', kind: 'device', areas: { security: 'act' },
        expires_at: '2026-11-01T10:00:00Z', version }],
});

function page() {
    const dom = new JSDOM('<!doctype html><html lang="en"><head><title>t</title></head><body><div id="agents-panel"></div></body></html>',
        { runScripts: 'dangerously', pretendToBeVisual: true, url: 'https://logs.example.com/settings/agents',
          beforeParse: win => { win.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} }); } });
    const w = dom.window;
    const run = source => {
        const script = w.document.createElement('script');
        script.textContent = source;
        w.document.head.appendChild(script);
    };
    [read('utils.js'), read('agents.js')].forEach(run);
    const sent = [];
    w.authenticatedFetch = async (url, options) => {
        sent.push({ url, options });
        return { ok: true, status: 200, json: async () => ({ changed: 1 }) };
    };
    w.showToast = () => {};
    w.loadAgentsPanel = () => {};
    run(`agentsData = ${JSON.stringify(DATA('v-old'))};`);
    return { w, run, sent, $: sel => w.document.querySelector(sel) };
}

test('the dialog shows the current access and Take action includes View', () => {
    const p = page();
    p.w.editAgentAccess(5);
    assert.ok(p.$('#agent-edit-modal'));
    assert.equal(p.$('input[data-area="security"][data-kind="act"]').checked, true);
    assert.equal(p.$('input[data-area="security"][data-kind="view"]').checked, true);
    assert.equal(p.$('input[data-area="logs"][data-kind="view"]').checked, false);
    // Clearing View clears Take action
    const view = p.$('input[data-area="security"][data-kind="view"]');
    view.checked = false;
    view.dispatchEvent(new p.w.Event('change', { bubbles: true }));
    assert.equal(p.$('input[data-area="security"][data-kind="act"]').checked, false);
});

test('saving sends the version the dialog opened with, not a newer one', async () => {
    const p = page();
    p.w.editAgentAccess(5);
    // The list reloads while the dialog is open: someone else changed the access
    p.run(`agentsData = ${JSON.stringify(DATA('v-new'))};`);
    const form = p.$('#agent-edit-form');
    await p.w.saveAgentAccess({ preventDefault() {} }, 5);
    assert.equal(p.sent.length, 1);
    const body = JSON.parse(p.sent[0].options.body);
    assert.equal(body.version, 'v-old');
    assert.deepEqual(body.views, ['security']);
    assert.deepEqual(body.acts, ['security']);
    assert.equal(body.days, null);
    assert.ok(form);
});

test('without any View the dialog says so and sends nothing', async () => {
    const p = page();
    p.w.editAgentAccess(5);
    for (const box of p.w.document.querySelectorAll('#agent-edit-modal input[type="checkbox"]')) box.checked = false;
    await p.w.saveAgentAccess({ preventDefault() {} }, 5);
    assert.equal(p.sent.length, 0);
    assert.match(p.$('#agent-edit-error').textContent, /Select View for at least one area/);
});
