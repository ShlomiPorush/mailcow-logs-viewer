// Settings > Agents in a real DOM (jsdom): agent access needs sign-in. With
// Basic Auth and OAuth2 both off the switch is locked and says where to turn
// sign-in on; turning the last one off in the form turns agent access off.
// Set A11Y_MODULES to jsdom's node_modules to run it locally (see layers.a11y.cjs).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');

function page({ basic = false, oauth = false, agents = false } = {}) {
    const dom = new JSDOM(`<!doctype html><html lang="en"><head><title>t</title></head><body><form id="f">
        <input type="checkbox" id="edit-basic_auth_enabled" ${basic ? 'checked' : ''}>
        <input type="checkbox" id="edit-oauth2_enabled" ${oauth ? 'checked' : ''}>
        <div class="ui-set-bool"><label for="edit-agent_access_enabled" class="ui-set-bool-main">
            <input type="checkbox" id="edit-agent_access_enabled" ${agents ? 'checked' : ''}>Enable agent access</label></div>
    </form></body></html>`, { runScripts: 'dangerously', pretendToBeVisual: true, url: 'https://logs.example.com/settings/agents' });
    const w = dom.window;
    w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    if (!('inert' in w.HTMLElement.prototype)) {
        Object.defineProperty(w.HTMLElement.prototype, 'inert', { configurable: true,
            get() { return this.hasAttribute('inert'); },
            set(value) { if (value) this.setAttribute('inert', ''); else this.removeAttribute('inert'); } });
    }
    for (const source of [read('utils.js'), read('settings.js')]) {
        const script = w.document.createElement('script');
        script.textContent = source;
        w.document.head.appendChild(script);
    }
    const form = w.document.getElementById('f');
    const inputs = [];
    form.addEventListener('input', () => inputs.push(1));
    const $ = id => w.document.getElementById(id);
    const row = $('edit-agent_access_enabled').closest('.ui-set-bool');
    return { w, form, $, row, inputs, note: () => row.querySelector('[data-agent-lock]') };
}

test('without sign-in the switch is locked and says where to turn sign-in on', () => {
    const p = page();
    p.w.settingsLockAgentAccess(p.form, false, false);
    assert.equal(p.row.inert, true);
    assert.ok(p.row.querySelector('.ui-set-bool-main').classList.contains('is-off'));
    assert.ok(!p.row.classList.contains('is-off'), 'the note is not dimmed');
    assert.match(p.note().textContent, /Turn on Basic Auth or OAuth2 in Settings → Authentication first/);
});

test('either sign-in method unlocks it', () => {
    for (const on of [{ basic: true }, { oauth: true }]) {
        const p = page(on);
        p.w.settingsLockAgentAccess(p.form, false, false);
        assert.equal(p.row.inert, false);
        assert.equal(p.note(), null);
    }
});

test('the old AUTH_ENABLED, which has no field, unlocks it too', () => {
    const p = page();
    p.w.settingsLockAgentAccess(p.form, false, true);
    assert.equal(p.row.inert, false);
});

test('turning the last sign-in method off turns agent access off, as an unsaved change', () => {
    const p = page({ basic: true, agents: true });
    p.w.settingsLockAgentAccess(p.form, false, false);
    p.$('edit-basic_auth_enabled').checked = false;
    p.w.settingsLockAgentAccess(p.form, true, false);
    assert.equal(p.$('edit-agent_access_enabled').checked, false);
    assert.equal(p.inputs.length, 1, 'the save bar hears about it');
    assert.equal(p.row.inert, true);
    p.$('edit-oauth2_enabled').checked = true;
    p.w.settingsLockAgentAccess(p.form, true, false);
    assert.equal(p.row.inert, false);
    assert.equal(p.note(), null);
    assert.equal(p.$('edit-agent_access_enabled').checked, false, 'turning sign-in on does not turn agents on');
});

test('opening the form never changes the switch, even in a state set in .env', () => {
    const p = page({ agents: true });
    p.w.settingsLockAgentAccess(p.form, false, false);
    assert.equal(p.$('edit-agent_access_enabled').checked, true);
    assert.equal(p.inputs.length, 0);
});
