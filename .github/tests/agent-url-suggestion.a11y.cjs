// Settings > Agents > App address for agents in a real DOM (jsdom): turning
// agent access on with no address fills in the suggestion, an empty field
// offers it on a button, and a typed or locked address is left alone.
// Set A11Y_MODULES to jsdom's node_modules to run it locally (see layers.a11y.cjs).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');

function page({ on = false, url = '', redirect = '', locked = false, at = 'https://logs.example.com/settings/agents' } = {}) {
    const dom = new JSDOM(`<!doctype html><html lang="en"><head><title>t</title></head><body><form id="f">
        <input type="checkbox" id="edit-agent_access_enabled" ${on ? 'checked' : ''}>
        <div class="ui-set-field"><input type="text" id="edit-agent_access_url" value="${url}" ${locked ? 'disabled' : ''}></div>
        <input type="text" id="edit-oauth2_redirect_uri" value="${redirect}">
    </form></body></html>`, { runScripts: 'dangerously', pretendToBeVisual: true, url: at });
    const w = dom.window;
    w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    for (const source of [read('utils.js'), read('settings.js')]) {
        const script = w.document.createElement('script');
        script.textContent = source;
        w.document.head.appendChild(script);
    }
    const form = w.document.getElementById('f');
    const inputs = [];
    form.addEventListener('input', () => { inputs.push(1); w.settingsSuggestAgentUrl(form, false); });
    const field = w.document.getElementById('edit-agent_access_url');
    const toggle = w.document.getElementById('edit-agent_access_enabled');
    const offer = () => form.querySelector('[data-agent-url-offer]');
    return { w, form, field, toggle, offer, inputs };
}

function turnOn(p) {
    p.toggle.checked = true;
    p.w.settingsSuggestAgentUrl(p.form, true);
}

test('turning agent access on fills in the address and counts as a change', () => {
    const p = page({ redirect: 'https://mail-logs.example.com/api/auth/callback' });
    p.w.settingsSuggestAgentUrl(p.form, false);
    assert.equal(p.offer().textContent, 'Use https://mail-logs.example.com');
    turnOn(p);
    assert.equal(p.field.value, 'https://mail-logs.example.com');
    assert.equal(p.inputs.length, 1, 'the save bar hears about it');
    assert.equal(p.offer(), null);
});

test('the page address is used without an OAuth2 callback', () => {
    const p = page();
    turnOn(p);
    assert.equal(p.field.value, 'https://logs.example.com');
});

test('an empty field offers the address on a button and keeps it until clicked', () => {
    const p = page({ on: true });
    p.w.settingsSuggestAgentUrl(p.form, false);
    assert.equal(p.field.value, '', 'opening the form changes nothing');
    assert.equal(p.offer().getAttribute('type'), 'button');
    p.offer().click();
    assert.equal(p.field.value, 'https://logs.example.com');
    assert.equal(p.offer(), null);
    p.field.value = '';
    p.field.dispatchEvent(new p.w.Event('input', { bubbles: true }));
    assert.equal(p.offer().textContent, 'Use https://logs.example.com', 'cleared again: offered again');
});

test('a typed address, a locked field or an address the server refuses is left alone', () => {
    const typed = page({ url: 'https://agents.example.com' });
    turnOn(typed);
    assert.equal(typed.field.value, 'https://agents.example.com');
    assert.equal(typed.offer(), null);

    const locked = page({ locked: true });
    turnOn(locked);
    assert.equal(locked.field.value, '');
    assert.equal(locked.offer(), null);

    const inside = page({ at: 'http://10.0.0.5:8080/settings/agents' });
    turnOn(inside);
    assert.equal(inside.field.value, '');
    assert.equal(inside.offer(), null);
});

test('turning it off fills in nothing', () => {
    const p = page({ on: true });
    p.toggle.checked = false;
    p.w.settingsSuggestAgentUrl(p.form, true);
    assert.equal(p.field.value, '');
});
