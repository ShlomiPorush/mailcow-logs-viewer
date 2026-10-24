// Settings > Agents > App address for agents in a real DOM (jsdom): the empty
// field shows the suggestion, turning agent access on (or opening the form with
// it on) makes it the value, and a typed or locked address is left alone.
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
    return { w, form, field, toggle, inputs };
}

function turnOn(p) {
    p.toggle.checked = true;
    p.w.settingsSuggestAgentUrl(p.form, true);
}

test('the empty field shows the address while agent access is off', () => {
    const p = page({ redirect: 'https://mail-logs.example.com/api/auth/callback' });
    p.w.settingsSuggestAgentUrl(p.form, true);
    assert.equal(p.field.placeholder, 'https://mail-logs.example.com');
    assert.equal(p.field.value, '', 'opening the form changes nothing');
    assert.equal(p.inputs.length, 0);
});

test('turning agent access on makes it the value, as an unsaved change', () => {
    const p = page({ redirect: 'https://mail-logs.example.com/api/auth/callback' });
    turnOn(p);
    assert.equal(p.field.value, 'https://mail-logs.example.com');
    assert.equal(p.inputs.length, 1, 'the save bar hears about it');
});

test('the page address is used without an OAuth2 callback', () => {
    const p = page();
    turnOn(p);
    assert.equal(p.field.value, 'https://logs.example.com');
});

test('opened with agent access on and no address, the field is filled; a cleared field stays empty', () => {
    const p = page({ on: true });
    p.w.settingsSuggestAgentUrl(p.form, true);
    assert.equal(p.field.value, 'https://logs.example.com');
    assert.equal(p.inputs.length, 1);
    p.field.value = '';
    p.field.dispatchEvent(new p.w.Event('input', { bubbles: true }));
    assert.equal(p.field.value, '', 'typing never refills it');
    assert.equal(p.field.placeholder, 'https://logs.example.com');
});

test('a typed address, a locked field or an address the server refuses is left alone', () => {
    const typed = page({ url: 'https://agents.example.com' });
    turnOn(typed);
    assert.equal(typed.field.value, 'https://agents.example.com');

    const locked = page({ locked: true });
    turnOn(locked);
    assert.equal(locked.field.value, '');

    const inside = page({ at: 'http://10.0.0.5:8080/settings/agents' });
    turnOn(inside);
    assert.equal(inside.field.value, '');
    assert.equal(inside.field.placeholder, '');
});

test('turning it off fills in nothing', () => {
    const p = page({ on: true });
    p.toggle.checked = false;
    p.w.settingsSuggestAgentUrl(p.form, true);
    assert.equal(p.field.value, '');
});
