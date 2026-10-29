// The password field of Settings > Users in a real DOM (jsdom): the meter follows what is typed,
// says the strength in a polite live region, marks each requirement with a check or a cross and
// tells a screen reader which are met, warns about a weak password that can still be saved, and
// waits for typing when editing. Save stops only under 8 characters (as the server does).
// Generate fills a readable password of the length chosen, draws a new one when the length
// moves, shows dots again once typed over, and Copy copies what the field holds.
// Set A11Y_MODULES to jsdom's node_modules to run it locally (see layers.a11y.cjs).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));
const axeSource = fs.readFileSync(require.resolve(path.join(modules, 'axe-core')), 'utf8');

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');
const SHORT = 'Use at least 8 characters.';

const DATA = {
    areas: [{ id: 'messages', label: 'Messages', view: 'Messages', act: '' }],
    presets: ['admin', 'operator', 'viewer', 'custom'].map(id => ({ id, label: id, areas: id === 'admin' || id === 'custom' ? {} : { messages: 'view' } })),
    builtin: { username: 'admin', basic_auth_enabled: true },
    oauth2: { enabled: false, default_access: 'admin', version: 0, provider_name: '' },
    users: [{ id: 2, kind: 'local', username: 'dana', email: null, access: 'viewer', areas: { messages: 'view' }, disabled: false,
        name_conflict: false, last_login_at: null, created_at: '2026-10-20T10:00:00Z', row_version: 1 }],
    you: { kind: 'builtin', user_id: null, via_default: false },
};

function page() {
    const dom = new JSDOM('<!doctype html><html lang="en"><head><title>t</title></head><body><div id="users-panel"></div></body></html>',
        { runScripts: 'dangerously', pretendToBeVisual: true, url: 'https://logs.example.com/settings/users',
          beforeParse: win => { win.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} }); } });
    const w = dom.window;
    const run = source => {
        const script = w.document.createElement('script');
        script.textContent = source;
        w.document.head.appendChild(script);
    };
    [read('utils.js'), read('users.js')].forEach(run);
    const sent = [];
    const copied = [];
    // The server refuses under 8 characters, as the real one does (its words)
    w.authenticatedFetch = async (url, options) => {
        sent.push({ url, options });
        const password = JSON.parse(options.body).password;
        if (password !== undefined && [...password].length < 8) return { ok: false, status: 422, json: async () => ({ detail: SHORT }) };
        return { ok: true, status: 201, json: async () => ({ username: 'erin' }) };
    };
    w.copyToClipboard = text => copied.push(text);
    w.loadUsersPanel = () => {};
    run(`usersData = ${JSON.stringify(DATA)};`);
    const $ = sel => w.document.querySelector(sel);
    const type = text => {
        const field = $('#user-edit-pass');
        field.value = text;
        field.dispatchEvent(new w.Event('input', { bubbles: true }));
    };
    const rules = () => [...w.document.querySelectorAll('#user-edit-pw-meter li')].map(li => li.textContent.trim());
    const warned = () => !$('#user-edit-pw-warn').classList.contains('hidden');
    return { w, $, type, rules, warned, sent, copied };
}

test('typing: a check or a cross per requirement, read out as met or not, and the strength', () => {
    const p = page();
    p.w.editUser(null);
    assert.equal(p.$('#user-edit-pass').placeholder, 'At least 8 characters');
    assert.ok(!p.$('#user-edit-pass').hasAttribute('maxlength'));
    assert.equal(p.$('#user-edit-pw-label').getAttribute('aria-live'), 'polite');
    assert.equal(p.w.document.querySelectorAll('#user-edit-pw-meter input[type="checkbox"]').length, 0, 'marks, not checkboxes');
    assert.deepEqual(p.rules(), ['✗8 or more characters, not met', '✗An uppercase letter, not met',
        '✗A lowercase letter, not met', '✗A number, not met', '✗A symbol, not met']);
    p.type('abc1');
    assert.equal(p.$('#user-edit-pw-label').textContent, 'Password strength: Weak');
    assert.deepEqual(p.rules(), ['✗8 or more characters, not met', '✗An uppercase letter, not met',
        '✓A lowercase letter, met', '✓A number, met', '✗A symbol, not met']);
    p.type('Correct Horse 7 Battery');
    assert.equal(p.$('#user-edit-pw-label').textContent, 'Password strength: Strong');
    assert.ok(p.rules().every(r => r.startsWith('✓') && r.endsWith(', met')));
});

test('a weak password of 8 or more says so, and is saved', async () => {
    const p = page();
    p.w.editUser(null);
    p.$('#user-edit-name').value = 'erin';
    p.type('abc');
    assert.equal(p.warned(), false, 'too short to save: no "you can still save it"');
    p.type('abcdefgh');
    assert.equal(p.$('#user-edit-pw-label').textContent, 'Password strength: Weak');
    assert.ok(p.warned());
    assert.equal(p.$('#user-edit-pw-warn').textContent, 'This password is weak. You can still save it.');
    p.type('Abcdef1!');
    assert.equal(p.warned(), false, 'every requirement met: no warning');
    p.type('abcdefgh');
    await p.w.saveUser({ preventDefault() {} }, null);
    assert.equal(p.sent.length, 1);
    assert.equal(JSON.parse(p.sent[0].options.body).password, 'abcdefgh');
});

test('Save stops a password under 8 characters, adding and editing, with the server\'s words', async () => {
    const p = page();
    p.w.editUser(null);
    p.$('#user-edit-name').value = 'erin';
    await p.w.saveUser({ preventDefault() {} }, null);
    assert.equal(p.$('#user-edit-error').textContent, SHORT);
    p.type('Abcd1!x');
    await p.w.saveUser({ preventDefault() {} }, null);
    assert.equal(p.$('#user-edit-error').textContent, SHORT);
    assert.equal(p.sent.length, 0);
    p.w.closeUserEditModal(true);
    p.w.editUser(2);
    assert.ok(p.$('#user-edit-pw-meter').classList.contains('hidden'), 'editing: the meter waits for typing');
    p.type('short');
    assert.ok(!p.$('#user-edit-pw-meter').classList.contains('hidden'));
    await p.w.saveUser({ preventDefault() {} }, 2);
    assert.equal(p.$('#user-edit-error').textContent, SHORT);
    assert.equal(p.sent.length, 0);
    p.type('');
    await p.w.saveUser({ preventDefault() {} }, 2);
    assert.equal(p.sent.length, 1);
    assert.ok(!('password' in JSON.parse(p.sent[0].options.body)), 'an empty field keeps the password');
});

test('Generate: a readable password of the length chosen, a new one when the length moves, dots once typed over', () => {
    const p = page();
    p.w.editUser(null);
    const field = p.$('#user-edit-pass');
    const length = p.$('#user-edit-pw-length');
    assert.equal(p.$('#user-edit-pw-length-value').textContent, '20');
    assert.equal(length.min, '12');
    assert.equal(length.max, '64');
    assert.ok(p.$('#user-edit-pw-copy').disabled, 'nothing to copy yet');
    p.$('#user-edit-pw-generate').click();
    assert.equal(field.type, 'text');
    assert.equal(field.value.length, 20);
    assert.equal(p.$('#user-edit-pw-label').textContent, 'Password strength: Strong');
    const first = field.value;
    length.value = '32';
    length.dispatchEvent(new p.w.Event('input', { bubbles: true }));
    assert.equal(p.$('#user-edit-pw-length-value').textContent, '32');
    assert.equal(field.value.length, 32);
    assert.notEqual(field.value, first);
    p.$('#user-edit-pw-copy').click();
    assert.deepEqual(p.copied, [field.value]);
    p.type(field.value + 'x');
    assert.equal(field.type, 'password', 'typed over: shown as dots again');
    // Moving the length now does not replace what was typed
    const typed = field.value;
    length.value = '40';
    length.dispatchEvent(new p.w.Event('input', { bubbles: true }));
    assert.equal(field.value, typed);
});

test('the dialog with the meter and the generator has no axe violations', async () => {
    const p = page();
    p.w.editUser(null);
    p.type('abcdefgh');
    const script = p.w.document.createElement('script');
    script.textContent = axeSource;
    p.w.document.head.appendChild(script);
    const result = await p.w.axe.run(p.$('#user-edit-modal'), { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } });
    // Plain strings out of the page's realm, so the comparison is by value
    assert.deepEqual(Array.from(result.violations, v => `${v.id}: ${Array.from(v.nodes, n => String(n.target)).join(' ')}`), []);
});
