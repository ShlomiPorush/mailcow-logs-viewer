// The password strength meter of Settings > Users in a real DOM (jsdom): it follows what is
// typed, says the strength in a polite live region, tells a screen reader which requirements
// are met, waits for typing when editing (an empty field keeps the password), and Save is
// blocked with the server's words until the password meets the rule.
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
const WEAK = 'Use at least 8 characters with an uppercase letter, a lowercase letter, a number and a symbol.';

const DATA = {
    areas: [{ id: 'messages', label: 'Messages', view: 'Messages', act: '' }],
    presets: ['admin', 'operator', 'viewer', 'custom'].map(id => ({ id, label: id, areas: {} })),
    builtin: { username: 'admin', basic_auth_enabled: true },
    oauth2: { enabled: false, default_access: 'admin', version: 0 },
    users: [{ id: 2, kind: 'local', username: 'dana', email: null, access: 'viewer', areas: {}, disabled: false,
        name_conflict: false, last_login_at: null, created_at: '2026-10-20T10:00:00Z', row_version: 1 }],
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
    w.authenticatedFetch = async (url, options) => {
        sent.push({ url, options });
        return { ok: true, status: 201, json: async () => ({ username: 'erin' }) };
    };
    w.loadUsersPanel = () => {};
    run(`usersData = ${JSON.stringify(DATA)};`);
    const $ = sel => w.document.querySelector(sel);
    const type = text => {
        const field = $('#user-edit-pass');
        field.value = text;
        field.dispatchEvent(new w.Event('input', { bubbles: true }));
    };
    const rules = () => [...w.document.querySelectorAll('#user-edit-pw-meter li')].map(li => [li.dataset.met, li.textContent.trim()]);
    return { w, $, type, rules, sent };
}

test('adding: the meter shows the requirements at once and follows what is typed', () => {
    const p = page();
    p.w.editUser(null);
    const meter = p.$('#user-edit-pw-meter');
    assert.ok(!meter.classList.contains('hidden'));
    assert.equal(p.$('#user-edit-pass').placeholder, 'At least 8 characters');
    assert.equal(p.$('#user-edit-pw-label').getAttribute('aria-live'), 'polite');
    assert.equal(p.$('#user-edit-pw-label').textContent, '');
    assert.deepEqual(p.rules(), [
        ['false', '8 or more characters, not met'], ['false', 'An uppercase letter, not met'],
        ['false', 'A lowercase letter, not met'], ['false', 'A number, not met'], ['false', 'A symbol, not met'],
    ]);
    p.type('abc1');
    assert.equal(meter.dataset.level, '1');
    assert.equal(p.$('#user-edit-pw-label').textContent, 'Password strength: Weak');
    assert.deepEqual(p.rules().map(r => r[1]), ['8 or more characters, not met', 'An uppercase letter, not met',
        'A lowercase letter, met', 'A number, met', 'A symbol, not met']);
    p.type('Abcdefgh1!');
    assert.equal(p.$('#user-edit-pw-label').textContent, 'Password strength: Good');
    assert.ok(p.rules().every(([met]) => met === 'true'));
    p.type('Correct Horse 7 Battery');
    assert.equal(p.$('#user-edit-pw-label').textContent, 'Password strength: Strong');
});

test('editing: the meter waits for typing, since an empty field keeps the password', () => {
    const p = page();
    p.w.editUser(2);
    assert.ok(p.$('#user-edit-pw-meter').classList.contains('hidden'));
    p.type('a');
    assert.ok(!p.$('#user-edit-pw-meter').classList.contains('hidden'));
    p.type('');
    assert.ok(p.$('#user-edit-pw-meter').classList.contains('hidden'));
});

test('Save is blocked with the server\'s words until the rule is met', async () => {
    const p = page();
    p.w.editUser(null);
    p.$('#user-edit-name').value = 'erin';
    p.type('abcdefgh');
    await p.w.saveUser({ preventDefault() {} }, null);
    assert.equal(p.$('#user-edit-error').textContent, WEAK);
    assert.equal(p.sent.length, 0);
    p.type('Abcdef1!');
    await p.w.saveUser({ preventDefault() {} }, null);
    assert.equal(p.sent.length, 1);
    assert.equal(JSON.parse(p.sent[0].options.body).password, 'Abcdef1!');
});

test('editing with a weak new password is blocked; an empty one keeps the password', async () => {
    const p = page();
    p.w.editUser(2);
    p.type('short');
    await p.w.saveUser({ preventDefault() {} }, 2);
    assert.equal(p.$('#user-edit-error').textContent, WEAK);
    assert.equal(p.sent.length, 0);
    p.type('');
    await p.w.saveUser({ preventDefault() {} }, 2);
    assert.equal(p.sent.length, 1);
    assert.ok(!('password' in JSON.parse(p.sent[0].options.body)));
});

test('the dialog with the meter has no axe violations', async () => {
    const p = page();
    p.w.editUser(null);
    p.type('Abc1');
    const script = p.w.document.createElement('script');
    script.textContent = axeSource;
    p.w.document.head.appendChild(script);
    const result = await p.w.axe.run(p.$('#user-edit-modal'), { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } });
    // Plain strings out of the page's realm, so the comparison is by value
    assert.deepEqual(Array.from(result.violations, v => `${v.id}: ${Array.from(v.nodes, n => String(n.target)).join(' ')}`), []);
});
