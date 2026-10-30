// The password field of Settings > Users in a real DOM (jsdom): the meter follows what is typed,
// says the strength in a polite live region, and marks each requirement with a check or a cross
// that a screen reader reads as met or not. Whether the password can be set is the server's
// answer (POST /api/users/password-check), asked while typing and at once after Generate, shown
// under the field and read out; only the answer for the latest value counts. Add and Save look
// disabled (aria-disabled) until the form can be saved, and say why when pressed.
// Generate fills a readable password of the length chosen, draws a new one when the length
// moves, shows dots again once typed over, and Copy copies it without showing it. The length
// alone is not a change the discard question asks about.
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
const COMMON = 'This password is too common. Choose another one.';
const GOOD = 'Kp7m-Rx4Tq9wZb2n';

const DATA = {
    areas: [{ id: 'messages', label: 'Messages', view: 'Messages', act: '' }],
    presets: ['admin', 'operator', 'viewer', 'custom'].map(id => ({ id, label: id, areas: id === 'admin' || id === 'custom' ? {} : { messages: 'view' } })),
    builtin: { username: 'admin', basic_auth_enabled: true },
    oauth2: { enabled: false, default_access: 'admin', version: 0, provider_name: '' },
    users: [{ id: 2, kind: 'local', username: 'dana', email: null, access: 'viewer', areas: { messages: 'view' }, disabled: false,
        name_conflict: false, last_login_at: null, created_at: '2026-10-20T10:00:00Z', row_version: 1 }],
    you: { kind: 'builtin', user_id: null, via_default: false, email: null },
};

// The server's rule, as services/passwords.py has it (a short list stands in for the common ones)
const problemOf = password => [...password].length < 8 ? SHORT : [...password].length > 256 ? 'Use at most 256 characters.'
    : ['password1'].includes(password.trim().toLowerCase()) ? COMMON : null;

// hold: password checks wait until released, so a test can answer them out of order.
// fail: the first checks fail this way ('throw', '500' or 'malformed'), failCount of them.
// refuse: the first this many passwords checked are too common, whatever they are
function page({ hold = false, fail = null, failCount = 1, refuse = 0 } = {}) {
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
    const checks = [];
    const copied = [];
    const toasts = [];
    w.authenticatedFetch = async (url, options) => {
        const body = JSON.parse(options.body);
        if (url === '/api/users/password-check') {
            if (fail && checks.filter(c => c.failed).length < failCount) {
                checks.push({ password: body.password, failed: true });
                if (fail === 'throw') throw new TypeError('Failed to fetch');
                if (fail === '500') return { ok: false, status: 500, json: async () => ({ detail: 'An error occurred' }) };
                return { ok: true, status: 200, json: async () => ({ fine: true }) };
            }
            const refused = checks.filter(c => !c.failed).length < refuse;
            const problem = refused ? COMMON : problemOf(body.password);
            const answer = { ok: true, status: 200, json: async () => ({ ok: !problem, problem }) };
            if (!hold) { checks.push({ password: body.password }); return answer; }
            // release(other): answer with other ({ ok, problem }) instead
            return new Promise(resolve => checks.push({ password: body.password,
                release: other => resolve(other ? { ok: true, status: 200, json: async () => other } : answer) }));
        }
        sent.push({ url, options });
        if (body.password !== undefined && problemOf(body.password)) return { ok: false, status: 422, json: async () => ({ detail: problemOf(body.password) }) };
        return { ok: true, status: 201, json: async () => ({ username: 'erin' }) };
    };
    // The real copy, with a clipboard that works, and the notices it shows
    Object.defineProperty(w.navigator, 'clipboard', { value: { writeText: async text => { copied.push(text); } } });
    w.showToast = message => toasts.push(message);
    w.loadUsersPanel = () => {};
    run(`usersData = ${JSON.stringify(DATA)};`);
    const $ = sel => w.document.querySelector(sel);
    const input = (sel, text) => {
        const field = $(sel);
        field.value = text;
        field.dispatchEvent(new w.Event('input', { bubbles: true }));
    };
    const type = text => input('#user-edit-pass', text);
    const rules = () => [...w.document.querySelectorAll('#user-edit-pw-meter li')].map(li => li.textContent.trim());
    const disabled = () => $('#user-edit-save').getAttribute('aria-disabled') === 'true';
    const problem = () => $('#user-edit-pw-problem').classList.contains('hidden') ? '' : $('#user-edit-pw-problem').textContent;
    return { w, $, input, type, rules, disabled, problem, sent, checks, copied, toasts };
}

// The check waits 300 ms after typing stops
const settle = () => new Promise(r => setTimeout(r, 360));
const tick = () => new Promise(r => setTimeout(r, 0));

test('typing: a check or a cross per requirement, read out as met or not, and the strength', () => {
    const p = page();
    p.w.editUser(null);
    assert.equal(p.$('#user-edit-pass').placeholder, 'At least 8 characters');
    assert.ok(!p.$('#user-edit-pass').hasAttribute('maxlength'));
    // The strength and the server's answer under it are one live region, which describes the field
    assert.equal(p.$('#user-edit-pw-status').getAttribute('aria-live'), 'polite');
    assert.ok(p.$('#user-edit-pw-status').contains(p.$('#user-edit-pw-label')));
    assert.ok(p.$('#user-edit-pw-status').contains(p.$('#user-edit-pw-problem')));
    assert.equal(p.$('#user-edit-pass').getAttribute('aria-describedby'), 'user-edit-pw-status');
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

test('a weak password says nothing more than its strength: no "you can still save it"', async () => {
    const p = page();
    p.w.editUser(null);
    p.input('#user-edit-name', 'erin');
    p.type('qzxkvbnw');
    await settle();
    assert.equal(p.$('#user-edit-pw-label').textContent, 'Password strength: Weak');
    assert.equal(p.$('#user-edit-pw-warn'), null);
    assert.ok(!p.$('#user-edit-modal').textContent.includes('still save'));
    assert.equal(p.disabled(), false, 'weak but accepted by the server: Add can go');
});

test('Add looks disabled until the form can be saved, and says why when pressed', async () => {
    const p = page();
    p.w.editUser(null);
    const save = p.$('#user-edit-save');
    assert.equal(save.textContent, 'Add');
    assert.ok(p.disabled(), 'empty');
    assert.equal(save.disabled, false, 'aria-disabled: still reachable, so pressing it can say why');
    await p.w.saveUser({ preventDefault() {} }, null);
    assert.equal(p.$('#user-edit-error').textContent, 'Enter a username.');
    p.input('#user-edit-name', 'erin');
    assert.ok(p.disabled(), 'no password yet');
    // A common password: the server's words under the field, read out, and Add stays disabled
    p.type('Password1');
    assert.ok(p.disabled(), 'while the check is on its way');
    await settle();
    assert.deepEqual(p.checks.map(c => c.password), ['Password1'], 'asked once typing stopped');
    assert.equal(p.problem(), COMMON);
    assert.ok(p.$('#user-edit-pw-status').textContent.includes(COMMON));
    assert.ok(p.disabled());
    await p.w.saveUser({ preventDefault() {} }, null);
    assert.equal(p.$('#user-edit-error').textContent, COMMON);
    p.type('short');
    await settle();
    assert.equal(p.problem(), SHORT);
    p.type(GOOD);
    await settle();
    assert.equal(p.problem(), '');
    assert.equal(p.disabled(), false);
    // Custom with no View anywhere
    p.$('#user-edit-level [data-level="custom"]').click();
    assert.equal(p.disabled(), false, 'Custom starts from what Operator gave');
    const view = p.$('#user-edit-grid input[data-kind="view"]');
    view.checked = false;
    view.dispatchEvent(new p.w.Event('change', { bubbles: true }));
    assert.ok(p.disabled());
    view.checked = true;
    view.dispatchEvent(new p.w.Event('change', { bubbles: true }));
    assert.equal(p.disabled(), false);
    // A username too long: said once the field is left
    p.input('#user-edit-name', 'x'.repeat(65));
    assert.ok(p.disabled());
    p.$('#user-edit-name').dispatchEvent(new p.w.Event('change', { bubbles: true }));
    assert.equal(p.$('#user-edit-name-problem').textContent, 'A username has 1 to 64 characters: letters, digits and . _ @ -');
    assert.equal(p.$('#user-edit-name').getAttribute('aria-describedby'), 'user-edit-name-problem');
    p.input('#user-edit-name', 'erin');
    assert.ok(p.$('#user-edit-name-problem').classList.contains('hidden'), 'gone once right');
    assert.equal(p.disabled(), false);
    await p.w.saveUser({ preventDefault() {} }, null);
    assert.equal(p.sent.length, 1);
    assert.equal(JSON.parse(p.sent[0].options.body).password, GOOD);
});

test('Generate is checked at once; an older answer that comes late is dropped', async () => {
    const p = page({ hold: true });
    p.w.editUser(null);
    p.input('#user-edit-name', 'erin');
    p.$('#user-edit-pw-generate').click();
    const first = p.$('#user-edit-pass').value;
    p.$('#user-edit-pw-generate').click();
    const second = p.$('#user-edit-pass').value;
    assert.deepEqual(p.checks.map(c => c.password), [first, second], 'both asked at once, no wait');
    assert.ok(p.disabled(), 'pending');
    p.checks[1].release();
    await tick();
    assert.equal(p.disabled(), false, 'the generated password came back fine');
    // The first answer arrives last, and says no: it is for a value no longer in the field
    p.checks[0].release({ ok: false, problem: COMMON });
    await tick();
    assert.equal(p.problem(), '');
    assert.equal(p.disabled(), false);
});

test('a stale answer that says no does not block the password now in the field', async () => {
    const p = page({ hold: true });
    p.w.editUser(null);
    p.input('#user-edit-name', 'erin');
    p.type('Password1');
    await settle();
    p.type(GOOD);
    await settle();
    assert.deepEqual(p.checks.map(c => c.password), ['Password1', GOOD]);
    p.checks[1].release();
    await tick();
    p.checks[0].release();
    await tick();
    assert.equal(p.problem(), '', 'the common-password answer was for the old value');
    assert.equal(p.disabled(), false);
});

test('a username or email the server takes is not refused here: groß leaves Add enabled', async () => {
    const p = page();
    p.w.editUser(null);
    p.input('#user-edit-name', 'groß');
    p.type(GOOD);
    await settle();
    assert.equal(p.disabled(), false);
    p.$('#user-edit-name').dispatchEvent(new p.w.Event('change', { bubbles: true }));
    assert.ok(p.$('#user-edit-name-problem').classList.contains('hidden'));
    await p.w.saveUser({ preventDefault() {} }, null);
    assert.equal(JSON.parse(p.sent[0].options.body).username, 'groß');
});

test('a password check that fails is not a pass: said, Add stays disabled, and Save asks again', async () => {
    for (const fail of ['throw', '500', 'malformed']) {
        const p = page({ fail });
        p.w.editUser(null);
        p.input('#user-edit-name', 'erin');
        p.type('Password1');
        await settle();
        assert.equal(p.problem(), 'Could not check the password. Try again.', fail);
        assert.ok(p.disabled(), fail);
        // Save asks at once: the server answers now, and its answer counts
        await p.w.saveUser({ preventDefault() {} }, null);
        assert.equal(p.$('#user-edit-error').textContent, COMMON, fail);
        assert.equal(p.problem(), COMMON, fail);
        assert.equal(p.sent.length, 0, fail);
    }
});

test('a failed check is tried once more after 3 seconds, not in a loop; typing asks again', async () => {
    const p = page({ fail: '500', failCount: 2 });
    p.w.editUser(null);
    p.input('#user-edit-name', 'erin');
    p.type(GOOD);
    await settle();
    assert.equal(p.checks.length, 1);
    assert.ok(p.disabled());
    await new Promise(r => setTimeout(r, 3200));
    assert.equal(p.checks.length, 2, 'one more try');
    assert.equal(p.problem(), 'Could not check the password. Try again.');
    await new Promise(r => setTimeout(r, 3500));
    assert.equal(p.checks.length, 2, 'and no more on its own');
    p.type(GOOD + 'x');
    await settle();
    assert.equal(p.checks.length, 3);
    assert.equal(p.disabled(), false, 'the server answered this time');
});

test('a change made while Save waits for the check is what is sent', async () => {
    const p = page({ hold: true });
    p.w.editUser(null);
    p.input('#user-edit-name', 'erin');
    p.$('#user-edit-level [data-level="admin"]').click();
    p.type(GOOD);
    const saving = p.w.saveUser({ preventDefault() {} }, null);
    assert.deepEqual(p.checks.map(c => c.password), [GOOD], 'asked at once on Save');
    p.$('#user-edit-level [data-level="viewer"]').click();
    p.checks[0].release();
    await saving;
    assert.equal(p.sent.length, 1);
    assert.equal(JSON.parse(p.sent[0].options.body).access, 'viewer');
});

test('the email field: empty or not an email address keeps Add disabled', async () => {
    const p = page();
    p.w.editUser(null);
    p.w.document.getElementById('user-edit-kind-value').value = 'oauth2';
    assert.ok(p.disabled());
    p.input('#user-edit-email', 'carol');
    assert.ok(p.disabled(), 'the browser says it is not an email address');
    p.$('#user-edit-email').dispatchEvent(new p.w.Event('change', { bubbles: true }));
    assert.equal(p.$('#user-edit-email-problem').textContent, 'Enter one email address.');
    p.input('#user-edit-email', 'carol@example.com');
    assert.equal(p.disabled(), false);
    assert.ok(p.$('#user-edit-email-problem').classList.contains('hidden'));
});

test('a generated password the server refuses is replaced without a word', async () => {
    const p = page({ refuse: 2 });
    p.w.editUser(null);
    p.input('#user-edit-name', 'erin');
    // Everything the refusal line ever says, while it happens
    const said = [];
    new p.w.MutationObserver(() => { const text = p.$('#user-edit-pw-problem').textContent; if (text) said.push(text); })
        .observe(p.$('#user-edit-pw-status'), { childList: true, subtree: true, characterData: true });
    p.$('#user-edit-pw-generate').click();
    for (let i = 0; i < 10; i++) await tick();
    assert.equal(p.checks.length, 3, 'two refused, the third accepted');
    assert.equal(new Set(p.checks.map(c => c.password)).size, 3, 'a new password each time');
    assert.equal(p.$('#user-edit-pass').value, p.checks[2].password);
    assert.equal(p.$('#user-edit-pass').type, 'text');
    assert.deepEqual(said, [], 'never shown or read out');
    assert.equal(p.problem(), '');
    assert.equal(p.disabled(), false);
});

test('Generate stops after 5 refused tries and then says why', async () => {
    const p = page({ refuse: 99 });
    p.w.editUser(null);
    p.input('#user-edit-name', 'erin');
    p.$('#user-edit-pw-generate').click();
    for (let i = 0; i < 20; i++) await tick();
    assert.equal(p.checks.length, 5);
    assert.equal(p.problem(), COMMON);
    assert.ok(p.disabled());
});

test('Save right after typing waits for the check, then sends', async () => {
    const p = page();
    p.w.editUser(null);
    p.input('#user-edit-name', 'erin');
    p.type(GOOD);
    assert.ok(p.disabled());
    await p.w.saveUser({ preventDefault() {} }, null);
    assert.equal(p.sent.length, 1);
    p.w.editUser(null);
    p.input('#user-edit-name', 'erin');
    p.type('Password1');
    await p.w.saveUser({ preventDefault() {} }, null);
    assert.equal(p.$('#user-edit-error').textContent, COMMON);
    assert.equal(p.sent.length, 1, 'nothing more sent');
});

test('editing: Save can go with the password left empty; a typed one must pass the check', async () => {
    const p = page();
    p.w.editUser(2);
    assert.equal(p.$('#user-edit-save').textContent, 'Save');
    assert.equal(p.disabled(), false, 'an empty field keeps the password');
    assert.ok(p.$('#user-edit-pw-meter').classList.contains('hidden'), 'the meter waits for typing');
    p.type('short');
    assert.ok(!p.$('#user-edit-pw-meter').classList.contains('hidden'));
    await settle();
    assert.equal(p.problem(), SHORT);
    assert.ok(p.disabled());
    await p.w.saveUser({ preventDefault() {} }, 2);
    assert.equal(p.$('#user-edit-error').textContent, SHORT);
    assert.equal(p.sent.length, 0);
    p.type('');
    assert.equal(p.disabled(), false);
    await p.w.saveUser({ preventDefault() {} }, 2);
    assert.equal(p.sent.length, 1);
    assert.ok(!('password' in JSON.parse(p.sent[0].options.body)), 'an empty field keeps the password');
});

test('Generate: a readable password of the length chosen, a new one when the length moves, dots once typed over', async () => {
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
    assert.ok(!/[0Oo1lI]/.test(field.value));
    assert.equal(p.$('#user-edit-pw-label').textContent, 'Password strength: Strong');
    const first = field.value;
    length.value = '32';
    length.dispatchEvent(new p.w.Event('input', { bubbles: true }));
    assert.equal(p.$('#user-edit-pw-length-value').textContent, '32');
    assert.equal(field.value.length, 32);
    assert.notEqual(field.value, first);
    p.$('#user-edit-pw-copy').click();
    await tick();
    assert.deepEqual(p.copied, [field.value]);
    assert.deepEqual(p.toasts, ['Password copied']);
    assert.ok(!p.toasts.some(t => t.includes(field.value)), 'the notice does not show the password');
    p.type(field.value + 'x');
    assert.equal(field.type, 'password', 'typed over: shown as dots again');
    // Moving the length now does not replace what was typed
    const typed = field.value;
    length.value = '40';
    length.dispatchEvent(new p.w.Event('input', { bubbles: true }));
    assert.equal(field.value, typed);
});

test('moving the length alone is not a change to discard; a generated password is', async () => {
    const asked = [];
    const p = page();
    p.w.showConfirmModal = async options => { asked.push(options.title); return false; };
    p.w.editUser(null);
    const length = p.$('#user-edit-pw-length');
    length.value = '40';
    length.dispatchEvent(new p.w.Event('input', { bubbles: true }));
    p.w.closeUserEditModal();
    await tick();
    assert.deepEqual(asked, []);
    assert.equal(p.$('#user-edit-modal'), null, 'closed without a question');
    p.w.editUser(null);
    p.$('#user-edit-pw-generate').click();
    p.w.closeUserEditModal();
    await tick();
    assert.deepEqual(asked, ['Discard your changes?']);
    assert.ok(p.$('#user-edit-modal'), 'kept open: Keep editing');
});

test('the dialog with the meter, the generator and a refused password has no axe violations', async () => {
    const p = page();
    p.w.editUser(null);
    p.input('#user-edit-name', 'x'.repeat(65));
    p.$('#user-edit-name').dispatchEvent(new p.w.Event('change', { bubbles: true }));
    p.type('Password1');
    await settle();
    assert.equal(p.problem(), COMMON);
    const script = p.w.document.createElement('script');
    script.textContent = axeSource;
    p.w.document.head.appendChild(script);
    const result = await p.w.axe.run(p.$('#user-edit-modal'), { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } });
    // Plain strings out of the page's realm, so the comparison is by value
    assert.deepEqual(Array.from(result.violations, v => `${v.id}: ${Array.from(v.nodes, n => String(n.target)).join(' ')}`), []);
});
