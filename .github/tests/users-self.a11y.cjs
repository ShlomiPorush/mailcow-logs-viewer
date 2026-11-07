// Settings > Users knows who is looking (GET /api/users you) and asks before a change that takes
// something away from that person's own access: their own row has a You tag; editing their own
// user to less access, disabling it or deleting it, and changing the access for everyone else
// while they get it themselves (an OAuth2 sign-in without an entry), and adding an OAuth2 entry
// for one's own email with less access or sign-in disabled, each ask first, in plain
// words, and send nothing on Cancel. A change that takes nothing away asks nothing.
// Set A11Y_MODULES to jsdom's node_modules to run it locally (see layers.a11y.cjs).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');

const AREAS = [
    { id: 'messages', label: 'Messages', view: 'Messages', act: '' },
    { id: 'quarantine', label: 'Quarantine', view: 'Held mail', act: 'Release' },
    { id: 'rspamd', label: 'Rspamd', view: 'Maps', act: 'Edit maps' },
];
const PRESETS = {
    admin: { messages: 'view', quarantine: 'act', rspamd: 'act' },
    operator: { messages: 'view', quarantine: 'act', rspamd: 'view' },
    viewer: { messages: 'view', quarantine: 'view', rspamd: 'view' },
    custom: {},
};
const ALL = ['messages:read', 'quarantine:read', 'quarantine:write', 'rspamd:read', 'rspamd:write', 'settings:read'];
const local = (id, username, access, extra = {}) => ({ id, kind: 'local', username, email: null, access, areas: PRESETS[access] || {},
    disabled: false, name_conflict: false, last_login_at: null, created_at: '2026-10-20T10:00:00Z', row_version: 1, ...extra });
const entry = (id, email, access) => ({ ...local(id, null, access), kind: 'oauth2', username: null, email });

function page({ you, status, defaultAccess = 'admin' }) {
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
        // The password check stores nothing: answered, not counted as sent
        if (url === '/api/users/password-check') return { ok: true, status: 200, json: async () => ({ ok: true, problem: null }) };
        sent.push({ url, method: options && options.method, body: options && options.body ? JSON.parse(options.body) : null });
        return { ok: true, status: 200, json: async () => ({ default_access: 'viewer', version: 2 }) };
    };
    w.loadUsersPanel = () => {};
    // app.js draws the panel through this; here it only needs to draw
    w.uiReplaceKeepingFocus = (box, html) => { box.innerHTML = html; };
    const data = {
        areas: AREAS, presets: Object.entries(PRESETS).map(([id, areas]) => ({ id, label: id, areas: id === 'custom' ? {} : areas })),
        builtin: { username: 'admin', basic_auth_enabled: true },
        oauth2: { enabled: true, default_access: defaultAccess, version: 1, provider_name: 'Authentik' },
        users: [local(2, 'ops', 'admin'), local(3, 'noc', 'viewer'), entry(4, 'lead@example.com', 'admin')],
        you,
    };
    run(`setAppAccess(${JSON.stringify({ authenticated: true, ...status })}); usersData = ${JSON.stringify(data)}; renderUsersPanel();`);
    const $ = sel => w.document.querySelector(sel);
    // The question shown, if any, answered with Cancel or its own button
    const asked = () => $('#app-confirm-modal') && { text: $('#app-confirm-modal .ui-confirm-text').textContent, ok: $('#app-confirm-ok').textContent };
    const answer = async ok => { $(ok ? '#app-confirm-ok' : '#app-confirm-cancel').click(); await new Promise(r => setTimeout(r, 0)); };
    const tick = () => new Promise(r => setTimeout(r, 0));
    return { w, $, sent, asked, answer, tick };
}

const ADMIN = { is_admin: true, scopes: ALL, user_name: 'ops' };

test('the person\'s own row says You', () => {
    const p = page({ you: { kind: 'local', user_id: 2, via_default: false }, status: ADMIN });
    assert.ok(p.$('[data-key="user-2"]').textContent.includes('You'));
    assert.ok(!p.$('[data-key="user-3"]').textContent.includes('You'));
    assert.ok(!p.$('[data-key="user-builtin"]').textContent.includes('You'));
    const q = page({ you: { kind: 'oauth2', user_id: 4, via_default: false }, status: { ...ADMIN, user_name: 'lead@example.com' } });
    assert.ok(q.$('[data-key="user-4"]').textContent.includes('You'));
    const b = page({ you: { kind: 'builtin', user_id: null, via_default: false }, status: { ...ADMIN, user_name: 'admin' } });
    assert.ok(b.$('[data-key="user-builtin"]').textContent.includes('You'));
});

test('making oneself a Viewer asks first, says what is lost, and Cancel sends nothing', async () => {
    const p = page({ you: { kind: 'local', user_id: 2, via_default: false }, status: ADMIN });
    p.w.editUser(2);
    p.$('#user-edit-level [data-level="viewer"]').click();
    const saving = p.w.saveUser({ preventDefault() {} }, 2);
    await p.tick();
    assert.deepEqual(p.asked(), {
        text: 'This is your own account. Changing its access signs you out at once, and you will lose Settings, Users and AI agents, and the actions you can take in Quarantine and Rspamd.',
        ok: 'Change my access',
    });
    await p.answer(false);
    await saving;
    assert.equal(p.sent.length, 0);
    assert.ok(p.$('#user-edit-modal'), 'the dialog stays open');
    const again = p.w.saveUser({ preventDefault() {} }, 2);
    await p.tick();
    await p.answer(true);
    await again;
    assert.equal(p.sent.length, 1);
    assert.equal(p.sent[0].body.access, 'viewer');
});

test('a change that takes nothing away from oneself asks nothing', async () => {
    // Only an admin edits users: staying Admin (here, a new password) takes nothing away
    const p = page({ you: { kind: 'local', user_id: 2, via_default: false }, status: ADMIN });
    p.w.editUser(2);
    p.$('#user-edit-pass').value = 'Another l0ng password';
    await p.w.saveUser({ preventDefault() {} }, 2);
    assert.equal(p.asked(), null);
    assert.equal(p.sent.length, 1);
    assert.equal(p.sent[0].body.access, 'admin');
    // Someone else's user: no question either
    const q = page({ you: { kind: 'local', user_id: 2, via_default: false }, status: ADMIN });
    q.w.editUser(3);
    q.$('#user-edit-disabled').checked = true;
    await q.w.saveUser({ preventDefault() {} }, 3);
    assert.equal(q.asked(), null);
    assert.equal(q.sent.length, 1);
});

test('disabling one\'s own sign-in and deleting oneself ask in their own words', async () => {
    const p = page({ you: { kind: 'local', user_id: 2, via_default: false }, status: ADMIN });
    p.w.editUser(2);
    p.$('#user-edit-disabled').checked = true;
    const saving = p.w.saveUser({ preventDefault() {} }, 2);
    await p.tick();
    assert.deepEqual(p.asked(), { text: 'This is your own account. Disabling sign-in signs you out at once.', ok: 'Disable my sign-in' });
    await p.answer(false);
    await saving;
    assert.equal(p.sent.length, 0);
    p.w.closeUserEditModal(true);
    const deleting = p.w.deleteUser(2);
    await p.tick();
    assert.deepEqual(p.asked(), { text: 'This is your own account. Deleting it signs you out at once, and you can no longer sign in.', ok: 'Delete my account' });
    await p.answer(true);
    await deleting;
    assert.deepEqual(p.sent.map(s => s.method), ['DELETE']);
});

test('an OAuth2 sign-in without an entry is asked before the access for everyone else goes down', async () => {
    const p = page({ you: { kind: 'oauth2', user_id: null, via_default: true }, status: { ...ADMIN, user_name: 'dave@example.com' } });
    const changing = p.w.setUsersDefault('viewer');
    await p.tick();
    assert.deepEqual(p.asked(), {
        text: 'You signed in with Authentik and get the access for everyone else. Changing it to Viewer changes your own access too: you will lose Settings, Users and AI agents, and the actions you can take in Quarantine and Rspamd.',
        ok: 'Change my access',
    });
    await p.answer(false);
    await changing;
    assert.equal(p.sent.length, 0);
    const none = p.w.setUsersDefault('none');
    await p.tick();
    assert.equal(p.asked().text, 'You signed in with Authentik and get the access for everyone else. Changing it to No access signs you out at once.');
    await p.answer(true);
    await none;
    assert.equal(p.sent.length, 1);
    assert.equal(p.sent[0].body.value, 'none');
});

test('with an entry of one\'s own, or another sign-in, the default change asks nothing', async () => {
    for (const you of [{ kind: 'oauth2', user_id: 4, via_default: false }, { kind: 'local', user_id: 2, via_default: false }]) {
        const p = page({ you, status: ADMIN });
        await p.w.setUsersDefault('viewer');
        assert.equal(p.asked(), null);
        assert.equal(p.sent.length, 1);
    }
});

test('deleting one\'s own OAuth2 entry says what the access for everyone else leaves', async () => {
    const p = page({ you: { kind: 'oauth2', user_id: 4, via_default: false }, status: { ...ADMIN, user_name: 'lead@example.com' }, defaultAccess: 'viewer' });
    const deleting = p.w.deleteUser(4);
    await p.tick();
    assert.equal(p.asked().text, 'This is your own entry. Without it you get the access for everyone else (Viewer): you will lose Settings, Users and AI agents, and the actions you can take in Quarantine and Rspamd.');
    await p.answer(false);
    await deleting;
    assert.equal(p.sent.length, 0);
});

test('adding an OAuth2 entry for one\'s own email with less access, or disabled, asks first', async () => {
    const you = { kind: 'oauth2', user_id: null, via_default: true, email: 'dave@example.com' };
    const p = page({ you, status: { ...ADMIN, user_name: 'dave@example.com' } });
    const add = (email, level, disabled) => {
        p.w.editUser(null);
        p.$('#user-edit-kind [data-kind="oauth2"]').click();
        p.$('#user-edit-email').value = email;
        p.$(`#user-edit-level [data-level="${level}"]`).click();
        p.$('#user-edit-disabled').checked = disabled;
        return p.w.saveUser({ preventDefault() {} }, null);
    };
    // Compared as the server compares: spaces, case
    const saving = add(' Dave@Example.COM ', 'viewer', false);
    await p.tick();
    assert.deepEqual(p.asked(), {
        text: 'This is your own email address. Adding it gives you this access instead of yours now: you will lose Settings, Users and AI agents, and the actions you can take in Quarantine and Rspamd.',
        ok: 'Change my access',
    });
    await p.answer(false);
    await saving;
    assert.equal(p.sent.length, 0);
    assert.ok(p.$('#user-edit-modal'), 'the dialog stays open');
    p.w.closeUserEditModal(true);
    const disabling = add('dave@example.com', 'admin', true);
    await p.tick();
    assert.deepEqual(p.asked(), { text: 'This is your own email address. Adding it with sign-in disabled signs you out at once.', ok: 'Disable my sign-in' });
    await p.answer(true);
    await disabling;
    assert.equal(p.sent.length, 1);
    assert.equal(p.sent[0].body.email, 'dave@example.com');
    // Someone else's email, or one's own as Admin: no question
    for (const [email, level] of [['erin@example.com', 'viewer'], ['dave@example.com', 'admin']]) {
        const q = page({ you, status: { ...ADMIN, user_name: 'dave@example.com' } });
        q.w.editUser(null);
        q.$('#user-edit-kind [data-kind="oauth2"]').click();
        q.$('#user-edit-email').value = email;
        q.$(`#user-edit-level [data-level="${level}"]`).click();
        await q.w.saveUser({ preventDefault() {} }, null);
        assert.equal(q.asked(), null);
        assert.equal(q.sent.length, 1);
    }
});
