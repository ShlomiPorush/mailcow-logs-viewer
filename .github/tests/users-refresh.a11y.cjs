// Settings > Users refreshes by itself (users.js refreshUsersPanel): a button that had the
// focus keeps it through a redraw (its row, by data-key, as app.js uiReplaceKeepingFocus
// finds it), a row that left gives the focus to the row now in its place, and an answer
// read before a change made here never draws the old state over it. Runs in a real DOM
// (jsdom), installed by CI outside the repository; set A11Y_MODULES to its node_modules:
//   npm install --no-save --prefix /tmp/a11y jsdom axe-core
//   A11Y_MODULES=/tmp/a11y/node_modules node --test .github/tests/users-refresh.a11y.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');

const user = (id, username, access = 'viewer') => ({ id, kind: 'local', username, email: null, access, areas: {}, disabled: false,
    name_conflict: false, last_login_at: null, created_at: '2026-10-20T10:00:00Z', row_version: 1 });
const overview = (users, defaultAccess = 'admin', version = 1) => ({
    areas: [{ id: 'messages', label: 'Messages', view: 'Messages', act: '' }],
    presets: ['admin', 'operator', 'viewer', 'custom'].map(id => ({ id, label: id, areas: {} })),
    builtin: { username: 'admin', basic_auth_enabled: true },
    oauth2: { enabled: true, default_access: defaultAccess, version },
    users,
});

function page() {
    const dom = new JSDOM(`<!doctype html><html lang="en"><head><title>t</title></head><body>
        <div class="settings-edit-content" data-keep-scroll><div data-tab-extra="users"><div id="users-panel"></div></div></div>
        </body></html>`, { runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/settings/users' });
    const w = dom.window;
    w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    const run = source => {
        const script = w.document.createElement('script');
        script.textContent = source;
        w.document.head.appendChild(script);
    };
    [read('utils.js'), read('router.js'), read('app.js'), read('users.js')].forEach(run);
    // A request answers what is served for it; a function answers when it wants to
    run(`var served = {}; authenticatedFetch = async (url, options) => {
        const answer = served[((options && options.method) || 'GET') + ' ' + url.split('?')[0]];
        const data = typeof answer === 'function' ? await answer() : answer;
        return { ok: true, status: 200, json: async () => data };
    };`);
    // jsdom has no layout: the section counts as shown
    w.document.getElementById('users-panel').getClientRects = () => [{}];
    const $ = s => w.document.querySelector(s);
    const button = (key, text) => [...w.document.querySelectorAll(`[data-key="${key}"] button`)].find(b => b.textContent.trim() === text);
    return { w, run, $, button };
}

test('a refresh keeps the focus on the same button of the same user', async () => {
    const p = page();
    p.w.served['GET /api/users'] = overview([user(2, 'dana'), user(3, 'noc')]);
    await p.w.loadUsersPanel();
    p.button('user-3', 'Delete').focus();
    // Someone else added a user listed above noc
    p.w.served['GET /api/users'] = overview([user(4, 'ann'), user(2, 'dana'), user(3, 'noc')]);
    await p.w.refreshUsersPanel();
    assert.ok(p.$('[data-key="user-4"]'), 'the new user is shown');
    assert.equal(p.w.document.activeElement, p.button('user-3', 'Delete'));
});

test('a row that left gives the focus to the row in its place', async () => {
    const p = page();
    p.w.served['GET /api/users'] = overview([user(2, 'dana'), user(3, 'noc'), user(5, 'zed')]);
    await p.w.loadUsersPanel();
    p.button('user-3', 'Edit').focus();
    p.w.served['GET /api/users'] = overview([user(2, 'dana'), user(5, 'zed')]);
    await p.w.refreshUsersPanel();
    const active = p.w.document.activeElement;
    assert.equal(active.tagName, 'BUTTON');
    assert.ok(active.closest('[data-key]'), 'the focus is on a row, not lost');
});

test('an answer read before a change made here does not draw the old state', async () => {
    const p = page();
    p.w.served['GET /api/users'] = overview([user(2, 'dana')], 'admin', 1);
    await p.w.loadUsersPanel();
    // A refresh starts and its answer (the state before the change) is slow
    let release;
    p.w.served['GET /api/users'] = () => new Promise(resolve => { release = () => resolve(overview([user(2, 'dana')], 'admin', 1)); });
    const refreshing = p.w.refreshUsersPanel();
    // Meanwhile the admin changes the access for everyone else
    p.w.served['PUT /api/users/oauth2-default'] = { default_access: 'viewer', version: 2 };
    await p.w.setUsersDefault('viewer');
    release();
    await refreshing;
    const pressed = p.$('.ui-users-default .ui-seg [aria-pressed="true"]');
    assert.equal(pressed.textContent.trim(), 'Viewer');
    assert.equal(p.w.eval('usersData.oauth2.version'), 2);
});

test('refresh starts, save starts, refresh ends, save ends: the screen shows the save', async () => {
    const p = page();
    p.w.served['GET /api/users'] = overview([user(2, 'dana')], 'admin', 1);
    await p.w.loadUsersPanel();
    let endRefresh, endSave;
    p.w.served['GET /api/users'] = () => new Promise(resolve => { endRefresh = () => resolve(overview([user(2, 'dana')], 'admin', 1)); });
    p.w.served['PUT /api/users/oauth2-default'] = () => new Promise(resolve => { endSave = () => resolve({ default_access: 'viewer', version: 2 }); });
    const refreshing = p.w.refreshUsersPanel();
    const saving = p.w.setUsersDefault('viewer');
    endRefresh();
    await refreshing;
    endSave();
    await saving;
    assert.equal(p.$('.ui-users-default .ui-seg [aria-pressed="true"]').textContent.trim(), 'Viewer');
    assert.equal(p.w.eval('usersData.oauth2.version'), 2);
});

test('save starts, a refresh starts and ends first with the old state, save ends: the screen shows the save', async () => {
    const p = page();
    p.w.served['GET /api/users'] = overview([user(2, 'dana')], 'admin', 1);
    await p.w.loadUsersPanel();
    let endSave;
    p.w.served['PUT /api/users/oauth2-default'] = () => new Promise(resolve => { endSave = () => resolve({ default_access: 'viewer', version: 2 }); });
    const saving = p.w.setUsersDefault('viewer');
    // Read before the save was stored: the old access, with a new user someone else added
    p.w.served['GET /api/users'] = overview([user(2, 'dana'), user(6, 'eve')], 'admin', 1);
    await p.w.refreshUsersPanel();
    endSave();
    await saving;
    assert.equal(p.$('.ui-users-default .ui-seg [aria-pressed="true"]').textContent.trim(), 'Viewer');
    assert.equal(p.w.eval('usersData.oauth2.version'), 2);
    assert.ok(p.$('[data-key="user-6"]'), 'what the refresh brought stays');
});

test('an older load that fails late does not wipe the list a newer load drew', async () => {
    const p = page();
    let fail;
    p.w.served['GET /api/users'] = () => new Promise((resolve, reject) => { fail = () => reject(new Error('network')); });
    const older = p.w.loadUsersPanel();
    p.w.served['GET /api/users'] = overview([user(2, 'dana')]);
    await p.w.loadUsersPanel();
    fail();
    await older;
    assert.ok(p.$('[data-key="user-2"]'), 'the list stays');
    assert.ok(!p.$('#users-panel .ui-text-fail'), 'no error shown');
});

test('after a failed load the next refresh draws the list, also when nothing changed', async () => {
    const p = page();
    p.w.served['GET /api/users'] = overview([user(2, 'dana')]);
    await p.w.loadUsersPanel();
    p.w.served['GET /api/users'] = () => Promise.reject(new Error('network'));
    await p.w.loadUsersPanel();
    assert.ok(p.$('#users-panel .ui-text-fail'), 'the error is shown');
    p.w.served['GET /api/users'] = overview([user(2, 'dana')]);
    await p.w.refreshUsersPanel();
    assert.ok(p.$('[data-key="user-2"]'), 'the list is back');
});

test('a late save answer does not undo a newer change a refresh already shows', async () => {
    const p = page();
    p.w.served['GET /api/users'] = overview([user(2, 'dana')], 'admin', 1);
    await p.w.loadUsersPanel();
    let endSave;
    p.w.served['PUT /api/users/oauth2-default'] = () => new Promise(resolve => { endSave = () => resolve({ default_access: 'viewer', version: 2 }); });
    const saving = p.w.setUsersDefault('viewer');
    // Another admin changed it again meanwhile; the refresh shows that (version 3)
    p.w.served['GET /api/users'] = overview([user(2, 'dana')], 'operator', 3);
    await p.w.refreshUsersPanel();
    endSave();
    await saving;
    assert.equal(p.$('.ui-users-default .ui-seg [aria-pressed="true"]').textContent.trim(), 'Operator');
    assert.equal(p.w.eval('usersData.oauth2.version'), 3);
});