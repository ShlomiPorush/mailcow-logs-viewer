// Settings controls that guard a value: Log level is a list of the levels the
// backend runs, the session signing key has Generate, the Basic Auth password
// cannot be removed while Basic Auth is on, and Message linking sits in Fetch.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');

function stub() {
    const fn = function () { return proxy; };
    const proxy = new Proxy(fn, {
        get: (_, key) => (key === Symbol.toPrimitive ? () => '' : key === 'length' ? 0 : proxy),
        apply: () => proxy,
        construct: () => proxy,
    });
    return proxy;
}

function load() {
    const context = vm.createContext({
        document: stub(), window: { matchMedia: () => ({ matches: false }), addEventListener() {} }, localStorage: stub(),
        sessionStorage: stub(), navigator: stub(), location: stub(), console: { log() {}, error() {}, warn() {} },
        setTimeout() {}, setInterval() {}, clearTimeout() {}, URLSearchParams, Intl,
    });
    for (const file of ['utils.js', 'app.js', 'settings.js']) {
        vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    }
    return context;
}

const render = (c, key, value) => vm.runInContext(
    `renderSettingsEditField(${JSON.stringify(key)}, ${JSON.stringify(value)}, SETTINGS_SENSITIVE_KEYS, '', false, '')`, c);

test('Log level is a list, and shows the level that runs', () => {
    const c = load();
    assert.deepEqual([...vm.runInContext('SETTINGS_FIELD_OPTIONS.log_level.map(o => o.value)', c)],
        ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']);
    assert.match(render(c, 'log_level', 'ERROR'), /<select id="edit-log_level"[^>]*>[\s\S]*<option value="ERROR" selected>/);
    // The backend reads any letters, and runs an unknown level as WARNING
    assert.match(render(c, 'log_level', 'info'), /<option value="INFO" selected>/);
    for (const stored of ['verbose', '', null]) {
        const html = render(c, 'log_level', stored);
        assert.match(html, /<option value="WARNING" selected>/, String(stored));
        assert.equal((html.match(/ selected>/g) || []).length, 1);
    }
});

test('the session signing key has Generate, empty or stored, and no other secret has it', () => {
    const c = load();
    assert.match(render(c, 'session_secret_key', ''), /onclick="settingsGenerateSecret\(this\)">Generate</);
    assert.match(render(c, 'session_secret_key', '********'), /onclick="settingsGenerateSecret\(this\)">Generate</);
    assert.doesNotMatch(render(c, 'auth_password', ''), /settingsGenerateSecret/);
});

// A field with its input, as settingsGenerateSecret finds it
function field() {
    const input = { type: 'password', value: '', events: [], dispatchEvent(e) { this.events.push(e.type); }, focus() {} };
    return { input, btn: { closest: () => ({ querySelector: sel => (sel === 'input[type="password"]' ? input : null) }) } };
}

test('Generate fills a new random key of 64 hex characters', () => {
    const c = load();
    c.crypto = require('node:crypto').webcrypto;
    c.Event = class { constructor(type) { this.type = type; } };
    const a = field(); const b = field();
    c.settingsGenerateSecret(a.btn);
    c.settingsGenerateSecret(b.btn);
    assert.match(a.input.value, /^[0-9a-f]{64}$/);
    assert.notEqual(a.input.value, b.input.value);
    // So the form counts it as a change
    assert.deepEqual(a.input.events, ['input']);
});

test('Remove of the Basic Auth password is off while Basic Auth is on', () => {
    const c = load();
    assert.match(render(c, 'auth_password', '********'), /onclick="settingsRemoveSecret\(this\)" data-needs-basic-off>Remove</);
    assert.doesNotMatch(render(c, 'smtp_password', '********'), /data-needs-basic-off/);

    const removing = { value: false };
    const btn = { disabled: false, title: '', closest: sel => (sel === '.is-removing' && removing.value ? {} : null) };
    const basic = { type: 'checkbox', checked: true };
    // The reason is on the screen too: a disabled button's title is out of reach by keyboard
    const hidden = new Set(['hidden']);
    const note = { classList: { toggle: (name, force) => (force ? hidden.add(name) : hidden.delete(name)) } };
    const parts = { '[data-needs-basic-off]': btn, '#edit-basic_auth_enabled': basic, '[data-remove-note]': note };
    const root = { querySelector: sel => parts[sel] || null };
    assert.match(render(c, 'auth_password', '********'), /<small class="ui-muted hidden" data-remove-note>Turn off Basic Auth to remove the password\.<\/small>/);
    let taken = 0;
    c.settingsRemoveSecret = () => { taken += 1; removing.value = false; };

    c.settingsLockPasswordRemove(root);
    assert.equal(btn.disabled, true);
    assert.match(btn.title, /Basic Auth/);
    assert.equal(hidden.has('hidden'), false);

    basic.checked = false;
    c.settingsLockPasswordRemove(root);
    assert.equal(btn.disabled, false);
    assert.equal(btn.title, '');
    assert.equal(hidden.has('hidden'), true);

    // Chosen to remove, then Basic Auth turned on: the removal is taken back
    removing.value = true;
    basic.checked = true;
    c.settingsLockPasswordRemove(root);
    assert.equal(taken, 1);
    assert.equal(btn.disabled, true);

    // AUTH_ENABLED in the environment keeps Basic Auth on with the switch off
    basic.checked = false;
    c.settingsLockPasswordRemove(root, true);
    assert.equal(btn.disabled, true);
    assert.match(btn.title, /AUTH_ENABLED/);
    assert.equal(hidden.has('hidden'), false);
    c.settingsLockPasswordRemove(root, false);
    assert.equal(btn.disabled, false);
});

test('Message linking is a section of Fetch, and has no section of its own', () => {
    const c = load();
    const tabs = vm.runInContext('SETTINGS_EDIT_TABS', c);
    assert.ok(!tabs.some(t => t.id === 'correlation'));
    const fetch = tabs.find(t => t.id === 'fetch');
    assert.ok(fetch.groups.some(g => g.keys.includes('max_correlation_age_minutes') && g.keys.includes('correlation_check_interval')));
    assert.ok(!vm.runInContext('SETTINGS_TAB_GROUPS', c).some(g => g.tabs.includes('correlation')));
    // Its old address opens Fetch: outbound-area.test.cjs, with the other moved addresses
});

test('Status code exceptions start closed and say what is excluded', () => {
    const c = load();
    const html = vm.runInContext(`settingsBounceCodes('hard', { suppression_hard_bounce_excluded_codes: '5.2.1', suppression_hard_bounce_standard_codes: true },
        new Set(), { suppression_hard_bounce_excluded_codes: '', suppression_hard_bounce_standard_codes: true })`, c);
    assert.match(html, /<details class="ui-collapse ui-set-codes-fold"><summary>/);
    assert.doesNotMatch(html, /<details class="ui-collapse ui-set-codes-fold" open/);
    // The value and its Reset stay reachable with the area closed
    assert.match(html, /<input type="hidden" id="edit-suppression_hard_bounce_excluded_codes"[^>]*><\/div><\/details><button type="button" class="ui-set-clear is-reset"/);
    const says = (standard, count) => c.settingsCodesSummary(standard, count);
    assert.match(says(true, 0), /unrelated to the recipient/);
    assert.match(says(true, 2), /2 codes/);
    assert.match(says(false, 1), /1 code\b/);
    // Without the switch, or with it off, nothing but the added codes is excluded
    assert.equal(says(false, 0), says(null, 0));
});

test('search and the save check open a closed area to reach its field', () => {
    for (const file of ['search.js', 'settings.js']) {
        const code = fs.readFileSync(path.join(frontend, file), 'utf8');
        assert.match(code, /closest\('details:not\(\[open\]\)'\); fold; fold = fold\.parentElement\.closest\('details:not\(\[open\]\)'\)\) fold\.open = true;/, file);
    }
});
