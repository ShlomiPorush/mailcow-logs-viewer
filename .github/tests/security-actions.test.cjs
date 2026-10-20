// The Security page's actions say and send what really happens: a single
// IPv6 address is written to the Fail2ban lists as /128, not as a /32 network;
// a button is offered only when the server will take its request; and the texts
// describe the period and the settings in force.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');

// Any DOM access returns another inert stub, so a file's top-level code runs
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
        document: stub(), window: { matchMedia: () => ({ matches: false }), addEventListener() {} }, localStorage: stub(), navigator: stub(),
        location: stub(), console: { log() {}, error() {}, warn() {} }, setTimeout() {}, setInterval() {}, appTimezone: 'UTC',
    });
    for (const file of ['utils.js', 'app.js', 'smtp-abuse.js', 'protection.js', 'security.js']) {
        vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    }
    return context;
}

// Confirms every dialog and records what is asked and what is sent
function recordRequests(context) {
    const sent = [];
    const asked = [];
    context.showConfirmModal = async options => { asked.push(options.message); return true; };
    context.showToast = () => {};
    context.authenticatedFetch = async (url, options = {}) => {
        sent.push([url, options.body ? JSON.parse(options.body) : null]);
        return { ok: true, json: async () => ({ status: 'success' }) };
    };
    for (const name of ['loadFail2BanSettings', 'smartRefreshNetfilter', 'renderSecurityOverview', 'refreshSecurityAddresses', 'loadSmtpAbusePanel']) {
        context[name] = () => {};
    }
    return { sent, asked };
}

test('a single address goes on the Fail2ban lists as /32 for IPv4 and /128 for IPv6', async () => {
    const context = load();
    const { sent, asked } = recordRequests(context);
    await context.banIP('2001:db8::1');
    await context.allowIP('2001:db8::2');
    await context.unbanIP('2001:db8::3');
    await context.banIP('198.51.100.7');
    await context.banIP('2001:db8::/64');
    assert.deepEqual(sent.map(([url, body]) => [url, body.ip]), [
        ['/api/fail2ban/ban', '2001:db8::1/128'],
        ['/api/fail2ban/allow', '2001:db8::2/128'],
        ['/api/fail2ban/unban', '2001:db8::3/128'],
        ['/api/fail2ban/ban', '198.51.100.7/32'],
        ['/api/fail2ban/ban', '2001:db8::/64'],
    ]);
    assert.ok(asked.every(message => !/2001:db8::\d\/32/.test(message)), asked.join('\n'));
});

test('a /32 IPv6 entry is a network, not the address it starts with', () => {
    const context = load();
    const bare = entry => vm.runInContext(`securityBare(${JSON.stringify(entry)})`, context);
    assert.equal(bare('2001:db8::1/128'), '2001:db8::1');
    assert.equal(bare('2001:db8::1/32'), '2001:db8::1/32');
    assert.equal(bare('198.51.100.7/32'), '198.51.100.7');
});

function address(overrides = {}) {
    return { ip: '203.0.113.7', tries: 4, attempts: 4, users: [], services: [], hits: [], f2b: null, listedAs: null, state: 'quiet', ...overrides };
}

test('the address buttons name the entry they write', () => {
    const context = load();
    vm.runInContext('mailcowRwConfigured = true; fail2banActiveBans = []', context);
    const { acts } = context.securityDescribe(address({ ip: '2001:db8::9' }));
    assert.match(acts, /2001:db8::9\/128/);
    assert.doesNotMatch(acts, /2001:db8::9\/32/);
});

test('the failed logins of an address are counted over the chosen period', () => {
    const context = load();
    vm.runInContext('securityDays = 7', context);
    assert.match(context.securityFailedText(address(), []), /4 in the last 7 days/);
});

const ownedBan = { id: 5, rule: 'trap', status: 'banned', owned: true, reason: 'Tried the trap account admin',
    banned_at: '2026-10-16T10:00:00Z', last_seen: '2026-10-16T10:00:00Z', expires_at: null };

test('a ban the rules wrote offers Undo only with the Read-Write key', () => {
    const context = load();
    const banned = address({ state: 'banned', hits: [ownedBan] });
    vm.runInContext('mailcowRwConfigured = false', context);
    assert.doesNotMatch(context.securityDescribe(banned).acts, /Undo/);
    // A ban the rules did not write is only forgotten, which needs no key
    assert.match(context.securityDescribe(address({ state: 'banned', hits: [{ ...ownedBan, owned: false }] })).acts, /Undo/);
    // A ban that is not written yet can always be cancelled
    assert.match(context.securityDescribe(address({ state: 'review', hits: [{ ...ownedBan, status: 'pending' }] })).acts, /Undo/);
    vm.runInContext('mailcowRwConfigured = true', context);
    assert.match(context.securityDescribe(banned).acts, /Undo/);
});

test('the denylist offers Remove on a rule ban only with the Read-Write key', () => {
    const context = load();
    const box = { innerHTML: '' };
    context.document = { getElementById: id => (id === 'security-lists' ? box : null) };
    vm.runInContext(`mailcowRwConfigured = false; fail2banActiveBans = []; fail2banWhitelist = [];
        fail2banBlacklist = ['203.0.113.7/32']; securityHits = [${JSON.stringify({ ...ownedBan, ip: '203.0.113.7' })}]`, context);
    context.renderSecurityLists();
    assert.match(box.innerHTML, /203\.0\.113\.7\/32/);
    assert.doesNotMatch(box.innerHTML, /undoProtectionHit/);
});

test('Outgoing spam counts as on only when its check can run', () => {
    const context = load();
    const abuse = () => context.securityProtectionItems().find(p => p.key === 'abuse');
    vm.runInContext('fail2banPolicy = null; smtpAbuseStatus = { enabled: true, rw_key_configured: false }', context);
    assert.equal(abuse().state, 'off');
    assert.match(abuse().note, /Read-Write/);
    vm.runInContext('smtpAbuseStatus = { enabled: true, rw_key_configured: true }', context);
    assert.equal(abuse().state, 'on');
});

test('the Outgoing spam card says it stops mailboxes only with the Read-Write key', () => {
    const context = load();
    vm.runInContext(`securityAppSettings = { configuration: { smtp_abuse_enabled: true }, env_locked_keys: [],
        settings_edit_via_ui_enabled: true, settings_migrated: true }; mailcowRwConfigured = false`, context);
    const card = () => vm.runInContext("securityCardHtml('abuse')", context);
    assert.doesNotMatch(card(), /Stops mailboxes/);
    assert.match(card(), /Needs a Read-Write key/);
    vm.runInContext('mailcowRwConfigured = true', context);
    assert.match(card(), /Stops mailboxes/);
});


test('Disable SMTP mentions app passwords only when they are revoked', async () => {
    for (const revoke of [false, true]) {
        const context = load();
        const { asked } = recordRequests(context);
        vm.runInContext(`smtpAbuseStatus = { enabled: true, rw_key_configured: true, revoke_app_passwords: ${revoke} }`, context);
        await context.smtpAbuseAction('user@example.com', 'block');
        assert.equal(/app passwords/.test(asked[0]), revoke, asked[0]);
    }
});

test('the Outgoing spam card and its setting do not say IMAP is never affected', () => {
    const intro = revoke => {
        const context = load();
        const panel = { innerHTML: '', insertAdjacentHTML() {} };
        context.document = { getElementById: id => (id === 'smtp-abuse-panel' ? panel : null) };
        context.securityUpdateSaveBar = () => {};
        vm.runInContext(`smtpAbuseStatus = { enabled: true, rw_key_configured: true, revoke_app_passwords: ${revoke},
            window_minutes: 60, mailboxes: [] }`, context);
        context.renderSmtpAbusePanel();
        return panel.innerHTML.match(/ui-sa-intro">([\s\S]*?)<\/p>/)[1];
    };
    assert.doesNotMatch(intro(true), /IMAP/);
    assert.match(intro(true), /app passwords are revoked/);
    assert.doesNotMatch(intro(false), /app passwords/);
    const context = load();
    vm.runInContext(fs.readFileSync(path.join(frontend, 'settings.js'), 'utf8'), context);
    assert.doesNotMatch(context.SETTINGS_FIELD_DESCRIPTIONS.smtp_abuse_enabled, /IMAP is never affected/);
    const tab = context.SETTINGS_EDIT_TABS.find(t => t.id === 'smtp_abuse').description;
    assert.doesNotMatch(tab, /IMAP is never affected|Abuse Protection/);
    assert.match(tab, /Security → Settings → Outgoing spam/);
});

test('Unban names and drops the network Fail2ban banned around the address', async () => {
    const context = load();
    const { sent, asked } = recordRequests(context);
    const toasts = [];
    context.showToast = (message, kind) => toasts.push([message, kind]);
    context.authenticatedFetch = async (url, options = {}) => {
        sent.push([url, JSON.parse(options.body)]);
        return { ok: true, json: async () => ({ status: 'success', networks: ['198.51.100.0/24'] }) };
    };
    vm.runInContext(`mailcowRwConfigured = true; fail2banActiveBans = [
        { network: '198.51.100.0/24', ip: '198.51.100.0', banned_until: '00h 20m 00s', queued_for_unban: 0 },
        { network: '203.0.113.5/32', ip: '203.0.113.5', banned_until: '00h 20m 00s', queued_for_unban: 0 }]`, context);
    // The Security page row of a network ban unbans, and names, the network
    const { acts } = context.securityDescribe(address({ ip: '198.51.100.0', state: 'banned',
        f2b: { network: '198.51.100.0/24', ip: '198.51.100.0', banned_until: '00h 20m 00s', queued_for_unban: 0 } }));
    assert.match(acts, /unbanIP\('198\.51\.100\.0\/24'/);
    assert.match(acts, /title="Unban 198\.51\.100\.0\/24"/);
    // The Events list unbans the address that tried; the answer says what was lifted
    await context.unbanIP('198.51.100.7');
    assert.deepEqual(sent, [['/api/fail2ban/unban', { ip: '198.51.100.7/32' }]]);
    assert.doesNotMatch(asked[0], /\/32/);
    assert.deepEqual(toasts, [['198.51.100.0/24 unbanned successfully', 'success']]);
    assert.equal(vm.runInContext('JSON.stringify(fail2banActiveBans.map(b => b.network))', context), '["203.0.113.5/32"]');
});

test('Ban and Allow say so when the address is already on the list', async () => {
    const context = load();
    recordRequests(context);
    const toasts = [];
    context.showToast = message => toasts.push(message);
    context.authenticatedFetch = async (url, options = {}) => {
        const label = url.endsWith('/allow') ? 'allowlist' : 'blacklist';
        const msg = `IP ${JSON.parse(options.body).ip} is already in the ${label}`;
        return { ok: true, json: async () => ({ status: 'success', msg, already: true }) };
    };
    await context.banIP('198.51.100.7');
    await context.allowIP('192.0.2.10');
    assert.deepEqual(toasts, ['IP 198.51.100.7/32 is already in the blacklist', 'IP 192.0.2.10/32 is already in the allowlist']);
});
