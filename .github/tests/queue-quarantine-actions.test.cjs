// Queue and Quarantine: the row actions follow the Read-Write key even when its
// status arrives after the rows were drawn, Suppress stays without the key, and
// editing a quarantine rule saves it back unchanged.
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

function decodeEntities(value) {
    return value.replace(/&(#\d+|#x[0-9a-f]+|quot|amp|lt|gt|apos);/gi, (m, e) => {
        const named = { quot: '"', amp: '&', lt: '<', gt: '>', apos: "'" };
        if (e[0] === '#') return String.fromCodePoint(e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
        return named[e.toLowerCase()];
    });
}

// app.js with a document whose elements keep what the page writes into them
function loadApp() {
    const elements = {};
    const inserted = [];
    const element = () => ({ innerHTML: '', textContent: '', value: '', style: {}, classList: stub(), remove() {}, focus() {} });
    const document = new Proxy(stub(), {
        get: (target, key) => key === 'getElementById' ? id => (elements[id] = elements[id] || element())
            : key === 'body' ? { style: {}, insertAdjacentHTML: (where, html) => inserted.push(html) } : stub(),
    });
    const base = stub();
    const window = new Proxy({}, { get: (_, key) => key === 'matchMedia' ? () => ({ matches: false, addEventListener() {} }) : base[key] });
    const context = vm.createContext({
        document, window, localStorage: stub(), navigator: stub(), location: stub(),
        console: { log() {}, error() {}, warn() {} }, setTimeout() {}, setInterval() {}, appTimezone: 'UTC',
    });
    for (const file of ['utils.js', 'app.js']) vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    context.showToast = () => {};
    return { context, elements, inserted };
}

const QUEUE = [{
    queue_id: 'ABC123', queue_name: 'deferred', sender: 'sender@example.com', arrival_time: 1760000000,
    message_size: 2048, recipients: ['user@example.org (connect to mx.example.org: Connection timed out)'],
}];

function drawQueue(app, rw) {
    vm.runInContext(`currentTab = 'queue'; mailcowRwConfigured = ${rw}; allQueueData = ${JSON.stringify(QUEUE)};`, app.context);
    app.context.applyQueueFilters();
    return app.elements['queue-logs'].innerHTML;
}

test('queue rows get their actions when the Read-Write status arrives after them', async () => {
    const app = loadApp();
    assert.match(drawQueue(app, false), /Queue actions are locked/);
    app.context.authenticatedFetch = async () => ({ ok: true, json: async () => ({ rw_configured: true }) });
    await app.context.fetchRwStatus();
    const html = app.elements['queue-logs'].innerHTML;
    assert.doesNotMatch(html, /Queue actions are locked/);
    assert.match(html, /queueRetry\(/);
    assert.match(html, /queueDeleteItem\(/);
});

test('quarantine rows get their actions when the Read-Write status arrives after them', async () => {
    const app = loadApp();
    const data = { total: 1, data: [{ id: 7, sender: 'sender@example.com', rcpt: 'user@example.org', subject: 'Hello', score: 9, action: 'reject', created: 1760000000 }] };
    vm.runInContext(`currentTab = 'quarantine'; mailcowRwConfigured = false;`, app.context);
    app.context.renderQuarantineData(data);
    assert.match(app.elements['quarantine-logs'].innerHTML, /Quarantine actions are locked/);
    app.context.authenticatedFetch = async () => ({ ok: true, json: async () => ({ rw_configured: true }) });
    await app.context.fetchRwStatus();
    assert.doesNotMatch(app.elements['quarantine-logs'].innerHTML, /Quarantine actions are locked/);
});

test('a direct load of the Queue waits for the Read-Write status instead of showing the lock', async () => {
    const app = loadApp();
    let answerRw;
    const rw = new Promise(resolve => { answerRw = resolve; });
    app.context.authenticatedFetch = async url => url === '/api/rw-status'
        ? rw.then(() => ({ ok: true, json: async () => ({ rw_configured: true }) }))
        : { ok: true, json: async () => ({ data: QUEUE }) };
    vm.runInContext(`currentTab = 'queue'; rwStatusReady = fetchRwStatus();`, app.context);
    const loading = app.context.loadQueue();
    await new Promise(resolve => setImmediate(resolve));
    assert.doesNotMatch(app.elements['queue-logs'].innerHTML, /actions are locked/);
    answerRw();
    await loading;
    const html = app.elements['queue-logs'].innerHTML;
    assert.doesNotMatch(html, /actions are locked/);
    assert.match(html, /queueRetry\(/);
});

test('Suppress stays on queue rows without the Read-Write key', () => {
    const html = drawQueue(loadApp(), false);
    // With the row's queue id, so the block keeps that message in its Block details
    assert.match(html, /showAddSuppressionModal\('user@example\.org', 'ABC123'\)/);
    assert.doesNotMatch(html, /queue-action-btn|queue-checkbox/);
    assert.match(html, /Actions<\/span>/);
});

test('with the key, queue rows keep every action', () => {
    const html = drawQueue(loadApp(), true);
    for (const action of ['queueRetry', 'queueHold', 'queueDeleteItem', 'showAddSuppressionModal']) assert.match(html, new RegExp(action + '\\('));
});

// Open the edit dialog for a stored rule, save it as the dialog shows it, and
// return what the dialog showed and what it sent
async function editAndSave(rule) {
    const app = loadApp();
    app.context.closeQuarantineRuleModal = () => {};
    app.context.loadQuarantineRules = async () => {};
    app.context._showQuarantineRuleModal(rule, null);
    const html = app.inserted.pop();
    const modeSelect = html.match(/<select id="qrule-match-mode"[\s\S]*?<\/select>/)[0];
    const shownMode = (modeSelect.match(/<option value="(\w+)" selected>/) || [])[1];
    const shownValue = decodeEntities(html.match(/id="qrule-match-value" value="([^"]*)"/)[1]);
    const fields = { 'qrule-name': rule.name, 'qrule-match-type': rule.match_type, 'qrule-match-value': shownValue,
                     'qrule-match-mode': shownMode, 'qrule-action': rule.action, 'qrule-notes': '' };
    for (const [id, value] of Object.entries(fields)) app.elements[id] = { value };
    let sent = null;
    app.context.authenticatedFetch = async (url, options) => { sent = JSON.parse(options.body); return { ok: true, json: async () => ({}) }; };
    await app.context.saveQuarantineRule(rule.id);
    return { shownMode, shownValue, sent };
}

const rule = (match_value, is_regex) => ({ id: 3, name: 'Rule', match_type: 'sender', match_value, is_regex, action: 'release' });

test('a Contains rule opens as Contains with its plain text and saves unchanged', async () => {
    const { shownMode, shownValue, sent } = await editAndSave(rule('example\\.com', true));
    assert.equal(shownMode, 'contains');
    assert.equal(shownValue, 'example.com');
    assert.equal(sent.match_value, 'example\\.com');
    assert.equal(sent.is_regex, true);
});

test('a regex without a leading ^ opens as Regex and saves unchanged', async () => {
    for (const value of ['.*@(spam|junk)\\.example$', 'invoice\\d+', 'a\\.b|c']) {
        const { shownMode, shownValue, sent } = await editAndSave(rule(value, true));
        assert.equal(shownMode, 'regex', value);
        assert.equal(shownValue, value);
        assert.equal(sent.match_value, value);
        assert.equal(sent.is_regex, true);
    }
});

test('a regex with a leading ^ and an Exact Match rule save unchanged', async () => {
    let result = await editAndSave(rule('^noreply@example\\.com$', true));
    assert.equal(result.shownMode, 'regex');
    assert.equal(result.sent.match_value, '^noreply@example\\.com$');
    result = await editAndSave(rule('NoReply@Example.com', false));
    assert.equal(result.shownMode, 'exact');
    assert.equal(result.sent.match_value, 'NoReply@Example.com');
    assert.equal(result.sent.is_regex, false);
});

// Save the rule dialog with these field values, and return what it sent
async function saveFields(fields, ruleId) {
    const app = loadApp();
    app.context.closeQuarantineRuleModal = () => {};
    app.context.loadQuarantineRules = async () => {};
    for (const [id, value] of Object.entries(fields)) app.elements[id] = { value };
    let sent = null;
    app.context.authenticatedFetch = async (url, options) => { sent = JSON.parse(options.body); return { ok: true, json: async () => ({}) }; };
    await app.context.saveQuarantineRule(ruleId);
    return sent;
}

// The pattern a Contains rule for example.com got when an earlier version
// opened it with its stored pattern and saved it again. The upgrade repairs
// it (backend/alembic/versions/0018_*, tested in test_quarantine_spam_upgrade.py).
const TWICE_SAVED = 'example\\\\\\.com';
const REPAIRED = 'example\\.com';

test('a Contains rule saved twice by an earlier version opens as Contains with its text once repaired', async () => {
    const fields = { 'qrule-name': 'Rule', 'qrule-match-type': 'sender_domain', 'qrule-match-value': 'example.com',
                     'qrule-match-mode': 'contains', 'qrule-action': 'release', 'qrule-notes': '' };
    const created = await saveFields(fields, null);
    assert.equal(created.match_value, REPAIRED);
    // The earlier edit dialog showed the stored pattern in the Contains field
    const edited = await saveFields({ ...fields, 'qrule-match-value': created.match_value }, 3);
    assert.equal(edited.match_value, TWICE_SAVED);
    const { shownMode, shownValue, sent } = await editAndSave({ ...rule(REPAIRED, true), match_type: 'sender_domain' });
    assert.equal(shownMode, 'contains');
    assert.equal(shownValue, 'example.com');
    assert.equal(sent.match_value, REPAIRED);
    assert.equal(sent.is_regex, true);
});

// Other rules an earlier edit escaped twice are not changed by the upgrade: the
// Auto-Rules list flags them, and Repair removes one level of escaping. The
// subject values are also in test_quarantine_spam_upgrade.py.
const SUBJECT_TWICE = 'Invoice\\\\\\.pdf';
const SUBJECT_REPAIRED = 'Invoice\\.pdf';
const listed = (id, match_type, match_value, is_regex) => ({
    id, name: `Rule ${id}`, match_type, match_value, is_regex, action: 'release', enabled: true,
    hit_count: 0, last_hit_at: null, notes: 'Kept as it is',
});

// Draw the Auto-Rules list for these rules; returns the app and each rule's row
async function drawRules(rules) {
    const app = loadApp();
    app.context.authenticatedFetch = async () => ({ ok: true, json: async () => ({ total: rules.length, data: rules }) });
    await app.context.loadQuarantineRules();
    const rows = app.elements['quarantine-rules-list'].innerHTML.split('<div class="ui-tr').slice(1);
    return { app, rows: Object.fromEntries(rules.map((r, i) => [r.id, rows[i]])) };
}

const BACKSLASH_NOTE = 'Looks for a backslash. An earlier version may have changed this rule when it was edited.';

test('a Contains rule that looks for a backslash is flagged in the list with a Repair button', async () => {
    const { rows } = await drawRules([
        listed(1, 'subject', SUBJECT_TWICE, true),
        listed(2, 'sender', 'a\\\\\\.b', true),            // Contains a\.b: flagged, left to the owner
        listed(3, 'sender', REPAIRED, true),                // Contains example.com
        listed(4, 'sender', 'a\\\\\\.b|c', true),           // Regex
        listed(5, 'subject', 'a\\\\\\.b\\*', true),         // Contains a\.b*: no Contains text escaped twice
        listed(6, 'sender', SUBJECT_TWICE, false),          // Exact Match
    ]);
    for (const id of [1, 2]) {
        assert.match(rows[id], /ui-tag ui-tag-warn">Check</, `rule ${id}`);
        assert.ok(rows[id].includes(BACKSLASH_NOTE), `rule ${id}`);
        assert.ok(rows[id].includes(`onclick="repairQuarantineRule(${id})"`), `rule ${id}`);
    }
    for (const id of [3, 4, 5, 6]) {
        assert.ok(!rows[id].includes('ui-tag-warn') && !rows[id].includes(BACKSLASH_NOTE) && !rows[id].includes('repairQuarantineRule'),
            `rule ${id}`);
    }
});

test('Repair saves the rule with one level of escaping removed, and it is no longer flagged', async () => {
    const damaged = listed(1, 'subject', SUBJECT_TWICE, true);
    const { app } = await drawRules([damaged]);
    let request = null;
    app.context.authenticatedFetch = async (url, options) => {
        if (options && options.method) {
            request = { url, method: options.method, body: JSON.parse(options.body) };
            return { ok: true, json: async () => ({}) };
        }
        return { ok: true, json: async () => ({ total: 1, data: [{ ...damaged, match_value: request.body.match_value }] }) };
    };
    await app.context.repairQuarantineRule(1);
    assert.equal(request.url, '/api/quarantine/rules/1');
    assert.equal(request.method, 'PUT');
    assert.deepEqual(request.body, { name: 'Rule 1', match_type: 'subject', match_value: SUBJECT_REPAIRED,
                                     is_regex: true, action: 'release', notes: 'Kept as it is' });
    const row = app.elements['quarantine-rules-list'].innerHTML;
    assert.ok(row.includes('Invoice\\.pdf') && !row.includes('repairQuarantineRule') && !row.includes(BACKSLASH_NOTE));
    // The edit dialog now opens it as Contains Invoice.pdf
    const { shownMode, shownValue } = await editAndSave({ ...damaged, match_value: SUBJECT_REPAIRED });
    assert.equal(shownMode, 'contains');
    assert.equal(shownValue, 'Invoice.pdf');
});

// Auto refresh while the Read-Write status is still loading: the rows wait for
// it, as on the first load, instead of showing the lock for a moment
async function refreshWhileRwLoads(page, data, refresh) {
    const app = loadApp();
    let answerRw;
    const rw = new Promise(resolve => { answerRw = resolve; });
    app.context.authenticatedFetch = async url => url === '/api/rw-status'
        ? rw.then(() => ({ ok: true, json: async () => ({ rw_configured: true }) }))
        : { ok: true, json: async () => data };
    vm.runInContext(`currentTab = '${page}'; rwStatusReady = fetchRwStatus();`, app.context);
    const refreshing = app.context[refresh]();
    await new Promise(resolve => setImmediate(resolve));
    assert.doesNotMatch(app.elements[`${page}-logs`]?.innerHTML || '', /actions are locked/);
    answerRw();
    await refreshing;
    const html = app.elements[`${page}-logs`].innerHTML;
    assert.doesNotMatch(html, /actions are locked/);
    return html;
}

test('auto refresh of the Queue waits for the Read-Write status', async () => {
    const html = await refreshWhileRwLoads('queue', { data: QUEUE }, 'smartRefreshQueue');
    assert.match(html, /queueRetry\(/);
});

test('auto refresh of the Quarantine waits for the Read-Write status', async () => {
    const data = { total: 1, data: [{ id: 7, sender: 'sender@example.com', rcpt: 'user@example.org', subject: 'Hello', score: 9, action: 'reject', created: 1760000000 }] };
    const html = await refreshWhileRwLoads('quarantine', data, 'smartRefreshQuarantine');
    assert.match(html, /Hello/);
});
