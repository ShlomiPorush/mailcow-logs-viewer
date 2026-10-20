const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const root = path.join(__dirname, '../..');
const app = fs.readFileSync(path.join(root, 'frontend/app.js'), 'utf8');
const settingsJs = fs.readFileSync(path.join(root, 'frontend/settings.js'), 'utf8');
const utils = fs.readFileSync(path.join(root, 'frontend/utils.js'), 'utf8');

function slice(source, from, to) {
    const start = source.indexOf(from);
    const end = source.indexOf(to, start);
    assert.ok(start >= 0 && end > start, `${from} ... ${to}`);
    return source.slice(start, end);
}

test('Status, Jobs lists every job the server reports', () => {
    // The job keys of background_jobs in GET /api/settings/info
    const routers = fs.readFileSync(path.join(root, 'backend/app/routers/settings.py'), 'utf8');
    const block = slice(routers, '"background_jobs": {', '"smtp_configuration": {');
    const serverJobs = [...block.matchAll(/^ {16}"(\w+)": \{$/gm)].map(m => m[1]);
    assert.ok(serverJobs.length > 20, serverJobs.join());

    const context = vm.createContext({});
    vm.runInContext(slice(app, 'function statusJobCategories(jobs)', 'function renderStatusJobsTable'), context);
    const jobs = Object.fromEntries(serverJobs.map(key => [key, {}]));
    const shown = context.statusJobCategories(jobs).flatMap(cat => cat.jobs.map(([, key]) => key));

    assert.deepEqual(serverJobs.filter(key => !shown.includes(key)), []);
});

test('the blocklist button reads Check all now again after a check', async () => {
    const original = '<svg aria-hidden="true"></svg>Check all now';
    const btn = { disabled: false, innerHTML: original };
    const context = vm.createContext({
        document: { getElementById: id => (id === 'blacklist-check-btn' ? btn : null) },
        showToast() {},
        setInterval: () => 1,
        clearInterval() {},
        URLSearchParams,
        authenticatedFetch: async () => ({ ok: true, json: async () => ({}) }),
        loadBlacklistStatus: async () => {},
        console: { error() {} },
    });
    vm.runInContext(slice(app, 'function checkHost(hostname)', 'async function loadBlacklistStatus'), context);

    const running = vm.runInContext('checkBlacklists(true)', context);
    assert.equal(btn.disabled, true);
    await running;

    assert.equal(btn.disabled, false);
    assert.equal(btn.innerHTML, original);
});

test('About does not call a failed version check Up to Date', () => {
    const context = vm.createContext({});
    vm.runInContext(slice(utils, 'function uiTag(', 'function uiDirectionTag'), context);
    vm.runInContext(slice(utils, 'function escapeHtml(', '\n}\n') + '\n}', context);
    vm.runInContext(slice(settingsJs, 'function renderLatestVersionState', 'function renderUpdateNote'), context);
    // The text between the tags
    const render = info => context.renderLatestVersionState(info).split(/<[^>]*>/).join('').trim();

    // GitHub could not be reached: the server answers "unknown"
    const failed = render({ latest_version: 'unknown', update_available: false });
    assert.doesNotMatch(failed, /Up to Date|vunknown/);
    assert.match(failed, /Check failed/);

    assert.equal(render({ latest_version: '3.0.0', update_available: false }), 'v3.0.0 Up to Date');
    assert.equal(render({ latest_version: '3.1.0', update_available: true }), 'v3.1.0 Update Available');
});
