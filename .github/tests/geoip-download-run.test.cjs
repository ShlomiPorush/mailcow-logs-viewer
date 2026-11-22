// GeoIP Setup and Repair wait for the download run they started: a result left
// from an earlier run is not theirs, a failed run is shown as failed, and Repair
// no longer waits for a state the job never reaches.
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

// The app with GET status answering the given states in turn (the last one repeats)
function load(states, { start = { ok: true, body: { status: 'started' } }, validate = { valid: true } } = {}) {
    const context = vm.createContext({
        document: stub(), window: { matchMedia: () => ({ matches: false }), addEventListener() {} }, localStorage: stub(),
        sessionStorage: stub(), navigator: stub(), location: stub(), console: { log() {}, error() {}, warn() {} },
        setTimeout: (fn) => setImmediate(fn), setInterval() {}, clearTimeout() {}, URLSearchParams, Intl,
    });
    for (const file of ['utils.js', 'app.js', 'settings.js']) {
        vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    }
    const calls = [];
    const toasts = [];
    let i = 0;
    context.authenticatedFetch = async (url, opts = {}) => {
        calls.push(`${opts.method || 'GET'} ${url}`);
        if (url === '/api/settings/geoip/download') return { ok: start.ok, json: async () => start.body };
        if (url === '/api/settings/geoip/validate') return { ok: true, json: async () => validate };
        const state = states[Math.min(i++, states.length - 1)];
        return { ok: true, json: async () => state };
    };
    context.showToast = (message, type) => toasts.push([type, message]);
    return { context, calls, toasts };
}

const earlier = { job_status: 'success', job_last_run: '2026-11-20T10:00:00Z', databases: {} };

test('a success left from an earlier run is not the new run\'s result', async () => {
    const { context } = load([earlier, earlier, earlier,
        { job_status: 'running', job_last_run: '2026-11-22T08:00:00Z' },
        { job_status: 'failed', job_last_run: '2026-11-22T08:00:05Z', job_error: 'Could not download the GeoIP City database from MaxMind.' }]);
    const run = await context.geoipDownloadRun({ every: 0 });
    assert.equal(run.ok, false);
    assert.match(run.error, /Could not download the GeoIP City database/);
});

test('the new run\'s success is reported, also when the run was too fast to be seen running', async () => {
    const { context } = load([earlier, { job_status: 'success', job_last_run: '2026-11-22T08:00:05Z' }]);
    const run = await context.geoipDownloadRun({ every: 0 });
    assert.equal(run.ok, true);
});

test('a refused start says why and polls nothing', async () => {
    const { context, calls } = load([earlier], { start: { ok: false, body: { detail: 'Add a MaxMind account ID and license key in Settings > MaxMind before downloading.' } } });
    const run = await context.geoipDownloadRun({ every: 0 });
    assert.equal(run.started, false);
    assert.match(run.error, /Settings > MaxMind/);
    assert.equal(calls.filter(c => c === 'GET /api/settings/geoip/status').length, 1);
});

test('a run that never ends is reported as not finished', async () => {
    const { context } = load([earlier, { job_status: 'running', job_last_run: '2026-11-22T08:00:00Z' }]);
    const run = await context.geoipDownloadRun({ every: 0, polls: 5 });
    assert.equal(run.ok, null);
});

test('Repair shows a failed download as failed, and a successful one as passed', async () => {
    const failed = load([earlier, { job_status: 'failed', job_last_run: '2026-11-22T08:00:05Z', job_error: 'Could not download the GeoIP City database from MaxMind.' }]);
    await failed.context.repairGeoIPDatabase();
    assert.ok(failed.toasts.some(([type, message]) => type === 'error' && /Could not download the GeoIP City database/.test(message)), JSON.stringify(failed.toasts));
    assert.ok(!failed.toasts.some(([type]) => type === 'success'));

    const passed = load([earlier, { job_status: 'success', job_last_run: '2026-11-22T08:00:05Z' }]);
    await passed.context.repairGeoIPDatabase();
    assert.ok(passed.toasts.some(([type, message]) => type === 'success' && /check passed/.test(message)), JSON.stringify(passed.toasts));
});
