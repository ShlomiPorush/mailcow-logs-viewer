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
function load(states, { start = { ok: true, body: { status: 'started' } }, validate = { valid: true }, hang = false } = {}) {
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
        calls.push(`${opts.method || 'GET'} ${url}${opts.timeout ? ' timeout' : ''}`);
        if (url === '/api/settings/geoip/download') {
            if (start.hang) throw new Error('The request timed out.');
            // start.html: a proxy's error page, which is not JSON
            return { ok: start.ok, status: start.status || (start.ok ? 200 : 400), json: async () => { if (start.html) throw new SyntaxError('Unexpected token <'); return start.body; } };
        }
        if (url === '/api/settings/geoip/validate') return { ok: true, json: async () => validate };
        // A status request that never answers ends at its timeout, as authenticatedFetch aborts it
        if (hang && i++ > 0) throw new Error('The request timed out.');
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
    assert.equal(calls.filter(c => c.startsWith('GET /api/settings/geoip/status')).length, 1);
});

test('a refused start without a reason says what the status means, not "check your credentials"', async () => {
    // The server's catch-all for an unexpected error, and a proxy's HTML page in front of the app
    for (const [start, words] of [[{ ok: false, status: 500, body: { detail: 'An error occurred' } }, /The server hit an error/],
        [{ ok: false, status: 502, html: true }, /The server did not answer/]]) {
        const { context } = load([earlier], { start });
        const run = await context.geoipDownloadRun({ every: 0 });
        assert.equal(run.started, false);
        assert.match(run.error, words);
        assert.doesNotMatch(run.error, /MaxMind credentials/);
    }
});

// A clock that moves ten seconds on every look
const minutes = () => { let t = 0; return () => (t += 10 * 1000); };

test('a run that never ends is reported as not finished at the time limit', async () => {
    const { context } = load([earlier, { job_status: 'running', job_last_run: '2026-11-22T08:00:00Z' }]);
    const run = await context.geoipDownloadRun({ every: 0, now: minutes() });
    assert.equal(run.ok, null);
});

test('a status request that does not answer still ends at the time limit, and every request is bounded', async () => {
    const { context, calls } = load([earlier], { hang: true });
    const run = await context.geoipDownloadRun({ every: 0, now: minutes() });
    assert.equal(run.ok, null);
    assert.ok(calls.length > 2 && calls.every(c => c.endsWith(' timeout')), calls.join(', '));
});

test('a new run in the same second as the one before is still told apart', async () => {
    const { context } = load([{ job_status: 'success', job_last_run: '2026-11-22T08:00:00.100000Z' },
        { job_status: 'failed', job_last_run: '2026-11-22T08:00:00.900000Z', job_error: 'Could not download the location database from MaxMind.' }]);
    const run = await context.geoipDownloadRun({ every: 0 });
    assert.equal(run.ok, false);
    assert.match(run.error, /location database/);
});

test('Repair shows a failed download as failed, and a successful one as passed', async () => {
    const failed = load([earlier, { job_status: 'failed', job_last_run: '2026-11-22T08:00:05Z', job_error: 'Could not download the GeoIP City database from MaxMind.' }]);
    await failed.context.repairGeoIPDatabase();
    // The run's own error, and that the older data still works
    assert.ok(failed.toasts.some(([type, message]) => type === 'error' && /^Could not download the GeoIP City database.* Previously installed data is still in use.$/.test(message)), JSON.stringify(failed.toasts));
    assert.ok(!failed.toasts.some(([type]) => type === 'success'));

    const passed = load([earlier, { job_status: 'success', job_last_run: '2026-11-22T08:00:05Z' }]);
    await passed.context.repairGeoIPDatabase();
    assert.ok(passed.toasts.some(([type, message]) => type === 'success' && /check passed/.test(message)), JSON.stringify(passed.toasts));
});

test('a start that does not answer in time still reports the run the server began', async () => {
    const { context } = load([earlier, { job_status: 'failed', job_last_run: '2026-11-22T08:00:05Z', job_error: 'Could not download the location database from MaxMind.' }], { start: { hang: true } });
    const run = await context.geoipDownloadRun({ every: 0 });
    assert.equal(run.started, true);
    assert.equal(run.ok, false);
    assert.match(run.error, /location database/);
});
