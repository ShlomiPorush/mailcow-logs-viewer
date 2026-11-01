// The Dashboard when a read fails (app.js), in a real DOM (jsdom): a figure that
// could not be read is never shown as 0 or as the last period's, a card says it
// could not load or update, Hosted says why instead of loading forever, and a
// sidebar counter that could not be read keeps what it showed.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || path.join(__dirname, 'node_modules');
const { JSDOM } = require(path.join(modules, 'jsdom'));

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');
// The page as index.html has it, without its scripts; parsed, not cut with a regex
const PAGE = new JSDOM(read('index.html')).window.document;
PAGE.querySelectorAll('script').forEach(el => el.remove());
const BODY = PAGE.body.innerHTML;
const SCRIPTS = [...read('index.html').matchAll(/src="\/static\/([a-z_-]+\.js)/g)].map(m => m[1]).filter(name => name !== 'session-guard.js');

// The server: reply(url) answers each request; { __status } makes it fail
const STUBS = `
    window.reply = () => ({});
    authenticatedFetch = (url, options = {}) => Promise.resolve(window.reply(url, (options.method || 'GET').toUpperCase()))
        .then(body => {
            const status = body && body.__status ? body.__status : 200;
            return { ok: status < 400, status, headers: { get: () => 'application/json' }, json: async () => body, clone() { return this; } };
        });
    checkAuthentication = async () => false;`;

function page() {
    const dom = new JSDOM(`<!doctype html><html lang="en"><head><title>t</title></head><body>${BODY}</body></html>`,
        { runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/dashboard' });
    const w = dom.window;
    w.Element.prototype.scrollIntoView = function () {};
    w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    w.HTMLElement.prototype.hidePopover = function () {};
    w.HTMLElement.prototype.showPopover = function () {};
    const run = source => { const s = w.document.createElement('script'); s.textContent = source; w.document.head.appendChild(s); };
    SCRIPTS.forEach(name => run(read(name)));
    run(STUBS);
    return w;
}
const settle = async w => { for (let i = 0; i < 10; i++) await new Promise(resolve => w.setTimeout(resolve, 0)); };
const text = (w, id) => w.document.getElementById(id).textContent.trim();
const FAIL = { __status: 502 };
const STATS = ['stat-messages-24h', 'stat-blocked-24h', 'stat-deferred-24h', 'stat-auth-failures-24h'];

const flow = (messages) => ({ from: '2026-10-31T12:00:00Z', to: '2026-11-01T12:00:00Z', bucket: 'hour', buckets: [],
    totals: { messages, deliveries: messages, blocked: 1, deferred: 0, auth_failures: 2 } });

test('before any answer the mail flow figures show no number, and a failed read never shows 0', async () => {
    const w = page();
    for (const id of STATS) assert.equal(text(w, id), '-', `${id} before an answer`);
    w.reply = url => url.startsWith('/api/stats/flow') ? FAIL : {};
    w.eval('loadMailFlowChart()');
    await settle(w);
    for (const id of STATS) assert.equal(text(w, id), '-', `${id} after a failed read`);
    assert.match(w.document.getElementById('dashboard-flow-chart').textContent, /Could not load the mail flow/);
});

test('a period whose read fails does not keep the last period\'s figures', async () => {
    const w = page();
    w.reply = url => url.startsWith('/api/stats/flow') ? flow(66) : {};
    w.eval('loadMailFlowChart()');
    await settle(w);
    assert.equal(text(w, 'stat-messages-24h'), '66');
    w.reply = url => url.startsWith('/api/stats/flow') ? FAIL : {};
    w.eval("setDashFlowPeriod('7d')");
    await settle(w);
    assert.equal(text(w, 'stat-messages-24h'), '-');
    assert.equal(w.document.getElementById('dashboard-flow-messages').disabled, true);
});

test('Hosted says why it is empty instead of loading forever; the health cards say they could not load', async () => {
    const w = page();
    w.reply = url => url.startsWith('/api/status/summary') ? FAIL : {};
    await w.eval('loadDashboardStatusSummary()');
    assert.equal(w.document.querySelector('#dashboard-system-summary .ui-loading'), null);
    assert.match(text(w, 'dashboard-system-summary'), /Could not load: The server did not answer/);
    assert.equal(text(w, 'dash-kpi-containers-note'), 'Could not load');
    assert.equal(text(w, 'dash-kpi-storage-note'), 'Could not load');
});

test('a health card that loaded once keeps its value and says it could not update', async () => {
    const w = page();
    w.reply = url => url.startsWith('/api/status/summary')
        ? { containers: { running: 18, total: 18, stopped: 0 }, storage: { used_percent: '11%', used: '21G', total: '200G' }, system: { domains: 4 } } : {};
    await w.eval('loadDashboardStatusSummary()');
    assert.equal(text(w, 'dash-kpi-containers'), '18 of 18 running');
    w.reply = url => url.startsWith('/api/status/summary') ? FAIL : {};
    await w.eval('loadDashboardStatusSummary()');
    assert.equal(text(w, 'dash-kpi-containers'), '18 of 18 running');
    assert.equal(text(w, 'dash-kpi-containers-note'), 'Could not update');
    assert.match(text(w, 'dashboard-system-summary'), /Domains\s*4/);
});

test('a sidebar counter that could not be read keeps what it showed, and the server card does not say "No problems"', async () => {
    const w = page();
    w.reply = url => url.startsWith('/api/queue') ? { data: [{}, {}, {}] } : {};
    await w.eval('loadNavCounters()');
    const badge = w.document.getElementById('nav-count-outbound');
    assert.equal(badge.textContent, '3');
    assert.equal(badge.classList.contains('hidden'), false);
    w.reply = () => FAIL;
    await w.eval('loadNavCounters()');
    assert.equal(badge.textContent, '3');
    assert.equal(badge.classList.contains('hidden'), false);
    assert.equal(text(w, 'ui-server-problems'), 'Could not check');
});
