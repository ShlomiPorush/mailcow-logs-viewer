// Loading (utils.js, ui.css): a load that failed offers Try again where it failed,
// and trying again shows the spinner, not the last error; the spinner waits a moment
// before it shows (a quick load does not flash it) and says so when a load takes long.
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
const css = fs.readFileSync(path.join(frontend, 'assets/css/ui.css'), 'utf8');

test('Try again after a failed load shows the spinner, not the last error', async () => {
    const w = page();
    for (const [loader, id] of [['loadDomains', 'domains-loading'], ['loadRateLimits', 'rate-limits-loading'], ['loadMailboxStats', 'mailbox-stats-loading'], ['loadSettings', 'settings-loading']]) {
        w.reply = () => FAIL;
        await w.eval(`${loader}()`);
        await settle(w);
        const box = w.document.getElementById(id);
        assert.match(box.textContent, /The server did not answer/, `${loader}: the error is shown`);
        assert.ok([...box.querySelectorAll('button')].some(b => /Try again/.test(b.textContent)), `${loader}: it offers Try again`);
        // Trying again: while the answer is on its way, the spinner is back
        w.reply = () => new Promise(() => {});
        w.eval(`${loader}()`);
        await settle(w);
        assert.ok(box.querySelector('.loading'), `${loader}: the spinner is back`);
        assert.doesNotMatch(box.textContent, /did not answer/, `${loader}: the old error is gone`);
    }
});

test('a failed load offers Try again where it failed', async () => {
    const w = page();
    w.reply = () => FAIL;
    for (const [loader, id, again] of [['loadQueue', 'queue-logs', 'loadQueue()'], ['loadStatusContainers', 'status-containers', 'loadStatusContainers()'],
        ['loadUsersPanel', 'users-panel', 'loadUsersPanel()']]) {
        const box = w.document.getElementById(id);
        if (!box) continue;
        await w.eval(`${loader}()`);
        await settle(w);
        assert.ok(box.querySelector(`button[onclick="${again}"]`), `${loader}: Try again calls ${again}`);
    }
});

test('the spinner waits before it shows, and says so when a load takes long', () => {
    assert.match(css, /\.ui-loading > \.loading, \.ui-loading > p \{ animation: ui-appear [^;]* \.3s both; \}/);
    assert.match(css, /\.ui-loading:has\(> \.loading\)::after \{ content: "This is taking longer than usual\."; animation: ui-appear [^;]* 8s both; \}/);
});
