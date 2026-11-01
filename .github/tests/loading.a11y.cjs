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
    // The Users panel is drawn by Settings: here it is put in place first
    const users = w.document.createElement('div');
    users.id = 'users-panel';
    w.document.body.appendChild(users);
    for (const [loader, id, again] of [['loadQueue()', 'queue-logs', 'loadQueue()'], ['loadStatusContainers()', 'status-containers', 'loadStatusContainers()'],
        ['loadUsersPanel()', 'users-panel', 'loadUsersPanel()'], ['loadNetfilterLogs(3)', 'netfilter-logs', 'loadNetfilterLogs(3)'],
        ['loadStatusExtended()', 'status-jobs', 'loadStatusExtended()'], ['loadStatusExtended()', 'status-correlation', 'loadStatusExtended()']]) {
        const box = w.document.getElementById(id);
        assert.ok(box, `${id} is on the page`);
        w.reply = () => FAIL;
        await w.eval(loader);
        await settle(w);
        const button = box.querySelector(`button[onclick="uiRetrying(this); ${again}"]`);
        assert.ok(button, `${loader}: Try again calls ${again}`);
        // Pressed, with the answer still on its way: the spinner, not the error
        w.reply = () => new Promise(() => {});
        button.click();
        await settle(w);
        assert.ok(box.querySelector('.loading'), `${loader}: Try again shows the spinner`);
        assert.doesNotMatch(box.textContent, /did not answer/, `${loader}: the error is gone`);
    }
});

test('the spinner waits before it shows, and says so when a load takes long', () => {
    assert.match(css, /\.ui-loading > p \{ animation: ui-appear [^;]* \.3s both; \}/);
    // The spinner fades in and keeps turning: its own spin is not replaced
    assert.match(css, /\.ui-loading > \.loading \{ animation: ui-appear [^;,]* \.3s both, spin 1s linear infinite; \}/);
    assert.match(css, /\.ui-loading:has\(> \.loading\)::after \{ content: "This is taking longer than usual\."; animation: ui-appear [^;]* 8s both; \}/);
});

test('Try again that fails again shows the failure again, also in a quiet Status refresh', async () => {
    const w = page();
    const users = w.document.createElement('div');
    users.id = 'users-panel';
    w.document.body.appendChild(users);
    w.reply = () => FAIL;
    for (const [loader, id] of [['loadUsersPanel()', 'users-panel'], ['loadQuarantineRules()', 'quarantine-rules-list'], ['loadStatusSystem()', 'status-system']]) {
        const box = w.document.getElementById(id);
        if (!box) { assert.equal(id, 'quarantine-rules-list', `${id} is on the page`); continue; }
        await w.eval(loader);
        await settle(w);
        // A refresh of Status is on (statusQuiet) while Try again is pressed
        if (id === 'status-system') w.eval('statusQuiet = true');
        box.querySelector('button[onclick^="uiRetrying"]').click();
        await settle(w);
        assert.ok(box.querySelector('button[onclick^="uiRetrying"]'), `${loader}: the second failure offers Try again`);
        assert.equal(box.querySelector('.loading'), null, `${loader}: no spinner left`);
        w.eval('statusQuiet = false');
    }
});

test('a Fail2ban read that fails after another succeeded can be tried again', async () => {
    const w = page();
    let calls = 0;
    // The first read answers late with a failure, the second at once with the lists
    w.reply = url => url === '/api/fail2ban'
        ? (++calls === 1 ? new Promise(resolve => w.setTimeout(() => resolve(FAIL), 30)) : { active_bans: [], blacklist: '', whitelist: '' }) : {};
    const first = w.eval('loadFail2BanSettings()');
    await w.eval('loadFail2BanSettings()');
    await first;
    assert.equal(w.eval('fail2banLoadError'), true);
    assert.equal(w.eval('fail2banSettingsLoaded'), false, 'Try again reads it again');
});
