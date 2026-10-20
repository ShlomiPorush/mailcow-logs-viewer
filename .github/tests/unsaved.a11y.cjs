// Unsaved changes (utils.js, router.js): a move that would drop them asks first,
// Stay keeps the page and the address, Leave goes on; Back and Forward are undone
// while the question is open, so the history stays as it was. Runs in a real DOM
// (jsdom), installed by CI outside the repository; set A11Y_MODULES to run it locally:
//   npm install --no-save --prefix /tmp/a11y jsdom axe-core
//   A11Y_MODULES=/tmp/a11y/node_modules node --test .github/tests/unsaved.a11y.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));
const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');

function app() {
    const dom = new JSDOM(`<!doctype html><html lang="en"><head><title>t</title><style>.hidden{display:none}</style></head>
        <body><main class="ui-shell"><section id="content-dashboard" class="ui-page"><h1>Dashboard</h1></section>
        <section id="content-domains" class="ui-page hidden"><h1>Domains</h1></section></main></body></html>`,
        { runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/dashboard' });
    const w = dom.window;
    w.Element.prototype.getClientRects = function () { return this.isConnected && !this.closest('.hidden') ? [{}] : []; };
    w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    const run = source => {
        const script = w.document.createElement('script');
        script.textContent = source;
        w.document.head.appendChild(script);
    };
    run(read('utils.js'));
    run(read('router.js'));
    // The page switch of app.js, reduced to what these tests watch
    run(`var currentTab = 'dashboard'; var switched = [];
        function switchTab(tab, params) { currentTab = tab; switched.push(tab);
            document.querySelectorAll('.ui-page').forEach(p => p.classList.toggle('hidden', p.id !== 'content-' + tab)); }
        watchOverlays(); initRouter();`);
    w.run = run;
    return w;
}
const frame = w => new Promise(resolve => w.requestAnimationFrame(() => setTimeout(resolve, 0)));
const settle = async w => { await frame(w); await frame(w); };
const popped = w => new Promise(resolve => w.addEventListener('popstate', () => setTimeout(resolve, 0), { once: true }));
const answer = async (w, leave) => {
    await settle(w);
    const modal = w.document.getElementById('app-confirm-modal');
    assert.ok(modal, 'the question is open');
    assert.match(modal.textContent, /unsaved change/);
    w.document.getElementById(leave ? 'app-confirm-ok' : 'app-confirm-cancel').click();
};

test('a move that would drop changes asks: Stay keeps the page, Leave goes and drops them', async () => {
    const w = app();
    let dropped = 0;
    w.uiUnsavedRegister('form', { count: () => 2, keeps: t => t.route === 'dashboard', drop: () => { dropped++; } });
    const stay = w.navigateTo('domains');
    await answer(w, false);
    assert.equal(await stay, false);
    assert.equal(w.location.pathname, '/dashboard');
    assert.equal(w.eval('currentTab'), 'dashboard');
    const leave = w.navigateTo('domains');
    await answer(w, true);
    assert.equal(await leave, true);
    assert.equal(w.location.pathname, '/domains');
    assert.equal(dropped, 1);
});

test('a move that keeps the changes asks nothing', async () => {
    const w = app();
    w.uiUnsavedRegister('form', { count: () => 1, keeps: t => t.route === 'dashboard' && !t.reload });
    assert.equal(await w.navigateTo('dashboard'), true);
    assert.equal(w.document.getElementById('app-confirm-modal'), null);
    assert.equal(w.uiUnsavedCount({ route: 'dashboard', reload: true }), 1, 'a reload of the page would drop them');
});

test('Back that would drop changes is undone while asking; Stay leaves the history as it was', async () => {
    const w = app();
    await w.navigateTo('domains');
    const length = w.history.length;
    w.uiUnsavedRegister('form', { count: () => 1, keeps: t => t.route === 'domains' });
    w.history.back();
    await popped(w);          // the Back
    await popped(w);          // undone
    assert.equal(w.location.pathname, '/domains', 'the address is the page the user is on');
    await answer(w, false);
    await settle(w);
    assert.equal(w.location.pathname, '/domains');
    assert.equal(w.eval('currentTab'), 'domains');
    assert.equal(w.history.length, length, 'no entry was added or cut');
    assert.equal(w.document.querySelectorAll('[data-no-history]').length, 0);
});

test('Back with Leave takes the same step again and opens the page', async () => {
    const w = app();
    await w.navigateTo('domains');
    w.uiUnsavedRegister('form', { count: () => 1, keeps: t => t.route === 'domains' });
    w.history.back();
    await popped(w);
    await popped(w);
    const going = popped(w);
    await answer(w, true);
    await going;
    await settle(w);
    assert.equal(w.location.pathname, '/dashboard');
    assert.equal(w.eval('currentTab'), 'dashboard');
});

test('Back to an entry an older version wrote (no place in the history) asks too', async () => {
    const w = app();
    w.history.replaceState({ route: 'dashboard', params: {} }, '', '/dashboard');   // as the old version wrote it
    await w.navigateTo('domains');
    w.uiUnsavedRegister('form', { count: () => 1, keeps: t => t.route === 'domains' });
    w.history.back();
    await popped(w);
    await answer(w, false);
    await settle(w);
    assert.equal(w.location.pathname, '/domains', 'Stay: the page is written back');
    assert.equal(w.eval('currentTab'), 'domains');
    w.history.back();
    await popped(w);   // asked again: the page was written back over the entry
    await answer(w, true);
    await settle(w);
    assert.equal(w.eval('currentTab'), 'dashboard', 'Leave goes where Back pointed');
});

test('the question asked during Back writes no history entry of its own', async () => {
    const w = app();
    w.showConfirmModal({ title: 'Leave without saving?', message: 'x', noHistory: true });
    await settle(w);
    assert.equal(w.history.state.overlay, undefined, 'no overlay entry for it');
    w.document.getElementById('app-confirm-cancel').click();
});

test('closing the browser tab with unsaved changes asks through the browser', () => {
    const w = app();
    const quiet = new w.Event('beforeunload', { cancelable: true });
    w.dispatchEvent(quiet);
    assert.equal(quiet.defaultPrevented, false);
    w.uiUnsavedRegister('security', { count: () => 1, keeps: () => true });
    const asks = new w.Event('beforeunload', { cancelable: true });
    w.dispatchEvent(asks);
    assert.equal(asks.defaultPrevented, true);
    w.uiUnsavedClear();
    const planned = new w.Event('beforeunload', { cancelable: true });
    w.dispatchEvent(planned);
    assert.equal(planned.defaultPrevented, false, 'a planned reload clears the list first');
});

test('server errors name the field', () => {
    const w = app();
    assert.equal(w.uiApiErrorText({ detail: 'Bad token' }, 'x'), 'Bad token');
    assert.equal(w.uiApiErrorText({ detail: { message: 'Locked' } }, 'x'), 'Locked');
    assert.equal(w.uiApiErrorText({ detail: [{ loc: ['body', 'retention_days'], msg: 'must be at least 1' }] }, 'x'), 'retention days: must be at least 1');
    assert.equal(w.uiApiErrorText({}, 'Not Found'), 'Not Found');
});
