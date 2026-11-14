// Needs attention in the header bell (app.js): one state for the Dashboard panel
// and the bell, an answer a newer load replaced is dropped, a check that cannot
// run is said and keeps what it showed, and the bell's window is a layer
// (router.js): focus in and back, Escape, inert behind it, a move to another
// page. Runs in a real DOM (jsdom), installed by CI outside the repository; set
// A11Y_MODULES to its node_modules to run it locally:
//   npm install --no-save --prefix /tmp/a11y jsdom axe-core
//   A11Y_MODULES=/tmp/a11y/node_modules node --test .github/tests/attention-bell.a11y.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));
const axeSource = fs.readFileSync(require.resolve(path.join(modules, 'axe-core')), 'utf8');

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');

const BODY = `
    <main class="ui-shell">
        <header id="ui-topbar" class="ui-topbar"><div id="ui-topbar-title"></div>
            <button type="button" id="ui-bell" class="ui-icon-btn ui-bell" aria-haspopup="dialog" aria-expanded="false" aria-label="Needs attention" title="Needs attention" onclick="attnWindowOpen(this)"><span class="ui-bell-n is-none" aria-hidden="true"></span></button>
        </header>
        <span id="theme-toggle-light-icon" class="hidden"></span><span id="theme-toggle-dark-icon" class="hidden"></span>
        <section class="ui-page" id="content-security"><h1>Security</h1><button type="button" id="other">Other</button></section>
        <section class="ui-page hidden" id="content-dashboard"><h1>Dashboard</h1>
            <section id="dashboard-attention-panel"><div>Needs attention <span id="dashboard-attention-count"></span>
                <button type="button" id="dashboard-dismiss-all" class="is-off">Dismiss all</button></div>
                <div id="dashboard-attention-scroll" class="ui-attn-scroll" role="region" aria-label="Needs attention" tabindex="0">
                    <div id="dashboard-attention"></div>
                    <div id="dashboard-security-alerts" class="hidden"></div>
                    <p id="dashboard-attention-clear" class="hidden"></p>
                </div>
                <p id="dashboard-attention-more" class="is-off"></p>
            </section>
        </section>
    </main>`;

const alert = (id, severity = 'warning', alert_type = 'volume_spike') => ({ id, alert_type, severity, title: `Alert ${id}`, detail: 'detail', created_at: '2026-10-22T10:00:00Z' });

// Answers by path; a function answers late or fails on purpose
function answers(over = {}) {
    return {
        '/api/security-alerts': { alerts: [alert(1, 'critical'), alert(2)], unacknowledged_count: 2, unacknowledged_critical: 1, unacknowledged_ids: [1, 2], writable_ids: [1, 2] },
        '/api/blacklist/summary': { status: 'clean' },
        '/api/status/summary': { containers: { running: 18, stopped: 0, total: 18 }, containers_known: true },
        '/api/dmarc/insights': { insights: [] },
        '/api/status/app-version': { update_available: false },
        '/api/status/version': { update_available: false },
        '/api/status/mailcow-connection': { connected: true },
        '/api/fail2ban': { legacy_entries: [] },
        ...over,
    };
}

// scripts: more page scripts to load; realSwitch keeps app.js's own switchTab
function page(over, { scripts = [], realSwitch = false } = {}) {
    const dom = new JSDOM(`<!doctype html><html lang="en"><head><title>t</title><style>.hidden { display: none; }</style></head><body>${BODY}</body></html>`,
        { runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/netfilter' });
    const w = dom.window;
    w.Element.prototype.getClientRects = function () { return this.isConnected && !this.closest('.hidden') ? [{}] : []; };
    w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    // jsdom has no scrolling element; app.js reads it when the focus leaves a field
    Object.defineProperty(w.document, 'scrollingElement', { get: () => w.document.documentElement });
    if (!('inert' in w.HTMLElement.prototype)) {
        Object.defineProperty(w.HTMLElement.prototype, 'inert', { configurable: true,
            get() { return this.hasAttribute('inert'); },
            set(value) { if (value) this.setAttribute('inert', ''); else this.removeAttribute('inert'); } });
    }
    const run = source => {
        const script = w.document.createElement('script');
        script.textContent = source;
        w.document.head.appendChild(script);
    };
    [read('utils.js'), read('router.js'), read('app.js'), ...scripts.map(read), 'watchOverlays();'].forEach(run);
    // The page switch, reduced to what these tests watch: the page's title goes up
    // into the top bar, as placeTopbar does on a wide screen
    if (!realSwitch) run(`var switched = []; function switchTab(tab) { switched.push(tab);
        document.querySelectorAll('.ui-page').forEach(p => p.classList.toggle('hidden', p.id !== 'content-' + tab));
        const bar = document.getElementById('ui-topbar-title');
        const up = bar.firstElementChild;
        if (up) document.getElementById('content-' + up.dataset.page).prepend(up);
        const h1 = document.querySelector('#content-' + tab + ' h1');
        if (h1) { h1.dataset.page = tab; bar.appendChild(h1); } }`);
    w.asked = [];
    w.answers = answers(over);
    w.authenticatedFetch = async url => {
        const key = url.split('?')[0];
        w.asked.push(key);
        let body = w.answers[key];
        if (typeof body === 'function') body = await body();
        if (body === 'fail') return { ok: false, status: 500, json: async () => ({}) };
        return { ok: true, status: 200, json: async () => body };
    };
    w.disabledFeatures = [];
    return w;
}

const state = w => w.eval('attention');
const frame = w => new Promise(resolve => w.requestAnimationFrame(() => setTimeout(resolve, 0)));
const settle = async w => { await frame(w); await frame(w); };
async function loadAll(w) {
    await Promise.all([w.loadDashboardSecurityAlerts(), w.loadDashboardAttention()]);
}

test('the bell counts every open item, also alerts past the rows read, red for a critical one', async () => {
    const w = page({ '/api/security-alerts': { alerts: Array.from({ length: 20 }, (_, i) => alert(i + 1)), unacknowledged_count: 25, unacknowledged_critical: 1, unacknowledged_ids: [] },
        '/api/dmarc/insights': { insights: [{ domain: 'example.com', recommendations: [{ type: 'low_pass_rate', message: 'Low' }] }] } });
    await loadAll(w);
    const bell = w.document.getElementById('ui-bell');
    const badge = bell.querySelector('.ui-bell-n');
    // 25 alerts and the DMARC row; the critical alert is not among the 20 rows, still red
    assert.equal(badge.textContent, '26');
    assert.equal(badge.className, 'ui-bell-n is-fail');
    assert.equal(bell.getAttribute('aria-label'), 'Needs attention, 26 items');
    assert.equal(w.document.getElementById('dashboard-attention-count').textContent, '26');
    // Warnings only: amber; news only: plain; nothing: no badge and all clear
    w.answers['/api/security-alerts'] = { alerts: [alert(3)], unacknowledged_count: 1, unacknowledged_critical: 0, unacknowledged_ids: [3] };
    await w.loadDashboardSecurityAlerts();
    assert.equal(badge.className, 'ui-bell-n is-warn');
    w.answers['/api/security-alerts'] = { alerts: [], unacknowledged_count: 0, unacknowledged_critical: 0, unacknowledged_ids: [] };
    w.answers['/api/dmarc/insights'] = { insights: [] };
    w.answers['/api/status/app-version'] = { update_available: true, latest_version: '3.1.0', current_version: '3.0.0' };
    await loadAll(w);
    assert.equal(badge.className, 'ui-bell-n is-info');
    w.answers['/api/status/app-version'] = { update_available: false };
    await w.loadDashboardAttention();
    assert.equal(badge.className, 'ui-bell-n is-none');
    assert.equal(bell.getAttribute('aria-label'), 'Needs attention');
    assert.equal(w.document.getElementById('dashboard-attention-clear').textContent, 'Nothing needs attention right now.');
});

test('a list read before a Dismiss and answering after it does not bring the alert back', async () => {
    const w = page();
    await loadAll(w);
    // The timer's load starts and is slow: it still has alert 1
    let release;
    const old = { alerts: [alert(1, 'critical'), alert(2)], unacknowledged_count: 2, unacknowledged_critical: 1, unacknowledged_ids: [1, 2] };
    w.answers['/api/security-alerts'] = () => new Promise(resolve => { release = () => resolve(old); });
    const polling = w.loadDashboardSecurityAlerts({ force: false });
    // A Dismiss of alert 1 reads the list again (force) while that load is on its way
    w.answers['/api/security-alerts'] = { alerts: [alert(2)], unacknowledged_count: 1, unacknowledged_critical: 0, unacknowledged_ids: [2] };
    assert.equal(await w.loadDashboardSecurityAlerts(), true);
    release();
    await polling;
    assert.deepEqual(state(w).alerts.list.map(a => a.id), [2]);
    assert.equal(w.document.querySelector('#ui-bell .ui-bell-n').textContent, '1');
    // A load without force joins the one on its way instead of asking twice
    w.asked.length = 0;
    await Promise.all([w.loadDashboardSecurityAlerts({ force: false }), w.loadDashboardSecurityAlerts({ force: false })]);
    assert.equal(w.asked.filter(u => u === '/api/security-alerts').length, 1);
});

test('a check that cannot run says so, keeps what it showed, and a container count without mailcow is no all clear', async () => {
    // Cold start: the blocklist cannot be read, the rest can
    const w = page({ '/api/blacklist/summary': 'fail', '/api/status/summary': { containers: { running: 17, stopped: 1, total: 18 }, containers_known: true } });
    await loadAll(w);
    const note = w.document.getElementById('dashboard-attention-clear');
    assert.match(note.textContent, /Some checks could not run\. Retry/);
    assert.match(w.document.getElementById('dashboard-attention').innerHTML, /A mailcow container is stopped/);
    // Next time mailcow does not answer: zeros that must not drop the stopped container
    w.answers['/api/status/summary'] = { containers: { running: 0, stopped: 0, total: 0 }, containers_known: false };
    w.answers['/api/blacklist/summary'] = { status: 'clean' };
    await w.loadDashboardAttention();
    assert.match(w.document.getElementById('dashboard-attention').innerHTML, /A mailcow container is stopped/);
    assert.match(note.textContent, /Some checks could not run/);
    // The alerts cannot be read: those shown stay
    w.answers['/api/security-alerts'] = 'fail';
    assert.equal(await w.loadDashboardSecurityAlerts(), false);
    assert.equal(state(w).alerts.list.length, 2);
    // Nothing known to need a look, but not everything checked: a grey dot, no all clear
    const quiet = page({ '/api/security-alerts': 'fail' });
    quiet.answers['/api/security-alerts'] = 'fail';
    await loadAll(quiet);
    assert.equal(quiet.document.querySelector('#ui-bell .ui-bell-n').className, 'ui-bell-n is-unknown');
    assert.equal(quiet.document.getElementById('ui-bell').getAttribute('aria-label'), 'Needs attention, some checks could not run');
    assert.doesNotMatch(quiet.document.getElementById('dashboard-attention-clear').textContent, /Nothing needs attention/);
    // Retry reads again what failed
    quiet.answers['/api/security-alerts'] = { alerts: [], unacknowledged_count: 0, unacknowledged_critical: 0, unacknowledged_ids: [] };
    quiet.attentionRetry();
    await state(quiet).alerts.busy;
    assert.equal(quiet.document.getElementById('dashboard-attention-clear').textContent, 'Nothing needs attention right now.');
});

test('mailcow Read changes shows the update the check found', async () => {
    const w = page({ '/api/status/version': { update_available: true, latest_version: '2026-11', current_version: '2026-08', name: 'November', changelog: 'Notes' } });
    await w.loadDashboardAttention();
    assert.equal(w.mailcowUpdateVersion, '2026-11');
    assert.equal(w.mailcowUpdateName, 'November');
    assert.equal(w.mailcowUpdateChangelog, 'Notes');
});

test('the window is a layer: focus in, Escape back to the bell, the page behind inert, no axe violations', async () => {
    const w = page();
    await loadAll(w);
    const bell = w.document.getElementById('ui-bell');
    bell.focus();
    bell.click();
    await settle(w);
    const win = w.document.getElementById('attn-window');
    assert.ok(win);
    assert.equal(bell.getAttribute('aria-expanded'), 'true');
    assert.equal(bell.getAttribute('aria-controls'), 'attn-window');
    assert.ok(win.contains(w.document.activeElement));
    assert.equal(w.document.getElementById('other').closest('[inert]') !== null, true);
    assert.equal(win.querySelectorAll('#attn-win-alerts .ui-alert').length, 2);
    assert.match(w.document.getElementById('attn-win-dismiss-all').textContent, /Dismiss all 2/);
    const script = w.document.createElement('script');
    script.textContent = axeSource;
    w.document.head.appendChild(script);
    const result = await w.axe.run(w.document, { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } });
    assert.equal(result.violations.length, 0, result.violations.map(v => `${v.id}: ${v.nodes.map(n => n.target).join(' ')}`).join('; '));
    w.document.activeElement.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
    await settle(w);
    assert.equal(w.document.getElementById('attn-window'), null);
    assert.equal(bell.getAttribute('aria-expanded'), 'false');
    assert.equal(bell.hasAttribute('aria-controls'), false);
    assert.equal(w.document.activeElement, bell);
    assert.equal(w.document.getElementById('other').closest('[inert]'), null);
});

test('a page opened from the window takes the focus; a move cancelled over unsaved changes leaves it open', async () => {
    const w = page();
    await loadAll(w);
    const bell = w.document.getElementById('ui-bell');
    bell.focus();
    bell.click();
    await settle(w);
    // Unsaved changes, and the answer is Stay
    w.uiUnsavedCount = () => 1;
    w.uiConfirmLeave = async () => false;
    await w.attnBellGo(['dashboard']);
    await settle(w);
    assert.ok(w.document.getElementById('attn-window'));
    w.uiUnsavedCount = () => 0;
    await w.attnBellGo(['dashboard']);
    await settle(w);
    assert.equal(w.document.getElementById('attn-window'), null);
    assert.equal(w.eval('switched').at(-1), 'dashboard');
    // Its title is in the top bar there, not in the page
    assert.equal(w.document.activeElement.textContent, 'Dashboard');
    assert.equal(w.document.activeElement.parentElement.id, 'ui-topbar-title');
});

test('Show activity from the window closes it, and the activity window gives the focus back to the bell', async () => {
    const w = page();
    await loadAll(w);
    const bell = w.document.getElementById('ui-bell');
    bell.focus();
    bell.click();
    await settle(w);
    // The activity window, reduced to a dialog
    w.openAlertActivity = id => {
        const dlg = w.document.createElement('div');
        dlg.id = 'activity';
        dlg.className = 'ui-dialog-backdrop';
        dlg.innerHTML = `<div role="dialog" aria-label="Activity ${id}"><button type="button" aria-label="Close" onclick="document.getElementById('activity').remove()">x</button></div>`;
        w.document.body.appendChild(dlg);
    };
    const show = [...w.document.querySelectorAll('#attn-win-alerts button')].find(b => b.textContent === 'Show activity');
    show.focus();
    show.click();
    await settle(w);
    assert.equal(w.document.getElementById('attn-window'), null);
    assert.ok(w.document.getElementById('activity').contains(w.document.activeElement));
    w.document.querySelector('#activity button').click();
    await settle(w);
    assert.equal(w.document.activeElement, bell);
});

test('Undo with the window open puts the keyboard on the alert back in the window', async () => {
    const w = page({ '/api/security-alerts': { alerts: [alert(2)], unacknowledged_count: 1, unacknowledged_critical: 0, unacknowledged_ids: [2] } });
    await loadAll(w);
    w.document.getElementById('ui-bell').click();
    await settle(w);
    w.showToast = () => {};
    w.answers['/api/security-alerts/acknowledgements/r1/undo'] = { restored: 1, ids: [1] };
    w.answers['/api/security-alerts'] = { alerts: [alert(1), alert(2)], unacknowledged_count: 2, unacknowledged_critical: 0, unacknowledged_ids: [1, 2] };
    await w.undoAlertDismissal('r1', 'Undo');
    const focused = w.document.activeElement;
    assert.equal(focused.textContent, 'Dismiss');
    assert.ok(focused.closest('#attn-win-alerts [data-key="alert-1"]'));
});

test('a blocklist check that ended in an error is no all clear: the listing stays and the note offers Retry', async () => {
    const w = page({ '/api/blacklist/summary': { status: 'listed', hosts: [{ hostname: '203.0.113.10', status: 'listed', listed_count: 1, total_blacklists: 30 }] } });
    await loadAll(w);
    assert.match(w.document.getElementById('dashboard-attention').innerHTML, /203\.0\.113\.10 is on a blocklist/);
    w.answers['/api/blacklist/summary'] = { status: 'error', hosts: [] };
    await w.loadDashboardAttention();
    assert.match(w.document.getElementById('dashboard-attention').innerHTML, /203\.0\.113\.10 is on a blocklist/);
    assert.match(w.document.getElementById('dashboard-attention-clear').textContent, /Some checks could not run/);
});

test('a press that begins in the window and ends beside it (a text selection) leaves it open; a click beside it closes it', async () => {
    const w = page();
    await loadAll(w);
    w.document.getElementById('ui-bell').click();
    await settle(w);
    const win = w.document.getElementById('attn-window');
    win.querySelector('.ui-alert p').dispatchEvent(new w.MouseEvent('mousedown', { bubbles: true }));
    win.dispatchEvent(new w.MouseEvent('click', { bubbles: true, detail: 1 }));
    await settle(w);
    assert.ok(w.document.getElementById('attn-window'));
    win.dispatchEvent(new w.MouseEvent('mousedown', { bubbles: true }));
    win.dispatchEvent(new w.MouseEvent('click', { bubbles: true, detail: 1 }));
    await settle(w);
    assert.equal(w.document.getElementById('attn-window'), null);
});

test('a hidden browser tab reads nothing, and shown again reads what is due', async () => {
    const w = page();
    state(w).ready = true;
    await loadAll(w);
    // The alerts are due, the server checks were just read
    state(w).alerts.at = Date.now() - 60000;
    w.asked.length = 0;
    Object.defineProperty(w.document, 'hidden', { configurable: true, get: () => true });
    w.attentionRefresh();
    assert.equal(w.asked.length, 0);
    Object.defineProperty(w.document, 'hidden', { configurable: true, get: () => false });
    w.attentionRefresh();
    await state(w).alerts.busy;
    assert.ok(w.asked.includes('/api/security-alerts'));
    assert.ok(!w.asked.includes('/api/status/summary'));
});

test('an alerts read that never answers has failed by the time limit, and the next refresh asks again', async () => {
    const w = page();
    await loadAll(w);
    state(w).timeout = 50;
    // The server stops answering: the list read hangs
    w.answers['/api/security-alerts'] = () => new Promise(() => {});
    assert.equal(await w.loadDashboardSecurityAlerts({ force: false }), false);
    assert.equal(state(w).alerts.ok, false);
    assert.equal(state(w).alerts.busy, null);
    assert.match(w.document.getElementById('dashboard-attention-clear').textContent, /Some checks could not run/);
    // The alerts it showed stay, and the next load goes out instead of joining the hung one
    assert.equal(state(w).alerts.list.length, 2);
    w.answers['/api/security-alerts'] = { alerts: [alert(2)], unacknowledged_count: 1, unacknowledged_critical: 0, unacknowledged_ids: [2] };
    assert.equal(await w.loadDashboardSecurityAlerts({ force: false }), true);
    assert.deepEqual(state(w).alerts.list.map(a => a.id), [2]);
});

// ---------- alerts of three areas: Security, Domains, DMARC & TLS ----------

const STORED_ALERTS = { alerts: [alert(1, 'critical'), { ...alert(5, 'warning', 'dns_change'), subject: 'example.com' }, alert(6, 'warning', 'dmarc_import_failed')],
    unacknowledged_count: 3, unacknowledged_critical: 1, unacknowledged_ids: [1, 5, 6] };

function person(w, scopes) {
    w.setAppAccess({ authenticated: true, is_admin: false, scopes });
    w.toasts = [];
    w.showToast = (message, tone) => w.toasts.push([message, tone]);
}

test('a person with View for Domains or DMARC & TLS only reads the alerts; one with neither does not', async () => {
    for (const [scopes, read] of [[['domains:read'], true], [['dmarc:read'], true], [['security:read'], true], [['messages:read', 'outbound:write'], false]]) {
        const w = page();
        person(w, scopes);
        await w.loadDashboardSecurityAlerts();
        assert.equal(w.asked.includes('/api/security-alerts'), read, scopes.join(' '));
    }
});

test('Dismiss all counts and sends only the alerts the person may dismiss, and is gone without any', async () => {
    const w = page({ '/api/security-alerts': { ...STORED_ALERTS, writable_ids: [5] } });
    person(w, ['security:read', 'domains:read', 'domains:write']);
    await w.loadDashboardSecurityAlerts();
    const button = w.document.getElementById('dashboard-dismiss-all');
    assert.equal(button.getAttribute('aria-label'), 'Dismiss 1 alert');
    assert.equal(button.classList.contains('is-off'), false);
    let sent = null;
    const fetch = w.authenticatedFetch;
    w.authenticatedFetch = async (url, options) => {
        if (url !== '/api/security-alerts/acknowledge-all') return fetch(url, options);
        sent = JSON.parse(options.body).ids;
        return { ok: true, status: 200, json: async () => ({ acknowledged: 1, ids: [5], receipt: null }) };
    };
    await w.acknowledgeAllSecurityAlerts();
    assert.deepEqual(sent, [5]);
    // Only View: the list is there, Dismiss all is not
    const viewer = page({ '/api/security-alerts': { ...STORED_ALERTS, writable_ids: [] } });
    person(viewer, ['security:read', 'domains:read']);
    await viewer.loadDashboardSecurityAlerts();
    assert.equal(viewer.document.querySelectorAll('#dashboard-security-alerts .ui-alert').length, 3);
    assert.equal(viewer.document.getElementById('dashboard-dismiss-all').classList.contains('is-off'), true);
});

test('Dismiss and Undo ask for Take action in the area of the alert, in the window and on the Dashboard', async () => {
    for (const [area, mine, other] of [['domains', 5, 1], ['dmarc', 6, 5], ['security', 1, 6]]) {
        const w = page({ '/api/security-alerts': { ...STORED_ALERTS, writable_ids: [mine] } });
        person(w, ['security:read', 'domains:read', 'dmarc:read', `${area}:write`]);
        await w.loadDashboardSecurityAlerts();
        w.document.getElementById('ui-bell').click();
        await settle(w);
        for (const where of ['#attn-win-alerts', '#dashboard-security-alerts']) {
            const dismiss = id => [...w.document.querySelectorAll(`${where} [data-key="alert-${id}"] button`)].find(b => b.textContent === 'Dismiss');
            assert.equal(dismiss(mine).dataset.acts, `alerts ${area}`, where);
            assert.notEqual(dismiss(other).dataset.acts, `alerts ${area}`, where);
        }
        w.answers[`/api/security-alerts/${other}/acknowledge`] = { acknowledged: 1, ids: [other], receipt: 'r-other' };
        w.answers[`/api/security-alerts/${mine}/acknowledge`] = { acknowledged: 1, ids: [mine], receipt: 'r-mine' };
        w.asked.length = 0;
        await w.acknowledgeSecurityAlert(other);
        assert.ok(!w.asked.includes(`/api/security-alerts/${other}/acknowledge`), `${area}: an alert of another area is not sent`);
        assert.equal(w.toasts.at(-1)[0], 'You do not have permission for this.');
        await w.acknowledgeSecurityAlert(mine);
        assert.ok(w.asked.includes(`/api/security-alerts/${mine}/acknowledge`), area);
        // Undo asks again: its own area yes, another no
        w.answers['/api/security-alerts/acknowledgements/r-mine/undo'] = { restored: 1, ids: [mine] };
        w.asked.length = 0;
        await w.undoAlertDismissal('r-other', 'Undo', [area === 'security' ? 'dmarc' : 'security']);
        assert.equal(w.asked.length, 0, area);
        await w.undoAlertDismissal('r-mine', 'Undo', [area]);
        assert.ok(w.asked.includes('/api/security-alerts/acknowledgements/r-mine/undo'), area);
    }
    // Only View: nothing is sent
    const viewer = page({ '/api/security-alerts': { ...STORED_ALERTS, writable_ids: [] } });
    person(viewer, ['domains:read']);
    await viewer.loadDashboardSecurityAlerts();
    viewer.asked.length = 0;
    await viewer.acknowledgeSecurityAlert(5);
    await viewer.acknowledgeAllSecurityAlerts();
    await viewer.undoAlertDismissal('r1', 'Undo');
    assert.deepEqual(viewer.asked, []);
});

test('Undo that brings nothing back says why it may be', async () => {
    const w = page();
    await loadAll(w);
    w.toasts = [];
    w.showToast = (message, tone) => w.toasts.push([message, tone]);
    w.answers['/api/security-alerts/acknowledgements/r9/undo'] = { restored: 0, ids: [] };
    await w.undoAlertDismissal('r9', 'Undo');
    assert.deepEqual(w.toasts.at(-1), ['Nothing to undo: dismissed again, or your access changed', 'info']);
});

test('Open on an alert moves to its page and then shows its place; from the window, only once the move is made', async () => {
    const w = page({ '/api/security-alerts': { ...STORED_ALERTS, writable_ids: [1, 5, 6] } });
    await loadAll(w);
    w.toasts = [];
    w.showToast = message => w.toasts.push(message);
    w.Element.prototype.scrollIntoView = function () { w.scrolled = this; };
    const domains = w.document.createElement('section');
    domains.className = 'ui-page hidden';
    domains.id = 'content-domains';
    domains.innerHTML = '<h1>Domains</h1><input id="domain-search-input" aria-label="Search domains" value="other"><div data-domain-row="example.com"></div><div id="domain-example-com-details" class="hidden"></div>';
    w.document.querySelector('main').appendChild(domains);
    w.eval(`var domainsLoading = Promise.resolve(true); var cleared = 0; var opened = [];
        function domainRowId(n) { return 'domain-' + String(n).replace(/[^A-Za-z0-9_-]/g, '-'); }
        function clearDomainFilters() { cleared++; }
        function toggleDomainDetails(id) { document.getElementById(id + '-details').classList.remove('hidden'); }
        function showDmarcSyncHistory() { opened.push('history'); }
        var securityCountry = 'DE', securityNetwork = 'Example Net', securityTab = 'settings';
        function setSecurityFilter(key) { opened.push('security:' + key); }`);
    const openButton = (id, label) => [...w.document.querySelectorAll(`#attn-win-alerts [data-key="alert-${id}"] button`)].find(b => b.textContent === label);
    w.document.getElementById('ui-bell').click();
    await settle(w);
    // Unsaved changes, and the answer is Stay: the window stays and nothing opens
    w.uiUnsavedCount = () => 1;
    w.uiConfirmLeave = async () => false;
    await w.openStoredAlert(6, 'bell');
    assert.ok(w.document.getElementById('attn-window'));
    assert.equal(w.eval('JSON.stringify(opened)'), '[]');
    w.uiUnsavedCount = () => 0;
    assert.ok(openButton(6, 'Open fetch history'));
    await w.openStoredAlert(6, 'bell');
    await settle(w);
    assert.equal(w.document.getElementById('attn-window'), null);
    assert.equal(w.eval('switched').at(-1), 'dmarc');
    assert.equal(w.eval('JSON.stringify(opened)'), '["history"]');
    // The domain: its details open in the list, whatever the filters showed
    w.document.getElementById('ui-bell').click();
    await settle(w);
    assert.ok(openButton(5, 'Open domain'));
    await w.openStoredAlert(5, 'bell');
    await settle(w);
    assert.equal(w.document.getElementById('attn-window'), null);
    assert.equal(w.eval('switched').at(-1), 'domains');
    assert.equal(w.eval('cleared'), 1);
    assert.equal(w.document.getElementById('domain-example-com-details').classList.contains('hidden'), false);
    assert.equal(w.scrolled.dataset.domainRow, 'example.com');
    // A domain no longer on the server says so
    w.document.getElementById('domain-example-com-details').remove();
    await w.openStoredAlert(5, 'page');
    assert.match(w.toasts.at(-1), /example\.com is not in the domain list any more\./);
    // Protection: To review, with no country or network that could hide the address
    w.eval(`attention.alerts.list.push({ id: 7, alert_type: 'protection_breach', severity: 'critical', title: 'Possible stolen password: user@example.com', subject: 'user@example.com', detail: 'An unusual sign-in may mean someone else has access.', created_at: '2026-10-22T10:00:00Z' }); dashboardAlerts.set(7, attention.alerts.list.at(-1));`);
    // A move cancelled over unsaved changes keeps the list as it was
    w.uiUnsavedCount = () => 1;
    await w.openStoredAlert(7, 'page');
    assert.equal(w.eval('JSON.stringify([securityCountry, securityNetwork, opened.at(-1)])'), '["DE","Example Net","history"]');
    w.uiUnsavedCount = () => 0;
    await w.openStoredAlert(7, 'page');
    assert.equal(w.eval('switched').at(-1), 'netfilter');
    assert.equal(w.eval('JSON.stringify([securityCountry, securityNetwork, opened.at(-1)])'), '[null,null,"security:review"]');
});

test('Open Security from another tab of the Security page loads and draws To review', async () => {
    const asked = [];
    const w = page({
        '/api/security-alerts': { alerts: [alert(7, 'critical', 'protection_breach')], unacknowledged_count: 1, unacknowledged_critical: 1, unacknowledged_ids: [7], writable_ids: [7] },
        '/api/security/addresses': { list: 'review', items: [], next: null, counts: {}, all_counts: { review: 0 } },
    }, { scripts: ['security.js'], realSwitch: true });
    const fetch = w.authenticatedFetch;
    w.authenticatedFetch = (url, options) => { asked.push(url); return fetch(url, options); };
    // The Security page is open on Settings; Overview was left on Banned, for one country and network
    const security = w.document.getElementById('content-security');
    security.id = 'content-netfilter';
    security.classList.add('tab-content');
    security.innerHTML = `<h1>Security</h1>
        <div id="security-tab-overview" class="hidden"><div id="security-protections"></div><div id="security-list"><p id="old-list">Banned list</p></div></div>
        <div id="security-tab-settings"></div><div id="security-tab-lists" class="hidden"></div><div id="security-tab-events" class="hidden"></div>`;
    w.eval(`currentTab = 'netfilter'; securityTab = 'settings'; securityFilter = 'banned'; securityCountry = 'DE'; securityNetwork = 'Example Net';`);
    w.uiUnsavedCount = () => 0;
    await w.loadDashboardSecurityAlerts();
    asked.length = 0;
    assert.equal(await w.openAlertSecurityReview(), true);
    await settle(w);
    assert.equal(w.eval('securityTab'), 'overview');
    assert.equal(w.document.getElementById('security-tab-overview').classList.contains('hidden'), false);
    assert.equal(w.eval('JSON.stringify([securityFilter, securityCountry, securityNetwork])'), '["review",null,null]');
    // The list is asked for again, for To review in every country and network, and drawn anew
    const lists = asked.filter(u => u.startsWith('/api/security/addresses?'));
    assert.equal(lists.length, 1, asked.join(' '));
    const query = new URLSearchParams(lists[0].split('?')[1]);
    assert.equal(query.get('list'), 'review');
    assert.ok(!query.has('country') && !query.has('network'));
    assert.equal(w.document.getElementById('old-list'), null);
});

test('Open domain says the domain is gone only when the list loaded without it, not when the list could not load', async () => {
    const domainsPage = { domains: [{ domain_name: 'example.org', active: 1, mboxes_in_domain: 1, aliases_in_domain: 0, dns_checks: {} }], total: 1, active: 1 };
    for (const [answer, toast] of [['fail', null], [domainsPage, 'example.com is not in the domain list any more.']]) {
        const w = page({ '/api/security-alerts': { ...STORED_ALERTS, writable_ids: [5] }, '/api/domains/all': answer }, { scripts: ['domains.js'] });
        const section = w.document.createElement('section');
        section.className = 'ui-page hidden';
        section.id = 'content-domains';
        section.innerHTML = '<h1>Domains</h1><div id="domains-loading"></div><div id="domains-content" class="hidden"></div>';
        w.document.querySelector('main').appendChild(section);
        // The page switch loads the list, as app.js does for Domains
        w.eval(`function switchTab(tab) { switched.push(tab); if (tab === 'domains') loadDomains(); }`);
        w.toasts = [];
        w.showToast = message => w.toasts.push(message);
        await w.loadDashboardSecurityAlerts();
        await w.openStoredAlert(5, 'page');
        assert.equal(w.eval('switched').at(-1), 'domains');
        if (answer === 'fail') {
            // The page says the list could not load; the alert adds nothing untrue
            assert.match(w.document.getElementById('domains-loading').textContent, /Failed to load domains/);
            assert.equal(w.toasts.length, 0, w.toasts.join(' | '));
        } else {
            assert.ok(w.document.querySelector('[data-domain-row="example.org"]'), 'the list was drawn');
            assert.deepEqual(w.toasts, [toast]);
        }
    }
});
