// Every dialog in the app, opened in a real DOM (jsdom) over the real index.html
// with the real page scripts: each has the shared frame (a head with its title
// and an X, unless it is a question; its actions in the foot), keeps the rule for
// a click outside (DS-9), asks before dropping typed changes, closes on a pull
// down on a phone (a question as Cancel), and a question shows above the dialog
// or sheet it was asked from. popups.test.cjs keeps new popups on this frame.
// Set A11Y_MODULES to jsdom's node_modules to run it locally (see layers.a11y.cjs).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test, afterEach } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');
const SCRIPTS = ['utils.js', 'router.js', 'app.js', 'settings.js', 'notifications.js', 'agents.js', 'spam_filter.js'].map(read);
const HTML = read('index.html').replace(/<script\b[^>]*\bsrc=[^>]*><\/script>/g, '').replace(/<link\b[^>]*>/g, '');
const STYLE = '<style>.hidden { display: none; } .ui-dialog-backdrop { z-index: 50; } .ui-sheet { z-index: 70; } .ui-confirm { z-index: 99999; }</style>';

// Every window a test opened closes after it, timers and all, so a failing test
// cannot leave a refresh running that keeps the run from ending
const opened = [];
afterEach(() => { while (opened.length) opened.pop().close(); });

// The app, with the network answered by answer(url) (pending when it returns undefined)
function page({ phone = false, answer = () => undefined } = {}) {
    const dom = new JSDOM(HTML.replace('</head>', `${STYLE}</head>`), {
        runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/settings',
        beforeParse: win => {
            win.matchMedia = query => ({ matches: phone && /max-width/.test(query), addEventListener() {}, removeEventListener() {} });
            win.fetch = () => new Promise(() => {});
            win.console = { log() {}, info() {}, warn() {}, error() {}, debug() {} };
        },
    });
    const w = dom.window;
    opened.push(w);
    // jsdom has no scrollingElement; the app resets the window's pan through it
    if (!w.document.scrollingElement) Object.defineProperty(w.document, 'scrollingElement', { value: w.document.documentElement });
    // jsdom does no layout: an element counts as shown when nothing hides it
    w.Element.prototype.getClientRects = function () {
        return this.isConnected && !this.closest('.hidden') ? [{}] : [];
    };
    if (!('inert' in w.HTMLElement.prototype)) {
        Object.defineProperty(w.HTMLElement.prototype, 'inert', { configurable: true,
            get() { return this.hasAttribute('inert'); },
            set(value) { if (value) this.setAttribute('inert', ''); else this.removeAttribute('inert'); } });
    }
    for (const source of SCRIPTS) {
        const script = w.document.createElement('script');
        script.textContent = source;
        w.document.head.appendChild(script);
    }
    w.showToast = () => {};
    w.authenticatedFetch = async url => {
        const body = answer(url);
        if (body === undefined) return new Promise(() => {});
        return { ok: true, status: 200, json: async () => body };
    };
    return w;
}

const frame = w => new Promise(resolve => w.requestAnimationFrame(() => setTimeout(resolve, 0)));
const settle = async w => { await frame(w); await frame(w); };
// Waits for a condition the app reaches through its own timers, up to a limit,
// so a busy machine does not fail a check that only came late
async function until(condition, limit = 3000) {
    const end = Date.now() + limit;
    while (Date.now() < end) {
        if (condition()) return true;
        await new Promise(resolve => setTimeout(resolve, 20));
    }
    return !!condition();
}
const $ = (w, sel) => w.document.querySelector(sel);
const escape = w => w.document.body.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
// A click with no mouse press counts as a click on the backdrop (uiBackdropClick)
const clickOutside = (w, el) => el.dispatchEvent(new w.MouseEvent('click', { bubbles: true, detail: 0 }));
const shown = (w, id) => { const el = w.document.getElementById(id); return !!el && !el.classList.contains('hidden'); };

// A finger pulls the sheet down by its head (utils.js, uiDialogSheet)
async function pullDown(w, backdrop) {
    const head = backdrop.querySelector('.ui-dialog-head');
    const touch = (type, y) => {
        const event = new w.Event(type, { bubbles: true });
        event.touches = y === null ? [] : [{ clientY: y }];
        head.dispatchEvent(event);
    };
    touch('touchstart', 100);
    touch('touchmove', 400);
    touch('touchend', null);
    await new Promise(resolve => setTimeout(resolve, 260));
    await settle(w);
}

const SUPPRESSION = { id: 7, email: 'user@example.com', reason: 'manual', source: 'manual', notes: '', expires_at: null,
    created_at: '2026-10-01T10:00:00Z', bounce_count: 0, active: true };
const AGENTS = { live: true, areas: [{ id: 'security', label: 'Security', view: 'Bans and alerts', act: 'Ban and unban' }],
    periods: [{ days: 7, label: '7 days' }],
    agents: [{ id: 5, name: 'Claude Code', state: 'connected', kind: 'device', areas: { security: 'view' }, expires_at: '2026-11-01T10:00:00Z', version: 'v1' }] };

// Every dialog built in JavaScript: how it opens, what it is, and a change for a typed one
const DIALOGS = [
    { name: 'Confirm', id: 'app-confirm-modal', kind: 'question',
      open: w => w.showConfirmModal({ title: 'Delete Message', message: 'Delete this message?', confirmText: 'Delete', isDangerous: true }), cancelled: false },
    { name: 'Choice', id: 'app-choice-modal', kind: 'question',
      open: w => w.showChoiceModal({ title: 'Keep blocks?', message: 'Pick one.', choices: [{ value: 'keep', label: 'Keep', kind: 'primary' }] }), cancelled: null },
    { name: 'Disable features', id: 'feature-disable-confirm-modal', kind: 'question',
      open: w => w.showFeatureDisableConfirmModal(['dmarc']), cancelled: false },
    { name: 'Verify credentials', id: 'basic-auth-verify-modal', kind: 'typed', guarded: false,
      open: w => w.showBasicAuthVerifyModal(), cancelled: null },
    { name: 'GeoIP setup', id: 'geoip-setup-overlay', kind: 'busy', open: w => { w.showGeoIPSetupModal(); } },
    { name: 'Connection test', id: 'connection-test-modal', kind: 'read', open: w => { w.showConnectionTestModal('Test SMTP', 'Testing SMTP connection...'); } },
    { name: 'Notification destination', id: 'notification-channel-modal', kind: 'typed', guarded: true,
      open: w => { w.eval("notificationChannelTypes = [{ id: 'slack', label: 'Slack', fields: [] }]; notificationEditing = { channel_type: 'slack', enabled: true };"); w.renderNotificationChannelModal(); },
      change: w => { $(w, '#nc-name').value = 'Ops'; } },
    { name: 'Edit access', id: 'agent-edit-modal', kind: 'typed', guarded: true,
      open: w => { w.eval(`agentsData = ${JSON.stringify(AGENTS)};`); w.editAgentAccess(5); },
      change: w => { $(w, '#agent-edit-end').value = '7'; } },
    { name: 'Add Suppression', id: 'add-suppression-modal', kind: 'typed', guarded: true,
      open: w => { w.showAddSuppressionModal(); }, change: w => { $(w, '#new-suppression-email').value = 'x@example.com'; } },
    { name: 'Edit Suppression', id: 'edit-suppression-modal', kind: 'typed', guarded: true,
      open: w => { w.showEditSuppressionModal(SUPPRESSION); }, change: w => { $(w, '#edit-suppression-notes').value = 'changed'; } },
    { name: 'Block details', id: 'block-details-modal', kind: 'read', open: w => { w.showBlockDetails(7); } },
    { name: 'Quarantine item details', id: 'quarantine-detail-modal', kind: 'read', open: w => { w.showQuarantineDetails('q1'); } },
    { name: 'Quarantine rule', id: 'quarantine-rule-modal-overlay', kind: 'typed', guarded: true,
      open: w => { w.showAddQuarantineRuleModal(); }, change: w => { $(w, '#qrule-name').value = 'Rule'; } },
    { name: 'Rule test results', id: 'qrule-test-modal', kind: 'read',
      answer: () => ({ total_matches: 1, total_quarantine: 3,
          matches: [{ rule_id: 1, rule_name: 'R', action: 'release', rule_enabled: true, sender: 'a@b.c', recipient: 'c@d.e', subject: 'Hi' }] }),
      open: w => { w.testQuarantineRules(); } },
];

async function open(dialog, options = {}) {
    const w = page({ answer: dialog.answer, ...options });
    await settle(w);
    const result = dialog.open(w);
    await settle(w);
    const backdrop = w.document.getElementById(dialog.id);
    assert.ok(backdrop, `${dialog.name} opened`);
    return { w, result, backdrop };
}

for (const dialog of DIALOGS) {
    test(`${dialog.name}: the shared frame, with its actions in the foot`, async () => {
        const { backdrop } = await open(dialog);
        assert.ok(backdrop.matches('.ui-dialog-backdrop[role]'));
        assert.ok(backdrop.getAttribute('aria-label') || backdrop.getAttribute('aria-labelledby'), 'it has a label');
        const box = backdrop.querySelector(':scope > .ui-dialog');
        assert.ok(box && box.classList.contains('ui-dialog-fit'), 'it fits its content');
        assert.ok(box.querySelector(':scope > .ui-dialog-head > h3').textContent.trim(), 'its head has a title');
        const x = box.querySelector(':scope > .ui-dialog-head [aria-label="Close"]');
        assert.equal(!!x, dialog.kind !== 'question', dialog.kind === 'question' ? 'a question has no X' : 'it has an X');
        const body = box.querySelector(':scope > .ui-dialog-body');
        const actions = [...body.querySelectorAll('button')].filter(b => (b.type === 'submit' && b.form) || /^(cancel|close|save)$/i.test(b.textContent.trim()));
        assert.deepEqual(actions.map(b => b.textContent.trim()), [], 'no Cancel, Close or Save inside the scrolling body');
    });

    test(`${dialog.name}: a click outside follows DS-9`, async () => {
        const { w, result, backdrop } = await open(dialog);
        clickOutside(w, backdrop);
        await settle(w);
        const closes = dialog.kind === 'read' || dialog.kind === 'question';
        assert.equal(!backdrop.isConnected || backdrop.classList.contains('hidden'), closes,
            closes ? 'a window without typed input closes' : 'a window with typed input (or still working) stays');
        if (dialog.kind === 'question') assert.equal(await result, dialog.cancelled, 'a click outside cancels');
    });

    test(`${dialog.name}: a pull down on a phone`, async () => {
        const { w, result, backdrop } = await open(dialog, { phone: true });
        if (dialog.change) dialog.change(w);
        await pullDown(w, backdrop);
        if (dialog.kind === 'busy') {
            assert.ok(backdrop.isConnected, 'it stays while it works');
        } else if (dialog.guarded) {
            assert.ok(await until(() => $(w, '#app-confirm-modal')), 'it asks before it drops the change');
            assert.ok(backdrop.isConnected, 'a change is not dropped');
            assert.ok(await until(() => w.document.activeElement && w.document.activeElement.id === 'app-confirm-cancel'),
                'the question starts on Keep editing');
            $(w, '#app-confirm-cancel').click();
            await settle(w);
            assert.ok(backdrop.isConnected, 'Keep editing keeps it');
        } else {
            assert.ok(await until(() => !backdrop.isConnected || backdrop.classList.contains('hidden')), 'it closed');
            if (dialog.kind === 'question' || 'cancelled' in dialog) assert.equal(await result, dialog.cancelled, 'it closed as Cancel');
        }
    });
}

for (const dialog of DIALOGS.filter(d => d.guarded)) {
    test(`${dialog.name}: X and Escape ask before dropping a change, and close when nothing changed`, async () => {
        for (const how of ['x', 'escape']) {
            const { w, backdrop } = await open(dialog);
            const close = () => how === 'x' ? backdrop.querySelector('.ui-dialog-head [aria-label="Close"]').click() : escape(w);
            dialog.change(w);
            close();
            assert.ok(await until(() => $(w, '#app-confirm-modal')), `${how}: it asks`);
            $(w, '#app-confirm-ok').click();
            assert.ok(await until(() => !backdrop.isConnected), `${how}: Discard closes it`);
        }
        const { w, backdrop } = await open(dialog);
        backdrop.querySelector('.ui-dialog-head [aria-label="Close"]').click();
        await settle(w);
        assert.ok(!backdrop.isConnected && !$(w, '#app-confirm-modal'), 'unchanged, it closes without asking');
    });
}

test('GeoIP setup: its X is off while the setup runs, like its Close', async () => {
    const { w, backdrop } = await open(DIALOGS.find(d => d.id === 'geoip-setup-overlay'));
    const x = backdrop.querySelector('.ui-dialog-head [aria-label="Close"]');
    assert.equal(x.disabled, true);
    assert.equal($(w, '#geoip-setup-close-btn').disabled, true);
    escape(w);
    await settle(w);
    assert.ok(backdrop.isConnected, 'Escape does not stop it halfway');
});

// Enter on a focused button presses that button (here as its click), never the confirm
const enterOn = (w, el) => {
    el.focus();
    const event = new w.KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true });
    el.dispatchEvent(event);
    if (!event.defaultPrevented) el.click();
};

test('Verify credentials: Enter on the X cancels, Enter in a field confirms', async () => {
    const verify = DIALOGS.find(d => d.id === 'basic-auth-verify-modal');
    let { w, result, backdrop } = await open(verify);
    $(w, '#verify-auth-username').value = 'admin';
    $(w, '#verify-auth-password').value = 'secret';
    enterOn(w, backdrop.querySelector('.ui-dialog-head [aria-label="Close"]'));
    assert.equal(await result, null, 'the X cancels, the typed credentials are not used');
    ({ w, result } = await open(verify));
    $(w, '#verify-auth-username').value = 'admin';
    $(w, '#verify-auth-password').value = 'secret';
    enterOn(w, $(w, '#verify-auth-password'));
    // Compared as plain values: the answer is an object of the page's own realm
    assert.deepEqual({ ...(await result) }, { username: 'admin', password: 'secret' });
});

test('Disable features: Enter on Cancel cancels, it does not delete the data', async () => {
    const { w, result } = await open(DIALOGS.find(d => d.id === 'feature-disable-confirm-modal'));
    enterOn(w, $(w, '#feature-disable-cancel'));
    assert.equal(await result, false);
});

test('a question asked from a dialog keeps the page locked until the dialog closes', async () => {
    const { w } = await open(DIALOGS.find(d => d.id === 'quarantine-detail-modal'));
    assert.equal(w.document.body.style.overflow, 'hidden');
    const answer = w.showConfirmModal({ title: 'Delete Message', message: 'Delete?' });
    await settle(w);
    $(w, '#app-confirm-cancel').click();
    assert.equal(await answer, false);
    assert.equal(w.document.body.style.overflow, 'hidden', 'the details are still open');
    w.closeQuarantineDetails();
    assert.equal(w.document.body.style.overflow, '');
});

test('a question asked from a sheet is the top layer', async () => {
    const w = page({ phone: true });
    await settle(w);
    w.uiSheetShow('help-sheet', { label: 'Help', head: '<h3>Help</h3>', body: '<p>Text</p>' });
    await settle(w);
    const answer = w.showConfirmModal({ title: 'Sure?', message: 'Really?' });
    await settle(w);
    const top = w.openOverlays().pop();
    assert.equal(top.id, 'app-confirm-modal');
    escape(w);
    assert.equal(await answer, false);
    await settle(w);
    assert.ok($(w, '#help-sheet'), 'Escape closed the question only');
});

test('the builder: sizes, ids, data, a form, and an X called without arguments', async () => {
    const w = page();
    await settle(w);
    const calls = [];
    const close = function () { calls.push(arguments.length); };
    const made = w.uiDialog({ id: 'demo-modal', title: 'Demo', titleId: 'demo-h', size: 'md', close, bodyClass: 'ui-form',
        form: { id: 'demo-form', onsubmit: 'event.preventDefault()' }, dataset: { version: 'v2' },
        body: '<input id="demo-field">', foot: '<button type="submit" form="demo-form">Save</button>' });
    assert.equal(made.backdrop.id, 'demo-modal');
    assert.equal(made.backdrop.getAttribute('aria-labelledby'), 'demo-h');
    assert.equal(made.backdrop.dataset.version, 'v2');
    assert.ok(made.dialog.classList.contains('ui-dialog-md'));
    assert.equal(made.body.tagName, 'FORM');
    assert.equal(made.body.id, 'demo-form');
    assert.ok(made.foot.matches('.ui-dialog-foot'));
    made.dialog.querySelector('[aria-label="Close"]').click();
    assert.deepEqual(calls, [0], 'close gets no argument, so a "saved" flag stays false');
    assert.throws(() => w.uiDialog({ title: 'No size', close }), /size/);
    assert.throws(() => w.uiDialog({ title: 'No X', size: 'sm' }), /close/);
    const question = w.uiDialog({ title: 'Sure?', size: 'sm', role: 'alertdialog', foot: '<button data-cancel>Cancel</button>' });
    assert.equal(question.dialog.querySelector('[aria-label="Close"]'), null);
});

// The log box with a size, since jsdom does no layout: 20px a line, 400px tall
function sizeLogBox(w) {
    const box = $(w, '#container-logs-content').parentElement;
    let top = 0;
    const height = () => w.document.querySelectorAll('#container-logs-content .ui-log-line').length * 20;
    Object.defineProperty(box, 'scrollHeight', { configurable: true, get: height });
    Object.defineProperty(box, 'clientHeight', { configurable: true, get: () => 400 });
    Object.defineProperty(box, 'scrollTop', { configurable: true, get: () => top,
        set: v => { top = Math.max(0, Math.min(Number(v) || 0, height() - 400)); } });
    return { box, atEnd: () => top === Math.max(0, height() - 400) };
}
const logLines = w => w.document.querySelectorAll('#container-logs-content .ui-log-line').length;
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));

test('the container log: the shared frame, a terminal inside, the whole screen on a phone, at its end, following', async () => {
    // Each read returns ten more lines, as a live log does
    let reads = 0;
    const w = page({ phone: true, answer: url => (/container-logs/.test(url)
        ? { logs: Array.from({ length: 300 + 10 * reads++ }, (_, i) => `line ${i}\n`) } : undefined) });
    await settle(w);
    const { box, atEnd } = sizeLogBox(w);
    const backdrop = $(w, '#container-logs-modal');
    for (let opening = 1; opening <= 2; opening++) {
        w.loadContainerLogs();
        await settle(w);
        await settle(w);
        assert.ok(backdrop.matches('.ui-dialog-backdrop:not(.hidden)'));
        assert.ok(backdrop.classList.contains('is-full'), `opening ${opening}: it fills the screen, and the dialog watcher did not undo it`);
        assert.ok(box.matches('.ui-dialog-body.ui-log-term'), 'the terminal body scrolls the log');
        assert.ok(backdrop.querySelector('.ui-dialog-head [aria-label="Close"]'));
        const first = logLines(w);
        assert.ok(first >= 300, `opening ${opening}: the log loaded`);
        assert.ok(atEnd() && box.scrollTop > 0, `opening ${opening}: it opens at its end`);
        // The refresh (every 2 seconds) adds lines and follows them
        assert.ok(await until(() => logLines(w) > first, 6000), `opening ${opening}: new lines arrive`);
        assert.ok(atEnd(), `opening ${opening}: it keeps following the end`);
        // Scrolled up, the reader keeps the place and the refresh waits
        box.scrollTop = 0;
        const held = logLines(w);
        await wait(2300);
        assert.equal(logLines(w), held, `opening ${opening}: no refresh while the reader is up the log`);
        assert.equal(box.scrollTop, 0, `opening ${opening}: the place is kept`);
        w.closeContainerLogsModal();
        assert.ok(backdrop.classList.contains('hidden'));
    }
});

test('the Suppressions More menu is a popover menu of buttons with an icon button', () => {
    const html = read('index.html');
    const w = new JSDOM(html.replace(/<script\b[\s\S]*?<\/script>/g, '')).window;
    const button = w.document.getElementById('suppression-more-btn');
    const menu = w.document.getElementById('suppression-more-menu');
    assert.ok(button.querySelector('svg'), 'an icon, not a text glyph');
    assert.equal(button.getAttribute('aria-controls'), 'suppression-more-menu');
    assert.ok(menu.hasAttribute('popover') && menu.classList.contains('ui-menu') && menu.getAttribute('role') === 'menu');
    const items = [...menu.children];
    assert.deepEqual(items.map(el => el.tagName), ['BUTTON', 'BUTTON', 'BUTTON']);
    assert.ok(items.every(el => el.getAttribute('role') === 'menuitem'));
});
