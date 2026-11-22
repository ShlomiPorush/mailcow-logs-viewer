// Needs attention rows (app.js attentionAlertRows and attentionCheckRows, on the Dashboard
// and in the bell) have no coloured bar on their start edge: the severity tag (WARNING,
// CRITICAL) carries the tone. The rows keep their tag, text and actions, and the lists'
// CSS gives the text its start padding instead of the bar's column.
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

function load() {
    const context = vm.createContext({
        document: stub(), window: { matchMedia: () => ({ matches: false }), addEventListener() {} }, localStorage: stub(),
        sessionStorage: stub(), navigator: stub(), location: stub(), console: { log() {}, error() {}, warn() {} },
        setTimeout() {}, setInterval() {}, clearTimeout() {}, URLSearchParams, Intl,
    });
    for (const file of ['utils.js', 'app.js', 'alert-activity.js']) vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    return context;
}

test('stored alerts have no bar, and keep their severity tag and Dismiss', () => {
    const c = load();
    vm.runInContext(`attention.alerts.list = ${JSON.stringify([
        { id: 1, alert_type: 'auth_failure_burst', severity: 'warning', title: 'Sign-in burst', detail: 'x', created_at: '2026-11-10T10:00:00Z' },
        { id: 2, alert_type: 'volume_spike', severity: 'critical', title: 'Sending spike', detail: 'y', created_at: '2026-11-10T10:00:00Z' },
    ])}`, c);
    for (const where of ['dashboard', 'bell']) {
        const html = c.attentionAlertRows(where);
        assert.doesNotMatch(html, /ui-alert-bar/, where);
        assert.match(html, /<span class="ui-tag ui-tag-warn">WARNING<\/span>/, where);
        assert.match(html, /<span class="ui-tag ui-tag-fail">CRITICAL<\/span>/, where);
        assert.equal((html.match(/acknowledgeSecurityAlertOnce\(/g) || []).length, 2, where);
    }
});

test('checks (such as a new version) have no bar, and keep their action', () => {
    const c = load();
    vm.runInContext(`attention.checks.items.appVersion = [{ tone: 'info', title: 'Version 9.9.9 is available', detail: 'Read what changed.',
        action: 'Read changes', onclick: 'showChangelog()' }]`, c);
    for (const where of ['dashboard', 'bell']) {
        const html = c.attentionCheckRows(where);
        assert.match(html, /class="ui-alert ui-alert-info/, where);
        assert.doesNotMatch(html, /ui-alert-bar/, where);
        assert.match(html, />Read changes<\/button>/, where);
    }
});

test('the two lists give the text its start padding and use one column', () => {
    const css = fs.readFileSync(path.join(frontend, 'assets/css/ui.css'), 'utf8');
    const lists = ':is(#dashboard-attention-panel, .ui-attn-win, #attn-sheet)';
    assert.ok(css.includes(`${lists} .ui-alert { padding-inline-start: var(--ui-pad-x); grid-template-columns: minmax(0, 1fr); }`));
    assert.ok(css.includes(`${lists} :is(.ui-alert > .ui-btn, .ui-alert-acts) { grid-column: 1; }`));
    // Later in the file than the rules that reserved the bar's column, so it wins at the same specificity
    assert.ok(css.indexOf(`${lists} .ui-alert {`) > css.indexOf(':is(.ui-attn-win, #attn-sheet) .ui-alert {'));
    assert.ok(css.indexOf(`${lists} .ui-alert {`) > css.indexOf('#dashboard-attention-panel .ui-alert {'));
});
