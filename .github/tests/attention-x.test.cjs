// Needs attention alerts (app.js attentionAlertRows) are dismissed with an X, a direct
// child of the row just before its buttons, on the Dashboard and in the bell (a touch swipe
// does the same, attention-swipe.a11y.cjs). The bell's rows have no buttons under
// them (alerts and checks); the Dashboard keeps its action buttons. Checks cannot be
// dismissed and get no X.
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

const ALERTS = [
    { id: 1, alert_type: 'auth_failure_burst', severity: 'warning', title: 'Sign-in burst', detail: 'x', created_at: '2026-11-10T10:00:00Z' },
    { id: 2, alert_type: 'dns_change', severity: 'critical', title: 'DNS changed', detail: 'y', created_at: '2026-11-10T10:00:00Z' },
    { id: 3, alert_type: 'something_new', severity: 'warning', title: 'New kind', detail: 'z', created_at: '2026-11-10T10:00:00Z' },
];

function rows(html) {
    return html.split(/(?=<div class="ui-alert[ "])/).filter(r => r.startsWith('<div class="ui-alert'));
}

test('each alert has one X, a row child just before its buttons, and no Dismiss button', () => {
    const c = load();
    vm.runInContext(`attention.alerts.list = ${JSON.stringify(ALERTS)}`, c);
    for (const where of ['dashboard', 'bell']) {
        const list = rows(c.attentionAlertRows(where));
        assert.equal(list.length, 3, where);
        for (const [i, row] of list.entries()) {
            const id = ALERTS[i].id;
            const x = row.match(/<button[^>]*class="ui-icon-btn ui-icon-btn-sm ui-alert-x"[^>]*>/g) || [];
            assert.equal(x.length, 1, `${where} ${id}`);
            assert.match(x[0], new RegExp(`onclick="acknowledgeSecurityAlertOnce\\(${id}, this\\)"`));
            assert.match(x[0], /title="Dismiss alert"/);
            assert.match(x[0], /aria-label="Dismiss alert"/);
            assert.match(x[0], /data-acts="alerts \w+"/);
            // Not in the title line: a row child after the text and just before the buttons,
            // so on a wide Dashboard it sits beside the button and the keyboard reaches it
            // first, as the eye does (D15); the row can be swiped
            const title = row.slice(row.indexOf('<div class="ui-alert-title">'), row.indexOf('</div>', row.indexOf('<div class="ui-alert-title">')));
            assert.doesNotMatch(title, /ui-alert-x/, `${where} ${id}`);
            assert.match(row, /<\/div>\s*<button[^>]*ui-alert-x[^>]*>[\s\S]*?<\/button>\s*(?:<div class="ui-alert-acts">[\s\S]*?<\/div>\s*)?<\/div>\s*$/, `${where} ${id}`);
            assert.match(row, /^<div class="ui-alert[^"]*" data-key="alert-\d+" data-swipe/, `${where} ${id}`);
            assert.doesNotMatch(row, />Dismiss<\/button>/, `${where} ${id}`);
        }
    }
});

test('the bell has no buttons under its rows; the Dashboard keeps them', () => {
    const c = load();
    vm.runInContext(`attention.alerts.list = ${JSON.stringify(ALERTS)};
        attention.checks.items.appVersion = [{ tone: 'info', title: 'Version 9.9.9 is available', detail: 'd', action: 'Read changes', onclick: 'showAppUpdateModal()', popup: true }];
        attention.checks.items.blocklist = [{ tone: 'fail', title: '203.0.113.10 is on a blocklist', detail: 'd', action: 'Check listing', onclick: 'navigateTo(\\'status\\')' }]`, c);
    const bell = c.attentionAlertRows('bell') + c.attentionCheckRows('bell');
    assert.doesNotMatch(bell, /class="ui-btn/);
    assert.doesNotMatch(bell, /ui-alert-acts/);
    // A row that opens something on a click still does
    assert.match(bell, /onclick="if \(uiAlertRowClick\(event\)\) \{ attnBellOpen\(\); openAlertActivity\(1\) \}"/);
    assert.match(bell, /onclick="if \(uiAlertRowClick\(event\)\) \{ openStoredAlert\(2, 'bell'\) \}"/);
    assert.match(bell, /onclick="if \(uiAlertRowClick\(event\)\) \{ attnBellOpen\(\); showAppUpdateModal\(\) \}"/);

    const dashboard = c.attentionAlertRows('dashboard') + c.attentionCheckRows('dashboard');
    assert.match(dashboard, /<div class="ui-alert-acts"><button[^>]*openAlertActivity\(1\)[^>]*>Show activity<\/button><\/div>/);
    assert.match(dashboard, /<div class="ui-alert-acts"><button[^>]*openStoredAlert\(2, 'page'\)[^>]*>Open domain<\/button><\/div>/);
    assert.match(dashboard, />Read changes<\/button>/);
    assert.match(dashboard, />Check listing<\/button>/);
    // An alert with no way on has no empty row of actions
    assert.equal(rows(c.attentionAlertRows('dashboard'))[2].includes('ui-alert-acts'), false);
});

test('checks cannot be dismissed and have no X', () => {
    const c = load();
    vm.runInContext(`attention.checks.items.appVersion = [{ tone: 'info', title: 'Version 9.9.9 is available', detail: 'd', action: 'Read changes', onclick: 'showAppUpdateModal()', popup: true }]`, c);
    for (const where of ['dashboard', 'bell']) assert.doesNotMatch(c.attentionCheckRows(where), /ui-alert-x|Dismiss/, where);
});

test('the X keeps its icon while busy: Dismiss passes no busy text', () => {
    const app = fs.readFileSync(path.join(frontend, 'app.js'), 'utf8');
    assert.match(app, /function acknowledgeSecurityAlertOnce\(alertId, button\) \{[\s\S]*?return uiOnce\(`alert-ack:\$\{alertId\}`, \(\) => acknowledgeSecurityAlert\(alertId\), button\);\n\}/);
});

test('the X sits in the row\'s top corner at the small icon button size, also in the grid rows', () => {
    const css = fs.readFileSync(path.join(frontend, 'assets/css/ui.css'), 'utf8');
    // Two classes, so it wins over .ui-icon-btn (34px) that comes later in the file
    assert.ok(css.includes('.ui-alert > .ui-alert-x { width: 24px; height: 24px; flex: none; align-self: flex-start;'));
    assert.ok(css.includes('.ui-alert > .ui-alert-x svg { width: 14px; height: 14px; }'));
    // The bell and a phone's Dashboard: the X in a second column, beside the title
    const lists = ':is(#dashboard-attention-panel, .ui-attn-win, #attn-sheet)';
    assert.ok(css.includes(`${lists} .ui-alert:has(> .ui-alert-x) { grid-template-columns: minmax(0, 1fr) auto;`));
    assert.ok(css.includes(`${lists} .ui-alert:has(> .ui-alert-x) > :not(.ui-alert-x) { grid-column: 1; }`));
    assert.ok(css.includes(`${lists} .ui-alert > .ui-alert-x { grid-column: 2; grid-row: 1; }`));
    assert.ok(css.includes('.ui-alert[data-swipe] { touch-action: pan-y; }'));
    assert.doesNotMatch(css, /ui-alert-name/);
});
