// Alert rows have no colored bar on their start edge: the Needs attention rows (app.js
// attentionAlertRows and attentionCheckRows, on the Dashboard and in the bell), the Status
// page list, the DMARC To do card, the Settings update note and the quarantine rule note.
// The severity tag or the text carries the tone. The rows keep their tag, text and actions,
// and the base .ui-alert gives the text its start padding instead of the bar's column.
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

function load(files = ['utils.js', 'app.js', 'alert-activity.js']) {
    const context = vm.createContext({
        document: stub(), window: { matchMedia: () => ({ matches: false }), addEventListener() {} }, localStorage: stub(),
        sessionStorage: stub(), navigator: stub(), location: stub(), console: { log() {}, error() {}, warn() {} },
        setTimeout() {}, setInterval() {}, clearTimeout() {}, URLSearchParams, Intl,
    });
    for (const file of files) vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    return context;
}

function frontendFiles(dir = frontend) {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) return e.name === 'vendor' ? [] : frontendFiles(p);
        return /\.(js|html|css)$/.test(e.name) ? [p] : [];
    });
}

test('no frontend file draws or styles the bar', () => {
    const files = frontendFiles();
    assert.ok(files.length > 10);
    for (const file of files) assert.doesNotMatch(fs.readFileSync(file, 'utf8'), /ui-alert-bar/, path.relative(frontend, file));
});

test('stored alerts keep their severity tag and Dismiss', () => {
    const c = load();
    vm.runInContext(`attention.alerts.list = ${JSON.stringify([
        { id: 1, alert_type: 'auth_failure_burst', severity: 'warning', title: 'Sign-in burst', detail: 'x', created_at: '2026-11-10T10:00:00Z' },
        { id: 2, alert_type: 'volume_spike', severity: 'critical', title: 'Sending spike', detail: 'y', created_at: '2026-11-10T10:00:00Z' },
    ])}`, c);
    for (const where of ['dashboard', 'bell']) {
        const html = c.attentionAlertRows(where);
        assert.match(html, /<span class="ui-tag ui-tag-warn">WARNING<\/span>/, where);
        assert.match(html, /<span class="ui-tag ui-tag-fail">CRITICAL<\/span>/, where);
        assert.equal((html.match(/acknowledgeSecurityAlertOnce\(/g) || []).length, 2, where);
    }
});

test('checks (such as a new version) keep their action', () => {
    const c = load();
    vm.runInContext(`attention.checks.items.appVersion = [{ tone: 'info', title: 'Version 9.9.9 is available', detail: 'Read what changed.',
        action: 'Read changes', onclick: 'showChangelog()' }]`, c);
    for (const where of ['dashboard', 'bell']) {
        const html = c.attentionCheckRows(where);
        assert.match(html, /class="ui-alert ui-alert-info/, where);
        assert.match(html, />Read changes<\/button>/, where);
    }
});

test('the Status page list keeps its tone, text and actions', () => {
    const c = load();
    const els = { 'status-attention': { innerHTML: '' }, 'status-attention-count': { textContent: '' } };
    c.document = { getElementById: id => els[id] || null };
    vm.runInContext(`statusState.containers = [{ name: 'postfix', container: 'postfix-mailcow', state: 'exited', running: false }];
        statusState.jobs = [{ key: 'dmarc_imap', name: 'DMARC IMAP', failed: true, error: 'Login refused' }]`, c);
    c.renderStatusAttention();
    const html = els['status-attention'].innerHTML;
    assert.match(html, /<div class="ui-alert ui-alert-fail">\s*<div class="ui-alert-text">/);
    assert.match(html, /<div class="ui-alert ui-alert-warn">\s*<div class="ui-alert-text">/);
    assert.match(html, /<b>postfix is stopped<\/b>/);
    assert.match(html, /<p>Login refused<\/p>/);
    assert.match(html, /setContainerIgnored\('postfix-mailcow', true\)/);
    assert.match(html, /triggerBackgroundJob\('dmarc_imap'/);
    assert.equal(els['status-attention-count'].textContent, '2');
});

test('the DMARC To do card keeps its text and button', () => {
    const c = load(['utils.js', 'app.js', 'dmarc.js']);
    const html = c.dmarcTodoCard([{ tone: 'warn', title: 'Publish a DMARC record', domain: 'example.org', text: 'No record was found.',
        label: 'Show record', action: 'dmarcShowRecord()' }], true);
    assert.match(html, /<div class="ui-alert ui-alert-warn">\s*<div class="ui-alert-text">/);
    assert.match(html, /<b>Publish a DMARC record<\/b>/);
    assert.match(html, /<small class="ui-dm-task-domain">example\.org<\/small>/);
    assert.match(html, /onclick="dmarcShowRecord\(\)">Show record<\/button>/);
});

test('the update note keeps its version and release notes link', () => {
    const c = load(['utils.js', 'app.js', 'settings.js']);
    const html = c.renderUpdateNote({ update_available: true, latest_version: '9.9.9' });
    assert.match(html, /<div class="ui-alert ui-alert-info ui-set-update">\s*<div class="ui-alert-text">/);
    assert.match(html, /A new version \(v9\.9\.9\) is available on GitHub\./);
    assert.match(html, />View release notes<\/a>/);
});

test('the quarantine rule note keeps its text', () => {
    const app = fs.readFileSync(path.join(frontend, 'app.js'), 'utf8');
    assert.match(app, /<div class="ui-alert ui-alert-warn ui-qr-note">\s*<div class="ui-alert-text"><p><b>Priority:<\/b> Delete rules always take priority over Release rules\./);
});

test('the base alert pads both sides, and no alert grid keeps a column for the bar', () => {
    const css = fs.readFileSync(path.join(frontend, 'assets/css/ui.css'), 'utf8');
    assert.match(css, /^\.ui-alert \{[^}]*padding-inline: var\(--ui-pad-x\);/m);
    const grids = css.split('\n').filter(l => /\.ui-alert \{[^}]*grid-template-columns/.test(l));
    assert.equal(grids.length, 3, 'Dashboard on phones, the bell, the DMARC To do card');
    for (const line of grids) assert.match(line, /grid-template-columns: minmax\(0, 1fr\);/, line.trim());
    // The phone indent of the actions was the bar and its gap
    assert.doesNotMatch(css, /\.ui-alert-acts \{ margin-inline-start: 18px/);
    assert.doesNotMatch(css, /\.ui-st-acts \{[^}]*padding-inline-start: 18px/);
    assert.doesNotMatch(css, /\.ui-alert > \.ui-btn \{ margin-inline-start: 18px/);
});
