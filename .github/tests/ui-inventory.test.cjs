const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

const { collect, toPlain, BASELINE } = require('../scripts/ui-inventory.cjs');

const list = map => [...map].map(([name, files]) => `${name} (${[...files].join(', ')})`).join('\n  ');

test('every inline handler calls a function the frontend defines', () => {
    const { undefinedHandlers } = collect();
    assert.equal(undefinedHandlers.size, 0,
        `Inline handlers call functions that do not exist, so the button throws on click:\n  ${list(undefinedHandlers)}`);
});

test('nothing in the UI baseline has disappeared', () => {
    const baseline = JSON.parse(fs.readFileSync(BASELINE, 'utf8'));
    const current = toPlain(collect());
    const missing = [];
    for (const kind of Object.keys(baseline)) {
        const have = new Set(current[kind]);
        for (const item of baseline[kind]) if (!have.has(item)) missing.push(`${kind}: ${item}`);
    }
    assert.deepEqual(missing, [],
        'These pages, modals, actions, handlers, API calls, form fields, drop-down options or settings ' +
        'existed before and are gone now. ' +
        'If the removal is intentional, run: node .github/scripts/ui-inventory.cjs --write-baseline');
});

test('the handler check catches a button whose function was removed', () => {
    // Same shape as the "Run Check for this Host" bug fixed in #101.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ui-inventory-'));
    try {
        fs.writeFileSync(path.join(dir, 'router.js'), "const VALID_ROUTES = [\n    'status'\n];\n");
        fs.writeFileSync(path.join(dir, 'index.html'), '<div id="help-modal"></div>');
        fs.writeFileSync(path.join(dir, 'app.js'), [
            'function renderHost(host) {',
            '    return `<button onclick="checkHost(\'${host}\')">Run Check for this Host</button>`;',
            '}',
            '// A comment mentioning onclick="documentedOnly()" is not code.',
            'const ok = `<button onclick="event.stopPropagation(); renderHost(\'x\')">ok</button>`;',
        ].join('\n'));
        const { undefinedHandlers, actions } = collect(dir);
        assert.deepEqual([...undefinedHandlers.keys()], ['checkHost']);
        assert.ok(actions.has('renderHost:x'), 'actions are keyed by function and literal argument');
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test('form fields, drop-down options and settings are inventoried', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ui-inventory-'));
    try {
        fs.writeFileSync(path.join(dir, 'router.js'), "const VALID_ROUTES = [\n    'settings'\n];\n");
        fs.writeFileSync(path.join(dir, 'index.html'), [
            '<select id="filter-status"><option value="">All</option><option value="sent">Sent</option></select>',
            '<input type="text" id="filter-search">',
        ].join('\n'));
        fs.writeFileSync(path.join(dir, 'settings.js'), [
            "const TABS = [{ id: 'smtp', groups: [{ label: 'Server', keys: ['smtp_host', 'smtp_port'] }] }];",
            'const SETTINGS_FIELD_OPTIONS = {',
            "    webhook_type: [{ value: 'slack', label: 'Slack' }]",
            '};',
            "const a = '<input id=\"edit-' + key + '\">';",
            'const b = `<textarea id="notes-${n}"></textarea><textarea id="rule-notes"></textarea>`;',
        ].join('\n'));
        const plain = toPlain(collect(dir));
        assert.deepEqual(plain.controls, ['filter-search', 'filter-status', 'rule-notes'],
            'ids built at runtime are skipped');
        assert.deepEqual(plain.options, ['filter-status=', 'filter-status=sent', 'setting:webhook_type=slack']);
        assert.deepEqual(plain.settings, ['smtp_host', 'smtp_port']);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});
