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
        'These pages, modals, actions, handlers or API calls existed before and are gone now. ' +
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
