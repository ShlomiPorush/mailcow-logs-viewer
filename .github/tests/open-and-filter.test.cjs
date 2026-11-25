const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const read = name => fs.readFileSync(path.join(__dirname, '../../frontend', name), 'utf8');

test('the edit row of a limit hides and shows with the row it edits', () => {
    const context = vm.createContext({
        document: { addEventListener() {}, getElementById: () => null }, window: {}, setTimeout() {}, setInterval() {},
        escapeHtml: text => text, escapeJsArg: text => text, uiTag: text => text, uiEntity: (kind, name) => name, uiBadge: text => text, uiUnsavedRegister() {},
    });
    vm.runInContext(read('rate-limits.js'), context);
    context.renderRateLimitBadge = () => '';
    for (const [value, limited] of [[null, '0'], [5, '1']]) {
        vm.runInContext("rateLimitEditing = { kind: 'mailbox', name: 'user@example.com' }", context);
        const rows = context.renderRateLimitConfigRow('mailbox', 'user@example.com', value, 'h', true);
        assert.deepEqual([...rows.matchAll(/data-rl-limited="(\d)"/g)].map(m => m[1]), [limited, limited]);
        assert.match(rows, /data-rl-editrow/);
    }
});

for (const [already, loads] of [[false, 0], [true, 1]]) {
    test(`opening the events of an alert ${already ? 'on the Security page loads them once' : 'leaves the load to the page it opens'}`, async () => {
        const loaded = [];
        const timers = [];
        const context = vm.createContext({
            document: {
                addEventListener() {}, querySelector: () => null,
                getElementById: id => (id === 'content-netfilter' ? { classList: { contains: () => !already } } : { value: '' }),
            },
            window: {}, setTimeout: fn => timers.push(fn), currentPage: {}, console,
            setNetfilterFilters(filters) { context.filters = filters; },
            navigateTo: async () => true,
            loadNetfilterLogs: page => loaded.push(page),
            applyNetfilterFilters: () => loaded.push('filters'),
        });
        vm.runInContext(read('alert-activity.js'), context);
        await context.openAlertSecurityEvents('user@example.com');
        await Promise.resolve();
        timers.forEach(run => run());
        assert.equal(loaded.length, loads);
        assert.equal(context.filters.username, 'user@example.com');
    });
}
