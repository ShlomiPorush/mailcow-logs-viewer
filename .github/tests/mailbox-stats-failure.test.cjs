const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');
const FAILED = { error: 'Unable to load mailbox statistics.' };
const SUMMARY = { total_sent: 5, total_received: 6, sent_failed: 0, failure_rate: 0 };
const LIST = { total: 1, total_pages: 1, page: 1, mailboxes: [{ username: 'user@example.com' }] };

function element(id) {
    const classes = new Set();
    return {
        id, innerHTML: '', textContent: '', value: '', options: [],
        classList: { add: c => classes.add(c), remove: c => classes.delete(c), contains: c => classes.has(c) },
        appendChild() {}, querySelector: () => null, querySelectorAll: () => [],
    };
}

function load(answers) {
    const elements = {};
    const drawn = [];
    const context = vm.createContext({
        document: {
            getElementById: id => (elements[id] = elements[id] || element(id)),
            createElement: element, addEventListener() {}, querySelectorAll: () => [],
        },
        window: { disabledFeatures: [] }, console: { log() {}, error() {} }, setTimeout() {}, setInterval() {},
        localStorage: { getItem: () => null, setItem() {} }, PAGE_REFRESH_TIMEOUT: 1, encodeURIComponent,
        uiLoadingShow() {}, uiFilterBarSync() {}, uiTextHeld: () => false, uiAgo() {}, uiErrorText: e => e.message,
        escapeHtml: text => text, uiCountLabel: count => `${count} mailboxes`, responseError: async () => new Error('http'),
        uiKeepRowInView: (list, row, key, draw) => draw(), uiKeepFocus: (list, key, draw) => draw(),
    });
    vm.runInContext(fs.readFileSync(path.join(frontend, 'mailbox-stats.js'), 'utf8'), context);
    context.renderMailboxStatsAccordion = mailboxes => drawn.push(mailboxes);
    context.authenticatedFetch = async url => {
        const key = Object.keys(answers).find(name => url.startsWith(`/api/mailbox-stats/${name}`));
        return { ok: true, json: async () => answers[key] };
    };
    return { context, elements, drawn };
}

const good = () => ({ summary: SUMMARY, domains: { domains: [] }, all: LIST });

for (const part of ['summary', 'domains']) {
    test(`a failed read of the ${part} shows the failure, not zeros`, async () => {
        const { context, elements } = load({ ...good(), [part]: FAILED });
        await context.loadMailboxStats();
        assert.match(elements['mailbox-stats-loading'].innerHTML, /Unable to load mailbox statistics/);
        assert.equal(elements['mailbox-stats-sent']?.textContent || '', '');
    });
}

for (const part of ['summary', 'domains', 'all']) {
    test(`a refresh whose ${part} could not be read keeps what is shown`, async () => {
        const answers = good();
        const { context, elements, drawn } = load(answers);
        await context.loadMailboxStats();
        assert.equal(elements['mailbox-stats-sent'].textContent, '5');
        assert.equal(drawn.length, 1);
        answers[part] = FAILED;
        await context.refreshMailboxStats();
        assert.equal(elements['mailbox-stats-sent'].textContent, '5');
        assert.equal(elements['mailbox-stats-count'].textContent, '1 mailboxes');
        assert.equal(drawn.length, 1);
    });
}

test('a list that could not be read is not drawn as empty', async () => {
    const { context, drawn } = load({ ...good(), all: { ...FAILED, total: 0, mailboxes: [] } });
    await context.loadMailboxStats();
    assert.deepEqual(drawn, []);
});

test('the global search treats a failed mailbox read as a failure', async () => {
    const { context } = load(good());
    vm.runInContext(fs.readFileSync(path.join(frontend, 'search.js'), 'utf8'), Object.assign(context, {
        navigator: {}, location: {}, GS_LIMIT: 5, requestAnimationFrame() {},
    }));
    context.gsJson = async () => ({ ...FAILED, total: 0, mailboxes: [] });
    await assert.rejects(context.gsSearchMailboxes('user'), /Unable to load/);
});
