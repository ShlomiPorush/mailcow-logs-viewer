const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../../frontend/dmarc.js'), 'utf8');
const start = source.indexOf('const reportsManagementState =');
const end = source.length;
assert.ok(start > 0 && end > start);

// What GET /api/dmarc/reports/domains answers in these tests
const DOMAINS = [
    { domain: 'example.com', dmarc_reports: 3, tls_reports: 1, last_report: 1767225600 },
    { domain: 'example.net', dmarc_reports: 1, tls_reports: 0, last_report: 1767312000 },
];

function harness({ allowDelete = true, confirm = true } = {}) {
    const elements = {};
    const element = id => elements[id] || (elements[id] = { innerHTML: '', value: '' });
    const content = element('dmarc-reports-management-content');
    const classes = new Set(['hidden']);
    const modal = { classList: {
        add: value => classes.add(value), remove: value => classes.delete(value),
        contains: value => classes.has(value)
    } };
    const requests = [];
    const calls = { confirms: [], toasts: [], domainsList: 0, manageButton: 0 };
    const summary = () => Promise.resolve({ ok: true, status: 200,
        json: async () => ({ domains: DOMAINS.slice(calls.summaries++ ? 1 : 0), allow_delete: allowDelete }) });
    calls.summaries = 0;
    const context = vm.createContext({
        document: { getElementById: id => id.endsWith('-modal') ? modal : element(id) },
        authenticatedFetch: (url, options) => url === '/api/dmarc/reports/domains' ? summary()
            : new Promise(resolve => requests.push({ url, options, resolve })),
        escapeHtml: value => value, escapeJsArg: value => value, encodeURIComponent,
        console: { error() {} }, showToast: (...args) => calls.toasts.push(args),
        showConfirmModal: async options => { calls.confirms.push(options); return confirm; },
        uiLocked: title => `<locked>${title}</locked>`,
        dmarcState: { currentView: 'reports' },
        dmarcGet: async () => ({ domains: [] }),
        dmarcUpdateManageButton: () => { calls.manageButton++; },
        loadDmarcDomains: async () => { calls.domainsList++; },
    });
    vm.runInContext(source.slice(start, end), context);
    const run = expression => vm.runInContext(expression, context);
    function resolve(index, page = 1, status = 200) {
        requests[index].resolve({ ok: status === 200, status, json: async () => ({
            reports: [{ id: page, type: 'dmarc', domain: 'example.com', record_count: 0 }],
            page, total_pages: 3, total: 101, allow_delete: true
        }) });
    }
    return { run, resolve, requests, content, modal, element, calls, context };
}

test('requests one page and renders the total with boundary controls', async () => {
    const h = harness();
    const pending = h.run('showReportsManagementModal()');
    assert.equal(h.requests[0].url, '/api/dmarc/reports/all?page=1&limit=50');
    h.resolve(0);
    await pending;
    assert.match(h.content.innerHTML, />101<\/span> reports/);
    assert.match(h.content.innerHTML, /Page 1 of 3/);
    assert.match(h.content.innerHTML, /loadReportsManagementPage\(0\)" disabled/);
});

test('late responses cannot replace a newer page or a closed dialog', async () => {
    const h = harness();
    const old = h.run('loadReportsManagementPage(1)');
    const current = h.run('loadReportsManagementPage(2)');
    h.resolve(1, 2);
    await current;
    h.resolve(0, 1);
    await old;
    assert.match(h.content.innerHTML, /Page 2 of 3/);
    const closing = h.run('loadReportsManagementPage(3)');
    h.run('closeReportsManagementModal()');
    h.resolve(2, 3);
    await closing;
    assert.doesNotMatch(h.content.innerHTML, /Page 3 of 3/);
});

test('request errors offer a retry for the requested page', async () => {
    const h = harness();
    const pending = h.run('loadReportsManagementPage(2)');
    h.resolve(0, 2, 503);
    await pending;
    assert.match(h.content.innerHTML, /Failed to load reports/);
    assert.match(h.content.innerHTML, /loadReportsManagementPage\(2\)/);
});

test('deleting a report reloads the current page and accepts server clamping', async () => {
    const h = harness();
    const opening = h.run('showReportsManagementModal()');
    h.resolve(0, 3);
    await opening;
    const deleting = h.run("deleteReport('dmarc', 3, 'example.com')");
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(h.requests[1].url, '/api/dmarc/reports/dmarc/3');
    h.resolve(1);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(h.requests[2].url, '/api/dmarc/reports/all?page=3&limit=50');
    h.resolve(2, 2);
    await deleting;
    assert.match(h.content.innerHTML, /Page 2 of 3/);
});

const tick = () => new Promise(resolve => setImmediate(resolve));

test('the dialog lists the reports by domain with Delete all and a search', async () => {
    const h = harness();
    const opening = h.run('showReportsManagementModal()');
    h.resolve(0);
    await opening;
    const table = h.element('dmarc-reports-domains-table').innerHTML;
    assert.match(table, /example\.com<\/b>/);
    assert.match(table, /data-sort="3"><small class="ui-sec-unit">DMARC <\/small>3/);
    assert.match(table, /data-sort="1767225600"/);
    assert.match(table, /deleteDomainReports\('example\.net'\)/);
    assert.equal(h.element('dmarc-reports-domains-count').textContent, '2 domains');
    h.element('dmarc-reports-domains-search').value = 'NET';
    h.run('filterReportsDomains()');
    assert.doesNotMatch(h.element('dmarc-reports-domains-table').innerHTML, /example\.com/);
    assert.equal(h.element('dmarc-reports-domains-count').textContent, '1 domain');
    h.element('dmarc-reports-domains-search').value = 'nothing';
    h.run('filterReportsDomains()');
    assert.match(h.element('dmarc-reports-domains-table').innerHTML, /No domains found matching "nothing"/);
});

test('with deletion off there is no Delete all and the dialog says why', async () => {
    const h = harness({ allowDelete: false });
    const opening = h.run('showReportsManagementModal()');
    h.resolve(0);
    await opening;
    assert.match(h.element('dmarc-reports-domains').innerHTML, /<locked>Deleting reports is off<\/locked>/);
    assert.doesNotMatch(h.element('dmarc-reports-domains-table').innerHTML, /deleteDomainReports|Actions/);
});

test('Delete all names the domain and the counts, then reloads everything', async () => {
    const h = harness();
    const opening = h.run('showReportsManagementModal()');
    h.resolve(0, 3);
    await opening;
    const deleting = h.run("deleteDomainReports('example.com')");
    await tick();
    const [confirm] = h.calls.confirms;
    assert.equal(confirm.isDangerous, true);
    assert.match(confirm.message, /example\.com/);
    assert.match(confirm.message, /3 DMARC reports and 1 TLS report\./);
    assert.match(confirm.message, /cannot be undone/);
    assert.equal(h.requests[1].url, '/api/dmarc/reports/domains/example.com');
    assert.equal(h.requests[1].options.method, 'DELETE');
    h.requests[1].resolve({ ok: true, status: 200, json: async () => ({ dmarc_reports: 3, tls_reports: 1 }) });
    await tick();
    assert.equal(h.requests[2].url, '/api/dmarc/reports/all?page=3&limit=50');
    h.resolve(2, 2);
    await deleting;
    assert.deepEqual(h.calls.toasts[0], ['Deleted 3 DMARC reports and 1 TLS report for example.com', 'success']);
    assert.match(h.content.innerHTML, /Page 2 of 3/);
    assert.doesNotMatch(h.element('dmarc-reports-domains-table').innerHTML, /example\.com/);
    assert.equal(h.calls.manageButton, 1);
    assert.equal(h.calls.domainsList, 0);
});

test('Delete all refreshes the domains list when it is the current view', async () => {
    const h = harness();
    h.run("dmarcState.currentView = 'domains'");
    const opening = h.run('showReportsManagementModal()');
    h.resolve(0);
    await opening;
    const deleting = h.run("deleteDomainReports('example.com')");
    await tick();
    h.requests[1].resolve({ ok: true, status: 200, json: async () => ({ dmarc_reports: 3, tls_reports: 1 }) });
    await tick();
    h.resolve(2);
    await deleting;
    assert.equal(h.calls.domainsList, 1);
});

test('a cancelled Delete all sends nothing', async () => {
    const h = harness({ confirm: false });
    const opening = h.run('showReportsManagementModal()');
    h.resolve(0);
    await opening;
    await h.run("deleteDomainReports('example.com')");
    assert.equal(h.requests.length, 1);
});
