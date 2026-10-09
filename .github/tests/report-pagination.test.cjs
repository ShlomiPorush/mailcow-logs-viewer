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
        escapeHtml: value => value, escapeJsArg: value => value, encodeURIComponent, setTimeout, clearTimeout,
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
    function resolve(index, page = 1, status = 200, total = 101) {
        requests[index].resolve({ ok: status === 200, status, json: async () => ({
            reports: total ? [{ id: page, type: 'dmarc', domain: 'example.com', record_count: 0 }] : [],
            page, total_pages: Math.max(1, Math.ceil(total / 50)), total, allow_delete: true
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
    assert.match(h.element('dmarc-reports-total').innerHTML, /Total: <span class="ui-strong">101<\/span> reports/);
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

test('the dialog lists the reports by domain with Delete all', async () => {
    const h = harness();
    const opening = h.run('showReportsManagementModal()');
    h.resolve(0);
    await opening;
    const table = h.element('dmarc-reports-domains').innerHTML;
    assert.match(table, /example\.com<\/b>/);
    assert.match(table, /data-sort="3"><small class="ui-sec-unit">DMARC <\/small>3/);
    assert.match(table, /data-sort="1767225600"/);
    assert.match(table, /deleteDomainReports\('example\.net'\)/);
});

test('with deletion off there is no Delete all and the dialog says why', async () => {
    const h = harness({ allowDelete: false });
    const opening = h.run('showReportsManagementModal()');
    h.resolve(0);
    await opening;
    assert.match(h.element('dmarc-reports-domains').innerHTML, /<locked>Deleting reports is off<\/locked>/);
    assert.doesNotMatch(h.element('dmarc-reports-domains').innerHTML, /deleteDomainReports|Actions/);
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
    assert.doesNotMatch(h.element('dmarc-reports-domains').innerHTML, /example\.com/);
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

const debounce = () => new Promise(resolve => setTimeout(resolve, 350));

async function opened(h) {
    const opening = h.run('showReportsManagementModal()');
    h.resolve(0, 1);
    await opening;
}

test('the search filters All reports on the server from page 1, debounced', async () => {
    const h = harness();
    await opened(h);
    h.run('reportsManagementState.page = 2');
    for (const value of ['g', 'go', ' Google & Co ']) {
        h.element('dmarc-reports-search').value = value;
        h.run('searchReportsManagement()');
    }
    await debounce();
    assert.equal(h.requests.length, 2, 'one request for the burst of typing');
    assert.equal(h.requests[1].url, '/api/dmarc/reports/all?page=1&limit=50&search=Google%20%26%20Co');
    h.resolve(1, 1, 200, 7);
    await tick();
    assert.match(h.element('dmarc-reports-total').innerHTML, />7<\/span> matching reports/);
    // The summary is not filtered by the search
    assert.match(h.element('dmarc-reports-domains').innerHTML, /example\.net/);
});

test('a search with no matches says so', async () => {
    const h = harness();
    await opened(h);
    h.element('dmarc-reports-search').value = 'nothing';
    h.run('searchReportsManagement()');
    await debounce();
    h.resolve(1, 1, 200, 0);
    await tick();
    assert.match(h.content.innerHTML, /No reports match "nothing"/);
    assert.match(h.element('dmarc-reports-total').innerHTML, />0<\/span> matching reports/);
});

test('paging and a single delete keep the search', async () => {
    const h = harness();
    await opened(h);
    h.element('dmarc-reports-search').value = 'example';
    h.run('searchReportsManagement()');
    await debounce();
    h.resolve(1, 1, 200, 120);
    await tick();
    const paging = h.run('loadReportsManagementPage(3)');
    assert.equal(h.requests[2].url, '/api/dmarc/reports/all?page=3&limit=50&search=example');
    h.resolve(2, 3, 200, 120);
    await paging;
    const deleting = h.run("deleteReport('dmarc', 3, 'example.com')");
    await tick();
    assert.equal(h.requests[3].url, '/api/dmarc/reports/dmarc/3');
    h.resolve(3);
    await tick();
    assert.equal(h.requests[4].url, '/api/dmarc/reports/all?page=3&limit=50&search=example');
    h.resolve(4, 3, 200, 119);
    await deleting;
});

test('a late answer for an earlier search cannot replace the newer one', async () => {
    const h = harness();
    await opened(h);
    h.element('dmarc-reports-search').value = 'first';
    h.run('searchReportsManagement()');
    await debounce();
    h.element('dmarc-reports-search').value = 'second';
    h.run('searchReportsManagement()');
    await debounce();
    h.resolve(2, 1, 200, 0);
    await tick();
    h.resolve(1, 1, 200, 5);
    await tick();
    assert.match(h.content.innerHTML, /No reports match "second"/);
});

test('reopening the dialog clears the search', async () => {
    const h = harness();
    await opened(h);
    h.element('dmarc-reports-search').value = 'example';
    h.run('searchReportsManagement()');
    await debounce();
    h.resolve(1);
    await tick();
    h.run('closeReportsManagementModal()');
    const reopening = h.run('showReportsManagementModal()');
    assert.equal(h.element('dmarc-reports-search').value, '');
    assert.equal(h.requests[2].url, '/api/dmarc/reports/all?page=1&limit=50');
    h.resolve(2);
    await reopening;
});
