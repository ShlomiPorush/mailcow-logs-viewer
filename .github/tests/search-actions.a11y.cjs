// The actions in the top-bar search (search.js) in a real DOM (jsdom) over the
// whole page (index.html with its scripts): a result row for an IP address has
// Card, Ban and Allow, a mailbox and a domain Card, a background job Run; one
// valid IP that matches nothing still gets its row; a network, a list or text that
// is not one IP gets no Ban or Allow; Ban and Allow go through their confirmation
// and are not offered without the Read-Write key; Run asks first, names the job and
// what it does, and keeps the checks for a job that is off or already running;
// Enter opens a card or a job, Right goes into the row's buttons, Left and Escape
// back; on a phone a "..." row menu holds the same. The results are a grid that
// axe accepts.
//   A11Y_MODULES=/tmp/a11y/node_modules node --test .github/tests/search-actions.a11y.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));
const axeSource = fs.readFileSync(path.join(modules, 'axe-core', 'axe.min.js'), 'utf8');

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');
const BODY = read('index.html').split('<body')[1].replace(/^[^>]*>/, '').split('</body>')[0].replace(/<script[\s\S]*?<\/script>/g, '');
const SCRIPTS = [...read('index.html').matchAll(/src="\/static\/([a-z_-]+\.js)/g)].map(m => m[1]).filter(name => name !== 'session-guard.js');

const ago = minutes => new Date(Date.now() - minutes * 60000).toISOString();
// The server's background_jobs (GET /api/settings/info), as many states as the search tells apart
const JOBS = {
    dmarc_imap_sync: { interval: '3600 seconds (60 minutes)', description: 'Imports DMARC and TLS reports from an IMAP mailbox', status: 'success', last_run: ago(12) },
    blacklist_check: { interval: '6 hours', description: 'Checks monitored hosts against DNS blacklists', status: 'running', last_run: ago(180) },
    mailbox_stats: { interval: 'Disabled (feature off)', description: 'Fetches mailbox statistics from mailcow API', status: 'disabled', feature_disabled: true },
    fetch_logs: { interval: '60 seconds', description: 'Imports logs from mailcow API', status: 'success', last_run: ago(1) },
    // Reported by the server, unknown to the page (not in the manual-run map): never offered
    mystery_job: { interval: '1 hour', description: 'Does a mystery thing', status: 'success', last_run: ago(5) },
};

// The server: each request is kept; reply(url, method, body) answers it
const STUBS = `
    window.requests = [];
    window.navs = [];
    window.cards = [];
    window.reply = () => ({});
    authenticatedFetch = (url, options = {}) => {
        const request = { url, method: (options.method || 'GET').toUpperCase(), body: options.body, signal: options.signal };
        window.requests.push(request);
        return Promise.resolve(window.reply(url, request.method, options.body)).then(body => {
            const status = body && body.__status ? body.__status : 200;
            return { ok: status < 400, status, headers: { get: () => 'application/json' }, json: async () => body };
        });
    };
    navigateTo = async (...args) => { window.navs.push(args); return true; };
    checkAuthentication = async () => false;
    mailcowRwConfigured = true;`;

function page({ phone = false } = {}) {
    const dom = new JSDOM(`<!doctype html><html lang="en"><head><title>t</title><style>.hidden { display: none; }</style></head><body>${BODY}</body></html>`,
        { runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/dashboard' });
    const w = dom.window;
    w.Element.prototype.getClientRects = function () { return this.isConnected && !this.closest('.hidden') ? [{}] : []; };
    w.Element.prototype.scrollIntoView = function () {};
    w.matchMedia = query => ({ matches: phone && /max-width:\s*760px/.test(query), addEventListener() {}, removeEventListener() {} });
    w.HTMLElement.prototype.hidePopover = function () {};
    w.HTMLElement.prototype.showPopover = function () {};
    const errors = [];
    w.addEventListener('error', e => errors.push(e.error || e.message));
    const run = source => { const s = w.document.createElement('script'); s.textContent = source; w.document.head.appendChild(s); };
    SCRIPTS.forEach(name => run(read(name)));
    run(STUBS);
    assert.deepEqual(errors, [], 'the scripts load');
    w.reply = server();
    return w;
}

// GET /api/entities/ip as the card reads it: every source read, nothing in them,
// over the default 7 days (sources: what to change)
const RANGE = { start: '2026-10-21T12:00:00Z', end: '2026-10-28T12:00:00Z' };
function ipEntity(value, sources = {}) {
    const ok = extra => ({ state: 'ok', reason: null, ...extra });
    return { kind: 'ip', value, display: value, range: RANGE, sources: {
        messages: ok({ count: 0, items: [] }), security: ok({ events: 0, rule_matches: 0, bans: 0, unbans: 0, items: [] }),
        lists: ok({ allowlisted_as: null, denylisted_as: null, ban: null }), protection: ok({ count: 0, open: 0, items: [] }),
        devices: ok({ count: 0, items: [] }), dmarc: ok({ messages: 0, reports: 0, domains: 0, by_domain: [], records: [] }),
        rbl: ok({ checked: false, monitored: false }), geo: { state: 'disabled', reason: 'No MaxMind key' }, ...sources },
        timeline: { items: [], truncated: false, left_out: [] } };
}

// The answers of a mailcow with one address on the review list and a few mailboxes, domains and jobs
function server({ addresses = [{ ip: '203.0.113.45', state: 'review', country: 'Netherlands', attempts: 38, last_seen: ago(24) }], jobs = JOBS,
    entity = value => ipEntity(value) } = {}) {
    return (url, method) => {
        if (url.startsWith('/api/entities/ip')) return entity(new URL(url, 'http://localhost').searchParams.get('value'));
        if (url.startsWith('/api/security/addresses')) {
            const banned = url.includes('list=banned');
            const items = addresses.filter(a => (a.state === 'banned') === banned);
            return { items, counts: { review: addresses.filter(a => a.state !== 'banned').length, banned: addresses.filter(a => a.state === 'banned').length } };
        }
        if (url.startsWith('/api/settings/info')) return { background_jobs: jobs };
        if (url.startsWith('/api/mailbox-stats/all')) {
            const q = new URL(url, 'http://localhost').searchParams.get('search');
            const all = [{ username: 'j.doe@example.net', name: 'J. Doe' }, { username: 'ann@example.com', name: 'Ann' }];
            const found = all.filter(m => m.username.includes(q));
            return { total: found.length, mailboxes: found };
        }
        if (url.startsWith('/api/domains/all')) return { domains: [{ domain_name: 'example.net', mboxes_in_domain: 3 }] };
        if (url.startsWith('/api/messages')) return { total: 0, data: [] };
        if (url.startsWith('/api/suppressions/config')) return { list_kept: false };
        if (url.startsWith('/api/fail2ban/') && method === 'POST') return { status: 'success' };
        if (url.startsWith('/api/settings/jobs/') && method === 'POST') return { status: 'started' };
        return {};
    };
}

const tick = w => new Promise(resolve => w.setTimeout(resolve, 0));
const settle = async (w, n = 8) => { for (let i = 0; i < n; i++) await tick(w); };
const wait = (w, ms) => new Promise(resolve => w.setTimeout(resolve, ms));
const $ = (w, s) => w.document.querySelector(s);
const input = w => $(w, '#ui-gs-input');
const asked = (w, part, method = 'GET') => w.requests.filter(r => r.url.includes(part) && r.method === method);

async function search(w, text) {
    await settle(w, 2);
    const field = input(w);
    field.focus();
    field.value = text;
    field.dispatchEvent(new w.Event('input', { bubbles: true }));
    await wait(w, 260);
    await settle(w);
}

const rows = w => [...w.document.querySelectorAll('#ui-gs-panel .ui-gs-row')];
const titleOf = row => row.querySelector('.ui-gs-item b').textContent;
const rowOf = (w, title) => rows(w).find(r => titleOf(r) === title);
const buttons = row => [...row.querySelectorAll('.ui-gs-acts > .ui-btn')].map(b => b.textContent.trim() + (b.disabled ? ' (unavailable)' : ''));
const menuItems = row => [...row.querySelectorAll('.ui-gs-acts .ui-menu [role="menuitem"]')].map(b => b.textContent.trim() + (b.classList.contains('ui-text-fail') ? ' (red)' : ''));
const groups = w => [...w.document.querySelectorAll('#ui-gs-panel .ui-gs-sec > span:first-child')].map(s => s.textContent);
const keyHint = w => $(w, '#ui-gs-panel .ui-gs-keys').textContent.replace(/\s+/g, ' ').trim();
const key = (w, el, name, extra = {}) => el.dispatchEvent(new w.KeyboardEvent('keydown', { key: name, bubbles: true, cancelable: true, ...extra }));
const confirmShown = w => $(w, '#app-confirm-modal');
const confirmText = w => `${$(w, '#app-confirm-modal h3, #app-confirm-modal .ui-dialog-head').textContent.trim()} | ${$(w, '#app-confirm-modal .ui-confirm-text').textContent.trim()}`;
async function answer(w, ok) {
    await settle(w);
    assert.ok(confirmShown(w), 'a confirmation is asked');
    $(w, ok ? '#app-confirm-ok' : '#app-confirm-cancel').click();
    await settle(w, 12);
}
const toast = w => ($(w, '#toast-notification') || { textContent: '' }).textContent.replace(/\s+/g, ' ').trim();

// --------------------------------------------------------------- what each row offers

test('each kind of row offers its buttons: IP Card, Ban and Allow, mailbox and domain Card, job Run', async () => {
    const w = page();
    await search(w, '203.0.113.45');
    const ip = rowOf(w, '203.0.113.45');
    assert.deepEqual(buttons(ip), ['Card', 'Ban', 'Allow']);
    assert.ok(ip.querySelector('[data-gs-act="ban"]').classList.contains('ui-btn-danger'), 'Ban in red text, as on the Security rows');
    assert.equal(ip.querySelector('[data-gs-act="ban"]').getAttribute('aria-label'), 'Ban 203.0.113.45');
    assert.equal(ip.querySelector('[data-gs-act="ban"]').title, 'Put 203.0.113.45/32 on the Fail2ban denylist; it stays until removed');
    // Reached with the arrows, not with Tab (Tab switches the kind)
    assert.ok([...ip.querySelectorAll('.ui-gs-acts > button')].every(b => b.tabIndex === -1));
    // No value in a handler: the row's index says which result
    assert.doesNotMatch($(w, '#ui-gs-panel').innerHTML, /onclick="[^"]*203\.0\.113\.45/);
    assert.equal(groups(w)[0], 'IP addresses · 1', 'the kind typed comes first');
    assert.ok(ip.classList.contains('is-active'), 'its row is the active one');
    assert.match(keyHint(w), /Enter open card/);

    await search(w, 'j.doe');
    assert.deepEqual(buttons(rowOf(w, 'j.doe@example.net')), ['Card']);
    assert.match(keyHint(w), /Enter open card/);

    await search(w, 'example.net');
    assert.deepEqual(buttons(rowOf(w, 'example.net')), ['Card']);

    await search(w, 'imap import');
    assert.deepEqual(buttons(rowOf(w, 'DMARC & TLS IMAP Import')), ['Run']);
    assert.match(keyHint(w), /Enter open job/);
});

test('Background jobs is a kind of its own: name, last run and schedule, first for "run"', async () => {
    const w = page();
    await search(w, 'run');
    assert.equal(groups(w)[0], 'Background jobs · 4');
    assert.equal($(w, '#ui-gs-panel .ui-gs-tab:nth-child(2)').firstChild.textContent, 'Background jobs');
    const sub = title => rowOf(w, title).querySelector('.ui-gs-item small').textContent;
    assert.equal(sub('DMARC & TLS IMAP Import'), 'Last run 12 min ago, finished · Every 3600 seconds (60 minutes)');
    assert.equal(sub('Fetch Logs'), 'Last run 1 min ago, finished · Every 60 seconds');
    // The tab lists them all, in the Status page's order
    w.gsSetTab('jobs');
    await settle(w);
    assert.deepEqual(Array.from(rows(w), titleOf), ['Fetch Logs', 'Mailbox Statistics', 'DMARC & TLS IMAP Import', 'IP Blacklist Check (All Hosts)']);
    assert.equal(sub('IP Blacklist Check (All Hosts)'), 'Running now · Every 6 hours');
    assert.equal($(w, '#ui-gs-panel .ui-gs-more').textContent.replace(/\s+/g, ' ').trim(), '4 foundOpen in Status');
    assert.equal(sub('Mailbox Statistics'), 'Off: its feature is turned off in Settings');
});

test('a job the page does not know (not in the manual-run map) is not offered', async () => {
    const w = page();
    await search(w, 'mystery');
    assert.equal(rowOf(w, 'mystery_job'), undefined);
    assert.ok(!rows(w).some(r => /mystery/i.test(r.textContent)));
    await search(w, 'jobs');
    assert.ok(!rows(w).some(r => /mystery/i.test(r.textContent)));
});

// --------------------------------------------------------------- the values typed

test('one valid IP that matches nothing gets one row with its buttons, and what its card holds', async () => {
    const w = page();
    w.reply = server({ addresses: [] });
    await search(w, '198.51.100.200');
    assert.deepEqual(groups(w), ['IP addresses · 1']);
    const row = rowOf(w, '198.51.100.200');
    assert.equal(row.querySelector('.ui-gs-item small').textContent, 'No activity in the last 7 days');
    assert.deepEqual(buttons(row), ['Card', 'Ban', 'Allow']);
    // An IPv6 address too
    await search(w, '2001:db8::7');
    assert.deepEqual(buttons(rowOf(w, '2001:db8::7')), ['Card', 'Ban', 'Allow']);
    // A longer address that holds the typed one does not stand for it
    w.reply = server({ addresses: [{ ip: '198.51.100.20', state: 'review', attempts: 2, last_seen: ago(3) }] });
    await search(w, '198.51.100.2');
    assert.deepEqual(rows(w).filter(r => r.closest('#ui-gs-panel')).map(titleOf).slice(0, 2), ['198.51.100.2', '198.51.100.20']);
    assert.equal(rowOf(w, '198.51.100.2').querySelector('small').textContent, 'No activity in the last 7 days');
});

test('a network, a range, a list or text that is not one IP gets no Ban or Allow', async () => {
    const w = page();
    w.reply = server({ addresses: [{ ip: '198.51.100.0/24', state: 'banned', network_size: 256, attempts: 0, last_seen: ago(30) }] });
    await search(w, '198.51.100.0/24');
    const network = rowOf(w, '198.51.100.0/24');
    assert.ok(network, 'the network is found');
    assert.equal(network.querySelector('.ui-gs-acts'), null, 'a network row has no buttons');
    for (const typed of ['198.51.100.0/24', '198.51.100.1-198.51.100.9', '198.51.100.1,198.51.100.2', '999.1.2.3', '203.0.113.045', 'fe80::1%eth0', '203.0.113.']) {
        w.reply = server({ addresses: [] });
        await search(w, typed);
        assert.equal(w.document.querySelector('#ui-gs-panel [data-gs-act="ban"]'), null, `${typed} offers Ban`);
        assert.equal(w.document.querySelector('#ui-gs-panel [data-gs-act="allow"]'), null, `${typed} offers Allow`);
    }
});

// --------------------------------------------------------------- Ban and Allow

test('Ban and Allow ask first: Cancel writes nothing, the answer posts the single address', async () => {
    const w = page();
    await search(w, '203.0.113.45');
    rowOf(w, '203.0.113.45').querySelector('[data-gs-act="ban"]').click();
    await answer(w, false);
    assert.equal(asked(w, '/api/fail2ban/', 'POST').length, 0, 'Cancel bans nothing');
    assert.ok($(w, '#ui-gs').classList.contains('is-open'), 'the search stays');

    rowOf(w, '203.0.113.45').querySelector('[data-gs-act="ban"]').click();
    await settle(w);
    assert.match(confirmText(w), /^Ban IP \| Are you sure you want to permanently ban 203\.0\.113\.45\/32\?/);
    const before = asked(w, '/api/security/addresses').length;
    await answer(w, true);
    const bans = asked(w, '/api/fail2ban/ban', 'POST');
    assert.equal(bans.length, 1);
    assert.deepEqual(JSON.parse(bans[0].body), { ip: '203.0.113.45/32' });
    assert.ok(asked(w, '/api/security/addresses').length > before, 'the addresses are read again');
    assert.equal(w.document.activeElement, input(w), 'the keys are back in the field');

    rowOf(w, '203.0.113.45').querySelector('[data-gs-act="allow"]').click();
    await answer(w, false);
    assert.equal(asked(w, '/api/fail2ban/allow', 'POST').length, 0);
    rowOf(w, '203.0.113.45').querySelector('[data-gs-act="allow"]').click();
    await settle(w);
    assert.match(confirmText(w), /^Allow IP \| Add 203\.0\.113\.45\/32 to the Fail2Ban allowlist\?/);
    await answer(w, true);
    assert.deepEqual(JSON.parse(asked(w, '/api/fail2ban/allow', 'POST')[0].body), { ip: '203.0.113.45/32' });
});

test('without the Read-Write key Ban and Allow are not offered, on a desktop and in the phone menu', async () => {
    for (const phone of [false, true]) {
        const w = page({ phone });
        w.mailcowRwConfigured = false;
        w.eval('mailcowRwConfigured = false');
        await search(w, '203.0.113.45');
        const row = rowOf(w, '203.0.113.45');
        assert.deepEqual(buttons(row), ['Card']);
        // On a phone the row's tap opens the card: a menu with only that is left out
        assert.equal(row.querySelector('.ui-gs-dots'), null);
        // And no handler bans by another way
        w.gsAct(0, 'ban', null);
        await settle(w);
        assert.equal(confirmShown(w), null);
    }
});

// --------------------------------------------------------------- Run

test('Run asks first, naming the job and what it does; Cancel runs nothing, the answer runs it', async () => {
    const w = page();
    await search(w, 'imap import');
    const run = () => rowOf(w, 'DMARC & TLS IMAP Import').querySelector('[data-gs-act="run"]');
    run().click();
    await settle(w);
    assert.equal(confirmText(w), 'Run DMARC & TLS IMAP Import | DMARC & TLS IMAP Import runs once now, outside its schedule, and imports DMARC and TLS reports from an IMAP mailbox.');
    await answer(w, false);
    assert.equal(asked(w, '/api/settings/jobs/', 'POST').length, 0, 'Cancel runs nothing');

    const reads = asked(w, '/api/settings/info').length;
    run().click();
    await answer(w, true);
    assert.deepEqual(Array.from(asked(w, '/api/settings/jobs/', 'POST'), r => r.url), ['/api/settings/jobs/dmarc_imap_sync/run']);
    assert.match(toast(w), /Job "DMARC & TLS IMAP Import" started successfully/);
    assert.ok(asked(w, '/api/settings/info').length > reads, 'the jobs are read again, so the row shows it running');
});

test('a running job has Run unavailable, a job that is off has none, and the server still has the last word', async () => {
    const w = page();
    await search(w, 'run');
    w.gsSetTab('jobs');
    await settle(w);
    const running = rowOf(w, 'IP Blacklist Check (All Hosts)');
    assert.deepEqual(buttons(running), ['Run (unavailable)']);
    assert.equal(running.querySelector('[data-gs-act="run"]').title, 'Job is running');
    // Even when asked to, it does not ask or post
    w.gsAct(Number(running.dataset.gsIndex), 'run', null);
    await settle(w);
    assert.equal(confirmShown(w), null);
    assert.deepEqual(buttons(rowOf(w, 'Mailbox Statistics')), [], 'a job that is off has no Run');

    // Started meanwhile by its schedule: the server says so after the answer
    w.reply = (url, method) => (url.includes('/api/settings/jobs/') && method === 'POST'
        ? { __status: 409, detail: 'Job fetch_logs is already running' } : server()(url, method));
    rowOf(w, 'Fetch Logs').querySelector('[data-gs-act="run"]').click();
    await answer(w, true);
    assert.match(toast(w), /Job "Fetch Logs" is already running/);

    // Turned off meanwhile: the server's reason
    w.reply = (url, method) => (url.includes('/api/settings/jobs/') && method === 'POST'
        ? { __status: 409, detail: 'The job cannot run. Its feature is turned off.' } : server()(url, method));
    rowOf(w, 'Fetch Logs').querySelector('[data-gs-act="run"]').click();
    await answer(w, true);
    assert.match(toast(w), /Job "Fetch Logs" cannot run now\. Its feature is turned off\./);
});

test('the run itself needs no button, and the Status page button still shows it running', async () => {
    const w = page();
    let release;
    w.reply = (url, method) => (method === 'POST' ? new Promise(resolve => { release = () => resolve({ status: 'started' }); }) : {});
    assert.equal(await (async () => { const p = w.runBackgroundJob('fetch_logs', 'Fetch Logs'); release(); return p; })(), 'started');
    const button = w.document.createElement('button');
    button.textContent = 'Run';
    const pending = w.triggerBackgroundJob('fetch_logs', button, 'Fetch Logs');
    assert.equal(button.disabled, true);
    assert.match(button.textContent, /Running/);
    release();
    await pending;
    assert.equal(button.disabled, false);
    assert.equal(button.textContent, 'Run');
});

// --------------------------------------------------------------- keyboard

test('Enter opens the card of an entity row and a job on Status > Jobs', async () => {
    const w = page();
    w.eval('openEntityCard = (kind, value) => window.cards.push([kind, value])');
    await search(w, '203.0.113.45');
    key(w, input(w), 'Enter');
    await settle(w);
    assert.deepEqual(JSON.parse(JSON.stringify(w.cards)), [['ip', '203.0.113.45']]);
    assert.ok($(w, '#ui-gs').classList.contains('is-open'), 'the search stays under the card');

    await search(w, 'j.doe');
    key(w, input(w), 'Enter');
    assert.deepEqual(JSON.parse(JSON.stringify(w.cards.at(-1))), ['address', 'j.doe@example.net']);

    await search(w, 'imap import');
    key(w, input(w), 'Enter');
    await settle(w);
    assert.deepEqual(JSON.parse(JSON.stringify(w.navs.at(-1))), ['status', { sub: 'jobs' }]);
    assert.ok(!$(w, '#ui-gs').classList.contains('is-open'), 'the search closes for the page');
});

test('Status > Jobs rows carry their job, so the search can open one', () => {
    const w = page();
    w.renderStatusJobs(JOBS);
    assert.ok($(w, '#status-jobs .ui-jobrow[data-job="dmarc_imap_sync"]'));
    assert.equal($(w, '#status-jobs .ui-jobrow[data-job="fetch_logs"] .ui-jobrow-runs').textContent.trim(), '60 seconds');
});

test('Right from the end of the field goes into the buttons, Left and Escape come back', async () => {
    const w = page();
    await search(w, '203.0.113.45');
    const field = input(w);
    // Back in the field the results are drawn again: the row is read each time
    const act = name => rowOf(w, '203.0.113.45').querySelector(`[data-gs-act="${name}"]`);

    // The caret inside the text moves as usual
    field.setSelectionRange(3, 3);
    key(w, field, 'ArrowRight');
    assert.equal(w.document.activeElement, field);

    field.setSelectionRange(field.value.length, field.value.length);
    key(w, field, 'ArrowRight');
    assert.equal(w.document.activeElement, act('card'));
    key(w, w.document.activeElement, 'ArrowRight');
    assert.equal(w.document.activeElement, act('ban'));
    key(w, w.document.activeElement, 'ArrowRight');
    assert.equal(w.document.activeElement, act('allow'));
    key(w, w.document.activeElement, 'ArrowRight');
    assert.equal(w.document.activeElement, act('allow'), 'the last one stays');
    key(w, w.document.activeElement, 'ArrowLeft');
    assert.equal(w.document.activeElement, act('ban'));
    key(w, w.document.activeElement, 'Escape');
    assert.equal(w.document.activeElement, field, 'Escape goes back to the field');
    assert.ok($(w, '#ui-gs').classList.contains('is-open'), 'and leaves the search open');

    key(w, field, 'ArrowRight');
    key(w, w.document.activeElement, 'ArrowLeft');
    assert.equal(w.document.activeElement, field, 'Left past the first button is the field');

    // Enter on a button is that button
    key(w, field, 'ArrowRight');
    key(w, w.document.activeElement, 'ArrowRight');
    assert.equal(w.document.activeElement, act('ban'));
    w.document.activeElement.click();
    await answer(w, false);

    // Tab keeps switching the kind
    const tab = $(w, '#ui-gs-panel .ui-gs-tab.is-on').dataset.gsTab;
    key(w, field, 'Tab');
    assert.notEqual($(w, '#ui-gs-panel .ui-gs-tab.is-on').dataset.gsTab, tab);
});

test('a running job leaves Right in the field: nothing there to use', async () => {
    const w = page();
    await search(w, 'blacklist check');
    const field = input(w);
    field.setSelectionRange(field.value.length, field.value.length);
    key(w, field, 'ArrowRight');
    assert.equal(w.document.activeElement, field);
});

// --------------------------------------------------------------- phone

test('on a phone a tap opens the row and one "..." button opens its row menu', async () => {
    const w = page({ phone: true });
    w.eval('openEntityCard = (kind, value) => window.cards.push([kind, value])');
    await search(w, '203.0.113.45');
    assert.ok($(w, '#ui-gs').classList.contains('is-sheet'), 'the search covers the screen');
    const row = rowOf(w, '203.0.113.45');
    const dots = row.querySelector('.ui-gs-dots');
    assert.equal(dots.getAttribute('aria-label'), 'Actions for 203.0.113.45');
    assert.equal(dots.getAttribute('aria-haspopup'), 'menu');
    const menu = w.document.getElementById(dots.getAttribute('popovertarget'));
    assert.ok(menu && menu.classList.contains('ui-menu') && menu.hasAttribute('popover') && menu.getAttribute('role') === 'menu', 'the row menu is a popover');
    assert.deepEqual(menuItems(row), ['Open card', 'Ban (red)', 'Allow']);
    // The "..." button opens only its menu
    dots.click();
    await settle(w);
    assert.equal(w.cards.length, 0);
    // Ban from the menu asks first as well
    menu.querySelector('[data-gs-act="ban"]').click();
    await answer(w, true);
    assert.deepEqual(JSON.parse(asked(w, '/api/fail2ban/ban', 'POST')[0].body), { ip: '203.0.113.45/32' });
    // A tap on the row opens the card
    rowOf(w, '203.0.113.45').querySelector('.ui-gs-item').click();
    await settle(w);
    assert.deepEqual(JSON.parse(JSON.stringify(w.cards)), [['ip', '203.0.113.45']]);

    // A job row: Open job and Run; a mailbox row has no menu (its tap is all it offers)
    await search(w, 'imap import');
    assert.deepEqual(menuItems(rowOf(w, 'DMARC & TLS IMAP Import')), ['Open job', 'Run']);
    await search(w, 'j.doe');
    assert.equal(rowOf(w, 'j.doe@example.net').querySelector('.ui-gs-dots'), null);
});

// --------------------------------------------------------------- the card over the search

test('a card opened from the search: closed, the field again; moved to a page from it, the search closes', async () => {
    const w = page();
    const card = { kind: 'ip', value: '203.0.113.45', display: '203.0.113.45', range: { start: ago(10080), end: ago(0) },
        sources: { lists: { state: 'ok', allowlisted_as: null, denylisted_as: null } }, timeline: { items: [], truncated: false, left_out: [] } };
    const base = w.reply;
    w.reply = (url, method) => (url.startsWith('/api/entities/') ? card : base(url, method));
    await search(w, '203.0.113.45');
    rowOf(w, '203.0.113.45').querySelector('[data-gs-act="card"]').click();
    await settle(w);
    assert.ok(!$(w, '#entity-card').classList.contains('hidden'), 'the card is open');
    w.closeEntityCard();
    await settle(w);
    assert.ok($(w, '#ui-gs').classList.contains('is-open'));
    assert.equal(w.document.activeElement, input(w));

    rowOf(w, '203.0.113.45').querySelector('[data-gs-act="card"]').click();
    await settle(w);
    w.history.pushState({}, '', '/messages');
    w.closeEntityCard();
    await settle(w);
    assert.ok(!$(w, '#ui-gs').classList.contains('is-open'), 'the search is done once a page opened from the card');
});

// --------------------------------------------------------------- accessibility

test('the results are a grid axe accepts, with buttons in their rows', async () => {
    for (const phone of [false, true]) {
        const w = page({ phone });
        w.eval(axeSource);
        await search(w, '203.0.113.45');
        assert.equal($(w, '#ui-gs-panel .ui-gs-body').getAttribute('role'), 'grid');
        assert.equal(input(w).getAttribute('aria-activedescendant'), rowOf(w, '203.0.113.45').querySelector('[role="gridcell"]').id);
        for (const text of ['203.0.113.45', 'run', 'zzzz']) {
            await search(w, text);
            const result = await w.axe.run($(w, '#ui-gs'), { rules: { 'color-contrast': { enabled: false } } });
            assert.deepEqual(Array.from(result.violations, v => `${v.id}: ${v.nodes.map(n => n.target.join(' ')).join(', ')}`), [], `${text}${phone ? ' (phone)' : ''}`);
        }
    }
});

// --------------------------------------------------------------- review fixes

// A key as a browser presses it on the focused element: Enter clicks a button on
// keydown unless the keydown was cancelled; a held key repeats keydown with repeat set
function press(w, keyName, { repeat = false } = {}) {
    const el = w.document.activeElement;
    const ok = el.dispatchEvent(new w.KeyboardEvent('keydown', { key: keyName, repeat, bubbles: true, cancelable: true }));
    if (ok && keyName === 'Enter' && el.tagName === 'BUTTON' && !el.disabled) el.click();
}
function release(w, keyName) {
    const el = w.document.activeElement;
    const ok = el.dispatchEvent(new w.KeyboardEvent('keyup', { key: keyName, bubbles: true, cancelable: true }));
    if (ok && keyName === ' ' && el.tagName === 'BUTTON' && !el.disabled) el.click();
}
// Enter held down on a control: the press, repeats before and after the question
// takes the focus (it does after 100 ms), then the release
async function holdEnter(w) {
    press(w, 'Enter');
    await settle(w, 2);
    for (let i = 0; i < 3; i++) press(w, 'Enter', { repeat: true });
    await wait(w, 160);
    for (let i = 0; i < 6; i++) { press(w, 'Enter', { repeat: true }); await wait(w, 30); }
    release(w, 'Enter');
    await settle(w);
}

test('S1: Enter held on Ban, Allow or Run in the search opens the question and never answers it', async () => {
    for (const act of ['ban', 'allow']) {
        const w = page();
        await search(w, '203.0.113.45');
        const field = input(w);
        field.setSelectionRange(field.value.length, field.value.length);
        key(w, field, 'ArrowRight');
        while (w.document.activeElement.dataset.gsAct !== act) key(w, w.document.activeElement, 'ArrowRight');
        await holdEnter(w);
        assert.ok(confirmShown(w), `${act}: the question is open`);
        assert.equal(asked(w, '/api/fail2ban/', 'POST').length, 0, `${act}: nothing was written`);
        assert.equal(w.document.activeElement.id, 'app-confirm-cancel', `${act}: the question starts on Cancel`);
        // A new press on Cancel answers it: Cancel
        press(w, 'Enter');
        await settle(w, 12);
        assert.equal(confirmShown(w), null);
        assert.equal(asked(w, '/api/fail2ban/', 'POST').length, 0);
    }
    const w = page();
    await search(w, 'imap import');
    const field = input(w);
    field.setSelectionRange(field.value.length, field.value.length);
    key(w, field, 'ArrowRight');
    assert.equal(w.document.activeElement.dataset.gsAct, 'run');
    await holdEnter(w);
    assert.ok(confirmShown(w), 'Run: the question is open');
    assert.equal(asked(w, '/api/settings/jobs/', 'POST').length, 0, 'Run: nothing ran');
    assert.equal(w.document.activeElement.id, 'app-confirm-cancel');
    // A deliberate press on Run still runs it
    $(w, '#app-confirm-ok').focus();
    press(w, 'Enter');
    await settle(w, 12);
    assert.equal(asked(w, '/api/settings/jobs/', 'POST').length, 1);
});

test('S1: Enter held on the card\'s Ban (the same banIP) never answers its question either', async () => {
    const w = page();
    const base = w.reply;
    w.reply = (url, method) => (url.startsWith('/api/entities/') ? ipEntity('203.0.113.45') : base(url, method));
    w.openEntityCard('ip', '203.0.113.45');
    await settle(w);
    const ban = $(w, '#entity-card-actions [data-ent-act="ban"]');
    assert.ok(ban, 'the card offers Ban');
    ban.focus();
    await holdEnter(w);
    assert.ok(confirmShown(w));
    assert.equal(asked(w, '/api/fail2ban/', 'POST').length, 0);
    assert.equal(w.document.activeElement.id, 'app-confirm-cancel');
});

test('S1: any question ignores a held key; one that does not write still starts on its main button', async () => {
    const w = page();
    let answered = null;
    w.showConfirmModal({ title: 'Delete Message', message: 'Delete this message from the queue?', confirmText: 'Delete', isDangerous: true })
        .then(result => { answered = result; });
    // The key that went down before the question
    w.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Enter' }));
    await wait(w, 160);
    assert.equal(w.document.activeElement.id, 'app-confirm-ok', 'the default is unchanged');
    for (let i = 0; i < 5; i++) press(w, 'Enter', { repeat: true });
    await settle(w);
    assert.equal(answered, null, 'repeats do not answer');
    release(w, 'Enter');
    press(w, 'Enter');
    await settle(w);
    assert.equal(answered, true, 'a new press does');
});

test('S3: a typed address the lists do not hold says what its card holds, read exactly', async () => {
    const w = page();
    w.reply = server({ addresses: [] });
    await search(w, '198.51.100.200');
    const entityAsks = asked(w, '/api/entities/ip');
    assert.deepEqual(Array.from(entityAsks, r => r.url), ['/api/entities/ip?value=198.51.100.200'], 'one request, the value only (the card\'s own period)');
    assert.equal(rowOf(w, '198.51.100.200').querySelector('small').textContent, 'No activity in the last 7 days');

    // Activity kept for it: the counts, not "nothing"
    w.reply = server({ addresses: [], entity: v => ipEntity(v, {
        messages: { state: 'ok', count: 2, items: [] }, security: { state: 'ok', events: 3, rule_matches: 3, bans: 0, unbans: 0, items: [] } }) });
    await search(w, '198.51.100.201');
    assert.equal(rowOf(w, '198.51.100.201').querySelector('small').textContent, '2 messages · 3 security events in the last 7 days');

    // A source not read (off, failed) or a card that could not be read claims nothing
    for (const entity of [v => ipEntity(v, { dmarc: { state: 'disabled', reason: 'DMARC is turned off.' } }),
        v => ipEntity(v, { messages: { state: 'error', reason: 'The query failed.' } }),
        () => ({ __status: 500, detail: 'Internal error' })]) {
        w.reply = server({ addresses: [], entity });
        await search(w, '198.51.100.202');
        const row = rowOf(w, '198.51.100.202');
        assert.equal(row.querySelector('small').textContent, 'Not in these results');
        assert.deepEqual(buttons(row), ['Card', 'Ban', 'Allow'], 'the buttons stay');
    }

    // The value as the server writes it is what Ban sends; the row shows what was typed
    w.reply = server({ addresses: [], entity: () => ipEntity('198.51.100.7') });
    await search(w, '::ffff:198.51.100.7');
    rowOf(w, '::ffff:198.51.100.7').querySelector('[data-gs-act="ban"]').click();
    await answer(w, true);
    assert.deepEqual(JSON.parse(asked(w, '/api/fail2ban/ban', 'POST')[0].body), { ip: '198.51.100.7/32' });
});

test('S3: the card is asked once typing pauses, and an older ask is cancelled', async () => {
    const w = page();
    const held = [];
    const base = server({ addresses: [] });
    w.reply = (url, method) => (url.startsWith('/api/entities/ip')
        ? new Promise(resolve => held.push({ url, resolve })) : base(url, method));
    await settle(w, 2);
    const field = input(w);
    field.focus();
    for (const text of ['198.51.100.2', '198.51.100.20', '198.51.100.201']) {
        field.value = text;
        field.dispatchEvent(new w.Event('input', { bubbles: true }));
        await wait(w, 40);
    }
    await wait(w, 260);
    await settle(w);
    assert.deepEqual(held.map(h => h.url), ['/api/entities/ip?value=198.51.100.201'], 'only the value typed last');
    // Typed on: the ask on its way is cancelled and its late answer is dropped
    field.value = '198.51.100.9';
    field.dispatchEvent(new w.Event('input', { bubbles: true }));
    await wait(w, 260);
    await settle(w);
    const first = asked(w, '/api/entities/ip').find(r => r.url.endsWith('198.51.100.201'));
    assert.equal(first.signal.aborted, true);
    held[0].resolve(ipEntity('198.51.100.201', { messages: { state: 'ok', count: 9, items: [] } }));
    held[1].resolve(ipEntity('198.51.100.9'));
    await settle(w);
    assert.equal(rowOf(w, '198.51.100.201'), undefined);
    assert.equal(rowOf(w, '198.51.100.9').querySelector('small').textContent, 'No activity in the last 7 days');
});

test('S4: the field controls the grid itself, which keeps its id while its rows change', async () => {
    const w = page();
    await settle(w, 2);
    const grid = w.document.getElementById(input(w).getAttribute('aria-controls'));
    assert.ok(grid, 'aria-controls names an element from the start');
    assert.equal(grid.getAttribute('role'), 'grid');
    assert.equal(input(w).getAttribute('aria-haspopup'), 'grid');
    await search(w, '203.0.113.45');
    assert.equal(w.document.getElementById(input(w).getAttribute('aria-controls')), grid, 'the same grid');
    assert.ok(grid.contains(w.document.getElementById(input(w).getAttribute('aria-activedescendant'))), 'the active cell is in it');
    key(w, input(w), 'ArrowDown');
    assert.ok(grid.contains(w.document.getElementById(input(w).getAttribute('aria-activedescendant'))));
    await search(w, 'run');
    assert.equal(w.document.getElementById('ui-gs-grid'), grid);
});

test('S5: while an input method composes, and with a modifier, Right stays in the field', async () => {
    const w = page();
    w.eval('openEntityCard = (kind, value) => window.cards.push([kind, value])');
    await search(w, '203.0.113.45');
    const field = input(w);
    field.setSelectionRange(field.value.length, field.value.length);
    key(w, field, 'ArrowRight', { isComposing: true });
    assert.equal(w.document.activeElement, field, 'composing');
    const ime = new w.KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true, cancelable: true });
    Object.defineProperty(ime, 'keyCode', { value: 229 });
    field.dispatchEvent(ime);
    assert.equal(w.document.activeElement, field, 'keyCode 229');
    for (const mod of ['ctrlKey', 'metaKey', 'altKey', 'shiftKey']) {
        key(w, field, 'ArrowRight', { [mod]: true });
        assert.equal(w.document.activeElement, field, mod);
    }
    // Enter that ends a composition opens nothing
    key(w, field, 'Enter', { isComposing: true });
    await settle(w);
    assert.equal(w.cards.length, 0);
    // A plain Right still goes in
    key(w, field, 'ArrowRight');
    assert.equal(w.document.activeElement.dataset.gsAct, 'card');
});
