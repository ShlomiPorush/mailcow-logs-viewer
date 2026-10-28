// The entity card's actions (entity-card.js) in a real DOM (jsdom) over the whole
// page (index.html with app.js, security.js, mailbox-stats.js, spam_filter.js and
// export.js): Show messages and Show security events open their page with the
// value matched whole, the filter shows as a chip, holds through a facet change
// and reaches the CSV export; Ban and Allow go through their confirmation and are
// locked, not hidden, without the Read-Write key; Check now posts the address and
// force in the URL and shows its progress; Open mailbox finds the mailbox when
// Mailbox Stats never loaded and for an alias; an action whose source is off or
// does not apply is not offered.
//   A11Y_MODULES=/tmp/a11y/node_modules node --test .github/tests/entity-card-actions.a11y.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');
// The page as index.html has it, without its scripts (they are run below, in order)
const BODY = read('index.html').split('<body')[1].replace(/^[^>]*>/, '').split('</body>')[0].replace(/<script[\s\S]*?<\/script>/g, '');
// The page's own scripts, in its order (session-guard.js, which signs out, aside)
const SCRIPTS = [...read('index.html').matchAll(/src="\/static\/([a-z_-]+\.js)/g)].map(m => m[1]).filter(name => name !== 'session-guard.js');

// The server: each request is kept; reply(url, method) answers it (a promise is held until resolved)
const STUBS = `
    window.requests = [];
    window.navs = [];
    window.reply = () => ({});
    authenticatedFetch = (url, options = {}) => {
        const request = { url, method: (options.method || 'GET').toUpperCase(), body: options.body };
        window.requests.push(request);
        return Promise.resolve(window.reply(url, request.method)).then(body => {
            const status = body && body.__status ? body.__status : 200;
            return { ok: status < 400, status, headers: { get: () => 'text/csv' }, json: async () => body, blob: async () => ({}) };
        });
    };
    // A move shows that page, as the router does (the page in use is currentTab)
    navigateTo = async (...args) => {
        window.navs.push(args);
        currentTab = args[0];
        document.querySelectorAll('.tab-content').forEach(el => el.classList.toggle('hidden', el.id !== 'content-' + args[0]));
        return true;
    };
    checkAuthentication = async () => false;
    mailcowRwConfigured = true;`;

function page() {
    const dom = new JSDOM(`<!doctype html><html lang="en"><head><title>t</title><style>.hidden { display: none; }</style></head><body>${BODY}</body></html>`,
        { runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/dashboard' });
    const w = dom.window;
    w.Element.prototype.getClientRects = function () { return this.isConnected && !this.closest('.hidden') ? [{}] : []; };
    w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    w.HTMLElement.prototype.hidePopover = function () {};
    w.HTMLElement.prototype.showPopover = function () {};
    const errors = [];
    w.addEventListener('error', e => errors.push(e.error || e.message));
    const run = source => { const s = w.document.createElement('script'); s.textContent = source; w.document.head.appendChild(s); };
    SCRIPTS.forEach(name => run(read(name)));
    run(STUBS);
    assert.deepEqual(errors, [], 'the scripts load');
    return w;
}

const tick = w => new Promise(resolve => w.setTimeout(resolve, 0));
const settle = async (w, n = 6) => { for (let i = 0; i < n; i++) await tick(w); };
const wait = (w, ms) => new Promise(resolve => w.setTimeout(resolve, ms));
const $ = (w, s) => w.document.querySelector(s);
const acts = w => [...w.document.querySelectorAll('#entity-card-actions > button')].map(b => b.textContent.trim());
const menu = w => [...w.document.querySelectorAll('#entity-card-actions .ui-menu button')].map(b => `${b.textContent.trim()}${b.classList.contains('ui-ent-phone') ? ' (phone)' : ''}`);
const asked = (w, part, method = 'GET') => w.requests.filter(r => r.url.includes(part) && r.method === method);
const nav = w => JSON.parse(JSON.stringify(w.navs.at(-1)));   // the last move, out of the page's realm
const params = url => new URL(url, 'http://localhost').searchParams;

const range = { start: '2026-10-21T12:00:00Z', end: '2026-10-28T12:00:00Z' };
const ok = extra => ({ state: 'ok', reason: null, ...extra });
const off = reason => ({ state: 'disabled', reason });
function ipCard(sources = {}) {
    return { kind: 'ip', value: '203.0.113.45', display: '203.0.113.45', range,
        sources: {
            messages: ok({ count: 2, items: [] }), security: ok({ events: 3, rule_matches: 3, bans: 0, unbans: 0, items: [] }),
            lists: ok({ allowlisted_as: null, denylisted_as: null, ban: null }), protection: ok({ count: 0, open: 0, items: [] }),
            devices: ok({ count: 0, items: [] }), dmarc: ok({ messages: 0, reports: 0, domains: 0, by_domain: [], records: [] }),
            rbl: ok({ checked: false, monitored: false }), geo: ok({}), ...sources },
        timeline: { items: [], truncated: false, left_out: [] } };
}
function addressCard(value, sources = {}) {
    return { kind: 'address', value, display: value, domain: value.split('@')[1], hosted_domain: true, excluded: false, range,
        sources: {
            messages: ok({ count: 4, sent: 1, received: 3, items: [] }), security: ok({ events: 0, rule_matches: 0, bans: 0, unbans: 0, ips: 0, items: [] }),
            protection: ok({ count: 0, open: 0, items: [] }), devices: ok({ count: 0, items: [] }),
            suppression: ok({ entry: null, domain_entry: null }),
            mailbox: ok({ local: true, mailbox: { username: value, name: 'J. Doe', domain: value.split('@')[1], active: true }, alias: null }),
            ...sources },
        timeline: { items: [], truncated: false, left_out: [] } };
}
function domainCard(sources = {}) {
    return { kind: 'domain', value: 'example.net', display: 'example.net', hosted: true, range,
        sources: {
            messages: ok({ count: 5, sent: 2, received: 3, items: [] }), security: ok({ events: 1, rule_matches: 1, bans: 0, unbans: 0, ips: 1, items: [] }),
            devices: ok({ count: 0, items: [] }), dmarc: ok({ reports: 0, messages: 0 }), suppression: ok({ entry: null }),
            mailboxes: ok({ mailboxes: 1, active_mailboxes: 1, aliases: 0 }), dns: ok({ checked: false }), ...sources },
        timeline: null };
}

async function openCard(w, kind, value, card) {
    const before = w.reply;
    w.reply = (url, method) => (url.startsWith('/api/entities/') ? card : before(url, method));
    w.openEntityCard(kind, value);
    await settle(w);
    w.reply = before;
    assert.ok(!$(w, '#entity-card').classList.contains('hidden'), 'the card is open');
}

// --------------------------------------------------------------- the actions offered

test('each kind offers its actions, the main one stays on a phone and the rest fold into More', async () => {
    const w = page();
    await openCard(w, 'ip', '203.0.113.45', ipCard());
    assert.deepEqual(acts(w), ['Show messages', 'Show security events', 'Ban', 'Allow', 'More']);
    assert.deepEqual(menu(w), ['Show messages (phone)', 'Show security events (phone)', 'Allow (phone)', 'Check blocklists now']);
    assert.ok($(w, '[data-ent-act="ban"]').classList.contains('ui-btn-danger'));
    assert.ok(!$(w, '[data-ent-act="ban"]').classList.contains('ui-ent-fold'), 'Ban stays on a phone');
    assert.ok($(w, '[data-ent-act="allow"]').classList.contains('ui-ent-fold'));
    assert.ok($(w, '#entity-card-watch').hidden, 'the slot for Watch is there, empty');
    // No value in a handler: the action reads it from the card
    assert.doesNotMatch($(w, '#entity-card-actions').innerHTML, /onclick="[^"]*203\.0\.113\.45/);

    await openCard(w, 'address', 'j.doe@example.net', addressCard('j.doe@example.net'));
    assert.deepEqual(acts(w), ['Open mailbox', 'Show messages', 'Add to Suppressions', 'More']);
    assert.deepEqual(menu(w), ['Show messages (phone)', 'Add to Suppressions (phone)', 'Show security events']);

    await openCard(w, 'domain', 'example.net', domainCard());
    assert.deepEqual(acts(w), ['Show messages', 'Show security events']);
    assert.deepEqual(menu(w), ['Show security events (phone)']);
    assert.ok($(w, '#entity-card-actions .ui-ent-more-phone'), 'More holds only what a phone folds, so only a phone shows it');
});

test('an action that does not apply, or whose source is off, is not offered', async () => {
    const w = page();
    // An outside address: no mailbox here; Suppressions off; its mail excluded
    await openCard(w, 'address', 'ann@example.org', addressCard('ann@example.org', {
        mailbox: ok({ local: false, mailbox: null, alias: null }),
        suppression: off('Sync with Rspamd is off, so the app keeps no suppression list.'),
        messages: off('This address is excluded, so Messages does not keep or show its mail.'),
    }));
    assert.deepEqual(acts(w), ['More']);
    assert.deepEqual(menu(w), ['Show security events']);
    // Already on the suppression list; Mailbox Stats could not be read
    await openCard(w, 'address', 'bob@example.net', addressCard('bob@example.net', {
        suppression: ok({ entry: { active: true, reason: 'manual' }, domain_entry: null }),
        mailbox: { state: 'error', reason: 'Could not read the mailboxes.' },
    }));
    assert.deepEqual(acts(w), ['Show messages', 'More']);
    assert.ok(!$(w, '[data-ent-act="messages"]').classList.contains('ui-ent-fold'), 'the first stays on a phone when the main one is not offered');
    // Security off: no events, no Ban or Allow and no lock either; blocklists off: no Check now
    await openCard(w, 'ip', '203.0.113.45', ipCard({
        security: off('The Security feature is turned off.'), lists: off('The Security feature is turned off.'),
        protection: off('The Security feature is turned off.'), rbl: off('The IP blocklists feature is turned off.'),
    }));
    assert.deepEqual(acts(w), ['Show messages'], 'nothing left for More');
    assert.deepEqual(menu(w), []);
    assert.equal($(w, '#entity-card .ui-locked'), null);
    assert.equal($(w, '[data-ent-act="rbl-tile"]'), null, 'no Check now in the Blocklists tile');
    assert.match($(w, '#entity-rbl-tile').textContent, /Disabled in Settings/);
});

// --------------------------------------------------------------- Show messages

test('Show messages opens Messages on the IP matched whole: a chip says so, a facet keeps it, the export sends it', async () => {
    const w = page();
    w.reply = url => (url.startsWith('/api/messages/facets') ? { status: {}, direction: {}, time: {} } : url.startsWith('/api/messages') ? { data: [], total: 0, watermark: 5 } : {});
    await openCard(w, 'ip', '203.0.113.45', ipCard());
    $(w, '[data-ent-act="messages"]').click();
    await settle(w);
    assert.deepEqual(nav(w), ['messages']);
    assert.ok($(w, '#entity-card').classList.contains('hidden'), 'the card closed once Messages opened');
    await wait(w, 150);   // the filters apply after the move (navigateToMessagesWithFilter)
    await settle(w);
    let list = params(asked(w, '/api/messages?').at(-1).url);
    assert.equal(list.get('ip'), '203.0.113.45');
    assert.equal(list.get('exact_ip'), 'true');
    assert.ok(list.get('start_date'), 'the card period: its last 7 days');
    assert.equal($(w, '#messages-date-range').value, '7days');
    assert.equal($(w, '#messages-filter-ip').value, '203.0.113.45');
    const chip = $(w, '#messages-exact .ui-sec-filter');
    assert.ok(chip, 'the whole-value filter shows');
    assert.match(chip.textContent, /IP\s+203\.0\.113\.45/);
    // A facet keeps it, and the counts and the new-mail count ask with it
    w.setMessagesFacet('status', 'delivered');
    await settle(w);
    list = params(asked(w, '/api/messages?').at(-1).url);
    assert.equal(list.get('status'), 'delivered');
    assert.equal(list.get('exact_ip'), 'true');
    const facets = params(asked(w, '/api/messages/facets').at(-1).url);
    assert.equal(facets.get('exact_ip'), 'true');
    assert.equal(facets.get('ip'), '203.0.113.45');
    // The export sends what the list shows
    await w.exportCSV('messages');
    const exported = params(asked(w, '/api/export/messages/csv', 'HEAD').at(-1).url);
    assert.equal(exported.get('exact_ip'), 'true');
    assert.equal(exported.get('ip'), '203.0.113.45');
    // The chip's X takes it off, with the IP it set
    $(w, '#messages-exact button').click();
    await settle(w);
    list = params(asked(w, '/api/messages?').at(-1).url);
    assert.equal(list.get('exact_ip'), null);
    assert.equal(list.get('ip'), null);
    assert.equal($(w, '#messages-exact').innerHTML, '');
});

test('Show messages for an address or a domain filters from or to it; another condition added keeps it', async () => {
    const w = page();
    w.reply = url => (url.startsWith('/api/messages') ? { data: [], total: 0, status: {}, direction: {} } : {});
    await openCard(w, 'address', 'J.Doe@Example.net', addressCard('j.doe@example.net'));
    // The Messages tab's count bar is the same action
    w.entityCardTab('messages');
    const bar = $(w, '#entity-card-content [data-ent-act="messages-bar"]');
    assert.match(bar.textContent, /Open in Messages/);
    bar.click();
    await wait(w, 150);
    await settle(w);
    let list = params(asked(w, '/api/messages?').at(-1).url);
    assert.equal(list.get('address'), 'j.doe@example.net');
    assert.equal(list.get('sender'), null);
    assert.equal(list.get('search'), null);
    assert.match($(w, '#messages-exact').textContent, /From or to\s+j\.doe@example\.net/);

    await openCard(w, 'domain', 'example.net', domainCard());
    $(w, '[data-ent-act="messages"]').click();
    await wait(w, 150);
    await settle(w);
    list = params(asked(w, '/api/messages?').at(-1).url);
    assert.equal(list.get('domain'), 'example.net');
    assert.equal(list.get('address'), null, 'the address before is gone');
    // An IP typed into the filters: another condition, so the card's domain stays
    $(w, '#messages-filter-ip').value = '192.0.2.9';
    w.applyMessagesFilters();
    await settle(w);
    list = params(asked(w, '/api/messages?').at(-1).url);
    assert.equal(list.get('domain'), 'example.net');
    assert.equal(list.get('ip'), '192.0.2.9');
    assert.equal(list.get('exact'), null, 'the IP typed is matched as a part, as on any visit');
    assert.equal(list.get('exact_ip'), null);
    assert.match($(w, '#messages-exact').textContent, /example\.net/);
});

test('a condition added keeps the whole value the card set; changing or clearing that value drops it', async () => {
    const w = page();
    w.reply = url => (url.startsWith('/api/messages') ? { data: [], total: 0, status: {}, direction: {} }
        : url.startsWith('/api/logs/netfilter') ? { data: [], total: 0, page: 1, pages: 0 } : {});
    await openCard(w, 'ip', '203.0.113.45', ipCard());
    $(w, '[data-ent-act="messages"]').click();
    await wait(w, 150);
    await settle(w);
    $(w, '#messages-filter-sender').value = 'billing@example.net';
    w.applyMessagesFilters();
    await settle(w);
    let list = params(asked(w, '/api/messages?').at(-1).url);
    assert.equal(list.get('exact_ip'), 'true', 'Sender added: the IP is still whole');
    assert.equal(list.get('exact'), null, 'and the Sender is a part, as on any visit');
    assert.equal(list.get('ip'), '203.0.113.45');
    assert.equal(list.get('sender'), 'billing@example.net');
    $(w, '#messages-filter-ip').value = '203.0.113';
    w.applyMessagesFilters();
    await settle(w);
    list = params(asked(w, '/api/messages?').at(-1).url);
    assert.equal(list.get('exact_ip'), null, 'the IP it set was changed');
    assert.equal($(w, '#messages-exact').innerHTML, '');

    // The same on Security events: a Username added keeps the IP whole, the IP cleared drops it
    await openCard(w, 'ip', '203.0.113.45', ipCard());
    $(w, '[data-ent-act="security"]').click();
    await settle(w);
    $(w, '#netfilter-filter-username').value = 'admin@example.com';
    w.applyNetfilterFilters();
    await settle(w);
    assert.equal(w.eval('currentFilters.netfilter').exact_ip, 'true');
    $(w, '#netfilter-filter-ip').value = '';
    w.applyNetfilterFilters();
    await settle(w);
    assert.equal(w.eval('currentFilters.netfilter').exact_ip, undefined);
});

test('filters set any other way take the card\'s whole values with them: no stale chip, no hidden restriction', async () => {
    const w = page();
    w.reply = url => (url.startsWith('/api/messages') ? { data: [], total: 0, status: {}, direction: {} }
        : url.startsWith('/api/logs/netfilter') ? { data: [], total: 0, page: 1, pages: 0 } : {});
    const fromDomainCard = async () => {
        await openCard(w, 'domain', 'example.net', domainCard());
        $(w, '[data-ent-act="security"]').click();
        await settle(w);
        w.loadNetfilterLogs(1);
        await settle(w);
        assert.match($(w, '#netfilter-exact').textContent, /Accounts on\s+example\.net/);
    };
    // The search's address row (search.js gsOpenAddress) sets the filters itself, from another
    // page: Security then loads with them (loadNetfilterLogs, as the router does)
    await fromDomainCard();
    await w.navigateTo('dashboard');
    await w.gsOpenAddress('198.51.100.7');
    w.loadNetfilterLogs(1);
    await settle(w);
    assert.equal($(w, '#netfilter-exact').innerHTML, '', 'no chip left from the card');
    w.applyNetfilterFilters();
    assert.equal(w.eval('currentFilters.netfilter').username_domain, undefined);
    // An alert's events (alert-activity.js openAlertSecurityEvents), applied later
    await fromDomainCard();
    w.openAlertSecurityEvents('ann@example.org');
    await wait(w, 150);
    await settle(w);
    assert.equal(w.eval('currentFilters.netfilter').username_domain, undefined);
    assert.equal(w.eval('currentFilters.netfilter').username, 'ann@example.org');
    // Security's own Events link for an address (security.js securityOpenEvents)
    await fromDomainCard();
    w.securityOpenEvents('198.51.100.8');
    await settle(w);
    assert.equal(w.eval('currentFilters.netfilter').username_domain, undefined);
    assert.equal($(w, '#netfilter-exact').innerHTML, '');
    // Messages: the Dashboard chart's range (openMessagesRange)
    await openCard(w, 'address', 'j.doe@example.net', addressCard('j.doe@example.net'));
    $(w, '[data-ent-act="messages"]').click();
    await wait(w, 150);
    await settle(w);
    w.openMessagesRange({ start: '2026-10-28T08:00:00Z', endInclusive: '2026-10-28T08:59:59.999Z' });
    w.loadMessages();
    await settle(w);
    const list = params(asked(w, '/api/messages?').at(-1).url);
    assert.equal(list.get('address'), null);
    assert.equal(list.get('exact'), null);
    assert.equal($(w, '#messages-exact').innerHTML, '');
});

// --------------------------------------------------------------- Show security events

test('Show security events opens the Events on the account matched whole, and its export sends it', async () => {
    const w = page();
    w.reply = url => (url.startsWith('/api/logs/netfilter') ? { data: [], total: 0, page: 1, pages: 0 } : {});
    await openCard(w, 'address', 'j.doe@example.net', addressCard('j.doe@example.net'));
    const item = $(w, '#entity-card-actions .ui-menu [data-ent-act="security-menu"]');
    item.click();
    await settle(w);
    assert.deepEqual(nav(w), ['netfilter', { sub: 'events' }]);
    assert.ok($(w, '#entity-card').classList.contains('hidden'));
    const f = w.eval('currentFilters.netfilter');
    assert.equal(f.username, 'j.doe@example.net');
    assert.equal(f.exact_username, 'true');
    assert.equal(f.start_date, range.start);
    assert.equal(f.end_date, undefined, 'a preset runs up to now');
    w.loadNetfilterLogs(1);
    await settle(w);
    assert.match($(w, '#netfilter-exact').textContent, /Account\s+j\.doe@example\.net, the last 7 days/);
    assert.equal(params(asked(w, '/api/logs/netfilter').at(-1).url).get('exact_username'), 'true');
    await w.exportCSV('netfilter');
    const exported = params(asked(w, '/api/export/netfilter/csv', 'HEAD').at(-1).url);
    assert.equal(exported.get('exact_username'), 'true');
    assert.equal(exported.get('username'), 'j.doe@example.net');

    // A domain: the accounts on it; an IP: exact_ip
    await openCard(w, 'domain', 'example.net', domainCard());
    $(w, '[data-ent-act="security"]').click();
    await settle(w);
    assert.equal(w.eval('currentFilters.netfilter').username_domain, 'example.net');
    await openCard(w, 'ip', '203.0.113.45', ipCard());
    w.entityCardTab('security');
    $(w, '#entity-card-content [data-ent-act="security-bar"]').click();
    await settle(w);
    const ipFilters = w.eval('currentFilters.netfilter');
    assert.equal(ipFilters.ip, '203.0.113.45');
    assert.equal(ipFilters.exact_ip, 'true');
    assert.equal(ipFilters.username_domain, undefined);
});

// --------------------------------------------------------------- Ban and Allow

test('Ban asks first: Cancel changes nothing, Ban bans and the card reads itself again', async () => {
    const w = page();
    w.reply = (url, method) => (url === '/api/fail2ban/ban' && method === 'POST' ? { status: 'success' } : {});
    await openCard(w, 'ip', '203.0.113.45', ipCard());
    $(w, '[data-ent-act="ban"]').click();
    await settle(w);
    const dialog = $(w, '#app-confirm-modal');
    assert.ok(dialog, 'the confirmation opens');
    assert.match(dialog.textContent, /203\.0\.113\.45\/32/);
    assert.ok($(w, '#app-confirm-ok').classList.contains('ui-btn-danger-solid'));
    $(w, '#app-confirm-cancel').click();
    await settle(w);
    assert.equal(asked(w, '/api/fail2ban/ban', 'POST').length, 0, 'Cancel bans nothing');
    assert.ok(!$(w, '#entity-card').classList.contains('hidden'), 'the card stays');

    const reads = asked(w, '/api/entities/ip').length;
    w.reply = (url, method) => (url === '/api/fail2ban/ban' && method === 'POST' ? { status: 'success' }
        : url.startsWith('/api/entities/') ? ipCard({ lists: ok({ allowlisted_as: null, denylisted_as: '203.0.113.45/32', ban: null }) }) : {});
    $(w, '[data-ent-act="ban"]').click();
    await settle(w);
    $(w, '#app-confirm-ok').click();
    await settle(w, 12);
    const posts = asked(w, '/api/fail2ban/ban', 'POST');
    assert.equal(posts.length, 1);
    assert.deepEqual(JSON.parse(posts[0].body), { ip: '203.0.113.45/32' });
    assert.equal(asked(w, '/api/entities/ip').length, reads + 1, 'the card read itself again');
    assert.match($(w, '#entity-card-header').textContent, /On the denylist/);
    assert.deepEqual(acts(w), ['Show messages', 'Show security events', 'Allow', 'More'], 'Ban is gone once on the denylist');
});

test('Allow asks first and allows', async () => {
    const w = page();
    w.reply = (url, method) => (url === '/api/fail2ban/allow' && method === 'POST' ? { status: 'success' } : {});
    await openCard(w, 'ip', '203.0.113.45', ipCard());
    $(w, '[data-ent-act="allow"]').click();
    await settle(w);
    assert.match($(w, '#app-confirm-modal').textContent, /allowlist/);
    $(w, '#app-confirm-cancel').click();
    await settle(w);
    assert.equal(asked(w, '/api/fail2ban/allow', 'POST').length, 0);
    $(w, '[data-ent-act="allow"]').click();
    await settle(w);
    $(w, '#app-confirm-ok').click();
    await settle(w, 12);
    assert.deepEqual(JSON.parse(asked(w, '/api/fail2ban/allow', 'POST')[0].body), { ip: '203.0.113.45/32' });
});

test('without the Read-Write key Ban and Allow are locked, not hidden, and a list not read leaves them', async () => {
    const w = page();
    w.eval('mailcowRwConfigured = false');
    w.reply = url => (url === '/api/rw-status' ? { rw_configured: false } : {});
    await openCard(w, 'ip', '203.0.113.45', ipCard());
    assert.equal(asked(w, '/api/rw-status').length, 1, 'the key is asked for once more');
    assert.deepEqual(acts(w), ['Show messages', 'Show security events', 'More']);
    const lock = $(w, '#entity-card-header .ui-locked');
    assert.ok(lock, 'the locked note shows');
    assert.match(lock.textContent, /Ban and Allow are locked/);
    assert.match(lock.textContent, /Read-Write API key/);
    w.entityCardAct('ban');
    await settle(w);
    assert.equal($(w, '#app-confirm-modal'), null, 'no ban without the key');

    // With the key, a list that could not be read leaves both; the state reads as not known
    w.eval('mailcowRwConfigured = true');
    await openCard(w, 'ip', '203.0.113.45', ipCard({ lists: { state: 'error', reason: 'mailcow did not answer.' } }));
    assert.deepEqual(acts(w), ['Show messages', 'Show security events', 'Ban', 'Allow', 'More']);
    assert.match($(w, '#entity-card-header').textContent, /ban state not known/);
});

// --------------------------------------------------------------- Check now

test('Check now posts the address and force in the URL, shows the progress and then the stored result', async () => {
    const w = page();
    let finish;
    w.reply = (url, method) => {
        if (url.startsWith('/api/blacklist/check') && method === 'POST') return new Promise(resolve => { finish = resolve; });
        if (url === '/api/blacklist/progress') return { in_progress: true, current: 12, total: 42, percent: 28 };
        if (url.startsWith('/api/entities/')) return ipCard({ rbl: ok({ checked: true, monitored: false, checked_at: '2026-10-28T12:00:00Z', status: 'clean', listed_count: 0, total_blacklists: 42, listed: [] }) });
        return {};
    };
    await openCard(w, 'ip', '203.0.113.45', ipCard());
    assert.match($(w, '#entity-rbl-tile').textContent, /Not checked/);
    $(w, '[data-ent-act="rbl-tile"]').focus();
    $(w, '[data-ent-act="rbl-tile"]').click();
    await settle(w);
    const post = asked(w, '/api/blacklist/check', 'POST');
    assert.equal(post.length, 1);
    assert.equal(post[0].url, '/api/blacklist/check?host=203.0.113.45&force=true');
    assert.equal($(w, '[data-ent-act="rbl-tile"]').getAttribute('aria-disabled'), 'true');
    assert.equal(w.document.activeElement, $(w, '[data-ent-act="rbl-tile"]'), 'the focus stays on it');
    await wait(w, 1100);
    await settle(w);
    assert.match($(w, '#entity-rbl-tile').textContent, /12 of 42 lists checked/);
    assert.equal($(w, '#entity-rbl-tile [role="progressbar"]').getAttribute('aria-valuenow'), '28');
    // A second click while it runs posts nothing more
    $(w, '[data-ent-act="rbl-tile"]').click();
    await settle(w);
    assert.equal(asked(w, '/api/blacklist/check', 'POST').length, 1);
    finish({ status: 'clean', total_blacklists: 42, listed_count: 0 });
    await settle(w, 12);
    assert.match($(w, '#entity-rbl-tile').textContent, /Not listed/);
    assert.match($(w, '#entity-rbl-tile').textContent, /On none of 42/);
    assert.equal($(w, '[data-ent-act="rbl-tile"]').getAttribute('aria-disabled'), null);
});

// --------------------------------------------------------------- Open mailbox

const mailboxRow = (username, aliases = []) => ({
    username, name: 'J. Doe', active: true, combined_sent: 3, combined_received: 7, combined_failure_rate: 0,
    activity: { sent: [1, 2], received: [3, 4] }, aliases: aliases.map(a => ({ alias_address: a })),
});

test('Open mailbox finds the mailbox when Mailbox Stats never loaded, over the card period', async () => {
    const w = page();
    assert.equal(w.eval('mailboxStatsCache.mailboxes'), null, 'nothing loaded');
    assert.equal($(w, '#mailbox-stats-hide-zero').checked, true, 'Hide Zero Activity is on by default');
    w.reply = url => (url.startsWith('/api/mailbox-stats/all')
        ? { mailboxes: [mailboxRow('xj.doe@example.net'), mailboxRow('j.doe@example.net')], activity_unit: 'day', activity_buckets: ['2026-10-27', '2026-10-28'] } : {});
    await openCard(w, 'address', 'j.doe@example.net', addressCard('j.doe@example.net'));
    $(w, '[data-ent-act="mailbox"]').click();
    await settle(w, 10);
    assert.deepEqual(nav(w), ['mailbox-stats', { sub: 'statistics' }]);
    const q = params(asked(w, '/api/mailbox-stats/all').at(-1).url);
    assert.equal(q.get('username'), 'j.doe@example.net', 'the mailbox by its whole address, on any page');
    assert.equal(q.get('date_range'), '7days', 'the period of the card');
    assert.equal(q.get('active_only'), 'false');
    assert.equal(q.get('hide_zero'), null, 'a mailbox with no mail in the period is listed too');
    assert.equal($(w, '#mailbox-stats-hide-zero').checked, false, 'and the page says so');
    assert.ok($(w, '#entity-card').classList.contains('hidden'), 'the card closed');
    assert.ok(!$(w, '#mailbox-activity-modal').classList.contains('hidden'), 'the activity is open');
    assert.equal($(w, '#mailbox-activity-title').textContent, 'j.doe@example.net', 'the mailbox asked for, not one that only contains it');
});

const aliasSource = local => ok({ local: false, mailbox: null,
    alias: { address: 'sales@example.net', goto: local || 'ann@outside.test', primary_mailbox: local || 'ann@outside.test', local_mailbox: local, active: true } });

test('Open mailbox on an alias opens the mailbox here it delivers to, and is not offered for one that forwards out', async () => {
    const w = page();
    w.reply = url => (url.startsWith('/api/mailbox-stats/all')
        ? { mailboxes: [mailboxRow('j.doe@example.net', ['sales@example.net'])], activity_unit: 'day', activity_buckets: [] } : {});
    await openCard(w, 'address', 'sales@example.net', addressCard('sales@example.net', { mailbox: aliasSource('j.doe@example.net') }));
    assert.equal($(w, '[data-ent-act="mailbox"]').title, 'Open j.doe@example.net, the mailbox this alias delivers to');
    $(w, '[data-ent-act="mailbox"]').click();
    await settle(w, 10);
    assert.equal(params(asked(w, '/api/mailbox-stats/all').at(-1).url).get('username'), 'j.doe@example.net', 'the mailbox the server resolved');
    assert.equal($(w, '#mailbox-activity-title').textContent, 'j.doe@example.net');
    // Its first target is outside this mailcow: no mailbox to open
    await openCard(w, 'address', 'sales@example.net', addressCard('sales@example.net', { mailbox: aliasSource(null) }));
    assert.equal($(w, '[data-ent-act="mailbox"]'), null);
});

test('Open mailbox asks for the mailbox as stored, an IDN domain as ASCII, not as the card shows it', async () => {
    const w = page();
    const stored = 'ann@xn--bcher-kva.example';
    w.reply = url => (url.startsWith('/api/mailbox-stats/all') ? { mailboxes: [mailboxRow(stored)], activity_unit: 'day', activity_buckets: [] } : {});
    const card = addressCard(stored, { mailbox: ok({ local: true, mailbox: { username: stored, name: 'Ann', domain: 'xn--bcher-kva.example', active: true }, alias: null }) });
    card.display = 'Ann@bücher.example';
    await openCard(w, 'address', 'Ann@bücher.example', card);
    $(w, '[data-ent-act="mailbox"]').click();
    await settle(w, 10);
    assert.equal(params(asked(w, '/api/mailbox-stats/all').at(-1).url).get('username'), stored);
    assert.equal($(w, '#mailbox-activity-title').textContent, stored);
});

test('a mailbox that comes after the user left Mailbox Stats, or after another opening, opens nothing', async () => {
    const w = page();
    const held = [];
    w.reply = url => (url.startsWith('/api/mailbox-stats/all') ? new Promise(resolve => held.push(resolve)) : {});
    const answer = (i, name) => held[i]({ mailboxes: [mailboxRow(name)], activity_unit: 'day', activity_buckets: [] });
    await openCard(w, 'address', 'j.doe@example.net', addressCard('j.doe@example.net'));
    $(w, '[data-ent-act="mailbox"]').click();
    await settle(w);
    await w.navigateTo('messages');   // the user moved on while it loaded
    answer(0, 'j.doe@example.net');
    await settle(w, 10);
    assert.ok($(w, '#mailbox-activity-modal').classList.contains('hidden'), 'not over Messages');
    // Two openings: only the last one opens
    const first = w.openMailboxFor('j.doe@example.net', { preset: '7days' });
    await settle(w);
    const second = w.openMailboxFor('bob@example.net', { preset: '7days' });
    await settle(w);
    answer(2, 'bob@example.net');
    await second;
    answer(1, 'j.doe@example.net');
    await first;
    await settle(w);
    assert.equal($(w, '#mailbox-activity-title').textContent, 'bob@example.net');
});

// --------------------------------------------------------------- Add to Suppressions

test('Add to Suppressions opens the Add dialog with the address, and the card reads itself again once added', async () => {
    const w = page();
    w.reply = (url, method) => (url === '/api/suppressions' && method === 'POST' ? { id: 1 } : url.startsWith('/api/entities/')
        ? addressCard('j.doe@example.net', { suppression: ok({ entry: { active: true, reason: 'manual', source: 'manual' }, domain_entry: null }) }) : {});
    await openCard(w, 'address', 'j.doe@example.net', addressCard('j.doe@example.net'));
    $(w, '[data-ent-act="suppress"]').click();
    await settle(w);
    assert.equal($(w, '#new-suppression-email').value, 'j.doe@example.net');
    assert.equal($(w, '#new-suppression-notes').value, '');
    assert.equal(asked(w, '/api/suppressions', 'POST').length, 0, 'nothing is added before the dialog is confirmed');
    await w.createSuppression();
    await settle(w, 12);
    assert.equal(JSON.parse(asked(w, '/api/suppressions', 'POST')[0].body).email, 'j.doe@example.net');
    assert.deepEqual(acts(w), ['Open mailbox', 'Show messages', 'More'], 'already on the list: not offered again');
    assert.match($(w, '#entity-card-header').textContent, /On the suppression list/);
});

// --------------------------------------------------------------- Check now: one check at a time

test('Check now when another check runs: the server starts nothing, the tile says so and Check now stays to try again', async () => {
    const w = page();
    const toasts = [];
    w.showToast = (message, type) => toasts.push([message, type]);
    w.reply = (url, method) => (url.startsWith('/api/blacklist/check') && method === 'POST'
        ? { status: 'busy', message: 'A blocklist check is already running. Try again when it is done.' } : {});
    await openCard(w, 'ip', '203.0.113.45', ipCard());
    const reads = asked(w, '/api/entities/ip').length;
    $(w, '[data-ent-act="rbl-tile"]').click();
    await settle(w, 10);
    assert.match($(w, '#entity-rbl-tile').textContent, /A blocklist check is already running/);
    const button = $(w, '[data-ent-act="rbl-tile"]');
    assert.equal(button.textContent, 'Check now');
    assert.equal(button.getAttribute('aria-disabled'), null);
    assert.deepEqual(JSON.parse(JSON.stringify(toasts)), [['A blocklist check is already running. Try again when it is done.', 'warning']]);
    assert.equal(asked(w, '/api/entities/ip').length, reads, 'nothing to read again');
});

test('the Status page says when a check already runs instead of "completed"', async () => {
    const w = page();
    const toasts = [];
    w.showToast = (message, type) => toasts.push([message, type]);
    w.reply = (url, method) => (url.startsWith('/api/blacklist/check') && method === 'POST'
        ? { status: 'busy', message: 'A blocklist check is already running. Try again when it is done.' } : {});
    await w.checkHost('mail.example.com');
    await settle(w);
    const said = JSON.parse(JSON.stringify(toasts)).map(t => t[0]);
    assert.ok(said.includes('A blocklist check is already running. Try again when it is done.'));
    assert.ok(!said.some(t => /Check completed/.test(t)), said.join(' | '));
});

test('the progress of a check stops with its card, and a late answer of an older check changes nothing', async () => {
    const w = page();
    w.eval('ENTITY_RBL_POLL.every = 50');
    let finish;
    const progress = [];
    w.reply = (url, method) => {
        if (url.startsWith('/api/blacklist/check') && method === 'POST') return new Promise(resolve => { finish = resolve; });
        if (url === '/api/blacklist/progress') return new Promise(resolve => progress.push(resolve));
        return {};
    };
    await openCard(w, 'ip', '203.0.113.45', ipCard());
    $(w, '[data-ent-act="rbl-tile"]').click();
    await wait(w, 120);
    assert.ok(progress.length >= 1, 'the progress is asked for');
    assert.equal(progress.length, asked(w, '/api/blacklist/progress').length);
    assert.equal(w.requests.filter(r => r.url === '/api/blacklist/progress').length, progress.length);
    // One request at a time: no second while the first is out
    assert.equal(progress.length, 1);
    // The card shows another address: its own check is gone, the old progress lands on nothing
    await openCard(w, 'ip', '198.51.100.23', ipCard());
    progress[0]({ in_progress: true, current: 40, total: 42, percent: 95 });
    await wait(w, 200);
    assert.equal(asked(w, '/api/blacklist/progress').length, 1, 'no more progress asked for after the card changed');
    assert.doesNotMatch($(w, '#entity-rbl-tile').textContent, /40 of 42/);
    // The old check ends: the card of the other address is not read again
    const reads = asked(w, '/api/entities/ip').length;
    finish({ status: 'clean', total_blacklists: 42 });
    await settle(w, 10);
    assert.equal(asked(w, '/api/entities/ip').length, reads);
    // Closed while it runs: the progress stops too
    $(w, '[data-ent-act="rbl-tile"]').click();
    await wait(w, 120);
    const before = asked(w, '/api/blacklist/progress').length;
    progress.at(-1)({ in_progress: true, current: 1, total: 42, percent: 2 });
    w.closeEntityCard();
    await wait(w, 200);
    assert.equal(asked(w, '/api/blacklist/progress').length, before);
});

test('the progress is asked for a limited time, each request with a time limit', async () => {
    const w = page();
    w.eval('ENTITY_RBL_POLL.every = 40; ENTITY_RBL_POLL.max = 300');
    const options = [];
    const before = w.authenticatedFetch;
    w.reply = (url, method) => (url.startsWith('/api/blacklist/check') && method === 'POST' ? new Promise(() => {})
        : url === '/api/blacklist/progress' ? { in_progress: true, current: 3, total: 42, percent: 7 } : {});
    await openCard(w, 'ip', '203.0.113.45', ipCard());
    w.authenticatedFetch = (url, opts = {}) => { if (url === '/api/blacklist/progress') options.push(opts); return before(url, opts); };
    $(w, '[data-ent-act="rbl-tile"]').click();
    await wait(w, 500);
    const asks = options.length;
    assert.ok(asks >= 2, 'it was asked');
    assert.ok(options.every(o => o.timeout === 5000), 'each request has its own limit');
    await wait(w, 300);
    assert.equal(options.length, asks, 'no more after the limit');
    assert.match($(w, '#entity-rbl-tile').textContent, /Still checking/);
});

// --------------------------------------------------------------- review round 2

test('a condition added to a card\'s filter is matched as a part, in the list, the counts, the new mail and the export', async () => {
    const w = page();
    w.reply = url => (url.startsWith('/api/messages/facets') ? { status: {}, direction: {}, time: {} }
        : url.startsWith('/api/messages/new') ? { count: 0, watermark: 5 }
        : url.startsWith('/api/messages') ? { data: [], total: 0, watermark: 5 } : {});
    const sent = (part, method = 'GET') => params(asked(w, part, method).at(-1).url);
    // A domain card, then a partial sender typed in: no exact anywhere
    await openCard(w, 'domain', 'example.net', domainCard());
    $(w, '[data-ent-act="messages"]').click();
    await wait(w, 150);
    await settle(w);
    $(w, '#messages-filter-sender').value = 'billing';
    w.applyMessagesFilters();
    await settle(w, 10);
    for (const q of [sent('/api/messages?'), sent('/api/messages/facets')]) {
        assert.equal(q.get('domain'), 'example.net');
        assert.equal(q.get('sender'), 'billing');
        assert.equal(q.get('exact'), null, 'billing matches billing@example.com, as on any visit');
        assert.equal(q.get('exact_ip'), null);
    }
    await w.exportCSV('messages');
    const exported = sent('/api/export/messages/csv', 'HEAD');
    assert.equal(exported.get('exact'), null);
    assert.equal(exported.get('domain'), 'example.net');
    // The new-mail count asks with the same filters
    const fresh = w.messagesFilterParams(w.eval('currentFilters.messages'));
    assert.equal(fresh.get('exact'), null);
    assert.equal(fresh.get('domain'), 'example.net');
    // An IP card: the IP whole (exact_ip), the sender added still a part
    await openCard(w, 'ip', '203.0.113.45', ipCard());
    $(w, '[data-ent-act="messages"]').click();
    await wait(w, 150);
    await settle(w);
    $(w, '#messages-filter-sender').value = 'billing';
    w.applyMessagesFilters();
    await settle(w, 10);
    for (const q of [sent('/api/messages?'), sent('/api/messages/facets'), w.messagesFilterParams(w.eval('currentFilters.messages'))]) {
        assert.equal(q.get('exact_ip'), 'true');
        assert.equal(q.get('exact'), null);
        assert.equal(q.get('sender'), 'billing');
    }
    await w.exportCSV('messages');
    assert.equal(sent('/api/export/messages/csv', 'HEAD').get('exact_ip'), 'true');
    assert.equal(sent('/api/export/messages/csv', 'HEAD').get('exact'), null);
});

test('a mailbox that comes after the period, the filters or the view changed opens nothing', async () => {
    const w = page();
    const held = [];
    w.reply = url => (url.startsWith('/api/mailbox-stats/all') && url.includes('username=') ? new Promise(resolve => held.push(resolve)) : {});
    const answer = i => held[i]({ mailboxes: [mailboxRow('j.doe@example.net')], activity_unit: 'day', activity_buckets: [] });
    // Asked over 7 days, then Today chosen before the answer
    const first = w.openMailboxFor('j.doe@example.net', { preset: '7days' });
    await settle(w);
    w.selectDatePreset('today');
    await settle(w);
    answer(0);
    await first;
    await settle(w);
    assert.ok($(w, '#mailbox-activity-modal').classList.contains('hidden'), 'not over another period');
    // Asked, then Rate Limits opened on the same page
    const second = w.openMailboxFor('j.doe@example.net', { preset: '7days' });
    await settle(w);
    w.mailboxStatsSwitchView('rate-limits');
    await settle(w);
    answer(1);
    await second;
    await settle(w);
    assert.ok($(w, '#mailbox-activity-modal').classList.contains('hidden'), 'not over Rate Limits');
});
