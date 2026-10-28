const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');
const source = fs.readFileSync(path.join(frontend, 'message-details.js'), 'utf8');

function harness(data, ok = true) {
    const elements = new Map();
    const listeners = {};
    const element = id => {
        if (!elements.has(id)) {
            const classes = new Set(id === 'message-modal' ? ['hidden'] : []);
            const attrs = {};
            elements.set(id, { id, innerHTML: '', style: {}, dataset: {}, attrs,
                setAttribute: (name, value) => { attrs[name] = String(value); }, getAttribute: name => attrs[name] ?? null,
                classList: { add: value => classes.add(value), remove: value => classes.delete(value), contains: value => classes.has(value) },
                addEventListener: (name, handler) => { listeners[id + ':' + name] = handler; },
                querySelector: () => null, querySelectorAll: () => [],
            });
        }
        return elements.get(id);
    };
    const requests = [];
    const document = {
        body: { style: {} }, getElementById: element, querySelector: () => null,
        querySelectorAll: () => ['overview', 'postfix', 'spam', 'netfilter'].map(tab => element('modal-tab-' + tab)),
        addEventListener: (name, handler) => { listeners[name] = handler; },
    };
    const context = vm.createContext({ document, window: { disabledFeatures: [] }, console: { log() {}, error() {} },
        authenticatedFetch: async url => { requests.push(url); return { ok, status: 500, statusText: 'Test failure', json: async () => data }; },
        renderGeoIPInfo: () => '', appTimezone: 'UTC',
        // Timers never fire here: a test sees the state a timer would undo
        setTimeout: () => 0, clearTimeout: () => {},
    });
    vm.runInContext(fs.readFileSync(path.join(frontend, 'utils.js'), 'utf8'), context);
    // Stable timestamp display keeps rendering assertions independent of host locale.
    context.formatTime = value => value || '-';
    vm.runInContext(source, context);
    return { context, document, element, requests, listeners };
}

function message() {
    return { correlation_key: 'example-key', queue_id: 'TEST123', sender: 'sender@example.com',
        recipient: 'recipient@example.com', recipients: ['recipient@example.com'], direction: 'inbound', final_status: 'delivered',
        postfix: [{ time: '2026-01-01T00:00:00Z', message: 'status=sent <test>', recipient: 'recipient@example.com', status: 'sent', program: 'postfix/lmtp' }],
        dovecot: { status: 'stored', mailbox: 'Junk' }, dovecot_logs: [],
        rspamd: { score: 1.5, action: 'no action', required_score: 15, symbols: { TEST_ZERO: { score: 0 }, TEST_SCORE: { score: 1.5, description: '<test>' } } },
        netfilter: [{ time: '2026-01-01T00:00:00Z', ip: '192.0.2.1', action: 'ban', message: 'test event' }],
    };
}


// The timeline's rows, and those every recipient shares
function timelineLines(html) {
    const rows = html.split('id="log-timeline-entries"')[1] || '';
    return { all: (rows.match(/data-log-source=/g) || []).length, shared: (rows.match(/>All recipients<\/span>/g) || []).length };
}

test('message entry point and all four tabs preserve content and actions', async () => {
    const h = harness(message());
    await h.context.viewMessageDetails('example-key');
    assert.deepEqual(h.requests, ['/api/message/example-key/details']);
    assert.equal(h.element('message-modal').classList.contains('hidden'), false);
    assert.equal(h.document.body.style.overflow, 'hidden');
    // Subject, sender and outcome sit in the header above the tabs
    assert.match(h.element('message-modal-header').innerHTML, /sender@example.com/);
    assert.match(h.element('message-modal-content').innerHTML, /What happened/);
    assert.match(h.element('message-modal-content').innerHTML, /Junk/);
    h.context.switchModalTab('postfix');
    assert.match(h.element('message-modal-content').innerHTML, /status=sent &lt;test&gt;/);
    h.context.switchModalTab('spam');
    assert.match(h.element('message-modal-content').innerHTML, /TEST_ZERO/);
    assert.match(h.element('message-modal-content').innerHTML, /toggleZeroSymbols\(this\)/);
    assert.match(h.element('message-modal-content').innerHTML, /&lt;test&gt;/);
    h.context.switchModalTab('netfilter');
    assert.match(h.element('message-modal-content').innerHTML, /192\.0\.2\.1/);
    h.context.closeMessageModal();
    assert.equal(h.element('message-modal').classList.contains('hidden'), true);
    assert.equal(h.document.body.style.overflow, '');
    assert.equal(h.element('modal-tab-netfilter').innerHTML, '<span>Security</span>');
});

test('right-to-left mail content keeps its own direction', async () => {
    // Written as escapes so the source stays ASCII; renders as a Hebrew subject
    const rtl = '\u05e9\u05dc\u05d5\u05dd (1)';
    const h = harness({ ...message(), subject: rtl });
    await h.context.viewMessageDetails('example-key');
    const html = h.element('message-modal-header').innerHTML;
    assert.ok(html.includes(`dir="auto" title="${rtl}">${rtl}</h2>`));
    assert.match(html, /<bdi>sender@example\.com<\/bdi>/);
});

test('empty analysis and security records retain their empty states', () => {
    const h = harness({});
    h.context.renderSpamTab(h.element('content'), {});
    assert.match(h.element('content').innerHTML, /No spam analysis/);
    h.context.renderNetfilterTab(h.element('content'), {});
    assert.match(h.element('content').innerHTML, /No security events detected/);
});

test('failed fetch and disabled security retain their behavior', async () => {
    const failed = harness({}, false);
    await failed.context.viewMessageDetails('example-key');
    assert.match(failed.element('message-modal-content').innerHTML, /Failed to load message details/);
    const disabled = harness(message());
    disabled.context.window.disabledFeatures.push('netfilter');
    await disabled.context.viewMessageDetails('example-key');
    assert.equal(disabled.element('modal-tab-netfilter').style.display, 'none');
});

test('shared list hints remain available and escape folder names', () => {
    const h = harness({});
    assert.equal(h.context.renderMailboxFolderHint({ dovecot_status: 'stored', dovecot_mailbox: '<Junk>' }), '<span>Folder: &lt;Junk&gt;</span>');
    // A message delivered twice is one email: its row counts recipients, not deliveries
    assert.equal(typeof h.context.renderDeliveriesChip, 'undefined');
});

test('message listeners close on backdrop, and on Escape when docked', async () => {
    const h = harness(message());
    h.listeners.DOMContentLoaded();
    await h.context.viewMessageDetails('example-key');
    const modal = h.element('message-modal');
    h.listeners['message-modal:click']({ target: h.element('message-modal-content'), currentTarget: modal });
    assert.equal(h.element('message-modal').classList.contains('hidden'), false);
    h.listeners['message-modal:click']({ target: modal, currentTarget: modal });
    assert.equal(h.element('message-modal').classList.contains('hidden'), true);
    // As a dialog, Escape belongs to the layers (router.js, layers.a11y.cjs)
    await h.context.viewMessageDetails('example-key');
    h.listeners.keydown({ key: 'Escape' });
    assert.equal(h.element('message-modal').classList.contains('hidden'), false);
    // Docked beside the list, Escape closes it
    h.element('message-modal').classList.add('ui-docked');
    h.listeners.keydown({ key: 'Escape' });
    assert.equal(h.element('message-modal').classList.contains('hidden'), true);
    assert.equal(h.document.body.style.overflow, '');
});

test('the feature script is versioned and loaded after its dependencies', () => {
    const html = fs.readFileSync(path.join(frontend, 'index.html'), 'utf8');
    const scripts = [...html.matchAll(/<script src="\/static\/([^"?]+)\?v=\d+"/g)].map(match => match[1]);
    assert.ok(scripts.indexOf('message-details.js') > scripts.indexOf('app.js'));
    assert.ok(scripts.indexOf('app.js') > scripts.indexOf('utils.js'));
});

test('opened as a dialog, the message is last on the page, over a dialog already open', async () => {
    const h = harness(message());
    const modal = h.element('message-modal');
    const appended = [];
    modal.parentNode = { insertBefore: () => {} };   // its place inside the page shell
    modal.nextSibling = null;
    h.document.body.appendChild = node => { appended.push(node); node.parentNode = h.document.body; };
    // Block details is open (appended to the page before the message is asked for)
    await h.context.viewMessageDetails('example-key');
    assert.deepEqual(appended, [modal], 'moved after Block details, so it is drawn on top');
    assert.equal(modal.classList.contains('ui-docked'), false);
});

// A message to many (issue #476): one delivered and one deferred twice through
// the same relay, one bounced, one Postfix has not logged yet
function messageToMany() {
    const at = s => `2026-01-01T00:00:0${s}Z`;
    const line = (s, recipient, status, message) => ({ time: at(s), program: 'postfix/smtp', recipient, status, relay: 'mx.example.net[192.0.2.9]:25', message });
    return { ...message(), final_status: 'deferred', dovecot: null,
        recipients: ['a@example.net', 'b@example.net', 'c@example.net', 'd@example.net'],
        postfix: [
            { time: at(0), program: 'postfix/qmgr', message: 'TEST123: from=<sender@example.com>, nrcpt=4 (queue active)' },
            line(1, 'a@example.net', 'sent', 'TEST123: to=<a@example.net>, status=sent (250 ok)'),
            line(2, 'b@example.net', 'deferred', 'TEST123: to=<b@example.net>, status=deferred (host mx said: 451 4.7.1 Try later (in reply to RCPT TO command))'),
            line(3, 'B@example.net', 'deferred', 'TEST123: to=<b@example.net>, status=deferred (host mx said: 451 4.7.1 Try later (in reply to RCPT TO command))'),
            line(4, 'c@example.net', 'bounced', 'TEST123: to=<c@example.net>, status=bounced (host mx said: 550 5.1.1 No such user (in reply to RCPT TO command))'),
        ] };
}

test('a message to many counts its recipients in the header and in What happened', async () => {
    const h = harness(messageToMany());
    await h.context.viewMessageDetails('example-key');
    const header = h.element('message-modal-header').innerHTML;
    assert.match(header, /To \(4\)/);
    assert.match(header, /Delivered to 1 of 4 recipients/);
    assert.match(header, /showMessageRecipients\(''\)">All 4 recipients/);
    // Every status but Delivered as a count that opens those recipients
    assert.match(header, /showMessageRecipients\('bounced'\)">1 bounced/);
    assert.match(header, /showMessageRecipients\('deferred'\)">1 deferred/);
    assert.match(header, /showMessageRecipients\('none'\)">1 not logged yet/);
    const overview = h.element('message-modal-content').innerHTML;
    assert.match(overview, /Delivered to 1 recipient</);
    assert.match(overview, /via mx\.example\.net/);
    assert.match(overview, /Deferred for 1 recipient</);
    assert.match(overview, /Bounced for 1 recipient</);
    assert.doesNotMatch(overview, /attempts/, 'deliveries to many are not attempts');
});

test('the Logs tab lists the recipients, problems first, and shows one recipient\'s lines', async () => {
    const h = harness(messageToMany());
    await h.context.viewMessageDetails('example-key');
    h.context.switchModalTab('postfix');
    const logs = h.element('message-modal-content').innerHTML;
    const order = ['c@example.net', 'b@example.net', 'd@example.net', 'a@example.net'].map(a => logs.indexOf(`title="Show the logs of ${a}"`));
    assert.ok(order.every((at, i) => at > 0 && (i === 0 || at > order[i - 1])), `problems first: ${order}`);
    assert.match(logs, /550 5\.1\.1 No such user/);
    assert.match(logs, /2 attempts/);
    assert.match(logs, /No delivery logged yet/);
    assert.doesNotMatch(logs, /Delivery Error/, 'the reasons are in the list');
    assert.match(logs, /5 entries/);
    // b@ was logged once in capitals: both its lines, and the shared qmgr line
    const b = vm.runInContext("mdRecipients.findIndex(r => r.key === 'b@example.net')", h.context);
    h.context.pickMessageRecipient(b, true);
    const timeline = h.element('md-timeline-slot').innerHTML;
    assert.deepEqual(timelineLines(timeline), { all: 3, shared: 1 });
    assert.match(timeline, /3 of 5 entries/);
    assert.doesNotMatch(timeline, /for this recipient/);
    // The picker: a status dot for each recipient, problems first
    const options = [...timeline.matchAll(/role="option"[^>]*>(?:<i class="ui-fct-dot ?([^"]*)" aria-hidden="true"><\/i>)?<span>([^<]*)<\/span>/g)]
        .map(m => ({ tone: m[1] || '', label: m[2], dot: m[0].includes('ui-fct-dot') }));
    assert.deepEqual(options[0], { tone: '', label: 'All recipients', dot: false });
    const rank = { 'ui-fct-fail': 0, 'ui-fct-warn': 1, '': 2, 'ui-fct-ok': 3 };
    const ranks = options.slice(1).map(o => rank[o.tone]);
    assert.ok(options.slice(1).every(o => o.dot) && ranks.length === 4, JSON.stringify(options));
    assert.deepEqual(ranks, [...ranks].sort((a, b) => a - b), JSON.stringify(options));
    assert.ok(ranks[0] < ranks[ranks.length - 1], 'a problem leads, a delivery trails');
    assert.doesNotMatch(timeline.split('id="log-timeline-entries"')[1], /a@example\.net/, 'the lines, the picker lists everyone');
    assert.match(timeline, /is-shared[\s\S]*All recipients/);
    assert.match(h.element('md-rcpt-results').innerHTML, /aria-pressed="true" aria-label="[^"]+, show the logs of b@example\.net"/);
    // The same row again shows every recipient
    h.context.pickMessageRecipient(b, true);
    assert.match(h.element('md-timeline-slot').innerHTML, /5 entries/);
    // A count in the header opens the list filtered to its status
    h.context.showMessageRecipients('bounced');
    assert.match(h.element('message-modal-content').innerHTML, /aria-pressed="true" onclick="filterMessageRecipients\('bounced'\)"/);
    h.context.searchMessageRecipients('zzz');
    assert.match(h.element('md-rcpt-results').innerHTML, /No recipient matches/);
});

test('one recipient keeps its strip and error box, with no recipient list', async () => {
    const one = { ...message(), postfix: [{ time: '2026-01-01T00:00:00Z', recipient: 'recipient@example.com', status: 'bounced', relay: 'mx.example.net[192.0.2.9]:25',
        program: 'postfix/smtp', message: 'TEST123: to=<recipient@example.com>, status=bounced (host mx said: 550 5.1.1 No such user (in reply to RCPT TO command))' }] };
    const h = harness(one);
    await h.context.viewMessageDetails('example-key');
    h.context.switchModalTab('postfix');
    const logs = h.element('message-modal-content').innerHTML;
    assert.match(logs, /Final Status/);
    assert.match(logs, /Delivery Error/);
    assert.doesNotMatch(logs, /id="md-rcpts"/);
    assert.doesNotMatch(h.element('message-modal-header').innerHTML, /All \d+ recipients/);
    // The sender and the queue ID stay in the header and Overview, not in the strip
    const strip = logs.split('md-timeline-slot')[0];
    assert.doesNotMatch(strip, /<span>From<\/span>/);
    assert.doesNotMatch(strip, /Queue ID/);
    // The relay in its parts: the host, its IP in a tooltip, the port beside it
    assert.match(logs, /data-host="mx\.example\.net" data-ip="192\.0\.2\.9" data-tip="IP 192\.0\.2\.9"/);
    assert.match(logs, /<bdi>mx\.example\.net<\/bdi>/);
    assert.match(logs, /class="ui-md-relay-port">:25</);
    assert.doesNotMatch(logs.split('md-timeline-slot')[0], /mx\.example\.net\[192\.0\.2\.9\]:25/);
});

test('a relay splits into host, IP and port, and keeps any other form whole', () => {
    const h = harness(message());
    const parts = relay => JSON.parse(JSON.stringify(h.context.relayParts(relay)));
    assert.deepEqual(parts('dovecot[172.22.1.250]:24'), { host: 'dovecot', ip: '172.22.1.250', port: '24' });
    assert.deepEqual(parts('mx.example.net[2001:db8::25]:25'), { host: 'mx.example.net', ip: '2001:db8::25', port: '25' });
    assert.deepEqual(parts('none'), { host: 'none', ip: '', port: '' });
    assert.deepEqual(parts('private/dovecot-lmtp'), { host: 'private/dovecot-lmtp', ip: '', port: '' });
    // A server with no name: its IP is the name, with no tooltip repeating it
    const bare = h.context.renderRelay('192.0.2.9[192.0.2.9]:25');
    assert.doesNotMatch(bare, /data-tip/);
    assert.match(bare, /ui-md-relay-host ui-mono/);
    // Text from the logs stays text
    assert.doesNotMatch(h.context.renderRelay('x"><img src=x>[192.0.2.1]:25'), /<img/);
});

test('a recipient address from the logs is text, and its row opens it by position', async () => {
    const payload = '"><img src=x onerror=alert(1)>@example.net';
    const data = messageToMany();
    data.recipients.push(payload);
    data.postfix.push({ time: '2026-01-01T00:00:05Z', program: 'postfix/smtp', recipient: payload, status: "sent');alert(1);//", message: 'x' });
    const h = harness(data);
    await h.context.viewMessageDetails('example-key');
    h.context.switchModalTab('postfix');
    const html = h.element('message-modal-header').innerHTML + h.element('message-modal-content').innerHTML;
    assert.doesNotMatch(html, /<img/);
    assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
    // escapeJsArg keeps the quote inside the argument (\')
    assert.doesNotMatch(html, /[^\\]'\);alert\(1\)/, 'a status from the logs never closes a handler argument');
    assert.match(html, /pickMessageRecipient\(\d+, true\)/);
});

const smtp = (s, to, status, extra = '') => ({ time: `2026-01-01T00:00:0${s}Z`, program: 'postfix/smtp', recipient: to, status, relay: 'mx.example.net[192.0.2.9]:25',
    // A queue ID is hex, as the server reads it
    message: `4F1A2B3C9D: to=<${to}>, ${extra}relay=mx.example.net[192.0.2.9]:25, delay=1, delays=0/0/0/1, dsn=${status === 'sent' ? '2.0.0' : '4.0.0'}, status=${status} (host mx said: 451 4.7.1 Try later (in reply to RCPT TO command))` });

test('a delivery to an alias counts for the alias, not as another recipient', async () => {
    // Rspamd saw the alias; Postfix delivered to the mailbox and logged the alias as orig_to
    const one = { ...message(), recipients: ['team@example.com'], postfix: [smtp(1, 'dana@example.com', 'sent', 'orig_to=<team@example.com>, ')] };
    const h = harness(one);
    await h.context.viewMessageDetails('example-key');
    assert.doesNotMatch(h.element('message-modal-header').innerHTML, /recipients/, 'one recipient, not two');
    h.context.switchModalTab('postfix');
    assert.doesNotMatch(h.element('message-modal-content').innerHTML, /id="md-rcpts"/);

    const two = { ...messageToMany(), recipients: ['team@example.com', 'b@example.net'],
        postfix: [smtp(1, 'dana@example.com', 'sent', 'orig_to=<team@example.com>, '), smtp(2, 'b@example.net', 'sent')] };
    const h2 = harness(two);
    await h2.context.viewMessageDetails('example-key');
    assert.match(h2.element('message-modal-header').innerHTML, /Delivered to all 2 recipients/);
    h2.context.switchModalTab('postfix');
    const logs = h2.element('message-modal-content').innerHTML;
    assert.match(logs, /title="Show the logs of team@example\.com"[\s\S]*?ui-tag ui-tag-ok">Delivered/);
    assert.match(logs, /· to <bdi>dana@example\.com<\/bdi>/);
    // The alias's line is its own in the timeline
    const team = vm.runInContext("mdRecipients.findIndex(r => r.key === 'team@example.com')", h2.context);
    h2.context.pickMessageRecipient(team, true);
    assert.deepEqual(timelineLines(h2.element('md-timeline-slot').innerHTML), { all: 1, shared: 0 });
});

test('a message that expired in the queue expires the recipients still waiting', async () => {
    const data = { ...messageToMany(), final_status: 'expired', recipients: ['a@example.net', 'b@example.net', 'c@example.net'],
        postfix: [smtp(1, 'a@example.net', 'sent'), smtp(2, 'b@example.net', 'deferred'), smtp(3, 'b@example.net', 'deferred'),
            { time: '2026-01-01T00:00:09Z', program: 'postfix/qmgr', status: 'expired', message: 'TEST123: from=<sender@example.com>, status=expired, returned to sender' }] };
    const h = harness(data);
    await h.context.viewMessageDetails('example-key');
    const header = h.element('message-modal-header').innerHTML;
    assert.match(header, /Delivered to 1 of 3 recipients/);
    assert.match(header, />2 expired</);
    assert.doesNotMatch(header, /deferred|not logged/);
    const overview = h.element('message-modal-content').innerHTML;
    assert.match(overview, /Expired for 2 recipients/);
    assert.doesNotMatch(overview, /try again/i);
});

test('the recipients are listed with no Postfix lines, where the header links to them', async () => {
    const data = { ...messageToMany(), postfix: [] };
    const h = harness(data);
    await h.context.viewMessageDetails('example-key');
    assert.match(h.element('message-modal-header').innerHTML, /All 4 recipients/);
    h.context.switchModalTab('postfix');
    const logs = h.element('message-modal-content').innerHTML;
    assert.match(logs, /No Postfix delivery logs available/);
    assert.match(logs, /id="md-rcpts"/);
    assert.match(logs, /<bdi>d@example\.net<\/bdi>/);
});

test('a store cancels a pending Sieve discard; an explicit discard still shows', async () => {
    const lmtp = to => ({ ...smtp(1, to, 'sent'), program: 'postfix/lmtp', relay: 'dovecot[172.22.1.250]:24' });
    const line = (to, verdict, action) => ({ time: '2026-01-01T00:00:02Z', recipient: to, verdict, message: `lmtp(${to})<1><S>: sieve: msgid=<m@x>: ${action}` });
    const data = { ...messageToMany(), recipients: ['a@example.com', 'b@example.com'], postfix: [lmtp('a@example.com'), lmtp('b@example.com')],
        dovecot: { status: 'stored', mailbox: 'INBOX', logs: [
            line('a@example.com', 'discarded', 'marked message to be discarded if not explicitly delivered (discard action)'),
            line('a@example.com', 'stored', "stored mail into mailbox 'INBOX'"),
            line('b@example.com', 'stored', "stored mail into mailbox 'INBOX'"),
            line('b@example.com', 'discarded', 'discarded message'),
        ] } };
    const h = harness(data);
    await h.context.viewMessageDetails('example-key');
    h.context.switchModalTab('postfix');
    const rows = h.element('message-modal-content').innerHTML;
    const row = address => rows.split('ui-md-rrow"').find(r => r.includes(`<bdi>${address}</bdi>`));
    assert.doesNotMatch(row('a@example.com'), /Mailbox delivery/);
    assert.match(row('b@example.com'), /Mailbox delivery: Discarded by Sieve/);
});

// Regression: the message delivered twice to one mailbox, as a mailing list
// copy does; Sieve stored the first and dropped the second. Each LMTP session
// is its own delivery, as on the server, so the store hides no discard.
test('a store in one LMTP session does not cancel a discard in another', async () => {
    const lmtp = to => ({ ...smtp(1, to, 'sent'), program: 'postfix/lmtp', relay: 'dovecot[172.22.1.250]:24' });
    const line = (prefix, session, verdict, action) => ({ time: '2026-01-01T00:00:02Z', recipient: 'a@example.com', verdict,
        message: `${prefix}lmtp(a@example.com)<1234><${session}>: sieve: msgid=<m@x>: ${action}` });
    for (const prefix of ['', 'dovecot: ']) {
        const data = { ...messageToMany(), recipients: ['a@example.com', 'b@example.com'], postfix: [lmtp('a@example.com'), lmtp('b@example.com')],
            dovecot: { status: 'discarded', mailbox: null, logs: [
                line(prefix, 'S1', 'stored', "stored mail into mailbox 'INBOX'"),
                line(prefix, 'S2', 'discarded', 'marked message to be discarded if not explicitly delivered (discard action)'),
            ] } };
        const h = harness(data);
        await h.context.viewMessageDetails('example-key');
        h.context.switchModalTab('postfix');
        const rows = h.element('message-modal-content').innerHTML;
        const row = rows.split('ui-md-rrow"').find(r => r.includes('<bdi>a@example.com</bdi>'));
        assert.match(row, /Mailbox delivery: Discarded by Sieve/, `prefix "${prefix}"`);
    }
});

// Round 2: an alias reaching several mailboxes, a mailbox two aliases reach,
// and a mailbox Rspamd named itself
test('aliases and their mailboxes keep each delivery\'s own Dovecot verdict', async () => {
    const lmtp = (s, to, orig) => ({ ...smtp(s, to, 'sent', orig ? `orig_to=<${orig}>, ` : ''), program: 'postfix/lmtp', relay: 'dovecot[172.22.1.250]:24' });
    const line = (to, verdict, action) => ({ time: '2026-01-01T00:00:05Z', recipient: to, verdict, message: `lmtp(${to})<1><S>: sieve: msgid=<m@x>: ${action}` });
    const pending = to => line(to, 'discarded', 'marked message to be discarded if not explicitly delivered (discard action)');
    const stored = to => line(to, 'stored', "stored mail into mailbox 'INBOX'");
    // team@ reaches a@ (stored) and b@ (dropped); ops@ and sales@ both reach shared@ (dropped)
    const data = { ...messageToMany(), recipients: ['team@example.com', 'ops@example.com', 'sales@example.com'],
        postfix: [lmtp(1, 'a@example.com', 'team@example.com'), lmtp(2, 'b@example.com', 'team@example.com'),
            lmtp(3, 'shared@example.com', 'ops@example.com'), lmtp(4, 'shared@example.com', 'sales@example.com')],
        dovecot: { status: 'stored', mailbox: 'INBOX', logs: [stored('a@example.com'), pending('b@example.com'), pending('shared@example.com')] } };
    const h = harness(data);
    await h.context.viewMessageDetails('example-key');
    h.context.switchModalTab('postfix');
    const rows = h.element('message-modal-content').innerHTML;
    const row = address => rows.split('ui-md-rrow"').find(r => r.includes(`title="Show the logs of ${address}"`));
    assert.match(row('team@example.com'), /Mailbox delivery: Discarded by Sieve/, 'a store in a@ hides no discard in b@');
    assert.match(row('ops@example.com'), /Mailbox delivery: Discarded by Sieve/);
    assert.match(row('sales@example.com'), /Mailbox delivery: Discarded by Sieve/, 'the second alias of shared@ too');
    // shared@'s Dovecot line is in both aliases' timelines
    for (const alias of ['ops@example.com', 'sales@example.com']) {
        const i = vm.runInContext(`mdRecipients.findIndex(r => r.key === '${alias}')`, h.context);
        h.context.pickMessageRecipient(i);
        assert.deepEqual(timelineLines(h.element('md-timeline-slot').innerHTML), { all: 2, shared: 0 }, alias);
    }
    // The address opens its card on a click and copies from the icon beside it
    assert.match(row('team@example.com'), /<button type="button" class="ui-ent-btn" data-entity-kind="address" data-entity-value="team@example\.com"/);
    assert.match(row('team@example.com'), /data-entity-copy="team@example\.com"/);
    assert.doesNotMatch(row('team@example.com'), /onclick="copyToClipboard/);
});

test('a mailbox Rspamd named stays a recipient though an alias also reached it', async () => {
    const data = { ...messageToMany(), recipients: ['team@example.com', 'shared@example.com'],
        postfix: [smtp(1, 'shared@example.com', 'sent', 'orig_to=<team@example.com>, ')] };
    const h = harness(data);
    await h.context.viewMessageDetails('example-key');
    assert.match(h.element('message-modal-header').innerHTML, /To \(2\)/);
    // The API's own list from Postfix (no Rspamd) still hides the mailbox
    const fallback = { ...messageToMany(), recipients: ['shared@example.com'],
        postfix: [smtp(1, 'shared@example.com', 'sent', 'orig_to=<team@example.com>, ')] };
    const h2 = harness(fallback);
    await h2.context.viewMessageDetails('example-key');
    assert.doesNotMatch(h2.element('message-modal-header').innerHTML, /To \(2\)/);
});

test('a message to many names its one server in the strip, and each recipient its own server', async () => {
    const h = harness(messageToMany());
    await h.context.viewMessageDetails('example-key');
    h.context.switchModalTab('postfix');
    const strip = h.element('message-modal-content').innerHTML.split('id="md-rcpts"')[0];
    // d@ has no line yet: a recipient not tried went to no server, so the one
    // server every tried recipient went through still names the message's
    assert.match(strip, /<span>Relay<\/span>[\s\S]*data-host="mx\.example\.net" data-ip="192\.0\.2\.9"/);
    // A row names its server, port and IP; a click on the row opens it, not a copy
    const rows = h.context.renderRecipientRows();
    assert.match(rows, /class="ui-md-rrow-via">via <span class="ui-md-relay">\s*<span class="ui-md-relay-host" data-host="mx\.example\.net" data-ip="192\.0\.2\.9" data-tip="IP 192\.0\.2\.9"[^>]*><bdi>mx\.example\.net<\/bdi>/);
    assert.match(rows, /class="ui-md-relay-port">:25</);
    assert.doesNotMatch(rows, /copyToClipboard\('mx\.example\.net'/);

    // Two servers: the strip leaves the server to the rows
    const data = messageToMany();
    data.postfix.find(l => l.recipient === 'a@example.net').relay = 'mx2.example.org[198.51.100.7]:25';
    const h2 = harness(data);
    await h2.context.viewMessageDetails('example-key');
    h2.context.switchModalTab('postfix');
    assert.doesNotMatch(h2.element('message-modal-content').innerHTML.split('id="md-rcpts"')[0], /<span>Relay<\/span>/);
    assert.match(h2.context.renderRecipientRows(), /data-host="mx2\.example\.org"/);
});

test('the Recipients list filters the timeline too, and a picked recipient or a clear wins', async () => {
    const h = harness(messageToMany());
    await h.context.viewMessageDetails('example-key');
    h.context.switchModalTab('postfix');
    const timeline = () => h.element('md-timeline-slot').innerHTML;
    const view = () => JSON.parse(JSON.stringify(vm.runInContext('mdView', h.context)));

    // A status: the bounced recipient's line and the shared one
    h.context.filterMessageRecipients('bounced');
    assert.deepEqual(timelineLines(timeline()), { all: 2, shared: 1 });
    const rows = () => timeline().split('id="log-timeline-entries"')[1];
    assert.match(rows(), /to=&lt;c@example\.net&gt;/);
    assert.doesNotMatch(rows(), /to=&lt;[ab]@example\.net&gt;/, 'which lines, not only how many');
    assert.match(timeline(), /2 of 5 entries/);
    assert.match(timeline(), /<bdi>Bounced \(1\)<\/bdi>/);
    assert.match(timeline(), /aria-label="Show every recipient"/);

    // A search, with the status cleared: b@'s two lines and the shared one
    h.context.filterMessageRecipients('');
    h.context.searchMessageRecipients('b@');
    assert.deepEqual(timelineLines(timeline()), { all: 3, shared: 1 });
    assert.match(timeline(), /<bdi>&quot;b@&quot; \(1\)<\/bdi>/);

    // A picked recipient wins over the list's filter
    const a = vm.runInContext("mdRecipients.findIndex(r => r.key === 'a@example.net')", h.context);
    h.context.pickMessageRecipient(a);
    assert.deepEqual(timelineLines(timeline()), { all: 2, shared: 1 });

    // "All recipients" clears the pick and the list's filter
    h.context.pickMessageRecipient(-1);
    assert.equal(view().query, '');
    assert.equal(view().status, '');
    assert.match(timeline(), /5 entries/);
    assert.deepEqual(timelineLines(timeline()), { all: 5, shared: 0 });

    // A count in the header shows its recipients, not one picked before
    h.context.pickMessageRecipient(a);
    h.context.showMessageRecipients('deferred');
    assert.equal(view().picked, -1);
    // (the tab draws itself whole: the timeline is in the tab's content)
    assert.deepEqual(timelineLines(h.element('message-modal-content').innerHTML), { all: 3, shared: 1 });
});

test('a relay tooltip fits the width it has, shows on a tap or the focus, and a tap on it does not open the row', async () => {
    const h = harness(messageToMany());
    const host = (dataset, scrollWidth, clientWidth) => {
        const classes = new Set();
        return { dataset, querySelector: () => ({ scrollWidth, clientWidth }), tipTimer: null,
            classList: { add: c => classes.add(c), remove: c => classes.delete(c), contains: c => classes.has(c) } };
    };
    // Cut: the host and its IP; whole again after a resize: the IP alone
    const el = host({ host: 'mail-protection.example.com', ip: '192.0.2.9', tip: 'IP 192.0.2.9' }, 300, 120);
    h.context.mdRelayTipFit(el);
    assert.equal(el.dataset.tip, 'mail-protection.example.com · IP 192.0.2.9');
    el.querySelector = () => ({ scrollWidth: 300, clientWidth: 300 });
    h.context.mdRelayTipFit(el);
    assert.equal(el.dataset.tip, 'IP 192.0.2.9');
    // A cut socket path has a tooltip too, and a whole one none
    const socket = host({ host: 'private/dovecot-lmtp-with-a-long-name' }, 300, 120);
    h.context.mdRelayTipFit(socket);
    assert.equal(socket.dataset.tip, 'private/dovecot-lmtp-with-a-long-name');
    socket.querySelector = () => ({ scrollWidth: 120, clientWidth: 120 });
    h.context.mdRelayTipFit(socket);
    assert.equal(socket.dataset.tip, undefined);

    // Every host fits its tooltip on hover and focus and shows it on a tap; only the strip's takes the focus
    for (const relay of ['mx.example.net[192.0.2.9]:25', 'private/dovecot-lmtp']) {
        assert.match(h.context.renderRelay(relay), /tabindex="0" onpointerenter="mdRelayTipFit\(this\)" onfocus="mdRelayTipFit\(this\)" onpointerup="mdRelayTipTap\(event, this\)"/);
        assert.doesNotMatch(h.context.renderRelay(relay, false), /tabindex/);
    }

    // A tap shows the tooltip; the one click that follows it does not open the row
    const tapped = host({ host: 'mx.example.net', ip: '192.0.2.9', tip: 'IP 192.0.2.9' }, 100, 100);
    const clickOn = (el, pointerType) => h.context.mdRelayTapped({ pointerType, target: { closest: () => el } });
    h.context.mdRelayTipTap({ pointerType: 'touch' }, tapped);
    assert.ok(tapped.classList.contains('is-tip'));
    assert.equal(clickOn(tapped, 'touch'), true);
    assert.equal(clickOn(tapped, 'touch'), false, 'once: the next click opens the row, the tooltip still showing');
    assert.equal(h.context.mdRelayTapped({ target: { closest: () => null } }), false, 'a tap elsewhere in the row opens it');
    // A mouse click right after a tap opens the row: the tap's hold is not global
    h.context.mdRelayTipTap({ pointerType: 'touch' }, tapped);
    assert.equal(clickOn(tapped, 'mouse'), false);
    const other = host({ host: 'mx2.example.net', ip: '192.0.2.10', tip: 'IP 192.0.2.10' }, 100, 100);
    assert.equal(clickOn(other, 'touch'), false, 'a tap on one host holds no click on another');
    const hovered = host({ host: 'mx.example.net', ip: '192.0.2.9' }, 100, 100);
    h.context.mdRelayTipTap({ pointerType: 'mouse' }, hovered);
    assert.equal(clickOn(hovered, 'mouse'), false, 'a mouse click opens the row');
    // A row fits its relay's tooltip when its button takes the focus (after a resize too);
    // a click on the row, not on the tooltip, picks it
    await h.context.viewMessageDetails('example-key');
    const rows = h.context.renderRecipientRows();
    assert.match(rows, /onfocus="mdRelayTip\(this\.parentElement\)" class="ui-row-open/);
    assert.match(rows, /<div class="ui-md-rrow" title="[^"]*" onclick="if \(!uiRowHeld\(event\) && !mdRelayTapped\(event\)\) pickMessageRecipient/);
});

test('a message delivered twice: the header names both recipients, the logs stay this delivery\'s', async () => {
    // Delivery 1 (viewed) to a local mailbox, delivery 2 of the same message to an outside address
    const data = { ...message(), final_status: 'delivered', related_deliveries: [{ correlation_key: 'second-key', sender: 'sender@example.com',
        recipient: 'friend@outside.example.net', direction: 'outbound', final_status: 'deferred', first_seen: '2026-01-01T00:01:00Z',
        queue_id: 'TEST456', dovecot_status: null, dovecot_mailbox: null, recipients: ['friend@outside.example.net'] }] };
    const h = harness(data);
    await h.context.viewMessageDetails('example-key');
    const header = h.element('message-modal-header').innerHTML;
    assert.match(header, /To \(2\)/);
    assert.match(header, /data-entity-value="recipient@example\.com"[\s\S]*?<\/span>, <span class="ui-ent"><button[^>]*data-entity-value="friend@outside\.example\.net"/);
    assert.match(header, /All 2 recipients/);
    // The outcome is this delivery's: no "Delivered to 1 of 2"
    assert.doesNotMatch(header, /of 2 recipients/);

    const section = h.context.renderRecipientsSection();
    assert.match(section, /Recipients <span class="ui-muted">2<\/span>/);
    // This delivery's recipient keeps its own row, which shows its logs
    assert.match(section, /pickMessageRecipient\(0, true\)[\s\S]*recipient@example\.com/);
    // The other delivery's recipient shows that delivery's outcome and opens it
    const other = section.split('Other deliveries of this message')[1] || '';
    assert.match(other, /friend@outside\.example\.net/);
    assert.match(other, /viewMessageDetails\('second-key'\)/);
    assert.match(other, /Deferred/i);
    assert.doesNotMatch(other, /pickMessageRecipient/);
    // The status filter is this delivery's, which has one recipient: none is offered
    assert.doesNotMatch(section, /ui-chip-row/);
    // The Logs tab's card names this delivery's recipients as such, not as the message's To
    h.context.renderPostfixTab(h.element('content'), data);
    const logs = h.element('content').innerHTML;
    assert.match(logs, /This delivery \(1\)/);
    assert.doesNotMatch(logs, /To \(1\)/);
});

test('a delivery with nothing logged yet names the one recipient another delivery reached', async () => {
    const data = { ...message(), recipient: null, recipients: [], postfix: [],
        related_deliveries: [{ correlation_key: 'second-key', sender: 'sender@example.com', recipient: 'friend@outside.example.net',
            direction: 'outbound', final_status: 'delivered', first_seen: '2026-01-01T00:01:00Z', queue_id: 'TEST456',
            dovecot_status: null, dovecot_mailbox: null, recipients: ['friend@outside.example.net'] }] };
    const h = harness(data);
    await h.context.viewMessageDetails('example-key');
    const header = h.element('message-modal-header').innerHTML;
    const to = header.split('<span>To</span>')[1] || '';
    assert.match(to, /^<div>[\s\S]*friend@outside\.example\.net/);
    assert.doesNotMatch(to.split('</div>')[0], />-</);
    assert.doesNotMatch(header, /All \d+ recipients/);
});
