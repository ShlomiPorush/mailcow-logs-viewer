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
                querySelector: () => null,
            });
        }
        return elements.get(id);
    };
    const requests = [];
    const document = {
        body: { style: {} }, getElementById: element,
        querySelectorAll: () => ['overview', 'postfix', 'spam', 'netfilter'].map(tab => element('modal-tab-' + tab)),
        addEventListener: (name, handler) => { listeners[name] = handler; },
    };
    const context = vm.createContext({ document, window: { disabledFeatures: [] }, console: { log() {}, error() {} },
        authenticatedFetch: async url => { requests.push(url); return { ok, status: 500, statusText: 'Test failure', json: async () => data }; },
        renderGeoIPInfo: () => '', appTimezone: 'UTC',
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
    assert.equal(h.context.renderDeliveriesChip({ deliveries: 2 }), '<span>Deliveries: 2</span>');
    assert.equal(h.context.renderDeliveriesChip({ deliveries: 1 }), '');
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
    assert.match(timeline, /2 for this recipient, 1 shared/);
    assert.doesNotMatch(timeline.split('id="log-timeline-entries"')[1], /a@example\.net/, 'the lines, the picker lists everyone');
    assert.match(timeline, /is-shared[\s\S]*All recipients/);
    assert.match(h.element('md-rcpt-results').innerHTML, /aria-pressed="true" title="Show the logs of b@example\.net"/);
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
    // The sender shows; the queue ID stays in Overview only
    assert.match(logs, /sender@example\.com/);
    assert.doesNotMatch(logs, /Queue ID/);
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
    assert.match(h2.element('md-timeline-slot').innerHTML, /1 for this recipient, 0 shared/);
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
        assert.match(h.element('md-timeline-slot').innerHTML, /2 for this recipient, 0 shared/, alias);
    }
    // The address is copied with a click, as before
    assert.match(row('team@example.com'), /copyToClipboard\('team@example\.com', event\)/);
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
