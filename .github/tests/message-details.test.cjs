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
            elements.set(id, { id, innerHTML: '', style: {}, dataset: {},
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
    assert.match(h.element('message-modal-content').innerHTML, /sender@example.com/);
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
    assert.equal(h.element('modal-tab-netfilter').innerHTML, '<span class="text-sm font-medium">Security</span>');
});

test('right-to-left mail content keeps its own direction', async () => {
    // Written as escapes so the source stays ASCII; renders as a Hebrew subject
    const rtl = '\u05e9\u05dc\u05d5\u05dd (1)';
    const h = harness({ ...message(), subject: rtl });
    await h.context.viewMessageDetails('example-key');
    const html = h.element('message-modal-content').innerHTML;
    assert.ok(html.includes(`dir="auto" title="${rtl}">${rtl}</p>`));
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

test('message listeners close on backdrop and Escape', async () => {
    const h = harness(message());
    h.listeners.DOMContentLoaded();
    await h.context.viewMessageDetails('example-key');
    h.listeners['message-modal:click']({ target: { id: 'message-modal-content' } });
    assert.equal(h.element('message-modal').classList.contains('hidden'), false);
    h.listeners['message-modal:click']({ target: { id: 'message-modal' } });
    assert.equal(h.element('message-modal').classList.contains('hidden'), true);
    await h.context.viewMessageDetails('example-key');
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
