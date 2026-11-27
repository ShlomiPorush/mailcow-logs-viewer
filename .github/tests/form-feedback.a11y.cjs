const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || path.join(__dirname, 'node_modules');
const { JSDOM } = require(path.join(modules, 'jsdom'));

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');
const PAGE = new JSDOM(read('index.html')).window.document;
PAGE.querySelectorAll('script').forEach(el => el.remove());
const BODY = PAGE.body.innerHTML;
const SCRIPTS = [...read('index.html').matchAll(/src="\/static\/([a-z_-]+\.js)/g)].map(m => m[1]).filter(name => name !== 'session-guard.js');

const STUBS = `
    window.requests = [];
    authenticatedFetch = (url, options = {}) => {
        const method = (options.method || 'GET').toUpperCase();
        window.requests.push({ url, method, body: options.body });
        const body = method === 'GET' ? { data: [], items: [] } : { id: 1, status: 'success' };
        return Promise.resolve({ ok: true, status: 200, headers: { get: () => 'application/json' }, json: async () => body, clone() { return this; } });
    };
    uiMayAct = () => true;
    checkAuthentication = async () => false;`;

function page() {
    const dom = new JSDOM(`<!doctype html><html lang="en"><head><title>t</title></head><body>${BODY}</body></html>`,
        { runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/quarantine' });
    const w = dom.window;
    w.Element.prototype.scrollIntoView = function () {};
    w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    w.HTMLElement.prototype.hidePopover = function () {};
    w.HTMLElement.prototype.showPopover = function () {};
    const run = source => { const s = w.document.createElement('script'); s.textContent = source; w.document.head.appendChild(s); };
    SCRIPTS.forEach(name => run(read(name)));
    run(STUBS);
    return w;
}
const settle = async w => { for (let i = 0; i < 10; i++) await new Promise(resolve => w.setTimeout(resolve, 0)); };
const sent = (w, url, method) => w.requests.filter(r => r.method === method && r.url === url);

test('a rule without a name says so under the name field, takes the focus there and sends nothing', async () => {
    const w = page();
    w.eval('showAddQuarantineRuleModal()');
    const name = w.document.getElementById('qrule-name');
    w.document.getElementById('qrule-match-value').value = 'news@example.com';
    assert.match(name.closest('label').querySelector('.ui-label').textContent, /\*/, 'the name is marked as required');
    [...w.document.querySelectorAll('button')].find(b => b.textContent.trim() === 'Create Rule').click();
    await settle(w);
    assert.equal(sent(w, '/api/quarantine/rules', 'POST').length, 0);
    const note = w.document.getElementById('qrule-name-invalid');
    assert.ok(note, 'the problem is shown under the field');
    assert.equal(note.textContent, 'Enter a name for the rule.');
    assert.ok(name.closest('label').contains(note));
    assert.equal(name.getAttribute('aria-invalid'), 'true');
    assert.match(name.getAttribute('aria-describedby'), /qrule-name-invalid/);
    assert.equal(w.document.activeElement, name);
    name.value = 'Newsletter';
    name.dispatchEvent(new w.Event('input', { bubbles: true }));
    assert.equal(w.document.getElementById('qrule-name-invalid'), null);
    assert.equal(name.hasAttribute('aria-invalid'), false);
    await w.eval('saveQuarantineRule(null)');
    assert.equal(sent(w, '/api/quarantine/rules', 'POST').length, 1);
});

async function addDomain(w, typed) {
    w.eval('showAddSuppressionModal()');
    w.document.getElementById('new-suppression-type').value = 'domain';
    w.eval('updateSuppressionInputPlaceholder()');
    w.document.getElementById('new-suppression-email').value = typed;
    await w.eval('createSuppression()');
    await settle(w);
    const posts = sent(w, '/api/suppressions', 'POST');
    return posts.length ? JSON.parse(posts[posts.length - 1].body).email : null;
}

test('a domain typed with a leading @ or a trailing dot makes the same pattern as the plain domain', async () => {
    assert.equal(await addDomain(page(), 'example.com'), '/^.+@example\\.com$/i');
    assert.equal(await addDomain(page(), '@example.com'), '/^.+@example\\.com$/i');
    assert.equal(await addDomain(page(), 'example.com.'), '/^.+@example\\.com$/i');
    assert.equal(await addDomain(page(), ' @Example.COM. '), '/^.+@example\\.com$/i');
});

test('*.example.com is refused under the field: only the domain itself is blocked', async () => {
    const w = page();
    assert.equal(await addDomain(w, '*.example.com'), null);
    assert.equal(w.document.getElementById('new-suppression-email-invalid').textContent,
        'Enter the domain without "*." - only that domain is blocked, not its subdomains.');
    const other = page();
    assert.equal(await addDomain(other, 'exa mple.com'), null);
    assert.equal(other.document.getElementById('new-suppression-email-invalid').textContent, 'Enter a plain domain name, for example example.com');
    const empty = page();
    assert.equal(await addDomain(empty, ''), null);
    assert.equal(empty.document.getElementById('new-suppression-email-invalid').textContent, 'Enter a domain name.');
    assert.equal(empty.document.activeElement, empty.document.getElementById('new-suppression-email'));
});

test('the whitelist takes addresses apart by lines, commas, semicolons and spaces', () => {
    const w = page();
    assert.deepEqual([...w.eval(`smtpAbuseWhitelistLines('a@example.com, b@example.com;c@example.com\\n d@example.com  e@example.com\\r\\n')`)],
        ['a@example.com', 'b@example.com', 'c@example.com', 'd@example.com', 'e@example.com']);
});

test('removing a whitelisted mailbox asks first; Cancel removes nothing', async () => {
    const w = page();
    const url = '/api/smtp-abuse/whitelist/a%40example.com';
    w.eval(`removeSmtpAbuseWhitelist('a@example.com')`);
    await settle(w);
    assert.match(w.document.getElementById('app-confirm-modal').textContent, /blocked automatically again/);
    w.document.getElementById('app-confirm-cancel').click();
    await settle(w);
    assert.equal(sent(w, url, 'DELETE').length, 0);
    w.eval(`removeSmtpAbuseWhitelist('a@example.com')`);
    await settle(w);
    w.document.getElementById('app-confirm-ok').click();
    await settle(w);
    assert.equal(sent(w, url, 'DELETE').length, 1);
});
