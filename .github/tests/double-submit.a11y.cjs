// One press, one action (uiOnce in utils.js), in a real DOM (jsdom): a second press
// while the first is still on its way (a double click) sends nothing, so a rule or
// a destination is not created twice and a switch is not flipped back. The button
// is off and says what it does meanwhile, and has its own words back after.
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

// The server answers when the test lets it (window.answerAll), like a slow network
const STUBS = `
    window.requests = [];
    window.waiting = [];
    window.answerAll = () => { window.waiting.splice(0).forEach(go => go()); };
    authenticatedFetch = (url, options = {}) => {
        const method = (options.method || 'GET').toUpperCase();
        window.requests.push({ url, method });
        const body = method === 'GET' ? (url.startsWith('/api/quarantine/rules') ? { data: [] } : {}) : { id: 1, status: 'success' };
        const answer = { ok: true, status: 200, headers: { get: () => 'application/json' }, json: async () => body, clone() { return this; } };
        if (method === 'GET' && !window.holdGets) return Promise.resolve(answer);
        return new Promise(resolve => window.waiting.push(() => resolve(answer)));
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
const posts = (w, part) => w.requests.filter(r => r.method !== 'GET' && r.url.includes(part)).length;

test('a double click on Create Rule creates one rule; the button says so meanwhile and comes back', async () => {
    const w = page();
    w.eval('showAddQuarantineRuleModal()');
    w.document.getElementById('qrule-name').value = 'Newsletter';
    w.document.getElementById('qrule-match-value').value = 'news@example.com';
    const button = [...w.document.querySelectorAll('button')].find(b => b.textContent.trim() === 'Create Rule');
    assert.ok(button, 'the dialog has its Create Rule button');
    button.click();
    button.click();
    await settle(w);
    assert.equal(posts(w, '/api/quarantine/rules'), 1);
    assert.equal(button.disabled, true);
    assert.equal(button.textContent, 'Creating...');
    assert.equal(button.getAttribute('aria-busy'), 'true');
    w.answerAll();
    await settle(w);
    assert.equal(button.textContent, 'Create Rule');
    assert.equal(button.disabled, false);
    assert.equal(button.hasAttribute('aria-busy'), false);
    // Once the first is done, the next press acts again
    await w.eval('saveQuarantineRuleOnce(null)');
    assert.equal(posts(w, '/api/quarantine/rules'), 1, 'the dialog closed with the save: nothing left to send');
});

test('a double click on a switch flips it once', async () => {
    const w = page();
    w.eval('toggleSuppressionOnce(7, false); toggleSuppressionOnce(7, false)');
    w.eval('toggleQuarantineRuleOnce(3); toggleQuarantineRuleOnce(3)');
    await settle(w);
    assert.equal(posts(w, '/api/suppressions/7'), 1);
    assert.equal(posts(w, '/api/quarantine/rules/3/toggle'), 1);
    // Another row is another action
    w.eval('toggleSuppressionOnce(8, false)');
    await settle(w);
    assert.equal(posts(w, '/api/suppressions/8'), 1);
});

test('a destination saved twice in a row is added once', async () => {
    const w = page();
    const form = w.document.createElement('form');
    const submit = w.document.createElement('button');
    submit.type = 'submit';
    submit.textContent = 'Save';
    form.appendChild(submit);
    w.document.body.appendChild(form);
    w.notificationEditing = { name: 'Ops', channel_type: 'slack', config: {}, enabled: true };
    const event = () => ({ preventDefault() {}, submitter: submit });
    w.eval('_collectChannelForm = () => ({ name: "Ops", channel_type: "slack", config: {}, enabled: true, alert_types: [] })');
    w.saveNotificationChannelOnce(event());
    w.saveNotificationChannelOnce(event());
    await settle(w);
    assert.equal(posts(w, '/api/notifications/channels'), 1);
    assert.equal(submit.textContent, 'Saving...');
    w.answerAll();
    await settle(w);
    assert.equal(submit.textContent, 'Save');
});

test('a save that is done does not hold the next dialog while the list reloads', async () => {
    const w = page();
    w.holdGets = true;
    const create = () => {
        w.eval('showAddQuarantineRuleModal()');
        w.document.getElementById('qrule-name').value = 'Newsletter';
        w.document.getElementById('qrule-match-value').value = 'news@example.com';
        return [...w.document.querySelectorAll('button')].find(b => b.textContent.trim() === 'Create Rule' && b.isConnected);
    };
    create().click();
    await settle(w);
    // The rule is saved and its dialog closed; the list's reload is still on its way
    w.answerAll();
    await settle(w);
    assert.equal(posts(w, '/api/quarantine/rules'), 1);
    create().click();
    await settle(w);
    assert.equal(posts(w, '/api/quarantine/rules'), 2);
});
