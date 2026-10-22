// A toast with an action (utils.js showToast): Undo after a dismissal, Retry after
// a failure. Its role, the action's own name, the keyboard's place when a toast
// is replaced, a pause while it has the focus, and a failure that stays until
// closed. Runs in a real DOM (jsdom), installed by CI outside the repository;
// set A11Y_MODULES to run it locally:
//   npm install --no-save --prefix /tmp/a11y jsdom axe-core
//   A11Y_MODULES=/tmp/a11y/node_modules node --test .github/tests/toast-action.a11y.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));
const axeSource = fs.readFileSync(require.resolve(path.join(modules, 'axe-core')), 'utf8');
const utils = fs.readFileSync(path.join(__dirname, '../../frontend/utils.js'), 'utf8');

function page() {
    const dom = new JSDOM('<!doctype html><html lang="en"><head><title>t</title></head><body><main><button id="row">Dismiss</button></main></body></html>',
        { runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/dashboard' });
    const w = dom.window;
    const script = w.document.createElement('script');
    script.textContent = utils;
    w.document.head.appendChild(script);
    return w;
}
const wait = ms => new Promise(r => setTimeout(r, ms));

test('Undo is a named button in a status toast, runs once and closes the toast', async () => {
    const w = page();
    const undone = [];
    w.showToast('Alert dismissed', 'success', { duration: 10000, action: { label: 'Undo', ariaLabel: "Undo dismissing Unusual sending: alice@example.com", onAction: () => undone.push(1) } });
    const toast = w.document.getElementById('toast-notification');
    assert.equal(toast.getAttribute('role'), 'status');
    const undo = toast.querySelector('.ui-toast-action');
    assert.equal(undo.textContent, 'Undo');
    assert.equal(undo.getAttribute('aria-label'), 'Undo dismissing Unusual sending: alice@example.com');
    const script = w.document.createElement('script');
    script.textContent = axeSource;
    w.document.head.appendChild(script);
    const result = await w.axe.run(toast, { rules: { 'color-contrast': { enabled: false } } });
    assert.equal(result.violations.length, 0, result.violations.map(v => v.id).join(', '));
    undo.click();
    assert.deepEqual(undone, [1]);
    assert.equal(w.document.getElementById('toast-notification'), null);
});

test('a toast replaced while the keyboard is in it hands the keyboard to the new one', () => {
    const w = page();
    w.showToast('Alert dismissed', 'success', { action: { label: 'Undo', onAction() {} } });
    w.document.querySelector('#toast-notification .ui-toast-action').focus();
    w.showToast('2 alerts dismissed', 'success', { action: { label: 'Undo', onAction() {} } });
    assert.equal(w.document.querySelectorAll('#toast-notification').length, 1);
    assert.equal(w.document.activeElement.textContent, 'Undo');
    assert.ok(w.document.getElementById('toast-notification').contains(w.document.activeElement));
    // Not in it: the keyboard stays where it was
    w.document.getElementById('row').focus();
    w.showToast('Saved', 'success');
    assert.equal(w.document.activeElement.id, 'row');
});

test('a toast waits while it has the focus, and goes after its own time without it', async () => {
    const w = page();
    w.showToast('Alert dismissed', 'success', { duration: 120, action: { label: 'Undo', onAction() {} } });
    w.document.querySelector('#toast-notification .ui-toast-action').focus();
    await wait(400);
    assert.ok(w.document.getElementById('toast-notification'), 'kept while focused');
    w.document.getElementById('row').focus();
    await wait(2200);
    assert.equal(w.document.getElementById('toast-notification'), null, 'gone after at least 1.5 seconds more');
});

test('a failure with Retry is an alert and stays until it is closed', async () => {
    const w = page();
    let tries = 0;
    w.showToast('Could not undo: the server answered 500.', 'error', { duration: Infinity, action: { label: 'Retry', ariaLabel: 'Retry: Undo dismissing 2 alerts', onAction: () => tries++ } });
    const toast = w.document.getElementById('toast-notification');
    assert.equal(toast.getAttribute('role'), 'alert');
    await wait(4500);
    assert.ok(w.document.getElementById('toast-notification'), 'still there');
    toast.querySelector('.ui-toast-action').click();
    assert.equal(tries, 1);
});

test('a toast without an action is as before', () => {
    const w = page();
    w.showToast('Saved', 'success');
    const toast = w.document.getElementById('toast-notification');
    assert.equal(toast.querySelector('.ui-toast-action'), null);
    assert.equal(toast.querySelectorAll('button').length, 1);
});

test('a toast that takes the keyboard over from the one it replaced stays while it has it', async () => {
    const w = page();
    w.showToast('Alert dismissed', 'success', { duration: 120, action: { label: 'Undo', onAction() {} } });
    w.document.querySelector('#toast-notification .ui-toast-action').focus();
    w.showToast('2 alerts dismissed', 'success', { duration: 120, action: { label: 'Undo', onAction() {} } });
    await wait(500);
    assert.ok(w.document.getElementById('toast-notification'), 'still there');
    assert.ok(w.document.getElementById('toast-notification').contains(w.document.activeElement));
});

test('an action that takes time keeps its toast and the keyboard, and a failure hands the keyboard to Retry', async () => {
    const w = page();
    w.showToast('Alert dismissed', 'success', { duration: 10000, action: { label: 'Undo', onAction: () => new w.Promise(resolve => setTimeout(() => {
        w.showToast('Could not undo: the server answered 500.', 'error', { duration: Infinity, action: { label: 'Retry', onAction() {} } });
        resolve();
    }, 50)) } });
    const undo = w.document.querySelector('#toast-notification .ui-toast-action');
    undo.focus();
    undo.click();
    assert.ok(w.document.getElementById('toast-notification'), 'the toast waits for the action');
    assert.equal(undo.getAttribute('aria-disabled'), 'true');
    await wait(150);
    assert.equal(w.document.activeElement.textContent, 'Retry');
    assert.equal(w.document.getElementById('toast-notification').getAttribute('role'), 'alert');
});

test('an action still running holds its toast after the pointer and the keyboard leave it', async () => {
    const w = page();
    let finish;
    w.showToast('Alert dismissed', 'success', { duration: 60, action: { label: 'Undo', onAction: () => new w.Promise(r => { finish = r; }) } });
    const toast = w.document.getElementById('toast-notification');
    toast.querySelector('.ui-toast-action').focus();
    toast.querySelector('.ui-toast-action').click();
    w.document.getElementById('row').focus();
    await wait(2200);
    assert.ok(toast.isConnected, 'still there while the action runs');
    finish();
    await wait(50);
    assert.equal(toast.isConnected, false, 'gone once it is done');
});
