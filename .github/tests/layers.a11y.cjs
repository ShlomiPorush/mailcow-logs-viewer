// Layers (router.js): dialogs and sheets. Escape and Back close the top layer
// only, focus moves into a layer and back to its opener, and what lies under the
// top layer is inert. Runs in a real DOM (jsdom), installed by CI outside the
// repository; set A11Y_MODULES to its node_modules to run it locally:
//   npm install --no-save --prefix /tmp/a11y jsdom axe-core
//   A11Y_MODULES=/tmp/a11y/node_modules node --test .github/tests/layers.a11y.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');
const utils = read('utils.js');
const router = read('router.js');

const STYLE = `.hidden { display: none; } .ui-dialog-backdrop { z-index: 50; } .ui-sheet { z-index: 70; } .ui-confirm { z-index: 99999; }`;

function page(body, extra = []) {
    const dom = new JSDOM(`<!doctype html><html lang="en"><head><title>t</title><style>${STYLE}</style></head><body>${body}</body></html>`,
        { runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/messages' });
    const w = dom.window;
    // jsdom does no layout: an element counts as shown when nothing hides it
    w.Element.prototype.getClientRects = function () {
        return this.isConnected && !this.closest('.hidden') ? [{}] : [];
    };
    w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    // jsdom has no inert property; browsers reflect it to the attribute
    if (!('inert' in w.HTMLElement.prototype)) {
        Object.defineProperty(w.HTMLElement.prototype, 'inert', { configurable: true,
            get() { return this.hasAttribute('inert'); },
            set(value) { if (value) this.setAttribute('inert', ''); else this.removeAttribute('inert'); } });
    }
    // As script elements, so the files share their top-level names as in a browser
    const run = source => {
        const script = w.document.createElement('script');
        script.textContent = source;
        w.document.head.appendChild(script);
    };
    [utils, router, ...extra, 'watchOverlays();'].forEach(run);
    w.run = run;
    return w;
}

const frame = w => new Promise(resolve => w.requestAnimationFrame(() => setTimeout(resolve, 0)));
const settle = async w => { await frame(w); await frame(w); };
const escape = (w, target) => {
    const event = new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true });
    (target || w.document.activeElement || w.document.body).dispatchEvent(event);
    return event;
};

const DIALOG = `
    <main class="ui-shell"><section class="ui-page"><h1>Page</h1>
        <button id="opener" type="button">Open</button><button id="other" type="button">Other</button></section></main>
    <div id="dlg" class="hidden ui-dialog-backdrop" role="dialog" aria-label="Details">
        <div class="ui-dialog"><div class="ui-dialog-head"><h3>Details</h3>
            <button type="button" aria-label="Close" onclick="document.getElementById('dlg').classList.add('hidden')">x</button></div>
            <div class="ui-dialog-body"><p>Text</p></div></div>
    </div>`;

async function openDialog(w) {
    const opener = w.document.getElementById('opener');
    opener.dispatchEvent(new w.Event('pointerdown', { bubbles: true }));
    opener.focus();
    w.document.getElementById('dlg').classList.remove('hidden');
    await settle(w);
}

test('a sheet over a dialog: Escape closes the sheet, the next Escape the dialog', async () => {
    const w = page(DIALOG);
    await openDialog(w);
    w.uiSheetShow('help-sheet', { label: 'Help', head: '<h3>Help</h3>', body: '<p>Help text</p>' });
    await settle(w);
    assert.equal(w.openOverlays().length, 2);
    const first = escape(w);
    assert.equal(first.defaultPrevented, true);
    await settle(w);
    assert.equal(w.document.getElementById('help-sheet'), null, 'the sheet closed');
    assert.equal(w.document.getElementById('dlg').classList.contains('hidden'), false, 'the dialog under it stayed open');
    escape(w);
    await settle(w);
    assert.equal(w.document.getElementById('dlg').classList.contains('hidden'), true);
});

test('one Escape never reaches a listener of the dialog underneath', async () => {
    const w = page(DIALOG);
    await openDialog(w);
    let heard = 0;
    w.document.addEventListener('keydown', event => { if (event.key === 'Escape') heard++; });
    w.document.addEventListener('keydown', event => { if (event.key === 'Escape') heard++; }, true);
    escape(w);
    assert.equal(heard, 0);
});

test('a picker open inside the top layer closes first, on its own Escape', async () => {
    const w = page(DIALOG);
    await openDialog(w);
    w.document.querySelector('#dlg .ui-dialog-body').insertAdjacentHTML('beforeend', '<span id="p-panel" class="ui-picker-panel"></span>');
    w.run("uiPickers.open = 'p'");
    assert.equal(w.layerChildOwnsEscape(w.document.getElementById('dlg')), true, 'the layers leave this Escape to the picker');
    escape(w);
    await settle(w);
    assert.equal(w.document.getElementById('dlg').classList.contains('hidden'), false, 'the dialog stays open');
});

test('focus moves into the dialog, the page behind is inert, and both come back on close', async () => {
    const w = page(DIALOG);
    await openDialog(w);
    const dlg = w.document.getElementById('dlg');
    assert.ok(dlg.contains(w.document.activeElement), 'focus is in the dialog');
    assert.equal(w.document.querySelector('main').inert, true, 'the page is inert');
    assert.equal(dlg.inert, false);
    assert.equal(dlg.getAttribute('aria-modal'), 'true');
    escape(w);
    await settle(w);
    assert.equal(w.document.querySelector('main').inert, false, 'the page is usable again');
    assert.equal(w.document.activeElement.id, 'opener', 'focus is back on what opened it');
});

test('the page keeps its own inert parts when a dialog closes', async () => {
    const w = page(DIALOG.replace('<button id="other"', '<div id="own" inert></div><button id="other"'));
    await openDialog(w);
    escape(w);
    await settle(w);
    assert.equal(w.document.getElementById('own').inert, true);
});

test('a toast stays usable over a dialog', async () => {
    const w = page(DIALOG);
    await openDialog(w);
    w.showToast('Saved', 'success');
    await settle(w);
    assert.equal(w.document.getElementById('toast-notification').inert, false);
});

test('the confirm dialog cancels on Escape and on a click outside', async () => {
    const w = page(DIALOG);
    let answer = w.showConfirmModal({ title: 'Delete?', message: 'Sure?' });
    await settle(w);
    escape(w);
    assert.equal(await answer, false);
    answer = w.showConfirmModal({ title: 'Delete?', message: 'Sure?' });
    await settle(w);
    const overlay = w.document.getElementById('app-confirm-modal');
    overlay.dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
    assert.equal(await answer, false);
});

test('a typed dialog closes at once while unchanged and asks once something changed', async () => {
    const w = page(`<main class="ui-shell"></main>
        <div id="form-dlg" class="ui-dialog-backdrop" role="dialog" aria-label="Edit">
            <div class="ui-dialog"><input id="f-name" value="a"><input id="f-on" type="checkbox">
            <select id="f-kind"><option>x</option><option>y</option></select>
            <button type="button" data-cancel onclick="uiCancelDialog('form-dlg')">Cancel</button></div></div>`);
    w.uiGuardDialog(w.document.getElementById('form-dlg'));
    await w.uiCloseGuarded(w.document.getElementById('form-dlg'), () => w.document.getElementById('form-dlg').remove());
    assert.equal(w.document.getElementById('form-dlg'), null, 'unchanged: closed without asking');
});

test('Keep editing keeps the dialog, Discard drops it, and every change kind counts', async () => {
    for (const change of [
        d => { d.getElementById('f-name').value = 'b'; },
        d => { d.getElementById('f-on').checked = true; },
        d => { d.getElementById('f-kind').selectedIndex = 1; },
    ]) {
        const w = page(`<main class="ui-shell"></main>
            <div id="form-dlg" class="ui-dialog-backdrop" role="dialog" aria-label="Edit">
                <div class="ui-dialog"><input id="f-name" value="a"><input id="f-on" type="checkbox">
                <select id="f-kind"><option>x</option><option>y</option></select></div></div>`);
        const dlg = w.document.getElementById('form-dlg');
        w.uiGuardDialog(dlg);
        change(w.document);
        let closing = w.uiCloseGuarded(dlg, () => dlg.remove());
        await settle(w);
        // A second close while the question is open asks nothing more
        await w.uiCloseGuarded(dlg, () => dlg.remove());
        assert.equal(w.document.querySelectorAll('#app-confirm-modal').length, 1);
        w.document.getElementById('app-confirm-cancel').click();
        await closing;
        assert.ok(dlg.isConnected, 'Keep editing keeps the dialog');
        closing = w.uiCloseGuarded(dlg, () => dlg.remove());
        await settle(w);
        w.document.getElementById('app-confirm-ok').click();
        await closing;
        assert.equal(dlg.isConnected, false, 'Discard closes it');
    }
});

test('Back closes the top layer through its Close button', async () => {
    const w = page(DIALOG);
    await openDialog(w);
    assert.equal(w.closeTopOverlay(), true);
    await settle(w);
    assert.equal(w.document.getElementById('dlg').classList.contains('hidden'), true);
    assert.equal(w.closeTopOverlay(), false, 'nothing left to close');
});

test('a dialog is aria-modal only while open, so the docked reading pane is not', async () => {
    const w = page(DIALOG);
    await openDialog(w);
    const dlg = w.document.getElementById('dlg');
    assert.equal(dlg.getAttribute('aria-modal'), 'true');
    escape(w);
    await settle(w);
    assert.equal(dlg.hasAttribute('aria-modal'), false);
});

test('a sheet drawn again in place keeps the focus inside it', async () => {
    const w = page(DIALOG);
    w.uiSheetShow('s', { label: 'Address', head: '<h3>Address</h3>', body: '<p>Loading</p>' });
    await settle(w);
    w.document.querySelector('#s .ui-sheet-x').focus();
    w.uiSheetShow('s', { label: 'Address', head: '<h3>Address</h3>', body: '<p>Loaded</p>' });
    await settle(w);
    assert.ok(w.document.getElementById('s').contains(w.document.activeElement), 'focus is back in the sheet');
});

test('the phone search gets the focus back when the result that opened a message is gone', async () => {
    const w = page('<main class="ui-shell"><div class="ui-gs is-sheet"><input id="q"><div class="ui-gs-panel"></div></div></main>');
    w.layerFocusIn(w.document.querySelector('.ui-gs'));
    assert.equal(w.document.activeElement.id, 'q');
});

test('a save closes the dialog and drops a discard question still open for it', async () => {
    const w = page(`<main class="ui-shell"></main>
        <div id="form-dlg" class="ui-dialog-backdrop" role="dialog" aria-label="Edit"><div class="ui-dialog"><input id="f-name" value="a"></div></div>`);
    const dlg = w.document.getElementById('form-dlg');
    w.uiGuardDialog(dlg);
    w.document.getElementById('f-name').value = 'b';
    const closing = w.uiCloseGuarded(dlg, () => dlg.remove());
    await settle(w);
    assert.ok(w.document.getElementById('app-confirm-modal'), 'the question is open');
    w.uiDialogSaved(dlg);
    dlg.remove();
    await closing;
    assert.equal(w.document.getElementById('app-confirm-modal'), null, 'the question went with the saved dialog');
});

test('a connection test reply for a closed or older window is dropped', async () => {
    const w = page('<main class="ui-shell"></main>', [read('settings.js')]);
    const first = w.showConnectionTestModal('SMTP Connection Test', 'Testing...');
    const second = w.showConnectionTestModal('Notification Test', 'Sending...');
    assert.equal(w.document.querySelectorAll('#connection-test-modal').length, 1, 'one window at a time');
    w.updateConnectionTestModal('success', ['✓ smtp'], first);
    assert.doesNotMatch(w.document.getElementById('connection-test-content').innerHTML, /smtp/);
    w.updateConnectionTestModal('error', ['✗ webhook'], second);
    assert.match(w.document.getElementById('connection-test-content').innerHTML, /webhook/);
});
