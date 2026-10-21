// Keyboard and screen reader (utils.js): sortable headers are buttons, a phone
// gets a Sort picker for a list whose header it hides, and a row that opens on
// click opens on Enter and Space. Runs in a real DOM (jsdom) with axe-core,
// installed by CI outside the repository; set A11Y_MODULES to run it locally:
//   npm install --no-save --prefix /tmp/a11y jsdom axe-core
//   A11Y_MODULES=/tmp/a11y/node_modules node --test .github/tests/keyboard.a11y.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));
const axeSource = fs.readFileSync(path.join(modules, 'axe-core', 'axe.min.js'), 'utf8');
const utils = fs.readFileSync(path.join(__dirname, '../../frontend/utils.js'), 'utf8');

function page(body) {
    const dom = new JSDOM(`<!doctype html><html lang="en"><head><title>t</title><style>.hidden{display:none}</style></head><body><main><h1>List</h1>${body}</main></body></html>`,
        { runScripts: 'dangerously', pretendToBeVisual: true });
    const w = dom.window;
    w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    // jsdom does no layout: an element counts as shown when nothing hides it
    w.Element.prototype.getClientRects = function () { return this.isConnected && !this.closest('.hidden') ? [{}] : []; };
    const script = w.document.createElement('script');
    script.textContent = utils;
    w.document.head.appendChild(script);
    w.eval(axeSource);
    return w;
}
const frame = w => new Promise(resolve => w.requestAnimationFrame(() => setTimeout(resolve, 0)));
const key = (w, el, k) => el.dispatchEvent(new w.KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true }));

async function noViolations(w, what) {
    const result = await w.axe.run(w.document, { rules: { 'color-contrast': { enabled: false } } });
    const found = [...result.violations].map(v => `${v.id}: ${v.help} (${v.nodes.map(n => n.target.join(' ')).join(', ')})`);
    assert.deepEqual(found, [], `${what} has accessibility violations`);
}

const LIST = `<section id="list"><div class="ui-table ui-stack">
    <div class="ui-tr ui-tr-head"><span>Name</span><span>Count</span><span>Actions</span></div>
    <div class="ui-tr"><span>beta</span><span>2</span><span><button type="button">Edit</button></span></div>
    <div class="ui-tr"><span>alpha</span><span>10</span><span><button type="button">Edit</button></span></div>
</div></section>`;
const names = w => [...w.document.querySelectorAll('#list .ui-tr:not(.ui-tr-head) > span:first-child')].map(s => s.textContent);

test('a list header is a button: it sorts, says its order in words, and keeps no aria-sort', async () => {
    const w = page(LIST);
    w.uiRefreshTableSorts();
    const [name, count, actions] = w.document.querySelectorAll('#list .ui-tr-head > span');
    const button = name.querySelector('.ui-sort-btn');
    assert.ok(button, 'Name holds a button');
    assert.equal(actions.querySelector('.ui-sort-btn'), null, 'Actions does not sort');
    assert.equal(name.hasAttribute('aria-sort'), false, 'no aria-sort outside a real column header');
    assert.equal(name.dataset.sortState, 'none');
    const key1 = w.uiTableKey(w.document.querySelector('#list .ui-table'));
    button.click();
    assert.deepEqual(names(w), ['alpha', 'beta']);
    assert.equal(name.dataset.sortState, 'ascending');
    assert.match(button.textContent, /sorted ascending/);
    assert.equal(w.uiTableKey(w.document.querySelector('#list .ui-table')), key1, 'the order said in words does not change the remembered key');
    count.querySelector('.ui-sort-btn').click();
    assert.deepEqual(names(w), ['alpha', 'beta'], 'numbers high to low first');
    assert.equal(count.dataset.sortState, 'descending');
    assert.equal(name.dataset.sortState, 'none');
    await noViolations(w, 'a sorted list');
});

test('a real table keeps aria-sort on its column header', async () => {
    const w = page(`<table id="t"><thead><tr><th>Domain</th><th>Messages</th></tr></thead>
        <tbody><tr><td>b.example</td><td>1</td></tr><tr><td>a.example</td><td>5</td></tr></tbody></table>`);
    w.uiRefreshTableSorts();
    const th = w.document.querySelector('th');
    assert.equal(th.getAttribute('aria-sort'), 'none');
    th.querySelector('.ui-sort-btn').click();
    assert.equal(th.getAttribute('aria-sort'), 'ascending');
    assert.equal(th.querySelector('.ui-sort-said').textContent, '', 'aria-sort says it already');
    await noViolations(w, 'a sorted table');
});

test('a table in help text does not sort', () => {
    const w = page('<div class="markdown-body"><table><thead><tr><th>Action</th><th>Effect</th></tr></thead><tbody><tr><td>b</td><td>x</td></tr></tbody></table></div>');
    w.uiRefreshTableSorts();
    const th = w.document.querySelector('th');
    assert.equal(th.querySelector('.ui-sort-btn'), null);
    assert.equal(th.hasAttribute('aria-sort'), false);
    th.click();
    assert.equal(th.hasAttribute('data-sort-state'), false);
});

const SORTED = (attrs = '') => `<section id="list"><div class="ui-fbar-row"><label class="ui-search"><input id="q" aria-label="Search things"></label></div>
    <div class="ui-table ui-stack" data-sort-at="q" data-sort-name="things" ${attrs}>
    <div class="ui-tr ui-tr-head"><span data-sort-kind="text">Name</span><span data-sort-kind="number">Count</span><span>Actions</span></div>
    <div class="ui-tr"><span>beta</span><span>2</span><span><button type="button">Edit</button></span></div>
    <div class="ui-tr"><span>gamma</span><span>5</span><span><button type="button">Edit</button></span></div>
    <div class="ui-tr"><span>alpha</span><span>10</span><span><button type="button">Edit</button></span></div>
</div></section>`;
const sortParts = w => {
    const slot = w.document.querySelector('.ui-sort-slot');
    const radio = (group, value) => slot.querySelector(`input[name$="-${group}"][value="${value}"]`);
    return { slot, button: slot.querySelector('.ui-picker-btn'), panel: slot.querySelector('.ui-picker-panel'), radio,
        dirs: slot.querySelector('.ui-sort-dir'), checked: group => (slot.querySelector(`input[name$="-${group}"]:checked`) || {}).value };
};

test('a list gets a Sort button beside its search: its menu sorts by a column and an order, and Default order puts the list back', async () => {
    const w = page(SORTED());
    w.uiRefreshTableSorts();
    const { slot, button, panel, radio, dirs, checked } = sortParts(w);
    assert.equal(slot.previousElementSibling, w.document.querySelector('.ui-search'), 'right after the search box');
    assert.equal(button.getAttribute('aria-haspopup'), 'dialog');
    assert.equal(button.getAttribute('aria-label'), 'Sort: Default order');
    assert.equal(panel.getAttribute('role'), 'dialog');
    assert.equal(panel.getAttribute('aria-label'), 'Sort things');
    assert.deepEqual([...panel.querySelectorAll('legend')].map(l => l.textContent), ['Sort by', 'Order']);
    assert.deepEqual([...panel.querySelectorAll('fieldset')[0].querySelectorAll('label')].map(l => l.textContent.trim()), ['Default order', 'Name', 'Count'], 'Actions is not a column to sort by');
    assert.equal(checked('by'), '', 'Default order is chosen');
    assert.equal(dirs.disabled, true, 'no order for the list\'s own order');
    radio('by', '0').click();
    assert.deepEqual(names(w), ['alpha', 'beta', 'gamma'], 'Name starts A to Z');
    w.uiRefreshTableSorts();
    assert.equal(button.getAttribute('aria-label'), 'Sort: Name, A to Z');
    assert.ok(button.classList.contains('is-set'), 'an order of its own stands out');
    assert.equal(dirs.disabled, false);
    assert.deepEqual([...dirs.querySelectorAll('label')].map(l => l.textContent.trim()), ['A to Z', 'Z to A']);
    radio('dir', '-1').click();
    assert.deepEqual(names(w), ['gamma', 'beta', 'alpha'], 'Z to A');
    radio('by', '1').click();
    assert.deepEqual(names(w), ['alpha', 'gamma', 'beta'], 'Count starts high to low');
    w.uiRefreshTableSorts();
    assert.equal(button.getAttribute('aria-label'), 'Sort: Count, High to low');
    w.uiPickerOpen(w.document.querySelector('.ui-sort-slot .ui-picker').dataset.picker);
    await noViolations(w, 'an open Sort menu');
    radio('by', '').click();
    assert.deepEqual(names(w), ['beta', 'gamma', 'alpha'], 'Default order: the order the list came in');
    w.uiRefreshTableSorts();
    assert.equal(button.getAttribute('aria-label'), 'Sort: Default order');
    assert.equal(button.classList.contains('is-set'), false);
    assert.ok([...w.document.querySelectorAll('#list .ui-tr-head > span')].every(h => h.dataset.sortState !== 'ascending' && h.dataset.sortState !== 'descending'), 'no header shows an order');
});

test('a header and the Sort button show the same order', () => {
    const w = page(SORTED());
    w.uiRefreshTableSorts();
    w.document.querySelectorAll('#list .ui-tr-head .ui-sort-btn')[1].click();
    w.uiRefreshTableSorts();
    const { button, checked } = sortParts(w);
    assert.equal(button.getAttribute('aria-label'), 'Sort: Count, High to low');
    assert.equal(checked('by'), '1');
    assert.equal(checked('dir'), '-1');
});

test('a list that arrives in a column\'s order shows it, offers no Default order, and stands out only when changed', () => {
    const w = page(SORTED('data-sort-default="Count:desc"'));
    w.uiRefreshTableSorts();
    const { button, panel, radio, checked } = sortParts(w);
    assert.equal(button.getAttribute('aria-label'), 'Sort: Count, High to low');
    assert.equal(button.classList.contains('is-set'), false);
    assert.equal(panel.querySelector('input[value=""]'), null, 'no Default order item');
    assert.equal(checked('by'), '1');
    radio('dir', '1').click();
    w.uiRefreshTableSorts();
    assert.equal(button.getAttribute('aria-label'), 'Sort: Count, Low to high');
    assert.ok(button.classList.contains('is-set'));
});

test('a list sorted on the server asks for the column and the order, and a second choice builds on the first before the answer', () => {
    const w = page(`<section id="srv"><label class="ui-search"><input id="sq" aria-label="Search"></label><div class="ui-table ui-stack" data-sort-handler="sortServer" data-sort-at="sq" data-sort-default="Seen:desc">
        <div class="ui-tr ui-tr-head"><span data-sort-key="name" data-sort-kind="text" aria-sort="none">Name</span><span data-sort-key="seen" data-sort-kind="date" aria-sort="descending">Seen</span></div>
        <div class="ui-tr"><span>a</span><span>1</span></div></div></section>`);
    const asked = [];
    w.sortServer = (key, dir) => asked.push(`${key}:${dir}`);   // the answer has not come yet
    w.uiRefreshTableSorts();
    const { radio } = sortParts(w);
    radio('by', '0').click();
    w.uiRefreshTableSorts();
    radio('dir', '-1').click();
    assert.deepEqual(asked, ['name:asc', 'name:desc']);
});

test('the Sort button stays one, keeps its id across redraws, and goes with its list', () => {
    const w = page(SORTED());
    w.uiRefreshTableSorts();
    const id = w.document.querySelector('.ui-sort-slot .ui-picker').dataset.picker;
    const table = w.document.querySelector('#list .ui-table');
    table.outerHTML = table.outerHTML;   // the page draws the list again
    w.uiRefreshTableSorts();
    w.uiRefreshTableSorts();
    assert.equal(w.document.querySelectorAll('.ui-sort-slot').length, 1);
    assert.equal(w.document.querySelector('.ui-sort-slot .ui-picker').dataset.picker, id);
    w.document.querySelector('#list .ui-table').remove();
    w.uiRefreshTableSorts();
    assert.equal(w.document.querySelector('.ui-sort-slot'), null);
});

test('a list without a place for it, or that says so, gets no Sort button; data-nosort does not sort at all', () => {
    for (const attrs of ['data-sort-icon="off"', 'data-nosort']) {
        const w = page(SORTED(attrs));
        w.uiRefreshTableSorts();
        assert.equal(w.document.querySelector('.ui-sort-slot'), null, attrs);
        if (attrs === 'data-nosort') assert.equal(w.document.querySelector('#list .ui-sort-btn'), null, 'no header sorts');
    }
    const w = page(LIST);
    w.uiRefreshTableSorts();
    assert.equal(w.document.querySelector('.ui-sort-slot'), null, 'no data-sort-at');
});

test('a helper element in a row (the phone line break) is not a cell', () => {
    const w = page(`<section id="h"><div class="ui-table ui-stack">
        <div class="ui-tr ui-tr-head"><span>Date</span><span>Status</span><span>Created</span></div>
        <div class="ui-tr"><span>a</span><span>ok</span><span class="ui-tr-break"></span><span>3</span></div>
        <div class="ui-tr"><span>b</span><span>ok</span><span class="ui-tr-break"></span><span>7</span></div>
        <div class="ui-tr"><span>c</span><span>ok</span><span class="ui-tr-break"></span><span>1</span></div></div></section>`);
    w.uiRefreshTableSorts();
    w.document.querySelectorAll('#h .ui-sort-btn')[2].click();
    assert.deepEqual([...w.document.querySelectorAll('#h .ui-tr:not(.ui-tr-head) > span:first-child')].map(s => s.textContent), ['b', 'a', 'c']);
});

test('rows drawn anew in the same list get its remembered order', () => {
    const w = page(SORTED());
    w.uiRefreshTableSorts();
    sortParts(w).radio('by', '0').click();
    const table = w.document.querySelector('#list .ui-table');
    // A filter draws the rows again inside the same element, in the list's own order
    table.innerHTML = table.innerHTML.replace(/<div class="ui-tr"[\s\S]*$/, '') + '<div class="ui-tr"><span>zeta</span><span>1</span><span></span></div><div class="ui-tr"><span>delta</span><span>4</span><span></span></div>';
    w.uiRefreshTableSorts();
    assert.deepEqual(names(w), ['delta', 'zeta']);
});

test('a list sorted on the server gets the focus back on the same header once it is drawn again', async () => {
    const list = dir => `<div class="ui-table ui-stack" data-sort-handler="sortServer">
        <div class="ui-tr ui-tr-head"><span data-sort-key="name" aria-sort="${dir}">Name</span><span data-sort-key="n" aria-sort="none">Count</span></div>
        <div class="ui-tr"><span>a</span><span>1</span></div></div>`;
    const w = page(`<section id="srv">${list('none')}</section>`);
    w.sortServer = (key, dir) => { setTimeout(() => { w.document.getElementById('srv').innerHTML = list(dir === 'asc' ? 'ascending' : 'descending'); }, 20); };
    w.uiRefreshTableSorts();
    const button = w.document.querySelector('#srv .ui-sort-btn');
    button.focus();
    button.click();
    await new Promise(resolve => setTimeout(resolve, 40));
    w.uiRefreshTableSorts();   // what the page's observer does once the new list is there
    const active = w.document.activeElement;
    assert.ok(active.matches('.ui-sort-btn'), `focus is on a header button again, not ${active.tagName}.${active.className}`);
    assert.equal(active.closest('[data-sort-key]').dataset.sortKey, 'name');
    assert.equal(active.closest('[data-sort-key]').dataset.sortState, 'ascending');
});

test('moving on before the sorted list comes back keeps the focus where the user put it', async () => {
    const list = dir => `<div class="ui-table ui-stack" data-sort-handler="sortServer">
        <div class="ui-tr ui-tr-head"><span data-sort-key="name" aria-sort="${dir}">Name</span></div>
        <div class="ui-tr"><span>a</span></div></div>`;
    const w = page(`<section id="srv">${list('none')}</section><button id="elsewhere">Elsewhere</button>`);
    w.sortServer = () => { setTimeout(() => { w.document.getElementById('srv').innerHTML = list('ascending'); }, 20); };
    w.uiRefreshTableSorts();
    const button = w.document.querySelector('#srv .ui-sort-btn');
    button.focus();
    button.click();
    w.document.getElementById('elsewhere').focus();
    await new Promise(resolve => setTimeout(resolve, 40));
    w.uiRefreshTableSorts();
    assert.equal(w.document.activeElement.id, 'elsewhere');
});

test('an answer with no list ends the wait for it', async () => {
    const w = page(`<section id="srv"><div class="ui-table ui-stack" data-sort-handler="sortServer">
        <div class="ui-tr ui-tr-head"><span data-sort-key="name" aria-sort="none">Name</span></div><div class="ui-tr"><span>a</span></div></div></section>`);
    w.sortServer = () => { w.document.getElementById('srv').innerHTML = '<p>Nothing found</p>'; };
    w.uiRefreshTableSorts();
    const button = w.document.querySelector('#srv .ui-sort-btn');
    button.focus();
    button.click();
    w.uiRefreshTableSorts();
    assert.equal(w.eval('uiSortFocus'), null);
});

test('every stacked list with a header row says where its Sort button goes, or that it has none', () => {
    const dir = path.join(__dirname, '../../frontend');
    const missing = [];
    for (const f of fs.readdirSync(dir).filter(n => n.endsWith('.js') || n.endsWith('.html'))) {
        const text = fs.readFileSync(path.join(dir, f), 'utf8');
        for (const m of text.matchAll(/<(div|table)\b[^>]*class="[^"]*\b(ui-stack|ui-dm-cards)\b[^"]*"[^>]*>/g)) {
            // A list with no header row (a rule list, a map) has no columns to sort by
            const after = text.slice(m.index, m.index + 700);
            if (!/ui-tr-head|<thead/.test(after)) continue;
            if (/data-sort-at=|data-nosort|data-sort-icon="off"/.test(m[0])) continue;
            missing.push(`${f}:${text.slice(0, m.index).split('\n').length}`);
        }
    }
    assert.deepEqual(missing, []);
});

test('a row that opens on click opens on Enter and Space, and its own button keeps its keys', () => {
    const w = page('<div id="row" class="ui-tr" role="button" tabindex="0" data-row-open onclick="window.opened = (window.opened || 0) + 1">Row <button type="button" id="inner">Copy</button></div>');
    const row = w.document.getElementById('row');
    key(w, row, 'Enter');
    key(w, row, ' ');
    assert.equal(w.opened, 2);
    key(w, w.document.getElementById('inner'), 'Enter');
    assert.equal(w.opened, 2, 'Enter on the inner button is not the row');
    key(w, row, 'a');
    assert.equal(w.opened, 2);
});

test('selecting text in a row leaves it closed; a plain click, a control inside and Enter still work', () => {
    const w = page(`<p id="elsewhere">Other text</p>
        <table><tbody><tr id="row" class="is-go" onclick="if (!uiRowHeld(event)) window.opened = (window.opened || 0) + 1"><td id="cell">mail.example.com</td><td><button type="button" id="inner" onclick="event.stopPropagation(); window.pressed = (window.pressed || 0) + 1">Edit</button></td></tr></tbody></table>
        <div id="msg" class="ui-mrow" role="button" tabindex="0" data-row-open onclick="if (!uiRowHeld(event)) window.shown = (window.shown || 0) + 1"><span id="subject">Subject</span></div>`);
    const d = w.document;
    let pageClicks = 0;
    d.addEventListener('click', () => { pageClicks++; });   // an outside-click closer, like a picker's
    // A press at x, then the click at x2 (a drag when they differ); detail 2 is a double click
    const gesture = (el, x, x2 = x, detail = 1) => {
        el.dispatchEvent(new w.MouseEvent('mousedown', { bubbles: true, clientX: x, clientY: 5, detail }));
        el.dispatchEvent(new w.MouseEvent('click', { bubbles: true, cancelable: true, clientX: x2, clientY: 5, detail }));
    };
    const select = el => { const range = d.createRange(); range.selectNodeContents(el); w.getSelection().removeAllRanges(); w.getSelection().addRange(range); };
    const cell = d.getElementById('cell');
    gesture(cell, 10);
    assert.equal(w.opened, 1, 'a plain click opens the row');
    select(cell);
    gesture(cell, 10, 80);
    assert.equal(w.opened, 1, 'a drag that selects text in the row opens nothing');
    assert.equal(String(w.getSelection()), 'mail.example.com', 'the selection stays for copying');
    assert.equal(pageClicks, 2, 'the held click still reaches the rest of the page');
    gesture(cell, 20);
    assert.equal(w.opened, 2, 'a plain click on text already selected opens the row');
    gesture(cell, 10, 80);
    assert.equal(w.opened, 2, 'dragging over the same text again opens nothing');
    gesture(cell, 20, 20, 2);
    assert.equal(w.opened, 2, 'a double click that selects a word opens nothing more');
    select(cell);
    cell.dispatchEvent(new w.MouseEvent('mousedown', { bubbles: true, clientX: 40, clientY: 5, detail: 1, shiftKey: true }));
    cell.dispatchEvent(new w.MouseEvent('click', { bubbles: true, cancelable: true, clientX: 40, clientY: 5, detail: 1, shiftKey: true }));
    assert.equal(w.opened, 2, 'Shift+click that extends a selection in the row opens nothing');
    gesture(d.getElementById('inner'), 30, 90);
    assert.equal(w.pressed, 1, 'a button inside keeps its click');
    select(d.getElementById('subject'));
    gesture(d.getElementById('subject'), 10, 80);
    assert.equal(w.shown, undefined, 'a div row that opens on click is held too');
    key(w, d.getElementById('msg'), 'Enter');
    assert.equal(w.shown, 1, 'Enter opens the row even with text selected in it');
    select(d.getElementById('elsewhere'));
    gesture(cell, 10, 80);
    assert.equal(w.opened, 3, 'a selection outside the row does not hold it');
});

test('every element that is not a control and opens on click asks uiRowHeld first', () => {
    const dir = path.join(__dirname, '../../frontend');
    const files = fs.readdirSync(dir).filter(f => f.endsWith('.js') || f.endsWith('.html'))
        .map(f => ({ f, text: fs.readFileSync(path.join(dir, f), 'utf8') }));
    const all = files.map(x => x.text).join('\n');
    // Helpers a row hands its click to must ask too
    const asks = name => {
        const at = all.indexOf(`function ${name}(`);
        return at >= 0 && all.slice(at, all.indexOf('\n}', at)).includes('uiRowHeld(event)');
    };
    // Handlers that only keep the click inside, or close a backdrop clicked itself, open nothing
    const inert = /^(?:event\.stopPropagation\(\)|if \(uiBackdropClick\(event\)\) \w+\(\)|if \(event\.target\.closest\('button'\)\) this\.hidePopover\(\))$/;
    // Not rows: a Settings choice card is the control that picks, and a sheet's backdrop holds no text
    const notRows = /^(?:settingsPickCard|uiSheetDismiss)\(/;
    const missing = [];
    for (const { f, text } of files) {
        for (const m of text.matchAll(/<(div|tr|td|li|article|section|span)\b([^<>]*?)\bonclick="([^"]*)"/g)) {
            const handler = m[3].trim();
            if (/\bcopyable\b/.test(m[2]) || inert.test(handler) || notRows.test(handler) || handler.startsWith('if (!uiRowHeld(event))')) continue;
            const helper = handler.match(/(\w+)\(event\b/);
            if (helper && asks(helper[1])) continue;
            missing.push(`${f}:${text.slice(0, m.index).split('\n').length} ${handler.slice(0, 60)}`);
        }
    }
    assert.deepEqual(missing, []);
});

test('a drag that selects text in a dialog and ends on the backdrop leaves it open; a click on the backdrop closes it', () => {
    const w = page(`<div id="back" class="ui-dialog-backdrop" onclick="if (uiBackdropClick(event)) window.closed = (window.closed || 0) + 1">
        <div class="ui-dialog"><p id="text">Message-ID: abc@example.com</p></div></div>`);
    const d = w.document;
    const back = d.getElementById('back');
    const gesture = (from, to, x, x2) => {
        from.dispatchEvent(new w.MouseEvent('mousedown', { bubbles: true, clientX: x, clientY: 5, detail: 1 }));
        to.dispatchEvent(new w.MouseEvent('click', { bubbles: true, cancelable: true, clientX: x2, clientY: 5, detail: 1 }));
    };
    // The browser sends the click of a drag to the element that holds both ends
    gesture(d.getElementById('text'), back, 10, 400);
    assert.equal(w.closed, undefined, 'a drag from the text onto the backdrop leaves the dialog open');
    gesture(d.getElementById('text'), d.getElementById('text'), 10, 10);
    assert.equal(w.closed, undefined, 'a click in the dialog leaves it open');
    gesture(back, back, 400, 400);
    assert.equal(w.closed, 1, 'a click on the backdrop closes it');
    back.click();
    assert.equal(w.closed, 2, 'a click with no mouse on the backdrop closes it');
});

test('a click on a log line selects the line, and the log knows while text is held in it', () => {
    const w = page(`<div id="log" data-line-select=".line"><div class="line" id="one"><span id="t1">10:00</span> first line</div><div class="line" id="two">second line</div></div><p id="other">Other text</p>`);
    const d = w.document;
    const log = d.getElementById('log');
    const press = (el, x, detail = 1, extra = {}) => el.dispatchEvent(new w.MouseEvent('mousedown', { bubbles: true, clientX: x, clientY: 5, detail, buttons: 1, ...extra }));
    const click = (el, x, detail = 1, extra = {}) => el.dispatchEvent(new w.MouseEvent('click', { bubbles: true, cancelable: true, clientX: x, clientY: 5, detail, ...extra }));
    const release = el => el.dispatchEvent(new w.MouseEvent('mouseup', { bubbles: true }));
    press(d.getElementById('t1'), 10); release(d.getElementById('t1')); click(d.getElementById('t1'), 10);
    assert.equal(String(w.getSelection()), '10:00 first line', 'a plain click selects the whole line');
    const copy = d.querySelector('#one > .ui-line-copy');
    assert.ok(copy, 'the line gets a Copy button');
    assert.equal(copy.getAttribute('aria-label'), 'Copy line');
    const range = w.getSelection().getRangeAt(0);
    assert.ok(range.endContainer === copy.parentNode && range.endOffset <= [...copy.parentNode.childNodes].indexOf(copy), 'the button is not part of the selection');
    assert.equal(w.uiTextHeld(log), true, 'a selection in the log holds it');
    w.getSelection().removeAllRanges();
    press(d.getElementById('two'), 10); release(d.getElementById('two')); click(d.getElementById('two'), 80);
    assert.equal(String(w.getSelection()), '', 'the end of a drag is left to the browser');
    click(d.getElementById('two'), 10, 2);
    assert.equal(String(w.getSelection()), '', 'a double click is left to the browser');
    press(d.getElementById('two'), 10); release(d.getElementById('two')); click(d.getElementById('two'), 10, 1, { shiftKey: true });
    assert.equal(String(w.getSelection()), '', 'Shift+click is left to the browser');
    press(d.getElementById('two'), 10); click(d.getElementById('two'), 10);
    press(d.getElementById('two'), 10, 2);
    assert.equal(String(w.getSelection()), '', 'the second press of a double click clears the line so the browser selects the word');
    press(d.getElementById('two'), 10); release(d.getElementById('two')); click(d.getElementById('two'), 10);
    press(d.getElementById('one'), 10, 2, { shiftKey: true });
    assert.equal(String(w.getSelection()), 'second line', 'Shift with a repeated press keeps the selection it extends');
    w.getSelection().removeAllRanges();
    assert.equal(w.uiTextHeld(log), true, 'a press held in the log holds it');
    d.dispatchEvent(new w.MouseEvent('mousemove', { buttons: 0 }));
    assert.equal(w.uiTextHeld(log), false, 'moving with no button down ends a press whose release was lost');
    press(d.getElementById('two'), 10);
    w.dispatchEvent(new w.Event('blur'));
    assert.equal(w.uiTextHeld(log), false, 'leaving the window ends the press');
    press(d.getElementById('other'), 10);
    assert.equal(w.uiTextHeld(log), false, 'a press elsewhere does not hold the log');
});

test('every dialog that closes on a backdrop click asks uiBackdropClick', () => {
    const dir = path.join(__dirname, '../../frontend');
    const found = [];
    for (const f of fs.readdirSync(dir).filter(n => n.endsWith('.js') || n.endsWith('.html'))) {
        fs.readFileSync(path.join(dir, f), 'utf8').split('\n').forEach((line, i) => {
            // A key handler on a row may compare the target with itself; that is not a backdrop
            if (/\.target(?:\.id)? === (?:this\b|\w*(?:modal|overlay|Modal|Overlay)\b|'[\w-]*-modal')/.test(line) && !/onkeydown|\.key ===/.test(line)) found.push(`${f}:${i + 1}`);
        });
    }
    assert.deepEqual(found, []);
});
