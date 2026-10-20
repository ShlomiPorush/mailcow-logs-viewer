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

test('a stacked list gets a Sort picker: a column sorts, the same column again turns it around', () => {
    const w = page(LIST);
    w.uiRefreshTableSorts();
    const select = w.document.querySelector('#list .ui-phone-sort select');
    assert.ok(select, 'the list has a Sort picker');
    assert.deepEqual([...select.options].map(o => o.textContent), ['Default order', 'Name', 'Count']);
    assert.ok(w.document.querySelector('#list .ui-phone-sort .ui-picker'), 'shown as the shared picker');
    select.value = '0';
    w.uiPhoneSortPick(select);
    assert.deepEqual(names(w), ['alpha', 'beta']);
    w.uiRefreshTableSorts();
    assert.equal(select.selectedOptions[0].dataset.short, 'Name ↑');
    select.value = '0';
    w.uiPhoneSortPick(select);
    assert.deepEqual(names(w), ['beta', 'alpha'], 'picked again: turned around');
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

test('the phone Sort picker keeps its id when its list is drawn again', () => {
    const w = page(LIST);
    w.uiRefreshTableSorts();
    const id = w.document.querySelector('#list .ui-phone-sort select').id;
    assert.equal(id, 'ui-phone-sort-list');
    w.document.getElementById('list').innerHTML = w.document.getElementById('list').innerHTML.replace(/<div class="ui-phone-sort">[\s\S]*?<\/select><\/div>/, '');
    w.uiRefreshTableSorts();
    assert.equal(w.document.querySelector('#list .ui-phone-sort select').id, 'ui-phone-sort-list');
});

test('a list with a sort control of its own gets no second one', () => {
    const w = page(LIST.replace('class="ui-table ui-stack"', 'class="ui-table ui-stack" data-phone-sort="off"'));
    w.uiRefreshTableSorts();
    assert.equal(w.document.querySelector('.ui-phone-sort'), null);
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
