// Accessibility of the pickers (utils.js, uiPicker): the shared drop-down that
// filters lists. Runs in a real DOM (jsdom) with axe-core, both installed by CI
// outside the repository; set A11Y_MODULES to their node_modules to run it locally:
//   npm install --no-save --prefix /tmp/a11y jsdom axe-core
//   A11Y_MODULES=/tmp/a11y/node_modules node --test .github/tests/pickers.a11y.cjs
// The keyboard and focus behaviour follows the WAI-ARIA listbox and dialog patterns.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));
const axeSource = fs.readFileSync(path.join(modules, 'axe-core', 'axe.min.js'), 'utf8');

const frontend = path.join(__dirname, '../../frontend');
const utils = fs.readFileSync(path.join(frontend, 'utils.js'), 'utf8');
const indexHtml = fs.readFileSync(path.join(frontend, 'index.html'), 'utf8');

function page(body) {
    const dom = new JSDOM(`<!doctype html><html lang="en"><head><title>t</title><style>.hidden{display:none}</style></head><body>${body}</body></html>`,
        { runScripts: 'dangerously', pretendToBeVisual: true });
    dom.window.eval(utils);
    dom.window.eval(axeSource);
    return dom.window;
}

const frame = w => new Promise(resolve => w.requestAnimationFrame(() => resolve()));
const key = (w, el, k) => el.dispatchEvent(new w.KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true }));

async function noViolations(w, what) {
    // jsdom does not lay out text, so colour contrast is checked in the browser, not here
    const result = await w.axe.run(w.document, { rules: { 'color-contrast': { enabled: false } } });
    const found = [...result.violations].map(v => `${v.id}: ${v.help} (${v.nodes.map(n => n.target.join(' ')).join(', ')})`);
    assert.deepEqual(found, [], `${what} has accessibility violations`);
}

function listPage() {
    const w = page('<main><h1>List</h1><div id="slot"></div><button id="outside">Elsewhere</button></main>');
    w.picked = [];
    w.document.getElementById('slot').innerHTML = w.uiPicker({
        id: 'period', label: 'Period', value: 'Last 7 days',
        options: [
            { label: 'Last 24 hours', selected: false, onclick: "picked.push('1')" },
            { label: 'Last 7 days', selected: true, onclick: "picked.push('7')" },
            { label: 'Last 30 days', selected: false, onclick: "picked.push('30')" },
        ],
    });
    const button = w.document.querySelector('.ui-picker-btn');
    const panel = w.document.getElementById(button.getAttribute('aria-controls'));
    return { w, button, panel, options: [...panel.querySelectorAll('[role="option"]')] };
}

test('a list picker names its filter and value and says what it opens', async () => {
    const { w, button, panel } = listPage();
    assert.match(button.textContent.replace(/\s+/g, ' ').trim(), /^Period: Last 7 days$/);
    assert.equal(button.getAttribute('aria-haspopup'), 'listbox');
    assert.equal(button.getAttribute('aria-expanded'), 'false');
    assert.equal(panel.getAttribute('role'), 'listbox');
    assert.ok(panel.getAttribute('aria-label'));
    await noViolations(w, 'a closed list picker');
});

test('opening moves the focus to the chosen option, arrows move between options', async () => {
    const { w, button, panel, options } = listPage();
    button.click();
    assert.equal(button.getAttribute('aria-expanded'), 'true');
    assert.ok(!panel.classList.contains('hidden'));
    assert.equal(w.document.activeElement, options[1], 'focus is on the chosen option');
    key(w, options[1], 'ArrowDown');
    assert.equal(w.document.activeElement, options[2]);
    key(w, options[2], 'ArrowDown');
    assert.equal(w.document.activeElement, options[2], 'stays on the last option');
    key(w, options[2], 'Home');
    assert.equal(w.document.activeElement, options[0]);
    key(w, options[0], 'End');
    assert.equal(w.document.activeElement, options[2]);
    key(w, options[2], 'ArrowUp');
    assert.equal(w.document.activeElement, options[1]);
    assert.ok(options.every(o => o.getAttribute('tabindex') === '-1'), 'options are reached with arrows, not Tab');
    assert.deepEqual(options.map(o => o.getAttribute('aria-selected')), ['false', 'true', 'false']);
    await noViolations(w, 'an open list picker');
});

test('picking an option runs it, closes the list and returns the focus to the button', async () => {
    const { w, button, panel, options } = listPage();
    button.click();
    options[2].click();
    await frame(w);
    assert.deepEqual([...w.picked], ['30']);
    assert.ok(panel.classList.contains('hidden'));
    assert.equal(button.getAttribute('aria-expanded'), 'false');
    assert.equal(w.document.activeElement, button);
});

test('Escape closes and returns the focus; ArrowDown on the button opens', () => {
    const { w, button, panel, options } = listPage();
    button.focus();
    key(w, button, 'ArrowDown');
    assert.ok(!panel.classList.contains('hidden'), 'ArrowDown opens');
    key(w, options[1], 'Escape');
    assert.ok(panel.classList.contains('hidden'));
    assert.equal(w.document.activeElement, button);
});

test('a click or the focus elsewhere closes the picker', () => {
    const { w, button, panel, options } = listPage();
    button.click();
    w.document.getElementById('outside').click();
    assert.ok(panel.classList.contains('hidden'), 'a click outside closes');
    button.click();
    options[1].dispatchEvent(new w.FocusEvent('focusout', { bubbles: true, relatedTarget: w.document.getElementById('outside') }));
    assert.ok(panel.classList.contains('hidden'), 'tabbing out closes');
});

test('a dialog picker focuses its first control and gives the focus back on Escape', async () => {
    const w = page('<main><h1>Dialog</h1><div id="slot"></div></main>');
    w.document.getElementById('slot').innerHTML = w.uiPicker({
        id: 'country', label: 'Country', value: 'All', panelLabel: 'Where attacks come from',
        panel: '<button type="button" aria-pressed="false">Netherlands</button><button type="button" aria-pressed="false">Sweden</button>',
    });
    const button = w.document.querySelector('.ui-picker-btn');
    const panel = w.document.getElementById(button.getAttribute('aria-controls'));
    assert.equal(button.getAttribute('aria-haspopup'), 'dialog');
    assert.equal(panel.getAttribute('role'), 'dialog');
    button.click();
    assert.equal(w.document.activeElement, panel.querySelector('button'));
    await noViolations(w, 'an open dialog picker');
    key(w, w.document.activeElement, 'Escape');
    assert.ok(panel.classList.contains('hidden'));
    assert.equal(w.document.activeElement, button);
});

test('only one picker is open at a time', () => {
    const w = page('<main><h1>Two</h1><div id="a"></div><div id="b"></div></main>');
    const make = id => w.uiPicker({ id, label: id, value: 'All', options: [{ label: 'All', selected: true, onclick: '' }] });
    w.document.getElementById('a').innerHTML = make('one');
    w.document.getElementById('b').innerHTML = make('two');
    const [first, second] = w.document.querySelectorAll('.ui-picker-btn');
    first.click();
    second.click();
    assert.equal(first.getAttribute('aria-expanded'), 'false');
    assert.equal(second.getAttribute('aria-expanded'), 'true');
});

test('the Messages pickers in index.html pass the same checks', async () => {
    const block = indexHtml.match(/<div id="messages-pickers"[\s\S]*?\n {28}<\/div>/);
    assert.ok(block, 'the Messages pickers markup was found');
    const w = page(`<main><h1>Messages</h1>${block[0]}</main>`);
    w.setMessagesFacet = () => {};
    w.messagesTimePanelOpened = () => {};
    // The outcome options are filled in by app.js; give the list the same shape
    w.document.getElementById('messages-status-options').innerHTML =
        '<button type="button" class="ui-fct" role="option" tabindex="-1" aria-selected="true">All messages</button>' +
        '<button type="button" class="ui-fct" role="option" tabindex="-1" aria-selected="false">Delivered</button>';
    w.document.getElementById('messages-direction-options').innerHTML =
        '<button type="button" class="ui-fct" role="option" tabindex="-1" aria-selected="true">Any direction</button>';
    await noViolations(w, 'the closed Messages pickers');
    for (const id of ['messages-status-pick', 'messages-direction-pick', 'messages-time-pick']) {
        const button = w.document.getElementById(id);
        assert.match(button.textContent.replace(/\s+/g, ' ').trim(), /^(Outcome|Direction|Time): /, `${id} names its filter`);
        button.click();
        const panel = w.document.getElementById(button.getAttribute('aria-controls'));
        assert.ok(panel.contains(w.document.activeElement), `${id} moves the focus into its panel`);
        await noViolations(w, `the open ${id}`);
        key(w, w.document.activeElement, 'Escape');
        assert.equal(w.document.activeElement, button, `${id} gives the focus back`);
    }
});
