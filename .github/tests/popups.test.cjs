// Every popup comes from the shared builders, so all of them look and behave
// alike on a desktop and on a phone (UI_Behavior_Catalog.md, "Shared dialogs and
// notices"): a dialog from uiDialog (utils.js), a sheet from uiSheetShow, a
// drop-down from uiPicker, a row menu from uiMenu, a notice from showToast.
// Dialogs that live in index.html must have the same frame: a head with a title
// and an X. This test fails when a floating layer is made any other way: markup
// or classes of a dialog, sheet, menu or panel outside those builders, a
// <dialog> or popover element, fixed positioning set in JavaScript or with a
// utility class, a CSS rule that floats a new class, or the browser's own
// alert(), confirm() or prompt(). A layer that must differ is listed below with
// the reason, like the More sheet and the phone search.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

const FRONTEND = path.join(__dirname, '../../frontend');

// The functions that may build a floating layer, and the classes they build
const BUILDERS = {
    'utils.js': {
        uiDialog: 'every dialog built in JavaScript',
        uiSheetShow: 'sheets (help on a phone, Security addresses, Needs attention on a phone)',
        uiPicker: 'the drop-down of every filter (MP-1)',
        uiMenu: 'row menus on the popover layer (MP-7)',
        showToast: 'the one toast (FB-2)',
        uiLineCopy: 'an off-screen text field for copying without HTTPS, not a popup',
    },
    'app.js': {
        attnWindowOpen: 'Needs attention: a window anchored under the bell on a wide screen, a sheet on a phone (NL-19)',
        showNavFlyout: "the sidebar's flyout of a page's tabs on hover (NL-8)",
    },
};

// Elements in index.html that float without being a shared dialog
const STATIC_LAYERS = {
    'mobile-menu': 'the phone More sheet above the tab bar (NL-9)',
    'messages-date-range-dropdown': 'Messages custom range, a picker panel that opens in place in the facets',
    'messages-status-panel': 'Messages outcome picker panel (uiPicker markup)',
    'messages-direction-panel': 'Messages direction picker panel (uiPicker markup)',
    'messages-time-panel': 'Messages time picker panel (uiPicker markup)',
    'date-range-dropdown': 'Mailbox Stats period picker panel (uiPicker markup)',
    'suppression-more-menu': 'Suppressions More menu on the popover layer (uiMenu markup)',
};

// CSS rules that may float above the page, and why
const FLOATING_CSS = {
    '.ui-dialog-backdrop': 'every dialog',
    '.ui-sheet': 'sheets',
    '.ui-menu': 'row menus on the popover layer',
    '.ui-popover': 'picker panels',
    '.ui-ms-dropdown': 'the Mailbox Stats period panel, a picker panel',
    '.ui-toast': 'the toast',
    '.ui-attn-win': 'the Needs attention window',
    '.ui-fly': "the sidebar's flyout of a page's tabs",
    '.ui-gs-panel': 'search results under the search field',
    '.ui-gs': 'the phone search over the whole screen (SR-8)',
    '.mobile-menu': 'the phone More sheet',
    '.ui-tabbar': 'the phone tab bar, part of the page frame',
    '.ui-savebar': 'the save bar, part of the page',
};

// Classes of a floating layer's frame: only its builder writes them
const FRAME_CLASSES = ['ui-dialog-backdrop', 'ui-dialog', 'ui-sheet', 'ui-sheet-panel', 'ui-menu', 'ui-menu-panel',
    'ui-popover', 'ui-attn-win', 'ui-fly', 'ui-toast', 'mobile-menu'];

// Comments say anything; strings and code are what count
function stripComments(text) {
    return text.replace(/<!--[\s\S]*?-->/g, '').replace(/\/\*[\s\S]*?\*\//g, '')
        .split('\n').map(line => {
            if (/^\s*\/\//.test(line)) return '';
            // A trailing comment, where the quotes before it are closed
            for (let i = line.indexOf('//'); i !== -1; i = line.indexOf('//', i + 2)) {
                const before = line.slice(0, i);
                if (!/[\s;,){}]$/.test(before)) continue;
                const open = q => (before.split(q).length - 1) % 2 === 1;
                if (!open("'") && !open('"') && !open('`')) return before;
            }
            return line;
        }).join('\n');
}

// The top-level function each line belongs to (null outside any)
function functionAt(text) {
    const lines = text.split('\n');
    const owner = [];
    let current = null;
    for (const line of lines) {
        const m = line.match(/^(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/);
        if (m) current = m[1];
        else if (/^\S/.test(line) && !/^[})\]]/.test(line)) current = null;
        owner.push(current);
    }
    return offset => owner[text.slice(0, offset).split('\n').length - 1];
}

const lineOf = (text, offset) => text.slice(0, offset).split('\n').length;

function frameClassesIn(classText) {
    return classText.split(/\s+/).filter(c => FRAME_CLASSES.includes(c));
}

// What makes a floating layer, found in a JavaScript file
function layerMarks(text) {
    const marks = [];
    const add = (re, what) => { for (const m of text.matchAll(re)) marks.push({ at: m.index, what: what(m) }); };
    add(/<[a-zA-Z][^<>]*?\sclass\s*=\s*(["'])([^"']*)\1/g, m => frameClassesIn(m[2]).map(c => `class ${c}`).join(', '));
    add(/\.className\s*\+?=\s*(["'`])([^"'`]*)\1/g, m => frameClassesIn(m[2]).map(c => `className ${c}`).join(', '));
    add(/\.classList\.(?:add|toggle|replace)\(([^)]*)\)/g,
        m => [...m[1].matchAll(/["'`]([^"'`]*)["'`]/g)].flatMap(s => frameClassesIn(s[1])).map(c => `classList ${c}`).join(', '));
    add(/<[a-zA-Z][^<>]*?\srole\s*=\s*["'](?:alert)?dialog["']/g, () => 'role dialog');
    add(/setAttribute\(\s*["']role["']\s*,\s*["'](?:alert)?dialog["']/g, () => 'role dialog');
    add(/<dialog[\s>]/g, () => '<dialog>');
    add(/createElement\(\s*["'`]dialog["'`]\s*\)|\.showModal\(/g, () => '<dialog>');
    add(/<[a-zA-Z][^<>]*?\spopover(?=[\s>=])/g, () => 'popover attribute');
    add(/setAttribute\(\s*["']popover["']|\.popover\s*=/g, () => 'popover attribute');
    add(/\bfixed\s+inset-0\b|class\s*=\s*["'][^"']*\bfixed\b/g, () => 'fixed utility class');
    add(/position\s*:\s*fixed/g, () => 'position fixed');
    add(/\.style\.position\s*=\s*["'`]fixed|setProperty\(\s*["']position["']\s*,\s*["']fixed|\.style\.inset\s*=/g, () => 'position fixed');
    return marks.filter(m => m.what);
}

// Where the element that opens at `start` closes (same tag name, counting nesting)
function elementEnd(html, start, tag) {
    const re = new RegExp(`<${tag}\\b[^>]*>|</${tag}\\s*>`, 'gi');
    re.lastIndex = start;
    let depth = 0, m;
    while ((m = re.exec(html))) {
        depth += m[0][1] === '/' ? -1 : 1;
        if (depth === 0) return m.index + m[0].length;
    }
    return html.length;
}

function check(dir = FRONTEND) {
    const problems = [];
    const read = name => stripComments(fs.readFileSync(path.join(dir, name), 'utf8'));
    const scripts = fs.readdirSync(dir).filter(f => f.endsWith('.js')).sort();

    for (const name of scripts) {
        const text = read(name);
        const owner = functionAt(text);
        for (const mark of layerMarks(text)) {
            const fn = owner(mark.at);
            if (fn && BUILDERS[name] && BUILDERS[name][fn]) continue;
            problems.push(`${name}:${lineOf(text, mark.at)} ${mark.what} in ${fn || 'top-level code'}: build it with uiDialog, uiSheetShow, uiPicker or uiMenu`);
        }
        // The browser's own dialogs look like none of ours and block the page
        for (const m of text.replace(/'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"/g, "''")
            .matchAll(/(^|[^.\w$])(?:window\.)?(alert|confirm|prompt)\s*\(/g)) {
            problems.push(`${name}:${lineOf(text, m.index)} ${m[2]}(): use showConfirmModal, showChoiceModal or showToast`);
        }
        // A dialog says how wide it is, and has an X unless it is a question
        {
            for (const m of text.matchAll(/\buiDialog\(\{/g)) {
                let depth = 0, end = m.index + m[0].length - 1;
                for (; end < text.length; end++) {
                    if (text[end] === '{') depth++;
                    else if (text[end] === '}' && --depth === 0) break;
                }
                const options = text.slice(m.index, end);
                const where = `${name}:${lineOf(text, m.index)}`;
                if (!/\bsize\b/.test(options)) problems.push(`${where} uiDialog without a size ('sm', 'md' or 'wide')`);
                if (!/\bclose\b/.test(options) && !/\brole:\s*'alertdialog'/.test(options)) {
                    problems.push(`${where} uiDialog without close: every dialog but a question has an X`);
                }
            }
        }
    }

    // index.html: dialogs keep the shared frame; other floating elements are listed
    const html = read('index.html');
    for (const m of html.matchAll(/<([a-zA-Z]+)\b([^<>]*)>/g)) {
        const attrs = m[2];
        const id = (attrs.match(/\sid="([^"]+)"/) || [])[1] || '';
        const classes = frameClassesIn((attrs.match(/\sclass="([^"]*)"/) || [])[1] || '');
        const role = /\srole="(?:alert)?dialog"/.test(attrs);
        const popover = /\spopover(?=[\s>=]|$)/.test(attrs);
        const fixed = /\bclass="[^"]*\bfixed\b/.test(attrs) || /position\s*:\s*fixed/.test(attrs);
        const where = `index.html:${lineOf(html, m.index)}${id ? ` #${id}` : ''}`;
        if (m[1].toLowerCase() === 'dialog') { problems.push(`${where} <dialog>: use the shared dialog frame`); continue; }
        if (classes.includes('ui-dialog-backdrop')) {
            // Only this dialog: up to the end of its own element, then up to its body
            const own = html.slice(m.index, elementEnd(html, m.index, m[1]));
            const body = own.indexOf('ui-dialog-body');
            const frame = body === -1 ? own : own.slice(0, body);
            if (!role || !/\saria-(?:label|labelledby)="/.test(attrs)) problems.push(`${where} a dialog needs role="dialog" and a label`);
            if (!/class="ui-dialog\b/.test(frame) || !/class="ui-dialog-head"/.test(frame) || !/<h3\b/.test(frame)
                || !/aria-label="Close"/.test(frame)) {
                problems.push(`${where} a dialog needs .ui-dialog with a .ui-dialog-head holding an h3 and an X (aria-label="Close")`);
            }
            continue;
        }
        if (classes.includes('ui-dialog') || STATIC_LAYERS[id] || classes.includes('mobile-menu')) continue;
        // The More sheet's content panel sits inside #mobile-menu
        if (role && /mobile-menu-content/.test(attrs)) continue;
        if (classes.length || role || popover || fixed) {
            problems.push(`${where} floating element outside the shared builders (${[...classes, role && 'role dialog', popover && 'popover', fixed && 'fixed'].filter(Boolean).join(', ')}): ` +
                'build it with uiDialog, uiSheetShow, uiPicker or uiMenu, or list it in STATIC_LAYERS with the reason');
        }
    }

    // CSS: what floats above the page is one of the shared layers
    // Read per element styled: the first class (or id) of the last compound of each
    // selector, across all its rules and states, so a position in one rule and a
    // z-index in another (.x and .x.is-open, .x:hover, .page .x) count together
    const css = fs.readFileSync(path.join(dir, 'assets/css/ui.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
    const styled = new Map();
    for (const m of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
        const position = (m[2].match(/(?:^|;)\s*position\s*:\s*(fixed|absolute)/) || [])[1];
        const z = Number((m[2].match(/(?:^|;)\s*z-index\s*:\s*(\d+)/) || [])[1] || 0);
        if (!position && !z) continue;
        for (const part of m[1].split(',')) {
            const last = part.trim().replace(/\s+/g, ' ').split(/\s*[\s>+~]\s*/).pop();
            const key = ((last || '').match(/[.#][\w-]+/) || [last])[0];
            if (!key || key.startsWith('@')) continue;
            const s = styled.get(key) || { fixed: false, absolute: false, z: 0 };
            if (position === 'fixed') s.fixed = true;
            if (position === 'absolute') s.absolute = true;
            s.z = Math.max(s.z, z);
            styled.set(key, s);
        }
    }
    for (const [selector, s] of styled) {
        const raised = s.absolute && s.z >= 20;
        if ((s.fixed || raised) && !FLOATING_CSS[selector]) {
            problems.push(`ui.css ${selector}: ${s.fixed ? 'position: fixed' : `position: absolute with z-index ${s.z}`} floats a layer of its own; ` +
                'use the shared dialog, sheet, picker or menu, or list the selector in FLOATING_CSS with the reason');
        }
    }
    return problems;
}

test('every popup is built by the shared builders', () => {
    assert.deepEqual(check(), []);
});

test('the listed exceptions still exist', () => {
    for (const [file, fns] of Object.entries(BUILDERS)) {
        const text = fs.readFileSync(path.join(FRONTEND, file), 'utf8');
        for (const fn of Object.keys(fns)) assert.match(text, new RegExp(`^(?:async\\s+)?function\\s+${fn}\\s*\\(`, 'm'), `${file} ${fn} is listed in BUILDERS but gone`);
    }
    const html = fs.readFileSync(path.join(FRONTEND, 'index.html'), 'utf8');
    for (const id of Object.keys(STATIC_LAYERS)) assert.ok(html.includes(`id="${id}"`), `#${id} is listed in STATIC_LAYERS but gone`);
    const css = fs.readFileSync(path.join(FRONTEND, 'assets/css/ui.css'), 'utf8');
    for (const selector of Object.keys(FLOATING_CSS)) {
        assert.match(css, new RegExp(`${selector.replace(/[.#]/g, '\\$&')}(?![\\w-])`), `${selector} is listed in FLOATING_CSS but gone`);
    }
});

// A copy of the frontend with one file changed, to show the check catches it
function checkWith(file, text) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'popups-'));
    try {
        fs.mkdirSync(path.join(dir, 'assets/css'), { recursive: true });
        for (const name of fs.readdirSync(FRONTEND).filter(f => f.endsWith('.js') || f === 'index.html')) {
            fs.copyFileSync(path.join(FRONTEND, name), path.join(dir, name));
        }
        fs.copyFileSync(path.join(FRONTEND, 'assets/css/ui.css'), path.join(dir, 'assets/css/ui.css'));
        const target = path.join(dir, file);
        fs.writeFileSync(target, (fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : '') + '\n' + text + '\n');
        return check(dir);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

const BYPASSES = {
    'a dialog written by hand in a page script': ['spam_filter.js',
        "function showThing() {\n    document.body.insertAdjacentHTML('beforeend', '<div class=\"ui-dialog-backdrop\" role=\"dialog\"><div class=\"ui-dialog\"></div></div>');\n}"],
    'a dialog written by hand in utils.js outside the builders': ['utils.js',
        "function myDialog() {\n    const el = document.createElement('div');\n    el.className = 'ui-dialog-backdrop';\n    document.body.appendChild(el);\n}"],
    'a <dialog> element': ['app.js', "function showNative() {\n    document.body.insertAdjacentHTML('beforeend', '<dialog open>Hi</dialog>');\n}"],
    'a <dialog> element made through the DOM': ['app.js',
        "function showNative2() {\n    const d = document.createElement('dialog');\n    document.body.appendChild(d);\n    d.showModal();\n}"],
    'a dialog in index.html with no frame, before one that has it': ['index.html',
        '<div id="broken-modal" class="hidden ui-dialog-backdrop" role="dialog" aria-label="Broken"><p>No frame</p></div>' +
        '<div id="fine-modal" class="hidden ui-dialog-backdrop" role="dialog" aria-label="Fine"><div class="ui-dialog"><div class="ui-dialog-head"><h3>Fine</h3>' +
        '<button aria-label="Close">x</button></div><div class="ui-dialog-body"></div></div></div>', '#broken-modal'],
    'a layer floating through two CSS rules': ['assets/css/ui.css', '.fresh-popup { position: absolute; }\n.fresh-popup { z-index: 999; inset: 0; }'],
    'a layer floating only in its open state': ['assets/css/ui.css', '.review-popup { position: absolute; }\n.review-popup.is-open { z-index: 999; inset: 0; }', '.review-popup'],
    'a layer fixed only in its open state': ['assets/css/ui.css', '.page .late-sheet.is-open { position: fixed; inset: 0; }', '.late-sheet'],
    'a menu panel made by hand': ['app.js', "function rowMenu() {\n    return '<div class=\"ui-menu-panel\"><button>Delete</button></div>';\n}"],
    'a popover element made by hand': ['app.js', "function myPop() {\n    return '<div popover class=\"thing\">x</div>';\n}"],
    'fixed positioning set in JavaScript': ['app.js', "function overlay() {\n    const el = document.createElement('div');\n    el.style.position = 'fixed';\n    el.style.inset = '0';\n}"],
    'fixed positioning in a style text': ['app.js', "function overlay2() {\n    return '<div style=\"position: fixed; inset: 0\">x</div>';\n}"],
    'a fixed utility overlay': ['index.html', '<div id="my-overlay" class="hidden fixed inset-0 bg-black z-50"></div>'],
    'a dialog in index.html without an X': ['index.html',
        '<div id="new-modal" class="hidden ui-dialog-backdrop" role="dialog" aria-label="New"><div class="ui-dialog"><div class="ui-dialog-head"><h3>New</h3></div><div class="ui-dialog-body"></div></div></div>'],
    'a new class floating through its own CSS': ['assets/css/ui.css', '.my-overlay { position: fixed; inset: 0; }'],
    'a menu raised through its own CSS': ['assets/css/ui.css', '.my-menu { position: absolute; top: 100%; z-index: 40; }'],
    'the browser confirm()': ['app.js', "function ask() {\n    if (confirm('Delete?')) return 1;\n}"],
    'the browser alert()': ['app.js', "function tell() {\n    window.alert('Done');\n}"],
    'a uiDialog without a size': ['app.js', "function sizeless() {\n    uiDialog({ id: 'x', title: 'X', close: () => {} });\n}"],
    'a uiDialog without an X': ['app.js', "function noX() {\n    uiDialog({ id: 'x', title: 'X', size: 'sm' });\n}"],
};

for (const [name, [file, text, expect]] of Object.entries(BYPASSES)) {
    test(`the check catches ${name}`, () => {
        const problems = checkWith(file, text);
        assert.ok(problems.length > 0, `${name} passed the check`);
        if (expect) assert.ok(problems.some(p => p.includes(expect)), `no finding names ${expect}: ${problems.join("; ")}`);
    });
}

test('the check lets through selectors, comments and the builders themselves', () => {
    const problems = checkWith('app.js', [
        "function findLayers() {",
        "    // a <div class=\"ui-dialog-backdrop\"> in a comment, and confirm() too",
        "    return document.querySelectorAll('.ui-dialog-backdrop, [role=\"dialog\"], .ui-sheet');",
        "}",
        "function showGood() {",
        "    uiDialog({ id: 'good', title: 'Good', size: 'sm', close: () => {} });",
        "    showConfirmModal({ title: 'Sure?' });",
        "}",
    ].join('\n'));
    assert.deepEqual(problems, []);
});
