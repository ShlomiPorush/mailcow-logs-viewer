#!/usr/bin/env node
// Static inventory of the web UI: pages, inline actions, handlers, modals and
// the API endpoints the frontend calls. It backs two guards:
//   - every inline handler (onclick="fn(...)" and friends) names a function
//     that is actually defined somewhere in the frontend, and
//   - nothing listed in the committed baseline silently disappears, so a
//     redesign cannot drop a page, button, modal or API call by accident.
//
// Usage:
//   node .github/scripts/ui-inventory.cjs               print the inventory (Markdown)
//   node .github/scripts/ui-inventory.cjs --json        print it as JSON
//   node .github/scripts/ui-inventory.cjs --write-baseline
//        rewrite .github/tests/ui-inventory.baseline.json after an intentional change
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..', '..');
const FRONTEND = path.join(ROOT, 'frontend');
const BASELINE = path.join(ROOT, '.github', 'tests', 'ui-inventory.baseline.json');

// Standalone files that are not part of the SPA.
const IGNORED_FILES = new Set(['login.html']);

// Names an inline handler may use without the frontend defining them.
const BUILTINS = new Set([
    'if', 'for', 'while', 'switch', 'return', 'typeof', 'new', 'function', 'void', 'await', 'async',
    'alert', 'confirm', 'prompt', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval',
    'parseInt', 'parseFloat', 'isNaN', 'String', 'Number', 'Boolean', 'Array', 'Object', 'JSON',
    'Math', 'Date', 'encodeURIComponent', 'decodeURIComponent', 'encodeURI', 'decodeURI',
    'fetch', 'open', 'print', 'scrollTo', 'requestAnimationFrame', 'structuredClone',
]);

const HANDLER_ATTR = /\bon(click|change|input|submit|keyup|keydown|keypress|blur|focus|mouseover|mouseout|mouseenter|mouseleave)\s*=\s*\\?(["'])([\s\S]*?)\\?\2/g;

function frontendFiles(dir) {
    return fs.readdirSync(dir)
        .filter(f => /\.(js|html)$/.test(f) && !IGNORED_FILES.has(f) && !/prototype/i.test(f))
        .sort()
        .map(f => ({ name: f, text: stripComments(fs.readFileSync(path.join(dir, f), 'utf8')) }));
}

// Comments document handler patterns ("onclick=\"fn(...)\"") without being code.
function stripComments(text) {
    // Repeat until stable so removing one comment cannot join the pieces of another.
    let prev;
    do {
        prev = text;
        text = text.replace(/<!--[\s\S]*?-->/g, '');
    } while (text !== prev);
    return text
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/^\s*\/\/.*$/gm, '');
}

// Identifiers called at the top level of an inline handler expression,
// e.g. "event.stopPropagation(); showHelp('dmarc')" -> ['showHelp'].
function calledNames(expr) {
    expr = expr.replace(/'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"/g, "''");   // ignore text inside string literals
    const names = [];
    const re = /(^|[^.\w$])([A-Za-z_$][\w$]*)\s*\(/g;
    let m;
    while ((m = re.exec(expr))) names.push(m[2]);
    return names.filter(n => !BUILTINS.has(n));
}

// A stable name for one user action: the function plus its first argument
// when that argument is a plain literal, e.g. navigateTo:queue.
function actionKey(expr) {
    const m = expr.match(/(?:^|[^.\w$])([A-Za-z_$][\w$]*)\s*\(\s*(['"])([^'"$\\{}]*)\2/);
    if (m && !BUILTINS.has(m[1])) return `${m[1]}:${m[3]}`;
    const names = calledNames(expr);
    return names.length ? names[0] : null;
}

function definedNames(files) {
    const defs = new Set();
    const patterns = [
        /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/g,
        /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/g,
        /\bwindow\.([A-Za-z_$][\w$]*)\s*=/g,
        /\bclass\s+([A-Za-z_$][\w$]*)/g,
    ];
    for (const f of files) {
        for (const re of patterns) {
            let m;
            re.lastIndex = 0;
            while ((m = re.exec(f.text))) defs.add(m[1]);
        }
    }
    return defs;
}

// Frontend API calls, normalised so they can be compared with backend routes:
// template placeholders become {param}; a trailing slash means the path is
// completed by string concatenation at runtime.
function apiCalls(files) {
    const calls = new Map();
    const re = /(['"`])(\/api\/[^'"`\s?#]*)/g;
    for (const f of files) {
        if (!f.name.endsWith('.js') && f.name !== 'index.html') continue;
        let m;
        while ((m = re.exec(f.text))) {
            const raw = m[2];
            const norm = raw.replace(/\$\{[^}]*\}/g, '{param}').replace(/\$\{.*$/, '{param}');
            if (!calls.has(norm)) calls.set(norm, new Set());
            calls.get(norm).add(f.name);
        }
    }
    return calls;
}

function pages(dir) {
    const router = fs.readFileSync(path.join(dir, 'router.js'), 'utf8');
    const block = router.match(/const VALID_ROUTES = \[([\s\S]*?)\];/);
    if (!block) throw new Error('router.js: VALID_ROUTES not found');
    return [...block[1].matchAll(/'([^']+)'/g)].map(m => m[1]);
}

function modals(files) {
    const html = files.find(f => f.name === 'index.html').text;
    return [...html.matchAll(/\sid="([^"]*modal[^"]*)"/gi)].map(m => m[1]).sort();
}

function collect(dir = FRONTEND) {
    const files = frontendFiles(dir);
    const defined = definedNames(files);
    const handlers = new Map();   // function name -> Set(files)
    const actions = new Map();    // action key -> Set(files)
    const undefinedHandlers = new Map();

    for (const f of files) {
        HANDLER_ATTR.lastIndex = 0;
        let m;
        while ((m = HANDLER_ATTR.exec(f.text))) {
            const expr = m[3];
            // Handler attributes that are themselves template output, e.g.
            // onclick="${action}", are resolved at runtime; the browser pass checks those.
            if (/^\s*\$\{[^}]*\}\s*$/.test(expr)) continue;
            for (const name of calledNames(expr.replace(/\$\{[^}]*\}/g, '0'))) {
                if (!handlers.has(name)) handlers.set(name, new Set());
                handlers.get(name).add(f.name);
                if (!defined.has(name)) {
                    if (!undefinedHandlers.has(name)) undefinedHandlers.set(name, new Set());
                    undefinedHandlers.get(name).add(f.name);
                }
            }
            const key = actionKey(expr);
            if (key) {
                if (!actions.has(key)) actions.set(key, new Set());
                actions.get(key).add(f.name);
            }
        }
    }

    return {
        pages: pages(dir),
        modals: modals(files),
        handlers,
        actions,
        undefinedHandlers,
        api: apiCalls(files),
    };
}

function toPlain(inv) {
    const sorted = map => [...map.keys()].sort();
    return {
        pages: inv.pages.slice().sort(),
        modals: inv.modals,
        actions: sorted(inv.actions),
        handlers: sorted(inv.handlers),
        api: sorted(inv.api),
    };
}

function toMarkdown(inv) {
    const plain = toPlain(inv);
    const byFile = map => {
        const out = {};
        for (const [k, files] of map) for (const f of files) (out[f] ||= []).push(k);
        return out;
    };
    const lines = ['# UI inventory', '',
        `${plain.pages.length} pages, ${plain.modals.length} modals, ${plain.actions.length} distinct actions, ` +
        `${plain.handlers.length} handler functions, ${plain.api.length} API paths.`, '',
        '## Pages', '', ...plain.pages.map(p => `- ${p}`), '',
        '## Modals', '', ...plain.modals.map(m => `- ${m}`), ''];
    const actions = byFile(inv.actions);
    lines.push('## Actions by file', '');
    for (const f of Object.keys(actions).sort()) {
        lines.push(`### ${f}`, '', ...actions[f].sort().map(a => `- ${a}`), '');
    }
    const api = byFile(inv.api);
    lines.push('## API calls by file', '');
    for (const f of Object.keys(api).sort()) {
        lines.push(`### ${f}`, '', ...api[f].sort().map(a => `- ${a}`), '');
    }
    return lines.join('\n');
}

module.exports = { collect, toPlain, calledNames, BASELINE };

if (require.main === module) {
    const inv = collect();
    if (process.argv.includes('--write-baseline')) {
        fs.writeFileSync(BASELINE, JSON.stringify(toPlain(inv), null, 2) + '\n');
        console.log(`baseline written: ${path.relative(ROOT, BASELINE)}`);
    } else if (process.argv.includes('--json')) {
        console.log(JSON.stringify(toPlain(inv), null, 2));
    } else {
        console.log(toMarkdown(inv));
    }
}
