#!/usr/bin/env node
// Generates the reference tables of documentation/UI_Behavior_Catalog.md:
// every small UI behaviour (click to copy, tooltips, toasts, confirmations,
// flags, empty and loading states, persisted preferences, timers, deep links,
// keyboard handling, help topics, badge colours) with the page it belongs to
// and the exact place in the code.
//
// Usage:
//   node .github/scripts/ui-catalog.cjs            print the generated section
//   node .github/scripts/ui-catalog.cjs --write    replace the generated section in the catalog
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..', '..');
const FRONTEND = path.join(ROOT, 'frontend');
const CATALOG = path.join(ROOT, 'documentation', 'UI_Behavior_Catalog.md');
const START = '<!-- generated:start (node .github/scripts/ui-catalog.cjs --write) -->';
const END = '<!-- generated:end -->';

const PAGE_BY_FILE = {
    'dmarc.js': 'DMARC', 'domains.js': 'Domains', 'logs-viewer.js': 'Logs', 'mailbox-stats.js': 'Mailbox stats',
    'message-details.js': 'Message details', 'notifications.js': 'Settings', 'rate-limits.js': 'Mailbox stats',
    'settings.js': 'Settings', 'smtp-abuse.js': 'Security', 'spam_filter.js': 'Spam filter',
    'utils.js': 'Shared', 'export.js': 'Shared', 'router.js': 'Shell',
};
const PAGE_BY_SECTION = {
    dashboard: 'Dashboard', messages: 'Messages', netfilter: 'Security', queue: 'Queue', quarantine: 'Quarantine',
    'spam-filter': 'Spam filter', status: 'Status', domains: 'Domains', dmarc: 'DMARC', 'mailbox-stats': 'Mailbox stats',
    logs: 'Logs', settings: 'Settings',
};
// app.js holds most pages; its functions are placed by name.
const PAGE_BY_FUNCTION = [
    [/dashboard|recent|quickSearch/i, 'Dashboard'],
    [/messageDetail|modalTab|postfixDetail/i, 'Message details'],
    [/message/i, 'Messages'],
    [/netfilter|fail2ban|security|abuse|unban|banIP/i, 'Security'],
    [/queue/i, 'Queue'],
    [/quarantine|qrule/i, 'Quarantine'],
    [/status|blacklist|container|storage|version|host|job/i, 'Status'],
    [/geoip|flag/i, 'Shared'],
    [/dark|theme|mobile|navigate|toast|help|changelog|autoRefresh|switchTab/i, 'Shell'],
];
const UNREACHABLE = 'Not rendered (possible dead code)';
const PAGE_ORDER = ['Shell', 'Dashboard', 'Messages', 'Message details', 'Security', 'Queue', 'Quarantine',
    'Spam filter', 'Status', 'Domains', 'DMARC', 'Mailbox stats', 'Logs', 'Settings', 'Shared', 'app.js (mixed)', UNREACHABLE];

function loadFiles() {
    return fs.readdirSync(FRONTEND)
        .filter(f => /\.(js|html)$/.test(f) && f !== 'login.html' && !/prototype/i.test(f))
        .sort()
        .map(name => ({ name, text: fs.readFileSync(path.join(FRONTEND, name), 'utf8') }));
}

const lineOf = (text, idx) => text.slice(0, idx).split('\n').length;

// Top-level functions only (declared at column 0), so a call inside a nested
// helper or callback is attributed to the function a reader would look for.
const FN_CACHE = new Map();
function topLevelFunctions(text) {
    if (FN_CACHE.has(text)) return FN_CACHE.get(text);
    const re = /^(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(|^(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)/gm;
    const fns = [...text.matchAll(re)].map(m => ({ name: m[1] || m[2], start: m.index, end: functionEnd(text, m) }));
    FN_CACHE.set(text, fns);
    return fns;
}

// End of a function's body. The body starts after the parameter list, so
// default values and destructuring ("params = {}", "{ total, page }") in the
// signature are not mistaken for it.
function functionEnd(text, m) {
    let i = m.index + m[0].length;
    if (!m[0].endsWith('(')) {
        const arrow = m[0].includes('=>');
        if (!arrow) {
            i = text.indexOf('(', i);
            if (i < 0) return text.length;
            i++;
        } else {
            while (/\s/.test(text[i])) i++;
            if (text[i] !== '{') {   // expression body: ends with the statement
                const semi = text.indexOf(';\n', i);
                return semi < 0 ? text.length : semi;
            }
            return scanCode(text, i + 1);
        }
    }
    // i is just after '(': skip to the matching ')'
    let depth = 0;
    for (; i < text.length; i++) {
        const c = text[i];
        if (c === '"' || c === "'") { for (i++; i < text.length && text[i] !== c; i++) if (text[i] === '\\') i++; continue; }
        if (c === '`') { i = scanTemplate(text, i); continue; }
        if (c === '(') depth++;
        else if (c === ')') { if (depth === 0) break; depth--; }
    }
    const open = text.indexOf('{', i);
    return open < 0 ? text.length : scanCode(text, open + 1);
}

// From i, returns the index of the '}' that closes the current block.
function scanCode(text, i) {
    let depth = 0;
    for (; i < text.length; i++) {
        const c = text[i];
        if (c === '/' && text[i + 1] === '/') { i = text.indexOf('\n', i); if (i < 0) return text.length; continue; }
        if (c === '/' && text[i + 1] === '*') { i = text.indexOf('*/', i + 2) + 1; if (i <= 0) return text.length; continue; }
        if (c === '"' || c === "'") { for (i++; i < text.length && text[i] !== c; i++) if (text[i] === '\\') i++; continue; }
        if (c === '`') { i = scanTemplate(text, i); continue; }
        if (c === '{') depth++;
        else if (c === '}') { if (depth === 0) return i; depth--; }
    }
    return text.length;
}

// From the opening backtick at i, returns the index of the closing one.
function scanTemplate(text, i) {
    for (i++; i < text.length; i++) {
        const c = text[i];
        if (c === '\\') { i++; continue; }
        if (c === '`') return i;
        if (c === '$' && text[i + 1] === '{') i = scanCode(text, i + 2);
    }
    return text.length;
}

// The top-level function that contains idx, or null for top-level code.
function containingFunction(text, idx) {
    for (const f of topLevelFunctions(text)) if (f.start <= idx && idx <= f.end) return f;
    return null;
}

function enclosingFunction(text, idx) {
    const f = containingFunction(text, idx);
    return f ? f.name : null;
}

// End of the <div> element whose opening tag contains position `at`.
const DIV_END = new Map();
function divEnd(html, at) {
    if (DIV_END.has(at)) return DIV_END.get(at);
    const re = /<div\b|<\/div>/g;
    re.lastIndex = html.lastIndexOf('<div', at);
    let depth = 0, m, end = html.length;
    while ((m = re.exec(html))) {
        depth += m[0] === '</div>' ? -1 : 1;
        if (depth === 0) { end = m.index; break; }
    }
    DIV_END.set(at, end);
    return end;
}

// Innermost page section or modal that contains idx.
function htmlPageAt(html, idx) {
    const scopes = [
        ...[...html.matchAll(/<div[^>]*\sid="content-([a-z-]+)"/g)].map(m => ({ at: m.index + 4, label: PAGE_BY_SECTION[m[1]] || m[1] })),
        ...[...html.matchAll(/<div[^>]*\sid="([a-z-]*modal[a-z-]*)"/gi)].map(m => ({ at: m.index + 4, label: `Modal: ${m[1]}` })),
    ].filter(s => s.at <= idx && idx <= divEnd(html, s.at)).sort((a, b) => b.at - a.at);
    return scopes.length ? scopes[0].label : 'Shell';
}

let ID_PAGE = null;   // element id in index.html -> page it lives on
function idPages(files) {
    if (ID_PAGE) return ID_PAGE;
    const html = files.find(f => f.name === 'index.html').text;
    ID_PAGE = new Map([...html.matchAll(/\sid="([^"$]+)"/g)].map(m => [m[1], htmlPageAt(html, m.index)]));
    return ID_PAGE;
}

// For JS, the page is read from the DOM ids the enclosing top-level function
// touches (majority vote), then from its name, then from the file.
function pageOf(file, idx, files) {
    if (file.name === 'index.html') return htmlPageAt(file.text, idx);
    if (PAGE_BY_FILE[file.name] && file.name !== 'app.js') return PAGE_BY_FILE[file.name];
    // Inside a function: its whole body. Top-level code: the statement around idx.
    const fn = containingFunction(file.text, idx) || { name: '', start: idx, end: Math.min(file.text.length, idx + 800) };
    {
        const body = file.text.slice(fn.start, fn.end + 1);
        const votes = {}, modalVotes = {};
        const ids = [...body.matchAll(/getElementById\(\s*['"]([^'"]+)['"]/g)].map(m => m[1]);
        for (const id of ids) {
            const p = idPages(files).get(id);
            if (!p) continue;
            const bucket = p.startsWith('Modal:') ? modalVotes : votes;
            bucket[p] = (bucket[p] || 0) + 1;
        }
        const best = Object.entries(votes).sort((a, b) => b[1] - a[1])[0]
            || Object.entries(modalVotes).sort((a, b) => b[1] - a[1])[0];
        if (best) return best[0];
        // Every element this function writes to is missing from the markup and
        // from every rendered template: nothing on screen can show its output.
        const rendered = files.map(f => f.text).join('\n');
        if (ids.length && ids.every(id => !rendered.includes(`id="${id}"`) && !rendered.includes(`id=\\"${id}\\"`))) {
            return UNREACHABLE;
        }
        for (const [re, page] of PAGE_BY_FUNCTION) if (fn.name && re.test(fn.name)) return page;
    }
    return 'app.js (mixed)';
}

function where(file, idx) {
    const fn = file.name.endsWith('.js') ? enclosingFunction(file.text, idx) : null;
    return `\`frontend/${file.name}:${lineOf(file.text, idx)}\`${fn ? ` (${fn})` : ''}`;
}

// Arguments of a call whose '(' is at `open`, split at top-level commas.
function callArgs(text, open) {
    const args = [];
    let depth = 0, cur = '', quote = null;
    for (let i = open + 1; i < text.length; i++) {
        const c = text[i];
        if (quote) {
            cur += c;
            if (c === '\\') { cur += text[++i] || ''; continue; }
            if (c === quote) quote = null;
            continue;
        }
        if (c === '"' || c === "'" || c === '`') { quote = c; cur += c; continue; }
        if (c === '(' || c === '[' || c === '{') depth++;
        if (c === ')' || c === ']' || c === '}') {
            if (depth === 0) { args.push(cur.trim()); return args; }
            depth--;
        }
        if (c === ',' && depth === 0) { args.push(cur.trim()); cur = ''; continue; }
        cur += c;
    }
    return args;
}

const clean = s => (s || '').replace(/\s+/g, ' ').replace(/\|/g, '\\|').trim();
const short = (s, n = 110) => { s = clean(s); return s.length > n ? s.slice(0, n - 3) + '...' : s; };
const literal = s => { const m = (s || '').match(/^(['"`])([\s\S]*)\1$/); return m && !m[2].includes('${') ? m[2] : null; };
const show = s => { const lit = literal(s); return lit !== null ? `"${short(lit)}"` : `dynamic: \`${short(s, 80)}\``; };

function calls(files, nameRe, fn) {
    const out = [];
    for (const f of files) {
        if (!f.name.endsWith('.js') && f.name !== 'index.html') continue;
        const re = new RegExp(`(?<![\\w$.])(${nameRe})\\s*\\(`, 'g');
        let m;
        while ((m = re.exec(f.text))) {
            const before = f.text.slice(Math.max(0, m.index - 12), m.index);
            if (/function\s+$/.test(before)) continue;   // the definition itself
            const row = fn(callArgs(f.text, m.index + m[0].length - 1), m[1], f, m.index);
            if (row) out.push({ page: pageOf(f, m.index, files), where: where(f, m.index), ...row });
        }
    }
    return out;
}

function matches(files, re, fn) {
    const out = [];
    for (const f of files) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(f.text))) {
            const row = fn(m, f);
            if (row) out.push({ page: pageOf(f, m.index, files), where: where(f, m.index), ...row });
        }
    }
    return out;
}

function collect() {
    const files = loadFiles();
    const cats = [];

    cats.push({ title: 'Click to copy', note: 'Fields that copy their value on click (hover shows a copy icon and "Click to copy").',
        rows: calls(files, 'copyableText|copyToClipboard', (a, name) => ({ what: `${name === 'copyableText' ? 'copies' : 'copyToClipboard'}: \`${short(a[0], 70)}\`` })) });

    cats.push({ title: 'Tooltips', note: 'Native `title` tooltips. Dynamic ones show the expression that builds the text.',
        rows: matches(files, /\stitle=\\?(["'])((?:(?!\1).){1,300}?)\\?\1/g, (m, f) => {
            if (f.name === 'utils.js' && m[2] === 'Click to copy') return null;   // part of copyableText
            return { what: m[2].includes('${') ? `dynamic: \`${short(m[2], 80)}\`` : `"${short(m[2])}"` };
        }) });

    cats.push({ title: 'Toasts', note: 'Transient notifications from `showToast(message, type)` (utils.js). Type defaults to info.',
        rows: calls(files, 'showToast', a => ({ what: `${show(a[0])} [${literal(a[1] || "'info'") || short(a[1], 20)}]` })) });

    cats.push({ title: 'Confirmation dialogs', note: 'Every action that asks before it acts. Losing one turns a guarded action into a one-click action.',
        rows: calls(files, 'showConfirmModal|showFeatureDisableConfirmModal|confirm', (a, name) =>
            ({ what: `${name}: ${a.slice(0, 2).map(show).join(' / ')}` })) });

    cats.push({ title: 'Country flags', note: 'PNG flags served locally from `frontend/assets/flags/<size>/<cc>.png` (sizes 16x12, 24x18, 48x36), no emoji and no external source.',
        rows: calls(files, 'getFlagUrl|getFlagEmoji|renderGeoIPInfo|renderDmarcGeoIPInfo', (a, name) =>
            ({ what: `${name}(${a.map(x => short(x, 40)).join(', ')})` })) });

    cats.push({ title: 'Markdown rendering', note: 'Places that render Markdown (help pages, changelogs) through `renderMarkdown` (marked, then DOMPurify) into a `.markdown-body` element.',
        rows: calls(files, 'renderMarkdown', a => ({ what: `renders \`${short(a[0], 60)}\`` })) });

    cats.push({ title: 'Help topics', note: 'In-app help buttons; the topic is the Markdown file name under documentation/HelpDocs.',
        rows: calls(files, 'showHelpModal', a => ({ what: `topic ${show(a[0])}` })) });

    cats.push({ title: 'Empty states', note: 'Text shown when a list or panel has nothing to show.',
        rows: matches(files, /(?:>|['"`])\s*(No [A-Za-z][A-Za-z0-9 ,'()/-]{2,80}?(?:found|yet|available|configured|data|results|matching[^<'"`]*|to show|recorded|reports|entries|messages|alerts))[.!]?\s*(?=<|['"`])/g,
            m => ({ what: `"${short(m[1])}"` })) });

    const loading = new Map();
    for (const f of files) {
        if (!f.name.endsWith('.js')) continue;
        for (const m of f.text.matchAll(/animate-spin|Loading\.\.\./g)) {
            const key = `${f.name}|${enclosingFunction(f.text, m.index) || '(top level)'}`;
            if (!loading.has(key)) loading.set(key, { page: pageOf(f, m.index, files), where: where(f, m.index), count: 0 });
            loading.get(key).count++;
        }
    }
    cats.push({ title: 'Loading states', note: 'Functions that render a spinner or "Loading..." while data is fetched.',
        rows: [...loading.values()].map(r => ({ page: r.page, where: r.where, what: `${r.count} loading indicator(s)` })) });

    cats.push({ title: 'Persisted preferences', note: 'Settings the browser remembers between visits.',
        rows: matches(files, /(localStorage|sessionStorage)\.(getItem|setItem|removeItem)\(\s*['"`]([^'"`]+)/g,
            m => ({ what: `${m[1]} ${m[2]} "${m[3]}"` })) });

    cats.push({ title: 'Auto refresh and timers', note: 'Background refreshes and polling.',
        rows: calls(files, 'setInterval', a => ({ what: `every ${short(a[1] || '?', 40)} ms` })) });

    cats.push({ title: 'Address bar and deep links', note: 'Places that change the URL so a view can be bookmarked or shared.',
        rows: matches(files, /history\.(pushState|replaceState)\(/g, m => ({ what: m[1] })) });

    cats.push({ title: 'Keyboard handling', note: 'Key handlers; the keys are read from the handler body.',
        rows: matches(files, /addEventListener\(\s*['"](keydown|keyup)['"]/g, (m, f) => {
            const body = f.text.slice(m.index, m.index + 900);
            const keys = [...new Set([...body.matchAll(/key\s*===?\s*['"]([^'"]+)['"]/g)].map(k => k[1]))];
            return { what: `${m[1]}${keys.length ? `: ${keys.join(', ')}` : ''}` };
        }) });

    const utils = files.find(f => f.name === 'utils.js');
    const colors = utils.text.match(/const APP_COLORS\s*=\s*\{([\s\S]*?)\n\};/);
    const colorKeys = [];
    let group = null;
    for (const line of (colors ? colors[1] : '').split('\n')) {
        const g = line.match(/^ {4}([A-Za-z_]\w*)\s*:\s*\{/);
        const k = line.match(/^ {8}['"]?([\w-]+)['"]?\s*:\s*\{/);
        if (g) group = g[1];
        else if (k && group) colorKeys.push(`${group}.${k[1]}`);
    }
    cats.push({ title: 'Badge colours', note: 'Named colour recipes in `APP_COLORS` (utils.js). Badges are squared, soft fill plus subtle border.',
        rows: colorKeys.map(k => ({ page: 'Shared', where: `\`frontend/utils.js\` (APP_COLORS)`, what: k })) });

    return cats;
}

function render(cats) {
    const lines = [START, '', '## Reference tables', '',
        'Generated from the code. Do not edit by hand; run `node .github/scripts/ui-catalog.cjs --write` after a change.', '',
        '| Behaviour | Count |', '|---|---|', ...cats.map(c => `| [${c.title}](#${c.title.toLowerCase().replace(/[^a-z0-9 -]/g, '').replace(/ /g, '-')}) | ${c.rows.length} |`), ''];
    for (const c of cats) {
        lines.push(`### ${c.title}`, '', c.note, '');
        const byPage = {};
        for (const r of c.rows) (byPage[r.page] ||= []).push(r);
        const pages = Object.keys(byPage).sort((a, b) => {
            const ia = PAGE_ORDER.indexOf(a), ib = PAGE_ORDER.indexOf(b);
            return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || a.localeCompare(b);
        });
        lines.push('| Page | What | Code |', '|---|---|---|');
        for (const p of pages) for (const r of byPage[p]) lines.push(`| ${p} | ${r.what} | ${r.where} |`);
        lines.push('');
    }
    lines.push(END);
    return lines.join('\n');
}

if (require.main === module) {
    const out = render(collect());
    if (process.argv.includes('--write')) {
        const doc = fs.readFileSync(CATALOG, 'utf8');
        const a = doc.indexOf(START), b = doc.indexOf(END);
        if (a < 0 || b < 0) throw new Error(`${CATALOG}: generated markers not found`);
        fs.writeFileSync(CATALOG, doc.slice(0, a) + out + doc.slice(b + END.length));
        console.log(`updated ${path.relative(ROOT, CATALOG)}`);
    } else {
        console.log(out);
    }
}

module.exports = { collect };
