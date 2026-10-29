// Every change the page can send is covered by the signed-in person's access
// (issue #544). The server checks each call anyway; this keeps the page from
// offering a control the server would refuse. For every fetch with a method other
// than GET in frontend/*.js, the function that sends it is listed in WRITES with
// the area it acts in, and that area is the one the backend gives the route
// (agent_access/scopes.py POLICY, user_access.py HUMAN_ENTRIES). Such a function
// starts with uiMayAct('<area>') (utils.js), and every inline control that calls it
// carries data-acts="<area>" (ui.css hides it while the person may not act there).
// A call that changes nothing, or a page only an admin reaches, is listed below
// with the reason. A new write call without a decision fails here.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

const ROOT = path.join(__dirname, '../..');
const FRONTEND = path.join(ROOT, 'frontend');

// file function -> the area it takes action in ('admin' for an admin's own)
const WRITES = {
    'app.js unbanIP': 'security',
    'app.js banIP': 'security',
    'app.js allowIP': 'security',
    'app.js acknowledgeSecurityAlert': 'security',
    'app.js acknowledgeAllSecurityAlerts': 'security',
    'app.js undoAlertDismissal': 'security',
    'app.js queueAction': 'outbound',
    'app.js queueDeleteRequest': 'outbound',
    'app.js quarantineAction': 'quarantine',
    'app.js _submitQuarantineRule': 'quarantine',
    'app.js deleteQuarantineRule': 'quarantine',
    'app.js toggleQuarantineRule': 'quarantine',
    'app.js setContainerIgnored': 'status',
    'app.js checkBlacklists': 'status',
    'app.js setBlocklistIgnored': 'status',
    'app.js runBackgroundJob': 'admin',
    'dmarc.js uploadDmarcReport': 'dmarc',
    'dmarc.js triggerDmarcSync': 'dmarc',
    'dmarc.js deleteDomainReports': 'dmarc',
    'dmarc.js deleteReport': 'dmarc',
    'domains.js checkAllDomainsDNS': 'domains',
    'domains.js checkSingleDomainDNS': 'domains',
    'entity-card.js entityCardCheckRbl': 'status',
    'protection.js saveProtectionRules': 'security',
    'protection.js protectionHitAction': 'security',
    'rate-limits.js resetRateLimitCounter': 'mailboxes',
    'rate-limits.js applyRateLimitBulk': 'mailboxes',
    'rate-limits.js submitRateLimit': 'mailboxes',
    'security.js securityRemoveFromList': 'security',
    'security.js securityRepairListEntry': 'security',
    'security.js saveSecurityF2b': 'security',
    'security.js saveSecurityAbuse': 'admin',
    'smtp-abuse.js smtpAbuseAction': 'security',
    'smtp-abuse.js saveSmtpAbuseWhitelist': 'security',
    'smtp-abuse.js removeSmtpAbuseWhitelist': 'security',
    'spam_filter.js saveMapContentOnce': 'rspamd',
    'spam_filter.js createSuppression': 'outbound',
    'spam_filter.js saveEditSuppression': 'outbound',
    'spam_filter.js toggleSuppression': 'outbound',
    'spam_filter.js deleteSuppression': 'outbound',
    'spam_filter.js autoSyncToRspamd': 'outbound',
    'spam_filter.js importSuppressions': 'outbound',
    'users.js setUsersDefault': 'admin',
    'users.js saveUser': 'admin',
    'users.js deleteUser': 'admin',
};

// The routes of a call whose address is not written out in the call
const DYNAMIC = {
    'app.js quarantineAction': ['POST /api/quarantine/release', 'POST /api/quarantine/delete',
        'POST /api/quarantine/learnham', 'POST /api/quarantine/learnspam'],
    'app.js _submitQuarantineRule': ['POST /api/quarantine/rules', 'PUT /api/quarantine/rules/{rule_id}'],
    'rate-limits.js submitRateLimit': ['POST /api/rate-limits/mailbox', 'POST /api/rate-limits/domain'],
    'app.js checkBlacklists': ['POST /api/blacklist/check'],
    'protection.js protectionHitAction': ['POST /api/protection/hits/{hit_id}/dismiss', 'POST /api/protection/hits/{hit_id}/ban',
        'POST /api/protection/hits/{hit_id}/undo'],
    'smtp-abuse.js smtpAbuseAction': ['POST /api/smtp-abuse/mailboxes/{email}/block', 'POST /api/smtp-abuse/mailboxes/{email}/unblock'],
    'users.js saveUser': ['POST /api/users', 'PUT /api/users/{user_id}'],
};

// Sent with POST but changing nothing, or allowed to anyone signed in
const NOT_ACTIONS = {
    'app.js handleLogout': 'signing out works whatever the access',
    'session-guard.js sessionGuardSignOut': 'signing out works whatever the access',
    'session-guard.js sessionGuardSend': 'the session checks (status and activity), open to anyone signed in',
    'app.js testQuarantineRules': 'a dry run of the rules: POST /api/quarantine/rules/test is View on Quarantine',
    'spam_filter.js validateMapContent': 'checks a map: POST /api/rspamd/validate is View on Rspamd',
};

// Files whose page only an admin reaches; the menu leaves it out for anyone else
const ADMIN_PAGES = {
    'settings.js': 'the Settings page',
    'notifications.js': 'Settings > Notifications',
    'agents.js': 'Settings > Agents',
    'authorize.js': 'the agent approval page, which the server opens to admins only',
};

// ------------------------------------------------------------------ the backend's areas

function backendRoutes() {
    const scopes = fs.readFileSync(path.join(ROOT, 'backend/app/agent_access/scopes.py'), 'utf8');
    const human = fs.readFileSync(path.join(ROOT, 'backend/app/user_access.py'), 'utf8');
    const routes = [];
    const add = (method, route, need) => routes.push({ method, route, need, re: routeRe(route) });
    // Where people differ from agents: an area's write, or the admin
    for (const m of human.matchAll(/\("(GET|POST|PUT|DELETE) (\/[^"]+)", (_ADMIN|Need\(AREAS, \(\("(\w+)", policy\.(WRITE|READ)\),\)\))\)/g)) {
        add(m[1], m[2], m[3] === '_ADMIN' ? 'admin' : `${m[4]}:${m[5] === 'WRITE' ? 'write' : 'read'}`);
    }
    for (const block of scopes.matchAll(/\*\*_r\(([\s\S]*?)area="?(\w+)"?, kind=(READ|WRITE)/g)) {
        const area = block[2] === 'ANY' ? 'any' : block[2];
        for (const r of block[1].matchAll(/"(GET|POST|PUT|DELETE) (\/[^"]+)"/g)) {
            add(r[1], r[2], area === 'settings' ? 'admin' : `${area}:${block[3] === 'WRITE' ? 'write' : 'read'}`);
        }
    }
    // Excluded from agents: settings changes, credential checks, test sends and job runs are an admin's
    for (const m of scopes.matchAll(/\("(GET|POST|PUT|DELETE)", "(\/api\/[^"]+)"\):/g)) add(m[1], m[2], 'admin');
    return routes;
}

function routeRe(route) {
    return new RegExp('^' + route.replace(/[.?+*()[\]\\^$|]/g, '\\$&').replace(/\{[^}]*\}/g, '\\{\\}') + '$');
}

// /api/users and /api/agents are an admin's, whatever the method
function needOf(routes, method, url) {
    if (/^\/api\/(users|agents)(\/|$)/.test(url)) return 'admin';
    const found = routes.find(r => r.method === method && r.re.test(url));
    return found ? found.need : null;
}

// ------------------------------------------------------------------ the frontend's calls

// The top-level function each offset belongs to (null outside any)
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

// A template's ${...} parts written as {}, and the query left out
function urlShape(literal) {
    let out = '';
    for (let i = 0; i < literal.length; i++) {
        if (literal[i] === '$' && literal[i + 1] === '{') {
            let depth = 0;
            for (; i < literal.length; i++) {
                if (literal[i] === '{') depth++;
                else if (literal[i] === '}' && --depth === 0) break;
            }
            out += '{}';
            continue;
        }
        out += literal[i];
    }
    return out.split('?')[0];
}

// Every fetch with a method other than GET: { file, fn, line, methods, url }
function writeCalls(dir) {
    const calls = [];
    for (const file of fs.readdirSync(dir).filter(f => f.endsWith('.js')).sort()) {
        const text = fs.readFileSync(path.join(dir, file), 'utf8');
        const owner = functionAt(text);
        for (const m of text.matchAll(/\bmethod\s*:\s*([^,}\n]+)|\{\s*method\s*,|,\s*method\s*,/g)) {
            const value = m[1] ? m[1].trim() : 'variable';
            const methods = [...value.matchAll(/['"`](POST|PUT|DELETE|PATCH)['"`]/g)].map(x => x[1]);
            if (m[1] && !methods.length) continue;      // GET, or not a request
            const before = text.slice(Math.max(0, m.index - 600), m.index);
            const at = before.toLowerCase().lastIndexOf('fetch(');
            if (at === -1) continue;                     // a method key that is not a request
            const literal = before.slice(at + 6).match(/^\s*(['"`])((?:\\.|(?!\1)[^\\])*)\1/);
            calls.push({ file, fn: owner(m.index), line: lineOf(text, m.index), methods: methods.length ? methods : ['POST', 'PUT', 'DELETE'],
                url: literal ? urlShape(literal[2]) : null });
        }
    }
    return calls;
}

// The end of the tag that starts at `start`: the first > outside quotes and ${...}
function tagEnd(text, start) {
    let depth = 0, quote = false;
    for (let i = start + 1; i < text.length; i++) {
        const c = text[i];
        if (depth === 0 && c === '"') quote = !quote;
        else if (c === '$' && text[i + 1] === '{') { depth++; i++; }
        else if (depth > 0 && c === '{') depth++;
        else if (depth > 0 && c === '}') depth--;
        else if (c === '>' && depth === 0 && !quote) return i + 1;
    }
    return text.length;
}

// Every inline handler that calls one of these functions, with its whole tag
function handlerTags(dir, names) {
    const found = [];
    const files = [...fs.readdirSync(dir).filter(f => f.endsWith('.js')).sort(), 'index.html'];
    for (const file of files) {
        const text = fs.readFileSync(path.join(dir, file), 'utf8');
        for (const m of text.matchAll(/\son(?:click|change|submit|input)\s*=\s*"([^"]*)"/g)) {
            const called = [...m[1].matchAll(/([A-Za-z_$][\w$]*)\s*\(/g)].map(c => c[1]).filter(n => names.has(n));
            if (!called.length) continue;
            const start = text.lastIndexOf('<', m.index);
            const tag = text.slice(start, tagEnd(text, start));
            called.forEach(name => found.push({ file, line: lineOf(text, m.index), name, tag }));
        }
    }
    return found;
}

// ------------------------------------------------------------------ the check

function check(dir = FRONTEND) {
    const problems = [];
    const routes = backendRoutes();
    const calls = writeCalls(dir);
    const seen = new Set();
    for (const call of calls) {
        const key = `${call.file} ${call.fn}`;
        const where = `${call.file}:${call.line} ${call.fn || 'top-level code'}`;
        if (ADMIN_PAGES[call.file] || NOT_ACTIONS[key]) { seen.add(key); continue; }
        const area = WRITES[key];
        if (!area) {
            problems.push(`${where} sends a change and is not in WRITES: list it with its area, gate its controls with data-acts and start it with uiMayAct`);
            continue;
        }
        seen.add(key);
        // The area agrees with the backend's for every route the call can reach
        const asked = DYNAMIC[key] ? DYNAMIC[key].map(r => r.replace(/\{[^}]*\}/g, '{}').split(' ')) : call.url ? call.methods.map(m => [m, call.url]) : null;
        if (!asked) { problems.push(`${where}: its address is not written out; list its routes in DYNAMIC`); continue; }
        const needs = asked.map(([method, url]) => needOf(routes, method, url)).filter(Boolean);
        if (!needs.length) problems.push(`${where}: no backend route matches ${asked.map(a => a.join(' ')).join(', ')}`);
        // A check on the way (View, like a map's validation before its save) is not the change itself
        for (const need of new Set(needs.filter(n => !/:read$/.test(n) && n !== 'any:read'))) {
            const expected = need === 'admin' ? 'admin' : need.endsWith(':write') ? need.split(':')[0] : null;
            if (expected !== area) problems.push(`${where}: listed as ${area}, the backend wants ${need}`);
        }
    }
    for (const key of Object.keys({ ...WRITES, ...NOT_ACTIONS })) {
        if (!seen.has(key)) problems.push(`${key} is listed but sends no change any more`);
    }
    // Each listed function checks the access first
    const sources = {};
    for (const key of Object.keys(WRITES)) {
        const [file, fn] = key.split(' ');
        const text = sources[file] = sources[file] || (fs.existsSync(path.join(dir, file)) ? fs.readFileSync(path.join(dir, file), 'utf8') : '');
        const start = text.search(new RegExp(`^(?:async\\s+)?function\\s+${fn.replace(/\$/g, '\\$')}\\s*\\(`, 'm'));
        if (start === -1) continue;
        const body = text.slice(start, text.indexOf('\n}', start));
        const guard = body.indexOf(`uiMayAct('${WRITES[key]}')`);
        const request = body.search(/fetch\(/);
        if (guard === -1 || (request !== -1 && guard > request)) problems.push(`${key} does not start with uiMayAct('${WRITES[key]}')`);
    }
    // Each control that calls one carries its area
    const names = new Map(Object.entries(WRITES).map(([key, area]) => [key.split(' ')[1], area]));
    for (const { file, line, name, tag } of handlerTags(dir, new Set(names.keys()))) {
        const acts = (tag.match(/\sdata-acts="([^"]*)"/) || [])[1] || '';
        if (!acts.split(/\s+/).includes(names.get(name))) {
            problems.push(`${file}:${line} a control calls ${name} without data-acts="${names.get(name)}"`);
        }
    }
    return problems;
}

test('every change the page sends is covered by the person\'s access', () => {
    assert.deepEqual(check(), []);
});

test('the reasons and pages listed still exist', () => {
    for (const file of Object.keys(ADMIN_PAGES)) assert.ok(fs.existsSync(path.join(FRONTEND, file)), `${file} is gone`);
    for (const key of Object.keys(DYNAMIC)) assert.ok(WRITES[key], `${key} is in DYNAMIC but not in WRITES`);
});

test('the backend routes are read', () => {
    const routes = backendRoutes();
    assert.ok(routes.length > 100, 'the route table was read');
    assert.equal(needOf(routes, 'POST', '/api/queue/action'), 'outbound:write');
    assert.equal(needOf(routes, 'POST', '/api/dmarc/upload'), 'dmarc:write');
    assert.equal(needOf(routes, 'PUT', '/api/settings'), 'admin');
    assert.equal(needOf(routes, 'DELETE', '/api/users/{}'), 'admin');
});

// A copy of the frontend with one file changed, to show the check catches it
function checkWith(file, edit) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'write-access-'));
    try {
        for (const name of fs.readdirSync(FRONTEND).filter(f => f.endsWith('.js') || f === 'index.html')) {
            fs.copyFileSync(path.join(FRONTEND, name), path.join(dir, name));
        }
        const target = path.join(dir, file);
        fs.writeFileSync(target, edit(fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : ''));
        return check(dir);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

const BYPASSES = {
    'a new write call nobody decided about': ['domains.js', t => t + "\nasync function forgetDomain(name) {\n    await authenticatedFetch(`/api/domains/${name}/check-dns`, { method: 'POST' });\n}\n", 'not in WRITES'],
    'a write function without its guard': ['domains.js', t => t.replace("    if (!uiMayAct('domains')) return;\n", ''), "checkAllDomainsDNS does not start"],
    'a control without data-acts': ['index.html', t => t.replace('onclick="checkAllDomainsDNS()" class="ui-btn ui-btn-primary ui-head-primary" data-acts="domains"', 'onclick="checkAllDomainsDNS()" class="ui-btn ui-btn-primary ui-head-primary"'), 'without data-acts="domains"'],
    'a control in a template without data-acts': ['spam_filter.js', t => t.replace('title="Delete permanently" data-acts="outbound"', 'title="Delete permanently"'), 'calls deleteSuppression'],
};

for (const [name, [file, edit, expect]] of Object.entries(BYPASSES)) {
    test(`the check catches ${name}`, () => {
        const problems = checkWith(file, edit);
        assert.ok(problems.some(p => p.includes(expect)), `no finding names "${expect}": ${problems.join('; ') || 'none'}`);
    });
}
