// A page opened by its own address (a link, a bookmark, a reload) opens at once
// in a real DOM (jsdom), with the real index.html and every script it loads: it
// does not wait for the checks that read mailcow or GitHub, which take their
// whole timeout when mailcow cannot be reached. jsdom is installed by CI outside
// the repository; set A11Y_MODULES to its node_modules:
//   npm install --no-save --prefix /tmp/a11y jsdom axe-core
//   A11Y_MODULES=/tmp/a11y/node_modules node --test .github/tests/deep-link.a11y.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM, VirtualConsole } = require(path.join(modules, 'jsdom'));

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');

// The page as served, without its scripts; the app's own scripts run in its order
const html = read('index.html');
const scripts = [...html.matchAll(/<script src="\/static\/([\w.-]+\.js)\?v=[^"]*"><\/script>/g)].map(m => m[1]);
const markup = html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/g, '');

const INFO = { app_title: 'mailcow Logs Viewer', version: '3.0.0', auth_enabled: true, disabled_features: [],
    settings_edit_via_ui_enabled: true, timezone: 'UTC' };
const answer = body => ({ ok: true, status: 200, headers: { get: () => null }, json: async () => body, clone() { return this; } });

// Sign-in and /api/info answer at once. The mailcow connection and app version
// checks answer only when the test releases them (every request to one of them
// at once); every other request never does. jsdom fires DOMContentLoaded itself
// once the scripts below have run.
function boot(address) {
    const dom = new JSDOM(markup, { runScripts: 'dangerously', pretendToBeVisual: true,
        url: `http://localhost${address}`, virtualConsole: new VirtualConsole() });
    const w = dom.window;
    w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    const asked = [];
    const held = {};
    w.fetch = url => {
        const u = String(url);
        asked.push(u);
        if (u.startsWith('/api/info')) return Promise.resolve(answer(INFO));
        if (u.startsWith('/api/auth/status')) return Promise.resolve(answer({ authenticated: true, auth_type: 'basic' }));
        const slow = u.match(/^\/api\/status\/(mailcow-connection|app-version)$/);
        if (slow) {
            if (!held[slow[1]]) {
                let release;
                const answered = new Promise(resolve => { release = body => resolve(answer(body)); });
                held[slow[1]] = Object.assign(release, { answered });
            }
            return held[slow[1]].answered;
        }
        return new Promise(() => {});
    };
    for (const name of scripts) {
        const script = w.document.createElement('script');
        script.textContent = read(name);
        w.document.body.appendChild(script);
    }
    return { w, asked, held, close: () => w.close() };
}

const settle = () => new Promise(resolve => setTimeout(resolve, 0));
async function until(check) {
    for (let i = 0; i < 100 && !check(); i++) await settle();
    return check();
}

const shown = w => [...w.document.querySelectorAll('.tab-content')].filter(el => !el.classList.contains('hidden')).map(el => el.id);

test('a Settings tab opened by its address loads Settings while mailcow does not answer', async () => {
    const p = boot('/settings/auth');
    try {
        assert.ok(await until(() => p.asked.includes('/api/settings/info')), `asked: ${p.asked.join(', ')}`);
        assert.equal(p.w.eval('currentTab'), 'settings');
        assert.equal(p.w.eval('settingsTab'), 'auth');
        assert.deepEqual(shown(p.w), ['content-settings']);
        assert.equal(p.w.location.pathname, '/settings/auth');
    } finally {
        p.close();
    }
});

// Every page, every tab of a page with tabs, and the addresses of pages that moved
function addresses() {
    const p = boot('/');
    try {
        const routes = p.w.eval('VALID_ROUTES');
        const subpages = p.w.eval('SUBPAGES');
        const list = [];
        for (const route of routes) {
            const page = subpages[route];
            const tabs = !page ? [null] : page.tabs || ['auth', 'notifications'];
            for (const sub of tabs) {
                const path = p.w.buildPath(route, sub ? { sub } : {});
                const canonical = p.w.canonicalRoute(route, sub ? { sub } : {});
                list.push({ path, route, sub, canonical });
            }
        }
        list.push({ path: '/settings', route: 'settings' }, { path: '/dmarc/tls', route: 'dmarc' }, { path: '/dmarc/example.com', route: 'dmarc' });
        list.push({ path: '/queue', route: 'outbound', sub: 'queue' }, { path: '/spam-filter', route: 'outbound', sub: 'suppressions' },
            { path: '/spam-filter/maps', route: 'rspamd' });
        return list;
    } finally {
        p.close();
    }
}

test('every page and tab opened by its address opens while mailcow and GitHub do not answer', async () => {
    const list = addresses();
    assert.ok(list.length > 25, `only ${list.length} addresses`);
    const failed = [];
    for (const { path, route, sub, canonical } of list) {
        const p = boot(path);
        try {
            const want = canonical ? canonical.route : route;
            // The old Security addresses open the card of the Settings tab they became
            const aliases = want === 'netfilter' ? p.w.eval('SECURITY_TAB_ALIASES') : {};
            const wantSub = canonical ? canonical.params.sub : (sub in aliases ? 'settings' : sub);
            const ok = await until(() => p.w.eval('currentTab') === want && shown(p.w).join() === `content-${want}`);
            const tab = wantSub && p.w.eval('SUBPAGES')[want] ? p.w.eval('SUBPAGES')[want].current() : wantSub;
            if (!ok || (wantSub && tab !== wantSub)) failed.push(`${path}: ${p.w.eval('currentTab')} ${shown(p.w).join()} ${tab || ''}`);
        } finally {
            p.close();
        }
    }
    assert.deepEqual(failed, []);
});

test('the sidebar counters still wait for the connection check, so they count a mailcow that is not connected', async () => {
    const p = boot('/messages');
    try {
        assert.ok(await until(() => p.w.eval('currentTab') === 'messages'));
        assert.ok(!p.asked.includes('/api/queue'), 'counters read before the connection check answered');
        assert.ok(await until(() => p.held['mailcow-connection']));
        p.held['mailcow-connection']({ connected: false });
        assert.ok(await until(() => p.asked.includes('/api/queue')), `asked: ${p.asked.join(', ')}`);
        assert.equal(p.w.document.getElementById('mailcow-connection-indicator').title, 'Not connected to mailcow');
    } finally {
        p.close();
    }
});
