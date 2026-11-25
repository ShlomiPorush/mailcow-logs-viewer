const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM, VirtualConsole } = require(path.join(modules, 'jsdom'));

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');

const html = read('index.html');
const scripts = [...new JSDOM(html).window.document.querySelectorAll('script[src]')]
    .map(el => new URL(el.getAttribute('src'), 'http://localhost').pathname)
    .filter(src => /^\/static\/[\w.-]+\.js$/.test(src))
    .map(src => src.slice('/static/'.length));

const INFO = { app_title: 'mailcow Logs Viewer', version: '3.0.0', auth_enabled: true, disabled_features: [],
    settings_edit_via_ui_enabled: true, timezone: 'UTC' };
const answer = body => ({ ok: true, status: 200, headers: { get: () => null }, json: async () => body, clone() { return this; } });
const CONNECTION = '/api/status/mailcow-connection';

function boot(address) {
    const dom = new JSDOM(html, { runScripts: 'dangerously', pretendToBeVisual: true,
        url: `http://localhost${address}`, virtualConsole: new VirtualConsole() });
    const w = dom.window;
    w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    const asked = [];
    const connection = [];
    w.fetch = url => {
        const u = String(url);
        asked.push(u);
        if (u.startsWith('/api/info')) return Promise.resolve(answer(INFO));
        if (u.startsWith('/api/auth/status')) return Promise.resolve(answer({ authenticated: true, auth_type: 'basic' }));
        if (u === CONNECTION) return new Promise(resolve => connection.push(body => resolve(answer(body))));
        return new Promise(() => {});
    };
    for (const name of scripts) {
        const script = w.document.createElement('script');
        script.textContent = read(name);
        w.document.body.appendChild(script);
    }
    w.startAttention = () => {};
    const count = target => asked.filter(u => u === target).length;
    const indicator = () => w.document.getElementById('mailcow-connection-indicator');
    const later = () => w.eval('navCountersAt = Date.now() - NAV_COUNTERS_EVERY');
    return { w, asked, connection, count, indicator, later, close: () => w.close() };
}

const settle = () => new Promise(resolve => setTimeout(resolve, 0));
async function until(check) {
    for (let i = 0; i < 100 && !check(); i++) await settle();
    return check();
}

async function loaded(p, connected) {
    assert.ok(await until(() => p.connection.length === 1), `asked: ${p.asked.join(', ')}`);
    p.connection[0]({ connected });
    assert.ok(await until(() => p.count('/api/queue') === 1), `asked: ${p.asked.join(', ')}`);
}

test('the first load checks the connection once', async () => {
    const p = boot('/messages');
    try {
        await loaded(p, true);
        await settle();
        assert.equal(p.count(CONNECTION), 1);
        assert.equal(p.indicator().title, 'Connected to mailcow');
        p.w.navCountersTick();
        await settle();
        assert.equal(p.count(CONNECTION), 1);
    } finally {
        p.close();
    }
});

test('the counters tick reads the connection again first, and the indicator shows mailcow back', async () => {
    const p = boot('/messages');
    try {
        await loaded(p, false);
        assert.equal(p.indicator().title, 'Not connected to mailcow');

        p.later();
        p.w.navCountersTick();
        assert.ok(await until(() => p.connection.length === 2), 'the tick did not check the connection');
        p.w.navCountersTick();
        await settle();
        assert.equal(p.count(CONNECTION), 2);
        assert.equal(p.count('/api/queue'), 1, 'counters read before the connection check answered');

        p.connection[1]({ connected: true });
        assert.ok(await until(() => p.count('/api/queue') === 2), `asked: ${p.asked.join(', ')}`);
        const indicator = p.indicator();
        assert.equal(indicator.title, 'Connected to mailcow');
        assert.ok(indicator.classList.contains('text-green-500') && !indicator.classList.contains('text-red-500'));
    } finally {
        p.close();
    }
});

test('a browser tab shown again reads the connection again once the counters are due', async () => {
    const p = boot('/settings/auth');
    try {
        await loaded(p, false);
        p.w.document.dispatchEvent(new p.w.Event('visibilitychange'));
        await settle();
        assert.equal(p.count(CONNECTION), 1, 'shown again within five minutes: nothing to read');

        p.later();
        p.w.document.dispatchEvent(new p.w.Event('visibilitychange'));
        assert.ok(await until(() => p.connection.length === 2), 'the tab shown again did not check the connection');
        p.connection[1]({ connected: true });
        assert.ok(await until(() => p.indicator().title === 'Connected to mailcow'));
    } finally {
        p.close();
    }
});

test('a check still pending after five minutes is not asked again until it answers', async () => {
    const p = boot('/messages');
    try {
        await loaded(p, true);
        p.later();
        p.w.navCountersTick();
        assert.ok(await until(() => p.connection.length === 2));
        p.later();
        p.w.navCountersTick();
        await settle();
        assert.equal(p.count(CONNECTION), 2, 'a second check while the first is pending');

        p.connection[1]({ connected: false });
        assert.ok(await until(() => p.count('/api/queue') === 2), `asked: ${p.asked.join(', ')}`);
        await settle();
        p.later();
        p.w.navCountersTick();
        assert.ok(await until(() => p.connection.length === 3), 'the next tick after the answer checks again');
    } finally {
        p.close();
    }
});
