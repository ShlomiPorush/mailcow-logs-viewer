// Settings > Agents > App address for agents: the address offered is the OAuth2
// callback's, else the page's, and only one the server accepts (https, or http
// on this computer) with no path.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');

function stub() {
    const fn = function () { return proxy; };
    const proxy = new Proxy(fn, {
        get: (_, key) => (key === Symbol.toPrimitive ? () => '' : key === 'length' ? 0 : proxy),
        apply: () => proxy,
        construct: () => proxy,
    });
    return proxy;
}

function load() {
    const base = stub();
    const window = new Proxy({}, { get: (_, key) => key === 'matchMedia' ? () => ({ matches: false, addEventListener() {} }) : base[key] });
    const context = vm.createContext({
        document: stub(), window, localStorage: stub(), sessionStorage: stub(), navigator: stub(), location: stub(),
        console: { log() {}, error() {}, warn() {} }, setTimeout() {}, setInterval() {}, appTimezone: 'UTC', URL,
    });
    for (const file of ['utils.js', 'settings.js']) vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    return context;
}

test('the OAuth2 callback names the address first, without its path', () => {
    const { settingsAgentUrlSuggestion: suggest } = load();
    assert.equal(suggest('https://logs.example.com/api/auth/callback', 'https://10.0.0.5'), 'https://logs.example.com');
    assert.equal(suggest(' https://logs.example.com:8443/api/auth/callback ', ''), 'https://logs.example.com:8443');
    assert.equal(suggest('https://logs.example.com:443/x', ''), 'https://logs.example.com');
});

test('without a usable callback, the page address is offered', () => {
    const { settingsAgentUrlSuggestion: suggest } = load();
    assert.equal(suggest('', 'https://logs.example.com'), 'https://logs.example.com');
    assert.equal(suggest('not a url', 'https://logs.example.com'), 'https://logs.example.com');
    assert.equal(suggest('http://logs.example.com/api/auth/callback', 'https://logs.example.com'), 'https://logs.example.com');
    assert.equal(suggest(undefined, 'http://127.0.0.1:8082'), 'http://127.0.0.1:8082');
    assert.equal(suggest('', 'http://localhost:8080'), 'http://localhost:8080');
});

test('an address the server refuses is not offered', () => {
    const { settingsAgentUrlSuggestion: suggest } = load();
    assert.equal(suggest('', 'http://10.0.0.5:8080'), '');
    assert.equal(suggest('http://logs.example.com/cb', 'http://logs.example.com'), '');
    assert.equal(suggest('ftp://logs.example.com', 'file:///x'), '');
    assert.equal(suggest('', 'http://127.0.0.1.example.com'), '');
});
