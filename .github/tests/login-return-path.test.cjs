// The login page's ?next= target: only a page on this site, whatever dot
// segments or encoded dots it holds. The browser removes /./ and /../ while
// parsing, so a value that passes as /.//host can come out as //host, which
// location.replace() reads as another site.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const page = fs.readFileSync(path.join(__dirname, '../../frontend/login.html'), 'utf8');
const ORIGIN = 'https://logs.example.test';

function functionSource(name) {
    const start = page.indexOf(`function ${name}(`);
    assert.ok(start >= 0, `${name} not found in login.html`);
    let depth = 0;
    for (let i = page.indexOf('{', start); i < page.length; i++) {
        if (page[i] === '{') depth++;
        if (page[i] === '}' && --depth === 0) return page.slice(start, i + 1);
    }
    throw new Error(`${name} has no end`);
}

const context = vm.createContext({ URL, window: { location: { origin: ORIGIN } } });
vm.runInContext(functionSource('safeReturnPath'), context);
const safeReturnPath = context.safeReturnPath;

// Where location.replace(result) goes from the login page
function landsOn(value) {
    return new URL(safeReturnPath(value), `${ORIGIN}/login?next=x`);
}

test('dot segments cannot turn the target into another site', () => {
    for (const value of ['/.//evil.example.test/x', '/..//evil.example.test', '/a/..//evil.example.test',
        '/%2e//evil.example.test', '/%2E%2E//evil.example.test/', '/././/evil.example.test',
        '/a/b/../..//evil.example.test/x?y=1#z']) {
        assert.equal(landsOn(value).origin, ORIGIN, value);
        assert.equal(safeReturnPath(value), '/', value);
    }
});

test('other sites and the sign-in pages are refused', () => {
    for (const value of ['//evil.example.test', 'https://evil.example.test/', '/\\evil.example.test',
        'evil.example.test', '/login', '/login/x', '/api/info', '/static/login.html', '/./login', '']) {
        assert.equal(safeReturnPath(value), '/', value);
    }
});

test('a page on this site is kept with its query and fragment', () => {
    assert.equal(safeReturnPath('/messages?q=a%20b#row-1'), '/messages?q=a%20b#row-1');
    assert.equal(safeReturnPath('/oauth/authorize?client_id=x&state=s'), '/oauth/authorize?client_id=x&state=s');
    assert.equal(safeReturnPath('/a/../dmarc'), '/dmarc');
    assert.equal(landsOn('/security').href, `${ORIGIN}/security`);
});

test('every inline script of the login page parses', () => {
    const scripts = [...page.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
    assert.ok(scripts.length > 0);
    for (const code of scripts) new vm.Script(code);
});
