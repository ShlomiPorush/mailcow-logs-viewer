const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');
const fn = (file, name) => {
    const source = fs.readFileSync(path.join(frontend, file), 'utf8');
    const start = source.indexOf(`function ${name}(`);
    assert.ok(start !== -1, `${file} has ${name}`);
    return source.slice(start, source.indexOf('\n}\n', start) + 3);
};

test('the whitelist splits on lines, commas, semicolons and spaces, but not inside quotes', () => {
    const context = vm.createContext({});
    vm.runInContext(fn('smtp-abuse.js', 'smtpAbuseWhitelistLines'), context);
    const lines = text => JSON.parse(JSON.stringify(context.smtpAbuseWhitelistLines(text)));
    assert.deepEqual(lines('a@example.com, b@example.com'), ['a@example.com', 'b@example.com']);
    assert.deepEqual(lines('a@example.com\nb@example.com;c@example.com d@example.com'), ['a@example.com', 'b@example.com', 'c@example.com', 'd@example.com']);
    assert.deepEqual(lines('"a,b"@example.com\nc@example.com'), ['"a,b"@example.com', 'c@example.com']);
    assert.deepEqual(lines('"a\\",b"@example.com, c@example.com'), ['"a\\",b"@example.com', 'c@example.com']);
    assert.deepEqual(lines('  \n '), []);
});

test('the wizard reads "*.example.com" as example.com, which it covers with its subdomains', () => {
    const source = fs.readFileSync(path.join(frontend, 'spam_filter.js'), 'utf8');
    assert.ok(source.includes("const domain = suppressionDomainInput(value).replace(/^\\*\\./, '');"));
});
