// A local user's password in Settings > Users (users.js): the strength the meter shows, the
// requirements it marks, and the words that block Save are the server's rule and words
// (backend services/passwords.py): at least 8 characters with an uppercase letter, a lowercase
// letter, a number and a symbol, by Unicode category; at most 256.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const root = path.join(__dirname, '../..');
const context = vm.createContext({ escapeHtml: text => String(text) });
vm.runInContext(fs.readFileSync(path.join(root, 'frontend/users.js'), 'utf8'), context);
const check = password => JSON.parse(JSON.stringify(context.usersPasswordCheck(password)));
// Top-level constants are not properties of the context: read them in it
const value = name => vm.runInContext(name, context);
const server = fs.readFileSync(path.join(root, 'backend/app/services/passwords.py'), 'utf8');

test('the dialog uses the server\'s words and limits', () => {
    assert.equal(value('USERS_PASSWORD_WEAK'), server.match(/^WEAK_PROBLEM = "([^"]+)"/m)[1]);
    assert.equal(value('USERS_PASSWORD_LONG'), server.match(/^LONG_PROBLEM = "([^"]+)"/m)[1]);
    assert.match(server, /^MIN_LENGTH = 8$/m);
    assert.match(server, /^MAX_LENGTH = 256$/m);
});

test('the strength: none when empty, Weak until every requirement is met, then by length', () => {
    const levels = {
        '': 0, 'a': 1, 'Abcdefg1': 1, 'abcdef1!': 1, 'Abcde1!': 1,
        'Abcdef1!': 2, 'Abcdefg1!': 2,                     // 8 and 9 characters: Fair
        'Abcdefgh1!': 3, 'Abcdefghijk1!': 3,               // 10 and 13: Good
        'Abcdefghijkl1!': 4, 'Correct Horse 7 Battery': 4, // 14 and more: Strong
    };
    for (const [password, level] of Object.entries(levels)) assert.equal(check(password).level, level, password);
    assert.deepEqual([...value('USERS_STRENGTH')], ['', 'Weak', 'Fair', 'Good', 'Strong']);
});

test('each requirement is marked on its own', () => {
    assert.deepEqual(check(''), { met: { length: false, upper: false, lower: false, digit: false, symbol: false }, level: 0,
        problem: 'Use at least 8 characters with an uppercase letter, a lowercase letter, a number and a symbol.' });
    assert.deepEqual(check('abc').met, { length: false, upper: false, lower: true, digit: false, symbol: false });
    assert.deepEqual(check('ABCDEFGH').met, { length: true, upper: true, lower: false, digit: false, symbol: false });
    assert.deepEqual(check('12345678 ').met, { length: true, upper: false, lower: false, digit: true, symbol: true });
    assert.deepEqual(check('Abcdef1!'), { met: { length: true, upper: true, lower: true, digit: true, symbol: true }, level: 2, problem: '' });
});

test('letters and symbols are told apart as the server does (Unicode categories)', () => {
    assert.equal(check('Ärger12€').problem, '');            // letters and a symbol outside ASCII
    assert.equal(check('Пароль1!').problem, '');            // Cyrillic cases
    assert.equal(check('Abcd日本12').met.symbol, false);     // letters without case are letters
    assert.equal(check('Abcdefg²').met.digit, false);        // a superscript two is a symbol
    assert.equal(check('Abcdefg²').met.symbol, true);
    // Characters, not UTF-16 units: an astral letter counts once
    assert.equal(check('\u{1D49C}bcde1!').met.length, false);
    assert.equal(check('\u{1D49C}bcdef1!').level, 2);
});

test('over 256 characters says so', () => {
    assert.equal(check('A1!' + 'b'.repeat(253)).problem, '');
    assert.equal(check('A1!' + 'b'.repeat(254)).problem, 'Use at most 256 characters.');
});
