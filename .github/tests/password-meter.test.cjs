// A local user's password in Settings > Users (users.js). The server requires 8 to 256
// characters (backend services/passwords.py); Save stops the same, in the same words. The meter
// shows the strength as guidance: an uppercase letter, a lowercase letter, a number and a symbol,
// by Unicode category. Generate draws from crypto.getRandomValues, one of each kind at least.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const { test } = require('node:test');

const root = path.join(__dirname, '../..');
// getRandomValues counted, so a test can see the generator uses it
const draws = { count: 0 };
const crypto = { getRandomValues: array => { draws.count++; return webcrypto.getRandomValues(array); } };
const context = vm.createContext({ escapeHtml: text => String(text), crypto, Uint32Array });
vm.runInContext(fs.readFileSync(path.join(root, 'frontend/users.js'), 'utf8'), context);
const check = password => JSON.parse(JSON.stringify(context.usersPasswordCheck(password)));
const block = (password, required) => context.usersPasswordBlock(password, required);
// Top-level constants are not properties of the context: read them in it
const value = name => vm.runInContext(name, context);
const server = fs.readFileSync(path.join(root, 'backend/app/services/passwords.py'), 'utf8');

test('the dialog uses the server\'s words and limits', () => {
    assert.equal(value('USERS_PASSWORD_SHORT'), server.match(/^SHORT_PROBLEM = "([^"]+)"/m)[1]);
    assert.equal(value('USERS_PASSWORD_LONG'), server.match(/^LONG_PROBLEM = "([^"]+)"/m)[1]);
    assert.equal(value('USERS_PASSWORD_SHORT'), 'Use at least 8 characters.');
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
    assert.deepEqual(check(''), { met: { length: false, upper: false, lower: false, digit: false, symbol: false }, level: 0 });
    assert.deepEqual(check('abc').met, { length: false, upper: false, lower: true, digit: false, symbol: false });
    assert.deepEqual(check('ABCDEFGH').met, { length: true, upper: true, lower: false, digit: false, symbol: false });
    assert.deepEqual(check('12345678 ').met, { length: true, upper: false, lower: false, digit: true, symbol: true });
    assert.deepEqual(check('Abcdef1!'), { met: { length: true, upper: true, lower: true, digit: true, symbol: true }, level: 2 });
    assert.equal(check('Abcd日本12').met.symbol, false);     // letters without case are letters
    assert.equal(check('Abcdefg²').met.digit, false);        // a superscript two is a symbol
});

test('Save stops only the length: under 8 characters, or over 256', () => {
    assert.equal(block('', true), 'Use at least 8 characters.');
    assert.equal(block('', false), '');                     // editing: an empty field keeps the password
    assert.equal(block('Abcde1!', true), 'Use at least 8 characters.');
    assert.equal(block('Abcde1!', false), 'Use at least 8 characters.');
    // Weak, but long enough: saved
    for (const password of ['abcdefgh', '12345678', 'ABCDEFGH']) assert.equal(block(password, true), '', password);
    assert.equal(block('A1!' + 'b'.repeat(253), true), '');
    assert.equal(block('A1!' + 'b'.repeat(254), true), 'Use at most 256 characters.');
});

test('the length counts characters (code points), not UTF-16 units', () => {
    assert.equal(block('\u{1F600}'.repeat(7), true), 'Use at least 8 characters.');   // 14 units
    assert.equal(block('\u{1F600}'.repeat(8), true), '');
    const password = '\u{1F600}'.repeat(126) + 'Ab1!x';                             // 131 characters, 257 units
    assert.equal(password.length, 257);
    assert.equal(block(password, true), '');
});

test('Generate makes the length asked, with one of each kind, from the four sets only', () => {
    const sets = [...value('USERS_PASSWORD_SETS')];
    for (const length of [12, 20, 64]) {
        for (let i = 0; i < 50; i++) {
            const password = context.usersGeneratePassword(length);
            assert.equal(password.length, length);
            for (const set of sets) assert.ok([...password].some(c => set.includes(c)), `${password} lacks one of ${set}`);
            assert.ok([...password].every(c => sets.some(set => set.includes(c))), password);
            assert.equal(check(password).level >= 3, true, 'a generated password is Good or Strong');
        }
    }
});

test('Generate draws from crypto.getRandomValues', () => {
    const before = draws.count;
    context.usersGeneratePassword(20);
    // One draw per character and per swap of the shuffle at least
    assert.ok(draws.count - before >= 39, `${draws.count - before} draws`);
});

test('a draw from the uneven top of the range is drawn again (no bias)', () => {
    // n = 3: 2**32 is not a multiple of 3, so the highest value lies in the uneven top part
    const values = [0xFFFFFFFF, 0xFFFFFFFE, 7];
    const fixed = vm.createContext({ escapeHtml: String, Uint32Array, crypto: { getRandomValues: array => { array[0] = values.shift(); return array; } } });
    vm.runInContext(fs.readFileSync(path.join(root, 'frontend/users.js'), 'utf8'), fixed);
    // 0xFFFFFFFF is past the limit; 0xFFFFFFFE (4294967294) is the last value below it: 4294967294 % 3 = 2
    assert.equal(fixed.usersRandomIndex(3), 2);
    assert.deepEqual(values, [7]);
});
