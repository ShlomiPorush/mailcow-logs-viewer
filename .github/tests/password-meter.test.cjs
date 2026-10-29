// A local user's password in Settings > Users (users.js). The server decides whether it can be
// set (backend services/passwords.py: 8 to 256 characters, not a common password), and the
// dialog asks it before Save. The meter shows the strength as guidance: an uppercase letter, a
// lowercase letter, a number and a symbol, by Unicode category. Generate draws from
// crypto.getRandomValues: readable letters and digits, and a few easy symbols inside, apart.
// The username and email: the dialog stops only what is missing or too long; the server decides
// the rest, so the dialog never refuses what the server takes.
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

test('the meter counts characters (code points), not UTF-16 units', () => {
    assert.equal(check('\u{1F600}'.repeat(7)).met.length, false);   // 14 units
    assert.equal(check('\u{1F600}'.repeat(8)).met.length, true);
});

test('Generate: readable letters and digits, a few easy symbols inside, one of each kind', () => {
    const upper = value('USERS_PASSWORD_UPPER');
    const lower = value('USERS_PASSWORD_LOWER');
    const digits = value('USERS_PASSWORD_DIGITS');
    const symbols = value('USERS_PASSWORD_SYMBOLS');
    assert.equal(symbols, '!@#$%*-_');
    for (const lookAlike of '0Oo1lI') assert.ok(!(upper + lower + digits).includes(lookAlike), lookAlike);
    for (const length of [12, 13, 16, 20, 33, 64]) {
        for (let i = 0; i < 100; i++) {
            const password = context.usersGeneratePassword(length);
            const chars = [...password];
            assert.equal(chars.length, length);
            assert.ok(!/[0Oo1lI]/.test(password), `${password} has a look-alike`);
            for (const set of [upper, lower, digits]) assert.ok(chars.some(c => set.includes(c)), `${password} lacks one of ${set}`);
            assert.ok(chars.every(c => (upper + lower + digits + symbols).includes(c)), password);
            // About one symbol in 8 characters, one at least, never first or last
            assert.equal(chars.filter(c => symbols.includes(c)).length, Math.max(1, Math.floor(length / 8)), password);
            assert.ok(!symbols.includes(chars[0]) && !symbols.includes(chars[length - 1]), password);
            assert.ok(!chars.some((c, i) => symbols.includes(c) && symbols.includes(chars[i + 1])), `${password}: two symbols side by side`);
            assert.equal(check(password).level >= 3, true, 'a generated password is Good or Strong');
        }
    }
});

test('the username and email: only missing or too long is stopped here, the server decides the rest', () => {
    const name = context.usersUsernameProblem;
    const email = context.usersEmailProblem;
    assert.equal(name(''), 'Enter a username.');
    assert.equal(name('   '), 'Enter a username.');
    // The server folds case (groß becomes gross) and decides which characters it takes
    for (const ok of ['alice', 'Alice', 'groß', 'ﬁona', 'al ice', 'x'.repeat(64), '\u{1F600}'.repeat(64), ' bob ']) assert.equal(name(ok), '', ok);
    assert.equal(name('x'.repeat(65)), value('USERS_USERNAME_RULE'));
    const store = fs.readFileSync(path.join(root, 'backend/app/services/users_store.py'), 'utf8');
    assert.ok(store.includes(`return "${value('USERS_USERNAME_RULE')}"`), 'the server\'s words');
    assert.equal(email(''), 'Enter the email address.');
    assert.equal(email('  '), 'Enter the email address.');
    // Without the field, anything typed passes here; with it, the browser's own email check counts
    assert.equal(email('carol'), '');
    assert.equal(email('carol', { validity: { typeMismatch: true } }), 'Enter one email address.');
    assert.equal(email('carol@example.com', { validity: { typeMismatch: false } }), '');
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
