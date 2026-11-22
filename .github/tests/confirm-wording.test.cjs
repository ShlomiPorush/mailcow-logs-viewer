// The questions the app asks before an action (showConfirmModal in utils.js) read
// alike: a sentence-case title, a direct question instead of "Are you sure", and a
// permanent delete says it cannot be undone.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');
const files = fs.readdirSync(frontend).filter(name => name.endsWith('.js'));

// Every call's argument object, up to the }) that closes it (the definition is not a call)
const calls = files.flatMap(name => {
    const source = fs.readFileSync(path.join(frontend, name), 'utf8');
    return [...source.matchAll(/(?<!function )showConfirmModal\(\{([\s\S]*?)\}\)/g)].map(m => ({ where: `${name}:${source.slice(0, m.index).split('\n').length}`, args: m[1] }));
});

test('the confirm calls are found', () => {
    assert.ok(calls.length > 30, `found ${calls.length}`);
});

test('no question starts with "Are you sure"', () => {
    const bad = calls.filter(c => /are you sure/i.test(c.args)).map(c => c.where);
    assert.deepEqual(bad, []);
});

test('titles are in sentence case: after the first word, only acronyms start with a capital', () => {
    const bad = [];
    for (const call of calls) {
        const title = (call.args.match(/title:([\s\S]*?)(?:,\s*(?:message|confirmText|size)\s*:|$)/) || [])[1] || '';
        const texts = [...title.matchAll(/(['"`])((?:(?!\1)[^\\]|\\.)*)\1/g)].map(m => m[2].replace(/\$\{[^}]*\}/g, ''));
        for (const text of texts) {
            const words = text.split(/\s+/).filter(Boolean).slice(1);
            if (words.some(word => /^[A-Z][a-z]/.test(word))) bad.push(`${call.where} "${text}"`);
        }
    }
    assert.deepEqual(bad, []);
});

test('a delete says it cannot be undone', () => {
    const bad = calls.filter(c => /confirmText:[^,}]*'Delete/.test(c.args) && !/cannot be undone/.test(c.args)).map(c => c.where);
    assert.deepEqual(bad, []);
});
