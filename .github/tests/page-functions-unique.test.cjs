const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

// The page scripts share one global scope, so a function declared twice is
// silently replaced by the later one, in the same file or in another script
const frontend = path.join(__dirname, '../../frontend');
const html = fs.readFileSync(path.join(frontend, 'index.html'), 'utf8');
const scripts = [...html.matchAll(/<script src="\/static\/([\w-]+\.js)[^"]*"><\/script>/g)].map(m => m[1]);

test('no two page scripts declare the same top-level function', () => {
    assert.ok(scripts.includes('dmarc.js'));
    const seen = new Map();
    const twice = [];
    for (const file of scripts) {
        const source = fs.readFileSync(path.join(frontend, file), 'utf8');
        for (const [, name] of source.matchAll(/^(?:async\s+)?function\s+([\w$]+)\s*\(/gm)) {
            if (seen.has(name)) twice.push(`${name} (${seen.get(name)}, ${file})`);
            else seen.set(name, file);
        }
    }
    assert.deepEqual(twice, []);
});

test('the All domains table shows each domain\'s DMARC policy', () => {
    const source = fs.readFileSync(path.join(frontend, 'dmarc.js'), 'utf8');
    // The helper the DMARC policy column calls, run with every declaration in the file, in order
    const helper = source.match(/data-label="DMARC policy">\$\{(\w+)\(d\)\}/)[1];
    const declarations = [...source.matchAll(/^function dmarc\w*PolicyTag\([\s\S]*?^}\n/gm)].map(m => m[0]);
    const context = vm.createContext({ dmarcTag: (tone, text) => `${tone}:${text}` });
    vm.runInContext(`const DMARC_POLICY_LEVEL = { none: ['fail', 'Monitoring'], quarantine: ['warn', 'Partial'], reject: ['ok', 'Enforced'] };\n${declarations.join('')}`, context);
    const tag = record => context[helper]({ dmarc_record: record });
    assert.equal(tag({ checked: true, found: true, policy: 'reject' }), 'ok:Reject');
    assert.equal(tag({ checked: true, found: true, policy: 'quarantine' }), 'warn:Quarantine');
    assert.equal(tag({ checked: true, found: true, policy: 'none' }), 'warn:None');
    assert.equal(tag({ checked: true, found: false }), 'fail:No record');
    assert.equal(tag({}), 'mut:Not checked');
});
