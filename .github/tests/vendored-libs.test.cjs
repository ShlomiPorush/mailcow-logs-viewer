const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const LIBS = path.join(__dirname, '..', '..', 'frontend', 'assets', 'libs');
const manifest = JSON.parse(fs.readFileSync(path.join(LIBS, 'vendored.json'), 'utf8'));

for (const [file, entry] of Object.entries(manifest)) {
    test(`${file} is ${entry.name} ${entry.version} as recorded`, () => {
        const bytes = fs.readFileSync(path.join(LIBS, file));
        assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), entry.sha256);
        const header = bytes.subarray(0, 200).toString('utf8');
        assert.ok(header.includes(`${entry.name} ${entry.version} `), `header: ${header}`);
        assert.ok(!bytes.toString('utf8').includes('sourceMappingURL'));
    });
}
