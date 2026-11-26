// The third-party files in frontend/assets/libs are pinned by SHA-256 in
// vendored.json, next to where each came from and what (if anything) was
// changed. A file that is replaced, edited or added without updating the
// manifest fails here, so a tampered or accidentally swapped library cannot
// reach the image unnoticed.
//
// To update a library: download the release file, record its source and
// source_sha256, make only the change the entry describes, and put the
// SHA-256 of the shipped file in sha256.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const LIBS = path.join(__dirname, '..', '..', 'frontend', 'assets', 'libs');
const MANIFEST = 'vendored.json';
const manifest = JSON.parse(fs.readFileSync(path.join(LIBS, MANIFEST), 'utf8'));

test('every file in frontend/assets/libs is recorded in vendored.json', () => {
    const files = fs.readdirSync(LIBS).filter(f => f !== MANIFEST).sort();
    assert.deepEqual(files, Object.keys(manifest).sort());
});

for (const [file, entry] of Object.entries(manifest)) {
    test(`${file} is ${entry.name} ${entry.version} as recorded`, () => {
        for (const key of ['name', 'version', 'source', 'source_sha256', 'change', 'sha256']) {
            assert.ok(entry[key], `${file}: vendored.json entry has no ${key}`);
        }
        const bytes = fs.readFileSync(path.join(LIBS, file));
        assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), entry.sha256);
        if (entry.header) {
            const head = bytes.subarray(0, 300).toString('utf8');
            assert.ok(head.includes(entry.header), `header: ${head}`);
        }
        // The maps are not shipped; a reference to one is a 404 in DevTools.
        assert.ok(!bytes.toString('utf8').includes('sourceMappingURL'));
    });
}
