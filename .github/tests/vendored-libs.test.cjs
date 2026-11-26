// The third-party files in frontend/assets/libs are pinned by SHA-256 in
// vendored.json, next to where each came from and the one change (if any)
// made to it. A file that is replaced, edited or added without updating the
// manifest fails here.
//
// header: text the first 200 bytes must contain; by default "<name> <version> ",
// null for a file with no version banner (the stylesheet).
// license_file / license_sha256: a licence shipped next to the library.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const LIBS = path.join(__dirname, '..', '..', 'frontend', 'assets', 'libs');
const manifest = JSON.parse(fs.readFileSync(path.join(LIBS, 'vendored.json'), 'utf8'));
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

test('every file in frontend/assets/libs is recorded in vendored.json', () => {
    const recorded = new Set(['vendored.json']);
    for (const [file, entry] of Object.entries(manifest)) {
        recorded.add(file);
        if (entry.license_file) recorded.add(entry.license_file);
    }
    assert.deepEqual(fs.readdirSync(LIBS).filter(f => !recorded.has(f)), []);
});

for (const [file, entry] of Object.entries(manifest)) {
    test(`${file} is ${entry.name} ${entry.version} as recorded`, () => {
        for (const key of ['source', 'source_sha256', 'change', 'sha256']) {
            assert.ok(entry[key], `${file}: vendored.json entry has no ${key}`);
        }
        const bytes = fs.readFileSync(path.join(LIBS, file));
        assert.equal(sha256(bytes), entry.sha256);
        const expected = entry.header === undefined ? `${entry.name} ${entry.version} ` : entry.header;
        if (expected !== null) {
            const header = bytes.subarray(0, 200).toString('utf8');
            assert.ok(header.includes(expected), `header: ${header}`);
        }
        assert.ok(!bytes.toString('utf8').includes('sourceMappingURL'));
        if (entry.license_file) {
            assert.equal(sha256(fs.readFileSync(path.join(LIBS, entry.license_file))), entry.license_sha256);
        }
    });
}
