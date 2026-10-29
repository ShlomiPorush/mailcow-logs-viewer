const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../../frontend/dmarc.js'), 'utf8');
const start = source.indexOf('async function loadDmarcSettings');
const end = source.indexOf('// All domains', start);
assert.ok(start > 0 && end > start);

test('the DMARC page reads the upload setting again on each visit', async () => {
    const server = { manual_upload_enabled: false };
    const seen = [];
    const context = vm.createContext({
        authenticatedFetch: async url => {
            assert.equal(url, '/api/settings/info');
            return { ok: true, json: async () => ({ dmarc_configuration: { ...server } }) };
        },
        loadDmarcImapStatus: async () => {},
        updateDmarcControls: () => seen.push(context.dmarcConfiguration.manual_upload_enabled),
        dmarcState: { domains: [] },
        console: { error() {} },
        // Full access, as for the built-in admin (utils.js)
        userCan: () => true,
    });
    vm.runInContext('var dmarcConfiguration = null;', context);
    vm.runInContext(source.slice(start, end), context);
    const visit = () => vm.runInContext('dmarcLoadControls()', context);

    await visit();
    // Upload is turned on in Settings, then the page is opened again without a reload
    server.manual_upload_enabled = true;
    await visit();

    assert.deepEqual(seen, [false, true]);
});
