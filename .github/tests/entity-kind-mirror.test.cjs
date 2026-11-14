// The browser's side of the value normalizer (utils.js entityKindOf) reads an IP
// address as the server does (backend/app/services/entity_values.py normalize_ip,
// cases mirrored from backend/tests/test_entity_values.py): the search offers Ban
// and Allow only on what the server takes as one address.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const utils = fs.readFileSync(path.join(__dirname, '../../frontend/utils.js'), 'utf8');
const start = utils.indexOf('const UI_ENTITY_KINDS');
const end = utils.indexOf('function uiEntity(', start);
assert.ok(start >= 0 && end > start);
const context = vm.createContext({});
vm.runInContext(utils.slice(start, end) + '\nthis.entityKindOf = entityKindOf;', context);
const kind = value => context.entityKindOf(value);

test('one IP address, as normalize_ip accepts it', () => {
    for (const value of [
        '203.0.113.4', '  203.0.113.4\n', '2001:DB8:0:0:0:0:0:1', '2001:0db8:0000:0000:0000:ff00:0042:8329',
        '::ffff:203.0.113.4', '::1', '::', '2001:db8::7',
        '::192.0.2.1',                       // IPv4-compatible
        '0:0:0:0:0:ffff:192.0.2.1', '1:2:3:4:5:6:192.0.2.1', '1:2:3:4:5:6:7::', '::2:3:4:5:6:7:8',
    ]) assert.equal(kind(value), 'ip', JSON.stringify(value));
});

test('what normalize_ip refuses is not an IP address', () => {
    for (const value of [
        'fe80::1%eth0', '203.0.113.0/24', '203.0.113.4/32', '2001:db8::/64', '203.0.113.256', '203.0.113.04',
        '203.0.113.4 203.0.113.5', '203.0.113.4\x00', '', '1'.repeat(65),
        // An IPv4 tail that is not the last group, or not after the ::
        '192.0.2.1::', '192.0.2.1:ffff::', '::ffff:192.0.2.1:1', '::192.0.2.1:0', '1::192.0.2.1:2',
        // Malformed
        ':::', '1::2::3', '1:2:3:4:5:6:7:8:9', '1:2:3:4:5:6:7:8::', '1:2:3:4:5:6:7:192.0.2.1', '2001:db8::12345',
        '::ffff:192.0.2.01', '::ffff:192.0.2', '1::2:', ':1::2', '203.0.113.', '203.0.113.4,198.51.100.1',
    ]) assert.notEqual(kind(value), 'ip', JSON.stringify(value));
});
