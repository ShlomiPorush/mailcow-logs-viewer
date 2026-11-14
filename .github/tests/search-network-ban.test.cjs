// The search in the top bar finds a Fail2ban network ban by its network and
// opens it on Security > Banned, with no country or network filter hiding it.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');

function stub() {
    const fn = function () { return proxy; };
    const proxy = new Proxy(fn, {
        get: (_, key) => (key === Symbol.toPrimitive ? () => '' : key === 'length' ? 0 : proxy),
        apply: () => proxy,
        construct: () => proxy,
    });
    return proxy;
}

function load(pageOpen) {
    const document = new Proxy(stub(), {
        get: (_, key) => key === 'getElementById' ? id => ({ classList: { contains: c => c === 'hidden' ? !(pageOpen && id === 'content-netfilter') : false } }) : stub(),
    });
    const context = vm.createContext({
        document, window: { disabledFeatures: [] }, localStorage: stub(), navigator: stub(), location: stub(),
        console: { log() {}, error() {}, warn() {} }, setTimeout() {}, setInterval() {}, appTimezone: 'UTC', URLSearchParams,
    });
    vm.runInContext(fs.readFileSync(path.join(frontend, 'utils.js'), 'utf8'), context);
    vm.runInContext(fs.readFileSync(path.join(frontend, 'search.js'), 'utf8'), context);
    const calls = [];
    vm.runInContext(`var securityCountry = 'Germany', securityNetwork = 'Example Network 5', securityTab = 'overview';`, context);
    context.setSecurityFilter = key => calls.push(['setSecurityFilter', key]);
    context.openSecurityList = key => calls.push(['openSecurityList', key]);
    context.authenticatedFetch = async url => ({ ok: true, status: 200, json: async () => ({
        items: url.includes('list=banned') ? [{ ip: '198.51.96.0/20', state: 'banned', network_size: 4096, attempts: 0 }] : [],
        counts: { review: 0, banned: 1 } }) });
    return { context, calls };
}

test('a network ban is found by its network and opens the Banned list with every country and network', async () => {
    for (const open of [false, true]) {
        const { context, calls } = load(open);
        const found = await context.gsSearchAddresses('198.51.96.0/20', undefined);
        assert.equal(found.items.length, 1);
        found.items[0].open();
        assert.equal(vm.runInContext('securityCountry', context), null);
        assert.equal(vm.runInContext('securityNetwork', context), null);
        // Already open: the list is asked again; otherwise the page opens on it
        assert.deepEqual(calls, [open ? ['setSecurityFilter', 'banned'] : ['openSecurityList', 'banned']]);
    }
});
