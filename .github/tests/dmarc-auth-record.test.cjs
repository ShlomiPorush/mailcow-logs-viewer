const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../../frontend/dmarc.js'), 'utf8');
const start = source.indexOf('// SPF or DKIM for the domain');
const end = source.indexOf('function dmarcTlsRecord', start);
assert.ok(start > 0 && end > start);
const records = source.slice(source.indexOf('function dmarcRecordsCard'), source.indexOf('function dmarcSendersCard'));
const policyTag = source.slice(source.indexOf('// How much a policy protects'), source.indexOf('const DMARC_POLICIES'));

function load() {
    const context = vm.createContext({
        escapeHtml: value => String(value),
        escapeJsArg: value => String(value),
        dmarcNum: value => String(value),
        dmarcPct: value => `${Math.round(value)}%`,
        dmarcTone: pct => (pct >= 95 ? 'ok' : pct >= 80 ? 'warn' : 'fail'),
        dmarcRate: pct => `${Math.round(pct)}%`,
        dmarcTag: (tone, text) => `<span class="tag">${text}</span>`,
    });
    vm.runInContext(source.slice(start, end) + records + policyTag, context);
    return context;
}

const group = (name, total, spf, dkim) => ({ name, total, spf, dkim, spfPct: spf / total * 100, dkimPct: dkim / total * 100, ips: [{ source_ip: `ip-${name}` }], place: '' });
const domain = {
    name: 'example.com',
    record: { record: 'v=DMARC1; p=none', policy: 'none', settings: {} },
    tlsRecord: {},
    spfPct: 0, dkimSeen: true,
    groups: [group('Hosting', 300, 300, 300), group('Newsletter', 100, 10, 100)],
};

test('the SPF window lists the senders, weakest first, each opening its details', () => {
    const html = load().dmarcAuthRecord(domain, 'spf');
    assert.match(html, /78% of your mail passed SPF/);
    assert.ok(html.indexOf('Newsletter') < html.indexOf('Hosting'));
    assert.match(html, /loadSourceDetails\('example\.com', 'ip-Newsletter'\)/);
    assert.match(html, /<th class="r">SPF aligned<\/th>/);
});

test('the DKIM window reads the DKIM share', () => {
    const html = load().dmarcAuthRecord(domain, 'dkim');
    assert.match(html, /100% of your mail was signed with DKIM/);
    assert.match(html, /DKIM aligned/);
});

test('without mail the window says the reports say nothing yet', () => {
    const html = load().dmarcAuthRecord({ ...domain, groups: [] }, 'spf');
    assert.match(html, /No mail in the last 30 days/);
});

test('the SPF and DKIM rows open their own windows, not the DMARC one', () => {
    const html = load().dmarcRecordsCard(domain);
    assert.match(html, /openDmarcRecord\('spf', 'example\.com'\)/);
    assert.match(html, /openDmarcRecord\('dkim', 'example\.com'\)/);
    assert.equal((html.match(/openDmarcRecord\('dmarc'/g) || []).length, 1);
});
