// A small trend beside a figure (utils.js uiSparkline): six hours to a point over a
// week, a break where the samples stop, the dashed "Collecting" line with fewer than
// two, and words that say where it went and when it was read
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const utils = fs.readFileSync(path.join(__dirname, '../../frontend/utils.js'), 'utf8');
const zoneHelpers = utils.slice(utils.indexOf('function appTz()'), utils.indexOf('function formatSeconds('));
const code = utils.slice(utils.indexOf('function uiSparkline('), utils.indexOf('// Overview strip under a zoomable chart:'));
const H = 3600000;
const NOW = Date.parse('2026-10-22T12:00:00Z');

function load() {
    const context = vm.createContext({ Date, Math, Number, Intl, appTimezone: 'UTC',
        escapeHtml: v => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;') });
    vm.runInContext(zoneHelpers + '\n' + code, context);
    return context;
}
const hours = (from, to, value) => {
    const out = [];
    for (let t = from; t < to; t += H) out.push({ slot: new Date(t).toISOString(), value: value(t), as_of: new Date(t + 60000).toISOString() });
    return out;
};

test('a week of hourly samples is a line of six-hour points with the words of its ends', () => {
    const c = load();
    const points = hours(NOW - 7 * 24 * H, NOW, t => (t - (NOW - 7 * 24 * H)) / H / 10);
    c.__p = points;
    const svg = vm.runInContext(`uiSparkline(__p, { days: 7, now: ${NOW}, label: 'Mail storage used', format: v => Math.round(v) + '%' })`, c);
    const d = svg.match(/<path d="([^"]+)"/)[1];
    assert.equal((d.match(/M/g) || []).length, 1, 'one line, no gap');
    assert.equal((d.match(/[ML]/g) || []).length, 28, 'six hours to a point');
    assert.match(svg, /aria-label="Mail storage used, last 7 days: from 0% to 17%, as of 10\/22\/2026, 11:01"/);
    assert.match(svg, /role="img"/);
});

test('hours with no sample break the line: a gap, never a drop to zero', () => {
    const c = load();
    // Samples stop for a day in the middle (mailcow did not answer)
    c.__p = [...hours(NOW - 7 * 24 * H, NOW - 4 * 24 * H, () => 50), ...hours(NOW - 3 * 24 * H, NOW, () => 50)];
    const svg = vm.runInContext(`uiSparkline(__p, { days: 7, now: ${NOW} })`, c);
    const d = svg.match(/<path d="([^"]+)"/)[1];
    assert.equal((d.match(/M/g) || []).length, 2, 'two pieces');
    assert.ok(!/ 18(\.0)? /.test(d.replace(/^M/, ' ')), 'no point at the bottom');
});

test('fewer than two samples: a dashed line that says it is collecting', () => {
    const c = load();
    const none = vm.runInContext(`uiSparkline([], { now: ${NOW}, label: 'Messages linked' })`, c);
    assert.match(none, /is-collecting/);
    assert.match(none, /aria-label="Messages linked: Collecting: the first samples come within the hour"/);
    c.__p = hours(NOW - H, NOW, () => 99);
    const one = vm.runInContext(`uiSparkline(__p, { now: ${NOW}, label: 'Messages linked' })`, c);
    assert.match(one, /Collecting since 10\/22\/2026, 11:00/);
});

test('words are escaped', () => {
    const c = load();
    const svg = vm.runInContext(`uiSparkline([], { now: ${NOW}, label: '<b>"x"</b>' })`, c);
    assert.ok(!svg.includes('<b>'), svg);
});
