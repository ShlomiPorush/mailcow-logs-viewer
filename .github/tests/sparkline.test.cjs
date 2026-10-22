// A small trend beside a figure (utils.js uiSparkline): runs of hourly samples
// broken where an hour is missing, six hours to a point within a run, the latest
// reading as the line's end and its mark, the dashed "Collecting" line with fewer
// than two samples, and words that say where it went and when it was read
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
const pathOf = svg => svg.match(/<path d="([^"]+)"/)[1];
// The date as formatDay writes it in this machine's language
const day = (c, iso) => vm.runInContext(`formatDay(Date.parse('${iso}'))`, c);

test('a week of hourly samples is a line of six-hour points ending at the latest reading, with the words of its ends', () => {
    const c = load();
    c.__p = hours(NOW - 7 * 24 * H, NOW, t => (t - (NOW - 7 * 24 * H)) / H / 10);
    const svg = vm.runInContext(`uiSparkline(__p, { days: 7, now: ${NOW}, label: 'Mail storage used', format: v => Math.round(v) + '%' })`, c);
    const d = pathOf(svg);
    assert.equal((d.match(/M/g) || []).length, 1, 'one line, no gap');
    assert.equal((d.match(/[ML]/g) || []).length, 29, 'six hours to a point, and the latest reading');
    assert.ok(svg.includes(`aria-label="Mail storage used, last 7 days: from 0% to 17%, as of ${day(c, '2026-10-22T11:01:00Z')}, 11:01"`), svg.match(/aria-label="[^"]+"/)[0]);
    assert.match(svg, /role="img"/);
});

test('hours with no sample break the line, also inside one six hours: a gap, never a drop to zero', () => {
    const c = load();
    c.__p = [...hours(NOW - 7 * 24 * H, NOW - 4 * 24 * H, () => 50), ...hours(NOW - 3 * 24 * H, NOW, () => 50)];
    assert.equal((pathOf(vm.runInContext(`uiSparkline(__p, { days: 7, now: ${NOW} })`, c)).match(/M/g) || []).length, 2);
    // 00:00, then 05:00 and 06:00: four hours missing in between
    c.__p = ['2026-10-22T00:00:00Z', '2026-10-22T05:00:00Z', '2026-10-22T06:00:00Z'].map(s => ({ slot: s, value: 5, as_of: s }));
    assert.equal((pathOf(vm.runInContext(`uiSparkline(__p, { days: 7, now: ${NOW} })`, c)).match(/M/g) || []).length, 2);
});

test('a sample with no neighbour is a dot: three lone samples are three marks', () => {
    const c = load();
    c.__p = ['2026-10-22T00:00:00Z', '2026-10-22T05:00:00Z', '2026-10-22T10:00:00Z'].map((s, i) => ({ slot: s, value: i, as_of: s }));
    const svg = vm.runInContext(`uiSparkline(__p, { days: 7, now: ${NOW} })`, c);
    assert.equal((svg.match(/<circle class="is-lone"/g) || []).length, 2, 'the two before the latest');
    assert.equal((svg.match(/<circle /g) || []).length, 3, 'and the mark of the latest reading');
    // Samples in a run draw a line and get no dot
    c.__p = hours(NOW - 7 * 24 * H, NOW, () => 5);
    assert.doesNotMatch(vm.runInContext(`uiSparkline(__p, { days: 7, now: ${NOW} })`, c), /is-lone/);
});

test('the mark is the latest reading where it was read, not a six hours\' average', () => {
    const c = load();
    c.__p = [0, 0, 0, 0, 0, 60].map((v, i) => ({ slot: new Date(Date.parse('2026-10-22T00:00:00Z') + i * H).toISOString(), value: v, as_of: '' }));
    const svg = vm.runInContext(`uiSparkline(__p, { days: 7, now: ${NOW} })`, c);
    const cy = Number(svg.match(/<circle cx="[\d.]+" cy="([\d.]+)"/)[1]);
    assert.equal(cy, 2, 'at the top: the line\'s highest value is the latest reading');
    assert.ok(pathOf(svg).endsWith(' 2.0'), 'the line ends there');
});

test('two samples are a line already; fewer is a dashed line that says it is collecting', () => {
    const c = load();
    const none = vm.runInContext(`uiSparkline([], { now: ${NOW}, label: 'Messages linked' })`, c);
    assert.match(none, /is-collecting/);
    assert.match(none, /aria-label="Messages linked: Collecting: the first samples come within the hour"/);
    c.__p = hours(NOW - H, NOW, () => 99);
    const one = vm.runInContext(`uiSparkline(__p, { now: ${NOW}, label: 'Messages linked' })`, c);
    assert.ok(one.includes(`Collecting since ${day(c, '2026-10-22T11:00:00Z')}, 11:00`), one);
    c.__p = hours(NOW - 6 * H, NOW - 4 * H, () => 99);
    assert.doesNotMatch(vm.runInContext(`uiSparkline(__p, { now: ${NOW} })`, c), /is-collecting/);
});

test('words are escaped', () => {
    const c = load();
    const svg = vm.runInContext(`uiSparkline([], { now: ${NOW}, label: '<b>"x"</b>' })`, c);
    assert.ok(!svg.includes('<b>'), svg);
});
