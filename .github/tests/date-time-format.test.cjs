// How dates and times are written: Settings > Application > Time (/api/info
// `date_format`, `time_format`). Every date and time on screen goes through
// the helpers in utils.js; "browser" leaves the order or the clock to the
// browser's language, every other choice reads the same in every browser.
// The browser here is in New York; the app's zone is Europe/Berlin, whose
// summer time ends on 2026-10-25 (02:00 to 03:00 happens twice).
process.env.TZ = 'America/New_York';

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

// The page scripts in one scope, as in the browser. `language` is the
// browser's: Intl without a locale reads it.
function load({ zone = 'Europe/Berlin', date = 'browser', time = '24h', language = 'en-US', files = [] } = {}) {
    const RealFormat = Intl.DateTimeFormat;
    function DateTimeFormat(locale, options) { return new RealFormat(locale === undefined ? language : locale, options); }
    DateTimeFormat.supportedLocalesOf = RealFormat.supportedLocalesOf;
    const context = vm.createContext({
        document: stub(), window: { matchMedia: () => ({ matches: false }), addEventListener() {} }, localStorage: stub(),
        sessionStorage: stub(), navigator: stub(), location: stub(), console: { log() {}, error() {}, warn() {} },
        setTimeout() {}, setInterval() {}, clearTimeout() {}, URLSearchParams,
        Intl: { ...Intl, DateTimeFormat },
    });
    for (const file of ['utils.js', 'app.js', ...files]) {
        vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    }
    context.setAppTimezone({ timezone: zone, timezone_valid: true, timezone_configured: zone, date_format: date, time_format: time });
    return context;
}

const NOON = '2026-01-15T12:05:09Z';        // 13:05:09 in Berlin, a Thursday
const MIDNIGHT = '2026-01-14T23:00:00Z';    // 00:00 on the 15th in Berlin

// ---------- each choice ----------

test('every date format writes the same date in the order it names', () => {
    const cases = {
        'DD/MM/YYYY': ['15/01/2026', '15/01'],
        'MM/DD/YYYY': ['01/15/2026', '01/15'],
        'DD.MM.YYYY': ['15.01.2026', '15.01'],
        'YYYY-MM-DD': ['2026-01-15', '01-15'],
    };
    for (const [format, [full, short]] of Object.entries(cases)) {
        for (const language of ['en-US', 'de-DE', 'he-IL']) {
            const c = load({ date: format, language });
            assert.equal(c.formatDay(NOON), full, `${format} ${language}`);
            assert.equal(c.formatDayMonth(NOON), short, `${format} ${language}`);
            assert.equal(c.formatDayKey('2026-01-15'), full, `${format} ${language}`);
            assert.equal(c.formatDayKey('2026-01-15', { year: false, weekday: 'short' }), `Thu, ${short}`);
            assert.equal(c.formatDayKey('2026-01-15', { weekday: 'long' }), `Thursday, ${full}`);
            assert.equal(c.formatTime(NOON), `${full}, 13:05:09`, `${format} ${language}`);
        }
    }
});

test('browser dates follow the browser language, as they always did', () => {
    assert.equal(load({ language: 'en-US' }).formatDay(NOON), '01/15/2026');
    assert.equal(load({ language: 'en-GB' }).formatDay(NOON), '15/01/2026');
    assert.equal(load({ language: 'de-DE' }).formatDay(NOON), '15.01.2026');
    assert.equal(load({ language: 'en-US' }).formatTime(NOON), '01/15/2026, 13:05:09');
    // A browser language with its own calendar keeps it: that is what Browser means
    assert.match(load({ language: 'th-TH' }).formatDay(NOON), /2569/);
});

test('the 24-hour clock is the default, the 12-hour clock says AM or PM', () => {
    const h24 = load();
    assert.equal(h24.formatClock(MIDNIGHT), '00:00');
    assert.equal(h24.formatClock(NOON), '13:05');
    assert.equal(h24.formatClock(NOON, { seconds: true }), '13:05:09');
    const h12 = load({ time: '12h', language: 'de-DE' });
    assert.equal(h12.formatClock(MIDNIGHT), '12:00 AM');
    assert.equal(h12.formatClock('2026-01-15T11:00:00Z'), '12:00 PM');
    assert.equal(h12.formatClock(NOON), '1:05 PM');
    assert.equal(h12.formatClock(NOON, { seconds: true }), '1:05:09 PM');
    assert.equal(h12.formatClockAt(2, 15), '2:15 AM');
});

test('an axis writes a whole hour short on the 12-hour clock, and as it is on the 24-hour one', () => {
    assert.equal(load({ time: '12h' }).formatClock('2026-01-15T14:00:00Z', { compact: true }), '3 PM');
    assert.equal(load({ time: '12h' }).formatClock(NOON, { compact: true }), '1:05 PM');
    assert.equal(load({ time: '24h' }).formatClock('2026-01-15T14:00:00Z', { compact: true }), '15:00');
    assert.equal(load({ time: 'browser', language: 'en-US' }).formatClock('2026-01-15T14:00:00Z', { compact: true }), '3 PM');
    assert.equal(load({ time: 'browser', language: 'de-DE' }).formatClock('2026-01-15T14:00:00Z', { compact: true }), '15:00');
});

test('the browser clock follows the browser language', () => {
    assert.equal(load({ time: 'browser', language: 'en-US' }).formatClock(NOON), '1:05 PM');
    assert.equal(load({ time: 'browser', language: 'en-GB' }).formatClock(NOON), '13:05');
    assert.equal(load({ time: 'browser', language: 'de-DE' }).formatClock(MIDNIGHT), '00:00');
});

test('an unknown value from the server falls back to the defaults', () => {
    const c = load({ date: 'DD-MM-YY', time: 'am/pm', language: 'de-DE' });
    assert.equal(c.formatDay(NOON), '15.01.2026');   // browser
    assert.equal(c.formatClock(NOON), '13:05');      // 24h
});

test('a missing or unreadable time is a dash, never Invalid Date', () => {
    const c = load({ date: 'DD/MM/YYYY' });
    for (const value of [null, undefined, '', 'not a date']) {
        assert.equal(c.formatTime(value), '-');
        assert.equal(c.formatDay(value), '-');
        assert.equal(c.formatClock(value), '-');
    }
    assert.equal(c.formatDayKey('nope'), '-');
});

// ---------- zones and days ----------

test('an instant takes the day of the app zone, a day key stays the day it names', () => {
    const west = load({ zone: 'America/Los_Angeles', date: 'YYYY-MM-DD' });
    assert.equal(west.formatDayKey('2026-10-25'), '2026-10-25');
    assert.equal(west.formatDay('2026-10-25T03:00:00Z'), '2026-10-24');
    const east = load({ zone: 'Asia/Tokyo', date: 'YYYY-MM-DD' });
    assert.equal(east.formatDay('2026-10-24T20:00:00Z'), '2026-10-25');
    const utc = load({ zone: 'UTC', date: 'YYYY-MM-DD', time: '12h' });
    assert.equal(utc.formatTime('2028-02-29T23:59:59Z'), '2028-02-29, 11:59:59 PM');
    assert.equal(utc.formatDayKey('2028-02-29'), '2028-02-29');
});

test('the hour that happens twice is written twice and still sorts in order', () => {
    const c = load({ date: 'DD/MM/YYYY' });
    const first = '2026-10-25T00:30:00Z', second = '2026-10-25T01:30:00Z';   // both 02:30 in Berlin
    assert.equal(c.formatTime(first), c.formatTime(second));
    const cell = iso => {
        const time = { getAttribute: () => /datetime="([^"]+)"/.exec(c.uiTime(iso, c.formatTime(iso)))[1], textContent: c.formatTime(iso) };
        return { hasAttribute: () => false, matches: () => false, querySelector: () => time };
    };
    assert.ok(c.uiSortValue(cell(first)).n < c.uiSortValue(cell(second)).n);
});

test('a list cell names its instant, so it sorts whatever the text says', () => {
    const c = load({ date: 'DD/MM/YYYY', time: '12h' });
    assert.equal(c.uiTime('2026-01-15T12:05:09Z', '5 min ago', { title: 'x"y', cls: 'ui-muted' }),
        '<time class="ui-muted" datetime="2026-01-15T12:05:09.000Z" title="x&quot;y">5 min ago</time>');
    assert.equal(c.uiTime(null, 'Never'), '<time>Never</time>');
    // An empty data-sort is no value, not zero
    const empty = { hasAttribute: () => true, getAttribute: () => '' };
    assert.equal(c.uiSortValue(empty).n, null);
});

test('a list row shows the time today, the day and month this year, the whole date before', () => {
    const c = load({ date: 'DD.MM.YYYY', time: '12h' });
    const now = new Date();
    assert.match(c.formatListTime(now.toISOString()), /^\d{1,2}:\d{2} (AM|PM)$/);
    assert.equal(c.formatListTime('2020-03-04T12:00:00Z'), '04.03.2020');
});

// ---------- the Dashboard span ----------

test('a span of whole days names the days; a span inside a day names the hours', () => {
    const c = load({ date: 'DD/MM/YYYY', time: '12h' });
    const at = s => Date.parse(s);
    // One whole day, also the 25-hour day the clocks go back on
    assert.equal(c.mailFlowSpan(at('2026-10-13T22:00:00Z'), at('2026-10-14T22:00:00Z')), '14/10/2026');
    assert.equal(c.mailFlowSpan(at('2026-10-24T22:00:00Z'), at('2026-10-25T23:00:00Z')), '25/10/2026');
    // Several whole days: the first and the last
    assert.equal(c.mailFlowSpan(at('2026-10-12T22:00:00Z'), at('2026-10-14T22:00:00Z')), '13/10/2026 to 14/10/2026');
    // Midnight on the 12-hour clock is still midnight
    assert.equal(c.mailFlowSpan(at('2026-10-14T04:00:00Z'), at('2026-10-14T10:00:00Z')), '14/10/2026, 6:00 AM to 12:00 PM');
    // A second past midnight is not a whole day: it names its hours
    assert.equal(c.mailFlowSpan(at('2026-10-13T22:00:01Z'), at('2026-10-14T22:00:00Z')), '14/10/2026, 12:00 AM to 12:00 AM');
    // A span over midnight that is not whole days names both days
    assert.equal(c.mailFlowSpan(at('2026-10-14T16:00:00Z'), at('2026-10-15T04:00:00Z')),
        '14/10/2026, 6:00 PM to 15/10/2026, 6:00 AM');
});

// ---------- the jobs list and Settings ----------

test('a clock-time job is written with the time setting, in the zone it runs in', () => {
    const c = load({ time: '12h' });
    const html = c.renderJobCard('Weekly summary', 'send_weekly_summary', {
        schedule: 'Weekly, Monday at 09:00 (Europe/Berlin)', status: 'idle',
        clock: { hour: 9, minute: 0, weekday: 'Monday', zone: 'Europe/Berlin' } });
    assert.match(html, /Weekly, Monday at 9:00 AM \(Europe\/Berlin\)/);
    const daily = c.renderJobCard('Cleanup', 'cleanup_logs', {
        schedule: 'Daily at 02:00 (UTC)', status: 'idle', clock: { hour: 2, minute: 0, weekday: null, zone: 'UTC' } });
    assert.match(daily, /Daily at 2:00 AM \(UTC\)/);
    // An older server sends only the text
    assert.match(c.renderJobCard('Cleanup', 'cleanup_logs', { schedule: 'Daily at 02:00 (UTC)', status: 'idle' }), /Daily at 02:00 \(UTC\)/);
});

test('Settings offers the formats under Time and shows the unsaved choice', () => {
    const c = load({ files: ['settings.js'] });
    const group = vm.runInContext("SETTINGS_EDIT_TABS.find(t => t.id === 'application').groups.find(g => g.label === 'Time')", c);
    assert.deepEqual([...group.keys], ['tz', 'date_format', 'time_format']);
    const values = key => vm.runInContext(`SETTINGS_FIELD_OPTIONS.${key}.map(o => o.value)`, c);
    assert.deepEqual([...values('date_format')], ['browser', 'DD/MM/YYYY', 'MM/DD/YYYY', 'DD.MM.YYYY', 'YYYY-MM-DD']);
    assert.deepEqual([...values('time_format')], ['24h', '12h', 'browser']);
    assert.ok(vm.runInContext("SETTINGS_READ_AT_PAGE_LOAD.includes('date_format') && SETTINGS_READ_AT_PAGE_LOAD.includes('time_format')", c));
    const html = vm.runInContext(`renderSettingsEditField('time_format', '24h', SETTINGS_SENSITIVE_KEYS,
        SETTINGS_FIELD_DESCRIPTIONS.time_format, false, '24h')`, c);
    assert.match(html, /id="settings-format-example"/);

    const out = { textContent: '' };
    const fields = { '#settings-format-example': out, '#edit-date_format': { value: 'YYYY-MM-DD' }, '#edit-time_format': { value: '12h' } };
    c.settingsShowFormatExample({ querySelector: sel => fields[sel] || null });
    assert.match(out.textContent, /^Example: \d{4}-\d{2}-\d{2}, \d{1,2}:\d{2} (AM|PM)$/);
});

// ---------- one way in ----------

// Formatting a date anywhere but the helpers in utils.js would miss the
// setting. These are the places allowed to build an Intl date format, by the
// function they are in, and why.
const ALLOWED_INTL = {
    'utils.js': ['tzPartFormat', 'browserFormat', 'writeDate'],   // the helpers themselves
    'app.js': ['setAppTimezone'],                                  // checks the zone is usable
    'settings.js': ['settingsZoneOffset', 'settingsTimeZoneKnown'],  // the zone list: offsets, known names
};

function frontendScripts(dir = frontend) {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) return entry.name === 'libs' ? [] : frontendScripts(full);
        return /\.(js|html)$/.test(entry.name) ? [full] : [];
    });
}

function enclosingFunction(source, index) {
    const before = source.slice(0, index);
    const matches = [...before.matchAll(/^(?:async )?function ([A-Za-z0-9_$]+)\(/gm)];
    return matches.length ? matches[matches.length - 1][1] : null;
}

test('no page formats a date or time on its own', () => {
    const problems = [];
    for (const file of frontendScripts()) {
        const name = path.relative(frontend, file).replace(/\\/g, '/');
        const source = fs.readFileSync(file, 'utf8');
        const rules = [
            [/Intl\.DateTimeFormat\(/g, (i) => (ALLOWED_INTL[name] || []).includes(enclosingFunction(source, i))],
            [/toLocale(Date|Time)String\(/g, () => false],
            [/Date\([^)]*\)\.toLocaleString\(/g, () => false],
            [/\bhour12\b|\bhourCycle\b/g, (i) => name === 'utils.js' && ['tzPartFormat', 'writeClock'].includes(enclosingFunction(source, i))],
            [/\bformatInZone\(/g, () => false],
            // The browser's own zone and clock: every time on screen is in the app's zone
            [/\.get(Hours|Minutes|Seconds|Date|Day|Month|FullYear)\(/g, () => false],
        ];
        for (const [pattern, allowed] of rules) {
            for (const m of source.matchAll(pattern)) {
                if (!allowed(m.index)) {
                    const line = source.slice(0, m.index).split('\n').length;
                    problems.push(`${name}:${line} ${m[0]} (in ${enclosingFunction(source, m.index) || 'top level'})`);
                }
            }
        }
    }
    assert.deepEqual(problems, [], 'format dates with formatTime, formatDay, formatDayMonth, formatDayKey or formatClock (utils.js)');
});

test('the check above catches a page that formats a date on its own', () => {
    const source = 'function renderThing(d) {\n    return new Intl.DateTimeFormat(undefined, { hour12: false }).format(d);\n}\n';
    const index = source.indexOf('Intl.DateTimeFormat(');
    assert.equal(enclosingFunction(source, index), 'renderThing');
    assert.ok(!(ALLOWED_INTL['app.js'] || []).includes(enclosingFunction(source, index)));
});
