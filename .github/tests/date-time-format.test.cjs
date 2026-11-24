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

const NOON = '2026-01-15T12:05:09Z';
const MIDNIGHT = '2026-01-14T23:00:00Z';

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
    assert.equal(c.formatDay(NOON), '15.01.2026');
    assert.equal(c.formatClock(NOON), '13:05');
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
    const first = '2026-10-25T00:30:00Z', second = '2026-10-25T01:30:00Z';
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
    const empty = { hasAttribute: () => true, getAttribute: () => '' };
    assert.equal(c.uiSortValue(empty).n, null);
});

function sortedCell(c, html) {
    const time = /<time[^>]*datetime="([^"]+)"[^>]*>([^<]*)<\/time>/.exec(html);
    const sort = /data-sort="([^"]*)"/.exec(html);
    return c.uiSortValue({
        hasAttribute: a => a === 'data-sort' && !!sort, getAttribute: () => sort[1], matches: () => false,
        querySelector: () => (time ? { getAttribute: () => time[1], textContent: time[2] } : null),
    }).n;
}

test('the lists the pages render sort their times by the instant', () => {
    const c = load({ date: 'DD/MM/YYYY', time: '12h', files: ['devices.js', 'rate-limits.js'] });
    const early = '2026-01-10T08:00:00Z', late = '2026-03-02T07:00:00Z';
    const row = c.renderDeviceRow({ username: 'a@example.com', device_id: 'x', first_seen: late, last_seen: early, client: '' }, 0, 0);
    const cells = row.split('<span class="ui-td').filter(s => /First seen|Last seen/.test(s));
    assert.equal(cells.length, 2);
    assert.equal(sortedCell(c, cells.find(s => s.includes('First seen'))), Date.parse(late));
    assert.equal(sortedCell(c, cells.find(s => s.includes('Last seen'))), Date.parse(early));
    const event = c.renderRateLimitEventRow({ time: late, rcpt: 'b@example.com', subject: 's' });
    assert.equal(sortedCell(c, event.split('</td>')[0]), Date.parse(late));
});

test('a list row shows the time today, the day and month this year, the whole date before', () => {
    const c = load({ date: 'DD.MM.YYYY', time: '12h' });
    const now = new Date();
    assert.match(c.formatListTime(now.toISOString()), /^\d{1,2}:\d{2} (AM|PM)$/);
    assert.equal(c.formatListTime('2020-03-04T12:00:00Z'), '04.03.2020');
});

test('a span of whole days names the days; a span inside a day names the hours', () => {
    const c = load({ date: 'DD/MM/YYYY', time: '12h' });
    const at = s => Date.parse(s);
    assert.equal(c.mailFlowSpan(at('2026-10-13T22:00:00Z'), at('2026-10-14T22:00:00Z')), '14/10/2026');
    assert.equal(c.mailFlowSpan(at('2026-10-24T22:00:00Z'), at('2026-10-25T23:00:00Z')), '25/10/2026');
    assert.equal(c.mailFlowSpan(at('2026-10-12T22:00:00Z'), at('2026-10-14T22:00:00Z')), '13/10/2026 to 14/10/2026');
    assert.equal(c.mailFlowSpan(at('2026-10-14T04:00:00Z'), at('2026-10-14T10:00:00Z')), '14/10/2026, 6:00 AM to 12:00 PM');
    assert.equal(c.mailFlowSpan(at('2026-10-13T22:00:01Z'), at('2026-10-14T22:00:00Z')), '14/10/2026, 12:00 AM to 12:00 AM');
    assert.equal(c.mailFlowSpan(at('2026-10-14T16:00:00Z'), at('2026-10-15T04:00:00Z')),
        '14/10/2026, 6:00 PM to 15/10/2026, 6:00 AM');
});

test('a clock-time job is written with the time setting, in the zone it runs in', () => {
    const c = load({ time: '12h' });
    const html = c.renderJobCard('Weekly summary', 'send_weekly_summary', {
        schedule: 'Weekly, Monday at 09:00 (Europe/Berlin)', status: 'idle',
        clock: { hour: 9, minute: 0, weekday: 'Monday', zone: 'Europe/Berlin' } });
    assert.match(html, /Weekly, Monday at 9:00 AM \(Europe\/Berlin\)/);
    const daily = c.renderJobCard('Cleanup', 'cleanup_logs', {
        schedule: 'Daily at 02:00 (UTC)', status: 'idle', clock: { hour: 2, minute: 0, weekday: null, zone: 'UTC' } });
    assert.match(daily, /Daily at 2:00 AM \(UTC\)/);
    assert.match(c.renderJobCard('Cleanup', 'cleanup_logs', { schedule: 'Daily at 02:00 (UTC)', status: 'idle' }), /Daily at 02:00 \(UTC\)/);
});

test('Settings offers the formats under Time', () => {
    const c = load({ files: ['settings.js'] });
    const group = vm.runInContext("SETTINGS_EDIT_TABS.find(t => t.id === 'application').groups.find(g => g.label === 'Time')", c);
    assert.deepEqual([...group.keys], ['tz', 'date_format', 'time_format']);
    const values = key => vm.runInContext(`SETTINGS_FIELD_OPTIONS.${key}.map(o => o.value)`, c);
    assert.deepEqual([...values('date_format')], ['browser', 'DD/MM/YYYY', 'MM/DD/YYYY', 'DD.MM.YYYY', 'YYYY-MM-DD']);
    assert.deepEqual([...values('time_format')], ['24h', '12h', 'browser']);
    assert.ok(vm.runInContext("SETTINGS_READ_AT_PAGE_LOAD.includes('date_format') && SETTINGS_READ_AT_PAGE_LOAD.includes('time_format')", c));
    const html = vm.runInContext(`renderSettingsEditField('time_format', '24h', SETTINGS_SENSITIVE_KEYS,
        SETTINGS_FIELD_DESCRIPTIONS.time_format, false, '24h')`, c);
    assert.match(html, /<option value="24h" selected>/);
});

const ALLOWED_INTL = {
    'utils.js': ['tzPartFormat', 'browserFormat', 'writeDate'],
    'app.js': ['setAppTimezone'],
    'settings.js': ['settingsZoneOffset', 'settingsTimeZoneKnown'],
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

function withoutComments(source) {
    return source
        .replace(/\/\*[\s\S]*?\*\//g, m => m.replace(/[^\n]/g, ' '))
        .replace(/(^|[ \t])\/\/[^\n]*/gm, m => m.replace(/[^\n]/g, ' '));
}

function scanSource(name, original) {
    const source = withoutComments(original);
    const rules = [
        [/Intl\s*\.\s*DateTimeFormat\s*\(/g, i => (ALLOWED_INTL[name] || []).includes(enclosingFunction(source, i))],
        [/toLocale(Date|Time)String\s*\(/g, () => false],
        [/(?:\bDate\s*\([^)]*\)|\b[\w$.]*(?:date|time|when|moment|instant|seen|_at|At)\b)\s*\.toLocaleString\s*\(/gi, () => false],
        [/\bhour12\b|\bhourCycle\b|\bdateStyle\b|\btimeStyle\b/g, i => name === 'utils.js' && ['tzPartFormat', 'writeClock'].includes(enclosingFunction(source, i))],
        [/\bformatInZone\s*\(/g, () => false],
        [/\.get(Hours|Minutes|Seconds|Date|Day|Month|FullYear)\s*\(/g, () => false],
    ];
    const problems = [];
    for (const [pattern, allowed] of rules) {
        for (const m of source.matchAll(pattern)) {
            if (!allowed(m.index)) {
                problems.push(`${name}:${source.slice(0, m.index).split('\n').length} ${m[0].trim()} (in ${enclosingFunction(source, m.index) || 'top level'})`);
            }
        }
    }
    return problems;
}

test('no page formats a date or time on its own', () => {
    const problems = frontendScripts().flatMap(file =>
        scanSource(path.relative(frontend, file).split(path.sep).join('/'), fs.readFileSync(file, 'utf8')));
    assert.deepEqual(problems, [], 'format dates with formatTime, formatDay, formatDayMonth, formatDayKey or formatClock (utils.js)');
});

test('the check above catches a page that formats a date on its own, and only that', () => {
    const caught = [
        'function a(d) { return new Intl.DateTimeFormat(undefined, { hour12: false }).format(d); }',
        'function a(d) { return new Intl.DateTimeFormat (undefined, { dateStyle: \'short\' }).format(d); }',
        'function a(date) { return date.toLocaleString(); }',
        'function a(row) { return row.created_at.toLocaleString(); }',
        'function a() { return new Date().toLocaleString(); }',
        'function a(d) { return d.toLocaleDateString(); }',
        'function a(d) { return formatInZone(d, {}); }',
        'function a(d) { return d.getHours(); }',
    ];
    for (const source of caught) assert.notDeepEqual(scanSource('pages.js', source), [], source);
    const fine = [
        'function a(count) { return count.toLocaleString(); }',
        'function a(r) { return Number(r.count).toLocaleString(); }',
        '// date.getDay() and new Intl.DateTimeFormat() named in a comment\nfunction a() {}',
        '/* d.toLocaleDateString() */ function a() {}',
        'function a() { return "https://example.com/getHours"; }',
        'function setAppTimezone(z) { new Intl.DateTimeFormat(\'en-US\', { timeZone: z }); }',
    ];
    for (const source of fine) assert.deepEqual(scanSource(source.includes('setAppTimezone') ? 'app.js' : 'pages.js', source), [], source);
    assert.notDeepEqual(scanSource('app.js', 'function other(z) { new Intl.DateTimeFormat(\'en-US\', { timeZone: z }); }'), []);
});
