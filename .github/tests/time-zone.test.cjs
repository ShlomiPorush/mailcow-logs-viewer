// Every time on screen, every day and every time a user types or picks follows
// the app's time zone (/api/info `timezone`), never the browser's. The browser
// in these tests is in New York and the app's zone is Europe/Berlin, whose
// daylight saving changes (2026-03-29 and 2026-10-25) fall on other days.
process.env.TZ = 'America/New_York';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');

// Any DOM access returns another inert stub, so a file's top-level code runs
function stub() {
    const fn = function () { return proxy; };
    const proxy = new Proxy(fn, {
        get: (_, key) => (key === Symbol.toPrimitive ? () => '' : key === 'length' ? 0 : proxy),
        apply: () => proxy,
        construct: () => proxy,
    });
    return proxy;
}

// The page scripts in one global scope, as in the browser, with the app's zone set
function load(files, zone = 'Europe/Berlin', dateFormat = 'browser', timeFormat = '24h') {
    const context = vm.createContext({
        document: stub(), window: { matchMedia: () => ({ matches: false }), addEventListener() {} }, localStorage: stub(),
        sessionStorage: stub(), navigator: stub(), location: stub(), console: { log() {}, error() {}, warn() {} },
        setTimeout() {}, setInterval() {}, clearTimeout() {}, URLSearchParams,
    });
    for (const file of ['utils.js', 'app.js', ...files]) {
        vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    }
    vm.runInContext(`appTimezone = ${JSON.stringify(zone)}; appDateFormat = ${JSON.stringify(dateFormat)}; appTimeFormat = ${JSON.stringify(timeFormat)}`, context);
    return context;
}

// A page whose elements are plain objects, kept by id
function page(context) {
    const elements = {};
    const element = id => elements[id] || (elements[id] = {
        id, value: '', textContent: '', innerHTML: '', checked: false, style: {}, dataset: {},
        classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
        setAttribute() {}, removeAttribute() {}, remove() {}, querySelectorAll: () => [], querySelector: () => null,
    });
    context.document = { getElementById: element, querySelector: () => null, querySelectorAll: () => [], addEventListener() {} };
    return element;
}

const iso = date => new Date(date).toISOString();

// ---------- the helpers in utils.js ----------

test('a wall time in the app zone is one instant, whatever the browser zone', () => {
    const c = load([]);
    // 02:30 does not exist on 2026-03-29 in Berlin: it moves forward to 03:30 CEST
    assert.equal(iso(c.zonedTimeToDate(2026, 3, 29, 2, 30)), '2026-03-29T01:30:00.000Z');
    // 02:30 happens twice on 2026-10-25 in Berlin: the first one, in CEST
    assert.equal(iso(c.zonedTimeToDate(2026, 10, 25, 2, 30)), '2026-10-25T00:30:00.000Z');
    assert.equal(iso(c.fromZonedInputValue('2026-10-25T12:00')), '2026-10-25T11:00:00.000Z');
    assert.equal(c.toZonedInputValue('2026-10-25T11:00:00Z'), '2026-10-25T12:00');
    assert.equal(c.zonedDateString(new Date('2026-10-24T22:30:00Z')), '2026-10-25');
});

test('a day in the app zone is 23 hours on 2026-03-29 and 25 hours on 2026-10-25', () => {
    const c = load([]);
    const hours = day => (c.zonedDayStart(c.addDaysToDateString(day, 1)) - c.zonedDayStart(day)) / 3600000;
    assert.equal(iso(c.zonedDayStart('2026-03-29')), '2026-03-28T23:00:00.000Z');
    assert.equal(hours('2026-03-29'), 23);
    assert.equal(iso(c.zonedDayStart('2026-10-25')), '2026-10-24T22:00:00.000Z');
    assert.equal(hours('2026-10-25'), 25);
});

test('n days later keeps the wall time in the app zone across a daylight saving change', () => {
    const c = load([]);
    // Noon CET on 2026-03-28 is noon CEST a day later, 23 hours on
    assert.equal(iso(c.addDaysInZone(new Date('2026-03-28T11:00:00Z'), 1)), '2026-03-29T10:00:00.000Z');
    // 11:00 CET on 2026-10-25 is 11:00 CEST the day before, 25 hours earlier
    assert.equal(iso(c.addDaysInZone(new Date('2026-10-25T10:00:00Z'), -1)), '2026-10-24T09:00:00.000Z');
});

test('a day key is named as it is, in any browser zone', () => {
    const c = load([], 'Europe/Berlin', 'DD/MM/YYYY');
    assert.equal(c.formatDayKey('2026-10-25', { weekday: 'short' }), 'Sun, 25/10/2026');
    assert.equal(c.formatDayKey('2026-03-29T00:00:00', { year: false }), '29/03');
});

test('a day key keeps its day in an app zone west of UTC, an instant takes the day of the app zone', () => {
    // Read as UTC midnight, 2026-10-25 would be the 24th in Los Angeles
    const west = load([], 'America/Los_Angeles', 'DD/MM/YYYY');
    assert.equal(west.formatDayKey('2026-10-25', { year: false }), '25/10');
    const c = load([], 'Europe/Berlin', 'DD/MM/YYYY');
    assert.equal(c.formatDayMonth('2026-10-24T22:30:00Z'), '25/10');
});

test('the app zone is used when it is UTC, and an unknown zone falls back to UTC', () => {
    const c = load([]);
    c.setAppTimezone({ timezone: 'UTC', timezone_valid: true, timezone_configured: 'UTC' });
    assert.equal(c.formatClock('2026-10-25T00:30:00Z'), '00:30');
    // The server sends only known zones; one the browser cannot use must not break every time
    c.setAppTimezone({ timezone: 'Europe/Berlinn', timezone_valid: false, timezone_configured: 'Europe/Berlinn' });
    assert.equal(vm.runInContext('appTimezone', c), 'UTC');
    assert.equal(vm.runInContext('appTimezoneStatus.valid', c), false);
    assert.equal(vm.runInContext('appTimezoneStatus.configured', c), 'Europe/Berlinn');
    assert.doesNotThrow(() => c.formatTime('2026-10-25T00:30:00Z'));
});

test('a table sorts shown times in order, also those in the hour the browser zone skips', () => {
    const c = load([]);
    const cell = text => ({ hasAttribute: () => false, cloneNode: () => ({ querySelectorAll: () => [], textContent: text }) });
    // 02:30 does not exist on 2026-03-08 in New York; in Berlin it is just a time before 03:15
    const early = c.uiSortValue(cell('03/08/2026, 02:30:00')).n;
    const late = c.uiSortValue(cell('03/08/2026, 03:15:00')).n;
    assert.ok(early < late, `${early} < ${late}`);
    assert.equal(c.uiSortValue(cell('25.10.2026 02:30')).n, Date.parse('2026-10-25T02:30:00Z'));
});

// ---------- finding 1: the suppression expiry editor ----------

function suppressionEditor(expiresAt) {
    const c = load(['spam_filter.js']);
    const element = page(c);
    let body = '';
    const sent = [];
    c.suppressionDialog = (id, title, html) => { body = html; };
    c.authenticatedFetch = async (url, options) => { sent.push(JSON.parse(options.body)); return { ok: true }; };
    for (const name of ['showToast', 'loadSuppressions', 'loadSuppressionStats', 'autoSyncToRspamd']) c[name] = () => {};
    const item = { id: 7, email: 'user@example.com', reason: 'hard_bounce', expires_at: expiresAt, created_at: expiresAt };
    c.__item = item;
    vm.runInContext('suppressionItemsById.set(7, __item)', c);
    c.showEditSuppressionModal(item);
    const shown = body.match(/id="edit-suppression-expiry" value="([^"]*)"/)[1];
    // The field as the browser builds it from the HTML
    element('edit-suppression-expiry').value = shown;
    element('edit-suppression-expiry').dataset.shown = body.match(/id="edit-suppression-expiry" value="[^"]*" data-shown="([^"]*)"/)[1];
    return { c, element, shown, sent };
}

test('the expiry editor shows the expiry in the app zone and reads a new one there', async () => {
    const { c, element, shown, sent } = suppressionEditor('2026-10-25T00:30:00Z');
    // 00:30 UTC is the first 02:30 in Berlin that night
    assert.equal(shown, '2026-10-25T02:30');
    // 03:30 on the same night is after the clocks went back, so UTC+1
    element('edit-suppression-expiry').value = '2026-10-25T03:30';
    await c.saveEditSuppression(7);
    assert.equal(sent[0].expires_at, '2026-10-25T02:30:00.000Z');
});

test('saving an expiry that was not touched keeps it to the second', async () => {
    // A real expiry is "now plus N days", with seconds; the field only holds minutes
    const { c, shown, sent } = suppressionEditor('2026-10-31T21:25:10.541492Z');
    assert.equal(shown, '2026-10-31T22:25');
    await c.saveEditSuppression(7);
    assert.equal(sent[0].expires_at, undefined, 'an untouched expiry is not sent');
});

test('+7 days on the expiry keeps its time of day across the change to summer time', () => {
    const { c, element } = suppressionEditor('2026-03-25T11:00:00Z');
    assert.equal(element('edit-suppression-expiry').value, '2026-03-25T12:00');
    c.extendExpiryBy(7);
    assert.equal(element('edit-suppression-expiry').value, '2026-04-01T12:00');
});

// ---------- finding 4: the Logs time inputs ----------

test('the Logs range is read in the app zone, and To covers its whole minute', async () => {
    const c = load(['logs-viewer.js']);
    const element = page(c);
    const urls = [];
    c.authenticatedFetch = async url => { urls.push(url); return { ok: true, json: async () => ({ data: [], total: 0 }) }; };
    for (const name of ['renderLogEntries', 'setLiveButtonActive', 'updateLogStatusBar', 'applyLogFilter', 'showToast']) c[name] = () => {};
    element('logs-date-from').value = '2026-10-25T02:30';
    element('logs-date-to').value = '2026-10-25T02:45';
    await c.loadDateRangeLogs();
    const params = new URL(urls[0], 'http://viewer.test').searchParams;
    assert.equal(params.get('start_date'), '2026-10-25T00:30:00.000Z');
    assert.equal(params.get('end_date'), '2026-10-25T00:45:59.999Z');
});

function logsRange() {
    const c = load(['logs-viewer.js']);
    const element = page(c);
    const urls = [];
    c.authenticatedFetch = async url => { urls.push(url); return { ok: true, json: async () => ({ data: [], total: 0 }) }; };
    for (const name of ['renderLogEntries', 'setLiveButtonActive', 'updateLogStatusBar', 'applyLogFilter', 'showToast']) c[name] = () => {};
    const sent = () => {
        const params = new URL(urls[urls.length - 1], 'http://viewer.test').searchParams;
        return [params.get('start_date'), params.get('end_date')];
    };
    return { c, element, sent };
}

test('a Logs preset shows wall times in the app zone and sends the exact hour it means', async () => {
    const { c, element, sent } = logsRange();
    // 01:10 UTC on 2026-10-25 is the second 02:10 in Berlin, an hour after the first one
    c.__now = new Date('2026-10-25T01:10:00Z');
    await vm.runInContext('setLogTimePreset(60, __now)', c);
    assert.equal(element('logs-date-from').value, '2026-10-25T02:10');
    assert.equal(element('logs-date-to').value, '2026-10-25T02:10');
    assert.deepEqual(sent(), ['2026-10-25T00:10:00.000Z', '2026-10-25T01:10:00.000Z']);
    // Load again on the untouched fields keeps the same hour
    await c.loadDateRangeLogs();
    assert.deepEqual(sent(), ['2026-10-25T00:10:00.000Z', '2026-10-25T01:10:00.000Z']);
    // A time typed over the preset is read in the app zone, To with its whole minute
    element('logs-date-to').value = '2026-10-25T02:40';
    await c.loadDateRangeLogs();
    assert.deepEqual(sent(), ['2026-10-25T00:10:00.000Z', '2026-10-25T00:40:59.999Z']);
});

test('a Logs preset does not outlive the fields it filled', async () => {
    const { c, element, sent } = logsRange();
    c.__now = new Date('2026-10-25T01:10:00Z');
    await vm.runInContext('setLogTimePreset(60, __now)', c);
    // Back to live clears the fields; the same text typed later is read as typed
    c.fetchInitialLogs = async () => {};
    c.connectLogWebSocket = async () => {};
    await c.resetToLiveLogs();
    element('logs-date-from').value = '2026-10-25T02:10';
    element('logs-date-to').value = '2026-10-25T02:10';
    await c.loadDateRangeLogs();
    assert.deepEqual(sent(), ['2026-10-25T00:10:00.000Z', '2026-10-25T00:10:59.999Z']);
});

test('a raw log time is shown in the app zone, also when it is UTC', () => {
    const c = load(['logs-viewer.js'], 'UTC');
    const epoch = Date.parse('2026-10-25T00:30:00Z') / 1000;
    assert.match(c.formatLogTimestamp(epoch), /00:30:00/);
});

// ---------- finding 5: hour buckets ----------

test('a Rate Limits hour bucket is a UTC instant shown in the app zone', () => {
    const c = load(['rate-limits.js'], 'Europe/Berlin', 'DD.MM.YYYY');
    // The two hours that start at 02:00 in Berlin on 2026-10-25 stay two buckets
    assert.equal(c.rateLimitBucketLabel('2026-10-25T00:00:00Z', 'hour'), '02:00');
    assert.equal(c.rateLimitBucketLabel('2026-10-25T01:00:00Z', 'hour'), '02:00');
    assert.equal(c.rateLimitBucketLabel('2026-10-25T02:00:00Z', 'hour'), '03:00');
    // The older shape, the UTC hour without a zone
    assert.equal(c.rateLimitBucketLabel('2026-10-25T02:00', 'hour'), '03:00');
    assert.equal(c.rateLimitBucketLabel('2026-10-25', 'day'), '25.10');
    const utc = load(['rate-limits.js'], 'UTC');
    assert.equal(utc.rateLimitBucketLabel('2026-10-25T02:00:00Z', 'hour'), '02:00');
    assert.match(utc.rateLimitShortTime('2026-10-25T02:00:00Z'), /02:00/);
});

test('a Mailbox Stats hour slot is a UTC instant shown in the app zone, a day slot as it is', () => {
    const c = load(['mailbox-stats.js'], 'Europe/Berlin', 'DD/MM/YYYY');
    assert.equal(c.mailboxActivityLabel('2026-10-25T00:00:00Z', 'hour'), 'Sun, 25/10, 02:00');
    assert.equal(c.mailboxActivityLabel('2026-10-25T01:00:00Z', 'hour'), 'Sun, 25/10, 02:00');
    assert.equal(c.mailboxActivityLabel('2026-10-24T22:00:00Z', 'hour'), 'Sun, 25/10, 00:00');
    assert.equal(c.mailboxActivityLabel('2026-10-25', 'day'), 'Sun, 25/10');
    assert.equal(c.mailboxActivityLabel('2026-03-29T00:00:00', 'day'), 'Sun, 29/03');
});

// ---------- finding 6: the Mailbox Stats range ----------

test('the Mailbox Stats custom range starts as the last 30 days of the app zone', () => {
    const c = load(['mailbox-stats.js']);
    const element = page(c);
    // 22:30 UTC on 2026-10-24 is already the 25th in Berlin (still the 24th in New York)
    c.mailboxStatsPeriodOpened(new Date('2026-10-24T22:30:00Z'));
    assert.equal(element('date-range-end').value, '2026-10-25');
    assert.equal(element('date-range-start').value, '2026-09-25');
});

// ---------- finding 8: Security ----------

test('the Security period names the day its logs start on in the app zone', () => {
    const c = load(['smtp-abuse.js', 'protection.js', 'security.js'], 'Europe/Berlin', 'DD/MM/YYYY');
    vm.runInContext("securityDays = 7; securityPage = { days: 7, since: '2026-10-25T23:30:00Z' }", c);
    assert.equal(c.securityPeriodSince(), '26/10/2026');
});

test('the allowlist and denylist count failed logins over the last 24 hours, not "today"', () => {
    const c = load(['smtp-abuse.js', 'protection.js', 'security.js']);
    const box = { innerHTML: '' };
    c.document = { getElementById: id => (id === 'security-lists' ? box : null) };
    vm.runInContext(`mailcowRwConfigured = true; fail2banActiveBans = []; securityHits = [];
        fail2banWhitelist = ['198.51.100.1']; fail2banBlacklist = ['203.0.113.7'];
        securityOverview = { sources: [{ ip: '198.51.100.1', failed_logins: 3 }, { ip: '203.0.113.7', failed_logins: 1 }] }`, c);
    c.renderSecurityLists();
    assert.match(box.innerHTML, /Failed 3 logins in the last 24 hours, never banned/);
    assert.match(box.innerHTML, /still tried 1 time in the last 24 hours/);
    assert.doesNotMatch(box.innerHTML, /today/);
});

// ---------- finding 19: Mailbox Stats dates ----------

test('Mailbox Stats names its own dates First seen and Last synced, not mailcow\'s', () => {
    const source = fs.readFileSync(path.join(frontend, 'mailbox-stats.js'), 'utf8');
    assert.match(source, /<span>First seen \/ Last synced<\/span>/);
    assert.doesNotMatch(source, /Created \/ Modified/);
});

// ---------- DMARC and TLS: report periods and Import Date ----------

test('Manage Reports shows the Import Date and the period in the app zone', () => {
    const c = load(['dmarc.js'], 'Europe/Berlin', 'MM/DD/YYYY', '12h');
    const element = page(c);
    const at = Date.parse('2026-10-24T22:30:00Z') / 1000;
    c.renderReportsManagementTable([{ id: 1, type: 'tls', domain: 'example.com', org_name: 'Reporter', record_count: 1,
        created_at: '2026-10-25T00:30:00Z', begin_date: at, end_date: Date.parse('2026-10-25T23:30:00Z') / 1000 }], false, { total: 1, page: 1, total_pages: 1 });
    const html = element('dmarc-reports-management-content').innerHTML;
    assert.ok(html.includes('10/25/2026, 2:30 AM'), html);
    assert.ok(html.includes('10/25/2026 - 10/26/2026'), html);
    vm.runInContext("reportsManagementState.domains = [{ domain: 'example.com', dmarc_reports: 1, tls_reports: 0, last_report: " + at + ' }]', c);
    c.renderReportsDomains();
    assert.ok(element('dmarc-reports-domains').innerHTML.includes('10/25/2026'));
});

test('a DMARC day from the server is named as it is', () => {
    const c = load(['dmarc.js'], 'Europe/Berlin', 'DD/MM/YYYY');
    assert.equal(c.dmarcDay('2026-10-25'), '25/10');
    assert.equal(c.dmarcDay('2026-03-29', true), 'Sunday, 29/03/2026');
});

// ---------- Settings > Application > Time Zone, and About ----------

function settingsField(value, { envLocked = false, status = { valid: true, configured: value } } = {}) {
    const c = load(['settings.js']);
    c.__status = status;
    vm.runInContext('appTimezoneStatus = __status', c);
    return vm.runInContext(`renderSettingsEditField('tz', ${JSON.stringify(value)}, SETTINGS_SENSITIVE_KEYS,
        SETTINGS_FIELD_DESCRIPTIONS.tz, ${envLocked}, 'UTC')`, c);
}

// One option of the Time Zone picker: chosen or not, its value, its text
const literal = text => text.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
const zoneOption = (selected, value, text) => new RegExp(literal(
    `aria-selected="${selected}" data-value="${value}" onclick="settingsPickZone(this)"><span>${text}</span>`));

test('the Time Zone setting is a searchable list of IANA zones under Application', () => {
    const html = settingsField('Europe/Berlin');
    assert.match(html, /<span class="ui-label" id="label-tz">Time Zone/);
    assert.match(html, /<button type="button" class="ui-select ui-select-btn ui-picker-btn" aria-haspopup="dialog" aria-expanded="false" aria-controls="settings-tz-panel" aria-labelledby="label-tz"><span>Europe\/Berlin <small class="ui-zone-offset">UTC\+0[12]:00<\/small><\/span>/);
    assert.match(html, /<input type="search" class="ui-input ui-picker-search" placeholder="Search time zones"/);
    assert.match(html, /<input type="hidden" id="edit-tz" name="tz" value="Europe\/Berlin" data-saved="Europe\/Berlin">/);
    assert.match(html, zoneOption(true, 'Europe/Berlin', 'Europe/Berlin'));
    assert.match(html, zoneOption(false, 'UTC', 'UTC'));
    assert.match(html, zoneOption(false, 'America/New_York', 'America/New_York'));
    assert.doesNotMatch(html, /not a known time zone|Times are shown in UTC/);
    const c = load(['settings.js']);
    const app = vm.runInContext("SETTINGS_EDIT_TABS.find(t => t.id === 'application').groups.flatMap(g => g.keys)", c);
    assert.ok(app.includes('tz'));
});

test('with no zone set the Time Zone field shows UTC, said once', () => {
    for (const value of ['', 'UTC']) {
        const html = settingsField(value);
        // The description says it; no note under the field repeats it
        assert.match(html, /The app&#039;s time zone\. Default: UTC\./);
        assert.doesNotMatch(html, /data-zone-note/);
        // Empty is UTC, the default: not marked as changed
        assert.doesNotMatch(html, /Changed|Reset to default/);
    }
    assert.match(settingsField(''), zoneOption(true, '', 'Not set (UTC)'));
    assert.match(settingsField(''), /<span>Not set \(UTC\) <small class="ui-zone-offset">UTC\+00:00<\/small><\/span><svg/);
});

test('every zone shows how far its clock is from UTC', () => {
    // Zones without daylight saving, so the offsets hold all year
    const c = load(['settings.js']);
    for (const [zone, offset] of [['', 'UTC+00:00'], ['UTC', 'UTC+00:00'], ['Asia/Kolkata', 'UTC+05:30'], ['Asia/Kathmandu', 'UTC+05:45'], ['America/Bogota', 'UTC-05:00']]) {
        assert.equal(c.settingsZoneOffset(zone), offset, zone);
    }
    // On the button after the name, and at the end of each option
    const html = settingsField('Asia/Kolkata');
    assert.match(html, /<span>Asia\/Kolkata <small class="ui-zone-offset">UTC\+05:30<\/small><\/span>/);
    for (const [zone, offset] of [['', 'UTC+00:00'], ['UTC', 'UTC+00:00'], ['Asia/Kolkata', 'UTC+05:30'], ['America/Bogota', 'UTC-05:00']]) {
        assert.match(html, new RegExp(literal(`data-value="${zone}" onclick="settingsPickZone(this)"><span>`) + '[^<]*' + literal(`</span><small>${offset}</small>`)));
    }
    // A name the browser does not know has no offset to show
    assert.equal(c.settingsZoneOffset('Europe/Berlinn'), '');
    assert.match(settingsField('Europe/Berlinn'), /<span>Europe\/Berlinn<\/span><svg/);
});

test('the time zone search finds a zone by its words', () => {
    const c = load(['settings.js']);
    assert.equal(c.uiPickerMatches('America/New_York', 'new york'), true);
    assert.equal(c.uiPickerMatches('America/New_York', 'New_Y'), true);
    assert.equal(c.uiPickerMatches('Europe/Berlin', ' berl '), true);
    assert.equal(c.uiPickerMatches('Europe/Berlin', 'paris'), false);
});

test('an unknown zone is kept in the field and named as unknown', () => {
    const html = settingsField('Europe/Berlinn', { status: { valid: false, configured: 'Europe/Berlinn' } });
    assert.match(html, zoneOption(true, 'Europe/Berlinn', 'Europe/Berlinn (unknown)'));
    assert.match(html, /&quot;Europe\/Berlinn&quot; is not a known time zone, so the app uses UTC\. Pick a time zone from the list\./);
    const locked = settingsField('Europe/Berlinn', { envLocked: true, status: { valid: false, configured: 'Europe/Berlinn' } });
    assert.match(locked, /Set by ENV/);
    assert.match(locked, /aria-labelledby="label-tz" disabled>/);
    assert.match(locked, /<input type="hidden" id="edit-tz" name="tz" value="Europe\/Berlinn" data-saved="Europe\/Berlinn" disabled>/);
    assert.match(locked, /Fix TZ in the environment\./);
});

test('saving a new time zone reloads the page', () => {
    const c = load(['settings.js']);
    assert.ok(vm.runInContext('SETTINGS_READ_AT_PAGE_LOAD', c).includes('tz'));
});

test('About shows the time zone in use, and why it is UTC', () => {
    const c = load(['settings.js', 'about.js']);
    const panel = app => c.aboutConfigurationPanel({ mailcow_url: 'https://mail.example.com' }, app);
    assert.match(panel({ timezone: 'Europe/Berlin', timezone_valid: true, timezone_configured: 'Europe/Berlin' }),
        /<span>Time zone<\/span><b class="ui-kv-small">Europe\/Berlin<\/b>/);
    assert.match(panel({ timezone: 'UTC', timezone_valid: false, timezone_configured: 'Europe/Berlinn' }),
        /UTC <small class="ui-text-warn">&quot;Europe\/Berlinn&quot; is not a known time zone<\/small>/);
    assert.match(panel({ timezone: 'UTC', timezone_valid: true, timezone_configured: '' }), /UTC <small class="ui-muted">not set<\/small>/);
});
