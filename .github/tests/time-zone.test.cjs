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
function load(files, zone = 'Europe/Berlin') {
    const context = vm.createContext({
        document: stub(), window: { matchMedia: () => ({ matches: false }), addEventListener() {} }, localStorage: stub(),
        sessionStorage: stub(), navigator: stub(), location: stub(), console: { log() {}, error() {}, warn() {} },
        setTimeout() {}, setInterval() {}, clearTimeout() {}, URLSearchParams,
    });
    for (const file of ['utils.js', 'app.js', ...files]) {
        vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);
    }
    vm.runInContext(`appTimezone = ${JSON.stringify(zone)}`, context);
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
    const c = load([]);
    assert.equal(c.formatDayKey('2026-10-25', { weekday: 'short', month: 'short', day: 'numeric' }), 'Sun, Oct 25');
    assert.equal(c.formatDayKey('2026-03-29T00:00:00', { month: 'short', day: 'numeric' }), 'Mar 29');
});

test('formatDateShort keeps a day key as it is, also in an app zone west of UTC', () => {
    // Read as UTC midnight, 2026-10-25 would be the 24th in Los Angeles
    const west = load([], 'America/Los_Angeles');
    assert.equal(west.formatDateShort('2026-10-25'), '25/10');
    const c = load([]);
    assert.equal(c.formatDateShort('2026-10-24T22:30:00Z'), '25/10');
});

test('the app zone is used when it is UTC, and an unknown zone falls back to UTC', () => {
    const c = load([]);
    c.setAppTimezone({ timezone: 'UTC', timezone_valid: true, timezone_configured: 'UTC' });
    assert.equal(c.formatInZone('2026-10-25T00:30:00Z', { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }, 'en-US'), '00:30');
    // The server sends only known zones; one the browser cannot use must not break every time
    c.setAppTimezone({ timezone: 'Europe/Berlinn', timezone_valid: false, timezone_configured: 'Europe/Berlinn' });
    assert.equal(vm.runInContext('appTimezone', c), 'UTC');
    assert.equal(vm.runInContext('appTimezoneStatus.valid', c), false);
    assert.equal(vm.runInContext('appTimezoneStatus.configured', c), 'Europe/Berlinn');
    assert.doesNotThrow(() => c.formatTime('2026-10-25T00:30:00Z'));
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
    c.showEditSuppressionModal({ id: 7, email: 'user@example.com', reason: 'hard_bounce', expires_at: expiresAt, created_at: expiresAt });
    const shown = body.match(/id="edit-suppression-expiry" value="([^"]*)"/)[1];
    element('edit-suppression-expiry').value = shown;
    return { c, element, shown, sent };
}

test('the expiry editor shows the expiry in the app zone and saves it unchanged', async () => {
    const { c, shown, sent } = suppressionEditor('2026-10-25T00:30:00Z');
    // 00:30 UTC is the first 02:30 in Berlin that night
    assert.equal(shown, '2026-10-25T02:30');
    await c.saveEditSuppression(7);
    assert.equal(sent[0].expires_at, '2026-10-25T00:30:00.000Z');
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

test('a Logs preset fills the inputs with wall times in the app zone', () => {
    const c = load(['logs-viewer.js']);
    const element = page(c);
    c.loadDateRangeLogs = () => {};
    c.__now = new Date('2026-10-25T01:10:00Z');
    vm.runInContext('setLogTimePreset(60, __now)', c);
    assert.equal(element('logs-date-from').value, '2026-10-25T02:10');
    assert.equal(element('logs-date-to').value, '2026-10-25T02:10');
});

test('a raw log time is shown in the app zone, also when it is UTC', () => {
    const c = load(['logs-viewer.js'], 'UTC');
    const epoch = Date.parse('2026-10-25T00:30:00Z') / 1000;
    assert.match(c.formatLogTimestamp(epoch), /00:30:00/);
});

// ---------- finding 5: hour buckets ----------

test('a Rate Limits hour bucket is a UTC instant shown in the app zone', () => {
    const c = load(['rate-limits.js']);
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
    const c = load(['mailbox-stats.js']);
    assert.equal(c.mailboxActivityLabel('2026-10-25T00:00:00Z', 'hour'), 'Sun, Oct 25, 02:00');
    assert.equal(c.mailboxActivityLabel('2026-10-25T01:00:00Z', 'hour'), 'Sun, Oct 25, 02:00');
    assert.equal(c.mailboxActivityLabel('2026-10-24T22:00:00Z', 'hour'), 'Sun, Oct 25, 00:00');
    assert.equal(c.mailboxActivityLabel('2026-10-25', 'day'), 'Sun, Oct 25');
    assert.equal(c.mailboxActivityLabel('2026-03-29T00:00:00', 'day'), 'Sun, Mar 29');
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
    const c = load(['smtp-abuse.js', 'protection.js', 'security.js']);
    vm.runInContext("securityDays = 7; securityPage = { days: 7, since: '2026-10-25T23:30:00Z' }", c);
    assert.equal(c.securityPeriodSince(), 'Oct 26');
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
    const c = load(['dmarc.js']);
    const element = page(c);
    const at = Date.parse('2026-10-24T22:30:00Z') / 1000;
    c.renderReportsManagementTable([{ id: 1, type: 'tls', domain: 'example.com', org_name: 'Reporter', record_count: 1,
        created_at: '2026-10-25T00:30:00Z', begin_date: at, end_date: Date.parse('2026-10-25T23:30:00Z') / 1000 }], false, { total: 1, page: 1, total_pages: 1 });
    const html = element('dmarc-reports-management-content').innerHTML;
    assert.match(html, /Oct 25, 2026, 02:30 AM/);
    assert.match(html, /Oct 25 - Oct 26/);
    vm.runInContext("reportsManagementState.domains = [{ domain: 'example.com', dmarc_reports: 1, tls_reports: 0, last_report: " + at + ' }]', c);
    c.renderReportsDomains();
    assert.match(element('dmarc-reports-domains').innerHTML, /Oct 25, 2026/);
});

test('a DMARC day from the server is named as it is', () => {
    const c = load(['dmarc.js']);
    assert.equal(c.dmarcDay('2026-10-25'), 'Oct 25');
    assert.equal(c.dmarcDay('2026-03-29', true), 'Sunday, March 29, 2026');
});

// ---------- Settings > Application > Time Zone, and About ----------

function settingsField(value, { envLocked = false, status = { valid: true, configured: value } } = {}) {
    const c = load(['settings.js']);
    c.__status = status;
    vm.runInContext('appTimezoneStatus = __status', c);
    return vm.runInContext(`renderSettingsEditField('tz', ${JSON.stringify(value)}, SETTINGS_SENSITIVE_KEYS,
        SETTINGS_FIELD_DESCRIPTIONS.tz, ${envLocked}, 'UTC')`, c);
}

test('the Time Zone setting is a list of IANA zones under Application', () => {
    const html = settingsField('Europe/Berlin');
    assert.match(html, /<label for="edit-tz" class="ui-label">Time Zone/);
    assert.match(html, /<select id="edit-tz" name="tz"/);
    assert.match(html, /<option value="Europe\/Berlin" selected>Europe\/Berlin<\/option>/);
    assert.match(html, /<option value="UTC">UTC<\/option>/);
    assert.match(html, /<option value="America\/New_York">/);
    assert.doesNotMatch(html, /not a known time zone|Times are shown in UTC/);
    const c = load(['settings.js']);
    const app = vm.runInContext("SETTINGS_EDIT_TABS.find(t => t.id === 'application').groups.flatMap(g => g.keys)", c);
    assert.ok(app.includes('tz'));
});

test('with no zone set the Time Zone field says times are in UTC', () => {
    for (const value of ['', 'UTC']) {
        const html = settingsField(value);
        assert.match(html, /Times are shown in UTC\. Pick the time zone of your mailcow server/);
        // Empty is UTC, the default: not marked as changed
        assert.doesNotMatch(html, /Changed|Reset to default/);
    }
    assert.match(settingsField(''), /<option value="" selected>Not set \(UTC\)<\/option>/);
});

test('an unknown zone is kept in the field and named as unknown', () => {
    const html = settingsField('Europe/Berlinn', { status: { valid: false, configured: 'Europe/Berlinn' } });
    assert.match(html, /<option value="Europe\/Berlinn" selected>Europe\/Berlinn \(unknown\)<\/option>/);
    assert.match(html, /&quot;Europe\/Berlinn&quot; is not a known time zone, so the app uses UTC\. Pick a time zone from the list\./);
    const locked = settingsField('Europe/Berlinn', { envLocked: true, status: { valid: false, configured: 'Europe/Berlinn' } });
    assert.match(locked, /Set by ENV/);
    assert.match(locked, /<select id="edit-tz" name="tz" disabled/);
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
