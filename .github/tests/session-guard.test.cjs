// The session guard (frontend/session-guard.js): what it decides from the
// server's answers, without a page. The file is loaded as it is; without a
// window it starts nothing.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');
const context = vm.createContext({});
vm.runInContext(fs.readFileSync(path.join(frontend, 'session-guard.js'), 'utf8'), context);
const g = context;

const state = (fields = {}) => ({ applied: 0, longestAt: null, idleEnabled: false, idleAt: null, ...fields });
const session = (fields = {}) => ({ longest_seconds_left: 3600, idle_enabled: true, idle_timeout_seconds: 600, idle_seconds_left: 600, ...fields });

test('only the known reasons are kept', () => {
    assert.equal(g.sessionGuardReason('session_idle'), 'session_idle');
    assert.equal(g.sessionGuardReason('session_expired'), 'session_expired');
    for (const value of ['', null, undefined, 'evil', '<b>x</b>', 'toString', '__proto__', 'Session_Idle']) {
        assert.equal(g.sessionGuardReason(value), '', String(value));
    }
});

test('the sign-in address carries the reason and the page to come back to', () => {
    assert.equal(g.sessionGuardLoginPath('session_idle', '/messages?q=a b'), '/login?reason=session_idle&next=%2Fmessages%3Fq%3Da%20b');
    assert.equal(g.sessionGuardLoginPath('session_expired', '/'), '/login?reason=session_expired');
    assert.equal(g.sessionGuardLoginPath('', '/'), '/login');
    assert.equal(g.sessionGuardLoginPath('javascript:alert(1)', '/dmarc'), '/login?next=%2Fdmarc');
    assert.equal(g.sessionGuardLoginPath(undefined, '/oauth/authorize?request=r1'), '/login?next=%2Foauth%2Fauthorize%3Frequest%3Dr1');
});

test('a 401 gives its reason through the header, else its JSON body', async () => {
    const response = (header, body) => ({
        headers: { get: name => (name === 'X-Session-End' ? header : null) },
        clone: () => ({ json: async () => { if (body === undefined) throw new Error('no JSON'); return body; } }),
    });
    assert.equal(await g.sessionGuardReasonOf(response('session_idle', { reason: 'session_expired' })), 'session_idle');
    assert.equal(await g.sessionGuardReasonOf(response(null, { detail: 'x', reason: 'session_expired' })), 'session_expired');
    assert.equal(await g.sessionGuardReasonOf(response('evil', { reason: 'session_idle' })), 'session_idle');
    assert.equal(await g.sessionGuardReasonOf(response(null, { detail: 'Not authenticated' })), '');
    assert.equal(await g.sessionGuardReasonOf(response(null, { reason: 'other' })), '');
    assert.equal(await g.sessionGuardReasonOf(response(null, undefined)), '');
});

test('the session is read from the status answer and from the activity answer', () => {
    const s = session();
    assert.equal(g.sessionGuardSessionOf({ authenticated: true, session: s }), s);
    assert.equal(g.sessionGuardSessionOf({ authenticated: true, auth_type: 'basic', session: null }), null);
    assert.equal(g.sessionGuardSessionOf(s), s);
    assert.equal(g.sessionGuardSessionOf({ session: s }), s);
    assert.equal(g.sessionGuardSessionOf(null), null);
    assert.equal(g.sessionGuardSessionOf({ longest_seconds_left: 'soon' }), null);
});

test('deadlines come from the answer, and an older answer never replaces a newer one', () => {
    const st = state();
    assert.equal(g.sessionGuardApply(st, 2, session({ idle_seconds_left: 300 }), 1000), true);
    assert.equal(st.longestAt, 1000 + 3600 * 1000);
    assert.equal(st.idleAt, 1000 + 300 * 1000);
    // The answer to an earlier request arrives late: ignored
    assert.equal(g.sessionGuardApply(st, 1, session({ idle_seconds_left: 5 }), 2000), false);
    assert.equal(st.idleAt, 1000 + 300 * 1000);
    assert.equal(st.applied, 2);
    // Idle off: no idle deadline
    assert.equal(g.sessionGuardApply(st, 3, session({ idle_enabled: false, idle_timeout_seconds: null, idle_seconds_left: null }), 3000), true);
    assert.equal(st.idleEnabled, false);
    assert.equal(st.idleAt, null);
});

test('which limit ended, from the server or from the local clock', () => {
    assert.equal(g.sessionGuardEndedBy(session({ idle_seconds_left: 0 })), 'session_idle');
    assert.equal(g.sessionGuardEndedBy(session({ longest_seconds_left: 0 })), 'session_expired');
    assert.equal(g.sessionGuardEndedBy(session({ idle_enabled: false, idle_seconds_left: null, longest_seconds_left: 10 })), '');
    assert.equal(g.sessionGuardGuessReason(state({ idleEnabled: true, idleAt: 500, longestAt: 9000 }), 1000), 'session_idle');
    assert.equal(g.sessionGuardGuessReason(state({ longestAt: 500 }), 1000), 'session_expired');
    // Signed out elsewhere, or the server restarted: no reason to give
    assert.equal(g.sessionGuardGuessReason(state({ idleEnabled: true, idleAt: 5000, longestAt: 9000 }), 1000), '');
});

test('activity is reported at once, then at most every 30 seconds; Stay signed in goes at once', () => {
    const base = { idleEnabled: true, pending: true, inFlight: false, lastReportAt: null };
    assert.equal(g.sessionGuardReportDelay({ ...base, idleEnabled: false }, 0), null);
    assert.equal(g.sessionGuardReportDelay(base, 0), 0);
    assert.equal(g.sessionGuardReportDelay({ ...base, pending: false }, 0), null);
    assert.equal(g.sessionGuardReportDelay({ ...base, inFlight: true }, 0), null);
    assert.equal(g.sessionGuardReportDelay({ ...base, lastReportAt: 100000 }, 110000), 20000);
    assert.equal(g.sessionGuardReportDelay({ ...base, lastReportAt: 100000 }, 131000), 0);
    assert.equal(g.sessionGuardReportDelay({ ...base, lastReportAt: 100000, inFlight: true, pending: false, force: true }, 101000), 0);
});

test('the question shows a minute before, the notice five minutes before', () => {
    const now = 1000000;
    const view = fields => g.sessionGuardView(state({ idleEnabled: true, longestAt: now + 3600000, ...fields }), now);
    assert.equal(view({ idleAt: now + 61000 }).ask, false);
    assert.equal(view({ idleAt: now + 60000 }).ask, true);
    assert.equal(view({ idleAt: now + 60000, idleEnabled: false }).ask, false);
    // Staying would not help when the longest session ends first
    assert.equal(view({ idleAt: now + 30000, longestAt: now + 20000 }).ask, false);
    assert.equal(view({ idleAt: null, idleEnabled: false, longestAt: now + 301000 }).notice, false);
    assert.equal(view({ idleAt: null, idleEnabled: false, longestAt: now + 300000 }).notice, true);
});

test('the next check comes with the regular poll or just after a moment that matters', () => {
    const now = 1000000;
    const next = fields => g.sessionGuardNextCheck(state(fields), now);
    assert.equal(next({ idleEnabled: true, idleAt: now + 600000, longestAt: now + 3600000 }), 60000);
    assert.equal(next({ idleEnabled: true, idleAt: now + 90000, longestAt: now + 3600000 }), 30000);
    // Inside the last minute: right after the end, to hear it from the server
    assert.equal(next({ idleEnabled: true, idleAt: now + 30000, longestAt: now + 3600000 }), 31000);
    assert.equal(next({ longestAt: now + 320000 }), 20000);
    assert.equal(next({ longestAt: now - 5000 }), 60000);
    assert.equal(next({ idleEnabled: true, idleAt: now + 200, longestAt: now + 3600000 }), 1200);
    assert.equal(next({ idleEnabled: true, idleAt: now - 900, longestAt: now + 3600000 }), 1000);
});

test('failures wait longer each time, never more than a minute', () => {
    assert.deepEqual([1, 2, 3, 4, 5, 9].map(n => g.sessionGuardRetryDelay(n)), [5000, 10000, 20000, 40000, 60000, 60000]);
});

test('every page behind the sign-in loads the guard', () => {
    for (const page of ['index.html', 'authorize.html', 'api-docs.html']) {
        const html = fs.readFileSync(path.join(frontend, page), 'utf8');
        assert.match(html, /<script src="\/static\/session-guard\.js\?v=\d+"><\/script>/, page);
    }
});

// The guard talking to a server that answers from a list, with timers that never fire
function guardWith(answers, left) {
    const response = ({ status, body, header = null }) => ({
        status,
        ok: status >= 200 && status < 300,
        headers: { get: name => (name === 'X-Session-End' ? header : null) },
        json: async () => { if (body === undefined) throw new Error('no JSON'); return body; },
        clone() { return this; },
    });
    const ctx = vm.createContext({
        fetch: async () => {
            const next = answers.shift();
            if (!next || next.network) throw new Error('network');
            return response(next);
        },
        setTimeout: () => 1, clearTimeout: () => {}, setInterval: () => 1, clearInterval: () => {},
        window: { location: { pathname: '/messages', search: '', replace: url => left.push(url) } },
    });
    vm.runInContext(fs.readFileSync(path.join(frontend, 'session-guard.js'), 'utf8'), ctx);
    const st = vm.runInContext('sessionGuardState', ctx);
    st.active = true;
    return { ctx, st };
}
const settle = async () => { for (let i = 0; i < 10; i++) await new Promise(resolve => setImmediate(resolve)); };

test('an activity report whose answer was lost is not sent again by itself', async () => {
    const { ctx, st } = guardWith([{ network: true }], []);
    st.idleEnabled = true;
    st.pending = true;
    await ctx.sessionGuardReport(false);
    assert.equal(st.pending, false);
    assert.equal(st.reportTimer, null);
});

test('an ended answer is checked again with the cookie the browser holds now', async () => {
    const left = [];
    const alive = { status: 200, body: { authenticated: true, session: session({ idle_enabled: false, idle_seconds_left: null, idle_timeout_seconds: null }) } };
    const { ctx, st } = guardWith([alive], left);
    // A late answer for a cookie another tab has replaced since
    ctx.sessionGuardHandle({ seq: ++st.seq, kind: 'ended', reason: '' });
    await settle();
    assert.deepEqual(left, []);
    assert.equal(st.leaving, false);
    // The browser's cookie has ended too: now it leaves, with the reason
    const answers = [{ status: 401, header: 'session_idle', body: { reason: 'session_idle' } }];
    const second = guardWith(answers, left);
    second.ctx.sessionGuardHandle({ seq: ++second.st.seq, kind: 'ended', reason: '' });
    await settle();
    assert.deepEqual(left, ['/login?reason=session_idle&next=%2Fmessages']);
});

test('a 401 without a reason after the longest session ended here says so', async () => {
    const { ctx, st } = guardWith([], []);
    st.longestAt = Date.now() - 1000;
    const bare = { headers: { get: () => null }, clone: () => ({ json: async () => { throw new Error('no JSON'); } }) };
    assert.equal(await ctx.sessionGuardReasonOf(bare), 'session_expired');
    st.longestAt = Date.now() + 60000;
    assert.equal(await ctx.sessionGuardReasonOf(bare), '');
});
