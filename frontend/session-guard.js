// =============================================================================
// SESSION GUARD - the two limits of a browser session (Settings > Authentication
// > Sign-in Security), for both sign-in methods:
// - Longest session: counted from sign-in whatever the activity. Five minutes
//   before it ends, a notice says so, once.
// - Sign out after inactivity (only while it is on): real interaction (keys,
//   clicks, the wheel, touch, assistive technology) is reported to the server,
//   at most once every 30 seconds. A page that refreshes by itself is no
//   activity. A minute before the end a dialog asks "Are you still there?".
// The server decides. Every decision follows a fresh answer from it, so a tab
// that slept, timers that fired late and activity in another tab all count. A
// network failure or a server error never signs anyone out: the guard tries
// again. A session the server ended goes to the sign-in page with the reason.
//
// Standalone: it runs on the app, the agent consent page, the API reference and
// the device code page, so it needs no other script. Its dialog and notice are
// built with the frame of uiDialog and showToast (utils.js) and the app's own
// classes, and uiUnsavedClear (utils.js) is used only where it exists.
// Agents and API tokens have no browser session, so they are not affected.
// =============================================================================

// The reasons the server gives for a session it ended; any other value is ignored
const SESSION_GUARD_REASONS = ['session_idle', 'session_expired'];
const SESSION_GUARD_REPORT_EVERY = 30000;   // activity reports, at most one per 30 s
const SESSION_GUARD_POLL_EVERY = 60000;     // the regular status check
const SESSION_GUARD_ASK_BEFORE = 60000;     // "Are you still there?" a minute before
const SESSION_GUARD_NOTICE_BEFORE = 300000; // the longest-session notice, five minutes before
const SESSION_GUARD_TICK = 5000;            // the clock that notices a sleep
// What counts as activity: no mousemove and no scroll, which a page can cause by itself
const SESSION_GUARD_ACTIVITY_EVENTS = ['keydown', 'pointerdown', 'click', 'input', 'wheel', 'touchstart'];
// The X of the notice (UI_CLOSE_ICON in utils.js)
const SESSION_GUARD_CLOSE_ICON = '<svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>';

const sessionGuardState = {
    active: false,        // a browser session with limits is watched
    leaving: false,       // on the way to the sign-in page
    seq: 0,               // the number of the last request sent
    applied: 0,           // the number of the newest answer applied
    longestAt: null,      // when the longest session ends (ms, Date.now())
    idleEnabled: false,
    idleAt: null,         // when the session ends without activity (ms)
    pending: false,       // activity seen since the last report
    reporting: false,
    lastReportAt: null,
    reportTimer: null,
    checking: false,
    checkTimer: null,
    failures: 0,          // failed requests in a row, for the wait before the next try
    noticeShown: false,
    dialog: null,
    dialogOpener: null,   // where the focus was when the question opened
    dialogOverflow: '',
    countdown: null,
    lastTick: 0,
};

// ---------- What the guard decides (no page needed; .github/tests/session-guard.test.cjs) ----------

function sessionGuardReason(value) {
    return SESSION_GUARD_REASONS.includes(value) ? value : '';
}

// The sign-in page, with why the session ended and the page to come back to
function sessionGuardLoginPath(reason, here) {
    const params = [];
    const known = sessionGuardReason(reason);
    if (known) params.push(`reason=${known}`);
    if (here && here !== '/') params.push(`next=${encodeURIComponent(here)}`);
    return params.length ? `/login?${params.join('&')}` : '/login';
}

// The session part of an answer: /api/auth/status holds it in `session`, the
// activity answer is the object itself (or holds it the same way). null: no
// limits to watch (no sign-in, a Basic Auth header, sign-in turned off)
function sessionGuardSessionOf(body) {
    if (!body || typeof body !== 'object') return null;
    const session = 'session' in body ? body.session : body;
    return session && typeof session === 'object' && Number.isFinite(session.longest_seconds_left) ? session : null;
}

// Takes the deadlines of an answer, unless a newer answer was applied already
// (answers can arrive out of order). Returns whether it was applied
function sessionGuardApply(state, seq, session, now) {
    if (seq <= state.applied) return false;
    state.applied = seq;
    state.longestAt = now + Math.max(0, session.longest_seconds_left) * 1000;
    state.idleEnabled = session.idle_enabled === true && Number.isFinite(session.idle_seconds_left);
    state.idleAt = state.idleEnabled ? now + Math.max(0, session.idle_seconds_left) * 1000 : null;
    return true;
}

// Which limit an answer says has run out ('' while neither has)
function sessionGuardEndedBy(session) {
    if (session.idle_enabled === true && Number.isFinite(session.idle_seconds_left) && session.idle_seconds_left <= 0) return 'session_idle';
    if (session.longest_seconds_left <= 0) return 'session_expired';
    return '';
}

// A session that ended without a reason from the server: the limit whose time
// has passed here, if one has ('' otherwise: signed out elsewhere, a restart)
function sessionGuardGuessReason(state, now) {
    if (state.idleEnabled && state.idleAt !== null && state.idleAt <= now) return 'session_idle';
    if (state.longestAt !== null && state.longestAt <= now) return 'session_expired';
    return '';
}

// When to report activity: null nothing to report, 0 now, else in so many ms.
// The first activity goes at once; after a report the next waits out the 30
// seconds. force (Stay signed in) goes at once, whatever the wait
function sessionGuardReportDelay({ idleEnabled, pending, inFlight, lastReportAt, force = false }, now) {
    if (!idleEnabled) return null;
    if (force) return 0;
    if (!pending || inFlight) return null;
    if (lastReportAt === null) return 0;
    return Math.max(0, lastReportAt + SESSION_GUARD_REPORT_EVERY - now);
}

// What the page shows now: the question (only when staying helps, so not when
// the longest session ends first) and the longest-session notice
function sessionGuardView(state, now) {
    const idleLeft = state.idleEnabled && state.idleAt !== null ? state.idleAt - now : null;
    return {
        ask: idleLeft !== null && idleLeft <= SESSION_GUARD_ASK_BEFORE && (state.longestAt === null || state.idleAt < state.longestAt),
        notice: state.longestAt !== null && state.longestAt - now <= SESSION_GUARD_NOTICE_BEFORE,
    };
}

// When to ask the server next (ms from now): the regular check, or just after a
// moment that changes what the page shows (the question, the idle end, the
// notice, the longest end), whichever comes first; at least a second
function sessionGuardNextCheck(state, now) {
    const moments = [now + SESSION_GUARD_POLL_EVERY];
    if (state.idleEnabled && state.idleAt !== null) moments.push(state.idleAt - SESSION_GUARD_ASK_BEFORE, state.idleAt + 1000);
    if (state.longestAt !== null) moments.push(state.longestAt - SESSION_GUARD_NOTICE_BEFORE, state.longestAt + 1000);
    const next = Math.min(...moments.filter(t => t > now));
    return Math.max(1000, next - now);
}

// The wait before trying again after failures in a row: 5, 10, 20, 40, 60 s
function sessionGuardRetryDelay(failures) {
    return Math.min(SESSION_GUARD_POLL_EVERY, 5000 * 2 ** Math.max(0, Math.min(failures, 5) - 1));
}

function sessionGuardSecondsText(seconds) {
    return seconds === 1 ? '1 second' : `${seconds} seconds`;
}

function sessionGuardNoticeText(msLeft) {
    const minutes = Math.max(1, Math.ceil(msLeft / 60000));
    return `Your session ends in ${minutes === 1 ? '1 minute' : `${minutes} minutes`}. You will need to sign in again.`;
}

// ---------- Talking to the server ----------

// The reason a 401 gives: the X-Session-End header, else `reason` in its JSON body
async function sessionGuardReasonOf(response) {
    const header = response && response.headers && typeof response.headers.get === 'function'
        ? response.headers.get('X-Session-End') : null;
    if (sessionGuardReason(header)) return header;
    try {
        const body = await response.clone().json();
        return sessionGuardReason(body && body.reason);
    } catch (e) {
        return '';
    }
}

// One request, as what it means for the guard:
// ok (with the session, or null), ended (with the reason, maybe ''), or retry
// (the network or the server failed: never a sign-out)
async function sessionGuardSend(url, method) {
    const seq = ++sessionGuardState.seq;
    let response;
    try {
        response = await fetch(url, { method, credentials: 'same-origin', cache: 'no-store' });
    } catch (e) {
        return { seq, kind: 'retry' };
    }
    if (response.status === 401) return { seq, kind: 'ended', reason: await sessionGuardReasonOf(response) };
    if (!response.ok) return { seq, kind: 'retry' };
    let body;
    try {
        body = await response.json();
    } catch (e) {
        return { seq, kind: 'retry' };
    }
    if (body && body.authenticated === false) return { seq, kind: 'ended', reason: sessionGuardReason(body.reason) };
    return { seq, kind: 'ok', session: sessionGuardSessionOf(body) };
}

// ---------- The guard on the page ----------

function sessionGuardHandle(answer) {
    const state = sessionGuardState;
    if (!state.active || state.leaving) return;
    if (answer.kind === 'retry') {
        state.failures++;
        return;
    }
    state.failures = 0;
    if (answer.kind === 'ended') {
        // An older request that failed does not end a session a newer one saw alive
        if (answer.seq <= state.applied) return;
        state.applied = answer.seq;
        sessionGuardLeave(answer.reason || sessionGuardGuessReason(state, Date.now()));
        return;
    }
    if (!answer.session) {
        // Sign-in was turned off, or this is no longer a session with limits
        if (answer.seq > state.applied) sessionGuardStop();
        return;
    }
    if (!sessionGuardApply(state, answer.seq, answer.session, Date.now())) return;
    const ended = sessionGuardEndedBy(answer.session);
    if (ended) {
        sessionGuardLeave(ended);
        return;
    }
    sessionGuardRender();
    sessionGuardScheduleCheck();
}

function sessionGuardScheduleCheck(delay) {
    const state = sessionGuardState;
    if (!state.active || state.leaving) return;
    clearTimeout(state.checkTimer);
    state.checkTimer = setTimeout(sessionGuardCheck, delay === undefined ? sessionGuardNextCheck(state, Date.now()) : delay);
}

// Read the status again (never counts as activity)
async function sessionGuardCheck() {
    const state = sessionGuardState;
    if (!state.active || state.leaving || state.checking) return;
    clearTimeout(state.checkTimer);
    state.checkTimer = null;
    state.checking = true;
    let answer;
    try {
        answer = await sessionGuardSend('/api/auth/status', 'GET');
    } finally {
        state.checking = false;
    }
    sessionGuardHandle(answer);
    // Always a next check, also when this answer came too late to be applied
    sessionGuardScheduleCheck(answer.kind === 'retry' ? sessionGuardRetryDelay(state.failures) : undefined);
}

function sessionGuardScheduleReport(force = false) {
    const state = sessionGuardState;
    if (!state.active || state.leaving) return;
    const delay = sessionGuardReportDelay({ idleEnabled: state.idleEnabled, pending: state.pending,
        inFlight: state.reporting, lastReportAt: state.lastReportAt, force }, Date.now());
    if (delay === null) return;
    if (delay === 0) {
        sessionGuardReport(force);
        return;
    }
    if (!state.reportTimer) {
        state.reportTimer = setTimeout(() => { state.reportTimer = null; sessionGuardScheduleReport(); }, delay);
    }
}

// Tell the server there was activity; it moves the idle clock and answers with the deadlines
async function sessionGuardReport(force) {
    const state = sessionGuardState;
    clearTimeout(state.reportTimer);
    state.reportTimer = null;
    state.pending = false;
    state.reporting = true;
    state.lastReportAt = Date.now();
    let answer;
    try {
        answer = await sessionGuardSend('/api/auth/activity', 'POST');
    } finally {
        state.reporting = false;
    }
    // Not reported: it goes again after the wait
    if (answer.kind === 'retry') state.pending = true;
    if (force) sessionGuardAskError(answer.kind === 'retry' ? 'Could not reach the server. Check your connection and try again.' : '');
    sessionGuardHandle(answer);
    if (state.pending) sessionGuardScheduleReport();
}

function sessionGuardOnActivity(event) {
    const state = sessionGuardState;
    if (event.isTrusted === false || !state.active || !state.idleEnabled || state.leaving) return;
    // The question's own buttons answer it themselves
    if (state.dialog && event.target instanceof Node && state.dialog.contains(event.target)) return;
    state.pending = true;
    sessionGuardScheduleReport();
}

function sessionGuardRender() {
    const state = sessionGuardState;
    const now = Date.now();
    const view = sessionGuardView(state, now);
    if (view.ask) sessionGuardAsk();
    else sessionGuardAskClose();
    if (view.notice && !state.noticeShown) {
        state.noticeShown = true;
        sessionGuardNotice(sessionGuardNoticeText(state.longestAt - now));
    }
}

// To the sign-in page, past the question about unsaved changes (the session is gone)
function sessionGuardLeave(reason) {
    const state = sessionGuardState;
    if (state.leaving) return;
    state.leaving = true;
    sessionGuardStop();
    if (typeof uiUnsavedClear === 'function') uiUnsavedClear();
    window.location.replace(sessionGuardLoginPath(reason, window.location.pathname + window.location.search));
}

function sessionGuardStop() {
    const state = sessionGuardState;
    state.active = false;
    clearTimeout(state.checkTimer);
    clearTimeout(state.reportTimer);
    state.checkTimer = null;
    state.reportTimer = null;
    sessionGuardAskClose();
}

// Sign out from the question: the same request as the app's Sign out
async function sessionGuardSignOut() {
    sessionGuardAskError('');
    let response;
    try {
        response = await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
    } catch (e) {
        sessionGuardAskError('Could not sign out. Try again in a moment.');
        return;
    }
    if (response.status === 401) {
        sessionGuardLeave(await sessionGuardReasonOf(response));
        return;
    }
    if (!response.ok) {
        sessionGuardAskError('Could not sign out. Try again in a moment.');
        return;
    }
    sessionGuardState.leaving = true;
    sessionGuardStop();
    if (typeof uiUnsavedClear === 'function') uiUnsavedClear();
    window.location.href = '/login';
}

// ---------- The question and the notice (the frame of uiDialog and showToast, utils.js) ----------

// "Are you still there?": a question (alertdialog) without an X. Stay signed in
// is its Cancel (data-cancel): Escape, Back and a pull down on a phone choose
// it, through the layers in router.js on the app and here on the other pages
function sessionGuardAsk() {
    const state = sessionGuardState;
    if (state.dialog) {
        sessionGuardAskText();
        return;
    }
    const backdrop = document.createElement('div');
    backdrop.id = 'session-guard-dialog';
    backdrop.className = 'ui-dialog-backdrop ui-confirm';
    backdrop.setAttribute('role', 'alertdialog');
    backdrop.setAttribute('aria-modal', 'true');
    backdrop.setAttribute('aria-labelledby', 'session-guard-title');
    backdrop.setAttribute('aria-describedby', 'session-guard-text');
    // It opens by itself, so it writes no history entry of its own
    backdrop.dataset.noHistory = '';
    backdrop.innerHTML = `
        <div class="ui-dialog ui-dialog-fit ui-dialog-sm">
            <div class="ui-dialog-head"><h3 id="session-guard-title">Are you still there?</h3></div>
            <div class="ui-dialog-body ui-form-stack">
                <p class="ui-confirm-text" id="session-guard-text"></p>
                <p class="ui-banner ui-banner-fail hidden" id="session-guard-error" role="alert"></p>
            </div>
            <div class="ui-dialog-foot">
                <button type="button" id="session-guard-sign-out" class="ui-btn">Sign out</button>
                <button type="button" id="session-guard-stay" class="ui-btn ui-btn-primary" data-cancel>Stay signed in</button>
            </div>
        </div>`;
    const stay = backdrop.querySelector('#session-guard-stay');
    const signOut = backdrop.querySelector('#session-guard-sign-out');
    stay.addEventListener('click', () => sessionGuardScheduleReport(true));
    signOut.addEventListener('click', sessionGuardSignOut);
    // Escape and Tab on a page without the layers (router.js stops Escape before it gets here)
    backdrop.addEventListener('keydown', event => {
        if (event.key === 'Escape') {
            event.preventDefault();
            stay.click();
        } else if (event.key === 'Tab') {
            const first = signOut, last = stay;
            if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
            else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
        }
    });
    state.dialog = backdrop;
    state.dialogOpener = document.activeElement;
    state.dialogOverflow = document.body.style.overflow;
    document.body.appendChild(backdrop);
    // A page without the app's styles still gets a dialog over the page
    if (getComputedStyle(backdrop).position !== 'fixed') {
        backdrop.style.cssText = 'position:fixed;inset:0;z-index:99999;display:flex;align-items:center;justify-content:center;padding:16px;background:rgb(0 0 0 / .45)';
        backdrop.firstElementChild.style.cssText = 'max-width:460px;padding:16px;background:#fff;color:#111;border-radius:8px';
    }
    document.body.style.overflow = 'hidden';
    sessionGuardAskText();
    state.countdown = setInterval(sessionGuardAskText, 1000);
    stay.focus({ preventScroll: true });
}

function sessionGuardAskText() {
    const state = sessionGuardState;
    const text = state.dialog && state.dialog.querySelector('#session-guard-text');
    if (!text || state.idleAt === null) return;
    const seconds = Math.ceil((state.idleAt - Date.now()) / 1000);
    text.textContent = seconds > 0
        ? `You will be signed out in ${sessionGuardSecondsText(seconds)} because there was no activity.`
        : 'You are being signed out because there was no activity.';
}

function sessionGuardAskError(message) {
    const state = sessionGuardState;
    const el = state.dialog && state.dialog.querySelector('#session-guard-error');
    if (!el) return;
    el.textContent = message;
    el.classList.toggle('hidden', !message);
}

function sessionGuardAskClose() {
    const state = sessionGuardState;
    if (!state.dialog) return;
    clearInterval(state.countdown);
    state.countdown = null;
    const hadFocus = state.dialog.contains(document.activeElement);
    state.dialog.remove();
    state.dialog = null;
    document.body.style.overflow = state.dialogOverflow || '';
    // On the app the layers give the focus back; elsewhere, to where it was
    const opener = state.dialogOpener;
    state.dialogOpener = null;
    if (hadFocus || document.activeElement === document.body) {
        if (opener && opener.isConnected && typeof opener.focus === 'function') opener.focus({ preventScroll: true });
    }
}

// The longest-session notice: the one toast (it replaces any other, as
// showToast does), warning style, staying until it is closed
function sessionGuardNotice(message) {
    const existing = document.getElementById('toast-notification');
    if (existing) existing.remove();
    const toast = document.createElement('div');
    toast.id = 'toast-notification';
    toast.className = 'ui-toast ui-toast-warning';
    toast.setAttribute('role', 'status');
    toast.innerHTML = `
        <span class="ui-toast-icon" aria-hidden="true">⚠</span>
        <p></p>
        <button type="button" class="ui-icon-btn" title="Close" aria-label="Close">${SESSION_GUARD_CLOSE_ICON}</button>`;
    toast.querySelector('p').textContent = message;
    toast.querySelector('button').addEventListener('click', () => toast.remove());
    document.body.appendChild(toast);
    if (getComputedStyle(toast).position !== 'fixed') {
        toast.style.cssText = 'position:fixed;bottom:18px;right:18px;z-index:100000;display:flex;gap:10px;max-width:420px;padding:12px;background:#fff;color:#111;border:1px solid #ccc;border-radius:6px';
    }
}

// ---------- Start ----------

async function sessionGuardStart() {
    const state = sessionGuardState;
    const answer = await sessionGuardSend('/api/auth/status', 'GET');
    if (answer.kind === 'retry') {
        state.failures++;
        setTimeout(sessionGuardStart, sessionGuardRetryDelay(state.failures));
        return;
    }
    state.failures = 0;
    // Not signed in: the page's own check sends the browser to the sign-in page;
    // a session the server ended for a limit goes there from here, with the reason
    if (answer.kind === 'ended') {
        if (answer.reason) {
            state.active = true;
            sessionGuardLeave(answer.reason);
        }
        return;
    }
    if (!answer.session) return;
    state.active = true;
    sessionGuardHandle(answer);
}

function sessionGuardInit() {
    SESSION_GUARD_ACTIVITY_EVENTS.forEach(type => window.addEventListener(type, sessionGuardOnActivity, { capture: true, passive: true }));
    // Back to the tab, out of the back-forward cache, back online: the local
    // timers may be stale, so ask the server
    document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') sessionGuardCheck(); });
    window.addEventListener('pageshow', event => { if (event.persisted) sessionGuardCheck(); });
    window.addEventListener('online', () => sessionGuardCheck());
    // A sleep stops the timers; a tick that comes much later than due means one.
    // A hidden tab's timers are slowed down on purpose, and coming back to it is
    // a check of its own, so only a visible tab counts
    sessionGuardState.lastTick = Date.now();
    setInterval(() => {
        const now = Date.now();
        const slept = now - sessionGuardState.lastTick > SESSION_GUARD_TICK * 3;
        sessionGuardState.lastTick = now;
        if (slept && document.visibilityState === 'visible') sessionGuardCheck();
    }, SESSION_GUARD_TICK);
    sessionGuardStart();
}

if (typeof window !== 'undefined' && typeof document !== 'undefined' && typeof fetch === 'function') {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', sessionGuardInit);
    else sessionGuardInit();
}
