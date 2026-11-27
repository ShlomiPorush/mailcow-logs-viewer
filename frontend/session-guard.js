const SESSION_GUARD_REASONS = ['session_idle', 'session_expired', 'access_changed'];
const SESSION_GUARD_REPORT_EVERY = 30000;
const SESSION_GUARD_POLL_EVERY = 60000;
const SESSION_GUARD_ASK_BEFORE = 60000;
const SESSION_GUARD_NOTICE_BEFORE = 300000;
const SESSION_GUARD_TICK = 5000;
const SESSION_GUARD_TIMEOUT = 15000;
// mousemove and scroll can come from the page itself and would keep a session alive.
const SESSION_GUARD_ACTIVITY_EVENTS = ['keydown', 'pointerdown', 'click', 'input', 'wheel', 'touchstart'];
const SESSION_GUARD_CLOSE_ICON = '<svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>';

const sessionGuardState = {
    active: false,
    leaving: false,
    seq: 0,
    applied: 0,
    longestAt: null,
    idleEnabled: false,
    idleAt: null,
    pending: false,
    reporting: false,
    lastReportAt: null,
    reportTimer: null,
    checking: false,
    checkTimer: null,
    failures: 0,
    noticeShown: false,
    dialog: null,
    dialogOpener: null,
    dialogOverflow: '',
    countdown: null,
    lastTick: 0,
};

function sessionGuardReason(value) {
    return SESSION_GUARD_REASONS.includes(value) ? value : '';
}

function sessionGuardLoginPath(reason, here) {
    const params = [];
    const known = sessionGuardReason(reason);
    if (known) params.push(`reason=${known}`);
    if (here && here !== '/') params.push(`next=${encodeURIComponent(here)}`);
    return params.length ? `/login?${params.join('&')}` : '/login';
}

function sessionGuardSessionOf(body) {
    if (!body || typeof body !== 'object') return null;
    const session = 'session' in body ? body.session : body;
    return session && typeof session === 'object' && Number.isFinite(session.longest_seconds_left) ? session : null;
}

function sessionGuardApply(state, seq, session, now) {
    if (seq <= state.applied) return false;
    state.applied = seq;
    state.longestAt = now + Math.max(0, session.longest_seconds_left) * 1000;
    state.idleEnabled = session.idle_enabled === true && Number.isFinite(session.idle_seconds_left);
    state.idleAt = state.idleEnabled ? now + Math.max(0, session.idle_seconds_left) * 1000 : null;
    return true;
}

function sessionGuardEndedBy(session) {
    if (session.idle_enabled === true && Number.isFinite(session.idle_seconds_left) && session.idle_seconds_left <= 0) return 'session_idle';
    if (session.longest_seconds_left <= 0) return 'session_expired';
    return '';
}

function sessionGuardGuessReason(state, now) {
    return state.longestAt !== null && state.longestAt <= now ? 'session_expired' : '';
}

function sessionGuardReportDelay({ idleEnabled, pending, inFlight, lastReportAt, force = false }, now) {
    if (!idleEnabled) return null;
    if (force) return 0;
    if (!pending || inFlight) return null;
    if (lastReportAt === null) return 0;
    return Math.max(0, lastReportAt + SESSION_GUARD_REPORT_EVERY - now);
}

function sessionGuardView(state, now) {
    const idleLeft = state.idleEnabled && state.idleAt !== null ? state.idleAt - now : null;
    return {
        ask: idleLeft !== null && idleLeft <= SESSION_GUARD_ASK_BEFORE && (state.longestAt === null || state.idleAt < state.longestAt),
        notice: state.longestAt !== null && state.longestAt - now <= SESSION_GUARD_NOTICE_BEFORE,
    };
}

function sessionGuardNextCheck(state, now) {
    const moments = [now + SESSION_GUARD_POLL_EVERY];
    if (state.idleEnabled && state.idleAt !== null) moments.push(state.idleAt - SESSION_GUARD_ASK_BEFORE, state.idleAt + 1000);
    if (state.longestAt !== null) moments.push(state.longestAt - SESSION_GUARD_NOTICE_BEFORE, state.longestAt + 1000);
    const next = Math.min(...moments.filter(t => t > now));
    return Math.max(1000, next - now);
}

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

async function sessionGuardReasonOf(response) {
    const header = response && response.headers && typeof response.headers.get === 'function'
        ? response.headers.get('X-Session-End') : null;
    if (sessionGuardReason(header)) return header;
    let reason = '';
    try {
        const body = await response.clone().json();
        reason = sessionGuardReason(body && body.reason);
    } catch (e) {
    }
    return reason || sessionGuardGuessReason(sessionGuardState, Date.now());
}

async function sessionGuardSend(url, method) {
    const seq = ++sessionGuardState.seq;
    const control = typeof AbortController === 'function' ? new AbortController() : null;
    const timer = control ? setTimeout(() => control.abort(), SESSION_GUARD_TIMEOUT) : null;
    let response, body;
    try {
        response = await fetch(url, { method, credentials: 'same-origin', cache: 'no-store', signal: control ? control.signal : undefined });
        if (response.status === 401) return { seq, kind: 'ended', reason: await sessionGuardReasonOf(response) };
        if (!response.ok) return { seq, kind: 'retry' };
        body = await response.json();
    } catch (e) {
        return { seq, kind: 'retry' };
    } finally {
        clearTimeout(timer);
    }
    if (body && body.authenticated === false) return { seq, kind: 'ended', reason: sessionGuardReason(body.reason) };
    if (url === '/api/auth/status' && typeof appAccessCheck === 'function') appAccessCheck(body);
    return { seq, kind: 'ok', session: sessionGuardSessionOf(body) };
}

function sessionGuardHandle(answer) {
    const state = sessionGuardState;
    if (!state.active || state.leaving) return;
    if (answer.kind === 'retry') {
        state.failures++;
        return;
    }
    state.failures = 0;
    if (answer.kind === 'ended') {
        if (answer.seq <= state.applied) return;
        state.applied = answer.seq;
        sessionGuardConfirmEnd(answer.reason);
        return;
    }
    if (!answer.session) {
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

async function sessionGuardConfirmEnd(reason) {
    const state = sessionGuardState;
    const again = await sessionGuardSend('/api/auth/status', 'GET');
    if (!state.active || state.leaving || again.seq <= state.applied) return;
    if (again.kind === 'ended') {
        sessionGuardLeave(again.reason || reason || sessionGuardGuessReason(state, Date.now()));
    } else if (again.kind === 'retry') {
        state.failures++;
        sessionGuardScheduleCheck(sessionGuardRetryDelay(state.failures));
    } else {
        sessionGuardHandle(again);
    }
}

function sessionGuardScheduleCheck(delay) {
    const state = sessionGuardState;
    if (!state.active || state.leaving) return;
    clearTimeout(state.checkTimer);
    state.checkTimer = setTimeout(sessionGuardCheck, delay === undefined ? sessionGuardNextCheck(state, Date.now()) : delay);
}

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
    if (force) sessionGuardAskError(answer.kind === 'retry' ? 'Could not reach the server. Check your connection and try again.' : '');
    sessionGuardHandle(answer);
    if (state.pending) sessionGuardScheduleReport();
}

function sessionGuardOnActivity(event) {
    const state = sessionGuardState;
    if (event.isTrusted === false || !state.active || !state.idleEnabled || state.leaving) return;
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
    const opener = state.dialogOpener;
    state.dialogOpener = null;
    if (hadFocus || document.activeElement === document.body) {
        if (opener && opener.isConnected && typeof opener.focus === 'function') opener.focus({ preventScroll: true });
    }
}

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
}

async function sessionGuardStart() {
    const state = sessionGuardState;
    const answer = await sessionGuardSend('/api/auth/status', 'GET');
    if (answer.kind === 'retry') {
        state.failures++;
        setTimeout(sessionGuardStart, sessionGuardRetryDelay(state.failures));
        return;
    }
    state.failures = 0;
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
    document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') sessionGuardCheck(); });
    window.addEventListener('pageshow', event => { if (event.persisted) sessionGuardCheck(); });
    window.addEventListener('online', () => sessionGuardCheck());
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
