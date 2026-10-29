// =============================================================================
// USERS - Settings > Users
// =============================================================================
// Who may sign in, and what each may view and do (GET /api/users): the built-in
// admin from .env, local users with a password, OAuth2 entries by email, and the
// access everyone else who signs in with OAuth2 gets. The rows, the dialog and its
// area table follow Settings > Agents (agents.js). Shown in the edit form's Users
// section and in the read-only settings view, so it works either way.
// =============================================================================

let usersData = null;
// Bumped by every load and every change made here: an answer read before a newer one
// started (a refresh that overlaps a save) is dropped instead of drawing the old state
let usersSeq = 0;
// The section shows the error of a load that failed: the next answer draws, also an unchanged one
let usersFailed = false;

const USERS_ACCESS_LABELS = { admin: 'Admin', operator: 'Operator', viewer: 'Viewer', custom: 'Custom', none: 'No access' };
const USERS_ACCESS_TONES = { admin: 'warn', operator: 'info', viewer: '' };

const USERS_ICON_PERSON = '<svg class="ui-channel-icon" width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="4" stroke-width="2"></circle><path stroke-linecap="round" stroke-width="2" d="M4 20c1.5-3.5 4.5-5 8-5s6.5 1.5 8 5"></path></svg>';
const USERS_ICON_KEY = '<svg class="ui-channel-icon" width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><circle cx="8" cy="15" r="4" stroke-width="2"></circle><path stroke-linecap="round" stroke-width="2" d="M11 12l9-9M17 6l3 3M15 8l2 2"></path></svg>';

async function loadUsersPanel() {
    const panel = document.getElementById('users-panel');
    if (!panel) return;
    const seq = ++usersSeq;
    try {
        const response = await authenticatedFetch('/api/users');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (seq !== usersSeq) return;
        usersData = data;
        renderUsersPanel();
    } catch (e) {
        // A newer load or change has drawn the section since: this failure is old news
        if (seq !== usersSeq) return;
        console.error('Users error:', e);
        usersFailed = true;
        uiReplaceKeepingFocus(panel, '<section class="ui-panel ui-set-channels"><p class="ui-empty ui-text-fail">Could not load users. Reload this page to try again.</p></section>');
    }
}

function usersName(user) {
    return (user.kind === 'oauth2' ? user.email : user.username) || '';
}

function usersAreaLabels() {
    const labels = {};
    (usersData.areas || []).forEach(a => { labels[a.id] = a.label; });
    return labels;
}

// What a level gives today, as the server resolves it (a preset covers a new area by itself)
function usersPresetAreas(level) {
    const preset = (usersData.presets || []).find(p => p.id === level);
    return preset ? { ...(preset.areas || {}) } : {};
}

// What each level allows, in a few lines. Operator's actions are read from the areas
// the server gives it, so the list stays true when an area is added
function usersPresetLines(level) {
    const settingsLine = 'No Settings, users or AI agents';
    if (level === 'admin') return ['Views every page and takes every action', 'Manages Settings, users and AI agents'];
    if (level === 'viewer') return ['Views every page', 'Takes no action', settingsLine];
    if (level === 'custom') return ['Choose below what this user may view and do in each area', settingsLine];
    const operator = usersPresetAreas('operator');
    const labels = usersAreaLabels();
    const acts = (usersData.areas || []).filter(a => operator[a.id] === 'act').map(a => a.label);
    const viewOnly = (usersData.areas || []).filter(a => a.act && operator[a.id] === 'view');
    const list = acts.length > 1 ? `${acts.slice(0, -1).join(', ')} and ${acts[acts.length - 1]}` : acts.join('');
    const lines = ['Views every page', `Takes every action: ${list}`];
    if (viewOnly.length === 1 && viewOnly[0].id === 'rspamd') lines.push('Views Rspamd maps, but cannot edit them');
    else if (viewOnly.length) lines.push(`Views ${viewOnly.map(a => labels[a.id] || a.id).join(', ')}, but takes no action there`);
    lines.push(settingsLine);
    return lines;
}

// A local user's password: the server requires 8 to 256 characters (backend services/passwords.py).
// The meter shows how strong it is as guidance: an uppercase letter, a lowercase letter, a number
// and a symbol (by Unicode category; a symbol is anything but a letter or digit)
const USERS_PASSWORD_SHORT = 'Use at least 8 characters.';
const USERS_PASSWORD_LONG = 'Use at most 256 characters.';
const USERS_PASSWORD_RULES = [
    ['length', '8 or more characters', text => [...text].length >= 8],
    ['upper', 'An uppercase letter', text => /\p{Lu}/u.test(text)],
    ['lower', 'A lowercase letter', text => /\p{Ll}/u.test(text)],
    ['digit', 'A number', text => /\p{Nd}/u.test(text)],
    ['symbol', 'A symbol', text => /[^\p{L}\p{Nd}]/u.test(text)],
];
const USERS_STRENGTH = ['', 'Weak', 'Fair', 'Good', 'Strong'];

// What a password meets, and its strength: 0 empty; Weak (1) until every rule is met; then by
// length, Fair (2) for 8 or 9 characters, Good (3) for 10 to 13, Strong (4) for 14 or more
function usersPasswordCheck(password) {
    const text = String(password || '');
    const met = {};
    USERS_PASSWORD_RULES.forEach(([id, , test]) => { met[id] = test(text); });
    const length = [...text].length;
    const complete = Object.values(met).every(Boolean);
    const level = !text ? 0 : !complete ? 1 : length >= 14 ? 4 : length >= 10 ? 3 : 2;
    return { met, level };
}

// What Save stops before asking the server, in its words: the length only (in characters, as the
// server counts them). required: adding, where a password must be given
function usersPasswordBlock(password, required) {
    const text = String(password || '');
    if (!text) return required ? USERS_PASSWORD_SHORT : '';
    const length = [...text].length;
    return length < 8 ? USERS_PASSWORD_SHORT : length > 256 ? USERS_PASSWORD_LONG : '';
}

// The characters Generate draws from: one of each kind at least. Symbols that read plainly and
// need no quoting when pasted
const USERS_PASSWORD_SETS = ['ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz', '0123456789', '!#$%&*+-.:;=?@^_~'];

// A number from 0 to n - 1 from crypto.getRandomValues, each as likely: a draw from the top part
// of the range that does not divide evenly by n is drawn again
function usersRandomIndex(n) {
    const limit = Math.floor(0x100000000 / n) * n;
    const draw = new Uint32Array(1);
    for (;;) {
        crypto.getRandomValues(draw);
        if (draw[0] < limit) return draw[0] % n;
    }
}

function usersGeneratePassword(length) {
    const all = USERS_PASSWORD_SETS.join('');
    const chars = USERS_PASSWORD_SETS.map(set => set[usersRandomIndex(set.length)]);
    while (chars.length < length) chars.push(all[usersRandomIndex(all.length)]);
    // Shuffled, so the guaranteed kinds are not always first
    for (let i = chars.length - 1; i > 0; i--) {
        const j = usersRandomIndex(i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join('');
}

// Under the password field: Generate with its length and Copy, then the meter: four segments,
// the strength in words (read out as it changes), a line when it is weak but can be saved, and
// the requirements marked as met or not, for the eye and for a screen reader
function usersPasswordMeterHtml(hidden) {
    return `<div class="ui-pw-tools">
        <button type="button" class="ui-btn ui-btn-sm" id="user-edit-pw-generate">Generate</button>
        <label class="ui-pw-length" for="user-edit-pw-length">Length
            <input type="range" id="user-edit-pw-length" class="ui-pw-range" min="12" max="64" value="20">
            <output id="user-edit-pw-length-value" for="user-edit-pw-length">20</output></label>
        <button type="button" class="ui-btn ui-btn-sm" id="user-edit-pw-copy" aria-label="Copy the password" disabled>Copy</button>
    </div>
    <div class="ui-pw-meter${hidden ? ' hidden' : ''}" id="user-edit-pw-meter" data-level="0">
        <div class="ui-pw-bar" aria-hidden="true"><i></i><i></i><i></i><i></i></div>
        <p class="ui-pw-label" id="user-edit-pw-label" aria-live="polite"></p>
        <p class="ui-pw-warn hidden" id="user-edit-pw-warn">This password is weak. You can still save it.</p>
        <ul class="ui-pw-rules" aria-label="Password requirements">
            ${USERS_PASSWORD_RULES.map(([id, label]) => `<li data-rule="${id}" data-met="false"><span class="ui-pw-mark" aria-hidden="true">✗</span>${escapeHtml(label)}<span class="ui-sr-only">, not met</span></li>`).join('')}
        </ul>
    </div>`;
}

// keepWhenEmpty: editing, where an empty field keeps the password, so the meter waits for typing
function usersShowPasswordMeter(modal, password, keepWhenEmpty) {
    const meter = modal.querySelector('#user-edit-pw-meter');
    if (!meter) return;
    const check = usersPasswordCheck(password);
    meter.classList.toggle('hidden', keepWhenEmpty && !password);
    meter.dataset.level = String(check.level);
    const label = meter.querySelector('#user-edit-pw-label');
    const words = check.level ? `Password strength: ${USERS_STRENGTH[check.level]}` : '';
    if (label.textContent !== words) label.textContent = words;
    // Long enough to save, but weak: said, and Save stays possible
    meter.querySelector('#user-edit-pw-warn').classList.toggle('hidden', !(check.level === 1 && check.met.length));
    meter.querySelectorAll('li[data-rule]').forEach(item => {
        const on = !!check.met[item.dataset.rule];
        item.dataset.met = String(on);
        item.querySelector('.ui-pw-mark').textContent = on ? '✓' : '✗';
        item.querySelector('.ui-sr-only').textContent = on ? ', met' : ', not met';
    });
}

// Generate fills the field as readable text (it shows again as dots once typed over), a new
// length draws a new one, and Copy takes what the field holds
function usersWirePassword(modal, keepWhenEmpty) {
    const field = modal.querySelector('#user-edit-pass');
    if (!field) return;
    const length = modal.querySelector('#user-edit-pw-length');
    const copy = modal.querySelector('#user-edit-pw-copy');
    let generated = false;
    const update = () => {
        usersShowPasswordMeter(modal, field.value, keepWhenEmpty);
        copy.disabled = !field.value;
    };
    const fill = () => {
        field.value = usersGeneratePassword(Number(length.value));
        field.type = 'text';
        generated = true;
        update();
    };
    modal.querySelector('#user-edit-pw-generate').addEventListener('click', fill);
    length.addEventListener('input', () => {
        modal.querySelector('#user-edit-pw-length-value').textContent = length.value;
        if (generated) fill();
    });
    field.addEventListener('input', () => {
        if (generated) {
            generated = false;
            field.type = 'password';
        }
        update();
    });
    copy.addEventListener('click', event => copyToClipboard(field.value, event));
    update();
}

function usersPresetText(level) {    return `<ul class="ui-users-preset">${usersPresetLines(level).map(line => `<li>${escapeHtml(line)}</li>`).join('')}</ul>`;
}

// Custom: each area by name, as an agent's access is shown (agents.js agentsAreaChips)
function usersAreaChips(areas) {
    const labels = usersAreaLabels();
    const entries = Object.entries(areas || {});
    if (!entries.length) return '<span class="ui-muted">No access</span>';
    const acts = entries.filter(([, mode]) => mode === 'act');
    const views = entries.filter(([, mode]) => mode !== 'act');
    const chips = acts.map(([id]) => uiTag(`${labels[id] || id}: Take action`, 'warn'));
    if (views.length && entries.length === (usersData.areas || []).length) {
        chips.push(uiTag(acts.length ? 'All other areas: View only' : 'All areas: View only', ''));
    } else {
        views.forEach(([id]) => chips.push(uiTag(`${labels[id] || id}: View only`, '')));
    }
    return chips.join(' ');
}

function usersAccessChips(user) {
    if (user.access === 'custom') return usersAreaChips(user.areas);
    return uiTag(USERS_ACCESS_LABELS[user.access] || user.access, USERS_ACCESS_TONES[user.access] || '');
}

function usersWhen(iso) {
    return iso ? uiTime(iso, formatTime(iso, { seconds: false })) : '<span class="ui-muted">never</span>';
}

// The OAuth2 provider by the name set for it in Authentication (plain text: escape it for HTML)
function usersProvider() {
    const name = usersData && usersData.oauth2 && typeof usersData.oauth2.provider_name === 'string' ? usersData.oauth2.provider_name.trim() : '';
    return name || 'OAuth2';
}

// Who is looking (GET /api/users you): the built-in admin, a local user or an OAuth2 person,
// with their entry or, without one, the access for everyone else (via_default)
function usersYou() {
    return (usersData && usersData.you) || { kind: 'builtin', user_id: null, via_default: false };
}

function usersIsYou(user) {
    const you = usersYou();
    return !!user && you.user_id != null && you.kind === user.kind && you.user_id === user.id;
}

// An access as what it allows: Admin, and area -> view or act ('none': nothing)
function usersAccessOf(level, areas) {
    if (level === 'none') return { admin: false, areas: {} };
    return { admin: level === 'admin', areas: level === 'custom' ? (areas || {}) : usersPresetAreas(level) };
}

// The person's own access now, as the server said when the page loaded (utils.js appAccess)
function usersAccessNow() {
    const areas = {};
    (usersData.areas || []).forEach(a => {
        if (a.act && userCan(a.id, 'write')) areas[a.id] = 'act';
        else if (userCan(a.id)) areas[a.id] = 'view';
    });
    return { admin: userIsAdmin(), areas };
}

// What going from one access to another takes away, or null when nothing
function usersLoss(before, after) {
    const lost = { admin: before.admin && !after.admin, views: [], acts: [] };
    (usersData.areas || []).forEach(a => {
        const was = before.admin ? (a.act ? 'act' : 'view') : before.areas[a.id];
        const will = after.admin ? (a.act ? 'act' : 'view') : after.areas[a.id];
        if (was && !will) lost.views.push(a.label);
        else if (was === 'act' && will !== 'act') lost.acts.push(a.label);
    });
    return lost.admin || lost.views.length || lost.acts.length ? lost : null;
}

function usersAnd(items) {
    return items.length > 1 ? `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}` : items.join('');
}

function usersLossText(lost) {
    const parts = [];
    if (lost.admin) parts.push('Settings, Users and AI agents');
    if (lost.views.length) parts.push(usersAnd(lost.views));
    if (lost.acts.length) parts.push(`the actions you can take in ${usersAnd(lost.acts)}`);
    // The parts already hold an "and" each: a comma before the last one keeps them apart
    return `you will lose ${parts.length > 1 ? `${parts.slice(0, -1).join(', ')}, and ${parts[parts.length - 1]}` : parts[0]}`;
}

// The question to ask before a change to one's own access ({ message, confirmText }), or null
// when the change takes nothing away from the person making it.
// change: { kind: 'default', value } | { kind: 'edit', user, level, areas, disabled } | { kind: 'delete', user }
function usersSelfWarning(change) {
    const you = usersYou();
    const provider = usersProvider();
    const label = value => USERS_ACCESS_LABELS[value] || value;
    if (change.kind === 'default') {
        if (you.kind !== 'oauth2' || !you.via_default) return null;
        const start = `You signed in with ${provider} and get the access for everyone else.`;
        if (change.value === 'none') return { message: `${start} Changing it to No access signs you out at once.`, confirmText: 'Change my access' };
        const lost = usersLoss(usersAccessNow(), usersAccessOf(change.value));
        return lost ? { message: `${start} Changing it to ${label(change.value)} changes your own access too: ${usersLossText(lost)}.`, confirmText: 'Change my access' } : null;
    }
    if (!usersIsYou(change.user)) return null;
    const local = change.user.kind === 'local';
    const own = `This is your own ${local ? 'account' : 'entry'}.`;
    if (change.kind === 'delete') {
        if (local) return { message: `${own} Deleting it signs you out at once, and you can no longer sign in.`, confirmText: 'Delete my account' };
        const value = usersData.oauth2.default_access;
        if (value === 'none') return { message: `${own} Without it you cannot sign in, because users who are not on the list have no access.`, confirmText: 'Delete my account' };
        const lost = usersLoss(usersAccessNow(), usersAccessOf(value));
        return lost ? { message: `${own} Without it you get the access for everyone else (${label(value)}): ${usersLossText(lost)}.`, confirmText: 'Delete my account' } : null;
    }
    if (change.disabled && !change.user.disabled) return { message: `${own} Disabling sign-in signs you out at once.`, confirmText: 'Disable my sign-in' };
    const lost = usersLoss(usersAccessNow(), usersAccessOf(change.level, change.areas));
    if (!lost) return null;
    return { message: `${own} ${local ? 'Changing its access signs you out at once, and' : 'Changing its access changes yours:'} ${usersLossText(lost)}.`, confirmText: 'Change my access' };
}

// The question for usersSelfWarning's answer; true to go on
function usersAskSelf(warning) {
    return showConfirmModal({ title: 'Your own access', message: warning.message, confirmText: warning.confirmText, isDangerous: true, focusCancel: true });
}

// The admin from .env: always there while Basic Auth is on, changed in Authentication (or in .env)
function usersBuiltinRow() {
    const builtin = usersData.builtin;
    const form = !!document.querySelector('[data-tab-extra="users"]');
    const where = form ? 'Change its name and password in Authentication.' : 'Change its name and password in <code>.env</code>.';
    return `
        <div class="ui-channel ui-agent" data-key="user-builtin">
            ${USERS_ICON_KEY}
            <div class="ui-q-who">
                <div class="ui-agent-title"><b>${escapeHtml(builtin.username || '')}</b> ${uiTag('Admin', 'warn')} ${uiTag('Built-in', 'info')}${usersYou().kind === 'builtin' && appAccess.name ? ' ' + uiTag('You', 'info') : ''}</div>
                <small>The admin from <code>.env</code>. It always has full access and cannot be deleted. ${where}</small>
            </div>
        </div>`;
}

function usersRow(user) {
    const id = Number(user.id);
    const blocked = user.disabled || user.name_conflict;
    const state = user.disabled ? ` ${uiTag('Sign-in disabled', 'fail')}` : user.name_conflict ? ` ${uiTag('Cannot sign in', 'fail')}` : '';
    const how = user.name_conflict ? 'It cannot sign in, because the built-in admin has the same name.'
        : user.kind === 'oauth2' ? `Signs in with ${escapeHtml(usersProvider())}`
            : `Signs in with a password · last signed in ${usersWhen(user.last_login_at)}`;
    return `
        <div class="ui-channel ui-agent${blocked ? ' is-off' : ''}" data-key="user-${id}">
            ${USERS_ICON_PERSON}
            <div class="ui-q-who">
                <div class="ui-agent-title"><b>${escapeHtml(usersName(user))}</b>${usersIsYou(user) ? ' ' + uiTag('You', 'info') : ''}${state} ${usersAccessChips(user)}</div>
                <small>${how}</small>
            </div>
            <div class="ui-row-actions">
                <button type="button" onclick="editUser(${id})" class="ui-btn ui-btn-sm">Edit</button>
                <button data-acts="admin" type="button" onclick="deleteUser(${id})" class="ui-btn ui-btn-sm ui-btn-danger">Delete</button>
            </div>
        </div>`;
}

// Everyone else the provider signs in: one choice, applied at once
function usersDefaultPanel() {
    const oauth2 = usersData.oauth2;
    if (!oauth2.enabled) return '';
    const value = oauth2.default_access;
    const note = value === 'none' ? 'Only users on the list can sign in.' : 'Applies at once, also to people who are signed in now.';
    return `
        <section class="ui-panel ui-set-channels ui-users-default" aria-labelledby="users-default-h" data-key="oauth2-default">
            <div class="ui-list-head"><h4 class="ui-md-h" id="users-default-h">Everyone else who signs in with ${escapeHtml(usersProvider())}</h4></div>
            <p class="ui-set-desc">Users who sign in with ${escapeHtml(usersProvider())} and are not on the list above get this access. To give one user other access, add them by email.</p>
            <div class="ui-sec-mode">
                <div class="ui-seg" role="group" aria-labelledby="users-default-h">
                    ${['admin', 'operator', 'viewer', 'none'].map(level => `<button data-acts="admin" type="button" aria-pressed="${value === level}" onclick="setUsersDefault('${level}')">${USERS_ACCESS_LABELS[level]}</button>`).join('')}
                </div>
                <span class="ui-muted">${note}</span>
            </div>
        </section>`;
}

function renderUsersPanel() {
    const panel = document.getElementById('users-panel');
    if (!panel || !usersData) return;
    usersFailed = false;
    // Through the same drawing as the refresh, so what it remembers as shown stays true
    uiReplaceKeepingFocus(panel, usersPanelHtml());
}

// Read again with the Settings refresh (app.js): drawn again only when it changed, keeping the
// focus and the scroll, and never while a dialog or a question of the section is open
async function refreshUsersPanel() {
    const panel = document.getElementById('users-panel');
    const busy = () => !!document.querySelector('.ui-dialog-backdrop:not(.hidden)');
    if (!panel || !panel.getClientRects().length || busy()) return;
    const seq = ++usersSeq;
    try {
        const response = await authenticatedFetch('/api/users', { timeout: PAGE_REFRESH_TIMEOUT });
        if (!response.ok) return;
        const data = await response.json();
        if (seq !== usersSeq || busy() || (!usersFailed && JSON.stringify(data) === JSON.stringify(usersData))) return;
        usersData = data;
        renderUsersPanel();
    } catch (e) {
        // The next refresh tries again
    }
}

function usersPanelHtml() {
    const users = usersData.users || [];
    const builtin = usersData.builtin.basic_auth_enabled ? usersBuiltinRow() : '';
    const count = users.length + (builtin ? 1 : 0);
    const signInOff = !usersData.builtin.basic_auth_enabled && !usersData.oauth2.enabled;
    return `
        <section class="ui-panel ui-set-channels" aria-labelledby="users-list-h">
            <div class="ui-list-head" data-key="users-head">
                <h4 class="ui-md-h" id="users-list-h">${uiCountLabel(count, 'user', 'users')}</h4>
                <button type="button" onclick="editUser(null)" class="ui-btn ui-btn-sm ui-btn-primary ui-head-actions">Add user</button>
            </div>
            ${signInOff ? uiLocked('Nobody signs in yet', 'Turn on Basic Auth or OAuth2 in Authentication. Until then, everyone who reaches this app has full access.', '') : ''}
            <div class="ui-channels">${builtin}${users.map(usersRow).join('') || (builtin ? '' : '<p class="ui-empty">No users yet.</p>')}</div>
        </section>
        ${usersDefaultPanel()}`;
}

async function setUsersDefault(value) {
    if (!uiMayAct('admin')) return;
    const oauth2 = usersData && usersData.oauth2;
    if (!oauth2 || oauth2.default_access === value) return;
    // Signed in through the provider without an entry: this is the person's own access too
    // Awaited only when there is a question, so a change without one starts at once
    const self = usersSelfWarning({ kind: 'default', value });
    if (self && !(await usersAskSelf(self))) return;
    // A refresh on its way now may have read the old value: it is dropped
    usersSeq++;
    try {
        const response = await authenticatedFetch('/api/users/oauth2-default', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ value, version: oauth2.version }),
        });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) {
            showToast(typeof body.detail === 'string' ? body.detail : 'Could not change the access. Try again.', 'error');
            // Changed meanwhile: show it as it is now
            if (response.status === 409) loadUsersPanel();
            return;
        }
        // Onto the list as it is now (a refresh may have replaced it meanwhile); one that
        // started during the save and is still on its way is dropped
        usersSeq++;
        // A newer version already shown (another admin changed it since) stays
        const current = usersData.oauth2;
        const latest = Number(body.version) >= Number(current.version);
        if (latest) {
            current.default_access = body.default_access || value;
            current.version = body.version;
        }
        renderUsersPanel();
        if (latest) showToast(value === 'none' ? 'Only users on the list can sign in now' : 'Access changed', 'success');
        else showToast('Someone else changed this access since. It is shown as it is now.', 'info');
    } catch (e) {
        showToast('Could not change the access. Check your connection and try again.', 'error');
    }
}

// The ways a new user can sign in: each one that is on; with none on, both, for later
function usersKinds() {
    const kinds = [];
    if (usersData.builtin.basic_auth_enabled) kinds.push('local');
    if (usersData.oauth2.enabled) kinds.push('oauth2');
    return kinds.length ? kinds : ['local', 'oauth2'];
}

// Add or edit one user: whether they may sign in, how (on adding), and what they may do.
// The area table is the Agents one and shows only for Custom, filled from the level before
function editUser(userId) {
    if (!usersData) return;
    const user = userId == null ? null : (usersData.users || []).find(u => u.id === userId);
    if (userId != null && !user) return;
    document.getElementById('user-edit-modal')?.remove();
    const kinds = usersKinds();
    const kind = user ? user.kind : kinds[0];
    const level = user ? user.access : 'operator';
    const areas = user ? (user.areas || {}) : usersPresetAreas('operator');
    const name = user ? usersName(user) : '';
    const box = (area, mode, on) => `<label class="ui-consent-box"><input type="checkbox" class="ui-check" data-area="${escapeHtml(area.id)}"
        data-kind="${mode}" ${on ? 'checked' : ''} aria-label="${mode === 'act' ? 'Take action' : 'View'}: ${escapeHtml(area.label)}"></label>`;
    const rows = (usersData.areas || []).map(area => `
        <div class="ui-consent-row">
            <div class="ui-consent-area"><b>${escapeHtml(area.label)}</b><small>${escapeHtml(area.view || '')}</small>
                ${area.act ? `<small class="ui-consent-act-text">Actions: ${escapeHtml(area.act)}</small>` : ''}</div>
            ${box(area, 'view', !!areas[area.id])}
            ${area.act ? box(area, 'act', areas[area.id] === 'act') : '<span class="ui-consent-box"><small class="ui-muted">No actions</small></span>'}
        </div>`).join('');
    const kindChoice = !user && kinds.length > 1 ? `
        <div><span class="ui-label" id="user-edit-kind-h">Signs in with</span>
            <div class="ui-seg" role="group" aria-labelledby="user-edit-kind-h" id="user-edit-kind">
                ${kinds.map(k => `<button type="button" aria-pressed="${k === kind}" data-kind="${k}">${k === 'local' ? 'Password' : escapeHtml(usersProvider())}</button>`).join('')}
            </div>
        </div>` : '';
    const localFields = user && user.kind !== 'local' ? '' : `
        <div data-for="local" class="ui-form${kind === 'local' ? '' : ' hidden'}">
            ${user ? '' : `<label for="user-edit-name"><span class="ui-label">Username</span>
                <input id="user-edit-name" class="ui-input" autocomplete="off" maxlength="64" spellcheck="false"></label>`}
            <label for="user-edit-pass"><span class="ui-label">${user ? 'New password' : 'Password'}</span>
                <input id="user-edit-pass" type="password" class="ui-input" autocomplete="new-password" placeholder="At least 8 characters"></label>
            ${usersPasswordMeterHtml(!!user)}
            <p class="ui-set-desc">${user ? `Leave it empty to keep the current password. A new password signs ${escapeHtml(name)} out.`
                : 'Give this password to the user. They sign in on the sign-in page with the username and this password.'}</p>
        </div>`;
    const oauthFields = user ? (user.kind === 'oauth2' ? `<p class="ui-set-desc">Signs in with ${escapeHtml(usersProvider())}.</p>` : '') : `
        <div data-for="oauth2" class="ui-form${kind === 'oauth2' ? '' : ' hidden'}">
            <label for="user-edit-email"><span class="ui-label">Email</span>
                <input id="user-edit-email" type="email" class="ui-input" autocomplete="off" maxlength="320" placeholder="user@example.com"></label>
            <p class="ui-set-desc">The email address ${escapeHtml(usersProvider())} reports for this user.</p>
        </div>`;
    // The two choices are kept as values too, as the Settings segmented fields keep theirs,
    // so the unsaved-changes guard (uiGuardDialog) sees them
    const { backdrop: modal } = uiDialog({
        id: 'user-edit-modal', title: user ? `Edit ${name}` : 'Add user', titleId: 'user-edit-h', size: 'md', close: closeUserEditModal,
        // The version of the user this dialog shows: a save after a change made meanwhile is refused
        dataset: { version: user ? String(user.row_version) : '' },
        bodyClass: 'ui-form ui-agent-edit',
        form: { id: 'user-edit-form', onsubmit: `saveUser(event, ${user ? Number(user.id) : 'null'})` },
        body: `
            <div>
                <label class="ui-sec-inline"><input type="checkbox" class="ui-check" id="user-edit-disabled" ${user && user.disabled ? 'checked' : ''}> Disable sign-in</label>
                <p class="ui-set-desc">Blocks this user without deleting them, and signs them out at once.</p>
            </div>
            <input type="hidden" id="user-edit-kind-value" value="${kind}">
            <input type="hidden" id="user-edit-level-value" value="${level}">
            ${kindChoice}
            ${localFields}
            ${oauthFields}
            <div><span class="ui-label" id="user-edit-level-h">Access</span>
                <div class="ui-seg" role="group" aria-labelledby="user-edit-level-h" id="user-edit-level">
                    ${['admin', 'operator', 'viewer', 'custom'].map(l => `<button type="button" aria-pressed="${l === level}" data-level="${l}">${USERS_ACCESS_LABELS[l]}</button>`).join('')}
                </div>
                <div id="user-edit-level-text">${usersPresetText(level)}</div>
            </div>
            <div class="ui-consent-areas${level === 'custom' ? '' : ' hidden'}" role="group" aria-label="What this user may do" id="user-edit-grid">
                <div class="ui-consent-row ui-consent-row-head" aria-hidden="true"><span>Area</span><span>View</span><span>Take action</span></div>
                ${rows}
            </div>`,
        footClass: 'ui-agent-edit-foot',
        foot: `<p id="user-edit-error" class="ui-text-fail hidden" role="alert"></p>
            <button type="button" onclick="closeUserEditModal()" class="ui-btn">Cancel</button>
            <button type="submit" form="user-edit-form" class="ui-btn ui-btn-primary">${user ? 'Save' : 'Add'}</button>`,
    });
    const press = (group, chosen) => group.querySelectorAll('button').forEach(b => b.setAttribute('aria-pressed', String(b === chosen)));
    const grid = modal.querySelector('#user-edit-grid');
    modal.querySelector('#user-edit-level').addEventListener('click', event => {
        const button = event.target.closest('button[data-level]');
        if (!button) return;
        const chosen = button.dataset.level;
        const was = modal.querySelector('#user-edit-level-value').value;
        modal.querySelector('#user-edit-level-value').value = chosen;
        press(button.parentElement, button);
        modal.querySelector('#user-edit-level-text').innerHTML = usersPresetText(chosen);
        grid.classList.toggle('hidden', chosen !== 'custom');
        // Custom starts from what the level chosen before gave
        if (chosen === 'custom' && was !== 'custom') {
            const from = usersPresetAreas(was);
            grid.querySelectorAll('input[data-area]').forEach(input => {
                input.checked = input.dataset.kind === 'act' ? from[input.dataset.area] === 'act' : !!from[input.dataset.area];
            });
        }
    });
    modal.querySelector('#user-edit-kind')?.addEventListener('click', event => {
        const button = event.target.closest('button[data-kind]');
        if (!button) return;
        press(button.parentElement, button);
        modal.querySelector('#user-edit-kind-value').value = button.dataset.kind;
        modal.querySelectorAll('[data-for]').forEach(el => el.classList.toggle('hidden', el.dataset.for !== button.dataset.kind));
    });
    // Take action includes View: ticking it ticks View, and clearing View clears it
    grid.addEventListener('change', event => {
        const changed = event.target;
        if (!changed.dataset || !changed.dataset.area) return;
        const other = grid.querySelector(`input[data-area="${CSS.escape(changed.dataset.area)}"][data-kind="${changed.dataset.kind === 'act' ? 'view' : 'act'}"]`);
        if (changed.dataset.kind === 'act' && changed.checked && other) other.checked = true;
        if (changed.dataset.kind === 'view' && !changed.checked && other) other.checked = false;
    });
    // The password's strength while it is typed; editing shows it once something is typed
    usersWirePassword(modal, !!user);
    uiGuardDialog(modal);
}

function closeUserEditModal(saved = false) {
    const modal = document.getElementById('user-edit-modal');
    const close = () => modal?.remove();
    if (saved || !modal) {
        uiDialogSaved(modal);
        close();
    } else uiCloseGuarded(modal, close);
}

async function saveUser(event, userId) {
    event.preventDefault();
    if (!uiMayAct('admin')) return;
    const modal = document.getElementById('user-edit-modal');
    const error = document.getElementById('user-edit-error');
    const say = text => { error.textContent = text; error.classList.remove('hidden'); };
    const kind = modal.querySelector('#user-edit-kind-value').value;
    const level = modal.querySelector('#user-edit-level-value').value;
    const chosen = mode => [...modal.querySelectorAll(`#user-edit-grid input[data-kind="${mode}"]:checked`)].map(i => i.dataset.area);
    const custom = level === 'custom';
    if (custom && !chosen('view').length) return say('Select View for at least one area.');
    const disabled = modal.querySelector('#user-edit-disabled').checked;
    const password = modal.querySelector('#user-edit-pass')?.value || '';
    let url = '/api/users';
    let method = 'POST';
    let body;
    if (userId == null) {
        const field = kind === 'local' ? modal.querySelector('#user-edit-name') : modal.querySelector('#user-edit-email');
        const name = (field ? field.value : '').trim();
        if (!name) return say(kind === 'local' ? 'Enter a username.' : 'Enter the email address.');
        // The rest of the rule is the server's: its answer shows in the error line
        if (kind === 'local' && usersPasswordBlock(password, true)) return say(usersPasswordBlock(password, true));
        body = kind === 'local' ? { kind, username: name, password } : { kind, email: name };
    } else {
        url = `/api/users/${Number(userId)}`;
        method = 'PUT';
        body = { row_version: Number(modal.dataset.version) };
        if (usersPasswordBlock(password, false)) return say(usersPasswordBlock(password, false));
        if (password) body.password = password;
    }
    Object.assign(body, { access: level, views: custom ? chosen('view') : [], acts: custom ? chosen('act') : [], disabled });
    // One's own entry: asked first when the change takes something away from oneself
    if (userId != null) {
        const areas = {};
        body.views.forEach(id => { areas[id] = 'view'; });
        body.acts.forEach(id => { areas[id] = 'act'; });
        const user = usersData.users.find(u => u.id === userId);
        const self = usersSelfWarning({ kind: 'edit', user, level, areas, disabled });
        if (self && !(await usersAskSelf(self))) return;
    }
    try {
        // A refresh on its way now may have read the state before this change: it is dropped
        usersSeq++;
        const response = await authenticatedFetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        if (!response.ok) {
            const answer = await response.json().catch(() => ({}));
            const text = typeof answer.detail === 'string' ? answer.detail : 'Could not save the user. Try again.';
            if (userId != null && (response.status === 409 || response.status === 404)) {
                // Changed or deleted meanwhile: show the list as it is now
                closeUserEditModal(true);
                showToast(text, 'error');
                loadUsersPanel();
                return;
            }
            return say(text);
        }
        const saved = await response.json().catch(() => ({}));
        closeUserEditModal(true);
        showToast(userId == null ? `${usersName(saved) || 'User'} added` : 'Changes saved', 'success');
    } catch (e) {
        return say('Could not save the user. Check your connection and try again.');
    }
    loadUsersPanel();
}

async function deleteUser(userId) {
    if (!uiMayAct('admin')) return;
    const user = (usersData?.users || []).find(u => u.id === userId);
    if (!user) return;
    const name = usersName(user);
    const oauth2 = usersData.oauth2;
    // An OAuth2 entry gone leaves its person to the access for everyone else
    const message = user.kind !== 'oauth2' || !oauth2.enabled
        ? `Delete ${name}? They are signed out at once and can no longer sign in.`
        : oauth2.default_access === 'none'
            ? `Delete ${name}? They can no longer sign in, because users who are not on the list have no access.`
            : `Delete ${name}? They can still sign in with ${usersProvider()} and then get the access for everyone else (${USERS_ACCESS_LABELS[oauth2.default_access] || oauth2.default_access}). To block them, edit them and turn on Disable sign-in.`;
    // One's own entry: what it means for oneself, in its place
    const self = usersSelfWarning({ kind: 'delete', user });
    const confirmed = await showConfirmModal({ title: 'Delete user', message: self ? self.message : message,
        confirmText: self ? self.confirmText : 'Delete', isDangerous: true, focusCancel: !!self });
    if (!confirmed) return;
    try {
        usersSeq++;
        const response = await authenticatedFetch(`/api/users/${Number(userId)}`, { method: 'DELETE' });
        if (!response.ok && response.status !== 404) {
            const answer = await response.json().catch(() => ({}));
            showToast(typeof answer.detail === 'string' ? answer.detail : 'Could not delete the user. Try again.', 'error');
        } else {
            showToast(`${name} deleted`, 'success');
        }
    } catch (e) {
        showToast('Could not delete the user. Check your connection and try again.', 'error');
    }
    loadUsersPanel();
}
