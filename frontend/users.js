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

const USERS_ACCESS_LABELS = { admin: 'Admin', operator: 'Operator', viewer: 'Viewer', custom: 'Custom', none: 'No access' };
const USERS_ACCESS_TONES = { admin: 'warn', operator: 'info', viewer: '' };

const USERS_ICON_PERSON = '<svg class="ui-channel-icon" width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="4" stroke-width="2"></circle><path stroke-linecap="round" stroke-width="2" d="M4 20c1.5-3.5 4.5-5 8-5s6.5 1.5 8 5"></path></svg>';
const USERS_ICON_KEY = '<svg class="ui-channel-icon" width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><circle cx="8" cy="15" r="4" stroke-width="2"></circle><path stroke-linecap="round" stroke-width="2" d="M11 12l9-9M17 6l3 3M15 8l2 2"></path></svg>';

async function loadUsersPanel() {
    const panel = document.getElementById('users-panel');
    if (!panel) return;
    try {
        const response = await authenticatedFetch('/api/users');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        usersData = await response.json();
        renderUsersPanel();
    } catch (e) {
        console.error('Users error:', e);
        panel.innerHTML = '<section class="ui-panel ui-set-channels"><p class="ui-empty ui-text-fail">Could not load users. Reload this page to try again.</p></section>';
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

function usersPresetText(level) {
    return `<ul class="ui-users-preset">${usersPresetLines(level).map(line => `<li>${escapeHtml(line)}</li>`).join('')}</ul>`;
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

// The admin from .env: always there while Basic Auth is on, changed in Authentication (or in .env)
function usersBuiltinRow() {
    const builtin = usersData.builtin;
    const form = !!document.querySelector('[data-tab-extra="users"]');
    const where = form ? 'Change its name and password in Authentication.' : 'Change its name and password in <code>.env</code>.';
    return `
        <div class="ui-channel ui-agent">
            ${USERS_ICON_KEY}
            <div class="ui-q-who">
                <div class="ui-agent-title"><b>${escapeHtml(builtin.username || '')}</b> ${uiTag('Admin', 'warn')} ${uiTag('Built-in', 'info')}</div>
                <small>The admin from <code>.env</code>. It always has full access and cannot be deleted. ${where}</small>
            </div>
            ${form ? `<div class="ui-row-actions">
                <button type="button" class="ui-btn ui-btn-sm" onclick="settingsShowTab('auth')">Authentication</button>
            </div>` : ''}
        </div>`;
}

function usersRow(user) {
    const id = Number(user.id);
    const blocked = user.disabled || user.name_conflict;
    const state = user.disabled ? ` ${uiTag('Sign-in disabled', 'fail')}` : user.name_conflict ? ` ${uiTag('Cannot sign in', 'fail')}` : '';
    const how = user.name_conflict ? 'It cannot sign in, because the built-in admin has the same name.'
        : user.kind === 'oauth2' ? 'Signs in with OAuth2'
            : `Signs in with a password · last signed in ${usersWhen(user.last_login_at)}`;
    return `
        <div class="ui-channel ui-agent${blocked ? ' is-off' : ''}">
            ${USERS_ICON_PERSON}
            <div class="ui-q-who">
                <div class="ui-agent-title"><b>${escapeHtml(usersName(user))}</b>${state} ${usersAccessChips(user)}</div>
                <small>${how}</small>
            </div>
            <div class="ui-row-actions">
                <button type="button" onclick="editUser(${id})" class="ui-btn ui-btn-sm">Edit</button>
                <button data-acts="admin" type="button" onclick="deleteUser(${id})" class="ui-btn ui-btn-sm ui-btn-danger">Delete</button>
            </div>
        </div>`;
}

// Everyone else OAuth2 signs in: one choice, applied at once
function usersDefaultPanel() {
    const oauth2 = usersData.oauth2;
    if (!oauth2.enabled) return '';
    const value = oauth2.default_access;
    const note = value === 'none' ? 'Only users on the list can sign in.' : 'Applies at once, also to people who are signed in now.';
    return `
        <section class="ui-panel ui-set-channels ui-users-default" aria-labelledby="users-default-h">
            <div class="ui-list-head"><h4 class="ui-md-h" id="users-default-h">Everyone else who signs in with OAuth2</h4></div>
            <p class="ui-set-desc">Users who sign in with OAuth2 and are not on the list above get this access. To give one user other access, add them by email.</p>
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
    const users = usersData.users || [];
    const builtin = usersData.builtin.basic_auth_enabled ? usersBuiltinRow() : '';
    const count = users.length + (builtin ? 1 : 0);
    const signInOff = !usersData.builtin.basic_auth_enabled && !usersData.oauth2.enabled;
    panel.innerHTML = `
        <section class="ui-panel ui-set-channels" aria-labelledby="users-list-h">
            <div class="ui-list-head">
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
        oauth2.default_access = body.default_access || value;
        oauth2.version = body.version;
        renderUsersPanel();
        showToast(value === 'none' ? 'Only users on the list can sign in now' : 'Access changed', 'success');
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
                ${kinds.map(k => `<button type="button" aria-pressed="${k === kind}" data-kind="${k}">${k === 'local' ? 'Password' : 'OAuth2'}</button>`).join('')}
            </div>
        </div>` : '';
    const localFields = user && user.kind !== 'local' ? '' : `
        <div data-for="local" class="ui-form${kind === 'local' ? '' : ' hidden'}">
            ${user ? '' : `<label for="user-edit-name"><span class="ui-label">Username</span>
                <input id="user-edit-name" class="ui-input" autocomplete="off" maxlength="64" spellcheck="false"></label>`}
            <label for="user-edit-pass"><span class="ui-label">${user ? 'New password' : 'Password'}</span>
                <input id="user-edit-pass" type="password" class="ui-input" autocomplete="new-password" maxlength="256" placeholder="At least 12 characters"></label>
            <p class="ui-set-desc">${user ? `Leave it empty to keep the current password. A new password signs ${escapeHtml(name)} out.`
                : 'Give this password to the user. They sign in on the sign-in page with the username and this password.'}</p>
        </div>`;
    const oauthFields = user ? (user.kind === 'oauth2' ? '<p class="ui-set-desc">Signs in with OAuth2.</p>' : '') : `
        <div data-for="oauth2" class="ui-form${kind === 'oauth2' ? '' : ' hidden'}">
            <label for="user-edit-email"><span class="ui-label">Email</span>
                <input id="user-edit-email" type="email" class="ui-input" autocomplete="off" maxlength="320" placeholder="user@example.com"></label>
            <p class="ui-set-desc">The email address your OAuth2 provider reports for this user.</p>
        </div>`;
    const { backdrop: modal } = uiDialog({
        id: 'user-edit-modal', title: user ? `Edit ${name}` : 'Add user', titleId: 'user-edit-h', size: 'md', close: closeUserEditModal,
        // The version of the user this dialog shows: a save after a change made meanwhile is refused
        dataset: { version: user ? String(user.row_version) : '', kind },
        bodyClass: 'ui-form ui-agent-edit',
        form: { id: 'user-edit-form', onsubmit: `saveUser(event, ${user ? Number(user.id) : 'null'})` },
        body: `
            <div>
                <label class="ui-sec-inline"><input type="checkbox" class="ui-check" id="user-edit-disabled" ${user && user.disabled ? 'checked' : ''}> Disable sign-in</label>
                <p class="ui-set-desc">Blocks this user without deleting them, and signs them out at once.</p>
            </div>
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
        const was = modal.querySelector('#user-edit-level [aria-pressed="true"]').dataset.level;
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
        modal.dataset.kind = button.dataset.kind;
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
    const kind = modal.dataset.kind;
    const level = modal.querySelector('#user-edit-level [aria-pressed="true"]').dataset.level;
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
        body = kind === 'local' ? { kind, username: name, password } : { kind, email: name };
    } else {
        url = `/api/users/${Number(userId)}`;
        method = 'PUT';
        body = { row_version: Number(modal.dataset.version) };
        if (password) body.password = password;
    }
    Object.assign(body, { access: level, views: custom ? chosen('view') : [], acts: custom ? chosen('act') : [], disabled });
    try {
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
            : `Delete ${name}? They can still sign in with OAuth2 and then get the access for everyone else (${USERS_ACCESS_LABELS[oauth2.default_access] || oauth2.default_access}). To block them, edit them and turn on Disable sign-in.`;
    const confirmed = await showConfirmModal({ title: 'Delete user', message, confirmText: 'Delete', isDangerous: true });
    if (!confirmed) return;
    try {
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
