// =============================================================================
// CONNECT AN AGENT - the consent page (/oauth/consent)
// =============================================================================
// An AI agent opened this page to ask for access. The signed-in person sees
// who is asking, picks View and Act per area and the period, then allows or
// denies; either way the browser goes back to the agent with the answer.
// Everything the agent sent (its name, its address) is set as text, never
// as markup.
// =============================================================================

const consentRequestId = new URLSearchParams(window.location.search).get('request') || '';
let consentDays = null;

function consentEl(id) {
    return document.getElementById(id);
}

function consentShowError(title, text) {
    consentEl('consent-loading').classList.add('hidden');
    consentEl('consent-form').classList.add('hidden');
    consentEl('consent-error-title').textContent = title;
    consentEl('consent-error-text').textContent = text;
    consentEl('consent-error').classList.remove('hidden');
}

async function consentErrorText(response, fallback) {
    try {
        const body = await response.json();
        if (body && typeof body.detail === 'string') return body.detail;
    } catch (e) { /* not JSON */ }
    return fallback;
}

function consentCheckbox(areaId, kind, label) {
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.className = 'ui-check';
    input.dataset.area = areaId;
    input.dataset.kind = kind;
    input.setAttribute('aria-label', `${kind === 'act' ? 'Act' : 'View'}: ${label}`);
    return input;
}

function consentRenderAreas(areas, preselected) {
    const host = consentEl('consent-areas');
    host.textContent = '';
    const head = document.createElement('div');
    head.className = 'ui-consent-row ui-consent-row-head';
    head.setAttribute('aria-hidden', 'true');
    ['Area', 'View', 'Act'].forEach(text => {
        const cell = document.createElement('span');
        cell.textContent = text;
        head.appendChild(cell);
    });
    host.appendChild(head);
    areas.forEach(area => {
        const row = document.createElement('div');
        row.className = 'ui-consent-row';
        const text = document.createElement('div');
        text.className = 'ui-consent-area';
        const name = document.createElement('b');
        name.textContent = area.label;
        const what = document.createElement('small');
        what.textContent = area.view;
        text.append(name, what);
        if (area.act) {
            const act = document.createElement('small');
            act.className = 'ui-consent-act-text';
            act.textContent = 'Act: ' + area.act;
            text.appendChild(act);
        }
        const view = consentCheckbox(area.id, 'view', area.label);
        view.checked = preselected.includes(area.id);
        const viewCell = document.createElement('label');
        viewCell.className = 'ui-consent-box';
        viewCell.appendChild(view);
        const actCell = document.createElement('label');
        actCell.className = 'ui-consent-box';
        if (area.act) {
            actCell.appendChild(consentCheckbox(area.id, 'act', area.label));
        } else {
            const none = document.createElement('small');
            none.className = 'ui-muted';
            none.textContent = 'None';
            none.title = 'This area has no actions';
            actCell.appendChild(none);
        }
        row.append(text, viewCell, actCell);
        host.appendChild(row);
    });
    host.addEventListener('change', consentBoxChanged);
}

// Act includes View: ticking Act ticks View, and clearing View clears Act
function consentBoxChanged(event) {
    const box = event.target;
    if (!box.dataset || !box.dataset.area) return;
    const other = consentEl('consent-areas').querySelector(
        `input[data-area="${CSS.escape(box.dataset.area)}"][data-kind="${box.dataset.kind === 'act' ? 'view' : 'act'}"]`);
    if (box.dataset.kind === 'act' && box.checked && other) other.checked = true;
    if (box.dataset.kind === 'view' && !box.checked && other) other.checked = false;
    consentShowActWarning();
}

function consentChosen(kind) {
    return [...consentEl('consent-areas').querySelectorAll(`input[data-kind="${kind}"]:checked`)].map(i => i.dataset.area);
}

function consentShowActWarning() {
    consentEl('consent-act-warning').classList.toggle('hidden', consentChosen('act').length === 0);
}

function consentRenderPeriods(periods, defaultDays) {
    const host = consentEl('consent-periods');
    host.textContent = '';
    consentDays = defaultDays;
    periods.forEach(period => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'ui-chip';
        button.setAttribute('role', 'radio');
        button.textContent = period.label;
        button.dataset.days = String(period.days);
        button.setAttribute('aria-checked', String(period.days === defaultDays));
        button.setAttribute('aria-pressed', String(period.days === defaultDays));
        button.tabIndex = period.days === defaultDays ? 0 : -1;
        button.addEventListener('click', () => consentPickPeriod(button));
        button.addEventListener('keydown', consentPeriodKeys);
        host.appendChild(button);
    });
}

function consentPickPeriod(button) {
    consentDays = Number(button.dataset.days);
    consentEl('consent-periods').querySelectorAll('button').forEach(b => {
        const on = b === button;
        b.setAttribute('aria-checked', String(on));
        b.setAttribute('aria-pressed', String(on));
        b.tabIndex = on ? 0 : -1;
    });
}

// Arrow keys move between the periods, as in any radio group
function consentPeriodKeys(event) {
    const keys = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 };
    if (!(event.key in keys)) return;
    event.preventDefault();
    const buttons = [...consentEl('consent-periods').querySelectorAll('button')];
    const next = buttons[(buttons.indexOf(event.currentTarget) + keys[event.key] + buttons.length) % buttons.length];
    consentPickPeriod(next);
    next.focus();
}

function consentRender(data) {
    const client = data.client || {};
    consentEl('consent-app').textContent = data.app_title || 'mailcow Logs Viewer';
    document.title = `Connect an agent - ${data.app_title || 'mailcow Logs Viewer'}`;
    consentEl('consent-declared').textContent = client.declared_name || 'Unnamed agent';
    const identity = consentEl('consent-identity');
    identity.textContent = '';
    if (client.publisher) {
        const tag = document.createElement('span');
        tag.className = 'ui-tag ui-tag-info';
        tag.textContent = `Details published by ${client.publisher}`;
        const note = document.createElement('span');
        note.textContent = ' The app cannot check which program on your computer is asking. Continue only if you just started this connection.';
        identity.append(tag, note);
    } else {
        const tag = document.createElement('span');
        tag.className = 'ui-tag ui-tag-warn';
        tag.textContent = 'Not verified';
        const note = document.createElement('span');
        note.textContent = ' Any program can use this name. Continue only if you just started this connection.';
        identity.append(tag, note);
    }
    consentEl('consent-redirect').textContent = client.redirect_uri || '';
    consentEl('consent-name').value = client.declared_name || '';
    consentRenderAreas(data.areas || [], data.preselected_views || []);
    consentRenderPeriods(data.periods || [], data.default_days);
    consentEl('consent-footnote').textContent = (data.signed_in_as ? `You approve as ${data.signed_in_as}. ` : '')
        + 'You can disconnect it at any time in Settings → Agents.';
    consentEl('consent-loading').classList.add('hidden');
    consentEl('consent-form').classList.remove('hidden');
    consentShowActWarning();
    consentEl('consent-allow').focus();
}

async function consentAnswer(allow) {
    const buttons = [consentEl('consent-allow'), consentEl('consent-deny')];
    const error = consentEl('consent-form-error');
    error.classList.add('hidden');
    const payload = { allow };
    if (allow) {
        payload.views = consentChosen('view');
        payload.acts = consentChosen('act');
        payload.name = consentEl('consent-name').value;
        payload.days = consentDays;
        if (!payload.views.length) {
            consentEl('consent-form-error-text').textContent = 'Choose at least one area to allow, or deny the request.';
            error.classList.remove('hidden');
            return;
        }
    }
    buttons.forEach(b => { b.disabled = true; });
    try {
        const response = await fetch(`/api/agents/consent/${encodeURIComponent(consentRequestId)}`, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (response.status === 401) {
            window.location.replace('/login?next=' + encodeURIComponent(window.location.pathname + window.location.search));
            return;
        }
        if (!response.ok) {
            const text = await consentErrorText(response, 'Could not save the answer. Try again.');
            if (response.status === 400) {
                consentEl('consent-form-error-text').textContent = text;
                error.classList.remove('hidden');
                buttons.forEach(b => { b.disabled = false; });
                return;
            }
            consentShowError('This request cannot be answered', text);
            return;
        }
        const body = await response.json();
        consentEl('consent-form').classList.add('hidden');
        consentEl('consent-done-title').textContent = allow ? 'Allowed' : 'Denied';
        consentEl('consent-done').classList.remove('hidden');
        window.location.replace(body.redirect);
    } catch (e) {
        consentEl('consent-form-error-text').textContent = 'Unable to connect. Check your connection and try again.';
        error.classList.remove('hidden');
        buttons.forEach(b => { b.disabled = false; });
    }
}

function consentSetAll(view) {
    consentEl('consent-areas').querySelectorAll('input[type="checkbox"]').forEach(box => {
        box.checked = view && box.dataset.kind === 'view';
    });
    consentShowActWarning();
}

async function consentLoad() {
    consentEl('consent-form').addEventListener('submit', event => { event.preventDefault(); consentAnswer(true); });
    consentEl('consent-deny').addEventListener('click', () => consentAnswer(false));
    consentEl('consent-view-all').addEventListener('click', () => consentSetAll(true));
    consentEl('consent-clear').addEventListener('click', () => consentSetAll(false));
    if (!consentRequestId) {
        consentShowError('No request', 'This page opens when an agent asks to connect. Start the connection from the agent.');
        return;
    }
    try {
        const response = await fetch(`/api/agents/consent/${encodeURIComponent(consentRequestId)}`, { credentials: 'same-origin' });
        if (response.status === 401) {
            window.location.replace('/login?next=' + encodeURIComponent(window.location.pathname + window.location.search));
            return;
        }
        if (!response.ok) {
            consentShowError('This request cannot be answered',
                await consentErrorText(response, 'Connect the agent again.'));
            return;
        }
        consentRender(await response.json());
    } catch (e) {
        consentShowError('Unable to connect', 'Check your connection and reload this page.');
    }
}

document.addEventListener('DOMContentLoaded', consentLoad);
