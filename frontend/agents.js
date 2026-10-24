// =============================================================================
// AGENTS - Settings > Agents
// =============================================================================
// AI agents (Claude Code, Codex, any MCP client) that a signed-in person
// connected through the consent page: how to connect one, which are
// connected, what each may do and did, and Disconnect. Shown in the edit form's
// Agents section and in the read-only settings view, so it works either way.
// =============================================================================

let agentsData = null;
const agentsOpenActivity = new Set();

// What is missing, or '' when the field right above already shows it. Without
// the edit form, only the variable can say it
function agentsProblemText(problem) {
    const form = !!document.querySelector('[data-tab-extra="agents"]');
    switch (problem) {
        case 'off': return form ? '' : 'Agent access is off. Set <code>AGENT_ACCESS_ENABLED=true</code> in <code>.env</code>.';
        case 'no_sign_in': return form ? '' : 'Agent access needs sign-in. Turn on Basic Auth or OAuth2 in Settings → Authentication.';
        case 'no_url': return form ? 'Fill in <strong>App URL</strong> above.'
            : 'The app URL is missing. Set <code>AGENT_ACCESS_URL</code> in <code>.env</code> to the address agents use to reach this app.';
        case 'bad_url': return 'Use an HTTPS app URL without a path, such as <code>https://logs.example.com</code>. HTTP works only on <code>localhost</code>, for a local test.';
        default: return 'Agent access is not available. Check Settings → Agents.';
    }
}

const AGENTS_END_REASONS = {
    disconnected: 'Disconnected',
    sign_in_changed: 'Disconnected after sign-in settings changed',
    code_reused: 'Disconnected after its sign-in code was used twice',
    refresh_reused: 'Disconnected after an old token was used again',
    revoked_by_agent: 'Disconnected by the agent',
    expired: 'Access expired',
};

async function loadAgentsPanel() {
    const panel = document.getElementById('agents-panel');
    if (!panel) return;
    try {
        const response = await authenticatedFetch('/api/agents');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        agentsData = await response.json();
        renderAgentsPanel();
    } catch (e) {
        console.error('Agents error:', e);
        panel.innerHTML = '<section class="ui-panel ui-set-channels"><p class="ui-empty ui-text-fail">Could not load agents. Reload this page to try again.</p></section>';
    }
}

function agentsAreaChips(areas) {
    const labels = {};
    (agentsData.areas || []).forEach(a => { labels[a.id] = a.label; });
    const entries = Object.entries(areas || {});
    if (!entries.length) return '<span class="ui-muted">No access</span>';
    // Actions first, each by name; views by name too, unless they cover every other area
    const acts = entries.filter(([, mode]) => mode === 'act');
    const views = entries.filter(([, mode]) => mode !== 'act');
    const chips = acts.map(([id]) => uiTag(`${labels[id] || id}: Take action`, 'warn'));
    if (views.length && entries.length === (agentsData.areas || []).length) {
        chips.push(uiTag(acts.length ? 'All other areas: View only' : 'All areas: View only', ''));
    } else {
        views.forEach(([id]) => chips.push(uiTag(`${labels[id] || id}: View only`, '')));
    }
    return chips.join(' ');
}

function agentsWhen(iso) {
    return iso ? uiTime(iso, formatTime(iso, { seconds: false })) : '<span class="ui-muted">never</span>';
}

function agentsIdentity(agent) {
    const declared = agent.declared_name && agent.declared_name !== agent.name
        ? ` <span class="ui-muted">(Agent name: ${escapeHtml(agent.declared_name)})</span>` : '';
    // Where an MCP client's details came from (its metadata document); the approval
    // page already said whose word the name is, so nothing more here
    const who = agent.publisher
        ? `<span title="${escapeHtml(`Details from ${agent.publisher}`)}">${uiTag(agent.publisher, 'info')}</span>`
        : '';
    return `${who}${declared}`;
}

function agentsRow(agent) {
    const connected = agent.state === 'connected';
    const facts = connected
        ? `${agent.kind === 'device' ? 'Skill' : 'MCP'} · Allowed ${agentsWhen(agent.created_at)}${agent.approved_by ? ` by ${escapeHtml(agent.approved_by)}` : ''} · expires ${agentsWhen(agent.expires_at)} · last used ${agentsWhen(agent.last_used_at)}`
        : `${escapeHtml(AGENTS_END_REASONS[agent.end_reason] || 'Access ended')} ${agentsWhen(agent.ended_at)}`;
    const open = agentsOpenActivity.has(agent.id);
    return `
        <div class="ui-channel ui-agent${connected ? '' : ' is-off'}">
            <svg class="ui-channel-icon" width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="8" width="14" height="11" rx="3" stroke-width="2"></rect><path stroke-linecap="round" stroke-width="2" d="M12 4v4M9 13h.01M15 13h.01M2 13v2M22 13v2"></path></svg>
            <div class="ui-q-who">
                <div class="ui-agent-title"><b>${escapeHtml(agent.name)}</b> ${agentsIdentity(agent)} ${agentsAreaChips(agent.areas)}</div>
                <small>${facts}</small>
            </div>
            <div class="ui-row-actions">
                <button type="button" onclick="toggleAgentActivity(${Number(agent.id)})" class="ui-btn ui-btn-sm" aria-expanded="${open}" aria-controls="agent-activity-${Number(agent.id)}">Activity</button>
                ${connected ? `<button type="button" onclick="editAgentAccess(${Number(agent.id)})" class="ui-btn ui-btn-sm">Edit</button>
                <button type="button" onclick="disconnectAgent(${Number(agent.id)})" class="ui-btn ui-btn-sm ui-btn-danger">Disconnect</button>` : ''}
            </div>
            <div id="agent-activity-${Number(agent.id)}" class="ui-agent-activity${open ? '' : ' hidden'}"></div>
        </div>`;
}

// How an agent connects, one tab per kind of agent (as in n8n-ops): agents that
// run commands get one sentence and approve with a code; MCP clients add the address
let agentsTab = 'skill';

function agentsConnectHelp() {
    const url = agentsData.mcp_url;
    const line = (label, text) => `
        <div class="ui-md-fact"><span>${label}</span>
            <div class="ui-agent-cmd"><code class="ui-mono">${escapeHtml(text)}</code>
            <button type="button" class="ui-btn ui-btn-sm" onclick="copyToClipboard(${escapeHtml(JSON.stringify(text))}, event)">Copy</button></div>
        </div>`;
    const tab = (id, label) => `<button type="button" id="agents-tab-${id}" class="modal-tab${agentsTab === id ? ' active' : ''}" role="tab"
        aria-selected="${agentsTab === id}" aria-controls="agents-connect-${id}" onclick="agentsShowTab('${id}')">${label}</button>`;
    const panel = (id, html) => `<div id="agents-connect-${id}" role="tabpanel" aria-labelledby="agents-tab-${id}"
        class="ui-agent-tabpanel${agentsTab === id ? '' : ' hidden'}">${html}</div>`;
    return `<div class="ui-agent-connect">
        <div class="ui-tabs ui-agent-tabs" role="tablist" aria-label="How to connect">${tab('skill', 'Agent')}${tab('mcp', 'MCP')}</div>
        ${panel('skill', `<p class="ui-set-desc">Paste this sentence to your AI agent. It replies with a link and a code that you approve from any device.</p>
            <div class="ui-md-ids ui-set-facts ui-agent-help">${line('Sentence for the agent', agentsData.skill_sentence || '')}</div>`)}
        ${panel('mcp', `<p class="ui-set-desc">Paste this sentence to your AI agent, or add the address yourself in your app's MCP settings. Approve the request in the browser that opens on that computer.</p>
            <div class="ui-md-ids ui-set-facts ui-agent-help">
                ${line('Sentence for the agent', agentsData.mcp_sentence || '')}
                ${line('MCP server URL', url)}
            </div>`)}
    </div>`;
}

function agentsShowTab(id) {
    agentsTab = id;
    ['skill', 'mcp'].forEach(other => {
        const button = document.getElementById(`agents-tab-${other}`);
        const panel = document.getElementById(`agents-connect-${other}`);
        if (button) {
            button.classList.toggle('active', other === id);
            button.setAttribute('aria-selected', String(other === id));
        }
        if (panel) panel.classList.toggle('hidden', other !== id);
    });
}

function renderAgentsPanel() {
    const panel = document.getElementById('agents-panel');
    if (!panel || !agentsData) return;
    const agents = agentsData.agents || [];
    const connected = agents.filter(a => a.state === 'connected');
    const problem = agentsData.live ? '' : agentsProblemText(agentsData.problem);
    const intro = agentsData.live ? agentsConnectHelp() : problem ? uiLocked('Agents cannot connect', problem, '') : '';
    // Two parts: how to connect an agent, and the agents that were allowed
    const connect = intro ? `
        <section class="ui-panel ui-set-channels" aria-labelledby="agents-connect-h">
            <div class="ui-list-head"><h4 class="ui-md-h" id="agents-connect-h">Connect an agent</h4></div>
            ${intro}
        </section>` : '';
    panel.innerHTML = `${connect}
        <section class="ui-panel ui-set-channels" aria-labelledby="agents-connected-h">
            <div class="ui-list-head">
                <h4 class="ui-md-h" id="agents-connected-h">Connected agents</h4>
                ${connected.length ? `<button type="button" onclick="disconnectAllAgents()" class="ui-btn ui-btn-sm ui-btn-danger ui-head-actions">Disconnect all</button>` : ''}
            </div>
            <div class="ui-channels">${agents.map(agentsRow).join('') || '<p class="ui-empty">No agents connected yet.</p>'}</div>
        </section>`;
    agentsOpenActivity.forEach(id => loadAgentActivity(id));
}

async function toggleAgentActivity(grantId) {
    if (agentsOpenActivity.has(grantId)) agentsOpenActivity.delete(grantId);
    else agentsOpenActivity.add(grantId);
    const box = document.getElementById(`agent-activity-${grantId}`);
    const button = box && box.parentElement.querySelector('[aria-controls]');
    if (box) box.classList.toggle('hidden', !agentsOpenActivity.has(grantId));
    if (button) button.setAttribute('aria-expanded', String(agentsOpenActivity.has(grantId)));
    if (agentsOpenActivity.has(grantId)) loadAgentActivity(grantId);
}

function agentsActivityRow(row) {
    const what = row.event === 'call' || row.event === 'denied'
        ? `<span class="ui-mono">${escapeHtml(row.method || '')} ${escapeHtml(row.path || '')}</span>`
        : escapeHtml(row.event === 'grant_created' ? 'Connected' : row.event === 'grant_revoked'
            ? (AGENTS_END_REASONS[row.detail] || 'Disconnected')
            : row.event === 'grant_changed' ? `Access changed${(/^by ([^:]+):/.exec(row.detail || '') || [])[1] ? ` by ${/^by ([^:]+):/.exec(row.detail)[1]}` : ''}`
            : row.event);
    const tone = row.outcome === 'ok' ? 'ok' : row.outcome === 'accepted' ? 'info' : row.outcome ? 'fail' : '';
    // A call that got no answer in time (504) may still be running: its outcome is unknown
    const unknown = row.outcome === 'accepted' && row.http_status === 504;
    const result = row.outcome === 'ok' ? 'Succeeded' : unknown ? 'Outcome unknown' : row.outcome === 'accepted' ? 'Accepted' : 'Failed';
    const outcome = row.event === 'denied' ? uiTag('Denied', 'fail')
        : row.http_status ? uiTag(unknown ? result : `${result} ${row.http_status}`, tone) : '';
    const action = row.tool === 'perform_action' ? uiTag('Action', 'warn') : '';
    const detail = unknown
        ? '<small class="ui-muted">No answer within 60 seconds. It may still be running.</small>'
        : row.detail && (row.event === 'denied' || row.outcome === 'error')
            ? `<small class="ui-muted" title="${escapeHtml(row.detail)}">${escapeHtml(row.detail)}</small>` : '';
    return `<li><span class="ui-agent-when">${uiTime(row.at, formatTime(row.at))}</span><span>${action} ${what} ${outcome}${detail ? '<br>' + detail : ''}</span></li>`;
}

async function loadAgentActivity(grantId) {
    const box = document.getElementById(`agent-activity-${grantId}`);
    if (!box) return;
    box.innerHTML = '<p class="ui-muted">Loading activity...</p>';
    try {
        const response = await authenticatedFetch(`/api/agents/${grantId}/activity`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const rows = (await response.json()).activity || [];
        box.innerHTML = rows.length
            ? `<ul class="ui-agent-log">${rows.map(agentsActivityRow).join('')}</ul>${rows.length >= 50 ? '<p class="ui-set-desc">Showing the latest 50 entries.</p>' : ''}`
            : '<p class="ui-muted">No activity yet.</p>';
    } catch (e) {
        box.innerHTML = '<p class="ui-text-fail">Could not load activity. Close and open it again to retry.</p>';
    }
}

// Edit: the areas a connected agent may view or take action in, and optionally a
// new end. The same table as the approval page; applies from the agent's next request.
function editAgentAccess(grantId) {
    const agent = (agentsData?.agents || []).find(a => a.id === grantId && a.state === 'connected');
    if (!agent) return;
    document.getElementById('agent-edit-modal')?.remove();
    const current = agent.areas || {};
    const box = (area, kind, on) => `<label class="ui-consent-box"><input type="checkbox" class="ui-check" data-area="${escapeHtml(area.id)}"
        data-kind="${kind}" ${on ? 'checked' : ''} aria-label="${kind === 'act' ? 'Take action' : 'View'}: ${escapeHtml(area.label)}"></label>`;
    const rows = (agentsData.areas || []).map(area => `
        <div class="ui-consent-row">
            <div class="ui-consent-area"><b>${escapeHtml(area.label)}</b><small>${escapeHtml(area.view || '')}</small>
                ${area.act ? `<small class="ui-consent-act-text">Actions: ${escapeHtml(area.act)}</small>` : ''}</div>
            ${box(area, 'view', !!current[area.id])}
            ${area.act ? box(area, 'act', current[area.id] === 'act') : '<span class="ui-consent-box"><small class="ui-muted">No actions</small></span>'}
        </div>`).join('');
    const ends = (agentsData.periods || []).map(p => `<option value="${Number(p.days)}">In ${escapeHtml(p.label)}</option>`).join('');
    const modal = document.createElement('div');
    modal.id = 'agent-edit-modal';
    // The version of the access this dialog shows: saving it after the list
    // reloaded meanwhile must not pass for an edit of the newer access
    modal.dataset.version = agent.version || '';
    modal.className = 'ui-dialog-backdrop';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-labelledby', 'agent-edit-h');
    modal.innerHTML = `
        <div class="ui-dialog ui-dialog-fit">
            <div class="ui-dialog-head">
                <h3 id="agent-edit-h">Edit access</h3>
                <button type="button" onclick="closeAgentEditModal()" class="ui-icon-btn" title="Close" aria-label="Close">
                    <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <form id="agent-edit-form" class="ui-dialog-body ui-form ui-agent-edit" onsubmit="saveAgentAccess(event, ${Number(agent.id)})">
                <p class="ui-set-desc">Changes to <b>${escapeHtml(agent.name)}</b> apply from its next request.</p>
                <div class="ui-consent-areas" role="group" aria-label="What it may do">
                    <div class="ui-consent-row ui-consent-row-head" aria-hidden="true"><span>Area</span><span>View</span><span>Take action</span></div>
                    ${rows}
                </div>
                <label for="agent-edit-end"><span class="ui-label">Access ends</span>
                    <select id="agent-edit-end" class="ui-select">
                        <option value="">Keep ${escapeHtml(formatTime(agent.expires_at, { seconds: false }))}</option>${ends}
                    </select>
                </label>
                <p id="agent-edit-error" class="ui-text-fail hidden" role="alert"></p>
                <div class="ui-form-actions">
                    <span class="ui-toolbar-gap"></span>
                    <button type="button" onclick="closeAgentEditModal()" class="ui-btn">Cancel</button>
                    <button type="submit" class="ui-btn ui-btn-primary">Save</button>
                </div>
            </form>
        </div>`;
    document.body.appendChild(modal);
    // Take action includes View: ticking it ticks View, and clearing View clears it
    modal.querySelector('.ui-consent-areas').addEventListener('change', event => {
        const changed = event.target;
        if (!changed.dataset || !changed.dataset.area) return;
        const other = modal.querySelector(`input[data-area="${CSS.escape(changed.dataset.area)}"][data-kind="${changed.dataset.kind === 'act' ? 'view' : 'act'}"]`);
        if (changed.dataset.kind === 'act' && changed.checked && other) other.checked = true;
        if (changed.dataset.kind === 'view' && !changed.checked && other) other.checked = false;
    });
    uiGuardDialog(modal);
}

function closeAgentEditModal(saved = false) {
    const modal = document.getElementById('agent-edit-modal');
    const close = () => modal?.remove();
    if (saved || !modal) {
        uiDialogSaved(modal);
        close();
    } else uiCloseGuarded(modal, close);
}

async function saveAgentAccess(event, grantId) {
    event.preventDefault();

    const modal = document.getElementById('agent-edit-modal');
    const version = modal.dataset.version || null;
    const error = document.getElementById('agent-edit-error');
    const chosen = kind => [...modal.querySelectorAll(`input[data-kind="${kind}"]:checked`)].map(i => i.dataset.area);
    const end = document.getElementById('agent-edit-end').value;
    const say = text => { error.textContent = text; error.classList.remove('hidden'); };
    if (!chosen('view').length) return say('Select View for at least one area. To end its access, use Disconnect.');
    try {
        const response = await authenticatedFetch(`/api/agents/${grantId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ views: chosen('view'), acts: chosen('act'), days: end === '' ? null : Number(end), version }),
        });
        if (!response.ok) {
            const body = await response.json().catch(() => ({}));
            const text = typeof body.detail === 'string' ? body.detail : 'Could not save the change. Try again.';
            if (response.status === 409 || response.status === 404) {
                // Changed or disconnected meanwhile: show the list as it is now
                closeAgentEditModal(true);
                showToast(text, 'error');
                loadAgentsPanel();
                return;
            }
            return say(text);
        }
        closeAgentEditModal(true);
        showToast('Access changed', 'success');
    } catch (e) {
        return say('Could not save the change. Check your connection and try again.');
    }
    loadAgentsPanel();
}

async function disconnectAgent(grantId) {
    const agent = (agentsData?.agents || []).find(a => a.id === grantId);
    const confirmed = await showConfirmModal({
        title: 'Disconnect agent',
        message: `Disconnect "${agent ? agent.name : 'this agent'}"? Its next request is refused. To use it again, connect it again from the agent.`,
        confirmText: 'Disconnect',
        isDangerous: true
    });
    if (!confirmed) return;
    try {
        const response = await authenticatedFetch(`/api/agents/${grantId}`, { method: 'DELETE' });
        if (!response.ok && response.status !== 404) throw new Error(`HTTP ${response.status}`);
        showToast('Agent disconnected', 'success');
    } catch (e) {
        showToast('Could not disconnect the agent. Try again.', 'error');
    }
    loadAgentsPanel();
}

async function disconnectAllAgents() {
    const count = (agentsData?.agents || []).filter(a => a.state === 'connected').length;
    const confirmed = await showConfirmModal({
        title: 'Disconnect all agents',
        message: `Disconnect ${uiCountLabel(count, 'agent', 'agents')}? Their next requests are refused. Each one has to connect again from its agent.`,
        confirmText: 'Disconnect all',
        isDangerous: true
    });
    if (!confirmed) return;
    try {
        const response = await authenticatedFetch('/api/agents', { method: 'DELETE' });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        showToast('All agents disconnected', 'success');
    } catch (e) {
        showToast('Could not disconnect all agents. Try again.', 'error');
    }
    loadAgentsPanel();
}
