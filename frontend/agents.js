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
        case 'no_sign_in': return 'Agent access needs sign-in, so a person can approve each agent. Turn on Basic or OAuth2 sign-in in Settings → Authentication.';
        case 'no_url': return form ? 'Fill in <strong>App address for agents</strong> above.'
            : 'Agent access needs the address agents reach this app at. Set <code>AGENT_ACCESS_URL</code> in <code>.env</code>.';
        case 'bad_url': return 'The app address for agents must be an <code>https://</code> address without a path, such as <code>https://logs.example.com</code>.';
        default: return 'Agent access is not available.';
    }
}

const AGENTS_END_REASONS = {
    disconnected: 'Disconnected',
    sign_in_changed: 'Sign-in settings changed',
    code_reused: 'Its sign-in code was used twice',
    refresh_reused: 'Its token was used twice',
    revoked_by_agent: 'Disconnected by the agent',
    expired: 'Period ended',
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
        panel.innerHTML = '<p class="ui-empty ui-text-fail">Could not load the connected agents.</p>';
    }
}

function agentsAreaChips(areas) {
    const labels = {};
    (agentsData.areas || []).forEach(a => { labels[a.id] = a.label; });
    const entries = Object.entries(areas || {});
    if (!entries.length) return '<span class="ui-muted">Nothing</span>';
    // Actions first, each by name; views by name too, unless they cover every other area
    const acts = entries.filter(([, mode]) => mode === 'act');
    const views = entries.filter(([, mode]) => mode !== 'act');
    const chips = acts.map(([id]) => uiTag(`${labels[id] || id}: View + Act`, 'warn'));
    if (views.length && entries.length === (agentsData.areas || []).length) {
        chips.push(uiTag(acts.length ? 'All other areas: View' : 'All areas: View', ''));
    } else {
        views.forEach(([id]) => chips.push(uiTag(`${labels[id] || id}: View`, '')));
    }
    return chips.join(' ');
}

function agentsWhen(iso) {
    return iso ? uiTime(iso, formatTime(iso, { seconds: false })) : '<span class="ui-muted">never</span>';
}

function agentsIdentity(agent) {
    const declared = agent.declared_name && agent.declared_name !== agent.name
        ? ` <span class="ui-muted">(calls itself ${escapeHtml(agent.declared_name)})</span>` : '';
    const who = agent.publisher
        ? uiTag(`Published by ${agent.publisher}`, 'info')
        : uiTag('Not verified', '');
    return `${who}${declared}`;
}

function agentsRow(agent) {
    const connected = agent.state === 'connected';
    const facts = connected
        ? `Approved ${agentsWhen(agent.created_at)}${agent.approved_by ? ` by ${escapeHtml(agent.approved_by)}` : ''} · ends ${agentsWhen(agent.expires_at)} · last used ${agentsWhen(agent.last_used_at)}`
        : `${escapeHtml(AGENTS_END_REASONS[agent.end_reason] || 'Ended')} ${agentsWhen(agent.ended_at)}`;
    const open = agentsOpenActivity.has(agent.id);
    return `
        <div class="ui-channel ui-agent${connected ? '' : ' is-off'}">
            <svg class="ui-channel-icon" width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="8" width="14" height="11" rx="3" stroke-width="2"></rect><path stroke-linecap="round" stroke-width="2" d="M12 4v4M9 13h.01M15 13h.01M2 13v2M22 13v2"></path></svg>
            <div class="ui-q-who">
                <div><b>${escapeHtml(agent.name)}</b> ${agentsIdentity(agent)}</div>
                <div class="ui-chip-row ui-agent-areas">${agentsAreaChips(agent.areas)}</div>
                <small>${facts}</small>
            </div>
            <div class="ui-row-actions">
                <button type="button" onclick="toggleAgentActivity(${Number(agent.id)})" class="ui-btn ui-btn-sm" aria-expanded="${open}" aria-controls="agent-activity-${Number(agent.id)}">Activity</button>
                ${connected ? `<button type="button" onclick="disconnectAgent(${Number(agent.id)})" class="ui-btn ui-btn-sm ui-btn-danger">Disconnect</button>` : ''}
            </div>
            <div id="agent-activity-${Number(agent.id)}" class="ui-agent-activity${open ? '' : ' hidden'}"></div>
        </div>`;
}

function agentsConnectHelp() {
    const url = agentsData.mcp_url;
    const claude = `claude mcp add --transport http mailcow ${url}`;
    const codex = `codex mcp add mailcow --url ${url}`;
    const line = (label, text) => `
        <div class="ui-md-fact"><span>${label}</span>
            <div class="ui-agent-cmd"><code class="ui-mono">${escapeHtml(text)}</code>
            <button type="button" class="ui-btn ui-btn-sm" onclick="copyToClipboard(${escapeHtml(JSON.stringify(text))}, event)">Copy</button></div>
        </div>`;
    return `<div class="ui-md-ids ui-set-facts ui-agent-help">
        ${line('MCP address', url)}
        ${line('Claude Code', claude)}
        ${line('Codex', codex)}
    </div>
    <p class="ui-set-desc">If the browser does not open, run <code>claude mcp login mailcow</code> or <code>codex mcp login mailcow</code>.</p>`;
}

function renderAgentsPanel() {
    const panel = document.getElementById('agents-panel');
    if (!panel || !agentsData) return;
    const agents = agentsData.agents || [];
    const connected = agents.filter(a => a.state === 'connected');
    const problem = agentsData.live ? '' : agentsProblemText(agentsData.problem);
    const intro = agentsData.live ? agentsConnectHelp() : problem ? uiLocked('Agents cannot connect', problem, '') : '';
    panel.innerHTML = `
        <div class="ui-list-head">
            <div>
                <h4 class="ui-md-h">Connected agents</h4>
            </div>
            ${connected.length ? `<button type="button" onclick="disconnectAllAgents()" class="ui-btn ui-btn-sm ui-btn-danger ui-head-actions">Disconnect all</button>` : ''}
        </div>
        ${intro}
        <div class="ui-channels">${agents.map(agentsRow).join('') || '<p class="ui-empty">No agents connected.</p>'}</div>`;
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
            ? (AGENTS_END_REASONS[row.detail] || 'Disconnected') : row.event);
    const tone = row.outcome === 'ok' ? 'ok' : row.outcome === 'accepted' ? 'info' : row.outcome ? 'fail' : '';
    const outcome = row.event === 'denied' ? uiTag('Refused', 'fail')
        : row.http_status ? uiTag(`${row.outcome === 'ok' ? 'Done' : row.outcome === 'accepted' ? 'Started' : 'Failed'} ${row.http_status}`, tone) : '';
    const action = row.tool === 'perform_action' ? uiTag('Act', 'warn') : '';
    const detail = row.detail && (row.event === 'denied' || row.outcome === 'error')
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
            ? `<ul class="ui-agent-log">${rows.map(agentsActivityRow).join('')}</ul>${rows.length >= 50 ? '<p class="ui-set-desc">The last 50 entries.</p>' : ''}`
            : '<p class="ui-muted">Nothing yet.</p>';
    } catch (e) {
        box.innerHTML = '<p class="ui-text-fail">Could not load the activity.</p>';
    }
}

async function disconnectAgent(grantId) {
    const agent = (agentsData?.agents || []).find(a => a.id === grantId);
    const confirmed = await showConfirmModal({
        title: 'Disconnect agent',
        message: `Disconnect "${agent ? agent.name : 'this agent'}"? It stops working at once. To use it again, connect it again.`,
        confirmText: 'Disconnect',
        isDangerous: true
    });
    if (!confirmed) return;
    try {
        const response = await authenticatedFetch(`/api/agents/${grantId}`, { method: 'DELETE' });
        if (!response.ok && response.status !== 404) throw new Error(`HTTP ${response.status}`);
        showToast('Agent disconnected', 'success');
    } catch (e) {
        showToast('Could not disconnect the agent', 'error');
    }
    loadAgentsPanel();
}

async function disconnectAllAgents() {
    const count = (agentsData?.agents || []).filter(a => a.state === 'connected').length;
    const confirmed = await showConfirmModal({
        title: 'Disconnect all agents',
        message: `Disconnect ${uiCountLabel(count, 'agent', 'agents')}? They stop working at once.`,
        confirmText: 'Disconnect all',
        isDangerous: true
    });
    if (!confirmed) return;
    try {
        const response = await authenticatedFetch('/api/agents', { method: 'DELETE' });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        showToast('All agents disconnected', 'success');
    } catch (e) {
        showToast('Could not disconnect the agents', 'error');
    }
    loadAgentsPanel();
}
