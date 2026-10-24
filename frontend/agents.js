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
    code_reused: 'Disconnected: authorization code reused',
    refresh_reused: 'Disconnected: refresh token reused',
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
        panel.innerHTML = '<p class="ui-empty ui-text-fail">Could not load agents. Reload this page to try again.</p>';
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
    const who = agent.publisher
        ? uiTag(`Name from ${agent.publisher}`, 'info')
        : uiTag('Name supplied by agent', '');
    return `${who}${declared}`;
}

function agentsRow(agent) {
    const connected = agent.state === 'connected';
    const facts = connected
        ? `Allowed ${agentsWhen(agent.created_at)}${agent.approved_by ? ` by ${escapeHtml(agent.approved_by)}` : ''} · expires ${agentsWhen(agent.expires_at)} · last used ${agentsWhen(agent.last_used_at)}`
        : `${escapeHtml(AGENTS_END_REASONS[agent.end_reason] || 'Access ended')} ${agentsWhen(agent.ended_at)}`;
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
    return `<p class="ui-set-desc">To connect an agent, run its command in a terminal on the computer where it runs, then approve access in the browser.</p>
    <div class="ui-md-ids ui-set-facts ui-agent-help">
        ${line('MCP server URL', url)}
        ${line('Claude Code', claude)}
        ${line('Codex', codex)}
    </div>
    <p class="ui-set-desc">If the browser does not open, run <code>claude mcp login mailcow</code> (Claude Code) or <code>codex mcp login mailcow</code> (Codex).</p>`;
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
                <h4 class="ui-md-h">Allowed agents</h4>
            </div>
            ${connected.length ? `<button type="button" onclick="disconnectAllAgents()" class="ui-btn ui-btn-sm ui-btn-danger ui-head-actions">Disconnect all</button>` : ''}
        </div>
        ${intro}
        <div class="ui-channels">${agents.map(agentsRow).join('') || '<p class="ui-empty">No agents have been allowed yet.</p>'}</div>`;
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

async function disconnectAgent(grantId) {
    const agent = (agentsData?.agents || []).find(a => a.id === grantId);
    const confirmed = await showConfirmModal({
        title: 'Disconnect agent',
        message: `Disconnect "${agent ? agent.name : 'this agent'}"? It cannot make new requests. To use it again, allow it again from the agent.`,
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
        message: `Disconnect ${uiCountLabel(count, 'agent', 'agents')}? They cannot make new requests. Each one must be allowed again to reconnect.`,
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
