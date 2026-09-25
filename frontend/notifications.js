// =============================================================================
// NOTIFICATION CHANNELS - Settings > Notifications
// =============================================================================
// Manage where alerts are delivered. Multiple destinations can be configured;
// each type only asks for the fields it actually needs (a Slack channel asks
// for its webhook URL, Telegram for a bot token and chat ID, and so on).
// =============================================================================

let notificationChannels = [];
let notificationChannelTypes = [];
let notificationAlertTypes = [];  // the alert topics a channel can subscribe to
let notificationEditing = null;   // channel being edited, or {} for a new one

const CHANNEL_ICONS = {
    slack: 'M14.5 10c-.83 0-1.5-.67-1.5-1.5v-5c0-.83.67-1.5 1.5-1.5s1.5.67 1.5 1.5v5c0 .83-.67 1.5-1.5 1.5z',
    discord: 'M20 12a8 8 0 11-16 0 8 8 0 0116 0z',
    telegram: 'M12 19l9 2-9-18-9 18 9-2zm0 0v-8',
    ntfy: 'M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9',
    gotify: 'M11 5.882V19.24l-7-3.5V2.382l7 3.5zm0 0L18 2.382v13.358l-7 3.5',
    webhook: 'M13 10V3L4 14h7v7l9-11h-7z'
};

async function loadNotificationChannels() {
    const panel = document.getElementById('notification-channels-panel');
    if (!panel) return;
    try {
        const [typesRes, channelsRes] = await Promise.all([
            authenticatedFetch('/api/notifications/types'),
            authenticatedFetch('/api/notifications/channels')
        ]);
        if (!typesRes.ok || !channelsRes.ok) throw new Error('HTTP error');
        const typesPayload = await typesRes.json();
        notificationChannelTypes = typesPayload.types || [];
        notificationAlertTypes = typesPayload.alert_types || [];
        notificationChannels = (await channelsRes.json()).channels || [];
        renderNotificationChannels();
    } catch (e) {
        console.error('Notification channels error:', e);
        panel.innerHTML = '<p class="ui-empty ui-text-fail">Could not load notification destinations.</p>';
    }
}

function _channelTypeLabel(typeId) {
    const t = notificationChannelTypes.find(t => t.id === typeId);
    return t ? t.label : typeId;
}

/** Which alert topics this channel receives, for the channel list. */
function _channelTopicsLabel(channel) {
    const selected = channel.alert_types || [];
    if (!selected.length || selected.length === notificationAlertTypes.length) {
        return 'Receives: all alerts';
    }
    const labels = selected.map(id => {
        const t = notificationAlertTypes.find(a => a.id === id);
        return escapeHtml(t ? t.label : id);
    });
    return 'Receives: ' + labels.join(', ');
}

function renderNotificationChannels() {
    const panel = document.getElementById('notification-channels-panel');
    if (!panel) return;

    const rows = notificationChannels.map(ch => {
        const statusDot = ch.last_status === 'success'
            ? '<i class="ui-mdot ui-mdot-ok" title="Last delivery succeeded"></i>'
            : ch.last_status === 'failed'
                ? '<i class="ui-mdot ui-mdot-fail" title="Last delivery failed"></i>'
                : '<i class="ui-mdot" title="Not used yet"></i>';
        const icon = CHANNEL_ICONS[ch.channel_type] || CHANNEL_ICONS.webhook;
        return `
        <div class="ui-channel${ch.enabled ? '' : ' is-off'}">
            <svg class="ui-channel-icon" width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${icon}"></path></svg>
            <div class="ui-q-who">
                <div>${statusDot} <b>${escapeHtml(ch.name)}</b> ${uiTag(_channelTypeLabel(ch.channel_type), '')} ${ch.enabled ? '' : '<span class="ui-muted">disabled</span>'}</div>
                <small>${_channelTopicsLabel(ch)}</small>
                ${ch.last_error ? `<small class="ui-text-fail" title="${escapeHtml(ch.last_error)}">${escapeHtml(ch.last_error)}</small>` : ''}
            </div>
            <div class="ui-row-actions">
                <button type="button" onclick="testNotificationChannel(${ch.id})" class="ui-btn ui-btn-sm">Test</button>
                <button type="button" onclick="editNotificationChannel(${ch.id})" class="ui-btn ui-btn-sm">Edit</button>
                <button type="button" onclick="deleteNotificationChannel(${ch.id})" class="ui-btn ui-btn-sm ui-btn-danger">Delete</button>
            </div>
        </div>`;
    }).join('');

    panel.innerHTML = `
        <div class="ui-list-head">
            <div>
                <h4 class="ui-md-h">Alert destinations</h4>
                <p class="ui-set-desc">Each destination receives the alert types you pick for it, in addition to email.</p>
            </div>
            <button type="button" onclick="editNotificationChannel(null)" class="ui-btn ui-btn-sm ui-btn-primary ui-head-actions">+ Add destination</button>
        </div>
        <div class="ui-channels">${rows || '<p class="ui-empty">No destinations yet. Alerts are sent by email only.</p>'}</div>`;
}

function editNotificationChannel(channelId) {
    const channel = channelId
        ? notificationChannels.find(c => c.id === channelId)
        : { name: '', channel_type: notificationChannelTypes[0]?.id || 'slack', config: {}, enabled: true };
    if (!channel) return;
    notificationEditing = JSON.parse(JSON.stringify(channel));
    renderNotificationChannelModal();
}

function _renderChannelFields() {
    const type = notificationChannelTypes.find(t => t.id === notificationEditing.channel_type);
    if (!type) return '';
    const cfg = notificationEditing.config || {};
    const fields = type.fields.map(f => {
        const value = cfg[f.key] !== undefined ? cfg[f.key] : (f.default || '');
        return `
            <label for="nc-field-${escapeHtml(f.key)}">
                <span class="ui-label">${escapeHtml(f.label)}${f.required ? ' <span class="ui-text-fail">*</span>' : ' <small class="ui-muted">(optional)</small>'}</span>
                <input type="text" id="nc-field-${escapeHtml(f.key)}" data-field="${escapeHtml(f.key)}"
                    value="${escapeHtml(value)}" placeholder="${escapeHtml(f.placeholder || '')}" class="nc-config-field ui-input">
            </label>`;
    }).join('');
    return `<p class="ui-set-desc">${escapeHtml(type.help)}</p>${fields}`;
}

function _renderAlertTypeChoices() {
    // No stored selection means "everything", so show all ticked
    const selected = notificationEditing.alert_types && notificationEditing.alert_types.length
        ? notificationEditing.alert_types
        : notificationAlertTypes.map(t => t.id);
    return notificationAlertTypes.map(t => `
        <label class="ui-check-label ui-check-top">
            <input type="checkbox" class="nc-alert-type ui-check" value="${escapeHtml(t.id)}" ${selected.indexOf(t.id) !== -1 ? 'checked' : ''}>
            <span><b>${escapeHtml(t.label)}</b><small class="ui-muted">${escapeHtml(t.description)}</small></span>
        </label>`).join('');
}

function renderNotificationChannelModal() {
    document.getElementById('notification-channel-modal')?.remove();
    const isNew = !notificationEditing.id;
    const typeOptions = notificationChannelTypes.map(t =>
        `<option value="${escapeHtml(t.id)}" ${t.id === notificationEditing.channel_type ? 'selected' : ''}>${escapeHtml(t.label)}</option>`
    ).join('');

    const modal = document.createElement('div');
    modal.id = 'notification-channel-modal';
    modal.className = 'ui-dialog-backdrop';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-label', isNew ? 'Add destination' : 'Edit destination');
    modal.innerHTML = `
        <div class="ui-dialog ui-dialog-fit ui-dialog-sm">
            <div class="ui-dialog-head">
                <h3>${isNew ? 'Add destination' : 'Edit destination'}</h3>
                <button type="button" onclick="closeNotificationChannelModal()" class="ui-icon-btn" title="Close" aria-label="Close">
                    <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <form id="nc-form" onsubmit="saveNotificationChannel(event)" class="ui-dialog-body ui-form">
                <label for="nc-name"><span class="ui-label">Name <span class="ui-text-fail">*</span></span>
                    <input type="text" id="nc-name" required value="${escapeHtml(notificationEditing.name || '')}" placeholder="e.g. Ops Slack" class="ui-input">
                    <small class="ui-muted">Only used to identify this destination in the list.</small>
                </label>
                <label for="nc-type"><span class="ui-label">Service</span>
                    <select id="nc-type" onchange="changeNotificationChannelType(this.value)" class="ui-select">${typeOptions}</select>
                </label>
                <div id="nc-fields" class="ui-form">${_renderChannelFields()}</div>

                <div class="ui-form ui-form-split">
                    <div><span class="ui-label">Which alerts to send here</span><p class="ui-set-desc">Leave all ticked to receive everything.</p></div>
                    ${_renderAlertTypeChoices()}
                </div>

                <label class="ui-check-label">
                    <input type="checkbox" id="nc-enabled" ${notificationEditing.enabled !== false ? 'checked' : ''} class="ui-check">
                    Enabled
                </label>
                <div class="ui-form-actions">
                    <button type="button" onclick="testNotificationChannelDraft()" class="ui-btn">Send test</button>
                    <span class="ui-toolbar-gap"></span>
                    <button type="button" onclick="closeNotificationChannelModal()" class="ui-btn">Cancel</button>
                    <button type="submit" class="ui-btn ui-btn-primary">Save</button>
                </div>
            </form>
        </div>`;
    document.body.appendChild(modal);
    document.getElementById('nc-name')?.focus();
}

function changeNotificationChannelType(newType) {
    _collectChannelForm();
    notificationEditing.channel_type = newType;
    notificationEditing.config = {};   // different service, different fields
    const fields = document.getElementById('nc-fields');
    if (fields) fields.innerHTML = _renderChannelFields();
}

function _collectChannelForm() {
    const cfg = {};
    document.querySelectorAll('.nc-config-field').forEach(input => {
        cfg[input.getAttribute('data-field')] = input.value.trim();
    });
    notificationEditing.name = document.getElementById('nc-name')?.value.trim() || '';
    notificationEditing.enabled = document.getElementById('nc-enabled')?.checked !== false;
    notificationEditing.config = cfg;
    notificationEditing.alert_types = Array.from(
        document.querySelectorAll('.nc-alert-type:checked')
    ).map(cb => cb.value);
    return notificationEditing;
}

function closeNotificationChannelModal() {
    document.getElementById('notification-channel-modal')?.remove();
    notificationEditing = null;
}

async function saveNotificationChannel(event) {
    event.preventDefault();
    const data = _collectChannelForm();
    const isNew = !data.id;
    try {
        const response = await authenticatedFetch(
            isNew ? '/api/notifications/channels' : `/api/notifications/channels/${data.id}`,
            {
                method: isNew ? 'POST' : 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: data.name,
                    channel_type: data.channel_type,
                    config: data.config,
                    alert_types: data.alert_types,
                    enabled: data.enabled
                })
            });
        if (!response.ok) {
            const detail = await response.json().catch(() => ({}));
            showToast(detail.detail || 'Could not save destination', 'error');
            return;
        }
        showToast(isNew ? 'Destination added' : 'Destination updated', 'success');
        closeNotificationChannelModal();
        loadNotificationChannels();
    } catch (e) {
        showToast('Could not save destination', 'error');
    }
}

async function deleteNotificationChannel(channelId) {
    const channel = notificationChannels.find(c => c.id === channelId);
    const confirmed = await showConfirmModal({
        title: 'Delete destination',
        message: `Delete "${channel ? channel.name : 'this destination'}"? Alerts will no longer be sent there.`,
        confirmText: 'Delete',
        isDangerous: true
    });
    if (!confirmed) return;
    try {
        const response = await authenticatedFetch(`/api/notifications/channels/${channelId}`, { method: 'DELETE' });
        if (!response.ok) { showToast('Could not delete destination', 'error'); return; }
        showToast('Destination deleted', 'success');
        loadNotificationChannels();
    } catch (e) {
        showToast('Could not delete destination', 'error');
    }
}

async function testNotificationChannel(channelId) {
    showConnectionTestModal('Notification Test', 'Sending test notification...');
    try {
        const response = await authenticatedFetch(`/api/notifications/channels/${channelId}/test`, { method: 'POST' });
        const result = await response.json();
        updateConnectionTestModal(result.success ? 'success' : 'error', result.logs || ['No logs available']);
        loadNotificationChannels();
    } catch (e) {
        updateConnectionTestModal('error', ['Failed to send test notification', `Error: ${e.message}`]);
    }
}

async function testNotificationChannelDraft() {
    const data = _collectChannelForm();
    showConnectionTestModal('Notification Test', 'Sending test notification...');
    try {
        const response = await authenticatedFetch('/api/notifications/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ channel_type: data.channel_type, config: data.config })
        });
        const result = await response.json();
        updateConnectionTestModal(result.success ? 'success' : 'error', result.logs || ['No logs available']);
    } catch (e) {
        updateConnectionTestModal('error', ['Failed to send test notification', `Error: ${e.message}`]);
    }
}
