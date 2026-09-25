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
        panel.innerHTML = '<p class="text-sm text-red-600 dark:text-red-400">Could not load notification destinations.</p>';
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

    const cards = notificationChannels.map(ch => {
        const statusDot = ch.last_status === 'success'
            ? '<span class="w-2 h-2 rounded-full bg-green-500" title="Last delivery succeeded"></span>'
            : ch.last_status === 'failed'
                ? '<span class="w-2 h-2 rounded-full bg-red-500" title="Last delivery failed"></span>'
                : '<span class="w-2 h-2 rounded-full bg-gray-300 dark:bg-gray-600" title="Not used yet"></span>';
        const icon = CHANNEL_ICONS[ch.channel_type] || CHANNEL_ICONS.webhook;
        return `
        <div class="flex items-center gap-3 p-3 rounded-lg border ${ch.enabled ? 'border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800' : 'border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/40 opacity-70'}">
            <svg class="w-5 h-5 flex-shrink-0 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${icon}"></path></svg>
            <div class="min-w-0 flex-1">
                <div class="flex items-center gap-2 flex-wrap">
                    ${statusDot}
                    <span class="text-sm font-medium text-gray-900 dark:text-white truncate">${escapeHtml(ch.name)}</span>
                    <span class="text-xs px-1.5 py-0.5 rounded bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300">${escapeHtml(_channelTypeLabel(ch.channel_type))}</span>
                    ${ch.enabled ? '' : '<span class="text-xs text-gray-500 dark:text-gray-400">disabled</span>'}
                </div>
                <p class="text-xs text-gray-500 dark:text-gray-400 mt-0.5">${_channelTopicsLabel(ch)}</p>
                ${ch.last_error ? `<p class="text-xs text-red-600 dark:text-red-400 mt-0.5 truncate" title="${escapeHtml(ch.last_error)}">${escapeHtml(ch.last_error)}</p>` : ''}
            </div>
            <div class="flex items-center gap-1 flex-shrink-0">
                <button type="button" onclick="testNotificationChannel(${ch.id})" class="px-2 py-1 text-xs rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700">Test</button>
                <button type="button" onclick="editNotificationChannel(${ch.id})" class="px-2 py-1 text-xs rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700">Edit</button>
                <button type="button" onclick="deleteNotificationChannel(${ch.id})" class="px-2 py-1 text-xs rounded text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20">Delete</button>
            </div>
        </div>`;
    }).join('');

    panel.innerHTML = `
        <div class="p-4 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
            <div class="flex items-center justify-between gap-3 mb-3 flex-wrap">
                <div>
                    <h4 class="text-sm font-semibold text-gray-700 dark:text-gray-300">Alert destinations</h4>
                    <p class="text-xs text-gray-500 dark:text-gray-400">Each destination receives the alert types you pick for it, in addition to email.</p>
                </div>
                <button type="button" onclick="editNotificationChannel(null)" class="px-3 py-1.5 bg-blue-500 hover:bg-blue-600 text-white rounded text-xs font-medium flex items-center gap-1.5">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
                    Add destination
                </button>
            </div>
            <div class="space-y-2">${cards || '<p class="text-sm text-gray-500 dark:text-gray-400 py-2">No destinations yet. Alerts are sent by email only.</p>'}</div>
        </div>`;
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
            <div>
                <label for="nc-field-${escapeHtml(f.key)}" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    ${escapeHtml(f.label)}${f.required ? ' <span class="text-red-500">*</span>' : ' <span class="text-xs font-normal text-gray-400">(optional)</span>'}
                </label>
                <input type="text" id="nc-field-${escapeHtml(f.key)}" data-field="${escapeHtml(f.key)}"
                    value="${escapeHtml(value)}" placeholder="${escapeHtml(f.placeholder || '')}"
                    class="nc-config-field w-full rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white px-3 py-2 text-sm">
            </div>`;
    }).join('');
    return `<p class="text-xs text-gray-500 dark:text-gray-400">${escapeHtml(type.help)}</p>${fields}`;
}

function _renderAlertTypeChoices() {
    // No stored selection means "everything", so show all ticked
    const selected = notificationEditing.alert_types && notificationEditing.alert_types.length
        ? notificationEditing.alert_types
        : notificationAlertTypes.map(t => t.id);
    return notificationAlertTypes.map(t => `
        <label class="flex items-start gap-2 cursor-pointer">
            <input type="checkbox" class="nc-alert-type mt-0.5 rounded border-gray-300 dark:border-gray-600"
                value="${escapeHtml(t.id)}" ${selected.indexOf(t.id) !== -1 ? 'checked' : ''}>
            <span>
                <span class="text-sm text-gray-800 dark:text-gray-200">${escapeHtml(t.label)}</span>
                <span class="block text-xs text-gray-500 dark:text-gray-400">${escapeHtml(t.description)}</span>
            </span>
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
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4';
    modal.innerHTML = `
        <div class="ui-panel shadow-xl w-full max-w-md max-h-[90vh] overflow-y-auto">
            <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white">${isNew ? 'Add destination' : 'Edit destination'}</h3>
                <button type="button" onclick="closeNotificationChannelModal()" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 text-xl leading-none">&times;</button>
            </div>
            <form id="nc-form" onsubmit="saveNotificationChannel(event)" class="p-5 space-y-4">
                <div>
                    <label for="nc-name" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name <span class="text-red-500">*</span></label>
                    <input type="text" id="nc-name" required value="${escapeHtml(notificationEditing.name || '')}" placeholder="e.g. Ops Slack"
                        class="w-full rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white px-3 py-2 text-sm">
                    <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">Only used to identify this destination in the list.</p>
                </div>
                <div>
                    <label for="nc-type" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Service</label>
                    <select id="nc-type" onchange="changeNotificationChannelType(this.value)"
                        class="w-full rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white px-3 py-2 text-sm">${typeOptions}</select>
                </div>
                <div id="nc-fields" class="space-y-3">${_renderChannelFields()}</div>

                <div class="border-t border-gray-200 dark:border-gray-700 pt-4">
                    <p class="text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Which alerts to send here</p>
                    <p class="text-xs text-gray-500 dark:text-gray-400 mb-2">Leave all ticked to receive everything.</p>
                    <div class="space-y-2">${_renderAlertTypeChoices()}</div>
                </div>

                <label class="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                    <input type="checkbox" id="nc-enabled" ${notificationEditing.enabled !== false ? 'checked' : ''} class="rounded border-gray-300 dark:border-gray-600">
                    Enabled
                </label>
                <div class="flex justify-between items-center gap-2 pt-2">
                    <button type="button" onclick="testNotificationChannelDraft()" class="px-3 py-2 text-sm rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700">Send test</button>
                    <div class="flex gap-2">
                        <button type="button" onclick="closeNotificationChannelModal()" class="px-3 py-2 text-sm rounded text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700">Cancel</button>
                        <button type="submit" class="px-4 py-2 text-sm rounded bg-blue-600 hover:bg-blue-700 text-white font-medium">Save</button>
                    </div>
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
