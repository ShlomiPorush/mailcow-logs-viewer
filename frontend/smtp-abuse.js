// =============================================================================
// SMTP ABUSE PROTECTION - Security page panel
// =============================================================================
// Lists outbound activity per mailbox, shows which mailboxes this system has
// blocked, and provides the whitelist plus manual block/unblock controls.
//
// Classic script sharing the global scope; loaded after utils.js and app.js.
// =============================================================================

let smtpAbuseStatus = null;
let smtpAbuseWhitelist = [];
let smtpAbuseWhitelistEditing = false;
let smtpAbusePage = 1;
const SMTP_ABUSE_PAGE_SIZE = 5;

async function loadSmtpAbusePanel() {
    const panel = document.getElementById('smtp-abuse-panel');
    if (!panel) return;

    try {
        const [statusResponse, whitelistResponse] = await Promise.all([
            authenticatedFetch('/api/smtp-abuse/status?limit=200'),
            authenticatedFetch('/api/smtp-abuse/whitelist')
        ]);
        if (!statusResponse.ok || !whitelistResponse.ok) throw new Error('HTTP error');
        smtpAbuseStatus = await statusResponse.json();
        smtpAbuseWhitelist = await whitelistResponse.json();
        renderSmtpAbusePanel();
    } catch (error) {
        console.error('SMTP abuse panel error:', error);
        panel.innerHTML = '<p class="text-sm text-red-600 dark:text-red-400">Could not load abuse protection.</p>';
    }
}

function renderSmtpAbusePanel() {
    const panel = document.getElementById('smtp-abuse-panel');
    if (!panel || !smtpAbuseStatus) return;

    const status = smtpAbuseStatus;
    const locked = !status.enabled || !status.rw_key_configured;
    const filter = (document.getElementById('smtp-abuse-whitelist-filter')?.value || '').toLowerCase();
    const filteredWhitelist = smtpAbuseWhitelist.filter(item => item.email.toLowerCase().includes(filter));

    const allRows = status.mailboxes || [];
    const blockedRows = allRows.filter(item => item.blocked_by_protection);
    const activityRows = allRows.filter(item => !item.blocked_by_protection);
    const pageCount = Math.max(1, Math.ceil(activityRows.length / SMTP_ABUSE_PAGE_SIZE));
    smtpAbusePage = Math.min(Math.max(1, smtpAbusePage), pageCount);
    const pageRows = activityRows.slice((smtpAbusePage - 1) * SMTP_ABUSE_PAGE_SIZE, smtpAbusePage * SMTP_ABUSE_PAGE_SIZE);

    const mailboxRow = item => `
        <tr class="border-t border-gray-200 dark:border-gray-700">
            <td class="px-4 py-2.5 font-mono text-sm text-gray-900 dark:text-white break-all">${escapeHtml(item.email)}</td>
            <td class="px-4 py-2.5 text-sm text-gray-700 dark:text-gray-300">${item.message_count}</td>
            <td class="px-4 py-2.5 text-sm">${
                item.blocked_by_protection
                    ? '<span class="text-red-600 dark:text-red-400 font-medium">SMTP disabled</span>'
                    : item.whitelisted
                        ? '<span class="text-green-600 dark:text-green-400">Whitelisted</span>'
                        : item.over_threshold
                            ? '<span class="text-amber-600 dark:text-amber-400 font-medium">Over limit</span>'
                            : '<span class="text-gray-500 dark:text-gray-400">Normal</span>'
            }</td>
            <td class="px-4 py-2.5 text-right whitespace-nowrap">${
                locked ? '' : (item.blocked_by_protection || item.smtp_access === false
                    ? `<button type="button" onclick="smtpAbuseAction('${escapeJsArg(item.email)}', 'unblock')" class="px-2 py-1 text-xs font-medium rounded bg-green-600 hover:bg-green-700 text-white">Re-enable SMTP</button>`
                    : `<button type="button" onclick="smtpAbuseAction('${escapeJsArg(item.email)}', 'block')" class="px-2 py-1 text-xs font-medium rounded bg-red-600 hover:bg-red-700 text-white">Disable SMTP</button>`)
            }</td>
        </tr>`;

    const tableHead = `
        <thead><tr class="text-left text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">
            <th class="px-4 py-2">Mailbox</th><th class="px-4 py-2">Sent (${status.window_minutes}m)</th>
            <th class="px-4 py-2">Status</th><th class="px-4 py-2"></th>
        </tr></thead>`;

    panel.innerHTML = `
        <div class="space-y-6">
            <div class="flex flex-wrap items-start justify-between gap-3">
                <p class="text-sm text-gray-600 dark:text-gray-300 flex-1 min-w-64">
                    ${status.enabled
                        ? `Mailboxes sending more than <strong>${status.threshold}</strong> messages in <strong>${status.window_minutes}</strong> minutes have SMTP disabled automatically. Receiving (IMAP) is never affected.`
                        : 'Automatic protection is off. Enable it under Settings → SMTP Abuse.'}
                </p>
                <button type="button" onclick="loadSmtpAbusePanel()" class="px-3 py-1.5 text-xs font-medium rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700">Refresh</button>
            </div>

            ${blockedRows.length ? `
            <div>
                <h4 class="font-medium text-gray-900 dark:text-white mb-2">Blocked by abuse protection (${blockedRows.length})</h4>
                <div class="overflow-x-auto rounded border border-red-200 dark:border-red-800">
                    <table class="w-full">${tableHead}<tbody>${blockedRows.map(mailboxRow).join('')}</tbody></table>
                </div>
                ${status.unblock_grace_minutes > 0 ? `<p class="text-xs text-gray-500 dark:text-gray-400 mt-1">After re-enabling, automatic blocking is paused for ${status.unblock_grace_minutes} minutes so the mailbox is not immediately re-blocked.</p>` : ''}
            </div>` : ''}

            <div>
                <h4 class="font-medium text-gray-900 dark:text-white mb-2">Outbound activity</h4>
                <div class="overflow-x-auto rounded border border-gray-200 dark:border-gray-700">
                    <table class="w-full">${tableHead}<tbody>${
                        pageRows.map(mailboxRow).join('') ||
                        `<tr><td colspan="4" class="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">No outbound activity in the last ${status.window_minutes} minutes</td></tr>`
                    }</tbody></table>
                </div>
                ${pageCount > 1 ? `
                <div class="flex justify-center items-center gap-3 mt-3">
                    <button type="button" onclick="smtpAbusePage--; renderSmtpAbusePanel()" ${smtpAbusePage === 1 ? 'disabled' : ''} class="px-3 py-1.5 text-sm rounded bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 disabled:opacity-50">Previous</button>
                    <span class="text-sm text-gray-600 dark:text-gray-400">Page ${smtpAbusePage} of ${pageCount}</span>
                    <button type="button" onclick="smtpAbusePage++; renderSmtpAbusePanel()" ${smtpAbusePage === pageCount ? 'disabled' : ''} class="px-3 py-1.5 text-sm rounded bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 disabled:opacity-50">Next</button>
                </div>` : ''}
            </div>

            <div class="border-t border-gray-200 dark:border-gray-700 pt-4">
                <form onsubmit="saveSmtpAbuseWhitelist(event)" class="space-y-2">
                    <div class="flex flex-wrap items-center justify-between gap-2">
                        <div>
                            <label for="smtp-abuse-whitelist-textarea" class="font-medium text-gray-900 dark:text-white block">Whitelist</label>
                            <p class="text-xs text-gray-500 dark:text-gray-400">One address per line. Whitelisted mailboxes are never blocked automatically.</p>
                        </div>
                        ${(!locked && !smtpAbuseWhitelistEditing) ? '<button type="button" onclick="editSmtpAbuseWhitelist()" class="px-3 py-1.5 text-sm font-medium rounded bg-gray-200 dark:bg-gray-600 hover:bg-gray-300 dark:hover:bg-gray-500 text-gray-700 dark:text-gray-200">Edit whitelist</button>' : ''}
                    </div>
                    <textarea id="smtp-abuse-whitelist-textarea" rows="4" placeholder="newsletter@example.com&#10;monitoring@example.com" ${smtpAbuseWhitelistEditing ? '' : 'disabled'} class="w-full px-2 py-1.5 text-sm font-mono rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-200 focus:ring-2 focus:ring-blue-500 resize-y disabled:opacity-60">${escapeHtml(smtpAbuseWhitelist.map(i => i.email).join('\n'))}</textarea>
                    ${smtpAbuseWhitelistEditing ? '<div class="flex justify-end gap-2"><button type="button" onclick="cancelSmtpAbuseWhitelistEdit()" class="px-3 py-2 rounded text-sm text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700">Cancel</button><button type="submit" class="px-3 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm">Save whitelist</button></div>' : ''}
                </form>

                ${smtpAbuseWhitelist.length ? `
                <div class="mt-3">
                    <div class="flex flex-wrap items-center justify-between gap-2 mb-1">
                        <span class="text-sm text-gray-600 dark:text-gray-300">${smtpAbuseWhitelist.length} whitelisted mailbox(es)</span>
                        <input id="smtp-abuse-whitelist-filter" type="search" value="${escapeHtml(filter)}" oninput="renderSmtpAbusePanel()" placeholder="Filter" class="rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white px-2 py-1 text-sm">
                    </div>
                    <ul class="divide-y divide-gray-200 dark:divide-gray-700">${
                        filteredWhitelist.map(item => `
                        <li class="flex items-center justify-between gap-3 py-1.5">
                            <span class="font-mono text-sm text-gray-900 dark:text-white break-all">${escapeHtml(item.email)}</span>
                            ${locked ? '' : `<button type="button" onclick="removeSmtpAbuseWhitelist('${escapeJsArg(item.email)}')" class="text-xs text-red-600 dark:text-red-400 hover:underline flex-shrink-0">Remove</button>`}
                        </li>`).join('') || '<li class="py-1.5 text-sm text-gray-500 dark:text-gray-400">No matching entries</li>'
                    }</ul>
                </div>` : ''}
            </div>
        </div>`;

    if (locked) {
        const reasons = [];
        if (!status.enabled) reasons.push('SMTP abuse protection is disabled');
        if (!status.rw_key_configured) reasons.push('a Read-Write mailcow API key is not configured');
        // The locked area explains the missing controls and leads to Settings;
        // the activity below stays readable
        panel.insertAdjacentHTML('afterbegin', `<div class="ui-list-note">${uiLocked('Abuse protection controls are locked', `${escapeHtml(reasons.join(' and '))}.`)}</div>`);
    }
}

async function smtpAbuseAction(email, action) {
    const verb = action === 'block' ? 'Disable SMTP for' : 'Re-enable SMTP for';
    const confirmed = await showConfirmModal({
        title: action === 'block' ? 'Disable SMTP' : 'Re-enable SMTP',
        message: `${verb} ${email}?` + (action === 'block'
            ? ' The mailbox can still receive mail, and its app passwords will be revoked.'
            : ''),
        confirmText: action === 'block' ? 'Disable SMTP' : 'Re-enable',
        isDangerous: action === 'block'
    });
    if (!confirmed) return;

    try {
        const response = await authenticatedFetch(
            `/api/smtp-abuse/mailboxes/${encodeURIComponent(email)}/${action}`, { method: 'POST' });
        if (!response.ok) {
            const detail = await response.json().catch(() => ({}));
            showToast(detail.detail || `Could not ${action} SMTP`, 'error');
            return;
        }
        showToast(action === 'block' ? 'SMTP disabled' : 'SMTP re-enabled', 'success');
        loadSmtpAbusePanel();
    } catch (e) {
        showToast(`Could not ${action} SMTP`, 'error');
    }
}

function editSmtpAbuseWhitelist() {
    smtpAbuseWhitelistEditing = true;
    renderSmtpAbusePanel();
    document.getElementById('smtp-abuse-whitelist-textarea')?.focus();
}

function cancelSmtpAbuseWhitelistEdit() {
    smtpAbuseWhitelistEditing = false;
    renderSmtpAbusePanel();
}

async function saveSmtpAbuseWhitelist(event) {
    event.preventDefault();
    const emails = (document.getElementById('smtp-abuse-whitelist-textarea')?.value || '')
        .split(/\r?\n/).map(e => e.trim()).filter(Boolean);
    try {
        const response = await authenticatedFetch('/api/smtp-abuse/whitelist', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ emails })
        });
        if (!response.ok) {
            const detail = await response.json().catch(() => ({}));
            showToast(detail.detail || 'Could not save whitelist', 'error');
            return;
        }
        smtpAbuseWhitelistEditing = false;
        showToast('Whitelist saved', 'success');
        loadSmtpAbusePanel();
    } catch (e) {
        showToast('Could not save whitelist', 'error');
    }
}

async function removeSmtpAbuseWhitelist(email) {
    try {
        const response = await authenticatedFetch(
            `/api/smtp-abuse/whitelist/${encodeURIComponent(email)}`, { method: 'DELETE' });
        if (!response.ok) { showToast('Could not remove whitelist entry', 'error'); return; }
        showToast('Whitelist entry removed', 'success');
        loadSmtpAbusePanel();
    } catch (e) {
        showToast('Could not remove whitelist entry', 'error');
    }
}
