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
        panel.innerHTML = '<p class="ui-empty ui-text-fail">Could not load abuse protection.</p>';
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
        <tr>
            <td class="ui-mono ui-dtable-wrap">${escapeHtml(item.email)}</td>
            <td>${item.message_count}</td>
            <td>${
                item.blocked_by_protection
                    ? uiTag('SMTP disabled', 'fail')
                    : item.whitelisted
                        ? uiTag('Whitelisted', 'ok')
                        : item.over_threshold
                            ? uiTag('Over limit', 'warn')
                            : '<span class="ui-muted">Normal</span>'
            }</td>
            <td class="ui-td-end ui-nowrap">${
                locked ? '' : (item.blocked_by_protection || item.smtp_access === false
                    ? `<button type="button" onclick="smtpAbuseAction('${escapeJsArg(item.email)}', 'unblock')" class="ui-btn ui-btn-sm ui-btn-primary">Re-enable SMTP</button>`
                    : `<button type="button" onclick="smtpAbuseAction('${escapeJsArg(item.email)}', 'block')" class="ui-btn ui-btn-sm ui-btn-danger">Disable SMTP</button>`)
            }</td>
        </tr>`;

    const tableHead = `
        <thead><tr>
            <th>Mailbox</th><th>Sent (${status.window_minutes}m)</th>
            <th>Status</th><th></th>
        </tr></thead>`;

    panel.innerHTML = `
        <div class="ui-sa">
            <div class="ui-list-head">
                <p class="ui-set-desc ui-sa-intro">
                    ${status.enabled
                        ? `Mailboxes sending more than <strong>${status.threshold}</strong> messages in <strong>${status.window_minutes}</strong> minutes have SMTP disabled automatically. Receiving (IMAP) is never affected.`
                        : 'Automatic protection is off. Enable it under Settings → SMTP Abuse.'}
                </p>
                <button type="button" onclick="loadSmtpAbusePanel()" class="ui-btn ui-btn-sm ui-head-actions">Refresh</button>
            </div>

            ${blockedRows.length ? `
            <div class="ui-sa-block">
                <h4 class="ui-md-h ui-text-fail">Blocked by abuse protection (${blockedRows.length})</h4>
                <div class="ui-dtable-scroll ui-sa-table is-blocked">
                    <table class="ui-dtable">${tableHead}<tbody>${blockedRows.map(mailboxRow).join('')}</tbody></table>
                </div>
                ${status.unblock_grace_minutes > 0 ? `<p class="ui-set-desc">After re-enabling, automatic blocking is paused for ${status.unblock_grace_minutes} minutes so the mailbox is not immediately re-blocked.</p>` : ''}
            </div>` : ''}

            <div class="ui-sa-block">
                <h4 class="ui-md-h">Outbound activity</h4>
                <div class="ui-dtable-scroll ui-sa-table">
                    <table class="ui-dtable">${tableHead}<tbody>${
                        pageRows.map(mailboxRow).join('') ||
                        `<tr><td colspan="4" class="ui-empty">No outbound activity in the last ${status.window_minutes} minutes</td></tr>`
                    }</tbody></table>
                </div>
                ${pageCount > 1 ? `
                <nav class="ui-pager" aria-label="Activity pages">
                    <button type="button" onclick="smtpAbusePage--; renderSmtpAbusePanel()" ${smtpAbusePage === 1 ? 'disabled' : ''} class="ui-btn ui-btn-sm">Previous</button>
                    <span class="ui-muted">Page ${smtpAbusePage} of ${pageCount}</span>
                    <button type="button" onclick="smtpAbusePage++; renderSmtpAbusePanel()" ${smtpAbusePage === pageCount ? 'disabled' : ''} class="ui-btn ui-btn-sm">Next</button>
                </nav>` : ''}
            </div>

            <div class="ui-sa-block ui-sa-whitelist">
                <form onsubmit="saveSmtpAbuseWhitelist(event)" class="ui-form">
                    <div class="ui-list-head">
                        <div>
                            <label for="smtp-abuse-whitelist-textarea" class="ui-md-h">Whitelist</label>
                            <p class="ui-set-desc">One address per line. Whitelisted mailboxes are never blocked automatically.</p>
                        </div>
                        ${(!locked && !smtpAbuseWhitelistEditing) ? '<button type="button" onclick="editSmtpAbuseWhitelist()" class="ui-btn ui-btn-sm ui-head-actions">Edit whitelist</button>' : ''}
                    </div>
                    <textarea id="smtp-abuse-whitelist-textarea" rows="4" placeholder="newsletter@example.com&#10;monitoring@example.com" ${smtpAbuseWhitelistEditing ? '' : 'disabled'} class="ui-textarea ui-mono">${escapeHtml(smtpAbuseWhitelist.map(i => i.email).join('\n'))}</textarea>
                    ${smtpAbuseWhitelistEditing ? '<div class="ui-form-actions"><span class="ui-toolbar-gap"></span><button type="button" onclick="cancelSmtpAbuseWhitelistEdit()" class="ui-btn">Cancel</button><button type="submit" class="ui-btn ui-btn-primary">Save whitelist</button></div>' : ''}
                </form>

                ${smtpAbuseWhitelist.length ? `
                <div class="ui-sa-list">
                    <div class="ui-list-head">
                        <span class="ui-muted">${smtpAbuseWhitelist.length} whitelisted mailbox(es)</span>
                        <input id="smtp-abuse-whitelist-filter" type="search" value="${escapeHtml(filter)}" oninput="renderSmtpAbusePanel()" placeholder="Filter" aria-label="Filter whitelist" class="ui-input ui-rl-search ui-head-actions">
                    </div>
                    <ul class="ui-sa-items">${
                        filteredWhitelist.map(item => `
                        <li>
                            <span class="ui-mono ui-dtable-wrap">${escapeHtml(item.email)}</span>
                            ${locked ? '' : `<button type="button" onclick="removeSmtpAbuseWhitelist('${escapeJsArg(item.email)}')" class="ui-btn ui-btn-sm ui-btn-danger">Remove</button>`}
                        </li>`).join('') || '<li class="ui-muted">No matching entries</li>'
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
