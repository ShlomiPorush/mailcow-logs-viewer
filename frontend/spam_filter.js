/**
 * Spam Filter module
 * Handles Rspamd Maps editor and Suppression list management
 */

// =============================================================================
// STATE
// =============================================================================
let spamFilterSubTab = 'suppressions'; // Fix #3: Suppressions first
let rspamdMapsData = null;
let rspamdMapsConfigured = false;
let suppressionPage = 1;

// =============================================================================
// TAB SWITCHING
// =============================================================================

function loadSpamFilter() {
    console.log('Loading Spam Filter...');
    // Fix #2: Always ensure the correct sub-tab is visible before loading data
    spamFilterSwitchSubTab(spamFilterSubTab);
}

function spamFilterSwitchSubTab(tab) {
    spamFilterSubTab = tab;
    
    // Update sub-tab buttons
    document.querySelectorAll('[id^="spam-subtab-"]').forEach(btn => {
        btn.classList.remove('active');
    });
    const activeBtn = document.getElementById(`spam-subtab-${tab}`);
    if (activeBtn) activeBtn.classList.add('active');
    
    // Toggle content
    const mapsContent = document.getElementById('spam-filter-maps-content');
    const suppressionsContent = document.getElementById('spam-filter-suppressions-content');
    
    if (tab === 'maps') {
        if (mapsContent) mapsContent.classList.remove('hidden');
        if (suppressionsContent) suppressionsContent.classList.add('hidden');
        loadRspamdMaps();
    } else {
        if (mapsContent) mapsContent.classList.add('hidden');
        if (suppressionsContent) suppressionsContent.classList.remove('hidden');
        loadSuppressions();
        loadSuppressionStats();
    }
}

/**
 * Smart refresh for Spam Filter page (called by auto-refresh timer).
 * Only refreshes the suppressions sub-tab silently;
 * does NOT refresh maps editor (would discard user edits).
 */
async function smartRefreshSpamFilter() {
    // Only auto-refresh the suppressions tab, not the maps editor
    if (spamFilterSubTab !== 'suppressions') return;
    
    // Don't refresh if a modal is open (add/edit suppression)
    const modal = document.getElementById('add-suppression-modal');
    if (modal && !modal.classList.contains('hidden')) return;
    const editModal = document.getElementById('edit-suppression-modal');
    if (editModal && !editModal.classList.contains('hidden')) return;
    
    await loadSuppressions();
    await loadSuppressionStats();
}

// =============================================================================
// RSPAMD MAPS
// =============================================================================

async function loadRspamdMaps() {
    const container = document.getElementById('rspamd-maps-list');
    
    try {
        const response = await authenticatedFetch('/api/rspamd/maps');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const data = await response.json();
        rspamdMapsConfigured = data.configured;
        rspamdMapsData = data.maps || [];
        
        if (!data.configured) {
            container.innerHTML = uiLocked('Rspamd Not Configured',
                escapeHtml(data.message || 'Set RSPAMD_PASSWORD in Settings to enable Rspamd map management.'),
                `<button type="button" class="ui-btn ui-btn-sm" onclick="navigateTo('settings')">Go to Settings</button>`);
            return;
        }
        
        if (data.error) {
            container.innerHTML = `<p class="ui-empty ui-panel ui-text-fail">${escapeHtml(data.error)}</p>`;
            return;
        }
        
        renderRspamdMapsList(data.maps, data.rw_key_configured);
        
    } catch (error) {
        console.error('Failed to load Rspamd maps:', error);
        container.innerHTML = `<p class="ui-empty ui-text-fail">Failed to load maps: ${escapeHtml(error.message)}</p>`;
    }
}

function renderRspamdMapsList(maps, rwKeyConfigured) {
    const container = document.getElementById('rspamd-maps-list');

    // Group maps by category
    const categories = {
        sender: { label: 'Sender Rules', maps: [] },
        recipient: { label: 'Recipient Rules', maps: [] },
        content: { label: 'Content Rules', maps: [] },
        system: { label: 'System', maps: [] }
    };

    maps.forEach(m => {
        const cat = categories[m.category] || categories.system;
        cat.maps.push(m);
    });

    let html = '';

    for (const cat of Object.values(categories)) {
        if (cat.maps.length === 0) continue;

        html += `
            <section class="ui-sec-block">
                <div class="ui-list-head"><h2 class="ui-h2">${cat.label}</h2> <span class="ui-count">${cat.maps.length}</span></div>
                <div class="ui-table ui-stack ui-map-table">
                    ${cat.maps.map(m => {
                        // Use our metadata description, not the rspamd technical description
                        const displayDesc = _getMapMetaDescription(m.filename) || m.description || '';
                        return `
                        <div class="ui-tr" onclick="openMapEditor('${escapeJsArg(m.filename)}')">
                            <div class="ui-td ui-q-who">
                                <div>${escapeHtml(m.name)} ${m.managed_by_suppression ? uiTag('Auto-managed', 'info') : ''}</div>
                                <small title="${escapeHtml(displayDesc)}">${escapeHtml(displayDesc)}</small>
                            </div>
                            <span class="ui-td ui-mono ui-muted">${escapeHtml(m.filename)}</span>
                            <span class="ui-td">${m.loaded !== undefined
                                ? `<i class="ui-mdot ${m.loaded ? 'ui-mdot-ok' : ''}"></i> ${m.loaded ? 'Loaded' : 'Not loaded'}`
                                : ''}</span>
                            <span class="ui-td ui-td-end ui-muted" aria-hidden="true">›</span>
                        </div>
                    `}).join('')}
                </div>
            </section>
        `;
    }

    if (!rwKeyConfigured) {
        html = `<div class="ui-list-note ui-flush">${uiLocked('Read-Only Mode', '<code>MAILCOW_API_KEY_RW</code> is not configured. You can view maps but cannot save changes.')}</div>` + html;
    }

    container.innerHTML = html;
}

async function openMapEditor(filename) {
    const container = document.getElementById('rspamd-maps-list');

    container.innerHTML = '<div class="ui-loading"><div class="loading"></div><p>Loading map content...</p></div>';

    try {
        const response = await authenticatedFetch(`/api/rspamd/maps/${filename}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data = await response.json();
        const meta = data.metadata || {};

        container.innerHTML = `
            <div class="ui-list-head">
                <button onclick="loadRspamdMaps()" class="ui-btn ui-btn-sm">← Back to Maps List</button>
            </div>

            <section class="ui-panel">
                <div class="ui-panel-head ui-rl-head">
                    <div>
                        <h3 class="ui-h2">${escapeHtml(meta.name || filename)}</h3>
                        <p class="ui-muted">${escapeHtml(meta.description || '')}</p>
                        <p class="ui-mono ui-muted">${escapeHtml(filename)}</p>
                    </div>
                    <div class="ui-rl-tools">
                        <span id="map-entry-count" class="ui-muted">${data.entry_count} entries</span>
                        <span id="map-validation-status"></span>
                    </div>
                </div>
                <div class="ui-map-body">
                    ${meta.supports_regex ? `
                        <div>
                            <button onclick="toggleRegexWizard()" id="regex-wizard-toggle" class="ui-btn ui-btn-sm">+ Regex Wizard</button>
                            <div id="regex-wizard-panel" class="hidden ui-wizard">
                                <div class="ui-list-head">
                                    <h4 class="ui-md-h">Regex Pattern Generator</h4>
                                    <button onclick="toggleRegexWizard()" class="ui-icon-btn ui-head-actions" title="Close" aria-label="Close">
                                        <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                                    </button>
                                </div>
                                <div class="ui-wizard-row">
                                    <label class="ui-wizard-type"><span class="ui-label">Type</span>
                                        <select id="regex-wizard-type" onchange="updateRegexWizardPreview()" class="ui-select">
                                            <option value="email">Exact Email</option>
                                            <option value="domain">Domain</option>
                                            <option value="tld">TLD</option>
                                            <option value="keyword">Keyword</option>
                                        </select>
                                    </label>
                                    <label class="ui-wizard-value"><span id="regex-wizard-input-label" class="ui-label">Email address</span>
                                        <input type="text" id="regex-wizard-input" oninput="updateRegexWizardPreview()" placeholder="user@example.com" class="ui-input" />
                                    </label>
                                    <button onclick="regexWizardAdd()" id="regex-wizard-add-btn" class="ui-btn ui-btn-primary" disabled>Add</button>
                                </div>
                                <div id="regex-wizard-preview" class="hidden">
                                    <span class="ui-label">Generated pattern</span>
                                    <code id="regex-wizard-result" class="ui-wizard-result"></code>
                                    <p id="regex-wizard-explain" class="ui-muted"></p>
                                </div>
                            </div>
                        </div>
                    ` : ''}
                    <textarea id="map-editor-content" class="ui-textarea ui-map-editor"
                        placeholder="Enter entries, one per line..."
                        oninput="onMapContentChange('${escapeJsArg(filename)}')">${escapeHtml(data.content || '')}</textarea>
                    <div id="map-validation-errors" class="hidden ui-map-errors"></div>
                    <div class="ui-map-foot">
                        <p class="ui-muted">Lines starting with # are comments. Empty lines are ignored.</p>
                        <div class="ui-row-actions">
                            <button onclick="validateMapContent('${escapeJsArg(filename)}')" class="ui-btn">Validate</button>
                            <button onclick="saveMapContent('${escapeJsArg(filename)}')" id="map-save-btn" class="ui-btn ui-btn-primary">Save Changes</button>
                        </div>
                    </div>
                </div>
            </section>
        `;

    } catch (error) {
        console.error('Failed to load map content:', error);
        container.innerHTML = `
            <div class="ui-list-head">
                <button onclick="loadRspamdMaps()" class="ui-btn ui-btn-sm">← Back to Maps List</button>
            </div>
            <p class="ui-empty ui-text-fail">Failed to load map: ${escapeHtml(error.message)}</p>
        `;
    }
}

function onMapContentChange(filename) {
    const statusEl = document.getElementById('map-validation-status');
    if (statusEl) {
        statusEl.innerHTML = uiTag('Modified', 'warn');
    }
}

async function validateMapContent(filename) {
    const content = document.getElementById('map-editor-content').value;
    const statusEl = document.getElementById('map-validation-status');
    const errorsEl = document.getElementById('map-validation-errors');

    try {
        const response = await authenticatedFetch('/api/rspamd/validate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content, filename })
        });

        const data = await response.json();

        document.getElementById('map-entry-count').textContent = `${data.entry_count} entries`;

        const line = (entry, tone) => `
            <div class="ui-map-error ui-text-${tone}">
                <span class="ui-mono ui-muted">Line ${entry.line}:</span>
                <span>${escapeHtml(entry.error)} - <code>${escapeHtml(entry.content)}</code></span>
            </div>
        `;
        const warnings = data.warnings || [];
        const warningHtml = warnings.map(w => line(w, 'warn')).join('');

        if (data.valid) {
            statusEl.innerHTML = warnings.length
                ? uiTag(`✓ Valid, ${warnings.length} warning(s)`, 'warn')
                : uiTag('✓ Valid', 'ok');
            errorsEl.classList.toggle('hidden', warnings.length === 0);
            errorsEl.innerHTML = warningHtml;
        } else {
            statusEl.innerHTML = uiTag(`✗ ${data.errors.length} error(s)`, 'fail');
            errorsEl.classList.remove('hidden');
            errorsEl.innerHTML = data.errors.map(e => line(e, 'fail')).join('') + warningHtml;
        }
    } catch (error) {
        statusEl.innerHTML = uiTag('Validation failed', 'fail');
    }
}

async function saveMapContent(filename) {
    const content = document.getElementById('map-editor-content').value;
    const saveBtn = document.getElementById('map-save-btn');
    
    // Validate first
    try {
        const valRes = await authenticatedFetch('/api/rspamd/validate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content, filename })
        });
        const valData = await valRes.json();
        
        if (!valData.valid) {
            showToast(`Cannot save: ${valData.errors.length} validation error(s). Fix them first.`, 'error');
            validateMapContent(filename);
            return;
        }
    } catch (e) {
        showToast('Validation failed: ' + e.message, 'error');
        return;
    }
    
    // Save
    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving...';
    
    try {
        const response = await authenticatedFetch(`/api/rspamd/maps/${filename}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content })
        });
        
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail?.message || err.detail || 'Save failed');
        }
        
        const result = await response.json();
        if (result.normalized_entries > 0) {
            // Bare addresses were anchored server side - reflect the saved form
            const textarea = document.getElementById('map-editor-content');
            if (textarea && typeof result.content === 'string') textarea.value = result.content;
            showToast(`Map saved (${result.entry_count} entries). ${result.normalized_entries} bare address entr${result.normalized_entries === 1 ? 'y was' : 'ies were'} anchored automatically.`, 'success');
        } else {
            showToast(`Map saved successfully (${result.entry_count} entries)`, 'success');
        }

        const statusEl = document.getElementById('map-validation-status');
        if (statusEl) statusEl.innerHTML = uiTag('✓ Saved', 'ok');
        document.getElementById('map-entry-count').textContent = `${result.entry_count} entries`;
        
    } catch (error) {
        showToast('Failed to save map: ' + error.message, 'error');
    } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = 'Save Changes';
    }
}

// =============================================================================
// SUPPRESSIONS
// =============================================================================

async function loadSuppressions(page) {
    suppressionPage = page || suppressionPage || 1;
    const container = document.getElementById('suppression-list');

    const search = document.getElementById('suppression-search')?.value || '';
    const reason = document.getElementById('suppression-filter-reason')?.value || '';
    const active = document.getElementById('suppression-filter-active')?.value || '';

    const params = new URLSearchParams({
        page: suppressionPage,
        per_page: 50,
    });
    if (search) params.append('search', search);
    if (reason) params.append('reason_filter', reason);
    if (active) params.append('active_filter', active);

    try {
        const response = await authenticatedFetch(`/api/suppressions?${params}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data = await response.json();

        if (!data.items || data.items.length === 0) {
            container.innerHTML = `
                <div class="ui-empty ui-panel">
                    <p><b>No Suppressions</b></p>
                    <p>Suppressed addresses will appear here when detected or added manually.</p>
                </div>
            `;
            return;
        }

        container.innerHTML = `
            <div class="ui-table ui-stack ui-supp-table">
                <div class="ui-tr ui-tr-head"><span>Address</span><span>Reason</span><span>Bounces</span><span>Expiry</span><span>Rspamd</span><span>Added</span><span class="ui-td-end">Actions</span></div>
                ${data.items.map(s => renderSuppressionItem(s)).join('')}
            </div>
            ${data.total_pages > 1 ? renderSuppressionPagination(data.page, data.total_pages, data.total) : ''}
        `;

    } catch (error) {
        console.error('Failed to load suppressions:', error);
        container.innerHTML = `<p class="ui-empty ui-text-fail">Failed to load: ${escapeHtml(error.message)}</p>`;
    }
}

function renderSuppressionItem(s) {
    const REASON_TONE = { hard_bounce: 'fail', soft_bounce: 'warn', deferred_stuck: 'warn', rejected: 'warn', manual: '' };
    const SOURCE_TONE = { auto: 'info', manual: '', import: 'spam' };

    // Fix #5: Show proper sync status based on active state
    let syncBadge = '<span class="ui-muted">-</span>';
    if (s.active) {
        syncBadge = s.synced_to_rspamd
            ? '<span class="ui-text-ok" title="Synced to Rspamd">✓ Synced</span>'
            : '<span class="ui-text-warn" title="Pending sync to Rspamd">⟳ Pending</span>';
    } else if (s.synced_to_rspamd) {
        // Inactive entries: show "Removed" if was synced, nothing if never synced
        syncBadge = '<span class="ui-muted" title="Will be removed from Rspamd on next sync">⊘ Will unsync</span>';
    }

    // For domain regex entries like /.+@example\.com/i, show clean domain
    const displayEmail = _cleanRegexDomain(s.email);
    const isRegexDomain = displayEmail !== s.email;
    const expiry = s.expires_in ? `Expires in ${s.expires_in.human}`
        : (!s.expires_at && s.active ? '<span class="ui-text-spam">∞ Permanent</span>' : '-');

    return `
        <div class="ui-tr${!s.active ? ' ui-row-off' : ''}">
            <div class="ui-td ui-q-who">
                <div>${copyableText(displayEmail)}
                    ${isRegexDomain ? `<span class="ui-tag ui-tag-info" title="${escapeHtml(s.email)}">Domain</span>` : ''}
                    ${!s.active ? uiTag('Inactive', '') : ''}
                    ${s.is_expired ? uiTag('Expired', 'fail') : ''}</div>
                ${s.notes ? `<small title="${escapeHtml(s.notes)}">${escapeHtml(s.notes)}</small>` : ''}
            </div>
            <span class="ui-td ui-td-wrap">${uiTag(s.reason.replace('_', ' '), REASON_TONE[s.reason] || '')} ${uiTag(s.source || 'manual', SOURCE_TONE[s.source] || '')}</span>
            <span class="ui-td"><small class="ui-sec-unit">Bounces </small>${s.bounce_count > 0 ? `${s.bounce_count} <small class="ui-muted">(H:${s.hard_bounce_count} S:${s.soft_bounce_count})</small>` : '<span class="ui-muted">-</span>'}</span>
            <span class="ui-td">${expiry}</span>
            <span class="ui-td">${syncBadge}</span>
            <span class="ui-td" title="${escapeHtml(formatTime(s.created_at))}"><small class="ui-sec-unit">Added </small>${formatAgo(s.created_at)}</span>
            <span class="ui-td ui-td-end ui-row-actions">
                <button onclick='showEditSuppressionModal(${JSON.stringify(s).replace(/'/g, "&#39;")})' class="ui-btn ui-btn-sm" title="Edit suppression">Edit</button>
                <button onclick="toggleSuppression(${s.id}, ${!s.active})" class="ui-btn ui-btn-sm" title="${s.active ? 'Deactivate' : 'Reactivate'}">${s.active ? 'Disable' : 'Enable'}</button>
                <button onclick="deleteSuppression(${s.id}, '${escapeJsArg(s.email)}')" class="ui-btn ui-btn-sm ui-btn-danger" title="Delete permanently">Delete</button>
            </span>
        </div>
    `;
}

function renderSuppressionPagination(page, totalPages, total) {
    return `
        <nav class="ui-pager" aria-label="Suppression pages">
            <span class="ui-muted">${total} total</span>
            ${page > 1 ? `<button onclick="loadSuppressions(${page - 1})" class="ui-btn ui-btn-sm">← Prev</button>` : ''}
            <span class="ui-muted">Page ${page}/${totalPages}</span>
            ${page < totalPages ? `<button onclick="loadSuppressions(${page + 1})" class="ui-btn ui-btn-sm">Next →</button>` : ''}
        </nav>
    `;
}

async function loadSuppressionStats() {
    const container = document.getElementById('suppression-stats');
    if (!container) return;

    try {
        const response = await authenticatedFetch('/api/suppressions/stats');
        if (!response.ok) return;

        const stats = await response.json();

        container.innerHTML = `
            <div class="ui-kpi"><b>${stats.active}</b>Active</div>
            <div class="ui-kpi"><b class="${stats.hard_bounce ? 'ui-fail' : ''}">${stats.hard_bounce}</b>Hard Bounces</div>
            <div class="ui-kpi"><b class="${stats.soft_bounce ? 'ui-warn' : ''}">${stats.soft_bounce}</b>Soft Bounces</div>
            <div class="ui-kpi"><b>${stats.pending_sync}</b>Pending Sync</div>
        `;
    } catch (error) {
        console.error('Failed to load suppression stats:', error);
    }
}

// =============================================================================
// SUPPRESSION CRUD
// =============================================================================

// A small v3 dialog; clicking the backdrop leaves it open, like before
function suppressionDialog(id, title, body, actions) {
    const modal = document.createElement('div');
    modal.id = id;
    modal.className = 'ui-dialog-backdrop';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-label', title);
    modal.innerHTML = `
        <div class="ui-dialog ui-dialog-fit ui-dialog-sm" onclick="event.stopPropagation()">
            <div class="ui-dialog-head"><h3>${escapeHtml(title)}</h3></div>
            <div class="ui-dialog-body ui-form">${body}</div>
            <div class="ui-dialog-foot">${actions}</div>
        </div>
    `;
    document.body.appendChild(modal);
    return modal;
}

function showAddSuppressionModal(prefillEmail) {
    suppressionDialog('add-suppression-modal', 'Add Suppression', `
        <label><span class="ui-label">Type</span>
            <select id="new-suppression-type" class="ui-select" onchange="updateSuppressionInputPlaceholder()">
                <option value="email">Email Address</option>
                <option value="domain">Domain</option>
            </select>
        </label>
        <label><span id="new-suppression-label" class="ui-label">Email Address</span>
            <input type="text" id="new-suppression-email" class="ui-input" placeholder="user@example.com">
            <small id="new-suppression-hint" class="ui-muted hidden"></small>
        </label>
        <label><span class="ui-label">Reason</span>
            <select id="new-suppression-reason" class="ui-select">
                <option value="manual">Manual</option>
                <option value="hard_bounce">Hard Bounce</option>
                <option value="soft_bounce">Soft Bounce</option>
                <option value="deferred_stuck">Deferred Stuck</option>
                <option value="rejected">Rejected</option>
            </select>
        </label>
        <label><span class="ui-label">Notes (optional)</span>
            <input type="text" id="new-suppression-notes" class="ui-input" placeholder="Reason for suppression...">
        </label>
        <div>
            <label class="ui-check-label">
                <input type="checkbox" id="new-suppression-permanent" class="ui-check" checked onchange="toggleCreateExpiryField()">
                Permanent block
            </label>
            <label id="new-suppression-expiry-row" class="hidden ui-form-sub"><span class="ui-label">Expires after (days)</span>
                <input type="number" id="new-suppression-expiry-days" min="1" max="365" value="7" class="ui-input">
            </label>
        </div>
    `, `
        <button onclick="document.getElementById('add-suppression-modal').remove()" class="ui-btn">Cancel</button>
        <button onclick="createSuppression()" class="ui-btn ui-btn-primary">Add Suppression</button>
    `);

    // Pre-fill email if provided (e.g., from queue page)
    if (prefillEmail) {
        document.getElementById('new-suppression-email').value = prefillEmail;
        document.getElementById('new-suppression-notes').value = 'Added from queue page';
    }

    document.getElementById('new-suppression-email').focus();
}

function updateSuppressionInputPlaceholder() {
    const type = document.getElementById('new-suppression-type').value;
    const input = document.getElementById('new-suppression-email');
    const label = document.getElementById('new-suppression-label');
    const hint = document.getElementById('new-suppression-hint');
    if (!input) return;
    
    if (type === 'domain') {
        label.textContent = 'Domain Name';
        input.placeholder = 'example.com';
        hint.textContent = 'Enter the domain name only. It will be stored as a regex pattern: /^.+@example\\.com$/i';
        hint.classList.remove('hidden');
    } else {
        label.textContent = 'Email Address';
        input.placeholder = 'user@example.com';
        hint.textContent = '';
        hint.classList.add('hidden');
    }
}

function toggleCreateExpiryField() {
    const permanent = document.getElementById('new-suppression-permanent').checked;
    const row = document.getElementById('new-suppression-expiry-row');
    if (row) {
        if (permanent) {
            row.classList.add('hidden');
        } else {
            row.classList.remove('hidden');
        }
    }
}

async function createSuppression() {
    let email = document.getElementById('new-suppression-email').value.trim();
    const type = document.getElementById('new-suppression-type').value;
    const reason = document.getElementById('new-suppression-reason').value;
    const notes = document.getElementById('new-suppression-notes').value.trim();
    
    if (!email) {
        showToast(type === 'domain' ? 'Domain name is required' : 'Email address is required', 'error');
        return;
    }
    
    // Fix #5: Convert domain to regex pattern
    if (type === 'domain') {
        // If user entered a raw domain, convert to regex
        if (!email.startsWith('/')) {
            // Only a plain hostname can be turned into a pattern safely. Escaping
            // just the dots left every other metacharacter (and the / delimiter)
            // free to change the regex that ends up in the Rspamd map.
            if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(email)) {
                showToast('Enter a plain domain name, for example example.com', 'error');
                return;
            }
            email = `/^.+@${escapeRegex(email)}$/i`;
        }
    }
    
    const permanent = document.getElementById('new-suppression-permanent')?.checked ?? true;
    let expiresAt = null;
    if (!permanent) {
        const days = parseInt(document.getElementById('new-suppression-expiry-days')?.value) || 7;
        const d = new Date();
        d.setDate(d.getDate() + days);
        expiresAt = d.toISOString();
    }
    
    try {
        const response = await authenticatedFetch('/api/suppressions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, type, reason, notes: notes || null, permanent, expires_at: expiresAt })
        });
        
        if (response.status === 409) {
            showToast('This address is already suppressed', 'error');
            return;
        }
        
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || 'Failed to create suppression');
        }
        
        showToast(`Suppression added: ${email}`, 'success');
        document.getElementById('add-suppression-modal')?.remove();
        loadSuppressions();
        loadSuppressionStats();
        // Fix #4: Auto-sync to Rspamd after changes
        autoSyncToRspamd();
        
    } catch (error) {
        showToast(error.message, 'error');
    }
}

function showEditSuppressionModal(s) {
    const isPermanent = !s.expires_at;
    const currentExpiry = s.expires_at ? new Date(s.expires_at).toISOString().slice(0, 16) : '';

    suppressionDialog('edit-suppression-modal', 'Edit Suppression', `
        <p class="ui-mono ui-muted">${escapeHtml(s.email)}</p>
        <div class="ui-md-ids ui-form-facts">
            <div class="ui-md-fact"><span>Reason</span><div>${escapeHtml(s.reason.replace('_', ' '))}</div></div>
            <div class="ui-md-fact"><span>Source</span><div>${escapeHtml(s.source || 'manual')}</div></div>
            ${s.bounce_count > 0 ? `<div class="ui-md-fact"><span>Bounces</span><div>${s.bounce_count}</div></div>` : ''}
            <div class="ui-md-fact"><span>Created</span><div>${formatTime(s.created_at)}</div></div>
        </div>
        <label><span class="ui-label">Notes</span>
            <input type="text" id="edit-suppression-notes" value="${escapeHtml(s.notes || '')}" class="ui-input" placeholder="Notes...">
        </label>
        <div>
            <label class="ui-check-label">
                <input type="checkbox" id="edit-suppression-permanent" class="ui-check" ${isPermanent ? 'checked' : ''} onchange="toggleEditExpiryField()">
                Permanent block
            </label>
            <div id="edit-suppression-expiry-row" class="ui-form-sub ${isPermanent ? 'hidden' : ''}">
                <label><span class="ui-label">Expiry date & time</span>
                    <input type="datetime-local" id="edit-suppression-expiry" value="${currentExpiry}" class="ui-input">
                </label>
                <div class="ui-chip-row">
                    <button onclick="extendExpiryBy(7)" class="ui-chip">+7 days</button>
                    <button onclick="extendExpiryBy(14)" class="ui-chip">+14 days</button>
                    <button onclick="extendExpiryBy(30)" class="ui-chip">+30 days</button>
                    <button onclick="extendExpiryBy(90)" class="ui-chip">+90 days</button>
                </div>
            </div>
        </div>
    `, `
        <button onclick="document.getElementById('edit-suppression-modal').remove()" class="ui-btn">Cancel</button>
        <button onclick="saveEditSuppression(${s.id})" class="ui-btn ui-btn-primary">Save Changes</button>
    `);
}

function toggleEditExpiryField() {
    const permanent = document.getElementById('edit-suppression-permanent').checked;
    const row = document.getElementById('edit-suppression-expiry-row');
    if (row) {
        if (permanent) {
            row.classList.add('hidden');
        } else {
            row.classList.remove('hidden');
            // If no date set, default to 7 days from now
            const input = document.getElementById('edit-suppression-expiry');
            if (input && !input.value) {
                const d = new Date();
                d.setDate(d.getDate() + 7);
                input.value = d.toISOString().slice(0, 16);
            }
        }
    }
}

function extendExpiryBy(days) {
    const input = document.getElementById('edit-suppression-expiry');
    if (!input) return;
    const base = input.value ? new Date(input.value) : new Date();
    base.setDate(base.getDate() + days);
    input.value = base.toISOString().slice(0, 16);
}

async function saveEditSuppression(id) {
    const notes = document.getElementById('edit-suppression-notes')?.value.trim() || null;
    const permanent = document.getElementById('edit-suppression-permanent')?.checked ?? true;
    
    let expiresAt;
    if (permanent) {
        expiresAt = 'null';  // clear expiry = permanent
    } else {
        const val = document.getElementById('edit-suppression-expiry')?.value;
        if (!val) {
            showToast('Please set an expiry date', 'error');
            return;
        }
        expiresAt = new Date(val).toISOString();
    }
    
    try {
        const response = await authenticatedFetch(`/api/suppressions/${id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ notes, expires_at: expiresAt })
        });
        
        if (!response.ok) throw new Error('Failed to update');
        
        showToast('Suppression updated', 'success');
        document.getElementById('edit-suppression-modal')?.remove();
        loadSuppressions();
        loadSuppressionStats();
        autoSyncToRspamd();
    } catch (error) {
        showToast(error.message, 'error');
    }
}

async function toggleSuppression(id, newActive) {
    try {
        const response = await authenticatedFetch(`/api/suppressions/${id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ active: newActive })
        });
        
        if (!response.ok) throw new Error('Failed to update');
        
        showToast(`Suppression ${newActive ? 'activated' : 'deactivated'}`, 'success');
        loadSuppressions();
        loadSuppressionStats();
        // Fix #4: Auto-sync to Rspamd after changes
        autoSyncToRspamd();
    } catch (error) {
        showToast(error.message, 'error');
    }
}

async function deleteSuppression(id, email) {
    if (!await showConfirmModal({ title: 'Delete Suppression', message: `Delete suppression for ${email}? This cannot be undone.`, confirmText: 'Delete', isDangerous: true })) return;
    
    try {
        const response = await authenticatedFetch(`/api/suppressions/${id}`, { method: 'DELETE' });
        if (!response.ok) throw new Error('Failed to delete');
        
        showToast(`Suppression deleted: ${email}`, 'success');
        loadSuppressions();
        loadSuppressionStats();
        // Fix #4: Auto-sync to Rspamd after changes
        autoSyncToRspamd();
    } catch (error) {
        showToast(error.message, 'error');
    }
}

// =============================================================================
// SYNC & IMPORT/EXPORT
// =============================================================================

/**
 * Fix #4: Auto-sync suppressions to Rspamd in the background after changes.
 * Does not show UI feedback beyond a quiet toast - the manual sync button
 * provides a more verbose experience.
 */
async function autoSyncToRspamd() {
    try {
        const response = await authenticatedFetch('/api/suppressions/sync', { method: 'POST' });
        if (response.ok) {
            const result = await response.json();
            console.log(`[autoSync] Synced ${result.synced} suppressions to Rspamd`);
            // Refresh list to show updated sync status
            loadSuppressions();
            loadSuppressionStats();
        }
    } catch (e) {
        console.warn('[autoSync] Background sync failed:', e.message);
    }
}

async function syncSuppressionsToRspamd() {
    const btn = document.getElementById('suppression-sync-btn');
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Syncing...';
    }
    
    try {
        const response = await authenticatedFetch('/api/suppressions/sync', { method: 'POST' });
        
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || 'Sync failed');
        }
        
        const result = await response.json();
        showToast(`Synced ${result.synced} suppressions to Rspamd (${result.newly_synced} new)`, 'success');
        loadSuppressions();
        loadSuppressionStats();
    } catch (error) {
        showToast('Sync failed: ' + error.message, 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                </svg>
                Sync to Rspamd
            `;
        }
    }
}

function exportSuppressions() {
    window.location.href = '/api/suppressions/export';
    toggleSuppressionMoreMenu();
}

async function importSuppressions(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await authenticatedFetch('/api/suppressions/import', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) throw new Error('Import failed');
        
        const result = await response.json();
        showToast(`Imported ${result.imported} suppressions (${result.skipped} skipped)`, 'success');
        loadSuppressions();
        loadSuppressionStats();
        // Fix #4: Auto-sync after import too
        autoSyncToRspamd();
    } catch (error) {
        showToast('Import failed: ' + error.message, 'error');
    }
    
    event.target.value = '';
    toggleSuppressionMoreMenu();
}

function clearSuppressionFilters() {
    const search = document.getElementById('suppression-search');
    const reason = document.getElementById('suppression-filter-reason');
    const active = document.getElementById('suppression-filter-active');
    if (search) search.value = '';
    if (reason) reason.value = '';
    if (active) active.value = 'true';
    loadSuppressions(1);
}

function toggleSuppressionMoreMenu() {
    const menu = document.getElementById('suppression-more-menu');
    if (menu) menu.classList.toggle('hidden');
}

// Close menu on outside click
document.addEventListener('click', function(e) {
    const menu = document.getElementById('suppression-more-menu');
    if (menu && !menu.classList.contains('hidden') && !e.target.closest('#suppression-more-menu') && !e.target.closest('[onclick*="toggleSuppressionMoreMenu"]')) {
        menu.classList.add('hidden');
    }
});


// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Static map descriptions lookup (fallback if backend sends Rspamd's technical description)
 */
const _MAP_META_DESCRIPTIONS = {
    'global_mime_from_blacklist.map': 'Block emails by From header address',
    'global_mime_from_whitelist.map': 'Allow emails by From header address',
    'global_smtp_from_blacklist.map': 'Block by envelope sender address',
    'global_smtp_from_whitelist.map': 'Allow by envelope sender address',
    'global_rcpt_blacklist.map': 'Block sending to these recipient addresses',
    'global_rcpt_whitelist.map': 'Allow sending to these recipient addresses',
    'fishy_tlds.map': 'Suspicious TLDs (only fired in combination with bad words)',
    'bad_words.map': 'Bad words (only fired in combination with fishy TLDs)',
    'bad_words_de.map': 'German bad words (only fired in combination with fishy TLDs)',
    'bad_languages.map': 'Blocked languages',
    'bulk_header.map': 'Bulk/mass mail header patterns',
    'bad_header.map': 'Junk mail header patterns',
    'monitoring_nolog.map': 'Hosts excluded from logging',
};

function _getMapMetaDescription(filename) {
    return _MAP_META_DESCRIPTIONS[filename] || null;
}

/**
 * Extract clean domain from regex pattern like /.+@example\.com/i → example.com
 */
function _cleanRegexDomain(email) {
    if (!email || !email.startsWith('/')) return email;
    // Match both the anchored form /^.+@example\.com$/i (optionally with the
    // wizard's subdomain group) and the legacy unanchored /.+@example\.com/i
    const match = email.match(/^\/\^?\.\+@(?:\(\.\+\\\.\)\?)?(.+?)\$?\/i?$/);
    if (match) {
        // Unescape dots: example\.com → example.com
        return match[1].replace(/\\\./g, '.');
    }
    return email;
}

/**
 * Regex Wizard - toggle panel visibility
 */
function toggleRegexWizard() {
    const panel = document.getElementById('regex-wizard-panel');
    if (panel) {
        panel.classList.toggle('hidden');
        if (!panel.classList.contains('hidden')) {
            // Focus input when opened
            const input = document.getElementById('regex-wizard-input');
            if (input) input.focus();
            updateRegexWizardPreview();
        }
    }
}

/**
 * Regex Wizard - update input label, placeholder, and preview based on selected type
 */
function updateRegexWizardPreview() {
    const type = document.getElementById('regex-wizard-type').value;
    const input = document.getElementById('regex-wizard-input');
    const label = document.getElementById('regex-wizard-input-label');
    const preview = document.getElementById('regex-wizard-preview');
    const result = document.getElementById('regex-wizard-result');
    const explain = document.getElementById('regex-wizard-explain');
    const addBtn = document.getElementById('regex-wizard-add-btn');
    
    // Update label & placeholder based on type
    const config = {
        email:          { label: 'Email address',  placeholder: 'user@example.com' },
        domain:         { label: 'Domain',          placeholder: 'example.com' },
        tld:            { label: 'TLD',             placeholder: 'xyz' },
        keyword:        { label: 'Keyword',         placeholder: 'sale' },
    };
    
    const c = config[type] || config.email;
    label.textContent = c.label;
    input.placeholder = c.placeholder;
    
    const value = input.value.trim();
    
    if (!value) {
        preview.classList.add('hidden');
        addBtn.disabled = true;
        return;
    }
    
    // Generate regex based on type
    let pattern = '';
    let explanation = '';
    
    // Escape special regex characters in user input
    const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    
    switch (type) {
        case 'email':
            // The map is a regexp map: a bare address would match as a
            // substring (e@example.com also hits alice@example.com), so an
            // exact match needs anchors
            pattern = `/^${value.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$/i`;
            explanation = `Blocks exactly: ${value}`;
            break;
        case 'domain':
            // Anchored, with the @ boundary and optional subdomain labels
            pattern = `/^.+@(.+\\.)?${escaped}$/i`;
            explanation = `Blocks: *@${value} and all subdomains (e.g. *@sub.${value})`;
            break;
        case 'tld':
            // Match any address ending in .tld
            pattern = `/^.+\\.${escaped}$/i`;
            explanation = `Blocks all addresses from .${value} domains`;
            break;
        case 'keyword':
            // Match keyword anywhere in the address
            pattern = `/.*${escaped}.*/i`;
            explanation = `Blocks any address containing "${value}"`;
            break;
    }
    
    result.textContent = pattern;
    explain.textContent = explanation;
    preview.classList.remove('hidden');
    addBtn.disabled = false;
}

/**
 * Regex Wizard - add the generated pattern to the textarea
 */
function regexWizardAdd() {
    const result = document.getElementById('regex-wizard-result');
    const textarea = document.getElementById('map-editor-content');
    const input = document.getElementById('regex-wizard-input');
    if (!result || !textarea) return;
    
    const pattern = result.textContent;
    if (!pattern) return;
    
    // Append to end of textarea content
    let content = textarea.value;
    if (content && !content.endsWith('\n')) {
        content += '\n';
    }
    content += pattern;
    textarea.value = content;
    
    // Trigger change event
    textarea.dispatchEvent(new Event('input'));
    
    // Show success feedback
    showToast(`Pattern added: ${pattern}`, 'success');
    
    // Clear input for next entry
    input.value = '';
    updateRegexWizardPreview();
    
    // Scroll textarea to bottom to show the new entry
    textarea.scrollTop = textarea.scrollHeight;
}
