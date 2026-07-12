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
            container.innerHTML = `
                <div class="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-6 text-center">
                    <svg class="w-12 h-12 mx-auto mb-3 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                    </svg>
                    <h3 class="text-lg font-semibold text-yellow-800 dark:text-yellow-200 mb-2">Rspamd Not Configured</h3>
                    <p class="text-yellow-700 dark:text-yellow-300 mb-4">${escapeHtml(data.message || 'Set RSPAMD_PASSWORD in Settings to enable Rspamd map management.')}</p>
                    <button onclick="navigateTo('settings')" class="px-4 py-2 bg-yellow-600 hover:bg-yellow-700 text-white rounded-lg text-sm">
                        Go to Settings
                    </button>
                </div>
            `;
            return;
        }
        
        if (data.error) {
            container.innerHTML = `
                <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 text-center">
                    <p class="text-red-700 dark:text-red-300">${escapeHtml(data.error)}</p>
                </div>
            `;
            return;
        }
        
        renderRspamdMapsList(data.maps, data.rw_key_configured);
        
    } catch (error) {
        console.error('Failed to load Rspamd maps:', error);
        container.innerHTML = `<p class="text-red-500 text-center py-8">Failed to load maps: ${escapeHtml(error.message)}</p>`;
    }
}

function renderRspamdMapsList(maps, rwKeyConfigured) {
    const container = document.getElementById('rspamd-maps-list');
    
    // Group maps by category
    const categories = {
        sender: { label: 'Sender Rules', icon: '📤', maps: [] },
        recipient: { label: 'Recipient Rules', icon: '📥', maps: [] },
        content: { label: 'Content Rules', icon: '📝', maps: [] },
        system: { label: 'System', icon: '⚙️', maps: [] }
    };
    
    maps.forEach(m => {
        const cat = categories[m.category] || categories.system;
        cat.maps.push(m);
    });
    
    let html = '';
    
    for (const [key, cat] of Object.entries(categories)) {
        if (cat.maps.length === 0) continue;
        
        html += `
            <div class="mb-6">
                <h3 class="text-sm font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                    <span>${cat.icon}</span> ${cat.label}
                </h3>
                <div class="space-y-2">
                    ${cat.maps.map(m => {
                        // Use our metadata description, not the rspamd technical description
                        const displayDesc = _getMapMetaDescription(m.filename) || m.description || '';
                        return `
                        <div class="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg hover:border-blue-300 dark:hover:border-blue-600 transition cursor-pointer"
                             onclick="openMapEditor('${escapeJsArg(m.filename)}')">
                            <div class="p-4 flex items-center justify-between">
                                <div class="flex-1 min-w-0">
                                    <div class="flex items-center gap-2 mb-1">
                                        <h4 class="font-medium text-gray-900 dark:text-white truncate">${escapeHtml(m.name)}</h4>
                                        ${m.managed_by_suppression ? '<span class="px-2 py-0.5 text-xs bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 rounded-full">Auto-managed</span>' : ''}
                                    </div>
                                    <p class="text-sm text-gray-500 dark:text-gray-400 truncate">${escapeHtml(displayDesc)}</p>
                                </div>
                                <div class="flex items-center gap-3 ml-4 flex-shrink-0">
                                    ${m.loaded !== undefined ? `
                                        <span class="inline-flex items-center gap-1 text-xs ${m.loaded ? 'text-green-600 dark:text-green-400' : 'text-gray-400'}">
                                            <span class="w-2 h-2 rounded-full ${m.loaded ? 'bg-green-500' : 'bg-gray-300'}"></span>
                                            ${m.loaded ? 'Loaded' : 'Not loaded'}
                                        </span>
                                    ` : ''}
                                    <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                                    </svg>
                                </div>
                            </div>
                        </div>
                    `}).join('')}
                </div>
            </div>
        `;
    }
    
    if (!rwKeyConfigured) {
        html = `
            <div class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mb-4 text-sm text-blue-700 dark:text-blue-300">
                <strong>Read-Only Mode:</strong> MAILCOW_API_KEY_RW is not configured. You can view maps but cannot save changes.
            </div>
        ` + html;
    }
    
    container.innerHTML = html;
}

async function openMapEditor(filename) {
    const container = document.getElementById('rspamd-maps-list');
    
    container.innerHTML = `
        <div class="text-center py-8">
            <div class="loading mx-auto mb-4"></div>
            <p class="text-gray-500 dark:text-gray-400">Loading map content...</p>
        </div>
    `;
    
    try {
        const response = await authenticatedFetch(`/api/rspamd/maps/${filename}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const data = await response.json();
        const meta = data.metadata || {};
        
        container.innerHTML = `
            <div class="mb-4">
                <button onclick="loadRspamdMaps()" class="inline-flex items-center gap-1.5 text-sm text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"></path>
                    </svg>
                    Back to Maps List
                </button>
            </div>
            
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/30 overflow-hidden">
                <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex flex-wrap items-center justify-between gap-2">
                    <div>
                        <h3 class="text-lg font-semibold text-gray-900 dark:text-white">${escapeHtml(meta.name || filename)}</h3>
                        <p class="text-sm text-gray-500 dark:text-gray-400">${escapeHtml(meta.description || '')}</p>
                        <p class="text-xs text-gray-400 dark:text-gray-500 font-mono mt-1">${escapeHtml(filename)}</p>
                    </div>
                    <div class="flex items-center gap-2">
                        <span id="map-entry-count" class="text-sm text-gray-500 dark:text-gray-400">${data.entry_count} entries</span>
                        <span id="map-validation-status"></span>
                    </div>
                </div>
                <div class="p-6">
                    ${meta.supports_regex ? `
                        <div class="mb-4">
                            <button onclick="toggleRegexWizard()" id="regex-wizard-toggle" class="inline-flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-lg border border-blue-300 dark:border-blue-600 text-blue-700 dark:text-blue-300 bg-blue-50 dark:bg-blue-900/20 hover:bg-blue-100 dark:hover:bg-blue-900/40 transition">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"></path>
                                </svg>
                                Regex Wizard
                            </button>
                            <div id="regex-wizard-panel" class="hidden mt-3 p-4 bg-gradient-to-br from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
                                <div class="flex items-center justify-between mb-3">
                                    <h4 class="text-sm font-semibold text-blue-800 dark:text-blue-200">Regex Pattern Generator</h4>
                                    <button onclick="toggleRegexWizard()" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                                    </button>
                                </div>
                                <div class="flex flex-col sm:flex-row gap-3">
                                    <div class="flex-shrink-0">
                                        <label class="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Type</label>
                                        <select id="regex-wizard-type" onchange="updateRegexWizardPreview()" class="w-full sm:w-40 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg">
                                            <option value="email">Exact Email</option>
                                            <option value="domain">Domain</option>
                                            <option value="tld">TLD</option>
                                            <option value="keyword">Keyword</option>
                                        </select>
                                    </div>
                                    <div class="flex-1">
                                        <label id="regex-wizard-input-label" class="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Email address</label>
                                        <input type="text" id="regex-wizard-input" oninput="updateRegexWizardPreview()" placeholder="user@example.com" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg" />
                                    </div>
                                    <div class="flex-shrink-0 flex items-end">
                                        <button onclick="regexWizardAdd()" id="regex-wizard-add-btn" class="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed" disabled>Add</button>
                                    </div>
                                </div>
                                <div id="regex-wizard-preview" class="mt-3 hidden">
                                    <label class="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Generated pattern</label>
                                    <div class="flex items-center gap-2">
                                        <code id="regex-wizard-result" class="flex-1 px-3 py-2 text-sm font-mono bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-600 rounded-lg text-green-700 dark:text-green-400 break-all"></code>
                                    </div>
                                    <p id="regex-wizard-explain" class="mt-1 text-xs text-gray-500 dark:text-gray-400"></p>
                                </div>
                            </div>
                        </div>
                    ` : ''}
                    <textarea id="map-editor-content" 
                        class="w-full h-64 font-mono text-sm border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg p-4 focus:ring-blue-500 focus:border-blue-500"
                        placeholder="Enter entries, one per line..."
                        oninput="onMapContentChange('${escapeJsArg(filename)}')">${escapeHtml(data.content || '')}</textarea>
                    <div id="map-validation-errors" class="mt-2 hidden"></div>
                    <div class="flex items-center justify-between mt-4">
                        <p class="text-xs text-gray-400 dark:text-gray-500">
                            Lines starting with # are comments. Empty lines are ignored.
                        </p>
                        <div class="flex items-center gap-2">
                            <button onclick="validateMapContent('${escapeJsArg(filename)}')" class="px-4 py-2 text-sm bg-gray-200 hover:bg-gray-300 dark:bg-gray-600 dark:hover:bg-gray-500 text-gray-700 dark:text-gray-300 rounded-lg">
                                Validate
                            </button>
                            <button onclick="saveMapContent('${escapeJsArg(filename)}')" id="map-save-btn" class="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed">
                                Save Changes
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
    } catch (error) {
        console.error('Failed to load map content:', error);
        container.innerHTML = `
            <div class="mb-4">
                <button onclick="loadRspamdMaps()" class="inline-flex items-center gap-1.5 text-sm text-blue-600 hover:text-blue-800">
                    ← Back to Maps List
                </button>
            </div>
            <p class="text-red-500 text-center py-8">Failed to load map: ${escapeHtml(error.message)}</p>
        `;
    }
}

function onMapContentChange(filename) {
    const statusEl = document.getElementById('map-validation-status');
    if (statusEl) {
        statusEl.innerHTML = '<span class="text-yellow-600 dark:text-yellow-400 text-xs">Modified</span>';
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
        
        if (data.valid) {
            statusEl.innerHTML = '<span class="text-green-600 dark:text-green-400 text-xs font-medium">✓ Valid</span>';
            errorsEl.classList.add('hidden');
        } else {
            statusEl.innerHTML = `<span class="text-red-600 dark:text-red-400 text-xs font-medium">✗ ${data.errors.length} error(s)</span>`;
            errorsEl.classList.remove('hidden');
            errorsEl.innerHTML = data.errors.map(e => `
                <div class="text-xs text-red-600 dark:text-red-400 flex items-start gap-2 py-1">
                    <span class="font-mono text-gray-500 dark:text-gray-400 flex-shrink-0">Line ${e.line}:</span>
                    <span>${escapeHtml(e.error)} — <code class="bg-red-50 dark:bg-red-900/30 px-1 rounded">${escapeHtml(e.content)}</code></span>
                </div>
            `).join('');
        }
    } catch (error) {
        statusEl.innerHTML = '<span class="text-red-600 text-xs">Validation failed</span>';
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
        showToast(`Map saved successfully (${result.entry_count} entries)`, 'success');
        
        const statusEl = document.getElementById('map-validation-status');
        if (statusEl) statusEl.innerHTML = '<span class="text-green-600 dark:text-green-400 text-xs font-medium">✓ Saved</span>';
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
                <div class="text-center py-12">
                    <svg class="w-16 h-16 mx-auto mb-4 text-gray-300 dark:text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z"></path>
                    </svg>
                    <h3 class="text-lg font-medium text-gray-500 dark:text-gray-400 mb-1">No Suppressions</h3>
                    <p class="text-sm text-gray-400 dark:text-gray-500">Suppressed addresses will appear here when detected or added manually.</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = `
            <div class="space-y-2">
                ${data.items.map(s => renderSuppressionItem(s)).join('')}
            </div>
            ${data.total_pages > 1 ? renderSuppressionPagination(data.page, data.total_pages, data.total) : ''}
        `;
        
    } catch (error) {
        console.error('Failed to load suppressions:', error);
        container.innerHTML = `<p class="text-red-500 text-center py-8">Failed to load: ${escapeHtml(error.message)}</p>`;
    }
}

function renderSuppressionItem(s) {
    const reasonColors = {
        hard_bounce: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300',
        soft_bounce: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300',
        deferred_stuck: 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300',
        rejected: 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300',
        manual: 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300',
    };
    
    const sourceColors = {
        auto: 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300',
        manual: 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300',
        import: 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300',
    };
    
    // Fix #5: Show proper sync status based on active state
    let syncBadge = '';
    if (s.active) {
        if (s.synced_to_rspamd) {
            syncBadge = '<span class="text-green-500 text-xs" title="Synced to Rspamd">✓ Synced</span>';
        } else {
            syncBadge = '<span class="text-yellow-500 text-xs" title="Pending sync to Rspamd">⟳ Pending</span>';
        }
    } else {
        // Inactive entries: show "Removed" if was synced, nothing if never synced
        if (s.synced_to_rspamd) {
            syncBadge = '<span class="text-gray-400 text-xs" title="Will be removed from Rspamd on next sync">⊘ Will unsync</span>';
        }
    }
    
    // For domain regex entries like /.+@example\.com/i, show clean domain
    const displayEmail = _cleanRegexDomain(s.email);
    const isRegexDomain = displayEmail !== s.email;
    
    return `
        <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4 ${!s.active ? 'opacity-60' : ''} hover:bg-gray-50 dark:hover:bg-gray-700/50 transition">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div class="flex-1 min-w-0">
                    <div class="flex flex-wrap items-center gap-2 mb-1">
                        <span class="font-medium text-gray-900 dark:text-white">${copyableText(displayEmail)}</span>
                        ${isRegexDomain ? '<span class="px-2 py-0.5 text-xs bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300 rounded" title="' + escapeHtml(s.email) + '">Domain</span>' : ''}
                        <span class="px-2 py-0.5 text-xs font-medium rounded ${reasonColors[s.reason] || reasonColors.manual}">${s.reason.replace('_', ' ')}</span>
                        <span class="px-2 py-0.5 text-xs font-medium rounded ${sourceColors[s.source] || sourceColors.manual}">${s.source || 'manual'}</span>
                        ${!s.active ? '<span class="px-2 py-0.5 text-xs font-medium rounded bg-gray-200 dark:bg-gray-600 text-gray-600 dark:text-gray-400">Inactive</span>' : ''}
                        ${s.is_expired ? '<span class="px-2 py-0.5 text-xs font-medium rounded bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300">Expired</span>' : ''}
                        ${syncBadge}
                    </div>
                    <div class="flex flex-wrap gap-3 text-xs text-gray-500 dark:text-gray-400">
                        ${s.bounce_count > 0 ? `<span>Bounces: ${s.bounce_count} (H:${s.hard_bounce_count} S:${s.soft_bounce_count})</span>` : ''}
                        ${!s.expires_at && s.active ? '<span class="text-purple-600 dark:text-purple-400 font-medium">∞ Permanent</span>' : ''}
                        ${s.expires_in ? `<span>Expires in ${s.expires_in.human}</span>` : ''}
                        ${s.notes ? `<span title="${escapeHtml(s.notes)}">📝 ${escapeHtml(s.notes.substring(0, 40))}${s.notes.length > 40 ? '...' : ''}</span>` : ''}
                        <span>${formatTime(s.created_at)}</span>
                    </div>
                </div>
                <div class="flex items-center gap-1 flex-shrink-0">
                    <button onclick='showEditSuppressionModal(${JSON.stringify(s).replace(/'/g, "&#39;")})' class="px-2 py-1 text-xs rounded bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 hover:bg-blue-200" title="Edit suppression">
                        Edit
                    </button>
                    <button onclick="toggleSuppression(${s.id}, ${!s.active})" class="px-2 py-1 text-xs rounded ${s.active ? 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300 hover:bg-yellow-200' : 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300 hover:bg-green-200'}" title="${s.active ? 'Deactivate' : 'Reactivate'}">
                        ${s.active ? 'Disable' : 'Enable'}
                    </button>
                    <button onclick="deleteSuppression(${s.id}, '${escapeJsArg(s.email)}')" class="px-2 py-1 text-xs rounded bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 hover:bg-red-200" title="Delete permanently">
                        Delete
                    </button>
                </div>
            </div>
        </div>
    `;
}

function renderSuppressionPagination(page, totalPages, total) {
    return `
        <div class="flex items-center justify-between mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
            <span class="text-sm text-gray-500 dark:text-gray-400">${total} total</span>
            <div class="flex items-center gap-1">
                ${page > 1 ? `<button onclick="loadSuppressions(${page - 1})" class="px-3 py-1 text-sm rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700">← Prev</button>` : ''}
                <span class="px-3 py-1 text-sm text-gray-500 dark:text-gray-400">Page ${page}/${totalPages}</span>
                ${page < totalPages ? `<button onclick="loadSuppressions(${page + 1})" class="px-3 py-1 text-sm rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700">Next →</button>` : ''}
            </div>
        </div>
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
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/30 p-4">
                <div class="text-2xl font-bold text-gray-900 dark:text-white">${stats.active}</div>
                <div class="text-xs text-gray-500 dark:text-gray-400">Active</div>
            </div>
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/30 p-4">
                <div class="text-2xl font-bold text-red-600 dark:text-red-400">${stats.hard_bounce}</div>
                <div class="text-xs text-gray-500 dark:text-gray-400">Hard Bounces</div>
            </div>
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/30 p-4">
                <div class="text-2xl font-bold text-yellow-600 dark:text-yellow-400">${stats.soft_bounce}</div>
                <div class="text-xs text-gray-500 dark:text-gray-400">Soft Bounces</div>
            </div>
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow dark:shadow-gray-900/30 p-4">
                <div class="text-2xl font-bold text-blue-600 dark:text-blue-400">${stats.pending_sync}</div>
                <div class="text-xs text-gray-500 dark:text-gray-400">Pending Sync</div>
            </div>
        `;
    } catch (error) {
        console.error('Failed to load suppression stats:', error);
    }
}

// =============================================================================
// SUPPRESSION CRUD
// =============================================================================

function showAddSuppressionModal(prefillEmail) {
    const modal = document.createElement('div');
    modal.id = 'add-suppression-modal';
    modal.className = 'fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4';
    
    modal.innerHTML = `
        <div class="bg-white dark:bg-gray-800 rounded-lg max-w-md w-full p-6" onclick="event.stopPropagation()">
            <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Add Suppression</h3>
            <div class="space-y-4">
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Type</label>
                    <select id="new-suppression-type" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg"
                        onchange="updateSuppressionInputPlaceholder()">
                        <option value="email">Email Address</option>
                        <option value="domain">Domain</option>
                    </select>
                </div>
                <div>
                    <label id="new-suppression-label" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Email Address</label>
                    <input type="text" id="new-suppression-email" 
                        class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg"
                        placeholder="user@example.com">
                    <p id="new-suppression-hint" class="text-xs text-gray-400 dark:text-gray-500 mt-1 hidden"></p>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Reason</label>
                    <select id="new-suppression-reason" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg">
                        <option value="manual">Manual</option>
                        <option value="hard_bounce">Hard Bounce</option>
                        <option value="soft_bounce">Soft Bounce</option>
                        <option value="deferred_stuck">Deferred Stuck</option>
                        <option value="rejected">Rejected</option>
                    </select>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Notes (optional)</label>
                    <input type="text" id="new-suppression-notes" 
                        class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg"
                        placeholder="Reason for suppression...">
                </div>
                <div>
                    <label class="flex items-center gap-2 cursor-pointer">
                        <input type="checkbox" id="new-suppression-permanent" checked
                            class="rounded border-gray-300 dark:border-gray-600"
                            onchange="toggleCreateExpiryField()">
                        <span class="text-sm font-medium text-gray-700 dark:text-gray-300">Permanent block</span>
                    </label>
                    <div id="new-suppression-expiry-row" class="mt-2 hidden">
                        <label class="block text-xs text-gray-500 dark:text-gray-400 mb-1">Expires after (days)</label>
                        <input type="number" id="new-suppression-expiry-days" min="1" max="365" value="7"
                            class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg">
                    </div>
                </div>
            </div>
            <div class="flex justify-end gap-2 mt-6">
                <button onclick="document.getElementById('add-suppression-modal').remove()" class="px-4 py-2 text-sm bg-gray-200 hover:bg-gray-300 dark:bg-gray-600 dark:hover:bg-gray-500 text-gray-700 dark:text-gray-300 rounded-lg">
                    Cancel
                </button>
                <button onclick="createSuppression()" class="px-4 py-2 text-sm bg-red-600 hover:bg-red-700 text-white rounded-lg">
                    Add Suppression
                </button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
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
        hint.textContent = 'Enter the domain name only. It will be stored as a regex pattern: /.+@example\\.com/i';
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
            const escapedDomain = email.replace(/\./g, '\\.');
            email = `/.+@${escapedDomain}/i`;
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
    const modal = document.createElement('div');
    modal.id = 'edit-suppression-modal';
    modal.className = 'fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4';
    
    const isPermanent = !s.expires_at;
    const currentExpiry = s.expires_at ? new Date(s.expires_at).toISOString().slice(0, 16) : '';
    
    modal.innerHTML = `
        <div class="bg-white dark:bg-gray-800 rounded-lg max-w-md w-full p-6" onclick="event.stopPropagation()">
            <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-2">Edit Suppression</h3>
            <p class="text-sm text-gray-500 dark:text-gray-400 mb-4 font-mono">${escapeHtml(s.email)}</p>
            
            <div class="space-y-4">
                <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3 text-xs text-gray-600 dark:text-gray-400">
                    <div class="grid grid-cols-2 gap-2">
                        <span>Reason: <strong>${s.reason.replace('_', ' ')}</strong></span>
                        <span>Source: <strong>${s.source || 'manual'}</strong></span>
                        ${s.bounce_count > 0 ? `<span>Bounces: <strong>${s.bounce_count}</strong></span>` : ''}
                        <span>Created: <strong>${formatTime(s.created_at)}</strong></span>
                    </div>
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Notes</label>
                    <input type="text" id="edit-suppression-notes" value="${escapeHtml(s.notes || '')}"
                        class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg"
                        placeholder="Notes...">
                </div>
                
                <div>
                    <label class="flex items-center gap-2 cursor-pointer">
                        <input type="checkbox" id="edit-suppression-permanent" ${isPermanent ? 'checked' : ''}
                            class="rounded border-gray-300 dark:border-gray-600"
                            onchange="toggleEditExpiryField()">
                        <span class="text-sm font-medium text-gray-700 dark:text-gray-300">Permanent block</span>
                    </label>
                    <div id="edit-suppression-expiry-row" class="mt-2 ${isPermanent ? 'hidden' : ''}">
                        <label class="block text-xs text-gray-500 dark:text-gray-400 mb-1">Expiry date & time</label>
                        <input type="datetime-local" id="edit-suppression-expiry" value="${currentExpiry}"
                            class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg">
                        <div class="flex gap-2 mt-2">
                            <button onclick="extendExpiryBy(7)" class="px-2 py-1 text-xs rounded bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-300">+7 days</button>
                            <button onclick="extendExpiryBy(14)" class="px-2 py-1 text-xs rounded bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-300">+14 days</button>
                            <button onclick="extendExpiryBy(30)" class="px-2 py-1 text-xs rounded bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-300">+30 days</button>
                            <button onclick="extendExpiryBy(90)" class="px-2 py-1 text-xs rounded bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-300">+90 days</button>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="flex justify-end gap-2 mt-6">
                <button onclick="document.getElementById('edit-suppression-modal').remove()" class="px-4 py-2 text-sm bg-gray-200 hover:bg-gray-300 dark:bg-gray-600 dark:hover:bg-gray-500 text-gray-700 dark:text-gray-300 rounded-lg">
                    Cancel
                </button>
                <button onclick="saveEditSuppression(${s.id})" class="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded-lg">
                    Save Changes
                </button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
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
 * Does not show UI feedback beyond a quiet toast — the manual sync button
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
        btn.innerHTML = '<span class="loading" style="width:16px;height:16px;border-width:2px;display:inline-block;vertical-align:middle;margin-right:4px"></span> Syncing...';
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
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
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
    // Match patterns like /.+@example\.com/i or /.+@sub\.example\.com/i
    const match = email.match(/^\/\.\+@(.+)\/i?$/);
    if (match) {
        // Unescape dots: example\.com → example.com
        return match[1].replace(/\\\./g, '.');
    }
    return email;
}

/**
 * Regex Wizard — toggle panel visibility
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
 * Regex Wizard — update input label, placeholder, and preview based on selected type
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
            // Plain email — no regex needed
            pattern = value.toLowerCase();
            explanation = `Blocks exactly: ${value}`;
            break;
        case 'domain':
            // mailcow style: /.+example\.com/i
            pattern = `/.+${escaped}/i`;
            explanation = `Blocks: *@${value} and all subdomains (e.g. *@sub.${value})`;
            break;
        case 'tld':
            // Match any address ending in .tld
            pattern = `/.+\\.${escaped}$/i`;
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
 * Regex Wizard — add the generated pattern to the textarea
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
