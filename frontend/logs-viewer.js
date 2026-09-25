// =============================================================================
// LIVE LOG VIEWER - raw service logs page, WebSocket stream, filters, controls
// =============================================================================
// Split out of app.js (phase 3). Classic script sharing the global scope;
// loaded after utils.js and app.js in index.html.

// =============================================================================
// LIVE LOG VIEWER
// =============================================================================

let logsState = {
    activeService: 'postfix',
    isPaused: false,
    autoScroll: true,
    // Display order (issue #69): false = newest at the bottom (classic tail -f),
    // true = newest at the top. allEntries stays chronological either way.
    newestFirst: localStorage.getItem('logsNewestFirst') === 'true',
    fontSize: 12,
    wordWrap: true,
    searchQuery: '',
    activeSmartFilters: [],
    ws: null,
    isConnected: false,
    services: [],
    smartFilters: [],
    entryCount: 0,
    lastUpdateTime: null,
    allEntries: [],
    // Pagination state for infinite scroll
    currentPage: 1,
    totalPages: 1,
    totalEntries: 0,
    isLoadingMore: false,
    oldestPageLoaded: 1,  // track which page we've loaded up to
    timeRangeMinutes: '',  // '' = all time, or minutes as string
};

// Service icon map (SVG paths for inline icons)
const LOG_SERVICE_ICONS = {
    mail: 'M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z',
    inbox: 'M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4',
    calendar: 'M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z',
    shield: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
    lock: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z',
    code: 'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4',
    search: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z',
    eye: 'M15 12a3 3 0 11-6 0 3 3 0 016 0z M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z',
    clock: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z',
    filter: 'M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z',
    file: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
};

async function loadLogViewer() {
    console.log('[LOGS] Loading log viewer...');
    
    try {
        // Fetch service list
        const response = await authenticatedFetch('/api/raw-logs/services');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const data = await response.json();
        
        // Check if raw logs feature is disabled
        if (data.raw_logs_enabled === false) {
            const output = document.getElementById('logs-output');
            if (output) {
                output.innerHTML = `<div class="ui-logs-locked">${uiLocked('Live Log Viewer is Disabled',
                    'Raw log collection is currently turned off. Enable it in Settings → Raw Logs to start viewing live logs.')}</div>`;
            }
            // Hide the service sidebar
            const sidebar = document.getElementById('logs-service-list');
            if (sidebar) sidebar.innerHTML = '';
            return;
        }
        
        logsState.services = data.services || [];
        
        // Render service sidebar
        renderLogServiceList(logsState.services);
        
        // Select first service or postfix
        const defaultService = logsState.services.find(s => s.id === 'postfix') || logsState.services[0];
        if (defaultService) {
            await selectLogService(defaultService.id);
        } else {
            const output = document.getElementById('logs-output');
            if (output) {
                output.innerHTML = `<div class="ui-logs-locked">${uiLocked('No log services available', 'Enable services in Settings → Raw Logs.')}</div>`;
            }
        }
    } catch (error) {
        console.error('[LOGS] Failed to load log viewer:', error);
        const output = document.getElementById('logs-output');
        if (output) {
            output.innerHTML = `<span class="text-red-400">Failed to load log services: ${escapeHtml(error.message)}</span>`;
        }
    }
}

function renderLogServiceList(services) {
    const container = document.getElementById('logs-service-list');
    if (!container) return;
    
    if (services.length === 0) {
        container.innerHTML = '<p class="text-xs text-gray-500 dark:text-gray-400 text-center py-4">No services enabled</p>';
        return;
    }
    
    container.innerHTML = services.map(svc => {
        const iconPath = LOG_SERVICE_ICONS[svc.icon] || LOG_SERVICE_ICONS.file;
        const isActive = svc.id === logsState.activeService;
        const countStr = svc.log_count >= 1000 ? (svc.log_count / 1000).toFixed(1) + 'K' : svc.log_count.toString();
        
        return `
            <button onclick="selectLogService('${svc.id}')" 
                id="log-svc-${svc.id}"
                class="w-full flex items-center gap-2 px-3 py-2 rounded-md text-left text-sm transition-colors log-service-btn ${
                    isActive 
                    ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-700' 
                    : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                }" data-service="${svc.id}">
                <svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${iconPath}"></path>
                </svg>
                <span class="flex-1 truncate font-medium">${escapeHtml(svc.name)}</span>
                <span class="text-xs text-gray-400 dark:text-gray-500 font-mono">${countStr}</span>
            </button>
        `;
    }).join('');
}


function filterLogServices(query) {
    const buttons = document.querySelectorAll('.log-service-btn');
    const q = query.toLowerCase();
    buttons.forEach(btn => {
        const service = btn.dataset.service || '';
        const text = btn.textContent.toLowerCase();
        btn.style.display = (text.includes(q) || service.includes(q)) ? '' : 'none';
    });
}

async function selectLogService(serviceId) {
    console.log('[LOGS] Selecting service:', serviceId);
    logsState.activeService = serviceId;
    logsState.entryCount = 0;
    
    // Update sidebar active state
    document.querySelectorAll('.log-service-btn').forEach(btn => {
        const isActive = btn.dataset.service === serviceId;
        if (isActive) {
            btn.className = btn.className.replace(
                /text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700/g, ''
            );
            btn.classList.add('bg-blue-50', 'dark:bg-blue-900/30', 'text-blue-700', 'dark:text-blue-300', 'border', 'border-blue-200', 'dark:border-blue-700');
            btn.classList.remove('hover:bg-gray-100', 'dark:hover:bg-gray-700');
        } else {
            btn.classList.remove('bg-blue-50', 'dark:bg-blue-900/30', 'text-blue-700', 'dark:text-blue-300', 'border', 'border-blue-200', 'dark:border-blue-700');
            btn.classList.add('text-gray-700', 'dark:text-gray-300', 'hover:bg-gray-100', 'dark:hover:bg-gray-700');
        }
    });
    
    // Update status bar
    const activeServiceEl = document.getElementById('logs-active-service');
    if (activeServiceEl) activeServiceEl.textContent = serviceId;
    
    // Clear output
    const output = document.getElementById('logs-output');
    if (output) {
        output.innerHTML = '<span class="text-gray-500">Loading logs...</span>';
    }
    
    // Reset date range
    logsState.dateRange = null;
    logsState.timeRangeMinutes = '';
    const fromInput = document.getElementById('logs-date-from');
    const toInput = document.getElementById('logs-date-to');
    if (fromInput) fromInput.value = '';
    if (toInput) toInput.value = '';
    
    // Load smart filters
    await loadSmartFilters(serviceId);
    
    // Fetch initial logs
    await fetchInitialLogs(serviceId);
    
    // Connect WebSocket
    await connectLogWebSocket(serviceId);
}

async function loadSmartFilters(serviceId) {
    const container = document.getElementById('logs-smart-filters');
    const chipsContainer = document.getElementById('logs-smart-filter-chips');
    if (!container || !chipsContainer) return;
    
    try {
        const response = await authenticatedFetch(`/api/raw-logs/${serviceId}/smart-filters`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const data = await response.json();
        logsState.smartFilters = data.filters || [];
        logsState.activeSmartFilters = [];
        
        if (logsState.smartFilters.length === 0) {
            container.classList.add('hidden');
            return;
        }
        
        container.classList.remove('hidden');
        
        const colorClasses = {
            red: 'border-red-300 dark:border-red-700 text-red-700 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20',
            orange: 'border-orange-300 dark:border-orange-700 text-orange-700 dark:text-orange-400 hover:bg-orange-50 dark:hover:bg-orange-900/20',
            yellow: 'border-yellow-300 dark:border-yellow-700 text-yellow-700 dark:text-yellow-400 hover:bg-yellow-50 dark:hover:bg-yellow-900/20',
            blue: 'border-blue-300 dark:border-blue-700 text-blue-700 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20',
        };
        
        const activeColorClasses = {
            red: 'bg-red-500 border-red-500 text-white',
            orange: 'bg-orange-500 border-orange-500 text-white',
            yellow: 'bg-yellow-500 border-yellow-500 text-white',
            blue: 'bg-blue-500 border-blue-500 text-white',
        };
        
        chipsContainer.innerHTML = logsState.smartFilters.map(f => {
            const colors = colorClasses[f.color] || colorClasses.blue;
            return `<button onclick="toggleSmartFilter('${f.id}')" 
                id="smart-filter-${f.id}"
                class="px-2.5 py-1 text-xs font-medium rounded-full border transition-colors ${colors}"
                title="${escapeHtml(f.description || '')}"
                data-filter-id="${f.id}" data-color="${f.color}">
                ${escapeHtml(f.label)}
            </button>`;
        }).join('');
        
    } catch (error) {
        console.error('[LOGS] Failed to load smart filters:', error);
        container.classList.add('hidden');
    }
}

async function toggleSmartFilter(filterId) {
    const idx = logsState.activeSmartFilters.indexOf(filterId);
    if (idx >= 0) {
        logsState.activeSmartFilters.splice(idx, 1);
    } else {
        logsState.activeSmartFilters.push(filterId);
    }
    
    // Update chip visual
    const colorClasses = {
        red: { inactive: 'border-red-300 dark:border-red-700 text-red-700 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20', active: 'bg-red-500 border-red-500 text-white' },
        orange: { inactive: 'border-orange-300 dark:border-orange-700 text-orange-700 dark:text-orange-400 hover:bg-orange-50 dark:hover:bg-orange-900/20', active: 'bg-orange-500 border-orange-500 text-white' },
        yellow: { inactive: 'border-yellow-300 dark:border-yellow-700 text-yellow-700 dark:text-yellow-400 hover:bg-yellow-50 dark:hover:bg-yellow-900/20', active: 'bg-yellow-500 border-yellow-500 text-white' },
        blue: { inactive: 'border-blue-300 dark:border-blue-700 text-blue-700 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20', active: 'bg-blue-500 border-blue-500 text-white' },
    };
    
    const btn = document.getElementById(`smart-filter-${filterId}`);
    if (btn) {
        const color = btn.dataset.color || 'blue';
        const isActive = logsState.activeSmartFilters.includes(filterId);
        const classes = colorClasses[color] || colorClasses.blue;
        
        // Reset classes
        btn.className = `px-2.5 py-1 text-xs font-medium rounded-full border transition-colors ${isActive ? classes.active : classes.inactive}`;
    }
    
    // Client-side filter: show/hide existing log lines
    applyLogFilter();
}

async function fetchInitialLogs(serviceId) {
    // Reflect the persisted sort order on the toolbar button
    updateLogSortButton();
    try {
        const limit = 500;
        const countParams = new URLSearchParams({ page: 1, limit: limit, order: 'asc' });
        
        const response = await authenticatedFetch(`/api/raw-logs/${serviceId}?${countParams}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const data = await response.json();
        const total = data.total || 0;
        const totalPages = Math.max(1, Math.ceil(total / limit));
        
        // Store pagination state
        logsState.totalEntries = total;
        logsState.totalPages = totalPages;
        logsState.currentPage = totalPages;
        logsState.oldestPageLoaded = totalPages;
        
        if (totalPages === 1) {
            // Only one page - use what we already have
            renderLogEntries(data.data || [], serviceId, true);
        } else {
            // Fetch the last page (newest entries)
            const lastParams = new URLSearchParams({ page: totalPages, limit: limit, order: 'asc' });
            const lastResp = await authenticatedFetch(`/api/raw-logs/${serviceId}?${lastParams}`);
            if (!lastResp.ok) throw new Error(`HTTP ${lastResp.status}`);
            const lastData = await lastResp.json();
            renderLogEntries(lastData.data || [], serviceId, true);
        }
        
        logsState.entryCount = total;
        updateLogStatusBar();
        setupTerminalScrollHandler();
        
    } catch (error) {
        console.error('[LOGS] Failed to fetch logs:', error);
        const output = document.getElementById('logs-output');
        if (output) {
            output.innerHTML = `<span class="text-red-400">Failed to load logs: ${escapeHtml(error.message)}</span>`;
        }
    }
}

async function fetchOlderLogs() {
    if (logsState.isLoadingMore || logsState.oldestPageLoaded <= 1) return;
    
    logsState.isLoadingMore = true;
    const pageToLoad = logsState.oldestPageLoaded - 1;
    
    // Show loading indicator at the history edge (top normally, bottom in
    // newest-first mode)
    const output = document.getElementById('logs-output');
    let loader = document.getElementById('logs-load-more-indicator');
    if (!loader && output) {
        loader = document.createElement('div');
        loader.id = 'logs-load-more-indicator';
        loader.className = 'text-center text-blue-400 py-2 text-xs';
        loader.innerHTML = '⟳ Loading older logs...';
        if (logsState.newestFirst) {
            output.appendChild(loader);
        } else {
            output.insertBefore(loader, output.firstChild);
        }
    }
    
    try {
        const params = new URLSearchParams({
            page: pageToLoad,
            limit: 500,
            order: 'asc'
        });
        
        const response = await authenticatedFetch(`/api/raw-logs/${logsState.activeService}?${params}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const data = await response.json();
        const entries = data.data || [];
        
        if (entries.length > 0) {
            logsState.oldestPageLoaded = pageToLoad;
            
            // Preserve scroll position
            const terminal = document.getElementById('logs-terminal');
            const prevScrollHeight = terminal ? terminal.scrollHeight : 0;
            
            // Insert older entries (top normally, bottom in newest-first mode)
            renderLogEntries(entries, logsState.activeService, false, true);

            // Restore scroll position (keep user at same visual point).
            // Only needed when history is inserted at the top - appending at
            // the bottom (newest-first mode) doesn't move the viewport.
            if (terminal && !logsState.newestFirst) {
                const newScrollHeight = terminal.scrollHeight;
                terminal.scrollTop = newScrollHeight - prevScrollHeight;
            }
        }
        
        // Remove loader
        if (loader) loader.remove();
        
        // Update status
        updateLogStatusBar();
        
    } catch (error) {
        console.error('[LOGS] Failed to load older logs:', error);
        if (loader) loader.textContent = '✕ Failed to load older logs';
        setTimeout(() => { if (loader) loader.remove(); }, 3000);
    } finally {
        logsState.isLoadingMore = false;
    }
}

function setupTerminalScrollHandler() {
    const terminal = document.getElementById('logs-terminal');
    if (!terminal || terminal._scrollHandlerAttached) return;
    
    terminal.addEventListener('scroll', () => {
        // Load older entries when scrolled near the history edge (within
        // 50px): the top normally, the bottom in newest-first mode
        if (logsState.isLoadingMore || logsState.oldestPageLoaded <= 1) return;
        const nearHistoryEdge = logsState.newestFirst
            ? terminal.scrollTop + terminal.clientHeight > terminal.scrollHeight - 50
            : terminal.scrollTop < 50;
        if (nearHistoryEdge) {
            fetchOlderLogs();
        }
    });
    terminal._scrollHandlerAttached = true;
}

/** Check if an entry matches both search query and active smart filters */
function entryMatchesFilters(entry) {
    const searchText = getEntrySearchText(entry).toLowerCase();
    
    // Check text search
    if (logsState.searchQuery) {
        if (!searchText.includes(logsState.searchQuery.toLowerCase())) {
            return false;
        }
    }
    
    // Check smart filters (entry must match at least one active filter)
    if (logsState.activeSmartFilters.length > 0) {
        const matchesAnyFilter = logsState.activeSmartFilters.some(filterId => {
            const filterDef = logsState.smartFilters.find(f => f.id === filterId);
            if (!filterDef) return false;
            
            // Each filter has a 'pattern' and a 'field' (program or message)
            const pattern = (filterDef.pattern || '').toLowerCase();
            if (!pattern) return false;
            
            const field = filterDef.field || 'message';
            const fieldValue = (entry[field] || '').toLowerCase();
            return fieldValue.includes(pattern);
        });
        if (!matchesAnyFilter) return false;
    }
    
    return true;
}

// Cap on live-stream entries kept in memory/DOM. Without it the WebSocket
// stream grows the page unboundedly and a busy server degrades the tab
// within hours. Oldest lines are dropped; auto-scroll favors the tail anyway.
const MAX_LIVE_LOG_ENTRIES = 5000;

function renderLogEntries(entries, serviceId, replace = false, prepend = false) {
    const output = document.getElementById('logs-output');
    if (!output) return;
    
    if (replace) {
        output.innerHTML = '';
        logsState.allEntries = [];
    }
    
    // Store entries
    if (prepend) {
        logsState.allEntries = entries.concat(logsState.allEntries);
    } else {
        logsState.allEntries = logsState.allEntries.concat(entries);
    }
    
    if (logsState.allEntries.length === 0 && replace) {
        output.innerHTML = '<span class="text-gray-500">No log entries found.</span>';
        return;
    }
    
    const fragment = document.createDocumentFragment();
    const hasFilters = logsState.searchQuery || logsState.activeSmartFilters.length > 0;

    // In newest-first mode the DOM is the exact reverse of chronological
    // order, so each batch is built reversed before insertion
    const domEntries = logsState.newestFirst ? entries.slice().reverse() : entries;

    domEntries.forEach(entry => {
        const line = document.createElement('div');
        line.className = 'log-line';
        line.style.padding = '1px 0';

        // Store the raw entry as data for search
        line._rawEntry = entry;

        const formatted = formatLogLine(entry, serviceId);
        line.innerHTML = formatted;

        // If there are active filters, check if this entry matches
        if (hasFilters && !entryMatchesFilters(entry)) {
            line.style.display = 'none';
            line.classList.add('log-filtered');
        }

        fragment.appendChild(line);
    });

    // prepend = older history; otherwise newer entries. Where each goes in
    // the DOM depends on the display order.
    const insertAtTop = logsState.newestFirst ? !prepend : prepend;
    if (insertAtTop && output.firstChild) {
        output.insertBefore(fragment, output.firstChild);
    } else {
        output.appendChild(fragment);
    }

    // Trim oldest entries beyond the cap (live stream only - prepend means
    // the user is deliberately paging back through history). The oldest
    // lines sit at the top normally, at the bottom in newest-first mode.
    if (!prepend && logsState.allEntries.length > MAX_LIVE_LOG_ENTRIES) {
        const excess = logsState.allEntries.length - MAX_LIVE_LOG_ENTRIES;
        logsState.allEntries.splice(0, excess);
        for (let i = 0; i < excess; i++) {
            const victim = logsState.newestFirst ? output.lastChild : output.firstChild;
            if (!victim) break;
            output.removeChild(victim);
        }
    }

    // Update filter badge if filters are active
    if (hasFilters) {
        const allLines = output.querySelectorAll('.log-line');
        const visibleCount = output.querySelectorAll('.log-line:not(.log-filtered)').length;
        updateFilterBadge(true, visibleCount, allLines.length);
    }

    // Auto-scroll to the newest entry (only for new entries, not when
    // loading older) - bottom normally, top in newest-first mode
    if (logsState.autoScroll && !prepend) {
        const terminal = document.getElementById('logs-terminal');
        if (terminal) {
            terminal.scrollTop = logsState.newestFirst ? 0 : terminal.scrollHeight;
        }
    }
}

/** Toggle log display order (issue #69) and re-render from stored entries */
function toggleLogSortOrder() {
    logsState.newestFirst = !logsState.newestFirst;
    localStorage.setItem('logsNewestFirst', logsState.newestFirst ? 'true' : 'false');
    updateLogSortButton();
    // Re-render the current buffer in the new order (copy: replace resets allEntries)
    renderLogEntries(logsState.allEntries.slice(), logsState.activeService, true);
}

function updateLogSortButton() {
    const label = document.getElementById('logs-sort-text');
    if (label) {
        label.textContent = logsState.newestFirst ? 'Newest first' : 'Newest last';
    }
    // Arrow points to where the newest entry lives: up = top, down = bottom
    const icon = document.getElementById('logs-sort-icon');
    if (icon) {
        icon.setAttribute('d', logsState.newestFirst
            ? 'M3 4h13M3 8h9m-9 4h6m4 0l4-4m0 0l4 4m-4-4v12'   // bars + arrow up
            : 'M3 4h13M3 8h9m-9 4h9m5-4v12m0 0l-4-4m4 4l4-4'); // bars + arrow down
    }
}

/** Get searchable text from a raw log entry */
function getEntrySearchText(entry) {
    // Build a single string from all fields for searching
    const parts = [];
    if (entry.message) parts.push(entry.message);
    if (entry.program) parts.push(entry.program);
    if (entry.uri) parts.push(entry.uri);
    if (entry.method) parts.push(entry.method);
    if (entry.remote) parts.push(entry.remote);
    if (entry.data) parts.push(String(entry.data));
    if (entry.service) parts.push(entry.service);
    if (entry.priority) parts.push(entry.priority);
    // Rspamd history fields
    if (entry.subject) parts.push(entry.subject);
    if (entry.sender_smtp) parts.push(entry.sender_smtp);
    if (entry.sender_mime) parts.push(entry.sender_mime);
    if (entry.rcpt_smtp) parts.push(Array.isArray(entry.rcpt_smtp) ? entry.rcpt_smtp.join(' ') : String(entry.rcpt_smtp));
    if (entry.rcpt_mime) parts.push(Array.isArray(entry.rcpt_mime) ? entry.rcpt_mime.join(' ') : String(entry.rcpt_mime));
    if (entry.action) parts.push(entry.action);
    if (entry.ip) parts.push(entry.ip);
    if (entry.user) parts.push(entry.user);
    return parts.join(' ');
}

function formatLogLine(entry, serviceId) {
    const timeVal = entry.time || entry.unix_time;
    const time = timeVal ? escapeHtml(formatLogTimestamp(timeVal)) : '';
    
    // Build the display message based on service type
    let displayContent = '';
    let lineColor = 'text-gray-300';
    let programStr = '';
    
    switch (serviceId) {
        case 'api':
            // API: { time, uri, method, remote, data }
            const method = escapeHtml(entry.method || '');
            const uri = escapeHtml(entry.uri || '');
            const remote = escapeHtml(entry.remote || '');
            const data = entry.data ? escapeHtml(String(entry.data).substring(0, 200)) : '';
            
            // Color by method
            const methodColors = { GET: 'text-green-400', POST: 'text-yellow-400', PUT: 'text-blue-400', DELETE: 'text-red-400' };
            const methodColor = methodColors[entry.method] || 'text-gray-300';
            
            displayContent = `<span class="${methodColor} font-bold">${method}</span> <span class="text-gray-200">${uri}</span> <span class="text-gray-500">from</span> <span class="text-purple-400">${remote}</span>`;
            if (data) {
                displayContent += ` <span class="text-gray-500">${data}</span>`;
            }
            lineColor = methodColor;
            break;
            
        case 'watchdog':
            // Watchdog: { time, service, lvl, hpnow, hptotal, hpdiff }
            const wdService = escapeHtml(entry.service || '');
            const lvl = parseInt(entry.lvl || '0');
            const hpnow = escapeHtml(entry.hpnow || '?');
            const hptotal = escapeHtml(entry.hptotal || '?');
            const hpdiff = parseInt(entry.hpdiff || '0');
            
            // Color by health
            if (hpdiff < 0 || lvl > 200) {
                lineColor = 'text-red-400';
            } else if (lvl > 100) {
                lineColor = 'text-yellow-400';
            } else {
                lineColor = 'text-green-400';
            }
            
            const hpBar = `${hpnow}/${hptotal}`;
            const diffStr = hpdiff > 0 ? `+${hpdiff}` : String(hpdiff);
            displayContent = `<span class="text-cyan-400">${wdService}</span> <span class="${lineColor}">HP: ${hpBar}</span> <span class="text-gray-500">(${diffStr})</span> <span class="text-gray-500">lvl:${lvl}</span>`;
            break;
            
        case 'rspamd-history': {
            // Rspamd history: { unix_time, sender_smtp, rcpt_smtp, subject, score, action, ip, symbols, ... }
            const score = parseFloat(entry.score || 0);
            const action = escapeHtml(entry.action || 'unknown');
            const sender = escapeHtml(entry.sender_smtp || entry.sender_mime || '');
            const rcpts = (entry.rcpt_smtp || entry.rcpt_mime || []);
            const recipient = escapeHtml(Array.isArray(rcpts) ? rcpts.join(', ') : String(rcpts));
            const subject = escapeHtml((entry.subject || '').substring(0, 80));
            const ip = escapeHtml(entry.ip || '');
            
            // Score color: green = ham, yellow = greylist zone, red = spam/reject
            const rejectThreshold = entry.thresholds?.reject || 15;
            const addHeaderThreshold = entry.thresholds?.['add header'] || 8;
            let scoreColor = 'text-green-400';
            if (score >= rejectThreshold) {
                scoreColor = 'text-red-400';
                lineColor = 'text-red-400';
            } else if (score >= addHeaderThreshold) {
                scoreColor = 'text-orange-400';
                lineColor = 'text-yellow-400';
            } else if (score >= 0) {
                scoreColor = 'text-yellow-400';
            } else {
                scoreColor = 'text-green-400';
            }
            
            // Action color
            const actionColors = {
                'reject': 'text-red-400',
                'greylist': 'text-yellow-400',
                'add header': 'text-orange-400',
                'rewrite subject': 'text-orange-400',
                'soft reject': 'text-yellow-400',
                'no action': 'text-green-400',
            };
            const actionColor = actionColors[entry.action] || 'text-gray-400';

            displayContent = `<span class="text-gray-300">${sender}</span> <span class="text-gray-500">→</span> <span class="text-gray-300">${recipient}</span> <span class="text-gray-500">subj:</span><span class="text-gray-400" dir="auto">${subject}</span> <span class="${scoreColor} font-bold">[${score.toFixed(1)}]</span> <span class="${actionColor}">${action}</span>`;
            if (ip) {
                displayContent += ` <span class="text-gray-600">${ip}</span>`;
            }
            break;
        }
            
        default:
            // Standard format: { time, program, priority, message }
            // Used by: postfix, dovecot, sogo, netfilter, acme, ratelimited
            const message = escapeHtml(entry.message || '');
            programStr = escapeHtml(entry.program || '');
            
            // Color code based on message content
            const msgLower = (entry.message || '').toLowerCase();
            if (msgLower.includes('reject') || msgLower.includes('error') || msgLower.includes('blocked') || 
                msgLower.includes('denied') || msgLower.includes('failed') || msgLower.includes('fatal')) {
                lineColor = 'text-red-400';
            } else if (msgLower.includes('warning') || msgLower.includes('pregreet') || msgLower.includes('timeout')) {
                lineColor = 'text-yellow-400';
            } else if (msgLower.includes('sent') || msgLower.includes('connect from') || msgLower.includes('login') ||
                       msgLower.includes('delivered') || msgLower.includes('success')) {
                lineColor = 'text-green-400';
            } else if (msgLower.includes('disconnect') || msgLower.includes('removed') || msgLower.includes('noqueue')) {
                lineColor = 'text-gray-400';
            }
            
            displayContent = message;
            break;
    }
    
    // Highlight search terms
    if (logsState.searchQuery && displayContent) {
        const regex = new RegExp(`(${escapeRegex(logsState.searchQuery)})`, 'gi');
        displayContent = displayContent.replace(regex, '<mark class="bg-yellow-500/40 text-yellow-200 rounded px-0.5">$1</mark>');
    }
    
    // Assemble final line
    if (serviceId === 'api' || serviceId === 'watchdog' || serviceId === 'rspamd-history') {
        // Custom format - content is already fully formatted
        return `<span class="text-blue-400">${time}</span> ${displayContent}`;
    } else if (time && programStr) {
        return `<span class="text-blue-400">${time}</span> <span class="text-cyan-400">${programStr}</span>: <span class="${lineColor}">${displayContent}</span>`;
    } else if (time) {
        return `<span class="text-blue-400">${time}</span> <span class="${lineColor}">${displayContent}</span>`;
    } else {
        return `<span class="${lineColor}">${displayContent || escapeHtml(JSON.stringify(entry))}</span>`;
    }
}

function formatLogTimestamp(timeVal) {
    try {
        let date;
        const numVal = Number(timeVal);
        if (!isNaN(numVal) && numVal > 0) {
            date = new Date(numVal * 1000);
        } else {
            date = new Date(timeVal);
        }
        
        if (isNaN(date.getTime())) return String(timeVal);
        
        // Use the same format as the Messages page (DD.MM.YYYY, HH:mm:ss)
        const options = {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        };
        
        if (appTimezone && appTimezone !== 'UTC') {
            options.timeZone = appTimezone;
        }
        
        return date.toLocaleString(undefined, options);
    } catch {
        return String(timeVal);
    }
}

// =============================================================================
// WEBSOCKET
// =============================================================================

async function connectLogWebSocket(serviceId) {
    // Disconnect existing connection
    disconnectLogWebSocket();
    
    if (logsState.isPaused) return;
    
    try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        let wsUrl = `${protocol}//${window.location.host}/ws/raw-logs?service=${serviceId}`;
        
        // Fetch a one-time auth token via the authenticated REST API
        try {
            const tokenResp = await authenticatedFetch('/api/raw-logs/ws-token');
            if (tokenResp.ok) {
                const tokenData = await tokenResp.json();
                if (tokenData.token) {
                    wsUrl += `&token=${encodeURIComponent(tokenData.token)}`;
                }
            }
        } catch (e) {
            console.warn('[LOGS WS] Could not fetch WS token:', e.message);
        }
        
        console.log('[LOGS WS] Connecting...');
        logsState.ws = new WebSocket(wsUrl);
        
        logsState.ws.onopen = () => {
            console.log('[LOGS WS] Connected');
            logsState.isConnected = true;
            updateWsIndicator(true);
        };
        
        logsState.ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                
                if (data.type === 'new_logs' && data.entries && data.entries.length > 0) {
                    if (!logsState.isPaused) {
                        renderLogEntries(data.entries, data.service, false);
                        logsState.entryCount += data.entries.length;
                        logsState.totalEntries = logsState.entryCount;
                        logsState.lastUpdateTime = new Date();
                        updateLogStatusBar();
                    }
                } else if (data.type === 'service_counts' && data.counts) {
                    // Update all sidebar badges with fresh DB counts
                    const fmtNum = (n) => n >= 1000 ? (n / 1000).toFixed(1) + 'K' : n.toString();
                    for (const [svcId, count] of Object.entries(data.counts)) {
                        const btn = document.getElementById(`log-svc-${svcId}`);
                        if (!btn) continue;
                        const badge = btn.querySelector('.font-mono');
                        if (badge) badge.textContent = fmtNum(count);
                    }
                    // Keep active service's totalEntries in sync
                    if (logsState.activeService && data.counts[logsState.activeService] !== undefined) {
                        logsState.totalEntries = data.counts[logsState.activeService];
                        logsState.entryCount = data.counts[logsState.activeService];
                        updateLogStatusBar();
                    }
                } else if (data.type === 'error') {
                    console.warn('[LOGS WS] Server error:', data.message);
                    // Don't reconnect on auth errors
                    if (data.message && data.message.includes('Authentication')) {
                        logsState._authFailed = true;
                    }
                } else if (data.type === 'connected' || data.type === 'subscribed') {
                    console.log('[LOGS WS]', data.message);
                }
            } catch (e) {
                console.error('[LOGS WS] Message parse error:', e);
            }
        };
        
        logsState.ws.onclose = (event) => {
            console.log('[LOGS WS] Disconnected:', event.code, event.reason);
            logsState.isConnected = false;
            updateWsIndicator(false);
            
            // Don't reconnect on authentication failure
            if (event.code === 4401 || logsState._authFailed) {
                console.warn('[LOGS WS] Authentication failed - not reconnecting');
                logsState._authFailed = false;
                return;
            }
            
            // Auto-reconnect after 3 seconds (only if still on logs tab)
            if (currentTab === 'logs' && !logsState.isPaused) {
                setTimeout(() => {
                    if (currentTab === 'logs' && !logsState.isPaused) {
                        connectLogWebSocket(logsState.activeService);
                    }
                }, 3000);
            }
        };
        
        logsState.ws.onerror = (error) => {
            console.error('[LOGS WS] Error:', error);
            logsState.isConnected = false;
            updateWsIndicator(false);
        };
        
    } catch (error) {
        console.error('[LOGS WS] Connection error:', error);
        updateWsIndicator(false);
    }
}

function disconnectLogWebSocket() {
    if (logsState.ws) {
        logsState.ws.onclose = null; // Prevent auto-reconnect
        logsState.ws.close();
        logsState.ws = null;
    }
    logsState.isConnected = false;
    updateWsIndicator(false);
}

function updateWsIndicator(connected) {
    const indicator = document.getElementById('logs-ws-indicator');
    const status = document.getElementById('logs-ws-status');
    
    if (indicator) {
        indicator.className = `w-2 h-2 rounded-full ${connected ? 'bg-green-500' : logsState.isPaused ? 'bg-yellow-500' : 'bg-red-500'}`;
    }
    if (status) {
        status.textContent = connected ? 'Connected' : logsState.isPaused ? 'Paused' : 'Disconnected';
    }
}

function updateLogStatusBar() {
    const countEl = document.getElementById('logs-entry-count');
    const updateEl = document.getElementById('logs-last-update');
    
    const fmtNum = (n) => n >= 1000 ? (n / 1000).toFixed(1) + 'K' : n.toString();
    
    if (countEl) {
        const loaded = logsState.allEntries.length;
        const total = logsState.totalEntries || logsState.entryCount;
        
        if (total > loaded) {
            countEl.textContent = `${fmtNum(loaded)} of ${fmtNum(total)} entries`;
        } else {
            countEl.textContent = `${fmtNum(total)} entries`;
        }
    }
    
    if (updateEl) {
        if (logsState.lastUpdateTime) {
            const seconds = Math.floor((new Date() - logsState.lastUpdateTime) / 1000);
            updateEl.textContent = `Last update: ${seconds}s ago`;
        } else {
            updateEl.textContent = 'Last update: just now';
        }
    }
}

// =============================================================================
// CONTROLS
// =============================================================================

function toggleLogPause() {
    logsState.isPaused = !logsState.isPaused;
    
    const btn = document.getElementById('logs-pause-btn');
    const text = document.getElementById('logs-pause-text');
    const icon = document.getElementById('logs-pause-icon');
    
    if (logsState.isPaused) {
        // Paused → show Resume
        if (text) text.textContent = 'Resume';
        if (icon) icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>';
        if (btn) {
            btn.classList.add('border-yellow-500', 'bg-yellow-500', 'text-white');
            btn.classList.remove('border-gray-300', 'dark:border-gray-600', 'text-gray-700', 'dark:text-gray-300');
        }
        disconnectLogWebSocket();
    } else {
        // Resumed → show Pause
        if (text) text.textContent = 'Pause';
        if (icon) icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>';
        if (btn) {
            btn.classList.remove('border-yellow-500', 'bg-yellow-500', 'text-white');
            btn.classList.add('border-gray-300', 'dark:border-gray-600', 'text-gray-700', 'dark:text-gray-300');
        }
        connectLogWebSocket(logsState.activeService);
    }
    
    updateWsIndicator(logsState.isConnected);
}

function toggleAutoScroll() {
    logsState.autoScroll = !logsState.autoScroll;
    
    const btn = document.getElementById('logs-autoscroll-btn');
    if (btn) {
        if (logsState.autoScroll) {
            btn.classList.add('border-blue-500', 'bg-blue-500', 'text-white');
            btn.classList.remove('border-gray-300', 'dark:border-gray-600', 'text-gray-700', 'dark:text-gray-300');
        } else {
            btn.classList.remove('border-blue-500', 'bg-blue-500', 'text-white');
            btn.classList.add('border-gray-300', 'dark:border-gray-600', 'text-gray-700', 'dark:text-gray-300');
        }
    }
    
    if (logsState.autoScroll) {
        const terminal = document.getElementById('logs-terminal');
        if (terminal) terminal.scrollTop = terminal.scrollHeight;
    }
}

function setLogFontSize(size) {
    logsState.fontSize = parseInt(size);
    const output = document.getElementById('logs-output');
    if (output) {
        output.style.fontSize = `${logsState.fontSize}px`;
    }
}

function toggleWordWrap() {
    logsState.wordWrap = !logsState.wordWrap;
    
    const output = document.getElementById('logs-output');
    const btn = document.getElementById('logs-wrap-btn');
    
    if (output) {
        output.style.whiteSpace = logsState.wordWrap ? 'pre-wrap' : 'pre';
        output.style.wordWrap = logsState.wordWrap ? 'break-word' : 'normal';
    }
    
    if (btn) {
        if (logsState.wordWrap) {
            btn.classList.add('border-blue-500', 'bg-blue-500', 'text-white');
            btn.classList.remove('border-gray-300', 'dark:border-gray-600', 'text-gray-700', 'dark:text-gray-300');
        } else {
            btn.classList.remove('border-blue-500', 'bg-blue-500', 'text-white');
            btn.classList.add('border-gray-300', 'dark:border-gray-600', 'text-gray-700', 'dark:text-gray-300');
        }
    }
}

function searchLogs() {
    const input = document.getElementById('logs-search-input');
    logsState.searchQuery = input ? input.value.trim() : '';
    
    // Client-side filter: show/hide existing log lines
    applyLogFilter();
}

/** Fill date inputs with a preset (minutes ago → now) */
function setLogTimePreset(minutes) {
    const now = new Date();
    const from = new Date(now.getTime() - minutes * 60 * 1000);
    
    // Format for datetime-local input (YYYY-MM-DDTHH:MM)
    const fmt = (d) => {
        const pad = (n) => String(n).padStart(2, '0');
        return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
    };
    
    const fromInput = document.getElementById('logs-date-from');
    const toInput = document.getElementById('logs-date-to');
    if (fromInput) fromInput.value = fmt(from);
    if (toInput) toInput.value = fmt(now);
    
    // Auto-load
    loadDateRangeLogs();
}

/** Load ALL logs within the selected date range */
async function loadDateRangeLogs() {
    const fromInput = document.getElementById('logs-date-from');
    const toInput = document.getElementById('logs-date-to');
    const loadingEl = document.getElementById('logs-range-loading');
    
    const startDate = fromInput?.value ? new Date(fromInput.value).toISOString() : null;
    const endDate = toInput?.value ? new Date(toInput.value).toISOString() : null;
    
    if (!startDate) {
        // No date selected - do nothing
        return;
    }
    
    // Show loading state
    if (loadingEl) loadingEl.classList.remove('hidden');
    const loadBtn = document.getElementById('logs-load-range-btn');
    if (loadBtn) loadBtn.disabled = true;
    
    try {
        // Store the date range in state
        logsState.dateRange = { start: startDate, end: endDate };
        logsState.timeRangeMinutes = '';  // not using minute-based anymore
        
        // Mark Live as inactive
        setLiveButtonActive(false);
        
        // Fetch page 1 to know overall total
        const params = new URLSearchParams({ page: 1, limit: 1000, order: 'asc' });
        params.set('start_date', startDate);
        if (endDate) params.set('end_date', endDate);
        
        const response = await authenticatedFetch(`/api/raw-logs/${logsState.activeService}?${params}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const data = await response.json();
        const total = data.total || 0;
        const limit = 1000;
        const totalPages = Math.max(1, Math.ceil(total / limit));
        
        // Render the first page
        renderLogEntries(data.data || [], logsState.activeService, true);
        
        // Fetch remaining pages
        for (let page = 2; page <= totalPages; page++) {
            if (loadingEl) loadingEl.textContent = `Loading page ${page}/${totalPages}...`;
            
            const nextParams = new URLSearchParams({ page, limit, order: 'asc' });
            nextParams.set('start_date', startDate);
            if (endDate) nextParams.set('end_date', endDate);
            
            const nextResp = await authenticatedFetch(`/api/raw-logs/${logsState.activeService}?${nextParams}`);
            if (!nextResp.ok) break;
            
            const nextData = await nextResp.json();
            renderLogEntries(nextData.data || [], logsState.activeService, false);
        }
        
        // Update state
        logsState.totalEntries = total;
        logsState.entryCount = total;
        logsState.oldestPageLoaded = 1;  // we loaded everything
        logsState.totalPages = 1;
        updateLogStatusBar();
        
        // Re-apply filters
        if (logsState.searchQuery || logsState.activeSmartFilters.length > 0) {
            applyLogFilter();
        }
        
    } catch (error) {
        console.error('[LOGS] Date range load failed:', error);
        const output = document.getElementById('logs-output');
        if (output) {
            output.innerHTML = `<span class="text-red-400">Failed to load date range: ${escapeHtml(error.message)}</span>`;
        }
    } finally {
        if (loadingEl) {
            loadingEl.textContent = 'Loading...';
            loadingEl.classList.add('hidden');
        }
        if (loadBtn) loadBtn.disabled = false;
    }
}

/** Reset to live mode - load latest entries + reconnect WS */
async function resetToLiveLogs() {
    // Clear date range state
    logsState.dateRange = null;
    logsState.timeRangeMinutes = '';
    
    // Clear date inputs
    const fromInput = document.getElementById('logs-date-from');
    const toInput = document.getElementById('logs-date-to');
    if (fromInput) fromInput.value = '';
    if (toInput) toInput.value = '';
    
    // Mark Live as active
    setLiveButtonActive(true);
    
    // Re-fetch latest logs
    await fetchInitialLogs(logsState.activeService);
    
    // Reconnect WebSocket
    await connectLogWebSocket(logsState.activeService);
}

function setLiveButtonActive(active) {
    const btn = document.getElementById('logs-live-btn');
    if (!btn) return;
    
    if (active) {
        btn.className = 'inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-green-500 bg-green-500 text-white transition-colors';
    } else {
        btn.className = 'inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors';
    }
}

function clearLogSearch() {
    const input = document.getElementById('logs-search-input');
    if (input) input.value = '';
    logsState.searchQuery = '';
    
    // Also clear smart filters
    if (logsState.activeSmartFilters.length > 0) {
        logsState.activeSmartFilters.forEach(filterId => {
            const btn = document.getElementById(`smart-filter-${filterId}`);
            if (btn) {
                const color = btn.dataset.color || 'blue';
                const inactiveClasses = {
                    red: 'border-red-300 dark:border-red-700 text-red-700 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20',
                    orange: 'border-orange-300 dark:border-orange-700 text-orange-700 dark:text-orange-400 hover:bg-orange-50 dark:hover:bg-orange-900/20',
                    yellow: 'border-yellow-300 dark:border-yellow-700 text-yellow-700 dark:text-yellow-400 hover:bg-yellow-50 dark:hover:bg-yellow-900/20',
                    blue: 'border-blue-300 dark:border-blue-700 text-blue-700 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20',
                };
                btn.className = `px-2.5 py-1 text-xs font-medium rounded-full border transition-colors ${inactiveClasses[color] || inactiveClasses.blue}`;
            }
        });
        logsState.activeSmartFilters = [];
    }
    
    applyLogFilter();
}

function applyLogFilter() {
    const output = document.getElementById('logs-output');
    if (!output) return;
    
    const hasFilters = logsState.searchQuery || logsState.activeSmartFilters.length > 0;
    const lines = output.querySelectorAll('.log-line');
    let visibleCount = 0;
    
    lines.forEach(line => {
        if (!hasFilters) {
            // No filters - show all
            line.style.display = '';
            line.classList.remove('log-filtered');
            visibleCount++;
        } else {
            const entry = line._rawEntry;
            if (entry && entryMatchesFilters(entry)) {
                line.style.display = '';
                line.classList.remove('log-filtered');
                visibleCount++;
            } else if (!entry) {
                // Fallback for lines without _rawEntry (shouldn't happen but safe)
                line.style.display = '';
                line.classList.remove('log-filtered');
                visibleCount++;
            } else {
                line.style.display = 'none';
                line.classList.add('log-filtered');
            }
        }
    });
    
    // Update the filter badge
    updateFilterBadge(hasFilters, visibleCount, lines.length);
}

function updateFilterBadge(hasFilters, visible, total) {
    let badge = document.getElementById('logs-filter-badge');
    if (!hasFilters) {
        if (badge) badge.remove();
        return;
    }
    if (!badge) {
        badge = document.createElement('div');
        badge.id = 'logs-filter-badge';
        badge.className = 'absolute bottom-12 left-1/2 -translate-x-1/2 bg-blue-600 text-white text-xs px-3 py-1.5 rounded-full shadow-lg flex items-center gap-2 z-10';
        const terminal = document.getElementById('logs-terminal');
        if (terminal) {
            terminal.style.position = 'relative';
            terminal.appendChild(badge);
        }
    }
    // Build description of active filters
    const parts = [];
    if (logsState.searchQuery) {
        parts.push(`"${escapeHtml(logsState.searchQuery)}"`);
    }
    if (logsState.activeSmartFilters.length > 0) {
        const filterNames = logsState.activeSmartFilters.map(id => {
            const f = logsState.smartFilters.find(sf => sf.id === id);
            return f ? f.label : id;
        });
        parts.push(filterNames.join(', '));
    }
    badge.innerHTML = `<span>Showing ${visible} of ${total} - filter: <strong>${parts.join(' + ')}</strong></span>` +
        `<button onclick="clearLogSearch()" class="ml-1 hover:text-yellow-300 font-bold" title="Clear all filters">✕</button>`;
}

function clearLogDisplay() {
    // Clear display
    const output = document.getElementById('logs-output');
    if (output) {
        output.innerHTML = '<span class="text-gray-500">Display cleared. New logs will appear here.</span>';
    }
    logsState.entryCount = 0;
    logsState.allEntries = [];
    
    // Clear search
    const searchInput = document.getElementById('logs-search-input');
    if (searchInput) searchInput.value = '';
    logsState.searchQuery = '';
    
    // Clear smart filters
    if (logsState.activeSmartFilters.length > 0) {
        logsState.activeSmartFilters.forEach(filterId => {
            const chip = document.querySelector(`[data-filter-id="${filterId}"]`);
            if (chip) {
                chip.classList.remove('bg-blue-100', 'dark:bg-blue-900/40', 'text-blue-700', 'dark:text-blue-300', 'border-blue-300', 'dark:border-blue-600');
                chip.classList.add('bg-gray-100', 'dark:bg-gray-700', 'text-gray-600', 'dark:text-gray-400', 'border-gray-300', 'dark:border-gray-600');
            }
        });
        logsState.activeSmartFilters = [];
    }
    
    // Clear date range
    const fromInput = document.getElementById('logs-date-from');
    const toInput = document.getElementById('logs-date-to');
    if (fromInput) fromInput.value = '';
    if (toInput) toInput.value = '';
    logsState.dateRange = null;
    logsState.timeRangeMinutes = '';
    
    // Clear filter badge
    updateFilterBadge(false);
    
    updateLogStatusBar();
}
