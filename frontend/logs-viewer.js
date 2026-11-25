let logsState = {
    activeService: 'postfix',
    isPaused: false,
    autoScroll: true,
    newEntries: [],
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
    currentPage: 1,
    totalPages: 1,
    totalEntries: 0,
    isLoadingMore: false,
    oldestPageLoaded: 1,
    timeRangeMinutes: '',
};

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
        const response = await authenticatedFetch('/api/raw-logs/services');
        if (!response.ok) {
            throw await responseError(response);
        }
        
        const data = await response.json();
        
        if (data.raw_logs_enabled === false) {
            const output = document.getElementById('logs-output');
            if (output) {
                output.innerHTML = `<div class="ui-logs-locked">${uiLocked('Live Log Viewer is Disabled',
                    'Raw log collection is currently turned off. Enable it in Settings → Logs to start viewing live logs.')}</div>`;
            }
            const sidebar = document.getElementById('logs-service-list');
            if (sidebar) sidebar.innerHTML = '';
            return;
        }
        
        logsState.services = data.services || [];
        
        renderLogServiceList(logsState.services);
        
        const defaultService = logsState.services.find(s => s.id === 'postfix') || logsState.services[0];
        if (defaultService) {
            await selectLogService(defaultService.id);
        } else {
            const output = document.getElementById('logs-output');
            if (output) {
                output.innerHTML = `<div class="ui-logs-locked">${uiLocked('No log services available', 'Enable services in Settings → Logs.')}</div>`;
            }
        }
    } catch (error) {
        console.error('[LOGS] Failed to load log viewer:', error);
        const output = document.getElementById('logs-output');
        if (output) {
            output.innerHTML = `<span class="text-red-400">Failed to load log services: ${escapeHtml(uiErrorText(error))}</span>`;
        }
    }
}

function renderLogServiceList(services) {
    const container = document.getElementById('logs-service-list');
    if (!container) return;
    
    if (services.length === 0) {
        container.innerHTML = '<p class="ui-empty">No services enabled</p>';
        return;
    }
    
    container.innerHTML = services.map(svc => {
        const iconPath = LOG_SERVICE_ICONS[svc.icon] || LOG_SERVICE_ICONS.file;
        const isActive = svc.id === logsState.activeService;
        const countStr = svc.log_count >= 1000 ? (svc.log_count / 1000).toFixed(1) + 'K' : String(Number(svc.log_count));
        
        return `
            <button onclick="selectLogService('${escapeJsArg(svc.id)}')" id="log-svc-${escapeHtml(svc.id)}"
                class="log-service-btn ui-log-svc"${isActive ? ' aria-current="true"' : ''} data-service="${escapeHtml(svc.id)}">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${iconPath}"></path>
                </svg>
                <span class="ui-log-svc-name">${escapeHtml(svc.name)}</span>
                <small>${countStr}</small>
            </button>
        `;
    }).join('');
    updateLogServiceToggle();
}

function toggleLogServices(open) {
    const side = document.getElementById('logs-side');
    const toggle = document.getElementById('logs-side-toggle');
    if (!side) return;
    const show = typeof open === 'boolean' ? open : !side.classList.contains('is-open');
    side.classList.toggle('is-open', show);
    if (toggle) toggle.setAttribute('aria-expanded', show);
}

function updateLogServiceToggle() {
    const active = document.querySelector('#logs-service-list .ui-log-svc[aria-current="true"]');
    const name = document.getElementById('logs-side-current');
    const count = document.getElementById('logs-side-count');
    if (name) name.textContent = active ? (active.querySelector('.ui-log-svc-name') || active).textContent.trim() : '-';
    if (count) count.textContent = active && active.querySelector('small') ? active.querySelector('small').textContent.trim() : '';
}

async function selectLogService(serviceId) {
    console.log('[LOGS] Selecting service:', serviceId);
    logsState.activeService = serviceId;
    logsState.entryCount = 0;
    
    document.querySelectorAll('.log-service-btn').forEach(btn => {
        if (btn.dataset.service === serviceId) btn.setAttribute('aria-current', 'true');
        else btn.removeAttribute('aria-current');
    });
    updateLogServiceToggle();
    toggleLogServices(false);
    
    const activeServiceEl = document.getElementById('logs-active-service');
    if (activeServiceEl) activeServiceEl.textContent = serviceId;
    
    const output = document.getElementById('logs-output');
    if (output) {
        output.innerHTML = '<span class="text-gray-500">Loading logs...</span>';
    }
    
    logsState.dateRange = null;
    logsState.timeRangeMinutes = '';
    setLogDateInput(document.getElementById('logs-date-from'), null);
    setLogDateInput(document.getElementById('logs-date-to'), null);
    
    await loadSmartFilters(serviceId);
    
    await fetchInitialLogs(serviceId);
    
    await connectLogWebSocket(serviceId);
}

async function loadSmartFilters(serviceId) {
    const container = document.getElementById('logs-smart-filters');
    const chipsContainer = document.getElementById('logs-smart-filter-chips');
    if (!container || !chipsContainer) return;
    
    try {
        const response = await authenticatedFetch(`/api/raw-logs/${serviceId}/smart-filters`);
        if (!response.ok) throw await responseError(response);
        
        const data = await response.json();
        logsState.smartFilters = data.filters || [];
        logsState.activeSmartFilters = [];
        
        if (logsState.smartFilters.length === 0) {
            container.classList.add('hidden');
            return;
        }
        
        container.classList.remove('hidden');
        
        chipsContainer.innerHTML = logsState.smartFilters.map(f => `<button onclick="toggleSmartFilter('${escapeJsArg(f.id)}')"
                id="smart-filter-${escapeHtml(f.id)}" class="ui-chip ui-chip-${escapeHtml(f.color || 'blue')}" aria-pressed="false"
                title="${escapeHtml(f.description || '')}" data-filter-id="${escapeHtml(f.id)}" data-color="${escapeHtml(f.color || 'blue')}">${escapeHtml(f.label)}</button>`).join('');
        fitQuickFilters();
        
    } catch (error) {
        console.error('[LOGS] Failed to load smart filters:', error);
        container.classList.add('hidden');
    }
}

let quickFiltersOpen = false;
function fitQuickFilters() {
    const chips = document.getElementById('logs-smart-filter-chips');
    const more = document.getElementById('logs-quick-more');
    if (!chips || !more) return;
    if (!quickFiltersObserver && typeof ResizeObserver === 'function') {
        let lastWidth = 0;
        quickFiltersObserver = new ResizeObserver(entries => {
            const width = Math.round(entries[0].contentRect.width);
            if (width && width !== lastWidth) { lastWidth = width; fitQuickFilters(); }
        });
        quickFiltersObserver.observe(chips);
    }
    chips.classList.remove('is-folded');
    const first = chips.firstElementChild;
    if (!first) { more.classList.add('hidden'); return; }
    const rowH = first.offsetHeight;
    const foldH = Math.round(rowH * 1.6 + 6);
    const overflows = chips.scrollHeight > foldH + rowH;
    const activeHidden = [...chips.querySelectorAll('[aria-pressed="true"]')].some(c => c.offsetTop - chips.offsetTop > rowH);
    if (activeHidden) quickFiltersOpen = true;
    more.classList.toggle('hidden', !overflows);
    chips.classList.toggle('is-folded', overflows && !quickFiltersOpen);
    chips.style.setProperty('--ui-fold-h', `${foldH}px`);
    more.textContent = quickFiltersOpen ? 'Show less' : `Show all ${chips.children.length}`;
    more.setAttribute('aria-expanded', quickFiltersOpen);
}

function toggleQuickFilters() {
    quickFiltersOpen = !quickFiltersOpen;
    fitQuickFilters();
}
let quickFiltersObserver = null;

function toggleLogCustomRange(open) {
    const box = document.getElementById('logs-custom-range');
    const btn = document.getElementById('logs-custom-range-btn');
    if (!box) return;
    const show = typeof open === 'boolean' ? open : box.classList.contains('hidden');
    box.classList.toggle('hidden', !show);
    if (btn) { btn.setAttribute('aria-expanded', show); btn.setAttribute('aria-pressed', show); }
    if (show) { const from = document.getElementById('logs-date-from'); if (from) from.focus(); }
}

async function toggleSmartFilter(filterId) {
    const idx = logsState.activeSmartFilters.indexOf(filterId);
    if (idx >= 0) {
        logsState.activeSmartFilters.splice(idx, 1);
    } else {
        logsState.activeSmartFilters.push(filterId);
    }
    
    const btn = document.getElementById(`smart-filter-${filterId}`);
    if (btn) btn.setAttribute('aria-pressed', logsState.activeSmartFilters.includes(filterId) ? 'true' : 'false');

    applyLogFilter();
}

async function fetchInitialLogs(serviceId) {
    updateLogSortButton();
    try {
        const limit = 500;
        const countParams = new URLSearchParams({ page: 1, limit: limit, order: 'asc' });
        
        const response = await authenticatedFetch(`/api/raw-logs/${serviceId}?${countParams}`);
        if (!response.ok) throw await responseError(response);
        
        const data = await response.json();
        const total = data.total || 0;
        const totalPages = Math.max(1, Math.ceil(total / limit));
        
        logsState.totalEntries = total;
        logsState.totalPages = totalPages;
        logsState.currentPage = totalPages;
        logsState.oldestPageLoaded = totalPages;
        
        if (totalPages === 1) {
            renderLogEntries(data.data || [], serviceId, true);
        } else {
            const lastParams = new URLSearchParams({ page: totalPages, limit: limit, order: 'asc' });
            const lastResp = await authenticatedFetch(`/api/raw-logs/${serviceId}?${lastParams}`);
            if (!lastResp.ok) throw await responseError(lastResp);
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
            output.innerHTML = `<span class="text-red-400">Failed to load logs: ${escapeHtml(uiErrorText(error))}</span>`;
        }
    }
}

async function fetchOlderLogs() {
    if (logsState.isLoadingMore || logsState.oldestPageLoaded <= 1) return;
    
    logsState.isLoadingMore = true;
    const view = logsState.viewId;
    const pageToLoad = logsState.oldestPageLoaded - 1;
    
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
        if (!response.ok) throw await responseError(response);
        
        const data = await response.json();
        const entries = data.data || [];
        if (view !== logsState.viewId) return;
        
        if (entries.length > 0) {
            logsState.oldestPageLoaded = pageToLoad;
            
            const terminal = document.getElementById('logs-terminal');
            const prevScrollHeight = terminal ? terminal.scrollHeight : 0;
            
            renderLogEntries(entries, logsState.activeService, false, true);

            if (terminal && !logsState.newestFirst) {
                const newScrollHeight = terminal.scrollHeight;
                terminal.scrollTop = newScrollHeight - prevScrollHeight;
            }
        }
        
        if (loader) loader.remove();
        
        updateLogStatusBar();
        
    } catch (error) {
        console.error('[LOGS] Failed to load older logs:', error);
        if (loader) loader.textContent = 'Failed to load older logs';
        setTimeout(() => { if (loader) loader.remove(); }, 3000);
    } finally {
        logsState.isLoadingMore = false;
    }
}

function setupTerminalScrollHandler() {
    const terminal = document.getElementById('logs-terminal');
    if (!terminal || terminal._scrollHandlerAttached) return;
    
    let byHandAt = 0;
    const byHand = () => { byHandAt = Date.now(); };
    ['wheel', 'touchmove', 'keydown'].forEach(type => terminal.addEventListener(type, byHand, { passive: true }));
    terminal.addEventListener('scroll', () => {
        const onBar = uiPress && uiPress.down && uiPress.target === terminal;
        if (logsState.newEntries.length && (onBar || Date.now() - byHandAt < 1000)) {
            const atNewest = logsState.newestFirst
                ? terminal.scrollTop < 4
                : terminal.scrollTop + terminal.clientHeight > terminal.scrollHeight - 4;
            if (atNewest) { logsState.newEntries = []; updateLogNewLines(); }
        }
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

function entryMatchesFilters(entry) {
    const searchText = getEntrySearchText(entry).toLowerCase();
    
    if (logsState.searchQuery) {
        if (!searchText.includes(logsState.searchQuery.toLowerCase())) {
            return false;
        }
    }
    
    if (logsState.activeSmartFilters.length > 0) {
        const matchesAnyFilter = logsState.activeSmartFilters.some(filterId => {
            const filterDef = logsState.smartFilters.find(f => f.id === filterId);
            if (!filterDef) return false;
            
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

const MAX_LIVE_LOG_ENTRIES = 5000;

function renderLogEntries(entries, serviceId, replace = false, prepend = false) {
    const output = document.getElementById('logs-output');
    if (!output) return;
    
    if (replace) {
        output.innerHTML = '';
        logsState.allEntries = [];
        logsState.newEntries = [];
        updateLogNewLines();
    } else if (entries.length) {
        output.querySelectorAll('.logs-placeholder').forEach(el => el.remove());
    }
    
    if (prepend) {
        logsState.allEntries = entries.concat(logsState.allEntries);
    } else {
        logsState.allEntries = logsState.allEntries.concat(entries);
    }
    
    if (logsState.allEntries.length === 0 && replace) {
        output.innerHTML = '<span class="text-gray-500">No log entries found.</span>';
        return;
    }
    
    const held = !replace && !prepend && uiTextHeld(output);
    if (held && logsState.autoScroll) setLogAutoScroll(false);
    const fragment = document.createDocumentFragment();
    const hasFilters = logsState.searchQuery || logsState.activeSmartFilters.length > 0;

    const domEntries = logsState.newestFirst ? entries.slice().reverse() : entries;

    domEntries.forEach(entry => {
        const line = document.createElement('div');
        line.className = 'log-line';
        line.style.padding = '1px 0';

        line._rawEntry = entry;

        const formatted = formatLogLine(entry, serviceId);
        line.innerHTML = formatted;

        if (hasFilters && !entryMatchesFilters(entry)) {
            line.style.display = 'none';
            line.classList.add('log-filtered');
        }

        fragment.appendChild(line);
    });

    const insertAtTop = logsState.newestFirst ? !prepend : prepend;
    if (insertAtTop && output.firstChild) {
        output.insertBefore(fragment, output.firstChild);
    } else {
        output.appendChild(fragment);
    }

    if (!prepend && !held && logsState.allEntries.length > MAX_LIVE_LOG_ENTRIES) {
        const excess = logsState.allEntries.length - MAX_LIVE_LOG_ENTRIES;
        logsState.allEntries.splice(0, excess);
        for (let i = 0; i < excess; i++) {
            const victim = logsState.newestFirst ? output.lastChild : output.firstChild;
            if (!victim) break;
            output.removeChild(victim);
        }
    }

    if (hasFilters) {
        const allLines = output.querySelectorAll('.log-line');
        const visibleCount = output.querySelectorAll('.log-line:not(.log-filtered)').length;
        updateFilterBadge(true, visibleCount, allLines.length);
    }

    if (logsState.autoScroll && !prepend) {
        const terminal = document.getElementById('logs-terminal');
        if (terminal) {
            terminal.scrollTop = logsState.newestFirst ? 0 : terminal.scrollHeight;
        }
    }
}

function toggleLogSortOrder() {
    logsState.newestFirst = !logsState.newestFirst;
    localStorage.setItem('logsNewestFirst', logsState.newestFirst ? 'true' : 'false');
    updateLogSortButton();
    renderLogEntries(logsState.allEntries.slice(), logsState.activeService, true);
}

function updateLogSortButton() {
    const label = document.getElementById('logs-sort-text');
    if (label) {
        label.textContent = logsState.newestFirst ? 'Newest first' : 'Newest last';
    }
    const icon = document.getElementById('logs-sort-icon');
    if (icon) {
        icon.setAttribute('d', logsState.newestFirst
            ? 'M3 4h13M3 8h9m-9 4h6m4 0l4-4m0 0l4 4m-4-4v12'
            : 'M3 4h13M3 8h9m-9 4h9m5-4v12m0 0l-4-4m4 4l4-4');
    }
}

function getEntrySearchText(entry) {
    const parts = [];
    if (entry.message) parts.push(entry.message);
    if (entry.program) parts.push(entry.program);
    if (entry.uri) parts.push(entry.uri);
    if (entry.method) parts.push(entry.method);
    if (entry.remote) parts.push(entry.remote);
    if (entry.data) parts.push(String(entry.data));
    if (entry.service) parts.push(entry.service);
    if (entry.priority) parts.push(entry.priority);
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
    
    let displayContent = '';
    let lineColor = 'text-gray-300';
    let programStr = '';
    
    switch (serviceId) {
        case 'api':
            const method = escapeHtml(entry.method || '');
            const uri = escapeHtml(entry.uri || '');
            const remote = escapeHtml(entry.remote || '');
            const data = entry.data ? escapeHtml(String(entry.data).substring(0, 200)) : '';
            
            const methodColors = { GET: 'text-green-400', POST: 'text-yellow-400', PUT: 'text-blue-400', DELETE: 'text-red-400' };
            const methodColor = methodColors[entry.method] || 'text-gray-300';
            
            displayContent = `<span class="${methodColor} font-bold">${method}</span> <span class="text-gray-200">${uri}</span> <span class="text-gray-500">from</span> <span class="text-purple-400">${remote}</span>`;
            if (data) {
                displayContent += ` <span class="text-gray-500">${data}</span>`;
            }
            lineColor = methodColor;
            break;
            
        case 'watchdog':
            const wdService = escapeHtml(entry.service || '');
            const lvl = parseInt(entry.lvl || '0');
            const hpnow = escapeHtml(entry.hpnow || '?');
            const hptotal = escapeHtml(entry.hptotal || '?');
            const hpdiff = parseInt(entry.hpdiff || '0');
            
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
            const score = parseFloat(entry.score || 0);
            const action = escapeHtml(entry.action || 'unknown');
            const sender = escapeHtml(entry.sender_smtp || entry.sender_mime || '');
            const rcpts = (entry.rcpt_smtp || entry.rcpt_mime || []);
            const recipient = escapeHtml(Array.isArray(rcpts) ? rcpts.join(', ') : String(rcpts));
            const subject = escapeHtml((entry.subject || '').substring(0, 80));
            const ip = escapeHtml(entry.ip || '');
            
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
            const message = escapeHtml(entry.message || '');
            programStr = escapeHtml(entry.program || '');
            
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
    
    if (logsState.searchQuery && displayContent) {
        const regex = new RegExp(`(${escapeRegex(logsState.searchQuery)})`, 'gi');
        displayContent = displayContent.replace(regex, '<mark class="bg-yellow-500/40 text-yellow-200 rounded px-0.5">$1</mark>');
    }
    
    if (serviceId === 'api' || serviceId === 'watchdog' || serviceId === 'rspamd-history') {
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
        
        return formatTime(date);
    } catch {
        return String(timeVal);
    }
}

async function connectLogWebSocket(serviceId) {
    disconnectLogWebSocket();
    
    if (logsState.isPaused) return;
    
    try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        let wsUrl = `${protocol}//${window.location.host}/ws/raw-logs?service=${serviceId}`;
        
        try {
            const tokenResp = await authenticatedFetch('/api/raw-logs/ws-token', { ownNotPermitted: true });
            if (tokenResp.status === 403) {
                logsNotPermitted();
                return;
            }
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
                    if (!logsState.isPaused && !logsState.dateRange) {
                        renderLogEntries(data.entries, data.service, false);
                        if (!logsState.autoScroll) {
                            logsState.newEntries = logsState.newEntries.concat(data.entries).slice(-MAX_LIVE_LOG_ENTRIES);
                            updateLogNewLines();
                        }
                        logsState.entryCount += data.entries.length;
                        logsState.totalEntries = logsState.entryCount;
                        logsState.lastUpdateTime = new Date();
                        updateLogStatusBar();
                    }
                } else if (data.type === 'service_counts' && data.counts) {
                    const fmtNum = (n) => n >= 1000 ? (n / 1000).toFixed(1) + 'K' : n.toString();
                    for (const [svcId, count] of Object.entries(data.counts)) {
                        const btn = document.getElementById(`log-svc-${svcId}`);
                        if (!btn) continue;
                        const badge = btn.querySelector('small');
                        if (badge) badge.textContent = fmtNum(count);
                    }
                    updateLogServiceToggle();
                    if (logsState.activeService && !logsState.dateRange && data.counts[logsState.activeService] !== undefined) {
                        logsState.totalEntries = data.counts[logsState.activeService];
                        logsState.entryCount = data.counts[logsState.activeService];
                        updateLogStatusBar();
                    }
                } else if (data.type === 'error') {
                    console.warn('[LOGS WS] Server error:', data.message);
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
            
            if (event.code === 4403) {
                logsNotPermitted();
                return;
            }

            if (event.code === 4401) {
                console.warn('[LOGS WS] Authentication failed - not reconnecting');
                return;
            }
            
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

const LOGS_NOT_PERMITTED = 'You do not have permission to view live logs.';

function logsNotPermitted() {
    updateWsIndicator(false);
    const status = document.getElementById('logs-ws-status');
    if (status) {
        status.textContent = 'No permission';
        status.title = LOGS_NOT_PERMITTED;
    }
    showToast(LOGS_NOT_PERMITTED, 'error');
    if (typeof refreshAppAccess === 'function') refreshAppAccess();
}

function disconnectLogWebSocket() {
    if (logsState.ws) {
        logsState.ws.onclose = null;
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
        indicator.className = `ui-mdot ${connected ? 'ui-mdot-ok' : logsState.isPaused ? 'ui-mdot-warn' : 'ui-mdot-fail'}`;
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
        uiAgo(updateEl, (logsState.lastUpdateTime || new Date()).toISOString(), 'Updated ');
    }
}

function toggleLogPause() {
    logsState.isPaused = !logsState.isPaused;
    
    const btn = document.getElementById('logs-pause-btn');
    const text = document.getElementById('logs-pause-text');
    const icon = document.getElementById('logs-pause-icon');
    
    if (logsState.isPaused) {
        if (text) text.textContent = 'Resume';
        if (icon) icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>';
        if (btn) btn.setAttribute('aria-pressed', 'true');
        disconnectLogWebSocket();
    } else {
        if (text) text.textContent = 'Pause';
        if (icon) icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>';
        if (btn) btn.setAttribute('aria-pressed', 'false');
        connectLogWebSocket(logsState.activeService);
    }
    
    updateWsIndicator(logsState.isConnected);
}

function toggleAutoScroll() {
    setLogAutoScroll(!logsState.autoScroll);
}

function setLogAutoScroll(on) {
    logsState.autoScroll = on;
    const btn = document.getElementById('logs-autoscroll-btn');
    if (btn) btn.setAttribute('aria-pressed', on ? 'true' : 'false');
    if (!on) return;
    const output = document.getElementById('logs-output');
    const selection = window.getSelection();
    if (output && selection && selection.rangeCount && selection.getRangeAt(0).intersectsNode(output)) selection.removeAllRanges();
    logsState.newEntries = [];
    updateLogNewLines();
    const terminal = document.getElementById('logs-terminal');
    if (terminal) terminal.scrollTop = logsState.newestFirst ? 0 : terminal.scrollHeight;
}

document.addEventListener('selectionchange', () => {
    if (!logsState.autoScroll) return;
    const output = document.getElementById('logs-output');
    if (output && output.offsetParent && uiTextHeld(output)) setLogAutoScroll(false);
});

function updateLogNewLines() {
    const wrap = document.getElementById('logs-new-wrap');
    const terminal = document.getElementById('logs-terminal');
    if (!wrap || !terminal) return;
    const hasFilters = logsState.searchQuery || logsState.activeSmartFilters.length > 0;
    const count = hasFilters ? logsState.newEntries.filter(entryMatchesFilters).length : logsState.newEntries.length;
    wrap.hidden = !count;
    if (!count) return;
    const top = logsState.newestFirst;
    wrap.classList.toggle('is-top', top);
    if (top ? terminal.firstElementChild !== wrap : terminal.lastElementChild !== wrap) {
        if (top) terminal.prepend(wrap); else terminal.append(wrap);
    }
    const label = document.getElementById('logs-new-text');
    if (label) label.textContent = `${count.toLocaleString()} new ${count === 1 ? 'line' : 'lines'}`;
    const arrow = document.getElementById('logs-new-arrow');
    if (arrow) arrow.setAttribute('d', top ? 'M5 15l7-7 7 7' : 'M19 9l-7 7-7-7');
}

function jumpToNewestLogs() {
    setLogAutoScroll(true);
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
    
    if (btn) btn.setAttribute('aria-pressed', logsState.wordWrap ? 'true' : 'false');
}

function searchLogs() {
    const input = document.getElementById('logs-search-input');
    logsState.searchQuery = input ? input.value.trim() : '';
    
    applyLogFilter();
}

function setLogDateInput(input, date) {
    if (!input) return;
    input.value = date ? toZonedInputValue(date) : '';
    input.dataset.shown = input.value;
    input.dataset.instant = date ? date.toISOString() : '';
}

function readLogDateInput(input, isEnd) {
    if (!input || !input.value) return null;
    if (input.dataset.instant && input.value === input.dataset.shown) return input.dataset.instant;
    const date = fromZonedInputValue(input.value);
    if (!date) return null;
    return (isEnd ? new Date(date.getTime() + (input.value.length > 16 ? 999 : 59999)) : date).toISOString();
}

function setLogTimePreset(minutes, now = new Date()) {
    const from = new Date(now.getTime() - minutes * 60 * 1000);
    
    setLogDateInput(document.getElementById('logs-date-from'), from);
    setLogDateInput(document.getElementById('logs-date-to'), now);
    
    return loadDateRangeLogs();
}

async function loadDateRangeLogs() {
    const fromInput = document.getElementById('logs-date-from');
    const toInput = document.getElementById('logs-date-to');
    const loadingEl = document.getElementById('logs-range-loading');
    
    const startDate = readLogDateInput(fromInput, false);
    const endDate = readLogDateInput(toInput, true);
    
    if (!startDate) {
        return;
    }
    
    if (loadingEl) loadingEl.classList.remove('hidden');
    const loadBtn = document.getElementById('logs-load-range-btn');
    if (loadBtn) loadBtn.disabled = true;
    
    try {
        logsState.dateRange = { start: startDate, end: endDate };
        logsState.timeRangeMinutes = '';
        
        setLiveButtonActive(false);
        
        const params = new URLSearchParams({ page: 1, limit: 1000, order: 'asc' });
        params.set('start_date', startDate);
        if (endDate) params.set('end_date', endDate);
        
        const response = await authenticatedFetch(`/api/raw-logs/${logsState.activeService}?${params}`);
        if (!response.ok) throw await responseError(response);
        
        const data = await response.json();
        const total = data.total || 0;
        const limit = 1000;
        const totalPages = Math.max(1, Math.ceil(total / limit));
        
        const firstShown = Math.max(1, Math.floor(Math.max(0, total - MAX_LIVE_LOG_ENTRIES) / limit) + 1);
        renderLogEntries(firstShown === 1 ? data.data || [] : [], logsState.activeService, true);

        for (let page = Math.max(2, firstShown); page <= totalPages; page++) {
            if (loadingEl) loadingEl.textContent = `Loading page ${page}/${totalPages}...`;
            
            const nextParams = new URLSearchParams({ page, limit, order: 'asc' });
            nextParams.set('start_date', startDate);
            if (endDate) nextParams.set('end_date', endDate);
            
            const nextResp = await authenticatedFetch(`/api/raw-logs/${logsState.activeService}?${nextParams}`);
            if (!nextResp.ok) break;
            
            const nextData = await nextResp.json();
            renderLogEntries(nextData.data || [], logsState.activeService, false);
        }
        
        logsState.totalEntries = total;
        logsState.entryCount = total;
        logsState.oldestPageLoaded = 1;
        logsState.totalPages = 1;
        updateLogStatusBar();
        
        if (logsState.searchQuery || logsState.activeSmartFilters.length > 0) {
            applyLogFilter();
        }
        
    } catch (error) {
        console.error('[LOGS] Date range load failed:', error);
        const output = document.getElementById('logs-output');
        if (output) {
            output.innerHTML = `<span class="text-red-400">Failed to load date range: ${escapeHtml(uiErrorText(error))}</span>`;
        }
    } finally {
        if (loadingEl) {
            loadingEl.textContent = 'Loading...';
            loadingEl.classList.add('hidden');
        }
        if (loadBtn) loadBtn.disabled = false;
    }
}

async function resetToLiveLogs() {
    logsState.dateRange = null;
    logsState.timeRangeMinutes = '';
    
    setLogDateInput(document.getElementById('logs-date-from'), null);
    setLogDateInput(document.getElementById('logs-date-to'), null);
    
    setLiveButtonActive(true);
    
    await fetchInitialLogs(logsState.activeService);
    
    await connectLogWebSocket(logsState.activeService);
}

function setLiveButtonActive(active) {
    const btn = document.getElementById('logs-live-btn');
    if (!btn) return;
    
    btn.setAttribute('aria-pressed', active ? 'true' : 'false');
}

function clearLogSearch() {
    const input = document.getElementById('logs-search-input');
    if (input) input.value = '';
    logsState.searchQuery = '';
    
    if (logsState.activeSmartFilters.length > 0) {
        logsState.activeSmartFilters.forEach(filterId => {
            const btn = document.getElementById(`smart-filter-${filterId}`);
            if (btn) btn.setAttribute('aria-pressed', 'false');
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
                line.style.display = '';
                line.classList.remove('log-filtered');
                visibleCount++;
            } else {
                line.style.display = 'none';
                line.classList.add('log-filtered');
            }
        }
    });
    
    updateFilterBadge(hasFilters, visibleCount, lines.length);
    updateLogNewLines();
}

function updateFilterBadge(hasFilters, visible, total) {
    let badge = document.getElementById('logs-filter-badge');
    if (!hasFilters) {
        if (badge) badge.remove();
        return;
    }
    if (!badge) {
        badge = document.createElement('span');
        badge.id = 'logs-filter-badge';
        badge.className = 'ui-logs-filter';
        const count = document.getElementById('logs-entry-count');
        if (count) count.after(badge);
    }
    const parts = [];
    if (logsState.searchQuery) {
        parts.push(`"${escapeHtml(logsState.searchQuery)}"`);
    }
    if (logsState.activeSmartFilters.length > 0) {
        const filterNames = logsState.activeSmartFilters.map(id => {
            const f = logsState.smartFilters.find(sf => sf.id === id);
            return escapeHtml(f ? f.label : id);
        });
        parts.push(filterNames.join(', '));
    }
    badge.innerHTML = `<span>Showing ${visible} of ${total} - filter: <strong>${parts.join(' + ')}</strong></span>` +
        `<button type="button" onclick="clearLogSearch()" aria-label="Clear all filters" title="Clear all filters">&times;</button>`;
}

function clearLogDisplay() {
    const output = document.getElementById('logs-output');
    if (output) {
        output.innerHTML = '<span class="text-gray-500 logs-placeholder">Display cleared. New logs will appear here.</span>';
    }
    logsState.entryCount = 0;
    logsState.allEntries = [];
    logsState.newEntries = [];
    updateLogNewLines();
    logsState.oldestPageLoaded = 1;
    logsState.viewId = (logsState.viewId || 0) + 1;
    const loader = document.getElementById('logs-load-more-indicator');
    if (loader) loader.remove();
    
    const searchInput = document.getElementById('logs-search-input');
    if (searchInput) searchInput.value = '';
    logsState.searchQuery = '';
    
    if (logsState.activeSmartFilters.length > 0) {
        logsState.activeSmartFilters.forEach(filterId => {
            const chip = document.querySelector(`[data-filter-id="${filterId}"]`);
            if (chip) chip.setAttribute('aria-pressed', 'false');
        });
        logsState.activeSmartFilters = [];
    }
    
    setLogDateInput(document.getElementById('logs-date-from'), null);
    setLogDateInput(document.getElementById('logs-date-to'), null);
    logsState.dateRange = null;
    logsState.timeRangeMinutes = '';
    
    updateFilterBadge(false);
    
    updateLogStatusBar();
}
