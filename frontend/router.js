/**
 * Router module for SPA clean URL navigation
 * Handles History API based routing for the mailcow Logs Viewer
 */

// Valid base routes for the SPA
const VALID_ROUTES = [
    'dashboard',
    'messages',
    'netfilter',
    'outbound',
    'quarantine',
    'rspamd',
    'status',
    'domains',
    'dmarc',
    'mailbox-stats',
    'devices',
    'logs',
    'settings',
    'about'
];

// URL aliases: URL path -> internal route name
const ROUTE_ALIASES = {
    'security': 'netfilter'
};

// Reverse aliases: internal route -> URL path
const ROUTE_DISPLAY = {
    'netfilter': 'security'
};

// Pages and tabs that moved: an old address, a bookmark or a Back into the
// history of an older version opens the new place. Null when nothing moved.
function canonicalRoute(route, params = {}) {
    const sub = (params && params.sub) || '';
    if (route === 'queue') return { route: 'outbound', params: { sub: 'queue' } };
    if (route === 'spam-filter') {
        return sub === 'maps' ? { route: 'rspamd', params: {} }
            : { route: 'outbound', params: { sub: 'suppressions' } };
    }
    if (route === 'quarantine' && sub === 'maps') return { route: 'rspamd', params: {} };
    if (route === 'settings' && sub === 'spam_filter') return { route, params: { ...params, sub: 'outbound' } };
    return null;
}

// Pages with tabs: every tab has its own address (/security/protection), so a
// tab can be reloaded, shared and reached with Back. The first tab is the
// page's own address. select() picks the tab before the page loads; show()
// switches it on a page already open. tabs: null takes any section name.
const SUBPAGES = {
    // protection, fail2ban and abuse are the old addresses of what is now the Settings tab
    netfilter: { tabs: ['overview', 'lists', 'settings', 'events', 'protection', 'fail2ban', 'abuse'], current: () => securityTab,
        select: t => securityShowTab(t), show: t => securityShowTab(t) },
    quarantine: { tabs: ['messages', 'rules'], current: () => quarantineTab,
        select: t => quarantineShowTab(t), show: t => quarantineShowTab(t) },
    outbound: { tabs: ['queue', 'suppressions'], current: () => outboundTab,
        select: t => outboundShowTab(t, false), show: t => outboundShowTab(t) },
    status: { tabs: ['server', 'blocklists', 'jobs'], current: () => statusTab,
        select: t => statusShowTab(t), show: t => statusShowTab(t) },
    'mailbox-stats': { tabs: ['statistics', 'rate-limits'], current: () => mailboxStatsView,
        select: t => { mailboxStatsView = t; }, show: t => mailboxStatsSwitchView(t) },
    settings: { tabs: null, get first() { return settingsFirstTab || 'features'; }, current: () => settingsTab,
        select: t => { settingsTab = t; }, show: t => { settingsTab = t; if (window.settingsShowTab) window.settingsShowTab(t); } }
};

function subpageFirst(route) {
    const page = SUBPAGES[route];
    return page.first || page.tabs[0];
}

function isSubpage(route, name) {
    const page = SUBPAGES[route];
    if (!page || !name) return false;
    return page.tabs ? page.tabs.includes(name) : /^[a-z0-9_-]+$/.test(name);
}

// A tab was opened on the page on screen: give it its address. While a page
// loads (replace), the address is corrected instead of adding a Back step.
// Every history entry the app writes carries its place in the history (idx), so
// Back and Forward know how far they went and can be undone exactly
let historyIdx = 0;
let routerHere = { route: 'dashboard', params: {} };   // the page the app shows
function routerPush(state, url) {
    routerSaveScroll();
    historyIdx += 1;
    routerNoteHere(state);
    history.pushState({ ...(state || {}), idx: historyIdx }, '', url);
}
function routerReplace(state, url) {
    routerNoteHere(state);
    history.replaceState({ ...(state || {}), idx: historyIdx }, '', url);
}
function routerNoteHere(state) {
    if (state && state.route && !state.overlay) routerHere = { route: state.route, params: state.params || {} };
}

function routerSyncSubpage(route, name, replace = false) {
    if (typeof currentTab === 'undefined' || currentTab !== route || !SUBPAGES[route]) return;
    const path = buildPath(route, { sub: name });
    if (window.location.pathname === path) return;
    const state = { route, params: { sub: name } };
    if (replace) routerReplace(state, path);
    else routerPush(state, path);
}

/**
 * Parse the current URL path into route components
 * @returns {Object} Route info with baseRoute and optional params
 */
function parseRoute() {
    const path = window.location.pathname;

    // Root path = dashboard
    if (path === '/' || path === '') {
        return { baseRoute: 'dashboard', params: {} };
    }

    // Split path into segments
    const segments = path.split('/').filter(s => s.length > 0);

    if (segments.length === 0) {
        return { baseRoute: 'dashboard', params: {} };
    }

    // Resolve URL aliases (e.g., /security -> netfilter)
    const baseRoute = ROUTE_ALIASES[segments[0]] || segments[0];

    // An address of a page or tab that moved
    const moved = canonicalRoute(baseRoute, { sub: decodeURIComponent(segments[1] || '') });
    if (moved) return { baseRoute: moved.route, params: moved.params, moved: true };

    // Special handling for DMARC nested routes
    if (baseRoute === 'dmarc' && segments.length > 1) {
        return parseDmarcRoute(segments);
    }

    // Validate base route
    if (!VALID_ROUTES.includes(baseRoute)) {
        console.warn(`Unknown route: ${baseRoute}, defaulting to dashboard`);
        return { baseRoute: 'dashboard', params: {} };
    }

    // A tab of the page; an unknown one opens the page's first tab
    if (SUBPAGES[baseRoute]) {
        const sub = decodeURIComponent(segments[1] || '');
        return { baseRoute, params: { sub: isSubpage(baseRoute, sub) ? sub : subpageFirst(baseRoute) } };
    }

    return { baseRoute, params: {} };
}

/**
 * Parse DMARC-specific nested routes
 * @param {string[]} segments - URL path segments
 * @returns {Object} Route info for DMARC
 */
function parseDmarcRoute(segments) {
    // segments[0] = 'dmarc'
    // segments[1] = domain (e.g., 'example.com')
    // segments[2] = type ('report', 'source', 'tls', 'reports', 'sources')
    // segments[3] = id (date or IP)

    const params = { domain: null, type: null, id: null };

    // The TLS tab: /dmarc/tls, /dmarc/tls/<domain>, /dmarc/tls/<domain>/<date>
    if (segments[1] === 'tls') {
        return { baseRoute: 'dmarc', params: {
            tab: 'tls',
            domain: segments[2] ? decodeURIComponent(segments[2]) : null,
            id: segments[3] ? decodeURIComponent(segments[3]) : null
        } };
    }

    if (segments.length >= 2) {
        params.domain = decodeURIComponent(segments[1]);
    }

    if (segments.length >= 3) {
        params.type = segments[2];
    }

    if (segments.length >= 4) {
        params.id = decodeURIComponent(segments[3]);
    }

    return { baseRoute: 'dmarc', params };
}

/**
 * Build a URL path from route components
 * @param {string} baseRoute - The base route
 * @param {Object} params - Optional parameters
 * @returns {string} The URL path
 */
function buildPath(baseRoute, params = {}) {
    if (baseRoute === 'dashboard') {
        return '/';
    }

    // Use display name for URL (e.g., netfilter -> /security)
    const urlSegment = ROUTE_DISPLAY[baseRoute] || baseRoute;
    let path = `/${urlSegment}`;

    // A page's tab; the first tab is the page's own address
    if (SUBPAGES[baseRoute] && params.sub && params.sub !== subpageFirst(baseRoute)) {
        path += `/${encodeURIComponent(params.sub)}`;
    }

    // The DMARC page's TLS tab
    if (baseRoute === 'dmarc' && params.tab === 'tls') {
        path += '/tls';
        if (params.domain) {
            path += `/${encodeURIComponent(params.domain)}`;
            if (params.id) path += `/${encodeURIComponent(params.id)}`;
        }
        return path;
    }

    // Handle DMARC nested routes
    if (baseRoute === 'dmarc' && params.domain) {
        path += `/${encodeURIComponent(params.domain)}`;

        if (params.type) {
            path += `/${params.type}`;

            if (params.id) {
                path += `/${encodeURIComponent(params.id)}`;
            }
        }
    }

    return path;
}

/**
 * Navigate to a route - updates URL and switches tab
 * @param {string} route - The base route to navigate to
 * @param {Object} params - Optional route parameters (for nested routes)
 * @param {boolean} updateHistory - Whether to push to browser history (default: true)
 * @param {boolean} confirmed - The user already agreed to drop unsaved changes
 * @returns {Promise<boolean>} false when the user chose to stay with unsaved changes;
 *   a caller that does more after the move (opens a card, applies a filter) waits for it
 */
function navigateTo(route, params = {}, updateHistory = true, confirmed = false) {
    // Handle legacy calls with just route string
    if (typeof params === 'boolean') {
        updateHistory = params;
        params = {};
    }

    const moved = canonicalRoute(route, params);
    if (moved) ({ route, params } = moved);

    // Validate base route
    if (!VALID_ROUTES.includes(route)) {
        console.warn(`Invalid route: ${route}, defaulting to dashboard`);
        route = 'dashboard';
        params = {};
    }

    // Note: disabled feature guard is in switchTab() which shows a "Feature Disabled" page

    // A page with tabs opens on the tab it was left on
    if (SUBPAGES[route] && !params.sub) {
        params = { ...params, sub: SUBPAGES[route].current() };
    }

    // Changes not saved yet that this move would drop: ask first
    if (!confirmed && typeof uiUnsavedCount === 'function' && uiUnsavedCount({ route, params })) {
        return uiConfirmLeave({ route, params }).then(ok => (ok ? navigateTo(route, params, updateHistory, true) : false));
    }

    // Build the new path
    const newPath = buildPath(route, params);

    // Update history if path actually changed. With a dialog open, its history
    // entry becomes the new page instead of stacking one more entry
    if (updateHistory && window.location.pathname !== newPath) {
        if (overlayHistoryEntry) {
            overlayHistoryEntry = false;
            routerReplace({ route, params }, newPath);
        } else {
            routerPush({ route, params }, newPath);
        }
    }

    // Always switch to the tab (even if URL is same, to handle returning to main view)
    routerHere = { route, params };
    if (typeof switchTab === 'function') {
        switchTab(route, params);
    } else {
        console.error('switchTab function not found');
    }
    return Promise.resolve(true);
}

// =============================================================================
// Layers: dialogs, sheets, the phone More sheet and the phone search. One owner
// for what every layer needs:
// - Back closes the top layer (one history entry while anything is open, at the
//   page's address), so a phone's back gesture never leaves the page
// - Escape closes the top layer only
// - focus moves into a layer when it opens and back to what opened it when it
//   closes, and what lies under the top layer is inert: Tab, clicks and a
//   screen reader reach only the top layer
// =============================================================================

// The docked message pane on the desktop Messages page is part of the page, not a dialog.
// The search over a phone's screen (search.js) is one too
const OVERLAY_SELECTOR = '.ui-dialog-backdrop:not(.hidden):not(.ui-docked), #container-logs-modal:not(.hidden), #mobile-menu.active, .ui-gs.is-sheet, .ui-sheet';
let overlayHistoryEntry = false;
let overlayIgnorePop = false;
let overlaySyncQueued = false;

function layerShown(el) {
    return el.getClientRects().length > 0;
}

function layerLevel(el) {
    const z = parseInt(getComputedStyle(el).zIndex, 10);
    return Number.isNaN(z) ? 0 : z;
}

// The open layers, lowest first: by stacking level, then by page order. So the
// phone search is under a message it opened, though it comes earlier in the page
function openOverlays() {
    return [...document.querySelectorAll(OVERLAY_SELECTOR)].filter(layerShown)
        .sort((a, b) => layerLevel(a) - layerLevel(b)
            || (a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1));
}

// Close the dialog on top the way a user would: its Close or Cancel button
let layerOwnEscape = false;
function closeTopOverlay() {
    const open = openOverlays();
    const top = open[open.length - 1];
    if (!top) return false;
    if (top.id === 'mobile-menu') {
        closeMobileMenu();
        return true;
    }
    const button = top.querySelector('[aria-label="Close"], [id$="-cancel"], [data-cancel]')
        || [...top.querySelectorAll('button')].find(b => /^(cancel|close)$/i.test(b.textContent.trim())
            || /^close/i.test(b.getAttribute('onclick') || ''));
    if (button) button.click();
    else {
        // A layer without a Close button (the phone search) closes on its own Escape
        layerOwnEscape = true;
        try { top.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })); } finally { layerOwnEscape = false; }
    }
    return true;
}

// A picker or a menu open inside the top layer closes first, on its own Escape;
// so does the phone search, which has no Close button
function layerChildOwnsEscape(top) {
    if (top.matches('.ui-gs')) return true;
    const picker = typeof uiPickers !== 'undefined' && uiPickers.open ? document.getElementById(`${uiPickers.open}-panel`) : null;
    if (picker && top.contains(picker)) return true;
    try { return !!top.querySelector(':popover-open'); } catch (e) { return false; }
}

// Capture on the window runs before every other listener, so no dialog under
// the top one sees this Escape as well
window.addEventListener('keydown', event => {
    if (event.key !== 'Escape' || event.isComposing || layerOwnEscape) return;
    const open = openOverlays();
    const top = open[open.length - 1];
    if (!top || layerChildOwnsEscape(top)) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    closeTopOverlay();
}, true);

// What the user acted on last: the control that opened a layer gets the focus
// back when the layer closes. A layer that opens after a request (help) names
// its opener up front with uiLayerOpener, since the user may act on something
// else while it loads
let layerLastAction = null;
let layerNamedOpener = null;
const layerOpeners = new Map();   // layer -> the control that opened it
function layerControl(el) {
    return el instanceof Element ? el.closest('button, a[href], input, select, textarea, summary, [tabindex]') : null;
}
document.addEventListener('pointerdown', event => { layerLastAction = layerControl(event.target); }, true);
// What had the focus, to notice when a redraw takes it away
let layerFocused = null;
document.addEventListener('focusin', event => { layerFocused = event.target; }, true);
document.addEventListener('keydown', event => { layerLastAction = layerControl(event.target) || layerLastAction; }, true);
function uiLayerOpener(el) {
    layerNamedOpener = layerControl(el);
}

function layerUsable(el) {
    return !!el && el.isConnected && layerShown(el) && !el.closest('[inert]') && !el.disabled;
}

function layerPanel(layer) {
    return layer.querySelector('[role="dialog"], [role="alertdialog"], .ui-sheet-panel, .ui-dialog, .mobile-menu-content') || layer;
}

// Into a layer that just opened: its first field (not on a touch screen, where it
// would raise the keyboard over the dialog), else its main button, else the panel.
// A layer that already put the focus somewhere inside keeps it
function layerFocusIn(layer) {
    if (layer.contains(document.activeElement)) return;
    const usable = el => el.getClientRects().length > 0 && !el.disabled;
    const touch = window.matchMedia('(pointer: coarse)').matches;
    // The phone search: its field, or its results on a touch screen (no keyboard popping up)
    if (layer.matches('.ui-gs')) {
        const results = layer.querySelector('.ui-gs-panel');
        const target = touch && results ? results : layer.querySelector('input');
        if (target === results && !results.hasAttribute('tabindex')) results.setAttribute('tabindex', '-1');
        if (target) target.focus({ preventScroll: true });
        return;
    }
    const field = touch ? null : [...layer.querySelectorAll('[autofocus], input:not([type="hidden"]), select, textarea')].find(usable);
    let target = field || [...layer.querySelectorAll('.ui-btn-primary')].find(usable);
    if (!target) {
        target = layerPanel(layer);
        if (!target.hasAttribute('tabindex')) target.setAttribute('tabindex', '-1');
        target.dataset.layerPanel = '';
    }
    target.focus({ preventScroll: true });
}

// Back to what opened the layer; when that is gone, into the layer below, else
// to the page's heading
function layerFocusBack(opener, below) {
    if (layerUsable(opener)) { opener.focus({ preventScroll: true }); return; }
    if (below) { layerFocusIn(below); return; }
    const page = [...document.querySelectorAll('.ui-page:not(.hidden)')].find(layerShown);
    const heading = page && page.querySelector('h1, h2');
    if (heading) {
        if (!heading.hasAttribute('tabindex')) heading.setAttribute('tabindex', '-1');
        heading.focus({ preventScroll: true });
    }
}

// Everything beside the path from the page to the top layer is inert. What stays
// usable: toasts, and the phone tab bar beside the More sheet it opens and closes
const layerInert = new Set();
function layerKeeps(top) {
    const keep = [...document.querySelectorAll('.ui-toast')];
    if (top && top.id === 'mobile-menu') keep.push(...document.querySelectorAll('.ui-tabbar'));
    return keep;
}
function layerInertTargets(top) {
    const targets = new Set();
    if (!top) return targets;
    const keep = layerKeeps(top);
    const mark = el => {
        if (el === top || el.contains(top) || ['SCRIPT', 'STYLE', 'TEMPLATE'].includes(el.tagName)) return;
        if (keep.includes(el)) return;
        // A branch holding something that stays usable: go into it instead
        if (keep.some(k => el.contains(k))) { [...el.children].forEach(mark); return; }
        targets.add(el);
    };
    for (let node = top; node.parentElement && node !== document.body; node = node.parentElement) {
        [...node.parentElement.children].forEach(child => { if (child !== node) mark(child); });
    }
    return targets;
}
function layerApplyInert(top) {
    const targets = layerInertTargets(top);
    for (const el of layerInert) {
        if (!targets.has(el)) { el.inert = false; layerInert.delete(el); }
    }
    // Only what this code made inert is released again; the page's own inert parts stay
    for (const el of targets) {
        if (!layerInert.has(el) && !el.inert) { el.inert = true; layerInert.add(el); }
    }
}

// Focus and inert follow the open layers
function syncLayerFocus(open) {
    const top = open[open.length - 1] || null;
    const closed = [...layerOpeners.keys()].filter(el => !open.includes(el));
    const opened = open.filter(el => !layerOpeners.has(el));
    const closedOpeners = closed.map(el => layerOpeners.get(el));
    closed.forEach(el => {
        layerOpeners.delete(el);
        // The message dialog becomes the docked reading pane, which is not modal
        const marked = el.matches('[data-layer-modal]') ? el : el.querySelector('[data-layer-modal]');
        if (marked) { marked.removeAttribute('aria-modal'); delete marked.dataset.layerModal; }
    });
    opened.forEach(el => {
        // A screen reader treats the dialog as the whole page while it is open
        const dialog = el.matches('[role="dialog"], [role="alertdialog"]') ? el : el.querySelector('[role="dialog"], [role="alertdialog"]');
        if (dialog && !el.matches('.ui-gs') && !dialog.hasAttribute('aria-modal')) {
            dialog.setAttribute('aria-modal', 'true');
            dialog.dataset.layerModal = '';
        }
        let opener = layerNamedOpener || layerLastAction;
        if (opener && el.contains(opener)) opener = null;
        layerOpeners.set(el, opener);
    });
    if (opened.length) layerNamedOpener = null;
    layerApplyInert(top);
    if (top && opened.includes(top)) layerFocusIn(top);
    else if (closed.length && !(top && top.contains(document.activeElement))) {
        layerFocusBack(closedOpeners[closedOpeners.length - 1], top);
    } else if (top && layerFocused && !layerFocused.isConnected && (!document.activeElement || document.activeElement === document.body)
        // A list sorted on the server puts the focus back on its header itself (utils.js)
        && !(typeof uiSortFocus !== 'undefined' && uiSortFocus && uiSortFocus.from.isConnected)) {
        // The top layer drew its content again and the focused control went with it
        layerFocusIn(top);
    }
}

// Keep one history entry while anything is open, and drop it when all is closed
function syncOverlayHistory() {
    overlaySyncQueued = false;
    const layers = openOverlays();
    syncLayerFocus(layers);
    const open = layers.some(el => !el.matches('[data-no-history]'));
    if (open && !overlayHistoryEntry) {
        routerPush({ ...(history.state || {}), overlay: true }, window.location.href);
        overlayHistoryEntry = true;
    } else if (!open && overlayHistoryEntry) {
        overlayHistoryEntry = false;
        if (history.state && history.state.overlay) {
            overlayIgnorePop = true;
            history.back();
        }
    }
}

function watchOverlays() {
    const queue = () => {
        if (overlaySyncQueued) return;
        overlaySyncQueued = true;
        requestAnimationFrame(syncOverlayHistory);
    };
    // Dialogs open by a class change or by being added to the page
    new MutationObserver(queue).observe(document.body, { subtree: true, childList: true, attributes: true, attributeFilter: ['class'] });
}
document.addEventListener('DOMContentLoaded', watchOverlays);

// Back and Forward: a page comes back where it was scrolled to. The app scrolls
// inside its pages, not the window: each scrolling area of the open page keeps its
// position per history entry. A list that grows as it scrolls is scrolled down
// until the old place is there again (up to 5 seconds); the user scrolling stops it
let routerPopUndo = false;
let routerPopConfirmed = false;
const routerScrolls = new Map();   // idx -> { area key: scrollTop }
function routerScrollAreas() {
    const page = [...document.querySelectorAll('.ui-page:not(.hidden)')].find(el => el.getClientRects().length);
    if (!page) return [];
    return [page, ...page.querySelectorAll('.ui-scroll, .ui-msg-items, #settings-content .settings-edit-content, .ui-logs-side')]
        .filter(el => el.scrollHeight > el.clientHeight);
}
function routerScrollKey(el) {
    if (el.id) return el.id;
    const owner = el.parentElement && el.parentElement.closest('[id]');
    return `${owner ? owner.id : ''}|${el.className}`;
}
function routerSaveScroll() {
    const areas = routerScrollAreas();
    if (!areas.length) return;
    const saved = {};
    areas.forEach(el => { if (el.scrollTop > 0) saved[routerScrollKey(el)] = el.scrollTop; });
    routerScrolls.set(historyIdx, saved);
}
let routerScrollRestore = null;
function routerRestoreScroll(idx) {
    if (routerScrollRestore) routerScrollRestore();
    const saved = routerScrolls.get(idx);
    if (!saved || !Object.keys(saved).length) return;
    const until = Date.now() + 5000;
    let stopped = false;
    const stop = () => {
        stopped = true;
        routerScrollRestore = null;
        ['wheel', 'touchstart', 'pointerdown', 'keydown'].forEach(type => window.removeEventListener(type, stop, true));
    };
    ['wheel', 'touchstart', 'pointerdown', 'keydown'].forEach(type => window.addEventListener(type, stop, true));
    routerScrollRestore = stop;
    const step = () => {
        if (stopped) return;
        let left = 0;
        for (const [key, top] of Object.entries(saved)) {
            const el = document.getElementById(key) || [...document.querySelectorAll('.ui-page:not(.hidden) *')].find(e => routerScrollKey(e) === key);
            if (!el) { left++; continue; }
            const max = el.scrollHeight - el.clientHeight;
            // Further down than the list reaches yet: to its end, where it loads more
            const want = Math.min(top, max);
            if (Math.abs(el.scrollTop - want) > 1) el.scrollTop = want;
            if (max < top) left++;
        }
        // The page may draw its list again once fresh data comes: the place is held
        // until the time is up, or until the user scrolls
        if (Date.now() < until) setTimeout(step, left ? 150 : 250);
        else stop();
    };
    requestAnimationFrame(step);
}

/**
 * Navigate specifically within DMARC section
 * @param {string} domain - Domain name (null for domains list)
 * @param {string} type - Type: 'reports', 'sources', 'tls', 'report', 'source'
 * @param {string} id - ID: date for report/tls, IP for source
 */
function navigateToDmarc(domain = null, type = null, id = null) {
    const params = {};
    if (domain) params.domain = domain;
    if (type) params.type = type;
    if (id) params.id = id;

    navigateTo('dmarc', params);
}

/**
 * Get current route from URL path
 * @returns {string} The current base route name
 */
function getCurrentRoute() {
    return parseRoute().baseRoute;
}

/**
 * Get current route with full parameters
 * @returns {Object} Route info with baseRoute and params
 */
function getFullRoute() {
    return parseRoute();
}

/**
 * Initialize the router
 * Sets up popstate listener and returns initial route info
 * @returns {Object} The initial route info { baseRoute, params }
 */
function initRouter() {
    console.log('Initializing SPA router...');

    // Handle browser back/forward buttons
    window.addEventListener('popstate', (event) => {
        const idx = event.state && Number.isInteger(event.state.idx) ? event.state.idx : null;
        const delta = idx === null ? null : idx - historyIdx;
        // The step that undid a Back or Forward while unsaved changes are asked about
        if (routerPopUndo) {
            routerPopUndo = false;
            if (idx !== null) historyIdx = idx;
            return;
        }
        // Back with a dialog or sheet open closes it and stays on the page
        if (overlayIgnorePop) {
            overlayIgnorePop = false;
            if (idx !== null) historyIdx = idx;
            return;
        }
        // While the unsaved changes question is open, Back and Forward wait for its answer
        if (typeof uiUnsavedAsking !== 'undefined' && uiUnsavedAsking && delta) {
            routerPopUndo = true;
            history.go(-delta);
            return;
        }
        if (overlayHistoryEntry && (delta === -1 || delta === null)) {
            overlayHistoryEntry = false;
            if (idx !== null) historyIdx = idx;
            closeTopOverlay();
            // Another dialog may still be open under it
            setTimeout(syncOverlayHistory, 0);
            return;
        }

        const routeInfo = event.state || parseRoute();
        let route = routeInfo.route || routeInfo.baseRoute || getCurrentRoute();
        let params = routeInfo.params || {};
        // A history entry an older version wrote, for a page that moved since
        const moved = canonicalRoute(route, params);

        // An entry an older version of the app wrote has no place in the history,
        // so the step cannot be undone exactly: the page the user was on is written
        // back as a new entry, then the question is asked
        const target = { route: (moved || { route }).route, params: (moved || { params }).params };
        if (!routerPopConfirmed && delta === null && typeof uiUnsavedCount === 'function' && uiUnsavedCount(target)) {
            const here = routerHere;
            routerPush({ route: here.route, params: here.params }, buildPath(here.route, here.params));
            uiConfirmLeave(target).then(ok => { if (ok) navigateTo(target.route, target.params, true, true); });
            return;
        }
        // Unsaved changes this step would drop: step back to where the user was,
        // ask, and take the same step again on Leave (the history stays as it was)
        if (!routerPopConfirmed && delta && typeof uiUnsavedCount === 'function'
            && uiUnsavedCount({ route: (moved || { route }).route, params: (moved || { params }).params })) {
            routerPopUndo = true;
            history.go(-delta);
            uiConfirmLeave({ route: (moved || { route }).route, params: (moved || { params }).params }).then(ok => {
                if (!ok) return;
                routerPopConfirmed = true;
                history.go(delta);
            });
            return;
        }
        routerPopConfirmed = false;
        routerSaveScroll();
        if (idx !== null) historyIdx = idx;

        // A jump of several steps back from an open dialog: whatever is open closes
        if (overlayHistoryEntry) {
            overlayHistoryEntry = false;
            for (let i = 0; i < 10 && openOverlays().length; i++) closeTopOverlay();
        }
        if (moved) {
            ({ route, params } = moved);
            routerReplace({ route, params }, buildPath(route, params));
        }

        console.log('Popstate event, navigating to:', route, params);

        // Use switchTab directly to avoid pushing duplicate history entries
        routerHere = { route, params };
        if (typeof switchTab === 'function') {
            switchTab(route, params);
        }
        routerRestoreScroll(historyIdx);
    });

    // Get initial route from URL. A reload keeps the entry's place in the history
    const routeInfo = parseRoute();
    routerHere = { route: routeInfo.baseRoute, params: routeInfo.params };
    if (history.state && Number.isInteger(history.state.idx)) historyIdx = history.state.idx;

    // Replace current history state with route info; a moved page gets its new address
    routerReplace({ route: routeInfo.baseRoute, params: routeInfo.params },
        routeInfo.moved ? buildPath(routeInfo.baseRoute, routeInfo.params) : window.location.pathname);

    // Closing or reloading the browser tab with changes not saved yet: the browser asks
    window.addEventListener('beforeunload', event => {
        if (typeof uiUnsavedCount === 'function' && uiUnsavedCount()) {
            event.preventDefault();
            event.returnValue = '';
        }
    });
    if ('scrollRestoration' in history) history.scrollRestoration = 'manual';

    console.log('Router initialized, initial route:', routeInfo);
    return routeInfo;
}

// Tab labels for mobile menu display
const TAB_LABELS = {
    'dashboard': 'Dashboard',
    'messages': 'Messages',
    'netfilter': 'Security',
    'outbound': 'Outbound',
    'quarantine': 'Quarantine',
    'rspamd': 'Rspamd',
    'status': 'Status',
    'domains': 'Domains',
    'dmarc': 'DMARC & TLS',
    'mailbox-stats': 'Mailbox Stats',
    'devices': 'Devices',
    'logs': 'Logs',
    'settings': 'Settings',
    'about': 'About'
};

/**
 * Toggle mobile menu open/close
 */
function toggleMobileMenu() {
    const mobileMenu = document.getElementById('mobile-menu');
    const hamburgerBtn = document.getElementById('hamburger-btn');

    if (mobileMenu && hamburgerBtn) {
        mobileMenu.classList.toggle('active');
        hamburgerBtn.classList.toggle('active');
    }
}

/**
 * Close mobile menu
 */
function closeMobileMenu() {
    const mobileMenu = document.getElementById('mobile-menu');
    const hamburgerBtn = document.getElementById('hamburger-btn');

    if (mobileMenu && hamburgerBtn) {
        mobileMenu.classList.remove('active');
        hamburgerBtn.classList.remove('active');
    }
}

/**
 * Navigate from mobile menu - closes menu and navigates
 * @param {string} route - The route to navigate to
 */
function navigateToMobile(route) {
    // Close the mobile menu first
    closeMobileMenu();

    // Navigate to the route; the menu and the label follow only when it went
    // (the user may stay with unsaved changes)
    navigateTo(route).then(moved => {
        if (!moved) return;
        updateMobileMenuActiveState(route);
        updateCurrentTabLabel(route);
    });
}

/**
 * Update mobile menu item active states
 * @param {string} activeRoute - The currently active route
 */
function updateMobileMenuActiveState(activeRoute) {
    // Remove active class from all mobile menu items
    document.querySelectorAll('.mobile-menu-item').forEach(item => {
        item.classList.remove('active');
    });

    // Add active class to the new active item
    const activeItem = document.getElementById(`mobile-tab-${activeRoute}`);
    if (activeItem) {
        activeItem.classList.add('active');
    }
}

/**
 * Update the current tab label shown on mobile
 * @param {string} route - The current route
 */
function updateCurrentTabLabel(route) {
    const label = document.getElementById('current-tab-label');
    if (label) {
        label.textContent = TAB_LABELS[route] || route;
    }
}

// Close mobile menu when clicking outside
document.addEventListener('click', (event) => {
    const mobileMenu = document.getElementById('mobile-menu');
    const hamburgerBtn = document.getElementById('hamburger-btn');

    if (mobileMenu && mobileMenu.classList.contains('active')) {
        // Check if click is outside the menu content and hamburger button
        const menuContent = mobileMenu.querySelector('.mobile-menu-content');
        if (!menuContent.contains(event.target) && !hamburgerBtn.contains(event.target)) {
            closeMobileMenu();
        }
    }
});

// Expose functions globally
window.navigateTo = navigateTo;
window.navigateToDmarc = navigateToDmarc;
window.getCurrentRoute = getCurrentRoute;
window.getFullRoute = getFullRoute;
window.parseRoute = parseRoute;
window.buildPath = buildPath;
window.SUBPAGES = SUBPAGES;
window.routerSyncSubpage = routerSyncSubpage;
window.initRouter = initRouter;
window.VALID_ROUTES = VALID_ROUTES;
window.toggleMobileMenu = toggleMobileMenu;
window.closeMobileMenu = closeMobileMenu;
window.navigateToMobile = navigateToMobile;
window.updateMobileMenuActiveState = updateMobileMenuActiveState;
window.updateCurrentTabLabel = updateCurrentTabLabel;
window.TAB_LABELS = TAB_LABELS;
